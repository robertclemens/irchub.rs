//! The frame pump and per-client dispatch (hub_logic.c).
//!
//! Wire format, every frame: `len(4, BE) || AES-256-GCM(iv(12) || ct || tag)`,
//! where the plaintext is `cmd(1) || inner_len(4) || payload`.  Before a
//! connection has authenticated the frame is plaintext instead — a bot's
//! UUID, its challenge signature, or a sealed box carrying a `HUBv3` login.
//! An SSH console's internal connection (docs/console.md) speaks plaintext
//! `op(1) || payload` frames instead, from the console thread.
//!
//! `handle_client_data` returns false when it disconnected the client, which
//! is the signal the main loop uses to re-examine the index that was just
//! swapped into place.

use zeroize::Zeroizing;

use crate::consts::*;
use crate::cstr::{Fmt, Tok, atoll, now, sscanf, trunc_string};
use crate::state::{BotAuthState, ClientType, HubClient, HubState, Lane, QueuedMsg};
use crate::{
    access, admin, auth, crypto, mesh, opflow, presence, queue, ratelimit, storage, upgrade,
};

const PEER_INFO: &[u8] = b"irchub-peer-session-v1";

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/// hub_client_send(): every frame to a linked bot or peer after the
/// handshake goes through its queue.  A direct write blocked the whole loop
/// on a client that stopped reading, and could land inside a part-sent
/// queued frame (the receiver's GCM check then failed and it dropped the
/// link).  The urgent lane keeps the old order -- ahead of queued deltas and
/// bulk frames, behind the frame already in flight -- and the drain right
/// after sends it at once when the socket has room.  False = not queued (no
/// socket, urgent lane full).
pub fn client_send(client: &mut HubClient, cmd: u8, payload: &str) -> bool {
    if client.sock.is_none() || client.internal {
        return false;
    }
    if !queue::send_urgent(client, cmd, payload) {
        return false;
    }
    queue::drain_writable(client);
    true
}

/// send_cmd_to_bot(): one frame to one authenticated bot, through
/// [`client_send`].  The queued copy is wiped when it is freed: a CHAN_REPLY
/// carries a channel key.
pub fn send_cmd_to_bot(client: &mut HubClient, cmd: u8, payload: &str) -> bool {
    if payload.len() + 5 > MAX_BUFFER {
        return false;
    }
    client_send(client, cmd, payload)
}

/// send_cmd_to_bot_after_config(): for a frame that acts on config the bot
/// may not have yet (a `mode` job reads the C| modes and c| key the console
/// has just stored): send the owed config push now, past the coalescing
/// window, and queue the frame behind it in the bulk lane --
/// [`send_cmd_to_bot`] goes out on the urgent lane and would overtake a
/// config still waiting in the bot's queue.
pub fn send_cmd_to_bot_after_config(
    state: &mut HubState,
    ci: usize,
    cmd: u8,
    payload: &str,
) -> bool {
    if state.bot_config_pending {
        send_owed_bot_config(state, now());
    }
    let c = &mut state.clients[ci];
    if !c.has_pending_writes() {
        return send_cmd_to_bot(c, cmd, payload);
    }
    QueuedMsg::new(cmd, Lane::Bulk, payload.as_bytes()).is_some_and(|m| queue::enqueue(c, m))
}

/// The largest reply the old hub_admin client accepted: its frame check refused anything
/// past a 65536-byte plaintext plus IV and tag.  The C hub built each reply in
/// a fixed buffer (8 KB for the user listings, 16 KB for most, 64 KB for the
/// bot list and the mesh matrix) and stopped adding rows at the end of it;
/// here the listings are built whole and cut once, at the one ceiling that
/// matters, so a full table is no longer truncated at 8 KB but also can never
/// grow past what the console can read.
const MAX_ADMIN_RESPONSE: usize = 65536;

/// send_response(): the reply to an admin command.  The connection is
/// dropped on any failure, and false says so.  An SSH console gets it queued
/// as plaintext, never as a partial write.
pub fn send_response(state: &mut HubState, ci: usize, msg: &str) -> bool {
    let msg = crate::cstr::trunc(msg, MAX_ADMIN_RESPONSE + 1);
    if state.clients[ci].internal {
        let ok = state.clients[ci]
            .console
            .as_mut()
            .is_some_and(|l| l.send(CONSOLE_REPLY, msg.as_bytes()));
        if ok {
            return true;
        }
        crate::hlog_warning!(
            "[CONSOLE] {}'s console is not reading — closing it\n",
            state.clients[ci].id
        );
        auth::disconnect_client(state, ci);
        return false;
    }
    // Admin replies go to SSH consoles only; a bot that sent an admin opcode
    // gets none (a frame sealed here, outside the queue, would also break the
    // link's sequence: review 6).
    crate::hlog_debug!(
        "[HUB] Admin reply to non-console {} dropped\n",
        state.clients[ci].ip
    );
    true
}

/// Review 6: start the sequenced framing on a link that just authenticated
/// (a bot, or a peer whose uuid is `peer_uuid`): fix the direction bytes and
/// send "offer".  A 2.5.1 node ignores it and the link stays as it is.
pub fn link_offer(state: &mut HubState, ci: usize, peer_uuid: Option<&str>) {
    let lower = peer_uuid.is_some_and(|pu| state.hub_uuid.as_str() < pu);
    let c = &mut state.clients[ci];
    if c.typ == ClientType::Hub {
        c.link_dir_tx = if lower { b'L' } else { b'G' };
        c.link_dir_rx = if lower { b'G' } else { b'L' };
    } else {
        c.link_dir_tx = b'H';
        c.link_dir_rx = b'B';
    }
    queue::send_urgent(c, CMD_LINK_SEQ, "offer");
}

/// Review 6: CMD_LINK_SEQ from the other end.  Its "offer" is answered with
/// our "go" (our frames after it are sequenced, see queue::encrypt_into_writing);
/// its "go" says every frame it sends after it is.
fn link_seq_recv(state: &mut HubState, ci: usize, what: &str) {
    let c = &mut state.clients[ci];
    if what == "offer" && !c.link_offered {
        c.link_offered = true;
        if !c.link_go_queued {
            c.link_go_queued = true;
            queue::send_urgent(c, CMD_LINK_SEQ, "go");
        }
    } else if what == "go" && c.link_offered && !c.link_rx_seq {
        c.link_rx_seq = true;
        c.link_rx_ctr = 0;
        crate::hlog_debug!(
            "[HUB] {}: sequenced link framing on\n",
            state.who_client(ci)
        );
    }
}

/// send_pong(): the keepalive answer, through [`client_send`].  Drops the
/// client when it cannot be queued.
fn send_pong(state: &mut HubState, ci: usize) -> bool {
    let ok = client_send(&mut state.clients[ci], CMD_PING, "");
    if !ok {
        auth::disconnect_client(state, ci);
        return false;
    }
    true
}

/// send_ping(): the maintenance keepalive, queued like every frame after the
/// handshake (a ping sent straight to the socket landed inside a part-sent
/// sync frame and broke the link).  False = it could not be queued: the
/// caller drops the connection.
pub fn send_ping(client: &mut HubClient) -> bool {
    client_send(client, CMD_PING, "")
}

/// SHA-256 of a bot config, leaving out the pd| line: it is stamped with the
/// time it was built, and bots do not read it, so it alone never makes a push
/// worth sending.
fn bot_config_hash(payload: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let pd = if payload.starts_with("pd|") {
        Some(0)
    } else {
        payload.find("\npd|").map(|i| i + 1)
    };
    let mut h = Sha256::new();
    match pd {
        None => h.update(payload.as_bytes()),
        Some(start) => {
            let after = payload[start..]
                .find('\n')
                .map_or(payload.len(), |nl| start + nl + 1);
            h.update(&payload.as_bytes()[..start]);
            h.update(&payload.as_bytes()[after..]);
        }
    }
    h.finalize().into()
}

/// send_config_to_bot(): queue this bot's full config on its BULK lane.
///
/// Coalesced on a per-bot key so a burst of
/// `broadcast_full_config_to_all_bots` calls collapses to one send per bot
/// per drain cycle.  `MAX_CONFIG_PAYLOAD` is a hard upper bound (see
/// `consts`), so the generator never truncates.  `force` false (a broadcast)
/// skips the push when the bot was already sent this exact config and that
/// push was not lost; true always sends (the bot's first config, a PULL, a
/// re-shape).
pub fn send_config_to_bot(state: &mut HubState, ci: usize, force: bool) {
    let id = state.clients[ci].id.clone();
    let payload = Zeroizing::new(storage::generate_bot_payload(state, &id));
    if payload.is_empty() {
        crate::hlog_warning!(
            "[HUB] No config to send to {id}\n",
            id = state.who_client(ci)
        );
        return;
    }
    let hash = bot_config_hash(&payload);
    if !force && state.clients[ci].cfg_sent_hash == Some(hash) {
        crate::stats::cfg_same();
        return;
    }
    crate::hlog_debug!(
        "[HUB-SYNC] Queueing config to {id} ({} bytes)\n",
        payload.len(),
        id = state.who_client(ci)
    );

    let coalesce = format!("{}|cfg_data|{id}", state.hub_uuid);
    let Some(mut m) = QueuedMsg::new(CMD_CONFIG_DATA, Lane::Bulk, payload.as_bytes()) else {
        return;
    };
    let seq = state.next_lamport_seq();
    let hub_uuid = state.hub_uuid.clone();
    m.set_coalesce(&hub_uuid, seq, &coalesce);
    let c = &mut state.clients[ci];
    c.cfg_sent_hash = None;
    if !queue::enqueue(c, m) {
        crate::stats::cfg_lost();
        return;
    }
    crate::stats::cfg_sent();
    c.cfg_sent_hash = Some(hash);
}

/// hub_broadcast_config_to_bots(): log the changed line, then re-send every
/// bot its full config.
/// A change the bots must see.  The line is for the log only: what reaches
/// the bots is the full config, owed through
/// `broadcast_full_config_to_all_bots` and coalesced by `flush_bot_config`.
pub fn broadcast_config_to_bots(state: &mut HubState, config_line: &str) {
    crate::hlog_debug!("[HUB] Broadcasting config update to all bots: {config_line}");
    broadcast_full_config_to_all_bots(state);
}

/// Owe every local bot a full config push.  It used to be sent right here,
/// once per accepted update: a burst of N updates (fifty bots reconnecting
/// send two each, and each one reaches every hub) became N full pushes to
/// every bot, while each push only ever carries the current state anyway.
/// `flush_bot_config` sends one, at most once per BOT_CONFIG_PUSH_COALESCE.
pub fn broadcast_full_config_to_all_bots(state: &mut HubState) {
    state.bot_config_pending = true;
}

/// hub_flush_bot_config(): send the owed full config push to every local
/// bot (maintenance loop).
pub fn flush_bot_config(state: &mut HubState, now_ts: i64) {
    if !state.bot_config_pending || now_ts - state.last_bot_config_push < BOT_CONFIG_PUSH_COALESCE {
        return;
    }
    send_owed_bot_config(state, now_ts);
}

/// send_owed_bot_config(): the push itself, past any coalescing window.
fn send_owed_bot_config(state: &mut HubState, now_ts: i64) {
    state.bot_config_pending = false;
    state.last_bot_config_push = now_ts;
    let bots = state.bot_clients();
    let n = bots.len();
    for ci in bots {
        send_config_to_bot(state, ci, false);
    }
    crate::hlog_debug!("[HUB] Broadcasted FULL config to {n} bots\n");
}

// ---------------------------------------------------------------------------
// Bot config push
// ---------------------------------------------------------------------------

/// Parse a `c|` push body.
///
/// The C chained four `sscanf` attempts, newest shape first, and the
/// variables carry across them: a later attempt overwrites only what it
/// actually converted, and the guard is on the count the *last* attempt
/// made. That cascade is reproduced literally here, because it is what
/// decides how a half-malformed line is read:
///
/// ```text
/// chan|key|modes|op|ts     (5)  a modern bot
/// chan||modes|op|ts        (4)  … with no key
/// chan|key|op|ts           (4)  the older shape, no modes
/// chan||op|ts              (3)  … with no key
/// ```
///
/// Returns None when fewer than three conversions were made, which is the C
/// `parsed >= 3` guard. Where an attempt converts no timestamp the C read an
/// uninitialised stack value; here it keeps whatever the previous attempt
/// left, or 0 — the same "never wins LWW" outcome, deterministically.
fn parse_push_channel(data: &str) -> Option<(String, String, i32, String, i64)> {
    const P: &[u8] = b"|";
    let (mut chan, mut key, mut op) = (String::new(), String::new(), String::new());
    let (mut modes, mut ts) = (0i32, 0i64);

    // "%64[^|]|%30[^|]|%d|%7[^|]|%lld"
    let c = sscanf(
        data,
        &[
            Fmt::Set(64, P),
            Fmt::Lit("|"),
            Fmt::Set(30, P),
            Fmt::Lit("|"),
            Fmt::Int,
            Fmt::Lit("|"),
            Fmt::Set(7, P),
            Fmt::Lit("|"),
            Fmt::Int,
        ],
    );
    let mut parsed = c.len();
    if let Some(v) = c.first() {
        chan = v.s().to_string();
    }
    if let Some(v) = c.get(1) {
        key = v.s().to_string();
    }
    if let Some(v) = c.get(2) {
        modes = v.i() as i32;
    }
    if let Some(v) = c.get(3) {
        op = v.s().to_string();
    }
    if let Some(v) = c.get(4) {
        ts = v.i();
    }

    if parsed < 5 {
        modes = 0;
        // "%64[^|]||%d|%7[^|]|%lld"
        let c = sscanf(
            data,
            &[
                Fmt::Set(64, P),
                Fmt::Lit("|"),
                Fmt::Lit("|"),
                Fmt::Int,
                Fmt::Lit("|"),
                Fmt::Set(7, P),
                Fmt::Lit("|"),
                Fmt::Int,
            ],
        );
        parsed = c.len();
        if let Some(v) = c.first() {
            chan = v.s().to_string();
        }
        if let Some(v) = c.get(1) {
            modes = v.i() as i32;
        }
        if let Some(v) = c.get(2) {
            op = v.s().to_string();
        }
        if let Some(v) = c.get(3) {
            ts = v.i();
        }

        if parsed >= 4 {
            key.clear();
        } else {
            modes = 0;
            // "%64[^|]|%30[^|]|%7[^|]|%lld"
            let c = sscanf(
                data,
                &[
                    Fmt::Set(64, P),
                    Fmt::Lit("|"),
                    Fmt::Set(30, P),
                    Fmt::Lit("|"),
                    Fmt::Set(7, P),
                    Fmt::Lit("|"),
                    Fmt::Int,
                ],
            );
            parsed = c.len();
            if let Some(v) = c.first() {
                chan = v.s().to_string();
            }
            if let Some(v) = c.get(1) {
                key = v.s().to_string();
            }
            if let Some(v) = c.get(2) {
                op = v.s().to_string();
            }
            if let Some(v) = c.get(3) {
                ts = v.i();
            }

            if parsed < 3 {
                // "%64[^|]||%7[^|]|%lld"
                let c = sscanf(
                    data,
                    &[
                        Fmt::Set(64, P),
                        Fmt::Lit("|"),
                        Fmt::Lit("|"),
                        Fmt::Set(7, P),
                        Fmt::Lit("|"),
                        Fmt::Int,
                    ],
                );
                parsed = c.len();
                if let Some(v) = c.first() {
                    chan = v.s().to_string();
                }
                if let Some(v) = c.get(1) {
                    op = v.s().to_string();
                }
                if let Some(v) = c.get(2) {
                    ts = v.i();
                }
                key.clear();
            }
        }
    }

    (parsed >= 3).then_some((chan, key, modes, op, ts))
}

/// process_bot_config_push().
/// One accepted record of a bot's config push, onto the batch forwarded to
/// peer hubs.  A line that would not fit sends the batch first, so nothing
/// accepted is dropped (C: `config_push_sync`).
fn push_sync(state: &mut HubState, s: &mut String, fd: i32, line: &str) {
    if !s.is_empty() && s.len() + line.len() >= MAX_BUFFER {
        mesh::broadcast_sync_to_peers(state, s, fd);
        s.clear();
    }
    s.push_str(line);
}

/// The v| protocol a config push carries (0 when unreadable), -1 when it has
/// no v| line.
fn push_proto(payload: &str) -> i64 {
    payload
        .split('\n')
        .find_map(|l| l.strip_prefix("v|"))
        .map(|v| {
            let v = crate::cstr::atoll(v);
            if v > 0 && v < 1000 { v } else { 0 }
        })
        .unwrap_or(-1)
}

fn process_bot_config_push(state: &mut HubState, ci: usize, payload: &str) {
    if state.clients[ci].typ != ClientType::Bot || !state.clients[ci].authenticated {
        crate::hlog_warning!("[HUB] Rejected config push from non-bot client\n");
        return;
    }
    let id = state.clients[ci].id.clone();
    let fd = state.clients[ci].fd;
    crate::hlog_debug!(
        "[HUB] Processing config push from {id}\n",
        id = state.who_client(ci)
    );
    // The bot's tables may now differ from what it was last sent (a push the
    // hub does not accept stays in them), so its next broadcast goes out.
    state.clients[ci].cfg_sent_hash = None;

    // opt 'h' (OPT_HUB_ONLY_MUTATIONS) enforcement point.  When the network
    // is in hub-only-mutation mode the hub is the SOLE authority for
    // privileged record types, and this is what makes the flag *binding*
    // against a rogue or malicious bot.  The matching bot-side guard only
    // stops a well-behaved bot from issuing the command locally; a modified
    // or compromised bot can ignore it and push the record straight up this
    // path.  These map 1:1 to the bot-side HUB_ONLY_CMDS list: a=+/-admin and
    // chkey, o=+/-oper and chkey, m=+/-usermask, c=join/part.  The bot's own
    // runtime identity (nick 'n', hostmask 'h') and its protocol version 'v'
    // are intrinsic state only the bot can report, so they stay accepted.
    //
    // Bots cannot clear this flag: 'opt|' updates arrive only via
    // CMD_PEER_SYNC (CLIENT_HUB) or CMD_ADMIN_SET_OPT_FLAGS (CLIENT_ADMIN),
    // and the bot dispatch never reaches process_peer_sync.  With the
    // rejection below, once opt 'h' is set a bot can neither mutate
    // privileged records nor escalate to an admin record that would let it
    // clear the flag.
    let hub_only_mutations = state.opt(OPT_HUB_ONLY_MUTATIONS);

    // Task 6 — opt 'F' (OPT_CONFIG_FROZEN): an upgrade run is open, so the
    // store holds still: a bot that restarts mid-roll re-pushes its config on
    // reconnect, and nothing is lost that it will not offer again once the
    // freeze lifts.  Its own nick (n|) and hostmask (h|) are the exception —
    // runtime identity, not config.  A bot that comes back from its upgrade
    // under another nick is opped by its peers only once they learn the new
    // mask, and the run waits for exactly that op (UPGRADE_OPS_WAIT).
    let frozen = upgrade::config_frozen(state);
    if frozen {
        crate::hlog_warning!(
            "[UPGRADE] config frozen: only nick/hostmask taken from config push from {id}\n"
        );
    }

    // v|<proto>|<unused> (docs/passwordless.md §3.4) heads a bot's full
    // push; record-only pushes (user/mask/ban deltas, split frames) carry
    // none.  A bot below BOT_PROTO_USER_FLAGS is refused before a line of it
    // is taken in: it would over-trust restricted users (MESH_MIN_VERSION).
    let proto = push_proto(payload);
    if (0..i64::from(BOT_PROTO_USER_FLAGS)).contains(&proto) {
        crate::hlog_warning!(
            "[HUB] {id} pushes protocol v{proto} (below v{BOT_PROTO_USER_FLAGS}): refused; upgrade it by hand to {MESH_MIN_VERSION}\n",
            id = state.who_client(ci)
        );
        state.clients[ci].refused = true;
        return;
    }

    let work_buf = trunc_string(payload, MAX_BUFFER);
    let mut updates = 0u32;
    let mut sync_buffer = String::new();

    for line in work_buf.split('\n') {
        if line.len() < 2
            || line.starts_with('#')
            || (frozen && !(line.starts_with("n|") || line.starts_with("h|")))
        {
            continue;
        }
        // uf| / uc|: admin flags and oper channel bindings (access.rs).  A bot
        // pushes them for its own chattr / chanoper / +admin / +oper; they are
        // hub-authoritative records exactly like a| / o| / m|.
        if let Some(body) = line
            .strip_prefix("uf|")
            .or_else(|| line.strip_prefix("uc|"))
        {
            let kind = line.as_bytes()[1] as char;
            if hub_only_mutations {
                crate::hlog_warning!(
                    "[HUB] opt 'h' active: REJECTED bot-pushed '{}' record from {} (hub-authoritative)\n",
                    &line[..2],
                    state.who_client(ci)
                );
            } else {
                match access::ingest(state, kind, body, true) {
                    None => crate::hlog_warning!(
                        "[HUB] Ignored invalid '{}' record from {}\n",
                        &line[..2],
                        state.who_client(ci)
                    ),
                    Some(true) => {
                        updates += 1;
                        push_sync(state, &mut sync_buffer, fd, &format!("{line}\n"));
                    }
                    Some(false) => {}
                }
            }
            continue;
        }
        // hl|<addr>/<fp>,...: the hubs this bot dials (the console's hub del
        // preview).  Only the bot knows it, so it is taken under every opt
        // and stamped here when it changed.
        if let Some(v) = line.strip_prefix("hl|") {
            let cur = state.bots.iter().find(|b| b.uuid == id).map(|b| {
                b.entries
                    .iter()
                    .find(|e| e.key == "hl")
                    .map(|e| (e.value.clone(), e.timestamp))
            });
            if !storage::hublist_valid(v) {
                crate::hlog_warning!(
                    "[HUB] Ignored invalid hub list from {id}\n",
                    id = state.who_client(ci)
                );
            } else if let Some(cur) = cur
                && cur.as_ref().is_none_or(|(cv, _)| cv != v)
            {
                let ts = crate::state::lww_next_ts(cur.map_or(0, |(_, t)| t));
                if storage::update_entry(state, &id, "hl", v, "", "", ts) {
                    updates += 1;
                    push_sync(
                        state,
                        &mut sync_buffer,
                        fd,
                        &format!("b|{id}|hl|{v}|{ts}\n"),
                    );
                }
            }
            continue;
        }
        let typ = line.as_bytes()[0] as char;
        if line.as_bytes()[1] != b'|' {
            continue;
        }
        let data = &line[2..];

        if typ == 'v' {
            // read up front (push_proto)
            continue;
        }

        // Reject hub-authoritative record types from bots while opt 'h' is
        // active.  'c' is the exception for what a bot learns (key / modes of
        // a channel that is already managed): that is enforcement, not an
        // admin change, and stays accepted (D43) -- see the 'c' branch below.
        if hub_only_mutations && matches!(typ, 'a' | 'o' | 'm') {
            crate::hlog_warning!(
                "[HUB] opt 'h' active: REJECTED bot-pushed '{typ}' record from {id} (hub-authoritative — mutation must originate from the admin console)\n",
                id = state.who_client(ci)
            );
            continue;
        }

        match typ {
            'c' => {
                let Some((chan, key, modes_val, op, ts)) = parse_push_channel(data) else {
                    continue;
                };
                // Opt 'h': a bot may only report the key / modes of a channel
                // the admins already manage; it may not add or remove one
                // (D43).
                if hub_only_mutations && (op != "add" || storage::chan_live(state, &chan).is_none())
                {
                    crate::hlog_warning!(
                        "[HUB] opt 'h' active: REJECTED bot-pushed 'c' {op} for {chan} from {id} (hub-authoritative)\n",
                        id = state.who_client(ci)
                    );
                    continue;
                }
                // Build extra as "key|modes" so the stored value becomes
                // "chan|key|modes|op".
                let extra = trunc_string(&format!("{key}|{modes_val}"), 80);
                let accepted = storage::update_global_entry(state, "c", &chan, &extra, &op, ts);
                crate::hlog_debug!(
                    "[HUB] Channel {chan}: ts={ts} op={op} modes={modes_val} -> {}\n",
                    if accepted { "ACCEPTED" } else { "REJECTED" }
                );
                if accepted {
                    updates += 1;
                    // Sync buffer: include modes for peer hubs.
                    push_sync(
                        state,
                        &mut sync_buffer,
                        fd,
                        &format!("b|{id}|c|{chan}|{key}|{modes_val}|{op}|{ts}\n"),
                    );
                }
            }
            'K' => {
                // K|chan|key|modes|ts: what this bot saw on IRC (learned key,
                // +k/+i).  Never existence: taken only while the channel is
                // managed, under every opt (enforcement, D43).
                if crate::storage::learned_ingest(state, data) {
                    updates += 1;
                    push_sync(state, &mut sync_buffer, fd, &format!("K|{data}\n"));
                } else {
                    crate::hlog_debug!(
                        "[HUB] K| from {id} not taken (channel not managed or not newer)\n",
                        id = state.who_client(ci)
                    );
                }
            }
            'B' => {
                // Enforcement ban: B|chan|mask|expires|flags|setter|reason|op|ts.
                // A bot writes only its own timed bans (modes::ban_bot_write
                // holds the rules); opt 'h' does not gate it (D43).
                let Some(p) = data.rfind('|') else { continue };
                if p == 0 || p >= 1024 {
                    continue;
                }
                let bval = &data[..p];
                let bts = atoll(&data[p + 1..]);
                if crate::modes::ban_bot_write(state, &id, bval, bts) {
                    updates += 1;
                    push_sync(state, &mut sync_buffer, fd, &format!("B|{bval}|{bts}\n"));
                }
            }
            'C' | 'D' => {
                // Channel settings and network defaults are written by the
                // console only.
                crate::hlog_warning!(
                    "[HUB] Ignored bot-pushed '{typ}' record from {id} (console only)\n",
                    id = state.who_client(ci)
                );
            }
            'm' => {
                // New format: uuid|mask|add/del|last_used|timestamp.  The old
                // `mask|add/del|timestamp` shape is ignored — the hub drives
                // the config.
                let f = crate::cstr::split_fields(data, 5);
                if f.len() < 5 || !crate::cstr::has_uuid_dashes(f[0]) {
                    continue;
                }
                let uuid = trunc_string(f[0], 37);
                let mask_s = trunc_string(f[1], MAX_MASK_LEN);
                let act = trunc_string(f[2], 8);
                let last_used = atoll(f[3]);
                let ts = atoll(f[4]);
                let is_active = act.starts_with("add");
                let found = state
                    .mask_records
                    .iter()
                    .position(|m| m.uuid == uuid && m.mask.eq_ignore_ascii_case(&mask_s));
                let mi = match found {
                    Some(i) => i,
                    None if state.mask_records.len() < MAX_HUB_USER_MASKS
                        && !crate::state::ts_ahead(ts)
                        && (is_active || !crate::storage::purge_floor_blocks(state, ts)) =>
                    {
                        state.mask_records.push(crate::state::MaskRecord {
                            uuid: uuid.clone(),
                            mask: mask_s.clone(),
                            ..Default::default()
                        });
                        state.mask_records.len() - 1
                    }
                    None => continue,
                };
                let cur = &state.mask_records[mi];
                if !crate::state::lww_accepts(ts, is_active, cur.timestamp, cur.is_active) {
                    // Activity repair, outside LWW: not an update.
                    crate::activity::raise(state, crate::activity::Slot::Mask(mi), last_used);
                    continue;
                }
                let m = &mut state.mask_records[mi];
                m.is_active = is_active;
                if last_used > m.last_used {
                    m.last_used = last_used;
                }
                m.timestamp = ts;
                state.config_dirty = true;
                updates += 1;
                push_sync(
                    state,
                    &mut sync_buffer,
                    fd,
                    &format!("m|{uuid}|{mask_s}|{act}|{last_used}|{ts}\n"),
                );
            }
            'o' | 'a' => {
                // hub_parse_user_record: uuid|name|pubkey|act|seen|ts|.  LWW
                // by timestamp.  Outside opt 'h' the network lets bots
                // create/re-key users (+admin/+oper/chkey); a keyless push
                // never erases a key the hub already holds.
                let Some(incoming) = crate::config::parse_user_record(data, typ) else {
                    continue;
                };
                let found = state
                    .user_records
                    .iter()
                    .position(|u| u.uuid == incoming.uuid);
                let ui = match found {
                    Some(i) => i,
                    None if state.user_records.len() < MAX_HUB_USER_RECORDS
                        && !crate::state::ts_ahead(incoming.timestamp)
                        && (incoming.is_active
                            || !crate::storage::purge_floor_blocks(state, incoming.timestamp)) =>
                    {
                        state.user_records.push(crate::state::UserRecord {
                            uuid: incoming.uuid.clone(),
                            ..Default::default()
                        });
                        state.user_records.len() - 1
                    }
                    None => continue,
                };
                let cur = &state.user_records[ui];
                if !crate::state::lww_accepts(
                    incoming.timestamp,
                    incoming.is_active,
                    cur.timestamp,
                    cur.is_active,
                ) {
                    // Activity repair, outside LWW: not an update.
                    crate::activity::raise(
                        state,
                        crate::activity::Slot::User(ui),
                        incoming.last_seen,
                    );
                    continue;
                }
                {
                    let u = &mut state.user_records[ui];
                    u.name = incoming.name;
                    u.typ = typ;
                    u.is_active = incoming.is_active;
                    if incoming.last_seen > u.last_seen {
                        u.last_seen = incoming.last_seen;
                    }
                    u.timestamp = incoming.timestamp;
                    if incoming.has_pubkey {
                        u.pubkey_b64 = incoming.pubkey_b64;
                        u.has_pubkey = true;
                    }
                }
                state.config_dirty = true;
                updates += 1;
                let uline = crate::config::format_user_record(&state.user_records[ui]);
                if uline.len() < USER_LINE_MAX {
                    push_sync(state, &mut sync_buffer, fd, &uline);
                }
            }
            'h' => {
                // Hostmask: h|nick!user@host|timestamp
                let conv = sscanf(data, &[Fmt::Set(255, b"|"), Fmt::Lit("|"), Fmt::Int]);
                if conv.len() != 2 {
                    continue;
                }
                let hostmask = conv[0].s().to_string();
                let ts = conv[1].i();
                let accepted = storage::update_entry(state, &id, "h", &hostmask, "", "", ts);
                crate::hlog_debug!(
                    "[HUB] Hostmask {hostmask}: ts={ts} -> {}\n",
                    if accepted { "ACCEPTED" } else { "REJECTED" }
                );
                if accepted {
                    updates += 1;
                    push_sync(
                        state,
                        &mut sync_buffer,
                        fd,
                        &format!("b|{id}|h|{hostmask}|{ts}\n"),
                    );
                }
            }
            'n' => {
                // Nick: n|nickname|timestamp.  The field width is 31, not 32:
                // a 32-char field plus its NUL overflowed nick[32] by a byte,
                // reachable by any authenticated bot.
                let conv = sscanf(data, &[Fmt::Set(31, b"|"), Fmt::Lit("|"), Fmt::Int]);
                if conv.len() != 2 {
                    continue;
                }
                let nick = conv[0].s().to_string();
                let ts = conv[1].i();
                let accepted = storage::update_entry(state, &id, "n", &nick, "", "", ts);
                crate::hlog_debug!(
                    "[HUB] Nick {nick}: ts={ts} -> {}\n",
                    if accepted { "ACCEPTED" } else { "REJECTED" }
                );
                if accepted {
                    updates += 1;
                    push_sync(
                        state,
                        &mut sync_buffer,
                        fd,
                        &format!("b|{id}|n|{nick}|{ts}\n"),
                    );
                }
            }
            _ => {}
        }
    }

    // A user this push created without uf| / uc| gets what it could do
    // before flags (access::migrate).
    if access::migrate(state) > 0 {
        updates += 1;
    }
    // A hubless bot's removal may have left no +a admin: undo it everywhere.
    if updates > 0 {
        let from = state.who_client(ci);
        if let Some((floor, _)) = access::admin_floor_restore(state, &from)
            && !floor.is_empty()
        {
            mesh::broadcast_sync_to_peers(state, &floor, -1);
        }
    }

    let first_push = !state.clients[ci].pushed;
    state.clients[ci].pushed = true;

    if updates > 0 {
        crate::hlog_debug!(
            "[HUB] Applied {updates} updates from {id}\n",
            id = state.who_client(ci)
        );
        // Update "seen" to track the last successful sync.
        storage::update_entry(state, &id, "seen", "", "", "", now());
        state.config_dirty = true;
        if !sync_buffer.is_empty() {
            mesh::broadcast_sync_to_peers(state, &sync_buffer, fd);
        }
        // Send the FULL config to all connected bots: this keeps them
        // consistent even when one of them missed an earlier update.
        broadcast_full_config_to_all_bots(state);
    } else if first_push && let Some(i) = state.client_by_fd(fd) {
        send_config_to_bot(state, i, true);
    }
}

// ---------------------------------------------------------------------------
// Bot command dispatch
// ---------------------------------------------------------------------------

/// CMD_BOT_DELTA: one key change for this bot, forwarded to peers as a single
/// DELTA rather than a full config push (mesh.md Phase 4).
fn process_bot_delta(state: &mut HubState, ci: usize, payload: &str) {
    state.clients[ci].cfg_sent_hash = None; // as for CMD_CONFIG_PUSH
    let conv = sscanf(
        payload,
        &[
            Fmt::Set(31, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(1023, b"|"),
            Fmt::Lit("|"),
            Fmt::Int,
        ],
    );
    let id = state.clients[ci].id.clone();
    if conv.len() < 2 {
        crate::hlog_warning!(
            "[HUB] Invalid CMD_BOT_DELTA from {id} — ignoring\n",
            id = state.who_client(ci)
        );
        return;
    }
    let key = conv[0].s().to_string();
    let val = conv[1].s().to_string();
    let mut ts = conv.get(2).map_or(0, |c| c.i());
    if ts == 0 {
        ts = now();
    }

    // Change 3 — opt 'h' (OPT_HUB_ONLY_MUTATIONS): the delta path bypasses
    // the reject-list that process_bot_config_push enforces, letting a
    // compromised bot mutate hub-authoritative records (a/o/m/c/p) that the
    // storage layer routes to global storage.  The same guard applies here so
    // the flag is binding on every bot-write path.
    if state.opt(OPT_HUB_ONLY_MUTATIONS) && matches!(key.as_str(), "a" | "o" | "m" | "c" | "p") {
        crate::hlog_warning!(
            "[HUB] opt 'h' active: REJECTED bot delta '{key}' from {id} (hub-authoritative)\n",
            id = state.who_client(ci)
        );
        return;
    }

    // Task 6 — opt 'F' (OPT_CONFIG_FROZEN): while an upgrade run is open the
    // store does not move, or a node that restarts mid-roll comes back
    // against a config its neighbours have not seen.  The bot's nick and
    // hostmask still move (see process_bot_config_push).
    if upgrade::config_frozen(state) && key != "n" && key != "h" {
        crate::hlog_warning!(
            "[UPGRADE] config frozen: REJECTED bot delta '{key}' from {id}\n",
            id = state.who_client(ci)
        );
        return;
    }

    // Change 3b's per-bot key whitelist and value caps are enforced centrally
    // in storage::update_entry (the single choke point shared by this delta
    // path, the config push, the peer sync and config load), so a rejected
    // key/value simply returns "not accepted" below.
    crate::hlog_debug!(
        "[HUB] BOT_DELTA from {id}: key={key} val={} ts={ts}\n",
        trunc_string(&val, 41),
        id = state.who_client(ci)
    );
    if !storage::update_entry(state, &id, &key, &val, "", "", ts) {
        return;
    }
    state.config_dirty = true;

    // The delta line forwarded to peers uses the existing process_peer_sync
    // wire format, compatible with its strrchr-based timestamp parsing.  The
    // Lamport seq lives in the queued message's coalesce metadata ONLY: it
    // must NOT be embedded in the payload, because the receiver reads the
    // last pipe as the timestamp and extra trailing fields corrupt the value.
    let seq = state.next_lamport_seq();
    let delta_line = format!("b|{id}|{key}|{val}|{ts}\n");
    if delta_line.len() >= MAX_BUFFER {
        return;
    }
    let coalesce = format!("{}|{id}|{key}", state.hub_uuid);
    mesh::sync_send_to_peers(
        state,
        &delta_line,
        -1,
        false,
        Lane::Delta,
        Some((&coalesce, seq)),
    );

    // The local bots learn the new hostmask / nick from the next coalesced
    // push (within BOT_CONFIG_PUSH_COALESCE), not one full push per delta:
    // a reconnect burst made that O(deltas x bots) frames of the same state.
    broadcast_full_config_to_all_bots(state);
}

/// CMD_BOT_RELAY: `target_uuid|<sealed frame>` — forward to the target bot.
///
/// The hub KNOWS the sender's identity from the authenticated session
/// (`client.id`), so it prepends that UUID to the forwarded CMD_BOT_MSG
/// payload and the receiver can verify the sender's GCM AAD binding.
fn process_bot_relay(state: &mut HubState, ci: usize, payload: &str) {
    let id = state.clients[ci].id.clone();
    let Some(bar) = payload.find('|') else {
        crate::hlog_warning!(
            "[HUB] Invalid CMD_BOT_RELAY payload from {id}\n",
            id = state.who_client(ci)
        );
        return;
    };
    let target_uuid = &payload[..bar];
    if target_uuid.is_empty() || target_uuid.len() >= 64 {
        crate::hlog_warning!(
            "[HUB] CMD_BOT_RELAY bad UUID len from {id}\n",
            id = state.who_client(ci)
        );
        return;
    }
    let t = now();
    let c = &mut state.clients[ci];
    if c.relay_window != t {
        c.relay_window = t;
        c.relay_count = 0;
    }
    c.relay_count += 1;
    if c.relay_count > BOT_RELAY_PER_SEC {
        if c.relay_count == BOT_RELAY_PER_SEC + 1 {
            crate::hlog_warning!(
                "[HUB] CMD_BOT_RELAY: {id} sends over {BOT_RELAY_PER_SEC} a second — dropping the rest\n",
                id = state.who_client(ci)
            );
        }
        return;
    }
    let target_uuid = target_uuid.to_string();
    let relay_payload = trunc_string(&payload[bar + 1..], MAX_BUFFER);
    crate::hlog_debug!(
        "[HUB] CMD_BOT_RELAY from {id} to {target_uuid}\n",
        id = state.who_client(ci),
        target_uuid = state.who('b', &target_uuid)
    );

    if let Some(ti) = state.bot_client(&target_uuid) {
        bot_relay_deliver(state, ti, &id, &relay_payload);
        return;
    }
    // Not one of ours: the target may be homed on any hub in the mesh, as
    // many hops out as the peer links go.  Flood it under a fresh id — but
    // only for a bot the config knows, so a bot cannot make the whole mesh
    // carry frames for uuids nobody will ever deliver.
    if !state
        .bots
        .iter()
        .any(|b| b.is_active && b.uuid == target_uuid)
    {
        crate::hlog_warning!(
            "[HUB] CMD_BOT_RELAY: target {target_uuid} is not a known bot\n",
            target_uuid = state.who('b', &target_uuid)
        );
        return;
    }
    let request_id = opflow::generate_request_id();
    opflow::forward_seen_check_and_add(state, &request_id);
    let sent = bot_relay_forward(
        state,
        &request_id,
        now(),
        &id,
        &target_uuid,
        &relay_payload,
        -1,
    );
    if sent == 0 {
        crate::hlog_warning!(
            "[HUB] CMD_BOT_RELAY: target {target_uuid} not connected and no peer to forward to\n",
            target_uuid = state.who('b', &target_uuid)
        );
    } else {
        crate::hlog_debug!(
            "[HUB] CMD_BOT_RELAY: {target_uuid} not local — forwarded (id:{request_id}) to {sent} peer(s)\n",
            target_uuid = state.who('b', &target_uuid)
        );
    }
}

/// Hand a sealed payload to local bot `ti` as CMD_BOT_MSG
/// `<sender>|<sealed frame>`.  The sender is the uuid the originating hub
/// authenticated, which is what the bot binds the GCM AAD to.
fn bot_relay_deliver(state: &mut HubState, ti: usize, sender: &str, sealed: &str) -> bool {
    let target_uuid = state.who_client(ti);
    let forwarded = format!("{sender}|{sealed}");
    if forwarded.len() + 5 > MAX_BUFFER {
        crate::hlog_warning!("[HUB] CMD_BOT_RELAY: forwarded payload too long\n");
        return false;
    }
    if send_cmd_to_bot(&mut state.clients[ti], CMD_BOT_MSG, &forwarded) {
        crate::hlog_debug!(
            "[HUB] CMD_BOT_RELAY: forwarded to {target_uuid} ({} bytes)\n",
            forwarded.len()
        );
        true
    } else {
        crate::hlog_warning!("[HUB] CMD_BOT_RELAY: write to {target_uuid} failed\n");
        false
    }
}

/// Flood one relay to every authenticated peer except `exclude_fd`.  Returns
/// how many peers took it.
fn bot_relay_forward(
    state: &mut HubState,
    request_id: &str,
    origin_ts: i64,
    sender: &str,
    target: &str,
    sealed: &str,
    exclude_fd: i32,
) -> usize {
    let fwd = format!("{request_id}|{origin_ts}|{sender}|{target}|{sealed}");
    if fwd.len() + 5 > MAX_BUFFER {
        crate::hlog_warning!("[HUB] CMD_BOT_RELAY: too long to forward to peers\n");
        return 0;
    }
    let mut sent = 0;
    for c in state.clients.iter_mut() {
        if c.typ != ClientType::Hub || !c.authenticated || c.fd == exclude_fd {
            continue;
        }
        // DELTA, not URGENT: a full lane drops the oldest relay, while a full
        // URGENT lane would take the peer link down with it.
        if let Some(m) = QueuedMsg::new(CMD_BOT_RELAY_FWD, Lane::Delta, fwd.as_bytes())
            && queue::enqueue(c, m)
        {
            sent += 1;
        }
        queue::drain_writable(c);
    }
    sent
}

/// A uuid a peer names in a forwarded relay: plain id characters only, so it
/// cannot smuggle a separator or a control byte into a bot frame or a log.
fn bot_relay_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// CMD_BOT_RELAY_FWD from a peer: deliver it if the target is ours, else pass
/// it on.  Payload: `id|origin_ts|sender_uuid|target_uuid|<sealed frame>`.
pub fn process_peer_bot_relay(state: &mut HubState, ci: usize, payload: &str) {
    let peer_fd = state.clients[ci].fd;
    let f: Vec<&str> = payload.splitn(5, '|').collect();
    if f.len() < 5 || !bot_relay_id_ok(f[0]) || !bot_relay_id_ok(f[2]) || !bot_relay_id_ok(f[3]) {
        let ip = state.clients[ci].ip.clone();
        crate::hlog_warning!("[HUB] Invalid BOT_RELAY_FWD payload from peer {ip}\n");
        return;
    }
    let (id, sender, target) = (f[0], f[2], f[3]);
    let sealed = f[4].trim_end_matches(['\r', '\n']);
    // Opaque to the hub (bots send "~B2 <b64>"): only require a non-empty
    // blob with no control bytes, so it cannot break a bot frame or a log.
    if sealed.is_empty() || sealed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        let ip = state.clients[ci].ip.clone();
        crate::hlog_warning!("[HUB] BOT_RELAY_FWD without a sealed payload from peer {ip}\n");
        return;
    }
    let origin_ts = atoll(f[1]);
    // atoll saturates: age only for a positive stamp (now - i64::MIN overflows)
    let age = if origin_ts > 0 { now() - origin_ts } else { 0 };
    if origin_ts <= 0 || !(-BOT_RELAY_FWD_TTL..=BOT_RELAY_FWD_TTL).contains(&age) {
        crate::hlog_debug!("[HUB] Dropping stale BOT_RELAY_FWD (id:{id}, age={age}s)\n");
        return;
    }
    if opflow::forward_seen_check_and_add(state, id) {
        return; // around a cycle
    }
    if let Some(ti) = state.bot_client(target) {
        crate::hlog_debug!("[HUB] BOT_RELAY_FWD {id}: {sender} -> local bot {target}\n");
        bot_relay_deliver(state, ti, sender, sealed);
        return;
    }
    let sent = bot_relay_forward(state, id, origin_ts, sender, target, sealed, peer_fd);
    crate::hlog_debug!("[HUB] BOT_RELAY_FWD {id} for {target} passed on to {sent} peer(s)\n");
}

/// CMD_INVITE_REQUEST: `nick|#channel` — broadcast to the other local bots
/// and forward to the peers.
fn process_invite_request(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(payload, &[Fmt::Set(63, b"|"), Fmt::Lit("|"), Fmt::Word(63)]);
    let id = state.who_client(ci);
    let fd = state.clients[ci].fd;
    if conv.len() != 2 {
        crate::hlog_warning!("[HUB] Invalid INVITE_REQUEST payload from {id}\n");
        return;
    }
    let inv_nick = conv[0].s().to_string();
    let inv_chan = conv[1].s().to_string();
    crate::hlog_info!("[HUB] INVITE_REQUEST from {id}: invite {inv_nick} into {inv_chan}\n");

    for bi in state.bot_clients() {
        if state.clients[bi].fd == fd {
            continue;
        }
        if !send_cmd_to_bot(&mut state.clients[bi], CMD_INVITE_REQUEST, payload) {
            crate::hlog_warning!(
                "[HUB] Failed to forward INVITE_REQUEST to {}\n",
                state.who_client(bi)
            );
        }
    }

    let peer_inv = trunc_string(&format!("invite|{inv_nick}|{inv_chan}"), 192);
    mesh::broadcast_sync_to_peers(state, &peer_inv, fd);
}

/// process_bot_command().
fn process_bot_command(state: &mut HubState, ci: usize, cmd: u8, payload: &str) {
    match cmd {
        CMD_PING => {
            if !HIDEPINGPONG {
                crate::hlog_debug!("[HUB] {} PING\n", state.who_client(ci));
            }
        }
        CMD_BOT_PRESENCE => presence::process_bot_presence(state, ci, payload),
        CMD_ACTIVITY => crate::activity::process(state, ci, payload),
        CMD_ACTIVITY_QUERY => crate::activity::process_query(state, ci, payload),
        CMD_UPGRADE_READY => upgrade::bot_report(state, CMD_UPGRADE_READY, payload),
        CMD_UPGRADE_RESULT => upgrade::bot_report(state, CMD_UPGRADE_RESULT, payload),
        CMD_CONFIG_PUSH => process_bot_config_push(state, ci, payload),
        CMD_CONFIG_PULL => {
            crate::hlog_debug!("[HUB] Config PULL request from {}\n", state.who_client(ci));
            send_config_to_bot(state, ci, true);
        }
        CMD_BOT_DELTA => process_bot_delta(state, ci, payload),
        CMD_OP_REQUEST => opflow::process_op_request(state, ci, payload),
        CMD_CHAN_REQUEST => opflow::process_chan_request(state, ci, payload),
        CMD_USER_CHAN_REQUEST => crate::elect::process_user_chan_request(state, ci, payload),
        CMD_CHAN_REPLY => opflow::process_chan_reply(state, ci, payload),
        CMD_CHAN_PROBE_ACK => crate::elect::process_probe_ack(state, ci, payload),
        CMD_CHAN_DONE => crate::elect::process_done(state, ci, payload),
        CMD_CHAN_EVENT => crate::modes::chan_event_receive(state, ci, payload),
        CMD_INVITE_REQUEST => process_invite_request(state, ci, payload),
        CMD_BOT_RELAY => process_bot_relay(state, ci, payload),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Authentication frames
// ---------------------------------------------------------------------------

/// v3 hub peer authentication (Ed25519 signature, no password).
/// Format: `HUBv3|<uuid>|<port>|<name>|<bind_ip>|<ts>|<sig_b64>`.
/// Review 7b: true when a HUBv3 hello with this ephemeral key was accepted in
/// the last HELLO_SEEN_SECS -- a replay, which would otherwise take over the
/// live link -- else it is remembered.  Only verified, fresh hellos get here,
/// so the ring holds real peers' hellos only.
fn hello_replayed(state: &mut HubState, eph: &[u8; 32]) -> bool {
    let t = now();
    if state
        .hello_seen
        .iter()
        .any(|(k, at)| *at != 0 && t - at <= HELLO_SEEN_SECS && crypto::ct_eq(k, eph))
    {
        return true;
    }
    let at = state.hello_seen_next;
    if state.hello_seen.len() < HELLO_SEEN_MAX {
        state.hello_seen.push((*eph, t));
    } else {
        state.hello_seen[at] = (*eph, t);
    }
    state.hello_seen_next = (at + 1) % HELLO_SEEN_MAX;
    false
}

/// Review 7a: peer `pi` already has a live link when `ci`, a link it dialled,
/// authenticates.  Both dialled by it: the new one is a reconnect and replaces
/// the old.  One dialled each way (both hubs dialled at once): the link the
/// lower uuid dialled stays, so the two hubs keep the same one without
/// talking.  True when `ci` stays; the old link is then shut down and reaped
/// on its EOF, as in auth::supersede_bot_sessions.
fn peer_link_tie(state: &mut HubState, pi: usize, ci: usize) -> bool {
    let peer_fd = state.peers[pi].fd;
    let old = if state.peers[pi].connected {
        (0..state.clients.len()).find(|&i| {
            let c = &state.clients[i];
            i != ci && c.typ == ClientType::Hub && c.fd >= 0 && c.fd == peer_fd
        })
    } else {
        None
    };
    let Some(oi) = old else { return true };
    let peer_uuid = state.peers[pi].uuid.clone();
    let keep_new = state.clients[oi].inbound || peer_uuid.as_str() < state.hub_uuid.as_str();
    if keep_new {
        crate::hlog_info!(
            "[MESH] {}: a second link (old one from {}) — keeping the new one\n",
            state.who('h', &peer_uuid),
            state.clients[oi].ip
        );
        let o = &mut state.clients[oi];
        o.superseded = true;
        if let Some(s) = o.sock.as_ref() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    } else {
        crate::hlog_info!(
            "[MESH] {} dialled while our link to it is up — ours stays (the lower uuid's link wins)\n",
            state.who('h', &peer_uuid)
        );
    }
    keep_new
}

fn handle_hubv3(state: &mut HubState, ci: usize, payload: &str, eph: &[u8; 32]) -> bool {
    let ip = state.clients[ci].ip.clone();
    let fd = state.clients[ci].fd;

    let work = trunc_string(&payload[6..], MAX_BUFFER);
    let mut tok = Tok::new(&work);
    let fields: Vec<Option<&str>> = (0..6).map(|_| tok.next("|")).collect();
    if fields.iter().any(Option::is_none) {
        crate::hlog_warning!("[HUB] v3 peer auth: malformed payload from {ip}\n");
        auth::disconnect_client(state, ci);
        return false;
    }
    let peer_uuid = trunc_string(fields[0].unwrap(), 64);
    let claimed_port = crate::cstr::atoi(fields[1].unwrap());
    let peer_name = trunc_string(fields[2].unwrap(), 64);
    let peer_bind_ip = trunc_string(fields[3].unwrap(), 64);
    let ts_str = trunc_string(fields[4].unwrap(), 32);
    let sig_b64 = trunc_string(fields[5].unwrap(), 128);

    // Locate the peer entry by UUID; a stored pubkey is required.
    let Some(pi) = state
        .peers
        .iter()
        .position(|p| !p.uuid.is_empty() && p.uuid == peer_uuid)
        .filter(|&i| state.peers[i].has_pubkey)
    else {
        crate::hlog_warning!(
            "[HUB] v3 peer auth: no pubkey on file for {peer_uuid} (from {ip}) — add the peer with its 88-char pubkey.\n",
            peer_uuid = state.who('h', &peer_uuid)
        );
        ratelimit::record_failed_auth(state, &ip);
        auth::disconnect_client(state, ci);
        return false;
    };

    // Reconstruct the transcript the sender committed to and verify it.
    let transcript = format!(
        "irchub-peer-auth-v3|{peer_uuid}|{ts_str}|{claimed_port}|{peer_name}|{peer_bind_ip}"
    );
    if transcript.len() >= 512 {
        crate::hlog_error!("[HUB] v3 peer auth: transcript overflow\n");
        auth::disconnect_client(state, ci);
        return false;
    }

    let sig = crypto::b64_decode(&sig_b64);
    let sig_len = sig.as_ref().map_or(0, |s| s.len());
    if sig_len != ED25519_SIG_LEN {
        crate::hlog_warning!("[HUB] v3 peer auth: bad signature length {sig_len}\n");
        ratelimit::record_failed_auth(state, &ip);
        auth::disconnect_client(state, ci);
        return false;
    }
    let sig_ok = crypto::ed25519_verify(
        &state.peers[pi].ed_pub,
        transcript.as_bytes(),
        sig.as_ref().unwrap(),
    );
    if !sig_ok {
        crate::hlog_warning!(
            "[HUB] v3 peer auth: signature verify FAILED for {peer_uuid} (from {ip})\n",
            peer_uuid = state.who('h', &peer_uuid)
        );
        ratelimit::record_failed_auth(state, &ip);
        auth::disconnect_client(state, ci);
        return false;
    }

    // Freshness window (±60 s).
    let client_ts = atoll(&ts_str);
    // a negative stamp is as stale as it gets; for one >= 0 the difference
    // cannot overflow
    let skew = if client_ts < 0 {
        i64::MAX
    } else {
        now() - client_ts
    };
    if skew.abs() > 60 {
        crate::hlog_warning!(
            "[HUB] v3 peer auth: timestamp skew {skew}s (max 60) for {peer_uuid}\n",
            peer_uuid = state.who('h', &peer_uuid)
        );
        ratelimit::record_failed_auth(state, &ip);
        auth::disconnect_client(state, ci);
        return false;
    }
    // Review 7b: the sealed box opens with the hello's ephemeral key (its
    // first 32 bytes); seen inside the window, it is replayed.
    if hello_replayed(state, eph) {
        crate::hlog_warning!(
            "[HUB] v3 peer auth: replayed hello for {} from {ip} — refused\n",
            state.who('h', &peer_uuid)
        );
        auth::disconnect_client(state, ci);
        return false;
    }
    if !peer_link_tie(state, pi, ci) {
        auth::disconnect_client(state, ci);
        return false;
    }

    // Accept.
    {
        let c = &mut state.clients[ci];
        c.typ = ClientType::Hub;
        c.authenticated = true;
        // D2: grow the buffers — peers exchange bulk anti-entropy sync.
        c.promote_buffers();
    }
    crate::ratelimit::known_ip_note(state, &ip);
    state.peers[pi].connected = true;
    state.peers[pi].fd = fd;
    state.peers[pi].remote_ip = ip.clone();
    if state.peers[pi].friendly_name.is_empty() && crate::state::name_valid(&peer_name) {
        state.peers[pi].friendly_name = peer_name.clone();
    }
    // If this process is the product of an upgrade this peer drove, close that
    // run out now that there is a peer to tell.
    upgrade::report_pending(state, ci);
    state.clients[ci].id = trunc_string(
        if !state.peers[pi].friendly_name.is_empty() {
            &state.peers[pi].friendly_name
        } else if crate::state::name_valid(&peer_name) {
            &peer_name
        } else {
            "HUB-PEER"
        },
        64,
    );

    crate::hlog_info!(
        "[HUB] v3 Peer authenticated by Ed25519 signature: {} ({peer_uuid})\n",
        if peer_name.is_empty() {
            &ip
        } else {
            &peer_name
        },
        peer_uuid = state.who('h', &peer_uuid)
    );

    link_offer(state, ci, Some(&peer_uuid));

    // Initial full-state sync to the newly authenticated peer.
    let init_sync = mesh::generate_sync_packet(state);
    mesh::peer_enqueue_sync(state, ci, CMD_PEER_SYNC, Lane::Bulk, &init_sync, None);
    crate::activity::send_bans(state, ci);
    true
}

/// The pre-authentication half of the pump.  False means the client was
/// disconnected.
fn handle_unauthenticated(state: &mut HubState, ci: usize, data: &[u8]) -> bool {
    let packet_len = data.len();

    // Detect the packet type: a bot UUID (plaintext, 36 chars, hex+hyphens)
    // or a mid-handshake bot packet (the 64-byte signature).
    let looks_like_uuid =
        packet_len == 36 && data.iter().all(|&c| c.is_ascii_hexdigit() || c == b'-');

    if looks_like_uuid || state.clients[ci].bot_auth_state != BotAuthState::Idle {
        if !auth::handle_bot_authentication(state, ci, data) {
            auth::disconnect_client(state, ci);
            return false;
        }
        return true;
    }

    // Sealed-box decrypt for HUB peer auth.  Frame layout:
    //   eph_pub(32) || IV(GCM_IV_LEN) || ct(N) || tag(GCM_TAG_LEN)
    if (32 + GCM_IV_LEN + GCM_TAG_LEN..=MAX_BUFFER).contains(&packet_len) {
        let mut x_priv = [0u8; 32];
        x_priv.copy_from_slice(state.hub_x25519_priv.get());

        let opened = crypto::seal_open(&x_priv, data, PEER_INFO);
        crypto::wipe(&mut x_priv);

        let Some((plain, session_key)) = opened else {
            // Sealed box failed — fall through to bot auth.
            if !auth::handle_bot_authentication(state, ci, data) {
                auth::disconnect_client(state, ci);
                return false;
            }
            return true;
        };
        state.clients[ci].session_key = session_key;
        let payload = String::from_utf8_lossy(crate::cstr::until_nul_bytes(&plain)).into_owned();

        // v3 hub peer authentication.  Any other handshake (HUBv2 and older
        // included) is refused below.
        if payload.starts_with("HUBv3|") {
            let mut eph = [0u8; 32];
            eph.copy_from_slice(&data[..32]);
            return handle_hubv3(state, ci, &payload, &eph);
        }
        auth::disconnect_client(state, ci);
        return false;
    }

    // Short packet — must be a bot UUID or mid-handshake.
    if !auth::handle_bot_authentication(state, ci, data) {
        auth::disconnect_client(state, ci);
        return false;
    }
    true
}

/// Dispatch one decrypted frame from an authenticated peer hub.
fn handle_peer_frame(state: &mut HubState, ci: usize, cmd: u8, payload: &str) {
    let fd = state.clients[ci].fd;
    match cmd {
        // Not read until this peer's version is known current:
        // mesh::peer_sync_release asks for it again then.
        CMD_PEER_SYNC | CMD_PEER_BCAST if mesh::peer_version_level(state, ci) != 2 => {
            state.clients[ci].sync_held = true;
        }
        CMD_PEER_SYNC => mesh::process_peer_sync(state, payload, fd, false),
        CMD_PEER_BCAST => mesh::process_peer_sync(state, payload, fd, true),
        CMD_MESH_STATE => mesh::process_mesh_state(state, ci, payload),
        CMD_BOT_ROSTER => {
            presence::process_bot_roster(state, ci, payload);
            if !state.clients[ci].refused {
                mesh::peer_sync_release(state, ci);
            }
        }
        CMD_OP_FORWARD_REQUEST => opflow::process_forward_op_request(state, ci, payload),
        CMD_OP_FORWARD_GRANT => opflow::process_forward_op_grant(state, payload),
        CMD_OP_FORWARD_FAILED => opflow::process_forward_op_failed(state, payload),
        CMD_BOT_RELAY_FWD => process_peer_bot_relay(state, ci, payload),
        CMD_ACTIVITY => crate::activity::process(state, ci, payload),
        CMD_UPGRADE_FORGET => upgrade::peer_forget(state, ci, payload),
        CMD_CHAN_FWD_REQUEST => opflow::process_forward_chan_request(state, ci, payload),
        CMD_CHAN_FWD_REPLY => opflow::process_forward_chan_reply(state, ci, payload),
        CMD_CHAN_ELECT_FWD => crate::elect::process_elect_fwd(state, ci, payload),
        CMD_CHAN_ELECT_ACK => crate::elect::process_elect_ack(state, ci, payload),
        CMD_CHAN_ELECT_DO => crate::elect::process_elect_do(state, ci, payload),
        CMD_CHAN_ELECT_DONE => crate::elect::process_elect_done(state, ci, payload),
        // A peer driving a run we are a node of...
        CMD_UPGRADE_PREPARE => upgrade::peer_prepare(state, ci, payload),
        CMD_UPGRADE_COMMIT => upgrade::peer_commit(state, ci, payload),
        CMD_UPGRADE_ABORT => upgrade::peer_abort(state, ci, payload),
        // ...and a peer answering a run WE drive — for itself, or forwarded on
        // behalf of one of its own local bots (recorded as a remote node
        // reached through this peer).
        CMD_UPGRADE_READY => {
            // If we are only a hop on someone else's run, pass it further up;
            // otherwise it answers a run WE drive.  Routed by the peer's own
            // hub uuid, not its friendly name: that is the key the node table
            // and every upgrade frame use.
            if !upgrade::relay_upstream(state, ci, CMD_UPGRADE_READY, payload) {
                let via = upgrade::peer_uuid_of(state, ci);
                upgrade::note_ready(state, payload, Some(&via));
            }
        }
        CMD_UPGRADE_RESULT => {
            if !upgrade::relay_upstream(state, ci, CMD_UPGRADE_RESULT, payload) {
                upgrade::note_result(state, payload);
            }
        }
        // v3: per-bot independent keys.  A peer-forwarded bot rekey would
        // carry a private key, so it is rejected.
        CMD_PEER_REKEY_BOT => crate::hlog_warning!(
            "[HUB] Rejected CMD_PEER_REKEY_BOT from peer {}: per-bot independent keys; rekey is bot-local.\n",
            state.clients[ci].ip
        ),
        CMD_SYNC_REQUEST => {
            // The peer is asking for our full state immediately.
            crate::hlog_debug!(
                "[MESH] Sync request from peer {} — sending full state\n",
                state.clients[ci].ip
            );
            let reply_sync = mesh::generate_sync_packet(state);
            mesh::peer_enqueue_sync(state, ci, CMD_PEER_SYNC, Lane::Bulk, &reply_sync, None);
        }
        // v3: independent per-hub keypairs.  A peer must NEVER push its
        // private key to us.
        CMD_UPDATE_PUBKEY => crate::hlog_warning!(
            "[HUB] Rejected CMD_UPDATE_PUBKEY from peer {}: per-hub independent keys; private keys do not cross hub boundaries.\n",
            state.clients[ci].ip
        ),
        _ => {}
    }
}

/// One plaintext `op || payload` frame from an SSH console (docs/console.md),
/// which authenticated the admin before this connection existed.  False
/// means the client was disconnected.
fn handle_console_frame(state: &mut HubState, ci: usize, data: &[u8]) -> bool {
    let Some((&op, body)) = data.split_first() else {
        auth::disconnect_client(state, ci);
        return false;
    };
    let payload = String::from_utf8_lossy(crate::cstr::until_nul_bytes(body)).into_owned();
    if op == CMD_CONSOLE {
        if !crate::console::frame(state, ci, &payload) {
            auth::disconnect_client(state, ci);
            return false;
        }
        return true;
    }
    // Both return false only after they closed this client.
    if admin::console_admin_op(op) {
        admin::handle_admin_command(state, ci, op, &payload, body, body.len())
    } else {
        send_response(state, ci, "err|admin.not_allowed|msg=not an admin command")
    }
}

/// hub_handle_client_data(): drain whole frames out of a client's receive
/// buffer.  At most 8 per call so the event loop stays fair across
/// connections — one backlogged peer must not starve bot auth.  False means
/// the client was disconnected.
pub fn handle_client_data(state: &mut HubState, ci: usize) -> bool {
    // The C held a `hub_client_t *`, which stayed valid however the client
    // list was reshuffled around it.  An index does not: a handler below may
    // disconnect OTHER clients (a peer whose URGENT queue filled, the bots
    // dropped by a rekey), and each of those swap-removes the list.  So the
    // fd is the stable handle here, and the index is re-resolved from it
    // around every dispatch.  `fd` cannot be reused mid-call — nothing
    // accepts while we are in here — and a `None` means this client is the
    // one that went, which is exactly what `false` reports to the caller.
    let fd = state.clients[ci].fd;
    let mut packets_this_call = 0;
    loop {
        let Some(ci) = state.client_by_fd(fd) else {
            return false;
        };
        let off = state.clients[ci].recv_off;
        if state.clients[ci].recv_buf.len() - off < 4 || packets_this_call >= 8 {
            return true;
        }
        packets_this_call += 1;
        let c = &state.clients[ci];
        let packet_len = i64::from(u32::from_be_bytes([
            c.recv_buf[off],
            c.recv_buf[off + 1],
            c.recv_buf[off + 2],
            c.recv_buf[off + 3],
        ]));

        // D2: bound against the client's actual buffer capacity, which is the
        // small PREAUTH_BUF_SIZE until the handshake completes.  That turns
        // the pre-auth buffer into a clean hard limit — an oversized pre-auth
        // frame is rejected here rather than hanging until the recv loop
        // fills and trips the overflow path.
        if packet_len < 0 || packet_len > (c.recv_cap as i64 - 4) {
            let (ip, cap) = (c.ip.clone(), c.recv_cap);
            crate::hlog_warning!(
                "[HUB] Invalid packet length {packet_len} from {ip} (cap {cap})\n"
            );
            auth::disconnect_client(state, ci);
            return false;
        }
        let packet_len = packet_len as usize;
        if c.recv_buf.len() - off < 4 + packet_len {
            return true; // need more data
        }
        let frame = off + 4..off + 4 + packet_len;

        if state.clients[ci].internal {
            let data = state.clients[ci].recv_buf[frame].to_vec();
            if !handle_console_frame(state, ci, &data) {
                return false;
            }
        } else if !state.clients[ci].authenticated {
            let data = state.clients[ci].recv_buf[frame].to_vec();
            if !handle_unauthenticated(state, ci, &data) {
                return false;
            }
        } else if packet_len > GCM_TAG_LEN {
            // Change 5: an authenticated peer frame (a full CMD_PEER_SYNC)
            // can be far larger than MAX_BUFFER — recv_cap was promoted to
            // MAX_SYNC_PAYLOAD for it — so the plaintext is sized to the
            // frame, never to a fixed 16 KB buffer.
            // Decrypted straight from the receive buffer: no copy of the
            // ciphertext first (review 2026-10-25 #25).
            // Review 6: on a sequenced link the frame must be the next one.
            let seq = state.clients[ci].link_rx_seq;
            let plain = {
                let c = &state.clients[ci];
                let (body, tag) = c.recv_buf[frame].split_at(packet_len - GCM_TAG_LEN);
                let aad = if seq {
                    queue::link_aad(c.link_dir_rx, c.link_rx_ctr).to_vec()
                } else {
                    Vec::new()
                };
                crypto::aes_gcm_decrypt_aad(body, &aad, c.session_key.as_ref(), tag)
            };
            if plain.is_some() && seq {
                state.clients[ci].link_rx_ctr += 1;
            }

            let Some(plain) = plain else {
                let ip = state.clients[ci].ip.clone();
                crate::hlog_warning!(
                    "[HUB] GCM tag verification failed from authenticated client {ip}{}\n",
                    if seq {
                        " (replayed, reordered or forged frame)"
                    } else {
                        ""
                    }
                );
                crate::hlog_warning!("[HUB] GCM decrypt failed from {ip}\n");
                auth::disconnect_client(state, ci);
                return false;
            };
            if plain.is_empty() {
                let ip = state.clients[ci].ip.clone();
                crate::hlog_warning!("[HUB] GCM decrypt failed from {ip}\n");
                auth::disconnect_client(state, ci);
                return false;
            }

            let cmd = plain[0];
            crate::stats::rx(cmd, packet_len + 4);
            if cmd == CMD_PING {
                let t = now();
                if t - state.clients[ci].last_pong_sent >= 5 {
                    if !send_pong(state, ci) {
                        return false;
                    }
                    state.clients[ci].last_pong_sent = t;
                }
            } else {
                // Every sender frames [cmd][len:4][payload]: a shorter frame
                // is malformed, and the C hub drops the client for it.
                if plain.len() < 5 {
                    let ip = state.clients[ci].ip.clone();
                    crate::hlog_warning!(
                        "[HUB] Short frame ({} bytes, cmd 0x{cmd:02x}) from {ip} — disconnecting\n",
                        plain.len()
                    );
                    auth::disconnect_client(state, ci);
                    return false;
                }
                let payload = if plain.len() > 5 {
                    String::from_utf8_lossy(crate::cstr::until_nul_bytes(&plain[5..])).into_owned()
                } else {
                    String::new()
                };
                let typ = state.clients[ci].typ;
                match typ {
                    ClientType::Bot | ClientType::Hub if cmd == CMD_LINK_SEQ => {
                        link_seq_recv(state, ci, &payload);
                    }
                    ClientType::Admin => {
                        let body_len = plain.len().saturating_sub(5);
                        if !admin::handle_admin_command(
                            state,
                            ci,
                            cmd,
                            &payload,
                            &plain[5.min(plain.len())..],
                            body_len,
                        ) {
                            return false;
                        }
                    }
                    ClientType::Bot if state.clients[ci].retiring => {
                        // Deleted: only its CMD_BOT_RETIRE_ACK counts, then it goes.
                        if cmd == CMD_BOT_RETIRE_ACK {
                            auth::retire_ack_apply(state, ci, payload.as_bytes());
                            auth::disconnect_client(state, ci);
                            return false;
                        }
                    }
                    ClientType::Bot => process_bot_command(state, ci, cmd, &payload),
                    ClientType::Hub => handle_peer_frame(state, ci, cmd, &payload),
                }
                // A bot or peer below MESH_MIN_VERSION (or a push below
                // BOT_PROTO_USER_FLAGS): drop the link.
                if let Some(ci) = state.client_by_fd(fd)
                    && state.clients[ci].refused
                {
                    auth::disconnect_client(state, ci);
                    return false;
                }
            }
        } else {
            // Too short to hold a GCM tag: never a frame we sent, so the
            // stream is not ours (or is out of step) -- drop, as on a bad tag.
            let ip = state.clients[ci].ip.clone();
            crate::hlog_warning!(
                "[HUB] Frame too short from authenticated client {ip} (len={packet_len}) — dropping\n"
            );
            auth::disconnect_client(state, ci);
            return false;
        }

        // Step past the frame; the reader compacts the buffer only when it is
        // full (a drain per frame made a backlog quadratic).
        let Some(ci) = state.client_by_fd(fd) else {
            return false;
        };
        let c = &mut state.clients[ci];
        c.recv_off += 4 + packet_len;
        if c.recv_off >= c.recv_buf.len() {
            c.recv_buf.clear();
            c.recv_off = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cascade_matches_c_sscanf() {
        let cases: &[(&str, &str)] = &[
            (
                "#c|key|5|add|100",
                "SOME chan=#c key=key modes=5 op=add ts=100",
            ),
            ("#c||5|del|100", "SOME chan=#c key= modes=5 op=del ts=100"),
            (
                "#c|key|add|100",
                "SOME chan=#c key=key modes=0 op=add ts=100",
            ),
            ("#c||add|100", "SOME chan=#c key= modes=0 op=add ts=100"),
            (
                "#c|key|5|add|100|extra",
                "SOME chan=#c key=key modes=5 op=add ts=100",
            ),
            ("#c|add|100", "SOME chan=#c key=add modes=0 op=100 ts=0"),
            ("#c|add", "NONE"),
            ("#c", "NONE"),
            ("|key|0|add|1", "NONE"),
            ("", "NONE"),
            (
                "#c|key|notanumber|add|100",
                "SOME chan=#c key=key modes=0 op=notanum ts=0",
            ),
            ("#c||||", "NONE"),
            (
                "#chan|k|0|add|0",
                "SOME chan=#chan key=k modes=0 op=add ts=0",
            ),
            ("#c|verylongkeythatgoesonandonandonandon|1|add|9", "NONE"),
            (
                "#c|k|1|averylongop|9",
                "SOME chan=#c key=k modes=0 op=1 ts=0",
            ),
        ];
        for (input, expect) in cases {
            let got = match super::parse_push_channel(input) {
                Some((c, k, m, o, t)) => format!("SOME chan={c} key={k} modes={m} op={o} ts={t}"),
                None => "NONE".to_string(),
            };
            assert_eq!(&got, expect, "input {input:?}");
        }
    }

    #[test]
    fn push_channel_shapes() {
        // The four shapes the cascade is built for.
        assert_eq!(
            parse_push_channel("#c|key|5|add|100"),
            Some(("#c".into(), "key".into(), 5, "add".into(), 100))
        );
        assert_eq!(
            parse_push_channel("#c||5|del|100"),
            Some(("#c".into(), String::new(), 5, "del".into(), 100))
        );
        assert_eq!(
            parse_push_channel("#c|key|add|100"),
            Some(("#c".into(), "key".into(), 0, "add".into(), 100))
        );
        assert_eq!(
            parse_push_channel("#c||add|100"),
            Some(("#c".into(), String::new(), 0, "add".into(), 100))
        );
        // Trailing fields are ignored, as sscanf ignores trailing input.
        assert_eq!(
            parse_push_channel("#c|key|5|add|100|extra"),
            Some(("#c".into(), "key".into(), 5, "add".into(), 100))
        );
        // Three fields fall through to attempt 3, which reads them
        // positionally as chan|key|op — a field-count reading would call it
        // chan|op|ts and store a different record.
        assert_eq!(
            parse_push_channel("#c|add|100"),
            Some(("#c".into(), "add".into(), 0, "100".into(), 0))
        );
        // Too few conversions: dropped.
        assert!(parse_push_channel("#c|add").is_none());
        assert!(parse_push_channel("#c").is_none());
        assert!(parse_push_channel("|key|0|add|1").is_none());
        assert!(parse_push_channel("").is_none());
    }

    #[test]
    fn config_hash_ignores_only_the_pd_stamp() {
        let a = "c|#x|add|1\npd|30|1000\nO|h|5\n";
        let b = "c|#x|add|1\npd|30|2000\nO|h|5\n";
        let c = "c|#x|add|1\npd|30|2000\nO|h|6\n";
        assert_eq!(bot_config_hash(a), bot_config_hash(b));
        assert_ne!(bot_config_hash(b), bot_config_hash(c));
        // pd| first, last, and missing its newline
        assert_eq!(
            bot_config_hash("pd|30|1\nc|#x|add|1\n"),
            bot_config_hash("pd|30|2\nc|#x|add|1\n")
        );
        assert_eq!(
            bot_config_hash("c|#x|add|1\npd|30|1"),
            bot_config_hash("c|#x|add|1\npd|30|2")
        );
        assert_ne!(
            bot_config_hash("c|#x|add|1\n"),
            bot_config_hash("c|#y|add|1\n")
        );
    }
}
