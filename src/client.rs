//! The frame pump and per-client dispatch (hub_logic.c).
//!
//! Wire format, every frame: `len(4, BE) || AES-256-GCM(iv(12) || ct || tag)`,
//! where the plaintext is `cmd(1) || inner_len(4) || payload`.  Before a
//! connection has authenticated the frame is plaintext instead — a bot's
//! UUID, its challenge signature, `ADMIN-HELLO`, or a sealed box carrying an
//! `ADMIN2` / `HUBv3` login.
//!
//! `handle_client_data` returns false when it disconnected the client, which
//! is the signal the main loop uses to re-examine the index that was just
//! swapped into place.

use zeroize::Zeroizing;

use crate::consts::*;
use crate::cstr::{Fmt, Tok, atoll, now, sscanf, trunc_string};
use crate::state::{BotAuthState, ClientType, HubClient, HubState, Lane, QueuedMsg};
use crate::{
    admin, auth, crypto, hlog, mesh, net, opflow, presence, queue, ratelimit, storage, upgrade,
};

const ADMIN_INFO: &[u8] = b"irchub-admin-session-v2";
const PEER_INFO: &[u8] = b"irchub-peer-session-v1";

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/// send_cmd_to_bot(): frame `payload` under `cmd` and write it to one
/// authenticated bot.
///
/// The plaintext frame is wiped after it goes out: a CHAN_REPLY carries a
/// channel key.
pub fn send_cmd_to_bot(client: &mut HubClient, cmd: u8, payload: &str) -> bool {
    if payload.len() + 5 > MAX_BUFFER {
        return false;
    }
    let plain = Zeroizing::new(net::frame_plain(cmd, payload.as_bytes(), true));
    let Some((body, tag)) = crypto::aes_gcm_encrypt(&plain, client.session_key.as_ref()) else {
        return false;
    };
    let mut wire = body;
    wire.extend_from_slice(&tag);
    let Some(sock) = &mut client.sock else {
        return false;
    };
    net::write_framed(sock, &wire)
}

/// The largest reply hub_admin will accept: its frame check refuses anything
/// past a 65536-byte plaintext plus IV and tag.  The C hub built each reply in
/// a fixed buffer (8 KB for the user listings, 16 KB for most, 64 KB for the
/// bot list and the mesh matrix) and stopped adding rows at the end of it;
/// here the listings are built whole and cut once, at the one ceiling that
/// matters, so a full table is no longer truncated at 8 KB but also can never
/// grow past what the console can read.
const MAX_ADMIN_RESPONSE: usize = 65536;

/// send_response(): an encrypted reply to hub_admin.  The connection is
/// dropped on any failure, and false says so.
pub fn send_response(state: &mut HubState, ci: usize, msg: &str) -> bool {
    let msg = crate::cstr::trunc(msg, MAX_ADMIN_RESPONSE + 1);
    let ok = {
        let c = &mut state.clients[ci];
        match crypto::aes_gcm_encrypt(msg.as_bytes(), c.session_key.as_ref()) {
            Some((body, tag)) => {
                let mut wire = body;
                wire.extend_from_slice(&tag);
                match &mut c.sock {
                    Some(sock) => net::write_framed(sock, &wire),
                    None => false,
                }
            }
            None => false,
        }
    };
    if !ok {
        auth::disconnect_client(state, ci);
        return false;
    }
    true
}

/// send_pong(): the keepalive answer.  Drops the client on a write failure.
fn send_pong(state: &mut HubState, ci: usize) -> bool {
    let plain = net::frame_plain(CMD_PING, &[], false);
    let ok = {
        let c = &mut state.clients[ci];
        match crypto::aes_gcm_encrypt(&plain, c.session_key.as_ref()) {
            Some((body, tag)) => {
                let mut wire = body;
                wire.extend_from_slice(&tag);
                match &mut c.sock {
                    Some(sock) => net::write_framed(sock, &wire),
                    None => false,
                }
            }
            None => true, // encryption failure was silently ignored in C
        }
    };
    if !ok {
        auth::disconnect_client(state, ci);
        return false;
    }
    true
}

/// send_ping(): the maintenance keepalive.  False means the connection is
/// dead and the caller should drop it; a full socket buffer is not a death.
pub fn send_ping(client: &mut HubClient) -> bool {
    let plain = net::frame_plain(CMD_PING, &[], false);
    let Some((body, tag)) = crypto::aes_gcm_encrypt(&plain, client.session_key.as_ref()) else {
        return true;
    };
    let mut wire = Vec::with_capacity(4 + body.len() + GCM_TAG_LEN);
    wire.extend_from_slice(&((body.len() + GCM_TAG_LEN) as u32).to_be_bytes());
    wire.extend_from_slice(&body);
    wire.extend_from_slice(&tag);
    let Some(sock) = &client.sock else {
        return false;
    };
    match net::send_dontwait(sock, &wire) {
        net::SendOutcome::Sent(n) => n == wire.len(),
        // The peer's send buffer is full but the connection is alive; skip
        // this ping.
        net::SendOutcome::WouldBlock => true,
        net::SendOutcome::Error(_) => false,
    }
}

/// send_config_to_bot(): queue this bot's full config on its BULK lane.
///
/// Coalesced on a per-bot key so a burst of
/// `broadcast_full_config_to_all_bots` calls collapses to one send per bot
/// per drain cycle.  `MAX_CONFIG_PAYLOAD` is a hard upper bound (see
/// `consts`), so the generator never truncates.
pub fn send_config_to_bot(state: &mut HubState, ci: usize) {
    let id = state.clients[ci].id.clone();
    let proto_v2 = state.clients[ci].bot_proto >= BOT_PROTO_PASSWORDLESS;
    let payload = storage::generate_bot_payload(state, &id, proto_v2);
    if payload.is_empty() {
        hlog!("[HUB] No config to send to {id}\n");
        return;
    }
    hlog!(
        "[HUB-SYNC] Queueing config to {id} ({} bytes)\n",
        payload.len()
    );

    let coalesce = format!("{}|cfg_data|{id}", state.hub_uuid);
    let Some(mut m) = QueuedMsg::new(CMD_CONFIG_DATA, Lane::Bulk, payload.as_bytes()) else {
        return;
    };
    let seq = state.next_lamport_seq();
    let hub_uuid = state.hub_uuid.clone();
    m.set_coalesce(&hub_uuid, seq, &coalesce);
    queue::enqueue(&mut state.clients[ci], m);
}

/// hub_broadcast_config_to_bots(): log the changed line, then re-send every
/// bot its full config.
pub fn broadcast_config_to_bots(state: &mut HubState, config_line: &str) {
    hlog!("[HUB] Broadcasting config update to all bots: {config_line}");
    for ci in state.bot_clients() {
        send_config_to_bot(state, ci);
    }
}

/// broadcast_full_config_to_all_bots().
pub fn broadcast_full_config_to_all_bots(state: &mut HubState) {
    let bots = state.bot_clients();
    let n = bots.len();
    for ci in bots {
        send_config_to_bot(state, ci);
    }
    hlog!("[HUB] Broadcasted FULL config to {n} bots\n");
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
fn process_bot_config_push(state: &mut HubState, ci: usize, payload: &str) {
    if state.clients[ci].typ != ClientType::Bot || !state.clients[ci].authenticated {
        hlog!("[HUB] Rejected config push from non-bot client\n");
        return;
    }
    let id = state.clients[ci].id.clone();
    let fd = state.clients[ci].fd;
    hlog!("[HUB] Processing config push from {id}\n");

    // opt 'h' (OPT_HUB_ONLY_MUTATIONS) enforcement point.  When the network
    // is in hub-only-mutation mode the hub is the SOLE authority for
    // privileged record types, and this is what makes the flag *binding*
    // against a rogue or malicious bot.  The matching bot-side guard only
    // stops a well-behaved bot from issuing the command locally; a modified
    // or compromised bot can ignore it and push the record straight up this
    // path.  These map 1:1 to the bot-side HUB_ONLY_CMDS list: a=+/-admin and
    // chkey, o=+/-oper and chkey, m=+/-usermask, c=join/part.  (p, the
    // retired bot password, is ignored under every opt.)  The bot's own
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
    // store holds still entirely.  Dropping the whole push (rather than
    // filtering it) is deliberate: a bot that restarts mid-roll re-pushes its
    // config on reconnect, and nothing here is lost that the bot will not
    // offer again once the freeze lifts.
    if upgrade::config_frozen(state) {
        let id = state.clients[ci].id.clone();
        hlog!("[UPGRADE] config frozen: REJECTED config push from {id}\n");
        return;
    }

    let work_buf = trunc_string(payload, MAX_BUFFER);
    let mut updates = 0u32;
    let mut proto_upgraded = false;
    let mut saw_proto = false;
    let mut sync_buffer = String::new();

    let push_sync = |s: &mut String, line: &str| {
        if s.len() + line.len() < MAX_BUFFER {
            s.push_str(line);
        }
    };

    for line in work_buf.split('\n') {
        if line.len() < 2 || line.starts_with('#') {
            continue;
        }
        let typ = line.as_bytes()[0] as char;
        if line.as_bytes()[1] != b'|' {
            continue;
        }
        let data = &line[2..];

        // v|<proto>|<unused>: protocol capability (docs/passwordless.md §3.4).
        // Recorded on this connection only; the first v >= 2 earns a fresh
        // config in the new record shapes.
        if typ == 'v' {
            saw_proto = true;
            let v = crate::cstr::atoll(data);
            if v >= i64::from(BOT_PROTO_PASSWORDLESS)
                && v < 1000
                && i64::from(state.clients[ci].bot_proto) < v
            {
                state.clients[ci].bot_proto = v as i32;
                proto_upgraded = true;
                hlog!("[HUB] Bot {id} speaks protocol v{v} (passwordless)\n");
            }
            continue;
        }
        if typ == 'p' {
            hlog!("[HUB] Ignored retired bot-password line from {id} (pre-passwordless bot)\n");
            continue;
        }

        // Reject hub-authoritative record types from bots while opt 'h' is
        // active.
        if hub_only_mutations && matches!(typ, 'a' | 'o' | 'm' | 'c') {
            hlog!(
                "[HUB] opt 'h' active: REJECTED bot-pushed '{typ}' record from {id} (hub-authoritative — mutation must originate from hub_admin)\n"
            );
            continue;
        }

        match typ {
            'c' => {
                let Some((chan, key, modes_val, op, ts)) = parse_push_channel(data) else {
                    continue;
                };
                // Build extra as "key|modes" so the stored value becomes
                // "chan|key|modes|op".
                let extra = trunc_string(&format!("{key}|{modes_val}"), 80);
                let accepted = storage::update_global_entry(state, "c", &chan, &extra, &op, ts);
                hlog!(
                    "[HUB-DEBUG] Channel {chan}: ts={ts} op={op} modes={modes_val} -> {}\n",
                    if accepted { "ACCEPTED" } else { "REJECTED" }
                );
                if accepted {
                    updates += 1;
                    // Sync buffer: include modes for peer hubs.
                    push_sync(
                        &mut sync_buffer,
                        &format!("b|{id}|c|{chan}|{key}|{modes_val}|{op}|{ts}\n"),
                    );
                }
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
                    None if state.mask_records.len() < MAX_HUB_USER_MASKS => {
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
                    &mut sync_buffer,
                    &format!("m|{uuid}|{mask_s}|{act}|{last_used}|{ts}\n"),
                );
            }
            'o' | 'a' => {
                // hub_parse_user_record: uuid|name|pubkey|act|seen|ts| (or a
                // legacy password shape, password dropped).  LWW by
                // timestamp.  Outside opt 'h' the network lets bots
                // create/re-key users (+admin/+oper/chkey); a keyless push
                // never erases a key the hub already holds.
                let Some((incoming, _)) = crate::config::parse_user_record(data, typ) else {
                    continue;
                };
                let found = state
                    .user_records
                    .iter()
                    .position(|u| u.uuid == incoming.uuid);
                let ui = match found {
                    Some(i) => i,
                    None if state.user_records.len() < MAX_HUB_USER_RECORDS => {
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
                let uline = crate::config::format_user_record(&state.user_records[ui], false);
                if uline.len() < USER_LINE_MAX {
                    push_sync(&mut sync_buffer, &uline);
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
                hlog!(
                    "[HUB-DEBUG] Hostmask {hostmask}: ts={ts} -> {}\n",
                    if accepted { "ACCEPTED" } else { "REJECTED" }
                );
                if accepted {
                    updates += 1;
                    push_sync(&mut sync_buffer, &format!("b|{id}|h|{hostmask}|{ts}\n"));
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
                hlog!(
                    "[HUB-DEBUG] Nick {nick}: ts={ts} -> {}\n",
                    if accepted { "ACCEPTED" } else { "REJECTED" }
                );
                if accepted {
                    updates += 1;
                    push_sync(&mut sync_buffer, &format!("b|{id}|n|{nick}|{ts}\n"));
                }
            }
            _ => {}
        }
    }

    // Every passwordless bot puts v| in each push, so its absence marks an
    // old build.  Say so once per connection, and sync it right away: its
    // first config replaces every password it still holds with an empty slot,
    // so it must not wait for the next periodic broadcast.
    let mut legacy_first = false;
    if !saw_proto && state.clients[ci].bot_proto == 0 {
        state.clients[ci].bot_proto = 1;
        legacy_first = true;
        hlog!(
            "[HUB] Bot {id} is a pre-passwordless build (no v|2): it gets legacy records with empty password slots; upgrade it\n"
        );
    }

    if updates > 0 {
        hlog!("[HUB] Applied {updates} updates from {id}\n");
        // Update "seen" to track the last successful sync.
        storage::update_entry(state, &id, "seen", "", "", "", now());
        state.config_dirty = true;
        if !sync_buffer.is_empty() {
            mesh::broadcast_sync_to_peers(state, &sync_buffer, fd);
        }
        // Send the FULL config to all connected bots: this keeps them
        // consistent even when one of them missed an earlier update.
        broadcast_full_config_to_all_bots(state);
    } else if proto_upgraded || legacy_first {
        // proto_upgraded: this connection just proved it is
        // passwordless-capable — replace the legacy-shaped config it may hold
        // right away.  legacy_first: an old build — empty its stored
        // passwords right away.
        if let Some(i) = state.client_by_fd(fd) {
            send_config_to_bot(state, i);
        }
    }
}

// ---------------------------------------------------------------------------
// Bot command dispatch
// ---------------------------------------------------------------------------

/// CMD_BOT_DELTA: one key change for this bot, forwarded to peers as a single
/// DELTA rather than a full config push (mesh.md Phase 4).
fn process_bot_delta(state: &mut HubState, ci: usize, payload: &str) {
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
        hlog!("[HUB] Invalid CMD_BOT_DELTA from {id} — ignoring\n");
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
        hlog!("[HUB] opt 'h' active: REJECTED bot delta '{key}' from {id} (hub-authoritative)\n");
        return;
    }

    // Task 6 — opt 'F' (OPT_CONFIG_FROZEN): while an upgrade run is open the
    // store does not move at all, or a node that restarts mid-roll comes back
    // against a config its neighbours have not seen.
    if upgrade::config_frozen(state) {
        hlog!("[UPGRADE] config frozen: REJECTED bot delta '{key}' from {id}\n");
        return;
    }

    // Change 3b's per-bot key whitelist and value caps are enforced centrally
    // in storage::update_entry (the single choke point shared by this delta
    // path, the config push, the peer sync and config load), so a rejected
    // key/value simply returns "not accepted" below.
    hlog!(
        "[HUB] BOT_DELTA from {id}: key={key} val={} ts={ts}\n",
        trunc_string(&val, 41)
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
    let hub_uuid = state.hub_uuid.clone();

    for pi in state.peer_clients() {
        let Some(mut m) = QueuedMsg::new(CMD_PEER_SYNC, Lane::Delta, delta_line.as_bytes()) else {
            continue;
        };
        m.set_coalesce(&hub_uuid, seq, &coalesce);
        if !queue::enqueue(&mut state.clients[pi], m) {
            hlog!(
                "[HUB] BOT_DELTA enqueue failed for peer fd={}\n",
                state.clients[pi].fd
            );
        }
    }

    // Also push a fresh config to the other locally connected bots so they
    // learn the new hostmask / nick immediately, without waiting for
    // anti-entropy.
    for bi in state.bot_clients() {
        if state.clients[bi].id != id {
            send_config_to_bot(state, bi);
        }
    }
}

/// CMD_BOT_RELAY: `target_uuid|cipher:tag` — forward to the target bot.
///
/// The hub KNOWS the sender's identity from the authenticated session
/// (`client.id`), so it prepends that UUID to the forwarded CMD_BOT_MSG
/// payload and the receiver can verify the sender's GCM AAD binding.
fn process_bot_relay(state: &mut HubState, ci: usize, payload: &str) {
    let id = state.clients[ci].id.clone();
    let Some(bar) = payload.find('|') else {
        hlog!("[HUB] Invalid CMD_BOT_RELAY payload from {id}\n");
        return;
    };
    let target_uuid = &payload[..bar];
    if target_uuid.is_empty() || target_uuid.len() >= 64 {
        hlog!("[HUB] CMD_BOT_RELAY bad UUID len from {id}\n");
        return;
    }
    let target_uuid = target_uuid.to_string();
    let relay_payload = trunc_string(&payload[bar + 1..], MAX_BUFFER);
    hlog!("[HUB] CMD_BOT_RELAY from {id} to {target_uuid}\n");

    let Some(ti) = state.bot_client(&target_uuid) else {
        hlog!("[HUB] CMD_BOT_RELAY: target {target_uuid} not connected\n");
        return;
    };
    let forwarded = format!("{id}|{relay_payload}");
    if forwarded.len() >= MAX_BUFFER {
        hlog!("[HUB] CMD_BOT_RELAY: forwarded payload too long\n");
        return;
    }
    if send_cmd_to_bot(&mut state.clients[ti], CMD_BOT_MSG, &forwarded) {
        hlog!(
            "[HUB] CMD_BOT_RELAY: forwarded to {target_uuid} ({} bytes)\n",
            forwarded.len()
        );
    } else {
        hlog!("[HUB] CMD_BOT_RELAY: write to {target_uuid} failed\n");
    }
}

/// CMD_INVITE_REQUEST: `nick|#channel` — broadcast to the other local bots
/// and forward to the peers.
fn process_invite_request(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(payload, &[Fmt::Set(63, b"|"), Fmt::Lit("|"), Fmt::Word(63)]);
    let id = state.clients[ci].id.clone();
    let fd = state.clients[ci].fd;
    if conv.len() != 2 {
        hlog!("[HUB] Invalid INVITE_REQUEST payload from {id}\n");
        return;
    }
    let inv_nick = conv[0].s().to_string();
    let inv_chan = conv[1].s().to_string();
    hlog!("[HUB] INVITE_REQUEST from {id}: invite {inv_nick} into {inv_chan}\n");

    for bi in state.bot_clients() {
        if state.clients[bi].fd == fd {
            continue;
        }
        if !send_cmd_to_bot(&mut state.clients[bi], CMD_INVITE_REQUEST, payload) {
            hlog!(
                "[HUB] Failed to forward INVITE_REQUEST to bot {}\n",
                state.clients[bi].id
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
                hlog!("[HUB] Bot {} PING\n", state.clients[ci].id);
            }
        }
        CMD_BOT_PRESENCE => presence::process_bot_presence(state, ci, payload),
        CMD_UPGRADE_READY => upgrade::bot_report(state, CMD_UPGRADE_READY, payload),
        CMD_UPGRADE_RESULT => upgrade::bot_report(state, CMD_UPGRADE_RESULT, payload),
        CMD_CONFIG_PUSH => process_bot_config_push(state, ci, payload),
        CMD_CONFIG_PULL => {
            hlog!("[HUB] Config PULL request from {}\n", state.clients[ci].id);
            send_config_to_bot(state, ci);
        }
        CMD_BOT_DELTA => process_bot_delta(state, ci, payload),
        CMD_OP_REQUEST => opflow::process_op_request(state, ci, payload),
        CMD_CHAN_REQUEST => opflow::process_chan_request(state, ci, payload),
        CMD_CHAN_REPLY => opflow::process_chan_reply(state, ci, payload),
        CMD_INVITE_REQUEST => process_invite_request(state, ci, payload),
        CMD_BOT_RELAY => process_bot_relay(state, ci, payload),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Authentication frames
// ---------------------------------------------------------------------------

/// The ADMIN-HELLO discovery probe.  Answers with
/// `HUB-PUBKEY2|<hub_x_pub_b64>|<hub_uuid>|<nonce32_b64>` (plaintext,
/// length-prefixed) and stays unauthenticated.  The nonce is this
/// connection's one-time login challenge, which hub_admin must sign — with
/// the hub key, hub UUID and its ephemeral key — in ADMIN2.  One HELLO per
/// connection; a second one is refused.
fn handle_admin_hello(state: &mut HubState, ci: usize) -> bool {
    if state.clients[ci].admin_hello_seen {
        let ip = state.clients[ci].ip.clone();
        hlog!("[HUB] Repeated ADMIN-HELLO from {ip} — disconnecting\n");
        ratelimit::record_failed_auth(state, &ip);
        auth::disconnect_client(state, ci);
        return false;
    }
    // D4b: an interactive admin client may take a moment before its
    // sealed-box ADMIN2 arrives.  Grant it the longer pre-auth window;
    // bots, peers and slowloris connections are unaffected.
    state.clients[ci].admin_hello_seen = true;

    if state.hub_keys_loaded {
        let mut nonce = [0u8; 32];
        if crypto::random_bytes(&mut nonce) {
            state.clients[ci].admin_nonce = nonce;
            state.clients[ci].admin_nonce_set = true;
            let reply = format!(
                "HUB-PUBKEY2|{}|{}|{}",
                crypto::b64_encode(&state.hub_x25519_pub),
                state.hub_uuid,
                crypto::b64_encode(&nonce)
            );
            if reply.len() < 256
                && let Some(sock) = &mut state.clients[ci].sock
            {
                net::write_framed(sock, reply.as_bytes());
            }
        }
    }
    true
}

/// ADMIN login v2 (docs/passwordless.md §6): no name, no password.
///
/// ```text
/// "ADMIN2|<admin_pub_b64>|<sig_b64>|<ip>:<port>"
/// sig = Ed25519(admin_ed_priv, "irchub-admin-auth-v2\0" || hub_uuid || "\0"
///       || hub_x_pub(32) || nonce(32) || eph_pub(32) || admin_pub(64))
/// ```
///
/// `eph_pub` is the first 32 bytes of the sealed frame — hub_admin's fresh
/// ephemeral key, which keyed this box; `nonce` is the challenge this
/// connection received in HUB-PUBKEY2.  The signature proves possession of
/// the admin's private key, is useless on any other connection or hub (nonce,
/// hub key and UUID are all bound), and the ephemeral key gives the session
/// forward secrecy.  The legacy "ADMIN|name|password|..." login is gone.
fn handle_admin2(state: &mut HubState, ci: usize, payload: &str, eph_pub: &[u8]) -> bool {
    let nonce_ok = state.clients[ci].admin_nonce_set;
    let nonce = state.clients[ci].admin_nonce;
    // Single use, success or not.
    crypto::wipe(&mut state.clients[ci].admin_nonce);
    state.clients[ci].admin_nonce_set = false;
    let ip = state.clients[ci].ip.clone();

    let body = &payload[7..];
    let f = crate::cstr::split_fields(body, 3);
    let shape_ok = f.len() == 3 && f[0].len() == COMBINED_KEY_B64 && f[1].len() == 88;
    let (pub_b64, sig_b64, client_addr) = if shape_ok {
        (f[0], f[1], trunc_string(f[2], 96))
    } else {
        ("", "", String::new())
    };

    let mut why = "malformed ADMIN2 payload";
    let mut pass_ok = false;
    let mut admin_ui: Option<usize> = None;
    let mut admin_pub = [0u8; COMBINED_KEY_LEN];

    if !nonce_ok {
        why = "no login challenge on this connection (ADMIN-HELLO first)";
    } else if shape_ok && let Some(p) = crypto::pubkey_b64_decode(pub_b64) {
        admin_pub = p;
        let matches: Vec<usize> = state
            .user_records
            .iter()
            .enumerate()
            .filter(|(_, u)| u.typ == 'a' && u.is_active && u.has_pubkey && u.pubkey_b64 == pub_b64)
            .map(|(i, _)| i)
            .collect();
        if matches.is_empty() {
            why = "no active admin record holds this key";
        } else if matches.len() > 1 {
            why = "key is on more than one admin record — refusing";
        } else {
            admin_ui = Some(matches[0]);
            if state.hub_uuid.len() < 64 {
                let mut msg = Vec::with_capacity(256);
                msg.extend_from_slice(b"irchub-admin-auth-v2\0"); // incl. NUL
                msg.extend_from_slice(state.hub_uuid.as_bytes());
                msg.push(0);
                msg.extend_from_slice(&state.hub_x25519_pub);
                msg.extend_from_slice(&nonce);
                msg.extend_from_slice(&eph_pub[..32]);
                msg.extend_from_slice(&admin_pub);
                let sig = crypto::b64_decode(sig_b64);
                pass_ok = sig.as_ref().is_some_and(|s| {
                    s.len() == ED25519_SIG_LEN
                        && crypto::ed25519_verify(&crypto::pub_halves(&admin_pub).0, &msg, s)
                });
            }
            if !pass_ok {
                why = "signature invalid";
                admin_ui = None;
            }
        }
    }

    let auth_name =
        admin_ui.map_or_else(|| "?".to_string(), |i| state.user_records[i].name.clone());

    if !pass_ok {
        hlog!("[HUB] Failed admin auth from {ip}: {why}\n");
        ratelimit::record_failed_auth(state, &ip);
        auth::disconnect_client(state, ci);
        return false;
    }

    // client.id is the admin's identity for storage lookups and logging.
    // "ADMIN:" plus a 63-char name does not fit in id[64], and two long names
    // sharing a prefix would collapse to the same id.  Fail closed rather
    // than authenticate under a truncated identity.
    if auth_name.len() + "ADMIN:".len() + 1 > 64 {
        hlog!("[HUB] Admin auth from {ip}: name '{auth_name}' too long for client id — refusing\n");
        auth::disconnect_client(state, ci);
        return false;
    }

    {
        let c = &mut state.clients[ci];
        c.typ = ClientType::Admin;
        c.authenticated = true;
        // D2: grow the buffers now that the admin is authenticated.
        c.promote_buffers();
        c.id = format!("ADMIN:{auth_name}");

        // Capture the admin's reported ip:port (informational).
        match client_addr.find(':') {
            Some(colon) if !client_addr.is_empty() => {
                c.admin_connect_ip = trunc_string(&client_addr[..colon], 64);
                c.admin_connect_port = crate::cstr::atoi(&client_addr[colon + 1..]);
            }
            _ => {
                c.admin_connect_ip.clear();
                c.admin_connect_port = 0;
            }
        }
    }

    if let Some(ui) = admin_ui {
        state.user_records[ui].last_seen = now();
    }
    state.config_dirty = true;
    hlog!(
        "[HUB] Admin Login (key {}): {ip} as '{auth_name}'\n",
        crypto::key_fingerprint(&admin_pub)
    );

    // Tell hub_admin who it is logged in as (encrypted).
    if !send_response(state, ci, &format!("AUTH-OK|{auth_name}")) {
        return false; // send_response already disconnected
    }

    state.anti_entropy_due = true;
    mesh::request_sync_from_peers(state);
    broadcast_full_config_to_all_bots(state);
    true
}

/// v3 hub peer authentication (Ed25519 signature, no password).
/// Format: `HUBv3|<uuid>|<port>|<name>|<bind_ip>|<ts>|<sig_b64>`.
fn handle_hubv3(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let ip = state.clients[ci].ip.clone();
    let fd = state.clients[ci].fd;

    let work = trunc_string(&payload[6..], MAX_BUFFER);
    let mut tok = Tok::new(&work);
    let fields: Vec<Option<&str>> = (0..6).map(|_| tok.next("|")).collect();
    if fields.iter().any(Option::is_none) {
        hlog!("[HUB] v3 peer auth: malformed payload from {ip}\n");
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
        hlog!(
            "[HUB] v3 peer auth: no pubkey on file for uuid {peer_uuid} (from {ip}) — add the peer with its 88-char pubkey.\n"
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
        hlog!("[HUB] v3 peer auth: transcript overflow\n");
        auth::disconnect_client(state, ci);
        return false;
    }

    let sig = crypto::b64_decode(&sig_b64);
    let sig_len = sig.as_ref().map_or(0, |s| s.len());
    if sig_len != ED25519_SIG_LEN {
        hlog!("[HUB] v3 peer auth: bad signature length {sig_len}\n");
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
        hlog!("[HUB] v3 peer auth: signature verify FAILED for uuid {peer_uuid} (from {ip})\n");
        ratelimit::record_failed_auth(state, &ip);
        auth::disconnect_client(state, ci);
        return false;
    }

    // Freshness window (±60 s).
    let client_ts = atoll(&ts_str);
    let skew = now() - client_ts;
    if skew.abs() > 60 {
        hlog!("[HUB] v3 peer auth: timestamp skew {skew}s (max 60) for {peer_uuid}\n");
        ratelimit::record_failed_auth(state, &ip);
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

    hlog!(
        "[HUB] v3 Peer authenticated by Ed25519 signature: {} ({peer_uuid})\n",
        if peer_name.is_empty() {
            &ip
        } else {
            &peer_name
        }
    );

    // Initial full-state sync to the newly authenticated peer.
    let init_sync = mesh::generate_sync_packet(state);
    if !init_sync.is_empty()
        && let Some(m) = QueuedMsg::new(CMD_PEER_SYNC, Lane::Bulk, init_sync.as_bytes())
    {
        queue::enqueue(&mut state.clients[ci], m);
    }
    true
}

/// The pre-authentication half of the pump.  False means the client was
/// disconnected.
fn handle_unauthenticated(state: &mut HubState, ci: usize, data: &[u8]) -> bool {
    let packet_len = data.len();

    if packet_len == 11
        && data == b"ADMIN-HELLO"
        && state.clients[ci].bot_auth_state == BotAuthState::Idle
    {
        return handle_admin_hello(state, ci);
    }

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

    // Sealed-box decrypt for ADMIN and HUB peer auth.  Frame layout:
    //   eph_pub(32) || IV(GCM_IV_LEN) || ct(N) || tag(GCM_TAG_LEN)
    if (32 + GCM_IV_LEN + GCM_TAG_LEN..=MAX_BUFFER).contains(&packet_len) {
        let mut x_priv = [0u8; 32];
        x_priv.copy_from_slice(state.hub_x25519_priv.get());

        let admin_try = crypto::seal_open(&x_priv, data, ADMIN_INFO);
        let tried_admin = admin_try
            .as_ref()
            .is_some_and(|(pt, _)| pt.len() >= 5 && &pt[..5] == b"ADMIN");

        let opened = if tried_admin {
            admin_try
        } else {
            // Retry under PEER_INFO; if that fails too there is nothing here
            // for the sealed-box path.
            crypto::seal_open(&x_priv, data, PEER_INFO)
        };
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

        if payload.starts_with("ADMIN2|") {
            return handle_admin2(state, ci, &payload, &data[..32]);
        }
        // HUBv2 is a pre-passwordless peer.  It would send a|/o| records with
        // passwords and read ours as passwords, so mixed versions must never
        // exchange state (docs/passwordless.md §3.4): refuse it by name.
        if payload.starts_with("HUBv2|") {
            let ip = state.clients[ci].ip.clone();
            hlog!(
                "[HUB] Peer {ip} speaks HUBv2 (pre-passwordless) — refusing; upgrade that hub (all hubs upgrade together)\n"
            );
            ratelimit::record_failed_auth(state, &ip);
            auth::disconnect_client(state, ci);
            return false;
        }
        if payload.starts_with("HUBv3|") {
            return handle_hubv3(state, ci, &payload);
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
        CMD_PEER_SYNC => mesh::process_peer_sync(state, payload, fd),
        CMD_MESH_STATE => mesh::process_mesh_state(state, ci, payload),
        CMD_BOT_ROSTER => presence::process_bot_roster(state, payload),
        CMD_OP_FORWARD_REQUEST => opflow::process_forward_op_request(state, ci, payload),
        CMD_OP_FORWARD_GRANT => opflow::process_forward_op_grant(state, payload),
        CMD_OP_FORWARD_FAILED => opflow::process_forward_op_failed(state, payload),
        CMD_CHAN_FWD_REQUEST => opflow::process_forward_chan_request(state, ci, payload),
        CMD_CHAN_FWD_REPLY => opflow::process_forward_chan_reply(state, ci, payload),
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
        CMD_PEER_REKEY_BOT => hlog!(
            "[HUB] Rejected CMD_PEER_REKEY_BOT from peer {}: per-bot independent keys; rekey is bot-local.\n",
            state.clients[ci].ip
        ),
        CMD_SYNC_REQUEST => {
            // The peer is asking for our full state immediately.
            hlog!(
                "[MESH] Sync request from peer {} — sending full state\n",
                state.clients[ci].ip
            );
            let reply_sync = mesh::generate_sync_packet(state);
            if !reply_sync.is_empty()
                && let Some(m) = QueuedMsg::new(CMD_PEER_SYNC, Lane::Bulk, reply_sync.as_bytes())
            {
                queue::enqueue(&mut state.clients[ci], m);
            }
        }
        // v3: independent per-hub keypairs.  A peer must NEVER push its
        // private key to us.
        CMD_UPDATE_PUBKEY => hlog!(
            "[HUB] Rejected CMD_UPDATE_PUBKEY from peer {}: per-hub independent keys; private keys do not cross hub boundaries.\n",
            state.clients[ci].ip
        ),
        _ => {}
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
        if state.clients[ci].recv_buf.len() < 4 || packets_this_call >= 8 {
            return true;
        }
        packets_this_call += 1;
        let c = &state.clients[ci];
        let packet_len = i64::from(u32::from_be_bytes([
            c.recv_buf[0],
            c.recv_buf[1],
            c.recv_buf[2],
            c.recv_buf[3],
        ]));

        // D2: bound against the client's actual buffer capacity, which is the
        // small PREAUTH_BUF_SIZE until the handshake completes.  That turns
        // the pre-auth buffer into a clean hard limit — an oversized pre-auth
        // frame is rejected here rather than hanging until the recv loop
        // fills and trips the overflow path.
        if packet_len < 0 || packet_len > (c.recv_cap as i64 - 4) {
            let (ip, cap) = (c.ip.clone(), c.recv_cap);
            hlog!("[ERROR] Invalid packet length {packet_len} from {ip} (cap {cap})\n");
            auth::disconnect_client(state, ci);
            return false;
        }
        let packet_len = packet_len as usize;
        if c.recv_buf.len() < 4 + packet_len {
            return true; // need more data
        }
        let data: Vec<u8> = c.recv_buf[4..4 + packet_len].to_vec();

        if !state.clients[ci].authenticated {
            if !handle_unauthenticated(state, ci, &data) {
                return false;
            }
        } else if packet_len > GCM_TAG_LEN {
            // Change 5: an authenticated peer frame (a full CMD_PEER_SYNC)
            // can be far larger than MAX_BUFFER — recv_cap was promoted to
            // MAX_SYNC_PAYLOAD for it — so the plaintext is sized to the
            // frame, never to a fixed 16 KB buffer.
            let (body, tag) = data.split_at(packet_len - GCM_TAG_LEN);
            let plain = crypto::aes_gcm_decrypt(body, state.clients[ci].session_key.as_ref(), tag);

            let Some(plain) = plain else {
                let ip = state.clients[ci].ip.clone();
                hlog!("[HUB] GCM tag verification failed from authenticated client {ip}\n");
                hlog!("[HUB] GCM decrypt failed from {ip}\n");
                auth::disconnect_client(state, ci);
                return false;
            };
            if plain.is_empty() {
                let ip = state.clients[ci].ip.clone();
                hlog!("[HUB] GCM decrypt failed from {ip}\n");
                auth::disconnect_client(state, ci);
                return false;
            }

            let cmd = plain[0];
            if cmd == CMD_PING {
                let t = now();
                if t - state.clients[ci].last_pong_sent >= 5 {
                    if !send_pong(state, ci) {
                        return false;
                    }
                    state.clients[ci].last_pong_sent = t;
                }
            } else {
                let payload = if plain.len() > 5 {
                    String::from_utf8_lossy(crate::cstr::until_nul_bytes(&plain[5..])).into_owned()
                } else {
                    String::new()
                };
                match state.clients[ci].typ {
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
                    ClientType::Bot => process_bot_command(state, ci, cmd, &payload),
                    ClientType::Hub => handle_peer_frame(state, ci, cmd, &payload),
                }
            }
        }

        // Remove the processed packet from the buffer.
        let consumed = 4 + packet_len;
        let Some(ci) = state.client_by_fd(fd) else {
            return false;
        };
        state.clients[ci].recv_buf.drain(..consumed);
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
}
