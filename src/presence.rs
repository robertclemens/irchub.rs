//! Bot presence — the data behind the bot's `bots` tree (hub_logic.c).
//!
//! Three hops, none of which touch the config store:
//!   1. bot  -> hub   CMD_BOT_PRESENCE  its version, IRC server, start time
//!   2. hub <-> hub   CMD_BOT_ROSTER    the bots connected to THIS hub
//!   3. hub  -> bot   CMD_BOT_TREE      the assembled tree, DFS pre-order
//!
//! Everything here is volatile and TTL'd.  A bot that disconnects stops being
//! reported and ages out; a hub that dies takes its whole branch with it.
//! The only persisted data read is identity (nick) and `seen`, both already
//! in the config, used to list bots that are known but currently offline.

use crate::consts::*;
use crate::cstr::{atoll, now, trunc_string};
use crate::queue;
use crate::state::{BotRoster, ClientType, HubState, Lane, QueuedMsg, UpgradeNodeKind};
use crate::{hlog, storage, upgrade};

/// Sanitize one field arriving from a bot or a peer before it is stored or
/// echoed into a tree row.  Presence text is attacker-controlled: it reaches
/// other operators' IRC clients, so '|' (our field separator), CR/LF and any
/// other control byte are dropped outright rather than escaped.
pub fn roster_clean(src: &str, cap: usize) -> String {
    let filtered: String = src
        .chars()
        .filter(|&c| c >= '\u{20}' && c != '\u{7f}' && c != '|')
        .collect();
    trunc_string(&filtered, cap)
}

/// hub_roster_mark_dirty(): ask for a tree push on the next tick.
pub fn roster_mark_dirty(state: &mut HubState) {
    state.tree_dirty = true;
}

/// hub_roster_expire(): drop entries nobody refreshed within the TTL.
pub fn roster_expire(state: &mut HubState, now_ts: i64) {
    let mut i = 0;
    while i < state.roster.len() {
        if now_ts - state.roster[i].reported_at > BOT_ROSTER_TTL {
            let e = &state.roster[i];
            hlog!(
                "[PRESENCE] {} on hub {} aged out of the roster\n",
                if e.nick.is_empty() {
                    &e.bot_uuid
                } else {
                    &e.nick
                },
                e.hub_name
            );
            state.roster.swap_remove(i);
            state.tree_dirty = true;
            continue; // the swapped-in entry still needs checking
        }
        i += 1;
    }
}

/// Upsert one reported bot.  Keyed on (reporting hub, bot) so the same bot
/// briefly reported by two hubs mid-migration shows up once per hub rather
/// than flapping — the stale one expires on its own.
fn roster_upsert(state: &mut HubState, incoming: BotRoster) {
    if let Some(i) = state
        .roster
        .iter()
        .position(|e| e.hub_uuid == incoming.hub_uuid && e.bot_uuid == incoming.bot_uuid)
    {
        let e = &state.roster[i];
        // An unchanged report just refreshes the TTL; only a real change is
        // worth re-rendering every bot's tree for.
        let changed = e.nick != incoming.nick
            || e.version != incoming.version
            || e.variant != incoming.variant
            || e.server != incoming.server
            || e.connected_at != incoming.connected_at;
        state.roster[i] = incoming;
        if changed {
            state.tree_dirty = true;
        }
        return;
    }
    if state.roster.len() >= MAX_BOT_ROSTER {
        hlog!(
            "[PRESENCE] Roster full ({MAX_BOT_ROSTER}) — dropping report for {}\n",
            incoming.bot_uuid
        );
        return;
    }
    state.roster.push(incoming);
    state.tree_dirty = true;
}

/// process_bot_presence(): this bot just told us what it is running.  Per
/// connection and volatile.
pub fn process_bot_presence(state: &mut HubState, ci: usize, payload: &str) {
    // "<version>|<server>|<started>|<variant>" — a short, fixed shape.  The
    // variant (code base, c / rs) is the newest field; a bot that predates it
    // sends three and simply shows no code base.  Anything longer than the
    // field caps is truncated by roster_clean, never rejected, so a newer bot
    // advertising more never drops off the tree entirely.
    let work = trunc_string(
        payload,
        ROSTER_VERSION_MAX + ROSTER_SERVER_MAX + ROSTER_VARIANT_MAX + 64,
    );
    let mut version_src = work.as_str();
    let mut server = String::new();
    let mut variant = String::new();
    let mut started = 0i64;
    if let Some(p1) = work.find('|') {
        version_src = &work[..p1];
        let rest = &work[p1 + 1..];
        let server_src = match rest.find('|') {
            Some(p2) => {
                let tail = &rest[p2 + 1..];
                started = atoll(tail);
                if let Some(p3) = tail.find('|') {
                    // Room for fields after it: stop at the next '|'.
                    let v = tail[p3 + 1..].split('|').next().unwrap_or("");
                    variant = roster_clean(v, ROSTER_VARIANT_MAX + 1);
                }
                &rest[..p2]
            }
            None => rest,
        };
        server = roster_clean(server_src, ROSTER_SERVER_MAX + 1);
    }
    let version = roster_clean(version_src, ROSTER_VERSION_MAX + 1);

    // A bot cannot claim to have started in the future, nor before the epoch
    // of this mesh; an out-of-range value just means "unknown uptime".
    let now_ts = now();
    if started <= 0 || started > now_ts {
        started = 0;
    }

    let c = &mut state.clients[ci];
    let changed = c.bot_version != version
        || c.bot_server != server
        || c.bot_variant != variant
        || c.bot_started != started;
    c.bot_version = version.clone();
    c.bot_server = server.clone();
    c.bot_variant = variant.clone();
    c.bot_started = started;

    if changed {
        let id = c.id.clone();
        hlog!(
            "[PRESENCE] Bot {id}: version {} ({}) on {}\n",
            if version.is_empty() { "?" } else { &version },
            if variant.is_empty() { "?" } else { &variant },
            if server.is_empty() {
                "(no server)"
            } else {
                &server
            }
        );
        state.tree_dirty = true;
        state.last_presence_gossip = 0; // gossip the change on the next tick
    }

    // A committed node coming back on the target version is the authoritative
    // success signal for a rolling upgrade — CMD_UPGRADE_RESULT can be lost,
    // but without this frame the bot is not on the mesh at all.
    let uuid = state.clients[ci].id.clone();
    upgrade::note_presence(state, &uuid, &version);
    upgrade::rollup_note_presence(state, &uuid, UpgradeNodeKind::Bot, &version);

    // If this hub is following a run another hub drives, a local bot
    // reappearing on the followed target is that bot's authoritative success:
    // synthesize a RESULT up to the driver so a lost bot RESULT does not stall
    // the run.
    if !state.follow_id.is_empty() && !version.is_empty() && state.follow_target == version {
        let origin = state.follow_origin.clone();
        if let Some(oi) = crate::upgrade::find_client_hub(state, &origin) {
            let p = format!("{}|{}|ok|{}|", state.follow_id, uuid, version);
            crate::queue::send_urgent(&mut state.clients[oi], CMD_UPGRADE_RESULT, &p);
        }
    }
}

/// The nick the config knows this bot by (the persisted 'n' key); empty if
/// none.
fn bot_nick_from_config(state: &HubState, uuid: &str) -> String {
    match state.bot_entry(uuid, "n") {
        Some(v) => roster_clean(v, MAX_NICK),
        None => String::new(),
    }
}

/// One roster frame to every authenticated peer.  Deliberately NOT
/// coalesced: a large roster is chunked into several frames and coalescing on
/// one key would collapse them into whichever arrived last.  Best-effort on
/// the BULK lane — a dropped frame just means those bots refresh on the next
/// tick.
fn roster_send_to_peers(state: &mut HubState, frame: &str) {
    for ci in state.peer_clients() {
        let Some(m) = QueuedMsg::new(CMD_BOT_ROSTER, Lane::Bulk, frame.as_bytes()) else {
            continue;
        };
        if !queue::enqueue(&mut state.clients[ci], m) {
            hlog!(
                "[PRESENCE] roster enqueue failed for peer {}\n",
                state.clients[ci].ip
            );
        }
    }
}

/// Gossip the bots connected to THIS hub out to the peers.  Chunked to a byte
/// budget: each frame repeats the h| header and carries whole rows only, so a
/// receiver can apply any frame on its own without waiting for the rest.
///
/// Frame shape:
/// ```text
/// h|<hub_uuid>|<name>|<started>|<hub_version>
/// v|<hub_variant>                          (this hub's code base: c / rs)
/// b|<bot_uuid>|<nick>|<version>|<server>|<started>|<variant>
/// ```
/// The hub's variant is a line of its own, not a sixth h| field: a hub that
/// predates it reads everything after the version's '|' into the version
/// (roster_clean drops the '|'), which would read as "2.4.0c" and stall any
/// upgrade run waiting on "2.4.0".  Older hubs skip an unknown line.  The b|
/// variant can ride last because older hubs split five fields and atoll() the
/// start time, which stops at the '|'.
fn gossip_bot_roster(state: &mut HubState) {
    if state.peers.is_empty() {
        return;
    }
    let now_ts = now();
    let header = format!(
        "h|{}|{}|{}|{HUB_VERSION}\nv|{HUB_UPDATE_VARIANT}\n",
        if state.hub_uuid.is_empty() {
            "-"
        } else {
            &state.hub_uuid
        },
        if state.hub_friendly_name.is_empty() {
            "-"
        } else {
            &state.hub_friendly_name
        },
        state.hub_started
    );
    if header.len() >= ROSTER_FRAME_BUDGET {
        return;
    }

    let mut frame = header.clone();
    let mut rows = 0;
    let mut frames = 0;

    for ci in state.bot_clients() {
        let c = &state.clients[ci];
        let nick = bot_nick_from_config(state, &c.id);
        let c = &state.clients[ci];
        let row = format!(
            "b|{}|{}|{}|{}|{}|{}\n",
            c.id,
            if nick.is_empty() { "-" } else { &nick },
            if c.bot_version.is_empty() {
                "-"
            } else {
                &c.bot_version
            },
            if c.bot_server.is_empty() {
                "-"
            } else {
                &c.bot_server
            },
            c.bot_started,
            if c.bot_variant.is_empty() {
                "-"
            } else {
                &c.bot_variant
            }
        );
        if row.len() >= TREE_ROW_MAX {
            continue; // an unrepresentable row
        }
        if frame.len() + row.len() >= ROSTER_FRAME_BUDGET {
            // Full: flush and restart.
            let f = std::mem::replace(&mut frame, header.clone());
            roster_send_to_peers(state, &f);
            frames += 1;
            rows = 0;
        }
        if frame.len() + row.len() >= ROSTER_FRAME_BUDGET {
            continue; // still won't fit
        }
        frame.push_str(&row);
        rows += 1;
    }

    // Always send a final frame, even carrying no bots: the header doubles as
    // this hub's liveness and uptime beacon, which is what lets a peer show
    // an empty hub in the tree with a real uptime instead of a blank.
    if rows > 0 || frames == 0 {
        roster_send_to_peers(state, &frame);
    }
    state.last_presence_gossip = now_ts;
}

/// process_bot_roster(): a peer told us which bots are on it.
pub fn process_bot_roster(state: &mut HubState, payload: &str) {
    let mut hub_uuid = String::new();
    let mut hub_name = String::new();
    let now_ts = now();

    for line in payload.split('\n') {
        if let Some(body) = line.strip_prefix("h|") {
            let f = crate::cstr::split_fields(body, 4);
            if f.len() < 2 {
                continue;
            }
            let mut started = 0i64;
            let mut hub_ver = String::new();
            if f.len() >= 3 {
                started = atoll(f[2]);
                if f.len() >= 4 {
                    hub_ver = roster_clean(f[3], ROSTER_VERSION_MAX + 1);
                }
            }
            hub_uuid = roster_clean(f[0], 64);
            hub_name = roster_clean(f[1], 64);

            // The header doubles as the remote hub's uptime and version
            // beacon.  Clamp rather than trust: a peer's clock skew would
            // render as a negative uptime.
            if !hub_uuid.is_empty()
                && let Some(p) = state
                    .peers
                    .iter_mut()
                    .find(|p| !p.uuid.is_empty() && p.uuid == hub_uuid)
            {
                let mut dirty = false;
                if started > 0 && started <= now_ts && p.remote_started != started {
                    p.remote_started = started;
                    dirty = true;
                }
                if p.remote_version != hub_ver {
                    p.remote_version = hub_ver.clone();
                    dirty = true;
                }
                if dirty {
                    state.tree_dirty = true;
                }
                // Same authoritative signal the bots give through their
                // presence: a hub node of a run we drive is done when it
                // reappears in the gossip on the target version.  Its
                // CMD_UPGRADE_RESULT can be lost — several hops more of it,
                // now that a run reaches the whole mesh — but this gossip
                // cannot, or the hub is not on the mesh at all.
                upgrade::note_presence(state, &hub_uuid, &hub_ver);
                // No roll-up here: a peer hub is never rolled up by a PREPARE
                // from its neighbour.  A peer cannot tell a single-node
                // roll-up PREPARE from a run's, so it would fan the frame out
                // to the whole mesh — and every hub holding the plan would do
                // the same to every other, which is the storm a hub-and-bot
                // net produced.
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("v|") {
            // The code base of the hub whose h| header this frame opened with.
            if hub_uuid.is_empty() || hub_uuid == "-" {
                continue;
            }
            let hv = roster_clean(v, ROSTER_VARIANT_MAX + 1);
            if let Some(p) = state
                .peers
                .iter_mut()
                .find(|p| !p.uuid.is_empty() && p.uuid == hub_uuid)
                && p.remote_variant != hv
            {
                p.remote_variant = hv;
                state.tree_dirty = true;
            }
            continue;
        }
        let Some(body) = line.strip_prefix("b|") else {
            continue;
        };
        // A row before its header has no hub to hang off — ignore it rather
        // than guess, so a malformed frame cannot graft bots onto the wrong
        // branch.
        if hub_uuid.is_empty() || hub_uuid == "-" {
            continue;
        }
        // Never let a peer report bots as belonging to US: our own branch is
        // built from our live client list and nothing else.
        if !state.hub_uuid.is_empty() && hub_uuid == state.hub_uuid {
            continue;
        }

        // Five fields from any hub; a sixth (the bot's code base) from one
        // that knows it.
        let f = crate::cstr::split_fields(body, 6);
        if f.len() < 5 || f[0].is_empty() {
            continue;
        }
        let bot_uuid = roster_clean(f[0], 64);
        if bot_uuid.is_empty() {
            continue;
        }
        let started = atoll(f[4]);
        let e = BotRoster {
            hub_uuid: hub_uuid.clone(),
            hub_name: if hub_name.is_empty() {
                hub_uuid.clone()
            } else {
                hub_name.clone()
            },
            bot_uuid,
            nick: if f[1] == "-" {
                String::new()
            } else {
                roster_clean(f[1], MAX_NICK)
            },
            version: if f[2] == "-" {
                String::new()
            } else {
                roster_clean(f[2], ROSTER_VERSION_MAX + 1)
            },
            variant: if f.len() < 6 || f[5] == "-" {
                String::new()
            } else {
                roster_clean(f[5], ROSTER_VARIANT_MAX + 1)
            },
            server: if f[3] == "-" {
                String::new()
            } else {
                roster_clean(f[3], ROSTER_SERVER_MAX + 1)
            },
            // Clamp a peer's clock skew rather than trusting it: a future
            // start time would render as a negative uptime.
            connected_at: if started > 0 && started <= now_ts {
                started
            } else {
                0
            },
            reported_at: now_ts,
        };
        roster_upsert(state, e);
    }
}

/// hub_build_tree(): the tree for the bots on THIS hub, in DFS pre-order.
///
/// Row shapes:
/// ```text
/// H|<depth>|<name>|<uuid>|<online>|<uptime>|<version>|<variant>
/// B|<depth>|<nick>|<uuid>|<version>|<server>|<uptime>|<variant>
/// D|<nick>|<uuid>|<last_seen>            (offline; always the tail)
/// ```
///
/// `<variant>` is the code base (c / rs), always the last field: a bot that
/// predates it splits a fixed field count and never looks past uptime or
/// version, so the extra field is invisible to it.
///
/// Depth plus pre-order is all a renderer needs to draw the connectors: a
/// node is the last child at its level when no later row shares its depth
/// before a shallower one appears.  The bot does the drawing so the glyphs
/// can change without a hub deploy.
///
/// Rooted at this hub because that is the vantage point the asking bot has:
/// its own hub first, peer hubs beneath it.  The mesh is flat, so the same
/// network legitimately renders differently depending on which bot you ask.
pub fn build_tree(state: &HubState) -> String {
    let max_len = MAX_TREE_PAYLOAD;
    let now_ts = now();
    let mut out = format!(
        "H|0|{}|{}|1|{}|{HUB_VERSION}|{HUB_UPDATE_VARIANT}\n",
        if state.hub_friendly_name.is_empty() {
            "hub"
        } else {
            &state.hub_friendly_name
        },
        if state.hub_uuid.is_empty() {
            "-"
        } else {
            &state.hub_uuid
        },
        if state.hub_started != 0 {
            now_ts - state.hub_started
        } else {
            0
        }
    );
    if out.len() >= max_len {
        return String::new();
    }

    // Our own bots, from the live client list — never from a peer's report.
    for ci in state.bot_clients() {
        if max_len - out.len() <= TREE_ROW_MAX {
            break;
        }
        let c = &state.clients[ci];
        let nick = bot_nick_from_config(state, &c.id);
        out.push_str(&format!(
            "B|1|{}|{}|{}|{}|{}|{}\n",
            if nick.is_empty() { "-" } else { &nick },
            c.id,
            if c.bot_version.is_empty() {
                "-"
            } else {
                &c.bot_version
            },
            if c.bot_server.is_empty() {
                "-"
            } else {
                &c.bot_server
            },
            if c.bot_started != 0 {
                now_ts - c.bot_started
            } else {
                0
            },
            if c.bot_variant.is_empty() {
                "-"
            } else {
                &c.bot_variant
            }
        ));
    }

    // Peer hubs at depth 1, each followed by its bots at depth 2.  A peer we
    // have no roster for still gets its node — "linked, nothing reported yet"
    // is more useful than silently omitting a hub that is plainly there.
    for peer in &state.peers {
        if max_len - out.len() <= TREE_ROW_MAX {
            break;
        }
        let online = peer.fd > 0
            && state
                .clients
                .iter()
                .any(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == peer.fd);
        let pname = roster_clean(
            if peer.friendly_name.is_empty() {
                &peer.ip
            } else {
                &peer.friendly_name
            },
            64,
        );
        out.push_str(&format!(
            "H|1|{}|{}|{}|{}|{}|{}\n",
            if pname.is_empty() { "peer" } else { &pname },
            if peer.uuid.is_empty() {
                "-"
            } else {
                &peer.uuid
            },
            i32::from(online),
            if peer.remote_started != 0 {
                now_ts - peer.remote_started
            } else {
                0
            },
            if peer.remote_version.is_empty() {
                "-"
            } else {
                &peer.remote_version
            },
            if peer.remote_variant.is_empty() {
                "-"
            } else {
                &peer.remote_variant
            }
        ));

        if peer.uuid.is_empty() {
            continue;
        }
        for e in state.roster.iter().filter(|e| e.hub_uuid == peer.uuid) {
            if max_len - out.len() <= TREE_ROW_MAX {
                break;
            }
            out.push_str(&format!(
                "B|2|{}|{}|{}|{}|{}|{}\n",
                if e.nick.is_empty() { "-" } else { &e.nick },
                e.bot_uuid,
                if e.version.is_empty() {
                    "-"
                } else {
                    &e.version
                },
                if e.server.is_empty() { "-" } else { &e.server },
                if e.connected_at != 0 {
                    now_ts - e.connected_at
                } else {
                    0
                },
                if e.variant.is_empty() {
                    "-"
                } else {
                    &e.variant
                }
            ));
        }
    }

    // Bots the config knows but nobody currently reports.  'seen' is already
    // persisted and replicated, so this needs no new storage — it is the one
    // place the tree reads the config store, and it reads it read-only.
    for b in state.bots.iter().filter(|b| b.is_active) {
        if max_len - out.len() <= TREE_ROW_MAX {
            break;
        }
        let live = state
            .clients
            .iter()
            .any(|c| c.typ == ClientType::Bot && c.authenticated && c.id == b.uuid)
            || state.roster.iter().any(|r| r.bot_uuid == b.uuid);
        if live {
            continue;
        }
        let mut last_seen = b.last_sync_time;
        let mut nick = String::new();
        for e in &b.entries {
            if e.key == "seen" {
                if e.timestamp > last_seen {
                    last_seen = e.timestamp;
                }
            } else if e.key == "n" {
                nick = roster_clean(&e.value, MAX_NICK);
            }
        }
        out.push_str(&format!(
            "D|{}|{}|{}\n",
            if nick.is_empty() { "-" } else { &nick },
            b.uuid,
            last_seen
        ));
    }
    out
}

/// Push the assembled tree to every connected bot.  Coalesced per bot so a
/// burst of roster changes collapses to one send per drain cycle.
fn push_tree_to_bots(state: &mut HubState) {
    let bots = state.bot_clients();
    if bots.is_empty() {
        return;
    }
    let payload = build_tree(state);
    if payload.is_empty() {
        return;
    }
    for ci in bots {
        let Some(mut m) = QueuedMsg::new(CMD_BOT_TREE, Lane::Bulk, payload.as_bytes()) else {
            continue;
        };
        let coalesce = format!("{}|bot_tree|{}", state.hub_uuid, state.clients[ci].id);
        let seq = state.next_lamport_seq();
        let hub_uuid = state.hub_uuid.clone();
        m.set_coalesce(&hub_uuid, seq, &coalesce);
        queue::enqueue(&mut state.clients[ci], m);
    }
}

/// hub_presence_tick(): drives both halves on the maintenance clock.  It
/// gossips this hub's own connected bots to the peers every
/// BOT_PRESENCE_INTERVAL and pushes a refreshed tree down to the bots when
/// the roster changed (or every BOT_TREE_REFRESH regardless, so a bot that
/// missed a frame — or connected between changes — still converges).
pub fn presence_tick(state: &mut HubState, now_ts: i64) {
    if state.hub_started == 0 {
        state.hub_started = now_ts;
    }

    roster_expire(state, now_ts);

    if now_ts - state.last_presence_gossip >= BOT_PRESENCE_INTERVAL {
        gossip_bot_roster(state);
    }

    if state.tree_dirty || now_ts - state.last_tree_push >= BOT_TREE_REFRESH {
        state.tree_dirty = false;
        state.last_tree_push = now_ts;
        push_tree_to_bots(state);
    }
}

/// bot_version_label(): "<version> (<code base>)" for a bot that is on the
/// mesh right now, e.g. "2.4.0 (rs)": our own live client first, else the
/// freshest peer report.  The bare version when the reporter did not say
/// which code base, "-" when nobody reports the bot at all.  For hub_admin's
/// bot list.
pub fn bot_version_label(state: &HubState, uuid: &str) -> String {
    let (ver, var) = if let Some(c) = state
        .clients
        .iter()
        .find(|c| c.typ == ClientType::Bot && c.authenticated && c.id == uuid)
    {
        (c.bot_version.as_str(), c.bot_variant.as_str())
    } else {
        let mut best: Option<&BotRoster> = None;
        for e in state.roster.iter().filter(|e| e.bot_uuid == uuid) {
            if best.is_none_or(|b| e.reported_at >= b.reported_at) {
                best = Some(e);
            }
        }
        best.map_or(("", ""), |e| (e.version.as_str(), e.variant.as_str()))
    };
    if ver.is_empty() {
        "-".to_string()
    } else if var.is_empty() {
        ver.to_string()
    } else {
        format!("{ver} ({var})")
    }
}

/// The `seen`/nick lookup the offline tail of the tree uses, exported for the
/// admin listing that shows the same value.
pub fn bot_last_seen(state: &HubState, uuid: &str) -> i64 {
    let Some(b) = state.bots.iter().find(|b| b.uuid == uuid) else {
        return 0;
    };
    let mut last = b.last_sync_time;
    if let Some(e) = b.entry("seen")
        && e.timestamp > last
    {
        last = e.timestamp;
    }
    last
}

/// Re-exported so the admin path can register a bot without importing
/// `storage` itself.
pub fn note_seen(state: &mut HubState, uuid: &str, ts: i64) {
    storage::update_entry(state, uuid, "seen", "", "", "", ts);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_clean_drops_separators_and_controls() {
        assert_eq!(roster_clean("ok", 32), "ok");
        assert_eq!(roster_clean("a|b", 32), "ab");
        assert_eq!(roster_clean("a\r\nb", 32), "ab");
        assert_eq!(roster_clean("a\u{7f}b", 32), "ab");
        // cap is the C buffer size, so cap-1 bytes survive.
        assert_eq!(roster_clean("abcdef", 4), "abc");
    }

    #[test]
    fn roster_expire_drops_stale_and_keeps_fresh() {
        let mut s = HubState::new();
        let t = now();
        s.roster.push(BotRoster {
            hub_uuid: "h1".into(),
            bot_uuid: "b1".into(),
            reported_at: t - BOT_ROSTER_TTL - 1,
            ..Default::default()
        });
        s.roster.push(BotRoster {
            hub_uuid: "h1".into(),
            bot_uuid: "b2".into(),
            reported_at: t,
            ..Default::default()
        });
        roster_expire(&mut s, t);
        assert_eq!(s.roster.len(), 1);
        assert_eq!(s.roster[0].bot_uuid, "b2");
        assert!(s.tree_dirty);
    }

    #[test]
    fn roster_ignores_rows_before_a_header_and_our_own_uuid() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        // A row with no header has no hub to hang off.
        process_bot_roster(&mut s, "b|bot-1|n|v|srv|0\n");
        assert!(s.roster.is_empty());
        // A peer claiming our own bots is refused.
        process_bot_roster(&mut s, "h|me|Me|0|2.0\nb|bot-1|n|v|srv|0\n");
        assert!(s.roster.is_empty());
        // A real peer's rows land.
        process_bot_roster(&mut s, "h|them|Them|0|2.0\nb|bot-1|nick|2.3.0|irc:6667|0\n");
        assert_eq!(s.roster.len(), 1);
        assert_eq!(s.roster[0].hub_name, "Them");
        assert_eq!(s.roster[0].nick, "nick");
        assert_eq!(s.roster[0].server, "irc:6667");
    }

    #[test]
    fn roster_carries_the_code_base_and_tolerates_its_absence() {
        let mut s = HubState::new();
        s.peers.push(crate::state::PeerConfig {
            uuid: "them".into(),
            ..Default::default()
        });
        // A new hub: v| line for itself, a sixth b| field per bot.
        process_bot_roster(
            &mut s,
            "h|them|Them|0|2.4.0\nv|rs\nb|bot-1|n|2.4.0|srv|0|c\n",
        );
        assert_eq!(s.peers[0].remote_version, "2.4.0");
        assert_eq!(s.peers[0].remote_variant, "rs");
        assert_eq!(s.roster[0].version, "2.4.0");
        assert_eq!(s.roster[0].variant, "c");
        assert_eq!(bot_version_label(&s, "bot-1"), "2.4.0 (c)");
        // A pre-variant hub: five fields, no v| line.
        process_bot_roster(&mut s, "h|them|Them|0|2.3.0\nb|bot-2|n|2.3.0|srv|0\n");
        assert_eq!(s.roster[1].variant, "");
        assert_eq!(bot_version_label(&s, "bot-2"), "2.3.0");
        assert_eq!(bot_version_label(&s, "nobody"), "-");
    }

    #[test]
    fn roster_clamps_a_future_start_time() {
        let mut s = HubState::new();
        let future = now() + 86400;
        process_bot_roster(
            &mut s,
            &format!("h|them|Them|{future}|2.0\nb|bot-1|-|-|-|{future}\n"),
        );
        assert_eq!(s.roster[0].connected_at, 0);
    }

    #[test]
    fn tree_lists_offline_bots_in_the_tail() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        s.hub_friendly_name = "Me".into();
        s.hub_started = now() - 60;
        storage::update_entry(&mut s, "bot-1", "n", "offbot", "", "", 100);
        storage::update_entry(&mut s, "bot-1", "seen", "", "", "", 4242);
        let tree = build_tree(&s);
        let lines: Vec<&str> = tree.lines().collect();
        assert_eq!(
            lines[0],
            format!("H|0|Me|me|1|60|{HUB_VERSION}|{HUB_UPDATE_VARIANT}")
        );
        assert_eq!(lines[1], "D|offbot|bot-1|4242");
    }
}
