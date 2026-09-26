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
use crate::state::{
    BotRoster, ClientType, HubState, Lane, MeshHub, MeshLink, PeerConfig, QueuedMsg,
    UpgradeNodeKind,
};
use crate::{storage, upgrade};

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

/// hub_roster_mark_dirty(): ask for a tree push (`local`: one of our own bots
/// changed, pushed within BOT_TREE_COALESCE_LOCAL).
pub fn roster_mark_dirty(state: &mut HubState, local: bool) {
    state.tree_dirty = true;
    state.tree_dirty_local |= local;
}

/// hub_roster_expire(): drop entries nobody refreshed within the TTL.
pub fn roster_expire(state: &mut HubState, now_ts: i64) {
    let mut i = 0;
    while i < state.roster.len() {
        if now_ts - state.roster[i].reported_at > BOT_ROSTER_TTL {
            let e = &state.roster[i];
            crate::hlog_info!(
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
    let before = state.mesh_hubs.len();
    state.mesh_hubs.retain(|h| {
        let keep = now_ts - h.reported_at <= BOT_ROSTER_TTL;
        if !keep {
            crate::hlog_info!(
                "[PRESENCE] Hub {} aged out of the mesh map\n",
                if h.name.is_empty() { &h.uuid } else { &h.name }
            );
        }
        keep
    });
    if state.mesh_hubs.len() != before {
        state.tree_dirty = true;
    }
}

/// The mesh-map record for hub `uuid`, or None.
fn mesh_hub_find(state: &HubState, uuid: &str) -> Option<usize> {
    state.mesh_hubs.iter().position(|h| h.uuid == uuid)
}

/// ...created on first sight.  None when the map is full: that hub's frames
/// are then applied as before but not relayed, so a map overflow degrades to
/// the one-hop tree instead of a relay loop.
fn mesh_hub_get(state: &mut HubState, uuid: &str) -> Option<usize> {
    if let Some(i) = mesh_hub_find(state, uuid) {
        return Some(i);
    }
    if state.mesh_hubs.len() >= MAX_MESH_HUBS {
        crate::hlog_warning!(
            "[PRESENCE] Mesh map full ({MAX_MESH_HUBS}) — {uuid} is not relayed\n"
        );
        return None;
    }
    state.mesh_hubs.push(MeshHub {
        uuid: uuid.to_string(),
        round: -1,
        ..MeshHub::default()
    });
    Some(state.mesh_hubs.len() - 1)
}

/// True when our link to configured peer `p` is up right now.
fn peer_is_linked(state: &HubState, p: &PeerConfig) -> bool {
    p.fd > 0
        && state
            .clients
            .iter()
            .any(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == p.fd)
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
        crate::hlog_warning!(
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
        crate::hlog_info!(
            "[PRESENCE] Bot {id}: version {} ({}) on {}\n",
            if version.is_empty() { "?" } else { &version },
            if variant.is_empty() { "?" } else { &variant },
            if server.is_empty() {
                "(no server)"
            } else {
                &server
            }
        );
        roster_mark_dirty(state, true);
        state.last_presence_gossip = 0; // gossip the change on the next tick
    }

    // A committed node coming back on the target version is the authoritative
    // success signal for a rolling upgrade — CMD_UPGRADE_RESULT can be lost,
    // but without this frame the bot is not on the mesh at all.
    let uuid = state.clients[ci].id.clone();
    upgrade::note_presence(state, &uuid, &version, &variant);
    upgrade::rollup_note_presence(state, &uuid, UpgradeNodeKind::Bot, &version);

    // If this hub is following a run another hub drives, a local bot
    // reappearing on the followed target is that bot's authoritative success:
    // synthesize a RESULT up to the driver so a lost bot RESULT does not stall
    // the run.
    if let Some(p) = follower_presence_ok(state, &uuid, &version, &variant) {
        let origin = state.follow_origin.clone();
        if let Some(oi) = crate::upgrade::find_client_hub(state, &origin) {
            crate::queue::send_urgent(&mut state.clients[oi], CMD_UPGRADE_RESULT, &p);
        }
    }
}

/// The RESULT a follower synthesizes for a local bot seen on the followed
/// target, or `None`.  Only on the right build: for a C<->Rust switch at the
/// same version the old process announced this very version, so the variant
/// the bot was told to take (its own `=v` in the selection, else the run's)
/// must match too.  It is `back`, not `ok`, for a bot that holds its own
/// "ok" until it is back in its channels with ops — when the driver is new
/// enough to read `back` (an older one takes any unknown status as fail).
fn follower_presence_ok(
    state: &HubState,
    uuid: &str,
    version: &str,
    variant: &str,
) -> Option<String> {
    if state.follow_id.is_empty()
        || version.is_empty()
        || crate::update::version_cmp(version, &state.follow_target) != std::cmp::Ordering::Equal
    {
        return None;
    }
    let want = crate::upgrade::sel_lookup(&state.follow_sel, uuid)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| state.follow_bot_variant.clone());
    if !want.is_empty() && variant != want {
        return None;
    }
    let gated = crate::update::version_cmp(&state.follow_target, UPGRADE_OPS_GATE_MIN_BOT)
        != std::cmp::Ordering::Less;
    let driver_new = state
        .peers
        .iter()
        .find(|p| p.uuid == state.follow_origin)
        .is_some_and(|p| {
            !p.remote_version.is_empty()
                && crate::update::version_cmp(&p.remote_version, UPGRADE_SELECT_MIN_HUB)
                    != std::cmp::Ordering::Less
        });
    let status = if gated && driver_new { "back" } else { "ok" };
    Some(format!(
        "{}|{}|{status}|{}|",
        state.follow_id, uuid, version
    ))
}

/// The nick the config knows this bot by (the persisted 'n' key); empty if
/// none.
fn bot_nick_from_config(state: &HubState, uuid: &str) -> String {
    match state.bot_entry(uuid, "n") {
        Some(v) => roster_clean(v, MAX_NICK),
        None => String::new(),
    }
}

/// One roster frame to every authenticated peer except `skip`.  Deliberately
/// NOT coalesced: a large roster is chunked into several frames and
/// coalescing on one key would collapse them into whichever arrived last.
/// Best-effort on the BULK lane — a dropped frame just means those bots
/// refresh on the next tick.
///
/// Split horizon for a relayed frame (`origin` set): a peer that IS the
/// origin, or that the origin says it is linked to right now, already has it
/// first hand.  On a full mesh this leaves nothing to relay at all.
fn roster_send_to_peers(
    state: &mut HubState,
    frame: &str,
    skip: Option<usize>,
    origin: Option<usize>,
) {
    for ci in state.peer_clients() {
        if Some(ci) == skip {
            continue;
        }
        if let Some(oi) = origin {
            let cu = upgrade::peer_uuid_of(state, ci);
            let o = &state.mesh_hubs[oi];
            if !cu.is_empty() && (cu == o.uuid || o.links.iter().any(|l| l.online && l.uuid == cu))
            {
                continue;
            }
        }
        let Some(m) = QueuedMsg::new(CMD_BOT_ROSTER, Lane::Bulk, frame.as_bytes()) else {
            continue;
        };
        if !queue::enqueue(&mut state.clients[ci], m) {
            crate::hlog_warning!(
                "[PRESENCE] roster enqueue failed for peer {}\n",
                state.clients[ci].ip
            );
        }
    }
}

/// Start one gossip frame: the header lines every frame repeats, the relay
/// line, and — on the first chunk only — this hub's peer links.
fn roster_frame_begin(state: &HubState, round: i64, chunk: u32) -> String {
    let mut f = format!(
        "h|{}|{}|{}|{HUB_VERSION}\nv|{HUB_UPDATE_VARIANT}\ng|{round}|{chunk}|{ROSTER_RELAY_HOPS}\n",
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
    if chunk != 0 {
        return f;
    }
    for peer in state.peers.iter().filter(|p| !p.uuid.is_empty()) {
        let pname = roster_clean(
            if peer.friendly_name.is_empty() {
                &peer.ip
            } else {
                &peer.friendly_name
            },
            64,
        );
        f.push_str(&format!(
            "l|{}|{}|{}\n",
            peer.uuid,
            if pname.is_empty() { "-" } else { &pname },
            i32::from(peer_is_linked(state, peer))
        ));
    }
    f
}

/// Gossip the bots connected to THIS hub out to the peers.  Chunked to a byte
/// budget: each frame repeats the h| header and carries whole rows only, so a
/// receiver can apply any frame on its own without waiting for the rest.
///
/// Frame shape:
/// ```text
/// h|<hub_uuid>|<name>|<started>|<hub_version>
/// v|<hub_variant>                          (this hub's code base: c / rs)
/// g|<round>|<chunk>|<ttl>                    (relay control, see below)
/// l|<peer_uuid>|<peer_name>|<online>       (first chunk only, per peer)
/// b|<bot_uuid>|<nick>|<version>|<server>|<started>|<variant>
/// ```
/// The hub's variant is a line of its own, not a sixth h| field: a hub that
/// predates it reads everything after the version's '|' into the version
/// (roster_clean drops the '|'), which would read as "2.4.0c" and stall any
/// upgrade run waiting on "2.4.0".  Older hubs skip an unknown line, which is
/// also why g| and l| are lines of their own.  The b| variant can ride last
/// because older hubs split five fields and atoll() the start time, which
/// stops at the '|'.
///
/// g| makes the gossip multi-hop: a hub that receives a frame it has not seen
/// (origin, round, chunk) passes it on with ttl-1, so every hub hears every
/// other hub however the peers are wired.  l| is what lets a receiver draw
/// the mesh deeper than its own peers.
fn gossip_bot_roster(state: &mut HubState) {
    if state.peers.is_empty() {
        return;
    }
    let now_ts = now();
    // Generations only ever grow, across restarts too (wall-clock based), so
    // a receiver can tell a new round from a late copy of an old one.
    let round = (now_ts * 1000).max(state.roster_gen + 1);
    state.roster_gen = round;

    let mut chunk = 0u32;
    let mut frame = roster_frame_begin(state, round, chunk);
    if frame.len() >= ROSTER_FRAME_BUDGET {
        return;
    }
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
        if frame.len() + row.len() >= ROSTER_FRAME_BUDGET && rows > 0 {
            // Full: flush and start the next chunk.
            chunk += 1;
            let next = roster_frame_begin(state, round, chunk);
            let f = std::mem::replace(&mut frame, next);
            roster_send_to_peers(state, &f, None, None);
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
        roster_send_to_peers(state, &frame, None, None);
    }
    state.last_presence_gossip = now_ts;
}

/// The relay control of a roster frame: origin uuid and start time from its
/// h| line, and `(round, chunk, ttl)` from its g| line if it has one.
fn roster_frame_peek(payload: &str) -> (String, i64, Option<(i64, u32, i32)>) {
    let mut origin = String::new();
    let mut started = 0;
    let mut g = None;
    for line in payload.split('\n') {
        if let Some(body) = line.strip_prefix("h|") {
            if origin.is_empty() {
                let f: Vec<&str> = body.split('|').collect();
                origin = roster_clean(f[0], 64);
                started = f.get(2).map_or(0, |v| atoll(v));
            }
        } else if let Some(body) = line.strip_prefix("g|")
            && g.is_none()
        {
            let f: Vec<&str> = body.split('|').collect();
            if f.len() >= 3 && !f[0].is_empty() {
                g = Some((
                    atoll(f[0]),
                    atoll(f[1]).clamp(0, u32::MAX as i64) as u32,
                    atoll(f[2]).clamp(i32::MIN as i64, i32::MAX as i64) as i32,
                ));
            }
        }
    }
    (origin, started, g)
}

/// The same frame with its g| ttl replaced, for the next hop.
fn roster_frame_rettl(payload: &str, round: i64, chunk: u32, ttl: i32) -> String {
    let mut out = String::with_capacity(payload.len() + 8);
    for line in payload.split('\n').filter(|l| !l.is_empty()) {
        if line.starts_with("g|") {
            out.push_str(&format!("g|{round}|{chunk}|{ttl}\n"));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// process_bot_roster(): a hub told us which bots are on it — a peer about
/// itself, or any hub further out, relayed.  `from` is the peer link it
/// arrived on.
pub fn process_bot_roster(state: &mut HubState, from: usize, payload: &str) {
    let mut hub_uuid = String::new();
    let mut hub_name = String::new();
    let now_ts = now();

    // Relay bookkeeping first, on the untouched frame.
    let (origin, o_started, g) = roster_frame_peek(payload);
    if origin.is_empty() || origin == "-" {
        return;
    }
    if !state.hub_uuid.is_empty() && origin == state.hub_uuid {
        return; // our own gossip, back around a cycle
    }
    let mh = mesh_hub_get(state, &origin);
    if let (Some((round, chunk, _)), Some(mi)) = (g, mh) {
        let h = &mut state.mesh_hubs[mi];
        // A restarted origin starts its generations over from its clock, so a
        // new start time resets the window rather than reading as stale.
        if o_started > 0 && h.started > 0 && o_started != h.started {
            h.round = -1;
            h.chunks_seen = 0;
        }
        if round < h.round {
            return; // a late copy of an older round
        }
        let bit = if chunk < 64 { 1u64 << chunk } else { 0 };
        if round == h.round && (bit == 0 || h.chunks_seen & bit != 0) {
            return;
        }
        if round > h.round {
            h.round = round;
            h.chunks_seen = 0;
        }
        h.chunks_seen |= bit;
    }
    let relay = match (g, mh) {
        (Some((round, chunk, ttl)), Some(_)) if ttl > 1 && ttl <= ROSTER_RELAY_HOPS => {
            let r = roster_frame_rettl(payload, round, chunk, ttl - 1);
            (r.len() <= ROSTER_FRAME_BUDGET + 64).then_some(r)
        }
        _ => None,
    };
    let first_chunk = matches!(g, Some((_, 0, _)));
    let mut links_reset = false;
    // The link list this frame replaces: re-rendering every bot's tree is
    // only worth it when the list really changed, not on every gossip round.
    let mut old_links: Option<Vec<MeshLink>> = None;

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
            if hub_uuid.is_empty() {
                continue;
            }
            let sane_start = started > 0 && started <= now_ts;

            // The header doubles as the remote hub's uptime and version
            // beacon.  Clamp rather than trust: a peer's clock skew would
            // render as a negative uptime.
            if let Some(mi) = mh
                && state.mesh_hubs[mi].uuid == hub_uuid
            {
                let h = &mut state.mesh_hubs[mi];
                if h.name != hub_name
                    || h.version != hub_ver
                    || (sane_start && h.started != started)
                {
                    state.tree_dirty = true;
                }
                h.name = hub_name.clone();
                h.version = hub_ver.clone();
                if sane_start {
                    h.started = started;
                }
                h.reported_at = now_ts;
            }
            if let Some(p) = state
                .peers
                .iter_mut()
                .find(|p| !p.uuid.is_empty() && p.uuid == hub_uuid)
            {
                let mut dirty = false;
                if sane_start && p.remote_started != started {
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
            }
            // Same authoritative signal the bots give through their presence:
            // a hub node of a run we drive is done when it reappears in the
            // gossip on the target version.  Its CMD_UPGRADE_RESULT can be
            // lost — several hops more of it, now that a run reaches the whole
            // mesh — but this gossip cannot, or the hub is not on the mesh at
            // all.  Relayed gossip counts too: that is how a hub several hops
            // out reports in.
            // No roll-up here: a peer hub is never rolled up by a PREPARE from
            // its neighbour.  A peer cannot tell a single-node roll-up PREPARE
            // from a run's, so it would fan the frame out to the whole mesh —
            // and every hub holding the plan would do the same to every other,
            // which is the storm a hub-and-bot net produced.
            // No variant here: it follows on the v| line, so a hub asked to
            // switch build at the same version is proven by its RESULT alone.
            upgrade::note_presence(state, &hub_uuid, &hub_ver, "");
            continue;
        }
        if let Some(v) = line.strip_prefix("v|") {
            // The code base of the hub whose h| header this frame opened with.
            if hub_uuid.is_empty() || hub_uuid == "-" {
                continue;
            }
            let hv = roster_clean(v, ROSTER_VARIANT_MAX + 1);
            if let Some(mi) = mh
                && state.mesh_hubs[mi].uuid == hub_uuid
                && state.mesh_hubs[mi].variant != hv
            {
                state.mesh_hubs[mi].variant = hv.clone();
                state.tree_dirty = true;
            }
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
        if let Some(body) = line.strip_prefix("l|") {
            // The origin's peer links, first chunk of a round only: the list
            // replaces what we had, so a link it dropped disappears.
            let Some(mi) = mh else { continue };
            if !first_chunk || state.mesh_hubs[mi].uuid != hub_uuid {
                continue;
            }
            let h = &mut state.mesh_hubs[mi];
            if !links_reset {
                old_links = h.have_links.then(|| std::mem::take(&mut h.links));
                h.links.clear();
                h.have_links = true;
                links_reset = true;
            }
            let f: Vec<&str> = body.split('|').collect();
            if f.len() < 3 || h.links.len() >= MAX_PEERS {
                continue;
            }
            let uuid = roster_clean(f[0], 64);
            if uuid.is_empty() {
                continue;
            }
            h.links.push(MeshLink {
                uuid,
                name: roster_clean(f[1], 64),
                online: f[2].starts_with('1'),
            });
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

    if let Some(mi) = mh.filter(|_| links_reset)
        && old_links.as_ref() != Some(&state.mesh_hubs[mi].links)
    {
        state.tree_dirty = true;
    }

    // Pass it on after applying it, so the split horizon uses the links this
    // very frame just reported.
    if let Some(r) = relay {
        roster_send_to_peers(state, &r, Some(from), mh);
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
/// its own hub first, its peer hubs beneath it, and every hub further out
/// beneath the hub that links to it (from the relayed gossip).  The same
/// network legitimately renders differently depending on which bot you ask.
pub fn build_tree(state: &HubState) -> String {
    let max_len = MAX_TREE_PAYLOAD;
    // <variant> is the code base (c / rs); after it comes <started>, the
    // node's absolute start time (0 = unknown), from which the bot works out
    // the uptime itself.  A bot that predates a field splits a fixed field
    // count and never looks past it.  The old uptime field is always 0: a
    // tree that says the same thing is then the same bytes, and an unchanged
    // tree is not pushed again (push_tree_to_bots).
    let mut out = format!(
        "H|0|{}|{}|1|0|{HUB_VERSION}|{HUB_UPDATE_VARIANT}|{}\n",
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
        state.hub_started
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
            "B|1|{}|{}|{}|{}|0|{}|{}\n",
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
            if c.bot_variant.is_empty() {
                "-"
            } else {
                &c.bot_variant
            },
            c.bot_started
        ));
    }

    // Every other hub, breadth-first from here: our configured peers at
    // depth 1 (linked or not — "configured, down" is worth showing), then
    // whatever each linked hub reports it is linked to, one level further
    // out.  A hub is placed once, at the first (so the shortest) path found;
    // a hub only reported through a DOWN link is hung, unlinked, under the
    // first hub that reports it once the live mesh has been walked.  Emitted
    // depth-first below, since pre-order plus depth is what the renderer
    // reads.
    struct TreeHub {
        uuid: String,
        name: String,
        online: bool,
        depth: i32,
        parent: Option<usize>,
    }
    let cap = MAX_MESH_HUBS + MAX_PEERS + 1;
    let mut th: Vec<TreeHub> = state
        .peers
        .iter()
        .take(cap)
        .map(|peer| TreeHub {
            uuid: if peer.uuid.is_empty() {
                "-".to_string()
            } else {
                peer.uuid.clone()
            },
            name: roster_clean(
                if peer.friendly_name.is_empty() {
                    &peer.ip
                } else {
                    &peer.friendly_name
                },
                64,
            ),
            online: peer_is_linked(state, peer),
            depth: 1,
            parent: None,
        })
        .collect();
    let placed = |th: &[TreeHub], u: &str| u == state.hub_uuid || th.iter().any(|t| t.uuid == u);
    for pass in 0..2 {
        // pass 0 walks live links only; pass 1 hangs what is left, unlinked.
        let mut i = 0;
        while i < th.len() && th.len() < cap {
            if th[i].online
                && th[i].depth < MAX_TREE_DEPTH
                && let Some(mi) = mesh_hub_find(state, &th[i].uuid)
            {
                for l in &state.mesh_hubs[mi].links {
                    if th.len() >= cap {
                        break;
                    }
                    if l.online != (pass == 0) || placed(&th, &l.uuid) {
                        continue;
                    }
                    let name = match mesh_hub_find(state, &l.uuid) {
                        Some(li) if !state.mesh_hubs[li].name.is_empty() => {
                            roster_clean(&state.mesh_hubs[li].name, 64)
                        }
                        _ => roster_clean(&l.name, 64),
                    };
                    let depth = th[i].depth + 1;
                    th.push(TreeHub {
                        uuid: l.uuid.clone(),
                        name,
                        online: l.online,
                        depth,
                        parent: Some(i),
                    });
                }
            }
            i += 1;
        }
    }

    // Depth-first emission: a hub, its bots, then its child hubs.
    let mut stack: Vec<usize> = (0..th.len())
        .rev()
        .filter(|&i| th[i].parent.is_none())
        .collect();
    while let Some(i) = stack.pop() {
        if max_len - out.len() <= TREE_ROW_MAX {
            break;
        }
        let t = &th[i];
        let puuid = if t.uuid == "-" { "" } else { t.uuid.as_str() };
        // Uptime / version / code base: from our own peer record for a direct
        // peer, else from the hub's own (relayed) gossip.
        let (mut started, mut ver, mut var) = (0i64, "", "");
        if let Some(p) = state
            .peers
            .iter()
            .find(|p| !puuid.is_empty() && p.uuid == puuid)
        {
            started = p.remote_started;
            ver = &p.remote_version;
            var = &p.remote_variant;
        }
        if let Some(mi) = if puuid.is_empty() {
            None
        } else {
            mesh_hub_find(state, puuid)
        } {
            let h = &state.mesh_hubs[mi];
            if started == 0 {
                started = h.started;
            }
            if ver.is_empty() {
                ver = &h.version;
            }
            if var.is_empty() {
                var = &h.variant;
            }
        }
        out.push_str(&format!(
            "H|{}|{}|{}|{}|0|{}|{}|{}\n",
            t.depth,
            if t.name.is_empty() { "peer" } else { &t.name },
            if puuid.is_empty() { "-" } else { puuid },
            i32::from(t.online),
            if ver.is_empty() { "-" } else { ver },
            if var.is_empty() { "-" } else { var },
            started
        ));

        if !puuid.is_empty() {
            for e in state.roster.iter().filter(|e| e.hub_uuid == puuid) {
                if max_len - out.len() <= TREE_ROW_MAX {
                    break;
                }
                out.push_str(&format!(
                    "B|{}|{}|{}|{}|{}|0|{}|{}\n",
                    t.depth + 1,
                    if e.nick.is_empty() { "-" } else { &e.nick },
                    e.bot_uuid,
                    if e.version.is_empty() {
                        "-"
                    } else {
                        &e.version
                    },
                    if e.server.is_empty() { "-" } else { &e.server },
                    if e.variant.is_empty() {
                        "-"
                    } else {
                        &e.variant
                    },
                    e.connected_at
                ));
            }
        }
        for k in ((i + 1)..th.len()).rev() {
            if th[k].parent == Some(i) {
                stack.push(k);
            }
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
/// `force` false (a change) skips a bot that was already sent this exact
/// tree; the BOT_TREE_REFRESH push is forced, which is what keeps a bot's
/// tree from looking stale (BOT_TREE_STALE_AFTER) on a quiet mesh.
fn push_tree_to_bots(state: &mut HubState, force: bool) {
    let bots = state.bot_clients();
    if bots.is_empty() {
        return;
    }
    let payload = build_tree(state);
    if payload.is_empty() {
        return;
    }
    let hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(payload.as_bytes()).into()
    };
    for ci in bots {
        if !force && state.clients[ci].tree_sent_hash == Some(hash) {
            continue;
        }
        let Some(mut m) = QueuedMsg::new(CMD_BOT_TREE, Lane::Bulk, payload.as_bytes()) else {
            continue;
        };
        let coalesce = format!("{}|bot_tree|{}", state.hub_uuid, state.clients[ci].id);
        let seq = state.next_lamport_seq();
        let hub_uuid = state.hub_uuid.clone();
        m.set_coalesce(&hub_uuid, seq, &coalesce);
        let c = &mut state.clients[ci];
        c.tree_sent_hash = Some(hash);
        if !queue::enqueue(c, m) {
            c.tree_sent_hash = None;
        }
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

    // A peer link that came up or went down is news for everyone's tree and
    // for every forwarder's split horizon (`mesh::sync_send_to_peers`):
    // gossip it now rather than on the next interval.
    let mut mask = 0u32;
    for (p, peer) in state.peers.iter().enumerate().take(32) {
        if peer_is_linked(state, peer) {
            mask |= 1 << p;
        }
    }
    if mask != state.gossip_link_mask {
        // A link went down: see SYNC_RESYNC_AFTER_LINK_LOSS.
        if state.gossip_link_mask & !mask != 0 {
            state.resync_due_at = now_ts + SYNC_RESYNC_AFTER_LINK_LOSS;
        }
        state.gossip_link_mask = mask;
        state.last_presence_gossip = 0;
        state.tree_dirty = true;
    }
    if state.resync_due_at != 0 && now_ts >= state.resync_due_at {
        state.resync_due_at = 0;
        crate::mesh::request_sync_from_peers(state);
    }

    if now_ts - state.last_presence_gossip >= BOT_PRESENCE_INTERVAL {
        gossip_bot_roster(state);
    }

    // Push on change (only to bots whose tree it changes), with an
    // unconditional refresh.  Only the refresh restarts the refresh clock: a
    // change push may reach no bot at all.  Changes are coalesced (see
    // BOT_TREE_COALESCE): under churn every peer's gossip round re-rendered
    // the tree for every bot, O(hubs x bots) 10 KB frames a minute.
    let refresh = now_ts - state.last_tree_push >= BOT_TREE_REFRESH;
    let gap = if state.tree_dirty_local {
        BOT_TREE_COALESCE_LOCAL
    } else {
        BOT_TREE_COALESCE
    };
    let due = state.tree_dirty && now_ts - state.last_tree_change_push >= gap;
    if due || refresh {
        state.tree_dirty = false;
        state.tree_dirty_local = false;
        state.last_tree_change_push = now_ts;
        if refresh {
            state.last_tree_push = now_ts;
        }
        push_tree_to_bots(state, refresh);
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
    #[test]
    fn follower_ok_needs_the_right_build() {
        let mut s = HubState::new();
        assert_eq!(follower_presence_ok(&s, "b", "2.4.5", "rs"), None);
        s.follow_id = "r1".to_string();
        s.follow_target = "2.4.5".to_string();
        assert!(follower_presence_ok(&s, "b", "2.4.5", "rs").is_some());
        assert_eq!(follower_presence_ok(&s, "b", "2.4.4", "rs"), None);
        // The run's bot variant.
        s.follow_bot_variant = "c".to_string();
        assert_eq!(follower_presence_ok(&s, "b", "2.4.5", "rs"), None);
        assert!(follower_presence_ok(&s, "b", "2.4.5", "c").is_some());
        // A per-bot "=v" in the selection wins over the run's.
        s.follow_sel = "b=rs,x=c".to_string();
        assert!(follower_presence_ok(&s, "b", "2.4.5", "rs").is_some());
        assert_eq!(follower_presence_ok(&s, "b", "2.4.5", "c"), None);
        // Listed without a variant: the run's applies.
        s.follow_sel = "b".to_string();
        assert!(follower_presence_ok(&s, "b", "2.4.5", "c").is_some());
        // Addendum A1: a gated bot's report is "back" — but only to a driver
        // new enough to read it; an older one gets the old "ok".
        let p = follower_presence_ok(&s, "b", "2.4.5", "c").unwrap();
        assert_eq!(p, "r1|b|ok|2.4.5|");
        s.follow_origin = "drv".to_string();
        s.peers.push(crate::state::PeerConfig {
            uuid: "drv".to_string(),
            remote_version: "2.4.3".to_string(),
            ..Default::default()
        });
        let p = follower_presence_ok(&s, "b", "2.4.5", "c").unwrap();
        assert_eq!(p, "r1|b|back|2.4.5|");
        s.follow_target = "2.4.4".to_string();
        let p = follower_presence_ok(&s, "b", "2.4.4", "c").unwrap();
        assert_eq!(p, "r1|b|ok|2.4.4|");
    }

    use super::*;

    /// A frame that arrived on no client link (unit tests have none).
    const NO_LINK: usize = usize::MAX;

    #[test]
    fn tree_change_pushes_are_coalesced() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        let now_ts = now();
        s.hub_started = now_ts;
        s.last_tree_push = now_ts; // no forced refresh due
        s.last_presence_gossip = now_ts;
        // Mesh news inside the gap waits; the flag is held, not dropped.
        s.last_tree_change_push = now_ts - 5;
        roster_mark_dirty(&mut s, false);
        presence_tick(&mut s, now_ts);
        assert!(s.tree_dirty, "mesh news inside BOT_TREE_COALESCE waits");
        // A change to one of our own bots goes out on the short gap, and
        // carries the held mesh news with it.
        roster_mark_dirty(&mut s, true);
        presence_tick(&mut s, now_ts);
        assert!(!s.tree_dirty && !s.tree_dirty_local);
        assert_eq!(s.last_tree_change_push, now_ts);
        // Past the gap, mesh news is pushed at once (leading edge).
        s.last_tree_change_push = now_ts - BOT_TREE_COALESCE;
        roster_mark_dirty(&mut s, false);
        presence_tick(&mut s, now_ts);
        assert!(!s.tree_dirty);
    }

    #[test]
    fn relayed_roster_is_applied_once_per_round_and_chunk() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        let f = "h|far|Far|0|2.4.1\nv|c\ng|5000|0|16\nl|mid|Mid|1\nb|bot-9|nine|2.4.1|srv|0|c\n";
        process_bot_roster(&mut s, NO_LINK, f);
        assert_eq!(s.roster.len(), 1);
        let h = &s.mesh_hubs[mesh_hub_find(&s, "far").unwrap()];
        assert_eq!((h.round, h.chunks_seen, h.links.len()), (5000, 1, 1));
        assert!(h.links[0].online && h.links[0].uuid == "mid");
        // The same frame around a cycle is dropped; so is an older round.
        s.roster.clear();
        process_bot_roster(&mut s, NO_LINK, f);
        process_bot_roster(&mut s, NO_LINK, &f.replace("g|5000|", "g|4000|"));
        assert!(s.roster.is_empty());
        // Our own gossip coming back is never applied.
        process_bot_roster(&mut s, NO_LINK, &f.replace("h|far|", "h|me|"));
        assert!(s.roster.is_empty());
        // The next round is; a frame without l| lines keeps the links it had.
        process_bot_roster(&mut s, NO_LINK, &f.replace("g|5000|0|", "g|6000|1|"));
        assert_eq!(s.roster.len(), 1);
        assert_eq!(s.mesh_hubs[0].links.len(), 1);
    }

    #[test]
    fn only_a_changed_link_list_dirties_the_tree() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        let f = |round: u32, online: u8| {
            format!(
                "h|far|Far|0|2.4.1\nv|c\ng|{round}|0|16\nl|mid|Mid|{online}\nb|bot-9|nine|2.4.1|srv|0|c\n"
            )
        };
        process_bot_roster(&mut s, NO_LINK, &f(5000, 1));
        assert!(s.tree_dirty, "a first report is news");
        s.tree_dirty = false;
        process_bot_roster(&mut s, NO_LINK, &f(6000, 1));
        assert!(!s.tree_dirty, "the same links next round are not");
        process_bot_roster(&mut s, NO_LINK, &f(7000, 0));
        assert!(s.tree_dirty, "a link that went down is");
    }

    #[test]
    fn relay_rewrites_only_the_ttl() {
        let f = "h|far|Far|0|2.4.1\ng|7|0|16\nb|x|-|-|-|0\n";
        assert_eq!(
            roster_frame_rettl(f, 7, 0, 15),
            "h|far|Far|0|2.4.1\ng|7|0|15\nb|x|-|-|-|0\n"
        );
    }

    #[test]
    fn tree_hangs_hubs_beyond_the_peers_at_their_hop_distance() {
        // me - mid (direct peer, linked) - far (mid's peer) - gone (far's
        // peer, link down).
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        s.hub_friendly_name = "Me".into();
        s.peers.push(crate::state::PeerConfig {
            uuid: "mid".into(),
            friendly_name: "Mid".into(),
            ..Default::default()
        });
        s.mesh_hubs.push(MeshHub {
            uuid: "mid".into(),
            name: "Mid".into(),
            links: vec![
                MeshLink {
                    uuid: "me".into(),
                    name: "Me".into(),
                    online: true,
                },
                MeshLink {
                    uuid: "far".into(),
                    name: "Far".into(),
                    online: true,
                },
            ],
            ..MeshHub::default()
        });
        s.mesh_hubs.push(MeshHub {
            uuid: "far".into(),
            name: "Far".into(),
            links: vec![MeshLink {
                uuid: "gone".into(),
                name: "Gone".into(),
                online: false,
            }],
            ..MeshHub::default()
        });
        s.roster.push(BotRoster {
            hub_uuid: "far".into(),
            bot_uuid: "b1".into(),
            nick: "farbot".into(),
            ..Default::default()
        });
        // Without a live link to mid nothing past it is walked...
        let tree = build_tree(&s);
        assert!(tree.contains("H|1|Mid|mid|0|"));
        assert!(!tree.contains("|far|"));
        // ...but a hub reached through a linked peer is placed under it, one
        // level deeper, with its bots one deeper still.  A hub reported only
        // through a down link is hung under its reporter, unlinked.
        s.peers[0].fd = 7;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let sock = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let mut c = crate::state::HubClient::new(sock, 7, "127.0.0.1", MAX_BUFFER);
        c.typ = ClientType::Hub;
        c.authenticated = true;
        s.clients.push(c);
        let tree = build_tree(&s);
        let rows: Vec<&str> = tree.lines().collect();
        assert!(rows[1].starts_with("H|1|Mid|mid|1|"), "{tree}");
        assert!(rows[2].starts_with("H|2|Far|far|1|"), "{tree}");
        assert!(rows[3].starts_with("B|3|farbot|b1|"), "{tree}");
        assert!(rows[4].starts_with("H|3|Gone|gone|0|"), "{tree}");
    }

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
        process_bot_roster(&mut s, NO_LINK, "b|bot-1|n|v|srv|0\n");
        assert!(s.roster.is_empty());
        // A peer claiming our own bots is refused.
        process_bot_roster(&mut s, NO_LINK, "h|me|Me|0|2.0\nb|bot-1|n|v|srv|0\n");
        assert!(s.roster.is_empty());
        // A real peer's rows land.
        process_bot_roster(
            &mut s,
            NO_LINK,
            "h|them|Them|0|2.0\nb|bot-1|nick|2.3.0|irc:6667|0\n",
        );
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
            NO_LINK,
            "h|them|Them|0|2.4.0\nv|rs\nb|bot-1|n|2.4.0|srv|0|c\n",
        );
        assert_eq!(s.peers[0].remote_version, "2.4.0");
        assert_eq!(s.peers[0].remote_variant, "rs");
        assert_eq!(s.roster[0].version, "2.4.0");
        assert_eq!(s.roster[0].variant, "c");
        assert_eq!(bot_version_label(&s, "bot-1"), "2.4.0 (c)");
        // A pre-variant hub: five fields, no v| line.
        process_bot_roster(
            &mut s,
            NO_LINK,
            "h|them|Them|0|2.3.0\nb|bot-2|n|2.3.0|srv|0\n",
        );
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
            NO_LINK,
            &format!("h|them|Them|{future}|2.0\nb|bot-1|-|-|-|{future}\n"),
        );
        assert_eq!(s.roster[0].connected_at, 0);
    }

    #[test]
    fn tree_lists_offline_bots_in_the_tail() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        s.hub_friendly_name = "Me".into();
        s.hub_started = 1_700_000_000;
        storage::update_entry(&mut s, "bot-1", "n", "offbot", "", "", 100);
        storage::update_entry(&mut s, "bot-1", "seen", "", "", "", 4242);
        let tree = build_tree(&s);
        let lines: Vec<&str> = tree.lines().collect();
        // The start time is absolute and the old uptime field 0: the same
        // tree built later is the same bytes.
        assert_eq!(
            lines[0],
            format!("H|0|Me|me|1|0|{HUB_VERSION}|{HUB_UPDATE_VARIANT}|1700000000")
        );
        assert_eq!(lines[1], "D|offbot|bot-1|4242");
    }
}
