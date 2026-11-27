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
                "[PRESENCE] {} on {} aged out of the roster\n",
                state.who('b', &e.bot_uuid),
                state.who('h', &e.hub_uuid)
            );
            state.roster.swap_remove(i);
            state.tree_dirty = true;
            continue; // the swapped-in entry still needs checking
        }
        i += 1;
    }
    let before = state.mesh_hubs.len();
    for h in state
        .mesh_hubs
        .iter()
        .filter(|h| now_ts - h.reported_at > BOT_ROSTER_TTL)
    {
        crate::hlog_info!(
            "[PRESENCE] {} aged out of the mesh map\n",
            state.who('h', &h.uuid)
        );
    }
    state
        .mesh_hubs
        .retain(|h| now_ts - h.reported_at <= BOT_ROSTER_TTL);
    if state.mesh_hubs.len() != before {
        state.tree_dirty = true;
    }
}

/// The mesh-map record for hub `uuid`, or None.
pub fn mesh_hub_find(state: &HubState, uuid: &str) -> Option<usize> {
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
            "[PRESENCE] Mesh map full ({MAX_MESH_HUBS}) — {uuid} is not relayed\n",
            uuid = state.who('h', uuid)
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
pub fn peer_is_linked(state: &HubState, p: &PeerConfig) -> bool {
    p.fd > 0
        && state
            .clients
            .iter()
            .any(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == p.fd)
}

/// Upsert one reported bot.  Keyed on (reporting hub, bot) so the same bot
/// briefly reported by two hubs mid-migration shows up once per hub rather
/// than flapping — the stale one expires on its own.
/// A bot has one hub link at a time: entries for it under any other hub than
/// `keep_hub` that are older than this sighting describe where it was.  `since`
/// 0 (with link_ord 0) drops them all — an authoritative local link.  Phase 4:
/// when both this sighting and the old entry carry a link-order counter the
/// counter decides; otherwise it falls back to the hubs' `link_since` clocks.
pub fn roster_evict_moved(
    state: &mut HubState,
    bot_uuid: &str,
    keep_hub: &str,
    since: i64,
    link_ord: u64,
) {
    let mut i = 0;
    while i < state.roster.len() {
        let e = &state.roster[i];
        let older = if e.bot_uuid != bot_uuid || e.hub_uuid == keep_hub {
            false
        } else if since == 0 && link_ord == 0 {
            true
        } else if link_ord > 0 && e.link_ord > 0 {
            e.link_ord < link_ord
        } else {
            e.link_since > 0 && since > 0 && e.link_since < since
        };
        if older {
            crate::hlog_debug!(
                "[PRESENCE] {} moved off {}\n",
                state.who('b', &e.bot_uuid),
                state.who('h', &e.hub_uuid)
            );
            state.roster.swap_remove(i);
            state.tree_dirty = true;
            continue;
        }
        i += 1;
    }
}

/// Every chunk 0..`last_chunk` of hub `mi`'s round has been applied: its bots the
/// round did not list have left it.
fn roster_round_done(state: &mut HubState, mi: usize, last_chunk: u32) {
    if last_chunk >= 64 {
        return;
    }
    let all = if last_chunk == 63 {
        u64::MAX
    } else {
        (1u64 << (last_chunk + 1)) - 1
    };
    let (uuid, round) = {
        let h = &state.mesh_hubs[mi];
        if h.chunks_seen & all != all {
            return;
        }
        (h.uuid.clone(), h.round)
    };
    let mut i = 0;
    while i < state.roster.len() {
        let e = &state.roster[i];
        if e.hub_uuid == uuid && e.round != round {
            crate::hlog_debug!(
                "[PRESENCE] {} left {}\n",
                state.who('b', &e.bot_uuid),
                state.who('h', &e.hub_uuid)
            );
            state.roster.swap_remove(i);
            state.tree_dirty = true;
            continue;
        }
        i += 1;
    }
}

fn roster_upsert(state: &mut HubState, incoming: BotRoster) {
    // A deleted bot, reported by a hub that has not heard yet.
    if crate::revoke::is_revoked(state, &incoming.bot_uuid) {
        return;
    }
    // The bot is linked here now and this report is older: it is where it was.
    // Phase 4: the bot's link-order counter decides when both sightings carry
    // it, else the hub clocks (its link time vs our local connect time).
    if state.bot_clients().into_iter().any(|ci| {
        let c = &state.clients[ci];
        c.id == incoming.bot_uuid
            && if incoming.link_ord > 0 && c.bot_link_ord > 0 {
                incoming.link_ord <= c.bot_link_ord
            } else {
                incoming.link_since > 0 && incoming.link_since <= c.connected_at
            }
    }) {
        return;
    }
    if incoming.link_since > 0 || incoming.link_ord > 0 {
        let (b, h) = (incoming.bot_uuid.clone(), incoming.hub_uuid.clone());
        roster_evict_moved(state, &b, &h, incoming.link_since, incoming.link_ord);
    }
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
        // Phase 4: a report with no counter (a p2 reconcile, which does not
        // carry it this release) must not wipe one the legacy gossip learned.
        let keep_ord = e.link_ord;
        let hub = incoming.hub_uuid.clone();
        state.roster[i] = incoming;
        if state.roster[i].link_ord == 0 && keep_ord > 0 {
            state.roster[i].link_ord = keep_ord;
        }
        state.roster[i].p2_stamp = p2_next_stamp(state);
        crate::presence2::roster_touched(state, &hub);
        if changed {
            state.tree_dirty = true;
        }
        return;
    }
    if state.roster.len() >= MAX_BOT_ROSTER {
        crate::hlog_warning!(
            "[PRESENCE] Roster full ({MAX_BOT_ROSTER}) — dropping report for {}\n",
            state.who('b', &incoming.bot_uuid)
        );
        return;
    }
    let mut incoming = incoming;
    incoming.p2_stamp = p2_next_stamp(state);
    let hub = incoming.hub_uuid.clone();
    state.roster.push(incoming);
    crate::presence2::roster_touched(state, &hub);
    state.tree_dirty = true;
}

/// `bot_roster_t.p2_stamp` for an entry upserted now (0 without presence v2).
fn p2_next_stamp(state: &mut HubState) -> u64 {
    match state.p2.as_mut() {
        Some(p) => {
            p.stamp_ctr += 1;
            p.stamp_ctr
        }
        None => 0,
    }
}

/// Presence v2 (C hub_roster_p2_drop_hub): hub `hub_uuid` has been
/// unreachable past the grace.  Its bots and its mesh-map entry go now instead
/// of on the BOT_ROSTER_TTL.  Called once per outage, and again if a late
/// relayed round brings entries of it back.
pub fn p2_drop_hub(state: &mut HubState, hub_uuid: &str) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < state.roster.len() {
        if state.roster[i].hub_uuid == hub_uuid {
            state.roster.swap_remove(i);
            n += 1;
            continue;
        }
        i += 1;
    }
    if let Some(i) = state.mesh_hubs.iter().position(|h| h.uuid == hub_uuid) {
        state.mesh_hubs.swap_remove(i);
        n += 1;
    }
    if n > 0 {
        state.tree_dirty = true;
    }
    n
}

/// Presence v2 (C hub_roster_p2_reconcile): a reachable hub's record says
/// which bots it has.  An entry of that hub for a bot it no longer lists goes,
/// unless it arrived after the record (`p2_stamp`); a listed bot nobody
/// reported yet gets a bare entry (nick from the config, details "-") until
/// the hub's own round fills it in.
pub fn p2_reconcile(state: &mut HubState, rec: &crate::presence2::P2Rec) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < state.roster.len() {
        let e = &state.roster[i];
        if e.hub_uuid == rec.origin
            && e.p2_stamp < rec.stamp
            && !rec.bots.iter().any(|b| b.id == e.bot_uuid)
        {
            crate::hlog_debug!(
                "[PRESENCE] {} left {} (record)\n",
                state.who('b', &e.bot_uuid),
                state.who('h', &e.hub_uuid)
            );
            state.roster.swap_remove(i);
            state.tree_dirty = true;
            n += 1;
            continue;
        }
        i += 1;
    }
    let mh = mesh_hub_find(state, &rec.origin);
    for b in &rec.bots {
        // Skip it when it is there already, or linked to another hub more
        // recently (it moved and this hub has not noticed yet).
        if state
            .roster
            .iter()
            .any(|e| e.bot_uuid == b.id && (e.hub_uuid == rec.origin || e.link_since >= b.since))
        {
            continue;
        }
        let now_ts = now();
        let e = BotRoster {
            hub_uuid: rec.origin.clone(),
            hub_name: mh
                .map(|i| state.mesh_hubs[i].name.clone())
                .unwrap_or_default(),
            bot_uuid: b.id.clone(),
            nick: bot_nick_from_config(state, &b.id),
            link_since: if b.since > 0 && b.since <= now_ts {
                b.since
            } else {
                0
            },
            reported_at: now_ts,
            round: mh.map_or(0, |i| state.mesh_hubs[i].round),
            ..Default::default()
        };
        roster_upsert(state, e);
        // Added (it was absent): still "older" than any round.
        if let Some(j) = state
            .roster
            .iter()
            .position(|e| e.hub_uuid == rec.origin && e.bot_uuid == b.id)
        {
            state.roster[j].p2_stamp = rec.stamp;
            n += 1;
        }
    }
    n
}

/// process_bot_presence(): this bot just told us what it is running.  Per
/// connection and volatile.
pub fn process_bot_presence(state: &mut HubState, ci: usize, payload: &str) {
    // "<version>|<server>|<started>|<variant>[|<cron>[|<linkord>]]"
    // (BOT_PRESENCE_MAX) — a short, fixed shape.  The
    // variant (code base, c / rs) is the newest field; a bot that predates it
    // sends three and simply shows no code base.  Anything longer than the
    // field caps is truncated by roster_clean, never rejected, so a newer bot
    // advertising more never drops off the tree entirely.
    let work = trunc_string(payload, BOT_PRESENCE_MAX + 1);
    let cut = work.len() < payload.len(); // the counter rode past the cut
    let mut version_src = work.as_str();
    let mut server = String::new();
    let mut variant = String::new();
    let mut cron = String::new();
    let mut started = 0i64;
    let mut link_ord = 0u64; // phase 4: the bot's link-order counter
    if let Some(p1) = work.find('|') {
        version_src = &work[..p1];
        let rest = &work[p1 + 1..];
        let server_src = match rest.find('|') {
            Some(p2) => {
                let tail = &rest[p2 + 1..];
                started = atoll(tail);
                if let Some(p3) = tail.find('|') {
                    // Room for fields after it: stop at the next '|'.
                    let mut more = tail[p3 + 1..].split('|');
                    variant = roster_clean(more.next().unwrap_or(""), ROSTER_VARIANT_MAX + 1);
                    cron = roster_clean(more.next().unwrap_or(""), CRON_STATUS_MAX + 1);
                    // The link-order counter rides last; a bad/missing value is 0.
                    if !cut {
                        link_ord = more.next().unwrap_or("").parse::<u64>().unwrap_or(0);
                    }
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

    // D1 of the 2.5.1 plan: a bot below MESH_MIN_VERSION is not served (it
    // still reads 100k files and old record shapes).  The hub cannot roll it
    // up either, so it says what to do and drops the link.
    if !version.is_empty()
        && crate::update::version_cmp(&version, MESH_MIN_VERSION) == std::cmp::Ordering::Less
    {
        let id = state.who_client(ci);
        crate::hlog_warning!(
            "[HUB] {id} runs {version}: refused; upgrade it by hand to {MESH_MIN_VERSION}\n"
        );
        state.clients[ci].refused = true;
        return;
    }
    // Review 6: every bot sends CMD_LINK_SEQ "offer" as its first frame,
    // before any presence; none means it was stripped on the way.
    if !version.is_empty() && !state.clients[ci].link_offered {
        let id = state.who_client(ci);
        crate::hlog_warning!(
            "[HUB] {id} runs {version} but never offered the sequenced link framing (a frame stripped on the way?): dropped\n"
        );
        state.clients[ci].refused = true;
        return;
    }

    let c = &mut state.clients[ci];
    // The bot's first config may have gone out before its version was known:
    // once it shows it takes the pool (or stops), it is owed one with
    // (without) the N|/S| lines — a delta, since it already holds a base.  A
    // held first config (CFG_FIRST_HOLD) has not gone out: it is sent below.
    let held = c.cfg_hold_at != 0 && !c.cfg_hold_done;
    if !held
        && crate::mesh::bot_version_takes_pool(&c.bot_version)
            != crate::mesh::bot_version_takes_pool(&version)
    {
        c.cfg_owed = true;
        queue::cfg_owed_set();
    }
    let changed = c.bot_version != version
        || c.bot_server != server
        || c.bot_variant != variant
        || c.bot_started != started
        || c.bot_link_ord != link_ord;
    c.bot_version = version.clone();
    c.bot_server = server.clone();
    if held {
        crate::client::cfg_hold_release(state, ci);
    }
    let c = &mut state.clients[ci];
    c.bot_variant = variant.clone();
    c.bot_started = started;
    c.bot_link_ord = link_ord;
    let cron_changed = c.bot_cron != cron;
    c.bot_cron = cron;
    if cron_changed {
        state.tree_dirty = true;
    }

    if changed {
        let id = state.who_client(ci);
        crate::hlog_info!(
            "[PRESENCE] {id}: version {} ({}) on {}\n",
            if version.is_empty() { "?" } else { &version },
            if variant.is_empty() { "?" } else { &variant },
            if server.is_empty() {
                "(no server)"
            } else {
                &server
            }
        );
        roster_mark_dirty(state, true);
        presence_event(state); // gossip the change now, damped
    }

    // A committed node coming back on the target version is the authoritative
    // success signal for a rolling upgrade — CMD_UPGRADE_RESULT can be lost,
    // but without this frame the bot is not on the mesh at all.
    let uuid = state.clients[ci].id.clone();
    upgrade::note_presence(state, &uuid, &version, &variant);
    upgrade::rollup_note_presence(state, &uuid, UpgradeNodeKind::Bot, &version);
    upgrade::prepare_late(state, ci, &version);

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
    // A bot that reports ready itself is only "back".
    Some(format!("{}|{}|back|{}|", state.follow_id, uuid, version))
}

/// The nick the config knows this bot by (the persisted 'n' key); empty if
/// none.
pub fn bot_nick_from_config(state: &HubState, uuid: &str) -> String {
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
        // Ahead of bulk syncs: after a heal the link list must not wait behind one.
        let Some(m) = QueuedMsg::new(CMD_BOT_ROSTER, Lane::Delta, frame.as_bytes()) else {
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
fn roster_frame_begin(state: &HubState, round: i64, chunk: u32, last: bool) -> String {
    let mut f = format!(
        "h|{}|{}|{}|{HUB_VERSION}\nv|{HUB_UPDATE_VARIANT}\ng|{round}|{chunk}|{ROSTER_RELAY_HOPS}|{}\n",
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
        state.hub_started,
        i32::from(last)
    );
    // A line of its own, like v|: older hubs skip a line they do not know.
    let cron = crate::update::cron_status();
    if !cron.is_empty() {
        f.push_str(&format!("c|{cron}\n"));
    }
    // This hub answers CMD_HUB_ROLLCALL.  Every hub the mesh admits does
    // (MESH_MIN_VERSION 2.5.3); a 2.5.3 hub still asks only hubs that say so.
    f.push_str("k|rollcall\n");
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
/// g|<round>|<chunk>|<ttl>|<last>             (relay control, see below; last=1 on
///                                            the round's final chunk)
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
/// One gossip round, chunked: its frames, the one numbered `total`-1 marked last
/// (`None` only counts them).  None if a header cannot fit.
fn roster_round(state: &HubState, round: i64, total: Option<usize>) -> Option<Vec<String>> {
    let is_last = |chunk: u32| total == Some(chunk as usize + 1);
    let mut out = Vec::new();
    let mut chunk = 0u32;
    let mut frame = roster_frame_begin(state, round, chunk, is_last(chunk));
    if frame.len() >= ROSTER_FRAME_BUDGET {
        return None;
    }
    let mut rows = 0;

    for ci in state.bot_clients() {
        let c = &state.clients[ci];
        if c.retiring {
            continue;
        }
        let nick = bot_nick_from_config(state, &c.id);
        let c = &state.clients[ci];
        let row = format!(
            // 7th field: when the bot linked to this hub; 8th: the bot's
            // address as this hub sees it; 9th: cron; 10th (phase 4): the bot's
            // link-order counter (a hub that predates any stops reading before it).
            "b|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
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
            },
            c.connected_at,
            if c.ip.is_empty() { "-" } else { &c.ip },
            if c.bot_cron.is_empty() {
                "-"
            } else {
                &c.bot_cron
            },
            c.bot_link_ord
        );
        // + the i| and j| riders
        const ROW_CAP: usize = TREE_ROW_MAX
            + CRON_STATUS_MAX
            + 48
            + 128
            + crate::pool_rec::POOL_NET_NAME_MAX
            + CHAN_STATE_MAX
            + 48;
        if row.len() >= ROW_CAP {
            continue; // an unrepresentable row
        }
        let mut row = row;
        // Server pool: the IRC link's entry and state, on the row's heels so
        // a chunk never splits the two (an older hub skips the i| tag).
        if !c.bot_irc_link.is_empty() {
            let il = format!(
                "i|{}|{}|{}|{}|{}|\n",
                c.id,
                crate::pool_rec::POOL_DEFAULT_NET,
                if c.bot_irc_entry.is_empty() {
                    "-"
                } else {
                    &c.bot_irc_entry
                },
                c.bot_irc_link,
                if c.bot_irc_network.is_empty() {
                    "-"
                } else {
                    &c.bot_irc_network
                }
            );
            if il.len() < ROW_CAP - row.len() {
                row.push_str(&il);
            }
        }
        // bot show's channels line (an older hub skips the j| tag)
        if !c.bot_chan_state.is_empty() {
            let jl = format!("j|{}|{}|\n", c.id, c.bot_chan_state);
            if jl.len() < ROW_CAP - row.len() {
                row.push_str(&jl);
            }
        }
        if frame.len() + row.len() >= ROSTER_FRAME_BUDGET && rows > 0 {
            // Full: flush and start the next chunk.
            chunk += 1;
            let next = roster_frame_begin(state, round, chunk, is_last(chunk));
            if next.len() >= ROSTER_FRAME_BUDGET {
                return None;
            }
            out.push(std::mem::replace(&mut frame, next));
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
    if rows > 0 || out.is_empty() {
        out.push(frame);
    }
    Some(out)
}

/// Gossip the bots connected to THIS hub out to the peers, as one round: the
/// receivers drop this hub's bots the round no longer lists (see roster_round_done).
fn gossip_bot_roster(state: &mut HubState) {
    if state.peers.is_empty() {
        return;
    }
    let now_ts = now();
    // Generations only ever grow, across restarts too (wall-clock based), so
    // a receiver can tell a new round from a late copy of an old one.
    let round = (now_ts * 1000).max(state.roster_gen + 1);
    state.roster_gen = round;
    let total = roster_round(state, round, None).map_or(0, |f| f.len());
    if total > 0
        && let Some(frames) = roster_round(state, round, Some(total))
    {
        for f in frames {
            roster_send_to_peers(state, &f, None, None);
        }
    }
    state.last_presence_gossip = now_ts;
    state.presence_event_due = false;
}

/// A peer link just authenticated: one round of our own, to it alone and past
/// the damping.  A hub that restarted knows nothing of us until our gossip
/// reaches it — not our bots, and not that we answer a roll call (k|), so its
/// upgrade gates would fall back to the gossip check for up to a full
/// BOT_PRESENCE_INTERVAL.  A fresh generation, so it relays and replaces like
/// any round; the other peers' damping clock is left alone.
pub fn roster_send_to_peer(state: &mut HubState, ci: usize) {
    let Some(c) = state.clients.get(ci) else {
        return;
    };
    if c.typ != ClientType::Hub || !c.authenticated {
        return;
    }
    let round = (now() * 1000).max(state.roster_gen + 1);
    state.roster_gen = round;
    let total = roster_round(state, round, None).map_or(0, |f| f.len());
    if total > 0
        && let Some(frames) = roster_round(state, round, Some(total))
    {
        for f in frames {
            let Some(m) = QueuedMsg::new(CMD_BOT_ROSTER, Lane::Delta, f.as_bytes()) else {
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
}

/// The g| relay control of a roster frame: `(round, chunk, ttl, last)`.
type RosterRelay = (i64, u32, i32, bool);

/// The relay control of a roster frame: origin uuid and start time from its
/// h| line, and `(round, chunk, ttl, last)` from its g| line if it has one.
fn roster_frame_peek(payload: &str) -> (String, i64, Option<RosterRelay>) {
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
                    f.get(3).is_some_and(|l| l.starts_with('1')),
                ));
            }
        }
    }
    (origin, started, g)
}

/// The same frame with its g| ttl replaced, for the next hop.
fn roster_frame_rettl(payload: &str, round: i64, chunk: u32, ttl: i32, last: bool) -> String {
    let mut out = String::with_capacity(payload.len() + 8);
    for line in payload.split('\n').filter(|l| !l.is_empty()) {
        if line.starts_with("g|") {
            out.push_str(&format!("g|{round}|{chunk}|{ttl}|{}\n", i32::from(last)));
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
    if let (Some((round, chunk, _, _)), Some(mi)) = (g, mh) {
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
        (Some((round, chunk, ttl, last)), Some(_)) if ttl > 1 && ttl <= ROSTER_RELAY_HOPS => {
            let r = roster_frame_rettl(payload, round, chunk, ttl - 1, last);
            (r.len() <= ROSTER_FRAME_BUDGET + 64).then_some(r)
        }
        _ => None,
    };
    let first_chunk = matches!(g, Some((_, 0, _, _)));
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
            // D4 of the 2.5.1 plan: a direct peer below MESH_MIN_VERSION
            // loses its link once its own roster header names its version
            // (relayed headers of hubs further away are only shown).
            if !hub_ver.is_empty()
                && crate::update::version_cmp(&hub_ver, MESH_MIN_VERSION)
                    == std::cmp::Ordering::Less
                && from < state.clients.len()
                && hub_uuid == upgrade::peer_uuid_of(state, from)
            {
                let ip = state.clients[from].ip.clone();
                crate::hlog_warning!(
                    "[MESH] Peer {hub_name} ({ip}) runs {hub_ver}: link refused; upgrade it by hand to {MESH_MIN_VERSION}\n"
                );
                state.clients[from].refused = true;
                return;
            }
            // Review 6: every direct peer offers CMD_LINK_SEQ on connect.
            if !hub_ver.is_empty()
                && from < state.clients.len()
                && !state.clients[from].link_offered
                && hub_uuid == upgrade::peer_uuid_of(state, from)
            {
                let ip = state.clients[from].ip.clone();
                crate::hlog_warning!(
                    "[MESH] Peer {hub_name} ({ip}) runs {hub_ver} but never offered the sequenced link framing (a frame stripped on the way?): link dropped\n"
                );
                state.clients[from].refused = true;
                return;
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
        if line.starts_with("k|") {
            continue; // capabilities: every hub answers a roll call
        }
        if let Some(body) = line.strip_prefix("i|") {
            // Server pool: a bot's IRC link, right after its b| row (upserted
            // above).
            if hub_uuid.is_empty() || hub_uuid == "-" {
                continue;
            }
            use crate::admin::wire_field;
            use crate::pool_rec::POOL_UUID_LEN;
            let (Some(bu), Some(ent), Some(lk)) = (
                wire_field(body, 0, 64),
                wire_field(body, 2, POOL_UUID_LEN + 2),
                wire_field(body, 3, POOL_LINK_WORD_MAX + 2),
            ) else {
                continue;
            };
            if !crate::pool::link_word_ok(&lk) || (ent != "-" && ent.len() != POOL_UUID_LEN) {
                continue;
            }
            if let Some(e) = state
                .roster
                .iter_mut()
                .find(|e| e.bot_uuid == bu && e.hub_uuid == hub_uuid)
            {
                e.irc_entry = roster_clean(if ent == "-" { "" } else { &ent }, POOL_UUID_LEN + 1);
                e.irc_link = trunc_string(&lk, 12);
                // field 4 (2.5.4): NETWORK=; absent or bad reads as unknown
                e.irc_network = wire_field(body, 4, crate::pool_rec::POOL_NET_NAME_MAX + 2)
                    .filter(|nw| nw != "-" && crate::pool_rec::net_name_ok(nw))
                    .unwrap_or_default();
            }
            continue;
        }
        if let Some(body) = line.strip_prefix("j|") {
            // bot show's channels line, right after its b| row
            if hub_uuid.is_empty() || hub_uuid == "-" {
                continue;
            }
            use crate::admin::wire_field;
            let (Some(bu), Some(list)) = (
                wire_field(body, 0, 64),
                wire_field(body, 1, CHAN_STATE_MAX + 2),
            ) else {
                continue;
            };
            if !crate::pool::chan_state_ok(&list) {
                continue;
            }
            if let Some(e) = state
                .roster
                .iter_mut()
                .find(|e| e.bot_uuid == bu && e.hub_uuid == hub_uuid)
            {
                e.chan_state = list;
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("c|") {
            // The production crontab line of the hub whose h| header opened it.
            let hc = roster_clean(v, CRON_STATUS_MAX + 1);
            if let Some(m) = state.mesh_hubs.iter_mut().find(|m| m.uuid == hub_uuid)
                && m.cron != hc
            {
                m.cron = hc;
                state.tree_dirty = true;
            }
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
                h.links_at = now_ts;
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

        // Five fields from any hub; a sixth (the bot's code base), a seventh
        // (when it linked to that hub) and an eighth (its address) from one
        // that knows them.
        let f = crate::cstr::split_fields(body, 10);
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
            cron: if f.len() < 9 || f[8] == "-" {
                String::new()
            } else {
                roster_clean(f[8], CRON_STATUS_MAX + 1)
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
            link_since: match f.get(6).map(|s| atoll(s)) {
                Some(s) if s > 0 && s <= now_ts => s,
                _ => 0,
            },
            // Phase 4: the link-order counter rides last; a bad or missing
            // value reads 0, which the move decision treats as "no counter".
            link_ord: f.get(9).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
            // Display only, but still a peer's word: an IPv4/IPv6 literal or
            // nothing.
            ip: match f.get(7) {
                Some(s)
                    if *s != "-"
                        && !s.is_empty()
                        && s.len() <= ROSTER_IP_MAX
                        && s.bytes()
                            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') =>
                {
                    (*s).to_string()
                }
                _ => String::new(),
            },
            reported_at: now_ts,
            round: match g {
                Some((round, ..)) if mh.is_some() && hub_uuid == origin => round,
                _ => 0,
            },
            p2_stamp: 0,
            // The i| line after the row fills these (pool, 2.5.4).
            irc_entry: String::new(),
            irc_link: String::new(),
            irc_network: String::new(),
            chan_state: String::new(),
        };
        roster_upsert(state, e);
    }
    if let (Some((_, chunk, _, true)), Some(mi)) = (g, mh) {
        roster_round_done(state, mi, chunk);
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
        "H|0|{}|{}|1|0|{HUB_VERSION}|{HUB_UPDATE_VARIANT}|{}|{}\n",
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
        state.hub_started,
        {
            let c = crate::update::cron_status();
            if c.is_empty() { "-".to_string() } else { c }
        }
    );
    if out.len() >= max_len {
        return String::new();
    }

    // Each bot once (uuid-keyed row deltas need unique rows): a superseded
    // session still open during a reconnect, or a moved bot a peer's roster
    // still reports, would list it twice.  Our own live session comes first.
    let mut listed: std::collections::HashSet<&str> = std::collections::HashSet::new();

    // Our own bots, from the live client list — never from a peer's report.
    for ci in state.bot_clients() {
        if max_len - out.len() <= TREE_ROW_MAX {
            break;
        }
        let c = &state.clients[ci];
        if c.superseded || !listed.insert(c.id.as_str()) {
            continue;
        }
        let nick = bot_nick_from_config(state, &c.id);
        out.push_str(&format!(
            "B|1|{}|{}|{}|{}|0|{}|{}|{}\n",
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
            c.bot_started,
            if c.bot_cron.is_empty() {
                "-"
            } else {
                &c.bot_cron
            }
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
            "H|{}|{}|{}|{}|0|{}|{}|{}|{}\n",
            t.depth,
            if t.name.is_empty() { "peer" } else { &t.name },
            if puuid.is_empty() { "-" } else { puuid },
            i32::from(t.online),
            if ver.is_empty() { "-" } else { ver },
            if var.is_empty() { "-" } else { var },
            started,
            state
                .mesh_hubs
                .iter()
                .find(|m| m.uuid == puuid && !m.cron.is_empty())
                .map_or("-", |m| m.cron.as_str())
        ));

        if !puuid.is_empty() {
            for e in state
                .roster
                .iter()
                .filter(|e| e.hub_uuid == puuid && !crate::presence2::hub_gone(state, puuid))
            {
                if max_len - out.len() <= TREE_ROW_MAX {
                    break;
                }
                if !listed.insert(e.bot_uuid.as_str()) {
                    continue;
                }
                out.push_str(&format!(
                    "B|{}|{}|{}|{}|{}|0|{}|{}|{}\n",
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
                    e.connected_at,
                    if e.cron.is_empty() { "-" } else { &e.cron }
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

/// Phase 5: FNV-1a 64 over the whole tree text — the hash in each row delta so
/// a bot that applied one can tell its tree matches ours and pull if not.
fn tree_fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The uuid of a tree row, "" if malformed: field 3 of KIND|depth|name|uuid|...,
/// but field 2 of an offline row D|nick|uuid|last_seen (its field 3 is a time
/// offline bots share, which made deltas hit the wrong row).  The bots' row key
/// (ircbot bot_row_uuid, ircbot.rs tree_row_uuid) must match.
fn tree_row_uuid(line: &str) -> &str {
    let idx = if line.starts_with('D') { 2 } else { 3 };
    line.split('|').nth(idx).unwrap_or("")
}

/// Every row has a key and no key repeats: the rows a delta addresses by uuid
/// are then exactly one each (C `tree_rows_keyed`).
fn tree_rows_keyed<'a>(rows: &[&'a str]) -> Option<std::collections::HashSet<&'a str>> {
    let mut set = std::collections::HashSet::with_capacity(rows.len());
    for r in rows {
        let u = tree_row_uuid(r);
        if u.is_empty() || !set.insert(u) {
            return None;
        }
    }
    Some(set)
}

/// Build the row-delta from `oldt` to `newt`: `<fnvhex>\n`, a `-|uuid` for each
/// row gone and a `+|anchor|row` for each row added, moved or changed (anchor =
/// the uuid of the row it now follows, `^` at head: no uuid is `^`, while `-` is
/// the key of a hub whose uuid is not known yet).  None if it would not be
/// smaller than the whole tree, or either tree has a row without a key or two
/// rows with one key (then the caller sends the whole tree).
fn build_tree_delta(oldt: &str, newt: &str, fnv: u64) -> Option<String> {
    let oldr: Vec<&str> = oldt.lines().filter(|l| !l.is_empty()).collect();
    let newr: Vec<&str> = newt.lines().filter(|l| !l.is_empty()).collect();
    tree_rows_keyed(&oldr)?;
    let newk = tree_rows_keyed(&newr)?;
    let mut out = format!("{fnv:016x}\n");
    // The deletions, and `w` = the old rows that stay (in order).
    let mut w: Vec<&str> = Vec::with_capacity(newr.len());
    for ol in &oldr {
        let u = tree_row_uuid(ol);
        if newk.contains(u) {
            w.push(ol);
        } else {
            out.push_str(&format!("-|{u}\n"));
        }
    }
    // Replay the bot's apply on `w`: after step j, w[..=j] == newr[..=j].  A row
    // is skipped only when it already sits at position j, so a row left behind
    // by a moved neighbour is re-sent.
    for (j, nl) in newr.iter().enumerate() {
        if w.get(j) == Some(nl) {
            continue;
        }
        let anchor = if j == 0 {
            "^"
        } else {
            tree_row_uuid(newr[j - 1])
        };
        out.push_str(&format!("+|{anchor}|{nl}\n"));
        // rows before j are final, so the old copy of this row sits at j or later
        let u = tree_row_uuid(nl);
        if let Some(i) = w.iter().skip(j).position(|r| tree_row_uuid(r) == u) {
            w.remove(j + i);
        }
        w.insert(j.min(w.len()), nl);
    }
    if out.len() >= newt.len() {
        None
    } else {
        Some(out)
    }
}

/// The payload of a keepalive PING to client `ci`: "t|<fnv64hex>", the hash
/// of the tree the bot holds once all we sent has landed; and, to a 2.5.4+
/// bot, a second line "c|<sha256hex>", the hash of S, the config text it
/// holds once every config frame already written has applied (plan §4.3a
/// I5), so a bot holding anything else pulls a full config.  Each part is
/// left out when there is nothing to vouch for: not a bot, a frame of that
/// kind still queued (pings jump the queue), or the bot not current; "" when
/// both are.  2.5.3 bots read t| alone and ignore anything
/// more, so they never get c|.  As C `hub_bot_ping_payload`.
pub fn bot_ping_payload(state: &HubState, ci: usize) -> String {
    let c = &state.clients[ci];
    if c.typ != ClientType::Bot || !c.authenticated || c.superseded {
        return String::new();
    }
    let mut out = String::new();
    let queued = c.out_lanes.iter().any(|l| {
        l.msgs
            .iter()
            .any(|m| m.cmd == CMD_BOT_TREE || m.cmd == CMD_BOT_TREE_DELTA)
    });
    if !state.tree_last.is_empty()
        && c.tree_sent_valid
        && c.tree_sent_seq == state.tree_seq
        && !queued
    {
        out = format!("t|{:016x}", state.tree_last_fnv);
    }
    if crate::client::bot_takes_cfg_deltas(c)
        && c.cfg_base.is_some()
        && !c.cfg_queued
        && !c.cfg_owed
    {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("c|");
        for b in c.cfg_base_hash {
            out.push_str(&format!("{b:02x}"));
        }
    }
    out
}

/// A bot owed a whole tree (a dropped tree frame, or it just connected): it
/// is pushed on the next tick, not left for the next change.
fn tree_owed(state: &HubState) -> bool {
    state
        .clients
        .iter()
        .any(|c| c.typ == ClientType::Bot && c.authenticated && !c.superseded && !c.tree_sent_valid)
}

/// Send bot `ci` the whole current tree (its own frame, coalesced).
fn send_whole_tree(state: &mut HubState, ci: usize, payload: &str, seq: u64) {
    let Some(mut m) = QueuedMsg::new(CMD_BOT_TREE, Lane::Bulk, payload.as_bytes()) else {
        return;
    };
    let coalesce = format!("{}|bot_tree|{}", state.hub_uuid, state.clients[ci].id);
    let lseq = state.next_lamport_seq();
    let hub_uuid = state.hub_uuid.clone();
    m.set_coalesce(&hub_uuid, lseq, &coalesce);
    let c = &mut state.clients[ci];
    c.tree_sent_valid = true;
    c.tree_sent_seq = seq;
    if !queue::enqueue(c, m) {
        c.tree_sent_valid = false;
        return;
    }
    crate::stats::tree_full(payload.len());
}

/// Push the assembled tree to every connected bot.  Phase 5: a bot already
/// holding the previous tree gets just the row delta to the new one; others
/// (new or lagging) get the whole tree.  On a quiet mesh the keepalive tree
/// hash (`bot_ping_payload`) keeps a bot's tree from looking stale.
fn push_tree_to_bots(state: &mut HubState) {
    // A superseded session is closing: no tree frames to it.
    let bots: Vec<usize> = state
        .bot_clients()
        .into_iter()
        .filter(|&ci| !state.clients[ci].superseded)
        .collect();
    if bots.is_empty() {
        return;
    }
    let payload = build_tree(state);
    if payload.is_empty() {
        return;
    }
    let fnv = tree_fnv64(&payload);
    let changed = state.tree_last.len() != payload.len()
        || fnv != state.tree_last_fnv
        || state.tree_last != payload;
    let old_seq = state.tree_seq;
    let new_seq = if changed { old_seq + 1 } else { old_seq };

    // One delta, shared by every bot holding the previous tree; the keepalive
    // hash checks that it landed.
    let delta = if changed && !state.tree_last.is_empty() {
        build_tree_delta(&state.tree_last, &payload, fnv)
    } else {
        None
    };

    for ci in bots {
        let current =
            state.clients[ci].tree_sent_valid && state.clients[ci].tree_sent_seq == old_seq;
        if !changed && current {
            continue; // already up to date
        }
        let m = if changed && current {
            delta
                .as_deref()
                .and_then(|d| QueuedMsg::new(CMD_BOT_TREE_DELTA, Lane::Bulk, d.as_bytes()))
        } else {
            None
        };
        match m {
            Some(m) => {
                let dlen = m.len();
                let c = &mut state.clients[ci];
                c.tree_sent_valid = true;
                c.tree_sent_seq = new_seq;
                if !queue::enqueue(c, m) {
                    c.tree_sent_valid = false;
                } else {
                    crate::stats::tree_delta(dlen, payload.len());
                }
            }
            None => send_whole_tree(state, ci, &payload, new_seq),
        }
    }

    if changed {
        state.tree_last = payload;
        state.tree_last_fnv = fnv;
        state.tree_seq = new_seq;
    }
}

/// A bot applied a delta whose hash did not match: send it the whole tree, at
/// most once per TREE_PULL_MIN_GAP; one inside the gap is held and served by
/// presence_tick when the gap ends (C `hub_tree_pull`).
pub fn tree_pull(state: &mut HubState, ci: usize) {
    let t = now();
    let c = &mut state.clients[ci];
    if c.tree_pull_at != 0 && t - c.tree_pull_at < TREE_PULL_MIN_GAP {
        c.tree_pull_due = true;
        return;
    }
    c.tree_pull_due = false;
    c.tree_pull_at = t;
    crate::stats::tree_pull();
    if state.tree_last.is_empty() {
        state.clients[ci].tree_sent_valid = false;
        state.tree_dirty = true;
        return;
    }
    let payload = state.tree_last.clone();
    let seq = state.tree_seq;
    send_whole_tree(state, ci, &payload, seq);
}

/// hub_presence_tick(): drives both halves on the maintenance clock.  It
/// gossips this hub's own connected bots to the peers every
/// BOT_PRESENCE_INTERVAL and pushes a refreshed tree down to the bots when
/// the roster changed (a bot that missed a frame converges through the
/// keepalive tree hash, one that connected between changes through
/// `tree_owed`).
/// How long event gossip holds after `burst` event gossips in a row: 1, 2, 4, 8,
/// 16, then PRESENCE_HOLD_MAX seconds.
pub fn presence_hold(burst: i32) -> i64 {
    if burst >= 5 {
        return PRESENCE_HOLD_MAX;
    }
    (1i64 << burst.max(0)).min(PRESENCE_HOLD_MAX)
}

/// A bot linked or left, or a peer link changed: gossip it as soon as the damping
/// allows (presence_tick).
pub fn presence_event(state: &mut HubState) {
    state.presence_event_due = true;
}

pub fn presence_tick(state: &mut HubState, now_ts: i64) {
    if state.hub_started == 0 {
        state.hub_started = now_ts;
    }

    roster_expire(state, now_ts);
    crate::presence2::tick(state); // presence v2 records, reachability (phase 1)

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
        presence_event(state);
        // Once more shortly: the first round can go out on a duplicate link the
        // far end then closes (both ends dialled).
        state.gossip_again_at = now_ts + PRESENCE_LINK_REGOSSIP;
        state.tree_dirty = true;
    }
    if state.gossip_again_at != 0 && now_ts >= state.gossip_again_at {
        state.gossip_again_at = 0;
        presence_event(state);
    }
    if state.resync_due_at != 0 && now_ts >= state.resync_due_at {
        state.resync_due_at = 0;
        crate::mesh::request_sync_from_peers(state);
    }

    // Presence v2 runs alongside today's rounds for one release (plan §8.4):
    // v2 gossips who is where, these rounds keep carrying it too and the roster
    // details (nick, version, capabilities) on their own cadence.
    let round = BOT_PRESENCE_INTERVAL;
    if now_ts - state.last_presence_gossip >= round {
        gossip_bot_roster(state);
    } else if state.presence_event_due && now_ts >= state.presence_hold_until {
        gossip_bot_roster(state);
        // Damping: an event gossip close on the last one doubles the next hold.
        state.presence_burst = if state.presence_last_event != 0
            && now_ts - state.presence_last_event < PRESENCE_FLAP_WINDOW
        {
            state.presence_burst + 1
        } else {
            0
        };
        state.presence_last_event = now_ts;
        state.presence_hold_until = now_ts + presence_hold(state.presence_burst);
    }

    // Pulls held by the TREE_PULL_MIN_GAP throttle, once the gap is over.
    for ci in 0..state.clients.len() {
        let c = &state.clients[ci];
        if c.tree_pull_due && now_ts - c.tree_pull_at >= TREE_PULL_MIN_GAP {
            tree_pull(state, ci);
        }
    }

    // Push on change (only to bots whose tree it changes).  Changes are
    // coalesced (see BOT_TREE_COALESCE): under churn every peer's gossip round
    // re-rendered the tree for every bot, O(hubs x bots) 10 KB frames a minute.
    let gap = if state.tree_dirty_local {
        BOT_TREE_COALESCE_LOCAL
    } else {
        BOT_TREE_COALESCE
    };
    let due = state.tree_dirty && now_ts - state.last_tree_change_push >= gap;
    // A bot owed a whole tree gets it now (a dropped frame used to wait for
    // the next change).
    if !due && tree_owed(state) {
        push_tree_to_bots(state);
        return;
    }
    if due {
        state.tree_dirty = false;
        state.tree_dirty_local = false;
        state.last_tree_change_push = now_ts;
        push_tree_to_bots(state);
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
        // Addendum A1: a bot's report is "back"; its own "ok" finishes it.
        let p = follower_presence_ok(&s, "b", "2.4.5", "c").unwrap();
        assert_eq!(p, "r1|b|back|2.4.5|");
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
            roster_frame_rettl(f, 7, 0, 15, true),
            "h|far|Far|0|2.4.1\ng|7|0|15|1\nb|x|-|-|-|0\n"
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
    fn presence_hold_doubles_to_the_cap() {
        let holds: Vec<i64> = (0..8).map(presence_hold).collect();
        assert_eq!(holds, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(presence_hold(-1), 1);
    }

    #[test]
    fn presence_events_are_damped_and_coalesced() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        s.peers.push(PeerConfig {
            uuid: "p".into(),
            ..Default::default()
        });
        let t = now();
        s.hub_started = t;
        s.last_presence_gossip = t; // no periodic round due
        presence_event(&mut s);
        presence_tick(&mut s, t);
        assert!(!s.presence_event_due, "the first event goes at once");
        assert_eq!(s.presence_hold_until, t + 1);
        presence_event(&mut s);
        presence_event(&mut s);
        presence_tick(&mut s, t);
        assert!(s.presence_event_due, "inside the hold: waits, coalesced");
        presence_tick(&mut s, t + 1);
        assert!(!s.presence_event_due);
        assert_eq!(s.presence_hold_until, t + 1 + 2, "a burst doubles the hold");
        // A quiet window resets it.
        let q = t + 1 + PRESENCE_FLAP_WINDOW;
        s.last_presence_gossip = q;
        presence_event(&mut s);
        presence_tick(&mut s, q);
        assert_eq!(s.presence_hold_until, q + 1);
    }

    fn row(hub: &str, bot: &str, since: i64, round: i64) -> BotRoster {
        BotRoster {
            hub_uuid: hub.into(),
            bot_uuid: bot.into(),
            link_since: since,
            reported_at: now(),
            round,
            ..Default::default()
        }
    }

    #[test]
    fn a_complete_round_drops_the_bots_it_no_longer_lists() {
        let mut s = HubState::new();
        s.mesh_hubs.push(MeshHub {
            uuid: "h1".into(),
            round: 20,
            chunks_seen: 0b11,
            ..Default::default()
        });
        s.roster.push(row("h1", "kept", 0, 20));
        s.roster.push(row("h1", "left", 0, 10));
        s.roster.push(row("h2", "other", 0, 10));
        roster_round_done(&mut s, 0, 2);
        assert_eq!(s.roster.len(), 3, "chunk 2 not seen yet: nothing goes");
        roster_round_done(&mut s, 0, 1);
        let mut left: Vec<&str> = s.roster.iter().map(|e| e.bot_uuid.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, vec!["kept", "other"]);
    }

    #[test]
    fn a_bot_that_moved_hubs_is_shown_on_the_new_one_only() {
        let mut s = HubState::new();
        s.roster.push(row("old", "b", 100, 1));
        roster_upsert(&mut s, row("new", "b", 200, 1));
        assert_eq!(s.roster.len(), 1);
        assert_eq!(s.roster[0].hub_uuid, "new");
        // A late report from where it was does not evict the newer one.
        roster_upsert(&mut s, row("old", "b", 100, 2));
        assert!(s.roster.iter().any(|e| e.hub_uuid == "new"));
        // Unknown link times keep today's behaviour.
        roster_upsert(&mut s, row("third", "b", 0, 1));
        assert!(s.roster.iter().any(|e| e.hub_uuid == "third"));
        roster_evict_moved(&mut s, "b", "me", 0, 0);
        assert!(
            s.roster.is_empty(),
            "linked here now: every other entry goes"
        );
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

        // A pre-variant hub: five fields, no v| line.
        process_bot_roster(
            &mut s,
            NO_LINK,
            "h|them|Them|0|2.3.0\nb|bot-2|n|2.3.0|srv|0\n",
        );
        assert_eq!(s.roster[1].variant, "");
        assert!(
            s.roster
                .iter()
                .any(|e| e.bot_uuid == "bot-2" && e.variant.is_empty())
        );
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
            format!("H|0|Me|me|1|0|{HUB_VERSION}|{HUB_UPDATE_VARIANT}|1700000000|-")
        );
        assert_eq!(lines[1], "D|offbot|bot-1|4242");
    }

    /// The bots' apply (ircbot hub_client_process_tree_delta): `-|uuid` drops
    /// a row, `+|anchor|row` replaces one after its anchor, `^` = head.
    fn apply_delta(raw: &str, delta: &str) -> (String, u64) {
        let mut lines = delta.split('\n');
        let want = u64::from_str_radix(lines.next().unwrap(), 16).unwrap();
        let mut rows: Vec<String> = raw.lines().map(str::to_string).collect();
        for op in lines.filter(|l| !l.is_empty()) {
            if let Some(u) = op.strip_prefix("-|") {
                rows.retain(|r| super::tree_row_uuid(r) != u);
            } else if let Some((anchor, row)) =
                op.strip_prefix("+|").and_then(|r| r.split_once('|'))
            {
                rows.retain(|r| super::tree_row_uuid(r) != super::tree_row_uuid(row));
                let pos = if anchor == "^" {
                    0
                } else {
                    rows.iter()
                        .position(|r| super::tree_row_uuid(r) == anchor)
                        .map_or(rows.len(), |i| i + 1)
                };
                rows.insert(pos, row.to_string());
            }
        }
        (rows.iter().map(|r| format!("{r}\n")).collect(), want)
    }

    #[test]
    fn tree_delta_replays_to_the_new_tree() {
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut rnd = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let (mut applied, mut whole) = (0, 0);
        for _ in 0..2000 {
            // old: up to 40 unique keys, one of them maybe the unknown-uuid `-`
            let mut rows: Vec<String> = Vec::new();
            for k in 0..(5 + rnd(35)) {
                let u = if k == 0 && rnd(3) == 0 {
                    "-".to_string()
                } else {
                    format!("u{k}")
                };
                rows.push(match rnd(3) {
                    0 => format!("D|n|{u}|{}", rnd(4)),
                    1 => format!("H|{}|nm|{u}|1", rnd(3)),
                    _ => format!("B|{}|nm|{u}|0", rnd(3)),
                });
            }
            let oldt: String = rows.iter().map(|r| format!("{r}\n")).collect();
            for _ in 0..(1 + rnd(4)) {
                match rnd(4) {
                    0 if !rows.is_empty() => {
                        let i = rnd(rows.len());
                        rows.remove(i);
                    }
                    1 if !rows.is_empty() => {
                        let r = rows.remove(rnd(rows.len()));
                        let i = rnd(rows.len() + 1);
                        rows.insert(i, r);
                    }
                    2 if !rows.is_empty() => {
                        let i = rnd(rows.len());
                        rows[i].push('x');
                    }
                    _ => {
                        let i = rnd(rows.len() + 1);
                        rows.insert(i, format!("B|1|nm|new{}|0|padding", rnd(1000)));
                    }
                }
            }
            let newt: String = rows.iter().map(|r| format!("{r}\n")).collect();
            let fnv = super::tree_fnv64(&newt);
            match super::build_tree_delta(&oldt, &newt, fnv) {
                Some(d) => {
                    assert_eq!(
                        apply_delta(&oldt, &d),
                        (newt.clone(), fnv),
                        "{oldt}->{newt}: {d}"
                    );
                    applied += 1;
                }
                None => whole += 1,
            }
        }
        assert!(applied > 1000, "applied {applied}, whole {whole}");
        // Two rows with one key, or a row with none: the whole tree instead.
        assert!(super::build_tree_delta("H|1|a|-|1\n", "H|1|a|-|1\nH|1|b|-|1\n", 0).is_none());
        assert!(super::build_tree_delta("H|1|a|u|1\n", "H|1|a|u|1\nB|1|x\n", 0).is_none());
    }
}
