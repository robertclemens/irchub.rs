//! Hub-to-hub replication (hub_logic.c): the full-state sync packet, the
//! peer-sync ingest, mesh-state gossip, and the tombstone purge.
//!
//! The store is a last-write-wins CRDT.  Every replicated record carries a
//! timestamp, and `state::lww_accepts` decides: a strictly newer stamp wins,
//! and on an exact tie a delete beats an add.  That tie rule is what makes
//! the mesh converge — two hubs stamping the same second would otherwise
//! each keep their own copy and refuse the other's forever — and it is
//! mirrored in ircbot, so a bot and a hub never disagree about a record.

use crate::consts::*;
use crate::cstr::{atoll, now, split_fields, trunc_string};
use crate::state::{
    ClientType, ConfigEntry, HubState, Lane, MaskRecord, QueuedMsg, UserRecord,
    global_value_active, lww_accepts, opt_accepts,
};
use crate::{client, config, crypto, hlog, queue, storage};

// ---------------------------------------------------------------------------
// PURGE deduplication
// ---------------------------------------------------------------------------
//
// A purge is known by its cutoff plus the random id its origin hub gave it.
// Keyed on the cutoff alone, every "immediate" purge (cutoff 0) looked like
// the previous one for PURGE_DEDUP_WINDOW seconds, and peers skipped a second
// purge sent inside that window.  A line from a hub that predates the id
// carries id "" and dedupes on its cutoff as before.

fn is_purge_recent(state: &HubState, cutoff: i64, id: &str) -> bool {
    let t = now();
    state
        .recent_purges
        .iter()
        .any(|p| p.cutoff == cutoff && p.id == id && t - p.received_at < PURGE_DEDUP_WINDOW)
}

fn record_recent_purge(state: &mut HubState, cutoff: i64, id: &str) {
    let t = now();
    let slot = match state
        .recent_purges
        .iter()
        .position(|p| p.cutoff == cutoff && p.id == id)
    {
        Some(i) => i,
        None if state.recent_purges.len() < MAX_RECENT_PURGES => {
            state.recent_purges.push(Default::default());
            state.recent_purges.len() - 1
        }
        None => {
            // Full: overwrite the oldest entry.
            let mut oldest = 0;
            for i in 1..state.recent_purges.len() {
                if state.recent_purges[i].received_at < state.recent_purges[oldest].received_at {
                    oldest = i;
                }
            }
            oldest
        }
    };
    state.recent_purges[slot].cutoff = cutoff;
    state.recent_purges[slot].id = trunc_string(id, PURGE_ID_HEX + 1);
    state.recent_purges[slot].received_at = t;
}

/// `PURGE|<cutoff>` or `PURGE|<cutoff>|<id>`, id 1..PURGE_ID_HEX hex digits.
/// None on anything else (the line is dropped, not forwarded).
fn parse_purge_line(line: &str) -> Option<(i64, String)> {
    let p = line.strip_prefix("PURGE|")?;
    if !p.as_bytes().first()?.is_ascii_digit() {
        return None;
    }
    let (v, used) = crate::cstr::strtoll(p);
    if v < 0 {
        return None;
    }
    let rest = &p[used..];
    let id = match rest.strip_prefix('|') {
        Some(h) => {
            if h.is_empty() || h.len() > PURGE_ID_HEX || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            h.to_string()
        }
        None => {
            if !rest.is_empty() {
                return None;
            }
            String::new()
        }
    };
    Some((v, id))
}

/// hub_broadcast_purge(): send `PURGE|<cutoff>|<id>` to every peer hub under
/// a fresh random id that this hub records as seen (so the copies peers
/// forward back are not run again).  False (nothing sent) if no id could be
/// drawn.
pub fn broadcast_purge(state: &mut HubState, cutoff: i64) -> bool {
    let Some(id) = crypto::random_hex(PURGE_ID_HEX / 2) else {
        hlog!("[PURGE][ERROR] no random bytes for a purge id; purge not broadcast\n");
        return false;
    };
    record_recent_purge(state, cutoff, &id);
    let msg = format!("PURGE|{cutoff}|{id}\n");
    broadcast_sync_to_peers(state, &msg, -1);
    true
}

/// hub_should_initiate_scheduled_purge(): leader election — the hub with the
/// lexicographically smallest UUID in the connected mesh leads.
pub fn should_initiate_scheduled_purge(state: &HubState) -> bool {
    !state
        .clients
        .iter()
        .any(|c| c.typ == ClientType::Hub && c.authenticated && c.id < state.hub_uuid)
}

// ---------------------------------------------------------------------------
// Mesh-state gossip
// ---------------------------------------------------------------------------

/// hub_broadcast_mesh_state(): the peer-topology snapshot every hub gossips.
///
/// Wire shape: `<connected>:<total>:<bots>:<bot_uuid_list>|<blocks>` where
/// each block is `ip:port:uuid:name|<peer>,<peer>,...;` — our own block
/// first, then any block a peer reported that we do not already carry.
pub fn broadcast_mesh_state(state: &mut HubState) {
    let mut payload = format!(
        "{}:{}:{}:{}|",
        state.bind_ip,
        state.port,
        if state.hub_uuid.is_empty() {
            "-"
        } else {
            &state.hub_uuid
        },
        if state.hub_friendly_name.is_empty() {
            "-"
        } else {
            &state.hub_friendly_name
        }
    );
    if payload.len() >= MAX_BUFFER {
        return;
    }

    for p in &state.peers {
        let is_up = p.fd > 0
            && state
                .clients
                .iter()
                .any(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == p.fd);
        let block = format!(
            "{}:{}:{}:{}:{},",
            p.ip,
            p.port,
            i32::from(is_up),
            if p.uuid.is_empty() { "-" } else { &p.uuid },
            if p.friendly_name.is_empty() {
                "-"
            } else {
                &p.friendly_name
            }
        );
        if payload.len() + block.len() >= MAX_BUFFER {
            break;
        }
        payload.push_str(&block);
    }
    if payload.len() < MAX_BUFFER - 1 {
        payload.push(';');
    }

    // Aggregate gossip from peers: add any block whose owner we do not
    // already list.
    let my_sig = format!("{}:{}", state.bind_ip, state.port);
    let gossips: Vec<String> = state
        .peers
        .iter()
        .filter(|p| p.connected && !p.last_gossip.is_empty())
        .map(|p| p.last_gossip.clone())
        .collect();
    for g in gossips {
        let Some(bar) = g.find('|') else { continue };
        let work = trunc_string(&g[bar + 1..], MAX_BUFFER);
        for block in work.split(';') {
            if block.is_empty() {
                continue;
            }
            let owner = match block.find('|') {
                Some(i) => &block[..i],
                None => block,
            };
            let owner = trunc_string(owner, 256);
            if owner.is_empty() || owner == my_sig {
                continue;
            }
            if payload.contains(&format!("{owner}|")) {
                continue;
            }
            if payload.len() + block.len() + 2 < MAX_BUFFER {
                payload.push_str(block);
                payload.push(';');
            }
        }
    }

    let connected_peers = state.peers.iter().filter(|p| p.connected).count();
    let bot_ids: Vec<String> = state
        .bot_clients()
        .into_iter()
        .map(|i| state.clients[i].id.clone())
        .collect();
    let active_bots = bot_ids.len();
    let bot_uuid_list = if bot_ids.is_empty() {
        "-".to_string()
    } else {
        trunc_string(&bot_ids.join(","), MAX_BUFFER)
    };

    let final_packet = format!(
        "{connected_peers}:{}:{active_bots}:{bot_uuid_list}|{payload}",
        state.peers.len()
    );
    if final_packet.len() >= MAX_BUFFER {
        return;
    }
    let payload_len = final_packet.len().min(MAX_BUFFER - 100);
    let body = &final_packet.as_bytes()[..payload_len];

    // Mesh-state gossip is best-effort and goes through the BULK lane.  A
    // single coalesce key per (origin_hub_uuid, "mesh_state") collapses
    // repeated gossip into the most recent payload if a peer is briefly
    // backed up, so we never queue stale snapshots ahead of fresh ones.
    let coalesce = format!("{}|mesh_state", state.hub_uuid);
    for ci in state.peer_clients() {
        let Some(mut m) = QueuedMsg::new(CMD_MESH_STATE, Lane::Bulk, body) else {
            continue;
        };
        let seq = state.next_lamport_seq();
        let hub_uuid = state.hub_uuid.clone();
        m.set_coalesce(&hub_uuid, seq, &coalesce);
        queue::enqueue(&mut state.clients[ci], m);
    }
}

/// process_mesh_state(): record a peer's snapshot and learn its identity.
pub fn process_mesh_state(state: &mut HubState, ci: usize, payload: &str) {
    // <connected>:<total>:<bots>:...
    let head: Vec<&str> = payload.splitn(4, ':').collect();
    if head.len() < 2
        || crate::cstr::strtoll(head[0]).1 == 0
        || crate::cstr::strtoll(head[1]).1 == 0
    {
        return;
    }
    let fd = state.clients[ci].fd;
    let Some(pi) = state.peers.iter().position(|p| p.connected && p.fd == fd) else {
        return;
    };
    state.peers[pi].last_mesh_report = now();
    state.peers[pi].last_gossip = trunc_string(payload, MAX_BUFFER);

    // Gossip shape: connected:total:bots:bot_list|ip:port:uuid:friendly_name|...
    let Some(bar) = payload.find('|') else { return };
    let mesh_start = &payload[bar + 1..];
    // Parse: ip:port:uuid:friendly_name|
    let f: Vec<&str> = mesh_start.splitn(4, ':').collect();
    if f.len() < 3 {
        return;
    }
    let remote_uuid = trunc_string(f[2], 64);
    let remote_name = if f.len() >= 4 {
        trunc_string(
            match f[3].find('|') {
                Some(i) => &f[3][..i],
                None => f[3],
            },
            64,
        )
    } else {
        String::new()
    };

    let mut config_updated = false;

    // Update friendly_name if it changed (and is a well-formed name: it is
    // written to our config and shown to operators).
    if !remote_name.is_empty()
        && remote_name != "-"
        && crate::state::name_valid(&remote_name)
        && state.peers[pi].friendly_name != remote_name
    {
        state.peers[pi].friendly_name = remote_name.clone();
        hlog!("[MESH] Updated peer friendly_name to: {remote_name}\n");
        config_updated = true;
    }

    // Also update the UUID if it changed (a peer added without one).
    if !remote_uuid.is_empty()
        && remote_uuid != "-"
        && (state.peers[pi].uuid.is_empty() || state.peers[pi].uuid != remote_uuid)
    {
        state.peers[pi].uuid = remote_uuid.clone();
        hlog!("[MESH] Updated peer UUID to: {remote_uuid}\n");
        config_updated = true;
    }

    if config_updated {
        state.config_dirty = true;
    }
}

// ---------------------------------------------------------------------------
// Sync fan-out
// ---------------------------------------------------------------------------

/// hub_broadcast_sync_to_peers().
///
/// Lane heuristic: a single-line CMD_PEER_SYNC payload originating from a
/// delta forward is short (< 1 KB) and time-sensitive, so it rides DELTA and
/// is not throttled by the BULK budget.  Larger, multi-line payloads (an
/// anti-entropy full sync) ride BULK.
pub fn broadcast_sync_to_peers(state: &mut HubState, payload: &str, exclude_fd: i32) {
    // Change 5: a full-state anti-entropy sync can exceed MAX_BUFFER; bound
    // by the sync-payload ceiling so it is never silently dropped here.
    if payload.len() > MAX_SYNC_PAYLOAD - 10 {
        return;
    }
    let lane = if payload.len() > 1024 {
        Lane::Bulk
    } else {
        Lane::Delta
    };
    for ci in state.peer_clients() {
        if state.clients[ci].fd == exclude_fd {
            continue;
        }
        let Some(m) = QueuedMsg::new(CMD_PEER_SYNC, lane, payload.as_bytes()) else {
            continue;
        };
        if !queue::enqueue(&mut state.clients[ci], m) {
            // Only URGENT can fail here; PEER_SYNC is DELTA/BULK so this is
            // effectively unreachable, but be safe.
            hlog!("[MESH] enqueue failed for peer {}\n", state.clients[ci].ip);
        }
    }
}

/// hub_request_sync_from_peers(): ask every peer for its full state now.
pub fn request_sync_from_peers(state: &mut HubState) {
    let mut sent = 0;
    let mut i = 0;
    while i < state.clients.len() {
        let c = &state.clients[i];
        if c.typ == ClientType::Hub && c.authenticated {
            if queue::send_urgent(&mut state.clients[i], CMD_SYNC_REQUEST, "") {
                sent += 1;
            } else {
                crate::auth::disconnect_client(state, i);
                continue;
            }
        }
        i += 1;
    }
    if sent > 0 {
        hlog!("[MESH] Sent sync request to {sent} peer(s)\n");
    }
}

/// hub_generate_sync_packet(): this hub's full state, for anti-entropy.
pub fn generate_sync_packet(state: &HubState) -> String {
    let max_len = MAX_SYNC_PAYLOAD;
    let mut out = String::with_capacity(4096);

    // 1. Global entries (c, m, o, a, p).
    //    h/n/w/x are hub-only local metadata and never belong here:
    //      - h/n: hub name/bind settings (shouldn't exist in global_entries)
    //      - w/x: allowlist/denylist, kept local
    //    Bot-specific h/n (b|uuid|h|..., b|uuid|n|...) go in the bot loop.
    for e in &state.global_entries {
        if matches!(
            e.key.as_str(),
            "h" | "n" | "w" | "x" | "a" | "o" | "m" | "p"
        ) {
            continue;
        }
        let line = format!("{}|{}|{}\n", e.key, e.value, e.timestamp);
        if out.len() + line.len() >= max_len {
            break;
        }
        out.push_str(&line);
    }

    // User records, so peer hubs share admin/oper records, in the
    // passwordless shape uuid|name|pubkey|act|seen|ts| (peers are HUBv3, so
    // they parse it).
    for u in &state.user_records {
        let line = config::format_user_record(u, false);
        if out.len() + line.len() >= max_len {
            break;
        }
        out.push_str(&line);
    }
    for m in &state.mask_records {
        let line = format!(
            "m|{}|{}|{}|{}|{}\n",
            m.uuid,
            m.mask,
            if m.is_active { "add" } else { "del" },
            m.last_used,
            m.timestamp
        );
        if out.len() + line.len() >= max_len {
            break;
        }
        out.push_str(&line);
    }

    // The network opt flag string (peers must converge on this).
    if state.opt_flags_ts > 0 {
        let line = format!("opt|{}|{}\n", state.opt_flags, state.opt_flags_ts);
        if out.len() + line.len() < max_len {
            out.push_str(&line);
        }
    }

    // 2. Bot entries.
    'outer: for b in &state.bots {
        for e in &b.entries {
            // "seen" and "t" carry no value field.
            let line = if e.key == "seen" || e.key == "t" {
                format!("b|{}|{}|{}\n", b.uuid, e.key, e.timestamp)
            } else {
                format!("b|{}|{}|{}|{}\n", b.uuid, e.key, e.value, e.timestamp)
            };
            if out.len() + line.len() >= max_len {
                break 'outer;
            }
            out.push_str(&line);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Global entry helpers
// ---------------------------------------------------------------------------

fn is_global_key(key: &str) -> bool {
    matches!(key, "c" | "m" | "o" | "a" | "p")
}

/// Store a global entry directly, without re-formatting: the value that
/// arrived over the wire is already combined.
fn store_global_entry_raw(state: &mut HubState, key: &str, value: &str, ts: i64) -> bool {
    let is_singleton = key == "a" || key == "p";
    let incoming_first = match value.find('|') {
        Some(i) => &value[..i],
        None => value,
    };
    let found = state.global_entries.iter().position(|e| {
        if is_singleton {
            e.key == key
        } else {
            let stored_first = match e.value.find('|') {
                Some(i) => &e.value[..i],
                None => e.value.as_str(),
            };
            e.key == key && stored_first == incoming_first
        }
    });

    if let Some(i) = found {
        if lww_accepts(
            ts,
            global_value_active(value),
            state.global_entries[i].timestamp,
            global_value_active(&state.global_entries[i].value),
        ) {
            state.global_entries[i].value = trunc_string(value, 1024);
            state.global_entries[i].timestamp = ts;
            return true;
        }
        return false;
    }

    if state.global_entries.len() < MAX_BOT_ENTRIES {
        state.global_entries.push(ConfigEntry {
            key: trunc_string(key, 32),
            value: trunc_string(value, 1024),
            timestamp: ts,
        });
        return true;
    }
    false
}

/// Split a stored global 'c' entry value into its parts.
///
/// Two shapes exist because two writers produce them:
///   3-field  `chan|key|op`        — CMD_ADMIN_ADD/DEL_CHANNEL and legacy
///   4-field  `chan|key|modes|op`  — a bot's config push (bots report modes)
///
/// Both share the same anchors — the channel is the first field, the op is
/// the last — so this splits on those instead of counting fields.  Whatever
/// sits between is the key, optionally followed by the modes.  Reading the op
/// as the *last* field is what makes the "del" tombstone check reliable
/// across both shapes: a positional parse reads "0|del" as the op on the
/// 4-field form and treats a deleted channel as live.
///
/// None only when the value has no '|' at all.
pub fn parse_global_channel_value(value: &str) -> Option<(String, String, i32, String)> {
    let first = value.find('|')?;
    let last = value.rfind('|')?;
    let chan = value[..first].to_string();
    let op = value[last + 1..].to_string();
    let mut key = String::new();
    let mut modes = 0i32;
    if last > first {
        // Middle field(s): "key" (3-field) or "key|modes" (4-field).
        let middle = trunc_string(&value[first + 1..last], 128);
        match middle.rfind('|') {
            Some(sep) => {
                modes = crate::cstr::atoi(&middle[sep + 1..]);
                key = middle[..sep].to_string();
            }
            None => key = middle,
        }
    }
    Some((chan, key, modes, op))
}

/// Modes currently recorded for a channel, or 0 when unknown.
///
/// The admin add path has no modes of its own — they only ever arrive from a
/// bot reporting a live MODE change — so a re-add must carry forward what is
/// already stored.  Global entries are overwritten wholesale once the
/// timestamp wins, so not carrying them forward erases them.  Matched
/// case-sensitively on the channel name, same as the storage layer.
pub fn global_channel_modes(state: &HubState, chan: &str) -> i32 {
    for e in state.global_entries.iter().filter(|e| e.key == "c") {
        if let Some((stored_chan, _, modes, _)) = parse_global_channel_value(&e.value)
            && trunc_string(&stored_chan, 128) == chan
        {
            return modes;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Peer sync ingest
// ---------------------------------------------------------------------------

/// The state one line of a peer sync may change.
struct SyncCounters {
    updates: u32,
    /// Only keys bots actually consume; gates the full config push.
    bot_push_updates: u32,
    forward: String,
}

/// One `a|`/`o|` record from a peer.
fn sync_user_record(state: &mut HubState, key: char, vstart: &str, cnt: &mut SyncCounters) {
    // hub_parse_user_record: uuid|name|pubkey|act|seen|ts| (a legacy password
    // shape parses too; the password is dropped).
    let Some((incoming, _)) = config::parse_user_record(vstart, key) else {
        return;
    };
    let mut found = state
        .user_records
        .iter()
        .position(|u| u.uuid == incoming.uuid);
    let mut discard_incoming = false;

    if found.is_none() {
        // No UUID match — check for a name collision before inserting.
        if let Some(ni) = state
            .user_records
            .iter()
            .position(|ex| ex.typ == key && ex.name.eq_ignore_ascii_case(&incoming.name))
        {
            let ex = &state.user_records[ni];
            let incoming_wins = incoming.last_seen > ex.last_seen
                || (incoming.last_seen == ex.last_seen && incoming.timestamp > ex.timestamp)
                || (incoming.last_seen == ex.last_seen
                    && incoming.timestamp == ex.timestamp
                    && incoming.uuid < ex.uuid);
            if incoming_wins {
                hlog!(
                    "[MESH] Dedup: '{}' ({key}) UUID collision resolved, adopting {}\n",
                    incoming.name,
                    incoming.uuid
                );
                let old_uuid = state.user_records[ni].uuid.clone();
                // Remap the existing record's masks to the incoming UUID.
                for m in state.mask_records.iter_mut().filter(|m| m.uuid == old_uuid) {
                    m.uuid = incoming.uuid.clone();
                }
                // Update the user record's own UUID so the next sync finds it
                // by UUID lookup and skips the name-collision path.
                state.user_records[ni].uuid = incoming.uuid.clone();
                state.config_dirty = true;
                found = Some(ni);
            } else {
                discard_incoming = true;
            }
        }
    }

    if found.is_none() && !discard_incoming && state.user_records.len() < MAX_HUB_USER_RECORDS {
        state.user_records.push(UserRecord {
            uuid: incoming.uuid.clone(),
            ..Default::default()
        });
        found = Some(state.user_records.len() - 1);
    }

    let Some(ui) = found else { return };
    if discard_incoming {
        return;
    }
    let cur = &state.user_records[ui];
    if !lww_accepts(
        incoming.timestamp,
        incoming.is_active,
        cur.timestamp,
        cur.is_active,
    ) {
        return;
    }
    let u = &mut state.user_records[ui];
    u.name = incoming.name;
    u.typ = key;
    u.is_active = incoming.is_active;
    if incoming.last_seen > u.last_seen {
        u.last_seen = incoming.last_seen;
    }
    u.timestamp = incoming.timestamp;
    // A keyless push never erases a key the hub already holds.
    if incoming.has_pubkey {
        u.pubkey_b64 = incoming.pubkey_b64;
        u.has_pubkey = true;
    }
    state.config_dirty = true;
    cnt.updates += 1;
    cnt.bot_push_updates += 1; // admin/oper name change — bots need this

    // Forward our canonical a|/o| line, never the raw one: a legacy-shaped
    // line must not carry a password onward.
    let uline = config::format_user_record(&state.user_records[ui], false);
    if uline.len() < USER_LINE_MAX && cnt.forward.len() + uline.len() < MAX_SYNC_PAYLOAD {
        cnt.forward.push_str(&uline);
    }
}

/// One `m|` record from a peer: `uuid|mask|add/del|last_used|ts`.
fn sync_mask_record(state: &mut HubState, vstart: &str, line: &str, cnt: &mut SyncCounters) {
    let f = split_fields(vstart, 5);
    if f.len() < 5 {
        return;
    }
    let uuid = trunc_string(f[0], 37);
    let mask = trunc_string(f[1], MAX_MASK_LEN);
    let act = trunc_string(f[2], 8);
    let last_used = atoll(f[3]);
    let ts = atoll(f[4]);
    let is_active = act.starts_with("add");

    // Reject masks for unknown user UUIDs.
    if !state.user_records.iter().any(|u| u.uuid == uuid) {
        return;
    }
    let found = state
        .mask_records
        .iter()
        .position(|m| m.uuid == uuid && m.mask.eq_ignore_ascii_case(&mask));
    let mi = match found {
        Some(i) => i,
        None if state.mask_records.len() < MAX_HUB_USER_MASKS => {
            state.mask_records.push(MaskRecord {
                uuid,
                mask,
                ..Default::default()
            });
            state.mask_records.len() - 1
        }
        None => return,
    };
    let cur = &state.mask_records[mi];
    if !lww_accepts(ts, is_active, cur.timestamp, cur.is_active) {
        return;
    }
    let m = &mut state.mask_records[mi];
    m.is_active = is_active;
    if last_used > m.last_used {
        m.last_used = last_used;
    }
    m.timestamp = ts;
    state.config_dirty = true;
    cnt.updates += 1;
    cnt.bot_push_updates += 1; // mask record — bots need this
    if cnt.forward.len() + line.len() + 1 < MAX_SYNC_PAYLOAD {
        cnt.forward.push_str(line);
        cnt.forward.push('\n');
    }
}

/// One `b|uuid|key|value|ts` (or `b|uuid|seen|ts`) record from a peer.
fn sync_bot_entry(state: &mut HubState, ptr: &str, cnt: &mut SyncCounters) {
    let Some(p1) = ptr.find('|') else { return };
    let uuid = trunc_string(&ptr[..p1], 64);
    let rest = &ptr[p1 + 1..];
    let Some(p2) = rest.find('|') else { return };
    let key = trunc_string(&rest[..p2], 32);
    let tail = &rest[p2 + 1..];

    let p3 = tail.rfind('|');
    // seen/t entries are 3-field: b|uuid|key|timestamp (no value).  When
    // there is no further '|' the timestamp sits at the start of `tail` and
    // the value is empty.
    if p3.is_none() && (key == "seen" || key == "t") {
        let ts = atoll(tail);
        if storage::update_entry(state, &uuid, &key, "", "", "", ts) {
            cnt.updates += 1;
            let line = format!("b|{uuid}|{key}|{ts}\n");
            if cnt.forward.len() + line.len() < MAX_SYNC_PAYLOAD {
                cnt.forward.push_str(&line);
            }
        }
        return;
    }
    let Some(p3) = p3 else { return };
    let val = trunc_string(&tail[..p3], 1024);
    let ts = atoll(&tail[p3 + 1..]);

    // For c/m/o keys, parse the combined value format.  The split works on a
    // copy: `val` itself is re-forwarded to the other peers below and must
    // leave exactly as it arrived.  Splitting it in place forwarded
    // "b|uuid|c|#chan|ts" — no key, modes or op — which the next hub stored
    // as an add, turning deletes into adds one hop out.
    let mut parsed_val = String::new();
    let mut parsed_extra = String::new();
    let mut parsed_op = String::new();
    if key == "c" || key == "o" {
        // chan|key[|modes]|op: first pipe gives chan, last pipe gives op,
        // everything between is extra.
        if let Some(vp1) = val.find('|') {
            parsed_val = trunc_string(&val[..vp1], 512);
            let rest = &val[vp1 + 1..];
            if let Some(last) = rest.rfind('|') {
                parsed_op = trunc_string(&rest[last + 1..], 16);
                parsed_extra = trunc_string(&rest[..last], 256);
            }
        }
    } else if key == "m" {
        // value|op
        if let Some(vp1) = val.find('|') {
            parsed_val = trunc_string(&val[..vp1], 512);
            parsed_op = trunc_string(&val[vp1 + 1..], 16);
        }
    }
    // For other keys (pub, h, n, ...) parsed_val stays empty so the original
    // value is stored as is.
    let store_val = if parsed_val.is_empty() {
        val.as_str()
    } else {
        parsed_val.as_str()
    };

    if storage::update_entry(state, &uuid, &key, store_val, &parsed_extra, &parsed_op, ts) {
        cnt.updates += 1;
        // seen/t are hub-side metadata; bots don't consume them.
        if key != "seen" && key != "t" {
            cnt.bot_push_updates += 1;
        }
        let line = format!("b|{uuid}|{key}|{val}|{ts}\n");
        if cnt.forward.len() + line.len() + 1200 < MAX_SYNC_PAYLOAD {
            cnt.forward.push_str(&line);
        }
    }
}

/// process_peer_sync(): apply one CMD_PEER_SYNC payload and re-forward what
/// it actually changed.
pub fn process_peer_sync(state: &mut HubState, payload: &str, origin_fd: i32) {
    let mut cnt = SyncCounters {
        updates: 0,
        bot_push_updates: 0,
        forward: String::new(),
    };

    for line in trunc_string(payload, MAX_SYNC_PAYLOAD).split('\n') {
        if line.is_empty() {
            continue;
        }

        if line.starts_with("PURGE|") {
            match parse_purge_line(line) {
                None => hlog!("[MESH] Dropped malformed PURGE line from peer\n"),
                Some((cutoff, purge_id)) => {
                    let shown = if purge_id.is_empty() { "-" } else { &purge_id };
                    hlog!("[MESH] Received PURGE from peer: cutoff={cutoff} id={shown}\n");
                    if is_purge_recent(state, cutoff, &purge_id) {
                        hlog!(
                            "[MESH] PURGE cutoff={cutoff} id={shown} already processed recently, skipping to prevent loop\n"
                        );
                    } else {
                        record_recent_purge(state, cutoff, &purge_id);
                        let purged = execute_purge(state, cutoff).0;
                        if purged > 0 {
                            hlog!("[MESH] Purged {purged} entries from peer sync\n");
                            cnt.updates += purged as u32;
                        }
                        // Forward to all other peers (excluding the sender to
                        // prevent an immediate echo; with the dedup above
                        // that closes the feedback loop).
                        if origin_fd != -1 {
                            broadcast_sync_to_peers(state, line, origin_fd);
                        }
                    }
                }
            }
            continue;
        }

        // Peer-forwarded invite request: invite|nick|#channel
        if let Some(body) = line.strip_prefix("invite|") {
            let f = split_fields(body, 2);
            if f.len() == 2 && !f[0].is_empty() && !f[1].is_empty() {
                let (inv_nick, inv_chan) = (f[0], f[1].split_whitespace().next().unwrap_or(""));
                if !inv_chan.is_empty() {
                    hlog!("[MESH] Forwarded INVITE_REQUEST: invite {inv_nick} into {inv_chan}\n");
                    let inv_payload = format!("{inv_nick}|{inv_chan}");
                    for ci in state.bot_clients() {
                        client::send_cmd_to_bot(
                            &mut state.clients[ci],
                            CMD_INVITE_REQUEST,
                            &inv_payload,
                        );
                    }
                }
            }
            continue;
        }

        // 'opt|<letters>|<ts>' from peer hubs (mesh-replicated opt flags),
        // including the 'opt||<ts>' of a clear.  Adopt it if newer than ours.
        if let Some(body) = line.strip_prefix("opt|") {
            if let Some((flags, ts)) = config::parse_opt_value(body)
                && opt_accepts(ts, &flags, state.opt_flags_ts, &state.opt_flags)
            {
                state.opt_flags = flags;
                state.opt_flags_ts = ts;
                state.config_dirty = true;
                cnt.updates += 1;
                cnt.bot_push_updates += 1;
                if cnt.forward.len() + line.len() + 64 < MAX_SYNC_PAYLOAD {
                    cnt.forward.push_str(line);
                    cnt.forward.push('\n');
                }
            }
            continue;
        }

        // A global entry (key|value|timestamp), i.e. not starting with "b|".
        if !line.starts_with("b|")
            && let Some(p1) = line.find('|')
            && p1 < 32
        {
            let key = &line[..p1];
            if is_global_key(key) {
                let vstart = &line[p1 + 1..];
                let is_user_key = key == "a" || key == "o";
                let is_mask_key = key == "m";

                // Detect the new-format user/mask records by a UUID in the
                // first value field:
                //   a|uuid|name|pubkey|add/del|last_seen|ts|
                //   m|uuid|mask|add/del|last_used|ts
                // Route these to the typed arrays; the old format goes to
                // global_entries.
                let first_f = match vstart.find('|') {
                    Some(i) if i < 40 => &vstart[..i],
                    _ => "",
                };
                let is_new_fmt = crate::cstr::has_uuid_dashes(first_f);

                if is_new_fmt && is_user_key {
                    sync_user_record(state, key.as_bytes()[0] as char, vstart, &mut cnt);
                    continue;
                }
                if is_new_fmt && is_mask_key {
                    sync_mask_record(state, vstart, line, &mut cnt);
                    continue;
                }

                // Retired password-era shapes — the shared bot password p|
                // and the pre-UUID a|<password>|<ts> / o|<mask>|<password>|..
                // rows — are dropped, never stored or forwarded.
                if key == "p" || is_user_key {
                    continue;
                }

                // Old-format or non-user global key: store in global_entries.
                if let Some(p_last) = vstart.rfind('|')
                    && p_last > 0
                {
                    let val = trunc_string(&vstart[..p_last], 1024);
                    let ts = atoll(&vstart[p_last + 1..]);
                    if store_global_entry_raw(state, key, &val, ts) {
                        cnt.updates += 1;
                        cnt.bot_push_updates += 1; // channel/global — bots need this
                        let fwd = format!("{key}|{val}|{ts}\n");
                        if cnt.forward.len() + fwd.len() + 1200 < MAX_SYNC_PAYLOAD {
                            cnt.forward.push_str(&fwd);
                        }
                    }
                }
                continue;
            }
        }

        // Bot entries (b|uuid|key|value|timestamp, or the bare uuid|... form
        // an admin add broadcasts).
        let ptr = line.strip_prefix("b|").unwrap_or(line);
        sync_bot_entry(state, ptr, &mut cnt);
    }

    if cnt.updates > 0 {
        state.config_dirty = true;
        hlog!(
            "[MESH] Synced {} entries from Peer ({} bot-relevant).\n",
            cnt.updates,
            cnt.bot_push_updates
        );
        if !cnt.forward.is_empty() {
            broadcast_sync_to_peers(state, &cnt.forward, origin_fd);
        }
        if cnt.bot_push_updates > 0 {
            client::broadcast_full_config_to_all_bots(state);
        }
    }
}

// ---------------------------------------------------------------------------
// Tombstone purge
// ---------------------------------------------------------------------------

/// hub_execute_purge(): remove tombstones locally.  `cutoff == 0` purges all
/// tombstones regardless of age; `cutoff > 0` purges those older than it.
/// Peer-hub propagation is the caller's responsibility.
///
/// Returns (count, log).
pub fn execute_purge(state: &mut HubState, cutoff: i64) -> (i32, String) {
    let mut purged_count = 0;
    let mut log_out = String::new();

    // --- Tombstoned global entries (channels, admin masks, oper masks) ---
    let mut kept: Vec<ConfigEntry> = Vec::new();
    for e in std::mem::take(&mut state.global_entries) {
        let is_tombstone =
            matches!(e.key.as_str(), "c" | "m" | "o") && e.value.rsplit('|').next() == Some("del");
        if is_tombstone && (cutoff == 0 || e.timestamp < cutoff) {
            purged_count += 1;
            log_out.push_str(&format!("  Purged: {}|{}\n", e.key, e.value));
        } else if kept.len() < MAX_BOT_ENTRIES {
            kept.push(e);
        }
    }
    state.global_entries = kept;

    // --- Tombstoned user_records (admins/opers) ---
    let mut kept_users: Vec<UserRecord> = Vec::new();
    for u in std::mem::take(&mut state.user_records) {
        if !u.is_active && (cutoff == 0 || u.timestamp < cutoff) {
            purged_count += 1;
        } else if kept_users.len() < MAX_HUB_USER_RECORDS {
            kept_users.push(u);
        }
    }
    state.user_records = kept_users;

    // --- Tombstoned mask_records, and masks whose user is gone ---
    // A mask with no user record left (its user purged above or earlier) can
    // never authenticate anyone and only holds a slot of the shared table.
    // Such orphans were left live on peers and bots by user deletes that did
    // not send the masks' tombstones; every hub applies the same rule on the
    // same PURGE, so they converge away.
    let mut kept_masks: Vec<MaskRecord> = Vec::new();
    for m in std::mem::take(&mut state.mask_records) {
        let owned = state.user_records.iter().any(|u| u.uuid == m.uuid);
        if !owned || (!m.is_active && (cutoff == 0 || m.timestamp < cutoff)) {
            purged_count += 1;
        } else if kept_masks.len() < MAX_HUB_USER_MASKS {
            kept_masks.push(m);
        }
    }
    state.mask_records = kept_masks;

    // --- Tombstoned bots (a d|1 entry present, regardless of is_active) ---
    let mut kept_bots = Vec::new();
    for b in std::mem::take(&mut state.bots) {
        let del_ts = b
            .entries
            .iter()
            .find(|e| e.key == "d" && e.value == "1")
            .map(|e| e.timestamp);
        let purge_bot = match del_ts {
            Some(ts) => cutoff == 0 || (ts > 0 && ts < cutoff),
            None => false,
        };
        if purge_bot {
            purged_count += 1;
            match b.entry("n") {
                Some(n) => log_out.push_str(&format!(
                    "  Purged bot: {} ({})\n",
                    b.uuid,
                    trunc_string(&n.value, 32)
                )),
                None => log_out.push_str(&format!("  Purged bot: {}\n", b.uuid)),
            }
        } else if kept_bots.len() < MAX_BOTS {
            kept_bots.push(b);
        }
    }
    state.bots = kept_bots;

    state.config_dirty = true;

    // Local bots: first the purged config, then the PURGE line itself.
    // broadcast_config_to_bots only logs its line and re-sends each bot its
    // full config — that replaces a bot's user/mask tables, but channel
    // tombstones are merged on the bot and only a PURGE| line removes them.
    // The PURGE frame is queued behind the (coalesced) config push on the
    // same lane, so a pre-purge config still queued cannot re-add what it
    // purged.
    let purge_msg = format!("PURGE|{cutoff}\n");
    client::broadcast_config_to_bots(state, &purge_msg);
    for ci in state.bot_clients() {
        let Some(m) = QueuedMsg::new(CMD_CONFIG_DATA, Lane::Bulk, purge_msg.as_bytes()) else {
            hlog!(
                "[PURGE] OOM queueing PURGE for bot {}\n",
                state.clients[ci].id
            );
            continue;
        };
        if !queue::enqueue(&mut state.clients[ci], m) {
            hlog!(
                "[PURGE] could not queue PURGE for bot {}\n",
                state.clients[ci].id
            );
        }
    }

    (purged_count, log_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_line_shapes() {
        assert_eq!(parse_purge_line("PURGE|0"), Some((0, String::new())));
        assert_eq!(
            parse_purge_line("PURGE|123|ab12"),
            Some((123, "ab12".into()))
        );
        assert!(parse_purge_line("PURGE|-1").is_none());
        assert!(parse_purge_line("PURGE|x").is_none());
        assert!(parse_purge_line("PURGE|1|").is_none());
        assert!(parse_purge_line("PURGE|1|zz").is_none());
        assert!(parse_purge_line("PURGE|1|00112233445566778").is_none());
        assert!(parse_purge_line("PURGE|1 junk").is_none());
    }

    #[test]
    fn purge_dedup_is_keyed_on_cutoff_and_id() {
        let mut s = HubState::new();
        assert!(!is_purge_recent(&s, 0, "aa"));
        record_recent_purge(&mut s, 0, "aa");
        assert!(is_purge_recent(&s, 0, "aa"));
        // A second "immediate" purge with its own id is not the same purge.
        assert!(!is_purge_recent(&s, 0, "bb"));
        // The ring never grows past its cap.
        for i in 0..MAX_RECENT_PURGES * 2 {
            record_recent_purge(&mut s, i as i64, "id");
        }
        assert_eq!(s.recent_purges.len(), MAX_RECENT_PURGES);
    }

    #[test]
    fn leader_is_the_smallest_uuid() {
        let mut s = HubState::new();
        s.hub_uuid = "bbb".into();
        assert!(should_initiate_scheduled_purge(&s));
    }

    #[test]
    fn channel_value_reads_op_as_the_last_field() {
        // 3-field admin shape.
        let (c, k, m, op) = parse_global_channel_value("#chan|key|add").unwrap();
        assert_eq!(
            (c.as_str(), k.as_str(), m, op.as_str()),
            ("#chan", "key", 0, "add")
        );
        // 4-field bot shape: a positional parse would read "0|del" as the op.
        let (c, k, m, op) = parse_global_channel_value("#chan|key|5|del").unwrap();
        assert_eq!(
            (c.as_str(), k.as_str(), m, op.as_str()),
            ("#chan", "key", 5, "del")
        );
        // Keyless.
        let (c, k, m, op) = parse_global_channel_value("#chan||0|add").unwrap();
        assert_eq!(
            (c.as_str(), k.as_str(), m, op.as_str()),
            ("#chan", "", 0, "add")
        );
        assert!(parse_global_channel_value("#chan").is_none());
    }

    #[test]
    fn purge_removes_tombstones_and_orphans() {
        let mut s = HubState::new();
        storage::update_global_entry(&mut s, "c", "#live", "k|0", "add", 100);
        storage::update_global_entry(&mut s, "c", "#dead", "|0", "del", 100);
        s.user_records.push(UserRecord {
            uuid: "u1".into(),
            name: "gone".into(),
            typ: 'a',
            is_active: false,
            timestamp: 100,
            ..Default::default()
        });
        s.mask_records.push(MaskRecord {
            uuid: "u1".into(),
            mask: "n!*@*".into(),
            is_active: true,
            timestamp: 100,
            ..Default::default()
        });
        storage::update_entry(&mut s, "bot-dead", "n", "x", "", "", 100);
        storage::update_entry(&mut s, "bot-dead", "d", "1", "", "", 100);
        storage::update_entry(&mut s, "bot-live", "n", "y", "", "", 100);

        let (n, log) = execute_purge(&mut s, 0);
        // dead channel + dead user + its now-orphaned mask + dead bot
        assert_eq!(n, 4);
        assert!(log.contains("#dead"));
        assert!(log.contains("bot-dead (x)"));
        assert_eq!(s.global_entries.len(), 1);
        assert!(s.user_records.is_empty());
        assert!(s.mask_records.is_empty());
        assert_eq!(s.bots.len(), 1);
        assert_eq!(s.bots[0].uuid, "bot-live");
    }

    #[test]
    fn purge_respects_a_cutoff() {
        let mut s = HubState::new();
        storage::update_global_entry(&mut s, "c", "#old", "|0", "del", 100);
        storage::update_global_entry(&mut s, "c", "#new", "|0", "del", 900);
        let (n, _) = execute_purge(&mut s, 500);
        assert_eq!(n, 1);
        assert_eq!(s.global_entries.len(), 1);
        assert!(s.global_entries[0].value.starts_with("#new"));
    }

    #[test]
    fn sync_packet_omits_local_only_keys() {
        let mut s = HubState::new();
        storage::update_global_entry(&mut s, "c", "#a", "|0", "add", 100);
        s.global_entries.push(ConfigEntry {
            key: "w".into(),
            value: "10.0.0.0/8".into(),
            timestamp: 100,
        });
        s.opt_flags = "h".into();
        s.opt_flags_ts = 500;
        storage::update_entry(&mut s, "bot-1", "h", "n!u@h", "", "", 100);
        storage::update_entry(&mut s, "bot-1", "seen", "", "", "", 200);
        let p = generate_sync_packet(&s);
        assert!(p.contains("c|#a||0|add|100\n"));
        assert!(!p.contains("w|"));
        assert!(p.contains("opt|h|500\n"));
        assert!(p.contains("b|bot-1|h|n!u@h|100\n"));
        assert!(p.contains("b|bot-1|seen|200\n"));
    }

    #[test]
    fn peer_sync_ingests_and_forwards_canonically() {
        let mut s = HubState::new();
        let (_, pubk) = crypto::generate_combined_keypair().unwrap();
        let k = crypto::b64_encode(&pubk);
        let payload = format!(
            "a|11111111-2222-3333-4444-555555555555|rob|{k}|add|10|20|\n\
             m|11111111-2222-3333-4444-555555555555|rob!*@host|add|0|20\n\
             c|#chan|key|0|add|30\n\
             b|bot-1|h|rob!u@h|40\n\
             opt|h|50\n"
        );
        process_peer_sync(&mut s, &payload, -1);
        assert_eq!(s.user_records.len(), 1);
        assert!(s.user_records[0].has_pubkey);
        assert_eq!(s.mask_records.len(), 1);
        assert_eq!(s.opt_flags, "h");
        assert_eq!(s.bot_entry("bot-1", "h"), Some("rob!u@h"));
        assert!(s.global_entries.iter().any(|e| e.key == "c"));
        // A mask whose owner we do not know is refused.
        process_peer_sync(
            &mut s,
            "m|99999999-2222-3333-4444-555555555555|x!*@*|add|0|99\n",
            -1,
        );
        assert_eq!(s.mask_records.len(), 1);
    }

    /// A legacy-shaped a| line carries a password in field 3.  It may be
    /// ingested (the key is taken from field 7), but what this hub forwards
    /// on must be its own canonical line — the password must not travel one
    /// hop further.
    #[test]
    fn peer_sync_forwards_canonically_never_a_password() {
        let mut s = HubState::new();
        s.hub_uuid = "me".into();
        let (_, pubk) = crypto::generate_combined_keypair().unwrap();
        let k = crypto::b64_encode(&pubk);
        // Stand in a peer so the forward path has somewhere to go.
        s.peers.push(crate::state::PeerConfig {
            uuid: "them".into(),
            ..Default::default()
        });

        let legacy = format!("a|11111111-2222-3333-4444-555555555555|rob|hunter2|add|10|20|{k}\n");
        process_peer_sync(&mut s, &legacy, -1);

        let u = &s.user_records[0];
        assert_eq!(u.name, "rob");
        assert!(u.has_pubkey);
        assert_eq!(u.pubkey_b64, k);
        // Nothing anywhere in this hub's state holds the password.
        let canonical = config::format_user_record(u, false);
        assert!(!canonical.contains("hunter2"));
        assert_eq!(
            canonical,
            format!("a|11111111-2222-3333-4444-555555555555|rob|{k}|add|10|20|\n")
        );
        // And the sync packet it will hand any peer carries only that shape.
        assert!(!generate_sync_packet(&s).contains("hunter2"));
    }

    /// The `b|` re-forward must be byte-identical to what arrived: splitting
    /// the value in place forwarded "b|uuid|c|#chan|ts" — no key, modes or op
    /// — which the next hub stored as an add, turning deletes into adds one
    /// hop out.
    #[test]
    fn peer_sync_reforwards_bot_values_unsplit() {
        let mut s = HubState::new();
        // A channel arrives on the per-bot wire shape; `c` is a global key,
        // so the storage layer routes it to the global table.
        process_peer_sync(&mut s, "b|bot-1|c|#chan|key|0|del|500\n", -1);
        let e = s.global_entries.iter().find(|e| e.key == "c").unwrap();
        // All four fields survived the split, so the op is still read as the
        // last one and the delete stayed a delete.
        assert_eq!(e.value, "#chan|key|0|del");
        assert_eq!(e.timestamp, 500);
        assert!(!global_value_active(&e.value));
        // A hub that split the value in place would have stored "#chan" with
        // no op, which reads as an add.
        assert!(!s.bots.iter().any(|b| b.uuid == "bot-1"));
    }

    #[test]
    fn peer_sync_drops_retired_shapes() {
        let mut s = HubState::new();
        process_peer_sync(&mut s, "p|sharedpassword|100\n", -1);
        assert!(s.global_entries.is_empty());
        // The pre-UUID a|<password>|<ts> row has no UUID in field 1.
        process_peer_sync(&mut s, "a|hunter2|100\n", -1);
        assert!(s.user_records.is_empty());
        assert!(s.global_entries.is_empty());
    }
}
