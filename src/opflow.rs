//! Cross-hub request routing (hub_logic.c): op grants between bots, and the
//! channel-access requests (unban / invite / key) a locked-out bot makes.
//!
//! Both flows work the same way: stamp a request id, act on it locally,
//! forward it to the peers under that id, and drop the second sighting via
//! the shared `seen_forwards` LRU ring — which is what keeps a mesh of hubs
//! from turning one request into a broadcast storm.  Everything rides the
//! URGENT lane so a bulk sync can never delay an op grant.

use crate::consts::*;
use crate::cstr::{Conv, Fmt, now, sscanf, trunc_string};
use crate::state::{ClientType, HubState};
use crate::{auth, client, crypto, mesh, queue};

// ---------------------------------------------------------------------------
// Shared request-id plumbing
// ---------------------------------------------------------------------------

/// generate_request_id(): "xxxxxxxx-xxxx-xxxx" from 8 random bytes.
pub fn generate_request_id() -> String {
    let h = crypto::random_hex(8).unwrap_or_else(|| "0".repeat(16));
    format!("{}-{}-{}", &h[0..8], &h[8..12], &h[12..16])
}

/// op_forward_seen_check_and_add(): true when this id was already processed
/// (the caller drops the packet); false the first time, inserting it into the
/// LRU ring.
///
/// This is the primary defence against infinite re-broadcast storms: each hub
/// processes a given request at most once, regardless of how many peers flood
/// copies of it back.
pub fn forward_seen_check_and_add(state: &mut HubState, request_id: &str) -> bool {
    if state
        .seen_forwards
        .iter()
        .any(|e| !e.request_id.is_empty() && e.request_id == request_id)
    {
        return true;
    }
    let slot = state.seen_forward_head;
    state.seen_forwards[slot].request_id = trunc_string(request_id, 64);
    state.seen_forwards[slot].seen_at = now();
    state.seen_forward_head = (slot + 1) % MAX_SEEN_FORWARD_IDS;
    false
}

// ---------------------------------------------------------------------------
// Pending OP requests
// ---------------------------------------------------------------------------

fn add_pending_op_request(
    state: &mut HubState,
    request_id: &str,
    requester_uuid: &str,
    target_uuid: &str,
    channel: &str,
    origin_fd: i32,
) -> bool {
    let Some(i) = state.pending_op_requests.iter().position(|p| !p.active) else {
        return false;
    };
    let p = &mut state.pending_op_requests[i];
    p.request_id = trunc_string(request_id, 64);
    p.requester_uuid = trunc_string(requester_uuid, 64);
    p.target_uuid = trunc_string(target_uuid, 64);
    p.channel = trunc_string(channel, MAX_CHAN);
    p.origin_fd = origin_fd;
    p.timestamp = now();
    p.active = true;
    true
}

fn find_pending_op_request(state: &HubState, request_id: &str) -> Option<usize> {
    state
        .pending_op_requests
        .iter()
        .position(|p| p.active && p.request_id == request_id)
}

fn remove_pending_op_request(state: &mut HubState, request_id: &str) {
    if let Some(i) = find_pending_op_request(state, request_id) {
        state.pending_op_requests[i].active = false;
    }
}

/// forward_op_request_to_peers().
///
/// Payload (6 fields):
///   `request_id|requester_uuid|target_uuid|channel|requester_hostmask|origin_ts`
/// The trailing origin_ts is newer than the rest; an old hub peer parses a
/// fixed field count and simply ignores it — wire-backwards-compatible.
// The argument list is the wire record, field for field; bundling it into a
// struct would only rename the same six values.
#[allow(clippy::too_many_arguments)]
pub fn forward_op_request_to_peers(
    state: &mut HubState,
    request_id: &str,
    requester_uuid: &str,
    target_uuid: &str,
    channel: &str,
    requester_hostmask: &str,
    exclude_fd: i32,
    origin_ts: i64,
) {
    let ts = if origin_ts > 0 { origin_ts } else { now() };
    let payload = trunc_string(
        &format!("{request_id}|{requester_uuid}|{target_uuid}|{channel}|{requester_hostmask}|{ts}"),
        680,
    );

    let mut queued = 0;
    let mut i = 0;
    while i < state.clients.len() {
        let c = &state.clients[i];
        if c.typ == ClientType::Hub && c.authenticated && c.fd != exclude_fd {
            let fd = c.fd;
            if !queue::send_urgent(&mut state.clients[i], CMD_OP_FORWARD_REQUEST, &payload) {
                crate::hlog_warning!(
                    "[HUB] URGENT queue full forwarding OP_REQUEST to peer fd={fd} — disconnecting\n"
                );
                auth::disconnect_client(state, i);
                continue;
            }
            queued += 1;
            crate::hlog_debug!(
                "[HUB] Queued OP_FORWARD_REQUEST (id:{request_id}) URGENT to peer fd={fd}\n"
            );
        }
        i += 1;
    }
    if queued > 0 {
        crate::hlog_debug!(
            "[HUB] Forwarded OP_FORWARD_REQUEST (id:{request_id}) to {queued} peer(s)\n"
        );
    }
}

/// Send CMD_OP_GRANT to every authenticated local bot.  They ignore it when
/// they are not in the channel.  Returns how many were told.
fn broadcast_op_grant(state: &mut HubState, payload: &str) -> usize {
    let mut sent = 0;
    for ci in state.bot_clients() {
        if client::send_cmd_to_bot(&mut state.clients[ci], CMD_OP_GRANT, payload) {
            sent += 1;
        }
    }
    sent
}

/// The requesting bot's stored hostmask ('h'), or empty.
fn requester_hostmask(state: &HubState, uuid: &str) -> String {
    state
        .bot_entry(uuid, "h")
        .map(|v| trunc_string(v, MAX_MASK_LEN))
        .unwrap_or_default()
}

/// CMD_OP_REQUEST from one of our own bots: `target_uuid|channel`.
pub fn process_op_request(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(payload, &[Fmt::Set(63, b"|"), Fmt::Lit("|"), Fmt::Word(64)]);
    if conv.len() != 2 {
        crate::hlog_warning!(
            "[HUB] Invalid OP_REQUEST payload from {}\n",
            state.clients[ci].id
        );
        return;
    }
    let target_uuid = conv[0].s().to_string();
    let channel = conv[1].s().to_string();
    let id = state.clients[ci].id.clone();
    let fd = state.clients[ci].fd;
    crate::hlog_info!("[HUB] OP_REQUEST from {id} for target {target_uuid} in {channel}\n");

    let target = state.bot_client(&target_uuid);

    if target.is_none() {
        // Target bot not connected locally — check for peer hubs.
        crate::hlog_info!("[HUB] Target bot {target_uuid} not connected locally\n");
        let mut peer_count = state.peer_clients().len();

        if peer_count > 0 {
            // Resolve the requester's hostmask here (the home hub always has
            // it).
            let req_hostmask = requester_hostmask(state, &id);
            if req_hostmask.is_empty() {
                crate::hlog_warning!(
                    "[HUB] No hostmask for requester {id} — cannot forward OP_REQUEST\n"
                );
                peer_count = 0; // fall through to OP_FAILED
            } else {
                let request_id = generate_request_id();
                if add_pending_op_request(state, &request_id, &id, &target_uuid, &channel, fd) {
                    // Stamp origin_ts and mark this id as seen on the
                    // originating hub so any loop-back copy is dropped.
                    let op_origin_ts = now();
                    forward_seen_check_and_add(state, &request_id);
                    forward_op_request_to_peers(
                        state,
                        &request_id,
                        &id,
                        &target_uuid,
                        &channel,
                        &req_hostmask,
                        -1,
                        op_origin_ts,
                    );
                    crate::hlog_info!(
                        "[HUB] Forwarded OP_REQUEST (id:{request_id}) to {peer_count} peer hub(s)\n"
                    );
                    return;
                }
                crate::hlog_warning!("[HUB] Failed to add pending OP request - table full\n");
                peer_count = 0;
            }
        }

        if peer_count == 0 {
            // No peers available, or the table is full — send OP_FAILED.
            if let Some(i) = state.client_by_fd(fd) {
                client::send_cmd_to_bot(
                    &mut state.clients[i],
                    CMD_OP_FAILED,
                    "Target bot not connected",
                );
            }
        }
        return;
    }

    let hostmask = requester_hostmask(state, &id);
    if hostmask.is_empty() {
        crate::hlog_warning!("[HUB] No hostmask stored for requesting bot {id}\n");
        if let Some(i) = state.client_by_fd(fd) {
            client::send_cmd_to_bot(
                &mut state.clients[i],
                CMD_OP_FAILED,
                "Hostmask not yet stored",
            );
        }
        return;
    }

    // Forward CMD_OP_GRANT to the target bot: requester_hostmask|channel.
    let grant_payload = trunc_string(&format!("{hostmask}|{channel}"), 512);
    let ti = target.expect("checked above");
    if client::send_cmd_to_bot(&mut state.clients[ti], CMD_OP_GRANT, &grant_payload) {
        crate::hlog_info!(
            "[HUB] Forwarded OP_GRANT to {target_uuid}: grant ops to {hostmask} in {channel}\n"
        );
    }
}

/// process_forward_op_request(): an op request relayed by a peer hub.
pub fn process_forward_op_request(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(
        payload,
        &[
            Fmt::Set(63, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(63, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(63, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(64, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(255, b"|"),
            Fmt::Lit("|"),
            Fmt::Int,
        ],
    );
    let fd = state.clients[ci].fd;
    if conv.len() < 4 {
        crate::hlog_warning!("[HUB] Invalid OP_FORWARD_REQUEST payload from peer fd={fd}\n");
        return;
    }
    let request_id = conv[0].s().to_string();
    let requester_uuid = conv[1].s().to_string();
    let target_uuid = conv[2].s().to_string();
    let channel = conv[3].s().to_string();
    let carried_hostmask = conv.get(4).map_or("", |c| c.s()).to_string();
    let origin_ts = conv.get(5).map_or(0, |c: &Conv| c.i());

    // 1. TTL: drop requests too old to be worth servicing.
    if origin_ts > 0 {
        let age = now() - origin_ts;
        if age > OP_FORWARD_TTL_SECONDS {
            crate::hlog_debug!(
                "[HUB] Dropping expired OP_FORWARD_REQUEST (id:{request_id}, age={age}s > {OP_FORWARD_TTL_SECONDS}s TTL)\n"
            );
            return;
        }
    }

    // 2. Dedup: drop if we have already processed this exact request_id.
    if forward_seen_check_and_add(state, &request_id) {
        crate::hlog_debug!(
            "[HUB] Dropping duplicate OP_FORWARD_REQUEST (id:{request_id}) -- already processed\n"
        );
        return;
    }

    crate::hlog_debug!(
        "[HUB] Received OP_FORWARD_REQUEST (id:{request_id}) from peer fd={fd} target={target_uuid} channel={channel}\n"
    );

    // Admin requests are special: target_uuid "ANY", requester_uuid "ADMIN",
    // and the channel field carries "nick:chan".
    if target_uuid == "ANY" && requester_uuid == "ADMIN" {
        let c = sscanf(
            &channel,
            &[Fmt::Set(63, b":"), Fmt::Lit(":"), Fmt::Word(64)],
        );
        if c.len() == 2 {
            let (nick, chan) = (c[0].s().to_string(), c[1].s().to_string());
            crate::hlog_info!(
                "[HUB] Admin OP_REQUEST for {nick} in {chan} - broadcasting to local bots\n"
            );
            let sent = broadcast_op_grant(state, &trunc_string(&format!("{nick}|{chan}"), 256));
            // Forward to the other peer hubs so they can deliver to their own
            // local bots.  Their seen-set keeps them from processing it twice.
            forward_op_request_to_peers(
                state,
                &request_id,
                &requester_uuid,
                &target_uuid,
                &channel,
                "",
                fd,
                origin_ts,
            );
            crate::hlog_info!(
                "[HUB] Admin OP_REQUEST delivered to {sent} local bot(s), forwarding to peers\n"
            );
        }
        return;
    }

    let Some(ti) = state.bot_client(&target_uuid) else {
        // Target not found locally — forward to the other peers.
        crate::hlog_debug!(
            "[HUB] Target bot {target_uuid} not found locally, forwarding to {} peer(s)\n",
            state.clients.len()
        );
        forward_op_request_to_peers(
            state,
            &request_id,
            &requester_uuid,
            &target_uuid,
            &channel,
            &carried_hostmask,
            fd,
            origin_ts,
        );
        return;
    };

    // Use the hostmask carried in the forwarded payload; fall back to local
    // storage.
    let hostmask = if carried_hostmask.is_empty() {
        requester_hostmask(state, &requester_uuid)
    } else {
        trunc_string(&carried_hostmask, MAX_MASK_LEN)
    };

    if hostmask.is_empty() {
        crate::hlog_warning!(
            "[HUB] No hostmask for requester {requester_uuid} (not in payload or storage)\n"
        );
        let fail_payload = trunc_string(&format!("{request_id}|No hostmask found"), 256);
        if let Some(i) = state.client_by_fd(fd)
            && !queue::send_urgent(&mut state.clients[i], CMD_OP_FORWARD_FAILED, &fail_payload)
        {
            auth::disconnect_client(state, i);
        }
        return;
    }

    let grant_payload = trunc_string(&format!("{hostmask}|{channel}"), 512);
    if client::send_cmd_to_bot(&mut state.clients[ti], CMD_OP_GRANT, &grant_payload) {
        crate::hlog_debug!(
            "[HUB] Sent OP_GRANT to local bot {target_uuid} for request id:{request_id}\n"
        );
        // Forward the grant confirmation back to the origin peer.
        if let Some(i) = state.client_by_fd(fd) {
            if queue::send_urgent(&mut state.clients[i], CMD_OP_FORWARD_GRANT, &request_id) {
                crate::hlog_debug!(
                    "[HUB] Queued OP_FORWARD_GRANT URGENT back to peer for id:{request_id}\n"
                );
            } else {
                auth::disconnect_client(state, i);
            }
        }
    }
}

/// process_forward_op_grant(): a peer confirmed it delivered the grant.
pub fn process_forward_op_grant(state: &mut HubState, payload: &str) {
    if payload.len() >= 64 {
        crate::hlog_warning!("[HUB] OP_FORWARD_GRANT: oversized request_id, ignoring\n");
        return;
    }
    let request_id = payload.to_string();
    crate::hlog_debug!("[HUB] Received OP_FORWARD_GRANT from peer for request id:{request_id}\n");

    let Some(pi) = find_pending_op_request(state, &request_id) else {
        crate::hlog_warning!("[HUB] No pending request found for id:{request_id}\n");
        return;
    };
    let origin_fd = state.pending_op_requests[pi].origin_fd;
    if state
        .client_by_fd(origin_fd)
        .is_some_and(|i| state.clients[i].typ == ClientType::Bot)
    {
        crate::hlog_debug!(
            "[HUB] OP_FORWARD_GRANT acknowledged for id:{request_id} — requester learns via IRC MODE\n"
        );
    }
    remove_pending_op_request(state, &request_id);
}

/// process_forward_op_failed(): a peer could not service the request.
pub fn process_forward_op_failed(state: &mut HubState, payload: &str) {
    let conv = sscanf(
        payload,
        &[Fmt::Set(63, b"|"), Fmt::Lit("|"), Fmt::Set(255, b"\n")],
    );
    if conv.is_empty() {
        crate::hlog_warning!("[HUB] Invalid OP_FORWARD_FAILED payload from peer\n");
        return;
    }
    let request_id = conv[0].s().to_string();
    let reason = conv.get(1).map_or("", |c| c.s()).to_string();
    crate::hlog_debug!("[HUB] Received OP_FORWARD_FAILED from peer for request id:{request_id}\n");

    let Some(pi) = find_pending_op_request(state, &request_id) else {
        crate::hlog_warning!("[HUB] No pending request found for id:{request_id}\n");
        return;
    };
    let origin_fd = state.pending_op_requests[pi].origin_fd;
    if let Some(i) = state.client_by_fd(origin_fd)
        && state.clients[i].typ == ClientType::Bot
    {
        let fail_msg = if reason.is_empty() {
            "Target bot not found on network"
        } else {
            &reason
        };
        if client::send_cmd_to_bot(&mut state.clients[i], CMD_OP_FAILED, fail_msg) {
            crate::hlog_info!("[HUB] Notified requester bot of failure for id:{request_id}\n");
        }
    }
    remove_pending_op_request(state, &request_id);
}

// ---------------------------------------------------------------------------
// Channel-access requests (unban / invite / key)
// ---------------------------------------------------------------------------

fn chan_kind_valid(kind: &str) -> bool {
    matches!(kind, "unban" | "invite" | "key")
}

/// add_pending_chan_request(): reuse a slot whose reply never came rather
/// than filling the table.
fn add_pending_chan_request(
    state: &mut HubState,
    request_id: &str,
    requester_uuid: &str,
    kind: &str,
    channel: &str,
    origin_fd: i32,
) -> bool {
    let t = now();
    for p in state.pending_chan_requests.iter_mut() {
        if p.active && t - p.timestamp > CHAN_REQUEST_TIMEOUT {
            p.active = false;
        }
        if !p.active {
            p.request_id = trunc_string(request_id, 64);
            p.requester_uuid = trunc_string(requester_uuid, 64);
            p.kind = trunc_string(kind, 8);
            p.channel = trunc_string(channel, MAX_CHAN);
            p.origin_fd = origin_fd;
            p.timestamp = t;
            p.active = true;
            return true;
        }
    }
    false
}

fn find_pending_chan_request(state: &HubState, request_id: &str) -> Option<usize> {
    state
        .pending_chan_requests
        .iter()
        .position(|p| p.active && p.request_id == request_id)
}

// As with forward_op_request_to_peers: these are the wire fields.
#[allow(clippy::too_many_arguments)]
fn forward_chan_request_to_peers(
    state: &mut HubState,
    request_id: &str,
    requester_uuid: &str,
    kind: &str,
    channel: &str,
    nick: &str,
    hostmask: &str,
    exclude_fd: i32,
) {
    // request_id|requester_uuid|kind|channel|nick|hostmask
    let fwd = trunc_string(
        &format!("{request_id}|{requester_uuid}|{kind}|{channel}|{nick}|{hostmask}"),
        MAX_MASK_LEN + 256,
    );
    let mut queued = 0;
    let mut i = 0;
    while i < state.clients.len() {
        let c = &state.clients[i];
        if c.typ == ClientType::Hub && c.authenticated && c.fd != exclude_fd {
            let fd = c.fd;
            if !queue::send_urgent(&mut state.clients[i], CMD_CHAN_FWD_REQUEST, &fwd) {
                crate::hlog_warning!(
                    "[HUB] URGENT queue full forwarding CHAN_REQUEST to peer fd={fd} — disconnecting\n"
                );
                auth::disconnect_client(state, i);
                continue;
            }
            queued += 1;
        }
        i += 1;
    }
    if queued > 0 {
        crate::hlog_debug!(
            "[HUB] Forwarded CHAN_FWD_REQUEST (id:{request_id} {kind} {channel}) to {queued} peer(s)\n"
        );
    }
}

/// Push the action to every authenticated local bot except the requester.
/// Returns how many bots were told.
fn broadcast_chan_action(
    state: &mut HubState,
    request_id: &str,
    requester_uuid: &str,
    kind: &str,
    channel: &str,
    nick: &str,
    hostmask: &str,
) -> usize {
    let action = trunc_string(
        &format!("{request_id}|{kind}|{channel}|{requester_uuid}|{nick}|{hostmask}"),
        MAX_MASK_LEN + 256,
    );
    let mut sent = 0;
    for ci in state.bot_clients() {
        // Never ask the locked-out bot to help itself.
        if state.clients[ci].id == requester_uuid {
            continue;
        }
        if client::send_cmd_to_bot(&mut state.clients[ci], CMD_CHAN_ACTION, &action) {
            sent += 1;
        } else {
            crate::hlog_warning!(
                "[HUB] Failed to send CHAN_ACTION to bot {}\n",
                state.clients[ci].id
            );
        }
    }
    sent
}

/// The entry point shared by a local bot's request and a peer-forwarded one.
/// `origin_fd` is the peer fd to route a reply back to, or -1 when the
/// requester is one of our own bots.
#[allow(clippy::too_many_arguments)]
fn chan_request_dispatch(
    state: &mut HubState,
    request_id: &str,
    requester_uuid: &str,
    kind: &str,
    channel: &str,
    nick: &str,
    hostmask: &str,
    origin_fd: i32,
) {
    // Only `key` sends anything back, so only `key` needs a pending slot.
    if kind == "key"
        && !add_pending_chan_request(state, request_id, requester_uuid, kind, channel, origin_fd)
    {
        crate::hlog_warning!(
            "[HUB] Pending channel-request table full — dropping {kind} for {channel}\n"
        );
        return;
    }

    let told = broadcast_chan_action(
        state,
        request_id,
        requester_uuid,
        kind,
        channel,
        nick,
        hostmask,
    );
    forward_chan_request_to_peers(
        state,
        request_id,
        requester_uuid,
        kind,
        channel,
        nick,
        hostmask,
        origin_fd,
    );
    crate::hlog_debug!(
        "[HUB] CHAN_REQUEST {kind} for {channel} (id:{request_id}) delivered to {told} local bot(s)\n"
    );
}

/// process_chan_request(): a local bot asking the mesh to let it back in.
///
/// The payload is only `kind|channel`; everything that could be forged — the
/// requester's nick and hostmask — is resolved here from the authenticated
/// bot's own records, so a bot can neither request an unban for a mask that
/// is not its own nor have a third party invited.
pub fn process_chan_request(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(payload, &[Fmt::Set(7, b"|"), Fmt::Lit("|"), Fmt::Word(64)]);
    let id = state.clients[ci].id.clone();
    if conv.len() != 2 || !chan_kind_valid(conv[0].s()) {
        crate::hlog_warning!("[HUB] Invalid CHAN_REQUEST payload from {id}\n");
        return;
    }
    let kind = conv[0].s().to_string();
    let channel = conv[1].s().to_string();
    if !channel.starts_with('#') && !channel.starts_with('&') {
        crate::hlog_warning!("[HUB] CHAN_REQUEST from {id} for non-channel '{channel}'\n");
        return;
    }

    let nick = state
        .bot_entry(&id, "n")
        .map(|v| trunc_string(v, MAX_NICK))
        .unwrap_or_default();
    let hostmask = requester_hostmask(state, &id);

    // An unban can only be matched against a mask, an invite only sent to a
    // nick.  Without them the request is unserviceable, so say so rather than
    // flooding the mesh with something no bot can act on.
    if kind == "unban" && hostmask.is_empty() {
        crate::hlog_warning!("[HUB] No hostmask for {id} — cannot service unban for {channel}\n");
        return;
    }
    if kind == "invite" && nick.is_empty() {
        crate::hlog_warning!("[HUB] No nick for {id} — cannot service invite for {channel}\n");
        return;
    }

    crate::hlog_info!("[HUB] CHAN_REQUEST {kind} from {id} for {channel}\n");
    let request_id = generate_request_id();
    forward_seen_check_and_add(state, &request_id);
    chan_request_dispatch(
        state,
        &request_id,
        &id,
        &kind,
        &channel,
        &nick,
        &hostmask,
        -1,
    );
}

/// process_chan_reply(): a bot answering a request (today only `key`).  Route
/// it to the requester if it is ours, otherwise back down the peer fd the
/// request arrived on.
pub fn process_chan_reply(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(
        payload,
        &[
            Fmt::Set(63, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(7, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(64, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(15, b"|"),
        ],
    );
    let id = state.clients[ci].id.clone();
    if conv.len() != 4 {
        crate::hlog_warning!("[HUB] Invalid CHAN_REPLY payload from {id}\n");
        return;
    }
    let request_id = conv[0].s().to_string();
    let kind = conv[1].s().to_string();
    let channel = conv[2].s().to_string();
    let status = conv[3].s().to_string();

    // The data field is the remainder after the 4th '|' — a channel key may
    // contain anything but whitespace, so it is never re-split.
    let mut data = "";
    let mut bars = 0;
    for (i, ch) in payload.char_indices() {
        if ch == '|' {
            bars += 1;
            if bars == 4 {
                data = &payload[i + 1..];
                break;
            }
        }
    }

    let Some(pi) = find_pending_chan_request(state, &request_id) else {
        // Late or duplicate answer — the first one already went home.
        crate::hlog_warning!(
            "[HUB] CHAN_REPLY (id:{request_id}) from {id} matches no pending request\n"
        );
        return;
    };
    // Bind the answer to what was actually asked: holding a request id must
    // not let a bot hand the requester a key for some other channel.
    let (req_kind, req_chan, req_uuid, origin_fd) = {
        let p = &state.pending_chan_requests[pi];
        (
            p.kind.clone(),
            p.channel.clone(),
            p.requester_uuid.clone(),
            p.origin_fd,
        )
    };
    if req_kind != kind || !req_chan.eq_ignore_ascii_case(&channel) {
        crate::hlog_warning!(
            "[HUB] CHAN_REPLY (id:{request_id}) from {id} answers {kind}/{channel} but the request was {req_kind}/{req_chan} — dropped\n"
        );
        return;
    }
    // A bot answering its own request tells us nothing.
    if id == req_uuid {
        return;
    }

    let out = zeroize::Zeroizing::new(trunc_string(
        &format!("{request_id}|{kind}|{channel}|{status}|{data}"),
        MAX_BUFFER,
    ));

    if origin_fd == -1 {
        match state.bot_client(&req_uuid) {
            Some(ti) if client::send_cmd_to_bot(&mut state.clients[ti], CMD_CHAN_REPLY, &out) => {
                crate::hlog_info!(
                    "[HUB] CHAN_REPLY {kind} for {channel} delivered to {req_uuid}\n"
                );
            }
            _ => crate::hlog_warning!(
                "[HUB] CHAN_REPLY {kind} for {channel} undeliverable to {req_uuid}\n"
            ),
        }
    } else if let Some(i) = state.client_by_fd(origin_fd)
        && state.clients[i].typ == ClientType::Hub
        && state.clients[i].authenticated
    {
        let fd = state.clients[i].fd;
        if queue::send_urgent(&mut state.clients[i], CMD_CHAN_FWD_REPLY, &out) {
            crate::hlog_debug!(
                "[HUB] CHAN_REPLY {kind} for {channel} sent back as CHAN_FWD_REPLY to peer fd={fd}\n"
            );
        } else {
            crate::hlog_warning!("[HUB] URGENT queue full routing CHAN_REPLY to peer fd={fd}\n");
            auth::disconnect_client(state, i);
        }
    }

    if let Some(pi) = find_pending_chan_request(state, &request_id) {
        state.pending_chan_requests[pi].active = false;
    }
}

/// process_forward_chan_request(): a peer relayed a channel-access request.
pub fn process_forward_chan_request(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(
        payload,
        &[
            Fmt::Set(63, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(63, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(7, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(64, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(31, b"|"),
            Fmt::Lit("|"),
            Fmt::Set(255, b"|"),
        ],
    );
    let fd = state.clients[ci].fd;
    if conv.len() < 4 || !chan_kind_valid(conv[2].s()) {
        crate::hlog_warning!("[HUB] Invalid CHAN_FWD_REQUEST from peer fd={fd}\n");
        return;
    }
    let request_id = conv[0].s().to_string();
    let requester_uuid = conv[1].s().to_string();
    let kind = conv[2].s().to_string();
    let channel = conv[3].s().to_string();
    let nick = conv.get(4).map_or("", |c| c.s()).to_string();
    let hostmask = conv.get(5).map_or("", |c| c.s()).to_string();

    // Second sighting of this id: another path already delivered it.
    if forward_seen_check_and_add(state, &request_id) {
        return;
    }

    crate::hlog_debug!(
        "[HUB] CHAN_FWD_REQUEST {kind} for {channel} (id:{request_id}) from peer fd={fd}\n"
    );
    chan_request_dispatch(
        state,
        &request_id,
        &requester_uuid,
        &kind,
        &channel,
        &nick,
        &hostmask,
        fd,
    );
}

/// process_forward_chan_reply(): route a peer's reply on toward its origin.
pub fn process_forward_chan_reply(state: &mut HubState, ci: usize, payload: &str) {
    let conv = sscanf(payload, &[Fmt::Set(63, b"|")]);
    let fd = state.clients[ci].fd;
    if conv.is_empty() {
        crate::hlog_warning!("[HUB] Invalid CHAN_FWD_REPLY from peer fd={fd}\n");
        return;
    }
    let request_id = conv[0].s().to_string();
    let Some(pi) = find_pending_chan_request(state, &request_id) else {
        return; // not ours, or already answered
    };
    let (origin_fd, req_uuid) = {
        let p = &state.pending_chan_requests[pi];
        (p.origin_fd, p.requester_uuid.clone())
    };

    if origin_fd == -1 {
        if let Some(ti) = state.bot_client(&req_uuid) {
            client::send_cmd_to_bot(&mut state.clients[ti], CMD_CHAN_REPLY, payload);
            crate::hlog_debug!(
                "[HUB] CHAN_FWD_REPLY (id:{request_id}) from peer fd={fd} delivered to {req_uuid}\n"
            );
        }
    } else if let Some(i) = state.client_by_fd(origin_fd)
        && state.clients[i].typ == ClientType::Hub
        && state.clients[i].authenticated
    {
        let peer_fd = state.clients[i].fd;
        if !queue::send_urgent(&mut state.clients[i], CMD_CHAN_FWD_REPLY, payload) {
            auth::disconnect_client(state, i);
        } else {
            crate::hlog_debug!(
                "[HUB] CHAN_FWD_REPLY (id:{request_id}) relayed on toward its origin (peer fd={peer_fd})\n"
            );
        }
    }

    if let Some(pi) = find_pending_chan_request(state, &request_id) {
        state.pending_chan_requests[pi].active = false;
    }
}

/// CMD_ADMIN_OP_USER's fan-out half, shared with the admin handler.
pub fn admin_op_user(state: &mut HubState, nick: &str, channel: &str) -> usize {
    let request_id = generate_request_id();
    let sent = broadcast_op_grant(state, &trunc_string(&format!("{nick}|{channel}"), 256));

    // Also forward to the peer hubs to reach bots connected to them.  Admin
    // requests encode nick:channel in the channel field.
    let admin_payload = trunc_string(&format!("{nick}:{channel}"), 256);
    // Stamp origin_ts now and mark it seen locally so any loop-back is
    // dropped.
    let admin_origin_ts = now();
    forward_seen_check_and_add(state, &request_id);
    forward_op_request_to_peers(
        state,
        &request_id,
        "ADMIN",
        "ANY",
        &admin_payload,
        "",
        -1,
        admin_origin_ts,
    );
    sent
}

/// Re-export so the admin handler can stamp a purge without importing `mesh`.
pub fn broadcast_purge(state: &mut HubState, cutoff: i64) -> bool {
    mesh::broadcast_purge(state, cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_shaped_and_unique() {
        let a = generate_request_id();
        let b = generate_request_id();
        assert_eq!(a.len(), 18);
        assert_eq!(a.as_bytes()[8], b'-');
        assert_eq!(a.as_bytes()[13], b'-');
        assert_ne!(a, b);
    }

    #[test]
    fn seen_ring_drops_the_second_sighting_and_wraps() {
        let mut s = HubState::new();
        assert!(!forward_seen_check_and_add(&mut s, "id-1"));
        assert!(forward_seen_check_and_add(&mut s, "id-1"));
        // Past the ring size the oldest entries are overwritten.
        for i in 0..MAX_SEEN_FORWARD_IDS {
            forward_seen_check_and_add(&mut s, &format!("fill-{i}"));
        }
        assert!(!forward_seen_check_and_add(&mut s, "id-1"));
    }

    #[test]
    fn pending_op_table_fills_and_frees() {
        let mut s = HubState::new();
        for i in 0..MAX_PENDING_OP_REQUESTS {
            assert!(add_pending_op_request(
                &mut s,
                &format!("r{i}"),
                "u",
                "t",
                "#c",
                -1
            ));
        }
        assert!(!add_pending_op_request(&mut s, "over", "u", "t", "#c", -1));
        assert!(find_pending_op_request(&s, "r0").is_some());
        remove_pending_op_request(&mut s, "r0");
        assert!(find_pending_op_request(&s, "r0").is_none());
        assert!(add_pending_op_request(&mut s, "again", "u", "t", "#c", -1));
    }

    #[test]
    fn chan_kinds_are_closed() {
        assert!(chan_kind_valid("unban"));
        assert!(chan_kind_valid("invite"));
        assert!(chan_kind_valid("key"));
        assert!(!chan_kind_valid("op"));
        assert!(!chan_kind_valid(""));
    }

    #[test]
    fn stale_chan_slots_are_reused() {
        let mut s = HubState::new();
        for i in 0..MAX_PENDING_CHAN_REQUESTS {
            assert!(add_pending_chan_request(
                &mut s,
                &format!("r{i}"),
                "u",
                "key",
                "#c",
                -1
            ));
        }
        assert!(!add_pending_chan_request(
            &mut s, "over", "u", "key", "#c", -1
        ));
        // Age one out; its slot comes back.
        s.pending_chan_requests[3].timestamp = now() - CHAN_REQUEST_TIMEOUT - 1;
        assert!(add_pending_chan_request(
            &mut s, "fresh", "u", "key", "#c", -1
        ));
        assert!(find_pending_chan_request(&s, "fresh").is_some());
        assert!(find_pending_chan_request(&s, "r3").is_none());
    }
}
