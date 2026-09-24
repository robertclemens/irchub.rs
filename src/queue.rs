//! Mesh transport — the per-peer outbound queue (docs/mesh.md Phase 1).
//!
//! Replaces the old "build packet → encrypt → send-or-drop on EAGAIN" model
//! with a per-client queue drained on POLLOUT.  Encryption happens at drain
//! time (so it uses the up-to-date session key) and partial writes are
//! tracked via `writing_buf` / `writing_offset`.  Three priority lanes:
//! URGENT (op flow), DELTA (small per-key updates), BULK (anti-entropy and
//! full sync).

use crate::consts::*;
use crate::crypto;
use crate::cstr::now;
use crate::net::{self, SendOutcome};
use crate::state::{DeltaSeen, HubClient, HubState, Lane, QueuedMsg};

/// peer_enqueue(): put `m` on the client's lane, coalescing when its key
/// matches one already queued.
///
/// Overflow handling: URGENT must never be dropped, so a full URGENT lane is
/// a fatal peer condition and returns false (the caller disconnects).  DELTA
/// and BULK drop their oldest entry to make room — for DELTA one update is
/// lost and the next anti-entropy reconciles it; for BULK a full sync is
/// lost and the next one fires within MESH_ANTI_ENTROPY_INTERVAL.
pub fn enqueue(client: &mut HubClient, m: QueuedMsg) -> bool {
    if client.fd < 0 {
        return false;
    }
    let li = m.lane.index();
    let fd = client.fd;
    let lane = &mut client.out_lanes[li];

    // Coalescing (Phase 5; harmless when the key is empty).  Walk the lane
    // FIFO; a same-key entry has its payload replaced in place, keeping its
    // position, and the new message is dropped.
    if !m.coalesce_key.is_empty()
        && let Some(cur) = lane
            .msgs
            .iter_mut()
            .find(|c| !c.coalesce_key.is_empty() && c.coalesce_key == m.coalesce_key)
    {
        let old_bytes = cur.len();
        let new_bytes = m.len();
        cur.payload = m.payload;
        cur.lamport_seq = m.lamport_seq;
        // The origin hub may differ if a peer's update overwrote a
        // local-origin one; the new origin "wins" because the newer seq
        // belongs to it.
        cur.origin_hub_uuid = m.origin_hub_uuid;
        lane.bytes = lane.bytes + new_bytes - old_bytes;
        client.out_total_bytes = client.out_total_bytes + new_bytes - old_bytes;
        return true;
    }

    if lane.msgs.len() >= MAX_QUEUE_PER_LANE
        || client.out_total_bytes + m.len() > MAX_QUEUED_BYTES_PER_PEER
    {
        if li == Lane::Urgent.index() {
            // The caller sees false and decides whether to disconnect.
            return false;
        }
        if let Some(old) = lane.msgs.pop_front() {
            lane.bytes -= old.len();
            client.out_total_bytes -= old.len();
            crate::hlog_warning!(
                "[MESH] queue {} lane full — dropping oldest (peer fd={fd})\n",
                m.lane.name()
            );
            cfg_push_lost(client, &old);
        }
    }

    let n = m.len();
    client.out_lanes[li].msgs.push_back(m);
    client.out_lanes[li].bytes += n;
    client.out_total_bytes += n;
    true
}

/// A config push that never reaches its bot must not stand as "sent", or the
/// next identical broadcast would be skipped and the bot left behind.
fn cfg_push_lost(client: &mut HubClient, m: &QueuedMsg) {
    if m.cmd == CMD_CONFIG_DATA {
        client.cfg_sent_hash = None;
        crate::stats::cfg_lost();
    }
}

/// Encrypt `m` with the client's session key into `writing_buf`.  Returns the
/// total wire length (4-byte length prefix + ciphertext + tag), or 0 on
/// failure.
fn encrypt_into_writing(client: &mut HubClient, m: &QueuedMsg) -> usize {
    if m.len() > MAX_BULK_PAYLOAD {
        return 0;
    }
    // The wire envelope; see net::frame_plain for why the inner length is
    // stamped big-endian for bot-destined opcodes only.
    let plain = zeroize::Zeroizing::new(net::frame_plain(
        m.cmd,
        &m.payload,
        net::inner_len_is_network_order(m.cmd),
    ));

    // D2: writing_buf may still be at the small pre-auth cap.  Refuse to
    // encrypt a frame that would not fit (4-byte length prefix + ciphertext +
    // tag).  AES-GCM ciphertext length equals the plaintext length.
    if 4 + plain.len() + GCM_TAG_LEN > client.writing_cap {
        return 0;
    }

    let Some((body, tag)) = crypto::aes_gcm_encrypt(&plain, client.session_key.as_ref()) else {
        return 0;
    };
    let packet_len = body.len() + GCM_TAG_LEN;
    client.writing_buf.clear();
    client
        .writing_buf
        .extend_from_slice(&(packet_len as u32).to_be_bytes());
    client.writing_buf.extend_from_slice(&body);
    client.writing_buf.extend_from_slice(&tag);
    4 + packet_len
}

/// Push bytes from `writing_buf` at `writing_offset` until the socket says
/// WouldBlock, the buffer empties, or the send errors.  Returns false when
/// the caller must stop draining this pass.
fn push_in_flight(client: &mut HubClient) -> bool {
    while client.writing_offset < client.writing_buf.len() {
        let Some(sock) = &client.sock else {
            client.writing_buf.clear();
            client.writing_offset = 0;
            return false;
        };
        match net::send_dontwait(sock, &client.writing_buf[client.writing_offset..]) {
            SendOutcome::Sent(n) if n > 0 => {
                client.writing_offset += n;
                let t = now();
                if client.bw_window_start != t {
                    client.bw_window_start = t;
                    client.bw_bytes_in_window = 0;
                }
                client.bw_bytes_in_window += n as i64;
            }
            // A zero-length accept would spin; treat it as "come back later".
            SendOutcome::Sent(_) | SendOutcome::WouldBlock => return false,
            SendOutcome::Error(e) => {
                // A hard send error: the caller cannot disconnect from here
                // (it is iterating the client list), so the in-flight buffer
                // is cleared and the recv side reaps the socket on EOF.
                crate::hlog_warning!(
                    "[MESH] send error to {} (fd={}): {e}\n",
                    client.ip,
                    client.fd
                );
                client.writing_buf.clear();
                client.writing_offset = 0;
                return false;
            }
        }
    }
    client.writing_buf.clear();
    client.writing_offset = 0;
    true
}

/// peer_drain_writable(): called when poll reports the socket writable.
pub fn drain_writable(client: &mut HubClient) {
    if client.fd < 0 || client.sock.is_none() {
        return;
    }

    // Step 1: finish any in-flight ciphertext.
    if !push_in_flight(client) {
        return;
    }

    // Step 2: drain lanes in priority order until we run out of messages or
    // the socket goes EAGAIN.
    for li in 0..LANE_COUNT {
        while !client.out_lanes[li].msgs.is_empty() {
            // Bandwidth budget enforcement (Phase 5; the defaults are
            // generous).
            let t = now();
            if client.bw_window_start != t {
                client.bw_window_start = t;
                client.bw_bytes_in_window = 0;
            }
            // Defer the rest of BULK to the next second.
            if li == Lane::Bulk.index() && client.bw_bytes_in_window > BULK_SOFT_BUDGET_BPS {
                return;
            }
            // Extreme case — let coalescing catch up.
            if li == Lane::Delta.index() && client.bw_bytes_in_window > DELTA_HARD_BUDGET_BPS {
                return;
            }

            let Some(m) = client.out_lanes[li].msgs.pop_front() else {
                break;
            };
            client.out_lanes[li].bytes -= m.len();
            client.out_total_bytes -= m.len();

            let wire_len = encrypt_into_writing(client, &m);
            if wire_len == 0 {
                crate::hlog_error!("[MESH] encrypt failed for peer {} lane {li}\n", client.ip);
                cfg_push_lost(client, &m);
                continue; // drop and move on
            }
            crate::stats::tx(m.cmd, wire_len);
            drop(m);
            client.writing_offset = 0;

            // Try to send immediately.
            if !push_in_flight(client) {
                return;
            }
        }
    }
}

/// peer_send_urgent(): enqueue a small hub→hub URGENT message.  False when
/// the URGENT queue is full — the caller must disconnect that peer.
pub fn send_urgent(client: &mut HubClient, cmd: u8, payload: &str) -> bool {
    let Some(m) = QueuedMsg::new(cmd, Lane::Urgent, payload.as_bytes()) else {
        return false;
    };
    if !enqueue(client, m) {
        crate::hlog_warning!(
            "[URGENT] Queue full for peer {} — disconnecting\n",
            client.ip
        );
        return false;
    }
    true
}

/// hub_delta_seen_check_and_update(): true if (origin, bot, seq) is new (and
/// updates the set); false if seq <= the last seen.
pub fn delta_seen_check_and_update(
    state: &mut HubState,
    origin_hub_uuid: &str,
    bot_uuid: &str,
    seq: u64,
) -> bool {
    if origin_hub_uuid.is_empty() || bot_uuid.is_empty() {
        return true;
    }
    if let Some(e) = state
        .delta_seen
        .iter_mut()
        .find(|e| e.origin_hub_uuid == origin_hub_uuid && e.bot_uuid == bot_uuid)
    {
        if seq <= e.max_seq_seen {
            return false;
        }
        e.max_seq_seen = seq;
        e.last_seen_at = now();
        return true;
    }

    // Insert new.  If full, LRU-evict the oldest by moving the last entry
    // into its slot (never shift the array).
    if state.delta_seen.len() >= MAX_DELTA_SEEN {
        let mut oldest = 0;
        for i in 1..state.delta_seen.len() {
            if state.delta_seen[i].last_seen_at < state.delta_seen[oldest].last_seen_at {
                oldest = i;
            }
        }
        state.delta_seen.swap_remove(oldest);
    }
    state.delta_seen.push(DeltaSeen {
        origin_hub_uuid: origin_hub_uuid.to_string(),
        bot_uuid: bot_uuid.to_string(),
        max_seq_seen: seq,
        last_seen_at: now(),
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn client() -> HubClient {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        HubClient::new(s, 42, "127.0.0.1", MAX_BUFFER)
    }

    #[test]
    fn coalescing_replaces_in_place() {
        let mut c = client();
        for (i, body) in ["first", "second", "third"].iter().enumerate() {
            let mut m = QueuedMsg::new(CMD_PEER_SYNC, Lane::Delta, body.as_bytes()).unwrap();
            if i != 1 {
                m.set_coalesce("hub-a", i as u64, "hub-a|h|bot-1");
            }
            assert!(enqueue(&mut c, m));
        }
        let lane = &c.out_lanes[Lane::Delta.index()];
        // "third" replaced "first" in slot 0; "second" was never coalesced.
        assert_eq!(lane.msgs.len(), 2);
        assert_eq!(&*lane.msgs[0].payload, b"third");
        assert_eq!(lane.msgs[0].lamport_seq, 2);
        assert_eq!(&*lane.msgs[1].payload, b"second");
        assert_eq!(lane.bytes, "third".len() + "second".len());
        assert_eq!(c.out_total_bytes, lane.bytes);
    }

    #[test]
    fn urgent_overflow_is_fatal_others_drop_oldest() {
        let mut c = client();
        for i in 0..MAX_QUEUE_PER_LANE {
            let m = QueuedMsg::new(
                CMD_OP_FORWARD_REQUEST,
                Lane::Urgent,
                format!("{i}").as_bytes(),
            )
            .unwrap();
            assert!(enqueue(&mut c, m));
        }
        let m = QueuedMsg::new(CMD_OP_FORWARD_REQUEST, Lane::Urgent, b"over").unwrap();
        assert!(!enqueue(&mut c, m));

        for i in 0..MAX_QUEUE_PER_LANE {
            let m = QueuedMsg::new(CMD_PEER_SYNC, Lane::Bulk, format!("{i}").as_bytes()).unwrap();
            assert!(enqueue(&mut c, m));
        }
        let m = QueuedMsg::new(CMD_PEER_SYNC, Lane::Bulk, b"over").unwrap();
        assert!(enqueue(&mut c, m));
        let lane = &c.out_lanes[Lane::Bulk.index()];
        assert_eq!(lane.msgs.len(), MAX_QUEUE_PER_LANE);
        assert_eq!(&*lane.msgs[0].payload, b"1");
        assert_eq!(&*lane.msgs[MAX_QUEUE_PER_LANE - 1].payload, b"over");
    }

    #[test]
    fn oversized_payload_is_refused() {
        assert!(
            QueuedMsg::new(CMD_PEER_SYNC, Lane::Bulk, &vec![0u8; MAX_BULK_PAYLOAD + 1]).is_none()
        );
        assert!(QueuedMsg::new(CMD_PEER_SYNC, Lane::Bulk, &vec![0u8; MAX_BULK_PAYLOAD]).is_some());
    }

    #[test]
    fn delta_seen_rejects_replays_and_evicts_lru() {
        let mut s = HubState::new();
        assert!(delta_seen_check_and_update(&mut s, "hub-a", "bot-1", 5));
        assert!(!delta_seen_check_and_update(&mut s, "hub-a", "bot-1", 5));
        assert!(!delta_seen_check_and_update(&mut s, "hub-a", "bot-1", 4));
        assert!(delta_seen_check_and_update(&mut s, "hub-a", "bot-1", 6));
        // A missing origin or bot is not tracked at all.
        assert!(delta_seen_check_and_update(&mut s, "", "bot-1", 1));
        assert!(delta_seen_check_and_update(&mut s, "hub-a", "", 1));
        assert_eq!(s.delta_seen.len(), 1);
    }

    #[test]
    fn queue_destroy_clears_every_lane() {
        let mut c = client();
        for lane in [Lane::Urgent, Lane::Delta, Lane::Bulk] {
            assert!(enqueue(
                &mut c,
                QueuedMsg::new(CMD_PING, lane, b"x").unwrap()
            ));
        }
        assert!(c.has_pending_writes());
        c.queue_destroy();
        assert!(!c.has_pending_writes());
        assert_eq!(c.out_total_bytes, 0);
    }
}
