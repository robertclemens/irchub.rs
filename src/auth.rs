//! Bot authentication and the bot registry (hub_logic.c).
//!
//! The v2 handshake, in three frames:
//!
//! 1. bot → hub  the bot's UUID, plaintext.
//! 2. hub → bot  `challenge(32) || hub_eph_x25519_pub(32) || hub_sig(64)`,
//!    the signature over `"irchub-hub-auth-v2|" uuid "|" challenge eph_pub`.
//!    It commits to the UUID, the challenge and the ephemeral public key, so
//!    a MITM cannot substitute its own eph_pub: the bot would derive a usable
//!    session key against the MITM, but the signature would not verify under
//!    the legitimate hub's pinned key.
//! 3. bot → hub  an Ed25519 signature over
//!    `"irchub-bot-challenge-v1|" uuid "|" eph_pub challenge`.
//!
//! The session key is `HKDF-SHA256(X25519(hub_eph, bot_x), salt = challenge,
//! info = "irchub-bot-session-v1|" uuid)`, and the hub closes with a
//! GCM-encrypted 1-byte ACK — without it a MITM that proxied the challenge
//! could flip the bot into "authenticated" with a plaintext 0x01.

use crate::consts::*;
use crate::cstr::{now, trunc_string};
use crate::state::{BotAuthState, BotConfig, ClientType, HubState, PendingBot};
use crate::{crypto, hlog, net, presence, ratelimit, storage};

/// Load a bot's combined 64-byte public key from the hub config.
fn load_bot_combined_pub(state: &HubState, uuid: &str) -> Option<[u8; COMBINED_KEY_LEN]> {
    let b = state.bots.iter().find(|b| b.uuid == uuid)?;
    let e = b.entry("pub")?;
    let dec = crypto::b64_decode(&e.value)?;
    if dec.len() != COMBINED_KEY_LEN {
        return None;
    }
    let mut out = [0u8; COMBINED_KEY_LEN];
    out.copy_from_slice(&dec);
    Some(out)
}

/// The transcript the hub signs in phase 2.
fn hub_transcript(uuid: &str, challenge: &[u8; 32], eph_pub: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(19 + uuid.len() + 1 + 64);
    t.extend_from_slice(b"irchub-hub-auth-v2|");
    t.extend_from_slice(uuid.as_bytes());
    t.push(b'|');
    t.extend_from_slice(challenge);
    t.extend_from_slice(eph_pub);
    t
}

/// The transcript the bot signs in phase 3.  Mirrors ed25519_sign_challenge()
/// in ircbot's hub_client.
fn bot_transcript(uuid: &str, eph_pub: &[u8; 32], challenge: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(24 + uuid.len() + 1 + 64);
    t.extend_from_slice(b"irchub-bot-challenge-v1|");
    t.extend_from_slice(uuid.as_bytes());
    t.push(b'|');
    t.extend_from_slice(eph_pub);
    t.extend_from_slice(challenge);
    t
}

/// handle_bot_authentication(): false means "drop this connection".
pub fn handle_bot_authentication(state: &mut HubState, ci: usize, data: &[u8]) -> bool {
    let packet_len = data.len();

    // PHASE 1: receive the UUID (plaintext).
    if !state.clients[ci].authenticated && state.clients[ci].bot_auth_state == BotAuthState::Idle {
        if packet_len == 0 || packet_len > 63 {
            return false;
        }
        let uuid = String::from_utf8_lossy(data).into_owned();
        let ip = state.clients[ci].ip.clone();
        // The claimed UUID is raw pre-authentication input, so it reaches the
        // log as the bytes that arrived — `uuid` above has already lost any
        // invalid byte to U+FFFD, which is exactly what the sanitizer is
        // there to show.
        crate::logging::hub_log_with_raw(
            &format!("[HUB] Bot auth attempt from {ip} with UUID: "),
            data,
            "\n",
        );

        let authorized = state.bots.iter().any(|b| b.uuid == uuid && b.is_active);
        if !authorized {
            crate::logging::hub_log_with_raw(
                "[HUB] Unauthorized bot UUID: ",
                data,
                &format!(" from {ip}\n"),
            );
            add_pending_bot(state, &uuid, &ip);
            ratelimit::record_failed_auth(state, &ip);
            return false;
        }

        let mut challenge = [0u8; 32];
        if !crypto::random_bytes(&mut challenge) {
            hlog!("[HUB][ERROR] Failed to generate challenge\n");
            return false;
        }
        let Some((eph_priv, eph_pub)) = crypto::gen_ephemeral_x25519() else {
            hlog!("[HUB][ERROR] Ephemeral X25519 keygen failed\n");
            return false;
        };

        let transcript = hub_transcript(&uuid, &challenge, &eph_pub);
        let mut ed_seed = [0u8; 32];
        ed_seed.copy_from_slice(state.hub_ed25519_priv.get());
        let hub_sig = crypto::ed25519_sign(&ed_seed, &transcript);
        crypto::wipe(&mut ed_seed);

        let mut out_buf = Vec::with_capacity(128);
        out_buf.extend_from_slice(&challenge);
        out_buf.extend_from_slice(&eph_pub);
        out_buf.extend_from_slice(&hub_sig);

        let c = &mut state.clients[ci];
        let Some(sock) = &mut c.sock else {
            return false;
        };
        if !net::write_framed(sock, &out_buf) {
            hlog!("[HUB][ERROR] Failed to send v2 challenge to {uuid}\n");
            return false;
        }

        c.challenge = challenge;
        c.bot_eph_x25519_priv = eph_priv;
        c.bot_eph_x25519_pub = eph_pub;
        c.bot_eph_priv_set = true;
        c.id = trunc_string(&uuid, 64);
        c.bot_auth_state = BotAuthState::ChallengeSent;
        c.last_seen = now();

        hlog!("[HUB] Sent v2 signed Curve25519 challenge to bot {uuid}\n");
        return true;
    }

    // PHASE 2: receive the 64-byte Ed25519 signature.
    if !state.clients[ci].authenticated
        && state.clients[ci].bot_auth_state == BotAuthState::ChallengeSent
    {
        let id = state.clients[ci].id.clone();
        let ip = state.clients[ci].ip.clone();
        hlog!("[HUB] Received signature from bot {id} ({packet_len} bytes)\n");

        if packet_len != ED25519_SIG_LEN || !state.clients[ci].bot_eph_priv_set {
            hlog!("[HUB][ERROR] Bad signature size or state from {id}\n");
            return false;
        }

        let Some(bot_combined) = load_bot_combined_pub(state, &id) else {
            hlog!("[HUB][ERROR] No public key for bot {id}\n");
            return false;
        };
        let (bot_ed_pub, bot_x_pub) = crypto::pub_halves(&bot_combined);

        let msg = bot_transcript(
            &id,
            &state.clients[ci].bot_eph_x25519_pub,
            &state.clients[ci].challenge,
        );
        if !crypto::ed25519_verify(&bot_ed_pub, &msg, data) {
            hlog!("[HUB][ERROR] Invalid signature from bot {id}\n");
            ratelimit::record_failed_auth(state, &ip);
            return false;
        }

        let Some(shared) =
            crypto::x25519_derive(&state.clients[ci].bot_eph_x25519_priv, &bot_x_pub)
        else {
            hlog!("[HUB][ERROR] X25519 derive failed for {id}\n");
            return false;
        };

        let info = format!("irchub-bot-session-v1|{id}");
        let mut session_key = zeroize::Zeroizing::new([0u8; 32]);
        let ok = crypto::hkdf_sha256(
            shared.as_ref(),
            &state.clients[ci].challenge,
            info.as_bytes(),
            session_key.as_mut(),
        );
        {
            let c = &mut state.clients[ci];
            crypto::wipe(c.bot_eph_x25519_priv.as_mut());
            c.bot_eph_priv_set = false;
        }
        if !ok {
            hlog!("[HUB][ERROR] HKDF failed for {id}\n");
            return false;
        }
        state.clients[ci].session_key = session_key;

        // The ACK: iv(12) || ciphertext(1) || tag(16) = 29 bytes.
        let Some((body, tag)) =
            crypto::aes_gcm_encrypt(&[0x01], state.clients[ci].session_key.as_ref())
        else {
            hlog!("[HUB][ERROR] ACK encrypt failed for {id}\n");
            return false;
        };
        let mut ack = body;
        ack.extend_from_slice(&tag);

        {
            let c = &mut state.clients[ci];
            let Some(sock) = &mut c.sock else {
                return false;
            };
            if !net::write_framed(sock, &ack) {
                hlog!("[HUB][ERROR] Failed to send v2 ACK to {id}\n");
                return false;
            }
            c.typ = ClientType::Bot;
            c.authenticated = true;
            c.bot_auth_state = BotAuthState::Complete;
            c.last_seen = now();
            // D2: grow the buffers now that the bot is authenticated.
            c.promote_buffers();
        }

        let seen = state.clients[ci].last_seen;
        storage::update_entry(state, &id, "seen", "", "", "", seen);

        // A new bot joins the tree: gossip and push on the next tick instead
        // of leaving it invisible to the mesh until the periodic refresh.
        presence::roster_mark_dirty(state);
        state.last_presence_gossip = 0;

        hlog!("[HUB] Bot {id} authenticated (Curve25519)\n");
        return true;
    }

    false
}

/// add_pending_bot(): a ring of the last MAX_PENDING_BOTS unauthorized UUIDs,
/// for the admin console's "pending authorization" list.
pub fn add_pending_bot(state: &mut HubState, uuid: &str, ip: &str) {
    if let Some(p) = state.pending.iter_mut().find(|p| p.uuid == uuid) {
        p.last_attempt = now();
        p.ip = trunc_string(ip, 64);
        return;
    }
    let entry = PendingBot {
        uuid: trunc_string(uuid, 64),
        nick: "Unknown".to_string(),
        ip: trunc_string(ip, 64),
        last_attempt: now(),
    };
    if state.pending.len() < MAX_PENDING_BOTS {
        state.pending.push(entry);
    } else {
        let idx = state.pending_head;
        state.pending[idx] = entry;
        state.pending_head = (state.pending_head + 1) % MAX_PENDING_BOTS;
    }
}

pub fn remove_pending_bot(state: &mut HubState, uuid: &str) {
    if let Some(i) = state.pending.iter().position(|p| p.uuid == uuid) {
        state.pending.remove(i);
    }
}

/// hub_state_add_bot_memory(): register a bot the admin just created.
///
/// (broadcast_new_key is gone: independent per-hub keypairs mean private keys
/// must never travel between hubs.  Rekey is local-only — each hub
/// regenerates its own keypair and exports the new pubkey for peers to
/// re-register.)
pub fn add_bot_memory(state: &mut HubState, uuid: &str, nick: &str, pub_key: &str) {
    if state.bots.iter().any(|b| b.uuid == uuid) {
        return;
    }
    if state.bots.len() >= MAX_BOTS {
        return;
    }
    state.bots.push(BotConfig {
        uuid: trunc_string(uuid, 64),
        entries: Vec::new(),
        // A new registration is live.  is_active follows the 'd' entry alone,
        // so it must be set here.
        is_active: true,
        last_sync_time: 0,
    });
    let t = now();
    storage::update_entry(state, uuid, "n", nick, "", "", t);
    storage::update_entry(state, uuid, "pub", pub_key, "", "", t);
    storage::update_entry(state, uuid, "seen", "", "", "", t);
}

/// hub_disconnect_client(): close one connection and free everything it held.
pub fn disconnect_client(state: &mut HubState, ci: usize) {
    if ci >= state.clients.len() {
        return;
    }
    let (ip, fd, typ, authed) = {
        let c = &state.clients[ci];
        (c.ip.clone(), c.fd, c.typ, c.authenticated)
    };
    hlog!("[HUB] Disconnecting client {ip} (FD: {fd})\n");

    ratelimit::decrement_active_connections(state, &ip);

    // 1. Update peer status FIRST.
    let mut peer_went_away = false;
    for p in &mut state.peers {
        if p.fd == fd && fd != -1 {
            p.connected = false;
            p.fd = -1;
            // Its uptime stops being a fact the moment the link drops; the
            // bots beneath it age out of the roster on the TTL.
            p.remote_started = 0;
            peer_went_away = true;
        }
    }
    if peer_went_away {
        state.mesh_state_dirty = true;
        presence::roster_mark_dirty(state); // a whole branch just went away
    }
    // A bot leaving changes the tree; gossip it on the next tick rather than
    // waiting for its roster entry to time out on the peers.
    if typ == ClientType::Bot && authed {
        presence::roster_mark_dirty(state);
        state.last_presence_gossip = 0;
    }

    // 2-4. Close the socket, drop it out of the list, and wipe what it held.
    // The queues and the in-flight ciphertext go after the socket is closed
    // so no drain attempt can race, and `Zeroizing`/`Locked` wipe the rest on
    // drop.
    let mut c = state.clients.swap_remove(ci);
    c.sock = None;
    c.fd = -1;
    c.queue_destroy();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcripts_are_domain_separated() {
        let ch = [1u8; 32];
        let ep = [2u8; 32];
        let h = hub_transcript("u", &ch, &ep);
        let b = bot_transcript("u", &ep, &ch);
        assert!(h.starts_with(b"irchub-hub-auth-v2|u|"));
        assert!(b.starts_with(b"irchub-bot-challenge-v1|u|"));
        assert_ne!(h, b);
        assert_eq!(h.len(), 19 + 1 + 1 + 64);
        assert_eq!(b.len(), 24 + 1 + 1 + 64);
    }

    #[test]
    fn pending_bots_ring_and_dedupe() {
        let mut s = HubState::new();
        for i in 0..MAX_PENDING_BOTS {
            add_pending_bot(&mut s, &format!("uuid-{i}"), "10.0.0.1");
        }
        assert_eq!(s.pending.len(), MAX_PENDING_BOTS);
        // A repeat refreshes in place rather than growing the ring.
        add_pending_bot(&mut s, "uuid-0", "10.0.0.2");
        assert_eq!(s.pending.len(), MAX_PENDING_BOTS);
        assert_eq!(s.pending[0].ip, "10.0.0.2");
        // A new one past the cap overwrites the ring head.
        add_pending_bot(&mut s, "uuid-new", "10.0.0.3");
        assert_eq!(s.pending.len(), MAX_PENDING_BOTS);
        assert_eq!(s.pending[0].uuid, "uuid-new");
        assert_eq!(s.pending_head, 1);

        remove_pending_bot(&mut s, "uuid-new");
        assert_eq!(s.pending.len(), MAX_PENDING_BOTS - 1);
    }

    #[test]
    fn add_bot_memory_is_idempotent_and_live() {
        let mut s = HubState::new();
        add_bot_memory(&mut s, "bot-1", "nick", "key");
        add_bot_memory(&mut s, "bot-1", "other", "key2");
        assert_eq!(s.bots.len(), 1);
        assert!(s.bots[0].is_active);
        assert_eq!(s.bots[0].entry("n").unwrap().value, "nick");
    }
}
