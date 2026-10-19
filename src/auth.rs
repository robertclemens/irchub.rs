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
use crate::state::{BotAuthState, BotConfig, ClientType, HubState, Lane};
use crate::{crypto, net, presence, ratelimit, storage};

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

/// The key a revoked bot must prove (`revoke`).
fn load_revoked_pub(state: &HubState, uuid: &str) -> Option<[u8; COMBINED_KEY_LEN]> {
    let r = crate::revoke::find(state, uuid)?;
    let dec = crypto::b64_decode(&r.pub_key)?;
    if dec.len() != COMBINED_KEY_LEN {
        return None;
    }
    let mut out = [0u8; COMBINED_KEY_LEN];
    out.copy_from_slice(&dec);
    Some(out)
}

/// retire_ack_apply(): a revoked bot's CMD_BOT_RETIRE_ACK (quarantine or in
/// session): stamp it wiped and tell the mesh.  The caller closes the
/// connection.
pub fn retire_ack_apply(state: &mut HubState, ci: usize, payload: &[u8]) {
    let id = state.clients[ci].id.clone();
    if let Some(line) = crate::revoke::mark_wiped(state, &id, now()) {
        crate::mesh::broadcast_sync_to_peers(state, &line, -1);
    }
    if payload.first() == Some(&b'1') {
        crate::hlog_info!("[REVOKE] Revoked bot {id} wiped its config and is exiting\n");
    } else {
        crate::hlog_warning!(
            "[REVOKE] Revoked bot {id} could not wipe its config; it exits, and is told again \
             if it ever connects\n"
        );
    }
}

/// hub_retire_revoked_bots(): bot del, here or on another hub: every
/// connected bot this hub holds that is on the revoke list is told
/// CMD_BOT_RETIRE.  The maintenance scan closes the ones that never answer
/// after RETIRE_GRACE_SEC.  Returns how many were told.
pub fn retire_revoked_bots(state: &mut HubState) -> usize {
    let t = now();
    let mut n = 0;
    for i in 0..state.clients.len() {
        let c = &state.clients[i];
        if c.typ != ClientType::Bot
            || !c.authenticated
            || c.retiring
            || !crate::revoke::is_revoked(state, &c.id)
        {
            continue;
        }
        let c = &mut state.clients[i];
        let Some(m) = crate::state::QueuedMsg::new(CMD_BOT_RETIRE, Lane::Urgent, &[]) else {
            continue;
        };
        if !crate::queue::enqueue(c, m) {
            crate::hlog_warning!("[REVOKE] Could not queue CMD_BOT_RETIRE for {}\n", c.id);
            continue;
        }
        c.retiring = true;
        c.retire_sent = t;
        crate::hlog_info!(
            "[REVOKE] Deleted bot {} is connected here: told to wipe its config\n",
            c.id
        );
        n += 1;
    }
    // Its row in the tree goes now, on every hub, rather than when the gossip
    // TTL runs out: roster_upsert refuses to bring it back.
    let mut i = 0;
    while i < state.roster.len() {
        if crate::revoke::is_revoked(state, &state.roster[i].bot_uuid) {
            state.roster.swap_remove(i);
            state.tree_dirty = true;
            continue;
        }
        i += 1;
    }
    n
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

    // QUARANTINE: a revoked bot was sent CMD_BOT_RETIRE as its ACK; the only
    // frame it may send is CMD_BOT_RETIRE_ACK.  Either way it is closed
    // (false) — never as a failed login.
    if state.clients[ci].bot_auth_state == BotAuthState::Quarantine {
        let mut plain = None;
        if packet_len > GCM_IV_LEN + GCM_TAG_LEN && packet_len <= 64 {
            let (body, tag) = data.split_at(packet_len - GCM_TAG_LEN);
            plain = crypto::aes_gcm_decrypt(body, state.clients[ci].session_key.as_ref(), tag);
        }
        match plain {
            Some(p) if p.len() >= 5 && p[0] == CMD_BOT_RETIRE_ACK => {
                let st = if p.len() > 5 { p[5] } else { b'0' };
                retire_ack_apply(state, ci, &[st]);
            }
            _ => crate::hlog_info!(
                "[REVOKE] Revoked bot {} did not answer the wipe (an older build?); closed\n",
                state.clients[ci].id
            ),
        }
        crypto::wipe(state.clients[ci].session_key.as_mut());
        return false;
    }

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
            LOG_DEBUG,
            &format!("[HUB] Bot auth attempt from {ip} with UUID: "),
            data,
            "\n",
        );

        // A revoked bot goes through the whole handshake (it must prove its
        // key) and is then told to wipe itself: never a failed login, so a
        // host that brings an old bot back is not blocked for its other bots.
        let quarantine = crate::revoke::is_revoked(state, &uuid);
        state.clients[ci].quarantine = quarantine;
        let authorized = quarantine || state.bots.iter().any(|b| b.uuid == uuid && b.is_active);
        if !authorized {
            crate::logging::hub_log_with_raw(
                LOG_WARNING,
                "[HUB] Unauthorized bot UUID: ",
                data,
                &format!(" from {ip}\n"),
            );
            ratelimit::record_failed_auth(state, &ip);
            return false;
        }
        if quarantine {
            crate::hlog_info!(
                "[REVOKE] Revoked bot {uuid} connecting from {ip}: checking its key\n"
            );
        }

        let mut challenge = [0u8; 32];
        if !crypto::random_bytes(&mut challenge) {
            crate::hlog_error!("[HUB] Failed to generate challenge\n");
            return false;
        }
        let Some((eph_priv, eph_pub)) = crypto::gen_ephemeral_x25519() else {
            crate::hlog_error!("[HUB] Ephemeral X25519 keygen failed\n");
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
            crate::hlog_warning!("[HUB] Failed to send v2 challenge to {uuid}\n");
            return false;
        }

        c.challenge = challenge;
        c.bot_eph_x25519_priv = eph_priv;
        c.bot_eph_x25519_pub = eph_pub;
        c.bot_eph_priv_set = true;
        c.id = trunc_string(&uuid, 64);
        c.bot_auth_state = BotAuthState::ChallengeSent;
        c.last_seen = now();

        crate::hlog_debug!("[HUB] Sent v2 signed Curve25519 challenge to bot {uuid}\n");
        return true;
    }

    // PHASE 2: receive the 64-byte Ed25519 signature.
    if !state.clients[ci].authenticated
        && state.clients[ci].bot_auth_state == BotAuthState::ChallengeSent
    {
        let id = state.clients[ci].id.clone();
        let ip = state.clients[ci].ip.clone();
        crate::hlog_debug!("[HUB] Received signature from bot {id} ({packet_len} bytes)\n");

        if packet_len != ED25519_SIG_LEN || !state.clients[ci].bot_eph_priv_set {
            crate::hlog_warning!("[HUB] Bad signature size or state from {id}\n");
            return false;
        }

        let key = if state.clients[ci].quarantine {
            load_revoked_pub(state, &id)
        } else {
            load_bot_combined_pub(state, &id)
        };
        let Some(bot_combined) = key else {
            crate::hlog_warning!("[HUB] No public key for bot {id}\n");
            return false;
        };
        let (bot_ed_pub, bot_x_pub) = crypto::pub_halves(&bot_combined);

        let msg = bot_transcript(
            &id,
            &state.clients[ci].bot_eph_x25519_pub,
            &state.clients[ci].challenge,
        );
        if !crypto::ed25519_verify(&bot_ed_pub, &msg, data) {
            crate::hlog_warning!("[HUB] Invalid signature from bot {id}\n");
            ratelimit::record_failed_auth(state, &ip);
            return false;
        }

        let Some(shared) =
            crypto::x25519_derive(&state.clients[ci].bot_eph_x25519_priv, &bot_x_pub)
        else {
            crate::hlog_error!("[HUB] X25519 derive failed for {id}\n");
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
            crate::hlog_error!("[HUB] HKDF failed for {id}\n");
            return false;
        }
        state.clients[ci].session_key = session_key;

        // The ACK: iv(12) || ciphertext(1) || tag(16) = 29 bytes.  A revoked
        // bot gets CMD_BOT_RETIRE in the ACK's place: it wipes its config,
        // answers CMD_BOT_RETIRE_ACK, and is never a ClientType::Bot here.
        let quarantine = state.clients[ci].quarantine;
        let ack_plain = if quarantine { CMD_BOT_RETIRE } else { 0x01 };
        let Some((body, tag)) =
            crypto::aes_gcm_encrypt(&[ack_plain], state.clients[ci].session_key.as_ref())
        else {
            crate::hlog_error!("[HUB] ACK encrypt failed for {id}\n");
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
                crate::hlog_warning!("[HUB] Failed to send v2 ACK to {id}\n");
                return false;
            }
            if quarantine {
                c.bot_auth_state = BotAuthState::Quarantine;
                crate::hlog_info!(
                    "[REVOKE] Revoked bot {id} proved its key: told to wipe its config\n"
                );
                return true;
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
        presence::roster_mark_dirty(state, true);
        state.last_presence_gossip = 0;

        crate::hlog_info!("[HUB] Bot {id} authenticated (Curve25519)\n");
        return true;
    }

    false
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
    // A console that goes away is owed nothing any more.
    if state.clients[ci].internal {
        let serial = state.clients[ci].conn_serial;
        crate::elect::forget_admin(state, serial);
    }
    // fd -1: a socket handed to the SSH console, not a disconnect.
    if fd >= 0 {
        crate::hlog_info!("[HUB] Disconnecting client {ip} (FD: {fd})\n");
    }

    ratelimit::decrement_active_connections(state, &ip);

    // 1. Update peer status FIRST.
    let mut peer_went_away = false;
    for p in &mut state.peers {
        if p.fd == fd && fd != -1 {
            p.connected = false;
            p.fd = -1;
            p.link_down_at = now();
            // Its uptime stops being a fact the moment the link drops; the
            // bots beneath it age out of the roster on the TTL.
            p.remote_started = 0;
            peer_went_away = true;
        }
    }
    if peer_went_away {
        state.mesh_state_dirty = true;
        presence::roster_mark_dirty(state, false); // a whole branch just went away
    }
    // A bot leaving changes the tree; gossip it on the next tick rather than
    // waiting for its roster entry to time out on the peers.
    if typ == ClientType::Bot && authed {
        presence::roster_mark_dirty(state, true);
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
    fn add_bot_memory_is_idempotent_and_live() {
        let mut s = HubState::new();
        add_bot_memory(&mut s, "bot-1", "nick", "key");
        add_bot_memory(&mut s, "bot-1", "other", "key2");
        assert_eq!(s.bots.len(), 1);
        assert!(s.bots[0].is_active);
        assert_eq!(s.bots[0].entry("n").unwrap().value, "nick");
    }
}
