//! irchub: the encrypted hub mesh ircbot connects to (safe-Rust port of
//! hub_main.c).  Entry point: process hardening, the setup wizard, the
//! machine-bound password file, daemonizing, and the poll loop.

#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

use irchub::cli_fmt as cli;
use irchub::consts::*;
use irchub::cstr::{now, trunc_string};
use irchub::state::Lane;
use irchub::state::{ClientType, HubClient, HubState, MaskRecord, UserRecord, name_valid};
use irchub::{
    activity, auth, client, config, crypto, hlog_debug, hlog_error, hlog_info, hlog_warning,
    logging, mesh, net, presence, presence2, queue, ratelimit, storage, tool, upgrade,
};

const PEER_INFO: &[u8] = b"irchub-peer-session-v1";

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

/// Detach: new session, stdio to /dev/null, umask 0077.  The working
/// directory stays, so the relative .pid / .log / .cnf paths resolve.
fn daemonize() {
    if let Err(e) = nix::unistd::daemon(true, false) {
        eprintln!("daemon: {e}");
        std::process::exit(1);
    }
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
}

/// The pid file, flock'd: the lock is what says this hub is running.
fn lock_pid_file() -> Option<fs::File> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(HUB_PID_FILE)
        .ok()?;
    if f.try_lock().is_err() {
        let mut existing = String::new();
        let _ = f.read_to_string(&mut existing);
        let existing = existing.lines().next().unwrap_or("");
        if existing.is_empty() {
            eprintln!("Hub already running — {HUB_PID_FILE} locked");
        } else {
            eprintln!("Hub already running (pid {existing}) — {HUB_PID_FILE}");
        }
        return None;
    }
    // Truncate first so no stale bytes remain when the new pid is shorter.
    f.set_len(0).ok()?;
    writeln!(f, "{}", std::process::id()).ok()?;
    Some(f)
}

/// Instance directory: .irchub.cnf/.pass/.pid/.log/.upgrade and hub_upgrade.sh all live beside the binary, so the hub behaves the same
/// whatever the caller's cwd -- cron starts jobs in $HOME.  One binary per hub.  Our own
/// path comes from /proc/self/exe (`current_exe`; argv[0] has no directory when launched
/// through PATH); returns it after chdir()ing to its directory.  That directory holds the
/// binary an upgrade replaces, its .prev and the upgrade script, so refuse one another user
/// owns and chmod go-w one group/other can write -- they could swap any of them.  Mirrors
/// `instance_dir_enter()` in irchub/hub_main.c.
fn instance_dir_enter() -> Option<String> {
    let Ok(exe) = std::env::current_exe() else {
        eprintln!("Cannot resolve my own path (/proc/self/exe)");
        return None;
    };
    let Some(dir) = exe.parent() else {
        eprintln!("Cannot resolve my own directory from {}", exe.display());
        return None;
    };
    let md = match fs::metadata(dir) {
        Ok(md) if md.is_dir() => md,
        _ => {
            eprintln!("Cannot stat my own directory {}", dir.display());
            return None;
        }
    };
    if md.uid() != nix::unistd::geteuid().as_raw() {
        eprintln!(
            "Refusing to run from {}: it must be owned by this user",
            dir.display()
        );
        return None;
    }
    // Group/other write (a 002 umask makes 0775 directories): we own it, so close the hole
    // rather than refuse -- refusing turned every upgrade on such a host into a watchdog
    // rollback and a fresh install into a dead start.  Nothing is weakened: the directory
    // was open before we ran.
    if md.mode() & 0o022 != 0 {
        let m = md.mode() & 0o7777 & !0o022;
        if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(m)) {
            eprintln!(
                "Refusing to run from {}: group/other can write it and chmod go-w failed ({e})",
                dir.display()
            );
            return None;
        }
        eprintln!(
            "Removed group/other write from {} (now {m:04o})",
            dir.display()
        );
    }
    if std::env::set_current_dir(dir).is_err() {
        eprintln!("Cannot change to my own directory {}", dir.display());
        return None;
    }
    Some(exe.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// Machine-bound password file
// ---------------------------------------------------------------------------

/// The context a .irchub.pass is bound to: the home directory's inode and
/// device, the uid and gid, and the machine type.  Moving the file to another
/// account or host makes it undecryptable.
fn passfile_context() -> String {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    let (ino, dev) = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .and_then(|u| fs::metadata(u.dir).ok())
        .map_or((0, 0), |md| (md.ino(), md.dev()));
    let machine = nix::sys::utsname::uname()
        .map(|u| u.machine().to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(
        "{ino}:{dev}:{}:{}:{}",
        uid.as_raw(),
        gid.as_raw(),
        trunc_string(&machine, 65)
    )
}

/// File layout: `[SALT_SIZE][IV+ciphertext][GCM_TAG_LEN]`.
fn passfile_load(path: &str) -> Option<Zeroizing<String>> {
    let md = fs::metadata(path).ok()?;
    if md.uid() != nix::unistd::getuid().as_raw() {
        eprintln!("[WARN] {path}: wrong owner, ignoring.");
        return None;
    }
    if md.permissions().mode() & 0o777 != 0o600 {
        eprintln!("[WARN] {path}: must be 0600, ignoring.");
        return None;
    }
    let min_size = SALT_SIZE + GCM_IV_LEN + 1 + GCM_TAG_LEN;
    if (md.len() as usize) < min_size {
        return None;
    }
    let buf = Zeroizing::new(fs::read(path).ok()?);
    let enc_len = buf.len() - SALT_SIZE - GCM_TAG_LEN;
    let salt = &buf[..SALT_SIZE];
    let enc_blk = &buf[SALT_SIZE..SALT_SIZE + enc_len];
    let tag = &buf[SALT_SIZE + enc_len..];

    let ctx = passfile_context();
    let key = crypto::derive_config_key(ctx.as_bytes(), salt, PBKDF2_ITERATIONS);
    match crypto::aes_gcm_decrypt(enc_blk, key.as_ref(), tag) {
        Some(plain) => Some(Zeroizing::new(String::from_utf8_lossy(&plain).into_owned())),
        None => {
            eprintln!(
                "[WARN] {path}: decryption failed (wrong machine, tampered, or written before 2.5.0), falling through."
            );
            None
        }
    }
}

fn passfile_create(path: &str, password: &str) -> bool {
    let mut salt = [0u8; SALT_SIZE];
    if !crypto::random_bytes(&mut salt) {
        eprintln!("RNG failure.");
        return false;
    }
    let key = crypto::derive_config_key(passfile_context().as_bytes(), &salt, PBKDF2_ITERATIONS);
    let Some((enc_buf, tag)) = crypto::aes_gcm_encrypt(password.as_bytes(), key.as_ref()) else {
        eprintln!("Encryption failed.");
        return false;
    };
    // Written beside it and renamed over it, so a rewrite (-p, or the PBKDF2
    // migration at start) never leaves a half-written pass file.
    let tmp = format!("{path}.tmp");
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp);
    let Ok(mut f) = f else {
        eprintln!("open {path} failed.");
        return false;
    };
    if f.set_permissions(fs::Permissions::from_mode(0o600))
        .is_err()
    {
        eprintln!("chmod {path} failed.");
        let _ = fs::remove_file(&tmp);
        return false;
    }
    let mut ok =
        f.write_all(&salt).is_ok() && f.write_all(&enc_buf).is_ok() && f.write_all(&tag).is_ok();
    if !ok {
        eprintln!("write {path} failed.");
    }
    drop(f);
    if ok && fs::rename(&tmp, path).is_err() {
        eprintln!("rename {path} failed.");
        ok = false;
    }
    if !ok {
        let _ = fs::remove_file(&tmp);
    }
    ok
}

// ---------------------------------------------------------------------------
// Peer handshake
// ---------------------------------------------------------------------------

/// hub_peer_handshake(): the outbound half of HUBv3.
///
/// A sealed box to the peer's X25519 key carries
/// `HUBv3|<uuid>|<port>|<name>|<bind_ip>|<ts>|<sig_b64>`, where the signature
/// commits to the same transcript the receiver reconstructs from the parsed
/// fields and the stored peer record.  The box's HKDF output is the session
/// key for every frame afterwards.
fn peer_handshake(state: &mut HubState, ci: usize, pi: usize) {
    if !state.hub_keys_loaded {
        hlog_error!("[PEER] No Curve25519 keys loaded; cannot handshake\n");
        auth::disconnect_client(state, ci);
        return;
    }
    if !state.peers[pi].has_pubkey {
        hlog_warning!(
            "[PEER] Peer has no registered pubkey — refusing to connect. Re-add this peer with its Curve25519 pubkey (HUBv3 auth needs it).\n"
        );
        auth::disconnect_client(state, ci);
        return;
    }

    let ts_str = now().to_string();
    let transcript = format!(
        "irchub-peer-auth-v3|{}|{ts_str}|{}|{}|{}",
        state.hub_uuid, state.port, state.hub_friendly_name, state.bind_ip
    );
    if transcript.len() >= 512 {
        hlog_error!("[PEER] v3 transcript too long\n");
        auth::disconnect_client(state, ci);
        return;
    }
    let mut ed_seed = [0u8; 32];
    ed_seed.copy_from_slice(state.hub_ed25519_priv.get());
    let sig = crypto::ed25519_sign(&ed_seed, transcript.as_bytes());
    crypto::wipe(&mut ed_seed);

    let pack = format!(
        "HUBv3|{}|{}|{}|{}|{ts_str}|{}",
        state.hub_uuid,
        state.port,
        state.hub_friendly_name,
        state.bind_ip,
        crypto::b64_encode(&sig)
    );
    if pack.len() >= 1024 {
        hlog_error!("[PEER] v3 packet too long\n");
        auth::disconnect_client(state, ci);
        return;
    }
    // The C sent msg_len + 1 bytes: the NUL terminator rides along.
    let mut plain = Zeroizing::new(pack.into_bytes());
    plain.push(0);

    let target = state.peers[pi].x25519_pub;
    let Some((enc, session_key)) = crypto::seal_send(&target, &plain, PEER_INFO) else {
        hlog_error!("[PEER] Sealed-box encryption failed\n");
        auth::disconnect_client(state, ci);
        return;
    };

    {
        let c = &mut state.clients[ci];
        c.session_key = session_key;
        let Some(sock) = &mut c.sock else {
            return;
        };
        if !net::write_framed(sock, &enc) {
            hlog_warning!("[PEER] Handshake write failed\n");
            auth::disconnect_client(state, ci);
            return;
        }
        c.authenticated = true;
        // D2/Change 5: grow the buffers to the per-type bulk size now that
        // the peer is authenticated (CLIENT_HUB → MAX_SYNC_PAYLOAD) — the
        // full sync below rides these.
        c.promote_buffers();
    }
    hlog_info!("[PEER] Handshake complete with {}\n", state.clients[ci].ip);
    let peer_uuid = state.peers[pi].uuid.clone();
    irchub::client::link_offer(state, ci, Some(&peer_uuid));
    // presence2::link_up waits for the first frame back (peer_heard): a hub
    // that is frozen still accepts the TCP connect, and must not look linked.
    irchub::presence::roster_send_to_peer(state, ci); // our k|rollcall + bots, past the damping
    // If this process is the product of an upgrade a peer drove, close that
    // run out now that there is a peer to tell (no-op otherwise).
    upgrade::report_pending(state, ci);
    irchub::uhist::send_digest(state, ci);
    irchub::upgrade::plan_send_digest(state, ci);

    // Send a full config sync immediately via the BULK queue.  The queue
    // enforces a per-peer byte budget (BULK_SOFT_BUDGET_BPS) so the
    // simultaneous startup of every hub no longer creates a cascade that
    // fills socket buffers; each hub's BULK drain is naturally staggered by
    // the poll cycle.  This replaces deferring the first sync to
    // anti-entropy (up to a 90 s wait).
    let full_sync = mesh::generate_sync_packet(state);
    let seq = state.next_lamport_seq();
    mesh::peer_enqueue_sync(
        state,
        ci,
        CMD_PEER_SYNC,
        Lane::Bulk,
        &full_sync,
        Some(("handshake_sync", seq)),
    );
    activity::send_bans(state, ci);
}

/// hub_check_peers(): reconnect to any peer we are not linked to.
fn check_peers(state: &mut HubState) {
    let t = now();
    if t - state.timers.last_peer_check < PEER_RECONNECT_INTERVAL {
        return;
    }
    state.timers.last_peer_check = t;

    for pi in 0..state.peers.len() {
        let uuid = state.peers[pi].uuid.clone();
        if state.peers[pi].connected
            || state
                .clients
                .iter()
                .any(|c| c.dialing && c.dial_uuid == uuid)
        {
            continue;
        }
        let (ip, port) = (state.peers[pi].ip.clone(), state.peers[pi].port);
        hlog_debug!("[PEER] Attempting to connect to {ip}:{port}...\n");
        // Review 16: non-blocking, finished by finish_dials from the main loop.
        let Ok(sock) = net::start_connect(&ip, port) else {
            hlog_warning!("[PEER] Failed to connect to {ip}:{port}\n");
            continue;
        };
        if state.clients.len() >= MAX_CLIENTS {
            hlog_warning!("[PEER] Client limit reached.\n");
            continue;
        }
        let fd = {
            use std::os::fd::AsRawFd;
            sock.as_raw_fd()
        };
        // D2: outbound peers immediately exchange bulk anti-entropy sync, so
        // allocate full-size buffers up front.
        let mut c = HubClient::new(sock, fd, &ip, MAX_BUFFER);
        c.typ = ClientType::Hub;
        // Named as an inbound peer is once it authenticates, so what logs a
        // link's id names this one too.
        c.id = trunc_string(
            if state.peers[pi].friendly_name.is_empty() {
                "HUB-PEER"
            } else {
                &state.peers[pi].friendly_name
            },
            64,
        );
        c.last_pong_sent = 0;
        c.dialing = true;
        c.dial_started = t;
        c.dial_uuid = uuid;
        state.clients.push(c);
    }
}

/// Review 16: finish the dials check_peers started.  Ready (writable, or an
/// error) means the connect is done: up, the HUBv3 handshake runs, unless the
/// peer linked to us meanwhile (then this dial is not needed).  Past
/// CONNECT_TIMEOUT it is given up, as the blocking connect gave up.
fn finish_dials(state: &mut HubState, ready: &[(i32, bool, bool)]) {
    let t = now();
    let mut i = 0;
    while i < state.clients.len() {
        if !state.clients[i].dialing {
            i += 1;
            continue;
        }
        let fd = state.clients[i].fd;
        let is_ready = ready.iter().any(|&(f, rd, wr)| f == fd && (rd || wr));
        let pi = state
            .peers
            .iter()
            .position(|p| p.uuid == state.clients[i].dial_uuid);
        if !is_ready && t - state.clients[i].dial_started <= CONNECT_TIMEOUT as i64 && pi.is_some()
        {
            i += 1;
            continue;
        }
        state.clients[i].dialing = false;
        let Some(pi) = pi.filter(|&pi| !state.peers[pi].connected) else {
            // the peer was deleted, or it linked to us first
            auth::disconnect_client(state, i);
            continue;
        };
        let res = if is_ready {
            state.clients[i].sock.as_ref().map_or(
                Err(std::io::Error::from(std::io::ErrorKind::NotConnected)),
                net::finish_connect,
            )
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
        };
        if let Err(e) = res {
            let (ip, port) = (state.peers[pi].ip.clone(), state.peers[pi].port);
            if is_ready {
                hlog_warning!("[PEER] Failed to connect to {ip}:{port}: {e}\n");
            } else {
                hlog_warning!("[PEER] Failed to connect to {ip}:{port} (timed out)\n");
            }
            auth::disconnect_client(state, i);
            continue;
        }
        state.clients[i].last_seen = t;
        state.peers[pi].connected = true;
        state.peers[pi].fd = fd;
        state.mesh_state_dirty = true;
        let before = state.clients.len();
        peer_handshake(state, i, pi);
        if state.clients.len() == before {
            i += 1; // else the handshake dropped it: the next client is at i
        }
    }
}

// ---------------------------------------------------------------------------
// Maintenance
// ---------------------------------------------------------------------------

fn maintenance(state: &mut HubState) {
    let t = now();
    if state.timers.last_mesh_gossip == 0 {
        state.timers.last_mesh_gossip = t;
    }
    if state.timers.last_client_scan == 0 {
        state.timers.last_client_scan = t;
    }
    if state.timers.last_ip_cleanup == 0 {
        state.timers.last_ip_cleanup = t;
    }

    // Bot presence: gossip our own bots to the peers, expire entries nobody
    // refreshed, and push the tree to bots when it changed.  All volatile.
    presence::presence_tick(state, t);
    irchub::pool::order_tick(state, t); // the bots' server orders
    irchub::pool::rebalance_tick(state, t); // server rebalance force waves

    // Rolling network upgrade: one step per tick (no-op unless running).
    upgrade::tick(state, t);

    // Channel-request elections: probe windows and hand-off timeouts.
    irchub::elect::tick(state, t);

    // Hub roll calls (the upgrade gates): end the ones whose wait ran out.
    irchub::rollcall::tick(state, t);

    // This hub's public address: at start, then daily (never blocks).
    irchub::pubip::tick(state, t);

    // Expired bans: one `del` per ban, self-throttled to BAN_SWEEP_INTERVAL.
    irchub::modes::bans_sweep(state, t);

    // The full config push owed to the bots, coalesced across a burst.
    client::flush_bot_config(state, t);

    // Mesh-state gossip: every 5 min as a heartbeat, or immediately when the
    // peer topology changes (connect/disconnect sets mesh_state_dirty).
    if state.mesh_state_dirty || t - state.timers.last_mesh_gossip > 300 {
        state.timers.last_mesh_gossip = t;
        state.mesh_state_dirty = false;
        if !state.peers.is_empty() {
            mesh::broadcast_mesh_state(state);
        }
    }

    // Anti-entropy: stagger the first fire 30-90 s, then every
    // MESH_ANTI_ENTROPY_INTERVAL.
    if state.timers.last_anti_entropy == 0 {
        let jitter = i64::from(30 + crypto::random_below(61));
        state.timers.last_anti_entropy = t - (MESH_ANTI_ENTROPY_INTERVAL - jitter);
    }
    if t - state.timers.last_anti_entropy > MESH_ANTI_ENTROPY_INTERVAL {
        state.timers.last_anti_entropy = t;
        if !state.peers.is_empty() {
            let full_sync = mesh::generate_sync_packet(state);
            mesh::anti_entropy_round(state, &full_sync);
            irchub::uhist::digest_all(state);
        }
    }

    // Config write debounce.
    if state.config_dirty && t - state.last_config_write >= CONFIG_WRITE_DEBOUNCE_S {
        config::write(state);
        state.config_dirty = false;
        state.last_config_write = t;
    }

    // The IP allow/deny lists changed: the accept-time check only sees new
    // connections, so close the inbound ones the lists no longer permit.
    // (The admin who made the change is permitted: the change is refused
    // otherwise.)  Outbound peer links are operator-configured, not listed.
    if state.ip_acl_changed {
        state.ip_acl_changed = false;
        let mut i = 0;
        while i < state.clients.len() {
            let c = &state.clients[i];
            if c.inbound && !ratelimit::ip_acl_permits(state, &c.ip) {
                hlog_warning!(
                    "[ACCESS_CONTROL] Closing {}: no longer permitted by the allow/deny lists\n",
                    c.ip
                );
                auth::disconnect_client(state, i);
                continue;
            }
            i += 1;
        }
    }

    // IP rate-limit cleanup: every 5 minutes.
    if t - state.timers.last_ip_cleanup > 300 {
        ratelimit::cleanup_old_ip_limits(state);
        state.timers.last_ip_cleanup = t;
    }

    // Scheduled tombstone purge: daily, leader only.
    if state.purge_days_setting > 0 {
        if state.timers.last_purge == 0 {
            state.timers.last_purge = t;
        }
        if t - state.timers.last_purge > 86400 {
            state.timers.last_purge = t;
            state.config_dirty = true; // purge_last|: a restart keeps the day
            if mesh::should_initiate_scheduled_purge(state) {
                hlog_info!(
                    "[HUB] Running scheduled purge (older than {} days)\n",
                    state.purge_days_setting
                );
                let cutoff = t - i64::from(state.purge_days_setting) * 86400;
                let purged = mesh::execute_purge(state, cutoff, None);
                if purged > 0 {
                    hlog_info!("[HUB] Scheduled purge removed {purged} tombstones\n");
                }
                mesh::broadcast_purge(state, cutoff);
            } else {
                hlog_info!("[HUB] Scheduled purge skipped (not elected leader in mesh)\n");
            }
        }
    }

    // Client timeout/ping scan: every 5 s.  There is no need to walk 50+
    // clients four times a second when the ping window is 60 s and the
    // timeout is 180 s.
    if t - state.timers.last_client_scan >= 5 {
        state.timers.last_client_scan = t;
        let mut i = 0;
        while i < state.clients.len() {
            let c = &state.clients[i];
            // An SSH console has no pings: the console thread owns its idle
            // timeout, and the socketpair closes when the session does.
            if c.internal {
                i += 1;
                continue;
            }
            // Phase 3: a v2 peer link lives on the 15 s digest, so it is dropped
            // after P2_LINK_TIMEOUT (3 missed digests) rather than CLIENT_TIMEOUT.
            let p2_keepalive = presence2::digest_keepalive(state, c);
            // A dialled peer link that has not answered gets no longer either.
            let unheard = c.typ == ClientType::Hub && c.authenticated && !c.peer_heard;
            let idle_limit = if p2_keepalive || unheard {
                presence2::P2_LINK_TIMEOUT
            } else {
                CLIENT_TIMEOUT
            };
            if t - c.last_seen > idle_limit {
                hlog_warning!("[HUB] Client {} timed out.\n", c.ip);
                auth::disconnect_client(state, i);
                continue;
            }
            // Output queued and none of it taken for WRITE_STALL_TIMEOUT: the
            // other end stopped reading (14b).  It reconnects once healthy.
            if c.has_pending_writes()
                && c.write_wait_since > 0
                && t - c.write_wait_since > WRITE_STALL_TIMEOUT
            {
                hlog_warning!(
                    "[HUB] {} took no output for {}s — dropping\n",
                    state.who_client(i),
                    t - c.write_wait_since
                );
                auth::disconnect_client(state, i);
                continue;
            }
            // D4: reap connections that never authenticated within the
            // pre-auth window.  Uses connected_at (not last_seen) so a
            // slowloris that dribbles bytes to keep last_seen fresh is still
            // dropped.  Outbound CLIENT_HUB peers are trusted,
            // operator-configured endpoints and are exempt.
            if !c.authenticated
                && c.typ != ClientType::Hub
                && t - c.connected_at > PREAUTH_TIMEOUT_SEC
            {
                if c.bot_auth_state == irchub::state::BotAuthState::Quarantine {
                    hlog_info!(
                        "[REVOKE] Revoked {} did not answer the wipe (an older build?); \
                         closed\n",
                        state.who_client(i)
                    );
                } else {
                    hlog_warning!(
                        "[HUB] Pre-auth timeout for {} ({}s, no handshake) — dropping\n",
                        c.ip,
                        t - c.connected_at
                    );
                }
                auth::disconnect_client(state, i);
                continue;
            }
            // A deleted bot told CMD_BOT_RETIRE that never answered.
            if c.retiring && t - c.retire_sent > RETIRE_GRACE_SEC {
                hlog_info!(
                    "[REVOKE] Deleted {} did not answer the wipe; closed\n",
                    state.who_client(i)
                );
                auth::disconnect_client(state, i);
                continue;
            }
            // Phase 3: no ping on a v2 peer link — its 15 s digest is the
            // keepalive; other clients keep the 60 s ping.
            if c.authenticated && !p2_keepalive && t - c.last_seen > PING_INTERVAL {
                let ip = c.ip.clone();
                if !client::send_ping(state, i) {
                    hlog_warning!("Ping failed to {ip}. Disconnecting.\n");
                    auth::disconnect_client(state, i);
                    continue;
                }
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Setup wizard
// ---------------------------------------------------------------------------

/// -setup: read a user's public key — the pasted 88 chars, or a path to their
/// .public.b64 — show its fingerprint and confirm.  None on EOF.
fn setup_read_pubkey(who: &str) -> Option<String> {
    loop {
        let input = cli::ask("public key", 4096);
        if cli::eof() {
            return None;
        }
        if input.is_empty() {
            cli::err(&format!(
                "a public key is required: run ./keygen {who} on the admin's machine"
            ));
            continue;
        }
        // Private and public key files have the same shape; refuse a keygen
        // private file by name before it gets published in the a| record.
        if input.contains(".private.") {
            cli::err("that is a PRIVATE key file: it stays with the admin; give the .public.b64");
            continue;
        }
        let key = match crypto::pubkey_b64_decode(&input) {
            Some(raw) => Some((input.to_string(), raw)),
            None => {
                let from_file = fs::read_to_string(&*input).ok();
                // C: the first line, cut at its first blank
                let line = from_file.as_ref().map(|s| {
                    let l = s.lines().next().unwrap_or("");
                    l.split([' ', '\t', '\r', '\n'])
                        .next()
                        .unwrap_or("")
                        .to_string()
                });
                match line
                    .as_deref()
                    .filter(|l| !l.is_empty())
                    .and_then(|l| crypto::pubkey_b64_decode(l).map(|r| (l.to_string(), r)))
                {
                    Some(v) => Some(v),
                    None => {
                        cli::err(&format!(
                            "not an 88-char public key{} (the .public.b64, never the .private.b64)",
                            if from_file.is_some() {
                                " in that file"
                            } else {
                                ""
                            }
                        ));
                        None
                    }
                }
            }
        };
        let Some((b64, raw)) = key else { continue };
        cli::kv("fingerprint", &crypto::key_fingerprint(&raw));
        if cli::ask_yes("use this key?", true) {
            return Some(b64);
        }
        if cli::eof() {
            return None;
        }
    }
}

/// The two lines other nodes paste, from -setup's summary and -id.  The
/// address is the looked-up public one, else a specific bind (a wildcard
/// tells nobody).
fn print_paste_lines(state: &HubState, pub_b64: &str) {
    let ip = irchub::pubip::dial_address(state).unwrap_or("<this-hub's-address>");
    let name = if state.hub_friendly_name.is_empty() {
        "-"
    } else {
        state.hub_friendly_name.as_str()
    };
    cli::skv(
        "other hubs",
        "paste on the console of EACH hub that links to this one:",
    );
    print!(
        "\n   hub add {ip} {} {} {name} {pub_b64}\n\n",
        state.port, state.hub_uuid
    );
    cli::note(
        "Hub links are not shared through the mesh: every hub this one links with needs \
         this line, and this hub needs a hub add for each of them.",
    );
    cli::skv("bots", "paste on IRC (or give to ircbot -setup):");
    print!("\n   +hub {ip}:{} {pub_b64}\n\n", state.port);
    if !state.public_ip.is_empty() {
        cli::note(&format!(
            "{} is this host's public address; hubs and bots on the same LAN can dial its \
             LAN address instead.",
            state.public_ip
        ));
    }
}

/// -setup: can this hub listen on ip:port?  A throwaway listener, bound
/// like the real one, then closed.  Err gets the reason.
fn setup_test_bind(ip: &str, port: i32) -> Result<(), String> {
    let Ok(a) = ip.parse::<std::net::Ipv4Addr>() else {
        return Err("not an IPv4 address".to_string());
    };
    match std::net::TcpListener::bind(std::net::SocketAddrV4::new(a, port as u16)) {
        Ok(_) => Ok(()),
        Err(e) => Err(match e.kind() {
            std::io::ErrorKind::AddrInUse => format!("port {port} is already in use"),
            std::io::ErrorKind::AddrNotAvailable => {
                format!("{ip} is not an address of this host")
            }
            std::io::ErrorKind::PermissionDenied => "ports below 1024 need privileges".to_string(),
            // strerror's text, as the C hub prints it
            _ => {
                let t = e.to_string();
                t.split(" (os error").next().unwrap_or(&t).to_string()
            }
        }),
    }
}

fn run_setup(state: &mut HubState) -> i32 {
    cli::header("irchub", HUB_VERSION, "setup");
    cli::note(&format!(
        "No {HUB_CONFIG_FILE} here yet: these steps write one, encrypted with a config password."
    ));
    let (mut admin_name, mut pub_b64_keep, mut id_fp, mut sshfp);
    loop {
        let mut step = 0;
        // a restart (no at the summary) begins from nothing
        state.user_records.clear();
        state.mask_records.clear();
        admin_name = String::new();

        step += 1;
        cli::step(step, "Listening");
        cli::note(
            "bind ip: one IPv4 address of this host to listen on, or empty for 0.0.0.0 (every \
             address).  Both are test-bound before going on.",
        );
        loop {
            let pb = cli::ask("port", 16);
            if cli::eof() {
                return 1;
            }
            match pb.parse::<i64>() {
                Ok(v) if v > 0 && v < 65536 => state.port = v as i32,
                _ => {
                    cli::err("a port is 1-65535");
                    continue;
                }
            }
            let bind = cli::ask("bind ip (empty = 0.0.0.0)", 65);
            if cli::eof() {
                return 1;
            }
            if !bind.is_empty() && bind.parse::<std::net::Ipv4Addr>().is_err() {
                cli::err("not an IPv4 address (a.b.c.d), or leave it empty for 0.0.0.0");
                continue;
            }
            state.bind_ip = if bind.is_empty() {
                "0.0.0.0".to_string()
            } else {
                trunc_string(&bind, 64)
            };
            if let Err(why) = setup_test_bind(&state.bind_ip, state.port) {
                cli::err(&format!(
                    "cannot listen on {}:{}: {why}",
                    state.bind_ip, state.port
                ));
                continue;
            }
            cli::ok(&format!(
                "{}:{} is free{}",
                state.bind_ip,
                state.port,
                if bind.is_empty() {
                    " (0.0.0.0: every address of this host)"
                } else {
                    ""
                }
            ));
            break;
        }

        // What other hubs and bots should dial.  Display only: it fills the
        // paste lines below, and the running hub looks it up again at every
        // start and daily (public| in the config).
        step += 1;
        cli::step(step, "Public address");
        cli::note("Looked up over DNS (OpenDNS, then Google, then Cloudflare).");
        if let Some((ip, src)) = irchub::pubip::lookup() {
            state.public_ip = ip;
            state.public_ip_at = irchub::cstr::now();
            cli::ok(&format!(
                "{} ({})",
                state.public_ip,
                if src >= 0 {
                    irchub::pubip::source_name(src)
                } else {
                    "test hook"
                }
            ));
        } else {
            state.public_ip.clear();
            state.public_ip_at = 0;
            cli::note(
                "no answer: the lines below show <this-hub's-address>; the running hub tries \
                 again at start (hub show prints it).",
            );
        }

        step += 1;
        cli::step(step, "Name");
        cli::note("Shown on every console and in the mesh; 1-63 letters, digits, '.', '_' or '-'.");
        loop {
            let name = cli::ask("name", 128);
            if cli::eof() {
                cli::err("no hub name given");
                return 1;
            }
            if name.len() > 63 {
                cli::err("longer than 63 characters");
                continue;
            }
            if name_valid(&name) {
                state.hub_friendly_name = name.to_string();
                break;
            }
            cli::err(
                "it is written into config lines and hub handshakes: 1-63 letters, digits, '.', '_' or '-'",
            );
        }

        step += 1;
        cli::step(step, "Config password");
        loop {
            let p1 = cli::ask_secret("password", MAX_PASS);
            let p2 = cli::ask_secret("confirm", MAX_PASS);
            if !p1.is_empty() && *p1 == *p2 {
                cli::ok("the passwords match");
                state.set_config_pass(&p1);
                break;
            }
            if cli::eof() {
                return 1;
            }
            cli::err("the passwords do not match, or are empty: again");
        }

        // Per-hub independent keypair (no shared-keypair mesh).  Generate
        // fresh and export only the public key; the private key stays inside
        // the encrypted config — no plaintext hub_private.b64 file is dumped.
        step += 1;
        cli::step(step, "Identity (generated here, Curve25519)");
        let Some(uuid) = crypto::gen_uuid_v4() else {
            cli::err("RNG failure");
            return 1;
        };
        state.hub_uuid = uuid;
        let Some((priv64, pub64)) = crypto::generate_combined_keypair() else {
            cli::err("key generation failed");
            return 1;
        };
        state.set_hub_priv(&priv64);
        state.set_hub_pub(&pub64);
        state.hub_keys_loaded = true;
        id_fp = crypto::key_fingerprint(&pub64);
        pub_b64_keep = crypto::b64_encode(&pub64);
        {
            let f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open("hub_public.b64");
            if let Ok(mut f) = f {
                let _ = write!(f, "{pub_b64_keep}");
            }
        }
        // What ssh shows admins on their first login to the console.
        sshfp = irchub::console::ssh_fingerprint(&state.hub_ed25519_pub);
        cli::kv("uuid", &state.hub_uuid);
        cli::kv("public key", &pub_b64_keep);
        cli::kv("fingerprint", &id_fp);
        cli::kv("host key", &format!("ssh-ed25519 {sshfp}"));
        cli::note(&format!(
            "The public key is also in hub_public.b64; the private key never leaves this machine (it is stored encrypted in {HUB_CONFIG_FILE}).  ./irchub -id prints all of this again at any time."
        ));

        // Admin user setup — creates the first a| and m| records.  Admins
        // have no password: the operator generates the admin's keypair on the
        // admin's own machine (keygen <name>) and imports only the PUBLIC key
        // here.  The hub never sees or prints a user's private key.
        step += 1;
        cli::step(step, "First admin");
        cli::note(
            "The first named admin can log in to this hub's SSH console and command bots over IRC.  Admins sign in with a Curve25519 key, not a password: on the admin's own machine run ./keygen <name> (irchub/bin/keygen or ircbot/utils/keygen), keep the <ts>_<name>.private.b64 there (chmod 600) and give the <ts>_<name>.public.b64 here.",
        );
        while admin_name.is_empty() {
            let n = cli::ask("name", 64);
            if cli::eof() {
                break;
            }
            if n.contains(' ') || n.contains('|') {
                cli::err("a name with no spaces or '|' (e.g. admin)");
                continue;
            }
            admin_name = n.to_string();
        }
        if admin_name.is_empty() {
            cli::err("no admin name given: setup stopped");
            return 1;
        }
        let Some(admin_pub_b64) = setup_read_pubkey(&admin_name) else {
            cli::err("no public key given: setup stopped");
            return 1;
        };
        let Some(admin_uuid) = crypto::gen_uuid_v4() else {
            cli::err("RNG failure");
            return 1;
        };
        let t = now();
        state.user_records.push(UserRecord {
            uuid: admin_uuid.clone(),
            name: admin_name.clone(),
            pubkey_b64: admin_pub_b64.clone(),
            has_pubkey: true,
            typ: 'a',
            is_active: true,
            last_seen: 0,
            timestamp: t,
        });

        cli::note(
            "Usermasks the admin is known by on IRC (e.g. nick!*@*.example.com); an empty line ends the list, at least one.",
        );
        let mut masks_added = 0;
        while state.mask_records.len() < MAX_HUB_USER_MASKS {
            let mask = cli::ask(&format!("usermask {}", masks_added + 1), MAX_MASK_LEN);
            if cli::eof() {
                break;
            }
            if mask.is_empty() {
                if masks_added == 0 {
                    cli::err("at least one usermask");
                    continue;
                }
                break;
            }
            if !mask.contains('!') || !mask.contains('@') {
                cli::err("a usermask holds '!' and '@' (nick!user@host)");
                continue;
            }
            state.mask_records.push(MaskRecord {
                uuid: admin_uuid.clone(),
                mask: mask.to_string(),
                is_active: true,
                last_used: 0,
                timestamp: t,
            });
            masks_added += 1;
        }

        // The summary: every answer, and what to paste elsewhere.
        cli::summary("Summary");
        cli::skv("name", &state.hub_friendly_name);
        cli::skv(
            "listening",
            &format!(
                "{}:{}{}",
                state.bind_ip,
                state.port,
                if state.bind_ip == "0.0.0.0" {
                    " (every address)"
                } else {
                    ""
                }
            ),
        );
        cli::skv(
            "public",
            if state.public_ip.is_empty() {
                "(not found)"
            } else {
                &state.public_ip
            },
        );
        cli::skv("uuid", &state.hub_uuid);
        cli::skv("key", &id_fp);
        cli::skv("host key", &format!("ssh-ed25519 {sshfp}"));
        let afp = crypto::pubkey_b64_decode(&admin_pub_b64)
            .map(|r| crypto::key_fingerprint(&r))
            .unwrap_or_else(|| "?".to_string());
        cli::skv(
            "admin",
            &format!("{admin_name} {} key {afp}", cli::g(cli::Glyph::Dot)),
        );
        for (i, m) in state.mask_records.iter().enumerate() {
            cli::skv(if i == 0 { "usermasks" } else { "" }, &m.mask);
        }
        cli::skv(
            "admin login",
            &format!(
                "ssh -i <ts>_{admin_name}_ed25519 -p {} {admin_name}@{}",
                state.port,
                irchub::pubip::dial_address(state).unwrap_or("<this hub>")
            ),
        );
        print_paste_lines(state, &pub_b64_keep);
        cli::rule();
        if cli::ask_yes(&format!("write {HUB_CONFIG_FILE}?"), true) {
            break;
        }
        if cli::eof() {
            return 1;
        }
        cli::note("Starting over.");
        state.hub_ed25519_priv.wipe();
        state.hub_x25519_priv.wipe();
        state.config_pass.wipe();
    }

    config::write(state);
    state.config_pass.wipe();
    state.config_key_forget();
    println!();
    cli::ok(&format!("wrote {HUB_CONFIG_FILE} and hub_public.b64"));
    cli::kv("next", "./irchub -p, then ./irchub");
    cli::note(&format!(
        "-p writes a machine-bound password file, so the hub starts without typing the password; ./irchub alone asks for it.  The admin's SSH key is the <ts>_{admin_name}_ed25519 keygen wrote with the IRC key."
    ));
    println!();
    state.hub_ed25519_priv.wipe();
    state.hub_x25519_priv.wipe();
    0
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

fn accept_one(state: &mut HubState) {
    let Some(listener) = &state.listener else {
        return;
    };
    let Ok((sock, addr)) = listener.accept() else {
        return;
    };
    let incoming_ip = net::peer_ip(&addr);

    if !ratelimit::check_ip_access_lists(state, &incoming_ip) {
        hlog_warning!("[HUB] Connection from {incoming_ip} rejected (access control)\n");
        return;
    }
    if !ratelimit::startup_admit(state, &incoming_ip) {
        return; // logged inside, at most once a minute
    }
    if !ratelimit::is_ip_allowed(state, &incoming_ip) {
        hlog_warning!("[HUB] Connection from {incoming_ip} rejected (rate limit)\n");
        return;
    }
    if state.clients.len() >= MAX_CLIENTS {
        return;
    }
    let fd = {
        use std::os::fd::AsRawFd;
        sock.as_raw_fd()
    };
    // D2: unauthenticated clients get a small buffer; it is grown to the
    // per-type bulk size once the handshake completes.
    let mut c = HubClient::new(sock, fd, &incoming_ip, PREAUTH_BUF_SIZE);
    c.inbound = true;
    c.last_pong_sent = 0;
    // First bytes decide: "SSH-" goes to the console.
    c.sniff_pending = true;
    c.sniff_deadline_ms = now_ms() + CONSOLE_SNIFF_MS;
    state.clients.push(c);
    ratelimit::increment_active_connections(state, &incoming_ip);
    hlog_info!("[HUB] Incoming connect: {incoming_ip}\n");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// First-bytes sniff.  Bot and peer frames start with a 4-byte length;
/// "SSH-" read as one is ~1.4 GB, never valid, so the split is exact.  The
/// bytes are only peeked: the console gets the stream untouched.
fn sniff(state: &mut HubState) {
    let t = now_ms();
    let mut i = 0;
    while i < state.clients.len() {
        let c = &state.clients[i];
        if !c.sniff_pending || c.fd <= 0 {
            i += 1;
            continue;
        }
        let mut head = [0u8; 4];
        let r = nix::sys::socket::recv(
            c.fd,
            &mut head,
            nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        );
        match r {
            Ok(4) => {
                state.clients[i].sniff_pending = false;
                if &head == b"SSH-" {
                    irchub::console::handoff(state, i);
                    continue;
                }
            }
            Ok(0) => {
                auth::disconnect_client(state, i);
                continue;
            }
            Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) | Ok(_) => {
                if t >= c.sniff_deadline_ms {
                    // bot/peer protocol from here
                    state.clients[i].sniff_pending = false;
                }
            }
            Err(_) => {
                auth::disconnect_client(state, i);
                continue;
            }
        }
        i += 1;
    }
}

/// One readable SSH console link: read what the socketpair has.
fn read_console(state: &mut HubState, ci: usize) {
    state.clients[ci].compact_recv();
    let space = state.clients[ci]
        .recv_cap
        .saturating_sub(state.clients[ci].recv_buf.len());
    let r = {
        let c = &mut state.clients[ci];
        let Some(l) = c.console.as_mut() else { return };
        let mut chunk = vec![0u8; space.min(64 * 1024)];
        match std::io::Read::read(&mut l.stream, &mut chunk) {
            Ok(n) => {
                c.recv_buf.extend_from_slice(&chunk[..n]);
                Ok(n)
            }
            Err(e) => Err(e),
        }
    };
    match r {
        Ok(0) if space > 0 => {
            auth::disconnect_client(state, ci);
            return;
        }
        Ok(_) => state.clients[ci].last_seen = now(),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(_) => {
            auth::disconnect_client(state, ci);
            return;
        }
    }
    client::handle_client_data(state, ci);
}

/// One readable client: fill its buffer, then hand whole frames to the pump.
fn read_one(state: &mut HubState, fd: i32) {
    let Some(ci) = state.client_by_fd(fd) else {
        return;
    };
    if state.clients[ci].internal {
        read_console(state, ci);
        return;
    }
    state.clients[ci].compact_recv();
    let space = state.clients[ci]
        .recv_cap
        .saturating_sub(state.clients[ci].recv_buf.len());

    if space > 0 {
        let n = {
            let c = &mut state.clients[ci];
            let Some(sock) = &mut c.sock else { return };
            let mut buf = std::mem::take(&mut c.recv_buf);
            let r = net::read_into(sock, &mut buf, space);
            c.recv_buf = buf;
            r
        };
        match n {
            Ok(0) | Err(_) => {
                auth::disconnect_client(state, ci);
                return;
            }
            Ok(_) => state.clients[ci].last_seen = now(),
        }
    } else if !state.clients[ci].has_buffered_frame() {
        // A full buffer with no whole frame in it cannot happen with a valid
        // length prefix, so the stream is bad.
        hlog_warning!("[HUB] Buffer overflow {}\n", state.clients[ci].ip);
        auth::disconnect_client(state, ci);
        return;
    }
    // A full buffer that still holds whole frames is not an overflow: handle
    // them and read the rest next pass.
    client::handle_client_data(state, ci);
}

fn run(mut state: HubState, password: Zeroizing<String>, stop: &Arc<AtomicBool>) -> i32 {
    // The config password must be in place BEFORE the load: config::load
    // rewrites the file itself when it dedups or migrates records (the
    // passwordless migration drops every password on the first start), and
    // that write reads the stored password — unset, it would re-encrypt the
    // config under an empty password and lock the hub out on the next start.
    state.set_config_pass(&password);
    if !config::load(&mut state, &password) {
        state.config_pass.wipe();
        state.config_key_forget();
        println!("Config load failed. Run -setup.");
        hlog_error!("[HUB] Config load failed.\n");
        let _ = fs::remove_file(HUB_PID_FILE);
        return 1;
    }
    irchub::uhist::boot(&mut state);
    irchub::upgrade::plan_boot(&mut state);
    irchub::access::sgrant_once(&mut state); // 2.5.4: +b admins get +s, once per mesh
    irchub::presence2::init(&mut state); // bumps the boot counter: after the config gave us our uuid
    drop(password);
    logging::set_levels(state.log_level, state.console_log_level);
    logging::set_max_size(state.log_max_size);

    // Ensure next_lamport_seq is above the time-based floor even on the first
    // boot (when no lamport_seq key exists in the config).
    let time_floor = (now() as u64) << 10;
    if state.next_lamport_seq < time_floor {
        state.next_lamport_seq = time_floor;
    }

    if state.bind_ip.is_empty() {
        state.bind_ip = "127.0.0.1".to_string();
    }

    if !state.hub_keys_loaded {
        hlog_error!("No Curve25519 keypair in config. Re-run -setup.\n");
        return 1;
    }

    // Per-hub independent keypairs: peers without a registered pubkey are
    // refused at handshake time — the operator must add each peer with its
    // own pubkey via the console.
    let peerless = state.peers.iter().filter(|p| !p.has_pubkey).count();
    if peerless > 0 {
        hlog_warning!(
            "[HUB] {peerless} peer(s) lack a Curve25519 pubkey and will be refused on connect. Re-add them with the key ./irchub -id prints on that hub (console: hub add / hub set <hub> key).\n"
        );
    }

    hlog_info!(
        "[HUB] Started on port {} (PID: {})\n",
        state.port,
        std::process::id()
    );

    let addr: SocketAddr = match net::bind_addr(&state.bind_ip, state.port) {
        Ok(a) => {
            if a.ip().is_unspecified() {
                hlog_info!("[HUB] Binding to 0.0.0.0:{} (all interfaces)\n", state.port);
            } else {
                hlog_info!("[HUB] Binding to {}:{}\n", state.bind_ip, state.port);
            }
            a
        }
        Err(fallback) => {
            hlog_error!("Invalid bind_ip: {}, using 0.0.0.0\n", state.bind_ip);
            fallback
        }
    };
    match net::listen_on(addr) {
        Ok(l) => {
            state.listener = Some(l);
            state.listen_ip = addr.ip().to_string();
            state.listen_port = state.port;
        }
        Err(_) => {
            hlog_error!("Bind failed\n");
            return 1;
        }
    }

    storage::init();

    // The SSH admin console (docs/console.md) shares this port: its thread
    // starts before the first accept.  A hub whose console cannot start still
    // serves its bots and peers, but no admin can reach it.
    if !irchub::console::start(&mut state) {
        hlog_error!(
            "[CONSOLE] SSH console unavailable — no admin access to this hub until it restarts\n"
        );
    }

    while state.running && !stop.load(Ordering::Relaxed) {
        check_peers(&mut state);
        maintenance(&mut state);

        // Frames already read but not yet handled (the pump's 8-per-call
        // cap): poll instead of sleeping, so they are handled this pass.
        let buffered = state.clients.iter().any(HubClient::has_buffered_frame);
        let sniffing = state.clients.iter().any(|c| c.sniff_pending);
        let timeout_ms: u16 = if buffered {
            0
        } else if sniffing {
            10
        } else {
            250
        };

        let (listener_ready, wake_ready, ready) = {
            let Some(listener) = &state.listener else {
                break;
            };
            let mut watches = vec![net::watch_listener(listener)];
            if let Some(core) = &state.console {
                watches.push(net::Watch {
                    fd: std::os::fd::AsFd::as_fd(&core.wake),
                    write: false,
                });
            }
            let wake_slot = state.console.is_some();
            let mut fds = Vec::with_capacity(state.clients.len());
            for c in &state.clients {
                // Not read until its first bytes are known (see sniff()).
                if c.sniff_pending {
                    continue;
                }
                if let Some(l) = &c.console {
                    watches.push(net::Watch {
                        fd: std::os::fd::AsFd::as_fd(&l.stream),
                        write: l.has_pending(),
                    });
                    fds.push(c.fd);
                    continue;
                }
                if c.fd > 0
                    && let Some(s) = &c.sock
                {
                    // Only watch writability when the per-peer queue or the
                    // in-flight cipher buffer has bytes pending.  Otherwise
                    // poll would return writable for every idle socket and
                    // burn CPU — exactly the failure mode docs/cpu.md warned
                    // about.
                    watches.push(net::watch(s, c.dialing || c.has_pending_writes()));
                    fds.push(c.fd);
                }
            }
            let r = net::poll_fds(&watches, timeout_ms);
            let lr = r[0].0;
            let wr = wake_slot && r[1].0;
            let skip = if wake_slot { 2 } else { 1 };
            let ready: Vec<(i32, bool, bool)> = fds
                .into_iter()
                .zip(r.into_iter().skip(skip))
                .map(|(f, (rd, wr))| (f, rd, wr))
                .collect();
            (lr, wr, ready)
        };

        // Dials whose connect finished (or timed out) first: a finished one
        // is a peer whose handshake goes out now.  What is still dialing is
        // left out of the passes below.
        finish_dials(&mut state, &ready);
        let ready: Vec<(i32, bool, bool)> = ready
            .into_iter()
            .filter(|&(fd, _, _)| {
                state
                    .client_by_fd(fd)
                    .is_some_and(|ci| !state.clients[ci].dialing)
            })
            .collect();

        // Drain writable peers FIRST.  This keeps URGENT op-flow traffic
        // prompt and prevents queues from accumulating across the read pass,
        // which can itself enqueue more outbound traffic.
        for &(fd, _, writable) in &ready {
            if writable && let Some(ci) = state.client_by_fd(fd) {
                queue::drain_writable(&mut state.clients[ci]);
            }
        }

        if listener_ready {
            accept_one(&mut state);
        }
        if wake_ready {
            irchub::console::on_wake(&mut state);
        }
        if sniffing {
            sniff(&mut state);
        }

        for &(fd, readable, _) in &ready {
            if readable {
                read_one(&mut state, fd);
            } else if state
                .client_by_fd(fd)
                .is_some_and(|ci| state.clients[ci].has_buffered_frame())
            {
                // Nothing new on the socket, but frames left over from an
                // earlier read: without this they wait for the sender's next
                // packet (a burst of peer records took minutes).
                if let Some(ci) = state.client_by_fd(fd) {
                    client::handle_client_data(&mut state, ci);
                }
            }
        }

        // Events and log lines for the SSH consoles.
        irchub::console::tick(&mut state);
    }

    // Shutdown.  The locked pid file is what says "this hub is running" (to
    // tooling, and to a second copy's single-instance check), so it goes
    // last: first the port and every link close and acknowledged changes
    // still inside the write debounce reach the config, then the file is
    // unlinked while still locked, then the lock is released.  Dropping it
    // first let an immediate restart find the port still bound.
    let sig = if stop.load(Ordering::Relaxed) { 1 } else { 0 };
    hlog_info!("[HUB] Shutting down (signal {sig}).\n");
    irchub::update::stage_kill_build(); // a stage's build does not outlive the hub
    state.listener = None;
    while !state.clients.is_empty() {
        let last = state.clients.len() - 1;
        auth::disconnect_client(&mut state, last);
    }
    irchub::console::stop(&mut state);
    if state.config_dirty {
        config::write(&mut state);
        state.config_dirty = false;
    }

    state.hub_ed25519_priv.wipe();
    state.hub_x25519_priv.wipe();
    state.config_pass.wipe();
    state.config_key_forget();

    let _ = fs::remove_file(HUB_PID_FILE);
    state.pid_file = None;
    logging::close();
    0
}

/// `irchub -selftest`: prints `selftest: OK irchub <version> <variant>` and
/// returns 0, or `selftest: FAIL <reason>` and 1.  Never writes the config
/// (config::READ_ONLY): the running build still owns it.
fn selftest() -> i32 {
    let fail = |why: &str| {
        println!("selftest: FAIL {why}");
        1
    };
    if let Some(f) = irchub::update::tls_cpu_missing() {
        return fail(&format!(
            "this CPU lacks {f}, which the Rust build's TLS needs — use the C build"
        ));
    }
    // The swap happens in this directory: one another user owns is refused at start (a
    // group/other-writable one we own is tightened there).
    if !fs::metadata(".").is_ok_and(|m| m.uid() == nix::unistd::geteuid().as_raw()) {
        return fail("this directory is not owned by this user");
    }
    if fs::metadata(HUB_CONFIG_FILE).is_err() {
        return fail(&format!("no {HUB_CONFIG_FILE}"));
    }
    // 2.5.1 reads only the 600k key; a pass file 2.5.0 never got to rewrite
    // is refused here so the upgrade reports it instead of leaving a hub that
    // cannot start.
    let password = match passfile_load(HUB_PASS_FILE) {
        Some(p) if !p.is_empty() => p,
        _ => {
            return fail(&format!(
                "cannot read {HUB_PASS_FILE} (written before 2.5.0? restart once on 2.5.0, or rewrite it with -p)"
            ));
        }
    };
    let mut state = HubState::new();
    state.log_level = HUB_DEFAULT_LOG_LEVEL;
    state.log_max_size = HUB_LOG_FILE_SIZE;
    config::READ_ONLY.store(true, std::sync::atomic::Ordering::Relaxed);
    state.set_config_pass(&password);
    let ok = config::load(&mut state, &password);
    state.config_pass.wipe();
    state.config_key_forget();
    if !ok {
        return fail("the config did not load (see the log)");
    }
    println!(
        "selftest: OK irchub {HUB_VERSION} {}",
        irchub::update::host_variant()
    );
    0
}

/// `irchub -id`: print this hub's name, uuid, public key and fingerprints —
/// what another hub's `hub add` and a bot's -setup / +hub need — from the
/// config (the key lives there; hub_public.b64 is only -setup's copy), and
/// exit.  Read-only: no daemon, no PID lock, no config rewrite.
fn identity(password: Zeroizing<String>) -> i32 {
    let mut state = HubState::new();
    state.log_level = HUB_DEFAULT_LOG_LEVEL;
    state.log_max_size = HUB_LOG_FILE_SIZE;
    config::READ_ONLY.store(true, std::sync::atomic::Ordering::Relaxed);
    state.set_config_pass(&password);
    let ok = config::load(&mut state, &password);
    drop(password);
    state.config_pass.wipe();
    state.config_key_forget();
    // The public key is derived from the private key, not taken from the
    // stored pub| copy: that is what peers and bots must pin.
    let pub64 = (ok && state.hub_keys_loaded)
        .then(|| crypto::combined_pub_from_priv(&state.hub_priv_combined()));
    state.hub_ed25519_priv.wipe();
    state.hub_x25519_priv.wipe();
    if !ok {
        eprintln!("Cannot load {HUB_CONFIG_FILE} (wrong password?).");
        return 1;
    }
    let Some(pub64) = pub64.filter(|_| !state.hub_uuid.is_empty()) else {
        eprintln!("{HUB_CONFIG_FILE} has no hub key or uuid; re-run -setup.");
        return 1;
    };
    if pub64[..32] != state.hub_ed25519_pub || pub64[32..] != state.hub_x25519_pub {
        eprintln!(
            "Note: the stored public key does not match the private key; the key below is the right one (console: hub set pubkey)."
        );
    }
    let pub_b64 = crypto::b64_encode(&pub64);
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&pub64[..32]);
    let wild = state.bind_ip.is_empty() || state.bind_ip == "0.0.0.0";
    let name = if state.hub_friendly_name.is_empty() {
        "-"
    } else {
        state.hub_friendly_name.as_str()
    };
    cli::header("irchub", HUB_VERSION, "identity");
    println!();
    cli::skv("name", name);
    cli::skv("uuid", &state.hub_uuid);
    cli::skv(
        "listening",
        &format!(
            "{}:{}",
            if wild {
                "0.0.0.0"
            } else {
                state.bind_ip.as_str()
            },
            state.port
        ),
    );
    // -id is offline and read-only: the address the running hub last looked up
    cli::skv(
        "public",
        if state.public_ip.is_empty() {
            "(not looked up yet)"
        } else {
            &state.public_ip
        },
    );
    cli::skv("public key", &pub_b64);
    cli::skv("fingerprint", &crypto::key_fingerprint(&pub64));
    cli::skv(
        "host key",
        &format!("ssh-ed25519 {}", irchub::console::ssh_fingerprint(&ed)),
    );
    print_paste_lines(&state, &pub_b64);
    cli::rule();
    0
}

fn main() {
    tool::harden_process();
    logging::install_panic_hook();

    // The C hub tuned glibc's mallopt() here: each accepted connection
    // allocated a ~33 KB hub_client_t, and glibc kept freed chunks of that
    // size in the arena, so a connect/close flood grew RSS even though the
    // structs were freed.  Rust's allocator returns large blocks to the OS on
    // free, and `HubClient` no longer carries fixed 33 KB buffers (the recv
    // and writing buffers are `Vec`s sized to what is actually in flight), so
    // there is nothing to tune.

    let args: Vec<String> = std::env::args().collect();
    // -checkupdate [variant]: verify the release channel and exit; needs no
    // config, no password and no PID lock.
    if let Some(i) = args.iter().skip(1).position(|a| a == "-checkupdate") {
        std::process::exit(irchub::update::check_cli(
            args.get(i + 2).map(String::as_str),
        ));
    }
    // -selftest: could this build run here?  Loads the config exactly as a
    // start would, then exits — no daemon, no PID lock, no network.  A hub-
    // driven upgrade runs the staged new build with it before swapping.
    if args.iter().skip(1).any(|a| a == "-selftest") {
        std::process::exit(selftest());
    }
    // -selftest (above) stays in the caller's directory: the updater runs a
    // staged build from a scratch subdirectory, against this hub's config.
    let Some(self_exe) = instance_dir_enter() else {
        std::process::exit(1)
    };
    let setup_mode = args.iter().skip(1).any(|a| a == "-setup");
    let passfile_mode = args.iter().skip(1).any(|a| a == "-p");
    let identity_mode = args.iter().skip(1).any(|a| a == "-id");

    let mut state = HubState::new();
    state.log_level = HUB_DEFAULT_LOG_LEVEL;
    state.log_max_size = HUB_LOG_FILE_SIZE;
    // The console log ring lives in its own mlock'd, MADV_DONTDUMP mapping
    // (console/mod.rs); allocated before the first line is logged.
    irchub::console::log_ring_init();
    logging::attach(state.log_level, state.console_log_level, state.log_max_size);

    if setup_mode {
        std::process::exit(run_setup(&mut state));
    }

    // -p: create/replace .irchub.pass from an interactive password prompt.
    if passfile_mode {
        cli::header("irchub", HUB_VERSION, "password file");
        cli::note(&format!(
            "{HUB_PASS_FILE} holds the config password, bound to this machine, so the hub starts without typing it."
        ));
        println!();
        let pass = loop {
            let p1 = cli::ask_secret("password", MAX_PASS);
            if p1.is_empty() {
                cli::err("the password cannot be empty");
                std::process::exit(1);
            }
            let p2 = cli::ask_secret("confirm", MAX_PASS);
            if *p1 == *p2 {
                break p1;
            }
            cli::err("the passwords do not match: again");
        };
        if passfile_create(HUB_PASS_FILE, &pass) {
            cli::ok(&format!(
                "wrote {HUB_PASS_FILE} (0600, bound to this machine)"
            ));
            cli::kv("next", "./irchub");
            println!();
            return;
        }
        cli::err(&format!("could not write {HUB_PASS_FILE}"));
        std::process::exit(1);
    }

    // Refuse to proceed without a config — it avoids prompting into a dead
    // end.
    if fs::metadata(HUB_CONFIG_FILE).is_err() {
        eprintln!("No config file found. First run: ./irchub -setup");
        std::process::exit(1);
    }

    // Password resolution: .irchub.pass, then the stdin prompt.
    let password = match passfile_load(HUB_PASS_FILE) {
        Some(p) if !p.is_empty() => p,
        _ => {
            let p = tool::read_pass_hidden("Config Password: ", MAX_PASS);
            if p.is_empty() {
                eprintln!("No password provided.");
                std::process::exit(1);
            }
            p
        }
    };

    if identity_mode {
        std::process::exit(identity(password));
    }

    if irchub::update::install_in_progress() {
        eprintln!("An upgrade is installing here; not starting");
        return;
    }
    irchub::update::stage_boot_clean();
    daemonize();

    // A stop signal sets the flag; the poll loop notices within its 250 ms
    // tick and main() shuts down in order.  The handler does nothing else:
    // stdio, unlink and exit() from a handler are unsafe (the signal can land
    // inside an allocation or a log write), and exiting there skipped the
    // pending config write and the secret wipes.
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }

    // The binary an upgrade replaces, and the one <exe>.prev sits beside
    // (resolved by instance_dir_enter() at startup).
    state.executable_path = self_exe;

    let Some(pid_file) = lock_pid_file() else {
        hlog_error!("Hub already running (PID file locked)\n");
        std::process::exit(1);
    };
    state.pid_file = Some(pid_file);

    std::process::exit(run(state, password, &stop));
}
