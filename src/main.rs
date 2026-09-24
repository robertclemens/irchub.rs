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

use irchub::consts::*;
use irchub::cstr::{now, trunc_string};
use irchub::state::{ClientType, HubClient, HubState, MaskRecord, UserRecord, name_valid};
use irchub::state::{Lane, QueuedMsg};
use irchub::{
    auth, client, config, crypto, hlog_debug, hlog_error, hlog_info, hlog_status, hlog_warning,
    logging, mesh, net, presence, queue, ratelimit, storage, tool, upgrade,
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

    let key = crypto::derive_config_key(passfile_context().as_bytes(), salt);
    match crypto::aes_gcm_decrypt(enc_blk, key.as_ref(), tag) {
        Some(plain) => Some(Zeroizing::new(String::from_utf8_lossy(&plain).into_owned())),
        None => {
            eprintln!(
                "[WARN] {path}: decryption failed (wrong machine or tampered file), falling through."
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
    let key = crypto::derive_config_key(passfile_context().as_bytes(), &salt);
    let Some((enc_buf, tag)) = crypto::aes_gcm_encrypt(password.as_bytes(), key.as_ref()) else {
        eprintln!("Encryption failed.");
        return false;
    };
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path);
    let Ok(mut f) = f else {
        eprintln!("open {path} failed.");
        return false;
    };
    if f.set_permissions(fs::Permissions::from_mode(0o600))
        .is_err()
    {
        eprintln!("chmod {path} failed.");
        return false;
    }
    let ok =
        f.write_all(&salt).is_ok() && f.write_all(&enc_buf).is_ok() && f.write_all(&tag).is_ok();
    if !ok {
        eprintln!("write {path} failed.");
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
    // If this process is the product of an upgrade a peer drove, close that
    // run out now that there is a peer to tell (no-op otherwise).
    upgrade::report_pending(state, ci);

    // Send a full config sync immediately via the BULK queue.  The queue
    // enforces a per-peer byte budget (BULK_SOFT_BUDGET_BPS) so the
    // simultaneous startup of every hub no longer creates a cascade that
    // fills socket buffers; each hub's BULK drain is naturally staggered by
    // the poll cycle.  This replaces deferring the first sync to
    // anti-entropy (up to a 90 s wait).
    let full_sync = mesh::generate_sync_packet(state);
    if full_sync.is_empty() {
        return;
    }
    let Some(mut m) = QueuedMsg::new(CMD_PEER_SYNC, Lane::Bulk, full_sync.as_bytes()) else {
        return;
    };
    let seq = state.next_lamport_seq();
    let hub_uuid = state.hub_uuid.clone();
    m.set_coalesce(&hub_uuid, seq, "handshake_sync");
    if !queue::enqueue(&mut state.clients[ci], m) {
        hlog_warning!(
            "[PEER] Could not queue initial sync to {}\n",
            state.clients[ci].ip
        );
    }
}

/// hub_check_peers(): reconnect to any peer we are not linked to.
fn check_peers(state: &mut HubState) {
    let t = now();
    if t - state.timers.last_peer_check < PEER_RECONNECT_INTERVAL {
        return;
    }
    state.timers.last_peer_check = t;

    for pi in 0..state.peers.len() {
        if state.peers[pi].connected {
            continue;
        }
        let (ip, port) = (state.peers[pi].ip.clone(), state.peers[pi].port);
        hlog_debug!("[PEER] Attempting to connect to {ip}:{port}...\n");
        let Ok(sock) = net::connect_peer(&ip, port) else {
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
        c.last_pong_sent = 0;
        state.clients.push(c);
        let ci = state.clients.len() - 1;

        state.peers[pi].connected = true;
        state.peers[pi].fd = fd;
        state.mesh_state_dirty = true;
        peer_handshake(state, ci, pi);
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
    if state.timers.last_status_dump == 0 {
        state.timers.last_status_dump = t;
    }

    // Bot presence: gossip our own bots to the peers, expire entries nobody
    // refreshed, and push the tree to bots when it changed.  All volatile.
    presence::presence_tick(state, t);

    // Rolling network upgrade: one step per tick (no-op unless running).
    upgrade::tick(state, t);

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
    let forced_ae = state.anti_entropy_due;
    if forced_ae || t - state.timers.last_anti_entropy > MESH_ANTI_ENTROPY_INTERVAL {
        state.timers.last_anti_entropy = t;
        state.anti_entropy_due = false;
        if !state.peers.is_empty() {
            hlog_debug!(
                "[MESH] Running {}anti-entropy sync...\n",
                if forced_ae { "forced " } else { "periodic " }
            );
            let full_sync = mesh::generate_sync_packet(state);
            mesh::broadcast_sync_to_peers(state, &full_sync, -1);
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
            if mesh::should_initiate_scheduled_purge(state) {
                hlog_info!(
                    "[HUB] Running scheduled purge (older than {} days)\n",
                    state.purge_days_setting
                );
                let cutoff = t - i64::from(state.purge_days_setting) * 86400;
                let (purged, _) = mesh::execute_purge(state, cutoff);
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
            if t - c.last_seen > CLIENT_TIMEOUT {
                hlog_warning!("[HUB] Client {} timed out.\n", c.ip);
                auth::disconnect_client(state, i);
                continue;
            }
            // D4: reap connections that never authenticated within the
            // pre-auth window.  Uses connected_at (not last_seen) so a
            // slowloris that dribbles bytes to keep last_seen fresh is still
            // dropped.  Outbound CLIENT_HUB peers are trusted,
            // operator-configured endpoints and are exempt.
            //
            // D4b: a connection that spoke ADMIN-HELLO is an interactive
            // admin login gated on manual entry — give it a longer grace
            // window.  Everything else keeps the strict one.
            let preauth_window = if c.admin_hello_seen {
                PREAUTH_ADMIN_TIMEOUT_SEC
            } else {
                PREAUTH_TIMEOUT_SEC
            };
            if !c.authenticated && c.typ != ClientType::Hub && t - c.connected_at > preauth_window {
                hlog_warning!(
                    "[HUB] Pre-auth timeout for {} ({}s, no handshake{}) — dropping\n",
                    c.ip,
                    t - c.connected_at,
                    if c.admin_hello_seen { ", admin" } else { "" }
                );
                auth::disconnect_client(state, i);
                continue;
            }
            if c.authenticated && t - c.last_seen > PING_INTERVAL {
                let ip = c.ip.clone();
                if !client::send_ping(&mut state.clients[i]) {
                    hlog_warning!("Ping failed to {ip}. Disconnecting.\n");
                    auth::disconnect_client(state, i);
                    continue;
                }
            }
            i += 1;
        }
    }

    // Periodic status dump: every 60 s at INFO level.  One line showing every
    // timer countdown and the current load, so idle churn is visible without
    // having to stare at top/perf.
    if t - state.timers.last_status_dump >= 60 {
        state.timers.last_status_dump = t;
        let mut bot_count = 0;
        let mut peer_count = 0;
        let mut authing_count = 0;
        for c in &state.clients {
            match (c.typ, c.authenticated) {
                (ClientType::Bot, true) => bot_count += 1,
                (ClientType::Hub, true) => peer_count += 1,
                _ => authing_count += 1,
            }
        }
        let gossip_in = (300 - (t - state.timers.last_mesh_gossip)).max(0);
        let entropy_in = (MESH_ANTI_ENTROPY_INTERVAL - (t - state.timers.last_anti_entropy)).max(0);
        let scan_in = (5 - (t - state.timers.last_client_scan)).max(0);
        let ipcln_in = (300 - (t - state.timers.last_ip_cleanup)).max(0);
        let peer_chk_in = PEER_RECONNECT_INTERVAL; // approximate
        let head = format!(
            "clients={}(bots={bot_count} peers={peer_count} authing={authing_count}) dirty={} gossip_in={gossip_in}s entropy_in={entropy_in}s scan_in={scan_in}s ipcln_in={ipcln_in}s peer_chk_in={peer_chk_in}s",
            state.clients.len(),
            i32::from(state.config_dirty)
        );
        if state.purge_days_setting > 0 && state.timers.last_purge > 0 {
            let purge_in = 86400 - (t - state.timers.last_purge);
            hlog_status!("{head} purge_in={purge_in}s\n");
        } else {
            hlog_status!("{head} purge=off\n");
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
        let input = tool::prompt_line(
            &format!("Public key for '{who}' (paste the 88 chars, or a path to the .public.b64): "),
            4096,
        );
        if input.is_empty() {
            println!("A public key is required (run ./keygen {who} on the admin's machine).");
            continue;
        }
        // Private and public key files have the same shape; refuse a keygen
        // private file by name before it gets published in the a| record.
        if input.contains(".private.") {
            println!(
                "That is a PRIVATE key file — it stays with the admin. Use the matching .public.b64."
            );
            continue;
        }
        let key = match crypto::pubkey_b64_decode(&input) {
            Some(raw) => Some((input.clone(), raw)),
            None => {
                let from_file = fs::read_to_string(&input).ok();
                let line = from_file
                    .as_ref()
                    .and_then(|s| s.lines().next())
                    .map(|l| l.trim_end_matches([' ', '\t', '\r', '\n']).to_string());
                match line
                    .as_deref()
                    .and_then(|l| crypto::pubkey_b64_decode(l).map(|r| (l.to_string(), r)))
                {
                    Some(v) => Some(v),
                    None => {
                        println!(
                            "Not an 88-char public key{}. Use the .public.b64 — never the .private.b64.",
                            if from_file.is_some() {
                                " in that file"
                            } else {
                                ""
                            }
                        );
                        None
                    }
                }
            }
        };
        let Some((b64, raw)) = key else { continue };
        let yn = tool::prompt_line(
            &format!(
                "  Key fingerprint: {} — use this key? (Y/n): ",
                crypto::key_fingerprint(&raw)
            ),
            16,
        );
        if !yn.starts_with('n') && !yn.starts_with('N') {
            return Some(b64);
        }
    }
}

fn run_setup(state: &mut HubState) -> i32 {
    println!("--- Setup ---");

    let port = tool::prompt_line("Port: ", 32);
    state.port = irchub::cstr::atoi(&port);

    let bind = tool::prompt_line("Bind IP (default 0.0.0.0): ", 65);
    state.bind_ip = if bind.is_empty() {
        "0.0.0.0".to_string()
    } else {
        trunc_string(&bind, 64)
    };

    loop {
        let name = tool::prompt_line("Friendly Name (A-Z a-z 0-9 . _ -, max 63): ", 128);
        if name_valid(&name) {
            state.hub_friendly_name = name;
            break;
        }
        if name.is_empty() {
            eprintln!("No hub name given.");
            return 1;
        }
        println!(
            "Invalid name: it is written into config lines and peer handshakes, so 1-63 letters, digits, '.', '_' or '-'."
        );
    }

    let Some(uuid) = crypto::gen_uuid_v4() else {
        eprintln!("RNG failure.");
        return 1;
    };
    state.hub_uuid = uuid;
    println!("Generated UUID: {}", state.hub_uuid);

    loop {
        let p1 = tool::read_pass_hidden("Config Password: ", MAX_PASS);
        if p1.is_empty() {
            println!("Password cannot be empty.");
            continue;
        }
        let p2 = tool::read_pass_hidden("Confirm Config Password: ", MAX_PASS);
        if *p1 != *p2 {
            println!("Passwords do not match. Try again.");
            continue;
        }
        state.set_config_pass(&p1);
        break;
    }

    // Per-hub independent keypair (no shared-keypair mesh).  Generate fresh
    // and export only the public key; the private key stays inside the
    // encrypted config — no plaintext hub_private.b64 file is dumped.
    println!("\n[*] Generating per-hub Curve25519 keypair (Ed25519 + X25519)...");
    let Some((priv64, pub64)) = crypto::generate_combined_keypair() else {
        println!("Key generation failed.");
        return 1;
    };
    state.set_hub_priv(&priv64);
    state.set_hub_pub(&pub64);
    state.hub_keys_loaded = true;
    let pub_b64 = crypto::b64_encode(&pub64);
    {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open("hub_public.b64");
        if let Ok(mut f) = f {
            let _ = write!(f, "{pub_b64}");
        }
    }
    println!("[+] Public key saved to: hub_public.b64");
    println!("[+] Public key: {pub_b64}\n");
    println!("    ┌─────────────────────────────────────────────────┐");
    println!("    │ Save this public key + this hub's UUID.         │");
    println!("    │   - Bots adding this hub will need both         │");
    println!("    │     (ircbot -setup prompts for UUID + pubkey).  │");
    println!("    │   - Peer hubs adding this hub will need the     │");
    println!("    │     UUID + ip:port + pubkey via hub_admin.      │");
    println!("    │ The hub's PRIVATE key never leaves this machine │");
    println!("    │ (stored encrypted inside .irchub.cnf).          │");
    println!("    └─────────────────────────────────────────────────┘");
    println!("[+] Curve25519 keypair generated.");

    // Admin user setup — creates the first a| and m| records.  Admins have no
    // password: the operator generates the admin's keypair on the admin's own
    // machine (keygen <name>) and imports only the PUBLIC key here.  The hub
    // never sees or prints a user's private key.
    println!("\n--- First Admin Setup ---");
    println!("This creates the first named admin, who can log into hub_admin");
    println!("and command bots over IRC. Admins sign in with a Curve25519 key,");
    println!("not a password: on the admin's own machine run");
    println!("    ./keygen <name>      (irchub/bin/keygen or ircbot/utils/keygen)");
    println!("keep the <ts>_<name>.private.b64 there (chmod 600), and give this");
    println!("wizard the <ts>_<name>.public.b64.\n");

    let mut admin_name = String::new();
    while admin_name.is_empty() {
        let n = tool::prompt_line("Admin friendly name (no spaces, e.g. robert): ", 64);
        if n.is_empty() {
            break;
        }
        if n.contains(' ') || n.contains('|') {
            println!("Name cannot contain spaces or '|'. Try again.");
            continue;
        }
        admin_name = n;
    }
    if admin_name.is_empty() {
        eprintln!("No admin name given; setup aborted.");
        return 1;
    }

    let Some(admin_pub_b64) = setup_read_pubkey(&admin_name) else {
        eprintln!("No public key given; setup aborted.");
        return 1;
    };

    let Some(new_uuid) = crypto::gen_uuid_v4() else {
        eprintln!("RNG failure.");
        return 1;
    };
    let t = now();
    state.user_records.push(UserRecord {
        uuid: new_uuid.clone(),
        name: admin_name.clone(),
        pubkey_b64: admin_pub_b64,
        has_pubkey: true,
        typ: 'a',
        is_active: true,
        last_seen: 0,
        timestamp: t,
    });

    let mut masks_added = 0;
    println!("\nEnter usermasks for this admin (e.g. nick!*@*.example.com).");
    println!("Press Enter with no mask when done (at least one required).\n");
    while state.mask_records.len() < MAX_HUB_USER_MASKS {
        let mask = tool::prompt_line(
            &format!(
                "Usermask {}{}: ",
                masks_added + 1,
                if masks_added == 0 {
                    " (required)"
                } else {
                    " (or Enter to finish)"
                }
            ),
            MAX_MASK_LEN,
        );
        if mask.is_empty() {
            if masks_added == 0 {
                println!("At least one usermask is required.");
                continue;
            }
            break;
        }
        if !mask.contains('!') || !mask.contains('@') {
            println!("Invalid — mask must contain '!' and '@'. Try again.");
            continue;
        }
        state.mask_records.push(MaskRecord {
            uuid: new_uuid.clone(),
            mask,
            is_active: true,
            last_used: 0,
            timestamp: t,
        });
        masks_added += 1;
    }

    println!("[+] Admin '{admin_name}' created with {masks_added} usermask(s), UUID {new_uuid}");
    println!("    Log in with:  ./hub_admin <ip> <port> <its .private.b64>");

    config::write(state);
    state.config_pass.wipe();
    println!("Done.");
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
    state.clients.push(c);
    ratelimit::increment_active_connections(state, &incoming_ip);
    hlog_info!("[HUB] Incoming connect: {incoming_ip}\n");
}

/// One readable client: fill its buffer, then hand whole frames to the pump.
fn read_one(state: &mut HubState, fd: i32) {
    let Some(ci) = state.client_by_fd(fd) else {
        return;
    };
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
        println!("Config load failed. Run -setup.");
        hlog_error!("[HUB] Config load failed.\n");
        let _ = fs::remove_file(HUB_PID_FILE);
        return 1;
    }
    drop(password);
    logging::set_level(state.log_level);
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
    // own pubkey via hub_admin.
    let peerless = state.peers.iter().filter(|p| !p.has_pubkey).count();
    if peerless > 0 {
        hlog_warning!(
            "[HUB] {peerless} peer(s) lack a Curve25519 pubkey and will be refused on connect. Re-add them with their hub_public.b64 via hub_admin (Add Peer / Set Peer Pubkey).\n"
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
        Ok(l) => state.listener = Some(l),
        Err(_) => {
            hlog_error!("Bind failed\n");
            return 1;
        }
    }

    storage::init();

    while state.running && !stop.load(Ordering::Relaxed) {
        check_peers(&mut state);
        maintenance(&mut state);

        // Frames already read but not yet handled (the pump's 8-per-call
        // cap): poll instead of sleeping, so they are handled this pass.
        let buffered = state.clients.iter().any(HubClient::has_buffered_frame);
        let timeout_ms: u16 = if buffered { 0 } else { 250 };

        let (listener_ready, ready) = {
            let Some(listener) = &state.listener else {
                break;
            };
            let mut watches = vec![net::watch_listener(listener)];
            let mut fds = Vec::with_capacity(state.clients.len());
            for c in &state.clients {
                if c.fd > 0
                    && let Some(s) = &c.sock
                {
                    // Only watch writability when the per-peer queue or the
                    // in-flight cipher buffer has bytes pending.  Otherwise
                    // poll would return writable for every idle socket and
                    // burn CPU — exactly the failure mode docs/cpu.md warned
                    // about.
                    watches.push(net::watch(s, c.has_pending_writes()));
                    fds.push(c.fd);
                }
            }
            let r = net::poll_fds(&watches, timeout_ms);
            let lr = r[0].0;
            let ready: Vec<(i32, bool, bool)> = fds
                .into_iter()
                .zip(r.into_iter().skip(1))
                .map(|(f, (rd, wr))| (f, rd, wr))
                .collect();
            (lr, ready)
        };

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
    }

    // Shutdown.  The locked pid file is what says "this hub is running" (to
    // tooling, and to a second copy's single-instance check), so it goes
    // last: first the port and every link close and acknowledged changes
    // still inside the write debounce reach the config, then the file is
    // unlinked while still locked, then the lock is released.  Dropping it
    // first let an immediate restart find the port still bound.
    let sig = if stop.load(Ordering::Relaxed) { 1 } else { 0 };
    hlog_info!("[HUB] Shutting down (signal {sig}).\n");
    state.listener = None;
    while !state.clients.is_empty() {
        let last = state.clients.len() - 1;
        auth::disconnect_client(&mut state, last);
    }
    if state.config_dirty {
        config::write(&mut state);
        state.config_dirty = false;
    }

    state.hub_ed25519_priv.wipe();
    state.hub_x25519_priv.wipe();
    state.config_pass.wipe();

    let _ = fs::remove_file(HUB_PID_FILE);
    state.pid_file = None;
    logging::close();
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
    let setup_mode = args.iter().skip(1).any(|a| a == "-setup");
    let passfile_mode = args.iter().skip(1).any(|a| a == "-p");

    let mut state = HubState::new();
    state.log_level = HUB_DEFAULT_LOG_LEVEL;
    state.log_max_size = HUB_LOG_FILE_SIZE;
    logging::attach(state.log_level, state.log_max_size);

    if setup_mode {
        std::process::exit(run_setup(&mut state));
    }

    // -p: create/replace .irchub.pass from an interactive password prompt.
    if passfile_mode {
        let pass = loop {
            let p1 = tool::read_pass_hidden("Config Password: ", MAX_PASS);
            if p1.is_empty() {
                eprintln!("Password cannot be empty.");
                std::process::exit(1);
            }
            let p2 = tool::read_pass_hidden("Confirm Config Password: ", MAX_PASS);
            if *p1 == *p2 {
                break p1;
            }
            println!("Passwords do not match. Try again.");
        };
        if passfile_create(HUB_PASS_FILE, &pass) {
            println!("Saved: {HUB_PASS_FILE} (0600, machine-bound)");
            return;
        }
        eprintln!("Failed to create {HUB_PASS_FILE}.");
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

    // The binary an upgrade replaces, and the one <exe>.prev sits beside.
    // Resolved once, here, because exec() through the upgrade script needs an
    // absolute path and argv[0] alone may be relative.  A hub that cannot
    // resolve it still runs; update::commit refuses instead.
    state.executable_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_default();
    if state.executable_path.is_empty() {
        hlog_warning!("Could not resolve my own path; self-upgrade disabled\n");
    }

    let Some(pid_file) = lock_pid_file() else {
        hlog_error!("Hub already running (PID file locked)\n");
        std::process::exit(1);
    };
    state.pid_file = Some(pid_file);

    std::process::exit(run(state, password, &stop));
}
