//! SSH admin console — the core's side (the poll loop's thread only).
//! docs/console.md; mirrors irchub `hub_console_core.c`.
//!
//! The console thread (`ssh`) terminates SSH and authenticates admins against
//! the credential snapshot published from here.  Each logged-in console
//! becomes an internal admin connection: a `HubClient` without a TCP socket
//! whose `console` holds the core's end of a socketpair, already
//! authenticated, speaking plaintext frames `len(4) || op(1) || payload`.
//! Its requests go through the same `admin::handle_admin_command` as every
//! admin command ever did; what this module adds is the handoff of "SSH-"
//! sockets, the channel to the console thread, the pushed events (status,
//! tree, upgrade, log lines) and the log ring.

pub mod fmt;
pub mod ssh;
pub mod ui;

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::consts::*;
use crate::cstr::now;
use crate::state::{ClientType, HubClient, HubState, UpgradeNodeState};
use crate::{auth, crypto, presence, ratelimit, upgrade};

// ---------------------------------------------------------------------------
// What the two threads share
// ---------------------------------------------------------------------------

/// An admin who may log in: the record's name and the Ed25519 half of its key.
#[derive(Clone)]
pub struct Cred {
    pub name: String,
    pub ed_pub: [u8; 32],
}

/// The snapshot the core publishes (mutex-protected): the only data shared
/// with the console thread.
pub struct Published {
    pub creds: Vec<Cred>,
    /// mlock'd like the core's own copy (secret.rs); wiped on stop and drop.
    pub host_seed: crate::secret::Locked<32>,
    pub host_pub: [u8; 32],
    /// Bumped on every host key change; 0 = none published yet.
    pub host_gen: u32,
    pub hubname: String,
}

pub type Shared = Arc<Mutex<Published>>;

/// core -> console thread.
pub enum ToConsole {
    /// An accepted socket whose first bytes were "SSH-".
    New(TcpStream, String),
}

/// console thread -> core.
pub enum FromConsole {
    /// A console logged in; `stream` is the core's end of its socketpair.
    Open {
        stream: UnixStream,
        name: String,
        ip: String,
    },
    /// A refused login: fed to the failed-auth rate limiter.
    Fail {
        ip: String,
        name: String,
        reason: String,
    },
    /// An audit line: the console thread never logs itself.
    Log { level: i32, text: String },
}

/// The core's side of the running console thread.
pub struct Core {
    to: tokio::sync::mpsc::UnboundedSender<ToConsole>,
    from: std::sync::mpsc::Receiver<FromConsole>,
    /// Readable whenever the console thread queued something in `from`.
    pub wake: UnixStream,
    shared: Shared,
    thread: Option<std::thread::JoinHandle<()>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    cred_hash: Option<[u8; 32]>,
    hostkey_pub: Option<[u8; 32]>,
    last_cred_check: i64,
    snap_now: bool,
    last_snap: i64,
}

// ---------------------------------------------------------------------------
// Per-console link (core side)
// ---------------------------------------------------------------------------

pub struct ConsoleLink {
    pub stream: UnixStream,
    admin: String,
    /// The key this console logged in with; the console closes on a change.
    ed_pub: [u8; 32],
    outq: Vec<u8>,
    outq_off: usize,
    sub_status: bool,
    sub_tree: bool,
    sub_upg: bool,
    /// -1 = no log lines.
    log_level: i32,
    log_next: u64,
    drops: u64,
    status_last: String,
    upg_last: String,
    tree_hash: Option<[u8; 32]>,
}

impl ConsoleLink {
    /// Queue one frame.  A CONSOLE_REPLY never drops: false = the queue is
    /// over its cap and the console must be closed.  Events are dropped (and
    /// counted) instead.
    pub fn send(&mut self, op: u8, data: &[u8]) -> bool {
        let need = 5 + data.len();
        if self.outq.len() - self.outq_off + need > CONSOLE_CORE_OUTQ_MAX {
            if op == CONSOLE_REPLY {
                return false;
            }
            self.drops += 1;
            return true;
        }
        if self.outq_off > 0 {
            self.outq.drain(..self.outq_off);
            self.outq_off = 0;
        }
        self.outq
            .extend_from_slice(&((1 + data.len()) as u32).to_be_bytes());
        self.outq.push(op);
        self.outq.extend_from_slice(data);
        true
    }

    fn event(&mut self, topic: &str, data: &[u8]) {
        let mut b = Vec::with_capacity(topic.len() + 1 + data.len());
        b.extend_from_slice(topic.as_bytes());
        b.push(b'|');
        b.extend_from_slice(data);
        self.send(CMD_CONSOLE, &b);
    }

    pub fn has_pending(&self) -> bool {
        self.outq.len() > self.outq_off
    }

    /// Write what the socketpair takes now.  False = the link is broken.
    pub fn drain(&mut self) -> bool {
        while self.outq.len() > self.outq_off {
            match self.stream.write(&self.outq[self.outq_off..]) {
                Ok(0) => return false,
                Ok(n) => self.outq_off += n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted =>
                {
                    return true;
                }
                Err(_) => return false,
            }
        }
        self.outq.clear();
        self.outq_off = 0;
        true
    }
}

impl Drop for ConsoleLink {
    fn drop(&mut self) {
        crypto::wipe(&mut self.outq);
    }
}

// ---------------------------------------------------------------------------
// Log ring
// ---------------------------------------------------------------------------

/// One slot's bookkeeping; its text lives in the ring's locked mapping.
#[derive(Clone, Copy, Default)]
struct LogMeta {
    seq: u64,
    level: i32,
    len: usize,
    /// When it was logged (log show's "oldest").
    ts: i64,
}

/// Not encrypted: the text is a mapping of its own, page-aligned so that
/// mlock (no swap, no hibernation image) and MADV_DONTDUMP (no core dump)
/// cover exactly it — `CONSOLE_LOG_RING` slots of `CONSOLE_LOG_LINE_MAX`
/// bytes.  `None` until log_ring_init(); a hub whose mapping failed runs
/// without a log view rather than with an unprotected one.
struct Ring {
    text: Option<memmap2::MmapMut>,
    meta: Vec<LogMeta>,
    /// Sequence the next line gets.
    next: u64,
}

thread_local! {
    static RING: RefCell<Ring> = const {
        RefCell::new(Ring { text: None, meta: Vec::new(), next: 1 })
    };
}

/// Allocate the log ring (hub_console_log_ring_init); false = no ring.
pub fn log_ring_init() -> bool {
    RING.with_borrow_mut(|r| {
        if r.text.is_some() {
            return true;
        }
        let m = match memmap2::MmapMut::map_anon(CONSOLE_LOG_RING * CONSOLE_LOG_LINE_MAX) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "Warning: console log ring: mmap failed ({e}) - the consoles' log view is off."
                );
                return false;
            }
        };
        if let Err(e) = m.advise(memmap2::Advice::DontDump) {
            eprintln!("Warning: console log ring: madvise(MADV_DONTDUMP) failed ({e}).");
        }
        if let Err(e) = m.lock() {
            eprintln!("Warning: mlock(console log ring) failed ({e}) - log lines may reach swap.");
        }
        r.meta = vec![LogMeta::default(); CONSOLE_LOG_RING];
        r.text = Some(m); // an anonymous mapping: already zero
        true
    })
}

/// hub_log feeds every line at or under console_log_level in here:
/// "[timestamp] <message>".
pub fn log_append(level: i32, line: &[u8]) {
    RING.with_borrow_mut(|r| {
        let Some(m) = r.text.as_mut() else { return };
        let seq = r.next;
        r.next += 1;
        let slot = (seq % CONSOLE_LOG_RING as u64) as usize;
        let text = &mut m[slot * CONSOLE_LOG_LINE_MAX..(slot + 1) * CONSOLE_LOG_LINE_MAX];
        // One line: a newline inside becomes a space, the last one goes.
        let cut = &line[..line.len().min(CONSOLE_LOG_LINE_MAX - 1)];
        let mut o = 0;
        for (i, &b) in cut.iter().enumerate() {
            if b == b'\n' || b == b'\r' {
                if i + 1 == cut.len() {
                    break;
                }
                text[o] = b' ';
            } else {
                text[o] = b;
            }
            o += 1;
        }
        // The rest of the slot still holds an older line: clear it.
        text[o..].fill(0);
        r.meta[slot] = LogMeta {
            seq,
            level: level.clamp(LOG_ERROR, LOG_DEBUG),
            len: o,
            ts: crate::cstr::now(),
        };
    });
}

fn ring_next() -> u64 {
    RING.with_borrow(|r| r.next)
}

fn log_level_word(level: i32) -> &'static str {
    match level {
        LOG_ERROR => "error",
        LOG_WARNING => "warning",
        LOG_DEBUG => "debug",
        _ => "info",
    }
}

// ---------------------------------------------------------------------------
// Start / stop / credentials
// ---------------------------------------------------------------------------

/// "SHA256:<base64 without padding>" of an ssh-ed25519 public key.
pub fn ssh_fingerprint(pub_key: &[u8; 32]) -> String {
    let mut blob = Vec::with_capacity(51);
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(pub_key);
    let h = Sha256::digest(&blob);
    let b = crypto::b64_encode(&h);
    format!("SHA256:{}", b.trim_end_matches('='))
}

/// The admins that may log in: active admin records with a key, each key on
/// exactly one of them (a key on two records is refused, as it always was).
fn build_creds(state: &HubState) -> Vec<Cred> {
    let mut out = Vec::new();
    for u in &state.user_records {
        if u.typ != 'a' || !u.is_active || !u.has_pubkey || u.name.is_empty() {
            continue;
        }
        let Some(pk) = crypto::pubkey_b64_decode(&u.pubkey_b64) else {
            continue;
        };
        let same = state
            .user_records
            .iter()
            .filter(|v| v.typ == 'a' && v.is_active && v.has_pubkey && v.pubkey_b64 == u.pubkey_b64)
            .count();
        if same != 1 || out.len() >= MAX_HUB_USER_RECORDS {
            continue;
        }
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&pk[..32]);
        out.push(Cred {
            name: crate::cstr::trunc_string(&u.name, CONSOLE_NAME_MAX - 1),
            ed_pub: ed,
        });
    }
    out
}

fn creds_hold(creds: &[Cred], name: &str, ed_pub: &[u8; 32]) -> bool {
    creds
        .iter()
        .any(|c| c.name == name && crypto::ct_eq(&c.ed_pub, ed_pub))
}

/// The hub key was regenerated or imported: publish the SSH host key now,
/// not at the next tick (a login right after `hub rekey` must see it).
pub fn hostkey_changed(state: &mut HubState) {
    let mut core = state.console.take();
    if let Some(c) = core.as_mut() {
        publish_hostkey(state, c);
    }
    state.console = core;
}

fn publish_hostkey(state: &HubState, core: &mut Core) {
    if !state.hub_keys_loaded {
        return;
    }
    {
        let mut p = core.shared.lock().unwrap_or_else(|e| e.into_inner());
        p.host_seed.set(state.hub_ed25519_priv.get());
        p.host_pub = state.hub_ed25519_pub;
        p.host_gen = p.host_gen.wrapping_add(1).max(1);
    }
    let was = core
        .hostkey_pub
        .filter(|p| *p != state.hub_ed25519_pub)
        .map(|p| ssh_fingerprint(&p));
    core.hostkey_pub = Some(state.hub_ed25519_pub);
    let fp = ssh_fingerprint(&state.hub_ed25519_pub);
    // Key material changed hands: an audit line, not just a notice.
    match was {
        Some(old_fp) => crate::hlog_warning!(
            "[AUDIT] SSH host key republished: ssh-ed25519 {fp} (was {old_fp}); admins must accept the new host key\n"
        ),
        None => crate::hlog_info!("[CONSOLE] SSH host key ssh-ed25519 {fp}\n"),
    }
}

fn refresh_creds(state: &mut HubState, force: bool) {
    let creds = build_creds(state);
    let mut h = Sha256::new();
    for c in &creds {
        h.update(c.name.as_bytes());
        h.update([0u8]);
        h.update(c.ed_pub);
    }
    let hash: [u8; 32] = h.finalize().into();
    let name = if state.hub_friendly_name.is_empty() {
        "hub".to_string()
    } else {
        state.hub_friendly_name.clone()
    };
    let Some(core) = state.console.as_mut() else {
        return;
    };
    if !force && core.cred_hash == Some(hash) {
        return;
    }
    core.cred_hash = Some(hash);
    {
        let mut p = core.shared.lock().unwrap_or_else(|e| e.into_inner());
        p.creds = creds.clone();
        p.hubname = name;
    }
    // A console whose admin was removed, or whose key changed, ends now.
    let mut i = 0;
    while i < state.clients.len() {
        let gone = match (&state.clients[i].console, state.clients[i].internal) {
            (Some(l), true) => !creds_hold(&creds, &l.admin, &l.ed_pub),
            _ => false,
        };
        if gone {
            let who = state.clients[i]
                .console
                .as_ref()
                .map(|l| l.admin.clone())
                .unwrap_or_default();
            crate::hlog_warning!(
                "[CONSOLE] Closing {who}'s console: the admin record or its key changed\n"
            );
            auth::disconnect_client(state, i);
            continue;
        }
        i += 1;
    }
}

/// Spawn the console thread and publish the host key and the admin
/// credentials to it.  False (logged) when it cannot start.
pub fn start(state: &mut HubState) -> bool {
    let (wake_core, wake_thread) = match UnixStream::pair() {
        Ok(p) => p,
        Err(e) => {
            crate::hlog_error!("[CONSOLE] socketpair failed: {e}\n");
            return false;
        }
    };
    if wake_core.set_nonblocking(true).is_err() || wake_thread.set_nonblocking(true).is_err() {
        return false;
    }
    let shared: Shared = Arc::new(Mutex::new(Published {
        creds: Vec::new(),
        host_seed: crate::secret::Locked::new(),
        host_pub: [0u8; 32],
        host_gen: 0,
        hubname: String::new(),
    }));
    let (to_tx, to_rx) = tokio::sync::mpsc::unbounded_channel();
    let (from_tx, from_rx) = std::sync::mpsc::channel();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut core = Core {
        to: to_tx,
        from: from_rx,
        wake: wake_core,
        shared: shared.clone(),
        thread: None,
        stop: stop.clone(),
        cred_hash: None,
        hostkey_pub: None,
        last_cred_check: 0,
        snap_now: false,
        last_snap: 0,
    };
    publish_hostkey(state, &mut core);
    let thread = std::thread::Builder::new()
        .name("console".into())
        .spawn(move || ssh::run(to_rx, from_tx, wake_thread, shared, stop));
    match thread {
        Ok(t) => core.thread = Some(t),
        Err(e) => {
            crate::hlog_error!("[CONSOLE] Could not start the console thread: {e}\n");
            return false;
        }
    }
    state.console = Some(core);
    refresh_creds(state, true);
    true
}

pub fn stop(state: &mut HubState) {
    let Some(mut core) = state.console.take() else {
        return;
    };
    core.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    // Dropping the sender ends the thread's receive loop.
    let Core { to, thread, .. } = &mut core;
    drop(std::mem::replace(
        to,
        tokio::sync::mpsc::unbounded_channel().0,
    ));
    if let Some(t) = thread.take() {
        let _ = t.join();
    }
    let mut p = core.shared.lock().unwrap_or_else(|e| e.into_inner());
    p.host_seed.wipe();
    p.creds.clear();
}

/// The accepted connection's first bytes are "SSH-": give its socket to the
/// console thread and drop the client from the core.
pub fn handoff(state: &mut HubState, ci: usize) {
    let ip = state.clients[ci].ip.clone();
    let sock = state.clients[ci].sock.take();
    let sent = match (sock, state.console.as_ref()) {
        (Some(s), Some(core)) => core.to.send(ToConsole::New(s, ip.clone())).is_ok(),
        _ => false,
    };
    if sent {
        crate::hlog_debug!("[CONSOLE] SSH connection from {ip} handed to the console\n");
    } else {
        crate::hlog_warning!("[CONSOLE] SSH connection from {ip} refused: console not running\n");
    }
    // fd -1: a socket handed to the SSH console, not a disconnect.
    state.clients[ci].fd = -1;
    auth::disconnect_client(state, ci);
}

fn admin_by_name(state: &HubState, name: &str) -> Option<usize> {
    state
        .user_records
        .iter()
        .position(|u| u.typ == 'a' && u.is_active && u.name == name)
}

fn open_console(state: &mut HubState, stream: UnixStream, name: String, ip: String) {
    let pk = admin_by_name(state, &name).and_then(|ui| {
        let u = &state.user_records[ui];
        if u.has_pubkey {
            crypto::pubkey_b64_decode(&u.pubkey_b64)
        } else {
            None
        }
    });
    let Some(pk) = pk.filter(|_| name.len() + "ADMIN:".len() < 64) else {
        crate::hlog_warning!(
            "[CONSOLE] Login for '{name}' from {ip} no longer matches a record — closing\n"
        );
        return;
    };
    if state.clients.len() >= MAX_CLIENTS {
        crate::hlog_warning!("[CONSOLE] Console for {name} from {ip} refused: client table full\n");
        return;
    }
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let fd = {
        use std::os::fd::AsRawFd;
        stream.as_raw_fd()
    };
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&pk[..32]);
    let link = ConsoleLink {
        stream,
        admin: name.clone(),
        ed_pub: ed,
        outq: Vec::new(),
        outq_off: 0,
        sub_status: false,
        sub_tree: false,
        sub_upg: false,
        log_level: -1,
        log_next: ring_next(),
        drops: 0,
        status_last: String::new(),
        upg_last: String::new(),
        tree_hash: None,
    };
    let mut c = HubClient::new_detached(fd, &ip, MAX_BUFFER);
    c.id = format!("ADMIN:{name}");
    c.typ = ClientType::Admin;
    c.authenticated = true;
    c.internal = true;
    c.inbound = true; // the SSH side came in on the listener
    c.console = Some(Box::new(link));
    state.clients.push(c);
    ratelimit::increment_active_connections(state, &ip);

    crate::hlog_info!(
        "[HUB] Admin Login (SSH console, key {}): {ip} as '{name}'\n",
        crypto::key_fingerprint(&pk)
    );
    if let Some(ui) = admin_by_name(state, &name) {
        // Activity, not a config change: no peer sync, no bot push.
        crate::activity::stamp_user(state, ui, now());
    }
}

/// The wake socket is readable: logins, refusals, audit lines.
pub fn on_wake(state: &mut HubState) {
    let mut msgs = Vec::new();
    {
        let Some(core) = state.console.as_mut() else {
            return;
        };
        let mut b = [0u8; 256];
        while let Ok(n) = core.wake.read(&mut b) {
            if n == 0 {
                break;
            }
        }
        while let Ok(m) = core.from.try_recv() {
            msgs.push(m);
        }
    }
    for m in msgs {
        match m {
            FromConsole::Open { stream, name, ip } => open_console(state, stream, name, ip),
            FromConsole::Fail { ip, name, reason } => {
                crate::hlog_warning!("[CONSOLE] Refused SSH login '{name}' from {ip}: {reason}\n");
                ratelimit::record_failed_auth(state, &ip);
            }
            FromConsole::Log { level, text } => match level {
                LOG_ERROR => crate::hlog_error!("{text}\n"),
                LOG_WARNING => crate::hlog_warning!("{text}\n"),
                LOG_DEBUG => crate::hlog_debug!("{text}\n"),
                _ => crate::hlog_info!("{text}\n"),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshots (docs/console.md §3.3)
// ---------------------------------------------------------------------------

/// One status line, fields in a fixed order.  `tree` is the current
/// presence::build_tree output: bots online are the distinct B rows, and the
/// mesh is split when any hub row is offline.
pub fn status_line(state: &HubState, tree: &str) -> String {
    let peers_up = state
        .peers
        .iter()
        .filter(|p| presence::peer_is_linked(state, p))
        .count();
    let bots_total = state.bots.iter().filter(|b| b.is_active).count();
    let mut seen: Vec<&str> = Vec::new();
    let mut split = false;
    for row in tree.split('\n') {
        if row.len() > TREE_ROW_MAX {
            continue;
        }
        let f: Vec<&str> = row.split('|').filter(|s| !s.is_empty()).collect();
        if f.len() >= 5 && f[0] == "H" && f[4] == "0" {
            split = true;
        }
        if f.len() >= 4 && f[0] == "B" && !seen.contains(&f[3]) && seen.len() < MAX_BOTS {
            seen.push(f[3]);
        }
    }
    let u = &state.upgrade;
    let upg = if u.active {
        let sel = u.nodes.iter().filter(|n| !n.not_selected);
        let total = sel.clone().count();
        let done = sel.filter(|n| n.state == UpgradeNodeState::Done).count();
        format!("{done}/{total}")
    } else {
        "-".to_string()
    };
    format!(
        "name={}|peers={}/{}|bots={}/{}|upg={}|frozen={}|rollup={}|split={}|loglevel={}|consolelevel={}",
        if state.hub_friendly_name.is_empty() {
            "hub"
        } else {
            &state.hub_friendly_name
        },
        peers_up,
        state.peers.len(),
        seen.len(),
        bots_total,
        upg,
        i32::from(upgrade::config_frozen(state)),
        i32::from(state.rollup.have_plan),
        i32::from(split),
        state.log_level,
        state.console_log_level
    )
}

/// `<id>|<phase>|<done>/<total>|<failed>`, or "" when this hub has not driven
/// a run.
pub fn upg_line(state: &HubState) -> String {
    let u = &state.upgrade;
    if u.id.is_empty() {
        return String::new();
    }
    let sel: Vec<_> = u.nodes.iter().filter(|n| !n.not_selected).collect();
    let done = sel
        .iter()
        .filter(|n| n.state == UpgradeNodeState::Done)
        .count();
    let failed = sel
        .iter()
        .filter(|n| n.state == UpgradeNodeState::Failed)
        .count();
    format!(
        "{}|{}|{}/{}|{}",
        u.id,
        u.phase.name(),
        done,
        sel.len(),
        failed
    )
}

// ---------------------------------------------------------------------------
// Session frames
// ---------------------------------------------------------------------------

/// "sub|status,tree,upg,log=3[,logreplay]" — replaces the console's
/// subscriptions.  logreplay also sends what the log ring still holds (the
/// full-screen log view); without it only new lines come.
fn subscribe(l: &mut ConsoleLink, topics: &str) -> bool {
    l.sub_status = false;
    l.sub_tree = false;
    l.sub_upg = false;
    let mut want_log = -1;
    let mut replay = false;
    for t in crate::cstr::trunc(topics, 255)
        .split(',')
        .filter(|t| !t.is_empty())
    {
        match t {
            "status" => l.sub_status = true,
            "tree" => l.sub_tree = true,
            "upg" => l.sub_upg = true,
            "logreplay" => replay = true,
            _ => {
                if let Some(v) = t.strip_prefix("log=")
                    && let Some(n) = crate::state::parse_uint(v, LOG_DEBUG as u64)
                {
                    want_log = n as i32;
                }
            }
        }
    }
    // A (re)subscription resends the current state of everything asked for.
    l.status_last.clear();
    l.upg_last.clear();
    l.tree_hash = None;
    if want_log >= 0 && l.log_level < 0 {
        let next = ring_next();
        l.log_next = if !replay {
            next
        } else if next > CONSOLE_LOG_RING as u64 {
            next - CONSOLE_LOG_RING as u64 + 1
        } else {
            1
        };
    }
    l.log_level = want_log;
    true
}

/// A CMD_CONSOLE frame on an internal connection.  False = the reply could
/// not be queued (the caller closes the console).
pub fn frame(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if let Some(topics) = payload.strip_prefix("sub|") {
        if let Some(core) = state.console.as_mut() {
            core.snap_now = true;
        }
        return match state.clients[ci].console.as_mut() {
            Some(l) => subscribe(l, topics),
            None => false,
        };
    }
    // get|tree and get|status: the result line, then the rows / key=value
    // lines exactly as the events carry them (docs/console.md §3.4).
    let reply = if payload == "get|tree" || payload == "get|status" {
        let rows = presence::build_tree(state);
        if payload == "get|tree" {
            let rows = rows.trim_end_matches('\n');
            format!(
                "ok|network.tree{}{}",
                if rows.is_empty() { "" } else { "\n" },
                rows
            )
        } else {
            // one key=value per line
            format!(
                "ok|network.status\n{}",
                status_line(state, &rows).replace('|', "\n")
            )
        }
    } else if payload == "get|log" {
        // the log settings and how full the file and the ring are
        let mut r = crate::reply::Reply::new();
        r.ok("log.show");
        r.kvi("file_level", i64::from(state.log_level));
        r.kvi("console_level", i64::from(state.console_log_level));
        r.kv("file", HUB_LOG_FILE);
        r.kvi(
            "file_bytes",
            std::fs::metadata(HUB_LOG_FILE).map_or(0, |m| m.len() as i64),
        );
        r.kvi(
            "limit",
            if state.log_max_size > 0 {
                state.log_max_size
            } else {
                HUB_LOG_FILE_SIZE
            },
        );
        let next = ring_next();
        let lines = (next.saturating_sub(1)).min(CONSOLE_LOG_RING as u64);
        r.kvu("ring_lines", lines);
        r.kvi("ring_cap", CONSOLE_LOG_RING as i64);
        if lines > 0 {
            let ts = RING.with_borrow(|rg| {
                if rg.text.is_none() {
                    return 0;
                }
                let slot = ((next - lines) % CONSOLE_LOG_RING as u64) as usize;
                rg.meta.get(slot).map_or(0, |e| e.ts)
            });
            if ts > 0 {
                r.kvi("ring_oldest", ts);
            }
        }
        let sl = state.clients[ci]
            .console
            .as_ref()
            .map_or(-1, |l| l.log_level);
        r.kvi("session_level", i64::from(sl));
        r.text().to_string()
    } else {
        "err|console.unknown|msg=unknown console request".to_string()
    };
    match state.clients[ci].console.as_mut() {
        Some(l) => l.send(CONSOLE_REPLY, reply.as_bytes()),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Per-pass work
// ---------------------------------------------------------------------------

fn push_log(l: &mut ConsoleLink) {
    let next = ring_next();
    if l.log_level < 0 {
        l.log_next = next;
        return;
    }
    let oldest = if next > CONSOLE_LOG_RING as u64 {
        next - CONSOLE_LOG_RING as u64 + 1
    } else {
        1
    };
    if l.log_next < oldest {
        l.drops += oldest - l.log_next;
        l.log_next = oldest;
    }
    while l.log_next < next {
        let seq = l.log_next;
        l.log_next += 1;
        let line = RING.with_borrow(|r| {
            let slot = (seq % CONSOLE_LOG_RING as u64) as usize;
            let e = r.meta.get(slot)?;
            let m = r.text.as_ref()?;
            (e.seq == seq && e.level <= l.log_level).then(|| {
                let text = &m[slot * CONSOLE_LOG_LINE_MAX..slot * CONSOLE_LOG_LINE_MAX + e.len];
                let mut d = Vec::with_capacity(text.len() + 10);
                d.extend_from_slice(log_level_word(e.level).as_bytes());
                d.push(b'|');
                d.extend_from_slice(text);
                d
            })
        });
        if let Some(mut d) = line {
            l.event("log", &d);
            crypto::wipe(&mut d);
        }
    }
}

/// One pass of the main loop: publish changed credentials and host key, push
/// events and log lines to the consoles that asked for them.
pub fn tick(state: &mut HubState) {
    let t = now();
    let Some(core) = state.console.as_mut() else {
        return;
    };
    if t != core.last_cred_check {
        core.last_cred_check = t;
        let key_changed = state.hub_keys_loaded && core.hostkey_pub != Some(state.hub_ed25519_pub);
        refresh_creds(state, false);
        if key_changed {
            let mut core = state.console.take();
            if let Some(c) = core.as_mut() {
                publish_hostkey(state, c);
            }
            state.console = core;
        }
    }
    let Some(core) = state.console.as_mut() else {
        return;
    };
    if core.snap_now {
        core.last_snap = 0;
        core.snap_now = false;
    }
    let due = t != core.last_snap;

    let mut any = false;
    let mut want_tree = false;
    for c in &state.clients {
        if let (true, Some(l)) = (c.internal, &c.console) {
            any = true;
            want_tree |= l.sub_tree || l.sub_status;
        }
    }
    if !any {
        return;
    }
    let (rows, status, tree_hash) = if want_tree && due {
        let rows = presence::build_tree(state);
        let status = status_line(state, &rows);
        let h: [u8; 32] = Sha256::digest(rows.as_bytes()).into();
        (Some(rows), status, Some(h))
    } else {
        (None, String::new(), None)
    };
    let upg = if due { upg_line(state) } else { String::new() };

    for c in &mut state.clients {
        let (true, Some(l)) = (c.internal, c.console.as_mut()) else {
            continue;
        };
        if due {
            if l.sub_status && !status.is_empty() && status != l.status_last {
                l.status_last = status.clone();
                l.event("status", status.as_bytes());
            }
            if l.sub_tree
                && let (Some(rows), Some(h)) = (&rows, tree_hash)
                && l.tree_hash != Some(h)
            {
                l.tree_hash = Some(h);
                l.event("tree", rows.as_bytes());
            }
            if l.sub_upg && !upg.is_empty() && upg != l.upg_last {
                l.upg_last = upg.clone();
                l.event("upg", upg.as_bytes());
            }
        }
        push_log(l);
        if l.drops > 0 && l.outq.len() - l.outq_off + 64 < CONSOLE_CORE_OUTQ_MAX {
            let n = l.drops.to_string();
            l.drops = 0;
            l.event("drop", n.as_bytes());
        }
    }
    if let Some(core) = state.console.as_mut()
        && due
    {
        core.last_snap = t;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring is its own mapping, MADV_DONTDUMP ("dd") and mlock'd ("lo"
    /// when RLIMIT_MEMLOCK allows it); a reused slot keeps no older bytes.
    #[test]
    fn log_ring_is_locked_not_dumped_and_cleared() {
        assert!(log_ring_init());
        let addr = RING.with_borrow(|r| r.text.as_ref().map(|m| m.as_ptr() as usize));
        let addr = addr.expect("ring mapped");
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut flags = None;
        let mut inside = false;
        for l in smaps.lines() {
            if let Some((range, _)) = l.split_once(' ')
                && let Some((a, _)) = range.split_once('-')
                && let Ok(start) = usize::from_str_radix(a, 16)
            {
                inside = start == addr;
            } else if inside && let Some(f) = l.strip_prefix("VmFlags:") {
                flags = Some(f.to_string());
            }
        }
        let flags = flags.expect("mapping in smaps");
        assert!(flags.split_whitespace().any(|f| f == "dd"), "{flags}");

        log_append(LOG_WARNING, b"[t] a long line that fills the slot\n");
        for _ in 1..CONSOLE_LOG_RING {
            log_append(LOG_DEBUG, b"x\n");
        }
        log_append(LOG_INFO, b"[t] short\n");
        RING.with_borrow(|r| {
            let slot = ((r.next - 1) % CONSOLE_LOG_RING as u64) as usize;
            let m = r.text.as_ref().unwrap();
            let t = &m[slot * CONSOLE_LOG_LINE_MAX..(slot + 1) * CONSOLE_LOG_LINE_MAX];
            assert_eq!(&t[..9], b"[t] short");
            assert!(t[9..].iter().all(|&b| b == 0));
            assert_eq!(r.meta[slot].level, LOG_INFO);
        });
    }
}
