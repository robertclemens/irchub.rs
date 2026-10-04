//! SSH admin console — the console thread.  docs/console.md; mirrors irchub
//! `hub_console.c`.
//!
//! One thread, one single-threaded tokio runtime, every SSH session of the
//! hub (russh).  The core hands over accepted sockets whose first bytes were
//! "SSH-" (`ToConsole::New`); this thread runs the key exchange,
//! authenticates the admin against the credential snapshot the core
//! published, enforces the channel policy, and then connects the session's
//! UI (`ui::Ui`) to the core through a fresh socketpair (`FromConsole::Open`).
//! It never touches HubState and never logs: refusals and audit lines go to
//! the core as `FromConsole::Fail` / `Log` and are logged there.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::ui::Ui;
use super::{FromConsole, Shared, ToConsole};
use crate::consts::*;

// ---------------------------------------------------------------------------
// Thread-wide context
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Counts {
    /// SSH connections not yet in a shell, per address.
    preauth: HashMap<String, usize>,
    consoles: usize,
}

struct Ctx {
    from: Mutex<std::sync::mpsc::Sender<FromConsole>>,
    wake: Mutex<UnixStream>,
    shared: Shared,
    counts: Mutex<Counts>,
    config: Mutex<Option<(u32, Arc<Config>)>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
}

impl Ctx {
    /// Queue a message for the core and wake its poll loop.
    fn notify(&self, m: FromConsole) {
        if self
            .from
            .lock()
            .map(|tx| tx.send(m).is_ok())
            .unwrap_or(false)
            && let Ok(mut w) = self.wake.lock()
        {
            let _ = w.write(&[1]);
        }
    }

    fn log(&self, level: i32, text: String) {
        self.notify(FromConsole::Log { level, text });
    }

    /// The russh server config for the current host key (rebuilt when the
    /// core published a new one).
    fn server_config(&self) -> Option<Arc<Config>> {
        let (generation, seed) = {
            let p = self.shared.lock().ok()?;
            if p.host_gen == 0 {
                return None;
            }
            (p.host_gen, zeroize::Zeroizing::new(*p.host_seed.get()))
        };
        let mut cache = self.config.lock().ok()?;
        if let Some((g, c)) = cache.as_ref()
            && *g == generation
        {
            return Some(c.clone());
        }
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
        let cfg = Config {
            server_id: russh::SshId::Standard(Cow::Borrowed("SSH-2.0-irchub")),
            methods: MethodSet::from(&[MethodKind::PublicKey][..]),
            auth_rejection_time: Duration::from_millis(500),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            preferred: Preferred {
                kex: Cow::Borrowed(&[
                    russh::kex::MLKEM768X25519_SHA256,
                    russh::kex::CURVE25519,
                    russh::kex::CURVE25519_PRE_RFC_8731,
                    russh::kex::EXTENSION_SUPPORT_AS_SERVER,
                    russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
                ]),
                key: Cow::Borrowed(&[Algorithm::Ed25519]),
                cipher: Cow::Borrowed(&[
                    russh::cipher::CHACHA20_POLY1305,
                    russh::cipher::AES_256_GCM,
                ]),
                mac: Cow::Borrowed(&[russh::mac::HMAC_SHA256_ETM, russh::mac::HMAC_SHA512_ETM]),
                compression: Cow::Borrowed(&[russh::compression::NONE]),
                ..Preferred::default()
            },
            max_auth_attempts: 10, // our own limit (CONSOLE_MAX_AUTH_TRIES) drops first
            inactivity_timeout: None,
            keepalive_interval: None,
            nodelay: true,
            ..Config::default()
        };
        let cfg = Arc::new(cfg);
        *cache = Some((generation, cfg.clone()));
        Some(cfg)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A client-supplied user name, safe for a log line and a record lookup.
fn clean_name(s: &str) -> String {
    s.chars()
        .take(64)
        .map(|c| {
            if (c as u32) < 0x20 || c == '\u{7f}' || c == '|' || !c.is_ascii() {
                '?'
            } else {
                c
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// One SSH connection
// ---------------------------------------------------------------------------

/// What the console task hears from the handler.
enum Ev {
    Data(Vec<u8>),
    Resize(u32, u32),
    Eof,
    Close,
}

/// State the handler and the connection task share.
#[derive(Default)]
struct Info {
    user: String,
    authed: bool,
    refused: u32,
    fail_sent: bool,
    shell: bool,
    drop_why: Option<String>,
}

struct H {
    ctx: Arc<Ctx>,
    ip: String,
    info: Arc<Mutex<Info>>,
    channel: Option<ChannelId>,
    have_pty: bool,
    term: String,
    cols: u32,
    rows: u32,
    events: Option<UnboundedSender<Ev>>,
}

fn violation(info: &Mutex<Info>, why: &str) -> russh::Error {
    if let Ok(mut i) = info.lock()
        && i.drop_why.is_none()
    {
        i.drop_why = Some(why.to_string());
    }
    russh::Error::Disconnect
}

impl H {
    fn key_matches(&self, user: &str, key: &PublicKey) -> bool {
        let offered: Option<[u8; 32]> = key.key_data().ed25519().map(|k| k.0);
        // Same work for every name: an unknown one is compared against a dummy.
        let mut want = [0u8; 32];
        let mut known = false;
        if let Ok(p) = self.ctx.shared.lock()
            && let Some(c) = p.creds.iter().find(|c| c.name == user)
        {
            want = c.ed_pub;
            known = true;
        }
        let eq = crate::crypto::ct_eq(&want, &offered.unwrap_or([0u8; 32]));
        offered.is_some() && known && eq
    }

    fn report_fail(&self, why: &str) {
        let (name, send) = {
            let Ok(mut i) = self.info.lock() else { return };
            let send = !i.fail_sent;
            i.fail_sent = true;
            (clean_name(&i.user), send)
        };
        if send {
            self.ctx.notify(FromConsole::Fail {
                ip: self.ip.clone(),
                name: if name.is_empty() { "?".into() } else { name },
                reason: why.to_string(),
            });
        }
    }

    fn refuse(&self) -> Result<Auth, russh::Error> {
        let n = {
            let Ok(mut i) = self.info.lock() else {
                return Err(russh::Error::Disconnect);
            };
            i.refused += 1;
            i.refused
        };
        if n >= CONSOLE_MAX_AUTH_TRIES {
            self.report_fail("too many refused keys");
            return Err(violation(&self.info, "authentication failed"));
        }
        Ok(Auth::reject())
    }
}

impl Handler for H {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if let Ok(mut i) = self.info.lock() {
            if i.authed {
                return Ok(Auth::reject());
            }
            i.user = user.to_string();
        }
        if self.key_matches(user, key) {
            return Ok(Auth::Accept);
        }
        self.refuse()
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        if self.key_matches(user, key) {
            if let Ok(mut i) = self.info.lock() {
                i.authed = true;
                i.user = user.to_string();
            }
            return Ok(Auth::Accept);
        }
        self.refuse()
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let authed = self.info.lock().map(|i| i.authed).unwrap_or(false);
        if !authed || self.channel.is_some() {
            drop(reply);
            return Err(violation(&self.info, "extra channel refused"));
        }
        self.channel = Some(channel.id());
        reply.accept().await;
        // The Channel object is not read: everything arrives through the
        // handler callbacks (dropping it closes nothing).
        drop(channel);
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _c: Channel<Msg>,
        _a: &str,
        _p: u32,
        _r: russh::server::ChannelOpenHandle,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(violation(&self.info, "x11 forwarding refused"))
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _c: Channel<Msg>,
        _h: &str,
        _p: u32,
        _oa: &str,
        _op: u32,
        _r: russh::server::ChannelOpenHandle,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(violation(&self.info, "channel type refused"))
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _c: Channel<Msg>,
        _h: &str,
        _p: u32,
        _oa: &str,
        _op: u32,
        _r: russh::server::ChannelOpenHandle,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(violation(&self.info, "channel type refused"))
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _c: Channel<Msg>,
        _p: &str,
        _r: russh::server::ChannelOpenHandle,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(violation(&self.info, "channel type refused"))
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let shell = self.info.lock().map(|i| i.shell).unwrap_or(true);
        if self.have_pty || shell || Some(channel) != self.channel {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.have_pty = true;
        self.term = clean_name(term);
        self.cols = col_width;
        self.rows = row_height;
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _n: &str,
        _v: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Refused, but clients send LANG/LC_* by default: not a violation.
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        _c: ChannelId,
        _d: &[u8],
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(violation(&self.info, "exec refused"))
    }

    async fn subsystem_request(
        &mut self,
        _c: ChannelId,
        _n: &str,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(violation(&self.info, "subsystem refused"))
    }

    async fn x11_request(
        &mut self,
        _c: ChannelId,
        _s1: bool,
        _p: &str,
        _k: &str,
        _n: u32,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(violation(&self.info, "x11 forwarding refused"))
    }

    async fn agent_request(
        &mut self,
        _c: ChannelId,
        _s: &mut Session,
    ) -> Result<bool, Self::Error> {
        Err(violation(&self.info, "agent forwarding refused"))
    }

    async fn tcpip_forward(
        &mut self,
        _a: &str,
        _p: &mut u32,
        _s: &mut Session,
    ) -> Result<bool, Self::Error> {
        Err(violation(&self.info, "port forwarding refused"))
    }

    async fn streamlocal_forward(
        &mut self,
        _p: &str,
        _s: &mut Session,
    ) -> Result<bool, Self::Error> {
        Err(violation(&self.info, "port forwarding refused"))
    }

    async fn window_change_request(
        &mut self,
        _c: ChannelId,
        col_width: u32,
        row_height: u32,
        _pw: u32,
        _ph: u32,
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        self.cols = col_width;
        self.rows = row_height;
        if let Some(tx) = &self.events {
            let _ = tx.send(Ev::Resize(col_width, row_height));
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _s: &mut Session,
    ) -> Result<(), Self::Error> {
        if Some(channel) == self.channel
            && let Some(tx) = &self.events
        {
            let _ = tx.send(Ev::Data(data.to_vec()));
        }
        Ok(())
    }

    async fn channel_eof(&mut self, _c: ChannelId, _s: &mut Session) -> Result<(), Self::Error> {
        // No more input, but what was typed still gets its answer (a script
        // piping commands in and closing stdin).
        if let Some(tx) = &self.events {
            let _ = tx.send(Ev::Eof);
        } else {
            return Err(violation(&self.info, "client closed"));
        }
        Ok(())
    }

    async fn channel_close(&mut self, _c: ChannelId, _s: &mut Session) -> Result<(), Self::Error> {
        if let Some(tx) = &self.events {
            let _ = tx.send(Ev::Close);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (authed, shell, user) = match self.info.lock() {
            Ok(i) => (i.authed, i.shell, i.user.clone()),
            Err(_) => return Err(russh::Error::Disconnect),
        };
        if shell || !authed || Some(channel) != self.channel {
            session.channel_failure(channel)?;
            return Ok(());
        }
        {
            let Ok(mut c) = self.ctx.counts.lock() else {
                return Err(russh::Error::Disconnect);
            };
            if c.consoles >= CONSOLE_MAX_SESSIONS {
                session.channel_failure(channel)?;
                return Err(violation(&self.info, "too many consoles"));
            }
            c.consoles += 1;
            // no longer pre-auth
            if let Some(n) = c.preauth.get_mut(&self.ip) {
                *n = n.saturating_sub(1);
            }
        }
        let Ok((ours, theirs)) = UnixStream::pair() else {
            return Err(violation(&self.info, "no socketpair"));
        };
        if ours.set_nonblocking(true).is_err() {
            return Err(violation(&self.info, "no socketpair"));
        }
        let Ok(core) = tokio::net::UnixStream::from_std(ours) else {
            return Err(violation(&self.info, "no socketpair"));
        };
        if let Ok(mut i) = self.info.lock() {
            i.shell = true;
        }
        self.ctx.notify(FromConsole::Open {
            stream: theirs,
            name: user.clone(),
            ip: self.ip.clone(),
        });
        let hub = self
            .ctx
            .shared
            .lock()
            .map(|p| p.hubname.clone())
            .unwrap_or_default();
        // TERM=dumb, or no pty at all, is line mode (docs/console.md §3).
        let line_mode = !self.have_pty || self.term == "dumb";
        let mut ui = Ui::new(
            line_mode,
            self.cols as i32,
            self.rows as i32,
            &user,
            &self.ip,
            &hub,
        );
        ui.start(now_ms());
        let (tx, rx) = unbounded_channel();
        self.events = Some(tx);
        session.channel_success(channel)?;
        let ctx = self.ctx.clone();
        let handle = session.handle();
        let ip = self.ip.clone();
        tokio::spawn(console_task(ctx, ui, core, handle, channel, rx, user, ip));
        Ok(())
    }
}

/// The running console: UI <-> core socketpair <-> SSH channel.
#[allow(clippy::too_many_arguments)]
async fn console_task(
    ctx: Arc<Ctx>,
    mut ui: Ui,
    core: tokio::net::UnixStream,
    handle: Handle,
    ch: ChannelId,
    mut ev: UnboundedReceiver<Ev>,
    user: String,
    ip: String,
) {
    let (mut core_r, mut core_w) = core.into_split();
    let backlog = Arc::new(AtomicUsize::new(0));
    let (wtx, mut wrx) = unbounded_channel::<Vec<u8>>();
    let writer = {
        let handle = handle.clone();
        let backlog = backlog.clone();
        tokio::spawn(async move {
            while let Some(b) = wrx.recv().await {
                let n = b.len();
                let failed = handle.data(ch, b).await.is_err();
                backlog.fetch_sub(n, Ordering::Relaxed);
                if failed {
                    break;
                }
            }
        })
    };
    let mut shutdown = ctx.shutdown.clone();
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    let mut inbuf: Vec<u8> = Vec::new();
    let mut rbuf = vec![0u8; 65536];
    let mut eof = false;
    let why: String = loop {
        tokio::select! {
            _ = tick.tick() => ui.tick(now_ms()),
            e = ev.recv() => match e {
                Some(Ev::Data(b)) => ui.input(&b, now_ms()),
                Some(Ev::Resize(c, r)) => ui.resize(c as i32, r as i32, now_ms()),
                Some(Ev::Eof) => eof = true,
                Some(Ev::Close) | None => break "client closed".to_string(),
            },
            r = core_r.read(&mut rbuf) => match r {
                Ok(0) | Err(_) => break "closed by the hub".to_string(),
                Ok(n) => {
                    inbuf.extend_from_slice(&rbuf[..n]);
                    let mut off = 0;
                    let mut bad = false;
                    while inbuf.len() - off >= 4 {
                        let len = u32::from_be_bytes([inbuf[off], inbuf[off + 1], inbuf[off + 2], inbuf[off + 3]]) as usize;
                        if !(1..=CONSOLE_FRAME_MAX).contains(&len) {
                            bad = true;
                            break;
                        }
                        if inbuf.len() - off - 4 < len {
                            break;
                        }
                        let f = &inbuf[off + 4..off + 4 + len];
                        ui.core_frame_in(f[0], &f[1..], now_ms());
                        off += 4 + len;
                    }
                    if bad {
                        break "bad frame from the hub".to_string();
                    }
                    inbuf.drain(..off);
                }
            },
            _ = shutdown.changed() => break "hub shutting down".to_string(),
        }
        let c = ui.take_core();
        if !c.is_empty() && core_w.write_all(&c).await.is_err() {
            break "hub link error".to_string();
        }
        ui.backlog = backlog.load(Ordering::Relaxed);
        let t = ui.take_term();
        if !t.is_empty() {
            backlog.fetch_add(t.len(), Ordering::Relaxed);
            let _ = wtx.send(t);
        }
        while let Some((lvl, line)) = ui.take_audit() {
            ctx.log(lvl, String::from_utf8_lossy(&line).into_owned());
        }
        if let Some(w) = ui.closing() {
            break w.to_string();
        }
        if eof && !ui.busy() {
            break "client closed".to_string();
        }
    };
    ui.goodbye(&why);
    let t = ui.take_term();
    if !t.is_empty() {
        let _ = wtx.send(t);
    }
    while let Some((lvl, line)) = ui.take_audit() {
        ctx.log(lvl, String::from_utf8_lossy(&line).into_owned());
    }
    ctx.log(
        LOG_INFO,
        format!("[CONSOLE] {user}@{ip} console closed: {why}"),
    );
    drop(wtx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    let _ = handle.eof(ch).await;
    let _ = handle.close(ch).await;
    let _ = handle
        .disconnect(
            russh::Disconnect::ByApplication,
            String::new(),
            String::new(),
        )
        .await;
    drop(core_w);
    if let Ok(mut c) = ctx.counts.lock() {
        c.consoles = c.consoles.saturating_sub(1);
    }
    drop(ui);
}

async fn connection(ctx: Arc<Ctx>, sock: std::net::TcpStream, ip: String) {
    {
        let Ok(mut c) = ctx.counts.lock() else { return };
        let total: usize = c.preauth.values().sum();
        let per_ip = c.preauth.get(&ip).copied().unwrap_or(0);
        if total >= CONSOLE_MAX_PREAUTH || per_ip >= CONSOLE_MAX_PREAUTH_PER_IP {
            drop(c);
            ctx.log(
                LOG_WARNING,
                format!("[CONSOLE] Too many SSH logins in progress; dropped {ip}"),
            );
            return;
        }
        *c.preauth.entry(ip.clone()).or_insert(0) += 1;
    }
    let info = Arc::new(Mutex::new(Info::default()));
    let run =
        async {
            let Some(cfg) = ctx.server_config() else {
                return;
            };
            if sock.set_nonblocking(true).is_err() {
                return;
            }
            // russh runs the session in a task of its own, which dropping
            // the RunningSession does not stop: ending a session early means
            // shutting its socket down through this second handle.
            let Ok(kill) = sock.try_clone() else {
                return;
            };
            let Ok(stream) = tokio::net::TcpStream::from_std(sock) else {
                return;
            };
            let h = H {
                ctx: ctx.clone(),
                ip: ip.clone(),
                info: info.clone(),
                channel: None,
                have_pty: false,
                term: String::new(),
                cols: 80,
                rows: 24,
                events: None,
            };
            // Login grace: connect -> running shell within CONSOLE_LOGIN_GRACE,
            // counted from the connect.  run_stream itself waits for the client's
            // identification and key exchange, so it is inside the deadline too:
            // a client that stalls there would otherwise hold its pre-auth slot
            // for good (the C hub times the whole session the same way).
            let deadline = tokio::time::Instant::now() + Duration::from_secs(CONSOLE_LOGIN_GRACE);
            let running =
                match tokio::time::timeout_at(deadline, russh::server::run_stream(cfg, stream, h))
                    .await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(_)) => return,
                    Err(_) => {
                        if let Ok(mut i) = info.lock()
                            && i.drop_why.is_none()
                        {
                            i.drop_why = Some("login grace expired".into());
                        }
                        return;
                    }
                };
            let handle = running.handle();
            tokio::pin!(running);
            // At the deadline a session without a shell ends: its socket is
            // shut down even while it still waits for the client's key
            // exchange, where a disconnect request alone is never acted on.
            let info2 = info.clone();
            let grace = async move {
                tokio::time::sleep_until(deadline).await;
                if info2.lock().map(|i| i.shell).unwrap_or(false) {
                    std::future::pending::<()>().await;
                }
                if let Ok(mut i) = info2.lock()
                    && i.drop_why.is_none()
                {
                    i.drop_why = Some("login grace expired".into());
                }
            };
            let mut shutdown = ctx.shutdown.clone();
            tokio::select! {
                _ = &mut running => {}
                _ = shutdown.changed() => {}
                _ = grace => {
                    // say goodbye where the protocol allows it, then drop
                    let bye = handle.disconnect(
                        russh::Disconnect::ByApplication,
                        String::new(),
                        String::new(),
                    );
                    let _ = tokio::time::timeout(Duration::from_secs(1), bye).await;
                    let _ = kill.shutdown(std::net::Shutdown::Both);
                    let _ = tokio::time::timeout(Duration::from_secs(1), &mut running).await;
                }
            }
        };
    run.await;
    let (authed, refused, shell, user, why) = match info.lock() {
        Ok(i) => (
            i.authed,
            i.refused,
            i.shell,
            clean_name(&i.user),
            i.drop_why.clone(),
        ),
        Err(_) => return,
    };
    if let Ok(mut c) = ctx.counts.lock()
        && !shell
        && let Some(n) = c.preauth.get_mut(&ip)
    {
        *n = n.saturating_sub(1);
        if *n == 0 {
            c.preauth.remove(&ip);
        }
    }
    if !authed && refused > 0 {
        let h = H {
            ctx: ctx.clone(),
            ip: ip.clone(),
            info: info.clone(),
            channel: None,
            have_pty: false,
            term: String::new(),
            cols: 0,
            rows: 0,
            events: None,
        };
        h.report_fail(why.as_deref().unwrap_or("key refused"));
    }
    if authed
        && !shell
        && let Some(w) = why
    {
        ctx.log(
            LOG_WARNING,
            format!("[CONSOLE] {user}@{ip} dropped before the console opened: {w}"),
        );
    }
}

/// The console thread's body: serve SSH until the core drops its sender.
pub fn run(
    mut rx: UnboundedReceiver<ToConsole>,
    from: std::sync::mpsc::Sender<FromConsole>,
    wake: UnixStream,
    shared: Shared,
    stop: Arc<AtomicBool>,
) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
    let ctx = Arc::new(Ctx {
        from: Mutex::new(from),
        wake: Mutex::new(wake),
        shared,
        counts: Mutex::new(Counts::default()),
        config: Mutex::new(None),
        shutdown: sd_rx,
    });
    rt.block_on(async move {
        while let Some(m) = rx.recv().await {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match m {
                ToConsole::New(sock, ip) => {
                    tokio::spawn(connection(ctx.clone(), sock, ip));
                }
            }
        }
        // Shutting down: every session says goodbye, briefly.
        let _ = sd_tx.send(true);
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
}
