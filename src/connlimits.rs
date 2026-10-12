//! Per-hub connection limits: `hub set ssh ...` and `hub set conn ...`
//! (hub_connlimits.c; docs/console.md §2.3a).
//!
//! Three independent pieces, all free of the console thread and of `HubState`
//! beyond the plain tables handed in:
//!   * the setting table (names, ranges, built-ins, parsing, canonical text),
//!   * the SSH-only address table (connect window, refused logins, escalating
//!     block), separate from the shared `ip_limits` table,
//!   * the eviction choice used when every SSH login slot is taken.
//!
//! The core owns `HubState::conn_cfg`; the console thread gets a copy through
//! `Published::limits` (the same mutex-guarded snapshot as the credentials).

use crate::consts::*;
use crate::state::parse_uint;

/// hub_conn_cfg_t.  `ssh` group first, then the `conn` group shared by bots,
/// peers and SSH.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnCfg {
    /// SSH logins in progress, all addresses.
    pub preauth: i32,
    /// ... and from one address (<= preauth).
    pub preauthip: i32,
    /// Open consoles.
    pub sessions: i32,
    /// Connect -> shell, seconds.
    pub grace: i32,
    /// Refused keys per connection before the drop.
    pub authtries: i32,
    /// Seconds without a keystroke.
    pub idle: i32,
    /// Refused SSH logins per address per window.
    pub authfail_n: i32,
    pub authfail_s: i32,
    /// New SSH connections per address per window.
    pub connect_n: i32,
    pub connect_s: i32,
    /// Base SSH block, seconds (doubles per repeat).
    pub block: i32,
    /// Console commands per session per window.
    pub cmdrate_n: i32,
    pub cmdrate_s: i32,
    /// Connections at once from one address.
    pub perip: i32,
    /// New connections per window -> block.
    pub churn_n: i32,
    pub churn_s: i32,
    pub churn_block: i32,
    /// Failed logins per window -> block.
    pub fail_n: i32,
    pub fail_s: i32,
    pub fail_block: i32,
}

/// Built-ins (the former compile-time constants).
pub const SSH_DEF_PREAUTHIP: i32 = 2;
pub const SSH_DEF_AUTHFAIL_N: i32 = 3;
pub const SSH_DEF_AUTHFAIL_S: i32 = 3600;
pub const SSH_DEF_CONNECT_N: i32 = 6;
pub const SSH_DEF_CONNECT_S: i32 = 60;
pub const SSH_DEF_BLOCK: i32 = 300;
pub const SSH_DEF_CMDRATE_N: i32 = 20;
pub const SSH_DEF_CMDRATE_S: i32 = 10;
/// Escalation ceiling: 24 h.
pub const SSH_BLOCK_MAX: i32 = 86400;
/// A repeat within this doubles.
pub const SSH_BLOCK_MEMORY: i64 = 86400;
/// An address with a console login this recent skips the connect window and
/// the churn block (not authfail / ACL).
pub const SSH_SUCCESS_MEMORY: i64 = 86400;
pub const MAX_SSH_IPS: usize = 256;
/// Ceiling `hub set ssh preauth` accepts.
pub const CONSOLE_MAX_PREAUTH_CAP: i32 = 64;

impl Default for ConnCfg {
    /// hub_conn_cfg_defaults().
    fn default() -> Self {
        ConnCfg {
            preauth: CONSOLE_MAX_PREAUTH as i32,
            preauthip: SSH_DEF_PREAUTHIP,
            sessions: CONSOLE_MAX_SESSIONS as i32,
            grace: CONSOLE_LOGIN_GRACE as i32,
            authtries: CONSOLE_MAX_AUTH_TRIES as i32,
            idle: CONSOLE_IDLE_TIMEOUT as i32,
            authfail_n: SSH_DEF_AUTHFAIL_N,
            authfail_s: SSH_DEF_AUTHFAIL_S,
            connect_n: SSH_DEF_CONNECT_N,
            connect_s: SSH_DEF_CONNECT_S,
            block: SSH_DEF_BLOCK,
            cmdrate_n: SSH_DEF_CMDRATE_N,
            cmdrate_s: SSH_DEF_CMDRATE_S,
            perip: MAX_CONNECTIONS_PER_IP,
            churn_n: CHURN_MAX_CONNS,
            churn_s: CHURN_WINDOW_SEC as i32,
            churn_block: CHURN_BLOCK_SEC as i32,
            fail_n: MAX_FAILED_AUTH_ATTEMPTS,
            fail_s: FAILED_AUTH_RESET_TIME as i32,
            fail_block: FAILED_AUTH_BLOCK_DURATION as i32,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Ssh,
    Conn,
}

impl Group {
    pub fn name(self) -> &'static str {
        match self {
            Group::Ssh => "ssh",
            Group::Conn => "conn",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetResult {
    Ok,
    Unknown,
    /// The reason, as the console shows it.
    Bad(String),
}

type Slot = fn(&mut ConnCfg) -> &mut i32;

/// One setting of the table: a name, one to three integer parts.
struct CSet {
    group: Group,
    name: &'static str,
    parts: usize,
    slot: [Slot; 3],
    def: [i32; 3],
    lo: [i32; 3],
    hi: [i32; 3],
    /// Shown in errors.
    range: &'static str,
}

fn nil(c: &mut ConnCfg) -> &mut i32 {
    &mut c.preauth
}

#[rustfmt::skip]
static SETS: &[CSet] = &[
    CSet { group: Group::Ssh, name: "preauth", parts: 1,
           slot: [|c| &mut c.preauth, nil, nil],
           def: [CONSOLE_MAX_PREAUTH as i32, 0, 0], lo: [1, 0, 0], hi: [CONSOLE_MAX_PREAUTH_CAP, 0, 0],
           range: "1 to 64" },
    CSet { group: Group::Ssh, name: "preauthip", parts: 1,
           slot: [|c| &mut c.preauthip, nil, nil],
           def: [SSH_DEF_PREAUTHIP, 0, 0], lo: [1, 0, 0], hi: [CONSOLE_MAX_PREAUTH_CAP, 0, 0],
           range: "1 to the preauth value" },
    CSet { group: Group::Ssh, name: "sessions", parts: 1,
           slot: [|c| &mut c.sessions, nil, nil],
           def: [CONSOLE_MAX_SESSIONS as i32, 0, 0], lo: [1, 0, 0], hi: [32, 0, 0], range: "1 to 32" },
    CSet { group: Group::Ssh, name: "grace", parts: 1,
           slot: [|c| &mut c.grace, nil, nil],
           def: [CONSOLE_LOGIN_GRACE as i32, 0, 0], lo: [5, 0, 0], hi: [120, 0, 0], range: "5 to 120 seconds" },
    CSet { group: Group::Ssh, name: "authtries", parts: 1,
           slot: [|c| &mut c.authtries, nil, nil],
           def: [CONSOLE_MAX_AUTH_TRIES as i32, 0, 0], lo: [1, 0, 0], hi: [6, 0, 0], range: "1 to 6" },
    CSet { group: Group::Ssh, name: "idle", parts: 1,
           slot: [|c| &mut c.idle, nil, nil],
           def: [CONSOLE_IDLE_TIMEOUT as i32, 0, 0], lo: [60, 0, 0], hi: [86400, 0, 0],
           range: "60 to 86400 seconds" },
    CSet { group: Group::Ssh, name: "authfail", parts: 2,
           slot: [|c| &mut c.authfail_n, |c| &mut c.authfail_s, nil],
           def: [SSH_DEF_AUTHFAIL_N, SSH_DEF_AUTHFAIL_S, 0], lo: [1, 1, 0], hi: [1000, 86400, 0],
           range: "N:S, N 1 to 1000, S 1 to 86400" },
    CSet { group: Group::Ssh, name: "connect", parts: 2,
           slot: [|c| &mut c.connect_n, |c| &mut c.connect_s, nil],
           def: [SSH_DEF_CONNECT_N, SSH_DEF_CONNECT_S, 0], lo: [2, 1, 0], hi: [1000, 3600, 0],
           range: "N:S, N 2 to 1000, S 1 to 3600" },
    CSet { group: Group::Ssh, name: "block", parts: 1,
           slot: [|c| &mut c.block, nil, nil],
           def: [SSH_DEF_BLOCK, 0, 0], lo: [30, 0, 0], hi: [SSH_BLOCK_MAX, 0, 0],
           range: "30 to 86400 seconds" },
    CSet { group: Group::Ssh, name: "cmdrate", parts: 2,
           slot: [|c| &mut c.cmdrate_n, |c| &mut c.cmdrate_s, nil],
           def: [SSH_DEF_CMDRATE_N, SSH_DEF_CMDRATE_S, 0], lo: [1, 1, 0], hi: [1000, 3600, 0],
           range: "N:S, N 1 to 1000, S 1 to 3600" },
    CSet { group: Group::Conn, name: "perip", parts: 1,
           slot: [|c| &mut c.perip, nil, nil],
           def: [MAX_CONNECTIONS_PER_IP, 0, 0], lo: [2, 0, 0], hi: [64, 0, 0], range: "2 to 64" },
    CSet { group: Group::Conn, name: "churn", parts: 3,
           slot: [|c| &mut c.churn_n, |c| &mut c.churn_s, |c| &mut c.churn_block],
           def: [CHURN_MAX_CONNS, CHURN_WINDOW_SEC as i32, CHURN_BLOCK_SEC as i32],
           lo: [2, 1, 30], hi: [1000, 3600, SSH_BLOCK_MAX],
           range: "N:S[:B], N 2 to 1000, S 1 to 3600, B 30 to 86400" },
    CSet { group: Group::Conn, name: "authfail", parts: 3,
           slot: [|c| &mut c.fail_n, |c| &mut c.fail_s, |c| &mut c.fail_block],
           def: [MAX_FAILED_AUTH_ATTEMPTS, FAILED_AUTH_RESET_TIME as i32,
                 FAILED_AUTH_BLOCK_DURATION as i32],
           lo: [1, 1, 30], hi: [1000, 86400, SSH_BLOCK_MAX],
           range: "N:S[:B], N 1 to 1000, S 1 to 86400, B 30 to 86400" },
];

fn find_set(group: Group, name: &str) -> Option<&'static CSet> {
    SETS.iter().find(|s| s.group == group && s.name == name)
}

fn values(c: &ConnCfg, s: &CSet) -> [i32; 3] {
    let mut copy = *c;
    let mut v = [0i32; 3];
    for (k, out) in v.iter_mut().enumerate().take(s.parts) {
        *out = *(s.slot[k])(&mut copy);
    }
    v
}

fn fmt_value(s: &CSet, v: &[i32; 3]) -> String {
    match s.parts {
        1 => format!("{}", v[0]),
        2 => format!("{}:{}", v[0], v[1]),
        _ => format!("{}:{}:{}", v[0], v[1], v[2]),
    }
}

/// hub_conn_cfg_count().
pub fn count(group: Group) -> usize {
    SETS.iter().filter(|s| s.group == group).count()
}

/// hub_conn_cfg_name().
pub fn name(group: Group, idx: usize) -> Option<&'static str> {
    SETS.iter()
        .filter(|s| s.group == group)
        .nth(idx)
        .map(|s| s.name)
}

/// hub_conn_cfg_default(): the built-in value as text.
pub fn default_text(group: Group, name: &str) -> Option<String> {
    find_set(group, name).map(|s| fmt_value(s, &s.def))
}

impl ConnCfg {
    /// hub_conn_cfg_get(): the current value as text.
    pub fn get(&self, group: Group, name: &str) -> Option<String> {
        find_set(group, name).map(|s| fmt_value(s, &values(self, s)))
    }

    /// hub_conn_cfg_is_default().
    pub fn is_default(&self, group: Group, name: &str) -> bool {
        match find_set(group, name) {
            Some(s) => values(self, s)[..s.parts] == s.def[..s.parts],
            None => true,
        }
    }

    /// hub_conn_cfg_preauthip(): the per-address login limit actually
    /// enforced, never above the total.
    pub fn preauthip(&self) -> i32 {
        self.preauthip.min(self.preauth)
    }

    /// hub_conn_cfg_set(): `value` None = back to the built-in.
    pub fn set(&mut self, group: Group, name: &str, value: Option<&str>) -> SetResult {
        let Some(s) = find_set(group, name) else {
            return SetResult::Unknown;
        };
        let cur = values(self, s);
        let nv = match value {
            None => s.def,
            Some("default") => s.def,
            Some(v) => {
                let Some(nv) = parse_value(s, v, &cur) else {
                    return SetResult::Bad(format!(
                        "{} {} takes {}",
                        group.name(),
                        s.name,
                        s.range
                    ));
                };
                // preauthip cannot exceed preauth
                if group == Group::Ssh && s.name == "preauthip" && nv[0] > self.preauth {
                    return SetResult::Bad(format!(
                        "ssh preauthip takes 1 to {} (the preauth value)",
                        self.preauth
                    ));
                }
                nv
            }
        };
        for (k, v) in nv.iter().enumerate().take(s.parts) {
            *(s.slot[k])(self) = *v;
        }
        SetResult::Ok
    }

    /// hub_conn_cfg_load(): a config line body "<name>|<value>"; false (and
    /// nothing changed) if the name or value is not valid, so a damaged file
    /// never loosens a limit.
    pub fn load(&mut self, group: Group, body: &str) -> bool {
        if body.len() >= 96 {
            return false;
        }
        let Some((n, v)) = body.split_once('|') else {
            return false;
        };
        if v == "default" {
            return false;
        }
        self.set(group, n, Some(v)) == SetResult::Ok
    }

    /// hub_conn_cfg_lines(): config lines for everything that differs from
    /// the built-ins.
    pub fn lines(&self) -> String {
        let mut out = String::new();
        for g in [Group::Ssh, Group::Conn] {
            for s in SETS.iter().filter(|s| s.group == g) {
                if self.is_default(g, s.name) {
                    continue;
                }
                let v = fmt_value(s, &values(self, s));
                out.push_str(&format!("{}|{}|{}\n", g.name(), s.name, v));
            }
        }
        out
    }

    /// hub_conn_cfg_fix(): make the combination coherent (a hand-edited file).
    pub fn fix(&mut self) {
        if self.preauthip > self.preauth {
            self.preauthip = self.preauth;
        }
    }
}

/// Strict "N", "N:S" or "N:S:B": decimal digits only, each part inside its
/// range.  A two-part value for a three-part setting keeps the current third
/// part.
fn parse_value(s: &CSet, input: &str, cur: &[i32; 3]) -> Option<[i32; 3]> {
    if input.is_empty() || input.len() > 40 {
        return None;
    }
    let mut out = [0i32; 3];
    let mut n = 0;
    for p in input.split(':') {
        if n >= 3 {
            return None;
        }
        out[n] = parse_uint(p, 1_000_000)? as i32;
        n += 1;
    }
    if n + 1 == s.parts && s.parts == 3 {
        out[n] = cur[2];
        n += 1;
    }
    if n != s.parts {
        return None;
    }
    for (k, v) in out.iter().enumerate().take(s.parts) {
        if *v < s.lo[k] || *v > s.hi[k] {
            return None;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The SSH address table (D26)
// ---------------------------------------------------------------------------

/// One address in the SSH-only table: refused logins and the connect window
/// of connections that sniffed as SSH.  Separate from `IpRateLimit`, so an
/// admin's mistyped keys never block a bot or peer on the same address.
#[derive(Clone, Debug, Default)]
pub struct SshIp {
    pub ip: String,
    /// Connect window.
    pub win_start: i64,
    pub conn_n: i32,
    /// Refused-login window.
    pub fail_last: i64,
    pub fail_n: i32,
    pub blocked_until: i64,
    /// Start of the latest block (escalation memory).
    pub last_block: i64,
    /// Blocks in a row within SSH_BLOCK_MEMORY.
    pub level: i32,
    pub last_seen: i64,
    /// Latest successful console auth (0 = never).
    pub last_success: i64,
}

fn ssh_find(tab: &mut Vec<SshIp>, ip: &str, now: i64) -> usize {
    if let Some(i) = tab.iter().position(|e| e.ip == ip) {
        tab[i].last_seen = now;
        return i;
    }
    let fresh = SshIp {
        ip: crate::cstr::trunc_string(ip, 64),
        last_seen: now,
        win_start: now,
        ..Default::default()
    };
    if tab.len() < MAX_SSH_IPS {
        tab.push(fresh);
        return tab.len() - 1;
    }
    // Full: recycle an address that is not blocked, longest unseen; failing
    // that, the one whose block ends first.  Never refuses a newcomer.
    let mut slot: Option<usize> = None;
    for (i, e) in tab.iter().enumerate() {
        if e.blocked_until > now {
            continue;
        }
        if slot.is_none_or(|s| e.last_seen < tab[s].last_seen) {
            slot = Some(i);
        }
    }
    let slot = slot.unwrap_or_else(|| {
        let mut s = 0;
        for (i, e) in tab.iter().enumerate().skip(1) {
            if e.blocked_until < tab[s].blocked_until {
                s = i;
            }
        }
        s
    });
    tab[slot] = fresh;
    slot
}

/// Block length for the next block of this address: the base, doubled for
/// each block already served within SSH_BLOCK_MEMORY, capped at SSH_BLOCK_MAX.
fn start_block(e: &mut SshIp, cfg: &ConnCfg, now: i64) -> i32 {
    if e.last_block > 0 && now - e.last_block < SSH_BLOCK_MEMORY {
        if e.level < 30 {
            e.level += 1;
        }
    } else {
        e.level = 0;
    }
    let mut secs = i64::from(cfg.block);
    let mut i = 0;
    while i < e.level && secs < i64::from(SSH_BLOCK_MAX) {
        secs *= 2;
        i += 1;
    }
    secs = secs.min(i64::from(SSH_BLOCK_MAX));
    e.blocked_until = now + secs;
    e.last_block = now;
    e.conn_n = 0;
    e.fail_n = 0;
    secs as i32
}

/// hub_ssh_table_connect(): a connection that sniffed as SSH.  `(admit,
/// new_block)`: false = refuse it; `new_block` is the length of a block this
/// very call started (0 otherwise).
pub fn ssh_table_connect(tab: &mut Vec<SshIp>, cfg: &ConnCfg, ip: &str, now: i64) -> (bool, i32) {
    let i = ssh_find(tab, ip, now);
    let e = &mut tab[i];
    if e.blocked_until > now {
        return (false, 0);
    }
    if e.blocked_until > 0 {
        // expired: a fresh start
        e.blocked_until = 0;
        e.conn_n = 0;
        e.fail_n = 0;
    }
    // An address that logged into the console lately is not held to the
    // connect window (a tightened limit must not lock its admin out); a block
    // it earned by refused logins, checked above, still stands.
    if e.last_success > 0 && now - e.last_success < SSH_SUCCESS_MEMORY {
        return (true, 0);
    }
    if now - e.win_start >= i64::from(cfg.connect_s) {
        e.win_start = now;
        e.conn_n = 0;
    }
    e.conn_n += 1;
    if e.conn_n > cfg.connect_n {
        return (false, start_block(e, cfg, now));
    }
    (true, 0)
}

/// hub_ssh_table_success(): a console login by key succeeded from `ip`.
pub fn ssh_table_success(tab: &mut Vec<SshIp>, ip: &str, now: i64) {
    let i = ssh_find(tab, ip, now);
    tab[i].last_success = now;
}

/// hub_ssh_table_peek(): the address's row, or None (never creates one).
pub fn ssh_table_peek<'a>(tab: &'a [SshIp], ip: &str) -> Option<&'a SshIp> {
    tab.iter().find(|e| e.ip == ip)
}

/// hub_ssh_table_recent_ok(): `ip` authenticated a console within
/// SSH_SUCCESS_MEMORY.
pub fn ssh_table_recent_ok(tab: &[SshIp], ip: &str, now: i64) -> bool {
    ssh_table_peek(tab, ip)
        .is_some_and(|e| e.last_success > 0 && now - e.last_success < SSH_SUCCESS_MEMORY)
}

/// hub_ssh_table_failed(): a refused SSH login (FAIL frame).  Returns the
/// length of a block this call started (0 otherwise).
pub fn ssh_table_failed(tab: &mut Vec<SshIp>, cfg: &ConnCfg, ip: &str, now: i64) -> i32 {
    let i = ssh_find(tab, ip, now);
    let e = &mut tab[i];
    if e.blocked_until > now {
        return 0;
    }
    if e.blocked_until > 0 {
        e.blocked_until = 0;
        e.conn_n = 0;
        e.fail_n = 0;
    }
    if e.fail_last > 0 && now - e.fail_last > i64::from(cfg.authfail_s) {
        e.fail_n = 0;
    }
    e.fail_n += 1;
    e.fail_last = now;
    if e.fail_n >= cfg.authfail_n {
        return start_block(e, cfg, now);
    }
    0
}

// ---------------------------------------------------------------------------
// Eviction (console thread, on its own copies)
// ---------------------------------------------------------------------------

/// hub_ssh_evict_pick(): all preauth slots taken and `new_ip` wants one: the
/// victim is the oldest login in progress of the address holding the most
/// slots (the newcomer's own address counts one more), so a flood from a few
/// addresses cannot keep anyone else out.  Ties go to the older session.
/// None when there are no logins.
pub fn evict_pick(logins: &[(&str, i64)], new_ip: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut best_cnt = 0usize;
    for (i, (ip, start)) in logins.iter().enumerate() {
        let mut cnt = usize::from(*ip == new_ip);
        cnt += logins.iter().filter(|(o, _)| o == ip).count();
        let better = match best {
            None => true,
            Some(b) => cnt > best_cnt || (cnt == best_cnt && *start < logins[b].1),
        };
        if better {
            best = Some(i);
            best_cnt = cnt;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evict_takes_oldest_of_the_fullest_address() {
        let l = [("a", 10), ("b", 5), ("a", 20), ("c", 1)];
        // "a" holds two slots: its older login (index 0) goes.
        assert_eq!(evict_pick(&l, "z"), Some(0));
        // The newcomer's address counts one more: "b" ties "a" at 2 and the
        // older start (b, 5) wins the tie.
        assert_eq!(evict_pick(&l, "b"), Some(1));
        // The newcomer's address "c" makes it 2, a tie with "a": c is oldest.
        assert_eq!(evict_pick(&l, "c"), Some(3));
        assert_eq!(evict_pick(&[], "a"), None);
    }

    #[test]
    fn block_doubles_per_repeat_and_caps() {
        let cfg = ConnCfg {
            authfail_n: 1,
            ..Default::default()
        };
        let mut t = Vec::new();
        let t0 = 1_000_000;
        assert_eq!(ssh_table_failed(&mut t, &cfg, "10.0.0.1", t0), 300);
        // Inside the block nothing new starts.
        assert_eq!(ssh_table_failed(&mut t, &cfg, "10.0.0.1", t0 + 10), 0);
        assert_eq!(ssh_table_failed(&mut t, &cfg, "10.0.0.1", t0 + 301), 600);
        assert_eq!(ssh_table_failed(&mut t, &cfg, "10.0.0.1", t0 + 1000), 1200);
        // Keep failing just after each block ends: 2400, 4800, ... then the
        // 24 h ceiling.
        let mut now = t0 + 1000;
        let mut last: i32 = 1200;
        let mut seen = Vec::new();
        while last < SSH_BLOCK_MAX {
            now += i64::from(last) + 1;
            last = ssh_table_failed(&mut t, &cfg, "10.0.0.1", now);
            seen.push(last);
        }
        assert_eq!(seen.first(), Some(&2400));
        assert_eq!(seen.last(), Some(&SSH_BLOCK_MAX));
        // A repeat a full memory window after the latest block starts over.
        now += i64::from(SSH_BLOCK_MAX) + 1;
        assert_eq!(ssh_table_failed(&mut t, &cfg, "10.0.0.1", now), 300);
    }

    #[test]
    fn connect_window_blocks_the_seventh_connection() {
        let cfg = ConnCfg::default();
        let mut t = Vec::new();
        for _ in 0..6 {
            assert_eq!(ssh_table_connect(&mut t, &cfg, "10.0.0.2", 500), (true, 0));
        }
        assert_eq!(
            ssh_table_connect(&mut t, &cfg, "10.0.0.2", 500),
            (false, 300)
        );
        assert_eq!(ssh_table_connect(&mut t, &cfg, "10.0.0.2", 501), (false, 0));
    }

    #[test]
    fn parse_floors_and_ranges() {
        let mut c = ConnCfg::default();
        assert_eq!(
            c.set(Group::Ssh, "preauth", Some("0")),
            SetResult::Bad("ssh preauth takes 1 to 64".into())
        );
        assert_eq!(
            c.set(Group::Ssh, "preauth", Some("65")),
            SetResult::Bad("ssh preauth takes 1 to 64".into())
        );
        assert!(matches!(
            c.set(Group::Ssh, "connect", Some("1:60")),
            SetResult::Bad(_)
        ));
        assert!(matches!(
            c.set(Group::Ssh, "connect", Some("6:0")),
            SetResult::Bad(_)
        ));
        assert!(matches!(
            c.set(Group::Ssh, "connect", Some("6")),
            SetResult::Bad(_)
        ));
        assert!(matches!(
            c.set(Group::Ssh, "connect", Some("6::60")),
            SetResult::Bad(_)
        ));
        assert!(matches!(
            c.set(Group::Conn, "perip", Some("1")),
            SetResult::Bad(_)
        ));
        assert!(matches!(
            c.set(Group::Conn, "churn", Some("1:10")),
            SetResult::Bad(_)
        ));
        assert!(matches!(
            c.set(Group::Conn, "churn", Some("30:10:29")),
            SetResult::Bad(_)
        ));
        assert!(matches!(
            c.set(Group::Conn, "churn", Some("-3:10")),
            SetResult::Bad(_)
        ));
        assert_eq!(c.set(Group::Ssh, "nope", Some("1")), SetResult::Unknown);
        // preauthip may not pass preauth
        assert_eq!(c.set(Group::Ssh, "preauth", Some("4")), SetResult::Ok);
        assert!(matches!(
            c.set(Group::Ssh, "preauthip", Some("5")),
            SetResult::Bad(_)
        ));
        assert_eq!(c.set(Group::Ssh, "preauthip", Some("3")), SetResult::Ok);
        // "N:S" keeps the third part of a three-part setting
        assert_eq!(c.set(Group::Conn, "churn", Some("40:20:90")), SetResult::Ok);
        assert_eq!(c.set(Group::Conn, "churn", Some("50:5")), SetResult::Ok);
        assert_eq!(c.get(Group::Conn, "churn").as_deref(), Some("50:5:90"));
        assert_eq!(c.set(Group::Conn, "churn", None), SetResult::Ok);
        assert!(c.is_default(Group::Conn, "churn"));
    }

    #[test]
    fn config_lines_round_trip() {
        let mut c = ConnCfg::default();
        assert_eq!(c.lines(), "");
        c.set(Group::Ssh, "authfail", Some("5:600"));
        c.set(Group::Conn, "perip", Some("9"));
        assert_eq!(c.lines(), "ssh|authfail|5:600\nconn|perip|9\n");
        let mut d = ConnCfg::default();
        assert!(d.load(Group::Ssh, "authfail|5:600"));
        assert!(d.load(Group::Conn, "perip|9"));
        assert!(!d.load(Group::Ssh, "block|5"));
        assert!(!d.load(Group::Ssh, "block|default"));
        assert_eq!(c, d);
    }
}
