//! Rate limiting and IP access control (hub_logic.c).
//!
//! Three independent gates sit on `accept()`:
//!   * the allow/deny lists — local policy, never replicated;
//!   * a per-IP concurrency cap;
//!   * D1's churn window, which catches a connect/close flood that never
//!     exceeds the concurrency cap and never fails an auth.
//!
//! Plus a failed-auth counter that temporarily blocks an address once it has
//! burned its allowance.  The limits are `HubState::conn_cfg` (`hub set conn`,
//! built-ins in `consts`); the SSH-only table is in `connlimits`.

use std::net::Ipv4Addr;

use crate::connlimits;
use crate::consts::*;
use crate::cstr::now;

use crate::state::{HubState, IpAcl, IpAclAdd, IpRateLimit};

/// The slot an address would take in the rate-limit table: its own entry
/// (`Some((i, false))`), a free one or the entry idle longest (no
/// connection open, not blocked) (`Some((i, true))`).  None when every
/// entry is open or blocked.  Without the reuse, MAX_IP_RATE_LIMITS
/// addresses inside the hourly prune left every new one untracked.
fn ip_limit_slot(state: &HubState, ip: &str, t: i64) -> Option<(usize, bool)> {
    if let Some(i) = state.ip_limits.iter().position(|e| e.ip == ip) {
        return Some((i, false));
    }
    if state.ip_limits.len() < MAX_IP_RATE_LIMITS {
        return Some((state.ip_limits.len(), true));
    }
    let mut slot: Option<(usize, i64)> = None;
    for (i, e) in state.ip_limits.iter().enumerate() {
        if e.active_connections > 0 || (e.blocked_until > 0 && t < e.blocked_until) {
            continue;
        }
        let last = e
            .first_seen
            .max(e.last_failed_auth)
            .max(e.churn_window_start);
        if slot.is_none_or(|(_, oldest)| last < oldest) {
            slot = Some((i, last));
        }
    }
    slot.map(|(i, _)| (i, true))
}

/// find_or_create_ip_limit(): the index of this IP's entry, or None when the
/// table is full of open or blocked entries.
fn find_or_create(state: &mut HubState, ip: &str) -> Option<usize> {
    let t = now();
    let (i, fresh) = ip_limit_slot(state, ip, t)?;
    if !fresh {
        return Some(i);
    }
    let entry = IpRateLimit {
        ip: crate::cstr::trunc_string(ip, 64),
        first_seen: t,
        churn_window_start: t,
        ..Default::default()
    };
    if i == state.ip_limits.len() {
        state.ip_limits.push(entry);
    } else {
        state.ip_limits[i] = entry;
    }
    Some(i)
}

/// 13b: a bot or peer authenticated from `ip`.
pub fn known_ip_note(state: &mut HubState, ip: &str) {
    if ip.is_empty() {
        return;
    }
    let t = now();
    if let Some(e) = state.known_ips.iter_mut().find(|e| e.0 == ip) {
        e.1 = t;
    } else if state.known_ips.len() < MAX_KNOWN_IPS {
        state.known_ips.push((crate::cstr::trunc_string(ip, 64), t));
    } else if let Some(e) = state.known_ips.iter_mut().min_by_key(|e| e.1) {
        *e = (crate::cstr::trunc_string(ip, 64), t);
    }
}

/// An address this hub has reason to trust: a configured peer, a bot in the
/// roster (any hub's), a bot or peer that authenticated here lately, or a
/// console login within SSH_SUCCESS_MEMORY.
fn ip_known(state: &HubState, ip: &str, t: i64) -> bool {
    if state.peers.iter().any(|p| p.ip == ip || p.remote_ip == ip) {
        return true;
    }
    if let Some(e) = state.known_ips.iter().find(|e| e.0 == ip) {
        return t - e.1 < KNOWN_IP_MEMORY;
    }
    if state.roster.iter().any(|r| r.ip == ip) {
        return true;
    }
    connlimits::ssh_table_recent_ok(&state.ssh_ips, ip, t)
}

fn startup_refused(state: &mut HubState, t: i64, ip: &str, why: &str) {
    if t - state.startup_logged >= STARTUP_LOG_EVERY {
        if state.startup_unlogged > 0 {
            crate::hlog_warning!(
                "[RATE_LIMIT] Connection from {ip} refused ({why}); {} more refused in the last {}s\n",
                state.startup_unlogged,
                t - state.startup_logged
            );
        } else {
            crate::hlog_warning!("[RATE_LIMIT] Connection from {ip} refused ({why})\n");
        }
        state.startup_logged = t;
        state.startup_unlogged = 0;
    } else {
        state.startup_unlogged += 1;
    }
}

/// hub_startup_admit() (13b): the gate before is_ip_allowed.  Known
/// addresses always pass; an unknown one is refused while the rate-limit
/// table has no room for it (rather than let through untracked), and
/// otherwise goes through a random early drop on the connections not yet
/// authenticated (`hub set conn startups`), so a flood of stalled
/// handshakes cannot hold every slot.
pub fn startup_admit(state: &mut HubState, ip: &str) -> bool {
    if trusted_loopback(state, ip) {
        return true;
    }
    let t = now();
    if ip_known(state, ip, t) {
        return true;
    }
    if ip_limit_slot(state, ip, t).is_none() {
        startup_refused(state, t, ip, "unknown address, rate-limit table full");
        return false;
    }
    let open = state
        .clients
        .iter()
        .filter(|c| c.inbound && !c.authenticated)
        .count() as i32;
    let cc = state.conn_cfg;
    let start = cc.startups_start;
    let full = cc.startups_full.max(start);
    if open < start {
        return true;
    }
    let mut drop = true;
    if open < full {
        let p = cc.startups_rate + (100 - cc.startups_rate) * (open - start) / (full - start);
        let mut r = [0u8; 4];
        if crate::crypto::random_bytes(&mut r) {
            drop = (u32::from_ne_bytes(r) % 100) < p as u32;
        }
    }
    if drop {
        let why = format!("unknown address, {open} connections not yet authenticated");
        startup_refused(state, t, ip, &why);
    }
    !drop
}

/// D3: loopback is exempt only when explicitly trusted.  The default is to
/// treat 127.0.0.1/::1 like any other IP, so a local / SSRF / co-tenant
/// source cannot bypass per-IP limits.
pub fn trusted_loopback(state: &HubState, ip: &str) -> bool {
    state.trust_loopback && (ip == "127.0.0.1" || ip == "::1")
}

/// is_ip_allowed(): the per-accept gate.  Each call is exactly one new
/// connection attempt, which is what makes the churn window meaningful.
pub fn is_ip_allowed(state: &mut HubState, ip: &str) -> bool {
    if trusted_loopback(state, ip) {
        return true;
    }
    // Untracked: only a known address gets here (13b, startup_admit).
    let Some(i) = find_or_create(state, ip) else {
        return true;
    };
    let t = now();

    if state.ip_limits[i].blocked_until > 0 && t < state.ip_limits[i].blocked_until {
        crate::hlog_warning!(
            "[RATE_LIMIT] IP {ip} is blocked until {}\n",
            state.ip_limits[i].blocked_until
        );
        return false;
    }
    if state.ip_limits[i].blocked_until > 0 && t >= state.ip_limits[i].blocked_until {
        state.ip_limits[i].blocked_until = 0;
        state.ip_limits[i].failed_auth_count = 0;
    }

    // D1: churn-based throttle.  Count attempts in a sliding window; a
    // connect/close flood trips a temporary block here even though it never
    // exceeds the concurrency limit or fails auth.
    let cc = state.conn_cfg; // hub set conn
    // An address with a console login in the last 24 h is not held to the
    // churn limit (a tightened limit must not lock its admin out); the block
    // above (authfail, or a churn block from before) still applies.
    if connlimits::ssh_table_recent_ok(&state.ssh_ips, ip, t) {
        return state.ip_limits[i].active_connections < cc.perip;
    }
    if t - state.ip_limits[i].churn_window_start >= i64::from(cc.churn_s) {
        state.ip_limits[i].churn_window_start = t;
        state.ip_limits[i].churn_count = 0;
    }
    state.ip_limits[i].churn_count += 1;
    if state.ip_limits[i].churn_count > cc.churn_n {
        state.ip_limits[i].blocked_until = t + i64::from(cc.churn_block);
        crate::hlog_warning!(
            "[RATE_LIMIT] IP {ip} connection churn flood ({} conns/{}s) — blocked {}s\n",
            state.ip_limits[i].churn_count,
            cc.churn_s,
            cc.churn_block
        );
        return false;
    }

    if state.ip_limits[i].active_connections >= cc.perip {
        crate::hlog_warning!(
            "[RATE_LIMIT] IP {ip} exceeded connection limit ({}/{})\n",
            state.ip_limits[i].active_connections,
            cc.perip
        );
        return false;
    }
    true
}

pub fn increment_active_connections(state: &mut HubState, ip: &str) {
    if let Some(i) = find_or_create(state, ip) {
        state.ip_limits[i].active_connections += 1;
    }
}

pub fn decrement_active_connections(state: &mut HubState, ip: &str) {
    if let Some(e) = state.ip_limits.iter_mut().find(|e| e.ip == ip)
        && e.active_connections > 0
    {
        e.active_connections -= 1;
    }
}

/// record_failed_auth().
pub fn record_failed_auth(state: &mut HubState, ip: &str) {
    if trusted_loopback(state, ip) {
        return;
    }
    let Some(i) = find_or_create(state, ip) else {
        return;
    };
    let t = now();

    // Reset the counter if the last failure was over the window ago.
    let cc = state.conn_cfg; // hub set conn
    if t - state.ip_limits[i].last_failed_auth > i64::from(cc.fail_s) {
        state.ip_limits[i].failed_auth_count = 0;
    }
    state.ip_limits[i].failed_auth_count += 1;
    state.ip_limits[i].last_failed_auth = t;

    crate::hlog_warning!(
        "[AUTH_FAIL] IP {ip} failed auth (attempt {}/{})\n",
        state.ip_limits[i].failed_auth_count,
        cc.fail_n
    );

    if state.ip_limits[i].failed_auth_count >= cc.fail_n {
        state.ip_limits[i].blocked_until = t + i64::from(cc.fail_block);
        crate::hlog_warning!(
            "[AUTH_BLOCK] IP {ip} blocked for {} seconds (too many failed attempts)\n",
            cc.fail_block
        );
    }
}

/// hub_console_ssh_failed(): a refused SSH login (FAIL frame), counted in the
/// SSH-only table (D26), so an admin's mistyped keys never block a bot or
/// peer on the same address.
pub fn ssh_failed(state: &mut HubState, ip: &str) {
    if trusted_loopback(state, ip) {
        return;
    }
    let blk = connlimits::ssh_table_failed(&mut state.ssh_ips, &state.conn_cfg, ip, now());
    if blk > 0 {
        crate::hlog_warning!(
            "[AUTH_BLOCK] SSH from {ip} blocked for {blk} seconds (too many refused logins)\n"
        );
    }
}

/// hub_console_ssh_admit(): the connection from `ip` just sniffed as SSH: the
/// console scope of the ACL (D27), then the SSH block and connect window.
/// False = close it.
pub fn ssh_admit(state: &mut HubState, ip: &str) -> bool {
    if !ip_acl_permits_console(state, ip) {
        crate::hlog_warning!(
            "[ACCESS_CONTROL] SSH from {ip} refused (console scope of the allow/deny lists)\n"
        );
        return false;
    }
    if trusted_loopback(state, ip) {
        return true;
    }
    let (ok, blk) = connlimits::ssh_table_connect(&mut state.ssh_ips, &state.conn_cfg, ip, now());
    if ok {
        return true;
    }
    if blk > 0 {
        crate::hlog_warning!(
            "[RATE_LIMIT] SSH from {ip} connecting too fast; blocked for {blk} seconds\n"
        );
    } else {
        crate::hlog_info!("[RATE_LIMIT] SSH from {ip} refused (blocked)\n");
    }
    false
}

/// cleanup_old_ip_limits(): drop idle, unblocked entries older than an hour.
pub fn cleanup_old_ip_limits(state: &mut HubState) {
    let t = now();
    state.ip_limits.retain(|e| {
        !(e.active_connections == 0 && e.blocked_until == 0 && t - e.first_seen > 3600)
    });
}

// ---------------------------------------------------------------------------
// IP access control
// ---------------------------------------------------------------------------

/// hub_ip_acl_parse(): "a.b.c.d" or "a.b.c.d/N" (N = 0..32, no sign or
/// leading zero) into a canonical entry (added = 0).  None on anything else.
pub fn ip_acl_parse(input: &str) -> Option<IpAcl> {
    if input.is_empty() || input.len() >= IP_ACL_PATTERN_MAX {
        return None;
    }
    let (addr, prefix) = match input.find('/') {
        None => (input, 32u32),
        Some(i) => {
            // 1-2 decimal digits, no sign/space/leading zero: atoi() used to
            // turn "10.0.0.0/" or "/x" into prefix 0, which matches every
            // address.
            let p = &input[i + 1..];
            let b = p.as_bytes();
            let ok = match b.len() {
                1 => b[0].is_ascii_digit(),
                2 => b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[0] != b'0',
                _ => false,
            };
            if !ok {
                return None;
            }
            let prefix: u32 = p.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            (&input[..i], prefix)
        }
    };

    // Strict dotted quad: no short forms, octal or spaces.
    let a: Ipv4Addr = addr.parse().ok()?;
    let mask: u32 = if prefix == 0 {
        0
    } else {
        0xFFFF_FFFFu32 << (32 - prefix)
    };
    let net = u32::from(a) & mask;

    let mut out = IpAcl {
        net,
        mask,
        added: 0,
        ..Default::default()
    };
    let canon = Ipv4Addr::from(net);
    let text = if prefix == 32 {
        canon.to_string()
    } else {
        format!("{canon}/{prefix}")
    };
    if !out.set_pattern(&text) {
        return None;
    }
    Some(out)
}

/// Entries of one scope: console (D27, applies once the first bytes say SSH)
/// or not (every inbound connection).  The two scopes never mix: an allowlist
/// with only console entries leaves bots and peers unrestricted.
fn ip_acl_match(list: &[IpAcl], addr: u32, console: bool) -> bool {
    list.iter()
        .any(|e| e.console == console && addr & e.mask == e.net)
}

pub fn ip_acl_scope_count(list: &[IpAcl], console: bool) -> usize {
    list.iter().filter(|e| e.console == console).count()
}

/// 0 = permitted, 1 = on the denylist, 2 = not on a non-empty allowlist.
fn ip_acl_verdict(state: &HubState, ip: &str, console: bool) -> i32 {
    let parsed = ip.parse::<Ipv4Addr>().ok();
    let addr = parsed.map_or(0u32, u32::from);

    // An address that does not parse is refused whenever either list has
    // entries: policy that cannot be evaluated is policy that failed.
    if ip_acl_scope_count(&state.ip_deny, console) > 0
        && (parsed.is_none() || ip_acl_match(&state.ip_deny, addr, console))
    {
        return 1;
    }
    if ip_acl_scope_count(&state.ip_allow, console) > 0
        && (parsed.is_none() || !ip_acl_match(&state.ip_allow, addr, console))
    {
        return 2;
    }
    0
}

/// hub_ip_acl_permits(): the silent decision.  Deny wins; a non-empty
/// allowlist must match.
pub fn ip_acl_permits(state: &HubState, ip: &str) -> bool {
    ip_acl_verdict(state, ip, false) == 0
}

/// hub_ip_acl_permits_console(): the same decision over the entries written
/// with the `console` word (D27).
pub fn ip_acl_permits_console(state: &HubState, ip: &str) -> bool {
    ip_acl_verdict(state, ip, true) == 0
}

/// check_ip_access_lists(): the accept-time decision, which logs a refusal.
pub fn check_ip_access_lists(state: &HubState, ip: &str) -> bool {
    let verdict = ip_acl_verdict(state, ip, false);
    if verdict == 0 {
        return true;
    }
    crate::hlog_warning!(
        "[ACCESS_CONTROL] IP {ip} denied ({})\n",
        if verdict == 1 {
            "denylist"
        } else {
            "not in allowlist"
        }
    );
    false
}

fn ip_acl_list(state: &mut HubState, list: char) -> Option<&mut Vec<IpAcl>> {
    match list {
        'w' => Some(&mut state.ip_allow),
        'x' => Some(&mut state.ip_deny),
        _ => None,
    }
}

/// hub_ip_acl_add(): refuses a duplicate (same network and prefix) or a full
/// list.
pub fn ip_acl_add(state: &mut HubState, list: char, e: &IpAcl) -> IpAclAdd {
    let Some(l) = ip_acl_list(state, list) else {
        return IpAclAdd::BadList;
    };
    if l.iter().any(|x| x.same_net(e)) {
        return IpAclAdd::Duplicate;
    }
    if l.len() >= MAX_IP_ACL_ENTRIES {
        return IpAclAdd::Full;
    }
    l.push(*e);
    IpAclAdd::Added
}

/// hub_ip_acl_remove(): matches the same way add refuses a duplicate.
pub fn ip_acl_remove(state: &mut HubState, list: char, e: &IpAcl) -> bool {
    let Some(l) = ip_acl_list(state, list) else {
        return false;
    };
    match l.iter().position(|x| x.same_net(e)) {
        Some(i) => {
            l.remove(i);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_parse_is_canonical_and_strict() {
        let e = ip_acl_parse("10.1.2.3").unwrap();
        assert_eq!(e.pattern(), "10.1.2.3");
        assert_eq!(e.mask, 0xFFFF_FFFF);
        // Host bits are cleared and the prefix kept.
        let e = ip_acl_parse("10.1.2.3/8").unwrap();
        assert_eq!(e.pattern(), "10.0.0.0/8");
        let e = ip_acl_parse("0.0.0.0/0").unwrap();
        assert_eq!(e.pattern(), "0.0.0.0/0");
        assert_eq!(e.mask, 0);
        // The shapes that used to read as /0 (i.e. everything).
        assert!(ip_acl_parse("10.0.0.0/").is_none());
        assert!(ip_acl_parse("/8").is_none());
        assert!(ip_acl_parse("10.0.0.0/08").is_none());
        assert!(ip_acl_parse("10.0.0.0/33").is_none());
        assert!(ip_acl_parse("10.0.0.0/2x").is_none());
        assert!(ip_acl_parse("10.0.0").is_none());
        assert!(ip_acl_parse("010.0.0.1").is_none());
        assert!(ip_acl_parse("").is_none());
    }

    #[test]
    fn deny_wins_and_allowlist_is_a_whitelist() {
        let mut s = HubState::new();
        assert!(ip_acl_permits(&s, "203.0.113.5"));
        // An unparseable address is fine while both lists are empty.
        assert!(ip_acl_permits(&s, "not-an-ip"));

        let allow = ip_acl_parse("10.0.0.0/8").unwrap();
        assert_eq!(ip_acl_add(&mut s, 'w', &allow), IpAclAdd::Added);
        assert_eq!(ip_acl_add(&mut s, 'w', &allow), IpAclAdd::Duplicate);
        assert_eq!(ip_acl_add(&mut s, 'q', &allow), IpAclAdd::BadList);
        assert!(ip_acl_permits(&s, "10.2.3.4"));
        assert!(!ip_acl_permits(&s, "203.0.113.5"));
        // Policy that cannot be evaluated is policy that failed.
        assert!(!ip_acl_permits(&s, "not-an-ip"));

        let deny = ip_acl_parse("10.2.0.0/16").unwrap();
        assert_eq!(ip_acl_add(&mut s, 'x', &deny), IpAclAdd::Added);
        assert!(!ip_acl_permits(&s, "10.2.3.4"));
        assert!(ip_acl_permits(&s, "10.3.3.4"));

        assert!(ip_acl_remove(&mut s, 'x', &deny));
        assert!(!ip_acl_remove(&mut s, 'x', &deny));
        assert!(ip_acl_permits(&s, "10.2.3.4"));
    }

    #[test]
    fn churn_window_blocks_a_connect_flood() {
        let mut s = HubState::new();
        for _ in 0..CHURN_MAX_CONNS {
            assert!(is_ip_allowed(&mut s, "203.0.113.9"));
        }
        // One past the window's cap trips the temporary block.
        assert!(!is_ip_allowed(&mut s, "203.0.113.9"));
        assert!(!is_ip_allowed(&mut s, "203.0.113.9"));
    }

    #[test]
    fn concurrency_cap_counts_live_connections() {
        let mut s = HubState::new();
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            assert!(is_ip_allowed(&mut s, "198.51.100.7"));
            increment_active_connections(&mut s, "198.51.100.7");
        }
        assert!(!is_ip_allowed(&mut s, "198.51.100.7"));
        decrement_active_connections(&mut s, "198.51.100.7");
        assert!(is_ip_allowed(&mut s, "198.51.100.7"));
    }

    #[test]
    fn failed_auth_blocks_after_the_cap() {
        let mut s = HubState::new();
        for _ in 0..MAX_FAILED_AUTH_ATTEMPTS {
            record_failed_auth(&mut s, "198.51.100.8");
        }
        assert!(!is_ip_allowed(&mut s, "198.51.100.8"));
    }
}
