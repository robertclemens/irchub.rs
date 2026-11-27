//! Server pool records N|, S| and R| (2.5.4): pool_rec.c in the C hub and bot,
//! rule for rule.  Byte-identical in irchub.rs and ircbot.rs.  Plan:
//! irchub/docs/plans/2026-10-29_server_pool_plan.md §3.  Pure apart from
//! SHA-256: no I/O, no globals.
//!
//! Stored value (the line minus its "N|"/"S|" tag and its trailing |<ts>):
//!   N: <net_id>|<label>|<name>|<aliases csv>|<split_wait min>|<pace_gap s>|<add|del>
//!   S: <uuid>|<net_id>|<host>|<port>|<weight>|<max>|<state>|<seen>|<add|del>
//!   R: <gen 8 hex>|<slot>|<slots>|<pace_gap s>|<uuid>,<uuid>,...
//!      slot (0-based) of slots = the bots of one origin with this first
//!      server; with slots > 1 a dial waits for a second t where
//!      t % (slots * pace_gap) == slot * pace_gap (one host, one clock)
//!      a bot's server order, computed by the hubs (never stored on a hub,
//!      cached by the bot; server order plan 2026-11-24)
//!
//! An S| uuid is derived, never chosen: the first 16 bytes of
//! SHA-256(<net_id> "|" <key>) with the RFC 9562 version-8 / variant bits set,
//! where <key> = lower(host without one trailing '.') ":" port.  Every entry
//! has an explicit port (1..65535): one typed without gets POOL_DEFAULT_PORT,
//! so "host" and "host:6667" are one entry; TLS is port 6697 (the bot's rule).
//! The same server added on any hub or bot is the same record, and a value
//! whose uuid does not match its own net_id/host/port is refused.

use sha2::{Digest, Sha256};

pub const POOL_NET_ID_MAX: usize = 16; // [a-z0-9-], immutable
pub const POOL_NET_LABEL_MAX: usize = 32;
pub const POOL_NET_NAME_MAX: usize = 64; // a NETWORK= value
pub const POOL_NET_ALIASES: usize = 8; // aliases per network
pub const POOL_NET_ALIASES_MAX: usize = POOL_NET_ALIASES * (POOL_NET_NAME_MAX + 1);
pub const POOL_SPLIT_WAIT_MAX: i32 = 1440; // minutes
pub const POOL_PACE_GAP_DEFAULT: i32 = 15; // s between two dials of one server
pub const POOL_PACE_GAP_MAX: i32 = 600; // s; 0 = no pacing
pub const POOL_ORDER_MAX: usize = 64; // servers in one R| order
pub const POOL_ORDER_SLOTS_MAX: i32 = 1000; // bots in one slot group
pub const POOL_HOST_MAX: usize = 253;
pub const POOL_WEIGHT_MAX: i32 = 100;
pub const POOL_MAX_MAX: i32 = 100; // soft cap on bots per entry; 0 = none
pub const POOL_UUID_LEN: usize = 36;
pub const POOL_DEFAULT_NET: &str = "main";
pub const POOL_DEFAULT_PORT: i32 = 6667;

/// One serialized line each at its caps: tag + fields + op + 20-digit stamp +
/// separators + newline, rounded up.
pub const POOL_N_LINE_MAX: usize = 2
    + POOL_NET_ID_MAX
    + POOL_NET_LABEL_MAX
    + POOL_NET_NAME_MAX
    + POOL_NET_ALIASES_MAX
    + 4
    + 3
    + 3
    + 20
    + 16;
pub const POOL_S_LINE_MAX: usize = 2
    + POOL_UUID_LEN
    + POOL_NET_ID_MAX
    + POOL_HOST_MAX
    + 5
    + 3
    + 4
    + 8
    + POOL_NET_NAME_MAX
    + 3
    + 20
    + 16;
pub const POOL_R_LINE_MAX: usize =
    2 + 8 + 4 + 4 + 3 + 4 + POOL_ORDER_MAX * (POOL_UUID_LEN + 1) + 20 + 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PoolState {
    #[default]
    Ok,
    WrongNet,
    Disabled,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolNet {
    pub net_id: String,
    pub label: String,
    pub name: String,
    pub aliases: String,
    pub split_wait: i32,
    /// 0..POOL_PACE_GAP_MAX
    pub pace_gap: i32,
    pub deleted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolSrv {
    pub uuid: String,
    pub net_id: String,
    pub host: String,
    /// 1..65535
    pub port: i32,
    /// 1..POOL_WEIGHT_MAX
    pub weight: i32,
    /// 0..POOL_MAX_MAX, 0 = none
    pub max: i32,
    pub state: PoolState,
    /// NETWORK= that flagged it
    pub seen: String,
    pub deleted: bool,
}

/// A bot's R| server order (C `pool_order_t`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolOrder {
    /// FNV-1a 32 of the rest of the value
    pub generation: u32,
    /// 0..slots-1
    pub slot: i32,
    /// 1..POOL_ORDER_SLOTS_MAX
    pub slots: i32,
    /// the network's pace gap
    pub gap: i32,
    /// 1..POOL_ORDER_MAX server uuids
    pub ids: Vec<String>,
}

/// Exactly `want` '|'-separated fields (the C split_fields; its scratch cap
/// is the line cap).
fn split_fields(value: &str, want: usize, cap: usize) -> Option<Vec<&str>> {
    if value.len() >= cap || value.as_bytes().contains(&0) {
        return None;
    }
    let f: Vec<&str> = value.split('|').collect();
    (f.len() == want).then_some(f)
}

/// A decimal 0..hi with no sign, no leading zero (except "0"), ≤ 5 digits.
fn num_ok(s: &str, hi: i32) -> Option<i32> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 5 || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    let mut v: i32 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + i32::from(c - b'0');
    }
    (v <= hi).then_some(v)
}

fn op_parse(s: &str) -> Option<bool> {
    match s {
        "add" => Some(false),
        "del" => Some(true),
        _ => None,
    }
}

/// A net_id: 1..POOL_NET_ID_MAX of [a-z0-9-].
pub fn net_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= POOL_NET_ID_MAX
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// A host: 1..POOL_HOST_MAX of [A-Za-z0-9.-] not starting with '-' or '.',
/// no "..", at least one alphanumeric; or a bracketed IPv6 literal [hex:.].
pub fn host_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let n = b.len();
    if n == 0 || n > POOL_HOST_MAX {
        return false;
    }
    if b[0] == b'[' {
        if n < 4 || b[n - 1] != b']' {
            return false;
        }
        let mut colon = false;
        for &c in &b[1..n - 1] {
            let c = c.to_ascii_lowercase();
            if c == b':' {
                colon = true;
            } else if !(c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || c == b'.') {
                return false;
            }
        }
        return colon;
    }
    if b[0] == b'-' || b[0] == b'.' {
        return false;
    }
    let mut alnum = false;
    for i in 0..n {
        let c = b[i];
        if c.is_ascii_alphanumeric() {
            alnum = true;
        } else if c == b'.' {
            if i + 1 < n && b[i + 1] == b'.' {
                return false;
            }
        } else if c != b'-' {
            return false;
        }
    }
    alnum
}

/// A NETWORK= value: 1..POOL_NET_NAME_MAX printable ASCII, no '|' or ','.
pub fn net_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= POOL_NET_NAME_MAX
        && s.bytes()
            .all(|c| c > 0x20 && c < 0x7f && c != b'|' && c != b',')
}

/// Up to POOL_NET_ALIASES names, comma separated, no empty items; "" valid.
fn aliases_ok(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    if s.len() > POOL_NET_ALIASES_MAX || s.starts_with(',') || s.ends_with(',') || s.contains(",,")
    {
        return false;
    }
    let mut count = 0;
    for t in s.split(',') {
        count += 1;
        if count > POOL_NET_ALIASES || !net_name_ok(t) {
            return false;
        }
    }
    true
}

/// Printable text without '|' (a label); "" valid.
fn text_ok(s: &str, cap: usize) -> bool {
    s.len() <= cap && s.bytes().all(|c| (0x20..0x7f).contains(&c) && c != b'|')
}

/// The derived uuid for (net_id, host, port).  None on a bad net_id/host or
/// a port outside 1..65535.
pub fn srv_uuid(net_id: &str, host: &str, port: i32) -> Option<String> {
    if !net_id_ok(net_id) || !host_ok(host) || !(1..=65535).contains(&port) {
        return None;
    }
    let hb = host.as_bytes();
    let hl = if hb.len() > 1 && hb[hb.len() - 1] == b'.' {
        hb.len() - 1
    } else {
        hb.len()
    };
    let mut key = Vec::with_capacity(POOL_NET_ID_MAX + 1 + POOL_HOST_MAX + 8);
    key.extend_from_slice(net_id.as_bytes());
    key.push(b'|');
    key.extend(hb[..hl].iter().map(u8::to_ascii_lowercase));
    key.extend_from_slice(format!(":{port}").as_bytes());
    let d = Sha256::digest(&key);
    let mut h = [0u8; 16];
    h.copy_from_slice(&d[..16]);
    h[6] = (h[6] & 0x0f) | 0x80; // version 8
    h[8] = (h[8] & 0x3f) | 0x80; // RFC 9562 variant
    let mut out = String::with_capacity(POOL_UUID_LEN);
    for (i, b) in h.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push('-');
        }
        out.push_str(&format!("{b:02x}"));
    }
    Some(out)
}

pub fn state_name(s: PoolState) -> &'static str {
    match s {
        PoolState::WrongNet => "wrongnet",
        PoolState::Disabled => "disabled",
        PoolState::Ok => "ok",
    }
}

/// The state of its text; None if unknown.
pub fn state_parse(s: &str) -> Option<PoolState> {
    match s {
        "ok" => Some(PoolState::Ok),
        "wrongnet" => Some(PoolState::WrongNet),
        "disabled" => Some(PoolState::Disabled),
        _ => None,
    }
}

/// Parse a stored N| value.  None on any shape, cap or charset error.
pub fn net_parse(value: &str) -> Option<PoolNet> {
    let f = split_fields(value, 7, POOL_N_LINE_MAX)?;
    if !net_id_ok(f[0]) || !text_ok(f[1], POOL_NET_LABEL_MAX) {
        return None;
    }
    if !f[2].is_empty() && !net_name_ok(f[2]) {
        return None;
    }
    if !aliases_ok(f[3]) {
        return None;
    }
    let split_wait = num_ok(f[4], POOL_SPLIT_WAIT_MAX)?;
    let pace_gap = num_ok(f[5], POOL_PACE_GAP_MAX)?;
    let deleted = op_parse(f[6])?;
    Some(PoolNet {
        net_id: f[0].to_string(),
        label: f[1].to_string(),
        name: f[2].to_string(),
        aliases: f[3].to_string(),
        split_wait,
        pace_gap,
        deleted,
    })
}

/// Parse a stored S| value.  None on any shape, cap or charset error, or a
/// uuid that is not the derived one.
pub fn srv_parse(value: &str) -> Option<PoolSrv> {
    let f = split_fields(value, 9, POOL_S_LINE_MAX)?;
    if f[0].len() != POOL_UUID_LEN || !net_id_ok(f[1]) || !host_ok(f[2]) {
        return None;
    }
    let port = num_ok(f[3], 65535)?;
    if port < 1 {
        return None;
    }
    let weight = num_ok(f[4], POOL_WEIGHT_MAX)?;
    if weight < 1 {
        return None;
    }
    let max = num_ok(f[5], POOL_MAX_MAX)?;
    let state = state_parse(f[6])?;
    let deleted = op_parse(f[8])?;
    // seen is set only on a wrongnet entry
    if !f[7].is_empty() && (state != PoolState::WrongNet || !net_name_ok(f[7])) {
        return None;
    }
    let want = srv_uuid(f[1], f[2], port)?;
    if want != f[0] {
        return None;
    }
    Some(PoolSrv {
        uuid: want,
        net_id: f[1].to_string(),
        host: f[2].to_string(),
        port,
        weight,
        max,
        state,
        seen: f[7].to_string(),
        deleted,
    })
}

/// Format a stored N| value (no tag, no stamp); None if the record is
/// invalid or longer than the C buffer would take.
pub fn net_format(n: &PoolNet) -> Option<String> {
    let s = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        n.net_id,
        n.label,
        n.name,
        n.aliases,
        n.split_wait,
        n.pace_gap,
        if n.deleted { "del" } else { "add" }
    );
    (s.len() < POOL_N_LINE_MAX && net_parse(&s).is_some()).then_some(s)
}

/// Format a stored S| value (no tag, no stamp); None if the record is
/// invalid or longer than the C buffer would take.
pub fn srv_format(s: &PoolSrv) -> Option<String> {
    let v = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        s.uuid,
        s.net_id,
        s.host,
        s.port,
        s.weight,
        s.max,
        state_name(s.state),
        s.seen,
        if s.deleted { "del" } else { "add" }
    );
    (v.len() < POOL_S_LINE_MAX && srv_parse(&v).is_some()).then_some(v)
}

/// ASCII case-insensitive match of `network` against a network's name and
/// aliases.  An empty name matches nothing (the caller decides "not learned").
pub fn net_matches(n: &PoolNet, network: &str) -> bool {
    if network.is_empty() || n.name.is_empty() {
        return false;
    }
    if n.name.eq_ignore_ascii_case(network) {
        return true;
    }
    !n.aliases.is_empty()
        && n.aliases
            .split(',')
            .any(|a| a.len() <= POOL_NET_NAME_MAX && a.eq_ignore_ascii_case(network))
}

/// Split "host[:port]" or "[v6][:port]" as typed by an admin; a missing port
/// is POOL_DEFAULT_PORT.  None on a bad host or port.
pub fn hostport_parse(input: &str) -> Option<(String, i32)> {
    let (host, port) = if input.starts_with('[') {
        let rb = input.find(']')?;
        let rest = &input[rb + 1..];
        match rest.strip_prefix(':') {
            Some(p) => (&input[..=rb], Some(p)),
            None if rest.is_empty() => (&input[..=rb], None),
            None => return None,
        }
    } else {
        match input.rfind(':') {
            Some(c) => (&input[..c], Some(&input[c + 1..])),
            None => (input, None),
        }
    };
    if host.is_empty() || host.len() > POOL_HOST_MAX {
        return None;
    }
    let port = match port {
        Some(p) => {
            let v = num_ok(p, 65535)?;
            if v == 0 {
                return None;
            }
            v
        }
        None => POOL_DEFAULT_PORT,
    };
    host_ok(host).then(|| (host.to_string(), port))
}

// ---- R| ----------------------------------------------------------------------

fn fnv32(s: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &c in s {
        h ^= u32::from(c);
        h = h.wrapping_mul(16777619);
    }
    h
}

fn uuid_shape(s: &[u8]) -> bool {
    s.len() == POOL_UUID_LEN
        && s.iter().enumerate().all(|(i, &c)| {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

/// "<slot>|<slots>|<gap>|<ids>" of an order; None when it is not a valid one.
fn order_body(o: &PoolOrder) -> Option<String> {
    if o.ids.is_empty()
        || o.ids.len() > POOL_ORDER_MAX
        || !(1..=POOL_ORDER_SLOTS_MAX).contains(&o.slots)
        || !(0..o.slots).contains(&o.slot)
        || !(0..=POOL_PACE_GAP_MAX).contains(&o.gap)
    {
        return None;
    }
    let mut out = format!("{}|{}|{}|", o.slot, o.slots, o.gap);
    for (i, id) in o.ids.iter().enumerate() {
        if !uuid_shape(id.as_bytes()) || o.ids[..i].contains(id) {
            return None;
        }
        if i > 0 {
            out.push(',');
        }
        out.push_str(id);
    }
    (out.len() < POOL_R_LINE_MAX).then_some(out)
}

/// Format an R| value, filling `o.generation` from the rest; None if the order is
/// invalid or longer than the C buffer would take.
pub fn order_format(o: &mut PoolOrder) -> Option<String> {
    let body = order_body(o)?;
    o.generation = fnv32(body.as_bytes());
    let v = format!("{:08x}|{body}", o.generation);
    (v.len() < POOL_R_LINE_MAX).then_some(v)
}

/// Parse an R| value: None on a gen that does not match, a repeated or
/// malformed id, or an empty order.
pub fn order_parse(value: &str) -> Option<PoolOrder> {
    let f = split_fields(value, 5, POOL_R_LINE_MAX)?;
    let g = f[0].as_bytes();
    if g.len() != 8
        || !g
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    {
        return None;
    }
    let generation = u32::from_str_radix(f[0], 16).ok()?;
    let slot = num_ok(f[1], POOL_ORDER_SLOTS_MAX)?;
    let slots = num_ok(f[2], POOL_ORDER_SLOTS_MAX)?;
    let gap = num_ok(f[3], POOL_PACE_GAP_MAX)?;
    let mut ids: Vec<String> = Vec::new();
    let list = f[4];
    if !list.is_empty() {
        // a leading, doubled or trailing ',' leaves an empty part: refused
        for p in list.split(',') {
            if ids.len() >= POOL_ORDER_MAX
                || !uuid_shape(p.as_bytes())
                || ids.iter().any(|x| x == p)
            {
                return None;
            }
            ids.push(p.to_string());
        }
    }
    if ids.is_empty() {
        return None;
    }
    let o = PoolOrder {
        generation,
        slot,
        slots,
        gap,
        ids,
    };
    let body = order_body(&o)?;
    (fnv32(body.as_bytes()) == generation).then_some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_matches_c() {
        // vectors from pool_rec.c (ircbot-testnet cross-check)
        assert_eq!(
            srv_uuid("main", "127.0.0.1", 6697).unwrap(),
            "60be3bd3-8d40-8411-81ac-96a777cd8710"
        );
        assert_eq!(
            srv_uuid("main", "Irc.EFnet.org.", 6667).unwrap(),
            "e55d6c0e-5410-8298-ae4e-2a88b713c421"
        );
    }

    #[test]
    fn round_trip() {
        let s = PoolSrv {
            uuid: srv_uuid("main", "irc.example.net", 6697).unwrap(),
            net_id: "main".into(),
            host: "irc.example.net".into(),
            port: 6697,
            weight: 2,
            max: 0,
            state: PoolState::Ok,
            seen: String::new(),
            deleted: false,
        };
        let v = srv_format(&s).unwrap();
        assert_eq!(srv_parse(&v).unwrap(), s);
        assert!(srv_parse(&v.replace("|6697|", "|6667|")).is_none()); // uuid no longer derived
        let n = net_parse("main|main|EFnet|EFNet,efnet|0|15|add").unwrap();
        assert!(net_matches(&n, "efNET"));
        assert_eq!(n.pace_gap, 15);
        assert_eq!(
            net_format(&n).unwrap(),
            "main|main|EFnet|EFNet,efnet|0|15|add"
        );
        assert!(net_parse("main|main|EFnet|EFNet,efnet|0|add").is_none()); // 6 fields
        assert!(net_parse("main|main|EFnet||0|601|add").is_none());
    }

    #[test]
    fn order_matches_c() {
        // vectors from pool_rec.c (a C harness against irchub/ircbot pool_rec.c)
        let mut o = PoolOrder {
            generation: 0,
            slot: 1,
            slots: 3,
            gap: 15,
            ids: vec![
                "60be3bd3-8d40-8411-81ac-96a777cd8710".into(),
                "e55d6c0e-5410-8298-ae4e-2a88b713c421".into(),
                "00000000-0000-8000-8000-000000000001".into(),
            ],
        };
        let v = order_format(&mut o).unwrap();
        assert_eq!(
            v,
            "d298d0f3|1|3|15|60be3bd3-8d40-8411-81ac-96a777cd8710,\
             e55d6c0e-5410-8298-ae4e-2a88b713c421,00000000-0000-8000-8000-000000000001"
        );
        assert_eq!(order_parse(&v).unwrap(), o);
        let mut one = PoolOrder {
            slots: 1,
            ids: vec!["60be3bd3-8d40-8411-81ac-96a777cd8710".into()],
            ..Default::default()
        };
        assert_eq!(
            order_format(&mut one).unwrap(),
            "a9850126|0|1|0|60be3bd3-8d40-8411-81ac-96a777cd8710"
        );
        assert!(order_parse("00000000|0|1|0|60be3bd3-8d40-8411-81ac-96a777cd8710").is_none());
        assert!(order_parse("a9850126|0|1|0|60be3bd3-8d40-8411-81ac-96a777cd8710,").is_none());
        assert!(order_parse("a9850126|0|1|0|").is_none());
        assert!(order_parse("x").is_none());
        let mut bad = one.clone();
        bad.slot = 1; // slot < slots
        assert!(order_format(&mut bad).is_none());
        bad.slot = 0;
        bad.slots = 0;
        assert!(order_format(&mut bad).is_none());
        let mut dup = o.clone();
        dup.ids[1] = dup.ids[0].clone();
        assert!(order_format(&mut dup).is_none());
        assert_eq!(POOL_R_LINE_MAX, 2429);
        assert_eq!(POOL_N_LINE_MAX, 680);
    }

    #[test]
    fn hostport() {
        assert_eq!(
            hostport_parse("irc.x.net"),
            Some(("irc.x.net".into(), 6667))
        );
        assert_eq!(hostport_parse("[::1]:6697"), Some(("[::1]".into(), 6697)));
        assert_eq!(hostport_parse("[::1]"), Some(("[::1]".into(), 6667)));
        assert!(hostport_parse("irc.x.net:0").is_none());
        assert!(hostport_parse("irc.x.net:06667").is_none());
        assert!(hostport_parse("::1").is_none());
    }
}
