//! Modes, channel settings, network defaults, bans (hub_modes.c, docs/modes.md,
//! 2.4.5).
//!
//! The records themselves (C|, D|, B|) live in `global_entries` and enter the
//! store only through [`storage::put_record`]: validation, LWW and the
//! ceilings are there.  This module is everything around them: the setting
//! table, the console-facing store functions, the ban rules (including the
//! bot-written ones), the expiry sweep, the older-hub check and the
//! CMD_CHAN_EVENT receipt.

use crate::consts::*;
use crate::cstr::{atoll, now, trunc_string, until_nul};
use crate::glob_overlap::hostmask_overlap;
use crate::state::{
    Ban, BotConfig, Chanset, ConfigEntry, HubState, ModesStatus, global_value_active, lww_next_ts,
};
use crate::{mesh, storage};

// ---- setting table ---------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum StKind {
    Flag,
    Num,
    Flood,
    Sendq,
}

struct SettingDef {
    name: &'static str,
    kind: StKind,
    /// StKind::Num range.
    lo: i64,
    hi: i64,
    /// Built-in value.
    def: &'static str,
    /// Only legal in D| (bot floods, ignore time).
    net_only: bool,
}

const fn sd(
    name: &'static str,
    kind: StKind,
    lo: i64,
    hi: i64,
    def: &'static str,
    net_only: bool,
) -> SettingDef {
    SettingDef {
        name,
        kind,
        lo,
        hi,
        def,
        net_only,
    }
}

/// Names, ranges and built-ins: the contract (docs/modes.md §4, §8.1, §9.1).
const SETTINGS: &[SettingDef] = &[
    sd("enforcemodes", StKind::Flag, 0, 1, "0", false),
    sd("bitch", StKind::Flag, 0, 1, "0", false),
    sd("protectops", StKind::Flag, 0, 1, "1", false),
    sd("revenge", StKind::Flag, 0, 1, "0", false),
    sd("stopnethack", StKind::Flag, 0, 1, "0", false),
    sd("enforcebans", StKind::Flag, 0, 1, "0", false),
    sd("dynamicbans", StKind::Flag, 0, 1, "1", false),
    sd("dontkickops", StKind::Flag, 0, 1, "1", false),
    sd("cycle", StKind::Flag, 0, 1, "1", false),
    sd("dynamiclimit", StKind::Flag, 0, 1, "0", false),
    sd("bantime", StKind::Num, 0, 525_600, "120", false),
    sd("bantype", StKind::Num, 0, 9, "2", false),
    sd("banidle", StKind::Num, 1, 10_080, "60", false),
    sd("limitgap", StKind::Num, 1, 1000, "5", false),
    sd("limitdelay", StKind::Num, 10, 3600, "60", false),
    sd("flood chan", StKind::Flood, 0, 0, "15:60", false),
    sd("flood ctcp", StKind::Flood, 0, 0, "3:60", false),
    sd("flood join", StKind::Flood, 0, 0, "5:60", false),
    sd("flood nick", StKind::Flood, 0, 0, "5:60", false),
    sd("flood deop", StKind::Flood, 0, 0, "3:10", false),
    sd("flood kick", StKind::Flood, 0, 0, "3:10", false),
    sd("flood ban", StKind::Flood, 0, 0, "3:10", false),
    sd("bflood cmd", StKind::Flood, 0, 0, "10:30", true),
    sd("bflood msg", StKind::Flood, 0, 0, "5:60", true),
    sd("bflood ctcp", StKind::Flood, 0, 0, "3:60", true),
    sd("ignoretime", StKind::Num, 1, 1440, "10", true),
    sd("sendq", StKind::Sendq, 0, 0, "10:100", true), // B:I, B 1-100 lines, I 0-10000 ms
];

fn setting_find(name: &str) -> Option<&'static SettingDef> {
    SETTINGS.iter().find(|d| d.name == name)
}

/// hub_setting_count(): the setting table, for the console's views.
pub fn setting_count() -> usize {
    SETTINGS.len()
}

/// hub_setting_name(): None past the end.
pub fn setting_name(i: usize) -> Option<&'static str> {
    SETTINGS.get(i).map(|d| d.name)
}

/// hub_setting_kind(): "flag" / "num" / "flood" / "sendq"; None for an unknown name.
pub fn setting_kind(name: &str) -> Option<&'static str> {
    setting_find(name).map(|d| match d.kind {
        StKind::Flag => "flag",
        StKind::Num => "num",
        StKind::Flood => "flood",
        StKind::Sendq => "sendq",
    })
}

/// hub_setting_net_only(): lives only in D| (the bot floods, ignoretime and sendq).
pub fn setting_net_only(name: &str) -> bool {
    setting_find(name).is_some_and(|d| d.net_only)
}

/// hub_setting_range(): range of a numeric setting; None for a flag, a flood
/// or an unknown name.
pub fn setting_range(name: &str) -> Option<(i64, i64)> {
    setting_find(name)
        .filter(|d| d.kind == StKind::Num)
        .map(|d| (d.lo, d.hi))
}

/// Strict unsigned decimal: 1..9 digits, nothing else.
fn parse_num(s: &str) -> Option<i64> {
    if s.is_empty() || s.len() > 9 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.bytes()
        .try_fold(0i64, |v, c| Some(v * 10 + i64::from(c - b'0')))
}

/// hub_setting_check(): one name/value against the contract's names and
/// ranges.
pub fn setting_check(name: &str, value: &str, net_default: bool) -> ModesStatus {
    let Some(d) = setting_find(name) else {
        return ModesStatus::BadSetting;
    };
    if d.net_only && !net_default {
        return ModesStatus::BadSetting;
    }
    let ok = match d.kind {
        StKind::Flag => value == "0" || value == "1",
        StKind::Num => parse_num(value).is_some_and(|v| v >= d.lo && v <= d.hi),
        StKind::Flood => {
            if value == "off" {
                true
            } else {
                match value.find(':') {
                    Some(colon) if colon < 16 => {
                        match (parse_num(&value[..colon]), parse_num(&value[colon + 1..])) {
                            (Some(n), Some(sec)) => {
                                (1..=1000).contains(&n) && (1..=3600).contains(&sec)
                            }
                            _ => false,
                        }
                    }
                    _ => false,
                }
            }
        }
        StKind::Sendq => match value.find(':') {
            Some(colon) if colon < 16 => {
                match (parse_num(&value[..colon]), parse_num(&value[colon + 1..])) {
                    (Some(b), Some(ms)) => (1..=100).contains(&b) && (0..=10_000).contains(&ms),
                    _ => false,
                }
            }
            _ => false,
        },
    };
    if ok {
        ModesStatus::Ok
    } else {
        ModesStatus::BadSetting
    }
}

/// Walk "a=b,c d=e": calls `f(name, value)` per token; false from `f` stops.
/// A token that is empty, has no name or an over-long part is passed as
/// ("", "") -- unknown to every table.
fn settings_walk(settings: &str, mut f: impl FnMut(&str, &str) -> bool) -> bool {
    for tok in storage::settings_tokens(settings) {
        let keep = match tok.find('=') {
            Some(eq) if !tok.is_empty() && eq > 0 => {
                let (name, value) = (&tok[..eq], &tok[eq + 1..]);
                if name.len() < 48 && value.len() < 48 {
                    f(name, value)
                } else {
                    f("", "")
                }
            }
            _ => f("", ""),
        };
        if !keep {
            return false;
        }
    }
    true
}

/// hub_settings_check(): the §4 settings string ("bitch=1,flood join=5:60").
/// Returns the status and, on BadSetting, the offending token.
pub fn settings_check(settings: &str, net_default: bool) -> (ModesStatus, String) {
    let cap = if net_default {
        D_SETTINGS_MAX
    } else {
        C_SETTINGS_MAX
    };
    if settings.len() > cap {
        return (ModesStatus::TooLong, String::new());
    }
    let mut st = ModesStatus::Ok;
    let mut bad = String::new();
    settings_walk(settings, |name, value| {
        // A name this build does not know is kept verbatim and ignored (a
        // newer hub's setting); a known name must carry a legal value.
        if name.is_empty() {
            st = ModesStatus::BadSetting;
            bad = "?".to_string();
            return false;
        }
        if setting_find(name).is_none() {
            return true;
        }
        if setting_check(name, value, net_default) != ModesStatus::Ok {
            st = ModesStatus::BadSetting;
            bad = name.to_string();
            return false;
        }
        true
    });
    (st, bad)
}

/// hub_settings_get(): value of `name` in a settings string; None if it is
/// not there.
pub fn settings_get(settings: &str, name: &str) -> Option<String> {
    let mut found = None;
    settings_walk(settings, |n, v| {
        if n != name {
            return true;
        }
        found = Some(v.to_string());
        false
    });
    found
}

/// hub_settings_set(): set (`value`) or remove (None) one token in a settings
/// string of capacity `cap`; TooLong when it would not fit.
pub fn settings_set(
    settings: &mut String,
    cap: usize,
    name: &str,
    value: Option<&str>,
) -> ModesStatus {
    const OUT_CAP: usize = C_SETTINGS_MAX + 64;
    if cap == 0
        || name.is_empty()
        || name.contains('=')
        || name.contains(',')
        || value.is_some_and(|v| v.contains(',') || v.contains('|'))
    {
        return ModesStatus::BadSetting;
    }
    let mut out = String::new();
    let mut p = settings.as_str();
    while !p.is_empty() {
        let tl = p.find(',').unwrap_or(p.len());
        let tok = &p[..tl];
        let same = tok.find('=') == Some(name.len()) && tok.starts_with(name);
        if tl > 0 && !same {
            if out.len() + tl + 2 >= OUT_CAP {
                return ModesStatus::TooLong;
            }
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(tok);
        }
        p = &p[tl..];
        if let Some(r) = p.strip_prefix(',') {
            p = r;
        }
    }
    if let Some(v) = value {
        let add = format!("{}{name}={v}", if out.is_empty() { "" } else { "," });
        if out.len() + add.len() >= OUT_CAP {
            return ModesStatus::TooLong;
        }
        out.push_str(&add);
    }
    if out.len() >= cap {
        return ModesStatus::TooLong;
    }
    *settings = out;
    ModesStatus::Ok
}

// ---- mode strings (§3.2) -----------------------------------------------------

/// hub_modes_check(): the STORED form: "+stnkl 20" -- letters with signs,
/// then the limit number when +l is set.  The key is not in it (it lives in
/// c|), so +k takes no argument here.  Empty = the network default.
pub fn modes_check(modes: &str) -> ModesStatus {
    if modes.is_empty() {
        return ModesStatus::Ok;
    }
    if modes.len() > C_MODES_MAX {
        return ModesStatus::TooLong;
    }
    let sp = modes.find(' ');
    let ml = sp.unwrap_or(modes.len());
    let mut sign = 0u8;
    let mut seen = [false; 256];
    let mut plus = [false; 256];
    let mut plus_l = false;
    let mut letters = 0;
    for &c in &modes.as_bytes()[..ml] {
        if c == b'+' || c == b'-' {
            sign = c;
            continue;
        }
        if sign == 0 || !b"imnpstkl".contains(&c) {
            return ModesStatus::BadModes;
        }
        if seen[usize::from(c)] {
            return ModesStatus::BadModes; // a letter twice
        }
        seen[usize::from(c)] = true;
        plus[usize::from(c)] = sign == b'+';
        letters += 1;
        if c == b'l' && sign == b'+' {
            plus_l = true;
        }
    }
    if letters == 0 || (plus[usize::from(b's')] && plus[usize::from(b'p')]) {
        return ModesStatus::BadModes; // no letter, or s and p together
    }
    if let Some(sp) = sp {
        let arg = &modes[sp + 1..];
        if !plus_l || arg.contains(' ') || !parse_num(arg).is_some_and(|l| (1..=99999).contains(&l))
        {
            return ModesStatus::BadModes;
        }
    } else if plus_l {
        return ModesStatus::BadModes; // +l needs its number
    }
    ModesStatus::Ok
}

// ---- store helpers -----------------------------------------------------------

fn frozen(state: &HubState) -> bool {
    state.opt(OPT_CONFIG_FROZEN)
}

/// Send one accepted record to the peers and owe the bots a push.
fn announce_record(state: &mut HubState, key: &str, value: &str, ts: i64) {
    let line = format!("{key}|{value}|{ts}\n");
    if line.len() < 1200 {
        mesh::broadcast_sync_to_peers(state, &line, -1);
    }
    state.config_dirty = true;
    state.bot_config_pending = true;
}

fn chan_name_shape(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b.len() >= MAX_CHAN || (b[0] != b'#' && b[0] != b'&') {
        return false;
    }
    b.iter()
        .all(|&c| c > 0x20 && c != b',' && c != 0x7f && c != b'|')
}

/// Field `idx` of a '|' separated value, cut to what a `char[cap]` holds;
/// empty when the value has fewer fields.
fn field(v: &str, idx: usize, cap: usize) -> String {
    v.split('|')
        .nth(idx)
        .map_or_else(String::new, |f| trunc_string(f, cap))
}

fn entry_field(e: &ConfigEntry, idx: usize, cap: usize) -> String {
    field(&e.value, idx, cap)
}

/// A B| value's reason (may hold '|'): between the 5th '|' and the last.
fn ban_reason(e: &ConfigEntry, cap: usize) -> String {
    let v = e.value.as_str();
    let Some(last) = v.rfind('|') else {
        return String::new();
    };
    let mut p = 0;
    for _ in 0..5 {
        match v[p..].find('|') {
            Some(i) => p += i + 1,
            None => return String::new(),
        }
    }
    if last < p {
        return String::new();
    }
    trunc_string(&v[p..last], cap)
}

/// hub_chanset_get(): the live C| record of `chan`.
pub fn chanset_get(state: &HubState, chan: &str) -> Option<Chanset> {
    let i = storage::global_find(state, "C", chan)?;
    let e = &state.global_entries[i];
    if !global_value_active(&e.value) {
        return None;
    }
    Some(Chanset {
        chan: entry_field(e, 0, MAX_CHAN),
        modes: entry_field(e, 1, C_MODES_MAX + 1),
        settings: entry_field(e, 2, C_SETTINGS_MAX + 1),
        ts: e.timestamp,
    })
}

/// hub_netset_get(): the D| record, when it holds anything.
pub fn netset_get(state: &HubState) -> Option<Chanset> {
    let i = storage::global_find(state, "D", "")?;
    let e = &state.global_entries[i];
    let cs = Chanset {
        chan: String::new(),
        modes: entry_field(e, 0, C_MODES_MAX + 1),
        settings: entry_field(e, 1, D_SETTINGS_MAX + 1),
        ts: e.timestamp,
    };
    (!cs.modes.is_empty() || !cs.settings.is_empty()).then_some(cs)
}

/// hub_chanset_put(): replace the whole C| record (the caller merges); both
/// empty writes a delete (back to defaults).  Needs a live c| for C|.
pub fn chanset_put(state: &mut HubState, chan: &str, modes: &str, settings: &str) -> ModesStatus {
    if frozen(state) {
        return ModesStatus::Frozen;
    }
    if !chan_name_shape(chan) {
        return ModesStatus::BadChan;
    }
    let Some(name) = storage::chan_live(state, chan) else {
        return ModesStatus::NotManaged;
    };
    let st = modes_check(modes);
    if st != ModesStatus::Ok {
        return st;
    }
    let st = settings_check(settings, false).0;
    if st != ModesStatus::Ok {
        return st;
    }

    let had = chanset_get(state, &name).is_some();
    let value = if modes.is_empty() && settings.is_empty() {
        if !had {
            return ModesStatus::Ok; // already the defaults
        }
        format!("{name}|||del")
    } else {
        format!("{name}|{modes}|{settings}|add")
    };
    let ts = lww_next_ts(storage::global_ts(state, "C", &name));
    if !storage::put_record(state, "C", &value, ts) {
        return ModesStatus::Full;
    }
    announce_record(state, "C", &value, ts);
    ModesStatus::Ok
}

/// hub_netset_put(): replace the D| record.
pub fn netset_put(state: &mut HubState, modes: &str, settings: &str) -> ModesStatus {
    if frozen(state) {
        return ModesStatus::Frozen;
    }
    let st = modes_check(modes);
    if st != ModesStatus::Ok {
        return st;
    }
    let st = settings_check(settings, true).0;
    if st != ModesStatus::Ok {
        return st;
    }
    let value = format!("{modes}|{settings}");
    let ts = lww_next_ts(storage::global_ts(state, "D", ""));
    if !storage::put_record(state, "D", &value, ts) {
        return ModesStatus::Full;
    }
    announce_record(state, "D", &value, ts);
    ModesStatus::Ok
}

/// hub_setting_effective(): effective value of a setting for a channel:
/// channel C| override, else the D| default, else the built-in.  The source
/// is 'c' / 'n' / 'b', or '\0' (with an empty value) for an unknown name.
/// `chan` None: network level only.
pub fn setting_effective(state: &HubState, chan: Option<&str>, name: &str) -> (char, String) {
    let Some(d) = setting_find(name) else {
        return ('\0', String::new());
    };
    if let Some(chan) = chan
        && !d.net_only
        && let Some(cs) = chanset_get(state, chan)
        && let Some(v) = settings_get(&cs.settings, name)
    {
        return ('c', v);
    }
    if let Some(cs) = netset_get(state)
        && let Some(v) = settings_get(&cs.settings, name)
    {
        return ('n', v);
    }
    ('b', d.def.to_string())
}

// ---- ban protection (§6.2 step 2) --------------------------------------------

fn bot_entry_value(b: &BotConfig, key: &str, cap: usize) -> Option<String> {
    b.entries
        .iter()
        .find(|e| e.key == key)
        .map(|e| trunc_string(&e.value, cap))
}

/// glob_match(): `pat` (with '*' and '?') matches the literal string `s`,
/// ASCII case-insensitively.
fn glob_match(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = si;
        } else if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&s[si])) {
            pi += 1;
            si += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// hub_ban_protected(): whether `mask` overlaps a trusted bot's hostmask or an
/// active usermask of an active admin / oper.  On Protected the second value
/// names what the mask would hit ("bot <nick>" / "user <name>").  The §6.2
/// step 1 check (members in the channel) is the bot's.
pub fn ban_protected(state: &HubState, mask: &str) -> (ModesStatus, String) {
    if mask.is_empty() {
        return (ModesStatus::BadMask, String::new());
    }
    // Trusted bots: the hostmask each one reported (a literal host, not a
    // pattern: matched one-sided).
    for b in &state.bots {
        if !b.is_active {
            continue;
        }
        let Some(h) = bot_entry_value(b, "h", MAX_MASK_LEN) else {
            continue;
        };
        if h.is_empty() || !glob_match(mask, &h) {
            continue;
        }
        let n = bot_entry_value(b, "n", MAX_NICK).unwrap_or_default();
        let who = format!("bot {}", if n.is_empty() { &b.uuid } else { &n });
        return (ModesStatus::Protected, who);
    }
    // Active usermasks of active admins and opers.
    for m in &state.mask_records {
        if !m.is_active {
            continue;
        }
        let Some(u) = state.user_records.iter().find(|u| u.uuid == m.uuid) else {
            continue;
        };
        if !u.is_active || !hostmask_overlap(mask, &m.mask) {
            continue;
        }
        return (ModesStatus::Protected, format!("user {}", u.name));
    }
    (ModesStatus::Ok, String::new())
}

// ---- bans ----------------------------------------------------------------------

fn mask_shape(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= BAN_MASK_MAX
        && s.bytes()
            .all(|c| c > 0x20 && c < 0x7f && c != b',' && c != b'|')
}

/// "chan|mask" key for the ban lookup.
fn ban_find(state: &HubState, chan: &str, mask: &str) -> Option<usize> {
    let id = trunc_string(&format!("{chan}|{mask}"), MAX_CHAN + BAN_MASK_MAX + 4);
    storage::global_find(state, "B", &id)
}

fn entry_live(e: &ConfigEntry) -> bool {
    global_value_active(&e.value)
}

fn ban_count_live(state: &HubState, chan: &str) -> usize {
    state
        .global_entries
        .iter()
        .filter(|e| {
            e.key == "B" && entry_live(e) && storage::ascii_ieq(&entry_field(e, 0, MAX_CHAN), chan)
        })
        .count()
}

/// hub_ban_add(): `chan` is "#chan" (must be a live channel) or "*".  expires
/// 0 = permanent.  add is also the update of an existing mask.  On Protected
/// the second value names what the mask would hit.
#[allow(clippy::too_many_arguments)]
pub fn ban_add(
    state: &mut HubState,
    chan: &str,
    mask: &str,
    expires: i64,
    sticky: bool,
    setter: &str,
    reason: &str,
) -> (ModesStatus, String) {
    let fail = |st| (st, String::new());
    if frozen(state) {
        return fail(ModesStatus::Frozen);
    }
    let global = chan == "*";
    let cname = if global {
        "*".to_string()
    } else {
        if !chan_name_shape(chan) {
            return fail(ModesStatus::BadChan);
        }
        match storage::chan_live(state, chan) {
            Some(n) => n,
            None => return fail(ModesStatus::NotManaged),
        }
    };
    if !mask_shape(mask) {
        return fail(ModesStatus::BadMask);
    }
    if reason.len() > BAN_REASON_MAX || reason.bytes().any(|c| c < 0x20 || c == 0x7f) {
        return fail(ModesStatus::BadReason);
    }
    let now = now();
    if expires != 0 && (expires <= now || expires > now + 10 * 365 * 86400) {
        return fail(ModesStatus::BadExpiry);
    }
    let (st, who) = ban_protected(state, mask);
    if st != ModesStatus::Ok {
        return (st, who);
    }

    let idx = ban_find(state, &cname, mask);
    let exists = idx.is_some_and(|i| entry_live(&state.global_entries[i]));
    let ceiling = if global {
        MAX_GLOBAL_BANS
    } else {
        MAX_BANS_PER_CHAN
    };
    if !exists && ban_count_live(state, &cname) >= ceiling {
        return fail(ModesStatus::Full);
    }

    // The setter is stored as one token: anything outside [A-Za-z0-9._-] (an
    // admin name may hold more) becomes '_'.
    let who_set: String = setter
        .bytes()
        .take(BAN_SETTER_MAX - 1)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-' {
                char::from(c)
            } else {
                '_'
            }
        })
        .collect();
    // Keep the stored mask spelling when the ban already exists.
    let mname = match idx {
        Some(i) => entry_field(&state.global_entries[i], 1, BAN_MASK_MAX + 1),
        None => trunc_string(mask, BAN_MASK_MAX + 1),
    };

    let value = format!(
        "{cname}|{mname}|{expires}|{}|{who_set}|{reason}|add",
        if sticky { "s" } else { "" }
    );
    if value.len() >= B_LINE_MAX + 64 {
        return fail(ModesStatus::TooLong);
    }
    let prev = idx.map_or(0, |i| state.global_entries[i].timestamp);
    let ts = lww_next_ts(prev);
    if !storage::put_record(state, "B", &value, ts) {
        return fail(ModesStatus::Full);
    }
    announce_record(state, "B", &value, ts);
    fail(ModesStatus::Ok)
}

/// hub_ban_del().
pub fn ban_del(state: &mut HubState, chan: &str, mask: &str) -> ModesStatus {
    if frozen(state) {
        return ModesStatus::Frozen;
    }
    let global = chan == "*";
    if !global && !chan_name_shape(chan) {
        return ModesStatus::BadChan;
    }
    if !mask_shape(mask) {
        return ModesStatus::BadMask;
    }
    let Some(idx) = ban_find(state, chan, mask) else {
        return ModesStatus::NotFound;
    };
    let e = &state.global_entries[idx];
    if !entry_live(e) {
        return ModesStatus::NotFound;
    }
    let value = format!(
        "{}|{}|0||||del",
        entry_field(e, 0, MAX_CHAN),
        entry_field(e, 1, BAN_MASK_MAX + 1)
    );
    let ts = lww_next_ts(e.timestamp);
    if !storage::put_record(state, "B", &value, ts) {
        return ModesStatus::NotFound;
    }
    announce_record(state, "B", &value, ts);
    ModesStatus::Ok
}

/// hub_ban_list(): live bans of `chan` ("*" = global only, None = all),
/// oldest first, up to `max`.
pub fn ban_list(state: &HubState, chan: Option<&str>, max: usize) -> Vec<Ban> {
    let mut out: Vec<Ban> = Vec::new();
    for e in &state.global_entries {
        if out.len() >= max {
            break;
        }
        if e.key != "B" || !entry_live(e) {
            continue;
        }
        let c = entry_field(e, 0, MAX_CHAN);
        if chan.is_some_and(|ch| !storage::ascii_ieq(&c, ch)) {
            continue;
        }
        out.push(Ban {
            chan: c,
            mask: entry_field(e, 1, BAN_MASK_MAX + 1),
            expires: atoll(&entry_field(e, 2, 16)),
            flags: entry_field(e, 3, 8),
            setter: entry_field(e, 4, BAN_SETTER_MAX),
            reason: ban_reason(e, BAN_REASON_MAX + 1),
            ts: e.timestamp,
            last_used: e.last_used,
        });
    }
    out.sort_by(|x, y| x.ts.cmp(&y.ts).then_with(|| x.mask.cmp(&y.mask)));
    out
}

/// hub_ban_used_slot(): index of the live ban (chan, mask) whose
/// `last_used` activity is kept, None when there is none.
pub fn ban_used_slot(state: &HubState, chan: &str, mask: &str) -> Option<usize> {
    ban_find(state, chan, mask).filter(|&i| entry_live(&state.global_entries[i]))
}

/// Effective bantime of `chan` in minutes (0 = permanent).
fn chan_bantime(state: &HubState, chan: &str) -> i64 {
    let (_, v) = setting_effective(state, Some(chan), "bantime");
    parse_num(&trunc_string(&v, 16)).unwrap_or(BANTIME_DEFAULT_MIN)
}

/// hub_ban_bot_write(): a ban a bot pushed (B| line body without the tag, and
/// its stamp): accepted only under the contract's bot rules; the caller
/// forwards on true.
pub fn ban_bot_write(state: &mut HubState, bot_uuid: &str, value: &str, ts: i64) -> bool {
    let now = now();
    if ts <= 0 || ts > now + 300 {
        return false;
    }
    if frozen(state) || !storage::record_valid("B", value) {
        return false;
    }

    // Parse the fields with the entry helpers.
    let chan = field(value, 0, MAX_CHAN);
    let mask = field(value, 1, BAN_MASK_MAX + 1);
    let ex = field(value, 2, 16);
    let flags = field(value, 3, 8);
    let setter = field(value, 4, BAN_SETTER_MAX);
    let op = trunc_string(value.rfind('|').map_or("", |i| &value[i + 1..]), 8);

    // A bot bans in one channel the hub manages, and signs its own bans.
    if chan.starts_with('*') || storage::chan_live(state, &chan).is_none() {
        return false;
    }
    if setter != bot_uuid {
        return false;
    }

    let idx = ban_find(state, &chan, &mask);
    if op == "del" {
        // Only a ban this bot wrote, and only while it is live.
        let Some(i) = idx else { return false };
        let e = &state.global_entries[i];
        if !entry_live(e) || entry_field(e, 4, BAN_SETTER_MAX) != bot_uuid {
            return false;
        }
        return storage::put_record(state, "B", value, ts);
    }

    // add: timed, no longer than the channel's bantime (+ slack), not sticky,
    // and never over an admin's (or another bot's) live ban.
    let expires = atoll(&ex);
    if expires <= now || !flags.is_empty() {
        return false;
    }
    let bt = chan_bantime(state, &chan);
    let cap_s = (if bt > 0 { bt } else { 525_600 }) * 60 + BAN_BOT_SLACK;
    if expires - now > cap_s {
        return false;
    }
    if let Some(i) = idx {
        let e = &state.global_entries[i];
        if entry_live(e) && entry_field(e, 4, BAN_SETTER_MAX) != bot_uuid {
            return false;
        }
    }
    // Never over a trusted bot's or an admin's / oper's own mask.
    if ban_protected(state, &mask).0 != ModesStatus::Ok {
        crate::hlog_warning!(
            "[BANS] ban {mask} in {chan} from {bot_uuid} refused (protected mask)\n",
            bot_uuid = state.who('b', bot_uuid)
        );
        return false;
    }
    // A bot holds at most BOT_BANS_PER_CHAN live bans per channel; renewing
    // its own live ban takes no new place.
    if idx.is_none_or(|i| !entry_live(&state.global_entries[i])) {
        let mut mine = 0;
        for e in &state.global_entries {
            if e.key != "B" || !entry_live(e) {
                continue;
            }
            if storage::ascii_ieq(&entry_field(e, 0, MAX_CHAN), &chan)
                && entry_field(e, 4, BAN_SETTER_MAX) == bot_uuid
            {
                mine += 1;
            }
        }
        if mine >= BOT_BANS_PER_CHAN {
            crate::hlog_warning!(
                "[BANS] ban in {chan} from {bot_uuid} refused ({mine} live bans)\n",
                bot_uuid = state.who('b', bot_uuid)
            );
            return false;
        }
    }
    storage::put_record(state, "B", value, ts)
}

/// hub_bans_sweep(): the 60 s sweep, `del` for every expired ban, announced
/// to peers and bots.
pub fn bans_sweep(state: &mut HubState, now: i64) {
    if state.bans_swept_at != 0 && now - state.bans_swept_at < BAN_SWEEP_INTERVAL {
        return;
    }
    state.bans_swept_at = now;
    if frozen(state) {
        return;
    }
    let mut out = String::new();
    let mut swept = 0;
    for i in 0..state.global_entries.len() {
        let e = &state.global_entries[i];
        if e.key != "B" || !entry_live(e) {
            continue;
        }
        let expires = atoll(&entry_field(e, 2, 16));
        if expires <= 0 || expires > now {
            continue;
        }
        let value = format!(
            "{}|{}|0||||del",
            entry_field(e, 0, MAX_CHAN),
            entry_field(e, 1, BAN_MASK_MAX + 1)
        );
        // One second past the record's own stamp: every hub sweeping the same
        // ban writes the same tombstone at the same stamp, so they agree
        // without talking, and any newer edit (an extension made on another
        // hub) wins.
        let ts = e.timestamp.saturating_add(1);
        if !storage::put_record(state, "B", &value, ts) {
            continue;
        }
        swept += 1;
        let line = format!("B|{value}|{ts}\n");
        if out.len() + line.len() >= 8192 {
            // C sends the full buffer here, a truncated last line included;
            // only complete lines are sent (docs/ARCHITECTURE_RUST.md §7).
            mesh::broadcast_sync_to_peers(state, &out, -1);
            out.clear();
        }
        out.push_str(&line);
    }
    if !out.is_empty() {
        mesh::broadcast_sync_to_peers(state, &out, -1);
    }
    if swept > 0 {
        crate::hlog_info!("[BANS] {swept} expired ban(s) removed\n");
        state.config_dirty = true;
        state.bot_config_pending = true;
    }
}

// ---- CMD_CHAN_EVENT (D42) --------------------------------------------------------

fn event_action_ok(a: &str) -> bool {
    matches!(
        a,
        "deop"
            | "reop"
            | "kick"
            | "ban"
            | "unban"
            | "moderevert"
            | "limit"
            | "floodtrip"
            | "ignore"
    )
}

fn no_ctrl(s: &str) -> bool {
    s.bytes().all(|c| c >= 0x20 && c != 0x7f)
}

/// hub_chan_event_receive(): CMD_CHAN_EVENT from an authenticated bot
/// (validate, rate-limit, log).  Hub local: never stored, never forwarded.
pub fn chan_event_receive(state: &mut HubState, ci: usize, payload: &str) {
    let who = state.who_client(ci);
    let c = &mut state.clients[ci];
    if c.typ != crate::state::ClientType::Bot || !c.authenticated {
        return;
    }
    let payload = until_nul(payload);
    let now = now();
    if now - c.chan_ev_window >= CHAN_EVENT_WINDOW {
        if c.chan_ev_dropped > 0 {
            crate::hlog_debug!(
                "[CHAN] {} event(s) from {} dropped (rate limit)\n",
                c.chan_ev_dropped,
                who
            );
        }
        c.chan_ev_window = now;
        c.chan_ev_count = 0;
        c.chan_ev_dropped = 0;
    }
    // Every event received counts, valid or not: junk must not be free.
    if c.chan_ev_count >= CHAN_EVENT_MAX_PER_WINDOW {
        c.chan_ev_dropped += 1;
        return;
    }
    c.chan_ev_count += 1;
    let id = who.clone();

    // #chan|action|target|detail -- detail is the tail and may hold '|'.
    if payload.len() >= MAX_CHAN + 16 + CHAN_EVENT_TARGET_MAX + CHAN_EVENT_DETAIL_MAX + 8 {
        crate::hlog_debug!("[CHAN] oversize event from {id} dropped\n");
        return;
    }
    let mut it = payload.splitn(4, '|');
    let (chan, action, target, detail) = (
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next().unwrap_or(""),
        it.next(),
    );
    let Some(detail) = detail else {
        crate::hlog_debug!("[CHAN] malformed event from {id} dropped\n");
        return;
    };
    if !chan_name_shape(chan)
        || !event_action_ok(action)
        || target.is_empty()
        || target.len() > CHAN_EVENT_TARGET_MAX
        || detail.len() > CHAN_EVENT_DETAIL_MAX
        || !no_ctrl(target)
        || !no_ctrl(detail)
    {
        crate::hlog_debug!("[CHAN] malformed event from {id} dropped\n");
        return;
    }
    crate::hlog_info!(
        "[CHAN] chan {chan} {action} {target} by {}: {detail}\n",
        state.who_client(ci)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_strings() {
        assert_eq!(modes_check(""), ModesStatus::Ok);
        assert_eq!(modes_check("+stnkl 20"), ModesStatus::Ok);
        assert_eq!(modes_check("+l"), ModesStatus::BadModes);
        assert_eq!(modes_check("+sp"), ModesStatus::BadModes);
        assert_eq!(modes_check("+nn"), ModesStatus::BadModes);
        assert_eq!(modes_check("+t 5"), ModesStatus::BadModes);
        assert_eq!(modes_check("+l 100000"), ModesStatus::BadModes);
    }

    #[test]
    fn sendq_check() {
        for ok in ["10:100", "1:0", "100:10000", "05:0100"] {
            assert_eq!(setting_check("sendq", ok, true), ModesStatus::Ok, "{ok}");
        }
        for bad in [
            "",
            "10",
            ":100",
            "10:",
            "0:100",
            "101:100",
            "10:10001",
            "off",
            "-1:5",
            "+5:5",
            "5:1x",
            "1234567890:5",
            "5:1234567890",
            "5:5:5",
            " 5:5",
        ] {
            assert_eq!(
                setting_check("sendq", bad, true),
                ModesStatus::BadSetting,
                "{bad}"
            );
        }
        // D|-only.
        assert_eq!(
            setting_check("sendq", "10:100", false),
            ModesStatus::BadSetting
        );
        assert_eq!(setting_kind("sendq"), Some("sendq"));
        assert!(setting_net_only("sendq"));
        assert_eq!(settings_check("sendq=5:250", true).0, ModesStatus::Ok);
        assert_eq!(
            settings_check("sendq=5:250", false).0,
            ModesStatus::BadSetting
        );
    }

    #[test]
    fn settings_tokens_and_ranges() {
        let (st, bad) = settings_check("bitch=1,flood join=5:60,future=x", false);
        assert_eq!((st, bad.as_str()), (ModesStatus::Ok, ""));
        let (st, bad) = settings_check("bantime=999999", false);
        assert_eq!((st, bad.as_str()), (ModesStatus::BadSetting, "bantime"));
        // net-only names are refused in a channel record.
        assert_eq!(
            settings_check("ignoretime=5", false).0,
            ModesStatus::BadSetting
        );
        assert_eq!(settings_check("ignoretime=5", true).0, ModesStatus::Ok);

        let mut s = String::from("bitch=1,cycle=0");
        assert_eq!(settings_set(&mut s, 512, "bitch", None), ModesStatus::Ok);
        assert_eq!(s, "cycle=0");
        assert_eq!(
            settings_set(&mut s, 512, "bantime", Some("30")),
            ModesStatus::Ok
        );
        assert_eq!(s, "cycle=0,bantime=30");
        assert_eq!(settings_get(&s, "bantime").as_deref(), Some("30"));
    }

    #[test]
    fn effective_setting_order() {
        let mut s = HubState::new();
        storage::update_global_entry(&mut s, "c", "#a", "|0", "add", 100);
        assert_eq!(
            setting_effective(&s, Some("#a"), "bantime"),
            ('b', "120".into())
        );
        assert_eq!(netset_put(&mut s, "", "bantime=60"), ModesStatus::Ok);
        assert_eq!(
            setting_effective(&s, Some("#a"), "bantime"),
            ('n', "60".into())
        );
        assert_eq!(
            chanset_put(&mut s, "#A", "+nt", "bantime=5"),
            ModesStatus::Ok
        );
        assert_eq!(
            setting_effective(&s, Some("#a"), "bantime"),
            ('c', "5".into())
        );
        assert_eq!(
            chanset_put(&mut s, "#nope", "", ""),
            ModesStatus::NotManaged
        );
        assert_eq!(chanset_put(&mut s, "#a", "", ""), ModesStatus::Ok);
        assert_eq!(
            setting_effective(&s, Some("#a"), "bantime"),
            ('n', "60".into())
        );
    }

    #[test]
    fn bot_ban_rules() {
        let mut s = HubState::new();
        storage::update_global_entry(&mut s, "c", "#a", "|0", "add", 100);
        let t = now();
        let ok = format!("#a|*!*@bad|{}||bot-1|spam|add", t + 600);
        assert!(ban_bot_write(&mut s, "bot-1", &ok, t));
        // Not its own, too long, sticky, or not a managed channel.
        assert!(!ban_bot_write(&mut s, "bot-2", &ok, t + 1));
        let long = format!("#a|*!*@bad2|{}||bot-1||add", t + 3 * 3600);
        assert!(!ban_bot_write(&mut s, "bot-1", &long, t));
        let sticky = format!("#a|*!*@bad3|{}|s|bot-1||add", t + 60);
        assert!(!ban_bot_write(&mut s, "bot-1", &sticky, t));
        let other = format!("#b|*!*@bad|{}||bot-1||add", t + 60);
        assert!(!ban_bot_write(&mut s, "bot-1", &other, t));
        // Only the writer may delete it.
        assert!(!ban_bot_write(
            &mut s,
            "bot-2",
            "#a|*!*@bad|0||bot-2|||del",
            t + 2
        ));
        assert!(ban_bot_write(
            &mut s,
            "bot-1",
            "#a|*!*@bad|0||bot-1|||del",
            t + 2
        ));
    }

    #[test]
    fn admin_ban_protection_sweep_and_list() {
        let mut s = HubState::new();
        storage::update_global_entry(&mut s, "c", "#a", "|0", "add", 100);
        storage::update_entry(&mut s, "b1", "h", "bot!u@host.example", "", "", 10);
        let (st, who) = ban_add(&mut s, "#a", "*!*@host.example", 0, false, "adm", "r");
        assert_eq!((st, who.as_str()), (ModesStatus::Protected, "bot b1"));
        let soon = now() + 1;
        assert_eq!(
            ban_add(&mut s, "#A", "*!*@evil", soon, true, "ad min", "r").0,
            ModesStatus::Ok
        );
        let l = ban_list(&s, Some("#a"), 10);
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].setter.as_str(), l[0].flags.as_str()), ("ad_min", "s"));
        bans_sweep(&mut s, soon);
        assert_eq!(ban_list(&s, None, 10).len(), 0);
        assert_eq!(ban_del(&mut s, "#a", "*!*@evil"), ModesStatus::NotFound);
    }
    #[test]
    fn bot_ban_protected_and_quota() {
        let mut s = HubState::new();
        storage::update_global_entry(&mut s, "c", "#a", "|0", "add", 100);
        storage::update_entry(&mut s, "b1", "h", "bot!u@host.example", "", "", 10);
        let t = now();
        // A bot's ban over a trusted bot's host is refused.
        let prot = format!("#a|*!*@host.example|{}||bot-1||add", t + 600);
        assert!(!ban_bot_write(&mut s, "bot-1", &prot, t));
        // The host is a literal: a glob in a ban matches it one-sided, a host
        // pattern never shields anything (and cannot be stored).
        assert_eq!(
            ban_protected(&s, "BOT!*@*.example").0,
            ModesStatus::Protected
        );
        assert_eq!(ban_protected(&s, "other!*@*").0, ModesStatus::Ok);
        // Quota: BOT_BANS_PER_CHAN live bans per bot and channel.
        for n in 0..BOT_BANS_PER_CHAN {
            let v = format!("#a|*!*@m{n}|{}||bot-1||add", t + 600);
            assert!(ban_bot_write(&mut s, "bot-1", &v, t), "ban {n}");
        }
        let over = format!("#a|*!*@over|{}||bot-1||add", t + 600);
        assert!(!ban_bot_write(&mut s, "bot-1", &over, t));
        // Renewing an own live ban takes no new place; another bot has its own.
        let renew = format!("#a|*!*@m0|{}||bot-1||add", t + 900);
        assert!(ban_bot_write(&mut s, "bot-1", &renew, t + 1));
        let other = format!("#a|*!*@over|{}||bot-2||add", t + 600);
        assert!(ban_bot_write(&mut s, "bot-2", &other, t));
        // A delete frees a place.
        assert!(ban_bot_write(
            &mut s,
            "bot-1",
            "#a|*!*@m1|0||bot-1|||del",
            t + 2
        ));
        let again = format!("#a|*!*@again|{}||bot-1||add", t + 600);
        assert!(ban_bot_write(&mut s, "bot-1", &again, t + 3));
    }

    #[test]
    fn sweep_tombstone_is_stamped_past_the_record() {
        let mut s = HubState::new();
        let t = now();
        // Expired long ago, but the record itself is stamped 100.
        let v = format!("#a|*!*@x|{}||adm||add", t - 10);
        assert!(storage::put_record(&mut s, "B", &v, 100));
        bans_sweep(&mut s, t);
        let i = storage::global_find(&s, "B", "#a|*!*@x").unwrap();
        assert!(!entry_live(&s.global_entries[i]));
        assert_eq!(s.global_entries[i].timestamp, 101);
    }
}
