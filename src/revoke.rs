//! Revoked bots and mesh-wide hub settings (hub_revoke.c;
//! irchub docs/plans/2026-10-17_bot_revoke_plan.md).
//!
//! `rv|<uuid>|<pub>|<pub_ts>|<nick>|<wiped_ts>|<del_ts>`
//!   A deleted bot's identity, kept for good: when the bot connects again —
//!   next week or in five years — it proves its key against this pub, is told
//!   to wipe its config (CMD_BOT_RETIRE) and is closed.  The list only grows,
//!   so hubs merge it as a union and never disagree.
//!
//! `hs|<name>|<value>|<ts>`
//!   One hub setting the whole mesh shares, each with its own stamp so two
//!   settings changed on two hubs at once both survive.  Newer stamp wins, on
//!   a tie the greater value.

use crate::consts::*;
use crate::cstr;
use crate::state::{BotConfig, HubState, Revoked, lww_next_ts};

// ---- hs| registry ---------------------------------------------------------

struct Gsetting {
    name: &'static str,
    max: i32,
}

const GSET: &[Gsetting] = &[Gsetting {
    name: "autopurge",
    max: 36500,
}];
const _: () = assert!(GSET.len() <= HUB_GSETTINGS_MAX);

fn gs_find(name: &str) -> Option<&'static Gsetting> {
    GSET.iter().find(|g| g.name == name)
}

fn gs_get(state: &HubState, name: &str) -> (i32, i64) {
    match name {
        "autopurge" => (state.purge_days_setting, state.purge_days_ts),
        _ => (0, 0),
    }
}

fn gs_put(state: &mut HubState, name: &str, v: i32, ts: i64) {
    if name == "autopurge" {
        state.purge_days_setting = v;
        state.purge_days_ts = ts;
    }
}

/// hub_gsetting_format(): `hs|<name>|<value>|<ts>\n`, or None for an unknown
/// setting.
pub fn gsetting_format(state: &HubState, name: &str) -> Option<String> {
    let g = gs_find(name)?;
    let (v, ts) = gs_get(state, g.name);
    Some(format!("hs|{}|{}|{}\n", g.name, v, ts))
}

/// hub_gsetting_set(): a local change, stamped past the previous one.
pub fn gsetting_set(state: &mut HubState, name: &str, value: i32) -> bool {
    let Some(g) = gs_find(name) else { return false };
    if value < 0 || value > g.max {
        return false;
    }
    let (_, ts) = gs_get(state, g.name);
    gs_put(state, g.name, value, lww_next_ts(ts));
    state.config_dirty = true;
    true
}

/// hub_gsetting_ingest(): `rest` = "<name>|<value>|<ts>".  None if it does
/// not parse or names a setting this hub does not have, else whether it won.
pub fn gsetting_ingest(state: &mut HubState, rest: &str) -> Option<bool> {
    let p1 = rest.find('|')?;
    let g = gs_find(&rest[..p1])?;
    let after = &rest[p1 + 1..];
    let (v, n) = cstr::strtoll(after);
    if n == 0 || !after[n..].starts_with('|') || v < 0 || v > i64::from(g.max) {
        return None;
    }
    let ts_s = &after[n + 1..];
    let (ts, m) = cstr::strtoll(ts_s);
    if m == 0 || m != ts_s.len() || ts <= 0 {
        return None;
    }
    let (cur, cur_ts) = gs_get(state, g.name);
    let v = v as i32;
    if ts > cur_ts || (ts == cur_ts && v > cur) {
        gs_put(state, g.name, v, ts);
        state.config_dirty = true;
        return Some(true);
    }
    Some(false)
}

/// hub_gsetting_append(): every stamped setting, for a full sync or the
/// config file.
pub fn gsetting_append(state: &HubState, out: &mut String) {
    for g in GSET {
        if gs_get(state, g.name).1 > 0
            && let Some(l) = gsetting_format(state, g.name)
        {
            out.push_str(&l);
        }
    }
}

// ---- rv| revoke list ------------------------------------------------------

fn pub_ok(s: &str) -> bool {
    s.len() == COMBINED_KEY_B64
        && crate::crypto::b64_decode(s).is_some_and(|d| d.len() == COMBINED_KEY_LEN)
}

/// A nick as the console may show it: printable, no '|', never truncated
/// mid-way into something else (too long = dropped).
fn nick_clean(src: &str) -> String {
    let b = src.as_bytes();
    if b.len() >= MAX_NICK
        || b.iter()
            .any(|&c| c <= 0x20 || c == 0x7f || c == b'|' || c >= 0x80)
    {
        return String::new();
    }
    src.to_string()
}

/// hub_revoke_find().
pub fn find<'a>(state: &'a HubState, uuid: &str) -> Option<&'a Revoked> {
    state.revoked.iter().find(|r| r.uuid == uuid)
}

pub fn is_revoked(state: &HubState, uuid: &str) -> bool {
    find(state, uuid).is_some()
}

/// hub_revoke_merge(): union merge of one record.  True when the list
/// changed.
pub fn merge(state: &mut HubState, inp: &Revoked) -> bool {
    let Some(i) = state.revoked.iter().position(|r| r.uuid == inp.uuid) else {
        if state.revoked.len() >= MAX_REVOKED {
            let older = |a: &Revoked, b: &Revoked| {
                a.del_ts < b.del_ts || (a.del_ts == b.del_ts && a.uuid < b.uuid)
            };
            let mut old = 0;
            for j in 1..state.revoked.len() {
                if older(&state.revoked[j], &state.revoked[old]) {
                    old = j;
                }
            }
            // Every hub drops the same one, so the lists stay equal.
            if older(inp, &state.revoked[old]) {
                return false;
            }
            let o = &state.revoked[old];
            crate::hlog_warning!(
                "[REVOKE] Revoke list full ({}): dropping the oldest, {} ({}); it can no longer \
                 be wiped if it connects\n",
                MAX_REVOKED,
                o.uuid,
                if o.nick.is_empty() {
                    "no nick"
                } else {
                    o.nick.as_str()
                }
            );
            state.revoked.swap_remove(old);
        }
        state.revoked.push(inp.clone());
        state.config_dirty = true;
        return true;
    };
    let r = &mut state.revoked[i];
    let mut changed = false;
    if inp.pub_ts > r.pub_ts || (inp.pub_ts == r.pub_ts && inp.pub_key > r.pub_key) {
        r.pub_key = inp.pub_key.clone();
        r.pub_ts = inp.pub_ts;
        changed = true;
    }
    if r.nick.is_empty() && !inp.nick.is_empty() {
        r.nick = inp.nick.clone();
        changed = true;
    }
    if inp.wiped_ts > r.wiped_ts {
        r.wiped_ts = inp.wiped_ts;
        changed = true;
    }
    if inp.del_ts < r.del_ts {
        r.del_ts = inp.del_ts;
        changed = true;
    }
    if changed {
        state.config_dirty = true;
    }
    changed
}

/// hub_revoke_parse(): `rest` = everything after "rv|".  Every field is
/// checked; a bad line is dropped whole.
pub fn parse(rest: &str) -> Option<Revoked> {
    let f: Vec<&str> = rest.split('|').collect();
    if f.len() != 6 || !cstr::is_uuid(f[0]) || !pub_ok(f[1]) {
        return None;
    }
    let num = |s: &str| -> Option<i64> {
        if s.is_empty() || s.len() >= 24 {
            return None;
        }
        let (v, n) = cstr::strtoll(s);
        (n == s.len() && v >= 0).then_some(v)
    };
    let r = Revoked {
        uuid: f[0].to_string(),
        pub_key: f[1].to_string(),
        pub_ts: num(f[2])?,
        nick: nick_clean(f[3]),
        wiped_ts: num(f[4])?,
        del_ts: num(f[5])?,
    };
    (r.del_ts > 0).then_some(r)
}

/// hub_revoke_format().
pub fn format(r: &Revoked) -> String {
    format!(
        "rv|{}|{}|{}|{}|{}|{}\n",
        r.uuid, r.pub_key, r.pub_ts, r.nick, r.wiped_ts, r.del_ts
    )
}

/// hub_revoke_append().
pub fn append(state: &HubState, out: &mut String) {
    for r in &state.revoked {
        out.push_str(&format(r));
    }
}

/// hub_revoke_from_bot(): a deleted bot that has a key goes on the list (bot
/// del, a synced delete, a config load — so tombstones from before the list
/// existed migrate).  True when the list changed.
pub fn from_bot(state: &mut HubState, b: &BotConfig) -> bool {
    if b.is_active || !cstr::is_uuid(&b.uuid) {
        return false;
    }
    let mut r = Revoked {
        uuid: b.uuid.clone(),
        ..Default::default()
    };
    let mut have_pub = false;
    for e in &b.entries {
        match e.key.as_str() {
            "pub" if pub_ok(&e.value) => {
                r.pub_key = e.value.clone();
                r.pub_ts = e.timestamp;
                have_pub = true;
            }
            "n" => r.nick = nick_clean(&e.value),
            "d" => r.del_ts = e.timestamp,
            _ => {}
        }
    }
    if !have_pub || r.del_ts <= 0 {
        return false;
    }
    merge(state, &r)
}

/// hub_revoke_migrate().
pub fn migrate(state: &mut HubState) -> usize {
    let bots: Vec<BotConfig> = state
        .bots
        .iter()
        .filter(|b| !b.is_active)
        .cloned()
        .collect();
    bots.iter().filter(|b| from_bot(state, b)).count()
}

/// hub_revoke_mark_wiped(): the bot wiped itself: stamp it.  The rv| line to
/// sync is returned.
pub fn mark_wiped(state: &mut HubState, uuid: &str, now: i64) -> Option<String> {
    let i = state.revoked.iter().position(|r| r.uuid == uuid)?;
    if now > state.revoked[i].wiped_ts {
        state.revoked[i].wiped_ts = now;
    }
    state.config_dirty = true;
    Some(format(&state.revoked[i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const U1: &str = "11111111-2222-3333-4444-555555555555";

    fn key() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([7u8; COMBINED_KEY_LEN])
    }

    #[test]
    fn rv_round_trip_and_rejects() {
        let line = format!("{U1}|{}|5|alpha|0|9", key());
        let r = parse(&line).unwrap();
        assert_eq!(format(&r), format!("rv|{line}\n"));
        assert!(parse(&format!("{U1}|{}|5|alpha|0|0", key())).is_none()); // del_ts 0
        assert!(parse(&format!("{U1}|short|5|alpha|0|9")).is_none());
        assert!(parse(&format!("{U1}|{}|5|alpha|0", key())).is_none());
        assert_eq!(
            parse(&format!("{U1}|{}|5|a b|0|9", key())).unwrap().nick,
            ""
        );
    }

    #[test]
    fn merge_is_a_union() {
        let mut s = HubState::new();
        let mut r = parse(&format!("{U1}|{}|5||0|9", key())).unwrap();
        assert!(merge(&mut s, &r));
        assert!(!merge(&mut s, &r));
        r.nick = "alpha".into();
        r.wiped_ts = 20;
        r.del_ts = 8;
        assert!(merge(&mut s, &r));
        let got = find(&s, U1).unwrap();
        assert_eq!(
            (got.nick.as_str(), got.wiped_ts, got.del_ts),
            ("alpha", 20, 8)
        );
        r.wiped_ts = 3;
        r.del_ts = 50;
        assert!(!merge(&mut s, &r));
    }

    #[test]
    fn hs_lww() {
        let mut s = HubState::new();
        assert_eq!(gsetting_ingest(&mut s, "autopurge|30|100"), Some(true));
        assert_eq!(gsetting_ingest(&mut s, "autopurge|7|99"), Some(false));
        assert_eq!(gsetting_ingest(&mut s, "autopurge|40|100"), Some(true));
        assert_eq!(gsetting_ingest(&mut s, "autopurge|-1|200"), None);
        assert_eq!(gsetting_ingest(&mut s, "nosuch|1|200"), None);
        assert_eq!(s.purge_days_setting, 40);
        assert_eq!(
            gsetting_format(&s, "autopurge").unwrap(),
            "hs|autopurge|40|100\n"
        );
    }
}
