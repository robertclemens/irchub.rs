//! Admin flags (`uf|`) and oper channel bindings (`uc|`) — C `hub_access.c`.
//!
//! irchub docs/plans/2026-10-16_user_flags_plan.md §3: one `uf|` per user
//! uuid, one `uc|` per (user uuid, channel).  Both are last-writer-wins and
//! fail closed: no flags record means no flags, no live binding means no
//! channel access.  Every writer (config load, bot push, peer sync, console)
//! goes through `uflag_put` / `uchan_put`, which validate and cap every field,
//! so the bulk ceilings in consts.rs stay hard bounds.

use crate::consts::*;
use crate::cstr::atoll;
use crate::state::{HubState, UchanRecord, UflagRecord, lww_accepts};

fn uuid_shape(u: &str) -> bool {
    let b = u.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Letters only, each from `USER_FLAG_LETTERS`, any order, repeats allowed;
/// the result has them once each in canonical order.  "" is valid (no flags).
pub fn uflags_canon(input: &str) -> Option<String> {
    let mut have = [false; USER_FLAG_LETTERS.len()];
    for c in input.bytes() {
        have[USER_FLAG_LETTERS.bytes().position(|l| l == c)?] = true;
    }
    Some(
        USER_FLAG_LETTERS
            .chars()
            .zip(have)
            .filter(|&(_, h)| h)
            .map(|(c, _)| c)
            .collect(),
    )
}

/// A flag change as typed: "+c-u" edits `cur`, "chu" (or "+chu" with no '-')
/// replaces it.  A leading '+' alone ("+a") is a replace.  None on an unknown
/// letter or an empty spec.
pub fn uflags_edit(cur: &str, spec: &str) -> Option<String> {
    if spec.is_empty() {
        return None;
    }
    if !spec.contains('-') {
        let body = spec.strip_prefix('+').unwrap_or(spec);
        if spec.starts_with('+') && body.is_empty() {
            return None;
        }
        return uflags_canon(body);
    }
    let work = uflags_canon(cur).unwrap_or_default();
    let mut have = [false; USER_FLAG_LETTERS.len()];
    for c in work.bytes() {
        have[USER_FLAG_LETTERS.bytes().position(|l| l == c)?] = true;
    }
    let mut sign = 0;
    let mut any = false;
    for c in spec.bytes() {
        if c == b'+' || c == b'-' {
            sign = if c == b'+' { 1 } else { -1 };
            continue;
        }
        let at = USER_FLAG_LETTERS.bytes().position(|l| l == c)?;
        if sign == 0 {
            return None;
        }
        have[at] = sign > 0;
        any = true;
    }
    if !any {
        return None;
    }
    Some(
        USER_FLAG_LETTERS
            .chars()
            .zip(have)
            .filter(|&(_, h)| h)
            .map(|(c, _)| c)
            .collect(),
    )
}

/// LWW for a flag set: newer stamp wins; on a tie the fewer rights win (no
/// 'a' beats 'a', then the shorter string, then the byte-wise smaller), so
/// every node picks the same side and a race never grants.
pub fn uflags_accepts(in_ts: i64, input: &str, cur_ts: i64, cur: &str) -> bool {
    if crate::state::ts_ahead(in_ts) {
        return false;
    }
    if in_ts != cur_ts {
        return in_ts > cur_ts;
    }
    let (ia, ca) = (input.contains('a'), cur.contains('a'));
    if ia != ca {
        return !ia;
    }
    if input.len() != cur.len() {
        return input.len() < cur.len();
    }
    input < cur
}

/// "*", or a channel name: # or & then 1..MAX_CHAN-2 bytes with no blank,
/// comma, '|', ':', control byte or 0x7f.
pub fn uchan_name_ok(chan: &str) -> bool {
    if chan == "*" {
        return true;
    }
    let b = chan.as_bytes();
    if b.len() < 2 || b.len() >= MAX_CHAN || (b[0] != b'#' && b[0] != b'&') {
        return false;
    }
    b.iter()
        .all(|&c| c > 0x20 && c != 0x7f && c != b',' && c != b'|' && c != b':')
}

pub fn uflag_find(state: &HubState, uuid: &str) -> Option<usize> {
    state.uflag_records.iter().position(|r| r.uuid == uuid)
}

pub fn uchan_find(state: &HubState, uuid: &str, chan: &str) -> Option<usize> {
    state
        .uchan_records
        .iter()
        .position(|r| r.uuid == uuid && r.chan.eq_ignore_ascii_case(chan))
}

/// Store a `uf|` if it wins LWW.  true = stored (a change).
pub fn uflag_put(state: &mut HubState, uuid: &str, flags: &str, ts: i64) -> bool {
    let Some(canon) = uflags_canon(flags) else {
        return false;
    };
    if !uuid_shape(uuid) || ts <= 0 || crate::state::ts_ahead(ts) {
        return false;
    }
    let i = match uflag_find(state, uuid) {
        Some(i) => {
            let r = &state.uflag_records[i];
            if !uflags_accepts(ts, &canon, r.timestamp, &r.flags) {
                return false;
            }
            i
        }
        None => {
            if state.uflag_records.len() >= MAX_HUB_USER_FLAGS {
                crate::hlog_warning!(
                    "[ACCESS] Flag table full ({}): uf| for {} dropped\n",
                    MAX_HUB_USER_FLAGS,
                    state.who('u', uuid)
                );
                return false;
            }
            state.uflag_records.push(UflagRecord {
                uuid: uuid.to_string(),
                ..Default::default()
            });
            state.uflag_records.len() - 1
        }
    };
    // a drop of 'a' is remembered for the admin floor
    if state.uflag_records[i].flags.contains('a') && !canon.contains('a') {
        let k = state.adrop_next;
        state.adrop_next = (k + 1) % ADMIN_DROP_LOG;
        state.adrop[k] = (uuid.to_string(), ts);
    }
    let r = &mut state.uflag_records[i];
    r.flags = canon;
    r.timestamp = ts;
    state.config_dirty = true;
    true
}

/// Store a `uc|` if it wins LWW.  true = stored (a change).
pub fn uchan_put(state: &mut HubState, uuid: &str, chan: &str, active: bool, ts: i64) -> bool {
    if !uuid_shape(uuid) || !uchan_name_ok(chan) || ts <= 0 || crate::state::ts_ahead(ts) {
        return false;
    }
    let i = match uchan_find(state, uuid, chan) {
        Some(i) => {
            let r = &state.uchan_records[i];
            if !lww_accepts(ts, active, r.timestamp, r.is_active) {
                return false;
            }
            i
        }
        None => {
            // a tombstone older than the last purge is not re-created
            if !active && crate::storage::purge_floor_blocks(state, ts) {
                return false;
            }
            if state.uchan_records.len() >= MAX_HUB_CHAN_BINDS {
                crate::hlog_warning!(
                    "[ACCESS] Binding table full ({}): uc| {} for {} dropped\n",
                    MAX_HUB_CHAN_BINDS,
                    chan,
                    state.who('u', uuid)
                );
                return false;
            }
            state.uchan_records.push(UchanRecord {
                uuid: uuid.to_string(),
                chan: chan.to_string(),
                ..Default::default()
            });
            state.uchan_records.len() - 1
        }
    };
    let r = &mut state.uchan_records[i];
    r.is_active = active;
    r.timestamp = ts;
    state.config_dirty = true;
    true
}

/// The flags a user holds ("" for none or an unknown uuid).
pub fn user_flags<'a>(state: &'a HubState, uuid: &str) -> &'a str {
    uflag_find(state, uuid).map_or("", |i| state.uflag_records[i].flags.as_str())
}

/// Admin flag check: 'a' passes every letter.
pub fn user_has_flag(state: &HubState, uuid: &str, flag: char) -> bool {
    let f = user_flags(state, uuid);
    f.contains('a') || (flag != '\0' && f.contains(flag))
}

/// An oper's channel access: a live "*" or a live binding to `chan`.
pub fn user_chan_ok(state: &HubState, uuid: &str, chan: Option<&str>) -> bool {
    state.uchan_records.iter().any(|r| {
        r.is_active
            && r.uuid == uuid
            && (r.chan == "*" || chan.is_some_and(|c| r.chan.eq_ignore_ascii_case(c)))
    })
}

/// Live bindings of one user, and whether "*" is among them.
pub fn user_chan_count(state: &HubState, uuid: &str) -> (usize, bool) {
    let live = state
        .uchan_records
        .iter()
        .filter(|r| r.is_active && r.uuid == uuid);
    let (mut n, mut global) = (0, false);
    for r in live {
        n += 1;
        global |= r.chan == "*";
    }
    (n, global)
}

pub fn format_uflag(r: &UflagRecord) -> String {
    format!("uf|{}|{}|{}\n", r.uuid, r.flags, r.timestamp)
}

pub fn format_uchan(r: &UchanRecord) -> String {
    format!(
        "uc|{}|{}|{}|{}\n",
        r.uuid,
        r.chan,
        if r.is_active { "add" } else { "del" },
        r.timestamp
    )
}

/// One record body (after "uf|" / "uc|").  kind 'f' or 'c'.  Some(changed),
/// None on a malformed line.  need_user: drop a record whose user this hub
/// does not hold (peer sync, bot push: the a|/o| lines come first in every
/// generated payload).
pub fn ingest(state: &mut HubState, kind: char, body: &str, need_user: bool) -> Option<bool> {
    if body.len() >= UC_LINE_MAX {
        return None;
    }
    let body = body.trim_end_matches(['\n', '\r']);
    let f: Vec<&str> = body.splitn(6, '|').collect();
    if need_user && !state.user_records.iter().any(|u| u.uuid == f[0]) {
        return None;
    }
    if kind == 'f' {
        if f.len() != 3 {
            return None;
        }
        Some(uflag_put(state, f[0], f[1], atoll(f[2])))
    } else {
        if f.len() != 4 || (f[2] != "add" && f[2] != "del") {
            return None;
        }
        Some(uchan_put(state, f[0], f[1], f[2] == "add", atoll(f[3])))
    }
}

/// §3.3: every live admin without a `uf|` becomes "a", every live oper
/// without any `uc|` becomes "*".  This is how a user written without access
/// records gets its default (-setup's first admin is one); run after config
/// load and after every ingest batch.  Stamped
/// `USER_ACCESS_MIGRATE_TS` (1), never "now": see C `hub_access_migrate`.
/// Returns how many records it wrote.
pub fn migrate(state: &mut HubState) -> usize {
    let now = USER_ACCESS_MIGRATE_TS;
    let mut made = 0;
    let users: Vec<(String, char)> = state
        .user_records
        .iter()
        .filter(|u| u.is_active)
        .map(|u| (u.uuid.clone(), u.typ))
        .collect();
    for (uuid, typ) in users {
        if typ == 'a' && uflag_find(state, &uuid).is_none() {
            if uflag_put(state, &uuid, "a", now) {
                made += 1;
            }
        } else if typ == 'o'
            && !state.uchan_records.iter().any(|r| r.uuid == uuid)
            && uchan_put(state, &uuid, "*", true, now)
        {
            made += 1;
        }
    }
    if made > 0 {
        crate::hlog_info!(
            "[ACCESS] Migrated {} user{} to flags / channel bindings (admins: +a, opers: *)\n",
            made,
            if made == 1 { "" } else { "s" }
        );
    }
    made
}

/// The dedup merged two user records into one uuid: follow it.  A record
/// left on `from` (its target already had one) goes with the next `prune`.
pub fn remap_uuid(state: &mut HubState, from: &str, to: &str) {
    for i in 0..state.uflag_records.len() {
        if state.uflag_records[i].uuid != from {
            continue;
        }
        match uflag_find(state, to) {
            None => state.uflag_records[i].uuid = to.to_string(),
            Some(d) if d != i => {
                let (sf, st) = (
                    state.uflag_records[i].flags.clone(),
                    state.uflag_records[i].timestamp,
                );
                let dst = &mut state.uflag_records[d];
                if uflags_accepts(st, &sf, dst.timestamp, &dst.flags) {
                    dst.flags = sf;
                    dst.timestamp = st;
                }
            }
            Some(_) => {}
        }
    }
    for i in 0..state.uchan_records.len() {
        if state.uchan_records[i].uuid != from {
            continue;
        }
        let chan = state.uchan_records[i].chan.clone();
        match uchan_find(state, to, &chan) {
            None => state.uchan_records[i].uuid = to.to_string(),
            Some(d) if d != i => {
                let (sa, st) = (
                    state.uchan_records[i].is_active,
                    state.uchan_records[i].timestamp,
                );
                let dst = &mut state.uchan_records[d];
                if lww_accepts(st, sa, dst.timestamp, dst.is_active) {
                    dst.is_active = sa;
                    dst.timestamp = st;
                }
            }
            Some(_) => {}
        }
    }
}

/// Drop records whose user is gone from user_records, and duplicates left
/// behind by a remap; keep the first of each.
pub fn prune(state: &mut HubState) {
    let users: Vec<String> = state.user_records.iter().map(|u| u.uuid.clone()).collect();
    let mut kept: Vec<UflagRecord> = Vec::new();
    for r in std::mem::take(&mut state.uflag_records) {
        if users.contains(&r.uuid) && !kept.iter().any(|k| k.uuid == r.uuid) {
            kept.push(r);
        }
    }
    state.uflag_records = kept;
    let mut kept: Vec<UchanRecord> = Vec::new();
    for r in std::mem::take(&mut state.uchan_records) {
        if users.contains(&r.uuid)
            && !kept
                .iter()
                .any(|k| k.uuid == r.uuid && k.chan.eq_ignore_ascii_case(&r.chan))
        {
            kept.push(r);
        }
    }
    state.uchan_records = kept;
}

/// Purge: drop binding tombstones older than `cutoff` (0 = all of them).  A
/// "*" del of a live user is never purged: it keeps `migrate` from making a
/// channel-bound oper global again.  Returns how many it dropped.
pub fn purge(state: &mut HubState, cutoff: i64) -> usize {
    let live: Vec<String> = state
        .user_records
        .iter()
        .filter(|u| u.is_active)
        .map(|u| u.uuid.clone())
        .collect();
    // A live binding to a channel nobody manages is an orphan: the channel
    // went (or never was -- user chan add needs a managed one).
    let orphan: Vec<bool> = state
        .uchan_records
        .iter()
        .map(|r| {
            r.is_active && r.chan != "*" && crate::storage::chan_live(state, &r.chan).is_none()
        })
        .collect();
    let before = state.uchan_records.len();
    let mut i = 0;
    state.uchan_records.retain(|r| {
        i += 1;
        !(orphan[i - 1]
            || (!r.is_active
                && (cutoff == 0 || r.timestamp < cutoff)
                && !(live.contains(&r.uuid) && r.chan == "*")))
    });
    let dropped = before - state.uchan_records.len();
    prune(state);
    if dropped > 0 {
        state.config_dirty = true;
    }
    dropped
}

/// Every `uf|` and `uc|` line for users that pass `keep` (None = all).
pub fn append(state: &HubState, out: &mut String, keep: Option<&dyn Fn(&str) -> bool>) {
    for r in &state.uflag_records {
        if keep.is_none_or(|k| k(&r.uuid)) {
            out.push_str(&format_uflag(r));
        }
    }
    for r in &state.uchan_records {
        if keep.is_none_or(|k| k(&r.uuid)) {
            out.push_str(&format_uchan(r));
        }
    }
}

// ---- Console helpers (T4) --------------------------------------------------

/// A user's live bindings as the console shows them: "*" when global, else
/// the channels comma-joined in table order ("" for none), cut like C's
/// 512-byte buffer (whole entries only).
pub fn user_chans(state: &HubState, uuid: &str) -> String {
    if user_chan_count(state, uuid).1 {
        return "*".to_string();
    }
    let mut out = String::new();
    for r in state
        .uchan_records
        .iter()
        .filter(|r| r.is_active && r.uuid == uuid)
    {
        let add = if out.is_empty() { 0 } else { 1 } + r.chan.len();
        if out.len() + add >= 512 {
            break;
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&r.chan);
    }
    out
}

/// The stamp for a change to `uuid`'s access records: now, past every stamp
/// those records already carry, so each line written wins everywhere.
pub fn next_ts(state: &HubState, uuid: &str) -> i64 {
    let mut prev = uflag_find(state, uuid).map_or(0, |i| state.uflag_records[i].timestamp);
    for r in state.uchan_records.iter().filter(|r| r.uuid == uuid) {
        prev = prev.max(r.timestamp);
    }
    crate::state::lww_next_ts(prev)
}

/// Write an oper binding change the U10 way, appending every `uc|` line
/// written to `out`.  add "*": "*" add and every live channel del; add #c: #c
/// add and "*" del; del "*": every live binding del; del #c: #c del.  The
/// number of lines written, or None when the table is full.  C
/// `hub_access_chan_change`.
pub fn chan_change(
    state: &mut HubState,
    uuid: &str,
    add: bool,
    chan: &str,
    out: &mut String,
) -> Option<usize> {
    let ts = next_ts(state, uuid);
    let star = chan == "*";
    let mut n = 0;
    let mut emit = |state: &mut HubState, c: &str, act: bool, out: &mut String| -> bool {
        if !uchan_put(state, uuid, c, act, ts) {
            return false;
        }
        if let Some(i) = uchan_find(state, uuid, c) {
            out.push_str(&format_uchan(&state.uchan_records[i]));
        }
        n += 1;
        true
    };
    let live_of = |state: &HubState| -> Vec<String> {
        state
            .uchan_records
            .iter()
            .filter(|r| r.is_active && r.uuid == uuid)
            .map(|r| r.chan.clone())
            .collect()
    };
    if add {
        if !emit(state, chan, true, out) {
            return None;
        }
        // the other kind goes: "*" clears the channels, a channel clears "*"
        for c in live_of(state) {
            let c_star = c == "*";
            if (if star { !c_star } else { c_star }) && !emit(state, &c, false, out) {
                return None;
            }
        }
        // a channel-bound oper always carries a "*" del (migrate)
        if !star && uchan_find(state, uuid, "*").is_none() && !emit(state, "*", false, out) {
            return None;
        }
    } else if star {
        for c in live_of(state) {
            if !emit(state, &c, false, out) {
                return None;
            }
        }
        if uchan_find(state, uuid, "*").is_none() && !emit(state, "*", false, out) {
            return None;
        }
    } else if !emit(state, chan, false, out) {
        return None;
    }
    Some(n)
}

fn adrop_match(state: &HubState, uuid: &str, ts: i64) -> bool {
    state.adrop.iter().any(|(u, t)| *t == ts && u == uuid)
}

/// The admin floor.  A hub refuses to remove the last +a admin itself
/// (`last_full_admin`), but two hubs can each remove a different one before
/// they sync, and a hubless bot can push a removal.  When no active admin
/// holds +a, every +a removal stamped within `ADMIN_FLOOR_WINDOW` of the
/// newest one is undone: a deleted admin comes back with the masks dropped
/// with it, an admin that lost 'a' is "a" again -- each at its removal stamp + 1.
/// Every hub holds the same records by then, so each writes the same
/// records and the mesh agrees; the stamps beat the removals everywhere.  A
/// flag drop is known only from `adrop` (the `uf|` no longer says it held
/// 'a').  Returns the sync lines for the peers (None when nothing was
/// restored) and how many admins came back.  C `hub_admin_floor_restore`.
pub fn admin_floor_restore(state: &mut HubState, from: &str) -> Option<(String, usize)> {
    let mut cand: Vec<(usize, i64)> = Vec::new();
    let mut newest = 0i64;
    for (i, u) in state.user_records.iter().enumerate() {
        if u.typ != 'a' {
            continue;
        }
        let has_a = user_flags(state, &u.uuid).contains('a');
        if u.is_active && has_a {
            state.floor_warned = false;
            return None; // a full admin is left
        }
        let fr = uflag_find(state, &u.uuid).map(|k| state.uflag_records[k].timestamp);
        let dropped = !has_a && fr.is_some_and(|t| adrop_match(state, &u.uuid, t));
        if !(dropped || (has_a && !u.is_active)) {
            continue;
        }
        let mut t = if u.is_active { 0 } else { u.timestamp };
        if dropped
            && let Some(ft) = fr
            && ft > t
        {
            t = ft;
        }
        cand.push((i, t));
        newest = newest.max(t);
    }
    if cand.is_empty() {
        if !state.floor_warned {
            crate::hlog_warning!(
                "[ADMIN] No full admin (+a) is left after {from}, and no recent +a removal to undo\n"
            );
        }
        state.floor_warned = true;
        return None;
    }
    let mut out = String::new();
    let mut restored = 0usize;
    for (ci, t) in cand {
        if t < newest - ADMIN_FLOOR_WINDOW {
            continue;
        }
        let was_del = !state.user_records[ci].is_active;
        let mut lost_a = false;
        let uuid = state.user_records[ci].uuid.clone();
        if was_del {
            let del_ts = state.user_records[ci].timestamp;
            let u = &mut state.user_records[ci];
            u.is_active = true;
            u.timestamp = del_ts.saturating_add(1);
            out.push_str(&crate::config::format_user_record(u));
            // the masks this delete dropped (DEL_ADMIN stamps them with it)
            for mr in state.mask_records.iter_mut() {
                if mr.is_active
                    || mr.uuid != uuid
                    || mr.timestamp < del_ts - 2
                    || mr.timestamp > del_ts.saturating_add(2)
                {
                    continue;
                }
                mr.is_active = true;
                mr.timestamp = mr.timestamp.saturating_add(1);
                out.push_str(&format!(
                    "m|{}|{}|add|{}|{}\n",
                    mr.uuid, mr.mask, mr.last_used, mr.timestamp
                ));
            }
        }
        if !user_flags(state, &uuid).contains('a')
            && let Some(k) = uflag_find(state, &uuid)
        {
            // back to "a": it held 'a', which covers every other letter
            let ts = state.uflag_records[k].timestamp;
            if uflag_put(state, &uuid, "a", ts.saturating_add(1)) {
                lost_a = true;
                out.push_str(&format_uflag(&state.uflag_records[k]));
            }
        }
        restored += 1;
        crate::hlog_warning!(
            "[ADMIN] No full admin (+a) was left after {from}: restored {} ({})\n",
            state.who('u', &uuid),
            if was_del && lost_a {
                "deleted, lost +a"
            } else if was_del {
                "deleted"
            } else {
                "lost +a"
            }
        );
    }
    state.config_dirty = true;
    state.floor_warned = false;
    Some((out, restored))
}
