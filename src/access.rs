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
use crate::state::{HubState, UchanRecord, UflagRecord, UserRecord, lww_accepts};

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
    if !uuid_shape(uuid) || ts <= 0 {
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
                    uuid
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
    let r = &mut state.uflag_records[i];
    r.flags = canon;
    r.timestamp = ts;
    state.config_dirty = true;
    true
}

/// Store a `uc|` if it wins LWW.  true = stored (a change).
pub fn uchan_put(state: &mut HubState, uuid: &str, chan: &str, active: bool, ts: i64) -> bool {
    if !uuid_shape(uuid) || !uchan_name_ok(chan) || ts <= 0 {
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
                    uuid
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

/// A user an older node would over-trust (§3.2): an admin whose `uf|` is
/// not exactly "a", or an oper with `uc|` records but no live "*".  A user
/// with no records yet is not: `migrate` makes it +a / * at the end of the
/// batch that brought it, which is what an older node assumes anyway.
pub fn user_restricted(state: &HubState, u: &UserRecord) -> bool {
    if !u.is_active {
        return false;
    }
    if u.typ == 'a' {
        return uflag_find(state, &u.uuid).is_some_and(|i| state.uflag_records[i].flags != "a");
    }
    let any = state.uchan_records.iter().any(|r| r.uuid == u.uuid);
    any && !user_chan_count(state, &u.uuid).1
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
/// without any `uc|` becomes "*" -- what they could do before flags existed.
/// Run after config load and after every ingest batch.  Stamped
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

// ---- Older nodes (plan §3.2, T2) -------------------------------------------
// See C hub_access.c: a peer hub whose version is not known yet (or older
// than MESH_MIN_VERSION, its link being refused) never gets uf| / uc|, sees each
// user at `user_ts`, gets a restricted user as a tombstone (a node known to be
// older) or not at all (one whose version is not known yet), never with its
// masks, and nothing it sends about a restricted user is taken in.

/// The newest stamp of a user's own record and its uf| / uc| records.
pub fn user_ts(state: &HubState, u: &UserRecord) -> i64 {
    let f = uflag_find(state, &u.uuid).map_or(0, |i| state.uflag_records[i].timestamp);
    let c = state
        .uchan_records
        .iter()
        .filter(|r| r.uuid == u.uuid)
        .map(|r| r.timestamp)
        .max()
        .unwrap_or(0);
    u.timestamp.max(f).max(c)
}

/// u's a|/o| line for an older node; "" = left out (a restricted user and
/// not `tomb`).
pub fn format_user_for_old(state: &HubState, u: &UserRecord, tomb: bool) -> String {
    let restricted = user_restricted(state, u);
    if restricted && !tomb {
        return String::new();
    }
    let mut c = u.clone();
    c.timestamp = user_ts(state, u);
    if restricted {
        c.is_active = false;
    }
    crate::config::format_user_record(&c)
}

/// A record an older node sent about user `uuid` may be taken in: not about
/// a restricted user.
pub fn from_old_ok(state: &HubState, uuid: &str) -> bool {
    state
        .user_records
        .iter()
        .find(|u| u.uuid == uuid)
        .is_none_or(|u| !user_restricted(state, u))
}

/// A sync payload rewritten for an older hub: uf| / uc| / rv| / hs| and a
/// bot's b|<uuid>|hl| dropped (an older hub's parser turns an unknown rv| or
/// hs| line into a phantom bot; its whitelist refuses hl), a| / o|
/// re-stamped (`format_user_for_old`), m| of a restricted user dropped;
/// every other line as it was.
pub fn downgrade(state: &HubState, payload: &str, tomb: bool) -> String {
    let mut out = String::with_capacity(payload.len());
    for line in payload.split('\n') {
        if line.is_empty() {
            continue;
        }
        let b = line.as_bytes();
        if b.len() > 3 && b[0] == b'u' && (b[1] == b'f' || b[1] == b'c') && b[2] == b'|' {
            continue;
        }
        if b.len() > 3 && (b.starts_with(b"rv") || b.starts_with(b"hs")) && b[2] == b'|' {
            continue;
        }
        if b.len() > 41 && b[0] == b'b' && b[1] == b'|' && b[38] == b'|' && &b[39..42] == b"hl|" {
            continue; // a bot's hub list: an older hub's whitelist refuses it
        }
        if b.len() > 38 && matches!(b[0], b'a' | b'o' | b'm') && b[1] == b'|' && b[38] == b'|' {
            let uuid = &line[2..38];
            if let Some(u) = state.user_records.iter().find(|u| u.uuid == uuid) {
                if b[0] == b'm' {
                    if user_restricted(state, u) {
                        continue;
                    }
                } else {
                    out.push_str(&format_user_for_old(state, u, tomb));
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
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
