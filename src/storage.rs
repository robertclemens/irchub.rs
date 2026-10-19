//! The config store (hub_storage.c): the global entry table, per-bot
//! records, and the payload generator that turns them into a bot's config.
//!
//! Every write path into per-bot state — the delta path, a config push, a
//! peer sync and config load — funnels through [`update_entry`], which is
//! where the zero-trust ingest bound lives: a bot's per-bot state is exactly
//! `{t, n, h, pub, seen, d}` with a per-key value cap, so it can never create
//! arbitrarily-named entries and unbound the sync payload.  That is what
//! makes `BOT_SYNC_FIELDS` a hard bound (see `consts`).

use crate::consts::*;
use crate::cstr::trunc_string;
use crate::state::{BotConfig, ConfigEntry, HubState, global_value_active, lww_accepts};
use crate::{config, crypto, mesh};
use std::collections::HashMap;

/// hub_storage_init(): nothing to do; the tables live in [`HubState::new`].
pub fn init() {}

/// Find the bot, or register it when there is room.
fn get_or_create_bot<'a>(state: &'a mut HubState, uuid: &str) -> Option<&'a mut BotConfig> {
    if let Some(i) = state.bots.iter().position(|b| b.uuid == uuid) {
        return Some(&mut state.bots[i]);
    }
    if state.bots.len() < MAX_BOTS {
        state.bots.push(BotConfig {
            uuid: trunc_string(uuid, 64),
            entries: Vec::new(),
            is_active: true,
            last_sync_time: 0,
        });
        return state.bots.last_mut();
    }
    None
}

/// The part of a stored value before its first '|' — what list entries match
/// on.  A value with no '|' matches whole.
fn first_field(value: &str) -> &str {
    match value.find('|') {
        Some(i) => &value[..i],
        None => value,
    }
}

/// ASCII case-insensitive equality (channel names, ban masks; D39).
/// hub_ascii_ieq().
pub fn ascii_ieq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Record kinds that live in `global_entries` beside c|/m|/o|.
fn key_is_modes(key: &str) -> bool {
    matches!(key, "C" | "D" | "B")
}

/// Length of a value's identity prefix: the channel (c|, C|), channel|mask
/// (B|), else the first field.
fn ident_len(key: &str, v: &str) -> usize {
    let fields = if key == "B" { 2 } else { 1 };
    let mut from = 0;
    for f in 0..fields {
        match v[from..].find('|') {
            None => return v.len(),
            Some(bar) => {
                if f == fields - 1 {
                    return from + bar;
                }
                from += bar + 1;
            }
        }
    }
    v.len()
}

/// hub_global_identity_eq(): whether two stored values of global key `key`
/// are the same RECORD: c|/C| compare the channel field, B| the channel and
/// mask (all ASCII case-insensitive), the singletons a/p/D always match,
/// every other key its first field case-sensitively.  `a`/`b` may be a full
/// stored value or just its identity prefix.
pub fn global_identity_eq(key: &str, a: &str, b: &str) -> bool {
    // Singletons: a|, p|, D| -- one record per key.
    if matches!(key, "a" | "p" | "D") {
        return true;
    }
    let (la, lb) = (ident_len(key, a), ident_len(key, b));
    if la != lb {
        return false;
    }
    let (x, y) = (&a.as_bytes()[..la], &b.as_bytes()[..lb]);
    if matches!(key, "c" | "C" | "B") {
        x.eq_ignore_ascii_case(y)
    } else {
        x == y
    }
}

/// Derived from `global_entries` (hub_storage.c's global_idx / global_n_* /
/// global_ban_chan): a hash index of (class, folded identity) -> entry index,
/// entries per class, and live bans per channel.  [`global_reindex`] rebuilds
/// all of it.  A `HashMap` stands in for the C open-addressing table; the
/// lookups, counts and bounds are the same.
#[derive(Clone, Debug, Default)]
pub struct GlobalIdx {
    /// "class\0folded identity" -> entry index (a duplicate keeps the first).
    map: HashMap<String, usize>,
    /// Folded channel -> live B| bans naming it.
    ban_chan: HashMap<String, usize>,
    n_old: usize,
    n_c: usize,
    n_d: usize,
    n_b: usize,
}

/// The identity (in the sense of [`global_identity_eq`]) as a hash key.
fn gkey(key: &str, value: &str) -> String {
    let mut k = String::with_capacity(key.len() + 1 + value.len());
    k.push_str(key);
    k.push('\0');
    if matches!(key, "a" | "p" | "D") {
        return k;
    }
    let id = &value[..ident_len(key, value)];
    if matches!(key, "c" | "C" | "B") {
        k.push_str(&id.to_ascii_lowercase());
    } else {
        k.push_str(id);
    }
    k
}

/// hub_global_find(): index of the stored global entry that `value` under
/// `key` addresses (a|/p|/D| are singletons; the rest match on their identity
/// prefix, channel and ban mask ASCII case-insensitively).  None if none.
/// O(1) through the index.
pub fn global_find(state: &HubState, key: &str, value: &str) -> Option<usize> {
    state.global_idx.map.get(&gkey(key, value)).copied()
}

fn global_entry_find(state: &HubState, key: &str, value: &str) -> Option<usize> {
    global_find(state, key, value)
}

/// The ban in entry `i` went live (`up`) or was deleted.
fn gban_adjust(state: &mut HubState, i: usize, up: bool) {
    let v = &state.global_entries[i].value;
    let chan = &v[..v.find('|').unwrap_or(v.len())];
    if chan.len() >= MAX_CHAN {
        return;
    }
    let n = state
        .global_idx
        .ban_chan
        .entry(chan.to_ascii_lowercase())
        .or_insert(0);
    *n = if up { *n + 1 } else { n.saturating_sub(1) };
}

/// hub_global_note_new(): entry `i` was just appended to `global_entries`.
pub fn global_note_new(state: &mut HubState, i: usize) {
    let e = &state.global_entries[i];
    let k = gkey(&e.key, &e.value);
    let (ek, live_ban) = (e.key.clone(), e.key == "B" && global_value_active(&e.value));
    let idx = &mut state.global_idx;
    idx.map.entry(k).or_insert(i); // a duplicate keeps the first
    match ek.as_str() {
        "C" => idx.n_c += 1,
        "D" => idx.n_d += 1,
        "B" => idx.n_b += 1,
        _ => idx.n_old += 1,
    }
    if live_ban {
        gban_adjust(state, i, true);
    }
}

/// hub_global_reindex(): `global_entries` was changed behind the store's back
/// (evict, the purge compaction): rebuild the index and counts.
pub fn global_reindex(state: &mut HubState) {
    state.global_idx = GlobalIdx::default();
    for i in 0..state.global_entries.len() {
        global_note_new(state, i);
    }
}

/// hub_global_room(): room for one more entry of `key`'s class: the old
/// c/m/o rows share MAX_BOT_ENTRIES, C| has MAX_CHANNELS, D| one, B|
/// MAX_BANS_TOTAL.
pub fn global_room(state: &HubState, key: &str) -> bool {
    let ix = &state.global_idx;
    let (n, cap) = if key_is_modes(key) {
        match key {
            "C" => (ix.n_c, MAX_CHANNELS),
            "D" => (ix.n_d, 1),
            _ => (ix.n_b, MAX_BANS_TOTAL),
        }
    } else {
        (ix.n_old, MAX_BOT_ENTRIES)
    };
    n < cap && state.global_entries.len() < MAX_GLOBAL_ENTRIES
}

/// hub_storage_global_ts(): stored timestamp of the global entry that
/// `value` under `key` addresses (same match as the update below), or 0.
pub fn global_ts(state: &HubState, key: &str, value: &str) -> i64 {
    global_entry_find(state, key, value).map_or(0, |i| state.global_entries[i].timestamp)
}

/// Sanitize the `op` argument: strip leading and trailing pipes from
/// malformed input, and default to "add".  The C code took a 16-byte copy
/// first, so an over-long op is cut before it is stripped.
fn safe_op(op: &str) -> String {
    let clean = trunc_string(op, 16);
    let s = clean.trim_start_matches('|').trim_end_matches('|');
    if s.is_empty() {
        "add".to_string()
    } else {
        s.to_string()
    }
}

/// Build the stored value for a key.  The shape depends on the type:
///   `c` → "chan|key|add" or "chan||del"
///   `m` → "mask|add" or "mask|del"
///   `o` → "mask|password|add" (per-bot) / "mask||add" (global)
///   everything else → just the value.
fn combined_value(key: &str, value: &str, extra: &str, op: &str, global: bool) -> String {
    let out = match key {
        "c" => {
            if !extra.is_empty() {
                format!("{value}|{extra}|{op}")
            } else {
                format!("{value}||{op}")
            }
        }
        "m" => format!("{value}|{op}"),
        "o" if global => {
            // Legacy global oper mask: the password slot is always stored
            // empty.  Oper passwords are retired; one arriving from an old
            // config, an old peer or an old admin client must not be kept,
            // synced or listed.
            format!("{value}||{op}")
        }
        "o" => format!("{value}|{extra}|{op}"),
        _ => value.to_string(),
    };
    trunc_string(&out, 1024)
}

/// hub_storage_update_global_entry().
pub fn update_global_entry(
    state: &mut HubState,
    key: &str,
    value: &str,
    extra: &str,
    op: &str,
    ts: i64,
) -> bool {
    // C|, D| and B| carry their own op and field set: they go through
    // put_record, never through this c/m/o composer.
    if key_is_modes(key) {
        crate::hlog_warning!("[STORAGE] Global {key}: not a c/m/o record (use put_record)\n");
        return false;
    }

    // A channel already stored keeps its first writer's spelling (D39).
    let found_idx = global_entry_find(state, key, value);
    let stored_chan;
    let mut value = value;
    if let Some(fi) = found_idx
        && key == "c"
    {
        stored_chan = trunc_string(first_field(&state.global_entries[fi].value), MAX_CHAN + 8);
        value = &stored_chan;
    }

    let op = safe_op(op);
    let combined = combined_value(key, value, extra, &op, true);

    if let Some(i) = found_idx {
        let stored_ts = state.global_entries[i].timestamp;
        if lww_accepts(
            ts,
            global_value_active(&combined),
            stored_ts,
            global_value_active(&state.global_entries[i].value),
        ) {
            crate::hlog_debug!(
                "[STORAGE] Global {key}={value}: incoming_ts={ts} {} stored_ts={stored_ts} -> UPDATED\n",
                if ts > stored_ts {
                    ">"
                } else {
                    "== (del beats add)"
                }
            );
            let removed = key == "c" && !global_value_active(&combined);
            state.global_entries[i].value = combined;
            state.global_entries[i].timestamp = ts;
            // A channel removed takes its settings and bans with it, at the
            // same stamp, on every hub (an older hub's c| del carries no C|/B|
            // dels).
            if removed {
                chan_cascade_del(state, value, ts, false);
            }
            return true;
        }
        crate::hlog_debug!(
            "[STORAGE] Global {key}={value}: incoming_ts={ts} <= stored_ts={stored_ts} -> REJECTED\n"
        );
        return false;
    }

    if global_room(state, key) {
        crate::hlog_debug!("[STORAGE] Global {key}={value}: NEW entry ts={ts}\n");
        state.global_entries.push(ConfigEntry {
            key: trunc_string(key, 32),
            value: combined,
            timestamp: ts,
            last_used: 0,
        });
        global_note_new(state, state.global_entries.len() - 1);
        return true;
    }
    crate::hlog_warning!("[STORAGE] Global {key}={value}: REJECTED (max entries reached)\n");
    false
}

/// nick!user@host, three non-empty parts, printable ASCII, no '*' or '?'.
fn hostmask_literal(h: &str) -> bool {
    let Some(bang) = h.find('!') else {
        return false;
    };
    let Some(at) = h[bang + 1..].find('@').map(|p| p + bang + 1) else {
        return false;
    };
    if bang == 0 || at == bang + 1 || at + 1 >= h.len() {
        return false;
    }
    if h[at + 1..].contains(['!', '@']) {
        return false;
    }
    h.bytes()
        .all(|c| c > 0x20 && c < 0x7f && c != b'*' && c != b'?' && c != b'|')
}

/// hub_storage_update_entry(): the single choke point for per-bot state.
/// A revoked uuid never comes back: no record is created for it but its
/// tombstone, and one that exists stays deleted.  A bot that becomes deleted
/// with a key on file joins the revoke list (`revoke`).
pub fn update_entry(
    state: &mut HubState,
    uuid: &str,
    key: &str,
    value: &str,
    extra: &str,
    op: &str,
    ts: i64,
) -> bool {
    let per_bot = matches!(key, "d" | "pub" | "n" | "h" | "t" | "seen");
    if per_bot
        && crate::revoke::is_revoked(state, uuid)
        && key != "d"
        && !state.bots.iter().any(|b| b.uuid == uuid)
    {
        return false;
    }
    let ok = update_entry_inner(state, uuid, key, value, extra, op, ts);
    if !ok || !per_bot {
        return ok;
    }
    let Some(i) = state.bots.iter().position(|b| b.uuid == uuid) else {
        return ok;
    };
    if crate::revoke::is_revoked(state, uuid) {
        state.bots[i].is_active = false;
    }
    if !state.bots[i].is_active && matches!(key, "d" | "pub" | "n") {
        let b = state.bots[i].clone();
        crate::revoke::from_bot(state, &b);
    }
    ok
}

/// hub_hublist_valid(): a bot's hl| value: up to HL_ENTRIES_MAX
/// comma-separated "<addr>/<fp>", <addr> empty or 1..HL_ADDR_MAX bytes of
/// [A-Za-z0-9.:_[]-], <fp> exactly HL_FP_LEN lowercase hex.  "" (a bot with
/// no keyed hub) is valid.
pub fn hublist_valid(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    let mut n = 0;
    for ent in v.split(',') {
        n += 1;
        if n > HL_ENTRIES_MAX {
            return false;
        }
        let Some((addr, fp)) = ent.split_once('/') else {
            return false;
        };
        if addr.len() > HL_ADDR_MAX
            || fp.len() != HL_FP_LEN
            || !addr
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".:_[]-".contains(&c))
            || !fp
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return false;
        }
    }
    true
}

fn update_entry_inner(
    state: &mut HubState,
    uuid: &str,
    key: &str,
    value: &str,
    extra: &str,
    op: &str,
    ts: i64,
) -> bool {
    // Retired password-era keys (docs/passwordless.md §3.3): the shared bot
    // password 'p' and the legacy global admin password 'a' are never stored
    // again, whichever path (delta, push, sync, load) offers them.
    if key == "p" || key == "a" {
        crate::hlog_warning!("[STORAGE] REJECTED retired key '{key}' (passwordless)\n");
        return false;
    }

    // C|, D|, B| are global records with their own writers and checks; a
    // per-bot delta or sync line under those keys is never one of them.
    if key_is_modes(key) {
        crate::hlog_warning!("[STORAGE] REJECTED key '{key}' on the per-bot path\n");
        return false;
    }

    // Global keys intercept.
    if key == "c" || key == "m" || key == "o" {
        return update_global_entry(state, key, value, extra, op, ts);
    }

    // Reject bot-specific key names being used as a UUID.
    if matches!(uuid, "n" | "h" | "seen" | "pub" | "d" | "t") {
        crate::hlog_warning!(
            "[STORAGE] REJECTED: Invalid UUID '{uuid}' (bot-specific key used as UUID)\n"
        );
        return false;
    }

    if get_or_create_bot(state, uuid).is_none() {
        return false;
    }

    // Change 3b — zero-trust per-bot ingest bound (the single enforcement
    // point for the delta path, config push, peer sync and config load).
    // Global keys were already intercepted above.  A bot's per-bot state is
    // exactly {t, n, h, pub, seen, d}; reject any other key so a hostile bot
    // or peer cannot create arbitrarily-named entries and unbound the sync
    // payload.  This is what makes BOT_SYNC_FIELDS a hard bound (see
    // `consts`).  Value length is capped per key so a per-bot line can never
    // approach value[1024].
    //
    // The bound is on entries, not on the registration above: a refused key
    // still leaves an (empty) bot record, exactly as in the C hub, so the two
    // trees converge on the same config from the same input.
    if !matches!(key, "t" | "n" | "h" | "pub" | "seen" | "d" | "hl") {
        crate::hlog_warning!(
            "[STORAGE] REJECTED per-bot key '{key}' for {uuid} (not in whitelist)\n"
        );
        return false;
    }
    {
        let cap = match key {
            "h" => MAX_MASK_LEN - 1,
            "n" => MAX_NICK - 1,
            "pub" => COMBINED_KEY_B64,
            "hl" => HL_VALUE_MAX,
            _ => 31, // seen/d/t: short numerics
        };
        let vlen = value.len();
        if vlen > cap {
            crate::hlog_warning!(
                "[STORAGE] REJECTED per-bot '{key}' for {uuid}: value too long ({vlen} > {cap})\n"
            );
            return false;
        }
        if key == "hl" && !hublist_valid(value) {
            crate::hlog_warning!("[STORAGE] REJECTED per-bot 'hl' for {uuid}: not a hub list\n");
            return false;
        }
    }

    let bi = state
        .bots
        .iter()
        .position(|b| b.uuid == uuid)
        .expect("get_or_create_bot just ensured it");

    // Special metadata: the sync timestamp is not stored as an entry.
    if key == "t" {
        if ts > state.bots[bi].last_sync_time {
            state.bots[bi].last_sync_time = ts;
            return true;
        }
        return false;
    }

    // A reported hostmask is a literal nick!user@host, never a pattern: the ban
    // protection matches bans against it, so a '*' here would shield everyone.
    if key == "h" && !value.is_empty() && !hostmask_literal(value) {
        crate::hlog_warning!(
            "[STORAGE] REJECTED per-bot 'h' for {uuid}: not a literal nick!user@host\n"
        );
        return false;
    }

    let op = safe_op(op);
    let combined = combined_value(key, value, extra, &op, false);

    // Singleton keys hold one entry; list keys match on key AND first field.
    //
    // is_active follows the 'd' entry alone.  An 'n' or 's' entry used to set
    // it back to true ("auto-undelete on check-in"): a peer still holding a
    // deleted bot's nick, or a config reload that read 'n' after 'd|1',
    // re-registered the bot.  A deleted bot cannot check in (auth needs
    // is_active), so nothing legitimate depended on it.
    let is_singleton = matches!(key, "n" | "a" | "p" | "h" | "d" | "pub" | "seen");

    let found = state.bots[bi].entries.iter().position(|e| {
        if is_singleton {
            e.key == key
        } else {
            e.key == key && trunc_string(first_field(&e.value), 256) == value
        }
    });

    if let Some(ei) = found {
        let stored_ts = state.bots[bi].entries[ei].timestamp;
        if ts < stored_ts {
            return false;
        }
        if ts > stored_ts {
            state.bots[bi].entries[ei].value = combined;
            state.bots[bi].entries[ei].timestamp = ts;
            if key == "d" {
                state.bots[bi].is_active = value != "1";
            }
            return true;
        }
        // Same stamp, different value: the byte-wise greater value wins on
        // every node.  "Last arrival wins" swapped two nodes' copies with
        // each other and kept them apart; for 'd' this makes "1" (deleted)
        // beat "0", the same delete-over-add rule as lww_accepts.
        if combined > state.bots[bi].entries[ei].value {
            state.bots[bi].entries[ei].value = combined;
            if key == "d" {
                state.bots[bi].is_active = value != "1";
            }
            return true;
        }
        return false;
    }

    if state.bots[bi].entries.len() < MAX_BOT_ENTRIES {
        state.bots[bi].entries.push(ConfigEntry {
            key: trunc_string(key, 32),
            value: combined,
            timestamp: ts,
            last_used: 0,
        });
        if key == "d" {
            state.bots[bi].is_active = value != "1";
        }
        return true;
    }

    crate::hlog_warning!("[STORAGE] Bot {uuid} has reached MAX_BOT_ENTRIES\n");
    false
}

/// hub_storage_delete(): soft-delete a registered bot with a `d|1` tombstone
/// stamped past any earlier 'd'.
///
/// A delete is a tombstone — the same record every peer stores from the sync
/// line — and the purge removes it later.  It used to remove the bot
/// outright: this hub then held nothing that outranks a peer still carrying
/// the bot live (a peer that had not yet seen the delete), and that peer's
/// next full sync registered the bot again.
///
/// None when the uuid is unknown or already deleted; otherwise the stamp.
pub fn delete(state: &mut HubState, uuid: &str) -> Option<i64> {
    let bi = state.bots.iter().position(|b| b.uuid == uuid)?;
    if !state.bots[bi].is_active {
        return None;
    }
    let prev = state.bots[bi].entry("d").map_or(0, |e| e.timestamp);
    let ts = crate::state::lww_next_ts(prev);
    if !update_entry(state, uuid, "d", "1", "", "", ts) {
        return None;
    }
    let bi = state.bots.iter().position(|b| b.uuid == uuid)?;
    if state.bots[bi].is_active {
        return None;
    }
    state.config_dirty = true;
    config::write(state);
    Some(ts)
}

/// hub_generate_bot_payload(): global + bot-specific config for one bot.
/// Global items carry no "b|uuid|" prefix, preserving protocol
/// compatibility.
///
/// `bot_proto` is what the receiving connection advertised: v|2 or more gets
/// the new a|/o|/b| shapes, less the fail-closed legacy shapes.  Below
/// `BOT_PROTO_USER_FLAGS` the bot does not know uf| / uc| (plan §3.2): users
/// are re-stamped, a restricted one is a tombstone (a v2 bot) or left out (an
/// older or not-yet-known one), and its masks and the access lines are not
/// sent.
pub fn generate_bot_payload(state: &HubState, uuid: &str, bot_proto: i32) -> String {
    let proto_v2 = bot_proto >= BOT_PROTO_PASSWORDLESS;
    let flags_ok = bot_proto >= BOT_PROTO_USER_FLAGS;
    let mut out = String::with_capacity(4096);

    // 1. Global entries (channels; skip h/n/a/m/o — now in typed arrays — and
    //    the retired bot password p).
    for e in &state.global_entries {
        if matches!(e.key.as_str(), "h" | "n" | "a" | "m" | "o" | "p") {
            continue;
        }
        out.push_str(&format!("{}|{}|{}\n", e.key, e.value, e.timestamp));
    }

    // 1a. Named admin/oper records.  A v2 (passwordless) bot gets
    //     uuid|name|pubkey|act|seen|ts|; any other connection gets the legacy
    //     shape with an EMPTY password slot, so an old bot refuses every
    //     admin command instead of reading the public key as a password.
    for u in &state.user_records {
        if flags_ok {
            out.push_str(&config::format_user_record(u, !proto_v2));
        } else {
            out.push_str(&crate::access::format_user_for_old(
                state, u, !proto_v2, proto_v2,
            ));
        }
    }

    // 1b. Usermask records (m| lines).
    for m in &state.mask_records {
        if !flags_ok && !crate::access::from_old_ok(state, &m.uuid) {
            continue;
        }
        out.push_str(&format!(
            "m|{}|{}|{}|{}|{}\n",
            m.uuid,
            m.mask,
            if m.is_active { "add" } else { "del" },
            m.last_used,
            m.timestamp
        ));
    }

    // 1b. Admin flags and oper channel bindings, after the users they name.
    if flags_ok {
        crate::access::append(state, &mut out, None);
    }

    // 1b. purge_days setting, so bots can validate purge policies.
    out.push_str(&format!(
        "pd|{}|{}\n",
        state.purge_days_setting,
        crate::cstr::now()
    ));

    // 1c. Push the network opt flag string, even when empty, so bots observe
    //     a clear.  Capital 'O' for the bot wire format.  Only with a real
    //     timestamp: a hub that has none (fresh, never synced) must not stamp
    //     "no flags" with `now` — bots would take that as newest, drop 'h'
    //     and then refuse the network's actual (older) value.
    if state.opt_flags_ts > 0 {
        out.push_str(&format!("O|{}|{}\n", state.opt_flags, state.opt_flags_ts));
    }

    // 2. This bot's own entries.  Skip h, n (hub-only metadata) and the
    //    global keys c, m, o, a, p.
    if let Some(b) = state.bots.iter().find(|b| b.uuid == uuid) {
        for e in &b.entries {
            if matches!(e.key.as_str(), "h" | "n" | "c" | "m" | "o" | "a" | "p") {
                continue;
            }
            out.push_str(&format!("{}|{}|{}\n", e.key, e.value, e.timestamp));
        }
    }

    // 3. Other bots as trusted-bot lines (for offline peer operation):
    //      v2:     b|<hostmask>|<uuid>|<pubkey>|<ts>   (pubkey seals ~B2)
    //      legacy: b|<hostmask>|<uuid>|<ts>
    //    ts = max(hostmask ts, pubkey ts) so a rekey alone is seen as newer.
    //
    //    v2 payloads end the list with T|<count>: the lines above are the
    //    whole trusted set, so the bot drops every trusted bot they do not
    //    name (a deleted or purged bot).  Without it a bot only ever added or
    //    updated trust and a revoked bot kept ~B2 and op grants forever.
    //    Bots that predate the marker ignore the unknown line.
    let mut trusted_lines = 0;
    for b in &state.bots {
        if b.uuid == uuid || !b.is_active {
            continue;
        }
        let Some(h) = b.entry("h") else { continue };
        let pubk = b.entry("pub");
        let mut ts = h.timestamp;
        if proto_v2 {
            let key_ok = pubk.is_some_and(|p| crypto::pubkey_b64_decode(&p.value).is_some());
            if key_ok
                && let Some(p) = pubk
                && p.timestamp > ts
            {
                ts = p.timestamp;
            }
            let key = if key_ok {
                pubk.map_or("", |p| p.value.as_str())
            } else {
                ""
            };
            out.push_str(&format!("b|{}|{}|{}|{}\n", h.value, b.uuid, key, ts));
        } else {
            out.push_str(&format!("b|{}|{}|{}\n", h.value, b.uuid, ts));
        }
        trusted_lines += 1;
    }
    if proto_v2 {
        out.push_str(&format!("T|{trusted_lines}\n"));
    }

    out
}

// ===========================================================================
// C| / D| / B| records (docs/modes.md §2) -- the single ingest point.
// Stored in `global_entries` as key + value + stamp; the value is the line
// between the tag and the stamp:
//   C   chan|modes|settings|op
//   D   modes|settings                      (no op, never deleted)
//   B   chan|mask|expires|flags|setter|reason|op
// Every writer -- console, bot push, peer sync, config load -- ends up in
// put_record, so the field caps and charsets are enforced once.
// ===========================================================================

const REC_MAX_FIELDS: usize = 8;

/// rec_split(): split `value` into exactly `want` '|' separated fields.
/// None when it is too long (>= cap) or has another field count.
fn rec_split(value: &str, want: usize, cap: usize) -> Option<Vec<&str>> {
    if value.len() >= cap || want > REC_MAX_FIELDS {
        return None;
    }
    let f: Vec<&str> = value.split('|').collect();
    (f.len() == want).then_some(f)
}

/// A channel name the bots can JOIN (# or &, no blank/comma/control), or "*".
fn rec_chan_ok(s: &str, star_ok: bool) -> bool {
    if star_ok && s == "*" {
        return true;
    }
    let b = s.as_bytes();
    if b.len() < 2 || b.len() >= MAX_CHAN || (b[0] != b'#' && b[0] != b'&') {
        return false;
    }
    b.iter()
        .all(|&c| c > 0x20 && c != b',' && c != 0x7f && c != b'|')
}

/// Free text: no control characters (UTF-8 bytes pass), <= max.  A ban
/// reason may hold '|': op and stamp are taken from the END of the line.
fn rec_text_ok(s: &str, max: usize) -> bool {
    s.len() <= max && s.bytes().all(|c| c >= 0x20 && c != 0x7f)
}

/// A hostmask pattern: printable ASCII, no blank, comma or '|'.
fn rec_mask_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= BAN_MASK_MAX
        && s.bytes()
            .all(|c| c > 0x20 && c < 0x7f && c != b',' && c != b'|')
}

fn rec_modes_ok(s: &str) -> bool {
    s.len() <= C_MODES_MAX
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-' || c == b' ')
}

/// Split a settings string into its comma-separated tokens the way the C
/// walkers do: an empty token (leading or doubled comma) is yielded as "", a
/// single trailing comma yields nothing.
pub(crate) fn settings_tokens(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut p = s;
    while !p.is_empty() {
        let tl = p.find(',').unwrap_or(p.len());
        out.push(&p[..tl]);
        p = &p[tl..];
        if let Some(r) = p.strip_prefix(',') {
            p = r;
        }
    }
    out
}

/// "name=value,name=value": printable ASCII, no '|', every token has a name
/// and an '='.  Names and values themselves are checked by the console's
/// setting table; unknown ones are kept for forward compatibility.
fn rec_settings_ok(s: &str, max: usize) -> bool {
    if s.len() > max || !s.bytes().all(|c| (0x20..0x7f).contains(&c) && c != b'|') {
        return false;
    }
    settings_tokens(s)
        .iter()
        .all(|t| t.find('=').is_some_and(|eq| eq > 0))
}

fn rec_num_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 11 && s.bytes().all(|c| c.is_ascii_digit())
}

fn rec_op_ok(s: &str) -> bool {
    s == "add" || s == "del"
}

/// hub_record_valid(): syntax check of one stored C/D/B value (all fields,
/// caps, charsets, op).  The single validator behind every ingest path.
pub fn record_valid(key: &str, value: &str) -> bool {
    const BUF: usize = 1100;
    match key {
        "C" => rec_split(value, 4, BUF).is_some_and(|f| {
            rec_chan_ok(f[0], false)
                && rec_modes_ok(f[1])
                && rec_settings_ok(f[2], C_SETTINGS_MAX)
                && rec_op_ok(f[3])
        }),
        "D" => rec_split(value, 2, BUF)
            .is_some_and(|f| rec_modes_ok(f[0]) && rec_settings_ok(f[1], D_SETTINGS_MAX)),
        "B" => {
            // chan|mask|expires|flags|setter|reason|op: the reason is
            // everything between the 5th '|' and the LAST '|' and may contain
            // '|'.
            if value.len() >= BUF {
                return false;
            }
            let Some(last) = value.rfind('|') else {
                return false;
            };
            let mut bars = 0;
            let mut sixth = None;
            for (i, c) in value.bytes().enumerate() {
                if c == b'|' {
                    bars += 1;
                    if bars == 5 {
                        sixth = Some(i);
                        break;
                    }
                }
            }
            let Some(sixth) = sixth else { return false };
            if last <= sixth || !rec_op_ok(&value[last + 1..]) {
                return false;
            }
            let Some(f) = rec_split(&value[..sixth], 5, BUF) else {
                return false;
            };
            if !rec_chan_ok(f[0], true) || !rec_mask_ok(f[1]) || !rec_num_ok(f[2]) {
                return false;
            }
            // flags: "s" or nothing
            if f[3].bytes().enumerate().any(|(i, c)| c != b's' || i >= 4) {
                return false;
            }
            if f[4].len() >= BAN_SETTER_MAX
                || !f[4]
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
            {
                return false;
            }
            let reason = &value[sixth + 1..last];
            reason.len() <= BAN_REASON_MAX && rec_text_ok(reason, BAN_REASON_MAX)
        }
        _ => false,
    }
}

/// LWW for these records: newer stamp wins; on a tie a delete beats an add,
/// and between two of the same kind the byte-wise greater value wins, so
/// every hub picks the same side (docs/modes.md D2; same shape as the opt
/// rule).
fn rec_accepts(
    in_ts: i64,
    in_val: &str,
    in_active: bool,
    cur_ts: i64,
    cur_val: &str,
    cur_active: bool,
) -> bool {
    if in_ts != cur_ts {
        return in_ts > cur_ts;
    }
    if cur_active != in_active {
        return cur_active && !in_active;
    }
    in_val > cur_val
}

/// First field of a stored value equals `chan`, ASCII case-insensitively.
fn entry_chan_eq(e: &ConfigEntry, chan: &str) -> bool {
    first_field(&e.value).eq_ignore_ascii_case(chan)
}

fn entry_active(e: &ConfigEntry) -> bool {
    e.key == "D" || global_value_active(&e.value)
}

/// Live (not deleted) bans stored for `chan` ("*" = the global ones).
fn bans_live_in(state: &HubState, chan: &str) -> usize {
    state
        .global_idx
        .ban_chan
        .get(&chan.to_ascii_lowercase())
        .copied()
        .unwrap_or(0)
}

/// Drop the oldest tombstone of class `key` to make room.  One younger than
/// the purge horizon (7 days when purge is off) is never dropped: it may still
/// be the only thing that stops an old add coming back.  False if none.
fn evict_oldest_tombstone(state: &mut HubState, key: &str) -> bool {
    let keep = if state.purge_days_setting > 0 {
        i64::from(state.purge_days_setting) * 86400
    } else {
        TOMB_MIN_AGE_OFF
    };
    let newest_ok = crate::cstr::now() - keep;
    let mut best: Option<usize> = None;
    for (i, e) in state.global_entries.iter().enumerate() {
        if e.key != key || entry_active(e) || e.timestamp > newest_ok {
            continue;
        }
        if best.is_none_or(|b| e.timestamp < state.global_entries[b].timestamp) {
            best = Some(i);
        }
    }
    match best {
        Some(b) => {
            state.global_entries.swap_remove(b);
            global_reindex(state);
            true
        }
        None => false,
    }
}

/// Live-ban ceiling of a channel ("*" = the global bans).
fn ban_ceiling(chan: &str) -> usize {
    if chan.starts_with('*') {
        MAX_GLOBAL_BANS
    } else {
        MAX_BANS_PER_CHAN
    }
}

/// hub_storage_put_record(): store one C|, D| or B| record (full stored value
/// incl. its op, no stamp) under LWW: newer stamp wins; on a tie a delete
/// beats an add, otherwise the byte-wise greater value wins.  Validates,
/// applies the per-class ceilings (MAX_CHANNELS, MAX_BANS_PER_CHAN,
/// MAX_GLOBAL_BANS, MAX_BANS_TOTAL), keeps the stored spelling of the
/// channel/mask.  False = rejected or not newer.
pub fn put_record(state: &mut HubState, key: &str, value: &str, ts: i64) -> bool {
    if !key_is_modes(key) || ts <= 0 {
        return false;
    }
    if !record_valid(key, value) {
        crate::hlog_warning!("[STORAGE] REJECTED malformed {key}| record\n");
        return false;
    }
    let in_active = key == "D" || global_value_active(value);
    let found = global_find(state, key, value);

    if let Some(i) = found {
        let e = &state.global_entries[i];
        let norm = if key == "D" {
            value.to_string()
        } else {
            // The stored channel / mask spelling stays: the first writer's.
            let (il, vl) = (ident_len(key, &e.value), ident_len(key, value));
            if il + value[vl..].len() >= 1024 {
                return false;
            }
            format!("{}{}", &e.value[..il], &value[vl..])
        };
        if !rec_accepts(ts, &norm, in_active, e.timestamp, &e.value, entry_active(e)) {
            return false;
        }
        if key == "B" && in_active && !entry_active(e) {
            // A deleted ban coming back counts against the ceilings again.
            let chan = first_field(&norm);
            if chan.len() >= MAX_CHAN || bans_live_in(state, chan) >= ban_ceiling(chan) {
                return false;
            }
        }
        let was_active = entry_active(&state.global_entries[i]);
        let e = &mut state.global_entries[i];
        e.value = norm;
        e.timestamp = ts;
        if key == "B" && was_active != in_active {
            gban_adjust(state, i, in_active);
        }
        return true;
    }

    if key == "B" && in_active {
        let chan = first_field(value);
        if chan.len() >= MAX_CHAN {
            return false;
        }
        if bans_live_in(state, chan) >= ban_ceiling(chan) {
            crate::hlog_warning!("[STORAGE] B| for {chan} REJECTED (ban ceiling)\n");
            return false;
        }
    }
    if !global_room(state, key) && !(evict_oldest_tombstone(state, key) && global_room(state, key))
    {
        crate::hlog_warning!("[STORAGE] {key}| record REJECTED (max entries reached)\n");
        return false;
    }
    state.global_entries.push(ConfigEntry {
        key: key.to_string(),
        value: value.to_string(),
        timestamp: ts,
        last_used: 0,
    });
    global_note_new(state, state.global_entries.len() - 1);
    true
}

/// hub_chan_live(): the stored spelling of `chan` when it has a live c|
/// record (ASCII case-insensitive), else None.
pub fn chan_live(state: &HubState, chan: &str) -> Option<String> {
    let i = global_find(state, "c", chan)?;
    let v = &state.global_entries[i].value;
    global_value_active(v).then(|| trunc_string(first_field(v), MAX_CHAN))
}

/// hub_chan_del_stamp(): channel stamp for a delete that must beat the
/// channel's c|, C| and every B| line: past the newest stored stamp of any of
/// them.
pub fn chan_del_stamp(state: &HubState, chan: &str) -> i64 {
    let newest = state
        .global_entries
        .iter()
        .filter(|e| matches!(e.key.as_str(), "c" | "C" | "B") && entry_chan_eq(e, chan))
        .map(|e| e.timestamp)
        .max()
        .unwrap_or(0);
    crate::state::lww_next_ts(newest)
}

/// hub_chan_cascade_del(): write `del` on the channel's C| and B| lines with
/// stamp `ts` (LWW decides each); `announce`: also send them to the peers and
/// owe the bots a push.  The c| line itself is the caller's.  Returns how
/// many records changed.
pub fn chan_cascade_del(state: &mut HubState, chan: &str, ts: i64, announce: bool) -> usize {
    let mut changed = 0;
    let mut out = String::new();
    let mut i = 0;
    while i < state.global_entries.len() {
        let e = &state.global_entries[i];
        i += 1;
        let is_c = e.key == "C";
        if !(is_c || e.key == "B") || !entry_active(e) || !entry_chan_eq(e, chan) {
            continue;
        }
        // Canonical tombstones: every hub writes the same text for the same
        // stamp.
        let tag = e.key.clone();
        let ident = &e.value[..ident_len(&tag, &e.value)];
        let nv = if is_c {
            format!("{ident}|||del")
        } else {
            format!("{ident}|0||||del")
        };
        if nv.len() >= 1024 || !put_record(state, &tag, &nv, ts) {
            continue;
        }
        changed += 1;
        if !announce {
            continue;
        }
        let line = format!("{tag}|{nv}|{ts}\n");
        if out.len() + line.len() >= 8192 {
            // C sends the full buffer here, a truncated last line included;
            // only complete lines are sent (docs/ARCHITECTURE_RUST.md §7).
            mesh::broadcast_sync_to_peers(state, &out, -1);
            out.clear();
        }
        out.push_str(&line);
    }
    // Oper bindings to the channel go too (user_flags plan U6), same stamp:
    // every hub and bot applies the same cascade to the same c| del.  "*" is
    // not a channel and stays.
    let hits: Vec<(String, String)> = state
        .uchan_records
        .iter()
        .filter(|r| r.is_active && r.chan != "*" && r.chan.eq_ignore_ascii_case(chan))
        .map(|r| (r.uuid.clone(), r.chan.clone()))
        .collect();
    for (uuid, c) in hits {
        if !crate::access::uchan_put(state, &uuid, &c, false, ts) {
            continue;
        }
        changed += 1;
        if !announce {
            continue;
        }
        let Some(ri) = crate::access::uchan_find(state, &uuid, &c) else {
            continue;
        };
        let line = crate::access::format_uchan(&state.uchan_records[ri]);
        if out.len() + line.len() >= 8192 {
            mesh::broadcast_sync_to_peers(state, &out, -1);
            out.clear();
        }
        out.push_str(&line);
    }
    if !out.is_empty() {
        mesh::broadcast_sync_to_peers(state, &out, -1);
    }
    if changed > 0 {
        state.config_dirty = true;
        if announce {
            state.bot_config_pending = true;
        }
    }
    changed
}

#[cfg(test)]
mod tests {

    #[test]
    fn hublist_valid_bounds() {
        let fp = "0123456789abcdef";
        assert!(hublist_valid(""));
        assert!(hublist_valid(&format!("127.0.0.1:7000/{fp}")));
        assert!(hublist_valid(&format!("/{fp},[::1]:7000/{fp}")));
        assert!(!hublist_valid(&format!("a b:1/{fp}")));
        assert!(!hublist_valid(&format!("h:1/{}", &fp[..15])));
        assert!(!hublist_valid(&format!("h:1/{}", fp.to_uppercase())));
        assert!(!hublist_valid(&format!("h|x:1/{fp}")));
        assert!(!hublist_valid(&format!(
            "{}/{fp}",
            "a".repeat(HL_ADDR_MAX + 1)
        )));
        assert!(!hublist_valid(
            &vec![format!("h:1/{fp}"); HL_ENTRIES_MAX + 1].join(",")
        ));
        assert!(hublist_valid(
            &vec![format!("h:1/{fp}"); HL_ENTRIES_MAX].join(",")
        ));
        assert!(!hublist_valid(&format!("h:1/{fp},")));
    }

    use super::*;

    fn st() -> HubState {
        HubState::new()
    }

    #[test]
    fn per_bot_whitelist_and_caps() {
        let mut s = st();
        assert!(update_entry(&mut s, "bot-1", "n", "nick", "", "", 100));
        // Not in {t,n,h,pub,seen,d}: the entry is refused.  The bot record
        // itself is still created, as in the C hub — the bound is on entries.
        assert!(!update_entry(&mut s, "bot-2", "zz", "x", "", "", 100));
        let b2 = s.bots.iter().find(|b| b.uuid == "bot-2").unwrap();
        assert!(b2.entries.is_empty());
        // Over the per-key value cap.
        assert!(!update_entry(
            &mut s,
            "bot-1",
            "n",
            &"x".repeat(32),
            "",
            "",
            200
        ));
        assert!(update_entry(
            &mut s,
            "bot-1",
            "h",
            &format!("n!u@{}", "x".repeat(251)),
            "",
            "",
            200
        ));
        assert!(!update_entry(
            &mut s,
            "bot-1",
            "h",
            &format!("n!u@{}", "x".repeat(252)),
            "",
            "",
            300
        ));
        // Retired keys never land anywhere.
        assert!(!update_entry(&mut s, "bot-1", "p", "secret", "", "", 400));
        // A bot-specific key name is not a UUID.
        assert!(!update_entry(&mut s, "seen", "n", "x", "", "", 400));
    }

    #[test]
    fn tombstone_beats_add_on_a_tie() {
        let mut s = st();
        assert!(update_entry(&mut s, "bot-1", "n", "nick", "", "", 100));
        assert!(update_entry(&mut s, "bot-1", "d", "0", "", "", 500));
        assert!(s.bots[0].is_active);
        // Same stamp, greater value: "1" beats "0".
        assert!(update_entry(&mut s, "bot-1", "d", "1", "", "", 500));
        assert!(!s.bots[0].is_active);
        // And the reverse is refused.
        assert!(!update_entry(&mut s, "bot-1", "d", "0", "", "", 500));
        assert!(!s.bots[0].is_active);
    }

    #[test]
    fn global_channel_list_matches_on_first_field() {
        let mut s = st();
        assert!(update_global_entry(&mut s, "c", "#a", "key|0", "add", 100));
        assert!(update_global_entry(&mut s, "c", "#b", "|0", "add", 100));
        assert_eq!(s.global_entries.len(), 2);
        // Same channel, newer stamp: updates in place.
        assert!(update_global_entry(&mut s, "c", "#a", "new|0", "add", 200));
        assert_eq!(s.global_entries.len(), 2);
        assert_eq!(s.global_entries[0].value, "#a|new|0|add");
        assert_eq!(global_ts(&s, "c", "#a"), 200);
        // Older stamp: refused.
        assert!(!update_global_entry(&mut s, "c", "#a", "old|0", "add", 150));
        // A delete on an exact tie wins.
        assert!(update_global_entry(&mut s, "c", "#a", "", "del", 200));
        assert!(!global_value_active(&s.global_entries[0].value));
    }

    #[test]
    fn op_is_sanitized() {
        assert_eq!(safe_op("|add|"), "add");
        assert_eq!(safe_op(""), "add");
        assert_eq!(safe_op("||"), "add");
        assert_eq!(safe_op("del"), "del");
    }

    /// The payload every bot consumes.  v2 gets the passwordless shapes and
    /// the T| trusted-set marker; anything else gets the fail-closed legacy
    /// shapes with an EMPTY password slot.
    #[test]
    fn bot_payload_shapes_per_protocol() {
        let mut s = st();
        let (_, pubk) = crypto::generate_combined_keypair().unwrap();
        let k = crypto::b64_encode(&pubk);

        update_global_entry(&mut s, "c", "#chan", "key|0", "add", 100);
        s.user_records.push(crate::state::UserRecord {
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            name: "rob".into(),
            pubkey_b64: k.clone(),
            has_pubkey: true,
            typ: 'a',
            is_active: true,
            last_seen: 10,
            timestamp: 20,
        });
        s.mask_records.push(crate::state::MaskRecord {
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            mask: "rob!*@*".into(),
            is_active: true,
            last_used: 0,
            timestamp: 20,
        });
        s.opt_flags = "h".into();
        s.opt_flags_ts = 500;
        // The bot being served, plus one other bot it should learn to trust.
        update_entry(&mut s, "me", "n", "mybot", "", "", 100);
        update_entry(&mut s, "me", "h", "mybot!u@h", "", "", 100);
        update_entry(&mut s, "other", "h", "otherbot!u@h", "", "", 100);
        update_entry(&mut s, "other", "pub", &k, "", "", 300);

        // Before flags: the admin is a full admin (access::migrate).
        crate::access::migrate(&mut s);
        let v2 = generate_bot_payload(&s, "me", BOT_PROTO_USER_FLAGS);
        assert!(v2.contains("c|#chan|key|0|add|100\n"));
        assert!(v2.contains(&format!(
            "a|11111111-2222-3333-4444-555555555555|rob|{k}|add|10|20|\n"
        )));
        assert!(v2.contains("m|11111111-2222-3333-4444-555555555555|rob!*@*|add|0|20\n"));
        assert!(v2.contains("O|h|500\n"));
        // The trusted-bot line carries the key, stamped with the later of the
        // hostmask and pubkey timestamps so a rekey alone reads as newer.
        assert!(v2.contains(&format!("b|otherbot!u@h|other|{k}|300\n")));
        assert!(v2.ends_with("T|1\n"));
        // Hub-only metadata never reaches a bot.
        assert!(!v2.contains("\nh|"));
        assert!(!v2.contains("\nn|"));

        let legacy = generate_bot_payload(&s, "me", 0);
        // Field 3 EMPTY so an old bot refuses every admin command; the key
        // still rides in field 7.
        assert!(legacy.contains(&format!(
            "a|11111111-2222-3333-4444-555555555555|rob||add|10|20|{k}\n"
        )));
        // No key on the b| line, and no T| marker for a bot that predates it.
        assert!(legacy.contains("b|otherbot!u@h|other|100\n"));
        assert!(!legacy.contains("T|"));
    }

    /// A bot that is not registered gets the globals but no b| line for
    /// itself, and is never listed as its own trusted peer.
    #[test]
    fn bot_payload_never_trusts_the_bot_itself() {
        let mut s = st();
        update_entry(&mut s, "me", "h", "mybot!u@h", "", "", 100);
        let p = generate_bot_payload(&s, "me", BOT_PROTO_USER_FLAGS);
        assert!(!p.contains("b|mybot!u@h|me"));
        assert!(p.ends_with("T|0\n"));
    }

    #[test]
    fn oper_password_slot_is_dropped_globally() {
        let mut s = st();
        assert!(update_global_entry(
            &mut s, "o", "n!*@*", "hunter2", "add", 100
        ));
        assert_eq!(s.global_entries[0].value, "n!*@*||add");
    }

    #[test]
    fn modes_records_lww_and_spelling() {
        let mut s = st();
        assert!(update_global_entry(&mut s, "c", "#Chan", "k|0", "add", 100));
        // A case variant addresses the same record and keeps the first spelling.
        assert!(update_global_entry(
            &mut s, "c", "#CHAN", "k2|0", "add", 200
        ));
        assert_eq!(s.global_entries.len(), 1);
        assert_eq!(s.global_entries[0].value, "#Chan|k2|0|add");

        assert!(put_record(&mut s, "C", "#Chan|+nt|bitch=1|add", 300));
        assert!(put_record(&mut s, "C", "#CHAN|+nt|bitch=0|add", 400));
        let c: Vec<_> = s.global_entries.iter().filter(|e| e.key == "C").collect();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].value, "#Chan|+nt|bitch=0|add");
        // Same stamp: a delete beats an add, then the greater value wins.
        assert!(put_record(&mut s, "C", "#chan|||del", 400));
        assert!(!put_record(&mut s, "C", "#chan|+nt|bitch=9|add", 400));
        // Malformed records never land.
        assert!(!put_record(&mut s, "C", "#chan|+nt|nonsense|add", 500));
        assert!(!put_record(&mut s, "B", "*|m!*@*|0|x|me|why|add", 500));
        assert!(!put_record(&mut s, "C", "#chan|+nt||add", 0));
    }

    #[test]
    fn ban_records_and_channel_cascade() {
        let mut s = st();
        update_global_entry(&mut s, "c", "#a", "|0", "add", 100);
        assert!(put_record(&mut s, "B", "#a|*!*@bad|0||adm|why|so|add", 150));
        assert!(put_record(&mut s, "B", "*|*!*@worse|0|s|adm||add", 150));
        assert!(put_record(&mut s, "C", "#a|+i||add", 150));
        assert_eq!(chan_live(&s, "#A").as_deref(), Some("#a"));
        let t = chan_del_stamp(&s, "#a");
        assert!(t > 150);
        assert_eq!(chan_cascade_del(&mut s, "#A", t, false), 2);
        assert!(
            s.global_entries
                .iter()
                .any(|e| e.value == "#a|*!*@bad|0||||del")
        );
        assert!(s.global_entries.iter().any(|e| e.value == "#a|||del"));
        // The global ban is not the channel's.
        assert!(
            s.global_entries
                .iter()
                .any(|e| e.value == "*|*!*@worse|0|s|adm||add")
        );
    }

    #[test]
    fn ban_ceiling_per_channel() {
        let mut s = st();
        for n in 0..MAX_BANS_PER_CHAN {
            assert!(put_record(
                &mut s,
                "B",
                &format!("#a|m{n}!*@*|0||x||add"),
                10
            ));
        }
        assert!(!put_record(&mut s, "B", "#a|extra!*@*|0||x||add", 10));
        // A deleted one frees its slot, and cannot come back over the limit.
        assert!(put_record(&mut s, "B", "#a|m0!*@*|0||||del", 20));
        assert!(put_record(&mut s, "B", "#a|extra!*@*|0||x||add", 21));
        assert!(!put_record(&mut s, "B", "#a|m0!*@*|0||x||add", 30));
    }

    #[test]
    fn bot_h_must_be_a_literal_hostmask() {
        let mut s = st();
        for (i, ok) in ["n!u@h", "", "N!~u@1.2.3.4", "n!u!x@h.example"]
            .iter()
            .enumerate()
        {
            let ts = 100 + i as i64;
            assert!(update_entry(&mut s, "bot-1", "h", ok, "", "", ts), "{ok}");
        }
        for bad in [
            "*!*@*", "n!u@*.x", "n?!u@h", "n!u@h|x", "nick", "n!u", "!u@h", "n!@h", "n!u@",
            "n!u@h@x", "n!u@h!x", "n !u@h",
        ] {
            assert!(
                !update_entry(&mut s, "bot-1", "h", bad, "", "", 200),
                "{bad}"
            );
        }
    }

    #[test]
    fn evict_keeps_young_tombstones() {
        let mut s = st();
        let now = crate::cstr::now();
        assert!(put_record(&mut s, "B", "#a|m0!*@*|0||||del", now - 3600));
        assert!(!evict_oldest_tombstone(&mut s, "B")); // an hour old, purge off
        s.purge_days_setting = 1;
        assert!(!evict_oldest_tombstone(&mut s, "B"));
        assert!(put_record(
            &mut s,
            "B",
            "#a|m1!*@*|0||||del",
            now - 40 * 86400
        ));
        assert!(put_record(
            &mut s,
            "B",
            "#a|m2!*@*|0||||del",
            now - 30 * 86400
        ));
        s.purge_days_setting = 0;
        assert!(evict_oldest_tombstone(&mut s, "B"));
        assert!(global_find(&s, "B", "#a|m1!*@*").is_none());
        assert!(global_find(&s, "B", "#a|m2!*@*").is_some());
        assert_eq!(s.global_idx.n_b, 2);
        // The index survived the swap_remove.
        assert!(global_find(&s, "B", "#A|M0!*@*").is_some());
    }

    #[test]
    fn counters_follow_live_bans() {
        let mut s = st();
        assert!(put_record(&mut s, "B", "#A|x!*@*|0||||add", 10));
        assert!(put_record(&mut s, "B", "#a|y!*@*|0||||add", 10));
        assert_eq!(bans_live_in(&s, "#a"), 2);
        assert!(put_record(&mut s, "B", "#a|X!*@*|0||||del", 20));
        assert_eq!(bans_live_in(&s, "#A"), 1);
        assert!(put_record(&mut s, "B", "#a|x!*@*|0||||add", 30));
        assert_eq!(bans_live_in(&s, "#a"), 2);
        global_reindex(&mut s);
        assert_eq!((bans_live_in(&s, "#a"), s.global_idx.n_b), (2, 2));
    }

    /// Bench note (4): a 6500-ban sync.  The C hub does it in 7.6 ms; this
    /// prints the Rust time (`cargo test --release -- --nocapture bench_`).
    #[test]
    fn bench_6500_ban_sync() {
        let mut s = st();
        let t0 = std::time::Instant::now();
        let mut n = 0;
        'o: for c in 0..=MAX_CHANNELS {
            // The last "channel" is the global one: MAX_GLOBAL_BANS bans.
            let (ch, per) = if c == MAX_CHANNELS {
                ("*".to_string(), MAX_GLOBAL_BANS)
            } else {
                (format!("#c{c}"), MAX_BANS_PER_CHAN)
            };
            for m in 0..per {
                if n >= 6500 {
                    break 'o;
                }
                let v = format!("{ch}|m{m}!*@*|0||||add");
                assert!(put_record(&mut s, "B", &v, 100 + n as i64), "ban {n}");
                n += 1;
            }
        }
        let el = t0.elapsed();
        eprintln!("bench: {n} bans in {el:?} (C: 7.6 ms)");
        assert_eq!(n, 6500);
        assert_eq!(s.global_idx.n_b, 6500);
        // The O(1) index: a quadratic scan would take seconds even in debug.
        assert!(el.as_millis() < 1000, "{el:?}");
    }
}
