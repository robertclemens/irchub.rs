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
use crate::{config, crypto};

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

/// Index of the stored global entry that `value` under `key` addresses: a|/p|
/// are singletons, every other key matches on its first field.  None if there
/// is none.
fn global_entry_find(state: &HubState, key: &str, value: &str) -> Option<usize> {
    let is_singleton = key == "a" || key == "p";
    state.global_entries.iter().position(|e| {
        e.key == key && (is_singleton || trunc_string(first_field(&e.value), 256) == value)
    })
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
            // config, an old peer or an old hub_admin must not be kept,
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
    let op = safe_op(op);
    let combined = combined_value(key, value, extra, &op, true);

    if let Some(i) = global_entry_find(state, key, value) {
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
            state.global_entries[i].value = combined;
            state.global_entries[i].timestamp = ts;
            return true;
        }
        crate::hlog_debug!(
            "[STORAGE] Global {key}={value}: incoming_ts={ts} <= stored_ts={stored_ts} -> REJECTED\n"
        );
        return false;
    }

    if state.global_entries.len() < MAX_BOT_ENTRIES {
        crate::hlog_debug!("[STORAGE] Global {key}={value}: NEW entry ts={ts}\n");
        state.global_entries.push(ConfigEntry {
            key: trunc_string(key, 32),
            value: combined,
            timestamp: ts,
        });
        return true;
    }
    crate::hlog_warning!("[STORAGE] Global {key}={value}: REJECTED (max entries reached)\n");
    false
}

/// hub_storage_update_entry(): the single choke point for per-bot state.
pub fn update_entry(
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
    if !matches!(key, "t" | "n" | "h" | "pub" | "seen" | "d") {
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
            _ => 31, // seen/d/t: short numerics
        };
        let vlen = value.len();
        if vlen > cap {
            crate::hlog_warning!(
                "[STORAGE] REJECTED per-bot '{key}' for {uuid}: value too long ({vlen} > {cap})\n"
            );
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

/// The nick a bot record carries ('n'), or `unknown`.
fn bot_nick(b: &BotConfig, unknown: &str) -> String {
    b.entry("n")
        .map_or_else(|| unknown.to_string(), |e| trunc_string(&e.value, 32))
}

fn local_time(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        None => "invalid".to_string(),
    }
}

/// hub_storage_get_full_list().
pub fn get_full_list(state: &HubState) -> String {
    let active = state.bots.iter().filter(|b| b.is_active).count();
    let mut out = format!("--- Registered Bots ({active}) ---\n");
    for b in state.bots.iter().filter(|b| b.is_active) {
        let time_buf = if b.last_sync_time == 0 {
            "Never".to_string()
        } else {
            local_time(b.last_sync_time)
        };
        out.push_str(&format!(
            "[{}] {} | Last Sync: {}\n",
            b.uuid,
            bot_nick(b, "Unknown"),
            time_buf
        ));
    }
    out
}

/// hub_storage_get_summary_list().
pub fn get_summary_list(state: &HubState) -> String {
    let mut out = String::from("--- Bot List ---\n");
    for b in state.bots.iter().filter(|b| b.is_active) {
        let nick = bot_nick(b, "");
        if nick.is_empty() {
            out.push_str(&format!("{}\n", b.uuid));
        } else {
            out.push_str(&format!("{:<16}  [{}]\n", nick, b.uuid));
        }
    }
    out
}

/// hub_generate_bot_payload(): global + bot-specific config for one bot.
/// Global items carry no "b|uuid|" prefix, preserving protocol
/// compatibility.
///
/// `proto_v2` means the receiving connection advertised v|2 (new a|/o|/b|
/// shapes); false sends the fail-closed legacy shapes.
pub fn generate_bot_payload(state: &HubState, uuid: &str, proto_v2: bool) -> String {
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
        out.push_str(&config::format_user_record(u, !proto_v2));
    }

    // 1b. Usermask records (m| lines).
    for m in &state.mask_records {
        out.push_str(&format!(
            "m|{}|{}|{}|{}|{}\n",
            m.uuid,
            m.mask,
            if m.is_active { "add" } else { "del" },
            m.last_used,
            m.timestamp
        ));
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

#[cfg(test)]
mod tests {
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
            &"x".repeat(255),
            "",
            "",
            200
        ));
        assert!(!update_entry(
            &mut s,
            "bot-1",
            "h",
            &"x".repeat(256),
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

        let v2 = generate_bot_payload(&s, "me", true);
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

        let legacy = generate_bot_payload(&s, "me", false);
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
        let p = generate_bot_payload(&s, "me", true);
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
}
