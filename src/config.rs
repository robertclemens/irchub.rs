//! The encrypted config file (hub_config.c): the a|/o| user-record codec,
//! the writer, and the loader with its one-shot migrations.
//!
//! File layout, unchanged from the C hub and shared with `hub_encrypt` /
//! `hub_decrypt`:
//!
//! ```text
//! salt[SALT_SIZE] | iv[GCM_IV_LEN] | tag[GCM_TAG_LEN] | AES-256-GCM(plaintext)
//! key = PBKDF2-HMAC-SHA256(config password, salt, PBKDF2_ITERATIONS)
//! ```

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use zeroize::Zeroizing;

use crate::consts::*;
use crate::cstr::{atoll, now, split_fields, trunc_string};
use crate::state::{HubState, IpAclAdd, MaskRecord, UserRecord, lww_next_ts, parse_uint};
use crate::{crypto, ratelimit, storage};

// ---------------------------------------------------------------------------
// a|/o| user record codec (docs/passwordless.md §3.1)
// ---------------------------------------------------------------------------
//
//   new     uuid|name|pubkey|add/del|last_seen|ts|<reserved, empty>
//   legacy  uuid|name|password|add/del|last_seen|ts[|pubkey]
//
// Field 3 decides.  A valid key there means the new format; anything else is
// a legacy password, which is never copied anywhere, and the key (if any) is
// field 7.  Covers every older shape, including an old hub that stored a
// pubkey in the password slot.

/// A field that is exactly a valid 88-char combined public key.
fn field_pubkey(f: &str) -> Option<String> {
    if f.len() != COMBINED_KEY_B64 {
        return None;
    }
    crypto::pubkey_b64_decode(f).map(|_| f.to_string())
}

/// hub_parse_opt_value(): the value of an opt line, `<letters>|<ts>` —
/// including the `|<ts>` form a clear produces, which a plain `%[^|]|%lld`
/// scan rejects.  `flags` gets only [a-zA-Z0-9]; None if the timestamp is
/// missing or not positive.
pub fn parse_opt_value(v: &str) -> Option<(String, i64)> {
    let bar = v.find('|')?;
    let flags: String = v[..bar]
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(MAX_OPT_FLAGS)
        .collect();
    let rest = &v[bar + 1..];
    let (ts, used) = crate::cstr::strtoll(rest);
    if used == 0 || ts <= 0 {
        return None;
    }
    // strtoll's endptr must land on end-of-string, '|' or '\r'.
    match rest.as_bytes().get(used) {
        None | Some(b'|') | Some(b'\r') => Some((flags, ts)),
        _ => None,
    }
}

/// hub_parse_user_record().  The bool reports whether a legacy (password)
/// shape was seen.
pub fn parse_user_record(data: &str, typ: char) -> Option<(UserRecord, bool)> {
    let f = split_fields(data, 8);
    if f.len() < 6 || !crate::cstr::is_uuid(f[0]) {
        return None;
    }
    if f[1].is_empty() || f[1].len() >= 64 {
        return None;
    }
    let mut out = UserRecord {
        uuid: f[0].to_string(),
        name: f[1].to_string(),
        typ,
        is_active: f[3] == "add",
        last_seen: atoll(f[4]),
        timestamp: atoll(f[5]),
        ..Default::default()
    };
    let mut legacy = false;
    match field_pubkey(f[2]) {
        Some(k) => {
            out.pubkey_b64 = k;
            out.has_pubkey = true;
        }
        None => {
            legacy = true;
            if f.len() >= 7
                && let Some(k) = field_pubkey(f[6])
            {
                out.pubkey_b64 = k;
                out.has_pubkey = true;
            }
        }
    }
    Some((out, legacy))
}

/// hub_format_user_record(): a full line including its "\n".  `legacy_v1`
/// emits the fail-closed shape for bots that have not advertised v|2:
/// `a|uuid|name||act|seen|ts|pubkey`.
pub fn format_user_record(u: &UserRecord, legacy_v1: bool) -> String {
    let pk = if u.has_pubkey {
        u.pubkey_b64.as_str()
    } else {
        ""
    };
    let act = if u.is_active { "add" } else { "del" };
    if legacy_v1 {
        // Old bots read field 3 as a ~A1 password: leave it EMPTY so they
        // refuse every admin command (fail closed); they still get the key in
        // field 7.
        format!(
            "{}|{}|{}||{}|{}|{}|{}\n",
            u.typ, u.uuid, u.name, act, u.last_seen, u.timestamp, pk
        )
    } else {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|\n",
            u.typ, u.uuid, u.name, pk, act, u.last_seen, u.timestamp
        )
    }
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// hub_config_write().  A config that does not fit its bound is NOT written
/// (the old file is kept) — never a truncated one.
/// Set by `-selftest`: nothing may write the config the running build owns,
/// whatever migration or dedup load() would otherwise do.
pub static READ_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn write(state: &mut HubState) {
    if READ_ONLY.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let estimated_size = HUB_CONFIG_FIXED_MAX + state.bots.len() * HUB_CONFIG_PER_BOT_MAX;
    let mut buf = Zeroizing::new(String::with_capacity(8192));

    buf.push_str(&format!("port|{}\n", state.port));
    buf.push_str(&format!(
        "bind_ip|{}\n",
        if state.bind_ip.is_empty() {
            "127.0.0.1"
        } else {
            &state.bind_ip
        }
    ));
    buf.push_str(&format!("uuid|{}\n", state.hub_uuid));
    buf.push_str(&format!("hub_name|{}\n", state.hub_friendly_name));
    // No 'admin|' line is written: admins authenticate with the public keys
    // in their a| records.  Existing files that carry one are ignored at load.
    //
    // Persist the Lamport seq so it survives a restart and stays monotonic.
    buf.push_str(&format!("lamport_seq|{}\n", state.next_lamport_seq));

    // Log settings set over CMD_ADMIN_SET_LOG_LEVEL / _SIZE: written only
    // when they differ from the defaults, so an untouched hub's file is
    // unchanged.
    if state.log_level != HUB_DEFAULT_LOG_LEVEL {
        buf.push_str(&format!("log_level|{}\n", state.log_level));
    }
    if state.log_max_size > 0 && state.log_max_size != HUB_LOG_FILE_SIZE {
        buf.push_str(&format!("log_size|{}\n", state.log_max_size));
    }

    if state.purge_days_setting > 0 {
        buf.push_str(&format!("purge_days|{}\n", state.purge_days_setting));
    }

    // D3: persist the loopback-trust flag.  Always written so the security
    // posture is explicit in the config file rather than implied by absence.
    buf.push_str(&format!(
        "trust_loopback|{}\n",
        i32::from(state.trust_loopback)
    ));

    // Network opt flags: opt|<letters>|<timestamp>.  Written whenever the
    // value has a timestamp, including a clear (opt||<ts>): without it a
    // restarted hub has ts 0 and adopts the stale flags back from a peer.
    if state.opt_flags_ts > 0 {
        buf.push_str(&format!("opt|{}|{}\n", state.opt_flags, state.opt_flags_ts));
    }

    // The roll-up plan (upgrade plan, Task 13): hub-local, never replicated.
    // rollup|target|variant|kind|min_from|hub_target|plan_set|base|hub_base —
    // every field was checked free of '|' and line breaks before it was
    // accepted (upgrade::plan_field_ok), and is checked again here, so the
    // line can never split or inject another.
    {
        let r = &state.rollup;
        let fields = [
            &r.target,
            &r.variant,
            &r.kind,
            &r.min_from,
            &r.hub_target,
            &r.base,
            &r.hub_base,
        ];
        if r.have_plan && fields.iter().all(|f| crate::upgrade::plan_field_ok(f)) {
            buf.push_str(&format!(
                "rollup|{}|{}|{}|{}|{}|{}|{}|{}\n",
                r.target,
                r.variant,
                r.kind,
                r.min_from,
                r.hub_target,
                r.plan_set,
                r.base,
                r.hub_base
            ));
        }
    }

    for p in &state.peers {
        // Serialize the per-peer Curve25519 pubkey (88 chars base64 of the
        // 64-byte combined Ed25519+X25519 key) as the 5th field.  An empty
        // string means "no pubkey known, peer will be refused at connection
        // time".
        let mut peer_pub_b64 = String::new();
        if p.has_pubkey {
            let mut combined = [0u8; COMBINED_KEY_LEN];
            combined[..ED25519_KEY_LEN].copy_from_slice(&p.ed_pub);
            combined[ED25519_KEY_LEN..].copy_from_slice(&p.x25519_pub);
            peer_pub_b64 = crypto::b64_encode(&combined);
        }
        buf.push_str(&format!(
            "peer|{}|{}|{}|{}|{}\n",
            p.ip, p.port, p.uuid, p.friendly_name, peer_pub_b64
        ));
    }

    if state.hub_keys_loaded {
        let priv64 = state.hub_priv_combined();
        let pub64 = state.hub_pub_combined();
        let priv_b64 = Zeroizing::new(crypto::b64_encode(priv64.as_ref()));
        buf.push_str(&format!("key|{}\n", priv_b64.as_str()));
        buf.push_str(&format!("pub|{}\n", crypto::b64_encode(&pub64)));
    }

    // Global entries (skip h/n metadata, a/m/o which use typed arrays, and
    // the retired bot password p).
    for e in &state.global_entries {
        if matches!(e.key.as_str(), "h" | "n" | "a" | "m" | "o" | "p") {
            continue;
        }
        buf.push_str(&format!("{}|{}|{}\n", e.key, e.value, e.timestamp));
    }

    // Local IP access lists: w|<pattern>|<added> (allow), x|... (deny).
    for e in &state.ip_allow {
        buf.push_str(&format!("w|{}|{}\n", e.pattern(), e.added));
    }
    for e in &state.ip_deny {
        buf.push_str(&format!("x|{}|{}\n", e.pattern(), e.added));
    }

    // Named admin/oper records (a| and o| lines) — skip duplicates by
    // type+name.
    let mut seen: Vec<(char, String)> = Vec::new();
    for u in &state.user_records {
        if seen
            .iter()
            .any(|(t, n)| *t == u.typ && n.eq_ignore_ascii_case(&u.name))
        {
            continue;
        }
        seen.push((u.typ, u.name.clone()));
        let line = format_user_record(u, false);
        if line.len() >= USER_LINE_MAX {
            crate::hlog_error!(
                "[CONFIG] user record for '{}' exceeds its line bound; NOT written (previous file kept)\n",
                u.name
            );
            return;
        }
        buf.push_str(&line);
    }

    // Usermask records (m| lines) — skip masks with no surviving owner.
    for m in &state.mask_records {
        if !state.user_records.iter().any(|u| u.uuid == m.uuid) {
            continue;
        }
        buf.push_str(&format!(
            "m|{}|{}|{}|{}|{}\n",
            m.uuid,
            m.mask,
            if m.is_active { "add" } else { "del" },
            m.last_used,
            m.timestamp
        ));
    }

    for b in &state.bots {
        if b.uuid.is_empty() {
            continue;
        }
        buf.push_str(&format!("b|{}|t|{}\n", b.uuid, b.last_sync_time));
        for e in &b.entries {
            // "seen" and "t" carry no value field.
            if e.key == "seen" || e.key == "t" {
                buf.push_str(&format!("b|{}|{}|{}\n", b.uuid, e.key, e.timestamp));
            } else {
                buf.push_str(&format!(
                    "b|{}|{}|{}|{}\n",
                    b.uuid, e.key, e.value, e.timestamp
                ));
            }
        }
    }

    if buf.len() >= estimated_size {
        crate::hlog_error!(
            "[CONFIG] config exceeds its {estimated_size}-byte bound; NOT written (previous file kept)\n"
        );
        return;
    }

    // CRITICAL: GCM nonce reuse is catastrophic.  Bail out instead of writing
    // with a predictable IV/salt if the RNG is unavailable.
    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; GCM_IV_LEN];
    if !crypto::random_bytes(&mut salt) || !crypto::random_bytes(&mut iv) {
        crate::hlog_error!("[HUB] RAND_bytes failed; aborting config write\n");
        return;
    }

    let pass = state.get_config_pass();
    let key = crypto::derive_config_key(pass.as_bytes(), &salt);
    drop(pass);

    let Some((ct, tag)) = crypto::gcm_encrypt_detached(key.as_ref(), &iv, &[], buf.as_bytes())
    else {
        crate::hlog_error!("[HUB] EVP encryption failed; aborting config write\n");
        return;
    };

    // Write to a temp file then rename (atomic).
    let tmp = format!("{HUB_CONFIG_FILE}.tmp");
    let out = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp);
    let Ok(mut f) = out else { return };
    let ok = f.write_all(&salt).is_ok()
        && f.write_all(&iv).is_ok()
        && f.write_all(&tag).is_ok()
        && f.write_all(&ct).is_ok()
        && f.flush().is_ok()
        && f.sync_all().is_ok();
    drop(f);
    if ok {
        let _ = fs::rename(&tmp, HUB_CONFIG_FILE);
    } else {
        let _ = fs::remove_file(&tmp);
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Body of a w|/x| line, "<pattern>|<ts>", into the local IP list ('w' allow,
/// 'x' deny).  A pattern that does not parse is dropped and logged rather
/// than guessed at (the old matcher read "10.0.0.0/" as /0, i.e. every
/// address).  False when the line should not stay in the file as written:
/// dropped, a duplicate, or not in canonical form.
fn load_ip_acl_line(state: &mut HubState, list: char, v: &str) -> bool {
    let name = if list == 'w' { "allowlist" } else { "denylist" };
    let Some(s_ts) = v.rfind('|') else {
        crate::hlog_warning!("[CONFIG] Dropping {name} line without a timestamp\n");
        return false;
    };
    let ts = atoll(&v[s_ts + 1..]);
    let head = &v[..s_ts];
    // Never written; tolerate "<pattern>|add".
    let (pattern, had_op) = match head.find('|') {
        Some(i) => {
            let op = &head[i + 1..];
            if op != "add" {
                crate::hlog_warning!(
                    "[CONFIG] Dropping {name} entry '{}' (op '{}')\n",
                    trunc_string(&head[..i], 41),
                    trunc_string(op, 9)
                );
                return false;
            }
            (&head[..i], true)
        }
        None => (head, false),
    };
    let Some(mut e) = ratelimit::ip_acl_parse(pattern) else {
        crate::hlog_warning!(
            "[CONFIG] Dropping invalid {name} entry '{}' (not an IPv4 address or CIDR)\n",
            trunc_string(pattern, 41)
        );
        return false;
    };
    e.added = ts;
    let r = ratelimit::ip_acl_add(state, list, &e);
    if r == IpAclAdd::Full {
        crate::hlog_warning!(
            "[CONFIG] {name} full ({MAX_IP_ACL_ENTRIES}); dropping {}\n",
            e.pattern()
        );
    }
    r == IpAclAdd::Added && !had_op && pattern == e.pattern()
}

/// One `b|` config line body: `<uuid>|<key>|<value...>|<ts>`, or the
/// three-field `<uuid>|t|<ts>` / `<uuid>|seen|<ts>` metadata shape.
fn load_bot_line(state: &mut HubState, v: &str) {
    let Some(s2) = v.find('|') else { return };
    let uuid = v[..s2].to_string();
    let rest = &v[s2 + 1..];
    let Some(s3) = rest.find('|') else { return };
    let bk = rest[..s3].to_string();
    let bv = &rest[s3 + 1..];

    if bk == "t" || bk == "seen" {
        // Metadata fields without a value: b|uuid|t|ts or b|uuid|seen|ts.
        storage::update_entry(state, &uuid, &bk, "", "", "", atoll(bv));
        return;
    }

    // Config entry: b|uuid|key|value|timestamp.
    let Some(s4) = bv.rfind('|') else { return };
    let ts = atoll(&bv[s4 + 1..]);
    let body = &bv[..s4];
    match body.find('|') {
        Some(p1) => {
            let value = &body[..p1];
            let rest2 = &body[p1 + 1..];
            match rest2.find('|') {
                // Three parts: value|extra|op (channel or oper).
                Some(p2) => {
                    let extra = &rest2[..p2];
                    let op = &rest2[p2 + 1..];
                    storage::update_entry(state, &uuid, &bk, value, extra, op, ts);
                }
                // Two parts: value|op (mask).
                None => {
                    storage::update_entry(state, &uuid, &bk, value, "", rest2, ts);
                }
            }
        }
        // One part: a simple value.
        None => {
            storage::update_entry(state, &uuid, &bk, body, "", "", ts);
        }
    }
}

/// One `peer|` config line body.  Formats accepted:
///   `ip|port`                              (oldest)
///   `ip|port|uuid|friendly_name`           (v1)
///   `ip|port|uuid|friendly_name|pubkey_b64` (v2; pubkey may be empty)
fn load_peer_line(state: &mut HubState, v: &str) {
    if state.peers.len() >= MAX_PEERS {
        return;
    }
    let sep = v.find('|').or_else(|| v.find(':'));
    let Some(sep) = sep else { return };
    let ip = &v[..sep];
    let after = &v[sep + 1..];

    let mut p = crate::state::PeerConfig {
        ip: trunc_string(ip, 64),
        fd: -1,
        ..Default::default()
    };

    match after.find('|') {
        None => {
            // Old format: peer|ip|port.
            p.port = crate::cstr::atoi(after);
        }
        Some(i) => {
            p.port = crate::cstr::atoi(&after[..i]);
            let rest = &after[i + 1..];
            let (uuid, rest) = match rest.find('|') {
                Some(j) => (&rest[..j], Some(&rest[j + 1..])),
                None => (rest, None),
            };
            p.uuid = trunc_string(uuid, 64);
            if let Some(rest) = rest {
                let (name, pubkey) = match rest.find('|') {
                    Some(j) => (&rest[..j], Some(&rest[j + 1..])),
                    None => (rest, None),
                };
                if !name.is_empty() {
                    p.friendly_name = trunc_string(name, 64);
                }
                if let Some(pk) = pubkey
                    && !pk.is_empty()
                {
                    match crypto::b64_decode(pk) {
                        Some(dec) if dec.len() == COMBINED_KEY_LEN => {
                            p.ed_pub.copy_from_slice(&dec[..ED25519_KEY_LEN]);
                            p.x25519_pub.copy_from_slice(&dec[ED25519_KEY_LEN..]);
                            p.has_pubkey = true;
                        }
                        other => {
                            crate::hlog_warning!(
                                "[PEER] peer {} pubkey wrong length ({}, need {COMBINED_KEY_LEN}) — ignoring; v2 auth disabled for this peer\n",
                                p.uuid,
                                other.map_or(0, |d| d.len())
                            );
                        }
                    }
                }
            }
        }
    }
    state.peers.push(p);
}

/// One `g|` config line body (the older layout): either the IP lists
/// (`g|w|<pattern>|<ts>`) or a global entry (`g|key|value...|ts`).
fn load_global_line(state: &mut HubState, v: &str) {
    let Some(s2) = v.find('|') else { return };
    let gk = v[..s2].to_string();
    let gv = &v[s2 + 1..];
    let Some(s_ts) = gv.rfind('|') else { return };
    let ts = atoll(&gv[s_ts + 1..]);
    let body = &gv[..s_ts];

    // Parse complex values based on the key:
    //   c -> value|extra|op        m -> value|op
    //   o -> value|extra|op        a, p -> value
    if gk == "c" || gk == "o" {
        // chan|key[|modes]|op — first pipe for chan, last pipe for op,
        // middle portion = extra (key or key|modes).
        let Some(p1) = body.find('|') else { return };
        let head = &body[..p1];
        let rest = &body[p1 + 1..];
        let Some(last) = rest.rfind('|') else { return };
        storage::update_global_entry(state, &gk, head, &rest[..last], &rest[last + 1..], ts);
    } else if gk == "m" {
        let Some(p1) = body.find('|') else { return };
        // Strip any trailing pipes from op (malformed config entries).
        let op = body[p1 + 1..].trim_end_matches('|');
        storage::update_global_entry(state, &gk, &body[..p1], "", op, ts);
    } else {
        storage::update_global_entry(state, &gk, body, "", "", ts);
    }
}

/// One `m|` config line body: the new `uuid|mask|add/del|last_used|ts` shape.
/// The old `mask|add/del|ts` shape has no UUID and is dropped.
fn load_mask_line(state: &mut HubState, v: &str) {
    let f = split_fields(v, 5);
    if f.len() < 5 || !crate::cstr::has_uuid_dashes(f[0]) {
        return;
    }
    if state.mask_records.len() >= MAX_HUB_USER_MASKS {
        return;
    }
    state.mask_records.push(MaskRecord {
        uuid: trunc_string(f[0], 37),
        mask: trunc_string(f[1], MAX_MASK_LEN),
        is_active: f[2].starts_with("add"),
        last_used: atoll(f[3]),
        timestamp: atoll(f[4]),
    });
}

/// One `c|` config line body: `chan|key[|modes]|op|timestamp`.
fn load_channel_line(state: &mut HubState, v: &str) {
    let Some(s_ts) = v.rfind('|') else { return };
    let ts = atoll(&v[s_ts + 1..]);
    let body = &v[..s_ts];
    let Some(p1) = body.find('|') else { return };
    let head = &body[..p1];
    let rest = &body[p1 + 1..];
    let Some(last) = rest.rfind('|') else { return };
    storage::update_global_entry(state, "c", head, &rest[..last], &rest[last + 1..], ts);
}

/// Deduplicate user records by name: for each name keep the record with the
/// highest last_seen (ties: highest timestamp; further ties: lowest UUID).
/// Orphaned mask records are remapped to the surviving UUID and duplicates
/// dropped.  This handles multiple hubs having independently migrated the
/// same admin/oper name and synced their records here.
///
/// Returns true when anything actually changed.
fn dedup_records(state: &mut HubState) -> bool {
    let mut users: Vec<UserRecord> = Vec::new();
    let mut remap: Vec<(String, String)> = Vec::new();

    for u in &state.user_records {
        let existing = users
            .iter()
            .position(|w| w.typ == u.typ && w.name.eq_ignore_ascii_case(&u.name));
        match existing {
            None => users.push(u.clone()),
            Some(j) => {
                let w = &users[j];
                let incoming_wins = u.last_seen > w.last_seen
                    || (u.last_seen == w.last_seen && u.timestamp > w.timestamp)
                    || (u.last_seen == w.last_seen
                        && u.timestamp == w.timestamp
                        && u.uuid < w.uuid);
                if remap.len() < MAX_HUB_USER_RECORDS {
                    if incoming_wins {
                        remap.push((w.uuid.clone(), u.uuid.clone()));
                    } else {
                        remap.push((u.uuid.clone(), w.uuid.clone()));
                    }
                }
                if incoming_wins {
                    users[j] = u.clone();
                }
                crate::hlog_debug!(
                    "[HUB] Dedup: merged duplicate '{}' {} record\n",
                    u.name,
                    u.typ
                );
            }
        }
    }

    let mut masks: Vec<MaskRecord> = Vec::new();
    for m in &state.mask_records {
        let mut m = m.clone();
        // Apply UUID remapping (known loser → winner).
        if let Some((_, to)) = remap.iter().find(|(from, _)| *from == m.uuid) {
            m.uuid = to.clone();
        }
        // Drop masks whose UUID has no surviving owner.
        if !users.iter().any(|u| u.uuid == m.uuid) {
            crate::hlog_debug!(
                "[HUB] Dedup: dropped orphaned mask '{}' (UUID {})\n",
                m.mask,
                m.uuid
            );
            continue;
        }
        match masks
            .iter()
            .position(|w| w.uuid == m.uuid && w.mask.eq_ignore_ascii_case(&m.mask))
        {
            Some(j) => {
                if m.last_used > masks[j].last_used {
                    masks[j] = m;
                }
            }
            None => {
                if masks.len() < MAX_HUB_USER_MASKS {
                    masks.push(m);
                }
            }
        }
    }

    let changed =
        users.len() != state.user_records.len() || masks.len() != state.mask_records.len();
    if changed {
        crate::hlog_info!(
            "[HUB] Config dedup: users {}->{}, masks {}->{}\n",
            state.user_records.len(),
            users.len(),
            state.mask_records.len(),
            masks.len()
        );
    }
    state.user_records = users;
    state.mask_records = masks;
    changed
}

/// hub_config_load().
pub fn load(state: &mut HubState, password: &str) -> bool {
    // Password-era a|/o| lines, or a p| line, seen.
    let mut cfg_legacy_users = 0u32;
    // w|/x| lines dropped, merged or canonicalised.
    let mut cfg_acl_fixed = 0u32;

    if let Ok(md) = fs::metadata(HUB_CONFIG_FILE) {
        let mode = md.permissions().mode();
        if mode & 0o177 != 0 {
            crate::hlog_warning!(
                "[HUB] {HUB_CONFIG_FILE} has insecure permissions {:04o} — should be 0600\n",
                mode & 0o777
            );
        }
    }

    let Ok(file) = fs::read(HUB_CONFIG_FILE) else {
        crate::hlog_error!("[HUB] Config file not found\n");
        return false;
    };
    let hdr = SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN;
    if file.len() <= hdr {
        crate::hlog_error!("[HUB] Invalid config file size\n");
        return false;
    }
    let salt = &file[..SALT_SIZE];
    let iv = &file[SALT_SIZE..SALT_SIZE + GCM_IV_LEN];
    let tag = &file[SALT_SIZE + GCM_IV_LEN..hdr];
    let ct = &file[hdr..];

    let key = crypto::derive_config_key(password.as_bytes(), salt);
    let Some(plain) = crypto::gcm_decrypt_detached(key.as_ref(), iv, &[], ct, tag) else {
        crate::hlog_error!("[HUB] Config decryption failed (wrong password or corrupted file)\n");
        return false;
    };
    let text = Zeroizing::new(String::from_utf8_lossy(&plain).into_owned());

    state.bots.clear();
    state.peers.clear();

    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let sep = line.find('|').or_else(|| line.find(':'));
        let Some(sep) = sep else { continue };
        let k = &line[..sep];
        let v = &line[sep + 1..];

        match k {
            "port" => state.port = crate::cstr::atoi(v),
            "bind_ip" => state.bind_ip = trunc_string(v, 64),
            "uuid" => state.hub_uuid = trunc_string(v, 64),
            // Only update when non-empty, so an empty line cannot blank out
            // an existing name.
            "hub_name" => {
                if !v.is_empty() {
                    state.hub_friendly_name = trunc_string(v, 64);
                }
            }
            // Legacy 'admin|' line ignored (the global admin password was
            // dropped in favour of per-admin records).  Old configs simply
            // lose the field on the next save; admins must already exist as
            // a| records.
            "admin" => {}
            "log_level" => {
                state.log_level = crate::cstr::atoi(v).clamp(LOG_NONE, LOG_DEBUG);
            }
            "log_size" => {
                state.log_max_size = v
                    .trim()
                    .parse::<i64>()
                    .unwrap_or(0)
                    .clamp(HUB_LOG_SIZE_MIN, HUB_LOG_SIZE_MAX);
            }
            "purge_days" => {
                state.purge_days_setting = crate::cstr::atoi(v).max(0);
            }
            // D3: exempt 127.0.0.1/::1 from rate limiting only when
            // explicitly set.  An absent key leaves the secure default.
            "trust_loopback" => {
                state.trust_loopback = v.starts_with('1')
                    || v.eq_ignore_ascii_case("true")
                    || v.eq_ignore_ascii_case("yes");
            }
            // opt|<letters>|<timestamp>, or opt||<timestamp> after a clear.
            "opt" => {
                if let Some((flags, ts)) = parse_opt_value(v) {
                    state.opt_flags = flags;
                    state.opt_flags_ts = ts;
                }
            }
            // rollup|target|variant|kind|min_from|hub_target|plan_set|base|hub_base
            // — see write().  A line that does not parse cleanly is dropped
            // whole: no plan is better than half of one.
            "rollup" => {
                let f: Vec<&str> = v.split('|').collect();
                let caps = [64, 8, 8, 64, 64, 0, 512, 512];
                let ok = f.len() == 8
                    && !f[0].is_empty()
                    && f.iter().zip(caps).all(|(x, cap)| {
                        cap == 0 || (x.len() < cap && crate::upgrade::plan_field_ok(x))
                    });
                let ts = if ok { crate::cstr::atoll(f[5]) } else { 0 };
                if ok && ts > 0 {
                    let r = &mut state.rollup;
                    r.target = f[0].to_string();
                    r.variant = f[1].to_string();
                    r.kind = f[2].to_string();
                    r.min_from = f[3].to_string();
                    r.hub_target = f[4].to_string();
                    r.plan_set = ts;
                    r.base = f[6].to_string();
                    r.hub_base = f[7].to_string();
                    r.have_plan = true;
                } else {
                    state.rollup = Default::default();
                    crate::hlog_warning!("[CONFIG] Ignoring a malformed rollup| line\n");
                }
            }
            "lamport_seq" => {
                let loaded_seq = parse_uint(v.trim(), u64::MAX).unwrap_or(0);
                // Bump past max(saved_seq, time_based_floor) so the seq stays
                // monotonic even if the clock or the saved value lagged.
                // Shifting left 10 bits gives ~1024 seqs/second of headroom
                // before any real tick fires.
                let time_floor = (now() as u64) << 10;
                state.next_lamport_seq = loaded_seq.max(time_floor);
            }
            "key" => match crypto::b64_decode(v) {
                Some(d) if d.len() == COMBINED_KEY_LEN => {
                    let mut c = [0u8; COMBINED_KEY_LEN];
                    c.copy_from_slice(&d);
                    state.set_hub_priv(&c);
                    crypto::wipe(&mut c);
                    state.hub_keys_loaded = true;
                }
                Some(_) => crate::hlog_error!(
                    "[HUB] Hub private key in config is not 64 bytes (legacy RSA?). Re-run -setup with a Curve25519 key.\n"
                ),
                None => {}
            },
            "pub" => {
                if let Some(d) = crypto::b64_decode(v)
                    && d.len() == COMBINED_KEY_LEN
                {
                    let mut c = [0u8; COMBINED_KEY_LEN];
                    c.copy_from_slice(&d);
                    state.set_hub_pub(&c);
                }
            }
            "peer" => load_peer_line(state, v),
            "b" => load_bot_line(state, v),
            // Older layout of the local IP lists: g|<w|x>|<pattern>|<ts>
            "g" if v.starts_with("w|") || v.starts_with("x|") => {
                let list = v.as_bytes()[0] as char;
                load_ip_acl_line(state, list, &v[2..]);
                cfg_acl_fixed += 1; // rewrite as w|/x|
            }
            "g" => load_global_line(state, v),
            // hub_parse_user_record: new uuid|name|pubkey|act|seen|ts| or the
            // legacy password shape (password dropped).  The pre-UUID global
            // admin-password shape a|<password>|<ts> is ignored outright.
            "a" | "o" => {
                if state.user_records.len() < MAX_HUB_USER_RECORDS {
                    match parse_user_record(v, k.as_bytes()[0] as char) {
                        Some((u, legacy)) => {
                            state.user_records.push(u);
                            if legacy {
                                cfg_legacy_users += 1;
                            }
                        }
                        // Rewrite without the unparseable line.
                        None => cfg_legacy_users += 1,
                    }
                }
            }
            "m" => load_mask_line(state, v),
            "c" => load_channel_line(state, v),
            // Retired shared bot password: dropped (bots use public keys).
            "p" => cfg_legacy_users += 1,
            "w" | "x" if !load_ip_acl_line(state, k.as_bytes()[0] as char, v) => {
                cfg_acl_fixed += 1;
            }
            _ => {}
        }
    }

    if dedup_records(state) {
        write(state);
    } else if cfg_legacy_users > 0 || cfg_acl_fixed > 0 {
        // Rewrite once so the passwords / p| line, and IP-list lines that
        // were dropped or canonicalised, leave the file for good.
        write(state);
    }

    if cfg_legacy_users > 0 {
        crate::hlog_info!(
            "[HUB] Config migrated to passwordless records ({cfg_legacy_users} legacy line(s)); passwords dropped\n"
        );
    }
    for u in &state.user_records {
        if u.is_active && !u.has_pubkey {
            crate::hlog_warning!(
                "[HUB] {} '{}' has no public key and cannot authenticate until given one (hub_admin: Change user public key)\n",
                if u.typ == 'a' { "Admin" } else { "Oper" },
                u.name
            );
        }
    }
    true
}

/// Bump the stamp of an existing replicated record.  Exported so the admin
/// handlers read the same rule the storage layer does.
pub fn next_record_ts(prev: i64) -> i64 {
    lww_next_ts(prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg=";

    fn real_key() -> String {
        let (_, p) = crypto::generate_combined_keypair().unwrap();
        crypto::b64_encode(&p)
    }

    #[test]
    fn user_record_new_shape_roundtrips() {
        let k = real_key();
        let line = format!("11111111-2222-3333-4444-555555555555|rob|{k}|add|10|20|");
        let (u, legacy) = parse_user_record(&line, 'a').unwrap();
        assert!(!legacy);
        assert_eq!(u.name, "rob");
        assert!(u.has_pubkey);
        assert_eq!(u.pubkey_b64, k);
        assert!(u.is_active);
        assert_eq!((u.last_seen, u.timestamp), (10, 20));
        assert_eq!(format_user_record(&u, false), format!("a|{line}\n"));
    }

    #[test]
    fn legacy_password_is_dropped_and_key_taken_from_field_7() {
        let k = real_key();
        let line = format!("11111111-2222-3333-4444-555555555555|rob|hunter2|add|10|20|{k}");
        let (u, legacy) = parse_user_record(&line, 'a').unwrap();
        assert!(legacy);
        assert!(u.has_pubkey);
        assert_eq!(u.pubkey_b64, k);
        // The password never reaches any output shape; the legacy line leaves
        // field 3 EMPTY so an old bot fails closed.
        let out = format_user_record(&u, true);
        assert!(!out.contains("hunter2"));
        assert!(out.starts_with("a|11111111-2222-3333-4444-555555555555|rob||add|10|20|"));
    }

    #[test]
    fn user_record_rejects_bad_shapes() {
        assert!(parse_user_record("not-a-uuid|rob|k|add|1|2|", 'a').is_none());
        assert!(
            parse_user_record("11111111-2222-3333-4444-555555555555||k|add|1|2|", 'a').is_none()
        );
        // Fewer than 6 fields.
        assert!(
            parse_user_record("11111111-2222-3333-4444-555555555555|rob|k|add|1", 'a').is_none()
        );
        // A field-3 value that is 88 chars but not a valid key is a password.
        let (u, legacy) = parse_user_record(
            &format!("11111111-2222-3333-4444-555555555555|rob|{KEY}|add|1|2|"),
            'a',
        )
        .unwrap();
        assert!(legacy);
        assert!(!u.has_pubkey);
    }

    #[test]
    fn opt_value_accepts_a_clear() {
        assert_eq!(
            parse_opt_value("h|1700000000"),
            Some(("h".into(), 1700000000))
        );
        assert_eq!(
            parse_opt_value("|1700000000"),
            Some((String::new(), 1700000000))
        );
        assert_eq!(parse_opt_value("h|0"), None);
        assert_eq!(parse_opt_value("h"), None);
        assert_eq!(parse_opt_value("h|12x"), None);
        // Only [a-zA-Z0-9] survives, capped at MAX_OPT_FLAGS.
        assert_eq!(parse_opt_value("h!|5"), Some(("h".into(), 5)));
    }
}
