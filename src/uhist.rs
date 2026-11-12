//! Upgrade history (C: hub_uhist.c, irchub
//! docs/plans/2026-10-31_upgrade_history_plan.md).
//!
//! The last X upgrade runs, one line each, kept in `.irchub.cnf` (`uhist|`) and
//! replicated hub to hub over `CMD_UPGRADE_HISTORY`.  A record belongs to the
//! hub that drove the run: only it bumps `rev`.  Every other hub stores the
//! body as it came and forwards it unchanged.
//!
//! The set converges without tombstones: same id = higher rev wins (a tie goes
//! to the greater string), and eviction is a pure function of the set: sort by
//! (started, id) descending and keep the top `keep`.
//!
//! Nothing here trusts a body, whichever way it came: `parse` validates every
//! field and bound.

use crate::consts::*;
use crate::reply::Reply;
use crate::state::{ClientType, HubState, Lane};
use std::cmp::Ordering;

/// A stored run: the line as it came, plus what the merge compares.
#[derive(Clone, Debug, Default)]
pub struct UhistRec {
    pub body: String,
    pub id: String,
    pub rev: i64,
    pub started: i64,
}

#[derive(Clone, Debug, Default)]
pub struct UhistNode {
    /// b, h, s = the driver
    pub kind: String,
    pub state: String,
    pub uuid: String,
    pub name: String,
    pub from: String,
    pub to: String,
    pub base: String,
    pub want: String,
    pub arch: String,
    pub libc: String,
    pub committed: i64,
    pub back: i64,
    pub done: i64,
    pub reason: String,
    /// Newer readers only; an older one stops at reason.
    /// Why it did not make it: disk, net, selftest, ...
    pub code: String,
    /// bin or src.
    pub build: String,
    /// How long getting it ready took.
    pub stage_s: i64,
}

/// A run parsed for reading or amending; never kept in the store.
#[derive(Clone, Debug, Default)]
pub struct UhistView {
    pub id: String,
    pub rev: i64,
    pub driver_uuid: String,
    pub driver_name: String,
    pub by: String,
    pub started: i64,
    pub rolling_at: i64,
    pub ended: i64,
    pub result: String,
    pub bot_ver: String,
    pub hub_ver: String,
    pub variant: String,
    pub kind: String,
    pub min_from: String,
    pub plan_id: i64,
    pub step: i64,
    pub steps: i64,
    pub sel: String,
    pub summary: String,
    pub nodes: Vec<UhistNode>,
}

// Field capacities, as the C structs size them (bytes + NUL).
const CAP_ID: usize = 64;
const CAP_RESULT: usize = 16;
const CAP_VARIANT: usize = 8;
const CAP_SEL: usize = MAX_UPGRADE_SELECT * 72;
const CAP_SUMMARY: usize = 192;
const CAP_NODE_KIND: usize = 2;
const CAP_NODE_STATE: usize = 16;
const CAP_ARCH: usize = 32;
const CAP_LIBC: usize = 16;
const CAP_REASON: usize = 128;

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

fn put_esc(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &c in s.as_bytes() {
        if matches!(c, b'%' | b'|' | b',' | b';') || !(0x20..0x7f).contains(&c) {
            out.push('%');
            out.push(char::from(HEX[usize::from(c >> 4)]));
            out.push(char::from(HEX[usize::from(c & 15)]));
        } else {
            out.push(char::from(c));
        }
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Decode a field.  None on a bad escape or one that does not fit `cap`.  A
/// decoded control character becomes a space: this text reaches a terminal.
fn unesc(s: &str, cap: usize) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let mut c = b[i];
        if c == b'%' {
            if i + 2 >= b.len() {
                return None;
            }
            c = hex_val(b[i + 1])? << 4 | hex_val(b[i + 2])?;
            i += 2;
        }
        if c < 0x20 || c == 0x7f {
            c = b' ';
        }
        if out.len() + 1 >= cap {
            return None;
        }
        out.push(c);
        i += 1;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// A whole non-negative decimal; empty reads as 0.
fn num(s: &str) -> Option<i64> {
    if s.len() > 18 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if s.is_empty() {
        return Some(0);
    }
    s.parse().ok()
}

/// An id travels in the digest between ':' and ',': letters, digits, - and _.
fn id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() < CAP_ID
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn parse_node(s: &str) -> Option<UhistNode> {
    let f: Vec<&str> = s.splitn(UHIST_NODE_FIELDS + 4, ',').collect();
    if f.len() < UHIST_NODE_FIELDS {
        return None;
    }
    let kind = unesc(f[0], CAP_NODE_KIND).filter(|x| !x.is_empty())?;
    let state = unesc(f[1], CAP_NODE_STATE).filter(|x| !x.is_empty())?;
    Some(UhistNode {
        kind,
        state,
        uuid: unesc(f[2], CAP_ID)?,
        name: unesc(f[3], CAP_ID)?,
        from: unesc(f[4], CAP_ID)?,
        to: unesc(f[5], CAP_ID)?,
        base: unesc(f[6], CAP_VARIANT)?,
        want: unesc(f[7], CAP_VARIANT)?,
        arch: unesc(f[8], CAP_ARCH)?,
        libc: unesc(f[9], CAP_LIBC)?,
        committed: num(f[10])?,
        back: num(f[11])?,
        done: num(f[12])?,
        reason: unesc(f[13], CAP_REASON)?,
        code: if f.len() >= UHIST_NODE_FIELDS + 3 {
            unesc(f[14], 16)?
        } else {
            String::new()
        },
        build: if f.len() >= UHIST_NODE_FIELDS + 3 {
            unesc(f[15], 8)?
        } else {
            String::new()
        },
        stage_s: if f.len() >= UHIST_NODE_FIELDS + 3 {
            num(f[16])?
        } else {
            0
        },
    })
}

pub fn parse(body: &str) -> Option<UhistView> {
    if body.is_empty()
        || body.len() >= UHIST_LINE_MAX
        || body.bytes().any(|c| !(0x20..0x7f).contains(&c))
    {
        return None;
    }
    // Fields after `nodes` are a later version's.
    let f: Vec<&str> = body.splitn(UHIST_HEADER_FIELDS + 1, '|').collect();
    if f.len() < UHIST_HEADER_FIELDS {
        return None;
    }
    let id = unesc(f[0], CAP_ID).filter(|x| id_ok(x))?;
    let rev = num(f[1]).filter(|&r| r > 0)?;
    let driver_uuid = unesc(f[2], CAP_ID).filter(|x| !x.is_empty())?;
    let driver_name = unesc(f[3], CAP_ID)?;
    let by = unesc(f[4], CAP_ID)?;
    // Not ts_ahead: it lets anything through during a config load, and a
    // future `started` would hold the top of the list against real runs.
    let started = num(f[5]).filter(|&t| t > 0 && t <= crate::cstr::now() + LWW_MAX_FUTURE)?;
    let rolling_at = num(f[6])?;
    let ended = num(f[7])?;
    let result = unesc(f[8], CAP_RESULT).filter(|x| !x.is_empty())?;
    let bot_ver = unesc(f[9], CAP_ID)?;
    let hub_ver = unesc(f[10], CAP_ID)?;
    let variant = unesc(f[11], CAP_VARIANT)?;
    let kind = unesc(f[12], CAP_VARIANT)?;
    let min_from = unesc(f[13], CAP_ID)?;
    let plan_id = num(f[14])?;
    let max_steps = MAX_UPGRADE_STEPS as i64;
    let step = num(f[15]).filter(|&x| x <= max_steps)?;
    let steps = num(f[16]).filter(|&x| x <= max_steps)?;
    let sel = unesc(f[17], CAP_SEL)?;
    let summary = unesc(f[18], CAP_SUMMARY)?;
    let mut nodes = Vec::new();
    if !f[19].is_empty() {
        let list: Vec<&str> = f[19].split(';').collect();
        if list.len() > MAX_UPGRADE_NODES {
            return None;
        }
        for n in list {
            nodes.push(parse_node(n)?);
        }
    }
    Some(UhistView {
        id,
        rev,
        driver_uuid,
        driver_name,
        by,
        started,
        rolling_at,
        ended,
        result,
        bot_ver,
        hub_ver,
        variant,
        kind,
        min_from,
        plan_id,
        step,
        steps,
        sel,
        summary,
        nodes,
    })
}

pub fn format(v: &UhistView) -> Option<String> {
    let mut o = String::with_capacity(512 + v.nodes.len() * 128);
    put_esc(&mut o, &v.id);
    o.push_str(&format!("|{}|", v.rev));
    for s in [&v.driver_uuid, &v.driver_name, &v.by] {
        put_esc(&mut o, s);
        o.push('|');
    }
    o.push_str(&format!("{}|{}|{}|", v.started, v.rolling_at, v.ended));
    for s in [
        &v.result,
        &v.bot_ver,
        &v.hub_ver,
        &v.variant,
        &v.kind,
        &v.min_from,
    ] {
        put_esc(&mut o, s);
        o.push('|');
    }
    o.push_str(&format!("{}|{}|{}|", v.plan_id, v.step, v.steps));
    for s in [&v.sel, &v.summary] {
        put_esc(&mut o, s);
        o.push('|');
    }
    for (i, n) in v.nodes.iter().enumerate() {
        if i > 0 {
            o.push(';');
        }
        for s in [
            &n.kind, &n.state, &n.uuid, &n.name, &n.from, &n.to, &n.base, &n.want, &n.arch, &n.libc,
        ] {
            put_esc(&mut o, s);
            o.push(',');
        }
        o.push_str(&format!("{},{},{},", n.committed, n.back, n.done));
        put_esc(&mut o, &n.reason);
        o.push(',');
        put_esc(&mut o, &n.code);
        o.push(',');
        put_esc(&mut o, &n.build);
        o.push_str(&format!(",{}", n.stage_s));
    }
    (o.len() < UHIST_LINE_MAX).then_some(o)
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub fn keep(state: &HubState) -> usize {
    let k = state.uhist_keep_setting;
    if k >= 1 && k as usize <= MAX_UPGRADE_HISTORY {
        k as usize
    } else {
        UHIST_DEFAULT_KEEP
    }
}

/// Newest first.
fn order(a_started: i64, a_id: &str, b_started: i64, b_id: &str) -> Ordering {
    b_started
        .cmp(&a_started)
        .then_with(|| b_id.as_bytes().cmp(a_id.as_bytes()))
}

pub fn trim(state: &mut HubState) {
    let k = keep(state);
    if state.uhist.len() > k {
        state.uhist.truncate(k);
        state.config_dirty = true;
    }
}

pub fn find(state: &HubState, id: &str) -> Option<usize> {
    state.uhist.iter().position(|r| r.id == id)
}

/// Merge a parsed body.  True when the store changed.
fn merge(state: &mut HubState, v: &UhistView, body: &str) -> bool {
    let at = find(state, &v.id);
    if let Some(at) = at {
        let r = &state.uhist[at];
        if v.rev < r.rev || (v.rev == r.rev && body.as_bytes() <= r.body.as_bytes()) {
            return false;
        }
        state.uhist.remove(at);
    }
    let k = keep(state);
    let pos = state
        .uhist
        .iter()
        .position(|r| order(r.started, &r.id, v.started, &v.id) != Ordering::Less)
        .unwrap_or(state.uhist.len());
    // It would fall straight off the end: nothing new is stored, but an older
    // revision removed above is a change the caller must save and flood.
    if pos >= k {
        return at.is_some();
    }
    state.uhist.insert(
        pos,
        UhistRec {
            body: body.to_string(),
            id: v.id.clone(),
            rev: v.rev,
            started: v.started,
        },
    );
    trim(state);
    true
}

pub fn load_line(state: &mut HubState, body: &str) -> bool {
    match parse(body) {
        Some(v) => {
            merge(state, &v, body);
            true
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

fn send_record(state: &mut HubState, ci: usize, body: &str) {
    let frame = format!("R|{body}");
    crate::mesh::peer_enqueue_sync(state, ci, CMD_UPGRADE_HISTORY, Lane::Bulk, &frame, None);
}

fn flood(state: &mut HubState, body: &str, except: Option<usize>) {
    for ci in 0..state.clients.len() {
        let c = &state.clients[ci];
        if c.typ == ClientType::Hub && c.authenticated && Some(ci) != except {
            send_record(state, ci, body);
        }
    }
}

pub fn send_digest(state: &mut HubState, ci: usize) {
    let list: Vec<String> = state
        .uhist
        .iter()
        .map(|r| format!("{}:{}:{}", r.id, r.rev, r.started))
        .collect();
    let d = format!("D|{}|{}", keep(state), list.join(","));
    crate::mesh::peer_enqueue_sync(state, ci, CMD_UPGRADE_HISTORY, Lane::Bulk, &d, None);
}

/// Every linked peer, on the anti-entropy tick.
pub fn digest_all(state: &mut HubState) {
    for ci in 0..state.clients.len() {
        let c = &state.clients[ci];
        if c.typ == ClientType::Hub && c.authenticated {
            send_digest(state, ci);
        }
    }
}

/// A digest's (keep, [(id, rev, started)]).
type Digest = (usize, Vec<(String, i64, i64)>);

fn parse_digest(rest: &str) -> Option<Digest> {
    let (keep_s, list) = rest.split_once('|')?;
    let peer_keep: usize = keep_s.parse().ok()?;
    if !(1..=MAX_UPGRADE_HISTORY).contains(&peer_keep) {
        return None;
    }
    let mut peer = Vec::new();
    if !list.is_empty() {
        for e in list.split(',').take(MAX_UPGRADE_HISTORY) {
            let mut p = e.split(':');
            let id = p.next()?;
            let rev = num(p.next()?)?;
            let started = num(p.next()?)?;
            if !id_ok(id) {
                return None;
            }
            peer.push((id.to_string(), rev, started));
        }
    }
    Some((peer_keep, peer))
}

/// Push what the sender of this digest lacks.  A digest is never answered with
/// a digest, so this cannot loop.
fn on_digest(state: &mut HubState, ci: usize, rest: &str) {
    let Some((peer_keep, peer)) = parse_digest(rest) else {
        crate::hlog_warning!(
            "[UPGRADE] Malformed history digest from {}\n",
            state.who_client(ci)
        );
        return;
    };
    let oldest = peer
        .iter()
        .max_by(|a, b| order(a.2, &a.0, b.2, &b.0))
        .cloned();
    let mut push = Vec::new();
    for r in &state.uhist {
        if let Some(p) = peer.iter().find(|p| p.0 == r.id) {
            if p.1 < r.rev {
                push.push(r.body.clone());
            }
            continue;
        }
        // Outside its window: it would evict this straight away.
        if peer.len() >= peer_keep
            && let Some(o) = &oldest
            && order(r.started, &r.id, o.2, &o.0) == Ordering::Greater
        {
            continue;
        }
        push.push(r.body.clone());
    }
    for b in push {
        send_record(state, ci, &b);
    }
}

pub fn process(state: &mut HubState, ci: usize, payload: &str) {
    if let Some(rest) = payload.strip_prefix("D|") {
        on_digest(state, ci, rest);
        return;
    }
    let Some(body) = payload.strip_prefix("R|") else {
        crate::hlog_warning!(
            "[UPGRADE] Unknown history frame from {}\n",
            state.who_client(ci)
        );
        return;
    };
    let Some(v) = parse(body) else {
        crate::hlog_warning!(
            "[UPGRADE] Dropped a malformed history record from {}\n",
            state.who_client(ci)
        );
        return;
    };
    if merge(state, &v, body) {
        state.config_dirty = true;
        flood(state, body, Some(ci));
    }
}

/// The driver stores a new rev of its own record, floods it and writes the
/// file now: it may be about to replace this process.
pub fn put_own(state: &mut HubState, v: &mut UhistView) {
    v.rev = find(state, &v.id).map_or(1, |at| state.uhist[at].rev + 1);
    let Some(body) = format(v) else {
        crate::hlog_warning!(
            "[UPGRADE] History record for {} does not fit; not kept\n",
            v.id
        );
        return;
    };
    if merge(state, v, &body) {
        flood(state, &body, None);
    }
    crate::config::write(state);
}

/// What the plan's earlier steps recorded as the admin who typed it.
pub fn plan_by(state: &HubState, plan_id: i64) -> String {
    for r in &state.uhist {
        if let Some(v) = parse(&r.body)
            && v.plan_id == plan_id
            && v.driver_uuid == state.hub_uuid
            && !v.by.is_empty()
        {
            return v.by;
        }
    }
    String::new()
}

/// A boot closes what the last process could not: a run it never finished, and
/// the driver's own node, which only the new build can report on.
pub fn boot(state: &mut HubState) {
    let mut changed = false;
    let ids: Vec<String> = state.uhist.iter().map(|r| r.id.clone()).collect();
    for id in ids {
        let Some(at) = find(state, &id) else { continue };
        let Some(mut v) = parse(&state.uhist[at].body) else {
            continue;
        };
        if v.driver_uuid != state.hub_uuid {
            continue;
        }
        let now = crate::cstr::now();
        let mut amend = false;
        if v.result == "running" {
            v.result = "interrupted".to_string();
            v.summary = "this hub restarted before the run finished".to_string();
            v.ended = now;
            amend = true;
        } else if v.result != "aborted" {
            let self_at = v
                .nodes
                .iter()
                .position(|n| n.kind == "s" && n.state == "committing");
            if let Some(k) = self_at {
                let variant = crate::update::host_variant();
                let nd = &mut v.nodes[k];
                let want = if nd.want.is_empty() {
                    &nd.base
                } else {
                    &nd.want
                };
                let ok = crate::update::version_cmp(HUB_VERSION, &nd.to) == Ordering::Equal
                    && (want.is_empty() || want == variant);
                nd.done = now;
                nd.state = if ok { "done" } else { "failed" }.to_string();
                if !ok {
                    nd.reason = format!("came back on {HUB_VERSION}/{variant}");
                }
                let done = v.nodes.iter().filter(|n| n.state == "done").count();
                let unable = v.nodes.iter().filter(|n| n.state == "unable").count();
                if ok {
                    v.summary =
                        format!("{done} node(s) now on the target, {unable} could not take it");
                } else {
                    v.result = "partial".to_string();
                    v.summary =
                        format!("{done} node(s) upgraded, but this hub stayed on {HUB_VERSION}");
                }
                v.ended = now;
                amend = true;
            }
        }
        if amend {
            put_own(state, &mut v);
            changed = true;
        }
    }
    if changed {
        crate::hlog_info!("[UPGRADE] Upgrade history brought up to date after the restart\n");
    }
}

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------

fn reply_run(r: &mut Reply, v: &UhistView) {
    let (mut done, mut failed, mut unable, mut already, mut skipped, mut idle, mut open) =
        (0i64, 0i64, 0i64, 0i64, 0i64, 0i64, 0i64);
    for n in &v.nodes {
        match n.state.as_str() {
            "done" => done += 1,
            "failed" => failed += 1,
            "unable" => unable += 1,
            "already" => already += 1,
            "skipped" => skipped += 1,
            "idle" => idle += 1,
            _ => open += 1,
        }
    }
    r.kv("id", &v.id);
    r.kvi("rev", v.rev);
    r.kvi("started", v.started);
    if v.rolling_at != 0 {
        r.kvi("rolling", v.rolling_at);
    }
    if v.ended != 0 {
        r.kvi("ended", v.ended);
    }
    r.kv("result", &v.result);
    // A driver that never came back never closes its record.
    if v.result == "running" && crate::cstr::now() - v.started > UPGRADE_PLAN_TTL {
        r.kvb("stale", true);
    }
    if !v.bot_ver.is_empty() {
        r.kv("bot_ver", &v.bot_ver);
    }
    if !v.hub_ver.is_empty() {
        r.kv("hub_ver", &v.hub_ver);
    }
    r.kv(
        "driver",
        if v.driver_name.is_empty() {
            &v.driver_uuid
        } else {
            &v.driver_name
        },
    );
    r.kv("driver_uuid", &v.driver_uuid);
    if !v.by.is_empty() {
        r.kv("by", &v.by);
    }
    if !v.sel.is_empty() {
        r.kv("sel", &v.sel);
    }
    if v.steps > 0 {
        r.kvi("plan", v.plan_id);
        r.kvi("step", v.step);
        r.kvi("steps", v.steps);
    }
    if !v.summary.is_empty() {
        r.kv("summary", &v.summary);
    }
    r.kvi("done", done);
    r.kvi("failed", failed);
    r.kvi("unable", unable);
    r.kvi("already", already);
    r.kvi("skipped", skipped);
    r.kvi("idle", idle);
    r.kvi("open", open);
}

pub fn reply_runs(state: &HubState, r: &mut Reply) {
    for rec in &state.uhist {
        if let Some(v) = parse(&rec.body) {
            r.rec("run");
            reply_run(r, &v);
        }
    }
}

/// Ok on one run found; Err(true) = more than one matches, Err(false) = none.
pub fn reply_one(state: &HubState, pfx: &str, r: &mut Reply) -> Result<(), bool> {
    if pfx.len() < UHIST_MIN_PREFIX {
        return Err(false);
    }
    let hits: Vec<&UhistRec> = state
        .uhist
        .iter()
        .filter(|x| x.id.starts_with(pfx))
        .collect();
    if hits.len() > 1 {
        return Err(true);
    }
    let v = hits.first().and_then(|x| parse(&x.body)).ok_or(false)?;
    r.ok("upg.run");
    reply_run(r, &v);
    for (k, s) in [
        ("variant", &v.variant),
        ("kind", &v.kind),
        ("min_from", &v.min_from),
    ] {
        if !s.is_empty() {
            r.kv(k, s);
        }
    }
    for n in &v.nodes {
        r.rec("node");
        r.kv(
            "kind",
            match n.kind.as_str() {
                "b" => "bot",
                "h" => "hub",
                _ => "driver",
            },
        );
        r.kv("uuid", &n.uuid);
        if !n.name.is_empty() {
            r.kv("name", &n.name);
        }
        r.kv("state", &n.state);
        for (k, s) in [
            ("from", &n.from),
            ("to", &n.to),
            ("base", &n.base),
            ("want", &n.want),
            ("arch", &n.arch),
            ("libc", &n.libc),
        ] {
            if !s.is_empty() {
                r.kv(k, s);
            }
        }
        for (k, t) in [
            ("committed", n.committed),
            ("back", n.back),
            ("done", n.done),
        ] {
            if t != 0 {
                r.kvi(k, t);
            }
        }
        if !n.reason.is_empty() {
            r.kv("reason", &n.reason);
        }
        if !n.code.is_empty() {
            r.kv("code", &n.code);
        }
        if !n.build.is_empty() {
            r.kv("build", &n.build);
        }
        if n.stage_s > 0 {
            r.kvi("stage_s", n.stage_s);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, started: i64, rev: i64) -> UhistView {
        UhistView {
            id: id.to_string(),
            rev,
            driver_uuid: "d-uuid".to_string(),
            driver_name: "hub|one,;%".to_string(),
            started,
            result: "done".to_string(),
            summary: "a|b\nc".to_string(),
            nodes: vec![UhistNode {
                kind: "b".to_string(),
                state: "done".to_string(),
                uuid: "u".to_string(),
                reason: "x;y,z|%\u{e9}".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn hostile_strings_round_trip_on_one_line() {
        let body = format(&sample("run-1", 1000, 1)).unwrap();
        assert!(!body.contains('\n') && body.is_ascii());
        assert_eq!(body.split('|').count(), UHIST_HEADER_FIELDS);
        let v = parse(&body).unwrap();
        assert_eq!(v.driver_name, "hub|one,;%");
        assert_eq!(v.summary, "a|b c");
        assert_eq!(v.nodes[0].reason, "x;y,z|%\u{e9}");
    }

    #[test]
    fn malformed_bodies_are_refused() {
        let good = format(&sample("run-1", 1000, 1)).unwrap();
        for bad in [
            "",
            "a|b",
            &good.replacen("run-1", "ru:n", 1),
            &good.replacen("|1|", "|0|", 1),
            &good.replacen("|1000|", "|0|", 1),
            &format!("{good}\n"),
            &good.replace("hub%7Cone", "hub%7"),
        ] {
            assert!(parse(bad).is_none(), "accepted {bad:?}");
        }
        assert!(parse(&format!("{good}|future")).is_some(), "later field");
        let too_many = "b,done,u,,,,,,,,0,0,0,;".repeat(MAX_UPGRADE_NODES + 1);
        let mut v = sample("run-1", 1000, 1);
        v.nodes.clear();
        let head = format(&v).unwrap();
        assert!(parse(&format!("{head}{}", too_many.trim_end_matches(';'))).is_none());
    }

    #[test]
    fn merge_converges_whatever_the_order() {
        let bodies: Vec<(UhistView, String)> = (0..14)
            .map(|i| {
                let v = sample(&format!("run-{i:02}"), 1000 + i, 1);
                let b = format(&v).unwrap();
                (v, b)
            })
            .collect();
        let mut a = HubState::default();
        let mut b = HubState::default();
        for (v, s) in &bodies {
            merge(&mut a, v, s);
        }
        for (v, s) in bodies.iter().rev() {
            merge(&mut b, v, s);
        }
        let ids = |s: &HubState| s.uhist.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&a), ids(&b));
        assert_eq!(a.uhist.len(), UHIST_DEFAULT_KEEP);
        assert_eq!(a.uhist[0].id, "run-13");
        // An older record than the window holds changes nothing.
        assert!(!merge(&mut a, &bodies[0].0, &bodies[0].1));
        // A higher rev replaces; a lower one does not.
        let v2 = sample("run-13", 1013, 2);
        let s2 = format(&v2).unwrap();
        assert!(merge(&mut a, &v2, &s2));
        assert!(!merge(&mut a, &bodies[13].0, &bodies[13].1));
        assert_eq!(a.uhist[0].rev, 2);
        // A higher rev of a record past a window that shrank before the
        // store was trimmed removes it and says so (fable_52_pass F10).
        a.uhist_keep_setting = 5;
        let last = a.uhist[UHIST_DEFAULT_KEEP - 1].clone();
        let v3 = sample(&last.id, last.started, last.rev + 1);
        let s3 = format(&v3).unwrap();
        assert!(merge(&mut a, &v3, &s3));
        assert!(find(&a, &last.id).is_none());
    }

    #[test]
    fn digest_parses_and_refuses() {
        assert_eq!(parse_digest("10|").unwrap().1.len(), 0);
        assert_eq!(parse_digest("10|a-1:2:3,b:1:4").unwrap().1.len(), 2);
        for bad in ["0|", "21|", "x|", "10", "10|a:b:c", "10|a:1", "10|a,b:1:2"] {
            assert!(parse_digest(bad).is_none(), "{bad}");
        }
    }
}
