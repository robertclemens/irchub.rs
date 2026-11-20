//! Presence v2, phases 1-2: one versioned record per hub (hub_presence2.c).
//!
//! Plan: irchub docs/plans/2026-11-14_presence_v2_plan.md (§9 phase 1, §10
//! phase 2).  Reference state machine, simulator and differential fuzz:
//! ~/ircbot-testnet/proto/presence2 (SPEC.md).  The C hub speaks the same
//! frames byte for byte.
//!
//! Each hub publishes {origin, epoch, seq, caps, links, bots}.  epoch is a boot
//! counter kept in P2_EPOCH_FILE, so a clock that steps or runs fast can never
//! make a restart look old.  Each change to it is one D frame (b+ b- l+ l-),
//! flooded at once with a per-origin seen window and split horizon; a seq gap
//! makes the receiver pull the record (R -> S), and a pulled record is passed
//! on, so a repair spreads in one go.  Each bot and each peer link is damped on
//! its own (P2_FLAP_*), so one flapping entity never slows anyone else's news;
//! past a token bucket (P2_BUCKET_*) changes go silent and one snapshot per
//! P2_STORM_GAP_MS carries them.  The whole record is flooded again every
//! P2_FULL_EVERY_MS at a new seq, and every link carries H|count|fnv64 every
//! P2_DIGEST_MS: on a mismatch the two sides swap full digests and pull.
//!
//! Reachability is a breadth-first walk over the records; a link counts only
//! when both ends list it.  Phase 1 runs beside the CMD_BOT_ROSTER rounds and
//! only ever shortens how long the roster shows something that is gone:
//! - a reachable hub's record is authoritative for which bots it has: a bot
//!   it no longer lists is dropped at once (`presence::p2_reconcile`);
//! - a hub unreachable for P2_GRACE_MS loses its roster entries and its
//!   mesh-map entry (`presence::p2_drop_hub`), the tree hides it at once.
//!
//! Both run only on change: a record accepted, a roster entry of that hub
//! upserted (`roster_touched`) or the hub turning reachable again.
//!
//! Both need every linked peer to speak v2 and every mesh-map hub to have a
//! record ("ready"): behind a hub that never publishes nothing can be walked,
//! and today's view stays in charge.

use std::sync::OnceLock;
use std::time::Instant;

use crate::consts::*;
use crate::queue;
use crate::state::QueuedMsg;
use crate::state::{ClientType, HubState, Lane};

pub const P2_EPOCH_FILE: &str = ".irchub.epoch";
pub const P2_TTL_HOPS: u64 = 16;
pub const P2_MAX_LINKS: usize = 16;
pub const P2_MAX_BOTS: usize = 128;
pub const P2_ID_MAX: usize = 63;
pub const P2_CAPS_MAX: usize = 15;
pub const P2_MAX_FRAME: usize = 16384;
pub const P2_EPOCH_MAX: u64 = 1 << 40;
pub const P2_SEQ_MAX: u64 = 1 << 48;
/// A relayed epoch jump refused above this...
pub const P2_EPOCH_JUMP: u64 = 1024;
/// ...and a seq jump within one epoch.
pub const P2_SEQ_JUMP: u64 = 1 << 20;
pub const P2_PULL_RETRY_MS: i64 = 2000;
/// Unreachable this long = gone for decisions.
pub const P2_GRACE_MS: i64 = 5000;
/// Own record re-flooded at a new seq.
pub const P2_FULL_EVERY_MS: i64 = 300_000;
pub const P2_RECONCILE_MS: i64 = 1000;
/// `tick` runs at most this often.
pub const P2_TICK_MS: i64 = 100;
// phase 2: deltas, damping, storm cap, compact digest
/// Per-origin seen window for D frames.
pub const P2_SEEN_WINDOW: u64 = 64;
pub const P2_FLAP_WINDOW_MS: i64 = 30_000;
/// Flips per window before damping.
pub const P2_FLAP_FREE: i32 = 4;
pub const P2_HOLD_MAX_MS: i64 = 30_000;
/// Deltas per second...
pub const P2_BUCKET_RATE: i64 = 20;
/// ...with this burst; past it: snapshots.
pub const P2_BUCKET_BURST: i64 = 100;
/// At most one storm snapshot per gap.
pub const P2_STORM_GAP_MS: i64 = 1000;
/// H|count|fnv64 on every link.
pub const P2_DIGEST_MS: i64 = 15_000;
/// Live + damped gone entities.
pub const P2_MAX_ENTS: usize = 2 * (P2_MAX_BOTS + P2_MAX_LINKS);
/// Phase 3: seconds a v2 peer link may go unheard (3 missed 15 s digests)
/// before it is dropped; such links carry no pings.
pub const P2_LINK_TIMEOUT: i64 = 45;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct P2Bot {
    pub id: String,
    /// Its link to the origin (unix s).
    pub since: i64,
}

#[derive(Clone, Debug, Default)]
pub struct P2Rec {
    pub origin: String,
    /// 0 = known name, no record yet.
    pub epoch: u64,
    pub seq: u64,
    pub caps: String,
    pub links: Vec<String>,
    pub bots: Vec<P2Bot>,
    /// `BotRoster::p2_stamp` order at accept.
    pub stamp: u64,
    pub pull_next_ms: i64,
    /// Monotonic: when it became unreachable.
    pub gone_ms: i64,
    pub reach: bool,
    pub purged: bool,
    /// Roster or record changed: reconcile.
    pub rdirty: bool,
    /// D seen window (P2_SEEN_WINDOW).
    pub win_epoch: u64,
    pub win_top: u64,
    pub win_mask: u64,
}

/// One of our bots or peer links, damped on its own (P2_FLAP_*).
#[derive(Clone, Debug, Default)]
pub struct P2Ent {
    pub id: String,
    /// 'b' bot, 'l' peer link.
    pub kind: char,
    pub live: bool,
    /// Bot: its link time while live.
    pub since: i64,
    pub flips: i32,
    /// Flap window start.
    pub window_ms: i64,
    /// Hold until.
    pub hold_ms: i64,
}

#[derive(Debug, Default)]
pub struct P2State {
    pub me: P2Rec,
    pub recs: Vec<P2Rec>,
    /// Storm pending: snapshot instead of D.
    pub dirty: bool,
    pub last_flood_ms: i64,
    /// P2_TICK_MS gate.
    pub last_tick_ms: i64,
    pub next_full_ms: i64,
    pub next_reconcile_ms: i64,
    pub next_digest_ms: i64,
    pub stamp_ctr: u64,
    pub ents: Vec<P2Ent>,
    /// Storm cap token bucket.
    pub tokens_milli: i64,
    pub bucket_ms: i64,
    /// Last tick's `ready()`.
    pub ready: bool,
    pub c_rx: u64,
    pub c_rx_bad: u64,
    pub c_tx: u64,
    pub c_relays: u64,
    pub c_pulls: u64,
    pub c_heals: u64,
    pub c_jumps: u64,
    pub c_purges: u64,
    pub c_deltas: u64,
    pub c_snaps: u64,
    pub c_held: u64,
    pub c_digest_miss: u64,
}

fn now_ms() -> i64 {
    static START: OnceLock<Instant> = OnceLock::new();
    // Offset so the first reading is never 0 (C's monotonic clock is not).
    START.get_or_init(Instant::now).elapsed().as_millis() as i64 + 1_000_000
}

// ---------- validation ----------

fn id_ok(s: &str) -> bool {
    (1..=P2_ID_MAX).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c == b'-')
}

/// 1..19 decimal digits, <= i64::MAX.
fn num_ok(s: &str) -> Option<u64> {
    if !(1..=19).contains(&s.len()) || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|v| *v <= i64::MAX as u64)
}

/// Split on sep; None when more than max fields.
fn split(s: &str, sep: char, max: usize) -> Option<Vec<&str>> {
    let v: Vec<&str> = s.split(sep).collect();
    (v.len() <= max).then_some(v)
}

fn es_sane(e: u64, s: u64) -> bool {
    e <= P2_EPOCH_MAX && s <= P2_SEQ_MAX
}

// ---------- epoch file ----------

fn epoch_read() -> u64 {
    let Ok(text) = std::fs::read_to_string(P2_EPOCH_FILE) else {
        return 0;
    };
    let line = text.lines().next().unwrap_or("");
    match num_ok(line).filter(|v| *v < P2_EPOCH_MAX) {
        Some(v) => v,
        None => {
            crate::hlog_warning!(
                "[PRESENCE] {P2_EPOCH_FILE} unreadable: boot counter restarts (peers heal it)\n"
            );
            0
        }
    }
}

fn epoch_write(epoch: u64) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{P2_EPOCH_FILE}.tmp");
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(format!("{epoch}\n").as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, P2_EPOCH_FILE)
    })();
    if let Err(e) = res {
        crate::hlog_error!("[PRESENCE] cannot write {P2_EPOCH_FILE}: {e}\n");
        let _ = std::fs::remove_file(&tmp);
    }
}

// ---------- records ----------

fn rec_find(p: &P2State, o: &str) -> Option<usize> {
    p.recs.iter().position(|r| r.origin == o)
}

/// Find or create.  Full: reuse the record unreachable the longest, never a
/// reachable one.
fn rec_get(p: &mut P2State, o: &str) -> Option<usize> {
    if let Some(i) = rec_find(p, o) {
        return Some(i);
    }
    let fresh = P2Rec {
        origin: o.to_string(),
        ..Default::default()
    };
    if p.recs.len() < MAX_MESH_HUBS {
        p.recs.push(fresh);
        return Some(p.recs.len() - 1);
    }
    // When an unreachable record went; one never reached has no gone_ms and
    // counts as the newest, so it is the last to be evicted (C p2_gone_key).
    let key = |r: &P2Rec| if r.gone_ms != 0 { r.gone_ms } else { i64::MAX };
    let mut pick: Option<usize> = None;
    for (i, r) in p.recs.iter().enumerate() {
        if !r.reach && pick.is_none_or(|k| key(r) < key(&p.recs[k])) {
            pick = Some(i);
        }
    }
    let i = pick?;
    p.recs[i] = fresh;
    Some(i)
}

/// `S|origin|epoch|seq|ttl|caps|links|bots`
fn snap_frame(r: &P2Rec, ttl: u64) -> Option<String> {
    let mut out = format!(
        "S|{}|{}|{}|{}|{}|",
        r.origin,
        r.epoch,
        r.seq,
        ttl,
        if r.caps.is_empty() { "-" } else { &r.caps }
    );
    if r.links.is_empty() {
        out.push('-');
    } else {
        out.push_str(&r.links.join(","));
    }
    out.push('|');
    if r.bots.is_empty() {
        out.push('-');
    }
    for (i, b) in r.bots.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{}:{}", b.id, b.since));
    }
    // C: the frame must fit P2_MAX_FRAME with its NUL.
    (out.len() < P2_MAX_FRAME).then_some(out)
}

// ---------- peers ----------

/// The configured peer uuid behind an authenticated hub connection, or "".
fn peer_uuid(state: &HubState, ci: usize) -> String {
    let Some(c) = state.clients.get(ci) else {
        return String::new();
    };
    if c.typ != ClientType::Hub || !c.authenticated || !c.peer_heard || c.fd < 0 {
        return String::new();
    }
    state
        .peers
        .iter()
        .find(|p| p.connected && p.fd == c.fd)
        .map(|p| p.uuid.clone())
        .unwrap_or_default()
}

/// Linked peers in configuration order, one connection each: (client, uuid).
fn linked(state: &HubState) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    for pc in &state.peers {
        if out.len() >= MAX_PEERS {
            break;
        }
        if !pc.connected || pc.fd <= 0 || !id_ok(&pc.uuid) || out.iter().any(|(_, u)| *u == pc.uuid)
        {
            continue;
        }
        if let Some(ci) = state.clients.iter().position(|c| {
            c.typ == ClientType::Hub && c.authenticated && c.peer_heard && c.fd == pc.fd
        }) {
            out.push((ci, pc.uuid.clone()));
        }
    }
    out
}

fn tx(state: &mut HubState, ci: usize, frame: &str) {
    let Some(m) = QueuedMsg::new(CMD_PRESENCE2, Lane::Delta, frame.as_bytes()) else {
        return;
    };
    if queue::enqueue(&mut state.clients[ci], m)
        && let Some(p) = state.p2.as_mut()
    {
        p.c_tx += 1;
    }
}

/// To every linked peer but the sender, the origin and the hubs the origin
/// lists as linked (they had it first hand).
fn relay(state: &mut HubState, frame: &str, from: usize, origin: &str, links: &[String]) {
    for (ci, id) in linked(state) {
        if ci == from || id == origin || links.contains(&id) {
            continue;
        }
        tx(state, ci, frame);
        if let Some(p) = state.p2.as_mut() {
            p.c_relays += 1;
        }
    }
}

fn flood_self(state: &mut HubState) {
    let Some(p) = state.p2.as_mut() else { return };
    let frame = snap_frame(&p.me, P2_TTL_HOPS);
    p.dirty = false;
    p.last_flood_ms = now_ms();
    if let Some(f) = frame {
        for (ci, _) in linked(state) {
            tx(state, ci, &f);
        }
    }
}

fn send_digest(state: &mut HubState, ci: usize, kind: char) {
    let Some(p) = state.p2.as_ref() else { return };
    let mut out = format!("{kind}|{}:{}:{}", p.me.origin, p.me.epoch, p.me.seq);
    for r in p.recs.iter().filter(|r| r.epoch > 0) {
        out.push_str(&format!(",{}:{}:{}", r.origin, r.epoch, r.seq));
    }
    if out.len() < P2_MAX_FRAME {
        tx(state, ci, &out);
    }
}

/// FNV-1a 64 over "origin:epoch:seq;" for us and every record with epoch > 0,
/// sorted by origin; also the entry count.
fn hash(p: &P2State) -> (usize, u64) {
    let mut v: Vec<&P2Rec> = vec![&p.me];
    v.extend(p.recs.iter().filter(|r| r.epoch > 0));
    v.sort_by(|a, b| a.origin.cmp(&b.origin));
    let mut h: u64 = 0xcbf29ce484222325;
    for r in &v {
        for b in format!("{}:{}:{};", r.origin, r.epoch, r.seq).bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    (v.len(), h)
}

fn send_hash(state: &mut HubState, ci: usize) {
    let Some(p) = state.p2.as_ref() else { return };
    let (n, h) = hash(p);
    tx(state, ci, &format!("H|{n}|{h:016x}"));
}

fn pull(state: &mut HubState, ri: usize, ci: usize) {
    let Some(p) = state.p2.as_mut() else { return };
    let now = now_ms();
    let r = &mut p.recs[ri];
    if now < r.pull_next_ms {
        return;
    }
    r.pull_next_ms = now + P2_PULL_RETRY_MS;
    let frame = format!("R|{}", r.origin);
    p.c_pulls += 1;
    tx(state, ci, &frame);
}

// ---------- own record ----------

// ---------- own record: entities, deltas, storm cap ----------

fn ent_get(p: &mut P2State, kind: char, id: &str) -> Option<usize> {
    if let Some(i) = p.ents.iter().position(|e| e.kind == kind && e.id == id) {
        return Some(i);
    }
    if p.ents.len() >= P2_MAX_ENTS {
        return None;
    }
    p.ents.push(P2Ent {
        id: id.to_string(),
        kind,
        ..Default::default()
    });
    Some(p.ents.len() - 1)
}

/// A bot or link of ours changed: count the flip; past P2_FLAP_FREE flips in
/// one window it is held 1, 2, 4 ... P2_HOLD_MAX_MS, and the hold publishes
/// the net change when it ends.
fn ent_event(p: &mut P2State, i: usize, live: bool, since: i64, now: i64) {
    let e = &mut p.ents[i];
    if now - e.window_ms >= P2_FLAP_WINDOW_MS {
        e.flips = 0;
        e.window_ms = now;
    }
    e.flips += 1;
    e.live = live;
    e.since = since;
    if e.flips > P2_FLAP_FREE {
        let sh = (e.flips - P2_FLAP_FREE - 1).min(15);
        e.hold_ms = now + (1000i64 << sh).min(P2_HOLD_MAX_MS);
        p.c_held += 1;
    }
}

fn take_token(p: &mut P2State, now: i64) -> bool {
    if now > p.bucket_ms {
        p.tokens_milli =
            (p.tokens_milli + (now - p.bucket_ms) * P2_BUCKET_RATE).min(P2_BUCKET_BURST * 1000);
    }
    p.bucket_ms = now;
    if p.tokens_milli < 1000 {
        return false;
    }
    p.tokens_milli -= 1000;
    true
}

/// One published change of ours: seq moves on, and a D goes to every linked
/// peer but `skip` while the bucket allows and no storm snapshot is pending;
/// otherwise the change stays silent and the next snapshot carries it.
fn publish(state: &mut HubState, skip: Option<usize>, op: &str, id: &str, since: i64, now: i64) {
    let peers: Vec<usize> = linked(state)
        .into_iter()
        .map(|(ci, _)| ci)
        .filter(|ci| Some(*ci) != skip)
        .collect();
    let Some(p) = state.p2.as_mut() else { return };
    p.me.seq += 1;
    if peers.is_empty() {
        return; // nobody to tell: link-up sends the record
    }
    if p.dirty || !take_token(p, now) {
        p.dirty = true;
        return;
    }
    let frame = format!(
        "D|{}|{}|{}|{}|{op}|{id}|{since}",
        p.me.origin, p.me.epoch, p.me.seq, P2_TTL_HOPS
    );
    p.c_deltas += 1;
    for ci in peers {
        tx(state, ci, &frame);
    }
}

/// Compare the live links and bots with our entities, then publish every
/// entity that is not held and differs from the record.  `skip`: a link
/// coming up gets the whole record instead.
fn refresh_self(state: &mut HubState, skip: Option<usize>) {
    let now = now_ms();
    let mut links: Vec<String> = linked(state).into_iter().map(|(_, u)| u).collect();
    links.truncate(P2_MAX_LINKS);
    let mut bots: Vec<P2Bot> = Vec::new();
    for c in &state.clients {
        if bots.len() >= P2_MAX_BOTS {
            break;
        }
        if c.typ != ClientType::Bot
            || !c.authenticated
            || c.superseded
            || !id_ok(&c.id)
            || bots.iter().any(|b| b.id == c.id)
        {
            continue;
        }
        bots.push(P2Bot {
            id: c.id.clone(),
            since: c.connected_at,
        });
    }
    let Some(p) = state.p2.as_mut() else { return };
    for l in &links {
        if let Some(i) = ent_get(p, 'l', l)
            && !p.ents[i].live
        {
            ent_event(p, i, true, 0, now);
        }
    }
    for b in &bots {
        if let Some(i) = ent_get(p, 'b', &b.id)
            && (!p.ents[i].live || p.ents[i].since != b.since)
        {
            ent_event(p, i, true, b.since, now);
        }
    }
    for i in 0..p.ents.len() {
        let e = &p.ents[i];
        if !e.live {
            continue;
        }
        let there = if e.kind == 'l' {
            links.contains(&e.id)
        } else {
            bots.iter().any(|b| b.id == e.id)
        };
        if !there {
            ent_event(p, i, false, 0, now);
        }
    }
    let n = p.ents.len();
    for i in 0..n {
        let Some(p) = state.p2.as_mut() else { return };
        let e = p.ents[i].clone();
        if now < e.hold_ms {
            continue;
        }
        if e.kind == 'l' {
            let k = p.me.links.iter().position(|l| *l == e.id);
            if e.live && k.is_none() && p.me.links.len() < P2_MAX_LINKS {
                p.me.links.push(e.id.clone());
                publish(state, skip, "l+", &e.id, 0, now);
            } else if let (false, Some(k)) = (e.live, k) {
                p.me.links.remove(k);
                publish(state, skip, "l-", &e.id, 0, now);
            }
            continue;
        }
        let k = p.me.bots.iter().position(|b| b.id == e.id);
        if e.live && k.is_none_or(|k| p.me.bots[k].since != e.since) {
            match k {
                Some(k) => p.me.bots[k].since = e.since,
                None if p.me.bots.len() >= P2_MAX_BOTS => continue,
                None => p.me.bots.push(P2Bot {
                    id: e.id.clone(),
                    since: e.since,
                }),
            }
            publish(state, skip, "b+", &e.id, e.since, now);
        } else if let (false, Some(k)) = (e.live, k) {
            p.me.bots.remove(k);
            publish(state, skip, "b-", &e.id, 0, now);
        }
    }
    // Forget entities that are gone, published and past their flap window.
    let Some(p) = state.p2.as_mut() else { return };
    let (me_links, me_bots) = (&p.me.links, &p.me.bots);
    p.ents.retain(|e| {
        let listed = if e.kind == 'l' {
            me_links.contains(&e.id)
        } else {
            me_bots.iter().any(|b| b.id == e.id)
        };
        e.live || listed || now < e.hold_ms || now - e.window_ms < P2_FLAP_WINDOW_MS
    });
}

/// Someone claims a version of OUR record above ours (a lost epoch file, a
/// bug, a forged frame): jump above it and flood the truth.  Claims near the
/// limits are ignored, so a heal always stays well inside the sane range.
fn self_claim(state: &mut HubState, e: u64, s: u64) {
    let Some(p) = state.p2.as_mut() else { return };
    if e >= P2_EPOCH_MAX || s >= P2_SEQ_MAX / 2 {
        return;
    }
    if e > p.me.epoch {
        p.me.epoch = e + 1;
        p.me.seq = 0;
        epoch_write(p.me.epoch);
        crate::hlog_warning!(
            "[PRESENCE] a peer holds our record at epoch {e}: boot counter moved to {}\n",
            p.me.epoch
        );
    } else if e == p.me.epoch && s > p.me.seq {
        p.me.seq = s;
    } else {
        return;
    }
    p.me.seq += 1;
    p.dirty = true;
    p.c_heals += 1;
}

/// Unsigned records: a reachable hub moves its epoch by one per boot and its
/// seq by a few thousand at most between our hearing from it.  A relayed
/// claim far above that is a bug or a forgery that would freeze the origin at
/// the ceiling, so it is refused.  The origin on its own link, an unreachable
/// origin (it may have rebooted many times while cut off) and a first
/// sighting pass.
fn jump_refused(state: &mut HubState, from: usize, ri: usize, e: u64, s: u64) -> bool {
    let sender = peer_uuid(state, from);
    let Some(p) = state.p2.as_mut() else {
        return false;
    };
    let r = &p.recs[ri];
    if sender == r.origin || !r.reach || r.epoch == 0 {
        return false;
    }
    if e > r.epoch + P2_EPOCH_JUMP || (e == r.epoch && s > r.seq + P2_SEQ_JUMP) {
        p.c_jumps += 1;
        return true;
    }
    false
}

fn bad(state: &mut HubState) {
    if let Some(p) = state.p2.as_mut() {
        p.c_rx_bad += 1;
    }
}

// ---------- frames ----------

fn rx_snap(state: &mut HubState, from: usize, f: &[&str]) {
    let (Some(e), Some(s), Some(ttl)) = (num_ok(f[2]), num_ok(f[3]), num_ok(f[4])) else {
        return bad(state);
    };
    if !id_ok(f[1]) || ttl > P2_TTL_HOPS || !es_sane(e, s) || e == 0 || f[5].len() > P2_CAPS_MAX {
        return bad(state);
    }
    if !f[5]
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c == b',' || c == b'-')
    {
        return bad(state);
    }
    let mut links: Vec<String> = Vec::new();
    if f[6] != "-" {
        let Some(l) = split(f[6], ',', P2_MAX_LINKS) else {
            return bad(state);
        };
        for x in l {
            if links.iter().any(|k| k == x) || !id_ok(x) {
                return bad(state);
            }
            links.push(x.to_string());
        }
    }
    let mut bots: Vec<P2Bot> = Vec::new();
    if f[7] != "-" {
        let Some(b) = split(f[7], ',', P2_MAX_BOTS) else {
            return bad(state);
        };
        for x in b {
            let Some(kv) = split(x, ':', 2).filter(|kv| kv.len() == 2) else {
                return bad(state);
            };
            let Some(since) = num_ok(kv[1]) else {
                return bad(state);
            };
            if !id_ok(kv[0]) || bots.iter().any(|k| k.id == kv[0]) {
                return bad(state);
            }
            bots.push(P2Bot {
                id: kv[0].to_string(),
                since: since as i64,
            });
        }
    }
    let Some(p) = state.p2.as_mut() else { return };
    if f[1] == p.me.origin {
        return self_claim(state, e, s);
    }
    let Some(ri) = rec_get(p, f[1]) else { return };
    let newer = {
        let r = &p.recs[ri];
        e > r.epoch || (e == r.epoch && s > r.seq)
    };
    if !newer || jump_refused(state, from, ri, e, s) {
        return;
    }
    let Some(p) = state.p2.as_mut() else { return };
    p.stamp_ctr += 1;
    let stamp = p.stamp_ctr;
    let r = &mut p.recs[ri];
    r.caps = if f[5] == "-" {
        String::new()
    } else {
        f[5].to_string()
    };
    r.epoch = e;
    r.seq = s;
    r.links = links;
    r.bots = bots;
    r.stamp = stamp;
    r.rdirty = true;
    // A pulled (ttl 0) record is news to our other peers too: pass it on, so
    // a repair spreads at once instead of one exchange per hop.
    let out_ttl = if ttl == 0 { P2_TTL_HOPS - 1 } else { ttl - 1 };
    let rec = r.clone();
    if out_ttl > 0
        && let Some(frame) = snap_frame(&rec, out_ttl)
    {
        relay(state, &frame, from, &rec.origin, &rec.links);
    }
    // Reconcile now if it is reachable (the walk next tick catches the rest).
    if rec.reach {
        if let Some(p) = state.p2.as_mut() {
            p.recs[ri].rdirty = false;
        }
        crate::presence::p2_reconcile(state, &rec);
    }
}

/// True when (e, s) is new in the record's P2_SEEN_WINDOW-wide window.
fn win_new(r: &mut P2Rec, e: u64, s: u64) -> bool {
    if e != r.win_epoch {
        if e < r.win_epoch {
            return false;
        }
        r.win_epoch = e;
        r.win_top = s;
        r.win_mask = 1;
        return true;
    }
    if s > r.win_top {
        let d = s - r.win_top;
        r.win_mask = if d >= P2_SEEN_WINDOW {
            0
        } else {
            r.win_mask << d
        };
        r.win_mask |= 1;
        r.win_top = s;
        return true;
    }
    let d = r.win_top - s;
    if d >= P2_SEEN_WINDOW || r.win_mask & (1u64 << d) != 0 {
        return false;
    }
    r.win_mask |= 1u64 << d;
    true
}

/// Apply one change; false when it cannot be (a list is full): pull instead.
/// Adding what is there or removing what is not leaves the record as the
/// origin has it.
fn apply(r: &mut P2Rec, op: &str, id: &str, since: i64) -> bool {
    let add = op.as_bytes()[1] == b'+';
    if op.starts_with('l') {
        let k = r.links.iter().position(|l| l == id);
        match (add, k) {
            (true, Some(_)) | (false, None) => {}
            (true, None) if r.links.len() >= P2_MAX_LINKS => return false,
            (true, None) => r.links.push(id.to_string()),
            (false, Some(k)) => {
                r.links.remove(k);
            }
        }
        return true;
    }
    let k = r.bots.iter().position(|b| b.id == id);
    match (add, k) {
        (true, Some(k)) => r.bots[k].since = since,
        (true, None) if r.bots.len() >= P2_MAX_BOTS => return false,
        (true, None) => r.bots.push(P2Bot {
            id: id.to_string(),
            since,
        }),
        (false, Some(k)) => {
            r.bots.remove(k);
        }
        (false, None) => {}
    }
    true
}

/// `D|origin|epoch|seq|ttl|op|id|since`
fn rx_delta(state: &mut HubState, from: usize, f: &[&str]) {
    let (Some(e), Some(s), Some(ttl), Some(since)) =
        (num_ok(f[2]), num_ok(f[3]), num_ok(f[4]), num_ok(f[7]))
    else {
        return bad(state);
    };
    let op_ok = matches!(f[5], "b+" | "b-" | "l+" | "l-");
    if !id_ok(f[1])
        || !(1..=P2_TTL_HOPS).contains(&ttl)
        || !es_sane(e, s)
        || e == 0
        || s == 0
        || !op_ok
        || !id_ok(f[6])
        || (f[5].starts_with('l') && f[6] == f[1])
    {
        return bad(state);
    }
    let Some(p) = state.p2.as_mut() else { return };
    if f[1] == p.me.origin {
        return self_claim(state, e, s);
    }
    let Some(ri) = rec_get(p, f[1]) else { return };
    if jump_refused(state, from, ri, e, s) {
        return;
    }
    let Some(p) = state.p2.as_mut() else { return };
    if !win_new(&mut p.recs[ri], e, s) {
        return;
    }
    let r = &mut p.recs[ri];
    if e < r.epoch || (e == r.epoch && s <= r.seq) {
        return; // stale: a snapshot had it
    }
    let mut applied = false;
    if e == r.epoch && s == r.seq + 1 {
        applied = apply(r, f[5], f[6], since as i64);
    } else if e > r.epoch && s == 1 {
        // A restart: its first change, on an empty record.
        r.epoch = e;
        r.seq = 0;
        r.links.clear();
        r.bots.clear();
        applied = apply(r, f[5], f[6], since as i64);
    }
    if applied {
        p.stamp_ctr += 1;
        let stamp = p.stamp_ctr;
        let r = &mut p.recs[ri];
        r.seq = s;
        r.stamp = stamp;
        r.rdirty = true;
    } else {
        pull(state, ri, from); // a gap (or a full list): fetch the record
    }
    let Some(p) = state.p2.as_ref() else { return };
    let rec = p.recs[ri].clone();
    if ttl > 1 {
        let frame = format!("D|{}|{e}|{s}|{}|{}|{}|{since}", f[1], ttl - 1, f[5], f[6]);
        relay(state, &frame, from, &rec.origin, &rec.links);
    }
    if applied && rec.reach {
        if let Some(p) = state.p2.as_mut() {
            p.recs[ri].rdirty = false;
        }
        crate::presence::p2_reconcile(state, &rec);
    }
}

/// `H|count|hash`: a mismatch with ours asks for the sender's full digest.
fn rx_hash(state: &mut HubState, from: usize, f: &[&str]) {
    let ok = num_ok(f[1]).filter(|c| *c <= (MAX_MESH_HUBS + 1) as u64);
    let hex_ok = f[2].len() == 16
        && f[2]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    let (Some(cnt), true) = (ok, hex_ok) else {
        return bad(state);
    };
    let Some(p) = state.p2.as_mut() else { return };
    let (n, h) = hash(p);
    if n as u64 == cnt && format!("{h:016x}") == f[2] {
        return;
    }
    p.c_digest_miss += 1;
    send_digest(state, from, 'W');
}

/// G / W: pull every origin the sender holds newer.  All entries are checked
/// before any is acted on: a bad digest does nothing.
fn rx_digest(state: &mut HubState, from: usize, list: &str) -> bool {
    let Some(ents) = split(list, ',', MAX_MESH_HUBS + 1) else {
        bad(state);
        return false;
    };
    let mut parsed: Vec<(&str, u64, u64)> = Vec::new();
    for x in ents {
        let kv = split(x, ':', 3).filter(|kv| kv.len() == 3);
        let ok = kv.and_then(|kv| {
            let (e, s) = (num_ok(kv[1])?, num_ok(kv[2])?);
            (id_ok(kv[0]) && es_sane(e, s)).then_some((kv[0], e, s))
        });
        let Some(t) = ok else {
            bad(state);
            return false;
        };
        parsed.push(t);
    }
    for (o, e, s) in parsed {
        let Some(p) = state.p2.as_mut() else {
            return false;
        };
        if o == p.me.origin {
            self_claim(state, e, s);
            continue;
        }
        let Some(ri) = rec_get(p, o) else { continue };
        let newer = {
            let r = &p.recs[ri];
            e > r.epoch || (e == r.epoch && s > r.seq)
        };
        if newer && !jump_refused(state, from, ri, e, s) {
            pull(state, ri, from);
        }
    }
    true
}

pub fn rx(state: &mut HubState, from: usize, payload: &str) {
    if state.p2.is_none() || peer_uuid(state, from).is_empty() {
        return; // not a configured, linked peer
    }
    if let Some(p) = state.p2.as_mut() {
        p.c_rx += 1;
    }
    if payload.len() > P2_MAX_FRAME {
        return bad(state);
    }
    let f: Vec<&str> = payload.splitn(10, '|').collect();
    let n = if f.len() > 9 { usize::MAX } else { f.len() };
    if n == 8 && f[0] == "S" {
        state.clients[from].p2_seen = true;
        rx_snap(state, from, &f);
    } else if n == 8 && f[0] == "D" {
        state.clients[from].p2_seen = true;
        rx_delta(state, from, &f);
    } else if n == 3 && f[0] == "H" {
        rx_hash(state, from, &f);
    } else if n == 2 && f[0] == "G" {
        rx_digest(state, from, f[1]);
    } else if n == 2 && f[0] == "W" {
        if rx_digest(state, from, f[1]) {
            send_digest(state, from, 'G');
        }
    } else if n == 2 && f[0] == "R" {
        if !id_ok(f[1]) {
            return bad(state);
        }
        let Some(p) = state.p2.as_ref() else { return };
        let r = if f[1] == p.me.origin {
            Some(&p.me)
        } else {
            rec_find(p, f[1]).map(|i| &p.recs[i])
        };
        if let Some(frame) = r.filter(|r| r.epoch > 0).and_then(|r| snap_frame(r, 0)) {
            tx(state, from, &frame);
        }
    } else if n == usize::MAX || f[0].len() != 1 {
        bad(state);
    } // else: a tag of a later phase, ignored
}

// ---------- link-up, tick ----------

/// Bumps the boot counter: after the config gave us our uuid.
pub fn init(state: &mut HubState) {
    if state.p2.is_some() {
        return;
    }
    let mut p = Box::<P2State>::default();
    p.me.origin = state.hub_uuid.clone();
    p.me.caps = "rollcall".to_string();
    p.me.epoch = epoch_read() + 1;
    epoch_write(p.me.epoch);
    let now = now_ms();
    // The full round lands half a digest period off the digest ticks.
    p.next_full_ms = now + P2_FULL_EVERY_MS + P2_DIGEST_MS / 2;
    p.next_digest_ms = now + P2_DIGEST_MS;
    p.tokens_milli = P2_BUCKET_BURST * 1000;
    p.bucket_ms = now;
    state.p2 = Some(p);
}

/// A peer link just authenticated: our record (ttl 0, for it alone) and our
/// digest, so each side pulls what the other holds newer, far hubs included.
pub fn link_up(state: &mut HubState, ci: usize) {
    if state.p2.is_none() || peer_uuid(state, ci).is_empty() {
        return;
    }
    refresh_self(state, Some(ci)); // the others hear of this link as a delta
    if let Some(frame) = state.p2.as_ref().and_then(|p| snap_frame(&p.me, 0)) {
        tx(state, ci, &frame);
    }
    send_digest(state, ci, 'G');
}

/// Every hub linked here (a dialled link once it has answered) speaks v2 and
/// every hub in the mesh map has a record: only then may the walk say "gone".
fn ready(state: &HubState) -> bool {
    let Some(p) = state.p2.as_ref() else {
        return false;
    };
    if state
        .clients
        .iter()
        .any(|c| c.typ == ClientType::Hub && c.authenticated && c.peer_heard && !c.p2_seen)
    {
        return false;
    }
    state
        .mesh_hubs
        .iter()
        .all(|h| h.uuid == p.me.origin || rec_find(p, &h.uuid).is_some_and(|i| p.recs[i].epoch > 0))
}

fn reach(p: &mut P2State, now: i64) {
    let mut queue: Vec<String> = Vec::new();
    for l in &p.me.links {
        if queue.len() < MAX_MESH_HUBS * 2 {
            queue.push(l.clone());
        }
    }
    let mut mark = vec![false; p.recs.len()];
    let mut qh = 0;
    while qh < queue.len() {
        let h = queue[qh].clone();
        qh += 1;
        let Some(ri) = rec_find(p, &h) else { continue };
        mark[ri] = true;
        let r = &p.recs[ri];
        for q in &r.links {
            if *q == p.me.origin {
                continue;
            }
            if let Some(qi) = rec_find(p, q) {
                let rq = &p.recs[qi];
                if rq.epoch > 0 && !rq.links.contains(&r.origin) {
                    continue;
                }
            }
            if !queue.contains(q) && queue.len() < MAX_MESH_HUBS * 2 {
                queue.push(q.clone());
            }
        }
    }
    for (i, r) in p.recs.iter_mut().enumerate() {
        if mark[i] {
            if !r.reach {
                r.rdirty = true;
            }
            r.reach = true;
            r.purged = false;
        } else {
            if r.reach || r.gone_ms == 0 {
                r.gone_ms = now;
            }
            r.reach = false;
        }
    }
}

/// Runs from every maintenance pass; the work below needs no finer clock than
/// P2_TICK_MS, so a busy poll loop does not repeat it per event.
pub fn tick(state: &mut HubState) {
    let now = now_ms();
    {
        let Some(p) = state.p2.as_mut() else { return };
        if p.last_tick_ms != 0 && now - p.last_tick_ms < P2_TICK_MS {
            return;
        }
        p.last_tick_ms = now;
    }
    refresh_self(state, None);
    let Some(p) = state.p2.as_mut() else { return };
    if now >= p.next_full_ms {
        p.next_full_ms = now + P2_FULL_EVERY_MS;
        p.me.seq += 1;
        p.dirty = true;
    }
    if p.dirty && now - p.last_flood_ms >= P2_STORM_GAP_MS {
        flood_self(state);
        if let Some(p) = state.p2.as_mut() {
            p.c_snaps += 1;
        }
    }
    let Some(p) = state.p2.as_mut() else { return };
    if now >= p.next_digest_ms {
        p.next_digest_ms = now + P2_DIGEST_MS;
        for (ci, _) in linked(state) {
            send_hash(state, ci);
        }
    }
    let Some(p) = state.p2.as_mut() else { return };
    reach(p, now);
    let rdy = ready(state);
    let Some(p) = state.p2.as_mut() else { return };
    p.ready = rdy;
    let rec_due = now >= p.next_reconcile_ms;
    if rec_due {
        p.next_reconcile_ms = now + P2_RECONCILE_MS;
    }
    for i in 0..p.recs.len() {
        let Some(p) = state.p2.as_ref() else { return };
        let r = p.recs[i].clone();
        if r.epoch == 0 {
            continue;
        }
        if r.reach {
            // Only when its record or its roster entries changed since.
            if rec_due && r.rdirty {
                if let Some(p) = state.p2.as_mut() {
                    p.recs[i].rdirty = false;
                }
                crate::presence::p2_reconcile(state, &r);
            }
        } else if rdy && now - r.gone_ms >= P2_GRACE_MS && (!r.purged || r.rdirty) {
            // Once per outage, and again only if a late frame brought entries
            // of it back (roster_upsert marks rdirty).
            if let Some(p) = state.p2.as_mut() {
                p.recs[i].rdirty = false;
            }
            let n = crate::presence::p2_drop_hub(state, &r.origin);
            if !r.purged && n > 0 {
                crate::hlog_info!(
                    "[PRESENCE] {} unreachable: dropped from the mesh view\n",
                    state.who('h', &r.origin)
                );
                if let Some(p) = state.p2.as_mut() {
                    p.c_purges += 1;
                }
            }
            if let Some(p) = state.p2.as_mut() {
                p.recs[i].purged = true;
            }
        }
    }
}

/// `roster_upsert` touched an entry of `hub_uuid` (C hub_p2_roster_touched):
/// its record is compared with the roster again on the next reconcile pass
/// (P2_RECONCILE_MS), and only then; an idle mesh costs no reconcile work.
pub fn roster_touched(state: &mut HubState, hub_uuid: &str) {
    let Some(p) = state.p2.as_mut() else { return };
    if let Some(i) = rec_find(p, hub_uuid) {
        p.recs[i].rdirty = true;
    }
}

/// For display: a hub the walk cannot reach right now (no grace).
pub fn hub_gone(state: &HubState, uuid: &str) -> bool {
    let Some(p) = state.p2.as_ref() else {
        return false;
    };
    if uuid.is_empty() {
        return false;
    }
    // p.ready: the last tick's ready()
    rec_find(p, uuid).is_some_and(|i| p.recs[i].epoch > 0 && !p.recs[i].reach) && p.ready
}

/// Phase 3: a link whose keepalive is the 15 s digest rather than pings — a
/// connected configured peer that has sent us a v2 record, so both ends run v2
/// and exchange `H` every `P2_DIGEST_MS`.  Its liveness is the digest; it is
/// pinged no more and dropped after `P2_LINK_TIMEOUT` unheard.  A bot, an older
/// peer that has not spoken v2, and an unconfigured inbound hub are not such
/// links and keep today's ping and `CLIENT_TIMEOUT`.  C `hub_p2_digest_keepalive`.
pub fn digest_keepalive(state: &HubState, c: &crate::state::HubClient) -> bool {
    if c.typ != ClientType::Hub || !c.authenticated || !c.p2_seen {
        return false;
    }
    state.peers.iter().any(|pc| pc.connected && pc.fd == c.fd)
}
