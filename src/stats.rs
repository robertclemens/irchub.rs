//! Traffic counters since start (hub.h `hub_stats_t` / `g_hub_stats`),
//! answered by CMD_ADMIN_STATS.  Monotonic: whoever reads them diffs two
//! snapshots.  One set per process; atomics only so the queue code, which
//! sees a client and not the hub state, can count without `unsafe`.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

struct Stats {
    rx_frames: [AtomicU64; 256],
    rx_bytes: [AtomicU64; 256],
    tx_frames: [AtomicU64; 256],
    tx_bytes: [AtomicU64; 256],
    /// Full configs queued to a bot (CMD_CONFIG_DATA), and their bytes.
    cfg_full: AtomicU64,
    cfg_full_bytes: AtomicU64,
    /// Config deltas queued (CMD_CONFIG_DELTA), their bytes, and the
    /// full-text bytes they stood in for.
    cfg_delta: AtomicU64,
    cfg_delta_bytes: AtomicU64,
    cfg_delta_of: AtomicU64,
    /// Skipped: that bot already has this exact one.
    cfg_same: AtomicU64,
    /// Queued config dropped on lane overflow.
    cfg_lost: AtomicU64,
    /// CMD_CONFIG_PULLs served (a bot's hash check).
    cfg_pull: AtomicU64,
    /// Whole bot trees queued (CMD_BOT_TREE), deltas (CMD_BOT_TREE_DELTA),
    /// the same byte counts, and CMD_BOT_TREE_PULLs served.
    tree_full: AtomicU64,
    tree_full_bytes: AtomicU64,
    tree_delta: AtomicU64,
    tree_delta_bytes: AtomicU64,
    tree_delta_of: AtomicU64,
    tree_pull: AtomicU64,
    /// CMD_SERVER_REPORTs taken in (server pool), entries this hub flagged
    /// wrong network, server-order recomputes that changed an order — 2.5.4.
    pool_reports: AtomicU64,
    pool_flagged: AtomicU64,
    pool_orders: AtomicU64,
    /// PEER_SYNC / PEER_BCAST frames processed.
    sync_frames: AtomicU64,
    /// ... of which changed nothing.
    sync_noop: AtomicU64,
    /// Record lines in them.
    sync_records: AtomicU64,
    /// ... of which were new and applied.
    sync_applied: AtomicU64,
    /// CMD_SYNC_DIGEST rounds sent / received / matched, kinds exchanged,
    /// and whole-state fallbacks (stuck or malformed) — 2.5.4.
    sd_tx: AtomicU64,
    sd_rx: AtomicU64,
    sd_match: AtomicU64,
    sd_kinds: AtomicU64,
    sd_full: AtomicU64,
    el_started: AtomicU64,
    el_batched: AtomicU64,
    el_refused: AtomicU64,
    el_ended: AtomicU64,
}

static STATS: Stats = Stats {
    rx_frames: [const { AtomicU64::new(0) }; 256],
    rx_bytes: [const { AtomicU64::new(0) }; 256],
    tx_frames: [const { AtomicU64::new(0) }; 256],
    tx_bytes: [const { AtomicU64::new(0) }; 256],
    cfg_full: AtomicU64::new(0),
    cfg_full_bytes: AtomicU64::new(0),
    cfg_delta: AtomicU64::new(0),
    cfg_delta_bytes: AtomicU64::new(0),
    cfg_delta_of: AtomicU64::new(0),
    cfg_same: AtomicU64::new(0),
    cfg_lost: AtomicU64::new(0),
    cfg_pull: AtomicU64::new(0),
    tree_full: AtomicU64::new(0),
    tree_full_bytes: AtomicU64::new(0),
    tree_delta: AtomicU64::new(0),
    tree_delta_bytes: AtomicU64::new(0),
    tree_delta_of: AtomicU64::new(0),
    tree_pull: AtomicU64::new(0),
    pool_reports: AtomicU64::new(0),
    pool_flagged: AtomicU64::new(0),
    pool_orders: AtomicU64::new(0),
    sync_frames: AtomicU64::new(0),
    sync_noop: AtomicU64::new(0),
    sync_records: AtomicU64::new(0),
    sync_applied: AtomicU64::new(0),
    sd_tx: AtomicU64::new(0),
    sd_rx: AtomicU64::new(0),
    sd_match: AtomicU64::new(0),
    sd_kinds: AtomicU64::new(0),
    sd_full: AtomicU64::new(0),
    el_started: AtomicU64::new(0),
    el_batched: AtomicU64::new(0),
    el_refused: AtomicU64::new(0),
    el_ended: AtomicU64::new(0),
};

/// An authenticated frame this hub decrypted (`wire_len` includes the
/// 4-byte length prefix).
pub fn rx(cmd: u8, wire_len: usize) {
    STATS.rx_frames[cmd as usize].fetch_add(1, Relaxed);
    STATS.rx_bytes[cmd as usize].fetch_add(wire_len as u64, Relaxed);
}

/// A frame sent from an outbound queue.
pub fn tx(cmd: u8, wire_len: usize) {
    STATS.tx_frames[cmd as usize].fetch_add(1, Relaxed);
    STATS.tx_bytes[cmd as usize].fetch_add(wire_len as u64, Relaxed);
}

/// A full config of `bytes` queued.
pub fn cfg_full(bytes: usize) {
    STATS.cfg_full.fetch_add(1, Relaxed);
    STATS.cfg_full_bytes.fetch_add(bytes as u64, Relaxed);
}

/// A config delta of `bytes` queued, standing in for `of` full bytes.
pub fn cfg_delta(bytes: usize, of: usize) {
    STATS.cfg_delta.fetch_add(1, Relaxed);
    STATS.cfg_delta_bytes.fetch_add(bytes as u64, Relaxed);
    STATS.cfg_delta_of.fetch_add(of as u64, Relaxed);
}

pub fn cfg_pull() {
    STATS.cfg_pull.fetch_add(1, Relaxed);
}

/// A whole tree of `bytes` queued.
pub fn tree_full(bytes: usize) {
    STATS.tree_full.fetch_add(1, Relaxed);
    STATS.tree_full_bytes.fetch_add(bytes as u64, Relaxed);
}

/// A tree row delta of `bytes` queued, standing in for `of` whole-tree bytes.
pub fn tree_delta(bytes: usize, of: usize) {
    STATS.tree_delta.fetch_add(1, Relaxed);
    STATS.tree_delta_bytes.fetch_add(bytes as u64, Relaxed);
    STATS.tree_delta_of.fetch_add(of as u64, Relaxed);
}

pub fn tree_pull() {
    STATS.tree_pull.fetch_add(1, Relaxed);
}

pub fn pool_report() {
    STATS.pool_reports.fetch_add(1, Relaxed);
}

pub fn pool_flagged() {
    STATS.pool_flagged.fetch_add(1, Relaxed);
}

pub fn pool_order() {
    STATS.pool_orders.fetch_add(1, Relaxed);
}

/// The server pool's state for the stats `pool` record: live entries,
/// usable ones, flagged ones, bots waiting.
#[derive(Clone, Copy, Debug, Default)]
pub struct PoolCounts {
    pub servers: usize,
    pub usable: usize,
    pub wrongnet: usize,
    pub idle: usize,
}

pub fn cfg_same() {
    STATS.cfg_same.fetch_add(1, Relaxed);
}

pub fn cfg_lost() {
    STATS.cfg_lost.fetch_add(1, Relaxed);
}

pub fn sd_tx() {
    STATS.sd_tx.fetch_add(1, Relaxed);
}

pub fn sd_rx() {
    STATS.sd_rx.fetch_add(1, Relaxed);
}

pub fn sd_match() {
    STATS.sd_match.fetch_add(1, Relaxed);
}

pub fn sd_kinds(n: usize) {
    STATS.sd_kinds.fetch_add(n as u64, Relaxed);
}

pub fn sd_full() {
    STATS.sd_full.fetch_add(1, Relaxed);
}

/// Channel-request elections: a copy taken, an own op that joined a batch,
/// one refused (table full), a relay copy freed by ELECT_END.
pub fn el_started() {
    STATS.el_started.fetch_add(1, Relaxed);
}

pub fn el_batched() {
    STATS.el_batched.fetch_add(1, Relaxed);
}

pub fn el_refused() {
    STATS.el_refused.fetch_add(1, Relaxed);
}

pub fn el_ended() {
    STATS.el_ended.fetch_add(1, Relaxed);
}

pub fn sync_frame() {
    STATS.sync_frames.fetch_add(1, Relaxed);
}

pub fn sync_record() {
    STATS.sync_records.fetch_add(1, Relaxed);
}

/// End of one sync frame: `updates` records applied, or a no-op frame.
pub fn sync_done(updates: u64) {
    if updates > 0 {
        STATS.sync_applied.fetch_add(updates, Relaxed);
    } else {
        STATS.sync_noop.fetch_add(1, Relaxed);
    }
}

/// The CMD_ADMIN_STATS reply as records: ok|stats|up, cfg|, sync|, then
/// one op| per opcode that saw traffic.
/// `load` adds the hub-state records (connections, maintenance timers)
/// between the sync counters and the per-opcode rows.
pub fn report(
    uptime: i64,
    r: &mut crate::reply::Reply,
    pool: PoolCounts,
    el_in_flight: usize,
    load: impl FnOnce(&mut crate::reply::Reply),
) {
    let g = |a: &AtomicU64| a.load(Relaxed);
    let s = &STATS;
    r.ok("stats");
    r.kvi("up", uptime);
    r.rec("cfg");
    r.kvu("full", g(&s.cfg_full));
    r.kvu("full_bytes", g(&s.cfg_full_bytes));
    r.kvu("delta", g(&s.cfg_delta));
    r.kvu("delta_bytes", g(&s.cfg_delta_bytes));
    r.kvu("delta_of", g(&s.cfg_delta_of));
    r.kvu("same", g(&s.cfg_same));
    r.kvu("lost", g(&s.cfg_lost));
    r.kvu("pull", g(&s.cfg_pull));
    r.rec("tree");
    r.kvu("full", g(&s.tree_full));
    r.kvu("full_bytes", g(&s.tree_full_bytes));
    r.kvu("delta", g(&s.tree_delta));
    r.kvu("delta_bytes", g(&s.tree_delta_bytes));
    r.kvu("delta_of", g(&s.tree_delta_of));
    r.kvu("pull", g(&s.tree_pull));
    // server pool: live entries, usable ones, flagged ones, bots waiting
    r.rec("pool");
    r.kvi("servers", pool.servers as i64);
    r.kvi("usable", pool.usable as i64);
    r.kvi("wrongnet", pool.wrongnet as i64);
    r.kvi("idle", pool.idle as i64);
    r.kvu("reports", g(&s.pool_reports));
    r.kvu("flagged", g(&s.pool_flagged));
    r.kvu("orders", g(&s.pool_orders));
    r.rec("elect");
    r.kvi("in_flight", el_in_flight as i64);
    r.kvi("slots", crate::consts::MAX_CHAN_ELECTIONS as i64);
    r.kvu("started", g(&s.el_started));
    r.kvu("batched", g(&s.el_batched));
    r.kvu("refused", g(&s.el_refused));
    r.kvu("ended", g(&s.el_ended));
    r.rec("sync");
    r.kvu("frames", g(&s.sync_frames));
    r.kvu("noop", g(&s.sync_noop));
    r.kvu("records", g(&s.sync_records));
    r.kvu("applied", g(&s.sync_applied));
    r.kvu("digests", g(&s.sd_tx));
    r.kvu("digests_in", g(&s.sd_rx));
    r.kvu("matched", g(&s.sd_match));
    r.kvu("repaired", g(&s.sd_kinds));
    r.kvu("fallbacks", g(&s.sd_full));
    load(r);
    for op in 0..256 {
        let (rf, tf) = (g(&s.rx_frames[op]), g(&s.tx_frames[op]));
        if rf == 0 && tf == 0 {
            continue;
        }
        r.rec("op");
        r.kv("code", &format!("0x{op:02X}"));
        r.kvu("rx_f", rf);
        r.kvu("rx_b", g(&s.rx_bytes[op]));
        r.kvu("tx_f", tf);
        r.kvu("tx_b", g(&s.tx_bytes[op]));
    }
}
