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
    /// Full configs queued to a bot.
    cfg_sent: AtomicU64,
    /// Skipped: that bot already has this exact one.
    cfg_same: AtomicU64,
    /// Queued config dropped on lane overflow.
    cfg_lost: AtomicU64,
    /// PEER_SYNC / PEER_BCAST frames processed.
    sync_frames: AtomicU64,
    /// ... of which changed nothing.
    sync_noop: AtomicU64,
    /// Record lines in them.
    sync_records: AtomicU64,
    /// ... of which were new and applied.
    sync_applied: AtomicU64,
}

static STATS: Stats = Stats {
    rx_frames: [const { AtomicU64::new(0) }; 256],
    rx_bytes: [const { AtomicU64::new(0) }; 256],
    tx_frames: [const { AtomicU64::new(0) }; 256],
    tx_bytes: [const { AtomicU64::new(0) }; 256],
    cfg_sent: AtomicU64::new(0),
    cfg_same: AtomicU64::new(0),
    cfg_lost: AtomicU64::new(0),
    sync_frames: AtomicU64::new(0),
    sync_noop: AtomicU64::new(0),
    sync_records: AtomicU64::new(0),
    sync_applied: AtomicU64::new(0),
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

pub fn cfg_sent() {
    STATS.cfg_sent.fetch_add(1, Relaxed);
}

pub fn cfg_same() {
    STATS.cfg_same.fetch_add(1, Relaxed);
}

pub fn cfg_lost() {
    STATS.cfg_lost.fetch_add(1, Relaxed);
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
pub fn report(uptime: i64, r: &mut crate::reply::Reply) {
    let g = |a: &AtomicU64| a.load(Relaxed);
    let s = &STATS;
    r.ok("stats");
    r.kvi("up", uptime);
    r.rec("cfg");
    r.kvu("sent", g(&s.cfg_sent));
    r.kvu("same", g(&s.cfg_same));
    r.kvu("lost", g(&s.cfg_lost));
    r.rec("sync");
    r.kvu("frames", g(&s.sync_frames));
    r.kvu("noop", g(&s.sync_noop));
    r.kvu("records", g(&s.sync_records));
    r.kvu("applied", g(&s.sync_applied));
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
