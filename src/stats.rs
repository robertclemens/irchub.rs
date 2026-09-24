//! Traffic counters since start (hub.h `hub_stats_t` / `g_hub_stats`),
//! answered by CMD_ADMIN_STATS.  Monotonic: whoever reads them diffs two
//! snapshots.  One set per process; atomics only so the queue code, which
//! sees a client and not the hub state, can count without `unsafe`.

use std::fmt::Write as _;
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

/// The CMD_ADMIN_STATS reply (format in consts::CMD_ADMIN_STATS), capped at
/// `cap` bytes; opcode rows with no traffic are left out.
pub fn report(uptime: i64, cap: usize) -> String {
    let g = |a: &AtomicU64| a.load(Relaxed);
    let s = &STATS;
    let mut out = format!(
        "stats|up={uptime}\ncfg|sent={}|same={}|lost={}\n\
         sync|frames={}|noop={}|records={}|applied={}\n",
        g(&s.cfg_sent),
        g(&s.cfg_same),
        g(&s.cfg_lost),
        g(&s.sync_frames),
        g(&s.sync_noop),
        g(&s.sync_records),
        g(&s.sync_applied),
    );
    for op in 0..256 {
        let (rf, tf) = (g(&s.rx_frames[op]), g(&s.tx_frames[op]));
        if rf == 0 && tf == 0 {
            continue;
        }
        let mut row = String::new();
        let _ = writeln!(
            row,
            "op|0x{op:02X}|rx={rf}/{}|tx={tf}/{}",
            g(&s.rx_bytes[op]),
            g(&s.tx_bytes[op])
        );
        if out.len() + row.len() >= cap {
            break;
        }
        out.push_str(&row);
    }
    if out.ends_with('\n') {
        out.pop();
    }
    out
}
