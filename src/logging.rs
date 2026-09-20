//! hub_log(): the size-capped, inode-checked HUB_LOG_FILE, and the level
//! filters that gate it.
//!
//! Log arguments routinely carry pre-authentication network input (a claimed
//! bot UUID, a peer name), so every byte an attacker could use to forge or
//! garble the log is made inert: control bytes and invalid UTF-8 become
//! `\xHH`, and a newline inside a message is followed by an indent so it can
//! never start a line that looks like a fresh "[timestamp]" entry.  Only the
//! message's final newline is kept as is.
//!
//! The C hub read the level off the global `g_state`; here the same two
//! fields live in the logger and are pushed to it whenever the config load or
//! an admin command changes them, so every call site stays a plain macro.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::consts::*;

struct LogState {
    /// False until main() has built the hub state — mirrors `g_state` being
    /// NULL, which makes the level macros no-ops but still lets a bare
    /// hub_log() through.
    attached: bool,
    level: i32,
    max_size: i64,
    file: Option<File>,
}

thread_local! {
    static LOG: RefCell<LogState> = const {
        RefCell::new(LogState {
            attached: false,
            level: HUB_DEFAULT_LOG_LEVEL,
            max_size: HUB_LOG_FILE_SIZE,
            file: None,
        })
    };
}

/// Mark the hub state as live (g_state = &state) with its initial settings.
pub fn attach(level: i32, max_size: i64) {
    LOG.with_borrow_mut(|l| {
        l.attached = true;
        l.level = level;
        l.max_size = max_size;
    });
}

pub fn set_level(level: i32) {
    LOG.with_borrow_mut(|l| l.level = level);
}

pub fn set_max_size(max_size: i64) {
    LOG.with_borrow_mut(|l| l.max_size = max_size);
}

/// The level a `hub_log_*` macro tests, or LOG_NONE while g_state is NULL.
pub fn level() -> i32 {
    LOG.with_borrow(|l| if l.attached { l.level } else { LOG_NONE })
}

/// Close the log file (shutdown).
pub fn close() {
    LOG.with_borrow_mut(|l| l.file = None);
}

/// Open HUB_LOG_FILE at 0600.  O_CREAT with an explicit mode rather than a
/// plain append open, so the mode never depends on the caller's umask, and
/// the permissions of a file that already exists with looser ones are
/// tightened — mode only applies on creation.
fn open_log(truncate: bool) -> Option<File> {
    let f = OpenOptions::new()
        .append(!truncate)
        .write(true)
        .create(true)
        .truncate(truncate)
        .mode(0o600)
        .open(HUB_LOG_FILE)
        .ok()?;
    if let Ok(md) = f.metadata()
        && md.mode() & 0o777 != 0o600
    {
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    Some(f)
}

use std::os::unix::fs::PermissionsExt;

fn local_time_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Length of the valid UTF-8 sequence starting at `p`, or 0 when the bytes
/// there are not one (overlong, surrogate, > U+10FFFF, cut short).
fn utf8_len(p: &[u8]) -> usize {
    let (len, min, mut cp) = match p[0] {
        0xC2..=0xDF => (2usize, 0x80u32, u32::from(p[0] & 0x1F)),
        0xE0..=0xEF => (3, 0x800, u32::from(p[0] & 0x0F)),
        0xF0..=0xF4 => (4, 0x10000, u32::from(p[0] & 0x07)),
        _ => return 0,
    };
    if p.len() < len {
        return 0;
    }
    for &b in &p[1..len] {
        if b & 0xC0 != 0x80 {
            return 0;
        }
        cp = (cp << 6) | u32::from(b & 0x3F);
    }
    if cp < min || cp > 0x10FFFF || (0xD800..=0xDFFF).contains(&cp) {
        return 0;
    }
    len
}

/// hub_log_write_sanitized().
fn sanitize(msg: &str) -> String {
    let p = msg.as_bytes();
    let mut out = String::with_capacity(p.len() + 8);
    let mut i = 0;
    while i < p.len() {
        let c = p[i];
        if c == b'\n' {
            out.push('\n');
            if i + 1 < p.len() {
                out.push_str("    ");
            }
            i += 1;
        } else if c == b'\t' || (0x20..0x7F).contains(&c) {
            out.push(c as char);
            i += 1;
        } else if c >= 0x80 {
            let ul = utf8_len(&p[i..]);
            if ul > 0 {
                out.push_str(&msg[i..i + ul]);
                i += ul;
            } else {
                out.push_str(&format!("\\x{c:02X}"));
                i += 1;
            }
        } else {
            out.push_str(&format!("\\x{c:02X}"));
            i += 1;
        }
    }
    out
}

/// hub_log(): one already-formatted message (its trailing newline included,
/// as in the C call sites).
pub fn hub_log(msg: &str) {
    LOG.with_borrow_mut(|l| {
        if l.attached && l.level == LOG_NONE {
            return;
        }
        let time_buf = local_time_str();

        // Does the path still point at the same inode as the open handle?  A
        // plain existence check misses a file that was deleted and recreated:
        // the old handle would go on writing to the unlinked inode while the
        // path belongs to a different file.
        if let Some(f) = &l.file {
            let same = match (std::fs::metadata(HUB_LOG_FILE), f.metadata()) {
                (Ok(p), Ok(h)) => p.ino() == h.ino(),
                _ => false,
            };
            if !same {
                l.file = None;
            }
        }
        if l.file.is_none() {
            l.file = open_log(false);
        }
        let Some(f) = &mut l.file else { return };

        let max_size = if l.max_size > 0 {
            l.max_size
        } else {
            HUB_LOG_FILE_SIZE
        };
        if let Ok(md) = std::fs::metadata(HUB_LOG_FILE)
            && md.len() as i64 >= max_size
        {
            l.file = open_log(true);
            if let Some(f) = &mut l.file {
                let _ = writeln!(f, "[{time_buf}] Log file truncated (size limit reached)");
                let _ = f.flush();
            }
            return;
        }

        let _ = write!(f, "[{time_buf}] {}", sanitize(msg));
        let _ = f.flush();
    });
}

/// hub_log(...) with format!.  The message keeps the caller's trailing
/// newline, exactly as the C format strings carry it.
#[macro_export]
macro_rules! hlog {
    ($($arg:tt)*) => { $crate::logging::hub_log(&format!($($arg)*)) };
}

/// The level-filtered variants (hub_log_error / _warning / _info / _debug).
/// The tag is glued on by the macro, as the C string-literal concatenation
/// did.
#[macro_export]
macro_rules! hlog_error {
    ($($arg:tt)*) => {
        if $crate::logging::level() >= $crate::consts::LOG_ERROR {
            $crate::logging::hub_log(&format!("[ERROR] {}", format!($($arg)*)));
        }
    };
}

#[macro_export]
macro_rules! hlog_warning {
    ($($arg:tt)*) => {
        if $crate::logging::level() >= $crate::consts::LOG_WARNING {
            $crate::logging::hub_log(&format!("[WARNING] {}", format!($($arg)*)));
        }
    };
}

#[macro_export]
macro_rules! hlog_info {
    ($($arg:tt)*) => {
        if $crate::logging::level() >= $crate::consts::LOG_INFO {
            $crate::logging::hub_log(&format!("[INFO] {}", format!($($arg)*)));
        }
    };
}

#[macro_export]
macro_rules! hlog_debug {
    ($($arg:tt)*) => {
        if $crate::logging::level() >= $crate::consts::LOG_DEBUG {
            $crate::logging::hub_log(&format!("[DEBUG] {}", format!($($arg)*)));
        }
    };
}

/// Periodic runtime counters.  Carries its own [STATUS] tag but is gated at
/// LOG_INFO, so it disappears together with the rest of the INFO traffic.
#[macro_export]
macro_rules! hlog_status {
    ($($arg:tt)*) => {
        if $crate::logging::level() >= $crate::consts::LOG_INFO {
            $crate::logging::hub_log(&format!("[STATUS] {}", format!($($arg)*)));
        }
    };
}

/// Record a fatal panic in HUB_LOG_FILE before the process goes down — the
/// job the C hub's crash left to the core dump it deliberately disabled.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let what = info.to_string().replace(['\r', '\n'], " ");
        let cut = crate::cstr::trunc(&what, 400).to_string();
        hub_log(&format!("[FATAL] {cut} - hub terminating.\n"));
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_neutralizes_forged_lines() {
        assert_eq!(sanitize("plain\n"), "plain\n");
        // An embedded newline cannot start a line that looks like an entry.
        assert_eq!(sanitize("a\n[2020] fake\n"), "a\n    [2020] fake\n");
        assert_eq!(sanitize("bell\x07\n"), "bell\\x07\n");
        assert_eq!(sanitize("caf\u{e9}\n"), "caf\u{e9}\n");
        assert_eq!(sanitize("tab\there\n"), "tab\there\n");
    }

    #[test]
    fn utf8_len_rejects_malformed() {
        assert_eq!(utf8_len(&[0xC3, 0xA9]), 2);
        assert_eq!(utf8_len(&[0xC0, 0x80]), 0); // overlong
        assert_eq!(utf8_len(&[0xED, 0xA0, 0x80]), 0); // surrogate
        assert_eq!(utf8_len(&[0xC3]), 0); // cut short
    }
}
