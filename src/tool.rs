//! Helpers shared by the daemon and the `hub_encrypt` / `hub_decrypt` /
//! `keygen` utilities (hub_tool.h).
//!
//! File format and KDF come straight from `consts` so they cannot drift from
//! `config::load` / `config::write`:
//!
//! ```text
//! salt[SALT_SIZE] | iv[GCM_IV_LEN] | tag[GCM_TAG_LEN] | AES-256-GCM ciphertext
//! key = PBKDF2-HMAC-SHA256(password, salt, PBKDF2_ITERATIONS), 32 bytes
//! ```
//!
//! Secrets are never taken from argv (visible in ps(1) and shell history).
//! Core dumps are disabled before any secret exists, and every secret buffer
//! is zeroized when it goes out of scope.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::sys::termios::{LocalFlags, SetArg, Termios, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

use crate::consts::*;

pub const HUB_TOOL_HDR_LEN: usize = SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN;

/// The largest config the hub itself can write: `config::write` sizes its
/// buffer as HUB_CONFIG_FIXED_MAX + bot_count * HUB_CONFIG_PER_BOT_MAX and
/// never writes past it (it refuses rather than truncates), with bot_count <=
/// MAX_BOTS.
pub const HUB_TOOL_MAX_CONFIG: usize = HUB_CONFIG_FIXED_MAX + MAX_BOTS * HUB_CONFIG_PER_BOT_MAX;

/// Process hardening: keep secrets out of anything that lands on disk.
///
/// PR_SET_DUMPABLE(0) suppresses the core dump on a crash.  Without it a
/// crash hands the config password and both hub private keys to
/// core_pattern — on a default Ubuntu host that pipes to systemd-coredump,
/// i.e. straight to disk.  It also blocks same-uid ptrace attach,
/// complementing kernel.yama.ptrace_scope.  RLIMIT_CORE 0 covers the same
/// ground and is inherited across exec.
///
/// Neither defends against root.  Mirrors harden_process() in ircbot.
pub fn harden_process() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    let _ = nix::sys::prctl::set_dumpable(false);
}

/// Restores the terminal when it goes out of scope — including on a panic,
/// which is what stops a crash leaving the user's shell with echo off.
struct EchoGuard {
    saved: Termios,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = tcsetattr(io::stdin().as_fd(), SetArg::TCSAFLUSH, &self.saved);
    }
}

/// Turn echo off on stdin, returning a guard that restores it.  None when
/// stdin is not a terminal.
fn echo_off() -> Option<EchoGuard> {
    let stdin = io::stdin();
    let saved = tcgetattr(stdin.as_fd()).ok()?;
    let mut noecho = saved.clone();
    noecho
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHONL);
    // TCSAFLUSH drops typeahead entered (and echoed) before the prompt.
    tcsetattr(stdin.as_fd(), SetArg::TCSAFLUSH, &noecho).ok()?;
    Some(EchoGuard { saved })
}

/// Ask the OS to interrupt our reads when one of these arrives, so a
/// ^C at the password prompt unwinds through the [`EchoGuard`] instead of
/// killing the process with the terminal still muted.
fn interrupt_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGQUIT,
    ] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&flag));
    }
    flag
}

/// tool_read_password(): read one password line into a wiped buffer.
///
///  - stdin is a terminal: prompt on /dev/tty (stderr as a fallback) with
///    echo off, so stdout stays clean for redirection.
///  - stdin is not a terminal: read the first line of stdin with no prompt —
///    the same convention as `echo <pw> | ./irchub`.
///
/// Fails closed — never truncates — on a password longer than `cap`-1 bytes
/// (the daemon's MAX_PASS buffer), an empty one, or one containing a NUL.
pub fn read_password(prompt: &str, cap: usize) -> Option<Zeroizing<String>> {
    let tty = nix::unistd::isatty(io::stdin().as_fd()).unwrap_or(false);
    let _guard = if tty {
        let g = echo_off();
        // Prompt on /dev/tty so a redirected stdout stays clean.
        match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
            Ok(mut f) => {
                let _ = f.write_all(prompt.as_bytes());
                let _ = f.flush();
            }
            Err(_) => {
                let _ = io::stderr().write_all(prompt.as_bytes());
                let _ = io::stderr().flush();
            }
        }
        g
    } else {
        None
    };
    let flag = if tty { Some(interrupt_flag()) } else { None };

    let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(cap));
    let mut too_long = false;
    let mut has_nul = false;
    let mut io_error = false;
    let mut stdin = io::stdin();
    let mut byte = [0u8; 1];
    loop {
        if flag.as_ref().is_some_and(|f| f.load(Ordering::Relaxed)) {
            io_error = true;
            break;
        }
        match stdin.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if byte[0] == 0 {
                    has_nul = true;
                }
                // Past the cap, keep draining to end of line: whatever is
                // left in a tty line buffer would otherwise be read by the
                // shell as a command.
                if buf.len() + 1 < cap {
                    buf.push(byte[0]);
                } else {
                    too_long = true;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                io_error = true;
                break;
            }
        }
    }

    if tty {
        let _ = writeln!(io::stderr());
    }

    let why = if io_error {
        Some("error reading password".to_string())
    } else if too_long {
        Some(format!("password too long (max {} characters)", cap - 1))
    } else if has_nul {
        Some("password contains a NUL byte".to_string())
    } else if buf.is_empty() {
        Some("empty password".to_string())
    } else {
        None
    };
    if let Some(why) = why {
        eprintln!("Error: {why}.");
        return None;
    }
    Some(Zeroizing::new(String::from_utf8_lossy(&buf).into_owned()))
}

/// read_pass_hidden(): the daemon's prompt.  Prints to stdout, reads one
/// line with echo off, and cuts at `cap`-1 bytes — the C `fgets` shape,
/// which truncates rather than refusing.
pub fn read_pass_hidden(prompt: &str, cap: usize) -> Zeroizing<String> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let _guard = echo_off();
    let mut line = Zeroizing::new(String::new());
    let n = io::stdin().read_line(&mut line).unwrap_or(0);
    println!();
    if n == 0 {
        return Zeroizing::new(String::new());
    }
    let end = line.find('\n').unwrap_or(line.len());
    Zeroizing::new(crate::cstr::trunc_string(&line[..end], cap))
}

/// One line from stdin, without its line ending, cut to `cap`-1 bytes.
pub fn read_line(cap: usize) -> String {
    let mut line = String::new();
    if io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
        return String::new();
    }
    let end = line.find(['\r', '\n']).unwrap_or(line.len());
    crate::cstr::trunc_string(&line[..end], cap)
}

/// A prompt plus [`read_line`].
pub fn prompt_line(prompt: &str, cap: usize) -> String {
    print!("{prompt}");
    let _ = io::stdout().flush();
    read_line(cap)
}

/// tool_read_file(): read a whole regular file of `min_len..=max_len` bytes.
/// The size is checked before anything is allocated.
pub fn read_file(path: &str, min_len: usize, max_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    let md = match std::fs::metadata(path) {
        Ok(md) => md,
        Err(e) => {
            eprintln!("Error: cannot open '{path}': {e}");
            return None;
        }
    };
    if !md.is_file() {
        eprintln!("Error: '{path}' is not a regular file.");
        return None;
    }
    let len = md.len();
    if len < min_len as u64 || len > max_len as u64 {
        eprintln!("Error: '{path}' is {len} bytes; expected {min_len}..{max_len}.");
        return None;
    }
    match std::fs::read(path) {
        Ok(v) if v.len() as u64 == len => Some(Zeroizing::new(v)),
        Ok(_) => {
            eprintln!("Error: short read on '{path}'.");
            None
        }
        Err(e) => {
            eprintln!("Error: reading '{path}': {e}");
            None
        }
    }
}

/// Write `buf` to `path` atomically: a 0600 temp file in the same directory,
/// fsync, rename.  The temp file is removed on any failure.
pub fn write_atomic(path: &str, buf: &[u8]) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{path}.tmp");
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp);
    let mut f = match f {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: cannot create temp file for '{path}': {e}");
            return false;
        }
    };
    let ok = f.write_all(buf).is_ok() && f.flush().is_ok() && f.sync_all().is_ok();
    drop(f);
    if ok && std::fs::rename(&tmp, path).is_ok() {
        return true;
    }
    eprintln!("Error: writing '{path}'.");
    let _ = std::fs::remove_file(&tmp);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_config_bounds_track_the_hub() {
        assert_eq!(HUB_TOOL_HDR_LEN, 16 + 12 + 16);
        // The tool must be able to read the largest config the hub can write.
        assert_eq!(
            HUB_TOOL_MAX_CONFIG,
            HUB_CONFIG_FIXED_MAX + MAX_BOTS * HUB_CONFIG_PER_BOT_MAX
        );
    }
}
