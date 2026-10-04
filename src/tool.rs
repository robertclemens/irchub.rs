//! The daemon's process hardening and terminal prompts (setup and the
//! startup password).
//!
//! Secrets are never taken from argv (visible in ps(1) and shell history).
//! Core dumps are disabled before any secret exists, and every secret buffer
//! is zeroized when it goes out of scope.

use std::io::{self, Write};
use std::os::fd::AsFd;

use nix::sys::termios::{LocalFlags, SetArg, Termios, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

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
