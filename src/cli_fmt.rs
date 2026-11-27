//! The command-line screens (-setup, -id, -p): one layout for the bot and
//! the hub, byte-identical to cli_fmt.c in the C trees.  Unicode rules and
//! marks, or an ASCII set when the locale is not UTF-8 (LC_ALL, LC_CTYPE,
//! LANG); never ANSI colors, so a pasted or logged screen stays clean.
//!
//! ```text
//!  ircbot 2.5.4 · setup
//!  ────────────────────────────────────────────────────────────────────
//!
//!  1  Config password
//!     password     ········
//!     confirm      ········
//!     ✓ the passwords match
//!
//!  ─ Summary ──────────────────────────────────────────────────────────
//!    mode          hub-managed · 2 hubs
//! ```

use std::io::{self, BufRead, Write};
use std::os::fd::AsFd;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroizing;

/// The rule's width, and where notes wrap.
pub const CLI_W: usize = 72;
/// A step's answer labels.
pub const CLI_LABEL_W: usize = 12;
/// The summary's labels.
pub const CLI_SLABEL_W: usize = 12;

#[derive(Clone, Copy)]
pub enum Glyph {
    Rule,
    Dot,
    Ok,
    Fail,
    More,
    Secret,
}

static EOF: AtomicBool = AtomicBool::new(false);

/// True once a read hit the end of stdin (C: feof(stdin)).
pub fn eof() -> bool {
    EOF.load(Ordering::Relaxed)
}

/// UTF-8 when the first set of LC_ALL, LC_CTYPE, LANG names it (the order
/// the C library uses); setlocale() is never called.
fn utf8() -> bool {
    static U: OnceLock<bool> = OnceLock::new();
    *U.get_or_init(|| {
        let v = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
            .unwrap_or_default();
        let low: String = v.chars().take(63).collect::<String>().to_ascii_lowercase();
        low.contains("utf-8") || low.contains("utf8")
    })
}

pub fn g(g: Glyph) -> &'static str {
    let (u, a) = match g {
        Glyph::Rule => ("\u{2500}", "-"),
        Glyph::Dot => ("\u{00b7}", "-"),
        Glyph::Ok => ("\u{2713}", "ok"),
        Glyph::Fail => ("\u{2717}", "x"),
        Glyph::More => ("\u{2026}", "..."),
        Glyph::Secret => ("\u{00b7}", "*"),
    };
    if utf8() { u } else { a }
}

fn out(s: &str) {
    let mut o = io::stdout();
    let _ = o.write_all(s.as_bytes());
}

fn flush() {
    let _ = io::stdout().flush();
}

pub fn rule() {
    out(&format!(" {}\n", g(Glyph::Rule).repeat(CLI_W)));
}

pub fn header(prog: &str, version: &str, what: &str) {
    out(&format!("\n {prog} {version} {} {what}\n", g(Glyph::Dot)));
    rule();
}

pub fn step(n: i32, title: &str) {
    out(&format!("\n {n}  {title}\n"));
}

/// Text wrapped at CLI_W bytes, indented to the answers' column (the C
/// wrap counts bytes too).
fn wrap(indent: &str, text: &str) {
    let ind = indent.len();
    let p = text.as_bytes();
    let mut i = 0;
    while i < p.len() {
        while i < p.len() && p[i] == b' ' {
            i += 1;
        }
        if i >= p.len() {
            break;
        }
        let room = if CLI_W > ind { CLI_W - ind } else { 20 };
        let (mut take, mut last_space) = (0usize, 0usize);
        while i + take < p.len() && p[i + take] != b'\n' && take < room {
            if p[i + take] == b' ' {
                last_space = take;
            }
            take += 1;
        }
        if i + take < p.len() && p[i + take] != b'\n' && last_space != 0 {
            take = last_space;
        }
        let mut show = take;
        while show > 0 && p[i + show - 1] == b' ' {
            show -= 1; // no trailing blanks
        }
        let mut line = Vec::with_capacity(ind + show + 1);
        line.extend_from_slice(indent.as_bytes());
        line.extend_from_slice(&p[i..i + show]);
        line.push(b'\n');
        let _ = io::stdout().write_all(&line);
        i += take;
        if i < p.len() && p[i] == b'\n' {
            i += 1;
        }
    }
}

pub fn note(text: &str) {
    wrap("    ", text);
}

/// C's "%-*s": pad to `w` bytes (labels are ASCII).
fn pad(s: &str, w: usize) -> String {
    let mut t = s.to_string();
    while t.len() < w {
        t.push(' ');
    }
    t
}

pub fn kv(label: &str, value: &str) {
    out(&format!("    {} {value}\n", pad(label, CLI_LABEL_W)));
}

pub fn ok(text: &str) {
    out(&format!("    {} {text}\n", g(Glyph::Ok)));
}

pub fn err(text: &str) {
    out(&format!("    {} {text}\n", g(Glyph::Fail)));
}

/// One line, its ending dropped, cut to `cap`-1 bytes (C fgets + drain).
fn read_line(cap: usize) -> Zeroizing<String> {
    let mut line = Zeroizing::new(String::with_capacity(4096));
    if io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        EOF.store(true, Ordering::Relaxed);
        return Zeroizing::new(String::new());
    }
    let end = line.find(['\r', '\n']).unwrap_or(line.len());
    let mut cut = end.min(cap.saturating_sub(1));
    while cut > 0 && !line.is_char_boundary(cut) {
        cut -= 1;
    }
    Zeroizing::new(line[..cut].to_string())
}

pub fn ask(label: &str, cap: usize) -> Zeroizing<String> {
    out(&format!("    {} ", pad(label, CLI_LABEL_W)));
    flush();
    read_line(cap)
}

/// No echo; the line then shows a fixed run of dots, never the length.
pub fn ask_secret(label: &str, cap: usize) -> Zeroizing<String> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    out(&format!("    {} ", pad(label, CLI_LABEL_W)));
    flush();
    let stdin = io::stdin();
    let old = tcgetattr(stdin.as_fd()).ok();
    if let Some(o) = &old {
        let mut t = o.clone();
        t.local_flags.remove(LocalFlags::ECHO);
        let _ = tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &t);
    }
    let v = read_line(cap);
    if let Some(o) = &old {
        let _ = tcsetattr(stdin.as_fd(), SetArg::TCSANOW, o);
    }
    out(&format!("{}\n", g(Glyph::Secret).repeat(8)));
    v
}

pub fn ask_yes(label: &str, dflt: bool) -> bool {
    out(&format!(
        "    {label} {} ",
        if dflt { "(Y/n)" } else { "(y/N)" }
    ));
    flush();
    let a = read_line(16);
    match a.as_bytes().first() {
        None => dflt,
        Some(c) => *c == b'y' || *c == b'Y',
    }
}

pub fn summary(title: &str) {
    let used = 3 + title.len() + 1; // " ─ title "
    let n = if CLI_W + 1 > used {
        CLI_W + 1 - used
    } else {
        3
    };
    out(&format!(
        "\n {} {title} {}\n",
        g(Glyph::Rule),
        g(Glyph::Rule).repeat(n)
    ));
}

pub fn skv(label: &str, value: &str) {
    out(&format!("   {} {value}\n", pad(label, CLI_SLABEL_W)));
}

/// "abcdefgh…wxyz=": a long key shortened for a summary line.
pub fn short(s: &str) -> String {
    if s.len() <= 16 {
        s.to_string()
    } else {
        format!("{}{}{}", &s[..8], g(Glyph::More), &s[s.len() - 4..])
    }
}
