//! SSH admin console — one session's user interface.  docs/console.md;
//! mirrors irchub `hub_console_ui.c` function for function.
//!
//! Runs on the console thread only.  Everything the admin sees is built here:
//! the line-mode transcript (TERM=dumb, the testnet's interface — byte for
//! byte the same as the C hub's) and the full-screen irssi-style console
//! (output pane, network tree, status bar, input line), with the key parser,
//! the command language and the sanitizer that keeps text from bots, peers
//! and logs from reaching the terminal as escape sequences.  Pure state
//! machine: no russh, no HubState.

use crate::consts::*;

/// Bytes waiting for the terminal above this: line mode drops events and log
/// lines (and says so), the full-screen console skips redraws.
pub const CONSOLE_TERM_OUTQ_MAX: usize = 256 * 1024;
const CONSOLE_SCROLLBACK: usize = 2000;
const CONSOLE_LOG_SCROLLBACK: usize = 5000;
const CONSOLE_HISTORY: usize = 100;
const CONSOLE_INPUT_MAX: usize = 1024;
const CONSOLE_ESC_MS: i64 = 50;
const CONSOLE_RESIZE_MS: i64 = 50;
const CONSOLE_MIN_COLS: i32 = 40;
const CONSOLE_MIN_ROWS: i32 = 10;
const CONSOLE_PANE_MIN_COLS: i32 = 80;
const CONSOLE_PANE_MIN: i32 = 24;
const CONSOLE_PANE_MAX: i32 = 40;
const CONSOLE_STATS_REFRESH_MS: i64 = 5000;
const CONSOLE_UPG_REFRESH_MS: i64 = 10000;

// ===========================================================================
// Text: UTF-8, display width, sanitizer (docs/console.md §5)
// ===========================================================================

/// Length of the valid UTF-8 sequence at p, 0 if none.
pub fn utf8_len(p: &[u8]) -> usize {
    let Some(&b0) = p.first() else { return 0 };
    if b0 < 0x80 {
        return 1;
    }
    let (len, min, mut cp) = match b0 {
        0xC2..=0xDF => (2usize, 0x80u32, u32::from(b0 & 0x1F)),
        0xE0..=0xEF => (3, 0x800, u32::from(b0 & 0x0F)),
        0xF0..=0xF4 => (4, 0x10000, u32::from(b0 & 0x07)),
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

fn utf8_cp(p: &[u8], len: usize) -> u32 {
    if len == 1 {
        return u32::from(p[0]);
    }
    let mask = match len {
        2 => 0x1F,
        3 => 0x0F,
        _ => 0x07,
    };
    let mut cp = u32::from(p[0] & mask);
    for &b in &p[1..len] {
        cp = (cp << 6) | u32::from(b & 0x3F);
    }
    cp
}

/// docs/console.md §5: control bytes dropped (TAB -> space), invalid UTF-8 ->
/// '?', C1 controls dropped.  At most `cap - 1` bytes out, never a split
/// character — the C `console_sanitize(in, n, out, cap)`.
pub fn sanitize(input: &[u8], cap: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().min(cap));
    if cap == 0 {
        return out;
    }
    let mut i = 0;
    while i < input.len() && out.len() + 1 < cap {
        let c = input[i];
        if c == b'\t' {
            out.push(b' ');
            i += 1;
        } else if c < 0x20 || c == 0x7f {
            i += 1;
        } else if c < 0x80 {
            out.push(c);
            i += 1;
        } else {
            let ul = utf8_len(&input[i..]);
            if ul == 0 {
                out.push(b'?');
                i += 1;
                continue;
            }
            let cp = utf8_cp(&input[i..], ul);
            if (0x80..=0x9F).contains(&cp) {
                i += ul;
                continue;
            }
            if out.len() + ul >= cap {
                break;
            }
            out.extend_from_slice(&input[i..i + ul]);
            i += ul;
        }
    }
    out
}

/// Terminal cells a code point takes: 0 for combining marks, 2 for the wide
/// East Asian ranges and emoji, else 1.  Mirrors cp_width in C.
fn cp_width(cp: u32) -> i32 {
    if (0x0300..=0x036F).contains(&cp) {
        return 0;
    }
    if cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFE0F {
        return 0;
    }
    if (0x1100..=0x115F).contains(&cp)
        || (0x2E80..=0xA4CF).contains(&cp)
        || (0xAC00..=0xD7A3).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0xFE30..=0xFE4F).contains(&cp)
        || (0xFF00..=0xFF60).contains(&cp)
        || (0xFFE0..=0xFFE6).contains(&cp)
        || (0x1F300..=0x1F64F).contains(&cp)
        || (0x1F900..=0x1F9FF).contains(&cp)
        || (0x20000..=0x3FFFD).contains(&cp)
    {
        return 2;
    }
    1
}

/// Next character of an already-sanitized string: (bytes, code point, cells).
fn next_char(s: &[u8]) -> (usize, u32, i32) {
    let mut ul = utf8_len(s);
    if ul == 0 {
        ul = 1;
    }
    let cp = utf8_cp(s, ul);
    (ul, cp, cp_width(cp))
}

fn str_width(s: &[u8]) -> i32 {
    let mut w = 0;
    let mut i = 0;
    while i < s.len() {
        let (ul, _, cw) = next_char(&s[i..]);
        w += cw;
        i += ul;
    }
    w
}

/// End offset of the segment of `s` (from `start`) that fits in `width`
/// cells (hard wrap).  Always advances by at least one character.
fn wrap_end(s: &[u8], start: usize, width: i32) -> usize {
    let mut w = 0;
    let mut i = start;
    while i < s.len() {
        let (ul, _, cw) = next_char(&s[i..]);
        if w + cw > width && i > start {
            break;
        }
        w += cw;
        i += ul;
    }
    i
}

fn wrap_rows(s: &[u8], width: i32) -> i32 {
    if s.is_empty() || width <= 0 {
        return 1;
    }
    let mut rows = 0;
    let mut i = 0;
    while i < s.len() {
        i = wrap_end(s, i, width);
        rows += 1;
    }
    rows
}

/// Case-insensitive (ASCII) substring test.
fn ci_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// What the C UI's usnprintf(buf, cap, "%s", s) keeps: the first cap-1
/// bytes, backed off so no UTF-8 character is split.
fn c_cut(s: &[u8], cap: usize) -> &[u8] {
    let n = s.len().min(cap.saturating_sub(1));
    if n < s.len() { &s[..utf8_cut(s, n)] } else { s }
}

/// Where a cut of s[..len] must end so no UTF-8 character is split: len, or
/// the start of a trailing lead byte whose sequence runs past len — the C
/// `utf8_cut`, the same walk.
fn utf8_cut(s: &[u8], len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let mut i = len - 1;
    let mut back = 0;
    while i > 0 && back < 3 && s[i] & 0xC0 == 0x80 {
        i -= 1;
        back += 1;
    }
    let need = match s[i] {
        0xF0..=0xF7 => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    };
    if i + need > len { i } else { len }
}

/// A field copied into a C char[cap]: at most cap-1 bytes, never splitting a
/// UTF-8 character — the C `copy_field`.
fn cut_field(s: &[u8], cap: usize) -> &[u8] {
    let max = cap.saturating_sub(1);
    let mut o = 0;
    while o < s.len() {
        let ul = utf8_len(&s[o..]).max(1);
        if o + ul > max {
            break;
        }
        o += ul;
    }
    &s[..o]
}

/// `%-Ns`: s, then spaces up to n bytes (C pads by bytes, not characters).
fn pad_bytes(s: &[u8], n: usize) -> Vec<u8> {
    let mut v = s.to_vec();
    if v.len() < n {
        v.resize(n, b' ');
    }
    v
}

fn eq_ic(a: &[u8], b: &str) -> bool {
    a.eq_ignore_ascii_case(b.as_bytes())
}

fn fmtb(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

// ===========================================================================
// Scrollback: a ring of sanitized lines, each with a colour class
// ===========================================================================
const L_NORMAL: u8 = 0;
const L_CMD: u8 = 1;
const L_ERR: u8 = 2;
#[allow(dead_code)]
const L_OK: u8 = 3;
const L_INFO: u8 = 4;
const L_WARN: u8 = 5;
const L_DIM: u8 = 6;

#[derive(Clone)]
struct SLine {
    text: Vec<u8>,
    kind: u8,
    level: i32,
}

struct Sback {
    v: Vec<Option<SLine>>,
    first: i64,
    next: i64,
}

impl Sback {
    fn new(cap: usize) -> Sback {
        Sback {
            v: vec![None; cap],
            first: 0,
            next: 0,
        }
    }

    fn cap(&self) -> i64 {
        self.v.len() as i64
    }

    fn add(&mut self, text: &[u8], kind: u8, level: i32) {
        if self.v.is_empty() {
            return;
        }
        let slot = (self.next % self.cap()) as usize;
        self.v[slot] = Some(SLine {
            text: text.to_vec(),
            kind,
            level,
        });
        self.next += 1;
        if self.next - self.first > self.cap() {
            self.first = self.next - self.cap();
        }
    }

    fn get(&self, seq: i64) -> Option<&SLine> {
        if seq < self.first || seq >= self.next || self.v.is_empty() {
            return None;
        }
        self.v[(seq % self.cap()) as usize].as_ref()
    }

    fn clear(&mut self) {
        self.v.fill(None);
        self.first = self.next;
    }
}

// ===========================================================================
// Key parser
// ===========================================================================
#[derive(Clone, Copy, PartialEq, Eq)]
enum K {
    None,
    Char,
    Enter,
    Bs,
    Tab,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PgUp,
    PgDn,
    Del,
    Esc,
    F,
    Alt,
    AltLeft,
    AltRight,
    Ctrl,
    PasteBegin,
    PasteEnd,
}

#[derive(Clone, Copy)]
struct Key {
    t: K,
    cp: u32,
}

fn key(t: K, cp: u32) -> Key {
    Key { t, cp }
}

/// Decode one CSI / SS3 sequence (without the leading ESC).  The xterm,
/// PuTTY, linux-console, rxvt and tmux spellings of the same key all land on
/// the same Key.
fn decode_seq(s: &[u8]) -> Key {
    let n = s.len();
    let mut k = key(K::None, 0);
    if n >= 2 && s[0] == b'O' {
        k = match s[1] {
            b'A' => key(K::Up, 0),
            b'B' => key(K::Down, 0),
            b'C' => key(K::Right, 0),
            b'D' => key(K::Left, 0),
            b'H' => key(K::Home, 0),
            b'F' => key(K::End, 0),
            b'P' => key(K::F, 1),
            b'Q' => key(K::F, 2),
            b'R' => key(K::F, 3),
            b'S' => key(K::F, 4),
            b'M' => key(K::Enter, 0),
            _ => k,
        };
        return k;
    }
    if n < 2 || s[0] != b'[' {
        return k;
    }
    if n == 3 && s[1] == b'[' {
        if (b'A'..=b'E').contains(&s[2]) {
            k = key(K::F, u32::from(s[2] - b'A' + 1));
        }
        return k;
    }
    let fin = s[n - 1];
    let (mut p1, mut p2, mut which) = (0i32, 0i32, 0);
    for &c in &s[1..n - 1] {
        if c.is_ascii_digit() {
            let p = if which == 1 { &mut p2 } else { &mut p1 };
            if *p < 1000 {
                *p = *p * 10 + i32::from(c - b'0');
            }
        } else if c == b';' {
            which = 1;
        }
    }
    let alt = p2 == 3 || p2 == 4;
    match fin {
        b'A' => k = key(K::Up, 0),
        b'B' => k = key(K::Down, 0),
        b'C' => k = key(if alt { K::AltRight } else { K::Right }, 0),
        b'D' => k = key(if alt { K::AltLeft } else { K::Left }, 0),
        b'H' => k = key(K::Home, 0),
        b'F' => k = key(K::End, 0),
        b'P' => k = key(K::F, 1),
        b'Q' => k = key(K::F, 2),
        b'R' => k = key(K::F, 3),
        b'S' => k = key(K::F, 4),
        b'~' => {
            k = match p1 {
                1 | 7 => key(K::Home, 0),
                4 | 8 => key(K::End, 0),
                3 => key(K::Del, 0),
                5 => key(K::PgUp, 0),
                6 => key(K::PgDn, 0),
                11..=15 => key(K::F, (p1 - 10) as u32),
                17..=21 => key(K::F, (p1 - 11) as u32),
                23 | 24 => key(K::F, (p1 - 12) as u32),
                200 => key(K::PasteBegin, 0),
                201 => key(K::PasteEnd, 0),
                _ => k,
            }
        }
        _ => {}
    }
    k
}

/// Length of a complete escape sequence at s (s[0] == ESC), 0 if it is not
/// complete yet, -1 if it can never be one (then ESC stands alone).
fn seq_complete(s: &[u8]) -> i32 {
    let n = s.len();
    if n < 2 {
        return 0;
    }
    if s[1] == b'[' {
        if n >= 3 && s[2] == b'[' {
            return if n >= 4 { 4 } else { 0 };
        }
        for (i, &c) in s.iter().enumerate().skip(2) {
            if (0x40..=0x7e).contains(&c) {
                return i as i32 + 1;
            }
            if i > 16 {
                return -1;
            }
        }
        return 0;
    }
    if s[1] == b'O' {
        return if n >= 3 { 3 } else { 0 };
    }
    2
}

// ===========================================================================
// Session state
// ===========================================================================
const V_CONSOLE: usize = 0;
const V_LOG: usize = 1;
const V_NET: usize = 2;
const V_UPG: usize = 3;
const V_STATS: usize = 4;
const V_COUNT: usize = 5;
const VIEW_NAME: [&str; V_COUNT] = ["console", "log", "network", "upgrades", "stats"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirm {
    None,
    Yn,
    TypeArg,
    TypeHub,
    TypeVer,
}

/// What a request in flight was for: replies come back in order.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rq {
    User,
    ViewUpg,
    ViewStats,
}

#[derive(Clone)]
struct PendingRq {
    kind: Rq,
    seq: i32,
    words: Vec<u8>,
    audit: Vec<u8>,
    audit_level: i32,
}

const MAX_PENDING_RQ: usize = 16;
const MAX_QUEUED_LINES: usize = 256;
const MAX_AUDIT: usize = 16;

#[derive(Clone, Default)]
struct Status {
    name: Vec<u8>,
    peers_up: i32,
    peers_total: i32,
    bots_on: i32,
    bots_total: i32,
    upg: Vec<u8>,
    frozen: bool,
    rollup: bool,
    split: bool,
    loglevel: i32,
    consolelevel: i32,
    have: bool,
}

pub struct Ui {
    line_mode: bool,
    ascii: bool,
    cols: i32,
    rows: i32,
    admin: Vec<u8>,
    ip: Vec<u8>,
    hubname: Vec<u8>,
    term: Vec<u8>,
    core: Vec<u8>,
    /// Bytes handed to the SSH writer and not yet sent (the Rust session
    /// drains `term` into a writer task; this keeps the C backlog checks).
    pub backlog: usize,

    input: Vec<u8>,
    in_cur: usize,
    in_scroll: i32,
    hist: Vec<Vec<u8>>,
    hist_pos: usize,
    hist_stash: Vec<u8>,

    esc: Vec<u8>,
    esc_ms: i64,
    pasting: bool,
    utf8: Vec<u8>,
    last_cr: bool,

    seq: i32,
    user_busy: bool,
    rq: Vec<PendingRq>,
    queued: Vec<Vec<u8>>,
    confirming: Confirm,
    confirm_seq: i32,
    confirm_want: Vec<u8>,
    confirm_q: Vec<u8>,
    confirm_op: u8,
    confirm_payload: Vec<u8>,
    confirm_rq: Option<PendingRq>,
    held: Vec<u8>,
    dropped: u64,

    st: Status,
    tree: Vec<u8>,
    upg_text: Option<Vec<u8>>,
    stats_text: Option<Vec<u8>>,
    upg_at: i64,
    stats_at: i64,
    log_on: bool,
    log_sub_level: i32,

    view: usize,
    sb: [Option<Sback>; V_COUNT],
    anchor: [i64; V_COUNT],
    act: [bool; V_COUNT],
    pane_user_off: bool,
    overlay: bool,
    log_show: i32,
    filter: Vec<u8>,
    paused: bool,
    paused_next: i64,
    search: Vec<u8>,
    searching: bool,
    net_sel: i32,
    prev_rows: Vec<Option<Vec<u8>>>,
    dirty: bool,
    full_redraw: bool,
    resize_ms: i64,
    last_draw_ms: i64,
    last_clock_ms: i64,
    last_input_ms: i64,
    started: bool,

    audit_q: Vec<(i32, Vec<u8>)>,

    closing: bool,
    close_why: String,
}

// ===========================================================================
// Command table (docs/console.md §2)
// ===========================================================================
#[derive(Clone, Copy, PartialEq, Eq)]
enum B {
    None,
    Arg,
    OptArg,
    Pipe,
    Colon,
    PeerAdd,
    ChanAdd,
    OptSet,
    LogLevel,
    LogSize,
    Purge,
    UpgReleases,
    UpgStart,
    Fixed,
    Local,
}

struct CmdDef {
    cmd: &'static str,
    sub: Option<&'static str>,
    op: u8,
    build: B,
    nargs: usize,
    optargs: usize,
    confirm: Confirm,
    fixed: &'static str,
    usage: &'static str,
    help: &'static str,
}

macro_rules! cmd {
    ($c:expr, $s:expr, $op:expr, $b:expr, $n:expr, $o:expr, $cf:expr, $fx:expr, $u:expr, $h:expr) => {
        CmdDef {
            cmd: $c,
            sub: $s,
            op: $op,
            build: $b,
            nargs: $n,
            optargs: $o,
            confirm: $cf,
            fixed: $fx,
            usage: $u,
            help: $h,
        }
    };
}

use Confirm as Cf;
#[rustfmt::skip]
const CMDS: &[CmdDef] = &[
    cmd!("help", None, 0, B::Local, 0, 1, Cf::None, "", "help [command]", "list commands, or show one"),
    cmd!("quit", None, 0, B::Local, 0, 0, Cf::None, "", "quit", "close this console"),
    cmd!("bot", Some("list"), CMD_ADMIN_LIST_FULL, B::None, 0, 0, Cf::None, "", "bot list", "every bot the hub knows, with its fields"),
    cmd!("bot", Some("summary"), CMD_ADMIN_LIST_SUMMARY, B::None, 0, 0, Cf::None, "", "bot summary", "bots, one line each"),
    cmd!("bot", Some("pending"), CMD_ADMIN_GET_PENDING, B::None, 0, 0, Cf::None, "", "bot pending", "bots waiting for approval"),
    cmd!("bot", Some("approve"), CMD_ADMIN_APPROVE, B::Arg, 1, 0, Cf::None, "", "bot approve <index|uuid>", "approve a pending bot"),
    cmd!("bot", Some("authorize"), CMD_ADMIN_ADD, B::Arg, 1, 0, Cf::None, "", "bot authorize <uuid>", "authorize a bot uuid"),
    cmd!("bot", Some("add"), CMD_ADMIN_CREATE_BOT, B::Pipe, 3, 0, Cf::None, "", "bot add <nick> <uuid> <pubkey>", "register a bot by the identity its setup printed"),
    cmd!("bot", Some("del"), CMD_ADMIN_DEL, B::Arg, 1, 0, Cf::Yn, "", "bot del <uuid>", "delete a bot (disconnects it)"),
    cmd!("bot", Some("kick"), CMD_ADMIN_DISCONNECT_BOT, B::Arg, 1, 0, Cf::Yn, "", "bot kick <uuid>", "disconnect a bot"),
    cmd!("bot", Some("rekey"), CMD_ADMIN_REKEY_BOT, B::Arg, 1, 0, Cf::None, "", "bot rekey <uuid>", "how to rekey a bot"),
    cmd!("peer", Some("list"), CMD_ADMIN_LIST_PEERS, B::None, 0, 0, Cf::None, "", "peer list", "peer hubs and the mesh matrix"),
    cmd!("peer", Some("add"), CMD_ADMIN_ADD_PEER, B::PeerAdd, 5, 0, Cf::None, "", "peer add <ip> <port> <uuid> <name|-> <pubkey>", "add a peer hub"),
    cmd!("peer", Some("del"), CMD_ADMIN_DEL_PEER, B::OptArg, 0, 1, Cf::TypeArg, "", "peer del [index]", "remove a peer hub (no index: list the configured peers)"),
    cmd!("peer", Some("setkey"), CMD_ADMIN_SET_PEER_PUBKEY, B::Colon, 2, 0, Cf::None, "", "peer setkey <uuid> <pubkey>", "set a peer's public key"),
    cmd!("peer", Some("sync"), CMD_ADMIN_SYNC_MESH, B::None, 0, 0, Cf::None, "", "peer sync", "send a full sync to every peer"),
    cmd!("hub", Some("pubkey"), CMD_ADMIN_GET_PUBKEY, B::None, 0, 0, Cf::None, "", "hub pubkey", "this hub's public key"),
    cmd!("hub", Some("setpub"), CMD_ADMIN_SET_PUBKEY, B::Arg, 1, 0, Cf::None, "", "hub setpub <pubkey>", "re-store the public key (must match the private key)"),
    cmd!("hub", Some("rekey"), CMD_ADMIN_REGEN_KEYS, B::None, 0, 0, Cf::TypeHub, "", "hub rekey", "new hub keypair; every peer and bot must re-learn it"),
    cmd!("hub", Some("name"), CMD_ADMIN_SET_HUB_NAME, B::Arg, 1, 0, Cf::None, "", "hub name <name>", "set this hub's name"),
    cmd!("hub", Some("bindip"), CMD_ADMIN_SET_BIND_IP, B::Arg, 1, 0, Cf::None, "", "hub bindip <ip>", "set the bind address (restart)"),
    cmd!("hub", Some("port"), CMD_ADMIN_SET_BIND_PORT, B::Arg, 1, 0, Cf::None, "", "hub port <port>", "set the listening port (restart)"),
    cmd!("hub", Some("logsize"), CMD_ADMIN_SET_LOG_SIZE, B::LogSize, 1, 0, Cf::None, "", "hub logsize <MB|nk|nb>", "log file size limit (MB, or k/b suffix), at most 1024 MB"),
    cmd!("hub", Some("purge"), CMD_ADMIN_PURGE_TOMBSTONES, B::Purge, 1, 0, Cf::Yn, "", "hub purge <now|days>", "purge tombstones now, or older than <days>"),
    cmd!("hub", Some("autopurge"), CMD_ADMIN_SET_PURGE_DAYS, B::Arg, 1, 0, Cf::None, "", "hub autopurge <days>", "daily purge of tombstones older than <days> (0 = off)"),
    cmd!("loglevel", None, CMD_ADMIN_SET_LOG_LEVEL, B::LogLevel, 1, 1, Cf::Yn, "", "loglevel [file|console] <none|error|warning|info|debug>", "set the log file's (default) or the console log's level"),
    cmd!("stats", None, CMD_ADMIN_STATS, B::None, 0, 0, Cf::None, "", "stats", "traffic counters since the hub started"),
    cmd!("allow", Some("list"), CMD_ADMIN_LIST_ALLOWLIST, B::None, 0, 0, Cf::None, "", "allow list", "the IP allowlist"),
    cmd!("allow", Some("add"), CMD_ADMIN_ADD_ALLOWLIST, B::Arg, 1, 0, Cf::None, "", "allow add <ip[/n]>", "add to the allowlist"),
    cmd!("allow", Some("del"), CMD_ADMIN_DEL_ALLOWLIST, B::Arg, 1, 0, Cf::Yn, "", "allow del <ip[/n]>", "remove from the allowlist"),
    cmd!("deny", Some("list"), CMD_ADMIN_LIST_DENYLIST, B::None, 0, 0, Cf::None, "", "deny list", "the IP denylist"),
    cmd!("deny", Some("add"), CMD_ADMIN_ADD_DENYLIST, B::Arg, 1, 0, Cf::None, "", "deny add <ip[/n]>", "add to the denylist"),
    cmd!("deny", Some("del"), CMD_ADMIN_DEL_DENYLIST, B::Arg, 1, 0, Cf::Yn, "", "deny del <ip[/n]>", "remove from the denylist"),
    cmd!("opt", Some("set"), CMD_ADMIN_SET_OPT_FLAGS, B::OptSet, 1, 0, Cf::Yn, "", "opt set <flags|->", "set the network opt flags (- clears)"),
    cmd!("opt", None, CMD_ADMIN_GET_OPT_FLAGS, B::None, 0, 0, Cf::None, "", "opt", "the network opt flags"),
    cmd!("admin", Some("list"), CMD_ADMIN_LIST_ADMINS, B::None, 0, 0, Cf::None, "", "admin list", "admin records"),
    cmd!("admin", Some("add"), CMD_ADMIN_ADD_ADMIN, B::Pipe, 3, 0, Cf::None, "", "admin add <name> <pubkey> <mask>", "add an admin"),
    cmd!("admin", Some("del"), CMD_ADMIN_DEL_ADMIN, B::Arg, 1, 0, Cf::TypeArg, "", "admin del <name>", "remove an admin and their masks"),
    cmd!("oper", Some("list"), CMD_ADMIN_LIST_OPERS_V2, B::None, 0, 0, Cf::None, "", "oper list", "oper records"),
    cmd!("oper", Some("add"), CMD_ADMIN_ADD_OPER_RECORD, B::Pipe, 3, 0, Cf::None, "", "oper add <name> <pubkey> <mask>", "add an oper"),
    cmd!("oper", Some("del"), CMD_ADMIN_DEL_OPER_RECORD, B::Arg, 1, 0, Cf::Yn, "", "oper del <name>", "remove an oper and their masks"),
    cmd!("mask", Some("add"), CMD_ADMIN_ADD_USERMASK, B::Pipe, 2, 0, Cf::None, "", "mask add <name> <mask>", "add a usermask to an admin or oper"),
    cmd!("mask", Some("del"), CMD_ADMIN_DEL_USERMASK, B::Pipe, 2, 0, Cf::Yn, "", "mask del <name> <mask>", "remove a usermask"),
    cmd!("userkey", None, CMD_ADMIN_SET_USERKEY, B::Pipe, 2, 0, Cf::Yn, "", "userkey <name> <pubkey>", "replace an admin's or oper's key"),
    cmd!("match", None, CMD_ADMIN_MATCH, B::Arg, 1, 0, Cf::None, "", "match <name|*>", "a user's records, or everyone's"),
    cmd!("chan", Some("list"), CMD_ADMIN_LIST_CHANNELS, B::None, 0, 0, Cf::None, "", "chan list", "managed channels"),
    cmd!("chan", Some("add"), CMD_ADMIN_ADD_CHANNEL, B::ChanAdd, 1, 1, Cf::None, "", "chan add <#chan> [key]", "add a channel"),
    cmd!("chan", Some("del"), CMD_ADMIN_DEL_CHANNEL, B::Arg, 1, 0, Cf::Yn, "", "chan del <#chan>", "remove a channel from every bot"),
    cmd!("op", None, CMD_ADMIN_OP_USER, B::Pipe, 2, 0, Cf::None, "", "op <nick> <#chan>", "have the bots op a user"),
    cmd!("upgrade", Some("status"), CMD_ADMIN_UPGRADE_STATUS, B::Fixed, 0, 0, Cf::None, "", "upgrade status", "the upgrade run on this hub"),
    cmd!("upgrade", Some("releases"), CMD_ADMIN_UPGRADE_STATUS, B::UpgReleases, 0, 2, Cf::None, "", "upgrade releases [bot=<base>] [hub=<base>]", "releases both products offer, and the nodes"),
    cmd!("upgrade", Some("start"), CMD_ADMIN_UPGRADE_NET, B::UpgStart, 1, 4, Cf::TypeVer, "", "upgrade start <botver> [hub=<ver>] [nodes=<a,b=c>] [botbase=<url>] [hubbase=<url>]", "start a rolling network upgrade"),
    cmd!("upgrade", Some("abort"), CMD_ADMIN_UPGRADE_STATUS, B::Fixed, 0, 0, Cf::Yn, "abort", "upgrade abort", "stop the run and roll back"),
    cmd!("upgrade", Some("forget"), CMD_ADMIN_UPGRADE_STATUS, B::Fixed, 0, 0, Cf::Yn, "forget", "upgrade forget", "drop the roll-up plan on every hub"),
    cmd!("tree", None, CMD_CONSOLE, B::Fixed, 0, 0, Cf::None, "get|tree", "tree", "the network tree rows"),
    cmd!("status", None, CMD_CONSOLE, B::Fixed, 0, 0, Cf::None, "get|status", "status", "the status fields"),
    cmd!("log", Some("on"), 0, B::Local, 0, 1, Cf::None, "", "log on [level]", "line mode: show hub log lines"),
    cmd!("log", Some("off"), 0, B::Local, 0, 0, Cf::None, "", "log off", "line mode: stop log lines"),
    cmd!("view", None, 0, B::Local, 1, 0, Cf::None, "", "view <1-5>", "console, log, network, upgrades, stats"),
    cmd!("pane", None, 0, B::Local, 0, 0, Cf::None, "", "pane", "show or hide the tree pane (F3)"),
    cmd!("ascii", None, 0, B::Local, 0, 0, Cf::None, "", "ascii", "plain ASCII lines for this session"),
    cmd!("filter", None, 0, B::Local, 1, 64, Cf::None, "", "filter <text|clear>", "log view: only lines containing <text>"),
    cmd!("clear", None, 0, B::Local, 0, 0, Cf::None, "", "clear", "clear the current view"),
];

const LEVEL_WORD: [&str; 5] = ["none", "error", "warning", "info", "debug"];

/// What Tab offers for one argument of a command (docs/console.md §2).
#[derive(Clone, Copy, PartialEq)]
enum Ck {
    Cmd,
    Words(&'static str),
    Bot,
    BotOn,
    Hub,
}

struct ArgComp {
    cmd: &'static str,
    sub: Option<&'static str>,
    /// argument index after cmd [sub]; None = any
    pos: Option<usize>,
    kind: Ck,
}

const LEVEL_WORDS: &str = "none error warning info debug";
const ARG_COMP: &[ArgComp] = &[
    ArgComp {
        cmd: "help",
        sub: None,
        pos: Some(0),
        kind: Ck::Cmd,
    },
    ArgComp {
        cmd: "bot",
        sub: Some("del"),
        pos: Some(0),
        kind: Ck::Bot,
    },
    ArgComp {
        cmd: "bot",
        sub: Some("kick"),
        pos: Some(0),
        kind: Ck::BotOn,
    },
    ArgComp {
        cmd: "bot",
        sub: Some("rekey"),
        pos: Some(0),
        kind: Ck::Bot,
    },
    ArgComp {
        cmd: "peer",
        sub: Some("setkey"),
        pos: Some(0),
        kind: Ck::Hub,
    },
    ArgComp {
        cmd: "hub",
        sub: Some("purge"),
        pos: Some(0),
        kind: Ck::Words("now"),
    },
    ArgComp {
        cmd: "loglevel",
        sub: None,
        pos: Some(0),
        kind: Ck::Words("file console none error warning info debug"),
    },
    // after file|console
    ArgComp {
        cmd: "loglevel",
        sub: None,
        pos: Some(1),
        kind: Ck::Words(LEVEL_WORDS),
    },
    ArgComp {
        cmd: "log",
        sub: Some("on"),
        pos: Some(0),
        kind: Ck::Words(LEVEL_WORDS),
    },
    ArgComp {
        cmd: "view",
        sub: None,
        pos: Some(0),
        kind: Ck::Words("1 2 3 4 5"),
    },
    ArgComp {
        cmd: "filter",
        sub: None,
        pos: Some(0),
        kind: Ck::Words("clear"),
    },
    ArgComp {
        cmd: "upgrade",
        sub: Some("releases"),
        pos: None,
        kind: Ck::Words("bot= hub="),
    },
    ArgComp {
        cmd: "upgrade",
        sub: Some("start"),
        pos: None,
        kind: Ck::Words("hub= nodes= botbase= hubbase="),
    },
];

fn cmd_has_subs(cmd: &[u8]) -> bool {
    CMDS.iter().any(|d| d.sub.is_some() && eq_ic(cmd, d.cmd))
}

/// Local time as "HH:MM:SS" (and its parts).
fn local_hms() -> (u32, u32, u32) {
    use chrono::Timelike;
    let t = chrono::Local::now();
    (t.hour(), t.minute(), t.second())
}

/// C atoi(): optional blanks, sign, digits; 0 if none.
fn atoi(s: &[u8]) -> i64 {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || (9..=13).contains(&s[i])) {
        i += 1;
    }
    let neg = i < s.len() && s[i] == b'-';
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add(i64::from(s[i] - b'0'));
        i += 1;
    }
    if neg { -v } else { v }
}

/// sscanf(v, "%d/%d", &a, &b): each stays 0 when it does not parse.
fn scan_pair(v: &[u8]) -> (i32, i32) {
    let digits = |s: &[u8]| -> Option<(i64, usize)> {
        let mut i = 0;
        while i < s.len() && (s[i] == b' ' || (9..=13).contains(&s[i])) {
            i += 1;
        }
        let st = i;
        if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
            i += 1;
        }
        let ds = i;
        while i < s.len() && s[i].is_ascii_digit() {
            i += 1;
        }
        if i == ds {
            return None;
        }
        Some((atoi(&s[st..i]), i))
    };
    let Some((a, n)) = digits(v) else {
        return (0, 0);
    };
    if v.get(n) != Some(&b'/') {
        return (a as i32, 0);
    }
    match digits(&v[n + 1..]) {
        Some((b, _)) => (a as i32, b as i32),
        None => (a as i32, 0),
    }
}

impl Ui {
    // -----------------------------------------------------------------------
    // Output helpers
    // -----------------------------------------------------------------------
    fn audit(&mut self, level: i32, msg: Vec<u8>) {
        if self.audit_q.len() >= MAX_AUDIT {
            return;
        }
        self.audit_q.push((level, c_cut(&msg, 384).to_vec()));
    }

    /// Next audit line, if any.
    pub fn take_audit(&mut self) -> Option<(i32, Vec<u8>)> {
        if self.audit_q.is_empty() {
            None
        } else {
            Some(self.audit_q.remove(0))
        }
    }

    fn core_frame(&mut self, op: u8, p: &[u8]) {
        self.core
            .extend_from_slice(&((1 + p.len()) as u32).to_be_bytes());
        self.core.push(op);
        self.core.extend_from_slice(p);
    }

    fn subscribe(&mut self) {
        let s = if self.line_mode {
            if self.log_on {
                format!("sub|status,tree,upg,log={}", self.log_sub_level)
            } else {
                "sub|status,tree,upg".to_string()
            }
        } else {
            format!("sub|status,tree,upg,log={LOG_DEBUG},logreplay")
        };
        self.core_frame(CMD_CONSOLE, s.as_bytes());
    }

    /// Line mode: one line of output (already sanitized), ending in CRLF.
    fn lm_line(&mut self, s: &[u8]) {
        self.term.extend_from_slice(s);
        self.term.extend_from_slice(b"\r\n");
    }

    /// Line mode: the prompt and whatever is typed so far.
    fn lm_prompt(&mut self) {
        let p: &[u8] = if self.confirming != Confirm::None {
            b"? "
        } else {
            b"> "
        };
        self.term.extend_from_slice(p);
        let input = self.input.clone();
        self.term.extend_from_slice(&input);
    }

    /// Line mode: something arrives while the admin is at the prompt.  A CR
    /// puts it over the prompt (a reader takes the text after a line's last
    /// CR), then the prompt and the partial input are printed again.  While
    /// a command is in flight it is held until that command's marker.
    fn lm_async(&mut self, text: &[u8]) {
        if self.term.len() + self.backlog + self.held.len() > CONSOLE_TERM_OUTQ_MAX {
            self.dropped += 1;
            return;
        }
        let hold = self.user_busy || self.confirming != Confirm::None;
        let mut out = Vec::with_capacity(text.len() + 16);
        if !hold {
            out.push(b'\r');
        }
        let mut p = 0;
        while p < text.len() {
            let n = text[p..]
                .iter()
                .position(|&b| b == b'\n')
                .unwrap_or(text.len() - p);
            out.extend_from_slice(&text[p..p + n]);
            out.extend_from_slice(b"\r\n");
            p += n + 1;
        }
        if hold {
            self.held.extend_from_slice(&out);
        } else {
            self.term.extend_from_slice(&out);
            self.lm_prompt();
        }
    }

    /// Full screen: add a line to a view's scrollback.
    fn fs_add(&mut self, view: usize, text: &[u8], kind: u8, level: i32) {
        if let Some(sb) = self.sb[view].as_mut() {
            sb.add(text, kind, level);
        }
        if view != self.view && (view != V_LOG || level <= LOG_WARNING) {
            self.act[view] = true;
        }
        self.dirty = true;
    }

    fn fs_timestamped(&mut self, view: usize, text: &[u8], kind: u8) {
        let (h, m, s) = local_hms();
        let buf = fmtb(&[format!("{h:02}:{m:02}:{s:02} ").as_bytes(), text]);
        let buf = c_cut(&buf, CONSOLE_INPUT_MAX + 32).to_vec();
        self.fs_add(view, &buf, kind, LOG_INFO);
    }

    /// A console-side message (help, a refused command) in either mode.
    fn note(&mut self, text: &[u8], kind: u8) {
        if self.line_mode {
            self.lm_line(text);
        } else {
            self.fs_timestamped(V_CONSOLE, text, kind);
        }
    }

    // -----------------------------------------------------------------------
    // Replies and events from the core
    // -----------------------------------------------------------------------
    fn emit_reply_line(&mut self, line: &[u8], kind: u8) {
        if self.line_mode {
            self.lm_line(line);
        } else {
            self.fs_add(V_CONSOLE, line, kind, LOG_INFO);
        }
    }

    /// Split a reply into sanitized lines, dropping empty trailing ones, and
    /// emit each.  Returns the first line as snprintf into [256] kept it.
    fn each_line(&mut self, text: &[u8], kind: u8) -> Vec<u8> {
        let mut end = text.len();
        while end > 0 && matches!(text[end - 1], b'\n' | b'\r' | b' ') {
            end -= 1;
        }
        let mut first: Option<Vec<u8>> = None;
        let mut i = 0;
        while i < end {
            let mut j = i;
            while j < end && text[j] != b'\n' {
                j += 1;
            }
            let mut n = j - i;
            if n > 0 && text[i + n - 1] == b'\r' {
                n -= 1;
            }
            let clean = sanitize(&text[i..i + n], n + 2);
            if first.is_none() {
                first = Some(c_cut(&clean, 256).to_vec());
            }
            self.emit_reply_line(&clean, kind);
            i = j + 1;
        }
        first.unwrap_or_default()
    }

    fn flush_held(&mut self) {
        if !self.held.is_empty() {
            let h = std::mem::take(&mut self.held);
            self.term.extend_from_slice(&h);
        }
    }

    /// The command in flight finished: held events, then the next queued
    /// line.  from_reply: it ended with the core's answer (asynchronously),
    /// so line mode owes the prompt here; otherwise the input handler prints
    /// it.
    fn command_done(&mut self, from_reply: bool) {
        self.user_busy = false;
        self.dirty = true;
        // Lines typed ahead: the next one answers a confirmation a queued
        // command asked for, as it would have at the prompt.
        while !self.user_busy && !self.queued.is_empty() && !self.closing {
            let next = self.queued.remove(0);
            if self.confirming != Confirm::None {
                self.confirm_answer(&next, false);
            } else {
                self.run_line(&next);
            }
        }
        if self.line_mode && from_reply && !self.user_busy && !self.closing {
            if self.confirming != Confirm::None {
                self.lm_prompt();
            } else {
                self.flush_held();
                self.lm_prompt();
            }
        }
    }

    fn marker_ok(&mut self, seq: i32, words: &[u8]) {
        if self.line_mode {
            let m = fmtb(&[format!("[ok #{seq}] ").as_bytes(), words]);
            self.lm_line(c_cut(&m, 96));
        }
    }

    fn marker_err(&mut self, seq: i32, why: &[u8]) {
        if self.line_mode {
            let m = fmtb(&[format!("[err #{seq}] ").as_bytes(), why]);
            self.lm_line(c_cut(&m, CONSOLE_INPUT_MAX + 32));
        } else {
            self.fs_timestamped(V_CONSOLE, why, L_ERR);
        }
    }

    fn on_reply(&mut self, text: &[u8]) {
        if self.rq.is_empty() {
            return; // nothing asked: ignore
        }
        let rq = self.rq.remove(0);
        if rq.kind == Rq::ViewUpg || rq.kind == Rq::ViewStats {
            // keep the newlines, clean each line
            let len = text.len();
            let mut dst: Vec<u8> = Vec::with_capacity(len + 1);
            let mut i = 0;
            while i < len {
                let mut j = i;
                while j < len && text[j] != b'\n' {
                    j += 1;
                }
                let cap = len + 1 - dst.len();
                dst.extend_from_slice(&sanitize(&text[i..j], cap));
                if j < len && dst.len() + 1 < len + 1 {
                    dst.push(b'\n');
                }
                i = j + 1;
            }
            if rq.kind == Rq::ViewUpg {
                self.upg_text = Some(dst);
            } else {
                self.stats_text = Some(dst);
            }
            self.dirty = true;
            return;
        }
        let err = !text.is_empty()
            && (text.len() >= 3 && text[..3].eq_ignore_ascii_case(b"ERR")
                || text == b"Buffer overflow");
        let first = self.each_line(text, if err { L_ERR } else { L_NORMAL });
        if err {
            if self.line_mode {
                let m = fmtb(&[format!("[err #{}] ", rq.seq).as_bytes(), &first]);
                self.lm_line(c_cut(&m, 320));
            }
        } else {
            self.marker_ok(rq.seq, &rq.words);
        }
        let msg = fmtb(&[
            b"[CONSOLE] ",
            &self.admin,
            b"@",
            &self.ip,
            format!(" #{} ", rq.seq).as_bytes(),
            &rq.audit,
            b" -> ",
            if err { b"err: " } else { b"ok" },
            if err {
                &first[..first.len().min(120)]
            } else {
                b""
            },
        ]);
        self.audit(rq.audit_level, msg);
        self.command_done(true);
    }

    fn parse_status(&mut self, data: &[u8]) {
        let mut st = Status {
            upg: b"-".to_vec(),
            ..Status::default()
        };
        for f in c_cut(data, 512)
            .split(|&b| b == b'|')
            .filter(|f| !f.is_empty())
        {
            let Some(eq) = f.iter().position(|&b| b == b'=') else {
                continue;
            };
            let (k, v) = (&f[..eq], &f[eq + 1..]);
            match k {
                b"name" => st.name = sanitize(v, 64),
                b"peers" => (st.peers_up, st.peers_total) = scan_pair(v),
                b"bots" => (st.bots_on, st.bots_total) = scan_pair(v),
                b"upg" => st.upg = sanitize(v, 24),
                b"frozen" => st.frozen = atoi(v) != 0,
                b"rollup" => st.rollup = atoi(v) != 0,
                b"split" => st.split = atoi(v) != 0,
                b"loglevel" => st.loglevel = atoi(v) as i32,
                b"consolelevel" => st.consolelevel = atoi(v) as i32,
                _ => {}
            }
        }
        st.have = true;
        if !st.name.is_empty() {
            self.hubname = c_cut(&st.name, 64).to_vec();
        }
        self.st = st;
    }

    fn request_view(&mut self, kind: Rq, now_ms: i64) {
        if self.rq.iter().any(|r| r.kind == kind) || self.rq.len() >= MAX_PENDING_RQ {
            return;
        }
        self.rq.push(PendingRq {
            kind,
            seq: 0,
            words: Vec::new(),
            audit: Vec::new(),
            audit_level: 0,
        });
        if kind == Rq::ViewUpg {
            self.core_frame(CMD_ADMIN_UPGRADE_STATUS, b"");
            self.upg_at = now_ms;
        } else {
            self.core_frame(CMD_ADMIN_STATS, b"");
            self.stats_at = now_ms;
        }
    }

    fn on_event(&mut self, payload: &[u8], now_ms: i64) {
        let Some(bar) = payload.iter().position(|&b| b == b'|') else {
            return;
        };
        if bar >= 16 {
            return;
        }
        let topic = &payload[..bar];
        let data = &payload[bar + 1..];
        match topic {
            b"status" => {
                let clean = sanitize(data, data.len() + 1);
                self.parse_status(&clean);
                if self.line_mode {
                    let line = fmtb(&[b"[evt status] ", &clean]);
                    self.lm_async(&line);
                }
                self.dirty = true;
            }
            b"tree" => {
                let dl = data.len();
                let mut tree = Vec::with_capacity(dl + 1);
                let mut rows = 0;
                let mut i = 0;
                while i < dl {
                    let mut j = i;
                    while j < dl && data[j] != b'\n' {
                        j += 1;
                    }
                    if j > i {
                        let cap = dl + 1 - tree.len();
                        tree.extend_from_slice(&sanitize(&data[i..j], cap));
                        tree.push(b'\n');
                        rows += 1;
                    }
                    i = j + 1;
                }
                self.tree = tree;
                if self.line_mode {
                    let mut blk = format!("[evt tree] begin {rows}\n").into_bytes();
                    let mut p = 0;
                    let t = self.tree.clone();
                    while p < t.len() {
                        let n = t[p..]
                            .iter()
                            .position(|&b| b == b'\n')
                            .unwrap_or(t.len() - p);
                        blk.extend_from_slice(b"[evt tree] ");
                        blk.extend_from_slice(&t[p..p + n]);
                        blk.push(b'\n');
                        p += n + 1;
                    }
                    blk.extend_from_slice(b"[evt tree] end");
                    self.lm_async(&blk);
                }
                self.dirty = true;
            }
            b"upg" => {
                let clean = sanitize(data, 256);
                if self.line_mode {
                    let line = fmtb(&[b"[evt upg] ", &clean]);
                    self.lm_async(c_cut(&line, 300));
                } else if self.view == V_UPG {
                    self.request_view(Rq::ViewUpg, now_ms);
                }
            }
            b"log" => {
                let Some(b2) = data.iter().position(|&b| b == b'|') else {
                    return;
                };
                if b2 >= 16 {
                    return;
                }
                let lvl = &data[..b2];
                let clean = sanitize(&data[b2 + 1..], CONSOLE_LOG_LINE_MAX + 8);
                let mut level = LOG_INFO;
                for (i, w) in LEVEL_WORD.iter().enumerate().skip(1) {
                    if lvl == w.as_bytes() {
                        level = i as i32;
                    }
                }
                if self.line_mode {
                    if !self.log_on {
                        return;
                    }
                    let line = fmtb(&[
                        format!("[log {}] ", LEVEL_WORD[level as usize]).as_bytes(),
                        &clean,
                    ]);
                    self.lm_async(&line);
                } else {
                    let kind = match level {
                        LOG_ERROR => L_ERR,
                        LOG_WARNING => L_WARN,
                        LOG_DEBUG => L_DIM,
                        _ => L_NORMAL,
                    };
                    self.fs_add(V_LOG, &clean, kind, level);
                }
            }
            b"drop" => {
                let n = atoi(data).max(0) as u64;
                self.dropped += n;
            }
            _ => {}
        }
    }

    /// A frame from the core.
    pub fn core_frame_in(&mut self, op: u8, payload: &[u8], now_ms: i64) {
        if op == CONSOLE_REPLY {
            self.on_reply(payload);
        } else if op == CMD_CONSOLE {
            self.on_event(payload, now_ms);
        }
    }
}

// ===========================================================================
// Running a command line
// ===========================================================================
const MAX_WORDS: usize = 16;

struct Words {
    buf: Vec<u8>,
    /// (start, end) of each word in `buf`.
    w: Vec<(usize, usize)>,
}

impl Words {
    fn split(line: &[u8]) -> Words {
        let buf = c_cut(line, CONSOLE_INPUT_MAX).to_vec();
        let mut w = Vec::new();
        let mut p = 0;
        while p < buf.len() && w.len() < MAX_WORDS {
            while p < buf.len() && buf[p] == b' ' {
                p += 1;
            }
            if p >= buf.len() {
                break;
            }
            let s = p;
            while p < buf.len() && buf[p] != b' ' {
                p += 1;
            }
            w.push((s, p));
            if p < buf.len() {
                p += 1;
            }
        }
        Words { buf, w }
    }

    fn n(&self) -> usize {
        self.w.len()
    }

    fn get(&self, i: usize) -> &[u8] {
        let (s, e) = self.w[i];
        &self.buf[s..e]
    }
}

fn find_cmd(ws: &Words) -> Option<(&'static CmdDef, usize)> {
    let c = ws.get(0);
    for d in CMDS {
        if !eq_ic(c, d.cmd) {
            continue;
        }
        match d.sub {
            Some(sub) => {
                if ws.n() >= 2 && eq_ic(ws.get(1), sub) {
                    return Some((d, 2));
                }
            }
            None => return Some((d, 1)),
        }
    }
    None
}

fn cmd_known_word(w: &[u8]) -> bool {
    CMDS.iter().any(|d| eq_ic(w, d.cmd))
}

fn level_arg(a: &[u8]) -> i32 {
    if a.len() == 1 && (b'0'..=b'4').contains(&a[0]) {
        return i32::from(a[0] - b'0');
    }
    for (i, w) in LEVEL_WORD.iter().enumerate() {
        if eq_ic(a, w) {
            return i as i32;
        }
    }
    if eq_ic(a, "warn") {
        return LOG_WARNING;
    }
    -1
}

fn all_digits(s: &[u8]) -> bool {
    !s.is_empty() && s.len() <= 10 && s.iter().all(u8::is_ascii_digit)
}

/// key=value option of "upgrade" commands.
fn kv_opt<'a>(arg: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let kl = key.len();
    (arg.len() > kl && arg[..kl].eq_ignore_ascii_case(key.as_bytes()) && arg[kl] == b'=')
        .then(|| &arg[kl + 1..])
}

/// Build the request payload; Err(why) when the arguments are bad.
fn build_payload(c: &CmdDef, ws: &Words, argi: usize) -> Result<Vec<u8>, &'static str> {
    const CAP: usize = 1024;
    let na = ws.n() - argi;
    let a = |i: usize| ws.get(argi + i);
    let too_long = "arguments too long";
    let out: Vec<u8> = match c.build {
        B::None | B::Local => return Ok(Vec::new()),
        B::Fixed => return Ok(c.fixed.as_bytes().to_vec()),
        B::Arg => a(0).to_vec(),
        B::OptArg => {
            if na > 0 {
                a(0).to_vec()
            } else {
                Vec::new()
            }
        }
        B::Pipe | B::Colon => {
            let sep = if c.build == B::Pipe { b'|' } else { b':' };
            let mut o = Vec::new();
            for i in 0..na {
                if c.build == B::Colon && a(i).contains(&b':') {
                    return Err("':' is not allowed in an argument here");
                }
                let add = a(i).len() + usize::from(i > 0);
                if o.len() + add >= CAP {
                    return Err(too_long);
                }
                if i > 0 {
                    o.push(sep);
                }
                o.extend_from_slice(a(i));
            }
            return Ok(o);
        }
        B::PeerAdd => {
            if (0..5).any(|i| a(i).contains(&b':')) {
                return Err("':' is not allowed in an argument here");
            }
            let name: &[u8] = if a(3) == b"-" { b"" } else { a(3) };
            fmtb(&[a(0), b":", a(1), b":", a(2), b":", name, b":", a(4)])
        }
        B::ChanAdd => fmtb(&[a(0), b"|", if na > 1 { a(1) } else { b"" }]),
        B::OptSet => {
            if a(0) == b"-" {
                Vec::new()
            } else {
                a(0).to_vec()
            }
        }
        B::LogLevel => {
            // <target><level>: target 0 = the log file, 1 = the console log.
            let target = if na == 2 {
                if a(0).eq_ignore_ascii_case(b"file") {
                    0
                } else if a(0).eq_ignore_ascii_case(b"console") {
                    1
                } else {
                    return Err("target: file or console");
                }
            } else {
                0
            };
            let lvl = level_arg(a(na - 1));
            if lvl < 0 {
                return Err("level: none, error, warning, info, debug or 0-4");
            }
            return Ok(vec![target, lvl as u8]);
        }
        B::LogSize => {
            // <n> MB, <n>k KiB or <n>b bytes, at most 1024 MB (the hub
            // clamps it to its own limits).
            let arg = a(0);
            let (num, mult): (&[u8], u64) = match arg.last() {
                Some(b'k' | b'K') if arg.len() > 1 && arg.len() < 16 => {
                    (&arg[..arg.len() - 1], 1024)
                }
                Some(b'b' | b'B') if arg.len() > 1 && arg.len() < 16 => (&arg[..arg.len() - 1], 1),
                _ => (c_cut(arg, 16), 1024 * 1024),
            };
            let v = if all_digits(num) {
                (atoi(num) as u64).saturating_mul(mult)
            } else {
                0
            };
            if !(1..=1024 * 1024 * 1024).contains(&v) {
                return Err("size: <MB>, <n>k or <n>b, at most 1024 MB");
            }
            return Ok((v as u32).to_be_bytes().to_vec());
        }
        B::Purge => {
            if eq_ic(a(0), "now") {
                b"immediate".to_vec()
            } else if all_digits(a(0)) && atoi(a(0)) > 0 {
                a(0).to_vec()
            } else {
                return Err("purge now, or purge <days>");
            }
        }
        B::UpgReleases => {
            let (mut bot, mut hub): (&[u8], &[u8]) = (b"", b"");
            for i in 0..na {
                if let Some(v) = kv_opt(a(i), "bot") {
                    bot = v;
                } else if let Some(v) = kv_opt(a(i), "hub") {
                    hub = v;
                } else {
                    return Err("options: bot=<base> hub=<base>");
                }
            }
            if !bot.is_empty() || !hub.is_empty() {
                fmtb(&[b"releases|", bot, b"|", hub])
            } else {
                b"releases".to_vec()
            }
        }
        B::UpgStart => {
            let (mut hubv, mut nodes, mut bb, mut hb): (&[u8], &[u8], &[u8], &[u8]) =
                (b"", b"", b"", b"");
            for i in 1..na {
                if let Some(v) = kv_opt(a(i), "hub") {
                    hubv = if v == b"-" { b"" } else { v };
                } else if let Some(v) = kv_opt(a(i), "nodes") {
                    nodes = v;
                } else if let Some(v) = kv_opt(a(i), "botbase") {
                    bb = v;
                } else if let Some(v) = kv_opt(a(i), "hubbase") {
                    hb = v;
                } else {
                    return Err("options: hub=<ver> nodes=<list> botbase=<url> hubbase=<url>");
                }
            }
            // ver|variant|kind|min_from|base|hub_ver|hub_base|sel — variant,
            // kind and min_from are left to each node, as hub_admin always did.
            let hbv: &[u8] = if hubv.is_empty() { b"" } else { hb };
            fmtb(&[a(0), b"||||", bb, b"|", hubv, b"|", hbv, b"|", nodes])
        }
    };
    if out.len() >= CAP {
        return Err(too_long);
    }
    Ok(out)
}

impl Ui {
    fn show_help(&mut self, topic: Option<&[u8]>) {
        for d in CMDS {
            if let Some(t) = topic
                && !eq_ic(t, d.cmd)
            {
                continue;
            }
            let line = format!("{:<44} {}", d.usage, d.help);
            self.note(c_cut(line.as_bytes(), 256), L_INFO);
        }
        if topic.is_none() && !self.line_mode {
            self.note(
                b"Alt+1..5 views, Alt+Left/Right cycle, F2 log level, F3 tree pane, \
PgUp/PgDn/End scroll, Tab completes, Ctrl-C cancels",
                L_INFO,
            );
        }
    }

    fn send_request(&mut self, op: u8, payload: &[u8], rq: PendingRq) {
        if self.rq.len() >= MAX_PENDING_RQ {
            self.marker_err(rq.seq, b"too many requests in flight");
            return;
        }
        self.rq.push(rq);
        self.core_frame(op, payload);
        self.user_busy = true;
    }

    fn local_command(
        &mut self,
        c: &CmdDef,
        ws: &Words,
        argi: usize,
        line: &[u8],
        seq: i32,
        words: &[u8],
    ) {
        let a1: Option<Vec<u8>> = (ws.n() > argi).then(|| ws.get(argi).to_vec());
        match c.cmd {
            "help" => {
                if let Some(a) = &a1
                    && !cmd_known_word(a)
                {
                    self.marker_err(seq, b"unknown command");
                    return;
                }
                self.show_help(a1.as_deref());
            }
            "quit" => {
                self.marker_ok(seq, words);
                self.closing = true;
                self.close_why = "quit".to_string();
                return;
            }
            "log" => {
                if !self.line_mode {
                    self.marker_err(seq, b"the log is the Alt+2 view in the full-screen console");
                    return;
                }
                if c.sub == Some("on") {
                    let lvl = a1.as_deref().map_or(LOG_INFO, level_arg);
                    if lvl <= 0 {
                        self.marker_err(seq, b"level: error, warning, info or debug");
                        return;
                    }
                    self.log_on = true;
                    self.log_sub_level = lvl;
                } else {
                    self.log_on = false;
                }
                self.subscribe();
            }
            _ => {
                if self.line_mode {
                    self.marker_err(seq, b"not available in line mode");
                    return;
                }
                match c.cmd {
                    "view" => {
                        let ok = a1
                            .as_deref()
                            .filter(|a| a.len() == 1 && (b'1'..=b'5').contains(&a[0]));
                        let Some(a) = ok else {
                            self.marker_err(seq, b"view 1-5");
                            return;
                        };
                        self.view = usize::from(a[0] - b'1');
                        self.act[self.view] = false;
                    }
                    "pane" => {
                        if self.cols >= CONSOLE_PANE_MIN_COLS {
                            self.pane_user_off = !self.pane_user_off;
                        } else {
                            self.overlay = !self.overlay;
                        }
                    }
                    "ascii" => {
                        self.ascii = !self.ascii;
                        self.full_redraw = true;
                    }
                    "filter" => {
                        let rest = &line[ws.w[argi].0..];
                        if eq_ic(rest, "clear") {
                            self.filter.clear();
                        } else {
                            self.filter = c_cut(rest, 128).to_vec();
                        }
                    }
                    "clear" => {
                        if (self.view == V_CONSOLE || self.view == V_LOG)
                            && let Some(sb) = self.sb[self.view].as_mut()
                        {
                            sb.clear();
                        }
                        self.anchor[self.view] = -1;
                    }
                    _ => {}
                }
                self.dirty = true;
            }
        }
        self.marker_ok(seq, words);
    }

    fn run_line(&mut self, line: &[u8]) {
        let mut s = 0;
        while s < line.len() && line[s] == b' ' {
            s += 1;
        }
        let line = &line[s..];
        if line.is_empty() {
            return;
        }
        if self.user_busy || self.confirming != Confirm::None {
            if self.queued.len() < MAX_QUEUED_LINES {
                self.queued.push(line.to_vec());
            } else {
                self.note(b"busy: line dropped", L_ERR);
            }
            return;
        }
        let l: Vec<u8> = if line[0] == b'/' {
            line[1..].to_vec()
        } else {
            line.to_vec()
        };
        self.seq += 1;
        let seq = self.seq;
        let ws = Words::split(&l);
        if ws.n() == 0 {
            self.marker_err(seq, b"empty command");
            return;
        }
        let Some((c, argi)) = find_cmd(&ws) else {
            if cmd_known_word(ws.get(0)) {
                let why = fmtb(&[b"usage: see help ", ws.get(0)]);
                self.marker_err(seq, c_cut(&why, 128));
            } else {
                self.marker_err(seq, b"unknown command (help lists them)");
            }
            return;
        };
        let words = match c.sub {
            Some(sub) => format!("{} {}", c.cmd, sub),
            None => c.cmd.to_string(),
        }
        .into_bytes();
        let na = ws.n() - argi;
        if na < c.nargs
            || (c.build != B::Local && na > c.nargs + c.optargs)
            || (c.build == B::Local && c.cmd != "filter" && na > c.nargs + c.optargs)
        {
            let why = format!("usage: {}", c.usage);
            self.marker_err(seq, c_cut(why.as_bytes(), 160));
            return;
        }
        if c.build != B::Local && (argi..ws.n()).any(|i| ws.get(i).contains(&b'|')) {
            self.marker_err(seq, b"'|' is not allowed in an argument");
            return;
        }
        if !self.line_mode {
            let echo = fmtb(&[b"> ", &l]);
            self.fs_timestamped(V_CONSOLE, c_cut(&echo, CONSOLE_INPUT_MAX + 4), L_CMD);
        }
        if c.build == B::Local {
            self.local_command(c, &ws, argi, &l, seq, &words);
            return;
        }
        let payload = match build_payload(c, &ws, argi) {
            Ok(p) => p,
            Err(why) => {
                self.marker_err(seq, why.as_bytes());
                return;
            }
        };
        let rq = PendingRq {
            kind: Rq::User,
            seq,
            words: words.clone(),
            audit: l[..l.len().min(300)].to_vec(),
            audit_level: if c.confirm != Confirm::None || c.op == CMD_ADMIN_SET_LOG_LEVEL {
                LOG_WARNING
            } else {
                LOG_INFO
            },
        };
        // An optional argument that was left out asks nothing (peer del
        // alone lists what could be deleted).
        if c.confirm == Confirm::None || (c.build == B::OptArg && na == 0) {
            self.send_request(c.op, &payload, rq);
            return;
        }
        // Ask first; the next line answers.
        self.confirming = c.confirm;
        self.confirm_seq = seq;
        self.confirm_op = c.op;
        self.confirm_payload = payload;
        self.confirm_rq = Some(rq);
        let a1: Vec<u8> = if na > 0 {
            ws.get(argi).to_vec()
        } else {
            Vec::new()
        };
        let q: Vec<u8> = match c.confirm {
            Confirm::Yn => {
                // every argument: "Really loglevel console debug?"
                let args: Vec<&[u8]> = (argi..ws.n()).map(|i| ws.get(i)).collect();
                let all = c_cut(&args.join(&b' '), 256).to_vec();
                self.confirm_want.clear();
                fmtb(&[b"Really ", &words, b" ", &all, b"? (y/N)"])
            }
            Confirm::TypeArg => {
                self.confirm_want = c_cut(&a1, 128).to_vec();
                fmtb(&[b"Type '", &a1, b"' to confirm ", &words, b":"])
            }
            Confirm::TypeHub => {
                let h: Vec<u8> = if self.hubname.is_empty() {
                    b"hub".to_vec()
                } else {
                    self.hubname.clone()
                };
                self.confirm_want = c_cut(&h, 128).to_vec();
                fmtb(&[
                    b"Type the hub name '",
                    &self.confirm_want,
                    b"' to confirm ",
                    &words,
                    b":",
                ])
            }
            Confirm::TypeVer => {
                self.confirm_want = c_cut(&a1, 128).to_vec();
                fmtb(&[b"Type the bot version '", &a1, b"' to start the upgrade:"])
            }
            Confirm::None => Vec::new(),
        };
        self.confirm_q = c_cut(&q, 256).to_vec();
        if self.line_mode {
            let m = fmtb(&[format!("[confirm #{seq}] ").as_bytes(), &self.confirm_q]);
            self.lm_line(c_cut(&m, 320));
        } else {
            let q = self.confirm_q.clone();
            self.fs_timestamped(V_CONSOLE, &q, L_WARN);
        }
    }

    fn confirm_answer(&mut self, answer: &[u8], cancelled: bool) {
        let kind = self.confirming;
        self.confirming = Confirm::None;
        let ok = !cancelled
            && if kind == Confirm::Yn {
                eq_ic(answer, "y") || eq_ic(answer, "yes")
            } else {
                answer == self.confirm_want.as_slice()
            };
        let rq = self.confirm_rq.take();
        if !ok {
            self.marker_err(self.confirm_seq, b"cancelled");
            let audit = rq.map(|r| r.audit).unwrap_or_default();
            let msg = fmtb(&[
                b"[CONSOLE] ",
                &self.admin,
                b"@",
                &self.ip,
                format!(" #{} ", self.confirm_seq).as_bytes(),
                &audit,
                b" -> cancelled",
            ]);
            self.audit(LOG_INFO, msg);
            crate::crypto::wipe(&mut self.confirm_payload);
            self.confirm_payload.clear();
            self.command_done(false);
            return;
        }
        let payload = std::mem::take(&mut self.confirm_payload);
        if let Some(rq) = rq {
            self.send_request(self.confirm_op, &payload, rq);
        }
        let mut p = payload;
        crate::crypto::wipe(&mut p);
    }
}

// ===========================================================================
// Input line
// ===========================================================================

/// Start of the character before byte offset `at`.
fn prev_char(s: &[u8], at: usize) -> usize {
    if at == 0 {
        return 0;
    }
    let mut i = at - 1;
    while i > 0 && s[i] & 0xC0 == 0x80 {
        i -= 1;
    }
    i
}

fn next_char_off(s: &[u8], at: usize) -> usize {
    let mut i = at + 1;
    while i < s.len() && s[i] & 0xC0 == 0x80 {
        i += 1;
    }
    i.min(s.len())
}

fn utf8_encode(cp: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    if cp < 0x80 {
        b.push(cp as u8);
    } else if cp < 0x800 {
        b.push((0xC0 | (cp >> 6)) as u8);
        b.push((0x80 | (cp & 0x3F)) as u8);
    } else if cp < 0x10000 {
        b.push((0xE0 | (cp >> 12)) as u8);
        b.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
        b.push((0x80 | (cp & 0x3F)) as u8);
    } else {
        b.push((0xF0 | (cp >> 18)) as u8);
        b.push((0x80 | ((cp >> 12) & 0x3F)) as u8);
        b.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
        b.push((0x80 | (cp & 0x3F)) as u8);
    }
    b
}

impl Ui {
    fn hist_add(&mut self, line: &[u8]) {
        if line.is_empty() {
            return;
        }
        if self.hist.last().is_some_and(|h| h == line) {
            return;
        }
        if self.hist.len() == CONSOLE_HISTORY {
            self.hist.remove(0);
        }
        self.hist.push(line.to_vec());
    }

    fn in_set(&mut self, s: &[u8]) {
        self.input = c_cut(s, CONSOLE_INPUT_MAX).to_vec();
        self.in_cur = self.input.len();
    }

    fn in_insert(&mut self, bytes: &[u8]) {
        if self.input.len() + bytes.len() >= CONSOLE_INPUT_MAX {
            return;
        }
        let tail = self.input.split_off(self.in_cur);
        self.input.extend_from_slice(bytes);
        self.input.extend_from_slice(&tail);
        self.in_cur += bytes.len();
        if self.line_mode {
            self.term.extend_from_slice(bytes); // echo
        }
    }

    fn in_delete(&mut self, from: usize, to: usize) {
        if from >= to {
            return;
        }
        self.input.drain(from..to);
        if self.in_cur > to {
            self.in_cur -= to - from;
        } else if self.in_cur > from {
            self.in_cur = from;
        }
    }

    fn in_backspace(&mut self) {
        if self.in_cur == 0 {
            return;
        }
        let p = prev_char(&self.input, self.in_cur);
        self.in_delete(p, self.in_cur);
        if self.line_mode {
            self.term.extend_from_slice(b"\x08 \x08");
        }
    }

    /// Tab candidates for the word at `word_idx`; `w` holds the words before
    /// it (the first without its '/').  Arguments only complete where a
    /// command takes a known kind of value: never a bot or hub name in place
    /// of an ip, a pubkey or an admin name.
    fn completions(&self, word_idx: usize, w: &[Vec<u8>; 3], prefix: &[u8]) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut pooln = 0usize;
        let starts =
            |s: &[u8]| s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix);
        let add = |out: &mut Vec<Vec<u8>>, s: &[u8]| -> bool {
            if out.len() < 64 && starts(s) && !out.iter().any(|o| o == s) {
                out.push(s.to_vec());
                return true;
            }
            false
        };
        if word_idx == 0 {
            for d in CMDS {
                add(&mut out, d.cmd.as_bytes());
            }
            return out;
        }
        let subs = cmd_has_subs(&w[0]);
        if word_idx == 1 && subs {
            for d in CMDS {
                if let Some(sub) = d.sub
                    && eq_ic(&w[0], d.cmd)
                {
                    add(&mut out, sub.as_bytes());
                }
            }
            return out;
        }
        // which command, and which of its arguments
        let mut sub: Option<&str> = None;
        let mut pos = word_idx - 1;
        if subs {
            for d in CMDS {
                if let Some(s) = d.sub
                    && eq_ic(&w[0], d.cmd)
                    && eq_ic(&w[1], s)
                {
                    sub = Some(s);
                }
            }
            if sub.is_none() {
                return out;
            }
            pos -= 1;
        }
        if eq_ic(&w[0], "loglevel") && pos == 1 && !eq_ic(&w[1], "file") && !eq_ic(&w[1], "console")
        {
            return out;
        }
        let Some(ac) = ARG_COMP.iter().find(|a| {
            eq_ic(&w[0], a.cmd) && a.sub == sub && (a.pos.is_none() || a.pos == Some(pos))
        }) else {
            return out;
        };
        match ac.kind {
            Ck::Cmd => {
                for d in CMDS {
                    add(&mut out, d.cmd.as_bytes());
                }
                return out;
            }
            Ck::Words(words) => {
                for wd in words.split(' ').filter(|x| !x.is_empty()) {
                    if pooln >= 128 {
                        break;
                    }
                    if add(&mut out, c_cut(wd.as_bytes(), 72)) {
                        pooln += 1;
                    }
                }
                return out;
            }
            _ => {}
        }
        // uuids from the tree rows: H|depth|name|uuid|..., B|depth|nick|uuid|...,
        // D|nick|uuid|... (a bot that is offline)
        for row in self.tree.split(|&b| b == b'\n') {
            if row.is_empty() || out.len() >= 64 || pooln >= 128 {
                continue;
            }
            if row.len() > TREE_ROW_MAX {
                continue;
            }
            let f: Vec<&[u8]> = row
                .split(|&b| b == b'|')
                .filter(|x| !x.is_empty())
                .take(10)
                .collect();
            let ty = f.first().map_or(0, |x| x[0]);
            let uuid = match (ac.kind, ty) {
                (Ck::Hub, b'H') | (Ck::Bot | Ck::BotOn, b'B') if f.len() >= 4 => Some(f[3]),
                (Ck::Bot, b'D') if f.len() >= 3 => Some(f[2]),
                _ => None,
            };
            if let Some(u) = uuid
                && u != b"-"
                && add(&mut out, c_cut(u, 72))
            {
                pooln += 1;
            }
        }
        out
    }

    fn complete(&mut self) {
        let mut ws = self.in_cur;
        while ws > 0 && self.input[ws - 1] != b' ' {
            ws -= 1;
        }
        let prefix_full = self.input[ws..self.in_cur].to_vec();
        // the words before this one (the first without its '/')
        let mut w: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        let mut idx = 0;
        let mut i = 0;
        while i < ws {
            while i < ws && self.input[i] == b' ' {
                i += 1;
            }
            if i >= ws {
                break;
            }
            let s = i;
            while i < ws && self.input[i] != b' ' {
                i += 1;
            }
            if idx < 3 {
                let skip = usize::from(idx == 0 && self.input[s] == b'/');
                w[idx] = c_cut(&self.input[s + skip..i], 64).to_vec();
            }
            idx += 1;
        }
        let pfx: &[u8] = if idx == 0 && prefix_full.first() == Some(&b'/') {
            &prefix_full[1..]
        } else {
            &prefix_full
        };
        let out = self.completions(idx, &w, pfx);
        if out.is_empty() {
            return;
        }
        let mut common = out[0].len();
        for o in &out[1..] {
            let mut k = 0;
            while k < common && k < o.len() && o[k].eq_ignore_ascii_case(&out[0][k]) {
                k += 1;
            }
            common = k;
        }
        let have = pfx.len();
        if common > have || out.len() == 1 {
            let mut add = out[0][have.min(common)..common.max(have)].to_vec();
            if common < have {
                add.clear();
            }
            // a key= option takes its value right after the '='
            if out.len() == 1 && out[0].last() != Some(&b'=') {
                add.push(b' ');
            }
            let add = c_cut(&add, 128).to_vec();
            self.in_insert(&add);
        } else if !self.line_mode {
            let mut line: Vec<u8> = Vec::new();
            for (i, o) in out.iter().enumerate() {
                if line.len() + 2 >= 512 {
                    break;
                }
                if i > 0 {
                    line.extend_from_slice(b"  ");
                }
                line.extend_from_slice(o);
            }
            let line = c_cut(&line, 512).to_vec();
            self.note(&line, L_INFO);
        }
        self.dirty = true;
    }

    fn on_enter(&mut self) {
        let line = std::mem::take(&mut self.input);
        self.in_cur = 0;
        self.in_scroll = 0;
        self.hist_pos = self.hist.len();
        if self.line_mode {
            self.term.extend_from_slice(b"\r\n");
        }
        if self.searching {
            self.searching = false;
            self.search = c_cut(&line, 128).to_vec();
            self.dirty = true;
            return;
        }
        if self.confirming != Confirm::None {
            self.confirm_answer(&line, false);
        } else {
            if line.iter().all(|&b| b == b' ') {
                if self.line_mode {
                    self.lm_prompt();
                }
                return;
            }
            self.hist_add(&line);
            self.run_line(&line);
        }
        if self.line_mode && !self.closing {
            if !self.user_busy && self.confirming == Confirm::None {
                self.flush_held();
            }
            if !self.user_busy {
                self.lm_prompt();
            }
        }
        self.dirty = true;
    }

    fn cancel_input(&mut self) {
        if self.line_mode {
            self.term.extend_from_slice(b"^C\r\n");
        }
        self.input.clear();
        self.in_cur = 0;
        self.in_scroll = 0;
        if self.searching {
            self.searching = false;
        } else if self.confirming != Confirm::None {
            self.confirm_answer(b"", true);
        }
        if self.line_mode && !self.user_busy {
            self.flush_held();
            self.lm_prompt();
        }
        self.dirty = true;
    }

    fn log_line_visible(&self, l: &SLine) -> bool {
        l.level <= self.log_show && (self.filter.is_empty() || ci_contains(&l.text, &self.filter))
    }

    /// Log view search: move the anchor to the next/previous line containing
    /// the search text.
    fn search_step(&mut self, dir: i64) {
        if self.search.is_empty() {
            return;
        }
        let Some(sb) = self.sb[V_LOG].as_ref() else {
            return;
        };
        let cur = if self.anchor[V_LOG] < 0 {
            sb.next - 1
        } else {
            self.anchor[V_LOG]
        };
        let mut s = cur + dir;
        while s >= sb.first && s < sb.next {
            if let Some(l) = sb.get(s)
                && self.log_line_visible(l)
                && ci_contains(&l.text, &self.search)
            {
                self.anchor[V_LOG] = s;
                self.dirty = true;
                return;
            }
            s += dir;
        }
    }

    fn set_view(&mut self, v: i64, now_ms: i64) {
        self.view = v.rem_euclid(V_COUNT as i64) as usize;
        self.act[self.view] = false;
        if self.view == V_UPG {
            self.request_view(Rq::ViewUpg, now_ms);
        }
        if self.view == V_STATS {
            self.request_view(Rq::ViewStats, now_ms);
        }
        self.dirty = true;
    }

    fn handle_key(&mut self, k: Key, now_ms: i64) {
        if self.line_mode {
            match k.t {
                K::Char => {
                    let b = utf8_encode(k.cp);
                    self.in_insert(&b);
                }
                K::Enter => self.on_enter(),
                K::Bs => self.in_backspace(),
                K::Tab => self.in_insert(b" "),
                K::Ctrl => {
                    if k.cp == u32::from(b'c') {
                        self.cancel_input();
                    } else if k.cp == u32::from(b'd') && self.input.is_empty() {
                        self.in_set(b"quit");
                        self.term.extend_from_slice(b"quit");
                        self.on_enter();
                    }
                }
                _ => {}
            }
            return;
        }

        let empty = self.input.is_empty();
        self.dirty = true;
        match k.t {
            K::Char => {
                if empty
                    && !self.searching
                    && self.confirming == Confirm::None
                    && self.view == V_LOG
                {
                    if k.cp == u32::from(b' ') {
                        self.paused = !self.paused;
                        self.paused_next = self.sb[V_LOG].as_ref().map_or(0, |s| s.next);
                        return;
                    }
                    if k.cp == u32::from(b'/') {
                        self.searching = true;
                        return;
                    }
                    if k.cp == u32::from(b'n') || k.cp == u32::from(b'N') {
                        self.search_step(if k.cp == u32::from(b'n') { -1 } else { 1 });
                        return;
                    }
                }
                let b = utf8_encode(k.cp);
                self.in_insert(&b);
            }
            K::Enter => self.on_enter(),
            K::Bs => self.in_backspace(),
            K::Del => {
                if self.in_cur < self.input.len() {
                    let e = next_char_off(&self.input, self.in_cur);
                    self.in_delete(self.in_cur, e);
                }
            }
            K::Left => {
                if self.in_cur > 0 {
                    self.in_cur = prev_char(&self.input, self.in_cur);
                }
            }
            K::Right => {
                if self.in_cur < self.input.len() {
                    self.in_cur = next_char_off(&self.input, self.in_cur);
                }
            }
            K::Home => self.in_cur = 0,
            K::End => {
                if empty || self.in_cur == self.input.len() {
                    self.anchor[self.view] = -1;
                    if self.view == V_LOG {
                        self.paused = false;
                    }
                }
                self.in_cur = self.input.len();
            }
            K::Up | K::Down => {
                if self.view == V_NET && empty {
                    let n = self.net_rows_count();
                    self.net_sel += if k.t == K::Up { -1 } else { 1 };
                    if self.net_sel >= n {
                        self.net_sel = n - 1;
                    }
                    if self.net_sel < 0 {
                        self.net_sel = 0;
                    }
                    return;
                }
                if k.t == K::Up && self.hist_pos > 0 {
                    if self.hist_pos == self.hist.len() {
                        self.hist_stash = c_cut(&self.input, CONSOLE_INPUT_MAX).to_vec();
                    }
                    self.hist_pos -= 1;
                    let h = self.hist[self.hist_pos].clone();
                    self.in_set(&h);
                } else if k.t == K::Down && self.hist_pos < self.hist.len() {
                    self.hist_pos += 1;
                    let h = if self.hist_pos == self.hist.len() {
                        self.hist_stash.clone()
                    } else {
                        self.hist[self.hist_pos].clone()
                    };
                    self.in_set(&h);
                }
            }
            K::PgUp => self.scroll_view(-1),
            K::PgDn => self.scroll_view(1),
            K::Tab => self.complete(),
            K::F => {
                if k.cp == 2 {
                    self.log_show = if self.log_show <= LOG_ERROR {
                        LOG_DEBUG
                    } else {
                        self.log_show - 1
                    };
                } else if k.cp == 3 {
                    if self.cols >= CONSOLE_PANE_MIN_COLS {
                        self.pane_user_off = !self.pane_user_off;
                    } else {
                        self.overlay = !self.overlay;
                    }
                }
            }
            K::Alt => {
                if (u32::from(b'1')..=u32::from(b'5')).contains(&k.cp) {
                    self.set_view(i64::from(k.cp - u32::from(b'1')), now_ms);
                }
            }
            K::AltLeft => self.set_view(self.view as i64 - 1, now_ms),
            K::AltRight => self.set_view(self.view as i64 + 1, now_ms),
            K::Esc => {
                if self.searching {
                    self.searching = false;
                }
                self.overlay = false;
            }
            K::Ctrl => match char::from_u32(k.cp).unwrap_or('\0') {
                'c' => self.cancel_input(),
                'l' => self.full_redraw = true,
                'u' => self.in_delete(0, self.in_cur),
                'a' => self.in_cur = 0,
                'e' => self.in_cur = self.input.len(),
                'w' => {
                    let mut p = self.in_cur;
                    while p > 0 && self.input[p - 1] == b' ' {
                        p -= 1;
                    }
                    while p > 0 && self.input[p - 1] != b' ' {
                        p -= 1;
                    }
                    self.in_delete(p, self.in_cur);
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn feed_char(&mut self, cp: u32, now_ms: i64) {
        let mut k = key(K::Char, cp);
        if self.pasting
            && (cp == u32::from(b'\r') || cp == u32::from(b'\n') || cp == u32::from(b'\t'))
        {
            k.cp = u32::from(b' ');
        }
        self.handle_key(k, now_ms);
    }

    fn feed_seq(&mut self, s: &[u8], now_ms: i64) {
        // s[0] == ESC
        let k = if s.len() == 2 {
            key(K::Alt, u32::from(s[1]))
        } else if s.len() >= 3 && s[1] == 0x1b {
            // ESC ESC [ D: Alt+arrow
            let inner = decode_seq(&s[2..]);
            match inner.t {
                K::Left => key(K::AltLeft, 0),
                K::Right => key(K::AltRight, 0),
                _ => inner,
            }
        } else {
            decode_seq(&s[1..])
        };
        match k.t {
            K::PasteBegin => self.pasting = true,
            K::PasteEnd => self.pasting = false,
            K::None => {}
            _ => self.handle_key(k, now_ms),
        }
    }

    /// Bytes typed at the terminal.
    pub fn input(&mut self, data: &[u8], now_ms: i64) {
        self.last_input_ms = now_ms;
        for &b in data {
            if !self.esc.is_empty() {
                if self.esc.len() < 32 {
                    self.esc.push(b);
                }
                let done = if self.esc.len() >= 2 && self.esc[1] == 0x1b {
                    // ESC ESC ...: the inner sequence decides
                    if self.esc.len() == 2 {
                        0
                    } else {
                        let inner = seq_complete(&self.esc[1..]);
                        if inner > 0 { inner + 1 } else { inner }
                    }
                } else {
                    seq_complete(&self.esc)
                };
                if done > 0 {
                    let seq = self.esc[..done as usize].to_vec();
                    self.feed_seq(&seq, now_ms);
                    self.esc.clear();
                } else if done < 0 || self.esc.len() >= 32 {
                    self.esc.clear(); // garbage: dropped
                }
                continue;
            }
            if !self.utf8.is_empty() {
                self.utf8.push(b);
                let need = if self.utf8[0] >= 0xF0 {
                    4
                } else if self.utf8[0] >= 0xE0 {
                    3
                } else {
                    2
                };
                if self.utf8.len() == need {
                    let ul = utf8_len(&self.utf8);
                    if ul == need {
                        let cp = utf8_cp(&self.utf8, need);
                        if !(0x80..=0x9F).contains(&cp) {
                            self.feed_char(cp, now_ms);
                        }
                    }
                    self.utf8.clear();
                }
                continue;
            }
            if b == 0x1b {
                self.esc.clear();
                self.esc.push(b);
                self.esc_ms = now_ms;
                continue;
            }
            let was_cr = self.last_cr;
            self.last_cr = b == b'\r';
            if b == b'\r' || b == b'\n' {
                if b == b'\n' && was_cr {
                    continue; // CRLF = one Enter
                }
                if self.pasting {
                    self.feed_char(u32::from(b' '), now_ms);
                } else {
                    self.handle_key(key(K::Enter, 0), now_ms);
                }
            } else if b == 0x7f || b == 0x08 {
                self.handle_key(key(K::Bs, 0), now_ms);
            } else if b == b'\t' {
                if self.pasting {
                    self.feed_char(u32::from(b' '), now_ms);
                } else {
                    self.handle_key(key(K::Tab, 0), now_ms);
                }
            } else if b < 0x20 {
                if !self.pasting {
                    self.handle_key(key(K::Ctrl, u32::from(b'a' + b - 1)), now_ms);
                }
            } else if b < 0x80 {
                self.feed_char(u32::from(b), now_ms);
            } else if (0xC2..=0xF4).contains(&b) {
                self.utf8.clear();
                self.utf8.push(b);
            }
            if self.closing {
                return;
            }
        }
    }
}

// ===========================================================================
// Full-screen renderer
// ===========================================================================
const SGR_RESET: &str = "0";
const SGR_TITLE: &str = "0;1;36";
const SGR_LINE: &str = "0;36";
const SGR_STATUS: &str = "0;37;44";
const SGR_ALERT: &str = "0;1;37;41";
const SGR_WARNBG: &str = "0;1;33;44";
const SGR_SEL: &str = "0;7";

fn kind_sgr(kind: u8) -> &'static str {
    match kind {
        L_CMD => "0;1",
        L_ERR => "0;31",
        L_OK => "0;32",
        L_INFO => "0;36",
        L_WARN => "0;33",
        L_DIM => "0;90",
        _ => SGR_RESET,
    }
}

struct RowB {
    b: Vec<u8>,
    w: i32,
    max: i32,
}

impl RowB {
    fn new(max: i32) -> RowB {
        RowB {
            b: Vec::new(),
            w: 0,
            max,
        }
    }

    fn sgr(&mut self, sgr: &str) {
        self.b.extend_from_slice(b"\x1b[");
        self.b.extend_from_slice(sgr.as_bytes());
        self.b.push(b'm');
    }

    /// Append sanitized text, at most `cells` cells (and never past the row).
    fn text(&mut self, s: &[u8], cells: i32) {
        let mut lim = self.max - self.w;
        if cells >= 0 && cells < lim {
            lim = cells;
        }
        let mut used = 0;
        let mut i = 0;
        while i < s.len() {
            let (ul, _, cw) = next_char(&s[i..]);
            if used + cw > lim {
                break;
            }
            self.b.extend_from_slice(&s[i..(i + ul).min(s.len())]);
            used += cw;
            i += ul;
        }
        self.w += used;
    }

    fn fill(&mut self, glyph: &str, n: i32) {
        let mut i = 0;
        while i < n && self.w < self.max {
            self.b.extend_from_slice(glyph.as_bytes());
            self.w += 1;
            i += 1;
        }
    }

    fn pad(&mut self, upto: i32) {
        let upto = upto.min(self.max);
        while self.w < upto {
            self.b.push(b' ');
            self.w += 1;
        }
    }

    /// Text right-aligned in a field of `width` cells.
    fn right(&mut self, s: &[u8], width: i32) {
        let sw = str_width(s).min(width);
        self.pad(self.w + (width - sw));
        self.text(s, width);
    }
}

#[derive(Clone, Default)]
struct TRow {
    typ: u8,
    depth: i32,
    name: Vec<u8>,
    uuid: Vec<u8>,
    ver: Vec<u8>,
    var: Vec<u8>,
    server: Vec<u8>,
    online: bool,
    started: i64,
}

const MAX_TROWS: usize = 1400;

fn parse_tree(tree: &[u8]) -> Vec<TRow> {
    let mut out = Vec::new();
    for row in tree.split(|&b| b == b'\n') {
        if row.is_empty() || out.len() >= MAX_TROWS || row.len() > TREE_ROW_MAX {
            continue;
        }
        // keep empty fields
        let f: Vec<&[u8]> = row.splitn(10, |&b| b == b'|').collect();
        let nf = f.len();
        let cut = |s: &[u8], cap: usize| cut_field(s, cap).to_vec();
        let mut t = TRow {
            typ: f[0].first().copied().unwrap_or(0),
            ..TRow::default()
        };
        if t.typ == b'H' && nf >= 9 {
            t.depth = atoi(f[1]) as i32;
            t.name = cut(f[2], 64);
            t.uuid = cut(f[3], 64);
            t.online = atoi(f[4]) != 0;
            t.ver = cut(f[6], 24);
            t.var = cut(f[7], 8);
            t.started = atoi(f[8]);
            out.push(t);
        } else if t.typ == b'B' && nf >= 9 {
            t.depth = atoi(f[1]) as i32;
            t.name = cut(f[2], 64);
            t.uuid = cut(f[3], 64);
            t.ver = cut(f[4], 24);
            t.server = cut(f[5], 72);
            t.var = cut(f[7], 8);
            t.started = atoi(f[8]);
            t.online = true;
            out.push(t);
        } else if t.typ == b'D' && nf >= 4 {
            t.depth = 1;
            t.name = cut(f[1], 64);
            t.uuid = cut(f[2], 64);
            t.started = atoi(f[3]);
            out.push(t);
        }
    }
    out
}

fn fmt_age(since: i64) -> String {
    if since <= 0 {
        return "--".to_string();
    }
    let d = (crate::cstr::now() - since).max(0);
    if d < 60 {
        format!("{d}s")
    } else if d < 3600 {
        format!("{}m", d / 60)
    } else if d < 86400 {
        format!("{}h", d / 3600)
    } else {
        format!("{}d", d / 86400)
    }
}

fn dash_empty(s: &[u8]) -> &[u8] {
    if s == b"-" { b"" } else { s }
}

#[derive(Clone, Copy)]
struct Seg {
    seq: i64,
    from: usize,
    to: usize,
}

impl Ui {
    /// Box drawing, or its ASCII stand-in (/ascii).
    fn g(&self, utf8: &'static str) -> &'static str {
        if !self.ascii {
            return utf8;
        }
        match utf8 {
            "│" => "|",
            "─" => "-",
            "┬" => "+",
            "▾" => "v",
            "├" => "|",
            "└" => "`",
            "●" => "*",
            "○" => "o",
            _ => "?",
        }
    }

    /// One pane line for tree row i.
    fn tree_line(&self, r: &mut RowB, all: &[TRow], i: usize, width: i32) {
        let t = &all[i];
        let start = r.w;
        let (wide_ver, wide_var, wide_up) = (width >= 30, width >= 26, width >= 34);
        let right = if wide_ver { 9 } else { 0 }
            + 2
            + if wide_var { 3 } else { 0 }
            + if wide_up { 5 } else { 0 };
        let mut indent = if t.typ == b'D' { 0 } else { t.depth * 2 };
        if indent > width / 3 {
            indent = width / 3;
        }
        r.pad(start + indent);
        if t.typ == b'H' {
            r.sgr("0;1");
            r.text(self.g("▾").as_bytes(), 1);
            r.text(b" ", 1);
        } else if t.typ == b'B' {
            let mut last = true;
            for k in all.iter().skip(i + 1) {
                if k.typ == b'B' && k.depth == t.depth {
                    last = false;
                    break;
                }
                if k.typ != b'B' || k.depth < t.depth {
                    break;
                }
            }
            r.sgr(SGR_RESET);
            r.text(self.g(if last { "└" } else { "├" }).as_bytes(), 1);
            r.text(b" ", 1);
        } else {
            r.sgr("0;90");
            r.text(b"  ", 2);
        }
        let name_w = (width - (r.w - start) - right).max(1);
        r.text(&t.name, name_w);
        r.pad(start + width - right);
        if wide_ver {
            r.sgr("0;90");
            let v: &[u8] = if t.typ == b'D' {
                b""
            } else {
                dash_empty(&t.ver)
            };
            r.right(v, 8);
            r.text(b" ", 1);
        }
        r.sgr(if t.online { "0;32" } else { "0;31" });
        r.text(self.g(if t.online { "●" } else { "○" }).as_bytes(), 1);
        r.text(b" ", 1);
        if wide_var {
            r.sgr(SGR_RESET);
            let v = dash_empty(&t.var);
            r.text(v, 2);
            r.pad(r.w + (2 - v.len() as i32));
            r.text(b" ", 1);
        }
        if wide_up {
            let age = fmt_age(if t.typ == b'D' { 0 } else { t.started });
            r.sgr("0;90");
            r.right(age.as_bytes(), 4);
            r.text(b" ", 1);
        }
        r.sgr(SGR_RESET);
        r.pad(start + width);
    }

    fn sb_visible(&self, view: usize, l: Option<&SLine>) -> bool {
        match l {
            None => false,
            Some(l) => view != V_LOG || self.log_line_visible(l),
        }
    }

    fn sb_bottom(&self, view: usize) -> i64 {
        let next = self.sb[view].as_ref().map_or(0, |s| s.next);
        if self.anchor[view] >= 0 {
            return self.anchor[view];
        }
        if view == V_LOG && self.paused {
            return self.paused_next - 1;
        }
        next - 1
    }

    /// The rows a scrollback view shows, top to bottom, ending at its bottom
    /// line.
    fn sb_layout(&self, view: usize, w: i32, h: usize) -> Vec<Seg> {
        let Some(sb) = self.sb[view].as_ref() else {
            return Vec::new();
        };
        let mut rev: Vec<Seg> = Vec::new();
        let mut s = self.sb_bottom(view);
        while s >= sb.first && rev.len() < h {
            let l = sb.get(s);
            if self.sb_visible(view, l) {
                let text = &l.map(|l| &l.text).cloned().unwrap_or_default();
                let len = text.len();
                let mut tmp: Vec<Seg> = Vec::new();
                if len == 0 {
                    tmp.push(Seg {
                        seq: s,
                        from: 0,
                        to: 0,
                    });
                }
                let mut i = 0;
                while i < len && tmp.len() < 256 {
                    let e = wrap_end(text, i, w);
                    tmp.push(Seg {
                        seq: s,
                        from: i,
                        to: e,
                    });
                    i = e;
                }
                for seg in tmp.iter().rev() {
                    if rev.len() >= h {
                        break;
                    }
                    rev.push(*seg);
                }
            }
            s -= 1;
        }
        rev.reverse();
        rev
    }

    fn scroll_view(&mut self, dir: i64) {
        let v = self.view;
        let h = self.rows - 3;
        if h < 1 {
            return;
        }
        if v == V_CONSOLE || v == V_LOG {
            let (first, next) = match self.sb[v].as_ref() {
                Some(sb) => (sb.first, sb.next),
                None => return,
            };
            let w = self.cols;
            let mut s = self.sb_bottom(v);
            let mut moved = 0;
            while moved < h - 1 {
                let ns = s + dir;
                if ns < first {
                    break;
                }
                if ns >= next {
                    self.anchor[v] = -1;
                    if v == V_LOG {
                        self.paused = false;
                    }
                    self.dirty = true;
                    return;
                }
                s = ns;
                let l = self.sb[v].as_ref().and_then(|sb| sb.get(s));
                if self.sb_visible(v, l) {
                    moved += wrap_rows(&l.map(|l| l.text.clone()).unwrap_or_default(), w);
                }
            }
            self.anchor[v] = s;
        } else {
            let mut top = if self.anchor[v] < 0 {
                0
            } else {
                self.anchor[v]
            };
            top += dir * i64::from(h - 1);
            if top <= 0 {
                top = -1;
            }
            self.anchor[v] = top;
        }
        self.dirty = true;
    }

    /// A text blob (upgrade status, stats) shown from line anchor[view] on.
    fn blob_rows(&self, view: usize, text: &[u8], w: i32, h: usize, rows: &mut [RowB], col0: i32) {
        let top = if self.anchor[view] < 0 {
            0
        } else {
            self.anchor[view]
        };
        let mut line = 0i64;
        let mut y = 0;
        let mut p = 0;
        while p < text.len() && y < h {
            let n = text[p..]
                .iter()
                .position(|&b| b == b'\n')
                .unwrap_or(text.len() - p);
            if line >= top {
                let buf = c_cut(&text[p..p + n], 1024);
                rows[y].sgr(SGR_RESET);
                rows[y].text(buf, w);
                rows[y].pad(col0 + w);
                y += 1;
            }
            line += 1;
            p += n + 1;
        }
    }

    fn net_rows_count(&self) -> i32 {
        parse_tree(&self.tree).len() as i32
    }

    /// View 3: every tree column, and the selected node's details.
    fn net_view(&mut self, w: i32, h: usize, rows: &mut [RowB], col0: i32) {
        let tr = parse_tree(&self.tree);
        let n = tr.len() as i32;
        if self.net_sel >= n {
            self.net_sel = if n > 0 { n - 1 } else { 0 };
        }
        let mut detail = if n > 0 { 5 } else { 0 };
        let mut list_h = h as i32 - detail;
        if list_h < 1 {
            list_h = h as i32;
            detail = 0;
        }
        let top = if self.net_sel >= list_h {
            self.net_sel - list_h + 1
        } else {
            0
        };
        rows[0].sgr("0;1");
        rows[0].text(
            if n > 0 {
                b"node                            version   base  up     server / uuid".as_slice()
            } else {
                b"(no tree yet)".as_slice()
            },
            w,
        );
        rows[0].pad(col0 + w);
        let mut y = 1;
        while y < list_h && top + y - 1 < n {
            let i = (top + y - 1) as usize;
            let t = &tr[i];
            let r = &mut rows[y as usize];
            r.sgr(if i as i32 == self.net_sel {
                SGR_SEL
            } else {
                SGR_RESET
            });
            let ind = if t.typ == b'D' {
                0
            } else {
                (t.depth * 2) as usize
            };
            let kind: &[u8] = match t.typ {
                b'H' => b"hub",
                b'B' => b"bot",
                _ => b"off",
            };
            let name = fmtb(&[" ".repeat(ind).as_bytes(), kind, b" ", &t.name]);
            r.text(c_cut(&name, 128), 32);
            r.pad(col0 + 32);
            let age = fmt_age(if t.typ == b'D' { 0 } else { t.started });
            let rest = fmtb(&[
                &pad_bytes(dash_empty(&t.ver), 9),
                b" ",
                &pad_bytes(dash_empty(&t.var), 5),
                b" ",
                format!("{age:<6} ").as_bytes(),
                if t.typ == b'B' { &t.server } else { &t.uuid },
            ]);
            r.text(c_cut(&rest, 256), w - 32);
            r.pad(col0 + w);
            y += 1;
        }
        if detail > 0 && n > 0 {
            let t = &tr[self.net_sel as usize];
            let when = if t.started > 0 {
                chrono::DateTime::from_timestamp(t.started, 0)
                    .map(|d| {
                        d.with_timezone(&chrono::Local)
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string()
                    })
                    .unwrap_or_else(|| "--".into())
            } else {
                "--".into()
            };
            let kind: &[u8] = match t.typ {
                b'H' => b"hub",
                b'B' => b"bot",
                _ => b"bot (not connected)",
            };
            let y0 = (h as i32 - detail) as usize;
            let g = self.g("─");
            rows[y0].sgr(SGR_LINE);
            rows[y0].fill(g, w);
            let l1 = fmtb(&[
                kind,
                b" ",
                &t.name,
                if t.online { b"  online" } else { b"  offline" },
            ]);
            rows[y0 + 1].sgr("0;1");
            rows[y0 + 1].text(c_cut(&l1, 256), w);
            rows[y0 + 1].pad(col0 + w);
            let l2 = fmtb(&[b"uuid     ", &t.uuid]);
            rows[y0 + 2].sgr(SGR_RESET);
            rows[y0 + 2].text(c_cut(&l2, 256), w);
            rows[y0 + 2].pad(col0 + w);
            let srv: &[u8] = if t.server.is_empty() { b"-" } else { &t.server };
            let l3 = fmtb(&[b"version  ", &t.ver, b" ", &t.var, b"   server ", srv]);
            rows[y0 + 3].text(c_cut(&l3, 256), w);
            rows[y0 + 3].pad(col0 + w);
            let l4 = fmtb(&[
                if t.typ == b'D' {
                    b"last seen"
                } else {
                    b"started  "
                },
                b"  ",
                when.as_bytes(),
            ]);
            rows[y0 + 4].text(c_cut(&l4, 256), w);
            rows[y0 + 4].pad(col0 + w);
        }
    }

    fn status_bar(&self, r: &mut RowB, now_ms: i64, pane_hidden: bool) {
        let mut s: Vec<(Vec<u8>, i32, &'static str)> = Vec::new();
        let (hh, mm, _) = local_hms();
        let push =
            |s: &mut Vec<(Vec<u8>, i32, &'static str)>, p: i32, sg: &'static str, t: Vec<u8>| {
                if s.len() < 16 {
                    s.push((c_cut(&t, 96).to_vec(), p, sg));
                }
            };
        let hub: &[u8] = if self.hubname.is_empty() {
            b"hub"
        } else {
            &self.hubname
        };
        push(
            &mut s,
            1,
            SGR_STATUS,
            fmtb(&[
                format!("{hh:02}:{mm:02} ").as_bytes(),
                c_cut(hub, 41),
                b" ",
                c_cut(&self.admin, 41),
            ]),
        );
        if self.st.have {
            push(
                &mut s,
                2,
                SGR_STATUS,
                format!("peers {}/{}", self.st.peers_up, self.st.peers_total).into_bytes(),
            );
            push(
                &mut s,
                2,
                SGR_STATUS,
                format!("bots {}/{}", self.st.bots_on, self.st.bots_total).into_bytes(),
            );
            if self.st.upg != b"-" {
                push(&mut s, 3, SGR_WARNBG, fmtb(&[b"UPG ", &self.st.upg]));
            }
            if self.st.frozen {
                push(&mut s, 3, SGR_ALERT, b"FROZEN".to_vec());
            }
            if self.st.rollup {
                push(&mut s, 3, SGR_WARNBG, b"ROLLUP".to_vec());
            }
            if self.st.split {
                push(&mut s, 3, SGR_ALERT, b"SPLIT".to_vec());
            }
        }
        if pane_hidden {
            push(&mut s, 3, SGR_STATUS, b"F3:tree".to_vec());
        }
        if self.view == V_LOG {
            push(
                &mut s,
                4,
                SGR_STATUS,
                fmtb(&[
                    VIEW_NAME[self.view].as_bytes(),
                    if self.filter.is_empty() { b"" } else { b" /" },
                    c_cut(&self.filter, 41),
                    b" show:",
                    LEVEL_WORD[self.log_show as usize].as_bytes(),
                ]),
            );
        } else {
            push(
                &mut s,
                4,
                SGR_STATUS,
                VIEW_NAME[self.view].as_bytes().to_vec(),
            );
        }
        if self.st.have
            && (0..=LOG_DEBUG).contains(&self.st.loglevel)
            && (0..=LOG_DEBUG).contains(&self.st.consolelevel)
        {
            push(
                &mut s,
                4,
                SGR_STATUS,
                format!(
                    "log file:{} console:{}",
                    LEVEL_WORD[self.st.loglevel as usize],
                    LEVEL_WORD[self.st.consolelevel as usize]
                )
                .into_bytes(),
            );
        }
        if self.paused {
            push(&mut s, 4, SGR_WARNBG, b"PAUSED".to_vec());
        }
        {
            let mut act = String::new();
            for v in 0..V_COUNT {
                if self.act[v] && act.len() + 3 < 32 {
                    if !act.is_empty() {
                        act.push(',');
                    }
                    act.push_str(&(v + 1).to_string());
                }
            }
            if !act.is_empty() {
                push(&mut s, 5, SGR_STATUS, format!("[Act: {act}]").into_bytes());
            }
        }
        let idle_left = CONSOLE_IDLE_TIMEOUT - (now_ms - self.last_input_ms) / 1000;
        if idle_left <= 60 {
            push(
                &mut s,
                6,
                SGR_ALERT,
                format!("idle {}s", idle_left.max(0)).into_bytes(),
            );
        }
        // drop the lowest priority until it fits
        loop {
            let w: i32 = 1 + s.iter().map(|x| str_width(&x.0) + 3).sum::<i32>();
            if w <= r.max || s.len() <= 1 {
                break;
            }
            let mut worst = 0;
            for i in 1..s.len() {
                if s[i].1 >= s[worst].1 {
                    worst = i;
                }
            }
            s.remove(worst);
        }
        r.sgr(SGR_STATUS);
        r.text(b" ", 1);
        for (i, (t, _, sg)) in s.iter().enumerate() {
            if i > 0 {
                r.sgr(SGR_STATUS);
                r.text(b" ", 1);
                r.text(self.g("│").as_bytes(), 1);
                r.text(b" ", 1);
            }
            r.sgr(sg);
            r.text(t, -1);
        }
        r.sgr(SGR_STATUS);
        r.pad(r.max);
        r.sgr(SGR_RESET);
    }

    fn compose(&mut self, now_ms: i64) -> (Vec<RowB>, i32, i32) {
        let (c, r) = (self.cols, self.rows);
        let mut rows: Vec<RowB> = (0..r)
            .map(|y| RowB::new(if y == r - 1 { c - 1 } else { c }))
            .collect();
        if c < CONSOLE_MIN_COLS || r < CONSOLE_MIN_ROWS {
            rows[0].text(b"terminal too small (40x10 at least)", -1);
            for row in rows.iter_mut() {
                let m = row.max;
                row.pad(m);
            }
            return (rows, 0, 0);
        }
        let wide = c >= CONSOLE_PANE_MIN_COLS;
        let mut pane_w = 0;
        if wide && !self.pane_user_off {
            pane_w = (c * 30 / 100).clamp(CONSOLE_PANE_MIN, CONSOLE_PANE_MAX);
        }
        // On a narrow terminal F3 lays the tree over the right of the screen,
        // squeezing the output pane while it is shown.
        let overlay = !wide && self.overlay;
        if overlay {
            pane_w = if c - 20 < CONSOLE_PANE_MIN {
                c - 20
            } else {
                CONSOLE_PANE_MIN
            };
        }
        pane_w = pane_w.max(0);
        let main_w = if pane_w > 0 { c - pane_w - 1 } else { c };
        let h = (r - 3) as usize;

        // title row
        {
            let row = &mut rows[0];
            row.sgr(SGR_LINE);
            row.text(self.g("─").as_bytes(), 1);
            row.text(b" ", 1);
            let label = format!("[{}:{}]", self.view + 1, VIEW_NAME[self.view]);
            row.sgr(SGR_TITLE);
            row.text(label.as_bytes(), -1);
            row.sgr(SGR_LINE);
            row.text(b" ", 1);
            let n = main_w - row.w;
            row.fill(self.g("─"), n);
            if pane_w > 0 {
                row.text(self.g("┬").as_bytes(), 1);
                row.text(self.g("─").as_bytes(), 1);
                row.sgr(SGR_TITLE);
                row.text(b" network ", -1);
                row.sgr(SGR_LINE);
                let n = c - row.w;
                row.fill(self.g("─"), n);
            }
            row.sgr(SGR_RESET);
        }

        // main pane
        {
            let (_, rest) = rows.split_at_mut(1);
            let body = &mut rest[..h];
            if self.view == V_CONSOLE || self.view == V_LOG {
                let segs = self.sb_layout(self.view, main_w, h);
                for (y, seg) in segs.iter().enumerate() {
                    let Some(l) = self.sb[self.view].as_ref().and_then(|sb| sb.get(seg.seq)) else {
                        continue;
                    };
                    let buf = c_cut(&l.text[seg.from..seg.to], CONSOLE_INPUT_MAX * 2).to_vec();
                    let hit = self.view == V_LOG
                        && !self.search.is_empty()
                        && ci_contains(&l.text, &self.search)
                        && self.anchor[V_LOG] == seg.seq;
                    body[y].sgr(if hit { SGR_SEL } else { kind_sgr(l.kind) });
                    body[y].text(&buf, main_w);
                    body[y].sgr(SGR_RESET);
                }
            } else if self.view == V_NET {
                self.net_view(main_w, h, body, 0);
            } else {
                let text = if self.view == V_UPG {
                    &self.upg_text
                } else {
                    &self.stats_text
                };
                let text = text
                    .clone()
                    .unwrap_or_else(|| b"(asking the hub...)".to_vec());
                self.blob_rows(self.view, &text, main_w, h, body, 0);
            }
            for row in body.iter_mut() {
                row.sgr(SGR_RESET);
                row.pad(main_w);
            }
            // tree pane
            if pane_w > 0 {
                let tr = parse_tree(&self.tree);
                for (y, row) in body.iter_mut().enumerate() {
                    row.sgr(SGR_LINE);
                    row.text(self.g("│").as_bytes(), 1);
                    row.sgr(SGR_RESET);
                    if y < tr.len() {
                        self.tree_line(row, &tr, y, pane_w);
                    } else {
                        let t = row.w + pane_w;
                        row.pad(t);
                    }
                }
            }
        }

        // status bar + input
        let mut sbar = RowB::new(rows[(r - 2) as usize].max);
        self.status_bar(&mut sbar, now_ms, !wide && !overlay);
        rows[(r - 2) as usize] = sbar;
        let (cur_row, cur_col);
        {
            let prompt: &[u8] = if self.searching {
                b"search: "
            } else if self.confirming != Confirm::None {
                b"confirm> "
            } else {
                b"> "
            };
            let row = &mut rows[(r - 1) as usize];
            row.sgr(if self.confirming != Confirm::None {
                "0;1;33"
            } else {
                "0;1"
            });
            row.text(prompt, -1);
            row.sgr(SGR_RESET);
            let pw = row.w;
            let avail = row.max - pw;
            let cw = str_width(&self.input[..self.in_cur]);
            if cw < self.in_scroll {
                self.in_scroll = cw;
            }
            if cw >= self.in_scroll + avail {
                self.in_scroll = cw - avail + 1;
            }
            // skip in_scroll cells
            let mut i = 0;
            let mut skipped = 0;
            while i < self.input.len() && skipped < self.in_scroll {
                let (ul, _, w) = next_char(&self.input[i..]);
                i += ul;
                skipped += w;
            }
            let rest = self.input[i.min(self.input.len())..].to_vec();
            row.text(&rest, avail);
            let m = row.max;
            row.pad(m);
            cur_row = r - 1;
            cur_col = pw + cw - self.in_scroll;
        }
        (rows, cur_row, cur_col)
    }

    fn draw(&mut self, now_ms: i64) {
        if self.line_mode {
            return;
        }
        let r = self.rows as usize;
        let (rows, cr, cc) = self.compose(now_ms);
        if self.prev_rows.len() != r {
            self.prev_rows = vec![None; r];
            self.full_redraw = true;
        }
        self.term.extend_from_slice(b"\x1b[?25l");
        if self.full_redraw {
            self.term.extend_from_slice(b"\x1b[0m\x1b[H\x1b[2J");
        }
        for (y, row) in rows.iter().enumerate() {
            if !self.full_redraw && self.prev_rows[y].as_deref() == Some(row.b.as_slice()) {
                continue;
            }
            self.term
                .extend_from_slice(format!("\x1b[{};1H", y + 1).as_bytes());
            self.term.extend_from_slice(&row.b);
            self.term.extend_from_slice(b"\x1b[0m");
            self.prev_rows[y] = Some(row.b.clone());
        }
        self.term
            .extend_from_slice(format!("\x1b[{};{}H\x1b[?25h", cr + 1, cc + 1).as_bytes());
        self.full_redraw = false;
        self.dirty = false;
        self.last_draw_ms = now_ms;
    }
}

// ===========================================================================
// Lifecycle
// ===========================================================================
impl Ui {
    pub fn new(line_mode: bool, cols: i32, rows: i32, admin: &str, ip: &str, hubname: &str) -> Ui {
        let mk = |cap: usize| Some(Sback::new(cap));
        Ui {
            line_mode,
            ascii: false,
            cols: if cols > 0 && cols < 1000 { cols } else { 80 },
            rows: if rows > 0 && rows < 1000 { rows } else { 24 },
            admin: sanitize(admin.as_bytes(), CONSOLE_NAME_MAX),
            ip: sanitize(ip.as_bytes(), 64),
            hubname: sanitize(hubname.as_bytes(), 64),
            term: Vec::new(),
            core: Vec::new(),
            backlog: 0,
            input: Vec::new(),
            in_cur: 0,
            in_scroll: 0,
            hist: Vec::new(),
            hist_pos: 0,
            hist_stash: Vec::new(),
            esc: Vec::new(),
            esc_ms: 0,
            pasting: false,
            utf8: Vec::new(),
            last_cr: false,
            seq: 0,
            user_busy: false,
            rq: Vec::new(),
            queued: Vec::new(),
            confirming: Confirm::None,
            confirm_seq: 0,
            confirm_want: Vec::new(),
            confirm_q: Vec::new(),
            confirm_op: 0,
            confirm_payload: Vec::new(),
            confirm_rq: None,
            held: Vec::new(),
            dropped: 0,
            st: Status {
                loglevel: -1,
                consolelevel: -1,
                ..Status::default()
            },
            tree: Vec::new(),
            upg_text: None,
            stats_text: None,
            upg_at: 0,
            stats_at: 0,
            log_on: false,
            log_sub_level: LOG_INFO,
            view: V_CONSOLE,
            sb: if line_mode {
                [None, None, None, None, None]
            } else {
                [
                    mk(CONSOLE_SCROLLBACK),
                    mk(CONSOLE_LOG_SCROLLBACK),
                    None,
                    None,
                    None,
                ]
            },
            anchor: [-1; V_COUNT],
            act: [false; V_COUNT],
            pane_user_off: false,
            overlay: false,
            log_show: LOG_DEBUG,
            filter: Vec::new(),
            paused: false,
            paused_next: 0,
            search: Vec::new(),
            searching: false,
            net_sel: 0,
            prev_rows: Vec::new(),
            dirty: false,
            full_redraw: true,
            resize_ms: 0,
            last_draw_ms: 0,
            last_clock_ms: 0,
            last_input_ms: 0,
            started: false,
            audit_q: Vec::new(),
            closing: false,
            close_why: String::new(),
        }
    }

    /// Greeting, first draw, subscriptions.
    pub fn start(&mut self, now_ms: i64) {
        self.last_input_ms = now_ms;
        self.started = true;
        self.subscribe();
        let hub: &[u8] = if self.hubname.is_empty() {
            b"hub"
        } else {
            &self.hubname
        };
        let hello = fmtb(&[
            format!("irchub console {HUB_VERSION} on ").as_bytes(),
            hub,
            b" - logged in as ",
            &self.admin,
        ]);
        let hello = c_cut(&hello, 256).to_vec();
        if self.line_mode {
            self.lm_line(&hello);
            self.lm_prompt();
            return;
        }
        // alternate screen, bracketed paste
        self.term
            .extend_from_slice(b"\x1b[?1049h\x1b[?2004h\x1b[H\x1b[2J");
        self.fs_timestamped(V_CONSOLE, &hello, L_INFO);
        self.fs_timestamped(
            V_CONSOLE,
            b"help lists the commands; Alt+1..5 switch views (or: view <n>)",
            L_INFO,
        );
        self.dirty = true;
    }

    pub fn resize(&mut self, cols: i32, rows: i32, now_ms: i64) {
        if cols > 0 && cols < 1000 {
            self.cols = cols;
        }
        if rows > 0 && rows < 1000 {
            self.rows = rows;
        }
        self.resize_ms = now_ms;
        self.dirty = true;
        self.full_redraw = true;
        if self.cols >= CONSOLE_PANE_MIN_COLS {
            self.overlay = false;
        }
    }

    /// Timers: ESC timeout, coalesced redraws, view refreshes, idle timeout.
    pub fn tick(&mut self, now_ms: i64) {
        if !self.started {
            return;
        }
        if !self.esc.is_empty() && now_ms - self.esc_ms >= CONSOLE_ESC_MS {
            if self.esc.len() == 1 {
                self.handle_key(key(K::Esc, 0), now_ms);
            }
            self.esc.clear();
        }
        if now_ms - self.last_input_ms >= CONSOLE_IDLE_TIMEOUT * 1000 && !self.closing {
            self.closing = true;
            self.close_why = "idle timeout".to_string();
            return;
        }
        if self.dropped > 0 && self.term.len() + self.backlog < CONSOLE_TERM_OUTQ_MAX / 2 {
            let n = self.dropped;
            self.dropped = 0;
            if self.line_mode {
                self.lm_async(format!("[evt drop] {n}").as_bytes());
            } else {
                self.fs_add(
                    V_LOG,
                    format!("[{n} lines dropped]").as_bytes(),
                    L_WARN,
                    LOG_ERROR,
                );
            }
        }
        if self.line_mode {
            return;
        }
        if self.view == V_UPG && now_ms - self.upg_at >= CONSOLE_UPG_REFRESH_MS {
            self.request_view(Rq::ViewUpg, now_ms);
        }
        if self.view == V_STATS && now_ms - self.stats_at >= CONSOLE_STATS_REFRESH_MS {
            self.request_view(Rq::ViewStats, now_ms);
        }
        // the clock, and the idle countdown in its last minute
        let idle_left = CONSOLE_IDLE_TIMEOUT - (now_ms - self.last_input_ms) / 1000;
        let tick = if idle_left <= 60 { 1000 } else { 60000 };
        if now_ms / tick != self.last_clock_ms / tick {
            self.last_clock_ms = now_ms;
            self.dirty = true;
        }
        if (self.dirty || self.full_redraw)
            && now_ms - self.resize_ms >= CONSOLE_RESIZE_MS
            && now_ms - self.last_draw_ms >= 30
            && self.term.len() + self.backlog < CONSOLE_TERM_OUTQ_MAX
        {
            self.draw(now_ms);
        }
    }

    /// Bytes for the terminal (taken).
    pub fn take_term(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.term)
    }

    /// Frames for the core (taken).
    pub fn take_core(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.core)
    }

    /// True once the session should end, with why.
    pub fn closing(&self) -> Option<&str> {
        self.closing.then_some(self.close_why.as_str())
    }

    /// True while a command is in flight, queued or waiting for confirmation.
    pub fn busy(&self) -> bool {
        self.user_busy || !self.queued.is_empty() || self.confirming != Confirm::None
    }

    /// Text for the terminal on the way out (restores the screen).
    pub fn goodbye(&mut self, why: &str) {
        if self.line_mode {
            let m = format!("\r\n[closed] {why}\r\n");
            self.term.extend_from_slice(c_cut(m.as_bytes(), 128));
            return;
        }
        self.term
            .extend_from_slice(b"\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l");
        self.term
            .extend_from_slice(format!("irchub console closed: {why}\r\n").as_bytes());
    }
}

impl Drop for Ui {
    fn drop(&mut self) {
        crate::crypto::wipe(&mut self.input);
        crate::crypto::wipe(&mut self.confirm_payload);
        crate::crypto::wipe(&mut self.term);
        crate::crypto::wipe(&mut self.core);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_matches_c_rules() {
        assert_eq!(sanitize(b"a\tb\x1b[31mc\x07", 64), b"a b[31mc");
        assert_eq!(sanitize(b"\xff\xc3\xa9", 64), "?\u{e9}".as_bytes());
        assert_eq!(sanitize("x\u{85}y".as_bytes(), 64), b"xy");
        // cap: at most cap-1 bytes, never a split character
        assert_eq!(sanitize("ab\u{e9}".as_bytes(), 4), b"ab");
        assert_eq!(sanitize(b"abcdef", 4), b"abc");
    }

    #[test]
    fn keys_decode_across_terminals() {
        assert!(decode_seq(b"[A").t == K::Up);
        assert!(decode_seq(b"OA").t == K::Up);
        let f3 = decode_seq(b"[13~");
        assert!(f3.t == K::F && f3.cp == 3);
        let f2 = decode_seq(b"[[B");
        assert!(f2.t == K::F && f2.cp == 2);
        assert!(decode_seq(b"[1;3D").t == K::AltLeft);
        assert!(decode_seq(b"[200~").t == K::PasteBegin);
        assert_eq!(seq_complete(b"\x1b[1;3"), 0);
        assert_eq!(seq_complete(b"\x1b[1;3D"), 6);
        assert_eq!(seq_complete(b"\x1b1"), 2);
    }

    fn run(ui: &mut Ui, s: &str) -> String {
        ui.input(s.as_bytes(), 1);
        String::from_utf8_lossy(&ui.take_term()).into_owned()
    }

    #[test]
    fn line_mode_markers_and_confirmations() {
        let mut ui = Ui::new(true, 80, 24, "robert", "127.0.0.1", "hub1");
        ui.start(1);
        let hello = String::from_utf8_lossy(&ui.take_term()).into_owned();
        assert_eq!(
            hello,
            format!("irchub console {HUB_VERSION} on hub1 - logged in as robert\r\n> ")
        );
        assert!(run(&mut ui, "foo\r").contains("[err #1] unknown command (help lists them)\r\n> "));
        assert!(
            run(&mut ui, "bot del x|y\r").contains("[err #2] '|' is not allowed in an argument")
        );
        let t = run(&mut ui, "bot del abc\r");
        assert!(
            t.contains("[confirm #3] Really bot del abc? (y/N)\r\n? "),
            "{t}"
        );
        assert!(run(&mut ui, "n\r").contains("[err #3] cancelled\r\n> "));
        let _ = ui.take_core();
        run(&mut ui, "bot list\r");
        let core = ui.take_core();
        assert_eq!(core, [0, 0, 0, 1, CMD_ADMIN_LIST_FULL]);
        ui.core_frame_in(CONSOLE_REPLY, b"--- Registered Bots (0) ---\n", 1);
        let t = String::from_utf8_lossy(&ui.take_term()).into_owned();
        assert_eq!(t, "--- Registered Bots (0) ---\r\n[ok #4] bot list\r\n> ");
        run(&mut ui, "match *\r");
        ui.core_frame_in(CONSOLE_REPLY, b"ERR:user not found", 1);
        let t = String::from_utf8_lossy(&ui.take_term()).into_owned();
        assert_eq!(t, "ERR:user not found\r\n[err #5] ERR:user not found\r\n> ");
    }

    #[test]
    fn events_are_held_during_a_command() {
        let mut ui = Ui::new(true, 80, 24, "a", "ip", "h");
        ui.start(1);
        let _ = ui.take_term();
        ui.core_frame_in(CMD_CONSOLE, b"status|name=h|peers=0/0", 1);
        assert_eq!(
            String::from_utf8_lossy(&ui.take_term()),
            "\r[evt status] name=h|peers=0/0\r\n> "
        );
        run(&mut ui, "stats\r");
        ui.core_frame_in(CMD_CONSOLE, b"tree|H|0|h|u|1|0|2.4.3|rs|0\n", 1);
        assert!(ui.take_term().is_empty());
        ui.core_frame_in(CONSOLE_REPLY, b"stats|up=1", 1);
        assert_eq!(
            String::from_utf8_lossy(&ui.take_term()),
            "stats|up=1\r\n[ok #1] stats\r\n[evt tree] begin 1\r\n[evt tree] H|0|h|u|1|0|2.4.3|rs|0\r\n[evt tree] end\r\n> "
        );
    }
}
