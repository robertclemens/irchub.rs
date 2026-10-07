//! SSH admin console — one session's user interface.  docs/console.md;
//! mirrors irchub `hub_console_ui.c` function for function (the output
//! renderer is `fmt`, hub_console_fmt.c).
//!
//! Runs on the console thread only.  Everything the admin sees is built here:
//! the line-mode transcript (TERM=dumb, the testnet's interface — byte for
//! byte the same as the C hub's) and the full-screen irssi-style console
//! (output pane, network tree, status bar, input line), with the key parser,
//! the command language and the sanitizer that keeps text from bots, peers
//! and logs from reaching the terminal as escape sequences.  Pure state
//! machine: no russh, no HubState.

use super::fmt::{
    self, Ctx, Flines, RL_CMD, RL_DIM, RL_ERR, RL_HEAD, RL_NORMAL, RL_OK, RL_RULE, RL_TITLE,
    RL_WARN,
};
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
pub(crate) fn next_char(s: &[u8]) -> (usize, u32, i32) {
    let mut ul = utf8_len(s);
    if ul == 0 {
        ul = 1;
    }
    let cp = utf8_cp(s, ul);
    (ul, cp, cp_width(cp))
}

pub(crate) fn str_width(s: &[u8]) -> i32 {
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

/// `%.*s` precision for at most `max` bytes of s, never splitting a
/// character — the C `uprec`.
pub(crate) fn uprec(s: &[u8], max: usize) -> usize {
    let n = s.len().min(max);
    if n == max && s.len() > max {
        utf8_cut(s, n)
    } else {
        n
    }
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

/// y/N, type an exact word, or type a number that becomes the payload
#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirm {
    None,
    Yn,
    Type,
    Pick,
}

/// What a request in flight was for: replies come back in order.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Rq {
    #[default]
    User,
    Pre,
    ViewUpg,
    ViewStats,
}

/// A read made before a confirmation so the question can name the object
/// (D2): what it reads, and what the question is built from.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Pre {
    #[default]
    None,
    BotDel,
    BotKick,
    PeerDel,
    Opt,
    UserDel,
    UserKey,
    UpgStart,
}

#[derive(Clone, Default)]
struct PendingRq {
    kind: Rq,
    /// the command number
    seq: i32,
    /// "bot list"
    words: Vec<u8>,
    /// what the audit line says was asked
    audit: Vec<u8>,
    audit_level: i32,
    /// fmt::FMT_MODE_*
    mode: i32,
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

/// The command a pre-read is for, and what its question needs.
#[derive(Clone, Default)]
struct PendCmd {
    pre: Pre,
    op: u8,
    payload: Vec<u8>,
    /// the object: uuid, #, name, flags
    arg: Vec<u8>,
    /// upgrade start: hub=, nodes=, botbase=, hubbase=
    extra: [Vec<u8>; 4],
    rq: PendingRq,
}

/// One entry of the full-screen console view: a finished line, or a reply
/// kept as it came so it can be laid out again at a new width (D5).
#[derive(Clone, Default)]
struct Centry {
    /// a line, or None for a reply
    text: Option<Vec<u8>>,
    kind: u8,
    /// the reply's records
    reply: Option<Vec<u8>>,
    words: Vec<u8>,
    mode: i32,
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
    /// commands run, for the goodbye line
    ncmds: i32,
    user_busy: bool,
    rq: Vec<PendingRq>,
    queued: Vec<Vec<u8>>,
    confirming: Confirm,
    confirm_seq: i32,
    confirm_want: Vec<u8>,
    confirm_pick_max: i32,
    confirm_op: u8,
    confirm_payload: Vec<u8>,
    confirm_rq: PendingRq,
    pend: PendCmd,
    held: Vec<u8>,
    dropped: u64,

    // display settings (docs/console.md §2 display)
    raw: bool,
    /// line mode: 0 default, -1 auto, else n
    width_set: i32,
    events_on: bool,
    greeted: bool,
    now_ms: i64,
    start_ms: i64,

    st: Status,
    /// rows, '\n'-separated; None until the first tree event
    tree: Option<Vec<u8>>,
    upg_text: Option<Vec<u8>>,
    stats_text: Option<Vec<u8>>,
    upg_at: i64,
    stats_at: i64,
    last_upg: Vec<u8>,
    log_on: bool,
    log_sub_level: i32,

    view: usize,
    sb: [Option<Sback>; V_COUNT],
    /// V_CONSOLE entries, a ring (full screen only)
    ent: Option<Vec<Centry>>,
    ent_first: i64,
    ent_next: i64,
    /// width the console view was laid out at
    render_w: i32,
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
// Command table (docs/console.md §2): <noun> <verb> [args] (D15)
// ===========================================================================
#[derive(Clone, Copy, PartialEq, Eq)]
enum B {
    None,
    Arg,
    Pipe,
    PeerAdd,
    PeerDel,
    PeerSet,
    ChanAdd,
    ChanSet,
    ChanOp,
    OptSet,
    LogSet,
    Purge,
    HubSet,
    Acl,
    UserList,
    UserAdd,
    UserSet,
    UserMask,
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
    pre: Pre,
    fixed: &'static str,
    usage: &'static str,
    help: &'static str,
    /// help <group>: a second line for the arguments
    args: Option<&'static str>,
}

macro_rules! cmd {
    ($c:expr, $s:expr, $op:expr, $b:expr, $n:expr, $o:expr, $cf:expr, $pre:expr, $fx:expr, $u:expr, $h:expr, $a:expr) => {
        CmdDef {
            cmd: $c,
            sub: $s,
            op: $op,
            build: $b,
            nargs: $n,
            optargs: $o,
            confirm: $cf,
            pre: $pre,
            fixed: $fx,
            usage: $u,
            help: $h,
            args: $a,
        }
    };
}

use Confirm as Cf;
#[rustfmt::skip]
const CMDS: &[CmdDef] = &[
    cmd!("help", None, 0, B::Local, 0, 2, Cf::None, Pre::None, "", "help [group [command]]", "the command groups, one group's commands, or one command in full (? does the same)", None),
    cmd!("quit", None, 0, B::Local, 0, 0, Cf::None, Pre::None, "", "quit", "close this console", None),
    cmd!("bot", Some("list"), CMD_ADMIN_LIST_FULL, B::None, 0, 0, Cf::None, Pre::None, "", "bot list", "every registered bot: state, hub, version, last seen", None),
    cmd!("bot", Some("show"), CMD_ADMIN_LIST_FULL, B::Arg, 1, 0, Cf::None, Pre::None, "", "bot show <uuid|nick>", "one bot in detail", None),
    cmd!("bot", Some("summary"), CMD_ADMIN_LIST_SUMMARY, B::None, 0, 0, Cf::None, Pre::None, "", "bot summary", "every bot's nick and uuid", None),
    cmd!("bot", Some("pending"), CMD_ADMIN_GET_PENDING, B::None, 0, 0, Cf::None, Pre::None, "", "bot pending", "bots that tried to connect but are not authorized", None),
    cmd!("bot", Some("approve"), CMD_ADMIN_APPROVE, B::Arg, 1, 0, Cf::None, Pre::None, "", "bot approve <#|uuid>", "approve a pending bot; # is the number from bot pending", None),
    cmd!("bot", Some("authorize"), CMD_ADMIN_ADD, B::Arg, 1, 0, Cf::None, Pre::None, "", "bot authorize <uuid>", "authorize a uuid before the bot first connects", None),
    cmd!("bot", Some("add"), CMD_ADMIN_CREATE_BOT, B::Pipe, 3, 0, Cf::None, Pre::None, "", "bot add <nick> <uuid> <key>", "register a bot from the identity its -setup printed", Some("key: the 88-char base64 public key")),
    cmd!("bot", Some("del"), CMD_ADMIN_DEL, B::Arg, 1, 0, Cf::Yn, Pre::BotDel, "", "bot del <uuid>", "delete a bot everywhere (asks y/N; disconnects it)", None),
    cmd!("bot", Some("kick"), CMD_ADMIN_DISCONNECT_BOT, B::Arg, 1, 0, Cf::Yn, Pre::BotKick, "", "bot kick <uuid>", "drop its connection to this hub (asks y/N; it reconnects)", None),
    cmd!("bot", Some("rekey"), CMD_ADMIN_REKEY_BOT, B::Arg, 1, 0, Cf::None, Pre::None, "", "bot rekey <uuid>", "how to rekey a bot (only the bot can)", None),
    cmd!("peer", Some("list"), CMD_ADMIN_LIST_PEERS, B::None, 0, 0, Cf::None, Pre::None, "", "peer list", "peer hubs, the mesh links and their health", None),
    cmd!("peer", Some("show"), CMD_ADMIN_LIST_PEERS, B::Arg, 1, 0, Cf::None, Pre::None, "", "peer show <#|uuid|name>", "one peer hub in detail", None),
    cmd!("peer", Some("add"), CMD_ADMIN_ADD_PEER, B::PeerAdd, 5, 0, Cf::None, Pre::None, "", "peer add <ip> <port> <uuid> <name|-> <key>", "add a peer hub", Some("key: the 88-char key from that hub's hub show")),
    cmd!("peer", Some("del"), CMD_ADMIN_DEL_PEER, B::PeerDel, 0, 1, Cf::Type, Pre::PeerDel, "", "peer del [#]", "remove a peer hub (types its number to confirm)", None),
    cmd!("peer", Some("set"), CMD_ADMIN_SET_PEER_PUBKEY, B::PeerSet, 3, 0, Cf::None, Pre::None, "", "peer set <#|uuid|name> key <key>", "replace a peer's key (the link comes back with it)", None),
    cmd!("peer", Some("sync"), CMD_ADMIN_SYNC_MESH, B::None, 0, 0, Cf::None, Pre::None, "", "peer sync", "send a full sync to every peer", None),
    cmd!("network", Some("tree"), CMD_CONSOLE, B::Fixed, 0, 0, Cf::None, Pre::None, "get|tree", "network tree", "every hub and bot as a tree", None),
    cmd!("network", Some("status"), CMD_CONSOLE, B::Fixed, 0, 0, Cf::None, Pre::None, "get|status", "network status", "the mesh-wide status (what the status bar shows)", None),
    cmd!("hub", Some("show"), CMD_ADMIN_GET_PUBKEY, B::None, 0, 0, Cf::None, Pre::None, "", "hub show", "this hub: identity, key, listener, counts", None),
    cmd!("hub", Some("set"), 0, B::HubSet, 0, 2, Cf::None, Pre::None, "", "hub set <setting> <value>", "name, bindip, port, pubkey or autopurge (alone: the table)", None),
    cmd!("hub", Some("stats"), CMD_ADMIN_STATS, B::None, 0, 0, Cf::None, Pre::None, "", "hub stats", "traffic counters since the hub started", None),
    cmd!("hub", Some("rekey"), CMD_ADMIN_REGEN_KEYS, B::None, 0, 0, Cf::Type, Pre::None, "", "hub rekey", "new hub keypair; every peer and bot must re-learn it", None),
    cmd!("hub", Some("purge"), CMD_ADMIN_PURGE_TOMBSTONES, B::Purge, 1, 0, Cf::Yn, Pre::None, "", "hub purge <now|days>", "purge tombstones now, or those older than <days>", None),
    cmd!("log", Some("show"), CMD_CONSOLE, B::Fixed, 0, 0, Cf::None, Pre::None, "get|log", "log show", "log levels, sizes and this session's log", None),
    cmd!("log", Some("set"), 0, B::LogSet, 2, 0, Cf::None, Pre::None, "", "log set file|console|size <value>", "the file or console ring level, or the file size limit", Some("level: none error warning info debug or 0-4 · size: <MB>, <n>k or <n>b, at most 1024 MB")),
    cmd!("log", Some("on"), 0, B::Local, 0, 1, Cf::None, Pre::None, "", "log on [level]", "line mode: stream hub log lines", None),
    cmd!("log", Some("off"), 0, B::Local, 0, 0, Cf::None, Pre::None, "", "log off", "line mode: stop the log lines", None),
    cmd!("log", Some("filter"), 0, B::Local, 1, 64, Cf::None, Pre::None, "", "log filter <text|clear>", "full screen: log view lines containing <text>", None),
    cmd!("acl", Some("list"), CMD_ADMIN_LIST_ALLOWLIST, B::None, 0, 0, Cf::None, Pre::None, "", "acl list", "the allow and deny lists", None),
    cmd!("acl", Some("add"), 0, B::Acl, 2, 0, Cf::None, Pre::None, "", "acl add allow|deny <ip[/n]>", "add an address or network", None),
    cmd!("acl", Some("del"), 0, B::Acl, 2, 0, Cf::Yn, Pre::None, "", "acl del allow|deny <ip[/n]>", "remove an address or network (asks y/N)", None),
    cmd!("option", Some("list"), CMD_ADMIN_GET_OPT_FLAGS, B::None, 0, 0, Cf::None, Pre::None, "", "option list", "the network option flags", None),
    cmd!("option", Some("set"), CMD_ADMIN_SET_OPT_FLAGS, B::OptSet, 1, 0, Cf::Yn, Pre::Opt, "", "option set <flags|->", "set the network option flags (- clears)", None),
    cmd!("user", Some("list"), 0, B::UserList, 0, 1, Cf::None, Pre::None, "", "user list [admin|oper]", "every user (or one role): key, last seen, masks", None),
    cmd!("user", Some("show"), CMD_ADMIN_MATCH, B::Arg, 1, 0, Cf::None, Pre::None, "", "user show <name|*>", "one user (or all) with masks and their last use", None),
    cmd!("user", Some("add"), 0, B::UserAdd, 4, 0, Cf::None, Pre::None, "", "user add admin|oper <name> <key> <mask>", "add an admin or an oper", Some("key: their 88-char public key · mask: nick!user@host")),
    cmd!("user", Some("del"), CMD_ADMIN_DEL_ADMIN, B::Arg, 1, 0, Cf::Yn, Pre::UserDel, "", "user del <name>", "remove a user and their masks", None),
    cmd!("user", Some("set"), CMD_ADMIN_SET_USERKEY, B::UserSet, 3, 0, Cf::Yn, Pre::UserKey, "", "user set <name> key <key>", "replace a user's key (asks y/N)", None),
    cmd!("user", Some("mask"), 0, B::UserMask, 3, 0, Cf::None, Pre::None, "", "user mask add|del <name> <mask>", "add or remove a usermask (del asks y/N)", None),
    cmd!("channel", Some("list"), CMD_ADMIN_LIST_CHANNELS, B::None, 0, 0, Cf::None, Pre::None, "", "channel list", "every managed channel with its settings", None),
    cmd!("channel", Some("show"), CMD_ADMIN_LIST_CHANNELS, B::Arg, 1, 0, Cf::None, Pre::None, "", "channel show <#chan>", "one channel in detail", None),
    cmd!("channel", Some("add"), CMD_ADMIN_ADD_CHANNEL, B::ChanAdd, 1, 1, Cf::None, Pre::None, "", "channel add <#chan> [key]", "add (or re-add) a channel", None),
    cmd!("channel", Some("del"), CMD_ADMIN_DEL_CHANNEL, B::Arg, 1, 0, Cf::Yn, Pre::None, "", "channel del <#chan>", "remove it from every bot (asks y/N)", None),
    cmd!("channel", Some("set"), CMD_ADMIN_ADD_CHANNEL, B::ChanSet, 3, 0, Cf::None, Pre::None, "", "channel set <#chan> <setting> <value|->", "change one setting (key today; - clears)", None),
    cmd!("channel", Some("op"), CMD_ADMIN_OP_USER, B::ChanOp, 2, 0, Cf::None, Pre::None, "", "channel op <#chan> <nick>", "have the bots op a user", None),
    cmd!("upgrade", Some("status"), CMD_ADMIN_UPGRADE_STATUS, B::Fixed, 0, 0, Cf::None, Pre::None, "", "upgrade status", "the upgrade run on this hub", None),
    cmd!("upgrade", Some("releases"), CMD_ADMIN_UPGRADE_STATUS, B::UpgReleases, 0, 2, Cf::None, Pre::None, "", "upgrade releases [bot=<base>] [hub=<base>]", "releases both products offer, and the nodes", None),
    cmd!("upgrade", Some("start"), CMD_ADMIN_UPGRADE_NET, B::UpgStart, 1, 4, Cf::Type, Pre::UpgStart, "", "upgrade start <botver> [hub=<ver>] [nodes=<a,b=c>] [botbase=<url>] [hubbase=<url>]", "start a rolling network upgrade", None),
    cmd!("upgrade", Some("abort"), CMD_ADMIN_UPGRADE_STATUS, B::Fixed, 0, 0, Cf::Yn, Pre::None, "abort", "upgrade abort", "stop the run and roll back", None),
    cmd!("upgrade", Some("forget"), CMD_ADMIN_UPGRADE_STATUS, B::Fixed, 0, 0, Cf::Yn, Pre::None, "forget", "upgrade forget", "drop the roll-up plan on every hub", None),
    cmd!("display", Some("show"), 0, B::Local, 0, 0, Cf::None, Pre::None, "", "display show", "this session's display settings", None),
    cmd!("display", Some("view"), 0, B::Local, 1, 0, Cf::None, Pre::None, "", "display view <1-5>", "full screen: console, log, network, upgrades, stats", None),
    cmd!("display", Some("pane"), 0, B::Local, 0, 0, Cf::None, Pre::None, "", "display pane", "full screen: show or hide the tree pane (F3)", None),
    cmd!("display", Some("ascii"), 0, B::Local, 0, 0, Cf::None, Pre::None, "", "display ascii", "plain ASCII glyphs for this session (again: Unicode)", None),
    cmd!("display", Some("format"), 0, B::Local, 1, 0, Cf::None, Pre::None, "", "display format pretty|raw", "laid-out output, or the records as the hub sends them", None),
    cmd!("display", Some("width"), 0, B::Local, 1, 0, Cf::None, Pre::None, "", "display width <60-250|auto>", "line mode: the output width", None),
    cmd!("display", Some("events"), 0, B::Local, 1, 0, Cf::None, Pre::None, "", "display events on|off", "line mode: a line for each peer, bot and upgrade change", None),
    cmd!("display", Some("clear"), 0, B::Local, 0, 0, Cf::None, Pre::None, "", "display clear", "full screen: clear the current view", None),
];

/// The root nouns, in help order, with what each groups.
const GROUPS: [(&str, &str); 11] = [
    ("bot", "registered bots"),
    ("peer", "peer hubs"),
    ("network", "the whole mesh"),
    ("hub", "this hub"),
    ("log", "the hub log"),
    ("acl", "IP allow / deny lists"),
    ("option", "network option flags"),
    ("user", "admins and opers"),
    ("channel", "managed channels"),
    ("upgrade", "rolling upgrades"),
    ("display", "this session's screen"),
];

/// help <group> <command> (§2.2): each argument, then examples that run as
/// typed.  args: "name\ttext" lines; examples: one per line.
macro_rules! ex_uuid {
    () => {
        "00010203-0405-4607-8809-0a0b0c0d0e0f"
    };
}
macro_rules! ex_key {
    () => {
        "O7Eu2jwpjbXeJVl/VNkk8uF+eKJq2JU+2CGO5oLwu76QIeLzAJ0VLJEb8fJexoOpAnFBZnZ6+9jlvQ+wEk7Lig=="
    };
}

/// (cmd, sub, args, examples)
type CmdHelp = (
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    &'static str,
);

#[rustfmt::skip]
const CMD_HELP: &[CmdHelp] = &[
    ("help", None,
     Some("group\tone of: bot peer network hub log acl option user channel upgrade display\n\
           command\tone of that group's commands: its arguments and an example\n\
           ?\ttyped in place of help it does the same"),
     "help\nhelp bot\nhelp bot add\n? upgrade start"),
    ("quit", None, None, "quit"),
    ("bot", Some("list"), None, "bot list"),
    ("bot", Some("show"), Some("uuid|nick\tthe bot's uuid or its current nick (Tab completes both)"),
     concat!("bot show alpha\nbot show ", ex_uuid!())),
    ("bot", Some("summary"), None, "bot summary"),
    ("bot", Some("pending"), None, "bot pending"),
    ("bot", Some("approve"),
     Some("#|uuid\tthe number bot pending shows in its # column, or the pending bot's uuid"),
     concat!("bot approve 1\nbot approve ", ex_uuid!())),
    ("bot", Some("authorize"), Some("uuid\tthe uuid of a bot that has not connected yet"),
     concat!("bot authorize ", ex_uuid!())),
    ("bot", Some("add"),
     Some("nick\tthe bot's IRC nick\n\
           uuid\tthe uuid the bot's -setup printed\n\
           key\tthe 88-character base64 public key the bot's -setup printed"),
     concat!("bot add alpha ", ex_uuid!(), " ", ex_key!())),
    ("bot", Some("del"), Some("uuid\tthe bot's uuid (Tab completes); asks y/N, then disconnects it"),
     concat!("bot del ", ex_uuid!())),
    ("bot", Some("kick"), Some("uuid\ta connected bot's uuid (Tab completes); asks y/N; it reconnects"),
     concat!("bot kick ", ex_uuid!())),
    ("bot", Some("rekey"), Some("uuid\tthe bot's uuid; prints how to rekey it on its host"),
     concat!("bot rekey ", ex_uuid!())),
    ("peer", Some("list"), None, "peer list"),
    ("peer", Some("show"), Some("#|uuid|name\tthe number peer list shows, the hub's uuid, or its name"),
     "peer show 1\npeer show east"),
    ("peer", Some("add"),
     Some("ip\tthe peer hub's address (no ':', so an IPv4 address or a host name)\n\
           port\tits listening port, 1-65535\n\
           uuid\tits uuid, from hub show on that hub\n\
           name|-\ta name for it, or - to learn its name from the peer\n\
           key\tthe 88-character public key from hub show on that hub"),
     concat!("peer add 203.0.113.7 6697 ", ex_uuid!(), " east ", ex_key!(), "\n",
             "peer add 203.0.113.7 6697 ", ex_uuid!(), " - ", ex_key!())),
    ("peer", Some("del"), Some("#\tthe number peer list shows; alone it lists the peers to pick from; \
                                 you type the number again to confirm"),
     "peer del\npeer del 2"),
    ("peer", Some("set"),
     Some("#|uuid|name\tthe peer: its number in peer list, its uuid, or its name\n\
           key\tthe setting; key is the only one\n\
           key\tthe new 88-character public key from hub show on that hub"),
     concat!("peer set east key ", ex_key!())),
    ("peer", Some("sync"), None, "peer sync"),
    ("network", Some("tree"), None, "network tree"),
    ("network", Some("status"), None, "network status"),
    ("hub", Some("show"), None, "hub show"),
    ("hub", Some("set"),
     Some("setting\tname, bindip, port, pubkey or autopurge; alone it shows them all\n\
           value\tname: this hub's name · bindip: the address it listens on · port: 1-65535 · \
           pubkey: the key its private key derives (a new key is hub rekey) · \
           autopurge: days to keep tombstones, 0 = off"),
     "hub set\nhub set name west\nhub set port 6697\nhub set autopurge 30"),
    ("hub", Some("stats"), None, "hub stats"),
    ("hub", Some("rekey"), Some("(confirm)\tyou type this hub's name to go ahead; every peer and bot \
                                 must then learn the new key"),
     "hub rekey"),
    ("hub", Some("purge"), Some("now|days\tnow purges every tombstone; a number purges those older \
                                 than that many days (asks y/N)"),
     "hub purge now\nhub purge 30"),
    ("log", Some("show"), None, "log show"),
    ("log", Some("set"),
     Some("file|console|size\twhich: the log file's level, the console ring's level, or the file \
           size limit\n\
           value\ta level (none error warning info debug, or 0-4) for file and console; for size \
           <MB>, <n>k or <n>b, at most 1024 MB"),
     "log set file info\nlog set console debug\nlog set size 50\nlog set size 512k"),
    ("log", Some("on"), Some("level\tnone error warning info debug, or 0-4 (default info)"),
     "log on\nlog on debug"),
    ("log", Some("off"), None, "log off"),
    ("log", Some("filter"), Some("text|clear\tthe rest of the line is the text a log view line must \
                                  contain (any case); clear drops the filter"),
     "log filter UPGRADE\nlog filter peer east\nlog filter clear"),
    ("acl", Some("list"), None, "acl list"),
    ("acl", Some("add"),
     Some("allow|deny\twhich list\n\
           ip[/n]\tan IPv4 or IPv6 address, or a network as address/prefix"),
     "acl add allow 203.0.113.0/24\nacl add deny 198.51.100.9"),
    ("acl", Some("del"),
     Some("allow|deny\twhich list\n\
           ip[/n]\tthe entry exactly as acl list shows it (asks y/N)"),
     "acl del deny 198.51.100.9"),
    ("option", Some("list"), None, "option list"),
    ("option", Some("set"), Some("flags|-\tthe whole new set of flag letters (it replaces the old \
                                  set; option list explains each); - clears them all (asks y/N)"),
     "option set h\noption set -"),
    ("user", Some("list"), Some("admin|oper\tonly that role (default both)"),
     "user list\nuser list oper"),
    ("user", Some("show"), Some("name|*\ta user's name, or * for every user"), "user show robert\nuser show *"),
    ("user", Some("add"),
     Some("admin|oper\tthe role\n\
           name\tthe user's name\n\
           key\ttheir 88-character public key (keygen's <stamp>_<name>.public.b64)\n\
           mask\ta first usermask, nick!user@host (* and ? match)"),
     concat!("user add oper alice ", ex_key!(), " alice!*@*.example.net")),
    ("user", Some("del"), Some("name\tthe user, either role; their masks go too (an admin: type the \
                                name to confirm; an oper: y/N)"), "user del alice"),
    ("user", Some("set"),
     Some("name\tthe user\n\
           key\tthe setting; key is the only one\n\
           key\ttheir new 88-character public key (asks y/N)"),
     concat!("user set alice key ", ex_key!())),
    ("user", Some("mask"),
     Some("add|del\tadd a mask, or remove one (del asks y/N)\n\
           name\tthe user\n\
           mask\tnick!user@host (* and ? match)"),
     "user mask add alice alice!*@203.0.113.*\nuser mask del alice alice!*@*.example.net"),
    ("channel", Some("list"), None, "channel list"),
    ("channel", Some("show"), Some("#chan\tthe channel's name"), "channel show #ops"),
    ("channel", Some("add"), Some("#chan\tthe channel's name\nkey\tits channel key, if it has one"),
     "channel add #ops\nchannel add #ops s3cret"),
    ("channel", Some("del"), Some("#chan\tthe channel; every bot parts it (asks y/N)"), "channel del #ops"),
    ("channel", Some("set"),
     Some("#chan\tthe channel\n\
           setting\tthe setting's name; key today\n\
           value|-\tthe new value (at most 128 bytes), or - to clear it"),
     "channel set #ops key s3cret\nchannel set #ops key -"),
    ("channel", Some("op"), Some("#chan\tthe channel\nnick\tthe user's current nick on IRC"),
     "channel op #ops alice"),
    ("upgrade", Some("status"), None, "upgrade status"),
    ("upgrade", Some("releases"),
     Some("bot=<base>\ta different release site for the bot builds (a URL)\n\
           hub=<base>\ta different release site for the hub builds (a URL)"),
     "upgrade releases\nupgrade releases bot=https://example.net/ircbot"),
    ("upgrade", Some("start"),
     Some("botver\tthe bot version to move to, as upgrade releases lists it\n\
           hub=<ver>\talso move the hubs to this version (- = leave them)\n\
           nodes=<sel>\tonly these nodes: names or uuids, comma-separated; name=c or name=rs \
           also switches that node's build (default: the whole network)\n\
           botbase=<url>\ta different release site for the bot builds\n\
           hubbase=<url>\ta different release site for the hub builds\n\
           (confirm)\tit shows the plan, then you type the bot version to start"),
     "upgrade start 2.4.6\nupgrade start 2.4.6 hub=2.4.4\nupgrade start 2.4.6 nodes=alpha,beta=rs"),
    ("upgrade", Some("abort"), None, "upgrade abort"),
    ("upgrade", Some("forget"), None, "upgrade forget"),
    ("display", Some("show"), None, "display show"),
    ("display", Some("view"), Some("1-5\t1 console, 2 log, 3 network, 4 upgrades, 5 stats (Alt+1..5)"),
     "display view 2"),
    ("display", Some("pane"), None, "display pane"),
    ("display", Some("ascii"), None, "display ascii"),
    ("display", Some("format"), Some("pretty|raw\tpretty lays replies out; raw shows the records as the \
                                       hub sent them"),
     "display format raw\ndisplay format pretty"),
    ("display", Some("width"), Some("60-250|auto\tthe columns to lay output out for; auto follows the \
                                      terminal"),
     "display width 100\ndisplay width auto"),
    ("display", Some("events"), Some("on|off\ta line for each peer, bot and upgrade change"),
     "display events on"),
    ("display", Some("clear"), None, "display clear"),
];

const LEVEL_WORD: [&str; 5] = ["none", "error", "warning", "info", "debug"];

/// What Tab offers for one argument of a command (docs/console.md §2).
#[derive(Clone, Copy, PartialEq)]
enum Ck {
    Group,
    Words(&'static str),
    Bot,
    BotOn,
    BotNick,
    HubName,
}

/// (cmd, sub, argument index after cmd [sub] or None = any, kind)
type ArgComp = (&'static str, Option<&'static str>, Option<usize>, Ck);

const LEVEL_WORDS: &str = "none error warning info debug";
const ARG_COMP: &[ArgComp] = &[
    ("help", None, Some(0), Ck::Group),
    ("bot", Some("show"), Some(0), Ck::BotNick),
    ("bot", Some("del"), Some(0), Ck::Bot),
    ("bot", Some("kick"), Some(0), Ck::BotOn),
    ("bot", Some("rekey"), Some(0), Ck::Bot),
    ("peer", Some("show"), Some(0), Ck::HubName),
    ("peer", Some("set"), Some(0), Ck::HubName),
    ("peer", Some("set"), Some(1), Ck::Words("key")),
    (
        "hub",
        Some("set"),
        Some(0),
        Ck::Words("name bindip port pubkey autopurge"),
    ),
    ("hub", Some("purge"), Some(0), Ck::Words("now")),
    ("log", Some("set"), Some(0), Ck::Words("file console size")),
    // after file|console
    ("log", Some("set"), Some(1), Ck::Words(LEVEL_WORDS)),
    ("log", Some("on"), Some(0), Ck::Words(LEVEL_WORDS)),
    ("log", Some("filter"), Some(0), Ck::Words("clear")),
    ("acl", Some("add"), Some(0), Ck::Words("allow deny")),
    ("acl", Some("del"), Some(0), Ck::Words("allow deny")),
    ("user", Some("list"), Some(0), Ck::Words("admin oper")),
    ("user", Some("add"), Some(0), Ck::Words("admin oper")),
    ("user", Some("set"), Some(1), Ck::Words("key")),
    ("user", Some("mask"), Some(0), Ck::Words("add del")),
    ("channel", Some("set"), Some(1), Ck::Words("key")),
    ("upgrade", Some("releases"), None, Ck::Words("bot= hub=")),
    (
        "upgrade",
        Some("start"),
        None,
        Ck::Words("hub= nodes= botbase= hubbase="),
    ),
    ("display", Some("view"), Some(0), Ck::Words("1 2 3 4 5")),
    ("display", Some("format"), Some(0), Ck::Words("pretty raw")),
    ("display", Some("width"), Some(0), Ck::Words("auto")),
    ("display", Some("events"), Some(0), Ck::Words("on off")),
];

fn cmd_has_subs(cmd: &[u8]) -> bool {
    CMDS.iter().any(|d| d.sub.is_some() && eq_ic(cmd, d.cmd))
}

fn now_s() -> i64 {
    crate::cstr::now()
}

/// "HH:MM:SSZ" (or "HH:MMZ") now, UTC (D3).
fn clock_utc(secs: bool) -> Vec<u8> {
    let t = now_s();
    let s = ((t % 86400) + 86400) % 86400;
    if secs {
        format!("{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60).into_bytes()
    } else {
        format!("{:02}:{:02}Z", s / 3600, s / 60 % 60).into_bytes()
    }
}

/// sscanf(v, "%d/%d", &a, &b): only what parses is assigned (a field that
/// does not parse keeps its earlier value, as sscanf leaves it alone).
fn scan_pair(v: &[u8], a: &mut i32, b: &mut i32) {
    let digits = |s: &[u8]| -> Option<(i32, usize)> {
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
        Some((fmt::atoi(&s[st..i]), i))
    };
    let Some((x, n)) = digits(v) else {
        return;
    };
    *a = x;
    if v.get(n) != Some(&b'/') {
        return;
    }
    if let Some((y, _)) = digits(&v[n + 1..]) {
        *b = y;
    }
}

/// The bytes before the first NUL (what a C string of them holds).
fn cstr(s: &[u8]) -> &[u8] {
    match s.iter().position(|&b| b == 0) {
        Some(n) => &s[..n],
        None => s,
    }
}

/// `%-*s` / `%*s`: pad with spaces to n bytes (left or right aligned).
fn padl(s: &[u8], n: usize) -> Vec<u8> {
    pad_bytes(s, n)
}
fn padr(s: &[u8], n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    while v.len() + s.len() < n {
        v.push(b' ');
    }
    v.extend_from_slice(s);
    v
}

impl Ui {
    // -----------------------------------------------------------------------
    // Output helpers
    // -----------------------------------------------------------------------
    /// An audit line: a C char[384] keeps 383 bytes, cut anywhere.
    fn audit(&mut self, level: i32, msg: Vec<u8>) {
        if self.audit_q.len() >= MAX_AUDIT {
            return;
        }
        self.audit_q.push((level, fmt::snp(384, msg)));
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
        if self.ascii {
            let a = fmt::ascii(s);
            self.term.extend_from_slice(&a);
        } else {
            self.term.extend_from_slice(s);
        }
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
        self.term.extend_from_slice(&self.input);
    }

    /// Line mode: something arrives while the admin is at the prompt.  A CR
    /// puts it over the prompt (a reader takes the text after a line's last
    /// CR), then the prompt and the partial input are printed again.  While
    /// a command is in flight it is held until that command's marker.
    fn lm_async(&mut self, text: &[u8]) {
        if self.term.len() + self.backlog + self.held.len() > CONSOLE_TERM_OUTQ_MAX {
            self.dropped = self.dropped.wrapping_add(1);
            return;
        }
        let hold = self.user_busy || self.confirming != Confirm::None;
        let mut out = Vec::with_capacity(text.len() + 16);
        if !hold {
            out.push(b'\r');
        }
        let a;
        let text = if self.ascii {
            a = fmt::ascii(text);
            a.as_slice()
        } else {
            text
        };
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

    /// The width output is laid out for (§1.4).
    fn out_width(&self) -> i32 {
        if !self.line_mode {
            return self.main_width();
        }
        if self.width_set > 0 {
            return self.width_set;
        }
        if self.width_set < 0 {
            return self.cols.clamp(CONSOLE_MIN_COLS, fmt::CONSOLE_WIDTH_MAX);
        }
        fmt::CONSOLE_LINE_WIDTH
    }

    fn session_log_phrase(&self, cap: usize) -> Vec<u8> {
        let v = if self.line_mode {
            if self.log_on {
                fmtb(&[
                    LEVEL_WORD[self.log_sub_level as usize].as_bytes(),
                    b" and worse (log on)",
                ])
            } else {
                b"off (log on [level] streams it here)".to_vec()
            }
        } else {
            fmtb(&[
                b"log view (Alt+2): ",
                LEVEL_WORD[self.log_show as usize].as_bytes(),
                b" and worse",
                if self.filter.is_empty() {
                    b""
                } else {
                    b", filter "
                },
                &self.filter,
            ])
        };
        c_cut(&v, cap).to_vec()
    }

    /// The renderer's context.  Full screen keeps its lines in Unicode and
    /// shows them through fmt::ascii, so display ascii can change every line
    /// both ways; line mode renders ASCII glyphs directly.
    fn ctx<'a>(&'a self, mode: i32, slog: &'a [u8]) -> Ctx<'a> {
        Ctx {
            width: self.out_width(),
            ascii: self.ascii && self.line_mode,
            now: now_s(),
            admin: &self.admin,
            ip: &self.ip,
            hubname: &self.hubname,
            mode,
            session_log: slog,
        }
    }

    /// Full screen: add a line to a view's scrollback.
    fn fs_add(&mut self, view: usize, text: &[u8], kind: u8, level: i32) {
        // the console view is rebuilt on a glyph change (relayout), so it
        // holds the shown form; other views are filtered as drawn (rb_text)
        let a;
        let text = if self.ascii && view == V_CONSOLE {
            a = fmt::ascii(text);
            a.as_slice()
        } else {
            text
        };
        if let Some(sb) = self.sb[view].as_mut() {
            sb.add(text, kind, level);
        }
        if view != self.view && (view != V_LOG || level <= LOG_WARNING) {
            self.act[view] = true;
        }
        self.dirty = true;
    }

    fn ent_push(
        &mut self,
        text: Option<&[u8]>,
        kind: u8,
        reply: Option<&[u8]>,
        words: Option<&[u8]>,
        mode: i32,
    ) {
        let next = self.ent_next;
        let Some(ent) = self.ent.as_mut() else {
            return;
        };
        ent[(next % CONSOLE_SCROLLBACK as i64) as usize] = Centry {
            text: text.map(|t| cstr(t).to_vec()),
            kind,
            reply: reply.map(|r| cstr(r).to_vec()),
            words: words.map_or_else(Vec::new, |w| c_cut(w, 32).to_vec()),
            mode,
        };
        self.ent_next += 1;
        if self.ent_next - self.ent_first > CONSOLE_SCROLLBACK as i64 {
            self.ent_first = self.ent_next - CONSOLE_SCROLLBACK as i64;
        }
    }

    /// Full screen: a finished console-view line (kept for a re-layout).
    fn fs_line(&mut self, text: &[u8], kind: u8) {
        self.fs_add(V_CONSOLE, text, kind, LOG_INFO);
        self.ent_push(Some(text), kind, None, None, 0);
    }

    fn fs_timestamped(&mut self, view: usize, text: &[u8], kind: u8) {
        let buf = fmtb(&[&clock_utc(true), b" ", text]);
        let buf = c_cut(&buf, CONSOLE_INPUT_MAX + 32).to_vec();
        if view == V_CONSOLE {
            self.fs_line(&buf, kind);
        } else {
            self.fs_add(view, &buf, kind, LOG_INFO);
        }
    }

    /// Lines into the current output: line mode prints, the full screen
    /// keeps.
    fn emit_flines(&mut self, mut f: Flines) {
        if !self.raw {
            fmt::wrap(&mut f, self.out_width());
        }
        for l in &f {
            if self.line_mode {
                self.lm_line(&l.text);
            } else {
                self.fs_line(&l.text, l.role);
            }
        }
    }

    /// A console-side note (help, a refused command) in either mode.
    fn note(&mut self, text: &[u8], kind: u8) {
        if self.line_mode {
            self.lm_line(text);
        } else {
            self.fs_timestamped(V_CONSOLE, text, kind);
        }
    }

    /// Render a reply into lines (pretty) for the current width.
    fn render_reply(&self, text: &[u8], words: &[u8], mode: i32) -> Flines {
        let rep = fmt::creply_parse(text);
        let sl = self.session_log_phrase(128);
        let mut c = self.ctx(mode, &sl);
        c.ascii = self.ascii; // re-rendered by relayout() on a change
        let mut f = Flines::new();
        fmt::reply(&c, &rep, words, &mut f);
        f
    }

    /// Show a reply: laid out (pretty) or as records (raw).
    fn show_reply(&mut self, text: &[u8], words: &[u8], mode: i32, err: bool) {
        if self.raw {
            let f = raw_lines(text, if err { RL_ERR } else { RL_NORMAL });
            self.emit_flines(f);
        } else if self.line_mode {
            let f = self.render_reply(text, words, mode);
            self.emit_flines(f);
        } else {
            // kept as records so a resize lays it out again (D5)
            let f = self.render_reply(text, words, mode);
            for l in &f {
                self.fs_add(V_CONSOLE, &l.text, l.role, LOG_INFO);
            }
            self.ent_push(None, 0, Some(text), Some(words), mode);
        }
    }

    // -----------------------------------------------------------------------
    // Replies and events from the core
    // -----------------------------------------------------------------------
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
            if self.confirming == Confirm::None {
                self.flush_held();
            }
            self.lm_prompt();
        }
    }

    fn marker_ok(&mut self, seq: i32, words: &[u8]) {
        if self.line_mode {
            let m = fmtb(&[format!("[ok #{seq}] ").as_bytes(), words]);
            self.lm_line(c_cut(&m, 96));
        }
    }

    /// The error marker: "<msg>" (pretty) or "<code>: <msg>" (raw, D6).
    fn marker_err(&mut self, seq: i32, code: &[u8], msg: &[u8]) {
        if !self.line_mode {
            return;
        }
        let head = format!("[err #{seq}] ");
        let m = if self.raw && !code.is_empty() {
            let mm: &[u8] = if msg.is_empty() { code } else { msg };
            fmtb(&[head.as_bytes(), code, b": ", mm])
        } else {
            let mm: &[u8] = if msg.is_empty() { code } else { msg };
            fmtb(&[head.as_bytes(), mm])
        };
        self.lm_line(c_cut(&m, CONSOLE_INPUT_MAX + 96));
    }

    /// A console-side refusal: the ✗ block (pretty), then the marker.
    fn refuse(&mut self, seq: i32, code: &str, msg: &[u8], hint: Option<&[u8]>) {
        if !self.raw && code != "cmd.cancelled" {
            let sl = self.session_log_phrase(128);
            let mut f = Flines::new();
            fmt::error(
                &self.ctx(fmt::FMT_MODE_NORMAL, &sl),
                Some(msg),
                hint,
                &mut f,
            );
            self.emit_flines(f);
        }
        self.marker_err(seq, code.as_bytes(), msg);
    }

    /// A hub-side refusal the console found itself (a D2 pre-read that ends
    /// the command): raw format shows it as the err| record the hub would
    /// have sent, escaped the same way (docs/console.md §3.1), then the
    /// marker.  msg and hint are at most 255 bytes, so C's 1024-byte record
    /// never truncates.
    fn refuse_hub(&mut self, seq: i32, code: &str, msg: &[u8], hint: Option<&[u8]>) {
        if !self.raw {
            self.refuse(seq, code, msg, hint);
            return;
        }
        fn esc_kv(out: &mut Vec<u8>, key: &[u8], val: &[u8]) {
            out.push(b'|');
            out.extend_from_slice(key);
            out.push(b'=');
            for &b in val.iter().take_while(|&&b| b != 0) {
                match b {
                    b'%' => out.extend_from_slice(b"%25"),
                    b'|' => out.extend_from_slice(b"%7C"),
                    b'\n' => out.extend_from_slice(b"%0A"),
                    b'\r' => out.extend_from_slice(b"%0D"),
                    _ => out.push(b),
                }
            }
        }
        let mut rec = b"err|".to_vec();
        rec.extend_from_slice(code.as_bytes());
        esc_kv(&mut rec, b"msg", msg);
        if let Some(h) = hint {
            esc_kv(&mut rec, b"hint", h);
        }
        let f = raw_lines(&rec, RL_ERR);
        self.emit_flines(f);
        self.marker_err(seq, code.as_bytes(), msg);
    }

    /// ✓ result of a console-side command (display, log on/off, …).
    fn local_ok(&mut self, what: &[u8], subject: Option<&[u8]>, effect: Option<&[u8]>) {
        if self.raw {
            return;
        }
        let sl = self.session_log_phrase(128);
        let mut f = Flines::new();
        {
            let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
            fmt::ok(&c, what, subject, &mut f);
            if let Some(e) = effect {
                let l = fmtb(&[b"   ", fmt::glyph(&c, fmt::G_BULLET), b" ", e]);
                fmt::flines_add(&mut f, RL_NORMAL, c_cut(&l, 256));
            }
        }
        self.emit_flines(f);
    }

    fn on_reply(&mut self, text: &[u8]) {
        if self.rq.is_empty() {
            return; // nothing asked: ignore
        }
        let rq = self.rq.remove(0);
        if rq.kind == Rq::ViewUpg || rq.kind == Rq::ViewStats {
            // read back as a C string
            let t = Some(cstr(text).to_vec());
            if rq.kind == Rq::ViewUpg {
                self.upg_text = t;
            } else {
                self.stats_text = t;
            }
            self.dirty = true;
            return;
        }
        if rq.kind == Rq::Pre {
            self.pre_reply(&rq, text);
            return;
        }
        let rep = fmt::creply_parse(text);
        let err = rep.err;
        let code = c_cut(&rep.code, 64).to_vec();
        let msg = match rep.res.rv("msg") {
            Some(m) if err => c_cut(m, 320).to_vec(),
            _ => Vec::new(),
        };
        drop(rep);
        self.show_reply(text, &rq.words, rq.mode, err);
        if err {
            self.marker_err(rq.seq, &code, &msg);
        } else {
            self.marker_ok(rq.seq, &rq.words);
        }
        let m = fmtb(&[
            b"[CONSOLE] ",
            &self.admin,
            b"@",
            &self.ip,
            format!(" #{} ", rq.seq).as_bytes(),
            &rq.audit,
            b" -> ",
            if err { b"err: " } else { b"ok" },
            if err { &code } else { b"" },
            if err { b": " } else { b"" },
            if err { &msg[..uprec(&msg, 120)] } else { b"" },
        ]);
        self.audit(rq.audit_level, m);
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
                b"peers" => scan_pair(v, &mut st.peers_up, &mut st.peers_total),
                b"bots" => scan_pair(v, &mut st.bots_on, &mut st.bots_total),
                b"upg" => st.upg = sanitize(v, 24),
                b"frozen" => st.frozen = fmt::atoi(v) != 0,
                b"rollup" => st.rollup = fmt::atoi(v) != 0,
                b"split" => st.split = fmt::atoi(v) != 0,
                b"loglevel" => st.loglevel = fmt::atoi(v),
                b"consolelevel" => st.consolelevel = fmt::atoi(v),
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
            ..PendingRq::default()
        });
        if kind == Rq::ViewUpg {
            self.core_frame(CMD_ADMIN_UPGRADE_STATUS, b"");
            self.upg_at = now_ms;
        } else {
            self.core_frame(CMD_ADMIN_STATS, b"");
            self.stats_at = now_ms;
        }
    }

    /// Human event lines (§3, D14): pretty only; line mode with display
    /// events on, the full-screen console view always.
    fn human_events(&self) -> bool {
        !self.raw && (!self.line_mode || self.events_on)
    }

    fn human_event(&mut self, text: &[u8], kind: u8) {
        if self.line_mode {
            self.lm_async(text);
        } else {
            self.fs_timestamped(V_CONSOLE, text, kind);
        }
    }

    /// What changed between two trees, as a line each (D14).
    fn tree_events(&mut self, old: &[u8], cur: &[u8]) {
        let a = parse_tree(old);
        let b = parse_tree(cur);
        let sl = self.session_log_phrase(128);
        let (g_on, g_warn, g_off) = {
            let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
            (
                fmt::glyph(&c, fmt::G_ON),
                fmt::glyph(&c, fmt::G_WARN),
                fmt::glyph(&c, fmt::G_OFF),
            )
        };
        // peers up/down
        for bj in &b {
            if bj.typ != b'H' || bj.depth < 1 {
                continue;
            }
            if let Some(ai) = a
                .iter()
                .find(|ai| ai.typ == b'H' && ai.uuid == bj.uuid && ai.name == bj.name)
                && ai.online != bj.online
            {
                let l = fmtb(&[
                    if bj.online { g_on } else { g_warn },
                    b" peer ",
                    &bj.name,
                    if bj.online { b" is up" } else { b" went down" },
                ]);
                self.human_event(c_cut(&l, 256), if bj.online { RL_DIM } else { RL_WARN });
            }
        }
        // bots in / out / moved: the hub is the nearest H row above
        let hubs = |rows: &[TRow]| -> Vec<Vec<u8>> {
            let mut h: Vec<u8> = Vec::new();
            rows.iter()
                .map(|r| {
                    if r.typ == b'H' {
                        h = r.name.clone();
                    }
                    h.clone()
                })
                .collect()
        };
        let hub_a = hubs(&a);
        let hub_b = hubs(&b);
        for (j, bj) in b.iter().enumerate() {
            if bj.typ != b'B' {
                continue;
            }
            match a.iter().position(|ai| ai.typ == b'B' && ai.uuid == bj.uuid) {
                None => {
                    let l = fmtb(&[g_on, b" bot ", &bj.name, b" connected to ", &hub_b[j]]);
                    self.human_event(c_cut(&l, 256), RL_DIM);
                }
                Some(i) if hub_a[i] != hub_b[j] => {
                    let l = fmtb(&[
                        g_on,
                        b" bot ",
                        &bj.name,
                        b" moved from ",
                        &hub_a[i],
                        b" to ",
                        &hub_b[j],
                    ]);
                    self.human_event(c_cut(&l, 256), RL_DIM);
                }
                _ => {}
            }
        }
        for (i, ai) in a.iter().enumerate() {
            if ai.typ != b'B' {
                continue;
            }
            if !b.iter().any(|bj| bj.typ == b'B' && bj.uuid == ai.uuid) {
                let l = fmtb(&[g_off, b" bot ", &ai.name, b" disconnected from ", &hub_a[i]]);
                self.human_event(c_cut(&l, 256), RL_DIM);
            }
        }
    }

    /// After login: what the mesh looks like, once (§2.1).
    fn greet_status(&mut self) {
        if self.greeted {
            return;
        }
        self.greeted = true;
        if self.raw || self.seq > 0 {
            return;
        }
        let sl = self.session_log_phrase(128);
        let dot = fmt::glyph(&self.ctx(fmt::FMT_MODE_NORMAL, &sl), fmt::G_DOT);
        let lw = |l: i32| -> &'static str {
            if (0..=4).contains(&l) {
                LEVEL_WORD[l as usize]
            } else {
                "?"
            }
        };
        let l1 = fmtb(&[
            format!(" peers {}/{} up ", self.st.peers_up, self.st.peers_total).as_bytes(),
            dot,
            format!(" bots {}/{} online ", self.st.bots_on, self.st.bots_total).as_bytes(),
            dot,
            format!(
                " log file {}, console {}",
                lw(self.st.loglevel),
                lw(self.st.consolelevel)
            )
            .as_bytes(),
        ]);
        let l1 = c_cut(&l1, 256).to_vec();
        let l2 = b" type help for commands";
        if self.line_mode {
            self.lm_async(&l1);
            self.lm_async(l2);
        } else {
            self.fs_line(&l1, RL_DIM);
            self.fs_line(l2, RL_DIM);
        }
    }

    fn on_event(&mut self, payload: &[u8], now_ms: i64) {
        let Some(bar) = payload.iter().position(|&b| b == b'|') else {
            return;
        };
        // a NUL inside the topic would end it early for strcmp below
        if bar >= 16 || payload[..bar].contains(&0) {
            return;
        }
        let topic = &payload[..bar];
        let data = &payload[bar + 1..];
        let dl = data.len();
        match topic {
            b"status" => {
                let clean = sanitize(data, dl + 1);
                self.parse_status(&clean);
                if self.line_mode {
                    let line = fmtb(&[b"[evt status] ", &clean]);
                    self.lm_async(c_cut(&line, dl + 32));
                }
                self.greet_status();
                self.dirty = true;
            }
            b"tree" => {
                // sanitize each row, keep the newlines
                let mut tree = Vec::with_capacity(dl + 1);
                let mut rows = 0;
                let mut i = 0;
                while i < dl {
                    let mut j = i;
                    while j < dl && data[j] != b'\n' {
                        j += 1;
                    }
                    if j > i {
                        let cap = dl + 2 - tree.len();
                        tree.extend_from_slice(&sanitize(&data[i..j], cap));
                        tree.push(b'\n');
                        rows += 1;
                    }
                    i = j + 1;
                }
                if self.line_mode {
                    let mut blk = format!("[evt tree] begin {rows}\n").into_bytes();
                    let mut p = 0;
                    while p < tree.len() {
                        let n = tree[p..]
                            .iter()
                            .position(|&b| b == b'\n')
                            .unwrap_or(tree.len() - p);
                        blk.extend_from_slice(b"[evt tree] ");
                        blk.extend_from_slice(&tree[p..p + n]);
                        blk.push(b'\n');
                        p += n + 1;
                    }
                    blk.extend_from_slice(b"[evt tree] end");
                    self.lm_async(&blk);
                }
                if self.human_events()
                    && let Some(old) = self.tree.clone()
                {
                    self.tree_events(&old, &tree);
                }
                self.tree = Some(tree);
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
                if self.human_events() && clean != self.last_upg {
                    // <id>|<phase>|<done>/<total>|<failed>
                    let mut f: [Vec<u8>; 4] = Default::default();
                    let mut k = 0;
                    let mut p = 0;
                    while k < 4 {
                        let q = clean[p..].iter().position(|&b| b == b'|').map(|x| p + x);
                        let n = q.unwrap_or(clean.len()) - p;
                        f[k] = clean[p..p + n.min(63)].to_vec();
                        k += 1;
                        match q {
                            Some(q) => p = q + 1,
                            None => break,
                        }
                    }
                    let failed = fmt::atoi(&f[3]) > 0;
                    let line = fmtb(&[
                        b"upgrade ",
                        &f[0],
                        b": ",
                        &f[2],
                        b" done (",
                        &f[1],
                        b")",
                        if failed { b", " } else { b"" },
                        if failed { &f[3] } else { b"" },
                        if failed { b" failed" } else { b"" },
                    ]);
                    if !clean.is_empty() {
                        self.human_event(c_cut(&line, 300), if failed { RL_WARN } else { RL_DIM });
                    }
                }
                self.last_upg = c_cut(&clean, 256).to_vec();
            }
            b"log" => {
                let Some(b2) = data.iter().position(|&b| b == b'|') else {
                    return;
                };
                if b2 >= 16 {
                    return;
                }
                let lvl = cstr(&data[..b2]);
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
                    let line = if self.raw {
                        fmtb(&[
                            format!("[log {}] ", LEVEL_WORD[level as usize]).as_bytes(),
                            &clean,
                        ])
                    } else {
                        fmtb(&[
                            format!("[log {} ", LEVEL_WORD[level as usize]).as_bytes(),
                            &clock_utc(true),
                            b"] ",
                            &clean,
                        ])
                    };
                    self.lm_async(c_cut(&line, CONSOLE_LOG_LINE_MAX + 48));
                } else {
                    let kind = match level {
                        LOG_ERROR => RL_ERR,
                        LOG_WARNING => RL_WARN,
                        LOG_DEBUG => RL_DIM,
                        _ => RL_NORMAL,
                    };
                    self.fs_add(V_LOG, &clean, kind, level);
                }
            }
            b"drop" => {
                // the payload is not NUL-terminated: parse a bounded copy
                let n = fmt::strtoull(&data[..dl.min(23)], 10);
                self.dropped = self.dropped.wrapping_add(n);
            }
            _ => {}
        }
    }

    /// A frame from the core.
    pub fn core_frame_in(&mut self, op: u8, payload: &[u8], now_ms: i64) {
        self.now_ms = now_ms;
        if op == CONSOLE_REPLY {
            self.on_reply(payload);
        } else if op == CMD_CONSOLE {
            self.on_event(payload, now_ms);
        }
    }
}

/// Raw format: the records as the hub sent them, sanitized, one per line.
fn raw_lines(text: &[u8], role: u8) -> Flines {
    let mut out = Flines::new();
    let mut end = text.len();
    while end > 0 && matches!(text[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
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
        fmt::flines_add(&mut out, role, &clean);
        i = j + 1;
    }
    out
}

// ===========================================================================
// Running a command line
// ===========================================================================
const MAX_WORDS: usize = 16;

struct Words {
    buf: Vec<u8>,
    /// (start, end) of each word in `buf` (= where it starts in the line)
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
    let c: &[u8] = if ws.get(0) == b"?" {
        b"help"
    } else {
        ws.get(0)
    }; // ? = help
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

fn cmd_words(d: &CmdDef) -> Vec<u8> {
    match d.sub {
        Some(sub) => format!("{} {}", d.cmd, sub).into_bytes(),
        None => d.cmd.as_bytes().to_vec(),
    }
}

/// help <group> <command>: usage, what it does, each argument, examples.
fn help_command(c: &Ctx, f: &mut Flines, d: &CmdDef) {
    let words = c_cut(&cmd_words(d), 32).to_vec();
    let (mut args, mut ex) = (None, None);
    for h in CMD_HELP {
        if h.0 == d.cmd && h.1 == d.sub {
            args = h.2;
            ex = Some(h.3);
        }
    }
    let conf = match d.confirm {
        Confirm::Yn => Some("asks y/N"),
        Confirm::Type => Some("type to confirm"),
        _ => None,
    };
    let right = if d.sub.is_some() {
        format!(
            "{}{}help {} for the group",
            conf.unwrap_or(""),
            if conf.is_some() { " · " } else { "" },
            d.cmd
        )
    } else {
        conf.unwrap_or("").to_string()
    };
    let right = c_cut(right.as_bytes(), 64).to_vec();
    fmt::title(
        c,
        f,
        &words,
        (!right.is_empty()).then_some(right.as_slice()),
    );
    fmt::flines_add(
        f,
        RL_NORMAL,
        c_cut(&fmtb(&[b"   ", d.usage.as_bytes()]), 1024),
    );
    fmt::flines_add(f, RL_DIM, c_cut(&fmtb(&[b"   ", d.help.as_bytes()]), 1024));
    // "name<TAB>text" lines as a two-column list; a long name puts its text
    // on the next line
    if let Some(args) = args {
        let a = args.as_bytes();
        fmt::flines_add(f, RL_NORMAL, b"");
        fmt::flines_add(f, RL_HEAD, b" Arguments");
        let find = |from: usize, ch: u8| a[from..].iter().position(|&b| b == ch).map(|x| from + x);
        let mut nw = 0usize;
        let mut p = 0;
        while p < a.len() {
            let tab = find(p, b'\t');
            let nl = find(p, b'\n').unwrap_or(a.len());
            let w = match tab {
                Some(t) if t < nl => t - p,
                _ => 0,
            };
            if w > nw && w <= 16 {
                nw = w;
            }
            p = if nl < a.len() { nl + 1 } else { nl };
        }
        p = 0;
        while p < a.len() {
            let nl = find(p, b'\n').unwrap_or(a.len());
            let tab = match find(p, b'\t') {
                Some(t) if t <= nl => t,
                _ => p,
            };
            let w = tab - p;
            let t = if tab == p { p } else { tab + 1 };
            let text = &a[t..nl];
            if w <= nw {
                let l = fmtb(&[b"   ", &a[p..tab], &vec![b' '; nw - w], b"  ", text]);
                fmt::flines_add(f, RL_NORMAL, c_cut(&l, 1024));
            } else {
                let l = fmtb(&[b"   ", &a[p..tab]]);
                fmt::flines_add(f, RL_NORMAL, c_cut(&l, 1024));
                let l = fmtb(&[b"   ", &vec![b' '; nw], b"  ", text]);
                fmt::flines_add(f, RL_NORMAL, c_cut(&l, 1024));
            }
            p = if nl < a.len() { nl + 1 } else { nl };
        }
    } else {
        fmt::flines_add(f, RL_DIM, b"   (no arguments)");
    }
    if let Some(ex) = ex {
        fmt::flines_add(f, RL_NORMAL, b"");
        fmt::flines_add(
            f,
            RL_HEAD,
            if ex.contains('\n') {
                b" Examples"
            } else {
                b" Example"
            },
        );
        for l in ex.split('\n') {
            // never wrapped: it copies as typed
            fmt::flines_add(f, RL_CMD, c_cut(&fmtb(&[b"   ", l.as_bytes()]), 1024));
        }
    }
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

/// What build_payload settled on.
struct Built {
    payload: Vec<u8>,
    op: u8,
    confirm: Confirm,
    mode: i32,
}

/// Build the request (op and payload); Err((why, hint)) when the arguments
/// are bad.  The op starts as the table's opcode and the confirmation as
/// its; a command whose arguments pick the opcode sets both.
fn build_payload(
    c: &CmdDef,
    ws: &Words,
    argi: usize,
) -> Result<Built, (Vec<u8>, Option<&'static str>)> {
    const CAP: usize = 1024;
    let na = ws.n() - argi;
    let a = |i: usize| ws.get(argi + i);
    let hint = Some(c.usage);
    let mut b = Built {
        payload: Vec::new(),
        op: c.op,
        confirm: c.confirm,
        mode: fmt::FMT_MODE_NORMAL,
    };
    let bad = |why: &str, hint: Option<&'static str>| Err((why.as_bytes().to_vec(), hint));
    let too_long = || Err((b"arguments too long".to_vec(), Some(c.usage)));
    let w: Vec<u8> = match c.build {
        B::None | B::Local => return Ok(b),
        B::Fixed => {
            b.payload = c.fixed.as_bytes().to_vec();
            return Ok(b);
        }
        B::Arg => a(0).to_vec(),
        B::Pipe => {
            let mut o = Vec::new();
            for i in 0..na {
                let add = a(i).len() + usize::from(i > 0);
                if o.len() + add >= CAP {
                    return too_long();
                }
                if i > 0 {
                    o.push(b'|');
                }
                o.extend_from_slice(a(i));
            }
            b.payload = o;
            return Ok(b);
        }
        B::PeerAdd => {
            if (0..5).any(|i| a(i).contains(&b':')) {
                return bad("':' is not allowed in an argument here", hint);
            }
            let name: &[u8] = if a(3) == b"-" { b"" } else { a(3) };
            fmtb(&[a(0), b":", a(1), b":", a(2), b":", name, b":", a(4)])
        }
        B::PeerDel => {
            if na > 0 && !all_digits(a(0)) {
                return bad(
                    "a peer is removed by its number in peer list",
                    Some("peer del [#]"),
                );
            }
            if na > 0 { a(0).to_vec() } else { Vec::new() }
        }
        B::PeerSet => {
            if !eq_ic(a(1), "key") {
                return bad("unknown peer setting", Some("settings: key"));
            }
            if a(0).contains(&b':') || a(2).contains(&b':') {
                return bad("':' is not allowed in an argument here", hint);
            }
            fmtb(&[a(0), b":", a(2)])
        }
        B::ChanAdd => fmtb(&[a(0), b"|", if na > 1 { a(1) } else { b"" }]),
        B::ChanSet => {
            if a(1)
                .iter()
                .any(|&ch| !ch.is_ascii_lowercase() && ch != b'_')
            {
                return bad(
                    "a setting name is lowercase letters and _",
                    Some("settings: key"),
                );
            }
            if a(2).len() > 128 {
                return bad("a setting value is at most 128 bytes", hint);
            }
            let v: &[u8] = if a(2) == b"-" { b"" } else { a(2) };
            fmtb(&[b"set|", a(0), b"|", a(1), b"|", v])
        }
        B::ChanOp => fmtb(&[a(1), b"|", a(0)]), // the hub takes nick|chan
        B::OptSet => {
            if a(0) == b"-" {
                Vec::new()
            } else {
                a(0).to_vec()
            }
        }
        B::LogSet => {
            if eq_ic(a(0), "size") {
                // <n> MB, <n>k KiB or <n>b bytes, at most 1024 MB (the hub
                // clamps it to its own limits)
                let arg = a(1);
                let al = arg.len();
                let mut mult: u64 = 1024 * 1024;
                let mut num = c_cut(arg, 16).to_vec();
                if al > 1 && al < 16 && b"kKbB".contains(&arg[al - 1]) {
                    mult = if arg[al - 1] == b'k' || arg[al - 1] == b'K' {
                        1024
                    } else {
                        1
                    };
                    num.truncate(al - 1);
                }
                let v = if all_digits(&num) {
                    fmt::strtoull(&num, 10).wrapping_mul(mult)
                } else {
                    0
                };
                if !(1..=1024 * 1024 * 1024).contains(&v) {
                    return bad(
                        "size: <MB>, <n>k or <n>b, at most 1024 MB",
                        Some("log set size <MB|nk|nb>"),
                    );
                }
                b.payload = (v as u32).to_be_bytes().to_vec();
                b.op = CMD_ADMIN_SET_LOG_SIZE;
                b.confirm = Confirm::None;
                return Ok(b);
            }
            // <target><level>: target 0 = the log file, 1 = the console log
            let target = if eq_ic(a(0), "file") {
                0
            } else if eq_ic(a(0), "console") {
                1
            } else {
                return bad("say file, console or size", hint);
            };
            let lvl = level_arg(a(1));
            if lvl < 0 {
                return bad("level: none, error, warning, info, debug or 0-4", hint);
            }
            b.payload = vec![target, lvl as u8];
            b.op = CMD_ADMIN_SET_LOG_LEVEL;
            b.confirm = Confirm::Yn;
            return Ok(b);
        }
        B::Purge => {
            if eq_ic(a(0), "now") {
                b"immediate".to_vec()
            } else if all_digits(a(0)) && fmt::atoll(a(0)) > 0 {
                a(0).to_vec()
            } else {
                return bad("purge now, or purge <days>", hint);
            }
        }
        B::HubSet => {
            if na == 0 {
                // the settings table: hub show's record, laid out as one
                b.op = CMD_ADMIN_GET_PUBKEY;
                b.mode = fmt::FMT_MODE_HUB_SETTINGS;
                return Ok(b);
            }
            const HS: [(&str, u8); 5] = [
                ("name", CMD_ADMIN_SET_HUB_NAME),
                ("bindip", CMD_ADMIN_SET_BIND_IP),
                ("port", CMD_ADMIN_SET_BIND_PORT),
                ("pubkey", CMD_ADMIN_SET_PUBKEY),
                ("autopurge", CMD_ADMIN_SET_PURGE_DAYS),
            ];
            let Some(k) = HS.iter().rposition(|h| eq_ic(a(0), h.0)) else {
                let m = fmtb(&[b"unknown hub setting \"", &a(0)[..uprec(a(0), 40)], b"\""]);
                return Err((
                    c_cut(&m, 96).to_vec(),
                    Some("name, bindip, port, pubkey, autopurge"),
                ));
            };
            if na < 2 {
                return bad("say the new value", hint);
            }
            b.op = HS[k].1;
            a(1).to_vec()
        }
        B::Acl => {
            let add = c.sub == Some("add");
            if eq_ic(a(0), "allow") {
                b.op = if add {
                    CMD_ADMIN_ADD_ALLOWLIST
                } else {
                    CMD_ADMIN_DEL_ALLOWLIST
                };
            } else if eq_ic(a(0), "deny") {
                b.op = if add {
                    CMD_ADMIN_ADD_DENYLIST
                } else {
                    CMD_ADMIN_DEL_DENYLIST
                };
            } else {
                return bad("say which list", hint);
            }
            a(1).to_vec()
        }
        B::UserList => {
            if na == 0 {
                b.op = CMD_ADMIN_LIST_ADMINS;
                b"*".to_vec()
            } else if eq_ic(a(0), "admin") {
                b.op = CMD_ADMIN_LIST_ADMINS;
                Vec::new()
            } else if eq_ic(a(0), "oper") {
                b.op = CMD_ADMIN_LIST_OPERS_V2;
                Vec::new()
            } else {
                return bad("role is admin or oper", hint);
            }
        }
        B::UserAdd => {
            if eq_ic(a(0), "admin") {
                b.op = CMD_ADMIN_ADD_ADMIN;
            } else if eq_ic(a(0), "oper") {
                b.op = CMD_ADMIN_ADD_OPER_RECORD;
            } else {
                return bad("role is admin or oper", hint);
            }
            fmtb(&[a(1), b"|", a(2), b"|", a(3)])
        }
        B::UserSet => {
            if !eq_ic(a(1), "key") {
                return bad("unknown user setting", Some("settings: key"));
            }
            fmtb(&[a(0), b"|", a(2)])
        }
        B::UserMask => {
            if eq_ic(a(0), "add") {
                b.op = CMD_ADMIN_ADD_USERMASK;
                b.confirm = Confirm::None;
            } else if eq_ic(a(0), "del") {
                b.op = CMD_ADMIN_DEL_USERMASK;
                b.confirm = Confirm::Yn;
            } else {
                return bad("say add or del", hint);
            }
            fmtb(&[a(1), b"|", a(2)])
        }
        B::UpgReleases => {
            let (mut bot, mut hub): (&[u8], &[u8]) = (b"", b"");
            for i in 0..na {
                if let Some(v) = kv_opt(a(i), "bot") {
                    bot = v;
                } else if let Some(v) = kv_opt(a(i), "hub") {
                    hub = v;
                } else {
                    return bad("options: bot=<base> hub=<base>", hint);
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
                    return bad(
                        "options: hub=<ver> nodes=<list> botbase=<url> hubbase=<url>",
                        hint,
                    );
                }
            }
            // ver|variant|kind|min_from|base|hub_ver|hub_base|sel — variant,
            // kind and min_from are left to each node, as hub_admin always did.
            let hbv: &[u8] = if hubv.is_empty() { b"" } else { hb };
            fmtb(&[a(0), b"||||", bb, b"|", hubv, b"|", hbv, b"|", nodes])
        }
    };
    if w.len() >= CAP {
        return too_long();
    }
    b.payload = w;
    Ok(b)
}

fn opt_meaning(f: u8) -> &'static str {
    match f {
        b'h' => "hub-only mutation",
        b'F' => "config frozen",
        _ => "unknown flag",
    }
}

impl Ui {
    /// help: the groups; help <group>: its commands; help <group> <command>:
    /// one command in full (§2.2).
    fn show_help(&mut self, topic: Option<&[u8]>, one: Option<&CmdDef>) {
        let sl = self.session_log_phrase(128);
        let mut f = Flines::new();
        {
            let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
            let dot = fmt::glyph(&c, fmt::G_DOT);
            if let Some(d) = one {
                help_command(&c, &mut f, d);
            } else if let Some(topic) = topic {
                let mut n = 0;
                let mut uw = 0;
                for d in CMDS.iter().filter(|d| eq_ic(topic, d.cmd)) {
                    n += 1;
                    uw = uw.max(str_width(d.usage.as_bytes()));
                }
                uw = uw.min(34);
                let right = fmtb(&[
                    format!("{n} command{} ", if n == 1 { "" } else { "s" }).as_bytes(),
                    dot,
                    b" help ",
                    topic,
                    b" <command> for one",
                ]);
                let right = c_cut(&right, 96).to_vec();
                fmt::title(&c, &mut f, topic, Some(&right));
                for d in CMDS.iter().filter(|d| eq_ic(topic, d.cmd)) {
                    let w = str_width(d.usage.as_bytes());
                    let pad = |k: i32| vec![b' '; k.max(0) as usize];
                    if w <= uw && 1 + uw + 2 + str_width(d.help.as_bytes()) <= c.width {
                        let l = fmtb(&[
                            b" ",
                            d.usage.as_bytes(),
                            &pad(uw - w),
                            b"  ",
                            d.help.as_bytes(),
                        ]);
                        fmt::flines_add(&mut f, RL_NORMAL, c_cut(&l, 512));
                    } else {
                        let l = fmtb(&[b" ", d.usage.as_bytes()]);
                        fmt::flines_add(&mut f, RL_NORMAL, c_cut(&l, 512));
                        let l = fmtb(&[b" ", &pad(uw), b"  ", d.help.as_bytes()]);
                        fmt::flines_add(&mut f, RL_NORMAL, c_cut(&l, 512));
                    }
                    if let Some(args) = d.args {
                        let l = fmtb(&[b" ", &pad(uw), b"  ", args.as_bytes()]);
                        fmt::flines_add(&mut f, RL_DIM, c_cut(&l, 512));
                    }
                }
            } else {
                let right = fmtb(&[
                    format!("{} groups ", GROUPS.len()).as_bytes(),
                    dot,
                    b" help <group> for its commands",
                ]);
                fmt::title(&c, &mut f, b"Commands", Some(&right));
                for (name, what) in GROUPS {
                    // the separator, once per verb
                    let sep = fmtb(&[b" ", dot, b" "]);
                    let mut joined: Vec<u8> = Vec::new();
                    let mut first = true;
                    for d in CMDS {
                        let Some(sub) = d.sub else { continue };
                        if d.cmd != name {
                            continue;
                        }
                        if !first {
                            joined.extend_from_slice(&sep);
                        }
                        joined.extend_from_slice(sub.as_bytes());
                        first = false;
                    }
                    let l = fmtb(&[
                        b"   ",
                        &padl(name.as_bytes(), 9),
                        b" ",
                        &padl(what.as_bytes(), 22),
                        b" ",
                        &joined,
                    ]);
                    let l = c_cut(&l, 512).to_vec();
                    if str_width(&l) <= c.width {
                        fmt::flines_add(&mut f, RL_NORMAL, &l);
                    } else {
                        let l = fmtb(&[b"   ", &padl(name.as_bytes(), 9), b" ", what.as_bytes()]);
                        fmt::flines_add(&mut f, RL_NORMAL, &l);
                        let l = fmtb(&[b"             ", &joined]);
                        fmt::flines_add(&mut f, RL_DIM, c_cut(&l, 512));
                    }
                }
                let l = fmtb(&[
                    b"   help [group [command]] ",
                    dot,
                    b" ? [group [command]] ",
                    dot,
                    b" quit",
                ]);
                fmt::flines_add(&mut f, RL_NORMAL, &l);
                if !self.line_mode {
                    fmt::flines_add(&mut f, RL_NORMAL, b"");
                    fmt::flines_add(
                        &mut f,
                        RL_DIM,
                        b" Keys  Alt+1..5 views, Alt+Left/Right cycle, F2 log level, F3 tree pane,",
                    );
                    fmt::flines_add(
                        &mut f,
                        RL_DIM,
                        b"       PgUp/PgDn/End scroll, Tab completes, Up/Down history, Ctrl-C cancels",
                    );
                }
            }
        }
        self.emit_flines(f);
    }

    fn send_request(&mut self, op: u8, payload: &[u8], rq: PendingRq) {
        if self.rq.len() >= MAX_PENDING_RQ {
            self.refuse(rq.seq, "cmd.busy", b"too many requests in flight", None);
            return;
        }
        self.rq.push(rq);
        self.core_frame(op, payload);
        self.user_busy = true;
    }

    fn display_show(&mut self) {
        let sl = self.session_log_phrase(128);
        let mut f = Flines::new();
        {
            let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
            let right = if self.line_mode {
                format!("line mode {}", self.out_width())
            } else {
                format!("full screen {}×{}", self.cols, self.rows)
            };
            fmt::title(&c, &mut f, b"Display", Some(c_cut(right.as_bytes(), 64)));
            const L: i32 = 9;
            let card = |f: &mut Flines, label: &str, v: &[u8]| {
                fmt::card_line(f, L, label.as_bytes(), Some(v), RL_NORMAL)
            };
            if !self.line_mode {
                let v = format!("{} (Alt+{})", VIEW_NAME[self.view], self.view + 1);
                card(&mut f, "view", v.as_bytes());
                let shown = if self.cols >= CONSOLE_PANE_MIN_COLS {
                    !self.pane_user_off
                } else {
                    self.overlay
                };
                card(
                    &mut f,
                    "tree pane",
                    if shown {
                        b"shown (F3 hides it)"
                    } else {
                        b"hidden (F3 shows it)"
                    },
                );
            }
            card(
                &mut f,
                "glyphs",
                if self.ascii { b"ascii" } else { b"unicode" },
            );
            card(&mut f, "format", if self.raw { b"raw" } else { b"pretty" });
            if self.line_mode {
                let v = if self.width_set < 0 {
                    format!("auto ({})", self.out_width())
                } else {
                    format!("{}", self.out_width())
                };
                card(&mut f, "width", v.as_bytes());
                card(
                    &mut f,
                    "events",
                    if self.events_on { b"on" } else { b"off" },
                );
                card(&mut f, "colors", b"off (line mode)");
            } else {
                let v = format!("{} for output", self.out_width());
                card(&mut f, "width", v.as_bytes());
                card(&mut f, "colors", b"on");
            }
            let v = self.session_log_phrase(192);
            card(&mut f, "log", &v);
        }
        self.emit_flines(f);
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
        let a1: Option<&[u8]> = (ws.n() > argi).then(|| ws.get(argi));
        let arrow = "→".as_bytes(); // lm_line / fs_add show it as ->
        match (c.cmd, c.sub.unwrap_or("")) {
            ("help", _) => {
                if let Some(a) = a1
                    && !cmd_known_word(a)
                {
                    let m = fmtb(&[b"no command group \"", &a[..uprec(a, 40)], b"\""]);
                    self.refuse(seq, "cmd.unknown", c_cut(&m, 96), Some(b"help"));
                    return;
                }
                let mut one: Option<&CmdDef> = None;
                let a2: Option<&[u8]> = (ws.n() > argi + 1).then(|| ws.get(argi + 1));
                if let Some(a) = a1
                    && (a2.is_some() || !cmd_has_subs(a))
                {
                    one = CMDS.iter().find(|d| {
                        eq_ic(a, d.cmd)
                            && match d.sub {
                                Some(sub) => a2.is_some_and(|x| eq_ic(x, sub)),
                                None => a2.is_none(),
                            }
                    });
                    if one.is_none() {
                        let x = a2.unwrap_or(b"");
                        let m = fmtb(&[a, b" has no command ", &x[..uprec(x, 40)]]);
                        let h = fmtb(&[b"help ", a]);
                        self.refuse(seq, "cmd.unknown", c_cut(&m, 128), Some(c_cut(&h, 64)));
                        return;
                    }
                }
                self.show_help(a1, one);
            }
            ("quit", _) => {
                if !self.raw {
                    let s = ((self.now_ms - self.start_ms) / 1000).max(0);
                    let d = format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60);
                    let d = c_cut(d.as_bytes(), 32).to_vec();
                    let sl = self.session_log_phrase(128);
                    let dot = fmt::glyph(&self.ctx(fmt::FMT_MODE_NORMAL, &sl), fmt::G_DOT);
                    let m = fmtb(&[
                        b" Goodbye ",
                        &self.admin,
                        b" ",
                        dot,
                        b" session ",
                        &d,
                        b" ",
                        dot,
                        format!(
                            " {} command{}",
                            self.ncmds,
                            if self.ncmds == 1 { "" } else { "s" }
                        )
                        .as_bytes(),
                    ]);
                    let m = c_cut(&m, 160).to_vec();
                    self.note(&m, RL_DIM);
                }
                self.marker_ok(seq, words);
                self.closing = true;
                self.close_why = "quit".to_string();
                return;
            }
            ("log", "filter") => {
                if self.line_mode {
                    self.refuse(
                        seq,
                        "cmd.mode",
                        b"only in the full-screen console",
                        Some(b"log on [level] in line mode"),
                    );
                    return;
                }
                let rest = &line[ws.w[argi].0..];
                let from: Vec<u8> = c_cut(
                    if self.filter.is_empty() {
                        b"-"
                    } else {
                        &self.filter
                    },
                    64,
                )
                .to_vec();
                if eq_ic(rest, "clear") {
                    self.filter.clear();
                } else {
                    self.filter = c_cut(rest, 128).to_vec();
                }
                self.dirty = true;
                let to: Vec<u8> = if self.filter.is_empty() {
                    b"-".to_vec()
                } else {
                    self.filter.clone()
                };
                let s = fmtb(&[b"filter   ", &from, b" ", arrow, b" ", &to]);
                self.local_ok(b"Log", Some(c_cut(&s, 300)), None);
            }
            ("log", sub) => {
                if !self.line_mode {
                    self.refuse(
                        seq,
                        "cmd.mode",
                        b"the log is the Alt+2 view in the full-screen console",
                        None,
                    );
                    return;
                }
                if sub == "on" {
                    let lvl = a1.map_or(LOG_INFO, level_arg);
                    if lvl <= 0 {
                        self.refuse(
                            seq,
                            "cmd.bad_arg",
                            b"level: error, warning, info or debug",
                            Some(b"log on [level]"),
                        );
                        return;
                    }
                    self.log_on = true;
                    self.log_sub_level = lvl;
                    let s = format!("{} and worse", LEVEL_WORD[lvl as usize]);
                    let cl = self.st.consolelevel;
                    let e = format!(
                        "the ring keeps {}; log off stops it",
                        if self.st.have && (0..=4).contains(&cl) {
                            LEVEL_WORD[cl as usize]
                        } else {
                            "what its level says"
                        }
                    );
                    self.local_ok(b"Log stream on", Some(s.as_bytes()), Some(e.as_bytes()));
                } else {
                    self.log_on = false;
                    self.local_ok(b"Log stream off", None, None);
                }
                self.subscribe();
            }
            ("display", sub) => {
                let fs_only = matches!(sub, "view" | "pane" | "clear");
                let lm_only = matches!(sub, "width" | "events");
                if fs_only && self.line_mode {
                    self.refuse(seq, "cmd.mode", b"only in the full-screen console", None);
                    return;
                }
                if lm_only && !self.line_mode {
                    self.refuse(seq, "cmd.mode", b"only in line mode", None);
                    return;
                }
                let a1v = a1.unwrap_or(b"");
                match sub {
                    "show" => self.display_show(),
                    "view" => {
                        if a1v.len() != 1 || !(b'1'..=b'5').contains(&a1v[0]) {
                            self.refuse(
                                seq,
                                "cmd.bad_arg",
                                b"view 1-5",
                                Some(b"display view <1-5>"),
                            );
                            return;
                        }
                        let from = VIEW_NAME[self.view];
                        self.view = usize::from(a1v[0] - b'1');
                        self.act[self.view] = false;
                        let s = fmtb(&[
                            b"view   ",
                            from.as_bytes(),
                            b" ",
                            arrow,
                            b" ",
                            VIEW_NAME[self.view].as_bytes(),
                        ]);
                        self.local_ok(b"Display", Some(&s), None);
                    }
                    "pane" => {
                        let was = if self.cols >= CONSOLE_PANE_MIN_COLS {
                            let w = !self.pane_user_off;
                            self.pane_user_off = !self.pane_user_off;
                            w
                        } else {
                            let w = self.overlay;
                            self.overlay = !self.overlay;
                            w
                        };
                        let s = fmtb(&[
                            b"tree pane   ",
                            if was { b"shown" } else { b"hidden" },
                            b" ",
                            arrow,
                            b" ",
                            if was { b"hidden" } else { b"shown" },
                            b" (F3 toggles)",
                        ]);
                        self.local_ok(b"Display", Some(&s), None);
                    }
                    "ascii" => {
                        let was = self.ascii;
                        self.ascii = !self.ascii;
                        self.full_redraw = true;
                        self.render_w = -1;
                        let s = fmtb(&[
                            b"glyphs   ",
                            if was { b"ascii" } else { b"unicode" },
                            b" ",
                            arrow,
                            b" ",
                            if self.ascii { b"ascii" } else { b"unicode" },
                        ]);
                        self.local_ok(b"Display", Some(&s), None);
                    }
                    "format" => {
                        let raw = if eq_ic(a1v, "raw") {
                            true
                        } else if eq_ic(a1v, "pretty") {
                            false
                        } else {
                            self.refuse(
                                seq,
                                "cmd.bad_arg",
                                b"format: pretty or raw",
                                Some(b"display format pretty|raw"),
                            );
                            return;
                        };
                        let s = fmtb(&[
                            b"format   ",
                            if self.raw { b"raw" } else { b"pretty" },
                            b" ",
                            arrow,
                            b" ",
                            if raw { b"raw" } else { b"pretty" },
                            if raw {
                                b" (records as the hub sends them)"
                            } else {
                                b""
                            },
                        ]);
                        self.local_ok(b"Display", Some(&s), None);
                        self.raw = raw;
                    }
                    "width" => {
                        let was = self.out_width();
                        if eq_ic(a1v, "auto") {
                            self.width_set = -1;
                        } else if all_digits(a1v)
                            && (fmt::CONSOLE_WIDTH_MIN..=fmt::CONSOLE_WIDTH_MAX)
                                .contains(&fmt::atoi(a1v))
                        {
                            self.width_set = fmt::atoi(a1v);
                        } else {
                            self.refuse(
                                seq,
                                "cmd.bad_arg",
                                b"width: 60-250 or auto",
                                Some(b"display width <60-250|auto>"),
                            );
                            return;
                        }
                        let s = fmtb(&[
                            format!("width   {was} ").as_bytes(),
                            arrow,
                            format!(
                                " {}{}",
                                self.out_width(),
                                if self.width_set < 0 { " (auto)" } else { "" }
                            )
                            .as_bytes(),
                        ]);
                        self.local_ok(b"Display", Some(&s), None);
                    }
                    "events" => {
                        let on = if eq_ic(a1v, "on") {
                            true
                        } else if eq_ic(a1v, "off") {
                            false
                        } else {
                            self.refuse(
                                seq,
                                "cmd.bad_arg",
                                b"events: on or off",
                                Some(b"display events on|off"),
                            );
                            return;
                        };
                        let s = fmtb(&[
                            b"events   ",
                            if self.events_on { b"on" } else { b"off" },
                            b" ",
                            arrow,
                            b" ",
                            if on { b"on" } else { b"off" },
                        ]);
                        self.events_on = on;
                        self.local_ok(b"Display", Some(&s), None);
                    }
                    "clear" => {
                        if (self.view == V_CONSOLE || self.view == V_LOG)
                            && let Some(sb) = self.sb[self.view].as_mut()
                        {
                            sb.clear();
                        }
                        if self.view == V_CONSOLE {
                            if let Some(ent) = self.ent.as_mut() {
                                for e in self.ent_first..self.ent_next {
                                    ent[(e % CONSOLE_SCROLLBACK as i64) as usize] =
                                        Centry::default();
                                }
                            }
                            self.ent_first = self.ent_next;
                        }
                        self.anchor[self.view] = -1;
                        let s = format!("{} view cleared", VIEW_NAME[self.view]);
                        self.local_ok(b"Display", Some(s.as_bytes()), None);
                    }
                    _ => {}
                }
                self.dirty = true;
            }
            _ => {}
        }
        self.marker_ok(seq, words);
    }

    /// Enter a confirmation: the question as [confirm #N] (line mode) or a
    /// highlighted line, and the next input line answers it.
    fn ask_confirm(&mut self, kind: Confirm, want: &[u8], pick_max: i32, question: &[u8]) {
        self.confirming = kind;
        self.confirm_want = c_cut(want, 128).to_vec();
        self.confirm_pick_max = pick_max;
        if self.line_mode {
            let m = fmtb(&[
                format!("[confirm #{}] ", self.confirm_seq).as_bytes(),
                question,
            ]);
            self.lm_line(c_cut(&m, CONSOLE_INPUT_MAX));
        } else {
            self.fs_timestamped(V_CONSOLE, question, RL_WARN);
        }
    }

    fn stage_confirm(&mut self, seq: i32, op: u8, p: &[u8], rq: &PendingRq) {
        self.confirm_seq = seq;
        self.confirm_op = op;
        self.confirm_payload = p.to_vec();
        self.confirm_rq = rq.clone();
    }

    /// Warning lines above a question (hub rekey).
    fn warn_lines(&mut self, lines: &[&[u8]]) {
        if self.raw {
            return;
        }
        let sl = self.session_log_phrase(128);
        let mut f = Flines::new();
        {
            let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
            for (i, l) in lines.iter().enumerate() {
                let t = if i == 0 {
                    fmtb(&[b" ", fmt::glyph(&c, fmt::G_WARN), b" ", l])
                } else {
                    fmtb(&[b"   ", l])
                };
                fmt::flines_add(&mut f, RL_WARN, c_cut(&t, 300));
            }
        }
        self.emit_flines(f);
    }
}

impl Ui {
    /// A pre-read came back: the question names the object, or the command
    /// ends here with what the read found (D2).
    fn pre_reply(&mut self, rq: &PendingRq, text: &[u8]) {
        let rep = fmt::creply_parse(text);
        if rep.err || !rep.ok {
            self.show_reply(text, &rq.words, fmt::FMT_MODE_NORMAL, true);
            let code = c_cut(&rep.code, 64).to_vec();
            let msg = c_cut(rep.res.rv("msg").unwrap_or(b"failed"), 320).to_vec();
            self.marker_err(rq.seq, &code, &msg);
            let m = fmtb(&[
                b"[CONSOLE] ",
                &self.admin,
                b"@",
                &self.ip,
                format!(" #{} ", rq.seq).as_bytes(),
                &self.pend.rq.audit,
                b" -> err: ",
                &code,
            ]);
            self.audit(rq.audit_level, m);
            self.command_done(true);
            return;
        }
        let pc = self.pend.clone();
        let sl = self.session_log_phrase(128);
        let (dot, arrow, dash, ell, g_on, g_err) = {
            let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
            (
                fmt::glyph(&c, fmt::G_DOT),
                fmt::glyph(&c, fmt::G_ARROW),
                fmt::glyph(&c, fmt::G_DASH),
                fmt::glyph(&c, fmt::G_ELL),
                fmt::glyph(&c, fmt::G_ON),
                fmt::glyph(&c, fmt::G_ERR),
            )
        };
        const QCAP: usize = CONSOLE_INPUT_MAX - 64;
        let mut q: Vec<u8> = Vec::new();
        let mut kind = Confirm::Yn;
        let mut want: Vec<u8> = Vec::new();
        let mut pick = 0;
        self.stage_confirm(rq.seq, pc.op, &pc.payload, &pc.rq);
        let mut fail: Option<(&str, Vec<u8>, Vec<u8>)> = None;
        let arg = pc.arg.as_slice();
        match pc.pre {
            Pre::BotDel | Pre::BotKick => {
                let b = rep.r.iter().find(|x| x.typ == b"bot");
                let nick: &[u8] = match b.and_then(|b| b.rvs("nick")) {
                    Some(n) => n,
                    None => arg,
                };
                let on = b.is_some_and(|b| b.rvb("online"));
                let local = on && b.and_then(|b| b.rv("hub")) == Some(b"local");
                let id: &[u8] = b.and_then(|b| b.rv("uuid")).unwrap_or(arg);
                let u8s = c_cut(&fmtb(&[&id[..uprec(id, 8)], ell]), 16).to_vec();
                let hub_name: &[u8] = b.and_then(|b| b.rvs("hub_name")).unwrap_or(b"another hub");
                if pc.pre == Pre::BotDel {
                    q = if local {
                        fmtb(&[
                            b"Delete bot ",
                            nick,
                            b" (",
                            &u8s,
                            b")? It is online on this hub and will be disconnected. (y/N)",
                        ])
                    } else if on {
                        fmtb(&[
                            b"Delete bot ",
                            nick,
                            b" (",
                            &u8s,
                            b")? It is online on ",
                            hub_name,
                            b" and is dropped everywhere. (y/N)",
                        ])
                    } else {
                        fmtb(&[
                            b"Delete bot ",
                            nick,
                            b" (",
                            &u8s,
                            b")? It is offline. (y/N)",
                        ])
                    };
                } else if !local {
                    let msg = fmtb(&[nick, b" is not connected to this hub"]);
                    let hint = if on {
                        fmtb(&[b"it is on ", hub_name, b": kick it there"])
                    } else {
                        b"bot list".to_vec()
                    };
                    fail = Some((
                        "bot.not_local",
                        c_cut(&msg, 256).to_vec(),
                        c_cut(&hint, 256).to_vec(),
                    ));
                } else {
                    q = fmtb(&[
                        b"Disconnect bot ",
                        nick,
                        b" from this hub? It will reconnect on its own. (y/N)",
                    ]);
                }
            }
            Pre::PeerDel => {
                let mut n = 0;
                let mut hit: Option<&fmt::Crec> = None;
                for r in rep.r.iter().filter(|x| x.typ == b"peer") {
                    n += 1;
                    if !arg.is_empty() && r.rvi("n", 0) == fmt::atoll(arg) {
                        hit = Some(r);
                    }
                }
                if n == 0 {
                    fail = Some((
                        "peer.none",
                        b"no peer hubs are configured".to_vec(),
                        b"peer list".to_vec(),
                    ));
                } else if !arg.is_empty() {
                    match hit {
                        None => {
                            let msg =
                                fmtb(&[b"no peer #", arg, format!(" ({n} configured)").as_bytes()]);
                            fail = Some((
                                "peer.not_found",
                                c_cut(&msg, 256).to_vec(),
                                b"peer list".to_vec(),
                            ));
                        }
                        Some(h) => {
                            kind = Confirm::Type;
                            want = c_cut(arg, 128).to_vec();
                            q = fmtb(&[
                                b"Type ",
                                arg,
                                b" to remove peer ",
                                h.rvs("name").or_else(|| h.rv("ip")).unwrap_or(b"?"),
                                b" (",
                                h.rv("ip").unwrap_or(b"?"),
                                b":",
                                &fmt::num(h.rvi("port", 0)),
                                b"):",
                            ]);
                        }
                    }
                } else {
                    // no number: the configured peers, then the number is
                    // the answer
                    if self.raw {
                        self.show_reply(text, &rq.words, fmt::FMT_MODE_NORMAL, false);
                    } else {
                        let mut f = Flines::new();
                        {
                            let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
                            let right = format!("{n} configured");
                            fmt::title(&c, &mut f, b"Peer hubs", Some(right.as_bytes()));
                            let mut nw = 4;
                            let mut aw = 7;
                            let ad_of = |p: &fmt::Crec| -> Vec<u8> {
                                c_cut(
                                    &fmtb(&[
                                        p.rv("ip").unwrap_or(b"?"),
                                        b":",
                                        &fmt::num(p.rvi("port", 0)),
                                    ]),
                                    96,
                                )
                                .to_vec()
                            };
                            for p in rep.r.iter().filter(|x| x.typ == b"peer") {
                                let nm = p.rvs("name").unwrap_or(dash);
                                nw = nw.max(str_width(nm));
                                aw = aw.max(str_width(&ad_of(p)));
                            }
                            let l = fmtb(&[
                                b"   #  ",
                                &padl(b"NAME", nw as usize),
                                b"  ",
                                &padl(b"ADDRESS", aw as usize),
                                b"  LINK",
                            ]);
                            fmt::flines_add(&mut f, RL_HEAD, c_cut(&l, 512));
                            for p in rep.r.iter().filter(|x| x.typ == b"peer") {
                                let ad = ad_of(p);
                                let nm = p.rvs("name").unwrap_or(dash);
                                let up = p.rvb("up");
                                let l = fmtb(&[
                                    b"  ",
                                    &padr(&fmt::num(p.rvi("n", 0)), 2),
                                    b"  ",
                                    nm,
                                    &vec![b' '; (nw - str_width(nm)).max(0) as usize],
                                    b"  ",
                                    &ad,
                                    &vec![b' '; (aw - str_width(&ad)).max(0) as usize],
                                    b"  ",
                                    if up { g_on } else { g_err },
                                    b" ",
                                    if up { b"up" } else { b"down" },
                                ]);
                                fmt::flines_add(
                                    &mut f,
                                    if up { RL_NORMAL } else { RL_WARN },
                                    c_cut(&l, 512),
                                );
                            }
                        }
                        self.emit_flines(f);
                    }
                    kind = Confirm::Pick;
                    pick = n;
                    q = b"Type the number of the peer to remove:".to_vec();
                }
            }
            Pre::Opt => {
                let cur = rep.res.rv("flags").unwrap_or(b"");
                // what the hub will store: letters and digits, each once
                let mut nf: Vec<u8> = Vec::new();
                for &p in arg {
                    if nf.len() + 1 >= 64 {
                        break;
                    }
                    if p.is_ascii_alphanumeric() && !nf.contains(&p) {
                        nf.push(p);
                    }
                }
                // changes[256]: co counts what was asked for; nothing more
                // is appended once it reaches the end
                let mut changes: Vec<u8> = Vec::new();
                let mut co = 0usize;
                let add = |e: Vec<u8>, changes: &mut Vec<u8>, co: &mut usize| {
                    if *co + 1 < 256 {
                        changes.extend_from_slice(c_cut(&e, 256 - *co));
                        *co += e.len();
                    }
                };
                for &p in &nf {
                    if !cur.contains(&p) {
                        let sep: &[u8] = if co > 0 { b"; " } else { b"" };
                        let e = fmtb(&[sep, b"adds ", &[p], b": ", opt_meaning(p).as_bytes()]);
                        add(e, &mut changes, &mut co);
                    }
                }
                for &p in cur {
                    if !nf.contains(&p) {
                        let sep: &[u8] = if co > 0 { b"; " } else { b"" };
                        let e = fmtb(&[sep, b"removes ", &[p], b": ", opt_meaning(p).as_bytes()]);
                        add(e, &mut changes, &mut co);
                    }
                }
                q = fmtb(&[
                    b"Change flags ",
                    if cur.is_empty() { b"none" } else { cur },
                    b" ",
                    arrow,
                    b" ",
                    if nf.is_empty() { b"none" } else { &nf },
                    if co > 0 { b" (" } else { b"" },
                    &changes,
                    if co > 0 { b")" } else { b"" },
                    b"? (y/N)",
                ]);
            }
            Pre::UserDel | Pre::UserKey => {
                // the named user's record (MATCH sends only it), and its masks
                let mut u: Option<&fmt::Crec> = None;
                let mut masks = 0;
                for r in &rep.r {
                    if u.is_none()
                        && r.typ == b"user"
                        && r.rv("name").is_some_and(|n| n.eq_ignore_ascii_case(arg))
                    {
                        u = Some(r);
                    } else if u.is_some() && r.typ == b"mask" {
                        masks += 1;
                    } else if u.is_some() && r.typ == b"user" {
                        break;
                    }
                }
                match u {
                    None => {
                        let msg = fmtb(&[b"no user called \"", arg, b"\""]);
                        fail = Some((
                            "user.not_found",
                            c_cut(&msg, 256).to_vec(),
                            b"user list".to_vec(),
                        ));
                    }
                    Some(u) => {
                        let name = u.rv("name").unwrap_or(arg);
                        let admin = u.rv("role") == Some(b"admin");
                        let ms: &[u8] = if masks == 1 { b"" } else { b"s" };
                        if pc.pre == Pre::UserDel {
                            if admin {
                                kind = Confirm::Type;
                                want = c_cut(name, 128).to_vec();
                                q = fmtb(&[
                                    b"Type ",
                                    name,
                                    b" to remove admin ",
                                    name,
                                    format!(" and their {masks} mask").as_bytes(),
                                    ms,
                                    b":",
                                ]);
                            } else {
                                q = fmtb(&[
                                    b"Remove oper ",
                                    name,
                                    format!(" and their {masks} mask").as_bytes(),
                                    ms,
                                    b"? (y/N)",
                                ]);
                            }
                        } else {
                            q = fmtb(&[
                                b"Replace ",
                                name,
                                b"'s key ",
                                u.rvs("fp").unwrap_or(b"(none)"),
                                b" with the new one?",
                                if admin {
                                    b" Their open consoles close."
                                } else {
                                    b""
                                },
                                b" (y/N)",
                            ]);
                        }
                    }
                }
            }
            Pre::UpgStart => {
                // the plan card: how many nodes already run the target (D2)
                let bv = arg;
                let hv = pc.extra[0].as_slice();
                let (mut b_on, mut b_to, mut h_on, mut h_to) = (0, 0, 0, 0);
                for nd in rep.r.iter().filter(|x| x.typ == b"node") {
                    let bot = nd.rv("kind") == Some(b"bot");
                    let ver = nd.rv("ver").unwrap_or(b"");
                    if bot && ver == bv {
                        b_on += 1;
                    } else if bot {
                        b_to += 1;
                    } else if !hv.is_empty() && ver == hv {
                        h_on += 1;
                    } else {
                        h_to += 1;
                    }
                }
                if !self.raw {
                    let mut f = Flines::new();
                    {
                        let c = self.ctx(fmt::FMT_MODE_NORMAL, &sl);
                        fmt::title(&c, &mut f, b"Upgrade plan", None);
                        let card = |f: &mut Flines, label: &str, v: &[u8]| {
                            fmt::card_line(f, 6, label.as_bytes(), Some(v), RL_NORMAL)
                        };
                        let v = fmtb(&[
                            arrow,
                            b" ",
                            bv,
                            format!("   ({b_on} already on it, {b_to} to upgrade)").as_bytes(),
                        ]);
                        card(&mut f, "bots", c_cut(&v, 512));
                        let v = if !hv.is_empty() {
                            fmtb(&[
                                arrow,
                                b" ",
                                hv,
                                format!("   ({h_on} already on it, {h_to} to upgrade)").as_bytes(),
                            ])
                        } else {
                            b"stay where they are".to_vec()
                        };
                        card(&mut f, "hubs", c_cut(&v, 512));
                        card(
                            &mut f,
                            "nodes",
                            if pc.extra[1].is_empty() {
                                b"whole network"
                            } else {
                                &pc.extra[1]
                            },
                        );
                        let v = fmtb(&[
                            b"bots: ",
                            if pc.extra[2].is_empty() {
                                b"default"
                            } else {
                                &pc.extra[2]
                            },
                            b" ",
                            dot,
                            b" hubs: ",
                            if pc.extra[3].is_empty() {
                                b"default"
                            } else {
                                &pc.extra[3]
                            },
                        ]);
                        card(&mut f, "bases", c_cut(&v, 512));
                    }
                    self.emit_flines(f);
                }
                kind = Confirm::Type;
                want = c_cut(bv, 128).to_vec();
                q = fmtb(&[b"Type ", bv, b" to start the upgrade:"]);
            }
            Pre::None => q = b"Go ahead? (y/N)".to_vec(),
        }
        if let Some((code, msg, hint)) = fail {
            self.refuse_hub(
                rq.seq,
                code,
                &msg,
                (!hint.is_empty()).then_some(hint.as_slice()),
            );
            let m = fmtb(&[
                b"[CONSOLE] ",
                &self.admin,
                b"@",
                &self.ip,
                format!(" #{} ", rq.seq).as_bytes(),
                &pc.rq.audit,
                b" -> err: ",
                code.as_bytes(),
            ]);
            self.audit(LOG_INFO, m);
            self.command_done(true);
            return;
        }
        let q = c_cut(&q, QCAP).to_vec();
        self.ask_confirm(kind, &want, pick, &q);
        // lines typed ahead answer it; then the prompt
        self.command_done(true);
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
                self.note(b"busy: line dropped", RL_ERR);
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
        self.ncmds += 1;
        let ws = Words::split(&l);
        if ws.n() == 0 {
            self.refuse(seq, "cmd.empty", b"empty command", None);
            return;
        }
        if !self.line_mode {
            let echo = fmtb(&[b"> ", &l]);
            self.fs_timestamped(V_CONSOLE, c_cut(&echo, CONSOLE_INPUT_MAX + 4), RL_CMD);
        }
        let Some((c, argi)) = find_cmd(&ws) else {
            let w0 = ws.get(0);
            if cmd_known_word(w0) {
                let m = if ws.n() >= 2 {
                    let w1 = ws.get(1);
                    fmtb(&[w0, b" has no command ", &w1[..uprec(w1, 40)]])
                } else {
                    fmtb(&[w0, b" needs a command"])
                };
                let h = fmtb(&[b"help ", w0]);
                self.refuse(seq, "cmd.usage", c_cut(&m, 128), Some(c_cut(&h, 64)));
            } else {
                let m = fmtb(&[b"unknown command \"", &w0[..uprec(w0, 40)], b"\""]);
                self.refuse(seq, "cmd.unknown", c_cut(&m, 128), Some(b"help"));
            }
            return;
        };
        let words = c_cut(&cmd_words(c), 32).to_vec();
        let na = ws.n() - argi;
        let rest_arg = c.build == B::Local && c.sub == Some("filter");
        if na < c.nargs || (!rest_arg && na > c.nargs + c.optargs) {
            let m = format!("usage: {}", c.usage);
            self.refuse(seq, "cmd.usage", c_cut(m.as_bytes(), 160), None);
            return;
        }
        if c.build != B::Local && (argi..ws.n()).any(|i| ws.get(i).contains(&b'|')) {
            self.refuse(
                seq,
                "cmd.bad_arg",
                b"'|' is not allowed in an argument",
                None,
            );
            return;
        }
        if c.build == B::Local {
            self.local_command(c, &ws, argi, &l, seq, &words);
            return;
        }
        let built = match build_payload(c, &ws, argi) {
            Ok(b) => b,
            Err((why, hint)) => {
                self.refuse(seq, "cmd.bad_arg", &why, hint.map(str::as_bytes));
                return;
            }
        };
        let (op, confirm) = (built.op, built.confirm);
        let rq = PendingRq {
            kind: Rq::User,
            seq,
            words: words.clone(),
            audit: l[..uprec(&l, 300)].to_vec(),
            audit_level: if confirm != Confirm::None || op == CMD_ADMIN_SET_LOG_LEVEL {
                LOG_WARNING
            } else {
                LOG_INFO
            },
            mode: built.mode,
        };
        let a1: Vec<u8> = if na > 0 {
            ws.get(argi).to_vec()
        } else {
            Vec::new()
        };
        if confirm == Confirm::None {
            self.send_request(op, &built.payload, rq);
            return;
        }

        // D2: read first, so the question names the object
        if c.pre != Pre::None {
            let mut pc = PendCmd {
                pre: c.pre,
                op,
                payload: built.payload.clone(),
                arg: c_cut(&a1, 256).to_vec(),
                extra: Default::default(),
                rq: rq.clone(),
            };
            let (pop, pp): (u8, Vec<u8>) = match c.pre {
                Pre::BotDel | Pre::BotKick => (CMD_ADMIN_LIST_FULL, c_cut(&a1, 600).to_vec()),
                Pre::PeerDel => (CMD_ADMIN_LIST_PEERS, Vec::new()),
                Pre::Opt => {
                    pc.arg = c_cut(if a1 == b"-" { b"" } else { &a1 }, 256).to_vec();
                    (CMD_ADMIN_GET_OPT_FLAGS, Vec::new())
                }
                Pre::UserDel | Pre::UserKey => (CMD_ADMIN_MATCH, c_cut(&a1, 600).to_vec()),
                Pre::UpgStart => {
                    let (mut bb, mut hb): (&[u8], &[u8]) = (b"", b"");
                    for i in argi + 1..ws.n() {
                        let w = ws.get(i);
                        if let Some(v) = kv_opt(w, "hub") {
                            pc.extra[0] = c_cut(if v == b"-" { b"" } else { v }, 256).to_vec();
                        } else if let Some(v) = kv_opt(w, "nodes") {
                            pc.extra[1] = c_cut(v, 256).to_vec();
                        } else if let Some(v) = kv_opt(w, "botbase") {
                            bb = v;
                        } else if let Some(v) = kv_opt(w, "hubbase") {
                            hb = v;
                        }
                    }
                    pc.extra[2] = c_cut(bb, 256).to_vec();
                    pc.extra[3] = c_cut(hb, 256).to_vec();
                    let pp = if !bb.is_empty() || !hb.is_empty() {
                        fmtb(&[b"releases|", bb, b"|", hb])
                    } else {
                        b"releases".to_vec()
                    };
                    (CMD_ADMIN_UPGRADE_STATUS, c_cut(&pp, 600).to_vec())
                }
                Pre::None => (0, Vec::new()),
            };
            self.pend = pc;
            let pr = PendingRq {
                kind: Rq::Pre,
                ..rq
            };
            self.send_request(pop, &pp, pr);
            return;
        }

        // Ask first; the next line answers.
        self.stage_confirm(seq, op, &built.payload, &rq);
        let mut want: Vec<u8> = Vec::new();
        let mut kind = Confirm::Yn;
        let a2: &[u8] = if na > 1 { ws.get(argi + 1) } else { b"" };
        let q: Vec<u8> = if op == CMD_ADMIN_REGEN_KEYS {
            let hn: Vec<u8> = if self.hubname.is_empty() {
                b"hub".to_vec()
            } else {
                self.hubname.clone()
            };
            let l1 = fmtb(&[b"hub rekey makes a new identity for ", &hn, b"."]);
            let l1 = c_cut(&l1, 160).to_vec();
            self.warn_lines(&[
                &l1,
                b"Every peer and bot link drops now; each peer runs peer set <uuid> key, each bot +hub with the new key.",
                b"Back up .irchub.cnf first: the old key is overwritten.",
            ]);
            kind = Confirm::Type;
            want = c_cut(&hn, 128).to_vec();
            fmtb(&[b"Type ", &hn, b" to go ahead:"])
        } else if op == CMD_ADMIN_PURGE_TOMBSTONES {
            if eq_ic(&a1, "now") {
                b"Purge every tombstone now, here and on all peers? (y/N)".to_vec()
            } else {
                fmtb(&[
                    b"Purge tombstones older than ",
                    &a1,
                    b" days, here and on all peers? (y/N)",
                ])
            }
        } else if op == CMD_ADMIN_DEL_ALLOWLIST || op == CMD_ADMIN_DEL_DENYLIST {
            fmtb(&[
                b"Remove ",
                a2,
                b" from the ",
                if op == CMD_ADMIN_DEL_ALLOWLIST {
                    b"allow"
                } else {
                    b"deny"
                },
                b" list? (y/N)",
            ])
        } else if op == CMD_ADMIN_SET_LOG_LEVEL {
            let lvl = level_arg(a2);
            fmtb(&[
                b"Set the ",
                if built.payload[0] != 0 {
                    b"console"
                } else {
                    b"file"
                },
                b" log level to ",
                if (0..=4).contains(&lvl) {
                    LEVEL_WORD[lvl as usize].as_bytes()
                } else {
                    a2
                },
                b"? (y/N)",
            ])
        } else if op == CMD_ADMIN_DEL_USERMASK {
            let a3: &[u8] = if na > 2 { ws.get(argi + 2) } else { b"" };
            fmtb(&[b"Remove mask ", a3, b" from ", a2, b"? (y/N)"])
        } else if op == CMD_ADMIN_DEL_CHANNEL {
            fmtb(&[b"Remove ", &a1, b" from every bot? They part it. (y/N)"])
        } else if op == CMD_ADMIN_UPGRADE_STATUS && c.sub == Some("abort") {
            b"Abort the running upgrade and roll back what it moved? (y/N)".to_vec()
        } else if op == CMD_ADMIN_UPGRADE_STATUS && c.sub == Some("forget") {
            b"Forget the roll-up plan here and on every hub? (y/N)".to_vec()
        } else {
            fmtb(&[b"Really ", &words, b"? (y/N)"])
        };
        let q = c_cut(&q, CONSOLE_INPUT_MAX - 64).to_vec();
        self.ask_confirm(kind, &want, 0, &q);
    }

    fn confirm_answer(&mut self, answer: &[u8], cancelled: bool) {
        let kind = self.confirming;
        self.confirming = Confirm::None;
        let mut ok = !cancelled;
        if ok {
            ok = match kind {
                Confirm::Yn => eq_ic(answer, "y") || eq_ic(answer, "yes"),
                Confirm::Pick => {
                    let v = fmt::atoi(answer);
                    let good = all_digits(answer) && v >= 1 && v <= self.confirm_pick_max;
                    if good {
                        self.confirm_payload = v.to_string().into_bytes();
                    }
                    good
                }
                _ => answer == self.confirm_want.as_slice(),
            };
        }
        if !ok {
            self.refuse(self.confirm_seq, "cmd.cancelled", b"cancelled", None);
            let m = fmtb(&[
                b"[CONSOLE] ",
                &self.admin,
                b"@",
                &self.ip,
                format!(" #{} ", self.confirm_seq).as_bytes(),
                &self.confirm_rq.audit,
                b" -> cancelled",
            ]);
            self.audit(LOG_INFO, m);
            crate::crypto::wipe(&mut self.confirm_payload);
            self.confirm_payload.clear();
            self.command_done(false);
            return;
        }
        let payload = std::mem::take(&mut self.confirm_payload);
        let rq = self.confirm_rq.clone();
        self.send_request(self.confirm_op, &payload, rq);
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
    fn completions(&self, word_idx: usize, w: &mut [Vec<u8>; 3], prefix: &[u8]) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut pooln = 0usize;
        let starts =
            |s: &[u8]| s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix);
        let add = |out: &mut Vec<Vec<u8>>, s: &[u8]| -> bool {
            if !out.iter().any(|o| o == s) && out.len() < 64 && starts(s) {
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
        if w[0] == b"?" {
            w[0] = b"help".to_vec();
        }
        // help <group> <command>
        if eq_ic(&w[0], "help") && word_idx == 2 {
            for d in CMDS {
                if let Some(sub) = d.sub
                    && eq_ic(&w[1], d.cmd)
                {
                    add(&mut out, sub.as_bytes());
                }
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
        if eq_ic(&w[0], "log")
            && sub == Some("set")
            && pos == 1
            && !eq_ic(&w[2], "file")
            && !eq_ic(&w[2], "console")
        {
            return out;
        }
        let Some(ac) = ARG_COMP
            .iter()
            .find(|a| eq_ic(&w[0], a.0) && a.1 == sub && (a.2.is_none() || a.2 == Some(pos)))
        else {
            return out;
        };
        match ac.3 {
            Ck::Group => {
                for g in GROUPS {
                    add(&mut out, g.0.as_bytes());
                }
                return out;
            }
            Ck::Words(words) => {
                let mut p = words.as_bytes();
                while !p.is_empty() && pooln < 128 {
                    let l = p.iter().position(|&b| b == b' ').unwrap_or(p.len());
                    if add(&mut out, c_cut(&p[..l], 72)) {
                        pooln += 1;
                    }
                    p = &p[l..];
                    while p.first() == Some(&b' ') {
                        p = &p[1..];
                    }
                }
                return out;
            }
            _ => {}
        }
        // uuids (and for show / peer set, names) from the tree rows:
        // H|depth|name|uuid|..., B|depth|nick|uuid|..., D|nick|uuid|... (offline)
        let tree = self.tree.as_deref().unwrap_or(b"");
        for row in tree.split(|&b| b == b'\n') {
            if row.is_empty() || out.len() >= 64 || pooln >= 128 {
                break;
            }
            if row.len() > TREE_ROW_MAX {
                continue;
            }
            let f: Vec<&[u8]> = row
                .split(|&b| b == b'|')
                .filter(|x| !x.is_empty())
                .take(10)
                .collect();
            let nf = f.len();
            let ty = f.first().map_or(0, |x| x[0]);
            let mut cand: [Option<&[u8]>; 2] = [None, None];
            match ac.3 {
                Ck::HubName if ty == b'H' && nf >= 4 && f[1] != b"0" => {
                    cand = [Some(f[2]), Some(f[3])];
                }
                Ck::Bot | Ck::BotOn | Ck::BotNick if ty == b'B' && nf >= 4 => {
                    cand[0] = Some(f[3]);
                    if ac.3 == Ck::BotNick {
                        cand[1] = Some(f[2]);
                    }
                }
                Ck::Bot | Ck::BotNick if ty == b'D' && nf >= 3 => {
                    cand[0] = Some(f[2]);
                    if ac.3 == Ck::BotNick {
                        cand[1] = Some(f[1]);
                    }
                }
                _ => {}
            }
            for c in cand.iter().flatten() {
                if pooln >= 128 {
                    break;
                }
                if *c == b"-" {
                    continue;
                }
                if add(&mut out, c_cut(c, 72)) {
                    pooln += 1;
                }
            }
        }
        out
    }

    fn complete(&mut self) {
        let mut ws = self.in_cur;
        while ws > 0 && self.input[ws - 1] != b' ' {
            ws -= 1;
        }
        let prefix_full = c_cut(&self.input[ws..self.in_cur], CONSOLE_INPUT_MAX).to_vec();
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
        let out = self.completions(idx, &mut w, pfx);
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
            // a key= option takes its value right after the '='
            let space = out.len() == 1 && out[0].last() != Some(&b'=');
            let add = fmtb(&[
                &out[0][have..common.max(have)],
                if space { b" " } else { b"" },
            ]);
            let add = c_cut(&add, 128).to_vec();
            self.in_insert(&add);
        } else if !self.line_mode {
            let mut line: Vec<u8> = Vec::new();
            for (i, o) in out.iter().enumerate() {
                if line.len() + 2 >= 512 {
                    break;
                }
                let e = fmtb(&[if i > 0 { b"  " } else { b"" }, o]);
                let room = 512 - line.len();
                line.extend_from_slice(c_cut(&e, room));
                if e.len() >= room {
                    break;
                }
            }
            self.note(&line, RL_RULE);
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
            self.search = line[..uprec(&line, 127)].to_vec();
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
        self.now_ms = now_ms;
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
        RL_CMD => "0;1",
        RL_ERR => "0;31",
        RL_OK => "0;32",
        RL_TITLE => "0;1;36",
        RL_RULE => "0;36",
        RL_HEAD => "0;1",
        RL_WARN => "0;33",
        RL_DIM => "0;90",
        _ => SGR_RESET,
    }
}

struct RowB {
    b: Vec<u8>,
    /// cells used
    w: i32,
    /// cells allowed
    max: i32,
    /// display ascii: non-ASCII through fmt::ascii_char
    ascii: bool,
}

impl RowB {
    fn new(max: i32) -> RowB {
        RowB {
            b: Vec::new(),
            w: 0,
            max,
            ascii: false,
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
            let (ul, _, mut cw) = next_char(&s[i..]);
            let mut a: Option<&[u8]> = None;
            if self.ascii && s[i] >= 0x80 {
                a = fmt::ascii_char(&s[i..]).0;
                if let Some(x) = a {
                    cw = x.len() as i32;
                }
            }
            if used + cw > lim {
                break;
            }
            match a {
                Some(x) => self.b.extend_from_slice(x),
                None => self.b.extend_from_slice(&s[i..(i + ul).min(s.len())]),
            }
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
            t.depth = fmt::atoi(f[1]);
            t.name = cut(f[2], 64);
            t.uuid = cut(f[3], 64);
            t.online = fmt::atoi(f[4]) != 0;
            t.ver = cut(f[6], 24);
            t.var = cut(f[7], 8);
            t.started = fmt::atoll(f[8]);
            out.push(t);
        } else if t.typ == b'B' && nf >= 9 {
            t.depth = fmt::atoi(f[1]);
            t.name = cut(f[2], 64);
            t.uuid = cut(f[3], 64);
            t.ver = cut(f[4], 24);
            t.server = cut(f[5], 72);
            t.var = cut(f[7], 8);
            t.started = fmt::atoll(f[8]);
            t.online = true;
            out.push(t);
        } else if t.typ == b'D' && nf >= 4 {
            t.depth = 1;
            t.name = cut(f[1], 64);
            t.uuid = cut(f[2], 64);
            t.started = fmt::atoll(f[3]);
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

    /// Views 4 and 5: the upgrade status / statistics reply, laid out by
    /// the same renderer as the commands (no result line), from line
    /// anchor[view].
    fn view_rows(
        &self,
        view: usize,
        text: Option<&[u8]>,
        w: i32,
        h: usize,
        rows: &mut [RowB],
        col0: i32,
    ) {
        let mut f = Flines::new();
        match text {
            None => fmt::flines_add(&mut f, RL_DIM, b"(asking the hub...)"),
            Some(text) => {
                let rep = fmt::creply_parse(text);
                let sl = self.session_log_phrase(128);
                let mut c = self.ctx(fmt::FMT_MODE_VIEW, &sl);
                c.ascii = self.ascii;
                c.width = w;
                let words: &[u8] = if view == V_UPG {
                    b"upgrade status"
                } else {
                    b"hub stats"
                };
                fmt::reply(&c, &rep, words, &mut f);
            }
        }
        let top = self.anchor[view].max(0);
        let start = (top.min(f.len() as i64)) as usize;
        for (y, l) in f[start..].iter().take(h).enumerate() {
            rows[y].sgr(kind_sgr(l.role));
            rows[y].text(&l.text, w);
            rows[y].sgr(SGR_RESET);
            rows[y].pad(col0 + w);
        }
    }

    fn net_rows_count(&self) -> i32 {
        parse_tree(self.tree.as_deref().unwrap_or(b"")).len() as i32
    }

    /// View 3: every tree column, and the selected node's details.
    fn net_view(&mut self, w: i32, h: usize, rows: &mut [RowB], col0: i32) {
        let tr = parse_tree(self.tree.as_deref().unwrap_or(b""));
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
            // %*s: a negative width pads as much on the left side
            let ind = if t.typ == b'D' {
                0
            } else {
                (t.depth.wrapping_mul(2).unsigned_abs() as usize).min(200)
            };
            let kind: &[u8] = match t.typ {
                b'H' => b"hub",
                b'B' => b"bot",
                _ => b"off",
            };
            let name = fmtb(&[&vec![b' '; ind], kind, b" ", &t.name]);
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
                c_cut(&fmt::when(t.started, now_s()), 64).to_vec()
            } else {
                b"--".to_vec()
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
                &when,
            ]);
            rows[y0 + 4].text(c_cut(&l4, 256), w);
            rows[y0 + 4].pad(col0 + w);
        }
    }

    fn status_bar(&self, r: &mut RowB, now_ms: i64, pane_hidden: bool) {
        let mut s: Vec<(Vec<u8>, i32, &'static str)> = Vec::new();
        let clk = clock_utc(false);
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
            fmtb(&[&clk, b" ", c_cut(hub, 41), b" ", c_cut(&self.admin, 41)]),
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
            .map(|y| {
                let mut rb = RowB::new(if y == r - 1 { c - 1 } else { c });
                rb.ascii = self.ascii;
                rb
            })
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
                    // a C char[2048]: a row of 3-byte glyphs (or zero-width
                    // marks) can outgrow it; cut where no character is split
                    let seg_text = &l.text[seg.from..seg.to];
                    let n = if seg_text.len() >= CONSOLE_INPUT_MAX * 2 {
                        utf8_cut(seg_text, CONSOLE_INPUT_MAX * 2 - 1)
                    } else {
                        seg_text.len()
                    };
                    let buf = seg_text[..n].to_vec();
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
                    self.upg_text.as_deref()
                } else {
                    self.stats_text.as_deref()
                };
                self.view_rows(self.view, text, main_w, h, body, 0);
            }
            for row in body.iter_mut() {
                row.sgr(SGR_RESET);
                row.pad(main_w);
            }
            // tree pane
            if pane_w > 0 {
                let tr = parse_tree(self.tree.as_deref().unwrap_or(b""));
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
        sbar.ascii = self.ascii;
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

    /// The output pane's width (the terminal minus the tree pane).
    fn main_width(&self) -> i32 {
        let c = self.cols;
        let wide = c >= CONSOLE_PANE_MIN_COLS;
        let mut pane_w = 0;
        if wide && !self.pane_user_off {
            pane_w = (c * 30 / 100).clamp(CONSOLE_PANE_MIN, CONSOLE_PANE_MAX);
        }
        if !wide && self.overlay {
            pane_w = if c - 20 < CONSOLE_PANE_MIN {
                c - 20
            } else {
                CONSOLE_PANE_MIN
            };
        }
        pane_w = pane_w.max(0);
        if pane_w > 0 { c - pane_w - 1 } else { c }
    }

    /// D5: the console view laid out again for a new width — every reply it
    /// holds is rendered anew from its records.
    fn relayout(&mut self) {
        let w = self.main_width();
        if self.render_w == w || self.ent.is_none() {
            return;
        }
        self.render_w = w;
        let mut lines: Vec<(Vec<u8>, u8)> = Vec::new();
        if let Some(ent) = self.ent.as_ref() {
            for e in self.ent_first..self.ent_next {
                let x = &ent[(e % CONSOLE_SCROLLBACK as i64) as usize];
                if let Some(t) = &x.text {
                    let t = if self.ascii { fmt::ascii(t) } else { t.clone() };
                    lines.push((t, x.kind));
                } else if let Some(r) = &x.reply {
                    for l in self.render_reply(r, &x.words, x.mode) {
                        lines.push((l.text, l.role));
                    }
                }
            }
        }
        if let Some(sb) = self.sb[V_CONSOLE].as_mut() {
            sb.clear();
            for (t, k) in &lines {
                sb.add(t, *k, LOG_INFO);
            }
        }
        self.anchor[V_CONSOLE] = -1;
    }

    fn draw(&mut self, now_ms: i64) {
        if self.line_mode {
            return;
        }
        self.relayout();
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
            ncmds: 0,
            user_busy: false,
            rq: Vec::new(),
            queued: Vec::new(),
            confirming: Confirm::None,
            confirm_seq: 0,
            confirm_want: Vec::new(),
            confirm_pick_max: 0,
            confirm_op: 0,
            confirm_payload: Vec::new(),
            confirm_rq: PendingRq::default(),
            pend: PendCmd::default(),
            held: Vec::new(),
            dropped: 0,
            raw: false,
            width_set: 0,
            events_on: false,
            greeted: false,
            now_ms: 0,
            start_ms: 0,
            st: Status {
                loglevel: -1,
                consolelevel: -1,
                ..Status::default()
            },
            tree: None,
            upg_text: None,
            stats_text: None,
            upg_at: 0,
            stats_at: 0,
            last_upg: Vec::new(),
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
            ent: (!line_mode).then(|| vec![Centry::default(); CONSOLE_SCROLLBACK]),
            ent_first: 0,
            ent_next: 0,
            render_w: -1,
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
        self.now_ms = now_ms;
        self.start_ms = now_ms;
        self.started = true;
        self.subscribe();
        // §2.1: "irchub console" stays the first words (scripts look for
        // it); the mesh summary follows once the first status event is in
        let hub: &[u8] = if self.hubname.is_empty() {
            b"hub"
        } else {
            &self.hubname
        };
        let hello = fmtb(&[
            format!("irchub console {HUB_VERSION} ({HUB_UPDATE_VARIANT}) · ").as_bytes(),
            hub,
            " · admin ".as_bytes(),
            &self.admin,
            b" from ",
            &self.ip,
        ]);
        let hello = c_cut(&hello, 320).to_vec();
        if self.line_mode {
            self.lm_line(&hello);
            self.lm_prompt();
            return;
        }
        // alternate screen, bracketed paste
        self.term
            .extend_from_slice(b"\x1b[?1049h\x1b[?2004h\x1b[H\x1b[2J");
        self.fs_line(&hello, RL_TITLE);
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
        self.now_ms = now_ms;
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
                    RL_WARN,
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
        let m = format!("irchub console closed: {why}\r\n");
        self.term.extend_from_slice(&fmt::snp(512, m.into_bytes()));
    }
}

impl Drop for Ui {
    fn drop(&mut self) {
        crate::crypto::wipe(&mut self.input);
        crate::crypto::wipe(&mut self.confirm_payload);
        crate::crypto::wipe(&mut self.pend.payload);
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
            format!(
                "irchub console {HUB_VERSION} ({HUB_UPDATE_VARIANT}) · hub1 · admin robert from 127.0.0.1\r\n> "
            )
        );
        assert!(run(&mut ui, "foo\r").contains("[err #1] unknown command \"foo\"\r\n> "));
        assert!(
            run(&mut ui, "bot del x|y\r").contains("[err #2] '|' is not allowed in an argument")
        );
        // bot del reads the bot first (D2), then asks
        let _ = ui.take_core();
        run(&mut ui, "bot del abc\r");
        assert_eq!(&ui.take_core()[4..], b"\x11abc");
        ui.core_frame_in(
            CONSOLE_REPLY,
            b"ok|bot.list|total=1|online=0\nbot|uuid=abc|nick=alpha|online=0",
            1,
        );
        let t = String::from_utf8_lossy(&ui.take_term()).into_owned();
        assert!(
            t.contains("[confirm #3] Delete bot alpha (abc…)? It is offline. (y/N)\r\n? "),
            "{t}"
        );
        assert!(run(&mut ui, "n\r").contains("[err #3] cancelled\r\n> "));
        run(&mut ui, "bot list\r");
        let core = ui.take_core();
        assert_eq!(core, [0, 0, 0, 1, CMD_ADMIN_LIST_FULL]);
        ui.core_frame_in(CONSOLE_REPLY, b"ok|bot.list|total=0|online=0", 1);
        let t = String::from_utf8_lossy(&ui.take_term()).into_owned();
        assert!(t.contains("(no bots registered)"), "{t}");
        assert!(t.ends_with("[ok #4] bot list\r\n> "), "{t}");
        run(&mut ui, "user show *\r");
        ui.core_frame_in(CONSOLE_REPLY, b"err|user.not_found|msg=no such user", 1);
        let t = String::from_utf8_lossy(&ui.take_term()).into_owned();
        assert_eq!(t, " ✗ no such user\r\n[err #5] no such user\r\n> ");
    }

    #[test]
    fn events_are_held_during_a_command() {
        let mut ui = Ui::new(true, 80, 24, "a", "ip", "h");
        ui.start(1);
        let _ = ui.take_term();
        ui.input(b"display format raw\r", 1);
        let _ = ui.take_term();
        ui.core_frame_in(CMD_CONSOLE, b"status|name=h|peers=0/0", 1);
        assert_eq!(
            String::from_utf8_lossy(&ui.take_term()),
            "\r[evt status] name=h|peers=0/0\r\n> "
        );
        run(&mut ui, "hub stats\r");
        ui.core_frame_in(CMD_CONSOLE, b"tree|H|0|h|u|1|0|2.4.3|rs|0\n", 1);
        assert!(ui.take_term().is_empty());
        ui.core_frame_in(CONSOLE_REPLY, b"ok|stats|up=1", 1);
        assert_eq!(
            String::from_utf8_lossy(&ui.take_term()),
            "ok|stats|up=1\r\n[ok #2] hub stats\r\n[evt tree] begin 1\r\n[evt tree] H|0|h|u|1|0|2.4.3|rs|0\r\n[evt tree] end\r\n> "
        );
    }

    #[test]
    fn ascii_filter_and_help_examples() {
        let mut ui = Ui::new(true, 80, 24, "a", "ip", "h");
        ui.start(1);
        let _ = ui.take_term();
        run(&mut ui, "display ascii\r");
        let t = run(&mut ui, "help bot add\r");
        assert!(t.is_ascii(), "{t}");
        // examples are never wrapped, whatever the width
        assert!(
            t.contains(&format!(
                "   bot add alpha {} {}\r\n",
                ex_uuid!(),
                ex_key!()
            )),
            "{t}"
        );
        let t = run(&mut ui, "? upgrade nope\r");
        assert!(t.contains("upgrade has no command nope"), "{t}");
        assert!(t.contains("hint  help upgrade"), "{t}");
    }
}
