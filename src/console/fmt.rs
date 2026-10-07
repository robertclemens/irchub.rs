//! SSH admin console — the output renderer (docs/console.md §3.5); mirrors
//! irchub `hub_console_fmt.c` function for function.
//!
//! The hub answers every admin command with records (`crate::reply`); this
//! module parses them and lays them out for the view: title rules, aligned
//! tables that go wide → stacked → cards as the width shrinks (never dropping
//! a field), key/value cards, ✓/✗ results with their effects, UTC times,
//! 1024-based sizes.  Pure functions of (records, width, glyphs, clock), so
//! the C console produces the same bytes: no locale, no floating point, no
//! time zone.  Text is bytes throughout — a C `char buf[N]` that truncates
//! (`snp`) may cut a character in half, and the Rust side must cut the same.

use super::ui::{next_char, sanitize, str_width, uprec};

/// Line mode's output width unless "display width" says otherwise.
pub const CONSOLE_LINE_WIDTH: i32 = 100;
pub const CONSOLE_WIDTH_MIN: i32 = 60;
pub const CONSOLE_WIDTH_MAX: i32 = 250;

// Line roles (the full screen colours them; line mode ignores them).
pub const RL_NORMAL: u8 = 0;
pub const RL_CMD: u8 = 1;
pub const RL_ERR: u8 = 2;
pub const RL_OK: u8 = 3;
pub const RL_TITLE: u8 = 4;
pub const RL_WARN: u8 = 5;
pub const RL_DIM: u8 = 6;
pub const RL_HEAD: u8 = 7;
pub const RL_RULE: u8 = 8;

pub const FMT_MODE_NORMAL: i32 = 0;
/// "hub set" alone: the settings table.
pub const FMT_MODE_HUB_SETTINGS: i32 = 1;
/// Full-screen views 4/5.
pub const FMT_MODE_VIEW: i32 = 2;

// ===========================================================================
// Small byte-string helpers (the C printf family, byte for byte)
// ===========================================================================

/// Concatenate byte strings.
pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

/// What `snprintf(buf, cap, …)` keeps: the first cap-1 bytes, cut anywhere
/// (the renderer's plain snprintf may split a character, as in C).
pub fn snp(cap: usize, mut v: Vec<u8>) -> Vec<u8> {
    if cap == 0 {
        v.clear();
    } else if v.len() >= cap {
        v.truncate(cap - 1);
    }
    v
}

/// Decimal text of a number (`%d`, `%lld`, `%llu`).
pub fn num<T: std::fmt::Display>(x: T) -> Vec<u8> {
    x.to_string().into_bytes()
}

/// `%s` of a pointer that may be NULL: glibc prints "(null)".
fn nul(o: Option<&[u8]>) -> &[u8] {
    o.unwrap_or(b"(null)")
}

fn s(x: &str) -> &[u8] {
    x.as_bytes()
}

/// C `isspace` (the "C" locale).
fn is_space(b: u8) -> bool {
    b == b' ' || (9..=13).contains(&b)
}

/// C `strtoll(s, &end, 10)`: (value, bytes consumed; 0 = no conversion).
/// Saturates on overflow like glibc.
pub fn strtoll(s: &[u8]) -> (i64, usize) {
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let neg = i < s.len() && s[i] == b'-';
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        i += 1;
    }
    let d0 = i;
    let mut v: i128 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if v < i128::from(i64::MAX) + 2 {
            v = v * 10 + i128::from(s[i] - b'0');
        }
        i += 1;
    }
    if i == d0 {
        return (0, 0);
    }
    let v = if neg { -v } else { v };
    let v = v.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
    (v, i)
}

/// C `atoll`.
pub fn atoll(s: &[u8]) -> i64 {
    strtoll(s).0
}

/// C `atoi`: (int)strtol — the long saturates, the int cast wraps.
pub fn atoi(s: &[u8]) -> i32 {
    strtoll(s).0 as i32
}

/// C `strtoull(s, NULL, base)` (base 10 or 16; 16 takes an optional 0x).
pub fn strtoull(s: &[u8], base: u32) -> u64 {
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let neg = i < s.len() && s[i] == b'-';
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        i += 1;
    }
    if base == 16
        && i + 1 < s.len()
        && s[i] == b'0'
        && (s[i + 1] == b'x' || s[i + 1] == b'X')
        && i + 2 < s.len()
        && s[i + 2].is_ascii_hexdigit()
    {
        i += 2;
    }
    let mut v: u64 = 0;
    let mut over = false;
    let d0 = i;
    while i < s.len() {
        let Some(d) = (s[i] as char).to_digit(base) else {
            break;
        };
        match v
            .checked_mul(u64::from(base))
            .and_then(|x| x.checked_add(u64::from(d)))
        {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if i == d0 {
        return 0;
    }
    if over {
        return u64::MAX;
    }
    if neg { v.wrapping_neg() } else { v }
}

// ===========================================================================
// Parsing (docs/console.md §3.1)
// ===========================================================================

/// One record: its type ("bot", "peer", …; tree rows "H", "B", "D") and its
/// fields, un-escaped and sanitized; `line` is the whole record, sanitized.
#[derive(Default, Clone)]
pub struct Crec {
    pub typ: Vec<u8>,
    pub k: Vec<Vec<u8>>,
    pub v: Vec<Vec<u8>>,
    pub line: Vec<u8>,
}

/// A parsed reply.  Neither ok nor err: not a record reply (shown as text).
#[derive(Default, Clone)]
pub struct Creply {
    pub ok: bool,
    pub err: bool,
    pub code: Vec<u8>,
    /// The result line's k=v (msg, hint, …).
    pub res: Crec,
    /// Data records.
    pub r: Vec<Crec>,
}

impl Crec {
    /// The value of `key`, None if absent.
    pub fn rv(&self, key: &str) -> Option<&[u8]> {
        let key = key.as_bytes();
        self.k
            .iter()
            .position(|k| k.as_slice() == key)
            .map(|i| self.v[i].as_slice())
    }

    /// The value as a number (the whole value must be one), else `dflt`.
    pub fn rvi(&self, key: &str, dflt: i64) -> i64 {
        match self.rv(key) {
            Some(v) if !v.is_empty() => {
                let (x, end) = strtoll(v);
                if end == v.len() { x } else { dflt }
            }
            _ => dflt,
        }
    }

    pub fn rvb(&self, key: &str) -> bool {
        self.rvi(key, 0) != 0
    }

    /// A value that is present and not empty.
    pub fn rvs(&self, key: &str) -> Option<&[u8]> {
        self.rv(key).filter(|v| !v.is_empty())
    }

    fn rvu(&self, key: &str) -> u64 {
        self.rv(key).map_or(0, |v| strtoull(v, 10))
    }

    fn is(&self, t: &str) -> bool {
        self.typ == t.as_bytes()
    }

    fn add(&mut self, k: Vec<u8>, v: Vec<u8>) {
        self.k.push(k);
        self.v.push(v);
    }
}

/// %25 %7C %0A %0D back to their bytes, then the sanitizer (§5).
fn unescape_clean(s: &[u8]) -> Vec<u8> {
    let n = s.len();
    let mut u = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        if s[i] == b'%' && i + 2 < n {
            let (a, b) = (s[i + 1], s[i + 2]);
            let c = match (a, b) {
                (b'2', b'5') => b'%',
                (b'7', b'C' | b'c') => b'|',
                (b'0', b'A' | b'a') => b'\n',
                (b'0', b'D' | b'd') => b'\r',
                _ => 0,
            };
            if c != 0 {
                u.push(c);
                i += 3;
                continue;
            }
        }
        u.push(s[i]);
        i += 1;
    }
    let cap = u.len() + 1;
    sanitize(&u, cap)
}

fn clean_dup(s: &[u8]) -> Vec<u8> {
    sanitize(s, s.len() + 1)
}

/// One "type|k=v|k=v" line; `kv` false keeps the fields positional (the
/// tree rows), stored as keys "0", "1", ….
fn parse_rec(s: &[u8], kv: bool) -> Crec {
    let mut r = Crec {
        line: clean_dup(s),
        ..Crec::default()
    };
    let n = s.len();
    let (mut start, mut field) = (0usize, 0usize);
    let mut i = 0;
    loop {
        if i < n && s[i] != b'|' {
            i += 1;
            continue;
        }
        let f = &s[start..i];
        if field == 0 {
            r.typ = clean_dup(f);
        } else if kv {
            match f.iter().position(|&b| b == b'=') {
                Some(eq) => r.add(clean_dup(&f[..eq]), unescape_clean(&f[eq + 1..])),
                None => r.add(clean_dup(f), Vec::new()),
            }
        } else {
            r.add(num(field - 1), clean_dup(f));
        }
        field += 1;
        if i >= n {
            break;
        }
        start = i + 1;
        i += 1;
    }
    r
}

pub fn creply_parse(text: &[u8]) -> Creply {
    let mut out = Creply::default();
    let mut end = text.len();
    while end > 0 && (text[end - 1] == b'\n' || text[end - 1] == b'\r') {
        end -= 1;
    }
    let (mut first, mut rows, mut status) = (true, false, false);
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
        let line = &text[i..i + n];
        if first {
            first = false;
            if line.starts_with(b"ok|") || line.starts_with(b"err|") {
                out.res = parse_rec(line, true);
                out.ok = out.res.typ.first() == Some(&b'o');
                out.err = !out.ok;
                // the code is the first field after the type: it was parsed
                // as a key without '='
                if !out.res.k.is_empty() && out.res.v[0].is_empty() {
                    out.code = std::mem::take(&mut out.res.k[0]);
                }
                rows = out.code == b"network.tree";
                status = out.code == b"network.status";
                i = j + 1;
                continue;
            }
        }
        if status {
            // key=value lines become fields of the result record
            if let Some(eq) = line.iter().position(|&b| b == b'=') {
                out.res
                    .add(clean_dup(&line[..eq]), clean_dup(&line[eq + 1..]));
            }
            i = j + 1;
            continue;
        }
        out.r.push(parse_rec(line, !rows));
        i = j + 1;
    }
    out
}

// ===========================================================================
// Output lines and the line builder
// ===========================================================================
#[derive(Clone)]
pub struct Fline {
    pub text: Vec<u8>,
    pub role: u8,
}

pub type Flines = Vec<Fline>;

pub fn flines_add(o: &mut Flines, role: u8, text: &[u8]) {
    // trailing blanks never reach the screen
    let mut n = text.len();
    while n > 0 && text[n - 1] == b' ' {
        n -= 1;
    }
    o.push(Fline {
        text: text[..n].to_vec(),
        role,
    });
}

/// The line builder: bytes and the display cells they take (each chunk is
/// measured on its own, as C's sb_addn does).
#[derive(Default)]
struct Sb {
    p: Vec<u8>,
    w: i32,
    /// C's p: NULL until the first add.
    used: bool,
}

impl Sb {
    fn addn(&mut self, s: &[u8]) {
        self.used = true;
        self.p.extend_from_slice(s);
        self.w += width_n(s);
    }
    /// None adds nothing (a record that lacks the key a card line shows).
    fn add(&mut self, s: Option<&[u8]>) {
        if let Some(s) = s {
            self.addn(s);
        }
    }
    fn a(&mut self, s: &[u8]) {
        self.addn(s);
    }
    fn pad(&mut self, col: i32) {
        while self.w < col {
            self.addn(b" ");
        }
    }
    fn rep(&mut self, g: &[u8], n: i32) {
        for _ in 0..n.max(0) {
            self.addn(g);
        }
    }
    fn reset(&mut self) {
        self.p.clear();
        self.w = 0;
    }
    fn emit(&mut self, out: &mut Flines, role: u8) {
        flines_add(out, role, &self.p);
        self.reset();
    }
    /// C's `b.p` as a `%s` / value: None while nothing was ever added.
    fn opt(&self) -> Option<&[u8]> {
        self.used.then_some(self.p.as_slice())
    }
}

fn width_n(s: &[u8]) -> i32 {
    let mut w = 0;
    let mut i = 0;
    while i < s.len() {
        let (ul, _, cw) = next_char(&s[i..]);
        w += cw;
        i += ul;
    }
    w
}

// ===========================================================================
// Glyphs and value formats
// ===========================================================================
pub const G_RULE: usize = 0;
pub const G_ON: usize = 1;
pub const G_OFF: usize = 2;
pub const G_PEND: usize = 3;
pub const G_OK: usize = 4;
pub const G_ERR: usize = 5;
pub const G_WARN: usize = 6;
pub const G_BULLET: usize = 7;
pub const G_ELL: usize = 8;
pub const G_DOT: usize = 9;
pub const G_ARROW: usize = 10;
pub const G_TMID: usize = 11;
pub const G_TEND: usize = 12;
pub const G_TV: usize = 13;
pub const G_DASH: usize = 14;
pub const G_TIMES: usize = 15;
pub const G_FULL: usize = 16;
pub const G_EMPTY: usize = 17;
pub const G_OPEN: usize = 18;
pub const G_UNKNOWN: usize = 19;
const G_COUNT: usize = 20;

const GLYPH_U: [&str; G_COUNT] = [
    "─", "●", "○", "◐", "✓", "✗", "▲", "•", "…", "·", "→", "├", "└", "│", "—", "×", "█", "░", "▾",
    "?",
];
const GLYPH_A: [&str; G_COUNT] = [
    "-", "*", "o", "~", "+", "x", "!", "-", "~", "|", "->", "|", "`", "|", "-", "x", "#", ".", "v",
    "?",
];

/// What a renderer needs to know about the session.
pub struct Ctx<'a> {
    /// cells
    pub width: i32,
    pub ascii: bool,
    /// Unix seconds
    pub now: i64,
    pub admin: &'a [u8],
    pub ip: &'a [u8],
    pub hubname: &'a [u8],
    /// FMT_MODE_*: how a reply is to be shown
    pub mode: i32,
    /// log show: this session's log subscription
    pub session_log: &'a [u8],
}

pub fn glyph(ctx: &Ctx, g: usize) -> &'static [u8] {
    if g >= G_COUNT {
        return b"?";
    }
    if ctx.ascii {
        GLYPH_A[g].as_bytes()
    } else {
        GLYPH_U[g].as_bytes()
    }
}

/// The ASCII stand-in for the character at s (display ascii): a glyph of
/// GLYPH_U becomes its GLYPH_A ("←" "<-"); any other non-ASCII character
/// becomes one '?' per cell, a zero-width one nothing.  Returns (stand-in,
/// bytes of s it covers); None = s[0] is ASCII, keep it.
pub fn ascii_char(s: &[u8]) -> (Option<&'static [u8]>, usize) {
    const Q: [&str; 3] = ["", "?", "??"];
    let (len, _, w) = next_char(s);
    if s[0] < 0x80 {
        return (None, len);
    }
    for g in 0..G_COUNT {
        if GLYPH_U[g].len() == len && GLYPH_U[g].as_bytes() == &s[..len] {
            return (Some(GLYPH_A[g].as_bytes()), len);
        }
    }
    if len == 3 && &s[..3] == "←".as_bytes() {
        return (Some(b"<-"), len);
    }
    (Some(Q[w.clamp(0, 2) as usize].as_bytes()), len)
}

/// A whole line through ascii_char.
pub fn ascii(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let (r, l) = ascii_char(&s[i..]);
        match r {
            None => out.push(s[i]),
            Some(r) => out.extend_from_slice(r),
        }
        i += l.max(1);
    }
    out
}

/// Days since 1970-01-01 to a civil date (proleptic Gregorian).
fn civil(days: i64) -> (i32, i32, i32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let yy = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as i32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as i32;
    let y = (yy + i64::from(m <= 2)) as i32;
    (y, m, d)
}

fn floordiv(a: i64, b: i64) -> i64 {
    let q = a / b;
    if a % b != 0 && ((a < 0) != (b < 0)) {
        q - 1
    } else {
        q
    }
}

const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// 14:02:11Z today, Oct 02 14:02Z this year, 2025-12-30 before; never for 0.
pub fn when(ts: i64, now: i64) -> Vec<u8> {
    if ts <= 0 {
        return b"never".to_vec();
    }
    let day = floordiv(ts, 86400);
    let sec = ts - day * 86400;
    let nday = floordiv(now, 86400);
    let (y, m, d) = civil(day);
    let (ny, _, _) = civil(nday);
    let (hh, mm, ss) = (sec / 3600, sec / 60 % 60, sec % 60);
    if day == nday {
        format!("{hh:02}:{mm:02}:{ss:02}Z").into_bytes()
    } else if y == ny {
        format!("{} {d:02} {hh:02}:{mm:02}Z", MONTH[(m - 1) as usize]).into_bytes()
    } else {
        format!("{y:04}-{m:02}-{d:02}").into_bytes()
    }
}

/// 42s, 7m, 3h 12m, 5d 03h
pub fn span(s: i64) -> Vec<u8> {
    let s = s.max(0);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86400 {
        format!("{}h {:02}m", s / 3600, s / 60 % 60)
    } else {
        format!("{}d {:02}h", s / 86400, s / 3600 % 24)
    }
    .into_bytes()
}

/// 3d 04h 12m — an uptime with one more unit
fn dur3(s: i64) -> Vec<u8> {
    let s = s.max(0);
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{}h {:02}m", s / 3600, s / 60 % 60)
    } else {
        format!("{}d {:02}h {:02}m", s / 86400, s / 3600 % 24, s / 60 % 60)
    }
    .into_bytes()
}

/// 512 B, 86.2 KiB, 12.0 MiB, 1.31 GiB
pub fn bytes(n: u64) -> Vec<u8> {
    const U: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B").into_bytes();
    }
    let mut u = 0;
    let mut d: u64 = 1024;
    while u < 3 && n >= d * 1024 {
        d *= 1024;
        u += 1;
    }
    if u >= 2 {
        let v = n / d * 100 + ((n % d) * 100 + d / 2) / d;
        format!("{}.{:02} {}", v / 100, v % 100, U[u]).into_bytes()
    } else {
        let v = n / d * 10 + ((n % d) * 10 + d / 2) / d;
        format!("{}.{} {}", v / 10, v % 10, U[u]).into_bytes()
    }
}

/// 1,402,881
pub fn count(n: u64) -> Vec<u8> {
    let d = n.to_string().into_bytes();
    let l = d.len();
    let mut out = Vec::with_capacity(l + l / 3);
    for (i, &c) in d.iter().enumerate() {
        if out.len() + 2 >= 32 {
            break;
        }
        if i > 0 && (l - i).is_multiple_of(3) {
            out.push(b',');
        }
        out.push(c);
    }
    out
}

const LEVEL_NAME: [&str; 5] = ["none", "error", "warning", "info", "debug"];
fn level_name(l: i64) -> &'static [u8] {
    if (0..=4).contains(&l) {
        LEVEL_NAME[l as usize].as_bytes()
    } else {
        b"?"
    }
}

fn pl(n: i64) -> &'static [u8] {
    if n == 1 { b"" } else { b"s" }
}

/// "1 peer hub" / "3 peer hubs"
fn plural(n: i64, one: &str, many: &str) -> Vec<u8> {
    cat(&[&num(n), b" ", s(if n == 1 { one } else { many })])
}

/// Case-insensitive ASCII order, then bytes (C: until the first NUL).
fn ci_cmp(a: &[u8], b: &[u8]) -> i32 {
    let mut i = 0;
    loop {
        let ca = i32::from(a.get(i).copied().unwrap_or(0).to_ascii_lowercase());
        let cb = i32::from(b.get(i).copied().unwrap_or(0).to_ascii_lowercase());
        if ca != cb || ca == 0 {
            return ca - cb;
        }
        i += 1;
    }
}

/// C strcmp sign.
fn cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.cmp(b)
}

// ===========================================================================
// Blocks: title rule, result, note, card line (§3.5 building blocks)
// ===========================================================================
pub fn title(ctx: &Ctx, out: &mut Flines, title: &[u8], right: Option<&[u8]>) {
    let mut b = Sb::default();
    let w = ctx.width;
    let tw = str_width(title);
    let right = right.filter(|r| !r.is_empty());
    let rw = right.map_or(0, str_width);
    b.a(b" ");
    b.a(title);
    b.a(b" ");
    let fill = w - (tw + 2) - if rw != 0 { rw + 1 } else { 0 };
    if fill >= 3 {
        b.rep(glyph(ctx, G_RULE), fill);
        if rw != 0 {
            b.a(b" ");
            b.add(right);
        }
        b.emit(out, RL_TITLE);
    } else {
        let n = if w - (tw + 2) >= 3 { w - (tw + 2) } else { 3 };
        b.rep(glyph(ctx, G_RULE), n);
        b.emit(out, RL_TITLE);
        if rw != 0 {
            b.a(b"  ");
            b.add(right);
            b.emit(out, RL_DIM);
        }
    }
}

fn rule_line(ctx: &Ctx, out: &mut Flines) {
    let mut b = Sb::default();
    b.a(b" ");
    b.rep(
        glyph(ctx, G_RULE),
        if ctx.width - 1 > 3 { ctx.width - 1 } else { 3 },
    );
    b.emit(out, RL_RULE);
}

fn line(out: &mut Flines, role: u8, parts: &[&[u8]]) {
    flines_add(out, role, &cat(parts));
}

/// " ✓ What   subject"
pub fn ok(ctx: &Ctx, what: &[u8], subject: Option<&[u8]>, out: &mut Flines) {
    match subject.filter(|x| !x.is_empty()) {
        Some(sub) => line(
            out,
            RL_OK,
            &[b" ", glyph(ctx, G_OK), b" ", what, b"   ", sub],
        ),
        None => line(out, RL_OK, &[b" ", glyph(ctx, G_OK), b" ", what]),
    }
}

/// A console-side refusal or note in the same shape as a hub's.
pub fn error(ctx: &Ctx, msg: Option<&[u8]>, hint_text: Option<&[u8]>, out: &mut Flines) {
    let m = msg.filter(|m| !m.is_empty()).unwrap_or(b"failed");
    line(out, RL_ERR, &[b" ", glyph(ctx, G_ERR), b" ", m]);
    if let Some(h) = hint_text.filter(|h| !h.is_empty()) {
        line(out, RL_DIM, &[b"   hint  ", h]);
    }
}

fn effect(ctx: &Ctx, out: &mut Flines, text: &[u8]) {
    line(out, RL_NORMAL, &[b"   ", glyph(ctx, G_BULLET), b" ", text]);
}

fn warn(ctx: &Ctx, out: &mut Flines, text: &[u8]) {
    line(out, RL_WARN, &[b"   ", glyph(ctx, G_WARN), b" ", text]);
}

fn hint(out: &mut Flines, text: &[u8]) {
    line(out, RL_DIM, &[b"   hint  ", text]);
}

/// "  label   value", labels padded to label_w
pub fn card_line(out: &mut Flines, label_w: i32, label: &[u8], value: Option<&[u8]>, role: u8) {
    let mut b = Sb::default();
    b.a(b"  ");
    b.a(label);
    b.pad(2 + label_w + 2);
    b.add(value);
    b.emit(out, role);
}

fn card(out: &mut Flines, label_w: i32, label: &str, value: &[u8], role: u8) {
    card_line(out, label_w, label.as_bytes(), Some(value), role);
}

/// A result's own card lines: "   key         value"
fn res_kv(out: &mut Flines, label: &str, value: &[u8]) {
    let mut b = Sb::default();
    b.a(b"   ");
    b.a(label.as_bytes());
    b.pad(15);
    b.a(value);
    b.emit(out, RL_NORMAL);
}

fn empty_note(out: &mut Flines, text: &str, hint_text: Option<&str>) {
    line(out, RL_DIM, &[b"  (", s(text), b")"]);
    if let Some(h) = hint_text {
        hint(out, s(h));
    }
}

/// Keys a renderer already showed; any other key of the record is shown
/// after them as "key  value" (rule 11: a newer hub never hides data).
fn unknown_keys(ctx: &Ctx, out: &mut Flines, r: &Crec, known: &[&str], label_w: i32) {
    for i in 0..r.k.len() {
        let k = r.k[i].is_empty() || known.iter().any(|x| x.as_bytes() == r.k[i].as_slice());
        if !k {
            let v: &[u8] = if r.v[i].is_empty() {
                glyph(ctx, G_DASH)
            } else {
                &r.v[i]
            };
            card_line(out, label_w, &r.k[i], Some(v), RL_NORMAL);
        }
    }
}

// ===========================================================================
// Tables: wide → stacked → cards (§1.4; every layout has every field)
// ===========================================================================
const TBL_MAX_COLS: usize = 16;

#[derive(Clone, Copy)]
struct Col {
    head: &'static str,
    /// b'L' or b'R'
    align: u8,
    /// 1 or 2: where it goes when the table is stacked
    line: i32,
}

const fn col(head: &'static str, align: u8, line: i32) -> Col {
    Col { head, align, line }
}

struct Tbl {
    cols: Vec<Col>,
    cells: Vec<Vec<Vec<u8>>>,
    roles: Vec<u8>,
    /// cards: the text on a row's title rule
    right: Vec<Option<Vec<u8>>>,
    indent: i32,
    /// column holding a status glyph, -1 = none
    badge: i32,
    /// column that names the object (cards)
    title: i32,
    /// stacked: line 2 starts under this column
    l2_at: i32,
}

#[allow(clippy::needless_range_loop)] // index-parallel arrays, as in C
impl Tbl {
    fn new(cols: &[Col], badge: i32, title: i32, l2_at: i32) -> Tbl {
        Tbl {
            cols: cols.to_vec(),
            cells: Vec::new(),
            roles: Vec::new(),
            right: Vec::new(),
            indent: 2,
            badge,
            title,
            l2_at,
        }
    }

    fn nc(&self) -> usize {
        self.cols.len()
    }

    fn nr(&self) -> usize {
        self.cells.len()
    }

    /// Append a row; None or "" become the dash.
    fn row(&mut self, ctx: &Ctx, role: u8, right: Option<&[u8]>, cells: &[Option<&[u8]>]) {
        let row: Vec<Vec<u8>> = (0..self.nc())
            .map(|c| match cells[c] {
                Some(x) if !x.is_empty() => x.to_vec(),
                _ => glyph(ctx, G_DASH).to_vec(),
            })
            .collect();
        self.cells.push(row);
        self.roles.push(role);
        self.right.push(right.map(<[u8]>::to_vec));
    }

    fn gap(&self, prev: usize) -> i32 {
        if prev as i32 == self.badge { 1 } else { 2 }
    }

    /// One line of the given columns (which: line 1 or 2, 0 = all).
    fn line_width(&self, w: &[i32], which: i32, x0: i32) -> i32 {
        let mut x = x0;
        let mut prev: Option<usize> = None;
        for c in 0..self.nc() {
            if which != 0 && self.cols[c].line != which {
                continue;
            }
            if let Some(p) = prev {
                x += self.gap(p);
            }
            x += w[c];
            prev = Some(c);
        }
        x
    }

    fn put(&self, b: &mut Sb, w: &[i32], which: i32, x0: i32, cells: &[&[u8]]) {
        let mut prev: Option<usize> = None;
        b.pad(x0);
        for c in 0..self.nc() {
            if which != 0 && self.cols[c].line != which {
                continue;
            }
            if let Some(p) = prev {
                b.rep(b" ", self.gap(p));
            }
            let start = b.w;
            let cs = cells[c];
            if self.cols[c].align == b'R' {
                b.pad(start + w[c] - str_width(cs));
                b.a(cs);
            } else {
                b.a(cs);
                b.pad(start + w[c]);
            }
            prev = Some(c);
        }
    }

    /// x of column `col` in a line-1 layout
    fn x_of(&self, w: &[i32], col: i32) -> i32 {
        let mut x = self.indent;
        let mut prev: Option<usize> = None;
        for c in 0..self.nc() {
            if self.cols[c].line != 1 {
                continue;
            }
            if let Some(p) = prev {
                x += self.gap(p);
            }
            if c as i32 == col {
                return x;
            }
            x += w[c];
            prev = Some(c);
        }
        self.indent
    }

    fn render(&self, ctx: &Ctx, out: &mut Flines) {
        let ww = ctx.width;
        let heads: Vec<&[u8]> = self.cols.iter().map(|c| c.head.as_bytes()).collect();
        let mut w: Vec<i32> = vec![0; self.nc()];
        for c in 0..self.nc() {
            w[c] = str_width(heads[c]);
            for r in &self.cells {
                w[c] = w[c].max(str_width(&r[c]));
            }
        }
        let mut b = Sb::default();
        let wide = self.line_width(&w, 0, self.indent);
        let l2x = self.x_of(&w, self.l2_at);
        let st1 = self.line_width(&w, 1, self.indent);
        let st2 = self.line_width(&w, 2, l2x);
        let has2 = self.cols.iter().any(|c| c.line == 2);
        let row_cells =
            |r: usize| -> Vec<&[u8]> { self.cells[r].iter().map(|x| x.as_slice()).collect() };
        if wide <= ww || (!has2 && ww >= CONSOLE_WIDTH_MIN) {
            self.put(&mut b, &w, 0, self.indent, &heads);
            b.emit(out, RL_HEAD);
            for r in 0..self.nr() {
                self.put(&mut b, &w, 0, self.indent, &row_cells(r));
                b.emit(out, self.roles[r]);
            }
        } else if ww >= CONSOLE_WIDTH_MIN && st1 <= ww && st2 <= ww {
            self.put(&mut b, &w, 1, self.indent, &heads);
            b.emit(out, RL_HEAD);
            self.put(&mut b, &w, 2, l2x, &heads);
            b.emit(out, RL_HEAD);
            for r in 0..self.nr() {
                self.put(&mut b, &w, 1, self.indent, &row_cells(r));
                b.emit(out, self.roles[r]);
                self.put(&mut b, &w, 2, l2x, &row_cells(r));
                b.emit(out, self.roles[r]);
            }
        } else {
            // cards: one block per row, every column a "label value" line
            let mut lw = 0;
            let mut low: Vec<Vec<u8>> = Vec::new();
            for c in 0..self.nc().min(TBL_MAX_COLS) {
                let h = self.cols[c].head.as_bytes();
                let l: Vec<u8> = h[..h.len().min(39)].to_ascii_lowercase();
                if c as i32 != self.badge && c as i32 != self.title && str_width(&l) > lw {
                    lw = str_width(&l);
                }
                low.push(l);
            }
            for r in 0..self.nr() {
                let cells = &self.cells[r];
                b.reset();
                if self.badge >= 0 {
                    b.a(&cells[self.badge as usize]);
                    b.a(b" ");
                }
                b.a(&cells[self.title as usize]);
                let t = b.p.clone();
                title(ctx, out, &t, self.right[r].as_deref());
                b.reset();
                for c in 0..self.nc() {
                    if c as i32 == self.badge || c as i32 == self.title {
                        continue;
                    }
                    let role = if self.roles[r] == RL_DIM {
                        RL_DIM
                    } else {
                        RL_NORMAL
                    };
                    card_line(out, lw, &low[c], Some(&cells[c]), role);
                }
            }
        }
    }
}

// ===========================================================================
// Shared value phrases
// ===========================================================================
fn peers_phrase(peers: i64) -> Vec<u8> {
    if peers <= 0 {
        b"no peer hub is linked now; peers catch up on their next sync".to_vec()
    } else {
        cat(&[b"synced to ", &num(peers), b" peer hub", pl(peers)])
    }
}

fn sync_push_phrase(cap: usize, peers: i64, bots: i64) -> Vec<u8> {
    let p = if peers <= 0 {
        b"no peer hub linked".to_vec()
    } else {
        cat(&[b"synced to ", &num(peers), b" peer hub", pl(peers)])
    };
    snp(
        cap,
        cat(&[&p, b"; pushed to ", &num(bots), b" bot", pl(bots)]),
    )
}

/// "Oct 03 22:10Z · 15h"
fn when_ago(ctx: &Ctx, ts: i64, cap: usize) -> Vec<u8> {
    if ts <= 0 {
        return b"never".to_vec();
    }
    let w = when(ts, ctx.now);
    let sp = span(ctx.now.wrapping_sub(ts));
    snp(cap, cat(&[&w, b" ", glyph(ctx, G_DOT), b" ", &sp]))
}

fn span_since(ctx: &Ctx, ts: i64) -> Vec<u8> {
    if ts <= 0 {
        glyph(ctx, G_DASH).to_vec()
    } else {
        span(ctx.now.wrapping_sub(ts))
    }
}

fn flags_phrase(f: Option<&[u8]>, cap: usize) -> Vec<u8> {
    snp(cap, f.filter(|f| !f.is_empty()).unwrap_or(b"none").to_vec())
}

// ===========================================================================
// Bots
// ===========================================================================
struct SortRow<'a> {
    r: &'a Crec,
    on: bool,
    name: &'a [u8],
    uuid: &'a [u8],
    idx: usize,
}

/// online first, then name (any case), then uuid, then arrival
fn row_before(a: &SortRow, b: &SortRow) -> bool {
    if a.on != b.on {
        return a.on && !b.on;
    }
    let c = ci_cmp(a.name, b.name);
    if c != 0 {
        return c < 0;
    }
    match cmp(a.name, b.name) {
        std::cmp::Ordering::Equal => {}
        o => return o.is_lt(),
    }
    match cmp(a.uuid, b.uuid) {
        std::cmp::Ordering::Equal => {}
        o => return o.is_lt(),
    }
    a.idx < b.idx
}

/// Records of one type, sorted.
fn collect<'a>(
    rep: &'a Creply,
    typ: &str,
    name_key: &str,
    on_key: Option<&str>,
) -> Vec<SortRow<'a>> {
    let mut v: Vec<SortRow> = Vec::new();
    for (i, r) in rep.r.iter().enumerate() {
        if !r.is(typ) {
            continue;
        }
        v.push(SortRow {
            r,
            on: on_key.is_some_and(|k| r.rvb(k)),
            name: r.rv(name_key).unwrap_or(b""),
            uuid: r.rv("uuid").unwrap_or(b""),
            idx: i,
        });
    }
    // insertion sort, as C
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && row_before(&v[j], &v[j - 1]) {
            v.swap(j, j - 1);
            j -= 1;
        }
    }
    v
}

fn bot_last_seen(ctx: &Ctx, r: &Crec, cap: usize) -> Vec<u8> {
    if r.rvb("online") {
        b"now".to_vec()
    } else {
        when_ago(ctx, r.rvi("seen", 0), cap)
    }
}

fn render_bot_list(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let total = rep.res.rvi("total", 0);
    let online = rep.res.rvi("online", 0);
    let dot = glyph(ctx, G_DOT);
    let right = snp(
        96,
        cat(&[
            &num(total),
            b" registered ",
            dot,
            b" ",
            &num(online),
            b" online ",
            dot,
            b" ",
            &num(total.wrapping_sub(online)),
            b" offline",
        ]),
    );
    title(ctx, out, b"Bots", Some(&right));
    let v = collect(rep, "bot", "nick", Some("online"));
    if v.is_empty() {
        empty_note(
            out,
            "no bots registered",
            Some("bot add <nick> <uuid> <key>, or approve one from bot pending"),
        );
        return;
    }
    const COLS: [Col; 13] = [
        col("", b'L', 1),
        col("NICK", b'L', 1),
        col("UUID", b'L', 1),
        col("VERSION", b'L', 1),
        col("CODE", b'L', 1),
        col("UPTIME", b'L', 1),
        col("SERVER", b'L', 2),
        col("HUB", b'L', 2),
        col("ADDRESS", b'L', 2),
        col("SINCE", b'L', 2),
        col("KEY", b'L', 2),
        col("AUTH", b'L', 2),
        col("LAST SEEN", b'L', 1),
    ];
    let mut t = Tbl::new(&COLS, 0, 1, 1);
    let (mut here, mut via) = (0, 0);
    // version and code-base breakdowns, in first-seen order then sorted
    let mut vers: Vec<Vec<u8>> = Vec::new();
    let mut vcnt: Vec<i32> = Vec::new();
    let (mut cc, mut crs) = (0, 0);
    for sr in &v {
        let r = sr.r;
        let on = r.rvb("online");
        let up = span_since(ctx, if on { r.rvi("started", 0) } else { 0 });
        let since = span_since(ctx, if on { r.rvi("since", 0) } else { 0 });
        let seen = bot_last_seen(ctx, r, 64);
        let fp: &[u8] = if r.rvs("fp").is_some() {
            r.rv("fp").unwrap_or(b"")
        } else {
            b"(no key)"
        };
        let cells: [Option<&[u8]>; 13] = [
            Some(glyph(ctx, if on { G_ON } else { G_OFF })),
            r.rv("nick"),
            r.rv("uuid"),
            r.rv("ver"),
            r.rv("base"),
            Some(&up),
            r.rv("server"),
            r.rv("hub_name"),
            r.rv("ip"),
            Some(&since),
            Some(fp),
            Some(if r.rvb("auth") { b"yes" } else { b"no" }),
            Some(&seen),
        ];
        let right: &[u8] = if on { b"online" } else { b"offline" };
        t.row(
            ctx,
            if on { RL_NORMAL } else { RL_DIM },
            Some(right),
            &cells,
        );
        if on {
            if r.rv("hub") == Some(b"local") {
                here += 1;
            } else {
                via += 1;
            }
            if let Some(ver) = r.rvs("ver") {
                let mut k = 0;
                while k < vers.len() && vers[k].as_slice() != ver {
                    k += 1;
                }
                if k == vers.len() && vers.len() < 64 {
                    vers.push(ver[..uprec(ver, 23)].to_vec());
                    vcnt.push(0);
                }
                if k < vers.len() {
                    vcnt[k] += 1;
                }
            }
            match r.rvs("base") {
                Some(b"c") => cc += 1,
                Some(b"rs") => crs += 1,
                _ => {}
            }
        }
    }
    t.render(ctx, out);
    rule_line(ctx, out);
    // most common version first, then the higher string
    for i in 1..vers.len() {
        let mut j = i;
        while j > 0
            && (vcnt[j] > vcnt[j - 1]
                || (vcnt[j] == vcnt[j - 1] && cmp(&vers[j], &vers[j - 1]).is_gt()))
        {
            vers.swap(j, j - 1);
            vcnt.swap(j, j - 1);
            j -= 1;
        }
    }
    let mut b = Sb::default();
    b.a(&cat(&[
        b"  online ",
        &num(online),
        b" ",
        dot,
        b" offline ",
        &num(total.wrapping_sub(online)),
        b" ",
        dot,
        b" on this hub ",
        &num(here),
        b" ",
        dot,
        b" via peers ",
        &num(via),
    ]));
    for i in 0..vers.len() {
        b.a(&cat(&[
            b" ",
            dot,
            b" ",
            &vers[i],
            b" ",
            glyph(ctx, G_TIMES),
            &num(vcnt[i]),
        ]));
    }
    if cc != 0 {
        b.a(&cat(&[b" ", dot, b" c ", &num(cc)]));
    }
    if crs != 0 {
        b.a(&cat(&[b" ", dot, b" rs ", &num(crs)]));
    }
    b.emit(out, RL_DIM);
    hint(out, b"bot show <uuid|nick> for one bot in detail");
}

fn render_bot_show(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = rep.r.iter().find(|x| x.is("bot"));
    let u = rep.r.iter().find(|x| x.is("upg"));
    let Some(r) = r else { return };
    let on = r.rvb("online");
    let dot = glyph(ctx, G_DOT);
    let name = if r.rvs("nick").is_some() {
        r.rv("nick")
    } else {
        r.rv("uuid")
    };
    let t = snp(128, cat(&[b"Bot ", nul(name)]));
    let right = snp(
        48,
        cat(&[
            glyph(ctx, if on { G_ON } else { G_OFF }),
            b" ",
            if on { b"online" } else { b"offline" },
        ]),
    );
    title(ctx, out, &t, Some(&right));
    const L: i32 = 12;
    card_line(out, L, b"uuid", r.rv("uuid"), RL_NORMAL);
    if on {
        let mut sb = Sb::default();
        sb.a(r.rvs("ver").unwrap_or(b"unknown version"));
        if let Some(base) = r.rvs("base") {
            sb.a(&cat(&[b" ", dot, b" code ", base]));
        }
        let st = r.rvi("started", 0);
        if st > 0 {
            let a = dur3(ctx.now.wrapping_sub(st));
            let b = when(st, ctx.now);
            sb.a(&cat(&[b" ", dot, b" up ", &a, b" (started ", &b, b")"]));
        }
        card(out, L, "version", &sb.p, RL_NORMAL);
        card(
            out,
            L,
            "irc server",
            r.rvs("server").unwrap_or(glyph(ctx, G_DASH)),
            RL_NORMAL,
        );
        sb.reset();
        let local = r.rv("hub") == Some(b"local");
        sb.a(&cat(&[
            r.rvs("hub_name").unwrap_or(glyph(ctx, G_DASH)),
            if local { b" (this hub)" } else { b"" },
        ]));
        let since = r.rvi("since", 0);
        if since > 0 {
            let a = when(since, ctx.now);
            let b = span(ctx.now.wrapping_sub(since));
            sb.a(&cat(&[b" ", dot, b" connected ", &a, b" ", dot, b" ", &b]));
        }
        if let Some(ip) = r.rvs("ip") {
            sb.a(&cat(&[b" ", dot, b" from ", ip]));
        }
        card(out, L, "hub", &sb.p, RL_NORMAL);
    } else {
        card(out, L, "hub", b"not connected to any hub", RL_DIM);
    }
    card(out, L, "key", r.rvs("fp").unwrap_or(b"(no key)"), RL_NORMAL);
    let v = bot_last_seen(ctx, r, 512);
    card(out, L, "last seen", &v, RL_NORMAL);
    let v: Vec<u8> = if r.rvb("auth") && r.rvi("auth_ts", 0) > 0 {
        let a = when(r.rvi("auth_ts", 0), ctx.now);
        snp(512, cat(&[b"yes ", dot, b" ", &a]))
    } else if r.rvb("auth") {
        b"yes".to_vec()
    } else {
        b"no".to_vec()
    };
    card(out, L, "authorized", &v, RL_NORMAL);
    if let Some(u) = u {
        let a = snp(64, when(u.rvi("started", 0), ctx.now));
        let v = snp(
            512,
            cat(&[
                b"run ",
                u.rv("id").unwrap_or(b"?"),
                b": ",
                u.rv("state").unwrap_or(b"?"),
                b" ",
                u.rvs("from").unwrap_or(b"?"),
                b" ",
                glyph(ctx, G_ARROW),
                b" ",
                u.rvs("to").unwrap_or(b"?"),
                b" (started ",
                &a,
                b")",
            ]),
        );
        card(out, L, "upgrade", &v, RL_NORMAL);
    }
    const KNOWN: &[&str] = &[
        "uuid", "nick", "online", "ver", "base", "started", "server", "hub", "hub_uuid",
        "hub_name", "ip", "since", "fp", "seen", "auth", "auth_ts",
    ];
    unknown_keys(ctx, out, r, KNOWN, L);
    if let Some(hu) = r.rvs("hub_uuid") {
        card(out, L, "hub uuid", hu, RL_DIM);
    }
}

fn render_bot_summary(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let right = snp(48, cat(&[&num(rep.res.rvi("total", 0)), b" registered"]));
    title(ctx, out, b"Bots", Some(&right));
    let v = collect(rep, "bot", "nick", None);
    if v.is_empty() {
        empty_note(
            out,
            "no bots registered",
            Some("bot add <nick> <uuid> <key>"),
        );
        return;
    }
    let dash = glyph(ctx, G_DASH);
    let nm = |x: &SortRow| -> Vec<u8> {
        if x.name.is_empty() {
            dash.to_vec()
        } else {
            x.name.to_vec()
        }
    };
    let mut nw = 4;
    for x in &v {
        nw = nw.max(str_width(&nm(x)));
    }
    let n = v.len() as i32;
    let entry = 2 + nw + 2 + 36;
    let per = if ctx.width >= 2 * entry + 3 { 2 } else { 1 };
    let rows = (n + per - 1) / per;
    let mut b = Sb::default();
    for row in 0..rows {
        for c in 0..per {
            let i = c * rows + row;
            if i >= n {
                break;
            }
            let x = &v[i as usize];
            b.pad(c * (entry + 3));
            b.a(b"  ");
            let x0 = b.w;
            b.a(&nm(x));
            b.pad(x0 + nw + 2);
            b.a(x.uuid);
        }
        b.emit(out, RL_NORMAL);
    }
}

fn render_bot_pending(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let right = snp(48, cat(&[&num(rep.res.rvi("count", 0)), b" waiting"]));
    title(ctx, out, b"Pending bots", Some(&right));
    const COLS: [Col; 5] = [
        col("#", b'R', 1),
        col("UUID", b'L', 1),
        col("FROM", b'L', 1),
        col("TRIES", b'R', 1),
        col("LAST TRY", b'L', 1),
    ];
    let mut t = Tbl::new(&COLS, -1, 1, 1);
    for r in rep.r.iter().filter(|r| r.is("pending")) {
        let nn = snp(16, num(r.rvi("n", 0)));
        let tries = snp(16, num(r.rvi("tries", 0)));
        let ts = r.rvi("last", 0);
        let last = if ts > 0 {
            cat(&[&span(ctx.now.wrapping_sub(ts)), b" ago"])
        } else {
            glyph(ctx, G_DASH).to_vec()
        };
        let cells = [
            Some(nn.as_slice()),
            r.rv("uuid"),
            r.rv("ip"),
            Some(&tries),
            Some(&last),
        ];
        t.row(ctx, RL_NORMAL, None, &cells);
    }
    if t.nr() == 0 {
        empty_note(out, "no bots waiting for approval", None);
        return;
    }
    t.render(ctx, out);
    rule_line(ctx, out);
    line(
        out,
        RL_DIM,
        &[
            b"  approve one: bot approve <#|uuid>   (the # changes as bots come and go ",
            glyph(ctx, G_DASH),
            b" the uuid does not)",
        ],
    );
}

// ===========================================================================
// Peers and the mesh
// ===========================================================================
fn addr_of(r: &Crec, cap: usize) -> Vec<u8> {
    snp(
        cap,
        cat(&[r.rv("ip").unwrap_or(b"?"), b":", &num(r.rvi("port", 0))]),
    )
}

fn peer_name(r: &Crec) -> &[u8] {
    r.rvs("name")
        .or_else(|| r.rvs("ip"))
        .or_else(|| r.rvs("uuid"))
        .unwrap_or(b"?")
}

fn peer_link(ctx: &Ctx, r: &Crec) -> Vec<u8> {
    let since = r.rvi("since", 0);
    let v = if r.rvb("up") {
        let sp = snp(32, span_since(ctx, since));
        cat(&[glyph(ctx, G_ON), b" up ", &sp])
    } else if since > 0 {
        let w = when(since, ctx.now);
        let sp = span(ctx.now.wrapping_sub(since));
        cat(&[
            glyph(ctx, G_ERR),
            b" down since ",
            &w,
            b" ",
            glyph(ctx, G_DOT),
            b" ",
            &sp,
        ])
    } else {
        cat(&[glyph(ctx, G_ERR), b" down"])
    };
    snp(96, v)
}

/// A hub's short name for a matrix column: the first 5 characters.
fn short5(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut i, mut chars) = (0usize, 0);
    while i < name.len() && chars < 5 && out.len() + 4 < 32 {
        let (l, _, _) = next_char(&name[i..]);
        out.extend_from_slice(&name[i..i + l]);
        i += l;
        chars += 1;
    }
    out
}

struct MNode<'a> {
    uuid: &'a [u8],
    name: &'a [u8],
    shrt: Vec<u8>,
}

fn mesh_find(nodes: &[MNode], uuid: Option<&[u8]>) -> i32 {
    match uuid {
        Some(u) => nodes
            .iter()
            .position(|n| n.uuid == u)
            .map_or(-1, |p| p as i32),
        None => -1,
    }
}

#[allow(clippy::needless_range_loop)] // the matrix is indexed both ways
fn render_mesh(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let mut nodes: Vec<MNode> = Vec::new();
    for r in &rep.r {
        if nodes.len() >= 64 {
            break;
        }
        if !r.is("self") && !r.is("peer") && !r.is("hub") {
            continue;
        }
        let Some(u) = r.rvs("uuid") else { continue };
        if mesh_find(&nodes, Some(u)) >= 0 {
            continue;
        }
        nodes.push(MNode {
            uuid: u,
            name: peer_name(r),
            shrt: Vec::new(),
        });
    }
    // hubs only a link names
    for r in &rep.r {
        if nodes.len() >= 64 {
            break;
        }
        if !r.is("link") {
            continue;
        }
        let Some(b) = r.rvs("b") else { continue };
        if mesh_find(&nodes, Some(b)) >= 0 {
            continue;
        }
        nodes.push(MNode {
            uuid: b,
            name: r.rvs("b_name").unwrap_or(b),
            shrt: Vec::new(),
        });
    }
    let nn = nodes.len();
    if nn < 2 {
        return;
    }
    for i in 0..nn {
        // a leading "hub-" says nothing in a column head
        let mut nm = nodes[i].name;
        if nm.len() > 4 && nm[..4].eq_ignore_ascii_case(b"hub-") {
            nm = &nm[4..];
        }
        let mut sh = short5(nm);
        let dup = (0..i).filter(|&k| nodes[k].shrt == sh).count();
        if dup > 0 {
            let l = sh.len();
            if l > 0 && l + 2 < 32 {
                sh.truncate(l - usize::from(l >= 5));
                let l2 = sh.len();
                sh.extend_from_slice(&snp(32 - l2, num(dup + 1)));
            }
        }
        nodes[i].shrt = sh;
    }
    // cell[a][b]: 0 unknown, 1 up, 2 down
    let mut cell = vec![vec![0u8; nn]; nn];
    for r in rep.r.iter().filter(|r| r.is("link")) {
        let a = mesh_find(&nodes, r.rv("a"));
        let b = mesh_find(&nodes, r.rv("b"));
        if a < 0 || b < 0 {
            continue;
        }
        cell[a as usize][b as usize] = if r.rv("state") == Some(b"up") { 1 } else { 2 };
    }
    title(ctx, out, b"Mesh links", Some(b"as gossiped"));
    let nw = nodes
        .iter()
        .map(|n| str_width(n.name))
        .max()
        .unwrap_or(0)
        .max(0);
    let cw = 6;
    let mut b = Sb::default();
    if 3 + nw + 2 + cw * nn as i32 <= ctx.width {
        b.pad(3 + nw + 2);
        for n in &nodes {
            let x = b.w;
            b.a(&n.shrt);
            b.pad(x + cw);
        }
        b.emit(out, RL_HEAD);
        for a in 0..nn {
            b.a(b"   ");
            b.a(nodes[a].name);
            b.pad(3 + nw + 2);
            for c in 0..nn {
                let x = b.w;
                b.pad(x + 2);
                let g = if a == c {
                    G_DOT
                } else if cell[a][c] == 1 {
                    G_ON
                } else if cell[a][c] == 2 {
                    G_ERR
                } else {
                    G_UNKNOWN
                };
                b.a(glyph(ctx, g));
                b.pad(x + cw);
            }
            b.emit(out, RL_NORMAL);
        }
        line(
            out,
            RL_DIM,
            &[
                b"  ",
                glyph(ctx, G_ON),
                b" link up   ",
                glyph(ctx, G_ERR),
                b" link down   ",
                glyph(ctx, G_UNKNOWN),
                b" not reported   ",
                glyph(ctx, G_DOT),
                b" self",
            ],
        );
    } else {
        for a in 0..nn {
            b.a(b"   ");
            b.a(nodes[a].name);
            b.pad(3 + nw + 2);
            let mut any = false;
            for pass in 1..=2u8 {
                let mut first = true;
                for c in 0..nn {
                    if c == a || cell[a][c] != pass {
                        continue;
                    }
                    let pre: &[u8] = if first {
                        if pass == 1 {
                            b"up: "
                        } else if any {
                            b"  down: "
                        } else {
                            b"down: "
                        }
                    } else {
                        b" "
                    };
                    b.a(&cat(&[pre, &nodes[c].shrt]));
                    first = false;
                    any = true;
                }
            }
            if !any {
                b.a(b"(not reported)");
            }
            b.emit(out, RL_NORMAL);
        }
    }
}

fn render_peer_list(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let conf = rep.res.rvi("configured", 0);
    let up = rep.res.rvi("up", 0);
    let dot = glyph(ctx, G_DOT);
    let right = snp(
        96,
        cat(&[
            &num(conf),
            b" configured ",
            dot,
            b" ",
            &num(up),
            b" up ",
            dot,
            b" ",
            &num(conf.wrapping_sub(up)),
            b" down",
        ]),
    );
    title(ctx, out, b"Peer hubs", Some(&right));
    const COLS: [Col; 11] = [
        col("#", b'R', 1),
        col("NAME", b'L', 1),
        col("ADDRESS", b'L', 1),
        col("UUID", b'L', 2),
        col("CODE", b'L', 2),
        col("VERSION", b'L', 2),
        col("UPTIME", b'L', 2),
        col("BOTS", b'R', 1),
        col("LINK", b'L', 1),
        col("KEY", b'L', 1),
        col("FROM", b'L', 2),
    ];
    let mut t = Tbl::new(&COLS, -1, 1, 1);
    let mut selfr: Option<&Crec> = None;
    for r in &rep.r {
        if r.is("self") {
            selfr = Some(r);
        }
        if !r.is("peer") {
            continue;
        }
        let nn = snp(16, num(r.rvi("n", 0)));
        let addr = addr_of(r, 96);
        let bots = if r.rv("bots").is_some() {
            snp(16, num(r.rvi("bots", 0)))
        } else {
            Vec::new()
        };
        let link = peer_link(ctx, r);
        let upt = snp(32, span_since(ctx, r.rvi("started", 0)));
        let from = match (r.rvs("remote_ip"), r.rvs("ip")) {
            (Some(a), Some(b)) if a != b => Some(a),
            _ => None,
        };
        let cells = [
            Some(nn.as_slice()),
            r.rvs("name"),
            Some(&addr),
            r.rv("uuid"),
            r.rv("base"),
            r.rv("ver"),
            Some(&upt),
            Some(&bots),
            Some(&link),
            r.rv("fp"),
            from,
        ];
        let isup = r.rvb("up");
        let right: &[u8] = if isup { b"up" } else { b"down" };
        t.row(
            ctx,
            if isup { RL_NORMAL } else { RL_WARN },
            Some(right),
            &cells,
        );
    }
    if t.nr() == 0 {
        empty_note(
            out,
            "no peer hubs configured: this hub runs alone",
            Some("peer add <ip> <port> <uuid> <name|-> <key>"),
        );
    } else {
        t.render(ctx, out);
    }
    if let Some(sf) = selfr {
        line(
            out,
            RL_DIM,
            &[
                b"  this hub: ",
                peer_name(sf),
                b"  ",
                sf.rvs("uuid").unwrap_or(glyph(ctx, G_DASH)),
                b"  ",
                sf.rvs("base").unwrap_or(b"?"),
                b" ",
                sf.rvs("ver").unwrap_or(b"?"),
                b"  ",
                &num(sf.rvi("bots", 0)),
                b" bots  port ",
                &num(sf.rvi("port", 0)),
            ],
        );
    }
    if conf == 0 {
        return;
    }
    flines_add(out, RL_NORMAL, b"");
    render_mesh(ctx, rep, out);
    // health
    let issues = rep.r.iter().filter(|r| r.is("issue")).count();
    flines_add(out, RL_NORMAL, b"");
    if issues == 0 {
        let h = snp(
            96,
            cat(&[
                glyph(ctx, G_ON),
                b" healthy ",
                glyph(ctx, G_DASH),
                b" every configured link is up, no unknown hubs",
            ]),
        );
        title(ctx, out, b"Health", Some(&h));
        return;
    }
    let h = snp(
        48,
        cat(&[
            glyph(ctx, G_WARN),
            b" ",
            &num(issues),
            b" issue",
            pl(issues as i64),
        ]),
    );
    title(ctx, out, b"Health", Some(&h));
    let wg = glyph(ctx, G_WARN);
    for r in rep.r.iter().filter(|r| r.is("issue")) {
        let kind = r.rv("kind").unwrap_or(b"");
        if kind == b"peer_down" {
            let since = r.rvi("since", 0);
            if since > 0 {
                let w = when(since, ctx.now);
                line(
                    out,
                    RL_WARN,
                    &[
                        b"  ",
                        wg,
                        b" ",
                        peer_name(r),
                        b" is down ",
                        glyph(ctx, G_DASH),
                        b" no link from this hub since ",
                        &w,
                    ],
                );
            } else {
                line(
                    out,
                    RL_WARN,
                    &[
                        b"  ",
                        wg,
                        b" ",
                        peer_name(r),
                        b" is down ",
                        glyph(ctx, G_DASH),
                        b" no link from this hub since it started",
                    ],
                );
            }
        } else if kind == b"unknown_hub" {
            line(
                out,
                RL_WARN,
                &[
                    b"  ",
                    wg,
                    b" ",
                    r.rvs("via_name").or_else(|| r.rv("via")).unwrap_or(b"?"),
                    b" links to ",
                    r.rvs("name").or_else(|| r.rv("uuid")).unwrap_or(b"?"),
                    b", which this hub has not configured",
                ],
            );
        } else {
            line(out, RL_WARN, &[b"  ", wg, b" ", &r.line]);
        }
    }
}

fn render_peer_show(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let Some(r) = rep.r.iter().find(|x| x.is("peer")) else {
        return;
    };
    let dot = glyph(ctx, G_DOT);
    let t = snp(96, cat(&[b"Peer ", peer_name(r)]));
    let link = peer_link(ctx, r);
    title(ctx, out, &t, Some(&link));
    const L: i32 = 12;
    card(out, L, "#", &snp(512, num(r.rvi("n", 0))), RL_NORMAL);
    card(
        out,
        L,
        "uuid",
        r.rvs("uuid").unwrap_or(glyph(ctx, G_DASH)),
        RL_NORMAL,
    );
    let a = addr_of(r, 48);
    let v = match r.rvs("remote_ip") {
        Some(ri) => cat(&[&a, b" (configured) ", dot, b" seen from ", ri]),
        None => cat(&[&a, b" (configured)"]),
    };
    card(out, L, "address", &snp(512, v), RL_NORMAL);
    let mut sb = Sb::default();
    sb.a(r.rvs("ver").unwrap_or(b"unknown version"));
    if let Some(base) = r.rvs("base") {
        sb.a(&cat(&[b" ", dot, b" code ", base]));
    }
    if r.rvi("started", 0) > 0 {
        let a = snp(48, dur3(ctx.now.wrapping_sub(r.rvi("started", 0))));
        sb.a(&cat(&[b" ", dot, b" up ", &a]));
    }
    card(out, L, "version", &sb.p, RL_NORMAL);
    sb.reset();
    card(out, L, "key", r.rvs("fp").unwrap_or(b"(no key)"), RL_NORMAL);
    let since = r.rvi("since", 0);
    if r.rvb("up") {
        let a = when(since, ctx.now);
        let b = span(ctx.now.wrapping_sub(since));
        sb.a(&cat(&[b"up since ", &a, b" ", dot, b" ", &b]));
    } else if since > 0 {
        let a = when(since, ctx.now);
        sb.a(&cat(&[b"down since ", &a]));
    } else {
        sb.a(b"down");
    }
    if r.rvi("gossip", 0) > 0 {
        let a = span(ctx.now.wrapping_sub(r.rvi("gossip", 0)));
        sb.a(&cat(&[b" ", dot, b" last gossip ", &a, b" ago"]));
    }
    card(
        out,
        L,
        "link",
        &sb.p,
        if r.rvb("up") { RL_NORMAL } else { RL_WARN },
    );
    sb.reset();
    if r.rv("bots").is_some() {
        sb.a(&num(r.rvi("bots", 0)));
        if let Some(bl) = r.rvs("bots_list") {
            sb.a(b" (");
            for &ch in bl {
                if ch == b',' {
                    sb.a(b", ");
                } else {
                    sb.a(&[ch]);
                }
            }
            sb.a(b")");
        }
        card(out, L, "bots", &sb.p, RL_NORMAL);
        sb.reset();
    }
    for l in rep.r.iter().filter(|x| x.is("link")) {
        if !sb.p.is_empty() {
            sb.a(&cat(&[b" ", dot, b" "]));
        }
        let lu = l.rv("state") == Some(b"up");
        sb.a(&cat(&[
            l.rvs("b_name").or_else(|| l.rv("b")).unwrap_or(b"?"),
            b" ",
            glyph(ctx, if lu { G_ON } else { G_ERR }),
        ]));
    }
    let its: &[u8] = if sb.p.is_empty() {
        b"(not reported)"
    } else {
        &sb.p
    };
    card(out, L, "its peers", its, RL_NORMAL);
    const KNOWN: &[&str] = &[
        "n",
        "uuid",
        "name",
        "ip",
        "port",
        "remote_ip",
        "up",
        "since",
        "base",
        "ver",
        "started",
        "bots",
        "fp",
        "bots_list",
        "gossip",
    ];
    unknown_keys(ctx, out, r, KNOWN, L);
}

// ===========================================================================
// This hub
// ===========================================================================
fn render_hub_show(ctx: &Ctx, h: &Crec, out: &mut Flines) {
    let dot = glyph(ctx, G_DOT);
    let arrow = glyph(ctx, G_ARROW);
    let t = snp(96, cat(&[b"Hub ", h.rv("name").unwrap_or(b"?")]));
    let a = snp(48, dur3(ctx.now.wrapping_sub(h.rvi("started", ctx.now))));
    let right = snp(64, cat(&[glyph(ctx, G_ON), b" up ", &a]));
    title(ctx, out, &t, Some(&right));
    const L: i32 = 12;
    card(
        out,
        L,
        "uuid",
        h.rvs("uuid").unwrap_or(glyph(ctx, G_DASH)),
        RL_NORMAL,
    );
    let a = when(h.rvi("started", 0), ctx.now);
    let v = cat(&[
        h.rv("ver").unwrap_or(b"?"),
        b" ",
        dot,
        b" code ",
        h.rv("base").unwrap_or(b"?"),
        b" ",
        dot,
        b" started ",
        &a,
    ]);
    card(out, L, "version", &snp(512, v), RL_NORMAL);
    let v = if h.rvs("pending_bind_ip").is_some() || h.rvs("pending_port").is_some() {
        cat(&[
            nul(h.rv("bind_ip")),
            b":",
            &num(h.rvi("port", 0)),
            b" ",
            arrow,
            b" ",
            nul(h.rvs("pending_bind_ip").or_else(|| h.rv("bind_ip"))),
            b":",
            &num(h.rvi("pending_port", h.rvi("port", 0))),
            b" after restart",
        ])
    } else {
        cat(&[
            h.rv("bind_ip").unwrap_or(b"?"),
            b":",
            &num(h.rvi("port", 0)),
        ])
    };
    card(out, L, "listening", &snp(512, v), RL_NORMAL);
    // the 88-character key on one unbroken line (D10)
    card(
        out,
        L,
        "public key",
        h.rvs("key").unwrap_or(glyph(ctx, G_DASH)),
        RL_NORMAL,
    );
    card(
        out,
        L,
        "key",
        h.rvs("fp").unwrap_or(glyph(ctx, G_DASH)),
        RL_NORMAL,
    );
    let v = cat(&[b"ssh-ed25519 ", h.rvs("ssh_fp").unwrap_or(b"?")]);
    card(out, L, "ssh host key", &snp(512, v), RL_NORMAL);
    let v = cat(&[
        &num(h.rvi("peers_up", 0)),
        b" / ",
        &num(h.rvi("peers", 0)),
        b" up",
    ]);
    card(out, L, "peers", &v, RL_NORMAL);
    let v = cat(&[
        &num(h.rvi("bots_here", 0)),
        b" here ",
        dot,
        b" ",
        &num(h.rvi("bots_online", 0)),
        b" / ",
        &num(h.rvi("bots", 0)),
        b" on the network",
    ]);
    card(out, L, "bots", &v, RL_NORMAL);
    let ap = h.rvi("autopurge", 0);
    let v = if ap > 0 {
        cat(&[b"tombstones older than ", &num(ap), b" days, daily"])
    } else {
        b"off (hub purge clears tombstones by hand)".to_vec()
    };
    card(out, L, "autopurge", &v, RL_NORMAL);
    let b = bytes(h.rvi("log_size", 0) as u64);
    let v = cat(&[
        b"file ",
        level_name(h.rvi("log_file", 0)),
        b" (limit ",
        &b,
        b") ",
        dot,
        b" console ",
        level_name(h.rvi("log_console", 0)),
    ]);
    card(out, L, "log", &v, RL_NORMAL);
    let v = cat(&[
        b"peers: peer add ",
        glyph(ctx, G_ELL),
        b" <key>   ",
        dot,
        b"   bots: +hub host:port <key>",
    ]);
    card(out, L, "give to", &v, RL_DIM);
    const KNOWN: &[&str] = &[
        "name",
        "uuid",
        "ver",
        "base",
        "started",
        "bind_ip",
        "port",
        "pending_bind_ip",
        "pending_port",
        "key",
        "fp",
        "ssh_fp",
        "peers_up",
        "peers",
        "bots_here",
        "bots_online",
        "bots",
        "autopurge",
        "log_file",
        "log_console",
        "log_size",
    ];
    unknown_keys(ctx, out, h, KNOWN, L);
}

fn render_hub_settings(ctx: &Ctx, h: &Crec, out: &mut Flines) {
    title(
        ctx,
        out,
        b"Hub settings",
        Some(b"hub set <setting> <value>"),
    );
    const COLS: [Col; 3] = [
        col("SETTING", b'L', 1),
        col("CURRENT", b'L', 1),
        col("MEANING", b'L', 2),
    ];
    let mut t = Tbl::new(&COLS, -1, 0, 1);
    let port = snp(16, num(h.rvi("pending_port", h.rvi("port", 0))));
    let d = h.rvi("autopurge", 0);
    let ap = if d > 0 {
        snp(32, cat(&[&num(d), b" days"]))
    } else {
        b"off".to_vec()
    };
    let bindip = h.rvs("pending_bind_ip").or_else(|| h.rv("bind_ip"));
    let rows: [[Option<&[u8]>; 3]; 5] = [
        [
            Some(b"name"),
            h.rv("name"),
            Some(b"this hub's name (A-Z a-z 0-9 . _ -, 1-63)"),
        ],
        [
            Some(b"bindip"),
            bindip,
            Some(b"address to listen on (restart)"),
        ],
        [
            Some(b"port"),
            Some(&port),
            Some(b"port to listen on (restart)"),
        ],
        [
            Some(b"pubkey"),
            h.rv("fp"),
            Some(b"re-store the public key (must match the private key)"),
        ],
        [
            Some(b"autopurge"),
            Some(&ap),
            Some(b"purge tombstones older than <days> daily (0 = off)"),
        ],
    ];
    for r in &rows {
        t.row(ctx, RL_NORMAL, None, r);
    }
    t.render(ctx, out);
}

fn render_hub_set(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let arrow = glyph(ctx, G_ARROW);
    let setting = r.rv("setting").unwrap_or(b"?");
    let old = r.rvs("old").unwrap_or(glyph(ctx, G_DASH));
    let val = r.rvs("value").unwrap_or(glyph(ctx, G_DASH));
    let hn: &[u8] = if setting == b"name" {
        old
    } else if !ctx.hubname.is_empty() {
        ctx.hubname
    } else {
        b"hub"
    };
    let what = snp(160, cat(&[b"Hub ", hn]));
    let subj = if setting == b"pubkey" {
        cat(&[b"pubkey   re-stored ", val, b" (matches the private key)"])
    } else if setting == b"autopurge" {
        let ov = r.rvi("old", 0);
        let nv = r.rvi("value", 0);
        let o = if ov > 0 {
            cat(&[&num(ov), b" days"])
        } else {
            b"off".to_vec()
        };
        let n = if nv > 0 {
            cat(&[&num(nv), b" days"])
        } else {
            b"off".to_vec()
        };
        if nv > 0 {
            cat(&[
                b"autopurge   ",
                &o,
                b" ",
                arrow,
                b" ",
                &n,
                b"   (tombstones older than ",
                &num(nv),
                b" days, checked daily)",
            ])
        } else {
            cat(&[b"autopurge   ", &o, b" ", arrow, b" ", &n])
        }
    } else {
        cat(&[
            setting,
            b"   ",
            old,
            b" ",
            arrow,
            b" ",
            val,
            if r.rvb("restart") {
                b"   (restart needed)"
            } else {
                b""
            },
        ])
    };
    ok(ctx, &what, Some(&snp(512, subj)), out);
    if setting == b"name" {
        effect(
            ctx,
            out,
            b"peers learn the new name with the next mesh gossip (now)",
        );
    }
    if r.rvb("restart") {
        let ph = cat(&[
            b"takes effect when the hub restarts; it listens on ",
            r.rv("listen_ip").unwrap_or(b"?"),
            b":",
            r.rv("listen_port").unwrap_or(b"?"),
            b" until then",
        ]);
        effect(ctx, out, &snp(160, ph));
        if setting == b"port" {
            let ph = cat(&[
                b"after the restart, admins connect with ssh -p ",
                val,
                b"; peers and bots must use :",
                val,
            ]);
            effect(ctx, out, &snp(160, ph));
        }
    }
    if r.rv("peers").is_some() && setting != b"name" {
        effect(ctx, out, &snp(160, peers_phrase(r.rvi("peers", 0))));
    }
}

fn render_hub_rekeyed(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let t = snp(64, cat(&[glyph(ctx, G_OK), b" Hub keypair replaced"]));
    title(ctx, out, &t, r.rv("name"));
    const L: i32 = 12;
    card(out, L, "new key", r.rvs("key").unwrap_or(b"?"), RL_NORMAL);
    let v = cat(&[
        r.rvs("old_fp").unwrap_or(glyph(ctx, G_DASH)),
        b" ",
        glyph(ctx, G_ARROW),
        b" ",
        r.rvs("fp").unwrap_or(b"?"),
    ]);
    card(out, L, "key", &snp(256, v), RL_NORMAL);
    let v = cat(&[
        b"now ",
        r.rvs("ssh_fp").unwrap_or(b"?"),
        b"  (admins: ssh-keygen -R '[host]:",
        &num(r.rvi("port", 0)),
        b"')",
    ]);
    card(out, L, "ssh host key", &snp(256, v), RL_NORMAL);
    card(
        out,
        L,
        "saved to",
        r.rvs("file").unwrap_or(b"(not written)"),
        if r.rvs("file").is_some() {
            RL_NORMAL
        } else {
            RL_WARN
        },
    );
    let p = snp(48, plural(r.rvi("peers", 0), "peer link", "peer links"));
    let b = snp(48, plural(r.rvi("bots", 0), "bot", "bots"));
    card(out, L, "dropped", &cat(&[&p, b", ", &b]), RL_NORMAL);
    line(out, RL_HEAD, &[b" Next steps"]);
    line(
        out,
        RL_NORMAL,
        &[
            b"  1. on each peer hub:   peer set ",
            r.rvs("uuid").unwrap_or(b"<this hub's uuid>"),
            b" key <new key>",
        ],
    );
    let name = r.rv("name").unwrap_or(b"hub");
    let port = num(r.rvi("port", 0));
    line(
        out,
        RL_NORMAL,
        &[
            b"  2. on each bot here:   -hub ",
            name,
            b":",
            &port,
            b"  then  +hub ",
            name,
            b":",
            &port,
            b" <new key>",
        ],
    );
}

fn render_tomb_purged(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let count = r.rvi("count", 0);
    let days = r.rvi("days", 0);
    let age = if days > 0 {
        cat(&[b"older than ", &num(days), b" days"])
    } else {
        Vec::new()
    };
    if count > 0 {
        let what = cat(&[
            b"Purged ",
            &num(count),
            b" tombstone",
            pl(count),
            b" on this hub",
        ]);
        if !age.is_empty() {
            let a2 = cat(&[b"(", &age, b")"]);
            ok(ctx, &what, Some(&a2), out);
        } else {
            ok(ctx, &what, None, out);
        }
        const COLS: [Col; 3] = [
            col("KIND", b'L', 1),
            col("NAME / ID", b'L', 1),
            col("DELETED", b'L', 1),
        ];
        let mut t = Tbl::new(&COLS, -1, 1, 1);
        t.indent = 3;
        for x in rep.r.iter().filter(|x| x.is("tomb")) {
            let nm = match (x.rvs("name"), x.rvs("id")) {
                (Some(n), Some(i)) => cat(&[n, b"  ", i]),
                (n, i) => n.or(i).unwrap_or(b"").to_vec(),
            };
            let nm = snp(256, nm);
            let del = when_ago(ctx, x.rvi("ts", 0), 64);
            let cells = [x.rv("kind"), Some(nm.as_slice()), Some(&del)];
            t.row(ctx, RL_NORMAL, None, &cells);
        }
        if t.nr() > 0 {
            t.render(ctx, out);
        }
    } else {
        let what = cat(&[
            b"No tombstones",
            if age.is_empty() { b"" } else { b" " },
            &age,
            b" on this hub",
        ]);
        ok(ctx, &what, None, out);
    }
    let peers = r.rvi("peers", 0);
    let p = if peers > 0 {
        cat(&[
            b"purge sent to ",
            &num(peers),
            b" peer hub",
            pl(peers),
            b" (they purge on their own)",
        ])
    } else {
        b"no peer hub is linked now to send the purge to".to_vec()
    };
    effect(ctx, out, &p);
}

// ===========================================================================
// Statistics (view 5 renders the same)
// ===========================================================================
fn opname(op: u64) -> Option<&'static str> {
    Some(match op {
        0x01 => "CMD_PING",
        0x02 => "CMD_CONFIG_PUSH",
        0x03 => "CMD_CONFIG_PULL",
        0x04 => "CMD_CONFIG_DATA",
        0x05 => "CMD_UPDATE_PUBKEY",
        0x06 => "CMD_PEER_SYNC",
        0x07 => "CMD_MESH_STATE",
        0x08 => "CMD_SYNC_REQUEST",
        0x09 => "CMD_INVITE_REQUEST",
        0x10 => "CMD_ADMIN_AUTH",
        0x11 => "CMD_ADMIN_LIST_FULL",
        0x12 => "CMD_ADMIN_ADD",
        0x13 => "CMD_ADMIN_DEL",
        0x14 => "CMD_ADMIN_REGEN_KEYS",
        0x15 => "CMD_ADMIN_LIST_SUMMARY",
        0x16 => "CMD_ADMIN_GET_PENDING",
        0x17 => "CMD_ADMIN_APPROVE",
        0x18 => "CMD_ADMIN_ADD_PEER",
        0x19 => "CMD_ADMIN_LIST_PEERS",
        0x1A => "CMD_ADMIN_DEL_PEER",
        0x1B => "CMD_ADMIN_GET_PUBKEY",
        0x1C => "CMD_ADMIN_SET_PRIVKEY",
        0x1D => "CMD_ADMIN_GET_PRIVKEY",
        0x1E => "CMD_ADMIN_SET_PUBKEY",
        0x1F => "CMD_ADMIN_SYNC_MESH",
        0x20 => "CMD_ADMIN_REKEY_BOT",
        0x21 => "CMD_ADMIN_DISCONNECT_BOT",
        0x22 => "CMD_ADMIN_BOT_STATUS",
        0x23 => "CMD_ADMIN_LIST_CHANNELS",
        0x24 => "CMD_ADMIN_ADD_CHANNEL",
        0x25 => "CMD_ADMIN_DEL_CHANNEL",
        0x26 => "CMD_ADMIN_LIST_MASKS",
        0x27 => "CMD_ADMIN_ADD_MASK",
        0x28 => "CMD_OP_REQUEST",
        0x29 => "CMD_OP_GRANT",
        0x2A => "CMD_OP_FAILED",
        0x2B => "CMD_ADMIN_DEL_MASK",
        0x2C => "CMD_ADMIN_LIST_OPERS",
        0x2D => "CMD_ADMIN_ADD_OPER",
        0x2E => "CMD_ADMIN_DEL_OPER",
        0x2F => "CMD_ADMIN_SET_ADMIN_PASS",
        0x30 => "CMD_ADMIN_SET_BOT_PASS",
        0x31 => "CMD_ADMIN_OP_USER",
        0x32 => "CMD_ADMIN_CREATE_BOT",
        0x33 => "CMD_OP_FORWARD_REQUEST",
        0x34 => "CMD_OP_FORWARD_GRANT",
        0x35 => "CMD_OP_FORWARD_FAILED",
        0x36 => "CMD_ADMIN_PURGE_TOMBSTONES",
        0x37 => "CMD_ADMIN_SET_BIND_IP",
        0x38 => "CMD_ADMIN_LIST_ALLOWLIST",
        0x39 => "CMD_ADMIN_ADD_ALLOWLIST",
        0x3A => "CMD_ADMIN_DEL_ALLOWLIST",
        0x3B => "CMD_ADMIN_LIST_DENYLIST",
        0x3C => "CMD_ADMIN_ADD_DENYLIST",
        0x3D => "CMD_ADMIN_DEL_DENYLIST",
        0x3E => "CMD_ADMIN_SET_HUB_NAME",
        0x3F => "CMD_ADMIN_SET_BIND_PORT",
        0x40 => "CMD_BOT_KEY_UPDATE",
        0x41 => "CMD_ADMIN_SET_PURGE_DAYS",
        0x42 => "CMD_PEER_REKEY_BOT",
        0x43 => "CMD_ADMIN_SET_LOG_LEVEL",
        0x44 => "CMD_ADMIN_SET_LOG_SIZE",
        0x45 => "CMD_BOT_DELTA",
        0x46 => "CMD_ADMIN_ADD_ADMIN",
        0x47 => "CMD_ADMIN_DEL_ADMIN",
        0x48 => "CMD_ADMIN_ADD_OPER_RECORD",
        0x49 => "CMD_ADMIN_DEL_OPER_RECORD",
        0x4A => "CMD_ADMIN_ADD_USERMASK",
        0x4B => "CMD_ADMIN_DEL_USERMASK",
        0x4C => "CMD_ADMIN_SET_USERPASS",
        0x4D => "CMD_ADMIN_MATCH",
        0x4E => "CMD_ADMIN_LIST_ADMINS",
        0x4F => "CMD_ADMIN_LIST_OPERS_V2",
        0x50 => "CMD_BOT_RELAY",
        0x51 => "CMD_BOT_MSG",
        0x52 => "CMD_ADMIN_SET_PEER_PUBKEY",
        0x53 => "CMD_ADMIN_SET_OPT_FLAGS",
        0x54 => "CMD_ADMIN_GET_OPT_FLAGS",
        0x55 => "CMD_ADMIN_SET_USERKEY",
        0x56 => "CMD_BOT_PRESENCE",
        0x57 => "CMD_BOT_ROSTER",
        0x58 => "CMD_BOT_TREE",
        0x59 => "CMD_CHAN_REQUEST",
        0x5A => "CMD_CHAN_ACTION",
        0x5B => "CMD_CHAN_REPLY",
        0x5C => "CMD_CHAN_FWD_REQUEST",
        0x5D => "CMD_CHAN_FWD_REPLY",
        0x5E => "CMD_UPGRADE_PREPARE",
        0x5F => "CMD_UPGRADE_READY",
        0x60 => "CMD_UPGRADE_COMMIT",
        0x61 => "CMD_UPGRADE_RESULT",
        0x62 => "CMD_UPGRADE_ABORT",
        0x63 => "CMD_ADMIN_UPGRADE_NET",
        0x64 => "CMD_ADMIN_UPGRADE_STATUS",
        0x65 => "CMD_BOT_RELAY_FWD",
        0x66 => "CMD_UPGRADE_FORGET",
        0x67 => "CMD_PEER_BCAST",
        0x68 => "CMD_ADMIN_STATS",
        0x69 => "CMD_ACTIVITY",
        0x6A => "CMD_ACTIVITY_QUERY",
        0x6B => "CMD_ACTIVITY_REPLY",
        0x6C => "CMD_CONSOLE",
        _ => return None,
    })
}

fn count_kv(b: &mut Sb, label: &str, n: u64, colx: i32) {
    let c = count(n);
    b.pad(colx);
    b.a(&cat(&[s(label), b"  ", &c]));
}

fn render_stats(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let up = snp(48, dur3(rep.res.rvi("up", 0)));
    let hn: &[u8] = if ctx.hubname.is_empty() {
        b"hub"
    } else {
        ctx.hubname
    };
    let right = snp(96, cat(&[hn, b" ", glyph(ctx, G_DOT), b" up ", &up]));
    title(ctx, out, b"Hub statistics", Some(&right));
    let cfg = rep.r.iter().rfind(|x| x.is("cfg"));
    let sy = rep.r.iter().rfind(|x| x.is("sync"));
    let mut b = Sb::default();
    if let Some(cfg) = cfg {
        line(out, RL_HEAD, &[b" Config pushes to bots"]);
        count_kv(&mut b, "  sent", cfg.rvu("sent"), 0);
        count_kv(&mut b, "skipped (unchanged)", cfg.rvu("same"), 24);
        count_kv(&mut b, "lost", cfg.rvu("lost"), 56);
        b.emit(out, RL_NORMAL);
    }
    if let Some(sy) = sy {
        line(out, RL_HEAD, &[b" Sync frames from peers"]);
        count_kv(&mut b, "  frames", sy.rvu("frames"), 0);
        count_kv(&mut b, "no-op", sy.rvu("noop"), 24);
        count_kv(&mut b, "records", sy.rvu("records"), 40);
        count_kv(&mut b, "applied", sy.rvu("applied"), 60);
        b.emit(out, RL_NORMAL);
    }
    flines_add(out, RL_NORMAL, b"");
    title(ctx, out, b"Traffic by message", Some(b"sorted by bytes"));
    let mut ix: Vec<usize> = (0..rep.r.len()).filter(|&i| rep.r[i].is("op")).collect();
    let tb = |i: usize| rep.r[i].rvu("rx_b").wrapping_add(rep.r[i].rvu("tx_b"));
    // most bytes first, then the opcode
    for i in 1..ix.len() {
        let x = ix[i];
        let bx = tb(x);
        let mut j = i;
        while j > 0 {
            let bj = tb(ix[j - 1]);
            let cx = rep.r[x].rv("code");
            let cj = rep.r[ix[j - 1]].rv("code");
            let before = bx > bj
                || (bx == bj && matches!((cx, cj), (Some(a), Some(b)) if cmp(a, b).is_lt()));
            if before {
                ix[j] = ix[j - 1];
                j -= 1;
            } else {
                break;
            }
        }
        ix[j] = x;
    }
    const COLS: [Col; 6] = [
        col("OPCODE", b'L', 1),
        col("NAME", b'L', 1),
        col("IN FRAMES", b'R', 1),
        col("IN BYTES", b'R', 1),
        col("OUT FRAMES", b'R', 2),
        col("OUT BYTES", b'R', 2),
    ];
    let mut t = Tbl::new(&COLS, -1, 1, 1);
    let mut tot = [0u64; 4];
    let fmt4 = |v: &[u64; 4]| -> Vec<Vec<u8>> {
        (0..4)
            .map(|q| if q % 2 == 1 { bytes(v[q]) } else { count(v[q]) })
            .collect()
    };
    for &k in &ix {
        let r = &rep.r[k];
        let code = r.rv("code").unwrap_or(b"?");
        let op = strtoull(code, 16);
        let name = if op < 256 {
            opname(op).unwrap_or("?")
        } else {
            "?"
        };
        let v = [r.rvu("rx_f"), r.rvu("rx_b"), r.rvu("tx_f"), r.rvu("tx_b")];
        for q in 0..4 {
            tot[q] = tot[q].wrapping_add(v[q]);
        }
        let c = fmt4(&v);
        let cells = [
            Some(code),
            Some(s(name)),
            Some(c[0].as_slice()),
            Some(&c[1]),
            Some(&c[2]),
            Some(&c[3]),
        ];
        t.row(ctx, RL_NORMAL, None, &cells);
    }
    if !ix.is_empty() {
        let c = fmt4(&tot);
        let cells = [
            Some(b"total".as_slice()),
            Some(b" "),
            Some(&c[0]),
            Some(&c[1]),
            Some(&c[2]),
            Some(&c[3]),
        ];
        t.row(ctx, RL_HEAD, None, &cells);
        t.render(ctx, out);
    } else {
        empty_note(out, "no traffic yet", None);
    }
}

// ===========================================================================
// Log
// ===========================================================================
/// `%-10s`
fn pad10(v: &[u8]) -> Vec<u8> {
    let mut x = v.to_vec();
    while x.len() < 10 {
        x.push(b' ');
    }
    x
}

fn render_log_show(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    title(ctx, out, b"Log", Some(ctx.hubname));
    const L: i32 = 13;
    let dot = glyph(ctx, G_DOT);
    let a = bytes(r.rvi("file_bytes", 0) as u64);
    let b = bytes(r.rvi("limit", 0) as u64);
    let v = cat(&[
        &pad10(level_name(r.rvi("file_level", 0))),
        b"  ",
        r.rv("file").unwrap_or(b"?"),
        b" ",
        dot,
        b" ",
        &a,
        b" of ",
        &b,
    ]);
    card(out, L, "file", &snp(256, v), RL_NORMAL);
    let c1 = count(r.rvi("ring_lines", 0) as u64);
    let c2 = count(r.rvi("ring_cap", 0) as u64);
    let lv = pad10(level_name(r.rvi("console_level", 0)));
    let v = if r.rvi("ring_oldest", 0) > 0 {
        let a = when(r.rvi("ring_oldest", 0), ctx.now);
        cat(&[
            &lv,
            b"  ",
            &c1,
            b" of ",
            &c2,
            b" lines ",
            dot,
            b" oldest ",
            &a,
        ])
    } else {
        cat(&[&lv, b"  ", &c1, b" of ", &c2, b" lines"])
    };
    card(out, L, "console ring", &snp(256, v), RL_NORMAL);
    card(out, L, "this session", ctx.session_log, RL_NORMAL);
}

fn render_log_set(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let arrow = glyph(ctx, G_ARROW);
    let setting = r.rv("setting").unwrap_or(b"?");
    if setting == b"size" {
        let a = bytes(r.rvi("old", 0) as u64);
        let b = bytes(r.rvi("value", 0) as u64);
        let asked = r.rvi("asked", 0);
        let val = r.rvi("value", 0);
        let subj = if asked != val {
            let q = bytes(asked as u64);
            cat(&[
                b"size   ",
                &a,
                b" ",
                arrow,
                b" ",
                &b,
                b" (the ",
                if asked > val { b"maximum" } else { b"minimum" },
                b"; ",
                &q,
                b" was asked)",
            ])
        } else {
            cat(&[b"size   ", &a, b" ", arrow, b" ", &b])
        };
        ok(ctx, b"Log", Some(&subj), out);
        if r.rvi("file_level", 1) == 0 {
            warn(
                ctx,
                out,
                b"the file level is none: nothing is written until log set file <level>",
            );
        }
        return;
    }
    let subj = cat(&[
        setting,
        b"   ",
        level_name(r.rvi("old", 0)),
        b" ",
        arrow,
        b" ",
        level_name(r.rvi("value", 0)),
    ]);
    ok(ctx, b"Log", Some(&snp(256, subj)), out);
    if setting == b"file" {
        if r.rvi("value", 0) == 0 {
            effect(ctx, out, b"the log file is off");
        } else {
            let b = bytes(r.rvi("limit", 0) as u64);
            let ph = cat(&[
                b"writes ",
                level_name(r.rvi("value", 0)),
                b" and worse to ",
                r.rv("file").unwrap_or(b"?"),
                b", limit ",
                &b,
            ]);
            effect(ctx, out, &snp(256, ph));
        }
    } else {
        let ph = cat(&[
            b"the console ring keeps ",
            level_name(r.rvi("value", 0)),
            b" and worse; F2 / log on <level> filter further per session",
        ]);
        effect(ctx, out, &ph);
    }
}

// ===========================================================================
// Access lists
// ===========================================================================
fn ip4(s: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    let mut parts = 0;
    let mut i = 0;
    while i < s.len() && parts < 4 {
        if !s[i].is_ascii_digit() {
            return None;
        }
        let mut p: u64 = 0;
        let mut digits = 0;
        while i < s.len() && s[i].is_ascii_digit() && digits < 4 {
            p = p * 10 + u64::from(s[i] - b'0');
            i += 1;
            digits += 1;
        }
        if p > 255 {
            return None;
        }
        v = (v << 8) | p;
        parts += 1;
        if i < s.len() && s[i] == b'.' && parts < 4 {
            i += 1;
        } else {
            break;
        }
    }
    if parts != 4 {
        return None;
    }
    if i == s.len() || s[i] == b'/' {
        Some((v, i))
    } else {
        None
    }
}

fn acl_covers(pattern: Option<&[u8]>, ip: Option<&[u8]>) -> bool {
    let (Some(pattern), Some(ip)) = (pattern, ip) else {
        return false;
    };
    let (Some((net, _)), Some((a, _))) = (ip4(pattern), ip4(ip)) else {
        return false;
    };
    let bits = match pattern.iter().position(|&b| b == b'/') {
        Some(sl) => strtoll(&pattern[sl + 1..]).0,
        None => 32,
    };
    if !(0..=32).contains(&bits) {
        return false;
    }
    let mask: u64 = if bits == 0 {
        0
    } else {
        (0xFFFF_FFFFu64 << (32 - bits)) & 0xFFFF_FFFF
    };
    (a & mask) == (net & mask)
}

fn render_acl_list(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let dot = glyph(ctx, G_DOT);
    let selfv = r.rv("self").unwrap_or(b"?");
    let right = cat(&[
        b"allow ",
        &num(r.rvi("allow", 0)),
        b" ",
        dot,
        b" deny ",
        &num(r.rvi("deny", 0)),
        b" ",
        dot,
        b" you: ",
        r.rv("self_ip").unwrap_or(b"?"),
        b" ",
        glyph(ctx, if selfv == b"denied" { G_ERR } else { G_ON }),
        b" ",
        selfv,
    ]);
    title(ctx, out, b"Access lists", Some(&snp(160, right)));
    for pass in 0..2 {
        let list: &[u8] = if pass == 0 { b"allow" } else { b"deny" };
        title(
            ctx,
            out,
            if pass == 0 { b"Allow" } else { b"Deny" },
            Some(if pass == 0 {
                b"only these addresses may connect"
            } else {
                b"these addresses are refused"
            }),
        );
        const COLS: [Col; 5] = [
            col("#", b'R', 1),
            col("PATTERN", b'L', 1),
            col("COVERS", b'L', 1),
            col("ADDED", b'L', 1),
            col("", b'L', 1),
        ];
        let mut t = Tbl::new(&COLS, -1, 1, 1);
        for x in &rep.r {
            if !x.is("acl") || x.rv("list") != Some(list) {
                continue;
            }
            let nn = snp(16, num(x.rvi("n", 0)));
            let sz = strtoull(x.rv("size").unwrap_or(b"0"), 10);
            let c = count(sz);
            let cov = snp(
                48,
                cat(&[&c, b" address", if sz == 1 { b"" } else { b"es" }]),
            );
            let added = when_ago(ctx, x.rvi("ts", 0), 64);
            let you: &[u8] = if ctx.ascii {
                b"<- you"
            } else {
                "← you".as_bytes()
            };
            let cov_you: &[u8] = if acl_covers(x.rv("pattern"), r.rv("self_ip")) {
                you
            } else {
                b" "
            };
            let cells = [
                Some(nn.as_slice()),
                x.rv("pattern"),
                Some(&cov),
                Some(&added),
                Some(cov_you),
            ];
            t.row(ctx, RL_NORMAL, None, &cells);
        }
        if t.nr() > 0 {
            t.render(ctx, out);
        } else if pass == 0 {
            line(
                out,
                RL_DIM,
                &[
                    b"  (empty ",
                    glyph(ctx, G_DASH),
                    b" every address may connect, subject to the deny list)",
                ],
            );
        } else {
            line(out, RL_DIM, &[b"  (empty)"]);
        }
    }
}

fn render_acl_change(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let add = rep.code == b"acl.added";
    let list = r.rv("list").unwrap_or(b"?");
    let what = cat(&[if list == b"allow" { b"Allow" } else { b"Deny" }, b" list"]);
    let sz = strtoull(r.rv("size").unwrap_or(b"0"), 10);
    let c = count(sz);
    let subj = cat(&[
        if add { b"added" } else { b"removed" },
        b"   ",
        r.rv("pattern").unwrap_or(b"?"),
        b"  (",
        &c,
        b" address",
        if sz == 1 { b"" } else { b"es" },
        b")",
    ]);
    ok(ctx, &what, Some(&snp(160, subj)), out);
    effect(ctx, out, b"local to this hub (the lists are not synced)");
    if r.rvb("first") {
        warn(
            ctx,
            out,
            b"the allow list was empty: from now on only listed addresses can connect",
        );
    }
    if r.rvb("empty") {
        warn(
            ctx,
            out,
            b"the allow list is empty now: every address may connect",
        );
    }
    let closing = r.rvi("closing", 0);
    if closing > 0 {
        let p = cat(&[
            b"closing ",
            &num(closing),
            b" connection",
            pl(closing),
            b" it no longer permits",
        ]);
        effect(ctx, out, &p);
    }
}

// ===========================================================================
// Options
// ===========================================================================
const OPT_FLAGS: [(u8, &str); 2] = [
    (
        b'h',
        "hub-only mutation: bots refuse config changes not coming from a hub",
    ),
    (
        b'F',
        "config frozen (an upgrade is running, or was left frozen)",
    ),
];

fn render_option_list(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let flags = rep.res.rv("flags").unwrap_or(b"");
    let fp = flags_phrase(Some(flags), 40);
    let right = snp(64, cat(&[b"flags: ", &fp]));
    title(ctx, out, b"Network options", Some(&right));
    const COLS: [Col; 3] = [
        col("FLAG", b'L', 1),
        col("STATE", b'L', 1),
        col("MEANING", b'L', 2),
    ];
    let mut t = Tbl::new(&COLS, -1, 0, 1);
    for (f, meaning) in OPT_FLAGS {
        let on = flags.contains(&f);
        let fb = [f];
        let cells = [
            Some(fb.as_slice()),
            Some(if on { b"on".as_slice() } else { b"off" }),
            Some(s(meaning)),
        ];
        t.row(ctx, if on { RL_NORMAL } else { RL_DIM }, None, &cells);
    }
    for &p in flags {
        if OPT_FLAGS.iter().any(|(f, _)| *f == p) {
            continue;
        }
        let pb = [p];
        let cells = [
            Some(pb.as_slice()),
            Some(b"on".as_slice()),
            Some(b"(unknown flag)".as_slice()),
        ];
        t.row(ctx, RL_WARN, None, &cells);
    }
    t.render(ctx, out);
    line(
        out,
        RL_DIM,
        &[
            b"  change with option set <flags>   ",
            glyph(ctx, G_DOT),
            b"   clear with option set -",
        ],
    );
}

fn render_option_set(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let o = flags_phrase(r.rv("old"), 40);
    let n = flags_phrase(r.rv("value"), 40);
    let subj = cat(&[b"flags   ", &o, b" ", glyph(ctx, G_ARROW), b" ", &n]);
    ok(ctx, b"Network options", Some(&snp(128, subj)), out);
    let ph = sync_push_phrase(128, r.rvi("peers", 0), r.rvi("bots", 0));
    effect(ctx, out, &ph);
}

// ===========================================================================
// Users
// ===========================================================================
fn user_seen(ctx: &Ctx, u: &Crec, with_ip: bool, cap: usize) -> Vec<u8> {
    if let Some(name) = u.rv("name")
        && name.eq_ignore_ascii_case(ctx.admin)
    {
        return if with_ip {
            snp(cap, cat(&[b"now (this session, from ", ctx.ip, b")"]))
        } else {
            b"now (this session)".to_vec()
        };
    }
    when_ago(ctx, u.rvi("seen", 0), cap)
}

fn render_user_list(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let dot = glyph(ctx, G_DOT);
    let t = match r.rvs("role") {
        Some(role) => snp(48, cat(&[b"Users ", dot, b" ", role])),
        None => b"Users".to_vec(),
    };
    let (a, o, m) = (r.rvi("admins", 0), r.rvi("opers", 0), r.rvi("masks", 0));
    let right = cat(&[
        &num(a),
        b" admin",
        pl(a),
        b" ",
        dot,
        b" ",
        &num(o),
        b" oper",
        pl(o),
        b" ",
        dot,
        b" ",
        &num(m),
        b" mask",
        pl(m),
    ]);
    title(ctx, out, &t, Some(&snp(96, right)));
    const COLS: [Col; 6] = [
        col("ROLE", b'L', 1),
        col("NAME", b'L', 1),
        col("KEY", b'L', 1),
        col("LAST SEEN", b'L', 1),
        col("MASKS", b'R', 1),
        col("CONSOLES", b'R', 1),
    ];
    let mut tb = Tbl::new(&COLS, -1, 1, 1);
    for u in rep.r.iter().filter(|u| u.is("user")) {
        let seen = user_seen(ctx, u, false, 96);
        let masks = snp(16, num(u.rvi("masks", 0)));
        let cons = if u.rv("sessions").is_some() {
            snp(16, num(u.rvi("sessions", 0)))
        } else {
            Vec::new()
        };
        let fp: &[u8] = if u.rvs("fp").is_some() {
            u.rv("fp").unwrap_or(b"")
        } else {
            b"(no key)"
        };
        let cells = [
            u.rv("role"),
            u.rv("name"),
            Some(fp),
            Some(&seen),
            Some(&masks),
            Some(&cons),
        ];
        tb.row(ctx, RL_NORMAL, u.rv("role"), &cells);
    }
    if tb.nr() == 0 {
        empty_note(out, "no users", Some("user add admin <name> <key> <mask>"));
        return;
    }
    tb.render(ctx, out);
    rule_line(ctx, out);
    line(
        out,
        RL_DIM,
        &[b"  user show <name> for masks and their last use"],
    );
}

fn render_user_show(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let mut any = false;
    for i in 0..rep.r.len() {
        let u = &rep.r[i];
        if !u.is("user") {
            continue;
        }
        if any {
            flines_add(out, RL_NORMAL, b"");
        }
        any = true;
        let t = snp(96, cat(&[b"User ", u.rv("name").unwrap_or(b"?")]));
        title(ctx, out, &t, u.rv("role"));
        const L: i32 = 10;
        card(out, L, "key", u.rvs("fp").unwrap_or(b"(no key)"), RL_NORMAL);
        let v = user_seen(ctx, u, true, 160);
        card(out, L, "last seen", &v, RL_NORMAL);
        if u.rv("sessions").is_some() {
            let sn = u.rvi("sessions", 0);
            let v = cat(&[&num(sn), b" open session", pl(sn)]);
            card(out, L, "console", &v, RL_NORMAL);
        }
        const KNOWN: &[&str] = &["name", "role", "fp", "seen", "masks", "sessions"];
        unknown_keys(ctx, out, u, KNOWN, L);
        const COLS: [Col; 2] = [col("MASK", b'L', 1), col("LAST USED", b'L', 1)];
        let mut t = Tbl::new(&COLS, -1, 0, 0);
        t.indent = 3;
        // this user's mask| records follow its user| record
        for m in rep.r[i + 1..].iter().take_while(|x| !x.is("user")) {
            if !m.is("mask") {
                continue;
            }
            let used = when_ago(ctx, m.rvi("used", 0), 64);
            let cells = [m.rv("mask"), Some(used.as_slice())];
            t.row(ctx, RL_NORMAL, None, &cells);
        }
        if t.nr() > 0 {
            t.render(ctx, out);
        } else {
            line(
                out,
                RL_DIM,
                &[b"   (no masks: no bot recognises this user on IRC)"],
            );
        }
    }
    if !any {
        empty_note(out, "no users", Some("user add admin <name> <key> <mask>"));
    }
}

fn render_user_change(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let code = rep.code.as_slice();
    let name = r.rv("name").unwrap_or(b"?");
    let ph = sync_push_phrase(160, r.rvi("peers", 0), r.rvi("bots", 0));
    if code == b"user.added" {
        let subj = snp(256, cat(&[name, b"   ", r.rv("role").unwrap_or(b"?")]));
        ok(ctx, b"User added", Some(&subj), out);
        res_kv(out, "key", r.rvs("fp").unwrap_or(b"?"));
        res_kv(out, "mask", r.rvs("mask").unwrap_or(b"?"));
        effect(ctx, out, &ph);
        let subj = if r.rv("role") == Some(b"admin") {
            cat(&[
                name,
                b" logs in with: ssh -i <their>_ed25519 -p ",
                &num(r.rvi("port", 0)),
                b" ",
                name,
                b"@<this hub>",
            ])
        } else {
            cat(&[name, b" authenticates to bots from IRC with their key"])
        };
        res_kv(out, "next", &snp(256, subj));
    } else if code == b"user.removed" {
        let m = r.rvi("masks", 0);
        let subj = cat(&[
            name,
            b"   ",
            r.rv("role").unwrap_or(b"?"),
            b", with ",
            &num(m),
            b" mask",
            pl(m),
        ]);
        ok(ctx, b"User removed", Some(&snp(256, subj)), out);
        effect(ctx, out, &ph);
        let sn = r.rvi("sessions", 0);
        if sn > 0 {
            let subj = cat(&[
                &num(sn),
                b" open console session",
                pl(sn),
                b" of ",
                name,
                b" closed",
            ]);
            effect(ctx, out, &snp(256, subj));
        }
    } else if code == b"user.set" {
        let what = snp(96, cat(&[b"User ", name]));
        let subj = cat(&[
            b"key   ",
            r.rvs("old").unwrap_or(b"(none)"),
            b" ",
            glyph(ctx, G_ARROW),
            b" ",
            r.rvs("value").unwrap_or(b"?"),
        ]);
        ok(ctx, &what, Some(&snp(256, subj)), out);
        effect(ctx, out, &ph);
        if r.rv("role") == Some(b"admin") {
            let sn = r.rvi("sessions", 0);
            let subj = cat(&[&num(sn), b" open console session", pl(sn), b" closed"]);
            effect(ctx, out, &subj);
        }
    } else {
        let add = code == b"user.mask_added";
        let m = r.rvi("masks", 0);
        let what = snp(96, cat(&[b"User ", name]));
        let mask = r.rv("mask").unwrap_or(b"?");
        let subj = if add {
            cat(&[
                b"mask added   ",
                mask,
                b"   (",
                &num(m),
                b" mask",
                pl(m),
                b" now)",
            ])
        } else {
            cat(&[b"mask removed   ", mask, b"   (", &num(m), b" left)"])
        };
        ok(ctx, &what, Some(&snp(256, subj)), out);
        effect(ctx, out, &ph);
        if !add && m == 0 {
            let subj = cat(&[
                name,
                b" has no masks left: the console still works, but no bot will recognise them on IRC",
            ]);
            warn(ctx, out, &snp(256, subj));
        }
    }
}

// ===========================================================================
// Channels (the CHAN_SETTINGS registry: a new setting is one row here)
// ===========================================================================
/// (key, head, label)
const CHAN_SETTINGS: [(&str, &str, &str); 2] = [("key", "KEY", "key"), ("modes", "MODES", "modes")];

fn chan_value(key: &str, v: Option<&[u8]>, cap: usize) -> Vec<u8> {
    match v {
        Some(v) if key == "modes" && !v.is_empty() => snp(cap, cat(&[b"+", v])),
        v => snp(cap, v.unwrap_or(b"").to_vec()),
    }
}

fn chan_known(k: &[u8]) -> bool {
    k == b"name" || k == b"ts" || CHAN_SETTINGS.iter().any(|c| c.0.as_bytes() == k)
}

fn render_channel_list(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let cnt = rep.res.rvi("count", 0);
    let dot = glyph(ctx, G_DOT);
    let right = cat(&[
        &num(cnt),
        b" channel",
        pl(cnt),
        b" ",
        dot,
        b" ",
        &num(rep.res.rvi("bots_online", 0)),
        b" bots online",
    ]);
    title(ctx, out, b"Channels", Some(&snp(96, right)));
    // CHANNEL, the registry's settings, ADDED / CHANGED, OTHER (unknown set.*)
    let mut cols: Vec<Col> = vec![col("CHANNEL", b'L', 1)];
    for cs in CHAN_SETTINGS {
        cols.push(col(cs.1, b'L', 2));
    }
    cols.push(col("ADDED / CHANGED", b'L', 1));
    let other = rep
        .r
        .iter()
        .filter(|c| c.is("chan"))
        .any(|c| c.k.iter().any(|k| !chan_known(k)));
    if other {
        cols.push(col("OTHER", b'L', 2));
    }
    let mut t = Tbl::new(&cols, -1, 0, 0);
    let v = collect(rep, "chan", "name", None);
    let mut keyed = 0;
    for sr in &v {
        let c = sr.r;
        let vals: Vec<Vec<u8>> = CHAN_SETTINGS
            .iter()
            .map(|cs| chan_value(cs.0, c.rv(cs.0), 128))
            .collect();
        let w = when_ago(ctx, c.rvi("ts", 0), 64);
        let mut o = Sb::default();
        if other {
            for q in 0..c.k.len() {
                if !chan_known(&c.k[q]) {
                    let sep: &[u8] = if o.p.is_empty() { b"" } else { b" " };
                    o.a(&cat(&[sep, &c.k[q], b"=", &c.v[q]]));
                }
            }
        }
        let mut cells: Vec<Option<&[u8]>> = vec![c.rv("name")];
        for x in &vals {
            cells.push(Some(x));
        }
        cells.push(Some(&w));
        if other {
            cells.push(Some(o.opt().unwrap_or(b"")));
        }
        if c.rvs("key").is_some() {
            keyed += 1;
        }
        t.row(ctx, RL_NORMAL, None, &cells);
    }
    if t.nr() == 0 {
        empty_note(
            out,
            "no channels configured",
            Some("channel add <#chan> [key]"),
        );
        return;
    }
    t.render(ctx, out);
    rule_line(ctx, out);
    let nr = v.len() as i32;
    line(
        out,
        RL_DIM,
        &[
            b"  ",
            &num(nr - keyed),
            b" open ",
            dot,
            b" ",
            &num(keyed),
            b" with a key      channel show <#chan> for detail",
        ],
    );
}

fn render_channel_show(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let Some(c) = rep.r.iter().find(|x| x.is("chan")) else {
        return;
    };
    let t = snp(96, cat(&[b"Channel ", c.rv("name").unwrap_or(b"?")]));
    title(ctx, out, &t, Some(b"managed"));
    const L: i32 = 12;
    for cs in CHAN_SETTINGS {
        let v = chan_value(cs.0, c.rv(cs.0), 160);
        let v: &[u8] = if v.is_empty() { glyph(ctx, G_DASH) } else { &v };
        card(out, L, cs.2, v, RL_NORMAL);
    }
    let v = when_ago(ctx, c.rvi("ts", 0), 160);
    card(out, L, "changed", &v, RL_NORMAL);
    const KNOWN: &[&str] = &["name", "ts", "key", "modes"];
    unknown_keys(ctx, out, c, KNOWN, L);
    line(
        out,
        RL_DIM,
        &[b"  bot presence per channel: not reported yet"],
    );
}

fn render_channel_change(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let code = rep.code.as_slice();
    let arrow = glyph(ctx, G_ARROW);
    let name = r.rv("name").unwrap_or(b"?");
    let bots = r.rvi("bots", 0);
    let peers = r.rvi("peers", 0);
    let pp = if peers > 0 {
        cat(&[b"synced to ", &num(peers), b" peer hub", pl(peers)])
    } else {
        b"no peer hub linked".to_vec()
    };
    if code == b"channel.added" {
        if r.rvb("existed") {
            let subj = cat(&[
                name,
                b"   key ",
                r.rvs("old_key").unwrap_or(b"(none)"),
                b" ",
                arrow,
                b" ",
                r.rvs("key").unwrap_or(b"(none)"),
            ]);
            ok(ctx, b"Channel updated", Some(&snp(256, subj)), out);
        } else {
            let subj = match r.rvs("key") {
                Some(k) => cat(&[name, b"   key ", k]),
                None => name.to_vec(),
            };
            ok(ctx, b"Channel added", Some(&snp(256, subj)), out);
        }
        let ph = cat(&[
            b"pushed to ",
            &num(bots),
            b" bot",
            pl(bots),
            b" (they join now); ",
            &pp,
        ]);
        effect(ctx, out, &snp(160, ph));
        if let Some(m) = r.rvs("modes") {
            effect(
                ctx,
                out,
                &snp(160, cat(&[b"recorded modes +", m, b" kept"])),
            );
        }
    } else if code == b"channel.set" {
        let what = snp(96, cat(&[b"Channel ", name]));
        let subj = cat(&[
            r.rv("setting").unwrap_or(b"?"),
            b"   ",
            r.rvs("old").unwrap_or(glyph(ctx, G_DASH)),
            b" ",
            arrow,
            b" ",
            r.rvs("value").unwrap_or(glyph(ctx, G_DASH)),
        ]);
        ok(ctx, &what, Some(&snp(256, subj)), out);
        let ph = cat(&[b"pushed to ", &num(bots), b" bot", pl(bots), b"; ", &pp]);
        effect(ctx, out, &snp(160, ph));
    } else if code == b"channel.removed" {
        ok(ctx, b"Channel removed", Some(name), out);
        if !r.rvb("existed") {
            warn(
                ctx,
                out,
                b"it was not a managed channel here; the removal still syncs",
            );
        }
        let ph = cat(&[&num(bots), b" bot", pl(bots), b" told to part; ", &pp]);
        effect(ctx, out, &snp(160, ph));
        let d = r.rvi("purge_days", 0);
        let ph = if d > 0 {
            cat(&[b"tombstone kept ", &num(d), b" days (hub set autopurge)"])
        } else {
            b"the tombstone stays until hub purge (autopurge is off)".to_vec()
        };
        effect(ctx, out, &ph);
    } else {
        let nick = r.rv("nick").unwrap_or(b"?");
        let chan = r.rv("chan").unwrap_or(b"?");
        let subj = cat(&[nick, b" on ", chan]);
        ok(ctx, b"Op request sent", Some(&snp(256, subj)), out);
        let local = r.rvi("local", 0);
        let ph = if local > 0 {
            cat(&[
                &num(local),
                b" bot",
                pl(local),
                b" on this hub asked; forwarded to ",
                &num(peers),
                b" peer hub",
                pl(peers),
            ])
        } else {
            cat(&[
                b"no bots on this hub; forwarded to ",
                &num(peers),
                b" peer hub",
                pl(peers),
            ])
        };
        effect(ctx, out, &snp(160, ph));
        let ph = cat(&[
            b"a bot that is opped on ",
            chan,
            b" and sees ",
            nick,
            b" will op them",
        ]);
        effect(ctx, out, &snp(160, ph));
    }
}

// ===========================================================================
// Upgrades (view 4 renders the same)
// ===========================================================================
fn node_rank(st: Option<&[u8]>) -> i32 {
    match st {
        None => 9,
        Some(b"committing") => 0,
        Some(b"failed" | b"unable") => 1,
        Some(b"pending" | b"ready") => 2,
        Some(b"done") => 3,
        Some(_) => 4,
    }
}

fn render_upg_status(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let ru = rep.r.iter().rfind(|x| x.is("rollup"));
    let dot = glyph(ctx, G_DOT);
    let arrow = glyph(ctx, G_ARROW);
    let plan = match ru {
        Some(ru) => {
            let v = match ru.rvs("hub_ver") {
                Some(hv) => cat(&[
                    b"bots ",
                    arrow,
                    b" ",
                    nul(ru.rv("bot_ver")),
                    b", hubs ",
                    arrow,
                    b" ",
                    hv,
                ]),
                None => cat(&[b"bots ", arrow, b" ", ru.rv("bot_ver").unwrap_or(b"?")]),
            };
            snp(160, v)
        }
        None => Vec::new(),
    };
    const L: i32 = 12;
    let Some(id) = r.rvs("id") else {
        title(ctx, out, b"Upgrades", Some(b"no run on this hub"));
        if let Some(ru) = ru {
            let a = when(ru.rvi("set", 0), ctx.now);
            let b = span(ctx.now.wrapping_sub(ru.rvi("set", 0)));
            let v = cat(&[&plan, b"  (set ", &a, b" ", dot, b" ", &b, b" ago)"]);
            card(out, L, "roll-up plan", &snp(512, v), RL_NORMAL);
        } else {
            card(out, L, "roll-up plan", b"none", RL_NORMAL);
        }
        if r.rvb("frozen") {
            warn(
                ctx,
                out,
                b"config is frozen: clear option flag F to lift it",
            );
        }
        hint(out, b"upgrade releases lists what can be installed");
        return;
    };
    let t = snp(96, cat(&[b"Upgrade ", id]));
    let right = match r.rvs("hub_ver") {
        Some(hv) => cat(&[
            b"bots ",
            arrow,
            b" ",
            nul(r.rv("bot_ver")),
            b" ",
            dot,
            b" hubs ",
            arrow,
            b" ",
            hv,
            b" ",
            dot,
            b" ",
            r.rv("phase").unwrap_or(b"?"),
        ]),
        None => cat(&[
            b"bots ",
            arrow,
            b" ",
            r.rv("bot_ver").unwrap_or(b"?"),
            b" ",
            dot,
            b" ",
            r.rv("phase").unwrap_or(b"?"),
        ]),
    };
    title(ctx, out, &t, Some(&snp(160, right)));
    let a = when(r.rvi("started", 0), ctx.now);
    let b = span(ctx.now.wrapping_sub(r.rvi("started", 0)));
    card(
        out,
        L,
        "started",
        &cat(&[&a, b" ", dot, b" ", &b, b" ago"]),
        RL_NORMAL,
    );
    let sel = r.rvi("selective", 0);
    let v = if sel > 0 {
        cat(&[&num(sel), b" node", pl(sel), b" named"])
    } else {
        b"no (whole network)".to_vec()
    };
    card(out, L, "selective", &v, RL_NORMAL);
    let (mut done, mut failed, mut waiting, mut total) = (0i32, 0i32, 0i32, 0i32);
    for n in rep.r.iter().filter(|x| x.is("node")) {
        let k = node_rank(n.rv("state"));
        if k == 4 {
            continue;
        }
        total += 1;
        if k == 3 {
            done += 1;
        } else if k == 1 {
            failed += 1;
        } else {
            waiting += 1;
        }
    }
    let mut sb = Sb::default();
    let bar = 24;
    let fill = if total != 0 { done * bar / total } else { 0 };
    sb.rep(glyph(ctx, G_FULL), fill);
    sb.rep(glyph(ctx, G_EMPTY), bar - fill);
    sb.a(&cat(&[
        b"  ",
        &num(done),
        b" / ",
        &num(total),
        b" done ",
        dot,
        b" ",
        &num(failed),
        b" failed ",
        dot,
        b" ",
        &num(waiting),
        b" waiting",
    ]));
    card(out, L, "progress", &sb.p, RL_NORMAL);
    if ru.is_some() {
        card(out, L, "roll-up", &plan, RL_NORMAL);
    }
    if let Some(sm) = r.rvs("summary") {
        card(out, L, "summary", sm, RL_NORMAL);
    }
    if r.rvb("frozen") {
        card(out, L, "frozen", b"yes (until the run ends)", RL_WARN);
    }
    const COLS: [Col; 8] = [
        col("KIND", b'L', 1),
        col("NODE", b'L', 1),
        col("STATE", b'L', 1),
        col("FROM", b'L', 1),
        col("TO", b'L', 1),
        col("CODE", b'L', 2),
        col("UUID", b'L', 2),
        col("NOTE", b'L', 2),
    ];
    let mut t = Tbl::new(&COLS, -1, 1, 1);
    for rank in 0..=4 {
        for n in rep.r.iter() {
            if !n.is("node") || node_rank(n.rv("state")) != rank {
                continue;
            }
            let code = match n.rvs("want") {
                Some(w) => cat(&[n.rvs("base").unwrap_or(b"?"), b" ", arrow, b" ", w]),
                None => n.rvs("base").unwrap_or(b"").to_vec(),
            };
            let code = snp(32, code);
            let cells = [
                n.rv("kind"),
                n.rvs("name").or_else(|| n.rv("uuid")),
                n.rv("state"),
                n.rv("from"),
                n.rv("to"),
                Some(code.as_slice()),
                n.rv("uuid"),
                n.rv("reason"),
            ];
            let role = if rank == 1 {
                RL_WARN
            } else if rank == 4 {
                RL_DIM
            } else {
                RL_NORMAL
            };
            t.row(ctx, role, n.rv("state"), &cells);
        }
    }
    if t.nr() > 0 {
        flines_add(out, RL_NORMAL, b"");
        t.render(ctx, out);
    }
}

fn render_upg_releases(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    for prod in 0..2 {
        let p: &[u8] = if prod == 0 { b"bot" } else { b"hub" };
        let base = rep.res.rv(if prod == 0 { "bot_base" } else { "hub_base" });
        let right: &[u8] = match base {
            Some(b) if !b.is_empty() => b,
            _ if prod == 0 => b"ircbot-releases (default base)",
            _ => b"this hub's release base",
        };
        title(
            ctx,
            out,
            if prod == 0 {
                b"Bot releases"
            } else {
                b"Hub releases"
            },
            Some(right),
        );
        const COLS: [Col; 4] = [
            col("VERSION", b'L', 1),
            col("DATE", b'L', 1),
            col("CODE", b'L', 1),
            col("NODES ON IT", b'R', 1),
        ];
        let mut t = Tbl::new(&COLS, -1, 0, 0);
        for r in &rep.r {
            if !r.is("rel") || r.rv("product") != Some(p) {
                continue;
            }
            let mut on = 0;
            for nd in &rep.r {
                let (Some(nv), Some(rvv)) = (nd.rv("ver"), r.rv("ver")) else {
                    continue;
                };
                if !nd.is("node") || nv != rvv {
                    continue;
                }
                let kind = nd.rv("kind").unwrap_or(b"");
                if (prod == 0) == (kind == b"bot") {
                    on += 1;
                }
            }
            let bases = snp(32, r.rv("bases").unwrap_or(b"").to_vec());
            let mut bb = Sb::default();
            for &q in &bases {
                if q == b',' {
                    bb.a(b", ");
                } else {
                    bb.a(&[q]);
                }
            }
            let cnt = num(on);
            let cells = [
                r.rv("ver"),
                r.rv("date"),
                Some(bb.opt().unwrap_or(b"")),
                Some(if on != 0 { cnt.as_slice() } else { b"" }),
            ];
            t.row(ctx, RL_NORMAL, None, &cells);
        }
        if t.nr() > 0 {
            t.render(ctx, out);
        } else {
            line(out, RL_DIM, &[b"  (no releases listed)"]);
        }
        for r in &rep.r {
            if !r.is("relerr") || r.rv("product") != Some(p) {
                continue;
            }
            line(
                out,
                RL_WARN,
                &[
                    b"   ",
                    glyph(ctx, G_WARN),
                    b" ",
                    r.rv("base").unwrap_or(b"?"),
                    b" tree unreadable: ",
                    r.rv("msg").unwrap_or(b"?"),
                ],
            );
        }
    }
    flines_add(out, RL_NORMAL, b"");
    let (mut hubs, mut bots) = (0i64, 0i64);
    for r in rep.r.iter().filter(|r| r.is("node")) {
        if r.rv("kind") == Some(b"bot") {
            bots += 1;
        } else {
            hubs += 1;
        }
    }
    let right = cat(&[
        &num(hubs),
        b" hub",
        pl(hubs),
        b" ",
        glyph(ctx, G_DOT),
        b" ",
        &num(bots),
        b" bot",
        pl(bots),
        b" online",
    ]);
    title(ctx, out, b"Nodes", Some(&right));
    const NCOLS: [Col; 5] = [
        col("KIND", b'L', 1),
        col("NAME", b'L', 1),
        col("VERSION", b'L', 1),
        col("CODE", b'L', 1),
        col("UUID", b'L', 2),
    ];
    let mut t = Tbl::new(&NCOLS, -1, 1, 1);
    // self, then hubs, then bots, each by name (rule 4)
    let nodes = collect(rep, "node", "name", None);
    for pass in 0..3 {
        for sr in &nodes {
            let r = sr.r;
            let kind = r.rv("kind").unwrap_or(b"");
            let want = if kind == b"self" {
                0
            } else if kind == b"hub" {
                1
            } else {
                2
            };
            if want != pass {
                continue;
            }
            let cells = [
                Some(kind),
                r.rvs("name").or_else(|| r.rv("uuid")),
                r.rv("ver"),
                r.rv("base"),
                r.rv("uuid"),
            ];
            t.row(ctx, RL_NORMAL, Some(kind), &cells);
        }
    }
    t.render(ctx, out);
    line(
        out,
        RL_DIM,
        &[b"  start a run: upgrade start <botver> [hub=<ver>] [nodes=<a,b=c>]"],
    );
}

fn render_upg_change(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let arrow = glyph(ctx, G_ARROW);
    if rep.code == b"upg.started" {
        let what = snp(
            128,
            cat(&[b"Upgrade ", r.rv("id").unwrap_or(b"?"), b" started"]),
        );
        let subj = match r.rvs("hub_ver") {
            Some(hv) => cat(&[
                b"bots ",
                arrow,
                b" ",
                nul(r.rv("bot_ver")),
                b" ",
                glyph(ctx, G_DOT),
                b" hubs ",
                arrow,
                b" ",
                hv,
            ]),
            None => cat(&[b"bots ", arrow, b" ", r.rv("bot_ver").unwrap_or(b"?")]),
        };
        ok(ctx, &what, Some(&snp(160, subj)), out);
        let sel = r.rvi("selected", 0);
        let ph = if sel > 0 {
            cat(&[
                &num(sel),
                b" selected node",
                pl(sel),
                b"; progress: upgrade status, or Alt+4",
            ])
        } else {
            let (b, p) = (r.rvi("bots", 0), r.rvi("peers", 0));
            cat(&[
                &num(b),
                b" bot",
                pl(b),
                b" and ",
                &num(p),
                b" peer hub",
                pl(p),
                b" asked to prepare, this hub last; progress: upgrade status, or Alt+4",
            ])
        };
        effect(ctx, out, &snp(160, ph));
        effect(ctx, out, b"the config is frozen until it finishes");
    } else if rep.code == b"upg.aborted" {
        let what = snp(
            128,
            cat(&[b"Upgrade ", r.rv("id").unwrap_or(b"?"), b" aborted"]),
        );
        let n = r.rvi("rolled_back", 0);
        let subj = cat(&[b"rolling back ", &num(n), b" upgraded node", pl(n)]);
        ok(ctx, &what, Some(&subj), out);
    } else {
        let peers = r.rvi("peers", 0);
        let ph = cat(&[
            b"told ",
            &num(peers),
            b" peer hub",
            pl(peers),
            b" to drop theirs",
        ]);
        if r.rvb("had") {
            let subj = cat(&[b"bots ", arrow, b" ", r.rv("bot_ver").unwrap_or(b"?")]);
            ok(ctx, b"Roll-up plan forgotten", Some(&snp(160, subj)), out);
        } else {
            ok(ctx, b"No roll-up plan on this hub", None, out);
        }
        effect(ctx, out, &ph);
    }
}

// ===========================================================================
// Network (tree rows: H|depth|name|uuid|online|0|ver|var|started,
// B|depth|nick|uuid|ver|server|0|var|started, D|nick|uuid|last_seen)
// ===========================================================================
fn pos(r: &Crec, i: usize) -> &[u8] {
    match r.rv(&i.to_string()) {
        Some(v) if v != b"-" => v,
        _ => b"",
    }
}

fn render_network_tree(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let hubs = rep.r.iter().filter(|r| r.is("H")).count() as i64;
    let on = rep.r.iter().filter(|r| r.is("B")).count();
    let off = rep.r.iter().filter(|r| r.is("D")).count();
    let dot = glyph(ctx, G_DOT);
    let right = cat(&[
        &num(hubs),
        b" hub",
        pl(hubs),
        b" ",
        dot,
        b" ",
        &num(on),
        b" bots online ",
        dot,
        b" ",
        &num(off),
        b" offline",
    ]);
    title(ctx, out, b"Network", Some(&right));
    const COLS: [Col; 6] = [
        col("NODE", b'L', 1),
        col("VERSION", b'L', 1),
        col("CODE", b'L', 1),
        col("UPTIME", b'L', 1),
        col("SERVER", b'L', 1),
        col("UUID", b'L', 2),
    ];
    let mut t = Tbl::new(&COLS, -1, 0, 1);
    for i in 0..rep.r.len() {
        let r = &rep.r[i];
        let h = r.is("H");
        let b = r.is("B");
        if !h && !b {
            continue;
        }
        let depth = atoi(pos(r, 0)).clamp(0, 8);
        let mut n = Sb::default();
        n.rep(b"  ", depth);
        if h {
            let up = pos(r, 3).first() == Some(&b'1');
            n.a(&cat(&[
                glyph(ctx, if up { G_OPEN } else { G_ERR }),
                b" ",
                pos(r, 1),
            ]));
            if depth == 0 {
                n.a(b"  (this hub)");
            } else if !up {
                n.a(b"  (down)");
            }
        } else {
            let mut last = true;
            for x in &rep.r[i + 1..] {
                if x.is("B") && atoi(pos(x, 0)) == depth {
                    last = false;
                    break;
                }
                if !x.is("B") || atoi(pos(x, 0)) < depth {
                    break;
                }
            }
            n.a(&cat(&[
                glyph(ctx, if last { G_TEND } else { G_TMID }),
                b" ",
                pos(r, 1),
            ]));
        }
        let st = atoll(pos(r, 7));
        let down = h && pos(r, 3).first() != Some(&b'1');
        let up = snp(24, span_since(ctx, if down { 0 } else { st }));
        let cells = [
            Some(n.p.as_slice()),
            Some(if h { pos(r, 5) } else { pos(r, 3) }),
            Some(pos(r, 6)),
            Some(&up),
            Some(if b { pos(r, 4) } else { b"" }),
            Some(pos(r, 2)),
        ];
        t.row(ctx, if h { RL_HEAD } else { RL_NORMAL }, None, &cells);
    }
    t.render(ctx, out);
    if off == 0 {
        return;
    }
    const DCOLS: [Col; 3] = [
        col("NOT CONNECTED", b'L', 1),
        col("LAST SEEN", b'L', 1),
        col("UUID", b'L', 2),
    ];
    let mut d = Tbl::new(&DCOLS, -1, 0, 0);
    for r in rep.r.iter().filter(|r| r.is("D")) {
        let nm = snp(96, cat(&[glyph(ctx, G_OFF), b" ", pos(r, 0)]));
        let seen = when_ago(ctx, atoll(pos(r, 2)), 64);
        let cells = [Some(nm.as_slice()), Some(&seen), Some(pos(r, 1))];
        d.row(ctx, RL_DIM, None, &cells);
    }
    d.render(ctx, out);
}

fn render_network_status(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let right = snp(96, cat(&[b"seen from ", r.rv("name").unwrap_or(b"?")]));
    title(ctx, out, b"Network status", Some(&right));
    const L: i32 = 8;
    let v = snp(96, cat(&[r.rv("peers").unwrap_or(b"?"), b" up"]));
    card(out, L, "peers", &v, RL_NORMAL);
    let v = snp(96, cat(&[r.rv("bots").unwrap_or(b"?"), b" online"]));
    card(out, L, "bots", &v, RL_NORMAL);
    let upg = r.rv("upg");
    let run = matches!(upg, Some(u) if u != b"-" && !u.is_empty());
    card(
        out,
        L,
        "upgrade",
        if run {
            upg.unwrap_or(b"")
        } else {
            glyph(ctx, G_DASH)
        },
        if run { RL_WARN } else { RL_NORMAL },
    );
    let fz = r.rvb("frozen");
    card(
        out,
        L,
        "frozen",
        if fz { b"yes" } else { b"no" },
        if fz { RL_WARN } else { RL_NORMAL },
    );
    card(
        out,
        L,
        "roll-up",
        if r.rvb("rollup") { b"yes" } else { b"no" },
        RL_NORMAL,
    );
    let sp = r.rvb("split");
    card(
        out,
        L,
        "split",
        if sp {
            b"yes (a hub is unreachable)"
        } else {
            b"no (the mesh is one piece)"
        },
        if sp { RL_WARN } else { RL_NORMAL },
    );
    let v = cat(&[
        b"file ",
        level_name(r.rvi("loglevel", 0)),
        b" ",
        glyph(ctx, G_DOT),
        b" console ",
        level_name(r.rvi("consolelevel", 0)),
    ]);
    card(out, L, "log", &v, RL_NORMAL);
}

// ===========================================================================
// Results of bot / peer changes
// ===========================================================================
fn render_bot_change(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let code = rep.code.as_slice();
    let uuid = r.rv("uuid").unwrap_or(b"?");
    let ph = snp(256, peers_phrase(r.rvi("peers", 0)));
    if code == b"bot.approved" {
        let subj = match r.rvs("ip") {
            Some(ip) => cat(&[
                uuid,
                b"  (was pending #",
                &num(r.rvi("n", 0)),
                b", from ",
                ip,
                b")",
            ]),
            None => uuid.to_vec(),
        };
        ok(ctx, b"Bot approved", Some(&snp(256, subj)), out);
        let p2 = snp(300, cat(&[b"authorization ", &ph]));
        effect(ctx, out, if r.rvi("peers", 0) > 0 { &p2 } else { &ph });
        effect(
            ctx,
            out,
            b"the bot is let in on its next connection attempt",
        );
    } else if code == b"bot.authorized" {
        ok(ctx, b"Bot authorized", Some(uuid), out);
        effect(ctx, out, &ph);
        if !r.rvb("registered") {
            effect(
                ctx,
                out,
                b"not yet registered: it still needs bot add, or it registers itself on first connect",
            );
        }
    } else if code == b"bot.added" {
        let subj = cat(&[r.rv("nick").unwrap_or(b"?"), b"  ", uuid]);
        ok(ctx, b"Bot registered", Some(&snp(256, subj)), out);
        res_kv(out, "key", r.rvs("fp").unwrap_or(b"?"));
        effect(
            ctx,
            out,
            b"saved to this hub's config; peers learn it on the next sync",
        );
        res_kv(
            out,
            "next",
            b"start the bot; it shows up in bot list when it connects",
        );
    } else if code == b"bot.deleted" {
        let subj = match r.rvs("nick") {
            Some(n) => cat(&[n, b"  ", uuid]),
            None => uuid.to_vec(),
        };
        ok(ctx, b"Bot deleted", Some(&snp(256, subj)), out);
        if r.rvb("was_online") {
            effect(ctx, out, b"disconnected from this hub");
        }
        let (peers, bots) = (r.rvi("peers", 0), r.rvi("bots", 0));
        let ph = cat(&[
            b"tombstone synced to ",
            &num(peers),
            b" peer hub",
            pl(peers),
            b"; ",
            &num(bots),
            b" bot",
            pl(bots),
            b" told to drop it from their trusted list",
        ]);
        effect(ctx, out, &snp(256, ph));
        let d = r.rvi("purge_days", 0);
        let ph = if d > 0 {
            cat(&[
                b"the tombstone is kept ",
                &num(d),
                b" days (hub set autopurge), then purged",
            ])
        } else {
            b"the tombstone stays until hub purge (autopurge is off)".to_vec()
        };
        effect(ctx, out, &ph);
    } else if code == b"bot.kicked" {
        let sp = snp(32, span(ctx.now.wrapping_sub(r.rvi("since", ctx.now))));
        let subj = cat(&[
            r.rv("nick").unwrap_or(b"?"),
            b"  ",
            uuid,
            b"  (was connected ",
            &sp,
            b" from ",
            r.rv("ip").unwrap_or(b"?"),
            b")",
        ]);
        ok(ctx, b"Bot disconnected", Some(&snp(256, subj)), out);
        effect(
            ctx,
            out,
            b"it reconnects by itself; use bot del to remove it for good",
        );
    } else if code == b"bot.rekey_howto" {
        let nick = r.rvs("nick").unwrap_or(uuid);
        let on = r.rvb("online");
        let t = snp(96, cat(&[b"Rekey bot ", nick]));
        let right = snp(
            48,
            cat(&[
                glyph(ctx, if on { G_ON } else { G_OFF }),
                b" ",
                if on { b"online" } else { b"offline" },
            ]),
        );
        title(ctx, out, &t, Some(&right));
        line(
            out,
            RL_NORMAL,
            &[b"  Only the bot holds its private key, so the rekey runs on the bot:"],
        );
        if !on {
            let ph = cat(&[
                nick,
                b" is offline ",
                glyph(ctx, G_DASH),
                b" wait until it reconnects",
            ]);
            warn(ctx, out, &snp(256, ph));
        }
        line(
            out,
            RL_NORMAL,
            &[
                b"   1. in your IRC client, send ",
                nick,
                b" the sealed command:  rekey",
            ],
        );
        line(
            out,
            RL_NORMAL,
            &[b"   2. the bot makes a new key pair, sends its new public key here and reconnects"],
        );
        line(
            out,
            RL_NORMAL,
            &[
                b"   3. peers pick up the new key with the next sync ",
                glyph(ctx, G_DASH),
                b" nothing else to do",
            ],
        );
        card(
            out,
            12,
            "current key",
            r.rvs("fp").unwrap_or(b"(no key)"),
            RL_NORMAL,
        );
    }
}

fn render_peer_change(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let r = &rep.res;
    let addr = addr_of(r, 96);
    if rep.code == b"peer.added" {
        let subj = cat(&[
            peer_name(r),
            b"  ",
            &addr,
            b"  (#",
            &num(r.rvi("n", 0)),
            b")",
        ]);
        ok(ctx, b"Peer added", Some(&snp(256, subj)), out);
        res_kv(out, "uuid", r.rvs("uuid").unwrap_or(glyph(ctx, G_DASH)));
        res_kv(out, "key", r.rvs("fp").unwrap_or(b"?"));
        let subj = cat(&[
            b"this hub dials it now; peer list shows the link once ",
            peer_name(r),
            b" has added this hub too",
        ]);
        effect(ctx, out, &snp(256, subj));
    } else if rep.code == b"peer.removed" {
        let subj = cat(&[peer_name(r), b"  ", &addr]);
        ok(ctx, b"Peer removed", Some(&snp(256, subj)), out);
        effect(
            ctx,
            out,
            if r.rvb("was_up") {
                b"link closed"
            } else {
                b"it was down; there was no link to close"
            },
        );
        effect(
            ctx,
            out,
            b"bots and peers it carried reach the mesh through the other hubs",
        );
    } else if rep.code == b"peer.set" {
        let what = snp(96, cat(&[b"Peer ", peer_name(r)]));
        let subj = cat(&[
            r.rv("setting").unwrap_or(b"?"),
            b"   ",
            r.rvs("old").unwrap_or(b"(none)"),
            b" ",
            glyph(ctx, G_ARROW),
            b" ",
            r.rvs("value").unwrap_or(b"?"),
        ]);
        ok(ctx, &what, Some(&snp(256, subj)), out);
        effect(
            ctx,
            out,
            if r.rvb("relinked") {
                b"the link was dropped and comes back with the new key"
            } else {
                b"the next connection uses the new key"
            },
        );
    } else {
        let peers = r.rvi("peers", 0);
        let mut names = Sb::default();
        let mut skipped = Sb::default();
        for p in rep.r.iter().filter(|p| p.is("peer")) {
            let b = if p.rvb("sent") {
                &mut names
            } else {
                &mut skipped
            };
            if !b.p.is_empty() {
                b.a(b", ");
            }
            b.a(peer_name(p));
        }
        let what = snp(
            96,
            cat(&[b"Full sync sent to ", &num(peers), b" peer hub", pl(peers)]),
        );
        ok(ctx, &what, names.opt(), out);
        let sz = bytes(r.rvi("bytes", 0) as u64);
        let c = count(r.rvi("records", 0) as u64);
        effect(
            ctx,
            out,
            &cat(&[&c, b" records ", glyph(ctx, G_DOT), b" ", &sz]),
        );
        if !skipped.p.is_empty() {
            let many = skipped.p.contains(&b',');
            let subj = cat(&[
                &skipped.p,
                b" ",
                if many { b"are" } else { b"is" },
                b" down and ",
                if many { b"were" } else { b"was" },
                b" skipped",
            ]);
            warn(ctx, out, &snp(256, subj));
        }
    }
}

// ===========================================================================
// Wrapping: no line past the width (§3.5 acceptance).  Lines break at blanks
// only, so a key, a uuid or any other unbroken token stays whole (D10) even
// where it is wider than the view.  A continuation lines up with the value
// column of a "label   value" line, else just past a leading glyph.
// ===========================================================================
fn wrap_indent(t: &[u8], ww: i32) -> i32 {
    let n = t.len();
    let mut lead = 0;
    while lead < n && t[lead] == b' ' {
        lead += 1;
    }
    let mut e = lead;
    while e < n && t[e] != b' ' {
        e += 1;
    }
    let mut sp = e;
    while sp < n && t[sp] == b' ' {
        sp += 1;
    }
    let mut ind = if sp - e >= 2 && sp < n {
        width_n(&t[..sp])
    } else {
        lead as i32 + 2
    };
    if ind > ww / 2 {
        ind = lead as i32 + 2;
    }
    ind
}

/// Break lines wider than `ww` at blanks (tokens stay whole).
pub fn wrap(f: &mut Flines, ww: i32) {
    let mut o: Flines = Vec::with_capacity(f.len());
    let mut cur = Sb::default();
    for fl in f.iter() {
        let t = fl.text.as_slice();
        let role = fl.role;
        // a command line (an echo, a help example) stays whole: the terminal
        // wraps it visually and a copy runs as typed
        if ww <= 0 || role == RL_CMD || str_width(t) <= ww {
            flines_add(&mut o, role, t);
            continue;
        }
        let ind = wrap_indent(t, ww);
        let n = t.len();
        let mut i = 0;
        let mut word = false; // the current line has a word on it
        cur.reset();
        while i < n {
            let s0 = i;
            while i < n && t[i] == b' ' {
                i += 1;
            }
            let w0 = i;
            while i < n && t[i] != b' ' {
                i += 1;
            }
            if w0 == i {
                break; // trailing blanks
            }
            let sw = (w0 - s0) as i32;
            let wwid = width_n(&t[w0..i]);
            // a token no continuation could hold either (a key) stays where
            // it is: the terminal wraps it visually, the copy stays one line
            if !word || cur.w + sw + wwid <= ww || wwid > ww - ind {
                cur.addn(&t[s0..w0]);
            } else {
                cur.emit(&mut o, role);
                cur.rep(b" ", ind);
            }
            cur.addn(&t[w0..i]);
            word = true;
        }
        cur.emit(&mut o, role);
    }
    *f = o;
}

// ===========================================================================
// Dispatch
// ===========================================================================
fn render_generic(ctx: &Ctx, rep: &Creply, out: &mut Flines) {
    let code: &[u8] = if rep.code.is_empty() {
        b"done"
    } else {
        &rep.code
    };
    ok(ctx, code, None, out);
    unknown_keys(ctx, out, &rep.res, &[], 12);
    for r in &rep.r {
        if r.k.is_empty() {
            line(out, RL_NORMAL, &[b"  ", &r.line]);
            continue;
        }
        line(out, RL_HEAD, &[b"  ", &r.typ]);
        unknown_keys(ctx, out, r, &[], 12);
    }
}

/// Render a parsed reply.  `words` is the command ("bot list").
pub fn reply(ctx: &Ctx, rep: &Creply, _words: &[u8], out: &mut Flines) {
    let c = rep.code.as_slice();
    if rep.err {
        error(ctx, rep.res.rv("msg"), rep.res.rv("hint"), out);
        if c == b"bot.ambiguous" {
            const COLS: [Col; 3] = [
                col("UUID", b'L', 1),
                col("NICK", b'L', 1),
                col("STATE", b'L', 1),
            ];
            let mut t = Tbl::new(&COLS, -1, 0, 0);
            t.indent = 3;
            for r in rep.r.iter().filter(|r| r.is("bot")) {
                let st: &[u8] = if r.rvb("online") {
                    b"online"
                } else {
                    b"offline"
                };
                let cells = [r.rv("uuid"), r.rv("nick"), Some(st)];
                t.row(ctx, RL_NORMAL, None, &cells);
            }
            t.render(ctx, out);
        }
        wrap(out, ctx.width);
        return;
    }
    if !rep.ok {
        // not a record reply: show it as it came
        for r in &rep.r {
            flines_add(out, RL_NORMAL, &r.line);
        }
        return;
    }
    let has = |p: &[u8]| c.starts_with(p);
    if ctx.mode == FMT_MODE_HUB_SETTINGS && c == b"hub.show" {
        render_hub_settings(ctx, &rep.res, out);
    } else if c == b"bot.list" {
        render_bot_list(ctx, rep, out);
    } else if c == b"bot.show" {
        render_bot_show(ctx, rep, out);
    } else if c == b"bot.summary" {
        render_bot_summary(ctx, rep, out);
    } else if c == b"bot.pending" {
        render_bot_pending(ctx, rep, out);
    } else if has(b"bot.") {
        render_bot_change(ctx, rep, out);
    } else if c == b"peer.list" {
        render_peer_list(ctx, rep, out);
    } else if c == b"peer.show" {
        render_peer_show(ctx, rep, out);
    } else if has(b"peer.") || c == b"mesh.synced" {
        render_peer_change(ctx, rep, out);
    } else if c == b"hub.show" {
        render_hub_show(ctx, &rep.res, out);
    } else if c == b"hub.set" {
        render_hub_set(ctx, rep, out);
    } else if c == b"hub.rekeyed" {
        render_hub_rekeyed(ctx, rep, out);
    } else if c == b"tomb.purged" {
        render_tomb_purged(ctx, rep, out);
    } else if c == b"stats" {
        render_stats(ctx, rep, out);
    } else if c == b"log.show" {
        render_log_show(ctx, rep, out);
    } else if c == b"log.set" {
        render_log_set(ctx, rep, out);
    } else if c == b"acl.list" {
        render_acl_list(ctx, rep, out);
    } else if c == b"acl.added" || c == b"acl.removed" {
        render_acl_change(ctx, rep, out);
    } else if c == b"option.list" {
        render_option_list(ctx, rep, out);
    } else if c == b"option.set" {
        render_option_set(ctx, rep, out);
    } else if c == b"user.list" {
        render_user_list(ctx, rep, out);
    } else if c == b"user.show" {
        render_user_show(ctx, rep, out);
    } else if has(b"user.") {
        render_user_change(ctx, rep, out);
    } else if c == b"channel.list" {
        render_channel_list(ctx, rep, out);
    } else if c == b"channel.show" {
        render_channel_show(ctx, rep, out);
    } else if has(b"channel.") {
        render_channel_change(ctx, rep, out);
    } else if c == b"upg.status" {
        render_upg_status(ctx, rep, out);
    } else if c == b"upg.releases" {
        render_upg_releases(ctx, rep, out);
    } else if has(b"upg.") {
        render_upg_change(ctx, rep, out);
    } else if c == b"network.tree" {
        render_network_tree(ctx, rep, out);
    } else if c == b"network.status" {
        render_network_status(ctx, rep, out);
    } else {
        render_generic(ctx, rep, out);
    }
    wrap(out, ctx.width);
}
