//! C library string semantics the protocol code depends on.
//!
//! The hub exchanges '|'-delimited records with C peers (irchub, ircbot).
//! Their parsers are strtok_r / sscanf / strtoll, so the helpers here
//! reproduce those rules exactly: which tokens a strtok_r walk yields, how
//! many conversions an sscanf field-width format makes, and where snprintf
//! into a fixed buffer cuts a string.
//!
//! Kept in step with ircbot.rs/src/cstr.rs — the two ports must agree on
//! every parse the shared wire format goes through.

use std::time::{SystemTime, UNIX_EPOCH};

/// time(NULL).
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// strcasecmp(a, b) == 0 (ASCII case folding, as in the "C" locale).
pub fn eq_ic(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// strncasecmp(s, prefix, strlen(prefix)) == 0.
pub fn starts_with_ic(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// What snprintf leaves in a `char[cap]`: at most cap-1 bytes, cut back to a
/// UTF-8 boundary so the result stays a valid str.
pub fn trunc(s: &str, cap: usize) -> &str {
    let max = cap.saturating_sub(1);
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Owned form of [`trunc`].
pub fn trunc_string(s: &str, cap: usize) -> String {
    trunc(s, cap).to_string()
}

/// The part of `s` before its first NUL -- what a C string handler sees.
pub fn until_nul(s: &str) -> &str {
    match s.find('\0') {
        Some(i) => &s[..i],
        None => s,
    }
}

/// [`until_nul`] over raw bytes: a decrypted frame is a C buffer the sender
/// NUL-terminated, and everything past that NUL is padding the C code never
/// looked at.
pub fn until_nul_bytes(b: &[u8]) -> &[u8] {
    match b.iter().position(|&c| c == 0) {
        Some(i) => &b[..i],
        None => b,
    }
}

fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// strtoll(s, &end, 10): leading white space, an optional sign, then digits.
/// Returns the value and the number of bytes consumed (0 when no digits were
/// found, like end == s).  Out-of-range values saturate, as glibc does.
pub fn strtoll(s: &str) -> (i64, usize) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_c_space(b[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: i64 = 0;
    let mut overflow = false;
    while i < b.len() && b[i].is_ascii_digit() {
        let d = i64::from(b[i] - b'0');
        if !overflow {
            match v.checked_mul(10).and_then(|x| {
                if neg {
                    x.checked_sub(d)
                } else {
                    x.checked_add(d)
                }
            }) {
                Some(x) => v = x,
                None => overflow = true,
            }
        }
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    if overflow {
        v = if neg { i64::MIN } else { i64::MAX };
    }
    (v, i)
}

/// atoll(s).
pub fn atoll(s: &str) -> i64 {
    strtoll(s).0
}

/// atoi(s) (the long long result narrowed like a C cast).
pub fn atoi(s: &str) -> i32 {
    strtoll(s).0 as i32
}

/// A strtok_r walk over one string.  `next(delims)` skips leading delimiters
/// and returns the next token; `next("")` returns everything left (the
/// `strtok_r(NULL, "", &save)` idiom), or None when nothing is left.
pub struct Tok<'a> {
    rest: &'a str,
}

impl<'a> Tok<'a> {
    pub fn new(s: &'a str) -> Self {
        Tok { rest: s }
    }

    pub fn next(&mut self, delims: &str) -> Option<&'a str> {
        let is_delim = |c: char| delims.contains(c);
        let s = self.rest.trim_start_matches(is_delim);
        if s.is_empty() {
            self.rest = s;
            return None;
        }
        match s.find(is_delim) {
            Some(i) => {
                let dl = s[i..].chars().next().map_or(1, char::len_utf8);
                self.rest = &s[i + dl..];
                Some(&s[..i])
            }
            None => {
                self.rest = &s[s.len()..];
                Some(s)
            }
        }
    }

    /// strtok_r(NULL, "", &save).
    pub fn rest(&mut self) -> Option<&'a str> {
        self.next("")
    }

    /// The save pointer: what the walk has not consumed yet.
    pub fn remaining(&self) -> &'a str {
        self.rest
    }
}

/// A cursor implementing the sscanf directives the protocol code uses.
/// Each method is one directive; it returns None (and the caller stops
/// counting) where sscanf would stop with a matching failure.
pub struct Scan<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Scan<'a> {
    pub fn new(s: &'a str) -> Self {
        Scan { s, pos: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    /// `%N[^set]`: one to N bytes, none of them in `excl`.
    pub fn set_not(&mut self, max: usize, excl: &[u8]) -> Option<&'a str> {
        let r = self.rest();
        let b = r.as_bytes();
        let mut n = 0;
        while n < b.len() && n < max && !excl.contains(&b[n]) {
            n += 1;
        }
        while n > 0 && !r.is_char_boundary(n) {
            n -= 1;
        }
        if n == 0 {
            return None;
        }
        self.pos += n;
        Some(&r[..n])
    }

    /// A literal byte in the format.
    pub fn lit(&mut self, c: u8) -> bool {
        if self.rest().as_bytes().first() == Some(&c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// `%lld` / `%d`.
    pub fn int(&mut self) -> Option<i64> {
        let (v, used) = strtoll(self.rest());
        if used == 0 {
            return None;
        }
        self.pos += used;
        Some(v)
    }

    /// `%Ns`: skip white space, then one to N non-space bytes.
    pub fn word(&mut self, max: usize) -> Option<&'a str> {
        let b = self.rest().as_bytes();
        let mut i = 0;
        while i < b.len() && is_c_space(b[i]) {
            i += 1;
        }
        self.pos += i;
        let r = self.rest();
        let b = r.as_bytes();
        let mut n = 0;
        while n < b.len() && n < max && !is_c_space(b[n]) {
            n += 1;
        }
        while n > 0 && !r.is_char_boundary(n) {
            n -= 1;
        }
        if n == 0 {
            return None;
        }
        self.pos += n;
        Some(&r[..n])
    }
}

/// One sscanf directive.
#[derive(Clone, Copy)]
pub enum Fmt {
    /// `%N[^set]`
    Set(usize, &'static [u8]),
    /// a literal
    Lit(&'static str),
    /// `%d` / `%lld`
    Int,
    /// `%Ns`
    Word(usize),
}

/// One successful conversion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conv<'a> {
    S(&'a str),
    I(i64),
}

impl<'a> Conv<'a> {
    pub fn s(self) -> &'a str {
        match self {
            Conv::S(s) => s,
            Conv::I(_) => "",
        }
    }

    pub fn i(self) -> i64 {
        match self {
            Conv::I(v) => v,
            Conv::S(_) => 0,
        }
    }
}

/// sscanf: the conversions made before the first failure, in order (the
/// return value of sscanf is their count).
pub fn sscanf<'a>(input: &'a str, fmt: &[Fmt]) -> Vec<Conv<'a>> {
    let mut sc = Scan::new(input);
    let mut out = Vec::new();
    for d in fmt {
        match *d {
            Fmt::Set(max, excl) => match sc.set_not(max, excl) {
                Some(s) => out.push(Conv::S(s)),
                None => break,
            },
            Fmt::Lit(l) => {
                if !l.bytes().all(|b| sc.lit(b)) {
                    break;
                }
            }
            Fmt::Int => match sc.int() {
                Some(v) => out.push(Conv::I(v)),
                None => break,
            },
            Fmt::Word(max) => match sc.word(max) {
                Some(s) => out.push(Conv::S(s)),
                None => break,
            },
        }
    }
    out
}

/// Split on '|' into at most `max` fields; a trailing '|' yields an empty
/// field (hub_config.c split_fields).
pub fn split_fields(s: &str, max: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while out.len() < max {
        match rest.find('|') {
            Some(i) => {
                out.push(&rest[..i]);
                rest = &rest[i + 1..];
            }
            None => {
                out.push(rest);
                break;
            }
        }
    }
    out
}

/// "8-4-4-4-12" hex UUID shape (hub_config.c is_uuid_field).
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Dashes in the UUID positions only (the looser check the `a|`/`o|`/`m|`
/// record paths use).
pub fn has_uuid_dashes(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36 && b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-'
}

/// Display columns of a UTF-8 string: continuation bytes do not advance.
pub fn display_width(s: &str) -> usize {
    s.chars().count()
}

/// Nick part of a mask (up to '!'), bounded to `cap`-1 bytes.
pub fn mask_nick(mask: &str, cap: usize) -> &str {
    let n = mask.find('!').unwrap_or(mask.len());
    trunc(&mask[..n], cap)
}

/// `%-*s`: left-justify in a field of `w` bytes.
pub fn pad_right(s: &str, w: usize) -> String {
    let mut out = String::from(s);
    while out.len() < w {
        out.push(' ');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strtok_matches_c() {
        let mut t = Tok::new("  a b  c");
        assert_eq!(t.next(" "), Some("a"));
        assert_eq!(t.next(" "), Some("b"));
        assert_eq!(t.rest(), Some(" c"));
        assert_eq!(t.next(" "), None);
        let mut t = Tok::new("uuid|7000|name|ip|ts|sig");
        assert_eq!(t.next("|"), Some("uuid"));
        assert_eq!(t.next("|"), Some("7000"));
        assert_eq!(t.rest(), Some("name|ip|ts|sig"));
    }

    #[test]
    fn scan_field_widths() {
        let mut s = Scan::new("#chan|key|add|123");
        assert_eq!(s.set_not(64, b"|"), Some("#chan"));
        assert!(s.lit(b'|'));
        assert_eq!(s.set_not(30, b"|"), Some("key"));
        assert!(s.lit(b'|'));
        assert_eq!(s.set_not(15, b"|"), Some("add"));
        assert!(s.lit(b'|'));
        assert_eq!(s.int(), Some(123));
        let mut s = Scan::new("||add");
        assert_eq!(s.set_not(64, b"|"), None);
    }

    #[test]
    fn strtoll_rules() {
        assert_eq!(strtoll("  -42x"), (-42, 5));
        assert_eq!(strtoll("abc"), (0, 0));
        assert_eq!(atoll("99999999999999999999"), i64::MAX);
        assert_eq!(atoi("7000"), 7000);
    }

    #[test]
    fn trunc_on_boundary() {
        assert_eq!(trunc("abcdef", 4), "abc");
        assert_eq!(trunc("ab\u{e9}", 4), "ab");
        assert_eq!(trunc("ab", 10), "ab");
    }
}
