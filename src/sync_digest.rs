//! Hash-first hub anti-entropy (CMD_SYNC_DIGEST 0x94), 2.5.4: sync_digest.c
//! in the C hub, rule for rule.  Spec and reference model:
//! ircbot-testnet/proto/syncdigest/model.py, whose vectors the testnet checks
//! this file and the C one against.
//!
//! A record kind is a line's first field (the bytes before its first '|', the
//! whole line when it has none).  Before hashing, a line's max-merged
//! activity field is blanked: field 5 of a|/o| (last_seen), field 4 of m|
//! (last_used).  A kind's normalised lines are sorted bytewise and hashed each
//! followed by '\n'.  Digest: `v|1\n`, then `s|<kind>|<count>|<hex>\n` per
//! kind, kinds sorted bytewise.

use sha2::{Digest, Sha256};

pub const SDG_KIND_MAX: usize = 15;
pub const SDG_KINDS_MAX: usize = 48;
pub const SDG_HEX: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: Vec<u8>,
    pub count: u64,
    pub hex: Vec<u8>,
}

fn kind_of(l: &[u8]) -> &[u8] {
    match l.iter().position(|&c| c == b'|') {
        Some(i) => &l[..i],
        None => l,
    }
}

fn blank_field(kind: &[u8]) -> Option<usize> {
    match kind {
        b"a" | b"o" => Some(5),
        b"m" => Some(4),
        _ => None,
    }
}

/// The line with field `blank` emptied.
fn norm(l: &[u8], blank: Option<usize>) -> Vec<u8> {
    let mut o = Vec::with_capacity(l.len());
    let mut field = 0;
    for &c in l {
        if c == b'|' {
            field += 1;
            o.push(c);
        } else if Some(field) != blank {
            o.push(c);
        }
    }
    o
}

/// The packet's non-empty lines (a last one without '\n' included).
fn lines(packet: &[u8]) -> impl Iterator<Item = &[u8]> {
    packet.split(|&c| c == b'\n').filter(|l| !l.is_empty())
}

/// sdg_digest(): the digest of `packet`, or None (a kind over SDG_KIND_MAX
/// bytes, or more than SDG_KINDS_MAX kinds).
pub fn digest(packet: &[u8]) -> Option<Vec<u8>> {
    let mut ls: Vec<(Vec<u8>, usize)> = Vec::new();
    for l in lines(packet) {
        let k = kind_of(l);
        if k.len() > SDG_KIND_MAX {
            return None;
        }
        ls.push((norm(l, blank_field(k)), k.len()));
    }
    // (kind, line) order: the kind is the normalised line's first field.
    ls.sort_by(|a, b| a.0[..a.1].cmp(&b.0[..b.1]).then_with(|| a.0.cmp(&b.0)));
    let mut out = b"v|1\n".to_vec();
    let mut kinds = 0;
    let mut i = 0;
    while i < ls.len() {
        let k = &ls[i].0[..ls[i].1];
        let mut h = Sha256::new();
        let mut e = i;
        while e < ls.len() && &ls[e].0[..ls[e].1] == k {
            h.update(&ls[e].0);
            h.update(b"\n");
            e += 1;
        }
        kinds += 1;
        if kinds > SDG_KINDS_MAX {
            return None;
        }
        out.extend_from_slice(b"s|");
        out.extend_from_slice(k);
        out.extend_from_slice(format!("|{}|", e - i).as_bytes());
        for b in h.finalize() {
            out.extend_from_slice(format!("{b:02x}").as_bytes());
        }
        out.push(b'\n');
        i = e;
    }
    Some(out)
}

/// A kind on the wire: 1..=SDG_KIND_MAX bytes, no '|', ',', '\n' or NUL.
fn kind_ok(k: &[u8]) -> bool {
    !k.is_empty()
        && k.len() <= SDG_KIND_MAX
        && !k.iter().any(|&c| matches!(c, b'|' | b',' | b'\n' | 0))
}

fn hex_ok(h: &[u8]) -> bool {
    h.len() == SDG_HEX && h.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// sdg_parse(): the entries (kinds strictly ascending), or None when malformed.
pub fn parse(p: &[u8]) -> Option<Vec<Entry>> {
    let rest = p.strip_prefix(b"v|1\n")?;
    let mut out: Vec<Entry> = Vec::new();
    let mut at = 0;
    while at < rest.len() {
        let nl = rest[at..].iter().position(|&c| c == b'\n')?;
        let s = &rest[at..at + nl];
        at += nl + 1;
        let body = s.strip_prefix(b"s|")?;
        let b1 = body.iter().position(|&c| c == b'|')?;
        let (k, tail) = (&body[..b1], &body[b1 + 1..]);
        let b2 = tail.iter().position(|&c| c == b'|')?;
        let (c, h) = (&tail[..b2], &tail[b2 + 1..]);
        if !kind_ok(k) || c.is_empty() || c.len() > 9 || !hex_ok(h) || out.len() >= SDG_KINDS_MAX {
            return None;
        }
        if !c.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let count = c.iter().fold(0u64, |n, &d| n * 10 + u64::from(d - b'0'));
        if out.last().is_some_and(|l| l.kind.as_slice() >= k) {
            return None; // strictly ascending
        }
        out.push(Entry {
            kind: k.to_vec(),
            count,
            hex: h.to_vec(),
        });
    }
    Some(out)
}

/// sdg_mismatch(): the kinds whose entry differs (count or hash, or present
/// on one side only), ascending, or None past SDG_KINDS_MAX.
pub fn mismatch(a: &[Entry], b: &[Entry]) -> Option<Vec<Vec<u8>>> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() || j < b.len() {
        let ord = if i >= a.len() {
            std::cmp::Ordering::Greater
        } else if j >= b.len() {
            std::cmp::Ordering::Less
        } else {
            a[i].kind.cmp(&b[j].kind)
        };
        let (k, differ) = match ord {
            std::cmp::Ordering::Less => {
                i += 1;
                (&a[i - 1].kind, true)
            }
            std::cmp::Ordering::Greater => {
                j += 1;
                (&b[j - 1].kind, true)
            }
            std::cmp::Ordering::Equal => {
                let d = a[i].count != b[j].count || a[i].hex != b[j].hex;
                i += 1;
                j += 1;
                (&a[i - 1].kind, d)
            }
        };
        if differ {
            if out.len() >= SDG_KINDS_MAX {
                return None;
            }
            out.push(k.clone());
        }
    }
    Some(out)
}

/// sdg_parse_pull(): `r|k1,k2\n` -> Some((kinds, false)); `r|*\n` ->
/// Some(([], true)); None when malformed.
pub fn parse_pull(p: &[u8]) -> Option<(Vec<Vec<u8>>, bool)> {
    if p.len() < 4 || !p.starts_with(b"r|") || p[p.len() - 1] != b'\n' {
        return None;
    }
    let s = &p[2..p.len() - 1];
    if s == b"*" {
        return Some((Vec::new(), true));
    }
    let mut out = Vec::new();
    for k in s.split(|&c| c == b',') {
        if !kind_ok(k) || out.len() >= SDG_KINDS_MAX {
            return None;
        }
        out.push(k.to_vec());
    }
    Some((out, false))
}

/// sdg_select(): the lines of `packet` whose kind is in `kinds` (every line
/// for `all`), unchanged, each ending '\n'.
pub fn select(packet: &[u8], kinds: &[Vec<u8>], all: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for l in lines(packet) {
        if all || kinds.iter().any(|k| k.as_slice() == kind_of(l)) {
            out.extend_from_slice(l);
            out.push(b'\n');
        }
    }
    out
}
