//! Bot config text deltas (CMD_CONFIG_DELTA 0x91), 2.5.4: cfg_delta.c in the
//! C hub and bot, rule for rule.  Byte-identical in irchub.rs and ircbot.rs.
//! Spec and reference model: ircbot-testnet/proto/cfgdelta/model.py; the
//! testnet checks this file, the C one and the model against the same
//! vectors.
//!
//! Payload: `<base sha256 hex>|<new sha256 hex>\n`, then ops each ending
//! `\n`: `=<n>` keep the next n base lines, `-<n>` drop them, `+<text>` insert
//! one line.  A line is a run of bytes ending in `\n`; both texts must be
//! empty or end in `\n`; the ops must consume the base exactly.  Pure: the
//! caller checks the base hash before `patch` and the result hash after it,
//! and applies nothing unless both match.

use zeroize::Zeroizing;

pub const CFGD_HASH_HEX: usize = 64;
/// `"<64>|<64>\n"`.
pub const CFGD_HEADER_LEN: usize = CFGD_HASH_HEX * 2 + 2;
/// Longest line a delta may insert.
pub const CFG_DELTA_LINE_MAX: usize = 8192;
/// Myers D past which the hub sends a full push.
pub const CFG_DELTA_MAX_EDITS: usize = 256;
/// A delta >= this % of the full text: send it full.
pub const CFG_DELTA_MAX_PCT: usize = 50;

struct Line<'a> {
    b: &'a [u8],
    /// FNV-1a 64: a cheap first comparison.
    h: u64,
}

fn fnv(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in b {
        h ^= u64::from(c);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The lines of `t`, each keeping its `\n`; None when `t` is not empty and
/// does not end in `\n`.
fn split(t: &[u8]) -> Option<Vec<Line<'_>>> {
    if t.is_empty() {
        return Some(Vec::new());
    }
    if t[t.len() - 1] != b'\n' {
        return None;
    }
    Some(
        t.split_inclusive(|&c| c == b'\n')
            .map(|b| Line { b, h: fnv(b) })
            .collect(),
    )
}

fn eq(a: &Line<'_>, b: &Line<'_>) -> bool {
    a.h == b.h && a.b == b.b
}

/// Myers shortest edit script `a` -> `b` as b'K' / b'D' / b'I' per line, or
/// None past `dmax` edits.  Tie rule (model.py, both hubs): at diagonal k step
/// down (insert) when k == -d, or when k != d and V[k-1] < V[k+1]; else right
/// (delete).
fn myers(a: &[Line<'_>], b: &[Line<'_>], dmax: usize) -> Option<Vec<u8>> {
    let (n, m) = (a.len() as i64, b.len() as i64);
    let w = 2 * dmax + 3;
    let off = dmax as i64 + 1;
    let mut v = vec![0i64; w];
    let mut trace: Vec<i64> = Vec::new();
    let mut dend: Option<i64> = None;
    'outer: for d in 0..=dmax as i64 {
        trace.extend_from_slice(&v);
        let mut k = -d;
        while k <= d {
            let mut x =
                if k == -d || (k != d && v[(off + k - 1) as usize] < v[(off + k + 1) as usize]) {
                    v[(off + k + 1) as usize]
                } else {
                    v[(off + k - 1) as usize] + 1
                };
            let mut y = x - k;
            while x < n && y < m && eq(&a[x as usize], &b[y as usize]) {
                x += 1;
                y += 1;
            }
            v[(off + k) as usize] = x;
            if x >= n && y >= m {
                dend = Some(d);
                break 'outer;
            }
            k += 2;
        }
    }
    let dend = dend?;
    // Walk back: trace row d is V as it stood before step d.
    let mut ops = Vec::with_capacity((n + m) as usize);
    let (mut x, mut y) = (n, m);
    for dd in (0..=dend).rev() {
        let tv = &trace[dd as usize * w..(dd as usize + 1) * w];
        let k = x - y;
        let pk = if k == -dd || (k != dd && tv[(off + k - 1) as usize] < tv[(off + k + 1) as usize])
        {
            k + 1
        } else {
            k - 1
        };
        let px = tv[(off + pk) as usize];
        let py = px - pk;
        while x > px && y > py {
            ops.push(b'K');
            x -= 1;
            y -= 1;
        }
        if dd > 0 {
            // The edit that led into this diagonal; (x, y) restart at its start.
            ops.push(if x == px { b'I' } else { b'D' });
        }
        x = px;
        y = py;
    }
    ops.reverse();
    Some(ops)
}

/// cfgd_diff(): the delta payload `base` -> `nw` (header from the two hex
/// hashes), or None for "send a full push instead": a text not line framed,
/// a line over CFG_DELTA_LINE_MAX or holding a NUL, more than
/// CFG_DELTA_MAX_EDITS edits, a payload over `cap`, or a delta >=
/// CFG_DELTA_MAX_PCT % of `nw`.
pub fn diff(
    base: &[u8],
    nw: &[u8],
    base_hex: &str,
    new_hex: &str,
    cap: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    let a = split(base)?;
    let b = split(nw)?;
    if b.iter()
        .any(|l| l.b.len() - 1 > CFG_DELTA_LINE_MAX || l.b.contains(&0))
    {
        return None;
    }
    if base_hex.len() != CFGD_HASH_HEX || new_hex.len() != CFGD_HASH_HEX {
        return None;
    }
    // Keep the common prefix and suffix as they are; Myers on the middle.
    let (n, m) = (a.len(), b.len());
    let mut p = 0;
    while p < n && p < m && eq(&a[p], &b[p]) {
        p += 1;
    }
    let mut q = 0;
    while q < n - p && q < m - p && eq(&a[n - 1 - q], &b[m - 1 - q]) {
        q += 1;
    }
    let mid = myers(&a[p..n - q], &b[p..m - q], CFG_DELTA_MAX_EDITS)?;
    let mut ops = vec![b'K'; p];
    ops.extend_from_slice(&mid);
    ops.extend(std::iter::repeat_n(b'K', q));

    let mut out = Zeroizing::new(Vec::with_capacity(nw.len() / 2 + CFGD_HEADER_LEN));
    out.extend_from_slice(base_hex.as_bytes());
    out.push(b'|');
    out.extend_from_slice(new_hex.as_bytes());
    out.push(b'\n');
    let mut j = 0;
    let mut i = 0;
    while i < ops.len() {
        if ops[i] == b'K' {
            let mut e = i;
            while e < ops.len() && ops[e] == b'K' {
                e += 1;
            }
            out.extend_from_slice(format!("={}\n", e - i).as_bytes());
            j += e - i;
            i = e;
            continue;
        }
        // A hunk: every delete before every insert.
        let (mut e, mut dels, mut ins) = (i, 0usize, 0usize);
        while e < ops.len() && ops[e] != b'K' {
            if ops[e] == b'D' {
                dels += 1;
            } else {
                ins += 1;
            }
            e += 1;
        }
        if dels > 0 {
            out.extend_from_slice(format!("-{dels}\n").as_bytes());
        }
        for _ in 0..ins {
            out.push(b'+');
            out.extend_from_slice(b[j].b);
            j += 1;
        }
        i = e;
    }
    if j != m || out.len() > cap || out.len() * 100 >= nw.len() * CFG_DELTA_MAX_PCT {
        return None;
    }
    Some(out)
}

fn is_hex(s: &[u8]) -> bool {
    s.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// cfgd_header(): the base and new hex hashes of a delta's header, or None
/// for a malformed one.
pub fn header(payload: &[u8]) -> Option<(&str, &str)> {
    if payload.len() < CFGD_HEADER_LEN
        || payload[CFGD_HASH_HEX] != b'|'
        || payload[CFGD_HEADER_LEN - 1] != b'\n'
    {
        return None;
    }
    let (bh, nh) = (
        &payload[..CFGD_HASH_HEX],
        &payload[CFGD_HASH_HEX + 1..CFGD_HEADER_LEN - 1],
    );
    if !is_hex(bh) || !is_hex(nh) {
        return None;
    }
    // Lowercase hex only: always valid UTF-8.
    Some((std::str::from_utf8(bh).ok()?, std::str::from_utf8(nh).ok()?))
}

/// A count: decimal, 1..=cap, no sign, no leading zero, at most 10 digits.
fn count(s: &[u8], cap: usize) -> Option<usize> {
    if s.is_empty() || s.len() > 10 || (s.len() > 1 && s[0] == b'0') {
        return None;
    }
    let mut v: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(c - b'0');
    }
    (v >= 1 && v <= cap as u64).then_some(v as usize)
}

/// cfgd_patch(): apply the ops of `payload` (header already checked) to
/// `held`: the new text, or Err(why).  `cap` bounds the result.
pub fn patch(held: &[u8], payload: &[u8], cap: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if payload.len() < CFGD_HEADER_LEN {
        return Err("bad header");
    }
    if !held.is_empty() && held[held.len() - 1] != b'\n' {
        return Err("held text not line framed");
    }
    let total = held.iter().filter(|&&c| c == b'\n').count();
    let mut used = 0usize;
    let mut hat = 0usize;
    let mut out = Zeroizing::new(Vec::new());
    let mut p = CFGD_HEADER_LEN;
    while p < payload.len() {
        let Some(e) = payload[p..].iter().position(|&c| c == b'\n') else {
            return Err("unterminated op");
        };
        let op = &payload[p..p + e];
        p += e + 1;
        if op.is_empty() {
            return Err("empty op");
        }
        match op[0] {
            b'=' | b'-' => {
                let Some(cnt) = count(&op[1..], total - used) else {
                    return Err("bad count");
                };
                let from = hat;
                for _ in 0..cnt {
                    // cnt <= lines left, so a \n is always ahead.
                    let nl = held[hat..].iter().position(|&c| c == b'\n').unwrap_or(0);
                    hat += nl + 1;
                }
                if op[0] == b'=' {
                    if hat - from > cap - out.len() {
                        return Err("too large");
                    }
                    out.extend_from_slice(&held[from..hat]);
                }
                used += cnt;
            }
            b'+' => {
                let l = &op[1..];
                if l.len() > CFG_DELTA_LINE_MAX {
                    return Err("line too long");
                }
                if l.contains(&0) {
                    return Err("bad byte");
                }
                if l.len() + 1 > cap - out.len() {
                    return Err("too large");
                }
                out.extend_from_slice(l);
                out.push(b'\n');
            }
            _ => return Err("bad op"),
        }
    }
    if used != total {
        return Err("base not consumed");
    }
    Ok(out)
}
