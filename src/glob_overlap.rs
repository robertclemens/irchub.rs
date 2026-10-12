//! Glob pattern overlap (glob_overlap.c).  The ircbot / ircbot.rs copies are
//! the same helper (docs/modes.md §6.2).

/// Longest pattern [`glob_overlap`] examines.  A longer one is reported as
/// overlapping (fail closed: it is only ever used to REFUSE a ban).
pub const GLOB_OVERLAP_MAX: usize = 256;

/// ASCII-only fold: a locale must never change what a ban mask protects.
fn gfold(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

/// Pattern-vs-pattern glob overlap: true when at least one string exists that
/// BOTH patterns match.  '*' matches any run (possibly empty), '?' exactly one
/// character, everything else compares ASCII case-insensitively.  Pure: no
/// state, O(len(a) * len(b)) time, memory bounded by GLOB_OVERLAP_MAX.
/// Over-long input -> true (fail closed).
pub fn glob_overlap(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (la, lb) = (a.len(), b.len());
    if la > GLOB_OVERLAP_MAX || lb > GLOB_OVERLAP_MAX {
        return true;
    }

    // ov[i][j]: do a[i..] and b[j..] share a string?  Filled from the ends
    // backwards; only the row below (i+1) and the current row are needed.
    let mut next = [0u8; GLOB_OVERLAP_MAX + 2];
    let mut cur = [0u8; GLOB_OVERLAP_MAX + 2];

    for i in (0..=la).rev() {
        for j in (0..=lb).rev() {
            let mut r = 0u8;
            if i == la && j == lb {
                r = 1;
            } else {
                let sa = i < la && a[i] == b'*';
                let sb = j < lb && b[j] == b'*';
                if sa {
                    // a's star takes nothing, or swallows b[j] (any element of b).
                    if next[j] != 0 || (j < lb && cur[j + 1] != 0) {
                        r = 1;
                    }
                }
                if r == 0 && sb && (cur[j + 1] != 0 || (i < la && next[j] != 0)) {
                    r = 1;
                }
                if r == 0 && i < la && j < lb && !sa && !sb {
                    let (x, y) = (a[i], b[j]);
                    if (x == b'?' || y == b'?' || gfold(x) == gfold(y)) && next[j + 1] != 0 {
                        r = 1;
                    }
                }
            }
            cur[j] = r;
        }
        std::mem::swap(&mut next, &mut cur);
    }
    // The last row filled (i == 0) was swapped into `next`.
    next[0] != 0
}

#[cfg(test)]
mod tests {
    use super::glob_overlap as ov;

    #[test]
    fn overlap() {
        assert!(ov("*!*@*", "nick!u@h"));
        assert!(ov("a*", "*b"));
        assert!(ov("n?ck!*@*.example.com", "N*!u@h.example.com"));
        assert!(!ov("nick!*@a", "nick!*@b"));
        assert!(!ov("abc", "abd"));
        assert!(ov("", "*"));
        assert!(!ov("", "a"));
        assert!(ov(&"a".repeat(300), "b"));
    }
}
