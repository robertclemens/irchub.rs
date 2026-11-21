//! Can this host run a gnu artifact?  Checked before anything is downloaded
//! (2.5.4, irchub docs/plans/2026-11-20_artifact_choice_plan.md §4a):
//! elf_needs.c in the C hub and bot, rule for rule.  Byte-identical in
//! irchub.rs and ircbot.rs.
//!
//! A manifest row's column 13 lists the libraries a gnu binary needs and the
//! symbol versions it requires from each, e.g.
//! `libssl.so.3@OPENSSL_3.0.0,libcurl.so.4@CURL_OPENSSL_4,libc.so.6@GLIBC_2.43`.
//! Each library is looked up where the loader would look ($LD_LIBRARY_PATH,
//! /etc/ld.so.conf and its includes, the standard and multiarch directories)
//! and its own ELF version-definition table (SHT_GNU_verdef) read: every
//! required version must be defined.  Reads only, bounded, fail closed —
//! anything that cannot be parsed counts as "not provided".

use std::io::{Read, Seek, SeekFrom};

pub const EN_NAME_MAX: usize = 63;
pub const EN_DEFS_MAX: usize = 512;
const EN_DIRS_MAX: usize = 64;
const EN_DIR_MAX: usize = 255;
const EN_CONF_FILES: usize = 32;
const EN_FILE_MAX: u64 = 256 * 1024 * 1024;
const EN_SECT_MAX: u64 = 4096;
const EN_TABLE_MAX: u64 = 4 * 1024 * 1024; // verdef section; names are read one at a time
const SHT_GNU_VERDEF: u64 = 0x6fff_fffd;
const VER_FLG_BASE: u64 = 0x1;

// ---- Where the loader looks ------------------------------------------------

fn dir_add(ds: &mut Vec<String>, p: &str) {
    if p.is_empty() || p.len() > EN_DIR_MAX || !p.starts_with('/') || ds.len() >= EN_DIRS_MAX {
        return;
    }
    if !ds.iter().any(|d| d == p) {
        ds.push(p.to_string());
    }
}

/// `*` / `?` match of one path component.
fn wild(pat: &[u8], s: &[u8]) -> bool {
    match (pat.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => wild(&pat[1..], s) || (!s.is_empty() && wild(pat, &s[1..])),
        (Some(b'?'), Some(_)) => wild(&pat[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => wild(&pat[1..], &s[1..]),
        _ => false,
    }
}

/// An ld.so.conf `include` pattern: wildcards in the last component only
/// (`/etc/ld.so.conf.d/*.conf`), matches in sorted order as glob(3) gives.
/// C uses glob(3) itself.
fn glob_last(pat: &str) -> Vec<String> {
    let Some((dir, base)) = pat.rsplit_once('/') else {
        return Vec::new();
    };
    if !base.contains(['*', '?']) {
        return if std::path::Path::new(pat).exists() {
            vec![pat.to_string()]
        } else {
            Vec::new()
        };
    }
    let dir = if dir.is_empty() { "/" } else { dir };
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| {
                    wild(base.as_bytes(), n.as_bytes())
                        && !(n.starts_with('.') && !base.starts_with('.'))
                })
                .map(|n| format!("{}/{n}", dir.trim_end_matches('/')))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// One ld.so.conf file: a directory per line, "include <glob>" one level down.
fn conf_read(ds: &mut Vec<String>, path: &str, depth: u32, files: &mut usize) {
    if depth > 1 || *files >= EN_CONF_FILES {
        return;
    }
    *files += 1;
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for raw in text.lines() {
        let line = raw
            .split('#')
            .next()
            .unwrap_or("")
            .trim_matches([' ', '\t', '\r']);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("include")
            .filter(|r| r.starts_with([' ', '\t']))
        {
            let g = rest.trim_start_matches([' ', '\t']);
            if g.starts_with('/') {
                for f in glob_last(g) {
                    conf_read(ds, &f, depth + 1, files);
                }
            }
            continue;
        }
        dir_add(ds, line);
    }
}

fn triplet() -> Option<&'static str> {
    let m = nix::sys::utsname::uname().ok()?;
    let m = m.machine().to_string_lossy().into_owned();
    match m.as_str() {
        "x86_64" => Some("x86_64-linux-gnu"),
        "aarch64" => Some("aarch64-linux-gnu"),
        "i686" | "i386" => Some("i386-linux-gnu"),
        a if a.starts_with("armv7") => Some("arm-linux-gnueabihf"),
        _ => None,
    }
}

fn dirs() -> Vec<String> {
    let mut ds = Vec::new();
    if let Ok(lp) = std::env::var("LD_LIBRARY_PATH") {
        for p in lp.split(':') {
            dir_add(&mut ds, p);
        }
    }
    let mut files = 0;
    conf_read(&mut ds, "/etc/ld.so.conf", 0, &mut files);
    if let Some(t) = triplet() {
        dir_add(&mut ds, &format!("/lib/{t}"));
        dir_add(&mut ds, &format!("/usr/lib/{t}"));
    }
    for d in ["/lib64", "/usr/lib64", "/lib", "/usr/lib"] {
        dir_add(&mut ds, d);
    }
    ds
}

/// A library name: [A-Za-z0-9._+-], no '/', 1..=EN_NAME_MAX.
fn soname_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= EN_NAME_MAX
        && !s.starts_with('.')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
}

/// en_find_lib(): where the loader would find `soname`, or None.
pub fn find_lib(soname: &str) -> Option<String> {
    if !soname_ok(soname) {
        return None;
    }
    dirs()
        .into_iter()
        .map(|d| format!("{d}/{soname}"))
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file()) && std::fs::File::open(p).is_ok())
}

// ---- The version-definition table ------------------------------------------

fn le(b: &[u8], at: usize, n: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(n)?)?;
    Some(s.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x)))
}

fn read_at(f: &mut std::fs::File, off: u64, n: u64, fsize: u64) -> Option<Vec<u8>> {
    if off > fsize || n > fsize - off {
        return None;
    }
    let mut buf = vec![0u8; usize::try_from(n).ok()?];
    f.seek(SeekFrom::Start(off)).ok()?;
    f.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// en_verdefs(): the version names `path` defines (its SHT_GNU_verdef, the
/// base entry left out), or None when it cannot be read as a little-endian
/// ELF.
pub fn verdefs(path: &str) -> Option<Vec<String>> {
    let mut f = std::fs::File::open(path).ok()?;
    let md = f.metadata().ok()?;
    let fsize = md.len();
    if !md.is_file() || !(64..=EN_FILE_MAX).contains(&fsize) {
        return None;
    }
    let eh = read_at(&mut f, 0, 64, fsize)?;
    if &eh[..4] != b"\x7fELF" || eh[5] != 1 {
        return None;
    }
    let is64 = match eh[4] {
        2 => true,
        1 => false,
        _ => return None,
    };
    let (shoff, shentsize, shnum) = if is64 {
        (le(&eh, 0x28, 8)?, le(&eh, 0x3A, 2)?, le(&eh, 0x3C, 2)?)
    } else {
        (le(&eh, 0x20, 4)?, le(&eh, 0x2E, 2)?, le(&eh, 0x30, 2)?)
    };
    if shentsize != if is64 { 64 } else { 40 } || shnum == 0 || shnum > EN_SECT_MAX {
        return None;
    }
    let sh = read_at(&mut f, shoff, shnum * shentsize, fsize)?;
    // Section i: (type, offset, size, link, info).
    let sect = |i: u64| -> Option<(u64, u64, u64, u64, u64)> {
        let b = usize::try_from(i * shentsize).ok()?;
        Some(if is64 {
            (
                le(&sh, b + 4, 4)?,
                le(&sh, b + 24, 8)?,
                le(&sh, b + 32, 8)?,
                le(&sh, b + 40, 4)?,
                le(&sh, b + 44, 4)?,
            )
        } else {
            (
                le(&sh, b + 4, 4)?,
                le(&sh, b + 16, 4)?,
                le(&sh, b + 20, 4)?,
                le(&sh, b + 24, 4)?,
                le(&sh, b + 28, 4)?,
            )
        })
    };
    let mut vdi = None;
    for i in 0..shnum {
        if sect(i)?.0 == SHT_GNU_VERDEF {
            vdi = Some(i);
            break;
        }
    }
    let Some(vdi) = vdi else {
        return Some(Vec::new()); // defines no versions
    };
    let (_, vdoff, vdsize, link, count) = sect(vdi)?;
    if link >= shnum || vdsize > EN_TABLE_MAX || count > EN_DEFS_MAX as u64 * 4 {
        return None;
    }
    let (_, stroff, strsize, _, _) = sect(link)?;
    if strsize == 0 || stroff > fsize || strsize > fsize - stroff {
        return None;
    }
    let vd = read_at(&mut f, vdoff, vdsize, fsize)?;
    // Verdef: version u16, flags u16, ndx u16, cnt u16, hash u32, aux u32,
    // next u32 (20 bytes); Verdaux: name u32, next u32.
    let mut out = Vec::new();
    let mut at: u64 = 0;
    for _ in 0..count {
        if vdsize < 20 || at > vdsize - 20 {
            return None;
        }
        let a = usize::try_from(at).ok()?;
        let (flags, cnt) = (le(&vd, a + 2, 2)?, le(&vd, a + 6, 2)?);
        let (aux, next) = (le(&vd, a + 12, 4)?, le(&vd, a + 16, 4)?);
        if cnt > 0 {
            if aux > vdsize - at || vdsize - at - aux < 8 {
                return None;
            }
            let name = le(&vd, usize::try_from(at + aux).ok()?, 4)?;
            if name >= strsize {
                return None;
            }
            // Just this name: up to EN_NAME_MAX + 1 bytes, never past the table.
            let take = (strsize - name).min(EN_NAME_MAX as u64 + 1);
            let s = read_at(&mut f, stroff + name, take, fsize)?;
            let nm = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
            if flags & VER_FLG_BASE == 0
                && !nm.is_empty()
                && nm.len() <= EN_NAME_MAX
                && out.len() < EN_DEFS_MAX
            {
                out.push(String::from_utf8_lossy(nm).into_owned());
            }
        }
        if next == 0 {
            break;
        }
        if next > vdsize - at {
            return None;
        }
        at += next;
    }
    Some(out)
}

// ---- The check -------------------------------------------------------------

/// A version name: [A-Za-z0-9._], 1..=EN_NAME_MAX.
fn ver_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= EN_NAME_MAX
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_'))
}

/// en_check(): Ok when every library and version `needs` names is present
/// here (or `needs` is empty / "-", or cannot be parsed: then -selftest
/// decides); Err(why) at the first miss.
pub fn check(needs: &str) -> Result<(), String> {
    if needs.is_empty() || needs == "-" || needs.len() > 1024 {
        return Ok(());
    }
    for item in needs.split(',') {
        let (soname, vers) = match item.split_once('@') {
            Some((s, v)) => (s, Some(v)),
            None => (item, None),
        };
        if !soname_ok(soname) {
            return Ok(()); // unreadable: decide nothing
        }
        let Some(path) = find_lib(soname) else {
            return Err(format!("{soname} (not found on this host)"));
        };
        let Some(vers) = vers.filter(|v| *v != "-") else {
            continue;
        };
        let defs = verdefs(&path).unwrap_or_default();
        for v in vers.split('+') {
            if !ver_ok(v) {
                break; // an unreadable version list: this library decides nothing (as C)
            }
            if !defs.iter().any(|d| d == v) {
                return Err(format!("{soname} with {v} (not provided by {path})"));
            }
        }
    }
    Ok(())
}

/// "2.43" vs "2.9": dot-separated parts compared as numbers.
fn glibc_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let p = |s: &str| {
        s.split('.')
            .map(|x| x.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    p(a).cmp(&p(b))
}

/// en_glibc(): the highest GLIBC_x.y the host's libc.so.6 defines.
pub fn glibc() -> Option<String> {
    let path = find_lib("libc.so.6")?;
    verdefs(&path)?
        .into_iter()
        .filter_map(|v| v.strip_prefix("GLIBC_").map(str::to_string))
        .filter(|v| {
            v.starts_with(|c: char| c.is_ascii_digit())
                && v.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        })
        .max_by(|a, b| glibc_cmp(a, b))
}
