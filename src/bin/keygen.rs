//! keygen — Curve25519 keypair generator for ircbot / irchub users and bots.
//!
//! The Rust twin of the shared C keygen.c (irchub/keygen.c ==
//! ircbot/utils/keygen.c).  SHARED FILE: kept byte-identical as
//! ircbot.rs/utils/keygen.rs and irchub.rs/src/bin/keygen.rs.  Self-contained
//! on purpose -- no daemon modules -- and file-compatible with the C tool:
//!
//! ```text
//! Usage:  keygen [-d <dir>] [--no-passphrase | --passphrase-file <f>] [name]
//!         keygen --passwd <YYYYMMDDHHMMSS_name.private.b64>
//!                [--old-passphrase-file <f>] [--no-passphrase | --passphrase-file <f>]
//!         keygen --ssh-fingerprint <public.b64 | hub_public.b64>
//! ```
//!
//! A new key writes, in `<dir>` (default: the current directory; created
//! 0700 if missing; never overwriting anything):
//!
//! ```text
//! YYYYMMDDHHMMSS_<name>.private.b64   0600  the IRC private key
//! YYYYMMDDHHMMSS_<name>.public.b64    0644  base64(ed25519_pub || x25519_pub)
//! YYYYMMDDHHMMSS_<name>_ed25519       0600  the Ed25519 half as an OpenSSH key
//! YYYYMMDDHHMMSS_<name>_ed25519.pub   0644
//! ```
//!
//! and prints the public key, its fingerprint and a ~/.ssh/config block --
//! never the private key.  An optional passphrase (asked twice on /dev/tty
//! with echo off, or read from a 0600 `--passphrase-file`) protects both
//! private files: `.private.b64` becomes one `irckey-v2 scrypt ...` line
//! (scrypt + AES-256-GCM), `_ed25519` an `openssh-key-v1` key with
//! aes256-ctr + bcrypt KDF.  `--passwd` adds, changes or removes the
//! passphrase of an existing key and rewrites its `_ed25519` pair.  See
//! irchub/docs/console.md §9.
//!
//! Build: `cargo build --release` (binary: `target/release/keygen`).

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{BufRead, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD, STANDARD_NO_PAD,
};
use ctr::cipher::{KeyIvInit, StreamCipher};
use nix::sys::termios::{LocalFlags, SetArg, Termios, tcgetattr, tcsetattr};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const KEYGEN_VERSION: &str = "2";
const NAME_MAX_LEN: usize = 32;
const DIR_MAX_LEN: usize = 1024;

/// Passphrases: UTF-8 bytes as typed, no normalisation.
const PASS_MIN: usize = 8;
const PASS_MAX: usize = 1024;

/// irckey-v2: written with these; readers accept only the ranges below, which
/// cap a hostile file at 128 * r * N = 256 MB and a few seconds of work.
const IRCKEY_TAG: &str = "irckey-v2";
const IRCKEY_LOG2N: u32 = 17;
const IRCKEY_R: u32 = 8;
const IRCKEY_P: u32 = 1;
const IRCKEY_LOG2N_MIN: u32 = 14;
const IRCKEY_LOG2N_MAX: u32 = 18;
const IRCKEY_R_MAX: u32 = 8;
const IRCKEY_P_MAX: u32 = 4;
const IRCKEY_SALT: usize = 16;
const IRCKEY_NONCE: usize = 12;
const IRCKEY_TAGLEN: usize = 16;
const IRCKEY_LINE_MAX: usize = 512;

/// openssh-key-v1 with a passphrase: ssh-keygen's defaults.
const SSH_BCRYPT_ROUNDS: u32 = 16;
const SSH_SALT: usize = 16;

/// EVP_DecodeBlock: padded input, non-canonical trailing bits accepted.
const DECODE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

/// Keep the private key out of core dumps and away from same-uid ptrace.
fn harden() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    let _ = nix::sys::prctl::set_dumpable(false);
}

/// strerror(errno) text for an I/O error, as the C tool prints it.
fn strerror(e: &std::io::Error) -> &'static str {
    nix::errno::Errno::from_raw(e.raw_os_error().unwrap_or(0)).desc()
}

/// A fixed-size secret: mlock'd best-effort, wiped then unlocked on drop.
struct Locked<const N: usize> {
    // Declared first so it drops first: unlock after the wipe in Drop.
    _guard: Option<region::LockGuard>,
    buf: Box<[u8; N]>,
}

impl<const N: usize> Locked<N> {
    fn new() -> Self {
        let buf = Box::new([0u8; N]);
        let guard = region::lock(buf.as_ptr(), N).ok();
        Locked { _guard: guard, buf }
    }
}

impl<const N: usize> Drop for Locked<N> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// A passphrase: up to PASS_MAX bytes in locked memory.
struct Pass {
    buf: Locked<{ PASS_MAX + 1 }>,
    len: usize,
}

impl Pass {
    fn new() -> Self {
        Pass {
            buf: Locked::new(),
            len: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.buf.buf[..self.len]
    }
}

/// `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$` — safe as a filename component.
fn valid_name(s: &[u8]) -> bool {
    if s.is_empty() || s.len() > NAME_MAX_LEN {
        return false;
    }
    s.iter().enumerate().all(|(i, &c)| {
        c.is_ascii_alphanumeric() || c == b'_' || (i > 0 && (c == b'.' || c == b'-'))
    })
}

/// X25519 private key as OpenSSL's keygen stores it: clamped.
fn clamp_x25519(k: &mut [u8]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

fn gen_combined(priv_key: &mut [u8; 64], pub_key: &mut [u8; 64]) -> bool {
    if getrandom::fill(priv_key).is_err() {
        priv_key.zeroize();
        return false;
    }
    clamp_x25519(&mut priv_key[32..]);
    derive_pub(priv_key, pub_key);
    true
}

/// The combined public key of a combined private key.
fn derive_pub(priv_key: &[u8; 64], pub_key: &mut [u8; 64]) {
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&priv_key[..32]);
    pub_key[..32].copy_from_slice(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .as_bytes(),
    );
    let mut x = Zeroizing::new([0u8; 32]);
    x.copy_from_slice(&priv_key[32..]);
    let xs = x25519_dalek::StaticSecret::from(*x);
    pub_key[32..].copy_from_slice(x25519_dalek::PublicKey::from(&xs).as_bytes());
}

/// Strict padded base64 of exactly n bytes; None otherwise.
fn unb64_n(s: &[u8], n: usize) -> Option<Zeroizing<Vec<u8>>> {
    let want = 4 * n.div_ceil(3);
    let pad = (3 - n % 3) % 3;
    if s.len() != want
        || s[want - pad..].iter().any(|&c| c != b'=')
        || (want > pad && s[want - 1 - pad] == b'=')
    {
        return None;
    }
    let v = DECODE.decode(s).map(Zeroizing::new).ok()?;
    (v.len() == n).then_some(v)
}

fn unb64_64(s: &[u8], out: &mut [u8; 64]) -> bool {
    match unb64_n(s, 64) {
        Some(v) => {
            out.copy_from_slice(&v);
            true
        }
        None => false,
    }
}

/// First line of a key file, trailing CR/LF removed: fgets(cap) then cut at
/// the first of "\r\n".
fn read_key_line(path: &str, cap: usize) -> Option<Zeroizing<Vec<u8>>> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("keygen: cannot open {path}: {}", strerror(&e));
            return None;
        }
    };
    let mut line = Zeroizing::new(Vec::with_capacity(cap));
    let mut r = std::io::BufReader::new(f).take(cap as u64 - 1);
    if r.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
        eprintln!("keygen: {path} is empty");
        return None;
    }
    let end = line
        .iter()
        .position(|&c| matches!(c, b'\r' | b'\n' | 0))
        .unwrap_or(line.len());
    line.truncate(end);
    Some(line)
}

// ---- passphrases ---------------------------------------------------------

/// Restores the terminal when it goes out of scope — including on a panic,
/// so a crash never leaves the user's shell with echo off.
struct EchoGuard<'a> {
    tty: &'a std::fs::File,
    saved: Termios,
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.tty.as_fd(), SetArg::TCSAFLUSH, &self.saved);
    }
}

struct Tty {
    file: std::fs::File,
    interrupted: Arc<AtomicBool>,
}

impl Tty {
    /// /dev/tty, or None when there is no controlling terminal.  A signal
    /// during a prompt sets `interrupted`, which ends the read and lets the
    /// EchoGuard restore the terminal.
    fn open() -> Option<Tty> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::fcntl::OFlag::O_NOCTTY.bits())
            .open("/dev/tty")
            .ok()?;
        let interrupted = Arc::new(AtomicBool::new(false));
        for sig in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
            signal_hook::consts::SIGQUIT,
        ] {
            let _ = signal_hook::flag::register(sig, Arc::clone(&interrupted));
        }
        Some(Tty { file, interrupted })
    }

    /// One line from the terminal with echo off into `p`.  Returns its
    /// length, or None (EOF, read error, a signal, longer than PASS_MAX).
    fn read_secret(&self, prompt: &str, p: &mut Pass) -> Option<usize> {
        let saved = tcgetattr(self.file.as_fd()).ok()?;
        let mut t = saved.clone();
        t.local_flags.remove(LocalFlags::ECHO | LocalFlags::ECHONL);
        t.local_flags.insert(LocalFlags::ICANON);
        tcsetattr(self.file.as_fd(), SetArg::TCSAFLUSH, &t).ok()?;
        let guard = EchoGuard {
            tty: &self.file,
            saved,
        };
        let _ = (&self.file).write_all(prompt.as_bytes());
        let mut n = 0usize;
        let (mut too_long, mut got_nl) = (false, false);
        let mut byte = [0u8; 1];
        loop {
            if self.interrupted.load(Ordering::Relaxed) {
                break;
            }
            match (&self.file).read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        got_nl = true;
                        break;
                    }
                    if n < PASS_MAX {
                        p.buf.buf[n] = byte[0];
                        n += 1;
                    } else {
                        too_long = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        drop(guard);
        let _ = (&self.file).write_all(b"\n");
        if n > 0 && p.buf.buf[n - 1] == b'\r' {
            n -= 1;
        }
        p.buf.buf[n..].zeroize();
        p.len = n;
        if self.interrupted.load(Ordering::Relaxed) {
            p.buf.buf.zeroize();
            p.len = 0;
            std::process::exit(130);
        }
        if !got_nl || too_long {
            p.buf.buf.zeroize();
            p.len = 0;
            if too_long {
                eprintln!("keygen: passphrase longer than {PASS_MAX} bytes");
            }
            return None;
        }
        Some(n)
    }
}

/// A passphrase from the first line of a file that only its owner can read.
/// Returns its length (0 = empty line), or None.
fn file_read_secret(path: &str, p: &mut Pass) -> Option<usize> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
        .and_then(|f| f.metadata().map(|m| (f, m)));
    let (f, md) = match f {
        Ok(v) => v,
        Err(e) => {
            eprintln!("keygen: cannot open {path}: {}", strerror(&e));
            return None;
        }
    };
    if !md.is_file() || md.permissions().mode() & 0o077 != 0 {
        eprintln!("keygen: {path} must be a regular file with mode 0600");
        return None;
    }
    let mut n = 0usize;
    let mut too_long = false;
    let mut r = std::io::BufReader::new(f);
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if n < PASS_MAX {
                    p.buf.buf[n] = byte[0];
                    n += 1;
                } else {
                    too_long = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    if n > 0 && p.buf.buf[n - 1] == b'\r' {
        n -= 1;
    }
    p.buf.buf[n..].zeroize();
    p.len = n;
    if too_long {
        p.buf.buf.zeroize();
        p.len = 0;
        eprintln!("keygen: passphrase in {path} is longer than {PASS_MAX} bytes");
        return None;
    }
    Some(n)
}

#[derive(Default)]
struct PassSrc {
    none: bool,           // --no-passphrase
    file: Option<String>, // --passphrase-file
}

/// The new passphrase for a key into `p`.  Returns its length, 0 for none,
/// None to abort.
fn ask_new_passphrase(src: &PassSrc, tty: Option<&Tty>, p: &mut Pass) -> Option<usize> {
    if src.none {
        return Some(0);
    }
    if let Some(file) = &src.file {
        let n = file_read_secret(file, p)?;
        if n > 0 && n < PASS_MIN {
            eprintln!("keygen: passphrase must be at least {PASS_MIN} bytes");
            p.buf.buf.zeroize();
            return None;
        }
        return Some(n);
    }
    let Some(tty) = tty else {
        eprintln!(
            "keygen: warning: no terminal to ask for a passphrase — writing the private keys WITHOUT one"
        );
        return Some(0);
    };
    let mut again = Pass::new();
    let mut result = None;
    for _ in 0..3 {
        let Some(n) = tty.read_secret("Passphrase for the private keys (empty for none): ", p)
        else {
            break;
        };
        if n == 0 {
            eprintln!(
                "keygen: warning: no passphrase — anyone who copies the private key files can use them"
            );
            result = Some(0);
            break;
        }
        if n < PASS_MIN {
            eprintln!("keygen: passphrase must be at least {PASS_MIN} bytes");
            p.buf.buf.zeroize();
            continue;
        }
        let m = tty.read_secret("Same passphrase again: ", &mut again);
        if m == Some(n) && p.bytes() == again.bytes() {
            result = Some(n);
            break;
        }
        eprintln!("keygen: the passphrases do not match");
        p.buf.buf.zeroize();
    }
    result
}

// ---- irckey-v2 -----------------------------------------------------------

fn irckey_kdf(pass: &[u8], salt: &[u8], log2n: u32, r: u32, p: u32) -> Option<Locked<32>> {
    let params = scrypt::Params::new(log2n as u8, r, p).ok()?;
    let mut key = Locked::<32>::new();
    scrypt::scrypt(pass, salt, &params, &mut key.buf[..]).ok()?;
    Some(key)
}

/// The .private.b64 line for priv: irckey-v2 with a passphrase, else the
/// plain 88-char base64.
fn irckey_line(priv_key: &[u8; 64], pass: &[u8]) -> Option<Zeroizing<String>> {
    if pass.is_empty() {
        return Some(Zeroizing::new(STANDARD.encode(&priv_key[..])));
    }
    let line = (|| {
        let mut salt = [0u8; IRCKEY_SALT];
        let mut nonce = [0u8; IRCKEY_NONCE];
        getrandom::fill(&mut salt).ok()?;
        getrandom::fill(&mut nonce).ok()?;
        let head = format!(
            "{IRCKEY_TAG} scrypt {IRCKEY_LOG2N} {IRCKEY_R} {IRCKEY_P} {} {}",
            STANDARD.encode(salt),
            STANDARD.encode(nonce)
        );
        let key = irckey_kdf(pass, &salt, IRCKEY_LOG2N, IRCKEY_R, IRCKEY_P)?;
        let c = Aes256Gcm::new_from_slice(&key.buf[..]).ok()?;
        let mut ct = Zeroizing::new(priv_key.to_vec());
        let n = Nonce::try_from(&nonce[..]).ok()?;
        let tag = c
            .encrypt_inout_detached(&n, head.as_bytes(), ct.as_mut_slice().into())
            .ok()?;
        ct.extend_from_slice(&tag);
        Some(Zeroizing::new(format!(
            "{head} {}",
            STANDARD.encode(&ct[..])
        )))
    })();
    if line.is_none() {
        eprintln!("keygen: could not encrypt the private key");
    }
    line
}

/// Parsed "irckey-v2 scrypt log2N r p salt nonce ct" (bounds checked).
struct IrcKey {
    log2n: u32,
    r: u32,
    p: u32,
    salt: Zeroizing<Vec<u8>>,
    nonce: Zeroizing<Vec<u8>>,
    ct: Zeroizing<Vec<u8>>,
    aad: Zeroizing<Vec<u8>>,
}

fn small_uint(s: &[u8], lo: u32, hi: u32) -> Option<u32> {
    if s.is_empty() || s.len() > 3 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let x = s.iter().fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
    (lo..=hi).contains(&x).then_some(x)
}

fn irckey_parse(line: &[u8]) -> Option<IrcKey> {
    if line.len() >= IRCKEY_LINE_MAX
        || line.windows(2).any(|w| w == b"  ")
        || line.last() == Some(&b' ')
    {
        return None;
    }
    let f: Vec<&[u8]> = line
        .split(|&c| c == b' ')
        .filter(|t| !t.is_empty())
        .collect();
    if f.len() != 8 || f[0] != IRCKEY_TAG.as_bytes() || f[1] != b"scrypt" {
        return None;
    }
    let aad_len = line.len() - f[7].len() - 1; // up to, not including, " <ct>"
    Some(IrcKey {
        log2n: small_uint(f[2], IRCKEY_LOG2N_MIN, IRCKEY_LOG2N_MAX)?,
        r: small_uint(f[3], 1, IRCKEY_R_MAX)?,
        p: small_uint(f[4], 1, IRCKEY_P_MAX)?,
        salt: unb64_n(f[5], IRCKEY_SALT)?,
        nonce: unb64_n(f[6], IRCKEY_NONCE)?,
        ct: unb64_n(f[7], 64 + IRCKEY_TAGLEN)?,
        aad: Zeroizing::new(line[..aad_len].to_vec()),
    })
}

fn is_irckey(line: &[u8]) -> bool {
    line.starts_with(format!("{IRCKEY_TAG} ").as_bytes())
}

fn irckey_open(k: &IrcKey, pass: &[u8], priv_key: &mut [u8; 64]) -> bool {
    let Some(key) = irckey_kdf(pass, &k.salt, k.log2n, k.r, k.p) else {
        return false;
    };
    let (Ok(c), Ok(n), Ok(tag)) = (
        Aes256Gcm::new_from_slice(&key.buf[..]),
        Nonce::try_from(&k.nonce[..]),
        Tag::try_from(&k.ct[64..]),
    ) else {
        return false;
    };
    let mut buf = Zeroizing::new(k.ct[..64].to_vec());
    if c.decrypt_inout_detached(&n, &k.aad, buf.as_mut_slice().into(), &tag)
        .is_err()
    {
        return false;
    }
    priv_key.copy_from_slice(&buf);
    true
}

/// Reads a .private.b64 (either format) into priv.  An encrypted key asks for
/// its passphrase (from old_file, else the terminal; 3 tries).  Returns
/// whether it was encrypted, or None.
fn load_private(
    path: &str,
    old_file: Option<&str>,
    tty: Option<&Tty>,
    priv_key: &mut [u8; 64],
) -> Option<bool> {
    if let Ok(md) = std::fs::metadata(path)
        && md.permissions().mode() & 0o077 != 0
    {
        eprintln!("keygen: warning: {path} is readable by others — chmod 600 it");
    }
    let line = read_key_line(path, IRCKEY_LINE_MAX + 2)?;
    if !is_irckey(&line) {
        if !unb64_64(&line, priv_key) {
            eprintln!("keygen: {path} does not hold a private key");
            return None;
        }
        return Some(false);
    }
    let Some(k) = irckey_parse(&line) else {
        eprintln!("keygen: {path}: unreadable or out-of-range irckey-v2 line");
        return None;
    };
    let tries = if old_file.is_some() { 1 } else { 3 };
    for _ in 0..tries {
        let mut pass = Pass::new();
        let n = match (old_file, tty) {
            (Some(f), _) => file_read_secret(f, &mut pass),
            (None, Some(t)) => t.read_secret("Current passphrase: ", &mut pass),
            (None, None) => None,
        };
        if n.is_none() {
            if old_file.is_none() {
                eprintln!(
                    "keygen: the key is encrypted and there is no terminal to ask for its passphrase"
                );
            }
            break;
        }
        if irckey_open(&k, pass.bytes(), priv_key) {
            return Some(true);
        }
        eprintln!("keygen: wrong passphrase (or a damaged key file)");
    }
    None
}

// ---- OpenSSH -------------------------------------------------------------

/// The ssh-ed25519 key blob: string "ssh-ed25519" || string pub(32).
fn ssh_blob(pub_key: &[u8; 32]) -> [u8; 51] {
    const HEAD: [u8; 19] = [
        0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0, 32,
    ];
    let mut out = [0u8; 51];
    out[..19].copy_from_slice(&HEAD);
    out[19..].copy_from_slice(pub_key);
    out
}

/// "SHA256:<base64, no padding>" — what OpenSSH prints for the key.
fn ssh_fingerprint(pub_key: &[u8; 32]) -> String {
    let h = Sha256::digest(ssh_blob(pub_key));
    format!("SHA256:{}", STANDARD_NO_PAD.encode(h))
}

fn cmd_ssh_fingerprint(path: &str) -> i32 {
    let Some(line) = read_key_line(path, 256) else {
        return 1;
    };
    if path.contains(".private.") || is_irckey(&line) {
        eprintln!("keygen: {path} is a PRIVATE key; give the .public.b64");
        return 1;
    }
    let mut pub_key = [0u8; 64];
    if !unb64_64(&line, &mut pub_key) {
        eprintln!("keygen: {path} does not hold an 88-char public key");
        return 1;
    }
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&pub_key[..32]);
    println!("{} ssh-ed25519", ssh_fingerprint(&ed));
    0
}

fn put32(p: &mut Vec<u8>, v: u32) {
    p.extend_from_slice(&v.to_be_bytes());
}

fn putstr(p: &mut Vec<u8>, d: &[u8]) {
    put32(p, d.len() as u32);
    p.extend_from_slice(d);
}

/// An "openssh-key-v1" private key: encrypted (aes256-ctr, bcrypt KDF) when
/// pass is not empty.  Without the final newline (write_file adds it).
fn openssh_pem(
    seed: &[u8; 32],
    pub_key: &[u8; 32],
    comment: &[u8],
    pass: &[u8],
) -> Option<Zeroizing<String>> {
    let mut check = [0u8; 4];
    if comment.len() > 64 || getrandom::fill(&mut check).is_err() {
        return None;
    }
    let block = if pass.is_empty() { 8 } else { 16 };
    let mut raw = Zeroizing::new(Vec::with_capacity(512));
    raw.extend_from_slice(b"openssh-key-v1\0");
    let mut salt = [0u8; SSH_SALT];
    if pass.is_empty() {
        putstr(&mut raw, b"none");
        putstr(&mut raw, b"none");
        putstr(&mut raw, b"");
    } else {
        getrandom::fill(&mut salt).ok()?;
        let mut kdfopt = Vec::with_capacity(24);
        putstr(&mut kdfopt, &salt);
        put32(&mut kdfopt, SSH_BCRYPT_ROUNDS);
        putstr(&mut raw, b"aes256-ctr");
        putstr(&mut raw, b"bcrypt");
        putstr(&mut raw, &kdfopt);
    }
    put32(&mut raw, 1);
    putstr(&mut raw, &ssh_blob(pub_key));
    let mut sec = Zeroizing::new(Vec::with_capacity(320));
    sec.extend_from_slice(&check);
    sec.extend_from_slice(&check);
    putstr(&mut sec, b"ssh-ed25519");
    putstr(&mut sec, pub_key);
    put32(&mut sec, 64);
    sec.extend_from_slice(seed);
    sec.extend_from_slice(pub_key);
    putstr(&mut sec, comment);
    let mut pad = 1u8;
    while sec.len() % block != 0 {
        sec.push(pad);
        pad += 1;
    }
    if !pass.is_empty() {
        let mut kiv = Locked::<48>::new();
        bcrypt_pbkdf::bcrypt_pbkdf(pass, &salt, SSH_BCRYPT_ROUNDS, &mut kiv.buf[..]).ok()?;
        let mut c =
            ctr::Ctr128BE::<aes::Aes256>::new_from_slices(&kiv.buf[..32], &kiv.buf[32..]).ok()?;
        c.apply_keystream(&mut sec);
    }
    putstr(&mut raw, &sec);

    let b = Zeroizing::new(STANDARD.encode(&raw[..]));
    let mut pem = Zeroizing::new(String::with_capacity(1024));
    pem.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b.as_bytes().chunks(70) {
        // base64 output is ASCII
        pem.push_str(std::str::from_utf8(chunk).ok()?);
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----");
    Some(pem)
}

/// "ssh-ed25519 <blob> <comment>"
fn openssh_pub(pub_key: &[u8; 32], comment: &str) -> String {
    format!(
        "ssh-ed25519 {} {comment}",
        STANDARD.encode(ssh_blob(pub_key))
    )
}

// ---- files ---------------------------------------------------------------

/// Write text + "\n" to path with `mode`.  replace = false: create it
/// exclusively (never replaces a file, never follows a symlink).  replace =
/// true: write a temporary file next to it and rename it over path.
fn write_file(path: &str, mode: u32, text: &[u8], replace: bool) -> bool {
    let target = if replace {
        let mut r = [0u8; 6];
        if getrandom::fill(&mut r).is_err() {
            return false;
        }
        const CH: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let sfx: String = r.iter().map(|&b| CH[b as usize % 62] as char).collect();
        format!("{path}.{sfx}")
    } else {
        path.to_string()
    };
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if replace { 0o600 } else { mode })
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(&target);
    let mut f = match f {
        Ok(f) => f,
        Err(e) => {
            eprintln!("keygen: cannot create {target}: {}", strerror(&e));
            return false;
        }
    };
    // Independent of the caller's umask.
    let _ = f.set_permissions(std::fs::Permissions::from_mode(mode));
    let mut ok = f.write_all(text).is_ok() && f.write_all(b"\n").is_ok() && f.sync_all().is_ok();
    drop(f);
    let mut err = String::new();
    if ok
        && replace
        && let Err(e) = std::fs::rename(&target, path)
    {
        err = strerror(&e).to_string();
        ok = false;
    }
    if !ok {
        eprintln!("keygen: writing {path} failed: {err}");
        let _ = std::fs::remove_file(&target);
    }
    ok
}

/// `<dir>` exists as a directory, or is created 0700 (one level).
fn ensure_dir(dir: &str) -> bool {
    match std::fs::metadata(dir) {
        Ok(md) if md.is_dir() => true,
        Ok(_) => {
            eprintln!("keygen: {dir} is not a directory");
            false
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            eprintln!("keygen: cannot create directory {dir}: {}", strerror(&e));
            false
        }
        Err(_) => match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("keygen: cannot create directory {dir}: {}", strerror(&e));
                false
            }
        },
    }
}

/// The ssh/ssh-add lines keygen prints after writing an SSH key.
fn print_ssh_help(key_path: &str, name: &str, enc: bool) {
    let p = std::fs::canonicalize(key_path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| key_path.to_string());
    println!("SSH console (any hub where '{name}' is an admin) — add to ~/.ssh/config:");
    println!("  Host irchub-<hub>");
    println!("      HostName <hub host>");
    println!("      Port <hubport>");
    println!("      User {name}");
    println!("      IdentityFile {p}");
    println!("      IdentitiesOnly yes");
    println!("then: ssh irchub-<hub>");
    if enc {
        println!("Unlock it for an hour at a time with: ssh-add -t 1h {p}");
    }
    println!("PuTTY: load {p} in PuTTYgen and save it as a .ppk.");
}

fn print_fp(pub_key: &[u8; 64]) {
    let h = Sha256::digest(pub_key);
    println!(
        "  fingerprint: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    );
}

/// The Ed25519 seed of a combined private key, in locked memory.
fn seed_of(priv_key: &[u8; 64]) -> Locked<32> {
    let mut seed = Locked::<32>::new();
    seed.buf.copy_from_slice(&priv_key[..32]);
    seed
}

/// keygen --passwd <stamp_name.private.b64>
fn cmd_passwd(path: &str, old_file: Option<&str>, src: &PassSrc) -> i32 {
    let base = path.rsplit('/').next().unwrap_or(path);
    // strstr: the first ".private.b64", which must end the name
    let suf = match base.find(".private.b64") {
        Some(i) if i > 0 && i + 12 == base.len() => i,
        _ => {
            eprintln!("keygen: expected a <YYYYMMDDHHMMSS>_<name>.private.b64 file");
            return 1;
        }
    };
    let stem = &path[..path.len() - 12];
    if stem.len() >= DIR_MAX_LEN + 128 - 16 {
        eprintln!("keygen: path too long");
        return 1;
    }
    // the name: the stem after the timestamp
    let sb = &base.as_bytes()[..suf];
    let name = match sb.iter().position(|&c| c == b'_') {
        Some(i) if valid_name(&sb[i + 1..]) => &sb[i + 1..],
        _ => sb,
    };
    if !valid_name(name) {
        eprintln!("keygen: cannot read a name from {base}");
        return 1;
    }
    // valid_name: ASCII only
    let name = String::from_utf8_lossy(name).into_owned();

    let tty = Tty::open();
    let mut priv_key = Locked::<64>::new();
    let Some(was_enc) = load_private(path, old_file, tty.as_ref(), &mut priv_key.buf) else {
        return 1;
    };
    let mut pub_key = [0u8; 64];
    derive_pub(&priv_key.buf, &mut pub_key);
    if !src.none && src.file.is_none() && tty.is_none() {
        eprintln!("keygen: --passwd needs a terminal (or --passphrase-file / --no-passphrase)");
        return 1;
    }
    let mut pass = Pass::new();
    let Some(n) = ask_new_passphrase(src, tty.as_ref(), &mut pass) else {
        return 1;
    };
    let key_path = format!("{stem}_ed25519");
    let kpub_path = format!("{stem}_ed25519.pub");
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&pub_key[..32]);
    let seed = seed_of(&priv_key.buf);
    let (Some(priv_line), Some(pem)) = (
        irckey_line(&priv_key.buf, pass.bytes()),
        openssh_pem(&seed.buf, &ed, name.as_bytes(), pass.bytes()),
    ) else {
        eprintln!("keygen: could not build the keys");
        return 1;
    };
    let pub_line = openssh_pub(&ed, &name);
    // SSH pair first: if it fails, the IRC key is still the old one.
    if !write_file(&key_path, 0o600, pem.as_bytes(), true)
        || !write_file(&kpub_path, 0o644, pub_line.as_bytes(), true)
        || !write_file(path, 0o600, priv_line.as_bytes(), true)
    {
        return 1;
    }
    let what = match (n > 0, was_enc) {
        (true, true) => "Passphrase changed",
        (true, false) => "Passphrase added",
        (false, _) => "Passphrase removed",
    };
    let enc = if n > 0 { "encrypted" } else { "NOT encrypted" };
    println!("{what} for '{name}':");
    println!("  irc key:  {path}  ({enc})");
    println!("  ssh key:  {key_path}  ({enc})");
    println!("  ssh pub:  {kpub_path}");
    print_fp(&pub_key);
    println!("The public key is unchanged; nothing on the hubs or bots needs updating.");
    println!("Load the new file in your IRC client script (or /botlock + /botunlock).\n");
    print_ssh_help(&key_path, &name, n > 0);
    0
}

fn usage(to_stdout: bool) {
    let text = format!(
        "Usage: keygen [-d <dir>] [--no-passphrase | --passphrase-file <f>] [name]\n\
         \x20      keygen --passwd <YYYYMMDDHHMMSS_name.private.b64>\n\
         \x20             [--old-passphrase-file <f>] [--no-passphrase | --passphrase-file <f>]\n\
         \x20      keygen --ssh-fingerprint <public.b64 | hub_public.b64>\n\
         Generates a Curve25519 (Ed25519 + X25519) keypair in <dir> (default: here):\n\
         \x20 YYYYMMDDHHMMSS_<name>.private.b64  (0600, for the IRC client scripts)\n\
         \x20 YYYYMMDDHHMMSS_<name>.public.b64   (give this to an admin)\n\
         \x20 YYYYMMDDHHMMSS_<name>_ed25519      (0600, SSH key for the hub console)\n\
         \x20 YYYYMMDDHHMMSS_<name>_ed25519.pub\n\
         It asks for an optional passphrase (empty for none) that protects both\n\
         private files.  Without [name] it asks for one. Names: letters, digits,\n\
         _ . - (max {NAME_MAX_LEN}, not starting with . or -).\n\
         --passwd adds/changes/removes the passphrase of an existing key and\n\
         rewrites its _ed25519 pair; --passphrase-file reads a passphrase from\n\
         the first line of a 0600 file; --ssh-fingerprint prints the SHA256\n\
         fingerprint ssh shows."
    );
    if to_stdout {
        println!("{text}");
    } else {
        eprintln!("{text}");
    }
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let (mut dir, mut passwd, mut sshfp, mut old_file, mut arg) = (None, None, None, None, None);
    let mut src = PassSrc::default();
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1).cloned();
        let mut take = |slot: &mut Option<String>| -> bool {
            if slot.is_some() || next.is_none() {
                return false;
            }
            *slot = next.clone();
            i += 1;
            true
        };
        let ok = match a {
            "-h" | "--help" => {
                usage(true);
                return 0;
            }
            "-d" => take(&mut dir),
            "--passwd" => take(&mut passwd),
            "--ssh-fingerprint" => take(&mut sshfp),
            "--passphrase-file" => take(&mut src.file),
            "--old-passphrase-file" => take(&mut old_file),
            "--no-passphrase" => {
                src.none = true;
                true
            }
            _ if !a.starts_with('-') && arg.is_none() => {
                arg = Some(a.to_string());
                true
            }
            _ => false,
        };
        if !ok {
            usage(false);
            return 1;
        }
        i += 1;
    }
    if (src.none && src.file.is_some())
        || (sshfp.is_some()
            && (passwd.is_some()
                || dir.is_some()
                || arg.is_some()
                || src.none
                || src.file.is_some()
                || old_file.is_some()))
        || (passwd.is_some() && (dir.is_some() || arg.is_some()))
        || (old_file.is_some() && passwd.is_none())
    {
        usage(false);
        return 1;
    }
    if let Some(p) = sshfp {
        return cmd_ssh_fingerprint(&p);
    }
    if let Some(p) = passwd {
        return cmd_passwd(&p, old_file.as_deref(), &src);
    }

    // char name[128]: argv is cut to 127 bytes, the prompt reads fgets(128).
    let mut name: Vec<u8> = if let Some(a) = &arg {
        let a = a.as_bytes();
        a[..a.len().min(127)].to_vec()
    } else {
        print!("Key name (e.g. your nick): ");
        let _ = std::io::stdout().flush();
        let mut line = Vec::new();
        let n = std::io::stdin()
            .lock()
            .take(127)
            .read_until(b'\n', &mut line)
            .unwrap_or(0);
        if n == 0 {
            eprintln!("keygen: no name given");
            return 1;
        }
        line
    };
    // name[strcspn(name, "\r\n")] = '\0' (strcspn also stops at a NUL)
    let end = name
        .iter()
        .position(|&c| matches!(c, b'\r' | b'\n' | 0))
        .unwrap_or(name.len());
    name.truncate(end);
    if !valid_name(&name) {
        eprintln!(
            "keygen: invalid name '{}' — use letters, digits, _ . - (max {NAME_MAX_LEN}, not starting with . or -)",
            String::from_utf8_lossy(&name)
        );
        return 1;
    }
    // valid_name: ASCII only
    let name = String::from_utf8_lossy(&name).into_owned();
    if let Some(d) = &dir {
        if d.is_empty() || d.len() > DIR_MAX_LEN {
            eprintln!("keygen: -d: empty or longer than {DIR_MAX_LEN} bytes");
            return 1;
        }
        if !ensure_dir(d) {
            return 1;
        }
    }

    let stamp = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let pre = dir.map(|d| format!("{d}/")).unwrap_or_default();
    let priv_path = format!("{pre}{stamp}_{name}.private.b64");
    let pub_path = format!("{pre}{stamp}_{name}.public.b64");
    let key_path = format!("{pre}{stamp}_{name}_ed25519");
    let kpub_path = format!("{pre}{stamp}_{name}_ed25519.pub");

    let tty = if src.none || src.file.is_some() {
        None
    } else {
        Tty::open()
    };
    let mut pass = Pass::new();
    let Some(n) = ask_new_passphrase(&src, tty.as_ref(), &mut pass) else {
        return 1;
    };
    let mut priv_key = Locked::<64>::new();
    let mut pub_key = [0u8; 64];
    let mut ed = [0u8; 32];
    let built = if gen_combined(&mut priv_key.buf, &mut pub_key) {
        ed.copy_from_slice(&pub_key[..32]);
        let seed = seed_of(&priv_key.buf);
        match (
            irckey_line(&priv_key.buf, pass.bytes()),
            openssh_pem(&seed.buf, &ed, name.as_bytes(), pass.bytes()),
        ) {
            (Some(l), Some(p)) => Some((l, p)),
            _ => None,
        }
    } else {
        None
    };
    let Some((priv_line, pem)) = built else {
        eprintln!("keygen: key generation failed");
        return 1;
    };
    let pub_b64 = STANDARD.encode(pub_key);
    let ssh_pub_line = openssh_pub(&ed, &name);
    let files: [(&str, u32, &[u8]); 4] = [
        (&priv_path, 0o600, priv_line.as_bytes()),
        (&pub_path, 0o644, pub_b64.as_bytes()),
        (&key_path, 0o600, pem.as_bytes()),
        (&kpub_path, 0o644, ssh_pub_line.as_bytes()),
    ];
    for (i, (p, mode, text)) in files.iter().enumerate() {
        if !write_file(p, *mode, text, false) {
            // never leave half a set
            for (q, _, _) in &files[..i] {
                let _ = std::fs::remove_file(q);
            }
            return 1;
        }
    }

    let prot = if n > 0 {
        "passphrase-protected"
    } else {
        "NOT passphrase-protected"
    };
    println!("Generated Curve25519 keypair (keygen v{KEYGEN_VERSION}) for '{name}':");
    println!("  private: {priv_path}  (0600, {prot})");
    println!("  public:  {pub_path}");
    println!("  ssh key: {key_path}  (0600, {prot})");
    println!("  ssh pub: {kpub_path}");
    println!("  public key:  {pub_b64}");
    print_fp(&pub_key);
    println!("\nNext:");
    println!("  - Give the PUBLIC key to an admin: hub console 'admin add' / 'oper add'");
    println!("    / 'userkey', or IRC '+admin|+oper <name> <pubkey> <mask>'.");
    println!("  - Point your IRC client script (ircbot/utils) at {priv_path}");
    if n == 0 {
        println!("  - Add a passphrase later with: keygen --passwd {priv_path}");
    }
    println!();
    print_ssh_help(&key_path, &name, n > 0);
    0
}

fn main() {
    harden();
    // Every secret is dropped (wiped) inside run() before the exit.
    let rc = run();
    std::process::exit(rc);
}
