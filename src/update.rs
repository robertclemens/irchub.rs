//! The hub's own signed self-update (`hub_update.c`).
//!
//! This is the hub-side twin of `ircbot.rs`'s updater, and it exists for one
//! reason: a network upgrade that can move every bot but not the hubs leaves
//! the mesh permanently mixed.  The orchestration in [`crate::upgrade`]
//! already treats peer hubs and this hub as nodes of a run; what lives here is
//! what a node needs to actually *be* upgraded — fetch a signed manifest, pick
//! the artifact that fits this host, install it atomically and keep the old
//! one so the run can be rolled back.
//!
//! Trust model, identical to the bot's: the manifest is verified against the
//! pinned Ed25519 key in [`HUB_UPDATE_PUBKEY_B64`] before a single field in it
//! is read, and each artifact against the SHA-256 the signed manifest gives.
//! An empty pinned key disables updates entirely (fail closed).

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::consts::*;
use crate::state::HubState;
use crate::{config, crypto};

// ---------------------------------------------------------------------------
// Host capability probe (answered in CMD_UPGRADE_READY)
// ---------------------------------------------------------------------------

/// Both answers describe the RUNNING binary, not the machine in the abstract:
/// a hub reports what it can be replaced with.  The arch is spelled the way
/// `uname -m` spells it, to match the manifest; the libc is decided at compile
/// time because the binary is already linked against one.
pub fn host_arch() -> String {
    std::env::consts::ARCH.to_string()
}

pub fn host_libc() -> String {
    if cfg!(target_env = "musl") {
        "musl".to_string()
    } else if cfg!(target_os = "linux") {
        "gnu".to_string()
    } else {
        "unknown".to_string()
    }
}

/// The variant this binary was built from.  Same value the compiled release
/// URL carries, so "keep my variant" and the URL can never disagree.
pub fn host_variant() -> &'static str {
    HUB_UPDATE_VARIANT
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

/// glibc `strverscmp` ("v2.10.0" > "v2.9.1"), carried here rather than linked
/// so a hub on musl or an older libc compares versions the same way every
/// other node does.
fn strverscmp(s1: &str, s2: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (a, b) = (s1.as_bytes(), s2.as_bytes());
    let at = |v: &[u8], i: usize| v.get(i).copied().unwrap_or(0);
    let mut i = 0;
    while at(a, i) == at(b, i) {
        if at(a, i) == 0 {
            return Ordering::Equal;
        }
        i += 1;
    }
    let (mut c1, mut c2) = (at(a, i), at(b, i));
    if c1.is_ascii_digit() && c2.is_ascii_digit() {
        let mut state = Ordering::Equal;
        let (mut p1, mut p2) = (i + 1, i + 1);
        loop {
            if state == Ordering::Equal {
                state = c1.cmp(&c2);
            }
            c1 = if at(a, p1).is_ascii_digit() {
                p1 += 1;
                at(a, p1 - 1)
            } else {
                0
            };
            c2 = if at(b, p2).is_ascii_digit() {
                p2 += 1;
                at(b, p2 - 1)
            } else {
                0
            };
            if c1 == 0 && c2 == 0 {
                break;
            }
            if c1 == 0 {
                return Ordering::Less;
            }
            if c2 == 0 {
                return Ordering::Greater;
            }
        }
        return state;
    }
    c1.cmp(&c2)
}

/// Release manifests spell versions with a leading 'v' ("v2.3.0") while
/// HUB_VERSION does not ("2.4.0").  Compare them on the numeric part alone:
/// `strverscmp("v0.0.1", "2.4.0")` would otherwise compare 'v' against '2' and
/// report a downgrade as an upgrade, which is exactly what the downgrade guard
/// exists to stop.
fn strip_v(v: &str) -> &str {
    v.strip_prefix('v')
        .or_else(|| v.strip_prefix('V'))
        .unwrap_or(v)
}

/// `hub_update_version_cmp()`.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    strverscmp(strip_v(a), strip_v(b))
}

fn version_eq(a: &str, b: &str) -> bool {
    strip_v(a).eq_ignore_ascii_case(strip_v(b))
}

// ---------------------------------------------------------------------------
// Release base
// ---------------------------------------------------------------------------

/// Test hook, compiled in only with the `test-hooks` feature (the testnet's
/// builds; never a release): a non-empty IRCHUB_UPDATE_BASE repoints the
/// updater at a local irchub-releases root over `file://`, and
/// IRCHUB_UPDATE_PUBKEY / IRCHUB_BOT_RELEASE_BASE are read alongside it.  A
/// production binary has no code that reads any of them: its roots and key
/// are the compiled-in ones, so nobody who can set the daemon's environment
/// can point it at their own signed releases.  A run never names a base
/// either: every node reads its own root, the only one its key can verify.
#[cfg(feature = "test-hooks")]
fn env_base() -> Option<String> {
    std::env::var("IRCHUB_UPDATE_BASE")
        .ok()
        .filter(|s| !s.is_empty())
}

#[cfg(not(feature = "test-hooks"))]
fn env_base() -> Option<String> {
    None
}

/// A test hook beside env_base(), read only while it is set.
#[cfg(feature = "test-hooks")]
fn env_hook(name: &str) -> Option<String> {
    env_base()?;
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// The bots' release root, for reading their manifest (roll-up stepping and
/// the console's release list): the compiled-in tree, or in a test-hooks
/// build IRCHUB_BOT_RELEASE_BASE.
pub fn bot_root() -> String {
    #[cfg(feature = "test-hooks")]
    if let Some(b) = env_hook("IRCHUB_BOT_RELEASE_BASE") {
        return b;
    }
    HUB_BOT_RELEASE_BASE.to_string()
}

/// `irchub -checkupdate [variant]`: fetch the irchub release manifest and its
/// signature exactly as a hub self-upgrade does — `<root>/<variant>`, the
/// compiled-in root and pinned key unless IRCHUB_UPDATE_BASE says otherwise —
/// verify one against the other, and report.  Nothing past the manifest is
/// downloaded and nothing is installed, so an operator (or the testnet) can
/// prove a host reaches and trusts the real release channel — TLS, CA store,
/// pinned key — without upgrading anything.  Returns the exit code: 0 =
/// verified.
pub fn check_cli(variant: Option<&str>) -> i32 {
    let want = variant.filter(|v| !v.is_empty()).unwrap_or(host_variant());
    if want.len() > 7 || want.contains(['/', ';', '|', '&', '`', '$', ' ', '\t', '\r', '\n']) {
        println!("checkupdate: FAIL malformed variant");
        return 1;
    }
    let tree = format!("{}/{want}", effective_root(""));
    let manifest = match fetch_verified_manifest(&tree) {
        Ok(m) => m,
        Err(e) => {
            println!("checkupdate: FAIL {e} ({tree})");
            return 1;
        }
    };
    let mut rows = 0;
    let mut newest = String::new();
    for line in manifest.lines() {
        let Some(version) = line.split_whitespace().next() else {
            continue;
        };
        if line.starts_with('#') {
            continue;
        }
        rows += 1;
        if newest.is_empty() || version_cmp(version, &newest) == std::cmp::Ordering::Greater {
            newest = version.to_string();
        }
    }
    println!(
        "checkupdate: OK {want} manifest verified: {rows} release row(s), newest {}, running {HUB_VERSION}",
        if newest.is_empty() { "-" } else { &newest }
    );
    0
}

/// The hub release root: the operator's env override, else the compiled-in
/// root.  `root`, when given, is a tree the caller names explicitly (the
/// bots' ircbot-releases root, for the roll-up and the release list).
fn effective_root(root: &str) -> String {
    if !root.is_empty() {
        return root.to_string();
    }
    env_base().unwrap_or_else(|| HUB_UPDATE_BASE.to_string())
}

/// An https:// URL whose host is exactly github.com, githubusercontent.com
/// or a subdomain of it (raw. for manifests; downloads redirect to
/// objects.).  "Contains github.com" let https://evil.example/github.com
/// through; userinfo (github.com@evil.example) is refused outright.
fn url_host_trusted(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let end = rest.find(['/', ':', '?', '#', '@']).unwrap_or(rest.len());
    if rest[end..].starts_with('@') {
        return false;
    }
    let host = rest[..end].to_ascii_lowercase();
    host == "github.com"
        || host == "githubusercontent.com"
        || host.ends_with(".githubusercontent.com")
}

fn validate_url(url: &str) -> bool {
    // Reject shell metacharacters regardless of source.
    if url.contains([';', '|', '&', '`', '$']) {
        return false;
    }
    if let Some(b) = env_base()
        && url.starts_with(&b)
    {
        return true;
    }
    url_host_trusted(url)
}

/// Keep `[A-Za-z0-9._-]`; the result must end in ".tar.gz".
fn sanitize_filename(input: &str) -> Option<String> {
    let out: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
        .take(255)
        .collect();
    (out.len() >= 8 && out.ends_with(".tar.gz")).then_some(out)
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

/// The first CPU feature graviola needs that this machine lacks, or `None`.
///
/// graviola 0.4.1 *asserts* on its required features, and it does so lazily —
/// on the first crypto call, deep inside a TLS handshake — not when the
/// provider is built.  A `catch_unwind` around provider construction therefore
/// guarded nothing (run 96e79880: an Ivy Bridge bot died mid-download).  The
/// features are checked here, in graviola's own order, so the name reported
/// matches its panic text.
pub fn tls_cpu_missing() -> Option<&'static str> {
    #[cfg(target_arch = "x86_64")]
    {
        if !std::arch::is_x86_feature_detected!("aes") {
            return Some("aes");
        }
        if !std::arch::is_x86_feature_detected!("pclmulqdq") {
            return Some("pclmulqdq");
        }
        if !std::arch::is_x86_feature_detected!("bmi1") {
            return Some("bmi1");
        }
        if !std::arch::is_x86_feature_detected!("adx") {
            return Some("adx");
        }
        if !std::arch::is_x86_feature_detected!("avx") {
            return Some("avx");
        }
        if !std::arch::is_x86_feature_detected!("avx2") {
            return Some("avx2");
        }
        None
    }
    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return Some("neon");
        }
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return Some("aes");
        }
        if !std::arch::is_aarch64_feature_detected!("pmull") {
            return Some("pmull");
        }
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            return Some("sha2");
        }
        None
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Some("a supported architecture (x86_64/aarch64)")
    }
}

/// Why HTTPS cannot be used on this machine, in the words an admin reads in
/// the upgrade status, or `None` when it can.
fn tls_refusal() -> Option<String> {
    tls_cpu_missing()
        .map(|f| format!("this CPU lacks {f}, which the Rust build's TLS needs — use the C build"))
}

/// Install the rustls provider once, and say whether HTTPS is usable at all.
///
/// The C hub gets TLS from libcurl and runs anywhere.  Here it comes from
/// graviola, which is x86_64/aarch64 only and asserts on the CPU features it
/// needs: the features are checked first (see [`tls_cpu_missing`]), so on a
/// CPU it does not support the provider is never built, graviola is never
/// entered and only the updater is unavailable.
fn tls_ready() -> bool {
    use std::sync::OnceLock;
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        tls_cpu_missing().is_none()
            && std::panic::catch_unwind(|| {
                let _ = rustls_graviola::default_provider().install_default();
            })
            .is_ok()
    })
}

/// Manifest reads made from the event loop (a PREPARE answer, the console's
/// release list) run on a short budget: the hub serves nothing while a fetch
/// blocks, and a peer link that misses its pings is a worse outcome than a
/// node answering "unable: manifest fetch failed".  0 = the full budget, for
/// COMMIT, which is about to restart the process anyway.
static FETCH_QUICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Run `f` with the quick fetch budget in force.
fn quick<T>(f: impl FnOnce() -> T) -> T {
    use std::sync::atomic::Ordering::Relaxed;
    FETCH_QUICK.store(HUB_UPDATE_QUICK_TIMEOUT, Relaxed);
    let out = f();
    FETCH_QUICK.store(0, Relaxed);
    out
}

fn agent() -> ureq::Agent {
    let q = FETCH_QUICK.load(std::sync::atomic::Ordering::Relaxed);
    ureq::Agent::config_builder()
        .user_agent("irchub-updater/1.0")
        .timeout_connect(Some(std::time::Duration::from_secs(if q > 0 {
            5
        } else {
            30
        })))
        .timeout_global(Some(std::time::Duration::from_secs(if q > 0 {
            q
        } else {
            HUB_UPDATE_FETCH_TIMEOUT
        })))
        .build()
        .into()
}

/// A `file://` URL is read straight off disk: ureq speaks HTTP only, while the
/// C updater gets this for free from libcurl.  Reachable only under the base
/// override (`validate_url` still rejects it otherwise), and the signature and
/// hash checks are unchanged either way.
fn file_url_path(url: &str) -> Option<&str> {
    url.strip_prefix("file://")
}

fn fetch(url: &str, limit: u64) -> Option<Vec<u8>> {
    if let Some(path) = file_url_path(url) {
        let meta = std::fs::metadata(path).ok()?;
        if meta.len() > limit {
            return None;
        }
        return std::fs::read(path).ok();
    }
    if !tls_ready() {
        return None;
    }
    let mut resp = agent().get(url).call().ok()?;
    resp.body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .ok()
}

fn download(url: &str, path: &str) -> bool {
    download_with(url, path, &mut |_, _| {})
}

/// `std::io::copy`, telling `tick` as it goes when the size is known.
fn copy_with(
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    total: u64,
    tick: &mut dyn FnMut(u64, u64),
) -> bool {
    let mut buf = [0u8; 65536];
    let mut got = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => return true,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    return false;
                }
                got += n as u64;
                if total > 0 {
                    tick(got, total);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

/// As `download`; `tick` hears the bytes so far against the size the server gave.
fn download_with(url: &str, path: &str, tick: &mut dyn FnMut(u64, u64)) -> bool {
    if let Some(src) = file_url_path(url) {
        return std::fs::metadata(src).is_ok_and(|m| m.len() <= HUB_UPDATE_MAX_ARCHIVE)
            && std::fs::copy(src, path).is_ok();
    }
    if !tls_ready() {
        return false;
    }
    let Ok(mut resp) = agent().get(url).call() else {
        return false;
    };
    let total = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    // 0600 from the start: no world-readable window on a file we are about to
    // unpack and run.
    let Ok(mut f) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
    else {
        return false;
    };
    let mut reader = resp
        .body_mut()
        .with_config()
        .limit(HUB_UPDATE_MAX_ARCHIVE)
        .reader();
    let ok = copy_with(&mut reader, &mut f, total, tick) && f.flush().is_ok();
    if !ok {
        let _ = std::fs::remove_file(path);
    }
    ok
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Fetch releases.txt and its detached signature and verify one against the
/// other before any field in the manifest is trusted.
fn fetch_verified_manifest(base: &str) -> Result<String, String> {
    // Pinned key; only a test-hooks build takes a throwaway one.
    #[cfg(feature = "test-hooks")]
    let pubkey_b64 =
        env_hook("IRCHUB_UPDATE_PUBKEY").unwrap_or_else(|| HUB_UPDATE_PUBKEY_B64.to_string());
    #[cfg(not(feature = "test-hooks"))]
    let pubkey_b64 = HUB_UPDATE_PUBKEY_B64.to_string();
    if pubkey_b64.is_empty() {
        return Err("hub updater disabled (no signing key configured)".to_string());
    }
    let pk = crypto::update_pubkey_b64_decode(&pubkey_b64)
        .ok_or("configured update public key is malformed")?;
    if file_url_path(base).is_none()
        && let Some(why) = tls_refusal()
    {
        return Err(why);
    }

    let man = fetch(&format!("{base}/releases.txt"), HUB_UPDATE_MAX_MANIFEST)
        .ok_or("failed to download release manifest")?;
    let sig = fetch(&format!("{base}/releases.sig"), HUB_UPDATE_MAX_MANIFEST)
        .ok_or("failed to download release signature")?;
    let sig_bytes = crypto::b64_decode(String::from_utf8_lossy(&sig).trim_end())
        .filter(|s| s.len() == 64)
        .ok_or("release signature is malformed")?;
    if !crypto::ed25519_verify(&pk, &man, &sig_bytes) {
        return Err("release manifest signature INVALID — possible tampering".to_string());
    }
    String::from_utf8(man).map_err(|_| "release manifest is not text".to_string())
}

/// One artifact row.  Columns 1-5 are the format ircbot's original updater
/// parses; 6-9 were appended for the network upgrade and are absent from older
/// manifests, which is why they default to a source build that fits anything.
struct ManifestRow {
    url: String,
    hash: String,
    kind: String,
    arch: String,
    libc: String,
    min_from: String,
    /// Column 10: the CPU features this artifact needs ("-" = none).
    cpu: String,
    /// Column 11: archive + unpacked bytes, 0 = unknown.
    size: u64,
}

impl ManifestRow {
    fn fits_host(&self) -> bool {
        (self.arch == "any" || self.arch.eq_ignore_ascii_case(&host_arch()))
            && (self.libc == "any" || self.libc.eq_ignore_ascii_case(&host_libc()))
    }
}

// ---- Preflight (PREPARE) ----------------------------------------------
//
// Can this host take the build at all?  Asked before anything changes, so a
// full disk or a read-only directory is an "unable" with a reason an admin can
// act on, not a failed restart.  Each reason starts with a fixed code word
// (disk:, dir:, exe:, exec:, tool:, net:).  Only a probe file is written, and
// it is gone again before this returns.  The instance dir is the cwd.

fn preflight_tool(name: &str) -> bool {
    let path = std::env::var("PATH").ok().filter(|p| !p.is_empty());
    path.as_deref()
        .unwrap_or("/usr/bin:/bin")
        .split(':')
        .filter(|d| !d.is_empty())
        .any(|d| {
            let c = format!("{d}/{name}");
            nix::unistd::access(c.as_str(), nix::unistd::AccessFlags::X_OK).is_ok()
        })
}

fn io_text(e: &std::io::Error) -> String {
    nix::errno::Errno::from_raw(e.raw_os_error().unwrap_or(0))
        .desc()
        .to_string()
}

fn preflight_dir_probe(dir: &str) -> Result<(), String> {
    let (probe, moved) = (".upgrade.probe", ".upgrade.probe2");
    let done = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(probe)?;
        f.write_all(b"x")?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(probe, moved)
    })();
    let _ = std::fs::remove_file(probe);
    let _ = std::fs::remove_file(moved);
    done.map_err(|e| format!("dir: cannot write {}: {}", clip(dir, 160), io_text(&e)))
}

/// The binary must be ours, and not immutable: a hard link fails on that where
/// a rename could not be tried without moving it.  A filesystem with no hard
/// links at all still passes: it is a different errno.
fn preflight_exe(exe: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(exe)
        .map_err(|e| format!("exe: cannot read {}: {}", clip(exe, 160), io_text(&e)))?;
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(format!(
            "exe: cannot replace {}: owned by another user",
            clip(exe, 160)
        ));
    }
    let probe = ".upgrade.probe3";
    let _ = std::fs::remove_file(probe);
    let linked = std::fs::hard_link(exe, probe);
    let _ = std::fs::remove_file(probe);
    if let Err(e) = linked
        && [nix::errno::Errno::EPERM, nix::errno::Errno::EACCES]
            .map(|n| n as i32)
            .contains(&e.raw_os_error().unwrap_or(0))
    {
        return Err(format!(
            "exe: cannot replace {}: {}",
            clip(exe, 160),
            io_text(&e)
        ));
    }
    Ok(())
}

fn clip(s: &str, cap: usize) -> &str {
    let mut end = s.len().min(cap);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Everything the swap will write, plus a margin.  A manifest row without the
/// size column gets a fixed allowance; a source build always gets one on top,
/// for its objects.
fn preflight_space(
    dir: &str,
    exe: &str,
    cfg: &str,
    size: u64,
    is_bin: bool,
    variant: &str,
) -> Result<(), String> {
    use nix::sys::statvfs::{FsFlags, statvfs};
    let Ok(sv) = statvfs(".") else {
        return Ok(()); // unknown: the stage will tell
    };
    if sv.flags().contains(FsFlags::ST_NOEXEC) {
        return Err(format!("exec: {} is mounted noexec", clip(dir, 160)));
    }
    if sv.files() > 0 && sv.files_available() < UPGRADE_MIN_INODES {
        return Err(format!("disk: no free inodes in {}", clip(dir, 160)));
    }
    let mut need = size;
    if need == 0 && is_bin {
        need = UPGRADE_SPACE_BIN_DEFAULT;
    }
    if !is_bin {
        need += if variant == "rs" {
            UPGRADE_SPACE_BUILD_RS
        } else {
            UPGRADE_SPACE_BUILD_C
        };
    }
    need += std::fs::metadata(cfg).map(|m| m.len()).unwrap_or(0);
    need += std::fs::metadata(exe).map(|m| m.len()).unwrap_or(0);
    need += UPGRADE_SPACE_MARGIN;
    let have = sv.blocks_available().saturating_mul(sv.fragment_size());
    if have < need {
        return Err(format!(
            "disk: needs {} MB in {}, has {} MB",
            need / (1024 * 1024) + 1,
            clip(dir, 160),
            have / (1024 * 1024)
        ));
    }
    Ok(())
}

/// HEAD on the artifact.  A server that does not do HEAD says nothing either
/// way, so it passes and the download decides.
fn preflight_artifact(url: &str) -> Result<(), String> {
    let name = clip(url.rsplit('/').next().unwrap_or(url), 120);
    if let Some(path) = file_url_path(url) {
        return std::fs::metadata(path)
            .map(|_| ())
            .map_err(|e| format!("net: cannot reach {name}: {}", io_text(&e)));
    }
    if !tls_ready() {
        return Ok(()); // the manifest read has already said why
    }
    match agent().head(url).call() {
        Ok(_) | Err(ureq::Error::StatusCode(405 | 501)) => Ok(()),
        Err(ureq::Error::StatusCode(code)) => Err(format!("net: {code} from {name}")),
        Err(e) => Err(format!("net: cannot reach {name}: {e}")),
    }
}

fn preflight_host(
    exe: &str,
    cfg: &str,
    url: &str,
    size: u64,
    kind: &str,
    variant: &str,
) -> Result<(), String> {
    let dir = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|_| ".".to_string());
    preflight_space(
        &dir,
        exe,
        cfg,
        size,
        kind.eq_ignore_ascii_case("bin"),
        variant,
    )?;
    preflight_dir_probe(&dir)?;
    preflight_exe(exe)?;
    if nix::unistd::access("/bin/bash", nix::unistd::AccessFlags::X_OK).is_err() {
        return Err("tool: /bin/bash not found".to_string());
    }
    if !preflight_tool("tar") {
        return Err("tool: tar not found".to_string());
    }
    preflight_artifact(url)
}

fn parse_row(line: &str) -> Option<(String, ManifestRow)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 5 {
        return None;
    }
    let caps = [63, 63, 511, 127, 255, 7, 31, 15, 63, 255];
    if f.iter().zip(caps).any(|(s, c)| s.len() > c) {
        return None;
    }
    let at = |i: usize, dflt: &str| f.get(i).copied().unwrap_or(dflt).to_string();
    Some((
        f[0].to_string(),
        ManifestRow {
            url: f[2].to_string(),
            hash: f[3].to_string(),
            kind: at(5, "src"),
            arch: at(6, "any"),
            libc: at(7, "any"),
            min_from: at(8, "*"),
            cpu: at(9, "-"),
            size: f.get(10).and_then(|v| v.parse().ok()).unwrap_or(0),
        },
    ))
}

/// Choose the artifact for `version`: a usable prebuilt binary for this host
/// wins, otherwise a source tarball.
///
/// Build dependencies are NOT checked as the bot's updater does: the hub has
/// no dependency prober, and a source build that cannot compile fails in the
/// upgrade script, which restores the retained binary.
fn manifest_select(manifest: &str, version: &str, variant: &str) -> Result<ManifestRow, String> {
    let mut why = "requested version is not in the manifest".to_string();
    let mut pick: Option<ManifestRow> = None;

    for line in manifest
        .split('\n')
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((row_ver, row)) = parse_row(line) else {
            continue;
        };
        if !version_eq(&row_ver, version) {
            continue;
        }
        if !validate_url(&row.url) {
            why = "untrusted artifact URL in manifest".to_string();
            continue;
        }
        if !row.fits_host() {
            why = "no artifact for this host arch/libc".to_string();
            continue;
        }
        if let Some(f) = cpu_missing(&row.cpu, &host_arch(), host_cpu_features()) {
            why = format!("this CPU lacks {f}, which the {variant} build needs");
            continue;
        }
        if row.min_from != "*"
            && version_cmp(HUB_VERSION, &row.min_from) == std::cmp::Ordering::Less
        {
            why = format!(
                "running version is below the artifact's min_from {}",
                row.min_from
            );
            continue;
        }
        let is_bin = row.kind.eq_ignore_ascii_case("bin");
        pick = Some(row);
        if is_bin {
            break;
        }
    }
    pick.ok_or(why)
}

// ---------------------------------------------------------------------------
// Capability answer (PREPARE)
// ---------------------------------------------------------------------------

/// Is `target_ver` a version this hub could move to at all?  Answered at
/// PREPARE time, before anything is downloaded, so a run's roster is honest
/// about a hub that has no usable artifact.  `min_from` is what the driving
/// hub sent; empty or "*" means the manifest decides.  `Err` is the reason.
/// Multi-version stepping (upgrade plan, Task 7).
///
/// A manifest row may declare a `min_from_version`: the oldest release it is
/// willing to be installed over.  A node further back than that cannot jump
/// straight to the target, so the run walks it there one release at a time.
/// This reads the manifest for ANOTHER node — a bot on its own release tree,
/// or a peer hub — so the host arch/libc filter is deliberately not applied:
/// the node itself picks the artifact when it commits.  Returns the highest
/// version `cur_ver` may take right now on the way to `target_ver`.
pub fn next_step(
    root: &str,
    variant: &str,
    cur_ver: &str,
    target_ver: &str,
) -> Result<String, String> {
    if target_ver.is_empty() {
        return Err("no target version".to_string());
    }
    let root = effective_root(root);
    let var = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    let manifest = fetch_verified_manifest(&format!("{root}/{var}"))?;
    next_step_in(&manifest, cur_ver, target_ver)
        .ok_or_else(|| format!("no release in the manifest can be installed over {cur_ver}"))
}

/// The row-scan behind [`next_step`], split out so it can be tested without a
/// manifest to fetch and a signature to make.
fn next_step_in(manifest: &str, cur_ver: &str, target_ver: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for line in manifest
        .split('\n')
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((row_ver, row)) = parse_row(line) else {
            continue;
        };
        // Strictly forward, and never past where the run is going.
        if version_cmp(&row_ver, cur_ver) != std::cmp::Ordering::Greater {
            continue;
        }
        if version_cmp(&row_ver, target_ver) == std::cmp::Ordering::Greater {
            continue;
        }
        // Reachable from where the node is now.
        if row.min_from != "*" && version_cmp(cur_ver, &row.min_from) == std::cmp::Ordering::Less {
            continue;
        }
        if best
            .as_deref()
            .is_none_or(|b| version_cmp(&row_ver, b) == std::cmp::Ordering::Greater)
        {
            best = Some(row_ver);
        }
    }
    best
}

/// The checks that need no network: version order, variant, min_from and the
/// unattended-restart password file.  Same version is only "already running"
/// when the variant matches too — a different variant is a switch between the
/// C and Rust builds, which is exactly what an admin's "name=c" asks.
fn can_take_local(target_ver: &str, want_variant: &str, min_from: &str) -> Result<(), String> {
    if target_ver.is_empty() {
        return Err("no target version".to_string());
    }
    let same_variant = want_variant == host_variant();
    match version_cmp(target_ver, HUB_VERSION) {
        std::cmp::Ordering::Equal if same_variant => {
            return Err("already running the target version".to_string());
        }
        std::cmp::Ordering::Less => {
            return Err("target is older than the running version".to_string());
        }
        _ => {}
    }
    if !min_from.is_empty()
        && min_from != "*"
        && version_cmp(HUB_VERSION, min_from) == std::cmp::Ordering::Less
    {
        return Err("running version is below the target's min_from".to_string());
    }
    // An unattended restart needs the machine-bound password file; without it
    // the new binary would stop at a password prompt with nobody to answer.
    if !std::path::Path::new(HUB_PASS_FILE).exists() {
        return Err(format!("no {HUB_PASS_FILE}; cannot restart unattended"));
    }
    Ok(())
}

fn bad_url_chars(s: &str) -> bool {
    s.contains([';', '|', '&', '`', '$', ' ', '\t', '\r', '\n'])
}

fn bad_variant(v: &str) -> bool {
    v.is_empty() || v.len() > 7 || v.contains(['/', ';', '|', '&', '`', '$', ' ', '\t', '\r', '\n'])
}

/// Is `target_ver` a version this hub could move to?  Answered at PREPARE
/// time, and it answers everything COMMIT will need short of the download
/// itself: the signed manifest for the wanted variant must verify and list an
/// artifact that fits this host.  A node that says "ready" here and then
/// cannot fetch its artifact at COMMIT is what turns a routine run into an
/// abort, so the question is asked in full up front.  `min_from` is what the
/// driving hub sent; empty or "*" means the manifest decides.  `Err` is the
/// reason.
pub fn can_take(target_ver: &str, variant: &str, min_from: &str) -> Result<(), String> {
    let want_variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    can_take_local(target_ver, want_variant, min_from)?;
    let root = effective_root("");
    if root.len() >= 512 || bad_url_chars(&root) || bad_variant(want_variant) {
        return Err("rejected malformed manifest base or variant".to_string());
    }
    let manifest = quick(|| fetch_verified_manifest(&format!("{root}/{want_variant}")))?;
    let row = match manifest_select(&manifest, target_ver, want_variant) {
        Ok(row) => row,
        // This CPU cannot run the wanted build: say so, and when the OTHER
        // build of the same version fits, say that too.  Never switches.
        Err(why) if why.starts_with("this CPU lacks ") => {
            let other = if want_variant == "c" { "rs" } else { "c" };
            let fits = quick(|| fetch_verified_manifest(&format!("{root}/{other}")))
                .is_ok_and(|m| manifest_select(&m, target_ver, other).is_ok());
            return Err(if fits {
                format!("{why} — the {other} build fits: select this node with ={other}")
            } else {
                why
            });
        }
        Err(why) => return Err(why),
    };
    let name = row.url.rsplit('/').next().unwrap_or(&row.url);
    if !name.starts_with("irchub-") {
        return Err("manifest artifact is not a irchub release".to_string());
    }
    let Ok(exe) = std::env::current_exe() else {
        return Ok(()); // unknown: the commit's own check will say
    };
    preflight_host(
        &exe.display().to_string(),
        HUB_CONFIG_FILE,
        &row.url,
        row.size,
        &row.kind,
        want_variant,
    )
}

/// Does this release have something this host can install: a build for its arch and
/// libc, or source?  An unreadable manifest says nothing either way, so it passes.
pub fn has_build(root: &str, variant: &str, ver: &str, arch: &str, libc: &str) -> bool {
    let base = if root.is_empty() {
        effective_root("")
    } else {
        root.to_string()
    };
    let Ok(manifest) = quick(|| fetch_verified_manifest(&format!("{base}/{variant}"))) else {
        return true;
    };
    manifest.lines().any(|line| {
        if line.starts_with('#') {
            return false;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        f.len() >= 5
            && version_eq(f[0], ver)
            && f.get(6).is_none_or(|a| *a == "any" || *a == arch)
            && f.get(7).is_none_or(|l| *l == "any" || *l == libc)
    })
}

/// One release a manifest lists: its version and date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    pub date: String,
}

/// The distinct versions in a manifest, newest first, at most `max` (the
/// newest kept) — the row scan behind [`list_releases`].
fn releases_in(manifest: &str, max: usize) -> Vec<Release> {
    let mut out: Vec<Release> = Vec::new();
    for line in manifest.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut t = line.split_whitespace();
        let (Some(version), Some(date)) = (t.next(), t.next()) else {
            continue;
        };
        if version.len() > 63 || version.contains(['|', ';', '&', '`', '$']) {
            continue;
        }
        let date: String = date.chars().take(15).collect();
        if out
            .iter()
            .any(|r| version_cmp(&r.version, version) == std::cmp::Ordering::Equal)
        {
            continue;
        }
        if out.len() >= max {
            // Full: keep the newest `max` — replace the oldest if this is newer.
            let Some(oldest) =
                (0..out.len()).min_by(|&a, &b| version_cmp(&out[a].version, &out[b].version))
            else {
                continue;
            };
            if version_cmp(version, &out[oldest].version) != std::cmp::Ordering::Greater {
                continue;
            }
            out[oldest] = Release {
                version: version.to_string(),
                date,
            };
            continue;
        }
        out.push(Release {
            version: version.to_string(),
            date,
        });
    }
    out.sort_by(|a, b| version_cmp(&b.version, &a.version));
    out
}

/// List the distinct versions a release tree offers, newest first — what
/// the console shows so an admin picks a version instead of typing one.  The
/// manifest is signature-verified like any other read of it; an unverifiable
/// one lists nothing.  An empty `root` is this hub's own release root.
pub fn list_releases(root: &str, variant: &str, max: usize) -> Result<Vec<Release>, String> {
    let root = if root.is_empty() {
        effective_root("")
    } else {
        root.to_string()
    };
    if root.len() >= 512 || bad_url_chars(&root) || bad_variant(variant) {
        return Err("malformed release base".to_string());
    }
    let manifest = quick(|| fetch_verified_manifest(&format!("{root}/{variant}")))?;
    Ok(releases_in(&manifest, max))
}

// ---------------------------------------------------------------------------
// Marker and rollback
// ---------------------------------------------------------------------------

/// exec() throws away everything the old process knew, so the upgrade id and
/// the version we were aiming at are left in a file for the new binary to
/// find.  Read exactly once, on the first authenticated peer link after the
/// restart, and removed there.
///
/// `id|version|variant`.  The variant is what makes a C<->Rust switch at the
/// same version checkable: without it the old build, restored by the script's
/// watchdog, would read the marker and report "ok".
pub fn marker_write(upgrade_id: &str, target_ver: &str, variant: &str) -> bool {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(HUB_UPGRADE_MARKER_FILE)
        .and_then(|mut f| f.write_all(format!("{upgrade_id}|{target_ver}|{variant}\n").as_bytes()))
        .is_ok()
}

/// Parse a marker line: `(id, version, variant)`.  A two-field marker (an older
/// build wrote it) has no variant: "".
fn parse_marker(line: &str) -> Option<(String, String, String)> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut f = line.splitn(3, '|');
    let id = f.next().filter(|s| !s.is_empty() && s.len() <= 63)?;
    let ver = f.next().filter(|s| !s.is_empty() && s.len() <= 63)?;
    let variant: String = f.next().unwrap_or("").chars().take(15).collect();
    Some((id.to_string(), ver.to_string(), variant))
}

/// Read and consume the marker.  `None` for every ordinary start.
pub fn take_pending() -> Option<(String, String, String)> {
    let body = std::fs::read_to_string(HUB_UPGRADE_MARKER_FILE).ok();
    // Consumed whatever it said: a marker we cannot parse must not be retried
    // on every reconnect for the rest of this process's life.
    let _ = std::fs::remove_file(HUB_UPGRADE_MARKER_FILE);
    parse_marker(&body?)
}

/// Put back the binary and config an upgrade retained, then restart onto them.
/// Used for CMD_UPGRADE_ABORT: by the time it arrives the new build is already
/// the running process, so undoing it means another exec.  False when there is
/// nothing retained to go back to.
pub fn rollback(state: &mut HubState, reason: &str) -> bool {
    let exe = state.executable_path.clone();
    if exe.is_empty() {
        return false;
    }
    let prev_exe = format!("{exe}{HUB_UPGRADE_PREV_SUFFIX}");
    let prev_cfg = format!("{HUB_CONFIG_FILE}{HUB_UPGRADE_PREV_SUFFIX}");
    if !std::path::Path::new(&prev_exe).exists() {
        crate::hlog_error!("[UPGRADE] Rollback requested ({reason}) but no retained binary\n");
        return false;
    }
    crate::hlog_warning!("[UPGRADE] Rolling back to the retained build: {reason}\n");
    // Config first: if the restart races us, the old binary must not come up
    // against a config only the newer build understands.
    let mut cfg_restored = false;
    if std::path::Path::new(&prev_cfg).exists() {
        cfg_restored = std::fs::rename(&prev_cfg, HUB_CONFIG_FILE).is_ok();
        if !cfg_restored {
            crate::hlog_error!("[UPGRADE] Could not restore {prev_cfg}; keeping the current one\n");
        }
    }
    if std::fs::rename(&prev_exe, &exe).is_err() {
        crate::hlog_error!("[UPGRADE] Could not restore {prev_exe}\n");
        return false;
    }
    let _ = std::fs::remove_file(HUB_UPGRADE_MARKER_FILE);
    failback_clear();

    // Not over a restored config: it is the retained build's own file, and
    // this build would write it in its format (2.5.0+: a PBKDF2 count older
    // builds cannot read).  What changed since comes back from the peers.
    if !cfg_restored {
        config::write(state);
    }
    state.pid_file = None;
    let _ = std::fs::remove_file(HUB_PID_FILE);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let err = Command::new(&exe).exec();
    eprintln!("exec of the restored build failed: {err}");
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

/// One upgrade's failback script, the same text in all four trees.  A node must
/// recover by itself: its admin may have no shell on the host.  It is called from
/// the upgrade script's background loop every 10 s and from a temporary crontab
/// line every minute, which outlives a reboot or a killed loop.  It holds no
/// secrets, and removes itself and the line once the new build confirms or the
/// old one is back.
const FAILBACK_BODY: &str = r##"umask 077
PATH="${PATH:-}:/usr/bin:/bin"; export PATH
cd "$D" 2>/dev/null || exit 1
STATE=.upgrade.state; CONF=.upgrade.confirmed; SELF=${SELF:-.upgrade.failback}
LOCK=.upgrade.lock; TRIES=.upgrade.tries; PREV="$EXE.prev"
FAILTAG="# $PRODUCT:failback:$D:"; PRODTAG="# $PRODUCT:production:$D:"
# A hardened daemon is not dumpable, so its /proc/<pid>/exe cannot be read: the
# pid file and the process name say whether it is ours.
COMM=$(basename "$EXE" | cut -c1-15)
HLOCK="${HOME:-$D}/.irc-cron.lock"
HELD=""

take_lock() {
  i=0; e=0
  while :; do
    if ( set -C; echo $$ >"$1" ) 2>/dev/null; then HELD="$HELD $1"; return 0; fi
    h=$(cat "$1" 2>/dev/null)
    # Empty: its holder may be between create and write; look once more first.
    if [ -z "$h" ] && [ "$e" = 0 ]; then e=1; sleep 1; continue; fi
    e=0
    if [ -n "$h" ] && kill -0 "$h" 2>/dev/null; then
      i=$((i + 1)); [ "$i" -ge "$2" ] && return 1
      sleep 1
    elif ( set -C; echo $$ >"$1.take" ) 2>/dev/null; then
      # Only the holder of $1.take clears a stale $1, and only while it still
      # names the dead holder it saw: two waiters can never both take over.
      [ "$(cat "$1" 2>/dev/null)" = "$h" ] && rm -f "$1"
      rm -f "$1.take"
    else
      t=$(cat "$1.take" 2>/dev/null)
      [ -n "$t" ] && ! kill -0 "$t" 2>/dev/null && rm -f "$1.take"
      i=$((i + 1)); [ "$i" -ge "$2" ] && return 1
      sleep 1
    fi
  done
}
drop_locks() { for l in $HELD; do rm -f "$l"; done; HELD=""; }
trap drop_locks EXIT

clean() { printf '%s' "$1" | tr -d '|\r\n' | cut -c1-160; }
set_state() { # phase pid note
  printf '%s|%s|%s|%s|%s\n' "$ID" "$1" "$(date +%s)" "$2" "$(clean "$3")" >"$STATE.tmp" &&
    mv -f "$STATE.tmp" "$STATE"
}
read_state() {
  rid=""; phase=""; since=0; spid=""; note=""
  [ -f "$STATE" ] || return 1
  IFS='|' read -r rid phase since spid note <"$STATE" || return 1
  [ "$rid" = "$ID" ]
}
pid_now() { [ -f "$PIDF" ] && tr -dc 0-9 <"$PIDF"; }
alive() {
  p=$(pid_now)
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null && [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "$COMM" ]
}
start_exe() { "$EXE" </dev/null >/dev/null 2>&1 & }

# Read, change, write, read back, compare.  Only an answer that says there is
# no crontab counts as empty: any other read error writes nothing, so a bad read
# can never wipe an admin's jobs.  Only a line holding this tag changes, along with
# tagged lines whose directory is gone; every other line stays as it was.
cron_read() { # file
  if ! crontab -l >"$1" 2>"$1.err"; then
    grep -Eqi 'no crontab|no such file|does not exist' "$1.err" || return 1
    : >"$1"
  fi
}
cron_sweep() { # in out
  sed -nE 's/.*# (ircbot|irchub):(production|failback):(\/[^:]*):$/\3/p' "$1" |
    while read -r dd; do [ -d "$dd" ] || printf ':%s:\n' "$dd"; done >"$2.dead"
  if [ -s "$2.dead" ]; then grep -vF -f "$2.dead" "$1" >"$2"; else cp "$1" "$2"; fi
}
cron_edit() { # add|remove tag line
  command -v crontab >/dev/null 2>&1 || return 3
  take_lock "$HLOCK" 15 || return 1
  T=".upgrade.cron.$$"; rc=1; n=0
  while [ "$n" -lt 3 ]; do
    n=$((n + 1))
    cron_read "$T.cur" || break
    if [ "$1" = remove ] && ! grep -qF "$2" "$T.cur"; then rc=0; break; fi
    if [ "$1" = add ] && grep -qF "$2" "$T.cur"; then rc=0; break; fi
    cron_sweep "$T.cur" "$T.swept"
    grep -vF "$2" "$T.swept" >"$T.rest"
    cp "$T.rest" "$T.new"
    [ "$1" = add ] && printf '%s\n' "$3" >>"$T.new"
    crontab "$T.new" >/dev/null 2>&1 || { sleep 1; continue; }
    crontab -l >"$T.chk" 2>/dev/null
    grep -vF "$2" "$T.chk" | grep -v '^# \(DO NOT EDIT\|(\)' >"$T.a"
    grep -v '^# \(DO NOT EDIT\|(\)' "$T.rest" >"$T.b"
    if cmp -s "$T.a" "$T.b"; then
      if [ "$1" = add ]; then grep -qF "$2" "$T.chk" && { rc=0; break; }
      else grep -qF "$2" "$T.chk" || { rc=0; break; }; fi
    fi
    sleep 1
  done
  rm -f "$T".*
  rm -f "$HLOCK"; HELD=$(printf '%s' "$HELD" | sed "s| $HLOCK||")
  return "$rc"
}
fail_line() {
  printf "* * * * * [ -x '%s/%s' ] && '%s/%s' tick >/dev/null 2>&1 %s\n" \
    "$D" "$SELF" "$D" "$SELF" "$FAILTAG"
}
prod_line() {
  printf "*/5 * * * * touch '%s/.cron.seen'; [ -x '%s' ] && '%s' >/dev/null 2>&1 %s\n" \
    "$D" "$EXE" "$EXE" "$PRODTAG"
}
# What this instance's production line is: 0 ours, 10 a hand-written line runs
# this binary, 11 none, 3 no crontab tool, 1 it cannot be read.
cron_status() {
  command -v crontab >/dev/null 2>&1 || return 3
  T=".upgrade.cron.$$"
  cron_read "$T.st" || { rm -f "$T".*; return 1; }
  rc=11
  if grep -qF "$PRODTAG" "$T.st"; then rc=0
  elif grep -vE '^[[:space:]]*#' "$T.st" | grep -qF "$EXE"; then rc=10
  fi
  rm -f "$T".*
  return "$rc"
}
safe_path() { case "$D" in *[!A-Za-z0-9._/-]*) return 1 ;; esac; }

# keep = leave the state file, for the build that has to report it
finish() {
  cron_edit remove "$FAILTAG"
  [ "${1:-}" = keep ] || rm -f "$STATE"
  rm -f "$CONF" "$TRIES" "$SELF" "./$SCRIPT"
  drop_locks
  exit 1
}

restore() { # reason
  read_state
  [ -n "$spid" ] && [ "$spid" != "$PPID" ] && [ "$spid" != "$$" ] && kill "$spid" 2>/dev/null
  if alive; then
    p=$(pid_now); kill "$p" 2>/dev/null
    i=0
    while kill -0 "$p" 2>/dev/null && [ "$i" -lt 5 ]; do sleep 1; i=$((i + 1)); done
    kill -9 "$p" 2>/dev/null
  fi
  if [ ! -f "$PREV" ]; then
    [ -x "$EXE" ] && ! alive && start_exe
    set_state failback-gave-up "" "$1; no previous build retained"
    return
  fi
  mv -f "$EXE" "$EXE.failed" 2>/dev/null
  if ! mv -f "$PREV" "$EXE"; then
    mv -f "$EXE.failed" "$EXE" 2>/dev/null
    set_state failback-gave-up "" "$1; could not restore the previous build"
    return
  fi
  [ -f "$CFG.prev" ] && cp -f "$CFG.prev" "$CFG"
  rm -f "$PIDF"
  set_state restored "" "$1"
  start_exe
}

tick() {
  # Another upgrade's state: it is about to replace this script, so leave it be.
  read_state || { [ -n "$rid" ] && exit 1; finish; }
  now=$(date +%s); age=$((now - since))
  if [ "$now" -ge "$HARD" ]; then
    case "$phase" in
      restored|failback-gave-up) ;;
      *) set_state failback-gave-up "" "the upgrade never finished" ;;
    esac
    finish keep
  fi
  case "$phase" in
    installing)
      if ! kill -0 "$spid" 2>/dev/null; then restore "the install was interrupted"
      elif [ "$age" -ge "$INSTALL_LIMIT" ]; then restore "the install took over $INSTALL_LIMIT s"
      fi ;;
    started)
      if [ -f "$CONF" ] && [ "$(cat "$CONF" 2>/dev/null)" = "$ID" ] && alive; then finish
      elif ! alive; then
        [ "$age" -ge "$WATCH" ] && restore "the new build did not stay up"
      elif [ "$age" -ge "$CONFIRM_LIMIT" ]; then restore "$NOTE within $CONFIRM_LIMIT s"
      fi ;;
    restored)
      alive && finish keep
      t=$(cat "$TRIES" 2>/dev/null); t=$((${t:-0} + 1)); echo "$t" >"$TRIES"
      if [ "$t" -ge 5 ]; then
        set_state failback-gave-up "" "$note; the previous build will not start"
        finish keep
      fi
      start_exe ;;
    failback-gave-up) finish keep ;;
    *) finish ;;
  esac
  return 0
}

# The cron-* arguments are a one-shot helper's: it runs once and removes itself.
case "${1:-tick}" in
  install)
    safe_path || exit 3
    cron_edit add "$FAILTAG" "$(fail_line)"; exit $? ;;
  phase) take_lock "$LOCK" 20 && set_state "$2" "$3" "" ;;
  restore) take_lock "$LOCK" 20 && restore "$2" ;;
  done) take_lock "$LOCK" 20; finish ;;
  # A loop names its upgrade: a loop that outlived it stops here, touching nothing.
  tick) [ -n "${2:-}" ] && [ "$2" != "$ID" ] && exit 1
    take_lock "$LOCK" 2 || exit 0; tick ;;
  cron-status) cron_status; rc=$?; rm -f "$SELF"; exit "$rc" ;;
  cron-on)
    cron_status; rc=$?
    if [ "$rc" = 11 ]; then
      if safe_path; then
        touch .cron.seen
        cron_edit add "$PRODTAG" "$(prod_line)" && cron_status; rc=$?
      else
        rc=4
      fi
    fi
    rm -f "$SELF"; exit "$rc" ;;
  cron-off)
    rc=0
    cron_edit remove "$PRODTAG" || rc=$?
    if [ "$rc" = 0 ]; then rm -f .cron.seen; cron_status; rc=$?; fi
    rm -f "$SELF"; exit "$rc" ;;
  cron-drop)
    rc=0
    cron_edit remove "$PRODTAG" || rc=$?
    cron_edit remove "$FAILTAG" || rc=$?
    if [ "$rc" = 0 ]; then
      cron_status; [ $? = 10 ] && rc=10
    fi
    rm -f "$SELF" .cron.seen; exit "$rc" ;;
esac
exit 0
"##;
const FAILBACK_FILE: &str = ".upgrade.failback";
const FAILBACK_STATE: &str = ".upgrade.state";
const FAILBACK_CONFIRM: &str = ".upgrade.confirmed";

fn failback_quoted(name: &str, value: &str) -> String {
    format!("{name}='{}'\n", value.replace('\'', "'\\''"))
}

/// Run the script with one argument; its exit status, -1 if it could not run.
fn failback_run(arg: &str) -> i32 {
    Command::new(format!("./{FAILBACK_FILE}"))
        .arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(-1)
}

/// Takes the upgrade back out of cron and off the disk.
fn failback_clear() {
    if std::path::Path::new(FAILBACK_FILE).exists() {
        let _ = failback_run("done");
    }
    let _ = std::fs::remove_file(FAILBACK_STATE);
    let _ = std::fs::remove_file(FAILBACK_CONFIRM);
}

/// The new build is up and has proved it can do its job.
pub fn failback_confirm() {
    let Ok(line) = std::fs::read_to_string(FAILBACK_STATE) else {
        return;
    };
    let Some((id, rest)) = line.split_once('|') else {
        return;
    };
    if !rest.starts_with("started|") {
        return;
    }
    let tmp = format!("{FAILBACK_CONFIRM}.tmp");
    if std::fs::write(&tmp, format!("{id}\n")).is_ok() {
        let _ = std::fs::rename(&tmp, FAILBACK_CONFIRM);
    }
}

/// Why this build is running instead of the one asked for: the note the script
/// wrote when it restored it.  Taken once.
pub fn failback_note() -> Option<String> {
    let line = std::fs::read_to_string(FAILBACK_STATE).ok()?;
    let line = line.lines().next()?;
    let (_, rest) = line.split_once('|')?;
    if !rest.starts_with("restored|") && !rest.starts_with("failback-gave-up|") {
        return None;
    }
    let note = rest.rsplit('|').next()?;
    if note.is_empty() {
        return None;
    }
    let out = note.to_string();
    let _ = std::fs::remove_file(FAILBACK_STATE);
    Some(out)
}

// ---- Production crontab line ---------------------------------------------
//
// An instance's keepalive line, tagged "# <product>:production:<dir>:".  Off
// unless a hub says otherwise, and only ever this one tagged line: everything
// else in the crontab is read and left alone.  The script runs as a child, so a
// slow crontab never holds up the event loop.
const CRON_HELPER: &str = ".cron.helper";

struct CronState {
    child: Option<std::process::Child>,
    started: u64,
    next: u64,
    stat: u64,
    wanted: i8, // -1 no hub has said, 0 off, 1 on
    status: String,
    ours: bool,
}

static CRON: std::sync::Mutex<CronState> = std::sync::Mutex::new(CronState {
    child: None,
    started: 0,
    next: 0,
    stat: 0,
    wanted: -1,
    status: String::new(),
    ours: false,
});

fn cron_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cron_note(c: &mut CronState, rc: i32, now: u64) {
    c.ours = rc == 0;
    c.status = match rc {
        0 => "yes",
        10 => "manual",
        _ if rc == 11 || (rc == 3 && c.wanted != 1) => "no",
        3 => "failed:no crontab tool",
        4 => "failed:unsafe path",
        _ => "failed:cannot read crontab",
    }
    .to_string();
    // Ours: look at the stamp in this same pass, so a host whose cron is dead
    // stays "silent" instead of reading "yes" for a minute after every check.
    c.stat = if c.ours { 0 } else { now };
}

/// The helper's work files are `.upgrade.cron.<its pid>.*`: a helper that was
/// killed could not remove them, and they hold a copy of the crontab.
fn cron_work_rm(pid: u32) {
    let pre = format!(".upgrade.cron.{pid}.");
    if let Ok(rd) = std::fs::read_dir(".") {
        for e in rd.flatten() {
            if e.file_name().to_str().is_some_and(|n| n.starts_with(&pre)) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// What `cron_tick` last found: yes, silent, manual, no or failed:<why>.
pub fn cron_status() -> String {
    CRON.lock().map(|c| c.status.clone()).unwrap_or_default()
}

/// A hub's order.
pub fn cron_set(on: bool) {
    if let Ok(mut c) = CRON.lock() {
        let want = i8::from(on);
        if want != c.wanted {
            c.next = 0;
        }
        c.wanted = want;
    }
}

/// True when the status changed, so the hub should hear it.
pub fn cron_tick(exe: &str) -> bool {
    let Ok(mut c) = CRON.lock() else {
        return false;
    };
    let now = cron_now();
    let before = c.status.clone();
    if let Some(child) = c.child.as_mut() {
        let pid = child.id();
        match child.try_wait() {
            Ok(None) => {
                if now.saturating_sub(c.started) > CRON_HELPER_TIMEOUT
                    && let Some(ch) = c.child.as_mut()
                {
                    kill_group(ch);
                }
                return false;
            }
            Ok(Some(st)) => {
                let rc = st.code().unwrap_or(1);
                cron_work_rm(pid);
                c.child = None;
                let _ = std::fs::remove_file(CRON_HELPER);
                cron_note(&mut c, rc, now);
            }
            Err(_) => {
                cron_work_rm(pid);
                c.child = None;
                let _ = std::fs::remove_file(CRON_HELPER);
                cron_note(&mut c, 1, now);
            }
        }
    }
    if now >= c.next && !exe.is_empty() {
        let mut fail = None;
        if c.wanted == 1 && !std::path::Path::new(HUB_PASS_FILE).exists() {
            fail = Some(format!("no {}", HUB_PASS_FILE));
        } else if !failback_write(
            CRON_HELPER,
            exe,
            "",
            true,
            HUB_CONFIG_FILE,
            HUB_PID_FILE,
            HUB_UPGRADE_SCRIPT,
            "",
            CRON_HELPER,
        ) {
            fail = Some("cannot write here".to_string());
        }
        if let Some(why) = fail {
            c.status = format!("failed:{why}");
            c.next = now + CRON_CHECK_SECS;
        } else {
            let arg = match c.wanted {
                1 => "cron-on",
                0 => "cron-off",
                _ => "cron-status",
            };
            if let Ok(child) = Command::new(format!("./{CRON_HELPER}"))
                .arg(arg)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
            {
                c.child = Some(child);
                c.started = now;
            } else {
                let _ = std::fs::remove_file(CRON_HELPER);
                c.status = "failed:cannot start the helper".to_string();
            }
            // Set before it finishes: an order that arrives meanwhile clears this,
            // and must not be overwritten when this child ends.
            c.next = now + CRON_CHECK_SECS;
        }
    }
    // The line stamps .cron.seen each time it runs: no stamp, no cron daemon.
    if c.ours && now.saturating_sub(c.stat) >= 60 {
        c.stat = now;
        let seen = std::fs::metadata(".cron.seen")
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let quiet = seen.is_none_or(|s| now.saturating_sub(s) > CRON_SILENT_SECS);
        c.status = if quiet { "silent" } else { "yes" }.to_string();
    }
    before != c.status
}

/// The node is being deleted: both tagged lines go.  0 gone, 10 gone but a
/// hand-written line still runs this binary, anything else could not.
pub fn cron_drop(exe: &str) -> i32 {
    if let Ok(mut c) = CRON.lock()
        && let Some(mut child) = c.child.take()
    {
        kill_group(&mut child);
        let _ = child.wait();
        cron_work_rm(child.id());
    }
    if !failback_write(
        CRON_HELPER,
        exe,
        "",
        true,
        HUB_CONFIG_FILE,
        HUB_PID_FILE,
        HUB_UPGRADE_SCRIPT,
        "",
        CRON_HELPER,
    ) {
        return 1;
    }
    let rc = Command::new(format!("./{CRON_HELPER}"))
        .arg("cron-drop")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(1);
    let _ = std::fs::remove_file(CRON_HELPER);
    rc
}

/// A keepalive line can fire while an upgrade installs, when no daemon holds the
/// pid lock.  Starting the old build then would make the new one refuse to start,
/// so a start waits that out.  A stale file past its limits stops nothing.
pub fn install_in_progress() -> bool {
    let Ok(line) = std::fs::read_to_string(FAILBACK_STATE) else {
        return false;
    };
    let f: Vec<&str> = line.trim_end().split('|').collect();
    if f.get(1) != Some(&"installing") {
        return false;
    }
    let (Some(since), Some(pid)) = (
        f.get(2).and_then(|v| v.parse::<u64>().ok()),
        f.get(3).and_then(|v| v.parse::<i32>().ok()),
    ) else {
        return false;
    };
    if pid <= 0 || cron_now().saturating_sub(since) > UPGRADE_BUILD_SECS + 60 {
        return false;
    }
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Lay the script down, before anything changes.  The state goes first: a tick
/// that finds none takes the script away again, and exec keeps this pid, so it
/// already names the upgrade script.
/// The script, for one upgrade (FAILBACK_FILE) or one crontab change (CRON_HELPER).
#[allow(clippy::too_many_arguments)]
fn failback_write(
    path: &str,
    exe: &str,
    id: &str,
    is_bin: bool,
    cfg: &str,
    pidf: &str,
    script: &str,
    note: &str,
    self_name: &str,
) -> bool {
    let Some(slash) = exe.rfind('/') else {
        return false;
    };
    let dir = &exe[..slash];
    let install = if is_bin {
        UPGRADE_INSTALL_SECS
    } else {
        UPGRADE_BUILD_SECS
    };
    let now = cron_now();
    let mut text =
        String::from("#!/bin/sh\n# Written by irchub: removes itself.  See its README.\n");
    for (name, value) in [
        ("PRODUCT", "irchub"),
        ("SELF", self_name),
        ("D", dir),
        ("EXE", exe),
        ("ID", id),
        ("CFG", cfg),
        ("PIDF", pidf),
        ("SCRIPT", script),
        ("NOTE", note),
    ] {
        text.push_str(&failback_quoted(name, value));
    }
    text.push_str(&format!(
        "INSTALL_LIMIT={install}\nCONFIRM_LIMIT={UPGRADE_CONFIRM_SECS}\nWATCH={UPGRADE_WATCH_SECS}\nHARD={}\n",
        now + install + UPGRADE_CONFIRM_SECS + UPGRADE_FAILBACK_EXPIRY
    ));
    text.push_str(FAILBACK_BODY);
    let wrote = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .open(path)
        .and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.set_permissions(std::fs::Permissions::from_mode(0o700))
        })
        .is_ok();
    if !wrote {
        let _ = std::fs::remove_file(path);
    }
    wrote
}

fn failback_stage(
    exe: &str,
    id: &str,
    is_bin: bool,
    cfg: &str,
    pidf: &str,
    script: &str,
    note: &str,
) -> bool {
    // The state first: a tick that finds none takes the script away again, and
    // the previous upgrade's loop may still tick.  Its script, finding this
    // upgrade's state, leaves it be.
    let now = cron_now();
    let _ = std::fs::remove_file(FAILBACK_CONFIRM);
    let tmp = format!("{FAILBACK_STATE}.tmp");
    let state = format!("{id}|installing|{now}|{}|\n", std::process::id());
    if std::fs::write(&tmp, state).is_err() || std::fs::rename(&tmp, FAILBACK_STATE).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    // Then the script, whole or not at all: a tick never runs a half-written one.
    let stmp = format!("{FAILBACK_FILE}.tmp");
    if !failback_write(
        &stmp,
        exe,
        id,
        is_bin,
        cfg,
        pidf,
        script,
        note,
        FAILBACK_FILE,
    ) || std::fs::rename(&stmp, FAILBACK_FILE).is_err()
    {
        let _ = std::fs::remove_file(&stmp);
        let _ = std::fs::remove_file(FAILBACK_STATE);
        return false;
    }
    true
}

// ---- Staging -------------------------------------------------------------
//
// Get the new build ready and proven while the old one keeps running.  A thread
// does the work under STAGE_DIR and notes each phase; the event loop reads that
// and tells the hub.  COMMIT then only swaps a file.  Nothing here touches <exe>,
// and everything here is gone again if no COMMIT comes.
const STAGE_DIR: &str = ".upgrade.stage";

#[derive(Default)]
struct StageState {
    gen_id: u64,
    id: String,
    ver: String,
    phase: String,
    code: String,
    note: String,
    started: u64,
    said: u64,
    done: u64,
    ready: bool,
    running: bool,
    changed: bool,
}

static STAGE: std::sync::Mutex<Option<StageState>> = std::sync::Mutex::new(None);
static STAGE_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// The process group of the build `stage_run` runs now (cargo or make and every
/// compiler under it), 0 when none: a stop or the daemon's exit kills it whole.
static STAGE_BUILD_PGID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Kill a child and everything it started: it leads a process group of its own.
fn kill_group(child: &mut std::process::Child) {
    let killed = i32::try_from(child.id()).is_ok_and(|p| {
        nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(p),
            nix::sys::signal::Signal::SIGKILL,
        )
        .is_ok()
    });
    if !killed {
        let _ = child.kill();
    }
}

/// The daemon is exiting, or the stage was called off: the running build goes
/// now, not when the stage thread next looks (the thread dies with the process
/// and would leave it running).
pub fn stage_kill_build() {
    let g = STAGE_BUILD_PGID.swap(0, std::sync::atomic::Ordering::Relaxed);
    if g > 0 {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(g),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

const STAGE_ASIDE: &str = ".upgrade.stage.old.";

/// The stage directory goes at once: renamed aside (so a new stage can start in
/// a clean one straight away, and nothing still writing lands in it), then
/// removed on a thread of its own so the event loop does not sit through a
/// cargo `target/` tree.  If it cannot be renamed, removed here as before.
fn stage_rm() {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    if !std::path::Path::new(STAGE_DIR).exists() {
        return;
    }
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let aside = format!("{STAGE_ASIDE}{}.{n}", std::process::id());
    if std::fs::rename(STAGE_DIR, &aside).is_ok() {
        stage_rm_detached(aside);
    } else {
        let _ = std::fs::remove_dir_all(STAGE_DIR);
    }
}

fn stage_rm_detached(dir: String) {
    if std::thread::Builder::new()
        .spawn({
            let dir = dir.clone();
            move || {
                let _ = std::fs::remove_dir_all(dir);
            }
        })
        .is_err()
    {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// In the thread: one note, unless a newer stage has replaced this one.
fn stage_say(id: u64, phase: &str, code: &str, note: &str) {
    if let Ok(mut g) = STAGE.lock()
        && let Some(s) = g.as_mut()
        && s.gen_id == id
    {
        if s.phase != phase {
            s.changed = true;
        }
        s.phase = phase.to_string();
        s.code = code.to_string();
        s.note = note.replace(['|', '\r', '\n'], " ");
    }
}

fn stage_cancelled(id: u64) -> bool {
    STAGE_GEN.load(std::sync::atomic::Ordering::Relaxed) != id
}

/// A child with a limit, and a way out if the stage is called off.  Err is the
/// first line it wrote, or that it ran out of time.
fn stage_run(id: u64, cmd: &mut Command, limit: u64) -> Result<(), String> {
    let log = format!("{STAGE_DIR}/run.log");
    let out = std::fs::File::create(&log).map_err(|e| e.to_string())?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    STAGE_BUILD_PGID.store(
        i32::try_from(child.id()).unwrap_or(0),
        std::sync::atomic::Ordering::Relaxed,
    );
    let res = stage_wait(id, &mut child, &log, limit);
    // Only ours: a newer stage may already have put its own build here.
    let _ = STAGE_BUILD_PGID.compare_exchange(
        i32::try_from(child.id()).unwrap_or(0),
        0,
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
    );
    res
}

fn stage_wait(
    id: u64,
    child: &mut std::process::Child,
    log: &str,
    limit: u64,
) -> Result<(), String> {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(limit);
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(_)) => {
                let text = std::fs::read_to_string(log).unwrap_or_default();
                return Err(text
                    .lines()
                    .next()
                    .unwrap_or("it exited with an error")
                    .to_string());
            }
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
        if stage_cancelled(id) || std::time::Instant::now() > end {
            kill_group(child);
            let _ = child.wait();
            return Err("ran past its limit".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// One stage's download, in the stage's own thread, saying how far it has got.
fn download_said(id: u64, url: &str, path: &str) -> bool {
    let mut last = -1i64;
    let mut said = std::time::Instant::now() - std::time::Duration::from_secs(60);
    download_with(url, path, &mut |got, total| {
        let pct = (got * 100 / total.max(1)) as i64;
        if pct != last && said.elapsed().as_secs() >= 2 {
            last = pct;
            said = std::time::Instant::now();
            stage_say(id, "fetching", "", &format!("{pct}%"));
        }
    })
}

/// Files make has compiled so far: a top-level .c with its object in place.
fn stage_count_c(dir: &str) -> (usize, usize) {
    let (mut total, mut done) = (0, 0);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(base) = name.to_str().and_then(|n| n.strip_suffix(".c")) else {
            continue;
        };
        if base.is_empty() || base.len() > 198 {
            continue;
        }
        total += 1;
        if ["", "build/", "build/obj/", "obj/"]
            .iter()
            .any(|w| std::path::Path::new(&format!("{dir}/{w}{base}.o")).exists())
        {
            done += 1;
        }
    }
    (total, done)
}

/// Crates cargo has got to, against the packages its lock file names.
fn stage_count_crates(dir: &str) -> (usize, usize) {
    let total = std::fs::read_to_string(format!("{dir}/Cargo.lock"))
        .map(|t| t.lines().filter(|l| l.starts_with("[[package]]")).count())
        .unwrap_or(0);
    let done = std::fs::read_dir(format!("{dir}/target/release/.fingerprint"))
        .map(|rd| {
            rd.flatten()
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .count()
        })
        .unwrap_or(0);
    (total, done)
}

/// How far a build has got, in the words of the note: "40% 18 of 45 files", or
/// "~60% 120 of 200 crates", whose sizes differ too much for more than an estimate.
fn stage_build_note(dir: &str) -> Option<String> {
    let crates = std::path::Path::new(&format!("{dir}/Cargo.toml")).exists();
    let (total, done) = if crates {
        stage_count_crates(dir)
    } else {
        stage_count_c(dir)
    };
    if total == 0 {
        return None;
    }
    let done = done.min(total);
    let pct = (done * 100 / total).min(99);
    Some(if crates {
        format!("~{pct}% {done} of {total} crates")
    } else {
        format!("{pct}% {done} of {total} files")
    })
}

/// `stage_run` for a build: at most one look every 5 s, and a word only on a change.
fn stage_run_build(id: u64, dir: &str, cmd: &mut Command, limit: u64) -> Result<(), String> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = {
        let (stop, dir) = (stop.clone(), dir.to_string());
        std::thread::spawn(move || {
            let mut last = String::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(note) = stage_build_note(&dir)
                    && note != last
                {
                    stage_say(id, "building", "src", &note);
                    last = note;
                }
                for _ in 0..25 {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        })
    };
    let r = stage_run(id, cmd, limit);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = watcher.join();
    r
}

/// The whole job, on its own thread.
fn stage_job(id: u64, ver: &str, variant: &str) -> Result<(), (&'static str, String)> {
    // A run names no variant unless the admin chose one: this host's own, as at PREPARE.
    let variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    stage_say(id, "fetching", "", "");
    let root = effective_root("");
    let manifest = fetch_verified_manifest(&format!("{root}/{variant}")).map_err(|t| {
        (
            if t.contains("signature") {
                "sig"
            } else {
                "net"
            },
            t,
        )
    })?;
    let row = manifest_select(&manifest, ver, variant).map_err(|e| ("build", e))?;
    let is_bin = row.kind.eq_ignore_ascii_case("bin");
    let word = if is_bin { "bin" } else { "src" };
    let archive = format!("{STAGE_DIR}/archive.tar.gz");
    if !download_said(id, &row.url, &archive) {
        return Err(("net", "artifact download failed".to_string()));
    }
    stage_say(id, "verifying", word, "");
    if !crypto::sha256_file_hex(&archive).is_some_and(|h| h.eq_ignore_ascii_case(&row.hash)) {
        return Err(("hash", "artifact SHA-256 mismatch".to_string()));
    }
    let bdir = format!("{STAGE_DIR}/build");
    std::fs::create_dir(&bdir)
        .map_err(|_| ("dir", "could not make the build directory".to_string()))?;
    stage_run(
        id,
        Command::new("tar").args(["-xzf", &archive, "--strip-components=1", "-C", &bdir]),
        120,
    )
    .map_err(|_| ("archive", "could not unpack the artifact".to_string()))?;
    let mut bin = format!("{bdir}/irchub");
    if !is_bin {
        stage_say(id, "building", "src", "");
        let cargo = format!("{bdir}/Cargo.toml");
        let limit = UPGRADE_BUILD_SECS - 60;
        let ran = if std::path::Path::new(&cargo).exists() {
            bin = format!("{bdir}/target/release/irchub");
            stage_run_build(
                id,
                &bdir,
                Command::new("cargo").args(["build", "--release", "--manifest-path", &cargo]),
                limit,
            )
        } else {
            let r = stage_run_build(id, &bdir, Command::new("make").args(["-C", &bdir]), limit);
            if !std::path::Path::new(&bin).exists()
                || std::path::Path::new(&format!("{bdir}/bin/irchub")).exists()
            {
                bin = format!("{bdir}/bin/irchub");
            }
            r
        };
        match ran {
            Err(e) if e.contains("past its limit") => {
                return Err(("build", "the build ran past its limit".to_string()));
            }
            Err(e) => return Err(("build", format!("the build failed: {}", clip(&e, 200)))),
            Ok(()) => {}
        }
    }
    if !std::path::Path::new(&bin).exists() {
        return Err(("archive", "the artifact holds no irchub binary".to_string()));
    }
    let _ = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700));
    stage_say(id, "testing", word, "");
    stage_run(id, Command::new(&bin).arg("-selftest"), SELFTEST_TIMEOUT).map_err(|e| {
        (
            "selftest",
            format!("new build failed its selftest: {}", clip(&e, 200)),
        )
    })?;
    std::fs::rename(&bin, format!("{STAGE_DIR}/new"))
        .map_err(|_| ("dir", "could not keep the staged build".to_string()))?;
    let _ = std::fs::remove_dir_all(&bdir);
    let _ = std::fs::remove_file(&archive);
    stage_say(id, "staged", word, "");
    Ok(())
}

/// A hub's STAGE.  Starting again for the same build is a no-op, so a repeat costs
/// nothing.
pub fn stage_start(id: &str, ver: &str, variant: &str) {
    if let Ok(g) = STAGE.lock()
        && let Some(s) = g.as_ref()
        && s.id == id
        && (s.running || s.ready)
    {
        return;
    }
    stage_clear();
    stage_rm();
    let gen_id = STAGE_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let mut s = StageState {
        gen_id,
        id: id.to_string(),
        ver: ver.to_string(),
        phase: "fetching".to_string(),
        started: cron_now(),
        running: true,
        ..Default::default()
    };
    if std::fs::create_dir(STAGE_DIR).is_err() {
        s.phase = "failed".to_string();
        s.code = "dir".to_string();
        s.note = format!("could not make {STAGE_DIR}");
        s.running = false;
    }
    let go = s.running;
    if let Ok(mut g) = STAGE.lock() {
        *g = Some(s);
    }
    if !go {
        return;
    }
    let (ver, variant) = (ver.to_string(), variant.to_string());
    std::thread::spawn(move || {
        let done = stage_job(gen_id, &ver, &variant);
        if let Err((code, note)) = &done {
            stage_say(gen_id, "failed", code, note);
        }
        if let Ok(mut g) = STAGE.lock()
            && let Some(s) = g.as_mut()
            && s.gen_id == gen_id
        {
            s.running = false;
            s.changed = true;
            s.ready = done.is_ok();
            s.done = cron_now();
        }
    });
}

pub fn stage_clear() {
    STAGE_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    stage_kill_build();
    let had = STAGE.lock().ok().and_then(|mut g| g.take()).is_some();
    if had {
        stage_rm();
    }
}

/// The last report could not be sent (no hub link, or the driver's peer link is
/// down): say the current state again on the next tick.
pub fn stage_unsaid() {
    if let Ok(mut g) = STAGE.lock()
        && let Some(s) = g.as_mut()
    {
        s.said = 0;
    }
}

/// When the hub should hear: the run's id and "phase|code|note".
pub fn stage_tick() -> Option<(String, String)> {
    let now = cron_now();
    let mut expired = false;
    let out = {
        let mut g = STAGE.lock().ok()?;
        let s = g.as_mut()?;
        if s.running && now.saturating_sub(s.started) > UPGRADE_BUILD_SECS {
            s.running = false;
            s.phase = "failed".to_string();
            s.code = "limit".to_string();
            s.note = "the stage ran past its limit".to_string();
            s.changed = true;
            STAGE_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // A failed stage holds nothing worth keeping, and the run may not come back to say so.
        if s.changed && !s.running && s.phase == "failed" {
            stage_rm();
        }
        if s.ready && now.saturating_sub(s.done) > UPGRADE_STAGE_KEEP {
            expired = true;
            None
        } else if s.changed
            || s.said == 0
            || (s.running && now.saturating_sub(s.said) >= UPGRADE_STAGE_BEAT)
        {
            // A beat while it works: silence is how the driver tells a stage has died.
            s.changed = false;
            s.said = now;
            Some((s.id.clone(), format!("{}|{}|{}", s.phase, s.code, s.note)))
        } else {
            None
        }
    };
    if expired {
        stage_clear();
    }
    out
}

/// A stage belongs to one process: whatever a dead one left is rubbish.
pub fn stage_boot_clean() {
    stage_rm();
    // and what an earlier process had set aside but not finished removing
    if let Ok(rd) = std::fs::read_dir(".") {
        for e in rd.flatten() {
            if let Some(n) = e.file_name().to_str()
                && n.starts_with(STAGE_ASIDE)
            {
                stage_rm_detached(n.to_string());
            }
        }
    }
}

/// The staged build for this run, ready to swap in.
fn stage_ready_for(id: &str, ver: &str) -> bool {
    STAGE.lock().ok().is_some_and(|g| {
        g.as_ref()
            .is_some_and(|s| s.ready && s.id == id && s.ver == ver)
    }) && std::path::Path::new(&format!("{STAGE_DIR}/new")).exists()
}

/// The upgrade script.  `kind` decides the middle of it: a prebuilt binary is
/// unpacked and moved into place, a source tarball is compiled first.  Either
/// way the previous binary stays at `<exe>.prev` — the driving hub, not the
/// script, decides whether to keep it.
///
/// It ends in a startup watchdog.  The new build daemonizes, so the script
/// outlives it: start it, give it UPGRADE_WATCH_SECS, and if its daemon is not
/// alive by then put the retained build (and config) back and start that
/// instead.  A build that cannot even come up — a CPU it cannot run on, a
/// config it cannot read — then costs one restart, not a dead node only an
/// admin can revive.  The marker is kept (by the rollback path too), so the
/// old build reports "version-mismatch" on its first peer link and the driver
/// learns of it at once.  The hub execs this script, so OLD_PID is usually
/// the script itself; waiting on it would only burn 30 s of every restart.
fn upgrade_script(pid: u32, kind: &str, archive: &str, exe: &str, selftest: bool) -> String {
    let staged = kind.eq_ignore_ascii_case("staged");
    let tar = if staged {
        String::new()
    } else {
        format!(
            "tar -xzf \"{archive}\" --strip-components=1 -C \"$UPGRADE_DIR\" 2>/dev/null || rollback \"could not extract artifact\"\n"
        )
    };
    let build = if staged {
        // Fetched, built and selftested while the old build ran: only the swap is left.
        format!(
            "NEW_BIN=\"{STAGE_DIR}/new\"\n[ -x \"$NEW_BIN\" ] || rollback \"the staged build is gone\""
        )
    } else if kind.eq_ignore_ascii_case("bin") {
        // Prebuilt: the tarball holds the binary itself, no toolchain needed.
        // No "run it once" probe — irchub has no --version flag and starting a
        // second instance would fight the one we are replacing for the pid
        // lock.  The driving hub is the health monitor.
        r#"NEW_BIN="$UPGRADE_DIR/irchub"
chmod 700 "$NEW_BIN" 2>/dev/null
[ -x "$NEW_BIN" ] || rollback "artifact binary is not executable""#
            .to_string()
    } else {
        r#"cd "$UPGRADE_DIR" || rollback "build directory vanished"
if [ -f Cargo.toml ]; then
  cargo build --release >build.log 2>&1
  BUILT=target/release/irchub
else
  make clean >/dev/null 2>&1
  make >make.log 2>&1
  BUILT=bin/irchub
  [ -f "$BUILT" ] || BUILT=irchub
fi
cd ..
NEW_BIN="$UPGRADE_DIR/$BUILT"
[ -f "$NEW_BIN" ] || rollback "build failed (see $UPGRADE_DIR)""#
            .to_string()
            // A source build is only testable once built: its -selftest runs
            // here, before the mv, for a target that knows the flag.
            + if selftest {
                "\n\"$NEW_BIN\" -selftest </dev/null >/dev/null 2>&1 || rollback \"new build failed its selftest\""
            } else {
                ""
            }
    };
    format!(
        r#"#!/bin/bash
set -u
OLD_PID={pid}
for i in $(seq 1 30); do
  [ "$OLD_PID" = "$$" ] && break
  kill -0 $OLD_PID 2>/dev/null || break
  sleep 1
done
UPGRADE_DIR="./hub_build_tmp"
rm -rf "$UPGRADE_DIR"
mkdir "$UPGRADE_DIR" || exit 1
rollback() {{
  echo "[UPGRADE] FAILED: $1 — restoring previous build"
  ./{FAILBACK_FILE} restore "$1"
  rm -rf "$UPGRADE_DIR" "{archive}"
  wait
  grep -qx "OLD_PID=$OLD_PID" ./{HUB_UPGRADE_SCRIPT} 2>/dev/null && rm -f ./{HUB_UPGRADE_SCRIPT}
  exit 0
}}
./{FAILBACK_FILE} phase installing $$
FB_ID=$(cut -d'|' -f1 <"{FAILBACK_STATE}" 2>/dev/null)
( while ./{FAILBACK_FILE} tick "$FB_ID"; do sleep 10; done ) </dev/null >/dev/null 2>&1 &
{tar}{build}
mv -f "$NEW_BIN" "{exe}" || rollback "could not install new binary"
chmod 700 "{exe}"
rm -f "{HUB_PID_FILE}"
rm -rf "$UPGRADE_DIR" "{archive}" 2>/dev/null
rm -rf {STAGE_DIR} 2>/dev/null
./{FAILBACK_FILE} phase started $$
"{exe}" </dev/null >/dev/null 2>&1
wait
grep -qx "OLD_PID=$OLD_PID" ./{HUB_UPGRADE_SCRIPT} 2>/dev/null && rm -f ./{HUB_UPGRADE_SCRIPT}
exit 0
"#
    )
}

/// Run the upgrade this hub was committed to.  `Err` means nothing was touched
/// (the caller answers CMD_UPGRADE_RESULT fail and stays on the current
/// build); on success this does not return — the process is replaced and
/// reports in after the restart.
pub fn commit(
    state: &mut HubState,
    upgrade_id: &str,
    target_ver: &str,
    variant: &str,
) -> Result<(), String> {
    if state.executable_path.is_empty() {
        return Err("this hub does not know its own executable path".to_string());
    }
    let want_variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    if bad_variant(want_variant) {
        return Err("rejected malformed variant".to_string());
    }
    can_take_local(target_ver, want_variant, "")?;
    // The run picks only the variant subtree under this hub's own root.  That
    // is what lets one run leave each node on its own kind of build — and
    // lets an admin move a hub from the Rust build to the C one.
    let root = effective_root("");
    if root.len() >= 512 || root.contains([';', '|', '&', '`', '$', ' ', '\t', '\r', '\n']) {
        return Err("rejected malformed manifest base".to_string());
    }
    let tree = format!("{root}/{want_variant}");

    crate::hlog_info!(
        "[UPGRADE] Commit {upgrade_id}: {} -> {target_ver} (variant {want_variant})\n",
        HUB_VERSION
    );

    let (row_kind, archive) = if stage_ready_for(upgrade_id, target_ver) {
        crate::hlog_info!("[UPGRADE] Using the build staged for {target_ver}\n");
        ("staged".to_string(), String::new())
    } else {
        stage_clear();
        let manifest = fetch_verified_manifest(&tree)?;
        let row = manifest_select(&manifest, target_ver, want_variant)?;

        let url_name = row
            .url
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("irchub.tar.gz");
        let archive =
            sanitize_filename(url_name).ok_or("artifact filename in manifest is not acceptable")?;

        // Every release artifact is named "<product>-…tar.gz" (see the releases
        // repo README).  A base override that names the OTHER product's tree
        // would otherwise hand this daemon the wrong binary and install it over
        // itself — fail closed here, where nothing has been downloaded yet.
        if !archive.starts_with("irchub-") {
            return Err("manifest artifact is not a irchub release".to_string());
        }

        crate::hlog_info!("[UPGRADE] Fetching {} artifact {archive}\n", row.kind);
        if !download(&row.url, &archive) {
            return Err("artifact download failed".to_string());
        }
        if !crypto::sha256_file_hex(&archive).is_some_and(|h| h.eq_ignore_ascii_case(&row.hash)) {
            let _ = std::fs::remove_file(&archive);
            return Err("artifact SHA-256 mismatch".to_string());
        }
        // Run the new build's own -selftest BEFORE anything is renamed: a build
        // that cannot run here is refused with nothing touched.  A target older
        // than MESH_MIN_VERSION would be refused by every peer and bot.
        if version_cmp(target_ver, MESH_MIN_VERSION) == std::cmp::Ordering::Less {
            let _ = std::fs::remove_file(&archive);
            return Err(format!(
                "target predates {MESH_MIN_VERSION}, the oldest the mesh links with"
            ));
        }
        if row.kind.eq_ignore_ascii_case("bin") {
            crate::hlog_info!("[UPGRADE] Running the new build's selftest\n");
            if let Err(e) = staged_selftest(&archive) {
                let _ = std::fs::remove_file(&archive);
                return Err(format!("new build failed its selftest: {e}"));
            }
        }

        (row.kind.clone(), archive)
    };

    // End the previous upgrade's failback before laying down anything of this
    // one.  Its loop may be inside finish(), which edits cron for a second or
    // more before removing the state, the script and upgrade.sh: whatever this
    // upgrade had written by then would go with them (nightly 2026-11-06).
    // "done" waits on the lock a tick holds, so that tick is over when it returns.
    failback_clear();

    // Flush the live config, then snapshot the pair we may have to restore.
    // The config is copied (this hub still needs it); the binary is renamed,
    // which is atomic and leaves <exe>.prev ready for a rollback.
    let saves = config::saves();
    config::write(state);
    if config::saves() == saves {
        if !archive.is_empty() {
            let _ = std::fs::remove_file(&archive);
        }
        return Err("could not save the config before the swap".to_string());
    }
    let exe = state.executable_path.clone();
    let prev_exe = format!("{exe}{HUB_UPGRADE_PREV_SUFFIX}");
    let prev_cfg = format!("{HUB_CONFIG_FILE}{HUB_UPGRADE_PREV_SUFFIX}");
    if std::fs::copy(HUB_CONFIG_FILE, &prev_cfg).is_err() {
        let _ = std::fs::remove_file(&archive);
        return Err("could not snapshot config for rollback".to_string());
    }
    // Both are copied: <exe> stays in place until the new one is renamed over
    // it, so there is never a moment with no binary there.
    let prev_tmp = format!("{prev_exe}.tmp");
    if std::fs::copy(&exe, &prev_tmp).is_err() || std::fs::rename(&prev_tmp, &prev_exe).is_err() {
        let _ = std::fs::remove_file(&prev_tmp);
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not retain previous binary".to_string());
    }

    // From here a failure is the script's to handle: it restores <exe>.prev
    // and restarts the old build rather than leaving this hub with no binary.
    let script = upgrade_script(std::process::id(), &row_kind, &archive, &exe, true);
    let staged = marker_write(upgrade_id, target_ver, want_variant)
        && OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o700)
            .open(format!("{HUB_UPGRADE_SCRIPT}.tmp"))
            .and_then(|mut f| {
                f.write_all(script.as_bytes())?;
                f.set_permissions(std::fs::Permissions::from_mode(0o700))
            })
            .and_then(|_| std::fs::rename(format!("{HUB_UPGRADE_SCRIPT}.tmp"), HUB_UPGRADE_SCRIPT))
            .map_err(|_| {
                let _ = std::fs::remove_file(format!("{HUB_UPGRADE_SCRIPT}.tmp"));
            })
            .is_ok()
        && failback_stage(
            &exe,
            upgrade_id,
            !row_kind.eq_ignore_ascii_case("src"),
            HUB_CONFIG_FILE,
            HUB_PID_FILE,
            HUB_UPGRADE_SCRIPT,
            "no peer link",
        );
    if !staged {
        failback_clear();
        let _ = std::fs::remove_file(HUB_UPGRADE_MARKER_FILE);
        let _ = std::fs::remove_file(&prev_exe);
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not stage the upgrade script".to_string());
    }

    let cron = failback_run("install");
    if cron != 0 {
        crate::hlog_warning!(
            "[UPGRADE] No cron failback on this host ({cron}): it will not survive a reboot during this upgrade\n"
        );
    }
    crate::hlog_info!("[UPGRADE] Installing {target_ver} and restarting\n");
    state.pid_file = None;
    std::thread::sleep(std::time::Duration::from_secs(1));
    let err = Command::new(format!("./{HUB_UPGRADE_SCRIPT}")).exec();
    // exec failed: <exe> was never moved.
    crate::hlog_info!("[UPGRADE] Could not run {HUB_UPGRADE_SCRIPT}: {err}\n");
    failback_clear();
    let _ = std::fs::remove_file(&prev_exe);
    let _ = std::fs::remove_file(HUB_UPGRADE_MARKER_FILE);
    eprintln!("exec of the upgrade script failed: {err}");
    std::process::exit(1);
}

/// The feature names this host's CPU reports (/proc/cpuinfo `flags` on
/// x86_64, `Features` on aarch64).  Read once.
fn host_cpu_features() -> &'static std::collections::HashSet<String> {
    use std::sync::OnceLock;
    static SET: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        cpuinfo_features(&text)
    })
}

fn cpuinfo_features(text: &str) -> std::collections::HashSet<String> {
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| matches!(k.trim(), "flags" | "Features"))
        .flat_map(|(_, v)| v.split_whitespace().map(str::to_string))
        .collect()
}

/// The first feature a manifest `cpu` column (column 10) needs that `have`
/// lacks on `arch`, or `None`.  "-" or empty = no requirement; an entry may
/// be arch-qualified ("x86_64:avx2") and then applies only on that arch;
/// "neon" is accepted for aarch64's "asimd".
fn cpu_missing<'a>(
    spec: &'a str,
    arch: &str,
    have: &std::collections::HashSet<String>,
) -> Option<&'a str> {
    if spec.is_empty() || spec == "-" {
        return None;
    }
    spec.split(',').filter(|e| !e.is_empty()).find_map(|entry| {
        let feat = match entry.split_once(':') {
            Some((a, f)) if a == arch => f,
            Some(_) => return None,
            None => entry,
        };
        let ok = have.contains(feat) || (feat == "neon" && have.contains("asimd"));
        (!ok).then_some(feat)
    })
}

/// Unpack `archive` into a staging directory and run the binary in it with
/// `-selftest` from the working directory (so it reads this node's config and
/// pass file), killed after SELFTEST_TIMEOUT.  The staging directory is
/// always removed.  `Err` carries the first line of what the build printed.
fn staged_selftest(archive: &str) -> Result<(), String> {
    let dir = "./irchub_selftest_tmp";
    let _ = std::fs::remove_dir_all(dir);
    let out = (|| {
        std::fs::create_dir(dir)
            .map_err(|_| "could not create the staging directory".to_string())?;
        let ok = Command::new("tar")
            .args(["-xzf", archive, "--strip-components=1", "-C", dir])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return Err("could not extract artifact".to_string());
        }
        run_selftest(&format!("{dir}/irchub"))
    })();
    let _ = std::fs::remove_dir_all(dir);
    out
}

/// Run `bin -selftest`, polling for its exit and killing it at the timeout.
fn run_selftest(bin: &str) -> Result<(), String> {
    use std::io::Read;
    let mut child = Command::new(bin)
        .arg("-selftest")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run it ({e})"))?;
    let end = std::time::Instant::now() + std::time::Duration::from_secs(SELFTEST_TIMEOUT);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() < end => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {SELFTEST_TIMEOUT} s"));
            }
        }
    };
    let mut text = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut text);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut text);
    }
    if status.success() {
        return Ok(());
    }
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    Err(if first.is_empty() {
        format!("exited with {status}")
    } else {
        first.chars().take(160).collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    /// The downgrade guard compares through version_cmp, which must ignore a
    /// leading 'v' on either side — strverscmp alone ranks "v0.0.1" above
    /// "2.0" because it compares 'v' against '2'.
    #[test]
    fn version_cmp_ignores_v_prefix() {
        assert_eq!(strverscmp("v0.0.1", "2.0"), Greater);
        assert_eq!(version_cmp("v0.0.1", "2.0"), Less);
        assert_eq!(version_cmp("v2.0", "2.0"), Equal);
        assert_eq!(version_cmp("2.1", "v2.0"), Greater);
        assert_eq!(version_cmp("v2.10.0", "v2.9.1"), Greater);
        assert!(version_eq("v2.0", "2.0"));
    }

    /// A prebuilt binary for this host beats the source row; an unusable
    /// binary row falls back to source rather than failing the upgrade.
    #[test]
    fn manifest_prefers_matching_binary() {
        let src = "v9.0 2026-09-21 https://github.com/x/y/v9.tar.gz aa none src any any *";
        let bin = format!(
            "v9.0 2026-09-21 https://github.com/x/y/v9-bin.tar.gz bb none bin {} {} *",
            host_arch(),
            host_libc()
        );
        let other =
            "v9.0 2026-09-21 https://github.com/x/y/v9-sparc.tar.gz cc none bin sparc64 gnu *";

        let m = format!("# comment\n{src}\n{bin}\n");
        assert_eq!(manifest_select(&m, "9.0", "c").unwrap().kind, "bin");
        let m = format!("{other}\n{src}\n");
        assert_eq!(manifest_select(&m, "v9.0", "c").unwrap().kind, "src");
        let m = format!("{other}\n");
        assert!(manifest_select(&m, "v9.0", "c").is_err());
        assert!(manifest_select(&m, "v1.0", "c").is_err());
    }

    /// min_from is a floor on the version we may upgrade FROM: a row that
    /// demands more than we run is skipped, which is what makes a driving hub
    /// walk the intermediate releases.
    #[test]
    fn manifest_honors_min_from() {
        let row = "v9.0 2026-09-21 https://github.com/x/y/v9.tar.gz aa none src any any 99.0";
        assert!(manifest_select(row, "9.0", "c").is_err());
        let row = "v9.0 2026-09-21 https://github.com/x/y/v9.tar.gz aa none src any any 1.0";
        assert!(manifest_select(row, "9.0", "c").is_ok());
    }

    #[test]
    fn names_and_urls() {
        assert_eq!(
            sanitize_filename("v2.0.tar.gz").as_deref(),
            Some("v2.0.tar.gz")
        );
        assert!(sanitize_filename("evil.sh").is_none());
        assert!(validate_url("https://github.com/x/y/archive/v1.tar.gz"));
        assert!(!validate_url("https://github.com/x;rm"));
        assert!(!validate_url("http://github.com/x"));
        assert!(!validate_url("file:///tmp/x.tar.gz"));
    }

    /// A manifest where 3.0.0 refuses to be installed over anything older
    /// than 2.0.0, so a 1.x node has to go through 2.0.0 first.
    const STEP_MANIFEST: &str = "\
# version date url sha256 deps kind arch libc min_from
v1.5.0 2026-01-01 https://github.com/x/a.tar.gz aa none bin any any *
v2.0.0 2026-02-01 https://github.com/x/b.tar.gz bb none bin any any *
v3.0.0 2026-03-01 https://github.com/x/c.tar.gz cc none bin any any v2.0.0
";

    #[test]
    fn next_step_walks_a_min_from_wall() {
        // 1.0.0 cannot take 3.0.0 (min_from v2.0.0), so it takes 2.0.0 first,
        // and from there the target itself.
        assert_eq!(
            next_step_in(STEP_MANIFEST, "1.0.0", "3.0.0").as_deref(),
            Some("v2.0.0")
        );
        assert_eq!(
            next_step_in(STEP_MANIFEST, "2.0.0", "3.0.0").as_deref(),
            Some("v3.0.0")
        );
    }

    #[test]
    fn next_step_never_passes_the_target_or_goes_back() {
        // The target caps the walk...
        assert_eq!(
            next_step_in(STEP_MANIFEST, "1.0.0", "2.0.0").as_deref(),
            Some("v2.0.0")
        );
        // ...and a node already at or past the target has no step to take.
        assert_eq!(next_step_in(STEP_MANIFEST, "3.0.0", "3.0.0"), None);
        assert_eq!(next_step_in(STEP_MANIFEST, "9.0.0", "3.0.0"), None);
    }

    #[test]
    fn next_step_is_empty_when_nothing_is_reachable() {
        let walled = "v3.0.0 2026-03-01 https://github.com/x/c.tar.gz cc none bin any any v2.0.0\n";
        assert_eq!(next_step_in(walled, "1.0.0", "3.0.0"), None);
    }

    /// A target that is not strictly newer is refused before anything is
    /// fetched, and so is one below its own min_from.
    #[test]
    fn can_take_refuses_non_upgrades() {
        assert!(can_take(HUB_VERSION, "", "").is_err());
        assert!(can_take("0.1", "", "").is_err());
        assert!(can_take("", "", "").is_err());
        assert!(can_take("99.0", "", "98.0").is_err());
        // Same version on the other build is a switch, not "already running"
        // (it then fails later on the password file / manifest, not here).
        assert_eq!(
            can_take_local(HUB_VERSION, host_variant(), "").unwrap_err(),
            "already running the target version"
        );
        assert_ne!(
            can_take_local(HUB_VERSION, "c", "").err().as_deref(),
            Some("already running the target version")
        );
    }

    #[test]
    fn marker_carries_the_variant() {
        assert_eq!(
            parse_marker("abc|2.4.3|c\n"),
            Some(("abc".into(), "2.4.3".into(), "c".into()))
        );
        // A marker an older build wrote has no variant.
        assert_eq!(
            parse_marker("abc|2.4.3\n"),
            Some(("abc".into(), "2.4.3".into(), String::new()))
        );
        assert_eq!(parse_marker("|2.4.3"), None);
        assert_eq!(parse_marker("abc"), None);
    }

    #[test]
    fn releases_are_distinct_and_newest_first() {
        let m = "# c\nv2.4.1 2026-09-23 u h none bin x any *\nv2.4.1 2026-09-23 u2 h none src any any *\nv2.4.10 2026-09-26 u h none bin x any *\nv2.4.2 2026-09-24 u h none bin x any *\n";
        let r = releases_in(m, 24);
        let v: Vec<&str> = r.iter().map(|x| x.version.as_str()).collect();
        assert_eq!(v, ["v2.4.10", "v2.4.2", "v2.4.1"]);
        assert_eq!(r[0].date, "2026-09-26");
        let r = releases_in(m, 2);
        let v: Vec<&str> = r.iter().map(|x| x.version.as_str()).collect();
        assert_eq!(v, ["v2.4.10", "v2.4.2"]);
    }

    #[test]
    fn watchdog_script_shape() {
        let s = upgrade_script(42, "bin", "a.tar.gz", "/x/irchub", true);
        assert!(!s.contains("-selftest"));
        let src = upgrade_script(42, "src", "a.tar.gz", "/x/irchub", true);
        assert!(src.contains(r#""$NEW_BIN" -selftest"#));
        assert!(s.contains(r#"[ "$OLD_PID" = "$$" ] && break"#));
        assert!(s.contains("phase started $$"));
        // Neither rollback path removes the marker.
        assert!(!s.contains(HUB_UPGRADE_MARKER_FILE));
    }

    #[test]
    fn cpu_column() {
        let have = cpuinfo_features(
            "processor\t: 0\nflags\t\t: fpu aes pclmulqdq avx\n\nprocessor\t: 1\nflags\t\t: fpu aes\n",
        );
        assert_eq!(cpu_missing("-", "x86_64", &have), None);
        assert_eq!(cpu_missing("", "x86_64", &have), None);
        assert_eq!(cpu_missing("aes,pclmulqdq,avx", "x86_64", &have), None);
        assert_eq!(cpu_missing("aes,avx2,bmi1", "x86_64", &have), Some("avx2"));
        assert_eq!(
            cpu_missing("aarch64:sha2,x86_64:avx", "x86_64", &have),
            None
        );
        assert_eq!(
            cpu_missing("aarch64:sha2,x86_64:adx", "x86_64", &have),
            Some("adx")
        );
        let arm = cpuinfo_features("Features\t: fp asimd aes pmull sha2\n");
        assert_eq!(cpu_missing("neon,aes,pmull,sha2", "aarch64", &arm), None);
        assert_eq!(
            cpu_missing("x86_64:avx2,aarch64:neon", "aarch64", &arm),
            None
        );
    }

    #[test]
    fn cpu_column_missing_is_none() {
        let (_, row) =
            parse_row("v9.0 2026-09-20 https://github.com/x/y/v9.tar.gz aa none src any any *")
                .unwrap();
        assert_eq!(row.cpu, "-");
        let (_, row) = parse_row(
            "v9.0 2026-09-20 https://github.com/x/y/v9.tar.gz aa none bin x86_64 any * aes,avx2",
        )
        .unwrap();
        assert_eq!(row.cpu, "aes,avx2");
    }
}
