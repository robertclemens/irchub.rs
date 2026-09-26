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
use std::sync::RwLock;

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

/// The release tree the driving hub named at COMMIT time.  The C twin puts it
/// in the environment (`setenv`); `#![forbid(unsafe_code)]` rules
/// `std::env::set_var` out here, so it lives in a process-global that
/// `env_base()` consults ahead of the env var.  Same effect, same
/// verification: only the github/https host allow-list is relaxed, never the
/// signature or the hash.
static DRIVER_BASE: RwLock<String> = RwLock::new(String::new());

fn set_driver_base(base: &str) -> bool {
    match DRIVER_BASE.write() {
        Ok(mut slot) => {
            slot.clear();
            slot.push_str(base);
            true
        }
        Err(_) => false,
    }
}

/// A non-empty override repoints the updater at a local irchub-releases tree
/// (the sandboxed testnet uses a `file://` base with no outbound network).
fn env_base() -> Option<String> {
    if let Ok(b) = DRIVER_BASE.read()
        && !b.is_empty()
    {
        return Some(b.clone());
    }
    std::env::var("IRCHUB_UPDATE_BASE")
        .ok()
        .filter(|s| !s.is_empty())
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

/// The base a run works against: what the driver named, else the operator's
/// env override, else the compiled-in root.
fn effective_root(base: &str) -> String {
    if !base.is_empty() {
        return base.to_string();
    }
    env_base().unwrap_or_else(|| HUB_UPDATE_BASE.to_string())
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
    url.starts_with("https://")
        && (url.contains("github.com") || url.contains("githubusercontent.com"))
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

/// Manifest reads made from the event loop (a PREPARE answer, the hub_admin
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
    let ok = std::io::copy(&mut reader, &mut f).is_ok() && f.flush().is_ok();
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
    // Pinned key, unless the local-source override is active AND a test key is
    // provided (sandbox only): IRCHUB_UPDATE_PUBKEY is honoured solely when
    // the base override is set, so production always uses the compiled key.
    let pubkey_b64: String = match (env_base(), std::env::var("IRCHUB_UPDATE_PUBKEY")) {
        (Some(_), Ok(k)) if !k.is_empty() => k,
        _ => HUB_UPDATE_PUBKEY_B64.to_string(),
    };
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
}

impl ManifestRow {
    fn fits_host(&self) -> bool {
        (self.arch == "any" || self.arch.eq_ignore_ascii_case(&host_arch()))
            && (self.libc == "any" || self.libc.eq_ignore_ascii_case(&host_libc()))
    }
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
    base: &str,
    variant: &str,
    cur_ver: &str,
    target_ver: &str,
) -> Result<String, String> {
    if target_ver.is_empty() {
        return Err("no target version".to_string());
    }
    let root = effective_root(base);
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
pub fn can_take(target_ver: &str, variant: &str, min_from: &str, base: &str) -> Result<(), String> {
    let want_variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    can_take_local(target_ver, want_variant, min_from)?;
    let root = effective_root(base);
    if root.len() >= 512 || bad_url_chars(&root) || bad_variant(want_variant) {
        return Err("rejected malformed manifest base or variant".to_string());
    }
    // A run's base travels the way the operator's override does, so artifact
    // URLs under it validate here exactly as they will at COMMIT.
    if !base.is_empty() && !set_driver_base(base) {
        return Err("could not record the driver's manifest base".to_string());
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
    Ok(())
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
/// hub_admin shows so an admin picks a version instead of typing one.  The
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
    if std::path::Path::new(&prev_cfg).exists()
        && std::fs::rename(&prev_cfg, HUB_CONFIG_FILE).is_err()
    {
        crate::hlog_error!("[UPGRADE] Could not restore {prev_cfg}; keeping the current one\n");
    }
    if std::fs::rename(&prev_exe, &exe).is_err() {
        crate::hlog_error!("[UPGRADE] Could not restore {prev_exe}\n");
        return false;
    }
    let _ = std::fs::remove_file(HUB_UPGRADE_MARKER_FILE);

    config::write(state);
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
fn upgrade_script(
    pid: u32,
    kind: &str,
    archive: &str,
    prev: &str,
    exe: &str,
    selftest: bool,
) -> String {
    let build = if kind.eq_ignore_ascii_case("bin") {
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
  mv -f "{prev}" "{exe}" 2>/dev/null
  rm -f "{HUB_PID_FILE}"
  rm -rf "$UPGRADE_DIR" "{archive}"
  exec "{exe}"
}}
tar -xzf "{archive}" --strip-components=1 -C "$UPGRADE_DIR" 2>/dev/null || rollback "could not extract artifact"
{build}
mv -f "$NEW_BIN" "{exe}" || rollback "could not install new binary"
chmod 700 "{exe}"
rm -f "{HUB_PID_FILE}"
rm -rf "$UPGRADE_DIR" "{archive}" 2>/dev/null
"{exe}" </dev/null >/dev/null 2>&1
sleep {UPGRADE_WATCH_SECS}
P=$(cat "{HUB_PID_FILE}" 2>/dev/null | tr -dc 0-9)
if [ -z "$P" ] || ! kill -0 "$P" 2>/dev/null; then
  echo "[UPGRADE] new build did not stay up — restoring previous build"
  mv -f "{exe}" "{exe}.failed" 2>/dev/null
  mv -f "{prev}" "{exe}" || exit 1
  [ -f "{HUB_CONFIG_FILE}{HUB_UPGRADE_PREV_SUFFIX}" ] && cp -f "{HUB_CONFIG_FILE}{HUB_UPGRADE_PREV_SUFFIX}" "{HUB_CONFIG_FILE}"
  rm -f "{HUB_PID_FILE}" "./{HUB_UPGRADE_SCRIPT}"
  exec "{exe}"
fi
rm -f "./{HUB_UPGRADE_SCRIPT}"
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
    base: &str,
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
    // The driving hub names the release tree ROOT; the variant picks the
    // subtree.  That is what lets one run leave each node on its own kind of
    // build — and lets an admin move a hub from the Rust build to the C one.
    let root = effective_root(base);
    if root.len() >= 512 || root.contains([';', '|', '&', '`', '$', ' ', '\t', '\r', '\n']) {
        return Err("rejected malformed manifest base".to_string());
    }
    if !base.is_empty() && !set_driver_base(base) {
        return Err("could not record the driver's manifest base".to_string());
    }
    let tree = format!("{root}/{want_variant}");

    crate::hlog_info!(
        "[UPGRADE] Commit {upgrade_id}: {} -> {target_ver} (variant {want_variant})\n",
        HUB_VERSION
    );

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
    // that cannot run here is refused with nothing touched.  Only a build new
    // enough to know the flag is asked — an older one would start a second
    // daemon instead.
    let selftest = version_cmp(target_ver, SELFTEST_MIN_HUB) != std::cmp::Ordering::Less;
    if row.kind.eq_ignore_ascii_case("bin") && selftest {
        crate::hlog_info!("[UPGRADE] Running the new build's selftest\n");
        if let Err(e) = staged_selftest(&archive) {
            let _ = std::fs::remove_file(&archive);
            return Err(format!("new build failed its selftest: {e}"));
        }
    }

    // Flush the live config, then snapshot the pair we may have to restore.
    // The config is copied (this hub still needs it); the binary is renamed,
    // which is atomic and leaves <exe>.prev ready for a rollback.
    config::write(state);
    let exe = state.executable_path.clone();
    let prev_exe = format!("{exe}{HUB_UPGRADE_PREV_SUFFIX}");
    let prev_cfg = format!("{HUB_CONFIG_FILE}{HUB_UPGRADE_PREV_SUFFIX}");
    if std::fs::copy(HUB_CONFIG_FILE, &prev_cfg).is_err() {
        let _ = std::fs::remove_file(&archive);
        return Err("could not snapshot config for rollback".to_string());
    }
    if std::fs::rename(&exe, &prev_exe).is_err() {
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not retain previous binary".to_string());
    }

    // From here a failure is the script's to handle: it restores <exe>.prev
    // and restarts the old build rather than leaving this hub with no binary.
    let script = upgrade_script(
        std::process::id(),
        &row.kind,
        &archive,
        &prev_exe,
        &exe,
        selftest,
    );
    let staged = marker_write(upgrade_id, target_ver, want_variant)
        && OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o700)
            .open(HUB_UPGRADE_SCRIPT)
            .and_then(|mut f| {
                f.write_all(script.as_bytes())?;
                f.set_permissions(std::fs::Permissions::from_mode(0o700))
            })
            .is_ok();
    if !staged {
        let _ = std::fs::remove_file(HUB_UPGRADE_MARKER_FILE);
        let _ = std::fs::rename(&prev_exe, &exe);
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not stage the upgrade script".to_string());
    }

    crate::hlog_info!("[UPGRADE] Installing {target_ver} and restarting\n");
    state.pid_file = None;
    std::thread::sleep(std::time::Duration::from_secs(1));
    let err = Command::new(format!("./{HUB_UPGRADE_SCRIPT}")).exec();
    // exec failed: put the old binary back so this hub is not left dead.
    let _ = std::fs::rename(&prev_exe, &exe);
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
        assert!(can_take(HUB_VERSION, "", "", "").is_err());
        assert!(can_take("0.1", "", "", "").is_err());
        assert!(can_take("", "", "", "").is_err());
        assert!(can_take("99.0", "", "98.0", "").is_err());
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
        let s = upgrade_script(42, "bin", "a.tar.gz", "/x/irchub.prev", "/x/irchub", true);
        assert!(!s.contains("-selftest"));
        let src = upgrade_script(42, "src", "a.tar.gz", "/x/irchub.prev", "/x/irchub", true);
        assert!(src.contains(r#""$NEW_BIN" -selftest"#));
        assert!(s.contains(r#"[ "$OLD_PID" = "$$" ] && break"#));
        assert!(s.contains(&format!("sleep {UPGRADE_WATCH_SECS}")));
        assert!(s.contains(r#"mv -f "/x/irchub" "/x/irchub.failed""#));
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
