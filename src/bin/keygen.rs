//! keygen — Curve25519 keypair generator for ircbot / irchub users and bots.
//!
//! The Rust twin of the shared C `keygen.c` (kept byte-identical as
//! irchub/keygen.c and ircbot/utils/keygen.c).  The file format it produces
//! is the contract, and that is unchanged:
//!
//! ```text
//! YYYYMMDDHHMMSS_<name>.private.b64   mode 0600  base64(ed25519_priv || x25519_priv)
//! YYYYMMDDHHMMSS_<name>.public.b64    mode 0644  base64(ed25519_pub  || x25519_pub)
//! ```
//!
//! It prints the public key and its fingerprint (the first 8 bytes of
//! SHA-256(pub), "ab12:cd34:ef56:7890") — never the private key.
//!
//! The public key is what an admin adds with hub_admin / +admin / +oper; the
//! private key stays on the user's machine for hub_admin and the IRC client
//! scripts.  See irchub/docs/passwordless.md.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use zeroize::Zeroizing;

use irchub::consts::COMBINED_KEY_LEN;
use irchub::{crypto, tool};

const KEYGEN_VERSION: &str = "1";
const NAME_MAX_LEN: usize = 32;

/// `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$` — safe as a filename component.
fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > NAME_MAX_LEN {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| {
        c.is_ascii_alphanumeric() || c == b'_' || (i > 0 && (c == b'.' || c == b'-'))
    })
}

/// Create `path` exclusively with `mode` and write `text` + "\n".  O_EXCL
/// refuses to replace an existing file or follow a symlink planted at that
/// name.
fn write_new(path: &str, mode: u32, text: &str) -> bool {
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path);
    let mut f = match f {
        Ok(f) => f,
        Err(e) => {
            eprintln!("keygen: cannot create {path}: {e}");
            return false;
        }
    };
    // Independent of the caller's umask.
    let _ = f.set_permissions(std::fs::Permissions::from_mode(mode));
    let ok =
        f.write_all(text.as_bytes()).is_ok() && f.write_all(b"\n").is_ok() && f.sync_all().is_ok();
    drop(f);
    if !ok {
        eprintln!("keygen: writing {path} failed");
        let _ = std::fs::remove_file(path);
    }
    ok
}

fn usage() {
    eprintln!(
        "Usage: keygen [name]\n\
         Generates a Curve25519 (Ed25519 + X25519) keypair as\n\
         \x20 YYYYMMDDHHMMSS_<name>.private.b64  (0600, keep it; used by\n\
         \x20                                     hub_admin and IRC scripts)\n\
         \x20 YYYYMMDDHHMMSS_<name>.public.b64   (give this to an admin)\n\
         Without [name] it asks for one. Names: letters, digits, _ . -\n\
         (max {NAME_MAX_LEN}, not starting with . or -)."
    );
}

fn main() {
    // Keep the private key out of core dumps and away from same-uid ptrace.
    tool::harden_process();

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 || (args.len() == 2 && (args[1] == "-h" || args[1] == "--help")) {
        usage();
        std::process::exit(i32::from(args.len() > 2));
    }

    let name = if args.len() == 2 {
        args[1].clone()
    } else {
        let n = tool::prompt_line("Key name (e.g. your nick): ", 128);
        if n.is_empty() {
            eprintln!("keygen: no name given");
            std::process::exit(1);
        }
        n
    };
    if !valid_name(&name) {
        eprintln!(
            "keygen: invalid name '{name}' — use letters, digits, _ . - (max {NAME_MAX_LEN}, not starting with . or -)"
        );
        std::process::exit(1);
    }

    let stamp = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let priv_path = format!("{stamp}_{name}.private.b64");
    let pub_path = format!("{stamp}_{name}.public.b64");

    let Some((priv_key, pub_key)) = crypto::generate_combined_keypair() else {
        eprintln!("keygen: key generation failed");
        std::process::exit(1);
    };
    let priv_b64 = Zeroizing::new(crypto::b64_encode(priv_key.as_ref()));
    let pub_b64 = crypto::b64_encode(&pub_key);

    if !write_new(&priv_path, 0o600, &priv_b64) {
        std::process::exit(1);
    }
    if !write_new(&pub_path, 0o644, &pub_b64) {
        // Never leave half a pair behind.
        let _ = std::fs::remove_file(&priv_path);
        std::process::exit(1);
    }

    let fp = {
        let mut raw = [0u8; COMBINED_KEY_LEN];
        raw.copy_from_slice(&pub_key);
        crypto::key_fingerprint(&raw)
    };

    println!("Generated Curve25519 keypair (keygen v{KEYGEN_VERSION}) for '{name}':");
    println!("  private: {priv_path}  (mode 0600 — keep it secret, keep it here)");
    println!("  public:  {pub_path}");
    println!("  public key:  {pub_b64}");
    println!("  fingerprint: {fp}\n");
    println!("Next:");
    println!("  - Give the PUBLIC key to an admin: hub_admin 'Add Admin/Oper' or");
    println!("    'Change user public key', or IRC '+admin|+oper <name> <pubkey> <mask>'.");
    println!("  - Admins log into the hub with: hub_admin <ip> <port> {priv_path}");
    println!("  - Point your IRC client script (ircbot/utils) at {priv_path}");
}
