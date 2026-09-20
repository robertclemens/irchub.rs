//! hub_encrypt — encrypt a plaintext irchub config.
//!
//! Usage: `hub_encrypt [plaintext_file] [output_file]`
//!        (defaults: config.txt, .irchub.cnf)
//!
//! The password is prompted for after start-up, twice, with echo off — or
//! read once as the first line of stdin when stdin is not a terminal.  It is
//! never taken from argv.  The output is written 0600 to a temp file and
//! renamed into place, as `config::write` does, so a failure never leaves a
//! truncated config behind.

#![forbid(unsafe_code)]

use irchub::consts::*;
use irchub::tool::{HUB_TOOL_HDR_LEN, HUB_TOOL_MAX_CONFIG};
use irchub::{crypto, tool};

fn usage(argv0: &str) {
    eprintln!(
        "Usage: {argv0} [plaintext_file] [output_file]   (defaults: config.txt, {HUB_CONFIG_FILE})\n\
         Prompts for the config password (twice), then writes the encrypted config.\n\
         With stdin not a terminal, the first line of stdin is the password."
    );
}

/// `config::load` reads "key|value" (or "key:value") lines and skips the
/// rest; every usable config has some.  Ciphertext almost always contains a
/// NUL (large files) or has no such line (small ones), so together these
/// catch an already-encrypted input without rejecting any config the hub
/// accepts.
fn looks_like_plain_config(p: &[u8]) -> bool {
    if p.contains(&0) {
        return false;
    }
    for line in p.split(|&c| c == b'\n') {
        let k = line
            .iter()
            .take_while(|&&c| c.is_ascii_alphabetic() || c == b'_')
            .count();
        if k > 0 && k < line.len() && (line[k] == b'|' || line[k] == b':') {
            return true;
        }
    }
    false
}

fn main() {
    tool::harden_process();

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 3 || args.iter().skip(1).any(|a| a.starts_with('-')) {
        usage(&args[0]);
        std::process::exit(1);
    }
    let in_path = args.get(1).map_or("config.txt", String::as_str);
    let out_path = args.get(2).map_or(HUB_CONFIG_FILE, String::as_str);

    let Some(plain) = tool::read_file(in_path, 1, HUB_TOOL_MAX_CONFIG) else {
        std::process::exit(1);
    };
    if !looks_like_plain_config(&plain) {
        eprintln!(
            "Error: '{in_path}' does not look like a plaintext config (no \"key|value\" lines; already encrypted?)."
        );
        std::process::exit(1);
    }

    let Some(password) = tool::read_password("New config password: ", MAX_PASS) else {
        std::process::exit(1);
    };
    if nix::unistd::isatty(std::io::stdin()).unwrap_or(false) {
        let Some(confirm) = tool::read_password("Confirm password: ", MAX_PASS) else {
            std::process::exit(1);
        };
        if *password != *confirm {
            eprintln!("Error: passwords do not match.");
            std::process::exit(1);
        }
    }

    // A fresh random salt and IV every run.  GCM IV reuse under one key is
    // catastrophic, so an RNG failure aborts rather than falling back.
    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; GCM_IV_LEN];
    if !crypto::random_bytes(&mut salt) || !crypto::random_bytes(&mut iv) {
        eprintln!("Error: RNG failure; nothing written.");
        std::process::exit(1);
    }
    let key = crypto::derive_config_key(password.as_bytes(), &salt);
    drop(password);

    let Some((ct, tag)) = crypto::gcm_encrypt_detached(key.as_ref(), &iv, &[], &plain) else {
        eprintln!("Error: encryption failed.");
        std::process::exit(1);
    };

    // salt | iv | tag | ciphertext, assembled in one buffer.
    let mut out = Vec::with_capacity(HUB_TOOL_HDR_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);

    if !tool::write_atomic(out_path, &out) {
        std::process::exit(1);
    }
    eprintln!("Encrypted {} bytes to '{out_path}' (0600).", plain.len());
}
