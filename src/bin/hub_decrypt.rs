//! hub_decrypt — dump a decrypted irchub config.
//!
//! Usage: `hub_decrypt [config_file]` (default: .irchub.cnf)
//!
//! The password is prompted for after start-up (echo off), or read as the
//! first line of stdin when stdin is not a terminal — never taken from argv.
//! stdout carries the raw plaintext and nothing else, byte for byte (no
//! banner, no framing), so it can be redirected or piped; the prompt goes to
//! the terminal, errors to stderr.

#![forbid(unsafe_code)]

use std::io::Write;

use irchub::consts::*;
use irchub::tool::{HUB_TOOL_HDR_LEN, HUB_TOOL_MAX_CONFIG};
use irchub::{crypto, tool};

fn usage(argv0: &str) {
    eprintln!(
        "Usage: {argv0} [config_file]   (default: {HUB_CONFIG_FILE})\n\
         Prompts for the config password, then writes the raw plaintext to stdout.\n\
         With stdin not a terminal, the first line of stdin is the password."
    );
}

fn main() {
    tool::harden_process();

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 || (args.len() == 2 && args[1].starts_with('-')) {
        usage(&args[0]);
        std::process::exit(1);
    }
    let path = if args.len() == 2 {
        args[1].as_str()
    } else {
        HUB_CONFIG_FILE
    };

    // Read the file first so a bad path fails before the user types anything.
    let Some(file) = tool::read_file(
        path,
        HUB_TOOL_HDR_LEN + 1,
        HUB_TOOL_HDR_LEN + HUB_TOOL_MAX_CONFIG,
    ) else {
        std::process::exit(1);
    };

    let salt = &file[..SALT_SIZE];
    let iv = &file[SALT_SIZE..SALT_SIZE + GCM_IV_LEN];
    let tag = &file[SALT_SIZE + GCM_IV_LEN..HUB_TOOL_HDR_LEN];
    let ct = &file[HUB_TOOL_HDR_LEN..];

    let Some(password) = tool::read_password("Config password: ", MAX_PASS) else {
        std::process::exit(1);
    };
    let key = crypto::derive_config_key(password.as_bytes(), salt);
    drop(password);

    // GCM authenticates here: nothing is released unless the tag verifies.
    let Some(plain) = crypto::gcm_decrypt_detached(key.as_ref(), iv, &[], ct, tag) else {
        eprintln!(
            "Error: decryption failed (wrong password, or the file is corrupt or not an irchub config)."
        );
        std::process::exit(1);
    };

    let mut out = std::io::stdout();
    if out.write_all(&plain).is_err() || out.flush().is_err() {
        eprintln!("Error: writing to stdout.");
        std::process::exit(1);
    }
}
