//! irchub: the encrypted hub mesh ircbot connects to (safe-Rust port of the
//! C irchub).  The daemon lives in `main.rs`; everything it shares with
//! `hub_admin`, `keygen`, `hub_encrypt` and `hub_decrypt` is here.
//!
//! Module map against the C tree (see docs/ARCHITECTURE_RUST.md):
//!
//! | C file            | Rust module(s)                                    |
//! |-------------------|---------------------------------------------------|
//! | `hub.h`           | `consts` (wire contract), `state` (records, rules) |
//! | `hub_crypto.c`    | `crypto`                                          |
//! | `hub_storage.c`   | `storage`                                         |
//! | `hub_config.c`    | `config`                                          |
//! | `hub_main.c`      | `main.rs`, `logging`, `net`                       |
//! | `hub_logic.c`     | `queue`, `ratelimit`, `auth`, `presence`, `mesh`, |
//! |                   | `opflow`, `admin`, `client`                       |
//! | `hub_tool.h`      | `tool`                                            |
//! | `hub_admin.c`     | `bin/hub_admin.rs`                                |
//! | `keygen.c`        | `bin/keygen.rs`                                   |
//! | `hub_encrypt.c`   | `bin/hub_encrypt.rs`                              |
//! | `hub_decrypt.c`   | `bin/hub_decrypt.rs`                              |
//!
//! `cstr` and `secret` have no C counterpart of their own: they hold the
//! libc string semantics the protocol parsers depend on and the mlock'd
//! secret buffers, and are kept in step with ircbot.rs.

#![forbid(unsafe_code)]

pub mod admin;
pub mod auth;
pub mod client;
pub mod config;
pub mod consts;
pub mod crypto;
pub mod cstr;
pub mod logging;
pub mod mesh;
pub mod net;
pub mod opflow;
pub mod presence;
pub mod queue;
pub mod ratelimit;
pub mod secret;
pub mod state;
pub mod storage;
pub mod tool;
