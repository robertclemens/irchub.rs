//! hub_admin — the interactive console for one hub (hub_admin.c).
//!
//! Login is passwordless (docs/passwordless.md §6): the hub is asked for its
//! X25519 key, its UUID and a one-time challenge with `ADMIN-HELLO`, and the
//! reply is signed with the admin's Ed25519 key inside a sealed box whose
//! ephemeral key gives the session forward secrecy.  There is no username and
//! no password — the hub finds the admin record by the key.
//!
//! Every frame afterwards is `len(4, BE) || AES-256-GCM(iv || ct || tag)`
//! under the session key.  A command carries the `cmd || inner_len ||
//! payload` envelope; a reply is the bare response text, except for the hub's
//! keepalive, which is a CMD_PING envelope this client answers in kind.

#![forbid(unsafe_code)]

use std::io::Write;
use std::net::TcpStream;
use std::os::fd::AsFd;

use zeroize::Zeroizing;

use irchub::consts::*;
use irchub::crypto::Key32;
use irchub::{crypto, net, tool};

/// Upper bound for any valid hub packet: a 65536-byte plaintext + IV + tag.
const MAX_HUB_PACKET: usize = 65536 + GCM_IV_LEN + GCM_TAG_LEN + 64;
const ADMIN_INFO: &[u8] = b"irchub-admin-session-v2";
const RULE_H: &str = "═══════════════════════════════════════════════════";

struct Admin {
    sock: TcpStream,
    key: Key32,
}

impl Admin {
    /// send_packet(): one command frame.  The inner length is host order,
    /// which is what the hub's admin path expects.
    fn send_packet(&mut self, cmd: u8, payload: &[u8]) {
        let plain = Zeroizing::new(net::frame_plain(cmd, payload, false));
        let Some((body, tag)) = crypto::aes_gcm_encrypt(&plain, self.key.as_ref()) else {
            return;
        };
        let mut wire = body;
        wire.extend_from_slice(&tag);
        net::write_framed(&mut self.sock, &wire);
    }

    fn send_text(&mut self, cmd: u8, payload: &str) {
        self.send_packet(cmd, payload.as_bytes());
    }

    /// One decrypted frame, or None when the connection is gone or the frame
    /// is unusable.
    fn recv_frame(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        if !net::read_exact(&mut self.sock, &mut len_buf) {
            return None;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if !(GCM_TAG_LEN + 5..=MAX_HUB_PACKET).contains(&len) {
            return None;
        }
        let mut enc = vec![0u8; len];
        if !net::read_exact(&mut self.sock, &mut enc) {
            return None;
        }
        let (body, tag) = enc.split_at(len - GCM_TAG_LEN);
        crypto::aes_gcm_decrypt(body, self.key.as_ref(), tag)
    }

    /// read_response(): the next real reply, answering any keepalive that
    /// arrives first.
    fn read_response(&mut self) -> String {
        loop {
            let Some(plain) = self.recv_frame() else {
                return "Error: Connection lost".to_string();
            };
            if plain.first() == Some(&CMD_PING) {
                self.send_packet(CMD_PING, &[]);
                continue;
            }
            return String::from_utf8_lossy(irchub::cstr::until_nul_bytes(&plain)).into_owned();
        }
    }

    /// process_incoming_packet(): drain one frame the hub sent unprompted.
    /// False means the link died.
    fn process_incoming(&mut self) -> bool {
        match self.recv_frame() {
            Some(plain) => {
                if plain.first() == Some(&CMD_PING) {
                    self.send_packet(CMD_PING, &[]);
                }
                true
            }
            None => false,
        }
    }

    /// wait_for_input_or_socket(): a line of input, servicing the hub's
    /// keepalives while we wait.  None means the connection died.
    fn wait_for_input(&mut self) -> Option<String> {
        loop {
            let ready = {
                let stdin = std::io::stdin();
                let watches = [
                    net::Watch {
                        fd: stdin.as_fd(),
                        write: false,
                    },
                    net::Watch {
                        fd: self.sock.as_fd(),
                        write: false,
                    },
                ];
                net::poll_fds(&watches, u16::MAX)
            };
            if ready[1].0 {
                if !self.process_incoming() {
                    println!("\n[!] Connection lost.");
                    return None;
                }
                continue;
            }
            if ready[0].0 {
                return Some(tool::read_line(4096));
            }
        }
    }

    fn input(&mut self, prompt: &str) -> String {
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        match self.wait_for_input() {
            Some(s) => s,
            None => {
                println!("Connection died during input.");
                std::process::exit(1);
            }
        }
    }

    fn confirm(&mut self, msg: &str) -> bool {
        let b = self.input(&format!("{msg} (y/n): "));
        b.starts_with('y') || b.starts_with('Y')
    }

    fn pause(&mut self) {
        self.input("\nPress Enter to continue...");
    }

    /// Send one command and print the hub's answer.
    fn ask(&mut self, cmd: u8, payload: &str) -> String {
        self.send_text(cmd, payload);
        self.read_response()
    }

    fn show(&mut self, cmd: u8, payload: &str) {
        let r = self.ask(cmd, payload);
        println!("\n{r}");
        self.pause();
    }
}

// ---------------------------------------------------------------------------
// Shared prompts
// ---------------------------------------------------------------------------

fn keygen_hint() {
    println!("The user makes their own keypair on their own machine:");
    println!("    ./keygen <name>     (irchub/bin/keygen or ircbot/utils/keygen)");
    println!("They keep <ts>_<name>.private.b64 (chmod 600) and give you only");
    println!("<ts>_<name>.public.b64. The hub never sees a private key.\n");
}

/// Prompt for a user's public key: the pasted 88 chars, or a path to their
/// .public.b64.  Shows the fingerprint and asks to confirm.  None when the
/// operator gives up (empty input).
fn prompt_user_pubkey(a: &mut Admin, who: &str) -> Option<String> {
    loop {
        let input = a.input(
            "Public key (paste the 88 chars, or a path to the .public.b64; blank to cancel): ",
        );
        if input.is_empty() {
            return None;
        }
        // A private and a public key file have the same shape (88-char base64
        // of 64 bytes), so the content cannot tell them apart; refuse a
        // keygen private file by name before it gets published.
        if input.contains(".private.") {
            println!(
                "  That is a PRIVATE key file — never hand it out. Use the matching .public.b64."
            );
            continue;
        }
        let key = match crypto::pubkey_b64_decode(&input) {
            Some(raw) => Some((input.clone(), raw)),
            None => {
                let from_file = std::fs::read_to_string(&input).ok();
                let line = from_file
                    .as_ref()
                    .and_then(|s| s.lines().next())
                    .map(|l| l.trim_end_matches([' ', '\t', '\r', '\n']).to_string());
                match line
                    .as_deref()
                    .and_then(|l| crypto::pubkey_b64_decode(l).map(|r| (l.to_string(), r)))
                {
                    Some(v) => Some(v),
                    None => {
                        println!(
                            "  Not an 88-char public key{}. Use the .public.b64 — never the .private.b64.",
                            if from_file.is_some() {
                                " in that file"
                            } else {
                                ""
                            }
                        );
                        None
                    }
                }
            }
        };
        let Some((b64, raw)) = key else { continue };
        println!(
            "  Key fingerprint for {who}: {}  (keygen printed it with the PUBLIC key)",
            crypto::key_fingerprint(&raw)
        );
        if a.confirm("  Use this key?") {
            return Some(b64);
        }
    }
}

fn strip_ws(s: &str) -> String {
    s.trim_end_matches([' ', '\r', '\n', '\t']).to_string()
}

// ---------------------------------------------------------------------------
// Bots
// ---------------------------------------------------------------------------

fn bot_list(a: &mut Admin) {
    a.show(CMD_ADMIN_LIST_FULL, "");
}

fn bot_add(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("           ADD BOT (bot-provided identity)");
    println!("{RULE_H}");
    println!("The bot has generated its own UUID and Curve25519");
    println!("keypair during 'ircbot -setup'.  Paste the UUID and");
    println!("the 88-char base64 public key it printed.\n");

    let nick = a.input("Bot Nickname: ");
    let uuid = a.input("Bot UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): ");
    if !irchub::cstr::has_uuid_dashes(&uuid) {
        println!("Error: UUID format invalid.");
        a.pause();
        return;
    }
    let pubkey = strip_ws(&a.input("Bot public key (88 chars base64): "));
    if pubkey.len() != COMBINED_KEY_B64 {
        println!(
            "Error: public key must be exactly {COMBINED_KEY_B64} chars (got {}).",
            pubkey.len()
        );
        a.pause();
        return;
    }

    let response = a.ask(CMD_ADMIN_CREATE_BOT, &format!("{nick}|{uuid}|{pubkey}"));
    if response.starts_with("SUCCESS") {
        println!("\n[+] Bot '{nick}' (UUID {uuid}) registered.");
        println!("    Hub UUID + pubkey were printed during 'irchub -setup'");
        println!("    (see hub_public.b64). Use those when configuring the");
        println!("    bot's hub connection from 'ircbot -setup'.");
    } else {
        println!("\nHub Response: {response}");
    }
    a.pause();
}

fn bot_remove(a: &mut Admin) {
    let r = a.ask(CMD_ADMIN_LIST_SUMMARY, "");
    println!("\n{r}");
    let uuid = a.input("UUID to REMOVE (or blank to cancel): ");
    if !uuid.is_empty() && a.confirm("Are you sure? Bot will be disconnected") {
        let r = a.ask(CMD_ADMIN_DEL, &uuid);
        println!("Hub: {r}");
    }
    a.pause();
}

fn bot_rekey(a: &mut Admin) {
    let r = a.ask(CMD_ADMIN_LIST_SUMMARY, "");
    println!("\n{r}");
    let uuid = a.input("UUID to REKEY: ");
    if uuid.is_empty() {
        println!("Cancelled.");
        return;
    }
    // Rekey is bot-local: only the bot can rotate its own keypair, because it
    // owns its private key (v3 trust model — the hub never holds bot
    // privkeys).  This menu just relays the request; the hub replies with
    // instructions to run the bot's own 'rekey' admin command, which
    // regenerates the keypair locally, pushes the new pubkey to the hub, and
    // reconnects.
    if !a.confirm("Ask the bot to rekey itself (it will reconnect)?") {
        return;
    }
    println!("\n[*] Requesting rekey instructions from hub...");
    let response = a.ask(CMD_ADMIN_REKEY_BOT, &uuid);
    if let Some(rest) = response.strip_prefix("INSTRUCT|") {
        let text = rest.split_once('|').map_or(response.as_str(), |(_, t)| t);
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║                  REKEY: NEXT STEP                ║");
        println!("╚══════════════════════════════════════════════════╝\n");
        println!("UUID: {uuid}\n\n{text}");
    } else {
        println!("Hub Response: {response}");
    }
    a.pause();
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

fn peer_list(a: &mut Admin) {
    println!();
    let r = a.ask(CMD_ADMIN_LIST_PEERS, "");
    println!("{r}");
    a.pause();
}

fn peer_add(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                   ADD PEER HUB");
    println!("{RULE_H}");
    println!("Paste the peer's 88-char Curve25519 pubkey (contents of");
    println!("its hub_public.b64). The pubkey is required — connections");
    println!("from peers without a registered pubkey are refused.\n");

    let ip = a.input("Peer IP: ");
    let port = a.input("Peer Port: ");
    let uuid = a.input("Peer UUID: ");
    let name = a.input("Friendly Name (optional, auto-syncs): ");
    let pubkey = strip_ws(&a.input("Peer pubkey (88 char base64, required): "));

    if pubkey.is_empty() {
        println!(
            "\nError: pubkey is required. Re-add the peer after obtaining its hub_public.b64."
        );
        a.pause();
        return;
    }
    if pubkey.len() != COMBINED_KEY_B64 {
        println!(
            "\nWarning: pubkey is {} chars, expected {COMBINED_KEY_B64}. Submitting anyway; hub will reject if invalid.",
            pubkey.len()
        );
    }
    let r = a.ask(
        CMD_ADMIN_ADD_PEER,
        &format!("{ip}:{port}:{uuid}:{name}:{pubkey}"),
    );
    println!("\nHub: {r}");
    a.pause();
}

fn peer_remove(a: &mut Admin) {
    let r = a.ask(CMD_ADMIN_LIST_PEERS, "");
    println!("\n{r}");
    let idx = a.input("Enter Index to Remove (or blank to cancel): ");
    if !idx.is_empty() && irchub::cstr::atoi(&idx) > 0 && a.confirm("Remove this peer?") {
        let r = a.ask(CMD_ADMIN_DEL_PEER, &idx);
        println!("Hub: {r}");
    }
    a.pause();
}

fn peer_set_pubkey(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                 SET PEER PUBKEY");
    println!("{RULE_H}");
    println!("Registers the peer's 88-char Curve25519 pubkey on an");
    println!("existing peer entry. The next connection from that peer");
    println!("authenticates with it (HUBv3 Ed25519 signature).\n");
    println!("Get the pubkey from the peer's hub_public.b64 file.\n");

    let uuid = a.input("Peer UUID: ");
    let pubkey = strip_ws(&a.input("Peer pubkey (88 char base64): "));
    if uuid.is_empty() || pubkey.is_empty() {
        println!("Cancelled.");
        return;
    }
    if pubkey.len() != COMBINED_KEY_B64 {
        println!(
            "\nWarning: pubkey is {} chars, expected {COMBINED_KEY_B64}.",
            pubkey.len()
        );
    }
    let r = a.ask(CMD_ADMIN_SET_PEER_PUBKEY, &format!("{uuid}:{pubkey}"));
    println!("\nHub: {r}");
    a.pause();
}

fn peer_force_sync(a: &mut Admin) {
    println!("\n[*] Forcing mesh synchronization...");
    let r = a.ask(CMD_ADMIN_SYNC_MESH, "");
    println!("Hub: {r}");
    a.pause();
}

fn peer_rekey_hubs(a: &mut Admin) {
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║               ⚠️  DANGER ZONE ⚠️                  ║");
    println!("║          REKEY THIS HUB'S IDENTITY KEY           ║");
    println!("╚══════════════════════════════════════════════════╝\n");
    println!("This will:");
    println!("  1. Generate a new Curve25519 keypair for this hub");
    println!("  2. Disconnect every peer and bot so they reauthenticate");
    println!("  3. Print and save the new PUBLIC key\n");
    println!("Per-hub keys are independent: the new public key is NOT pushed");
    println!("anywhere. Every peer must re-register it ('Set Peer Pubkey'),");
    println!("and every bot must re-run 'sethubpub', or they cannot reconnect.\n");

    if !a.confirm("Proceed with hub rekey?") {
        println!("Cancelled.");
        return;
    }
    println!("\n[*] Requesting hub to generate new keypair...");
    let response = a.ask(CMD_ADMIN_REGEN_KEYS, "");

    if crypto::pubkey_b64_decode(&response).is_some() {
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║           HUB KEYS REGENERATED SUCCESS           ║");
        println!("╚══════════════════════════════════════════════════╝\n");
        let fname = chrono::Local::now()
            .format("hub_public_%Y%m%d_%H%M%S.b64")
            .to_string();
        if std::fs::write(&fname, &response).is_ok() {
            println!("[NEW PUBLIC KEY SAVED: {fname}]\n");
        }
        println!("NEW PUBLIC KEY:");
        println!("{RULE_H}");
        println!("{response}");
        println!("{RULE_H}\n");
        println!("ACTION REQUIRED:");
        println!("1. On every peer hub: 'Set Peer Pubkey' with this key.");
        println!("2. On every bot: re-run 'sethubpub' with this key.\n");
    } else {
        println!("Hub Response: {response}");
    }
    a.pause();
}

// ---------------------------------------------------------------------------
// Admins, opers, usermasks
// ---------------------------------------------------------------------------

fn add_user_record(a: &mut Admin, admin: bool) {
    println!("\n{RULE_H}");
    println!(
        "                   ADD {}",
        if admin { "ADMIN" } else { "OPER" }
    );
    println!("{RULE_H}\n");
    keygen_hint();

    let name = a.input("Name (no spaces, e.g. robert): ");
    if name.is_empty() || name.contains(' ') || name.contains('|') {
        println!("Invalid name.");
        a.pause();
        return;
    }
    let Some(pubkey) = prompt_user_pubkey(a, &name) else {
        println!("Cancelled.");
        a.pause();
        return;
    };
    let mask = a.input("First usermask (e.g. nick!*@*.example.com): ");
    if !mask.contains('!') || !mask.contains('@') {
        println!("Mask must contain '!' and '@'.");
        a.pause();
        return;
    }

    let cmd = if admin {
        CMD_ADMIN_ADD_ADMIN
    } else {
        CMD_ADMIN_ADD_OPER_RECORD
    };
    let response = a.ask(cmd, &format!("{name}|{pubkey}|{mask}"));
    // Response: SUCCESS|<a|o>|<name>|<mask>|<key fingerprint>
    if response.starts_with("SUCCESS|") {
        let t: Vec<&str> = response.split('|').collect();
        println!(
            "\n[+] {} '{name}' created with mask {} (key {}).",
            if admin { "Admin" } else { "Oper" },
            t.get(3).copied().unwrap_or(mask.as_str()),
            t.get(4).copied().unwrap_or("?")
        );
        if admin {
            println!("    They log in with: ./hub_admin <ip> <port> <their .private.b64>");
        }
        println!("    IRC: their client script (ircbot/utils) uses the same .private.b64.");
    } else {
        println!("\nHub: {response}");
    }
    a.pause();
}

fn del_user_record(a: &mut Admin, admin: bool) {
    let (list_cmd, del_cmd, what) = if admin {
        (CMD_ADMIN_LIST_ADMINS, CMD_ADMIN_DEL_ADMIN, "Admin")
    } else {
        (CMD_ADMIN_LIST_OPERS_V2, CMD_ADMIN_DEL_OPER_RECORD, "Oper")
    };
    let r = a.ask(list_cmd, "");
    println!("\n{r}");
    let name = a.input(&format!("{what} name to REMOVE (or blank to cancel): "));
    if !name.is_empty()
        && a.confirm(&format!(
            "Remove this {} and all their masks?",
            what.to_lowercase()
        ))
    {
        let r = a.ask(del_cmd, &name);
        println!("Hub: {r}");
    }
    a.pause();
}

fn add_usermask(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("               ADD USERMASK TO USER");
    println!("{RULE_H}\n");
    let name = a.input("User name (admin or oper): ");
    let mask = a.input("New usermask (e.g. nick!*@*.example.com): ");
    if !name.is_empty() && !mask.is_empty() {
        let r = a.ask(CMD_ADMIN_ADD_USERMASK, &format!("{name}|{mask}"));
        println!("\nHub: {r}");
    }
    a.pause();
}

fn del_usermask(a: &mut Admin) {
    let name = a.input("User name: ");
    if !name.is_empty() {
        let r = a.ask(CMD_ADMIN_MATCH, &name);
        println!("\n{r}");
    }
    let mask = a.input("Mask to REMOVE (or blank to cancel): ");
    if !name.is_empty() && !mask.is_empty() && a.confirm("Remove this mask?") {
        let r = a.ask(CMD_ADMIN_DEL_USERMASK, &format!("{name}|{mask}"));
        println!("Hub: {r}");
    }
    a.pause();
}

fn match_user(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                    MATCH USER");
    println!("{RULE_H}\n");
    println!("Enter a name to show that user's records, or * for all users.");
    println!("WARNING: * may produce many lines of output.\n");
    let name = a.input("Name or *: ");
    if !name.is_empty() {
        let r = a.ask(CMD_ADMIN_MATCH, &name);
        println!("\n{r}");
    }
    a.pause();
}

fn change_userkey(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("              CHANGE USER PUBLIC KEY");
    println!("{RULE_H}\n");
    println!("Replaces the key of an admin or oper (rotation, a lost key, or a");
    println!("legacy user with no key). UUID and usermasks are kept; the old key");
    println!("stops working on the hub and on every bot as soon as it syncs.\n");
    keygen_hint();
    let name = a.input("User name: ");
    if name.is_empty() {
        println!("Cancelled.");
        a.pause();
        return;
    }
    match prompt_user_pubkey(a, &name) {
        Some(pubkey) => {
            let r = a.ask(CMD_ADMIN_SET_USERKEY, &format!("{name}|{pubkey}"));
            println!("\nHub: {r}");
        }
        None => println!("Cancelled."),
    }
    a.pause();
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

fn add_channel(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                   ADD CHANNEL");
    println!("{RULE_H}\n");
    let chan = a.input("Channel Name: ");
    let key = a.input("Channel Key (or blank): ");
    if !chan.is_empty() {
        let r = a.ask(CMD_ADMIN_ADD_CHANNEL, &format!("{chan}|{key}"));
        println!("\nHub: {r}");
    }
    a.pause();
}

fn del_channel(a: &mut Admin) {
    let r = a.ask(CMD_ADMIN_LIST_CHANNELS, "");
    println!("\n{r}");
    let chan = a.input("Channel to REMOVE (or blank to cancel): ");
    if !chan.is_empty() && a.confirm("Remove this channel from all bots?") {
        let r = a.ask(CMD_ADMIN_DEL_CHANNEL, &chan);
        println!("Hub: {r}");
    }
    a.pause();
}

fn op_user(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                     OP USER");
    println!("{RULE_H}\n");
    let nick = a.input("Nick to OP: ");
    let channel = a.input("Channel: ");
    if !nick.is_empty() && !channel.is_empty() {
        println!("[*] Sending op request to hub...");
        let r = a.ask(CMD_ADMIN_OP_USER, &format!("{nick}|{channel}"));
        println!("\nHub: {r}");
    }
    a.pause();
}

// ---------------------------------------------------------------------------
// Local hub config
// ---------------------------------------------------------------------------

fn purge_tombstones(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("             PURGE TOMBSTONED ENTRIES");
    println!("{RULE_H}\n");
    println!("This will permanently remove deleted (tombstoned)");
    println!("channels, admin masks, and oper masks.\n");
    println!("  1. Immediate purge (all tombstones)");
    println!("  2. Time-based purge (default: 30 days)");
    println!("  3. Custom time-based purge");
    println!("  4. Cancel\n");

    let choice = a.input("Select option: ");
    let (payload, proceed) = match irchub::cstr::atoi(&choice) {
        1 => (
            "immediate".to_string(),
            a.confirm("Purge ALL tombstoned entries immediately?"),
        ),
        2 => (
            "30".to_string(),
            a.confirm("Purge tombstones older than 30 days?"),
        ),
        3 => {
            let days = a.input("Enter number of days: ");
            let d = irchub::cstr::atoi(&days);
            if d > 0 {
                let ok = a.confirm(&format!("Purge tombstones older than {d} days?"));
                (d.to_string(), ok)
            } else {
                println!("Invalid number of days.");
                (String::new(), false)
            }
        }
        4 => {
            println!("Cancelled.");
            (String::new(), false)
        }
        _ => {
            println!("Invalid option.");
            (String::new(), false)
        }
    };

    if proceed {
        println!("\n[*] Sending purge request to hub...");
        let r = a.ask(CMD_ADMIN_PURGE_TOMBSTONES, &payload);
        println!("\nHub Response:\n{r}");
    }
    a.pause();
}

fn configure_auto_purge(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("         CONFIGURE AUTOMATIC PURGE");
    println!("{RULE_H}\n");
    println!("Configure automatic daily purging of old tombstones.");
    println!("Tombstones are deleted channels, masks, and opers.\n");
    println!("Enter number of days (tombstones older than this");
    println!("will be purged daily), or 0 to disable:\n");

    let days_input = a.input("Days (0 to disable): ");
    let days = irchub::cstr::atoi(&days_input);
    if days < 0 {
        println!("Invalid input. Must be 0 or a positive number.");
        a.pause();
        return;
    }
    println!("\n[*] Sending configuration to hub...");
    let r = a.ask(CMD_ADMIN_SET_PURGE_DAYS, &days.to_string());
    println!("\nHub Response:\n{r}");
    a.pause();
}

fn ip_list_menu(a: &mut Admin, allow: bool) {
    let (name, list_cmd, add_cmd, del_cmd) = if allow {
        (
            "ALLOWLIST",
            CMD_ADMIN_LIST_ALLOWLIST,
            CMD_ADMIN_ADD_ALLOWLIST,
            CMD_ADMIN_DEL_ALLOWLIST,
        )
    } else {
        (
            "DENYLIST",
            CMD_ADMIN_LIST_DENYLIST,
            CMD_ADMIN_ADD_DENYLIST,
            CMD_ADMIN_DEL_DENYLIST,
        )
    };
    loop {
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║            MANAGE IP {name:<28}║");
        println!("╚══════════════════════════════════════════════════╝\n");
        println!("  1. List {name}");
        println!("  2. Add IP to {name}");
        println!("  3. Remove IP from {name}");
        println!("  4. Back\n");
        let buf = a.input("Select: ");
        match irchub::cstr::atoi(&buf) {
            1 => {
                println!();
                let r = a.ask(list_cmd, "");
                println!("{r}");
                a.pause();
            }
            2 => {
                println!("\n{RULE_H}");
                println!("              ADD IP TO {name}");
                println!("{RULE_H}\n");
                println!("Format examples (IPv4):");
                println!("  192.168.1.5       - Single IP");
                println!("  192.168.1.0/24    - Subnet (CIDR notation)");
                println!("  10.0.0.0/8        - Large network\n");
                if allow {
                    println!("The first entry turns the allowlist on: only listed addresses");
                    println!("(bots, peer hubs, hub_admin) can connect after that.\n");
                } else {
                    println!("A denied address is refused even if the allowlist has it.\n");
                }
                let pat = a.input("IP or CIDR pattern: ");
                if !pat.is_empty() {
                    let r = a.ask(add_cmd, &pat);
                    println!("\nHub: {r}");
                }
                a.pause();
            }
            3 => {
                let r = a.ask(list_cmd, "");
                println!("\n{r}");
                let pat = a.input("IP/CIDR to REMOVE (or blank to cancel): ");
                if !pat.is_empty()
                    && a.confirm(&format!("Remove this {} entry?", name.to_lowercase()))
                {
                    let r = a.ask(del_cmd, &pat);
                    println!("Hub: {r}");
                }
                a.pause();
            }
            4 => return,
            _ => println!("Invalid choice."),
        }
    }
}

fn set_hub_name(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                   SET HUB NAME");
    println!("{RULE_H}\n");
    println!("Set a friendly name for this hub.");
    println!("This name will be synced across the mesh network.\n");
    let name = a.input("Hub Name: ");
    if !name.is_empty() {
        let r = a.ask(CMD_ADMIN_SET_HUB_NAME, &name);
        println!("\nHub: {r}");
    }
    a.pause();
}

fn set_bind_ip(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                SET BIND IP ADDRESS");
    println!("{RULE_H}\n");
    println!("Set the IP address this hub binds to:");
    println!("  0.0.0.0      - Bind to all interfaces (default)");
    println!("  127.0.0.1    - Localhost only");
    println!("  192.168.x.x  - Specific interface\n");
    println!("NOTE: Hub restart required for changes to take effect.\n");
    let ip = a.input("Bind IP: ");
    if !ip.is_empty() {
        let r = a.ask(CMD_ADMIN_SET_BIND_IP, &ip);
        println!("\nHub: {r}");
    }
    a.pause();
}

fn set_bind_port(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("                 SET BIND PORT");
    println!("{RULE_H}\n");
    println!("Set the port this hub listens on (1-65535).");
    println!("NOTE: Hub restart required for changes to take effect.\n");
    let port = a.input("Bind Port: ");
    if !port.is_empty() {
        let r = a.ask(CMD_ADMIN_SET_BIND_PORT, &port);
        println!("\nHub: {r}");
    }
    a.pause();
}

fn export_private_key(a: &mut Admin) {
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║           *** SECURITY WARNING ***               ║");
    println!("║              EXPORT PRIVATE KEY                  ║");
    println!("╚══════════════════════════════════════════════════╝\n");
    println!("This is the hub's private key used for hub-to-hub");
    println!("and hub_admin authentication. Anyone with this key");
    println!("can authenticate to this hub.\n");
    println!("  - Store it in a password manager or encrypted vault");
    println!("  - Never share it over unencrypted channels");
    println!("  - Keep a secure backup — losing it means re-keying");
    println!("    all peer hubs and hub_admin installations\n");

    if !a.confirm("I understand the risks. Export private key?") {
        println!("Cancelled.");
        a.pause();
        return;
    }
    let response = Zeroizing::new(a.ask(CMD_ADMIN_GET_PRIVKEY, ""));
    if response.starts_with("ERROR") {
        println!("\n{}", response.as_str());
        a.pause();
        return;
    }
    println!("\n  1. Save to file");
    println!("  2. Print to terminal only (do not write to disk)\n");
    let choice = a.input("Choice: ");
    if irchub::cstr::atoi(&choice) == 2 {
        println!("\n══════════════════════ PRIVATE KEY ══════════════════════");
        println!("{}", response.as_str());
        println!("═════════════════════════════════════════════════════════");
        println!("Copy and store this key securely before closing.");
    } else {
        let fname = chrono::Local::now()
            .format("hub_private_%Y%m%d_%H%M%S.b64")
            .to_string();
        // Create the private-key file with mode 0600 atomically.  A plain
        // create honours the umask first and would leave the key
        // world-readable in the window before a chmod — a local-disclosure
        // race for key material.
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&fname);
        let saved = match f {
            Ok(mut f) => f.write_all(response.as_bytes()).is_ok() && f.flush().is_ok(),
            Err(_) => false,
        };
        if saved {
            println!("\n[PRIVATE KEY SAVED: {fname}] (permissions: 0600)");
            println!("Move this file to secure storage and delete it from here.");
        } else {
            println!("\nFailed to save private key to file.");
        }
    }
    a.pause();
}

fn export_public_key(a: &mut Admin) {
    println!("\n{RULE_H}");
    println!("               EXPORT PUBLIC KEY");
    println!("{RULE_H}\n");
    println!("The public key is what peer hubs and bots pin for this hub.");
    println!("Share it with anyone who needs to connect.\n");
    println!("  1. Save to file");
    println!("  2. Print to terminal only\n");

    let response = a.ask(CMD_ADMIN_GET_PUBKEY, "");
    if response.starts_with("ERROR") {
        println!("\n{response}");
        a.pause();
        return;
    }
    let choice = a.input("Choice: ");
    if irchub::cstr::atoi(&choice) == 2 {
        println!("\n══════════════════════ PUBLIC KEY ═══════════════════════");
        println!("{response}");
        println!("═════════════════════════════════════════════════════════");
        println!("Peers register it with 'Set Peer Pubkey'; bots with 'sethubpub'.");
    } else {
        let fname = chrono::Local::now()
            .format("hub_public_%Y%m%d_%H%M%S.b64")
            .to_string();
        if std::fs::write(&fname, &response).is_ok() {
            println!("\n[PUBLIC KEY SAVED: {fname}]\n");
            println!("Give this file to peer hub operators and bot owners.");
        } else {
            println!("\nFailed to save public key to file.");
        }
    }
    a.pause();
}

fn set_log_level(a: &mut Admin) {
    println!();
    println!("Log Levels:");
    println!("  0: NONE (no logging)");
    println!("  1: ERROR (only errors)");
    println!("  2: WARNING (errors + warnings)");
    println!("  3: INFO (errors + warnings + info) [default]");
    println!("  4: DEBUG (everything)");
    println!();
    let buf = a.input("Select level (0-4): ");
    let level = irchub::cstr::atoi(&buf);
    if !(LOG_NONE..=LOG_DEBUG).contains(&level) {
        println!("Invalid level.");
        return;
    }
    a.send_packet(CMD_ADMIN_SET_LOG_LEVEL, &[level as u8]);
    let r = a.read_response();
    println!("[+] {r}");
}

fn set_log_size(a: &mut Admin) {
    println!("\nCurrent default: 10 MB");
    let buf = a.input("Enter log size limit in MB (1-1024): ");
    let mb = irchub::cstr::atoi(&buf);
    if !(1..=1024).contains(&mb) {
        println!("Invalid size (must be 1-1024 MB).");
        return;
    }
    let bytes = (mb as u32) * 1024 * 1024;
    a.send_packet(CMD_ADMIN_SET_LOG_SIZE, &bytes.to_be_bytes());
    let r = a.read_response();
    println!("[+] {r}");
}

fn opt_flags_menu(a: &mut Admin) {
    loop {
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║         MANAGE GLOBAL PEER CONFIG                ║");
        println!("╚══════════════════════════════════════════════════╝\n");
        println!("  1. Show Opt Flags");
        println!("  2. Set Opt Flags");
        println!("  3. Back to Main Menu\n");
        let buf = a.input("Select: ");
        match irchub::cstr::atoi(&buf) {
            1 => {
                let r = a.ask(CMD_ADMIN_GET_OPT_FLAGS, "");
                println!("\nCurrent network opt flags:\n  {r}");
                a.pause();
            }
            2 => {
                println!("\n{RULE_H}");
                println!("              SET NETWORK OPT FLAGS");
                println!("{RULE_H}");
                println!("Each character is a single option letter [a-zA-Z0-9].");
                println!("Known options:");
                println!("  h  hub-only mutations (bots refuse local +admin/-admin,");
                println!("     +oper/-oper, +usermask/-usermask, +bot/-bot, join/part,");
                println!("     chkey; users, masks, keys and channels change only here)\n");
                let flags = a.input("Enter the full flag string (empty to clear): ");
                let r = a.ask(CMD_ADMIN_SET_OPT_FLAGS, &flags);
                println!("\nHub: {r}");
                a.pause();
            }
            3 => return,
            _ => println!("Invalid choice."),
        }
    }
}

// ---------------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------------

fn menu(a: &mut Admin, title: &str, items: &[&str]) -> i32 {
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║{:^50}║", title);
    println!("╚══════════════════════════════════════════════════╝\n");
    for (i, it) in items.iter().enumerate() {
        println!("  {}. {it}", i + 1);
    }
    println!();
    let buf = a.input("Select: ");
    irchub::cstr::atoi(&buf)
}

fn menu_manage_bots(a: &mut Admin) {
    loop {
        match menu(
            a,
            "MANAGE BOTS",
            &[
                "List Bots",
                "Add Bot",
                "Remove Bot",
                "Rekey Bot",
                "Back to Main Menu",
            ],
        ) {
            1 => bot_list(a),
            2 => bot_add(a),
            3 => bot_remove(a),
            4 => bot_rekey(a),
            5 => return,
            _ => println!("Invalid choice."),
        }
    }
}

fn menu_manage_peer_connections(a: &mut Admin) {
    loop {
        match menu(
            a,
            "MANAGE PEER CONNECTIONS",
            &[
                "List Peers (Mesh Matrix)",
                "Add Peer",
                "Remove Peer",
                "Set Peer Pubkey",
                "Force Mesh Sync",
                "Rekey Hubs (DANGER)",
                "Back to Main Menu",
            ],
        ) {
            1 => peer_list(a),
            2 => peer_add(a),
            3 => peer_remove(a),
            4 => peer_set_pubkey(a),
            5 => peer_force_sync(a),
            6 => peer_rekey_hubs(a),
            7 => return,
            _ => println!("Invalid choice."),
        }
    }
}

fn menu_manage_peer_config(a: &mut Admin) {
    loop {
        match menu(
            a,
            "MANAGE LOCAL PEER CONFIG",
            &[
                "Set Hub Name",
                "Set Bind IP",
                "Set Bind Port",
                "Manage IP Allowlist",
                "Manage IP Denylist",
                "Purge Tombstones",
                "Configure Automatic Purge",
                "Export Private Key",
                "Export Public Key",
                "Set Log Level",
                "Set Log Size Limit",
                "Back to Main Menu",
            ],
        ) {
            1 => set_hub_name(a),
            2 => set_bind_ip(a),
            3 => set_bind_port(a),
            4 => ip_list_menu(a, true),
            5 => ip_list_menu(a, false),
            6 => purge_tombstones(a),
            7 => configure_auto_purge(a),
            8 => export_private_key(a),
            9 => export_public_key(a),
            10 => set_log_level(a),
            11 => set_log_size(a),
            12 => return,
            _ => println!("Invalid choice."),
        }
    }
}

fn menu_manage_users(a: &mut Admin, admin: bool) {
    let title = if admin {
        "MANAGE ADMINS"
    } else {
        "MANAGE OPERS"
    };
    let what = if admin { "Admins" } else { "Opers" };
    loop {
        let items = [
            format!("List {what}"),
            format!("Add {}", if admin { "Admin" } else { "Oper" }),
            format!("Remove {}", if admin { "Admin" } else { "Oper" }),
            "Add Usermask to Admin/Oper".to_string(),
            "Remove Usermask from Admin/Oper".to_string(),
            "Change User Public Key".to_string(),
            "Match User (show all records)".to_string(),
            "Back".to_string(),
        ];
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        match menu(a, title, &refs) {
            1 => {
                println!();
                let r = a.ask(
                    if admin {
                        CMD_ADMIN_LIST_ADMINS
                    } else {
                        CMD_ADMIN_LIST_OPERS_V2
                    },
                    "",
                );
                println!("{r}");
                a.pause();
            }
            2 => add_user_record(a, admin),
            3 => del_user_record(a, admin),
            4 => add_usermask(a),
            5 => del_usermask(a),
            6 => change_userkey(a),
            7 => match_user(a),
            8 => return,
            _ => println!("Invalid choice."),
        }
    }
}

fn menu_manage_channels(a: &mut Admin) {
    loop {
        match menu(
            a,
            "MANAGE CHANNELS",
            &["List Channels", "Add Channel", "Del Channel", "Back"],
        ) {
            1 => {
                println!();
                let r = a.ask(CMD_ADMIN_LIST_CHANNELS, "");
                println!("{r}");
                a.pause();
            }
            2 => add_channel(a),
            3 => del_channel(a),
            4 => return,
            _ => println!("Invalid choice."),
        }
    }
}

fn menu_admin_commands(a: &mut Admin) {
    loop {
        match menu(
            a,
            "IRC ADMIN COMMANDS",
            &[
                "Op User",
                "Manage Admins",
                "Manage Opers",
                "Manage Channels",
                "Back to Main Menu",
            ],
        ) {
            1 => op_user(a),
            2 => menu_manage_users(a, true),
            3 => menu_manage_users(a, false),
            4 => menu_manage_channels(a),
            5 => return,
            _ => println!("Invalid choice."),
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn usage() {
    println!("Usage: ./hub_admin <ip> <port> <private-key-file>");
    println!();
    println!("<private-key-file> is your <YYYYMMDDHHMMSS>_<name>.private.b64 from");
    println!("keygen. There is no username or password: the hub finds your admin");
    println!("record by the key and you prove you hold it by signing a one-time");
    println!("challenge. Keep the file chmod 600.");
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

fn main() {
    tool::harden_process();

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        usage();
        std::process::exit(1);
    }

    // Load the admin's combined Curve25519 PRIVATE key (88 chars base64).
    if let Ok(md) = std::fs::metadata(&args[3]) {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "[!] Warning: {} is readable by others (mode {:04o}) — chmod 600 it.",
                args[3],
                mode & 0o777
            );
        }
    }
    let Ok(text) = std::fs::read_to_string(&args[3]) else {
        die("Failed to open private key file");
    };
    let ab64 = Zeroizing::new(
        text.lines()
            .next()
            .unwrap_or("")
            .trim_matches([' ', '\t', '\r', '\n'])
            .to_string(),
    );
    let Some(dec) = crypto::b64_decode(&ab64).filter(|d| d.len() == COMBINED_KEY_LEN) else {
        die(
            "Invalid private key file: expected the 88-char base64 of a 64-byte Curve25519 combined key (a .private.b64).",
        );
    };
    // Layout: ed_priv(32) || x_priv(32).  The Ed25519 half signs the login
    // challenge; the public key identifies the admin record.
    let mut admin_priv = Zeroizing::new([0u8; COMBINED_KEY_LEN]);
    admin_priv.copy_from_slice(&dec);
    drop(dec);
    let admin_pub = crypto::combined_pub_from_priv(&admin_priv);
    println!("[*] Using key {}", crypto::key_fingerprint(&admin_pub));

    let port = irchub::cstr::atoi(&args[2]);
    let Ok(sock) = net::connect_peer(&args[1], port) else {
        die(&format!(
            "Bad hub address '{}' or connect failed (IPv4 literal expected).",
            args[1]
        ));
    };
    let _ = sock.set_nodelay(true);

    // Step 1: ADMIN-HELLO.  The hub answers with its X25519 pubkey, its UUID
    // and a one-time 32-byte login challenge:
    //   HUB-PUBKEY2|<x_pub_b64>|<hub_uuid>|<nonce_b64>
    let mut sock = sock;
    if !net::write_framed(&mut sock, b"ADMIN-HELLO") {
        die("HELLO write failed");
    }

    let mut len_buf = [0u8; 4];
    if !net::read_exact(&mut sock, &mut len_buf) {
        die("No usable HELLO reply from hub.");
    }
    let rl = u32::from_be_bytes(len_buf) as usize;
    if !(14..=200).contains(&rl) {
        die("No usable HELLO reply from hub.");
    }
    let mut reply = vec![0u8; rl];
    if !net::read_exact(&mut sock, &mut reply) {
        die("No usable HELLO reply from hub.");
    }
    let reply = String::from_utf8_lossy(&reply).into_owned();
    if reply.starts_with("HUB-PUBKEY|") {
        die("This hub predates passwordless login (HUB-PUBKEY v1); upgrade it.");
    }
    let Some(body) = reply.strip_prefix("HUB-PUBKEY2|") else {
        die("Unexpected HELLO reply from hub.");
    };
    let f = irchub::cstr::split_fields(body, 3);
    let ok = f.len() == 3 && f[1].len() < 64;
    let x = ok.then(|| crypto::b64_decode(f[0])).flatten();
    let n = ok.then(|| crypto::b64_decode(f[2])).flatten();
    let (Some(xb), Some(nb)) = (x, n) else {
        die("Unexpected HELLO reply from hub.");
    };
    if xb.len() != 32 || nb.len() != 32 {
        die("Unexpected HELLO reply from hub.");
    }
    let mut hub_x25519_pub = [0u8; 32];
    hub_x25519_pub.copy_from_slice(&xb);
    let mut nonce = Zeroizing::new([0u8; 32]);
    nonce.copy_from_slice(&nb);
    let hub_uuid = f[1].to_string();
    println!("[*] Hub {hub_uuid} answered; signing its login challenge.");

    // Step 2: a fresh ephemeral X25519 key gives the session forward secrecy;
    // the Ed25519 signature over the transcript proves we hold the admin key
    // and binds it to this hub, this challenge and this session.
    let Some((eph_priv, eph_pub)) = crypto::gen_ephemeral_x25519() else {
        die("Ephemeral key generation failed.");
    };

    let mut transcript = Vec::with_capacity(256);
    transcript.extend_from_slice(b"irchub-admin-auth-v2\0"); // incl. NUL
    transcript.extend_from_slice(hub_uuid.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&hub_x25519_pub);
    transcript.extend_from_slice(nonce.as_ref());
    transcript.extend_from_slice(&eph_pub);
    transcript.extend_from_slice(&admin_pub);

    let (ed_priv, _) = crypto::split_priv(&admin_priv);
    let sig = crypto::ed25519_sign(&ed_priv, &transcript);
    drop(ed_priv);
    drop(admin_priv);
    drop(nonce);

    let Some(shared) = crypto::x25519_derive(&eph_priv, &hub_x25519_pub) else {
        die("Session key derivation failed.");
    };
    let mut session_key = Zeroizing::new([0u8; 32]);
    if !crypto::hkdf_sha256(shared.as_ref(), &eph_pub, ADMIN_INFO, session_key.as_mut()) {
        die("Session key derivation failed.");
    }
    drop(shared);
    drop(eph_priv);

    // The C sent msg_len + 1 bytes: the NUL terminator rides along.
    let mut plain = Zeroizing::new(
        format!(
            "ADMIN2|{}|{}|{}:{}",
            crypto::b64_encode(&admin_pub),
            crypto::b64_encode(&sig),
            args[1],
            args[2]
        )
        .into_bytes(),
    );
    if plain.len() >= 512 {
        die("Could not build the login message.");
    }
    plain.push(0);

    // Sealed-box wire layout (the hub's seal_open): eph_pub || iv || ct || tag
    let Some((body, tag)) = crypto::aes_gcm_encrypt(&plain, session_key.as_ref()) else {
        die("AES-GCM encryption failed");
    };
    let mut enc = Vec::with_capacity(32 + body.len() + GCM_TAG_LEN);
    enc.extend_from_slice(&eph_pub);
    enc.extend_from_slice(&body);
    enc.extend_from_slice(&tag);
    if !net::write_framed(&mut sock, &enc) {
        die("Send failed");
    }

    let mut a = Admin {
        sock,
        key: session_key,
    };

    // Step 3: the hub confirms (encrypted) or hangs up.
    let response = a.read_response();
    let Some(who) = response.strip_prefix("AUTH-OK|") else {
        eprintln!(
            "[!] Login refused by the hub ({response}).\n    The key must be on an active admin record; see the hub log for the reason."
        );
        std::process::exit(1);
    };
    println!("[+] Authenticated to hub as '{who}'.");

    loop {
        match menu(
            &mut a,
            "IRC HUB ADMIN CONSOLE",
            &[
                "Manage Bots",
                "Manage Peer Connections",
                "Manage Local Peer Config",
                "Manage Global Peer Config",
                "IRC Admin Commands",
                "Exit",
            ],
        ) {
            1 => menu_manage_bots(&mut a),
            2 => menu_manage_peer_connections(&mut a),
            3 => menu_manage_peer_config(&mut a),
            4 => opt_flags_menu(&mut a),
            5 => menu_admin_commands(&mut a),
            6 => {
                println!("\nExiting...");
                return;
            }
            _ => println!("Invalid choice."),
        }
    }
}
