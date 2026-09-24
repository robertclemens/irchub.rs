//! The hub_admin command surface (hub_logic.c `handle_admin_command`).
//!
//! Every handler answers with one encrypted `send_response`, and returning
//! false means the connection is gone (a failed write already dropped it).
//! Mutations set `config_dirty` and let the write debounce in `maintenance`
//! flush them, rather than paying PBKDF2(100k) per command.

use zeroize::Zeroizing;

use crate::consts::*;
use crate::cstr::{now, pad_right, split_fields, trunc_string};
use crate::state::{
    ClientType, HubState, IpAcl, IpAclAdd, MaskRecord, PeerConfig, UserRecord, lww_next_ts,
    name_valid, parse_uint,
};
use crate::{auth, client, crypto, mesh, opflow, presence, ratelimit, storage, upgrade};

fn resp(state: &mut HubState, ci: usize, msg: &str) -> bool {
    client::send_response(state, ci, msg)
}

fn utc_time(ts: i64) -> String {
    if ts == 0 {
        return "never".to_string();
    }
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => "invalid".to_string(),
    }
}

fn local_time(ts: i64) -> String {
    if ts == 0 {
        return "Never".to_string();
    }
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
        None => "invalid".to_string(),
    }
}

const RULE: &str = "----------------------------------------------------------------------------";

// ---------------------------------------------------------------------------
// IP access lists
// ---------------------------------------------------------------------------

/// CMD_ADMIN_ADD/DEL_ALLOWLIST/DENYLIST (list 'w' or 'x').  The lists are
/// local to this hub: nothing is sent to peers or bots.  A change after which
/// the admin's own address could not connect is refused and rolled back; the
/// inbound connections a change refuses are closed by `maintenance`.
fn ip_acl_change(state: &mut HubState, ci: usize, list: char, add: bool, payload: &str) -> bool {
    let name = if list == 'w' { "allowlist" } else { "denylist" };
    if payload.is_empty() {
        return resp(state, ci, "ERROR: Missing IP pattern.");
    }
    let Some(mut e) = ratelimit::ip_acl_parse(payload) else {
        let msg = format!(
            "ERROR: '{}' is not an IPv4 address or CIDR (e.g. 192.168.1.5 or 10.0.0.0/8).",
            trunc_string(payload, 41)
        );
        return resp(state, ci, &msg);
    };

    let saved_allow = state.ip_allow.clone();
    let saved_deny = state.ip_deny.clone();

    if add {
        e.added = now();
        match ratelimit::ip_acl_add(state, list, &e) {
            IpAclAdd::Added => {}
            IpAclAdd::Duplicate => {
                let msg = format!("ERROR: {} is already on the {name}.", e.pattern());
                return resp(state, ci, &msg);
            }
            _ => {
                let msg = format!("ERROR: The {name} is full ({MAX_IP_ACL_ENTRIES} entries).");
                return resp(state, ci, &msg);
            }
        }
    } else if !ratelimit::ip_acl_remove(state, list, &e) {
        let msg = format!("ERROR: {} is not on the {name}.", e.pattern());
        return resp(state, ci, &msg);
    }

    let admin_ip = state.clients[ci].ip.clone();
    if !ratelimit::ip_acl_permits(state, &admin_ip) {
        state.ip_allow = saved_allow;
        state.ip_deny = saved_deny;
        let msg = format!(
            "ERROR: Refused: your own address {admin_ip} could not connect after this change.{}",
            if list == 'w' { " Allow it first." } else { "" }
        );
        return resp(state, ci, &msg);
    }

    let admin_fd = state.clients[ci].fd;
    let closing = state
        .clients
        .iter()
        .filter(|c| c.fd != admin_fd && c.inbound && !ratelimit::ip_acl_permits(state, &c.ip))
        .count();
    state.ip_acl_changed = true;
    state.config_dirty = true;
    crate::hlog_info!(
        "[ACCESS_CONTROL] {} {} {name} by {}\n",
        e.pattern(),
        if add { "added to" } else { "removed from" },
        state.clients[ci].id
    );

    let count = if list == 'w' {
        state.ip_allow.len()
    } else {
        state.ip_deny.len()
    };
    let mut msg = format!(
        "SUCCESS: {} {} {name}.",
        e.pattern(),
        if add { "added to" } else { "removed from" }
    );
    if list == 'w' && add && count == 1 {
        msg.push_str(" The allowlist is now on: only listed addresses may connect.");
    } else if list == 'w' && !add && count == 0 {
        msg.push_str(" The allowlist is now empty: any address may connect.");
    }
    if closing > 0 {
        msg.push_str(&format!(
            " Closing {closing} existing connection(s) it no longer permits."
        ));
    }
    resp(state, ci, &msg)
}

fn list_ip_acl(state: &mut HubState, ci: usize, allow: bool) -> bool {
    let l: Vec<IpAcl> = if allow {
        state.ip_allow.clone()
    } else {
        state.ip_deny.clone()
    };
    let mut out = format!(
        "════════════════════════════════════════════\n           IP {}\n════════════════════════════════════════════\n\n",
        if allow { "ALLOWLIST" } else { "DENYLIST" }
    );
    for (i, e) in l.iter().enumerate() {
        out.push_str(&format!("{:>3}. {}\n", i + 1, e.pattern()));
    }
    if l.is_empty() {
        out.push_str(if allow {
            "(No allowlist entries - all IPs allowed)\n"
        } else {
            "(No denylist entries)\n"
        });
    }
    resp(state, ci, &out)
}

// ---------------------------------------------------------------------------
// Bots
// ---------------------------------------------------------------------------

fn list_full(state: &mut HubState, ci: usize) -> bool {
    let active = state.bots.iter().filter(|b| b.is_active).count();
    let mut out = format!("--- Registered Bots ({active}) ---\n");

    for bi in 0..state.bots.len() {
        if !state.bots[bi].is_active {
            continue;
        }
        let uuid = state.bots[bi].uuid.clone();
        let nick = state.bots[bi]
            .entry("n")
            .map_or_else(|| "Unknown".to_string(), |e| trunc_string(&e.value, 32));

        // "seen" is synced between hubs and is the most recent time this bot
        // authenticated anywhere; a live client value is fresher still.
        let mut last_seen = presence::bot_last_seen(state, &uuid);
        let mut is_connected = false;
        let mut connected_to = "N/A".to_string();

        if let Some(ci2) = state
            .clients
            .iter()
            .position(|c| c.typ == ClientType::Bot && c.id == uuid)
        {
            is_connected = true;
            connected_to = format!("LOCAL ({}:{})", state.bind_ip, state.port);
            if state.clients[ci2].last_seen > last_seen {
                last_seen = state.clients[ci2].last_seen;
            }
        }

        // Otherwise check whether a peer's gossip lists this bot.  Gossip
        // shape: connected:total:count:uuid_list|...
        if !is_connected {
            for p in state
                .peers
                .iter()
                .filter(|p| p.connected && !p.last_gossip.is_empty())
            {
                let f: Vec<&str> = p.last_gossip.splitn(4, ':').collect();
                if f.len() < 4 {
                    continue;
                }
                let Some(bar) = f[3].find('|') else { continue };
                let uuid_list = &f[3][..bar];
                if uuid_list.is_empty() || uuid_list == "-" {
                    continue;
                }
                if uuid_list.contains(&uuid) {
                    is_connected = true;
                    connected_to = format!("PEER ({}:{})", p.ip, p.port);
                    break;
                }
            }
        }

        // Still not found: the live presence roster (CMD_BOT_ROSTER) knows
        // every bot a peer hub has right now, TTL'd, whatever the legacy
        // gossip above carries.
        if !is_connected {
            let mut best: Option<&crate::state::BotRoster> = None;
            for e in state.roster.iter().filter(|e| e.bot_uuid == uuid) {
                if best.is_none_or(|b| e.reported_at >= b.reported_at) {
                    best = Some(e);
                }
            }
            if let Some(e) = best {
                is_connected = true;
                connected_to = match state
                    .peers
                    .iter()
                    .find(|p| !p.uuid.is_empty() && p.uuid == e.hub_uuid)
                {
                    Some(p) => format!("PEER ({}:{})", trunc_string(&p.ip, 64), p.port),
                    None => format!("PEER ({})", trunc_string(&e.hub_name, 100)),
                };
            }
        }

        // Key fingerprint: compare with what a client script prints on ~A2A
        // auth, and with the bot's own 'status'.
        let bfp = state.bots[bi].entry("pub").map_or_else(
            || "(no key)".to_string(),
            |e| crypto::key_fingerprint_b64(&e.value),
        );

        // Version and code base, e.g. "2.4.0 (rs)", from the volatile
        // presence data — known only while the bot is on the mesh.
        let ver = if is_connected {
            presence::bot_version_label(state, &uuid)
        } else {
            "-".to_string()
        };

        out.push_str(&format!(
            "[{uuid}] {} | Status: {} | Peer: {} | Version: {} | Key: {bfp} | Last: {}\n",
            pad_right(&nick, 15),
            pad_right(if is_connected { "CONNECTED" } else { "OFFLINE" }, 10),
            pad_right(if is_connected { &connected_to } else { "N/A" }, 20),
            pad_right(&ver, 12),
            local_time(last_seen)
        ));
    }
    resp(state, ci, &out)
}

fn get_pending(state: &mut HubState, ci: usize) -> bool {
    if state.pending.is_empty() {
        return resp(state, ci, "No pending bots.");
    }
    let mut out = String::from("--- Pending Authorization ---\n");
    for (i, p) in state.pending.iter().enumerate() {
        out.push_str(&format!("[{}] {} | IP: {}\n", i + 1, p.uuid, p.ip));
    }
    resp(state, ci, &out)
}

fn create_bot(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // v3: bot-provided identity.  Payload: "NICK|UUID|PUBKEY_B64".  The hub no
    // longer generates the bot keypair — the bot did, locally during
    // 'ircbot -setup'.  Only the public key reaches the hub.
    if payload.is_empty() {
        return resp(state, ci, "ERROR|Empty payload");
    }
    let f = split_fields(payload, 3);
    if f.len() < 3 || f[0].is_empty() || f[1].is_empty() || f[2].is_empty() {
        return resp(state, ci, "ERROR|Format: NICK|UUID|PUBKEY_B64");
    }
    let nick = trunc_string(f[0], 64);
    let uuid_in = trunc_string(f[1], 64);
    let pubkey_in = trunc_string(f[2].split_whitespace().next().unwrap_or(""), 256);

    if !crate::cstr::has_uuid_dashes(&uuid_in) {
        return resp(state, ci, "ERROR|Invalid UUID format");
    }
    if pubkey_in.len() != COMBINED_KEY_B64 {
        return resp(state, ci, "ERROR|pubkey must be 88-char base64");
    }
    if crypto::b64_decode(&pubkey_in).map_or(0, |d| d.len()) != COMBINED_KEY_LEN {
        return resp(state, ci, "ERROR|pubkey not valid 64-byte Curve25519");
    }
    if state.bots.iter().any(|b| b.uuid == uuid_in) {
        return resp(state, ci, "ERROR|Bot UUID already registered");
    }
    auth::add_bot_memory(state, &uuid_in, &nick, &pubkey_in);
    state.config_dirty = true;
    let msg = format!("SUCCESS|{uuid_in}|registered");
    resp(state, ci, &msg)
}

// ---------------------------------------------------------------------------
// Peers and the mesh matrix
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MatrixPeer {
    ip: String,
    port: i32,
    uuid: String,
    friendly_name: String,
    is_me: bool,
}

impl MatrixPeer {
    fn label(&self) -> String {
        if !self.friendly_name.is_empty() {
            if self.uuid.is_empty() {
                format!("{} (no-uuid)", self.friendly_name)
            } else {
                format!("{} ({})", self.friendly_name, self.uuid)
            }
        } else {
            format!("{}:{}", trunc_string(&self.ip, 256), self.port)
        }
    }

    /// Match by UUID when both sides have one (preferred), else by ip:port.
    fn matches(&self, uuid: &str, ip: &str, port: i32) -> bool {
        if !uuid.is_empty() && !self.uuid.is_empty() {
            return self.uuid == uuid;
        }
        self.port == port && self.ip == ip
    }
}

/// One gossip block: `ip:port:uuid:name|<peer>,<peer>,...`.
struct GossipBlock<'a> {
    owner_ip: String,
    owner_port: i32,
    owner_uuid: String,
    owner_name: String,
    peers: &'a str,
}

fn parse_gossip_block(block: &str) -> Option<GossipBlock<'_>> {
    let head = match block.find('|') {
        Some(i) => &block[..i],
        None => block,
    };
    let f: Vec<&str> = head.splitn(4, ':').collect();
    if f.len() < 2 {
        return None;
    }
    let owner_port = crate::cstr::atoi(f[1]);
    let dash_to_empty = |s: &str| {
        if s == "-" {
            String::new()
        } else {
            trunc_string(s, 64)
        }
    };
    Some(GossipBlock {
        owner_ip: trunc_string(f[0], 256),
        owner_port,
        owner_uuid: f.get(2).map_or(String::new(), |s| dash_to_empty(s)),
        owner_name: f.get(3).map_or(String::new(), |s| dash_to_empty(s)),
        peers: match block.find('|') {
            Some(i) => &block[i + 1..],
            None => "",
        },
    })
}

/// One entry in a block's peer list: `ip:port:is_up:uuid:name`.
fn parse_gossip_peer(tok: &str) -> Option<(String, i32, bool, String, String)> {
    let f: Vec<&str> = tok.splitn(5, ':').collect();
    if f.len() < 2 {
        return None;
    }
    let dash_to_empty = |s: &str| {
        if s == "-" {
            String::new()
        } else {
            trunc_string(s, 64)
        }
    };
    Some((
        trunc_string(f[0], 256),
        crate::cstr::atoi(f[1]),
        f.get(2).is_some_and(|s| crate::cstr::atoi(s) != 0),
        f.get(3).map_or(String::new(), |s| dash_to_empty(s)),
        f.get(4).map_or(String::new(), |s| dash_to_empty(s)),
    ))
}

/// The blocks a connected peer last gossiped to us.
fn peer_gossip_blocks(gossip: &str) -> Vec<String> {
    let Some(bar) = gossip.find('|') else {
        return Vec::new();
    };
    trunc_string(&gossip[bar + 1..], MAX_BUFFER)
        .split(';')
        .filter(|b| !b.is_empty())
        .map(str::to_string)
        .collect()
}

/// Is this hub currently linked to `peer`?
fn peer_link_up(state: &HubState, p: &PeerConfig) -> bool {
    p.fd > 0
        && state
            .clients
            .iter()
            .any(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == p.fd)
}

fn list_peers(state: &mut HubState, ci: usize) -> bool {
    let mut all: Vec<MatrixPeer> = Vec::new();

    // The local hub, shown by friendly name rather than bind_ip.
    all.push(MatrixPeer {
        ip: "Local".into(),
        port: state.port,
        uuid: state.hub_uuid.clone(),
        friendly_name: state.hub_friendly_name.clone(),
        is_me: true,
    });
    for p in &state.peers {
        if all.len() >= 64 {
            break;
        }
        let display_ip = if p.remote_ip.is_empty() {
            &p.ip
        } else {
            &p.remote_ip
        };
        all.push(MatrixPeer {
            ip: trunc_string(display_ip, 256),
            port: p.port,
            uuid: p.uuid.clone(),
            friendly_name: p.friendly_name.clone(),
            is_me: false,
        });
    }

    // Learn about hubs we are not configured for from the peers' gossip.
    let gossips: Vec<String> = state
        .peers
        .iter()
        .filter(|p| p.connected && !p.last_gossip.is_empty())
        .map(|p| p.last_gossip.clone())
        .collect();
    for g in &gossips {
        for block in peer_gossip_blocks(g) {
            let Some(b) = parse_gossip_block(&block) else {
                continue;
            };
            // Skip 0.0.0.0 entries (a hub's bind_ip, not a reachable address).
            if b.owner_ip != "0.0.0.0"
                && !all
                    .iter()
                    .any(|x| x.matches(&b.owner_uuid, &b.owner_ip, b.owner_port))
                && all.len() < 64
            {
                all.push(MatrixPeer {
                    ip: b.owner_ip.clone(),
                    port: b.owner_port,
                    uuid: b.owner_uuid.clone(),
                    friendly_name: b.owner_name.clone(),
                    is_me: false,
                });
            }
            for tok in b.peers.split(',') {
                let Some((t_ip, t_port, _, t_uuid, t_name)) = parse_gossip_peer(tok) else {
                    continue;
                };
                if t_ip == "0.0.0.0" {
                    continue;
                }
                if !all.iter().any(|x| x.matches(&t_uuid, &t_ip, t_port)) && all.len() < 64 {
                    all.push(MatrixPeer {
                        ip: t_ip,
                        port: t_port,
                        uuid: t_uuid,
                        friendly_name: t_name,
                        is_me: false,
                    });
                }
            }
        }
    }

    let count = all.len();
    let peer_col_width = all
        .iter()
        .map(|p| p.label().len())
        .max()
        .unwrap_or(0)
        .max(25)
        + 3;
    // Add 24 for the IP:Port column (21 chars + " | "); 7 for Code.
    let line_len = peer_col_width + 3 + 24 + count * 5 + 15 + 10 + 7;

    let mut out = String::with_capacity(8192);
    out.push_str("\n [M] MESH CONNECTION MATRIX        You are connected to peer 1\n");
    out.push_str(&"-".repeat(line_len));
    out.push('\n');
    out.push_str(&format!(
        " {} | {} |",
        pad_right("Peer", peer_col_width),
        pad_right("IP:Port", 21)
    ));
    for i in 0..count {
        out.push_str(&format!(" {} |", pad_right(&(i + 1).to_string(), 2)));
    }
    out.push_str(" Mesh State    | Bots | Code |\n");
    out.push_str(&"-".repeat(line_len));
    out.push('\n');

    let mut issues = 0;
    let mut issue_log = String::new();
    let mut reported_mismatches: Vec<String> = Vec::new();

    for row in 0..count {
        let peer_str = all[row].label();
        // The IP:Port column shows actual connection info.
        let ip_port_str = if all[row].is_me {
            // For the local hub (peer 1), show the address hub_admin used to
            // reach us, falling back to bind_ip:port.
            let c = &state.clients[ci];
            if !c.admin_connect_ip.is_empty() && c.admin_connect_port > 0 {
                format!(
                    "{}:{}",
                    trunc_string(&c.admin_connect_ip, 46),
                    c.admin_connect_port
                )
            } else {
                format!(
                    "{}:{}",
                    trunc_string(
                        if state.bind_ip.is_empty() {
                            "0.0.0.0"
                        } else {
                            &state.bind_ip
                        },
                        46
                    ),
                    state.port
                )
            }
        } else {
            format!("{}:{}", trunc_string(&all[row].ip, 46), all[row].port)
        };
        out.push_str(&format!(
            " {}. {} | {} |",
            row + 1,
            pad_right(&peer_str, peer_col_width.saturating_sub(3)),
            pad_right(&ip_port_str, 21)
        ));

        let mut row_connected = 0;
        let mut row_total = 0;
        for col in 0..count {
            if row == col {
                out.push_str(" -- |");
                continue;
            }
            let mut found_block = false;
            let mut found_link = false;
            let mut link_up = false;

            if all[row].is_me {
                found_block = true;
                for p in &state.peers {
                    if all[col].matches(&p.uuid, &p.ip, p.port) {
                        found_link = true;
                        if peer_link_up(state, p) {
                            link_up = true;
                        }
                    }
                }
            } else {
                for g in &gossips {
                    for block in peer_gossip_blocks(g) {
                        let Some(b) = parse_gossip_block(&block) else {
                            continue;
                        };
                        if !all[row].matches(&b.owner_uuid, &b.owner_ip, b.owner_port) {
                            continue;
                        }
                        found_block = true;
                        for tok in b.peers.split(',') {
                            let Some((t_ip, t_port, stat, t_uuid, _)) = parse_gossip_peer(tok)
                            else {
                                continue;
                            };
                            if all[col].matches(&t_uuid, &t_ip, t_port) {
                                found_link = true;
                                if stat {
                                    link_up = true;
                                }
                            }
                        }
                    }
                }
            }

            // A peer may claim a link to us that we do not actually hold;
            // our own client list is the authority for our own column.
            if all[col].is_me && found_link && link_up {
                let actually_connected = state
                    .peers
                    .iter()
                    .any(|p| all[row].matches(&p.uuid, &p.ip, p.port) && peer_link_up(state, p));
                if !actually_connected {
                    link_up = false;
                }
            }

            let cell = if found_block && found_link {
                row_total += 1;
                if link_up {
                    row_connected += 1;
                    "\x1b[32mUP\x1b[0m"
                } else {
                    "\x1b[31mDN\x1b[0m"
                }
            } else {
                "??"
            };
            out.push_str(&format!(" {cell} |"));
        }

        // Are we directly connected to this row's hub?
        let directly_connected = all[row].is_me
            || state
                .peers
                .iter()
                .any(|p| all[row].matches(&p.uuid, &p.ip, p.port) && peer_link_up(state, p));

        let mut is_offline = false;
        if row_total > 0 {
            if row_connected > 0 {
                out.push_str(&format!(" {row_connected}/{row_total} Connected |"));
            } else if directly_connected {
                out.push_str(&format!(" 0/{row_total} Partial   |"));
            } else {
                out.push_str(" \x1b[31mOffline\x1b[0m       |");
                is_offline = true;
                issues += 1;
            }
        } else if all[row].is_me {
            out.push_str(" ---          |");
        } else if directly_connected {
            out.push_str(" Connected     |");
        } else {
            out.push_str(" \x1b[31mOffline\x1b[0m       |");
            is_offline = true;
            issues += 1;
        }

        // Code base (c / rs): ours is compiled in; a peer's comes from the v|
        // line of its roster gossip, so only hubs we peer with directly (and
        // that send one) are known — anything else shows "?".
        let code = if all[row].is_me {
            HUB_UPDATE_VARIANT
        } else {
            state
                .peers
                .iter()
                .find(|p| all[row].matches(&p.uuid, &p.ip, p.port))
                .map(|p| p.remote_variant.as_str())
                .filter(|v| !v.is_empty())
                .unwrap_or("?")
        };

        if is_offline {
            out.push_str(&format!(" ??   | {} |\n", pad_right(code, 4)));
        } else {
            let bot_cnt = if all[row].is_me {
                state.bot_clients().len() as i32
            } else {
                state
                    .peers
                    .iter()
                    .find(|p| p.connected && p.port == all[row].port && p.ip == all[row].ip)
                    .and_then(|p| {
                        let f: Vec<&str> = p.last_gossip.splitn(4, ':').collect();
                        (f.len() >= 3).then(|| crate::cstr::atoi(f[2]))
                    })
                    .unwrap_or(0)
            };
            out.push_str(&format!(
                " {} | {} |\n",
                pad_right(&bot_cnt.to_string(), 4),
                pad_right(code, 4)
            ));
        }

        if all[row].is_me {
            for p in &state.peers {
                if !peer_link_up(state, p) {
                    issues += 1;
                    issue_log.push_str(&format!(" [!] Peer {}:{} is DOWN.\n", p.ip, p.port));
                }
            }
        }
    }

    // Hubs a peer knows about that we are not configured for.
    for m in all.iter().filter(|m| !m.is_me) {
        let in_config = state.peers.iter().any(|p| p.port == m.port && p.ip == m.ip);
        if in_config {
            continue;
        }
        for g in &gossips {
            for block in peer_gossip_blocks(g) {
                let Some(b) = parse_gossip_block(&block) else {
                    continue;
                };
                let owner_is_known = state
                    .peers
                    .iter()
                    .any(|z| z.port == b.owner_port && z.ip == b.owner_ip);
                if !owner_is_known || !block.contains(&m.ip) {
                    continue;
                }
                let sig = format!("{}:{}->{}:{}", b.owner_ip, b.owner_port, m.ip, m.port);
                if reported_mismatches.contains(&sig) || reported_mismatches.len() >= 64 {
                    continue;
                }
                reported_mismatches.push(sig);
                issues += 1;
                issue_log.push_str(&format!(
                    " [!] Config Mismatch: Peer {}:{} knows {}:{}, but we don't.\n",
                    b.owner_ip, b.owner_port, m.ip, m.port
                ));
            }
        }
    }

    out.push_str(&"-".repeat(line_len));
    out.push('\n');
    let status_str = if issues == 0 {
        "\x1b[32mHEALTHY\x1b[0m".to_string()
    } else {
        format!("\x1b[33mDEGRADED ({issues} ISSUES)\x1b[0m")
    };
    out.push_str(&format!(
        " [i] MESH STATUS: {status_str}\n [Legend: -- = Self, UP = Connected, DN = Down, ?? = Unknown/Not Configured]\n"
    ));
    if issues > 0 {
        out.push_str(&format!(" --- Mesh Diagnostics ---\n{issue_log}"));
    }
    resp(state, ci, &out)
}

fn add_peer(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // Parse IP:PORT:UUID:NAME[:PUBKEY_B64].  UUID and NAME are optional;
    // PUBKEY_B64 is required (refused below when missing) and must be a valid
    // 88-char Curve25519 combined key — the peer is authenticated by its
    // HUBv3 signature, and there is no shared secret to fall back on.
    let f: Vec<&str> = payload.splitn(5, ':').collect();
    if payload.is_empty() || f.len() < 2 {
        return resp(state, ci, "ERROR: Use IP:PORT:UUID:NAME[:PUBKEY_B64]");
    }
    let ip = trunc_string(f[0], 256);
    let port = crate::cstr::atoi(f[1]);
    let uuid = f.get(2).map_or(String::new(), |s| trunc_string(s, 64));
    let name = f.get(3).map_or(String::new(), |s| trunc_string(s, 64));
    let pubkey_b64 = f.get(4).map_or(String::new(), |s| {
        trunc_string(s.split_whitespace().next().unwrap_or(""), 128)
    });

    // A duplicate is named as such even on a full table: "max peers" would
    // send the admin looking for a slot the add never needed.
    if !uuid.is_empty()
        && state
            .peers
            .iter()
            .any(|p| !p.uuid.is_empty() && p.uuid == uuid)
    {
        return resp(state, ci, "ERROR: Peer with this UUID already exists.");
    }
    if state.peers.len() >= MAX_PEERS {
        return resp(state, ci, "ERROR: Max peers reached.");
    }

    let mut np = PeerConfig {
        ip: trunc_string(&ip, 64),
        port,
        fd: -1,
        ..Default::default()
    };
    if !uuid.is_empty() {
        np.uuid = uuid;
    }
    if !name.is_empty() {
        np.friendly_name = name;
    }
    if !pubkey_b64.is_empty() {
        match crypto::b64_decode(&pubkey_b64) {
            Some(dec) if dec.len() == COMBINED_KEY_LEN => {
                np.ed_pub.copy_from_slice(&dec[..ED25519_KEY_LEN]);
                np.x25519_pub.copy_from_slice(&dec[ED25519_KEY_LEN..]);
                np.has_pubkey = true;
            }
            _ => {
                return resp(
                    state,
                    ci,
                    "ERROR: pubkey must be 88-char base64 of 64-byte Curve25519 combined key.",
                );
            }
        }
    }
    if !np.has_pubkey {
        return resp(
            state,
            ci,
            "ERROR: Pubkey is required. Supply the 88-char base64 Curve25519 combined key.",
        );
    }
    state.peers.push(np);
    state.config_dirty = true;
    resp(state, ci, "SUCCESS: Peer added (HUBv3 / Ed25519 auth).")
}

fn del_peer(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        let mut out = String::from(" --- Remove Local Peer ---\n");
        for (i, p) in state.peers.iter().enumerate() {
            out.push_str(&format!("[{}] {}:{}\n", i + 2, p.ip, p.port));
        }
        out.push_str("Enter Index to Remove: ");
        return resp(state, ci, &out);
    }
    // The payload is the index LIST_PEERS printed.  Anything that is not a
    // plain number is refused outright rather than read as some index.
    let Some(uidx) = parse_uint(payload, MAX_PEERS as u64 + 1) else {
        return resp(
            state,
            ci,
            "ERROR: Invalid Index (expected the number from the peer list).",
        );
    };
    let idx = uidx as usize;
    if idx == 1 {
        return resp(state, ci, "ERROR: Cannot remove local hub (Index 1).");
    }
    if idx < 2 || idx > state.peers.len() + 1 {
        return resp(state, ci, "ERROR: Invalid Index.");
    }
    let target = idx - 2;
    let admin_fd = state.clients[ci].fd;
    let target_fd = state.peers[target].fd;
    if target_fd != -1
        && let Some(cj) = state.client_by_fd(target_fd)
    {
        auth::disconnect_client(state, cj);
    }
    let msg = format!(
        "SUCCESS: Deleted Peer {}:{}.",
        state.peers[target].ip, state.peers[target].port
    );
    state.peers.remove(target);
    state.config_dirty = true;
    // The disconnect above swap-removed the client list; re-find ourselves.
    let Some(ci) = state.client_by_fd(admin_fd) else {
        return false;
    };
    resp(state, ci, &msg)
}

fn set_peer_pubkey(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let f: Vec<&str> = payload.splitn(2, ':').collect();
    if f.len() != 2 || f[0].is_empty() || f[1].is_empty() {
        return resp(state, ci, "ERROR: Use UUID:PUBKEY_B64");
    }
    let uuid = trunc_string(f[0], 64);
    let pubkey_b64 = trunc_string(f[1].split_whitespace().next().unwrap_or(""), 128);
    let Some(pi) = state.peers.iter().position(|p| p.uuid == uuid) else {
        return resp(state, ci, "ERROR: No peer with that UUID.");
    };
    match crypto::b64_decode(&pubkey_b64) {
        Some(dec) if dec.len() == COMBINED_KEY_LEN => {
            state.peers[pi]
                .ed_pub
                .copy_from_slice(&dec[..ED25519_KEY_LEN]);
            state.peers[pi]
                .x25519_pub
                .copy_from_slice(&dec[ED25519_KEY_LEN..]);
            state.peers[pi].has_pubkey = true;
        }
        _ => {
            return resp(
                state,
                ci,
                "ERROR: pubkey must be 88-char base64 of 64-byte combined key.",
            );
        }
    }
    state.config_dirty = true;
    crate::hlog_info!("[HUB] Peer {uuid} pubkey set — next connection will use v2 Ed25519 auth.\n");
    resp(
        state,
        ci,
        "SUCCESS: Peer pubkey registered. Reconnect the peer to authenticate with it (HUBv3).",
    )
}

// ---------------------------------------------------------------------------
// Named admin/oper records
// ---------------------------------------------------------------------------

fn list_users(state: &mut HubState, ci: usize, type_ch: char) -> bool {
    let label = if type_ch == 'a' { "admins" } else { "opers" };
    let name_w = state
        .user_records
        .iter()
        .filter(|u| u.typ == type_ch && u.is_active)
        .map(|u| u.name.len())
        .max()
        .unwrap_or(0)
        .max(8);
    let mut out = format!("| irchub {label}\n+{RULE}\n");
    let mut shown = 0;
    for u in state
        .user_records
        .iter()
        .filter(|u| u.typ == type_ch && u.is_active)
    {
        out.push_str(&format!(
            "| {}  key {}  (last seen: {})\n",
            pad_right(&u.name, name_w),
            crypto::key_fingerprint_b64(if u.has_pubkey { &u.pubkey_b64 } else { "" }),
            utc_time(u.last_seen)
        ));
        for m in state
            .mask_records
            .iter()
            .filter(|m| m.uuid == u.uuid && m.is_active)
        {
            out.push_str(&format!("|   {}\n", m.mask));
        }
        shown += 1;
    }
    if shown == 0 {
        out.push_str("| (none)\n");
    }
    out.push_str(&format!("`{RULE}"));
    resp(state, ci, &out)
}

fn add_user_record(state: &mut HubState, ci: usize, payload: &str, typ: char) -> bool {
    // Payload: name|pubkey_b64|mask.  The user generated their own keypair
    // (keygen) and only the public half arrives: the hub never mints or
    // delivers a user's private key.
    if payload.is_empty() {
        return resp(state, ci, "ERR:missing payload");
    }
    let f = split_fields(payload, 3);
    if f.len() < 3 || f[0].is_empty() || f[1].is_empty() || f[2].is_empty() {
        return resp(state, ci, "ERR:syntax name|pubkey|mask");
    }
    let pname = trunc_string(f[0], 64);
    let ppub = trunc_string(f[1], COMBINED_KEY_B64 + 2);
    let pmask = trunc_string(f[2].split_whitespace().next().unwrap_or(""), MAX_MASK_LEN);

    if pname.is_empty() || pname.contains('|') || pname.contains(' ') {
        return resp(state, ci, "ERR:invalid name");
    }
    let Some(praw) = crypto::pubkey_b64_decode(&ppub) else {
        return resp(
            state,
            ci,
            "ERR:pubkey must be the user's 88-char public key (contents of their .public.b64)",
        );
    };
    if !pmask.contains('!') || !pmask.contains('@') {
        return resp(state, ci, "ERR:mask must contain ! and @");
    }
    // Name uniqueness across all a|/o| records, and key uniqueness:
    // hub_admin logins identify the admin by key.
    for u in state.user_records.iter().filter(|u| u.is_active) {
        if u.name.eq_ignore_ascii_case(&pname) {
            return resp(state, ci, "ERR:name already exists");
        }
        if u.has_pubkey && u.pubkey_b64 == ppub {
            return resp(state, ci, "ERR:that key already belongs to another user");
        }
    }
    if state.user_records.len() >= MAX_HUB_USER_RECORDS {
        return resp(state, ci, "ERR:user record table full");
    }
    if state.mask_records.len() >= MAX_HUB_USER_MASKS {
        return resp(state, ci, "ERR:mask record table full");
    }
    let t = now();
    let Some(new_uuid) = crypto::gen_uuid_v4() else {
        return resp(state, ci, "ERR:out of entropy");
    };

    state.user_records.push(UserRecord {
        uuid: new_uuid.clone(),
        name: pname.clone(),
        pubkey_b64: ppub,
        has_pubkey: true,
        typ,
        is_active: true,
        last_seen: 0,
        timestamp: t,
    });
    state.mask_records.push(MaskRecord {
        uuid: new_uuid,
        mask: pmask.clone(),
        is_active: true,
        last_used: 0,
        timestamp: t,
    });
    state.config_dirty = true;

    // Bots get fresh per-connection payloads (the right shape per bot
    // version); peers get the canonical record line.
    let u = state.user_records.last().unwrap().clone();
    let m = state.mask_records.last().unwrap().clone();
    let sync = crate::config::format_user_record(&u, false);
    client::broadcast_config_to_bots(state, &sync);
    mesh::broadcast_sync_to_peers(state, &sync, -1);
    let msync = format!("m|{}|{}|add|0|{t}\n", m.uuid, m.mask);
    mesh::broadcast_sync_to_peers(state, &msync, -1);

    let msg = format!(
        "SUCCESS|{typ}|{pname}|{pmask}|{}",
        crypto::key_fingerprint(&praw)
    );
    resp(state, ci, &msg)
}

fn del_user_record(state: &mut HubState, ci: usize, payload: &str, is_admin: bool) -> bool {
    if payload.is_empty() {
        return resp(state, ci, "ERR:missing name");
    }
    let Some(ui) = state
        .user_records
        .iter()
        .position(|u| u.is_active && u.name.eq_ignore_ascii_case(payload))
    else {
        return resp(state, ci, "ERR:user not found");
    };

    // Peers get ONE sync payload: the user tombstone, then a tombstone for
    // every mask the user owned.  No peer or bot cascades a user delete to
    // its masks, so a mask tombstone that is not sent leaves the mask live
    // there: an orphan holding a slot of the shared 200-mask table on every
    // other hub and on their bots.  One payload keeps the lines in order and
    // off the per-lane message cap (a user may own every mask slot).
    state.user_records[ui].is_active = false;
    state.user_records[ui].timestamp = lww_next_ts(state.user_records[ui].timestamp);
    state.config_dirty = true;

    let target_uuid = state.user_records[ui].uuid.clone();
    let target_name = state.user_records[ui].name.clone();
    let uline = crate::config::format_user_record(&state.user_records[ui], false);
    let mut sync = if uline.len() < USER_LINE_MAX {
        uline.clone()
    } else {
        String::new()
    };

    let mut masks_dropped = 0;
    for m in state.mask_records.iter_mut() {
        if m.uuid != target_uuid || !m.is_active {
            continue;
        }
        m.is_active = false;
        m.timestamp = lww_next_ts(m.timestamp);
        masks_dropped += 1;
        sync.push_str(&format!(
            "m|{}|{}|del|{}|{}\n",
            m.uuid, m.mask, m.last_used, m.timestamp
        ));
    }

    client::broadcast_config_to_bots(state, &uline); // logs the user line only
    mesh::broadcast_sync_to_peers(state, &sync, -1);
    crate::hlog_info!(
        "[ADMIN] {} {target_name} removed with {masks_dropped} usermask(s)\n",
        if is_admin { "Admin" } else { "Oper" }
    );
    let msg = format!("SUCCESS: {payload} removed");
    resp(state, ci, &msg)
}

fn add_usermask(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        return resp(state, ci, "ERR:missing payload");
    }
    let f = split_fields(payload, 2);
    if f.len() < 2 || f[0].is_empty() || f[1].is_empty() {
        return resp(state, ci, "ERR:syntax name|mask");
    }
    let pname = trunc_string(f[0], 64);
    let pmask = trunc_string(f[1].split_whitespace().next().unwrap_or(""), MAX_MASK_LEN);
    if !pmask.contains('!') || !pmask.contains('@') {
        return resp(state, ci, "ERR:mask must contain ! and @");
    }
    let Some(ui) = state
        .user_records
        .iter()
        .position(|u| u.is_active && u.name.eq_ignore_ascii_case(&pname))
    else {
        return resp(state, ci, "ERR:user not found");
    };
    let target_uuid = state.user_records[ui].uuid.clone();

    // A duplicate active mask is an error; a tombstone for the same mask is
    // revived past its stamp (a second record could tie with the remove).
    let mut mi = None;
    for i in 0..state.mask_records.len() {
        let m = &state.mask_records[i];
        if m.uuid != target_uuid || !m.mask.eq_ignore_ascii_case(&pmask) {
            continue;
        }
        if m.is_active {
            return resp(state, ci, "ERR:mask already exists");
        }
        mi = Some(i);
    }
    let mi = match mi {
        Some(i) => {
            state.mask_records[i].timestamp = lww_next_ts(state.mask_records[i].timestamp);
            i
        }
        None => {
            if state.mask_records.len() >= MAX_HUB_USER_MASKS {
                return resp(state, ci, "ERR:mask table full");
            }
            state.mask_records.push(MaskRecord {
                uuid: target_uuid,
                mask: pmask.clone(),
                is_active: false,
                last_used: 0,
                timestamp: now(),
            });
            state.mask_records.len() - 1
        }
    };
    state.mask_records[mi].is_active = true;
    state.config_dirty = true;
    let m = state.mask_records[mi].clone();
    let sync = format!(
        "m|{}|{}|add|{}|{}\n",
        m.uuid, m.mask, m.last_used, m.timestamp
    );
    client::broadcast_config_to_bots(state, &sync);
    mesh::broadcast_sync_to_peers(state, &sync, -1);
    let msg = format!("SUCCESS: mask {pmask} added to {pname}");
    resp(state, ci, &msg)
}

fn del_usermask(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        return resp(state, ci, "ERR:missing payload");
    }
    let f = split_fields(payload, 2);
    if f.len() < 2 || f[0].is_empty() || f[1].is_empty() {
        return resp(state, ci, "ERR:syntax name|mask");
    }
    let pname = trunc_string(f[0], 64);
    let pmask = trunc_string(f[1].split_whitespace().next().unwrap_or(""), MAX_MASK_LEN);
    let Some(ui) = state
        .user_records
        .iter()
        .position(|u| u.is_active && u.name.eq_ignore_ascii_case(&pname))
    else {
        return resp(state, ci, "ERR:user not found");
    };
    let target_uuid = state.user_records[ui].uuid.clone();
    let Some(mi) = state
        .mask_records
        .iter()
        .position(|m| m.is_active && m.uuid == target_uuid && m.mask.eq_ignore_ascii_case(&pmask))
    else {
        return resp(state, ci, "ERR:mask not found");
    };
    state.mask_records[mi].is_active = false;
    state.mask_records[mi].timestamp = lww_next_ts(state.mask_records[mi].timestamp);
    state.config_dirty = true;
    let m = state.mask_records[mi].clone();
    let sync = format!(
        "m|{}|{}|del|{}|{}\n",
        m.uuid, m.mask, m.last_used, m.timestamp
    );
    client::broadcast_config_to_bots(state, &sync);
    mesh::broadcast_sync_to_peers(state, &sync, -1);
    let msg = format!("SUCCESS: mask {pmask} removed from {pname}");
    resp(state, ci, &msg)
}

fn set_userkey(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // Payload: name|pubkey_b64 — replace a user's key (rotation, a lost key,
    // or giving a legacy keyless user one).  UUID, masks and history stay;
    // the old key stops working for hub_admin and every bot at sync speed.
    if payload.is_empty() {
        return resp(state, ci, "ERR:missing payload");
    }
    let f = split_fields(payload, 2);
    if f.len() < 2 || f[0].is_empty() || f[1].is_empty() {
        return resp(state, ci, "ERR:syntax name|pubkey");
    }
    let pname = trunc_string(f[0], 64);
    let ppub = trunc_string(
        f[1].split_whitespace().next().unwrap_or(""),
        COMBINED_KEY_B64 + 2,
    );
    let Some(praw) = crypto::pubkey_b64_decode(&ppub) else {
        return resp(
            state,
            ci,
            "ERR:pubkey must be the user's 88-char public key (contents of their .public.b64)",
        );
    };
    let Some(ti) = state
        .user_records
        .iter()
        .position(|u| u.is_active && u.name.eq_ignore_ascii_case(&pname))
    else {
        return resp(state, ci, "ERR:user not found");
    };
    if state
        .user_records
        .iter()
        .enumerate()
        .any(|(i, o)| i != ti && o.is_active && o.has_pubkey && o.pubkey_b64 == ppub)
    {
        return resp(state, ci, "ERR:that key already belongs to another user");
    }
    {
        let u = &mut state.user_records[ti];
        u.pubkey_b64 = ppub;
        u.has_pubkey = true;
        // Bump the timestamp so peers and bots see this update as newer than
        // the old record (otherwise replication compares ts and drops it).
        u.timestamp = lww_next_ts(u.timestamp);
    }
    state.config_dirty = true;
    let sync = crate::config::format_user_record(&state.user_records[ti], false);
    client::broadcast_config_to_bots(state, &sync);
    mesh::broadcast_sync_to_peers(state, &sync, -1);
    let msg = format!(
        "SUCCESS: key for {} set ({})",
        state.user_records[ti].name,
        crypto::key_fingerprint(&praw)
    );
    resp(state, ci, &msg)
}

fn match_user(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        return resp(state, ci, "ERR:missing name");
    }
    let match_all = payload == "*";
    let hit = |u: &UserRecord| u.is_active && (match_all || u.name.eq_ignore_ascii_case(payload));
    let name_w = state
        .user_records
        .iter()
        .filter(|u| hit(u))
        .map(|u| u.name.len())
        .max()
        .unwrap_or(0)
        .max(8);

    let mut out = format!(
        "| irchub match{}\n+{RULE}\n",
        if match_all { " *" } else { "" }
    );
    let mut shown = 0;
    for u in state.user_records.iter().filter(|u| hit(u)) {
        out.push_str(&format!(
            "| [{}] {}  key {}  (last seen: {})\n",
            u.typ,
            pad_right(&u.name, name_w),
            crypto::key_fingerprint_b64(if u.has_pubkey { &u.pubkey_b64 } else { "" }),
            utc_time(u.last_seen)
        ));
        for m in state
            .mask_records
            .iter()
            .filter(|m| m.uuid == u.uuid && m.is_active)
        {
            out.push_str(&format!(
                "|   {}  (last used: {})\n",
                m.mask,
                utc_time(m.last_used)
            ));
        }
        shown += 1;
    }
    if shown == 0 {
        out.push_str("| unknown user\n");
    }
    out.push_str(&format!("`{RULE}"));
    resp(state, ci, &out)
}

// ---------------------------------------------------------------------------
// Channels and legacy global masks
// ---------------------------------------------------------------------------

fn list_channels(state: &mut HubState, ci: usize) -> bool {
    let mut out = String::from("--- Global Channels ---\n");
    out.push_str(&format!(
        "{}{}\n",
        pad_right("Channel", 31),
        pad_right("Key", 20)
    ));
    out.push_str(&format!(
        "{}{}\n",
        pad_right("-------", 31),
        pad_right("---", 20)
    ));
    let mut chan_count = 0;
    for e in state.global_entries.iter().filter(|e| e.key == "c") {
        // Handles both the 3-field admin shape and the 4-field bot shape that
        // carries modes; op is read as the last field so the tombstone check
        // below is correct for either.
        let Some((chan_name, chan_key, _, op)) = mesh::parse_global_channel_value(&e.value) else {
            continue;
        };
        if op == "del" || chan_name.is_empty() {
            continue;
        }
        chan_count += 1;
        out.push_str(&format!(
            "{}{}\n",
            pad_right(&trunc_string(&chan_name, 128), 31),
            pad_right(&trunc_string(&chan_key, 64), 20)
        ));
    }
    if chan_count == 0 {
        out.push_str("  (No channels configured)\n");
    }
    resp(state, ci, &out)
}

fn add_channel(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        return resp(state, ci, "ERROR: Invalid payload.");
    }
    let f: Vec<&str> = payload.splitn(2, '|').collect();
    let chan = trunc_string(f[0], 128);
    if chan.is_empty() {
        return resp(state, ci, "ERROR: Invalid payload.");
    }
    let key = f.get(1).map_or(String::new(), |s| {
        trunc_string(s.split_whitespace().next().unwrap_or(""), 64)
    });

    // Past the stored stamp: a remove in this same second would tie, and the
    // newest command must be the one that sticks.
    let t = lww_next_ts(storage::global_ts(state, "c", &chan));
    // Carry forward any modes a bot previously reported for this channel.
    // The admin console only prompts for name + key, and the storage layer
    // replaces the whole value once the timestamp wins, so without this an
    // admin re-add to change the key silently wipes the recorded +i/+k state.
    // Store and sync the 4-field shape so both writers agree.
    let modes = mesh::global_channel_modes(state, &chan);
    let extra = format!("{key}|{modes}");
    storage::update_global_entry(state, "c", &chan, &extra, "add", t);
    state.config_dirty = true;

    let sync_msg = format!("c|{chan}|{key}|{modes}|add|{t}\n");
    client::broadcast_config_to_bots(state, &sync_msg);
    mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
    resp(state, ci, "SUCCESS: Channel added and synced.")
}

fn del_channel(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        return resp(state, ci, "ERROR: Missing channel name.");
    }
    let t = lww_next_ts(storage::global_ts(state, "c", payload));
    storage::update_global_entry(state, "c", payload, "", "del", t);
    state.config_dirty = true;
    let sync_msg = format!("c|{payload}||del|{t}\n");
    client::broadcast_config_to_bots(state, &sync_msg);
    mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
    resp(state, ci, "SUCCESS: Channel removed and synced.")
}

fn list_masks(state: &mut HubState, ci: usize) -> bool {
    let mut out = String::from("--- Admin Masks ---\n");
    out.push_str(&format!("{}\n", pad_right("Mask", 50)));
    out.push_str(&format!("{}\n", pad_right("----", 50)));
    let mut mask_count = 0;
    for e in state.global_entries.iter().filter(|e| e.key == "m") {
        let f: Vec<&str> = e.value.splitn(2, '|').collect();
        if f.len() != 2 {
            continue;
        }
        let op = f[1].split_whitespace().next().unwrap_or("");
        if op == "del" {
            continue;
        }
        mask_count += 1;
        out.push_str(&format!("{}\n", pad_right(&trunc_string(f[0], 256), 50)));
    }
    if mask_count == 0 {
        out.push_str("  (No admin masks configured)\n");
    }
    resp(state, ci, &out)
}

/// Legacy global oper masks (pre-passwordless).  They authenticate no one any
/// more; they are listed only so they can be removed.  Their stored password
/// is never shown (and is no longer stored at all).
fn list_opers_legacy(state: &mut HubState, ci: usize) -> bool {
    let mut out =
        String::from("--- Legacy Oper Masks (retired: no password, no login; remove them) ---\n");
    let mut oper_count = 0;
    for e in state.global_entries.iter().filter(|e| e.key == "o") {
        let (Some(first), Some(last)) = (e.value.find('|'), e.value.rfind('|')) else {
            continue;
        };
        if &e.value[last + 1..] == "del" {
            continue;
        }
        oper_count += 1;
        out.push_str(&format!("  {}\n", &e.value[..first]));
    }
    if oper_count == 0 {
        out.push_str("  (No oper masks configured)\n");
    }
    resp(state, ci, &out)
}

// ---------------------------------------------------------------------------
// Hub keys
// ---------------------------------------------------------------------------

/// Local-only hub rekey: generate a new Curve25519 keypair, save it encrypted
/// in the config, and dump the new public key for re-distribution.  With
/// independent per-hub keys the new pubkey is NOT pushed to peers; each peer
/// hub must re-register it via 'Set Peer Pubkey', and bots must re-run
/// 'sethubpub'.
fn regen_keys(state: &mut HubState, ci: usize) -> bool {
    let Some((priv64, pub64)) = crypto::generate_combined_keypair() else {
        return resp(state, ci, "ERROR: Key generation failed.");
    };
    state.set_hub_priv(&priv64);
    state.set_hub_pub(&pub64);
    let pub_b64 = crypto::b64_encode(&pub64);
    state.hub_keys_loaded = true;
    state.config_dirty = true;

    // Disconnect peers and bots so they must reauthenticate (and rediscover
    // that this hub's pubkey changed).
    let admin_fd = state.clients[ci].fd;
    let mut i = 0;
    while i < state.clients.len() {
        if matches!(state.clients[i].typ, ClientType::Hub | ClientType::Bot) {
            auth::disconnect_client(state, i);
            continue;
        }
        i += 1;
    }
    let Some(ci) = state.client_by_fd(admin_fd) else {
        return false;
    };

    let fname = chrono::Local::now()
        .format("%Y%m%d%H%M_pub.b64")
        .to_string();
    let _ = std::fs::write(&fname, &pub_b64);
    resp(state, ci, &pub_b64)
}

fn set_privkey(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.len() < COMBINED_KEY_B64 {
        return resp(state, ci, "ERROR: Empty or short payload.");
    }
    let Some(dec) = crypto::b64_decode(payload).filter(|d| d.len() == COMBINED_KEY_LEN) else {
        return resp(
            state,
            ci,
            "ERROR: Invalid Curve25519 key (need 64-byte base64).",
        );
    };
    let mut combined = Zeroizing::new([0u8; COMBINED_KEY_LEN]);
    combined.copy_from_slice(&dec);
    state.set_hub_priv(&combined);
    // Derive the public key from the private one — it is not a setting of its
    // own.
    let pub64 = crypto::combined_pub_from_priv(&combined);
    state.set_hub_pub(&pub64);
    state.hub_keys_loaded = true;
    state.config_dirty = true;
    resp(state, ci, "SUCCESS: Private Key Imported & Saved.")
}

fn set_pubkey(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.len() < COMBINED_KEY_B64 {
        return resp(state, ci, "ERROR: Empty Payload.");
    }
    let Some(want) = crypto::pubkey_b64_decode(payload) else {
        return resp(state, ci, "ERROR: Invalid Curve25519 public key.");
    };
    // The public key is not a setting of its own: it is fixed by the private
    // key.  Storing any other key made every signature this hub produces
    // (admin logins, bot and peer handshakes) fail against what it announces
    // — an admin lockout.  Accept only the key the private key derives; a new
    // identity goes through Set Private Key or Regenerate.
    if !state.hub_keys_loaded {
        return resp(
            state,
            ci,
            "ERROR: No private key loaded; cannot verify the public key.",
        );
    }
    let derived = crypto::combined_pub_from_priv(&state.hub_priv_combined());
    if !crypto::ct_eq(&derived, &want) {
        return resp(
            state,
            ci,
            "ERROR: That public key does not belong to this hub's private key (use Set Private Key or Regenerate to change the hub identity).",
        );
    }
    state.set_hub_pub(&derived);
    state.config_dirty = true;
    resp(state, ci, "SUCCESS: Public Key Imported & Saved.")
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// handle_admin_command().
///
/// `payload` is the NUL-terminated text for the text opcodes; `raw` and
/// `raw_len` are the bytes the frame actually carried, for the binary ones (a
/// log level of 0 is the byte 0x00, and a log size with a zero byte has
/// strlen < its real length).
pub fn handle_admin_command(
    state: &mut HubState,
    ci: usize,
    cmd: u8,
    payload: &str,
    raw: &[u8],
    raw_len: usize,
) -> bool {
    // Task 6: an upgrade run holds the config still.  One gate here covers
    // every mutator rather than a check inside each; queries and the opt-flag
    // command itself stay available (the latter is how a stuck freeze is
    // lifted by hand).
    if upgrade::config_frozen(state) && upgrade::admin_cmd_mutates_config(cmd) {
        crate::hlog_warning!(
            "[UPGRADE] Refused admin command 0x{:02x}: config frozen\n",
            cmd
        );
        return resp(state, ci, "ERROR: config frozen (upgrade in progress)");
    }

    match cmd {
        CMD_ADMIN_UPGRADE_NET => {
            // Payload: target_ver|variant|kind|min_from|base|hub_ver|hub_base
            // — everything past the version is optional ("" = let each node
            // decide).  target_ver/base are the bots' (ircbot-releases);
            // hub_ver/hub_base are the hubs' own (irchub-releases), and an
            // empty hub_ver leaves every hub where it is.  A base never
            // contains '|' (upgrade::start refuses one), so only the last
            // field is a tail.
            let f: Vec<&str> = payload.splitn(7, '|').collect();
            let at = |i: usize| f.get(i).copied().unwrap_or("");
            let fd = state.clients[ci].fd;
            let msg = upgrade::start(
                state,
                fd,
                &upgrade::StartArgs {
                    target_ver: at(0),
                    variant: at(1),
                    kind: at(2),
                    min_from: at(3),
                    base: at(4),
                    hub_ver: at(5),
                    hub_base: at(6),
                },
            );
            resp(state, ci, &msg)
        }

        CMD_ADMIN_UPGRADE_STATUS => {
            // A payload of "abort" stops a run in flight and rolls the mesh
            // back.
            if payload.eq_ignore_ascii_case("abort") {
                if !state.upgrade.active {
                    return resp(state, ci, "ERROR: no upgrade is running");
                }
                upgrade::abort(state, "aborted by admin");
                return resp(state, ci, "OK:upgrade aborted; rolling back");
            }
            // "forget" drops the roll-up plan a finished run left behind, here
            // and (flooded) on every other hub.
            if payload.eq_ignore_ascii_case("forget") {
                let out = upgrade::admin_forget(state);
                return resp(state, ci, &out);
            }
            let out = upgrade::status(state);
            resp(state, ci, &out)
        }

        CMD_ADMIN_LIST_SUMMARY => {
            let out = storage::get_summary_list(state);
            resp(state, ci, &out)
        }
        CMD_ADMIN_GET_PENDING => get_pending(state, ci),
        CMD_ADMIN_LIST_FULL => list_full(state, ci),

        CMD_ADMIN_REKEY_BOT => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR|Missing UUID");
            }
            // v3: per-bot independent keys.  Only the bot can rekey — it owns
            // its private key.  The bot's 'rekey' admin command regenerates
            // the keypair locally and pushes the new PUBLIC key to us over
            // its authenticated session (we store it as the bot's 'pub' entry
            // and fan it out to peers via auto-sync).  We deliberately do NOT
            // disconnect the bot here: it needs that active session to push
            // the new pub, and it reconnects itself with the new key as the
            // final step of 'rekey'.
            let bot_online = state
                .clients
                .iter()
                .any(|c| c.typ == ClientType::Bot && c.id == payload);
            let msg = format!(
                "INSTRUCT|{payload}|rekey is bot-local (only the bot holds its private key). As an admin, send the bot the command 'rekey' through your IRC client's ircbot auth script (a sealed ~A2 command signed with your key).\nThe bot generates a new keypair, pushes its new pubkey here, and reconnects; peers auto-sync. Bot is currently {}.",
                if bot_online {
                    "ONLINE — you can rekey now"
                } else {
                    "OFFLINE — wait for it to reconnect first"
                }
            );
            resp(state, ci, &msg)
        }

        CMD_ADMIN_DISCONNECT_BOT => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing UUID");
            }
            let admin_fd = state.clients[ci].fd;
            let found = state
                .clients
                .iter()
                .position(|c| c.typ == ClientType::Bot && c.id == payload);
            match found {
                Some(bi) => {
                    crate::hlog_warning!("[ADMIN] Disconnecting bot {payload}\n");
                    auth::disconnect_client(state, bi);
                    let Some(ci) = state.client_by_fd(admin_fd) else {
                        return false;
                    };
                    resp(state, ci, "SUCCESS: Bot disconnected")
                }
                None => resp(state, ci, "ERROR: Bot not connected"),
            }
        }

        CMD_ADMIN_DEL => {
            let admin_fd = state.clients[ci].fd;
            let Some(del_ts) = storage::delete(state, payload) else {
                return resp(state, ci, "ERROR: Not found.");
            };
            if let Some(bi) = state
                .clients
                .iter()
                .position(|c| c.typ == ClientType::Bot && c.id == payload)
            {
                crate::hlog_warning!("[ADMIN] Disconnecting deleted bot {payload}\n");
                auth::disconnect_client(state, bi);
            }
            // Peers store the same tombstone (same stamp); every bot gets a
            // config that no longer lists the deleted bot and ends in the T|
            // marker, so it drops the bot from its trusted list (no more ~B2
            // or op grants).
            let sync = format!("b|{payload}|d|1|{del_ts}\n");
            mesh::broadcast_sync_to_peers(state, &sync, -1);
            client::broadcast_config_to_bots(state, &sync);
            let Some(ci) = state.client_by_fd(admin_fd) else {
                return false;
            };
            resp(state, ci, "SUCCESS: Deleted & Synced.")
        }

        CMD_ADMIN_APPROVE => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing Index or UUID.");
            }
            let target_uuid = if payload.len() < 4 {
                let idx = parse_uint(payload, 999).unwrap_or(0) as usize;
                if idx == 0 || idx > state.pending.len() {
                    return resp(state, ci, "ERROR: Invalid Index.");
                }
                state.pending[idx - 1].uuid.clone()
            } else {
                payload.to_string()
            };
            if target_uuid.is_empty() {
                return resp(state, ci, "ERROR: Missing Index or UUID.");
            }
            let t = now();
            storage::update_entry(state, &target_uuid, "t", "", "", "", t);
            state.config_dirty = true;
            auth::remove_pending_bot(state, &target_uuid);
            let sync = format!("{target_uuid}|t||{t}\n");
            mesh::broadcast_sync_to_peers(state, &sync, -1);
            resp(state, ci, "SUCCESS: Bot Authorized & Synced.")
        }

        CMD_ADMIN_ADD => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Invalid UUID.");
            }
            let t = now();
            storage::update_entry(state, payload, "t", "", "", "", t);
            state.config_dirty = true;
            let sync = format!("{payload}|t||{t}\n");
            mesh::broadcast_sync_to_peers(state, &sync, -1);
            resp(state, ci, "SUCCESS: UUID Authorized & Synced.")
        }

        CMD_ADMIN_SYNC_MESH => {
            let full_sync = mesh::generate_sync_packet(state);
            mesh::broadcast_sync_to_peers(state, &full_sync, -1);
            resp(state, ci, "SUCCESS: Full Sync broadcasted.")
        }

        CMD_ADMIN_CREATE_BOT => create_bot(state, ci, payload),
        CMD_ADMIN_REGEN_KEYS => regen_keys(state, ci),

        CMD_ADMIN_GET_PUBKEY => {
            if !state.hub_keys_loaded {
                return resp(state, ci, "ERROR: No Key Available.");
            }
            let b = crypto::b64_encode(&state.hub_pub_combined());
            resp(state, ci, &b)
        }
        CMD_ADMIN_SET_PRIVKEY => set_privkey(state, ci, payload),
        CMD_ADMIN_GET_PRIVKEY => {
            if !state.hub_keys_loaded {
                return resp(state, ci, "ERROR: No Private Key in Memory.");
            }
            let b = Zeroizing::new(crypto::b64_encode(state.hub_priv_combined().as_ref()));
            resp(state, ci, &b)
        }
        CMD_ADMIN_SET_PUBKEY => set_pubkey(state, ci, payload),

        CMD_ADMIN_ADD_PEER => add_peer(state, ci, payload),
        CMD_ADMIN_DEL_PEER => del_peer(state, ci, payload),
        CMD_ADMIN_SET_PEER_PUBKEY => set_peer_pubkey(state, ci, payload),
        CMD_ADMIN_LIST_PEERS => list_peers(state, ci),

        CMD_ADMIN_LIST_CHANNELS => list_channels(state, ci),
        CMD_ADMIN_ADD_CHANNEL => add_channel(state, ci, payload),
        CMD_ADMIN_DEL_CHANNEL => del_channel(state, ci, payload),

        CMD_ADMIN_LIST_MASKS => list_masks(state, ci),
        CMD_ADMIN_ADD_MASK => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing mask.");
            }
            let t = now();
            storage::update_global_entry(state, "m", payload, "", "add", t);
            state.config_dirty = true;
            let sync_msg = format!("m|{payload}|add|{t}\n");
            client::broadcast_config_to_bots(state, &sync_msg);
            mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
            resp(state, ci, "SUCCESS: Admin mask added and synced.")
        }
        CMD_ADMIN_DEL_MASK => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing mask.");
            }
            let t = now();
            storage::update_global_entry(state, "m", payload, "", "del", t);
            state.config_dirty = true;
            let sync_msg = format!("m|{payload}|del|{t}\n");
            client::broadcast_config_to_bots(state, &sync_msg);
            mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
            resp(state, ci, "SUCCESS: Admin mask removed and synced.")
        }

        CMD_ADMIN_LIST_OPERS => list_opers_legacy(state, ci),
        // Retired with passwordless: a mask|password oper stored the password
        // in plaintext, replicated it to every hub and listed it back.  Opers
        // are key-based records now (CMD_ADMIN_ADD_OPER_RECORD).
        CMD_ADMIN_ADD_OPER => resp(
            state,
            ci,
            "ERR:retired (oper passwords removed; add an oper with a public key instead)",
        ),
        CMD_ADMIN_DEL_OPER => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing mask.");
            }
            let t = now();
            storage::update_global_entry(state, "o", payload, "", "del", t);
            state.config_dirty = true;
            let sync_msg = format!("o|{payload}||del|{t}\n");
            client::broadcast_config_to_bots(state, &sync_msg);
            mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
            resp(state, ci, "SUCCESS: Oper mask removed and synced.")
        }

        // Retired with passwordless (docs/passwordless.md §7.2): an older
        // hub_admin still offering these gets a clear answer, nothing changes.
        CMD_ADMIN_SET_ADMIN_PASS | CMD_ADMIN_SET_BOT_PASS | CMD_ADMIN_SET_USERPASS => resp(
            state,
            ci,
            "ERR:retired (passwords removed; keys only — use 'Change user public key')",
        ),

        CMD_ADMIN_OP_USER => {
            let f = split_fields(payload, 2);
            if payload.is_empty() || f.len() < 2 || f[0].is_empty() || f[1].is_empty() {
                return resp(state, ci, "ERROR: Invalid payload (need nick|channel).");
            }
            let nick = f[0].to_string();
            let channel = f[1].split_whitespace().next().unwrap_or("").to_string();
            let admin_fd = state.clients[ci].fd;
            let sent = opflow::admin_op_user(state, &nick, &channel);
            // Forwarding may have dropped a peer whose URGENT queue was full,
            // which swap-removes the client list.
            let Some(ci) = state.client_by_fd(admin_fd) else {
                return false;
            };
            let msg = if sent > 0 {
                format!(
                    "SUCCESS: Op request sent to {sent} local bot(s) and forwarded to peer hubs"
                )
            } else {
                "SUCCESS: Op request forwarded to peer hubs (no local bots connected)".to_string()
            };
            resp(state, ci, &msg)
        }

        CMD_ADMIN_PURGE_TOMBSTONES => {
            // Payload: "immediate" -> cutoff 0 (purge all); "<N>" days ->
            // cutoff = now - N*86400.
            //
            // Fail closed: only "immediate" purges everything.  A payload
            // that is not a whole number of days >= 1 is refused — atoi()
            // used to read "7d", "-3" or an empty payload as 0, i.e. purge
            // every tombstone now.
            let t = now();
            let mut cutoff = 0i64;
            let mut days_label = 0u64;
            if payload != "immediate" {
                let Some(udays) = parse_uint(payload, 36500).filter(|&d| d != 0) else {
                    return resp(
                        state,
                        ci,
                        "ERROR: Purge needs 'immediate' or a number of days >= 1.",
                    );
                };
                cutoff = t - (udays as i64) * 86400;
                days_label = udays;
            }
            let (purged_count, purge_log) = mesh::execute_purge(state, cutoff);
            if !mesh::broadcast_purge(state, cutoff) {
                return resp(
                    state,
                    ci,
                    "ERROR: Purged locally, but the purge could not be sent to peers.",
                );
            }
            let msg = if purged_count > 0 {
                format!(
                    "SUCCESS: Purged {purged_count} local tombstone(s), purge broadcast sent to peers\n{}",
                    trunc_string(&purge_log, MAX_BUFFER - 100)
                )
            } else if days_label > 0 {
                format!(
                    "SUCCESS: No local tombstones older than {days_label} days found, purge broadcast sent to peers"
                )
            } else {
                "SUCCESS: No local tombstones found, purge broadcast sent to peers".to_string()
            };
            resp(state, ci, &msg)
        }

        CMD_ADMIN_SET_PURGE_DAYS => {
            if payload.is_empty() {
                return resp(
                    state,
                    ci,
                    "ERROR: Missing days parameter (use 0 to disable)",
                );
            }
            let Some(udays) = parse_uint(payload, 36500) else {
                return resp(
                    state,
                    ci,
                    "ERROR: Purge days must be a whole number (0 disables).",
                );
            };
            let days = udays as i32;
            state.purge_days_setting = days;
            state.config_dirty = true;
            let msg = if days > 0 {
                format!(
                    "SUCCESS: Automatic purge enabled (purge tombstones older than {days} days, runs daily)"
                )
            } else {
                "SUCCESS: Automatic purge disabled".to_string()
            };
            resp(state, ci, &msg)
        }

        CMD_ADMIN_SET_BIND_IP => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing IP address.");
            }
            if payload.parse::<std::net::Ipv4Addr>().is_err() {
                return resp(state, ci, "ERROR: Invalid IP address format.");
            }
            state.bind_ip = trunc_string(payload, 64);
            state.config_dirty = true;
            let sync_msg = format!("bind_ip|{payload}|{}\n", now());
            mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
            resp(
                state,
                ci,
                "SUCCESS: Bind IP updated. Restart hub for changes to take effect.",
            )
        }

        CMD_ADMIN_SET_HUB_NAME => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing hub name.");
            }
            // The name is written into '|'-separated config lines and sent
            // inside handshakes and ':'/','-separated gossip: a newline or
            // separator in it forged config records ("x|203.0.113.77|0"
            // became a denylist entry).
            if !name_valid(payload) {
                return resp(
                    state,
                    ci,
                    "ERR:hub name must be 1-63 characters of A-Z a-z 0-9 . _ -",
                );
            }
            state.hub_friendly_name = trunc_string(payload, 64);
            state.config_dirty = true;
            // Peers learn names from mesh-state gossip, not from sync lines:
            // the 'hub_name|<name>|<ts>' line sent here before was ignored by
            // every receiver, so a rename reached them only at the next
            // 5-minute gossip.  Gossip now.
            state.mesh_state_dirty = true;
            let msg = format!("SUCCESS: Hub name updated to '{}'", state.hub_friendly_name);
            resp(state, ci, &msg)
        }

        CMD_ADMIN_SET_BIND_PORT => {
            if payload.is_empty() {
                return resp(state, ci, "ERROR: Missing port number.");
            }
            let port = parse_uint(payload, 65535).unwrap_or(0) as i32;
            if port <= 0 {
                return resp(state, ci, "ERROR: Port must be between 1 and 65535.");
            }
            state.port = port;
            state.config_dirty = true;
            let sync_msg = format!("port|{port}|{}\n", now());
            mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
            resp(
                state,
                ci,
                "SUCCESS: Bind port updated. Restart hub for changes to take effect.",
            )
        }

        CMD_ADMIN_LIST_ALLOWLIST => list_ip_acl(state, ci, true),
        CMD_ADMIN_LIST_DENYLIST => list_ip_acl(state, ci, false),
        CMD_ADMIN_ADD_ALLOWLIST => ip_acl_change(state, ci, 'w', true, payload),
        CMD_ADMIN_DEL_ALLOWLIST => ip_acl_change(state, ci, 'w', false, payload),
        CMD_ADMIN_ADD_DENYLIST => ip_acl_change(state, ci, 'x', true, payload),
        CMD_ADMIN_DEL_DENYLIST => ip_acl_change(state, ci, 'x', false, payload),

        CMD_ADMIN_SET_LOG_LEVEL => {
            // One raw byte: level 0 is the byte 0x00, so the frame length
            // decides, never strlen.
            if raw_len != 1 {
                return resp(state, ci, "ERR:invalid payload");
            }
            let level = i32::from(raw[0]).clamp(LOG_NONE, LOG_DEBUG);
            state.log_level = level;
            state.config_dirty = true; // log_level| survives a restart
            crate::logging::set_level(level);
            let msg = format!("OK:log_level set to {level}");
            resp(state, ci, &msg)
        }

        CMD_ADMIN_SET_LOG_SIZE => {
            // Four raw bytes, network order: 10 MB is 00 A0 00 00.
            if raw_len != 4 {
                return resp(state, ci, "ERR:invalid payload");
            }
            let size = i64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
                .clamp(HUB_LOG_SIZE_MIN, HUB_LOG_SIZE_MAX);
            state.log_max_size = size;
            state.config_dirty = true; // log_size| survives a restart
            crate::logging::set_max_size(state.log_max_size);
            let msg = format!("OK:log_size set to {}", state.log_max_size);
            resp(state, ci, &msg)
        }

        CMD_ADMIN_STATS => {
            // Read-only snapshot of the traffic counters; see
            // consts::CMD_ADMIN_STATS.
            let up = if state.hub_started > 0 {
                now() - state.hub_started
            } else {
                0
            };
            let msg = crate::stats::report(up, MAX_BUFFER - 64);
            resp(state, ci, &msg)
        }

        CMD_ADMIN_GET_OPT_FLAGS => {
            let msg = format!(
                "opt|{}",
                if state.opt_flags.is_empty() {
                    "(none)"
                } else {
                    &state.opt_flags
                }
            );
            resp(state, ci, &msg)
        }

        CMD_ADMIN_SET_OPT_FLAGS => {
            // Payload: a bare flag string ([a-zA-Z0-9]+), or empty to clear.
            let mut dedup = String::new();
            for c in payload
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(MAX_OPT_FLAGS)
            {
                if !dedup.contains(c) && dedup.len() < MAX_OPT_FLAGS {
                    dedup.push(c);
                }
            }
            state.opt_flags = dedup;
            // Past the previous stamp: a set and a clear in the same second
            // must not tie, or peers keep whichever arrived and the mesh
            // splits.
            state.opt_flags_ts = lww_next_ts(state.opt_flags_ts);
            state.config_dirty = true;

            let sync_pkt = format!("opt|{}|{}\n", state.opt_flags, state.opt_flags_ts);
            mesh::broadcast_sync_to_peers(state, &sync_pkt, -1);
            client::broadcast_full_config_to_all_bots(state);

            let msg = format!(
                "SUCCESS: opt flags now '{}'",
                if state.opt_flags.is_empty() {
                    "(none)"
                } else {
                    &state.opt_flags
                }
            );
            resp(state, ci, &msg)
        }

        CMD_ADMIN_LIST_ADMINS => list_users(state, ci, 'a'),
        CMD_ADMIN_LIST_OPERS_V2 => list_users(state, ci, 'o'),
        CMD_ADMIN_ADD_ADMIN => add_user_record(state, ci, payload, 'a'),
        CMD_ADMIN_ADD_OPER_RECORD => add_user_record(state, ci, payload, 'o'),
        CMD_ADMIN_DEL_ADMIN => del_user_record(state, ci, payload, true),
        CMD_ADMIN_DEL_OPER_RECORD => del_user_record(state, ci, payload, false),
        CMD_ADMIN_ADD_USERMASK => add_usermask(state, ci, payload),
        CMD_ADMIN_DEL_USERMASK => del_usermask(state, ci, payload),
        CMD_ADMIN_SET_USERKEY => set_userkey(state, ci, payload),
        CMD_ADMIN_MATCH => match_user(state, ci, payload),

        _ => resp(state, ci, "ERROR: Unknown command."),
    }
}
