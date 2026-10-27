//! The admin command surface, reached only from the SSH console (hub_logic.c
//! `handle_admin_command`).
//!
//! Every reply is a record list (`reply`, docs/console.md §3.1): a result line
//! with a stable code, then data records.  The console lays them out; nothing
//! here formats for a screen.  Returning false means the connection is gone (a
//! failed write already dropped it).  Mutations set `config_dirty` and let the
//! write debounce in `maintenance` flush them, rather than paying
//! PBKDF2 per command.

use crate::connlimits::{self, Group, SetResult};
use crate::consts::*;
use crate::cstr::{now, split_fields, trunc_string};
use crate::reply::Reply;
use crate::state::{
    BotConfig, BotRoster, ClientType, HubState, IpAcl, IpAclAdd, MaskRecord, ModesStatus,
    PeerConfig, UserRecord, lww_next_ts, name_valid, parse_uint,
};
use crate::{
    access, auth, client, console, crypto, mesh, modes, opflow, presence, queue, ratelimit,
    storage, upgrade,
};

fn resp(state: &mut HubState, ci: usize, msg: &str) -> bool {
    client::send_response(state, ci, msg)
}

pub(crate) fn send_reply(state: &mut HubState, ci: usize, r: &mut Reply) -> bool {
    let t = r.text().to_string();
    resp(state, ci, &t)
}

pub(crate) fn admin_err(
    state: &mut HubState,
    ci: usize,
    code: &str,
    msg: &str,
    hint: Option<&str>,
) -> bool {
    let mut r = Reply::new();
    r.err(code, Some(msg), hint);
    send_reply(state, ci, &mut r)
}

/// The admin connection again after something that may have swap-removed
/// the client list (a disconnect).
fn refind(state: &HubState, fd: i32) -> Option<usize> {
    state.client_by_fd(fd)
}

/// Field `idx` of a '|' payload, None when missing or `cap` bytes or more
/// (hub_logic.c wire_field).
pub(crate) fn wire_field(s: &str, idx: usize, cap: usize) -> Option<String> {
    let mut rest = s;
    for _ in 0..idx {
        rest = &rest[rest.find('|')? + 1..];
    }
    let end = rest
        .find('|')
        .unwrap_or_else(|| rest.find(['\r', '\n']).unwrap_or(rest.len()));
    let f = &rest[..end];
    (f.len() < cap).then(|| f.to_string())
}

/// Field `idx` and everything after it, clamped (hub_logic.c wire_tail).
pub(crate) fn wire_tail(s: &str, idx: usize, cap: usize) -> Option<String> {
    let mut rest = s;
    for _ in 0..idx {
        rest = &rest[rest.find('|')? + 1..];
    }
    let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
    Some(trunc_string(&rest[..end], cap))
}

/// What a C `sscanf("%<w>[^|]")` field accepts: 1..=w bytes (a longer one
/// makes the scan stop short, and the command reads as malformed).
fn scan_ok(f: &str, w: usize) -> bool {
    !f.is_empty() && f.len() <= w
}

/// The token a C `%<w>s` reads: leading blanks skipped, up to the next blank,
/// at most w bytes; None when there is none (the scan fails).
fn scan_word(f: &str, w: usize) -> Option<String> {
    f.split_whitespace().next().map(|t| trunc_string(t, w + 1))
}

/// Peer hubs a sync sent now reaches, and bots a config push reaches.
pub(crate) fn linked_peer_count(state: &HubState) -> i64 {
    state
        .clients
        .iter()
        .filter(|c| c.typ == ClientType::Hub && c.authenticated)
        .count() as i64
}

fn local_bot_count(state: &HubState) -> i64 {
    state
        .clients
        .iter()
        .filter(|c| c.typ == ClientType::Bot && c.authenticated)
        .count() as i64
}

fn local_bot_client(state: &HubState, uuid: &str) -> Option<usize> {
    state
        .clients
        .iter()
        .position(|c| c.typ == ClientType::Bot && c.authenticated && !c.superseded && c.id == uuid)
}

pub(crate) fn hub_display_name(state: &HubState) -> &str {
    if state.hub_friendly_name.is_empty() {
        "hub"
    } else {
        &state.hub_friendly_name
    }
}

/// The freshest roster report of a bot some other hub holds.
fn roster_best<'a>(state: &'a HubState, uuid: &str) -> Option<&'a BotRoster> {
    let mut best: Option<&BotRoster> = None;
    for e in state.roster.iter().filter(|e| e.bot_uuid == uuid) {
        if best.is_none_or(|b| e.reported_at >= b.reported_at) {
            best = Some(e);
        }
    }
    best
}

fn bot_by_uuid(state: &HubState, uuid: &str) -> Option<usize> {
    state.bots.iter().position(|b| b.uuid == uuid)
}

/// Online anywhere on the mesh: connected here, or in a peer's roster.
fn bot_online(state: &HubState, uuid: &str) -> bool {
    local_bot_client(state, uuid).is_some() || roster_best(state, uuid).is_some()
}

/// Distinct bots online on the whole network (here + every roster).
fn network_bots_online(state: &HubState) -> i64 {
    state
        .bots
        .iter()
        .filter(|b| b.is_active && bot_online(state, &b.uuid))
        .count() as i64
}

/// Every hub in the mesh tree (its H rows: this hub, its peers and the hubs
/// beyond them), as (online, total).
fn network_hubs(state: &HubState) -> (i64, i64) {
    let (mut up, mut total) = (0, 0);
    for row in presence::build_tree(state).split('\n') {
        // H|depth|name|uuid|online|...
        let f: Vec<&str> = row.splitn(6, '|').collect();
        if f[0] == "H" && f.len() >= 5 {
            total += 1;
            if f[4].starts_with('1') {
                up += 1;
            }
        }
    }
    (up, total)
}

/// bot|uuid|nick|online|ver|base|started|server|hub|hub_uuid|hub_name|ip|
///     since|fp|seen|auth|auth_ts — every field the hub has for one bot.
///     started is the bot's own start (uptime), since its link to its hub.
fn reply_bot(state: &HubState, r: &mut Reply, b: &BotConfig) {
    let c = local_bot_client(state, &b.uuid).map(|i| &state.clients[i]);
    let e = if c.is_some() {
        None
    } else {
        roster_best(state, &b.uuid)
    };
    // "seen" is synced between hubs: the last time it authenticated anywhere
    let mut seen = b.last_sync_time;
    if let Some(s) = b.entry("seen")
        && s.timestamp > seen
    {
        seen = s.timestamp;
    }
    if let Some(c) = c
        && c.last_seen > seen
    {
        seen = c.last_seen;
    }
    r.rec("bot");
    r.kv("uuid", &b.uuid);
    if let Some(n) = b.entry("n")
        && !n.value.is_empty()
    {
        r.kv("nick", &n.value);
    }
    r.kvb("online", c.is_some() || e.is_some());
    if let Some(c) = c {
        opt(r, "ver", &c.bot_version);
        opt(r, "base", &c.bot_variant);
        if c.bot_started > 0 {
            r.kvi("started", c.bot_started);
        }
        opt(r, "server", &c.bot_server);
        r.kv("hub", "local");
        opt(r, "hub_uuid", &state.hub_uuid);
        r.kv("hub_name", hub_display_name(state));
        r.kv("ip", &c.ip);
        r.kvi("since", c.connected_at);
    } else if let Some(e) = e {
        opt(r, "ver", &e.version);
        opt(r, "base", &e.variant);
        if e.connected_at > 0 {
            r.kvi("started", e.connected_at);
        }
        opt(r, "server", &e.server);
        r.kv("hub", "peer");
        r.kv("hub_uuid", &e.hub_uuid);
        r.kv("hub_name", &e.hub_name);
        if e.link_since > 0 {
            r.kvi("since", e.link_since);
        }
        opt(r, "ip", &e.ip);
    }
    if let Some(p) = b.entry("pub")
        && !p.value.is_empty()
    {
        r.kv("fp", &crypto::key_fingerprint_b64(&p.value));
    }
    r.kvi("seen", seen);
    // An active record is the authorization ("t" only stamps the record's
    // sync time, the newest authorization or sync of it).
    r.kvb("auth", b.is_active);
    if b.last_sync_time > 0 {
        r.kvi("auth_ts", b.last_sync_time);
    }
}

/// key=value only when the value is not empty.
fn opt(r: &mut Reply, k: &str, v: &str) {
    if !v.is_empty() {
        r.kv(k, v);
    }
}

/// Index of the configured peer `sel` names: its number in peer list
/// (1..n), its uuid, or its name (any case).
fn peer_find(state: &HubState, sel: &str) -> Option<usize> {
    if let Some(v) = parse_uint(sel, MAX_PEERS as u64)
        && v >= 1
        && v as usize <= state.peers.len()
    {
        return Some(v as usize - 1);
    }
    if let Some(i) = state
        .peers
        .iter()
        .position(|p| !p.uuid.is_empty() && p.uuid == sel)
    {
        return Some(i);
    }
    state
        .peers
        .iter()
        .position(|p| !p.friendly_name.is_empty() && p.friendly_name.eq_ignore_ascii_case(sel))
}

fn peer_client(state: &HubState, p: &PeerConfig) -> Option<usize> {
    if p.fd <= 0 {
        return None;
    }
    state
        .clients
        .iter()
        .position(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == p.fd)
}

fn peer_key_fp(p: &PeerConfig) -> String {
    let mut k = [0u8; COMBINED_KEY_LEN];
    k[..ED25519_KEY_LEN].copy_from_slice(&p.ed_pub);
    k[ED25519_KEY_LEN..].copy_from_slice(&p.x25519_pub);
    crypto::key_fingerprint(&k)
}

/// peer|n|uuid|name|ip|port|remote_ip|up|since|base|ver|started|bots|fp
/// [|bots_list|gossip]: since = the link's connect time while up, the time
/// it went down while down (absent: never up since this hub started).
fn reply_peer(state: &HubState, r: &mut Reply, i: usize, detail: bool) {
    let p = &state.peers[i];
    let c = peer_client(state, p).map(|ci| &state.clients[ci]);
    let mh = if p.uuid.is_empty() {
        None
    } else {
        presence::mesh_hub_find(state, &p.uuid).map(|m| &state.mesh_hubs[m])
    };
    r.rec("peer");
    r.kvi("n", i as i64 + 1);
    opt(r, "uuid", &p.uuid);
    opt(r, "name", &p.friendly_name);
    r.kv("ip", &p.ip);
    r.kvi("port", i64::from(p.port));
    opt(r, "remote_ip", &p.remote_ip);
    r.kvb("up", c.is_some());
    if let Some(c) = c {
        r.kvi("since", c.connected_at);
    } else if p.link_down_at > 0 {
        r.kvi("since", p.link_down_at);
    }
    let var = if !p.remote_variant.is_empty() {
        p.remote_variant.as_str()
    } else {
        mh.map_or("", |m| m.variant.as_str())
    };
    let ver = if !p.remote_version.is_empty() {
        p.remote_version.as_str()
    } else {
        mh.map_or("", |m| m.version.as_str())
    };
    let started = if p.remote_started != 0 {
        p.remote_started
    } else {
        mh.map_or(0, |m| m.started)
    };
    opt(r, "base", var);
    opt(r, "ver", ver);
    if c.is_some() && started > 0 {
        r.kvi("started", started);
    }
    let mut bots = 0;
    let mut list = String::new();
    let mut lo = 0usize;
    if !p.uuid.is_empty() {
        for e in state.roster.iter().filter(|e| e.hub_uuid == p.uuid) {
            bots += 1;
            let nm = if e.nick.is_empty() {
                &e.bot_uuid
            } else {
                &e.nick
            };
            // list[1024]: what snprintf keeps, and nothing after a cut
            if detail && lo + e.nick.len() + 2 < 1024 {
                let add = format!("{}{nm}", if lo > 0 { "," } else { "" });
                lo += add.len();
                list.push_str(&trunc_string(&add, 1024 - list.len()));
            }
        }
    }
    if c.is_some() {
        r.kvi("bots", bots);
    }
    if p.has_pubkey {
        r.kv("fp", &peer_key_fp(p));
    }
    if detail {
        opt(r, "bots_list", &list);
        if p.last_mesh_report > 0 {
            r.kvi("gossip", p.last_mesh_report);
        }
    }
}

fn configured_peer_uuid(state: &HubState, uuid: &str) -> bool {
    state
        .peers
        .iter()
        .any(|p| !p.uuid.is_empty() && p.uuid == uuid)
}

/// link|a|b|b_name|state: every link a hub reported (its roster gossip), and
/// this hub's own; a pair nobody reported is "unknown" by its absence.
fn reply_links_of(state: &HubState, r: &mut Reply, uuid: &str) {
    let Some(mi) = presence::mesh_hub_find(state, uuid) else {
        return;
    };
    let mh = &state.mesh_hubs[mi];
    if !mh.have_links {
        return;
    }
    for l in &mh.links {
        r.rec("link");
        r.kv("a", &mh.uuid);
        r.kv("b", &l.uuid);
        opt(r, "b_name", &l.name);
        r.kv("state", if l.online { "up" } else { "down" });
    }
}

/// A hub's name as the hub del preview shows it: its friendly name, else the
/// first 8 characters of its uuid.
fn refs_hub_name(name: &str, uuid: &str) -> String {
    if name.is_empty() {
        trunc_string(uuid, 9)
    } else {
        name.to_string()
    }
}

/// admin_peer_refs(): hub del's preview (CMD_ADMIN_PEER_REFS): who still
/// knows hub `sel` once this hub unlinks it.  ok|peer.refs|hubs|bots, the
/// target's peer record, then hubref|uuid|name|state|self for every hub whose
/// links name it (this hub first), hubunrep|uuid|name for hubs whose links
/// never reached us, botref|uuid|nick|on|on_uuid|on_name|seen|addr|others for
/// every bot whose hl| list holds its key (others: the bot's other hubs, by
/// name, or ?<addr> for one this hub has no key for) and botunrep|uuid|nick
/// for bots that sent no list.  Read only.
fn peer_refs(state: &mut HubState, ci: usize, sel: &str) -> bool {
    let Some(ti) = (if sel.is_empty() {
        None
    } else {
        peer_find(state, sel)
    }) else {
        let m = format!(
            "no hub {}: none with that uuid or name",
            trunc_string(sel, 61)
        );
        return admin_err(state, ci, "peer.not_found", &m, Some("hub list"));
    };
    let t = &state.peers[ti];
    let tuuid = t.uuid.clone();
    let tfp = if t.has_pubkey {
        crypto::hl_fp(&t.ed_pub)
    } else {
        String::new()
    };

    // The hubs other than the target this hub knows: itself, its peers, and
    // the ones only gossip names.
    let mut hubs = 1i64;
    for (i, p) in state.peers.iter().enumerate() {
        if i != ti && (p.uuid.is_empty() || p.uuid != tuuid) {
            hubs += 1;
        }
    }
    for m in &state.mesh_hubs {
        if m.uuid.is_empty()
            || m.uuid == state.hub_uuid
            || (!tuuid.is_empty() && m.uuid == tuuid)
            || configured_peer_uuid(state, &m.uuid)
        {
            continue;
        }
        hubs += 1;
    }
    let bots = state.bots.iter().filter(|b| b.is_active).count() as i64;

    let mut r = Reply::new();
    r.ok("peer.refs");
    r.kvi("hubs", hubs);
    r.kvi("bots", bots);
    reply_peer(state, &mut r, ti, false);

    r.rec("hubref");
    opt(&mut r, "uuid", &state.hub_uuid);
    r.kv("name", hub_display_name(state));
    r.kv(
        "state",
        if peer_client(state, &state.peers[ti]).is_some() {
            "up"
        } else {
            "down"
        },
    );
    r.kvb("self", true);
    // every other hub whose gossiped links name the target
    let mut cand: Vec<(String, String)> = Vec::new();
    for (i, p) in state.peers.iter().enumerate() {
        if i != ti {
            cand.push((p.uuid.clone(), p.friendly_name.clone()));
        }
    }
    for m in &state.mesh_hubs {
        if !configured_peer_uuid(state, &m.uuid) {
            cand.push((m.uuid.clone(), m.name.clone()));
        }
    }
    for (uuid, name) in cand {
        if uuid.is_empty() || uuid == state.hub_uuid || (!tuuid.is_empty() && uuid == tuuid) {
            continue;
        }
        let m = presence::mesh_hub_find(state, &uuid).map(|mi| &state.mesh_hubs[mi]);
        let name = match m {
            Some(m) if !m.name.is_empty() => m.name.clone(),
            _ => name,
        };
        let nm = refs_hub_name(&name, &uuid);
        let Some(m) = m.filter(|m| m.have_links) else {
            r.rec("hubunrep");
            r.kv("uuid", &uuid);
            r.kv("name", &nm);
            continue;
        };
        if tuuid.is_empty() {
            continue;
        }
        if let Some(l) = m.links.iter().find(|l| l.uuid == tuuid) {
            r.rec("hubref");
            r.kv("uuid", &uuid);
            r.kv("name", &nm);
            r.kv("state", if l.online { "up" } else { "down" });
        }
    }

    // Hubs a bot's fingerprints can name: this one and its keyed peers.
    let self_fp = crypto::hl_fp(&state.hub_ed25519_pub);
    let peer_fp: Vec<String> = state
        .peers
        .iter()
        .map(|p| {
            if p.has_pubkey {
                crypto::hl_fp(&p.ed_pub)
            } else {
                String::new()
            }
        })
        .collect();

    for b in state.bots.iter().filter(|b| b.is_active) {
        let nick = presence::bot_nick_from_config(state, &b.uuid);
        let Some(hl) = b.entry("hl") else {
            r.rec("botunrep");
            r.kv("uuid", &b.uuid);
            opt(&mut r, "nick", &nick);
            continue;
        };
        if tfp.is_empty() || !storage::hublist_valid(&hl.value) || hl.value.is_empty() {
            continue;
        }
        // the entry for the target, and the bot's other hubs
        let mut addr: Option<String> = None;
        let mut others: Vec<String> = Vec::new();
        for ent in hl.value.split(',') {
            let (ea, ef) = ent.split_once('/').unwrap_or((ent, ""));
            if ef == tfp {
                if addr.is_none() {
                    addr = Some(ea.to_string());
                }
            } else if ef == self_fp {
                others.push(hub_display_name(state).to_string());
            } else if let Some(pk) = peer_fp.iter().position(|f| !f.is_empty() && f == ef) {
                let p = &state.peers[pk];
                let m = if p.uuid.is_empty() {
                    None
                } else {
                    presence::mesh_hub_find(state, &p.uuid).map(|mi| &state.mesh_hubs[mi])
                };
                let name = if !p.friendly_name.is_empty() {
                    p.friendly_name.as_str()
                } else {
                    m.map_or("", |m| m.name.as_str())
                };
                let id = if p.uuid.is_empty() { &p.ip } else { &p.uuid };
                others.push(refs_hub_name(name, id));
            } else {
                others.push(format!("?{ea}"));
            }
        }
        let Some(addr) = addr else { continue };
        let c = local_bot_client(state, &b.uuid).map(|i| &state.clients[i]);
        let e = if c.is_some() {
            None
        } else {
            roster_best(state, &b.uuid)
        };
        let mut seen = b.last_sync_time;
        if let Some(s) = b.entry("seen")
            && s.timestamp > seen
        {
            seen = s.timestamp;
        }
        if let Some(c) = c
            && c.last_seen > seen
        {
            seen = c.last_seen;
        }
        r.rec("botref");
        r.kv("uuid", &b.uuid);
        opt(&mut r, "nick", &nick);
        if c.is_some() {
            r.kv("on", "local");
            opt(&mut r, "on_uuid", &state.hub_uuid);
            r.kv("on_name", hub_display_name(state));
        } else if let Some(e) = e {
            r.kv("on", "peer");
            r.kv("on_uuid", &e.hub_uuid);
            r.kv("on_name", &refs_hub_name(&e.hub_name, &e.hub_uuid));
        }
        if seen > 0 {
            r.kvi("seen", seen);
        }
        opt(&mut r, "addr", &addr);
        opt(&mut r, "others", &others.join(","));
    }
    send_reply(state, ci, &mut r)
}

fn list_peers(state: &mut HubState, ci: usize, sel: &str) -> bool {
    let mut r = Reply::new();
    if !sel.is_empty() {
        let Some(i) = peer_find(state, sel) else {
            let m = format!(
                "no hub #{}, and none with that uuid or name",
                trunc_string(sel, 41)
            );
            return admin_err(state, ci, "peer.not_found", &m, Some("hub list"));
        };
        r.ok("peer.show");
        reply_peer(state, &mut r, i, true);
        if !state.peers[i].uuid.is_empty() {
            let u = state.peers[i].uuid.clone();
            reply_links_of(state, &mut r, &u);
        }
        return send_reply(state, ci, &mut r);
    }
    let up = state
        .peers
        .iter()
        .filter(|p| peer_client(state, p).is_some())
        .count() as i64;
    r.ok("peer.list");
    r.kvi("configured", state.peers.len() as i64);
    r.kvi("up", up);
    r.rec("self");
    opt(&mut r, "uuid", &state.hub_uuid);
    r.kv("name", hub_display_name(state));
    r.kv("base", HUB_UPDATE_VARIANT);
    r.kv("ver", HUB_VERSION);
    if state.hub_started > 0 {
        r.kvi("started", state.hub_started);
    }
    r.kvi("bots", local_bot_count(state));
    r.kv(
        "bind_ip",
        if state.bind_ip.is_empty() {
            "0.0.0.0"
        } else {
            &state.bind_ip
        },
    );
    r.kvi("port", i64::from(state.port));
    for i in 0..state.peers.len() {
        reply_peer(state, &mut r, i, false);
    }
    // hubs only gossip tells about
    for m in &state.mesh_hubs {
        if m.uuid.is_empty() || m.uuid == state.hub_uuid || configured_peer_uuid(state, &m.uuid) {
            continue;
        }
        r.rec("hub");
        r.kv("uuid", &m.uuid);
        opt(&mut r, "name", &m.name);
        opt(&mut r, "ver", &m.version);
        opt(&mut r, "base", &m.variant);
        r.kv("known", "gossip");
    }
    // links: ours first, then what every hub reports
    for p in &state.peers {
        if p.uuid.is_empty() {
            continue;
        }
        r.rec("link");
        r.kv("a", &state.hub_uuid);
        r.kv("b", &p.uuid);
        opt(&mut r, "b_name", &p.friendly_name);
        r.kv(
            "state",
            if peer_client(state, p).is_some() {
                "up"
            } else {
                "down"
            },
        );
    }
    for m in &state.mesh_hubs {
        if !m.uuid.is_empty() && m.uuid != state.hub_uuid {
            reply_links_of(state, &mut r, &m.uuid);
        }
    }
    // issues: a configured peer that is down; a hub a linked peer links to
    // that this hub has no entry for
    for (i, p) in state.peers.iter().enumerate() {
        if peer_client(state, p).is_some() {
            continue;
        }
        r.rec("issue");
        r.kv("kind", "peer_down");
        r.kvi("n", i as i64 + 1);
        opt(&mut r, "uuid", &p.uuid);
        opt(&mut r, "name", &p.friendly_name);
        r.kv("ip", &p.ip);
        r.kvi("port", i64::from(p.port));
        if p.link_down_at > 0 {
            r.kvi("since", p.link_down_at);
        }
    }
    for p in &state.peers {
        if p.uuid.is_empty() || peer_client(state, p).is_none() {
            continue;
        }
        let Some(mi) = presence::mesh_hub_find(state, &p.uuid) else {
            continue;
        };
        let mh = &state.mesh_hubs[mi];
        if !mh.have_links {
            continue;
        }
        for l in &mh.links {
            if l.uuid == state.hub_uuid || configured_peer_uuid(state, &l.uuid) {
                continue;
            }
            r.rec("issue");
            r.kv("kind", "unknown_hub");
            r.kv("via", &p.uuid);
            opt(&mut r, "via_name", &p.friendly_name);
            r.kv("uuid", &l.uuid);
            opt(&mut r, "name", &l.name);
        }
    }
    send_reply(state, ci, &mut r)
}

fn chan_modes_letters(modes: i32) -> String {
    let mut s = String::new();
    if modes & 128 != 0 {
        s.push('i');
    }
    if modes & 64 != 0 {
        s.push('k');
    }
    s
}

/// A managed channel's stored entry (active or a tombstone).
fn chan_entry(state: &HubState, chan: &str) -> Option<usize> {
    state.global_entries.iter().position(|e| {
        e.key == "c"
            && mesh::parse_global_channel_value(&e.value)
                .is_some_and(|(name, _, _, _)| storage::ascii_ieq(&trunc_string(&name, 128), chan))
    })
}

/// chan|name|key|modes|ts — the generic channel record; a later setting
/// adds a set.<name>= key (docs/console.md §3.1).
fn reply_chan(state: &HubState, r: &mut Reply, value: &str, ts: i64) -> bool {
    let Some((name, key, mut modes, op)) = mesh::parse_global_channel_value(value) else {
        return false;
    };
    let name = trunc_string(&name, 128);
    let mut key = trunc_string(&key, 64);
    if name.is_empty() || op == "del" {
        return false;
    }
    // the key the bots join with and the +k/+i they saw (K|, when newer)
    if let Some(l) = storage::learned_find(state, &name) {
        modes = l.modes;
        if l.ts > ts {
            key = trunc_string(&l.key, 64);
        }
    }
    r.rec("chan");
    r.kv("name", &name);
    opt(r, "key", &key);
    opt(r, "modes", &chan_modes_letters(modes));
    r.kvi("ts", ts);
    true
}

/// A channel name the bots can JOIN: # or & first, no blank, comma, BEL or
/// control character, at most MAX_CHAN - 1 bytes.
fn chan_name_valid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b.len() >= MAX_CHAN || (b[0] != b'#' && b[0] != b'&') {
        return false;
    }
    b.iter().all(|&c| c > 0x20 && c != b',' && c != 0x7f)
}

/// Write a channel's key (add, re-add or channel set key): the same stored
/// line and sync both ways.
fn chan_store(state: &mut HubState, chan: &str, key: &str) {
    // Past the stored stamp: a remove in this same second would tie, and the
    // newest command must be the one that sticks.
    let t = lww_next_ts(storage::global_ts(state, "c", chan));
    // Carry forward any modes a bot previously reported for this channel: the
    // storage layer replaces the whole value once the timestamp wins, so a
    // re-add to change the key would otherwise wipe the recorded +i/+k.
    let modes = mesh::global_channel_modes(state, chan);
    let extra = format!("{key}|{modes}");
    storage::update_global_entry(state, "c", chan, &extra, "add", t);
    state.config_dirty = true;
    let sync_msg = format!("c|{chan}|{key}|{modes}|add|{t}\n");
    client::broadcast_config_to_bots(state, &sync_msg);
    mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
}

/// The active key of a channel ("" = none); None when it is not managed.
fn chan_active_key(state: &HubState, chan: &str) -> Option<String> {
    let i = chan_entry(state, chan)?;
    let (_, key, _, op) = mesh::parse_global_channel_value(&state.global_entries[i].value)?;
    if op == "del" {
        return None;
    }
    Some(trunc_string(&key, 64))
}

/// The key the bots join with: the newer of the admin's (c|) and the one they
/// learned on IRC (K|); a tie keeps the admin's.  None when not managed.
fn chan_effective_key(state: &HubState, chan: &str) -> Option<String> {
    let key = chan_active_key(state, chan)?;
    Some(match storage::learned_find(state, chan) {
        Some(l) if l.ts > storage::global_ts(state, "c", chan) => l.key.clone(),
        _ => key,
    })
}

fn user_by_name(state: &HubState, name: &str) -> Option<usize> {
    state
        .user_records
        .iter()
        .position(|u| u.is_active && u.name.eq_ignore_ascii_case(name))
}

fn user_mask_count(state: &HubState, uuid: &str) -> i64 {
    state
        .mask_records
        .iter()
        .filter(|m| m.is_active && m.uuid == uuid)
        .count() as i64
}

/// Open consoles of an admin: they close when the record or its key goes.
fn admin_console_sessions(state: &HubState, name: &str) -> i64 {
    state
        .clients
        .iter()
        .filter(|c| {
            c.internal
                && c.typ == ClientType::Admin
                && c.id
                    .strip_prefix("ADMIN:")
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .count() as i64
}

fn role_name(typ: char) -> &'static str {
    if typ == 'a' { "admin" } else { "oper" }
}

/// user|name|role|fp|seen|masks|sessions, then mask|user|mask|used per mask.
fn reply_user(state: &HubState, r: &mut Reply, u: &UserRecord) {
    r.rec("user");
    r.kv("name", &u.name);
    r.kv("role", role_name(u.typ));
    if u.has_pubkey {
        r.kv("fp", &crypto::key_fingerprint_b64(&u.pubkey_b64));
    }
    r.kvi("seen", u.last_seen);
    r.kvi("masks", user_mask_count(state, &u.uuid));
    if u.typ == 'a' {
        r.kvi("sessions", admin_console_sessions(state, &u.name));
    }
    // user_flags plan U9: an admin's flags, an oper's channels ("*" = all)
    if u.typ == 'a' {
        r.kv("flags", access::user_flags(state, &u.uuid));
    } else {
        r.kv("chans", &access::user_chans(state, &u.uuid));
    }
    for m in state
        .mask_records
        .iter()
        .filter(|m| m.is_active && m.uuid == u.uuid)
    {
        r.rec("mask");
        r.kv("user", &u.name);
        r.kv("mask", &m.mask);
        r.kvi("used", m.last_used);
    }
}

/// typ None = every role; name None = every user.
fn list_users(
    state: &mut HubState,
    ci: usize,
    code: &str,
    typ: Option<char>,
    name: Option<&str>,
) -> bool {
    let hit = |u: &UserRecord| {
        u.is_active
            && typ.is_none_or(|t| u.typ == t)
            && name.is_none_or(|n| u.name.eq_ignore_ascii_case(n))
    };
    let (mut admins, mut opers, mut masks) = (0, 0, 0);
    for u in state.user_records.iter().filter(|u| hit(u)) {
        if u.typ == 'a' {
            admins += 1;
        } else {
            opers += 1;
        }
        masks += user_mask_count(state, &u.uuid);
    }
    if let Some(n) = name
        && admins + opers == 0
    {
        let m = format!("no user called \"{}\"", trunc_string(n, 65));
        return admin_err(state, ci, "user.not_found", &m, Some("user list"));
    }
    let mut r = Reply::new();
    r.ok(code);
    if let Some(t) = typ {
        r.kv("role", role_name(t));
    }
    r.kvi("admins", admins);
    r.kvi("opers", opers);
    r.kvi("masks", masks);
    // admins first, as the console sorts them too
    for pass in ['a', 'o'] {
        for u in state
            .user_records
            .iter()
            .filter(|u| u.typ == pass && hit(u))
        {
            reply_user(state, &mut r, u);
        }
    }
    send_reply(state, ci, &mut r)
}

// ---------------------------------------------------------------------------
// IP access lists
// ---------------------------------------------------------------------------

fn acl_size(e: &IpAcl) -> u64 {
    u64::from(!e.mask) + 1
}

/// CMD_ADMIN_ADD/DEL_ALLOWLIST/DENYLIST (list 'w' or 'x').  The lists are
/// local to this hub: nothing is sent to peers or bots.  A change after which
/// the admin's own address could not connect is refused and rolled back; the
/// inbound connections a change refuses are closed by `maintenance`.
fn ip_acl_change(state: &mut HubState, ci: usize, list: char, add: bool, payload: &str) -> bool {
    let name = if list == 'w' { "allow" } else { "deny" };
    if payload.is_empty() {
        return admin_err(
            state,
            ci,
            "acl.usage",
            "say which address",
            Some("acl add|del allow|deny <ip[/n]> [console]"),
        );
    }
    // "<pattern>" or "<pattern>|console" (D27: the entry applies only once the
    // first bytes say SSH).  Anything else after the pattern is refused.
    let (pat, console_scope) = match payload.find('|') {
        Some(bar) => {
            if &payload[bar + 1..] != "console" || bar >= IP_ACL_PATTERN_MAX + 2 {
                return admin_err(
                    state,
                    ci,
                    "acl.bad_scope",
                    "the only scope word is console",
                    Some("acl add allow <ip[/n]> console"),
                );
            }
            (&payload[..bar], true)
        }
        None => (payload, false),
    };
    let Some(mut e) = ratelimit::ip_acl_parse(pat) else {
        let msg = format!("{} is not an IPv4 address or CIDR", trunc_string(pat, 41));
        return admin_err(
            state,
            ci,
            "acl.bad_pattern",
            &msg,
            Some("1.2.3.4 or 1.2.3.0/24"),
        );
    };
    e.console = console_scope;

    let saved_allow = state.ip_allow.clone();
    let saved_deny = state.ip_deny.clone();

    if add {
        e.added = now();
        match ratelimit::ip_acl_add(state, list, &e) {
            IpAclAdd::Added => {}
            IpAclAdd::Duplicate => {
                let msg = format!(
                    "{} is already on the {name} list{}",
                    e.pattern(),
                    if console_scope {
                        " (console scope)"
                    } else {
                        ""
                    }
                );
                return admin_err(state, ci, "acl.exists", &msg, Some("acl list"));
            }
            _ => {
                let msg = format!("the {name} list is full ({MAX_IP_ACL_ENTRIES} entries)");
                return admin_err(state, ci, "acl.full", &msg, Some("acl del to make room"));
            }
        }
    } else if !ratelimit::ip_acl_remove(state, list, &e) {
        let msg = format!(
            "{} is not on the {name} list{}",
            e.pattern(),
            if console_scope {
                " with the console scope"
            } else {
                ""
            }
        );
        return admin_err(state, ci, "acl.not_found", &msg, Some("acl list"));
    }

    let admin_ip = state.clients[ci].ip.clone();
    // The admin is on an SSH console: both scopes must let this address in.
    if !ratelimit::ip_acl_permits(state, &admin_ip)
        || !ratelimit::ip_acl_permits_console(state, &admin_ip)
    {
        state.ip_allow = saved_allow;
        state.ip_deny = saved_deny;
        let msg = format!("refused: this would lock out your own address {admin_ip}");
        return admin_err(
            state,
            ci,
            "acl.self_lockout",
            &msg,
            (list == 'w').then_some("acl add allow <your address> first"),
        );
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
        "[ACCESS_CONTROL] {} {} {name}list by {}\n",
        e.pattern(),
        if add { "added to" } else { "removed from" },
        state.who_client(ci)
    );
    let in_scope = ratelimit::ip_acl_scope_count(
        if list == 'w' {
            &state.ip_allow
        } else {
            &state.ip_deny
        },
        console_scope,
    );
    let mut r = Reply::new();
    r.ok(if add { "acl.added" } else { "acl.removed" });
    r.kv("list", name);
    r.kv("pattern", e.pattern());
    r.kvu("size", acl_size(&e));
    if console_scope {
        r.kv("scope", "console");
    }
    if list == 'w' && add && in_scope == 1 {
        r.kvb("first", true);
    }
    if list == 'w' && !add && in_scope == 0 {
        r.kvb("empty", true);
    }
    r.kvi("closing", closing as i64);
    send_reply(state, ci, &mut r)
}

fn list_acl(state: &mut HubState, ci: usize) -> bool {
    let ip = state.clients[ci].ip.clone();
    let mut r = Reply::new();
    r.ok("acl.list");
    r.kvi("allow", state.ip_allow.len() as i64);
    r.kvi("deny", state.ip_deny.len() as i64);
    r.kv("self_ip", &ip);
    r.kv(
        "self",
        if state.ip_allow.is_empty() && state.ip_deny.is_empty() {
            "open"
        } else if ratelimit::ip_acl_permits(state, &ip)
            && ratelimit::ip_acl_permits_console(state, &ip)
        {
            "allowed"
        } else {
            "denied"
        },
    );
    for (lname, l) in [("allow", &state.ip_allow), ("deny", &state.ip_deny)] {
        for (i, e) in l.iter().enumerate() {
            r.rec("acl");
            r.kv("list", lname);
            r.kvi("n", i as i64 + 1);
            r.kv("pattern", e.pattern());
            r.kvu("size", acl_size(e));
            if e.console {
                r.kv("scope", "console");
            }
            if e.added > 0 {
                r.kvi("ts", e.added);
            }
        }
    }
    send_reply(state, ci, &mut r)
}

// ---------------------------------------------------------------------------
// This hub
// ---------------------------------------------------------------------------

fn listen_port(state: &HubState) -> i32 {
    if state.listen_port != 0 {
        state.listen_port
    } else {
        state.port
    }
}

/// ok|hub.show: everything about this hub in one record.
fn hub_show(state: &mut HubState, ci: usize) -> bool {
    if !state.hub_keys_loaded {
        return admin_err(state, ci, "hub.no_key", "this hub has no key loaded", None);
    }
    let pub64 = state.hub_pub_combined();
    let pub_b64 = crypto::b64_encode(&pub64);
    let fp = crypto::key_fingerprint(&pub64);
    let ssh_fp = crate::console::ssh_fingerprint(&state.hub_ed25519_pub);
    let peers_up = state
        .peers
        .iter()
        .filter(|p| peer_client(state, p).is_some())
        .count() as i64;
    let bots = state.bots.iter().filter(|b| b.is_active).count() as i64;
    let (hubs_up, hubs) = network_hubs(state);
    let mut r = Reply::new();
    r.ok("hub.show");
    r.kv("name", hub_display_name(state));
    opt(&mut r, "uuid", &state.hub_uuid);
    r.kv("ver", HUB_VERSION);
    r.kv("base", HUB_UPDATE_VARIANT);
    if state.hub_started > 0 {
        r.kvi("started", state.hub_started);
    }
    let bind = if state.bind_ip.is_empty() {
        "0.0.0.0"
    } else {
        &state.bind_ip
    };
    r.kv(
        "bind_ip",
        if state.listen_ip.is_empty() {
            bind
        } else {
            &state.listen_ip
        },
    );
    r.kvi("port", i64::from(listen_port(state)));
    if !state.listen_ip.is_empty() && state.listen_ip != bind {
        r.kv("pending_bind_ip", bind);
    }
    if state.listen_port != 0 && state.listen_port != state.port {
        r.kvi("pending_port", i64::from(state.port));
    }
    r.kv("key", &pub_b64);
    r.kv("fp", &fp);
    r.kv("ssh_fp", &ssh_fp);
    r.kvi("peers_up", peers_up);
    r.kvi("peers", state.peers.len() as i64);
    if hubs > 0 {
        r.kvi("hubs_up", hubs_up);
        r.kvi("hubs", hubs);
    }
    r.kvi("bots_here", local_bot_count(state));
    r.kvi("bots_online", network_bots_online(state));
    r.kvi("bots", bots);
    r.kvi("autopurge", i64::from(state.purge_days_setting));
    r.kvi("log_file", i64::from(state.log_level));
    r.kvi("log_console", i64::from(state.console_log_level));
    r.kvi(
        "log_size",
        if state.log_max_size > 0 {
            state.log_max_size
        } else {
            HUB_LOG_FILE_SIZE
        },
    );
    send_reply(state, ci, &mut r)
}

/// ok|hub.set|setting|old|value[|restart][|peers]
fn hub_set_reply(
    state: &mut HubState,
    ci: usize,
    setting: &str,
    old: Option<&str>,
    value: &str,
    restart: bool,
    peers: i64,
) -> bool {
    let mut r = Reply::new();
    r.ok("hub.set");
    r.kv("setting", setting);
    r.kv_opt("old", old);
    r.kv("value", value);
    r.kvb("restart", restart);
    if peers >= 0 {
        r.kvi("peers", peers);
    }
    if restart {
        r.kv(
            "listen_ip",
            if state.listen_ip.is_empty() {
                "0.0.0.0"
            } else {
                &state.listen_ip
            },
        );
        r.kv("listen_port", &listen_port(state).to_string());
    }
    send_reply(state, ci, &mut r)
}

/// Local-only hub rekey: generate a new Curve25519 keypair, save it encrypted
/// in the config, and dump the new public key for re-distribution.  With
/// independent per-hub keys the new pubkey is NOT pushed to peers; each peer
/// hub must re-register it with 'peer set <uuid> key', and bots must re-learn
/// it (+hub).
fn regen_keys(state: &mut HubState, ci: usize) -> bool {
    let (old_fp, old_ssh) = if state.hub_keys_loaded {
        (
            crypto::key_fingerprint(&state.hub_pub_combined()),
            crate::console::ssh_fingerprint(&state.hub_ed25519_pub),
        )
    } else {
        (String::new(), String::new())
    };
    let Some((priv64, pub64)) = crypto::generate_combined_keypair() else {
        crate::hlog_error!(
            "[AUDIT] Hub keypair regeneration by {} failed; the old key stays\n",
            state.who_client(ci)
        );
        return admin_err(
            state,
            ci,
            "hub.keygen_failed",
            "key generation failed; the old key stays",
            None,
        );
    };
    state.set_hub_priv(&priv64);
    state.set_hub_pub(&pub64);
    let pub_b64 = crypto::b64_encode(&pub64);
    state.hub_keys_loaded = true;
    state.config_dirty = true;
    let fp = crypto::key_fingerprint(&pub64);
    let ssh_fp = crate::console::ssh_fingerprint(&state.hub_ed25519_pub);
    crate::hlog_warning!(
        "[AUDIT] Hub keypair regenerated by {}: new key {fp}; peers and bots are disconnected and must re-learn it\n",
        state.who_client(ci)
    );
    crate::console::hostkey_changed(state); // SSH host key follows, now

    // Disconnect peers and bots so they must reauthenticate (and rediscover
    // that this hub's pubkey changed).
    let admin_fd = state.clients[ci].fd;
    let (mut dropped_peers, mut dropped_bots) = (0, 0);
    let mut i = 0;
    while i < state.clients.len() {
        match state.clients[i].typ {
            ClientType::Hub => dropped_peers += 1,
            ClientType::Bot => dropped_bots += 1,
            ClientType::Admin => {
                i += 1;
                continue;
            }
        }
        auth::disconnect_client(state, i);
    }
    let Some(ci) = refind(state, admin_fd) else {
        return false;
    };

    let fname = chrono::Local::now()
        .format("%Y%m%d%H%M_pub.b64")
        .to_string();
    let written = std::fs::write(&fname, &pub_b64).is_ok();
    let mut r = Reply::new();
    r.ok("hub.rekeyed");
    r.kv("name", hub_display_name(state));
    opt(&mut r, "uuid", &state.hub_uuid);
    r.kvi("port", i64::from(listen_port(state)));
    r.kv("key", &pub_b64);
    opt(&mut r, "old_fp", &old_fp);
    r.kv("fp", &fp);
    opt(&mut r, "old_ssh_fp", &old_ssh);
    r.kv("ssh_fp", &ssh_fp);
    if written {
        r.kv("file", &fname);
    }
    r.kvi("peers", dropped_peers);
    r.kvi("bots", dropped_bots);
    send_reply(state, ci, &mut r)
}

fn set_pubkey(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        return admin_err(
            state,
            ci,
            "hub.usage",
            "say which key",
            Some("hub set pubkey <key>"),
        );
    }
    let want = if payload.len() == COMBINED_KEY_B64 {
        crypto::pubkey_b64_decode(payload)
    } else {
        None
    };
    let Some(want) = want else {
        return admin_err(
            state,
            ci,
            "hub.bad_key",
            "the key must be 88 base64 characters of a 64-byte public key",
            None,
        );
    };
    // The public key is not a setting of its own: it is fixed by the private
    // key.  Storing any other key made every signature this hub produces
    // (admin logins, bot and peer handshakes) fail against what it announces
    // — an admin lockout.  Accept only the key the private key derives; a new
    // identity goes through hub rekey.
    if !state.hub_keys_loaded {
        return admin_err(
            state,
            ci,
            "hub.no_key",
            "no private key loaded; cannot verify the public key",
            None,
        );
    }
    let derived = crypto::combined_pub_from_priv(&state.hub_priv_combined());
    if !crypto::ct_eq(&derived, &want) {
        return admin_err(
            state,
            ci,
            "hub.key_mismatch",
            "that key does not belong to this hub's private key",
            Some("to change the hub identity use hub rekey"),
        );
    }
    state.set_hub_pub(&derived);
    state.config_dirty = true;
    let fp = crypto::key_fingerprint(&derived);
    hub_set_reply(state, ci, "pubkey", None, &fp, false, -1)
}

// ---------------------------------------------------------------------------
// Bots
// ---------------------------------------------------------------------------

fn list_full(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // "" = every bot; a uuid or a nick = that one bot (bot show).
    let mut r = Reply::new();
    if payload.is_empty() {
        let total = state.bots.iter().filter(|b| b.is_active).count() as i64;
        let online = state
            .bots
            .iter()
            .filter(|b| b.is_active && bot_online(state, &b.uuid))
            .count() as i64;
        r.ok("bot.list");
        r.kvi("total", total);
        r.kvi("online", online);
        for b in state.bots.iter().filter(|b| b.is_active) {
            reply_bot(state, &mut r, b);
        }
        return send_reply(state, ci, &mut r);
    }
    let by_nick = |b: &BotConfig| {
        b.is_active
            && b.entry("n")
                .is_some_and(|n| n.value.eq_ignore_ascii_case(payload))
    };
    let mut hit = bot_by_uuid(state, payload).filter(|&i| state.bots[i].is_active);
    let mut matches = usize::from(hit.is_some());
    if hit.is_none() {
        for (i, b) in state.bots.iter().enumerate() {
            if by_nick(b) {
                if hit.is_none() {
                    hit = Some(i);
                }
                matches += 1;
            }
        }
    }
    let Some(hit) = hit else {
        let m = format!(
            "no registered bot is called or has the uuid \"{}\"",
            trunc_string(payload, 65)
        );
        return admin_err(state, ci, "bot.not_found", &m, Some("bot list"));
    };
    if matches > 1 {
        let m = format!(
            "{matches} bots are called \"{}\"",
            trunc_string(payload, 65)
        );
        r.err("bot.ambiguous", Some(&m), Some("bot show <uuid>"));
        for b in state.bots.iter().filter(|b| by_nick(b)) {
            r.rec("bot");
            r.kv("uuid", &b.uuid);
            r.kv("nick", b.entry("n").map_or("", |n| n.value.as_str()));
            r.kvb("online", bot_online(state, &b.uuid));
        }
        return send_reply(state, ci, &mut r);
    }
    r.ok("bot.show");
    reply_bot(state, &mut r, &state.bots[hit]);
    // the last upgrade run this hub drove, when it moved this bot
    let u = &state.upgrade;
    if !u.id.is_empty()
        && let Some(n) = u.nodes.iter().find(|n| {
            n.kind == crate::state::UpgradeNodeKind::Bot
                && n.uuid == state.bots[hit].uuid
                && !n.not_selected
        })
    {
        r.rec("upg");
        r.kv("id", &u.id);
        r.kv("state", n.state.name());
        opt(&mut r, "from", &n.cur_version);
        r.kv("to", &u.target_ver);
        r.kvi("started", u.started);
    }
    send_reply(state, ci, &mut r)
}

fn create_bot(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // v3: bot-provided identity.  Payload: "NICK|UUID|PUBKEY_B64".  The hub no
    // longer generates the bot keypair — the bot did, locally during
    // 'ircbot -setup'.  Only the public key reaches the hub.
    // sscanf("%63[^|]|%63[^|]|%255s")
    let f = split_fields(payload, 3);
    let key = f.get(2).and_then(|k| scan_word(k, 255));
    if f.len() < 3 || !scan_ok(f[0], 63) || !scan_ok(f[1], 63) || key.is_none() {
        return admin_err(
            state,
            ci,
            "bot.usage",
            "bot add needs a nick, a uuid and a key",
            Some("bot add <nick> <uuid> <key>"),
        );
    }
    let nick = f[0].to_string();
    let uuid_in = f[1].to_string();
    let pubkey_in = key.unwrap_or_default();
    if !crate::cstr::is_uuid(&uuid_in) {
        return admin_err(
            state,
            ci,
            "bot.bad_uuid",
            "that is not a valid uuid",
            Some("8-4-4-4-12 hex digits"),
        );
    }
    if pubkey_in.len() != COMBINED_KEY_B64 {
        let m = format!(
            "the key must be {COMBINED_KEY_B64} base64 characters (got {})",
            pubkey_in.len()
        );
        return admin_err(
            state,
            ci,
            "bot.bad_key",
            &m,
            Some("the public key the bot's -setup printed"),
        );
    }
    if crypto::b64_decode(&pubkey_in).map_or(0, |d| d.len()) != COMBINED_KEY_LEN {
        return admin_err(
            state,
            ci,
            "bot.bad_key",
            "the key is not a valid 64-byte public key",
            Some("the public key the bot's -setup printed"),
        );
    }
    if crate::revoke::is_revoked(state, &uuid_in) {
        return admin_err(
            state,
            ci,
            "bot.revoked",
            "that uuid was deleted; run -setup on the bot's host for a new one",
            Some("bot revoked"),
        );
    }
    if let Some(i) = bot_by_uuid(state, &uuid_in) {
        if !state.bots[i].is_active {
            return admin_err(
                state,
                ci,
                "bot.exists",
                "that uuid belongs to a deleted bot",
                Some("hub purge now removes its tombstone"),
            );
        }
        let n = state.bots[i]
            .entry("n")
            .filter(|n| !n.value.is_empty())
            .map_or("no nick".to_string(), |n| trunc_string(&n.value, 64));
        let m = format!("uuid already registered ({n})");
        return admin_err(state, ci, "bot.exists", &m, Some("bot list"));
    }
    auth::add_bot_memory(state, &uuid_in, &nick, &pubkey_in);
    state.config_dirty = true;
    let mut r = Reply::new();
    r.ok("bot.added");
    r.kv("uuid", &uuid_in);
    r.kv("nick", &nick);
    r.kv("fp", &crypto::key_fingerprint_b64(&pubkey_in));
    send_reply(state, ci, &mut r)
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

fn add_peer(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // Parse IP:PORT:UUID:NAME:PUBKEY_B64.  UUID and NAME may be empty;
    // PUBKEY_B64 is required — the peer is authenticated by its HUBv3
    // signature (there is no shared secret).
    let f: Vec<&str> = payload.splitn(5, ':').collect();
    let port_ok = f.get(1).is_some_and(|p| {
        let p = p.trim_start();
        let p = p.strip_prefix(['+', '-']).unwrap_or(p);
        p.as_bytes().first().is_some_and(u8::is_ascii_digit)
    });
    // sscanf("%255[^:]:%d:…") reads no port past a 255-byte address
    if f.len() < 2 || !scan_ok(f[0], 255) || !port_ok {
        return admin_err(
            state,
            ci,
            "peer.usage",
            "hub add needs an address and a port",
            Some("hub add <ip> <port> <uuid> <name|-> <key>"),
        );
    }
    let ip = trunc_string(f[0], 256);
    let port = crate::cstr::atoi(f[1]);
    let uuid = f.get(2).map_or(String::new(), |s| trunc_string(s, 64));
    let name = f.get(3).map_or(String::new(), |s| trunc_string(s, 64));
    let pubkey_b64 = f.get(4).map_or(String::new(), |s| {
        trunc_string(s.split_whitespace().next().unwrap_or(""), 128)
    });
    if !(1..=65535).contains(&port) {
        return admin_err(state, ci, "peer.bad_port", "port must be 1-65535", None);
    }
    // A duplicate is named as such even on a full table: "max peers" would
    // send the admin looking for a slot the add never needed.
    if !uuid.is_empty()
        && let Some(i) = state
            .peers
            .iter()
            .position(|p| !p.uuid.is_empty() && p.uuid == uuid)
    {
        let p = &state.peers[i];
        let m = format!(
            "a hub with that uuid is already linked (#{} {})",
            i + 1,
            trunc_string(
                if p.friendly_name.is_empty() {
                    &p.ip
                } else {
                    &p.friendly_name
                },
                64
            )
        );
        return admin_err(state, ci, "peer.exists", &m, Some("hub list"));
    }
    if state.peers.len() >= MAX_PEERS {
        let m = format!("hub table full (MAX_PEERS = {MAX_PEERS})");
        return admin_err(state, ci, "peer.full", &m, Some("hub del to make room"));
    }
    if pubkey_b64.is_empty() {
        return admin_err(
            state,
            ci,
            "peer.no_key",
            "a hub needs its public key",
            Some("the 88-character key from that hub's hub show"),
        );
    }
    let key: [u8; COMBINED_KEY_LEN] = match crypto::b64_decode(&pubkey_b64) {
        Some(dec) if dec.len() == COMBINED_KEY_LEN => {
            let mut k = [0u8; COMBINED_KEY_LEN];
            k.copy_from_slice(&dec);
            k
        }
        _ => {
            return admin_err(
                state,
                ci,
                "peer.bad_key",
                "the key must be 88 base64 characters of a 64-byte public key",
                Some("the key from that hub's hub show"),
            );
        }
    };
    let mut np = PeerConfig {
        ip: trunc_string(&ip, 64),
        port,
        fd: -1,
        ..Default::default()
    };
    np.uuid = uuid.clone();
    np.friendly_name = name.clone();
    np.ed_pub.copy_from_slice(&key[..ED25519_KEY_LEN]);
    np.x25519_pub.copy_from_slice(&key[ED25519_KEY_LEN..]);
    np.has_pubkey = true;
    let nip = np.ip.clone();
    state.peers.push(np);
    state.config_dirty = true;
    let mut r = Reply::new();
    r.ok("peer.added");
    r.kvi("n", state.peers.len() as i64);
    opt(&mut r, "uuid", &uuid);
    opt(&mut r, "name", &name);
    r.kv("ip", &nip);
    r.kvi("port", i64::from(port));
    r.kv("fp", &crypto::key_fingerprint(&key));
    send_reply(state, ci, &mut r)
}

fn del_peer(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // The payload names the peer: its uuid or its name (the console sends
    // the uuid hub del's preview resolved), or its number in hub list.
    if payload.is_empty() {
        return admin_err(
            state,
            ci,
            "peer.usage",
            "say which hub",
            Some("hub del <uuid|name>"),
        );
    }
    let Some(target) = peer_find(state, payload) else {
        let m = format!(
            "no hub {}: none with that uuid or name",
            trunc_string(payload, 61)
        );
        return admin_err(state, ci, "peer.not_found", &m, Some("hub list"));
    };
    let gone = state.peers[target].clone();
    let was_up = peer_client(state, &gone).is_some();
    let admin_fd = state.clients[ci].fd;
    if gone.fd != -1
        && let Some(cj) = state.client_by_fd(gone.fd)
    {
        auth::disconnect_client(state, cj);
    }
    state.peers.remove(target);
    state.config_dirty = true;
    let Some(ci) = refind(state, admin_fd) else {
        return false;
    };
    let mut r = Reply::new();
    r.ok("peer.removed");
    r.kvi("n", target as i64 + 1);
    opt(&mut r, "uuid", &gone.uuid);
    opt(&mut r, "name", &gone.friendly_name);
    r.kv("ip", &gone.ip);
    r.kvi("port", i64::from(gone.port));
    r.kvb("was_up", was_up);
    send_reply(state, ci, &mut r)
}

fn set_peer_pubkey(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // "<#|uuid|name>:<pubkey>" — peer set <peer> key <key>.  The link is
    // dropped at once so it comes back authenticated with the new key.
    // sscanf("%63[^:]:%127s") != 2
    let f: Vec<&str> = payload.splitn(2, ':').collect();
    let sel = f.first().copied().unwrap_or("").to_string();
    let pubkey_b64 = f.get(1).and_then(|s| scan_word(s, 127)).unwrap_or_default();
    if !scan_ok(&sel, 63) || pubkey_b64.is_empty() {
        return admin_err(
            state,
            ci,
            "peer.usage",
            "say which hub and the key",
            Some("hub set <#|uuid|name> key <key>"),
        );
    }
    let Some(pi) = peer_find(state, &sel) else {
        let m = format!(
            "no hub #{}, and none with that uuid or name",
            trunc_string(&sel, 41)
        );
        return admin_err(state, ci, "peer.not_found", &m, Some("hub list"));
    };
    let dec = match crypto::b64_decode(&pubkey_b64) {
        Some(d) if d.len() == COMBINED_KEY_LEN => d,
        _ => {
            return admin_err(
                state,
                ci,
                "peer.bad_key",
                "the key must be 88 base64 characters of a 64-byte public key",
                Some("the key from that hub's hub show"),
            );
        }
    };
    let old_fp = if state.peers[pi].has_pubkey {
        peer_key_fp(&state.peers[pi])
    } else {
        String::new()
    };
    {
        let p = &mut state.peers[pi];
        p.ed_pub.copy_from_slice(&dec[..ED25519_KEY_LEN]);
        p.x25519_pub.copy_from_slice(&dec[ED25519_KEY_LEN..]);
        p.has_pubkey = true;
    }
    let fp = peer_key_fp(&state.peers[pi]);
    state.config_dirty = true;
    let p = state.peers[pi].clone();
    crate::hlog_info!(
        "[HUB] {} pubkey set by {}\n",
        if p.uuid.is_empty() {
            p.ip.clone()
        } else {
            state.who('h', &p.uuid)
        },
        state.who_client(ci)
    );
    let admin_fd = state.clients[ci].fd;
    let pc = peer_client(state, &p);
    let relinked = pc.is_some();
    if let Some(cj) = pc {
        auth::disconnect_client(state, cj); // D9: relink with the new key now
    }
    let Some(ci) = refind(state, admin_fd) else {
        return false;
    };
    let mut r = Reply::new();
    r.ok("peer.set");
    r.kvi("n", pi as i64 + 1);
    opt(&mut r, "uuid", &p.uuid);
    opt(&mut r, "name", &p.friendly_name);
    r.kv("setting", "key");
    opt(&mut r, "old", &old_fp);
    r.kv("value", &fp);
    r.kvb("relinked", relinked);
    send_reply(state, ci, &mut r)
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

fn add_user_record(state: &mut HubState, ci: usize, payload: &str, typ: char) -> bool {
    // Payload: name|pubkey_b64|mask|access.  The user generated their own
    // keypair (keygen) and only the public half arrives: the hub never mints
    // or delivers a user's private key.  access (user_flags plan U4/U5): an
    // admin's flags (+a, or letters from bchou), an oper's channels (* or
    // #a,#b) -- required, there is no default.
    let is_admin = typ == 'a';
    let usage = if is_admin {
        "user add admin <name> <key> <mask> <+a|flags>"
    } else {
        "user add oper <name> <key> <mask> <*|#chan,#chan>"
    };
    // sscanf("%63[^|]|%89[^|]|%255[^|]|%511[^|]") < 3
    let f = split_fields(payload, 4);
    if f.len() < 3 || !scan_ok(f[0], 63) || !scan_ok(f[1], COMBINED_KEY_B64 + 1) || f[2].is_empty()
    {
        return admin_err(
            state,
            ci,
            "user.usage",
            "user add needs a name, a key and a mask",
            Some(usage),
        );
    }
    let pname = f[0].to_string();
    let ppub = f[1].to_string();
    let pmask = trunc_string(f[2], MAX_MASK_LEN);
    // a mask past 255 bytes stops the scan there: no access field read
    let pacc = if f[2].len() >= MAX_MASK_LEN {
        String::new()
    } else {
        trunc_string(f.get(3).copied().unwrap_or(""), 512)
    };
    if pacc.is_empty() {
        return admin_err(
            state,
            ci,
            "user.usage",
            if is_admin {
                "say the admin's flags: +a for a full admin, or letters from bchou (b bots, c channels, h hub, o opers, u upgrades)"
            } else {
                "say the oper's channels: * for every channel, or #a,#b"
            },
            Some(usage),
        );
    }
    let mut flags = String::new();
    let mut chans: Vec<String> = Vec::new();
    if is_admin {
        match access::uflags_edit("", &pacc) {
            Some(fl) if !fl.is_empty() => flags = fl,
            _ => {
                return admin_err(
                    state,
                    ci,
                    "user.bad_flags",
                    "flags are +a (full admin) or letters from bchou",
                    Some("+a, +chu, +b · help user add lists the flags"),
                );
            }
        }
    } else {
        let bad = |state: &mut HubState| {
            admin_err(
                state,
                ci,
                "user.bad_chans",
                "channels are * (every channel) or up to 16 of #a,#b",
                Some(usage),
            )
        };
        for t in pacc.split(',').filter(|t| !t.is_empty()) {
            if chans.iter().any(|c| c.eq_ignore_ascii_case(t)) {
                continue;
            }
            if !access::uchan_name_ok(t) || chans.len() >= 16 {
                return bad(state);
            }
            chans.push(t.to_string());
        }
        let star = chans.iter().any(|c| c == "*");
        if chans.is_empty() || (star && chans.len() > 1) {
            return bad(state);
        }
        // a binding to a channel nobody manages would be an orphan from the
        // start (user chan add refuses it too)
        if let Some(c) = chans
            .iter()
            .find(|c| *c != "*" && storage::chan_live(state, c).is_none())
        {
            let c = c.clone();
            return mf_status_err(state, ci, ModesStatus::NotManaged, Some(&c));
        }
    }
    if pname.is_empty() || pname.contains('|') || pname.contains(' ') {
        return admin_err(
            state,
            ci,
            "user.bad_name",
            "that is not a usable name",
            Some(usage),
        );
    }
    let Some(praw) = crypto::pubkey_b64_decode(&ppub) else {
        return admin_err(
            state,
            ci,
            "user.bad_key",
            "the key must be the user's 88-character public key",
            Some("the contents of their .public.b64"),
        );
    };
    if !pmask.contains('!') || !pmask.contains('@') {
        return admin_err(
            state,
            ci,
            "user.bad_mask",
            "a mask needs ! and @ (nick!user@host)",
            None,
        );
    }
    // Name and key are unique across all records: console logins identify
    // the admin by key.
    for o in state.user_records.iter().filter(|u| u.is_active) {
        if o.name.eq_ignore_ascii_case(&pname) {
            let m = format!("the name {} is taken", trunc_string(&pname, 64));
            return admin_err(state, ci, "user.name_taken", &m, Some("user list"));
        }
        if o.has_pubkey && o.pubkey_b64 == ppub {
            let m = format!("that key already belongs to {}", trunc_string(&o.name, 64));
            return admin_err(state, ci, "user.key_taken", &m, None);
        }
    }
    if state.user_records.len() >= MAX_HUB_USER_RECORDS {
        return admin_err(
            state,
            ci,
            "user.full",
            "the user table is full",
            Some("hub purge removes old tombstones"),
        );
    }
    if state.mask_records.len() >= MAX_HUB_USER_MASKS {
        return admin_err(
            state,
            ci,
            "user.mask_full",
            "the usermask table is full",
            Some("hub purge removes old tombstones"),
        );
    }
    if (is_admin && state.uflag_records.len() >= MAX_HUB_USER_FLAGS)
        || (!is_admin && state.uchan_records.len() + chans.len() + 1 > MAX_HUB_CHAN_BINDS)
    {
        return admin_err(
            state,
            ci,
            "user.full",
            "the flag / channel table is full",
            Some("hub purge removes old tombstones"),
        );
    }
    let t = now();
    let Some(new_uuid) = crypto::gen_uuid_v4() else {
        return admin_err(state, ci, "internal.entropy", "out of entropy", None);
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
        uuid: new_uuid.clone(),
        mask: pmask.clone(),
        is_active: true,
        last_used: 0,
        timestamp: t,
    });
    // Flags / bindings at the user's own stamp; a channel-bound oper also
    // gets its "*" del (access::migrate must never make it global).
    if is_admin {
        access::uflag_put(state, &new_uuid, &flags, t);
    } else {
        for c in &chans {
            access::uchan_put(state, &new_uuid, c, true, t);
        }
        if chans[0] != "*" {
            access::uchan_put(state, &new_uuid, "*", false, t);
        }
    }
    state.config_dirty = true;
    // Bots get fresh per-connection payloads (the right shape per bot
    // version); peers get ONE sync: the record, its mask, its flags /
    // bindings, in the order a peer needs them.
    let u = state.user_records.last().unwrap().clone();
    let m = state.mask_records.last().unwrap().clone();
    let mut sync = crate::config::format_user_record(&u);
    sync.push_str(&format!("m|{}|{}|add|0|{t}\n", m.uuid, m.mask));
    access::append(state, &mut sync, Some(&|uu: &str| uu == new_uuid));
    client::broadcast_config_to_bots(state, &sync);
    mesh::broadcast_sync_to_peers(state, &sync, -1);
    let mut r = Reply::new();
    r.ok("user.added");
    r.kv("name", &pname);
    r.kv("role", role_name(typ));
    r.kv("fp", &crypto::key_fingerprint(&praw));
    r.kv("mask", &pmask);
    if is_admin {
        r.kv("flags", &flags);
    } else {
        r.kv("chans", &access::user_chans(state, &new_uuid));
    }
    r.kvi("peers", linked_peer_count(state));
    r.kvi("bots", local_bot_count(state));
    r.kvi("port", i64::from(listen_port(state)));
    send_reply(state, ci, &mut r)
}

fn del_user_record(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // Either opcode removes the named user, whatever its role.
    if payload.is_empty() {
        return admin_err(
            state,
            ci,
            "user.usage",
            "say which user",
            Some("user del <name>"),
        );
    }
    let Some(ui) = user_by_name(state, payload) else {
        let m = format!("no user called \"{}\"", trunc_string(payload, 65));
        return admin_err(state, ci, "user.not_found", &m, Some("user list"));
    };
    if state.user_records[ui].typ == 'a' && last_full_admin(state, &state.user_records[ui].uuid) {
        return admin_err(
            state,
            ci,
            "user.last_admin",
            "that is the last full admin (+a); the network needs one",
            Some("make another admin +a first"),
        );
    }
    // Peers get ONE sync payload: the user tombstone, then a tombstone for
    // every mask the user owned.  No peer or bot cascades a user delete to
    // its masks, so a mask tombstone that is not sent leaves the mask live
    // there: an orphan holding a slot of the shared 200-mask table on every
    // other hub and on their bots.  One payload keeps the lines in order and
    // off the per-lane message cap (a user may own every mask slot).
    let typ = state.user_records[ui].typ;
    let sessions = if typ == 'a' {
        admin_console_sessions(state, &state.user_records[ui].name)
    } else {
        0
    };
    state.user_records[ui].is_active = false;
    state.user_records[ui].timestamp = lww_next_ts(state.user_records[ui].timestamp);
    state.config_dirty = true;

    let target_uuid = state.user_records[ui].uuid.clone();
    let target_name = state.user_records[ui].name.clone();
    let uline = crate::config::format_user_record(&state.user_records[ui]);
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
        if typ == 'a' { "Admin" } else { "Oper" }
    );
    let mut r = Reply::new();
    r.ok("user.removed");
    r.kv("name", &target_name);
    r.kv("role", role_name(typ));
    r.kvi("masks", masks_dropped);
    r.kvi("peers", linked_peer_count(state));
    r.kvi("bots", local_bot_count(state));
    r.kvi("sessions", sessions);
    send_reply(state, ci, &mut r)
}

fn add_usermask(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // sscanf("%63[^|]|%255s") < 2
    let f = split_fields(payload, 2);
    let mask = f.get(1).and_then(|m| scan_word(m, MAX_MASK_LEN - 1));
    if f.len() < 2 || !scan_ok(f[0], 63) || mask.is_none() {
        return admin_err(
            state,
            ci,
            "user.usage",
            "say which user and mask",
            Some("user mask add <name> <mask>"),
        );
    }
    let pname = f[0].to_string();
    let pmask = mask.unwrap_or_default();
    if !pmask.contains('!') || !pmask.contains('@') {
        return admin_err(
            state,
            ci,
            "user.bad_mask",
            "a mask needs ! and @ (nick!user@host)",
            None,
        );
    }
    let Some(ui) = user_by_name(state, &pname) else {
        let m = format!("no user called \"{}\"", trunc_string(&pname, 64));
        return admin_err(state, ci, "user.not_found", &m, Some("user list"));
    };
    let target_uuid = state.user_records[ui].uuid.clone();
    let target_name = state.user_records[ui].name.clone();
    // A duplicate active mask is an error; a tombstone for the same mask is
    // revived past its stamp (a second record could tie with the remove).
    let mut mi = None;
    for i in 0..state.mask_records.len() {
        let m = &state.mask_records[i];
        if m.uuid != target_uuid || !m.mask.eq_ignore_ascii_case(&pmask) {
            continue;
        }
        if m.is_active {
            let msg = format!("{} already has that mask", trunc_string(&target_name, 64));
            return admin_err(
                state,
                ci,
                "user.mask_exists",
                &msg,
                Some("user show <name>"),
            );
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
                return admin_err(
                    state,
                    ci,
                    "user.mask_full",
                    "the usermask table is full",
                    Some("hub purge removes old tombstones"),
                );
            }
            state.mask_records.push(MaskRecord {
                uuid: target_uuid.clone(),
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
    let mut r = Reply::new();
    r.ok("user.mask_added");
    r.kv("name", &target_name);
    r.kv("mask", &pmask);
    r.kvi("masks", user_mask_count(state, &target_uuid));
    r.kvi("peers", linked_peer_count(state));
    r.kvi("bots", local_bot_count(state));
    send_reply(state, ci, &mut r)
}

fn del_usermask(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // sscanf("%63[^|]|%255s") < 2
    let f = split_fields(payload, 2);
    let mask = f.get(1).and_then(|m| scan_word(m, MAX_MASK_LEN - 1));
    if f.len() < 2 || !scan_ok(f[0], 63) || mask.is_none() {
        return admin_err(
            state,
            ci,
            "user.usage",
            "say which user and mask",
            Some("user mask del <name> <mask>"),
        );
    }
    let pname = f[0].to_string();
    let pmask = mask.unwrap_or_default();
    let Some(ui) = user_by_name(state, &pname) else {
        let m = format!("no user called \"{}\"", trunc_string(&pname, 64));
        return admin_err(state, ci, "user.not_found", &m, Some("user list"));
    };
    let target_uuid = state.user_records[ui].uuid.clone();
    let target_name = state.user_records[ui].name.clone();
    let Some(mi) = state
        .mask_records
        .iter()
        .position(|m| m.is_active && m.uuid == target_uuid && m.mask.eq_ignore_ascii_case(&pmask))
    else {
        let m = format!("{} has no such mask", trunc_string(&target_name, 64));
        return admin_err(
            state,
            ci,
            "user.mask_not_found",
            &m,
            Some("user show <name>"),
        );
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
    let mut r = Reply::new();
    r.ok("user.mask_removed");
    r.kv("name", &target_name);
    r.kv("mask", &m.mask);
    r.kvi("masks", user_mask_count(state, &target_uuid));
    r.kvi("peers", linked_peer_count(state));
    r.kvi("bots", local_bot_count(state));
    send_reply(state, ci, &mut r)
}

fn set_userkey(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // Payload: name|pubkey_b64 — replace a user's key (rotation, a lost key,
    // or giving a legacy keyless user one).  UUID, masks and history stay;
    // the old key stops working for the console and every bot at sync speed.
    // sscanf("%63[^|]|%89s") < 2
    let f = split_fields(payload, 2);
    let key = f.get(1).and_then(|k| scan_word(k, COMBINED_KEY_B64 + 1));
    if f.len() < 2 || !scan_ok(f[0], 63) || key.is_none() {
        return admin_err(
            state,
            ci,
            "user.usage",
            "say which user and the key",
            Some("user set <name> key <key>"),
        );
    }
    let pname = f[0].to_string();
    let ppub = key.unwrap_or_default();
    let Some(praw) = crypto::pubkey_b64_decode(&ppub) else {
        return admin_err(
            state,
            ci,
            "user.bad_key",
            "the key must be the user's 88-character public key",
            Some("the contents of their .public.b64"),
        );
    };
    let Some(ti) = user_by_name(state, &pname) else {
        let m = format!("no user called \"{}\"", trunc_string(&pname, 64));
        return admin_err(state, ci, "user.not_found", &m, Some("user list"));
    };
    if let Some(o) = state
        .user_records
        .iter()
        .enumerate()
        .find(|(i, o)| *i != ti && o.is_active && o.has_pubkey && o.pubkey_b64 == ppub)
        .map(|(_, o)| o.name.clone())
    {
        let m = format!("that key already belongs to {}", trunc_string(&o, 64));
        return admin_err(state, ci, "user.key_taken", &m, None);
    }
    let old_fp = if state.user_records[ti].has_pubkey {
        crypto::key_fingerprint_b64(&state.user_records[ti].pubkey_b64)
    } else {
        String::new()
    };
    let typ = state.user_records[ti].typ;
    let sessions = if typ == 'a' {
        admin_console_sessions(state, &state.user_records[ti].name)
    } else {
        0
    };
    {
        let u = &mut state.user_records[ti];
        u.pubkey_b64 = ppub;
        u.has_pubkey = true;
        // Bump the timestamp so peers and bots see this update as newer than
        // the old record (otherwise replication compares ts and drops it).
        u.timestamp = lww_next_ts(u.timestamp);
    }
    state.config_dirty = true;
    let sync = crate::config::format_user_record(&state.user_records[ti]);
    client::broadcast_config_to_bots(state, &sync);
    mesh::broadcast_sync_to_peers(state, &sync, -1);
    let name = state.user_records[ti].name.clone();
    let mut r = Reply::new();
    r.ok("user.set");
    r.kv("name", &name);
    r.kv("role", role_name(typ));
    r.kv("setting", "key");
    opt(&mut r, "old", &old_fp);
    r.kv("value", &crypto::key_fingerprint(&praw));
    r.kvi("peers", linked_peer_count(state));
    r.kvi("bots", local_bot_count(state));
    r.kvi("sessions", sessions);
    send_reply(state, ci, &mut r)
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

fn list_channels(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let mut r = Reply::new();
    if !payload.is_empty() {
        let e = chan_entry(state, payload).filter(|&i| {
            mesh::parse_global_channel_value(&state.global_entries[i].value)
                .is_some_and(|(_, _, _, op)| op != "del")
        });
        let Some(i) = e else {
            let m = format!("{} is not a managed channel", trunc_string(payload, 65));
            return admin_err(state, ci, "channel.not_found", &m, Some("channel list"));
        };
        r.ok("channel.show");
        r.kvi("bots_online", network_bots_online(state));
        // modes.md §5.1: the stored modes and where they come from, the
        // settings the channel overrides, and its ban count
        let cn = storage::chan_live(state, payload).unwrap_or_default();
        {
            let cs = if cn.is_empty() {
                None
            } else {
                modes::chanset_get(state, &cn)
            };
            let ns = modes::netset_get(state);
            let (mut eff, mut src) = ("+nt".to_string(), "built-in");
            match (&cs, &ns) {
                (Some(c), _) if !c.modes.is_empty() => {
                    eff = c.modes.clone();
                    src = "chan";
                }
                (_, Some(n)) if !n.modes.is_empty() => {
                    eff = n.modes.clone();
                    src = "net";
                }
                _ => {}
            }
            r.kv("want", &eff);
            r.kv("want_src", src);
            r.kv("overrides", cs.as_ref().map_or("", |c| c.settings.as_str()));
            let nb = if cn.is_empty() {
                0
            } else {
                modes::ban_list(state, Some(&cn), MF_BANS_CHAN_MAX).len()
            };
            r.kvi("bans", nb as i64);
        }
        let (v, ts) = (
            state.global_entries[i].value.clone(),
            state.global_entries[i].timestamp,
        );
        reply_chan(state, &mut r, &v, ts);
        // every setting's effective value, so the view need not say only
        // "all default"
        mf_setting_rows(
            state,
            &mut r,
            (!cn.is_empty()).then_some(cn.as_str()),
            false,
        );
        return send_reply(state, ci, &mut r);
    }
    let count = state
        .global_entries
        .iter()
        .filter(|e| {
            e.key == "c"
                && mesh::parse_global_channel_value(&e.value)
                    .is_some_and(|(n, _, _, op)| !n.is_empty() && op != "del")
        })
        .count() as i64;
    r.ok("channel.list");
    r.kvi("count", count);
    r.kvi("bots_online", network_bots_online(state));
    for e in state.global_entries.iter().filter(|e| e.key == "c") {
        reply_chan(state, &mut r, &e.value, e.timestamp);
    }
    send_reply(state, ci, &mut r)
}

fn add_channel(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // "<#chan>|<key>" adds (or re-adds) a channel.  (The key as a setting
    // moved to channel mode +k; channel set is CMD_ADMIN_CHAN_SET.)
    if payload.is_empty() {
        return admin_err(
            state,
            ci,
            "channel.usage",
            "say which channel",
            Some("channel add <#chan> [key]"),
        );
    }
    let chan = wire_field(payload, 0, 128).unwrap_or_default();
    let key = wire_tail(payload, 1, 64).unwrap_or_default();
    if !chan_name_valid(&chan) {
        return admin_err(
            state,
            ci,
            "channel.bad_name",
            "a channel name starts with # or & and has no spaces, commas or control characters",
            Some("channel add #name [key]"),
        );
    }
    if key.bytes().any(|c| c <= 0x20 || c == b',') {
        return admin_err(
            state,
            ci,
            "channel.bad_key",
            "a channel key has no spaces, commas or control characters",
            None,
        );
    }
    let old = chan_active_key(state, &chan);
    let existed = old.is_some();
    let old_key = old.unwrap_or_default();
    chan_store(state, &chan, &key);
    let mut r = Reply::new();
    r.ok("channel.added");
    r.kv("name", &chan);
    opt(&mut r, "key", &key);
    opt(&mut r, "old_key", &old_key);
    r.kvb("existed", existed);
    opt(
        &mut r,
        "modes",
        &chan_modes_letters(mesh::global_channel_modes(state, &chan)),
    );
    r.kvi("bots", local_bot_count(state));
    r.kvi("peers", linked_peer_count(state));
    send_reply(state, ci, &mut r)
}

fn del_channel(state: &mut HubState, ci: usize, payload: &str) -> bool {
    if payload.is_empty() {
        return admin_err(
            state,
            ci,
            "channel.usage",
            "say which channel",
            Some("channel del <#chan>"),
        );
    }
    let existed = chan_active_key(state, payload).is_some();
    // One stamp past the channel's c|, C| and every B| line, so the delete
    // beats all of them: the settings and bans go with the channel.
    let t = storage::chan_del_stamp(state, payload);
    storage::chan_cascade_del(state, payload, t, true);
    storage::update_global_entry(state, "c", payload, "", "del", t);
    state.config_dirty = true;
    let sync_msg = format!("c|{payload}||del|{t}\n");
    client::broadcast_config_to_bots(state, &sync_msg);
    mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
    let mut r = Reply::new();
    r.ok("channel.removed");
    r.kv("name", payload);
    r.kvb("existed", existed);
    r.kvi("bots", local_bot_count(state));
    r.kvi("peers", linked_peer_count(state));
    r.kvi("purge_days", i64::from(state.purge_days_setting));
    send_reply(state, ci, &mut r)
}

// ---------------------------------------------------------------------------
// Modes, channel settings, network defaults, bans (docs/modes.md §5.1)
//
// channel mode / channel set / ban / network set.  The store functions are
// modes.rs's; this is the console's side: parse the (hostile) payload, call
// them, answer in records.  Mirrors the mf_* block of hub_logic.c.
// ---------------------------------------------------------------------------
const MF_MAX_TOKENS: usize = 16;
const MF_BANS_LIST_MAX: usize = 600;
/// >= MAX_BANS_PER_CHAN and MAX_GLOBAL_BANS.
const MF_BANS_CHAN_MAX: usize = 128;
/// 10 years, the store's own ceiling.
const MF_BAN_MINUTES_MAX: u64 = 5_256_000;

pub(crate) fn mf_field_count(s: &str) -> usize {
    1 + s.bytes().filter(|&c| c == b'|').count()
}

/// The name a console session logs in as ("ADMIN:robert" -> "robert").
fn mf_admin_name(state: &HubState, ci: usize) -> String {
    let id = &state.clients[ci].id;
    id.strip_prefix("ADMIN:").unwrap_or(id).to_string()
}

fn mf_status_err(state: &mut HubState, ci: usize, st: ModesStatus, what: Option<&str>) -> bool {
    let (code, msg, hint): (&str, String, Option<&str>) = match st {
        ModesStatus::Frozen => (
            "config.frozen",
            "the config is frozen while an upgrade runs".into(),
            Some("upgrade status; a stale freeze is lifted with option set"),
        ),
        ModesStatus::BadChan => (
            "channel.bad_name",
            "a channel name starts with # or & and has no spaces, commas or control characters"
                .into(),
            None,
        ),
        ModesStatus::NotManaged => (
            "channel.not_found",
            format!(
                "{} is not a managed channel",
                crate::cstr::trunc(what.unwrap_or("?"), 65)
            ),
            Some("channel add <#chan>"),
        ),
        ModesStatus::BadModes => (
            "channel.bad_mode",
            "that is not a valid mode string".into(),
            Some("channel mode <#chan> <+modes> [args]"),
        ),
        ModesStatus::TooLong => (
            "channel.too_long",
            "the settings would not fit the record (512 bytes)".into(),
            Some("reset some with <name> default"),
        ),
        ModesStatus::BadSetting => (
            "channel.bad_value",
            "that setting value is not valid".into(),
            None,
        ),
        ModesStatus::BadMask => (
            "ban.bad_mask",
            "a ban mask is 1-120 printable characters with no spaces, commas or |".into(),
            Some("ban add <#chan|*> nick!user@host"),
        ),
        ModesStatus::BadReason => (
            "ban.bad_reason",
            "a ban reason is at most 120 bytes with no control characters".into(),
            None,
        ),
        ModesStatus::BadExpiry => (
            "ban.bad_time",
            "a ban lasts 1 minute to 10 years, or perm".into(),
            Some("ban add <#chan|*> <mask> [<min>|perm]"),
        ),
        ModesStatus::NotFound => (
            "ban.not_found",
            "no such ban".into(),
            Some("ban list [#chan|*]"),
        ),
        ModesStatus::Full => (
            "ban.full",
            "the record or ban table is full (100 bans per channel, 100 global)".into(),
            Some("ban del <#chan|*> <mask>"),
        ),
        ModesStatus::Protected | ModesStatus::Ok => {
            ("modes.failed", "the change was refused".into(), None)
        }
    };
    admin_err(state, ci, code, &msg, hint)
}

/// Whether a stored mode string ("+stnkl 20", "-i+t") sets `letter` on.
fn mf_modes_plus(modes: &str, letter: u8) -> bool {
    let mut sign = 0u8;
    for c in modes.bytes() {
        if c == b' ' {
            break;
        }
        if c == b'+' || c == b'-' {
            sign = c;
        } else if c == letter && sign == b'+' {
            return true;
        }
    }
    false
}

/// The channel's mode card: stored string (""= network default), the string
/// in force and where it comes from, the modes a bot last reported live,
/// whether a key is set, and whether +l fights +dynamiclimit.  `cname` must
/// be a live channel.
pub(crate) fn mf_mode_card_extra(state: &HubState, r: &mut Reply, cname: &str) {
    let cs = modes::chanset_get(state, cname);
    let ns = modes::netset_get(state);
    let (mut eff, mut src) = ("+nt".to_string(), "built-in");
    match (&cs, &ns) {
        (Some(c), _) if !c.modes.is_empty() => {
            eff = c.modes.clone();
            src = "chan";
        }
        (_, Some(n)) if !n.modes.is_empty() => {
            eff = n.modes.clone();
            src = "net";
        }
        _ => {}
    }
    r.kv("modes", cs.as_ref().map_or("", |c| c.modes.as_str()));
    r.kv("effective", &eff);
    r.kv("source", src);
    let key = zeroize::Zeroizing::new(chan_effective_key(state, cname).unwrap_or_default());
    r.kvb("key_set", !key.is_empty());
    r.kv(
        "live",
        &chan_modes_letters(mesh::global_channel_modes(state, cname)),
    );
    let (_, dyn_v) = modes::setting_effective(state, Some(cname), "dynamiclimit");
    r.kvb("dynlimit", mf_modes_plus(&eff, b'l') && dyn_v == "1");
}

fn mf_mode_card(state: &HubState, r: &mut Reply, cname: &str) {
    r.kv("chan", cname);
    mf_mode_card_extra(state, r, cname);
}

/// Parsed channel modes: the stored form, the +k key op and the key.
struct MfModes {
    stored: String,
    key_op: i32,
    key: zeroize::Zeroizing<String>,
}

/// Channel mode strings the console sends: "<+modes>|<arg>|<arg>".  Fills the
/// stored form (letters, then the limit) and the key to set / clear.
fn mf_parse_modes(modes: &str, args: &[String]) -> Result<MfModes, &'static str> {
    let mut sign = 0u8;
    let mut limit = String::new();
    let mut seen = [false; 256];
    let mut ai = 0usize;
    let (mut plus_s, mut plus_p) = (false, false);
    let mut key_op = 0;
    let mut key = zeroize::Zeroizing::new(String::new());
    if modes.is_empty() {
        return Err("say the modes, e.g. +nt");
    }
    for c in modes.bytes() {
        if c == b'+' || c == b'-' {
            sign = c;
            continue;
        }
        if !b"imnpstkl".contains(&c) {
            return Err("modes are i m n p s t k l");
        }
        if sign == 0 {
            return Err("start the modes with + or -");
        }
        if seen[usize::from(c)] {
            return Err("a mode letter may appear only once");
        }
        seen[usize::from(c)] = true;
        if sign == b'+' && c == b's' {
            plus_s = true;
        }
        if sign == b'+' && c == b'p' {
            plus_p = true;
        }
        if c == b'k' {
            if sign == b'+' {
                if ai >= args.len() {
                    return Err("+k needs a key");
                }
                let k = &args[ai];
                ai += 1;
                if k.is_empty() || k.len() > 30 {
                    return Err("a key is 1-30 bytes");
                }
                if k.bytes().any(|b| b <= 0x20 || b == b',' || b == 0x7f) {
                    return Err("a key has no spaces, commas or control characters");
                }
                *key = k.clone();
                key_op = 1;
            } else {
                key_op = -1;
            }
        } else if c == b'l' && sign == b'+' {
            if ai >= args.len() {
                return Err("+l needs a limit");
            }
            let l = &args[ai];
            ai += 1;
            if l.is_empty() || l.len() > 5 || !l.bytes().all(|b| b.is_ascii_digit()) {
                return Err("the limit is 1-99999");
            }
            let v: i64 = l.parse().map_err(|_| "the limit is 1-99999")?;
            if !(1..=99999).contains(&v) {
                return Err("the limit is 1-99999");
            }
            limit = v.to_string();
        }
    }
    if ai != args.len() {
        return Err("more arguments than +k and +l take");
    }
    if plus_s && plus_p {
        return Err("+s and +p cannot both be set");
    }
    let stored = format!("{modes}{}{limit}", if limit.is_empty() { "" } else { " " });
    if stored.len() > C_MODES_MAX {
        return Err("the mode string is too long");
    }
    if modes::modes_check(&stored) != ModesStatus::Ok {
        return Err("that is not a valid mode string");
    }
    Ok(MfModes {
        stored,
        key_op,
        key,
    })
}

/// channel mode: #chan | #chan|<modes>|<arg>... | #chan|-
fn admin_chan_mode(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let chan = if payload.is_empty() {
        None
    } else {
        wire_field(payload, 0, MAX_CHAN)
    };
    let Some(chan) = chan else {
        return admin_err(
            state,
            ci,
            "channel.usage",
            "say which channel",
            Some("channel mode <#chan> [<+modes> [args]]"),
        );
    };
    if !chan_name_valid(&chan) {
        return mf_status_err(state, ci, ModesStatus::BadChan, Some(&chan));
    }
    let Some(cname) = storage::chan_live(state, &chan) else {
        return mf_status_err(state, ci, ModesStatus::NotManaged, Some(&chan));
    };
    let nf = mf_field_count(payload);
    if nf == 1 {
        let mut r = Reply::new();
        r.ok("channel.mode");
        r.kvb("view", true);
        mf_mode_card(state, &mut r, &cname);
        return send_reply(state, ci, &mut r);
    }
    if nf > 5 {
        return admin_err(
            state,
            ci,
            "channel.bad_mode",
            "too many arguments",
            Some("channel mode <#chan> <+modes> [key] [limit]"),
        );
    }
    let Some(modes_f) = wire_field(payload, 1, C_MODES_MAX + 2) else {
        return admin_err(
            state,
            ci,
            "channel.bad_mode",
            "the mode string is too long",
            None,
        );
    };
    let nargs = nf - 2;
    let mut args: Vec<String> = Vec::new();
    for i in 0..nargs {
        match wire_field(payload, 2 + i, 64) {
            Some(a) => args.push(a),
            None => {
                args.iter_mut().for_each(zeroize::Zeroize::zeroize);
                return admin_err(
                    state,
                    ci,
                    "channel.bad_mode",
                    "an argument is too long",
                    None,
                );
            }
        }
    }
    let parsed = if modes_f == "-" && nargs == 0 {
        Ok(MfModes {
            stored: String::new(),
            key_op: 0,
            key: zeroize::Zeroizing::new(String::new()),
        })
    } else {
        mf_parse_modes(&modes_f, &args)
    };
    args.iter_mut().for_each(zeroize::Zeroize::zeroize);
    let m = match parsed {
        Ok(m) => m,
        Err(why) => {
            return admin_err(
                state,
                ci,
                "channel.bad_mode",
                why,
                Some("channel mode <#chan> <+modes> [key] [limit]  (- = network default)"),
            );
        }
    };
    let settings = modes::chanset_get(state, &cname)
        .map(|c| c.settings)
        .unwrap_or_default();
    let st = modes::chanset_put(state, &cname, &m.stored, &settings);
    if st == ModesStatus::Ok && m.key_op != 0 {
        let cur = zeroize::Zeroizing::new(chan_effective_key(state, &cname).unwrap_or_default());
        let want: &str = if m.key_op > 0 { &m.key } else { "" };
        if *cur != want {
            chan_store(state, &cname, want);
        }
    }
    if st != ModesStatus::Ok {
        return mf_status_err(state, ci, st, Some(&cname));
    }
    // Apply once: the answer (channel.mode with who did it, or channel.nobody)
    // comes when the election ends.
    let admin = Some((state.clients[ci].fd, state.clients[ci].conn_serial));
    if !crate::elect::chan_mode_apply(state, &cname, admin) {
        return admin_err(
            state,
            ci,
            "channel.busy",
            "the modes are stored, but too many channel requests are in flight to apply them now",
            Some("channel mode <#chan> again in a few seconds"),
        );
    }
    true
}

/// Effective value of `name` as seen from `work` (a settings string being
/// edited) with the network level below it; src 'c' / 'n' / 'b'.
fn mf_eff(state: &HubState, work: &str, net_target: bool, name: &str) -> (char, String) {
    if let Some(v) = modes::settings_get(work, name) {
        return (if net_target { 'n' } else { 'c' }, v);
    }
    modes::setting_effective(state, None, name)
}

fn mf_src_word(s: char) -> &'static str {
    match s {
        'c' => "chan",
        'n' => "net",
        _ => "built-in",
    }
}

/// Canonical text of a validated value: numbers without leading zeros, floods
/// as N:S or off.
fn mf_canon(kind: &str, value: &mut String) {
    let num = |s: &str| s.parse::<i64>().ok();
    if kind == "num" {
        if let Some(a) = num(value) {
            *value = a.to_string();
        }
    } else if (kind == "flood" && value != "off" || kind == "sendq")
        && let Some((a, b)) = value.split_once(':')
        && let (Some(a), Some(b)) = (num(a), num(b))
    {
        *value = format!("{a}:{b}");
    }
}

fn mf_value_hint(name: &str, kind: &str) -> String {
    match modes::setting_range(name) {
        Some((lo, hi)) if kind == "num" => {
            format!("{name} is a whole number from {lo} to {hi}")
        }
        _ if kind == "sendq" => format!("{name} takes B:I (B 1-100 lines, I 0-10000 ms)"),
        _ if kind == "flood" => {
            format!("{name} takes N:S (N 1-1000 events in S 1-3600 seconds), off or default")
        }
        _ => format!("{name} is an on/off option: use +{name} or -{name}"),
    }
}

/// One setting change: the pieces of a `chg` record.
struct MfChg {
    name: String,
    kind: String,
    old: String,
    val: String,
    old_src: char,
    src: char,
    reset: bool,
}

/// One edit of a settings string.  tok: "+name", "-name" or "name=value"
/// (value may be "default").  net: the target is D| (channel set default).
/// The change goes to `work`.  Err is (code, message).
fn mf_edit(
    state: &HubState,
    work: &mut String,
    cap: usize,
    net: bool,
    tok: &str,
) -> Result<MfChg, (&'static str, String)> {
    let eq = tok.find('=');
    let signed_form = tok.starts_with('+') || tok.starts_with('-');
    let (name, mut value): (String, String);
    if signed_form {
        name = crate::cstr::trunc(&tok[1..], 48).to_string();
        value = if tok.starts_with('+') { "1" } else { "0" }.to_string();
        if tok.len() > 48 || eq.is_some() {
            return Err((
                "channel.unknown_setting",
                "that is not a setting name".into(),
            ));
        }
    } else {
        let nl = eq.unwrap_or(0);
        if eq.is_none() || nl == 0 || nl >= 48 || tok.len() - nl > 48 {
            return Err(("channel.usage", "say a value after the setting name".into()));
        }
        name = tok[..nl].to_string();
        value = tok[nl + 1..].to_string();
    }
    let unknown = || {
        (
            "channel.unknown_setting",
            format!("unknown setting \"{}\"", crate::cstr::trunc(&name, 41)),
        )
    };
    if !name.bytes().all(|c| c.is_ascii_lowercase() || c == b' ') {
        return Err(unknown());
    }
    if name == "key" {
        return Err((
            "channel.moved",
            "the channel key is a mode now: use channel mode <#chan> +k <key>".into(),
        ));
    }
    let Some(kind) = modes::setting_kind(&name) else {
        return Err(unknown());
    };
    if modes::setting_net_only(&name) {
        return Err(unknown());
    }
    let reset = value == "default";
    if !reset {
        let flag = kind == "flag";
        if flag != signed_form || modes::setting_check(&name, &value, net) != ModesStatus::Ok {
            return Err(("channel.bad_value", mf_value_hint(&name, kind)));
        }
        mf_canon(kind, &mut value);
    }
    let (old_src, old) = mf_eff(state, work, net, &name);
    if modes::settings_set(work, cap, &name, if reset { None } else { Some(&value) })
        != ModesStatus::Ok
    {
        return Err((
            "channel.too_long",
            "the settings would not fit the record (512 bytes)".into(),
        ));
    }
    let (src, val) = mf_eff(state, work, net, &name);
    Ok(MfChg {
        name,
        kind: kind.to_string(),
        old: crate::cstr::trunc(&old, 24).to_string(),
        val: crate::cstr::trunc(&val, 24).to_string(),
        old_src,
        src,
        reset,
    })
}

fn mf_chg_rec(r: &mut Reply, c: &MfChg, shown: &str) {
    r.rec("chg");
    r.kv("setting", shown);
    r.kv("kind", &c.kind);
    r.kv("old", &c.old);
    r.kv("old_src", mf_src_word(c.old_src));
    r.kv("value", &c.val);
    r.kv("src", mf_src_word(c.src));
    r.kvb("reset", c.reset);
}

/// One `setting` row per table entry of the wanted class, with the value in
/// force and where it comes from.
fn mf_setting_rows(state: &HubState, r: &mut Reply, cname: Option<&str>, net_rows: bool) {
    for i in 0..modes::setting_count() {
        let Some(n) = modes::setting_name(i) else {
            break;
        };
        if modes::setting_net_only(n) != net_rows {
            continue;
        }
        let (s, v) = modes::setting_effective(state, cname, n);
        let v = crate::cstr::trunc(&v, 24);
        let shown = match n.strip_prefix("bflood ") {
            Some(t) => format!("flood {t}"),
            None => n.to_string(),
        };
        r.rec("setting");
        r.kv("name", &shown);
        r.kv("kind", modes::setting_kind(n).unwrap_or(""));
        r.kv("value", v);
        r.kv("src", mf_src_word(s));
    }
}

/// channel set <#chan|default> [tokens...]
fn admin_chan_set(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let target = if payload.is_empty() {
        None
    } else {
        wire_field(payload, 0, MAX_CHAN)
    };
    let Some(target) = target else {
        return admin_err(
            state,
            ci,
            "channel.usage",
            "say which channel, or default",
            Some("channel set <#chan|default> [+opt|-opt|<name> <value>]"),
        );
    };
    let net = target == "default";
    let mut cname = String::new();
    let cur = if net {
        modes::netset_get(state).unwrap_or_default()
    } else {
        if !chan_name_valid(&target) {
            return mf_status_err(state, ci, ModesStatus::BadChan, Some(&target));
        }
        let Some(cn) = storage::chan_live(state, &target) else {
            return mf_status_err(state, ci, ModesStatus::NotManaged, Some(&target));
        };
        cname = cn;
        modes::chanset_get(state, &cname).unwrap_or_default()
    };
    let nf = mf_field_count(payload);
    let mut r = Reply::new();
    if nf == 1 {
        // the view
        r.ok("channel.settings");
        r.kv("name", if net { "default" } else { &cname });
        let (mut eff, mut src) = ("+nt".to_string(), "built-in");
        if !cur.modes.is_empty() {
            eff = cur.modes.clone();
            src = if net { "net" } else { "chan" };
        } else if !net
            && let Some(ns) = modes::netset_get(state)
            && !ns.modes.is_empty()
        {
            eff = ns.modes;
            src = "net";
        }
        r.kv("modes", &cur.modes);
        r.kv("effective", &eff);
        r.kv("source", src);
        r.kvi("ts", cur.ts);
        mf_setting_rows(state, &mut r, if net { None } else { Some(&cname) }, false);
        return send_reply(state, ci, &mut r);
    }
    if nf - 1 > MF_MAX_TOKENS {
        return admin_err(
            state,
            ci,
            "channel.usage",
            "too many settings in one line",
            None,
        );
    }
    let mut work = cur.settings.clone();
    let mut chg: Vec<MfChg> = Vec::new();
    for i in 1..nf {
        let tok = match wire_field(payload, i, 96) {
            Some(t) if !t.is_empty() => t,
            _ => {
                return admin_err(
                    state,
                    ci,
                    "channel.bad_value",
                    "a setting is too long or empty",
                    None,
                );
            }
        };
        match mf_edit(state, &mut work, C_SETTINGS_MAX + 1, net, &tok) {
            Ok(c) => chg.push(c),
            Err((code, why)) => {
                let hint = if code == "channel.moved" {
                    "channel mode <#chan> +k <key>"
                } else {
                    "channel set <#chan|default> shows the settings"
                };
                return admin_err(state, ci, code, &why, Some(hint));
            }
        }
    }
    let written = work != cur.settings;
    if written {
        let st = if net {
            modes::netset_put(state, &cur.modes, &work)
        } else {
            modes::chanset_put(state, &cname, &cur.modes, &work)
        };
        if st != ModesStatus::Ok {
            return mf_status_err(state, ci, st, Some(&cname));
        }
    }
    r.ok("channel.set");
    r.kv("name", if net { "default" } else { &cname });
    r.kvi("changes", chg.len() as i64);
    r.kvb("written", written);
    r.kvi("bots", local_bot_count(state));
    r.kvi("peers", linked_peer_count(state));
    for c in &chg {
        mf_chg_rec(&mut r, c, &c.name);
    }
    send_reply(state, ci, &mut r)
}

/// bot set (CMD_ADMIN_NET_SET): "" | flood|<cmd|msg|ctcp>|<N:S|off|default> | ignoretime|<min|default> | sendq|<B:I|default>
fn admin_net_set(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let cur = modes::netset_get(state).unwrap_or_default();
    let mut r = Reply::new();
    if payload.is_empty() {
        r.ok("network.settings");
        r.kvi("ts", cur.ts);
        mf_setting_rows(state, &mut r, None, true);
        return send_reply(state, ci, &mut r);
    }
    let nf = mf_field_count(payload);
    let Some(sub) = wire_field(payload, 0, 16) else {
        return admin_err(state, ci, "network.usage", "unknown bot setting", None);
    };
    let (name, shown, mut value);
    if sub == "flood" && nf == 3 {
        let (t, v) = (wire_field(payload, 1, 8), wire_field(payload, 2, 48));
        let (Some(t), Some(v)) = (t, v) else {
            return admin_err(
                state,
                ci,
                "network.unknown_setting",
                "flood types are cmd, msg and ctcp",
                Some("bot set flood <cmd|msg|ctcp> <N:S|off|default>"),
            );
        };
        if t != "cmd" && t != "msg" && t != "ctcp" {
            return admin_err(
                state,
                ci,
                "network.unknown_setting",
                "flood types are cmd, msg and ctcp",
                Some("bot set flood <cmd|msg|ctcp> <N:S|off|default>"),
            );
        }
        name = format!("bflood {t}");
        shown = format!("flood {t}");
        value = v;
    } else if sub == "ignoretime" && nf == 2 {
        let Some(v) = wire_field(payload, 1, 48) else {
            return admin_err(
                state,
                ci,
                "network.bad_value",
                "that value is too long",
                None,
            );
        };
        name = "ignoretime".to_string();
        shown = "ignoretime".to_string();
        value = v;
    } else if sub == "sendq" && nf == 2 {
        let Some(v) = wire_field(payload, 1, 48) else {
            return admin_err(
                state,
                ci,
                "network.bad_value",
                "that value is too long",
                None,
            );
        };
        name = "sendq".to_string();
        shown = "sendq".to_string();
        value = v;
    } else {
        return admin_err(
            state,
            ci,
            "network.unknown_setting",
            "bot settings are flood <cmd|msg|ctcp>, ignoretime and sendq",
            Some("bot set shows them"),
        );
    }
    let kind = modes::setting_kind(&name).unwrap_or("");
    let reset = value == "default";
    if !reset {
        if modes::setting_check(&name, &value, true) != ModesStatus::Ok {
            return admin_err(
                state,
                ci,
                "network.bad_value",
                &mf_value_hint(&shown, kind),
                Some(if sub == "flood" {
                    "bot set flood cmd 10:30"
                } else if sub == "sendq" {
                    "bot set sendq 10:100"
                } else {
                    "bot set ignoretime 10"
                }),
            );
        }
        mf_canon(kind, &mut value);
    }
    let mut work = cur.settings.clone();
    let (old_src, old) = mf_eff(state, &work, true, &name);
    if modes::settings_set(
        &mut work,
        D_SETTINGS_MAX + 1,
        &name,
        if reset { None } else { Some(&value) },
    ) != ModesStatus::Ok
    {
        return mf_status_err(state, ci, ModesStatus::TooLong, None);
    }
    let (src, val) = mf_eff(state, &work, true, &name);
    let written = work != cur.settings;
    if written {
        let st = modes::netset_put(state, &cur.modes, &work);
        if st != ModesStatus::Ok {
            return mf_status_err(state, ci, st, None);
        }
    }
    r.ok("network.set");
    r.kv("setting", &shown);
    r.kv("kind", kind);
    r.kv("old", crate::cstr::trunc(&old, 24));
    r.kv("old_src", mf_src_word(old_src));
    r.kv("value", crate::cstr::trunc(&val, 24));
    r.kv("src", mf_src_word(src));
    r.kvb("reset", reset);
    r.kvb("written", written);
    r.kvi("bots", local_bot_count(state));
    r.kvi("peers", linked_peer_count(state));
    send_reply(state, ci, &mut r)
}

/// hub set ssh | hub set conn (CMD_ADMIN_SET_SSH, docs/modes.md §9.3, D35):
///   "" | conn                       view of the ssh / conn group (ok|hub.show)
///   <name>|<value|default>          ssh setting
///   conn|<name>|<value|default>     shared connection limit
/// Local to this hub (.irchub.cnf, never synced).  A change reaches the console
/// thread as a fresh snapshot and applies to the next connection.
fn admin_set_ssh(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let nf = if payload.is_empty() {
        0
    } else {
        mf_field_count(payload)
    };
    let f0 = if nf > 0 {
        wire_field(payload, 0, 40)
    } else {
        None
    };
    let f1 = if nf > 1 {
        wire_field(payload, 1, 40)
    } else {
        None
    };
    let f2 = if nf > 2 {
        wire_field(payload, 2, 64)
    } else {
        None
    };
    if nf > 3 || (nf > 0 && f0.is_none()) || (nf > 1 && f1.is_none()) || (nf > 2 && f2.is_none()) {
        return admin_err(
            state,
            ci,
            "hub.bad_value",
            "that setting line is malformed",
            Some("hub set ssh <name> <value|default>"),
        );
    }
    let (f0, f1, f2) = (
        f0.unwrap_or_default(),
        f1.unwrap_or_default(),
        f2.unwrap_or_default(),
    );
    let conn = nf >= 1 && f0 == "conn";
    let group = if conn { Group::Conn } else { Group::Ssh };
    let gname = group.name();
    let mut r = Reply::new();

    if nf == 0 || (conn && nf == 1) {
        r.ok("hub.show");
        r.kv("group", gname);
        for i in 0..connlimits::count(group) {
            let Some(nm) = connlimits::name(group, i) else {
                continue;
            };
            let v = state.conn_cfg.get(group, nm).unwrap_or_default();
            let d = connlimits::default_text(group, nm).unwrap_or_default();
            r.kv(nm, &v);
            r.kv(&format!("{nm}_def"), &d);
        }
        return send_reply(state, ci, &mut r);
    }

    let (name, value) = if conn { (&f1, &f2) } else { (&f0, &f1) };
    if (conn && nf != 3) || (!conn && nf != 2) {
        return admin_err(
            state,
            ci,
            "hub.bad_value",
            "say a setting and its value",
            Some(if conn {
                "hub set conn <perip|churn|authfail|startups> <value|default>"
            } else {
                "hub set ssh <name> <value|default>"
            }),
        );
    }
    let Some(old) = state.conn_cfg.get(group, name) else {
        let why = format!("unknown {gname} setting \"{}\"", trunc_string(name, 31));
        return admin_err(
            state,
            ci,
            "hub.unknown_setting",
            &why,
            Some(if conn {
                "perip, churn, authfail, startups"
            } else {
                "preauth, preauthip, sessions, grace, authtries, idle, authfail, connect, block, cmdrate"
            }),
        );
    };
    let reset = value == "default";
    let mut next = state.conn_cfg;
    match next.set(group, name, if reset { None } else { Some(value) }) {
        SetResult::Ok => {}
        SetResult::Bad(why) => {
            return admin_err(
                state,
                ci,
                "hub.bad_value",
                &why,
                Some("hub set ssh shows the settings"),
            );
        }
        // find above already matched the name
        SetResult::Unknown => return admin_err(state, ci, "hub.unknown_setting", "?", None),
    }
    // A new connect / churn limit the issuing admin's own address is already
    // over would lock the console out: refuse it.
    {
        let t = crate::cstr::now();
        let ip = state.clients[ci].ip.clone();
        let lo = crate::ratelimit::trusted_loopback(state, &ip);
        let (mut seen, mut win) = (0, 0);
        if !lo && !conn && name == "connect" {
            win = next.connect_s;
            if let Some(e) = connlimits::ssh_table_peek(&state.ssh_ips, &ip)
                && t - e.win_start < i64::from(win)
                && e.conn_n > next.connect_n
            {
                seen = e.conn_n;
            }
        } else if !lo && conn && name == "churn" {
            win = next.churn_s;
            for e in &state.ip_limits {
                if e.ip == ip
                    && t - e.churn_window_start < i64::from(win)
                    && e.churn_count > next.churn_n
                {
                    seen = e.churn_count;
                }
            }
        }
        if seen > 0 {
            let why = format!(
                "your own address made {seen} connections in the last {win} s, over that limit"
            );
            return admin_err(
                state,
                ci,
                "hub.bad_value",
                &why,
                Some("raise it, or wait for the window to pass"),
            );
        }
    }
    let now_v = next.get(group, name).unwrap_or_default();
    let written = old != now_v;
    if written {
        state.conn_cfg = next;
        state.config_dirty = true;
        console::limits_changed(state);
        crate::hlog_info!(
            "[CONFIG] {gname} {name} {old} -> {now_v} by {}\n",
            state.who_client(ci)
        );
    }
    r.ok("hub.set");
    r.kv("setting", &format!("{gname} {name}"));
    r.kv("old", &old);
    r.kv("value", &now_v);
    r.kv("group", gname);
    r.kvb("reset", reset);
    r.kvb("written", written);
    r.kvb("restart", false);
    send_reply(state, ci, &mut r)
}

/// ban: list|<#c|*|""> | add|<#c|*>|<mask>|<min|perm>|<sticky 0/1>|<reason> | del|<#c|*>|<mask>
fn admin_ban(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let Some(sub) = wire_field(payload, 0, 8) else {
        return admin_err(
            state,
            ci,
            "ban.usage",
            "ban list, add or del",
            Some("help ban"),
        );
    };
    let nf = mf_field_count(payload);
    let (list, add, del) = (sub == "list", sub == "add", sub == "del");
    if !(list && nf <= 2) && !(add && nf >= 6) && !(del && nf == 3) {
        return admin_err(
            state,
            ci,
            "ban.usage",
            "ban list, add or del",
            Some("help ban"),
        );
    }
    let mut chan = String::new();
    let mut cname = "*".to_string();
    if nf > 1 {
        match wire_field(payload, 1, MAX_CHAN) {
            Some(c) => chan = c,
            None => return mf_status_err(state, ci, ModesStatus::BadChan, Some("")),
        }
    }
    let global = chan == "*";
    if !(list && chan.is_empty()) && !global {
        if !chan_name_valid(&chan) {
            return mf_status_err(state, ci, ModesStatus::BadChan, Some(&chan));
        }
        if !list {
            match storage::chan_live(state, &chan) {
                Some(c) => cname = c,
                None => return mf_status_err(state, ci, ModesStatus::NotManaged, Some(&chan)),
            }
        }
        if list {
            cname = chan.clone();
        }
    }
    let mut r = Reply::new();
    if list {
        let b = modes::ban_list(
            state,
            if chan.is_empty() { None } else { Some(&cname) },
            MF_BANS_LIST_MAX,
        );
        r.ok("ban.list");
        r.kv("chan", if chan.is_empty() { "" } else { &cname });
        r.kvi("count", b.len() as i64);
        r.kvb("truncated", b.len() >= MF_BANS_LIST_MAX);
        for x in &b {
            r.rec("ban");
            r.kv("chan", &x.chan);
            r.kv("mask", &x.mask);
            r.kvi("expires", x.expires);
            r.kvb("sticky", x.flags.contains('s'));
            r.kv("setter", &x.setter);
            r.kv("reason", &x.reason);
            r.kvi("ts", x.ts);
            r.kvi("used", x.last_used);
        }
        return send_reply(state, ci, &mut r);
    }
    let Some(mask) = wire_field(payload, 2, BAN_MASK_MAX + 8) else {
        return mf_status_err(state, ci, ModesStatus::BadMask, None);
    };
    let bchan = if global { "*" } else { cname.as_str() };
    if del {
        let st = modes::ban_del(state, bchan, &mask);
        if st != ModesStatus::Ok {
            return mf_status_err(state, ci, st, Some(&chan));
        }
        r.ok("ban.removed");
        r.kv("chan", bchan);
        r.kv("mask", &mask);
        r.kvi("bots", local_bot_count(state));
        r.kvi("peers", linked_peer_count(state));
        return send_reply(state, ci, &mut r);
    }
    // add
    let (dur, sticky) = (wire_field(payload, 3, 16), wire_field(payload, 4, 4));
    let (Some(dur), Some(sticky)) = (dur, sticky) else {
        return mf_status_err(state, ci, ModesStatus::BadExpiry, None);
    };
    let reason = wire_tail(payload, 5, BAN_REASON_MAX + 8).unwrap_or_default();
    if reason.contains('|') {
        return mf_status_err(state, ci, ModesStatus::BadReason, None);
    }
    let mut expires = 0i64;
    if dur != "perm" {
        match parse_uint(&dur, MF_BAN_MINUTES_MAX) {
            Some(m) if m >= 1 => expires = now() + (m as i64) * 60,
            _ => return mf_status_err(state, ci, ModesStatus::BadExpiry, None),
        }
    }
    // Whether this mask is already banned there (an update, not a new ban).
    let existed = modes::ban_list(state, Some(bchan), MF_BANS_CHAN_MAX)
        .iter()
        .any(|b| storage::ascii_ieq(&b.mask, &mask));
    let admin = mf_admin_name(state, ci);
    let (st, who) = modes::ban_add(state, bchan, &mask, expires, sticky == "1", &admin, &reason);
    if st == ModesStatus::Protected {
        let msg = format!(
            "{} would also ban {}, who must never be banned",
            crate::cstr::trunc(&mask, 121),
            crate::cstr::trunc(&who, 81)
        );
        r.err("ban.protected", Some(&msg), Some("use a narrower mask"));
        r.kv("mask", &mask);
        r.kv("who", &who);
        return send_reply(state, ci, &mut r);
    }
    if st != ModesStatus::Ok {
        return mf_status_err(state, ci, st, Some(&chan));
    }
    r.ok("ban.added");
    r.kv("chan", bchan);
    r.kv("mask", &mask);
    r.kvi("expires", expires);
    r.kvb("sticky", sticky == "1");
    r.kv("reason", &reason);
    r.kvb("existed", existed);
    r.kvi("bots", local_bot_count(state));
    r.kvi("peers", linked_peer_count(state));
    send_reply(state, ci, &mut r)
}

/// While an upgrade holds the config still, only the changing forms of the
/// four modes opcodes are refused; their views stay readable.
fn mf_payload_mutates(cmd: u8, payload: &str) -> bool {
    match cmd {
        CMD_ADMIN_CHAN_MODE | CMD_ADMIN_CHAN_SET => payload.contains('|'),
        CMD_ADMIN_BAN => !payload.starts_with("list"),
        CMD_ADMIN_NET_SET => !payload.is_empty(),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Admin flags (irchub docs/plans/2026-10-16_user_flags_plan.md §2, R4)
// ---------------------------------------------------------------------------

/// The admin a console connection belongs to (its id is "ADMIN:<name>"), or
/// None when that record is gone or is not a live admin.
fn admin_of_client(state: &HubState, ci: usize) -> Option<usize> {
    let name = state.clients[ci].id.strip_prefix("ADMIN:")?;
    user_by_name(state, name).filter(|&i| state.user_records[i].typ == 'a')
}

/// C `sscanf(payload, "%63[^|]", name)`: the first field, at most 63 bytes;
/// None when it is empty.
fn first_field63(payload: &str) -> Option<&str> {
    let f = payload.split('|').next().unwrap_or("");
    if f.is_empty() {
        return None;
    }
    let mut end = f.len().min(63);
    while !f.is_char_boundary(end) {
        end -= 1;
    }
    Some(&f[..end])
}

/// The flag a user-record command needs for the user it names: 'a' for an
/// admin, 'o' for an oper (plan R1, U13); None when it names nobody.
fn user_target_flag(state: &HubState, payload: &str) -> Option<char> {
    let i = user_by_name(state, first_field63(payload)?)?;
    Some(if state.user_records[i].typ == 'a' {
        'a'
    } else {
        'o'
    })
}

/// The admin flag an admin opcode needs (plan §2), or None for a view any
/// admin may run.  C `admin_flag_needed`.
fn admin_flag_needed(state: &HubState, me: Option<usize>, cmd: u8, payload: &str) -> Option<char> {
    match cmd {
        CMD_ADMIN_CREATE_BOT | CMD_ADMIN_DEL | CMD_ADMIN_DISCONNECT_BOT | CMD_ADMIN_REKEY_BOT => {
            Some('b')
        }
        CMD_ADMIN_NET_SET => mf_payload_mutates(cmd, payload).then_some('b'),
        CMD_ADMIN_ADD_PEER
        | CMD_ADMIN_DEL_PEER
        | CMD_ADMIN_SET_PEER_PUBKEY
        | CMD_ADMIN_SYNC_MESH
        | CMD_ADMIN_SET_PUBKEY
        | CMD_ADMIN_REGEN_KEYS
        | CMD_ADMIN_SET_HUB_NAME
        | CMD_ADMIN_SET_BIND_IP
        | CMD_ADMIN_SET_BIND_PORT
        | CMD_ADMIN_SET_LOG_SIZE
        | CMD_ADMIN_SET_LOG_LEVEL
        | CMD_ADMIN_PURGE_TOMBSTONES
        | CMD_ADMIN_SET_PURGE_DAYS
        | CMD_ADMIN_ADD_ALLOWLIST
        | CMD_ADMIN_DEL_ALLOWLIST
        | CMD_ADMIN_ADD_DENYLIST
        | CMD_ADMIN_DEL_DENYLIST => Some('h'),
        // "" and "conn" show the tables; a name and a value change one
        CMD_ADMIN_SET_SSH => (!payload.is_empty() && mf_field_count(payload) > 1).then_some('h'),
        // R5: opt h / F decide the security model
        CMD_ADMIN_SET_OPT_FLAGS => Some('a'),
        CMD_ADMIN_ADD_CHANNEL
        | CMD_ADMIN_DEL_CHANNEL
        | CMD_ADMIN_OP_USER
        | CMD_ADMIN_INVITE_USER => Some('c'),
        CMD_ADMIN_CHAN_MODE | CMD_ADMIN_CHAN_SET | CMD_ADMIN_BAN => {
            mf_payload_mutates(cmd, payload).then_some('c')
        }
        CMD_ADMIN_UPGRADE_NET => Some('u'),
        CMD_ADMIN_UPGRADE_STATUS => (payload == "abort" || payload == "forget").then_some('u'),
        CMD_ADMIN_ADD_ADMIN => Some('a'),
        CMD_ADMIN_ADD_OPER_RECORD => Some('o'),
        // flags|… changes an admin, chan|… an oper
        CMD_ADMIN_USER_ACCESS => Some(if payload.starts_with("flags|") {
            'a'
        } else {
            'o'
        }),
        // either role
        CMD_ADMIN_DEL_ADMIN
        | CMD_ADMIN_DEL_OPER_RECORD
        | CMD_ADMIN_ADD_USERMASK
        | CMD_ADMIN_DEL_USERMASK => user_target_flag(state, payload),
        CMD_ADMIN_SET_USERKEY => {
            // your own key: any admin
            if let (Some(m), Some(name)) = (me, first_field63(payload))
                && name.eq_ignore_ascii_case(&state.user_records[m].name)
            {
                return None;
            }
            user_target_flag(state, payload)
        }
        _ => None,
    }
}

/// Plan R2: whether `uuid` is the last live admin holding +a.
fn last_full_admin(state: &HubState, uuid: &str) -> bool {
    if !access::user_flags(state, uuid).contains('a') {
        return false;
    }
    !state.user_records.iter().any(|u| {
        u.is_active
            && u.typ == 'a'
            && u.uuid != uuid
            && access::user_flags(state, &u.uuid).contains('a')
    })
}

/// CMD_ADMIN_USER_ACCESS (user_flags plan §4.1): `flags|<name>|<spec>`,
/// `chan|add|<name>|<#chan|*>`, `chan|del|<name>|<#chan|*>`.  C
/// `admin_user_access`.
fn user_access(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let usage_hint = "user set <name> flags <+x-y> | user chan add|del <name> <#chan|*>";
    let nf = if payload.is_empty() {
        0
    } else {
        mf_field_count(payload)
    };
    let kind = wire_field(payload, 0, 8);
    let f1 = wire_field(payload, 1, 64);
    let f2 = wire_field(payload, 2, 64);
    let f3 = if nf > 3 {
        wire_field(payload, 3, MAX_CHAN)
    } else {
        Some(String::new())
    };
    let (Some(kind), Some(f1), Some(f2), Some(f3)) = (kind, f1, f2, f3) else {
        return admin_err(
            state,
            ci,
            "user.usage",
            "say which user and what to change",
            Some(usage_hint),
        );
    };
    if nf < 3 {
        return admin_err(
            state,
            ci,
            "user.usage",
            "say which user and what to change",
            Some(usage_hint),
        );
    }
    let flags_cmd = kind == "flags" && nf == 3;
    let chan_cmd = kind == "chan" && nf == 4 && (f1 == "add" || f1 == "del");
    if !flags_cmd && !chan_cmd {
        return admin_err(
            state,
            ci,
            "user.usage",
            "say which user and what to change",
            Some(usage_hint),
        );
    }
    let name = if flags_cmd { &f1 } else { &f2 };
    let Some(ti) = user_by_name(state, name) else {
        let m = format!("no user called \"{}\"", trunc_string(name, 64));
        return admin_err(state, ci, "user.not_found", &m, Some("user list"));
    };
    let t = state.user_records[ti].clone();
    let mut sync = String::new();
    let mut r = Reply::new();
    if flags_cmd {
        if t.typ != 'a' {
            return admin_err(
                state,
                ci,
                "user.not_admin",
                "flags are for admins; an oper has channels",
                Some("user chan add|del"),
            );
        }
        let old = access::user_flags(state, &t.uuid).to_string();
        let nw = match access::uflags_edit(&old, &f2) {
            Some(n) if !n.is_empty() => n,
            _ => {
                return admin_err(
                    state,
                    ci,
                    "user.bad_flags",
                    "flags are +a (full admin) or letters from bchou; +x-y changes some",
                    Some("+a, +chu, +b-u · help user set lists the flags"),
                );
            }
        };
        if !nw.contains('a') && last_full_admin(state, &t.uuid) {
            return admin_err(
                state,
                ci,
                "user.last_admin",
                "that is the last full admin (+a); the network needs one",
                Some("make another admin +a first"),
            );
        }
        let written = old != nw;
        if written {
            let ts = access::next_ts(state, &t.uuid);
            if !access::uflag_put(state, &t.uuid, &nw, ts) {
                return admin_err(
                    state,
                    ci,
                    "user.full",
                    "the flag table is full",
                    Some("hub purge removes old tombstones"),
                );
            }
            access::append(state, &mut sync, Some(&|u: &str| u == t.uuid));
        }
        r.ok("user.flags");
        r.kv("name", &t.name);
        r.kv("old", &old);
        r.kv("flags", &nw);
        r.kvb("written", written);
    } else {
        if t.typ != 'o' {
            return admin_err(
                state,
                ci,
                "user.not_oper",
                "channels are for opers; an admin has flags",
                Some("user set <name> flags"),
            );
        }
        let add = f1 == "add";
        if !access::uchan_name_ok(&f3) {
            return admin_err(
                state,
                ci,
                "user.bad_chans",
                "a channel is #name, or * for every channel",
                None,
            );
        }
        let live = access::uchan_find(state, &t.uuid, &f3)
            .is_some_and(|i| state.uchan_records[i].is_active);
        let any_live = access::user_chan_count(state, &t.uuid).0 > 0;
        let missing = if f3 == "*" { !any_live } else { !live };
        // A binding to a channel nobody manages would be an orphan from the
        // start: the purge removes those (as channel mode / set / ban refuse).
        if add && f3 != "*" && storage::chan_live(state, &f3).is_none() {
            return mf_status_err(state, ci, ModesStatus::NotManaged, Some(&f3));
        }
        if !add && missing {
            let m = format!(
                "{} has no {}",
                trunc_string(&t.name, 64),
                if f3 == "*" { "channels" } else { f3.as_str() }
            );
            return admin_err(
                state,
                ci,
                "user.chan_not_found",
                &m,
                Some("user show <name>"),
            );
        }
        let written = !(add && live && (f3 == "*" || !access::user_chan_ok(state, &t.uuid, None)));
        if written && access::chan_change(state, &t.uuid, add, &f3, &mut sync).is_none() {
            return admin_err(
                state,
                ci,
                "user.full",
                "the channel binding table is full",
                Some("hub purge removes old tombstones"),
            );
        }
        r.ok("user.chan");
        r.kv("name", &t.name);
        r.kv("action", &f1);
        r.kv("chan", &f3);
        r.kv("chans", &access::user_chans(state, &t.uuid));
        r.kvb("written", written);
    }
    if !sync.is_empty() {
        state.config_dirty = true;
        client::broadcast_config_to_bots(state, &sync);
        mesh::broadcast_sync_to_peers(state, &sync, -1);
    }
    r.kvi("peers", linked_peer_count(state));
    r.kvi("bots", local_bot_count(state));
    send_reply(state, ci, &mut r)
}

fn admin_flag_word(f: char) -> &'static str {
    match f {
        'a' => "full admin",
        'b' => "bots",
        'c' => "channels",
        'h' => "hub",
        'o' => "opers",
        'u' => "upgrades",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// The admin opcodes an SSH console may send (docs/console.md §2) -- every
/// command the console offers and nothing else.  The hub's private key never
/// leaves it and is never set from outside (GET/SET_PRIVKEY are retired: back
/// up .irchub.cnf instead), and the retired password and legacy global
/// mask opcodes have no console command.  Mirrors console_admin_op in C.
pub fn console_admin_op(cmd: u8) -> bool {
    matches!(
        cmd,
        CMD_ADMIN_LIST_FULL
            | CMD_ADMIN_LIST_SUMMARY
            | CMD_ADMIN_LIST_REVOKED
            | CMD_ADMIN_CREATE_BOT
            | CMD_ADMIN_DEL
            | CMD_ADMIN_DISCONNECT_BOT
            | CMD_ADMIN_REKEY_BOT
            | CMD_ADMIN_LIST_PEERS
            | CMD_ADMIN_ADD_PEER
            | CMD_ADMIN_DEL_PEER
            | CMD_ADMIN_PEER_REFS
            | CMD_ADMIN_SET_PEER_PUBKEY
            | CMD_ADMIN_SYNC_MESH
            | CMD_ADMIN_GET_PUBKEY
            | CMD_ADMIN_SET_PUBKEY
            | CMD_ADMIN_REGEN_KEYS
            | CMD_ADMIN_SET_HUB_NAME
            | CMD_ADMIN_SET_BIND_IP
            | CMD_ADMIN_SET_BIND_PORT
            | CMD_ADMIN_SET_LOG_SIZE
            | CMD_ADMIN_PURGE_TOMBSTONES
            | CMD_ADMIN_SET_PURGE_DAYS
            | CMD_ADMIN_SET_LOG_LEVEL
            | CMD_ADMIN_STATS
            | CMD_ADMIN_LIST_ALLOWLIST
            | CMD_ADMIN_ADD_ALLOWLIST
            | CMD_ADMIN_DEL_ALLOWLIST
            | CMD_ADMIN_LIST_DENYLIST
            | CMD_ADMIN_ADD_DENYLIST
            | CMD_ADMIN_DEL_DENYLIST
            | CMD_ADMIN_GET_OPT_FLAGS
            | CMD_ADMIN_SET_OPT_FLAGS
            | CMD_ADMIN_LIST_ADMINS
            | CMD_ADMIN_ADD_ADMIN
            | CMD_ADMIN_DEL_ADMIN
            | CMD_ADMIN_LIST_OPERS_V2
            | CMD_ADMIN_ADD_OPER_RECORD
            | CMD_ADMIN_DEL_OPER_RECORD
            | CMD_ADMIN_ADD_USERMASK
            | CMD_ADMIN_DEL_USERMASK
            | CMD_ADMIN_SET_USERKEY
            | CMD_ADMIN_MATCH
            | CMD_ADMIN_USER_ACCESS
            | CMD_ADMIN_LIST_CHANNELS
            | CMD_ADMIN_ADD_CHANNEL
            | CMD_ADMIN_DEL_CHANNEL
            | CMD_ADMIN_OP_USER
            | CMD_ADMIN_INVITE_USER
            | CMD_ADMIN_CHAN_MODE
            | CMD_ADMIN_CHAN_SET
            | CMD_ADMIN_BAN
            | CMD_ADMIN_NET_SET
            | CMD_ADMIN_SET_SSH
            | CMD_ADMIN_UPGRADE_NET
            | CMD_ADMIN_UPGRADE_STATUS
    )
}

fn upgrade_status_cmd(state: &mut HubState, ci: usize, payload: &str) -> bool {
    // "releases[|bot_ver|hub_ver|sel]": what the console's `upgrade releases`
    // offers to pick from — the verified release manifests of both products
    // and the nodes a selective run could name — plus, when targets are
    // given, the path an `upgrade start` would take to them.  Read-only;
    // allowed during a run.
    let lower = payload.get(..8).map(str::to_ascii_lowercase);
    if lower.as_deref() == Some("releases") && (payload.len() == 8 || payload.as_bytes()[8] == b'|')
    {
        let mut r = Reply::new();
        upgrade::releases(state, payload, &mut r);
        return send_reply(state, ci, &mut r);
    }
    // A payload of "abort" stops a run in flight and rolls the mesh back, and
    // stops a multi-step upgrade for good — here, and (flooded) on the hub
    // driving it if that is another one.
    if payload.eq_ignore_ascii_case("abort") {
        let run = state.upgrade.active;
        let plan = state.plan.active;
        let (step, steps) = (state.plan.step as i64 + 1, state.plan.steps() as i64);
        let moved = state
            .upgrade
            .nodes
            .iter()
            .filter(|n| {
                matches!(
                    n.state,
                    crate::state::UpgradeNodeState::Done
                        | crate::state::UpgradeNodeState::Committed
                )
            })
            .count() as i64;
        let moved = if run { moved } else { 0 };
        let id = if run {
            state.upgrade.id.clone()
        } else {
            String::new()
        };
        let admin_fd = state.clients[ci].fd;
        if run {
            upgrade::abort(state, "aborted by admin");
        }
        if state.plan.active {
            upgrade::plan_stop(
                state,
                &format!("aborted by admin before step {step}/{steps}"),
            );
        }
        let told = upgrade::cancel_flood(state);
        let Some(ci) = refind(state, admin_fd) else {
            return false;
        };
        let mut r = Reply::new();
        if !run && !plan {
            // Nothing here; whatever runs elsewhere has been told to stop.
            r.ok("upg.abort_sent");
            r.kvi("peers", told);
            return send_reply(state, ci, &mut r);
        }
        r.ok("upg.aborted");
        opt(&mut r, "id", &id);
        r.kvi("rolled_back", moved);
        if plan {
            r.kvi("step", step);
            r.kvi("steps", steps);
        }
        r.kvi("peers", told);
        return send_reply(state, ci, &mut r);
    }
    // "forget" drops the roll-up plan a finished run left behind, here and
    // (flooded) on every other hub.
    if payload.eq_ignore_ascii_case("forget") {
        if state.upgrade.active || upgrade::config_frozen(state) {
            return admin_err(
                state,
                ci,
                "upg.running",
                "an upgrade is running: the plan is kept until it ends",
                Some("upgrade abort"),
            );
        }
        let had = state.rollup.have_plan;
        let (had_bot, had_hub) = if had {
            (state.rollup.target.clone(), state.rollup.hub_target.clone())
        } else {
            (String::new(), String::new())
        };
        upgrade::rollup_forget(state, "forgotten by admin");
        let id = opflow::generate_request_id();
        opflow::forward_seen_check_and_add(state, &id);
        let fwd = format!("{id}|{}", now());
        let mut told = 0;
        for cj in state.peer_clients() {
            if queue::send_urgent(&mut state.clients[cj], CMD_UPGRADE_FORGET, &fwd) {
                told += 1;
            }
        }
        let mut r = Reply::new();
        r.ok("upg.forgotten");
        r.kvb("had", had);
        opt(&mut r, "bot_ver", &had_bot);
        opt(&mut r, "hub_ver", &had_hub);
        r.kvi("peers", told);
        return send_reply(state, ci, &mut r);
    }
    if !payload.is_empty() {
        return admin_err(
            state,
            ci,
            "upg.usage",
            "unknown upgrade request",
            Some("upgrade status · releases · abort · forget"),
        );
    }
    let mut r = Reply::new();
    upgrade::status(state, &mut r);
    send_reply(state, ci, &mut r)
}

/// Client load and the maintenance countdowns of CMD_ADMIN_STATS
/// (hub_maintenance), between the sync counters and the opcode rows.
fn stats_load(state: &HubState, r: &mut Reply) {
    let t = now();
    let (mut bots, mut peers, mut authing) = (0i64, 0i64, 0i64);
    for c in &state.clients {
        match (c.typ, c.authenticated) {
            (ClientType::Bot, true) => bots += 1,
            (ClientType::Hub, true) => peers += 1,
            _ => authing += 1,
        }
    }
    r.rec("load");
    r.kvi("clients", state.clients.len() as i64);
    r.kvi("bots", bots);
    r.kvi("peers", peers);
    r.kvi("authing", authing);
    r.kvi("dirty", i64::from(state.config_dirty));
    let tm = &state.timers;
    stats_timer(r, "gossip", 300, tm.last_mesh_gossip, t);
    stats_timer(
        r,
        "entropy",
        MESH_ANTI_ENTROPY_INTERVAL,
        tm.last_anti_entropy,
        t,
    );
    stats_timer(r, "scan", 5, tm.last_client_scan, t);
    stats_timer(r, "ipclean", 300, tm.last_ip_cleanup, t);
    stats_timer(r, "peers", PEER_RECONNECT_INTERVAL, tm.last_peer_check, t);
    let purge = if state.purge_days_setting > 0 && tm.last_purge > 0 {
        tm.last_purge
    } else {
        -1
    };
    stats_timer(r, "purge", 86400, purge, t);
}

/// One "timer" record: seconds until the next run of a job that runs every
/// `every` s and last ran at `last` (-1 = off).
fn stats_timer(r: &mut Reply, name: &str, every: i64, last: i64, t: i64) {
    r.rec("timer");
    r.kv("name", name);
    r.kvi("every", every);
    if last < 0 {
        r.kv("in", "off");
        return;
    }
    let left = if last > 0 { every - (t - last) } else { every };
    r.kvi("in", left.max(0));
}

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
    if upgrade::config_frozen(state)
        && upgrade::admin_cmd_mutates_config(cmd)
        && mf_payload_mutates(cmd, payload)
    {
        crate::hlog_warning!(
            "[UPGRADE] Refused admin command 0x{:02x}: config frozen\n",
            cmd
        );
        return admin_err(
            state,
            ci,
            "config.frozen",
            "the config is frozen while an upgrade runs",
            Some("upgrade status; a stale freeze is lifted with option set"),
        );
    }

    // Admin flags (plan R4): checked here for every opcode, whatever the
    // console already checked.  An admin whose record is gone runs views only.
    let me = admin_of_client(state, ci);
    if let Some(need) = admin_flag_needed(state, me, cmd, payload)
        && !me.is_some_and(|m| access::user_has_flag(state, &state.user_records[m].uuid, need))
    {
        crate::hlog_warning!(
            "[ADMIN] {} refused 0x{:02x}: needs +{}\n",
            state.who_client(ci),
            cmd,
            need
        );
        let msg = format!("this needs +{need} ({})", admin_flag_word(need));
        return admin_err(
            state,
            ci,
            "user.no_flag",
            &msg,
            Some(if need == 'a' {
                "ask a full admin (+a)"
            } else {
                "ask a full admin (+a) for the flag"
            }),
        );
    }

    match cmd {
        CMD_ADMIN_UPGRADE_NET => {
            // Payload: target_ver|variant|kind|min_from|base|hub_ver|hub_base
            // |sel — everything past the version is optional ("" = let each
            // node decide).  target_ver is the bots' (ircbot-releases);
            // hub_ver is the hubs' own (irchub-releases), and an empty hub_ver
            // leaves every hub where it is.  The two base slots are no longer
            // read: every node fetches from its own compiled-in root, the only
            // tree its pinned key verifies.  Only the last field — the
            // selection ("" = whole network), comma-separated
            // name-or-uuid[=c|rs] tokens — is a tail.
            // wire_field: a field that does not fit its buffer reads as ""
            let caps = [64, 8, 8, 64, 512, 64, 512];
            let fld: Vec<String> = (0..7)
                .map(|i| wire_field(payload, i, caps[i]).unwrap_or_default())
                .collect();
            let sel = wire_tail(payload, 7, MAX_UPGRADE_SELECT * 80).unwrap_or_default();
            let at = |i: usize| {
                if i == 7 {
                    sel.as_str()
                } else {
                    fld[i].as_str()
                }
            };
            let fd = state.clients[ci].fd;
            let msg = upgrade::plan_begin(
                state,
                fd,
                &upgrade::StartArgs {
                    target_ver: at(0),
                    variant: at(1),
                    kind: at(2),
                    min_from: at(3),
                    hub_ver: at(5),
                    sel: at(7),
                },
            );
            let Some(ci) = refind(state, fd) else {
                return false;
            };
            if !msg.starts_with("OK") {
                return admin_err(
                    state,
                    ci,
                    "upg.refused",
                    msg.strip_prefix("ERROR: ").unwrap_or(&msg),
                    Some("upgrade status · upgrade releases"),
                );
            }
            let u = &state.upgrade;
            let bots = u
                .nodes
                .iter()
                .filter(|n| n.kind == crate::state::UpgradeNodeKind::Bot)
                .count() as i64;
            let hubs = u
                .nodes
                .iter()
                .filter(|n| n.kind == crate::state::UpgradeNodeKind::PeerHub)
                .count() as i64;
            let mut r = Reply::new();
            r.ok("upg.started");
            r.kv("id", &u.id);
            r.kv("bot_ver", &u.target_ver);
            opt(&mut r, "hub_ver", &u.hub_ver);
            r.kvi("selected", u.select.len() as i64);
            r.kvi("bots", bots);
            r.kvi("peers", hubs);
            let pl = &state.plan;
            if pl.active && pl.run_id == u.id {
                r.kvi("step", pl.step as i64 + 1);
                r.kvi("steps", pl.steps() as i64);
                r.kv("bot_final", &pl.bot_target);
                opt(&mut r, "hub_final", &pl.hub_target);
            }
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_UPGRADE_STATUS => upgrade_status_cmd(state, ci, payload),

        CMD_ADMIN_LIST_SUMMARY => {
            let mut r = Reply::new();
            r.ok("bot.summary");
            r.kvi(
                "total",
                state.bots.iter().filter(|b| b.is_active).count() as i64,
            );
            for b in state.bots.iter().filter(|b| b.is_active) {
                r.rec("bot");
                r.kv("uuid", &b.uuid);
                if let Some(n) = b.entry("n") {
                    opt(&mut r, "nick", &n.value);
                }
            }
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_LIST_REVOKED => {
            // bot revoked: every deleted bot that is wiped if it ever connects.
            let mut r = Reply::new();
            r.ok("bot.revoked");
            r.kvi("count", state.revoked.len() as i64);
            r.kvi("max", MAX_REVOKED as i64);
            for rv in &state.revoked {
                r.rec("revoked");
                r.kv("uuid", &rv.uuid);
                opt(&mut r, "nick", &rv.nick);
                r.kvi("deleted", rv.del_ts);
                r.kvi("wiped", rv.wiped_ts);
            }
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_LIST_FULL => list_full(state, ci, payload),

        CMD_ADMIN_REKEY_BOT => {
            // v3: per-bot independent keys.  Only the bot can rekey — it owns
            // its private key.  The bot's 'rekey' admin command regenerates
            // the keypair locally and pushes the new PUBLIC key to us over
            // its authenticated session (we store it as the bot's 'pub' entry
            // and fan it out to peers via auto-sync).  We deliberately do NOT
            // disconnect the bot here: it needs that active session to push
            // the new pub, and it reconnects itself with the new key as the
            // final step of 'rekey'.  The console prints the steps; the
            // record says only which bot and its state.
            if payload.is_empty() {
                return admin_err(
                    state,
                    ci,
                    "bot.usage",
                    "say which bot",
                    Some("bot rekey <uuid>"),
                );
            }
            let b = bot_by_uuid(state, payload).filter(|&i| state.bots[i].is_active);
            let online = bot_online(state, payload);
            if b.is_none() && !online {
                return admin_err(
                    state,
                    ci,
                    "bot.not_found",
                    "no registered bot has that uuid",
                    Some("bot list"),
                );
            }
            let mut r = Reply::new();
            r.ok("bot.rekey_howto");
            r.kv("uuid", payload);
            if let Some(b) = b
                && let Some(n) = state.bots[b].entry("n")
            {
                opt(&mut r, "nick", &n.value);
            }
            r.kvb("online", online);
            r.kvb("local", local_bot_client(state, payload).is_some());
            if let Some(b) = b
                && let Some(p) = state.bots[b].entry("pub")
                && !p.value.is_empty()
            {
                r.kv("fp", &crypto::key_fingerprint_b64(&p.value));
            }
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_DISCONNECT_BOT => {
            if payload.is_empty() {
                return admin_err(
                    state,
                    ci,
                    "bot.usage",
                    "say which bot",
                    Some("bot kick <uuid>"),
                );
            }
            let nick = presence::bot_nick_from_config(state, payload);
            let Some(bi) = local_bot_client(state, payload) else {
                let msg = format!(
                    "{} is not connected to this hub",
                    trunc_string(if nick.is_empty() { payload } else { &nick }, 65)
                );
                if let Some(e) = roster_best(state, payload) {
                    let hub_name = e.hub_name.clone();
                    let hint = format!("it is on {}: kick it there", trunc_string(&hub_name, 65));
                    let mut r = Reply::new();
                    r.err("bot.not_local", Some(&msg), Some(&hint));
                    r.kv("hub_name", &hub_name);
                    return send_reply(state, ci, &mut r);
                }
                return admin_err(state, ci, "bot.not_local", &msg, Some("bot list"));
            };
            let since = state.clients[bi].connected_at;
            let ip = state.clients[bi].ip.clone();
            let admin_fd = state.clients[ci].fd;
            crate::hlog_warning!("[ADMIN] Disconnecting bot {payload}\n");
            auth::disconnect_client(state, bi);
            let Some(ci) = refind(state, admin_fd) else {
                return false;
            };
            let mut r = Reply::new();
            r.ok("bot.kicked");
            r.kv("uuid", payload);
            opt(&mut r, "nick", &nick);
            r.kvi("since", since);
            r.kv("ip", &ip);
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_DEL => {
            if payload.is_empty() {
                return admin_err(
                    state,
                    ci,
                    "bot.usage",
                    "say which bot",
                    Some("bot del <uuid>"),
                );
            }
            let nick = presence::bot_nick_from_config(state, payload);
            let admin_fd = state.clients[ci].fd;
            let Some(del_ts) = storage::delete(state, payload) else {
                return admin_err(
                    state,
                    ci,
                    "bot.not_found",
                    "no registered bot has that uuid",
                    Some("bot list"),
                );
            };
            // The tombstone put it on the revoke list (storage::update_entry).
            // Connected here: told to wipe its config and exit; a hub that
            // holds it does the same when this delete reaches it.
            let was_online = auth::retire_revoked_bots(state) > 0;
            // Peers store the same tombstone (same stamp); every bot gets a
            // config that no longer lists the deleted bot and ends in the T|
            // marker, so it drops the bot from its trusted list (no more ~B2
            // or op grants).
            let mut sync = format!("b|{payload}|d|1|{del_ts}\n");
            if let Some(rv) = crate::revoke::find(state, payload) {
                sync.push_str(&crate::revoke::format(rv));
            }
            mesh::broadcast_sync_to_peers(state, &sync, -1);
            client::broadcast_config_to_bots(state, &sync);
            let Some(ci) = refind(state, admin_fd) else {
                return false;
            };
            let mut r = Reply::new();
            r.ok("bot.deleted");
            r.kv("uuid", payload);
            opt(&mut r, "nick", &nick);
            r.kvb("was_online", was_online);
            r.kvi("peers", linked_peer_count(state));
            r.kvi("bots", local_bot_count(state));
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_SYNC_MESH => {
            let full_sync = mesh::generate_sync_packet(state);
            mesh::broadcast_sync_to_peers(state, &full_sync, -1);
            let records = full_sync.bytes().filter(|&b| b == b'\n').count() as i64;
            let mut r = Reply::new();
            r.ok("mesh.synced");
            r.kvi("peers", linked_peer_count(state));
            r.kvi("records", records);
            r.kvi("bytes", full_sync.len() as i64);
            for (i, p) in state.peers.iter().enumerate() {
                r.rec("peer");
                r.kvi("n", i as i64 + 1);
                opt(&mut r, "uuid", &p.uuid);
                opt(&mut r, "name", &p.friendly_name);
                r.kvb("sent", peer_client(state, p).is_some());
            }
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_CREATE_BOT => create_bot(state, ci, payload),
        CMD_ADMIN_REGEN_KEYS => regen_keys(state, ci),
        CMD_ADMIN_GET_PUBKEY => hub_show(state, ci),
        CMD_ADMIN_SET_PUBKEY => set_pubkey(state, ci, payload),

        CMD_ADMIN_ADD_PEER => add_peer(state, ci, payload),
        CMD_ADMIN_DEL_PEER => del_peer(state, ci, payload),
        CMD_ADMIN_SET_PEER_PUBKEY => set_peer_pubkey(state, ci, payload),
        CMD_ADMIN_LIST_PEERS => list_peers(state, ci, payload),
        CMD_ADMIN_PEER_REFS => peer_refs(state, ci, payload),

        CMD_ADMIN_LIST_CHANNELS => list_channels(state, ci, payload),
        CMD_ADMIN_ADD_CHANNEL => add_channel(state, ci, payload),
        CMD_ADMIN_DEL_CHANNEL => del_channel(state, ci, payload),
        CMD_ADMIN_CHAN_MODE => admin_chan_mode(state, ci, payload),
        CMD_ADMIN_CHAN_SET => admin_chan_set(state, ci, payload),
        CMD_ADMIN_BAN => admin_ban(state, ci, payload),
        CMD_ADMIN_NET_SET => admin_net_set(state, ci, payload),
        CMD_ADMIN_SET_SSH => admin_set_ssh(state, ci, payload),

        CMD_ADMIN_OP_USER => {
            // sscanf("%63[^|]|%63s") != 2
            let f = split_fields(payload, 2);
            let chan = f.get(1).and_then(|c| scan_word(c, 63));
            if f.len() < 2 || !scan_ok(f[0], 63) || chan.is_none() {
                return admin_err(
                    state,
                    ci,
                    "channel.usage",
                    "say which channel and nick",
                    Some("channel op <#chan> <nick>"),
                );
            }
            let nick = f[0].to_string();
            let channel = chan.unwrap_or_default();
            let admin_fd = state.clients[ci].fd;
            // One bot does it (CMD_CHAN_PROBE); the answer goes out when the
            // election ends.
            if crate::elect::start(
                state,
                "op",
                &channel,
                "ADMIN",
                &nick,
                "",
                Some((admin_fd, state.clients[ci].conn_serial)),
            )
            .is_some()
            {
                return true;
            }
            admin_err(
                state,
                ci,
                "channel.busy",
                "too many channel requests in flight",
                Some("try again in a few seconds"),
            )
        }

        CMD_ADMIN_INVITE_USER => {
            // sscanf("%63[^|]|%63s") != 2, and a channel name
            let f = split_fields(payload, 2);
            let chan = f.get(1).and_then(|c| scan_word(c, 63));
            if f.len() < 2
                || !scan_ok(f[0], 63)
                || !chan
                    .as_deref()
                    .is_some_and(|c| c.starts_with('#') || c.starts_with('&'))
            {
                return admin_err(
                    state,
                    ci,
                    "channel.usage",
                    "say which channel and nick",
                    Some("channel invite <#chan> <nick>"),
                );
            }
            let nick = f[0].to_string();
            let channel = chan.unwrap_or_default();
            let admin_fd = state.clients[ci].fd;
            if crate::elect::start(
                state,
                "invite",
                &channel,
                "ADMIN",
                &nick,
                "",
                Some((admin_fd, state.clients[ci].conn_serial)),
            )
            .is_some()
            {
                return true;
            }
            admin_err(
                state,
                ci,
                "channel.busy",
                "too many channel requests in flight",
                Some("try again in a few seconds"),
            )
        }

        CMD_ADMIN_PURGE_TOMBSTONES => {
            // Payload: "immediate" -> cutoff 0 (purge all); "<N>" days ->
            // cutoff = now - N*86400.  Fail closed: only "immediate" purges
            // everything; a payload that is not a whole number of days >= 1
            // is refused.
            let t = now();
            let mut cutoff = 0i64;
            let mut days = 0u64;
            if payload != "immediate" {
                let Some(udays) = parse_uint(payload, 36500).filter(|&d| d != 0) else {
                    return admin_err(
                        state,
                        ci,
                        "tomb.bad_arg",
                        "purge takes now or a number of days of at least 1",
                        Some("hub purge <now|days>"),
                    );
                };
                cutoff = t - (udays as i64) * 86400;
                days = udays;
            }
            let admin_fd = state.clients[ci].fd;
            let mut tombs = Reply::new();
            let purged_count = mesh::execute_purge(state, cutoff, Some(&mut tombs));
            let sent = mesh::broadcast_purge(state, cutoff);
            let Some(ci) = refind(state, admin_fd) else {
                return false;
            };
            if !sent {
                let m = format!(
                    "purged {purged_count} tombstones here, but the purge could not be sent to peers"
                );
                return admin_err(state, ci, "tomb.not_sent", &m, None);
            }
            let mut r = Reply::new();
            r.ok("tomb.purged");
            r.kvi("count", i64::from(purged_count));
            r.kvi("days", days as i64);
            r.kvi("peers", linked_peer_count(state));
            // the tomb| records the purge collected, after the result line
            let mut all = r.text().to_string();
            let t = tombs.text();
            if !t.is_empty() {
                all.push('\n');
                all.push_str(t);
            }
            resp(state, ci, &all)
        }

        CMD_ADMIN_SET_PURGE_DAYS => {
            let Some(udays) = parse_uint(payload, 36500).filter(|_| !payload.is_empty()) else {
                return admin_err(
                    state,
                    ci,
                    "hub.bad_days",
                    "autopurge takes a whole number of days (0 = off)",
                    Some("hub set autopurge <days|0>"),
                );
            };
            let old = state.purge_days_setting.to_string();
            // Mesh-wide (hs|autopurge): every hub purges on the same
            // schedule, the elected leader runs it.
            crate::revoke::gsetting_set(state, "autopurge", udays as i32); // 0 = disabled
            if let Some(line) = crate::revoke::gsetting_format(state, "autopurge") {
                mesh::broadcast_sync_to_peers(state, &line, -1);
            }
            let val = state.purge_days_setting.to_string();
            let peers = linked_peer_count(state);
            hub_set_reply(state, ci, "autopurge", Some(&old), &val, false, peers)
        }

        CMD_ADMIN_SET_BIND_IP => {
            if payload.is_empty() || payload.parse::<std::net::Ipv4Addr>().is_err() {
                return admin_err(
                    state,
                    ci,
                    "hub.bad_ip",
                    "not an IPv4 address",
                    Some("hub set bindip <a.b.c.d>"),
                );
            }
            let old = if state.bind_ip.is_empty() {
                "0.0.0.0".to_string()
            } else {
                state.bind_ip.clone()
            };
            state.bind_ip = trunc_string(payload, 64);
            state.config_dirty = true;
            let sync_msg = format!("bind_ip|{payload}|{}\n", now());
            mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
            let v = state.bind_ip.clone();
            let peers = linked_peer_count(state);
            hub_set_reply(state, ci, "bindip", Some(&old), &v, true, peers)
        }

        CMD_ADMIN_SET_HUB_NAME => {
            // The name is written into '|'-separated config lines and sent
            // inside handshakes and ':'/','-separated gossip: a newline or
            // separator in it forged config records ("x|203.0.113.77|0"
            // became a denylist entry).
            if payload.is_empty() || !name_valid(payload) {
                return admin_err(
                    state,
                    ci,
                    "hub.bad_name",
                    "a hub name is 1-63 characters of A-Z a-z 0-9 . _ -",
                    None,
                );
            }
            let old = hub_display_name(state).to_string();
            state.hub_friendly_name = trunc_string(payload, 64);
            state.config_dirty = true;
            // Peers learn names from mesh-state gossip, not from sync lines;
            // gossip now.
            state.mesh_state_dirty = true;
            let v = state.hub_friendly_name.clone();
            let peers = linked_peer_count(state);
            hub_set_reply(state, ci, "name", Some(&old), &v, false, peers)
        }

        CMD_ADMIN_SET_BIND_PORT => {
            let port = parse_uint(payload, 65535).unwrap_or(0) as i32;
            if payload.is_empty() || port < 1 {
                return admin_err(state, ci, "hub.bad_port", "port must be 1-65535", None);
            }
            let old = state.port.to_string();
            state.port = port;
            state.config_dirty = true;
            let sync_msg = format!("port|{port}|{}\n", now());
            mesh::broadcast_sync_to_peers(state, &sync_msg, -1);
            let peers = linked_peer_count(state);
            hub_set_reply(
                state,
                ci,
                "port",
                Some(&old),
                &port.to_string(),
                true,
                peers,
            )
        }

        CMD_ADMIN_LIST_ALLOWLIST | CMD_ADMIN_LIST_DENYLIST => list_acl(state, ci),
        CMD_ADMIN_ADD_ALLOWLIST => ip_acl_change(state, ci, 'w', true, payload),
        CMD_ADMIN_DEL_ALLOWLIST => ip_acl_change(state, ci, 'w', false, payload),
        CMD_ADMIN_ADD_DENYLIST => ip_acl_change(state, ci, 'x', true, payload),
        CMD_ADMIN_DEL_DENYLIST => ip_acl_change(state, ci, 'x', false, payload),

        CMD_ADMIN_SET_LOG_LEVEL => {
            // 1 byte: the file level.  2 bytes: <target><level>, target 0 =
            // the log file, 1 = the console log ring.  Level 0 is the byte
            // 0x00, so the frame length decides, never strlen.
            if !(raw_len == 1 || raw_len == 2 && raw[0] <= 1) {
                return admin_err(
                    state,
                    ci,
                    "log.bad_payload",
                    "invalid log level request",
                    Some("log set file|console <level>"),
                );
            }
            let ring = raw_len == 2 && raw[0] == 1;
            let level = i32::from(raw[raw_len - 1]).clamp(LOG_NONE, LOG_DEBUG);
            let old = if ring {
                state.console_log_level
            } else {
                state.log_level
            };
            if ring {
                state.console_log_level = level;
            } else {
                state.log_level = level;
            }
            state.config_dirty = true; // the level survives a restart
            crate::logging::set_levels(state.log_level, state.console_log_level);
            let mut r = Reply::new();
            r.ok("log.set");
            r.kv("setting", if ring { "console" } else { "file" });
            r.kvi("old", i64::from(old));
            r.kvi("value", i64::from(level));
            r.kv("file", HUB_LOG_FILE);
            r.kvi(
                "limit",
                if state.log_max_size > 0 {
                    state.log_max_size
                } else {
                    HUB_LOG_FILE_SIZE
                },
            );
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_SET_LOG_SIZE => {
            // Four raw bytes, network order: 10 MB is 00 A0 00 00.
            if raw_len != 4 {
                return admin_err(
                    state,
                    ci,
                    "log.bad_payload",
                    "invalid log size request",
                    Some("log set size <MB|nk|nb>"),
                );
            }
            let asked = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let size = i64::from(asked).clamp(HUB_LOG_SIZE_MIN, HUB_LOG_SIZE_MAX);
            let old = if state.log_max_size > 0 {
                state.log_max_size
            } else {
                HUB_LOG_FILE_SIZE
            };
            state.log_max_size = size;
            state.config_dirty = true; // log_size| survives a restart
            crate::logging::set_max_size(state.log_max_size);
            let mut r = Reply::new();
            r.ok("log.set");
            r.kv("setting", "size");
            r.kvi("old", old);
            r.kvi("value", state.log_max_size);
            r.kvu("asked", u64::from(asked));
            r.kvi("file_level", i64::from(state.log_level));
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_STATS => {
            // Read-only snapshot of the traffic counters; see
            // consts::CMD_ADMIN_STATS.
            let up = if state.hub_started > 0 {
                now() - state.hub_started
            } else {
                0
            };
            let mut r = Reply::new();
            crate::stats::report(up, &mut r, |r| stats_load(state, r));
            send_reply(state, ci, &mut r)
        }

        CMD_ADMIN_GET_OPT_FLAGS => {
            let mut r = Reply::new();
            r.ok("option.list");
            r.kv("flags", &state.opt_flags);
            if state.opt_flags_ts > 0 {
                r.kvi("ts", state.opt_flags_ts);
            }
            send_reply(state, ci, &mut r)
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
            let old = std::mem::replace(&mut state.opt_flags, dedup);
            // Past the previous stamp: a set and a clear in the same second
            // must not tie, or peers keep whichever arrived and the mesh
            // splits.
            state.opt_flags_ts = lww_next_ts(state.opt_flags_ts);
            state.config_dirty = true;
            let sync_pkt = format!("opt|{}|{}\n", state.opt_flags, state.opt_flags_ts);
            mesh::broadcast_sync_to_peers(state, &sync_pkt, -1);
            client::broadcast_full_config_to_all_bots(state);
            let mut r = Reply::new();
            r.ok("option.set");
            r.kv("old", &old);
            r.kv("value", &state.opt_flags);
            r.kvi("peers", linked_peer_count(state));
            r.kvi("bots", local_bot_count(state));
            send_reply(state, ci, &mut r)
        }

        // "" = admins, "*" = every user (user list)
        CMD_ADMIN_LIST_ADMINS => {
            let typ = if payload == "*" { None } else { Some('a') };
            list_users(state, ci, "user.list", typ, None)
        }
        CMD_ADMIN_LIST_OPERS_V2 => list_users(state, ci, "user.list", Some('o'), None),
        CMD_ADMIN_MATCH => {
            if payload.is_empty() {
                return admin_err(
                    state,
                    ci,
                    "user.usage",
                    "say which user",
                    Some("user show <name|*>"),
                );
            }
            let name = (payload != "*").then_some(payload);
            list_users(state, ci, "user.show", None, name)
        }
        CMD_ADMIN_ADD_ADMIN => add_user_record(state, ci, payload, 'a'),
        CMD_ADMIN_ADD_OPER_RECORD => add_user_record(state, ci, payload, 'o'),
        CMD_ADMIN_DEL_ADMIN | CMD_ADMIN_DEL_OPER_RECORD => del_user_record(state, ci, payload),
        CMD_ADMIN_ADD_USERMASK => add_usermask(state, ci, payload),
        CMD_ADMIN_DEL_USERMASK => del_usermask(state, ci, payload),
        CMD_ADMIN_SET_USERKEY => set_userkey(state, ci, payload),
        CMD_ADMIN_USER_ACCESS => user_access(state, ci, payload),

        _ => admin_err(state, ci, "admin.unknown", "unknown admin command", None),
    }
}

#[cfg(test)]
mod sendq_tests {
    use super::*;

    #[test]
    fn sendq_canon_and_hint() {
        let mut v = String::from("05:0100");
        mf_canon("sendq", &mut v);
        assert_eq!(v, "5:100");
        let mut v = String::from("010:00");
        mf_canon("sendq", &mut v);
        assert_eq!(v, "10:0");
        let mut v = String::from("off");
        mf_canon("flood", &mut v);
        assert_eq!(v, "off");
        assert_eq!(
            mf_value_hint("sendq", "sendq"),
            "sendq takes B:I (B 1-100 lines, I 0-10000 ms)"
        );
    }
}
