//! Network upgrade orchestration (`hub_logic.c`: `CMD_ADMIN_UPGRADE_NET` →
//! `CMD_UPGRADE_*`).
//!
//! hub_admin asks this hub to move the whole network to a version.  The hub
//! freezes the config, asks every node whether it could take that build
//! (PREPARE → READY/UNABLE), then commits them in a rolling plan: bots in
//! waves so a channel never loses all its bots at once, peer hubs afterwards
//! one at a time so the mesh never fully drops, and this hub last of all.
//!
//! The ack routing mirrors `opflow`'s pending-request tables: one id per run,
//! replies matched by that id, status routed home down `origin_fd`.  Unlike
//! an op grant a committed node DISCONNECTS (it execs a new binary), so
//! success is normally observed as "it came back announcing the target
//! version" — the `CMD_UPGRADE_RESULT` frame is a faster confirmation, not
//! the only one.

use crate::consts::*;
use crate::cstr::{now, trunc_string};
use crate::state::{
    ClientType, HubState, RollupTry, UpgradeNode, UpgradeNodeKind, UpgradeNodeState, UpgradePhase,
    UpgradeRoute, lww_next_ts,
};
use crate::{client, mesh, opflow, queue, update};

// ---------------------------------------------------------------------------
// Config freeze (Task 6)
// ---------------------------------------------------------------------------

/// Add or remove a flag in the replicated opt record, stamped and pushed the
/// same way `CMD_ADMIN_SET_OPT_FLAGS` does it.
fn opt_flag_set(state: &mut HubState, flag: char, on: bool) {
    if state.opt_flags.contains(flag) == on {
        return;
    }
    let mut next: String = state.opt_flags.chars().filter(|c| *c != flag).collect();
    if on && next.len() < MAX_OPT_FLAGS {
        next.push(flag);
    }
    state.opt_flags = next;
    // Past the previous stamp: a set and a clear in the same second must not
    // tie, or peers keep whichever arrived and the mesh splits.
    state.opt_flags_ts = lww_next_ts(state.opt_flags_ts);
    state.config_dirty = true;

    let sync_pkt = format!("opt|{}|{}\n", state.opt_flags, state.opt_flags_ts);
    mesh::broadcast_sync_to_peers(state, &sync_pkt, -1);
    client::broadcast_full_config_to_all_bots(state);
    crate::hlog_info!(
        "[UPGRADE] opt flags now '{}'\n",
        if state.opt_flags.is_empty() {
            "(none)"
        } else {
            &state.opt_flags
        }
    );
}

/// While a run holds the freeze, config mutations are refused.  The flag
/// replicates like any other opt, so peer hubs refuse them too.
pub fn config_frozen(state: &HubState) -> bool {
    state.opt(OPT_CONFIG_FROZEN)
}

/// Admin commands that write the replicated store or change which nodes
/// exist.  Read-only queries and the local operational settings stay
/// available, and so does `CMD_ADMIN_SET_OPT_FLAGS` deliberately: it is the
/// manual escape hatch that lifts a freeze a crashed run left behind.
pub fn admin_cmd_mutates_config(cmd: u8) -> bool {
    matches!(
        cmd,
        CMD_ADMIN_ADD
            | CMD_ADMIN_DEL
            | CMD_ADMIN_REGEN_KEYS
            | CMD_ADMIN_APPROVE
            | CMD_ADMIN_ADD_PEER
            | CMD_ADMIN_DEL_PEER
            | CMD_ADMIN_SET_PRIVKEY
            | CMD_ADMIN_SET_PUBKEY
            | CMD_ADMIN_REKEY_BOT
            | CMD_ADMIN_CREATE_BOT
            | CMD_ADMIN_ADD_CHANNEL
            | CMD_ADMIN_DEL_CHANNEL
            | CMD_ADMIN_ADD_MASK
            | CMD_ADMIN_DEL_MASK
            | CMD_ADMIN_ADD_OPER
            | CMD_ADMIN_DEL_OPER
            | CMD_ADMIN_PURGE_TOMBSTONES
            | CMD_ADMIN_SET_PURGE_DAYS
            | CMD_ADMIN_ADD_ADMIN
            | CMD_ADMIN_DEL_ADMIN
            | CMD_ADMIN_ADD_OPER_RECORD
            | CMD_ADMIN_DEL_OPER_RECORD
            | CMD_ADMIN_ADD_USERMASK
            | CMD_ADMIN_DEL_USERMASK
            | CMD_ADMIN_SET_PEER_PUBKEY
            | CMD_ADMIN_SET_USERKEY
    )
}

// ---------------------------------------------------------------------------
// Node table helpers
// ---------------------------------------------------------------------------

fn find_node(state: &HubState, uuid: &str) -> Option<usize> {
    if uuid.is_empty() {
        return None;
    }
    state.upgrade.nodes.iter().position(|n| n.uuid == uuid)
}

fn count(state: &HubState, st: UpgradeNodeState, kind: Option<UpgradeNodeKind>) -> usize {
    state
        .upgrade
        .nodes
        .iter()
        .filter(|n| n.state == st && kind.is_none_or(|k| n.kind == k))
        .count()
}

fn find_client(state: &HubState, uuid: &str, typ: ClientType) -> Option<usize> {
    state
        .clients
        .iter()
        .position(|c| c.typ == typ && c.authenticated && c.id == uuid)
}

/// The uuid a peer hub knows ITSELF by.  A peer connection's `id` is the
/// peer's FRIENDLY NAME — that is what the roster, the logs and hub_admin show
/// — while every upgrade frame a peer sends is keyed by its hub uuid.  The two
/// have to be bridged, or the driver never matches a peer's own
/// `CMD_UPGRADE_READY` to the node it created for it and files the answer as a
/// brand-new bot.  Empty when the connection is not a known peer.
pub fn peer_uuid_of(state: &HubState, ci: usize) -> String {
    let fd = state.clients[ci].fd;
    state
        .peers
        .iter()
        .find(|p| p.connected && p.fd == fd)
        .map(|p| p.uuid.clone())
        .unwrap_or_default()
}

/// The peer connection belonging to a hub uuid (the inverse of the above).
pub fn find_client_hub(state: &HubState, uuid: &str) -> Option<usize> {
    if uuid.is_empty() {
        return None;
    }
    let fd = state
        .peers
        .iter()
        .find(|p| p.connected && p.uuid == uuid)
        .map(|p| p.fd)?;
    state
        .clients
        .iter()
        .position(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == fd)
}

/// Strip '|' and control bytes: reasons come back from nodes and travel on
/// through a '|'-delimited status frame into an admin's terminal.
fn clean(src: &str, cap: usize) -> String {
    let out: String = src
        .chars()
        .map(|c| match c {
            '|' => '/',
            c if (c as u32) < 0x20 || c == '\u{7f}' => ' ',
            c => c,
        })
        .collect();
    trunc_string(&out, cap)
}

// ---------------------------------------------------------------------------
// Run lifecycle
// ---------------------------------------------------------------------------

/// End the run: lift the freeze and record why it stopped.  The table stays
/// behind so `CMD_ADMIN_UPGRADE_STATUS` can still explain what happened.
fn finish(state: &mut HubState, phase: UpgradePhase, summary: &str) {
    // Keep the plan of a run that actually got somewhere: a node that was down
    // or homed elsewhere while it went through is walked up to this target
    // when it comes back (see the roll-up below).  An aborted run left the
    // mesh where it was, so there is nothing to catch up to.
    if phase == UpgradePhase::Done {
        state.rollup.have_plan = true;
        state.rollup.target = state.upgrade.target_ver.clone();
        state.rollup.variant = state.upgrade.variant.clone();
        state.rollup.kind = state.upgrade.kind.clone();
        state.rollup.min_from = state.upgrade.min_from.clone();
        state.rollup.base = state.upgrade.base.clone();
        state.rollup.hub_target = state.upgrade.hub_ver.clone();
        state.rollup.hub_base = state.upgrade.hub_base.clone();
        state.rollup.plan_set = now();
        state.rollup_tries.clear();
        crate::config::write(state); // the plan survives a restart (Task 13)
    } else if phase == UpgradePhase::Aborted {
        state.rollup.have_plan = false;
        crate::config::write(state);
    }
    state.upgrade.active = false;
    state.upgrade.phase = phase;
    state.upgrade.summary = clean(summary, 192);
    opt_flag_set(state, OPT_CONFIG_FROZEN, false);
    crate::hlog_info!(
        "[UPGRADE] Run {} {}: {}\n",
        state.upgrade.id,
        phase.name(),
        state.upgrade.summary
    );
}

/// Tell every node that already moved (or is moving) to go back, then end the
/// run.  Rolling the finished nodes back too is the point: a half-upgraded
/// mesh is worse than one that never started.
pub fn abort(state: &mut HubState, reason: &str) {
    let id = state.upgrade.id.clone();
    let clean_reason = clean(reason, 160);
    // Local bots get a plain id|reason ABORT.
    let msg = format!("{id}|{clean_reason}");
    let targets: Vec<(String, UpgradeNodeKind, String)> = state
        .upgrade
        .nodes
        .iter()
        .filter(|n| n.state == UpgradeNodeState::Committed || n.state == UpgradeNodeState::Done)
        .map(|n| (n.uuid.clone(), n.kind, n.via.clone()))
        .collect();

    let mut told = 0;
    for (uuid, kind, via) in targets {
        match kind {
            // A node below a peer hub: send that peer an id|uuid|reason
            // frame.  Each hop relays it on, and the last one turns it into
            // the plain id|reason ABORT its local bot understands.
            _ if !via.is_empty() && kind != UpgradeNodeKind::SelfHub => {
                let relay = format!("{id}|{uuid}|{clean_reason}");
                if let Some(ci) = find_client_hub(state, &via)
                    && queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_ABORT, &relay)
                {
                    told += 1;
                }
            }
            UpgradeNodeKind::Bot => {
                if let Some(ci) = find_client(state, &uuid, ClientType::Bot)
                    && client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_ABORT, &msg)
                {
                    told += 1;
                }
            }
            UpgradeNodeKind::PeerHub => {
                // Peer hub as a self-node: id||reason (empty uuid = "you").
                let relay = format!("{id}||{clean_reason}");
                if let Some(ci) = find_client_hub(state, &uuid)
                    && queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_ABORT, &relay)
                {
                    told += 1;
                }
            }
            UpgradeNodeKind::SelfHub => {}
        }
    }
    crate::hlog_info!(
        "[UPGRADE] Abort {} sent to {} node(s): {}\n",
        state.upgrade.id,
        told,
        reason
    );
    finish(state, UpgradePhase::Aborted, reason);
}

/// The version a node of this run is being moved to: the bots' target for a
/// bot, the hubs' own for a hub.  Never mixed — the two are separate products
/// on separate version lines.
fn node_target(u: &crate::state::PendingUpgrade, ni: usize) -> &str {
    if u.nodes[ni].kind == UpgradeNodeKind::Bot {
        &u.target_ver
    } else {
        &u.hub_ver
    }
}

/// Send one node its `CMD_UPGRADE_COMMIT`.  A node that dropped off in the
/// meantime is marked unable rather than failing the run — Task 7 rolls it up
/// when it reconnects.
fn commit_node(state: &mut HubState, ni: usize) -> bool {
    let ver = node_target(&state.upgrade, ni).to_string();
    let payload = format!("{}|{}|{}", state.upgrade.id, ver, state.upgrade.variant);
    let (uuid, kind, via) = (
        state.upgrade.nodes[ni].uuid.clone(),
        state.upgrade.nodes[ni].kind,
        state.upgrade.nodes[ni].via.clone(),
    );
    let sent = match kind {
        // A node somewhere below a peer hub — a bot homed on it, or a hub
        // further out in the mesh.  Route COMMIT through that peer, naming
        // the node in a 4th field; each hop either recognises the uuid
        // (itself or one of its own bots) or forwards the frame on along the
        // route it learned at PREPARE time.
        _ if !via.is_empty() && kind != UpgradeNodeKind::SelfHub => {
            let relay = format!("{payload}|{uuid}");
            find_client_hub(state, &via).is_some_and(|ci| {
                queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_COMMIT, &relay)
            })
        }
        UpgradeNodeKind::Bot => find_client(state, &uuid, ClientType::Bot).is_some_and(|ci| {
            client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_COMMIT, &payload)
        }),
        UpgradeNodeKind::PeerHub => find_client_hub(state, &uuid).is_some_and(|ci| {
            queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_COMMIT, &payload)
        }),
        // This hub is the last node of its own run, so there is no frame and
        // no ack: update::commit either does not return (the process is
        // replaced and the marker file carries the run into it) or it fails
        // here with nothing touched.  The freeze is lifted BEFORE the exec so
        // the network is not left frozen by a hub that never comes back.
        UpgradeNodeKind::SelfHub => return commit_self(state, ni),
    };
    let node = &mut state.upgrade.nodes[ni];
    if !sent {
        node.state = UpgradeNodeState::Unable;
        node.reason = "disconnected before commit".to_string();
        return false;
    }
    node.state = UpgradeNodeState::Committed;
    node.committed_at = now();
    crate::hlog_info!(
        "[UPGRADE] COMMIT {} -> {} ({})\n",
        state.upgrade.id,
        uuid,
        ver
    );
    true
}

/// Commit *this* hub, the last node of its own run.
fn commit_self(state: &mut HubState, ni: usize) -> bool {
    {
        let node = &mut state.upgrade.nodes[ni];
        node.state = UpgradeNodeState::Committed;
        node.committed_at = now();
    }
    crate::hlog_info!(
        "[UPGRADE] COMMIT {} -> this hub ({})\n",
        state.upgrade.id,
        state.upgrade.hub_ver
    );
    let done_msg = format!(
        "{} node(s) on {}; this hub is restarting onto it last",
        count(state, UpgradeNodeState::Done, None),
        state.upgrade.target_ver
    );
    finish(state, UpgradePhase::Done, &done_msg);

    let (id, ver, variant, base) = (
        state.upgrade.id.clone(),
        state.upgrade.hub_ver.clone(),
        state.upgrade.variant.clone(),
        state.upgrade.hub_base.clone(),
    );
    match update::commit(state, &id, &ver, &variant, &base) {
        Ok(()) => true, // unreachable: update::commit exec'd
        Err(e) => {
            // The other nodes are already on the target and the freeze is
            // lifted; only this hub stayed behind.  Say so in the summary
            // rather than leaving the run reading "done" with no explanation.
            let done = count(state, UpgradeNodeState::Done, None);
            {
                let node = &mut state.upgrade.nodes[ni];
                node.state = UpgradeNodeState::Failed;
                node.reason = e.clone();
            }
            state.upgrade.summary = clean(
                &format!("{done} node(s) upgraded, but this hub stayed on {HUB_VERSION}: {e}"),
                192,
            );
            state.upgrade.phase = UpgradePhase::Failed;
            crate::hlog_warning!("[UPGRADE] This hub could not take {ver}: {e}\n");
            false
        }
    }
}

/// hub_admin asked for a network upgrade.  Freeze the config, enumerate the
/// nodes and fan PREPARE out; the rolling plan itself runs on the maintenance
/// tick.  The returned string is what the admin console prints.
/// What `CMD_ADMIN_UPGRADE_NET` asked for, field by field.
pub struct StartArgs<'a> {
    pub target_ver: &'a str,
    pub variant: &'a str,
    pub kind: &'a str,
    pub min_from: &'a str,
    pub base: &'a str,
    pub hub_ver: &'a str,
    pub hub_base: &'a str,
}

pub fn start(state: &mut HubState, origin_fd: i32, a: &StartArgs) -> String {
    let StartArgs {
        target_ver,
        variant,
        kind,
        min_from,
        base,
        hub_ver,
        hub_base,
    } = *a;
    if state.upgrade.active {
        return format!(
            "ERROR: upgrade {} already running ({})",
            state.upgrade.id,
            state.upgrade.phase.name()
        );
    }
    if target_ver.is_empty() || target_ver.len() >= 64 {
        return "ERROR: bad target version".to_string();
    }
    // The base travels to every node and ends up in a shell-free download
    // path there, but reject the obvious shapes here rather than at each node.
    if !base.is_empty()
        && (base.len() >= 512 || base.contains([';', '|', '&', '`', '$', ' ', '\t', '\r', '\n']))
    {
        return "ERROR: bad manifest base".to_string();
    }
    if hub_ver.len() >= 64 || hub_ver.contains(['|', ';', '&', '`', '$', ' ', '\t', '\r', '\n']) {
        return "ERROR: bad hub target version".to_string();
    }
    if !hub_base.is_empty()
        && (hub_ver.is_empty()
            || hub_base.len() >= 512
            || hub_base.contains([';', '|', '&', '`', '$', ' ', '\t', '\r', '\n']))
    {
        return "ERROR: bad hub manifest base".to_string();
    }

    // Seed the PREPARE seen-ring: our own PREPARE coming back to us around a
    // cycle of peers is then dropped silently instead of being answered.
    let run_id = opflow::generate_request_id();
    opflow::forward_seen_check_and_add(state, &run_id);
    let u = &mut state.upgrade;
    *u = crate::state::PendingUpgrade {
        active: true,
        id: run_id,
        target_ver: target_ver.to_string(),
        variant: variant.to_string(),
        kind: kind.to_string(),
        min_from: if min_from.is_empty() {
            "*".to_string()
        } else {
            min_from.to_string()
        },
        base: base.to_string(),
        hub_ver: hub_ver.to_string(),
        hub_base: hub_base.to_string(),
        origin_fd,
        started: now(),
        phase_started: now(),
        phase: UpgradePhase::Prepare,
        nodes: Vec::new(),
        last_added: now(),
        ready_seq_next: 0,
        summary: String::new(),
    };

    // Freeze first: a config change that lands between PREPARE and the last
    // COMMIT would reach half the mesh on one build and half on another.
    opt_flag_set(state, OPT_CONFIG_FROZEN, true);

    let prepare = format!(
        "{}|{}|{}|{}|{}|{}",
        state.upgrade.id,
        state.upgrade.target_ver,
        state.upgrade.variant,
        state.upgrade.kind,
        state.upgrade.min_from,
        state.upgrade.base
    );
    // Two shapes of the same PREPARE.  A bot gets the six fields it has
    // always read; a peer hub also needs the hubs' own target and base,
    // appended so the bot prefix stays byte-identical and a follower can
    // relay it on.
    let prepare_peer = format!(
        "{prepare}|{}|{}",
        state.upgrade.hub_ver, state.upgrade.hub_base
    );

    let roster: Vec<(usize, String, ClientType, String)> = state
        .clients
        .iter()
        .enumerate()
        .filter(|(_, c)| c.authenticated && c.typ != ClientType::Admin)
        .map(|(i, c)| (i, c.id.clone(), c.typ, c.bot_version.clone()))
        .collect();
    // A peer hub's node is keyed by its OWN hub uuid — that is what its READY
    // and RESULT carry — with the friendly name kept for display only.
    let roster: Vec<(usize, String, String, ClientType, String)> = roster
        .into_iter()
        .map(|(i, id, typ, ver)| {
            let key = if typ == ClientType::Hub {
                peer_uuid_of(state, i)
            } else {
                id.clone()
            };
            (i, key, id, typ, ver)
        })
        .collect();

    let (mut bots, mut peers) = (0usize, 0usize);
    for (ci, key, name, typ, ver) in roster {
        if state.upgrade.nodes.len() >= MAX_UPGRADE_NODES {
            break;
        }
        match typ {
            ClientType::Bot => {
                let fd = state.clients[ci].fd;
                let delivered =
                    client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &prepare);
                state.upgrade.nodes.push(UpgradeNode {
                    uuid: key,
                    kind: UpgradeNodeKind::Bot,
                    fd,
                    cur_version: ver,
                    state: if delivered {
                        UpgradeNodeState::Pending
                    } else {
                        UpgradeNodeState::Unable
                    },
                    reason: if delivered {
                        String::new()
                    } else {
                        "could not deliver PREPARE".to_string()
                    },
                    ..UpgradeNode::default()
                });
                state.upgrade.last_added = now();
                if delivered {
                    bots += 1;
                }
            }
            ClientType::Hub => {
                // No version to seed: a peer's version lives on PeerConfig,
                // not on the connection.  Its READY ack carries the
                // authoritative one.
                if key.is_empty() {
                    crate::hlog_warning!(
                        "[UPGRADE] Peer {} has no uuid yet — left out of run {}\n",
                        name,
                        state.upgrade.id
                    );
                    continue;
                }
                let fd = state.clients[ci].fd;
                let delivered =
                    queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &prepare_peer);
                state.upgrade.nodes.push(UpgradeNode {
                    uuid: key,
                    name,
                    kind: UpgradeNodeKind::PeerHub,
                    fd,
                    state: if delivered {
                        UpgradeNodeState::Pending
                    } else {
                        UpgradeNodeState::Unable
                    },
                    reason: if delivered {
                        String::new()
                    } else {
                        "could not deliver PREPARE".to_string()
                    },
                    ..UpgradeNode::default()
                });
                state.upgrade.last_added = now();
                if delivered {
                    peers += 1;
                }
            }
            ClientType::Admin => {}
        }
    }
    // This hub goes last, and answers its own PREPARE without a round trip.
    let (self_state, self_reason) = if state.upgrade.hub_ver.is_empty() {
        (
            UpgradeNodeState::Unable,
            "no hub target in this run".to_string(),
        )
    } else {
        match update::can_take(
            &state.upgrade.hub_ver,
            &state.upgrade.min_from,
            &state.upgrade.hub_base,
        ) {
            Ok(()) => (UpgradeNodeState::Ready, String::new()),
            Err(why) => (UpgradeNodeState::Unable, why),
        }
    };
    state.upgrade.nodes.push(UpgradeNode {
        uuid: state.hub_uuid.clone(),
        kind: UpgradeNodeKind::SelfHub,
        fd: -1,
        cur_version: HUB_VERSION.to_string(),
        variant: update::host_variant().to_string(),
        arch: update::host_arch(),
        libc: update::host_libc(),
        state: self_state,
        reason: self_reason,
        ..UpgradeNode::default()
    });
    state.upgrade.last_added = now();

    crate::hlog_info!(
        "[UPGRADE] Run {} -> {}: PREPARE to {} bot(s) and {} peer hub(s); this hub is {}\n",
        state.upgrade.id,
        state.upgrade.target_ver,
        bots,
        peers,
        self_state.name()
    );
    format!(
        "OK:upgrade {} started for {} — {} bot(s) and {} peer hub(s) asked to prepare, this hub \
         last; config frozen until it finishes",
        state.upgrade.id, state.upgrade.target_ver, bots, peers
    )
}

// ---------------------------------------------------------------------------
// Inbound frames
// ---------------------------------------------------------------------------

/// `CMD_UPGRADE_READY`: `id|uuid|cur_ver|variant|arch|libc|ready|reason`
pub fn note_ready(state: &mut HubState, payload: &str, from_peer: Option<&str>) {
    let f: Vec<&str> = payload.splitn(9, '|').collect();
    if f.len() < 7 {
        crate::hlog_warning!("[UPGRADE] Malformed UPGRADE_READY\n");
        return;
    }
    let (id, uuid) = (f[0], f[1]);
    if rollup_note_ready(state, payload) {
        return;
    }
    if !state.upgrade.active || state.upgrade.id != id {
        crate::hlog_debug!(
            "[UPGRADE] READY for unknown run {} from {} — ignoring\n",
            id,
            uuid
        );
        return;
    }
    let ni = match find_node(state, uuid) {
        Some(ni) => {
            // Learned locally first, then forwarded: remember the route.
            if let Some(via) = from_peer
                && state.upgrade.nodes[ni].via.is_empty()
                && state.upgrade.nodes[ni].kind != UpgradeNodeKind::SelfHub
            {
                state.upgrade.nodes[ni].via = via.to_string();
            }
            ni
        }
        None => {
            // A READY the origin has not seen this uuid for, forwarded up a
            // peer link, is a node somewhere in that peer's subtree — a bot
            // homed on it, or a hub further out in the mesh, which says so in
            // the trailing kind field.  Add it as a remote node reached
            // through the peer so the rolling plan drives it and STATUS
            // accounts for it network-wide.
            let Some(via) = from_peer else {
                crate::hlog_warning!("[UPGRADE] READY from {} which is not in run {}\n", uuid, id);
                return;
            };
            if state.upgrade.nodes.len() >= MAX_UPGRADE_NODES {
                crate::hlog_warning!("[UPGRADE] No room for remote node {} in run {}\n", uuid, id);
                return;
            }
            let kind = if f.get(8).copied().unwrap_or("") == "h" {
                UpgradeNodeKind::PeerHub
            } else {
                UpgradeNodeKind::Bot
            };
            state.upgrade.nodes.push(UpgradeNode {
                uuid: uuid.to_string(),
                kind,
                via: via.to_string(),
                fd: -1,
                ..UpgradeNode::default()
            });
            state.upgrade.last_added = now();
            state.upgrade.nodes.len() - 1
        }
    };
    let reason = clean(f.get(7).copied().unwrap_or(""), 128);
    if state.upgrade.nodes[ni].ready_seq == 0 {
        state.upgrade.ready_seq_next += 1;
        state.upgrade.nodes[ni].ready_seq = state.upgrade.ready_seq_next;
    }
    let node = &mut state.upgrade.nodes[ni];
    // Explicit truncation: a version longer than the roster field is cut on
    // purpose, exactly as the presence path cuts it for the tree.
    node.cur_version = trunc_string(f[2], ROSTER_VERSION_MAX + 1);
    node.variant = trunc_string(f[3], 8);
    node.arch = trunc_string(f[4], 32);
    node.libc = trunc_string(f[5], 16);
    node.reason = reason;
    node.state = if f[6] == "1" {
        UpgradeNodeState::Ready
    } else {
        UpgradeNodeState::Unable
    };
    if node.kind == UpgradeNodeKind::PeerHub
        && let Some(rel) = f.get(9).and_then(|v| v.parse::<usize>().ok())
    {
        node.relayed = if rel <= MAX_UPGRADE_NODES { rel } else { 0 };
    }
    crate::hlog_debug!(
        "[UPGRADE] {} is {} ({} {}/{}){}{}\n",
        uuid,
        node.state.name(),
        node.cur_version,
        node.arch,
        node.libc,
        if node.reason.is_empty() { "" } else { ": " },
        node.reason
    );
}

/// A local bot's `CMD_UPGRADE_READY`/`RESULT`.  If this hub is following a run
/// another hub drives and the frame belongs to it, the bot is a node of that
/// run reached through us — forward the frame up to the driver unchanged so it
/// records the bot as a remote node.  Otherwise it belongs to a run this hub
/// drives itself (or none), and is noted locally.
pub fn bot_report(state: &mut HubState, cmd: u8, payload: &str) {
    let id = payload.split('|').next().unwrap_or("");
    if !state.follow_id.is_empty() && !id.is_empty() && state.follow_id == id {
        let origin = state.follow_origin.clone();
        if let Some(oi) = find_client_hub(state, &origin) {
            queue::send_urgent(&mut state.clients[oi], cmd, payload);
            return;
        }
        // Driver gone: fall through and note it locally so nothing is lost.
    }
    if cmd == CMD_UPGRADE_READY {
        note_ready(state, payload, None);
    } else {
        note_result(state, payload);
    }
}

/// `CMD_UPGRADE_RESULT`: `id|uuid|status|version|detail`
pub fn note_result(state: &mut HubState, payload: &str) {
    let f: Vec<&str> = payload.splitn(5, '|').collect();
    if f.len() < 4 {
        crate::hlog_warning!("[UPGRADE] Malformed UPGRADE_RESULT\n");
        return;
    }
    let (id, uuid, status) = (f[0], f[1], f[2]);
    if rollup_note_result(state, payload) {
        return;
    }
    if state.upgrade.id != id {
        return;
    }
    let Some(ni) = find_node(state, uuid) else {
        return;
    };
    let detail = clean(f.get(4).copied().unwrap_or(""), 128);
    let node = &mut state.upgrade.nodes[ni];
    node.cur_version = trunc_string(f[3], ROSTER_VERSION_MAX + 1);
    node.reason = detail;
    node.state = match status {
        "ok" => UpgradeNodeState::Done,
        // "aborted" is the answer to our own ABORT; the run is already over.
        _ => UpgradeNodeState::Failed,
    };
    if node.state == UpgradeNodeState::Failed && node.reason.is_empty() {
        node.reason = status.to_string();
    }
    crate::hlog_debug!(
        "[UPGRADE] {} reports {} ({}){}{}\n",
        uuid,
        status,
        node.cur_version,
        if node.reason.is_empty() { "" } else { ": " },
        node.reason
    );
}

/// A bot that just announced its version may be a committed node coming back
/// on the new build — that, not the RESULT frame, is the authoritative signal
/// (the RESULT can be lost, the presence cannot: without it the bot is not on
/// the mesh at all).
pub fn note_presence(state: &mut HubState, uuid: &str, version: &str) {
    if !state.upgrade.active || state.upgrade.phase != UpgradePhase::Rolling {
        return;
    }
    let Some(ni) = find_node(state, uuid) else {
        return;
    };
    if state.upgrade.nodes[ni].state != UpgradeNodeState::Committed {
        return;
    }
    let target = node_target(&state.upgrade, ni).to_string();
    let node = &mut state.upgrade.nodes[ni];
    node.cur_version = trunc_string(version, ROSTER_VERSION_MAX + 1);
    if version == target {
        node.state = UpgradeNodeState::Done;
        crate::hlog_info!("[UPGRADE] {} is back on {}\n", uuid, version);
    }
}

// ---------------------------------------------------------------------------
// Offline roll-up
// ---------------------------------------------------------------------------
// A node that was down, or homed on a hub the run never reached, comes back on
// the old build.  Rather than making an admin notice and re-run the whole
// thing, the hub walks that ONE node up to the last completed run's target on
// its own: a single-node PREPARE/COMMIT, no config freeze (a late bot is not a
// reason to hold the whole network's config still) and a hard retry bound, or
// a node that cannot take the build is re-committed on every reconnect.  When
// the node sits below the target's min_from_version the walk is taken one
// release at a time, reading the steps out of the manifest.

/// Drop the roll-up plan (and any attempt in flight) from memory and from
/// .irchub.cnf.  Returns true when there was a plan to drop.
pub fn rollup_forget(state: &mut HubState, why: &str) -> bool {
    rollup_end(state, why, false);
    let had = state.rollup.have_plan;
    if had {
        crate::hlog_info!(
            "[ROLLUP] Plan {} (hubs {}) dropped: {}\n",
            state.rollup.target,
            if state.rollup.hub_target.is_empty() {
                "-"
            } else {
                &state.rollup.hub_target
            },
            why
        );
    }
    state.rollup = crate::state::PendingRollup::default();
    state.rollup_tries.clear();
    if had {
        crate::config::write(state);
    }
    had
}

/// The admin's "forget": drop our plan and flood CMD_UPGRADE_FORGET so every
/// other hub drops its copy.  Returns the admin reply.
pub fn admin_forget(state: &mut HubState) -> String {
    if state.upgrade.active || config_frozen(state) {
        return "ERROR: an upgrade is running — the plan is kept until it ends (abort it first)"
            .to_string();
    }
    let had = state.rollup.have_plan.then(|| state.rollup.target.clone());
    rollup_forget(state, "forgotten by admin");
    let id = opflow::generate_request_id();
    opflow::forward_seen_check_and_add(state, &id);
    let fwd = format!("{id}|{}", now());
    let mut told = 0;
    for ci in state.peer_clients() {
        if queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_FORGET, &fwd) {
            told += 1;
        }
    }
    match had {
        Some(t) => format!(
            "OK:roll-up plan {t} forgotten on this hub; told {told} peer hub(s) to drop theirs"
        ),
        None => format!("OK:no roll-up plan on this hub; told {told} peer hub(s) to drop theirs"),
    }
}

/// CMD_UPGRADE_FORGET from a peer: drop our plan and pass it on.
pub fn peer_forget(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.split('|').collect();
    if f.len() < 2 || f[0].is_empty() || f[0].len() >= 64 || !plan_field_ok(f[0]) {
        let ip = state.clients[ci].ip.clone();
        crate::hlog_warning!("[ROLLUP] Malformed UPGRADE_FORGET from peer {ip}\n");
        return;
    }
    let ts = crate::cstr::atoll(f[1]);
    let age = now() - ts;
    if ts <= 0 || !(-UPGRADE_FORGET_TTL..=UPGRADE_FORGET_TTL).contains(&age) {
        return;
    }
    if opflow::forward_seen_check_and_add(state, f[0]) {
        return;
    }
    // A plan is never dropped under a run: the freeze is replicated, so every
    // hub sees the same answer the admin's own hub gave.
    if !state.upgrade.active && !config_frozen(state) {
        rollup_forget(state, "forgotten by an admin on another hub");
    }
    for pi in state.peer_clients() {
        if pi != ci {
            queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_FORGET, payload);
        }
    }
}

/// End the attempt in flight and charge it to the node's ledger.
fn rollup_end(state: &mut HubState, why: &str, charge: bool) {
    if !state.rollup.active {
        return;
    }
    if charge {
        let uuid = state.rollup.uuid.clone();
        if let Some(t) = state.rollup_tries.iter_mut().find(|t| t.uuid == uuid) {
            t.tries += 1;
            t.last_try = now();
        } else {
            // The ledger is a bound, not a record: drop the oldest attempt so
            // a long-lived hub keeps rolling recent arrivals up.
            if state.rollup_tries.len() >= MAX_ROLLUP_TRIES {
                state.rollup_tries.remove(0);
            }
            state.rollup_tries.push(RollupTry {
                uuid,
                last_try: now(),
                tries: 1,
            });
        }
    }
    crate::hlog_info!(
        "[ROLLUP] {} -> {}: {}\n",
        state.rollup.uuid,
        state.rollup.step,
        why
    );
    state.rollup.active = false;
    state.rollup.committed = false;
    state.rollup.id.clear();
    state.rollup.uuid.clear();
    state.rollup.step.clear();
}

/// Is this uuid a node worth catching up, and may we try it now?
/// True when `s` may be one field of an upgrade plan: no '|', no line break,
/// no shell metacharacter or blank, and short enough for any plan field.  The
/// same rule gates what a follower accepts at PREPARE and what the `rollup|`
/// config line carries, so a peer can never split or inject a config line.
pub fn plan_field_ok(s: &str) -> bool {
    s.len() < 512 && !s.contains(['|', ';', '&', '`', '$', ' ', '\t', '\r', '\n'])
}

/// A roll-up only chases a target the mesh is demonstrably running: some bot
/// other than the one being considered announces it — locally, or through
/// the presence gossip.  A follower learns the plan at PREPARE, before it can
/// know how the run ends, and only committed nodes are told of an abort;
/// without this gate an aborted run's target (a bad artifact, say) would be
/// chased by every follower the moment the freeze lifted, and — now that the
/// plan is persisted — again after every restart.  An aborted run leaves no
/// bot on its target (they roll back, or never installed it), so nothing is
/// chased.
fn rollup_target_proven(state: &HubState, target: &str, except: &str) -> bool {
    state.clients.iter().any(|c| {
        c.typ == ClientType::Bot && c.authenticated && c.id != except && c.bot_version == target
    }) || state
        .roster
        .iter()
        .any(|e| e.bot_uuid != except && e.version == target)
}

fn rollup_may_try(state: &HubState, uuid: &str, version: &str) -> bool {
    let r = &state.rollup;
    if !r.have_plan || r.active || state.upgrade.active {
        return false;
    }
    // The freeze is the mesh-wide "a run is in flight" signal: it is set at
    // PREPARE, replicated with the rest of the opt record, and lifted when the
    // run ends.  A follower learns a run finished from it — nothing else tells
    // it — and neither end may chase a straggler while it holds.
    if config_frozen(state) {
        return false;
    }
    if uuid.is_empty() || version.is_empty() {
        return false;
    }
    if update::version_cmp(version, &r.target) != std::cmp::Ordering::Less {
        return false;
    }
    if !rollup_target_proven(state, &r.target, uuid) {
        return false;
    }
    let t_now = now();
    if t_now - r.plan_set < ROLLUP_SETTLE {
        return false;
    }
    match state.rollup_tries.iter().find(|t| t.uuid == uuid) {
        None => true,
        Some(t) => t.tries < ROLLUP_MAX_TRIES && t_now - t.last_try >= ROLLUP_COOLDOWN,
    }
}

/// A node announced a version older than the last completed run's target.
/// Start a single-node PREPARE for the next step it can take.
fn rollup_consider(state: &mut HubState, uuid: &str, node_kind: UpgradeNodeKind, version: &str) {
    if !rollup_may_try(state, uuid, version) {
        return;
    }

    // Stepping: when the node is below the target's min_from it cannot jump
    // straight there, so ask the manifest for the highest release it may take
    // from where it is.  A manifest this hub cannot read (no key, no network)
    // is not fatal — aim straight at the target and let the node's own updater
    // refuse if it must.
    let (base, variant, target) = (
        state.rollup.base.clone(),
        state.rollup.variant.clone(),
        state.rollup.target.clone(),
    );
    let step = match update::next_step(&base, &variant, version, &target) {
        Ok(v) => v,
        Err(why) => {
            crate::hlog_info!("[ROLLUP] No step read for {uuid} ({why}); aiming at {target}\n");
            target.clone()
        }
    };

    let id = opflow::generate_request_id();
    state.rollup.active = true;
    state.rollup.committed = false;
    state.rollup.node_kind = node_kind;
    state.rollup.id = id.clone();
    state.rollup.uuid = uuid.to_string();
    state.rollup.step = step.clone();
    state.rollup.started = now();

    // min_from is "*": the step was already chosen against the manifest, and a
    // second check at the node would only re-answer the same question.
    let kind = state.rollup.kind.clone();
    let prepare = format!("{id}|{step}|{variant}|{kind}|*|{base}");
    // Local bots only (see the peer-gossip presence hook): a roll-up PREPARE
    // sent to a peer hub would be taken for a run's and fanned mesh-wide.
    let sent = node_kind == UpgradeNodeKind::Bot
        && find_client(state, uuid, ClientType::Bot).is_some_and(|ci| {
            client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &prepare)
        });
    if !sent {
        rollup_end(state, "could not deliver PREPARE", true);
        return;
    }
    crate::hlog_info!(
        "[ROLLUP] {uuid} is on {version}, the network is on {target}: PREPARE {id} -> {step}\n"
    );
}

/// `CMD_UPGRADE_READY` carrying a roll-up id.  Returns true when it was one.
fn rollup_note_ready(state: &mut HubState, payload: &str) -> bool {
    let f: Vec<&str> = payload.splitn(9, '|').collect();
    let id = f.first().copied().unwrap_or("");
    if !state.rollup.active || id.is_empty() || state.rollup.id != id {
        return false;
    }
    if f.get(1).copied().unwrap_or("") != state.rollup.uuid {
        return true; // not the node we asked
    }
    if f.get(6).copied().unwrap_or("") != "1" {
        let why = f.get(7).copied().unwrap_or("");
        let why = if why.is_empty() {
            "node cannot take it".to_string()
        } else {
            why.to_string()
        };
        rollup_end(state, &why, true);
        return true;
    }

    let (id, step, variant, uuid) = (
        state.rollup.id.clone(),
        state.rollup.step.clone(),
        state.rollup.variant.clone(),
        state.rollup.uuid.clone(),
    );
    let commit = format!("{id}|{step}|{variant}");
    let sent = find_client(state, &uuid, ClientType::Bot).is_some_and(|ci| {
        client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_COMMIT, &commit)
    });
    if !sent {
        rollup_end(state, "disconnected before commit", true);
        return true;
    }
    state.rollup.committed = true;
    state.rollup.started = now();
    crate::hlog_info!("[ROLLUP] COMMIT {id} -> {uuid} ({step})\n");
    true
}

/// `CMD_UPGRADE_RESULT` carrying a roll-up id.  Returns true when it was one.
fn rollup_note_result(state: &mut HubState, payload: &str) -> bool {
    let f: Vec<&str> = payload.splitn(5, '|').collect();
    let id = f.first().copied().unwrap_or("");
    if !state.rollup.active || id.is_empty() || state.rollup.id != id {
        return false;
    }
    let status = f.get(2).copied().unwrap_or("");
    let detail = f.get(4).copied().unwrap_or("");
    if status == "ok" {
        rollup_end(state, "node reports it installed the step", false);
    } else {
        rollup_end(state, if detail.is_empty() { status } else { detail }, true);
    }
    true
}

/// A node's presence is the authoritative signal here too: it came back on the
/// step, so this attempt succeeded and the NEXT one (if the target is further
/// on) may start straight away.
pub fn rollup_note_presence(
    state: &mut HubState,
    uuid: &str,
    node_kind: UpgradeNodeKind,
    version: &str,
) {
    if state.rollup.active
        && state.rollup.uuid == uuid
        && !version.is_empty()
        && update::version_cmp(version, &state.rollup.step) != std::cmp::Ordering::Less
    {
        rollup_end(state, "back on the step it was given", false);
    }
    rollup_consider(state, uuid, node_kind, version);
}

/// Time out an attempt that went nowhere.  Runs on the maintenance clock.
fn rollup_tick(state: &mut HubState, t_now: i64) {
    if !state.rollup.active || t_now - state.rollup.started <= ROLLUP_TIMEOUT {
        return;
    }
    let why = if state.rollup.committed {
        "did not come back on the step in time"
    } else {
        "no answer to PREPARE"
    };
    rollup_end(state, why, true);
}

// ---------------------------------------------------------------------------
// The rolling plan
// ---------------------------------------------------------------------------

/// Relayed-bot READYs still owed: what the hub nodes said they relayed to,
/// less the remote bots already in the table.  Bounded by the PREPARE timeout
/// like every other wait.
fn relays_owed(u: &crate::state::PendingUpgrade) -> usize {
    let promised: usize = u
        .nodes
        .iter()
        .filter(|n| n.kind == UpgradeNodeKind::PeerHub)
        .map(|n| n.relayed)
        .sum();
    let seen = u
        .nodes
        .iter()
        .filter(|n| n.kind == UpgradeNodeKind::Bot && !n.via.is_empty())
        .count();
    promised.saturating_sub(seen)
}

/// One step per maintenance tick.  A no-op unless a run is active.
pub fn tick(state: &mut HubState, now_ts: i64) {
    rollup_tick(state, now_ts);
    if !state.upgrade.active {
        return;
    }

    if state.upgrade.phase == UpgradePhase::Prepare {
        let timed_out = now_ts - state.upgrade.phase_started > UPGRADE_PREPARE_TIMEOUT;
        if !timed_out
            && (count(state, UpgradeNodeState::Pending, None) > 0
                || relays_owed(&state.upgrade) > 0
                || now_ts - state.upgrade.last_added < UPGRADE_PREPARE_SETTLE)
        {
            return;
        }
        for n in &mut state.upgrade.nodes {
            if n.state == UpgradeNodeState::Pending {
                n.state = UpgradeNodeState::Unable;
                n.reason = "no answer to PREPARE".to_string();
            }
        }
        let ready = count(state, UpgradeNodeState::Ready, None);
        if ready == 0 {
            finish(state, UpgradePhase::Done, "no node needed the upgrade");
            return;
        }
        state.upgrade.phase = UpgradePhase::Rolling;
        state.upgrade.phase_started = now_ts;
        crate::hlog_info!(
            "[UPGRADE] Run {} rolling: {} node(s) ready\n",
            state.upgrade.id,
            ready
        );
        return;
    }

    if state.upgrade.phase != UpgradePhase::Rolling {
        return;
    }

    // A committed node that never came back fails the whole run: the rest of
    // the mesh must not keep marching onto a build that does not come up.
    let stalled = state.upgrade.nodes.iter().position(|n| {
        n.state == UpgradeNodeState::Committed && now_ts - n.committed_at > UPGRADE_COMMIT_TIMEOUT
    });
    if let Some(ni) = stalled {
        let target = node_target(&state.upgrade, ni).to_string();
        let uuid = state.upgrade.nodes[ni].uuid.clone();
        let node = &mut state.upgrade.nodes[ni];
        node.state = UpgradeNodeState::Failed;
        node.reason = format!("did not return on {target} in time");
        abort(state, &format!("{uuid} did not come back on {target}"));
        return;
    }
    if count(state, UpgradeNodeState::Failed, None) > 0 {
        abort(state, "a node reported the upgrade failed");
        return;
    }

    let mut in_flight = count(state, UpgradeNodeState::Committed, None);
    let ready_bots = count(state, UpgradeNodeState::Ready, Some(UpgradeNodeKind::Bot));

    if ready_bots > 0 {
        // Wave size: never more than a quarter of the bots this run touches,
        // and never more than UPGRADE_BOT_WAVE_MAX, so the channels a botnet
        // holds keep a quorum of bots up throughout.
        let touched = ready_bots
            + count(
                state,
                UpgradeNodeState::Committed,
                Some(UpgradeNodeKind::Bot),
            )
            + count(state, UpgradeNodeState::Done, Some(UpgradeNodeKind::Bot));
        let wave = (touched / UPGRADE_BOT_WAVE_DIVISOR).clamp(1, UPGRADE_BOT_WAVE_MAX);
        for ni in 0..state.upgrade.nodes.len() {
            if in_flight >= wave {
                break;
            }
            let n = &state.upgrade.nodes[ni];
            if n.state != UpgradeNodeState::Ready || n.kind != UpgradeNodeKind::Bot {
                continue;
            }
            if commit_node(state, ni) {
                in_flight += 1;
            }
        }
        return;
    }

    // Bots are settled.  Peer hubs go one at a time, and only once nothing is
    // mid-restart, so the mesh never drops below one reachable hub.
    //
    // Deepest first: a follower's run state (follow_id, its COMMIT routes) is
    // volatile, so a hub that restarts can no longer carry a COMMIT to the
    // hubs it routes for.  The latest READY is always from a hub no other
    // pending hub routes through (see `UpgradeNode::ready_seq`).  This hub
    // goes after every peer hub: it restarts last and its run table goes
    // with it.
    if in_flight > 0 {
        return;
    }
    let ready =
        |n: &UpgradeNode, k: UpgradeNodeKind| n.state == UpgradeNodeState::Ready && n.kind == k;
    let next_hub = state
        .upgrade
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| ready(n, UpgradeNodeKind::PeerHub))
        .max_by_key(|(_, n)| n.ready_seq)
        .map(|(i, _)| i)
        .or_else(|| {
            state
                .upgrade
                .nodes
                .iter()
                .position(|n| ready(n, UpgradeNodeKind::SelfHub))
        });
    if let Some(ni) = next_hub {
        commit_node(state, ni);
        return;
    }

    let done_msg = format!(
        "{} node(s) now on {}, {} could not take it",
        count(state, UpgradeNodeState::Done, None),
        state.upgrade.target_ver,
        count(state, UpgradeNodeState::Unable, None)
    );
    finish(state, UpgradePhase::Done, &done_msg);
}

// ---------------------------------------------------------------------------
// Follower side: this hub as a node of another hub's run
// ---------------------------------------------------------------------------
// Symmetrical to the bot handlers in ircbot.rs's hub_client, and reachable
// only on an authenticated peer link.  A hub is a follower and a driver at the
// same time — the mesh is flat — so the two halves are kept apart:
// `state.upgrade` holds the run THIS hub drives, while the `follow_*` fields
// are about a run someone else drives.

// ---- Follower routing table (UpgradeRoute) -------------------------------
// A run reaches every hub in the mesh, whatever topology it is wired in: a
// follower re-broadcasts PREPARE to its own peers and forwards their answers
// back toward the driver.  For that to work in reverse, each hop remembers
// which peer it heard a given node from; COMMIT and ABORT then walk the same
// tree back down.  Suppression is by run id: a hub joins a run exactly once,
// through the first peer that told it about the run, so a cycle in the peer
// graph cannot make the fan-out loop.

/// Remember (or refresh) "frames for `uuid` go out through `via`".
fn route_note(state: &mut HubState, uuid: &str, via: &str) {
    if uuid.is_empty() || via.is_empty() {
        return;
    }
    if let Some(r) = state.follow_routes.iter_mut().find(|r| r.uuid == uuid) {
        r.via = via.to_string();
        return;
    }
    if state.follow_routes.len() >= MAX_UPGRADE_ROUTES {
        crate::hlog_warning!("[UPGRADE] No room to route {uuid} — it stays out of the run\n");
        return;
    }
    state.follow_routes.push(UpgradeRoute {
        uuid: uuid.to_string(),
        via: via.to_string(),
    });
}

/// The next hop toward `uuid`, or `None` when this hub never saw it.
fn route_via(state: &HubState, uuid: &str) -> Option<String> {
    state
        .follow_routes
        .iter()
        .find(|r| r.uuid == uuid)
        .map(|r| r.via.clone())
}

/// `id|uuid|cur_ver|variant|arch|libc|ready|reason|kind|relayed`
fn answer_ready(
    state: &mut HubState,
    ci: usize,
    id: &str,
    ready: bool,
    reason: &str,
    relayed: usize,
) {
    let clean_reason = clean(reason, 192);
    // The trailing "h" is the node KIND.  A bot's READY stops at the reason,
    // so an absent field still means "bot" and ircbot is untouched; a hub
    // several hops from the driver has no other way to say what it is, and the
    // driver has to know to route its COMMIT back through the peer that
    // forwarded this.  clean() has already turned any '|' in the reason into
    // '/', so the field after it is unambiguous.  After the kind: how many
    // local bots this hub relayed the PREPARE to, so the driver waits for
    // their answers.
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|h|{}",
        id,
        state.hub_uuid,
        HUB_VERSION,
        update::host_variant(),
        update::host_arch(),
        update::host_libc(),
        if ready { 1 } else { 0 },
        clean_reason,
        relayed
    );
    queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_READY, &payload);
    crate::hlog_info!(
        "[UPGRADE] {} upgrade {id}{}{}\n",
        if ready { "Ready for" } else { "Cannot take" },
        if clean_reason.is_empty() { "" } else { ": " },
        clean_reason
    );
}

/// Report a result upstream on behalf of `uuid` — this hub itself, or a local
/// bot the driver reaches through it.
fn answer_result_uuid(
    state: &mut HubState,
    ci: usize,
    id: &str,
    uuid: &str,
    status: &str,
    detail: &str,
) {
    let payload = format!(
        "{}|{}|{}|{}|{}",
        id,
        uuid,
        status,
        HUB_VERSION,
        clean(detail, 192)
    );
    queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_RESULT, &payload);
}

/// `id|uuid|status|version|detail`
fn answer_result(state: &mut HubState, ci: usize, id: &str, status: &str, detail: &str) {
    let uuid = state.hub_uuid.clone();
    answer_result_uuid(state, ci, id, &uuid, status, detail);
}

/// `CMD_UPGRADE_PREPARE` from a peer: a capability question.  Nothing is
/// downloaded and nothing on disk is touched until COMMIT.
pub fn peer_prepare(state: &mut HubState, ci: usize, payload: &str) {
    // id|ver|variant|kind|min_from|base|hub_ver|hub_base — the bots' six
    // fields, then the hubs' own target and base (see start).
    let f: Vec<&str> = payload.splitn(8, '|').collect();
    if f.len() < 2 || f[0].is_empty() || f[1].is_empty() || f[0].len() > 63 || f[1].len() > 63 {
        crate::hlog_warning!(
            "[UPGRADE] Malformed UPGRADE_PREPARE from peer {}\n",
            state.clients[ci].ip
        );
        return;
    }
    let (id, ver) = (f[0].to_string(), f[1].to_string());
    let variant = f.get(2).copied().unwrap_or("").to_string();
    let min_from = f.get(4).copied().unwrap_or("").to_string();
    let base = f.get(5).copied().unwrap_or("").to_string();
    let hub_ver = f.get(6).copied().unwrap_or("").to_string();
    let hub_base = f.get(7).copied().unwrap_or("").to_string();
    // Every field lands in this hub's config (the persisted roll-up plan) and
    // in a download path, so a peer's PREPARE is held to the same shape the
    // driver enforced on its admin: nothing that could split a line.
    if !f.iter().all(|x| plan_field_ok(x)) {
        crate::hlog_warning!(
            "[UPGRADE] Malformed UPGRADE_PREPARE from peer {}\n",
            state.clients[ci].ip
        );
        return;
    }
    // Kept verbatim for the roll-up plan: `variant` is normalised to this
    // host's below, and f[3] (the artifact kind) is otherwise unused here —
    // it is chosen from the manifest at COMMIT.
    let variant_field = variant.clone();
    let kind_field = f.get(3).copied().unwrap_or("").to_string();

    // Loop suppression: a hub joins a run exactly ONCE, through the first peer
    // that told it about it.  Re-broadcasting means the same PREPARE arrives
    // again around every cycle in the peer graph; answering or relaying it a
    // second time would both duplicate the node and keep the frame circulating
    // forever.  Silence is the right answer — the driver already has ours.
    //
    // The id goes through the same seen-ring as OP_FORWARD, not a compare
    // against follow_id alone: follow_id holds ONE id and is cleared on abort,
    // refusal and expiry, so two runs in flight at once flip it back and forth
    // and a late copy after a clear is taken as new — either way the frames
    // circulate forever.  The driver seeds the ring with its own id at start,
    // so its PREPARE coming back around a cycle is dropped here too.
    if opflow::forward_seen_check_and_add(state, &id) {
        crate::hlog_debug!("[UPGRADE] PREPARE {id} already seen — not relaying it again\n");
        return;
    }

    // Refuse to be a follower while driving a run of our own: two plans
    // moving the same mesh is what the one-run-at-a-time rule prevents.
    if state.upgrade.active {
        answer_ready(
            state,
            ci,
            &id,
            false,
            "already driving an upgrade of its own",
            0,
        );
        return;
    }

    // f[3] is the artifact kind, chosen from the manifest at COMMIT.
    // Remember the plan whether or not this hub itself can take it: even a hub
    // that cannot upgrade must still relay the run to its own local bots and
    // carry their COMMITs, so `follow_*` is set unconditionally and
    // `follow_self_ready` records only whether the hub itself may commit.
    let (ready, why) = if hub_ver.is_empty() {
        (false, "no hub target in this run".to_string())
    } else {
        match update::can_take(&hub_ver, &min_from, &hub_base) {
            Ok(()) => (true, String::new()),
            Err(why) => (false, why),
        }
    };
    // Bots get the six fields they read, not the hubs' two on the end.
    let bot_prepare = format!(
        "{id}|{ver}|{variant}|{}|{min_from}|{base}",
        f.get(3).copied().unwrap_or("")
    );
    let origin = peer_uuid_of(state, ci);
    state.follow_id = id.clone();
    state.follow_origin = origin;
    state.follow_target = ver;
    state.follow_variant = if variant.is_empty() {
        update::host_variant().to_string()
    } else {
        variant
    };
    state.follow_hub_target = hub_ver;
    state.follow_hub_base = hub_base;
    state.follow_self_ready = ready;
    state.follow_prepared = now();
    state.follow_routes.clear();

    // Record the driver's plan as this hub's roll-up plan too.  A bot that was
    // down while the run went through reconnects to whichever hub it likes, so
    // every hub has to know what the network is supposed to be running; the
    // replicated config freeze is what keeps any of them from acting on it
    // before the run is over (see rollup_may_try).
    state.rollup.have_plan = true;
    state.rollup.target = state.follow_target.clone();
    state.rollup.variant = variant_field;
    state.rollup.kind = kind_field;
    state.rollup.min_from = if min_from.is_empty() {
        "*".to_string()
    } else {
        min_from.clone()
    };
    state.rollup.base = base;
    state.rollup.hub_target = state.follow_hub_target.clone();
    state.rollup.hub_base = state.follow_hub_base.clone();
    state.rollup.plan_set = now();
    state.rollup_tries.clear();
    crate::config::write(state); // the plan survives a restart (Task 13)

    // Fan PREPARE out to this hub's own local bots.  Each answers READY to us
    // (its hub); we forward that up to the origin, which records it as a
    // remote node reached through this hub.  That is what makes one run reach
    // a bot no matter which hub it is homed on.
    let bots: Vec<usize> = state
        .clients
        .iter()
        .enumerate()
        .filter(|(_, c)| c.typ == ClientType::Bot && c.authenticated)
        .map(|(i, _)| i)
        .collect();
    let mut relayed = 0;
    for bi in bots {
        if client::send_cmd_to_bot(&mut state.clients[bi], CMD_UPGRADE_PREPARE, &bot_prepare) {
            relayed += 1;
        }
    }
    if relayed > 0 {
        crate::hlog_info!(
            "[UPGRADE] Relayed PREPARE {} to {} local bot(s)\n",
            id,
            relayed
        );
    }

    // ...and on to this hub's OWN peers, minus the one it came from.  This is
    // what carries a run past the driver's immediate neighbours: every hub the
    // mesh can reach joins the run, whatever shape the peer links are wired in
    // (a chain, a star, a partial mesh).  Their answers come back to us and we
    // forward them up, so the driver sees one flat node table.
    let peers: Vec<usize> = state
        .clients
        .iter()
        .enumerate()
        .filter(|(i, c)| *i != ci && c.typ == ClientType::Hub && c.authenticated)
        .map(|(i, _)| i)
        .collect();
    let mut fanned = 0;
    for pi in peers {
        if queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_PREPARE, payload) {
            fanned += 1;
        }
    }
    if fanned > 0 {
        crate::hlog_info!("[UPGRADE] Re-broadcast PREPARE {id} to {fanned} peer hub(s)\n");
    }

    answer_ready(state, ci, &id, ready, &why, relayed);
}

/// A frame this hub is only relaying: an answer from somewhere below it in the
/// fan-out tree, on its way to the driver.  Returns true when it was handled
/// as a relay (route remembered, frame forwarded), false when the frame
/// belongs to a run this hub drives itself and should be noted locally.
pub fn relay_upstream(state: &mut HubState, ci: usize, cmd: u8, payload: &str) -> bool {
    let f: Vec<&str> = payload.splitn(3, '|').collect();
    let id = f.first().copied().unwrap_or("");
    let uuid = f.get(1).copied().unwrap_or("").to_string();
    if state.follow_id.is_empty() || id.is_empty() || state.follow_id != id {
        return false;
    }

    let from_uuid = peer_uuid_of(state, ci);
    // A frame coming DOWN from the driver's direction is not an answer to
    // relay; nothing below us is reached through the hop we answer to.
    if !from_uuid.is_empty() && from_uuid == state.follow_origin {
        return false;
    }

    if cmd == CMD_UPGRADE_READY {
        route_note(state, &uuid, &from_uuid);
    }

    let origin = state.follow_origin.clone();
    let Some(oi) = find_client_hub(state, &origin) else {
        crate::hlog_debug!(
            "[UPGRADE] Driver of {id} is gone — dropping a relayed answer for {uuid}\n"
        );
        return true;
    };
    queue::send_urgent(&mut state.clients[oi], cmd, payload);
    true
}

/// `CMD_UPGRADE_COMMIT` from a peer: go.  Only an id we acknowledged at
/// PREPARE, and only while that acknowledgement is still fresh, may commit.
pub fn peer_commit(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.splitn(4, '|').collect();
    if f.len() < 2 || f[0].is_empty() || f[1].is_empty() || f[0].len() > 63 || f[1].len() > 63 {
        crate::hlog_warning!(
            "[UPGRADE] Malformed UPGRADE_COMMIT from peer {}\n",
            state.clients[ci].ip
        );
        return;
    }
    let (id, ver) = (f[0].to_string(), f[1].to_string());
    let variant = f.get(2).copied().unwrap_or("").to_string();
    let target_uuid = f.get(3).copied().unwrap_or("").to_string();

    if state.follow_id.is_empty() || state.follow_id != id {
        answer_result(state, ci, &id, "fail", "no matching UPGRADE_PREPARE");
        return;
    }
    // The version must be one this run named: the bots' target for a frame
    // on its way to a bot, the hubs' own for this hub (checked again below).
    if state.follow_target != ver
        && (state.follow_hub_target.is_empty() || state.follow_hub_target != ver)
    {
        answer_result(
            state,
            ci,
            &id,
            "fail",
            "commit version differs from prepare",
        );
        return;
    }
    if now() - state.follow_prepared > UPGRADE_PREPARE_TTL {
        state.follow_id.clear();
        answer_result(state, ci, &id, "fail", "prepare expired");
        return;
    }

    // A 4th field names the node the driver is addressing.  It is one of three
    // things, in order: this hub, one of its local bots, or something further
    // out that this hub relayed an answer for at PREPARE time — in which case
    // the frame goes on, unchanged, along the route it learned.
    if !target_uuid.is_empty() && target_uuid != state.hub_uuid {
        if let Some(bi) = find_client(state, &target_uuid, ClientType::Bot) {
            let relay = format!("{id}|{ver}|{variant}");
            if !client::send_cmd_to_bot(&mut state.clients[bi], CMD_UPGRADE_COMMIT, &relay) {
                answer_result_uuid(
                    state,
                    ci,
                    &id,
                    &target_uuid,
                    "fail",
                    "bot not reachable through this hub",
                );
            }
            return;
        }
        let sent = route_via(state, &target_uuid)
            .and_then(|via| find_client_hub(state, &via))
            .is_some_and(|ni| {
                queue::send_urgent(&mut state.clients[ni], CMD_UPGRADE_COMMIT, payload)
            });
        if !sent {
            answer_result_uuid(
                state,
                ci,
                &id,
                &target_uuid,
                "fail",
                "no route to that node from this hub",
            );
        }
        return;
    }

    // No target uuid: this hub is the node being committed.
    if !state.follow_self_ready {
        answer_result(state, ci, &id, "fail", "this hub cannot take the upgrade");
        return;
    }
    if state.follow_hub_target != ver {
        answer_result(
            state,
            ci,
            &id,
            "fail",
            "commit version differs from prepare",
        );
        return;
    }

    let variant = if variant.is_empty() {
        state.follow_variant.clone()
    } else {
        variant
    };
    let base = state.follow_hub_base.clone();
    // On success update::commit does not return: the process is replaced and
    // report_pending() reports in after the restart.
    if let Err(e) = update::commit(state, &id, &ver, &variant, &base) {
        // Nothing was changed on disk; stay on this build and say why.
        crate::hlog_warning!("[UPGRADE] Commit {id} refused: {e}\n");
        answer_result(state, ci, &id, "fail", &e);
        state.follow_id.clear();
    }
}

/// `CMD_UPGRADE_ABORT` from a peer: put the retained build back.
pub fn peer_abort(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.splitn(3, '|').collect();
    let id = f.first().copied().unwrap_or("");
    let id = if id.is_empty() { "-" } else { id }.to_string();
    let uuid = f.get(1).copied().unwrap_or("").to_string();
    let raw_reason = f.get(2).copied().unwrap_or("");
    let reason = if raw_reason.is_empty() {
        "the upgrade was aborted".to_string()
    } else {
        clean(raw_reason, 192)
    };
    crate::hlog_info!(
        "[UPGRADE] Abort {id} from peer {}{}{}: {reason}\n",
        state.clients[ci].ip,
        if uuid.is_empty() { "" } else { " for bot " },
        uuid
    );

    // A named node that is not this hub: one of its local bots (which gets the
    // plain id|reason frame), or something further out, which the route
    // learned at PREPARE time carries the frame on to unchanged.  Either way
    // this hub's own follower state belongs to its own node and is left alone.
    if !uuid.is_empty() && uuid != state.hub_uuid {
        if let Some(bi) = find_client(state, &uuid, ClientType::Bot) {
            let relay = format!("{id}|{reason}");
            client::send_cmd_to_bot(&mut state.clients[bi], CMD_UPGRADE_ABORT, &relay);
            return;
        }
        if let Some(ni) = route_via(state, &uuid).and_then(|via| find_client_hub(state, &via)) {
            queue::send_urgent(&mut state.clients[ni], CMD_UPGRADE_ABORT, payload);
        }
        return;
    }

    state.follow_id.clear();
    state.follow_prepared = 0;
    state.follow_self_ready = false;
    state.follow_routes.clear();
    // A successful rollback execs; the driver sees the old version reappear.
    if !update::rollback(state, &reason) {
        answer_result(
            state,
            ci,
            &id,
            "aborted",
            "nothing retained to roll back to",
        );
    }
}

/// Called once per authenticated peer link.  If this process is the product of
/// an upgrade another hub drove, the marker left behind by `update::commit`
/// says which run it belongs to; report whether we came up on the version that
/// run was aiming at.  The driver also infers success from the roster gossip,
/// so a lost RESULT costs nothing.
pub fn report_pending(state: &mut HubState, ci: usize) {
    let Some((id, want)) = update::take_pending() else {
        return;
    };
    let ok = update::version_cmp(HUB_VERSION, &want) == std::cmp::Ordering::Equal;
    crate::hlog_warning!("[UPGRADE] Restarted after {id}: running {HUB_VERSION} (wanted {want})\n");
    let status = if ok { "ok" } else { "version-mismatch" };
    answer_result(state, ci, &id, status, if ok { "" } else { &want });
}

/// `CMD_ADMIN_UPGRADE_STATUS`: one line per node, for hub_admin to print.
pub fn status(state: &HubState) -> String {
    let u = &state.upgrade;
    // The roll-up plan this hub holds, if any: what a bot that comes back is
    // walked up to, until an admin's "forget" drops it.
    let r = &state.rollup;
    let plan = if r.have_plan {
        format!(
            "roll-up plan: bots -> {}{}{} (set {} s ago; \"forget\" drops it)\n",
            r.target,
            if r.hub_target.is_empty() {
                ""
            } else {
                ", hubs -> "
            },
            r.hub_target,
            now() - r.plan_set
        )
    } else {
        String::new()
    };
    if u.id.is_empty() {
        let mut out = "No upgrade has run on this hub.".to_string();
        if !plan.is_empty() {
            out.push('\n');
            out.push_str(&plan);
        }
        if config_frozen(state) {
            out.push_str("\nWARNING: config is frozen — clear opt flag 'F' to lift it.");
        }
        return out;
    }
    let mut out = format!(
        "--- Upgrade {} -> {} ({}) ---\nstarted {} s ago{}{}\n",
        u.id,
        u.target_ver,
        u.phase.name(),
        now() - u.started,
        if u.summary.is_empty() { "" } else { "; " },
        u.summary
    );
    if !u.hub_ver.is_empty() {
        out.push_str(&format!("hubs -> {}\n", u.hub_ver));
    }
    out.push_str(&plan);
    for n in &u.nodes {
        out.push_str(&format!(
            "{:<4} {:<36} {:<10} {:<8} {}{}{}\n",
            n.kind.name(),
            if n.name.is_empty() { &n.uuid } else { &n.name },
            n.state.name(),
            if n.cur_version.is_empty() {
                "-"
            } else {
                &n.cur_version
            },
            n.variant,
            if n.reason.is_empty() { "" } else { " " },
            n.reason
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::plan_field_ok;

    #[test]
    fn plan_fields_cannot_split_a_config_line() {
        assert!(plan_field_ok("2.99.0"));
        assert!(plan_field_ok("*"));
        assert!(plan_field_ok(""));
        assert!(plan_field_ok(
            "file:///home/u/.irc-testnet/ns/releases/irchub"
        ));
        for bad in ["a|b", "a\nrollup|x", "a\rb", "a b", "a;b", "$(x)", "`x`"] {
            assert!(!plan_field_ok(bad), "{bad:?} must be refused");
        }
        assert!(!plan_field_ok(&"x".repeat(512)));
    }
}
