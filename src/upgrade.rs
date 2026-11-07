//! Network upgrade orchestration (`hub_logic.c`: `CMD_ADMIN_UPGRADE_NET` →
//! `CMD_UPGRADE_*`).
//!
//! An admin's console `upgrade start` asks this hub to move the whole network to a version.  The hub
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
use crate::reply::Reply;
use crate::state::{
    ClientType, HubState, PendingUpgrade, RollupTry, UpgradeNode, UpgradeNodeKind,
    UpgradeNodeState, UpgradePhase, UpgradePlan, UpgradeRoute, lww_next_ts,
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
        CMD_ADMIN_DEL
            | CMD_ADMIN_REGEN_KEYS
            | CMD_ADMIN_ADD_PEER
            | CMD_ADMIN_DEL_PEER
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
            | CMD_ADMIN_USER_ACCESS
            // the changing forms only: admin::mf_payload_mutates
            | CMD_ADMIN_CHAN_MODE
            | CMD_ADMIN_CHAN_SET
            | CMD_ADMIN_BAN
            | CMD_ADMIN_NET_SET
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
        .position(|c| c.typ == typ && c.authenticated && !c.superseded && c.id == uuid)
}

/// The uuid a peer hub knows ITSELF by.  A peer connection's `id` is the
/// peer's FRIENDLY NAME — that is what the roster, the logs and the console show
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
// Selective runs
// ---------------------------------------------------------------------------
// An admin may move a handful of nodes instead of the whole network, each
// optionally onto the other build ("optiplex=c").  Names are resolved here,
// once, against everything this hub knows a node by — the stored bot records
// (so an offline bot can still be named and ends "no answer to PREPARE"), the
// live roster, and every hub heard from — and the run itself only ever
// carries uuids.

/// One node a selection token may name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cand {
    pub uuid: String,
    pub name: String,
    pub kind: UpgradeNodeKind,
}

fn cand_add(c: &mut Vec<Cand>, uuid: &str, name: &str, kind: UpgradeNodeKind) {
    if uuid.is_empty() || uuid == "-" {
        return;
    }
    if let Some(e) = c.iter_mut().find(|e| e.uuid == uuid) {
        if e.name.is_empty() && !name.is_empty() {
            e.name = name.to_string();
        }
        return;
    }
    c.push(Cand {
        uuid: uuid.to_string(),
        name: name.to_string(),
        kind,
    });
}

/// Every node this hub could name.
pub fn candidates(state: &HubState) -> Vec<Cand> {
    let mut c = Vec::new();
    cand_add(
        &mut c,
        &state.hub_uuid,
        &state.hub_friendly_name,
        UpgradeNodeKind::SelfHub,
    );
    for p in &state.peers {
        cand_add(&mut c, &p.uuid, &p.friendly_name, UpgradeNodeKind::PeerHub);
    }
    for m in &state.mesh_hubs {
        cand_add(&mut c, &m.uuid, &m.name, UpgradeNodeKind::PeerHub);
    }
    for cl in &state.clients {
        if cl.typ == ClientType::Bot && cl.authenticated {
            let nick = state.bot_entry(&cl.id, "n").unwrap_or("");
            cand_add(&mut c, &cl.id, nick, UpgradeNodeKind::Bot);
        }
    }
    for e in &state.roster {
        cand_add(&mut c, &e.bot_uuid, &e.nick, UpgradeNodeKind::Bot);
    }
    for b in state.bots.iter().filter(|b| b.is_active) {
        let nick = state.bot_entry(&b.uuid, "n").unwrap_or("");
        cand_add(&mut c, &b.uuid, nick, UpgradeNodeKind::Bot);
    }
    c
}

/// One token: a full uuid, else an exact name (case-insensitive), else a uuid
/// prefix of at least 4 characters.  Anything matching two different nodes is
/// refused rather than guessed.
pub fn resolve<'a>(c: &'a [Cand], tok: &str) -> Result<&'a Cand, String> {
    if let Some(e) = c.iter().find(|e| e.uuid.eq_ignore_ascii_case(tok)) {
        return Ok(e);
    }
    let mut hit: Option<&Cand> = None;
    for e in c
        .iter()
        .filter(|e| !e.name.is_empty() && e.name.eq_ignore_ascii_case(tok))
    {
        if let Some(h) = hit {
            return Err(format!(
                "'{tok}' names more than one node ({}, {}) — use a uuid",
                h.uuid, e.uuid
            ));
        }
        hit = Some(e);
    }
    if let Some(h) = hit {
        return Ok(h);
    }
    if tok.len() >= 4 {
        let t = tok.to_ascii_lowercase();
        for e in c
            .iter()
            .filter(|e| e.uuid.to_ascii_lowercase().starts_with(&t))
        {
            if let Some(h) = hit {
                return Err(format!(
                    "uuid prefix '{tok}' is ambiguous ({}, {})",
                    h.uuid, e.uuid
                ));
            }
            hit = Some(e);
        }
        if let Some(h) = hit {
            return Ok(h);
        }
    }
    Err(format!("no node known as '{tok}'"))
}

/// Is `uuid` in this run's selection?  `Some(variant)` ("" = the run's) when
/// it is — always, for a whole-network run.
fn selected<'a>(u: &'a crate::state::PendingUpgrade, uuid: &str) -> Option<&'a str> {
    if u.select.is_empty() {
        return Some("");
    }
    u.select
        .iter()
        .find(|(id, _)| id == uuid)
        .map(|(_, v)| v.as_str())
}

/// Look `uuid` up in a peer PREPARE's resolved selection ("uuid[=v],...").
/// `Some(variant)` ("" when none given) when it is listed.
pub fn sel_lookup(sel: &str, uuid: &str) -> Option<String> {
    if uuid.is_empty() {
        return None;
    }
    sel.split(',').find_map(|e| {
        let (id, v) = e.split_once('=').unwrap_or((e, ""));
        (id == uuid).then(|| v.to_string())
    })
}

/// The variant a node is being moved onto: its own override in a selective
/// run, else the run's ("" = keep its own).
fn node_variant(u: &crate::state::PendingUpgrade, ni: usize) -> &str {
    let n = &u.nodes[ni];
    if n.want_variant.is_empty() {
        &u.variant
    } else {
        &n.want_variant
    }
}

/// A manifest's "v2.4.4" spelled the way nodes announce it ("2.4.4"), so a
/// run's target compares with strcmp against what nodes say.
fn strip_version_v(v: &str) -> &str {
    match v.strip_prefix('v') {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
        _ => v,
    }
}

// ---------------------------------------------------------------------------
// Run lifecycle
// ---------------------------------------------------------------------------

/// End the run: lift the freeze and record why it stopped.  The table stays
/// behind so `CMD_ADMIN_UPGRADE_STATUS` can still explain what happened.
fn history_node_state(u: &PendingUpgrade, ni: usize) -> &'static str {
    let n = &u.nodes[ni];
    let to = node_target(u, ni);
    let want = node_variant(u, ni);
    if n.kind != UpgradeNodeKind::Bot
        && u.hub_ver.is_empty()
        && (n.not_selected || n.state == UpgradeNodeState::Unable)
    {
        return "idle";
    }
    if n.not_selected {
        return "skipped";
    }
    if n.state == UpgradeNodeState::Unable
        && !to.is_empty()
        && !n.cur_version.is_empty()
        && update::version_cmp(&n.cur_version, to) == std::cmp::Ordering::Equal
        && (want.is_empty() || want == n.variant)
    {
        return "already";
    }
    n.state.name()
}

fn history_result(u: &PendingUpgrade) -> &'static str {
    if u.active {
        return "running";
    }
    match u.phase {
        UpgradePhase::Aborted => return "aborted",
        UpgradePhase::Failed => return "failed",
        _ => {}
    }
    let (mut moved, mut missed) = (0, 0);
    for ni in 0..u.nodes.len() {
        let st = history_node_state(u, ni);
        if st == "done" || (u.nodes[ni].kind == UpgradeNodeKind::SelfHub && st == "committing") {
            moved += 1;
        } else if st == "failed" || st == "unable" {
            missed += 1;
        }
    }
    if moved == 0 {
        "noop"
    } else if missed > 0 {
        "partial"
    } else {
        "done"
    }
}

/// The run this hub drives, as a history record.  See `uhist`.
fn history_note(state: &mut HubState) {
    use crate::uhist::{UhistNode, UhistView};
    let u = &state.upgrade;
    let mut nodes = Vec::with_capacity(u.nodes.len());
    for (ni, n) in u.nodes.iter().enumerate() {
        // The nick now: the bot may be gone by the time anyone reads this.
        let name = if !n.name.is_empty() {
            n.name.clone()
        } else {
            match n.kind {
                UpgradeNodeKind::Bot => crate::presence::bot_nick_from_config(state, &n.uuid),
                UpgradeNodeKind::SelfHub => state.hub_friendly_name.clone(),
                UpgradeNodeKind::PeerHub => String::new(),
            }
        };
        nodes.push(UhistNode {
            kind: match n.kind {
                UpgradeNodeKind::Bot => "b",
                UpgradeNodeKind::PeerHub => "h",
                UpgradeNodeKind::SelfHub => "s",
            }
            .to_string(),
            state: history_node_state(u, ni).to_string(),
            uuid: trunc_string(&n.uuid, 64),
            name: trunc_string(&name, 64),
            from: trunc_string(&n.cur_version, 64),
            to: trunc_string(node_target(u, ni), 64),
            base: trunc_string(&n.variant, 8),
            want: trunc_string(&n.want_variant, 8),
            arch: trunc_string(&n.arch, 32),
            libc: trunc_string(&n.libc, 16),
            committed: n.committed_at,
            back: n.back_at,
            done: n.done_at,
            reason: trunc_string(&n.reason, 128),
            code: trunc_string(&n.stage_code, 16),
            build: if n.is_src {
                "src".to_string()
            } else if n.staged {
                "bin".to_string()
            } else {
                String::new()
            },
            stage_s: if n.staged_at > 0 && n.stage_sent > 0 {
                n.staged_at - n.stage_sent
            } else {
                0
            },
        });
    }
    let mut v = UhistView {
        id: u.id.clone(),
        rev: 0,
        driver_uuid: trunc_string(&state.hub_uuid, 64),
        driver_name: trunc_string(&state.hub_friendly_name, 64),
        by: trunc_string(&u.by, 64),
        started: u.started,
        rolling_at: u.rolling_at,
        ended: if u.active { 0 } else { now() },
        result: history_result(u).to_string(),
        bot_ver: trunc_string(&u.target_ver, 64),
        hub_ver: trunc_string(&u.hub_ver, 64),
        variant: trunc_string(&u.variant, 8),
        kind: trunc_string(&u.kind, 8),
        min_from: trunc_string(&u.min_from, 64),
        plan_id: u.plan_id,
        step: u.plan_step,
        steps: u.plan_steps,
        sel: trunc_string(&u.sel_wire, MAX_UPGRADE_SELECT * 72),
        summary: trunc_string(&u.summary, 192),
        nodes,
    };
    crate::uhist::put_own(state, &mut v);
}

fn finish(state: &mut HubState, phase: UpgradePhase, summary: &str) {
    // Keep the plan of a run that actually got somewhere: a node that was down
    // or homed elsewhere while it went through is walked up to this target
    // when it comes back (see the roll-up below).  An aborted run left the
    // mesh where it was, so there is nothing to catch up to.  A selective run
    // leaves the plan alone either way: moving three named bots says nothing
    // about what every other bot should run.
    //
    // A run where nothing actually moved must not replace a good plan either.
    if !state.upgrade.select.is_empty() {
        // no roll-up plan change
    } else if (phase == UpgradePhase::Done || phase == UpgradePhase::Partial)
        && (count(state, UpgradeNodeState::Done, None) > 0
            // commit_self finishes the run just before this hub execs.
            || state.upgrade.nodes.iter().any(|n| {
                n.kind == UpgradeNodeKind::SelfHub && n.state == UpgradeNodeState::Committed
            }))
    {
        state.rollup.have_plan = true;
        state.rollup.target = state.upgrade.target_ver.clone();
        state.rollup.variant = state.upgrade.variant.clone();
        state.rollup.kind = state.upgrade.kind.clone();
        state.rollup.min_from = state.upgrade.min_from.clone();
        state.rollup.hub_target = state.upgrade.hub_ver.clone();
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
    history_note(state); // before this hub can replace itself
    opt_flag_set(state, OPT_CONFIG_FROZEN, false);
    crate::hlog_info!(
        "[UPGRADE] Run {} {}: {}\n",
        state.upgrade.id,
        phase.name(),
        state.upgrade.summary
    );
    plan_single_end(state);
    // A step of a multi-step upgrade: decide whether the next one follows.
    // Before this hub restarts onto the step itself, so the decision is on
    // disk when the new build boots.
    plan_note_run_end(state, phase);
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
        // Ready too: still staging, nothing changed for them, and nothing will.
        .filter(|n| {
            n.state == UpgradeNodeState::Committed
                || n.state == UpgradeNodeState::Done
                || n.state == UpgradeNodeState::Ready
        })
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
    update::stage_clear();
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
    let variant = node_variant(&state.upgrade, ni).to_string();
    let payload = format!("{}|{}|{}", state.upgrade.id, ver, variant);
    let (uuid, kind, via) = (
        state.upgrade.nodes[ni].uuid.clone(),
        state.upgrade.nodes[ni].kind,
        state.upgrade.nodes[ni].via.clone(),
    );
    // Never through a hub that has already restarted: its run state
    // (follow_id and the COMMIT routes) went with the old process, so the
    // frame could only come back as a failure — and one a pre-2.4.3 follower
    // files under its own uuid.  Hubs go after bots, so this only catches a
    // straggler; it stays out of the run, unharmed.
    if !via.is_empty()
        && kind != UpgradeNodeKind::SelfHub
        && find_node(state, &via).is_some_and(|h| {
            matches!(
                state.upgrade.nodes[h].state,
                UpgradeNodeState::Committed | UpgradeNodeState::Done | UpgradeNodeState::Failed
            )
        })
    {
        let node = &mut state.upgrade.nodes[ni];
        node.state = UpgradeNodeState::Unable;
        node.reason = "its hub restarted before it could be committed".to_string();
        crate::hlog_warning!(
            "[UPGRADE] Not committing {uuid}: hub {via} already restarted\n",
            uuid = state.who('\0', &uuid)
        );
        return false;
    }
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
        state.who('\0', &uuid),
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
    // The step is not over until this hub is seen on it: the next boot decides.
    if state.plan.active {
        state.plan.self_target = state.upgrade.hub_ver.clone();
    }
    finish(state, UpgradePhase::Done, &done_msg);

    let (id, ver, variant) = (
        state.upgrade.id.clone(),
        state.upgrade.hub_ver.clone(),
        node_variant(&state.upgrade, ni).to_string(),
    );
    match update::commit(state, &id, &ver, &variant) {
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
                node.done_at = now();
            }
            state.upgrade.summary = clean(
                &format!("{done} node(s) upgraded, but this hub stayed on {HUB_VERSION}: {e}"),
                192,
            );
            state.upgrade.phase = UpgradePhase::Failed;
            history_note(state);
            crate::hlog_warning!("[UPGRADE] This hub could not take {ver}: {e}\n");
            if state.plan.active {
                state.plan.self_target.clear();
                let why = state.upgrade.summary.clone();
                plan_hold(state, &why, true, "", "");
            }
            false
        }
    }
}

/// What `CMD_ADMIN_UPGRADE_NET` asked for, field by field.
pub struct StartArgs<'a> {
    pub target_ver: &'a str,
    pub variant: &'a str,
    pub kind: &'a str,
    pub min_from: &'a str,
    pub hub_ver: &'a str,
    /// The admin's selection ("" = whole network): comma-separated
    /// name-or-uuid tokens, each optionally "=c" / "=rs".
    pub sel: &'a str,
}

/// Resolve a selection into `(uuid, variant, kind)` picks.  Done before
/// anything is frozen or sent, so a typo refuses the run instead of quietly
/// moving nothing.
fn resolve_selection(
    state: &HubState,
    sel: &str,
    hub_ver: &str,
) -> Result<Vec<(String, String, UpgradeNodeKind)>, String> {
    let cands = candidates(state);
    let mut picks: Vec<(String, String, UpgradeNodeKind)> = Vec::new();
    for tok in sel.split([',', ' ']).filter(|t| !t.is_empty()) {
        let (name, want) = match tok.split_once('=') {
            Some((n, w)) => {
                if w != "c" && w != "rs" {
                    return Err(format!("ERROR: '{n}={w}': the build must be c or rs"));
                }
                (n, w)
            }
            None => (tok, ""),
        };
        let c = resolve(&cands, name).map_err(|e| format!("ERROR: {e}"))?;
        if picks.iter().any(|(u, _, _)| *u == c.uuid) {
            continue;
        }
        if picks.len() >= MAX_UPGRADE_SELECT {
            return Err(format!(
                "ERROR: at most {MAX_UPGRADE_SELECT} nodes per selective run — run the whole \
                 network instead"
            ));
        }
        if c.kind != UpgradeNodeKind::Bot && hub_ver.is_empty() {
            return Err(format!(
                "ERROR: '{name}' is a hub, and this run has no hub target"
            ));
        }
        picks.push((c.uuid.clone(), want.to_string(), c.kind));
    }
    if picks.is_empty() {
        return Err("ERROR: the selection names no node".to_string());
    }
    Ok(picks)
}

/// The console asked for a network upgrade.  Freeze the config, enumerate the
/// nodes and fan PREPARE out; the rolling plan itself runs on the maintenance
/// tick.  The returned string is what the admin console prints.
pub fn start(state: &mut HubState, origin_fd: i32, a: &StartArgs) -> String {
    let StartArgs {
        target_ver,
        variant,
        kind,
        min_from,
        hub_ver,
        sel,
    } = *a;
    if state.upgrade.active {
        return format!(
            "ERROR: upgrade {} already running ({})",
            state.upgrade.id,
            state.upgrade.phase.name()
        );
    }
    // The freeze replicates, so it is how this hub knows a run driven from
    // anywhere else in the mesh is still in flight.  Two plans moving the same
    // nodes is what the one-run-at-a-time rule exists to prevent.
    if config_frozen(state) {
        return "ERROR: config is frozen — an upgrade is already in flight somewhere in the mesh \
                (if none is, clear opt flag 'F')"
            .to_string();
    }
    if target_ver.is_empty() || !plan_field_ok(target_ver) || target_ver.len() >= 64 {
        return "ERROR: bad target version".to_string();
    }
    if !variant.is_empty() && variant != "c" && variant != "rs" {
        return "ERROR: variant must be c or rs".to_string();
    }
    if !kind.is_empty() && kind != "bin" && kind != "src" {
        return "ERROR: kind must be bin or src".to_string();
    }
    if !min_from.is_empty() && (!plan_field_ok(min_from) || min_from.len() >= 64) {
        return "ERROR: bad min_from version".to_string();
    }
    if hub_ver.len() >= 64 || hub_ver.contains(['|', ';', '&', '`', '$', ' ', '\t', '\r', '\n']) {
        return "ERROR: bad hub target version".to_string();
    }
    // Resolve the selection first: an error must leave the last run's table
    // (and its status) untouched.
    let picks = if sel.is_empty() {
        Vec::new()
    } else {
        match resolve_selection(state, sel, hub_ver) {
            Ok(p) => p,
            Err(e) => return e,
        }
    };
    // One spelling of a version everywhere a run compares it with strcmp —
    // what nodes announce ("2.4.4"), not what manifests write ("v2.4.4").
    let target_ver = strip_version_v(target_ver);
    let hub_ver = strip_version_v(hub_ver);

    // Seed the PREPARE seen-ring: our own PREPARE coming back to us around a
    // cycle of peers is then dropped silently instead of being answered.
    let run_id = opflow::generate_request_id();
    opflow::forward_seen_check_and_add(state, &run_id);
    let sel_wire = picks
        .iter()
        .map(|(u, v, _)| {
            if v.is_empty() {
                u.clone()
            } else {
                format!("{u}={v}")
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    // Who typed it: the console connection, or a plan's earlier step.
    let (plan_id, plan_step, plan_steps) = if state.plan.active {
        (
            state.plan.started,
            state.plan.step as i64 + 1,
            state.plan.steps() as i64,
        )
    } else {
        (0, 0, 0)
    };
    let by = state
        .clients
        .iter()
        .find(|c| c.fd == origin_fd && origin_fd >= 0)
        .and_then(|c| c.id.strip_prefix("ADMIN:"))
        .map(str::to_string)
        .unwrap_or_else(|| {
            if plan_id != 0 {
                crate::uhist::plan_by(state, plan_id)
            } else {
                String::new()
            }
        });
    let u = &mut state.upgrade;
    *u = crate::state::PendingUpgrade {
        build_stopped: false,
        hubs_stopped: false,
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
        hub_ver: hub_ver.to_string(),
        origin_fd,
        started: now(),
        phase_started: now(),
        by,
        plan_id,
        plan_step,
        plan_steps,
        rolling_at: 0,
        phase: UpgradePhase::Prepare,
        nodes: Vec::new(),
        last_added: now(),
        ready_seq_next: 0,
        summary: String::new(),
        select: picks
            .iter()
            .map(|(u, v, _)| (u.clone(), v.clone()))
            .collect(),
        sel_wire,
    };
    plan_single_start(state);

    // Freeze first: a config change that lands between PREPARE and the last
    // COMMIT would reach half the mesh on one build and half on another.
    opt_flag_set(state, OPT_CONFIG_FROZEN, true);

    // Two shapes of the same PREPARE.  A bot gets the six fields it has
    // always read; a peer hub also needs the hubs' own target, appended so
    // the bot prefix stays byte-identical and a follower can relay it on,
    // and — in a selective run — the resolved selection, which tells it which
    // of its own bots to ask and whether it is itself part of the run.  Both
    // base slots are reserved and always empty (fields are positional): each
    // node reads its own compiled-in root.
    let prepare_peer = {
        let u = &state.upgrade;
        let mut p = format!(
            "{}|{}|{}|{}|{}||{}|",
            u.id, u.target_ver, u.variant, u.kind, u.min_from, u.hub_ver
        );
        if !u.sel_wire.is_empty() {
            p.push('|');
            p.push_str(&u.sel_wire);
        }
        p
    };

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
                let Some(want) = selected(&state.upgrade, &key).map(str::to_string) else {
                    continue;
                };
                // The variant this bot is asked about is ITS target build, so
                // a bot told "=c" checks the C manifest at PREPARE, not its own.
                let u = &state.upgrade;
                let prepare = format!(
                    "{}|{}|{}|{}|{}|",
                    u.id,
                    u.target_ver,
                    if want.is_empty() { &u.variant } else { &want },
                    u.kind,
                    u.min_from
                );
                let fd = state.clients[ci].fd;
                let delivered =
                    client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &prepare);
                state.upgrade.nodes.push(UpgradeNode {
                    uuid: key,
                    kind: UpgradeNodeKind::Bot,
                    fd,
                    cur_version: ver,
                    want_variant: want,
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
                        "[UPGRADE] {} has no uuid yet — left out of run {}\n",
                        state.who_client(ci),
                        state.upgrade.id
                    );
                    continue;
                }
                let want = selected(&state.upgrade, &key).unwrap_or("").to_string();
                let fd = state.clients[ci].fd;
                let delivered =
                    queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &prepare_peer);
                state.upgrade.nodes.push(UpgradeNode {
                    uuid: key,
                    name,
                    kind: UpgradeNodeKind::PeerHub,
                    fd,
                    want_variant: want,
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
    let self_pick = selected(&state.upgrade, &state.hub_uuid).map(str::to_string);
    let self_want = self_pick.clone().unwrap_or_default();
    let (self_state, self_reason) = if self_pick.is_none() {
        (UpgradeNodeState::Unable, "not selected".to_string())
    } else if state.upgrade.hub_ver.is_empty() {
        (
            UpgradeNodeState::Unable,
            "no hub target in this run".to_string(),
        )
    } else {
        let want = if self_want.is_empty() {
            state.upgrade.variant.clone()
        } else {
            self_want.clone()
        };
        match update::can_take(&state.upgrade.hub_ver, &want, &state.upgrade.min_from) {
            Ok(()) => (UpgradeNodeState::Ready, String::new()),
            Err(why) => (UpgradeNodeState::Unable, why),
        }
    };
    state.upgrade.nodes.push(UpgradeNode {
        uuid: state.hub_uuid.clone(),
        name: state.hub_friendly_name.clone(),
        kind: UpgradeNodeKind::SelfHub,
        fd: -1,
        cur_version: HUB_VERSION.to_string(),
        variant: update::host_variant().to_string(),
        want_variant: self_want,
        not_selected: self_pick.is_none(),
        arch: update::host_arch(),
        libc: update::host_libc(),
        state: self_state,
        reason: self_reason,
        ..UpgradeNode::default()
    });
    state.upgrade.last_added = now();
    // A selected node this hub did not just ask directly is somewhere below a
    // peer (or offline).  Seed it as pending: its READY fills it in, and one
    // that never answers ends "no answer to PREPARE" instead of vanishing from
    // the status an admin is watching.
    for (uuid, want, kind) in &picks {
        if find_node(state, uuid).is_some() || state.upgrade.nodes.len() >= MAX_UPGRADE_NODES {
            continue;
        }
        state.upgrade.nodes.push(UpgradeNode {
            uuid: uuid.clone(),
            kind: if *kind == UpgradeNodeKind::Bot {
                UpgradeNodeKind::Bot
            } else {
                UpgradeNodeKind::PeerHub
            },
            fd: -1,
            want_variant: want.clone(),
            ..UpgradeNode::default()
        });
        state.upgrade.last_added = now();
    }

    let u = &state.upgrade;
    crate::hlog_info!(
        "[UPGRADE] Run {} -> {}: PREPARE to {} bot(s) and {} peer hub(s){}{}; this hub is {}\n",
        u.id,
        u.target_ver,
        bots,
        peers,
        if u.select.is_empty() {
            ""
        } else {
            "; selection "
        },
        u.sel_wire,
        self_state.name()
    );
    let msg = if !u.select.is_empty() {
        format!(
            "OK:upgrade {} started for {} selected node(s) -> {}{}{}; config frozen until it \
             finishes",
            u.id,
            u.select.len(),
            u.target_ver,
            if u.hub_ver.is_empty() {
                ""
            } else {
                ", hubs -> "
            },
            u.hub_ver
        )
    } else {
        format!(
            "OK:upgrade {} started for {} — {} bot(s) and {} peer hub(s) asked to prepare, this \
             hub last; config frozen until it finishes",
            u.id, u.target_ver, bots, peers
        )
    };
    history_note(state);
    msg
}

// ---------------------------------------------------------------------------
// Inbound frames
// ---------------------------------------------------------------------------

/// `CMD_UPGRADE_READY`: `id|uuid|cur_ver|variant|arch|libc|ready|reason`,
/// then — from a hub — `|kind|relayed`.  All ten fields are split out: with
/// `splitn(9)` the kind read as "h|5", a hub further out was filed as a bot
/// and a peer's relayed-bot count was never read, so PREPARE closed before
/// its bots answered (run 83aac614).
pub fn note_ready(state: &mut HubState, payload: &str, from_peer: Option<&str>) {
    let f: Vec<&str> = payload.splitn(10, '|').collect();
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
            state.who('\0', uuid)
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
                crate::hlog_warning!(
                    "[UPGRADE] READY from {} which is not in run {}\n",
                    state.who('\0', uuid),
                    id
                );
                return;
            };
            if state.upgrade.nodes.len() >= MAX_UPGRADE_NODES {
                crate::hlog_warning!(
                    "[UPGRADE] No room for remote node {} in run {}\n",
                    state.who('\0', uuid),
                    id
                );
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
    // A READY answers PREPARE, once.  A second copy (a relay loop, a bot that
    // reconnected and was re-asked by a follower) must not move a node that
    // is already committed or finished back to "ready" — that re-commits it.
    if state.upgrade.nodes[ni].state != UpgradeNodeState::Pending {
        crate::hlog_debug!(
            "[UPGRADE] Duplicate READY from {} ({}) — ignored\n",
            state.who('\0', uuid),
            state.upgrade.nodes[ni].state.name()
        );
        return;
    }
    let reason = clean(f.get(7).copied().unwrap_or(""), 128);
    if state.upgrade.nodes[ni].ready_seq == 0 {
        state.upgrade.ready_seq_next += 1;
        state.upgrade.nodes[ni].ready_seq = state.upgrade.ready_seq_next;
    }
    let plan_fixed = state.upgrade.phase != UpgradePhase::Prepare;
    let hop_moving = {
        let via = &state.upgrade.nodes[ni].via;
        !via.is_empty()
            && state.upgrade.nodes.iter().any(|h| {
                &h.uuid == via
                    && matches!(
                        h.state,
                        UpgradeNodeState::Committed | UpgradeNodeState::Done
                    )
            })
    };
    let is_selected = selected(&state.upgrade, uuid).is_some();
    let who = state.who('\0', uuid);
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
    // The plan is fixed when PREPARE closes.  An answer that arrives later —
    // a bot a follower relayed to, whose READY lost the race — is recorded
    // but never committed: by then the hub it sits behind may already be
    // restarting, and a COMMIT sent through it would come back as a failure
    // that aborts a healthy run (run 83aac614).
    if node.state == UpgradeNodeState::Ready && plan_fixed {
        // Only if the hub it sits behind may be restarting.  Otherwise it joins: it
        // could not stage, so it takes the old path at COMMIT.
        if hop_moving {
            node.state = UpgradeNodeState::Unable;
            node.reason = "answered after the plan was fixed — run again to include it".to_string();
        } else {
            node.can_stage = false;
        }
    }
    // A whole-network follower (or an older one) asks every bot it has; a
    // selective run only moves what the admin named.
    if !is_selected {
        node.state = UpgradeNodeState::Unable;
        node.not_selected = true;
        node.reason = "not selected".to_string();
    }
    if node.kind == UpgradeNodeKind::PeerHub
        && let Some(rel) = f.get(9).and_then(|v| v.parse::<usize>().ok())
    {
        node.relayed = if rel <= MAX_UPGRADE_NODES { rel } else { 0 };
    }
    crate::hlog_debug!(
        "[UPGRADE] {} is {} ({} {}/{}){}{}\n",
        who,
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
pub fn bot_report(state: &mut HubState, ci: usize, cmd: u8, payload: &str) {
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
        return;
    }
    if cmd == CMD_UPGRADE_PROGRESS {
        note_progress(state, payload);
        return;
    }
    // A bot reports for itself, and once per link: a bot sends one RESULT after
    // a restart, so one relay per link bounds what it can make the mesh carry.
    let uuid = payload.split('|').nth(1).unwrap_or("");
    if !state.clients[ci].result_relayed
        && uuid == state.clients[ci].id
        && result_relay(state, None, payload)
    {
        state.clients[ci].result_relayed = true;
    }
    note_result(state, payload);
}

/// A bot restarted by a roll-up can come back on any hub, and its done report
/// reaches only that one.  An id that is not this hub's to answer is passed on,
/// once, to every other peer, so the hub that asked hears it.  False = not
/// relayed.  A peer on an older build ignores it, and the attempt times out.
pub fn result_relay(state: &mut HubState, from: Option<usize>, payload: &str) -> bool {
    let mut f = payload.split('|');
    let (id, uuid, status) = (
        f.next().unwrap_or(""),
        f.next().unwrap_or(""),
        f.next().unwrap_or(""),
    );
    if payload.len() > UPGRADE_RESULT_RELAY_MAX
        || id.is_empty()
        || id.len() >= 64
        || uuid.is_empty()
        || uuid.len() >= 64
        || status.is_empty()
        || status.len() >= 32
    {
        return false;
    }
    if state.follow_id == id
        || state.upgrade.id == id
        || (state.rollup.active && state.rollup.id == id)
    {
        return false;
    }
    let key = format!("ur:{}", id.get(..59).unwrap_or(id));
    if opflow::forward_seen_check_and_add(state, &key) {
        return false;
    }
    for pi in state.peer_clients() {
        if Some(pi) != from {
            queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_RESULT, payload);
        }
    }
    true
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
    // A RESULT answers a COMMIT.  Anything for a node that is not committed —
    // a duplicate, a late reply from a hub that restarted, the answer to our
    // own ABORT — is logged and dropped: a finished node must never be turned
    // back into a failure by noise (run 83aac614's eb04).
    if state.upgrade.nodes[ni].state != UpgradeNodeState::Committed {
        crate::hlog_info!(
            "[UPGRADE] {} reports {} ({}) while {} — ignored{}{}\n",
            state.who('\0', uuid),
            status,
            f[3],
            state.upgrade.nodes[ni].state.name(),
            if detail.is_empty() { "" } else { ": " },
            detail
        );
        return;
    }
    let who = state.who('\0', uuid);
    let node = &mut state.upgrade.nodes[ni];
    // cur_version stays what the run found ("from"); the reported one is f[3].
    // A follower saw this bot back on the target; its own "ok" follows once
    // it is back in its channels with ops.  Stays committed (Addendum A1).
    if status == "back" {
        if node.back_at == 0 {
            node.back_at = now();
        }
        crate::hlog_info!(
            "[UPGRADE] {} is back on {}; waiting for its ready report\n",
            uuid,
            f[3]
        );
        return;
    }
    node.reason = detail;
    node.done_at = now();
    node.state = match status {
        "ok" => UpgradeNodeState::Done,
        // Nothing on that node changed and it is healthy on its current
        // build: it leaves the run, the run goes on.  Abort is for harm, not
        // noise.
        "skip" => UpgradeNodeState::Unable,
        _ => UpgradeNodeState::Failed,
    };
    if node.reason.is_empty() && node.state != UpgradeNodeState::Done {
        node.reason = if node.state == UpgradeNodeState::Unable {
            "skipped".to_string()
        } else {
            status.to_string()
        };
    }
    crate::hlog_info!(
        "[UPGRADE] {} reports {} ({}){}{}\n",
        who,
        status,
        f[3],
        if node.reason.is_empty() { "" } else { ": " },
        node.reason
    );
}

/// A bot that just announced its version may be a committed node coming back
/// on the new build — that, not the RESULT frame, is the authoritative signal
/// (the RESULT can be lost, the presence cannot: without it the bot is not on
/// the mesh at all).
pub fn note_presence(state: &mut HubState, uuid: &str, version: &str, variant: &str) {
    if !state.upgrade.active || state.upgrade.phase != UpgradePhase::Rolling {
        return;
    }
    let Some(ni) = find_node(state, uuid) else {
        return;
    };
    let target = node_target(&state.upgrade, ni).to_string();
    let want = node_variant(&state.upgrade, ni).to_string();
    let on_target = update::version_cmp(version, &target) == std::cmp::Ordering::Equal;
    let node = &mut state.upgrade.nodes[ni];

    // A node that reported done and then shows up on another build fell back:
    // its upgrade script's watchdog put the old binary back because the new
    // one would not stay up.  That is the one signal a bad build gives.  Bots
    // only: their presence comes straight off their own connection, while a
    // hub's header may be a relayed copy older than its restart.
    if node.state == UpgradeNodeState::Done {
        if !on_target && node.kind == UpgradeNodeKind::Bot {
            node.state = UpgradeNodeState::Failed;
            node.done_at = now();
            node.reason = format!(
                "came back on {} after reporting done",
                trunc_string(version, 41)
            );
            crate::hlog_warning!(
                "[UPGRADE] {uuid} fell back to {version} after reporting done\n",
                uuid = state.who('\0', uuid)
            );
        }
        return;
    }
    // Failed for lateness, and here it is on the target: the record says so.
    if node.state == UpgradeNodeState::Failed
        && on_target
        && node.kind == UpgradeNodeKind::Bot
        && node.staged_at == 0
    {
        node.state = UpgradeNodeState::Done;
        node.done_at = now();
        node.reason = "came back late".to_string();
        return;
    }
    if node.state != UpgradeNodeState::Committed {
        return;
    }
    if !on_target {
        return;
    }
    // A build switch at the same version is only proven by the variant: the
    // old process announced this very version before it restarted.  Without a
    // variant to compare (a hub's header line), wait for the RESULT.
    if !want.is_empty() && want != node.variant && variant != want {
        return;
    }
    // A bot holds its "ok" until it is back in its channels with ops, so it
    // is not done yet — the next wave waits for that (Addendum A1).
    if node.kind == UpgradeNodeKind::Bot {
        if node.back_at == 0 {
            node.back_at = now();
            crate::hlog_info!(
                "[UPGRADE] {} is back on {}; waiting for its ready report\n",
                uuid,
                version
            );
        }
        return;
    }
    node.state = UpgradeNodeState::Done;
    node.done_at = now();
    crate::hlog_info!(
        "[UPGRADE] {} is back on {}\n",
        state.who('\0', uuid),
        version
    );
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
/// CMD_UPGRADE_FORGET from a peer: drop our plan and pass it on.
pub fn peer_forget(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.split('|').collect();
    if f.len() < 2 || f[0].is_empty() || f[0].len() >= 64 || !plan_field_ok(f[0]) {
        let ip = state.clients[ci].ip.clone();
        crate::hlog_warning!("[ROLLUP] Malformed UPGRADE_FORGET from peer {ip}\n");
        return;
    }
    let ts = crate::cstr::atoll(f[1]);
    // atoll saturates: age only for a positive stamp
    let age = if ts > 0 { now() - ts } else { 0 };
    if ts <= 0 || !(-UPGRADE_FORGET_TTL..=UPGRADE_FORGET_TTL).contains(&age) {
        return;
    }
    if opflow::forward_seen_check_and_add(state, f[0]) {
        return;
    }
    if f.get(2) == Some(&"A") {
        // `upgrade abort` typed on another hub: stop whatever this hub
        // drives — a run in flight, and a multi-step plan between its steps —
        // unless it started after the admin typed it (a re-sent abort meeting
        // a new run).  Remembered, so a peer that comes up in the next
        // UPGRADE_CANCEL_HOLD seconds hears it too.
        let issued = match f.get(3) {
            Some(s) if !s.is_empty() => crate::cstr::atoll(s),
            _ => ts,
        };
        state.upgrade_cancel_id = f[0].to_string();
        state.upgrade_cancel_issued = issued;
        state.upgrade_cancel_seen = now();
        // A run that carries on a plan begun before the abort is stopped too: a hub
        // that took the plan over after the admin typed it still drives that plan.
        if state.upgrade.active
            && (state.upgrade.started <= issued
                || (state.plan.active && state.plan.started <= issued))
        {
            abort(state, "aborted by an admin on another hub");
        }
        plan_cancelled(state, issued);
        if state.plan.active && state.plan.started <= issued {
            plan_stop(state, "aborted by an admin on another hub");
        }
    } else if !state.upgrade.active && !config_frozen(state) {
        // A plan is never dropped under a run: the freeze is replicated, so
        // every hub sees the same answer the admin's own hub gave.
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
                ..Default::default()
            });
        }
    }
    // The last attempt, charged or not, for upgrade status.
    {
        let uuid = state.rollup.uuid.clone();
        let step = state.rollup.step.clone();
        if !state.rollup_tries.iter().any(|t| t.uuid == uuid) {
            if state.rollup_tries.len() >= MAX_ROLLUP_TRIES {
                state.rollup_tries.remove(0);
            }
            state.rollup_tries.push(RollupTry {
                uuid: uuid.clone(),
                ..Default::default()
            });
        }
        if let Some(t) = state.rollup_tries.iter_mut().find(|t| t.uuid == uuid) {
            t.step = step;
            t.note = clean(why, 128);
            if !charge {
                t.last_try = now();
            }
        }
    }
    state.rollup.staging = false;
    state.rollup.ready_at = 0;
    crate::hlog_info!(
        "[ROLLUP] {} -> {}: {}\n",
        state.who('\0', &state.rollup.uuid),
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

/// The hubs' counterpart: some hub other than `except` — this one, or any in
/// the mesh map — announces the hub target.
fn rollup_hub_target_proven(state: &HubState, target: &str, except: &str) -> bool {
    (state.hub_uuid != except && update::version_cmp(HUB_VERSION, target).is_eq())
        || state.mesh_hubs.iter().any(|m| {
            m.uuid != except
                && !m.version.is_empty()
                && update::version_cmp(&m.version, target).is_eq()
        })
}

fn rollup_may_try(state: &HubState, uuid: &str, node_kind: UpgradeNodeKind, version: &str) -> bool {
    let r = &state.rollup;
    if !r.have_plan || r.active || state.upgrade.active {
        return false;
    }
    // ...and so does a multi-step upgrade between its steps: the next step
    // moves every node anyway, and a straggler is caught up after the last.
    if state.plan.active && (state.plan.hold_uuid.is_empty() || state.plan.hold_uuid != uuid) {
        return false;
    }
    // Any hub, while a plan is out: the freeze lifts between steps, this does not.
    // The one exception is the node a plan is on hold for.
    if state.splan.active
        && !state.splan.single
        && (state.splan.hold_uuid.is_empty() || state.splan.hold_uuid != uuid)
    {
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
    if node_kind == UpgradeNodeKind::PeerHub {
        if r.hub_target.is_empty()
            || update::version_cmp(version, &r.hub_target) != std::cmp::Ordering::Less
            || !rollup_hub_target_proven(state, &r.hub_target, uuid)
        {
            return false;
        }
    } else if update::version_cmp(version, &r.target) != std::cmp::Ordering::Less
        || !rollup_target_proven(state, &r.target, uuid)
    {
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
    if !rollup_may_try(state, uuid, node_kind, version) {
        return;
    }

    // Stepping: when the node is below the target's min_from it cannot jump
    // straight there, so ask the manifest for the highest release it may take
    // from where it is.  A manifest this hub cannot read (no key, no network)
    // is not fatal — aim straight at the target and let the node's own updater
    // refuse if it must.
    // Read the node's OWN product tree for its own build: a bot steps along
    // ircbot-releases, a hub along this hub's irchub tree.
    let hub = node_kind == UpgradeNodeKind::PeerHub;
    let variant = state.rollup.variant.clone();
    let target = if hub {
        state.rollup.hub_target.clone()
    } else {
        state.rollup.target.clone()
    };
    let step_root = if hub {
        String::new()
    } else {
        update::bot_root()
    };
    let step_variant = if hub {
        state
            .mesh_hubs
            .iter()
            .find(|m| m.uuid == uuid)
            .map(|m| m.variant.clone())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| update::host_variant().to_string())
    } else if !variant.is_empty() {
        variant.clone()
    } else {
        find_client(state, uuid, ClientType::Bot)
            .map(|ci| state.clients[ci].bot_variant.clone())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "c".to_string())
    };
    let step = match update::next_step(&step_root, &step_variant, version, &target) {
        Ok(v) => strip_version_v(&v).to_string(),
        Err(why) => {
            crate::hlog_info!(
                "[ROLLUP] No step read for {uuid} ({why}); aiming at {target}\n",
                uuid = state.who('\0', uuid)
            );
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
    let sent = if hub {
        // A directly linked hub gets the peer shape of a SELECTIVE run naming
        // only itself: it checks its own hub target, asks none of its bots,
        // and whatever it relays on is answered "not selected" and ignored
        // here.  A selective PREPARE leaves no roll-up plan behind on anyone,
        // and our own copy coming back around a cycle is dropped by the
        // seen-ring.
        let bot_target = state.rollup.target.clone();
        let prepare = format!("{id}|{bot_target}|{variant}|{kind}|*||{step}||{uuid}");
        opflow::forward_seen_check_and_add(state, &id);
        find_client_hub(state, uuid).is_some_and(|pi| {
            queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_PREPARE, &prepare)
        })
    } else {
        // Local bots only for the bot side: the run's bot PREPARE carries no
        // selection, so sent to a peer it would be fanned mesh-wide.
        let prepare = format!("{id}|{step}|{variant}|{kind}|*|");
        find_client(state, uuid, ClientType::Bot).is_some_and(|ci| {
            client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &prepare)
        })
    };
    if !sent {
        rollup_end(state, "could not deliver PREPARE", true);
        return;
    }
    crate::hlog_info!(
        "[ROLLUP] {uuid} is on {version}, the network is on {target}: PREPARE {id} -> {step}\n",
        uuid = state.who('\0', uuid)
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
    // Its progress frame says whether it can stage; one that says nothing is an older
    // build, and rollup_tick commits it the old way.
    state.rollup.ready_at = now();
    true
}

/// The node is ready, staged or never able to be: go.
fn rollup_commit(state: &mut HubState) {
    state.rollup.ready_at = 0;
    state.rollup.staging = false;
    let (id, step, variant, uuid) = (
        state.rollup.id.clone(),
        state.rollup.step.clone(),
        state.rollup.variant.clone(),
        state.rollup.uuid.clone(),
    );
    let sent = if state.rollup.node_kind == UpgradeNodeKind::PeerHub {
        // addressed to the hub itself (4th field), as a run commits a hub
        let commit = format!("{id}|{step}||{uuid}");
        find_client_hub(state, &uuid).is_some_and(|pi| {
            queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_COMMIT, &commit)
        })
    } else {
        let commit = format!("{id}|{step}|{variant}");
        find_client(state, &uuid, ClientType::Bot).is_some_and(|ci| {
            client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_COMMIT, &commit)
        })
    };
    if !sent {
        rollup_end(state, "disconnected before commit", true);
        return;
    }
    state.rollup.committed = true;
    state.rollup.started = now();
    crate::hlog_info!(
        "[ROLLUP] COMMIT {id} -> {uuid} ({step})\n",
        uuid = state.who('\0', &uuid)
    );
}

/// CMD_UPGRADE_PROGRESS carrying a roll-up id.  True when it was one.
fn rollup_note_progress(state: &mut HubState, payload: &str) -> bool {
    let f: Vec<&str> = payload.splitn(6, '|').collect();
    let id = f.first().copied().unwrap_or("");
    if !state.rollup.active || id.is_empty() || state.rollup.id != id {
        return false;
    }
    if f.get(1).copied().unwrap_or("") != state.rollup.uuid {
        return true;
    }
    let phase = f.get(2).copied().unwrap_or("");
    state.rollup.stage_last = now();
    if phase == "ready" {
        let (rid, uuid) = (state.rollup.id.clone(), state.rollup.uuid.clone());
        let sent = if state.rollup.node_kind == UpgradeNodeKind::PeerHub {
            find_client_hub(state, &uuid).is_some_and(|pi| {
                queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_STAGE, &rid)
            })
        } else {
            find_client(state, &uuid, ClientType::Bot).is_some_and(|ci| {
                client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_STAGE, &rid)
            })
        };
        if sent {
            state.rollup.staging = true;
            state.rollup.ready_at = 0;
            state.rollup.started = now();
        }
    } else if phase == "staged" {
        rollup_commit(state);
    } else if phase == "failed" {
        let code = f.get(3).copied().unwrap_or("");
        let note = f.get(4).copied().unwrap_or("");
        let why = format!("{}: {note}", if code.is_empty() { "stage" } else { code });
        rollup_end(state, &why, true);
    }
    true
}

/// `CMD_UPGRADE_RESULT` carrying a roll-up id.  Returns true when it was one.
fn rollup_note_result(state: &mut HubState, payload: &str) -> bool {
    let f: Vec<&str> = payload.splitn(5, '|').collect();
    let id = f.first().copied().unwrap_or("");
    if !state.rollup.active || id.is_empty() || state.rollup.id != id {
        return false;
    }
    let uuid = f.get(1).copied().unwrap_or("");
    if state.rollup.uuid != uuid {
        return true; // not the node we asked
    }
    let status = f.get(2).copied().unwrap_or("");
    let ver = f.get(3).copied().unwrap_or("");
    let detail = f.get(4).copied().unwrap_or("");
    if status != "ok" {
        rollup_end(state, if detail.is_empty() { status } else { detail }, true);
        return true;
    }
    // "ok" with a detail: the bot waited UPGRADE_OPS_WAIT and is on the step, but
    // not back on IRC or not re-opped everywhere.
    if !detail.is_empty() {
        let who = state.who('\0', uuid);
        crate::hlog_warning!(
            "[ROLLUP] {} installed {}: {}\n",
            who,
            state.rollup.step,
            detail
        );
        rollup_end(state, "reports done, with a problem", false);
    } else {
        rollup_end(state, "reports done", false);
    }
    // A walk of several releases keeps going from the new version, here if the
    // bot came back here; else the hub it is on takes it from its presence.
    if !ver.is_empty() && find_client(state, uuid, ClientType::Bot).is_some() {
        rollup_consider(state, uuid, UpgradeNodeKind::Bot, ver);
    }
    true
}

/// An attempt on a bot ends on its done report (`rollup_note_result`), not on
/// its presence: presence comes as soon as it has a hub link, and "done" means
/// back on IRC and re-opped.  Presence only starts the next attempt.
pub fn rollup_note_presence(
    state: &mut HubState,
    uuid: &str,
    node_kind: UpgradeNodeKind,
    version: &str,
) {
    rollup_consider(state, uuid, node_kind, version);
}

/// The newest version this hub knows a bot runs: its live link here, or any
/// hub's presence report.  None when nobody reports it (it is down).
fn rollup_bot_version<'a>(state: &'a HubState, uuid: &str) -> Option<&'a str> {
    let mut best: Option<&str> = None;
    for c in &state.clients {
        if c.typ == ClientType::Bot
            && c.authenticated
            && !c.superseded
            && !c.bot_version.is_empty()
            && c.id == uuid
        {
            best = Some(&c.bot_version);
        }
    }
    for e in &state.roster {
        if !e.version.is_empty()
            && e.bot_uuid == uuid
            && best
                .is_none_or(|b| update::version_cmp(&e.version, b) == std::cmp::Ordering::Greater)
        {
            best = Some(&e.version);
        }
    }
    best
}

fn rollup_hub_on(state: &HubState, uuid: &str, target: &str) -> bool {
    if uuid.is_empty() {
        return false; // a peer never heard from
    }
    if !state.hub_uuid.is_empty() && uuid == state.hub_uuid {
        return update::version_cmp(HUB_VERSION, target) != std::cmp::Ordering::Less;
    }
    state
        .mesh_hubs
        .iter()
        .find(|m| m.uuid == uuid)
        .is_some_and(|m| {
            !m.version.is_empty()
                && update::version_cmp(&m.version, target) != std::cmp::Ordering::Less
        })
}

/// Is anybody still owed the plan?  Every registered bot heard from on the
/// target or later and, when the run moved hubs, this hub, every configured
/// peer and every hub in the mesh map on the hub target.  A node that is down
/// is unknown here, so it keeps the plan alive -- that is what it is for.
fn rollup_owed(state: &HubState) -> bool {
    let r = &state.rollup;
    for b in &state.bots {
        if !b.is_active || b.entry("pub").is_none() {
            continue;
        }
        match rollup_bot_version(state, &b.uuid) {
            Some(v) if update::version_cmp(v, &r.target) != std::cmp::Ordering::Less => {}
            _ => return true,
        }
    }
    if r.hub_target.is_empty() {
        return false;
    }
    !rollup_hub_on(state, &state.hub_uuid, &r.hub_target)
        || state
            .peers
            .iter()
            .any(|p| !rollup_hub_on(state, &p.uuid, &r.hub_target))
        || state
            .mesh_hubs
            .iter()
            .any(|m| !rollup_hub_on(state, &m.uuid, &r.hub_target))
}

/// Drop a plan nobody is owed any more, or one past ROLLUP_PLAN_TTL.  Never
/// under a run or the freeze that announces one: a follower holds the
/// driver's plan from PREPARE on, long before the nodes have moved.
fn rollup_settle(state: &mut HubState, t_now: i64) {
    let r = &state.rollup;
    if !r.have_plan || r.active || state.upgrade.active || config_frozen(state) {
        return;
    }
    if r.plan_set > 0 && t_now - r.plan_set > ROLLUP_PLAN_TTL {
        rollup_forget(
            state,
            "expired: the stragglers never came back within 7 days",
        );
    } else if !rollup_owed(state) {
        rollup_forget(state, "complete: every bot and hub is on the target");
    }
}

/// Time out an attempt that went nowhere, and drop a plan nobody is owed.
/// Runs on the maintenance clock.
/// Hubs have no presence frame of their own here: the mesh gossip carries
/// each hub's version.  So once a maintenance tick, (a) end a hub attempt
/// whose hub is back on the step, and (b) consider ONE directly linked hub
/// that is behind the plan's hub target.  Of the hubs linked to a lagging
/// hub, only the one with the lowest uuid walks it, so two neighbours never
/// prepare it at once; a hub whose links are not known yet is walked by any.
fn rollup_scan_hubs(state: &mut HubState) {
    if !state.rollup.have_plan || state.rollup.hub_target.is_empty() {
        return;
    }
    if state.rollup.active {
        if state.rollup.node_kind != UpgradeNodeKind::PeerHub {
            return;
        }
        let back = state
            .mesh_hubs
            .iter()
            .find(|m| m.uuid == state.rollup.uuid)
            .filter(|m| {
                !m.version.is_empty()
                    && update::version_cmp(&m.version, &state.rollup.step)
                        != std::cmp::Ordering::Less
            })
            .map(|m| m.version.clone());
        if let Some(ver) = back {
            let uuid = state.rollup.uuid.clone();
            rollup_end(state, "back on the step it was given", false);
            rollup_consider(state, &uuid, UpgradeNodeKind::PeerHub, &ver);
        }
        return;
    }
    let lagging: Vec<(String, String)> = state
        .peers
        .iter()
        .filter(|p| p.connected && !p.uuid.is_empty())
        .filter_map(|p| state.mesh_hubs.iter().find(|m| m.uuid == p.uuid))
        .filter(|m| {
            !m.version.is_empty()
                && update::version_cmp(&m.version, &state.rollup.hub_target)
                    == std::cmp::Ordering::Less
                && !m.links.iter().any(|l| l.online && l.uuid < state.hub_uuid)
        })
        .map(|m| (m.uuid.clone(), m.version.clone()))
        .collect();
    for (uuid, ver) in lagging {
        rollup_consider(state, &uuid, UpgradeNodeKind::PeerHub, &ver);
        if state.rollup.active {
            return;
        }
    }
}

fn rollup_tick(state: &mut HubState, t_now: i64) {
    rollup_settle(state, t_now);
    rollup_scan_hubs(state);
    if !state.rollup.active {
        return;
    }
    // READY, and no word that it can stage: an older build.
    if state.rollup.ready_at > 0 && t_now - state.rollup.ready_at >= ROLLUP_STAGE_WAIT {
        rollup_commit(state);
        return;
    }
    if state.rollup.staging {
        if t_now - state.rollup.stage_last > UPGRADE_STAGE_SILENCE {
            rollup_end(state, "stage: no word from it", true);
        } else if t_now - state.rollup.started > UPGRADE_BUILD_SECS as i64 {
            rollup_end(state, "stage: past its limit", true);
        }
        return;
    }
    if t_now - state.rollup.started <= ROLLUP_TIMEOUT {
        return;
    }
    // On the step, but no done report: it came through a hub that cannot relay
    // it, or was lost.  The bot is not behind, so charge it nothing.
    let on_step = state.rollup.committed
        && state.rollup.node_kind == UpgradeNodeKind::Bot
        && rollup_bot_version(state, &state.rollup.uuid).is_some_and(|v| {
            update::version_cmp(v, &state.rollup.step) != std::cmp::Ordering::Less
        });
    if on_step {
        let who = state.who('\0', &state.rollup.uuid);
        crate::hlog_warning!(
            "[ROLLUP] {} is on {}, but no done report reached this hub\n",
            who,
            state.rollup.step
        );
        rollup_end(state, "on the step, no done report", false);
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
// Multi-step upgrades
// ---------------------------------------------------------------------------
//
// `upgrade start` to a version some node cannot reach in one go — it sits
// below that release's min_from — takes the intermediate releases the signed
// manifests name, one ordinary run per step.  The path is planned once, up
// front, from the oldest node of each product; each step's target is the
// newest release the previous one may install (update::next_step), so a
// release that floors nothing is skipped.  Every node finishes a step before
// any starts the next: a release's min_from is also what keeps a newer mesh
// from refusing nodes still on an older one (MESH_MIN_VERSION).
//
// Only this hub knows the plan, and it restarts onto each step itself, so the
// plan lives in its .irchub.cnf (uplan|, see config::write).  Nothing new
// goes on the wire: each step is a run like any other, which is what lets it
// move 2.4.x nodes that know nothing about plans.

/// A reply field only when it has a value.
fn opt(r: &mut Reply, k: &str, v: &str) {
    if !v.is_empty() {
        r.kv(k, v);
    }
}

/// The admin's selection resolved to "uuid,uuid,...", or "" for the whole
/// network.  A token that does not resolve is left out here: `start`
/// resolves the selection again and refuses it with the reason.
fn plan_sel_uuids(state: &HubState, sel: &str) -> String {
    if sel.is_empty() {
        return String::new();
    }
    let cands = candidates(state);
    sel.split([',', ' '])
        .filter(|t| !t.is_empty())
        .filter_map(|t| resolve(&cands, t.split('=').next().unwrap_or(t)).ok())
        .map(|c| c.uuid.clone())
        .collect::<Vec<_>>()
        .join(",")
}

/// The oldest version (and its build) among the nodes of one product a run
/// would move: bots — local and those the roster gossip reports — or hubs,
/// this one included.  Empty when no version is known.
fn plan_oldest(state: &HubState, hubs: bool, uuids: &str) -> (String, String) {
    let mut best: (String, String) = (String::new(), String::new());
    let mut consider = |uuid: &str, ver: &str, var: &str| {
        if !ver.is_empty()
            && (uuids.is_empty() || sel_lookup(uuids, uuid).is_some())
            && (best.0.is_empty() || update::version_cmp(ver, &best.0) == std::cmp::Ordering::Less)
        {
            best = (ver.to_string(), var.to_string());
        }
    };
    if hubs {
        consider(&state.hub_uuid, HUB_VERSION, update::host_variant());
        for m in &state.mesh_hubs {
            if !m.uuid.is_empty() && m.uuid != state.hub_uuid {
                consider(&m.uuid, &m.version, &m.variant);
            }
        }
    } else {
        for c in &state.clients {
            if c.typ == ClientType::Bot && c.authenticated {
                consider(&c.id, &c.bot_version, &c.bot_variant);
            }
        }
        for e in &state.roster {
            consider(&e.bot_uuid, &e.version, &e.variant);
        }
    }
    best
}

/// The steps from `from` to `target` along one release tree: each one the
/// newest release the previous may install.  Empty = nothing to do.  A
/// manifest this hub cannot read gives the one-step path a run always took:
/// the nodes still check min_from themselves.
fn plan_path(root: &str, variant: &str, from: &str, target: &str) -> Result<Vec<String>, String> {
    use std::cmp::Ordering::*;
    if from.is_empty() {
        return Ok(vec![target.to_string()]);
    }
    if update::version_cmp(from, target) != Less {
        return Ok(Vec::new());
    }
    let mut path: Vec<String> = Vec::new();
    let mut cur = from.to_string();
    while update::version_cmp(&cur, target) == Less {
        let step = match update::next_step(root, variant, &cur, target) {
            Ok(s) => strip_version_v(&s).to_string(),
            Err(_) if path.is_empty() => return Ok(vec![target.to_string()]),
            Err(e) => return Err(format!("no step from {cur} towards {target}: {e}")),
        };
        if update::version_cmp(&step, &cur) != Greater {
            return Err(format!(
                "no release in the manifest can be installed over {cur}"
            ));
        }
        if path.len() >= MAX_UPGRADE_STEPS {
            return Err(format!(
                "the path from {from} to {target} takes more than {MAX_UPGRADE_STEPS} steps — \
                 upgrade to an intermediate release first"
            ));
        }
        path.push(step.clone());
        cur = step;
    }
    Ok(path)
}

/// Plan both products' paths (the plan is not active yet).
fn plan_compute(
    state: &HubState,
    bot_ver: &str,
    hub_ver: &str,
    variant: &str,
    sel: &str,
) -> Result<UpgradePlan, String> {
    let mut p = UpgradePlan {
        bot_target: strip_version_v(bot_ver).to_string(),
        hub_target: strip_version_v(hub_ver).to_string(),
        ..Default::default()
    };
    let uuids = plan_sel_uuids(state, sel);
    let pick = |own: &str| -> String {
        if !variant.is_empty() {
            variant.to_string()
        } else if !own.is_empty() {
            own.to_string()
        } else {
            "c".to_string()
        }
    };
    let (from, var) = plan_oldest(state, false, &uuids);
    p.bot_path = plan_path(&update::bot_root(), &pick(&var), &from, &p.bot_target)?;
    p.bot_from = from;
    if !p.hub_target.is_empty() {
        let (from, var) = plan_oldest(state, true, &uuids);
        p.hub_path = plan_path("", &pick(&var), &from, &p.hub_target)?;
        p.hub_from = from;
    }
    Ok(p)
}

/// The targets of step `i`.  A product whose path is shorter sits the later
/// steps out: its final target, which every node of it already runs.
fn plan_step_targets(p: &UpgradePlan, i: usize) -> (String, String) {
    let at = |path: &[String], fin: &str| match path.len() {
        0 => fin.to_string(),
        n => path[i.min(n - 1)].clone(),
    };
    let bot = at(&p.bot_path, &p.bot_target);
    let hub = if p.hub_target.is_empty() {
        String::new()
    } else {
        at(&p.hub_path, &p.hub_target)
    };
    (bot, hub)
}

pub fn plan_stop(state: &mut HubState, summary: &str) {
    if !state.plan.active {
        return;
    }
    state.plan.active = false;
    state.plan.run_id.clear();
    state.plan.summary = clean(summary, 192);
    crate::hlog_info!(
        "[UPGRADE] Multi-step upgrade to {}{}{} stopped: {}\n",
        state.plan.bot_target,
        if state.plan.hub_target.is_empty() {
            ""
        } else {
            " / hubs "
        },
        state.plan.hub_target,
        state.plan.summary
    );
    plan_publish(state);
    crate::config::write(state);
}

/// One plan as a line, for uplan|, uplanr| and CMD_UPGRADE_PLAN alike:
///   bot_target|hub_target|variant|kind|step|run_id|started|progressed|bot_from|
///   hub_from|bot_path|hub_path|sel|reruns|self_target|hold_rerun|hold_uuid|
///   hold_ver|last_run|driver|rev|single|active|left|hold|summary|driver_name
/// Every field but hold and summary passes plan_field_ok, here and on the way in,
/// so the line can never split or inject another; hold and summary are free text.
/// driver_name is written empty when it would not pass, so a name can never keep a
/// plan off the wire.  A 13-field line is a 2.5.1 roll-up plan.
pub fn plan_format(p: &UpgradePlan) -> Option<String> {
    let fields = [
        &p.bot_target,
        &p.hub_target,
        &p.variant,
        &p.kind,
        &p.run_id,
        &p.bot_from,
        &p.hub_from,
        &p.sel,
        &p.self_target,
        &p.hold_uuid,
        &p.hold_ver,
        &p.last_run,
        &p.driver,
        &p.left,
    ];
    if !fields.iter().all(|f| plan_field_ok(f))
        || !p
            .bot_path
            .iter()
            .chain(&p.hub_path)
            .all(|v| plan_field_ok(v))
        || p.hold.contains(['|', '\r', '\n'])
        || p.summary.contains(['|', '\r', '\n'])
    {
        return None;
    }
    let dn = if p.driver_name.len() < 64 && plan_field_ok(&p.driver_name) {
        p.driver_name.as_str()
    } else {
        ""
    };
    Some(format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        p.bot_target,
        p.hub_target,
        p.variant,
        p.kind,
        p.step,
        p.run_id,
        p.started,
        p.progressed,
        p.bot_from,
        p.hub_from,
        p.bot_path.join(","),
        p.hub_path.join(","),
        p.sel,
        p.reruns,
        p.self_target,
        i32::from(p.hold_rerun),
        p.hold_uuid,
        p.hold_ver,
        p.last_run,
        p.driver,
        p.rev,
        i32::from(p.single),
        i32::from(p.active),
        p.left,
        p.hold,
        p.summary,
        dn
    ))
}

/// None unless the whole line is sound.
pub fn plan_parse(body: &str) -> Option<UpgradePlan> {
    let f: Vec<&str> = body.split('|').collect();
    // 13 fields: a 2.5.1 roll-up plan; 25: before the stop reason; 26: before the
    // driver's name; 27: now.
    if !matches!(f.len(), 13 | 25 | 26 | 27) || f[0].is_empty() {
        return None;
    }
    let caps: [(usize, usize); 15] = [
        (0, 64),
        (1, 64),
        (2, 8),
        (3, 8),
        (5, 64),
        (8, 64),
        (9, 64),
        (12, MAX_UPGRADE_SELECT * 80),
        (14, 64),
        (16, 64),
        (17, 64),
        (18, 64),
        (19, 64),
        (23, MAX_PLAN_LEFT * 37 + 1),
        (26, 64),
    ];
    for (at, cap) in caps {
        if let Some(x) = f.get(at)
            && (x.len() >= cap || !plan_field_ok(x))
        {
            return None;
        }
    }
    let path = |s: &str| -> Option<Vec<String>> {
        if s.is_empty() {
            return Some(Vec::new());
        }
        let p: Vec<String> = s.split(',').map(str::to_string).collect();
        (p.len() <= MAX_UPGRADE_STEPS
            && p.iter()
                .all(|x| !x.is_empty() && x.len() < 64 && plan_field_ok(x)))
        .then_some(p)
    };
    let get = |i: usize| f.get(i).copied().unwrap_or("").to_string();
    let mut p = UpgradePlan {
        active: true,
        bot_target: get(0),
        hub_target: get(1),
        variant: get(2),
        kind: get(3),
        run_id: get(5),
        started: crate::cstr::atoll(f[6]),
        progressed: crate::cstr::atoll(f[7]),
        bot_from: get(8),
        hub_from: get(9),
        bot_path: path(f[10])?,
        hub_path: path(f[11])?,
        sel: get(12),
        ..Default::default()
    };
    if f.len() >= 25 {
        p.reruns = crate::cstr::atoll(f[13]) as i32;
        p.self_target = get(14);
        p.hold_rerun = f[15].starts_with('1');
        p.hold_uuid = get(16);
        p.hold_ver = get(17);
        p.last_run = get(18);
        p.driver = get(19);
        p.rev = crate::cstr::atoll(f[20]);
        p.single = f[21].starts_with('1');
        p.active = f[22].starts_with('1');
        p.left = get(23);
        if f[24].len() >= 192 || f[24].contains(['\r', '\n']) {
            return None;
        }
        p.hold = get(24);
    }
    if f.len() >= 26 {
        if f[25].len() >= 192 || f[25].contains(['\r', '\n']) {
            return None;
        }
        p.summary = get(25);
        p.driver_name = get(26);
    }
    let step = crate::state::parse_uint(f[4], u64::MAX)? as usize;
    if p.single {
        return (step == 0).then_some(p);
    }
    if step >= p.bot_path.len().max(p.hub_path.len()) {
        return None;
    }
    p.step = step;
    Some(p)
}

/// A plan on hold: the network stays at the last closed step, every hub says why,
/// and it resumes when the named node reaches the step or on upgrade continue.
fn plan_hold(state: &mut HubState, why: &str, rerun: bool, uuid: &str, ver: &str) {
    if !state.plan.active {
        return;
    }
    state.plan.hold = clean(why, 192).replace('|', "/");
    state.plan.hold_rerun = rerun;
    state.plan.hold_uuid = uuid.to_string();
    state.plan.hold_ver = ver.to_string();
    state.plan.run_id.clear();
    state.plan.progressed = now();
    state.plan.next_at = 0;
    crate::hlog_warning!(
        "[UPGRADE] Upgrade to {} on hold at step {}/{}: {}\n",
        state.plan.bot_target,
        state.plan.step + 1,
        state.plan.steps(),
        state.plan.hold
    );
    plan_publish(state);
    crate::config::write(state);
}

/// The step is really finished: move on, or end.
fn plan_close_step(state: &mut HubState) {
    let steps = state.plan.steps();
    state.plan.reruns = 0;
    state.plan.progressed = now();
    if state.plan.step + 1 >= steps {
        plan_stop(state, &format!("done: all {steps} steps completed"));
        return;
    }
    state.plan.step += 1;
    state.plan.next_at = now() + UPGRADE_PLAN_SETTLE;
    state.plan.mesh_until = 0;
    plan_publish(state);
    crate::config::write(state);
    crate::hlog_info!(
        "[UPGRADE] Step {}/{steps} done; step {} starts in {UPGRADE_PLAN_SETTLE} s\n",
        state.plan.step,
        state.plan.step + 1
    );
}

/// What the mesh says a node runs right now, "" if it is not here.
/// What a candidate runs right now: this hub's own build, else what the mesh says.
fn node_version_now(state: &HubState, c: &Cand) -> String {
    if c.kind == UpgradeNodeKind::SelfHub {
        crate::consts::HUB_VERSION.to_string()
    } else {
        plan_node_version(state, &c.uuid)
    }
}

fn plan_node_version(state: &HubState, uuid: &str) -> String {
    for ci in state.bot_clients() {
        if state.clients[ci].id == uuid {
            return state.clients[ci].bot_version.clone();
        }
    }
    // A bot that moved hubs has an entry under each until the old one ages out: the
    // newest report is what it runs now.
    if let Some(e) = state
        .roster
        .iter()
        .filter(|e| e.bot_uuid == uuid)
        .max_by_key(|e| e.reported_at)
    {
        return e.version.clone();
    }
    state
        .peers
        .iter()
        .find(|p| p.uuid == uuid)
        .map_or(String::new(), |p| p.remote_version.clone())
}

/// How many nodes the last step finished have not come back.  It reads the step's
/// record, because the run table went with this hub's own restart.
fn plan_mesh_missing(state: &HubState) -> usize {
    let mut missing = state
        .peers
        .iter()
        .filter(|p| !p.uuid.is_empty() && !crate::presence::peer_is_linked(state, p))
        .count();
    if !state.plan.last_run.is_empty()
        && let Some(at) = crate::uhist::find(state, &state.plan.last_run)
        && let Some(v) = crate::uhist::parse(&state.uhist[at].body)
    {
        missing += v
            .nodes
            .iter()
            .filter(|n| {
                n.kind == "b" && n.state == "done" && plan_node_version(state, &n.uuid).is_empty()
            })
            .count();
    }
    missing
}

/// What history says about one node: its class and its usual times, newest record
/// first.  History orders and times.  It never decides: preflight asks the host.
#[derive(Default)]
struct NodePast {
    records: usize,
    bad: usize,
    restart: i64,
    stage_bin: i64,
    stage_src: i64,
    code: String,
    arch: String,
    libc: String,
    base: String,
    last: String,
}

fn node_past(state: &HubState, uuid: &str) -> NodePast {
    let mut p = NodePast::default();
    for rec in state.uhist.iter().rev() {
        if p.records >= UPGRADE_CLASS_RECORDS {
            break;
        }
        let Some(v) = crate::uhist::parse(&rec.body) else {
            continue;
        };
        let Some(n) = v.nodes.iter().find(|n| n.uuid == uuid) else {
            continue;
        };
        if matches!(n.state.as_str(), "already" | "skipped" | "idle") {
            continue;
        }
        if p.records == 0 {
            p.arch = n.arch.clone();
            p.libc = n.libc.clone();
            p.base = n.base.clone();
            p.last = trunc_string(if n.state == "done" { &n.to } else { &n.from }, 31);
        }
        p.records += 1;
        if p.records <= 3 {
            if n.state == "failed" || !n.code.is_empty() {
                p.bad += 1;
                if p.code.is_empty() {
                    p.code = n.code.clone();
                }
            }
            if n.back > n.committed && n.committed > 0 {
                p.restart = p.restart.max(n.back - n.committed);
            }
            if n.build == "src" {
                p.stage_src = p.stage_src.max(n.stage_s);
            } else {
                p.stage_bin = p.stage_bin.max(n.stage_s);
            }
        }
    }
    p
}

fn node_class(p: &NodePast) -> char {
    if p.bad > 0 {
        'p'
    } else if p.restart > UPGRADE_SLOW_RESTART || p.stage_src > 0 {
        's'
    } else if p.records >= 3 {
        'f'
    } else {
        'u'
    }
}

/// Limits from its own record: 3x its slowest, between a floor and the agreed
/// ceiling.  With too little to go on, the ceiling.  A known slow host is not failed
/// for being slow, and a fast host's failure shows sooner.
fn apply_history(state: &mut HubState) {
    for ni in 0..state.upgrade.nodes.len() {
        let p = node_past(state, &state.upgrade.nodes[ni].uuid);
        let n = &mut state.upgrade.nodes[ni];
        n.cls = node_class(&p);
        n.stage_limit = if p.stage_bin == 0 {
            UPGRADE_STAGE_GATE
        } else {
            (p.stage_bin * 3).clamp(UPGRADE_STAGE_FLOOR, UPGRADE_STAGE_GATE)
        };
        n.build_limit = if p.stage_src == 0 {
            UPGRADE_BUILD_SECS as i64
        } else {
            (p.stage_src * 3).clamp(UPGRADE_BUILD_FLOOR, UPGRADE_BUILD_SECS as i64)
        };
    }
}

/// Does every step have a build for this node's shape?  Only a shape history has seen
/// can be checked; anything else finds out at its PREPARE.  A step the node already
/// runs, or is past, needs nothing from it.
fn plan_node_blocked(is_bot: bool, p: &NodePast, cur: &str, pl: &UpgradePlan) -> Option<String> {
    if p.arch.is_empty() || p.base.is_empty() {
        return None;
    }
    let root = if is_bot {
        update::bot_root()
    } else {
        String::new()
    };
    let path = if is_bot { &pl.bot_path } else { &pl.hub_path };
    path.iter()
        .filter(|ver| cur.is_empty() || update::version_cmp(cur, ver).is_lt())
        .find(|ver| !update::has_build(&root, &p.base, ver, &p.arch, &p.libc))
        .map(|ver| format!("no {ver} build for {}/{}, and no source", p.arch, p.libc))
}

// ---- The shared plan ------------------------------------------------------
//
// Every hub keeps what the driver last published, so any of them can say what is
// going on, a restarted hub can carry on, and no hub chases a straggler between
// steps.  The driver alone changes it while it lives.  Older hubs drop the opcode
// and behave as they did, and are never asked to take over.

fn plan_send_all(state: &mut HubState, frame: &str, skip: Option<i32>) {
    for ci in 0..state.clients.len() {
        let c = &mut state.clients[ci];
        if c.typ == ClientType::Hub && c.authenticated && Some(c.fd) != skip {
            queue::send_urgent(c, CMD_UPGRADE_PLAN, frame);
        }
    }
}

fn plan_flood(state: &mut HubState, pl: &UpgradePlan, skip: Option<i32>) {
    if let Some(body) = plan_format(pl) {
        plan_send_all(state, &format!("P|{body}"), skip);
    }
}

/// This hub directs `pl`.  Its name rides along: a hub that boots mid-plan logs the
/// director before any link has told it who that is.
fn plan_stamp_driver(state: &HubState, pl: &mut UpgradePlan) {
    pl.driver = state.hub_uuid.clone();
    pl.driver_name =
        if state.hub_friendly_name.len() < 64 && plan_field_ok(&state.hub_friendly_name) {
            state.hub_friendly_name.clone()
        } else {
            String::new()
        };
}

fn plan_publish(state: &mut HubState) {
    let mut pl = std::mem::take(&mut state.plan);
    plan_stamp_driver(state, &mut pl);
    state.plan = pl;
    // Clock-based: a driver the failback rolled back has an older config and an older
    // rev.  A plain +1 could land on one the mesh already holds, and the hold it is
    // reporting would be dropped as old news.
    let t_now = now();
    state.plan.rev = if t_now > state.plan.rev {
        t_now
    } else {
        state.plan.rev + 1
    };
    state.splan = state.plan.clone();
    state.splan_seen = now();
    let p = state.plan.clone();
    plan_flood(state, &p, None);
}

/// A plain run is published too, so a lost driver cannot leave the mesh frozen.
fn plan_single_start(state: &mut HubState) {
    if state.plan.active {
        return;
    }
    let u = &state.upgrade;
    let mut s = UpgradePlan {
        active: true,
        single: true,
        bot_target: u.target_ver.clone(),
        hub_target: u.hub_ver.clone(),
        variant: u.variant.clone(),
        kind: u.kind.clone(),
        run_id: u.id.clone(),
        started: u.started,
        rev: state.splan.rev + 1,
        ..Default::default()
    };
    plan_stamp_driver(state, &mut s);
    state.splan = s.clone();
    state.splan_seen = now();
    plan_flood(state, &s, None);
}

fn plan_single_end(state: &mut HubState) {
    if !state.splan.active || !state.splan.single || state.splan.driver != state.hub_uuid {
        return;
    }
    state.splan.active = false;
    state.splan.rev += 1;
    let s = state.splan.clone();
    plan_flood(state, &s, None);
}

/// `upgrade abort` from anywhere ends the shared copy too: its driver may be gone.
/// Stop this hub's copy of a plan another hub drives, and say so to the rest.  The
/// director hears it too, on the next digest if not now: a stopped copy beats a
/// running one, so it stops as well.  Nothing is rolled back and nobody takes over.
fn splan_stop(state: &mut HubState, why: &str) {
    if !state.splan.active {
        return;
    }
    let t_now = now();
    state.splan.active = false;
    state.splan.rev = if t_now > state.splan.rev {
        t_now
    } else {
        state.splan.rev + 1
    };
    state.splan.summary = clean(why, 192);
    state.splan_seen = t_now;
    state.follow_id.clear();
    if config_frozen(state) {
        opt_flag_set(state, OPT_CONFIG_FROZEN, false);
    }
    crate::hlog_warning!(
        "[UPGRADE] The upgrade to {} driven by {} stopped here: {}\n",
        state.splan.bot_target,
        state.who('h', &state.splan.driver),
        state.splan.summary
    );
    let s = state.splan.clone();
    plan_flood(state, &s, None);
    crate::config::write(state);
}

pub fn plan_cancelled(state: &mut HubState, issued: i64) {
    if !state.splan.active || state.splan.started > issued || state.splan.driver == state.hub_uuid {
        return;
    }
    splan_stop(state, "aborted by an admin");
}

pub fn plan_send_digest(state: &mut HubState, ci: usize) {
    let frame = format!("D|{}|{}", state.splan.started, state.splan.rev);
    queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_PLAN, &frame);
}

/// Which copy of a plan stands, `a` over `b`.  The same plan (same start): a stopped
/// copy beats a running one, since a stop is final wherever it was decided, then the
/// higher rev.  Two different plans both running, only from a race or a split: the one
/// begun first stands.  Otherwise the later plan replaces an older one.
fn plan_beats(a: &UpgradePlan, b: &UpgradePlan) -> bool {
    if b.driver.is_empty() {
        return true;
    }
    if a.started == b.started {
        if a.active != b.active {
            return !a.active;
        }
        return a.rev > b.rev;
    }
    if a.active && b.active {
        return a.started < b.started;
    }
    a.started > b.started
}

/// A restarted hub picks up the run its copy names: it can carry COMMITs and "back"
/// reports again with no fresh PREPARE.
pub fn plan_boot(state: &mut HubState) {
    state.splan_seen = now();
    let s = state.splan.clone();
    if !s.active
        || s.run_id.is_empty()
        || s.driver.is_empty()
        || s.driver == state.hub_uuid
        || !state.follow_id.is_empty()
    {
        return;
    }
    let (bot, hub) = if s.single {
        (s.bot_target.clone(), s.hub_target.clone())
    } else {
        plan_step_targets(&s, s.step)
    };
    state.follow_id = s.run_id.clone();
    state.follow_origin = s.driver.clone();
    state.follow_target = bot;
    state.follow_hub_target = hub;
    state.follow_variant = s.variant.clone();
    state.follow_bot_variant = s.variant.clone();
    state.follow_self_ready = false;
    state.follow_prepared = now();
    crate::hlog_info!(
        "[UPGRADE] Back in run {}, driven by {}\n",
        s.run_id,
        state.who('h', &s.driver)
    );
}

/// Start or resume after an admin's word, on the driver.
fn plan_left_has(pl: &UpgradePlan, uuid: &str) -> bool {
    !uuid.is_empty() && pl.left.split(',').any(|u| u == uuid)
}

/// Remember the admin's word for the rest of the plan.  A list that is full, or a
/// uuid that does not fit, only means that node can hold the plan again.
fn plan_left_add(pl: &mut UpgradePlan, uuid: &str) {
    let count = if pl.left.is_empty() {
        0
    } else {
        pl.left.split(',').count()
    };
    if uuid.is_empty()
        || plan_left_has(pl, uuid)
        || count >= MAX_PLAN_LEFT
        || pl.left.len() + uuid.len() + 2 > MAX_PLAN_LEFT * 37 + 1
    {
        return;
    }
    if !pl.left.is_empty() {
        pl.left.push(',');
    }
    pl.left.push_str(uuid);
}

fn plan_continue(state: &mut HubState, by_admin: bool) {
    if !state.plan.active || state.plan.hold.is_empty() {
        return;
    }
    let rerun = state.plan.hold_rerun;
    crate::hlog_info!(
        "[UPGRADE] Upgrade to {} resumes: {}\n",
        state.plan.bot_target,
        if rerun {
            "running the step again"
        } else if by_admin {
            "leaving that node behind"
        } else {
            "that node reached the step"
        }
    );
    if by_admin && !rerun {
        let uuid = state.plan.hold_uuid.clone();
        plan_left_add(&mut state.plan, &uuid);
    }
    state.plan.hold.clear();
    state.plan.hold_uuid.clear();
    state.plan.hold_ver.clear();
    state.plan.hold_rerun = false;
    state.plan.reruns = 0;
    if rerun {
        state.plan.next_at = now() + UPGRADE_PLAN_SETTLE;
        state.plan.mesh_until = 0;
        plan_publish(state);
        crate::config::write(state);
    } else {
        plan_close_step(state);
    }
}

/// `upgrade continue`: the hold, wherever its driver is.  False if none is held.
pub fn plan_continue_cmd(state: &mut HubState) -> bool {
    let known = if state.plan.active {
        &state.plan
    } else {
        &state.splan
    };
    if !known.active || known.single || known.hold.is_empty() {
        return false;
    }
    let id = known.started;
    let t = now();
    crate::opflow::forward_seen_check_and_add(state, &format!("pc:{id}:{t}"));
    if state.plan.active {
        plan_continue(state, true);
    }
    plan_send_all(state, &format!("C|{id}|{t}"), None);
    true
}

/// CMD_UPGRADE_PLAN from a peer.
pub fn plan_process(state: &mut HubState, ci: usize, payload: &str) {
    state.clients[ci].plan_capable = true;
    let peer_fd = state.clients[ci].fd;
    let Some((kind, rest)) = payload.split_once('|') else {
        return;
    };
    let f: Vec<&str> = rest.splitn(4, '|').collect();
    let at = |i: usize| crate::cstr::atoll(f.get(i).copied().unwrap_or(""));
    match kind {
        // A different copy: send ours, and they send theirs.  Each keeps what
        // plan_beats() says stands, so both ends settle on the same one.
        "D" => {
            if !state.splan.driver.is_empty()
                && (state.splan.started != at(0) || state.splan.rev != at(1))
            {
                let s = state.splan.clone();
                plan_flood(state, &s, None);
            }
        }
        "B" => {
            if state.splan.started != at(0) || state.splan.rev != at(1) {
                return;
            }
            let key = format!(
                "pb:{}:{}",
                state.splan.driver,
                f.get(2).copied().unwrap_or("")
            );
            if crate::opflow::forward_seen_check_and_add(state, &key) {
                return;
            }
            state.splan_seen = now();
            plan_send_all(state, payload, Some(peer_fd));
        }
        "C" => {
            let key = format!(
                "pc:{}:{}",
                f.first().copied().unwrap_or(""),
                f.get(1).copied().unwrap_or("")
            );
            if crate::opflow::forward_seen_check_and_add(state, &key) {
                return;
            }
            if state.plan.started == at(0) {
                plan_continue(state, true);
            }
            plan_send_all(state, payload, Some(peer_fd));
        }
        "P" => {
            let Some(t) = plan_parse(rest) else {
                return;
            };
            if t.driver.is_empty() || !plan_beats(&t, &state.splan) {
                return;
            }
            if state.plan.active {
                if state.plan.started == t.started && !t.active {
                    // Stopped elsewhere (an admin, or the director given up for lost):
                    // stopped here too.  A run in flight finishes; no next step follows it.
                    crate::hlog_warning!(
                        "[UPGRADE] The upgrade to {} was stopped elsewhere ({}); it stops here too\n",
                        state.plan.bot_target,
                        t.summary
                    );
                    state.plan = Default::default();
                } else if state.plan.started != t.started && t.active {
                    // Two plans begun at once: the first one stands, and this one goes back.
                    crate::hlog_warning!(
                        "[UPGRADE] An upgrade to {} from {} began first; the upgrade to {} stops\n",
                        t.bot_target,
                        state.who('h', &t.driver),
                        state.plan.bot_target
                    );
                    state.plan = Default::default();
                    if state.upgrade.active {
                        abort(state, "another upgrade began first");
                    }
                }
            }
            state.splan = t.clone();
            state.splan_seen = now();
            crate::config::write(state);
            plan_flood(state, &t, Some(peer_fd));
        }
        _ => {}
    }
}

/// The driver has gone quiet: the reachable hub with the lowest uuid carries on.  A
/// partition can make one on each side, both walking the same path; rev settles it.
fn plan_watch(state: &mut HubState, t_now: i64) {
    if !state.splan.active || state.splan.driver.is_empty() {
        return;
    }
    if state.splan.driver == state.hub_uuid {
        if t_now - state.plan_beat >= UPGRADE_PLAN_BEAT {
            state.plan_beat = t_now;
            let frame = format!("B|{}|{}|{t_now}", state.splan.started, state.splan.rev);
            plan_send_all(state, &frame, None);
        }
        return;
    }
    #[cfg(feature = "test-hooks")]
    // A sandbox cannot wait 15 minutes for each run of its test.
    let silence = std::env::var("IRCHUB_TEST_DRIVER_SILENCE")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(UPGRADE_DRIVER_SILENCE);
    #[cfg(not(feature = "test-hooks"))]
    let silence = UPGRADE_DRIVER_SILENCE;
    if state.plan.active || t_now - state.splan_seen < silence {
        return;
    }
    // Linked to the director after all: its beats are only late.
    if hubs_reached(state).contains(&state.splan.driver) {
        return;
    }
    // One director: nobody takes over.  The plan stops; upgrade start carries on.
    let who = trunc_string(&state.who('h', &state.splan.driver), 60);
    let why = if state.splan.single {
        format!("director {who} lost")
    } else {
        format!(
            "director {who} lost at step {}/{}; upgrade start carries on",
            state.splan.step + 1,
            state.splan.steps()
        )
    };
    splan_stop(state, &why);
}

/// A bot that links during a run joins it, wherever it landed.  One still further
/// back answers unable, and the end of the step deals with that.
pub fn prepare_late(state: &mut HubState, ci: usize, version: &str) {
    if state.clients[ci].late_prepared || version.is_empty() {
        return;
    }
    let id = state.clients[ci].id.clone();
    let fd = state.clients[ci].fd;
    let u = &state.upgrade;
    if u.active
        && u.select.is_empty()
        && matches!(u.phase, UpgradePhase::Prepare | UpgradePhase::Rolling)
    {
        if find_node(state, &id).is_some()
            || update::version_cmp(version, &u.target_ver) != std::cmp::Ordering::Less
        {
            return;
        }
        let frame = format!(
            "{}|{}|{}|{}|{}|",
            u.id, u.target_ver, u.variant, u.kind, u.min_from
        );
        state.clients[ci].late_prepared = true;
        state.upgrade.nodes.push(UpgradeNode {
            uuid: id,
            kind: UpgradeNodeKind::Bot,
            state: UpgradeNodeState::Pending,
            fd,
            cur_version: version.to_string(),
            ..Default::default()
        });
        client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &frame);
    } else if !state.follow_id.is_empty()
        && config_frozen(state)
        && state.follow_sel.is_empty()
        && !state.follow_target.is_empty()
        && update::version_cmp(version, &state.follow_target) == std::cmp::Ordering::Less
    {
        let frame = format!(
            "{}|{}|{}||*|",
            state.follow_id, state.follow_target, state.follow_bot_variant
        );
        state.clients[ci].late_prepared = true;
        client::send_cmd_to_bot(&mut state.clients[ci], CMD_UPGRADE_PREPARE, &frame);
    }
}

/// Start step `plan.step` as an ordinary run.  Returns the run's message
/// ("OK..." or "ERROR: ...").
fn plan_start_step(state: &mut HubState, origin_fd: i32, min_from: &str) -> String {
    let (bot, hub) = plan_step_targets(&state.plan, state.plan.step);
    let (variant, kind, sel) = (
        state.plan.variant.clone(),
        state.plan.kind.clone(),
        state.plan.sel.clone(),
    );
    let msg = start(
        state,
        origin_fd,
        &StartArgs {
            target_ver: &bot,
            variant: &variant,
            kind: &kind,
            min_from,
            hub_ver: &hub,
            sel: &sel,
        },
    );
    if !msg.starts_with("OK") {
        return msg;
    }
    state.plan.run_id = state.upgrade.id.clone();
    state.plan.progressed = now();
    state.plan.next_at = 0;
    state.plan.mesh_until = 0;
    plan_publish(state);
    crate::config::write(state);
    crate::hlog_info!(
        "[UPGRADE] Step {}/{} of the upgrade to {}: run {} (bots -> {bot}{}{hub})\n",
        state.plan.step + 1,
        state.plan.steps(),
        state.plan.bot_target,
        state.plan.run_id,
        if hub.is_empty() { "" } else { ", hubs -> " }
    );
    msg
}

/// CMD_ADMIN_UPGRADE_NET: plan the path, then start its first step.  A
/// one-step path is exactly the run `upgrade start` always was, and keeps no
/// plan.  Returns the run's message ("OK..." or "ERROR: ...").
/// The hubs an upgrade would miss: every hub known here, from its own peers and from what
/// the others report, less those reached over live links from here.  Returns their names.
/// The hubs reached from here over live links, direct or through other hubs, by what
/// each reports of its own links.
pub fn hubs_reached(state: &HubState) -> Vec<String> {
    let usable = |u: &str| !u.is_empty() && u != "-" && u != state.hub_uuid;
    let mut reached: Vec<String> = state
        .peers
        .iter()
        .filter(|p| !p.uuid.is_empty() && crate::presence::peer_is_linked(state, p))
        .map(|p| p.uuid.clone())
        .collect();
    let mut r = 0;
    while r < reached.len() {
        if let Some(mh) = state.mesh_hubs.iter().find(|m| m.uuid == reached[r]) {
            for l in &mh.links {
                if l.online && usable(&l.uuid) && !reached.contains(&l.uuid) {
                    reached.push(l.uuid.clone());
                }
            }
        }
        r += 1;
    }
    reached
}

pub fn hubs_missing(state: &HubState) -> Vec<String> {
    let usable = |u: &str| !u.is_empty() && u != "-" && u != state.hub_uuid;
    let reached = hubs_reached(state);
    let mut named: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for p in &state.peers {
        if !p.uuid.is_empty() && reached.contains(&p.uuid) {
            continue;
        }
        if !p.uuid.is_empty() {
            named.push(&p.uuid);
        }
        out.push(if p.friendly_name.is_empty() {
            p.ip.clone()
        } else {
            p.friendly_name.clone()
        });
    }
    for mh in &state.mesh_hubs {
        for l in &mh.links {
            if usable(&l.uuid) && !reached.contains(&l.uuid) && !named.contains(&l.uuid.as_str()) {
                named.push(&l.uuid);
                out.push(if l.name.is_empty() {
                    l.uuid.clone()
                } else {
                    l.name.clone()
                });
            }
        }
    }
    out
}

pub fn plan_begin(state: &mut HubState, origin_fd: i32, a: &StartArgs) -> String {
    if state.plan.active {
        return format!(
            "ERROR: a multi-step upgrade to {} is in progress (step {}/{}) — upgrade abort stops it",
            state.plan.bot_target,
            state.plan.step + 1,
            state.plan.steps()
        );
    }
    if a.target_ver.is_empty()
        || !plan_field_ok(a.target_ver)
        || a.target_ver.len() >= 64
        || a.hub_ver.len() >= 64
        || !plan_field_ok(a.hub_ver)
        || a.hub_ver.contains(',')
    {
        // let the run refuse it with its own words
        return start(state, origin_fd, a);
    }
    let mut np = match plan_compute(state, a.target_ver, a.hub_ver, a.variant, a.sel) {
        Ok(p) => p,
        Err(why) => return format!("ERROR: {why}"),
    };
    // A build missing for a host history knows: refused now, not part way up.
    if a.sel.is_empty() {
        for c in candidates(state) {
            let is_bot = c.kind == UpgradeNodeKind::Bot;
            if !is_bot && a.hub_ver.is_empty() {
                continue;
            }
            let cur = node_version_now(state, &c);
            if let Some(why) = plan_node_blocked(is_bot, &node_past(state, &c.uuid), &cur, &np) {
                let who = if c.name.is_empty() { &c.uuid } else { &c.name };
                let on = if cur.is_empty() { "?" } else { cur.as_str() };
                return format!(
                    "ERROR: {} (on {}): {why}",
                    trunc_string(who, 60),
                    trunc_string(on, 24)
                );
            }
        }
    }
    if np.steps() <= 1 {
        return start(state, origin_fd, a);
    }
    if a.variant.len() >= 8
        || a.kind.len() >= 8
        || a.sel.len() >= MAX_UPGRADE_SELECT * 80
        || !plan_field_ok(a.sel)
    {
        return "ERROR: bad variant, kind or selection".to_string();
    }
    np.variant = a.variant.to_string();
    np.kind = a.kind.to_string();
    np.sel = a.sel.to_string();
    np.started = now();
    np.active = true;
    state.plan = np;
    let msg = plan_start_step(state, origin_fd, a.min_from);
    if !msg.starts_with("OK") {
        state.plan = UpgradePlan::default();
    }
    msg
}

/// A run ended; if it was a step of the plan, decide what follows.  A step
/// that left a node behind — one that answered, is not on the step, and
/// could not take it — stops the plan there: the next step would move the
/// rest of the mesh past a version that node can still talk to.  A node that
/// never answered (down) does not: the roll-up walks it up afterwards.
fn plan_note_run_end(state: &mut HubState, phase: UpgradePhase) {
    if !state.plan.active || state.plan.run_id.is_empty() || state.plan.run_id != state.upgrade.id {
        return;
    }
    let steps = state.plan.steps();
    let step = state.plan.step;
    state.plan.last_run = state.plan.run_id.clone();
    state.plan.run_id.clear();
    state.plan.progressed = now();
    if (phase != UpgradePhase::Done && phase != UpgradePhase::Partial)
        || state.upgrade.build_stopped
    {
        let why = format!(
            "step {}/{steps} {}: {}",
            step + 1,
            phase.name(),
            state.upgrade.summary
        );
        state.plan.self_target.clear();
        plan_hold(state, &why, true, "", "");
        return;
    }
    if step + 1 < steps {
        let (next_bot, next_hub) = plan_step_targets(&state.plan, step + 1);
        for ni in 0..state.upgrade.nodes.len() {
            let n = state.upgrade.nodes[ni].clone();
            if n.not_selected
                || plan_left_has(&state.plan, &n.uuid)
                || !matches!(n.state, UpgradeNodeState::Unable | UpgradeNodeState::Failed)
            {
                continue;
            }
            let is_bot = n.kind == UpgradeNodeKind::Bot;
            if n.cur_version.is_empty() && n.state == UpgradeNodeState::Unable {
                crate::hlog_warning!(
                    "[UPGRADE] {} never answered step {}/{steps}; if the next step leaves it below its floor it must be upgraded by hand\n",
                    state.who(if is_bot { 'b' } else { 'h' }, &n.uuid),
                    step + 1
                );
                continue;
            }
            let to = node_target(&state.upgrade, ni).to_string();
            if to.is_empty() || update::version_cmp(&n.cur_version, &to) != std::cmp::Ordering::Less
            {
                continue;
            }
            let want = if is_bot { &next_bot } else { &next_hub };
            let final_ver = if is_bot {
                state.plan.bot_target.clone()
            } else {
                state.plan.hub_target.clone()
            };
            let root = if is_bot {
                update::bot_root()
            } else {
                String::new()
            };
            let variant = if !state.plan.variant.is_empty() {
                state.plan.variant.clone()
            } else if !n.variant.is_empty() {
                n.variant.clone()
            } else {
                "c".to_string()
            };
            let reach = !want.is_empty()
                && update::next_step(&root, &variant, &n.cur_version, &final_ver).is_ok_and(|v| {
                    update::version_cmp(strip_version_v(&v), want) != std::cmp::Ordering::Less
                });
            if !reach {
                let why = format!(
                    "step {}/{steps} left {} behind on {} ({}), and the next step would lock it out",
                    step + 1,
                    trunc_string(if n.name.is_empty() { &n.uuid } else { &n.name }, 40),
                    trunc_string(&n.cur_version, 20),
                    trunc_string(&n.reason, 60)
                );
                plan_hold(state, &why, false, &n.uuid, &to);
                return;
            }
        }
    }
    if !state.plan.self_target.is_empty() {
        plan_publish(state);
        crate::config::write(state);
        return;
    }
    plan_close_step(state);
}

/// Drive the plan between its steps (maintenance clock).
fn plan_tick(state: &mut HubState, t_now: i64) {
    plan_watch(state, t_now);
    if !state.plan.active || state.upgrade.active {
        return;
    }
    if !state.plan.self_target.is_empty() {
        // This hub restarted onto the step.  Its first link confirms it; the
        // failback undoes it if none comes, and then this is the old build,
        // reading this.
        let linked = state.peers.is_empty()
            || state
                .peers
                .iter()
                .any(|p| crate::presence::peer_is_linked(state, p));
        let same =
            update::version_cmp(HUB_VERSION, &state.plan.self_target) == std::cmp::Ordering::Equal;
        if same && !linked && t_now - state.plan.progressed < UPGRADE_CONFIRM_SECS as i64 {
            return;
        }
        let want = std::mem::take(&mut state.plan.self_target);
        if !same {
            let note = update::failback_note().unwrap_or_else(|| "no reason left".to_string());
            let why = format!(
                "this hub is back on {HUB_VERSION}, not {want}: {}",
                trunc_string(&note, 180)
            );
            plan_hold(state, &why, true, "", "");
            return;
        }
        if state.plan.hold.is_empty() {
            plan_close_step(state);
        } else {
            crate::config::write(state);
        }
        return;
    }
    if !state.plan.hold.is_empty() {
        if state.plan.progressed > 0 && t_now - state.plan.progressed > UPGRADE_PLAN_TTL {
            let why = format!(
                "stopped at step {} of {}: {}",
                state.plan.step + 1,
                state.plan.steps(),
                trunc_string(&state.plan.hold, 200)
            );
            plan_stop(state, &why);
            return;
        }
        if !state.plan.hold_uuid.is_empty() && !state.plan.hold_ver.is_empty() {
            let v = plan_node_version(state, &state.plan.hold_uuid);
            if !v.is_empty()
                && update::version_cmp(&v, &state.plan.hold_ver) != std::cmp::Ordering::Less
            {
                plan_continue(state, false);
            }
        }
        return;
    }
    if !state.plan.run_id.is_empty() {
        // A step was in flight when this hub went down: its run table went
        // with the old process.  The freeze it set is still up — lift it —
        // and run the step again; nodes already on it answer that they are.
        crate::hlog_warning!(
            "[UPGRADE] Step {}/{} (run {}) was cut off by a restart; running it again\n",
            state.plan.step + 1,
            state.plan.steps(),
            state.plan.run_id
        );
        if config_frozen(state) {
            opt_flag_set(state, OPT_CONFIG_FROZEN, false);
        }
        state.plan.run_id.clear();
        state.plan.reruns += 1;
        if state.plan.reruns > UPGRADE_PLAN_RERUNS {
            let why = format!(
                "step {}/{} was cut off by a restart {} times",
                state.plan.step + 1,
                state.plan.steps(),
                state.plan.reruns
            );
            plan_hold(state, &why, true, "", "");
            return;
        }
        state.plan.next_at = t_now + UPGRADE_PLAN_SETTLE;
        crate::config::write(state);
        return;
    }
    if state.plan.next_at == 0 {
        // just booted (onto a step, typically): let the mesh come back first
        state.plan.next_at = t_now + UPGRADE_PLAN_SETTLE;
        return;
    }
    if state.plan.progressed > 0 && t_now - state.plan.progressed > UPGRADE_PLAN_TTL {
        plan_stop(state, "no progress for a day; start the upgrade again");
        return;
    }
    if t_now < state.plan.next_at || config_frozen(state) || state.rollup.active {
        return;
    }
    // Steps wait for the mesh, not a clock: a bot still relinking would otherwise
    // miss the next run's table.
    #[cfg(feature = "test-hooks")]
    // As for the driver silence: a sandbox cannot sit out the whole wait on each step.
    let mesh_wait = std::env::var("IRCHUB_TEST_PLAN_MESH_WAIT")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(UPGRADE_PLAN_MESH_WAIT);
    #[cfg(not(feature = "test-hooks"))]
    let mesh_wait = UPGRADE_PLAN_MESH_WAIT;
    if state.plan.mesh_until == 0 {
        state.plan.mesh_until = t_now + mesh_wait;
    }
    // A step starts with every hub, as the plan did.  One still gone after the wait
    // ends the plan here; upgrade start carries on from this step later.
    let Some(gone) = crate::rollcall::plan_hubs_answered(state) else {
        return; // the hubs are being asked
    };
    if !gone.is_empty() {
        if t_now < state.plan.mesh_until {
            return;
        }
        let why = format!(
            "step {}/{} needs every hub; {} missing: {}; upgrade start carries on",
            state.plan.step + 1,
            state.plan.steps(),
            gone.len(),
            trunc_string(&gone.join(", "), 319)
        );
        plan_stop(state, &why);
        return;
    }
    let missing = plan_mesh_missing(state);
    if missing > 0 {
        if t_now < state.plan.mesh_until {
            return;
        }
        crate::hlog_warning!(
            "[UPGRADE] {missing} node(s) still missing after {mesh_wait} s; step {}/{} starts without them\n",
            state.plan.step + 1,
            state.plan.steps()
        );
    }
    let msg = plan_start_step(state, -1, "");
    if !msg.starts_with("OK") {
        let why = format!(
            "step {}/{} could not start: {}",
            state.plan.step + 1,
            state.plan.steps(),
            trunc_string(msg.strip_prefix("ERROR: ").unwrap_or(&msg), 140)
        );
        plan_hold(state, &why, true, "", "");
    }
}

/// Tell every hub to stop whatever upgrade it drives: an UPGRADE_FORGET
/// flagged "A" (abort), id|ts|A|issued.  `issued` is when the admin typed it:
/// a run or plan started after that is not the one meant.
pub fn cancel_flood(state: &mut HubState) -> i64 {
    let id = opflow::generate_request_id();
    opflow::forward_seen_check_and_add(state, &id);
    let t = now();
    state.upgrade_cancel_id = id.clone();
    state.upgrade_cancel_issued = t;
    state.upgrade_cancel_seen = t;
    let fwd = format!("{id}|{t}|A|{t}");
    let mut told = 0;
    for pi in state.peer_clients() {
        if queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_FORGET, &fwd) {
            told += 1;
        }
    }
    told
}

/// "releases|bot_ver|hub_ver|sel": the path `upgrade start` would take, for
/// the console's confirmation card.
fn plan_preview(state: &HubState, payload: &str, r: &mut Reply) {
    if payload.as_bytes().get(8) != Some(&b'|') {
        return;
    }
    let f: Vec<&str> = payload.splitn(4, '|').collect();
    let (bot, hub, sel) = (
        f.get(1).copied().unwrap_or(""),
        f.get(2).copied().unwrap_or(""),
        f.get(3).copied().unwrap_or(""),
    );
    if bot.is_empty()
        || bot.len() >= 64
        || !plan_field_ok(bot)
        || hub.len() >= 64
        || !plan_field_ok(hub)
    {
        return;
    }
    let res = plan_compute(state, bot, hub, "", sel);
    // What is known before anything is touched: who is who, and whether every step
    // has a build for every host history knows the shape of.
    if let Ok(pl) = &res {
        for c in candidates(state) {
            let is_bot = c.kind == UpgradeNodeKind::Bot;
            if !is_bot && hub.is_empty() {
                continue;
            }
            let p = node_past(state, &c.uuid);
            r.rec("past");
            r.kv("name", if c.name.is_empty() { &c.uuid } else { &c.name });
            r.kv("class", &node_class(&p).to_string());
            r.kvi("restart", p.restart);
            r.kvi("stage_bin", p.stage_bin);
            r.kvi("stage_src", p.stage_src);
            opt(r, "code", &p.code);
            if is_bot && plan_node_version(state, &c.uuid).is_empty() {
                r.kvb("down", true);
                opt(r, "last", &p.last);
            }
            if let Some(why) = plan_node_blocked(is_bot, &p, &node_version_now(state, &c), pl) {
                r.kv("blocked", &why);
            }
        }
    }
    r.rec("path");
    r.kv("product", "bot");
    match &res {
        Ok(p) => {
            opt(r, "from", &p.bot_from);
            opt(r, "steps", &p.bot_path.join(","));
            if !hub.is_empty() {
                r.rec("path");
                r.kv("product", "hub");
                opt(r, "from", &p.hub_from);
                opt(r, "steps", &p.hub_path.join(","));
            }
        }
        Err(why) => r.kv("err", why),
    }
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

/// A bot seen back on the target whose "ok" never came (lost, or it could not
/// get its ops back) is done once UPGRADE_OPS_GRACE has passed: it is
/// running the new build, which is what the run is about (Addendum A1).
fn ops_grace(state: &mut HubState, now_ts: i64) {
    for ni in 0..state.upgrade.nodes.len() {
        let n = &state.upgrade.nodes[ni];
        if n.state == UpgradeNodeState::Committed
            && n.back_at > 0
            && now_ts - n.back_at > UPGRADE_OPS_GRACE
        {
            let who = state.who('\0', &n.uuid);
            let n = &mut state.upgrade.nodes[ni];
            n.state = UpgradeNodeState::Done;
            n.done_at = now_ts;
            n.reason = "back on target; no ready report".to_string();
            crate::hlog_info!("[UPGRADE] {who} back on target; no ready report\n");
        }
    }
}

/// Production crontab lines: this hub's own, and each of its bots' orders.
fn cron_tick(state: &mut HubState) {
    update::cron_set(crate::revoke::cron_wanted(state, 'h', &state.hub_uuid));
    let exe = state.executable_path.clone();
    if update::cron_tick(&exe) {
        state.tree_dirty = true;
    }
    for ci in state.bot_clients() {
        let c = &state.clients[ci];
        if c.retiring || c.bot_version.is_empty() {
            continue;
        }
        let want = i32::from(crate::revoke::cron_wanted(state, 'b', &c.id));
        if c.cron_sent == want + 1 {
            continue;
        }
        let text = if want == 1 { "on" } else { "off" };
        if crate::client::send_cmd_to_bot(&mut state.clients[ci], CMD_CRON_SET, text) {
            state.clients[ci].cron_sent = want + 1;
        }
    }
}

/// The next bot to swap: staged (or with nothing to stage), and in class order.
fn next_bot(u: &crate::state::PendingUpgrade) -> Option<usize> {
    for c in ['f', 'u', 's', 'p'] {
        if let Some(i) = u.nodes.iter().position(|n| {
            n.state == UpgradeNodeState::Ready
                && n.kind == UpgradeNodeKind::Bot
                && (!n.can_stage || n.staged)
                && (if n.cls == '\0' { 'u' } else { n.cls }) == c
        }) {
            return Some(i);
        }
    }
    None
}

fn same_build(a: &UpgradeNode, b: &UpgradeNode) -> bool {
    a.kind == b.kind && a.variant == b.variant && a.arch == b.arch && a.libc == b.libc
}

/// No node of this build has come through yet: the next goes alone.  A problem host
/// always goes alone.
fn build_unproven(u: &crate::state::PendingUpgrade, ni: usize) -> bool {
    let n = &u.nodes[ni];
    if n.cls == 'p' {
        return true;
    }
    !u.nodes
        .iter()
        .enumerate()
        .any(|(i, o)| i != ni && o.state == UpgradeNodeState::Done && same_build(o, n))
}

/// Who has left the stage, and is the release itself bad?  True when the run ended.
fn stage_watch(state: &mut HubState, t_now: i64) -> bool {
    let mut left = 0;
    let mut touched = 0;
    for ni in 0..state.upgrade.nodes.len() {
        let n = &state.upgrade.nodes[ni];
        if !n.not_selected && n.state != UpgradeNodeState::Unable {
            touched += 1;
        }
        if n.left {
            left += 1;
            touched += 1;
        }
        if n.state != UpgradeNodeState::Ready || !n.can_stage || n.staged {
            continue;
        }
        let limit = if n.is_src {
            if n.build_limit > 0 {
                n.build_limit
            } else {
                UPGRADE_BUILD_SECS as i64
            }
        } else {
            n.stage_limit
        };
        let silent =
            n.kind != UpgradeNodeKind::SelfHub && t_now - n.stage_last > UPGRADE_STAGE_SILENCE;
        if !silent && t_now - n.stage_sent <= limit {
            continue;
        }
        let who = state.who(
            if n.kind == UpgradeNodeKind::Bot {
                '\0'
            } else {
                'h'
            },
            &n.uuid,
        );
        let id = state.upgrade.id.clone();
        let n = &mut state.upgrade.nodes[ni];
        n.state = UpgradeNodeState::Unable;
        n.left = true;
        left += 1;
        n.stage_code = if silent { "silent" } else { "limit" }.to_string();
        n.reason = if silent {
            format!("stage: no word for {UPGRADE_STAGE_SILENCE} s")
        } else {
            format!(
                "stage: still {} at its {limit} s limit",
                if n.stage_phase.is_empty() {
                    "going"
                } else {
                    &n.stage_phase
                }
            )
        };
        crate::hlog_warning!("[UPGRADE] {who} left run {id}: {}\n", n.reason);
    }
    if left >= 2 && left * 100 > touched * UPGRADE_STOP_PERCENT {
        abort(
            state,
            &format!(
                "{left} of {touched} nodes could not stage it: something is wrong beyond one host, and nothing has changed"
            ),
        );
        return true;
    }
    false
}

/// What failures mean.  One host failing leaves the run; the rest go on.  Two on one
/// build stop that build and undo it.  A quarter of the network stops everything, and
/// a peer hub failing stops the hubs.  A host with a bad history counts for nothing:
/// its failure says little about the build.  True when the run ended.
fn weigh_failures(state: &mut HubState) -> bool {
    let (mut failed, mut touched) = (0, 0);
    for n in state.upgrade.nodes.iter().filter(|n| !n.not_selected) {
        if n.state != UpgradeNodeState::Unable {
            touched += 1;
        }
        if n.state == UpgradeNodeState::Failed && n.cls != 'p' {
            failed += 1;
        }
    }
    if failed >= 2 && failed * 100 > touched * UPGRADE_STOP_PERCENT {
        abort(state, "too many nodes failed: stopping everything");
        return true;
    }
    for ni in 0..state.upgrade.nodes.len() {
        if state.upgrade.nodes[ni].state != UpgradeNodeState::Failed
            || state.upgrade.nodes[ni].counted
        {
            continue;
        }
        state.upgrade.nodes[ni].counted = true;
        let n = state.upgrade.nodes[ni].clone();
        crate::hlog_warning!(
            "[UPGRADE] {} failed: {}\n",
            state.who(
                if n.kind == UpgradeNodeKind::Bot {
                    '\0'
                } else {
                    'h'
                },
                &n.uuid
            ),
            n.reason
        );
        if n.kind == UpgradeNodeKind::PeerHub {
            state.upgrade.hubs_stopped = true;
            for o in &mut state.upgrade.nodes {
                if o.state == UpgradeNodeState::Ready && o.kind != UpgradeNodeKind::Bot {
                    o.state = UpgradeNodeState::Unable;
                    o.reason = "a peer hub failed: no more hubs move".to_string();
                }
            }
            continue;
        }
        if n.cls == 'p' {
            continue;
        }
        let same = state
            .upgrade
            .nodes
            .iter()
            .filter(|o| o.state == UpgradeNodeState::Failed && o.cls != 'p' && same_build(o, &n))
            .count();
        if same < 2 {
            continue;
        }
        // Stop this build: nothing more of it moves, and what moved comes back.
        state.upgrade.build_stopped = true;
        let why = format!(
            "{same} nodes of the {} {}/{} build failed",
            n.variant, n.arch, n.libc
        );
        let id = state.upgrade.id.clone();
        crate::hlog_warning!("[UPGRADE] {why}: stopping that build\n");
        for ki in 0..state.upgrade.nodes.len() {
            let o = state.upgrade.nodes[ki].clone();
            if !same_build(&o, &n) {
                continue;
            }
            if o.state == UpgradeNodeState::Ready {
                state.upgrade.nodes[ki].state = UpgradeNodeState::Unable;
                state.upgrade.nodes[ki].reason = why.clone();
            } else if matches!(
                o.state,
                UpgradeNodeState::Done | UpgradeNodeState::Committed
            ) {
                if !o.via.is_empty() {
                    if let Some(pi) = find_client_hub(state, &o.via) {
                        queue::send_urgent(
                            &mut state.clients[pi],
                            CMD_UPGRADE_ABORT,
                            &format!("{id}|{}|{why}", o.uuid),
                        );
                    }
                } else if let Some(ci) = find_client(state, &o.uuid, ClientType::Bot) {
                    client::send_cmd_to_bot(
                        &mut state.clients[ci],
                        CMD_UPGRADE_ABORT,
                        &format!("{id}|{why}"),
                    );
                }
                let k = &mut state.upgrade.nodes[ki];
                k.state = UpgradeNodeState::Failed;
                k.counted = true;
                k.reason = format!("rolled back: {}", trunc_string(&why, 100));
            }
        }
    }
    false
}

/// CMD_UPGRADE_PROGRESS: id|uuid|phase|code|note
/// A note of "72%", "40% 18 of 45 files" or "~60% 120 of 200 crates", while a node
/// fetches or builds.  Anything else is no measure of how far it has got.
fn stage_note_read(phase: &str, note: &str) -> (String, String) {
    let none = (String::new(), String::new());
    if phase != "fetching" && phase != "building" {
        return none;
    }
    let at = usize::from(note.starts_with('~'));
    let b = note.as_bytes();
    let digits = b[at..]
        .iter()
        .take(4)
        .take_while(|c| c.is_ascii_digit())
        .count();
    if digits == 0 || digits > 3 || b.get(at + digits) != Some(&b'%') {
        return none;
    }
    if crate::cstr::atoll(&note[at..at + digits]) > 100 {
        return none;
    }
    let rest = &note[at + digits + 1..];
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    (note[..=at + digits].to_string(), clean(rest, 48))
}

pub fn note_progress(state: &mut HubState, payload: &str) {
    if rollup_note_progress(state, payload) {
        return;
    }
    let f: Vec<&str> = payload.splitn(6, '|').collect();
    if f.len() < 3 {
        return;
    }
    let (id, uuid, phase) = (f[0], f[1], f[2]);
    let code = f.get(3).copied().unwrap_or("");
    let note = f.get(4).copied().unwrap_or("");
    if !state.upgrade.active || state.upgrade.id != id {
        return;
    }
    let Some(ni) = find_node(state, uuid) else {
        return;
    };
    let plan_open = state.upgrade.phase == UpgradePhase::Prepare;
    let n = &mut state.upgrade.nodes[ni];
    if phase == "ready" {
        n.can_stage = plan_open; // too late to stage: the old path
        return;
    }
    n.stage_last = now();
    n.stage_phase = trunc_string(phase, 16);
    (n.stage_pct, n.stage_detail) = stage_note_read(phase, note);
    if phase == "building" || code == "src" {
        n.is_src = true;
    }
    if n.state != UpgradeNodeState::Ready {
        return;
    }
    if phase == "staged" {
        n.staged = true;
        n.staged_at = now();
    } else if phase == "failed" {
        n.stage_code = trunc_string(code, 16);
        let why = format!("{}: {note}", if code.is_empty() { "stage" } else { code });
        n.state = UpgradeNodeState::Unable;
        n.reason = clean(&why, 128);
        // A signature or hash that does not hold is the release's fault, not this
        // host's.
        if code == "sig" || code == "hash" {
            abort(
                state,
                &format!("the release is bad: {}", trunc_string(&why, 200)),
            );
            return;
        }
        n.left = true;
        let r = n.reason.clone();
        let who = state.who('\0', uuid);
        crate::hlog_warning!("[UPGRADE] {who} left run {id}: {r}\n");
    }
}

/// A hub's STAGE: on to its own bots and peers, and itself if it is in the run.
pub fn process_peer_stage(state: &mut HubState, ci: usize, payload: &str) {
    let id = payload.split('|').next().unwrap_or("");
    if id.is_empty()
        || crate::opflow::forward_seen_check_and_add(state, &format!("st:{}", trunc_string(id, 60)))
    {
        return;
    }
    for i in 0..state.clients.len() {
        let c = &mut state.clients[i];
        if i == ci || !c.authenticated {
            continue;
        }
        if c.typ == ClientType::Bot {
            client::send_cmd_to_bot(c, CMD_UPGRADE_STAGE, id);
        } else if c.typ == ClientType::Hub {
            queue::send_urgent(c, CMD_UPGRADE_STAGE, id);
        }
    }
    if state.follow_id == id && state.follow_self_ready && !state.follow_hub_target.is_empty() {
        let (ver, variant) = (
            state.follow_hub_target.clone(),
            state.follow_variant.clone(),
        );
        update::stage_start(id, &ver, &variant);
    }
}

/// This hub's own stage: into the run it drives, or up to whoever does.
fn stage_tick(state: &mut HubState) {
    let Some((id, status)) = update::stage_tick() else {
        return;
    };
    let payload = format!("{id}|{}|{status}", state.hub_uuid);
    if state.follow_id == id {
        let origin = state.follow_origin.clone();
        if let Some(oi) = find_client_hub(state, &origin) {
            queue::send_urgent(&mut state.clients[oi], CMD_UPGRADE_PROGRESS, &payload);
            return;
        }
    }
    note_progress(state, &payload);
}

/// One step per maintenance tick.  A no-op unless a run is active.
pub fn tick(state: &mut HubState, now_ts: i64) {
    // A hub with no peers to link to has nothing more to prove than being up.
    if state.peers.is_empty() {
        update::failback_confirm();
    }
    cron_tick(state);
    stage_tick(state);
    rollup_tick(state, now_ts);
    plan_tick(state, now_ts);
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
        // Get the build ready everywhere first, while nothing has changed.  A node
        // that never said it can stage takes the old path at COMMIT.
        apply_history(state);
        let mut staging = 0;
        let (id, hub_ver) = (state.upgrade.id.clone(), state.upgrade.hub_ver.clone());
        for ni in 0..state.upgrade.nodes.len() {
            let is_self = state.upgrade.nodes[ni].kind == UpgradeNodeKind::SelfHub;
            let n = &mut state.upgrade.nodes[ni];
            if is_self && n.state == UpgradeNodeState::Ready {
                n.can_stage = true;
            }
            if n.state != UpgradeNodeState::Ready || !n.can_stage {
                continue;
            }
            n.stage_sent = now_ts;
            n.stage_last = now_ts;
            if n.stage_limit == 0 {
                n.stage_limit = UPGRADE_STAGE_GATE;
            }
            staging += 1;
            if is_self {
                let variant = node_variant(&state.upgrade, ni).to_string();
                update::stage_start(&id, &hub_ver, &variant);
            }
        }
        if staging > 0 {
            crate::opflow::forward_seen_check_and_add(
                state,
                &format!("st:{}", trunc_string(&id, 60)),
            );
            for ci in 0..state.clients.len() {
                let c = &mut state.clients[ci];
                if !c.authenticated {
                    continue;
                }
                if c.typ == ClientType::Bot {
                    client::send_cmd_to_bot(c, CMD_UPGRADE_STAGE, &id);
                } else if c.typ == ClientType::Hub {
                    queue::send_urgent(c, CMD_UPGRADE_STAGE, &id);
                }
            }
            state.upgrade.phase = UpgradePhase::Staging;
            state.upgrade.phase_started = now_ts;
            history_note(state);
            crate::hlog_info!("[UPGRADE] Run {id} staging on {staging} node(s)\n");
            return;
        }
        state.upgrade.phase = UpgradePhase::Rolling;
        state.upgrade.phase_started = now_ts;
        state.upgrade.rolling_at = now_ts;
        history_note(state);
        crate::hlog_info!(
            "[UPGRADE] Run {} rolling: {} node(s) ready\n",
            state.upgrade.id,
            ready
        );
        return;
    }

    if matches!(
        state.upgrade.phase,
        UpgradePhase::Staging | UpgradePhase::Rolling
    ) && stage_watch(state, now_ts)
    {
        return;
    }
    if state.upgrade.phase == UpgradePhase::Staging {
        // A source build gets its time, but the rest of the run does not wait on it.
        if state
            .upgrade
            .nodes
            .iter()
            .any(|n| n.state == UpgradeNodeState::Ready && n.can_stage && !n.staged && !n.is_src)
        {
            return;
        }
        state.upgrade.phase = UpgradePhase::Rolling;
        state.upgrade.phase_started = now_ts;
        state.upgrade.rolling_at = now_ts;
        history_note(state);
        crate::hlog_info!(
            "[UPGRADE] Run {} rolling: {} node(s) ready, {} staged\n",
            state.upgrade.id,
            count(state, UpgradeNodeState::Ready, None),
            state.upgrade.nodes.iter().filter(|n| n.staged).count()
        );
        return;
    }

    if state.upgrade.phase != UpgradePhase::Rolling {
        return;
    }

    ops_grace(state, now_ts);

    // A committed node that did not come back has failed.  A staged one had only a
    // swap to do; one that took the old path may still be fetching.  If it turns up
    // later on the target, the record says so.  Whether the run goes on is decided
    // below: one bad host must not roll back a healthy network.
    for ni in 0..state.upgrade.nodes.len() {
        let n = &state.upgrade.nodes[ni];
        if n.state != UpgradeNodeState::Committed || n.back_at != 0 {
            continue;
        }
        let limit = if n.staged {
            UPGRADE_SWAP_BACK
        } else {
            UPGRADE_COMMIT_TIMEOUT
        };
        if now_ts - n.committed_at <= limit {
            continue;
        }
        let target = node_target(&state.upgrade, ni).to_string();
        let node = &mut state.upgrade.nodes[ni];
        node.state = UpgradeNodeState::Failed;
        node.done_at = now_ts;
        node.stage_code = "late".to_string();
        node.reason = format!("did not return on {target} in time");
    }
    if weigh_failures(state) {
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
        // A source build still staging holds no one else up, only the hubs after.
        for _ in 0..state.upgrade.nodes.len() {
            if in_flight >= wave {
                break;
            }
            let Some(ni) = next_bot(&state.upgrade) else {
                break;
            };
            // Each build's first node goes alone: a bad build costs one restart.
            let alone = build_unproven(&state.upgrade, ni);
            if alone && in_flight > 0 {
                break;
            }
            if commit_node(state, ni) {
                in_flight += 1;
            } else {
                // a refused commit leaves the node out of the run
                if state.upgrade.nodes[ni].state == UpgradeNodeState::Ready {
                    break;
                }
            }
            if alone {
                break;
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
    // A hub still staging is waited for: order matters here, and the ring relies on
    // the deepest going first.
    if state.upgrade.nodes.iter().any(|n| {
        n.state == UpgradeNodeState::Ready
            && n.can_stage
            && !n.staged
            && n.kind != UpgradeNodeKind::Bot
    }) {
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

    let unable = state
        .upgrade
        .nodes
        .iter()
        .filter(|n| n.state == UpgradeNodeState::Unable && !n.not_selected)
        .count();
    let failed = count(state, UpgradeNodeState::Failed, None);
    let partial = failed > 0 || state.upgrade.build_stopped;
    let done_msg = if partial {
        format!(
            "{} node(s) now on the target, {} could not take it, {} failed",
            count(state, UpgradeNodeState::Done, None),
            unable,
            failed
        )
    } else {
        format!(
            "{} node(s) now on the target, {} could not take it",
            count(state, UpgradeNodeState::Done, None),
            unable
        )
    };
    finish(
        state,
        if partial {
            UpgradePhase::Partial
        } else {
            UpgradePhase::Done
        },
        &done_msg,
    );
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
        crate::hlog_warning!(
            "[UPGRADE] No room to route {uuid} — it stays out of the run\n",
            uuid = state.who('\0', uuid)
        );
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
    // id|ver|variant|kind|min_from|base|hub_ver|hub_base[|sel] — the bots'
    // six fields, the hubs' own target, then (2.4.3+) a selective run's
    // resolved selection, uuid[=v],... (see start).  The base slots are
    // reserved and never read: every node reads its own compiled-in root,
    // the only tree its pinned key verifies.
    let f: Vec<&str> = payload.splitn(9, '|').collect();
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
    let hub_ver = f.get(6).copied().unwrap_or("").to_string();
    let sel = f.get(8).copied().unwrap_or("").to_string();
    if !sel
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '=' || c == ',')
    {
        crate::hlog_warning!(
            "[UPGRADE] Malformed selection in PREPARE from peer {}\n",
            state.clients[ci].ip
        );
        return;
    }
    let selective = !sel.is_empty();
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
    let self_pick = if selective {
        sel_lookup(&sel, &state.hub_uuid)
    } else {
        Some(String::new())
    };
    let self_variant = match &self_pick {
        Some(v) if !v.is_empty() => v.clone(),
        _ => variant.clone(),
    };
    let (ready, why) = if self_pick.is_none() {
        (false, "not selected".to_string())
    } else if hub_ver.is_empty() {
        (false, "no hub target in this run".to_string())
    } else {
        match update::can_take(&hub_ver, &self_variant, &min_from) {
            Ok(()) => (true, String::new()),
            Err(why) => (false, why),
        }
    };
    let origin = peer_uuid_of(state, ci);
    state.follow_id = id.clone();
    state.follow_origin = origin;
    state.follow_target = ver.clone();
    state.follow_bot_variant = variant.clone();
    state.follow_sel = sel.clone();
    state.follow_variant = if self_variant.is_empty() {
        update::host_variant().to_string()
    } else {
        self_variant
    };
    state.follow_hub_target = hub_ver;
    state.follow_self_ready = ready;
    state.follow_prepared = now();
    state.follow_routes.clear();

    // Record the driver's plan as this hub's roll-up plan too.  A bot that was
    // down while the run went through reconnects to whichever hub it likes, so
    // every hub has to know what the network is supposed to be running; the
    // replicated config freeze is what keeps any of them from acting on it
    // before the run is over (see rollup_may_try).  Not for a selective run:
    // a few named nodes moving is no statement about the rest.
    if !selective {
        state.rollup.have_plan = true;
        state.rollup.target = state.follow_target.clone();
        state.rollup.variant = variant_field;
        state.rollup.kind = kind_field.clone();
        state.rollup.min_from = if min_from.is_empty() {
            "*".to_string()
        } else {
            min_from.clone()
        };
        state.rollup.hub_target = state.follow_hub_target.clone();
        state.rollup.plan_set = now();
        state.rollup_tries.clear();
        crate::config::write(state); // the plan survives a restart (Task 13)
    }

    // Fan PREPARE out to this hub's own local bots.  Each answers READY to us
    // (its hub); we forward that up to the origin, which records it as a
    // remote node reached through this hub.  That is what makes one run reach
    // a bot no matter which hub it is homed on.
    // Bots get the six fields they read, not the hubs' on the end — and in a
    // selective run only the bots it names, each asked about its own build.
    let bots: Vec<(usize, String)> = state
        .clients
        .iter()
        .enumerate()
        .filter(|(_, c)| c.typ == ClientType::Bot && c.authenticated)
        .filter_map(|(i, c)| {
            if selective {
                sel_lookup(&sel, &c.id).map(|v| (i, v))
            } else {
                Some((i, String::new()))
            }
        })
        .collect();
    let mut relayed = 0;
    for (bi, bot_variant) in bots {
        let bot_prepare = format!(
            "{id}|{ver}|{}|{kind_field}|{min_from}|",
            if bot_variant.is_empty() {
                &variant
            } else {
                &bot_variant
            }
        );
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
    // forward them up, so the driver sees one flat node table.  Rebuilt from
    // the checked fields, so anything in a reserved slot goes no further.
    let fwd = format!(
        "{id}|{ver}|{variant}|{kind_field}|{min_from}||{}|{}{sel}",
        state.follow_hub_target,
        if sel.is_empty() { "" } else { "|" }
    );
    let peers: Vec<usize> = state
        .clients
        .iter()
        .enumerate()
        .filter(|(i, c)| *i != ci && c.typ == ClientType::Hub && c.authenticated)
        .map(|(i, _)| i)
        .collect();
    let mut fanned = 0;
    for pi in peers {
        if queue::send_urgent(&mut state.clients[pi], CMD_UPGRADE_PREPARE, &fwd) {
            fanned += 1;
        }
    }
    if fanned > 0 {
        crate::hlog_info!("[UPGRADE] Re-broadcast PREPARE {id} to {fanned} peer hub(s)\n");
    }

    answer_ready(state, ci, &id, ready, &why, relayed);
    // A frame an older driver drops: this hub can get a build ready before COMMIT.
    if ready {
        let pr = format!("{id}|{}|ready|", state.hub_uuid);
        if let Some(c) = state.clients.get_mut(ci) {
            queue::send_urgent(c, CMD_UPGRADE_PROGRESS, &pr);
        }
    }
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
            "[UPGRADE] Driver of {id} is gone — dropping a relayed answer for {uuid}\n",
            uuid = state.who('\0', &uuid)
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
    let for_self = target_uuid.is_empty() || target_uuid == state.hub_uuid;
    // Every refusal below touched nothing, so it is answered "skip" — the
    // node stays healthy where it is and leaves the run — and always under
    // the uuid of the node the driver addressed.  Answering a relayed bot's
    // COMMIT under this hub's own uuid is what turned a done hub into a
    // failed one and aborted run 83aac614.
    let who = if for_self {
        state.hub_uuid.clone()
    } else {
        target_uuid.clone()
    };

    if state.follow_id.is_empty() || state.follow_id != id {
        // No run state: this hub restarted (or never saw the PREPARE).  If it
        // is itself the target and already on that build, the COMMIT's work
        // is done — say so rather than fail a node that succeeded.
        let there = for_self
            && update::version_cmp(HUB_VERSION, &ver) == std::cmp::Ordering::Equal
            && (variant.is_empty() || variant == update::host_variant());
        if there {
            answer_result_uuid(state, ci, &id, &who, "ok", "");
        } else {
            answer_result_uuid(
                state,
                ci,
                &id,
                &who,
                "skip",
                "this hub holds no such run (restarted since PREPARE?)",
            );
        }
        return;
    }
    // The version must be one this run named: the bots' target for a frame
    // on its way to a bot, the hubs' own for this hub (checked again below).
    if state.follow_target != ver
        && (state.follow_hub_target.is_empty() || state.follow_hub_target != ver)
    {
        answer_result_uuid(
            state,
            ci,
            &id,
            &who,
            "skip",
            "commit version differs from prepare",
        );
        return;
    }
    if now() - state.follow_prepared > UPGRADE_PREPARE_TTL {
        state.follow_id.clear();
        answer_result_uuid(state, ci, &id, &who, "skip", "prepare expired");
        return;
    }

    // A 4th field names the node the driver is addressing.  It is one of three
    // things, in order: this hub, one of its local bots, or something further
    // out that this hub relayed an answer for at PREPARE time — in which case
    // the frame goes on, unchanged, along the route it learned.
    if !for_self {
        if let Some(bi) = find_client(state, &target_uuid, ClientType::Bot) {
            let relay = format!("{id}|{ver}|{variant}");
            if !client::send_cmd_to_bot(&mut state.clients[bi], CMD_UPGRADE_COMMIT, &relay) {
                answer_result_uuid(
                    state,
                    ci,
                    &id,
                    &target_uuid,
                    "skip",
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
                "skip",
                "no route to that node from this hub",
            );
        }
        return;
    }

    // No target uuid: this hub is the node being committed.
    if !state.follow_self_ready {
        answer_result(state, ci, &id, "skip", "this hub cannot take the upgrade");
        return;
    }
    if state.follow_hub_target != ver {
        answer_result(
            state,
            ci,
            &id,
            "skip",
            "commit version differs from prepare",
        );
        return;
    }

    let variant = if variant.is_empty() {
        state.follow_variant.clone()
    } else {
        variant
    };
    // On success update::commit does not return: the process is replaced and
    // report_pending() reports in after the restart.
    if let Err(e) = update::commit(state, &id, &ver, &variant) {
        // Nothing was changed on disk; stay on this build and say why.
        crate::hlog_warning!("[UPGRADE] Commit {id} refused: {e}\n");
        // Nothing was touched either way, but a tampered or corrupt release
        // must still abort the run rather than be retried on every node.
        let status = if commit_err_is_integrity(&e) {
            "fail"
        } else {
            "skip"
        };
        answer_result(state, ci, &id, status, &e);
        state.follow_id.clear();
    }
}

/// Is a COMMIT refusal an artifact-integrity failure?  Those answer "fail",
/// not "skip": every other node would read the same bad release, so the run
/// must stop instead of walking it through the mesh in waves.
pub fn commit_err_is_integrity(e: &str) -> bool {
    [
        "SHA-256 mismatch",
        "signature INVALID",
        "is not a irchub release",
        "is not a ircbot release",
        "untrusted artifact URL",
    ]
    .iter()
    .any(|m| e.contains(m))
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
        "[UPGRADE] Abort {id} from {}{}{}: {reason}\n",
        state.who_client(ci),
        if uuid.is_empty() { "" } else { " for " },
        state.who('b', &uuid)
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

    // Whether it names this hub or nobody, the run is over here: a staged build
    // must not stay behind.
    update::stage_clear();
    state.follow_id.clear();
    state.follow_prepared = 0;
    state.follow_self_ready = false;
    // The routes stay until the next PREPARE: the driver's aborts for the nodes behind
    // this hub may still be on their way, and they travel by this table.
    // Only the run that installed the build we are running may take it back.  A hub
    // still staging never moved, and its <exe>.prev is the build from before an
    // earlier, completed run: going back to it would walk a healthy hub off the
    // version the rest of the mesh is on.
    if id != state.upgrade_installed_id {
        answer_result(state, ci, &id, "aborted", "this hub did not move");
        return;
    }
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
    // A recent `upgrade abort` goes to every link that comes up: the hub it
    // was meant for may have been restarting onto a step when it was typed.
    if !state.upgrade_cancel_id.is_empty()
        && now() - state.upgrade_cancel_seen < UPGRADE_CANCEL_HOLD
    {
        let fwd = format!(
            "{}|{}|A|{}",
            state.upgrade_cancel_id,
            now(),
            state.upgrade_cancel_issued
        );
        queue::send_urgent(&mut state.clients[ci], CMD_UPGRADE_FORGET, &fwd);
    }
    let Some((id, want, want_variant)) = update::take_pending() else {
        return;
    };
    state.upgrade_installed_id = id.clone();
    let host = update::host_variant();
    let ok = update::version_cmp(HUB_VERSION, &want) == std::cmp::Ordering::Equal
        && (want_variant.is_empty() || want_variant == host);
    let wanted = if want_variant.is_empty() {
        want.clone()
    } else {
        format!("{want}/{want_variant}")
    };
    crate::hlog_warning!(
        "[UPGRADE] Restarted after {id}: running {HUB_VERSION}/{host} (wanted {wanted})\n"
    );
    let status = if ok { "ok" } else { "version-mismatch" };
    let detail = if ok {
        update::failback_confirm();
        String::new()
    } else {
        update::failback_note().unwrap_or_else(|| format!("wanted {wanted}"))
    };
    answer_result(state, ci, &id, status, &detail);
}

/// CMD_ADMIN_UPGRADE_STATUS "releases": everything the
/// admin console needs to offer choices instead of free text:
///   ok|upg.releases
///   rel|product|ver|date|bases           newest first, per product
///   relerr|product|base|msg              a tree that could not be read
///   node|kind|uuid|name|ver|base         the nodes a selective run can name
/// Manifests are signature-verified exactly as an upgrade would read them;
/// an unverifiable tree lists nothing.
pub fn releases(state: &HubState, payload: &str, r: &mut Reply) {
    r.ok("upg.releases");
    let bot_root = update::bot_root();
    for (pname, root) in [
        ("bot", bot_root.as_str()),
        ("hub", ""), // "" = this hub's own root
    ] {
        let mut merged: Vec<(update::Release, String)> = Vec::new();
        for v in ["c", "rs"] {
            match update::list_releases(root, v, MAX_UPGRADE_RELEASES) {
                Err(e) => {
                    r.rec("relerr");
                    r.kv("product", pname);
                    r.kv("base", v);
                    r.kv("msg", &e);
                }
                Ok(list) => {
                    for rel in list {
                        if let Some((_, have)) = merged.iter_mut().find(|(m, _)| {
                            update::version_cmp(&m.version, &rel.version)
                                == std::cmp::Ordering::Equal
                        }) {
                            have.push(',');
                            have.push_str(v);
                        } else if merged.len() < MAX_UPGRADE_RELEASES {
                            merged.push((rel, v.to_string()));
                        }
                    }
                }
            }
        }
        // Newest first across both trees.
        merged.sort_by(|a, b| update::version_cmp(&b.0.version, &a.0.version));
        for (rel, have) in merged {
            r.rec("rel");
            r.kv("product", pname);
            r.kv("ver", &rel.version);
            if !rel.date.is_empty() {
                r.kv("date", &rel.date);
            }
            r.kv("bases", &have);
        }
    }

    // The nodes a selective run could name, as this hub sees them now.
    let opt = |r: &mut Reply, k: &str, v: &str| {
        if !v.is_empty() {
            r.kv(k, v);
        }
    };
    r.rec("node");
    r.kv("kind", "self");
    r.kv("uuid", &state.hub_uuid);
    r.kv(
        "name",
        if state.hub_friendly_name.is_empty() {
            "hub"
        } else {
            &state.hub_friendly_name
        },
    );
    r.kv("ver", HUB_VERSION);
    r.kv("base", update::host_variant());
    for m in &state.mesh_hubs {
        if m.uuid.is_empty() || m.uuid == state.hub_uuid {
            continue;
        }
        r.rec("node");
        r.kv("kind", "hub");
        r.kv("uuid", &m.uuid);
        opt(r, "name", &m.name);
        opt(r, "ver", &m.version);
        opt(r, "base", &m.variant);
    }
    for c in &state.clients {
        if c.typ != ClientType::Bot || !c.authenticated {
            continue;
        }
        let nick = state.bot_entry(&c.id, "n").unwrap_or("");
        r.rec("node");
        r.kv("kind", "bot");
        r.kv("uuid", &c.id);
        opt(r, "name", nick);
        opt(r, "ver", &c.bot_version);
        opt(r, "base", &c.bot_variant);
    }
    for (i, e) in state.roster.iter().enumerate() {
        if e.hub_uuid == state.hub_uuid
            || find_client(state, &e.bot_uuid, ClientType::Bot).is_some()
            || state.roster[..i].iter().any(|p| p.bot_uuid == e.bot_uuid)
        {
            continue;
        }
        r.rec("node");
        r.kv("kind", "bot");
        r.kv("uuid", &e.bot_uuid);
        opt(r, "name", &e.nick);
        opt(r, "ver", &e.version);
        opt(r, "base", &e.variant);
    }
    plan_preview(state, payload, r);
}

/// CMD_ADMIN_UPGRADE_STATUS "": the run this hub drives (or drove last), the
/// roll-up plan it holds, and one node| record per node of the run:
///   ok|upg.status[|id|phase|active|started|bot_ver|hub_ver|selective|summary]|frozen
///   rollup|bot_ver|hub_ver|set
///   node|kind|uuid|name|state|from|to|base|want|reason
pub fn status(state: &HubState, r: &mut Reply) {
    let u = &state.upgrade;
    r.ok("upg.status");
    if !u.id.is_empty() {
        r.kv("id", &u.id);
        r.kv("phase", u.phase.name());
        r.kvb("active", u.active);
        r.kvi("started", u.started);
        r.kv("bot_ver", &u.target_ver);
        if !u.hub_ver.is_empty() {
            r.kv("hub_ver", &u.hub_ver);
        }
        r.kvi("selective", u.select.len() as i64);
        if !u.summary.is_empty() {
            r.kv("summary", &u.summary);
        }
    }
    r.kvb("frozen", config_frozen(state));
    if !state.uhist.is_empty() {
        r.kvi("keep", crate::uhist::keep(state) as i64);
    }
    // The roll-ups are outside history, so what each node's last one did is here.
    for t in state.rollup_tries.iter().filter(|t| !t.note.is_empty()) {
        r.rec("rolled");
        r.kv("uuid", &t.uuid);
        r.kv("name", &state.who('\0', &t.uuid));
        r.kv("step", &t.step);
        r.kvi("tries", i64::from(t.tries));
        r.kvi("when", t.last_try);
        r.kv("note", &t.note);
    }
    // The roll-up plan this hub holds, if any: what a bot that comes back is
    // walked up to, until an admin's "forget" drops it.
    let ru = &state.rollup;
    if ru.have_plan {
        r.rec("rollup");
        r.kv("bot_ver", &ru.target);
        if !ru.hub_target.is_empty() {
            r.kv("hub_ver", &ru.hub_target);
        }
        r.kvi("set", ru.plan_set);
        r.kvi("expires", ru.plan_set + ROLLUP_PLAN_TTL);
    }
    // A multi-step upgrade: the whole path, where it is, and — once it has
    // stopped — why (kept until this hub restarts).
    // Not this hub's to drive: what its driver last said, or why it stopped.
    let sp = &state.splan;
    let pl = if !state.plan.active
        && !sp.single
        && (sp.active || !sp.summary.is_empty())
        && sp.started >= state.plan.started
    {
        &state.splan
    } else {
        &state.plan
    };
    if pl.active || !pl.summary.is_empty() {
        r.rec("plan");
        r.kvb("active", pl.active);
        if !pl.driver.is_empty() {
            r.kv("driver", &pl.driver);
            if pl.driver != state.hub_uuid {
                r.kv("driver_name", &state.who('h', &pl.driver));
                r.kvi("heard", state.splan_seen);
            }
        }
        opt(r, "hold", &pl.hold);
        r.kvi("step", pl.step as i64 + 1);
        r.kvi("steps", pl.steps() as i64);
        r.kv("bot_final", &pl.bot_target);
        opt(r, "bot_from", &pl.bot_from);
        opt(r, "bot_path", &pl.bot_path.join(","));
        if !pl.hub_target.is_empty() {
            r.kv("hub_final", &pl.hub_target);
            opt(r, "hub_from", &pl.hub_from);
            opt(r, "hub_path", &pl.hub_path.join(","));
        }
        if pl.active {
            r.kv(
                "state",
                if !pl.hold.is_empty() {
                    "held"
                } else if pl.run_id.is_empty() {
                    "waiting"
                } else {
                    "running"
                },
            );
            if pl.run_id.is_empty() && pl.next_at > 0 {
                r.kvi("next", pl.next_at);
            }
        }
        r.kvi("started", pl.started);
        opt(r, "summary", &pl.summary);
    }
    status_nodes(state, r);
    crate::uhist::reply_runs(state, r);
}

/// The current run's node table, if this hub holds one.
fn status_nodes(state: &HubState, r: &mut Reply) {
    let u = &state.upgrade;
    if u.id.is_empty() {
        return;
    }
    for (ni, n) in u.nodes.iter().enumerate() {
        r.rec("node");
        r.kv("kind", n.kind.name());
        r.kv("uuid", &n.uuid);
        // a bot node has no label of its own: its nick from the config
        if !n.name.is_empty() {
            r.kv("name", &n.name);
        } else if n.kind == UpgradeNodeKind::Bot {
            let nick = crate::presence::bot_nick_from_config(state, &n.uuid);
            if !nick.is_empty() {
                r.kv("name", &nick);
            }
        }
        r.kv(
            "state",
            if n.not_selected {
                "skipped"
            } else {
                n.state.name()
            },
        );
        if !n.cur_version.is_empty() {
            r.kv("from", &n.cur_version);
        }
        let to = if n.kind == UpgradeNodeKind::Bot {
            &u.target_ver
        } else {
            &u.hub_ver
        };
        if !to.is_empty() {
            r.kv("to", to);
        }
        if !n.variant.is_empty() {
            r.kv("base", &n.variant);
        }
        // the build it is being moved onto, when that is the other one
        let want = node_variant(u, ni);
        if !want.is_empty() && want != n.variant {
            r.kv("want", want);
        }
        if !n.reason.is_empty() {
            r.kv("reason", &n.reason);
        }
        opt(r, "code", &n.stage_code);
        if n.cls != '\0' {
            r.kv("class", &n.cls.to_string());
        }
        // Where it is in the run, and for how long.
        let t = now();
        if n.state == UpgradeNodeState::Ready && n.can_stage && u.active {
            r.kv(
                "phase",
                if n.staged {
                    "staged"
                } else if !n.stage_phase.is_empty() {
                    &n.stage_phase
                } else {
                    "staging"
                },
            );
            if !n.staged && !n.stage_pct.is_empty() {
                r.kv("pct", &n.stage_pct);
                if !n.stage_detail.is_empty() {
                    r.kv("detail", &n.stage_detail);
                }
            }
            if n.stage_sent > 0 {
                r.kvi(
                    "secs",
                    (if n.staged_at > 0 { n.staged_at } else { t }) - n.stage_sent,
                );
            }
        } else if n.left {
            r.kv("phase", "left");
        } else if n.committed_at > 0 {
            let end = if n.back_at > 0 {
                n.back_at
            } else if n.done_at > 0 {
                n.done_at
            } else {
                t
            };
            r.kvi("secs", end - n.committed_at);
        }
        // idle: a hub a bots-only run never moves (it only relays the run to
        // its bots).  already: a node that declined because it already runs
        // the target build -- a no-op, not a failure.
        if n.kind != UpgradeNodeKind::Bot
            && u.hub_ver.is_empty()
            && (n.not_selected || n.state == UpgradeNodeState::Unable)
        {
            r.kvb("idle", true);
        } else if !n.not_selected
            && n.state == UpgradeNodeState::Unable
            && !to.is_empty()
            && !n.cur_version.is_empty()
            && crate::update::version_cmp(&n.cur_version, to) == std::cmp::Ordering::Equal
            && (want.is_empty() || want == n.variant)
        {
            r.kvb("already", true);
        }
    }
    // The kept runs, under the current one (view 4 and `upgrade status`).
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The director's name rides as field 27; a 26-field line still parses, and a
    /// name that would not pass is sent empty rather than keeping the plan off the wire.
    #[test]
    fn plan_line_carries_driver_name() {
        let mut p = UpgradePlan {
            active: true,
            bot_target: "3.0.2".into(),
            bot_path: vec!["3.0.0".into(), "3.0.2".into()],
            driver: "d-uuid".into(),
            driver_name: "tnhub1".into(),
            started: 100,
            ..Default::default()
        };
        let line = plan_format(&p).expect("formats");
        assert_eq!(line.split('|').count(), 27);
        let back = plan_parse(&line).expect("parses");
        assert_eq!(back.driver_name, "tnhub1");
        let old: Vec<&str> = line.split('|').take(26).collect();
        let back = plan_parse(&old.join("|")).expect("26 fields parse");
        assert!(back.driver_name.is_empty());
        p.driver_name = "bad name;x".into();
        let line = plan_format(&p).expect("still formats");
        assert!(line.ends_with('|'));
        assert!(plan_parse(&format!("{line}a b")).is_none());
    }

    /// A driver mid-PREPARE for run "r1".
    fn driver() -> HubState {
        let mut s = HubState::new();
        s.hub_uuid = "self-uuid".to_string();
        s.upgrade.active = true;
        s.upgrade.id = "r1".to_string();
        s.upgrade.target_ver = "2.4.5".to_string();
        s.upgrade.hub_ver = "2.4.3".to_string();
        s.upgrade.phase = UpgradePhase::Prepare;
        s
    }

    fn node<'a>(s: &'a HubState, uuid: &str) -> &'a UpgradeNode {
        &s.upgrade.nodes[find_node(s, uuid).expect("node")]
    }

    /// Run 83aac614: a hub's READY carries ten fields.  The kind and the
    /// relayed-bot count must both be read, or PREPARE closes before the
    /// peer's bots have answered.
    #[test]
    fn ready_parses_all_ten_fields() {
        let mut s = driver();
        note_ready(
            &mut s,
            "r1|far-hub|2.4.2|rs|x86_64|musl|1|some reason|h|5",
            Some("peer-a"),
        );
        let n = node(&s, "far-hub");
        assert_eq!(n.kind, UpgradeNodeKind::PeerHub);
        assert_eq!(n.relayed, 5);
        assert_eq!(n.state, UpgradeNodeState::Ready);
        assert_eq!(n.via, "peer-a");
        assert_eq!(relays_owed(&s.upgrade), 5);
        // A bot's READY stops at the reason: kind defaults to bot.
        note_ready(&mut s, "r1|bot-1|2.4.4|c|x86_64|musl|1|", Some("peer-a"));
        assert_eq!(node(&s, "bot-1").kind, UpgradeNodeKind::Bot);
        assert_eq!(relays_owed(&s.upgrade), 4);
    }

    #[test]
    fn ready_moves_only_a_pending_node() {
        let mut s = driver();
        note_ready(&mut s, "r1|bot-1|2.4.4|c|x86_64|musl|1|", Some("peer-a"));
        let ni = find_node(&s, "bot-1").unwrap();
        s.upgrade.nodes[ni].state = UpgradeNodeState::Committed;
        note_ready(&mut s, "r1|bot-1|2.4.4|c|x86_64|musl|1|", Some("peer-a"));
        assert_eq!(node(&s, "bot-1").state, UpgradeNodeState::Committed);
    }

    #[test]
    fn late_ready_is_never_committed() {
        let mut s = driver();
        s.upgrade.phase = UpgradePhase::Rolling;
        // The hub it sits behind may be restarting: it stays out.
        s.upgrade.nodes.push(UpgradeNode {
            uuid: "eb04".to_string(),
            state: UpgradeNodeState::Committed,
            kind: UpgradeNodeKind::PeerHub,
            ..UpgradeNode::default()
        });
        note_ready(&mut s, "r1|bot-7209|2.4.3|rs|x86_64|musl|1|", Some("eb04"));
        let n = node(&s, "bot-7209");
        assert_eq!(n.state, UpgradeNodeState::Unable);
        assert!(n.reason.starts_with("answered after the plan was fixed"));
    }

    #[test]
    fn late_ready_joins_the_old_way() {
        let mut s = driver();
        s.upgrade.phase = UpgradePhase::Rolling;
        note_ready(&mut s, "r1|bot-7|2.4.3|rs|x86_64|musl|1|", Some("peer-a"));
        let n = node(&s, "bot-7");
        assert_eq!(n.state, UpgradeNodeState::Ready);
        assert!(!n.can_stage);
    }

    #[test]
    fn unselected_ready_is_not_selected() {
        let mut s = driver();
        s.upgrade.select = vec![("bot-a".to_string(), "c".to_string())];
        note_ready(&mut s, "r1|bot-b|2.4.3|rs|x86_64|musl|1|", Some("peer"));
        let n = node(&s, "bot-b");
        assert_eq!(n.state, UpgradeNodeState::Unable);
        assert!(n.not_selected);
        assert_eq!(n.reason, "not selected");
    }

    /// Run 83aac614's eb04: a done node must never be turned back into a
    /// failure by a late RESULT.
    #[test]
    fn result_moves_only_a_committed_node() {
        let mut s = driver();
        s.upgrade.phase = UpgradePhase::Rolling;
        for id in ["done", "c1", "c2", "c3"] {
            s.upgrade.nodes.push(UpgradeNode {
                uuid: id.to_string(),
                kind: UpgradeNodeKind::PeerHub,
                state: if id == "done" {
                    UpgradeNodeState::Done
                } else {
                    UpgradeNodeState::Committed
                },
                ..UpgradeNode::default()
            });
        }
        note_result(&mut s, "r1|done|fail|2.4.3|no matching UPGRADE_PREPARE");
        assert_eq!(node(&s, "done").state, UpgradeNodeState::Done);
        note_result(&mut s, "r1|c1|skip|2.4.2|prepare expired");
        assert_eq!(node(&s, "c1").state, UpgradeNodeState::Unable);
        assert_eq!(node(&s, "c1").reason, "prepare expired");
        note_result(&mut s, "r1|c2|version-mismatch|2.4.2|wanted 2.4.3");
        assert_eq!(node(&s, "c2").state, UpgradeNodeState::Failed);
        note_result(&mut s, "r1|c3|ok|2.4.3|");
        assert_eq!(node(&s, "c3").state, UpgradeNodeState::Done);
    }

    #[test]
    fn integrity_failures_abort() {
        assert!(commit_err_is_integrity("artifact SHA-256 mismatch"));
        assert!(commit_err_is_integrity(
            "release manifest signature INVALID — possible tampering"
        ));
        assert!(commit_err_is_integrity(
            "manifest artifact is not a irchub release"
        ));
        assert!(commit_err_is_integrity(
            "manifest artifact is not a ircbot release"
        ));
        assert!(commit_err_is_integrity(
            "untrusted artifact URL in manifest"
        ));
        assert!(!commit_err_is_integrity("artifact download failed"));
        assert!(!commit_err_is_integrity(
            "failed to download release manifest"
        ));
        assert!(!commit_err_is_integrity(
            "already running the target version"
        ));
    }

    #[test]
    fn sel_lookup_matches_whole_uuids() {
        let sel = "aaaa-1=c,bbbb-2,cccc-3=rs";
        assert_eq!(sel_lookup(sel, "aaaa-1").as_deref(), Some("c"));
        assert_eq!(sel_lookup(sel, "bbbb-2").as_deref(), Some(""));
        assert_eq!(sel_lookup(sel, "cccc-3").as_deref(), Some("rs"));
        assert_eq!(sel_lookup(sel, "aaaa"), None);
        assert_eq!(sel_lookup(sel, "bbbb-2x"), None);
        assert_eq!(sel_lookup("", "aaaa-1"), None);
        assert_eq!(sel_lookup(sel, ""), None);
    }

    #[test]
    fn tokens_resolve_or_refuse() {
        let c = |u: &str, n: &str| Cand {
            uuid: u.to_string(),
            name: n.to_string(),
            kind: UpgradeNodeKind::Bot,
        };
        let cands = vec![
            c("c68c4ce0-a933-4a8a-bfdf-c481a37273ef", "optiplex"),
            c("c68c9999-0000-0000-0000-000000000000", "fusoya"),
            c("7209ad7f-705b-45ae-b93a-b261b6cb0a99", "trojan"),
            c("37b8f85c-d90c-4926-bc2a-689f206f18c0", "trojan"),
        ];
        // Exact uuid, any case.
        assert_eq!(
            resolve(&cands, "C68C4CE0-A933-4A8A-BFDF-C481A37273EF")
                .unwrap()
                .name,
            "optiplex"
        );
        // Exact name, any case.
        assert_eq!(
            resolve(&cands, "OPTIPLEX").unwrap().uuid,
            "c68c4ce0-a933-4a8a-bfdf-c481a37273ef"
        );
        // Two nodes by the same name.
        assert!(
            resolve(&cands, "trojan")
                .unwrap_err()
                .contains("more than one")
        );
        // Unique prefix, ambiguous prefix, too-short prefix, unknown.
        assert_eq!(resolve(&cands, "7209").unwrap().name, "trojan");
        assert!(resolve(&cands, "c68c").unwrap_err().contains("ambiguous"));
        assert!(resolve(&cands, "720").is_err());
        assert!(
            resolve(&cands, "nosuch")
                .unwrap_err()
                .contains("no node known")
        );
    }

    #[test]
    fn done_bot_falling_back_fails_the_run() {
        let mut s = driver();
        s.upgrade.phase = UpgradePhase::Rolling;
        s.upgrade.nodes.push(UpgradeNode {
            uuid: "b".to_string(),
            kind: UpgradeNodeKind::Bot,
            variant: "rs".to_string(),
            state: UpgradeNodeState::Done,
            ..UpgradeNode::default()
        });
        note_presence(&mut s, "b", "2.4.4", "rs");
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Failed);
    }

    #[test]
    fn variant_switch_needs_the_new_variant() {
        let mut s = driver();
        s.upgrade.phase = UpgradePhase::Rolling;
        s.upgrade.nodes.push(UpgradeNode {
            uuid: "b".to_string(),
            kind: UpgradeNodeKind::Bot,
            variant: "rs".to_string(),
            want_variant: "c".to_string(),
            state: UpgradeNodeState::Committed,
            ..UpgradeNode::default()
        });
        note_presence(&mut s, "b", "2.4.5", "rs");
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Committed);
        assert_eq!(node(&s, "b").back_at, 0);
        // The right build: back, but a 2.4.5 bot is done only on its "ok".
        note_presence(&mut s, "b", "2.4.5", "c");
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Committed);
        assert!(node(&s, "b").back_at > 0);
    }

    /// Addendum A1: a bot's presence on the target stamps back_at and keeps
    /// it committing; its "ok" is what makes it done.
    #[test]
    fn gated_bot_is_done_on_its_ok_not_its_presence() {
        let mut s = driver();
        s.upgrade.phase = UpgradePhase::Rolling;
        s.upgrade.nodes.push(UpgradeNode {
            uuid: "b".to_string(),
            kind: UpgradeNodeKind::Bot,
            variant: "c".to_string(),
            state: UpgradeNodeState::Committed,
            ..UpgradeNode::default()
        });
        note_presence(&mut s, "b", "2.4.5", "c");
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Committed);
        assert!(node(&s, "b").back_at > 0);
        note_result(&mut s, "r1|b|ok|2.4.5|");
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Done);
    }

    /// A follower's "back" stamps back_at and never finishes or fails the
    /// node; past UPGRADE_OPS_GRACE with no "ok" the bot is done anyway.
    #[test]
    fn back_then_grace() {
        let mut s = driver();
        s.upgrade.phase = UpgradePhase::Rolling;
        s.upgrade.nodes.push(UpgradeNode {
            uuid: "b".to_string(),
            kind: UpgradeNodeKind::Bot,
            via: "peer".to_string(),
            state: UpgradeNodeState::Committed,
            ..UpgradeNode::default()
        });
        note_result(&mut s, "r1|b|back|2.4.5|");
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Committed);
        let back = node(&s, "b").back_at;
        assert!(back > 0);
        ops_grace(&mut s, back + UPGRADE_OPS_GRACE);
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Committed);
        ops_grace(&mut s, back + UPGRADE_OPS_GRACE + 1);
        assert_eq!(node(&s, "b").state, UpgradeNodeState::Done);
        assert_eq!(node(&s, "b").reason, "back on target; no ready report");
    }

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
