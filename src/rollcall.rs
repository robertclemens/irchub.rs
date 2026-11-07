//! Hub roll call: the upgrade gates ask the hubs themselves whether they are
//! there, instead of trusting second-hand link gossip (see CMD_HUB_ROLLCALL in
//! consts.rs).  Mirrors the roll call block of irchub/hub_logic.c.

use crate::consts::*;
use crate::cstr::{atoll, is_uuid, now};
use crate::state::{ClientType, HubRollcall, HubState, RollcallPurpose};
use crate::{opflow, queue};

fn rc_find(state: &HubState, id: &str) -> Option<usize> {
    state.rollcalls.iter().position(|r| r.active && r.id == id)
}

/// A free slot; a relay entry past its routing window counts as free.
fn rc_alloc(state: &mut HubState, t: i64) -> Option<usize> {
    let i = state
        .rollcalls
        .iter()
        .position(|r| !r.active || (!r.origin && t - r.started > ROLLCALL_KEEP))?;
    state.rollcalls[i] = HubRollcall {
        from_fd: -1,
        started: t,
        ..HubRollcall::default()
    };
    Some(i)
}

fn rc_id_ok(s: &str) -> bool {
    (8..ROLLCALL_ID_LEN).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Every hub known here: the configured peers and every hub the others report
/// a link to (the same set upgrade::hubs_missing counts).  None when the
/// gossip check has to decide instead: a configured peer that has never linked
/// (no uuid, nobody can ask it), a known hub that has not said it answers a
/// roll call (an older build), or more hubs than a roll call holds.
fn known_hubs(state: &HubState) -> Option<Vec<(String, String, bool)>> {
    let mut want: Vec<(String, String, bool)> = Vec::new();
    let add = |uuid: &str, name: &str, want: &mut Vec<(String, String, bool)>| -> bool {
        if want.iter().any(|w| w.0 == uuid) {
            return true;
        }
        if want.len() >= MAX_MESH_HUBS {
            return false;
        }
        let shown = if name.is_empty() { uuid } else { name };
        want.push((uuid.to_string(), shown.to_string(), false));
        true
    };
    for p in &state.peers {
        if p.uuid.is_empty() {
            return None;
        }
        let name = if p.friendly_name.is_empty() {
            &p.ip
        } else {
            &p.friendly_name
        };
        if !add(&p.uuid, name, &mut want) {
            return None;
        }
    }
    for mh in &state.mesh_hubs {
        for l in &mh.links {
            if l.uuid.is_empty() || l.uuid == "-" || l.uuid == state.hub_uuid {
                continue;
            }
            if !add(&l.uuid, &l.name, &mut want) {
                return None;
            }
        }
    }
    if want.is_empty() {
        return None;
    }
    let all_answer = want.iter().all(|w| {
        state
            .mesh_hubs
            .iter()
            .find(|m| m.uuid == w.0)
            .is_some_and(|m| m.rollcall)
    });
    all_answer.then_some(want)
}

/// Ask every hub known here.  Some(id) when the roll call is out (its end comes
/// through rollcall_end), None when the gossip check has to decide instead.
pub fn begin(state: &mut HubState, purpose: RollcallPurpose) -> Option<String> {
    let want = known_hubs(state)?;
    let t = now();
    let i = rc_alloc(state, t)?;
    let id = crate::crypto::random_hex(16)?;
    let _ = opflow::forward_seen_check_and_add(state, &id); // our own, back around a cycle
    let asked = want.len();
    {
        let rc = &mut state.rollcalls[i];
        rc.active = true;
        rc.origin = true;
        rc.purpose = purpose;
        rc.id = id.clone();
        rc.want = want;
    }
    let frame = format!("{id}|{}|{t}", state.hub_uuid);
    for pi in state.peer_clients() {
        queue::send_urgent(&mut state.clients[pi], CMD_HUB_ROLLCALL, &frame);
    }
    crate::hlog_debug!("[UPGRADE] Roll call {id}: asking {asked} hub(s)\n");
    Some(id)
}

/// The roll call is over: every hub answered, or ROLLCALL_WAIT ran out.
fn rollcall_end(state: &mut HubState, i: usize) {
    let rc = std::mem::take(&mut state.rollcalls[i]);
    let gone: Vec<String> = rc
        .want
        .iter()
        .filter(|w| !w.2)
        .map(|w| w.1.clone())
        .collect();
    crate::hlog_debug!(
        "[UPGRADE] Roll call {}: {} of {} hub(s) answered\n",
        rc.id,
        rc.want.len() - gone.len(),
        rc.want.len()
    );
    state.rollcalls[i].from_fd = -1;
    match rc.purpose {
        RollcallPurpose::Start
            if state.upg_start_wait.active && state.upg_start_wait.rc == rc.id =>
        {
            start_resume(state, &gone);
        }
        RollcallPurpose::Step if state.step_rollcall.rc == rc.id => {
            let s = &mut state.step_rollcall;
            s.rc.clear();
            s.outcome = if gone.is_empty() { 1 } else { 2 };
            s.gone = gone;
            s.at = now();
        }
        _ => {}
    }
}

/// ROLLCALL from a peer: rid|origin_uuid|origin_ts.  Pass it on, remember the
/// way back, answer.
pub fn peer_rollcall(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.splitn(4, '|').collect();
    if f.len() < 3 || !rc_id_ok(f[0]) || !is_uuid(f[1]) {
        let ip = state.clients[ci].ip.clone();
        crate::hlog_warning!("[UPGRADE] Malformed HUB_ROLLCALL from peer {ip}\n");
        return;
    }
    let (id, origin) = (f[0].to_string(), f[1]);
    let ts = atoll(f[2]);
    // atoll saturates: age only for a positive stamp
    let age = if ts > 0 { now() - ts } else { 0 };
    if ts <= 0 || !(-ROLLCALL_TTL..=ROLLCALL_TTL).contains(&age) {
        return;
    }
    if origin == state.hub_uuid {
        return;
    }
    if opflow::forward_seen_check_and_add(state, &id) {
        return; // another path got here first
    }
    let (fd, serial) = (state.clients[ci].fd, state.clients[ci].conn_serial);
    if let Some(i) = rc_alloc(state, now()) {
        let rc = &mut state.rollcalls[i];
        rc.active = true;
        rc.id = id.clone();
        rc.from_fd = fd;
        rc.from_serial = serial;
        for pi in state.peer_clients() {
            if pi != ci {
                queue::send_urgent(&mut state.clients[pi], CMD_HUB_ROLLCALL, payload);
            }
        }
    } else {
        // No way back for the hubs past this one: they read as missing and the
        // gate refuses, which is the safe answer.
        crate::hlog_warning!("[UPGRADE] Roll call table full: not passing {id} on\n");
    }
    let ack = format!("{id}|{}", state.hub_uuid);
    queue::send_urgent(&mut state.clients[ci], CMD_HUB_ROLLCALL_ACK, &ack);
}

/// ROLLCALL_ACK: rid|hub_uuid.  The asking hub ticks it off; a relay routes it
/// back down the link the roll call came in on.
pub fn peer_rollcall_ack(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.splitn(3, '|').collect();
    if f.len() < 2 || !rc_id_ok(f[0]) || !is_uuid(f[1]) {
        let ip = state.clients[ci].ip.clone();
        crate::hlog_warning!("[UPGRADE] Malformed HUB_ROLLCALL_ACK from peer {ip}\n");
        return;
    }
    let Some(i) = rc_find(state, f[0]) else {
        return;
    };
    if !state.rollcalls[i].origin {
        let rc = &state.rollcalls[i];
        if now() - rc.started > ROLLCALL_KEEP {
            return;
        }
        let (fd, serial) = (rc.from_fd, rc.from_serial);
        if let Some(pi) = state.clients.iter().position(|c| {
            c.typ == ClientType::Hub && c.authenticated && c.fd == fd && c.conn_serial == serial
        }) {
            queue::send_urgent(&mut state.clients[pi], CMD_HUB_ROLLCALL_ACK, payload);
        }
        return;
    }
    let rc = &mut state.rollcalls[i];
    for w in rc.want.iter_mut().filter(|w| w.0 == f[1]) {
        w.2 = true;
    }
    if rc.want.iter().all(|w| w.2) {
        rollcall_end(state, i);
    }
}

/// Ends the roll calls whose wait ran out and frees the relays' entries.  Runs
/// on every maintenance pass.
pub fn tick(state: &mut HubState, t: i64) {
    for i in 0..state.rollcalls.len() {
        let rc = &state.rollcalls[i];
        if !rc.active {
            continue;
        }
        if rc.origin && t - rc.started > ROLLCALL_WAIT {
            rollcall_end(state, i);
        } else if !rc.origin && t - rc.started > ROLLCALL_KEEP {
            state.rollcalls[i].active = false;
        }
    }
}

/// The upgrade start that waited on its roll call: answer the console that
/// asked, if it is still there.
fn start_resume(state: &mut HubState, gone: &[String]) {
    let w = std::mem::take(&mut state.upg_start_wait);
    let Some(ci) = state
        .clients
        .iter()
        .position(|c| c.fd == w.admin_fd && c.conn_serial == w.admin_serial)
    else {
        crate::hlog_info!(
            "[UPGRADE] The console that asked for the start is gone; nothing started\n"
        );
        return;
    };
    if !gone.is_empty() {
        let why = format!(
            "{} hub{} did not answer: {}",
            gone.len(),
            if gone.len() == 1 { "" } else { "s" },
            crate::cstr::trunc_string(&gone.join(", "), 319)
        );
        crate::admin::admin_err(
            state,
            ci,
            "upg.hubs_missing",
            &why,
            Some("bring it back, or remove it with hub del; then start again"),
        );
        return;
    }
    crate::admin::upgrade_start(state, ci, &w.payload, true);
}

/// The step gate: Some(names of the hubs that did not answer, empty when all
/// did), or None while its roll call is still out.
pub fn plan_hubs_answered(state: &mut HubState) -> Option<Vec<String>> {
    let t = now();
    let s = &mut state.step_rollcall;
    if s.outcome != 0 && t - s.at <= ROLLCALL_WAIT + 2 {
        s.outcome = 0;
        return Some(std::mem::take(&mut s.gone));
    }
    s.outcome = 0;
    if !s.rc.is_empty() {
        return None;
    }
    if let Some(id) = begin(state, RollcallPurpose::Step) {
        state.step_rollcall.rc = id;
        return None;
    }
    Some(crate::upgrade::hubs_missing(state))
}
