//! Channel-request election (see CMD_CHAN_PROBE in consts.rs).  One bot acts.
//! This hub asks its own bots, hands the action to one that said yes, and --
//! when it started the request and none of its own can -- asks the rest of
//! the mesh the same question and hands it to one hub that has a ready bot.
//! Every step is bounded by a wait in consts.rs, so a console waiting for the
//! answer always gets one.  1:1 with the election block in hub_logic.c.

use crate::admin::{
    admin_err, hub_display_name, linked_peer_count, send_reply, wire_field, wire_tail,
};
use crate::consts::*;
use crate::cstr::{now, trunc_string};
use crate::opflow::{add_pending_chan_request, chan_kind_valid, forward_seen_check_and_add};
use crate::presence::{bot_nick_from_config, roster_clean};
use crate::reply::Reply;
use crate::state::{ChanElect, ChanElectBot, ChanElectHub, ChanElectPhase, ClientType, HubState};
use crate::{client, crypto, queue, update};

fn find(state: &HubState, id: &str) -> Option<usize> {
    state
        .chan_elections
        .iter()
        .position(|e| e.active && e.id == id)
}

fn alloc(state: &mut HubState) -> Option<usize> {
    let i = state.chan_elections.iter().position(|e| !e.active)?;
    let t = now();
    state.chan_elections[i] = ChanElect {
        from_fd: -1,
        admin_fd: -1,
        created: t,
        phase_at: t,
        ..ChanElect::default()
    };
    Some(i)
}

/// A uniformly drawn index below n (n > 0).
fn pick(n: usize) -> usize {
    crypto::random_below(n as u32) as usize
}

/// Every hub this one knows of speaks the election; otherwise the request
/// takes the old path end to end (an older hub ignores the new frames).
pub fn mesh_ready(state: &HubState) -> bool {
    state.mesh_hubs.iter().all(|m| {
        (!state.hub_uuid.is_empty() && m.uuid == state.hub_uuid)
            || (!m.version.is_empty()
                && update::version_cmp(&m.version, CHAN_ELECT_MIN_HUB) != std::cmp::Ordering::Less)
    })
}

fn peer(state: &HubState, fd: i32) -> Option<usize> {
    state
        .clients
        .iter()
        .position(|c| c.typ == ClientType::Hub && c.authenticated && c.fd == fd)
}

fn bot(state: &HubState, uuid: &str) -> Option<usize> {
    state
        .clients
        .iter()
        .position(|c| c.typ == ClientType::Bot && c.authenticated && c.id == uuid)
}

fn send_peer(state: &mut HubState, fd: i32, cmd: u8, payload: &str) -> bool {
    match peer(state, fd) {
        Some(pi) => queue::send_urgent(&mut state.clients[pi], cmd, payload),
        None => false,
    }
}

fn count(e: &ChanElect, st: u8) -> usize {
    e.bots.iter().filter(|b| b.st == st).count()
}

/// Ask every local bot except the requester.
fn probe_local(state: &mut HubState, ei: usize) {
    let (id, kind, channel, requester) = {
        let e = &state.chan_elections[ei];
        (
            e.id.clone(),
            e.kind.clone(),
            e.channel.clone(),
            e.requester.clone(),
        )
    };
    let probe = format!("{id}|{kind}|{channel}");
    let mut bots = Vec::new();
    for ci in state.bot_clients() {
        if bots.len() >= MAX_CLIENTS {
            break;
        }
        if state.clients[ci].id == requester {
            continue; // it cannot help itself
        }
        let uuid = state.clients[ci].id.clone();
        let nick = bot_nick_from_config(state, &uuid);
        let sent = client::send_cmd_to_bot(&mut state.clients[ci], CMD_CHAN_PROBE, &probe);
        bots.push(ChanElectBot {
            uuid,
            nick,
            st: if sent { b'a' } else { b'n' },
            reason: if sent {
                String::new()
            } else {
                "unreachable".into()
            },
        });
    }
    let e = &mut state.chan_elections[ei];
    e.bots = bots;
    e.phase = ChanElectPhase::Probe;
    e.phase_at = now();
}

/// Hand the action to one ready local bot.  False when none is left.
fn try_local(state: &mut HubState, ei: usize) -> bool {
    loop {
        let e = &state.chan_elections[ei];
        let ready = count(e, b'y');
        if ready == 0 {
            return false;
        }
        let k = pick(ready);
        let Some(bi) = e
            .bots
            .iter()
            .enumerate()
            .filter(|(_, b)| b.st == b'y')
            .nth(k)
            .map(|(i, _)| i)
        else {
            return false;
        };
        let act = trunc_string(
            &format!(
                "{}|{}|{}|{}|{}|{}",
                e.id, e.kind, e.channel, e.requester, e.nick, e.hostmask
            ),
            MAX_MASK_LEN + 256,
        );
        let uuid = e.bots[bi].uuid.clone();
        state.chan_elections[ei].bots[bi].st = b't';
        let sent = match bot(state, &uuid) {
            Some(ci) => client::send_cmd_to_bot(&mut state.clients[ci], CMD_CHAN_DO, &act),
            None => false,
        };
        let e = &mut state.chan_elections[ei];
        if !sent {
            e.bots[bi].reason = "unreachable".into();
            continue;
        }
        e.doing = uuid;
        e.phase = ChanElectPhase::LocalDo;
        e.phase_at = now();
        return true;
    }
}

/// The old path, for local bots that never answered the probe.  Returns how
/// many were told.
fn legacy_local(state: &mut HubState, ei: usize) -> i64 {
    let e = state.chan_elections[ei].clone();
    let mut told = 0;
    for b in e.bots.iter().filter(|b| b.st == b'a') {
        let Some(ci) = bot(state, &b.uuid) else {
            continue;
        };
        let ok = if e.kind == "op" {
            let buf = format!("{}|{}", e.nick, e.channel);
            client::send_cmd_to_bot(&mut state.clients[ci], CMD_OP_GRANT, &buf)
        } else {
            let buf = trunc_string(
                &format!(
                    "{}|{}|{}|{}|{}|{}",
                    e.id, e.kind, e.channel, e.requester, e.nick, e.hostmask
                ),
                MAX_MASK_LEN + 256,
            );
            client::send_cmd_to_bot(&mut state.clients[ci], CMD_CHAN_ACTION, &buf)
        };
        if ok {
            told += 1;
        }
    }
    told
}

/// "3 not opped, 1 not in channel" from our own bots' answers.
fn reasons(e: &ChanElect, cap: usize) -> String {
    let said_no = |b: &ChanElectBot| (b.st == b'n' || b.st == b't') && !b.reason.is_empty();
    let mut used = vec![false; e.bots.len()];
    let mut out = String::new();
    for (i, bi) in e.bots.iter().enumerate() {
        if used[i] || !said_no(bi) {
            continue;
        }
        let mut n = 0;
        for (j, bj) in e.bots.iter().enumerate().skip(i) {
            if !used[j] && said_no(bj) && bj.reason == bi.reason {
                used[j] = true;
                n += 1;
            }
        }
        let piece = format!(
            "{}{} {}",
            if out.is_empty() { "" } else { ", " },
            n,
            bi.reason
        );
        if out.len() + piece.len() >= cap {
            break;
        }
        out.push_str(&piece);
    }
    out
}

fn kind_word(kind: &str) -> &'static str {
    match kind {
        "op" => "op",
        "invite" => "invite",
        "unban" => "unban",
        _ => "key",
    }
}

/// The origin's end of an election: answer the console that asked, log, and
/// free the slot.  status: "ok" (one bot did it), "legacy" (older bots were
/// asked the old way), anything else = nobody could.
#[allow(clippy::too_many_arguments)]
fn finish(
    state: &mut HubState,
    ei: usize,
    status: &str,
    by_uuid: &str,
    by_nick: &str,
    hub_name: &str,
    detail: &str,
    legacy: i64,
) {
    let e = state.chan_elections[ei].clone();
    let asked = e.bots.len() as i64 + e.hubs.iter().map(|h| h.asked).sum::<i64>();
    let hubs = 1 + e.hubs.len() as i64;
    let ok = status == "ok";
    let leg = status == "legacy";
    let who = if e.nick.is_empty() {
        &e.requester
    } else {
        &e.nick
    };
    let kw = kind_word(&e.kind);
    if ok {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): done by {} on {hub_name}\n",
            e.channel,
            e.id,
            if by_nick.is_empty() { by_uuid } else { by_nick }
        );
    } else if leg {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): no ready bot; {legacy} older bot(s) asked\n",
            e.channel,
            e.id
        );
    } else {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): nobody could ({})\n",
            e.channel,
            e.id,
            if detail.is_empty() { status } else { detail }
        );
    }

    let admin = if e.admin_fd >= 0 {
        state
            .clients
            .iter()
            .rposition(|c| c.internal && c.fd == e.admin_fd && c.conn_serial == e.admin_serial)
    } else {
        None
    };
    if let Some(ai) = admin {
        let code = format!("channel.{}", e.kind);
        if ok || leg {
            let mut r = Reply::new();
            r.ok(&code);
            r.kv("nick", &e.nick);
            r.kv("chan", &e.channel);
            if ok {
                r.kv("by", if by_nick.is_empty() { by_uuid } else { by_nick });
                r.kv("by_uuid", by_uuid);
                r.kv("hub_name", hub_name);
                if !detail.is_empty() {
                    r.kv("detail", detail);
                }
            } else {
                r.kvi("legacy", legacy);
            }
            r.kvi("asked", asked);
            r.kvi("hubs", hubs);
            send_reply(state, ai, &mut r);
        } else {
            let mut why = reasons(&e, 160);
            // Only our own bots' reasons travel; the other hubs send counts.
            if why.is_empty() && detail.is_empty() && asked > 0 {
                why = "none is in the channel and opped".into();
            }
            let tail = if !why.is_empty() {
                why.as_str()
            } else {
                detail
            };
            let msg = trunc_string(
                &format!(
                    "no bot could {kw} {} on {}: {asked} bot{} asked on {hubs} hub{}{}{tail}",
                    e.nick,
                    e.channel,
                    if asked == 1 { "" } else { "s" },
                    if hubs == 1 { "" } else { "s" },
                    if !tail.is_empty() { "; " } else { "" },
                ),
                256,
            );
            admin_err(
                state,
                ai,
                "channel.nobody",
                &msg,
                Some("a bot must be in the channel and opped there"),
            );
        }
    }
    state.chan_elections[ei].active = false;
}

/// A relay hub's report back toward the origin.
fn up(state: &mut HubState, ei: usize, cmd: u8, payload: &str) {
    let fd = state.chan_elections[ei].from_fd;
    send_peer(state, fd, cmd, payload);
}

fn done_up(
    state: &mut HubState,
    ei: usize,
    bot_uuid: &str,
    bot_nick: &str,
    status: &str,
    detail: &str,
) {
    let buf = trunc_string(
        &format!(
            "{}|{}|{}|{bot_uuid}|{bot_nick}|{status}|{detail}",
            state.chan_elections[ei].id,
            state.hub_uuid,
            hub_display_name(state)
        ),
        512,
    );
    up(state, ei, CMD_CHAN_ELECT_DONE, &buf);
}

/// Origin, nobody local can: the next hub with a ready bot, else the older
/// bots, else nobody.
fn try_hub(state: &mut HubState, ei: usize) {
    loop {
        let e = &state.chan_elections[ei];
        let ready: Vec<usize> = (0..e.hubs.len())
            .filter(|&i| !e.hubs[i].tried && e.hubs[i].ready > 0)
            .collect();
        if ready.is_empty() {
            break;
        }
        let hi = ready[pick(ready.len())];
        let (fd, uuid, id) = (e.hubs[hi].fd, e.hubs[hi].uuid.clone(), e.id.clone());
        state.chan_elections[ei].hubs[hi].tried = true;
        if !send_peer(state, fd, CMD_CHAN_ELECT_DO, &format!("{id}|{uuid}|elect")) {
            continue; // that hub's link went away: the next one
        }
        let e = &mut state.chan_elections[ei];
        e.doing = uuid;
        e.phase = ChanElectPhase::MeshDo;
        e.phase_at = now();
        return;
    }
    let mut legacy = legacy_local(state, ei);
    let e = state.chan_elections[ei].clone();
    for h in e.hubs.iter().filter(|h| h.silent > 0) {
        if send_peer(
            state,
            h.fd,
            CMD_CHAN_ELECT_DO,
            &format!("{}|{}|legacy", e.id, h.uuid),
        ) {
            legacy += h.silent;
        }
    }
    if legacy > 0 {
        finish(state, ei, "legacy", "", "", "", "", legacy);
    } else {
        finish(state, ei, "nobody", "", "", "", "", 0);
    }
}

/// Nothing (more) to do locally: the origin asks the mesh, a relay says so.
fn local_exhausted(state: &mut HubState, ei: usize) {
    if !state.chan_elections[ei].origin {
        done_up(state, ei, "", "", "fail", "no ready bot");
        state.chan_elections[ei].phase = ChanElectPhase::Acked;
        return;
    }
    let e = &state.chan_elections[ei];
    if e.phase == ChanElectPhase::MeshDo || !e.hubs.is_empty() || linked_peer_count(state) == 0 {
        try_hub(state, ei);
        return;
    }
    let fwd = trunc_string(
        &format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            e.id,
            state.hub_uuid,
            e.kind,
            e.channel,
            e.requester,
            e.nick,
            e.hostmask,
            now()
        ),
        MAX_MASK_LEN + 320,
    );
    for i in 0..state.clients.len() {
        if state.clients[i].typ == ClientType::Hub && state.clients[i].authenticated {
            queue::send_urgent(&mut state.clients[i], CMD_CHAN_ELECT_FWD, &fwd);
        }
    }
    let e = &mut state.chan_elections[ei];
    e.phase = ChanElectPhase::MeshWait;
    e.phase_at = now();
}

/// Start an election on this hub (the origin).  admin: the console owed the
/// answer as (fd, conn_serial), or None.  False when the table is full
/// (nothing was sent).
pub fn start(
    state: &mut HubState,
    kind: &str,
    channel: &str,
    requester: &str,
    nick: &str,
    hostmask: &str,
    admin: Option<(i32, u64)>,
) -> bool {
    let Some(ei) = alloc(state) else {
        return false;
    };
    let id = crate::opflow::generate_request_id();
    if kind == "key" && !add_pending_chan_request(state, &id, requester, kind, channel, -1) {
        return false;
    }
    forward_seen_check_and_add(state, &id);
    {
        let e = &mut state.chan_elections[ei];
        e.id = id;
        e.active = true;
        e.origin = true;
        // The answer is bound to this connection, not just its fd: a console
        // that closes and a new one that takes over the fd must never meet.
        (e.admin_fd, e.admin_serial) = admin.unwrap_or((-1, 0));
        e.kind = trunc_string(kind, 8);
        e.channel = trunc_string(channel, MAX_CHAN);
        e.requester = trunc_string(requester, 64);
        e.nick = trunc_string(nick, MAX_NICK);
        e.hostmask = trunc_string(hostmask, MAX_MASK_LEN);
    }
    probe_local(state, ei);
    let e = &state.chan_elections[ei];
    crate::hlog_debug!(
        "[CHANREQ] Election {}: {kind} {} on {channel}, {} local bot(s) asked\n",
        e.id,
        if e.nick.is_empty() {
            requester
        } else {
            &e.nick
        },
        e.bots.len()
    );
    true
}

/// A local bot's answer to PROBE: eid|1| or eid|0|reason.
pub fn process_probe_ack(state: &mut HubState, ci: usize, payload: &str) {
    let id = wire_field(payload, 0, 64).unwrap_or_default();
    let okf = wire_field(payload, 1, 4).unwrap_or_default();
    let reason = wire_tail(payload, 2, CHAN_ELECT_REASON_MAX - 1).unwrap_or_default();
    let Some(ei) = (!id.is_empty()).then(|| find(state, &id)).flatten() else {
        return;
    };
    let from = state.clients[ci].id.clone();
    let e = &mut state.chan_elections[ei];
    if e.phase != ChanElectPhase::Probe {
        return;
    }
    if let Some(b) = e.bots.iter_mut().find(|b| b.st == b'a' && b.uuid == from) {
        b.st = if okf.starts_with('1') { b'y' } else { b'n' };
        b.reason = if b.st == b'y' {
            String::new()
        } else {
            roster_clean(
                if reason.is_empty() { "cannot" } else { &reason },
                CHAN_ELECT_REASON_MAX,
            )
        };
    }
}

/// The bot we handed the action to reports: eid|ok|detail or eid|fail|detail.
pub fn process_done(state: &mut HubState, ci: usize, payload: &str) {
    let id = wire_field(payload, 0, 64).unwrap_or_default();
    let status = wire_field(payload, 1, 8).unwrap_or_default();
    let detail = wire_tail(payload, 2, 95).unwrap_or_default();
    let Some(ei) = (!id.is_empty()).then(|| find(state, &id)).flatten() else {
        return;
    };
    let from = state.clients[ci].id.clone();
    let e = &state.chan_elections[ei];
    if e.phase != ChanElectPhase::LocalDo || e.doing != from {
        return;
    }
    let clean = roster_clean(&detail, 96);
    let nick = e
        .bots
        .iter()
        .rfind(|b| b.uuid == from)
        .map(|b| b.nick.clone())
        .unwrap_or_default();
    if status == "ok" {
        if e.origin {
            let hn = hub_display_name(state).to_string();
            finish(state, ei, "ok", &from, &nick, &hn, &clean, 0);
        } else {
            done_up(state, ei, &from, &nick, "ok", &clean);
            state.chan_elections[ei].phase = ChanElectPhase::Acked;
        }
        return;
    }
    let e = &mut state.chan_elections[ei];
    if let Some(b) = e.bots.iter_mut().rfind(|b| b.uuid == from) {
        b.reason = roster_clean(
            if clean.is_empty() { "failed" } else { &clean },
            CHAN_ELECT_REASON_MAX,
        );
    }
    e.doing.clear();
    if !try_local(state, ei) {
        local_exhausted(state, ei);
    }
}

/// ELECT_FWD from a peer: eid|origin_hub|kind|channel|requester|nick|hostmask|ts
pub fn process_elect_fwd(state: &mut HubState, ci: usize, payload: &str) {
    let fd = state.clients[ci].fd;
    let f = |i, cap| wire_field(payload, i, cap);
    let (Some(id), Some(_origin), Some(kind), Some(channel), Some(requester)) =
        (f(0, 64), f(1, 64), f(2, 8), f(3, MAX_CHAN), f(4, 64))
    else {
        crate::hlog_warning!("[CHANREQ] Malformed CHAN_ELECT_FWD from peer fd={fd}\n");
        return;
    };
    if id.is_empty()
        || !(chan_kind_valid(&kind) || kind == "op")
        || !(channel.starts_with('#') || channel.starts_with('&'))
    {
        crate::hlog_warning!("[CHANREQ] Malformed CHAN_ELECT_FWD from peer fd={fd}\n");
        return;
    }
    let nick = f(5, MAX_NICK).unwrap_or_default();
    let hostmask = f(6, MAX_MASK_LEN).unwrap_or_default();
    let ts = crate::cstr::atoll(&f(7, 24).unwrap_or_default());
    let age = now() - ts;
    if ts <= 0 || !(-CHAN_ELECT_TTL..=CHAN_ELECT_TTL).contains(&age) {
        return;
    }
    if forward_seen_check_and_add(state, &id) {
        return; // another path got here first
    }
    let Some(ei) = alloc(state) else {
        crate::hlog_warning!("[CHANREQ] Election table full — not answering {id}\n");
        return;
    };
    // A key travels home as CHAN_REPLY through the pending table, hop by hop.
    if kind == "key" {
        add_pending_chan_request(state, &id, &requester, &kind, &channel, fd);
    }
    {
        let e = &mut state.chan_elections[ei];
        e.active = true;
        e.from_fd = fd;
        e.id = id;
        e.kind = kind;
        e.channel = channel;
        e.requester = requester;
        e.nick = nick;
        e.hostmask = hostmask;
    }
    for i in 0..state.clients.len() {
        let c = &state.clients[i];
        if c.typ == ClientType::Hub && c.authenticated && c.fd != fd {
            queue::send_urgent(&mut state.clients[i], CMD_CHAN_ELECT_FWD, payload);
        }
    }
    probe_local(state, ei);
    let e = &state.chan_elections[ei];
    crate::hlog_debug!(
        "[CHANREQ] Election {} from peer fd={fd}: {} {} on {}, {} local bot(s) asked\n",
        e.id,
        e.kind,
        if e.nick.is_empty() {
            &e.requester
        } else {
            &e.nick
        },
        e.channel,
        e.bots.len()
    );
}

/// ELECT_ACK: eid|hub_uuid|hub_name|asked|ready|silent.  The origin records
/// it; a relay remembers which peer leads to that hub and passes it on.
pub fn process_elect_ack(state: &mut HubState, ci: usize, payload: &str) {
    let f = |i, cap| wire_field(payload, i, cap).unwrap_or_default();
    let (id, hub, name) = (f(0, 64), f(1, 64), f(2, 64));
    let num = |s: String| crate::cstr::atoi(&s).max(0) as i64;
    let (a, r, s) = (num(f(3, 12)), num(f(4, 12)), num(f(5, 12)));
    if id.is_empty() || hub.is_empty() {
        return;
    }
    let Some(ei) = find(state, &id) else {
        return;
    };
    let fd = state.clients[ci].fd;
    let e = &mut state.chan_elections[ei];
    if e.hubs.len() >= MAX_MESH_HUBS || e.hubs.iter().any(|h| h.uuid == hub) {
        return; // full, or a second copy
    }
    e.hubs.push(ChanElectHub {
        uuid: roster_clean(&hub, 64),
        name: roster_clean(if name.is_empty() { &hub } else { &name }, 64),
        fd,
        asked: a,
        ready: r,
        silent: s,
        tried: false,
    });
    if !e.origin {
        up(state, ei, CMD_CHAN_ELECT_ACK, payload);
    }
}

/// ELECT_DO: eid|hub_uuid|elect or legacy.  Ours: act; else route it on.
pub fn process_elect_do(state: &mut HubState, ci: usize, payload: &str) {
    let f = |i, cap| wire_field(payload, i, cap).unwrap_or_default();
    let (id, hub, mode) = (f(0, 64), f(1, 64), f(2, 8));
    let Some(ei) = (!id.is_empty()).then(|| find(state, &id)).flatten() else {
        return;
    };
    let fd = state.clients[ci].fd;
    let e = &state.chan_elections[ei];
    if e.origin || fd != e.from_fd {
        return;
    }
    if hub != state.hub_uuid {
        if let Some(h) = e.hubs.iter().find(|h| h.uuid == hub) {
            let hfd = h.fd;
            send_peer(state, hfd, CMD_CHAN_ELECT_DO, payload);
        }
        return;
    }
    if mode == "legacy" {
        let n = legacy_local(state, ei);
        let e = &state.chan_elections[ei];
        crate::hlog_info!(
            "[CHANREQ] {} {} on {} (id:{}): {n} older bot(s) asked here\n",
            kind_word(&e.kind),
            if e.nick.is_empty() {
                &e.requester
            } else {
                &e.nick
            },
            e.channel,
            e.id
        );
        return;
    }
    if !try_local(state, ei) {
        local_exhausted(state, ei);
    }
}

/// ELECT_DONE: eid|hub_uuid|hub_name|bot_uuid|bot_nick|status|detail.
pub fn process_elect_done(state: &mut HubState, _ci: usize, payload: &str) {
    let f = |i, cap| wire_field(payload, i, cap).unwrap_or_default();
    let (id, hub, name, bot_uuid, nick, status) = (
        f(0, 64),
        f(1, 64),
        f(2, 64),
        f(3, 64),
        f(4, MAX_NICK),
        f(5, 8),
    );
    let detail = wire_tail(payload, 6, 95).unwrap_or_default();
    let Some(ei) = (!id.is_empty()).then(|| find(state, &id)).flatten() else {
        return;
    };
    let e = &state.chan_elections[ei];
    if !e.origin {
        up(state, ei, CMD_CHAN_ELECT_DONE, payload);
        return;
    }
    if e.phase != ChanElectPhase::MeshDo || e.doing != hub {
        return;
    }
    let cn = roster_clean(if name.is_empty() { &hub } else { &name }, 64);
    if status == "ok" {
        finish(
            state,
            ei,
            "ok",
            &roster_clean(&bot_uuid, 64),
            &roster_clean(&nick, MAX_NICK),
            &cn,
            &roster_clean(&detail, 96),
            0,
        );
    } else {
        try_hub(state, ei);
    }
}

/// A console disconnected: the elections it waits on still finish and log,
/// but answer nobody.
pub fn forget_admin(state: &mut HubState, serial: u64) {
    for e in state
        .chan_elections
        .iter_mut()
        .filter(|e| e.active && e.admin_fd >= 0 && e.admin_serial == serial)
    {
        e.admin_fd = -1;
        e.admin_serial = 0;
    }
}

/// Drive every election one step.  Runs on every maintenance pass.
pub fn tick(state: &mut HubState, t: i64) {
    for ei in 0..state.chan_elections.len() {
        let e = &state.chan_elections[ei];
        if !e.active {
            continue;
        }
        if t - e.created > CHAN_ELECT_TTL {
            if e.origin {
                finish(state, ei, "timeout", "", "", "", "timed out", 0);
            }
            state.chan_elections[ei].active = false;
            continue;
        }
        match e.phase {
            ChanElectPhase::Probe => {
                if count(e, b'a') > 0 && t - e.phase_at < CHAN_ELECT_PROBE_WAIT {
                    continue;
                }
                if !e.origin {
                    let ack = format!(
                        "{}|{}|{}|{}|{}|{}",
                        e.id,
                        state.hub_uuid,
                        hub_display_name(state),
                        e.bots.len(),
                        count(e, b'y'),
                        count(e, b'a')
                    );
                    up(state, ei, CMD_CHAN_ELECT_ACK, &ack);
                    let e = &mut state.chan_elections[ei];
                    e.phase = ChanElectPhase::Acked;
                    e.phase_at = t;
                    continue;
                }
                if !try_local(state, ei) {
                    local_exhausted(state, ei);
                }
            }
            ChanElectPhase::LocalDo => {
                if t - e.phase_at < CHAN_ELECT_DO_WAIT {
                    continue;
                }
                let e = &mut state.chan_elections[ei];
                let doing = std::mem::take(&mut e.doing);
                for b in e.bots.iter_mut().filter(|b| b.uuid == doing) {
                    b.reason = "no answer".into();
                }
                if !try_local(state, ei) {
                    local_exhausted(state, ei);
                }
            }
            ChanElectPhase::MeshWait => {
                let expect = state
                    .mesh_hubs
                    .iter()
                    .filter(|m| m.uuid != state.hub_uuid)
                    .count();
                if e.hubs.len() < expect && t - e.phase_at < CHAN_ELECT_MESH_WAIT {
                    continue;
                }
                try_hub(state, ei);
            }
            ChanElectPhase::MeshDo => {
                if t - e.phase_at < CHAN_ELECT_HUB_WAIT {
                    continue;
                }
                try_hub(state, ei);
            }
            ChanElectPhase::Acked => {}
        }
    }
}
