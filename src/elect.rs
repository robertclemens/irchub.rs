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
use crate::{client, crypto, queue};

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
        reply_fd: -1,
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
        let act = if e.kind == "mode" {
            // The bot needs only eid|mode|channel.
            trunc_string(
                &format!("{}|{}|{}", e.id, e.kind, e.channel),
                MAX_MASK_LEN + 256,
            )
        } else {
            trunc_string(
                &format!(
                    "{}|{}|{}|{}|{}|{}",
                    e.id, e.kind, e.channel, e.requester, e.nick, e.hostmask
                ),
                MAX_MASK_LEN + 256,
            )
        };
        let uuid = e.bots[bi].uuid.clone();
        state.chan_elections[ei].bots[bi].st = b't';
        let mode = state.chan_elections[ei].kind == "mode";
        let sent = match bot(state, &uuid) {
            Some(ci) if mode => client::send_cmd_to_bot_after_config(state, ci, CMD_CHAN_DO, &act),
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
        "mode" => "mode",
        _ => "key",
    }
}

/// The origin's end of an election: answer the console that asked, log, and
/// free the slot.  status: "ok" (one bot did it), "bitch" (refused, D12),
/// anything else = nobody could.
fn finish(
    state: &mut HubState,
    ei: usize,
    status: &str,
    by_uuid: &str,
    by_nick: &str,
    hub_name: &str,
    detail: &str,
) {
    let e = state.chan_elections[ei].clone();
    let asked = e.bots.len() as i64 + e.hubs.iter().map(|h| h.asked).sum::<i64>();
    let hubs = 1 + e.hubs.len() as i64;
    let ok = status == "ok";
    let bitch = status == "bitch";
    let who = if e.nick.is_empty() {
        &e.requester
    } else {
        &e.nick
    };
    let kw = kind_word(&e.kind);
    if bitch {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): refused, not authorised and +bitch is on\n",
            e.channel,
            e.id
        );
    } else if ok {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): done by {} on {hub_name}\n",
            e.channel,
            e.id,
            if by_nick.is_empty() { by_uuid } else { by_nick }
        );
    } else {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): nobody could ({})\n",
            e.channel,
            e.id,
            if detail.is_empty() { status } else { detail }
        );
    }

    // a person's request from a bot: the answer goes back to that bot
    if e.reply_fd >= 0
        && let Some(bi) = state.clients.iter().position(|c| {
            c.typ == ClientType::Bot
                && c.authenticated
                && c.fd == e.reply_fd
                && c.conn_serial == e.reply_serial
        })
    {
        let res = if bitch {
            format!(
                "{}|fail|not authorised on {} and +bitch is on",
                e.reply_rid,
                crate::cstr::trunc(&e.channel, 65)
            )
        } else if ok {
            format!(
                "{}|ok|{} by {} on {}",
                e.reply_rid,
                kw,
                crate::cstr::trunc(if by_nick.is_empty() { by_uuid } else { by_nick }, 32),
                crate::cstr::trunc(hub_name, 64)
            )
        } else {
            let why = reasons(&e, 160);
            format!(
                "{}|fail|no bot could: {asked} asked on {hubs} hub{}{}{}",
                e.reply_rid,
                if hubs == 1 { "" } else { "s" },
                if why.is_empty() { "" } else { "; " },
                crate::cstr::trunc(&why, 121)
            )
        };
        client::send_cmd_to_bot(
            &mut state.clients[bi],
            CMD_USER_CHAN_RESULT,
            &trunc_string(&res, 256),
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
    if let (Some(ai), true) = (admin, bitch) {
        // A bot answered fail|bitch: the nick is not authorised on a +bitch
        // channel (D12).  Deterministic for that nick, so no other bot is
        // tried.
        let msg = format!(
            "{} is not authorised on {} and +bitch is on",
            crate::cstr::trunc(&e.nick, 32),
            crate::cstr::trunc(&e.channel, 65)
        );
        let hint = format!(
            "add the user as an operator, or channel set {} -bitch",
            crate::cstr::trunc(&e.channel, 65)
        );
        admin_err(state, ai, "channel.not_authorised", &msg, Some(&hint));
    } else if let Some(ai) = admin {
        let code = format!("channel.{}", e.kind);
        if ok {
            let mut r = Reply::new();
            r.ok(&code);
            if !e.nick.is_empty() || e.kind != "mode" {
                r.kv("nick", &e.nick);
            }
            r.kv("chan", &e.channel);
            r.kv("by", if by_nick.is_empty() { by_uuid } else { by_nick });
            r.kv("by_uuid", by_uuid);
            r.kv("hub_name", hub_name);
            if !detail.is_empty() {
                r.kv("detail", detail);
            }
            r.kvi("asked", asked);
            r.kvi("hubs", hubs);
            if e.kind == "mode"
                && let Some(cn) = crate::storage::chan_live(state, &e.channel)
            {
                // the stored string rides the apply answer: it is the one
                // reply channel mode gets
                crate::admin::mf_mode_card_extra(state, &mut r, &cn);
            }
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
            let msg = if e.kind == "mode" {
                trunc_string(
                    &format!(
                        "no bot could apply the modes of {}: {asked} bot{} asked on {hubs} hub{}{}{tail}",
                        e.channel,
                        if asked == 1 { "" } else { "s" },
                        if hubs == 1 { "" } else { "s" },
                        if !tail.is_empty() { "; " } else { "" },
                    ),
                    256,
                )
            } else {
                trunc_string(
                    &format!(
                        "no bot could {kw} {} on {}: {asked} bot{} asked on {hubs} hub{}{}{tail}",
                        e.nick,
                        e.channel,
                        if asked == 1 { "" } else { "s" },
                        if hubs == 1 { "" } else { "s" },
                        if !tail.is_empty() { "; " } else { "" },
                    ),
                    256,
                )
            };
            if e.kind == "mode" {
                // the modes were stored before the election: say so, and warn
                // about older hubs here too (D38)
                let mut er = Reply::new();
                er.err(
                    "channel.nobody",
                    Some(&msg),
                    Some(
                        "the modes are stored; a bot must be in the channel and opped there to apply them (channel mode again)",
                    ),
                );
                er.kvb("stored", true);
                send_reply(state, ai, &mut er);
            } else {
                admin_err(
                    state,
                    ai,
                    "channel.nobody",
                    &msg,
                    Some("a bot must be in the channel and opped there"),
                );
            }
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

/// Origin, nobody local can: the next hub with a ready bot, else nobody.  A
/// bot that never answered the probe is not handed a blind old-style request:
/// every bot the mesh admits (MESH_MIN_VERSION) answers probes, so silence
/// means busy or gone, and the old fan-out skipped +bitch (D12).
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
    finish(state, ei, "nobody", "", "", "", "");
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
/// answer as (fd, conn_serial), or None.  Its slot, or None when the table is
/// full (nothing was sent).
pub fn start(
    state: &mut HubState,
    kind: &str,
    channel: &str,
    requester: &str,
    nick: &str,
    hostmask: &str,
    admin: Option<(i32, u64)>,
) -> Option<usize> {
    let ei = alloc(state)?;
    let id = crate::opflow::generate_request_id();
    if kind == "key" && !add_pending_chan_request(state, &id, requester, kind, channel, -1) {
        return None;
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
    Some(ei)
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
            finish(state, ei, "ok", &from, &nick, &hn, &clean);
        } else {
            done_up(state, ei, &from, &nick, "ok", &clean);
            state.chan_elections[ei].phase = ChanElectPhase::Acked;
        }
        return;
    }
    // fail|bitch: not authorised on a +bitch channel.  The answer is about
    // the nick, not the bot, so it ends the election (D12).
    if status == "fail" && clean == "bitch" && state.chan_elections[ei].kind == "op" {
        if state.chan_elections[ei].origin {
            let hn = hub_display_name(state).to_string();
            finish(state, ei, "bitch", &from, &nick, &hn, &clean);
        } else {
            done_up(state, ei, &from, &nick, "fail", &clean);
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
        || !(chan_kind_valid(&kind) || kind == "op" || kind == "mode")
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

/// ELECT_DO: eid|hub_uuid|elect.  Ours: act; else route it on.  "legacy"
/// (from a 2.5.0 origin) is no longer acted on: see try_hub.
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
    if mode != "elect" {
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
        );
    } else if status == "fail"
        && roster_clean(&detail, 96) == "bitch"
        && state.chan_elections[ei].kind == "op"
    {
        finish(
            state,
            ei,
            "bitch",
            &roster_clean(&bot_uuid, 64),
            &roster_clean(&nick, MAX_NICK),
            &cn,
            &roster_clean(&detail, 96),
        );
    } else {
        try_hub(state, ei);
    }
}

/// hub_chan_mode_apply(): console entry point, apply a channel's stored modes
/// once (kind "mode").  One elected bot reads the stored C| modes and the c|
/// key and sends the MODE line(s); the answer reaches `admin` when the
/// election ends.  False = the election table is full.
pub fn chan_mode_apply(state: &mut HubState, channel: &str, admin: Option<(i32, u64)>) -> bool {
    if !(channel.starts_with('#') || channel.starts_with('&')) {
        return false;
    }
    start(state, "mode", channel, "ADMIN", "", "", admin).is_some()
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
                finish(state, ei, "timeout", "", "", "", "timed out");
            }
            state.chan_elections[ei].active = false;
            continue;
        }
        match e.phase {
            ChanElectPhase::Probe => {
                if count(e, b'a') > 0 && t - e.phase_at < CHAN_ELECT_PROBE_WAIT {
                    continue;
                }
                // still silent: a no, with the reason the answer gives
                for b in state.chan_elections[ei]
                    .bots
                    .iter_mut()
                    .filter(|b| b.st == b'a')
                {
                    b.st = b'n';
                    b.reason = "no answer".into();
                }
                let e = &state.chan_elections[ei];
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

/// A field of a person's request: 1..max-1 bytes, no blank, '|' or control.
fn uchan_field_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() < max && s.bytes().all(|c| c > 0x20 && c != 0x7f && c != b'|')
}

/// CMD_USER_CHAN_REQUEST (user_flags plan §5): `rid|kind|#chan|user_uuid|
/// nick|nick!user@host` from a bot that could not act itself.  The user's
/// rights are checked again here (an admin +c / +a, or an oper bound to the
/// channel or *).  C `process_user_chan_request`.
pub fn process_user_chan_request(state: &mut HubState, ci: usize, payload: &str) {
    let t = now();
    {
        let c = &mut state.clients[ci];
        if t - c.uchan_req_window >= USER_CHAN_REQ_WINDOW {
            c.uchan_req_window = t;
            c.uchan_req_count = 0;
        }
        c.uchan_req_count += 1;
        if c.uchan_req_count > USER_CHAN_REQ_MAX {
            if c.uchan_req_count == USER_CHAN_REQ_MAX + 1 {
                crate::hlog_warning!(
                    "[CHANREQ] {} sends too many user requests; dropping\n",
                    c.id
                );
            }
            return;
        }
    }
    let id = state.clients[ci].id.clone();
    let f = |i: usize, cap: usize| crate::admin::wire_field(payload, i, cap);
    let fields = (
        f(0, USER_CHAN_RID_MAX + 1),
        f(1, 8),
        f(2, MAX_CHAN),
        f(3, 40),
        f(4, MAX_NICK),
        f(5, MAX_MASK_LEN),
    );
    let (Some(mut rid), Some(kind), Some(chan), Some(uuid), Some(nick), Some(mask)) = fields else {
        crate::hlog_warning!("[CHANREQ] Malformed USER_CHAN_REQUEST from {id}\n");
        return;
    };
    if crate::admin::mf_field_count(payload) != 6 {
        crate::hlog_warning!("[CHANREQ] Malformed USER_CHAN_REQUEST from {id}\n");
        return;
    }
    if !rid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        rid.clear();
    }
    if rid.is_empty() {
        crate::hlog_warning!("[CHANREQ] Bad request id from {id}\n");
        return;
    }
    let fail = |state: &mut HubState, why: &str| {
        let res = trunc_string(&format!("{rid}|fail|{why}"), 256);
        client::send_cmd_to_bot(&mut state.clients[ci], CMD_USER_CHAN_RESULT, &res);
    };
    if kind != "op" && kind != "invite" && kind != "unban" {
        return fail(state, "unknown request");
    }
    if !crate::access::uchan_name_ok(&chan) || chan == "*" {
        return fail(state, "not a channel");
    }
    if !uchan_field_ok(&nick, MAX_NICK)
        || !uchan_field_ok(&mask, MAX_MASK_LEN)
        || !mask.contains('!')
        || !mask.contains('@')
    {
        return fail(state, "bad nick or hostmask");
    }
    let u = state
        .user_records
        .iter()
        .find(|u| u.is_active && u.uuid == uuid)
        .cloned();
    let allowed = u.as_ref().is_some_and(|u| {
        if u.typ == 'a' {
            crate::access::user_has_flag(state, &u.uuid, 'c')
        } else {
            crate::access::user_chan_ok(state, &u.uuid, Some(&chan))
        }
    });
    let who = u.as_ref().map_or(uuid.clone(), |u| u.name.clone());
    let Some(u) = u.filter(|_| allowed) else {
        crate::hlog_warning!(
            "[CHANREQ] {id} asked {kind} {nick} on {chan} for {who}: refused (no rights there)\n"
        );
        let why = format!("no rights on {chan}");
        return fail(state, &why);
    };
    if crate::storage::chan_live(state, &chan).is_none() {
        let why = format!("{chan} is not a managed channel");
        return fail(state, &why);
    }
    crate::hlog_info!(
        "[CHANREQ] {kind} for {nick} ({}) on {chan}, from {id}\n",
        u.name
    );
    let Some(ei) = start(state, &kind, &chan, &u.uuid, &nick, &mask, None) else {
        return fail(state, "too many channel requests in flight; try again");
    };
    let (fd, serial) = (state.clients[ci].fd, state.clients[ci].conn_serial);
    let e = &mut state.chan_elections[ei];
    e.reply_fd = fd;
    e.reply_serial = serial;
    e.reply_rid = rid;
}
