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
use crate::state::{
    ChanElect, ChanElectBot, ChanElectHub, ChanElectPhase, ChanElectTarget, ClientType, HubState,
};
use crate::{client, crypto, queue};

fn find(state: &HubState, id: &str) -> Option<usize> {
    state
        .chan_elections
        .iter()
        .position(|e| e.active && e.id == id)
}

/// End an election: the slot is free and a `who` answer's buffer and a
/// batch's targets go.
fn release(state: &mut HubState, ei: usize) {
    let e = &mut state.chan_elections[ei];
    crypto::wipe(&mut e.who_buf); // it holds the key
    e.who_buf = Vec::new();
    e.tg = None;
    e.active = false;
}

/// Elections this hub holds a copy of now (hub stats).
pub fn in_flight(state: &HubState) -> usize {
    state.chan_elections.iter().filter(|e| e.active).count()
}

/// A bot's own request: the requester is neither the console nor a person.
fn own_requester(state: &HubState, requester: &str) -> bool {
    !requester.is_empty()
        && requester != "ADMIN"
        && !state.user_records.iter().any(|u| u.uuid == requester)
}

/// "Election table full": the first refusal is logged, the rest are counted
/// and logged as one line every CHAN_ELECT_FULL_LOG s (full_flush).
fn full_flush(state: &mut HubState, t: i64) {
    if state.ce_full_n == 0 || t - state.ce_full_at < CHAN_ELECT_FULL_LOG {
        return;
    }
    crate::hlog_warning!(
        "[CHANREQ] Election table full: {} more request(s) refused in the last {} s\n",
        state.ce_full_n,
        CHAN_ELECT_FULL_LOG
    );
    state.ce_full_n = 0;
    state.ce_full_at = t;
}

fn full_note(state: &mut HubState, own: bool, kind: &str, channel: &str) {
    let t = now();
    crate::stats::el_refused();
    if state.ce_full_at != 0 && t - state.ce_full_at < CHAN_ELECT_FULL_LOG {
        state.ce_full_n += 1;
        return;
    }
    state.ce_full_at = t;
    let n = in_flight(state);
    if own {
        crate::hlog_warning!(
            "[CHANREQ] Election table full ({n} in flight, {CHAN_ELECT_RESERVE} kept for the console): refused {kind} for {channel}; further refusals are counted\n"
        );
    } else {
        crate::hlog_warning!(
            "[CHANREQ] Election table full ({n} in flight): refused {kind} for {channel}; further refusals are counted\n"
        );
    }
}

/// A free slot, or None (logged).  A bot's own request leaves the last
/// CHAN_ELECT_RESERVE slots to the console and to persons.
fn alloc(state: &mut HubState, own: bool, kind: &str, channel: &str) -> Option<usize> {
    if own && in_flight(state) >= MAX_CHAN_ELECTIONS - CHAN_ELECT_RESERVE {
        full_note(state, own, kind, channel);
        return None;
    }
    let Some(i) = state.chan_elections.iter().position(|e| !e.active) else {
        full_note(state, own, kind, channel);
        return None;
    };
    release(state, i);
    crate::stats::el_started();
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

fn peer(state: &HubState, fd: i32, serial: u64) -> Option<usize> {
    state.clients.iter().position(|c| {
        c.typ == ClientType::Hub && c.authenticated && c.fd == fd && c.conn_serial == serial
    })
}

fn bot(state: &HubState, uuid: &str) -> Option<usize> {
    state
        .clients
        .iter()
        .position(|c| c.typ == ClientType::Bot && c.authenticated && !c.superseded && c.id == uuid)
}

fn send_peer(state: &mut HubState, fd: i32, serial: u64, cmd: u8, payload: &str) -> bool {
    match peer(state, fd, serial) {
        Some(pi) => queue::send_urgent(&mut state.clients[pi], cmd, payload),
        None => false,
    }
}

fn count(e: &ChanElect, st: u8) -> usize {
    e.bots.iter().filter(|b| b.st == st).count()
}

/// A hub version that takes ELECT_END and batched own-op elections.
fn version_new(v: &str) -> bool {
    !v.is_empty()
        && crate::update::version_cmp(v, CHAN_ELECT_BATCH_MIN_HUB) != std::cmp::Ordering::Less
}

/// Every hub this one knows (gossip and its own links) runs
/// CHAN_ELECT_BATCH_MIN_HUB or newer: only then may own op be batched.
fn batch_ok(state: &HubState) -> bool {
    state
        .mesh_hubs
        .iter()
        .all(|m| m.uuid == state.hub_uuid || version_new(&m.version))
        && (0..state.clients.len()).all(|ci| {
            let c = &state.clients[ci];
            !(c.typ == ClientType::Hub && c.authenticated)
                || version_new(&crate::mesh::peer_version_str(state, ci))
        })
}

/// A known hub's version from gossip ("" when unknown).
fn hub_version(state: &HubState, uuid: &str) -> String {
    state
        .mesh_hubs
        .iter()
        .find(|m| m.uuid == uuid)
        .map(|m| m.version.clone())
        .unwrap_or_default()
}

/// ELECT_END to every 2.5.4+ peer except `skip`, once per election (the
/// seen ring, key "end:<eid>").
fn end_send(state: &mut HubState, id: &str, skip: Option<usize>) {
    if forward_seen_check_and_add(state, &format!("end:{id}")) {
        return;
    }
    for ci in 0..state.clients.len() {
        let c = &state.clients[ci];
        if Some(ci) != skip
            && c.typ == ClientType::Hub
            && c.authenticated
            && version_new(&crate::mesh::peer_version_str(state, ci))
        {
            queue::send_urgent(&mut state.clients[ci], CMD_CHAN_ELECT_END, id);
        }
    }
}

/// The batch target `uuid`'s index, or None.
fn target(e: &ChanElect, uuid: &str) -> Option<usize> {
    e.tg.as_ref()?.iter().position(|t| t.uuid == uuid)
}

fn tg_count(e: &ChanElect, st: u8) -> usize {
    e.tg.as_ref()
        .map(|v| v.iter().filter(|t| t.st == st).count())
        .unwrap_or(0)
}

/// Tell batch target t its answer: rid|status|detail to its bot (origin).
fn tg_answer(state: &mut HubState, t: &ChanElectTarget, status: &str, detail: &str) {
    if t.reply_fd < 0 {
        return;
    }
    if let Some(ci) = state.clients.iter().position(|c| {
        c.typ == ClientType::Bot
            && c.authenticated
            && c.fd == t.reply_fd
            && c.conn_serial == t.reply_serial
    }) {
        let res = trunc_string(&format!("{}|{status}|{detail}", t.rid), 256);
        client::send_cmd_to_bot(&mut state.clients[ci], CMD_USER_CHAN_RESULT, &res);
    }
}

/// Target ti was served by bot `by` (ok) or refused for +bitch (!ok): the
/// origin answers its bot, a relay reports it toward the origin.
#[allow(clippy::too_many_arguments)]
fn tg_served(
    state: &mut HubState,
    ei: usize,
    ti: usize,
    ok: bool,
    by_uuid: &str,
    by_nick: &str,
    hub_name: &str,
    detail: &str,
) {
    let t = {
        let tg = state.chan_elections[ei].tg.as_mut().expect("batch");
        tg[ti].st = if ok { b'o' } else { b'x' };
        tg[ti].clone()
    };
    if !state.chan_elections[ei].origin {
        let sub = format!("{}.{}", state.chan_elections[ei].id, t.uuid);
        done_up_id(
            state,
            ei,
            &sub,
            by_uuid,
            by_nick,
            if ok { "ok" } else { "fail" },
            if ok { detail } else { "bitch" },
        );
        return;
    }
    let d = if ok {
        format!(
            "op by {} on {}",
            trunc_string(if by_nick.is_empty() { by_uuid } else { by_nick }, 32),
            trunc_string(hub_name, 64)
        )
    } else {
        format!(
            "not authorised on {} and +bitch is on",
            trunc_string(&state.chan_elections[ei].channel, 65)
        )
    };
    tg_answer(state, &t, if ok { "ok" } else { "denied" }, &d);
}

/// Hand every waiting target to one ready local bot: one CHAN_DO each, id
/// <eid>.<target>.  False when no ready bot is left.
fn try_local_batch(state: &mut HubState, ei: usize) -> bool {
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
        let buuid = e.bots[bi].uuid.clone();
        state.chan_elections[ei].bots[bi].st = b't';
        let mut sent = 0;
        if let Some(ci) = bot(state, &buuid) {
            let n = state.chan_elections[ei].tg.as_ref().map_or(0, |v| v.len());
            for ti in 0..n {
                let e = &state.chan_elections[ei];
                let t = &e.tg.as_ref().expect("batch")[ti];
                if t.st != b'p' {
                    continue;
                }
                let act = trunc_string(
                    &format!(
                        "{}.{}|op|{}|{}|{}|{}",
                        e.id, t.uuid, e.channel, t.uuid, t.nick, t.hostmask
                    ),
                    MAX_MASK_LEN + 320,
                );
                if !client::send_cmd_to_bot(&mut state.clients[ci], CMD_CHAN_DO, &act) {
                    break;
                }
                state.chan_elections[ei].tg.as_mut().expect("batch")[ti].st = b'd';
                sent += 1;
            }
        }
        let e = &mut state.chan_elections[ei];
        if sent == 0 {
            e.bots[bi].reason = "unreachable".into();
            continue;
        }
        e.doing = buuid;
        e.phase = ChanElectPhase::LocalDo;
        e.phase_at = now();
        return true;
    }
}

/// Nothing left to hand out: the origin ends, a relay reports "all served".
fn batch_complete(state: &mut HubState, ei: usize) {
    if state.chan_elections[ei].origin {
        finish(state, ei, "ok", "", "", "", "");
        return;
    }
    let id = state.chan_elections[ei].id.clone();
    done_up_id(state, ei, &id, "", "", "ok", "batch done");
    let e = &mut state.chan_elections[ei];
    e.doing.clear();
    e.phase = ChanElectPhase::Acked;
    e.phase_at = now();
}

/// A batch's next step: done, the next ready local bot, or the mesh.
fn batch_next(state: &mut HubState, ei: usize) {
    let e = &state.chan_elections[ei];
    if tg_count(e, b'p') == 0 && tg_count(e, b'd') == 0 {
        batch_complete(state, ei);
        return;
    }
    if !try_local_batch(state, ei) {
        local_exhausted(state, ei);
    }
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
        if target(&state.chan_elections[ei], &state.clients[ci].id).is_some() {
            continue; // nor can a batch's bots
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
    if state.chan_elections[ei].tg.is_some() {
        return try_local_batch(state, ei);
    }
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
            let ban = e.kind == "ban";
            trunc_string(
                &format!(
                    "{}|{}|{}|{}|{}|{}",
                    e.id,
                    e.kind,
                    e.channel,
                    e.requester,
                    if ban && e.nick.is_empty() {
                        "*"
                    } else {
                        &e.nick
                    },
                    e.hostmask
                ),
                MAX_MASK_LEN + 256,
            )
        };
        let uuid = e.bots[bi].uuid.clone();
        state.chan_elections[ei].bots[bi].st = b't';
        // mode and ban act on records the bot must hold first (C|/c|, B|)
        let mode = matches!(state.chan_elections[ei].kind.as_str(), "mode" | "ban");
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
        "kick" => "kick",
        "ban" => "ban",
        "who" => "who",
        _ => "key",
    }
}

// ---- `channel who` (kind "who", CMD_CHAN_WHO) -----------------------------

/// Text from a bot for the console: control bytes go ('|' stays; the reply
/// escapes it).  Under `cap` bytes, as C's buffer of that size.
fn wtext_clean(src: &[u8], cap: usize) -> Vec<u8> {
    let mut o = Vec::new();
    for &ch in src {
        if o.len() + 1 >= cap {
            break;
        }
        if ch < 0x20 || ch == 0x7f {
            continue;
        }
        o.push(ch);
    }
    o
}

/// The value after "<tag>|" of the first body line that starts with it.
fn who_line(body: &[u8], tag: u8) -> Option<&[u8]> {
    body.split(|&b| b == b'\n')
        .find(|l| l.len() >= 2 && l[0] == tag && l[1] == b'|')
        .map(|l| &l[2..])
}

/// Field i ('|'-separated) of a line value, cleaned; last = the rest.
fn who_field(val: &[u8], i: usize, last: bool, cap: usize) -> Vec<u8> {
    let mut s = 0usize;
    for _ in 0..i {
        match val[s..].iter().position(|&b| b == b'|') {
            Some(p) => s += p + 1,
            None => return Vec::new(),
        }
    }
    let e = if last {
        val.len()
    } else {
        val[s..]
            .iter()
            .position(|&b| b == b'|')
            .map_or(val.len(), |p| s + p)
    };
    wtext_clean(&val[s..e], cap)
}

/// Leading decimal digits; 0 when none or past 1e15 (hub_chanwho.c who_num).
fn who_num(s: &[u8]) -> i64 {
    let mut v: i64 = 0;
    for &c in s.iter().take_while(|c| c.is_ascii_digit()) {
        if v > 1_000_000_000_000_000 {
            return 0;
        }
        v = v * 10 + i64::from(c - b'0');
    }
    v
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// irssi order: ops, halfops, voices, the rest; A-Z ignoring ASCII case
/// within each; then by bytes (hub_logic.c who_nick_cmp).
fn who_nick_cmp(x: &(u8, Vec<u8>), y: &(u8, Vec<u8>)) -> std::cmp::Ordering {
    x.0.cmp(&y.0)
        .then_with(|| {
            let a = x.1.iter().map(u8::to_ascii_lowercase);
            let b = y.1.iter().map(u8::to_ascii_lowercase);
            a.cmp(b)
        })
        .then_with(|| x.1.cmp(&y.1))
}

#[allow(clippy::too_many_arguments)]
fn who_answer(
    state: &mut HubState,
    ai: usize,
    e: &ChanElect,
    ok: bool,
    by_uuid: &str,
    by_nick: &str,
    hub_name: &str,
    detail: &str,
    asked: i64,
    hubs: i64,
) {
    if !ok {
        let mut why = reasons(e, 160);
        if why.is_empty() && !detail.is_empty() {
            why = trunc_string(detail, 160);
        }
        if why.is_empty() && asked > 0 {
            why = "none is in the channel".to_string();
        }
        let msg = trunc_string(
            &format!(
                "no bot could list {}: {asked} bot{} asked on {hubs} hub{}{}{why}",
                e.channel,
                if asked == 1 { "" } else { "s" },
                if hubs == 1 { "" } else { "s" },
                if why.is_empty() { "" } else { "; " }
            ),
            256,
        );
        admin_err(
            state,
            ai,
            "channel.nobody",
            &msg,
            Some("a bot must be in the channel (it needs no ops)"),
        );
        return;
    }
    if e.who_buf.is_empty() || !e.who_done || e.who_bad {
        let msg = format!(
            "{} answered for {} but its list did not arrive whole",
            crate::cstr::trunc(if by_nick.is_empty() { "a bot" } else { by_nick }, 32),
            crate::cstr::trunc(&e.channel, 65)
        );
        admin_err(
            state,
            ai,
            "channel.who_incomplete",
            &msg,
            Some("channel who again"),
        );
        return;
    }
    let body = e.who_buf.as_slice();
    let mut r = Reply::new();
    r.ok("channel.who");
    r.kv("chan", &e.channel);
    r.kv("by", if by_nick.is_empty() { by_uuid } else { by_nick });
    r.kv("by_uuid", by_uuid);
    r.kv("hub_name", hub_name);
    r.kvi("asked", asked);
    r.kvi("hubs", hubs);
    let (mut f1, mut f2) = (Vec::new(), Vec::new());
    if let Some(v) = who_line(body, b't') {
        f1 = who_field(v, 0, false, 24);
        f2 = who_field(v, 1, false, 24);
    }
    let by = who_line(body, b'B').map_or(Vec::new(), |v| wtext_clean(v, MAX_MASK_LEN));
    let topic = who_line(body, b'T').map_or(Vec::new(), |v| wtext_clean(v, CHAN_WHO_TOPIC_MAX));
    r.kvb("topic_known", f1 == b"1");
    r.kv("topic", &lossy(&topic));
    r.kv("topic_by", &lossy(&by));
    r.kvi("topic_at", who_num(&f2));
    let (mut f1, mut f2, mut modes) = (Vec::new(), Vec::new(), Vec::new());
    if let Some(v) = who_line(body, b'M') {
        f1 = who_field(v, 0, false, 24);
        f2 = who_field(v, 1, false, 24);
        modes = who_field(v, 2, true, 64);
    }
    let mut key = who_line(body, b'K').map_or(Vec::new(), |v| wtext_clean(v, 64));
    r.kvb("modes_known", f1 == b"1");
    r.kv("modes", &lossy(&modes));
    r.kvi("limit", who_num(&f2));
    r.kv("key", &lossy(&key));
    crypto::wipe(&mut key);
    let capped = who_line(body, b'C').is_some_and(|v| who_field(v, 1, false, 24) == b"1");
    // the members: N|@a %b +c d ... (any number of N lines)
    let mut list: Vec<(u8, Vec<u8>)> = Vec::new();
    for l in body.split(|&b| b == b'\n') {
        if l.len() < 2 || l[0] != b'N' || l[1] != b'|' {
            continue;
        }
        for t in l[2..].split(|&b| b == b' ') {
            if t.is_empty() {
                continue;
            }
            let (rank, t) = match t[0] {
                b'@' => (0u8, &t[1..]),
                b'%' => (1, &t[1..]),
                b'+' => (2, &t[1..]),
                _ => (3, t),
            };
            let nick = wtext_clean(t, MAX_NICK);
            if !nick.is_empty() {
                list.push((rank, nick));
            }
        }
    }
    list.sort_by(who_nick_cmp);
    let mut cnt = [0i64; 4];
    for (rank, _) in &list {
        cnt[usize::from(*rank)] += 1;
    }
    r.kvi("total", list.len() as i64);
    r.kvb("capped", capped);
    r.kvi("ops", cnt[0]);
    r.kvi("halfops", cnt[1]);
    r.kvi("voices", cnt[2]);
    r.kvi("normal", cnt[3]);
    const PFX: [&str; 4] = ["@", "%", "+", ""];
    for (rank, nick) in &list {
        r.rec("nick");
        r.kv("p", PFX[usize::from(*rank)]);
        r.kv("n", &lossy(nick));
    }
    send_reply(state, ai, &mut r);
}

/// CHAN_WHO eid|seq|more|<chunk>: from the bot we picked, or from the peer
/// on the election's path.  A relay passes it up unchanged; the origin joins
/// the chunks (seq 0 starts afresh: a retry with the next bot).
pub fn process_who(state: &mut HubState, ci: usize, payload: &str) {
    let (Some(id), Some(seqs), Some(more)) = (
        wire_field(payload, 0, 64),
        wire_field(payload, 1, 12),
        wire_field(payload, 2, 4),
    ) else {
        return;
    };
    let mut body = payload;
    for _ in 0..3 {
        match body.find('|') {
            Some(p) => body = &body[p + 1..],
            None => return,
        }
    }
    let Some(ei) = (!id.is_empty()).then(|| find(state, &id)).flatten() else {
        return;
    };
    let c = &state.clients[ci];
    let e = &state.chan_elections[ei];
    if e.kind != "who" {
        return;
    }
    match c.typ {
        ClientType::Bot => {
            if e.phase != ChanElectPhase::LocalDo || e.doing != c.id {
                return;
            }
        }
        ClientType::Hub => {
            if !e.origin {
                if c.fd == e.from_fd && c.conn_serial == e.from_serial {
                    return;
                }
            } else if !(e.phase == ChanElectPhase::MeshDo
                && e.hubs
                    .iter()
                    .any(|h| h.uuid == e.doing && h.fd == c.fd && h.serial == c.conn_serial))
            {
                return;
            }
        }
        _ => return,
    }
    if !e.origin {
        up(state, ei, CMD_CHAN_WHO, payload);
        return;
    }
    // hub_chanwho.c chanwho_add: digits only, at most ~1e6
    let mut seq: i64 = 0;
    if seqs.is_empty() {
        return;
    }
    for c in seqs.bytes() {
        if !c.is_ascii_digit() || seq > 100_000 {
            return;
        }
        seq = seq * 10 + i64::from(c - b'0');
    }
    let e = &mut state.chan_elections[ei];
    if seq == 0 {
        crypto::wipe(&mut e.who_buf);
        e.who_buf.clear();
        e.who_seq = 0;
        e.who_done = false;
        e.who_bad = false;
    }
    if e.who_bad {
        return;
    }
    if seq != e.who_seq || e.who_done {
        e.who_bad = true;
        return;
    }
    if body.len() > CHAN_WHO_MAX - e.who_buf.len() {
        e.who_bad = true;
        let (chan, eid) = (e.channel.clone(), e.id.clone());
        crate::hlog_warning!(
            "[CHANREQ] channel who {chan} (id:{eid}): the answer is over {CHAN_WHO_MAX} bytes, dropped\n"
        );
        return;
    }
    if e.who_buf.capacity() < CHAN_WHO_MAX + 1 {
        e.who_buf.reserve_exact(CHAN_WHO_MAX + 1 - e.who_buf.len());
    }
    e.who_buf.extend_from_slice(body.as_bytes());
    e.who_seq += 1;
    if more == "0" {
        e.who_done = true;
    }
}

/// The origin's end of an election: answer the console that asked, log, and
/// free the slot.  status: "ok" (one bot did it), "bitch" (refused, D12),
/// anything else = nobody could.
/// A batched own op ends at the origin: every target still waiting gets
/// none (its bot may ask over IRC), one summary line, ELECT_END.
fn batch_finish(state: &mut HubState, ei: usize) {
    let e = state.chan_elections[ei].clone();
    let asked = e.bots.len() as i64 + e.hubs.iter().map(|h| h.asked).sum::<i64>();
    let hubs = 1 + e.hubs.len() as i64;
    let why = reasons(&e, 160);
    let d = trunc_string(
        &format!(
            "no bot could: {asked} asked on {hubs} hub{}{}{}",
            if hubs == 1 { "" } else { "s" },
            if why.is_empty() { "" } else { "; " },
            trunc_string(&why, 121)
        ),
        256,
    );
    let tg = e.tg.clone().unwrap_or_default();
    let mut left = 0;
    for t in tg.iter().filter(|t| t.st == b'p' || t.st == b'd') {
        tg_answer(state, t, "none", &d);
        left += 1;
    }
    crate::hlog_info!(
        "[CHANREQ] own op for {} bot{} on {} (id:{}): {} opped, {} refused (+bitch), {left} left to ask over IRC\n",
        tg.len(),
        if tg.len() == 1 { "" } else { "s" },
        e.channel,
        e.id,
        tg_count(&e, b'o'),
        tg_count(&e, b'x')
    );
    if e.flooded {
        end_send(state, &e.id, None);
    }
    release(state, ei);
}

fn finish(
    state: &mut HubState,
    ei: usize,
    status: &str,
    by_uuid: &str,
    by_nick: &str,
    hub_name: &str,
    detail: &str,
) {
    if state.chan_elections[ei].tg.is_some() {
        batch_finish(state, ei);
        return;
    }
    let e = state.chan_elections[ei].clone();
    let asked = e.bots.len() as i64 + e.hubs.iter().map(|h| h.asked).sum::<i64>();
    let hubs = 1 + e.hubs.len() as i64;
    let ok = status == "ok";
    let bitch = status == "bitch";
    // a kick's target not in the channel, or a bot / authorised member: the
    // answer is about the nick, so no other bot was tried
    let absent = status == "absent";
    let prot = status == "protected";
    let ban = e.kind == "ban";
    let who = if e.kind == "who" {
        "members"
    } else if !e.nick.is_empty() {
        &e.nick
    } else if ban && !e.hostmask.is_empty() {
        &e.hostmask
    } else {
        &e.requester
    };
    let kw = kind_word(&e.kind);
    if bitch {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): refused, not authorised and +bitch is on\n",
            e.channel,
            e.id
        );
    } else if absent || prot {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): refused, {}\n",
            e.channel,
            e.id,
            if absent {
                "not in the channel"
            } else {
                "a bot or an authorised member"
            }
        );
    } else if ok {
        crate::hlog_info!(
            "[CHANREQ] {kw} {who} on {} (id:{}): done by {} on {hub_name}\n",
            e.channel,
            e.id,
            if by_uuid.is_empty() {
                by_nick.to_string()
            } else {
                state.who('b', by_uuid)
            }
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
        let res = if e.reply_own {
            // a bot's own request: ok / denied (policy: no ~B2 around it) /
            // none (nobody on any hub could: the bot may ask over IRC)
            if ok {
                format!(
                    "{}|ok|{} by {} on {}",
                    e.reply_rid,
                    kw,
                    crate::cstr::trunc(if by_nick.is_empty() { by_uuid } else { by_nick }, 32),
                    crate::cstr::trunc(hub_name, 64)
                )
            } else if bitch {
                format!(
                    "{}|denied|not authorised on {} and +bitch is on",
                    e.reply_rid,
                    crate::cstr::trunc(&e.channel, 65)
                )
            } else {
                let why = reasons(&e, 160);
                format!(
                    "{}|none|no bot could: {asked} asked on {hubs} hub{}{}{}",
                    e.reply_rid,
                    if hubs == 1 { "" } else { "s" },
                    if why.is_empty() { "" } else { "; " },
                    crate::cstr::trunc(&why, 121)
                )
            }
        } else if bitch {
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
    if let (Some(ai), true) = (admin, e.kind == "who") {
        who_answer(
            state, ai, &e, ok, by_uuid, by_nick, hub_name, detail, asked, hubs,
        );
    } else if let (Some(ai), true) = (admin, ban) {
        // ban add / channel ban: the ban is stored whatever happened; the
        // answer says whether one bot set it now (placed) or why not (the
        // bots' sweep keeps trying)
        let mut r = Reply::new();
        r.ok("ban.added");
        r.kv("chan", &e.channel);
        r.kv("mask", &e.hostmask);
        r.kvi("expires", e.ban_expires);
        r.kvb("sticky", e.ban_sticky);
        r.kv("reason", &e.ban_reason);
        r.kvb("existed", e.ban_existed);
        r.kvi("bots", crate::admin::local_bot_count(state));
        r.kvi("peers", linked_peer_count(state));
        r.kvb("placed", ok);
        if status == "dynamic" {
            r.kvb("dynamic", true);
        }
        if ok {
            r.kv("by", if by_nick.is_empty() { by_uuid } else { by_nick });
            r.kv("by_uuid", by_uuid);
            r.kv("hub_name", hub_name);
            if !detail.is_empty() {
                r.kv("detail", detail);
            }
        } else {
            let mut why = reasons(&e, 160);
            if status == "dynamic" {
                why = "+dynamicbans: it goes on while someone it matches is there".into();
            }
            if why.is_empty() && !detail.is_empty() {
                why = detail.to_string();
            }
            if why.is_empty() {
                why = "no bot is in the channel and opped".into();
            }
            r.kv("why", &why);
        }
        r.kvi("asked", asked);
        r.kvi("hubs", hubs);
        send_reply(state, ai, &mut r);
    } else if let (Some(ai), true) = (admin, absent || prot) {
        let (msg, hint) = if absent {
            (
                format!(
                    "{} is not in {}",
                    crate::cstr::trunc(&e.nick, 32),
                    crate::cstr::trunc(&e.channel, 65)
                ),
                "check the nick: the bots see the channel's members",
            )
        } else {
            (
                format!(
                    "{} is a bot or an authorised user in {}",
                    crate::cstr::trunc(&e.nick, 32),
                    crate::cstr::trunc(&e.channel, 65)
                ),
                "the bots never kick their own or a known user",
            )
        };
        let code = if absent {
            "channel.not_present"
        } else {
            "channel.protected"
        };
        admin_err(state, ai, code, &msg, Some(hint));
    } else if let (Some(ai), true) = (admin, bitch) {
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
            if e.kind == "kick" {
                r.kv("reason", &e.hostmask);
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
    if e.flooded {
        end_send(state, &e.id, None); // the relays free their copies
    }
    release(state, ei);
}

/// A relay hub's report back toward the origin.
fn up(state: &mut HubState, ei: usize, cmd: u8, payload: &str) {
    let (fd, serial) = (
        state.chan_elections[ei].from_fd,
        state.chan_elections[ei].from_serial,
    );
    send_peer(state, fd, serial, cmd, payload);
}

fn done_up_id(
    state: &mut HubState,
    ei: usize,
    id: &str,
    bot_uuid: &str,
    bot_nick: &str,
    status: &str,
    detail: &str,
) {
    let buf = trunc_string(
        &format!(
            "{id}|{}|{}|{bot_uuid}|{bot_nick}|{status}|{detail}",
            state.hub_uuid,
            hub_display_name(state)
        ),
        512,
    );
    up(state, ei, CMD_CHAN_ELECT_DONE, &buf);
}

fn done_up(
    state: &mut HubState,
    ei: usize,
    bot_uuid: &str,
    bot_nick: &str,
    status: &str,
    detail: &str,
) {
    let id = state.chan_elections[ei].id.clone();
    done_up_id(state, ei, &id, bot_uuid, bot_nick, status, detail);
}

/// Origin, nobody local can: the next hub with a ready bot, else nobody.  A
/// bot that never answered the probe is not handed a blind old-style request:
/// every bot the mesh admits (MESH_MIN_VERSION) answers probes, so silence
/// means busy or gone, and the old fan-out skipped +bitch (D12).
fn try_hub(state: &mut HubState, ei: usize) {
    if state.chan_elections[ei].tg.is_some() {
        // a batch goes only to a hub that reads its target list
        let old: Vec<bool> = state.chan_elections[ei]
            .hubs
            .iter()
            .map(|h| !version_new(&hub_version(state, &h.uuid)))
            .collect();
        let e = &mut state.chan_elections[ei];
        for (h, o) in e.hubs.iter_mut().zip(old) {
            if o {
                h.tried = true;
            }
        }
        for t in e.tg.as_mut().expect("batch").iter_mut() {
            if t.st == b'd' {
                t.st = b'p'; // the last hub's leftovers
            }
        }
        if tg_count(e, b'p') == 0 {
            finish(state, ei, "ok", "", "", "", "");
            return;
        }
    }
    loop {
        let e = &state.chan_elections[ei];
        let ready: Vec<usize> = (0..e.hubs.len())
            .filter(|&i| !e.hubs[i].tried && e.hubs[i].ready > 0)
            .collect();
        if ready.is_empty() {
            break;
        }
        let hi = ready[pick(ready.len())];
        let (fd, serial, uuid, id) = (
            e.hubs[hi].fd,
            e.hubs[hi].serial,
            e.hubs[hi].uuid.clone(),
            e.id.clone(),
        );
        state.chan_elections[ei].hubs[hi].tried = true;
        let mut buf = format!("{id}|{uuid}|elect");
        if let Some(tg) = &state.chan_elections[ei].tg {
            let list: Vec<&str> = tg
                .iter()
                .filter(|t| t.st == b'p')
                .map(|t| t.uuid.as_str())
                .collect();
            buf.push('|');
            buf.push_str(&list.join(","));
        }
        let buf = trunc_string(&buf, 160 + CHAN_ELECT_BATCH_MAX * 65);
        if !send_peer(state, fd, serial, CMD_CHAN_ELECT_DO, &buf) {
            continue; // that hub's link went away: the next one
        }
        let e = &mut state.chan_elections[ei];
        if let Some(tg) = e.tg.as_mut() {
            for t in tg.iter_mut().filter(|t| t.st == b'p') {
                t.st = b'd';
            }
        }
        e.doing = uuid;
        e.phase = ChanElectPhase::MeshDo;
        e.phase_at = now();
        return;
    }
    finish(state, ei, "nobody", "", "", "", "");
}

/// Hubs this one knows, itself included: what its ELECT_ACK reports.
fn mesh_total(state: &HubState) -> usize {
    1 + state
        .mesh_hubs
        .iter()
        .filter(|m| m.uuid != state.hub_uuid)
        .count()
}

/// True while this hub's picture of the mesh is still being built: it
/// started moments ago and configured peers are not all linked yet, or a
/// peer linked moments ago has not yet named its version (no sync
/// exchanged).  An origin that asked the mesh then would take a few
/// neighbours for all of it.  C `ce_mesh_settling`.
fn mesh_settling(state: &HubState, t: i64) -> bool {
    if state.hub_started > 0
        && t - state.hub_started < CHAN_ELECT_SETTLE
        && (crate::admin::linked_peer_count(state) as usize) < state.peers.len()
    {
        return true;
    }
    state.clients.iter().any(|c| {
        c.typ == ClientType::Hub
            && c.authenticated
            && c.sync_held
            && t - c.connected_at < CHAN_ELECT_SETTLE
    })
}

/// A bot authenticated here that the election has not asked yet.
fn new_local_bot(state: &HubState, ei: usize) -> bool {
    let e = &state.chan_elections[ei];
    state.clients.iter().any(|c| {
        c.typ == ClientType::Bot
            && c.authenticated
            && c.id != e.requester
            && target(e, &c.id).is_none()
            && !e.bots.iter().any(|b| b.uuid == c.id)
    })
}

/// Nothing (more) to do locally: the origin asks the mesh, a relay says so.
fn local_exhausted(state: &mut HubState, ei: usize) {
    if !state.chan_elections[ei].origin {
        done_up(state, ei, "", "", "fail", "no ready bot");
        state.chan_elections[ei].phase = ChanElectPhase::Acked;
        return;
    }
    // Held once, not re-sent: the one election waits for the mesh view and
    // then runs; the requester is answered either way, nothing is repeated.
    let t = now();
    {
        let e = &state.chan_elections[ei];
        if !e.held
            && e.phase != ChanElectPhase::MeshDo
            && e.hubs.is_empty()
            && mesh_settling(state, t)
        {
            let e = &mut state.chan_elections[ei];
            e.held = true;
            e.phase = ChanElectPhase::Hold;
            e.phase_at = t;
            crate::hlog_debug!(
                "[CHANREQ] Election {}: mesh view still settling, held up to {} s\n",
                e.id,
                CHAN_ELECT_HOLD_MAX
            );
            return;
        }
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
    e.flooded = true;
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
    start_x(
        state, kind, channel, requester, nick, hostmask, admin, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn start_x(
    state: &mut HubState,
    kind: &str,
    channel: &str,
    requester: &str,
    nick: &str,
    hostmask: &str,
    admin: Option<(i32, u64)>,
    gather: bool,
) -> Option<usize> {
    let own = own_requester(state, requester);
    let ei = alloc(state, own, kind, channel)?;
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
        if gather {
            e.phase = ChanElectPhase::Gather;
            e.phase_at = now();
            crate::hlog_debug!(
                "[CHANREQ] Election {}: own op on {channel}, gathering {} s\n",
                e.id,
                CHAN_ELECT_BATCH_WAIT
            );
            return Some(ei);
        }
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

/// Own op, every hub new enough?  (opflow's CHAN_REQUEST asks first.)
pub fn batch_wanted(state: &HubState) -> bool {
    batch_ok(state)
}

/// A local bot's own op: into the batch gathering for that channel, else a
/// new one.  False when the table is full.
pub fn batch_join(
    state: &mut HubState,
    ci: usize,
    channel: &str,
    nick: &str,
    hostmask: &str,
    rid: &str,
) -> bool {
    let me = state.clients[ci].id.clone();
    let found = state.chan_elections.iter().position(|x| {
        x.active
            && x.origin
            && x.phase == ChanElectPhase::Gather
            && x.channel.eq_ignore_ascii_case(channel)
            && x.tg
                .as_ref()
                .is_some_and(|v| v.len() < CHAN_ELECT_BATCH_MAX || v.iter().any(|t| t.uuid == me))
    });
    let fresh = found.is_none();
    let ei = match found {
        Some(ei) => ei,
        None => {
            let Some(ei) = start_x(state, "op", channel, &me, nick, hostmask, None, true) else {
                return false;
            };
            state.chan_elections[ei].tg = Some(Vec::with_capacity(CHAN_ELECT_BATCH_MAX));
            ei
        }
    };
    let (fd, serial) = (state.clients[ci].fd, state.clients[ci].conn_serial);
    let t = ChanElectTarget {
        uuid: me.clone(),
        nick: trunc_string(nick, MAX_NICK),
        hostmask: trunc_string(hostmask, MAX_MASK_LEN),
        rid: trunc_string(rid, USER_CHAN_RID_MAX + 1),
        reply_fd: fd,
        reply_serial: serial,
        st: b'p',
    };
    let tg = state.chan_elections[ei].tg.as_mut().expect("batch");
    match tg.iter().position(|x| x.uuid == me) {
        Some(i) => tg[i] = t,
        None => {
            tg.push(t);
            if !fresh {
                crate::stats::el_batched();
            }
        }
    }
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

/// A failure that is about the target, not the bot: no other bot is tried.
/// A ban's "dynamic": +dynamicbans keeps a non-sticky ban off the channel
/// while no member it matches is there.
fn final_fail(e: &ChanElect, detail: &str) -> bool {
    match e.kind.as_str() {
        "op" => detail == "bitch",
        "kick" => detail == "absent" || detail == "protected",
        "ban" => detail == "dynamic",
        _ => false,
    }
}

/// The bot we handed the action to reports: eid|ok|detail or eid|fail|detail.
pub fn process_done(state: &mut HubState, ci: usize, payload: &str) {
    let full = wire_field(payload, 0, 64).unwrap_or_default();
    let status = wire_field(payload, 1, 8).unwrap_or_default();
    let detail = wire_tail(payload, 2, 95).unwrap_or_default();
    // a batch: <eid>.<target uuid>
    let (id, sub) = match full.split_once('.') {
        Some((a, b)) => (a.to_string(), Some(b.to_string())),
        None => (full, None),
    };
    let Some(ei) = (!id.is_empty()).then(|| find(state, &id)).flatten() else {
        return;
    };
    let from = state.clients[ci].id.clone();
    let e = &state.chan_elections[ei];
    if e.phase != ChanElectPhase::LocalDo || e.doing != from {
        return;
    }
    if sub.is_some() != e.tg.is_some() {
        return;
    }
    let clean = roster_clean(&detail, 96);
    let nick = e
        .bots
        .iter()
        .rfind(|b| b.uuid == from)
        .map(|b| b.nick.clone())
        .unwrap_or_default();
    if let Some(sub) = sub {
        let Some(ti) = target(e, &sub) else {
            return;
        };
        if e.tg.as_ref().expect("batch")[ti].st != b'd' {
            return;
        }
        let hn = hub_display_name(state).to_string();
        if status == "ok" {
            tg_served(state, ei, ti, true, &from, &nick, &hn, &clean);
        } else if status == "fail" && final_fail(&state.chan_elections[ei], &clean) {
            tg_served(state, ei, ti, false, &from, &nick, &hn, &clean);
        } else {
            let e = &mut state.chan_elections[ei];
            e.tg.as_mut().expect("batch")[ti].st = b'p'; // the next ready bot gets it
            if let Some(b) = e.bots.iter_mut().rfind(|b| b.uuid == from) {
                b.reason = roster_clean(
                    if clean.is_empty() { "failed" } else { &clean },
                    CHAN_ELECT_REASON_MAX,
                );
            }
        }
        if tg_count(&state.chan_elections[ei], b'd') == 0 {
            state.chan_elections[ei].doing.clear();
            batch_next(state, ei);
        }
        return;
    }
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
    // fail|bitch: not authorised on a +bitch channel (D12); a kick's
    // fail|absent / fail|protected.  The answer is about the nick, not the
    // bot, so it ends the election.
    if status == "fail" && final_fail(&state.chan_elections[ei], &clean) {
        if state.chan_elections[ei].origin {
            let hn = hub_display_name(state).to_string();
            finish(state, ei, &clean, &from, &nick, &hn, &clean);
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
    let (fd, serial) = (state.clients[ci].fd, state.clients[ci].conn_serial);
    let f = |i, cap| wire_field(payload, i, cap);
    let (Some(id), Some(_origin), Some(kind), Some(channel), Some(requester)) =
        (f(0, 64), f(1, 64), f(2, 8), f(3, MAX_CHAN), f(4, 64))
    else {
        crate::hlog_warning!("[CHANREQ] Malformed CHAN_ELECT_FWD from peer fd={fd}\n");
        return;
    };
    if id.is_empty()
        || !(chan_kind_valid(&kind)
            || kind == "op"
            || kind == "mode"
            || kind == "kick"
            || kind == "ban"
            || kind == "who")
        || !(channel.starts_with('#') || channel.starts_with('&'))
    {
        crate::hlog_warning!("[CHANREQ] Malformed CHAN_ELECT_FWD from peer fd={fd}\n");
        return;
    }
    let nick = f(5, MAX_NICK).unwrap_or_default();
    let hostmask = f(6, MAX_MASK_LEN).unwrap_or_default();
    let ts = crate::cstr::atoll(&f(7, 24).unwrap_or_default());
    // atoll saturates: age only for a positive stamp
    let age = if ts > 0 { now() - ts } else { 0 };
    if ts <= 0 || !(-CHAN_ELECT_TTL..=CHAN_ELECT_TTL).contains(&age) {
        return;
    }
    if forward_seen_check_and_add(state, &id) {
        return; // another path got here first
    }
    let own = own_requester(state, &requester);
    let Some(ei) = alloc(state, own, &kind, &channel) else {
        // logged; the origin hears no answer from us, but the hubs behind us
        // still get the question
        for i in 0..state.clients.len() {
            let c = &state.clients[i];
            if c.typ == ClientType::Hub && c.authenticated && c.fd != fd {
                queue::send_urgent(&mut state.clients[i], CMD_CHAN_ELECT_FWD, payload);
            }
        }
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
        e.from_serial = serial;
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

/// ELECT_ACK: eid|hub_uuid|hub_name|asked|ready|silent|mesh.  mesh (2.5.3+:
/// every hub the mesh admits sends it) is how many hubs the answering hub knows, itself
/// included.  The origin records it; a relay remembers which peer leads to
/// that hub and passes it on unchanged.
pub fn process_elect_ack(state: &mut HubState, ci: usize, payload: &str) {
    let f = |i, cap| wire_field(payload, i, cap).unwrap_or_default();
    let (id, hub, name) = (f(0, 64), f(1, 64), f(2, 64));
    let num = |s: String| crate::cstr::atoi(&s).max(0) as i64;
    let (a, r) = (num(f(3, 12)), num(f(4, 12)));
    // bounded: a wild count can only cost CHAN_ELECT_MESH_WAIT
    let known = (num(f(6, 12)) as usize).min(MAX_MESH_HUBS);
    if id.is_empty() || hub.is_empty() {
        return;
    }
    let Some(ei) = find(state, &id) else {
        return;
    };
    let (fd, serial) = (state.clients[ci].fd, state.clients[ci].conn_serial);
    let e = &mut state.chan_elections[ei];
    if e.hubs.len() >= MAX_MESH_HUBS {
        return;
    }
    e.mesh_known = e.mesh_known.max(known);
    if e.hubs.iter().any(|h| h.uuid == hub) {
        return; // full, or a second copy
    }
    e.hubs.push(ChanElectHub {
        uuid: roster_clean(&hub, 64),
        name: roster_clean(if name.is_empty() { &hub } else { &name }, 64),
        fd,
        serial,
        asked: a,
        ready: r,
        tried: false,
    });
    if !e.origin {
        up(state, ei, CMD_CHAN_ELECT_ACK, payload);
    }
}

/// ELECT_DO: eid|hub_uuid|elect.  Ours: act; else route it on.
pub fn process_elect_do(state: &mut HubState, ci: usize, payload: &str) {
    let f = |i, cap| wire_field(payload, i, cap).unwrap_or_default();
    let (id, hub, mode) = (f(0, 64), f(1, 64), f(2, 8));
    let Some(ei) = (!id.is_empty()).then(|| find(state, &id)).flatten() else {
        return;
    };
    let (fd, serial) = (state.clients[ci].fd, state.clients[ci].conn_serial);
    let e = &state.chan_elections[ei];
    if e.origin || fd != e.from_fd || serial != e.from_serial {
        return;
    }
    if hub != state.hub_uuid {
        if let Some(h) = e.hubs.iter().find(|h| h.uuid == hub) {
            let (hfd, hserial) = (h.fd, h.serial);
            send_peer(state, hfd, hserial, CMD_CHAN_ELECT_DO, payload);
        }
        return;
    }
    if mode != "elect" {
        return;
    }
    // a batch: the targets still waiting, as bot uuids; their nick and mask
    // come from our own copy of each bot's record
    let list = f(3, CHAN_ELECT_BATCH_MAX * 65 + 1);
    if !list.is_empty() {
        let mut tg: Vec<ChanElectTarget> = Vec::with_capacity(CHAN_ELECT_BATCH_MAX);
        for tok in list.split(',').filter(|t| !t.is_empty()) {
            if tg.len() >= CHAN_ELECT_BATCH_MAX {
                break;
            }
            if tok.len() >= 64
                || !tok.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
                || tg.iter().any(|t| t.uuid == tok)
            {
                continue;
            }
            let nick = state
                .bot_entry(tok, "n")
                .map(|v| trunc_string(v, MAX_NICK))
                .unwrap_or_default();
            if nick.is_empty() {
                continue; // not a bot we know
            }
            let hostmask = state
                .bot_entry(tok, "h")
                .map(|v| trunc_string(v, MAX_MASK_LEN))
                .unwrap_or_default();
            tg.push(ChanElectTarget {
                uuid: tok.to_string(),
                nick,
                hostmask,
                reply_fd: -1,
                st: b'p',
                ..ChanElectTarget::default()
            });
        }
        if tg.is_empty() {
            state.chan_elections[ei].tg = Some(tg);
            local_exhausted(state, ei);
            return;
        }
        state.chan_elections[ei].tg = Some(tg);
        batch_next(state, ei);
        return;
    }
    if !try_local(state, ei) {
        local_exhausted(state, ei);
    }
}

/// ELECT_DONE: eid|hub_uuid|hub_name|bot_uuid|bot_nick|status|detail.
pub fn process_elect_done(state: &mut HubState, _ci: usize, payload: &str) {
    let f = |i, cap| wire_field(payload, i, cap).unwrap_or_default();
    let (full, hub, name, bot_uuid, nick, status) = (
        f(0, 64),
        f(1, 64),
        f(2, 64),
        f(3, 64),
        f(4, MAX_NICK),
        f(5, 8),
    );
    let detail = wire_tail(payload, 6, 95).unwrap_or_default();
    // a batch target's own report: <eid>.<uuid>
    let (id, sub) = match full.split_once('.') {
        Some((a, b)) => (a.to_string(), Some(b.to_string())),
        None => (full, None),
    };
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
    if sub.is_some() && e.tg.is_none() {
        return;
    }
    let cn = roster_clean(if name.is_empty() { &hub } else { &name }, 64);
    if let Some(sub) = sub {
        let Some(ti) = target(e, &sub) else {
            return;
        };
        if e.tg.as_ref().expect("batch")[ti].st != b'd' {
            return;
        }
        let (cb, ck, cd) = (
            roster_clean(&bot_uuid, 64),
            roster_clean(&nick, MAX_NICK),
            roster_clean(&detail, 96),
        );
        if status == "ok" {
            tg_served(state, ei, ti, true, &cb, &ck, &cn, &cd);
        } else if status == "fail" && final_fail(&state.chan_elections[ei], &cd) {
            tg_served(state, ei, ti, false, &cb, &ck, &cn, &cd);
        } else {
            state.chan_elections[ei].tg.as_mut().expect("batch")[ti].st = b'p';
        }
        return;
    }
    if e.tg.is_some() {
        // that hub is through: the next one for what is left
        try_hub(state, ei);
        return;
    }
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
    } else if status == "fail" && final_fail(&state.chan_elections[ei], &roster_clean(&detail, 96))
    {
        finish(
            state,
            ei,
            &roster_clean(&detail, 96),
            &roster_clean(&bot_uuid, 64),
            &roster_clean(&nick, MAX_NICK),
            &cn,
            &roster_clean(&detail, 96),
        );
    } else {
        try_hub(state, ei);
    }
}

/// ELECT_END: eid.  The origin's election is over: free our copy (a
/// relay's; the origin freed its own) and pass it on once.
pub fn process_elect_end(state: &mut HubState, ci: usize, payload: &str) {
    let id = wire_field(payload, 0, 64).unwrap_or_default();
    if id.is_empty() || id.contains('.') {
        return;
    }
    if let Some(ei) = find(state, &id).filter(|&ei| !state.chan_elections[ei].origin) {
        release(state, ei);
        crate::stats::el_ended();
    }
    end_send(state, &id, Some(ci));
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
    full_flush(state, t);
    for ei in 0..state.chan_elections.len() {
        let e = &state.chan_elections[ei];
        if !e.active {
            continue;
        }
        if t - e.created > CHAN_ELECT_TTL {
            if e.origin {
                finish(state, ei, "timeout", "", "", "", "timed out");
            }
            release(state, ei);
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
                        "{}|{}|{}|{}|{}|{}|{}",
                        e.id,
                        state.hub_uuid,
                        hub_display_name(state),
                        e.bots.len(),
                        count(e, b'y'),
                        count(e, b'a'),
                        mesh_total(state)
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
                if let Some(tg) = e.tg.as_mut() {
                    for x in tg.iter_mut().filter(|x| x.st == b'd') {
                        x.st = b'p';
                    }
                    batch_next(state, ei);
                    continue;
                }
                if !try_local(state, ei) {
                    local_exhausted(state, ei);
                }
            }
            ChanElectPhase::Gather => {
                if t - e.phase_at < CHAN_ELECT_BATCH_WAIT {
                    continue;
                }
                probe_local(state, ei);
                let e = &state.chan_elections[ei];
                crate::hlog_debug!(
                    "[CHANREQ] Election {}: own op for {} bot(s) on {}, {} local bot(s) asked\n",
                    e.id,
                    e.tg.as_ref().map_or(0, |v| v.len()),
                    e.channel,
                    e.bots.len()
                );
            }
            ChanElectPhase::MeshWait => {
                // every other hub we know of, or that any answer says exists
                let expect = (mesh_total(state) - 1).max(e.mesh_known.saturating_sub(1));
                if e.hubs.len() < expect && t - e.phase_at < CHAN_ELECT_MESH_WAIT {
                    continue;
                }
                try_hub(state, ei);
            }
            ChanElectPhase::Hold => {
                if mesh_settling(state, t) && t - e.phase_at < CHAN_ELECT_HOLD_MAX {
                    continue;
                }
                if new_local_bot(state, ei) {
                    probe_local(state, ei); // attached meanwhile
                } else {
                    local_exhausted(state, ei);
                }
            }
            ChanElectPhase::MeshDo => {
                if t - e.phase_at < CHAN_ELECT_HUB_WAIT {
                    continue;
                }
                try_hub(state, ei);
            }
            ChanElectPhase::Acked => {
                // A relay with no ready bot that routed no other hub's answer
                // is never handed the action and has nothing to route: free its
                // copy once the other hubs' answers can no longer arrive
                // through it.
                if !e.origin
                    && e.hubs.is_empty()
                    && count(e, b'y') == 0
                    && e.doing.is_empty()
                    && t - e.phase_at >= CHAN_ELECT_MESH_WAIT
                {
                    release(state, ei);
                }
            }
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
                    state.who_client(ci)
                );
            }
            return;
        }
    }
    let id = state.who_client(ci);
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
    // the mask is the person's live identity, never a pattern: the bot that
    // acts checks the nick against it, and an unban matches bans to it
    if !uchan_field_ok(&nick, MAX_NICK)
        || !uchan_field_ok(&mask, MAX_MASK_LEN)
        || !mask.contains('!')
        || !mask.contains('@')
        || !crate::storage::hostmask_literal(&mask)
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
            "[CHANREQ] {id} asked {kind} {nick} on {chan} for {who}: refused (no rights there)\n",
            who = state.who('u', &who)
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
