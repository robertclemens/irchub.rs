//! The hub side of the IRC server pool (2.5.4): hub_pool.c, rule for rule.
//!
//! Plan: irchub docs/plans/2026-10-29_server_pool_plan.md.  The N|/S| records
//! live in `global_entries` (storage.rs: `put_record`, validated by
//! pool_rec); this module holds what acts on them: the bots' NETWORK=
//! reports (CMD_SERVER_REPORT), learning the network's name and flagging an
//! entry wrongnet, the bots' IRC link state (CMD_BOT_IRC_LINK), the load
//! view the console shows, the bots' server orders (R|) and `server
//! rebalance force`.

use crate::consts::*;
use crate::cstr::trunc_string;
use crate::pool_rec::{
    self, POOL_DEFAULT_NET, POOL_NET_ID_MAX, POOL_NET_NAME_MAX, POOL_UUID_LEN, PoolNet, PoolSrv,
    PoolState,
};
use crate::state::{ClientType, HubState, Lane, QueuedMsg, lww_next_ts};
use crate::{mesh, queue, storage};

/// Volatile strike list per entry (§4.1): the distinct bots that reported it
/// wrong in the last POOL_STRIKE_WINDOW seconds.
const POOL_STRIKE_BOTS: usize = 4;
const POOL_STRIKE_WINDOW: i64 = 3600;
const POOL_STRIKES_NEEDED: usize = 2;

/// C `pool_strikes_t`; `HubState::pool_strikes` holds MAX_POOL_SERVERS.
#[derive(Clone, Debug, Default)]
pub struct PoolStrikes {
    uuid: String,
    bot: [String; POOL_STRIKE_BOTS],
    at: [i64; POOL_STRIKE_BOTS],
}

fn announce(state: &mut HubState, key: &str, value: &str, ts: i64) {
    let line = format!("{key}|{value}|{ts}\n");
    if line.len() < pool_rec::POOL_N_LINE_MAX + pool_rec::POOL_S_LINE_MAX {
        mesh::broadcast_sync_to_peers(state, &line, -1);
    }
    state.config_dirty = true;
    state.bot_config_pending = true;
}

/// hub_pool_net_get(): the stored N| of `net_id` and its stamp, or the
/// default (name not learned) with stamp 0.
pub fn net_get(state: &HubState, net_id: &str) -> (PoolNet, i64) {
    if let Some(i) = storage::global_find(state, "N", net_id)
        && let Some(n) = pool_rec::net_parse(&state.global_entries[i].value)
    {
        return (n, state.global_entries[i].timestamp);
    }
    let n = PoolNet {
        net_id: trunc_string(net_id, POOL_NET_ID_MAX + 1),
        label: trunc_string(net_id, pool_rec::POOL_NET_LABEL_MAX + 1),
        pace_gap: default_pace(),
        ..Default::default()
    };
    (n, 0)
}

/// hub_pool_net_put(): store + announce (peers, owed bot pushes) one N|,
/// stamped past the stored one.
pub fn net_put(state: &mut HubState, n: &PoolNet) -> bool {
    let (_, cur_ts) = net_get(state, &n.net_id);
    let Some(v) = pool_rec::net_format(n) else {
        return false;
    };
    let ts = lww_next_ts(cur_ts);
    if !storage::put_record(state, "N", &v, ts) {
        return false;
    }
    announce(state, "N", &v, ts);
    true
}

/// hub_pool_srv_put(): store + announce one S|, stamped past the stored one.
pub fn srv_put(state: &mut HubState, s: &PoolSrv) -> bool {
    let Some(v) = pool_rec::srv_format(s) else {
        return false;
    };
    let ts = lww_next_ts(storage::global_ts(state, "S", &v));
    if !storage::put_record(state, "S", &v, ts) {
        return false;
    }
    announce(state, "S", &v, ts);
    true
}

/// hub_pool_srv_get(): the S| stored under `uuid` (live or a tombstone).
pub fn srv_get(state: &HubState, uuid: &str) -> Option<PoolSrv> {
    let i = storage::global_find(state, "S", uuid)?;
    pool_rec::srv_parse(&state.global_entries[i].value)
}

fn strikes_for<'a>(st: &'a mut [PoolStrikes], uuid: &str) -> &'a mut PoolStrikes {
    let mut free_slot = None;
    let mut oldest = 0;
    for (i, p) in st.iter().enumerate() {
        if p.uuid == uuid {
            return &mut st[i];
        }
        if p.uuid.is_empty() && free_slot.is_none() {
            free_slot = Some(i);
        }
        if p.at[0] < st[oldest].at[0] {
            oldest = i;
        }
    }
    let p = &mut st[free_slot.unwrap_or(oldest)];
    *p = PoolStrikes {
        uuid: trunc_string(uuid, POOL_UUID_LEN + 1),
        ..Default::default()
    };
    p
}

/// Record bot `who` against entry `uuid`: the number of distinct bots now,
/// and whether `who` is new on it.
fn strike(state: &mut HubState, uuid: &str, who: &str, now: i64) -> (usize, bool) {
    let p = strikes_for(&mut state.pool_strikes, uuid);
    let mut slot = None;
    for i in 0..POOL_STRIKE_BOTS {
        if !p.bot[i].is_empty() && now - p.at[i] > POOL_STRIKE_WINDOW {
            p.bot[i].clear();
        }
        if !p.bot[i].is_empty() && p.bot[i] == who {
            slot = Some(i);
        }
    }
    let added = slot.is_none();
    if slot.is_none() {
        slot = (0..POOL_STRIKE_BOTS).find(|&i| p.bot[i].is_empty());
    }
    let slot = slot.unwrap_or(0);
    p.bot[slot] = trunc_string(who, 64);
    p.at[slot] = now;
    (p.bot.iter().filter(|b| !b.is_empty()).count(), added)
}

/// hub_pool_strikes_clear().
/// C `linked_noted`: true when this entry was already noted linked under this
/// name; else notes it.  Volatile (`HubState::pool_linked`), so the warning is
/// logged once per name, once more after a restart; not the record's seen
/// field, which holds a wrongnet entry's name only.
fn linked_noted(state: &mut HubState, uuid: &str, network: &str) -> bool {
    let v = &mut state.pool_linked;
    if let Some(e) = v.iter_mut().find(|e| e.0 == uuid) {
        if e.1 == network {
            return true;
        }
        e.1 = network.to_string();
        return false;
    }
    if v.len() >= MAX_POOL_SERVERS {
        v[0] = (uuid.to_string(), network.to_string()); // full: more than the pool holds
    } else {
        v.push((uuid.to_string(), network.to_string()));
    }
    false
}

pub fn strikes_clear(state: &mut HubState, uuid: &str) {
    for p in state.pool_strikes.iter_mut().filter(|p| p.uuid == uuid) {
        *p = PoolStrikes::default();
    }
}

fn active_bots(state: &HubState) -> usize {
    state.bots.iter().filter(|b| b.is_active).count()
}

/// Printable ASCII, no '|', at most cap-1 bytes: a server name for the log.
fn printable_field(s: &str, cap: usize) -> bool {
    s.len() < cap && s.bytes().all(|c| (0x20..0x7f).contains(&c))
}

/// A strike that is new here goes to every peer that keeps a pool except
/// the one it came from, which pass it on the same way: the two-bot
/// threshold is mesh-wide although each bot reports only to its own hub.  A
/// bot already struck against the entry is not forwarded again, which ends
/// the flood.
fn strike_forward(
    state: &mut HubState,
    from_fd: i32,
    bot: &str,
    uuid: &str,
    kind: &str,
    network: &str,
    server: &str,
) {
    let fw = format!(
        "{bot}|{uuid}|{kind}|{network}|{}",
        crate::cstr::trunc(server, 256)
    );
    if fw.len() >= 64 + POOL_UUID_LEN + POOL_NET_NAME_MAX + 300 {
        return;
    }
    for ci in state.peer_clients() {
        if state.clients[ci].fd == from_fd || !mesh::peer_takes_pool(state, ci) {
            continue;
        }
        if let Some(m) = QueuedMsg::new(CMD_SERVER_REPORT, Lane::Delta, fw.as_bytes())
            && !queue::enqueue(&mut state.clients[ci], m)
        {
            crate::hlog_warning!(
                "[POOL] Could not queue a report to {}\n",
                state.clients[ci].ip
            );
        }
    }
}

/// One report, from a local bot (from_fd = its fd) or a peer's forward.
#[allow(clippy::too_many_arguments)]
fn report_apply(
    state: &mut HubState,
    from_fd: i32,
    local: bool,
    bot: &str,
    who: &str,
    uuid: &str,
    kind: &str,
    network: &str,
    server: &str,
) {
    let Some(mut s) = srv_get(state, uuid).filter(|s| !s.deleted) else {
        return;
    };
    let (mut net, _) = net_get(state, &s.net_id);

    if kind == "ok" {
        if !local || network.is_empty() {
            return;
        }
        if net.name.is_empty() {
            // The first bot to register names the network; then it is
            // locked (plan D6).  A +s admin can change it or add aliases.
            net.name = trunc_string(network, POOL_NET_NAME_MAX + 1);
            net.deleted = false;
            if net_put(state, &net) {
                crate::hlog_info!(
                    "[POOL] Network {} learned as {network} (from {who} on {})\n",
                    net.net_id,
                    if server.is_empty() { &s.host } else { server }
                );
            }
        }
        if pool_rec::net_matches(&net, network) {
            strikes_clear(state, uuid);
        }
        return;
    }
    if kind == "linked" {
        // NETWORK= is not ours, but a trusted bot on a verified server proved
        // the link (ircbot pool::netproof_*): usable, and the admin is told
        // how to make it plain.  Noted once per name, never a strike.
        if !local || network.is_empty() || pool_rec::net_matches(&net, network) {
            return;
        }
        strikes_clear(state, uuid);
        if !linked_noted(state, uuid, network) {
            crate::hlog_warning!(
                "[POOL] Server {} ({uuid}) says NETWORK={network}, but {who} proved it linked to {}; \
                 to accept that name: network set alias={}{}{network}\n",
                s.host,
                net.name,
                net.aliases,
                if net.aliases.is_empty() { "" } else { "," }
            );
        }
        return;
    }
    if kind != "wrongnet" && kind != "unverified" {
        return;
    }
    if net.name.is_empty() || s.state != PoolState::Ok {
        return; // nothing to be wrong against
    }
    if !network.is_empty() && pool_rec::net_matches(&net, network) {
        return; // a stale report
    }
    let (n, added) = strike(state, uuid, bot, crate::cstr::now());
    if added {
        strike_forward(state, from_fd, bot, uuid, kind, network, server);
    }
    if n < POOL_STRIKES_NEEDED && active_bots(state) > 1 {
        crate::hlog_info!(
            "[POOL] {who} reports {} ({uuid}) as {kind} (NETWORK={}); {n} of {POOL_STRIKES_NEEDED} bots so far\n",
            s.host,
            if network.is_empty() { "none" } else { network }
        );
        return;
    }
    s.state = PoolState::WrongNet;
    s.seen = trunc_string(network, POOL_NET_NAME_MAX + 1);
    if srv_put(state, &s) {
        crate::stats::pool_flagged();
        crate::hlog_warning!(
            "[POOL] Server {} ({uuid}) flagged wrong network: NETWORK={}, expected {} ({n} bot{}); 'server clear' or a network alias undoes it\n",
            s.host,
            if network.is_empty() { "none" } else { network },
            net.name,
            if n == 1 { "" } else { "s" }
        );
    }
    strikes_clear(state, uuid);
}

/// Split `payload` into exactly `want` '|' fields; the last may not hold
/// '|'.  None when the shape is wrong or it is cap bytes or longer.
fn report_fields(payload: &str, cap: usize, want: usize) -> Option<Vec<&str>> {
    if payload.len() >= cap {
        return None;
    }
    let f: Vec<&str> = payload.splitn(want, '|').collect();
    (f.len() == want && !f[want - 1].contains('|')).then_some(f)
}

fn report_shape_ok(uuid: &str, network: &str, server: &str) -> bool {
    uuid.len() == POOL_UUID_LEN
        && (network.is_empty() || pool_rec::net_name_ok(network))
        && printable_field(server, 256)
}

/// hub_pool_server_report(): a CMD_SERVER_REPORT from a local bot,
/// `<entry_uuid>|<kind>|<network>|<server>`.
pub fn server_report(state: &mut HubState, ci: usize, payload: &str) {
    let c = &state.clients[ci];
    if c.typ != ClientType::Bot || !c.authenticated || !mesh::bot_version_takes_pool(&c.bot_version)
    {
        return;
    }
    let Some(f) = report_fields(payload, POOL_UUID_LEN + POOL_NET_NAME_MAX + 320, 4)
        .filter(|f| report_shape_ok(f[0], f[2], f[3]))
    else {
        crate::hlog_warning!(
            "[POOL] Ignored a malformed server report from {}\n",
            state.who_client(ci)
        );
        return;
    };
    crate::stats::pool_report();
    let who = trunc_string(&state.who_client(ci), 160);
    let (fd, id) = (state.clients[ci].fd, state.clients[ci].id.clone());
    report_apply(state, fd, true, &id, &who, f[0], f[1], f[2], f[3]);
}

/// hub_pool_peer_report(): a strike forwarded by a peer,
/// `<bot_uuid>|<entry>|<kind>|<network>|<server>`.
pub fn peer_report(state: &mut HubState, ci: usize, payload: &str) {
    let c = &state.clients[ci];
    if c.typ != ClientType::Hub || !c.authenticated {
        return;
    }
    let Some(f) = report_fields(payload, 64 + POOL_UUID_LEN + POOL_NET_NAME_MAX + 320, 5)
        .filter(|f| crate::access::uuid_shape(f[0]) && report_shape_ok(f[1], f[3], f[4]))
    else {
        crate::hlog_warning!(
            "[POOL] Ignored a malformed server report forwarded by {}\n",
            state.clients[ci].ip
        );
        return;
    };
    let bot_who = trunc_string(&state.who('b', f[0]), 128);
    let via = trunc_string(&state.who_client(ci), 128);
    let who = trunc_string(&format!("{bot_who} (via {via})"), 280);
    let fd = state.clients[ci].fd;
    report_apply(state, fd, false, f[0], &who, f[1], f[2], f[3], f[4]);
}

/// hub_pool_link_word_ok().
pub fn link_word_ok(w: &str) -> bool {
    matches!(w, "connecting" | "up" | "down" | "idle")
}

/// hub_pool_irc_link(): CMD_BOT_IRC_LINK, `<net_id>|<entry_uuid>|<link>|<vs>`:
/// store the bot's link state; true when it changed.
pub fn irc_link(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let c = &state.clients[ci];
    if c.typ != ClientType::Bot || !c.authenticated || !mesh::bot_version_takes_pool(&c.bot_version)
    {
        return false;
    }
    if payload.len() >= POOL_NET_ID_MAX + POOL_UUID_LEN + POOL_LINK_WORD_MAX + 1100 {
        return false;
    }
    let f: Vec<&str> = payload.splitn(4, '|').collect();
    if f.len() < 3
        || !pool_rec::net_id_ok(f[0])
        || !link_word_ok(f[2])
        || (!f[1].is_empty() && f[1] != "-" && f[1].len() != POOL_UUID_LEN)
    {
        return false;
    }
    if !f[1]
        .bytes()
        .all(|q| q.is_ascii_digit() || (b'a'..=b'f').contains(&q) || q == b'-')
    {
        return false;
    }
    // 4th field (2.5.4): the server's NETWORK=, "-" while unknown; a bad one
    // reads as unknown, the rest of the report still counts.
    let net = if f.len() == 4 && f[3] != "-" && pool_rec::net_name_ok(f[3]) {
        f[3]
    } else {
        ""
    };
    let ent = if f[1] == "-" { "" } else { f[1] };
    let c = &mut state.clients[ci];
    let changed = c.bot_irc_entry != ent || c.bot_irc_link != f[2] || c.bot_irc_network != net;
    c.bot_irc_entry = ent.to_string();
    c.bot_irc_link = f[2].to_string();
    c.bot_irc_network = net.to_string();
    changed
}

/// One channel name as RFC 2812 has it: a # & + ! start, then no NUL, BEL,
/// CR, LF, space, ',' or ':' (and no other control byte here), < MAX_CHAN.
fn chan_name_ok(s: &[u8]) -> bool {
    s.len() >= 2
        && s.len() < MAX_CHAN
        && b"#&+!".contains(&s[0])
        && s.iter()
            .all(|&c| c > 0x20 && c != 0x7f && c != b',' && c != b':')
}

/// CMD_BOT_CHAN_STATE / j|: every token valid or the list is refused whole.
pub fn chan_state_ok(s: &str) -> bool {
    if s.len() >= CHAN_STATE_MAX {
        return false;
    }
    if s.is_empty() {
        return true;
    }
    let toks: Vec<&[u8]> = s.as_bytes().split(|&c| c == b',').collect();
    for (i, t) in toks.iter().enumerate() {
        let last = i + 1 == toks.len();
        if t.is_empty() {
            return false;
        }
        if t[0] == b'~' {
            // the tail: N more, last token only
            if !last || t.len() < 2 || t.len() > 6 || !t[1..].iter().all(u8::is_ascii_digit) {
                return false;
            }
        } else if t[0] == b'-' {
            let Some(colon) = t.iter().position(|&c| c == b':') else {
                return false;
            };
            if !chan_name_ok(&t[1..colon]) {
                return false;
            }
            let why = &t[colon + 1..];
            if why.is_empty() || why.len() >= 16 {
                return false;
            }
            if !CHAN_STATE_WHYS.split(' ').any(|w| w.as_bytes() == why) {
                return false;
            }
        } else {
            let mut skip = usize::from(t[0] == b'@' || t[0] == b'%');
            // '+' is voice only when a channel name follows; "+chan" alone is
            // a +channel the bot is in
            if skip == 0 && t[0] == b'+' && t.len() > 2 && b"#&+!".contains(&t[1]) {
                skip = 1;
            }
            if !chan_name_ok(&t[skip..]) {
                return false;
            }
        }
    }
    true
}

/// hub_bot_chan_state(): keep a bot's channel list; true when it changed.
pub fn bot_chan_state(state: &mut HubState, ci: usize, payload: &str) -> bool {
    let c = &state.clients[ci];
    if c.typ != ClientType::Bot || !c.authenticated || !chan_state_ok(payload) {
        return false;
    }
    if c.bot_chan_state == payload {
        return false;
    }
    state.clients[ci].bot_chan_state = payload.to_string();
    true
}

// ---- the load view: who is on which entry (console server list) -----------

struct ViewBot {
    bot: String,
    entry: String,
    server: String,
    /// else connecting
    up: bool,
    /// local reported_at, newest wins for a bot seen twice
    at: i64,
}

fn view_add(
    v: &mut Vec<ViewBot>,
    cap: usize,
    bot: &str,
    entry: &str,
    link: &str,
    server: &str,
    at: i64,
) {
    let up = link == "up";
    if entry.is_empty() || (!up && link != "connecting") {
        return;
    }
    let (bot, entry, server) = (
        trunc_string(bot, 64),
        trunc_string(entry, POOL_UUID_LEN + 1),
        trunc_string(server, ROSTER_SERVER_MAX + 1),
    );
    if let Some(b) = v.iter_mut().find(|b| b.bot == bot) {
        if at < b.at {
            return;
        }
        b.entry = entry;
        b.server = server;
        b.up = up;
        b.at = at;
        return;
    }
    if v.len() >= cap {
        return;
    }
    v.push(ViewBot {
        bot,
        entry,
        server,
        up,
        at,
    });
}

/// The view text's byte cap (C `text[]`).
const VIEW_CAP: usize = (MAX_POOL_SERVERS + MAX_POOL_TOMBS) * POOL_VIEW_LINE_MAX + 16;

/// The view text; None when it would not fit.
fn view_build(state: &HubState) -> Option<String> {
    let vcap = MAX_BOT_ROSTER + MAX_BOTS;
    let mut v: Vec<ViewBot> = Vec::new();
    let now = crate::cstr::now();
    for c in &state.clients {
        if c.typ == ClientType::Bot && c.authenticated && !c.retiring && !c.bot_irc_link.is_empty()
        {
            view_add(
                &mut v,
                vcap,
                &c.id,
                &c.bot_irc_entry,
                &c.bot_irc_link,
                &c.bot_server,
                now,
            );
        }
    }
    for r in &state.roster {
        if !r.irc_link.is_empty() {
            view_add(
                &mut v,
                vcap,
                &r.bot_uuid,
                &r.irc_entry,
                &r.irc_link,
                &r.server,
                r.reported_at,
            );
        }
    }
    // Distinct real servers (the 004 names) with the bots up on each, and
    // the server index of every bot that is up.
    let mut srv: Vec<&str> = Vec::new();
    let mut srv_up: Vec<usize> = Vec::new();
    let mut bot_srv: Vec<Option<usize>> = Vec::with_capacity(v.len());
    for b in &v {
        if !b.up || b.server.is_empty() {
            bot_srv.push(None);
            continue;
        }
        let k = match srv.iter().position(|s| s.eq_ignore_ascii_case(&b.server)) {
            Some(k) => k,
            None => {
                srv.push(&b.server);
                srv_up.push(0);
                srv.len() - 1
            }
        };
        srv_up[k] += 1;
        bot_srv.push(Some(k));
    }
    let mut out = String::new();
    for e in &state.global_entries {
        if e.key != "S" {
            continue;
        }
        let Some(s) = pool_rec::srv_parse(&e.value).filter(|s| !s.deleted) else {
            continue;
        };
        // up = the bots on every real server this entry leads to now (a
        // second name for one server shares its load), plus its own bots
        // whose server is not known yet; connecting = its own bots still
        // dialing.
        let (mut up, mut conn) = (0usize, 0usize);
        let mut mark = vec![false; srv.len()];
        for (i, b) in v.iter().enumerate() {
            if b.entry != s.uuid {
                continue;
            }
            if !b.up {
                conn += 1;
            } else {
                match bot_srv[i] {
                    None => up += 1,
                    Some(k) => mark[k] = true,
                }
            }
        }
        up += mark
            .iter()
            .zip(&srv_up)
            .filter(|(m, _)| **m)
            .map(|(_, n)| n)
            .sum::<usize>();
        let line = format!("E|{}|{up}|{conn}\n", s.uuid);
        if out.len() + line.len() >= VIEW_CAP {
            return None;
        }
        out.push_str(&line);
    }
    Some(out)
}

// ---- server order (plan 2026-11-24_server_order_plan.md) -------------------
//
// Every hub computes every bot's server order from replicated config only:
// the usable S| entries of POOL_DEFAULT_NET (weight, max), the active bots
// and the host of each bot's published hostmask (its origin: what the IRC
// server sees), and the network's pace gap.  The same input gives the same
// orders on every hub, so no hub asks another anything.
//
//  rank   weighted rendezvous: a server's score for a bot is the highest of
//         its `weight` hashes H(bot|server#k) (k = 0 is H(bot|server)), so
//         a server is a bot's best with odds in proportion to its weight.
//  first  bots in uuid order take their best server that no earlier bot of
//         the same origin took first and that is under its share
//         (ceil(bots * w / W), capped by max); a sibling-free server beats
//         one under its share.
//  rest   position by position: the best server not yet in the order that
//         no earlier sibling holds at that position, so siblings that lose
//         their servers together fall back to different ones.
//  slot   siblings that share a first server get slot k of m: each dials
//         only in its own second of a (m * pace_gap) s cycle (ircbot).
//
// A bot dials in that order (ircbot pool.rs); a new order never moves a
// connected bot, it applies at its next connect.

/// s an input must hold still before a recompute.
const ORDER_DEBOUNCE: i64 = 2;

/// The orders this hub computed and the debounce state (C's file statics).
#[derive(Clone, Debug, Default)]
pub struct OrderState {
    /// (bot uuid, R| value) in bot uuid order.
    pub orders: Vec<(String, String)>,
    input: u64,
    input_at: i64,
    /// C `g_order_dirty` inverted (a fresh state is dirty).
    clean: bool,
    last_tick: i64,
}

struct OrdSrv {
    uuid: String,
    weight: i32,
    max: i32,
}

struct OrdBot {
    uuid: String,
    origin: String,
    first: usize,
    n: usize,
    pos: Vec<usize>,
}

fn fnv64(mut h: u64, s: &str) -> u64 {
    for &c in s.as_bytes() {
        h ^= u64::from(c);
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// The rendezvous hash of one (server, k): the first 8 bytes of
/// SHA-256("<bot>|<server>") for k = 0, of "<bot>|<server>#<k>" above.
fn ord_hash(bot: &str, srv: &str, k: i32) -> u64 {
    use sha2::{Digest, Sha256};
    let input = if k != 0 {
        format!("{bot}|{srv}#{k}")
    } else {
        format!("{bot}|{srv}")
    };
    if input.len() >= 160 {
        return 0;
    }
    let d = Sha256::digest(input.as_bytes());
    let mut v = 0u64;
    for b in &d[..8] {
        v = (v << 8) | u64::from(*b);
    }
    v
}

/// The host of a "nick!ident@host" mask, lower-cased; "" without one.
fn ord_origin(mask: &str) -> String {
    match mask.rfind('@') {
        Some(at) if at + 1 < mask.len() => {
            let h = &mask.as_bytes()[at + 1..];
            let h = &h[..h.len().min(MAX_MASK_LEN - 1)];
            String::from_utf8_lossy(&h.to_ascii_lowercase()).into_owned()
        }
        _ => String::new(),
    }
}

/// The inputs, sorted; (servers, bots, gap, digest).
fn ord_inputs(state: &HubState) -> (Vec<OrdSrv>, Vec<OrdBot>, i32, u64) {
    let mut srv: Vec<OrdSrv> = Vec::new();
    for e in &state.global_entries {
        if srv.len() >= MAX_POOL_SERVERS {
            break;
        }
        if e.key != "S" {
            continue;
        }
        let Some(s) = pool_rec::srv_parse(&e.value) else {
            continue;
        };
        if s.deleted || s.state != PoolState::Ok || s.net_id != POOL_DEFAULT_NET {
            continue;
        }
        srv.push(OrdSrv {
            uuid: s.uuid,
            weight: s.weight.max(1),
            max: s.max,
        });
    }
    srv.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    let mut bots: Vec<OrdBot> = Vec::new();
    for b in &state.bots {
        if bots.len() >= MAX_BOTS {
            break;
        }
        if !b.is_active || b.uuid.len() != POOL_UUID_LEN {
            continue;
        }
        let origin = b
            .entries
            .iter()
            .rfind(|e| e.key == "h")
            .map(|e| ord_origin(&e.value))
            .unwrap_or_default();
        bots.push(OrdBot {
            uuid: trunc_string(&b.uuid, 64),
            origin,
            first: 0,
            n: 0,
            pos: Vec::new(),
        });
    }
    bots.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    let gap = net_get(state, POOL_DEFAULT_NET).0.pace_gap;
    let mut h: u64 = 14695981039346656037;
    h = fnv64(h, &format!("g{gap}\n"));
    for s in &srv {
        h = fnv64(fnv64(h, &s.uuid), &format!("|{}|{}\n", s.weight, s.max));
    }
    for b in &bots {
        h = fnv64(fnv64(fnv64(h, &b.uuid), "|"), &b.origin);
    }
    (srv, bots, gap, h)
}

/// Two bots of one origin.  A bot with no published mask is its own.
fn ord_siblings(a: &OrdBot, b: &OrdBot) -> bool {
    !a.origin.is_empty() && a.origin == b.origin
}

fn ord_compute(srv: &[OrdSrv], bots: &mut [OrdBot]) {
    let ns = srv.len();
    let nb = bots.len();
    // rank: each bot's servers by score, best first (ties: server uuid).
    for b in bots.iter_mut() {
        let sc: Vec<u64> = srv
            .iter()
            .map(|s| {
                (0..s.weight)
                    .map(|k| ord_hash(&b.uuid, &s.uuid, k))
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        // insertion sort as C: equal scores keep uuid order (srv is sorted)
        let mut rank: Vec<usize> = Vec::with_capacity(ns);
        for s in 0..ns {
            let mut j = rank.len();
            rank.push(s);
            while j > 0 && sc[rank[j - 1]] < sc[s] {
                rank[j] = rank[j - 1];
                j -= 1;
            }
            rank[j] = s;
        }
        b.pos = rank;
        b.n = 0;
    }
    let wsum: i64 = srv.iter().map(|s| i64::from(s.weight)).sum();
    let mut load = vec![0i64; ns];
    let cap: Vec<i64> = srv
        .iter()
        .map(|s| {
            // the exact share ceil(nb * w / W), at least 1: a new order moves
            // no connected bot, so a tight bound costs nothing
            let mut c = if wsum > 0 {
                (nb as i64 * i64::from(s.weight) + wsum - 1) / wsum
            } else {
                nb as i64
            };
            if c < 1 {
                c = 1;
            }
            if s.max > 0 && c > i64::from(s.max) {
                c = i64::from(s.max);
            }
            c
        })
        .collect();
    // first: rank order, preferring (no sibling, under cap) > (no sibling) >
    // (under cap) > best.
    for b in 0..nb {
        let mut pick: [Option<usize>; 4] = [None; 4];
        for r in 0..ns {
            let s = bots[b].pos[r];
            let sib = (0..b).any(|o| ord_siblings(&bots[o], &bots[b]) && bots[o].first == s);
            let under = load[s] < cap[s];
            let cls = if !sib && under {
                0
            } else if !sib {
                1
            } else if under {
                2
            } else {
                3
            };
            if pick[cls].is_none() {
                pick[cls] = Some(s);
            }
        }
        let f = pick.iter().flatten().next().copied().unwrap_or(0);
        bots[b].first = f;
        load[f] += 1;
    }
    // the order: first, then position by position
    for b in 0..nb {
        let mut out: Vec<usize> = Vec::with_capacity(ns);
        let mut used = vec![false; ns];
        let f = bots[b].first;
        out.push(f);
        used[f] = true;
        for p in 1..ns {
            // free of every earlier sibling at p > free of the siblings that
            // share this bot's order so far (they lose their servers
            // together) > any
            let (mut take, mut mid, mut any) = (None, None, None);
            for r in 0..ns {
                let s = bots[b].pos[r];
                if used[s] {
                    continue;
                }
                if any.is_none() {
                    any = Some(s);
                }
                let (mut held, mut close) = (false, false);
                for o in 0..b {
                    if !ord_siblings(&bots[o], &bots[b]) || bots[o].n <= p || bots[o].pos[p] != s {
                        continue;
                    }
                    held = true;
                    if bots[o].pos[..p] == out[..p] {
                        close = true;
                    }
                }
                if !held {
                    take = Some(s);
                    break;
                } else if !close && mid.is_none() {
                    mid = Some(s);
                }
            }
            let t = take.or(mid).or(any).unwrap_or(0);
            out.push(t);
            used[t] = true;
        }
        // pos is reused as the final order (earlier bots' finals are read
        // above through n > p)
        bots[b].pos = out;
        bots[b].n = ns;
    }
}

/// Recompute when the inputs changed and held still; true when any order
/// changed (the caller pushes configs).
fn ord_refresh(state: &mut HubState, now: i64) -> bool {
    let (srv, mut bots, gap, digest) = ord_inputs(state);
    let os = &mut state.pool_order;
    if digest != os.input {
        os.input = digest;
        os.input_at = now;
        os.clean = false;
        return false;
    }
    if os.clean || now - os.input_at < ORDER_DEBOUNCE {
        return false;
    }
    os.clean = true;
    let ns = srv.len();
    let mut next: Vec<(String, String)> = Vec::new();
    if ns > 0 {
        ord_compute(&srv, &mut bots);
        let nb = bots.len();
        for b in 0..nb {
            let (mut slot, mut slots) = (0i32, 0i32);
            for x in 0..nb {
                let same = x == b
                    || (ord_siblings(&bots[x], &bots[b]) && bots[x].pos[0] == bots[b].pos[0]);
                slots += i32::from(same);
                slot += i32::from(same && x < b);
            }
            let slots = slots.min(pool_rec::POOL_ORDER_SLOTS_MAX);
            let slot = slot.min(slots - 1);
            let n = bots[b].n.min(pool_rec::POOL_ORDER_MAX);
            let mut o = pool_rec::PoolOrder {
                generation: 0,
                slot,
                slots,
                gap,
                ids: bots[b].pos[..n]
                    .iter()
                    .map(|&i| srv[i].uuid.clone())
                    .collect(),
            };
            if let Some(line) = pool_rec::order_format(&mut o) {
                next.push((bots[b].uuid.clone(), line));
            }
        }
    }
    let os = &mut state.pool_order;
    let changed = next != os.orders;
    if changed {
        let nn = next.len();
        os.orders = next;
        crate::stats::pool_order();
        crate::hlog_debug!(
            "[POOL] Server orders recomputed: {nn} bot{} over {ns} server{}\n",
            if nn == 1 { "" } else { "s" },
            if ns == 1 { "" } else { "s" }
        );
    }
    changed
}

/// hub_pool_order_tick(): once a second, recompute the bots' server orders
/// when their inputs changed (debounced) and owe every bot a config push when
/// one did.
pub fn order_tick(state: &mut HubState, now: i64) {
    if now == state.pool_order.last_tick {
        return;
    }
    state.pool_order.last_tick = now;
    if ord_refresh(state, now) {
        state.bot_config_pending = true;
    }
}

/// hub_pool_default_pace(): the pace gap of a network with no N| stored.
pub fn default_pace() -> i32 {
    #[cfg(feature = "test-hooks")]
    {
        // A testnet has every bot on one host and one server: a 15 s gap per
        // slot would hold its tenth bot off IRC for two minutes.
        if let Ok(v) = std::env::var("IRCHUB_TEST_POOL_PACE")
            && v.as_bytes().first().is_some_and(u8::is_ascii_digit)
        {
            let n = crate::cstr::atoi(&v);
            if n <= pool_rec::POOL_PACE_GAP_MAX {
                return n;
            }
        }
    }
    pool_rec::POOL_PACE_GAP_DEFAULT
}

/// hub_pool_order_line(): the R| value of a bot, None when it has none.
pub fn order_line<'a>(state: &'a HubState, bot_uuid: &str) -> Option<&'a str> {
    state
        .pool_order
        .orders
        .iter()
        .find(|(u, _)| u == bot_uuid)
        .map(|(_, l)| l.as_str())
}

/// hub_pool_order_first(): a bot's first server and its slot of slots.
pub fn order_first(state: &HubState, bot_uuid: &str) -> Option<(String, i32, i32)> {
    let o = pool_rec::order_parse(order_line(state, bot_uuid)?)?;
    Some((o.ids[0].clone(), o.slot, o.slots))
}

/// hub_pool_order_place(): where a pool entry sits in a bot's computed order:
/// (1-based place, the order's length); None when the bot has no order or
/// the entry is not in it (bot show: "1st of 3 in its order").
pub fn order_place(state: &HubState, bot_uuid: &str, entry: &str) -> Option<(i64, i64)> {
    if entry.is_empty() {
        return None;
    }
    let o = pool_rec::order_parse(order_line(state, bot_uuid)?)?;
    let k = o.ids.iter().position(|x| x == entry)?;
    Some((k as i64 + 1, o.ids.len() as i64))
}

/// hub_pool_order_first_count(): how many bots have this server first.
pub fn order_first_count(state: &HubState, srv_uuid: &str) -> i64 {
    state
        .pool_order
        .orders
        .iter()
        .filter(|(_, l)| {
            // "<gen>|<slot>|<slots>|<gap>|<first>,..."
            l.splitn(5, '|')
                .nth(4)
                .is_some_and(|rest| rest.as_bytes().starts_with(srv_uuid.as_bytes()))
        })
        .count() as i64
}

/// hub_pool_order_bots(): the bots with an order, in uuid order.
pub fn order_bots(state: &HubState) -> Vec<String> {
    state
        .pool_order
        .orders
        .iter()
        .take(MAX_BOTS)
        .map(|(u, _)| u.clone())
        .collect()
}

/// hub_pool_bot_link(): a bot's IRC link as this hub knows it (its own bot,
/// else the roster): (link word, "" = unknown; the entry it is on).
pub fn bot_link(state: &HubState, bot_uuid: &str) -> (String, String) {
    if let Some(c) = state
        .clients
        .iter()
        .find(|c| c.typ == ClientType::Bot && c.authenticated && !c.retiring && c.id == bot_uuid)
    {
        return (c.bot_irc_link.clone(), c.bot_irc_entry.clone());
    }
    let mut word = String::new();
    let mut entry = String::new();
    let mut at = 0;
    for r in &state.roster {
        if r.bot_uuid != bot_uuid || r.reported_at < at {
            continue;
        }
        at = r.reported_at;
        entry = r.irc_entry.clone();
        word = r.irc_link.clone();
    }
    (word, entry)
}

/// hub_pool_bot_origin(): the bot's origin as the order uses it.
pub fn bot_origin(state: &HubState, bot_uuid: &str) -> String {
    state
        .bots
        .iter()
        .find(|b| b.uuid == bot_uuid)
        .and_then(|b| b.entries.iter().rfind(|e| e.key == "h"))
        .map(|e| ord_origin(&e.value))
        .unwrap_or_default()
}

// ---- server rebalance (server order plan §7) -------------------------------

/// The waves this hub drives (C `rebalance_t`).
#[derive(Clone, Debug, Default)]
pub struct Rebalance {
    pub active: bool,
    pub waves: i64,
    pub moved: i64,
    pub wave: Vec<String>,
    pub wave_at: i64,
    pub by: String,
    /// moved once already: never again this run
    pub done: Vec<String>,
}

/// CMD_BOT_MOVE to our bot `uuid` (a pool bot): true when it was ours.
fn bot_move_local(state: &mut HubState, uuid: &str) -> bool {
    for ci in state.bot_clients() {
        let c = &state.clients[ci];
        if c.superseded
            || c.retiring
            || c.id != uuid
            || !mesh::bot_version_takes_pool(&c.bot_version)
        {
            continue;
        }
        // the bot's own uuid: a frame with an empty payload never reaches its
        // dispatch
        let id = c.id.clone();
        if let Some(m) = QueuedMsg::new(CMD_BOT_MOVE, Lane::Urgent, id.as_bytes()) {
            queue::enqueue(&mut state.clients[ci], m);
        }
        return true;
    }
    false
}

fn bot_move_flood(state: &mut HubState, skip: Option<usize>, payload: &str) {
    for pi in state.peer_clients() {
        if Some(pi) != skip && mesh::peer_takes_pool(state, pi) {
            queue::send_urgent(&mut state.clients[pi], CMD_BOT_MOVE, payload);
        }
    }
}

/// Move one bot, wherever it is linked.
fn bot_move(state: &mut HubState, uuid: &str) {
    if bot_move_local(state, uuid) {
        return;
    }
    let Some(id) = crate::crypto::gen_uuid_v4() else {
        return;
    };
    let payload = format!("{id}|{}|{uuid}", crate::cstr::now());
    crate::opflow::forward_seen_check_and_add(state, &id);
    bot_move_flood(state, None, &payload);
}

/// CMD_BOT_MOVE from a peer: our bot moves, else it is passed on.
pub fn peer_bot_move(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.split('|').collect();
    let ok = f.len() >= 3
        && !f[0].is_empty()
        && f[0].len() < 64
        && f[1].len() < 24
        && f[2].len() < 64
        && crate::upgrade::plan_field_ok(f[0])
        && crate::cstr::is_uuid(f[2]);
    if !ok {
        let ip = state.clients[ci].ip.clone();
        crate::hlog_warning!("[HUB] Malformed BOT_MOVE from peer {ip}\n");
        return;
    }
    let ts = crate::cstr::atoll(f[1]);
    let age = if ts > 0 { crate::cstr::now() - ts } else { 0 };
    if ts <= 0 || !(-CFG_RESYNC_TTL..=CFG_RESYNC_TTL).contains(&age) {
        return;
    }
    if crate::opflow::forward_seen_check_and_add(state, f[0]) {
        return;
    }
    if !bot_move_local(state, f[2]) {
        bot_move_flood(state, Some(ci), payload);
    }
}

/// A bot up on IRC on an entry that is not its first.
pub fn rebalance_off_first(state: &HubState, uuid: &str) -> bool {
    let Some((first, _, _)) = order_first(state, uuid) else {
        return false;
    };
    let (w, cur) = bot_link(state, uuid);
    w == "up" && !cur.is_empty() && cur != first
}

fn rebalance_up_count(state: &HubState) -> usize {
    order_bots(state)
        .iter()
        .filter(|u| bot_link(state, u).0 == "up")
        .count()
}

/// The driver: the bots off their first server, moved in waves of at most
/// REBALANCE_WAVE_MAX (and a quarter of the bots up), one per origin; the
/// next wave when every bot of the last is up on its first again (or
/// REBALANCE_WAVE_WAIT) and a pace gap has passed.  Only the hub where it
/// was typed drives it; it ends there with that hub.
pub fn rebalance_tick(state: &mut HubState, now: i64) {
    if !state.rebalance.active {
        return;
    }
    let gap = net_get(state, POOL_DEFAULT_NET).0.pace_gap;
    if !state.rebalance.wave.is_empty() {
        // back = up on its first server again
        let back = state
            .rebalance
            .wave
            .iter()
            .all(|u| !rebalance_off_first(state, u) && bot_link(state, u).0 == "up");
        let since = now - state.rebalance.wave_at;
        if since < i64::from(gap) || since < 2 || (!back && since < REBALANCE_WAVE_WAIT) {
            return;
        }
        state.rebalance.wave.clear();
    }
    let ids = order_bots(state);
    let size = (rebalance_up_count(state) / 4).clamp(1, REBALANCE_WAVE_MAX);
    let mut origins: Vec<String> = Vec::new();
    let mut wave: Vec<String> = Vec::new();
    for u in &ids {
        if wave.len() >= size {
            break;
        }
        if !rebalance_off_first(state, u) {
            continue;
        }
        // moved once and still off: its first is not taking it
        if state.rebalance.done.contains(u) {
            continue;
        }
        let org = bot_origin(state, u);
        if !org.is_empty() && origins.contains(&org) {
            continue;
        }
        origins.push(org);
        wave.push(u.clone());
    }
    if wave.is_empty() {
        let rb = &state.rebalance;
        crate::hlog_info!(
            "[POOL] Rebalance by {} done: {} bot{} moved in {} wave{}\n",
            rb.by,
            rb.moved,
            if rb.moved == 1 { "" } else { "s" },
            rb.waves,
            if rb.waves == 1 { "" } else { "s" }
        );
        state.rebalance.active = false;
        return;
    }
    for u in &wave {
        let who = state.who('b', u);
        crate::hlog_info!(
            "[POOL] Rebalance wave {}: moving {who} to its first server\n",
            state.rebalance.waves + 1
        );
        bot_move(state, u);
        if state.rebalance.done.len() < MAX_BOTS {
            state.rebalance.done.push(u.clone());
        }
    }
    state.rebalance.moved += wave.len() as i64;
    state.rebalance.waves += 1;
    state.rebalance.wave = wave;
    state.rebalance.wave_at = now;
}

/// hub_pool_view_text(): the view text (E| lines) for the console.
pub fn view_text(state: &HubState) -> Option<String> {
    view_build(state)
}

/// hub_pool_idle_bots(): bots idle for want of a server (local bots, then
/// roster rows of bots not already counted).
pub fn idle_bots(state: &HubState) -> usize {
    let cap = MAX_BOT_ROSTER + MAX_BOTS;
    let mut seen: Vec<&str> = Vec::new();
    let mut n = 0;
    for c in &state.clients {
        if c.typ != ClientType::Bot || !c.authenticated || c.retiring {
            continue;
        }
        if seen.len() < cap {
            seen.push(&c.id);
        }
        n += usize::from(c.bot_irc_link == "idle");
    }
    for r in &state.roster {
        if seen.contains(&r.bot_uuid.as_str()) {
            continue;
        }
        if seen.len() < cap {
            seen.push(&r.bot_uuid);
        }
        n += usize::from(r.irc_link == "idle");
    }
    n
}

/// hub_pool_find(): the stored entry an admin names: a uuid, or host[:port]
/// in POOL_DEFAULT_NET (with no port, host:POOL_DEFAULT_PORT first, else the
/// only entry of that host).
pub fn find(state: &HubState, what: &str) -> Option<PoolSrv> {
    if what.len() == POOL_UUID_LEN
        && let Some(s) = srv_get(state, what)
    {
        return Some(s);
    }
    let (host, port) = pool_rec::hostport_parse(what)?;
    if let Some(uuid) = pool_rec::srv_uuid(POOL_DEFAULT_NET, &host, port)
        && let Some(s) = srv_get(state, &uuid)
    {
        return Some(s);
    }
    let typed_port = if what.starts_with('[') {
        what.contains("]:")
    } else {
        what.contains(':')
    };
    if typed_port {
        return None;
    }
    let mut hits = state
        .global_entries
        .iter()
        .filter(|e| e.key == "S")
        .filter_map(|e| pool_rec::srv_parse(&e.value))
        .filter(|s| !s.deleted && s.host.eq_ignore_ascii_case(&host));
    let one = hits.next()?;
    hits.next().is_none().then_some(one)
}

/// The stats `pool` record's state counts (hub_logic.c's stats block).
pub fn counts(state: &HubState) -> crate::stats::PoolCounts {
    let mut c = crate::stats::PoolCounts::default();
    for s in state
        .global_entries
        .iter()
        .filter(|e| e.key == "S")
        .filter_map(|e| pool_rec::srv_parse(&e.value))
        .filter(|s| !s.deleted)
    {
        c.servers += 1;
        c.wrongnet += usize::from(s.state == PoolState::WrongNet);
    }
    c.usable = storage::pool_eligible_count(state, POOL_DEFAULT_NET);
    c.idle = idle_bots(state);
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consts_mirror_pool_rec() {
        assert_eq!(POOL_N_LINE_MAX_CFG, pool_rec::POOL_N_LINE_MAX);
        assert_eq!(POOL_S_LINE_MAX_CFG, pool_rec::POOL_S_LINE_MAX);
        assert_eq!(POOL_R_LINE_MAX_CFG, pool_rec::POOL_R_LINE_MAX);
        assert_eq!(POOL_VIEW_LINE_MAX, POOL_UUID_LEN + 32);
    }

    const VEC_SRV: [(&str, i32, i32); 3] = [
        ("11111111-0000-8000-8000-000000000001", 1, 0),
        ("22222222-0000-8000-8000-000000000002", 2, 0),
        ("33333333-0000-8000-8000-000000000003", 1, 1),
    ];
    const VEC_BOTS: [(&str, &str); 9] = [
        ("a0000000-0000-4000-8000-000000000001", "host-a"),
        ("a0000000-0000-4000-8000-000000000002", "host-a"),
        ("a0000000-0000-4000-8000-000000000003", "host-a"),
        ("a0000000-0000-4000-8000-000000000008", "host-a"),
        ("a0000000-0000-4000-8000-000000000009", "host-a"),
        ("b0000000-0000-4000-8000-000000000004", "host-b"),
        ("b0000000-0000-4000-8000-000000000005", "host-b"),
        ("c0000000-0000-4000-8000-000000000006", ""),
        ("c0000000-0000-4000-8000-000000000007", ""),
    ];

    #[test]
    fn order_compute_matches_c() {
        // expected from hub_pool.c's ord_compute (a C harness), which the
        // Python mirror (scratchpad sim/order.py) agrees with: (slot, order)
        let want: [(usize, [usize; 3]); 9] = [
            (0, [1, 2, 0]),
            (0, [2, 1, 0]),
            (0, [0, 1, 2]),
            (1, [1, 0, 2]),
            (2, [1, 2, 0]),
            (0, [1, 2, 0]),
            (0, [0, 1, 2]),
            (0, [1, 0, 2]),
            (0, [0, 2, 1]),
        ];
        let srv: Vec<OrdSrv> = VEC_SRV
            .iter()
            .map(|(u, w, m)| OrdSrv {
                uuid: (*u).into(),
                weight: *w,
                max: *m,
            })
            .collect();
        let mut bots: Vec<OrdBot> = VEC_BOTS
            .iter()
            .map(|(u, o)| OrdBot {
                uuid: (*u).into(),
                origin: (*o).into(),
                first: 0,
                n: 0,
                pos: Vec::new(),
            })
            .collect();
        ord_compute(&srv, &mut bots);
        for (b, (slot, order)) in want.iter().enumerate() {
            let got = (0..b)
                .filter(|&x| ord_siblings(&bots[x], &bots[b]) && bots[x].pos[0] == bots[b].pos[0])
                .count();
            assert_eq!(
                (got, bots[b].pos.as_slice()),
                (*slot, &order[..]),
                "bot {b}"
            );
        }
    }

    #[test]
    fn order_refresh_debounces_and_writes_r_lines() {
        let mut s = HubState::default();
        let su: Vec<String> = ["irc1.x.net", "irc2.x.net", "irc3.x.net"]
            .iter()
            .map(|h| {
                let u = pool_rec::srv_uuid("main", h, 6667).unwrap();
                let v = format!("{u}|main|{h}|6667|1|0|ok||add");
                assert!(storage::put_record(&mut s, "S", &v, 100));
                u
            })
            .collect();
        for (i, (u, _)) in VEC_BOTS.iter().enumerate().take(5) {
            s.bots.push(crate::state::BotConfig {
                uuid: (*u).into(),
                entries: vec![crate::state::ConfigEntry {
                    key: "h".into(),
                    value: format!("tnbot{i}!~tnbot{i}@Host.Example"),
                    ..Default::default()
                }],
                is_active: true,
                last_sync_time: 0,
            });
        }
        order_tick(&mut s, 1000); // input seen
        assert!(s.pool_order.orders.is_empty());
        order_tick(&mut s, 1001); // still inside the debounce
        assert!(s.pool_order.orders.is_empty());
        order_tick(&mut s, 1002);
        assert_eq!(s.pool_order.orders.len(), 5);
        assert!(s.bot_config_pending);
        // five bots of one host, three servers: bots that share a first
        // server are slot k of m, m = how many share it
        let got: Vec<(String, i32, i32)> = VEC_BOTS[..5]
            .iter()
            .map(|(u, _)| order_first(&s, u).unwrap())
            .collect();
        for (f, slot, slots) in &got {
            let m = got.iter().filter(|g| g.0 == *f).count() as i32;
            assert_eq!(*slots, m);
            assert!(*slot < *slots);
        }
        assert_eq!(got.iter().filter(|g| g.2 == 1).count(), 1);
        let firsts: i64 = su.iter().map(|u| order_first_count(&s, u)).sum();
        assert_eq!(firsts, 5);
        let p = storage::generate_bot_payload(&s, VEC_BOTS[0].0, true);
        assert!(p.contains(&format!("R|{}|0\n", order_line(&s, VEC_BOTS[0].0).unwrap())));
        assert!(!storage::generate_bot_payload(&s, VEC_BOTS[0].0, false).contains("R|"));
        // same input: no recompute counts as a change
        s.bot_config_pending = false;
        order_tick(&mut s, 1010);
        assert!(!s.bot_config_pending);
    }

    #[test]
    fn report_fields_shape() {
        assert_eq!(
            report_fields("a|b|c|d", 100, 4),
            Some(vec!["a", "b", "c", "d"])
        );
        assert!(report_fields("a|b|c", 100, 4).is_none());
        assert!(report_fields("a|b|c|d|e", 100, 4).is_none());
        assert!(report_fields("a|b|c|d", 7, 4).is_none());
    }

    #[test]
    fn strikes_count_distinct_bots() {
        let mut s = HubState::default();
        assert_eq!(strike(&mut s, "u1", "bot1", 100), (1, true));
        assert_eq!(strike(&mut s, "u1", "bot1", 101), (1, false));
        assert_eq!(strike(&mut s, "u1", "bot2", 102), (2, true));
        // past the window the old strike is gone
        assert_eq!(
            strike(&mut s, "u1", "bot3", 102 + POOL_STRIKE_WINDOW + 1),
            (1, true)
        );
        strikes_clear(&mut s, "u1");
        assert_eq!(strike(&mut s, "u1", "bot1", 5000), (1, true));
    }
}
