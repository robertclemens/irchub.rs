//! The hub side of the IRC server pool (2.5.4): hub_pool.c, rule for rule.
//!
//! Plan: irchub docs/plans/2026-10-29_server_pool_plan.md.  The N|/S| records
//! live in `global_entries` (storage.rs: `put_record`, validated by
//! pool_rec); this module holds what acts on them: the bots' NETWORK=
//! reports (CMD_SERVER_REPORT), learning the network's name and flagging an
//! entry wrongnet, the bots' IRC link state (CMD_BOT_IRC_LINK) and the load
//! view sent back to them (CMD_POOL_VIEW).

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
    let ent = if f[1] == "-" { "" } else { f[1] };
    let c = &mut state.clients[ci];
    let changed = c.bot_irc_entry != ent || c.bot_irc_link != f[2];
    c.bot_irc_entry = ent.to_string();
    c.bot_irc_link = f[2].to_string();
    changed
}

// ---- CMD_POOL_VIEW (plan §5.3) ---------------------------------------------

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

/// hub_pool_view_tick(): once a second, send CMD_POOL_VIEW to the pool bots
/// when it changed (at most every POOL_VIEW_GAP s).
pub fn view_tick(state: &mut HubState, now: i64) {
    use sha2::{Digest, Sha256};
    if now - state.pool_view_last_sent < POOL_VIEW_GAP {
        return;
    }
    let Some(text) = view_build(state) else {
        return;
    };
    let h: [u8; 32] = Sha256::digest(text.as_bytes()).into();
    let changed = h != state.pool_view_hash;
    for ci in state.bot_clients() {
        let c = &state.clients[ci];
        if c.retiring || !mesh::bot_version_takes_pool(&c.bot_version) {
            continue;
        }
        // everyone on a change; a bot that has not had this view yet anyway
        if !changed && c.pool_view_sent {
            continue;
        }
        if let Some(m) = QueuedMsg::new(CMD_POOL_VIEW, Lane::Delta, text.as_bytes())
            && queue::enqueue(&mut state.clients[ci], m)
        {
            state.clients[ci].pool_view_sent = true;
            crate::stats::pool_view();
        }
    }
    state.pool_view_hash = h;
    state.pool_view_last_sent = now;
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
        assert_eq!(POOL_VIEW_LINE_MAX, POOL_UUID_LEN + 32);
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
