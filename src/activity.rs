//! Activity: admin/oper `last_seen` and usermask `last_used` (hub_logic.c
//! "Activity" section; wire contract in `consts::CMD_ACTIVITY`).
//!
//! These are max-merged values outside the LWW config: they only rise, a
//! rise is never a config change (no record forward, no bot push), and every
//! hub converges on the latest time any node saw.  A hub forwards only the
//! lines that raised its own value, so a flood dies out without a seen-set.

use crate::consts::*;
use crate::cstr::now;
use crate::queue;
use crate::state::{ClientType, HubState, Lane, QueuedMsg};

/// A user uuid as the config stores it: 36 chars, hex and dashes.
fn uuid_ok(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// Max-merge one activity time outside LWW.  A rise is persisted but is
/// never a config update: nothing forwarded or pushed.
pub fn raise(state: &mut HubState, slot: Slot, ts: i64) -> bool {
    if ts > now() + ACTIVITY_MAX_FUTURE {
        return false;
    }
    let cur = match slot {
        Slot::User(i) => &mut state.user_records[i].last_seen,
        Slot::Mask(i) => &mut state.mask_records[i].last_used,
    };
    if ts <= *cur {
        return false;
    }
    *cur = ts;
    state.config_dirty = true;
    true
}

/// Which record's activity time `raise` touches.
#[derive(Clone, Copy)]
pub enum Slot {
    User(usize),
    Mask(usize),
}

/// Send CMD_ACTIVITY lines to every authenticated peer except `exclude_fd`.
fn flood(state: &mut HubState, lines: &str, exclude_fd: i32) {
    if lines.is_empty() {
        return;
    }
    for c in state.clients.iter_mut() {
        if c.typ != ClientType::Hub || !c.authenticated || c.fd == exclude_fd {
            continue;
        }
        let Some(m) = QueuedMsg::new(CMD_ACTIVITY, Lane::Delta, lines.as_bytes()) else {
            continue;
        };
        if !queue::enqueue(c, m) {
            crate::hlog_warning!("[ACTIVITY] enqueue failed for peer {}\n", c.ip);
        }
    }
}

/// hub_admin login: stamp the admin's exact time; the first login in an
/// ACTIVITY_BUCKET is flooded to the peers.  Never a config change.
pub fn stamp_user(state: &mut HubState, ui: usize, t: i64) {
    let prev = state.user_records[ui].last_seen;
    if t <= prev {
        return;
    }
    state.user_records[ui].last_seen = t;
    state.config_dirty = true;
    let new_bucket = prev / ACTIVITY_BUCKET < t / ACTIVITY_BUCKET;
    crate::hlog_debug!(
        "[ACTIVITY] {} last seen {t}{}\n",
        state.user_records[ui].name,
        if new_bucket {
            " (first this hour: flooded to peers)"
        } else {
            ""
        }
    );
    if new_bucket {
        let line = format!("a|{}|{t}\n", state.user_records[ui].uuid);
        flood(state, &line, -1);
    }
}

/// One validated CMD_ACTIVITY line: the record it names and its time.
/// `a|uuid|ts` or `m|uuid|mask|ts`; the time is always the last field, so a
/// mask may hold a '|' of its own.
fn parse_line(state: &HubState, line: &str) -> Option<(Slot, i64, String)> {
    let b = line.as_bytes();
    if b.len() < 2 + 36 + 2 || b[1] != b'|' || !matches!(b[0], b'a' | b'm') {
        return None;
    }
    let uuid = line.get(2..38)?;
    if !uuid_ok(uuid) || b[38] != b'|' {
        return None;
    }
    let last = line.rfind('|')?;
    let ts: i64 = line[last + 1..].parse().ok()?;
    if b[0] == b'a' {
        if last != 38 {
            return None;
        }
        let ui = state.user_records.iter().position(|u| u.uuid == uuid)?;
        Some((Slot::User(ui), ts, format!("a|{uuid}|{ts}\n")))
    } else {
        if last <= 39 || last - 39 >= MAX_MASK_LEN {
            return None;
        }
        let mask = &line[39..last];
        let mi = state
            .mask_records
            .iter()
            .position(|m| m.uuid == uuid && m.mask.eq_ignore_ascii_case(mask))?;
        Some((Slot::Mask(mi), ts, format!("m|{uuid}|{mask}|{ts}\n")))
    }
}

/// CMD_ACTIVITY from a bot or a peer (client `ci`).  Every line is validated
/// on its own; a bad or unknown one is dropped.  Lines that raised our value
/// go on to the other peers.
pub fn process(state: &mut HubState, ci: usize, payload: &str) {
    let from_id = state.clients[ci].id.clone();
    let exclude_fd = if state.clients[ci].typ == ClientType::Hub {
        state.clients[ci].fd
    } else {
        -1
    };
    let t = now();
    let mut fwd = String::new();
    let mut raised = 0;
    for line in payload
        .split('\n')
        .filter(|l| !l.is_empty())
        .take(MAX_HUB_USER_RECORDS + MAX_HUB_USER_MASKS)
    {
        let Some((slot, ts, canon)) = parse_line(state, line) else {
            crate::hlog_debug!("[ACTIVITY] malformed or unknown line from {from_id}\n");
            continue;
        };
        if ts <= 0 || ts > t + ACTIVITY_MAX_FUTURE {
            crate::hlog_debug!("[ACTIVITY] bad time from {from_id}\n");
            continue;
        }
        if raise(state, slot, ts) {
            raised += 1;
            if fwd.len() + canon.len() < MAX_BUFFER - 5 {
                fwd.push_str(&canon);
            }
        }
    }
    if raised > 0 {
        crate::hlog_debug!("[ACTIVITY] {raised} record(s) raised by {from_id}\n");
        flood(state, &fwd, exclude_fd);
    }
}

/// Queue one CMD_ACTIVITY_REPLY chunk to bot `ci`.
fn reply_send(state: &mut HubState, ci: usize, frame: &str) {
    let Some(m) = QueuedMsg::new(CMD_ACTIVITY_REPLY, Lane::Delta, frame.as_bytes()) else {
        return;
    };
    if !queue::enqueue(&mut state.clients[ci], m) {
        crate::hlog_warning!(
            "[ACTIVITY] reply enqueue failed for {}\n",
            state.clients[ci].id
        );
    }
}

/// A request id a bot names: plain id characters only.
fn req_id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= ACTIVITY_REQ_ID_MAX
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// CMD_ACTIVITY_QUERY from bot `ci`: `<req_id>|users` or
/// `<req_id>|masks|<uuid|*>`.  Answers every known time (records at 0 are
/// left out), chunked under MAX_BUFFER.
pub fn process_query(state: &mut HubState, ci: usize, payload: &str) {
    let f: Vec<&str> = payload.trim_end_matches(['\r', '\n']).split('|').collect();
    let id = state.clients[ci].id.clone();
    if f.len() < 2 || !req_id_ok(f[0]) {
        crate::hlog_warning!("[ACTIVITY] invalid query from {id}\n");
        return;
    }
    let masks = f[1] == "masks";
    if !masks && f[1] != "users" {
        crate::hlog_warning!("[ACTIVITY] unknown query kind from {id}\n");
        return;
    }
    let who = if masks {
        f.get(2).copied().unwrap_or("")
    } else {
        "*"
    };
    if masks && who != "*" && !uuid_ok(who) {
        crate::hlog_warning!("[ACTIVITY] invalid masks query from {id}\n");
        return;
    }
    let all = who == "*";

    let mut lines: Vec<String> = Vec::new();
    for u in &state.user_records {
        if u.last_seen > 0 && (all || u.uuid == who) {
            lines.push(format!("a|{}|{}\n", u.uuid, u.last_seen));
        }
    }
    if masks {
        for m in &state.mask_records {
            if m.last_used > 0 && (all || m.uuid == who) {
                lines.push(format!("m|{}|{}|{}\n", m.uuid, m.mask, m.last_used));
            }
        }
    }

    // Frame budget: header + the longest line must always fit.
    let cap = MAX_BUFFER - 64;
    let req = f[0].to_string();
    let mut frame = String::new();
    for line in lines {
        if !frame.is_empty() && format!("{req}|1\n").len() + frame.len() + line.len() > cap {
            reply_send(state, ci, &format!("{req}|1\n{frame}"));
            frame.clear();
        }
        frame.push_str(&line);
    }
    reply_send(state, ci, &format!("{req}|0\n{frame}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{MaskRecord, UserRecord};

    const U: &str = "11111111-2222-3333-4444-555555555555";

    fn st() -> HubState {
        let mut s = HubState::new();
        s.user_records.push(UserRecord {
            uuid: U.into(),
            name: "rob".into(),
            typ: 'a',
            is_active: true,
            last_seen: 100,
            ..Default::default()
        });
        s.mask_records.push(MaskRecord {
            uuid: U.into(),
            mask: "rob|away!*@*".into(),
            is_active: true,
            last_used: 100,
            ..Default::default()
        });
        s
    }

    #[test]
    fn lines_parse_and_validate() {
        let s = st();
        assert!(matches!(
            parse_line(&s, &format!("a|{U}|200")),
            Some((Slot::User(0), 200, _))
        ));
        // A '|' inside the mask: the time is the last field.
        assert!(matches!(
            parse_line(&s, &format!("m|{U}|ROB|AWAY!*@*|300")),
            Some((Slot::Mask(0), 300, _))
        ));
        assert!(parse_line(&s, &format!("a|{U}|x")).is_none());
        assert!(parse_line(&s, &format!("a|{U}|1|2")).is_none());
        assert!(parse_line(&s, &format!("m|{U}||5")).is_none());
        assert!(parse_line(&s, "a|11111111-2222-3333-4444-55555555555z|5").is_none());
        assert!(parse_line(&s, &format!("m|{U}|other!*@*|5")).is_none());
    }

    #[test]
    fn raise_is_max_merge_and_refuses_the_future() {
        let mut s = st();
        assert!(!raise(&mut s, Slot::User(0), 50));
        assert_eq!(s.user_records[0].last_seen, 100);
        assert!(raise(&mut s, Slot::User(0), 150));
        assert_eq!(s.user_records[0].last_seen, 150);
        assert!(!raise(
            &mut s,
            Slot::Mask(0),
            now() + ACTIVITY_MAX_FUTURE + 10
        ));
        assert_eq!(s.mask_records[0].last_used, 100);
    }
}
