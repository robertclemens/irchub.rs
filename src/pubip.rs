//! This hub's public IPv4 address, looked up over DNS (hub_pubip.c).
//!
//! Three public "what is my address" names, each asked of its own
//! authoritative server by IP literal (no system resolver, no dig):
//!
//! | who        | name                      | class/type | server         |
//! |------------|---------------------------|------------|----------------|
//! | OpenDNS    | `myip.opendns.com`        | IN A       | 208.67.222.222 |
//! | Google     | `o-o.myaddr.l.google.com` | IN TXT     | 216.239.32.10  |
//! | Cloudflare | `whoami.cloudflare`       | CH TXT     | 1.1.1.1        |
//!
//! Tried in that order; the first global unicast IPv4 answer wins.  Display
//! and advice only (hub list, hub show, -id, -setup's paste lines): nothing
//! dials it and nothing reaches the mesh.  Replies are still hostile input:
//! the source must be the server asked, from port 53, the id must match a
//! random one, and every length is checked before it is read.
//!
//! `lookup` (blocking) serves -setup; `tick` (non-blocking, one UDP socket
//! polled each main-loop pass) runs at start and daily.  The answer is kept
//! as `public|<ip>|<ts>` and cannot be set by hand.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::state::HubState;

pub const PUBIP_SOURCES: usize = 3;
/// A good answer is looked up again daily.
pub const PUBIP_REFRESH: i64 = 86400;
/// After every server failed.
pub const PUBIP_RETRY: i64 = 3600;
/// Seconds per server.
const PUBIP_TIMEOUT: i64 = 2;
const PUBIP_MAX_ANSWERS: usize = 16;

struct Src {
    who: &'static str,
    server: Ipv4Addr,
    qname: &'static str,
    qtype: u16,
    qclass: u16,
}

const SRC: [Src; PUBIP_SOURCES] = [
    Src {
        who: "OpenDNS",
        server: Ipv4Addr::new(208, 67, 222, 222),
        qname: "myip.opendns.com",
        qtype: 1,
        qclass: 1,
    },
    Src {
        who: "Google",
        server: Ipv4Addr::new(216, 239, 32, 10),
        qname: "o-o.myaddr.l.google.com",
        qtype: 16,
        qclass: 1,
    },
    Src {
        who: "Cloudflare",
        server: Ipv4Addr::new(1, 1, 1, 1),
        qname: "whoami.cloudflare",
        qtype: 16,
        qclass: 3,
    },
];

pub fn source_name(i: i32) -> &'static str {
    usize::try_from(i)
        .ok()
        .and_then(|i| SRC.get(i))
        .map_or("?", |s| s.who)
}

/// A public answer only: no private, shared, loopback, link-local,
/// multicast or reserved range.
pub fn is_global(ip: &str) -> bool {
    let Ok(a) = ip.parse::<Ipv4Addr>() else {
        return false;
    };
    let [o1, o2, o3, _] = a.octets();
    !(o1 == 0
        || o1 == 10
        || o1 == 127
        || o1 >= 224
        || (o1 == 100 && (o2 & 0xc0) == 64)
        || (o1 == 169 && o2 == 254)
        || (o1 == 172 && (o2 & 0xf0) == 16)
        || (o1 == 192 && o2 == 168)
        || (o1 == 192 && o2 == 0 && o3 == 0)
        || (o1 == 198 && (o2 & 0xfe) == 18))
}

fn build(i: usize, id: u16) -> Option<Vec<u8>> {
    let s = &SRC[i];
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&id.to_be_bytes());
    // QR=0 opcode=0, RD=0: these are authoritative servers; QDCOUNT 1
    b.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in s.qname.split('.') {
        if l.is_empty() || l.len() > 63 {
            return None;
        }
        b.push(l.len() as u8);
        b.extend_from_slice(l.as_bytes());
    }
    b.push(0);
    b.extend_from_slice(&s.qtype.to_be_bytes());
    b.extend_from_slice(&s.qclass.to_be_bytes());
    Some(b)
}

/// Skip a (possibly compressed) name at `off`; None when it runs off the end.
fn skip_name(b: &[u8], mut o: usize) -> Option<usize> {
    for _ in 0..128 {
        let l = *b.get(o)?;
        if l == 0 {
            return Some(o + 1);
        }
        if l & 0xc0 == 0xc0 {
            return (o + 2 <= b.len()).then_some(o + 2);
        }
        if l & 0xc0 != 0 {
            return None;
        }
        o += 1 + l as usize;
    }
    None
}

fn be16(b: &[u8], o: usize) -> usize {
    (usize::from(b[o]) << 8) | usize::from(b[o + 1])
}

/// The reply to query `id` for source `i`: the first global IPv4 answer.
pub fn parse(i: usize, id: u16, b: &[u8]) -> Option<String> {
    let s = SRC.get(i)?;
    let n = b.len();
    if !(12..=4096).contains(&n) || be16(b, 0) != usize::from(id) {
        return None;
    }
    if b[2] & 0x80 == 0 || b[2] & 0x78 != 0 || b[3] & 0x0f != 0 {
        return None; // QR, opcode, rcode
    }
    let (qd, an) = (be16(b, 4), be16(b, 6));
    if qd != 1 || an == 0 || an > PUBIP_MAX_ANSWERS {
        return None;
    }
    let mut o = skip_name(b, 12)?;
    if o + 4 > n {
        return None;
    }
    o += 4;
    for _ in 0..an {
        o = skip_name(b, o)?;
        if o + 10 > n {
            return None;
        }
        let (ty, cls, rdlen) = (be16(b, o), be16(b, o + 2), be16(b, o + 8));
        o += 10;
        if rdlen > n - o {
            return None;
        }
        let rd = &b[o..o + rdlen];
        let mut ip = None;
        if ty == usize::from(s.qtype) && cls == usize::from(s.qclass) {
            if ty == 1 && rdlen == 4 {
                ip = Some(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]).to_string());
            } else if ty == 16 && rdlen >= 1 {
                let sl = usize::from(rd[0]); // the first character-string
                if (7..=15).contains(&sl) && sl < rdlen {
                    ip = std::str::from_utf8(&rd[1..=sl]).ok().map(str::to_string);
                }
            }
        }
        if let Some(ip) = ip.filter(|v| is_global(v)) {
            // canonical form
            return ip.parse::<Ipv4Addr>().ok().map(|a| a.to_string());
        }
        o += rdlen;
    }
    None
}

/// One query socket, sent; None on error.
fn send(i: usize) -> Option<(UdpSocket, u16)> {
    let mut r = [0u8; 2];
    if !crate::crypto::random_bytes(&mut r) {
        return None;
    }
    let id = u16::from_be_bytes(r);
    let q = build(i, id)?;
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.set_nonblocking(true).ok()?;
    let to = SocketAddrV4::new(SRC[i].server, 53);
    (sock.send_to(&q, to).ok()? == q.len()).then_some((sock, id))
}

/// What has arrived for source `i`: Ok(Some) = answer, Ok(None) = nothing
/// yet, Err = this server gave no usable answer.
fn recv(sock: &UdpSocket, i: usize, id: u16) -> Result<Option<String>, ()> {
    for _ in 0..8 {
        let mut b = [0u8; 1500];
        match sock.recv_from(&mut b) {
            Ok((n, from)) => {
                // only the server asked, from port 53: anything else is dropped
                if from != SocketAddr::V4(SocketAddrV4::new(SRC[i].server, 53)) {
                    continue;
                }
                return parse(i, id, &b[..n]).map(Some).ok_or(());
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                return Ok(None);
            }
            Err(_) => return Err(()),
        }
    }
    Ok(None)
}

/// IRCHUB_TEST_PUBIP: "off" never looks up; an IPv4 address is the answer.
#[cfg(feature = "test-hooks")]
fn hook() -> Option<String> {
    std::env::var("IRCHUB_TEST_PUBIP")
        .ok()
        .filter(|v| !v.is_empty())
}
#[cfg(not(feature = "test-hooks"))]
fn hook() -> Option<String> {
    None
}

/// Blocking lookup for -setup: (address, source index; -1 = test hook).
pub fn lookup() -> Option<(String, i32)> {
    if let Some(h) = hook() {
        return (h != "off" && h.parse::<Ipv4Addr>().is_ok()).then_some((h, -1));
    }
    for i in 0..PUBIP_SOURCES {
        let Some((sock, id)) = send(i) else { continue };
        let until = Instant::now() + Duration::from_secs(PUBIP_TIMEOUT as u64);
        while Instant::now() < until {
            match recv(&sock, i, id) {
                Ok(Some(ip)) => return Some((ip, i as i32)),
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(()) => break,
            }
        }
    }
    None
}

/// The running hub's lookup, one step per main-loop pass, never blocking.
struct Pl {
    sock: Option<(UdpSocket, u16)>,
    src: usize,
    sent: i64,
    next: i64,
    failed_logged: bool,
}

static PL: Mutex<Pl> = Mutex::new(Pl {
    sock: None,
    src: 0,
    sent: 0,
    next: 0,
    failed_logged: false,
});

fn found(state: &mut HubState, pl: &mut Pl, ip: &str, src: i32, now: i64) {
    pl.failed_logged = false;
    let changed = state.public_ip != ip;
    if changed {
        crate::hlog_info!(
            "[HUB] Public address {} (looked up via {})\n",
            ip,
            if src >= 0 {
                source_name(src)
            } else {
                "test hook"
            }
        );
    }
    state.public_ip = ip.to_string();
    state.public_ip_at = now;
    // the timestamp alone is not worth a config rewrite
    if changed {
        state.config_dirty = true;
    }
}

pub fn tick(state: &mut HubState, now: i64) {
    let mut pl = PL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(h) = hook() {
        if now < pl.next {
            return;
        }
        pl.next = now + PUBIP_REFRESH;
        if h != "off" && is_global(&h) {
            found(state, &mut pl, &h, -1, now);
        }
        return;
    }
    if pl.sock.is_none() {
        if now < pl.next {
            return;
        }
        pl.src = 0;
        while pl.src < PUBIP_SOURCES {
            pl.sock = send(pl.src);
            if pl.sock.is_some() {
                break;
            }
            pl.src += 1;
        }
        pl.sent = now;
        if pl.sock.is_some() {
            return;
        }
    } else {
        let (src, sent) = (pl.src, pl.sent);
        let got = {
            let (sock, id) = pl.sock.as_ref().expect("checked");
            recv(sock, src, *id)
        };
        match got {
            Ok(Some(ip)) => {
                pl.sock = None;
                pl.next = now + PUBIP_REFRESH;
                found(state, &mut pl, &ip, src as i32, now);
                return;
            }
            Ok(None) if now - sent < PUBIP_TIMEOUT => return,
            _ => {}
        }
        // this server is silent or useless: the next one
        pl.sock = None;
        while pl.src + 1 < PUBIP_SOURCES {
            pl.src += 1;
            pl.sock = send(pl.src);
            if pl.sock.is_some() {
                pl.sent = now;
                return;
            }
        }
    }
    // every server failed: keep the last known address, try again in an hour
    pl.next = now + PUBIP_RETRY;
    if !pl.failed_logged {
        crate::hlog_info!(
            "[HUB] Public address lookup failed (OpenDNS, Google, Cloudflare); {}\n",
            if state.public_ip.is_empty() {
                "retrying hourly"
            } else {
                "keeping the last one"
            }
        );
    }
    pl.failed_logged = true;
}

/// The address other nodes should dial, for printouts: the public one when
/// known, else a specific bind address, else None (a wildcard tells nobody).
pub fn dial_address(state: &HubState) -> Option<&str> {
    if !state.public_ip.is_empty() {
        Some(&state.public_ip)
    } else if !state.bind_ip.is_empty() && state.bind_ip != "0.0.0.0" {
        Some(&state.bind_ip)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply to query `id` for source `i`: the question echoed, QR set,
    /// then `answers` (each already a full RR).
    fn reply(i: usize, id: u16, answers: &[&[u8]]) -> Vec<u8> {
        let mut r = build(i, id).unwrap();
        r[2] = 0x84; // QR + AA
        r[7] = answers.len() as u8;
        for a in answers {
            r.extend_from_slice(a);
        }
        r
    }

    fn rr(ty: u16, class: u16, rd: &[u8]) -> Vec<u8> {
        let mut v = vec![0xc0, 12]; // pointer to the question name
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(&class.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 60]);
        v.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        v.extend_from_slice(rd);
        v
    }

    fn txt(s: &str) -> Vec<u8> {
        let mut v = vec![s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    #[test]
    fn global_ranges() {
        for ip in ["8.8.8.8", "149.76.112.174", "203.0.113.10"] {
            assert!(is_global(ip), "{ip}");
        }
        for ip in [
            "0.1.2.3",
            "10.1.1.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "1.2.3",
            "x",
            "",
        ] {
            assert!(!is_global(ip), "{ip}");
        }
    }

    #[test]
    fn opendns_a() {
        let r = reply(0, 0x1234, &[&rr(1, 1, &[149, 76, 112, 174])]);
        assert_eq!(parse(0, 0x1234, &r).as_deref(), Some("149.76.112.174"));
    }

    #[test]
    fn google_and_cloudflare_txt() {
        let g = reply(1, 9, &[&rr(16, 1, &txt("149.76.112.174"))]);
        assert_eq!(parse(1, 9, &g).as_deref(), Some("149.76.112.174"));
        let c = reply(2, 7, &[&rr(16, 3, &txt("149.76.112.174"))]);
        assert_eq!(parse(2, 7, &c).as_deref(), Some("149.76.112.174"));
    }

    #[test]
    fn first_usable_answer_wins() {
        // Google can add an edns0-client-subnet TXT; a private one is skipped
        let r = reply(
            1,
            3,
            &[
                &rr(16, 1, &txt("edns0-client-subnet")),
                &rr(16, 1, &txt("10.0.0.1")),
                &rr(16, 1, &txt("149.76.112.174")),
            ],
        );
        assert_eq!(parse(1, 3, &r).as_deref(), Some("149.76.112.174"));
    }

    #[test]
    fn refused_replies() {
        let ok = reply(0, 1, &[&rr(1, 1, &[149, 76, 112, 174])]);
        assert_eq!(parse(0, 2, &ok), None, "wrong id");
        assert_eq!(parse(1, 1, &ok), None, "wrong source: A is not TXT");
        let mut q = ok.clone();
        q[2] &= 0x7f;
        assert_eq!(parse(0, 1, &q), None, "QR clear (a query, not a reply)");
        let mut rc = ok.clone();
        rc[3] |= 3;
        assert_eq!(parse(0, 1, &rc), None, "NXDOMAIN");
        let mut op = ok.clone();
        op[2] |= 0x08;
        assert_eq!(parse(0, 1, &op), None, "opcode not 0");
        assert_eq!(parse(0, 1, &reply(0, 1, &[])), None, "no answers");
        let p = reply(0, 1, &[&rr(1, 1, &[192, 168, 0, 1])]);
        assert_eq!(parse(0, 1, &p), None, "private answer");
        let w = reply(0, 1, &[&rr(1, 1, &[1, 2, 3])]);
        assert_eq!(parse(0, 1, &w), None, "A of 3 bytes");
        let ch = reply(2, 1, &[&rr(16, 1, &txt("149.76.112.174"))]);
        assert_eq!(parse(2, 1, &ch), None, "IN where CH was asked");
        let long = reply(1, 1, &[&rr(16, 1, &txt("149.76.112.174.1"))]);
        assert_eq!(parse(1, 1, &long), None, "TXT longer than an address");
    }

    #[test]
    fn hostile_lengths() {
        let ok = reply(0, 1, &[&rr(1, 1, &[149, 76, 112, 174])]);
        for n in 0..ok.len() {
            assert_eq!(parse(0, 1, &ok[..n]), None, "truncated at {n}");
        }
        let mut big = ok.clone();
        let rdlen_at = big.len() - 6;
        big[rdlen_at] = 0xff; // RDLENGTH past the end
        assert_eq!(parse(0, 1, &big), None);
        let mut lie = ok.clone();
        lie[7] = 16; // ANCOUNT says 16, one is there
        lie[rdlen_at + 2] = 10; // and that one is private, so parsing goes on
        assert_eq!(parse(0, 1, &lie), None);
        let mut many = ok.clone();
        many[7] = 17;
        assert_eq!(parse(0, 1, &many), None, "ANCOUNT over the cap");
        // a label run with no end, and a pointer cut in half
        let mut lab = vec![0x12, 0x34, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        lab.extend(std::iter::repeat_n(0x3f, 200));
        assert_eq!(parse(0, 0x1234, &lab), None);
        let mut cut = vec![0x12, 0x34, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        cut.push(0xc0);
        assert_eq!(parse(0, 0x1234, &cut), None);
        assert_eq!(parse(0, 1, &vec![0u8; 5000]), None, "over 4096 bytes");
        assert_eq!(parse(3, 1, &ok), None, "no such source");
    }

    #[test]
    fn queries_are_well_formed() {
        for (i, src) in SRC.iter().enumerate() {
            let q = build(i, 0xbeef).unwrap();
            assert_eq!(&q[..2], &[0xbe, 0xef]);
            assert_eq!(q[2] & 0x01, 0, "RD clear");
            assert_eq!(&q[4..6], &[0, 1]);
            let end = skip_name(&q, 12).unwrap();
            assert_eq!(end + 4, q.len());
            assert_eq!(be16(&q, end), usize::from(src.qtype));
            assert_eq!(be16(&q, end + 2), usize::from(src.qclass));
        }
    }

    #[test]
    fn dial_address_order() {
        let mut s = HubState {
            bind_ip: "0.0.0.0".into(),
            ..Default::default()
        };
        assert_eq!(dial_address(&s), None);
        s.bind_ip = "192.0.2.5".into();
        assert_eq!(dial_address(&s), Some("192.0.2.5"));
        s.public_ip = "203.0.113.10".into();
        assert_eq!(dial_address(&s), Some("203.0.113.10"));
    }
}
