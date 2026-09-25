//! Socket plumbing for the hub's poll loop: the listener, outbound peer
//! connects with a timeout, blocking writes, one-shot non-blocking sends, and
//! the frame envelope shared by every code path that talks to a client.
//!
//! The C hub ran `select()` over blocking sockets and used
//! `send(..., MSG_DONTWAIT | MSG_NOSIGNAL)` on the queue-drain path only.
//! That split is reproduced exactly: `write_all` is the blocking write the
//! handshake and response paths use, `send_dontwait` is the one-shot send the
//! drain uses, and `poll_fds` replaces `select()` (poll(2) has no FD_SETSIZE
//! ceiling, and the hub already indexes clients by fd, never by set bit).

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::Duration;

use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::socket::MsgFlags;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::consts::*;

/// SO_REUSEADDR listener on `bind_ip:port`, backlog 10.  An unparseable
/// bind_ip falls back to 0.0.0.0, as the C hub does (with the same warning
/// left to the caller).
pub fn listen_on(addr: SocketAddr) -> io::Result<TcpListener> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&SockAddr::from(addr))?;
    sock.listen(10)?;
    Ok(TcpListener::from(sock))
}

/// The bind address: `bind_ip` when it parses as an IPv4 literal other than
/// 0.0.0.0, else INADDR_ANY.  `Err(())` reports an unparseable non-empty
/// bind_ip so the caller can log it before falling back.
pub fn bind_addr(bind_ip: &str, port: i32) -> Result<SocketAddr, SocketAddr> {
    let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as u16);
    if bind_ip.is_empty() || bind_ip == "0.0.0.0" {
        return Ok(any);
    }
    match bind_ip.parse::<Ipv4Addr>() {
        Ok(ip) => Ok(SocketAddr::new(IpAddr::V4(ip), port as u16)),
        Err(_) => Err(any),
    }
}

/// Outbound peer connect, bounded by CONNECT_TIMEOUT.  The C hub set
/// SO_SNDTIMEO on a blocking connect; socket2 does the non-blocking
/// connect + wait, with the same ceiling and the same blocking socket
/// afterwards.
pub fn connect_peer(ip: &str, port: i32) -> io::Result<TcpStream> {
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad peer address"))?;
    let addr = SocketAddr::new(IpAddr::V4(ip), port as u16);
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    sock.connect_timeout(&SockAddr::from(addr), Duration::from_secs(CONNECT_TIMEOUT))?;
    let s = TcpStream::from(sock);
    s.set_nonblocking(false)?;
    Ok(s)
}

/// The dotted-quad of a peer address, as `inet_ntoa` rendered it.
pub fn peer_ip(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    }
}

/// `write(fd, buf, n) == n` on a blocking socket: true only on a full write.
pub fn write_all(sock: &mut TcpStream, buf: &[u8]) -> bool {
    sock.write_all(buf).is_ok()
}

/// One length-prefixed frame (`htonl(len) || body`) written blocking.
pub fn write_framed(sock: &mut TcpStream, body: &[u8]) -> bool {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    write_all(sock, &out)
}

/// What one `send(..., MSG_DONTWAIT | MSG_NOSIGNAL)` did.
pub enum SendOutcome {
    /// Bytes accepted by the kernel.
    Sent(usize),
    /// EAGAIN / EWOULDBLOCK / EINTR — try again on the next POLLOUT.
    WouldBlock,
    /// A hard error; the caller drops the in-flight buffer and logs it.
    Error(io::Error),
}

/// The drain path's one-shot non-blocking send.
pub fn send_dontwait(sock: &TcpStream, buf: &[u8]) -> SendOutcome {
    match nix::sys::socket::send(
        sock.as_raw_fd(),
        buf,
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
    ) {
        Ok(n) => SendOutcome::Sent(n),
        Err(nix::errno::Errno::EAGAIN) | Err(nix::errno::Errno::EINTR) => SendOutcome::WouldBlock,
        Err(e) => SendOutcome::Error(io::Error::from_raw_os_error(e as i32)),
    }
}

/// One read(2) of at most `space` bytes appended to `into`.  `Ok(0)` is EOF —
/// the C loop treats `n <= 0` as a disconnect, and so does every caller here.
pub fn read_into(sock: &mut TcpStream, into: &mut Vec<u8>, space: usize) -> io::Result<usize> {
    if space == 0 {
        return Ok(0);
    }
    let mut chunk = vec![0u8; space.min(64 * 1024)];
    let n = sock.read(&mut chunk)?;
    into.extend_from_slice(&chunk[..n]);
    Ok(n)
}

/// Read exactly `buf.len()` bytes, or fail (hub_admin's recv_all).
pub fn read_exact(sock: &mut TcpStream, buf: &mut [u8]) -> bool {
    sock.read_exact(buf).is_ok()
}

/// What one fd wants watched this pass.
#[derive(Clone, Copy)]
pub struct Watch<'a> {
    pub fd: BorrowedFd<'a>,
    pub write: bool,
}

/// One poll(2) pass.  Returns, per entry in `watch`, whether it is readable
/// and whether it is writable.  A poll error yields "nothing ready", which is
/// what `if (select(...) < 0) continue;` did.
pub fn poll_fds(watch: &[Watch<'_>], timeout_ms: u16) -> Vec<(bool, bool)> {
    let mut fds: Vec<PollFd> = watch
        .iter()
        .map(|w| {
            let mut flags = PollFlags::POLLIN;
            if w.write {
                flags |= PollFlags::POLLOUT;
            }
            PollFd::new(w.fd, flags)
        })
        .collect();
    if nix::poll::poll(&mut fds, PollTimeout::from(timeout_ms)).is_err() {
        return vec![(false, false); watch.len()];
    }
    fds.iter()
        .map(|p| {
            let r = p.revents().unwrap_or(PollFlags::empty());
            // A hangup or error makes the fd readable so the read path reaps
            // it, exactly as select() reported such a socket ready.
            let readable =
                r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR);
            let writable = r.contains(PollFlags::POLLOUT);
            (readable, writable)
        })
        .collect()
}

/// A borrowed fd for a stream, for [`poll_fds`].
pub fn watch(sock: &TcpStream, write: bool) -> Watch<'_> {
    Watch {
        fd: sock.as_fd(),
        write,
    }
}

/// A borrowed fd for the listener.
pub fn watch_listener(l: &TcpListener) -> Watch<'_> {
    Watch {
        fd: l.as_fd(),
        write: false,
    }
}

/// The wire envelope inside an encrypted frame:
///   `plain[0]` = cmd, `plain[1..5]` = inner payload length, `plain[5..]` =
///   payload.
///
/// The inner length is stamped in NETWORK order for bot-destined opcodes and
/// in HOST order for peers and admins.  The bot's frame parser ntohl()s the
/// field unconditionally, so every opcode a bot receives must be big-endian;
/// peers and admins ignore the field entirely and keep the host order the
/// original protocol shipped with.  CMD_BOT_TREE joined the bot list late —
/// without it the bot computed a garbage length, failed its bounds check and
/// silently dropped every tree push.
pub fn inner_len_is_network_order(cmd: u8) -> bool {
    matches!(cmd, CMD_CONFIG_DATA | CMD_BOT_TREE | CMD_ACTIVITY_REPLY)
}

/// Build `cmd || inner_len || payload`.  `network_order` picks how the length
/// field is stamped (see [`inner_len_is_network_order`]).
pub fn frame_plain(cmd: u8, payload: &[u8], network_order: bool) -> Vec<u8> {
    let mut plain = Vec::with_capacity(5 + payload.len());
    plain.push(cmd);
    let n = payload.len() as u32;
    plain.extend_from_slice(&if network_order {
        n.to_be_bytes()
    } else {
        n.to_ne_bytes()
    });
    plain.extend_from_slice(payload);
    plain
}
