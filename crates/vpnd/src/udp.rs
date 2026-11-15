//! The outer UDP socket. One `[::]` socket with IPV6_V6ONLY off serves both
//! IP versions, but the kernel then reports IPv4 peers as v4-mapped IPv6
//! (`::ffff:a.b.c.d`) and expects them back in that form. This module
//! translates at the edge, so `Device` only ever sees plain IPv4 or IPv6.
//!
//! On Linux it also batches: UDP_SEGMENT (GSO) sends a run of equal-sized
//! datagrams to one address in a single sendmsg, and UDP_GRO hands back
//! several datagrams from one sender in a single recvmsg. Both cut the
//! syscalls per packet, which is what limits throughput (docs/benchmarks.md).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ops::Range;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

pub struct Udp {
    socket: UdpSocket,
    dual_stack: bool,
    /// Cleared if the kernel refuses a GSO send, after which runs go out
    /// one datagram at a time.
    #[cfg(target_os = "linux")]
    gso: std::sync::atomic::AtomicBool,
}

/// The kernel caps a GSO send at 64 segments and one IP datagram's worth of
/// payload.
#[cfg(target_os = "linux")]
const GSO_MAX_SEGMENTS: usize = 64;
#[cfg(target_os = "linux")]
const GSO_MAX_BYTES: usize = 65_000;

const MAX_DATAGRAM: usize = 65_535;
/// Without GRO, datagrams already queued when we wake are read one by one
/// up to this many, so one wakeup still handles a burst.
#[cfg(not(target_os = "linux"))]
const DRAIN: usize = 64;

/// What one wakeup received. With GRO that's one read of several datagrams
/// from one sender; elsewhere, separate reads of whatever was queued.
pub struct UdpRx {
    buf: Vec<u8>,
    datagrams: Vec<(SocketAddr, Range<usize>)>,
}

impl Default for UdpRx {
    fn default() -> Self {
        // Room for four maximum-size datagrams, so draining never has to
        // read into a buffer that could truncate one.
        let len = if cfg!(target_os = "linux") {
            MAX_DATAGRAM
        } else {
            4 * MAX_DATAGRAM
        };
        Self {
            buf: vec![0; len],
            datagrams: Vec::new(),
        }
    }
}

impl UdpRx {
    pub fn datagrams(&self) -> impl Iterator<Item = (SocketAddr, &[u8])> {
        self.datagrams
            .iter()
            .map(|(from, r)| (*from, &self.buf[r.clone()]))
    }
}

impl Udp {
    /// Binds `[::]:port` dual-stack, or `0.0.0.0:port` where IPv6 is
    /// disabled. Port 0 picks a random one.
    /// `mark` sets SO_MARK (Linux) so policy routing can tell our packets
    /// apart; it needs CAP_NET_ADMIN.
    pub fn bind(port: u16, mark: Option<u32>) -> io::Result<Self> {
        match bind_dual_stack(port, mark) {
            Ok(socket) => Ok(Self::new(socket, true)),
            Err(e) => {
                tracing::warn!(%e, "IPv6 unavailable, listening on IPv4 only");
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                set_mark(&socket, mark)?;
                socket.set_nonblocking(true)?;
                socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
                let std: std::net::UdpSocket = socket.into();
                Ok(Self::new(UdpSocket::from_std(std)?, false))
            }
        }
    }

    fn new(socket: UdpSocket, dual_stack: bool) -> Self {
        #[cfg(target_os = "linux")]
        if let Err(e) =
            nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::UdpGroSegment, &true)
        {
            tracing::debug!(%e, "UDP GRO unavailable");
        }
        set_buffer_sizes(&socket);
        Self {
            socket,
            dual_stack,
            #[cfg(target_os = "linux")]
            gso: true.into(),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// How many datagrams of up to `max_len` bytes one `send_run` can carry.
    pub fn max_segments(&self, max_len: usize) -> usize {
        #[cfg(target_os = "linux")]
        return (GSO_MAX_BYTES / max_len.max(1)).clamp(1, GSO_MAX_SEGMENTS);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = max_len;
            1
        }
    }

    pub async fn recv_batch(&self, rx: &mut UdpRx) -> io::Result<()> {
        rx.datagrams.clear();
        #[cfg(target_os = "linux")]
        {
            let (len, stride, from) = self
                .socket
                .async_io(tokio::io::Interest::READABLE, || {
                    gro::recv(&self.socket, &mut rx.buf)
                })
                .await?;
            let from = unmap(from);
            let stride = stride.max(1);
            rx.datagrams.extend(
                (0..len)
                    .step_by(stride)
                    .map(|at| (from, at..len.min(at + stride))),
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            let (n, from) = self.socket.recv_from(&mut rx.buf[..MAX_DATAGRAM]).await?;
            rx.datagrams.push((unmap(from), 0..n));
            let mut at = n;
            while rx.datagrams.len() < DRAIN && at + MAX_DATAGRAM <= rx.buf.len() {
                match self
                    .socket
                    .try_recv_from(&mut rx.buf[at..at + MAX_DATAGRAM])
                {
                    Ok((n, from)) => {
                        rx.datagrams.push((unmap(from), at..at + n));
                        at += n;
                    }
                    // WouldBlock, or an error the next recv_from reports.
                    Err(_) => break,
                }
            }
        }
        Ok(())
    }

    /// Sends `bytes` to `to` as datagrams of `segment` bytes each (the last
    /// may be shorter), in one syscall where GSO allows.
    pub async fn send_run(&self, bytes: &[u8], segment: usize, to: SocketAddr) -> io::Result<()> {
        let to = if self.dual_stack { map(to) } else { to };
        #[cfg(target_os = "linux")]
        if bytes.len() > segment && self.gso.load(std::sync::atomic::Ordering::Relaxed) {
            let r = self
                .socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    gro::send(&self.socket, bytes, segment, to)
                })
                .await;
            match r {
                Ok(()) => return Ok(()),
                // EIO: the egress device can't checksum for us. EINVAL: GSO
                // isn't supported on this socket at all.
                Err(e) if matches!(e.raw_os_error(), Some(libc_code) if libc_code == nix::libc::EIO || libc_code == nix::libc::EINVAL) =>
                {
                    tracing::warn!(%e, "UDP GSO send failed, sending datagrams one at a time from now on");
                    self.gso.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => return Err(e),
            }
        }
        let mut result = Ok(());
        for datagram in bytes.chunks(segment) {
            if let Err(e) = self.socket.send_to(datagram, to).await {
                result = Err(e);
            }
        }
        result
    }
}

#[cfg(target_os = "linux")]
mod gro {
    use std::io::{self, IoSlice, IoSliceMut};
    use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage, recvmsg,
        sendmsg,
    };
    use tokio::net::UdpSocket;

    /// One recvmsg. Returns total length, segment stride and sender.
    pub fn recv(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, usize, SocketAddr)> {
        let mut iov = [IoSliceMut::new(buf)];
        let mut cmsg = nix::cmsg_space!(i32);
        let msg = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::empty(),
        )?;
        let mut stride = msg.bytes;
        for c in msg.cmsgs()? {
            if let ControlMessageOwned::UdpGroSegments(s) = c {
                stride = usize::try_from(s).unwrap_or(msg.bytes);
            }
        }
        let from = msg
            .address
            .as_ref()
            .and_then(to_socket_addr)
            .ok_or_else(|| io::Error::other("datagram without a source address"))?;
        Ok((msg.bytes, stride, from))
    }

    pub fn send(
        socket: &UdpSocket,
        bytes: &[u8],
        segment: usize,
        to: SocketAddr,
    ) -> io::Result<()> {
        let segment = u16::try_from(segment).map_err(|_| io::Error::other("segment too large"))?;
        let addr = SockaddrStorage::from(to);
        let sent = sendmsg(
            socket.as_raw_fd(),
            &[IoSlice::new(bytes)],
            &[ControlMessage::UdpGsoSegments(&segment)],
            MsgFlags::empty(),
            Some(&addr),
        )?;
        if sent != bytes.len() {
            return Err(io::Error::other(format!(
                "GSO send wrote {sent} of {} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }

    fn to_socket_addr(s: &SockaddrStorage) -> Option<SocketAddr> {
        match s.family()? {
            nix::sys::socket::AddressFamily::Inet => {
                s.as_sockaddr_in().map(|a| SocketAddrV4::from(*a).into())
            }
            nix::sys::socket::AddressFamily::Inet6 => {
                s.as_sockaddr_in6().map(|a| SocketAddrV6::from(*a).into())
            }
            _ => None,
        }
    }
}

fn bind_dual_stack(port: u16, mark: Option<u32>) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    set_mark(&socket, mark)?;
    // Linux defaults this to off and macOS to on, so always set it.
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    UdpSocket::from_std(socket.into())
}

/// The default (208 KB on Linux) holds about three GSO bursts, so a peer
/// sending while we decrypt overflows it and TCP inside the tunnel backs
/// off. Same size wireguard-go asks for.
const SOCKET_BUFFER: usize = 7 << 20;

fn set_buffer_sizes(socket: &UdpSocket) {
    // The FORCE variants go past net.core.[rw]mem_max but need
    // CAP_NET_ADMIN, which we still have here (privileges drop later).
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{setsockopt, sockopt};
        let forced = setsockopt(&socket, sockopt::RcvBufForce, &SOCKET_BUFFER)
            .and_then(|()| setsockopt(&socket, sockopt::SndBufForce, &SOCKET_BUFFER));
        if forced.is_ok() {
            return;
        }
    }
    // Linux caps this at the sysctl maximums; macOS refuses past kern.ipc.maxsockbuf.
    let socket = socket2::SockRef::from(socket);
    let sized = socket
        .set_recv_buffer_size(SOCKET_BUFFER)
        .and_then(|()| socket.set_send_buffer_size(SOCKET_BUFFER));
    if let Err(e) = sized {
        tracing::debug!(%e, "keeping default UDP socket buffers");
    }
}

#[cfg(target_os = "linux")]
fn set_mark(socket: &Socket, mark: Option<u32>) -> io::Result<()> {
    mark.map_or(Ok(()), |m| socket.set_mark(m))
}

#[cfg(not(target_os = "linux"))]
fn set_mark(_: &Socket, mark: Option<u32>) -> io::Result<()> {
    match mark {
        Some(_) => Err(io::Error::other("socket marks are Linux only")),
        None => Ok(()),
    }
}

fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => addr,
        },
        v4 => v4,
    }
}

fn map(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0).into(),
        v6 => v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_round_trips() {
        let v4: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let mapped = map(v4);
        assert_eq!(mapped.to_string(), "[::ffff:192.0.2.1]:51820");
        assert_eq!(unmap(mapped), v4);

        let v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_eq!(map(v6), v6);
        assert_eq!(unmap(v6), v6);
    }

    #[tokio::test]
    async fn socket_buffers_grow_past_the_default() {
        let udp = Udp::bind(0, None).unwrap();
        let ours = socket2::SockRef::from(&udp.socket);
        let fresh = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fresh = socket2::SockRef::from(&fresh);
        assert!(ours.recv_buffer_size().unwrap() > fresh.recv_buffer_size().unwrap());
        assert!(ours.send_buffer_size().unwrap() > fresh.send_buffer_size().unwrap());
    }

    #[tokio::test]
    async fn one_socket_talks_to_both_families() {
        let server = Udp::bind(0, None).unwrap();
        assert!(server.dual_stack, "test host should have IPv6 loopback");
        let port = server.local_addr().unwrap().port();

        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
        for (client, to) in [
            (&v4, format!("127.0.0.1:{port}")),
            (&v6, format!("[::1]:{port}")),
        ] {
            client.send_to(b"ping", &to).await.unwrap();
            let mut rx = UdpRx::default();
            server.recv_batch(&mut rx).await.unwrap();
            let got: Vec<_> = rx.datagrams().collect();
            assert_eq!(got.len(), 1);
            let (from, datagram) = got[0];
            assert_eq!(datagram, b"ping");
            assert_eq!(
                from,
                client.local_addr().unwrap(),
                "plain address, not v4-mapped"
            );

            server.send_run(b"pong", 4, from).await.unwrap();
            let mut buf = [0; 16];
            let n = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"pong");
        }
    }

    /// One send_run of four datagrams arrives as four datagrams, whether or
    /// not GSO and GRO batched them on the way.
    /// Datagrams queued from two senders before we wake all arrive, each
    /// with its own source, however many wakeups it takes.
    #[tokio::test]
    async fn a_burst_from_several_senders_keeps_each_source() {
        let server = Udp::bind(0, None).unwrap();
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, server.local_addr().unwrap().port()));
        let (a, b) = (
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        );
        for i in 0..10u8 {
            a.send_to(&[b'a', i], to).await.unwrap();
            b.send_to(&[b'b', i], to).await.unwrap();
        }
        // macOS can hand loopback datagrams over a moment after send returns.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut got = Vec::new();
        let mut rx = UdpRx::default();
        while got.len() < 20 {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                server.recv_batch(&mut rx),
            )
            .await
            .expect("all twenty should arrive")
            .unwrap();
            let before = got.len();
            got.extend(rx.datagrams().map(|(from, d)| (from, d.to_vec())));
            // Everything was queued before the first wakeup, which takes
            // it all whether by GRO (one sender per read) or draining.
            if before == 0 && cfg!(not(target_os = "linux")) {
                assert_eq!(got.len(), 20, "one wakeup drains the queue");
            }
        }
        for (sock, tag) in [(&a, b'a'), (&b, b'b')] {
            let from = sock.local_addr().unwrap();
            let mine: Vec<_> = got
                .iter()
                .filter(|(f, _)| *f == from)
                .map(|(_, d)| d.clone())
                .collect();
            assert_eq!(mine, (0..10u8).map(|i| vec![tag, i]).collect::<Vec<_>>());
        }
    }

    #[tokio::test]
    async fn runs_arrive_as_separate_datagrams() {
        let a = Udp::bind(0, None).unwrap();
        let b = Udp::bind(0, None).unwrap();
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, b.local_addr().unwrap().port()));
        let mut run = Vec::new();
        for (i, len) in [100, 100, 100, 50].into_iter().enumerate() {
            run.extend(std::iter::repeat_n(i as u8, len));
        }
        assert!(a.max_segments(100) >= 4 || cfg!(not(target_os = "linux")));
        a.send_run(&run, 100, to).await.unwrap();

        let mut got = Vec::new();
        let mut rx = UdpRx::default();
        while got.len() < 4 {
            tokio::time::timeout(std::time::Duration::from_secs(2), b.recv_batch(&mut rx))
                .await
                .expect("all four should arrive")
                .unwrap();
            got.extend(rx.datagrams().map(|(_, d)| (d[0], d.len())));
        }
        assert_eq!(got, [(0, 100), (1, 100), (2, 100), (3, 50)]);
    }
}
