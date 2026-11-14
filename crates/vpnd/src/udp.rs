//! The outer UDP socket. One `[::]` socket with IPV6_V6ONLY off serves both
//! IP versions, but the kernel then reports IPv4 peers as v4-mapped IPv6
//! (`::ffff:a.b.c.d`) and expects them back in that form. This module
//! translates at the edge, so `Device` only ever sees plain IPv4 or IPv6.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

pub struct Udp {
    socket: UdpSocket,
    dual_stack: bool,
}

impl Udp {
    /// Binds `[::]:port` dual-stack, or `0.0.0.0:port` where IPv6 is
    /// disabled. Port 0 picks a random one.
    pub fn bind(port: u16) -> io::Result<Self> {
        match bind_dual_stack(port) {
            Ok(socket) => Ok(Self {
                socket,
                dual_stack: true,
            }),
            Err(e) => {
                tracing::warn!(%e, "IPv6 unavailable, listening on IPv4 only");
                let std = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))?;
                std.set_nonblocking(true)?;
                Ok(Self {
                    socket: UdpSocket::from_std(std)?,
                    dual_stack: false,
                })
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (n, from) = self.socket.recv_from(buf).await?;
        Ok((n, unmap(from)))
    }

    pub async fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        let to = if self.dual_stack { map(to) } else { to };
        self.socket.send_to(buf, to).await
    }
}

fn bind_dual_stack(port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // Linux defaults this to off and macOS to on, so always set it.
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    UdpSocket::from_std(socket.into())
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
    async fn one_socket_talks_to_both_families() {
        let server = Udp::bind(0).unwrap();
        assert!(server.dual_stack, "test host should have IPv6 loopback");
        let port = server.local_addr().unwrap().port();

        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
        for (client, to) in [
            (&v4, format!("127.0.0.1:{port}")),
            (&v6, format!("[::1]:{port}")),
        ] {
            client.send_to(b"ping", &to).await.unwrap();
            let mut buf = [0; 16];
            let (n, from) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            assert_eq!(
                from,
                client.local_addr().unwrap(),
                "plain address, not v4-mapped"
            );

            server.send_to(b"pong", from).await.unwrap();
            let n = client.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"pong");
        }
    }
}
