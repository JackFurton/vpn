//! A tunnel peer with no TUN device: it answers ICMP echo requests that
//! arrive through the tunnel. Lets one machine test a real vpnd end to end
//! (ping goes into the OS's tunnel interface, through vpnd, here, and back)
//! without a second host or a second interface.
//!
//! cargo run -p vpnd --example echo_peer -- LISTEN PRIVATE_KEY PEER_PUBLIC_KEY ALLOWED_IP

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use vpn_proto::device::{Dest, Device, Outbox, PeerConfig};
use vpn_proto::keys::{PrivateKey, PublicKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [listen, private, peer, allowed] = args.as_slice() else {
        return Err("usage: echo_peer LISTEN PRIVATE_KEY PEER_PUBLIC_KEY ALLOWED_IP".into());
    };
    let socket = UdpSocket::bind(listen.parse::<SocketAddr>()?)?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    let mut device = Device::new(private.parse::<PrivateKey>()?, 1420);
    device.add_peer(PeerConfig {
        public_key: peer.parse::<PublicKey>()?,
        endpoint: None,
        // The peer may ping any address through us (full tunnel tests).
        allowed_ips: vec![allowed.parse()?],
        persistent_keepalive: None,
    });
    // Route replies back: everything goes to the one peer.
    eprintln!("echo_peer listening on {listen}");

    let mut buf = [0u8; 65_535];
    let mut out = Outbox::new();
    loop {
        let now = Instant::now();
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => device.handle_udp(&buf[..n], from, now, &mut out),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => return Err(e.into()),
        }
        device.tick(now, &mut out);
        // Replies to tunnel packets go back through the device, which may
        // queue more output, so drain until quiet.
        while !out.is_empty() {
            let mut replies = Vec::new();
            for (dest, bytes) in out.iter() {
                match dest {
                    Dest::Udp(to) => {
                        socket.send_to(bytes, to)?;
                    }
                    Dest::Tun => replies.extend(echo_reply(bytes)),
                }
            }
            out.clear();
            for reply in replies {
                device.handle_tun(&reply, now, &mut out);
            }
        }
    }
}

/// Turns an IPv4 ICMP echo request into its reply.
fn echo_reply(packet: &[u8]) -> Option<Vec<u8>> {
    let ihl = usize::from(packet.first()? & 0x0f) * 4;
    if packet[0] >> 4 != 4 || packet.len() < ihl + 8 || packet[9] != 1 || packet[ihl] != 8 {
        return None;
    }
    let mut p = packet.to_vec();
    // Swapping source and destination leaves the IP header checksum valid.
    let (src, dst) = (p[12..16].to_vec(), p[16..20].to_vec());
    p[12..16].copy_from_slice(&dst);
    p[16..20].copy_from_slice(&src);
    p[ihl] = 0;
    p[ihl + 2..ihl + 4].fill(0);
    let sum = checksum(&p[ihl..]);
    p[ihl + 2..ihl + 4].copy_from_slice(&sum.to_be_bytes());
    Some(p)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
