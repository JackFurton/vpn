//! Arbitrary datagrams, TUN packets and clock ticks into a real Device. This
//! covers everything up to authentication: parsing, mac1, session lookup,
//! cookie replies, routing and the handshake timers. Nothing may panic.
#![no_main]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vpn_proto::device::{Device, Outbox, PeerConfig};
use vpn_proto::keys::PrivateKey;

#[derive(Arbitrary, Debug)]
enum Event {
    Udp { port: u16, data: Vec<u8> },
    Tun(Vec<u8>),
    Tick { ms: u16 },
}

fuzz_target!(|events: Vec<Event>| {
    // Fixed keys keep runs reproducible.
    let ours = PrivateKey::from_bytes([1; 32]);
    let theirs = PrivateKey::from_bytes([2; 32]).public_key();
    let mut device = Device::new(ours, 1420);
    device.add_peer(PeerConfig {
        public_key: theirs,
        endpoint: Some(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 51820))),
        allowed_ips: vec!["10.0.0.0/24".parse().unwrap(), "fd00::/64".parse().unwrap()],
        persistent_keepalive: Some(Duration::from_secs(25)),
    });

    let mut now = Instant::now();
    let mut out = Outbox::new();
    for event in events {
        match event {
            Event::Udp { port, data } => {
                let from = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), port));
                device.handle_udp(&data, from, now, &mut out);
            }
            Event::Tun(packet) => device.handle_tun(&packet, now, &mut out),
            Event::Tick { ms } => {
                now += Duration::from_millis(u64::from(ms) * 50);
                device.tick(now, &mut out);
            }
        }
        out.clear();
    }
});
