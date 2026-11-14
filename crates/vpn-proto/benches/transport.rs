use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use ipnet::IpNet;
use vpn_proto::allowed_ips::AllowedIps;
use vpn_proto::device::{Dest, Device, Outbox, PeerConfig};
use vpn_proto::handshake::{Initiator, Tai64N, read_init};
use vpn_proto::keys::KeyPair;
use vpn_proto::session::Session;
use vpn_proto::wire::{HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, Message};

const MTU: usize = 1420;
const SIZES: [usize; 3] = [64, 512, MTU];

fn ipv4(len: usize, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0xab; len];
    p[..20].fill(0);
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p
}

/// Initiator and responder ends of one session.
fn sessions() -> (Session, Session) {
    let (i, r) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let mut init = [0; HANDSHAKE_INIT_LEN];
    let initiator = Initiator::start(&i.private, &r.public, 1, Tai64N::now(), &mut init).unwrap();
    let Ok(Message::HandshakeInit(msg)) = Message::parse(&init) else {
        unreachable!()
    };
    let mut resp = [0; HANDSHAKE_RESPONSE_LEN];
    let responder = read_init(&r.private, &msg)
        .unwrap()
        .accept(None, 2, &mut resp)
        .unwrap();
    let Ok(Message::HandshakeResponse(msg)) = Message::parse(&resp) else {
        unreachable!()
    };
    (initiator.finish(&msg).unwrap(), responder)
}

fn session(c: &mut Criterion) {
    let mut g = c.benchmark_group("session");
    for size in SIZES {
        let packet = ipv4(size, [10, 0, 0, 1], [10, 0, 0, 2]);
        let mut out = vec![0; Session::encrypted_len(MTU, MTU)];
        g.throughput(Throughput::Bytes(size as u64));

        let (mut tx, _) = sessions();
        g.bench_function(format!("encrypt/{size}"), |b| {
            b.iter(|| tx.encrypt(black_box(&packet), MTU, &mut out).unwrap())
        });

        // Every message needs a fresh counter or the replay window drops it,
        // so encryption happens in untimed setup.
        let (mut tx, mut rx) = sessions();
        let mut plain = vec![0; MTU + 16];
        g.bench_function(format!("decrypt/{size}"), |b| {
            b.iter_batched_ref(
                || {
                    let n = tx.encrypt(&packet, MTU, &mut out).unwrap();
                    out[..n].to_vec()
                },
                |msg| {
                    let Ok(Message::Data(data)) = Message::parse(msg) else {
                        unreachable!()
                    };
                    rx.decrypt(&data, &mut plain).unwrap().len()
                },
                BatchSize::SmallInput,
            )
        });
    }
    g.finish();
}

const A: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1000);
const B: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 2000);

/// Two devices with a session up, so each iteration is routing, encryption,
/// parsing, decryption and the cryptokey routing check.
fn device(c: &mut Criterion) {
    let (ka, kb) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
    let mut a = Device::new(ka.private, MTU);
    a.add_peer(PeerConfig {
        public_key: kb.public,
        endpoint: Some(B),
        allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
        persistent_keepalive: None,
    });
    let mut b = Device::new(kb.private, MTU);
    b.add_peer(PeerConfig {
        public_key: ka.public,
        endpoint: None,
        allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
        persistent_keepalive: None,
    });
    let now = Instant::now();
    let (mut out_a, mut out_b) = (Outbox::new(), Outbox::new());
    let mut round_trip = |a: &mut Device, b: &mut Device, packet: &[u8]| -> usize {
        out_a.clear();
        a.handle_tun(packet, now, &mut out_a);
        let mut delivered = 0;
        for (dest, bytes) in out_a.iter() {
            if let Dest::Udp(_) = dest {
                out_b.clear();
                b.handle_udp(bytes, A, now, &mut out_b);
                for (dest, bytes) in out_b.iter() {
                    match dest {
                        Dest::Tun => delivered += bytes.len(),
                        Dest::Udp(_) => a.handle_udp(bytes, B, now, &mut Outbox::new()),
                    }
                }
            }
        }
        delivered
    };

    // The first packet triggers the handshake and waits for it, so pump
    // until one arrives.
    let warm = ipv4(64, [10, 0, 0, 1], [10, 0, 0, 2]);
    while round_trip(&mut a, &mut b, &warm) == 0 {}

    let mut g = c.benchmark_group("device");
    for size in SIZES {
        let packet = ipv4(size, [10, 0, 0, 1], [10, 0, 0, 2]);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_function(format!("tun_to_tun/{size}"), |bench| {
            bench.iter(|| assert_eq!(round_trip(&mut a, &mut b, black_box(&packet)), size))
        });
    }
    g.finish();
}

fn handshake(c: &mut Criterion) {
    c.bench_function("handshake", |b| b.iter(sessions));
}

fn allowed_ips(c: &mut Criterion) {
    // A server with 10k clients on /32s, a few site /24s and a default route.
    let mut t = AllowedIps::new();
    for i in 0..10_000u32 {
        let ip = Ipv4Addr::from(0x0a00_0000 + i);
        t.insert(IpNet::new(ip.into(), 32).unwrap(), i as usize);
    }
    for i in 0..100u32 {
        let ip = Ipv4Addr::from(0xac10_0000 + (i << 8));
        t.insert(IpNet::new(ip.into(), 24).unwrap(), 20_000 + i as usize);
    }
    t.insert("0.0.0.0/0".parse().unwrap(), usize::MAX);

    let mut g = c.benchmark_group("allowed_ips");
    for (name, ip) in [
        ("hit_32", Ipv4Addr::new(10, 0, 30, 57)),
        ("hit_24", Ipv4Addr::new(172, 16, 42, 9)),
        ("default", Ipv4Addr::new(198, 51, 100, 1)),
    ] {
        g.bench_function(name, |b| b.iter(|| t.lookup(black_box(ip.into())).copied()));
    }
    g.finish();
}

criterion_group!(benches, session, device, handshake, allowed_ips);
criterion_main!(benches);
