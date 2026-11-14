//! The whole tunnel as a sans-IO state machine: feed it packets from the TUN
//! device, datagrams from the UDP socket, and the time; it fills an `Outbox`
//! with what to send where. The event loop in vpnd only moves bytes.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use tracing::{debug, trace};

use crate::handshake::{HandshakeError, InitReceived, Initiator, Tai64N, read_init};
use crate::ip::IpHeader;
use crate::keys::{PrivateKey, PublicKey};
use crate::session::{Session, TransportError};
use crate::wire::{
    Data, HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, HandshakeInit, HandshakeResponse, Message,
};

/// Resend an unanswered initiation after this long.
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// Stop retrying a handshake (and drop queued packets) after this long.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// Packets held per peer while a handshake is in flight.
pub const MAX_QUEUED: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dest {
    Udp(SocketAddr),
    Tun,
}

/// Output of one `Device` call. Bytes live in one reusable buffer, so a
/// steady-state loop that clears it each iteration doesn't allocate.
#[derive(Default)]
pub struct Outbox {
    buf: Vec<u8>,
    items: Vec<(Dest, Range<usize>)>,
}

impl Outbox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Dest, &[u8])> {
        self.items.iter().map(|(d, r)| (*d, &self.buf[r.clone()]))
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.items.clear();
    }

    /// Reserves `max` bytes, lets `write` fill a prefix of them, and keeps
    /// the item only if it succeeds.
    fn push<E>(
        &mut self,
        dest: Dest,
        max: usize,
        write: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Result<&[u8], E> {
        let start = self.buf.len();
        self.buf.resize(start + max, 0);
        match write(&mut self.buf[start..]) {
            Ok(n) => {
                self.buf.truncate(start + n);
                self.items.push((dest, start..start + n));
                Ok(&self.buf[start..])
            }
            Err(e) => {
                self.buf.truncate(start);
                Err(e)
            }
        }
    }

    fn pop(&mut self) {
        if let Some((_, r)) = self.items.pop() {
            self.buf.truncate(r.start);
        }
    }
}

pub struct PeerConfig {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
}

struct Attempt {
    /// None after a response failed to authenticate; `tick` retries.
    initiator: Option<Initiator>,
    first_sent: Instant,
    last_sent: Instant,
}

struct Peer {
    public_key: PublicKey,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<IpNet>,
    /// Confirmed session we send on.
    current: Option<Session>,
    /// Session we accepted as responder, waiting for the initiator's first
    /// packet before we may send on it.
    next: Option<Session>,
    attempt: Option<Attempt>,
    last_init: Option<Tai64N>,
    queue: VecDeque<Vec<u8>>,
}

pub struct Device {
    private: PrivateKey,
    mtu: usize,
    peers: Vec<Peer>,
}

impl Device {
    pub fn new(private: PrivateKey, mtu: usize) -> Self {
        Self {
            private,
            mtu,
            peers: Vec::new(),
        }
    }

    pub fn add_peer(&mut self, c: PeerConfig) {
        self.peers.push(Peer {
            public_key: c.public_key,
            endpoint: c.endpoint,
            allowed_ips: c.allowed_ips,
            current: None,
            next: None,
            attempt: None,
            last_init: None,
            queue: VecDeque::new(),
        });
    }

    /// An outbound IP packet the kernel routed into the tunnel.
    pub fn handle_tun(&mut self, packet: &[u8], now: Instant, out: &mut Outbox) {
        let Some(h) = IpHeader::parse(packet) else {
            debug!(len = packet.len(), "dropping non-IP packet from TUN");
            return;
        };
        // The kernel sends its own traffic (IPv6 router solicitations, for
        // one) into any interface that's up, so this is routine.
        let Some(i) = self.route(h.dst) else {
            trace!(dst = %h.dst, "no peer for destination");
            return;
        };
        self.send_or_queue(i, packet, now, out);
    }

    /// A datagram that arrived on the UDP socket.
    pub fn handle_udp(
        &mut self,
        datagram: &[u8],
        from: SocketAddr,
        now: Instant,
        out: &mut Outbox,
    ) {
        match Message::parse(datagram) {
            Ok(Message::HandshakeInit(m)) => self.on_init(&m, from, out),
            Ok(Message::HandshakeResponse(m)) => self.on_response(&m, from, now, out),
            Ok(Message::Data(d)) => self.on_data(&d, now, out),
            Err(e) => trace!(%from, %e, "dropping datagram"),
        }
    }

    /// Call periodically, a few times a second, to drive retries.
    pub fn tick(&mut self, now: Instant, out: &mut Outbox) {
        for i in 0..self.peers.len() {
            let peer = &mut self.peers[i];
            let Some(a) = &peer.attempt else { continue };
            if now.saturating_duration_since(a.first_sent) >= REKEY_ATTEMPT_TIME {
                debug!(peer = ?peer.public_key, dropped = peer.queue.len(), "handshake timed out");
                peer.attempt = None;
                peer.queue.clear();
            } else if now.saturating_duration_since(a.last_sent) >= REKEY_TIMEOUT {
                self.initiate(i, now, out);
            }
        }
    }

    fn route(&self, dst: IpAddr) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .flat_map(|(i, p)| {
                p.allowed_ips
                    .iter()
                    .filter(move |n| n.contains(&dst))
                    .map(move |n| (n.prefix_len(), i))
            })
            .max_by_key(|&(len, _)| len)
            .map(|(_, i)| i)
    }

    fn send_or_queue(&mut self, i: usize, packet: &[u8], now: Instant, out: &mut Outbox) {
        let mtu = self.mtu;
        let peer = &mut self.peers[i];
        if let (Some(s), Some(ep)) = (peer.current.as_mut(), peer.endpoint) {
            let max = Session::encrypted_len(packet.len(), mtu);
            match out.push(Dest::Udp(ep), max, |b| s.encrypt(packet, mtu, b)) {
                Ok(_) => return,
                Err(TransportError::CounterExhausted) => peer.current = None,
                Err(e) => {
                    debug!(%e, "dropping outbound packet");
                    return;
                }
            }
        }
        if peer.queue.len() < MAX_QUEUED {
            peer.queue.push_back(packet.to_vec());
        } else {
            debug!(peer = ?peer.public_key, "handshake queue full, dropping packet");
        }
        if peer.attempt.is_none() {
            self.initiate(i, now, out);
        }
    }

    fn initiate(&mut self, i: usize, now: Instant, out: &mut Outbox) {
        let index = self.fresh_index();
        let Self { private, peers, .. } = self;
        let peer = &mut peers[i];
        let Some(ep) = peer.endpoint else {
            debug!(peer = ?peer.public_key, "no endpoint known, can't start handshake");
            peer.queue.clear();
            return;
        };
        let first_sent = peer.attempt.as_ref().map_or(now, |a| a.first_sent);
        let mut initiator = None;
        let res = out.push(Dest::Udp(ep), HANDSHAKE_INIT_LEN, |b| {
            let b = b.try_into().expect("push reserved exactly this many bytes");
            initiator = Some(Initiator::start(
                private,
                &peer.public_key,
                index,
                Tai64N::now(),
                b,
            )?);
            Ok::<_, HandshakeError>(HANDSHAKE_INIT_LEN)
        });
        if let Err(e) = res {
            debug!(%e, "failed to build initiation");
        }
        // Record the attempt even on failure so `tick` retries instead of
        // every outbound packet trying again immediately.
        peer.attempt = Some(Attempt {
            initiator,
            first_sent,
            last_sent: now,
        });
    }

    fn fresh_index(&self) -> u32 {
        loop {
            let candidate = getrandom::u32().expect("OS random source failed");
            let in_use = self.peers.iter().any(|p| {
                [&p.current, &p.next]
                    .into_iter()
                    .flatten()
                    .any(|s| s.local_index == candidate)
                    || p.attempt
                        .as_ref()
                        .and_then(|a| a.initiator.as_ref())
                        .is_some_and(|x| x.sender_index() == candidate)
            });
            if !in_use {
                return candidate;
            }
        }
    }

    fn on_init(&mut self, m: &HandshakeInit, from: SocketAddr, out: &mut Outbox) {
        let received = match read_init(&self.private, m) {
            Ok(r) => r,
            Err(e) => {
                debug!(%from, %e, "dropping initiation");
                return;
            }
        };
        let Some(i) = self
            .peers
            .iter()
            .position(|p| &p.public_key == received.peer())
        else {
            debug!(%from, peer = ?received.peer(), "initiation from unknown key");
            return;
        };
        let index = self.fresh_index();
        let peer = &mut self.peers[i];
        let timestamp = received.timestamp();
        match respond(received, peer.last_init, index, from, out) {
            Ok(session) => {
                peer.last_init = Some(timestamp);
                // The initiation proved the sender holds the peer's key and
                // the timestamp proved it's fresh, so this is where it lives now.
                peer.endpoint = Some(from);
                peer.next = Some(session);
            }
            Err(e) => debug!(%from, %e, "rejecting initiation"),
        }
    }

    fn on_response(
        &mut self,
        m: &HandshakeResponse,
        from: SocketAddr,
        now: Instant,
        out: &mut Outbox,
    ) {
        let Some(i) = self.peers.iter().position(|p| {
            p.attempt
                .as_ref()
                .and_then(|a| a.initiator.as_ref())
                .is_some_and(|x| x.sender_index() == m.receiver_index)
        }) else {
            trace!(%from, "response for no pending handshake");
            return;
        };
        let peer = &mut self.peers[i];
        let attempt = peer.attempt.as_mut().expect("found above");
        let initiator = attempt.initiator.take().expect("found above");
        match initiator.finish(m) {
            Ok(session) => {
                peer.attempt = None;
                peer.current = Some(session);
                peer.endpoint = Some(from);
                self.flush(i, true, now, out);
            }
            // The index is visible on the wire, so anyone can send a bogus
            // response. Leave the attempt in place for `tick` to retry.
            Err(e) => debug!(%from, %e, "dropping response"),
        }
    }

    fn on_data(&mut self, d: &Data, now: Instant, out: &mut Outbox) {
        let found = self.peers.iter().enumerate().find_map(|(i, p)| {
            if p.current
                .as_ref()
                .is_some_and(|s| s.local_index == d.receiver_index)
            {
                Some((i, false))
            } else if p
                .next
                .as_ref()
                .is_some_and(|s| s.local_index == d.receiver_index)
            {
                Some((i, true))
            } else {
                None
            }
        });
        let Some((i, is_next)) = found else {
            trace!(index = d.receiver_index, "data for unknown session");
            return;
        };
        let peer = &mut self.peers[i];
        let session = if is_next {
            &mut peer.next
        } else {
            &mut peer.current
        };
        let session = session.as_mut().expect("found above");

        let max = d.ciphertext.len().saturating_sub(crate::wire::TAG_LEN);
        let packet = match out.push(Dest::Tun, max, |b| session.decrypt(d, b).map(<[u8]>::len)) {
            Ok(p) => p,
            Err(e) => {
                trace!(%e, "dropping data");
                return;
            }
        };
        let allowed = match IpHeader::parse(packet) {
            None => false,
            Some(h) => peer.allowed_ips.iter().any(|n| n.contains(&h.src)),
        };
        if packet.is_empty() || !allowed {
            if !packet.is_empty() {
                debug!(peer = ?peer.public_key, "dropping packet from a source outside allowed_ips");
            }
            out.pop();
        }
        if is_next {
            peer.current = peer.next.take();
            self.flush(i, false, now, out);
        }
    }

    /// Sends everything queued for peer `i` on its new session. The
    /// initiator sends a keepalive if nothing is queued, since the responder
    /// can't send until it hears from us.
    fn flush(&mut self, i: usize, initiator: bool, now: Instant, out: &mut Outbox) {
        let queued = std::mem::take(&mut self.peers[i].queue);
        let had_queued = !queued.is_empty();
        for packet in queued {
            self.send_or_queue(i, &packet, now, out);
        }
        if initiator && !had_queued {
            let peer = &mut self.peers[i];
            if let (Some(s), Some(ep)) = (peer.current.as_mut(), peer.endpoint) {
                let _ = out.push(Dest::Udp(ep), crate::wire::DATA_MIN_LEN, |b| s.keepalive(b));
            }
        }
    }
}

fn respond(
    received: InitReceived,
    last_init: Option<Tai64N>,
    index: u32,
    to: SocketAddr,
    out: &mut Outbox,
) -> Result<Session, HandshakeError> {
    let mut session = None;
    out.push(Dest::Udp(to), HANDSHAKE_RESPONSE_LEN, |b| {
        let b = b.try_into().expect("push reserved exactly this many bytes");
        session = Some(received.accept(last_init, index, b)?);
        Ok::<_, HandshakeError>(HANDSHAKE_RESPONSE_LEN)
    })?;
    Ok(session.expect("set on success"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    const A: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)), 1000);
    const B: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)), 2000);

    fn ipv4(src: [u8; 4], dst: [u8; 4], body: u8) -> Vec<u8> {
        let mut p = vec![body; 28];
        p[..20].fill(0);
        p[0] = 0x45;
        p[2..4].copy_from_slice(&28u16.to_be_bytes());
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    fn to_b(body: u8) -> Vec<u8> {
        ipv4([10, 0, 0, 1], [10, 0, 0, 2], body)
    }

    fn to_a(body: u8) -> Vec<u8> {
        ipv4([10, 0, 0, 2], [10, 0, 0, 1], body)
    }

    /// A at 10.0.0.1 knows B's endpoint; B learns A's from the handshake.
    struct Net {
        a: Device,
        b: Device,
        now: Instant,
        /// Datagrams the network should drop, by message type byte.
        drop_types: Vec<u8>,
        sent: Vec<u8>,
    }

    impl Net {
        fn new() -> Self {
            let (ka, kb) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
            let mut a = Device::new(ka.private, 1420);
            a.add_peer(PeerConfig {
                public_key: kb.public,
                endpoint: Some(B),
                allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
            });
            let mut b = Device::new(kb.private, 1420);
            b.add_peer(PeerConfig {
                public_key: ka.public,
                endpoint: None,
                allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            });
            Self {
                a,
                b,
                now: Instant::now(),
                drop_types: vec![],
                sent: vec![],
            }
        }

        /// Delivers everything in `out` (emitted by the device at `from`)
        /// and whatever that triggers, until the network is quiet. Returns
        /// packets written to (A's TUN, B's TUN).
        fn pump(&mut self, from: SocketAddr, out: Outbox) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            let mut tun = (vec![], vec![]);
            let mut pending = VecDeque::from([(from, out)]);
            while let Some((src, out)) = pending.pop_front() {
                for (dest, bytes) in out.iter() {
                    match dest {
                        Dest::Tun if src == A => tun.0.push(bytes.to_vec()),
                        Dest::Tun => tun.1.push(bytes.to_vec()),
                        Dest::Udp(to) => {
                            self.sent.push(bytes[0]);
                            if self.drop_types.contains(&bytes[0]) {
                                continue;
                            }
                            let mut next = Outbox::new();
                            let dev = if to == A { &mut self.a } else { &mut self.b };
                            dev.handle_udp(bytes, src, self.now, &mut next);
                            pending.push_back((to, next));
                        }
                    }
                }
            }
            tun
        }

        fn send_a(&mut self, packet: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            let mut out = Outbox::new();
            self.a.handle_tun(packet, self.now, &mut out);
            self.pump(A, out)
        }

        fn send_b(&mut self, packet: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            let mut out = Outbox::new();
            self.b.handle_tun(packet, self.now, &mut out);
            self.pump(B, out)
        }

        fn tick_a(&mut self, after: Duration) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            self.now += after;
            let mut out = Outbox::new();
            self.a.tick(self.now, &mut out);
            self.pump(A, out)
        }
    }

    #[test]
    fn handshake_then_traffic_both_ways() {
        let mut net = Net::new();
        let (_, at_b) = net.send_a(&to_b(1));
        assert_eq!(at_b, vec![to_b(1)]);
        // init, response, then the queued packet. No keepalive needed.
        assert_eq!(net.sent, [1, 2, 4]);

        let (at_a, _) = net.send_b(&to_a(2));
        assert_eq!(at_a, vec![to_a(2)]);
        let (_, at_b) = net.send_a(&to_b(3));
        assert_eq!(at_b, vec![to_b(3)]);
        assert_eq!(net.sent, [1, 2, 4, 4, 4]);
    }

    #[test]
    fn queued_packets_arrive_in_order() {
        let mut net = Net::new();
        net.drop_types = vec![1];
        for body in 1..=3 {
            net.send_a(&to_b(body));
        }
        net.drop_types.clear();
        let (_, at_b) = net.tick_a(REKEY_TIMEOUT);
        assert_eq!(at_b, vec![to_b(1), to_b(2), to_b(3)]);
    }

    #[test]
    fn retries_lost_initiation_then_gives_up() {
        let mut net = Net::new();
        net.drop_types = vec![1];
        net.send_a(&to_b(1));
        net.tick_a(REKEY_TIMEOUT - Duration::from_millis(1));
        assert_eq!(net.sent, [1], "no retry before REKEY_TIMEOUT");
        net.tick_a(Duration::from_millis(1));
        assert_eq!(net.sent, [1, 1]);

        net.tick_a(REKEY_ATTEMPT_TIME);
        net.drop_types.clear();
        // The attempt was abandoned with its queue, so the next tick is quiet.
        let (_, at_b) = net.tick_a(REKEY_TIMEOUT);
        assert!(at_b.is_empty());
        assert_eq!(net.sent, [1, 1]);
    }

    #[test]
    fn initiator_sends_keepalive_when_nothing_queued() {
        let mut net = Net::new();
        net.drop_types = vec![1];
        net.send_a(&to_b(1));
        // Queue is dropped by the give-up; the next attempt has nothing queued.
        net.tick_a(REKEY_ATTEMPT_TIME);
        net.drop_types.clear();
        net.sent.clear();
        net.a.peers[0].attempt = None;
        let mut out = Outbox::new();
        net.a.initiate(0, net.now, &mut out);
        net.pump(A, out);
        assert_eq!(net.sent, [1, 2, 4]);
        assert!(
            net.b.peers[0].current.is_some(),
            "keepalive confirmed B's session"
        );
    }

    #[test]
    fn forged_response_does_not_stall_handshake() {
        let mut net = Net::new();
        net.drop_types = vec![1];
        net.send_a(&to_b(1));
        let index = net.a.peers[0]
            .attempt
            .as_ref()
            .unwrap()
            .initiator
            .as_ref()
            .unwrap()
            .sender_index();
        let mut forged = [0u8; HANDSHAKE_RESPONSE_LEN];
        forged[0] = 2;
        forged[8..12].copy_from_slice(&index.to_le_bytes());
        net.a.handle_udp(&forged, B, net.now, &mut Outbox::new());

        net.drop_types.clear();
        let (_, at_b) = net.tick_a(REKEY_TIMEOUT);
        assert_eq!(at_b, vec![to_b(1)]);
    }

    #[test]
    fn drops_spoofed_source_and_unrouted_packets() {
        let mut net = Net::new();
        net.send_a(&to_b(1));
        let (_, at_b) = net.send_a(&ipv4([10, 0, 0, 99], [10, 0, 0, 2], 5));
        assert!(
            at_b.is_empty(),
            "B must reject a source outside A's allowed_ips"
        );

        let before = net.sent.len();
        net.send_a(&ipv4([10, 0, 0, 1], [8, 8, 8, 8], 6));
        assert_eq!(net.sent.len(), before, "no peer routes 8.8.8.8");
    }

    #[test]
    fn ignores_initiation_from_unknown_key() {
        let mut net = Net::new();
        let stranger = KeyPair::generate().unwrap();
        let b_public = net.a.peers[0].public_key.clone();
        let mut c = Device::new(stranger.private, 1420);
        c.add_peer(PeerConfig {
            public_key: b_public,
            endpoint: Some(B),
            allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
        });
        let mut out = Outbox::new();
        c.handle_tun(&to_b(1), net.now, &mut out);
        net.pump(A, out);
        assert_eq!(net.sent, [1], "B must not answer");
    }

    #[test]
    fn responder_without_endpoint_drops() {
        let mut net = Net::new();
        net.send_b(&to_a(1));
        assert!(net.sent.is_empty());
        assert!(net.b.peers[0].queue.is_empty());
    }
}
