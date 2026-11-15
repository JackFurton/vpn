//! Moves bytes between the TUN device, the UDP socket and `Device`. All
//! protocol decisions live in `Device`; this only does IO.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tokio::time::MissedTickBehavior;
use vpn_proto::device::{Dest, Device, Outbox};
use vpn_proto::session::Session;

use crate::tun::{Tun, TunRx, TunTx};
use crate::udp::{Udp, UdpRx};

/// Retries are on a 5s scale; 250ms keeps them within a tick of on time.
const TICK: Duration = Duration::from_millis(250);
/// Rendering is cheap, but a scrape never needs fresher numbers than this.
const METRICS_EVERY: Duration = Duration::from_secs(1);

/// Packet IO the loop needs from a TUN device. A trait so tests can use
/// channels instead of a real interface, which needs root.
pub trait PacketDevice {
    fn recv_batch(&self, rx: &mut TunRx) -> impl Future<Output = io::Result<()>> + Send;
    fn send_batch(&self, tx: &mut TunTx) -> impl Future<Output = io::Result<()>> + Send;
}

impl PacketDevice for Tun {
    fn recv_batch(&self, rx: &mut TunRx) -> impl Future<Output = io::Result<()>> + Send {
        Tun::recv_batch(self, rx)
    }

    fn send_batch(&self, tx: &mut TunTx) -> impl Future<Output = io::Result<()>> + Send {
        Tun::send_batch(self, tx)
    }
}

/// With nothing else in flight, a batch with less crypto than this runs it
/// inline, so a lone ping doesn't pay for two thread wakeups. Tests use the
/// workers for any crypto at all.
const INLINE_BYTES: usize = if cfg!(test) { 1 } else { 8 * 1024 };

/// Runs until `shutdown` resolves or the TUN device fails. `on_endpoints`
/// gets every peer endpoint whenever one moves. `threads` counts this one,
/// so with more than one, the rest encrypt and decrypt while this one keeps
/// moving packets.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut device: Device,
    tun: &impl PacketDevice,
    udp: &Udp,
    mtu: usize,
    threads: usize,
    metrics: Option<watch::Sender<String>>,
    mut on_endpoints: impl FnMut(Vec<IpAddr>),
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let mut last_publish: Option<Instant> = None;
    let mut tun_rx = TunRx::new(mtu);
    let mut tun_tx = TunTx::default();
    let mut udp_rx = UdpRx::default();
    let max_segments = udp.max_segments(Session::encrypted_len(mtu, mtu));
    let mut pipeline = Pipeline::new(threads)?;
    let mut tick_out = Outbox::new();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::pin!(shutdown);

    loop {
        // Every branch is cancel-safe: losing the race drops a future that
        // hasn't consumed anything yet.
        tokio::select! {
            r = tun.recv_batch(&mut tun_rx), if pipeline.has_room() => {
                r?;
                let mut out = pipeline.outbox();
                device.prepare_tun(tun_rx.packets(), Instant::now(), &mut out);
                pipeline.submit(out);
            }
            r = udp.recv_batch(&mut udp_rx), if pipeline.has_room() => match r {
                Ok(()) => {
                    let mut out = pipeline.outbox();
                    device.prepare_udp(udp_rx.datagrams(), Instant::now(), &mut out);
                    pipeline.submit(out);
                }
                // Some platforms surface ICMP errors from earlier sends here.
                // They say nothing about this socket's health.
                Err(e) => tracing::debug!(%e, "UDP receive error"),
            },
            Some((seq, out)) = pipeline.done.recv() => pipeline.crypto_done(seq, out),
            _ = ticker.tick() => {
                let now = Instant::now();
                device.tick(now, &mut tick_out);
                if let Some(tx) = &metrics
                    && last_publish.is_none_or(|t| now - t >= METRICS_EVERY)
                {
                    tx.send_replace(crate::metrics::render(&device.stats(now)));
                    last_publish = Some(now);
                }
                send(&tick_out, tun, udp, max_segments, &mut tun_tx).await;
                tick_out.clear();
            }
            () = &mut shutdown => return Ok(()),
        }

        // Batches finish in the order they were read, whatever order their
        // crypto finished in.
        while let Some(mut out) = pipeline.next_ready() {
            device.finish(Instant::now(), &mut out);
            // Before sending: a reply to a peer's new address needs its
            // route in place (macOS full tunnel), or it loops into the tunnel.
            if device.take_endpoints_changed() {
                on_endpoints(device.endpoints().map(|e| e.ip()).collect());
            }
            send(&out, tun, udp, max_segments, &mut tun_tx).await;
            pipeline.recycle(out);
        }
    }
}

async fn send(
    out: &Outbox,
    tun: &impl PacketDevice,
    udp: &Udp,
    max_segments: usize,
    tun_tx: &mut TunTx,
) {
    for (to, bytes, segment) in out.udp_runs(max_segments) {
        if let Err(e) = udp.send_run(bytes, segment, to).await {
            tracing::debug!(%to, %e, "UDP send failed");
        }
    }
    for (dest, bytes) in out.iter() {
        if dest == Dest::Tun {
            tun_tx.push(bytes);
        }
    }
    if !tun_tx.is_empty()
        && let Err(e) = tun.send_batch(tun_tx).await
    {
        tracing::warn!(%e, "TUN write failed");
    }
}

/// Batches between being read and being finished, numbered in read order.
struct Pipeline {
    workers: Option<rayon_core::ThreadPool>,
    max_in_flight: usize,
    done_tx: mpsc::UnboundedSender<(u64, Outbox)>,
    done: mpsc::UnboundedReceiver<(u64, Outbox)>,
    next_seq: u64,
    next_finish: u64,
    /// Crypto finished, waiting for every batch before them.
    ready: BTreeMap<u64, Outbox>,
    spare: Vec<Outbox>,
}

impl Pipeline {
    fn new(threads: usize) -> io::Result<Self> {
        let workers = (threads > 1)
            .then(|| {
                rayon_core::ThreadPoolBuilder::new()
                    .num_threads(threads - 1)
                    .thread_name(|i| format!("vpnd-crypto-{i}"))
                    .build()
                    .map_err(io::Error::other)
            })
            .transpose()?;
        let (done_tx, done) = mpsc::unbounded_channel();
        Ok(Self {
            // Enough that every worker has the next batch queued.
            max_in_flight: 2 * threads.max(1),
            workers,
            done_tx,
            done,
            next_seq: 0,
            next_finish: 0,
            ready: BTreeMap::new(),
            spare: Vec::new(),
        })
    }

    fn in_flight(&self) -> usize {
        (self.next_seq - self.next_finish) as usize
    }

    fn has_room(&self) -> bool {
        self.in_flight() < self.max_in_flight
    }

    fn outbox(&mut self) -> Outbox {
        self.spare.pop().unwrap_or_default()
    }

    fn submit(&mut self, mut out: Outbox) {
        let seq = self.next_seq;
        self.next_seq += 1;
        match &self.workers {
            // Raising the bar (offload only 16 KB and up) cut Linux from 10.3
            // to 7.7 Gbit/s: plenty of batches under load are smaller.
            Some(pool) if self.in_flight() > 1 || out.crypto_bytes() >= INLINE_BYTES => {
                let done = self.done_tx.clone();
                pool.spawn(move || {
                    out.run_crypto();
                    // Fails only once the loop has exited.
                    let _ = done.send((seq, out));
                });
            }
            _ => {
                out.run_crypto();
                self.ready.insert(seq, out);
            }
        }
    }

    fn crypto_done(&mut self, seq: u64, out: Outbox) {
        self.ready.insert(seq, out);
    }

    fn next_ready(&mut self) -> Option<Outbox> {
        let out = self.ready.remove(&self.next_finish)?;
        self.next_finish += 1;
        Some(out)
    }

    fn recycle(&mut self, mut out: Outbox) {
        out.clear();
        self.spare.push(out);
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::sync::{Mutex, mpsc, oneshot};
    use vpn_proto::device::PeerConfig;
    use vpn_proto::keys::KeyPair;

    use super::*;

    struct ChannelTun {
        from_kernel: Mutex<mpsc::Receiver<Vec<u8>>>,
        to_kernel: mpsc::Sender<Vec<u8>>,
    }

    impl PacketDevice for ChannelTun {
        async fn recv_batch(&self, rx: &mut TunRx) -> io::Result<()> {
            let p = self.from_kernel.lock().await.recv().await;
            let p = p.ok_or_else(|| io::Error::other("closed"))?;
            rx.set(&p);
            Ok(())
        }

        async fn send_batch(&self, tx: &mut TunTx) -> io::Result<()> {
            for packet in tx.packets() {
                self.to_kernel
                    .send(packet.to_vec())
                    .await
                    .map_err(|_| io::Error::other("closed"))?;
            }
            tx.clear();
            Ok(())
        }
    }

    /// One side of the tunnel: inject packets as the kernel would, and read
    /// what the loop writes back.
    struct Side {
        inject: mpsc::Sender<Vec<u8>>,
        delivered: mpsc::Receiver<Vec<u8>>,
        stop: oneshot::Sender<()>,
        task: tokio::task::JoinHandle<io::Result<()>>,
    }

    fn spawn(device: Device, udp: Udp, threads: usize) -> Side {
        let (inject, from_kernel) = mpsc::channel(16);
        let (to_kernel, delivered) = mpsc::channel(16);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let tun = ChannelTun {
                from_kernel: Mutex::new(from_kernel),
                to_kernel,
            };
            run(device, &tun, &udp, 1420, threads, None, |_| {}, async {
                let _ = stopped.await;
            })
            .await
        });
        Side {
            inject,
            delivered,
            stop,
            task,
        }
    }

    fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 48];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&48u16.to_be_bytes());
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..].fill(0xab);
        p
    }

    async fn next(side: &mut Side) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(5), side.delivered.recv())
            .await
            .expect("packet should arrive within 5s")
            .expect("loop still running")
    }

    /// A knows B's endpoint; B learns A's from the handshake.
    fn pair(threads: usize) -> (Side, Side) {
        let (ka, kb) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
        let udp_a = Udp::bind(0, None).unwrap();
        let udp_b = Udp::bind(0, None).unwrap();
        let b_port = udp_b.local_addr().unwrap().port();

        let mut a = Device::new(ka.private, 1420);
        a.add_peer(PeerConfig {
            public_key: kb.public,
            endpoint: Some(SocketAddr::from(([127, 0, 0, 1], b_port))),
            allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
            persistent_keepalive: None,
        });
        let mut b = Device::new(kb.private, 1420);
        b.add_peer(PeerConfig {
            public_key: ka.public,
            endpoint: None,
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            persistent_keepalive: None,
        });

        (spawn(a, udp_a, threads), spawn(b, udp_b, threads))
    }

    async fn stop(sides: [Side; 2]) {
        for side in sides {
            side.stop.send(()).unwrap();
            side.task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn forwards_both_directions_over_real_udp() {
        for threads in [1, 3] {
            let (mut a, mut b) = pair(threads);
            let ping = ipv4([10, 0, 0, 1], [10, 0, 0, 2]);
            a.inject.send(ping.clone()).await.unwrap();
            assert_eq!(next(&mut b).await, ping);

            let pong = ipv4([10, 0, 0, 2], [10, 0, 0, 1]);
            b.inject.send(pong.clone()).await.unwrap();
            assert_eq!(next(&mut a).await, pong);
            stop([a, b]).await;
        }
    }

    /// Workers finish batches in any order; the far side still gets every
    /// packet in the order it was sent.
    #[tokio::test]
    async fn worker_pipeline_keeps_order() {
        let (a, mut b) = pair(3);
        let first = ipv4([10, 0, 0, 1], [10, 0, 0, 2]);
        a.inject.send(first.clone()).await.unwrap();
        assert_eq!(next(&mut b).await, first);

        let packets: Vec<_> = (0..500u16)
            .map(|i| {
                let mut p = ipv4([10, 0, 0, 1], [10, 0, 0, 2]);
                p[20..22].copy_from_slice(&i.to_be_bytes());
                p
            })
            .collect();
        let inject = a.inject.clone();
        let sending = tokio::spawn({
            let packets = packets.clone();
            async move {
                for p in packets {
                    inject.send(p).await.unwrap();
                }
            }
        });
        for p in &packets {
            assert_eq!(&next(&mut b).await, p);
        }
        sending.await.unwrap();
        stop([a, b]).await;
    }
}
