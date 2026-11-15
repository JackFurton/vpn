//! Moves bytes between the TUN device, the UDP socket and `Device`. All
//! protocol decisions live in `Device`; this only does IO.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::watch;
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

/// Runs until `shutdown` resolves or the TUN device fails. `on_endpoints`
/// gets every peer endpoint whenever one moves.
pub async fn run(
    mut device: Device,
    tun: &impl PacketDevice,
    udp: &Udp,
    mtu: usize,
    metrics: Option<watch::Sender<String>>,
    mut on_endpoints: impl FnMut(Vec<IpAddr>),
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let mut last_publish: Option<Instant> = None;
    let mut tun_rx = TunRx::new(mtu);
    let mut tun_tx = TunTx::default();
    let mut udp_rx = UdpRx::default();
    let max_segments = udp.max_segments(Session::encrypted_len(mtu, mtu));
    let mut out = Outbox::new();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    tokio::pin!(shutdown);

    loop {
        // Every branch is cancel-safe: losing the race drops a future that
        // hasn't consumed anything yet.
        tokio::select! {
            r = tun.recv_batch(&mut tun_rx) => {
                r?;
                let now = Instant::now();
                for packet in tun_rx.packets() {
                    device.handle_tun(packet, now, &mut out);
                }
            }
            r = udp.recv_batch(&mut udp_rx) => match r {
                Ok(()) => {
                    let now = Instant::now();
                    for (from, datagram) in udp_rx.datagrams() {
                        device.handle_udp(datagram, from, now, &mut out);
                    }
                }
                // Some platforms surface ICMP errors from earlier sends here.
                // They say nothing about this socket's health.
                Err(e) => tracing::debug!(%e, "UDP receive error"),
            },
            _ = ticker.tick() => {
                let now = Instant::now();
                device.tick(now, &mut out);
                if let Some(tx) = &metrics
                    && last_publish.is_none_or(|t| now - t >= METRICS_EVERY)
                {
                    tx.send_replace(crate::metrics::render(&device.stats(now)));
                    last_publish = Some(now);
                }
            }
            () = &mut shutdown => return Ok(()),
        }

        // Before sending: a reply to a peer's new address needs its route
        // in place (macOS full tunnel), or it loops into the tunnel.
        if device.take_endpoints_changed() {
            on_endpoints(device.endpoints().map(|e| e.ip()).collect());
        }

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
            && let Err(e) = tun.send_batch(&mut tun_tx).await
        {
            tracing::warn!(%e, "TUN write failed");
        }
        out.clear();
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

    fn spawn(device: Device, udp: Udp) -> Side {
        let (inject, from_kernel) = mpsc::channel(16);
        let (to_kernel, delivered) = mpsc::channel(16);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let tun = ChannelTun {
                from_kernel: Mutex::new(from_kernel),
                to_kernel,
            };
            run(device, &tun, &udp, 1420, None, |_| {}, async {
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

    #[tokio::test]
    async fn forwards_both_directions_over_real_udp() {
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

        let mut a = spawn(a, udp_a);
        let mut b = spawn(b, udp_b);

        let ping = ipv4([10, 0, 0, 1], [10, 0, 0, 2]);
        a.inject.send(ping.clone()).await.unwrap();
        assert_eq!(next(&mut b).await, ping);

        let pong = ipv4([10, 0, 0, 2], [10, 0, 0, 1]);
        b.inject.send(pong.clone()).await.unwrap();
        assert_eq!(next(&mut a).await, pong);

        for side in [a, b] {
            side.stop.send(()).unwrap();
            side.task.await.unwrap().unwrap();
        }
    }
}
