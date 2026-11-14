//! `vpnd up`: config in, running tunnel out.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use vpn_proto::device::{Device, PeerConfig};

use crate::config::Config;
use crate::event_loop;
use crate::tun::Tun;

pub async fn up(
    config: Config,
    interface: Option<&str>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let iface = &config.interface;
    let mtu = usize::from(iface.mtu);

    let mut device = Device::new(iface.private_key.clone(), mtu);
    for p in &config.peers {
        device.add_peer(PeerConfig {
            public_key: p.public_key.clone(),
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips.clone(),
            persistent_keepalive: p
                .persistent_keepalive
                .map(|s| Duration::from_secs(s.into())),
        });
    }

    // IPv4 only for now: a dual-stack socket needs v4-mapped endpoint
    // handling, and the IPV6_V6ONLY default differs between Linux and macOS.
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, iface.listen_port.unwrap_or(0)));
    let udp = UdpSocket::bind(bind)
        .await
        .with_context(|| format!("binding UDP {bind}"))?;
    let tun = Tun::create(interface, &iface.addresses, iface.mtu)
        .context("creating TUN device (needs root or CAP_NET_ADMIN)")?;

    tracing::info!(
        interface = tun.name(),
        listen = %udp.local_addr()?,
        public_key = %iface.private_key.public_key().to_base64(),
        peers = config.peers.len(),
        "tunnel up"
    );
    event_loop::run(device, &tun, &udp, mtu, shutdown).await?;
    // Dropping the TUN fd removes the interface and its routes.
    tracing::info!(interface = tun.name(), "tunnel down");
    Ok(())
}

/// Resolves on SIGINT, or SIGTERM where it exists (systemd and docker stop
/// send SIGTERM).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
