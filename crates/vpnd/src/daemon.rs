//! `vpnd up`: config in, running tunnel out.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result};
use vpn_proto::device::{Device, PeerConfig};

use crate::config::Config;
use crate::event_loop;
use crate::tun::Tun;
use crate::udp::Udp;

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

    let port = iface.listen_port.unwrap_or(0);
    let udp = Udp::bind(port).with_context(|| format!("binding UDP port {port}"))?;
    let tun = Tun::create(interface, &iface.addresses, iface.mtu)
        .context("creating TUN device (needs root or CAP_NET_ADMIN)")?;

    tracing::info!(
        interface = tun.name(),
        listen = %udp.local_addr()?,
        public_key = %iface.private_key.public_key().to_base64(),
        peers = config.peers.len(),
        "tunnel up"
    );
    let metrics = match iface.metrics {
        Some(addr) => {
            if !addr.ip().is_loopback() {
                tracing::warn!(%addr, "metrics are not on loopback; they expose peer keys and endpoints");
            }
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding metrics on {addr}"))?;
            let (tx, rx) = tokio::sync::watch::channel(String::new());
            tokio::spawn(crate::metrics::serve(listener, rx));
            tracing::info!(%addr, "serving metrics at /metrics");
            Some(tx)
        }
        None => None,
    };
    event_loop::run(device, &tun, &udp, mtu, metrics, shutdown).await?;
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
