//! `vpnd up`: config in, running tunnel out.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, oneshot};
use vpn_proto::device::{Device, PeerConfig};

use crate::config::{self, Config};
use crate::event_loop::{self, Command};
use crate::tun::Tun;
use crate::udp::Udp;

pub async fn up(
    config: Config,
    interface: Option<&str>,
    user: Option<&str>,
    control: Option<&Path>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let iface = &config.interface;
    let mtu = usize::from(iface.mtu);

    let mut device = Device::new(iface.private_key.clone(), mtu);
    device.set_peers(peer_configs(&config.peers));

    let port = iface.listen_port.unwrap_or(0);
    let routes = crate::routes::plan(&config);
    // Linux steers around the tunnel by socket mark; macOS uses host routes.
    let mark = (cfg!(target_os = "linux") && routes.has_default()).then_some(crate::routes::FWMARK);
    let udp = Udp::bind(port, mark).with_context(|| format!("binding UDP port {port}"))?;
    let tun = Tun::create(interface, &iface.addresses, iface.mtu)
        .context("creating TUN device (needs root or CAP_NET_ADMIN)")?;
    let control_path = control.map_or_else(
        || crate::control::default_path(tun.name()),
        Path::to_path_buf,
    );
    let listener = crate::control::bind(&control_path).context("opening the control socket")?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut installed = crate::routes::apply(&routes, tun.name())
        .await
        .context("installing routes")?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let mut installed = crate::routes::Installed::default();

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
    // Everything privileged is open; nothing after this needs privilege.
    // Tearing the interface down on exit only needs the fd closed.
    let dns = crate::dns::apply(&iface.dns, tun.name())?;
    crate::privdrop::drop_privileges(user)?;

    let (commands, command_rx) = mpsc::channel(1);
    let mut running = config;
    let reload = move |new: Config| {
        let checked = crate::control::check(&running, &routes, &new);
        let peers = peer_configs(&new.peers);
        if checked.is_ok() {
            running.peers = new.peers;
        }
        let commands = commands.clone();
        async move {
            let mut notes = checked?;
            let (reply, changes) = oneshot::channel();
            let gone = || "the tunnel is shutting down".to_string();
            commands
                .send(Command::SetPeers(peers, reply))
                .await
                .map_err(|_| gone())?;
            let c = changes.await.map_err(|_| gone())?;
            tracing::info!(
                added = c.added,
                removed = c.removed,
                kept = c.kept,
                "reloaded peers"
            );
            for note in &notes {
                tracing::warn!("reload: {note}");
            }
            notes.insert(
                0,
                format!(
                    "peers: {} added, {} removed, {} kept",
                    c.added, c.removed, c.kept
                ),
            );
            Ok(notes)
        }
    };
    tracing::info!(path = %control_path.display(), "listening for reloads");
    let control_task = tokio::spawn(crate::control::serve(listener, reload));

    let on_endpoints = |eps| installed.update_endpoints(eps);
    // Crypto workers pay off where a wakeup brings tens of packets (Linux
    // offload). Elsewhere it's a few, and handing those to another thread
    // made macOS slower, so it keeps everything on one.
    let threads = if cfg!(target_os = "linux") {
        std::thread::available_parallelism().map_or(1, usize::from)
    } else {
        1
    };
    let result = event_loop::run(
        device,
        &tun,
        &udp,
        mtu,
        threads,
        metrics,
        command_rx,
        on_endpoints,
        shutdown,
    )
    .await;
    control_task.abort();
    // Fails once vpnd has dropped to a user that can't write the socket's
    // directory. The next start replaces it.
    let _ = std::fs::remove_file(&control_path);
    installed.remove();
    dns.remove();
    result?;
    // Dropping the TUN fd removes the interface and its routes.
    tracing::info!(interface = tun.name(), "tunnel down");
    Ok(())
}

fn peer_configs(peers: &[config::Peer]) -> Vec<PeerConfig> {
    peers
        .iter()
        .map(|p| PeerConfig {
            public_key: p.public_key.clone(),
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips.clone(),
            persistent_keepalive: p
                .persistent_keepalive
                .map(|s| Duration::from_secs(s.into())),
        })
        .collect()
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
