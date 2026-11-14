//! Prometheus text exposition of `Device::stats`, served over a deliberately
//! tiny HTTP responder. Scrapes are rare and local, so connections are
//! handled one at a time with a short timeout rather than pulling in an HTTP
//! stack.

use std::fmt::Write;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use vpn_proto::device::{PeerCounters, Stats};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

type CounterDef = (&'static str, &'static str, fn(&PeerCounters) -> u64);

pub fn render(stats: &Stats) -> String {
    let mut out = String::new();
    let peer_counters: [CounterDef; 5] = [
        (
            "vpn_peer_rx_bytes_total",
            "Transport bytes received from the peer (UDP payload).",
            |c| c.rx_bytes,
        ),
        (
            "vpn_peer_tx_bytes_total",
            "Transport bytes sent to the peer (UDP payload).",
            |c| c.tx_bytes,
        ),
        (
            "vpn_peer_rx_packets_total",
            "Transport packets received from the peer, keepalives included.",
            |c| c.rx_packets,
        ),
        (
            "vpn_peer_tx_packets_total",
            "Transport packets sent to the peer, keepalives included.",
            |c| c.tx_packets,
        ),
        (
            "vpn_peer_handshakes_total",
            "Completed handshakes with the peer.",
            |c| c.handshakes,
        ),
    ];
    for (name, help, get) in peer_counters {
        header(&mut out, name, help, "counter");
        for p in &stats.peers {
            let _ = writeln!(
                out,
                "{name}{{peer=\"{}\"}} {}",
                p.public_key.to_base64(),
                get(&p.counters)
            );
        }
    }

    header(
        &mut out,
        "vpn_peer_session_up",
        "1 if there is a usable session with the peer.",
        "gauge",
    );
    for p in &stats.peers {
        let _ = writeln!(
            out,
            "vpn_peer_session_up{{peer=\"{}\"}} {}",
            p.public_key.to_base64(),
            u8::from(p.has_session)
        );
    }
    header(
        &mut out,
        "vpn_peer_last_handshake_age_seconds",
        "Seconds since the last completed handshake.",
        "gauge",
    );
    for p in &stats.peers {
        if let Some(age) = p.since_handshake {
            let _ = writeln!(
                out,
                "vpn_peer_last_handshake_age_seconds{{peer=\"{}\"}} {:.3}",
                p.public_key.to_base64(),
                age.as_secs_f64()
            );
        }
    }

    header(
        &mut out,
        "vpn_dropped_total",
        "Packets and messages discarded, by reason.",
        "counter",
    );
    for (reason, n) in &stats.drops {
        let _ = writeln!(
            out,
            "vpn_dropped_total{{reason=\"{}\"}} {n}",
            reason.as_str()
        );
    }
    header(
        &mut out,
        "vpn_cookie_replies_sent_total",
        "Cookie replies sent while under load.",
        "counter",
    );
    let _ = writeln!(
        out,
        "vpn_cookie_replies_sent_total {}",
        stats.cookie_replies_sent
    );
    header(
        &mut out,
        "vpn_under_load",
        "1 while demanding cookies on handshakes.",
        "gauge",
    );
    let _ = writeln!(out, "vpn_under_load {}", u8::from(stats.under_load));
    out
}

fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

pub async fn serve(listener: TcpListener, latest: watch::Receiver<String>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        if tokio::time::timeout(REQUEST_TIMEOUT, respond(stream, &latest))
            .await
            .is_err()
        {
            tracing::debug!("metrics request timed out");
        }
    }
}

async fn respond(mut stream: TcpStream, latest: &watch::Receiver<String>) -> io::Result<()> {
    let mut buf = [0u8; 2048];
    let mut n = 0;
    while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") && n < buf.len() {
        match stream.read(&mut buf[n..]).await? {
            0 => return Ok(()),
            m => n += m,
        }
    }
    let (status, body) = if buf[..n].starts_with(b"GET /metrics ") {
        ("200 OK", latest.borrow().clone())
    } else {
        ("404 Not Found", "not found\n".to_owned())
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use vpn_proto::device::{Device, PeerConfig};
    use vpn_proto::keys::KeyPair;

    use super::*;

    fn stats() -> (Stats, String) {
        let peer = KeyPair::generate().unwrap().public;
        let mut d = Device::new(KeyPair::generate().unwrap().private, 1420);
        d.add_peer(PeerConfig {
            public_key: peer.clone(),
            endpoint: None,
            allowed_ips: vec![],
            persistent_keepalive: None,
        });
        (d.stats(Instant::now()), peer.to_base64())
    }

    #[test]
    fn renders_exposition_format() {
        let (s, peer) = stats();
        let text = render(&s);
        assert!(text.contains(&format!("vpn_peer_rx_bytes_total{{peer=\"{peer}\"}} 0\n")));
        assert!(text.contains("vpn_dropped_total{reason=\"replay\"} 0\n"));
        assert!(text.contains("# TYPE vpn_under_load gauge\n"));
        assert!(
            !text.contains("last_handshake_age_seconds{"),
            "no sample before any handshake"
        );
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (_, value) = line.rsplit_once(' ').unwrap();
            value
                .parse::<f64>()
                .unwrap_or_else(|_| panic!("bad sample: {line}"));
        }
    }

    #[tokio::test]
    async fn serves_metrics_and_404s_everything_else() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(String::new());
        tx.send("vpn_under_load 0\n".into()).unwrap();
        tokio::spawn(serve(listener, rx));

        for (path, want) in [("/metrics", "200 OK"), ("/", "404 Not Found")] {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).await.unwrap();
            assert!(resp.starts_with(&format!("HTTP/1.1 {want}")), "{resp}");
            if want == "200 OK" {
                assert!(resp.ends_with("vpn_under_load 0\n"));
            }
        }
    }
}
