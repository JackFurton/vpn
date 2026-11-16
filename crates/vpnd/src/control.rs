//! The socket `vpnd reload` hands a new config to. systemd gives the daemon
//! a copy of its config that `systemctl reload` doesn't refresh, and the
//! dropped-privilege daemon can't read /etc/vpnd itself, so the new config
//! has to come from a root process rather than a re-read.
//!
//! One request per connection: the client writes `reload`, a newline and
//! the config, then shuts down its write half. The daemon answers `ok` or
//! `error` on the first line, then any notes, one per line.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::routes::Plan;

/// Bigger than any real config, small enough that a client can't make the
/// daemon buffer much.
const MAX_REQUEST: u64 = 1 << 20;
/// A client that connects and stalls only holds up other reloads, but
/// shouldn't do that for long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub fn default_path(interface: &str) -> PathBuf {
    let run = if cfg!(target_os = "macos") {
        "/var/run"
    } else {
        "/run"
    };
    Path::new(run)
        .join("vpnd")
        .join(format!("{interface}.sock"))
}

pub struct Listener {
    inner: UnixListener,
    /// Who owned the socket when it was made. Read now, because after
    /// dropping privilege vpnd may not be able to look at it.
    owner: u32,
}

/// Binds `path`, owner-only. Call while still privileged: once vpnd drops
/// to its own user, the socket stays owned by root, so only root can
/// connect. A socket left by a vpnd that's gone is replaced; one that still
/// answers is an error, since two daemons can't share it.
pub fn bind(path: &Path) -> Result<Listener> {
    if let Some(dir) = path.parent()
        && !dir.exists()
    {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        bail!("another vpnd is listening on {}", path.display());
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("removing stale {}", path.display()));
        }
        _ => {}
    }
    let inner = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let owner = std::fs::metadata(path)?.uid();
    Ok(Listener { inner, owner })
}

/// Answers requests one at a time. `reload` gets each new config and
/// returns the lines to send back, or the reason it refused.
pub async fn serve<F>(listener: Listener, mut reload: impl FnMut(Config) -> F)
where
    F: Future<Output = Result<Vec<String>, String>>,
{
    loop {
        let mut stream = match listener.inner.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(%e, "control socket accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let request = tokio::time::timeout(REQUEST_TIMEOUT, read(&mut stream, listener.owner))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out reading the request")));
        let answer = match request {
            Ok(text) => match parse(&text) {
                Ok(config) => reload(config).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(format!("{e:#}")),
        };
        let text = match answer {
            Ok(notes) => std::iter::once("ok".to_string())
                .chain(notes)
                .collect::<Vec<_>>(),
            Err(why) => {
                tracing::warn!("control request refused: {why}");
                vec!["error".to_string(), why]
            }
        };
        let _ = stream.write_all((text.join("\n") + "\n").as_bytes()).await;
    }
}

async fn read(stream: &mut UnixStream, owner: u32) -> Result<Zeroizing<String>> {
    // The socket file's permissions already keep others out. This is in
    // case they're ever looser than intended.
    let uid = stream.peer_cred()?.uid();
    if uid != 0 && uid != owner {
        bail!("uid {uid} may not control vpnd");
    }
    let mut buf = Zeroizing::new(Vec::new());
    stream.take(MAX_REQUEST).read_to_end(&mut buf).await?;
    let text = String::from_utf8(std::mem::take(&mut *buf)).context("request isn't UTF-8")?;
    Ok(Zeroizing::new(text))
}

fn parse(text: &str) -> Result<Config, String> {
    let Some(("reload", config)) = text.split_once('\n') else {
        return Err("unknown request".into());
    };
    Config::parse(config).map_err(|e| e.to_string())
}

/// Sends `config` (the file's text) to the daemon at `path` and returns its
/// notes, or what it refused with.
pub async fn reload(path: &Path, config: &str) -> Result<Vec<String>> {
    let mut stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connecting to {}", path.display()))?;
    let request = Zeroizing::new(format!("reload\n{config}"));
    stream.write_all(request.as_bytes()).await?;
    stream.shutdown().await?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await?;
    let mut lines = reply.lines().map(str::to_string);
    match lines.next().as_deref() {
        Some("ok") => Ok(lines.collect()),
        Some("error") => bail!("{}", lines.collect::<Vec<_>>().join("\n")),
        _ => bail!("no answer from vpnd at {}", path.display()),
    }
}

/// What applying `new` over `running` can't do live, as notes for the
/// operator. Peers always apply. Refuses a different private key, which is
/// more likely the wrong file than a key rotation.
pub fn check(running: &Config, installed: &Plan, new: &Config) -> Result<Vec<String>, String> {
    let (old, i) = (&running.interface, &new.interface);
    if old.private_key.public_key() != i.private_key.public_key() {
        return Err("private_key differs from the running one; restart to change it".into());
    }
    let mut notes = Vec::new();
    let mut changed = |field: &str, differs: bool| {
        if differs {
            notes.push(format!("{field} changed; restart to apply"));
        }
    };
    changed("listen_port", old.listen_port != i.listen_port);
    changed("addresses", old.addresses != i.addresses);
    changed("mtu", old.mtu != i.mtu);
    changed("metrics", old.metrics != i.metrics);
    changed("dns", old.dns != i.dns);

    let plan = crate::routes::plan(new);
    if (plan.default_v4, plan.default_v6) != (installed.default_v4, installed.default_v6) {
        notes.push("default route changed; restart to apply".into());
    }
    for net in plan.routes.iter().filter(|n| !installed.routes.contains(n)) {
        notes.push(format!("{net} has no route into the tunnel until restart"));
    }
    for net in installed.routes.iter().filter(|n| !plan.routes.contains(n)) {
        notes.push(format!(
            "{net} keeps its route into the tunnel until restart"
        ));
    }
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_proto::keys::KeyPair;

    fn config(private: &str, extra: &str) -> Config {
        Config::parse(&format!(
            "[interface]\nprivate_key = \"{private}\"\naddresses = [\"10.9.0.1/24\"]\n{extra}"
        ))
        .unwrap()
    }

    fn peer(allowed: &str) -> String {
        let public = KeyPair::generate().unwrap().public.to_base64();
        format!("[[peer]]\npublic_key = \"{public}\"\nallowed_ips = [\"{allowed}\"]\n")
    }

    #[test]
    fn peers_inside_the_subnet_reload_cleanly() {
        let key = KeyPair::generate().unwrap().private.to_base64();
        let running = config(&key, &peer("10.9.0.2/32"));
        let installed = crate::routes::plan(&running);
        let new = config(&key, &(peer("10.9.0.2/32") + &peer("10.9.0.3/32")));
        assert_eq!(check(&running, &installed, &new), Ok(vec![]));
    }

    #[test]
    fn notes_what_needs_a_restart() {
        let key = KeyPair::generate().unwrap().private.to_base64();
        let running = config(&key, &peer("10.50.0.0/16"));
        let installed = crate::routes::plan(&running);
        let new = config(&key, &format!("mtu = 1380\n{}", peer("10.60.0.0/16")));
        assert_eq!(
            check(&running, &installed, &new),
            Ok(vec![
                "mtu changed; restart to apply".to_string(),
                "10.60.0.0/16 has no route into the tunnel until restart".to_string(),
                "10.50.0.0/16 keeps its route into the tunnel until restart".to_string(),
            ])
        );
    }

    #[test]
    fn refuses_another_private_key() {
        let running = config(&KeyPair::generate().unwrap().private.to_base64(), "");
        let installed = crate::routes::plan(&running);
        let new = config(&KeyPair::generate().unwrap().private.to_base64(), "");
        assert!(check(&running, &installed, &new).is_err());
    }

    #[tokio::test]
    async fn round_trip_over_the_socket() {
        let dir = std::env::temp_dir().join(format!("vpnd-control-{}", std::process::id()));
        let path = dir.join("test.sock");
        let listener = bind(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(bind(&path).is_err(), "a live socket isn't replaced");

        let server = tokio::spawn(serve(listener, |c: Config| async move {
            Ok(vec![format!("{} peers", c.peers.len())])
        }));
        let key = KeyPair::generate().unwrap().private.to_base64();
        let text = format!(
            "[interface]\nprivate_key = \"{key}\"\naddresses = [\"10.9.0.1/24\"]\n{}",
            peer("10.9.0.2/32")
        );
        assert_eq!(reload(&path, &text).await.unwrap(), ["1 peers"]);
        let bad = reload(&path, "[interface]\n").await.unwrap_err();
        assert!(bad.to_string().contains("private_key"), "{bad}");

        server.abort();
        let _ = server.await;
        bind(&path).expect("a dead socket is replaced");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// After dropping privilege vpnd may be locked out of the socket's
    /// directory (in Docker it made it 0700 as root), and must still answer.
    #[tokio::test]
    async fn answers_without_access_to_the_socket_directory() {
        let dir = std::env::temp_dir().join(format!("vpnd-locked-{}", std::process::id()));
        let path = dir.join("test.sock");
        let listener = bind(&path).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let server = tokio::spawn(serve(listener, |_: Config| async { Ok(vec![]) }));
        client.set_nonblocking(true).unwrap();
        let mut client = UnixStream::from_std(client).unwrap();
        let key = KeyPair::generate().unwrap().private.to_base64();
        let request = format!(
            "reload\n[interface]\nprivate_key = \"{key}\"\naddresses = [\"10.9.0.1/24\"]\n"
        );
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = String::new();
        let read = client.read_to_string(&mut reply).await;

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        server.abort();
        std::fs::remove_dir_all(&dir).unwrap();
        read.unwrap();
        assert_eq!(reply, "ok\n");
    }
}
