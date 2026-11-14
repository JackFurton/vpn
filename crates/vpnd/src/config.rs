//! TOML config file. See examples/ for annotated configs.
//!
//! Parsing happens in two steps: serde reads the raw strings, then `validate`
//! turns them into typed values and checks the things serde can't, so every
//! error can name the peer it's about.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use ipnet::IpNet;
use serde::Deserialize;
use vpn_proto::keys::{KeyError, PrivateKey, PublicKey};
use zeroize::Zeroizing;

pub const DEFAULT_MTU: u16 = 1420;
/// IPv6 requires every link to carry 1280-byte packets.
pub const MIN_MTU: u16 = 1280;
pub const MAX_MTU: u16 = 9000;

#[derive(Debug)]
pub struct Config {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

#[derive(Debug)]
pub struct Interface {
    pub private_key: PrivateKey,
    /// None means pick a random port, which is fine for a client.
    pub listen_port: Option<u16>,
    pub addresses: Vec<IpNet>,
    pub mtu: u16,
}

#[derive(Debug)]
pub struct Peer {
    pub public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("interface private_key: {0}")]
    PrivateKey(KeyError),
    #[error("peer {index}: public_key: {source}")]
    PublicKey { index: usize, source: KeyError },
    #[error("interface needs at least one address")]
    NoAddress,
    #[error("listen_port 0 isn't valid, leave it out to pick a random port")]
    ZeroPort,
    #[error("mtu {0} is outside {MIN_MTU}..={MAX_MTU}")]
    Mtu(u16),
    #[error("peer {index} has our own public key")]
    SelfPeer { index: usize },
    #[error("peers {first} and {second} have the same public key")]
    DuplicatePeer { first: usize, second: usize },
    #[error("peer {index}: allowed_ips {net} has host bits set, did you mean {}?", net.trunc())]
    HostBits { index: usize, net: IpNet },
    #[error("peer {first} allowed_ips {a} overlaps peer {second} allowed_ips {b}")]
    Overlap {
        first: usize,
        a: IpNet,
        second: usize,
        b: IpNet,
    },
    #[error("peer {index}: persistent_keepalive 0 isn't valid, leave it out to disable")]
    ZeroKeepalive { index: usize },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    interface: RawInterface,
    #[serde(default, rename = "peer")]
    peers: Vec<RawPeer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterface {
    private_key: String,
    listen_port: Option<u16>,
    addresses: Vec<IpNet>,
    mtu: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    public_key: String,
    endpoint: Option<SocketAddr>,
    #[serde(default)]
    allowed_ips: Vec<IpNet>,
    persistent_keepalive: Option<u16>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if let Some(warning) = permission_warning(path) {
            tracing::warn!("{warning}");
        }
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let text = Zeroizing::new(text);
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        validate(toml::from_str(text)?)
    }
}

fn validate(raw: RawConfig) -> Result<Config, ConfigError> {
    let i = raw.interface;
    let private_key: PrivateKey = Zeroizing::new(i.private_key)
        .parse()
        .map_err(ConfigError::PrivateKey)?;
    if i.addresses.is_empty() {
        return Err(ConfigError::NoAddress);
    }
    if i.listen_port == Some(0) {
        return Err(ConfigError::ZeroPort);
    }
    let mtu = i.mtu.unwrap_or(DEFAULT_MTU);
    if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
        return Err(ConfigError::Mtu(mtu));
    }

    let own_public = private_key.public_key();
    let mut peers: Vec<Peer> = Vec::with_capacity(raw.peers.len());
    for (index, p) in raw.peers.into_iter().enumerate() {
        let public_key: PublicKey = p
            .public_key
            .parse()
            .map_err(|source| ConfigError::PublicKey { index, source })?;
        if public_key == own_public {
            return Err(ConfigError::SelfPeer { index });
        }
        if let Some(first) = peers.iter().position(|q| q.public_key == public_key) {
            return Err(ConfigError::DuplicatePeer {
                first,
                second: index,
            });
        }
        if p.persistent_keepalive == Some(0) {
            return Err(ConfigError::ZeroKeepalive { index });
        }
        if let Some(&net) = p.allowed_ips.iter().find(|n| **n != n.trunc()) {
            return Err(ConfigError::HostBits { index, net });
        }
        // Overlap would make routing depend on lookup order. Within one peer
        // it's harmless, so only compare against earlier peers.
        for (first, q) in peers.iter().enumerate() {
            for &a in &q.allowed_ips {
                if let Some(&b) = p.allowed_ips.iter().find(|b| overlaps(a, **b)) {
                    return Err(ConfigError::Overlap {
                        first,
                        a,
                        second: index,
                        b,
                    });
                }
            }
        }
        peers.push(Peer {
            public_key,
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips,
            persistent_keepalive: p.persistent_keepalive,
        });
    }

    Ok(Config {
        interface: Interface {
            private_key,
            listen_port: i.listen_port,
            addresses: i.addresses,
            mtu,
        },
        peers,
    })
}

fn overlaps(a: IpNet, b: IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(unix)]
fn permission_warning(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o077 != 0).then(|| {
        format!(
            "{} holds a private key but is accessible to group or others (mode {:o}), run chmod 600",
            path.display(),
            mode & 0o777
        )
    })
}

#[cfg(not(unix))]
fn permission_warning(_: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use vpn_proto::keys::KeyPair;

    use super::*;

    fn key() -> KeyPair {
        KeyPair::generate().unwrap()
    }

    fn config(peers: &str) -> String {
        format!(
            "[interface]\nprivate_key = \"{}\"\naddresses = [\"10.8.0.1/24\"]\n{peers}",
            key().private.to_base64()
        )
    }

    fn peer(allowed: &str) -> String {
        format!(
            "[[peer]]\npublic_key = \"{}\"\nallowed_ips = [{allowed}]\n",
            key().public.to_base64()
        )
    }

    fn err(text: &str) -> String {
        Config::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn parses_full_config() {
        let pk = key().public;
        let text = config(&format!(
            "listen_port = 51820\nmtu = 1400\n\n[[peer]]\npublic_key = \"{}\"\nendpoint = \"203.0.113.5:51820\"\nallowed_ips = [\"10.8.0.2/32\", \"fd00::/64\"]\npersistent_keepalive = 25\n",
            pk.to_base64()
        ));
        // listen_port and mtu above land in [interface] since no table follows yet.
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.interface.listen_port, Some(51820));
        assert_eq!(c.interface.mtu, 1400);
        assert_eq!(c.peers.len(), 1);
        let p = &c.peers[0];
        assert_eq!(p.public_key, pk);
        assert_eq!(p.endpoint, Some("203.0.113.5:51820".parse().unwrap()));
        assert_eq!(p.allowed_ips.len(), 2);
        assert_eq!(p.persistent_keepalive, Some(25));
    }

    #[test]
    fn defaults() {
        let c = Config::parse(&config("")).unwrap();
        assert_eq!(c.interface.mtu, DEFAULT_MTU);
        assert_eq!(c.interface.listen_port, None);
        assert!(c.peers.is_empty());
    }

    #[test]
    fn rejects_bad_keys() {
        let text = "[interface]\nprivate_key = \"nope\"\naddresses = [\"10.8.0.1/24\"]\n";
        assert!(err(text).starts_with("interface private_key"));
        let text = config("[[peer]]\npublic_key = \"AAAA\"\n");
        assert!(
            err(&text).starts_with("peer 0: public_key"),
            "{}",
            err(&text)
        );
    }

    #[test]
    fn rejects_typos_and_bad_values() {
        assert!(err(&config("mtuu = 1400\n")).contains("unknown field"));
        assert!(err(&config("mtu = 1000\n")).contains("mtu 1000"));
        assert!(err(&config("listen_port = 0\n")).contains("listen_port 0"));
        let no_addr = format!(
            "[interface]\nprivate_key = \"{}\"\naddresses = []\n",
            key().private.to_base64()
        );
        assert_eq!(err(&no_addr), "interface needs at least one address");
    }

    #[test]
    fn rejects_self_and_duplicate_peers() {
        let kp = key();
        let own = format!(
            "[interface]\nprivate_key = \"{}\"\naddresses = [\"10.8.0.1/24\"]\n[[peer]]\npublic_key = \"{}\"\n",
            kp.private.to_base64(),
            kp.public.to_base64()
        );
        assert_eq!(err(&own), "peer 0 has our own public key");

        let p = peer("");
        assert_eq!(
            err(&config(&format!("{p}{p}"))),
            "peers 0 and 1 have the same public key"
        );
    }

    #[test]
    fn rejects_host_bits_with_suggestion() {
        assert_eq!(
            err(&config(&peer("\"10.8.0.5/24\""))),
            "peer 0: allowed_ips 10.8.0.5/24 has host bits set, did you mean 10.8.0.0/24?"
        );
    }

    #[test]
    fn overlap_across_peers_only() {
        let same_peer = peer("\"10.0.0.0/8\", \"10.1.0.0/16\"");
        assert!(Config::parse(&config(&same_peer)).is_ok());

        let text = config(&format!(
            "{}{}",
            peer("\"10.0.0.0/8\""),
            peer("\"192.168.0.0/16\", \"10.1.0.0/16\"")
        ));
        assert_eq!(
            err(&text),
            "peer 0 allowed_ips 10.0.0.0/8 overlaps peer 1 allowed_ips 10.1.0.0/16"
        );

        let v4_and_v6 = config(&format!("{}{}", peer("\"0.0.0.0/0\""), peer("\"::/0\"")));
        assert!(Config::parse(&v4_and_v6).is_ok());
    }

    #[test]
    fn examples_parse() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        for name in ["server.toml", "client.toml"] {
            let text = fs::read_to_string(dir.join(name)).unwrap();
            let filled = text
                .replace("<PRIVATE_KEY>", &key().private.to_base64())
                .replace("<PEER_PUBLIC_KEY>", &key().public.to_base64())
                .replace("<PEER2_PUBLIC_KEY>", &key().public.to_base64());
            Config::parse(&filled).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn warns_on_readable_config() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("vpnd-perm-{}.toml", std::process::id()));
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(permission_warning(&path).unwrap().contains("mode 644"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(permission_warning(&path).is_none());
        fs::remove_file(&path).unwrap();
    }
}
