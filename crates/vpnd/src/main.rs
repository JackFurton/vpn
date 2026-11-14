use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use tracing_subscriber::EnvFilter;
use vpn_proto::ip::IpHeader;
use vpn_proto::keys::KeyPair;
use vpnd::config::DEFAULT_MTU;
use vpnd::tun::Tun;

#[derive(Parser)]
#[command(version, about = "VPN daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new static keypair
    Keygen,
    /// Create a TUN device and log every packet the kernel routes into it
    #[command(hide = true)]
    TunDump {
        /// Interface address with prefix, e.g. 10.9.0.1/24. Repeatable.
        #[arg(long = "address", required = true)]
        addresses: Vec<IpNet>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = DEFAULT_MTU)]
        mtu: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Keygen => {
            let kp = KeyPair::generate()?;
            println!("private: {}", kp.private.to_base64());
            println!("public:  {}", kp.public.to_base64());
        }
        Command::TunDump {
            addresses,
            name,
            mtu,
        } => tun_dump(&addresses, name.as_deref(), mtu).await?,
    }
    Ok(())
}

async fn tun_dump(addresses: &[IpNet], name: Option<&str>, mtu: u16) -> Result<()> {
    let tun = Tun::create(name, addresses, mtu).context("creating TUN device (needs root)")?;
    tracing::info!(interface = tun.name(), ?addresses, mtu, "TUN device up");
    let mut buf = vec![0; usize::from(mtu)];
    loop {
        tokio::select! {
            n = tun.recv(&mut buf) => {
                let n = n?;
                match IpHeader::parse(&buf[..n]) {
                    Some(h) => tracing::info!(
                        "{} {} -> {} proto {} len {n}",
                        if h.src.is_ipv4() { "IPv4" } else { "IPv6" },
                        h.src, h.dst, h.protocol
                    ),
                    None => tracing::info!("non-IP packet, len {n}"),
                }
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}
