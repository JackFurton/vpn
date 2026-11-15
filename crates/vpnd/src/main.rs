use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use vpn_proto::ip::IpHeader;

use vpn_proto::keys::{KeyPair, PrivateKey};
use vpnd::config::{Config, DEFAULT_MTU};
use vpnd::daemon;
use vpnd::tun::Tun;

#[derive(Parser)]
#[command(version, about = "VPN daemon")]
struct Cli {
    /// Log as plain text or one JSON object per line
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new static keypair
    Keygen,
    /// Read a private key on stdin and print its public key
    Pubkey,
    /// Bring the tunnel up and run until SIGINT or SIGTERM
    Up {
        #[arg(short, long)]
        config: PathBuf,
        /// Interface name. Defaults to the OS's choice (tun0, utun3, ...).
        #[arg(short, long)]
        interface: Option<String>,
        /// Switch to this user (name or uid) once the tunnel is up. Needs
        /// vpnd started as root. Linux only.
        #[arg(short, long)]
        user: Option<String>,
    },
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

// One thread: the event loop is the only busy task. On a multi-thread
// runtime a worker polls kqueue and wakes the loop's thread through a condvar
// for every batch, which cost macOS about a fifth of vpnd's CPU per packet.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let logs = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr);
    match cli.log_format {
        LogFormat::Text => logs.with_ansi(std::io::stderr().is_terminal()).init(),
        LogFormat::Json => logs.json().init(),
    }

    match cli.command {
        Command::Keygen => {
            let kp = KeyPair::generate()?;
            println!("private: {}", kp.private.to_base64());
            println!("public:  {}", kp.public.to_base64());
        }
        Command::Pubkey => {
            let mut line = zeroize::Zeroizing::new(String::new());
            std::io::stdin().read_line(&mut line)?;
            let private: PrivateKey = line.parse().context("parsing private key")?;
            println!("{}", private.public_key().to_base64());
        }
        Command::Up {
            config,
            interface,
            user,
        } => {
            let config = Config::load(&config)?;
            daemon::up(
                config,
                interface.as_deref(),
                user.as_deref(),
                daemon::shutdown_signal(),
            )
            .await?;
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
    let mut rx = vpnd::tun::TunRx::new(usize::from(mtu));
    loop {
        tokio::select! {
            r = tun.recv_batch(&mut rx) => {
                r?;
                for packet in rx.packets() {
                    let n = packet.len();
                    match IpHeader::parse(packet) {
                        Some(h) => tracing::info!(
                            "{} {} -> {} proto {} len {n}",
                            if h.src.is_ipv4() { "IPv4" } else { "IPv6" },
                            h.src, h.dst, h.protocol
                        ),
                        None => tracing::info!("non-IP packet, len {n}"),
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}
