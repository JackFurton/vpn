use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use vpn_proto::keys::KeyPair;

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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Keygen => {
            let kp = KeyPair::generate()?;
            println!("private: {}", kp.private.to_base64());
            println!("public:  {}", kp.public.to_base64());
        }
    }
    Ok(())
}
