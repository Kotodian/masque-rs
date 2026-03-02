use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use masque::config::{self, ServerConfig};
use masque::server::Server;

/// MASQUE proxy server (CONNECT-UDP / CONNECT-IP over HTTP/3).
#[derive(Parser)]
#[command(name = "masque-server")]
struct Cli {
    /// Config file path.
    #[arg(short, long, default_value = "masque.toml")]
    config: PathBuf,

    /// Override listen address.
    #[arg(short, long)]
    listen: Option<String>,

    /// TLS certificate path.
    #[arg(long)]
    cert: Option<PathBuf>,

    /// TLS private key path.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Increase log verbosity (repeatable: -v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Logging
    let default_filter = match cli.verbose {
        0 => "masque=info",
        1 => "masque=debug",
        _ => "masque=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .init();

    // Load config
    let mut cfg = if cli.config.exists() {
        let toml_str = std::fs::read_to_string(&cli.config)?;
        config::parse_toml(&toml_str)?
    } else {
        info!(path = %cli.config.display(), "config file not found, using defaults");
        ServerConfig::default()
    };

    // CLI overrides
    if let Some(listen) = cli.listen {
        cfg.server.listen_addr = listen.parse()?;
    }
    if let Some(cert) = cli.cert {
        cfg.tls.cert_path = cert;
    }
    if let Some(key) = cli.key {
        cfg.tls.key_path = key;
    }

    info!(?cfg, "configuration loaded");

    let mut server = Server::bind(cfg).await?;
    server.run().await
}
