use anyhow::Result;
use clap::Parser;
use rama_elite_proxy::{config::Config, server::Server};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    #[arg(short, long)]
    validate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize Rustls CryptoProvider with ring
    let _ = rustls::crypto::ring::default_provider().install_default();
    
    dotenvy::dotenv().ok();

    let args = Args::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,rama_elite_proxy=debug"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(filter)
        .init();

    info!("🚀 Elite Rama Proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Loading configuration from: {}", args.config);

    let config = Config::from_file(&args.config)?;

    if args.validate {
        info!("✅ Configuration is valid");
        return Ok(());
    }

    config.validate()?;

    let server = Server::new(config).await?;
    server.run().await?;

    Ok(())
}
