use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use ferriskv_coord::{CoordConfig, CoordState};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ferriskv-coord", version)]
struct Args {
    #[arg(long, default_value = "config/coord.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let args = Args::parse();

    let cfg = if args.config.exists() {
        let raw = ::config::Config::builder()
            .add_source(::config::File::from(args.config.clone()))
            .build()?;
        raw.try_deserialize::<CoordConfig>()?
    } else {
        CoordConfig {
            node_id: Arc::<str>::from("coord-0"),
            listen: "127.0.0.1:7000".parse()?,
            peers: Vec::new(),
            data_dir: PathBuf::from("./data/coord"),
            target_range_size_bytes: 128 * 1024 * 1024,
            replication_factor: 3,
        }
    };

    let state = Arc::new(CoordState::new(cfg));
    info!(node_id = %state.config.node_id, listen = %state.config.listen, "ferriskv-coord starting");

    tokio::signal::ctrl_c().await?;
    info!("shutdown");
    Ok(())
}
