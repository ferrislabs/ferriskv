use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use ferriskv_core::Limits;
use ferriskv_node::{config::Backend, GrpcApi, NodeConfig, NodeService};
use ferriskv_proto::ferris_kv_server::FerrisKvServer;
use tonic::transport::Server;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ferriskv-node", version)]
struct Args {
    #[arg(long, default_value = "config/node.toml")]
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
            .build()
            .context("loading config file")?;
        raw.try_deserialize::<NodeConfig>()
            .context("deserializing config")?
    } else {
        NodeConfig {
            node_id: Arc::<str>::from("node-0"),
            listen: "127.0.0.1:7100".parse()?,
            data_dir: PathBuf::from("./data/node"),
            coord_endpoints: Vec::new(),
            backend: Backend::Memory,
            limits: Limits::default(),
            shutdown_timeout_secs: 30,
        }
    };

    cfg.validate().map_err(anyhow::Error::msg)?;

    let service = Arc::new(NodeService::open(cfg)?);
    let addr = service.config.listen;
    let shutdown_timeout = Duration::from_secs(service.config.shutdown_timeout_secs);
    info!(
        node_id = %service.config.node_id,
        listen = %addr,
        backend = ?service.config.backend,
        "ferriskv-node starting",
    );

    let api = GrpcApi::new(Arc::clone(&service));
    let serve = Server::builder()
        .add_service(FerrisKvServer::new(api))
        .serve_with_shutdown(addr, shutdown_signal());

    let outcome = tokio::time::timeout(shutdown_timeout + Duration::from_secs(5), serve).await;
    match outcome {
        Ok(Ok(())) => info!("server stopped accepting requests"),
        Ok(Err(e)) => error!(error = %e, "server error"),
        Err(_) => error!("shutdown exceeded timeout, forcing exit"),
    }

    if let Err(e) = service.wal.sync() {
        error!(error = %e, "WAL sync failed during shutdown");
    } else {
        info!("WAL flushed");
    }

    info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(error = %e, "failed installing SIGINT handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => error!(error = %e, "failed installing SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}
