use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ferriskv_auth::JwtVerifier;
use ferriskv_core::Limits;
use ferriskv_node::{
    admin,
    config::{AuthConfig, Backend, TlsConfig},
    ttl, AuthInterceptor, GrpcApi, NodeConfig, NodeService,
};
use ferriskv_proto::ferris_kv_server::FerrisKvServer;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ferriskv-node", version)]
struct Args {
    #[arg(long, default_value = "config/node.toml")]
    config: PathBuf,

    #[command(flatten)]
    log: LogArgs,
}

#[derive(clap::Args, Debug, Clone)]
pub struct LogArgs {
    #[arg(
        long = "log-filter",
        env = "LOG_FILTER",
        name = "LOG_FILTER",
        long_help = "The log filter to use\nhttps://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives",
        default_value = "info"
    )]
    pub filter: String,

    #[arg(
        long = "log-json",
        env = "LOG_JSON",
        name = "LOG_JSON",
        long_help = "Whether to log in JSON format"
    )]
    pub json: bool,
}

fn init_logging(args: &LogArgs) -> Result<()> {
    let filter = EnvFilter::try_new(&args.filter)
        .with_context(|| format!("invalid log filter '{}'", args.filter))?;
    if args.json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log)?;

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
            auth: AuthConfig {
                insecure: true,
                ..Default::default()
            },
            tls: None,
            admin_listen: None,
            ttl_sweep_interval_secs: 60,
            shutdown_timeout_secs: 10,
            wal_rotate_bytes: 64 * 1024 * 1024,
            watch_buffer: 1024,
            watch_heartbeat_secs: 30,
        }
    };

    cfg.validate().map_err(anyhow::Error::msg)?;

    let metrics_handle = install_metrics_recorder()?;

    let service = Arc::new(NodeService::open(cfg)?);
    let addr = service.config.listen;
    let shutdown_timeout = Duration::from_secs(service.config.shutdown_timeout_secs);
    info!(
        node_id = %service.config.node_id,
        listen = %addr,
        backend = ?service.config.backend,
        "ferriskv-node starting",
    );

    let ttl_handle = {
        let svc = Arc::clone(&service);
        let interval = Duration::from_secs(service.config.ttl_sweep_interval_secs);
        tokio::spawn(async move {
            ttl::run_sweeper(svc, interval, shutdown_signal()).await;
        })
    };

    let admin_handle = if let Some(admin_addr) = service.config.admin_listen {
        if !admin_addr.ip().is_loopback() {
            warn!(
                listen = %admin_addr,
                "admin server listens on a non-loopback address, ensure network access is restricted",
            );
        } else {
            info!(listen = %admin_addr, "admin server starting");
        }
        let admin_svc = Arc::clone(&service);
        let admin_metrics = metrics_handle.clone();
        Some(tokio::spawn(async move {
            if let Err(e) =
                admin::serve(admin_addr, admin_svc, admin_metrics, shutdown_signal()).await
            {
                error!(error = %e, "admin server error");
            }
        }))
    } else {
        info!("admin server disabled (set admin_listen to enable /healthz and /readyz)");
        None
    };

    let interceptor = build_auth_interceptor(&service.config.auth)?;
    let api = GrpcApi::new(Arc::clone(&service));
    let mut builder = Server::builder()
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keepalive_interval(Some(Duration::from_secs(10)))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)));

    if let Some(tls) = &service.config.tls {
        builder = builder.tls_config(build_tls(tls)?)?;
        info!(cert = %tls.cert_path.display(), "TLS enabled");
    } else {
        warn!("TLS disabled, server listens in plaintext");
    }

    let serve = builder
        .add_service(FerrisKvServer::with_interceptor(api, interceptor))
        .serve_with_shutdown(addr, shutdown_signal());

    let outcome = tokio::time::timeout(shutdown_timeout + Duration::from_secs(5), serve).await;
    match outcome {
        Ok(Ok(())) => info!("server stopped accepting requests"),
        Ok(Err(e)) => error!(error = %e, "server error"),
        Err(_) => error!("shutdown exceeded timeout, forcing exit"),
    }

    if let Some(handle) = admin_handle {
        if let Err(e) = handle.await {
            error!(error = ?e, "admin server task ended unexpectedly");
        }
    }

    if let Err(e) = ttl_handle.await {
        error!(error = ?e, "ttl sweeper task ended unexpectedly");
    }

    if let Err(e) = service.wal.sync() {
        error!(error = %e, "WAL sync failed during shutdown");
    } else {
        info!("WAL flushed");
    }

    info!("shutdown complete");
    Ok(())
}

fn install_metrics_recorder() -> Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow!("install global metrics recorder: {e}"))?;
    describe_metrics();
    Ok(handle)
}

fn describe_metrics() {
    metrics::describe_counter!(
        "ferriskv_rpc_requests_total",
        "Total number of gRPC requests received by the node"
    );
    metrics::describe_histogram!(
        "ferriskv_rpc_duration_seconds",
        "gRPC request latency in seconds"
    );
    metrics::describe_histogram!(
        "ferriskv_value_bytes",
        "Distribution of value sizes processed by the node, in bytes"
    );
    metrics::describe_histogram!(
        "ferriskv_scan_entries",
        "Number of entries returned per Scan call"
    );
    metrics::describe_counter!(
        "ferriskv_audit_events_total",
        "Total number of audit events emitted by the node"
    );
    metrics::describe_counter!(
        "ferriskv_ttl_evicted_total",
        "Total number of expired keys evicted by the TTL sweeper"
    );
    metrics::describe_histogram!(
        "ferriskv_ttl_sweep_duration_seconds",
        "Duration of a TTL sweeper pass, in seconds"
    );
    metrics::describe_gauge!(
        "ferriskv_ttl_index_size",
        "Number of keys currently scheduled in the in-memory TTL index"
    );
    metrics::describe_gauge!(
        "ferriskv_watch_streams",
        "Number of Watch streams currently open"
    );
    metrics::describe_counter!(
        "ferriskv_watch_events_total",
        "Total number of events delivered to Watch streams, by kind"
    );
    metrics::describe_counter!(
        "ferriskv_watch_lagged_total",
        "Total number of Watch streams terminated for falling behind the event buffer"
    );
}

fn build_tls(cfg: &TlsConfig) -> Result<ServerTlsConfig> {
    let (cert, key) = cfg.load().map_err(anyhow::Error::msg)?;
    let identity = Identity::from_pem(cert, key);
    Ok(ServerTlsConfig::new().identity(identity))
}

fn build_auth_interceptor(cfg: &AuthConfig) -> Result<AuthInterceptor> {
    if cfg.insecure {
        warn!("auth disabled (insecure=true); the server trusts every caller");
        return Ok(AuthInterceptor::insecure());
    }
    let pem = cfg
        .load_public_key()
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow!("auth: public_key_path required when not insecure"))?;
    let verifier = Arc::new(JwtVerifier::new_rs256(&pem)?);
    info!("auth enabled (JWT RS256, public key from disk)");
    Ok(AuthInterceptor::with_verifier(verifier))
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
