use std::path::PathBuf;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use ferriskv_proto::{
    ferris_kv_client::FerrisKvClient, DeleteRequest, GetRequest, PutRequest, ScanRequest,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ferriskv", version)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:7100")]
    endpoint: String,

    #[arg(long, default_value = "default")]
    tenant: String,

    /// Path to a PEM-encoded CA certificate, in addition to the system trust store.
    #[arg(long, env = "FERRISKV_TLS_CA")]
    tls_ca: Option<PathBuf>,

    /// Override the SNI domain sent during the TLS handshake.
    #[arg(long, env = "FERRISKV_TLS_DOMAIN")]
    tls_domain: Option<String>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Get {
        key: String,
    },
    Put {
        key: String,
        value: String,
    },
    Delete {
        key: String,
    },
    Scan {
        prefix: String,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}

async fn build_channel(args: &Args) -> Result<Channel> {
    let mut endpoint =
        Endpoint::from_shared(args.endpoint.clone()).context("invalid endpoint URL")?;

    if args.endpoint.starts_with("https://") {
        let mut tls = ClientTlsConfig::new().with_native_roots();
        if let Some(path) = &args.tls_ca {
            let pem = std::fs::read(path)
                .with_context(|| format!("read tls-ca {}", path.display()))?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
        if let Some(domain) = &args.tls_domain {
            tls = tls.domain_name(domain.clone());
        }
        endpoint = endpoint.tls_config(tls).context("configure TLS")?;
    }

    endpoint.connect().await.context("connect to endpoint")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();
    let channel = build_channel(&args).await?;
    let mut client = FerrisKvClient::new(channel);

    match args.cmd {
        Command::Get { key } => {
            let resp = client
                .get(GetRequest {
                    tenant: args.tenant,
                    key: Bytes::from(key.into_bytes()),
                })
                .await?
                .into_inner();
            if resp.found {
                println!("{}", String::from_utf8_lossy(&resp.value));
            } else {
                std::process::exit(1);
            }
        }
        Command::Put { key, value } => {
            let resp = client
                .put(PutRequest {
                    tenant: args.tenant,
                    key: Bytes::from(key.into_bytes()),
                    value: Bytes::from(value.into_bytes()),
                    ttl_ms: 0,
                })
                .await?
                .into_inner();
            println!("version={}", resp.version);
        }
        Command::Delete { key } => {
            let resp = client
                .delete(DeleteRequest {
                    tenant: args.tenant,
                    key: Bytes::from(key.into_bytes()),
                })
                .await?
                .into_inner();
            println!("found={}", resp.found);
        }
        Command::Scan { prefix, limit } => {
            let mut stream = client
                .scan(ScanRequest {
                    tenant: args.tenant,
                    prefix: Bytes::from(prefix.into_bytes()),
                    limit,
                })
                .await?
                .into_inner();
            while let Some(chunk) = stream.message().await? {
                for kv in chunk.entries {
                    println!(
                        "{}\t{}",
                        String::from_utf8_lossy(&kv.key),
                        String::from_utf8_lossy(&kv.value)
                    );
                }
            }
        }
    }
    Ok(())
}
