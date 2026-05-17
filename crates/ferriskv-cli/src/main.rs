use anyhow::Result;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use ferriskv_proto::{
    ferris_kv_client::FerrisKvClient, DeleteRequest, GetRequest, PutRequest, ScanRequest,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "ferriskv", version)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:7100")]
    endpoint: String,

    #[arg(long, default_value = "default")]
    tenant: String,

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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();
    let mut client = FerrisKvClient::connect(args.endpoint.clone()).await?;

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
