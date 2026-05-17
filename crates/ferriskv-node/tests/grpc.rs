use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ferriskv_core::Limits;
use ferriskv_node::{config::Backend, GrpcApi, NodeConfig, NodeService};
use ferriskv_proto::ferris_kv_client::FerrisKvClient;
use ferriskv_proto::ferris_kv_server::FerrisKvServer;
use ferriskv_proto::{
    BatchOp, BatchRequest, DeleteRequest, GetRequest, PutRequest, ScanRequest, WatchRequest,
};
use tonic::transport::Server;

fn pick_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn temp_dir() -> PathBuf {
    let mut p = std::env::temp_dir();
    let id = format!(
        "ferriskv-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    p.push(id);
    std::fs::create_dir_all(&p).unwrap();
    p
}

async fn spawn_server() -> SocketAddr {
    spawn_server_with_limits(Limits::default()).await
}

async fn spawn_server_with_limits(limits: Limits) -> SocketAddr {
    let addr = pick_port();
    let cfg = NodeConfig {
        node_id: Arc::<str>::from("test-node"),
        listen: addr,
        data_dir: temp_dir(),
        coord_endpoints: Vec::new(),
        backend: Backend::Memory,
        limits,
        shutdown_timeout_secs: 5,
    };
    let service = Arc::new(NodeService::open(cfg).unwrap());
    let api = GrpcApi::new(service);
    tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(FerrisKvServer::new(api))
            .serve(addr)
            .await;
    });
    addr
}

async fn connect(addr: SocketAddr) -> FerrisKvClient<tonic::transport::Channel> {
    for _ in 0..30 {
        if let Ok(c) = FerrisKvClient::connect(format!("http://{addr}")).await {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("could not connect to {addr}");
}

#[tokio::test]
async fn put_get_delete_roundtrip() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    client
        .put(PutRequest {
            tenant: "default".into(),
            key: Bytes::from_static(b"hello"),
            value: Bytes::from_static(b"world"),
            ttl_ms: 0,
        })
        .await
        .unwrap();

    let g = client
        .get(GetRequest {
            tenant: "default".into(),
            key: Bytes::from_static(b"hello"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(g.found);
    assert_eq!(&g.value[..], b"world");

    let d = client
        .delete(DeleteRequest {
            tenant: "default".into(),
            key: Bytes::from_static(b"hello"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(d.found);

    let g2 = client
        .get(GetRequest {
            tenant: "default".into(),
            key: Bytes::from_static(b"hello"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!g2.found);
}

#[tokio::test]
async fn tenant_isolation() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"shared"),
            value: Bytes::from_static(b"alice-value"),
            ttl_ms: 0,
        })
        .await
        .unwrap();

    client
        .put(PutRequest {
            tenant: "bob".into(),
            key: Bytes::from_static(b"shared"),
            value: Bytes::from_static(b"bob-value"),
            ttl_ms: 0,
        })
        .await
        .unwrap();

    let alice = client
        .get(GetRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"shared"),
        })
        .await
        .unwrap()
        .into_inner();
    let bob = client
        .get(GetRequest {
            tenant: "bob".into(),
            key: Bytes::from_static(b"shared"),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(&alice.value[..], b"alice-value");
    assert_eq!(&bob.value[..], b"bob-value");

    let stranger = client
        .get(GetRequest {
            tenant: "carol".into(),
            key: Bytes::from_static(b"shared"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!stranger.found);

    let err = client
        .get(GetRequest {
            tenant: "".into(),
            key: Bytes::from_static(b"x"),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn scan_returns_prefix() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    for (k, v) in [("a:1", "1"), ("a:2", "2"), ("b:1", "x")] {
        client
            .put(PutRequest {
                tenant: "default".into(),
                key: Bytes::copy_from_slice(k.as_bytes()),
                value: Bytes::copy_from_slice(v.as_bytes()),
                ttl_ms: 0,
            })
            .await
            .unwrap();
    }

    let mut stream = client
        .scan(ScanRequest {
            tenant: "default".into(),
            prefix: Bytes::from_static(b"a:"),
            limit: 10,
        })
        .await
        .unwrap()
        .into_inner();

    let mut all = Vec::new();
    while let Some(chunk) = stream.message().await.unwrap() {
        all.extend(chunk.entries);
    }
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn batch_applies_put_and_delete() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"existing"),
            value: Bytes::from_static(b"old"),
            ttl_ms: 0,
        })
        .await
        .unwrap();

    client
        .batch(BatchRequest {
            tenant: "alice".into(),
            ops: vec![
                BatchOp {
                    op: 1,
                    key: Bytes::from_static(b"new"),
                    value: Bytes::from_static(b"value"),
                },
                BatchOp {
                    op: 2,
                    key: Bytes::from_static(b"existing"),
                    value: Bytes::new(),
                },
            ],
        })
        .await
        .unwrap();

    let g = client
        .get(GetRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"new"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(g.found);

    let g = client
        .get(GetRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"existing"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!g.found);
}

#[tokio::test]
async fn batch_rejects_unknown_opcode() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    let err = client
        .batch(BatchRequest {
            tenant: "alice".into(),
            ops: vec![BatchOp {
                op: 99,
                key: Bytes::from_static(b"k"),
                value: Bytes::new(),
            }],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn watch_is_unimplemented() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    let err = client
        .watch(WatchRequest {
            tenant: "alice".into(),
            prefix: Bytes::from_static(b""),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn oversize_value_is_rejected() {
    let limits = Limits {
        max_value_size: 16,
        ..Limits::default()
    };
    let addr = spawn_server_with_limits(limits).await;
    let mut client = connect(addr).await;

    let err = client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k"),
            value: Bytes::from(vec![0u8; 32]),
            ttl_ms: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn oversize_key_is_rejected() {
    let limits = Limits {
        max_key_size: 16,
        ..Limits::default()
    };
    let addr = spawn_server_with_limits(limits).await;
    let mut client = connect(addr).await;

    let err = client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from(vec![b'k'; 32]),
            value: Bytes::from_static(b"v"),
            ttl_ms: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn oversize_batch_is_rejected() {
    let limits = Limits {
        max_batch_ops: 2,
        ..Limits::default()
    };
    let addr = spawn_server_with_limits(limits).await;
    let mut client = connect(addr).await;

    let ops: Vec<BatchOp> = (0..5)
        .map(|i| BatchOp {
            op: 1,
            key: Bytes::from(format!("k{i}").into_bytes()),
            value: Bytes::from_static(b"v"),
        })
        .collect();
    let err = client
        .batch(BatchRequest {
            tenant: "alice".into(),
            ops,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn scan_limit_is_capped() {
    let limits = Limits {
        max_scan_limit: 3,
        ..Limits::default()
    };
    let addr = spawn_server_with_limits(limits).await;
    let mut client = connect(addr).await;

    for i in 0..10 {
        client
            .put(PutRequest {
                tenant: "alice".into(),
                key: Bytes::from(format!("k{i:02}").into_bytes()),
                value: Bytes::from_static(b"v"),
                ttl_ms: 0,
            })
            .await
            .unwrap();
    }

    let mut stream = client
        .scan(ScanRequest {
            tenant: "alice".into(),
            prefix: Bytes::from_static(b""),
            limit: 999,
        })
        .await
        .unwrap()
        .into_inner();

    let mut count = 0;
    while let Some(chunk) = stream.message().await.unwrap() {
        count += chunk.entries.len();
    }
    assert_eq!(count, 3);
}

#[tokio::test]
async fn oversize_tenant_is_rejected() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    let big = "x".repeat(256);
    let err = client
        .get(GetRequest {
            tenant: big,
            key: Bytes::from_static(b"k"),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}
