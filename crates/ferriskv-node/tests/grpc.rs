use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ferriskv_auth::{Claims, JwtVerifier};
use ferriskv_core::Limits;
use ferriskv_node::{
    config::{AuthConfig, Backend},
    AuthInterceptor, GrpcApi, NodeConfig, NodeService,
};
use ferriskv_proto::ferris_kv_client::FerrisKvClient;
use ferriskv_proto::ferris_kv_server::FerrisKvServer;
use ferriskv_proto::{
    BatchOp, BatchRequest, DeleteRequest, GetRequest, PutRequest, ScanRequest, WatchRequest,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use tempfile::TempDir;
use tonic::transport::Server;

fn pick_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn spawn_server() -> SocketAddr {
    spawn_server_with_limits(Limits::default()).await
}

async fn spawn_server_with_limits(limits: Limits) -> SocketAddr {
    spawn_with(limits, AuthInterceptor::insecure()).await
}

async fn spawn_secure_server(secret: &[u8]) -> SocketAddr {
    let verifier = Arc::new(JwtVerifier::new_hs256(secret));
    spawn_with(Limits::default(), AuthInterceptor::with_verifier(verifier)).await
}

async fn spawn_with(limits: Limits, interceptor: AuthInterceptor) -> SocketAddr {
    let addr = pick_port();
    let dir = TempDir::new().unwrap();
    let cfg = NodeConfig {
        node_id: Arc::<str>::from("test-node"),
        listen: addr,
        data_dir: dir.path().to_path_buf(),
        coord_endpoints: Vec::new(),
        backend: Backend::Memory,
        limits,
        auth: AuthConfig {
            insecure: true,
            ..Default::default()
        },
        tls: None,
        admin_listen: None,
        shutdown_timeout_secs: 5,
    };
    let service = Arc::new(NodeService::open(cfg).unwrap());
    let api = GrpcApi::new(service);
    tokio::spawn(async move {
        let _keep_dir = dir;
        let _ = Server::builder()
            .add_service(FerrisKvServer::with_interceptor(api, interceptor))
            .serve(addr)
            .await;
    });
    addr
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn make_token(secret: &[u8], tenant: &str, perms: &[&str]) -> String {
    let claims = Claims {
        sub: Arc::<str>::from("test-user"),
        tenant: Arc::<str>::from(tenant),
        roles: Vec::new(),
        perms: perms.iter().map(|p| Arc::<str>::from(*p)).collect(),
        exp: now() + 3600,
        iss: None,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap()
}

fn with_auth<T>(payload: T, token: &str) -> tonic::Request<T> {
    let mut r = tonic::Request::new(payload);
    r.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    r
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

#[tokio::test]
async fn auth_rejects_missing_token() {
    let addr = spawn_secure_server(b"hunter2").await;
    let mut client = connect(addr).await;
    let err = client
        .get(GetRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k"),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn auth_accepts_valid_token() {
    let secret = b"hunter2";
    let addr = spawn_secure_server(secret).await;
    let mut client = connect(addr).await;
    let token = make_token(secret, "alice", &["read", "write"]);

    client
        .put(with_auth(
            PutRequest {
                tenant: "alice".into(),
                key: Bytes::from_static(b"k"),
                value: Bytes::from_static(b"v"),
                ttl_ms: 0,
            },
            &token,
        ))
        .await
        .unwrap();

    let g = client
        .get(with_auth(
            GetRequest {
                tenant: "alice".into(),
                key: Bytes::from_static(b"k"),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(g.found);
}

#[tokio::test]
async fn auth_rejects_tenant_mismatch() {
    let secret = b"hunter2";
    let addr = spawn_secure_server(secret).await;
    let mut client = connect(addr).await;
    let alice_token = make_token(secret, "alice", &["read", "write"]);

    let err = client
        .put(with_auth(
            PutRequest {
                tenant: "bob".into(),
                key: Bytes::from_static(b"k"),
                value: Bytes::from_static(b"v"),
                ttl_ms: 0,
            },
            &alice_token,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn auth_rejects_insufficient_permission() {
    let secret = b"hunter2";
    let addr = spawn_secure_server(secret).await;
    let mut client = connect(addr).await;
    let read_only = make_token(secret, "alice", &["read"]);

    let err = client
        .put(with_auth(
            PutRequest {
                tenant: "alice".into(),
                key: Bytes::from_static(b"k"),
                value: Bytes::from_static(b"v"),
                ttl_ms: 0,
            },
            &read_only,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn auth_admin_perm_grants_everything() {
    let secret = b"hunter2";
    let addr = spawn_secure_server(secret).await;
    let mut client = connect(addr).await;
    let admin = make_token(secret, "alice", &["admin"]);

    client
        .put(with_auth(
            PutRequest {
                tenant: "alice".into(),
                key: Bytes::from_static(b"k"),
                value: Bytes::from_static(b"v"),
                ttl_ms: 0,
            },
            &admin,
        ))
        .await
        .unwrap();

    client
        .delete(with_auth(
            DeleteRequest {
                tenant: "alice".into(),
                key: Bytes::from_static(b"k"),
            },
            &admin,
        ))
        .await
        .unwrap();
}
