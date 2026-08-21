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
    BatchOp, BatchRequest, DeleteRequest, GetRequest, PutRequest, ScanRequest, WatchEvent,
    WatchEventKind, WatchRequest,
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

async fn spawn_watch_server(watch_buffer: usize, heartbeat_secs: u64) -> SocketAddr {
    spawn_tuned(Limits::default(), AuthInterceptor::insecure(), |cfg| {
        cfg.watch_buffer = watch_buffer;
        cfg.watch_heartbeat_secs = heartbeat_secs;
    })
    .await
}

async fn spawn_with(limits: Limits, interceptor: AuthInterceptor) -> SocketAddr {
    spawn_tuned(limits, interceptor, |_| {}).await
}

async fn spawn_tuned(
    limits: Limits,
    interceptor: AuthInterceptor,
    tune: impl FnOnce(&mut NodeConfig),
) -> SocketAddr {
    let addr = pick_port();
    let dir = TempDir::new().unwrap();
    let mut cfg = NodeConfig {
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
        ttl_sweep_interval_secs: 0,
        shutdown_timeout_secs: 5,
        wal_rotate_bytes: 64 * 1024 * 1024,
        quota: Default::default(),
        watch_buffer: 1024,
        watch_heartbeat_secs: 30,
    };
    tune(&mut cfg);
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

/// Opens a watch stream and waits until the server has actually registered the
/// subscription.
///
/// `watch()` returning is not enough: the response arrives before the handler's
/// `subscribe` is guaranteed to have run, so a write issued immediately after
/// can be published to nobody. Every test here would then be flaky in the
/// direction that looks like a bug in the feature.
async fn open_watch(
    client: &mut FerrisKvClient<tonic::transport::Channel>,
    tenant: &str,
    prefix: &'static [u8],
) -> tonic::Streaming<WatchEvent> {
    let stream = client
        .watch(WatchRequest {
            tenant: tenant.into(),
            prefix: Bytes::from_static(prefix),
        })
        .await
        .unwrap()
        .into_inner();
    tokio::time::sleep(Duration::from_millis(150)).await;
    stream
}

async fn next_event(stream: &mut tonic::Streaming<WatchEvent>) -> WatchEvent {
    tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("watch stream produced no event within 5s")
        .unwrap()
        .expect("watch stream ended unexpectedly")
}

#[tokio::test]
async fn watch_reports_puts_and_deletes() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;
    let mut stream = open_watch(&mut client, "alice", b"").await;

    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"watched"),
            value: Bytes::from_static(b"v1"),
            ttl_ms: 0,
        })
        .await
        .unwrap();

    let event = next_event(&mut stream).await;
    assert_eq!(event.kind(), WatchEventKind::Put);
    assert_eq!(&event.key[..], b"watched");
    assert_eq!(&event.value[..], b"v1");

    client
        .delete(DeleteRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"watched"),
        })
        .await
        .unwrap();

    let event = next_event(&mut stream).await;
    assert_eq!(event.kind(), WatchEventKind::Delete);
    assert_eq!(&event.key[..], b"watched");
    assert!(
        event.value.is_empty(),
        "a delete carries no value to report",
    );
}

#[tokio::test]
async fn watch_only_reports_keys_under_the_requested_prefix() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;
    let mut stream = open_watch(&mut client, "alice", b"cache:").await;

    for key in [&b"other:1"[..], b"cache:hit", b"cacheless"] {
        client
            .put(PutRequest {
                tenant: "alice".into(),
                key: Bytes::copy_from_slice(key),
                value: Bytes::from_static(b"v"),
                ttl_ms: 0,
            })
            .await
            .unwrap();
    }

    let event = next_event(&mut stream).await;
    assert_eq!(
        &event.key[..],
        b"cache:hit",
        "the two non-matching keys must not appear at all",
    );
}

#[tokio::test]
async fn watch_never_leaks_across_tenants() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;
    // An empty prefix is the widest subscription a client can ask for. If
    // anything is going to escape a tenant, it is this.
    let mut stream = open_watch(&mut client, "alice", b"").await;

    client
        .put(PutRequest {
            tenant: "bob".into(),
            key: Bytes::from_static(b"bob-only"),
            value: Bytes::from_static(b"secret"),
            ttl_ms: 0,
        })
        .await
        .unwrap();
    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"alice-key"),
            value: Bytes::from_static(b"v"),
            ttl_ms: 0,
        })
        .await
        .unwrap();

    let event = next_event(&mut stream).await;
    assert_eq!(
        &event.key[..],
        b"alice-key",
        "bob's write must not reach alice's stream",
    );
}

#[tokio::test]
async fn watch_reports_a_batch_op_by_op() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;
    let mut stream = open_watch(&mut client, "alice", b"").await;

    client
        .batch(BatchRequest {
            tenant: "alice".into(),
            ops: vec![
                BatchOp {
                    op: 1,
                    key: Bytes::from_static(b"one"),
                    value: Bytes::from_static(b"1"),
                },
                BatchOp {
                    op: 1,
                    key: Bytes::from_static(b"two"),
                    value: Bytes::from_static(b"2"),
                },
                BatchOp {
                    op: 2,
                    key: Bytes::from_static(b"one"),
                    value: Bytes::new(),
                },
            ],
        })
        .await
        .unwrap();

    let seen: Vec<_> = {
        let mut out = Vec::new();
        for _ in 0..3 {
            let e = next_event(&mut stream).await;
            out.push((e.kind(), e.key.to_vec()));
        }
        out
    };
    assert_eq!(
        seen,
        vec![
            (WatchEventKind::Put, b"one".to_vec()),
            (WatchEventKind::Put, b"two".to_vec()),
            (WatchEventKind::Delete, b"one".to_vec()),
        ],
    );
}

#[tokio::test]
async fn watch_sends_a_heartbeat_while_idle() {
    let addr = spawn_watch_server(1024, 1).await;
    let mut client = connect(addr).await;
    let mut stream = open_watch(&mut client, "alice", b"").await;

    // No writes at all: whatever arrives is the liveness signal.
    let event = next_event(&mut stream).await;
    assert_eq!(event.kind(), WatchEventKind::Heartbeat);
    assert!(event.key.is_empty());
    assert!(event.value.is_empty());
}

#[tokio::test]
async fn watch_requires_the_watch_permission() {
    let secret = b"hunter2";
    let addr = spawn_secure_server(secret).await;
    let mut client = connect(addr).await;

    let no_watch = make_token(secret, "alice", &["read", "write"]);
    let err = client
        .watch(with_auth(
            WatchRequest {
                tenant: "alice".into(),
                prefix: Bytes::new(),
            },
            &no_watch,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let allowed = make_token(secret, "alice", &["watch"]);
    client
        .watch(with_auth(
            WatchRequest {
                tenant: "alice".into(),
                prefix: Bytes::new(),
            },
            &allowed,
        ))
        .await
        .expect("the watch permission must be enough to open a stream");
}

#[tokio::test]
async fn watch_rejects_a_foreign_tenant() {
    let secret = b"hunter2";
    let addr = spawn_secure_server(secret).await;
    let mut client = connect(addr).await;
    let alice = make_token(secret, "alice", &["watch"]);

    let err = client
        .watch(with_auth(
            WatchRequest {
                tenant: "bob".into(),
                prefix: Bytes::new(),
            },
            &alice,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

async fn spawn_quota_server(max_bytes: u64, max_ops_per_sec: u32) -> SocketAddr {
    spawn_tuned(Limits::default(), AuthInterceptor::insecure(), |cfg| {
        cfg.quota.default_max_bytes = max_bytes;
        cfg.quota.default_max_ops_per_sec = max_ops_per_sec;
    })
    .await
}

#[tokio::test]
async fn a_write_over_the_storage_quota_is_resource_exhausted() {
    let addr = spawn_quota_server(64, 0).await;
    let mut client = connect(addr).await;

    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k"),
            value: Bytes::from(vec![b'x'; 40]),
            ttl_ms: 0,
        })
        .await
        .unwrap();

    let err = client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k2"),
            value: Bytes::from(vec![b'x'; 40]),
            ttl_ms: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);

    // The refused key must not be readable: a quota refusal is not a partial
    // success.
    let g = client
        .get(GetRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k2"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!g.found);
}

#[tokio::test]
async fn a_quota_refusal_does_not_affect_other_tenants() {
    let addr = spawn_quota_server(64, 0).await;
    let mut client = connect(addr).await;

    client
        .put(PutRequest {
            tenant: "noisy".into(),
            key: Bytes::from_static(b"k"),
            value: Bytes::from(vec![b'x'; 60]),
            ttl_ms: 0,
        })
        .await
        .unwrap();
    assert_eq!(
        client
            .put(PutRequest {
                tenant: "noisy".into(),
                key: Bytes::from_static(b"k2"),
                value: Bytes::from(vec![b'x'; 60]),
                ttl_ms: 0,
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted,
    );

    client
        .put(PutRequest {
            tenant: "quiet".into(),
            key: Bytes::from_static(b"k"),
            value: Bytes::from(vec![b'x'; 60]),
            ttl_ms: 0,
        })
        .await
        .expect("a quiet tenant must not pay for a noisy one");
}

#[tokio::test]
async fn deleting_frees_quota_for_the_next_write() {
    let addr = spawn_quota_server(64, 0).await;
    let mut client = connect(addr).await;

    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k"),
            value: Bytes::from(vec![b'x'; 60]),
            ttl_ms: 0,
        })
        .await
        .unwrap();
    assert!(client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k2"),
            value: Bytes::from(vec![b'x'; 60]),
            ttl_ms: 0,
        })
        .await
        .is_err());

    client
        .delete(DeleteRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k"),
        })
        .await
        .unwrap();

    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"k2"),
            value: Bytes::from(vec![b'x'; 60]),
            ttl_ms: 0,
        })
        .await
        .expect("the deleted bytes must be usable again");
}

#[tokio::test]
async fn a_tenant_over_its_rate_limit_is_resource_exhausted() {
    let addr = spawn_quota_server(0, 5).await;
    let mut client = connect(addr).await;

    let mut throttled = false;
    for i in 0..40 {
        let outcome = client
            .put(PutRequest {
                tenant: "alice".into(),
                key: Bytes::from(format!("k{i}").into_bytes()),
                value: Bytes::from_static(b"v"),
                ttl_ms: 0,
            })
            .await;
        if let Err(status) = outcome {
            assert_eq!(status.code(), tonic::Code::ResourceExhausted);
            throttled = true;
            break;
        }
    }
    assert!(throttled, "40 writes against a 5/s limit must be throttled");
}

#[tokio::test]
async fn reads_are_throttled_too() {
    // A tenant can saturate a node with reads just as effectively as with
    // writes, so a limit that only covered writes would not be a limit.
    let addr = spawn_quota_server(0, 5).await;
    let mut client = connect(addr).await;

    let mut throttled = false;
    for _ in 0..40 {
        if let Err(status) = client
            .get(GetRequest {
                tenant: "alice".into(),
                key: Bytes::from_static(b"absent"),
            })
            .await
        {
            assert_eq!(status.code(), tonic::Code::ResourceExhausted);
            throttled = true;
            break;
        }
    }
    assert!(throttled);
}

#[tokio::test]
async fn a_batch_cannot_be_used_to_bypass_the_rate_limit() {
    // Charging one operation per RPC would make the limit meaningless against
    // any client willing to batch.
    let addr = spawn_quota_server(0, 4).await;
    let mut client = connect(addr).await;

    let ops: Vec<BatchOp> = (0..4)
        .map(|i| BatchOp {
            op: 1,
            key: Bytes::from(format!("k{i}").into_bytes()),
            value: Bytes::from_static(b"v"),
        })
        .collect();
    client
        .batch(BatchRequest {
            tenant: "alice".into(),
            ops,
        })
        .await
        .unwrap();

    let err = client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"one-more"),
            value: Bytes::from_static(b"v"),
            ttl_ms: 0,
        })
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::ResourceExhausted,
        "the batch must have consumed the whole allowance",
    );
}

#[tokio::test]
async fn a_request_costing_more_than_the_whole_allowance_is_invalid_not_throttled() {
    // No amount of waiting admits it, so reporting it as a rate limit would send
    // the client into a retry loop that can never succeed.
    let addr = spawn_quota_server(0, 3).await;
    let mut client = connect(addr).await;

    let ops: Vec<BatchOp> = (0..10)
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
async fn no_quota_configured_means_no_enforcement() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;
    for i in 0..200 {
        client
            .put(PutRequest {
                tenant: "alice".into(),
                key: Bytes::from(format!("k{i}").into_bytes()),
                value: Bytes::from(vec![b'x'; 256]),
                ttl_ms: 0,
            })
            .await
            .expect("an unconfigured node must not enforce a limit nobody set");
    }
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

#[tokio::test]
async fn ttl_expired_key_returns_not_found() {
    let addr = spawn_server().await;
    let mut client = connect(addr).await;

    client
        .put(PutRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"ephemeral"),
            value: Bytes::from_static(b"v"),
            ttl_ms: 100,
        })
        .await
        .unwrap();

    let immediate = client
        .get(GetRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"ephemeral"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(immediate.found);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let after = client
        .get(GetRequest {
            tenant: "alice".into(),
            key: Bytes::from_static(b"ephemeral"),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!after.found);
}
