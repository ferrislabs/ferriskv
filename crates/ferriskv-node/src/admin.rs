use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{FromRef, Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use ferriskv_core::Storage;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};

use crate::quota::{Quota, TenantUsage};
use crate::service::NodeService;

const READYZ_PROBE_KEY: &[u8] = b"__ferriskv_internal_probe__";
const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct AdminState {
    service: Arc<NodeService>,
    metrics: PrometheusHandle,
}

impl FromRef<AdminState> for Arc<NodeService> {
    fn from_ref(input: &AdminState) -> Self {
        Arc::clone(&input.service)
    }
}

impl FromRef<AdminState> for PrometheusHandle {
    fn from_ref(input: &AdminState) -> Self {
        input.metrics.clone()
    }
}

#[derive(Serialize)]
struct LiveResponse {
    status: &'static str,
    node_id: Arc<str>,
    version: &'static str,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    node_id: Arc<str>,
    version: &'static str,
    checks: ReadyChecks,
}

#[derive(Serialize)]
struct ReadyChecks {
    storage: String,
}

pub fn router(service: Arc<NodeService>, metrics: PrometheusHandle) -> Router {
    let state = AdminState { service, metrics };
    Router::new()
        .route("/healthz", get(live))
        .route("/readyz", get(ready))
        .route("/metrics", get(render_metrics))
        // Quota administration. On this server rather than as gRPC RPCs: the
        // admin port is already the operator surface and binds to loopback by
        // default, whereas a tenant-facing RPC for cluster administration would
        // need an admin RBAC role that does not exist yet. Adding a
        // half-authorized write path to the tenant API to save an HTTP route
        // would be the wrong trade.
        .route("/quotas", get(list_quotas))
        // `:tenant`, not `{tenant}`: axum 0.7 routes on matchit 0.7, where brace
        // syntax is a literal path segment rather than a capture. Both compile.
        .route(
            "/quotas/:tenant",
            get(get_quota).put(set_quota).delete(clear_quota),
        )
        .with_state(state)
}

#[derive(Serialize)]
struct QuotaEntry {
    tenant: Arc<str>,
    #[serde(flatten)]
    usage: TenantUsage,
}

#[derive(Serialize)]
struct QuotaListResponse {
    node_id: Arc<str>,
    tenants: Vec<QuotaEntry>,
}

/// Body of a quota write. Both fields are optional so an operator can raise the
/// byte cap without having to restate the rate limit, and `0` means unlimited.
#[derive(Deserialize)]
struct SetQuotaRequest {
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    max_ops_per_sec: Option<u32>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Lists every tenant this node knows about, with usage and limits.
async fn list_quotas(State(svc): State<Arc<NodeService>>) -> Json<QuotaListResponse> {
    let tenants = svc
        .quotas
        .list()
        .into_iter()
        .map(|(tenant, usage)| QuotaEntry { tenant, usage })
        .collect();
    Json(QuotaListResponse {
        node_id: Arc::clone(&svc.config.node_id),
        tenants,
    })
}

/// Reports one tenant's usage and limits.
///
/// Answers for a tenant that has never been seen, rather than 404: "no data and
/// the default limits" is the true state of an unknown tenant, and a 404 would
/// make a caller distinguish two cases that behave identically.
async fn get_quota(
    State(svc): State<Arc<NodeService>>,
    Path(tenant): Path<String>,
) -> Result<Json<QuotaEntry>, (StatusCode, Json<ErrorResponse>)> {
    validate_tenant(&tenant)?;
    Ok(Json(QuotaEntry {
        tenant: Arc::<str>::from(tenant.as_str()),
        usage: svc.quotas.usage_of(&tenant),
    }))
}

/// Sets one tenant's limits, leaving unspecified fields as they were.
async fn set_quota(
    State(svc): State<Arc<NodeService>>,
    Path(tenant): Path<String>,
    Json(body): Json<SetQuotaRequest>,
) -> Result<Json<QuotaEntry>, (StatusCode, Json<ErrorResponse>)> {
    validate_tenant(&tenant)?;
    let current = svc.quotas.quota(&tenant);
    let updated = Quota {
        max_bytes: body.max_bytes.unwrap_or(current.max_bytes),
        max_ops_per_sec: body.max_ops_per_sec.unwrap_or(current.max_ops_per_sec),
    };
    svc.quotas
        .set_quota(&svc.storage, &tenant, updated)
        .map_err(internal)?;
    tracing::info!(
        tenant = %tenant,
        max_bytes = updated.max_bytes,
        max_ops_per_sec = updated.max_ops_per_sec,
        "tenant quota updated",
    );
    Ok(Json(QuotaEntry {
        tenant: Arc::<str>::from(tenant.as_str()),
        usage: svc.quotas.usage_of(&tenant),
    }))
}

/// Removes one tenant's own limits, returning it to the node defaults.
async fn clear_quota(
    State(svc): State<Arc<NodeService>>,
    Path(tenant): Path<String>,
) -> Result<Json<QuotaEntry>, (StatusCode, Json<ErrorResponse>)> {
    validate_tenant(&tenant)?;
    svc.quotas
        .clear_quota(&svc.storage, &tenant)
        .map_err(internal)?;
    tracing::info!(tenant = %tenant, "tenant quota cleared");
    Ok(Json(QuotaEntry {
        tenant: Arc::<str>::from(tenant.as_str()),
        usage: svc.quotas.usage_of(&tenant),
    }))
}

/// Rejects tenant names the key codec could not encode.
///
/// Without this the failure would surface as a 500 from deep inside the codec,
/// which reads as a node fault rather than a bad request.
fn validate_tenant(tenant: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if tenant.is_empty() || tenant.len() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "tenant must be between 1 and 255 bytes".to_string(),
            }),
        ));
    }
    Ok(())
}

fn internal(e: ferriskv_core::Error) -> (StatusCode, Json<ErrorResponse>) {
    tracing::error!(error = %e, "quota administration failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: e.to_string(),
        }),
    )
}

async fn live(State(svc): State<Arc<NodeService>>) -> Json<LiveResponse> {
    Json(LiveResponse {
        status: "ok",
        node_id: Arc::clone(&svc.config.node_id),
        version: NODE_VERSION,
    })
}

async fn ready(State(svc): State<Arc<NodeService>>) -> (StatusCode, Json<ReadyResponse>) {
    let (code, status, storage) = match svc.storage.get(READYZ_PROBE_KEY) {
        Ok(_) => (StatusCode::OK, "ready", "ok".to_string()),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, "unready", e.to_string()),
    };
    (
        code,
        Json(ReadyResponse {
            status,
            node_id: Arc::clone(&svc.config.node_id),
            version: NODE_VERSION,
            checks: ReadyChecks { storage },
        }),
    )
}

async fn render_metrics(State(handle): State<PrometheusHandle>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        handle.render(),
    )
}

pub async fn serve<F>(
    addr: SocketAddr,
    service: Arc<NodeService>,
    metrics: PrometheusHandle,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = router(service, metrics);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Method, Request, StatusCode};
    use ferriskv_core::Limits;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use serde_json::Value;
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;
    use crate::config::{AuthConfig, Backend};
    use crate::{NodeConfig, NodeService};

    fn test_service() -> (Arc<NodeService>, TempDir) {
        let dir = TempDir::new().unwrap();
        let cfg = NodeConfig {
            node_id: Arc::<str>::from("test-node"),
            listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            data_dir: dir.path().to_path_buf(),
            coord_endpoints: Vec::new(),
            backend: Backend::Memory,
            limits: Limits::default(),
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
        (Arc::new(NodeService::open(cfg).unwrap()), dir)
    }

    fn test_handle() -> PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    async fn read_json(body: Body) -> Value {
        let bytes = to_bytes(body, 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn read_text(body: Body) -> String {
        let bytes = to_bytes(body, 16 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn call(
        app: Router,
        method: Method,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, Value) {
        let builder = Request::builder().method(method).uri(uri);
        let request = match body {
            Some(json) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };
        let resp = app.oneshot(request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn healthz_returns_ok_json() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        let body = read_json(resp.into_body()).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["node_id"], "test-node");
        assert!(body["version"].is_string());
    }

    #[tokio::test]
    async fn readyz_returns_ready_json_when_storage_responsive() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp.into_body()).await;
        assert_eq!(body["status"], "ready");
        assert_eq!(body["node_id"], "test-node");
        assert_eq!(body["checks"]["storage"], "ok");
    }

    #[tokio::test]
    async fn metrics_returns_prometheus_text_with_correct_content_type() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("text/plain"),
            "unexpected content-type: {ct}"
        );
        let _ = read_text(resp.into_body()).await;
    }

    #[tokio::test]
    async fn a_tenant_quota_can_be_set_then_read_back() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());

        let (status, body) = call(
            app.clone(),
            Method::PUT,
            "/quotas/alice",
            Some(r#"{"max_bytes": 4096, "max_ops_per_sec": 25}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["tenant"], "alice");
        assert_eq!(body["max_bytes"], 4096);
        assert_eq!(body["max_ops_per_sec"], 25);

        let (status, body) = call(app, Method::GET, "/quotas/alice", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["max_bytes"], 4096);
        assert_eq!(body["used_bytes"], 0);
    }

    /// The route must actually capture the tenant.
    ///
    /// axum 0.7 routes on matchit 0.7, where `{tenant}` is a literal segment
    /// rather than a capture — and it compiles either way. Without a test that
    /// reads the name back, that mistake ships silently and every tenant shares
    /// one quota.
    #[tokio::test]
    async fn the_route_captures_the_tenant_rather_than_matching_a_literal() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());

        call(
            app.clone(),
            Method::PUT,
            "/quotas/alice",
            Some(r#"{"max_bytes": 100}"#),
        )
        .await;
        call(
            app.clone(),
            Method::PUT,
            "/quotas/bob",
            Some(r#"{"max_bytes": 200}"#),
        )
        .await;

        let (_, alice) = call(app.clone(), Method::GET, "/quotas/alice", None).await;
        let (_, bob) = call(app, Method::GET, "/quotas/bob", None).await;
        assert_eq!(alice["tenant"], "alice");
        assert_eq!(alice["max_bytes"], 100);
        assert_eq!(bob["tenant"], "bob");
        assert_eq!(bob["max_bytes"], 200);
    }

    #[tokio::test]
    async fn setting_one_field_leaves_the_other_alone() {
        // An operator raising a byte cap should not have to restate the rate
        // limit, and silently zeroing it would mean silently unthrottling.
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());

        call(
            app.clone(),
            Method::PUT,
            "/quotas/alice",
            Some(r#"{"max_bytes": 100, "max_ops_per_sec": 7}"#),
        )
        .await;
        let (_, body) = call(
            app,
            Method::PUT,
            "/quotas/alice",
            Some(r#"{"max_bytes": 999}"#),
        )
        .await;
        assert_eq!(body["max_bytes"], 999);
        assert_eq!(body["max_ops_per_sec"], 7);
    }

    #[tokio::test]
    async fn an_unknown_tenant_reports_defaults_rather_than_404() {
        // No data and the default limits is the true state of a tenant nobody
        // has written to; a 404 would make callers distinguish two cases that
        // behave identically.
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());
        let (status, body) = call(app, Method::GET, "/quotas/never-seen", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["used_bytes"], 0);
        assert_eq!(body["max_bytes"], 0);
    }

    #[tokio::test]
    async fn clearing_a_quota_returns_the_tenant_to_the_defaults() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());

        call(
            app.clone(),
            Method::PUT,
            "/quotas/alice",
            Some(r#"{"max_bytes": 100}"#),
        )
        .await;
        let (status, body) = call(app.clone(), Method::DELETE, "/quotas/alice", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["max_bytes"], 0);

        let (_, body) = call(app, Method::GET, "/quotas/alice", None).await;
        assert_eq!(body["max_bytes"], 0);
    }

    #[tokio::test]
    async fn a_tenant_name_the_codec_cannot_encode_is_a_bad_request() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());
        let long = "x".repeat(256);
        let (status, body) = call(app, Method::GET, &format!("/quotas/{long}"), None).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "surfacing this as a 500 would read as a node fault",
        );
        assert!(body["error"].is_string());
    }

    #[tokio::test]
    async fn listing_reports_usage_alongside_limits() {
        let (svc, _dir) = test_service();
        let key =
            ferriskv_core::KeyCodec::encode("alice", ferriskv_core::Subspace::Data, b"order:42")
                .unwrap();
        svc.put_with_ttl(&key, b"payload", 0).unwrap();

        let app = router(Arc::clone(&svc), test_handle());
        call(
            app.clone(),
            Method::PUT,
            "/quotas/prepared",
            Some(r#"{"max_bytes": 512}"#),
        )
        .await;

        let (status, body) = call(app, Method::GET, "/quotas", None).await;
        assert_eq!(status, StatusCode::OK);
        let tenants = body["tenants"].as_array().unwrap();
        let names: Vec<&str> = tenants
            .iter()
            .map(|t| t["tenant"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["alice", "prepared"]);
        assert_eq!(
            tenants[0]["used_bytes"], 15,
            "8 bytes of key plus 7 of value",
        );
        assert_eq!(tenants[1]["used_bytes"], 0);
        assert_eq!(tenants[1]["max_bytes"], 512);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let (svc, _dir) = test_service();
        let app = router(svc, test_handle());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/whatever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
