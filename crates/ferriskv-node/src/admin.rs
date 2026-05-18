use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{FromRef, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use ferriskv_core::Storage;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;

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
        .with_state(state)
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
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
    use ferriskv_core::Limits;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::config::{AuthConfig, Backend};
    use crate::{NodeConfig, NodeService};

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ferriskv-admin-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        p
    }

    fn test_service(tag: &str) -> Arc<NodeService> {
        let cfg = NodeConfig {
            node_id: Arc::<str>::from("test-node"),
            listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            data_dir: tmp_dir(tag),
            coord_endpoints: Vec::new(),
            backend: Backend::Memory,
            limits: Limits::default(),
            auth: AuthConfig {
                insecure: true,
                ..Default::default()
            },
            tls: None,
            admin_listen: None,
            shutdown_timeout_secs: 5,
        };
        Arc::new(NodeService::open(cfg).unwrap())
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

    #[tokio::test]
    async fn healthz_returns_ok_json() {
        let app = router(test_service("healthz"), test_handle());
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
        let app = router(test_service("readyz"), test_handle());
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
        let app = router(test_service("metrics"), test_handle());
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
    async fn unknown_route_returns_404() {
        let app = router(test_service("404"), test_handle());
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
