use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use ferriskv_core::Storage;
use serde::Serialize;

use crate::service::NodeService;

const READYZ_PROBE_KEY: &[u8] = b"__ferriskv_internal_probe__";
const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

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

pub fn router(service: Arc<NodeService>) -> Router {
    Router::new()
        .route("/healthz", get(live))
        .route("/readyz", get(ready))
        .with_state(service)
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

pub async fn serve<F>(
    addr: SocketAddr,
    service: Arc<NodeService>,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = router(service);
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

    async fn read_json(body: Body) -> Value {
        let bytes = to_bytes(body, 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_ok_json() {
        let svc = test_service("healthz");
        let app = router(svc);
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
        let svc = test_service("readyz");
        let app = router(svc);
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
    async fn unknown_route_returns_404() {
        let svc = test_service("404");
        let app = router(svc);
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
