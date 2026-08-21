#![allow(clippy::result_large_err)]

use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use ferriskv_core::{Error, KeyCodec, Subspace};
use ferriskv_proto::ferris_kv_server::FerrisKv;
use ferriskv_proto::{
    BatchRequest, BatchResponse, DeleteRequest, DeleteResponse, GetRequest, GetResponse, KeyValue,
    PutRequest, PutResponse, ScanChunk, ScanRequest, WatchEvent, WatchEventKind, WatchRequest,
};
use futures::stream::Iter;
use futures::Stream;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::Receiver;
use tokio::time::Instant as TokioInstant;
use tonic::{Request, Response, Status};

use crate::audit;
use crate::auth_layer::Principal;
use crate::service::NodeService;
use crate::watch::{ChangeKind, KeyChange};

const PERM_READ: &str = "read";
const PERM_WRITE: &str = "write";
const PERM_DELETE: &str = "delete";
const PERM_WATCH: &str = "watch";

const OP_PUT: u32 = 1;
const OP_DELETE: u32 = 2;

const SCAN_CHUNK_SIZE: usize = 256;

pub struct GrpcApi {
    inner: Arc<NodeService>,
}

impl GrpcApi {
    pub fn new(inner: Arc<NodeService>) -> Self {
        Self { inner }
    }

    #[inline]
    fn enforce_key_size(&self, key: &[u8]) -> Result<(), Status> {
        let max = self.inner.config.limits.max_key_size;
        if key.len() > max {
            return Err(Status::invalid_argument(format!(
                "key size {} exceeds limit {}",
                key.len(),
                max
            )));
        }
        Ok(())
    }

    #[inline]
    fn enforce_value_size(&self, value: &[u8]) -> Result<(), Status> {
        let max = self.inner.config.limits.max_value_size;
        if value.len() > max {
            return Err(Status::resource_exhausted(format!(
                "value size {} exceeds limit {}",
                value.len(),
                max
            )));
        }
        Ok(())
    }

    #[inline]
    fn enforce_batch_size(&self, n: usize) -> Result<(), Status> {
        let max = self.inner.config.limits.max_batch_ops;
        if n > max {
            return Err(Status::invalid_argument(format!(
                "batch size {n} exceeds limit {max}"
            )));
        }
        Ok(())
    }

    #[inline]
    fn cap_scan_limit(&self, requested: u32) -> u32 {
        let max = self.inner.config.limits.max_scan_limit;
        if requested == 0 || requested > max {
            max
        } else {
            requested
        }
    }
}

#[inline]
fn to_status(e: Error) -> Status {
    match e {
        Error::NotFound(_) => Status::not_found(e.to_string()),
        Error::NotLeader { .. } => Status::failed_precondition(e.to_string()),
        Error::UnknownTenant(_) => Status::unauthenticated(e.to_string()),
        Error::NotOwner(_) => Status::failed_precondition(e.to_string()),
        // Both are the client's problem and both are retryable, which is what
        // ResourceExhausted means — unlike the size limits above, waiting or
        // deleting actually helps here.
        Error::QuotaExceeded { .. } | Error::RateLimited { .. } => {
            Status::resource_exhausted(e.to_string())
        }
        // A request whose cost exceeds the tenant's entire per-second allowance
        // arrives here: no wait admits it, so calling it a rate limit would send
        // the client into a retry loop that can never succeed.
        Error::Config(_) => Status::invalid_argument(e.to_string()),
        Error::Corrupt(_) | Error::Storage(_) | Error::Io(_) => Status::internal(e.to_string()),
    }
}

#[inline]
fn check_tenant(t: &str) -> Result<(), Status> {
    if t.is_empty() {
        return Err(Status::invalid_argument("tenant must not be empty"));
    }
    if t.len() > 255 {
        return Err(Status::invalid_argument("tenant exceeds 255 bytes"));
    }
    Ok(())
}

fn authorize<T>(req: &Request<T>, tenant: &str, perm: &str) -> Result<(), Status> {
    let principal = req
        .extensions()
        .get::<Principal>()
        .ok_or_else(|| Status::internal("auth layer missing"))?;

    if let Some(claim_tenant) = principal.tenant() {
        if claim_tenant != tenant {
            return Err(Status::permission_denied(format!(
                "tenant {tenant} not authorized for this principal"
            )));
        }
    }

    if !principal.allows(perm) {
        return Err(Status::permission_denied(format!(
            "permission {perm} required"
        )));
    }
    Ok(())
}

#[inline]
fn encode_data_key(tenant: &str, payload: &[u8]) -> Result<Bytes, Status> {
    KeyCodec::encode(tenant, Subspace::Data, payload).map_err(to_status)
}

struct ScanBounds {
    start: Bytes,
    end: Bytes,
    strip_len: usize,
}

fn encode_data_scan_bounds(tenant: &str, user_prefix: &[u8]) -> Result<ScanBounds, Status> {
    let sub_prefix = KeyCodec::encode_subspace_prefix(tenant, Subspace::Data).map_err(to_status)?;
    let strip_len = sub_prefix.len();
    let mut start = BytesMut::with_capacity(sub_prefix.len() + user_prefix.len());
    start.put_slice(&sub_prefix);
    start.put_slice(user_prefix);
    let end = next_prefix_bound(&start);
    Ok(ScanBounds {
        start: start.freeze(),
        end,
        strip_len,
    })
}

fn next_prefix_bound(prefix: &[u8]) -> Bytes {
    let mut end = prefix.to_vec();
    while let Some(&last) = end.last() {
        if last == 0xFF {
            end.pop();
        } else {
            *end.last_mut().expect("non-empty") = last + 1;
            return Bytes::from(end);
        }
    }
    Bytes::new()
}

#[inline]
fn record_rpc<T>(rpc: &'static str, tenant: &str, start: Instant, result: &Result<T, Status>) {
    let code = result
        .as_ref()
        .err()
        .map(|s| s.code())
        .unwrap_or(tonic::Code::Ok);
    let code_label = format!("{code:?}");
    let tenant_label = tenant.to_string();

    metrics::counter!(
        "ferriskv_rpc_requests_total",
        "rpc" => rpc,
        "tenant" => tenant_label.clone(),
        "code" => code_label.clone(),
    )
    .increment(1);

    metrics::histogram!(
        "ferriskv_rpc_duration_seconds",
        "rpc" => rpc,
        "tenant" => tenant_label,
        "code" => code_label,
    )
    .record(start.elapsed().as_secs_f64());
}

#[inline]
fn to_watch_event(change: KeyChange) -> WatchEvent {
    let kind = match change.kind {
        ChangeKind::Put => WatchEventKind::Put,
        ChangeKind::Delete => WatchEventKind::Delete,
    };
    WatchEvent {
        kind: kind as i32,
        key: change.key,
        value: change.value,
        // Filled in once MVCC gives writes a version (#22).
        version: 0,
    }
}

#[inline]
fn heartbeat_event() -> WatchEvent {
    WatchEvent {
        kind: WatchEventKind::Heartbeat as i32,
        key: Bytes::new(),
        value: Bytes::new(),
        version: 0,
    }
}

/// Keeps the active-stream gauge honest even when a client disappears.
///
/// A `Watch` stream ends by being dropped — the client goes away, the server
/// shuts down, a proxy times out — and none of those run any code in the
/// handler. Tying the decrement to a guard's `Drop` is the only version of this
/// that cannot drift.
struct StreamGauge;

impl StreamGauge {
    fn new() -> Self {
        metrics::gauge!("ferriskv_watch_streams").increment(1.0);
        Self
    }
}

impl Drop for StreamGauge {
    fn drop(&mut self) {
        metrics::gauge!("ferriskv_watch_streams").decrement(1.0);
    }
}

struct WatchState {
    rx: Receiver<KeyChange>,
    prefix: Bytes,
    heartbeat: Duration,
    /// When the next heartbeat is due, as an absolute deadline.
    ///
    /// Absolute rather than a fresh relative sleep per loop iteration, because
    /// the loop also spins on events filtered out by the prefix. A relative
    /// timer would be reset by each of those, so a tenant with heavy traffic
    /// outside a subscriber's prefix would starve that subscriber of heartbeats
    /// entirely — the one case where it most needs to know the stream is alive.
    next_beat: TokioInstant,
    tenant: String,
    _gauge: StreamGauge,
}

impl WatchState {
    fn defer_heartbeat(&mut self) {
        self.next_beat = TokioInstant::now() + self.heartbeat;
    }
}

/// Turns a tenant's change feed into the client's event stream.
///
/// Filters to the requested prefix, and emits a heartbeat whenever the feed has
/// been quiet for `heartbeat`, so a client can distinguish an idle keyspace from
/// a connection that died silently.
fn watch_stream(state: WatchState) -> impl Stream<Item = Result<WatchEvent, Status>> + Send {
    futures::stream::unfold(Some(state), |state| async move {
        let mut state = state?;
        loop {
            let idle = tokio::time::sleep_until(state.next_beat);
            tokio::pin!(idle);

            tokio::select! {
                _ = &mut idle => {
                    metrics::counter!(
                        "ferriskv_watch_events_total",
                        "kind" => "heartbeat",
                        "tenant" => state.tenant.clone(),
                    )
                    .increment(1);
                    state.defer_heartbeat();
                    return Some((Ok(heartbeat_event()), Some(state)));
                }
                received = state.rx.recv() => match received {
                    Ok(change) => {
                        if !change.key.starts_with(&state.prefix) {
                            continue;
                        }
                        let kind = match change.kind {
                            ChangeKind::Put => "put",
                            ChangeKind::Delete => "delete",
                        };
                        metrics::counter!(
                            "ferriskv_watch_events_total",
                            "kind" => kind,
                            "tenant" => state.tenant.clone(),
                        )
                        .increment(1);
                        // A delivered event proves the stream is alive just as
                        // well as a heartbeat would, so the next beat moves out.
                        state.defer_heartbeat();
                        return Some((Ok(to_watch_event(change)), Some(state)));
                    }
                    // The subscriber outran the buffer. Continuing would hand it
                    // a keyspace with holes it has no way to detect, so the
                    // stream ends and says how much it lost: the client's only
                    // correct move is to re-read and resubscribe.
                    Err(RecvError::Lagged(missed)) => {
                        metrics::counter!(
                            "ferriskv_watch_lagged_total",
                            "tenant" => state.tenant.clone(),
                        )
                        .increment(1);
                        tracing::warn!(
                            tenant = %state.tenant,
                            missed,
                            "watch stream fell behind and was terminated",
                        );
                        return Some((
                            Err(Status::data_loss(format!(
                                "watch fell behind by {missed} events; re-read and resubscribe"
                            ))),
                            None,
                        ));
                    }
                    // Only reachable once the hub itself is gone, i.e. the node
                    // is shutting down.
                    Err(RecvError::Closed) => return None,
                },
            }
        }
    })
}

impl GrpcApi {
    /// Charges `cost` operations to the tenant's rate limit.
    ///
    /// Called after authorization and before any storage access: an unauthorized
    /// caller must not be able to spend a tenant's allowance, and an admitted
    /// one must not be able to do work it will then be refused for.
    #[inline]
    fn admit(&self, tenant: &str, cost: u32) -> Result<(), Status> {
        self.inner.admit(tenant, cost).map_err(to_status)
    }

    async fn get_impl(&self, req: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_READ)?;
        self.admit(&req.get_ref().tenant, 1)?;
        let r = req.into_inner();
        self.enforce_key_size(&r.key)?;
        let k = encode_data_key(&r.tenant, &r.key)?;
        let value = self.inner.get(&k).map_err(to_status)?;
        Ok(Response::new(match value {
            Some(v) => {
                metrics::histogram!("ferriskv_value_bytes", "op" => "get").record(v.len() as f64);
                GetResponse {
                    found: true,
                    value: v,
                    version: 0,
                }
            }
            None => GetResponse {
                found: false,
                value: Default::default(),
                version: 0,
            },
        }))
    }

    async fn put_impl(&self, req: Request<PutRequest>) -> Result<Response<PutResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_WRITE)?;
        self.admit(&req.get_ref().tenant, 1)?;
        let principal = req
            .extensions()
            .get::<Principal>()
            .cloned()
            .unwrap_or(Principal::Anonymous);
        let r = req.into_inner();
        self.enforce_key_size(&r.key)?;
        self.enforce_value_size(&r.value)?;
        let value_size = r.value.len();
        metrics::histogram!("ferriskv_value_bytes", "op" => "put").record(value_size as f64);
        let k = encode_data_key(&r.tenant, &r.key)?;
        self.inner
            .put_with_ttl(&k, &r.value, r.ttl_ms)
            .map_err(to_status)?;
        audit::write(&principal, &r.tenant, "put", &r.key, value_size);
        Ok(Response::new(PutResponse { version: 0 }))
    }

    async fn delete_impl(
        &self,
        req: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_DELETE)?;
        self.admit(&req.get_ref().tenant, 1)?;
        let principal = req
            .extensions()
            .get::<Principal>()
            .cloned()
            .unwrap_or(Principal::Anonymous);
        let r = req.into_inner();
        self.enforce_key_size(&r.key)?;
        let k = encode_data_key(&r.tenant, &r.key)?;
        let found = self.inner.get(&k).map_err(to_status)?.is_some();
        self.inner.delete(&k).map_err(to_status)?;
        audit::write(&principal, &r.tenant, "delete", &r.key, 0);
        Ok(Response::new(DeleteResponse { found }))
    }

    async fn scan_impl(
        &self,
        req: Request<ScanRequest>,
    ) -> Result<Response<<Self as FerrisKv>::ScanStream>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_READ)?;
        self.admit(&req.get_ref().tenant, 1)?;
        let r = req.into_inner();
        let bounds = encode_data_scan_bounds(&r.tenant, &r.prefix)?;

        let iter = self
            .inner
            .scan_range(&bounds.start, &bounds.end)
            .map_err(to_status)?;

        let limit = self.cap_scan_limit(r.limit) as usize;

        let mut chunks: Vec<Result<ScanChunk, Status>> = Vec::new();
        let mut current: Vec<KeyValue> = Vec::with_capacity(SCAN_CHUNK_SIZE);
        let mut total_entries: u64 = 0;
        for (k, v) in iter.take(limit) {
            let user_key = k.slice(bounds.strip_len..);
            current.push(KeyValue {
                key: user_key,
                value: v,
            });
            total_entries += 1;
            if current.len() >= SCAN_CHUNK_SIZE {
                chunks.push(Ok(ScanChunk {
                    entries: std::mem::take(&mut current),
                }));
            }
        }
        if !current.is_empty() {
            chunks.push(Ok(ScanChunk { entries: current }));
        }
        metrics::histogram!("ferriskv_scan_entries").record(total_entries as f64);
        Ok(Response::new(futures::stream::iter(chunks)))
    }

    /// Streams changes to a tenant's keys under `prefix`.
    ///
    /// The stream starts from now. There is no history to replay from: the node
    /// has no version to seek to until MVCC lands (#22), so a client that needs
    /// a consistent starting point scans first and then watches, accepting the
    /// overlap. Subscribing before the scan is the safer order, since an event
    /// seen twice is recoverable and one missed is not.
    async fn watch_impl(
        &self,
        req: Request<WatchRequest>,
    ) -> Result<Response<<Self as FerrisKv>::WatchStream>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        authorize(&req, &req.get_ref().tenant, PERM_WATCH)?;
        self.admit(&req.get_ref().tenant, 1)?;
        let r = req.into_inner();
        self.enforce_key_size(&r.prefix)?;

        let rx = self.inner.watch.subscribe(&r.tenant);
        tracing::debug!(
            tenant = %r.tenant,
            prefix_len = r.prefix.len(),
            "watch stream opened",
        );

        let heartbeat = Duration::from_secs(self.inner.config.watch_heartbeat_secs);
        let state = WatchState {
            rx,
            prefix: r.prefix,
            heartbeat,
            next_beat: TokioInstant::now() + heartbeat,
            tenant: r.tenant,
            _gauge: StreamGauge::new(),
        };
        Ok(Response::new(Box::pin(watch_stream(state))))
    }

    async fn batch_impl(
        &self,
        req: Request<BatchRequest>,
    ) -> Result<Response<BatchResponse>, Status> {
        check_tenant(&req.get_ref().tenant)?;
        let needs_write = req.get_ref().ops.iter().any(|o| o.op == OP_PUT);
        let needs_delete = req.get_ref().ops.iter().any(|o| o.op == OP_DELETE);
        let tenant = req.get_ref().tenant.clone();
        if needs_write {
            authorize(&req, &tenant, PERM_WRITE)?;
        }
        if needs_delete {
            authorize(&req, &tenant, PERM_DELETE)?;
        }
        let principal = req
            .extensions()
            .get::<Principal>()
            .cloned()
            .unwrap_or(Principal::Anonymous);
        let r = req.into_inner();
        self.enforce_batch_size(r.ops.len())?;
        // The cost is the number of operations, not one for the RPC. Charging
        // per call would let a client bypass its rate limit entirely by
        // batching, which is the one loophole a limit on a batching API cannot
        // have. Charged after the size check so an oversized batch is refused
        // for its size rather than for its cost.
        self.admit(&r.tenant, u32::try_from(r.ops.len()).unwrap_or(u32::MAX))?;
        for op in r.ops {
            self.enforce_key_size(&op.key)?;
            if op.op == OP_PUT {
                self.enforce_value_size(&op.value)?;
            }
            let value_size = op.value.len();
            let k = encode_data_key(&r.tenant, &op.key)?;
            let op_name = match op.op {
                OP_PUT => {
                    metrics::histogram!("ferriskv_value_bytes", "op" => "put")
                        .record(value_size as f64);
                    self.inner
                        .put_with_ttl(&k, &op.value, 0)
                        .map_err(to_status)?;
                    "put"
                }
                OP_DELETE => {
                    self.inner.delete(&k).map_err(to_status)?;
                    "delete"
                }
                other => return Err(Status::invalid_argument(format!("unknown op code {other}"))),
            };
            audit::write(&principal, &r.tenant, op_name, &op.key, value_size);
        }
        Ok(Response::new(BatchResponse { ok: true }))
    }
}

#[tonic::async_trait]
impl FerrisKv for GrpcApi {
    async fn get(&self, req: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let start = Instant::now();
        let tenant = req.get_ref().tenant.clone();
        let result = self.get_impl(req).await;
        record_rpc("get", &tenant, start, &result);
        result
    }

    async fn put(&self, req: Request<PutRequest>) -> Result<Response<PutResponse>, Status> {
        let start = Instant::now();
        let tenant = req.get_ref().tenant.clone();
        let result = self.put_impl(req).await;
        record_rpc("put", &tenant, start, &result);
        result
    }

    async fn delete(
        &self,
        req: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let start = Instant::now();
        let tenant = req.get_ref().tenant.clone();
        let result = self.delete_impl(req).await;
        record_rpc("delete", &tenant, start, &result);
        result
    }

    type ScanStream = Iter<std::vec::IntoIter<Result<ScanChunk, Status>>>;

    async fn scan(&self, req: Request<ScanRequest>) -> Result<Response<Self::ScanStream>, Status> {
        let start = Instant::now();
        let tenant = req.get_ref().tenant.clone();
        let result = self.scan_impl(req).await;
        record_rpc("scan", &tenant, start, &result);
        result
    }

    // Boxed rather than a named type: the stream is a `select!` over a
    // broadcast receiver and a timer, which has no nameable type.
    type WatchStream = Pin<Box<dyn Stream<Item = Result<WatchEvent, Status>> + Send>>;

    async fn watch(
        &self,
        req: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let start = Instant::now();
        let tenant = req.get_ref().tenant.clone();
        let result = self.watch_impl(req).await;
        record_rpc("watch", &tenant, start, &result);
        result
    }

    async fn batch(&self, req: Request<BatchRequest>) -> Result<Response<BatchResponse>, Status> {
        let start = Instant::now();
        let tenant = req.get_ref().tenant.clone();
        let result = self.batch_impl(req).await;
        record_rpc("batch", &tenant, start, &result);
        result
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::sync::broadcast;

    use super::*;

    fn change(kind: ChangeKind, key: &'static str) -> KeyChange {
        KeyChange {
            kind,
            key: Bytes::from_static(key.as_bytes()),
            value: Bytes::from_static(b"v"),
        }
    }

    fn state(rx: Receiver<KeyChange>, prefix: &'static [u8], heartbeat_ms: u64) -> WatchState {
        let heartbeat = Duration::from_millis(heartbeat_ms);
        WatchState {
            rx,
            prefix: Bytes::from_static(prefix),
            heartbeat,
            next_beat: TokioInstant::now() + heartbeat,
            tenant: "alice".to_string(),
            _gauge: StreamGauge::new(),
        }
    }

    /// A stream that falls behind must report it, and reporting it must end the
    /// stream.
    ///
    /// This is unit-tested rather than driven through gRPC on purpose: HTTP/2
    /// flow control buffers a burst of small events, so an integration test
    /// cannot reliably make a subscriber lag. It would pass for the wrong reason
    /// today and stop testing anything the moment the buffer size changed.
    #[tokio::test]
    async fn a_lagging_stream_ends_with_data_loss() {
        let (tx, rx) = broadcast::channel(2);
        for i in 0..16 {
            tx.send(KeyChange {
                kind: ChangeKind::Put,
                key: Bytes::from(format!("k{i}")),
                value: Bytes::new(),
            })
            .unwrap();
        }

        let mut stream = Box::pin(watch_stream(state(rx, b"", 60_000)));
        let status = stream
            .next()
            .await
            .expect("the stream must yield the failure, not just end")
            .expect_err("a receiver 14 events behind a 2-event buffer must have lagged");
        assert_eq!(status.code(), tonic::Code::DataLoss);
        assert!(
            status.message().contains("resubscribe"),
            "the error has to tell the client what to do: {}",
            status.message(),
        );

        assert!(
            stream.next().await.is_none(),
            "a stream that lost events must not carry on as if it had not",
        );
    }

    #[tokio::test]
    async fn events_outside_the_prefix_never_reach_the_client() {
        let (tx, rx) = broadcast::channel(16);
        tx.send(change(ChangeKind::Put, "other:1")).unwrap();
        tx.send(change(ChangeKind::Put, "cacheless")).unwrap();
        tx.send(change(ChangeKind::Delete, "cache:hit")).unwrap();

        let mut stream = Box::pin(watch_stream(state(rx, b"cache:", 60_000)));
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.kind(), WatchEventKind::Delete);
        assert_eq!(&event.key[..], b"cache:hit");
    }

    #[tokio::test]
    async fn an_idle_stream_heartbeats_instead_of_going_quiet() {
        let (_tx, rx) = broadcast::channel(16);
        let mut stream = Box::pin(watch_stream(state(rx, b"", 20)));

        for _ in 0..2 {
            let event = stream.next().await.unwrap().unwrap();
            assert_eq!(event.kind(), WatchEventKind::Heartbeat);
            assert!(event.key.is_empty());
            assert!(event.value.is_empty());
        }
    }

    /// Traffic a subscriber filters out must not starve it of heartbeats.
    ///
    /// The filtered branch loops without yielding, so a heartbeat measured as a
    /// fresh delay per iteration would be reset by every non-matching event and
    /// never fire. A subscriber on a narrow prefix in a busy tenant would then
    /// go permanently silent — exactly when it most needs to know the stream is
    /// still alive.
    #[tokio::test]
    async fn a_flood_of_filtered_events_does_not_starve_the_heartbeat() {
        let (tx, rx) = broadcast::channel(256);
        let noise = tokio::spawn(async move {
            for i in 0..200 {
                if tx
                    .send(KeyChange {
                        kind: ChangeKind::Put,
                        key: Bytes::from(format!("elsewhere:{i}")),
                        value: Bytes::new(),
                    })
                    .is_err()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let mut stream = Box::pin(watch_stream(state(rx, b"mine:", 40)));
        let event = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .expect("no heartbeat arrived while filtered events kept flowing")
            .unwrap()
            .unwrap();
        assert_eq!(event.kind(), WatchEventKind::Heartbeat);
        noise.abort();
    }

    /// A quiet keyspace must not starve real events, and a busy one must not
    /// starve the heartbeat's own timer.
    #[tokio::test]
    async fn a_real_event_wins_over_a_pending_heartbeat() {
        let (tx, rx) = broadcast::channel(16);
        tx.send(change(ChangeKind::Put, "k")).unwrap();

        let mut stream = Box::pin(watch_stream(state(rx, b"", 60_000)));
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.kind(), WatchEventKind::Put);
        assert_eq!(&event.key[..], b"k");
    }

    #[tokio::test]
    async fn the_stream_ends_when_the_hub_goes_away() {
        let (tx, rx) = broadcast::channel(16);
        drop(tx);
        let mut stream = Box::pin(watch_stream(state(rx, b"", 60_000)));
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn a_delete_event_carries_no_value() {
        let event = to_watch_event(KeyChange {
            kind: ChangeKind::Delete,
            key: Bytes::from_static(b"gone"),
            value: Bytes::new(),
        });
        assert_eq!(event.kind(), WatchEventKind::Delete);
        assert!(event.value.is_empty());
        assert_eq!(event.version, 0);
    }
}
