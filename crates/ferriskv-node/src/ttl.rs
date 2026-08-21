use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ferriskv_core::{Storage, ValueCodec};
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::service::NodeService;

/// In-memory index of keys with a scheduled expiration time.
///
/// Maps an expiration timestamp to the set of keys expiring at that
/// timestamp. The sweeper consults this index to know what to delete and
/// when to wake up next, avoiding full keyspace scans.
pub struct TtlIndex {
    inner: Mutex<Inner>,
    notify: Arc<Notify>,
}

struct Inner {
    by_expiry: BTreeMap<u64, BTreeSet<Bytes>>,
    total: usize,
}

impl TtlIndex {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_expiry: BTreeMap::new(),
                total: 0,
            }),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Register that `key` will expire at `expires_at_ms`. Wakes the sweeper
    /// if this is now the earliest scheduled expiration.
    pub fn schedule(&self, key: Bytes, expires_at_ms: u64) {
        let wake = {
            let mut g = self.inner.lock();
            let was_earliest = g.by_expiry.keys().next().copied();
            let inserted = g.by_expiry.entry(expires_at_ms).or_default().insert(key);
            if inserted {
                g.total += 1;
            }
            was_earliest.map_or(true, |prev| expires_at_ms < prev)
        };
        if wake {
            self.notify.notify_one();
        }
    }

    /// Earliest scheduled expiration, if any.
    pub fn next_due_ms(&self) -> Option<u64> {
        self.inner.lock().by_expiry.keys().next().copied()
    }

    /// Pops every key with expiration `<= now_ms`. The caller verifies that
    /// each key is actually expired in storage before deleting it, because
    /// the key may have been overwritten with a later expiration since
    /// it was scheduled here.
    pub fn drain_due(&self, now_ms: u64) -> Vec<Bytes> {
        let mut g = self.inner.lock();
        let mut out = Vec::new();
        while let Some((&ts, _)) = g.by_expiry.first_key_value() {
            if ts > now_ms {
                break;
            }
            let (_, keys) = g.by_expiry.pop_first().expect("non-empty bucket");
            out.extend(keys);
        }
        g.total = g.total.saturating_sub(out.len());
        out
    }

    pub fn len(&self) -> usize {
        self.inner.lock().total
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn notify_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }
}

impl Default for TtlIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Async loop that wakes when the next scheduled expiration is due, when a
/// new earlier expiration is scheduled, or when `fallback_interval` elapses
/// since the last pass. On wakeup, it drains expired entries from the index
/// and removes them from storage.
///
/// Passing a zero `fallback_interval` disables the sweeper. The index is
/// still maintained and reads still filter expired entries, so disk grows
/// unbounded for expired-but-not-read keys; use only for tests.
pub async fn run_sweeper<F>(service: Arc<NodeService>, fallback_interval: Duration, shutdown: F)
where
    F: Future<Output = ()>,
{
    if fallback_interval.is_zero() {
        tracing::info!("ttl sweeper disabled (interval = 0)");
        return;
    }

    let notify = service.ttl_index.notify_handle();
    tracing::info!(
        interval_secs = fallback_interval.as_secs(),
        index_size = service.ttl_index.len(),
        "ttl sweeper started",
    );

    tokio::pin!(shutdown);
    loop {
        let wake_at = compute_wakeup(&service, fallback_interval);
        let sleep = tokio::time::sleep_until(wake_at);
        tokio::pin!(sleep);

        tokio::select! {
            _ = &mut sleep => {}
            _ = notify.notified() => {}
            _ = &mut shutdown => {
                tracing::info!("ttl sweeper shutting down");
                break;
            }
        }

        let removed = sweep_once(&service);
        if removed > 0 {
            tracing::info!(removed, "ttl sweeper evicted expired keys");
        }
        metrics::gauge!("ferriskv_ttl_index_size").set(service.ttl_index.len() as f64);
    }
}

fn compute_wakeup(service: &NodeService, fallback: Duration) -> Instant {
    let now = Instant::now();
    let fallback_at = now + fallback;

    match service.ttl_index.next_due_ms() {
        Some(due_ms) => {
            let clock_now = service.clock.now_ms();
            if due_ms <= clock_now {
                now
            } else {
                let delta = Duration::from_millis(due_ms - clock_now);
                std::cmp::min(now + delta, fallback_at)
            }
        }
        None => fallback_at,
    }
}

/// Performs one sweep pass: drains the index and deletes expired keys from
/// storage. Verifies the actual expiration in storage to stay safe against
/// concurrent writes that may have rescheduled a key.
pub fn sweep_once(service: &NodeService) -> usize {
    let started = std::time::Instant::now();
    let now_ms = service.clock.now_ms();
    let candidates = service.ttl_index.drain_due(now_ms);

    let mut removed = 0u64;
    for key in &candidates {
        match service.storage.get(key) {
            Ok(Some(raw)) => match ValueCodec::is_expired(&raw, now_ms) {
                // Through the service rather than straight to storage, so an
                // eviction is a real delete: it gets a WAL record, and watchers
                // are told. A watcher whose keys vanish without an event would
                // hold a view of the keyspace that silently diverges.
                Ok(true) => match service.delete(key) {
                    Ok(()) => removed += 1,
                    Err(e) => tracing::warn!(error = %e, "ttl sweeper: delete failed"),
                },
                Ok(false) => {
                    if let Ok(sv) = ValueCodec::decode(raw) {
                        if let Some(exp) = sv.expires_at_ms {
                            service.ttl_index.schedule(key.clone(), exp);
                        }
                    }
                }
                Err(_) => {}
            },
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "ttl sweeper: storage get failed"),
        }
    }

    metrics::counter!("ferriskv_ttl_evicted_total").increment(removed);
    metrics::histogram!("ferriskv_ttl_sweep_duration_seconds")
        .record(started.elapsed().as_secs_f64());

    removed as usize
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use ferriskv_core::{Clock, KeyCodec, Subspace};
    use tempfile::TempDir;

    use super::*;
    use crate::config::{AuthConfig, Backend};
    use crate::watch::ChangeKind;
    use crate::{NodeConfig, NodeService};

    #[test]
    fn schedule_then_drain_returns_keys_in_order() {
        let idx = TtlIndex::new();
        idx.schedule(Bytes::from_static(b"a"), 200);
        idx.schedule(Bytes::from_static(b"b"), 100);
        idx.schedule(Bytes::from_static(b"c"), 300);

        let due = idx.drain_due(150);
        assert_eq!(due.len(), 1);
        assert_eq!(&due[0][..], b"b");

        let due = idx.drain_due(250);
        assert_eq!(due.len(), 1);
        assert_eq!(&due[0][..], b"a");

        let due = idx.drain_due(500);
        assert_eq!(due.len(), 1);
        assert_eq!(&due[0][..], b"c");
    }

    #[test]
    fn next_due_reflects_earliest() {
        let idx = TtlIndex::new();
        assert_eq!(idx.next_due_ms(), None);
        idx.schedule(Bytes::from_static(b"a"), 500);
        assert_eq!(idx.next_due_ms(), Some(500));
        idx.schedule(Bytes::from_static(b"b"), 100);
        assert_eq!(idx.next_due_ms(), Some(100));
        idx.schedule(Bytes::from_static(b"c"), 1000);
        assert_eq!(idx.next_due_ms(), Some(100));
    }

    #[test]
    fn drain_does_not_include_future_expirations() {
        let idx = TtlIndex::new();
        idx.schedule(Bytes::from_static(b"now"), 100);
        idx.schedule(Bytes::from_static(b"later"), 1000);

        let due = idx.drain_due(500);
        assert_eq!(due.len(), 1);
        assert_eq!(&due[0][..], b"now");
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.next_due_ms(), Some(1000));
    }

    #[test]
    fn duplicate_schedule_is_idempotent() {
        let idx = TtlIndex::new();
        idx.schedule(Bytes::from_static(b"k"), 100);
        idx.schedule(Bytes::from_static(b"k"), 100);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn notify_fires_on_earlier_expiration() {
        let idx = TtlIndex::new();
        idx.schedule(Bytes::from_static(b"late"), 1_000_000);
        let notify = idx.notify_handle();

        idx.schedule(Bytes::from_static(b"early"), 100);

        let permit = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                tokio::time::timeout(Duration::from_millis(50), notify.notified()).await
            });
        assert!(permit.is_ok());
    }

    fn cfg(dir: &TempDir) -> NodeConfig {
        NodeConfig {
            node_id: Arc::<str>::from("n0"),
            listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            data_dir: dir.path().to_path_buf(),
            coord_endpoints: Vec::new(),
            backend: Backend::Memory,
            limits: ferriskv_core::Limits::default(),
            auth: AuthConfig {
                insecure: true,
                ..Default::default()
            },
            tls: None,
            admin_listen: None,
            ttl_sweep_interval_secs: 0,
            shutdown_timeout_secs: 5,
            wal_rotate_bytes: 64 * 1024 * 1024,
            watch_buffer: 1024,
            watch_heartbeat_secs: 30,
        }
    }

    #[test]
    fn sweep_removes_expired_and_keeps_alive() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        let svc = NodeService::open_with_clock(cfg(&dir), clock.clone()).unwrap();
        svc.put_with_ttl(b"a", b"alive", 0).unwrap();
        svc.put_with_ttl(b"b", b"short", 100).unwrap();
        svc.put_with_ttl(b"c", b"long", 1_000_000).unwrap();

        clock.advance(200);
        let removed = sweep_once(&svc);
        assert_eq!(removed, 1);

        let remaining: Vec<_> = svc.scan(b"").unwrap().collect();
        let keys: Vec<&[u8]> = remaining.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&b"a".as_ref()));
        assert!(keys.contains(&b"c".as_ref()));
    }

    #[test]
    fn an_eviction_is_announced_to_watchers() {
        // A key that disappears on its own is the one case a watcher cannot
        // discover for itself: no client wrote anything, so without an event its
        // view of the keyspace silently diverges from the node's.
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        let svc = NodeService::open_with_clock(cfg(&dir), clock.clone()).unwrap();

        let mut rx = svc.watch.subscribe("alice");
        let key = KeyCodec::encode("alice", Subspace::Data, b"ephemeral").unwrap();
        svc.put_with_ttl(&key, b"v", 100).unwrap();
        assert_eq!(rx.try_recv().unwrap().kind, ChangeKind::Put);

        clock.advance(200);
        assert_eq!(sweep_once(&svc), 1);

        let event = rx.try_recv().expect("the eviction must be published");
        assert_eq!(event.kind, ChangeKind::Delete);
        assert_eq!(&event.key[..], b"ephemeral");
        assert!(event.value.is_empty());
    }

    #[test]
    fn an_eviction_is_recorded_in_the_wal() {
        // Going through the service rather than straight to storage is what
        // gives the eviction a WAL record. Without one, replay after a crash
        // would resurrect the key.
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        let svc = NodeService::open_with_clock(cfg(&dir), clock.clone()).unwrap();
        svc.put_with_ttl(b"k", b"v", 100).unwrap();
        let before = svc.wal.next_seq();

        clock.advance(200);
        assert_eq!(sweep_once(&svc), 1);
        assert_eq!(
            svc.wal.next_seq(),
            before + 1,
            "the eviction must append exactly one record",
        );
    }

    #[test]
    fn sweep_reschedules_overwritten_key_with_longer_ttl() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        let svc = NodeService::open_with_clock(cfg(&dir), clock.clone()).unwrap();

        svc.put_with_ttl(b"k", b"v1", 100).unwrap();
        // Overwrite with a much longer TTL before the first expiration kicks in.
        svc.put_with_ttl(b"k", b"v2", 1_000_000).unwrap();

        clock.advance(200);
        let removed = sweep_once(&svc);
        assert_eq!(removed, 0);
        assert_eq!(svc.get(b"k").unwrap().as_deref(), Some(&b"v2"[..]));

        // The index should still hold the new expiration.
        assert!(svc.ttl_index.next_due_ms().is_some());
    }

    #[test]
    fn sweep_is_silent_when_index_is_empty() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        let svc = NodeService::open_with_clock(cfg(&dir), clock).unwrap();
        let removed = sweep_once(&svc);
        assert_eq!(removed, 0);
    }
}
