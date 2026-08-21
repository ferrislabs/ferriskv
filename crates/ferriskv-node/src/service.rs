use std::sync::Arc;

use bytes::Bytes;
use ferriskv_core::{
    Clock, FjallStorage, MemStorage, ScanIter, Storage, StorageBackend, ValueCodec,
};

use crate::config::{Backend, NodeConfig};
use crate::ttl::TtlIndex;
use crate::wal::{Wal, WalOp, WalRecord};

pub struct NodeService {
    pub config: NodeConfig,
    pub storage: Arc<StorageBackend>,
    pub wal: Arc<Wal>,
    pub clock: Clock,
    pub ttl_index: Arc<TtlIndex>,
}

impl NodeService {
    pub fn open(config: NodeConfig) -> ferriskv_core::Result<Self> {
        Self::open_with_clock(config, Clock::system())
    }

    pub fn open_with_clock(config: NodeConfig, clock: Clock) -> ferriskv_core::Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let backend = match config.backend {
            Backend::Memory => StorageBackend::Memory(MemStorage::new()),
            Backend::Fjall => {
                let path = config.data_dir.join("fjall");
                StorageBackend::Fjall(FjallStorage::open(path, "default")?)
            }
        };
        let storage = Arc::new(backend);

        let (wal, recovery) = Wal::open(config.data_dir.join("wal.log"))?;
        if recovery.truncated_bytes > 0 {
            tracing::warn!(
                bytes = recovery.truncated_bytes,
                "discarded a torn WAL tail, the process did not exit cleanly",
            );
        }
        let replayed = replay(&storage, &recovery.records)?;
        if replayed > 0 {
            tracing::info!(records = replayed, "replayed WAL records into storage");
        }
        // Everything the segment holds is now in storage, so the segment is
        // redundant — but only once storage has actually made it durable.
        //
        // Unlike the same operation on the write path, a failure here is fatal:
        // at startup nobody is waiting on a write, and a disk that cannot fsync
        // is better met with a node that refuses to boot than with one that
        // serves reads it will not be able to keep.
        if storage.is_durable() {
            storage.flush()?;
            wal.rotate()?;
        }

        let ttl_index = Arc::new(TtlIndex::new());
        let bootstrap = bootstrap_ttl_index(&storage, &ttl_index)?;
        tracing::info!(count = bootstrap, "ttl index bootstrapped");

        Ok(Self {
            config,
            storage,
            wal: Arc::new(wal),
            clock,
            ttl_index,
        })
    }

    /// Rotates the WAL once the segment grows past `wal_rotate_bytes`.
    ///
    /// Without this the log would grow for the whole uptime of the node, since
    /// nothing else ever shortens it. The fsync it costs is amortised over a
    /// segment's worth of writes; against a non-durable backend the log is the
    /// only copy of the data, so rotation is simply not available.
    ///
    /// Failures are logged, not propagated. Rotation is housekeeping that runs
    /// after the caller's write is already in the log, so surfacing its error
    /// would tell the caller their write failed when it did not. The cost of
    /// staying quiet is a segment that keeps growing, which the warning names.
    fn rotate_wal_if_needed(&self) {
        if !self.storage.is_durable() {
            return;
        }
        let size = self.wal.segment_bytes();
        if size < self.config.wal_rotate_bytes {
            return;
        }
        if let Err(e) = self.storage.flush().and_then(|()| self.wal.rotate()) {
            tracing::warn!(
                error = %e,
                segment_bytes = size,
                "WAL rotation failed, the segment will keep growing",
            );
            return;
        }
        tracing::debug!(previous_bytes = size, "rotated WAL segment");
    }

    #[inline]
    pub fn storage(&self) -> &StorageBackend {
        &self.storage
    }

    pub fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl_ms: u64) -> ferriskv_core::Result<()> {
        let expires_at = if ttl_ms > 0 {
            Some(self.clock.now_ms().saturating_add(ttl_ms))
        } else {
            None
        };
        let encoded = ValueCodec::encode(value, expires_at);
        self.wal.append(WalOp::Put, key, &encoded)?;
        self.storage.put(key, encoded)?;
        if let Some(exp) = expires_at {
            self.ttl_index.schedule(Bytes::copy_from_slice(key), exp);
        }
        self.rotate_wal_if_needed();
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> ferriskv_core::Result<Option<Bytes>> {
        match self.storage.get(key)? {
            None => Ok(None),
            Some(raw) => {
                if ValueCodec::is_expired(&raw, self.clock.now_ms())? {
                    Ok(None)
                } else {
                    Ok(Some(ValueCodec::decode(raw)?.value))
                }
            }
        }
    }

    pub fn delete(&self, key: &[u8]) -> ferriskv_core::Result<()> {
        self.wal.append(WalOp::Delete, key, &[])?;
        self.storage.delete(key)?;
        self.rotate_wal_if_needed();
        Ok(())
    }

    pub fn scan(&self, prefix: &[u8]) -> ferriskv_core::Result<ScanIter> {
        let raw = self.storage.scan(prefix)?;
        Ok(self.filter_scan(raw))
    }

    pub fn scan_range(&self, start: &[u8], end: &[u8]) -> ferriskv_core::Result<ScanIter> {
        let raw = self.storage.scan_range(start, end)?;
        Ok(self.filter_scan(raw))
    }

    fn filter_scan(&self, raw: ScanIter) -> ScanIter {
        let now = self.clock.now_ms();
        let filtered: Vec<(Bytes, Bytes)> = raw
            .filter_map(|(k, v)| match ValueCodec::is_expired(&v, now) {
                Ok(true) => None,
                Ok(false) => ValueCodec::decode(v).ok().map(|sv| (k, sv.value)),
                Err(_) => None,
            })
            .collect();
        filtered.into_iter()
    }
}

/// Re-applies the records a segment still holds, in write order.
///
/// No checkpoint is needed to make this safe. A segment is only ever rotated
/// after storage has been fsynced, so what remains is exactly the suffix
/// storage may be missing — and re-applying a record that did land is a no-op,
/// since the frame carries the encoded value byte for byte, TTL stamp included.
fn replay(storage: &StorageBackend, records: &[WalRecord]) -> ferriskv_core::Result<usize> {
    for record in records {
        match record.op {
            WalOp::Put => storage.put(&record.key, record.value.clone())?,
            WalOp::Delete => storage.delete(&record.key)?,
        }
    }
    Ok(records.len())
}

fn bootstrap_ttl_index(storage: &StorageBackend, index: &TtlIndex) -> ferriskv_core::Result<usize> {
    let mut count = 0usize;
    for (k, v) in storage.scan(b"")? {
        if let Ok(sv) = ValueCodec::decode(v) {
            if let Some(exp) = sv.expires_at_ms {
                index.schedule(k, exp);
                count += 1;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use ferriskv_core::Clock;
    use tempfile::TempDir;

    use super::*;
    use crate::config::Backend;

    fn config(dir: &TempDir, backend: Backend) -> NodeConfig {
        NodeConfig {
            node_id: Arc::<str>::from("n0"),
            listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            data_dir: dir.path().to_path_buf(),
            coord_endpoints: Vec::new(),
            backend,
            limits: ferriskv_core::Limits::default(),
            auth: crate::config::AuthConfig {
                insecure: true,
                ..Default::default()
            },
            tls: None,
            admin_listen: None,
            ttl_sweep_interval_secs: 0,
            shutdown_timeout_secs: 5,
            wal_rotate_bytes: 64 * 1024 * 1024,
        }
    }

    #[test]
    fn opens_memory_backend_and_writes_through_wal() {
        let dir = TempDir::new().unwrap();
        let svc = NodeService::open(config(&dir, Backend::Memory)).unwrap();
        svc.put_with_ttl(b"k", b"v", 0).unwrap();
        svc.delete(b"k").unwrap();
        assert!(dir.path().join("wal.log").exists());
    }

    #[test]
    fn replay_is_idempotent() {
        // Replaying the same records twice must land on the same state, which
        // is what lets recovery run without tracking what storage already has.
        let storage = StorageBackend::Memory(MemStorage::new());
        let records = vec![
            WalRecord {
                seq: 0,
                op: WalOp::Put,
                key: Bytes::from_static(b"a"),
                value: ValueCodec::encode(b"1", None),
            },
            WalRecord {
                seq: 1,
                op: WalOp::Put,
                key: Bytes::from_static(b"b"),
                value: ValueCodec::encode(b"2", None),
            },
            WalRecord {
                seq: 2,
                op: WalOp::Delete,
                key: Bytes::from_static(b"a"),
                value: Bytes::new(),
            },
        ];
        assert_eq!(replay(&storage, &records).unwrap(), 3);
        let once: Vec<_> = storage.scan(b"").unwrap().collect();
        replay(&storage, &records).unwrap();
        let twice: Vec<_> = storage.scan(b"").unwrap().collect();
        assert_eq!(once, twice);
        assert!(storage.get(b"a").unwrap().is_none());
    }

    #[test]
    fn opens_fjall_backend() {
        let dir = TempDir::new().unwrap();
        let svc = NodeService::open(config(&dir, Backend::Fjall)).unwrap();
        svc.put_with_ttl(b"k", b"v", 0).unwrap();
        assert_eq!(svc.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn put_with_ttl_populates_index() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(1_000);
        let svc =
            NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
        assert!(svc.ttl_index.is_empty());
        svc.put_with_ttl(b"a", b"alive", 0).unwrap();
        assert!(svc.ttl_index.is_empty(), "no TTL means no index entry");
        svc.put_with_ttl(b"b", b"short", 100).unwrap();
        assert_eq!(svc.ttl_index.len(), 1);
        assert_eq!(svc.ttl_index.next_due_ms(), Some(1_100));
    }

    #[test]
    fn scan_and_scan_range_filter_expired() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(1_000);
        let svc =
            NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
        svc.put_with_ttl(b"a", b"alive", 0).unwrap();
        svc.put_with_ttl(b"b", b"short", 100).unwrap();
        svc.put_with_ttl(b"c", b"long", 1_000_000).unwrap();

        let all: Vec<_> = svc.scan(b"").unwrap().collect();
        assert_eq!(all.len(), 3);

        clock.advance(200);

        let after: Vec<_> = svc.scan(b"").unwrap().collect();
        let keys: Vec<&[u8]> = after.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&b"a".as_ref()));
        assert!(keys.contains(&b"c".as_ref()));
    }

    #[test]
    fn get_returns_none_when_expired() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        let svc =
            NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
        svc.put_with_ttl(b"k", b"v", 50).unwrap();
        assert_eq!(svc.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
        clock.advance(100);
        assert!(svc.get(b"k").unwrap().is_none());
    }

    #[test]
    fn put_without_ttl_never_expires() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        let svc =
            NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
        svc.put_with_ttl(b"k", b"v", 0).unwrap();
        clock.advance(u64::MAX / 2);
        assert_eq!(svc.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn a_memory_backend_recovers_its_whole_state_from_the_wal() {
        // The memory backend keeps nothing across a restart, so whatever the
        // reopened node can read came from the WAL and nowhere else. That makes
        // it the sharpest available test of replay.
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(1_000);
        {
            let svc =
                NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
            svc.put_with_ttl(b"kept", b"v1", 0).unwrap();
            svc.put_with_ttl(b"overwritten", b"first", 0).unwrap();
            svc.put_with_ttl(b"overwritten", b"second", 0).unwrap();
            svc.put_with_ttl(b"removed", b"v", 0).unwrap();
            svc.delete(b"removed").unwrap();
            svc.wal.sync().unwrap();
        }

        let svc = NodeService::open_with_clock(config(&dir, Backend::Memory), clock).unwrap();
        assert_eq!(svc.get(b"kept").unwrap().as_deref(), Some(&b"v1"[..]));
        assert_eq!(
            svc.get(b"overwritten").unwrap().as_deref(),
            Some(&b"second"[..]),
            "records are applied in write order, so the last write wins",
        );
        assert!(
            svc.get(b"removed").unwrap().is_none(),
            "a delete record must be replayed too, not just the puts",
        );
    }

    #[test]
    fn replay_restores_the_ttl_stamp_and_not_a_fresh_one() {
        // The frame carries the encoded value, expiry included, so a key put
        // with 500ms of TTL before a restart must still expire at t=1500 —
        // replay must not restamp it relative to the restart.
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(1_000);
        {
            let svc =
                NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
            svc.put_with_ttl(b"short", b"v", 500).unwrap();
            svc.wal.sync().unwrap();
        }
        clock.advance(400);

        let svc =
            NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
        assert_eq!(svc.ttl_index.next_due_ms(), Some(1_500));
        assert_eq!(svc.get(b"short").unwrap().as_deref(), Some(&b"v"[..]));
        clock.advance(200);
        assert!(svc.get(b"short").unwrap().is_none());
    }

    #[test]
    fn a_torn_wal_tail_does_not_stop_the_node_from_starting() {
        use std::io::Write;

        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        {
            let svc =
                NodeService::open_with_clock(config(&dir, Backend::Memory), clock.clone()).unwrap();
            svc.put_with_ttl(b"a", b"1", 0).unwrap();
            svc.wal.sync().unwrap();
        }
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("wal.log"))
            .unwrap();
        f.write_all(b"half a frame").unwrap();
        drop(f);

        let svc = NodeService::open_with_clock(config(&dir, Backend::Memory), clock).unwrap();
        assert_eq!(svc.get(b"a").unwrap().as_deref(), Some(&b"1"[..]));
    }

    #[test]
    fn a_durable_backend_rotates_the_wal_on_startup() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        {
            let svc =
                NodeService::open_with_clock(config(&dir, Backend::Fjall), clock.clone()).unwrap();
            svc.put_with_ttl(b"a", b"1", 0).unwrap();
            svc.put_with_ttl(b"b", b"2", 0).unwrap();
            svc.wal.sync().unwrap();
            assert!(svc.wal.segment_bytes() > crate::wal::HEADER_LEN as u64);
        }
        let svc = NodeService::open_with_clock(config(&dir, Backend::Fjall), clock).unwrap();
        assert_eq!(
            svc.wal.segment_bytes(),
            crate::wal::HEADER_LEN as u64,
            "fjall already holds the data, so the segment must be dropped",
        );
        assert_eq!(svc.get(b"a").unwrap().as_deref(), Some(&b"1"[..]));
        assert_eq!(svc.get(b"b").unwrap().as_deref(), Some(&b"2"[..]));
        assert!(
            svc.wal.next_seq() >= 2,
            "sequences must survive the rotation",
        );
    }

    #[test]
    fn a_memory_backend_never_rotates_because_the_wal_is_the_only_copy() {
        let dir = TempDir::new().unwrap();
        let mut cfg = config(&dir, Backend::Memory);
        cfg.wal_rotate_bytes = 4096;
        let svc = NodeService::open_with_clock(cfg, Clock::manual(0)).unwrap();
        for i in 0..200u32 {
            svc.put_with_ttl(format!("k{i}").as_bytes(), &[b'x'; 64], 0)
                .unwrap();
        }
        assert!(
            svc.wal.segment_bytes() > 4096,
            "rotation would destroy the only copy of the data",
        );
    }

    #[test]
    fn rotation_keeps_the_data_readable_and_bounds_the_segment() {
        let dir = TempDir::new().unwrap();
        let mut cfg = config(&dir, Backend::Fjall);
        cfg.wal_rotate_bytes = 4096;
        let svc = NodeService::open_with_clock(cfg, Clock::manual(0)).unwrap();
        for i in 0..200u32 {
            svc.put_with_ttl(format!("k{i}").as_bytes(), &[b'x'; 64], 0)
                .unwrap();
        }
        assert!(
            svc.wal.segment_bytes() <= 4096 + 256,
            "segment grew to {} bytes despite a 4096 threshold",
            svc.wal.segment_bytes(),
        );
        assert_eq!(svc.get(b"k0").unwrap().as_deref(), Some(&[b'x'; 64][..]));
        assert_eq!(svc.get(b"k199").unwrap().as_deref(), Some(&[b'x'; 64][..]));
    }

    #[test]
    fn bootstrap_recovers_index_from_storage() {
        let dir = TempDir::new().unwrap();
        let clock = Clock::manual(0);
        {
            let svc =
                NodeService::open_with_clock(config(&dir, Backend::Fjall), clock.clone()).unwrap();
            svc.put_with_ttl(b"with-ttl", b"v", 5_000).unwrap();
            svc.put_with_ttl(b"no-ttl", b"v", 0).unwrap();
        }
        let svc = NodeService::open_with_clock(config(&dir, Backend::Fjall), clock).unwrap();
        assert_eq!(svc.ttl_index.len(), 1);
        assert_eq!(svc.ttl_index.next_due_ms(), Some(5_000));
    }
}
