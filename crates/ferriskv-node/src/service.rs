use std::sync::Arc;

use bytes::Bytes;
use ferriskv_core::{
    Clock, FjallStorage, MemStorage, ScanIter, Storage, StorageBackend, ValueCodec,
};

use crate::config::{Backend, NodeConfig};
use crate::ttl::TtlIndex;
use crate::wal::Wal;

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
        let wal = Wal::open(config.data_dir.join("wal.log"))?;
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
        self.wal.append(1, key, &encoded)?;
        self.storage.put(key, encoded)?;
        if let Some(exp) = expires_at {
            self.ttl_index.schedule(Bytes::copy_from_slice(key), exp);
        }
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
        self.wal.append(2, key, &[])?;
        self.storage.delete(key)
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
