use std::sync::Arc;

use ferriskv_core::{FjallStorage, MemStorage, Storage, StorageBackend};

use crate::config::{Backend, NodeConfig};
use crate::wal::Wal;

pub struct NodeService {
    pub config: NodeConfig,
    pub storage: Arc<StorageBackend>,
    pub wal: Arc<Wal>,
}

impl NodeService {
    pub fn open(config: NodeConfig) -> ferriskv_core::Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let storage = match config.backend {
            Backend::Memory => StorageBackend::Memory(MemStorage::new()),
            Backend::Fjall => {
                let path = config.data_dir.join("fjall");
                StorageBackend::Fjall(FjallStorage::open(path, "default")?)
            }
        };
        let wal = Wal::open(config.data_dir.join("wal.log"))?;
        Ok(Self {
            config,
            storage: Arc::new(storage),
            wal: Arc::new(wal),
        })
    }

    #[inline]
    pub fn storage(&self) -> &StorageBackend {
        &self.storage
    }
}

impl Storage for NodeService {
    #[inline]
    fn get(&self, key: &[u8]) -> ferriskv_core::Result<Option<bytes::Bytes>> {
        self.storage.get(key)
    }

    #[inline]
    fn put(&self, key: &[u8], value: bytes::Bytes) -> ferriskv_core::Result<()> {
        self.wal.append(1, key, &value)?;
        self.storage.put(key, value)
    }

    #[inline]
    fn delete(&self, key: &[u8]) -> ferriskv_core::Result<()> {
        self.wal.append(2, key, &[])?;
        self.storage.delete(key)
    }

    fn scan(&self, prefix: &[u8]) -> ferriskv_core::Result<ferriskv_core::ScanIter> {
        self.storage.scan(prefix)
    }

    fn scan_range(
        &self,
        start: &[u8],
        end: &[u8],
    ) -> ferriskv_core::Result<ferriskv_core::ScanIter> {
        self.storage.scan_range(start, end)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use bytes::Bytes;
    use ferriskv_core::Storage;
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
            shutdown_timeout_secs: 5,
        }
    }

    #[test]
    fn opens_memory_backend_and_writes_through_wal() {
        let dir = TempDir::new().unwrap();
        let svc = NodeService::open(config(&dir, Backend::Memory)).unwrap();
        svc.put(b"k", Bytes::from_static(b"v")).unwrap();
        svc.delete(b"k").unwrap();
        assert!(dir.path().join("wal.log").exists());
    }

    #[test]
    fn opens_fjall_backend() {
        let dir = TempDir::new().unwrap();
        let svc = NodeService::open(config(&dir, Backend::Fjall)).unwrap();
        svc.put(b"k", Bytes::from_static(b"v")).unwrap();
        assert_eq!(svc.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
    }

    #[test]
    fn scan_and_scan_range_delegate_to_storage() {
        let dir = TempDir::new().unwrap();
        let svc = NodeService::open(config(&dir, Backend::Memory)).unwrap();
        for k in [b"a", b"b", b"c", b"d"] {
            svc.put(k, Bytes::from_static(b"v")).unwrap();
        }
        let prefix: Vec<_> = svc.scan(b"a").unwrap().collect();
        assert_eq!(prefix.len(), 1);
        let range: Vec<_> = svc.scan_range(b"b", b"d").unwrap().collect();
        assert_eq!(range.len(), 2);
    }
}
