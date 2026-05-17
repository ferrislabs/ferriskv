use std::path::Path;

use bytes::Bytes;
use dashmap::DashMap;
use fjall::{Config, Keyspace, PartitionCreateOptions, PartitionHandle};

use crate::error::{Error, Result};

pub type ScanIter = std::vec::IntoIter<(Bytes, Bytes)>;

pub trait Storage: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>>;
    fn put(&self, key: &[u8], value: Bytes) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    fn scan(&self, prefix: &[u8]) -> Result<ScanIter>;
    fn scan_range(&self, start: &[u8], end: &[u8]) -> Result<ScanIter>;
}

#[derive(Default)]
pub struct MemStorage {
    inner: DashMap<Bytes, Bytes>,
}

impl MemStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemStorage {
    #[inline]
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        Ok(self.inner.get(key).map(|v| v.value().clone()))
    }

    #[inline]
    fn put(&self, key: &[u8], value: Bytes) -> Result<()> {
        let k = Bytes::copy_from_slice(key);
        self.inner.insert(k, value);
        Ok(())
    }

    #[inline]
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.inner.remove(key);
        Ok(())
    }

    fn scan(&self, prefix: &[u8]) -> Result<ScanIter> {
        let mut out = Vec::new();
        for entry in self.inner.iter() {
            if entry.key().starts_with(prefix) {
                out.push((entry.key().clone(), entry.value().clone()));
            }
        }
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Ok(out.into_iter())
    }

    fn scan_range(&self, start: &[u8], end: &[u8]) -> Result<ScanIter> {
        let mut out = Vec::new();
        for entry in self.inner.iter() {
            let k: &[u8] = entry.key().as_ref();
            if k >= start && k < end {
                out.push((entry.key().clone(), entry.value().clone()));
            }
        }
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Ok(out.into_iter())
    }
}

pub struct FjallStorage {
    _keyspace: Keyspace,
    partition: PartitionHandle,
}

impl FjallStorage {
    pub fn open(path: impl AsRef<Path>, partition_name: &str) -> Result<Self> {
        let keyspace = Config::new(path.as_ref()).open()?;
        let partition =
            keyspace.open_partition(partition_name, PartitionCreateOptions::default())?;
        Ok(Self {
            _keyspace: keyspace,
            partition,
        })
    }
}

impl Storage for FjallStorage {
    #[inline]
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        match self.partition.get(key)? {
            Some(slice) => Ok(Some(Bytes::copy_from_slice(&slice))),
            None => Ok(None),
        }
    }

    #[inline]
    fn put(&self, key: &[u8], value: Bytes) -> Result<()> {
        self.partition.insert(key, &value[..])?;
        Ok(())
    }

    #[inline]
    fn delete(&self, key: &[u8]) -> Result<()> {
        self.partition.remove(key)?;
        Ok(())
    }

    fn scan(&self, prefix: &[u8]) -> Result<ScanIter> {
        let mut out = Vec::new();
        for kv in self.partition.prefix(prefix) {
            let (k, v) = kv?;
            out.push((Bytes::copy_from_slice(&k), Bytes::copy_from_slice(&v)));
        }
        Ok(out.into_iter())
    }

    fn scan_range(&self, start: &[u8], end: &[u8]) -> Result<ScanIter> {
        let mut out = Vec::new();
        for kv in self.partition.range(start..end) {
            let (k, v) = kv?;
            out.push((Bytes::copy_from_slice(&k), Bytes::copy_from_slice(&v)));
        }
        Ok(out.into_iter())
    }
}

pub enum StorageBackend {
    Memory(MemStorage),
    Fjall(FjallStorage),
}

impl Storage for StorageBackend {
    #[inline]
    fn get(&self, key: &[u8]) -> Result<Option<Bytes>> {
        match self {
            Self::Memory(s) => s.get(key),
            Self::Fjall(s) => s.get(key),
        }
    }

    #[inline]
    fn put(&self, key: &[u8], value: Bytes) -> Result<()> {
        match self {
            Self::Memory(s) => s.put(key, value),
            Self::Fjall(s) => s.put(key, value),
        }
    }

    #[inline]
    fn delete(&self, key: &[u8]) -> Result<()> {
        match self {
            Self::Memory(s) => s.delete(key),
            Self::Fjall(s) => s.delete(key),
        }
    }

    fn scan(&self, prefix: &[u8]) -> Result<ScanIter> {
        match self {
            Self::Memory(s) => s.scan(prefix),
            Self::Fjall(s) => s.scan(prefix),
        }
    }

    fn scan_range(&self, start: &[u8], end: &[u8]) -> Result<ScanIter> {
        match self {
            Self::Memory(s) => s.scan_range(start, end),
            Self::Fjall(s) => s.scan_range(start, end),
        }
    }
}

impl StorageBackend {
    pub fn require_key(&self, key: &[u8]) -> Result<Bytes> {
        match self.get(key)? {
            Some(v) => Ok(v),
            None => Err(Error::NotFound(Bytes::copy_from_slice(key))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_roundtrip() {
        let s = MemStorage::new();
        s.put(b"k", Bytes::from_static(b"v")).unwrap();
        assert_eq!(s.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
        s.delete(b"k").unwrap();
        assert!(s.get(b"k").unwrap().is_none());
    }

    #[test]
    fn mem_scan_prefix() {
        let s = MemStorage::new();
        s.put(b"a:1", Bytes::from_static(b"1")).unwrap();
        s.put(b"a:2", Bytes::from_static(b"2")).unwrap();
        s.put(b"b:1", Bytes::from_static(b"x")).unwrap();
        let out: Vec<_> = s.scan(b"a:").unwrap().collect();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn mem_scan_range_excludes_end() {
        let s = MemStorage::new();
        for k in [b"a", b"b", b"c", b"d"] {
            s.put(k, Bytes::from_static(b"v")).unwrap();
        }
        let out: Vec<_> = s.scan_range(b"b", b"d").unwrap().collect();
        let keys: Vec<&[u8]> = out.iter().map(|(k, _)| k.as_ref()).collect();
        assert_eq!(keys, vec![b"b".as_ref(), b"c".as_ref()]);
    }

    #[test]
    fn backend_enum_dispatches_to_memory() {
        let backend = StorageBackend::Memory(MemStorage::new());
        backend.put(b"k", Bytes::from_static(b"v")).unwrap();
        assert_eq!(backend.get(b"k").unwrap().as_deref(), Some(&b"v"[..]));
        assert!(backend.require_key(b"k").is_ok());
        assert!(matches!(
            backend.require_key(b"missing"),
            Err(Error::NotFound(_))
        ));
    }

    fn tmp_fjall_path() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "ferriskv-fjall-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        p
    }

    #[test]
    fn fjall_roundtrip_and_scan_range() {
        let path = tmp_fjall_path();
        let s = FjallStorage::open(&path, "test").unwrap();
        for k in [b"aa", b"ab", b"ba", b"bb"] {
            s.put(k, Bytes::from_static(b"v")).unwrap();
        }
        assert_eq!(s.get(b"aa").unwrap().as_deref(), Some(&b"v"[..]));

        let prefix: Vec<_> = s.scan(b"a").unwrap().map(|(k, _)| k).collect();
        assert_eq!(prefix.len(), 2);

        let range: Vec<_> = s
            .scan_range(b"ab", b"bb")
            .unwrap()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(range.len(), 2);
        assert_eq!(&range[0][..], b"ab");
        assert_eq!(&range[1][..], b"ba");

        s.delete(b"aa").unwrap();
        assert!(s.get(b"aa").unwrap().is_none());

        drop(s);
        std::fs::remove_dir_all(&path).ok();
    }
}
