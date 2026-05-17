use bytes::Bytes;
use ferriskv_core::{NodeId, ShardId};
use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct RangeEntry {
    pub shard_id: ShardId,
    pub start: Bytes,
    pub end: Option<Bytes>,
    pub primary: NodeId,
    pub replicas: Vec<NodeId>,
}

impl RangeEntry {
    #[inline]
    pub fn contains(&self, key: &[u8]) -> bool {
        if key < self.start.as_ref() {
            return false;
        }
        match &self.end {
            Some(end) => key < end.as_ref(),
            None => true,
        }
    }
}

#[derive(Default)]
pub struct RangeMap {
    inner: RwLock<Vec<RangeEntry>>,
}

impl RangeMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, entry: RangeEntry) {
        let mut g = self.inner.write();
        let pos = g.partition_point(|e| e.start <= entry.start);
        g.insert(pos, entry);
    }

    pub fn lookup(&self, key: &[u8]) -> Option<RangeEntry> {
        let g = self.inner.read();
        let idx = g.partition_point(|e| e.start.as_ref() <= key);
        if idx == 0 {
            return None;
        }
        let candidate = &g[idx - 1];
        if candidate.contains(key) {
            Some(candidate.clone())
        } else {
            None
        }
    }

    pub fn all(&self) -> Vec<RangeEntry> {
        self.inner.read().clone()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn entry(id: ShardId, start: &[u8], end: Option<&[u8]>) -> RangeEntry {
        RangeEntry {
            shard_id: id,
            start: Bytes::copy_from_slice(start),
            end: end.map(Bytes::copy_from_slice),
            primary: Arc::<str>::from("n0"),
            replicas: vec![Arc::<str>::from("n0")],
        }
    }

    #[test]
    fn lookup_finds_owning_range() {
        let m = RangeMap::new();
        m.insert(entry(1, b"", Some(b"m")));
        m.insert(entry(2, b"m", Some(b"z")));
        m.insert(entry(3, b"z", None));

        assert_eq!(m.lookup(b"a").unwrap().shard_id, 1);
        assert_eq!(m.lookup(b"m").unwrap().shard_id, 2);
        assert_eq!(m.lookup(b"y").unwrap().shard_id, 2);
        assert_eq!(m.lookup(b"z").unwrap().shard_id, 3);
        assert_eq!(m.lookup(b"zzzz").unwrap().shard_id, 3);
    }

    #[test]
    fn lookup_returns_none_outside_coverage() {
        let m = RangeMap::new();
        m.insert(entry(1, b"m", Some(b"z")));
        assert!(m.lookup(b"a").is_none());
        assert!(m.lookup(b"z").is_none());
    }
}
