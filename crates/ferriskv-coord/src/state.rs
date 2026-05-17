use std::sync::Arc;

use parking_lot::RwLock;

use crate::config::CoordConfig;
use crate::placement::RangeMap;

pub struct CoordState {
    pub config: CoordConfig,
    pub ranges: RangeMap,
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    leader_hint: Option<Arc<str>>,
    term: u64,
}

impl CoordState {
    pub fn new(config: CoordConfig) -> Self {
        Self {
            config,
            ranges: RangeMap::new(),
            inner: RwLock::new(Inner::default()),
        }
    }

    pub fn term(&self) -> u64 {
        self.inner.read().term
    }

    pub fn bump_term(&self, term: u64) {
        let mut g = self.inner.write();
        if term > g.term {
            g.term = term;
        }
    }

    pub fn leader_hint(&self) -> Option<Arc<str>> {
        self.inner.read().leader_hint.clone()
    }

    pub fn set_leader_hint(&self, leader: Arc<str>) {
        self.inner.write().leader_hint = Some(leader);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    fn cfg() -> CoordConfig {
        CoordConfig {
            node_id: Arc::<str>::from("c0"),
            listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            peers: Vec::new(),
            data_dir: PathBuf::from("/tmp/none"),
            target_range_size_bytes: 1,
            replication_factor: 1,
        }
    }

    #[test]
    fn term_only_moves_forward() {
        let s = CoordState::new(cfg());
        assert_eq!(s.term(), 0);
        s.bump_term(5);
        assert_eq!(s.term(), 5);
        s.bump_term(3);
        assert_eq!(s.term(), 5);
        s.bump_term(10);
        assert_eq!(s.term(), 10);
    }

    #[test]
    fn leader_hint_roundtrip() {
        let s = CoordState::new(cfg());
        assert!(s.leader_hint().is_none());
        s.set_leader_hint(Arc::<str>::from("c2"));
        assert_eq!(s.leader_hint().as_deref(), Some("c2"));
    }
}
