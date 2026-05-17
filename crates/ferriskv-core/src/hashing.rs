use crate::types::NodeId;

#[inline]
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[inline]
fn hrw_score(key: &[u8], node: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(node.as_bytes());
    let h = hasher.finalize();
    let b = h.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

pub fn hrw_select<'a>(key: &[u8], nodes: &'a [NodeId], n: usize) -> Vec<&'a NodeId> {
    if nodes.is_empty() || n == 0 {
        return Vec::new();
    }
    let mut scored: Vec<(u64, &NodeId)> = nodes
        .iter()
        .map(|node| (hrw_score(key, node.as_ref()), node))
        .collect();
    scored.sort_unstable_by_key(|(score, _)| std::cmp::Reverse(*score));
    scored.into_iter().take(n).map(|(_, node)| node).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn hrw_picks_n_unique_nodes() {
        let nodes: Vec<NodeId> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| Arc::<str>::from(*s))
            .collect();
        let picked = hrw_select(b"some-key", &nodes, 3);
        assert_eq!(picked.len(), 3);
        let unique: std::collections::HashSet<_> = picked.iter().map(|n| n.as_ref()).collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn hrw_is_stable() {
        let nodes: Vec<NodeId> = ["a", "b", "c"]
            .iter()
            .map(|s| Arc::<str>::from(*s))
            .collect();
        let a = hrw_select(b"k", &nodes, 2);
        let b = hrw_select(b"k", &nodes, 2);
        assert_eq!(a, b);
    }
}
