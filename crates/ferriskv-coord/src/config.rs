use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordConfig {
    pub node_id: Arc<str>,
    pub listen: SocketAddr,
    pub peers: Vec<Arc<str>>,
    pub data_dir: std::path::PathBuf,
    #[serde(default = "default_range_size")]
    pub target_range_size_bytes: u64,
    #[serde(default = "default_rf")]
    pub replication_factor: u8,
}

fn default_range_size() -> u64 {
    128 * 1024 * 1024
}

fn default_rf() -> u8 {
    3
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::config::{Config, File, FileFormat};

    fn parse(s: &str) -> CoordConfig {
        Config::builder()
            .add_source(File::from_str(s, FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize::<CoordConfig>()
            .unwrap()
    }

    #[test]
    fn deserializes_minimal_toml() {
        let cfg = parse(
            r#"
            node_id = "c0"
            listen = "127.0.0.1:7000"
            peers = []
            data_dir = "/tmp/ferriskv-coord"
        "#,
        );
        assert_eq!(cfg.node_id.as_ref(), "c0");
        assert_eq!(cfg.target_range_size_bytes, 128 * 1024 * 1024);
        assert_eq!(cfg.replication_factor, 3);
    }

    #[test]
    fn deserializes_full_toml() {
        let cfg = parse(
            r#"
            node_id = "c1"
            listen = "0.0.0.0:7100"
            peers = ["c0", "c2"]
            data_dir = "/var/ferriskv/coord"
            target_range_size_bytes = 67108864
            replication_factor = 5
        "#,
        );
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.target_range_size_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.replication_factor, 5);
    }
}
