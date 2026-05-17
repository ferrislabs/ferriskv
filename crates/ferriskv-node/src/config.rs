use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ferriskv_core::Limits;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub insecure: bool,
    pub jwt_secret: Option<String>,
    pub jwt_secret_path: Option<PathBuf>,
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.insecure {
            return Ok(());
        }
        if self.jwt_secret.is_none() && self.jwt_secret_path.is_none() {
            return Err("auth: set insecure=true or provide jwt_secret/jwt_secret_path".into());
        }
        Ok(())
    }

    pub fn load_secret(&self) -> Result<Option<Vec<u8>>, String> {
        if let Some(literal) = &self.jwt_secret {
            return Ok(Some(literal.as_bytes().to_vec()));
        }
        if let Some(path) = &self.jwt_secret_path {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("read jwt_secret_path {}: {e}", path.display()))?;
            return Ok(Some(bytes));
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: Arc<str>,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub coord_endpoints: Vec<Arc<str>>,
    #[serde(default = "default_backend")]
    pub backend: Backend,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default = "default_shutdown_secs")]
    pub shutdown_timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Memory,
    Fjall,
}

fn default_backend() -> Backend {
    Backend::Fjall
}

fn default_shutdown_secs() -> u64 {
    30
}

impl NodeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.node_id.is_empty() {
            return Err("node_id must not be empty".into());
        }
        if self.node_id.len() > 255 {
            return Err("node_id exceeds 255 bytes".into());
        }
        self.limits.validate()?;
        self.auth.validate()?;
        if self.shutdown_timeout_secs == 0 {
            return Err("shutdown_timeout_secs must be > 0".into());
        }
        if let Some(parent) = self.data_dir.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(format!(
                    "data_dir parent does not exist: {}",
                    parent.display()
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::config::{Config, File, FileFormat};

    fn parse(s: &str) -> NodeConfig {
        Config::builder()
            .add_source(File::from_str(s, FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize::<NodeConfig>()
            .unwrap()
    }

    fn base_cfg() -> NodeConfig {
        NodeConfig {
            node_id: Arc::<str>::from("n0"),
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: std::env::temp_dir(),
            coord_endpoints: Vec::new(),
            backend: Backend::Memory,
            limits: Limits::default(),
            auth: AuthConfig {
                insecure: true,
                ..Default::default()
            },
            shutdown_timeout_secs: 30,
        }
    }

    #[test]
    fn deserializes_with_defaults() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []
        "#,
        );
        assert_eq!(cfg.node_id.as_ref(), "n0");
        assert_eq!(cfg.backend, Backend::Fjall);
        assert_eq!(cfg.limits.max_value_size, 10 * 1024 * 1024);
        assert_eq!(cfg.shutdown_timeout_secs, 30);
        assert!(!cfg.auth.insecure);
    }

    #[test]
    fn auth_validate_rejects_missing_secret_when_not_insecure() {
        let mut c = base_cfg();
        c.auth = AuthConfig::default();
        assert!(c.validate().is_err());
    }

    #[test]
    fn auth_validate_accepts_inline_secret() {
        let mut c = base_cfg();
        c.auth = AuthConfig {
            insecure: false,
            jwt_secret: Some("hunter2".into()),
            jwt_secret_path: None,
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn parses_backend_memory_with_overrides() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = ["c0:7000"]
            backend = "memory"
            shutdown_timeout_secs = 5

            [limits]
            max_key_size = 8192
            max_value_size = 1048576
        "#,
        );
        assert_eq!(cfg.backend, Backend::Memory);
        assert_eq!(cfg.limits.max_key_size, 8192);
        assert_eq!(cfg.limits.max_value_size, 1024 * 1024);
        assert_eq!(cfg.shutdown_timeout_secs, 5);
    }

    #[test]
    fn validate_accepts_sane_config() {
        assert!(base_cfg().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_node_id() {
        let mut c = base_cfg();
        c.node_id = Arc::<str>::from("");
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_shutdown_timeout() {
        let mut c = base_cfg();
        c.shutdown_timeout_secs = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_limits() {
        let mut c = base_cfg();
        c.limits.max_value_size = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_nonexistent_data_dir_parent() {
        let mut c = base_cfg();
        c.data_dir = PathBuf::from("/this/path/definitely/does/not/exist/sub");
        assert!(c.validate().is_err());
    }
}
