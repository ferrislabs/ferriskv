use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ferriskv_core::Limits;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl TlsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.cert_path.exists() {
            return Err(format!(
                "tls.cert_path does not exist: {}",
                self.cert_path.display()
            ));
        }
        if !self.key_path.exists() {
            return Err(format!(
                "tls.key_path does not exist: {}",
                self.key_path.display()
            ));
        }
        Ok(())
    }

    pub fn load(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        let cert = std::fs::read(&self.cert_path)
            .map_err(|e| format!("read {}: {e}", self.cert_path.display()))?;
        let key = std::fs::read(&self.key_path)
            .map_err(|e| format!("read {}: {e}", self.key_path.display()))?;
        Ok((cert, key))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub insecure: bool,
    pub public_key_path: Option<PathBuf>,
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.insecure {
            return Ok(());
        }
        if self.public_key_path.is_none() {
            return Err("auth: set insecure=true or provide public_key_path".into());
        }
        Ok(())
    }

    pub fn load_public_key(&self) -> Result<Option<Vec<u8>>, String> {
        match &self.public_key_path {
            Some(path) => {
                let bytes = std::fs::read(path)
                    .map_err(|e| format!("read public_key_path {}: {e}", path.display()))?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
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
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub admin_listen: Option<SocketAddr>,
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
    10
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
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
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
            tls: None,
            admin_listen: None,
            shutdown_timeout_secs: 10,
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
        assert_eq!(cfg.shutdown_timeout_secs, 10);
        assert!(!cfg.auth.insecure);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn auth_validate_rejects_missing_secret_when_not_insecure() {
        let mut c = base_cfg();
        c.auth = AuthConfig::default();
        assert!(c.validate().is_err());
    }

    #[test]
    fn auth_validate_accepts_public_key_path() {
        let mut c = base_cfg();
        c.auth = AuthConfig {
            insecure: false,
            public_key_path: Some(PathBuf::from("/etc/ferriskv/idp.pub")),
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
    fn tls_validate_rejects_missing_files() {
        let tls = TlsConfig {
            cert_path: PathBuf::from("/does/not/exist.crt"),
            key_path: PathBuf::from("/does/not/exist.key"),
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn tls_validate_accepts_existing_files() {
        let dir = std::env::temp_dir().join(format!(
            "ferriskv-tls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("server.crt");
        let key = dir.join("server.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\n").unwrap();
        let tls = TlsConfig {
            cert_path: cert,
            key_path: key,
        };
        assert!(tls.validate().is_ok());
        let (c, k) = tls.load().unwrap();
        assert!(!c.is_empty());
        assert!(!k.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_admin_listen() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []
            admin_listen = "127.0.0.1:7101"
        "#,
        );
        assert_eq!(
            cfg.admin_listen,
            Some("127.0.0.1:7101".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn admin_listen_defaults_to_none() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []
        "#,
        );
        assert!(cfg.admin_listen.is_none());
    }

    #[test]
    fn parses_tls_section() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []

            [tls]
            cert_path = "/etc/ferriskv/server.crt"
            key_path = "/etc/ferriskv/server.key"
        "#,
        );
        let tls = cfg.tls.expect("tls section should be present");
        assert_eq!(tls.cert_path, PathBuf::from("/etc/ferriskv/server.crt"));
        assert_eq!(tls.key_path, PathBuf::from("/etc/ferriskv/server.key"));
    }

    #[test]
    fn validate_rejects_nonexistent_data_dir_parent() {
        let mut c = base_cfg();
        c.data_dir = PathBuf::from("/this/path/definitely/does/not/exist/sub");
        assert!(c.validate().is_err());
    }
}
