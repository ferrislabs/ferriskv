use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

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

/// Where the node gets the keys it verifies tokens with.
///
/// The TOML surface is three optional settings, which can express combinations
/// that mean nothing. `AuthConfig::mode` collapses a validated config into this
/// closed set, so the startup path matches on one value instead of re-deriving
/// which fields were present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode<'a> {
    /// Every caller is trusted. Development only.
    Insecure,
    /// One RS256 public key, read from disk at startup.
    StaticKey(&'a Path),
    /// Many keys, fetched from an IAM and refreshed as it rotates them.
    Jwks { url: &'a str, refresh: Duration },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub public_key_path: Option<PathBuf>,
    /// JWKS endpoint of the IAM, e.g. `https://idp.example/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default = "default_jwks_refresh_secs")]
    pub jwks_refresh_secs: u64,
    /// Permits a `http://` JWKS endpoint outside loopback.
    ///
    /// Off by default, because whoever answers that request decides which
    /// signatures the node accepts: on plaintext, anyone on the path can serve
    /// their own key and mint tokens for any tenant. The escape hatch exists
    /// for meshes that terminate TLS at the sidecar, where the plaintext hop is
    /// the loopback interface in all but name.
    #[serde(default)]
    pub jwks_allow_plaintext: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            insecure: false,
            public_key_path: None,
            jwks_url: None,
            jwks_refresh_secs: default_jwks_refresh_secs(),
            jwks_allow_plaintext: false,
        }
    }
}

/// One hour: long enough to be invisible next to an IAM's rotation period,
/// short enough that an unnoticed rotation heals on its own. A key retired
/// early is picked up sooner than this anyway, on the first token that names it.
fn default_jwks_refresh_secs() -> u64 {
    3600
}

/// Floor on the refresh interval, so a typo cannot turn the node into a
/// polling load on the IAM.
const MIN_JWKS_REFRESH_SECS: u64 = 30;

impl AuthConfig {
    pub fn validate(&self) -> Result<(), String> {
        let configured = self.public_key_path.is_some() || self.jwks_url.is_some();

        if self.insecure {
            if configured {
                return Err(
                    "auth: insecure=true ignores public_key_path and jwks_url; remove one or the other"
                        .into(),
                );
            }
            return Ok(());
        }

        match (&self.public_key_path, &self.jwks_url) {
            (None, None) => {
                return Err(
                    "auth: set insecure=true, or provide public_key_path or jwks_url".into(),
                )
            }
            (Some(_), Some(_)) => {
                return Err("auth: public_key_path and jwks_url are mutually exclusive".into())
            }
            (Some(_), None) => return Ok(()),
            (None, Some(url)) => self.validate_jwks(url)?,
        }

        Ok(())
    }

    fn validate_jwks(&self, url: &str) -> Result<(), String> {
        if self.jwks_refresh_secs < MIN_JWKS_REFRESH_SECS {
            return Err(format!(
                "auth: jwks_refresh_secs must be at least {MIN_JWKS_REFRESH_SECS}"
            ));
        }

        if url.starts_with("https://") {
            return Ok(());
        }

        let Some(rest) = url.strip_prefix("http://") else {
            return Err("auth: jwks_url must be an http:// or https:// URL".into());
        };

        if self.jwks_allow_plaintext || is_loopback_authority(rest) {
            return Ok(());
        }

        Err(format!(
            "auth: refusing a plaintext JWKS endpoint outside loopback ({url}); \
             use https, or set jwks_allow_plaintext=true if TLS terminates at a sidecar"
        ))
    }

    /// Resolves a validated config into the mode the node will run in.
    ///
    /// Returns `Insecure` for a config that never passed `validate`, which is
    /// why callers must validate first — a fact the startup path honours by
    /// validating the whole `NodeConfig` before touching auth.
    pub fn mode(&self) -> AuthMode<'_> {
        if self.insecure {
            return AuthMode::Insecure;
        }
        if let Some(url) = &self.jwks_url {
            return AuthMode::Jwks {
                url,
                refresh: Duration::from_secs(self.jwks_refresh_secs),
            };
        }
        match &self.public_key_path {
            Some(path) => AuthMode::StaticKey(path),
            None => AuthMode::Insecure,
        }
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

/// Whether the authority of a URL points back at this host.
///
/// Deliberately textual: the alternative is resolving the name, which would let
/// whoever controls DNS decide whether the plaintext check applies.
fn is_loopback_authority(rest: &str) -> bool {
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();

    let host = match authority.strip_prefix('[') {
        // IPv6 literal: everything up to the closing bracket.
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };

    matches!(host, "localhost" | "127.0.0.1" | "::1")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Node-wide quota defaults, applied to any tenant without a record of its own.
///
/// Both fields default to `0`, meaning unlimited. A node that started enforcing
/// a limit nobody configured would reject writes for reasons its operator never
/// chose, so opting in is the only safe default.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct QuotaConfig {
    #[serde(default)]
    pub default_max_bytes: u64,
    #[serde(default)]
    pub default_max_ops_per_sec: u32,
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
    #[serde(default = "default_ttl_sweep_interval_secs")]
    pub ttl_sweep_interval_secs: u64,
    #[serde(default = "default_shutdown_secs")]
    pub shutdown_timeout_secs: u64,
    #[serde(default)]
    pub quota: QuotaConfig,
    /// Events a Watch subscriber may fall behind by before its stream is
    /// terminated.
    ///
    /// A subscriber that outruns this buffer is told it lost events rather than
    /// being silently skipped, so the bound trades memory per stream against how
    /// tolerant the node is of a slow client.
    #[serde(default = "default_watch_buffer")]
    pub watch_buffer: usize,
    /// How often an idle Watch stream emits a heartbeat, in seconds.
    ///
    /// Without it a client cannot tell a quiet keyspace from a dead connection.
    #[serde(default = "default_watch_heartbeat_secs")]
    pub watch_heartbeat_secs: u64,
    /// Size at which the WAL segment is rotated, in bytes.
    ///
    /// Rotation drops records that storage already holds, so it is what keeps
    /// the log from growing for the whole uptime of the node. It costs one
    /// storage fsync, hence a threshold rather than a per-write check.
    #[serde(default = "default_wal_rotate_bytes")]
    pub wal_rotate_bytes: u64,
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

fn default_ttl_sweep_interval_secs() -> u64 {
    60
}

fn default_wal_rotate_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_watch_buffer() -> usize {
    1024
}

fn default_watch_heartbeat_secs() -> u64 {
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
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
        if self.shutdown_timeout_secs == 0 {
            return Err("shutdown_timeout_secs must be > 0".into());
        }
        // A threshold below one frame would rotate on every write, turning
        // every put into a storage fsync.
        if self.wal_rotate_bytes < 4096 {
            return Err("wal_rotate_bytes must be at least 4096".into());
        }
        // A zero-capacity broadcast channel cannot be constructed, and a
        // one-event buffer makes every subscriber lag on its second event.
        if self.watch_buffer < 2 {
            return Err("watch_buffer must be at least 2".into());
        }
        if self.watch_heartbeat_secs == 0 {
            return Err("watch_heartbeat_secs must be > 0".into());
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
            ttl_sweep_interval_secs: 0,
            shutdown_timeout_secs: 10,
            wal_rotate_bytes: default_wal_rotate_bytes(),
            quota: QuotaConfig::default(),
            watch_buffer: default_watch_buffer(),
            watch_heartbeat_secs: default_watch_heartbeat_secs(),
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
        assert_eq!(cfg.wal_rotate_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.watch_buffer, 1024);
        assert_eq!(cfg.watch_heartbeat_secs, 30);
        assert_eq!(cfg.quota.default_max_bytes, 0);
        assert_eq!(cfg.quota.default_max_ops_per_sec, 0);
        assert!(!cfg.auth.insecure);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn parses_wal_rotate_bytes() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []
            wal_rotate_bytes = 8388608
        "#,
        );
        assert_eq!(cfg.wal_rotate_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn parses_watch_settings() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []
            watch_buffer = 64
            watch_heartbeat_secs = 5
        "#,
        );
        assert_eq!(cfg.watch_buffer, 64);
        assert_eq!(cfg.watch_heartbeat_secs, 5);
    }

    #[test]
    fn parses_the_quota_section() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []

            [quota]
            default_max_bytes = 1073741824
            default_max_ops_per_sec = 500
        "#,
        );
        assert_eq!(cfg.quota.default_max_bytes, 1024 * 1024 * 1024);
        assert_eq!(cfg.quota.default_max_ops_per_sec, 500);
    }

    #[test]
    fn quotas_default_to_unlimited_when_the_section_is_absent() {
        // Enforcing a limit nobody configured would reject writes for reasons
        // the operator never chose.
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []
        "#,
        );
        assert_eq!(cfg.quota.default_max_bytes, 0);
        assert_eq!(cfg.quota.default_max_ops_per_sec, 0);
        // Unlimited must also be a valid configuration, not merely the parsed
        // default.
        let mut valid = base_cfg();
        valid.quota = cfg.quota;
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn validate_rejects_a_watch_buffer_that_lags_immediately() {
        let mut c = base_cfg();
        c.watch_buffer = 1;
        assert!(c.validate().is_err());
        c.watch_buffer = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_a_heartbeat_that_never_fires() {
        let mut c = base_cfg();
        c.watch_heartbeat_secs = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_a_rotation_threshold_that_would_fsync_every_write() {
        let mut c = base_cfg();
        c.wal_rotate_bytes = 512;
        assert!(c.validate().is_err());
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
            public_key_path: Some(PathBuf::from("/etc/ferriskv/idp.pub")),
            ..Default::default()
        };
        assert!(c.validate().is_ok());
        assert_eq!(
            c.auth.mode(),
            AuthMode::StaticKey(Path::new("/etc/ferriskv/idp.pub"))
        );
    }

    fn jwks_auth(url: &str) -> AuthConfig {
        AuthConfig {
            jwks_url: Some(url.to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn parses_the_jwks_settings() {
        let cfg = parse(
            r#"
            node_id = "n0"
            listen = "127.0.0.1:7100"
            data_dir = "/tmp/ferriskv-node"
            coord_endpoints = []

            [auth]
            jwks_url = "https://idp.example/.well-known/jwks.json"
            jwks_refresh_secs = 900
        "#,
        );
        assert_eq!(
            cfg.auth.jwks_url.as_deref(),
            Some("https://idp.example/.well-known/jwks.json")
        );
        assert_eq!(cfg.auth.jwks_refresh_secs, 900);
        assert!(!cfg.auth.jwks_allow_plaintext);
        assert_eq!(
            cfg.auth.mode(),
            AuthMode::Jwks {
                url: "https://idp.example/.well-known/jwks.json",
                refresh: Duration::from_secs(900),
            }
        );
    }

    #[test]
    fn jwks_refresh_defaults_to_an_hour() {
        let c = jwks_auth("https://idp.example/jwks.json");
        assert_eq!(c.jwks_refresh_secs, 3600);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn auth_validate_rejects_two_key_sources_at_once() {
        let mut c = jwks_auth("https://idp.example/jwks.json");
        c.public_key_path = Some(PathBuf::from("/etc/ferriskv/idp.pub"));
        assert!(c.validate().is_err());
    }

    #[test]
    fn auth_validate_rejects_a_key_source_alongside_insecure() {
        // Believing auth is on while it is off is worse than either state.
        let mut c = jwks_auth("https://idp.example/jwks.json");
        c.insecure = true;
        assert!(c.validate().is_err());
    }

    #[test]
    fn auth_validate_rejects_a_refresh_interval_that_polls_the_iam() {
        let mut c = jwks_auth("https://idp.example/jwks.json");
        c.jwks_refresh_secs = 1;
        assert!(c.validate().is_err());
        c.jwks_refresh_secs = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn auth_validate_refuses_a_plaintext_jwks_endpoint() {
        // Whoever answers this URL decides which signatures the node trusts.
        for url in [
            "http://idp.example/jwks.json",
            "http://10.0.0.5:8080/jwks.json",
            "http://user@idp.example/jwks.json",
        ] {
            assert!(
                jwks_auth(url).validate().is_err(),
                "{url} should have been refused",
            );
        }
    }

    #[test]
    fn auth_validate_allows_plaintext_on_loopback_for_development() {
        for url in [
            "http://localhost:8080/jwks.json",
            "http://127.0.0.1:8080/realms/x/protocol/openid-connect/certs",
            "http://[::1]:8080/jwks.json",
        ] {
            assert!(
                jwks_auth(url).validate().is_ok(),
                "{url} should have been allowed",
            );
        }
    }

    #[test]
    fn auth_validate_allows_plaintext_when_a_sidecar_terminates_tls() {
        let mut c = jwks_auth("http://idp.internal/jwks.json");
        assert!(c.validate().is_err());
        c.jwks_allow_plaintext = true;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn auth_validate_rejects_a_url_that_is_not_http() {
        for url in ["file:///etc/keys.json", "idp.example/jwks.json", ""] {
            assert!(
                jwks_auth(url).validate().is_err(),
                "{url} should have been refused",
            );
        }
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
        let dir = tempfile::TempDir::new().unwrap();
        let cert = dir.path().join("server.crt");
        let key = dir.path().join("server.key");
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
