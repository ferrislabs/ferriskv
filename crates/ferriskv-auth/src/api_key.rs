use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::rbac::RoleSet;
use crate::{AuthError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Arc<str>,
    pub tenant: Arc<str>,
    pub hashed: [u8; 32],
    #[serde(skip)]
    pub roles: RoleSet,
}

#[derive(Default)]
pub struct ApiKeyStore {
    by_hash: DashMap<[u8; 32], Arc<ApiKey>>,
}

impl ApiKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, key: ApiKey) {
        self.by_hash.insert(key.hashed, Arc::new(key));
    }

    pub fn verify(&self, raw: &str) -> Result<Arc<ApiKey>> {
        let hash = *blake3::hash(raw.as_bytes()).as_bytes();
        match self.by_hash.get(&hash) {
            Some(entry) => Ok(Arc::clone(entry.value())),
            None => Err(AuthError::UnknownApiKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, tenant: &str, raw: &str) -> ApiKey {
        ApiKey {
            id: Arc::<str>::from(id),
            tenant: Arc::<str>::from(tenant),
            hashed: *blake3::hash(raw.as_bytes()).as_bytes(),
            roles: RoleSet::default(),
        }
    }

    #[test]
    fn insert_and_verify_returns_shared_arc() {
        let store = ApiKeyStore::new();
        store.insert(key("k1", "alice", "secret"));
        let a = store.verify("secret").unwrap();
        let b = store.verify("secret").unwrap();
        assert_eq!(a.id.as_ref(), "k1");
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn unknown_raw_is_rejected() {
        let store = ApiKeyStore::new();
        store.insert(key("k1", "alice", "secret"));
        let err = store.verify("wrong").unwrap_err();
        assert!(matches!(err, AuthError::UnknownApiKey));
    }
}
