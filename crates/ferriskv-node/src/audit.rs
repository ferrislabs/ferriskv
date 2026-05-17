use std::fmt;

use crate::auth_layer::Principal;

pub const TARGET: &str = "ferriskv_audit";

pub fn write(principal: &Principal, tenant: &str, op: &str, key: &[u8], value_size: usize) {
    tracing::info!(
        target: TARGET,
        principal = principal_label(principal),
        tenant = tenant,
        op = op,
        key_hash = %KeyHash::of(key),
        value_size = value_size,
        "audit",
    );
}

fn principal_label(p: &Principal) -> &str {
    match p {
        Principal::Anonymous => "anonymous",
        Principal::Authenticated(c) => c.sub.as_ref(),
    }
}

struct KeyHash([u8; 8]);

impl KeyHash {
    fn of(key: &[u8]) -> Self {
        let full = blake3::hash(key);
        let mut out = [0u8; 8];
        out.copy_from_slice(&full.as_bytes()[..8]);
        Self(out)
    }
}

impl fmt::Display for KeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferriskv_auth::Claims;
    use std::sync::Arc;

    fn claims(sub: &str) -> Claims {
        Claims {
            sub: Arc::<str>::from(sub),
            tenant: Arc::<str>::from("alice"),
            roles: Vec::new(),
            perms: vec![Arc::<str>::from("admin")],
            exp: 0,
            iss: None,
        }
    }

    #[test]
    fn key_hash_is_stable_and_hex() {
        let a = KeyHash::of(b"hello").to_string();
        let b = KeyHash::of(b"hello").to_string();
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_keys_yield_different_hashes() {
        let a = KeyHash::of(b"hello").to_string();
        let b = KeyHash::of(b"world").to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn principal_label_for_anonymous() {
        assert_eq!(principal_label(&Principal::Anonymous), "anonymous");
    }

    #[test]
    fn principal_label_uses_sub() {
        let p = Principal::Authenticated(Arc::new(claims("user-42")));
        assert_eq!(principal_label(&p), "user-42");
    }

    #[test]
    fn write_does_not_panic() {
        write(&Principal::Anonymous, "alice", "put", b"key", 16);
    }
}
