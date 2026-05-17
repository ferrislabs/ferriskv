use std::sync::Arc;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::{AuthError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Arc<str>,
    pub tenant: Arc<str>,
    pub roles: Vec<Arc<str>>,
    pub exp: u64,
    #[serde(default)]
    pub iss: Option<Arc<str>>,
}

pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
}

impl JwtVerifier {
    pub fn new_hs256(secret: &[u8]) -> Self {
        Self {
            key: DecodingKey::from_secret(secret),
            validation: Validation::new(Algorithm::HS256),
        }
    }

    pub fn new_rs256(pem: &[u8]) -> Result<Self> {
        Ok(Self {
            key: DecodingKey::from_rsa_pem(pem)?,
            validation: Validation::new(Algorithm::RS256),
        })
    }

    pub fn verify(&self, token: &str) -> Result<Claims> {
        let data =
            decode::<Claims>(token, &self.key, &self.validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::Expired,
                _ => AuthError::InvalidToken(e.to_string()),
            })?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[test]
    fn hs256_roundtrip() {
        let secret = b"super-secret";
        let claims = Claims {
            sub: Arc::<str>::from("user-1"),
            tenant: Arc::<str>::from("alice"),
            roles: vec![Arc::<str>::from("read")],
            exp: now() + 3600,
            iss: None,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let verifier = JwtVerifier::new_hs256(secret);
        let decoded = verifier.verify(&token).unwrap();
        assert_eq!(decoded.sub.as_ref(), "user-1");
        assert_eq!(decoded.tenant.as_ref(), "alice");
        assert_eq!(decoded.roles.len(), 1);
    }

    #[test]
    fn expired_token_is_rejected() {
        let secret = b"super-secret";
        let claims = Claims {
            sub: Arc::<str>::from("user-1"),
            tenant: Arc::<str>::from("alice"),
            roles: Vec::new(),
            exp: now() - 3600,
            iss: None,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let verifier = JwtVerifier::new_hs256(secret);
        let err = verifier.verify(&token).unwrap_err();
        assert!(matches!(err, AuthError::Expired));
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let claims = Claims {
            sub: Arc::<str>::from("user-1"),
            tenant: Arc::<str>::from("alice"),
            roles: Vec::new(),
            exp: now() + 3600,
            iss: None,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret-a"),
        )
        .unwrap();
        let verifier = JwtVerifier::new_hs256(b"secret-b");
        assert!(matches!(
            verifier.verify(&token),
            Err(AuthError::InvalidToken(_))
        ));
    }
}
