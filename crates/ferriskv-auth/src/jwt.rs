use std::sync::Arc;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::jwks::SharedKeyRing;
use crate::{AuthError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Arc<str>,
    pub tenant: Arc<str>,
    #[serde(default)]
    pub roles: Vec<Arc<str>>,
    #[serde(default)]
    pub perms: Vec<Arc<str>>,
    pub exp: u64,
    #[serde(default)]
    pub iss: Option<Arc<str>>,
}

impl Claims {
    pub fn allows(&self, perm: &str) -> bool {
        self.perms
            .iter()
            .any(|p| p.as_ref() == "admin" || p.as_ref() == perm)
    }
}

/// Where the verifier gets the key for a given token.
///
/// A closed set of two, so the choice is resolved by a match rather than a
/// vtable, and adding a third source makes the compiler point at every place
/// that has to account for it.
enum KeySource {
    /// One key, fixed for the lifetime of the process.
    ///
    /// Boxed because `DecodingKey` and `Validation` together dwarf the other
    /// variant, and a verifier is built once and shared behind an `Arc`.
    Static(Box<StaticKey>),
    /// Many keys, selected by the token's `kid` and replaced as the IAM rotates.
    Jwks(Arc<SharedKeyRing>),
}

struct StaticKey {
    key: DecodingKey,
    validation: Validation,
}

pub struct JwtVerifier {
    source: KeySource,
}

impl JwtVerifier {
    pub fn new_hs256(secret: &[u8]) -> Self {
        Self {
            source: KeySource::Static(Box::new(StaticKey {
                key: DecodingKey::from_secret(secret),
                validation: Validation::new(Algorithm::HS256),
            })),
        }
    }

    pub fn new_rs256(pem: &[u8]) -> Result<Self> {
        Ok(Self {
            source: KeySource::Static(Box::new(StaticKey {
                key: DecodingKey::from_rsa_pem(pem)?,
                validation: Validation::new(Algorithm::RS256),
            })),
        })
    }

    pub fn new_jwks(keys: Arc<SharedKeyRing>) -> Self {
        Self {
            source: KeySource::Jwks(keys),
        }
    }

    pub fn verify(&self, token: &str) -> Result<Claims> {
        match &self.source {
            KeySource::Static(k) => decode_claims(token, &k.key, &k.validation),
            KeySource::Jwks(keys) => {
                let kid = decode_header(token)?.kid.ok_or(AuthError::MissingKid)?;
                let ring = keys.load();
                let Some(entry) = ring.get(&kid) else {
                    // The IAM may have rotated since the last fetch. Asking for
                    // a refresh does not save this request — the signature
                    // cannot be checked against a key we do not hold — it only
                    // shortens the window for the next caller.
                    keys.signal_stale();
                    return Err(AuthError::UnknownKid(kid));
                };
                decode_claims(token, &entry.key, &entry.validation)
            }
        }
    }
}

fn decode_claims(token: &str, key: &DecodingKey, validation: &Validation) -> Result<Claims> {
    let data = decode::<Claims>(token, key, validation).map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::Expired,
        _ => AuthError::InvalidToken(e.to_string()),
    })?;
    Ok(data.claims)
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
            perms: vec![Arc::<str>::from("read")],
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
            perms: Vec::new(),
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
            perms: Vec::new(),
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

    mod jwks {
        use super::*;
        use crate::jwks::KeyRing;
        use crate::test_keys::{JWK_E, JWK_N_A, JWK_N_B, PEM_A, PEM_B};

        fn claims() -> Claims {
            Claims {
                sub: Arc::<str>::from("user-1"),
                tenant: Arc::<str>::from("alice"),
                roles: Vec::new(),
                perms: vec![Arc::<str>::from("read")],
                exp: now() + 3600,
                iss: None,
            }
        }

        /// Signs with `pem` while announcing `kid`, which is what lets a test
        /// present a key the ring knows under a name it does not, and vice versa.
        fn sign(pem: &[u8], kid: Option<&str>) -> String {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = kid.map(str::to_owned);
            encode(&header, &claims(), &EncodingKey::from_rsa_pem(pem).unwrap()).unwrap()
        }

        fn ring(kid: &str, n: &str) -> KeyRing {
            let doc = format!(
                r#"{{"keys":[{{"kty":"RSA","use":"sig","alg":"RS256","kid":"{kid}","n":"{n}","e":"{JWK_E}"}}]}}"#
            );
            KeyRing::from_json(doc.as_bytes()).unwrap()
        }

        #[test]
        fn accepts_a_token_signed_by_a_key_in_the_ring() {
            let shared = Arc::new(SharedKeyRing::new(ring("k1", JWK_N_A)));
            let verifier = JwtVerifier::new_jwks(shared);
            let decoded = verifier.verify(&sign(PEM_A, Some("k1"))).unwrap();
            assert_eq!(decoded.tenant.as_ref(), "alice");
            assert!(decoded.allows("read"));
        }

        #[test]
        fn rejects_a_kid_the_ring_does_not_hold_and_asks_for_a_refresh() {
            use std::sync::atomic::{AtomicUsize, Ordering};

            let shared = Arc::new(SharedKeyRing::new(ring("k1", JWK_N_A)));
            let refreshes = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&refreshes);
            shared.set_stale_hook(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            });

            let verifier = JwtVerifier::new_jwks(Arc::clone(&shared));
            let err = verifier.verify(&sign(PEM_B, Some("k2"))).unwrap_err();

            assert!(matches!(err, AuthError::UnknownKid(kid) if kid == "k2"));
            assert_eq!(refreshes.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn rejects_a_token_carrying_no_kid() {
            // Without a kid there is no way to pick a key, and picking one
            // arbitrarily would make the ring's size decide who gets in.
            let shared = Arc::new(SharedKeyRing::new(ring("k1", JWK_N_A)));
            let verifier = JwtVerifier::new_jwks(shared);
            let err = verifier.verify(&sign(PEM_A, None)).unwrap_err();
            assert!(matches!(err, AuthError::MissingKid));
        }

        #[test]
        fn rejects_a_signature_that_does_not_match_the_kid_it_claims() {
            let shared = Arc::new(SharedKeyRing::new(ring("k1", JWK_N_A)));
            let verifier = JwtVerifier::new_jwks(shared);
            let err = verifier.verify(&sign(PEM_B, Some("k1"))).unwrap_err();
            assert!(matches!(err, AuthError::InvalidToken(_)));
        }

        #[test]
        fn rejects_an_expired_token_signed_by_a_ring_key() {
            let expired = Claims {
                exp: now() - 3600,
                ..claims()
            };
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("k1".to_owned());
            let token = encode(
                &header,
                &expired,
                &EncodingKey::from_rsa_pem(PEM_A).unwrap(),
            )
            .unwrap();

            let shared = Arc::new(SharedKeyRing::new(ring("k1", JWK_N_A)));
            let verifier = JwtVerifier::new_jwks(shared);
            assert!(matches!(verifier.verify(&token), Err(AuthError::Expired)));
        }

        #[test]
        fn a_rotation_takes_effect_without_rebuilding_the_verifier() {
            let shared = Arc::new(SharedKeyRing::new(ring("old", JWK_N_A)));
            let verifier = JwtVerifier::new_jwks(Arc::clone(&shared));

            let old_token = sign(PEM_A, Some("old"));
            let new_token = sign(PEM_B, Some("new"));
            assert!(verifier.verify(&old_token).is_ok());
            assert!(verifier.verify(&new_token).is_err());

            shared.replace(ring("new", JWK_N_B));

            assert!(verifier.verify(&new_token).is_ok());
            assert!(matches!(
                verifier.verify(&old_token),
                Err(AuthError::UnknownKid(_))
            ));
        }
    }
}
