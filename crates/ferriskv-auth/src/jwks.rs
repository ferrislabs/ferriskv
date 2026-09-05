//! Verification keys fetched from a JWKS document, selected per token by `kid`.
//!
//! This module knows how to turn a JWKS payload into a set of usable keys and
//! how to hand the right one to the verifier. It deliberately knows nothing
//! about HTTP: an IAM is reached over the network by the node, which owns the
//! transport, the refresh schedule and the failure policy. Keeping the bytes as
//! the boundary is what lets every rule below be tested without a server.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use serde::Deserialize;

use crate::{AuthError, Result};

/// One usable verification key, with the validation rules its algorithm implies.
pub(crate) struct RingEntry {
    pub(crate) key: DecodingKey,
    pub(crate) validation: Validation,
}

/// Why a key present in the JWKS document did not make it into the ring.
///
/// Skipping is silent to the protocol but never silent to the operator: a key
/// published by the IAM and dropped here is invisible in every other way, and
/// the resulting "unknown kid" looks like a client problem rather than a
/// configuration one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedKey {
    pub kid: Option<String>,
    pub reason: &'static str,
}

/// The keys a JWKS document yielded, indexed by `kid`.
pub struct KeyRing {
    entries: HashMap<Arc<str>, RingEntry>,
    skipped: Vec<SkippedKey>,
}

/// The outer shape of a JWKS document.
///
/// Keys are held as raw JSON rather than as `Jwk` so that one entry this
/// version cannot model — a key type added to the IAM after this build — costs
/// that single key instead of the whole document. An all-or-nothing parse would
/// turn a routine IdP upgrade into a node that refuses to boot.
#[derive(Deserialize)]
struct RawKeySet {
    #[serde(default)]
    keys: Vec<serde_json::Value>,
}

impl KeyRing {
    /// Parses a JWKS document, keeping every key that can verify a signature.
    ///
    /// Fails only when nothing usable comes out: an empty ring authenticates
    /// nobody, so surfacing it here lets the caller refuse to start rather than
    /// serve a node that rejects every token for reasons no log explains.
    pub fn from_json(raw: &[u8]) -> Result<Self> {
        let set: RawKeySet = serde_json::from_slice(raw)
            .map_err(|e| AuthError::Jwks(format!("malformed JWKS document: {e}")))?;

        let mut entries = HashMap::with_capacity(set.keys.len());
        let mut skipped = Vec::new();

        for value in set.keys {
            let kid_hint = value
                .get("kid")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);

            let jwk: Jwk = match serde_json::from_value(value) {
                Ok(jwk) => jwk,
                Err(_) => {
                    skipped.push(SkippedKey {
                        kid: kid_hint,
                        reason: "unsupported key type",
                    });
                    continue;
                }
            };

            let Some(kid) = jwk.common.key_id.clone() else {
                // Without a kid the key cannot be selected for an incoming
                // token, so it would sit in the ring unreachable.
                skipped.push(SkippedKey {
                    kid: None,
                    reason: "no kid",
                });
                continue;
            };

            let Some(alg) = verification_algorithm(&jwk) else {
                skipped.push(SkippedKey {
                    kid: Some(kid),
                    reason: "no signature algorithm usable for verification",
                });
                continue;
            };

            match DecodingKey::from_jwk(&jwk) {
                Ok(key) => {
                    entries.insert(
                        Arc::<str>::from(kid),
                        RingEntry {
                            key,
                            validation: Validation::new(alg),
                        },
                    );
                }
                Err(_) => skipped.push(SkippedKey {
                    kid: Some(kid),
                    reason: "key material rejected",
                }),
            }
        }

        if entries.is_empty() {
            return Err(AuthError::Jwks(
                "JWKS document contains no usable verification key".into(),
            ));
        }

        Ok(Self { entries, skipped })
    }

    pub(crate) fn get(&self, kid: &str) -> Option<&RingEntry> {
        self.entries.get(kid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, kid: &str) -> bool {
        self.entries.contains_key(kid)
    }

    /// Keys the document carried that this ring cannot use.
    pub fn skipped(&self) -> &[SkippedKey] {
        &self.skipped
    }
}

/// The algorithm a key may verify with, or `None` if it may not verify at all.
///
/// Two families are refused on purpose. Symmetric algorithms (`HS*`, `oct`)
/// have no place in a document published to the world: the "secret" would be
/// the public key, and anyone could mint a token. Key-transport algorithms
/// (`RSA-OAEP`, `RSA1_5`) encrypt, they do not sign.
fn verification_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    if let Some(declared) = jwk.common.key_algorithm {
        return match declared {
            KeyAlgorithm::RS256 => Some(Algorithm::RS256),
            KeyAlgorithm::RS384 => Some(Algorithm::RS384),
            KeyAlgorithm::RS512 => Some(Algorithm::RS512),
            KeyAlgorithm::PS256 => Some(Algorithm::PS256),
            KeyAlgorithm::PS384 => Some(Algorithm::PS384),
            KeyAlgorithm::PS512 => Some(Algorithm::PS512),
            KeyAlgorithm::ES256 => Some(Algorithm::ES256),
            KeyAlgorithm::ES384 => Some(Algorithm::ES384),
            KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
            KeyAlgorithm::HS256
            | KeyAlgorithm::HS384
            | KeyAlgorithm::HS512
            | KeyAlgorithm::RSA1_5
            | KeyAlgorithm::RSA_OAEP
            | KeyAlgorithm::RSA_OAEP_256 => None,
        };
    }

    // `alg` is optional in RFC 7517 and plenty of IAMs omit it. Falling back to
    // the key type keeps those documents usable; `oct` still gets nothing,
    // which is the whole point of the rule above.
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(_) => Some(Algorithm::ES256),
        AlgorithmParameters::OctetKeyPair(_) => Some(Algorithm::EdDSA),
        AlgorithmParameters::OctetKey(_) => None,
    }
}

/// A key ring the verifier reads and a refresher replaces.
///
/// Reads happen on every authenticated request and replacements once per
/// refresh interval, so the lock is held for the length of an `Arc` clone and
/// no verification ever waits on a fetch.
pub struct SharedKeyRing {
    ring: RwLock<Arc<KeyRing>>,
    on_stale: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl SharedKeyRing {
    pub fn new(ring: KeyRing) -> Self {
        Self {
            ring: RwLock::new(Arc::new(ring)),
            on_stale: OnceLock::new(),
        }
    }

    pub fn load(&self) -> Arc<KeyRing> {
        Arc::clone(&self.ring.read())
    }

    pub fn replace(&self, ring: KeyRing) {
        *self.ring.write() = Arc::new(ring);
    }

    /// Registers what to do when a token names a `kid` this ring does not hold.
    ///
    /// The first registration wins; a second is ignored rather than replacing a
    /// live refresher mid-flight.
    pub fn set_stale_hook(&self, hook: impl Fn() + Send + Sync + 'static) {
        let _ = self.on_stale.set(Box::new(hook));
    }

    /// Signals that the ring may be behind the IAM.
    ///
    /// This does not rescue the request that triggered it — the token cannot be
    /// verified against keys we do not have — it only shortens how long the next
    /// caller presenting that `kid` keeps failing.
    pub(crate) fn signal_stale(&self) {
        if let Some(hook) = self.on_stale.get() {
            hook();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::{JWK_E, JWK_N_A, JWK_N_B};

    fn rsa_set(entries: &[&str]) -> Vec<u8> {
        format!(r#"{{"keys":[{}]}}"#, entries.join(",")).into_bytes()
    }

    fn rsa_key(kid: &str, n: &str, alg: Option<&str>) -> String {
        let alg = alg.map(|a| format!(r#""alg":"{a}","#)).unwrap_or_default();
        format!(r#"{{"kty":"RSA","use":"sig",{alg}"kid":"{kid}","n":"{n}","e":"{JWK_E}"}}"#)
    }

    #[test]
    fn parses_a_single_rsa_key() {
        let ring = KeyRing::from_json(&rsa_set(&[&rsa_key("k1", JWK_N_A, Some("RS256"))])).unwrap();
        assert_eq!(ring.len(), 1);
        assert!(ring.contains("k1"));
        assert!(ring.skipped().is_empty());
    }

    #[test]
    fn keeps_every_kid_of_a_rotating_set() {
        // During a rotation the IAM publishes the outgoing and incoming keys at
        // once; dropping either would reject live tokens.
        let ring = KeyRing::from_json(&rsa_set(&[
            &rsa_key("old", JWK_N_A, Some("RS256")),
            &rsa_key("new", JWK_N_B, Some("RS256")),
        ]))
        .unwrap();
        assert_eq!(ring.len(), 2);
        assert!(ring.contains("old"));
        assert!(ring.contains("new"));
    }

    #[test]
    fn infers_rs256_when_alg_is_omitted() {
        let ring = KeyRing::from_json(&rsa_set(&[&rsa_key("k1", JWK_N_A, None)])).unwrap();
        assert!(ring.contains("k1"));
    }

    #[test]
    fn skips_a_key_without_a_kid() {
        let keyed = rsa_key("k1", JWK_N_A, Some("RS256"));
        let anonymous = format!(r#"{{"kty":"RSA","alg":"RS256","n":"{JWK_N_B}","e":"{JWK_E}"}}"#);
        let ring = KeyRing::from_json(&rsa_set(&[&keyed, &anonymous])).unwrap();
        assert_eq!(ring.len(), 1);
        assert_eq!(
            ring.skipped(),
            &[SkippedKey {
                kid: None,
                reason: "no kid",
            }]
        );
    }

    #[test]
    fn refuses_a_symmetric_key_published_in_a_public_set() {
        // An `oct` key in a JWKS means the signing secret is world-readable.
        // Accepting it would let anyone mint a token for any tenant.
        let good = rsa_key("k1", JWK_N_A, Some("RS256"));
        let symmetric =
            r#"{"kty":"oct","alg":"HS256","kid":"shared","k":"c2VjcmV0LXNoYXJlZC1rZXk"}"#;
        let ring = KeyRing::from_json(&rsa_set(&[&good, symmetric])).unwrap();
        assert_eq!(ring.len(), 1);
        assert!(!ring.contains("shared"));
        assert_eq!(ring.skipped().len(), 1);
        assert_eq!(ring.skipped()[0].kid.as_deref(), Some("shared"));
    }

    #[test]
    fn refuses_an_encryption_only_key() {
        let good = rsa_key("k1", JWK_N_A, Some("RS256"));
        let wrapping = rsa_key("wrap", JWK_N_B, Some("RSA-OAEP"));
        let ring = KeyRing::from_json(&rsa_set(&[&good, &wrapping])).unwrap();
        assert_eq!(ring.len(), 1);
        assert!(!ring.contains("wrap"));
    }

    #[test]
    fn one_unmodellable_key_does_not_cost_the_document() {
        // A key type this build predates must not take the whole set down with
        // it, or upgrading the IAM stops the node from booting.
        let good = rsa_key("k1", JWK_N_A, Some("RS256"));
        let exotic = r#"{"kty":"QUANTUM","kid":"future","q":"unknowable"}"#;
        let ring = KeyRing::from_json(&rsa_set(&[&good, exotic])).unwrap();
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.skipped()[0].kid.as_deref(), Some("future"));
        assert_eq!(ring.skipped()[0].reason, "unsupported key type");
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(matches!(
            KeyRing::from_json(b"not json at all"),
            Err(AuthError::Jwks(_))
        ));
    }

    #[test]
    fn rejects_a_document_with_nothing_usable() {
        assert!(matches!(
            KeyRing::from_json(br#"{"keys":[]}"#),
            Err(AuthError::Jwks(_))
        ));
    }

    #[test]
    fn replace_swaps_the_whole_ring() {
        let shared = SharedKeyRing::new(
            KeyRing::from_json(&rsa_set(&[&rsa_key("old", JWK_N_A, Some("RS256"))])).unwrap(),
        );
        assert!(shared.load().contains("old"));

        shared.replace(
            KeyRing::from_json(&rsa_set(&[&rsa_key("new", JWK_N_B, Some("RS256"))])).unwrap(),
        );
        let ring = shared.load();
        assert!(ring.contains("new"));
        assert!(!ring.contains("old"));
    }

    #[test]
    fn the_stale_hook_fires_and_only_the_first_one_is_kept() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let shared = SharedKeyRing::new(
            KeyRing::from_json(&rsa_set(&[&rsa_key("k1", JWK_N_A, Some("RS256"))])).unwrap(),
        );
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));

        let f = Arc::clone(&first);
        shared.set_stale_hook(move || {
            f.fetch_add(1, Ordering::Relaxed);
        });
        let s = Arc::clone(&second);
        shared.set_stale_hook(move || {
            s.fetch_add(1, Ordering::Relaxed);
        });

        shared.signal_stale();
        assert_eq!(first.load(Ordering::Relaxed), 1);
        assert_eq!(second.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn signalling_without_a_hook_is_a_no_op() {
        let shared = SharedKeyRing::new(
            KeyRing::from_json(&rsa_set(&[&rsa_key("k1", JWK_N_A, Some("RS256"))])).unwrap(),
        );
        shared.signal_stale();
    }
}
