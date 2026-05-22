use std::sync::Arc;

use divan::{black_box, Bencher};
use ferriskv_auth::{ApiKey, ApiKeyStore, JwtVerifier, RoleSet};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;

fn main() {
    divan::main();
}

#[divan::bench]
fn api_key_verify_hit(bencher: Bencher) {
    let store = ApiKeyStore::new();
    let raw = "my-very-secret-api-key-value";
    store.insert(ApiKey {
        id: Arc::<str>::from("k1"),
        tenant: Arc::<str>::from("alice"),
        hashed: *blake3::hash(raw.as_bytes()).as_bytes(),
        roles: RoleSet::default(),
    });
    bencher.bench(|| store.verify(black_box(raw)).unwrap());
}

#[divan::bench]
fn api_key_verify_miss(bencher: Bencher) {
    let store = ApiKeyStore::new();
    store.insert(ApiKey {
        id: Arc::<str>::from("k1"),
        tenant: Arc::<str>::from("alice"),
        hashed: *blake3::hash(b"present").as_bytes(),
        roles: RoleSet::default(),
    });
    bencher.bench(|| store.verify(black_box("absent")).ok());
}

fn make_hs256_token(secret: &[u8]) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = json!({
        "sub": "user-1",
        "tenant": "alice",
        "roles": ["read"],
        "perms": ["read", "write"],
        "exp": exp,
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap()
}

#[divan::bench]
fn jwt_verify_hs256(bencher: Bencher) {
    let secret = b"super-secret-bench-key";
    let token = make_hs256_token(secret);
    let verifier = JwtVerifier::new_hs256(secret);
    bencher.bench(|| verifier.verify(black_box(&token)).unwrap());
}
