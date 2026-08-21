//! `KeyCodec` decode/encode symmetry.
//!
//! The two directions must agree on exactly one set of valid keys. An input
//! `decode` accepts but `encode` cannot produce means a corrupt key can be read
//! back as a legitimate one — which is how a key escapes its tenant.

#![no_main]

use ferriskv_core::key::KeyCodec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((tenant, subspace, payload)) = KeyCodec::decode(data) else {
        return;
    };
    let tenant = tenant.to_string();
    let payload = payload.to_vec();

    let reencoded = KeyCodec::encode(&tenant, subspace, &payload)
        .expect("decode accepted parts that encode rejects");
    assert_eq!(
        reencoded.as_ref(),
        data,
        "re-encoding a decoded key must reproduce it byte for byte",
    );

    // Every valid key must sit under its own tenant prefix and nowhere else.
    let prefix = KeyCodec::encode_tenant_prefix(&tenant).expect("tenant came from a valid key");
    assert!(data.starts_with(&prefix));
});
