//! `KeyCodec::decode` over arbitrary bytes.
//!
//! Keys arrive from disk, so any byte sequence is reachable after a corruption
//! or a format change. Decoding one must be an error, never a panic.

#![no_main]

use ferriskv_core::key::{KeyCodec, Subspace};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((tenant, subspace, payload)) = KeyCodec::decode(data) else {
        return;
    };

    // A successful decode makes promises about the bytes it consumed. Check
    // them here rather than only that we did not crash: a decoder that returns
    // Ok with the wrong slice boundaries is a silent tenant-isolation bug, and
    // no amount of not-panicking would surface it.
    assert!(!tenant.is_empty(), "decode accepted an empty tenant");
    assert!(tenant.len() <= 255);
    assert_eq!(
        data.len(),
        1 + tenant.len() + 1 + payload.len(),
        "the decoded parts must account for every byte of the key",
    );
    assert_eq!(Subspace::from_u8(subspace as u8), Some(subspace));
});
