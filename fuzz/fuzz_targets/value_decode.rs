//! `ValueCodec` decoding and its expiry fast path.
//!
//! `is_expired` reads the TTL stamp without allocating a `StoredValue`, so it
//! duplicates the header parsing that `decode` does. Two parsers over one format
//! drift; this target is what keeps them honest.

#![no_main]

use bytes::Bytes;
use ferriskv_core::value::ValueCodec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = ValueCodec::decode(Bytes::copy_from_slice(data));

    for now in [0u64, 1, u64::MAX / 2, u64::MAX] {
        match (&decoded, ValueCodec::is_expired(data, now)) {
            (Ok(value), Ok(expired)) => {
                let expected = value.expires_at_ms.is_some_and(|exp| exp <= now);
                assert_eq!(
                    expired, expected,
                    "is_expired disagrees with decode at now={now}",
                );
            }
            (Err(_), Err(_)) => {}
            (left, right) => panic!("decode and is_expired disagree on validity: {left:?} / {right:?}"),
        }
    }

    // Whatever decoded must re-encode to the same bytes: the encoder is the
    // only writer of this format, so anything the decoder accepts that it
    // cannot reproduce is a value it is reading wrong.
    if let Ok(value) = decoded {
        let reencoded = ValueCodec::encode(&value.value, value.expires_at_ms);
        assert_eq!(reencoded.as_ref(), data);
    }
});
