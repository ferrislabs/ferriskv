//! Codec microbenchmarks.
//!
//! # Only parameterise a dimension the operation actually scales with
//!
//! Encoding copies the payload, so payload size is a real dimension for it.
//! Decoding does not: it reads a header and slices, so its only size-dependent
//! work is validating the tenant name as UTF-8. Parameterising a decode by
//! payload size measures the same thing once per argument — and the regression
//! check counts each copy separately, so one movement arrives as three.
//!
//! # These numbers are not the ones CI reports
//!
//! CodSpeed runs in simulation mode and reports a derived figure, roughly two
//! orders of magnitude above the wall-clock times printed here. Compare its
//! numbers against each other, never against a local run.

use bytes::Bytes;
use divan::{black_box, Bencher};
use ferriskv_core::key::{KeyCodec, Subspace};
use ferriskv_core::value::ValueCodec;

fn main() {
    divan::main();
}

/// Sizes for the operations that actually copy the payload.
const PAYLOAD_SIZES: &[usize] = &[16, 256, 4096];

/// Tenant name lengths, up to the 255-byte maximum the codec allows.
///
/// This is the dimension key decoding scales with, not the payload size:
/// `KeyCodec::decode` validates the tenant as UTF-8 and slices everything else.
const TENANT_LENS: &[usize] = &[1, 8, 64, 255];

#[divan::bench(args = PAYLOAD_SIZES)]
fn key_encode(bencher: Bencher, size: usize) {
    let payload = vec![0xABu8; size];
    bencher.bench(|| {
        KeyCodec::encode(black_box("tenant-1"), Subspace::Data, black_box(&payload)).unwrap()
    });
}

/// Decoding scales with the tenant name, not with the payload.
///
/// The payload is sliced, never read, so varying its size measured the same work
/// three times over — three parameterisations reporting byte-identical numbers,
/// and every result counted three times by the regression check. The tenant is
/// the part that is validated as UTF-8, so that is what varies here.
#[divan::bench(args = TENANT_LENS)]
fn key_decode(bencher: Bencher, tenant_len: usize) {
    let tenant = "t".repeat(tenant_len);
    let payload = vec![0xABu8; 256];
    let encoded = KeyCodec::encode(&tenant, Subspace::Data, &payload).unwrap();
    bencher.bench(|| KeyCodec::decode(black_box(&encoded)).unwrap());
}

#[divan::bench]
fn key_tenant_prefix(bencher: Bencher) {
    bencher.bench(|| KeyCodec::encode_tenant_prefix(black_box("tenant-1")).unwrap());
}

#[divan::bench(args = PAYLOAD_SIZES)]
fn value_encode_no_ttl(bencher: Bencher, size: usize) {
    let payload = vec![0xABu8; size];
    bencher.bench(|| ValueCodec::encode(black_box(&payload), None));
}

#[divan::bench(args = PAYLOAD_SIZES)]
fn value_encode_with_ttl(bencher: Bencher, size: usize) {
    let payload = vec![0xABu8; size];
    bencher.bench(|| ValueCodec::encode(black_box(&payload), Some(1_700_000_000_000)));
}

// Value decoding is O(1) in every dimension, so these take no argument.
//
// `decode` reads the version byte and returns `Bytes::slice` of the rest — a
// refcount bump and some pointer arithmetic, never a copy. There is no size to
// vary: parameterising it produced three identical measurements per benchmark
// and tripled the weight of each in the regression check.

#[divan::bench]
fn value_decode_no_ttl(bencher: Bencher) {
    let encoded: Bytes = ValueCodec::encode(&[0xABu8; 256], None);
    bencher.bench(|| ValueCodec::decode(black_box(encoded.clone())).unwrap());
}

#[divan::bench]
fn value_decode_with_ttl(bencher: Bencher) {
    let encoded: Bytes = ValueCodec::encode(&[0xABu8; 256], Some(1_700_000_000_000));
    bencher.bench(|| ValueCodec::decode(black_box(encoded.clone())).unwrap());
}

/// Calls per batch for the header-only paths below.
///
/// A single call to either is a load and a compare — roughly two cycles, which
/// no harness can resolve. Measured one at a time they report the cost of being
/// measured: about 0.5 ns of real work behind a figure two to three orders of
/// magnitude larger, swinging 29% between runs of identical code. Batching puts
/// the function back in charge of the number.
///
/// These report per batch, not per call — hence the `_batch` suffix on their
/// names. Keeping the old `_hot` names would have made the regression check
/// compare a batch against a single call and read the 64x more work as a 95%
/// regression, which is exactly what it did before they were renamed.
const HOT_BATCH: usize = 64;

fn hot_batch(ttl: Option<u64>) -> Vec<Bytes> {
    (0..HOT_BATCH)
        .map(|i| ValueCodec::encode(&[0xABu8; 32], ttl.map(|t| t + i as u64)))
        .collect()
}

/// The header-only path quota accounting takes on every write.
///
/// Reads the header and returns a length, so it is the counterpart to
/// `value_decode_*`: same header parse, no `StoredValue` built.
#[divan::bench]
fn value_payload_len_batch(bencher: Bencher) {
    let batch = hot_batch(Some(1_700_000_000_000));
    bencher.bench(|| {
        let mut total = 0usize;
        for encoded in &batch {
            total += ValueCodec::payload_len(black_box(encoded)).unwrap();
        }
        total
    });
}

/// The header-only path every read takes to decide whether a key is still live.
#[divan::bench]
fn value_is_expired_batch(bencher: Bencher) {
    let batch = hot_batch(Some(1_700_000_000_000));
    bencher.bench(|| {
        let mut live = 0usize;
        for encoded in &batch {
            if !ValueCodec::is_expired(black_box(encoded), black_box(1_600_000_000_000)).unwrap() {
                live += 1;
            }
        }
        live
    });
}
