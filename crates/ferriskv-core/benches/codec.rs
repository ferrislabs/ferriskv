use bytes::Bytes;
use divan::{black_box, Bencher};
use ferriskv_core::key::{KeyCodec, Subspace};
use ferriskv_core::value::ValueCodec;

fn main() {
    divan::main();
}

const PAYLOAD_SIZES: &[usize] = &[16, 256, 4096];

#[divan::bench(args = PAYLOAD_SIZES)]
fn key_encode(bencher: Bencher, size: usize) {
    let payload = vec![0xABu8; size];
    bencher.bench(|| {
        KeyCodec::encode(black_box("tenant-1"), Subspace::Data, black_box(&payload)).unwrap()
    });
}

#[divan::bench(args = PAYLOAD_SIZES)]
fn key_decode(bencher: Bencher, size: usize) {
    let payload = vec![0xABu8; size];
    let encoded = KeyCodec::encode("tenant-1", Subspace::Data, &payload).unwrap();
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

#[divan::bench(args = PAYLOAD_SIZES)]
fn value_decode_no_ttl(bencher: Bencher, size: usize) {
    let payload = vec![0xABu8; size];
    let encoded: Bytes = ValueCodec::encode(&payload, None);
    bencher.bench(|| ValueCodec::decode(black_box(encoded.clone())).unwrap());
}

#[divan::bench(args = PAYLOAD_SIZES)]
fn value_decode_with_ttl(bencher: Bencher, size: usize) {
    let payload = vec![0xABu8; size];
    let encoded: Bytes = ValueCodec::encode(&payload, Some(1_700_000_000_000));
    bencher.bench(|| ValueCodec::decode(black_box(encoded.clone())).unwrap());
}

#[divan::bench]
fn value_is_expired_hot(bencher: Bencher) {
    let encoded = ValueCodec::encode(b"value", Some(1_700_000_000_000));
    bencher.bench(|| ValueCodec::is_expired(black_box(&encoded), black_box(1_600_000_000_000)).unwrap());
}
