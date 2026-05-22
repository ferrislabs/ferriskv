use bytes::Bytes;
use divan::{black_box, Bencher};
use ferriskv_core::key::{KeyCodec, Subspace};
use ferriskv_core::storage::{MemStorage, Storage};

fn main() {
    divan::main();
}

const N_KEYS: &[usize] = &[100, 10_000];

fn populate(n: usize) -> (MemStorage, Vec<Bytes>) {
    let store = MemStorage::new();
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let payload = format!("k{i:08}");
        let key = KeyCodec::encode("tenant-1", Subspace::Data, payload.as_bytes()).unwrap();
        let value = Bytes::from(format!("v{i:08}"));
        store.put(&key, value).unwrap();
        keys.push(key);
    }
    (store, keys)
}

#[divan::bench(args = N_KEYS)]
fn put(bencher: Bencher, n: usize) {
    bencher
        .with_inputs(|| {
            let store = MemStorage::new();
            let mut items = Vec::with_capacity(n);
            for i in 0..n {
                let k = KeyCodec::encode("tenant-1", Subspace::Data, format!("k{i:08}").as_bytes())
                    .unwrap();
                items.push((k, Bytes::from(format!("v{i:08}"))));
            }
            (store, items)
        })
        .bench_values(|(store, items)| {
            for (k, v) in items {
                store.put(black_box(&k), black_box(v)).unwrap();
            }
            store
        });
}

#[divan::bench(args = N_KEYS)]
fn get_hit(bencher: Bencher, n: usize) {
    let (store, keys) = populate(n);
    let target = keys[n / 2].clone();
    bencher.bench(|| store.get(black_box(&target)).unwrap());
}

#[divan::bench(args = N_KEYS)]
fn get_miss(bencher: Bencher, n: usize) {
    let (store, _) = populate(n);
    let missing = KeyCodec::encode("tenant-1", Subspace::Data, b"absent-key").unwrap();
    bencher.bench(|| store.get(black_box(&missing)).unwrap());
}

#[divan::bench(args = N_KEYS)]
fn scan_tenant(bencher: Bencher, n: usize) {
    let (store, _) = populate(n);
    let prefix = KeyCodec::encode_subspace_prefix("tenant-1", Subspace::Data).unwrap();
    bencher.bench(|| {
        let iter = store.scan(black_box(&prefix)).unwrap();
        iter.count()
    });
}
