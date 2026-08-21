//! Property tests over the WAL segment parser.
//!
//! The fuzz target in `fuzz/` covers the same parser with a coverage-guided
//! mutator. These tests cover it with generated *valid* logs, which is the case
//! a fuzzer reaches slowly and by accident: it has to rediscover a CRC to build
//! a well-formed frame. Between them, one side checks that nothing crashes and
//! the other that the records come back intact.

use ferriskv_node::wal::{parse_frames, Wal, WalOp, HEADER_LEN};
use proptest::prelude::*;
use tempfile::TempDir;

fn op_strategy() -> impl Strategy<Value = WalOp> {
    prop_oneof![Just(WalOp::Put), Just(WalOp::Delete)]
}

fn record_strategy() -> impl Strategy<Value = (WalOp, Vec<u8>, Vec<u8>)> {
    (
        op_strategy(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(any::<u8>(), 0..256),
    )
}

fn log_strategy() -> impl Strategy<Value = Vec<(WalOp, Vec<u8>, Vec<u8>)>> {
    prop::collection::vec(record_strategy(), 0..24)
}

/// Writes `records` to a fresh segment and returns the raw file.
fn write_segment(records: &[(WalOp, Vec<u8>, Vec<u8>)]) -> (TempDir, Vec<u8>) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("wal.log");
    {
        let (wal, _) = Wal::open(&path).unwrap();
        for (op, key, value) in records {
            wal.append(*op, key, value).unwrap();
        }
        wal.sync().unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    (dir, bytes)
}

proptest! {
    #[test]
    fn every_appended_record_comes_back_unchanged(records in log_strategy()) {
        let (_dir, bytes) = write_segment(&records);
        let (parsed, consumed) = parse_frames(&bytes[HEADER_LEN..]);

        prop_assert_eq!(consumed, bytes.len() - HEADER_LEN, "a clean segment has no torn tail");
        prop_assert_eq!(parsed.len(), records.len());
        for (i, (record, (op, key, value))) in parsed.iter().zip(&records).enumerate() {
            prop_assert_eq!(record.seq, i as u64, "sequences must be dense and ordered");
            prop_assert_eq!(record.op, *op);
            prop_assert_eq!(&record.key[..], &key[..]);
            prop_assert_eq!(&record.value[..], &value[..]);
        }
    }

    /// A crash can cut the file at any byte. Whatever survives must be a prefix
    /// of what was written — never a different record, never a panic.
    #[test]
    fn truncating_anywhere_yields_a_prefix_of_the_records(
        records in log_strategy(),
        cut in any::<prop::sample::Index>(),
    ) {
        let (_dir, bytes) = write_segment(&records);
        let (whole, _) = parse_frames(&bytes[HEADER_LEN..]);

        let body = &bytes[HEADER_LEN..];
        let torn = &body[..cut.index(body.len() + 1)];
        let (partial, consumed) = parse_frames(torn);

        prop_assert!(consumed <= torn.len());
        prop_assert!(partial.len() <= whole.len());
        prop_assert_eq!(&partial[..], &whole[..partial.len()]);
    }

    /// Flipping one byte can only ever cost records from the flip onwards. It
    /// must never resurrect a record, and must never crash the parser.
    #[test]
    fn corrupting_one_byte_only_costs_the_tail(
        records in prop::collection::vec(record_strategy(), 1..12),
        index in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let (_dir, bytes) = write_segment(&records);
        let (clean, _) = parse_frames(&bytes[HEADER_LEN..]);

        let mut corrupted = bytes.clone();
        let at = HEADER_LEN + index.index(corrupted.len() - HEADER_LEN);
        corrupted[at] ^= mask;

        let (parsed, consumed) = parse_frames(&corrupted[HEADER_LEN..]);
        prop_assert!(consumed <= corrupted.len() - HEADER_LEN);
        prop_assert!(parsed.len() <= clean.len(), "corruption cannot add records");
        prop_assert_eq!(&parsed[..], &clean[..parsed.len()]);
    }

    /// Reopening a segment must agree with parsing its bytes directly. These are
    /// two code paths over one format, so they are exactly the pair that drifts.
    #[test]
    fn reopening_agrees_with_parsing_the_bytes(records in log_strategy()) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let (wal, _) = Wal::open(&path).unwrap();
            for (op, key, value) in &records {
                wal.append(*op, key, value).unwrap();
            }
            wal.sync().unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        let (direct, _) = parse_frames(&bytes[HEADER_LEN..]);

        let (wal, recovery) = Wal::open(&path).unwrap();
        prop_assert_eq!(&recovery.records[..], &direct[..]);
        prop_assert_eq!(recovery.truncated_bytes, 0);
        prop_assert_eq!(recovery.next_seq, records.len() as u64);
        prop_assert_eq!(wal.segment_bytes(), bytes.len() as u64);
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_parser(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let (records, consumed) = parse_frames(&bytes);
        prop_assert!(consumed <= bytes.len());
        // Anything that parsed out of random bytes still has to be internally
        // consistent, or the parser is reading past what it validated.
        for record in &records {
            prop_assert!(record.key.len() + record.value.len() <= consumed);
        }
    }
}
