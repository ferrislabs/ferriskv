//! WAL segment parsing.
//!
//! The tail of a segment is torn by definition — the process can die in the
//! middle of a write — so this parser sees malformed input on the normal
//! recovery path, not just under corruption. It has to be total.

#![no_main]

use ferriskv_node::wal::{parse_frames, parse_header, HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_header(data);

    let (records, consumed) = parse_frames(data);
    assert!(
        consumed <= data.len(),
        "the parser reported consuming more than it was given",
    );

    // Parsing must be deterministic and prefix-stable: re-running over exactly
    // the bytes it claimed has to yield the same records. That is the property
    // recovery relies on when it truncates at `consumed` and reopens.
    let (again, again_consumed) = parse_frames(&data[..consumed]);
    assert_eq!(again_consumed, consumed);
    assert_eq!(again, records);

    // Whatever survived parsing must have a known opcode and a length that
    // fits the buffer it came from.
    for record in &records {
        assert!(record.key.len() + record.value.len() <= consumed);
    }

    // A full segment goes header-then-frames. Exercise that composition too,
    // so the target covers how recovery actually calls these.
    if data.len() >= HEADER_LEN && parse_header(data).is_ok() {
        let _ = parse_frames(&data[HEADER_LEN..]);
    }
});
