//! Write-ahead log for node-local writes.
//!
//! # Segment layout
//!
//! ```text
//! header  MAGIC(4) | format_version(u16 LE) | base_seq(u64 LE)
//! frame   seq(u64 LE) | op(u8) | klen(u32 LE) | key | vlen(u32 LE) | value | crc32(u32 LE)
//! ```
//!
//! The CRC covers every byte of the frame that precedes it.
//!
//! # Why the header carries `base_seq`
//!
//! Once the records of a segment are durable in storage, the segment is dead
//! weight and [`Wal::rotate`] drops it. Sequence numbers must nevertheless keep
//! climbing across that boundary — a reader that saw seq 41 in the old segment
//! must not meet seq 0 in the new one — so the fresh header records where the
//! new segment starts counting.
//!
//! # Torn tails are normal, not corruption
//!
//! A process can die in the middle of a `write_all`. The last frame of a
//! segment is therefore allowed to be short or to fail its CRC: recovery stops
//! there, truncates the remainder and carries on. Anything past the first bad
//! frame is unreachable by construction, since a frame's length is only known
//! from the frame before it.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use ferriskv_core::Error;
use parking_lot::Mutex;

/// Identifies a ferriskv WAL segment. A file that does not start with this is
/// not one of ours, and we refuse it rather than reinterpret its bytes.
const MAGIC: &[u8; 4] = b"FKVW";

/// Bumped whenever the frame layout changes in a way older readers cannot
/// handle. An unknown version is a hard failure, never a best-effort parse.
pub const FORMAT_VERSION: u16 = 1;

/// MAGIC + version + base_seq.
pub const HEADER_LEN: usize = 4 + 2 + 8;

/// seq + op + klen + vlen + crc, i.e. a frame with an empty key and value.
const MIN_FRAME_LEN: usize = 8 + 1 + 4 + 4 + 4;

/// The mutation a record describes.
///
/// Modelled as an enum rather than a raw `u8` so an unknown opcode is rejected
/// at parse time instead of reaching the replay `match` as an unhandled case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WalOp {
    Put = 1,
    Delete = 2,
}

impl WalOp {
    #[inline]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Put),
            2 => Some(Self::Delete),
            _ => None,
        }
    }
}

/// One durable mutation, as read back from a segment.
///
/// `value` carries the already-encoded [`ferriskv_core::ValueCodec`] payload,
/// not the caller's raw value: replay must reproduce exactly the bytes the
/// original write put in storage, TTL stamp included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecord {
    pub seq: u64,
    pub op: WalOp,
    pub key: Bytes,
    pub value: Bytes,
}

/// What opening a segment found.
#[derive(Debug)]
pub struct Recovery {
    /// Records still held by the segment, in write order.
    pub records: Vec<WalRecord>,
    /// Bytes dropped from the tail because the last frame was torn or corrupt.
    pub truncated_bytes: u64,
    /// Sequence the next append will use.
    pub next_seq: u64,
    /// Size of the segment on disk once the torn tail was dropped.
    pub segment_bytes: u64,
}

impl Recovery {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Parses every complete, CRC-valid frame at the front of `body`.
///
/// Returns the records and the number of bytes they occupy; the caller treats
/// the rest as a torn tail. Total function: no input panics, and a garbage
/// length field yields a short read rather than an allocation attempt.
pub fn parse_frames(body: &[u8]) -> (Vec<WalRecord>, usize) {
    let mut records = Vec::new();
    let mut pos = 0usize;
    while let Some((record, len)) = parse_frame(&body[pos..]) {
        records.push(record);
        pos += len;
    }
    (records, pos)
}

/// Parses the frame at the front of `buf`, returning it with its encoded length.
///
/// `None` means "stop here": too short, unknown opcode, or CRC mismatch. The
/// three are deliberately indistinguishable to the caller, because the response
/// to all of them is the same — truncate.
fn parse_frame(buf: &[u8]) -> Option<(WalRecord, usize)> {
    if buf.len() < MIN_FRAME_LEN {
        return None;
    }
    let seq = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let op = WalOp::from_u8(buf[8])?;

    let klen = u32::from_le_bytes(buf[9..13].try_into().ok()?) as usize;
    let key_end = 13usize.checked_add(klen)?;
    let vlen_end = key_end.checked_add(4)?;
    if vlen_end > buf.len() {
        return None;
    }

    let vlen = u32::from_le_bytes(buf[key_end..vlen_end].try_into().ok()?) as usize;
    let value_end = vlen_end.checked_add(vlen)?;
    let frame_end = value_end.checked_add(4)?;
    if frame_end > buf.len() {
        return None;
    }

    let stored_crc = u32::from_le_bytes(buf[value_end..frame_end].try_into().ok()?);
    if crc32fast::hash(&buf[..value_end]) != stored_crc {
        return None;
    }

    Some((
        WalRecord {
            seq,
            op,
            key: Bytes::copy_from_slice(&buf[13..key_end]),
            value: Bytes::copy_from_slice(&buf[vlen_end..value_end]),
        },
        frame_end,
    ))
}

fn encode_header(base_seq: u64) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..4].copy_from_slice(MAGIC);
    out[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    out[6..14].copy_from_slice(&base_seq.to_le_bytes());
    out
}

/// Reads the `base_seq` out of a segment header.
///
/// Unlike frame parsing, a bad header is fatal: it means either a file that is
/// not a WAL or a format this build cannot read, and silently starting a fresh
/// log over it would discard committed writes.
pub fn parse_header(buf: &[u8]) -> Result<u64, Error> {
    if buf.len() < HEADER_LEN {
        return Err(Error::Corrupt("wal header is truncated"));
    }
    if &buf[0..4] != MAGIC {
        return Err(Error::Corrupt("file is not a ferriskv wal segment"));
    }
    let version = u16::from_le_bytes(
        buf[4..6]
            .try_into()
            .map_err(|_| Error::Corrupt("wal format version"))?,
    );
    if version != FORMAT_VERSION {
        return Err(Error::Corrupt("unsupported wal format version"));
    }
    let base_seq = u64::from_le_bytes(
        buf[6..14]
            .try_into()
            .map_err(|_| Error::Corrupt("wal base sequence"))?,
    );
    Ok(base_seq)
}

pub struct Wal {
    path: PathBuf,
    inner: Mutex<WalInner>,
}

struct WalInner {
    writer: BufWriter<File>,
    next_seq: u64,
    /// Bytes the current segment occupies on disk, header included. Tracked
    /// here rather than read back with `metadata()` so the rotation check on
    /// the write path costs nothing.
    segment_bytes: u64,
}

impl Wal {
    /// Opens the segment at `path`, creating it if absent, and hands back what
    /// it held.
    ///
    /// Returning the [`Recovery`] alongside the handle is deliberate: replaying
    /// is the caller's job — only it knows where the records must be applied —
    /// but nothing else can see them, so the signature makes the hand-off
    /// explicit rather than leaving a "did you replay?" call to be forgotten.
    pub fn open(path: impl AsRef<Path>) -> Result<(Self, Recovery), Error> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let recovery = {
            let mut file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&path)?;
            let len = file.seek(SeekFrom::End(0))?;
            if len == 0 {
                file.write_all(&encode_header(0))?;
                file.sync_data()?;
                Recovery {
                    records: Vec::new(),
                    truncated_bytes: 0,
                    next_seq: 0,
                    segment_bytes: HEADER_LEN as u64,
                }
            } else {
                file.seek(SeekFrom::Start(0))?;
                let mut buf = Vec::with_capacity(len as usize);
                file.read_to_end(&mut buf)?;

                let base_seq = parse_header(&buf)?;
                let (records, consumed) = parse_frames(&buf[HEADER_LEN..]);

                let valid_len = HEADER_LEN + consumed;
                let truncated_bytes = (buf.len() - valid_len) as u64;
                if truncated_bytes > 0 {
                    file.set_len(valid_len as u64)?;
                    file.sync_data()?;
                }

                let next_seq = records
                    .last()
                    .map(|r| r.seq.saturating_add(1))
                    .unwrap_or(base_seq)
                    .max(base_seq);
                Recovery {
                    records,
                    truncated_bytes,
                    next_seq,
                    segment_bytes: valid_len as u64,
                }
            }
        };

        let appender = OpenOptions::new().append(true).open(&path)?;
        Ok((
            Self {
                path,
                inner: Mutex::new(WalInner {
                    writer: BufWriter::new(appender),
                    next_seq: recovery.next_seq,
                    segment_bytes: recovery.segment_bytes,
                }),
            },
            recovery,
        ))
    }

    /// Appends one record and returns the sequence it was given.
    ///
    /// The frame is assembled in full before it reaches the file so that a
    /// partial write leaves a tail recovery can recognise, never a frame with a
    /// valid CRC over half a value.
    pub fn append(&self, op: WalOp, key: &[u8], value: &[u8]) -> Result<u64, Error> {
        let mut g = self.inner.lock();
        let seq = g.next_seq;

        let mut frame = Vec::with_capacity(MIN_FRAME_LEN + key.len() + value.len());
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.push(op as u8);
        frame.extend_from_slice(&(key.len() as u32).to_le_bytes());
        frame.extend_from_slice(key);
        frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
        frame.extend_from_slice(value);
        let crc = crc32fast::hash(&frame);
        frame.extend_from_slice(&crc.to_le_bytes());

        g.writer.write_all(&frame)?;
        g.writer.flush()?;
        g.next_seq = seq.saturating_add(1);
        g.segment_bytes = g.segment_bytes.saturating_add(frame.len() as u64);
        Ok(seq)
    }

    pub fn sync(&self) -> Result<(), Error> {
        let mut g = self.inner.lock();
        g.writer.flush()?;
        g.writer.get_ref().sync_data()?;
        Ok(())
    }

    /// Drops every record in the segment and starts a fresh one that keeps
    /// counting from the current sequence.
    ///
    /// # Safety of use
    ///
    /// Not memory safety — data safety. After this call the discarded records
    /// exist nowhere else, so the caller must have fenced on
    /// [`ferriskv_core::Storage::flush`] first. Rotating a log whose records
    /// only ever reached a non-durable backend destroys them.
    pub fn rotate(&self) -> Result<(), Error> {
        let mut g = self.inner.lock();
        g.writer.flush()?;
        let base_seq = g.next_seq;

        let mut fresh = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        fresh.write_all(&encode_header(base_seq))?;
        fresh.sync_data()?;
        drop(fresh);

        let appender = OpenOptions::new().append(true).open(&self.path)?;
        g.writer = BufWriter::new(appender);
        g.segment_bytes = HEADER_LEN as u64;
        Ok(())
    }

    /// Sequence the next append will use. Exposed for metrics and assertions.
    pub fn next_seq(&self) -> u64 {
        self.inner.lock().next_seq
    }

    /// Current on-disk size of the segment, header included.
    pub fn segment_bytes(&self) -> u64 {
        self.inner.lock().segment_bytes
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use tempfile::TempDir;

    use super::*;

    fn open(dir: &TempDir) -> (Wal, Recovery) {
        Wal::open(dir.path().join("wal.log")).unwrap()
    }

    #[test]
    fn fresh_segment_starts_at_zero_and_writes_a_header() {
        let dir = TempDir::new().unwrap();
        let (wal, rec) = open(&dir);
        assert!(rec.is_empty());
        assert_eq!(rec.next_seq, 0);
        assert_eq!(rec.truncated_bytes, 0);
        assert_eq!(
            std::fs::metadata(wal.path()).unwrap().len() as usize,
            HEADER_LEN
        );
    }

    #[test]
    fn append_returns_monotonic_seq() {
        let dir = TempDir::new().unwrap();
        let (wal, _) = open(&dir);
        assert_eq!(wal.append(WalOp::Put, b"k1", b"v1").unwrap(), 0);
        assert_eq!(wal.append(WalOp::Put, b"k2", b"v2").unwrap(), 1);
        assert_eq!(wal.append(WalOp::Delete, b"k1", b"").unwrap(), 2);
    }

    #[test]
    fn reopen_returns_every_record_in_write_order() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let (wal, _) = Wal::open(&path).unwrap();
            wal.append(WalOp::Put, b"a", b"1").unwrap();
            wal.append(WalOp::Put, b"b", b"2").unwrap();
            wal.append(WalOp::Delete, b"a", b"").unwrap();
            wal.sync().unwrap();
        }
        let (wal, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.truncated_bytes, 0);
        assert_eq!(rec.next_seq, 3);
        assert_eq!(wal.append(WalOp::Put, b"c", b"3").unwrap(), 3);

        let ops: Vec<_> = rec.records.iter().map(|r| (r.seq, r.op)).collect();
        assert_eq!(
            ops,
            vec![(0, WalOp::Put), (1, WalOp::Put), (2, WalOp::Delete)]
        );
        assert_eq!(&rec.records[0].key[..], b"a");
        assert_eq!(&rec.records[0].value[..], b"1");
        assert_eq!(&rec.records[2].value[..], b"");
    }

    #[test]
    fn empty_key_and_value_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let (wal, _) = Wal::open(&path).unwrap();
            wal.append(WalOp::Delete, b"", b"").unwrap();
            wal.sync().unwrap();
        }
        let (_, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.records.len(), 1);
        assert!(rec.records[0].key.is_empty());
    }

    #[test]
    fn torn_tail_is_discarded_and_the_segment_stays_usable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let (wal, _) = Wal::open(&path).unwrap();
            wal.append(WalOp::Put, b"a", b"1").unwrap();
            wal.append(WalOp::Put, b"b", b"2").unwrap();
            wal.sync().unwrap();
        }
        // A crash mid-write leaves the head of a frame behind.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xAB; 11]).unwrap();
        f.sync_data().unwrap();
        drop(f);

        let (wal, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.records.len(), 2);
        assert_eq!(rec.truncated_bytes, 11);
        assert_eq!(rec.next_seq, 2);

        // The garbage is gone from disk, so the next append is readable again.
        wal.append(WalOp::Put, b"c", b"3").unwrap();
        wal.sync().unwrap();
        drop(wal);
        let (_, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.records.len(), 3);
        assert_eq!(rec.truncated_bytes, 0);
        assert_eq!(&rec.records[2].key[..], b"c");
    }

    #[test]
    fn a_flipped_bit_stops_recovery_at_that_frame() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let (wal, _) = Wal::open(&path).unwrap();
            wal.append(WalOp::Put, b"a", b"first").unwrap();
            wal.append(WalOp::Put, b"b", b"second").unwrap();
            wal.append(WalOp::Put, b"c", b"third").unwrap();
            wal.sync().unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        // Corrupt a value byte inside the second frame. Its length fields stay
        // intact, so only the CRC can catch it.
        let first_frame_len = MIN_FRAME_LEN + 1 + 5;
        let target = HEADER_LEN + first_frame_len + 13 + 1 + 4 + 1;
        bytes[target] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        let (_, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.records.len(), 1, "recovery must stop at the bad frame");
        assert_eq!(&rec.records[0].key[..], b"a");
        assert!(rec.truncated_bytes > 0);
    }

    #[test]
    fn a_foreign_file_is_refused_rather_than_overwritten() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        std::fs::write(&path, b"this is somebody else's file, please do not eat").unwrap();
        assert!(matches!(Wal::open(&path), Err(Error::Corrupt(_))));
    }

    #[test]
    fn an_unknown_format_version_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        let mut header = encode_header(0);
        header[4..6].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        std::fs::write(&path, header).unwrap();
        assert!(matches!(Wal::open(&path), Err(Error::Corrupt(_))));
    }

    #[test]
    fn a_header_shorter_than_the_layout_is_refused() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        std::fs::write(&path, &MAGIC[..3]).unwrap();
        assert!(matches!(Wal::open(&path), Err(Error::Corrupt(_))));
    }

    #[test]
    fn rotate_forgets_the_records_but_not_the_sequence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        let (wal, _) = Wal::open(&path).unwrap();
        wal.append(WalOp::Put, b"a", b"1").unwrap();
        wal.append(WalOp::Put, b"b", b"2").unwrap();
        wal.rotate().unwrap();

        assert_eq!(wal.next_seq(), 2);
        assert_eq!(wal.append(WalOp::Put, b"c", b"3").unwrap(), 2);
        wal.sync().unwrap();
        drop(wal);

        let (_, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.records.len(), 1, "rotated records must be gone");
        assert_eq!(rec.records[0].seq, 2, "sequences must not move backwards");
        assert_eq!(rec.next_seq, 3);
    }

    #[test]
    fn an_empty_rotated_segment_still_remembers_where_it_starts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let (wal, _) = Wal::open(&path).unwrap();
            wal.append(WalOp::Put, b"a", b"1").unwrap();
            wal.append(WalOp::Put, b"b", b"2").unwrap();
            wal.rotate().unwrap();
        }
        let (_, rec) = Wal::open(&path).unwrap();
        assert!(rec.is_empty());
        assert_eq!(
            rec.next_seq, 2,
            "base_seq in the header carries the sequence across rotations"
        );
    }

    #[test]
    fn segment_bytes_tracks_the_file_and_resets_on_rotate() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        let (wal, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.segment_bytes, HEADER_LEN as u64);

        wal.append(WalOp::Put, b"key", b"value").unwrap();
        wal.append(WalOp::Put, b"other", b"payload").unwrap();
        wal.sync().unwrap();
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            wal.segment_bytes(),
            on_disk,
            "the counter must match what a stat() would report"
        );

        wal.rotate().unwrap();
        assert_eq!(wal.segment_bytes(), HEADER_LEN as u64);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), HEADER_LEN as u64);
    }

    #[test]
    fn a_torn_tail_is_not_counted_in_segment_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let (wal, _) = Wal::open(&path).unwrap();
            wal.append(WalOp::Put, b"a", b"1").unwrap();
            wal.sync().unwrap();
        }
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xAB; 7]).unwrap();
        drop(f);

        let (wal, rec) = Wal::open(&path).unwrap();
        assert_eq!(rec.truncated_bytes, 7);
        assert_eq!(wal.segment_bytes(), std::fs::metadata(&path).unwrap().len());
    }

    #[test]
    fn parse_frames_never_panics_on_arbitrary_bytes() {
        // Spot-check the shapes a fuzzer would reach first; the exhaustive
        // version of this check lives in the fuzz target.
        for len in 0..64usize {
            let _ = parse_frames(&vec![0xFFu8; len]);
            let _ = parse_frames(&vec![0u8; len]);
        }
        // A frame claiming a key far larger than the buffer must be a short
        // read, not an allocation.
        let mut bogus = vec![0u8; MIN_FRAME_LEN];
        bogus[8] = WalOp::Put as u8;
        bogus[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        let (records, consumed) = parse_frames(&bogus);
        assert!(records.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn unknown_opcodes_are_rejected() {
        assert_eq!(WalOp::from_u8(1), Some(WalOp::Put));
        assert_eq!(WalOp::from_u8(2), Some(WalOp::Delete));
        for b in [0u8, 3, 42, 255] {
            assert_eq!(WalOp::from_u8(b), None);
        }
    }
}
