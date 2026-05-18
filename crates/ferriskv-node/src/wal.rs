use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use ferriskv_core::Error;

pub struct Wal {
    path: PathBuf,
    inner: Mutex<WalInner>,
}

struct WalInner {
    writer: BufWriter<File>,
    next_seq: u64,
}

impl Wal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        let next_seq = read_last_seq(&path)?.map(|s| s + 1).unwrap_or(0);
        Ok(Self {
            path,
            inner: Mutex::new(WalInner {
                writer: BufWriter::new(file),
                next_seq,
            }),
        })
    }

    pub fn append(&self, op: u8, key: &[u8], value: &[u8]) -> Result<u64, Error> {
        let mut g = self.inner.lock();
        let seq = g.next_seq;
        let mut frame = Vec::with_capacity(8 + 1 + 4 + key.len() + 4 + value.len() + 4);
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.push(op);
        frame.extend_from_slice(&(key.len() as u32).to_le_bytes());
        frame.extend_from_slice(key);
        frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
        frame.extend_from_slice(value);
        let crc = crc32fast::hash(&frame);
        frame.extend_from_slice(&crc.to_le_bytes());
        g.writer.write_all(&frame)?;
        g.writer.flush()?;
        g.next_seq += 1;
        Ok(seq)
    }

    pub fn sync(&self) -> Result<(), Error> {
        let mut g = self.inner.lock();
        g.writer.flush()?;
        g.writer.get_ref().sync_data()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn read_last_seq(path: &Path) -> Result<Option<u64>, Error> {
    let mut file = File::open(path)?;
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let mut pos = 0usize;
    let mut last = None;
    while pos + 21 <= buf.len() {
        let seq = u64::from_le_bytes(
            buf[pos..pos + 8]
                .try_into()
                .map_err(|_| Error::Corrupt("seq"))?,
        );
        let klen = u32::from_le_bytes(
            buf[pos + 9..pos + 13]
                .try_into()
                .map_err(|_| Error::Corrupt("klen"))?,
        ) as usize;
        let vlen_off = pos + 13 + klen;
        if vlen_off + 4 > buf.len() {
            return Err(Error::Corrupt("vlen-bounds"));
        }
        let vlen = u32::from_le_bytes(
            buf[vlen_off..vlen_off + 4]
                .try_into()
                .map_err(|_| Error::Corrupt("vlen"))?,
        ) as usize;
        let end = vlen_off + 4 + vlen + 4;
        if end > buf.len() {
            return Err(Error::Corrupt("frame-bounds"));
        }
        last = Some(seq);
        pos = end;
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn append_returns_monotonic_seq() {
        let dir = TempDir::new().unwrap();
        let wal = Wal::open(dir.path().join("wal.log")).unwrap();
        assert_eq!(wal.append(1, b"k1", b"v1").unwrap(), 0);
        assert_eq!(wal.append(1, b"k2", b"v2").unwrap(), 1);
        assert_eq!(wal.append(2, b"k1", b"").unwrap(), 2);
    }

    #[test]
    fn reopen_recovers_next_seq() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.log");
        {
            let wal = Wal::open(&path).unwrap();
            wal.append(1, b"a", b"v").unwrap();
            wal.append(1, b"b", b"v").unwrap();
            wal.sync().unwrap();
        }
        let wal = Wal::open(&path).unwrap();
        assert_eq!(wal.append(1, b"c", b"v").unwrap(), 2);
    }
}
