use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Subspace {
    Metadata = 0,
    Data = 1,
    Index = 2,
    Stats = 3,
}

impl Subspace {
    #[inline]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Metadata),
            1 => Some(Self::Data),
            2 => Some(Self::Index),
            3 => Some(Self::Stats),
            _ => None,
        }
    }
}

const MAX_TENANT_LEN: usize = 255;

pub struct KeyCodec;

impl KeyCodec {
    #[inline]
    fn write_tenant(out: &mut BytesMut, tenant: &str) {
        debug_assert!(!tenant.is_empty(), "tenant must not be empty");
        debug_assert!(tenant.len() <= MAX_TENANT_LEN, "tenant exceeds 255 bytes");
        out.put_u8(tenant.len() as u8);
        out.put_slice(tenant.as_bytes());
    }

    pub fn encode(tenant: &str, subspace: Subspace, payload: &[u8]) -> Result<Bytes> {
        if tenant.is_empty() {
            return Err(Error::Config("empty tenant".into()));
        }
        if tenant.len() > MAX_TENANT_LEN {
            return Err(Error::Config(format!(
                "tenant length {} exceeds {}",
                tenant.len(),
                MAX_TENANT_LEN
            )));
        }
        let mut out = BytesMut::with_capacity(1 + tenant.len() + 1 + payload.len());
        Self::write_tenant(&mut out, tenant);
        out.put_u8(subspace as u8);
        out.put_slice(payload);
        Ok(out.freeze())
    }

    pub fn encode_subspace_prefix(tenant: &str, subspace: Subspace) -> Result<Bytes> {
        Self::encode(tenant, subspace, &[])
    }

    pub fn encode_tenant_prefix(tenant: &str) -> Result<Bytes> {
        if tenant.is_empty() {
            return Err(Error::Config("empty tenant".into()));
        }
        if tenant.len() > MAX_TENANT_LEN {
            return Err(Error::Config(format!(
                "tenant length {} exceeds {}",
                tenant.len(),
                MAX_TENANT_LEN
            )));
        }
        let mut out = BytesMut::with_capacity(1 + tenant.len());
        Self::write_tenant(&mut out, tenant);
        Ok(out.freeze())
    }

    pub fn decode(key: &[u8]) -> Result<(&str, Subspace, &[u8])> {
        if key.is_empty() {
            return Err(Error::Corrupt("empty key"));
        }
        let tlen = key[0] as usize;
        // `encode` rejects an empty tenant, so a zero length here did not come
        // from this codec. Symmetry matters: whatever `decode` accepts, callers
        // will treat as a real tenant name.
        if tlen == 0 {
            return Err(Error::Corrupt("empty tenant"));
        }
        if 1 + tlen + 1 > key.len() {
            return Err(Error::Corrupt("truncated key"));
        }
        let tenant =
            std::str::from_utf8(&key[1..1 + tlen]).map_err(|_| Error::Corrupt("tenant utf8"))?;
        let sub = Subspace::from_u8(key[1 + tlen]).ok_or(Error::Corrupt("subspace byte"))?;
        let payload = &key[2 + tlen..];
        Ok((tenant, sub, payload))
    }

    #[inline]
    pub fn strip_prefix<'a>(key: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
        key.strip_prefix(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode() {
        let k = KeyCodec::encode("alice", Subspace::Data, b"hello").unwrap();
        let (t, s, p) = KeyCodec::decode(&k).unwrap();
        assert_eq!(t, "alice");
        assert_eq!(s, Subspace::Data);
        assert_eq!(p, b"hello");
    }

    #[test]
    fn tenants_do_not_overlap() {
        let a = KeyCodec::encode("alice", Subspace::Data, b"k").unwrap();
        let b = KeyCodec::encode("bob", Subspace::Data, b"k").unwrap();
        assert_ne!(a, b);
        let pa = KeyCodec::encode_tenant_prefix("alice").unwrap();
        let pb = KeyCodec::encode_tenant_prefix("bob").unwrap();
        assert!(a.starts_with(&pa));
        assert!(!a.starts_with(&pb));
    }

    #[test]
    fn subspaces_are_ordered() {
        let meta = KeyCodec::encode("t", Subspace::Metadata, b"").unwrap();
        let data = KeyCodec::encode("t", Subspace::Data, b"").unwrap();
        let stats = KeyCodec::encode("t", Subspace::Stats, b"").unwrap();
        assert!(meta < data);
        assert!(data < stats);
    }

    #[test]
    fn empty_tenant_rejected() {
        assert!(KeyCodec::encode("", Subspace::Data, b"x").is_err());
    }

    #[test]
    fn decode_rejects_what_encode_can_never_produce() {
        // `encode` refuses an empty tenant, so a leading length of zero cannot
        // come from this codec. Accepting it on the way back in would let a
        // corrupt key decode into a tenant nobody can own, and every caller
        // downstream would treat that empty string as a legitimate tenant.
        let forged = [0u8, Subspace::Data as u8, b'p', b'a', b'y'];
        assert!(matches!(KeyCodec::decode(&forged), Err(Error::Corrupt(_))));
    }

    #[test]
    fn similar_tenants_dont_collide() {
        let a = KeyCodec::encode("default", Subspace::Data, b"k").unwrap();
        let b = KeyCodec::encode("defaults", Subspace::Data, b"k").unwrap();
        let pa = KeyCodec::encode_tenant_prefix("default").unwrap();
        let pb = KeyCodec::encode_tenant_prefix("defaults").unwrap();
        assert!(a.starts_with(&pa) && !a.starts_with(&pb));
        assert!(b.starts_with(&pb) && !b.starts_with(&pa));
    }
}
