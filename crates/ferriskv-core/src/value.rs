use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

const VERSION_NO_TTL: u8 = 0;
const VERSION_WITH_TTL: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredValue {
    pub expires_at_ms: Option<u64>,
    pub value: Bytes,
}

pub struct ValueCodec;

impl ValueCodec {
    pub fn encode(value: &[u8], expires_at_ms: Option<u64>) -> Bytes {
        match expires_at_ms {
            None => {
                let mut out = BytesMut::with_capacity(1 + value.len());
                out.put_u8(VERSION_NO_TTL);
                out.put_slice(value);
                out.freeze()
            }
            Some(exp) => {
                let mut out = BytesMut::with_capacity(1 + 8 + value.len());
                out.put_u8(VERSION_WITH_TTL);
                out.put_u64(exp);
                out.put_slice(value);
                out.freeze()
            }
        }
    }

    pub fn decode(raw: Bytes) -> Result<StoredValue> {
        if raw.is_empty() {
            return Err(Error::Corrupt("empty value"));
        }
        match raw[0] {
            VERSION_NO_TTL => Ok(StoredValue {
                expires_at_ms: None,
                value: raw.slice(1..),
            }),
            VERSION_WITH_TTL => {
                if raw.len() < 9 {
                    return Err(Error::Corrupt("ttl value too short"));
                }
                let exp =
                    u64::from_be_bytes(raw[1..9].try_into().map_err(|_| Error::Corrupt("ttl"))?);
                Ok(StoredValue {
                    expires_at_ms: Some(exp),
                    value: raw.slice(9..),
                })
            }
            _ => Err(Error::Corrupt("unknown value version")),
        }
    }

    /// Length of the caller's value inside an encoded entry, without decoding it.
    ///
    /// Usage accounting needs the size of the value a key currently holds in
    /// order to compute the delta an overwrite represents. Going through
    /// [`Self::decode`] for that would build a `StoredValue` and clone the
    /// payload handle for a number.
    #[inline]
    pub fn payload_len(raw: &[u8]) -> Result<usize> {
        if raw.is_empty() {
            return Err(Error::Corrupt("empty value"));
        }
        match raw[0] {
            VERSION_NO_TTL => Ok(raw.len() - 1),
            VERSION_WITH_TTL => {
                if raw.len() < 9 {
                    return Err(Error::Corrupt("ttl value too short"));
                }
                Ok(raw.len() - 9)
            }
            _ => Err(Error::Corrupt("unknown value version")),
        }
    }

    #[inline]
    pub fn is_expired(raw: &[u8], now_ms: u64) -> Result<bool> {
        if raw.is_empty() {
            return Err(Error::Corrupt("empty value"));
        }
        match raw[0] {
            VERSION_NO_TTL => Ok(false),
            VERSION_WITH_TTL => {
                if raw.len() < 9 {
                    return Err(Error::Corrupt("ttl value too short"));
                }
                let exp =
                    u64::from_be_bytes(raw[1..9].try_into().map_err(|_| Error::Corrupt("ttl"))?);
                Ok(exp <= now_ms)
            }
            _ => Err(Error::Corrupt("unknown value version")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_then_decode_no_ttl() {
        let encoded = ValueCodec::encode(b"hello", None);
        let decoded = ValueCodec::decode(encoded).unwrap();
        assert_eq!(decoded.expires_at_ms, None);
        assert_eq!(&decoded.value[..], b"hello");
    }

    #[test]
    fn encode_then_decode_with_ttl() {
        let encoded = ValueCodec::encode(b"hello", Some(1_700_000_000_000));
        let decoded = ValueCodec::decode(encoded).unwrap();
        assert_eq!(decoded.expires_at_ms, Some(1_700_000_000_000));
        assert_eq!(&decoded.value[..], b"hello");
    }

    #[test]
    fn encode_empty_value_works() {
        let encoded = ValueCodec::encode(b"", Some(42));
        let decoded = ValueCodec::decode(encoded).unwrap();
        assert_eq!(decoded.expires_at_ms, Some(42));
        assert_eq!(decoded.value.len(), 0);
    }

    #[test]
    fn no_ttl_is_never_expired() {
        let encoded = ValueCodec::encode(b"x", None);
        assert!(!ValueCodec::is_expired(&encoded, u64::MAX).unwrap());
    }

    #[test]
    fn ttl_expires_at_boundary() {
        let encoded = ValueCodec::encode(b"x", Some(100));
        assert!(!ValueCodec::is_expired(&encoded, 99).unwrap());
        assert!(ValueCodec::is_expired(&encoded, 100).unwrap());
        assert!(ValueCodec::is_expired(&encoded, 101).unwrap());
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(ValueCodec::decode(Bytes::new()).is_err());
    }

    #[test]
    fn decode_rejects_truncated_ttl() {
        let mut bad = BytesMut::new();
        bad.put_u8(VERSION_WITH_TTL);
        bad.put_slice(&[0u8; 4]);
        assert!(ValueCodec::decode(bad.freeze()).is_err());
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut bad = BytesMut::new();
        bad.put_u8(99);
        bad.put_slice(b"hello");
        assert!(ValueCodec::decode(bad.freeze()).is_err());
    }

    #[test]
    fn payload_len_matches_decode_for_both_versions() {
        for (payload, ttl) in [
            (&b""[..], None),
            (&b"x"[..], None),
            (&b"hello world"[..], None),
            (&b""[..], Some(0u64)),
            (&b"hello"[..], Some(u64::MAX)),
        ] {
            let encoded = ValueCodec::encode(payload, ttl);
            assert_eq!(
                ValueCodec::payload_len(&encoded).unwrap(),
                ValueCodec::decode(encoded.clone()).unwrap().value.len(),
            );
            assert_eq!(ValueCodec::payload_len(&encoded).unwrap(), payload.len());
        }
    }

    #[test]
    fn payload_len_rejects_what_decode_rejects() {
        assert!(ValueCodec::payload_len(b"").is_err());
        assert!(ValueCodec::payload_len(&[VERSION_WITH_TTL, 0, 0, 0]).is_err());
        assert!(ValueCodec::payload_len(&[99, b'x']).is_err());
    }

    #[test]
    fn no_ttl_overhead_is_one_byte() {
        let encoded = ValueCodec::encode(b"hello", None);
        assert_eq!(encoded.len(), 1 + 5);
    }

    #[test]
    fn ttl_overhead_is_nine_bytes() {
        let encoded = ValueCodec::encode(b"hello", Some(1));
        assert_eq!(encoded.len(), 1 + 8 + 5);
    }
}
