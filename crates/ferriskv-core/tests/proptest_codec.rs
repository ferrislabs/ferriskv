use bytes::Bytes;
use ferriskv_core::key::{KeyCodec, Subspace};
use ferriskv_core::value::ValueCodec;
use proptest::prelude::*;

fn tenant_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_-]{1,64}".prop_map(String::from)
}

fn subspace_strategy() -> impl Strategy<Value = Subspace> {
    prop_oneof![
        Just(Subspace::Metadata),
        Just(Subspace::Data),
        Just(Subspace::Index),
        Just(Subspace::Stats),
    ]
}

fn payload_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024)
}

proptest! {
    #[test]
    fn key_roundtrip(
        tenant in tenant_strategy(),
        sub in subspace_strategy(),
        payload in payload_strategy(),
    ) {
        let encoded = KeyCodec::encode(&tenant, sub, &payload).unwrap();
        let (t, s, p) = KeyCodec::decode(&encoded).unwrap();
        prop_assert_eq!(t, tenant.as_str());
        prop_assert_eq!(s, sub);
        prop_assert_eq!(p, &payload[..]);
    }

    #[test]
    fn encoded_key_starts_with_tenant_prefix(
        tenant in tenant_strategy(),
        sub in subspace_strategy(),
        payload in payload_strategy(),
    ) {
        let encoded = KeyCodec::encode(&tenant, sub, &payload).unwrap();
        let prefix = KeyCodec::encode_tenant_prefix(&tenant).unwrap();
        prop_assert!(encoded.starts_with(&prefix));
    }

    #[test]
    fn distinct_tenants_never_overlap(
        a in tenant_strategy(),
        b in tenant_strategy(),
        payload in payload_strategy(),
    ) {
        prop_assume!(a != b);
        let ka = KeyCodec::encode(&a, Subspace::Data, &payload).unwrap();
        let pb = KeyCodec::encode_tenant_prefix(&b).unwrap();
        prop_assert!(!ka.starts_with(&pb));
    }

    #[test]
    fn subspace_ordering_within_tenant(
        tenant in tenant_strategy(),
        payload in payload_strategy(),
    ) {
        let meta = KeyCodec::encode(&tenant, Subspace::Metadata, &payload).unwrap();
        let data = KeyCodec::encode(&tenant, Subspace::Data, &payload).unwrap();
        let index = KeyCodec::encode(&tenant, Subspace::Index, &payload).unwrap();
        let stats = KeyCodec::encode(&tenant, Subspace::Stats, &payload).unwrap();
        prop_assert!(meta < data);
        prop_assert!(data < index);
        prop_assert!(index < stats);
    }

    #[test]
    fn payload_ordering_preserved_within_subspace(
        tenant in tenant_strategy(),
        sub in subspace_strategy(),
        a in payload_strategy(),
        b in payload_strategy(),
    ) {
        let ka = KeyCodec::encode(&tenant, sub, &a).unwrap();
        let kb = KeyCodec::encode(&tenant, sub, &b).unwrap();
        prop_assert_eq!(ka.cmp(&kb), a.cmp(&b));
    }

    #[test]
    fn value_roundtrip_no_ttl(payload in payload_strategy()) {
        let encoded = ValueCodec::encode(&payload, None);
        let decoded = ValueCodec::decode(encoded).unwrap();
        prop_assert_eq!(decoded.expires_at_ms, None);
        prop_assert_eq!(&decoded.value[..], &payload[..]);
    }

    #[test]
    fn value_roundtrip_with_ttl(payload in payload_strategy(), exp in any::<u64>()) {
        let encoded = ValueCodec::encode(&payload, Some(exp));
        let decoded = ValueCodec::decode(encoded).unwrap();
        prop_assert_eq!(decoded.expires_at_ms, Some(exp));
        prop_assert_eq!(&decoded.value[..], &payload[..]);
    }

    #[test]
    fn is_expired_matches_decode(payload in payload_strategy(), exp in any::<u64>(), now in any::<u64>()) {
        let encoded = ValueCodec::encode(&payload, Some(exp));
        let by_helper = ValueCodec::is_expired(&encoded, now).unwrap();
        let by_decode = exp <= now;
        prop_assert_eq!(by_helper, by_decode);
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = KeyCodec::decode(&bytes);
        let _ = ValueCodec::decode(Bytes::from(bytes));
    }
}
