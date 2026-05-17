# Keyspace

Every key stored in FerrisKV is a byte string with a fixed structure. This document covers the encoding and the conventions that sit on top of it.

## Encoding

```
+-------------+------------------+--------------+----------------+
| tenant_len  | tenant_bytes     | subspace     | user_key       |
| u8 (1 byte) | tenant_len bytes | u8 (1 byte)  | variable       |
+-------------+------------------+--------------+----------------+
```

The encoding is implemented in `ferriskv-core/src/key.rs`. The codec is the single source of truth; both the server and the proto layer go through it before touching storage.

Three properties matter:

1. **Lexicographic order is preserved inside a tenant.** Once you commit to one tenant, the bytes after the prefix are simply the user key. Sorting by raw bytes equals sorting by user key.
2. **Tenants do not overlap.** Because the tenant length is part of the prefix, a tenant named `foo` and one named `foobar` never share a prefix even though their names do. The encoded prefixes are `[3, f, o, o]` and `[6, f, o, o, b, a, r]`.
3. **The maximum tenant identifier is 255 bytes.** That fits any reasonable identifier (UUIDs, slugs, names) without forcing a length field that would dominate small keys.

## Subspaces

After the tenant prefix, a single byte selects a subspace. Four are defined.

| Byte | Name     | Purpose                                                   |
|------|----------|-----------------------------------------------------------|
| `0`  | metadata | Schemas, ACLs, tenant configuration                       |
| `1`  | data     | User records, keyed by primary key                        |
| `2`  | index    | Secondary indexes, one entry per indexed field value      |
| `3`  | stats    | Storage usage, telemetry, billing counters                |

The byte values are chosen so that, inside a tenant, the subspaces appear in the order metadata, data, index, stats. Metadata lookups walk over a small prefix at the very start of the tenant region; statistics live at the end and never sit between hot reads.

The `Subspace` enum lives in `ferriskv-core/src/key.rs`:

```rust
#[repr(u8)]
pub enum Subspace {
    Metadata = 0,
    Data     = 1,
    Index    = 2,
    Stats    = 3,
}
```

## Encoding a user request

When a client sends `put(tenant = "alice", key = b"order:42", value = ...)`, the server encodes the key as:

```
[5, a, l, i, c, e, 1, o, r, d, e, r, :, 4, 2]
```

That is, length-prefixed `alice`, the `data` subspace byte, then the user-supplied key. Reads, scans, and deletes follow the same rule. The CLI and the gRPC clients only see the user portion; the encoding is purely server-side.

## Prefix scans

A scan with a user-supplied prefix searches `1_data` inside the tenant. The server builds the encoded range:

```
start = [tenant_prefix || 1 || user_prefix]
end   = lexicographically smallest key greater than every key starting with start
```

Computing `end` is a standard byte-string successor: increment the last non-`0xFF` byte and drop everything after it. The result stays inside the tenant's `data` subspace because the subspace byte is `1` (well below `0xFF`), so the successor will never cross into `2_index`.

## Why range sharding follows from this layout

A hash-sharded system would scatter `alice`'s keys across every shard in the cluster. A prefix scan inside `alice` would have to fan out to all shards and merge the results. Range sharding keeps `alice` contiguous, so a prefix scan reads only the shards covering her data, usually one.

The placement layer commits to ranges of encoded keys, not user keys. Splits and merges are decisions over the same byte space the storage engine sees.

## Reserved areas (planned, not yet enforced)

A future system tenant (for example `__sys`) will own:

- Cluster configuration that survives across restarts.
- Persistent counters used by the timestamp oracle.
- Audit trails for administrative actions.

It is referenced through the same codec, so the rules above still apply.

## Caveats

- The codec rejects an empty tenant. There is no global, tenantless area for user data.
- The codec rejects tenants longer than 255 bytes; pick short identifiers.
- The encoding does not include a version byte. If we ever need to evolve the format, we will introduce a new top-level prefix and migrate over.
