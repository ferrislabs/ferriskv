# Fuzz targets

Coverage-guided fuzzing over every byte-parser in the workspace. Each target
covers a format that arrives from somewhere the node does not control — disk,
after a crash, or an operator's text editor — so malformed input is a normal
occurrence there rather than an attack.

| Target | Covers | Why it exists |
| --- | --- | --- |
| `key_decode` | `KeyCodec::decode` | Keys come back from disk. A decode that returns `Ok` with the wrong slice boundaries is a tenant-isolation bug, so the target asserts the decoded parts account for every byte, not merely that nothing panicked. |
| `key_roundtrip` | `KeyCodec` decode/encode symmetry | An input `decode` accepts but `encode` cannot produce means a corrupt key reads back as a legitimate one. This target found exactly that: `decode` used to accept a zero-length tenant. |
| `value_decode` | `ValueCodec::decode`, `is_expired` | `is_expired` re-parses the TTL header without allocating, so there are two parsers over one format. This is what keeps them from drifting. |
| `wal_frame` | `wal::parse_frames`, `wal::parse_header` | The tail of a WAL segment is torn by definition — the process can die mid-write — so this parser meets malformed input on the ordinary recovery path. |
| `node_config` | TOML through to `NodeConfig::validate` | A panic here is a node that will not start and cannot say why. Validation is included: a config that deserializes but describes an impossible node must be refused with a message. |

Avro schema parsing is listed in [#35](https://github.com/ferrislabs/ferriskv/issues/35)
but has no target yet, because Avro validation itself is not implemented
([#27](https://github.com/ferrislabs/ferriskv/issues/27)). The target belongs in
that change.

## Running them

Requires nightly (libFuzzer needs sanitizer flags stable does not expose) and
`cargo-fuzz`:

```sh
cargo install cargo-fuzz
make fuzz                          # one 60s pass per target, what CI runs on a PR
SECONDS_PER_TARGET=600 make fuzz   # what the nightly workflow runs
```

One target on its own, with a longer budget:

```sh
mkdir -p fuzz/corpus/wal_frame
cargo +nightly fuzz run wal_frame fuzz/corpus/wal_frame fuzz/seeds/wal_frame
```

On a host whose default target links libc statically — musl, as some CI images
report — AddressSanitizer cannot be linked at all and the build fails before a
single input is tried. Pass the gnu triple explicitly:

```sh
cargo +nightly fuzz run wal_frame --target x86_64-unknown-linux-gnu ...
```

The CI workflow pins it for exactly this reason.

## Corpus layout

`seeds/<target>/` is committed and read-only. `corpus/<target>/` is where
libFuzzer accumulates what it discovers, and is gitignored. Passing both — with
the working corpus first — is deliberate: libFuzzer only writes new inputs to
the first directory, so a CI run cannot churn the committed seeds.

The seeds are hand-written rather than harvested: valid inputs for every branch
of each format, plus the near-misses each parser has to reject. A fuzzer will
eventually derive a well-formed WAL frame on its own, but only after
rediscovering CRC32, so handing it one is worth far more than the bytes cost.

## When a target fails

libFuzzer writes the crashing input to `fuzz/artifacts/<target>/`. The CI
workflow uploads that directory, because without the input a failed run says
only "something panicked". To reproduce and then keep it honest:

```sh
cargo +nightly fuzz run wal_frame fuzz/artifacts/wal_frame/crash-<hash>
```

Fix the parser, then add the reduced input to `seeds/<target>/` so the case is
covered deterministically from then on, not only when the fuzzer rediscovers it.
