# FerrisKV

[![CI](https://github.com/ferrislabs/ferriskv/actions/workflows/ci.yml/badge.svg)](https://github.com/ferrislabs/ferriskv/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ferrislabs/ferriskv/branch/main/graph/badge.svg)](https://codecov.io/gh/ferrislabs/ferriskv)
[![License](https://img.shields.io/github/license/ferrislabs/ferriskv)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![Issues](https://img.shields.io/github/issues/ferrislabs/ferriskv)](https://github.com/ferrislabs/ferriskv/issues)
[![Last commit](https://img.shields.io/github/last-commit/ferrislabs/ferriskv)](https://github.com/ferrislabs/ferriskv/commits/main)

A distributed key-value store in Rust. Every tenant gets its own slice of an ordered keyspace, and the rest of the design works out from there.

## Status

Early. The single-node binary runs. It speaks gRPC, keeps tenants apart at the keyspace level, has configurable limits, shuts down without losing in-flight requests, and stores data either in memory or on disk through fjall. Everything that would make it actually distributed (Raft, range sharding, transactions) is on the roadmap and tracked as [milestones](https://github.com/ferrislabs/ferriskv/milestones).

A short reality check before going further: [Current capabilities](#current-capabilities) lists what works. [What is not done yet](#what-is-not-done-yet) lists what does not. Do not run this in production.

## Why

The whole design starts from one decision: tenants belong inside the keyspace, not on top of it. Every key carries a tenant prefix. That means a tenant's data is contiguous on disk and contiguous across shards, range scans inside a tenant stay local to a small number of shards, and per-tenant accounting (bytes used, ops/second) falls out for free. Tenants do not get separate processes or VMs; the isolation is logical and that is enough.

The second piece is the provisioning model. Picking instance sizes and disk volumes for a database is a bad time, so the goal is to not ask. Nodes join. Shards split when they grow past a target size. The placement layer moves things around. The cluster has whatever capacity it has.

If this reminds you of FoundationDB, that is the point. The keyspace model is borrowed. The difference is that FerrisKV does not sit on top of FoundationDB; it tries to reach a similar surface on a pure-Rust stack: fjall for local storage, raft-rs for consensus, tonic for gRPC.

## Architecture

Short version below. Longer write-up in [docs/architecture.md](docs/architecture.md).

```
                 +---------------------------------+
                 | Coordinator cluster (3 to 5)    |
                 | Raft-replicated metadata:       |
                 |   placement table, schemas,     |
                 |   timestamp oracle              |
                 +-----------------+---------------+
                                   |
                 +-----------------+---------------+
                 | Storage nodes                   |
                 | Per-shard Raft groups           |
                 | Local engine: fjall (LSM)       |
                 | MVCC + Percolator on top        |
                 +-----------------+---------------+
                                   |
                 +-----------------+---------------+
                 | Clients (CLI, gRPC, eventually  |
                 | SQL via DataFusion)             |
                 +---------------------------------+
```

What exists today is the scaffolding. The Raft and transactional code lives in proto definitions and roadmap issues, not in running code.

## Keyspace layout

Keys have structure. Encoding details in [docs/keyspace.md](docs/keyspace.md). The summary:

```
[tenant length: u8] [tenant bytes] [subspace: u8] [user key]
```

Four subspaces per tenant:

| Byte | Subspace   | What lives here                            |
|------|------------|--------------------------------------------|
| 0    | metadata   | Schemas, configuration, ACLs               |
| 1    | data       | User records, keyed by primary key         |
| 2    | index      | Secondary indexes for non-primary lookup   |
| 3    | stats      | Storage usage and telemetry                |

Lexicographic order is preserved, so a tenant's data is one contiguous range and a prefix scan over `1_data` only reads inside that tenant.

## Current capabilities

The server handles gRPC `get`, `put`, `delete`, streamed `scan`, and `batch`. Tenant isolation is enforced at the keyspace level. Two storage backends are configurable: an in-memory `DashMap` for development, or `fjall` for persistence. The write-ahead log on disk recovers its sequence counter at boot. Configurable limits on key size, value size, batch size, and scan cap. Shutdown handles SIGINT and SIGTERM, drains in-flight requests, and flushes the WAL before exiting. The workspace currently has 51 tests covering the codec, the storage backends, the placement structure, the gRPC handlers, and the auth primitives.

## What is not done yet

No authentication is enforced. The auth crate carries JWT and RBAC primitives, but nothing plugs them into the gRPC stack, so the server trusts whoever connects. No TLS either. The `ttl_ms` field of `PutRequest` is accepted and silently ignored. No replication, so losing the single node loses data. No multi-key transactions, no MVCC, no snapshot reads. The `Watch` RPC returns `Unimplemented`.

All of it is tracked as [issues](https://github.com/ferrislabs/ferriskv/issues), grouped under the [milestones](https://github.com/ferrislabs/ferriskv/milestones).

## Getting started

Build the release binaries.

```sh
cargo build --release -p ferriskv-node -p ferriskv-cli
```

Write a minimal config.

```sh
mkdir -p config data
cat > config/node.toml <<'EOF'
node_id = "node-0"
listen = "127.0.0.1:7100"
data_dir = "./data/node"
coord_endpoints = []
backend = "fjall"
shutdown_timeout_secs = 30

[limits]
max_key_size = 4096
max_value_size = 10485760
max_batch_ops = 1000
max_scan_limit = 10000
EOF
```

Start the node.

```sh
./target/release/ferriskv-node --config config/node.toml
```

## Health checks

Set `admin_listen` in `node.toml` to start a secondary HTTP server with two routes:

```toml
admin_listen = "127.0.0.1:7101"
```

- `GET /healthz` returns `200 OK` while the process is alive.
- `GET /readyz` returns `200 OK` when the storage engine answers a probe read, `503` otherwise.
- `GET /metrics` returns Prometheus text format with RPC latencies and counters, value size histograms, and audit event counts.

Bind to `127.0.0.1` (the default convention) so the routes stay reachable only from the same host: Kubernetes probes, sidecars and local agents have access, the outside network does not. If you genuinely need cross-host scraping, switch to `0.0.0.0` and pair it with a `NetworkPolicy` or firewall rule. The server logs a warning at startup when it binds outside loopback.

Leaving `admin_listen` unset disables the admin server entirely.

## TTL

Two settings, one per request, one server-wide. They are independent.

**Per-request, on the `put`:** `ttl_ms`. The lifetime of that specific key in milliseconds. `0` (the default) means the key never expires. Set it via the CLI flag `--ttl-ms` or directly in `PutRequest.ttl_ms` from a gRPC client. Stored values are framed with a one-byte version prefix; setting a TTL adds an 8-byte expiration timestamp on top.

**Server-wide, in `node.toml`:** `ttl_sweep_interval_secs`. Maximum interval between two passes of the background TTL sweeper, in seconds. Default 60. Setting it to `0` disables the sweeper entirely, in which case expired values stay on disk but remain invisible to reads (a get on an expired key still returns "not found").

```toml
ttl_sweep_interval_secs = 60
```

Internally the node keeps an in-memory index of keys with a scheduled expiration. The sweeper wakes exactly when the next key is due, not on a fixed tick, so cleanup happens at the millisecond after expiration in the common case. The interval above is only an upper bound used as a fallback (so the loop still runs from time to time even when no key has a TTL). Expired keys disappear from reads immediately regardless of when the sweeper runs.

Quick test:

```sh
# 5-second TTL
./target/release/ferriskv --tenant alice put hello world --ttl-ms 5000
./target/release/ferriskv --tenant alice get hello   # world
sleep 6
./target/release/ferriskv --tenant alice get hello   # exits 1
```

The GC currently does a full keyspace scan per pass, which is fine for the scale targeted in P0. An indexed scan keyed by expiration time is planned for later.

## TLS

The server listens in plaintext by default. To enable TLS, add a `[tls]` section to `node.toml` pointing at a certificate and key in PEM format:

```toml
[tls]
cert_path = "/etc/ferriskv/server.crt"
key_path  = "/etc/ferriskv/server.key"
```

For local development, [mkcert](https://github.com/FiloSottile/mkcert) is the fastest way to get a trusted certificate:

```sh
mkcert -install
mkcert -cert-file server.crt -key-file server.key localhost 127.0.0.1
```

For production, point at certificates issued by Let's Encrypt or your internal CA. The node does not handle certificate renewal; reload by restarting the process or use a sidecar that watches the file and signals the node.

Use the CLI.

```sh
./target/release/ferriskv --tenant alice put hello world
./target/release/ferriskv --tenant alice get hello
./target/release/ferriskv --tenant alice scan ""
./target/release/ferriskv --tenant alice delete hello
```

A different tenant sees none of alice's keys, even when the user-supplied key is identical:

```sh
./target/release/ferriskv --tenant bob get hello
```

## Workspace layout

| Crate            | Role                                                       |
|------------------|------------------------------------------------------------|
| `ferriskv-core`  | Key codec, storage trait, error types, limits, hashing     |
| `ferriskv-proto` | Protobuf generated by `tonic-build` (pure Rust via protox) |
| `ferriskv-auth`  | JWT verification, RBAC, API key store                      |
| `ferriskv-coord` | Coordinator binary and placement code                      |
| `ferriskv-node`  | Storage node binary, WAL, gRPC service                     |
| `ferriskv-cli`   | Command-line client                                        |

## Development

```sh
make test       # cargo test --workspace
make clippy     # cargo clippy --workspace --all-targets -- -D warnings
make fmt        # cargo fmt --all
make build      # cargo build --workspace --all-targets
```

CI runs the same on every push and pull request.

## Roadmap

Six phases, each a GitHub milestone.

| Phase | Theme                                |
|-------|--------------------------------------|
| P0    | Single-node production readiness     |
| P1    | Distribution (Raft, sharding)        |
| P2    | Transactions (MVCC, Percolator)      |
| P3    | Multi-tenant database features       |
| P4    | SQL and ecosystem                    |
| P5    | Maturity (tests, fuzzing, docs)      |

The intent behind each phase is in [docs/roadmap.md](docs/roadmap.md).

## License

Apache-2.0.
