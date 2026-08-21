# Roadmap

Six phases, each tracked as a GitHub milestone. Phases run roughly in order, but parts of P3 and P5 can land alongside P1 and P2.

The authoritative source of truth is the [milestones list](https://github.com/ferrislabs/ferriskv/milestones) on GitHub; this document gives the intent behind each phase.

## P0: Single-node production readiness

Make the single-node binary safe to run in real environments. Authentication, TLS, resource limits, observability, TTL, deployment artifacts. By the end of P0 the server is something you can put behind a reverse proxy on a private network and use.

Notable items: auth interceptor, TLS, Prometheus metrics, health checks, audit log, Docker and systemd files.

## P1: Distribution

Replace the single node with a cluster. Three components land in this phase:

- A coordinator cluster running Raft (via raft-rs) that holds the placement table.
- Per-shard Raft groups on the storage nodes, multiplexed by a MultiRaft scheduler.
- A range-based placement model where each shard owns a contiguous slice of the keyspace, splits when it grows too large, and rebalances when nodes come and go.

By the end of P1, killing a node does not take the cluster down, adding a node redistributes data, and clients route requests to the shard that owns the key.

## P2: Transactions

ACID multi-key transactions. Three subsystems:

- A batched timestamp oracle served by the coord Raft leader.
- MVCC encoding on top of fjall, with a background garbage collector.
- Percolator two-phase commit, including a lock cleanup worker for crashed clients.

By the end of P2, transactions across keys, across shards, and across tenants are serializable.

## P3: Multi-tenant database features

Higher-level capabilities. Watches let clients subscribe to changes on a prefix. Per-tenant quotas track storage and operation rate, with throttling for noisy neighbours. Optional Avro schemas validate writes against a typed contract. Secondary indexes turn the KV into something you can query on non-primary fields. Encryption at rest uses a derived key per tenant.

By the end of P3, FerrisKV is no longer just a KV store; it is a database with isolation, optional schemas, and queryable indexes.

## P4: SQL and ecosystem

A new crate, `ferriskv-sql`, exposes a DataFusion table provider over the transactional KV. Pushdown for predicates on the primary key and for projection keeps the server work small. Client libraries for Go, Python, and Node make it usable beyond Rust. A Kubernetes operator and a Helm chart cover deployment. Automated backups stream snapshots to object storage.

By the end of P4, FerrisKV is reachable from outside the Rust ecosystem and operable from a Kubernetes cluster.

## P5: Maturity

Property tests with `madsim` exercise the distributed layer under injected partitions, restarts, and clock skew. Fuzz targets already cover the codecs, the WAL parser, and the config loader; what remains here is the Avro schema parser, which lands with schema validation itself. Benchmarks with `criterion` and `goose` track regressions over time. A documentation site collects everything that today lives in `docs/`.

P5 is continuous; it overlaps with the other phases as soon as there is something to test.

## How to read the issue tracker

- Each phase has a milestone. Filter issues by milestone to see scope.
- Labels starting with `area:` group issues by subsystem (`storage`, `raft`, `txn`, `auth`, `observability`, `deploy`, `proto`, `sql`, `client`, `core`).
- Labels starting with `priority:` mark importance inside a phase.
- The `type:tech-debt` label tracks known shortcuts that need cleanup later.
