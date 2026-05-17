# Architecture

A walk through the layers, what each one is responsible for, and where they sit in the codebase. The system is built around three ideas: an ordered keyspace shared by every tenant, replicated state machines for both metadata and data, and a transactional layer that turns the raw KV into a database with multi-key guarantees.

## Layered view

```
+--------------------------------------------------+
| Clients                                          |
|   CLI, gRPC clients, eventually SQL (DataFusion) |
+----------------------+---------------------------+
                       |
+----------------------v---------------------------+
| Multi-tenant database features                   |
|   Watches, schemas, indexes, quotas, encryption  |
+----------------------+---------------------------+
                       |
+----------------------v---------------------------+
| Transactions                                     |
|   Percolator: prewrite, commit, lock cleanup     |
|   Timestamp Oracle                               |
+----------------------+---------------------------+
                       |
+----------------------v---------------------------+
| Range-sharded distributed KV                     |
|   Per-shard Raft groups, MultiRaft scheduler     |
|   Split, rebalance, snapshot streaming           |
+----------------------+---------------------------+
                       |
+----------------------v---------------------------+
| Local storage                                    |
|   fjall (LSM), separate partitions for data,     |
|   write CF, lock CF, raft log                    |
+--------------------------------------------------+
```

Each layer is independent enough that it can be developed, tested, and reasoned about on its own. Higher layers do not reach past their immediate neighbour.

## Components

### Coordinator cluster

A small set of nodes (three or five), each running the `ferriskv-coord` binary. They form a single Raft group that holds the cluster's metadata:

- **Placement table.** A map from key ranges to replica sets. Looking up a key here tells the routing layer which storage nodes own it.
- **Schema registry.** Per-tenant schemas live in this Raft state, replicated alongside the placement table.
- **Timestamp oracle.** A monotonic counter served by the Raft leader; clients ask for batches of timestamps to avoid round-tripping per transaction.
- **Node membership.** Storage nodes register here at startup and send heartbeats; failures trigger rebalancing.

Because the coord is small and amount of metadata stays bounded, a single Raft group is enough. There is no MultiRaft on the coord side.

### Storage nodes

Each `ferriskv-node` binary holds many shards. The current target sizes a shard around 128 MB, which means a few thousand shards on a node with terabytes of storage.

Three subsystems run inside each node:

- **MultiRaft scheduler.** One `RawNode` per shard from `raft-rs`. A scheduler ticks all groups on a fixed cadence, collects their outgoing messages, and batches them by destination so that two nodes share a single connection no matter how many shards they have in common. The transport is a bidirectional streaming gRPC service.
- **Local storage.** Several fjall partitions: one for the user data (MVCC-encoded), one for in-progress locks, one for committed write records, and one for the Raft log. Splitting them keeps compaction work isolated.
- **Service layer.** The gRPC service that clients talk to. It enforces resource limits, routes reads to the right shard, and forwards writes through the transactional layer.

### Transactions

The transactional model is Percolator on top of the per-shard Raft groups.

- A transaction starts by asking the timestamp oracle for a `start_ts`.
- Reads return the latest version with `commit_ts <= start_ts`.
- Writes are buffered locally; on commit, the client picks a primary key, sends prewrites to every involved shard, then asks the oracle for a `commit_ts` and sends commit records.
- A lock cleanup worker scans for orphaned locks (clients that crashed mid-commit) and resolves them by reading the primary key's status.

This model gives serializable snapshot isolation and survives shard splits, because locks point at the primary key rather than at a shard identity.

### Range routing

Clients keep a local cache of the placement table. Each request is routed to the shard that owns its key. When the placement changes (split, rebalance, leader transfer), the server replies with a `NotOwner` status; the client refreshes its cache and retries once. Stale caches do not produce wrong results; they produce one extra round-trip.

## Keyspace ordering and locality

Sharding is **range-based**, not hash-based. The reason is locality. With hash sharding a tenant's keys end up scattered across every shard in the cluster, so any range scan inside the tenant becomes a fan-out. With range sharding, contiguous chunks of the keyspace live on the same machines; a prefix scan reads from a small set of shards, usually one.

The tenant prefix is the first thing in every key, which means a tenant occupies a contiguous range of the keyspace. The split algorithm picks split points by sampling keys, which keeps tenants on the smallest possible number of shards.

## Failure handling

- **A storage node fails.** Its shards lose one replica each. The coord detects this through heartbeats and triggers rebalancing.
- **A shard's leader fails.** The Raft group elects a new leader; routing clients get `NotOwner` until they refresh.
- **The coord leader fails.** The coord Raft group elects a new leader. Timestamp allocation stalls briefly; clients see retries.
- **The disk dies.** Replication on other nodes covers it. Recovery streams a snapshot to a fresh disk.
- **A client crashes mid-commit.** The lock cleanup worker resolves the orphaned locks by reading the primary key.

## What is not yet built

Everything below the local storage layer works today. Everything above is on the roadmap: see the [P1 milestone](https://github.com/ferrislabs/ferriskv/milestones) for the Raft and sharding work, the [P2 milestone](https://github.com/ferrislabs/ferriskv/milestones) for transactions, and the [P3 milestone](https://github.com/ferrislabs/ferriskv/milestones) for the higher-level database features.
