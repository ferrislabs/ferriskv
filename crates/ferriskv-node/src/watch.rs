//! Change notification for `Watch` subscribers.
//!
//! # One channel per tenant
//!
//! The design note on the issue called for a channel per watched prefix. That
//! turns out to be the wrong key. A prefix is an arbitrary byte string chosen by
//! the client, so a registry keyed by prefix has to be walked on every write to
//! find the matching entries, and garbage-collected when the last subscriber of
//! each prefix leaves — a prefix tree maintained on the write path in exchange
//! for narrowing fan-out that is already narrow.
//!
//! Keying by tenant instead gives a bounded, meaningful key: a write wakes only
//! the watchers of its own tenant, which is the isolation boundary the rest of
//! the node already enforces. Prefix filtering then happens per subscriber,
//! where it costs a `starts_with` on an event that subscriber was going to be
//! woken for anyway.
//!
//! # Publishing never fails a write
//!
//! [`WatchHub::publish`] takes no `Result` on purpose. A watcher is an observer,
//! and a slow or absent observer must not be able to make a `put` fail or block.
//! A subscriber that cannot keep up is dropped by the broadcast channel and told
//! about it; the writer never learns.

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::broadcast;

/// What happened to a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Put,
    Delete,
}

/// One committed change to one key.
///
/// `key` is tenant-relative — the bytes the client wrote, with the tenant and
/// subspace framing stripped — so a subscriber's prefix filter compares against
/// the same key space the subscriber asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChange {
    pub kind: ChangeKind,
    pub key: Bytes,
    /// Empty for a delete.
    pub value: Bytes,
}

/// Routes committed changes to the streams watching them.
pub struct WatchHub {
    capacity: usize,
    /// Created on subscribe, never on publish: a node with no watchers pays one
    /// hash lookup per write and this map stays empty.
    channels: DashMap<Arc<str>, broadcast::Sender<KeyChange>>,
}

impl WatchHub {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            channels: DashMap::new(),
        }
    }

    /// Subscribes to every change in `tenant`.
    ///
    /// The receiver only sees changes published after this call. There is no
    /// history to replay from — see the note on `Watch` in the gRPC layer.
    pub fn subscribe(&self, tenant: &str) -> broadcast::Receiver<KeyChange> {
        if let Some(tx) = self.channels.get(tenant) {
            return tx.subscribe();
        }
        self.channels
            .entry(Arc::<str>::from(tenant))
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .subscribe()
    }

    /// Whether anyone is listening to `tenant`.
    ///
    /// Callers check this before building a [`KeyChange`], because assembling
    /// one copies the key and the value. On the overwhelmingly common path —
    /// nobody watching — that copy would be pure waste on every write.
    pub fn is_watched(&self, tenant: &str) -> bool {
        self.channels
            .get(tenant)
            .is_some_and(|tx| tx.receiver_count() > 0)
    }

    /// Delivers `change` to the watchers of `tenant`, if any.
    pub fn publish(&self, tenant: &str, change: KeyChange) {
        // A channel whose last subscriber left is collected here rather than on
        // unsubscribe: a dropped `Receiver` has no hook to run, and publish is
        // the next moment anyone looks at the entry.
        let abandoned = match self.channels.get(tenant) {
            None => return,
            Some(tx) => {
                if tx.receiver_count() == 0 {
                    true
                } else {
                    // Fails only when the last receiver went away between the
                    // count and the send. Nothing to do about it, and nothing
                    // the writer needs to hear.
                    let _ = tx.send(change);
                    false
                }
            }
        };
        if abandoned {
            self.channels.remove(tenant);
        }
    }

    /// Number of tenants with a live channel. For metrics and tests.
    pub fn watched_tenants(&self) -> usize {
        self.channels.len()
    }

    /// Number of streams currently watching `tenant`.
    pub fn subscriber_count(&self, tenant: &str) -> usize {
        self.channels
            .get(tenant)
            .map(|tx| tx.receiver_count())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(key: &'static str, value: &'static str) -> KeyChange {
        KeyChange {
            kind: ChangeKind::Put,
            key: Bytes::from_static(key.as_bytes()),
            value: Bytes::from_static(value.as_bytes()),
        }
    }

    #[tokio::test]
    async fn a_subscriber_receives_changes_for_its_tenant() {
        let hub = WatchHub::new(16);
        let mut rx = hub.subscribe("alice");
        hub.publish("alice", put("k", "v"));

        let got = rx.recv().await.unwrap();
        assert_eq!(got, put("k", "v"));
    }

    #[tokio::test]
    async fn a_change_never_crosses_a_tenant_boundary() {
        let hub = WatchHub::new(16);
        let mut alice = hub.subscribe("alice");
        let mut bob = hub.subscribe("bob");

        hub.publish("alice", put("shared", "alice-value"));

        assert_eq!(alice.recv().await.unwrap().value, "alice-value");
        assert!(
            bob.try_recv().is_err(),
            "bob must not see a write to alice, whatever prefix he asked for",
        );
    }

    #[tokio::test]
    async fn every_subscriber_of_a_tenant_sees_every_change() {
        let hub = WatchHub::new(16);
        let mut first = hub.subscribe("alice");
        let mut second = hub.subscribe("alice");
        assert_eq!(hub.subscriber_count("alice"), 2);

        hub.publish("alice", put("k", "v"));

        assert_eq!(first.recv().await.unwrap().key, "k");
        assert_eq!(second.recv().await.unwrap().key, "k");
    }

    #[test]
    fn publishing_with_no_watchers_is_a_no_op() {
        let hub = WatchHub::new(16);
        hub.publish("nobody-here", put("k", "v"));
        assert!(!hub.is_watched("nobody-here"));
        assert_eq!(
            hub.watched_tenants(),
            0,
            "a write must not be able to grow this map",
        );
    }

    #[test]
    fn a_channel_is_collected_once_its_last_subscriber_leaves() {
        let hub = WatchHub::new(16);
        let rx = hub.subscribe("alice");
        assert_eq!(hub.watched_tenants(), 1);
        assert!(hub.is_watched("alice"));

        drop(rx);
        assert!(!hub.is_watched("alice"));

        hub.publish("alice", put("k", "v"));
        assert_eq!(hub.watched_tenants(), 0);
    }

    #[tokio::test]
    async fn a_subscriber_that_falls_behind_is_told_rather_than_lied_to() {
        // Silently skipping is the dangerous failure here: the subscriber would
        // believe it had seen every change and act on a keyspace it never read.
        let hub = WatchHub::new(2);
        let mut rx = hub.subscribe("alice");
        for i in 0..8 {
            hub.publish(
                "alice",
                KeyChange {
                    kind: ChangeKind::Put,
                    key: Bytes::from(format!("k{i}")),
                    value: Bytes::new(),
                },
            );
        }
        assert!(matches!(
            rx.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
    }

    #[tokio::test]
    async fn a_late_subscriber_sees_only_what_follows_it() {
        let hub = WatchHub::new(16);
        hub.publish("alice", put("before", "v"));
        let mut rx = hub.subscribe("alice");
        hub.publish("alice", put("after", "v"));

        assert_eq!(rx.recv().await.unwrap().key, "after");
    }

    #[tokio::test]
    async fn resubscribing_after_the_channel_was_collected_still_works() {
        let hub = WatchHub::new(16);
        drop(hub.subscribe("alice"));
        hub.publish("alice", put("collected", "v"));
        assert_eq!(hub.watched_tenants(), 0);

        let mut rx = hub.subscribe("alice");
        hub.publish("alice", put("fresh", "v"));
        assert_eq!(rx.recv().await.unwrap().key, "fresh");
    }
}
