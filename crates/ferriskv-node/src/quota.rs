//! Per-tenant storage quotas and the usage they are checked against.
//!
//! # Two things live here, with different owners
//!
//! A **quota** is a limit an operator sets. It changes rarely, is written
//! through the admin API, and lives in the tenant's `metadata` subspace next to
//! its other configuration.
//!
//! **Usage** is a fact about the data. It changes on every write, lives in the
//! tenant's `stats` subspace, and nobody sets it — it is derived.
//!
//! # Where the truth lives
//!
//! The authority on usage is the data itself. The in-memory counter is what
//! writes are checked against, because a quota check on the write path cannot
//! afford a scan; the value in `stats` is a materialised view of that counter,
//! kept current so an operator or a future billing job can read it without
//! asking the node.
//!
//! Startup rebuilds the counters by scanning, rather than trusting what `stats`
//! holds. That costs nothing — the TTL index needs the same scan — and it means
//! any drift, from a crash between the two writes or from a bug here, is
//! corrected on the next boot instead of compounding forever.
//!
//! # What a byte is
//!
//! Usage counts the caller's key plus the caller's value. Not the encoded key:
//! the tenant-name length prefix and the subspace byte are the node's framing,
//! and billing a tenant for the length of its own name would be indefensible.
//! Not the storage engine's on-disk footprint either — that moves with
//! compaction, and a quota that drifts under the tenant's feet is not a quota.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use ferriskv_core::{Error, KeyCodec, Result, Storage, StorageBackend, Subspace, ValueCodec};
use serde::{Deserialize, Serialize};

/// Key of the quota record inside a tenant's `metadata` subspace.
const QUOTA_KEY: &[u8] = b"quota";
/// Key of the usage record inside a tenant's `stats` subspace.
const USAGE_KEY: &[u8] = b"usage";

/// Limits applied to one tenant. `0` means unlimited, on both fields.
///
/// Unlimited is the default because a node that starts enforcing a limit nobody
/// configured would reject writes for reasons its operator never chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    #[serde(default)]
    pub max_bytes: u64,
    #[serde(default)]
    pub max_ops_per_sec: u32,
}

impl Quota {
    pub const UNLIMITED: Self = Self {
        max_bytes: 0,
        max_ops_per_sec: 0,
    };

    #[inline]
    pub fn is_unlimited(&self) -> bool {
        self.max_bytes == 0 && self.max_ops_per_sec == 0
    }
}

impl Default for Quota {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

/// A tenant's quota alongside what it is currently using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TenantUsage {
    pub used_bytes: u64,
    pub max_bytes: u64,
    pub max_ops_per_sec: u32,
}

/// Tracks usage per tenant and answers whether a write fits.
pub struct QuotaStore {
    /// Applied to any tenant without a record of its own.
    default_quota: Quota,
    /// Cached so the write path does not read storage for the limit as well as
    /// for the old value size. Invalidated by [`Self::set_quota`], which is the
    /// only way a quota changes.
    quotas: DashMap<Arc<str>, Quota>,
    usage: DashMap<Arc<str>, AtomicU64>,
}

impl QuotaStore {
    pub fn new(default_quota: Quota) -> Self {
        Self {
            default_quota,
            quotas: DashMap::new(),
            usage: DashMap::new(),
        }
    }

    /// The limits in force for `tenant`.
    pub fn quota(&self, tenant: &str) -> Quota {
        self.quotas
            .get(tenant)
            .map(|q| *q)
            .unwrap_or(self.default_quota)
    }

    pub fn used_bytes(&self, tenant: &str) -> u64 {
        self.usage
            .get(tenant)
            .map(|u| u.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn usage_of(&self, tenant: &str) -> TenantUsage {
        let quota = self.quota(tenant);
        TenantUsage {
            used_bytes: self.used_bytes(tenant),
            max_bytes: quota.max_bytes,
            max_ops_per_sec: quota.max_ops_per_sec,
        }
    }

    /// Every tenant this node has seen, with its usage and limits.
    ///
    /// Includes tenants at zero usage that have a quota set, since "configured
    /// but empty" is a state an operator needs to be able to see.
    pub fn list(&self) -> Vec<(Arc<str>, TenantUsage)> {
        let mut out: Vec<(Arc<str>, TenantUsage)> = self
            .usage
            .iter()
            .map(|e| (Arc::clone(e.key()), self.usage_of(e.key())))
            .collect();
        for entry in self.quotas.iter() {
            if !self.usage.contains_key(entry.key()) {
                out.push((Arc::clone(entry.key()), self.usage_of(entry.key())));
            }
        }
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Records `quota` for `tenant`, in memory and in storage.
    pub fn set_quota(&self, storage: &StorageBackend, tenant: &str, quota: Quota) -> Result<()> {
        let key = KeyCodec::encode(tenant, Subspace::Metadata, QUOTA_KEY)?;
        let body = serde_json::to_vec(&quota)
            .map_err(|e| Error::Config(format!("encoding quota for {tenant}: {e}")))?;
        storage.put(&key, ValueCodec::encode(&body, None))?;
        self.quotas.insert(Arc::<str>::from(tenant), quota);
        Ok(())
    }

    /// Removes `tenant`'s own quota, returning it to the node default.
    pub fn clear_quota(&self, storage: &StorageBackend, tenant: &str) -> Result<()> {
        let key = KeyCodec::encode(tenant, Subspace::Metadata, QUOTA_KEY)?;
        storage.delete(&key)?;
        self.quotas.remove(tenant);
        Ok(())
    }

    /// Rejects a write that would take `tenant` over its byte quota.
    ///
    /// `delta` is signed because an overwrite can shrink a value and a delete
    /// always does. Only growth can be refused: a write that frees bytes is
    /// allowed even for a tenant already over its limit, which is the only way
    /// such a tenant can get back under it.
    pub fn check_write(&self, tenant: &str, delta: i64) -> Result<()> {
        let limit = self.quota(tenant).max_bytes;
        if limit == 0 || delta <= 0 {
            return Ok(());
        }
        let used = self.used_bytes(tenant);
        let after = used.saturating_add(delta as u64);
        if after > limit {
            return Err(Error::QuotaExceeded {
                tenant: Arc::<str>::from(tenant),
                used: after,
                limit,
            });
        }
        Ok(())
    }

    /// Applies `delta` to `tenant`'s usage and writes the new total to storage.
    pub fn apply(&self, storage: &StorageBackend, tenant: &str, delta: i64) -> Result<()> {
        if delta == 0 {
            return Ok(());
        }
        let total = self.adjust(tenant, delta);
        let key = KeyCodec::encode(tenant, Subspace::Stats, USAGE_KEY)?;
        storage.put(&key, ValueCodec::encode(&total.to_be_bytes(), None))?;
        metrics::gauge!("ferriskv_tenant_bytes_used", "tenant" => tenant.to_string())
            .set(total as f64);
        Ok(())
    }

    /// Moves the in-memory counter, saturating at zero.
    ///
    /// Saturating rather than wrapping matters: a counter that has drifted low
    /// and then meets a large delete would otherwise wrap to near-`u64::MAX` and
    /// lock the tenant out of writing entirely until the next restart.
    fn adjust(&self, tenant: &str, delta: i64) -> u64 {
        if let Some(counter) = self.usage.get(tenant) {
            return apply_delta(counter.value(), delta);
        }
        let counter = self
            .usage
            .entry(Arc::<str>::from(tenant))
            .or_insert_with(|| AtomicU64::new(0));
        apply_delta(counter.value(), delta)
    }

    /// Replaces every counter with `totals`, discarding what was there.
    ///
    /// Called at startup with the result of a scan over the real data, which is
    /// what makes the counters self-healing rather than merely persistent.
    pub fn reset_usage(&self, totals: impl IntoIterator<Item = (Arc<str>, u64)>) {
        self.usage.clear();
        for (tenant, total) in totals {
            metrics::gauge!("ferriskv_tenant_bytes_used", "tenant" => tenant.to_string())
                .set(total as f64);
            self.usage.insert(tenant, AtomicU64::new(total));
        }
    }

    /// Loads every persisted quota from storage into the cache.
    pub fn load_quotas(&self, storage: &StorageBackend) -> Result<usize> {
        self.quotas.clear();
        let mut loaded = 0usize;
        for (key, raw) in storage.scan(b"")? {
            let Ok((tenant, subspace, payload)) = KeyCodec::decode(&key) else {
                continue;
            };
            if subspace != Subspace::Metadata || payload != QUOTA_KEY {
                continue;
            }
            let stored = ValueCodec::decode(raw)?;
            match serde_json::from_slice::<Quota>(&stored.value) {
                Ok(quota) => {
                    self.quotas.insert(Arc::<str>::from(tenant), quota);
                    loaded += 1;
                }
                // A quota nobody can parse must not stop the node from booting.
                // Falling back to the node default is the conservative choice:
                // it is what an unconfigured tenant already gets.
                Err(e) => tracing::warn!(
                    tenant = %tenant,
                    error = %e,
                    "ignoring an unreadable quota record, falling back to the default",
                ),
            }
        }
        Ok(loaded)
    }
}

#[inline]
fn apply_delta(counter: &AtomicU64, delta: i64) -> u64 {
    if delta >= 0 {
        counter.fetch_add(delta as u64, Ordering::Relaxed) + delta as u64
    } else {
        let magnitude = delta.unsigned_abs();
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(magnitude);
            match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Bytes a key/value pair counts for.
///
/// Both lengths, because a tenant storing a million empty values under long
/// keys is using the node just as much as one storing a million long values.
#[inline]
pub fn entry_bytes(key_len: usize, value_len: usize) -> u64 {
    key_len as u64 + value_len as u64
}

#[cfg(test)]
mod tests {
    use ferriskv_core::MemStorage;

    use super::*;

    fn storage() -> StorageBackend {
        StorageBackend::Memory(MemStorage::new())
    }

    #[test]
    fn an_unconfigured_tenant_is_unlimited() {
        let store = QuotaStore::new(Quota::UNLIMITED);
        assert!(store.quota("alice").is_unlimited());
        assert!(store.check_write("alice", i64::MAX).is_ok());
    }

    #[test]
    fn the_node_default_applies_to_tenants_without_a_record() {
        let store = QuotaStore::new(Quota {
            max_bytes: 100,
            max_ops_per_sec: 5,
        });
        assert_eq!(store.quota("alice").max_bytes, 100);
        assert!(store.check_write("alice", 101).is_err());
        assert!(store.check_write("alice", 100).is_ok());
    }

    #[test]
    fn a_tenant_quota_overrides_the_node_default() {
        let s = storage();
        let store = QuotaStore::new(Quota {
            max_bytes: 100,
            max_ops_per_sec: 0,
        });
        store
            .set_quota(
                &s,
                "alice",
                Quota {
                    max_bytes: 1_000,
                    max_ops_per_sec: 0,
                },
            )
            .unwrap();
        assert_eq!(store.quota("alice").max_bytes, 1_000);
        assert_eq!(store.quota("bob").max_bytes, 100, "bob keeps the default");
    }

    #[test]
    fn clearing_a_quota_returns_the_tenant_to_the_default() {
        let s = storage();
        let store = QuotaStore::new(Quota {
            max_bytes: 100,
            max_ops_per_sec: 0,
        });
        store
            .set_quota(
                &s,
                "alice",
                Quota {
                    max_bytes: 1,
                    max_ops_per_sec: 0,
                },
            )
            .unwrap();
        store.clear_quota(&s, "alice").unwrap();
        assert_eq!(store.quota("alice").max_bytes, 100);
    }

    #[test]
    fn a_write_is_refused_at_the_point_it_would_cross_the_limit() {
        let s = storage();
        let store = QuotaStore::new(Quota {
            max_bytes: 10,
            max_ops_per_sec: 0,
        });
        store.apply(&s, "alice", 8).unwrap();
        assert!(store.check_write("alice", 2).is_ok());
        let err = store.check_write("alice", 3).unwrap_err();
        assert!(matches!(
            err,
            Error::QuotaExceeded {
                used: 11,
                limit: 10,
                ..
            }
        ));
    }

    #[test]
    fn a_tenant_over_its_limit_can_still_free_bytes() {
        // Otherwise the only way out of an exceeded quota would be an operator
        // raising it, and a tenant could not fix its own problem.
        let s = storage();
        let store = QuotaStore::new(Quota {
            max_bytes: 10,
            max_ops_per_sec: 0,
        });
        store.apply(&s, "alice", 50).unwrap();
        assert!(store.check_write("alice", -20).is_ok());
        assert!(store.check_write("alice", 0).is_ok());
        assert!(store.check_write("alice", 1).is_err());
    }

    #[test]
    fn usage_never_wraps_below_zero() {
        // A counter that drifted low and then wrapped would read near u64::MAX
        // and lock the tenant out of writing until the next restart.
        let s = storage();
        let store = QuotaStore::new(Quota::UNLIMITED);
        store.apply(&s, "alice", 10).unwrap();
        store.apply(&s, "alice", -100).unwrap();
        assert_eq!(store.used_bytes("alice"), 0);
    }

    #[test]
    fn usage_is_persisted_and_isolated_per_tenant() {
        let s = storage();
        let store = QuotaStore::new(Quota::UNLIMITED);
        store.apply(&s, "alice", 42).unwrap();
        store.apply(&s, "bob", 7).unwrap();

        assert_eq!(store.used_bytes("alice"), 42);
        assert_eq!(store.used_bytes("bob"), 7);

        let key = KeyCodec::encode("alice", Subspace::Stats, USAGE_KEY).unwrap();
        let raw = s.get(&key).unwrap().expect("usage must reach storage");
        let stored = ValueCodec::decode(raw).unwrap();
        assert_eq!(u64::from_be_bytes(stored.value[..].try_into().unwrap()), 42);

        let bobs = KeyCodec::encode("bob", Subspace::Stats, USAGE_KEY).unwrap();
        assert_ne!(
            key, bobs,
            "each tenant's counter lives under its own prefix"
        );
    }

    #[test]
    fn quotas_survive_a_reload_from_storage() {
        let s = storage();
        let written = QuotaStore::new(Quota::UNLIMITED);
        written
            .set_quota(
                &s,
                "alice",
                Quota {
                    max_bytes: 999,
                    max_ops_per_sec: 3,
                },
            )
            .unwrap();
        written
            .set_quota(
                &s,
                "bob",
                Quota {
                    max_bytes: 1,
                    max_ops_per_sec: 0,
                },
            )
            .unwrap();

        let reloaded = QuotaStore::new(Quota::UNLIMITED);
        assert_eq!(reloaded.load_quotas(&s).unwrap(), 2);
        assert_eq!(reloaded.quota("alice").max_bytes, 999);
        assert_eq!(reloaded.quota("alice").max_ops_per_sec, 3);
        assert_eq!(reloaded.quota("bob").max_bytes, 1);
    }

    #[test]
    fn an_unreadable_quota_record_does_not_stop_the_node() {
        let s = storage();
        let key = KeyCodec::encode("alice", Subspace::Metadata, QUOTA_KEY).unwrap();
        s.put(&key, ValueCodec::encode(b"{not json", None)).unwrap();

        let store = QuotaStore::new(Quota {
            max_bytes: 50,
            max_ops_per_sec: 0,
        });
        assert_eq!(store.load_quotas(&s).unwrap(), 0);
        assert_eq!(
            store.quota("alice").max_bytes,
            50,
            "an unparseable record falls back to the node default",
        );
    }

    #[test]
    fn reset_usage_replaces_rather_than_adds() {
        let s = storage();
        let store = QuotaStore::new(Quota::UNLIMITED);
        store.apply(&s, "alice", 1_000).unwrap();
        store.reset_usage([(Arc::<str>::from("alice"), 7u64)]);
        assert_eq!(store.used_bytes("alice"), 7);
    }

    #[test]
    fn reset_usage_forgets_tenants_that_no_longer_exist() {
        let s = storage();
        let store = QuotaStore::new(Quota::UNLIMITED);
        store.apply(&s, "gone", 100).unwrap();
        store.reset_usage([(Arc::<str>::from("alice"), 5u64)]);
        assert_eq!(store.used_bytes("gone"), 0);
    }

    #[test]
    fn list_includes_a_configured_tenant_that_has_written_nothing() {
        let s = storage();
        let store = QuotaStore::new(Quota::UNLIMITED);
        store
            .set_quota(
                &s,
                "prepared",
                Quota {
                    max_bytes: 10,
                    max_ops_per_sec: 1,
                },
            )
            .unwrap();
        store.apply(&s, "active", 3).unwrap();

        let listed = store.list();
        let names: Vec<&str> = listed.iter().map(|(t, _)| t.as_ref()).collect();
        assert_eq!(
            names,
            vec!["active", "prepared"],
            "sorted, and both present"
        );
        assert_eq!(listed[1].1.used_bytes, 0);
        assert_eq!(listed[1].1.max_bytes, 10);
    }

    #[test]
    fn entry_bytes_counts_the_key_as_well_as_the_value() {
        assert_eq!(entry_bytes(0, 0), 0);
        assert_eq!(entry_bytes(4, 10), 14);
        assert_eq!(entry_bytes(4, 0), 4, "a long key with no value still costs");
    }
}
