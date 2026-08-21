//! Per-tenant operation rate limiting.
//!
//! # Why a map of direct limiters rather than governor's keyed one
//!
//! `governor` ships a keyed rate limiter, which is the obvious fit. Its
//! `check_key` takes `&K`, so with an owned key type — `String`, `Arc<str>` —
//! every request has to allocate a key just to look one up. That is an
//! allocation per RPC on the hottest path in the node, in exchange for code we
//! would otherwise write once.
//!
//! A `DashMap<Arc<str>, _>` can be probed with a bare `&str`, because
//! `Arc<str>: Borrow<str>`. So the map is ours and the limiters are governor's.
//!
//! # Throttling is admission control, so it happens before the work
//!
//! A limiter that rejected requests after they had already read from storage
//! would protect nobody. This is checked at the edge, which also means reads are
//! throttled alongside writes: a tenant can saturate a node with `scan` just as
//! effectively as with `put`.

use std::num::NonZeroU32;
use std::sync::Arc;

use dashmap::DashMap;
use ferriskv_core::{Error, Result};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota as GovernorQuota, RateLimiter};

type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Rate limiters, one per tenant, created on first use.
pub struct Throttle {
    /// Applied to tenants without a limit of their own. `0` means unthrottled.
    default_ops_per_sec: u32,
    limiters: DashMap<Arc<str>, Arc<Entry>>,
}

/// A limiter plus the rate it was built for.
///
/// The rate is kept so a quota change can be noticed: a limiter's capacity is
/// fixed at construction, so raising a tenant's limit means replacing it rather
/// than reconfiguring it.
struct Entry {
    ops_per_sec: u32,
    limiter: Limiter,
}

impl Throttle {
    pub fn new(default_ops_per_sec: u32) -> Self {
        Self {
            default_ops_per_sec,
            limiters: DashMap::new(),
        }
    }

    /// Charges `cost` operations to `tenant`.
    ///
    /// `cost` is the number of operations the request represents, so a batch of
    /// 50 puts costs 50. Charging one per RPC would let a client bypass the
    /// limit entirely by batching, which is the one thing a rate limit on a
    /// batching API must not allow.
    pub fn check(&self, tenant: &str, ops_per_sec: u32, cost: u32) -> Result<()> {
        let limit = if ops_per_sec > 0 {
            ops_per_sec
        } else {
            self.default_ops_per_sec
        };
        let Some(rate) = NonZeroU32::new(limit) else {
            return Ok(());
        };
        let Some(cost) = NonZeroU32::new(cost) else {
            return Ok(());
        };

        // `check_n` nests its results, and the two failures mean different
        // things to the caller. The inner error is "not yet" — waiting helps.
        // The outer one is "never": the request costs more than the whole
        // per-second allowance, so no amount of waiting admits it, and calling
        // that a rate limit would send the client into a retry loop that cannot
        // succeed.
        match self.entry(tenant, rate).limiter.check_n(cost) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_not_yet)) => {
                metrics::counter!(
                    "ferriskv_throttled_total",
                    "tenant" => tenant.to_string(),
                )
                .increment(1);
                Err(Error::RateLimited {
                    tenant: Arc::<str>::from(tenant),
                    limit,
                })
            }
            Err(_never) => Err(Error::Config(format!(
                "request costs {cost} operations, above the {limit} per second allowed for {tenant}"
            ))),
        }
    }

    /// The limiter for `tenant` at `rate`, rebuilt if the rate has changed.
    fn entry(&self, tenant: &str, rate: NonZeroU32) -> Arc<Entry> {
        if let Some(existing) = self.limiters.get(tenant) {
            if existing.ops_per_sec == rate.get() {
                return Arc::clone(existing.value());
            }
        }
        let fresh = Arc::new(Entry {
            ops_per_sec: rate.get(),
            limiter: RateLimiter::direct(GovernorQuota::per_second(rate)),
        });
        self.limiters
            .insert(Arc::<str>::from(tenant), Arc::clone(&fresh));
        fresh
    }

    /// Tenants with a live limiter. For metrics and tests.
    pub fn tracked_tenants(&self) -> usize {
        self.limiters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_limit_anywhere_means_no_throttling() {
        let t = Throttle::new(0);
        for _ in 0..10_000 {
            assert!(t.check("alice", 0, 1).is_ok());
        }
        assert_eq!(
            t.tracked_tenants(),
            0,
            "an unthrottled tenant must not cost a limiter",
        );
    }

    #[test]
    fn a_tenant_is_refused_once_its_allowance_is_spent() {
        let t = Throttle::new(0);
        for _ in 0..5 {
            assert!(t.check("alice", 5, 1).is_ok());
        }
        assert!(matches!(
            t.check("alice", 5, 1),
            Err(Error::RateLimited { limit: 5, .. })
        ));
    }

    #[test]
    fn one_tenant_cannot_spend_anothers_allowance() {
        let t = Throttle::new(2);
        assert!(t.check("noisy", 0, 1).is_ok());
        assert!(t.check("noisy", 0, 1).is_ok());
        assert!(t.check("noisy", 0, 1).is_err());

        assert!(
            t.check("quiet", 0, 1).is_ok(),
            "a quiet tenant must not pay for a noisy one",
        );
    }

    #[test]
    fn a_batch_costs_what_it_contains() {
        // Charging one per RPC would let a client bypass the limit entirely by
        // batching, which is the one loophole a rate limit here must not have.
        let t = Throttle::new(0);
        assert!(t.check("alice", 10, 10).is_ok());
        assert!(t.check("alice", 10, 1).is_err());
    }

    #[test]
    fn a_request_larger_than_the_whole_allowance_is_a_configuration_error() {
        // No amount of waiting admits it, so reporting it as a rate limit would
        // send the client into a retry loop that can never succeed.
        let t = Throttle::new(0);
        let err = t.check("alice", 5, 50).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn a_tenant_specific_limit_overrides_the_default() {
        let t = Throttle::new(1);
        for _ in 0..20 {
            assert!(t.check("alice", 20, 1).is_ok());
        }
    }

    #[test]
    fn raising_a_limit_replaces_the_limiter_rather_than_keeping_the_old_rate() {
        let t = Throttle::new(0);
        assert!(t.check("alice", 1, 1).is_ok());
        assert!(t.check("alice", 1, 1).is_err());

        // An operator raises the quota. The tenant must feel it immediately, not
        // after some cache expiry nobody documented.
        assert!(t.check("alice", 100, 1).is_ok());
        assert_eq!(t.tracked_tenants(), 1);
    }

    #[test]
    fn a_zero_cost_request_is_never_refused() {
        let t = Throttle::new(1);
        assert!(t.check("alice", 0, 1).is_ok());
        for _ in 0..100 {
            assert!(t.check("alice", 0, 0).is_ok());
        }
    }
}
