//! Fetching the IAM's key set and keeping it current.
//!
//! `ferriskv-auth` owns what a key set *means*; this module owns how it reaches
//! the node — the HTTP call, the schedule, and what happens when the IAM is
//! unreachable. The split is what lets every parsing rule be tested without a
//! server and every failure policy be tested without a real IAM.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ferriskv_auth::{KeyRing, SharedKeyRing};
use futures::StreamExt;
use reqwest::Client;
use tokio::sync::Notify;
use tokio::time::{interval_at, Instant, MissedTickBehavior};
use tracing::{debug, info, warn};

/// How long a single fetch may take before it is abandoned.
///
/// An IAM that hangs must not hold the refresher: the cached keys keep working,
/// so waiting forever buys nothing and blocks the next scheduled attempt.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest key set accepted, as a guard against a compromised or confused
/// endpoint streaming until the node runs out of memory.
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Shortest gap between two fetches triggered by an unknown `kid`.
///
/// The `kid` comes from the token, so any caller can pick one the ring does not
/// hold. Without a floor here, a stream of invented kids turns this node into a
/// load generator aimed at the IAM — an unauthenticated caller must not be able
/// to schedule the node's outbound traffic.
const MIN_STALE_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// The IAM endpoint the key set is read from.
pub struct JwksSource {
    client: Client,
    url: String,
}

impl JwksSource {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        let client = Client::builder()
            .timeout(FETCH_TIMEOUT)
            .build()
            .context("building the JWKS HTTP client")?;
        Ok(Self { client, url })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Reads the endpoint and turns it into a usable key ring.
    ///
    /// Every failure is one value: a ring is either wholly replaceable or the
    /// caller keeps what it has. A partially applied key set would leave the
    /// node authenticating against a mix of two IAM states.
    pub async fn fetch(&self) -> Result<KeyRing> {
        let response = self
            .client
            .get(&self.url)
            .send()
            .await
            .with_context(|| format!("fetching JWKS from {}", self.url))?;

        let status = response.status();
        if !status.is_success() {
            bail!("JWKS endpoint {} answered {}", self.url, status);
        }

        // Read chunk by chunk and stop at the cap. Buffering the whole body
        // first and measuring it afterwards would let an endpoint serving an
        // endless response exhaust memory before the check ever runs.
        let mut body = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk.with_context(|| format!("reading JWKS body from {}", self.url))?;
            if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
                bail!(
                    "JWKS document from {} exceeds the {MAX_DOCUMENT_BYTES} byte limit",
                    self.url
                );
            }
            body.extend_from_slice(&chunk);
        }

        let ring =
            KeyRing::from_json(&body).with_context(|| format!("parsing JWKS from {}", self.url))?;

        for skipped in ring.skipped() {
            warn!(
                url = %self.url,
                kid = skipped.kid.as_deref().unwrap_or("<none>"),
                reason = skipped.reason,
                "ignoring a key published in the JWKS",
            );
        }

        Ok(ring)
    }
}

/// Fetches the key set once, before the node starts serving.
///
/// Failing here is deliberate. A node that booted without keys would answer
/// every request with "unauthenticated", which reads as a client problem and
/// sends whoever is on call looking in the wrong place. Refusing to start says
/// what is actually wrong, once.
pub async fn load_at_startup(source: &JwksSource) -> Result<Arc<SharedKeyRing>> {
    let ring = source.fetch().await.with_context(|| {
        format!(
            "JWKS endpoint {} is unreachable; the node will not start without verification keys",
            source.url()
        )
    })?;
    info!(url = %source.url(), keys = ring.len(), "JWKS loaded");
    Ok(Arc::new(SharedKeyRing::new(ring)))
}

/// Wires "a token named a kid we do not have" to "go ask the IAM again".
pub fn notify_on_stale(keys: &SharedKeyRing) -> Arc<Notify> {
    let stale = Arc::new(Notify::new());
    let handle = Arc::clone(&stale);
    keys.set_stale_hook(move || handle.notify_one());
    stale
}

/// When the refresher goes back to the IAM.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPolicy {
    /// Longest the ring may go without being re-read.
    pub interval: Duration,
    /// Shortest gap between two fetches an unknown `kid` may trigger.
    pub min_stale_gap: Duration,
}

impl RefreshPolicy {
    pub fn every(interval: Duration) -> Self {
        Self {
            interval,
            min_stale_gap: MIN_STALE_REFRESH_INTERVAL,
        }
    }
}

/// Keeps the ring current until shutdown.
///
/// Wakes on the interval, or early when a token named a key the ring does not
/// hold — a rotation is visible to callers before it is visible to the clock.
///
/// A failed refresh is logged and dropped: the keys already in the ring stay in
/// force. Rotation is rare and the IAM being down is not, so widening or
/// narrowing access on a network error would make an IAM outage into a FerrisKV
/// outage.
pub async fn run_refresher(
    source: JwksSource,
    keys: Arc<SharedKeyRing>,
    stale: Arc<Notify>,
    policy: RefreshPolicy,
    shutdown: impl Future<Output = ()> + Send,
) {
    let mut ticker = interval_at(Instant::now() + policy.interval, policy.interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The startup fetch counts: a miss arriving seconds after boot is asking
    // about a ring that was just read.
    let mut last_fetch = Instant::now();
    tokio::pin!(shutdown);

    loop {
        let woken_by_miss = tokio::select! {
            _ = &mut shutdown => {
                debug!("JWKS refresher stopping");
                return;
            }
            _ = ticker.tick() => false,
            _ = stale.notified() => true,
        };

        if woken_by_miss {
            let since = Instant::now().saturating_duration_since(last_fetch);
            if let Some(wait) = policy.min_stale_gap.checked_sub(since) {
                // Delay rather than drop. The signal says the ring is behind;
                // discarding it would leave it behind until the next full
                // interval, which is an hour by default. Waiting out the floor
                // also coalesces a burst into the single fetch it deserves.
                debug!(?wait, "holding a JWKS refresh requested by an unknown kid");
                tokio::select! {
                    _ = &mut shutdown => {
                        debug!("JWKS refresher stopping");
                        return;
                    }
                    _ = tokio::time::sleep(wait) => {}
                }
            }
        }

        last_fetch = Instant::now();
        match source.fetch().await {
            Ok(ring) => {
                let count = ring.len();
                keys.replace(ring);
                debug!(url = %source.url(), keys = count, "JWKS refreshed");
            }
            Err(e) => warn!(
                url = %source.url(),
                error = %e,
                "JWKS refresh failed, continuing with the keys already loaded",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use tokio::sync::oneshot;

    use super::*;

    const E: &str = "AQAB";
    const N_A: &str = "pURFKodLI8fzKTrP8X11yT6HfqbCfkcAbpy7hDdeQd4jau5L6Fi1punF66nScZIwCYVdpSqTd_DDlBQH2sWtg7wRZb_gkcPwRAkOH16zSaEooZVYX_bRY1oV0167w6AOjkze7DeFsmMf-Akh0vRQLRzWRNdM48qRPZmXrS9v7cy-KkwCGibv6PI-Vw94izDTbwrqqYfdCrqR6GRVC0pZHOjpMMvAWukCstjYdCJTaChqbzgk1uCKOA_cwNWj9mtpyG2cTkpBsB68U2NwMsJOjFpGCO6ZI5tc283AnNEbyiSGk3jeST2uOl4g3TJWp6QC_9r2A0iRjK6SBRkPgVevnw";
    const N_B: &str = "6bE_ESlcjP-bscRbq8HU9vrg3_dIgT3YrxwHf0cDaHQ6Wk1qD6douWx3hHg-GvXeO3JteTiNzUSItaR1RIqHfuaDh-pTWlk_TOs_pzbJa4bckXhuMiEAneL44MKZPfKOzWXLvDkY1BAdg8VDyO7CbyXkQIfLwzHfkSuRVj8E2DVn3pl3JdFe7sb7BRRqjmJDZ9Nz-HA9mBFzmG2D_U_zEu4J5UgM3ek64vDjuOgoDLRidFQX2JO-4EPKaVWjYm7AlbOVbwzuyhWrjvopsemI8naMmYDdathEmLjE1-EROE9b45u002MKo_0U2F4JDBZlIoA5vR2LvYrBJFFWayiOBQ";

    fn document(kid: &str, n: &str) -> String {
        format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","alg":"RS256","kid":"{kid}","n":"{n}","e":"{E}"}}]}}"#
        )
    }

    /// What the fake IAM answers, and how many times it has been asked.
    #[derive(Clone)]
    struct Idp {
        body: Arc<parking_lot::RwLock<String>>,
        status: Arc<parking_lot::RwLock<StatusCode>>,
        hits: Arc<AtomicUsize>,
    }

    struct Harness {
        url: String,
        idp: Idp,
        _stop: oneshot::Sender<()>,
    }

    /// Serves a JWKS over loopback, so the fetch path under test is a real HTTP
    /// round trip rather than a stub standing in for one.
    async fn serve(body: String) -> Harness {
        let idp = Idp {
            body: Arc::new(parking_lot::RwLock::new(body)),
            status: Arc::new(parking_lot::RwLock::new(StatusCode::OK)),
            hits: Arc::new(AtomicUsize::new(0)),
        };

        async fn handler(State(idp): State<Idp>) -> (StatusCode, String) {
            idp.hits.fetch_add(1, Ordering::SeqCst);
            (*idp.status.read(), idp.body.read().clone())
        }

        let app = Router::new()
            .route("/jwks.json", get(handler))
            .with_state(idp.clone());

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let bound = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();

        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await;
        });

        Harness {
            url: format!("http://{bound}/jwks.json"),
            idp,
            _stop: stop,
        }
    }

    #[tokio::test]
    async fn fetches_and_parses_a_live_document() {
        let idp = serve(document("k1", N_A)).await;
        let source = JwksSource::new(&idp.url).unwrap();
        let ring = source.fetch().await.unwrap();
        assert!(ring.contains("k1"));
        assert_eq!(idp.idp.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejects_a_non_success_status() {
        let idp = serve(document("k1", N_A)).await;
        *idp.idp.status.write() = StatusCode::INTERNAL_SERVER_ERROR;
        let source = JwksSource::new(&idp.url).unwrap();
        assert!(source.fetch().await.is_err());
    }

    #[tokio::test]
    async fn rejects_a_body_that_is_not_a_key_set() {
        let idp = serve("<html>login page</html>".to_owned()).await;
        let source = JwksSource::new(&idp.url).unwrap();
        assert!(source.fetch().await.is_err());
    }

    #[tokio::test]
    async fn refuses_a_document_past_the_size_cap() {
        // The body is read in chunks and abandoned at the cap, so an endpoint
        // that never stops sending cannot be answered with unbounded memory.
        let mut oversized = String::with_capacity(2 * 1024 * 1024);
        oversized.push_str(r#"{"keys":["#);
        while oversized.len() < 2 * 1024 * 1024 {
            oversized.push_str(&document("pad", N_A));
            oversized.push(',');
        }
        oversized.push_str("]}");

        let idp = serve(oversized).await;
        let source = JwksSource::new(&idp.url).unwrap();
        // `KeyRing` has no Debug on purpose — nothing holding key material
        // should be printable — so match rather than unwrap_err.
        let err = match source.fetch().await {
            Ok(_) => panic!("the size cap did not fire"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("byte limit"),
            "expected the size cap to fire, got: {err}",
        );
    }

    #[tokio::test]
    async fn refuses_to_boot_when_the_endpoint_is_unreachable() {
        // Port 1 on loopback: nothing listens, and the connection is refused
        // rather than left hanging.
        let source = JwksSource::new("http://127.0.0.1:1/jwks.json").unwrap();
        assert!(load_at_startup(&source).await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_kid_pulls_the_rotation_forward() {
        let idp = serve(document("old", N_A)).await;
        let source = JwksSource::new(&idp.url).unwrap();
        let keys = load_at_startup(&source).await.unwrap();
        let stale = notify_on_stale(&keys);

        // A long interval, so anything that happens next came from the miss and
        // not from the clock, and a floor short enough not to swallow it.
        let (stop, stopped) = oneshot::channel::<()>();
        let refresher = tokio::spawn(run_refresher(
            source,
            Arc::clone(&keys),
            Arc::clone(&stale),
            RefreshPolicy {
                interval: Duration::from_secs(3600),
                min_stale_gap: Duration::from_millis(10),
            },
            async {
                let _ = stopped.await;
            },
        ));

        *idp.idp.body.write() = document("new", N_B);
        stale.notify_one();

        let rotated = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if keys.load().contains("new") {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;

        assert!(rotated.is_ok(), "the ring never picked up the new kid");
        assert!(!keys.load().contains("old"));

        let _ = stop.send(());
        let _ = refresher.await;
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_keys_already_loaded() {
        let idp = serve(document("k1", N_A)).await;
        let source = JwksSource::new(&idp.url).unwrap();
        let keys = load_at_startup(&source).await.unwrap();
        let stale = notify_on_stale(&keys);

        // The IAM goes down after the node booted.
        *idp.idp.status.write() = StatusCode::SERVICE_UNAVAILABLE;

        let (stop, stopped) = oneshot::channel::<()>();
        let refresher = tokio::spawn(run_refresher(
            source,
            Arc::clone(&keys),
            Arc::clone(&stale),
            RefreshPolicy::every(Duration::from_millis(50)),
            async {
                let _ = stopped.await;
            },
        ));

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            keys.load().contains("k1"),
            "an IAM outage must not empty the ring",
        );
        assert!(idp.idp.hits.load(Ordering::SeqCst) > 1, "no retry happened");

        let _ = stop.send(());
        let _ = refresher.await;
    }

    #[tokio::test]
    async fn a_burst_of_unknown_kids_collapses_into_a_couple_of_fetches() {
        // The kid comes from the token, so a caller can invent one at will. The
        // floor is what stops that from becoming outbound load on the IAM.
        let idp = serve(document("k1", N_A)).await;
        let source = JwksSource::new(&idp.url).unwrap();
        let keys = load_at_startup(&source).await.unwrap();
        let stale = notify_on_stale(&keys);
        let after_boot = idp.idp.hits.load(Ordering::SeqCst);

        let (stop, stopped) = oneshot::channel::<()>();
        let refresher = tokio::spawn(run_refresher(
            source,
            Arc::clone(&keys),
            Arc::clone(&stale),
            RefreshPolicy {
                interval: Duration::from_secs(3600),
                min_stale_gap: Duration::from_millis(100),
            },
            async {
                let _ = stopped.await;
            },
        ));

        for _ in 0..50 {
            stale.notify_one();
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;

        let triggered = idp.idp.hits.load(Ordering::SeqCst) - after_boot;
        assert!(
            triggered <= 6,
            "50 unknown kids over 100ms caused {triggered} fetches; \
             expected the floor to coalesce them into a handful",
        );

        let _ = stop.send(());
        let _ = refresher.await;
    }

    #[tokio::test]
    async fn the_default_floor_holds_off_an_immediate_miss() {
        let idp = serve(document("k1", N_A)).await;
        let source = JwksSource::new(&idp.url).unwrap();
        let keys = load_at_startup(&source).await.unwrap();
        let stale = notify_on_stale(&keys);
        let after_boot = idp.idp.hits.load(Ordering::SeqCst);

        let (stop, stopped) = oneshot::channel::<()>();
        let refresher = tokio::spawn(run_refresher(
            source,
            Arc::clone(&keys),
            Arc::clone(&stale),
            RefreshPolicy::every(Duration::from_secs(3600)),
            async {
                let _ = stopped.await;
            },
        ));

        stale.notify_one();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            idp.idp.hits.load(Ordering::SeqCst),
            after_boot,
            "a miss moments after the startup fetch should wait out the floor",
        );

        let _ = stop.send(());
        let _ = refresher.await;
    }
}
