use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub enum Clock {
    System,
    Manual(Arc<AtomicU64>),
}

impl Clock {
    pub fn system() -> Self {
        Self::System
    }

    pub fn manual(initial_ms: u64) -> Self {
        Self::Manual(Arc::new(AtomicU64::new(initial_ms)))
    }

    #[inline]
    pub fn now_ms(&self) -> u64 {
        match self {
            Self::System => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            Self::Manual(t) => t.load(Ordering::SeqCst),
        }
    }

    pub fn advance(&self, by_ms: u64) {
        if let Self::Manual(t) = self {
            t.fetch_add(by_ms, Ordering::SeqCst);
        }
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::system()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_positive() {
        let c = Clock::system();
        assert!(c.now_ms() > 0);
    }

    #[test]
    fn manual_clock_starts_at_initial() {
        let c = Clock::manual(1_000);
        assert_eq!(c.now_ms(), 1_000);
    }

    #[test]
    fn manual_clock_advances() {
        let c = Clock::manual(0);
        c.advance(500);
        assert_eq!(c.now_ms(), 500);
        c.advance(250);
        assert_eq!(c.now_ms(), 750);
    }

    #[test]
    fn cloned_manual_clock_shares_state() {
        let a = Clock::manual(100);
        let b = a.clone();
        a.advance(50);
        assert_eq!(b.now_ms(), 150);
    }
}
