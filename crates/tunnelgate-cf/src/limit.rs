//! Client-side request budget, so the operator stays under Cloudflare's global limit
//! (1200 requests per 5 minutes per token) instead of discovering it through 429s.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

/// A token bucket: `burst` requests at once, then `per_second` on average.
///
/// With the default (burst 100, 3/s) at most 100 + 300 × 3 = 1000 requests fit in any 5-minute
/// window, which leaves room for cloudflared and people using the same token.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimit {
    pub per_second: f64,
    pub burst: u32,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self { per_second: 3.0, burst: 100 }
    }
}

/// Shared by all clones of a client. A 429 pauses every request, not only the one that got it.
#[derive(Debug, Clone)]
pub(crate) struct Limiter {
    limit: RateLimit,
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    /// May go negative: callers reserve a token and sleep until it would have been there.
    tokens: f64,
    updated: Instant,
    paused_until: Option<Instant>,
}

impl Limiter {
    pub(crate) fn new(limit: RateLimit) -> Self {
        let state = State { tokens: f64::from(limit.burst), updated: Instant::now(), paused_until: None };
        Self { limit, state: Arc::new(Mutex::new(state)) }
    }

    /// Waits until a request may be sent, and takes one token.
    pub(crate) async fn acquire(&self) {
        let wait = self.reserve(Instant::now());
        if !wait.is_zero() {
            tracing::debug!(?wait, "waiting for the cloudflare request budget");
            tokio::time::sleep(wait).await;
        }
    }

    /// Holds back all requests for `wait` (from a 429's Retry-After or the backoff).
    pub(crate) fn pause(&self, wait: Duration) {
        let until = Instant::now() + wait;
        let mut s = self.state.lock().expect("limiter lock");
        if s.paused_until.is_none_or(|p| p < until) {
            s.paused_until = Some(until);
        }
    }

    fn reserve(&self, now: Instant) -> Duration {
        let mut s = self.state.lock().expect("limiter lock");
        let elapsed = now.saturating_duration_since(s.updated).as_secs_f64();
        s.tokens = (s.tokens + elapsed * self.limit.per_second).min(f64::from(self.limit.burst));
        s.updated = now;
        s.tokens -= 1.0;
        let budget =
            if s.tokens < 0.0 { Duration::from_secs_f64(-s.tokens / self.limit.per_second) } else { Duration::ZERO };
        let paused = s.paused_until.map(|p| p.saturating_duration_since(now)).unwrap_or_default();
        budget.max(paused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn bursts_then_spaces_requests() {
        let l = Limiter::new(RateLimit { per_second: 2.0, burst: 3 });
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(l.reserve(now), Duration::ZERO);
        }
        assert_eq!(l.reserve(now), Duration::from_millis(500));
        assert_eq!(l.reserve(now), Duration::from_millis(1000));
        // Two seconds later four tokens have come back, two of them already promised.
        assert_eq!(l.reserve(now + Duration::from_secs(2)), Duration::ZERO);
        assert_eq!(l.reserve(now + Duration::from_secs(2)), Duration::ZERO);
        assert_eq!(l.reserve(now + Duration::from_secs(2)), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn refills_up_to_the_burst_only() {
        let l = Limiter::new(RateLimit { per_second: 1.0, burst: 2 });
        let later = Instant::now() + Duration::from_secs(3600);
        assert_eq!(l.reserve(later), Duration::ZERO);
        assert_eq!(l.reserve(later), Duration::ZERO);
        assert_eq!(l.reserve(later), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_pause_holds_back_everyone() {
        let l = Limiter::new(RateLimit::default());
        l.pause(Duration::from_secs(5));
        l.pause(Duration::from_secs(1)); // a shorter pause doesn't cut the longer one
        let now = Instant::now();
        assert_eq!(l.reserve(now), Duration::from_secs(5));
        assert_eq!(l.reserve(now + Duration::from_secs(5)), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_sleeps_for_the_budget() {
        let l = Limiter::new(RateLimit { per_second: 10.0, burst: 1 });
        let start = Instant::now();
        l.acquire().await;
        l.acquire().await;
        l.acquire().await;
        assert_eq!(start.elapsed(), Duration::from_millis(200));
    }
}
