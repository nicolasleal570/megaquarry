//! Global transfer speed limiting.
//!
//! A token bucket with a one-second burst: callers take what they need and sleep off any debt.

use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

/// A shared bytes-per-second limiter.
#[derive(Debug)]
pub struct RateLimiter {
    bytes_per_second: u64,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Available bytes; negative while callers owe time.
    available: f64,
    last: Instant,
}

impl RateLimiter {
    /// A limiter allowing `bytes_per_second` on average (minimum 1).
    ///
    /// The setting uses 0 for "unlimited"; callers map that to no
    /// limiter at all rather than to `RateLimiter::new(0)`.
    pub fn new(bytes_per_second: u64) -> Self {
        let rate = bytes_per_second.max(1);
        Self {
            bytes_per_second: rate,
            state: Mutex::new(State {
                available: rate as f64,
                last: Instant::now(),
            }),
        }
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }

    /// Waits until `bytes` may be transferred.
    pub async fn acquire(&self, bytes: u64) {
        let rate = self.bytes_per_second as f64;
        let wait = {
            let mut state = self.state.lock().await;
            let now = Instant::now();
            let refill = now.duration_since(state.last).as_secs_f64() * rate;
            state.available = (state.available + refill).min(rate);
            state.last = now;
            state.available -= bytes as f64;
            if state.available < 0.0 {
                Duration::from_secs_f64(-state.available / rate)
            } else {
                Duration::ZERO
            }
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}
