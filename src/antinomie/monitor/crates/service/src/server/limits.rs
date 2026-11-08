// SPDX-License-Identifier: GPL-3.0-only
//! The limits of the local socket (design 5.9, 5.5 and abuse cases A8, A18).
//!
//! | Limit | Value | Over it |
//! |---|---|---|
//! | line, either way | 2 MiB | request: `payload_too_large`, then the connection closes (the stream cannot be framed); reply: replaced by `payload_too_large` |
//! | requests in flight per connection | 16 | `quota_exceeded`, reason `too_many_requests` |
//! | requests in flight in all | 256 | the same |
//! | request rate per connection | 50 a second, bursts of 100 | `quota_exceeded`, reason `rate_limited`, `retry_after_s` |
//! | connections | 64 | one `unavailable` line (reason `too_many_connections`), then closed |
//! | subscriptions | 64 per client, 256 in all | `quota_exceeded`, reason `too_many_subscriptions` |
//! | idle connection (nothing in flight, no subscription) | 300 s | closed |
//! | a line started and not finished | 30 s | closed |
//! | one reply line written | 10 s | the connection is a slow consumer and closes (`slow_consumer`) |
//! | a subscription with no event | 15 s | `engine.ping` frame |
//! | events a subscription has not taken | 4096 | re-read from the table (no event is lost); a client that cannot take one line in 10 s is closed |
//! | `upload.put` data | 1 MiB decoded | `payload_too_large` |

use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_line: usize,
    pub in_flight_per_connection: usize,
    pub in_flight_total: usize,
    pub connections: usize,
    pub subscriptions_per_client: usize,
    pub subscriptions_total: usize,
    pub rate_per_s: f64,
    pub burst: f64,
    pub idle: Duration,
    pub partial_line: Duration,
    pub write_timeout: Duration,
    pub ping_every: Duration,
    pub subscription_backlog: usize,
    /// How often a blocked read wakes to check the clocks and the stop flag.
    pub tick: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line: super::frame::MAX_LINE,
            in_flight_per_connection: 16,
            in_flight_total: 256,
            connections: 64,
            subscriptions_per_client: 64,
            subscriptions_total: 256,
            rate_per_s: 50.0,
            burst: 100.0,
            idle: Duration::from_secs(300),
            partial_line: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            ping_every: Duration::from_secs(15),
            subscription_backlog: 4096,
            tick: Duration::from_millis(250),
        }
    }
}

/// A token bucket: `rate` tokens a second up to `burst`.
#[derive(Clone, Debug)]
pub struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    at: Instant,
}

impl Bucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            rate,
            burst,
            at: Instant::now(),
        }
    }

    /// Take one token at `now`; `Err(seconds)` until one is there.
    pub fn take(&mut self, now: Instant) -> Result<(), u64> {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - self.tokens) / self.rate).ceil().max(1.0) as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bucket_allows_a_burst_then_the_rate() {
        let start = Instant::now();
        let mut bucket = Bucket::new(50.0, 100.0);
        for _ in 0..100 {
            assert!(bucket.take(start).is_ok());
        }
        assert_eq!(bucket.take(start), Err(1));
        // A tenth of a second later five more requests may go.
        let later = start + Duration::from_millis(100);
        for _ in 0..5 {
            assert!(bucket.take(later).is_ok());
        }
        assert!(bucket.take(later).is_err());
        // A long pause refills to the burst, never above it.
        let much_later = later + Duration::from_secs(3600);
        for _ in 0..100 {
            assert!(bucket.take(much_later).is_ok());
        }
        assert!(bucket.take(much_later).is_err());
    }
}
