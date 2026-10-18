// SPDX-License-Identifier: MIT
//! Bounded holding area for packets of a root task the host has not been told
//! about yet.
//!
//! The guest can send telemetry of a launched program before the reply to its
//! EXEC command reaches the host; those packets carry a root cookie no run
//! owns. They wait here, keyed by that cookie, until the reply claims them.
//! Everything else leaves on its own: packets older than the age limit are
//! dropped, a cookie is bounded by its own size, and a cookie nobody claims
//! disappears. A cookie that overflows or ages out only notes the loss for
//! itself; the loss is reported when (and only if) that cookie is claimed.
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

/// Limits of the pre-acknowledgement buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreAckLimits {
    /// Most bytes buffered for one root cookie.
    pub cookie_size: usize,
    /// Most bytes buffered for all root cookies together.
    pub total_size: usize,
    /// How long a packet may wait for its acknowledgement.
    pub max_age: Duration,
}

impl Default for PreAckLimits {
    fn default() -> Self {
        Self {
            cookie_size: 16 * 1024 * 1024,
            total_size: 32 * 1024 * 1024,
            max_age: Duration::from_secs(5),
        }
    }
}

/// Root cookies tracked at once; the least recently active one is forgotten first.
const MAX_COOKIES: usize = 64;
/// A cookie with no packets left (all aged out) keeps its loss counters this
/// many ages, so a late claim can still say what was lost.
const TOMBSTONE_AGES: u32 = 12;

#[derive(Default)]
struct Waiting {
    packets: VecDeque<(Instant, Vec<u8>)>,
    len: usize,
    last_push: Option<Instant>,
    lost: Lost,
}

/// Packets of one cookie that could not be kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Lost {
    pub count: u64,
    pub len: u64,
}

impl Lost {
    /// The note a run carries when part of its pre-acknowledgement telemetry
    /// was not kept. A note is information, never a saving failure.
    pub fn note(&self) -> Option<String> {
        (self.count > 0).then(|| {
            format!(
                "{} telemetry packets ({} bytes) sent before the launch was acknowledged could not be \
                 assigned to this run (buffer size or age limit); they remain in the boot's raw archives",
                self.count, self.len
            )
        })
    }
}

/// What a claim hands over: the buffered packets in arrival order and the loss.
#[derive(Debug, Default)]
pub(crate) struct Claim {
    pub packets: Vec<Vec<u8>>,
    pub lost: Lost,
}

pub(crate) struct PreAckBuffer {
    limits: PreAckLimits,
    cookies: BTreeMap<u64, Waiting>,
    total_len: usize,
}

impl PreAckBuffer {
    pub fn new(limits: PreAckLimits) -> Self {
        Self {
            limits,
            cookies: BTreeMap::new(),
            total_len: 0,
        }
    }
    /// Bytes buffered for all cookies.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.total_len
    }
    /// Cookies with buffered packets or remembered losses.
    #[cfg(test)]
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }
    /// Bytes buffered for one cookie.
    #[cfg(test)]
    pub fn cookie_len(&self, cookie: u64) -> usize {
        self.cookies.get(&cookie).map_or(0, |waiting| waiting.len)
    }
    /// Losses remembered for one cookie.
    #[cfg(test)]
    pub fn lost(&self, cookie: u64) -> Lost {
        self.cookies
            .get(&cookie)
            .map_or_else(Lost::default, |waiting| waiting.lost)
    }
    /// Keep a packet of `cookie` until it is claimed or too old.
    pub fn push(&mut self, cookie: u64, packet: &[u8], now: Instant) {
        if packet.len() > self.limits.cookie_size.min(self.limits.total_size) {
            let waiting = self.waiting(cookie, now);
            waiting.lost.count += 1;
            waiting.lost.len += packet.len() as u64;
            return;
        }
        let waiting = self.waiting(cookie, now);
        waiting.packets.push_back((now, packet.to_vec()));
        waiting.len += packet.len();
        self.total_len += packet.len();
        let mut overflow = Lost::default();
        if let Some(waiting) = self.cookies.get_mut(&cookie) {
            while waiting.len > self.limits.cookie_size {
                let Some((_, old)) = waiting.packets.pop_front() else {
                    break;
                };
                waiting.len -= old.len();
                overflow.count += 1;
                overflow.len += old.len() as u64;
            }
            waiting.lost.count += overflow.count;
            waiting.lost.len += overflow.len;
        }
        self.total_len -= overflow.len as usize;
        while self.total_len > self.limits.total_size {
            // The cookie whose oldest packet waited longest pays first.
            let Some(oldest) = self
                .cookies
                .iter()
                .filter_map(|(cookie, waiting)| {
                    waiting.packets.front().map(|(at, _)| (*at, *cookie))
                })
                .min()
                .map(|(_, cookie)| cookie)
            else {
                break;
            };
            self.evict_front(oldest);
        }
    }
    /// Keep a packet of root `cookie` that no run owns, unless it cannot be
    /// claimed: cookie 0 is no root task, and the app's own resource collector
    /// (`own_cookie`) runs for the whole boot without ever being acknowledged
    /// as a run, so nothing would ever claim its continuous telemetry.
    /// True when the packet was offered to the buffer.
    pub fn hold(&mut self, cookie: u64, own_cookie: u64, packet: &[u8], now: Instant) -> bool {
        let claimable = cookie != 0 && cookie != own_cookie;
        if claimable {
            self.push(cookie, packet, now);
        }
        claimable
    }
    /// Drop packets older than the age limit and forget cookies that nothing
    /// holds any more.
    pub fn expire(&mut self, now: Instant) {
        let max_age = self.limits.max_age;
        let tombstone_age = max_age.saturating_mul(TOMBSTONE_AGES);
        let cookies: Vec<u64> = self.cookies.keys().copied().collect();
        for cookie in cookies {
            while self
                .cookies
                .get(&cookie)
                .and_then(|waiting| waiting.packets.front())
                .is_some_and(|(at, _)| now.saturating_duration_since(*at) > max_age)
            {
                self.evict_front(cookie);
            }
            if self.cookies.get(&cookie).is_some_and(|waiting| {
                waiting.packets.is_empty()
                    && waiting.last_push.is_none_or(|at| {
                        now.saturating_duration_since(at)
                            > if waiting.lost.count == 0 {
                                max_age
                            } else {
                                tombstone_age
                            }
                    })
            }) {
                self.cookies.remove(&cookie);
            }
        }
    }
    /// Hand over everything buffered for `cookie`, and forget it.
    pub fn claim(&mut self, cookie: u64, now: Instant) -> Claim {
        self.expire(now);
        let Some(waiting) = self.cookies.remove(&cookie) else {
            return Claim::default();
        };
        self.total_len -= waiting.len;
        Claim {
            packets: waiting
                .packets
                .into_iter()
                .map(|(_, packet)| packet)
                .collect(),
            lost: waiting.lost,
        }
    }
    /// Forget a cookie that is known not to need its packets.
    pub fn discard(&mut self, cookie: u64) {
        if let Some(waiting) = self.cookies.remove(&cookie) {
            self.total_len -= waiting.len;
        }
    }
    fn evict_front(&mut self, cookie: u64) {
        if let Some(waiting) = self.cookies.get_mut(&cookie)
            && let Some((_, old)) = waiting.packets.pop_front()
        {
            waiting.len -= old.len();
            waiting.lost.count += 1;
            waiting.lost.len += old.len() as u64;
            self.total_len -= old.len();
        }
    }
    fn waiting(&mut self, cookie: u64, now: Instant) -> &mut Waiting {
        if !self.cookies.contains_key(&cookie) && self.cookies.len() >= MAX_COOKIES {
            // The cookie that has been quiet longest is the least likely to be claimed.
            if let Some(stale) = self
                .cookies
                .iter()
                .min_by_key(|(_, waiting)| waiting.last_push)
                .map(|(cookie, _)| *cookie)
            {
                self.discard(stale);
            }
        }
        let waiting = self.cookies.entry(cookie).or_default();
        waiting.last_push = Some(now);
        waiting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(cookie_size: usize, total_size: usize, age_ms: u64) -> PreAckLimits {
        PreAckLimits {
            cookie_size,
            total_size,
            max_age: Duration::from_millis(age_ms),
        }
    }
    fn ms(start: Instant, n: u64) -> Instant {
        start + Duration::from_millis(n)
    }

    #[test]
    fn claim_returns_only_that_cookie_in_arrival_order() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(1000, 4000, 5000));
        buffer.push(1, &[1; 10], t0);
        buffer.push(2, &[2; 20], t0);
        buffer.push(1, &[3; 10], ms(t0, 1));
        let claim = buffer.claim(1, ms(t0, 2));
        assert_eq!(claim.packets, vec![vec![1; 10], vec![3; 10]]);
        assert_eq!(claim.lost, Lost::default());
        assert_eq!(buffer.cookie_len(2), 20);
        assert_eq!(buffer.len(), 20);
        assert!(buffer.claim(1, ms(t0, 3)).packets.is_empty());
    }

    #[test]
    fn overflow_is_per_cookie_and_does_not_touch_other_cookies() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(100, 10_000, 5000));
        buffer.push(7, &[7; 60], t0);
        for n in 0..5 {
            buffer.push(9, &[n; 40], ms(t0, n as u64));
        }
        // Cookie 9 keeps its newest 80 bytes; cookie 7 is untouched.
        assert_eq!(buffer.cookie_len(9), 80);
        assert_eq!(buffer.lost(9), Lost { count: 3, len: 120 });
        assert_eq!(buffer.lost(7), Lost::default());
        assert_eq!(buffer.cookie_len(7), 60);
        let claim = buffer.claim(9, ms(t0, 10));
        assert_eq!(claim.packets, vec![vec![3; 40], vec![4; 40]]);
        assert_eq!(claim.lost.count, 3);
    }

    #[test]
    fn the_collector_and_cookie_zero_are_never_buffered() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(1000, 4000, 5000));
        let collector = 99;
        // Thousands of packets of the collector, far past every limit.
        for n in 0..4000u64 {
            assert!(!buffer.hold(collector, collector, &[0; 200], ms(t0, n)));
        }
        assert!(!buffer.hold(0, collector, &[0; 200], t0));
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.cookie_count(), 0);
        // Another root cookie is still held for its acknowledgement.
        assert!(buffer.hold(5, collector, &[1; 50], t0));
        assert_eq!(buffer.cookie_len(5), 50);
        // Packets that arrived before the collector's reply are dropped once it is known.
        buffer.push(collector, &[2; 80], t0);
        assert_eq!(buffer.len(), 130);
        buffer.discard(collector);
        assert_eq!(buffer.len(), 50);
    }

    #[test]
    fn a_loss_is_a_note_only_when_something_was_lost() {
        assert_eq!(Lost::default().note(), None);
        let note = Lost { count: 3, len: 600 }.note().unwrap();
        assert!(note.contains("3 telemetry packets (600 bytes)"));
    }

    #[test]
    fn claim_clears_the_overflow_of_that_cookie_only() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(50, 10_000, 5000));
        for cookie in [1, 2] {
            buffer.push(cookie, &[0; 40], t0);
            buffer.push(cookie, &[1; 40], t0);
        }
        assert_eq!(buffer.claim(1, t0).lost.count, 1);
        assert_eq!(buffer.lost(1), Lost::default());
        assert_eq!(buffer.lost(2).count, 1);
        // The next run with a reused cookie value starts clean.
        buffer.push(1, &[5; 10], t0);
        assert_eq!(buffer.claim(1, t0).lost, Lost::default());
    }

    #[test]
    fn packets_older_than_the_age_limit_are_dropped_and_counted() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(1000, 4000, 100));
        buffer.push(1, &[1; 10], t0);
        buffer.push(1, &[2; 10], ms(t0, 80));
        buffer.expire(ms(t0, 150));
        assert_eq!(buffer.cookie_len(1), 10);
        assert_eq!(buffer.lost(1).count, 1);
        let claim = buffer.claim(1, ms(t0, 160));
        assert_eq!(claim.packets, vec![vec![2; 10]]);
        assert_eq!(claim.lost, Lost { count: 1, len: 10 });
    }

    #[test]
    fn unclaimed_cookies_disappear_and_a_busy_stream_stays_bounded_by_age() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(1_000_000, 4_000_000, 100));
        // A stream nobody claims (the app's own collector) for 10 s of packets.
        for n in 0..1000u64 {
            let now = ms(t0, n * 10);
            buffer.push(5, &[0; 200], now);
            buffer.expire(now);
            assert!(buffer.len() <= 200 * 11);
        }
        // Once it stops, the whole cookie is forgotten.
        buffer.expire(ms(t0, 10_000 + 100 * 13));
        assert_eq!(buffer.cookie_count(), 0);
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn a_late_claim_still_learns_that_packets_aged_out() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(1000, 4000, 100));
        buffer.push(3, &[0; 30], t0);
        buffer.expire(ms(t0, 500));
        assert_eq!(buffer.len(), 0);
        let claim = buffer.claim(3, ms(t0, 600));
        assert!(claim.packets.is_empty());
        assert_eq!(claim.lost, Lost { count: 1, len: 30 });
    }

    #[test]
    fn total_limit_evicts_the_cookie_that_waited_longest() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(200, 150, 5000));
        buffer.push(1, &[1; 60], t0);
        buffer.push(2, &[2; 60], ms(t0, 1));
        buffer.push(2, &[2; 60], ms(t0, 2));
        assert!(buffer.len() <= 150);
        assert_eq!(buffer.lost(1).count, 1);
        assert_eq!(buffer.cookie_len(2), 120);
    }

    #[test]
    fn an_oversized_packet_is_counted_not_buffered() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(10, 100, 5000));
        buffer.push(1, &[0; 11], t0);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.lost(1), Lost { count: 1, len: 11 });
    }

    #[test]
    fn the_number_of_tracked_cookies_is_bounded() {
        let t0 = Instant::now();
        let mut buffer = PreAckBuffer::new(limits(100, 1_000_000, 5000));
        for cookie in 1..=(MAX_COOKIES as u64 + 10) {
            buffer.push(cookie, &[0; 10], ms(t0, cookie));
        }
        assert_eq!(buffer.cookie_count(), MAX_COOKIES);
        assert_eq!(buffer.len(), MAX_COOKIES * 10);
        buffer.discard(MAX_COOKIES as u64 + 10);
        assert_eq!(buffer.len(), (MAX_COOKIES - 1) * 10);
    }
}
