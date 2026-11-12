// SPDX-License-Identifier: GPL-3.0-only
//! Call durations: exact min, max and total, percentiles from a log-linear
//! histogram, and the slowest calls (design 4.3.2).
//!
//! The histogram has 16 buckets per doubling from 1 ns to 2^40 ns (about 18
//! minutes; longer calls fall in the last bucket, whose bound is the exact
//! maximum). A percentile is the upper bound of the bucket where the running
//! count reaches it, clamped to `[min, max]`: at most 1/16 above the true value.
use super::blocking::BlockClass;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

const STEPS: u32 = 16;
const DOUBLINGS: u32 = 40;
/// Buckets of one histogram: 5,120 bytes of counters.
pub const BUCKETS: usize = (STEPS * DOUBLINGS) as usize;
/// The slowest calls each list keeps.
pub const SLOWEST: usize = 20;

#[derive(Clone)]
pub struct Histogram {
    counts: Box<[u64]>,
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub total: u128,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: vec![0; BUCKETS].into_boxed_slice(),
            count: 0,
            min: u64::MAX,
            max: 0,
            total: 0,
        }
    }
}

/// The bucket of a duration of `ns` nanoseconds.
fn bucket(ns: u64) -> usize {
    if ns == 0 {
        return 0;
    }
    let exponent = 63 - ns.leading_zeros();
    if exponent >= DOUBLINGS {
        return BUCKETS - 1;
    }
    let sub = if exponent >= 4 {
        (ns >> (exponent - 4)) & 15
    } else {
        (ns << (4 - exponent)) & 15
    };
    (exponent * STEPS) as usize + sub as usize
}

/// The smallest and largest duration (inclusive) that land in bucket `index`.
fn bounds(index: usize) -> (u64, u64) {
    let exponent = index as u32 / STEPS;
    let sub = u128::from(index as u32 % STEPS);
    let low = ((16 + sub) << exponent) >> 4;
    let high = ((17 + sub) << exponent) >> 4;
    let low = low as u64;
    let high = (high as u64).saturating_sub(1).max(low);
    (low, high)
}

impl Histogram {
    pub fn add(&mut self, ns: u64) {
        self.counts[bucket(ns)] += 1;
        self.count += 1;
        self.min = self.min.min(ns);
        self.max = self.max.max(ns);
        self.total += u128::from(ns);
    }

    pub fn heap_bytes(&self) -> usize {
        BUCKETS * 8 + std::mem::size_of::<Self>()
    }

    /// The duration below which a share `p` (0..=1) of the calls fall, within 1/16.
    pub fn percentile(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let rank = ((p * self.count as f64).ceil() as u64).clamp(1, self.count);
        let mut seen = 0;
        for (index, &n) in self.counts.iter().enumerate() {
            seen += n;
            if seen >= rank {
                let bound = if index == BUCKETS - 1 {
                    self.max
                } else {
                    bounds(index).1
                };
                return bound.clamp(self.min, self.max);
            }
        }
        self.max
    }

    /// The non-empty buckets as `(upper bound ns, calls)`, for the distribution.
    pub fn buckets(&self) -> Vec<(u64, u64)> {
        self.counts
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(index, &n)| {
                let bound = if index == BUCKETS - 1 {
                    self.max
                } else {
                    bounds(index).1
                };
                (bound.clamp(self.min, self.max), n)
            })
            .collect()
    }
}

/// One row of the latency tables: a call name in one blocking class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyRow {
    pub name: String,
    pub class: BlockClass,
    /// Calls with both an entry and an exit.
    pub timed: u64,
    pub min_ns: u64,
    pub median_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    /// Saturates at `u64::MAX` (584 years).
    pub total_ns: u64,
    pub mean_ns: u64,
    /// Non-empty histogram buckets as `(upper bound ns, calls)`.
    pub histogram: Vec<(u64, u64)>,
}

impl LatencyRow {
    pub fn from_histogram(name: &str, class: BlockClass, h: &Histogram) -> Self {
        Self {
            name: name.to_owned(),
            class,
            timed: h.count,
            min_ns: h.min,
            median_ns: h.percentile(0.5),
            p95_ns: h.percentile(0.95),
            p99_ns: h.percentile(0.99),
            max_ns: h.max,
            total_ns: u64::try_from(h.total).unwrap_or(u64::MAX),
            mean_ns: u64::try_from(h.total / u128::from(h.count.max(1))).unwrap_or(u64::MAX),
            histogram: h.buckets(),
        }
    }
}

/// A call that took long, with what the Trace needs to open it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlowCall {
    /// `(stream id, task cookie, call id)`, as `trace::key`.
    pub key: (u64, u64, u64),
    pub name: String,
    pub pid: u32,
    pub tid: u32,
    pub start_ns: u64,
    pub duration_ns: u64,
}

#[derive(PartialEq, Eq)]
struct Ranked(SlowCall);

impl Ord for Ranked {
    /// Longer first; equal durations by the lower key.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .duration_ns
            .cmp(&other.0.duration_ns)
            .then_with(|| other.0.key.cmp(&self.0.key))
    }
}
impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The `SLOWEST` longest calls seen: a min-heap that drops its shortest.
#[derive(Default)]
pub struct Slowest {
    heap: BinaryHeap<Reverse<Ranked>>,
}

impl Slowest {
    /// Offer a call; the name is only copied when the call makes the list.
    pub fn offer(
        &mut self,
        duration_ns: u64,
        key: (u64, u64, u64),
        make: impl FnOnce() -> SlowCall,
    ) {
        if self.heap.len() >= SLOWEST {
            let Some(Reverse(shortest)) = self.heap.peek() else {
                return;
            };
            let beats = duration_ns > shortest.0.duration_ns
                || (duration_ns == shortest.0.duration_ns && key < shortest.0.key);
            if !beats {
                return;
            }
            self.heap.pop();
        }
        self.heap.push(Reverse(Ranked(make())));
    }

    /// Longest first.
    pub fn sorted(&self) -> Vec<SlowCall> {
        let mut calls: Vec<_> = self.heap.iter().map(|Reverse(r)| r.0.clone()).collect();
        calls.sort_by(|a, b| {
            b.duration_ns
                .cmp(&a.duration_ns)
                .then_with(|| a.key.cmp(&b.key))
        });
        calls
    }

    pub fn heap_bytes(&self) -> usize {
        SLOWEST * (std::mem::size_of::<SlowCall>() + 32)
    }
}
