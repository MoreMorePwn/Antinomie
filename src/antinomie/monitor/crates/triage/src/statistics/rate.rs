// SPDX-License-Identifier: GPL-3.0-only
//! Calls per interval over the run (design 4.3.3).
//!
//! Every series shares one timeline of at most `MAX_BINS` bins. The bin width
//! starts at 1 ms and doubles (adjacent bins merge) whenever a call falls past
//! the last bin, so a run of any length fits: an hour ends at 64 ms bins, a day
//! at 2.048 s. Bins sit on a grid of whole widths from time 0, so a merge never
//! splits a bin and a call earlier than the first bin only adds bins in front.
use serde::{Deserialize, Serialize};

/// Bins per series.
pub const MAX_BINS: usize = 65_536;
/// The first bin width.
pub const FIRST_WIDTH_NS: u64 = 1_000_000;
const SECOND_NS: u64 = 1_000_000_000;

#[derive(Clone, Debug)]
pub struct RateBins {
    origin: u64,
    width: u64,
    used: usize,
    started: bool,
    series: Vec<Vec<u32>>,
    active: Vec<bool>,
}

/// One series of the result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateSeries {
    /// `all`, `failed`, a group label, `Other`, or the text of a custom line's filter.
    pub name: String,
    pub bins: Vec<u32>,
}

/// The bins of a finished walk. Bin `i` covers `[start_ns + i * bin_ns, start_ns + (i + 1) * bin_ns)`
/// on the guest clock; every series has the same length.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    pub start_ns: u64,
    pub bin_ns: u64,
    pub series: Vec<RateSeries>,
}

/// The busiest stretch of about a second: `calls` in `[start_ns, start_ns + span_ns)`.
/// `span_ns` is a whole number of bins, a little under a second for narrow bins
/// and one bin when bins are wider than a second (then it is "the busiest 2 s",
/// and so on; say so).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peak {
    pub calls: u64,
    pub start_ns: u64,
    pub span_ns: u64,
}

impl RateBins {
    /// `count` series; `active[i]` says whether series `i` is filled at all.
    pub fn new(active: Vec<bool>) -> Self {
        Self {
            origin: 0,
            width: FIRST_WIDTH_NS,
            used: 0,
            started: false,
            series: vec![Vec::new(); active.len()],
            active,
        }
    }

    pub fn width_ns(&self) -> u64 {
        self.width
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn heap_bytes(&self) -> usize {
        self.series.iter().map(|s| s.capacity() * 4).sum()
    }

    /// Count a call at guest time `ts` in each series of `ids`.
    pub fn add(&mut self, ts: u64, ids: &[usize]) {
        if !self.started {
            self.origin = ts / self.width * self.width;
            self.started = true;
        } else if ts < self.origin {
            self.move_back(ts);
        }
        let mut index = ((ts - self.origin) / self.width) as usize;
        while index >= MAX_BINS {
            self.double();
            index = ((ts - self.origin) / self.width) as usize;
        }
        if index >= self.used {
            self.used = index + 1;
            let used = self.used;
            for (series, active) in self.series.iter_mut().zip(&self.active) {
                if *active && series.len() < used {
                    series.resize(used, 0);
                }
            }
        }
        for &id in ids {
            if let Some(bin) = self.series[id].get_mut(index) {
                *bin = bin.saturating_add(1);
            }
        }
    }

    /// Start earlier so that `ts` has a bin.
    fn move_back(&mut self, ts: u64) {
        loop {
            let origin = ts / self.width * self.width;
            let shift = ((self.origin - origin) / self.width) as usize;
            if self.used.saturating_add(shift) <= MAX_BINS {
                for (series, active) in self.series.iter_mut().zip(&self.active) {
                    if *active {
                        series.splice(0..0, std::iter::repeat_n(0, shift));
                    }
                }
                self.origin = origin;
                self.used += shift;
                return;
            }
            self.double();
            if ts >= self.origin {
                return;
            }
        }
    }

    /// Merge adjacent bins; the width doubles.
    fn double(&mut self) {
        let width = self.width * 2;
        let origin = self.origin / width * width;
        let offset = ((self.origin - origin) / self.width) as usize;
        let used = (offset + self.used).div_ceil(2);
        for (series, active) in self.series.iter_mut().zip(&self.active) {
            if !*active {
                continue;
            }
            let mut merged = vec![0_u32; used];
            for (i, &n) in series.iter().enumerate() {
                let slot = &mut merged[(i + offset) / 2];
                *slot = slot.saturating_add(n);
            }
            *series = merged;
        }
        self.width = width;
        self.origin = origin;
        self.used = used;
    }

    /// The sum of series `id` over all bins.
    pub fn total(&self, id: usize) -> u64 {
        self.series[id].iter().map(|&n| u64::from(n)).sum()
    }

    /// The busiest second of series `id`.
    pub fn peak(&self, id: usize) -> Option<Peak> {
        let bins = &self.series[id];
        if bins.is_empty() {
            return None;
        }
        let window = (SECOND_NS / self.width).max(1) as usize;
        let mut sum: u64 = bins.iter().take(window).map(|&n| u64::from(n)).sum();
        let (mut best, mut at) = (sum, 0);
        for i in window..bins.len() {
            sum += u64::from(bins[i]);
            sum -= u64::from(bins[i - window]);
            if sum > best {
                best = sum;
                at = i + 1 - window;
            }
        }
        (best > 0).then(|| Peak {
            calls: best,
            start_ns: self.origin + at as u64 * self.width,
            span_ns: window as u64 * self.width,
        })
    }

    /// The result, with the series `names[i]`; a series nothing was counted in
    /// is left out unless `keep(i)`.
    pub fn finish(&self, names: &[String], keep: impl Fn(usize) -> bool) -> Rate {
        if !self.started {
            return Rate::default();
        }
        let series = (0..self.series.len())
            .filter(|&i| self.active[i] && (keep(i) || self.series[i].iter().any(|&n| n > 0)))
            .map(|i| RateSeries {
                name: names[i].clone(),
                bins: self.series[i].clone(),
            })
            .collect();
        Rate {
            start_ns: self.origin,
            bin_ns: self.width,
            series,
        }
    }
}
