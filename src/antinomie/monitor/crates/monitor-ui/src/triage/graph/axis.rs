// SPDX-License-Identifier: GPL-3.0-only
//! How time is laid along the graph: true time, or equal slots.
//!
//! With **Events** spacing every distinct moment a finding happened at gets
//! one slot of the same width, in time order, so a burst of findings in a few
//! milliseconds is as wide as the same number of findings spread over minutes.
//! Between two slots the axis is linear in time, so any time still has a place
//! on it. **Time** spacing is the plain scale.
//!
//! The window the graph shows is kept in the axis's own units: ns for Time,
//! slot numbers for Events.
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Spacing {
    /// One slot per moment, equal widths.
    #[default]
    Events,
    /// True time scale.
    Time,
}

impl Spacing {
    pub(in crate::triage) fn other(self) -> Self {
        match self {
            Self::Events => Self::Time,
            Self::Time => Self::Events,
        }
    }
}

/// Room kept before the first slot and after the last, in slots: 2% of the
/// run, but never so much that a few findings are left in the middle of the
/// plot with the sides empty (three slots at half a slot's room each would
/// leave a sixth of the width empty at both ends).
pub(super) fn slot_pad(slots: f64) -> f64 {
    if slots <= 1.0 {
        // A lone slot still gets a window as wide as one slot.
        return 0.5;
    }
    (slots * 0.02).max(0.25)
}

/// A gap in time at least this many times the typical gap is marked.
pub(super) const BREAK_RATIO: f64 = 8.0;
/// Breaks drawn at most.
pub(super) const MAX_BREAKS: usize = 48;

/// The slots of one index, shared with every axis made from it.
#[derive(Clone, Debug, Default)]
pub(in crate::triage) struct Slots {
    /// Distinct `first_ns` of the findings, sorted.
    pub times: Arc<[u64]>,
    /// The width of a slot, in ns, outside the first and last: the median gap.
    pub unit: f64,
    /// The widest gaps, as (slot before the gap, gap in ns), in time order.
    pub breaks: Arc<[(u32, u64)]>,
}

impl Slots {
    pub(in crate::triage) fn new(times: Vec<u64>) -> Self {
        let mut gaps: Vec<u64> = times.windows(2).map(|pair| pair[1] - pair[0]).collect();
        let median = if gaps.is_empty() {
            1_000_000.0
        } else {
            let middle = gaps.len() / 2;
            *gaps.select_nth_unstable(middle).1 as f64
        };
        let unit = median.max(1.0);
        let mut breaks: Vec<(u32, u64)> = times
            .windows(2)
            .enumerate()
            .filter(|(_, pair)| (pair[1] - pair[0]) as f64 >= unit * BREAK_RATIO)
            .map(|(at, pair)| (at as u32, pair[1] - pair[0]))
            .collect();
        if breaks.len() > MAX_BREAKS {
            breaks.sort_by_key(|(_, gap)| std::cmp::Reverse(*gap));
            breaks.truncate(MAX_BREAKS);
            breaks.sort_unstable();
        }
        Self {
            times: times.into(),
            unit,
            breaks: breaks.into(),
        }
    }
}

/// The map between a time in ns and a place on the axis.
#[derive(Clone, Debug)]
pub(in crate::triage) struct Axis {
    pub spacing: Spacing,
    pub slots: Slots,
}

impl Axis {
    pub(in crate::triage) fn new(spacing: Spacing, slots: &Slots) -> Self {
        Self {
            spacing,
            slots: slots.clone(),
        }
    }

    fn events(&self) -> bool {
        self.spacing == Spacing::Events && !self.slots.times.is_empty()
    }

    /// The place of `ns` on the axis.
    pub(in crate::triage) fn to_u(&self, ns: f64) -> f64 {
        if !self.events() {
            return ns;
        }
        let times = &self.slots.times;
        let (first, last) = (times[0] as f64, times[times.len() - 1] as f64);
        if ns <= first {
            return (ns - first) / self.slots.unit;
        }
        if ns >= last {
            return (times.len() - 1) as f64 + (ns - last) / self.slots.unit;
        }
        let at = times.partition_point(|time| (*time as f64) <= ns) - 1;
        let (a, b) = (times[at] as f64, times[at + 1] as f64);
        at as f64 + (ns - a) / (b - a)
    }

    /// The time at a place on the axis.
    pub(in crate::triage) fn to_ns(&self, u: f64) -> f64 {
        if !self.events() {
            return u;
        }
        let times = &self.slots.times;
        let last_slot = (times.len() - 1) as f64;
        if u <= 0.0 {
            return times[0] as f64 + u * self.slots.unit;
        }
        if u >= last_slot {
            return times[times.len() - 1] as f64 + (u - last_slot) * self.slots.unit;
        }
        let at = u.floor() as usize;
        let (a, b) = (times[at] as f64, times[at + 1] as f64);
        a + (u - at as f64) * (b - a)
    }

    /// The shortest window worth showing: a microsecond, or a slot and a half.
    pub(in crate::triage) fn min_span(&self) -> f64 {
        if self.events() {
            1.5
        } else {
            super::view::MIN_SPAN_NS
        }
    }

    /// The window that shows every finding with a little room.
    pub(in crate::triage) fn all(&self, findings: (u64, u64)) -> (f64, f64) {
        if self.events() {
            let slots = self.slots.times.len() as f64;
            let pad = slot_pad(slots);
            (-pad, slots - 1.0 + pad)
        } else {
            super::view::fitted_findings(findings)
        }
    }

    /// Where the whole run lies on the axis: what pan and zoom stay inside and
    /// the overview ruler spans.
    pub(in crate::triage) fn run(&self, run: (u64, u64)) -> (f64, f64) {
        if self.events() {
            let slots = self.slots.times.len() as f64;
            let pad = slot_pad(slots);
            (-pad, slots - 1.0 + pad)
        } else {
            super::view::fitted(run)
        }
    }

    /// A window in ns, as the other spacing's units.
    pub(in crate::triage) fn convert_from(&self, other: Spacing, window: (f64, f64)) -> (f64, f64) {
        if other == self.spacing {
            return window;
        }
        let from = Axis {
            spacing: other,
            slots: self.slots.clone(),
        };
        (
            self.to_u(from.to_ns(window.0)),
            self.to_u(from.to_ns(window.1)),
        )
    }
}
