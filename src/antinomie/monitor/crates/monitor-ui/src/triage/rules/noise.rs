// SPDX-License-Identifier: GPL-3.0-only
//! The noise pipeline: what turns a stream of hits into a readable list.
//!
//! In order: hits with the same key fold into one row; the row's tier follows
//! the failed calls and allow-listed programs among them; activity outside the
//! run's tree drops a tier and is hidden; a row that repeats at a steady pace
//! says so; per-rule, per-task and per-run caps keep the rest. Nothing is
//! discarded without being counted.
use super::super::*;
use super::{spec, Spec, Tier};

/// Rows kept per `(rule, task)`, per rule, per task and per run.
pub(super) const PER_RULE_TASK: usize = 50;
pub(super) const PER_RULE: usize = 2_000;
pub(super) const PER_TASK: usize = 500;
pub(super) const PER_RUN: usize = 20_000;

/// A failing HIGH rule that keeps trying (this many times) is still trying.
pub(super) const RESTORE_AFTER: u64 = 5;
/// A row is periodic when at least this many gaps are this regular.
const PERIODIC_GAPS: u64 = 7;
const PERIODIC_SPREAD: f64 = 0.2;

pub(super) mod flag {
    pub const FAILED: u16 = 1;
    pub const ALLOW: u16 = 2;
    pub const OUTSIDE: u16 = 4;
    pub const VM_WIDE: u16 = 8;
    pub const SUPPRESSED: u16 = 16;
    pub const ASYNC: u16 = 32;
    pub const COLLAPSED: u16 = 64;
    pub const CAPPED: u16 = 128;
    pub const PERIODIC: u16 = 256;
    pub const RESTORED: u16 = 512;
    pub const INFERRED: u16 = 1024;
    pub const NAMES: [(u16, &str); 11] = [
        (FAILED, "failed"),
        (ALLOW, "allow-listed"),
        (OUTSIDE, "outside-scope"),
        (VM_WIDE, "vm-wide"),
        (SUPPRESSED, "suppressed"),
        (ASYNC, "async"),
        (COLLAPSED, "collapsed"),
        (CAPPED, "capped"),
        (PERIODIC, "periodic"),
        (RESTORED, "repeated"),
        (INFERRED, "inferred"),
    ];
}

/// Inter-arrival times of one row, kept as running moments.
#[derive(Default, Clone)]
pub(super) struct Gaps {
    last: Option<u64>,
    n: u64,
    mean: f64,
    m2: f64,
}

impl Gaps {
    pub(super) fn add(&mut self, time: u64) {
        if let Some(last) = self.last.filter(|last| time >= *last) {
            let gap = (time - last) as f64;
            self.n += 1;
            let delta = gap - self.mean;
            self.mean += delta / self.n as f64;
            self.m2 += delta * (gap - self.mean);
        }
        self.last = Some(time);
    }

    /// The pace, in nanoseconds, when the repeats are regular enough to call a loop.
    pub(super) fn period(&self) -> Option<u64> {
        if self.n < PERIODIC_GAPS || self.mean <= 0.0 {
            return None;
        }
        let spread = (self.m2 / self.n as f64).sqrt() / self.mean;
        (spread < PERIODIC_SPREAD).then_some(self.mean as u64)
    }
}

/// One folded row, before its tier is final.
#[derive(Clone)]
pub(super) struct Agg {
    pub rule: &'static str,
    pub cookie: u64,
    pub pid: u32,
    pub tid: u32,
    pub process: String,
    pub image: Option<String>,
    pub object: String,
    pub summary: String,
    pub attack: &'static [&'static str],
    pub base: Tier,
    pub count: u64,
    pub failed: u64,
    pub allowed: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    pub stream: u64,
    pub call_id: u64,
    pub ret: Option<i64>,
    pub high_confidence: bool,
    pub outcome: String,
    /// The `Evidence` cell: which call to open.
    pub evidence: String,
    pub gaps: Gaps,
    pub flags: u16,
    pub detail: Vec<String>,
    pub siblings: u64,
    /// Occurrences kept as extra evidence, after the first.
    pub samples: Vec<(u64, u64)>,
    /// The capture and frame a row stands on, for a row found in packets.
    pub packet: Option<(String, u64)>,
    /// The tier after context; set by [`settle`].
    pub tier: Tier,
    pub why: Vec<String>,
}

pub(super) const SAMPLES: usize = 16;

impl Agg {
    pub(super) fn spec(&self) -> &'static Spec {
        spec(self.rule).expect("rows only come from classified rules")
    }

    pub(super) fn hidden(&self) -> bool {
        self.flags & (flag::OUTSIDE | flag::SUPPRESSED) != 0
    }

    pub(super) fn key(&self) -> (u64, u64, u64) {
        (self.stream, self.cookie, self.call_id)
    }

    pub(super) fn period(&self) -> Option<u64> {
        self.gaps.period()
    }
}

/// Decide a row's tier from what folded into it, and say why.
pub(super) fn settle(agg: &mut Agg) {
    let spec = agg.spec();
    let mut tier = agg.base;
    agg.why.clear();
    agg.why
        .push(format!("Rule tier {} ({}).", agg.base.tag(), spec.id));
    if agg.base != spec.tier {
        agg.why.push(format!(
            "The rule's own tier is {}; this match depends on its context.",
            spec.tier.tag()
        ));
    }
    if agg.allowed == agg.count && agg.count > 0 {
        tier = tier.down();
        agg.flags |= flag::ALLOW;
        agg.why.push(format!(
            "{} is on the rule's allow-list: one tier down, not hidden.",
            agg.image
                .as_deref()
                .map_or("The program", |image| super::ctx::base(image))
        ));
    }
    if agg.failed == agg.count && agg.count > 0 {
        agg.flags |= flag::FAILED;
        if spec.signal {
            agg.why.push(
                "Every call failed, and for this rule failing is the signal: the tier stays."
                    .into(),
            );
        } else if agg.failed >= RESTORE_AFTER && agg.base == Tier::High {
            agg.flags |= flag::RESTORED;
            agg.why.push(format!(
                "{} failed attempts at the same target: repeated attempts keep the tier.",
                agg.failed
            ));
        } else {
            tier = tier.down();
            agg.why
                .push("Every call failed: one tier down (a failed attempt).".into());
        }
    } else if agg.failed > 0 {
        agg.why.push(format!(
            "{} of {} calls failed; one succeeded, so the tier stays.",
            agg.failed, agg.count
        ));
    }
    if agg.flags & flag::OUTSIDE != 0 {
        tier = tier.down();
        agg.why.push(
            "The process is outside the run's tree and the sample did not cause it: one tier down, hidden unless Show hidden is on."
                .into(),
        );
    }
    if agg.flags & flag::VM_WIDE != 0 {
        tier = tier.down();
        agg.why.push(
            "Seen on the network only, not tied to a process of the run (VM-wide): one tier down."
                .into(),
        );
    }
    if agg.flags & flag::SUPPRESSED != 0 {
        agg.why
            .push("VM housekeeping on the built-in suppression list: hidden.".into());
    }
    if let Some(period) = agg.period() {
        agg.flags |= flag::PERIODIC;
        agg.why.push(format!(
            "Repeats at a steady pace, about every {}: shown as one row; the tier is unchanged.",
            pace(period)
        ));
    }
    if agg.siblings > 1 {
        agg.flags |= flag::COLLAPSED;
        agg.why.push(format!(
            "{} processes started from the same parent did the same: one row.",
            agg.siblings
        ));
    }
    agg.tier = tier;
}

/// A pace in the largest unit that shows it, for "every ~T".
pub(super) fn pace(nanoseconds: u64) -> String {
    let seconds = nanoseconds as f64 / 1e9;
    if seconds >= 3600.0 {
        format!("{:.1} h", seconds / 3600.0)
    } else if seconds >= 120.0 {
        format!("{:.1} min", seconds / 60.0)
    } else if seconds >= 1.0 {
        format!("{seconds:.1} s")
    } else if seconds >= 0.001 {
        format!("{:.0} ms", seconds * 1e3)
    } else {
        format!("{:.0} µs", seconds * 1e6)
    }
}

/// Fold rows of tasks that one parent started and that did the same thing.
/// The key is the rule, the program, its arguments and the object.
pub(super) fn fold_siblings(rows: &mut Vec<Agg>, files: &FdState) {
    let mut first: std::collections::BTreeMap<
        (&'static str, Option<TaskKey>, String, u64, String),
        usize,
    > = std::collections::BTreeMap::new();
    let mut folded = vec![false; rows.len()];
    for index in 0..rows.len() {
        let task = TaskKey {
            pid: rows[index].pid,
            cookie: rows[index].cookie,
        };
        let Some(node) = files.process_images.get(&task) else {
            continue;
        };
        let Some(parent) = node.parent else { continue };
        let digest = node.argv.iter().fold(0u64, |hash, part| {
            part.bytes().fold(hash.rotate_left(7) ^ 0xff, |hash, byte| {
                hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
            })
        });
        let key = (
            rows[index].rule,
            Some(parent),
            node.comm.clone(),
            digest,
            rows[index].object.clone(),
        );
        match first.get(&key).copied() {
            Some(head) if head != index => {
                let (left, right) = rows.split_at_mut(index);
                let target = &mut left[head];
                let source = &right[0];
                if target.siblings == 0 {
                    target.siblings = 1;
                }
                target.siblings += 1;
                target.count += source.count;
                target.failed += source.failed;
                target.allowed += source.allowed;
                target.first_ns = target.first_ns.min(source.first_ns);
                target.last_ns = target.last_ns.max(source.last_ns);
                folded[index] = true;
            }
            _ => {
                first.insert(key, index);
            }
        }
    }
    let mut keep = folded.into_iter();
    rows.retain(|_| !keep.next().unwrap_or(false));
}

/// What the caps dropped, per rule.
#[derive(Default)]
pub(super) struct Overflow {
    pub count: u64,
    pub tier: Option<Tier>,
    pub first: Option<Agg>,
}

/// Apply the caps in first-seen order. Returns the rows kept and the overflow.
pub(super) fn cap(
    rows: Vec<Agg>,
) -> (Vec<Agg>, std::collections::BTreeMap<&'static str, Overflow>) {
    let mut per_pair = std::collections::BTreeMap::<(&str, u64), usize>::new();
    let mut per_rule = std::collections::BTreeMap::<&str, usize>::new();
    let mut per_task = std::collections::BTreeMap::<u64, usize>::new();
    let mut total = 0usize;
    let mut kept = Vec::new();
    let mut overflow = std::collections::BTreeMap::<&'static str, Overflow>::new();
    for row in rows {
        let pair = per_pair.entry((row.rule, row.cookie)).or_default();
        let rule = per_rule.entry(row.rule).or_default();
        let task = per_task.entry(row.cookie).or_default();
        if *pair >= PER_RULE_TASK || *rule >= PER_RULE || *task >= PER_TASK || total >= PER_RUN {
            let slot = overflow.entry(row.rule).or_default();
            slot.count += 1;
            slot.tier = Some(slot.tier.map_or(row.tier, |tier| tier.max(row.tier)));
            if slot.first.is_none() {
                slot.first = Some(row);
            }
            continue;
        }
        *pair += 1;
        *rule += 1;
        *task += 1;
        total += 1;
        kept.push(row);
    }
    (kept, overflow)
}
