// SPDX-License-Identifier: GPL-3.0-only
//! Phases of a run: the stretches where one kind of activity leads.
//!
//! Each category maps to a phase. A base bucket takes the phase with the
//! largest weighted sum; equal neighbours merge; a span shorter than 2 % of the
//! run, or lighter than [`MIN_WEIGHT`], is absorbed into a neighbour; at most
//! eight remain. The band is a summary, never evidence.
use super::index::Bin;
use crate::triage::rules::Category;

/// A span lighter than this is absorbed. The design set it to 5 for the 10/4/1
/// weights: a lone MEDIUM (4) cannot form a phase, one HIGH can, and so can a
/// MEDIUM with one LOW, two MEDIUMs or five LOWs.
pub(in crate::triage) const MIN_WEIGHT: u32 = 5;
/// A recon span made of INFO matches only needs this many of them.
pub(in crate::triage) const MIN_INFO: u32 = 20;
/// Spans shorter than this share of the run are absorbed.
const MIN_SHARE: f64 = 0.02;
/// Labelled spans at most.
pub(in crate::triage) const MAX_SPANS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) enum Phase {
    Recon,
    Download,
    Persistence,
    Escalation,
    Hide,
    C2,
    Spread,
    Impact,
}

impl Phase {
    pub(in crate::triage) const ALL: [Phase; 8] = [
        Self::Recon,
        Self::Download,
        Self::Persistence,
        Self::Escalation,
        Self::Hide,
        Self::C2,
        Self::Spread,
        Self::Impact,
    ];

    pub(in crate::triage) fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|other| *other == self)
            .unwrap_or(0)
    }

    pub(in crate::triage) fn label(self) -> &'static str {
        match self {
            Self::Recon => "recon",
            Self::Download => "download",
            Self::Persistence => "persistence",
            Self::Escalation => "escalation",
            Self::Hide => "hide/inject",
            Self::C2 => "C2",
            Self::Spread => "spread",
            Self::Impact => "impact",
        }
    }
}

/// Rules that bring code in from outside: Execution with ingress.
const INGRESS: &[&str] = &[
    "execution.download_cradle",
    "c2.elf_download",
    "execution.dropped_exec",
];

/// The anti-analysis checks of the Evasion category.
const ANTI_ANALYSIS: &[&str] = &[
    "evasion.sandbox_probe",
    "evasion.probe_then_exit",
    "evasion.traceme",
    "evasion.debugger_check",
    "evasion.container_check",
    "evasion.long_sleep",
];

/// The phase a finding belongs to, if its category has one.
pub(in crate::triage) fn phase_of(rule: &str, category: Category) -> Option<Phase> {
    if INGRESS.contains(&rule) {
        return Some(Phase::Download);
    }
    match category {
        Category::Discovery => Some(Phase::Recon),
        Category::Evasion if ANTI_ANALYSIS.contains(&rule) => Some(Phase::Recon),
        Category::Persistence => Some(Phase::Persistence),
        Category::Privilege => Some(Phase::Escalation),
        Category::Injection | Category::Rootkit => Some(Phase::Hide),
        Category::Command | Category::Exfiltration => Some(Phase::C2),
        Category::Lateral => Some(Phase::Spread),
        Category::Impact => Some(Phase::Impact),
        _ => None,
    }
}

/// One labelled stretch, in base buckets (both ends included).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) struct Span {
    pub phase: Phase,
    pub first: u32,
    pub last: u32,
    pub weight: u32,
    pub info: u32,
}

impl Span {
    fn width(&self) -> u32 {
        self.last - self.first + 1
    }

    /// Whether the span stands. A span with a neighbour must also be long
    /// enough; a lone one is not absorbed for its length, since it has nowhere to go.
    fn holds(&self, run: u32, alone: bool) -> bool {
        let long = alone || f64::from(self.width()) >= (MIN_SHARE * f64::from(run)).max(1.0);
        let heavy = self.weight >= MIN_WEIGHT
            || (self.phase == Phase::Recon && self.weight == 0 && self.info >= MIN_INFO);
        long && heavy
    }
}

/// The phase a bucket leans to: its heaviest, else recon by INFO count.
fn lean(bin: &Bin) -> Option<(Phase, u32, u32)> {
    let (at, weight) = bin
        .phase_weight
        .iter()
        .enumerate()
        .rev()
        .max_by_key(|(_, weight)| **weight)?;
    if *weight > 0 {
        return Some((Phase::ALL[at], *weight, 0));
    }
    (bin.info_recon > 0).then_some((Phase::Recon, 0, bin.info_recon))
}

/// The phases of a run from its base buckets.
pub(in crate::triage) fn detect(bins: &[Bin]) -> Vec<Span> {
    let run = bins.len() as u32;
    let mut spans: Vec<Span> = Vec::new();
    for (at, bin) in bins.iter().enumerate() {
        let Some((phase, weight, info)) = lean(bin) else {
            continue;
        };
        match spans.last_mut() {
            Some(span) if span.phase == phase => {
                span.last = at as u32;
                span.weight += weight;
                span.info += info;
            }
            _ => spans.push(Span {
                phase,
                first: at as u32,
                last: at as u32,
                weight,
                info,
            }),
        }
    }
    // A phase lasts until the next one begins: the quiet bins between two are
    // part of the earlier span, so a short burst of activity still has a length.
    for at in 1..spans.len() {
        spans[at - 1].last = spans[at].first - 1;
    }
    // Drop the weakest span that does not hold, or the weakest past the limit.
    loop {
        let alone = spans.len() == 1;
        let weakest = spans
            .iter()
            .enumerate()
            .filter(|(_, span)| !span.holds(run, alone) || spans.len() > MAX_SPANS)
            .min_by_key(|(_, span)| (span.weight + span.info / 4, span.width()))
            .map(|(at, _)| at);
        let Some(at) = weakest else { break };
        absorb(&mut spans, at);
    }
    spans
}

/// Give span `at` to its heavier neighbour, then merge equal neighbours.
fn absorb(spans: &mut Vec<Span>, at: usize) {
    let span = spans.remove(at);
    let before = at.checked_sub(1);
    let after = (at < spans.len()).then_some(at);
    let into = match (before, after) {
        (Some(before), Some(after)) if spans[after].weight > spans[before].weight => Some(after),
        (Some(before), _) => Some(before),
        (None, after) => after,
    };
    if let Some(into) = into {
        let target = &mut spans[into];
        target.first = target.first.min(span.first);
        target.last = target.last.max(span.last);
        target.weight += span.weight;
        target.info += span.info;
    }
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans.drain(..) {
        match merged.last_mut() {
            Some(last) if last.phase == span.phase => {
                last.last = last.last.max(span.last);
                last.weight += span.weight;
                last.info += span.info;
            }
            _ => merged.push(span),
        }
    }
    *spans = merged;
}
