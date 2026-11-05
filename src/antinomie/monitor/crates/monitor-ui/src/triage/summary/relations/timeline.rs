// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships box's Timeline: one lane per process (the busiest ones),
//! time across, markers for what happened in it and lines between lanes where
//! one process started another.
use super::super::super::rules::Tier;
use super::model::{Facts, Key};

/// Lanes shown.
pub(in crate::triage) const LANES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) enum MarkKind {
    Fork,
    Exec,
    FileWrite,
    Connect,
    Finding(Tier),
}

#[derive(Clone, Debug)]
pub(in crate::triage) struct Lane {
    pub key: Key,
    pub label: String,
    pub warn: bool,
}

#[derive(Clone, Debug)]
pub(in crate::triage) struct Mark {
    pub lane: usize,
    pub ns: u64,
    pub kind: MarkKind,
    pub label: String,
}

/// A fork or exec from one lane to another.
#[derive(Clone, Debug)]
pub(in crate::triage) struct Link {
    pub from: usize,
    pub to: usize,
    pub ns: u64,
    pub exec: bool,
}

#[derive(Clone, Debug, Default)]
pub(in crate::triage) struct Timeline {
    pub lanes: Vec<Lane>,
    pub marks: Vec<Mark>,
    pub links: Vec<Link>,
    pub start_ns: u64,
    pub end_ns: u64,
}

impl Timeline {
    pub(in crate::triage) fn build(facts: &Facts, limit: usize) -> Self {
        let mut out = Timeline::default();
        let activity = |key: Key| -> u32 {
            let findings = facts
                .findings
                .iter()
                .filter(|f| f.tier != Tier::Info && (f.pid, f.cookie) == key)
                .count() as u32;
            let files = facts
                .files
                .iter()
                .filter(|f| f.process == Some(key))
                .count() as u32;
            let endpoints = facts
                .endpoints
                .iter()
                .filter(|e| e.process == Some(key))
                .count() as u32;
            findings * 10 + files + endpoints
        };
        let mut procs: Vec<_> = facts.procs.iter().collect();
        procs.sort_by_key(|p| (p.first_ns.unwrap_or(0), p.pid));
        let root = procs
            .iter()
            .position(|p| {
                p.parent
                    .is_none_or(|parent| !facts.procs.iter().any(|q| (q.pid, q.cookie) == parent))
            })
            .unwrap_or(0);
        let mut ranked: Vec<usize> = (0..procs.len()).collect();
        ranked.sort_by_key(|&at| {
            let p = procs[at];
            (
                at != root,
                std::cmp::Reverse(activity((p.pid, p.cookie))),
                at,
            )
        });
        ranked.truncate(limit.max(1));
        ranked.sort_unstable();
        for &at in &ranked {
            let p = procs[at];
            out.lanes.push(Lane {
                key: (p.pid, p.cookie),
                label: format!(
                    "{} ({})",
                    if p.name.is_empty() {
                        "unknown"
                    } else {
                        &p.name
                    },
                    p.pid
                ),
                warn: p.mismatch,
            });
        }
        let lane_of = |key: Key| out.lanes.iter().position(|lane| lane.key == key);
        let mut marks = Vec::new();
        let mut links = Vec::new();
        for p in &procs {
            let Some(me) = lane_of((p.pid, p.cookie)) else {
                continue;
            };
            if let (Some(parent), Some(ns)) = (p.parent, p.first_ns) {
                if let Some(from) = lane_of(parent) {
                    marks.push(Mark {
                        lane: from,
                        ns,
                        kind: MarkKind::Fork,
                        label: format!("forked {} ({})", p.name, p.pid),
                    });
                    links.push(Link {
                        from,
                        to: me,
                        ns,
                        exec: !p.forked,
                    });
                }
            }
            for (image, ns) in &p.execs {
                marks.push(Mark {
                    lane: me,
                    ns: *ns,
                    kind: MarkKind::Exec,
                    label: format!("exec {image}"),
                });
            }
        }
        for file in &facts.files {
            if let (Some(lane), Some(ns)) = (file.process.and_then(lane_of), file.ns) {
                marks.push(Mark {
                    lane,
                    ns,
                    kind: MarkKind::FileWrite,
                    label: format!("file {}", file.path),
                });
            }
        }
        for endpoint in &facts.endpoints {
            if let (Some(lane), Some(ns)) = (endpoint.process.and_then(lane_of), endpoint.ns) {
                marks.push(Mark {
                    lane,
                    ns,
                    kind: MarkKind::Connect,
                    label: format!("connect {}", endpoint.endpoint),
                });
            }
        }
        for finding in &facts.findings {
            if finding.tier == Tier::Info {
                continue;
            }
            if let Some(lane) = lane_of((finding.pid, finding.cookie)) {
                marks.push(Mark {
                    lane,
                    ns: finding.first_ns,
                    kind: MarkKind::Finding(finding.tier),
                    label: format!("{} {}", finding.rule, finding.object),
                });
            }
        }
        out.start_ns = procs.iter().filter_map(|p| p.first_ns).min().unwrap_or(0);
        out.end_ns = marks
            .iter()
            .map(|m| m.ns)
            .chain(links.iter().map(|l| l.ns))
            .max()
            .unwrap_or(out.start_ns)
            .max(out.start_ns + 1);
        // A capture time is an estimate and may fall just before the first task.
        for mark in &mut marks {
            mark.ns = mark.ns.max(out.start_ns);
        }
        marks.sort_by_key(|m| (m.ns, m.lane));
        out.marks = marks;
        out.links = links;
        out
    }

    /// Where `ns` falls from 0 (the start) to 1 (the end).
    pub(in crate::triage) fn fraction(&self, ns: u64) -> f32 {
        let span = self.end_ns.saturating_sub(self.start_ns).max(1);
        (ns.saturating_sub(self.start_ns) as f64 / span as f64) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::tests::fixture;
    use super::*;

    #[test]
    fn one_lane_per_process_with_markers_and_links() {
        let tl = Timeline::build(&fixture(), LANES);
        assert_eq!(tl.lanes.len(), 4);
        assert_eq!(tl.lanes[0].label, "demo-all (401)", "the root leads");
        assert!(tl.lanes[0].warn);
        let kinds = |kind: fn(&MarkKind) -> bool| tl.marks.iter().filter(|m| kind(&m.kind)).count();
        assert_eq!(kinds(|k| *k == MarkKind::Fork), 3, "one per child");
        assert_eq!(kinds(|k| *k == MarkKind::Exec), 1);
        assert_eq!(kinds(|k| *k == MarkKind::FileWrite), 1);
        assert_eq!(kinds(|k| *k == MarkKind::Connect), 1);
        assert_eq!(
            kinds(|k| matches!(k, MarkKind::Finding(_))),
            2,
            "INFO is no marker"
        );
        // sh is a fork, the dropped binary an exec; curl is sh's fork-less child.
        let exec_links = tl.links.iter().filter(|l| l.exec).count();
        assert_eq!(tl.links.len(), 3);
        assert_eq!(exec_links, 2);
        assert!(tl.marks.windows(2).all(|w| w[0].ns <= w[1].ns), "by time");
    }

    #[test]
    fn the_busiest_processes_get_the_lanes_and_the_root_always_does() {
        let tl = Timeline::build(&fixture(), 2);
        assert_eq!(tl.lanes.len(), 2);
        assert_eq!(tl.lanes[0].key, (401, 1));
        assert_eq!(
            tl.lanes[1].key,
            (420, 4),
            "the finding and the file are sh's"
        );
        // A mark of a process without a lane is dropped.
        assert!(tl.marks.iter().all(|m| m.lane < 2));
        assert!(tl.links.iter().all(|l| l.from < 2 && l.to < 2));
    }

    #[test]
    fn fractions_run_from_start_to_end() {
        let tl = Timeline::build(&fixture(), LANES);
        assert_eq!(tl.fraction(tl.start_ns), 0.0);
        assert!((tl.fraction(tl.end_ns) - 1.0).abs() < 1e-6);
        assert_eq!(Timeline::default().fraction(0), 0.0);
    }
}
