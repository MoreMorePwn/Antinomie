// SPDX-License-Identifier: GPL-3.0-only
//! The Full view as a tree you open. Each node that has something under it
//! (what it started, wrote or contacted) can be open or closed; a closed
//! node hides everything under it and says how many nodes that is. The open
//! set is a set of node ids, kept for the run; it starts as the root, the
//! path from the root to every node with a finding, and those nodes
//! themselves (so their children show).
use super::layout::tree_parent;
use super::model::{Graph, NodeKind};
use std::collections::BTreeSet;

const NONE: u32 = u32::MAX;

/// What a box shows about its place in the tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::triage) struct Fold {
    /// Something hangs under it: it gets the open/close arrow.
    pub has_kids: bool,
    pub open: bool,
    /// Nodes under it that are not drawn.
    pub hidden: u32,
}

/// The ids of repeat groups (see `group`); a click on one opens its members.
pub(in crate::triage) fn is_group(id: &str) -> bool {
    id.starts_with("pg:") || id.starts_with("fg:")
}

/// The nodes `open` and `before` differ in include a repeat group.
pub(in crate::triage) fn groups_differ(open: &BTreeSet<String>, before: &BTreeSet<String>) -> bool {
    open.symmetric_difference(before).any(|id| is_group(id))
}

/// What the Full view shows of a view graph.
pub(super) struct Folded {
    pub shown: Vec<usize>,
    pub folds: Vec<Fold>,
    /// More was open than the cap lets be drawn.
    pub capped: bool,
}

impl Graph {
    /// Of the raw graph: the nodes that must not be hidden: those with a
    /// finding and the chain of anchors that joins each to the root.
    pub(super) fn needed(&self) -> Vec<bool> {
        let mut chosen = BTreeSet::new();
        if !self.nodes.is_empty() {
            chosen.insert(self.root());
        }
        for at in 0..self.nodes.len() {
            if self.nodes[at].tier.is_some() || self.nodes[at].findings > 0 {
                self.add_chain(at, &mut chosen);
            }
        }
        let mut needed = vec![false; self.nodes.len()];
        for at in chosen {
            needed[at] = true;
        }
        needed
    }

    /// Of the raw graph: the open set a run starts with.
    pub(in crate::triage) fn default_open(&self) -> BTreeSet<String> {
        self.needed()
            .iter()
            .enumerate()
            .filter(|(_, needed)| **needed)
            .map(|(at, _)| self.nodes[at].kind.id())
            .collect()
    }

    /// Of the raw graph: an open set with everything open, as far as about
    /// `budget` nodes of groups can be.
    pub(in crate::triage) fn expanded(&self, budget: usize) -> BTreeSet<String> {
        let policy = super::group::Policy { all: true, budget };
        let view = self.view_with(&BTreeSet::new(), policy, Some(self.needed()));
        let (_, kids) = view.forest();
        (0..view.nodes.len())
            .filter(|&at| match &view.nodes[at].kind {
                NodeKind::Group(info) => info.open,
                _ => !kids[at].is_empty(),
            })
            .map(|at| view.nodes[at].kind.id())
            .collect()
    }

    /// Of a view graph: each node's parent in the tree and its children.
    fn forest(&self) -> (Vec<u32>, Vec<Vec<u32>>) {
        let n = self.nodes.len();
        let parent: Vec<u32> = (0..n)
            .map(|at| tree_parent(self, at, &|_| true).map_or(NONE, |from| from as u32))
            .collect();
        let mut kids: Vec<Vec<u32>> = vec![Vec::new(); n];
        for (at, &up) in parent.iter().enumerate() {
            if up != NONE {
                kids[up as usize].push(at as u32);
            }
        }
        (parent, kids)
    }

    /// Of a view graph: what shows when the nodes in `open` are open and the
    /// rest closed, at most about `cap` of it.
    pub(super) fn fold(&self, open: &BTreeSet<String>, cap: usize) -> Folded {
        let n = self.nodes.len();
        let (parent, kids) = self.forest();
        let is_open: Vec<bool> = self
            .nodes
            .iter()
            .map(|node| open.contains(&node.kind.id()))
            .collect();
        // Parents before their children.
        let mut order: Vec<u32> = Vec::with_capacity(n);
        let mut stack: Vec<u32> = (0..n as u32)
            .rev()
            .filter(|&at| parent[at as usize] == NONE)
            .collect();
        while let Some(at) = stack.pop() {
            order.push(at);
            stack.extend(kids[at as usize].iter().rev());
        }
        let mut visible = vec![false; n];
        for &at in &order {
            let up = parent[at as usize];
            visible[at as usize] = up == NONE || (visible[up as usize] && is_open[up as usize]);
        }
        let mut capped = false;
        if visible.iter().filter(|&&v| v).count() > cap {
            capped = true;
            // The nodes with a finding and the way to each, then the rest in
            // breadth-first order.
            let mut keep = vec![false; n];
            let mut count = 0;
            for at in (0..n).filter(|&at| visible[at] && self.nodes[at].tier.is_some()) {
                if count >= cap / 4 {
                    break;
                }
                let mut next = at;
                while visible[next] && !keep[next] {
                    keep[next] = true;
                    count += 1;
                    match parent[next] {
                        NONE => break,
                        up => next = up as usize,
                    }
                }
            }
            for at in 0..n {
                if count >= cap {
                    break;
                }
                // Only nodes whose parent is kept, so the view stays joined.
                let joined = parent[at] == NONE || keep[parent[at] as usize];
                if visible[at] && !keep[at] && joined {
                    keep[at] = true;
                    count += 1;
                }
            }
            visible = keep;
        }
        // Bottom up: nodes under each, and how many of them are drawn.
        let mut under = vec![1u32; n];
        let mut drawn: Vec<u32> = visible.iter().map(|&v| u32::from(v)).collect();
        for &at in order.iter().rev() {
            let up = parent[at as usize];
            if up != NONE {
                under[up as usize] += under[at as usize];
                drawn[up as usize] += drawn[at as usize];
            }
        }
        let folds = (0..n)
            .map(|at| {
                let mut fold = Fold {
                    has_kids: !kids[at].is_empty(),
                    open: is_open[at],
                    hidden: if visible[at] {
                        under[at] - drawn[at]
                    } else {
                        0
                    },
                };
                if let NodeKind::Group(info) = &self.nodes[at].kind {
                    // A group opens to show its members.
                    fold.has_kids = true;
                    fold.open = info.open;
                    if !info.open {
                        fold.hidden += info.members;
                    }
                }
                fold
            })
            .collect();
        Folded {
            shown: (0..n).filter(|&at| visible[at]).collect(),
            folds,
            capped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::group::{Rendered, FULL_CAP};
    use super::super::model::{
        tests::{fixture, synthetic},
        Facts, Proc,
    };
    use super::*;

    fn proc(pid: u32, parent: Option<u32>, name: &str) -> Proc {
        Proc {
            pid,
            cookie: u64::from(pid),
            parent: parent.map(|p| (p, u64::from(p))),
            name: name.into(),
            ..Proc::default()
        }
    }

    /// A chain root > a > b > c, and a leaf `z` beside `a`.
    fn chain() -> Facts {
        let mut facts = Facts::default();
        facts.procs.push(proc(1, None, "root"));
        facts.procs.push(proc(2, Some(1), "a"));
        facts.procs.push(proc(3, Some(2), "b"));
        facts.procs.push(proc(4, Some(3), "c"));
        facts.procs.push(proc(5, Some(1), "z"));
        facts
    }

    fn id(pid: u32) -> String {
        NodeKind::Process((pid, u64::from(pid))).id()
    }

    fn labels(made: &Rendered) -> Vec<String> {
        made.shown
            .iter()
            .map(|&at| made.graph.nodes[at].label.clone())
            .collect()
    }

    fn at(made: &Rendered, pid: u32) -> usize {
        made.graph
            .nodes
            .iter()
            .position(|n| n.kind == NodeKind::Process((pid, u64::from(pid))))
            .unwrap()
    }

    #[test]
    fn a_run_starts_with_the_root_the_paths_to_findings_and_their_children_open() {
        let raw = Graph::build(&synthetic(300, 0));
        let open = raw.default_open();
        assert!(open.contains(&id(1)), "the root");
        let tiered: Vec<usize> = (0..raw.nodes.len())
            .filter(|&n| raw.nodes[n].tier.is_some())
            .collect();
        assert!(tiered.len() >= 3);
        for &node in &tiered {
            // The node itself and every anchor up to the root is open.
            let mut next = Some(node);
            while let Some(at) = next {
                assert!(
                    open.contains(&raw.nodes[at].kind.id()),
                    "{}",
                    raw.nodes[at].label
                );
                next = raw.anchor(at);
            }
        }
        // Everything else is closed: far fewer than the nodes.
        assert!(
            open.len() < raw.nodes.len() / 3,
            "{} of {}",
            open.len(),
            raw.nodes.len()
        );
        let made = Rendered::full(&raw, &open);
        for &node in &tiered {
            let wanted = &raw.nodes[node].label;
            assert!(labels(&made).contains(wanted), "{wanted} is shown");
        }
        assert!(
            made.drawn < raw.nodes.len() / 2,
            "{} of {}",
            made.drawn,
            raw.nodes.len()
        );
    }

    #[test]
    fn opening_a_node_shows_one_level_and_the_count_of_what_stays_hidden() {
        let raw = Graph::build(&chain());
        // Only the root is open: its children show, closed.
        let mut open = raw.default_open();
        assert_eq!(open, BTreeSet::from([id(1)]));
        let made = Rendered::full(&raw, &open);
        let mut shown = labels(&made);
        shown.sort();
        assert_eq!(shown, ["a (2)", "root (1)", "z (5)"]);
        let (root, a, z) = (at(&made, 1), at(&made, 2), at(&made, 5));
        assert!(made.folds[root].open && made.folds[root].has_kids);
        assert_eq!(made.folds[root].hidden, 2, "b and c are under a");
        assert!(!made.folds[a].open && made.folds[a].has_kids);
        assert_eq!(made.folds[a].hidden, 2, "+2: b and c");
        assert!(!made.folds[z].has_kids && made.folds[z].hidden == 0);
        // Opening a shows b only, not c.
        open.insert(id(2));
        let made = Rendered::full(&raw, &open);
        let mut shown = labels(&made);
        shown.sort();
        assert_eq!(shown, ["a (2)", "b (3)", "root (1)", "z (5)"]);
        assert_eq!(made.folds[at(&made, 3)].hidden, 1, "+1: c");
        assert_eq!(made.folds[at(&made, 2)].hidden, 1);
        // Opening a node again closes it, with what was under it.
        open.remove(&id(2));
        assert_eq!(Rendered::full(&raw, &open).shown.len(), 3);
        // Only the arrows moved: the grouped graph is kept.
        let again = made.refold(&open);
        assert!(std::sync::Arc::ptr_eq(&again.graph, &made.graph));
        assert_eq!(again.shown.len(), 3);
        assert_ne!(again.layout.generation, made.layout.generation);
    }

    #[test]
    fn expand_all_opens_everything_up_to_the_cap_and_collapse_all_goes_back() {
        let raw = Graph::build(&chain());
        let all = raw.expanded(FULL_CAP);
        let made = Rendered::full(&raw, &all);
        assert_eq!(made.shown.len(), raw.nodes.len());
        assert!(!made.capped);
        assert!(made.shown.iter().all(|&n| made.folds[n].hidden == 0));
        assert_ne!(all, raw.default_open());
        // A run of 1,500 processes is drawn at about 800 and says so.
        let big = Graph::build(&synthetic(1500, 5000));
        let made = Rendered::full(&big, &big.expanded(FULL_CAP));
        assert!(made.capped);
        assert!(made.shown.len() <= FULL_CAP + 8, "{}", made.shown.len());
        assert!(made.shown.len() > FULL_CAP / 2);
        let tiered = made
            .shown
            .iter()
            .filter(|&&n| made.graph.nodes[n].tier.is_some())
            .count();
        assert!(tiered >= 10, "{tiered}");
        // The default again is a handful.
        let back = Rendered::full(&big, &big.default_open());
        assert!(back.shown.len() < 200, "{}", back.shown.len());
        assert!(!back.capped);
    }

    #[test]
    fn a_repeat_group_on_the_way_to_a_finding_is_not_stacked_and_others_are() {
        use super::super::model::Fact;
        let mut facts = fixture();
        for n in 0..6u32 {
            facts.procs.push(Proc {
                pid: 1000 + n,
                cookie: u64::from(1000 + n),
                parent: Some((401, 1)),
                name: "sh".into(),
                ..Proc::default()
            });
        }
        // A child of one `sh` has the finding.
        facts.procs.push(Proc {
            pid: 2000,
            cookie: 2000,
            parent: Some((1003, 1003)),
            name: "implant".into(),
            ..Proc::default()
        });
        facts.findings.push(Fact {
            tier: crate::triage::rules::Tier::High,
            rule: "execution.temp_exec".into(),
            object: "/tmp/i".into(),
            pid: 2000,
            cookie: 2000,
        });
        let raw = Graph::build(&facts);
        let made = Rendered::full(&raw, &raw.default_open());
        let labels = labels(&made);
        assert!(labels.contains(&"implant (2000)".to_owned()), "{labels:?}");
        assert!(labels.contains(&"sh (1003)".to_owned()), "{labels:?}");
        assert!(labels.contains(&"sh \u{d7}5".to_owned()), "{labels:?}");
    }

    #[test]
    fn opening_a_node_in_a_run_of_ten_thousand_is_made_in_a_frame() {
        let raw = Graph::build(&synthetic(2000, 8000));
        let mut open = raw.default_open();
        let made = Rendered::full(&raw, &open);
        let node = made
            .shown
            .iter()
            .copied()
            .find(|&n| made.folds[n].has_kids && !made.folds[n].open)
            .expect("something to open");
        open.insert(made.graph.nodes[node].kind.id());
        let best = (0..5)
            .map(|_| {
                let started = std::time::Instant::now();
                let next = made.refold(&open);
                assert!(next.shown.len() > made.shown.len());
                started.elapsed()
            })
            .min()
            .unwrap();
        assert!(best.as_millis() < 16, "{best:?}");
    }
}
