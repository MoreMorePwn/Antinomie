// SPDX-License-Identifier: GPL-3.0-only
//! What the Relationships graph draws: the raw graph with repeats grouped.
//! Children of one parent that ran the same image, and have no finding of
//! their own, become one node ("ps ×120"); the files one process wrote into
//! one folder become one node ("/tmp/x/ · 1,240 files written"). A node with
//! a finding is never grouped. A group is open or shut; an open group stays
//! as a node with its members beside it, so a click can shut it again.
use super::fold::{Fold, Folded};
use super::layout::Layout;
use super::model::{Edge, EdgeKind, Graph, GroupInfo, GroupWhat, Node, NodeKind};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// Siblings that ran one image are grouped from this many.
pub(super) const PROCESS_GROUP_MIN: usize = 3;
/// Files one process wrote into one folder are grouped from this many.
pub(super) const FILE_GROUP_MIN: usize = 3;
/// The Full view draws about this many nodes, however much is open.
pub(in crate::triage) const FULL_CAP: usize = 800;
/// Members listed in a group's tooltip.
const SAMPLE: usize = 8;

const NONE: u32 = u32::MAX;

/// Which groups start open.
#[derive(Clone, Copy, Debug)]
pub(in crate::triage) struct Policy {
    /// Open every group while the view stays within `budget` nodes.
    pub all: bool,
    pub budget: usize,
}

/// A graph as drawn, with its layout.
pub(in crate::triage) struct Rendered {
    pub graph: Arc<Graph>,
    pub shown: Vec<usize>,
    pub layout: Layout,
    /// Nodes of the raw graph.
    pub total: usize,
    /// Boxes standing for one node of the run or a shut group: the shown
    /// nodes but the headers of open groups.
    pub drawn: usize,
    /// Groups that are shut among the shown nodes.
    pub shut: usize,
    /// For the Full view, per node of `graph`: its arrow and the count of
    /// nodes it hides. Empty in Compact.
    pub folds: Vec<Fold>,
    /// More was open than the cap lets be drawn.
    pub capped: bool,
}

impl Rendered {
    /// The best `per_kind` of each kind, groups counted as nodes. `toggled`
    /// holds the groups the reader has opened.
    pub(in crate::triage) fn compact(
        raw: &Graph,
        toggled: &BTreeSet<String>,
        per_kind: usize,
    ) -> Self {
        let policy = Policy {
            all: false,
            budget: 0,
        };
        let graph = raw.view(toggled, policy);
        let shown = graph.compact(per_kind);
        Self::of(raw.nodes.len(), Arc::new(graph), shown)
    }

    /// The Full view: a tree of the nodes in `open` (see `fold`), with the
    /// repeat groups in `open` unstacked. At most about `FULL_CAP` nodes.
    pub(in crate::triage) fn full(raw: &Graph, open: &BTreeSet<String>) -> Self {
        let policy = Policy {
            all: false,
            budget: 0,
        };
        let graph = raw.view_with(open, policy, Some(raw.needed()));
        Self::folded(raw.nodes.len(), Arc::new(graph), open)
    }

    /// The Full view of the same groups with another open set: the grouped
    /// graph is kept, only what shows and where it sits is made again.
    pub(in crate::triage) fn refold(&self, open: &BTreeSet<String>) -> Self {
        Self::folded(self.total, self.graph.clone(), open)
    }

    fn folded(total: usize, graph: Arc<Graph>, open: &BTreeSet<String>) -> Self {
        let Folded {
            shown,
            folds,
            capped,
        } = graph.fold(open, FULL_CAP);
        let mut made = Self::of(total, graph, shown);
        made.folds = folds;
        made.capped = capped;
        made
    }

    fn of(total: usize, graph: Arc<Graph>, shown: Vec<usize>) -> Self {
        let layout = Layout::of(&graph, &shown);
        let shut = shown
            .iter()
            .filter(|&&at| matches!(&graph.nodes[at].kind, NodeKind::Group(info) if !info.open))
            .count();
        let open = shown
            .iter()
            .filter(|&&at| matches!(&graph.nodes[at].kind, NodeKind::Group(info) if info.open))
            .count();
        Self {
            drawn: shown.len() - open,
            total,
            graph,
            shown,
            layout,
            shut,
            folds: Vec::new(),
            capped: false,
        }
    }
}

fn directory(path: &str) -> &str {
    match path.rfind('/') {
        Some(at) => &path[..=at],
        None => "",
    }
}

struct Builder<'a> {
    raw: &'a Graph,
    toggled: &'a BTreeSet<String>,
    policy: Policy,
    out: Graph,
    rep: Vec<u32>,
    owned: Vec<bool>,
    edges: BTreeMap<(usize, usize, EdgeKind), u32>,
    queue: VecDeque<(usize, Vec<usize>)>,
    /// For the Full view: `toggled` is the set of open groups, and the
    /// processes marked here (with a finding, or on the way to one) are never
    /// grouped, so a finding is never inside a stack.
    keep: Option<Vec<bool>>,
}

impl Builder<'_> {
    fn emit(&mut self, raw: usize) -> usize {
        let at = self.out.nodes.len();
        self.out.nodes.push(self.raw.nodes[raw].clone());
        self.rep[raw] = at as u32;
        at
    }

    fn link(&mut self, from: usize, to: usize, kind: EdgeKind, count: u32) {
        if from != to {
            *self.edges.entry((from, to, kind)).or_default() += count;
        }
    }

    /// Whether the group `id` of `members` is open: the policy's choice,
    /// flipped by the reader.
    fn open(&self, id: &str, members: usize) -> bool {
        if self.keep.is_some() && !self.policy.all {
            return self.toggled.contains(id);
        }
        let by_policy = self.policy.all && self.out.nodes.len() + members <= self.policy.budget;
        by_policy != self.toggled.contains(id)
    }

    fn group(
        &mut self,
        id: String,
        what: GroupWhat,
        label: String,
        members: &[usize],
        open: bool,
    ) -> usize {
        let sample = members
            .iter()
            .take(SAMPLE)
            .map(|&at| self.raw.nodes[at].label.clone())
            .collect();
        self.out.nodes.push(Node {
            kind: NodeKind::Group(GroupInfo {
                id,
                what,
                members: members.len() as u32,
                open,
                sample,
            }),
            label,
            tier: None,
            warn: false,
            findings: 0,
            image: String::new(),
        });
        self.out.nodes.len() - 1
    }

    /// A process or file with nothing of its own to say.
    fn plain(&self, at: usize) -> bool {
        let node = &self.raw.nodes[at];
        node.tier.is_none() && node.findings == 0 && !node.warn
    }

    fn children(&mut self, at: usize, members: &[usize]) {
        let raw = self.raw;
        let mut kids: Vec<(usize, usize)> = Vec::new();
        for &m in members {
            for &e in &raw.out[m] {
                let edge = &raw.edges[e as usize];
                if matches!(edge.kind, EdgeKind::Forked | EdgeKind::Execed)
                    && matches!(raw.nodes[edge.to].kind, NodeKind::Process(_))
                {
                    self.owned[e as usize] = true;
                    kids.push((edge.to, e as usize));
                }
            }
        }
        kids.sort_unstable();
        // Items in the order they first appear: a node, or an image's bucket.
        enum Item {
            One(usize, usize),
            Many(String, Vec<(usize, usize)>),
        }
        let mut items: Vec<Item> = Vec::new();
        let mut bucket: BTreeMap<&str, usize> = BTreeMap::new();
        for &(kid, e) in &kids {
            let groupable = self.plain(kid)
                && !self.keep.as_ref().is_some_and(|keep| keep[kid])
                && !raw
                    .edges_in(kid)
                    .any(|edge| matches!(edge.kind, EdgeKind::Injected | EdgeKind::Signalled));
            if !groupable {
                items.push(Item::One(kid, e));
                continue;
            }
            let image = raw.nodes[kid].image.as_str();
            match bucket.get(image) {
                Some(&slot) => {
                    if let Item::Many(_, list) = &mut items[slot] {
                        list.push((kid, e));
                    }
                }
                None => {
                    bucket.insert(image, items.len());
                    items.push(Item::Many(image.to_owned(), vec![(kid, e)]));
                }
            }
        }
        let parent_id = self.out.nodes[at].kind.id();
        for item in items {
            match item {
                Item::One(kid, e) => self.one(at, kid, e),
                Item::Many(_, list) if list.len() < PROCESS_GROUP_MIN => {
                    for (kid, e) in list {
                        self.one(at, kid, e);
                    }
                }
                Item::Many(image, list) => {
                    let id = format!("pg:{parent_id}:{image}");
                    let raws: Vec<usize> = list.iter().map(|&(kid, _)| kid).collect();
                    let open = self.open(&id, raws.len());
                    let name = crate::triage::process_cells::file_name(&image);
                    let label = format!(
                        "{} \u{d7}{}",
                        if name.is_empty() { "unknown" } else { name },
                        crate::values::thousands(raws.len() as u64)
                    );
                    let group = self.group(id, GroupWhat::Processes, label, &raws, open);
                    let kind = raw.edges[list[0].1].kind;
                    self.link(at, group, kind, raws.len() as u32);
                    if open {
                        for &kid in &raws {
                            let member = self.emit(kid);
                            self.link(group, member, EdgeKind::Member, 1);
                            self.queue.push_back((member, vec![kid]));
                        }
                    } else {
                        for &kid in &raws {
                            self.rep[kid] = group as u32;
                        }
                        self.queue.push_back((group, raws));
                    }
                }
            }
        }
    }

    fn one(&mut self, at: usize, kid: usize, e: usize) {
        let edge = &self.raw.edges[e];
        let (kind, count) = (edge.kind, edge.count);
        let node = self.emit(kid);
        self.link(at, node, kind, count);
        self.queue.push_back((node, vec![kid]));
    }

    /// The files, endpoints and processes beside the node `at`.
    fn beside(&mut self, at: usize, members: &[usize], round: &mut [u32], stamp: u32) {
        let raw = self.raw;
        for &m in members {
            round[m] = stamp;
        }
        // (folder, file, edge) of the files only these members wrote.
        let mut written: Vec<(&str, usize, usize)> = Vec::new();
        let mut others: Vec<usize> = Vec::new();
        for &m in members {
            for &e in &raw.out[m] {
                let edge = &raw.edges[e as usize];
                let to = edge.to;
                match &raw.nodes[to].kind {
                    NodeKind::File(path) => {
                        let only_these = edge.kind == EdgeKind::Wrote
                            && self.plain(to)
                            && raw.edges_in(to).all(|edge| {
                                edge.kind == EdgeKind::Wrote && round[edge.from] == stamp
                            });
                        if only_these {
                            written.push((directory(path), to, e as usize));
                        } else {
                            others.push(to);
                        }
                    }
                    NodeKind::Endpoint(_) | NodeKind::Victim(_) => others.push(to),
                    NodeKind::Process(_) | NodeKind::Group(_) => {}
                }
            }
        }
        written.sort_unstable();
        let mut folders: BTreeMap<&str, Vec<(usize, usize)>> = BTreeMap::new();
        for (folder, file, e) in written {
            folders.entry(folder).or_default().push((file, e));
        }
        let parent_id = self.out.nodes[at].kind.id();
        for (folder, list) in folders {
            if list.len() < FILE_GROUP_MIN {
                others.extend(list.iter().map(|&(file, _)| file));
                continue;
            }
            let mut files: Vec<usize> = list.iter().map(|&(file, _)| file).collect();
            files.dedup();
            if files.len() < FILE_GROUP_MIN {
                others.extend(files);
                continue;
            }
            let id = format!("fg:{parent_id}:{folder}");
            let open = self.open(&id, files.len());
            let label = format!(
                "{} \u{b7} {} files written",
                if folder.is_empty() { "/" } else { folder },
                crate::values::thousands(files.len() as u64)
            );
            let group = self.group(id, GroupWhat::Files, label, &files, open);
            let mut count = 0;
            for &(_, e) in &list {
                self.owned[e] = true;
                count += raw.edges[e].count;
            }
            self.link(at, group, EdgeKind::Wrote, count);
            for &file in &files {
                if open {
                    let member = self.emit(file);
                    self.link(group, member, EdgeKind::Member, 1);
                } else {
                    self.rep[file] = group as u32;
                }
            }
        }
        others.sort_unstable();
        others.dedup();
        for to in others {
            if self.rep[to] == NONE {
                self.emit(to);
            }
        }
    }
}

impl Graph {
    /// The graph as drawn: repeats grouped, shut unless `toggled` or `policy`
    /// opens them. The nodes come in breadth-first order from the roots, so
    /// the first `n` of them are joined to each other. `self` is a raw graph.
    pub(in crate::triage) fn view(&self, toggled: &BTreeSet<String>, policy: Policy) -> Graph {
        self.view_with(toggled, policy, None)
    }

    /// `view`, or with `keep` the Full view's: `toggled` the open groups.
    pub(super) fn view_with(
        &self,
        toggled: &BTreeSet<String>,
        policy: Policy,
        keep: Option<Vec<bool>>,
    ) -> Graph {
        let n = self.nodes.len();
        let mut b = Builder {
            raw: self,
            toggled,
            policy,
            out: Graph::default(),
            rep: vec![NONE; n],
            owned: vec![false; self.edges.len()],
            edges: BTreeMap::new(),
            queue: VecDeque::new(),
            keep,
        };
        let roots: Vec<usize> = (0..n)
            .filter(|&at| {
                matches!(self.nodes[at].kind, NodeKind::Process(_))
                    && !self
                        .edges_in(at)
                        .any(|edge| matches!(edge.kind, EdgeKind::Forked | EdgeKind::Execed))
            })
            .collect();
        for root in roots {
            let at = b.emit(root);
            b.queue.push_back((at, vec![root]));
        }
        let mut stamps = vec![0u32; n];
        let mut stamp = 0;
        while let Some((at, members)) = b.queue.pop_front() {
            stamp += 1;
            b.children(at, &members);
            b.beside(at, &members, &mut stamps, stamp);
        }
        for node in 0..n {
            if b.rep[node] == NONE {
                b.emit(node);
            }
        }
        for (at, edge) in self.edges.iter().enumerate() {
            if b.owned[at] {
                continue;
            }
            let (from, to) = (b.rep[edge.from], b.rep[edge.to]);
            if from != NONE && to != NONE {
                b.link(from as usize, to as usize, edge.kind, edge.count);
            }
        }
        let mut out = b.out;
        out.edges = b
            .edges
            .into_iter()
            .map(|((from, to, kind), count)| Edge {
                from,
                to,
                kind,
                count,
            })
            .collect();
        out.index();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{
        tests::{fixture, synthetic},
        Fact, FileFact, Proc,
    };
    use super::*;
    use crate::triage::rules::Tier;

    fn child(pid: u32, name: &str) -> Proc {
        Proc {
            pid,
            cookie: u64::from(pid),
            parent: Some((401, 1)),
            name: name.into(),
            ..Proc::default()
        }
    }

    fn shut() -> Policy {
        Policy {
            all: false,
            budget: 0,
        }
    }

    fn labels(graph: &Graph) -> Vec<String> {
        graph.nodes.iter().map(|n| n.label.clone()).collect()
    }

    fn group_id(graph: &Graph, label: &str) -> String {
        graph
            .nodes
            .iter()
            .find_map(|n| match &n.kind {
                NodeKind::Group(info) if n.label == label => Some(info.id.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{label} in {:?}", labels(graph)))
    }

    #[test]
    fn siblings_that_ran_one_image_are_one_node_and_a_finding_keeps_one_apart() {
        let mut facts = fixture();
        for n in 0..6 {
            facts.procs.push(child(1000 + n, "ps"));
        }
        // Two that are alone with their image stay nodes.
        facts.procs.push(child(2000, "id"));
        facts.procs.push(child(2001, "id"));
        let raw = Graph::build(&facts);
        let none = BTreeSet::new();
        let view = raw.view(&none, shut());
        assert!(
            labels(&view).contains(&"ps \u{d7}6".to_owned()),
            "{:?}",
            labels(&view)
        );
        assert!(labels(&view).contains(&"id (2000)".to_owned()));
        assert!(labels(&view).contains(&"id (2001)".to_owned()));
        assert!(!labels(&view).iter().any(|l| l.starts_with("ps (")));
        // The group is joined to the root by one edge that counts the six.
        let root = view
            .nodes
            .iter()
            .position(|n| n.kind == NodeKind::Process((401, 1)))
            .unwrap();
        let group = view
            .nodes
            .iter()
            .position(|n| n.label == "ps \u{d7}6")
            .unwrap();
        let edge = view
            .edges
            .iter()
            .find(|e| e.from == root && e.to == group)
            .unwrap();
        assert_eq!(edge.count, 6);
        // A finding of one of them keeps it apart; the other five group.
        facts.findings.push(Fact {
            tier: Tier::Medium,
            rule: "execution.temp_exec".into(),
            object: "/tmp/y".into(),
            pid: 1003,
            cookie: 1003,
        });
        let view = Graph::build(&facts).view(&none, shut());
        assert!(
            labels(&view).contains(&"ps (1003)".to_owned()),
            "{:?}",
            labels(&view)
        );
        assert!(
            labels(&view).contains(&"ps \u{d7}5".to_owned()),
            "{:?}",
            labels(&view)
        );
        // Two siblings are not enough to group.
        let mut few = fixture();
        few.procs.push(child(1000, "ps"));
        few.procs.push(child(1001, "ps"));
        let view = Graph::build(&few).view(&none, shut());
        assert_eq!(view.nodes.len(), Graph::build(&few).nodes.len());
    }

    #[test]
    fn a_group_opens_and_shuts_and_keeps_its_members_reachable() {
        let mut facts = fixture();
        for n in 0..6 {
            facts.procs.push(child(1000 + n, "ps"));
        }
        let raw = Graph::build(&facts);
        let mut toggled = BTreeSet::new();
        let shut_view = raw.view(&toggled, shut());
        let id = group_id(&shut_view, "ps \u{d7}6");
        toggled.insert(id.clone());
        let open = raw.view(&toggled, shut());
        let members: Vec<_> = open
            .nodes
            .iter()
            .filter(|n| n.label.starts_with("ps ("))
            .collect();
        assert_eq!(members.len(), 6, "{:?}", labels(&open));
        let header = open
            .nodes
            .iter()
            .position(|n| n.label == "ps \u{d7}6")
            .unwrap();
        assert!(matches!(&open.nodes[header].kind, NodeKind::Group(info) if info.open));
        assert_eq!(
            open.edges_out(header)
                .filter(|e| e.kind == EdgeKind::Member)
                .count(),
            6
        );
        assert_eq!(open.nodes.len(), shut_view.nodes.len() + 6);
        // Toggling it again shuts it.
        toggled.remove(&id);
        assert_eq!(
            raw.view(&toggled, shut()).nodes.len(),
            shut_view.nodes.len()
        );
        // Full opens every group, within the budget.
        let all = raw.view(
            &BTreeSet::new(),
            Policy {
                all: true,
                budget: 100,
            },
        );
        assert_eq!(all.nodes.len(), shut_view.nodes.len() + 6);
        let tight = raw.view(
            &BTreeSet::new(),
            Policy {
                all: true,
                budget: 3,
            },
        );
        assert_eq!(tight.nodes.len(), shut_view.nodes.len(), "no room: shut");
        // Flipping an open-by-policy group shuts it.
        let flipped = raw.view(
            &BTreeSet::from([id]),
            Policy {
                all: true,
                budget: 100,
            },
        );
        assert_eq!(flipped.nodes.len(), shut_view.nodes.len());
    }

    #[test]
    fn files_are_one_node_per_folder_per_writer_and_a_finding_keeps_a_file_apart() {
        let mut facts = fixture();
        let write = |path: String| FileFact {
            path,
            roles: vec!["created".into()],
            process: Some((420, 4)),
        };
        for n in 0..5 {
            facts.files.push(write(format!("/tmp/x/f{n}")));
        }
        facts.files.push(write("/var/lib/one".into()));
        facts.files.push(write("/var/lib/two".into()));
        let raw = Graph::build(&facts);
        let view = raw.view(&BTreeSet::new(), shut());
        assert!(
            labels(&view).contains(&"/tmp/x/ \u{b7} 5 files written".to_owned()),
            "{:?}",
            labels(&view)
        );
        // Two files in a folder stay files.
        assert!(labels(&view).contains(&"one".to_owned()));
        assert!(labels(&view).contains(&"two".to_owned()));
        // A file with a finding is a node of its own.
        facts.findings.push(Fact {
            tier: Tier::High,
            rule: "execution.temp_exec".into(),
            object: "/tmp/x/f2".into(),
            pid: 420,
            cookie: 4,
        });
        let view = Graph::build(&facts).view(&BTreeSet::new(), shut());
        assert!(
            labels(&view).contains(&"f2".to_owned()),
            "{:?}",
            labels(&view)
        );
        assert!(
            labels(&view).contains(&"/tmp/x/ \u{b7} 4 files written".to_owned()),
            "{:?}",
            labels(&view)
        );
        // The file group hangs off its writer by a write edge, and opens.
        let id = group_id(&view, "/tmp/x/ \u{b7} 4 files written");
        let open = Graph::build(&facts).view(&BTreeSet::from([id]), shut());
        assert_eq!(
            open.nodes
                .iter()
                .filter(|n| n.label.starts_with('f'))
                .count(),
            5,
            "the four and the one with a finding"
        );
    }

    #[test]
    fn a_shut_group_passes_what_its_members_did_to_the_group() {
        // Fifty `sh`, each with a `ps` child: sh ×50 holds ps ×50.
        let mut facts = fixture();
        for n in 0..50u32 {
            facts.procs.push(child(1000 + n, "sh"));
            facts.procs.push(Proc {
                parent: Some((1000 + n, u64::from(1000 + n))),
                ..child(5000 + n, "ps")
            });
        }
        let view = Graph::build(&facts).view(&BTreeSet::new(), shut());
        let labels = labels(&view);
        assert!(labels.contains(&"sh \u{d7}50".to_owned()), "{labels:?}");
        assert!(labels.contains(&"ps \u{d7}50".to_owned()), "{labels:?}");
        assert!(view.nodes.len() < 15, "{labels:?}");
    }

    #[test]
    fn a_big_run_collapses_and_every_node_is_joined_to_the_root() {
        let facts = synthetic(1500, 5000);
        let raw = Graph::build(&facts);
        let view = raw.view(&BTreeSet::new(), shut());
        assert!(
            view.nodes.len() * 4 < raw.nodes.len(),
            "{}",
            view.nodes.len()
        );
        // Breadth first: every node but the roots has an edge from an earlier one.
        for at in 1..view.nodes.len() {
            assert!(
                view.edges_in(at).any(|e| e.from < at),
                "{} floats",
                view.nodes[at].label
            );
        }
        let full = Rendered::full(&raw, &raw.expanded(FULL_CAP));
        assert!(full.layout.len() <= FULL_CAP + 8, "{}", full.layout.len());
        assert!(full.layout.len() > FULL_CAP / 2);
        // The nodes with findings are among them.
        let tiered = full
            .shown
            .iter()
            .filter(|&&at| full.graph.nodes[at].tier.is_some())
            .count();
        assert!(tiered >= 10, "{tiered}");
    }
}
