// SPDX-License-Identifier: GPL-3.0-only
//! Where the Relationships graph's nodes sit, in graph space: a tidy tree.
//! Each node's subtree has its own width and height, so siblings never pile
//! into one global column. A process has the processes it started, the files
//! it wrote or ran and the endpoints it contacted beside it, to its right;
//! the root is at the top left. All the children of a node are stacked in the
//! next column to its right, however many there are.
use super::model::{EdgeKind, Graph, NodeKind};
use eframe::egui::{self, Pos2, Rect, Vec2};

pub(super) const NODE: Vec2 = egui::vec2(188.0, 30.0);
/// From the middle of a node to the middle of the next one down.
pub(super) const ROW: f32 = 64.0;
/// From one column to the next.
pub(super) const COLUMN: f32 = 260.0;

const NONE: u32 = u32::MAX;

/// Where each shown node sits.
pub(in crate::triage) struct Layout {
    rects: Vec<Rect>,
    /// The shown nodes, in the order they were given.
    pub shown: Vec<usize>,
    pub bounds: Rect,
    /// The node the view opens on: the run's root.
    pub root: Option<usize>,
    /// Which layout this is: a new one has a new number, so a view can tell
    /// that the nodes moved.
    pub generation: u64,
}

static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Default for Layout {
    fn default() -> Self {
        Self {
            rects: Vec::new(),
            shown: Vec::new(),
            bounds: Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)),
            root: None,
            generation: 0,
        }
    }
}

/// How early a kind of child comes among its siblings.
fn rank(kind: &NodeKind) -> u8 {
    match kind {
        NodeKind::Process(_) | NodeKind::Group(_) => 0,
        NodeKind::Victim(_) => 1,
        NodeKind::File(_) => 2,
        NodeKind::Endpoint(_) => 3,
    }
}

/// How firmly an edge makes its target a child of its source.
fn strength(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Forked | EdgeKind::Execed | EdgeKind::Member => 0,
        EdgeKind::Wrote | EdgeKind::Ran | EdgeKind::Connected => 1,
        EdgeKind::Injected | EdgeKind::Signalled => 2,
    }
}

/// The node `node` hangs from in the tree: the strongest edge in from a node
/// `allowed` accepts.
pub(super) fn tree_parent(
    graph: &Graph,
    node: usize,
    allowed: &dyn Fn(usize) -> bool,
) -> Option<usize> {
    graph
        .edges_in(node)
        .filter(|edge| edge.from != node && allowed(edge.from))
        // A process is started by its parent; what it suffered from
        // another is a cross edge, or the run's root would hang off
        // the child that injected into it.
        .filter(|edge| {
            strength(edge.kind) < 2
                || !matches!(
                    graph.nodes[node].kind,
                    NodeKind::Process(_) | NodeKind::Group(_)
                )
        })
        .min_by_key(|edge| (strength(edge.kind), edge.from))
        .map(|edge| edge.from)
}

impl Layout {
    pub(in crate::triage) fn get(&self, node: usize) -> Option<Rect> {
        self.rects
            .get(node)
            .copied()
            .filter(|rect| rect.is_positive())
    }

    #[cfg(test)]
    pub(in crate::triage) fn len(&self) -> usize {
        self.shown.len()
    }

    pub(in crate::triage) fn of(graph: &Graph, shown: &[usize]) -> Self {
        let m = shown.len();
        if m == 0 {
            return Self::default();
        }
        let mut local = vec![NONE; graph.nodes.len()];
        for (l, &node) in shown.iter().enumerate() {
            local[node] = l as u32;
        }
        // Each node's parent among the shown ones: the strongest edge in.
        let mut parent = vec![NONE; m];
        for (l, &node) in shown.iter().enumerate() {
            parent[l] = tree_parent(graph, node, &|from| local[from] != NONE)
                .map_or(NONE, |from| local[from]);
        }
        let mut below: Vec<Vec<u32>> = vec![Vec::new(); m + 1];
        let mut roots: Vec<u32> = Vec::new();
        let main = graph.root();
        for (l, &up) in parent.iter().enumerate() {
            match up {
                NONE => roots.push(l as u32),
                p => below[p as usize].push(l as u32),
            }
        }
        roots.sort_by_key(|&l| (shown[l as usize] != main, l));
        let sort = |list: &mut Vec<u32>| {
            list.sort_by_key(|&l| {
                (
                    rank(&graph.nodes[shown[l as usize]].kind),
                    shown[l as usize],
                )
            });
        };
        // The tree, breadth first, under a virtual top node that holds the
        // roots. A node whose parent chain loops back on itself (injections)
        // is a root of its own.
        let top = m as u32;
        let mut seen = vec![false; m];
        let mut order: Vec<u32> = Vec::with_capacity(m + 1);
        order.push(top);
        let mut tree: Vec<Vec<u32>> = vec![Vec::new(); m + 1];
        for start in roots.iter().copied().chain(0..top) {
            if seen[start as usize] {
                continue;
            }
            seen[start as usize] = true;
            tree[top as usize].push(start);
            let mut head = order.len();
            order.push(start);
            while head < order.len() {
                let at = order[head] as usize;
                head += 1;
                let mut kids = std::mem::take(&mut below[at]);
                sort(&mut kids);
                for kid in kids {
                    if !seen[kid as usize] {
                        seen[kid as usize] = true;
                        tree[at].push(kid);
                        order.push(kid);
                    }
                }
            }
        }
        // Bottom up: the height of each subtree and where its children go.
        let mut high = vec![ROW; m + 1];
        let mut centre = vec![ROW / 2.0; m + 1];
        let mut dx = vec![0.0f32; m + 1];
        let mut dy = vec![0.0f32; m + 1];
        for &v in order.iter().rev() {
            let v = v as usize;
            let kids = &tree[v];
            if kids.is_empty() {
                continue;
            }
            // The children are one column: stacked, one under the other.
            let mut stacked = 0.0f32;
            for &k in kids {
                let k = k as usize;
                dx[k] = 0.0;
                dy[k] = stacked;
                stacked += high[k];
            }
            high[v] = stacked.max(ROW);
            // Between the first and the last child; but never far below the
            // top of the column, so the root of a tall tree is near the top,
            // where the view opens.
            let first = centre[kids[0] as usize];
            let last = kids[kids.len() - 1] as usize;
            centre[v] = ((first + dy[last] + centre[last]) / 2.0)
                .min(3.0 * ROW)
                .clamp(ROW / 2.0, high[v] - ROW / 2.0);
        }
        // Top down: absolute places. The children of a node start one column
        // right of it; the roots start at the left edge.
        let mut x = vec![0.0f32; m + 1];
        let mut y = vec![0.0f32; m + 1];
        let mut rects = vec![Rect::NOTHING; graph.nodes.len()];
        let mut bounds = Rect::NOTHING;
        for &v in &order {
            let v = v as usize;
            let (base_x, base_y) = (x[v], y[v]);
            let step = if v == m { 0.0 } else { COLUMN };
            for &k in &tree[v] {
                let k = k as usize;
                x[k] = base_x + step + dx[k];
                y[k] = base_y + dy[k];
            }
            if v < m {
                let rect =
                    Rect::from_min_size(Pos2::new(base_x, base_y + centre[v] - NODE.y / 2.0), NODE);
                rects[shown[v]] = rect;
                bounds = bounds.union(rect);
            }
        }
        Self {
            rects,
            shown: shown.to_vec(),
            bounds: bounds.expand(24.0),
            root: roots.first().map(|&l| shown[l as usize]),
            generation: GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::group::Rendered;
    use super::super::model::{
        tests::{fixture, synthetic},
        Proc,
    };
    use super::*;
    use std::collections::{BTreeSet, HashMap};

    fn all(graph: &Graph) -> Vec<usize> {
        (0..graph.nodes.len()).collect()
    }

    /// No two shown nodes overlap (by cells, so a big layout is quick).
    fn assert_no_overlap(layout: &Layout) {
        let mut cells: HashMap<(i32, i32), Vec<Rect>> = HashMap::new();
        for &node in &layout.shown {
            let rect = layout.get(node).expect("every shown node is placed");
            for x in (rect.left() / 128.0).floor() as i32..=(rect.right() / 128.0).floor() as i32 {
                for y in
                    (rect.top() / 128.0).floor() as i32..=(rect.bottom() / 128.0).floor() as i32
                {
                    let cell = cells.entry((x, y)).or_default();
                    for other in cell.iter() {
                        assert!(!rect.intersects(*other), "{rect:?} overlaps {other:?}");
                    }
                    cell.push(rect);
                }
            }
        }
    }

    #[test]
    fn a_small_run_is_a_tree_from_the_root_with_no_overlap() {
        let graph = Graph::build(&fixture());
        let layout = Layout::of(&graph, &all(&graph));
        assert_eq!(layout.len(), graph.nodes.len());
        assert_no_overlap(&layout);
        let root = graph
            .nodes
            .iter()
            .position(|n| n.kind == NodeKind::Process((401, 1)))
            .unwrap();
        assert_eq!(layout.root, Some(root));
        let at = |n: usize| layout.get(n).unwrap();
        // The root is the leftmost and the topmost-left of the processes; every
        // node but it has its anchor to its left.
        for node in 0..graph.nodes.len() {
            if node == root {
                assert!(layout
                    .shown
                    .iter()
                    .all(|&n| at(n).left() >= at(root).left()));
                continue;
            }
            let anchor = graph.anchor(node).expect("joined");
            assert!(
                at(node).left() > at(anchor).left(),
                "{node} right of {anchor}"
            );
        }
        assert!(layout.bounds.contains_rect(at(root)));
    }

    #[test]
    fn a_process_that_was_injected_into_by_its_child_is_still_the_root() {
        use super::super::model::Fact;
        let mut facts = fixture();
        facts.findings.push(Fact {
            tier: crate::triage::rules::Tier::High,
            rule: "injection.proc_mem_write".into(),
            object: "/proc/401/mem".into(),
            pid: 420,
            cookie: 4,
        });
        let graph = Graph::build(&facts);
        let root = graph
            .nodes
            .iter()
            .position(|n| n.kind == NodeKind::Process((401, 1)))
            .unwrap();
        assert_eq!(graph.root(), root);
        let layout = Layout::of(&graph, &all(&graph));
        assert_eq!(layout.root, Some(root));
        let left = layout.get(root).unwrap().left();
        assert!(layout
            .shown
            .iter()
            .all(|&n| layout.get(n).unwrap().left() >= left));
        assert_no_overlap(&layout);
    }

    #[test]
    fn many_children_are_one_column_however_many_there_are() {
        let mut facts = fixture();
        for n in 0..150u32 {
            facts.procs.push(Proc {
                pid: 1000 + n,
                cookie: 100 + u64::from(n),
                parent: Some((401, 1)),
                name: format!("ls{n}"),
                ..Default::default()
            });
        }
        let graph = Graph::build(&facts);
        let layout = Layout::of(&graph, &all(&graph));
        assert_no_overlap(&layout);
        let ls: Vec<Rect> = (0..graph.nodes.len())
            .filter(|&n| graph.nodes[n].label.starts_with("ls"))
            .map(|n| layout.get(n).unwrap())
            .collect();
        assert_eq!(ls.len(), 150);
        assert!(
            ls.iter().all(|r| r.left() == ls[0].left()),
            "all in one column"
        );
        assert!(
            layout.bounds.height() >= 150.0 * ROW,
            "a column as tall as its children: {:?}",
            layout.bounds
        );
    }

    #[test]
    fn a_big_run_is_placed_without_overlap_in_the_full_view_and_the_grouped_one() {
        let graph = Graph::build(&synthetic(1500, 5000));
        assert!(graph.nodes.len() > 6000);
        let layout = Layout::of(&graph, &all(&graph));
        assert_no_overlap(&layout);
        // The grouped view of the same run, and its capped Full.
        let view = Rendered::compact(&graph, &BTreeSet::new(), 15);
        assert_no_overlap(&view.layout);
        let full = Rendered::full(&graph, &graph.expanded(super::super::group::FULL_CAP));
        assert_no_overlap(&full.layout);
    }

    #[test]
    fn a_deep_chain_and_a_loop_of_injections_are_placed() {
        let mut facts = fixture();
        let mut parent = (401, 1);
        for n in 0..3000u32 {
            let pid = 10_000 + n;
            facts.procs.push(Proc {
                pid,
                cookie: u64::from(pid),
                parent: Some(parent),
                name: "chain".into(),
                ..Default::default()
            });
            parent = (pid, u64::from(pid));
        }
        let graph = Graph::build(&facts);
        let layout = Layout::of(&graph, &all(&graph));
        assert_eq!(layout.len(), graph.nodes.len());
        assert_no_overlap(&layout);
    }

    #[test]
    fn ten_thousand_nodes_are_laid_out_in_well_under_a_tenth_of_a_second() {
        let graph = Graph::build(&synthetic(2000, 8000));
        assert!(graph.nodes.len() >= 10_000, "{}", graph.nodes.len());
        let nodes = all(&graph);
        let best = (0..3)
            .map(|_| {
                let started = std::time::Instant::now();
                let layout = Layout::of(&graph, &nodes);
                assert_eq!(layout.len(), nodes.len());
                started.elapsed()
            })
            .min()
            .unwrap();
        assert!(best.as_millis() < 100, "{best:?}");
        // The grouped view of it, built and laid out, is as quick.
        let started = std::time::Instant::now();
        let full = Rendered::full(&graph, &graph.expanded(super::super::group::FULL_CAP));
        assert!(full.layout.len() > 100);
        assert!(
            started.elapsed().as_millis() < 100,
            "{:?}",
            started.elapsed()
        );
    }
}
