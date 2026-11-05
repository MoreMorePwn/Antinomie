// SPDX-License-Identifier: GPL-3.0-only
//! Where the Relationships graph's nodes sit, in graph space. The root is at
//! the centre; each kind grows in its own direction from it: processes (and
//! the processes they injected into or signalled) to the right, one column
//! per level of the tree; files below, in a column under the process that
//! wrote or ran them; network endpoints to the left. A level is one column
//! however many nodes it has: the viewport pans and zooms over it.
use super::model::{Graph, NodeKind};
use eframe::egui::{self, Pos2, Rect, Vec2};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const NODE: Vec2 = egui::vec2(188.0, 30.0);
/// From the middle of a node to the middle of the next one down a column.
pub(super) const ROW: f32 = 64.0;
/// From one column to the next.
pub(super) const COLUMN: f32 = 260.0;
/// Between the lowest process and the first file.
const BAND: f32 = 60.0;

/// The way a kind of node grows from the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::triage) enum Side {
    Right,
    Below,
    Left,
}

impl Side {
    pub(in crate::triage) fn of(kind: &NodeKind) -> Self {
        match kind {
            NodeKind::Process(_) | NodeKind::Victim(_) => Self::Right,
            NodeKind::File(_) => Self::Below,
            NodeKind::Endpoint(_) => Self::Left,
        }
    }
}

/// Where each shown node sits.
pub(in crate::triage) struct Layout {
    pub at: BTreeMap<usize, Rect>,
    pub bounds: Rect,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            at: BTreeMap::new(),
            bounds: Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)),
        }
    }
}

impl Layout {
    pub(in crate::triage) fn of(graph: &Graph, shown: &[usize]) -> Self {
        let side = |node: usize| Side::of(&graph.nodes[node].kind);
        let shown_set: BTreeSet<usize> = shown.iter().copied().collect();
        let right: Vec<usize> = shown
            .iter()
            .copied()
            .filter(|&n| side(n) == Side::Right)
            .collect();
        let level = graph.levels(&right);
        let mut at: BTreeMap<usize, Rect> = BTreeMap::new();
        let mut row_of: BTreeMap<usize, f32> = BTreeMap::new();
        // The node that leads to `node`, among the shown ones: its sort key.
        let order = |nodes: &mut Vec<usize>, row_of: &BTreeMap<usize, f32>| {
            nodes.sort_by(|a, b| {
                let key = |n: &usize| {
                    graph
                        .edges
                        .iter()
                        .filter(|edge| edge.to == *n && shown_set.contains(&edge.from))
                        .filter_map(|edge| row_of.get(&edge.from))
                        .next()
                        .copied()
                        .unwrap_or(0.0)
                };
                key(a).total_cmp(&key(b)).then(a.cmp(b))
            });
        };
        let place = |at: &mut BTreeMap<usize, Rect>,
                     row_of: &mut BTreeMap<usize, f32>,
                     node: usize,
                     x: f32,
                     centre_y: f32| {
            let rect = Rect::from_min_size(Pos2::new(x, centre_y - NODE.y / 2.0), NODE);
            row_of.insert(node, centre_y);
            at.insert(node, rect);
        };

        // Processes: one column per level, centred on the root's row.
        let mut columns: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &node in &right {
            columns
                .entry(level.get(&node).copied().unwrap_or(0))
                .or_default()
                .push(node);
        }
        for (&at_level, nodes) in &mut columns {
            order(nodes, &row_of);
            let height = (nodes.len().max(1) - 1) as f32 * ROW;
            for (i, &node) in nodes.iter().enumerate() {
                place(
                    &mut at,
                    &mut row_of,
                    node,
                    at_level as f32 * COLUMN,
                    -height / 2.0 + i as f32 * ROW,
                );
            }
        }
        let bottom = at.values().map(|r| r.bottom()).fold(NODE.y / 2.0, f32::max);

        // Files: below, in the column of the process that leads to them.
        let column_of = |node: usize| -> usize {
            graph
                .edges
                .iter()
                .filter(|edge| edge.to == node && shown_set.contains(&edge.from))
                .find_map(|edge| level.get(&edge.from).copied())
                .unwrap_or(0)
        };
        let mut below: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &node in shown.iter().filter(|&&n| side(n) == Side::Below) {
            below.entry(column_of(node)).or_default().push(node);
        }
        for (&at_level, nodes) in &mut below {
            order(nodes, &row_of);
            for (i, &node) in nodes.iter().enumerate() {
                place(
                    &mut at,
                    &mut row_of,
                    node,
                    at_level as f32 * COLUMN,
                    bottom + BAND + NODE.y / 2.0 + i as f32 * ROW,
                );
            }
        }

        // Endpoints: one column to the left of the root.
        let mut left: Vec<usize> = shown
            .iter()
            .copied()
            .filter(|&n| side(n) == Side::Left)
            .collect();
        order(&mut left, &row_of);
        let height = (left.len().max(1) - 1) as f32 * ROW;
        for (i, &node) in left.iter().enumerate() {
            place(
                &mut at,
                &mut row_of,
                node,
                -COLUMN,
                -height / 2.0 + i as f32 * ROW,
            );
        }
        let bounds = at
            .values()
            .copied()
            .reduce(|a, b| a.union(b))
            .unwrap_or_else(|| Rect::from_min_size(Pos2::ZERO, Vec2::splat(1.0)))
            .expand(24.0);
        Self { at, bounds }
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{tests::fixture, Proc};
    use super::*;

    fn node_of(graph: &Graph, kind: NodeKind) -> usize {
        graph.nodes.iter().position(|n| n.kind == kind).unwrap()
    }

    #[test]
    fn processes_grow_right_files_below_and_endpoints_left_without_overlap() {
        let graph = Graph::build(&fixture());
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &all);
        assert_eq!(layout.at.len(), all.len());
        let rects: Vec<Rect> = layout.at.values().copied().collect();
        for (i, a) in rects.iter().enumerate() {
            for b in &rects[i + 1..] {
                assert!(!a.intersects(*b), "{a:?} overlaps {b:?}");
            }
        }
        let root = layout.at[&node_of(&graph, NodeKind::Process((401, 1)))];
        for (node, rect) in &layout.at {
            match Side::of(&graph.nodes[*node].kind) {
                Side::Right if *node != 0 => assert!(rect.left() > root.left(), "{node}"),
                Side::Below => assert!(rect.top() > root.bottom(), "file {node}"),
                Side::Left => assert!(rect.right() < root.left(), "endpoint {node}"),
                Side::Right => {}
            }
        }
        assert!(layout.bounds.contains_rect(root));
    }

    #[test]
    fn a_wide_level_stays_one_column() {
        let mut facts = fixture();
        for n in 0..40u32 {
            facts.procs.push(Proc {
                pid: 1000 + n,
                cookie: 100 + u64::from(n),
                parent: Some((401, 1)),
                name: "ls".into(),
                ..Default::default()
            });
        }
        let graph = Graph::build(&facts);
        let all: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &all);
        let ls: Vec<Rect> = (0..graph.nodes.len())
            .filter(|&n| graph.nodes[n].label.starts_with("ls ("))
            .map(|n| layout.at[&n])
            .collect();
        assert_eq!(ls.len(), 40);
        assert!(ls.iter().all(|r| r.left() == ls[0].left()), "one column");
        assert!(layout.bounds.height() > 39.0 * ROW);
    }
}
