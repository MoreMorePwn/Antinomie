// SPDX-License-Identifier: GPL-3.0-only
//! Trunk lines: when the children of a process sit in more than one lane,
//! their fork and exec edges are drawn as one trunk beside each lane with a
//! short stub to every child, instead of one curve each, which would cross
//! the boxes of the lanes in front. Inject, signal, write and connect edges
//! stay curves of their own.
use super::layout::Layout;
use super::model::{EdgeKind, Graph};
use eframe::egui::{Color32, Pos2, Rect};
use std::collections::BTreeMap;

/// How far left of a lane its trunk runs, at zoom 1.
const BESIDE: f32 = 14.0;

/// One child on a trunk: its box in graph space and the colour of its stub.
pub(super) struct Kid {
    pub edge: usize,
    pub node: usize,
    pub rect: Rect,
    pub tint: Option<Color32>,
}

/// A process whose fork and exec edges are drawn as trunks.
pub(super) struct Trunks {
    pub rect: Rect,
    /// The top of the room its children have, in graph space.
    pub top: f32,
    pub kids: Vec<Kid>,
}

/// The parents whose children are in more than one lane, with those
/// children. `tint` gives the stub colour of a child with a finding.
pub(super) fn find(
    graph: &Graph,
    layout: &Layout,
    tint: impl Fn(usize) -> Option<Color32>,
) -> Vec<Trunks> {
    let mut by_parent: BTreeMap<usize, Vec<Kid>> = BTreeMap::new();
    for (at, edge) in graph.edges.iter().enumerate() {
        if !matches!(edge.kind, EdgeKind::Forked | EdgeKind::Execed) {
            continue;
        }
        let (Some(from), Some(to)) = (layout.get(edge.from), layout.get(edge.to)) else {
            continue;
        };
        if to.left() >= from.right() && layout.is_child(edge.from, edge.to) {
            by_parent.entry(edge.from).or_default().push(Kid {
                edge: at,
                node: edge.to,
                rect: to,
                tint: tint(edge.to),
            });
        }
    }
    by_parent
        .into_iter()
        .filter_map(|(parent, kids)| {
            let first = kids[0].rect.left() as i32;
            let lanes = kids.iter().any(|kid| kid.rect.left() as i32 != first);
            let (rect, top) = (layout.get(parent)?, layout.room_top(parent)?);
            lanes.then_some(Trunks { rect, top, kids })
        })
        .collect()
}

/// A segment to draw, in screen space, and the colour of a child's stub.
pub(super) struct Segment {
    pub line: [Pos2; 2],
    /// The child this is the stub of; `None` for the trunk and its rail.
    pub stub_of: Option<usize>,
    pub tint: Option<Color32>,
}

/// The lines of one parent's trunks at the view's `zoom`, given `to_screen`.
pub(super) fn segments(
    trunks: &Trunks,
    zoom: f32,
    to_screen: impl Fn(Rect) -> Rect,
) -> Vec<Segment> {
    let mut lanes: BTreeMap<i32, Vec<(Rect, usize, Option<Color32>)>> = BTreeMap::new();
    for kid in &trunks.kids {
        lanes.entry(kid.rect.left() as i32).or_default().push((
            to_screen(kid.rect),
            kid.node,
            kid.tint,
        ));
    }
    let parent = to_screen(trunks.rect).right_center();
    let rail = to_screen(Rect::from_min_max(
        Pos2::new(0.0, trunks.top),
        Pos2::new(1.0, trunks.top + 1.0),
    ))
    .top();
    let beside = BESIDE * zoom.clamp(0.3, 1.0);
    let mut out = Vec::new();
    let mut xs = Vec::new();
    for (index, members) in lanes.values_mut().enumerate() {
        members.sort_by(|a, b| a.0.top().total_cmp(&b.0.top()));
        let x = members[0].0.left() - beside;
        xs.push(x);
        let mut bottom = members[members.len() - 1].0.center().y;
        // The first lane's trunk is where the parent joins.
        if index == 0 {
            bottom = bottom.max(parent.y);
        }
        out.push(Segment {
            line: [Pos2::new(x, rail), Pos2::new(x, bottom)],
            stub_of: None,
            tint: None,
        });
        for &(rect, node, tint) in members.iter() {
            let y = rect.center().y;
            out.push(Segment {
                line: [Pos2::new(x, y), Pos2::new(rect.left(), y)],
                stub_of: Some(node),
                tint,
            });
        }
    }
    out.push(Segment {
        line: [parent, Pos2::new(xs[0], parent.y)],
        stub_of: None,
        tint: None,
    });
    if xs.len() > 1 {
        out.push(Segment {
            line: [Pos2::new(xs[0], rail), Pos2::new(xs[xs.len() - 1], rail)],
            stub_of: None,
            tint: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::layout::Layout;
    use super::super::model::{Facts, Graph, Proc};
    use super::*;

    /// One root with `children` distinct children, as lanes lay them out.
    fn wide(children: u32) -> (Graph, Layout) {
        let mut facts = Facts::default();
        facts.procs.push(Proc {
            pid: 1,
            cookie: 1,
            name: "root".into(),
            ..Default::default()
        });
        for n in 0..children {
            facts.procs.push(Proc {
                pid: 100 + n,
                cookie: 100 + u64::from(n),
                parent: Some((1, 1)),
                name: format!("child{n:02}"),
                ..Default::default()
            });
        }
        let graph = Graph::build(&facts);
        let shown: Vec<usize> = (0..graph.nodes.len()).collect();
        let layout = Layout::of(&graph, &shown);
        (graph, layout)
    }

    #[test]
    fn thirty_children_over_lanes_get_trunks_no_segment_crosses_a_box() {
        let (graph, layout) = wide(30);
        let trunks = find(&graph, &layout, |_| None);
        assert_eq!(trunks.len(), 1, "the root has trunks");
        assert_eq!(trunks[0].kids.len(), 30);
        let mut lefts: Vec<i32> = trunks[0]
            .kids
            .iter()
            .map(|k| k.rect.left() as i32)
            .collect();
        lefts.sort_unstable();
        lefts.dedup();
        assert!(lefts.len() >= 3, "{lefts:?}");
        let boxes: Vec<(usize, Rect)> = layout
            .shown
            .iter()
            .filter_map(|&n| layout.get(n).map(|r| (n, r)))
            .collect();
        let rect_of = |node: usize| layout.get(node).unwrap();
        for zoom in [1.0, 0.5] {
            let lines = segments(&trunks[0], zoom, |r| {
                Rect::from_min_max(r.min * zoom, r.max * zoom)
            });
            // A trunk, a stub for each child, the parent's lead and the rail.
            assert_eq!(lines.iter().filter(|s| s.stub_of.is_some()).count(), 30);
            for line in &lines {
                let hit = Rect::from_two_pos(line.line[0], line.line[1]);
                for (node, rect) in &boxes {
                    let rect = Rect::from_min_max(rect.min * zoom, rect.max * zoom);
                    // A stub touches only the box it ends at, and the lead
                    // only the parent.
                    let own = line.stub_of == Some(*node)
                        || (line.stub_of.is_none() && rect_of(*node) == trunks[0].rect);
                    if own {
                        continue;
                    }
                    assert!(
                        !hit.intersects(rect.shrink(0.5)),
                        "segment {:?} crosses box {node} {rect:?} at zoom {zoom}",
                        line.line
                    );
                }
            }
        }
    }

    #[test]
    fn a_single_lane_keeps_its_curves() {
        let (graph, layout) = wide(3);
        assert!(find(&graph, &layout, |_| None).is_empty());
    }

    #[test]
    fn a_child_with_a_finding_keeps_its_colour_on_its_stub() {
        let (graph, layout) = wide(30);
        let red = Color32::RED;
        let target = graph
            .nodes
            .iter()
            .position(|n| n.label.contains("child07"))
            .unwrap();
        let trunks = find(&graph, &layout, |node| (node == target).then_some(red));
        let lines = segments(&trunks[0], 1.0, |r| r);
        let tinted: Vec<_> = lines.iter().filter(|s| s.tint.is_some()).collect();
        assert_eq!(tinted.len(), 1);
        assert_eq!(tinted[0].stub_of, Some(target));
    }
}
