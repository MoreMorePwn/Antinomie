// SPDX-License-Identifier: GPL-3.0-only
//! Edge routes and label placement for the lineage graph, in graph space and
//! free of egui state so the maths can be tested: a label sits on its edge but
//! slides along it (or off it) until it covers no node and no other label.
use eframe::egui::{self, Pos2, Rect, Vec2};

/// How far a same-column edge bulges to the right of its nodes.
const BULGE: f32 = 60.0;
/// Room kept between a label and whatever it avoids.
const MARGIN: f32 = 3.0;

/// An edge's route, from the parent's right side to the child's left side. An
/// edge between two nodes of one column leaves and enters on the right side and
/// bulges out, so it does not run through the nodes between them; a self-edge
/// is a loop above the node.
pub(super) fn route(from: Rect, to: Rect, same: bool) -> [Pos2; 4] {
    if same {
        let top = from.center_top();
        return [
            top + egui::vec2(-24.0, 0.0),
            top + egui::vec2(-34.0, -30.0),
            top + egui::vec2(34.0, -30.0),
            top + egui::vec2(24.0, 0.0),
        ];
    }
    if (to.center().x - from.center().x).abs() < from.width() * 0.5 {
        let (a, b) = (from.right_center(), to.right_center());
        let out = egui::vec2(BULGE, 0.0);
        return [a, a + out, b + out, b];
    }
    let (a, b) = if to.center().x >= from.center().x {
        (from.right_center(), to.left_center())
    } else {
        (from.left_center(), to.right_center())
    };
    let pull = ((b.x - a.x).abs() / 2.0).max(30.0) * (b.x - a.x).signum();
    [a, a + egui::vec2(pull, 0.0), b - egui::vec2(pull, 0.0), b]
}

/// The point at `t` (0 to 1) on the cubic curve.
pub(super) fn bezier(points: &[Pos2; 4], t: f32) -> Pos2 {
    let u = 1.0 - t;
    let weights = [u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t];
    let mut at = Vec2::ZERO;
    for (point, weight) in points.iter().zip(weights) {
        at += point.to_vec2() * weight;
    }
    at.to_pos2()
}

/// Where along the curve a label may sit, the middle first, then outwards.
const STEPS: [f32; 17] = [
    0.5, 0.45, 0.55, 0.4, 0.6, 0.35, 0.65, 0.3, 0.7, 0.25, 0.75, 0.2, 0.8, 0.15, 0.85, 0.1, 0.9,
];

/// How much of a label's area lies on `others`, with the margin kept.
fn covered(label: Rect, others: &[Rect]) -> f32 {
    let label = label.expand(MARGIN);
    others
        .iter()
        .map(|other| {
            let both = label.intersect(*other);
            if both.is_positive() {
                both.area().max(1.0)
            } else {
                0.0
            }
        })
        .sum()
}

/// Choose each edge's label rectangle (centred where the label sits). `edges`
/// holds the route and the label size of each; `nodes` are the rectangles to
/// keep clear. The first free spot along the edge, nearest its middle, wins;
/// with none free, the spot covering least. Labels placed earlier count as
/// obstacles to later ones, so no two labels share a spot.
pub(super) fn place(edges: &[([Pos2; 4], Vec2)], nodes: &[Rect]) -> Vec<Rect> {
    let mut placed: Vec<Rect> = Vec::with_capacity(edges.len());
    for (points, size) in edges {
        let mut candidates: Vec<Pos2> = STEPS.iter().map(|t| bezier(points, *t)).collect();
        // Beside the curve too, for a loop whose own arc has no free spot.
        let middle = bezier(points, 0.5);
        for dy in [size.y + 2.0, -(size.y + 2.0)] {
            candidates.push(middle + egui::vec2(0.0, dy));
        }
        let mut best: Option<(f32, Rect)> = None;
        for (rank, centre) in candidates.into_iter().enumerate() {
            let rect = Rect::from_center_size(centre, *size);
            let overlap = covered(rect, nodes) + covered(rect, &placed);
            if overlap == 0.0 {
                best = Some((0.0, rect));
                break;
            }
            let cost = overlap * 4.0 + rank as f32;
            if best.is_none_or(|(least, _)| cost < least) {
                best = Some((cost, rect));
            }
        }
        placed.push(best.map_or(Rect::NOTHING, |(_, rect)| rect));
    }
    placed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(x: f32, row: f32) -> Rect {
        Rect::from_min_size(Pos2::new(x, row * 64.0), egui::vec2(170.0, 32.0))
    }

    fn overlaps(a: Rect, b: Rect) -> bool {
        a.intersect(b).is_positive()
    }

    #[test]
    fn an_edge_within_one_column_bulges_out_to_the_right() {
        let (a, b) = (node(310.0, 0.0), node(310.0, 2.0));
        let points = route(a, b, false);
        assert_eq!(points[0], a.right_center());
        assert_eq!(points[3], b.right_center());
        let mid = bezier(&points, 0.5);
        assert!(mid.x > a.right() + 20.0, "the middle clears the column");
    }

    #[test]
    fn a_label_in_the_middle_of_a_long_edge_slides_off_a_node_it_would_cover() {
        // sample (col 0) to a node two columns on, with a node of column 1
        // lying across the middle of the edge.
        let (from, to) = (node(0.0, 0.0), node(620.0, 0.0));
        let between = node(310.0, 0.0);
        let points = route(from, to, false);
        let size = egui::vec2(70.0, 17.0);
        assert!(overlaps(
            Rect::from_center_size(bezier(&points, 0.5), size),
            between
        ));
        let rects = place(&[(points, size)], &[from, to, between]);
        assert!(!overlaps(rects[0], between), "{:?}", rects[0]);
        assert!(!overlaps(rects[0], from) && !overlaps(rects[0], to));
    }

    #[test]
    fn labels_of_edges_fanning_out_of_one_node_do_not_overlap_each_other() {
        let sample = node(0.0, 0.0);
        let kids: Vec<Rect> = (0..4).map(|row| node(310.0, row as f32)).collect();
        let far = node(620.0, 1.0);
        let mut targets = kids.clone();
        targets.push(far);
        let size = egui::vec2(66.0, 17.0);
        let edges: Vec<([Pos2; 4], Vec2)> = targets
            .iter()
            .map(|to| (route(sample, *to, false), size))
            .collect();
        let mut nodes = targets.clone();
        nodes.push(sample);
        let rects = place(&edges, &nodes);
        for (i, a) in rects.iter().enumerate() {
            for node in &nodes {
                assert!(!overlaps(*a, *node), "label {i} covers a node");
            }
            for b in &rects[i + 1..] {
                assert!(!overlaps(*a, *b), "two labels overlap");
            }
        }
    }

    #[test]
    fn parallel_edges_into_one_node_get_separate_labels() {
        // Two parents of one child, stacked, both with the same text.
        let (a, b, child) = (node(0.0, 0.0), node(0.0, 1.0), node(310.0, 0.0));
        let size = egui::vec2(66.0, 17.0);
        let edges = [
            (route(a, child, false), size),
            (route(b, child, false), size),
        ];
        let rects = place(&edges, &[a, b, child]);
        assert!(!overlaps(rects[0], rects[1]));
    }

    #[test]
    fn a_self_loop_label_stays_off_the_row_above() {
        let (above, me) = (node(0.0, 0.0), node(0.0, 1.0));
        let points = route(me, me, true);
        let rects = place(&[(points, egui::vec2(60.0, 17.0))], &[above, me]);
        assert!(!overlaps(rects[0], above) && !overlaps(rects[0], me));
    }

    #[test]
    fn with_no_free_spot_the_least_covered_one_is_taken() {
        let from = node(0.0, 0.0);
        let to = node(310.0, 0.0);
        let points = route(from, to, false);
        // A wall of obstacles across the whole route.
        let wall = Rect::from_min_max(Pos2::new(-100.0, -200.0), Pos2::new(600.0, 200.0));
        let rects = place(&[(points, egui::vec2(60.0, 17.0))], &[wall]);
        assert_eq!(rects.len(), 1);
        assert!(rects[0].is_finite());
    }
}
