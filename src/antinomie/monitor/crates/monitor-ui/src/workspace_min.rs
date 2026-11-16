// SPDX-License-Identifier: GPL-3.0-only
//! The least size each workspace window keeps.
//!
//! Splitting a pane halves it, and a window drawn in less room than its
//! controls need ran its rows off the edge, piled its parts on each other or
//! showed only a corner of itself. Two rules keep a window whole:
//!
//! - a drop that would split a pane into parts smaller than the windows in
//!   them need is refused (it joins the tabs instead), see [`split_fits`];
//! - a separator stops where the windows on either side reach their least
//!   size, see [`hold_minimums`] (when the main window itself is made too
//!   small for both, they share what there is in proportion).
//!
//! A pane is not made to scroll a window kept at its least size: the side
//! lists and views inside a window are `egui::Panel`s, which clip to their
//! own rect, not to a scroll area around them, and drew over the next pane.
//!
//! Text that does not fit a column, a tab or a list row is cut with "…" and
//! shown whole on hover where the app draws it (tables, tab titles, lists);
//! the least sizes below are what each window needs for its controls.
use super::*;
use egui_dock::{Node, Tree};

/// The least body size of `panel`'s window (without its tab bar), chosen per
/// window from its controls (see the task record of 0.9.0 UI round 2).
pub(crate) fn min_size(panel: &Panel) -> egui::Vec2 {
    let (width, height) = match panel {
        // The bottom pane: a few rows are enough to read and scroll.
        Panel::Details => (300.0, 100.0),
        Panel::Activity | Panel::Jobs => (340.0, 100.0),
        Panel::Summary => (340.0, 200.0),
        // Run History drops its Sample and Arguments columns when narrow.
        Panel::RunHistory => (380.0, 180.0),
        Panel::Terminal(_) => (320.0, 160.0),
        Panel::VmScreen => (320.0, 240.0),
        Panel::AnalysisSection { .. } => (380.0, 220.0),
        Panel::StaticAnalysis => (420.0, 260.0),
        // A list at the left and the selection's view beside it.
        Panel::Trace | Panel::Network | Panel::Memory | Panel::Disks | Panel::CoreDump => {
            (440.0, 260.0)
        }
        Panel::Triage => (440.0, 300.0),
        Panel::Debugger => (480.0, 300.0),
        Panel::Library(_) => (420.0, 260.0),
    };
    egui::vec2(width, height)
}

/// The sizes a tree needs: `bar` is the tab bar's height, `gap` the
/// separator's width; a folded bottom pane needs only its tab bar.
#[derive(Clone, Copy, Debug)]
pub(super) struct Room {
    pub(super) bar: f32,
    pub(super) gap: f32,
    pub(super) folded_bottom: bool,
}

/// The least size of the subtree at `node`.
pub(super) fn subtree_min(tree: &Tree<Panel>, node: NodeIndex, room: Room) -> egui::Vec2 {
    if node.0 >= tree.len() {
        return egui::Vec2::ZERO;
    }
    match &tree[node] {
        Node::Empty => egui::Vec2::ZERO,
        Node::Leaf(leaf) => {
            let folded = room.folded_bottom
                && !leaf.tabs.is_empty()
                && leaf.tabs.iter().all(WorkspaceLayout::is_bottom_panel);
            let body = leaf
                .tabs
                .iter()
                .map(min_size)
                .fold(egui::Vec2::ZERO, egui::Vec2::max);
            if folded {
                egui::vec2(body.x, room.bar)
            } else {
                body + egui::vec2(0.0, room.bar)
            }
        }
        Node::Horizontal(_) => {
            let (left, right) = (
                subtree_min(tree, node.left(), room),
                subtree_min(tree, node.right(), room),
            );
            egui::vec2(left.x + right.x + room.gap, left.y.max(right.y))
        }
        Node::Vertical(_) => {
            let (top, bottom) = (
                subtree_min(tree, node.left(), room),
                subtree_min(tree, node.right(), room),
            );
            egui::vec2(top.x.max(bottom.x), top.y + bottom.y + room.gap)
        }
    }
}

/// The fraction of a split `size` long that leaves its first part at least
/// `first` and its second at least `second`. When both do not fit, the room
/// is shared in proportion to what each needs.
pub(super) fn held_fraction(fraction: f32, size: f32, first: f32, second: f32, gap: f32) -> f32 {
    if size <= 0.0 {
        return fraction;
    }
    let room = size - gap;
    if first + second <= room {
        let low = first / size;
        let high = 1.0 - (second + gap) / size;
        fraction.clamp(low, high.max(low))
    } else if first + second > 0.0 {
        (first / (first + second)).clamp(0.05, 0.95)
    } else {
        fraction
    }
}

/// Move every separator of `tree` so the parts on either side keep their
/// least size. `skip_root` leaves the root split alone (the bottom pane
/// folded to its tab strip holds it there).
pub(super) fn hold_minimums(tree: &mut Tree<Panel>, room: Room, skip_root: bool) {
    for index in 0..tree.len() {
        if skip_root && index == 0 {
            continue;
        }
        let node = NodeIndex(index);
        let horizontal = match &tree[node] {
            Node::Horizontal(_) => true,
            Node::Vertical(_) => false,
            _ => continue,
        };
        let first = subtree_min(tree, node.left(), room);
        let second = subtree_min(tree, node.right(), room);
        if let Node::Horizontal(split) | Node::Vertical(split) = &mut tree[node] {
            if !split.rect.is_positive() || !split.rect.is_finite() {
                continue;
            }
            split.fraction = if horizontal {
                held_fraction(
                    split.fraction,
                    split.rect.width(),
                    first.x,
                    second.x,
                    room.gap,
                )
            } else {
                held_fraction(
                    split.fraction,
                    split.rect.height(),
                    first.y,
                    second.y,
                    room.gap,
                )
            };
        }
    }
}

/// Once per frame, before the dock of `surface` is drawn: note the sizes
/// of its tab bar and separator and hold its separators (the folded bottom
/// pane's split, `strip_only`, is held by `apply_bottom`).
pub(super) fn hold_surface(
    layout: &mut WorkspaceLayout,
    local: &mut DockState<Panel>,
    style: &egui_dock::Style,
    surface: SurfaceIndex,
    strip_only: bool,
) {
    let room = Room {
        bar: style.tab_bar.height,
        gap: style.separator.width,
        folded_bottom: surface.is_main() && layout.bottom_folded(),
    };
    layout.min_room = Some(room);
    hold_minimums(
        local.main_surface_mut(),
        room,
        surface.is_main() && (layout.bottom_folded() || strip_only),
    );
}

/// Whether moving `panel` into a split of the pane at `node` of `surface`
/// leaves every window of that surface its least size, in the surface's
/// current size `area`.
pub(super) fn split_fits(
    dock: &DockState<Panel>,
    panel: &Panel,
    surface: SurfaceIndex,
    node: NodeIndex,
    split: egui_dock::Split,
    area: egui::Vec2,
    room: Room,
) -> bool {
    let Some(location) = dock.find_tab(panel) else {
        return false;
    };
    let mut after = dock.clone();
    after.move_tab(
        location,
        (NodePath { surface, node }, TabInsert::Split(split)),
    );
    if !after.is_surface_valid(surface) {
        return false;
    }
    let need = subtree_min(&after[surface], NodeIndex::root(), room);
    need.x <= area.x + 0.5 && need.y <= area.y + 0.5
}

#[cfg(test)]
#[path = "workspace_min_tests.rs"]
mod tests;
