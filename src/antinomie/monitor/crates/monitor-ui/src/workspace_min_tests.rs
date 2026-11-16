// SPDX-License-Identifier: GPL-3.0-only
//! The least size of workspace windows: refused splits, held separators and
//! every window split small without harm.
use super::*;

const ROOM: Room = Room {
    bar: 30.0,
    gap: 1.0,
    folded_bottom: false,
};

#[test]
fn a_separator_stops_where_either_side_reaches_its_least_size() {
    // Room for both: the fraction stays inside the limits.
    assert_eq!(held_fraction(0.5, 1000.0, 300.0, 300.0, 0.0), 0.5);
    assert!((held_fraction(0.1, 1000.0, 300.0, 300.0, 0.0) - 0.3).abs() < 1e-6);
    assert!((held_fraction(0.9, 1000.0, 300.0, 300.0, 0.0) - 0.7).abs() < 1e-6);
    // No room for both: shared in proportion to what each needs.
    assert!((held_fraction(0.9, 400.0, 300.0, 100.0, 0.0) - 0.75).abs() < 1e-6);
}

/// Memory and Network side by side in a pane `width` wide, the separator
/// at `fraction`.
fn side_by_side(width: f32, fraction: f32) -> Tree<Panel> {
    let mut tree = Tree::new(vec![Panel::Memory]);
    tree.split_right(NodeIndex::root(), fraction, vec![Panel::Network]);
    tree[NodeIndex::root()].set_rect(Rect::from_min_size(
        egui::Pos2::ZERO,
        egui::vec2(width, 600.0),
    ));
    tree
}

fn fraction(tree: &Tree<Panel>) -> f32 {
    match &tree[NodeIndex::root()] {
        Node::Horizontal(split) | Node::Vertical(split) => split.fraction,
        _ => panic!("not a split"),
    }
}

#[test]
fn a_dragged_separator_is_held_at_the_windows_least_width() {
    let least = min_size(&Panel::Memory).x;
    let mut tree = side_by_side(1400.0, 0.05);
    hold_minimums(&mut tree, ROOM, false);
    assert!(
        (fraction(&tree) * 1400.0 - least).abs() < 0.5,
        "{}",
        fraction(&tree)
    );
    let mut tree = side_by_side(1400.0, 0.98);
    hold_minimums(&mut tree, ROOM, false);
    let right = (1.0 - fraction(&tree)) * 1400.0;
    assert!((right - least - ROOM.gap).abs() < 0.5, "{right}");
    // A split the folded pane holds is left alone.
    let mut tree = side_by_side(1400.0, 0.05);
    hold_minimums(&mut tree, ROOM, true);
    assert_eq!(fraction(&tree), 0.05);
}

#[test]
fn the_least_size_of_a_layout_adds_up_its_parts() {
    let tree = side_by_side(1400.0, 0.5);
    let need = subtree_min(&tree, NodeIndex::root(), ROOM);
    let part = min_size(&Panel::Memory);
    assert_eq!(need.x, 2.0 * part.x + ROOM.gap);
    assert_eq!(need.y, part.y + ROOM.bar);
    // A pane takes the largest least size of its tabs.
    let tree = Tree::new(vec![Panel::Details, Panel::Triage]);
    assert_eq!(
        subtree_min(&tree, NodeIndex::root(), ROOM),
        min_size(&Panel::Triage) + egui::vec2(0.0, ROOM.bar)
    );
    // Folded to its tab strip, the bottom pane needs only the strip.
    let tree = Tree::new(vec![Panel::Details, Panel::Activity]);
    let folded = Room {
        folded_bottom: true,
        ..ROOM
    };
    assert_eq!(subtree_min(&tree, NodeIndex::root(), folded).y, ROOM.bar);
}

/// The default layout with its main pane `width` by `height` points.
fn layout_of(width: f32, height: f32) -> WorkspaceLayout {
    let mut layout = WorkspaceLayout::default();
    layout.dock.main_surface_mut()[NodeIndex::root()].set_rect(Rect::from_min_size(
        egui::Pos2::ZERO,
        egui::vec2(width, height),
    ));
    layout.min_room = Some(ROOM);
    layout
}

#[test]
fn a_split_that_leaves_a_window_too_small_is_refused_and_a_roomy_one_is_not() {
    let work = NodeIndex::root().left();
    for (width, fits) in [(700.0, false), (1300.0, true)] {
        let layout = layout_of(width, 800.0);
        assert_eq!(
            layout.split_fits(
                &Panel::Network,
                SurfaceIndex::main(),
                work,
                egui_dock::Split::Right
            ),
            fits,
            "{width}"
        );
    }
    // Stacked: the height has to hold both and the bottom pane.
    for (height, fits) in [(500.0, false), (1000.0, true)] {
        let layout = layout_of(1300.0, height);
        assert_eq!(
            layout.split_fits(
                &Panel::Network,
                SurfaceIndex::main(),
                work,
                egui_dock::Split::Below
            ),
            fits,
            "{height}"
        );
    }
}

#[test]
fn a_refused_split_joins_the_tabs_and_says_so() {
    let mut layout = layout_of(700.0, 800.0);
    let work = NodeIndex::root().left();
    let rect = Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(700.0, 560.0));
    layout.targets = vec![(SurfaceIndex::main(), work, rect)];
    layout.target_headers = vec![(
        SurfaceIndex::main(),
        work,
        Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(700.0, 30.0)),
    )];
    // Network shares the work pane with other tabs: its right edge splits.
    let target = layout
        .drop_target(&Panel::Network, egui::pos2(690.0, 300.0))
        .expect("a target");
    assert!(target.refused);
    assert_eq!(target.action, workspace_drag::DropAction::Append);
    let mut layout = layout_of(1300.0, 800.0);
    let rect = Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1300.0, 560.0));
    layout.targets = vec![(SurfaceIndex::main(), work, rect)];
    layout.target_headers = vec![(
        SurfaceIndex::main(),
        work,
        Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1300.0, 30.0)),
    )];
    let target = layout
        .drop_target(&Panel::Network, egui::pos2(1290.0, 300.0))
        .expect("a target");
    assert!(!target.refused);
    assert_eq!(
        target.action,
        workspace_drag::DropAction::Split(egui_dock::Split::Right)
    );
}

/// Every window of the workspace the test app can draw (a terminal needs a
/// run's terminal, and the Debugger and VM screen a live session: the dock
/// rule is the same for them).
fn every_window() -> Vec<Panel> {
    let mut panels = Panel::MAIN.to_vec();
    panels.extend([Panel::Details, Panel::Activity, Panel::Jobs]);
    panels.extend([
        Panel::Library(LibraryPage::BaseImages),
        Panel::Library(LibraryPage::Rules),
        Panel::Library(LibraryPage::Tools),
        Panel::Library(LibraryPage::Samples),
        Panel::Library(LibraryPage::Screenshots),
    ]);
    panels
}

#[test]
fn every_window_split_small_beside_run_history_draws_without_harm() {
    for split in [egui_dock::Split::Right, egui_dock::Split::Below] {
        for size in [egui::vec2(900.0, 600.0), egui::vec2(1400.0, 900.0)] {
            let mut app = crate::app::tests::app();
            for panel in every_window() {
                let ctx = egui::Context::default();
                theme::install(&ctx);
                let layout = crate::app::tests::workspace(&mut app);
                *layout = WorkspaceLayout::default();
                layout.split_beside_history(&panel, split, 0.5);
                for _ in 0..4 {
                    crate::app::tests::draw_input(
                        &mut app,
                        &ctx,
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                            ..Default::default()
                        },
                    );
                }
                let layout = crate::app::tests::workspace(&mut app);
                let at = layout
                    .dock
                    .find_tab(&panel)
                    .unwrap_or_else(|| panic!("{panel:?} left the layout"));
                let pane = layout.dock[at.surface][at.node]
                    .rect()
                    .unwrap_or_else(|| panic!("{panel:?} has no pane"));
                let least = min_size(&panel);
                // The pane has its least size when there is room for it,
                // else its share of what there is (never a sliver).
                assert!(
                    pane.width() >= least.x.min(size.x * 0.25)
                        && pane.height() >= (least.y * 0.33).min(size.y * 0.2),
                    "{panel:?} {split:?} {size:?}: pane {pane:?}"
                );
            }
        }
    }
}
