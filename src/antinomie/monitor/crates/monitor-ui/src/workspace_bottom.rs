// SPDX-License-Identifier: GPL-3.0-only
//! The Details, Activity and Jobs pane folded to its tab strip: no tab shows
//! as selected and there is no body. A click on the shown tab, a drag of a
//! tab to the bottom edge of the window, Ctrl+` and View > Details, Activity
//! and Jobs fold it; a click on any of its tabs (or a shortcut that opens one)
//! opens it again at the height it had.
use super::*;
use egui_dock::{Node, Tree};

/// The fraction change that tells a drag of the separator from our own
/// setting of it.
const DRAGGED: f32 = 0.004;

impl WorkspaceLayout {
    /// Whether `panel` is one of the three the pane holds.
    pub(crate) fn is_bottom_panel(panel: &Panel) -> bool {
        matches!(panel, Panel::Details | Panel::Activity | Panel::Jobs)
    }

    /// The pane's tab strip is all there is of it.
    pub(crate) fn bottom_folded(&self) -> bool {
        self.bottom_folded
    }

    /// Fold the pane, or open it.
    pub(crate) fn toggle_bottom(&mut self) {
        if self.bottom_folded {
            self.unfold_bottom();
        } else {
            self.fold_bottom();
        }
    }

    pub(crate) fn fold_bottom(&mut self) {
        self.bottom_folded = true;
        self.bottom_badge = false;
    }

    /// Open the pane; a shortcut, the View menu or a click on its tab asked.
    pub(crate) fn unfold_bottom(&mut self) {
        self.bottom_folded = false;
        self.bottom_badge = false;
    }

    /// Whether a drag released at `position` (screen points) folds the pane:
    /// a tab of the pane let go at the bottom edge of the window.
    pub(super) fn drops_to_bottom_edge(&self, panel: &Panel, position: egui::Pos2) -> bool {
        Self::is_bottom_panel(panel)
            && self.bottom_edge > 0.0
            && position.y >= self.bottom_edge
            && self
                .dock
                .find_tab(panel)
                .is_some_and(|location| location.surface.is_main())
    }

    /// A click on a tab of the pane: on the shown tab it folds the pane, on
    /// any other it opens it (the dock has selected it by now).
    pub(super) fn bottom_tab_clicked(&mut self, panel: &Panel) {
        if !Self::is_bottom_panel(panel) {
            return;
        }
        if self.bottom_folded || self.bottom_active.as_ref() != Some(panel) {
            self.unfold_bottom();
        } else {
            self.fold_bottom();
        }
    }

    /// A tab of the pane was focused by the app itself (a selection filled
    /// Details): a folded pane stays folded and the tab says there is news.
    pub(super) fn note_bottom_focus(&mut self, panel: &Panel) {
        if self.bottom_folded && Self::is_bottom_panel(panel) {
            self.bottom_badge = true;
        }
    }

    /// Whether the pane's tab `panel` carries the news mark.
    pub(super) fn bottom_news(&self, panel: &Panel) -> bool {
        self.bottom_folded && self.bottom_badge && *panel == Panel::Details
    }

    /// The pane's split: the root, when it is a vertical split whose lower
    /// part is a bar of Details, Activity or Jobs.
    fn bottom_split(tree: &mut Tree<Panel>) -> Option<(&mut f32, Option<Panel>)> {
        let shown = match &tree[NodeIndex::root().right()] {
            Node::Leaf(egui_dock::LeafNode { tabs, active, .. })
                if tabs.iter().any(Self::is_bottom_panel) =>
            {
                tabs.get(active.0).cloned()
            }
            _ => return None,
        };
        match &mut tree[NodeIndex::root()] {
            Node::Vertical(egui_dock::SplitNode { fraction, .. }) => Some((fraction, shown)),
            _ => None,
        }
    }

    /// Once per frame, before the dock is drawn: keep the split at the tab
    /// strip while folded, put it back when opened, and note the height the
    /// open pane has. `height` is the dock's, `bar` the tab bar's.
    pub(super) fn apply_bottom(&mut self, tree: &mut Tree<Panel>, height: f32, bar: f32) {
        if tree.is_empty() || height <= 0.0 {
            return;
        }
        let (folded, open, set) = (
            self.bottom_folded,
            self.bottom_open_fraction,
            self.bottom_set,
        );
        let Some((fraction, shown)) = Self::bottom_split(tree) else {
            self.bottom_set = None;
            return;
        };
        self.bottom_active = shown;
        match (folded, set) {
            (true, Some(before)) if (*fraction - before).abs() > DRAGGED => {
                // The separator was dragged: the pane opens where it is let go.
                self.bottom_folded = false;
                self.bottom_set = None;
                self.bottom_open_fraction = Some(*fraction);
            }
            (true, _) => {
                if set.is_none() && open.is_none() {
                    self.bottom_open_fraction = Some(*fraction);
                }
                let target = (1.0 - (bar + 3.0) / height).clamp(0.5, 0.995);
                *fraction = target;
                self.bottom_set = Some(target);
            }
            (false, Some(_)) => {
                *fraction = open.unwrap_or(0.72);
                self.bottom_set = None;
            }
            (false, None) => self.bottom_open_fraction = Some(*fraction),
        }
    }
}

/// The look of the pane's tabs while it is folded: none of them is selected.
pub(super) fn unselected(style: &egui_dock::TabStyle) -> egui_dock::TabStyle {
    let mut style = style.clone();
    style.active = style.inactive.clone();
    style.focused = style.inactive.clone();
    style.active_with_kb_focus = style.inactive_with_kb_focus.clone();
    style.focused_with_kb_focus = style.inactive_with_kb_focus.clone();
    style
}
