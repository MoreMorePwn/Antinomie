// SPDX-License-Identifier: MIT
//! Branch prefixes in the style of the `tree` command: `├── `, `└── `,
//! `│   ` and blanks, one four-character cell per level below the roots.
//! Each level has its own color from the theme's cycling tree palette; the
//! row's label keeps its own color.
//!
//! A flat list of rows in tree order gets its prefixes from [`prefixes`];
//! views that walk the tree build them with [`Prefix::child`]. Rows draw the
//! prefix with [`Prefix::paint`] (lines on the monospace cell grid, joined
//! from row to row) or [`row`]; [`Prefix::job`] is the same prefix as colored
//! characters, for menus.
use crate::theme;
use eframe::egui::{self, text::LayoutJob, FontId, Painter, Rect, Stroke, TextFormat};

/// Characters in the cell of one level.
pub(crate) const CELL_CHARS: usize = 4;

/// The cell of one level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Glyph {
    /// `├── `: the row has later siblings.
    Branch,
    /// `└── `: the row is the last of its siblings.
    Corner,
    /// `│   `: an ancestor at this level has later siblings.
    Pipe,
    /// Four spaces: an ancestor at this level was the last.
    Blank,
}

impl Glyph {
    pub(crate) fn text(self) -> &'static str {
        match self {
            Self::Branch => "├── ",
            Self::Corner => "└── ",
            Self::Pipe => "│   ",
            Self::Blank => "    ",
        }
    }
}

/// The cells in front of one row; the first belongs to level 0 (directly
/// below a root). A root has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Prefix {
    glyphs: Vec<Glyph>,
}

impl Prefix {
    /// How many levels deep the row is; 0 for a root.
    pub(crate) fn levels(&self) -> usize {
        self.glyphs.len()
    }

    /// The prefix of a child of the row this belongs to; `last` when the
    /// child is the last of its siblings.
    pub(crate) fn child(&self, last: bool) -> Self {
        let mut glyphs = Vec::with_capacity(self.glyphs.len() + 1);
        glyphs.extend_from_slice(&self.glyphs);
        if let Some(own) = glyphs.last_mut() {
            *own = match *own {
                Glyph::Branch | Glyph::Pipe => Glyph::Pipe,
                Glyph::Corner | Glyph::Blank => Glyph::Blank,
            };
        }
        glyphs.push(if last { Glyph::Corner } else { Glyph::Branch });
        Self { glyphs }
    }

    /// The prefix as the `tree` command prints it.
    #[cfg(test)]
    pub(crate) fn text(&self) -> String {
        self.glyphs.iter().map(|glyph| glyph.text()).collect()
    }

    /// The prefix as colored characters.
    pub(crate) fn job(&self, font: &FontId) -> LayoutJob {
        let mut job = LayoutJob::default();
        for (level, glyph) in self.glyphs.iter().enumerate() {
            job.append(
                glyph.text(),
                0.0,
                TextFormat::simple(font.clone(), theme::tree_branch(level)),
            );
        }
        job
    }

    pub(crate) fn width(&self, char_width: f32) -> f32 {
        (self.glyphs.len() * CELL_CHARS) as f32 * char_width
    }

    /// Draw the prefix from the left edge of `rect`, as lines through its
    /// whole height so that rows join up. The cells are `CELL_CHARS`
    /// monospace characters of `char_width` wide.
    pub(crate) fn paint(&self, painter: &Painter, rect: Rect, char_width: f32) {
        let cell_width = CELL_CHARS as f32 * char_width;
        let middle = painter.round_to_pixel_center(rect.center().y);
        for (level, glyph) in self.glyphs.iter().enumerate() {
            if *glyph == Glyph::Blank {
                continue;
            }
            let left = rect.left() + level as f32 * cell_width;
            let x = painter.round_to_pixel_center(left + char_width * 0.5);
            let stroke = Stroke::new(1.25_f32, theme::tree_branch(level));
            match glyph {
                Glyph::Pipe => {
                    painter.vline(x, rect.y_range(), stroke);
                }
                Glyph::Branch | Glyph::Corner => {
                    let bottom = if *glyph == Glyph::Branch {
                        rect.bottom()
                    } else {
                        middle
                    };
                    painter.vline(x, rect.top()..=bottom, stroke);
                    painter.hline(x..=left + char_width * 3.0, middle, stroke);
                }
                Glyph::Blank => {}
            }
        }
    }
}

/// The prefix of every row of a list in tree order, from the rows' depths
/// alone (0 is a root). Rows left out of the list, by a filter, are simply
/// not siblings: a row is last when no row of its depth follows it before
/// a shallower one.
pub(crate) fn prefixes(depths: &[usize]) -> Vec<Prefix> {
    let mut found = vec![Prefix::default(); depths.len()];
    // Walking up from the bottom: whether a row at each depth is still to
    // come below, in the same subtree.
    let mut more: Vec<bool> = Vec::new();
    for (row, &depth) in depths.iter().enumerate().rev() {
        if depth == 0 {
            more.clear();
            continue;
        }
        more.resize(depth + 1, false);
        let mut glyphs = Vec::with_capacity(depth);
        glyphs.extend((1..depth).map(|level| {
            if more[level] {
                Glyph::Pipe
            } else {
                Glyph::Blank
            }
        }));
        glyphs.push(if more[depth] {
            Glyph::Branch
        } else {
            Glyph::Corner
        });
        found[row] = Prefix { glyphs };
        more[depth] = true;
    }
    found
}

/// Width of a character of the monospace `font`.
pub(crate) fn char_width(ui: &egui::Ui, font: &FontId) -> f32 {
    ui.fonts(|fonts| fonts.glyph_width(font, '0'))
}

/// A caret that opens and closes a collapsible branch; true when open.
pub(crate) fn caret(
    ui: &mut egui::Ui,
    state: &mut egui::collapsing_header::CollapsingState,
) -> bool {
    let open = state.is_open();
    let icon = if open {
        egui_phosphor::regular::CARET_DOWN
    } else {
        egui_phosphor::regular::CARET_RIGHT
    };
    let response = ui
        .add(
            egui::Label::new(egui::RichText::new(icon).color(theme::muted()))
                .selectable(false)
                .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.clicked() {
        state.set_open(!open);
        state.store(ui.ctx());
        return !open;
    }
    open
}

/// A horizontal row: `prefix`, then what `add_contents` puts in it. The
/// lines reach half the spacing past the row, so they meet the next row's.
pub(crate) fn row<R>(
    ui: &mut egui::Ui,
    prefix: &Prefix,
    char_width: f32,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    let spacing = ui.spacing().item_spacing;
    ui.horizontal(|ui| {
        let left = ui.cursor().left();
        let width = prefix.width(char_width);
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.add_space(width);
        ui.spacing_mut().item_spacing.x = spacing.x;
        let result = add_contents(ui);
        let used = ui.min_rect();
        let reach = spacing.y * 0.5;
        let lines = Rect::from_x_y_ranges(
            left..=left + width,
            (used.top() - reach)..=(used.bottom() + reach),
        );
        prefix.paint(ui.painter(), lines, char_width);
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(depths: &[usize]) -> Vec<String> {
        prefixes(depths).iter().map(Prefix::text).collect()
    }

    #[test]
    fn single_root_has_no_prefix() {
        assert_eq!(texts(&[0]), [""]);
        assert_eq!(prefixes(&[0])[0].levels(), 0);
    }

    #[test]
    fn siblings_join_with_branches_and_end_with_a_corner() {
        assert_eq!(texts(&[0, 1, 1, 1]), ["", "├── ", "├── ", "└── "]);
    }

    #[test]
    fn nested_last_and_non_last_rows_carry_pipes_and_blanks() {
        // root
        // ├── a
        // │   ├── a1
        // │   └── a2
        // │       └── a2x
        // └── b
        //     └── b1
        assert_eq!(
            texts(&[0, 1, 2, 2, 3, 1, 2]),
            [
                "",
                "├── ",
                "│   ├── ",
                "│   └── ",
                "│       └── ",
                "└── ",
                "    └── ",
            ]
        );
    }

    #[test]
    fn several_roots_are_not_siblings_of_each_other() {
        assert_eq!(texts(&[0, 1, 0, 1, 1]), ["", "└── ", "", "├── ", "└── "]);
    }

    #[test]
    fn rows_left_out_by_a_filter_still_get_a_closed_tree() {
        // A match without its parent in the list sits under a gap.
        assert_eq!(texts(&[2, 2]), ["    ├── ", "    └── "]);
        assert_eq!(texts(&[1, 3, 1]), ["├── ", "│       └── ", "└── "]);
    }

    #[test]
    fn child_extends_the_parent_prefix() {
        let root = Prefix::default();
        let first = root.child(false);
        let second = root.child(true);
        assert_eq!(
            (first.text(), second.text()),
            ("├── ".into(), "└── ".into())
        );
        assert_eq!(first.child(true).text(), "│   └── ");
        assert_eq!(second.child(false).text(), "    ├── ");
        assert_eq!(first.child(false).child(true).text(), "│   │   └── ");
    }

    #[test]
    fn child_and_depth_prefixes_agree() {
        let a = Prefix::default().child(false);
        let a1 = a.child(false);
        let a2 = a.child(true);
        let b = Prefix::default().child(true);
        let b1 = b.child(true);
        let flat = prefixes(&[1, 2, 2, 1, 2]);
        assert_eq!(flat, [a, a1, a2, b, b1]);
    }

    #[test]
    fn each_level_has_its_own_color_and_the_palette_cycles() {
        let colors: Vec<_> = (0..theme::TREE_COLOR_COUNT)
            .map(theme::tree_branch)
            .collect();
        for (index, color) in colors.iter().enumerate() {
            assert!(
                !colors[..index].contains(color),
                "level {index} repeats a color"
            );
        }
        for level in 0..3 * theme::TREE_COLOR_COUNT {
            assert_eq!(
                theme::tree_branch(level),
                colors[level % theme::TREE_COLOR_COUNT]
            );
        }
        assert_eq!(
            theme::tree_branch(theme::TREE_COLOR_COUNT),
            theme::tree_branch(0)
        );
        // The job colors each cell by its level, past the palette too.
        let depth = theme::TREE_COLOR_COUNT + 2;
        let prefix = (0..depth).fold(Prefix::default(), |prefix, _| prefix.child(false));
        let job = prefix.job(&FontId::monospace(12.0));
        assert_eq!(job.sections.len(), depth);
        for (level, section) in job.sections.iter().enumerate() {
            assert_eq!(section.format.color, theme::tree_branch(level));
        }
    }

    fn luminance(color: egui::Color32) -> f32 {
        let linear = |value: u8| {
            let value = f32::from(value) / 255.0;
            if value <= 0.03928 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
    }

    fn contrast(a: egui::Color32, b: egui::Color32) -> f32 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn branch_colors_are_legible_on_both_themes() {
        for palette in [&theme::DARK, &theme::LIGHT] {
            for color in palette.tree {
                for ground in [palette.bg, palette.panel, palette.selection] {
                    assert!(
                        contrast(color, ground) >= 3.0,
                        "{color:?} on {ground:?}: {}",
                        contrast(color, ground)
                    );
                }
            }
            // Neighboring levels differ clearly.
            for level in 0..theme::TREE_COLOR_COUNT {
                let next = (level + 1) % theme::TREE_COLOR_COUNT;
                let (a, b) = (palette.tree[level], palette.tree[next]);
                let distance = f32::from(a.r().abs_diff(b.r()))
                    + f32::from(a.g().abs_diff(b.g()))
                    + f32::from(a.b().abs_diff(b.b()));
                assert!(distance >= 120.0, "{a:?} next to {b:?}");
            }
        }
    }
}
