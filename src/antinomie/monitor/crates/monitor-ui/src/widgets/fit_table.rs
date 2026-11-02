// SPDX-License-Identifier: GPL-3.0-only
//! Tables that fit the box they are drawn in.
//!
//! `egui_extras::Column::exact`/`initial` keep their width even when the sum
//! of the columns no longer fits, so a table built from estimated widths grows
//! past its container (and past the background it paints). This module decides
//! the widths from the width of the container the table is really placed in:
//!
//! - fixed columns keep their width only while the whole table fits;
//! - otherwise every shrinkable column gives way in proportion to how much it
//!   can give (down to its own minimum, no global floor);
//! - one `remainder()` column takes what is left;
//! - only when even the minimums do not fit, the table sits in a horizontal
//!   `ScrollArea` of its own, at the sum of the minimums;
//! - every cell is clipped (use the `table::cell*` helpers or
//!   [`cell_middle`]: ellipsis, full text on hover);
//! - the background is painted from the table's final rect.
//!
//! ```ignore
//! let cols = [Col::fixed(90.0), Col::flex(160.0), Col::rest(120.0)];
//! fit_table::show(ui, &cols, |ui, plan| {
//!     plan.apply(TableBuilder::new(ui).striped(true))
//!         .header(h, |mut header| { /* header.col(...) per column */ })
//!         .body(|body| { /* rows */ });
//! });
//! ```
use crate::theme;
use eframe::egui::{self, Pos2, Rect, Shape, Ui};
use egui_extras::{Column, TableBuilder};

/// Narrowest a fixed column gets squeezed to when its table is too tight.
const FIXED_FLOOR: f32 = 40.0;
/// Narrowest a flexible column gets squeezed to.
const FLEX_FLOOR: f32 = 48.0;
/// Narrowest a remainder column is, unless a table says otherwise.

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Fixed,
    Flex,
    Rest,
}

/// One column of a table: its preferred width and how far it may shrink.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Col {
    kind: Kind,
    width: f32,
    min: f32,
    max: f32,
    resizable: bool,
}

impl Col {
    /// A column that keeps `width` while the table fits and is squeezed down
    /// to 40 px (or [`Col::min`]) before the table would pass its box.
    pub fn fixed(width: f32) -> Self {
        Self {
            kind: Kind::Fixed,
            width,
            min: FIXED_FLOOR.min(width),
            max: f32::INFINITY,
            resizable: false,
        }
    }

    /// A text column that prefers `width` and shrinks (text cut with an
    /// ellipsis) down to 48 px (or [`Col::min`]) when the table is tight.
    pub fn flex(width: f32) -> Self {
        Self {
            kind: Kind::Flex,
            width,
            min: FLEX_FLOOR.min(width),
            max: f32::INFINITY,
            resizable: false,
        }
    }

    /// The column that takes the rest of the width, at least `min`. A table
    /// has one; a second is treated as a flexible column of its `min`.
    pub fn rest(min: f32) -> Self {
        Self {
            kind: Kind::Rest,
            width: min,
            min,
            max: f32::INFINITY,
            resizable: false,
        }
    }

    /// Narrowest width of the column (the name `egui_extras` uses). A
    /// remainder column also wants that much.
    pub fn at_least(mut self, min: f32) -> Self {
        if self.kind == Kind::Rest {
            self.width = min;
            self.min = min;
        } else {
            self.min = min.min(self.width);
        }
        self
    }

    /// Narrowest width of the column.
    pub fn min(self, min: f32) -> Self {
        self.at_least(min)
    }

    /// Every cell of a fitted table is clipped; kept so a column reads like
    /// the `egui_extras` one it replaces.
    pub fn clip(self, _clip: bool) -> Self {
        self
    }

    /// The column can be dragged by its right edge (kept inside the box).
    pub fn resizable(mut self, resizable: bool) -> Self {
        self.resizable = resizable;
        self
    }

    /// Narrowest and widest the column may be (widest only matters to a
    /// dragged column).
    pub fn range(mut self, range: std::ops::RangeInclusive<f32>) -> Self {
        self.max = *range.end();
        self.at_least(*range.start())
    }
}

/// The widths decided for a container.
#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    cols: Vec<Col>,
    widths: Vec<f32>,
    rest: Option<usize>,
    /// The minimums do not fit: the table needs a horizontal scroll area.
    pub scrolls: bool,
    /// Width of all columns and gaps (the table's own width when it scrolls).
    pub total: f32,
    shrunk: bool,
}

/// Decide the widths of `cols` for a container `available` wide with
/// `spacing` between columns. Pure, so the rules are tested without egui.
pub fn plan(available: f32, spacing: f32, cols: &[Col]) -> Plan {
    let mut cols = cols.to_vec();
    let rest = cols.iter().position(|col| col.kind == Kind::Rest);
    for (index, col) in cols.iter_mut().enumerate() {
        if col.kind == Kind::Rest && Some(index) != rest {
            col.kind = Kind::Flex;
        }
    }
    let gaps = spacing * cols.len().saturating_sub(1) as f32;
    let budget = (available - gaps - 1.0).max(0.0);
    let wanted: f32 = cols.iter().map(|col| col.width).sum();
    let mut widths: Vec<f32> = cols.iter().map(|col| col.width).collect();
    let mut scrolls = false;
    let mut shrunk = false;
    if wanted > budget {
        shrunk = true;
        // The remainder column only gives way after the others.
        let slack: Vec<f32> = cols
            .iter()
            .map(|col| {
                if col.kind == Kind::Rest {
                    0.0
                } else {
                    (col.width - col.min).max(0.0)
                }
            })
            .collect();
        let total_slack: f32 = slack.iter().sum();
        let need = wanted - budget;
        if total_slack >= need && total_slack > 0.0 {
            for (width, slack) in widths.iter_mut().zip(&slack) {
                *width -= slack * need / total_slack;
            }
        } else {
            for (width, col) in widths.iter_mut().zip(&cols) {
                *width = col.min;
            }
            let minimum: f32 = widths.iter().sum();
            scrolls = minimum > budget;
        }
    }
    let used: f32 = widths.iter().sum();
    let total = used + gaps;
    Plan {
        cols,
        widths,
        rest,
        scrolls,
        total,
        shrunk,
    }
}

impl Plan {
    /// Width decided for column `index`.
    pub fn width(&self, index: usize) -> f32 {
        self.widths.get(index).copied().unwrap_or(0.0)
    }

    /// True when the table had to be narrower than the columns asked for.
    pub fn shrunk(&self) -> bool {
        self.shrunk
    }

    /// Add the columns to `builder`, every one clipped. While the table is
    /// scrolling sideways the remainder column is fixed at its minimum too.
    pub fn apply<'a>(&self, mut builder: TableBuilder<'a>) -> TableBuilder<'a> {
        let others_min = |skip: usize| -> f32 {
            self.cols
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != skip)
                .map(|(_, col)| col.min)
                .sum::<f32>()
        };
        for (index, col) in self.cols.iter().enumerate() {
            let width = self.widths[index];
            let column = if Some(index) == self.rest && !self.scrolls {
                Column::remainder().at_least(col.min)
            } else if col.resizable && !self.scrolls {
                // The widest a dragged column gets leaves the others their
                // minimums; a table that had to shrink does not let the
                // widths kept from a wider window stand.
                let widest = if self.shrunk {
                    width
                } else {
                    (self.total - others_min(index)).max(col.min)
                }
                .min(col.max)
                .max(col.min);
                Column::initial(width)
                    .range(col.min..=widest)
                    .resizable(true)
            } else {
                Column::exact(width)
            };
            builder = builder.column(column.clip(true));
        }
        builder
    }
}

/// Run `add` with the table placed in the width really left in `ui`: the
/// widths are planned from `ui.available_width()` (less the body's scroll
/// bar), a horizontal scroll area wraps the table only when the minimums do
/// not fit, and the deepest-surface background is painted from the rect the
/// table finally took (not the rest of the page below it).
pub fn show<R>(ui: &mut Ui, cols: &[Col], add: impl FnOnce(&mut Ui, &Plan) -> R) -> R {
    show_with(ui, cols, true, add)
}

/// [`show`] for a table whose body may not scroll (`vscroll(false)`): no
/// room is kept for a scroll bar.
pub fn show_with<R>(
    ui: &mut Ui,
    cols: &[Col],
    vscroll: bool,
    add: impl FnOnce(&mut Ui, &Plan) -> R,
) -> R {
    let gutter = if vscroll {
        ui.spacing().scroll.allocated_width()
    } else {
        0.0
    };
    let available = ui.available_width() - gutter;
    let plan = plan(available, ui.spacing().item_spacing.x, cols);
    let area = ui.available_rect_before_wrap();
    let (start, full) = (area.min, area.width());
    let slot = ui.painter().add(Shape::Noop);
    let out = if plan.scrolls {
        let id = ui.id().with("fit-table-scroll");
        let width = plan.total;
        let shown = egui::ScrollArea::horizontal()
            .id_salt(id)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_min_width(width);
                add(ui, &plan)
            });
        shown.inner
    } else {
        add(ui, &plan)
    };
    // The fill covers the table: the whole width when a remainder column or
    // the scroll area takes it, else the columns only.
    let width = if plan.scrolls || plan.rest.is_some() {
        full
    } else {
        (plan.total + gutter).min(full)
    };
    let bottom = ui.min_rect().bottom().max(start.y);
    let rect = Rect::from_min_max(start, Pos2::new(start.x + width, bottom));
    ui.painter().set(
        slot,
        egui::epaint::RectShape::filled(rect, 0.0, theme::bg()),
    );
    out
}

/// `egui_extras::TableBuilder` with the columns fitted to the container: the
/// same chain (`id_salt`, `striped`, `column`, `header`, `body`, ...), with
/// [`Col`] instead of `Column`.
pub struct FitBuilder<'a> {
    ui: &'a mut Ui,
    cols: Vec<Col>,
    id_salt: Option<egui::Id>,
    striped: Option<bool>,
    cell_layout: Option<egui::Layout>,
    resizable: bool,
    vscroll: Option<bool>,
    max_scroll_height: Option<f32>,
    min_scrolled_height: Option<f32>,
    sense: Option<egui::Sense>,
    auto_shrink: Option<egui::Vec2b>,
    stick_to_bottom: Option<bool>,
    scroll_to_row: Option<(usize, Option<egui::Align>)>,
}

type HeaderFn<'a> = Box<dyn FnOnce(egui_extras::TableRow<'_, '_>) + 'a>;

/// A [`FitBuilder`] with its header; add the rows with [`FitTable::body`].
pub struct FitTable<'a> {
    builder: FitBuilder<'a>,
    header: Option<(f32, HeaderFn<'a>)>,
}

impl<'a> FitBuilder<'a> {
    pub fn new(ui: &'a mut Ui) -> Self {
        Self {
            ui,
            cols: Vec::new(),
            id_salt: None,
            striped: None,
            cell_layout: None,
            resizable: false,
            vscroll: None,
            max_scroll_height: None,
            min_scrolled_height: None,
            sense: None,
            auto_shrink: None,
            stick_to_bottom: None,
            scroll_to_row: None,
        }
    }

    pub fn column(mut self, column: Col) -> Self {
        self.cols.push(column);
        self
    }

    pub fn id_salt(mut self, salt: impl std::hash::Hash) -> Self {
        self.id_salt = Some(egui::Id::new(salt));
        self
    }

    pub fn striped(mut self, striped: bool) -> Self {
        self.striped = Some(striped);
        self
    }

    pub fn cell_layout(mut self, layout: egui::Layout) -> Self {
        self.cell_layout = Some(layout);
        self
    }

    /// Every column that is not the remainder can be dragged.
    pub fn resizable(mut self, resizable: bool) -> Self {
        self.resizable = resizable;
        self
    }

    pub fn vscroll(mut self, vscroll: bool) -> Self {
        self.vscroll = Some(vscroll);
        self
    }

    pub fn max_scroll_height(mut self, height: f32) -> Self {
        self.max_scroll_height = Some(height);
        self
    }

    pub fn min_scrolled_height(mut self, height: f32) -> Self {
        self.min_scrolled_height = Some(height);
        self
    }

    pub fn sense(mut self, sense: egui::Sense) -> Self {
        self.sense = Some(sense);
        self
    }

    pub fn auto_shrink(mut self, shrink: impl Into<egui::Vec2b>) -> Self {
        self.auto_shrink = Some(shrink.into());
        self
    }

    pub fn stick_to_bottom(mut self, stick: bool) -> Self {
        self.stick_to_bottom = Some(stick);
        self
    }

    pub fn scroll_to_row(mut self, row: usize, align: Option<egui::Align>) -> Self {
        self.scroll_to_row = Some((row, align));
        self
    }

    pub fn header(
        self,
        height: f32,
        add: impl FnOnce(egui_extras::TableRow<'_, '_>) + 'a,
    ) -> FitTable<'a> {
        FitTable {
            builder: self,
            header: Some((height, Box::new(add))),
        }
    }

    /// A table without a header row.
    pub fn body(
        self,
        add: impl FnOnce(egui_extras::TableBody<'_>),
    ) -> egui::scroll_area::ScrollAreaOutput<()> {
        self.run(None, add)
    }

    fn run(
        self,
        header: Option<(f32, HeaderFn<'a>)>,
        body: impl FnOnce(egui_extras::TableBody<'_>),
    ) -> egui::scroll_area::ScrollAreaOutput<()> {
        let Self {
            ui,
            mut cols,
            id_salt,
            striped,
            cell_layout,
            resizable,
            vscroll,
            max_scroll_height,
            min_scrolled_height,
            sense,
            auto_shrink,
            stick_to_bottom,
            scroll_to_row,
        } = self;
        if resizable {
            let rest = cols.iter().position(|col| col.kind == Kind::Rest);
            for (index, col) in cols.iter_mut().enumerate() {
                col.resizable |= Some(index) != rest;
            }
        }
        let vscroll_on = vscroll.unwrap_or(true);
        show_with(ui, &cols, vscroll_on, |ui, plan| {
            let mut builder = TableBuilder::new(ui);
            if let Some(salt) = id_salt {
                builder = builder.id_salt(salt);
            }
            if let Some(striped) = striped {
                builder = builder.striped(striped);
            }
            if let Some(layout) = cell_layout {
                builder = builder.cell_layout(layout);
            }
            if let Some(vscroll) = vscroll {
                builder = builder.vscroll(vscroll);
            }
            if let Some(height) = max_scroll_height {
                builder = builder.max_scroll_height(height);
            }
            if let Some(height) = min_scrolled_height {
                builder = builder.min_scrolled_height(height);
            }
            if let Some(sense) = sense {
                builder = builder.sense(sense);
            }
            if let Some(shrink) = auto_shrink {
                builder = builder.auto_shrink(shrink);
            }
            if let Some(stick) = stick_to_bottom {
                builder = builder.stick_to_bottom(stick);
            }
            if let Some((row, align)) = scroll_to_row {
                builder = builder.scroll_to_row(row, align);
            }
            let builder = plan.apply(builder);
            match header {
                Some((height, add)) => builder.header(height, add).body(body),
                None => builder.body(body),
            }
        })
    }
}

impl FitTable<'_> {
    pub fn body(
        self,
        add: impl FnOnce(egui_extras::TableBody<'_>),
    ) -> egui::scroll_area::ScrollAreaOutput<()> {
        let Self { builder, header } = self;
        builder.run(header, add)
    }
}

/// A cell of text whose middle becomes an ellipsis when it does not fit
/// ("7dd32a00…c1e1a3"): hashes, ids and paths whose two ends matter. The
/// whole value is on hover.
pub fn cell_middle(ui: &mut Ui, text: &str, mono: bool) -> egui::Response {
    let width = ui.available_width();
    let font = if mono {
        egui::TextStyle::Monospace.resolve(ui.style())
    } else {
        egui::TextStyle::Body.resolve(ui.style())
    };
    let shown = middle(ui, text, &font, width);
    let label = if mono {
        egui::RichText::new(&shown).monospace()
    } else {
        egui::RichText::new(&shown)
    };
    let response = ui.add(egui::Label::new(label).wrap_mode(egui::TextWrapMode::Extend));
    if shown != text {
        response.on_hover_text(text)
    } else {
        response
    }
}

/// `text` cut in the middle with "…" to fit `width` (half of the kept
/// characters on each side), whole when it fits.
pub fn middle(ui: &Ui, text: &str, font: &egui::FontId, width: f32) -> String {
    let measure = |candidate: &str| {
        ui.fonts(|fonts| {
            fonts
                .layout_no_wrap(candidate.to_owned(), font.clone(), egui::Color32::WHITE)
                .size()
                .x
        })
    };
    if measure(text) <= width {
        return text.to_owned();
    }
    let chars: Vec<char> = text.chars().collect();
    let build = |kept: usize| {
        let head = kept.div_ceil(2);
        let tail = kept - head;
        let start: String = chars[..head].iter().collect();
        let end: String = chars[chars.len() - tail..].iter().collect();
        format!("{start}…{end}")
    };
    let (mut low, mut high) = (0usize, chars.len().saturating_sub(1));
    while low < high {
        let probe = (low + high).div_ceil(2);
        if measure(&build(probe)) <= width {
            low = probe;
        } else {
            high = probe - 1;
        }
    }
    build(low)
}
