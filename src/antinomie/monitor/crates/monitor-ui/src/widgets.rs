// SPDX-License-Identifier: GPL-3.0-only
//! The shared widget kit of the redesigned UI. Each helper is the egui form
//! of one component of the design (see "UI Redesign - Design", section 6) and
//! reads its colors from `theme`, so all three themes restyle it at once.
//!
//! How to use it:
//! - Windows and dialogs: start with [`window`] instead of `egui::Window::new`
//!   (mockup chrome: closable title bar, no collapse arrow, 8 px corners,
//!   1 px line, shadow; no dim, position free). Finish the body with
//!   [`footer`] or [`footer_split`].
//! - In-page tabs (anything that is not a dock tab): [`tabs`] for a plain
//!   list, or [`tab_row`] with [`tab`] when each tab needs a badge, a tooltip
//!   or a disabled state. Exclusive options that are not sections (Graph /
//!   Tree, Table / Text) use [`segmented`].
//! - Tables ([`fit_table::FitBuilder`], the `egui_extras::TableBuilder` fitted
//!   to its box): draw header cells with [`fit_table::head`] (or
//!   [`fit_table::head_cell`] around custom header content such as a sort
//!   button), draw monospace data with [`fit_table::cell`] and the
//!   [`fit_table::Cell`] kinds, and mark rows with [`fit_table::row_mark`] in
//!   the first cell. Row height comes from [`fit_table::row_height`] and the
//!   header from [`fit_table::header_height`]. Zebra, hover and selection
//!   fills come from the active theme's visuals.
//! - Grouped facts on a page: [`card`]; a jump to another view: [`link`].
//! - A run-based window with nothing to show: [`info_panel`].
//! - Status words: [`chip`] with a [`Tone`]; filter-bar switches: [`toggle_chip`].
//!
//! Nothing here holds a literal color; add new ones to `theme::Palette`.

pub(crate) mod attack;
mod card;
mod facts;
mod fit;
pub mod fit_table;
mod info_panel;
mod tabs;
pub(crate) mod tone;
mod wheel;
mod window;
mod written;

pub use card::{back_link, bounded_menu, card, detail_block, link};
pub use facts::{fact_line, facts, titled};
pub use fit::fit_middle;
pub use info_panel::{info_panel, InfoPanel};
pub use tabs::{segmented, tab, tab_row, tabs, tight_tabs, TabItem, TIGHT_SAVING};
pub use tone::{chip, chip_wide, chip_width, fg_or_muted, toggle_chip, toggle_chip_with, Tone};
pub(crate) use wheel::raw_delta;
pub use window::{columns, fixed_width_body, footer, footer_split, frame_extra, window};
pub use written::{short_name, written_files};

#[cfg(test)]
mod tests;
