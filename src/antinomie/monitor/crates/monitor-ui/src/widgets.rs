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
//! - Tables (`egui_extras::TableBuilder`): call [`table::begin`] before the
//!   builder, draw header cells with [`table::head`] (or [`table::head_cell`]
//!   around custom header content such as a sort button), draw monospace
//!   data with [`table::cell`] and the [`table::Cell`] kinds, and mark rows
//!   with [`table::row_mark`] in the first cell. Row height comes from
//!   [`table::row_height`] and the header from [`table::header_height`].
//!   Zebra, hover and selection fills come from the active theme's visuals.
//! - Grouped facts on a page: [`card`]; a jump to another view: [`link`].
//! - A run-based window with nothing to show: [`info_panel`].
//! - Status words: [`chip`] with a [`Tone`]; filter-bar switches: [`toggle_chip`].
//!
//! Nothing here holds a literal color; add new ones to `theme::Palette`.
// Parts of the kit (chip, footer_split, row marks) are adopted screen by
// screen in the next batches.
#![allow(dead_code, unused_imports)]

mod card;
mod info_panel;
pub mod table;
mod tabs;
mod tone;
mod window;

pub use card::{card, link};
pub use info_panel::{info_panel, InfoPanel};
pub use tabs::{segmented, tab, tab_row, tabs, TabItem};
pub use tone::{chip, toggle_chip, toggle_chip_with, Tone};
pub use window::{footer, footer_split, window, Dialog};

#[cfg(test)]
mod tests;
