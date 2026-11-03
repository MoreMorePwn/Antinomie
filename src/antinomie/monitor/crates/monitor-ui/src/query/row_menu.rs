// SPDX-License-Identifier: GPL-3.0-only
//! The right-click menu of a table row: a short list that acts on the cell
//! that was clicked. Filter on its value, add that clause with AND or OR,
//! exclude it, copy it, and add a note about the row. It never lists the
//! row's other fields, so it is as tall as a handful of items at any table.
//!
//! The clicked cell is found from where the pointer pressed: the header
//! cells of the frame say which column lies under that x, and the cell
//! helpers of `widgets::fit_table` remember the text of a cell that was
//! right-clicked. The column's title then names the row field: by the cell's
//! own text when a field holds it, else by the title's likeness to the
//! field's name. A cell that no field matches still copies and notes.
use super::*;
use crate::theme;
use eframe::egui::{Id, RichText};

/// The header cells the last frame drew: x range, bottom edge and title.
#[derive(Clone, Default)]
struct Heads {
    frame: u64,
    cells: Vec<(f32, f32, f32, String)>,
}

/// The cell a secondary press landed on.
#[derive(Clone)]
struct Pressed {
    frame: u64,
    text: String,
}

/// The cell a menu was opened on: kept while the menu is open.
#[derive(Clone)]
struct Target {
    /// The frame the menu was last drawn in; a gap means a new menu.
    seen: u64,
    column: Option<String>,
    text: Option<String>,
}

fn heads_id() -> Id {
    Id::new("table-row-menu-heads")
}

fn pressed_id() -> Id {
    Id::new("table-row-menu-pressed")
}

/// A header cell calls this with its title, so a row menu can name the column
/// under a click.
pub(crate) fn note_head(ui: &egui::Ui, title: &str) {
    let rect = ui.max_rect();
    let frame = ui.ctx().cumulative_pass_nr();
    ui.ctx().data_mut(|data| {
        let heads = data.get_temp_mut_or_default::<Heads>(heads_id());
        if heads.frame != frame {
            heads.frame = frame;
            heads.cells.clear();
        }
        if heads.cells.len() < 64 {
            heads
                .cells
                .push((rect.left(), rect.right(), rect.bottom(), title.to_owned()));
        }
    });
}

/// A body cell calls this with its text: when the pointer just pressed the
/// secondary button over it, a row menu opened by that press acts on it.
pub(crate) fn note_cell(ui: &egui::Ui, text: &str) {
    if ui.input(|input| input.pointer.secondary_pressed())
        && ui.rect_contains_pointer(ui.max_rect())
    {
        let frame = ui.ctx().cumulative_pass_nr();
        ui.ctx().data_mut(|data| {
            data.insert_temp(
                pressed_id(),
                Pressed {
                    frame,
                    text: text.to_owned(),
                },
            );
        });
    }
}

/// The column under `pos`: the title of the nearest header above it.
fn column_at(ctx: &egui::Context, pos: egui::Pos2) -> Option<String> {
    ctx.data(|data| data.get_temp::<Heads>(heads_id()))?
        .cells
        .into_iter()
        .filter(|(left, right, bottom, _)| {
            *left <= pos.x && pos.x <= *right && *bottom <= pos.y + 1.0
        })
        .max_by(|a, b| a.2.total_cmp(&b.2))
        .map(|(_, _, _, title)| title)
}

fn letters(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// What a value reads as in a cell.
pub(crate) fn value_text(value: &RowValue) -> Option<String> {
    match value {
        RowValue::Text(text) => Some(text.clone()),
        RowValue::Number(number) => Some(number.to_string()),
        RowValue::Bool(flag) => Some(flag.to_string()),
        RowValue::List(items) if !items.is_empty() => Some(items.join(", ")),
        RowValue::List(_) | RowValue::Missing => None,
    }
}

/// The field of `row` the clicked cell shows: the one holding its text (the
/// one the column's title names when several do), else the one the title
/// names.
fn field_of<'a>(
    row: &'a [(&'a str, RowValue)],
    column: Option<&str>,
    text: Option<&str>,
    columns: &[(&str, &str)],
) -> Option<&'a (&'a str, RowValue)> {
    if let Some(named) = column.and_then(|title| {
        columns
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(title))
    }) {
        return row.iter().find(|field| field.0 == named.1);
    }
    let title = column.map(letters).filter(|title| !title.is_empty());
    let names = |name: &str| {
        let Some(title) = &title else {
            return false;
        };
        let whole = letters(name);
        let last = letters(name.rsplit('.').next().unwrap_or(name));
        whole == *title || last == *title || last.starts_with(title.as_str())
    };
    if let Some(text) = text.map(str::trim).filter(|text| !text.is_empty()) {
        let holding = |field: &&(&str, RowValue)| {
            value_text(&field.1).is_some_and(|value| {
                value == text || value.replace(',', "") == text.replace(',', "")
            })
        };
        let mut found = row.iter().filter(holding);
        let first = found.next();
        return found
            .find(|field| names(field.0))
            .or(first)
            .or_else(|| row.iter().find(|field| names(field.0)));
    }
    row.iter().find(|field| names(field.0))
}

/// The fields a list row with no columns filters on when its table gives
/// none: the first one the row has a value for.
const LIST_DEFAULTS: &[&str] = &["entry.name", "entry.id", "function.name", "name"];

/// What a row menu offers besides filtering.
#[derive(Default)]
pub(crate) struct Extras {
    /// The note the row's "Add note…" starts, when it has one: the SHA-256 of
    /// the sample the row's run started (`None`: the sample that is open) and
    /// the reference.
    pub note: Option<(Option<String>, antinomie_monitor_core::samples::NoteRef)>,
    /// Why the row has no note (shown on the disabled item); `None` hides
    /// the item when there is no note either.
    pub no_note: Option<&'static str>,
    /// The row as one line for "Copy row"; the filter values by default.
    pub row_text: Option<String>,
    /// Column titles whose field the title's likeness does not find:
    /// `(title, field)`.
    pub columns: &'static [(&'static str, &'static str)],
    /// For a list that has no columns (cores, captures): the fields the
    /// menu filters on, the first the row has a value for.
    pub defaults: &'static [&'static str],
}

/// The run whose evidence a view is showing, and the sample that run started:
/// what a note about one of its rows is filed under. The app sets it every
/// frame a run's view is drawn; a row menu reads it.
#[derive(Clone)]
pub(crate) struct NoteRun {
    pub vm_id: String,
    pub run_id: String,
    pub sample: Option<String>,
}

impl NoteRun {
    pub(crate) fn set(ctx: &egui::Context, run: &antinomie_monitor_core::RunSummary) {
        let note = Self {
            vm_id: run.vm_id.clone(),
            run_id: run.id.clone(),
            sample: run
                .request
                .sample
                .as_ref()
                .map(|sample| sample.sha256.clone()),
        };
        ctx.data_mut(|data| data.insert_temp(Id::new("table-row-note-run"), note));
    }

    pub(crate) fn get(ctx: &egui::Context) -> Option<Self> {
        ctx.data(|data| data.get_temp::<Self>(Id::new("table-row-note-run")))
    }

    /// The menu's note for an entry of this run, or why there is none.
    pub(crate) fn extras(
        &self,
        reference: Option<antinomie_monitor_core::samples::NoteRef>,
    ) -> Extras {
        match (&self.sample, reference) {
            (Some(sample), Some(reference)) => Extras {
                note: Some((Some(sample.clone()), reference)),
                ..Extras::default()
            },
            (None, Some(_)) => Extras {
                no_note: Some("This run did not start a sample of the library"),
                ..Extras::default()
            },
            (_, None) => Extras {
                no_note: Some("This kind of row cannot be noted yet"),
                ..Extras::default()
            },
        }
    }
}

/// Every run the app lists, by VM and run id, with the sample it started: for
/// the views that show a run's files (cores, captures) without its summary.
#[derive(Clone, Default)]
struct RunIndex {
    stamp: (usize, usize),
    runs: std::sync::Arc<std::collections::HashMap<(String, String), Option<String>>>,
}

impl NoteRun {
    /// Keep the index of the app's runs; rebuilt when their number changes.
    pub(crate) fn publish(
        ctx: &egui::Context,
        live: &[antinomie_monitor_core::RunSummary],
        history: &[antinomie_monitor_core::RunSummary],
    ) {
        let id = Id::new("table-row-note-runs");
        let stamp = (live.len(), history.len());
        let current = ctx
            .data(|data| data.get_temp::<RunIndex>(id))
            .unwrap_or_default();
        if current.stamp == stamp && !current.runs.is_empty() {
            return;
        }
        let runs = live
            .iter()
            .chain(history)
            .map(|run| {
                (
                    (run.vm_id.clone(), run.id.clone()),
                    run.request
                        .sample
                        .as_ref()
                        .map(|sample| sample.sha256.clone()),
                )
            })
            .collect();
        ctx.data_mut(|data| {
            data.insert_temp(
                id,
                RunIndex {
                    stamp,
                    runs: std::sync::Arc::new(runs),
                },
            )
        });
    }

    /// The run `run_id` of `vm_id`, if the app lists it.
    pub(crate) fn find(ctx: &egui::Context, vm_id: &str, run_id: &str) -> Option<Self> {
        let index = ctx.data(|data| data.get_temp::<RunIndex>(Id::new("table-row-note-runs")))?;
        let sample = index.runs.get(&(vm_id.to_owned(), run_id.to_owned()))?;
        Some(Self {
            vm_id: vm_id.to_owned(),
            run_id: run_id.to_owned(),
            sample: sample.clone(),
        })
    }
}

/// Where a filter built from the menu goes.
pub(crate) enum Draft<'a> {
    /// The table has no filter: the menu copies and notes only.
    None,
    /// The table's draft kept in egui state under this id.
    State(Id),
    /// A string the caller owns.
    Text(&'a mut String),
}

#[cfg(test)]
fn row_menu_for_test(ui: &mut egui::Ui, filter: &mut String, row: &[(&str, RowValue)]) {
    menu(
        ui,
        Id::new("test-menu"),
        Draft::Text(filter),
        row,
        Extras::default(),
    );
}

/// The row's menu with its filter actions on the clicked cell.
pub(crate) fn menu(
    ui: &mut egui::Ui,
    key: Id,
    mut draft: Draft<'_>,
    row: &[(&str, RowValue)],
    extras: Extras,
) {
    let ctx = ui.ctx().clone();
    let frame = ctx.cumulative_pass_nr();
    let key = key.with("row-menu-target");
    let mut target = ctx
        .data(|data| data.get_temp::<Target>(key))
        .filter(|target| target.seen + 1 >= frame);
    if target.is_none() {
        // A new menu: read where the pointer pressed.
        let pos = ctx
            .input(|input| input.pointer.press_origin().or(input.pointer.latest_pos()))
            .unwrap_or(ui.min_rect().min);
        let text = ctx
            .data(|data| data.get_temp::<Pressed>(pressed_id()))
            .filter(|pressed| pressed.frame + 1 >= frame)
            .map(|pressed| pressed.text);
        target = Some(Target {
            seen: frame,
            column: column_at(&ctx, pos),
            text,
        });
    }
    let mut target = target.expect("set above");
    target.seen = frame;
    ctx.data_mut(|data| data.insert_temp(key, target.clone()));

    let field = field_of(
        row,
        target.column.as_deref(),
        target.text.as_deref(),
        extras.columns,
    )
    .or_else(|| {
        // A list without columns: its first named field that has a value.
        if target.column.is_some() {
            return None;
        }
        let defaults = if extras.defaults.is_empty() {
            LIST_DEFAULTS
        } else {
            extras.defaults
        };
        defaults.iter().find_map(|name| {
            row.iter()
                .find(|field| field.0 == *name && !matches!(field.1, RowValue::Missing))
        })
    });
    ui.set_max_width(ctx.screen_rect().width().min(420.0));
    match field {
        Some((name, value)) if matches!(draft, Draft::None) => {
            let shown = value_text(value).unwrap_or_else(|| "(none)".into());
            ui.label(
                RichText::new(format!("{name} = {}", clip(&shown, 40)))
                    .small()
                    .color(theme::muted()),
            );
        }
        Some((name, value)) => {
            let shown = value_text(value).unwrap_or_else(|| "(none)".into());
            ui.label(
                RichText::new(format!("{name} = {}", clip(&shown, 40)))
                    .small()
                    .color(theme::muted()),
            );
            match &mut draft {
                Draft::None => {}
                Draft::Text(text) => value_menu(ui, name, value, text),
                Draft::State(id) => {
                    let mut text = ctx
                        .data(|data| data.get_temp::<String>(*id))
                        .unwrap_or_default();
                    let before = text.clone();
                    value_menu(ui, name, value, &mut text);
                    if text != before {
                        ctx.data_mut(|data| data.insert_temp(*id, text));
                    }
                }
            }
        }
        None if matches!(draft, Draft::None) => {}
        None => {
            ui.label(
                RichText::new("No filter field for this cell")
                    .small()
                    .color(theme::muted()),
            );
        }
    }
    ui.separator();
    let cell = target
        .text
        .clone()
        .or_else(|| field.and_then(|(_, value)| value_text(value)));
    if ui
        .add_enabled(cell.is_some(), egui::Button::new("Copy value"))
        .clicked()
    {
        ctx.copy_text(cell.unwrap_or_default());
        ui.close_menu();
    }
    if ui.button("Copy row").clicked() {
        let text = extras.row_text.clone().unwrap_or_else(|| {
            row.iter()
                .filter_map(|(name, value)| Some(format!("{name}: {}", value_text(value)?)))
                .collect::<Vec<_>>()
                .join("\n")
        });
        ctx.copy_text(text);
        ui.close_menu();
    }
    if let Some((sample, note)) = extras.note {
        ui.separator();
        crate::app::note_menu_item(ui, sample.as_deref(), note);
    } else if let Some(why) = extras.no_note {
        ui.separator();
        ui.add_enabled(false, egui::Button::new("Add note…"))
            .on_disabled_hover_text(why);
    }
}

fn clip(text: &str, most: usize) -> String {
    if text.chars().count() <= most {
        text.to_owned()
    } else {
        format!("{}…", text.chars().take(most - 1).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Vec<(&'static str, RowValue)> {
        vec![
            ("entry.id", RowValue::Text("r7".into())),
            ("entry.name", RowValue::Text("install.sh".into())),
            ("capture.state", RowValue::Text("finalized".into())),
            ("capture.requested_size", RowValue::Number(4096)),
            ("tag", RowValue::List(vec!["dropper".into(), "cron".into()])),
        ]
    }

    #[test]
    fn a_cell_names_the_field_that_holds_its_text() {
        let row = row();
        assert_eq!(
            field_of(&row, None, Some("finalized"), &[]).unwrap().0,
            "capture.state"
        );
        assert_eq!(
            field_of(&row, Some("Size"), Some("4096"), &[]).unwrap().0,
            "capture.requested_size"
        );
        assert_eq!(
            field_of(&row, None, Some("dropper, cron"), &[]).unwrap().0,
            "tag"
        );
    }

    #[test]
    fn a_title_names_the_field_when_the_text_matches_none() {
        let row = row();
        assert_eq!(
            field_of(&row, Some("State"), Some("Done"), &[]).unwrap().0,
            "capture.state"
        );
        assert_eq!(
            field_of(&row, Some("Name"), None, &[]).unwrap().0,
            "entry.name"
        );
        assert!(field_of(&row, Some("Latest run"), Some("2 h ago"), &[]).is_none());
    }

    #[test]
    fn a_listed_title_names_its_field_first() {
        let row = row();
        let columns = [("Latest run", "entry.id")];
        assert_eq!(
            field_of(&row, Some("latest run"), Some("2 h ago"), &columns)
                .unwrap()
                .0,
            "entry.id"
        );
    }

    #[test]
    fn two_fields_with_one_text_follow_the_column() {
        let row = vec![
            ("a.id", RowValue::Text("same".into())),
            ("b.name", RowValue::Text("same".into())),
        ];
        assert_eq!(
            field_of(&row, Some("Name"), Some("same"), &[]).unwrap().0,
            "b.name"
        );
        assert_eq!(field_of(&row, None, Some("same"), &[]).unwrap().0, "a.id");
    }

    /// A right click opens one short menu on the clicked cell, however many
    /// fields the row has, and it stays on the screen.
    #[test]
    fn a_right_click_opens_a_short_menu_that_fits_the_screen() {
        use crate::table_sort::testing::frame;
        let ctx = egui::Context::default();
        let many: Vec<(&'static str, RowValue)> =
            std::iter::once(("entry.name", RowValue::Text("dropper".into())))
                .chain((0..60).map(|index| {
                    let name: &'static str = Box::leak(format!("field.n{index}").into_boxed_str());
                    (name, RowValue::Number(index))
                }))
                .collect();
        let mut filter = String::new();
        let mut show = |ui: &mut egui::Ui| {
            let head = egui::Rect::from_min_size(egui::pos2(20.0, 10.0), egui::vec2(160.0, 20.0));
            ui.scope_builder(egui::UiBuilder::new().max_rect(head), |ui| {
                note_head(ui, "Name")
            });
            let cell = egui::Rect::from_min_size(egui::pos2(20.0, 40.0), egui::vec2(160.0, 24.0));
            let response = ui.put(
                cell,
                egui::Label::new("dropper").sense(egui::Sense::click()),
            );
            response.context_menu(|ui| {
                row_menu_for_test(ui, &mut filter, &many);
            });
        };
        let pos = egui::pos2(60.0, 52.0);
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Secondary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        for _ in 0..2 {
            frame(&ctx, vec![], &mut show);
        }
        frame(&ctx, vec![egui::Event::PointerMoved(pos)], &mut show);
        frame(&ctx, vec![button(true)], &mut show);
        frame(&ctx, vec![button(false)], &mut show);
        let texts = frame(&ctx, vec![], &mut show);
        let find = |text: &str| texts.iter().any(|(painted, _)| painted.starts_with(text));
        assert!(find("entry.name = dropper"), "{texts:?}");
        assert!(find("Apply as filter") && find("Add AND") && find("Add OR") && find("Exclude"));
        assert!(find("Copy value") && find("Copy row"));
        assert!(
            !find("Filter by field"),
            "the menu does not list the row's fields"
        );
        assert!(!find("field.n5"), "{texts:?}");
        let lowest = texts
            .iter()
            .map(|(_, rect)| rect.bottom())
            .fold(0.0_f32, f32::max);
        assert!(
            lowest < 400.0,
            "the menu ends at {lowest}, past the 400 px screen"
        );
    }
}
