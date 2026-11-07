// SPDX-License-Identifier: GPL-3.0-only
//! The IOCs tab: every indicator of every run of the sample, one row per
//! unique indicator, read from the runs' Triage digests (so it costs nothing
//! to draw and is already cached in the window's data). The table is the
//! shared fit table; the selected row is shown in the shared Details pane
//! (`iocs_details`), and the export lives in `iocs_export`.
use super::{parts, *};
use crate::widgets::fit_table;
use crate::widgets::fit_table::{Col, FitBuilder};
use antinomie_monitor_core::samples::{SampleIoc, IOC_KINDS};
use antinomie_monitor_core::{
    api_keys::{self, ApiKey},
    report::{defang, IndicatorKind},
    samples::{NoteRef, RefKind},
};
use eframe::egui::RichText;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Which rows the every-run filter keeps.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Presence {
    All,
    EveryRun,
    SomeRuns,
}

/// The identity of a row: kind, value and, for a file, its path.
pub(super) type RowKey = (String, String, String);

pub(super) struct State {
    pub(super) kinds: BTreeSet<String>,
    pub(super) presence: Presence,
    pub(super) search: String,
    pub(super) hide_private: bool,
    pub(super) hide_guest: bool,
    pub(super) defang: bool,
    pub(super) selected: Option<RowKey>,
    /// Export only the selected row.
    pub(super) only_selected: bool,
    pub(super) status: Option<(String, bool)>,
    pub(super) job: Option<std::sync::mpsc::Receiver<Result<String, String>>>,
    key: Option<(bool, Instant)>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            kinds: BTreeSet::new(),
            presence: Presence::All,
            search: String::new(),
            hide_private: false,
            hide_guest: true,
            defang: true,
            selected: None,
            only_selected: false,
            status: None,
            job: None,
            key: None,
        }
    }
}

/// The union of the runs' indicators, computed with the rest of the window's
/// data on its worker thread.
pub(super) fn union_of(entries: &[RunEntry]) -> antinomie_monitor_core::samples::IocUnion {
    antinomie_monitor_core::samples::ioc_union(
        &entries
            .iter()
            .map(|entry| (entry.number, entry.digest.as_ref()))
            .collect::<Vec<_>>(),
    )
}

/// The tab: the total in grey and the matched count in red, as Triage's.
pub(super) fn tab_item(label: &str, data: &Data) -> widgets::TabItem {
    crate::triage::ioc_count_tab(
        label,
        data.iocs.rows.iter().filter(|row| row.matched()).count(),
        data.iocs.rows.len(),
    )
}

/// What a click asked of the app.
pub(super) enum Go {
    Triage(usize, RowKey),
    Export(&'static str),
}

pub(super) fn key_of(row: &SampleIoc) -> RowKey {
    (row.ty.clone(), row.value.clone(), row.path.clone())
}

fn singular(ty: &str) -> &str {
    match ty {
        "domain" => "Domain",
        "endpoint" => "IP:port",
        "url" => "URL",
        "file" => "File",
        "tls" => "TLS",
        other => other,
    }
}

/// The value as the table and the Details show it.
pub(super) fn shown(row: &SampleIoc, defanged: bool) -> String {
    match (defanged, IndicatorKind::from_id(&row.ty)) {
        (true, Some(kind)) => defang::indicator(kind, &row.value),
        _ => row.value.clone(),
    }
}

/// "run 4, 7", "5 runs" or "every run (3)".
pub(super) fn runs_text(row: &SampleIoc, listed: usize) -> String {
    let runs = row.runs();
    if listed > 1 && row.in_every_run(listed) {
        format!("every run ({listed})")
    } else if runs.len() <= 3 {
        format!(
            "run {}",
            runs.iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!("{} runs", runs.len())
    }
}

pub(super) fn time_text(us: Option<u64>) -> String {
    us.map_or("—".into(), crate::time_format::short_time_us)
}

impl State {
    pub(super) fn has_selection(&self) -> bool {
        self.selected.is_some()
    }

    /// Whether an abuse.ch key is stored (looked at every two seconds; the
    /// key itself is never kept).
    pub(super) fn has_key(&mut self, data_dir: &std::path::Path) -> bool {
        match self.key {
            Some((have, at)) if at.elapsed() < Duration::from_secs(2) => have,
            _ => {
                let have = !api_keys::get(data_dir, ApiKey::Abusech).is_empty();
                self.key = Some((have, Instant::now()));
                have
            }
        }
    }

    /// Every filter but the kind chips and the every-run choice. The search
    /// also finds a value typed or pasted defanged (`[.]`, `hxxp`).
    fn base(&self, row: &SampleIoc) -> bool {
        let needle = self
            .search
            .trim()
            .to_lowercase()
            .replace("[.]", ".")
            .replace("hxxp", "http");
        !(self.hide_private && row.private())
            && !(self.hide_guest && row.guest_infrastructure())
            && (needle.is_empty() || row.haystack().contains(&needle))
    }

    /// Every filter but the kind chips.
    fn passes(&self, row: &SampleIoc, listed: usize) -> bool {
        (match self.presence {
            Presence::All => true,
            Presence::EveryRun => row.in_every_run(listed),
            Presence::SomeRuns => !row.in_every_run(listed),
        }) && self.base(row)
    }

    /// The rows the filters keep, in table order.
    pub(super) fn visible<'a>(&self, data: &'a Data) -> Vec<&'a SampleIoc> {
        let listed = data.iocs.listed.len();
        data.iocs
            .rows
            .iter()
            .filter(|row| {
                self.passes(row, listed) && (self.kinds.is_empty() || self.kinds.contains(&row.ty))
            })
            .collect()
    }
}

/// The reference a note on this indicator carries (the Triage IOC table's).
pub(super) fn note_reference(row: &SampleIoc) -> NoteRef {
    NoteRef::new(
        RefKind::Indicator,
        format!("{}:{}", row.ty, row.value),
        format!("{} ({})", row.value, row.ty),
    )
}

/// The Check online button: it asks abuse.ch from the run's Triage, where the
/// lookup, its Cancel and its rate limit are. Without a key it stays off.
pub(super) fn check_online(
    ui: &mut egui::Ui,
    have_key: bool,
    row: &SampleIoc,
    go: &mut Option<Go>,
) {
    let response = ui
        .add_enabled(have_key, egui::Button::new("Check online"))
        .on_hover_text(
            "Opens the newest run with this indicator in Triage; turn on online lookups there",
        )
        .on_disabled_hover_text(
            "No abuse.ch key is stored. Add one in Tools > API keys to ask abuse.ch about an indicator.",
        );
    if response.clicked() {
        if let Some(seen) = row.sightings.last() {
            *go = Some(Go::Triage(seen.run, key_of(row)));
        }
    }
}

impl MonitorApp {
    pub(super) fn iocs_tab(&mut self, ui: &mut egui::Ui, data: &Arc<Data>) {
        let Some(detail) = self.samples_page.detail.as_mut() else {
            return;
        };
        let mut state = std::mem::take(&mut detail.iocs);
        let mut go = None;
        // The page scrolls when the window is too short for the filters and
        // a table (a short window with Details open); the table keeps a
        // height of its own meanwhile.
        let table_height = (ui.available_height() - 150.0).max(200.0);
        egui::ScrollArea::vertical()
            .id_salt("sample-iocs-page")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.iocs_body(ui, data, &mut state, &mut go, table_height);
            });
        self.iocs_poll(ui.ctx(), &mut state);
        if let Some(detail) = self.samples_page.detail.as_mut() {
            detail.iocs = state;
        }
        self.apply_ioc_go(ui.ctx(), data, go);
    }

    fn iocs_body(
        &mut self,
        ui: &mut egui::Ui,
        data: &Arc<Data>,
        state: &mut State,
        go: &mut Option<Go>,
        table_height: f32,
    ) {
        let union = &data.iocs;
        let listed = union.listed.len();
        notes(ui, data);
        if union.rows.is_empty() {
            let text = if listed == 0 {
                "No run of this sample has been read by Triage yet: open a run in Triage and its indicators appear here."
            } else {
                "The runs listed no indicators."
            };
            ui.add_space(6.0);
            parts::muted_line(ui, text);
            return;
        }
        let key = state.has_key(&self.options.data_dir);
        // The filter bar: kind chips with their counts, then the other filters.
        ui.horizontal_wrapped(|ui| {
            for (id, label) in IOC_KINDS {
                let count = union
                    .rows
                    .iter()
                    .filter(|row| row.ty == id && state.passes(row, listed))
                    .count();
                if count == 0 && !state.kinds.contains(id) {
                    continue;
                }
                let on = state.kinds.contains(id);
                if widgets::toggle_chip(ui, &format!("{label} ({count})"), on, None).clicked() {
                    if on {
                        state.kinds.remove(id);
                    } else {
                        state.kinds.insert(id.to_owned());
                    }
                }
            }
        });
        let (all, every, some) = union
            .rows
            .iter()
            .filter(|row| {
                state.base(row) && (state.kinds.is_empty() || state.kinds.contains(&row.ty))
            })
            .fold((0, 0, 0), |(all, every, some), row| {
                if row.in_every_run(listed) {
                    (all + 1, every + 1, some)
                } else {
                    (all + 1, every, some + 1)
                }
            });
        ui.horizontal_wrapped(|ui| {
            widgets::segmented(
                ui,
                [
                    (
                        Presence::All,
                        widgets::TabItem::new(format!("All {all}")),
                    ),
                    (
                        Presence::EveryRun,
                        widgets::TabItem::new(format!("Seen in every run {every}")),
                    ),
                    (
                        Presence::SomeRuns,
                        widgets::TabItem::new(format!("Only in some runs {some}")),
                    ),
                ],
                &mut state.presence,
            );
            let edit = ui.add(
                egui::TextEdit::singleline(&mut state.search)
                    .hint_text(crate::theme::placeholder(ui, "Search value, path, process"))
                    .margin(crate::widgets::clear_margin(egui::Margin::symmetric(4, 2)))
                    .desired_width(crate::theme::plain_edit_width(220.0)),
            );
            crate::widgets::clear_button(ui, &edit, &mut state.search);
            for (label, flag, tip) in [
                (
                    "Hide private and reserved",
                    &mut state.hide_private,
                    "Private, loopback and local addresses and names, which no feed lists",
                ),
                (
                    "Hide guest infrastructure",
                    &mut state.hide_guest,
                    "The base image's own traffic (clock sync, DHCP, apt) and the emulated network's 10.0.2.x addresses",
                ),
                (
                    "Defanged",
                    &mut state.defang,
                    "Show hxxp and [.] instead of live values; Copy follows it",
                ),
            ] {
                if widgets::toggle_chip(ui, label, *flag, None)
                    .on_hover_text(tip)
                    .clicked()
                {
                    *flag = !*flag;
                }
            }
        });
        let rows = state.visible(data);
        if let Some(selected) = &state.selected {
            if !rows.iter().any(|row| &key_of(row) == selected) {
                state.selected = None;
            }
        }
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                theme::muted(),
                format!("{} of {}", rows.len(), union.rows.len()),
            );
            self.export_menu(ui, state, &rows, go);
            let selected = state
                .selected
                .as_ref()
                .and_then(|key| union.rows.iter().find(|row| &key_of(row) == key));
            match selected {
                Some(row) => check_online(ui, key, row, go),
                None => {
                    ui.add_enabled(false, egui::Button::new("Check online"))
                        .on_disabled_hover_text(if key {
                            "Select an indicator first"
                        } else {
                            "No abuse.ch key is stored. Add one in Tools > API keys to ask abuse.ch about an indicator."
                        });
                }
            }
        });
        if let Some((text, error)) = &state.status {
            ui.colored_label(
                if *error {
                    theme::error()
                } else {
                    theme::muted()
                },
                text,
            );
        }
        if rows.is_empty() {
            ui.add_space(6.0);
            parts::muted_line(ui, "Nothing matches these filters.");
            return;
        }
        self.ioc_table(ui, data, state, &rows, key, go, table_height);
    }

    #[allow(clippy::too_many_arguments)]
    fn ioc_table(
        &mut self,
        ui: &mut egui::Ui,
        data: &Arc<Data>,
        state: &mut State,
        rows: &[&SampleIoc],
        have_key: bool,
        go: &mut Option<Go>,
        table_height: f32,
    ) {
        let listed = data.iocs.listed.len();
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = fit_table::row_height(font) + 6.0;
        let height = table_height;
        let mut picked = None;
        let defanged = state.defang;
        let selected = state.selected.clone();
        ui.scope(|ui| {
            FitBuilder::new(ui)
                .id_salt("sample-iocs")
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .striped(true)
                .column(Col::fixed(80.0))
                .column(Col::flex(300.0).at_least(160.0).clip(true))
                .column(Col::fixed(120.0))
                .column(Col::flex(150.0).at_least(80.0).clip(true))
                .column(Col::fixed(132.0))
                .column(Col::fixed(132.0))
                .column(Col::flex(130.0).at_least(70.0).clip(true))
                .column(Col::rest(80.0).at_least(120.0).clip(true))
                .max_scroll_height(height)
                .min_scrolled_height(0.0)
                .header(fit_table::header_height(font), |mut header| {
                    for title in [
                        "Kind",
                        "Indicator",
                        "Runs",
                        "Observed",
                        "First seen",
                        "Last seen",
                        "Process",
                        "Detections",
                    ] {
                        header.col(|ui| fit_table::head(ui, title));
                    }
                })
                .body(|body| {
                    body.rows(row_height, rows.len(), |mut line| {
                        let row = rows[line.index()];
                        let key = key_of(row);
                        line.set_selected(selected.as_ref() == Some(&key));
                        line.col(|ui| {
                            fit_table::cell_click(ui, fit_table::Cell::Text, singular(&row.ty));
                        });
                        line.col(|ui| {
                            let value = if row.ty == "file" && row.value.len() > 40 {
                                format!(
                                    "{}…{}",
                                    &row.value[..16],
                                    &row.value[row.value.len() - 8..]
                                )
                            } else {
                                shown(row, defanged)
                            };
                            let sub = if row.ty == "file" {
                                row.path.clone()
                            } else {
                                row.sub().to_owned()
                            };
                            let mut job = egui::text::LayoutJob::default();
                            job.append(
                                &value,
                                0.0,
                                egui::TextFormat::simple(
                                    egui::TextStyle::Monospace.resolve(ui.style()),
                                    theme::text(),
                                ),
                            );
                            if !sub.is_empty() {
                                job.append(
                                    &format!("   {sub}"),
                                    0.0,
                                    egui::TextFormat::simple(
                                        egui::TextStyle::Small.resolve(ui.style()),
                                        theme::muted(),
                                    ),
                                );
                            }
                            ui.add(egui::Label::new(job).selectable(false).truncate());
                        });
                        line.col(|ui| {
                            let text = runs_text(row, listed);
                            let all = row
                                .runs()
                                .iter()
                                .map(|run| parts::run_name(*run))
                                .collect::<Vec<_>>()
                                .join(", ");
                            fit_table::cell_click(ui, fit_table::Cell::Text, &text)
                                .on_hover_text(all);
                        });
                        line.col(|ui| {
                            fit_table::cell_click(
                                ui,
                                fit_table::Cell::Text,
                                &row.observed().join(", "),
                            );
                        });
                        line.col(|ui| {
                            fit_table::cell_click(
                                ui,
                                fit_table::Cell::Mono,
                                &time_text(row.first_us()),
                            );
                        });
                        line.col(|ui| {
                            fit_table::cell_click(
                                ui,
                                fit_table::Cell::Mono,
                                &time_text(row.last_us()),
                            );
                        });
                        line.col(|ui| {
                            let processes = row.processes();
                            let text = if processes.is_empty() {
                                "—".to_owned()
                            } else {
                                processes.join(", ")
                            };
                            fit_table::cell_click(ui, fit_table::Cell::Text, &text);
                        });
                        line.col(|ui| {
                            let hits = antinomie_monitor_core::samples::ioc_hit_texts(row);
                            if hits.is_empty() {
                                ui.label(RichText::new("—").color(theme::muted()));
                            } else {
                                widgets::chip(ui, hits.join("; "), Tone::Error)
                                    .on_hover_text("A stored abuse.ch dataset lists it");
                            }
                        });
                        let response = line.response();
                        response.context_menu(|ui| {
                            self.ioc_menu(ui, data, defanged, row, have_key, go);
                        });
                        if response.clicked() {
                            picked = Some(key);
                        }
                    });
                });
        });
        if let Some(key) = picked {
            state.selected = Some(key);
        }
    }

    /// The row's menu: Copy, Open in Triage, Add note, Check online.
    pub(super) fn ioc_menu(
        &mut self,
        ui: &mut egui::Ui,
        data: &Arc<Data>,
        defanged: bool,
        row: &SampleIoc,
        have_key: bool,
        go: &mut Option<Go>,
    ) {
        if ui.button("Copy").clicked() {
            ui.ctx().copy_text(shown(row, defanged));
            ui.close();
        }
        if defanged && ui.button("Copy raw value").clicked() {
            ui.ctx().copy_text(row.value.clone());
            ui.close();
        }
        ui.menu_button("Open in Triage", |ui| {
            for seen in &row.sightings {
                let has_folder = data
                    .runs
                    .iter()
                    .any(|entry| entry.number == seen.run && entry.folder);
                if ui
                    .add_enabled(has_folder, egui::Button::new(parts::run_name(seen.run)))
                    .on_disabled_hover_text("The run's folder was deleted")
                    .clicked()
                {
                    *go = Some(Go::Triage(seen.run, key_of(row)));
                    ui.close();
                }
            }
        });
        super::super::notes::menu_item(ui, || note_reference(row));
        check_online(ui, have_key, row, go);
    }

    pub(super) fn apply_ioc_go(&mut self, ctx: &egui::Context, data: &Arc<Data>, go: Option<Go>) {
        match go {
            Some(Go::Triage(number, (ty, value, path))) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.number == number) {
                    self.open_sample_indicator(&entry.run, &ty, &value, &path);
                }
            }
            Some(Go::Export(format)) => self.start_ioc_export(ctx, data, format),
            None => {}
        }
    }
}

/// What the tab cannot say, as Info lines: runs Triage has not read, digests
/// from before 0.8.2, and the rules that match runs and not indicators.
fn notes(ui: &mut egui::Ui, data: &Data) {
    let union = &data.iocs;
    let names = |runs: &[usize]| {
        runs.iter()
            .map(|run| parts::run_name(*run))
            .collect::<Vec<_>>()
            .join(", ")
    };
    // A run that never started has nothing for Triage to read; its digest
    // says why, so it is not listed as one waiting to be read.
    for entry in &data.runs {
        if let Some(why) = entry
            .digest
            .as_ref()
            .and_then(|digest| digest.launch_failure.as_deref())
        {
            crate::activity::inline_only(
                ui,
                crate::activity::Level::Info,
                format!("{} did not start: {why}", parts::run_name(entry.number)),
            );
        }
    }
    if !union.unlisted.is_empty() {
        crate::activity::inline_only(
            ui,
            crate::activity::Level::Info,
            format!(
                "{} not read by Triage yet, so its indicators are missing here. Open it in Triage once.",
                names(&union.unlisted)
            ),
        );
    }
    if !union.plain.is_empty() {
        crate::activity::inline_only(
            ui,
            crate::activity::Level::Info,
            format!(
                "{} was read by an older Triage: only the value is known, with no times, sources or process. Open it in Triage again to fill them in.",
                names(&union.plain)
            ),
        );
    }
    ui.label(
        RichText::new(
            "IDS, YARA and Sigma rules match a run, not a single indicator: they are in Summary > Detections. Detections here are stored abuse.ch records. A row with no hit is not a clean result.",
        )
        .small()
        .color(theme::muted()),
    );
}
