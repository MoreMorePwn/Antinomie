// SPDX-License-Identifier: GPL-3.0-only
//! The parts around the tabs: target line, filter box, quality strip, progress
//! line, tab strip and footer (design 2.1), and the pure functions that word
//! them.
use super::hierarchy::{self, Click};
use super::navigate::{self, Navigate};
use super::worker::{Phase, Where, Worker};
use super::{latency, rate, Pick};
use super::{properties, AppView, Question, StatisticsWindow, Tab, Target, TimeBase};
use crate::theme;
use antinomie_triage::statistics::export::{self, ExportContext, Table};
use antinomie_triage::statistics::RunStatistics;
use eframe::egui;
use std::sync::Arc;

/// One chip of the quality strip.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Chip {
    pub text: String,
    pub hint: String,
    pub tone: properties::Tone,
}

fn chip(text: impl Into<String>, hint: &str, tone: properties::Tone) -> Chip {
    Chip {
        text: text.into(),
        hint: hint.into(),
        tone,
    }
}

/// The chips above every tab (design 2.1): what the counts can and cannot say.
pub(super) fn chips(stats: &RunStatistics, live: bool, partial: bool) -> Vec<Chip> {
    use properties::Tone::{Bad, Plain, Warn};
    let q = &stats.quality;
    let mut chips = Vec::new();
    if let Some(loss) = q.telemetry_lost.filter(|loss| loss.lost_packets > 0) {
        chips.push(chip(
            format!(
                "Incomplete: at least {} packets lost",
                super::int(loss.lost_packets)
            ),
            "Packets the guest numbered that never arrived. Every count is of the calls that reached the host.",
            Bad,
        ));
    } else if q.incomplete() {
        chips.push(chip(
            "Incomplete: packets dropped",
            "The transport or the recorder dropped packets; see Properties.",
            Bad,
        ));
    } else if q.source == antinomie_triage::statistics::quality::QualitySource::Missing {
        chips.push(chip(
            "Quality not recorded",
            "This run has no manifest figures; nothing is known about loss.",
            Warn,
        ));
    } else {
        chips.push(chip("Complete", "No lost packets were seen.", Plain));
    }
    if let Some(reduced) = &q.reduced {
        let from = stats.first_ns.map_or_else(
            || "the switch".to_owned(),
            |first| super::run_time(reduced.at_guest_ns.saturating_sub(first)),
        );
        chips.push(chip(
            format!("Reduced from {from}"),
            "From the switch on, only calls the Triage rules read were kept (the recording quota ran low).",
            Warn,
        ));
    }
    if let (Some(gaps), Some(first), Some(last)) = (&q.read_gaps, stats.first_ns, stats.last_ns) {
        let inside = gaps
            .gaps
            .iter()
            .filter(|gap| gap.guest_ns >= first && gap.guest_ns <= last)
            .count();
        if inside > 0 {
            chips.push(chip(
                format!("{inside} host read gaps"),
                "Pauses in the host's reading inside this run: a quiet stretch there is not an idle program.",
                Warn,
            ));
        }
    }
    if let Some(waits) = q.guest_send_waits.filter(|waits| waits.count > 0) {
        chips.push(chip(
            format!("Guest waited {} times", super::int(waits.count)),
            "Guest sends found the ring full and waited; latencies of the guest's calls include this. This VM boot's figure.",
            Warn,
        ));
    }
    if live {
        chips.push(chip(
            "Still recording",
            "The run is not over; the numbers cover what was saved when they were read.",
            Plain,
        ));
    }
    if stats.out_of_scope > 0 {
        chips.push(chip(
            format!(
                "{} calls of another program not counted",
                super::int(stats.out_of_scope)
            ),
            "Calls in this recording that belong to another launched program. The Syscall Trace lists them.",
            Warn,
        ));
    }
    if partial {
        chips.push(chip(
            "Partial",
            "The walk is still going: these numbers cover the calls read so far.",
            Warn,
        ));
    }
    chips
}

/// The line under the strip: where the walk is, why it stopped, what is empty.
pub(super) fn status_line(
    phase: &Phase,
    total: u64,
    stats: Option<&RunStatistics>,
    filter: &str,
) -> Option<String> {
    match phase {
        Phase::Idle => None,
        Phase::Running(Where::Starting) => Some("Starting…".into()),
        Phase::Running(Where::Indexing { done, total }) => Some(format!(
            "Indexing the recording: {} of {}",
            antinomie_monitor_core::byte_size::short_size(*done),
            antinomie_monitor_core::byte_size::short_size(*total)
        )),
        Phase::Running(Where::Reading { read, total }) => {
            let percent = if *total == 0 { 0 } else { read * 100 / total };
            Some(format!(
                "Reading calls: {} of {} ({percent} %)",
                super::count_short(*read),
                super::count_short(*total)
            ))
        }
        Phase::Stopped => Some(format!(
            "Stopped after {} of {} calls. The numbers cover those calls.",
            super::count_short(stats.map_or(0, |s| s.read)),
            super::count_short(total)
        )),
        Phase::Failed(error) => Some(error.clone()),
        Phase::Done => stats.filter(|s| s.calls == 0).map(|s| {
            if s.read == 0 {
                "This recording holds no calls.".into()
            } else if filter.trim().is_empty() {
                "No call of this run's program is in the recording.".into()
            } else {
                format!("No call matches `{filter}`.")
            }
        }),
    }
}

/// The recording grew past what the result read (a live run).
pub(super) fn grew_by(target: &Target, stats: &RunStatistics) -> Option<u64> {
    if !target.live {
        return None;
    }
    let stamp = stats.stamp.as_ref()?;
    let len = crate::stat_cache::len(&target.directory.join("telemetry.raw")).ok()?;
    len.checked_sub(stamp.length)
        .filter(|grown| *grown >= 64 * 1024)
}

/// What the Call rate tab draws: the main result and the custom lines' walk.
fn rate_inputs<'a>(
    window: &'a StatisticsWindow,
    target: &Target,
    stats: &'a RunStatistics,
    running: bool,
) -> rate::Inputs<'a> {
    let customs = window.rate.lines.customs();
    inputs_of(
        &window.rate_worker,
        &window.applied,
        &customs,
        (window.time_base, target.facts.anchor),
        stats,
        running,
    )
}

fn inputs_of<'a>(
    worker: &'a Worker,
    applied: &str,
    customs: &[String],
    (base, anchor): (
        TimeBase,
        Option<antinomie_monitor_core::api::HostClockAnchor>,
    ),
    stats: &'a RunStatistics,
    running: bool,
) -> rate::Inputs<'a> {
    let custom = worker
        .shown()
        .filter(|(key, _)| key.lines == customs && key.filter == applied)
        .map(|(_, result)| &**result);
    rate::Inputs {
        stats,
        custom,
        progress: rate::LineProgress::of(&worker.phase, running, custom.is_some()),
        base,
        anchor,
        partial: running,
    }
}

impl StatisticsWindow {
    /// Everything inside the window.
    pub(super) fn body(
        &mut self,
        ui: &mut egui::Ui,
        view: &AppView<'_>,
        navigate: &mut Vec<Navigate>,
    ) {
        let Some(target) = view.target.as_ref() else {
            theme::empty_state(
                ui,
                "Select a run in Run History or the sidebar to see its statistics.",
            );
            return;
        };
        self.target_line(ui, target, navigate);
        self.filter_row(ui, view);
        let shown = self
            .worker
            .shown()
            .map(|(key, stats)| (key.filter.clone(), Arc::clone(stats)));
        let running = self.worker.running();
        let current = shown
            .as_ref()
            .is_some_and(|(filter, _)| *filter == self.applied)
            && self.filter_error.is_none();
        let stats = shown.map(|(_, stats)| stats);
        if let Some(stats) = &stats {
            self.strip(ui, target, stats, running);
        }
        self.progress_line(ui, target, stats.as_deref());
        self.question_row(ui, navigate);
        ui.separator();
        ui.horizontal(|ui| {
            for tab in Tab::ALL {
                if ui
                    .selectable_label(self.tab == tab, tab.label())
                    .on_hover_text(tab.hint())
                    .clicked()
                {
                    self.tab = tab;
                }
            }
        });
        ui.separator();
        let footer = 52.0;
        let height = (ui.available_height() - footer).max(60.0);
        let width = ui.available_width();
        let pick = ui
            .allocate_ui(egui::vec2(width, height), |ui| {
                ui.set_min_size(egui::vec2(width, height));
                match &stats {
                    Some(stats) => {
                        ui.add_enabled_ui(current || running, |ui| {
                            self.tab_body(ui, target, stats, running)
                        })
                        .inner
                    }
                    None => {
                        if !running && !matches!(self.worker.phase, Phase::Failed(_)) {
                            theme::empty_state(ui, "Nothing read yet.");
                        }
                        None
                    }
                }
            })
            .inner;
        if let Some(pick) = pick {
            let filter = stats.as_ref().map_or(&self.applied, |s| &s.filter).clone();
            match pick {
                Pick::Count(click) => self.click(view, &filter, click, navigate),
                Pick::Call(key) => navigate.push(Navigate::Call(key)),
            }
        }
        if self.rate_stop {
            self.rate_stop = false;
            self.rate_worker.stop();
        }
        ui.separator();
        self.footer(ui, view, target, stats.as_deref());
    }

    fn target_line(&mut self, ui: &mut egui::Ui, target: &Target, navigate: &mut Vec<Navigate>) {
        ui.horizontal_wrapped(|ui| {
            ui.label(theme::bold(ui, &target.label));
            if let Some((_, program)) = target
                .facts
                .run
                .iter()
                .find(|(label, _)| label == "Program")
            {
                ui.add(egui::Label::new(egui::RichText::new(program).monospace()).truncate());
            }
            if let Some((_, state)) = target.facts.run.iter().find(|(label, _)| label == "State") {
                ui.colored_label(theme::muted(), state);
            }
            if let Ok(size) = crate::stat_cache::len(&target.directory.join("telemetry.raw")) {
                ui.colored_label(
                    theme::muted(),
                    antinomie_monitor_core::byte_size::short_size(size),
                );
            }
            if ui
                .button("Change…")
                .on_hover_text("Open Run History to choose another run")
                .clicked()
            {
                navigate.push(Navigate::RunHistory);
            }
        });
    }

    fn filter_row(&mut self, ui: &mut egui::Ui, view: &AppView<'_>) {
        let mut apply = false;
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 480.0).max(180.0);
            let response = crate::query::filter_edit(
                ui,
                &mut self.filter,
                "syscall.name == openat",
                width,
                crate::query::FilterScope::Syscall,
            )
            .on_hover_text(format!(
                "{}\nStatistics ignores the Trace's hidden categories and selected process.",
                crate::query::HELP
            ));
            if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                apply = true;
            }
            if ui.button("Apply").on_hover_text("Count the calls this filter keeps (Enter)").clicked() {
                apply = true;
            }
            if ui
                .button("Use Trace filter")
                .on_hover_text("Copy the Syscall Trace's applied filter into this box, once")
                .clicked()
            {
                self.filter = view.trace_filter.to_owned();
                apply = true;
            }
            if ui.button("Clear").clicked() {
                self.filter.clear();
                apply = true;
            }
            egui::ComboBox::from_id_salt("statistics-time-base")
                .selected_text(self.time_base.label())
                .show_ui(ui, |ui| {
                    for base in TimeBase::ALL {
                        ui.selectable_value(&mut self.time_base, base, base.label());
                    }
                })
                .response
                .on_hover_text("How times are written. Host time is an estimate through the run's clock anchor.");
        });
        if apply {
            self.apply();
        }
        if let Some(error) = &self.filter_error {
            crate::activity::inline_only(ui, crate::activity::Level::Warn, error);
        }
    }

    fn strip(&mut self, ui: &mut egui::Ui, target: &Target, stats: &RunStatistics, running: bool) {
        let segments = self
            .segments
            .as_ref()
            .filter(|(id, count)| *id == target.id && *count > 1)
            .map(|(_, count)| {
                chip(
                    format!("Continued after a reconnect ({count} parts)"),
                    "This run continued after a telemetry reconnect. Like the Syscall Trace, the statistics cover the part after it.",
                    properties::Tone::Warn,
                )
            });
        ui.horizontal_wrapped(|ui| {
            for chip in chips(stats, target.live, running)
                .into_iter()
                .chain(segments)
            {
                let color = match chip.tone {
                    properties::Tone::Plain => theme::muted(),
                    properties::Tone::Warn => theme::warn(),
                    properties::Tone::Bad => theme::error(),
                };
                let icon = match chip.tone {
                    properties::Tone::Plain => "",
                    properties::Tone::Warn => egui_phosphor::regular::WARNING,
                    properties::Tone::Bad => egui_phosphor::regular::WARNING_OCTAGON,
                };
                let text = egui::RichText::new(format!("{icon} {}", chip.text).trim().to_owned())
                    .color(color);
                let response = ui
                    .add(egui::Button::new(text).small().frame(true))
                    .on_hover_text(format!(
                        "{}\nClick for the Quality figures in Properties.",
                        chip.hint
                    ));
                if response.clicked() {
                    self.tab = Tab::Properties;
                    self.scroll_quality = true;
                }
            }
            if let Some(grown) = grew_by(target, stats) {
                ui.colored_label(
                    theme::muted(),
                    format!(
                        "Recording grew by {} since it was read.",
                        antinomie_monitor_core::byte_size::short_size(grown)
                    ),
                );
                if ui.button("Refresh").clicked() {
                    let key = self.key_of(target);
                    self.worker.forget(&key);
                }
            }
        });
    }

    fn progress_line(&mut self, ui: &mut egui::Ui, target: &Target, stats: Option<&RunStatistics>) {
        let phase = self.worker.phase.clone();
        let mut text = status_line(&phase, self.worker.total, stats, &self.applied);
        if matches!(&phase, Phase::Failed(error) if error.starts_with("This run saved no telemetry"))
            && !target.directory.exists()
        {
            text = Some("This run's folder is gone.".into());
        }
        let Some(text) = text else {
            return;
        };
        ui.horizontal(|ui| {
            match &phase {
                Phase::Running(_) => {
                    ui.spinner();
                    ui.label(&text);
                    if ui
                        .button("Stop")
                        .on_hover_text("Stop reading; the numbers keep the calls read so far")
                        .clicked()
                    {
                        self.worker.stop();
                    }
                }
                Phase::Stopped | Phase::Failed(_) => {
                    ui.colored_label(theme::warn(), &text);
                    if ui.button("Read again").clicked() {
                        let key = self.key_of(target);
                        self.worker.forget(&key);
                    }
                }
                _ => {
                    ui.colored_label(theme::muted(), &text);
                    if !self.applied.is_empty() && ui.button("Clear filter").clicked() {
                        self.filter.clear();
                        self.apply();
                    }
                }
            };
        });
    }

    fn question_row(&mut self, ui: &mut egui::Ui, navigate: &mut Vec<Navigate>) {
        let Some(question) = self.question.clone() else {
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.colored_label(
                theme::warn(),
                format!(
                    "{} is hidden in the Syscall Trace. Show it there and open these calls?",
                    question.group.label()
                ),
            );
            if ui.button("Show and open").clicked() {
                navigate.push(Navigate::ShowGroup {
                    group: question.group,
                    filter: question.filter.clone(),
                });
                self.question = None;
            }
            if ui.button("Cancel").clicked() {
                self.question = None;
            }
        });
    }

    /// A click on a count: open the calls, or ask first when their group is hidden in the Trace.
    pub(super) fn click(
        &mut self,
        view: &AppView<'_>,
        window_filter: &str,
        click: Click,
        navigate: &mut Vec<Navigate>,
    ) {
        let filter = navigate::with_window_filter(window_filter, &click.clause);
        match click.group {
            Some(group) if view.hidden.contains(&group) => {
                self.question = Some(Question { group, filter });
            }
            _ => navigate.push(Navigate::Filter(filter)),
        }
    }

    /// The tab on view. A new tab is a new arm here.
    fn tab_body(
        &mut self,
        ui: &mut egui::Ui,
        target: &Target,
        stats: &RunStatistics,
        running: bool,
    ) -> Option<Pick> {
        match self.tab {
            Tab::Properties => {
                let blocks = properties::blocks(&target.facts, stats, self.time_base);
                let scroll = std::mem::take(&mut self.scroll_quality);
                properties::show(ui, &blocks, scroll);
                None
            }
            Tab::Hierarchy => {
                hierarchy::show(ui, stats, &mut self.hierarchy, running).map(Pick::Count)
            }
            Tab::CallRate => {
                let customs = self.rate.lines.customs();
                let input = inputs_of(
                    &self.rate_worker,
                    &self.applied,
                    &customs,
                    (self.time_base, target.facts.anchor),
                    stats,
                    running,
                );
                let out = rate::show(ui, &mut self.rate, &input);
                self.rate_stop |= out.stop_custom;
                out.click.map(Pick::Count)
            }
            Tab::Latency => latency::show(
                ui,
                &mut self.latency,
                &latency::Inputs {
                    stats,
                    facts: &target.facts,
                    base: self.time_base,
                    anchor: target.facts.anchor,
                },
            ),
        }
    }

    /// The table of the tab on view, for Copy and Export.
    pub(super) fn current_table(&self, target: &Target, stats: &RunStatistics) -> Table {
        match self.tab {
            Tab::Properties => {
                properties::table(&properties::blocks(&target.facts, stats, self.time_base))
            }
            Tab::Hierarchy => {
                export::hierarchy_table(stats, self.hierarchy.failed_only, self.hierarchy.by_error)
            }
            Tab::CallRate => {
                let input = rate_inputs(self, target, stats, false);
                rate::table(&input.plot(&self.rate), &rate::bands(stats))
            }
            Tab::Latency => latency::table(stats, self.latency.part),
        }
    }

    fn footer(
        &mut self,
        ui: &mut egui::Ui,
        view: &AppView<'_>,
        target: &Target,
        stats: Option<&RunStatistics>,
    ) {
        ui.horizontal(|ui| {
            let ready = stats.is_some();
            if ui
                .add_enabled(ready, egui::Button::new("Copy"))
                .on_hover_text("Copy this table as tab-separated text, with a header row")
                .clicked()
            {
                if let Some(stats) = stats {
                    self.copy(ui.ctx(), target, stats);
                }
            }
            let mut asked = None;
            ui.add_enabled_ui(ready, |ui| {
                ui.menu_button("Export ▾", |ui| {
                    for (text, kind) in [
                        ("This table as CSV", Export::Csv),
                        ("This table as JSON", Export::Json),
                        ("All statistics as JSON", Export::All),
                    ] {
                        if ui.button(text).clicked() {
                            asked = Some(kind);
                            ui.close();
                        }
                    }
                });
            });
            if let (Some(kind), Some(stats)) = (asked, stats) {
                self.export(ui.ctx(), view, target, stats, kind);
            }
            let (label, hint) = if self.popped {
                (
                    "Back into the main window",
                    "Return the window to the main window",
                )
            } else {
                (
                    "Pop out",
                    "Move the window into its own operating-system window",
                )
            };
            if ui.button(label).on_hover_text(hint).clicked() {
                let popped = !self.popped;
                self.set_popped(popped);
            }
            if let Some(note) = &self.note {
                ui.add(
                    egui::Label::new(egui::RichText::new(note).color(theme::muted())).truncate(),
                );
            }
        });
    }

    /// Put the table on the clipboard as tab-separated text.
    pub(super) fn copy(&mut self, ctx: &egui::Context, target: &Target, stats: &RunStatistics) {
        let table = self.current_table(target, stats);
        ctx.copy_text(table.to_tsv());
        self.note = Some(format!("Copied {} rows.", table.rows.len()));
    }

    /// Write the table to `<data>/exports/statistics` and say where.
    pub(super) fn export(
        &mut self,
        ctx: &egui::Context,
        view: &AppView<'_>,
        target: &Target,
        stats: &RunStatistics,
        kind: Export,
    ) {
        let table = self.current_table(target, stats);
        let context = ExportContext {
            run_id: target.id.clone(),
            vm: target.vm.clone(),
            boot: target.boot.clone(),
            time_base: self.time_base.export_name().into(),
        };
        let (name, ext, text) = match kind {
            Export::Csv => (format!("statistics-{}", table.name), "csv", table.to_csv()),
            Export::Json => (
                format!("statistics-{}", table.name),
                "json",
                export::table_json(&context, stats, &table),
            ),
            Export::All => ("statistics-all".to_owned(), "json", export::all_json(stats)),
        };
        let folder = crate::export_dirs::default_folder(view.data_dir, "statistics");
        let path = folder.join(crate::export_dirs::stamped(&name, &target.id, ext));
        let written = crate::export_dirs::ensure_parent(&path).and_then(|()| {
            std::fs::write(&path, text).map_err(|error| format!("{}: {error}", path.display()))
        });
        match written {
            Ok(()) => {
                crate::export_dirs::wrote(ctx, "statistics", "Statistics", &path);
                self.note = Some(crate::export_dirs::wrote_text("Statistics", &path));
            }
            Err(error) => {
                crate::activity::report(
                    ctx,
                    crate::activity::Level::Error,
                    format!("Statistics export: {error}"),
                );
                self.note = Some(format!("Export failed: {error}"));
            }
        }
    }
}

/// What Export ▾ writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Export {
    Csv,
    Json,
    All,
}
