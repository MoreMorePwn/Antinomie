// SPDX-License-Identifier: GPL-3.0-only
//! Triage for the selected run: process activity, files, HTTP/DNS and eBPF.
//! Rows are observations from captured syscalls and packets, not a verdict.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    bpf,
    query::{self, FieldSpec, RowValue},
    theme, trace,
};
#[cfg(test)]
use antinomie_monitor_core::EventSummary;
use antinomie_monitor_core::InvocationSummary;
use eframe::egui::{self, RichText};

// The scan, the activity rules and the other models are in `antinomie_triage`;
// every module of it is named here as it was when the modules were this
// crate's, so that the views below reach them as before.
pub(crate) use antinomie_triage::family;
pub(crate) use antinomie_triage::run_end;
#[allow(unused_imports)]
use antinomie_triage::*;
use antinomie_triage::{
    archive_scan, file_category, file_location, file_type, file_visibility, files, findings,
    ioc_scan, live_judge, process_cells, process_env, process_record, rules, scan_progress,
};
#[cfg(test)]
use antinomie_triage::{async_files, descriptors, file_content, kernel_records};

/// Where a row of Detection > Scanned inputs opens.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum OpenInput {
    StaticAnalysis,
    Capture(std::path::PathBuf),
    Core(std::path::PathBuf),
    /// A memory dump directory.
    Memory(std::path::PathBuf),
    Folder(std::path::PathBuf),
}

/// Temp-data key a clicked input is left under for the app.
pub(crate) const OPEN_INPUT: &str = "triage-open-input";

mod attack;
mod bpf_fields;
mod bpf_notes;
mod change_view;
use change_view::ChangeView;
mod counts;
mod details;
mod detection;
mod digest;
mod file_activity;
mod file_shown;
mod file_tabs;
pub(crate) const DEFAULT_REBUILD_FILE_MIB: u32 = files::DEFAULT_FILE_MIB;
pub(crate) const DEFAULT_REBUILD_RUN_MIB: u32 = files::DEFAULT_RUN_MIB;
mod finding_bar;
mod finding_cells;
mod finding_details;
mod graph;
pub(crate) use graph::Spacing as GraphSpacing;
pub(crate) const GRAPH_WINDOW_SIZE: [f32; 2] = graph::DEFAULT_SIZE;
#[cfg(test)]
mod idle_tests;
mod ioc_view;
pub(crate) use ioc_view::{count_tab as ioc_count_tab, source_tone_of as ioc_source_tone};
mod net_tabs;
mod network;
mod not_started;
mod presentation;
mod process_details;
mod process_mermaid;
mod process_tree;
mod properties;
mod refresh;
#[cfg(test)]
mod refresh_tests;
mod report_export;
#[cfg(test)]
mod saved_run_tests;

/// Where the app leaves the selected run's dump-trigger log for Triage, and
/// where Triage leaves a request to open the Memory or Core dumps tab.
pub(crate) const TRIGGER_LOG: &str = "run-trigger-log";
pub(crate) const OPEN_DUMP_TAB: &str = "open-dump-tab";

pub(crate) fn register_live_judge() {
    live_judge::register();
}

pub(crate) fn watched_calls() -> Vec<String> {
    rules::watched_calls()
}
mod sorting;
pub(crate) use antinomie_triage::sorting::Spec as SortSpec;
pub(crate) use sorting::{current as sort_current, header as sort_header};
mod summary;
mod table;
#[cfg(test)]
mod workload_qa;
use self::{
    archive_scan::*, bpf_notes::*, file_category::FILE_FIELDS, findings::*, process_tree::*,
    table::*,
};
#[cfg(test)]
use self::{descriptors::*, pcap_scan::*};
pub(crate) use antinomie_triage::network::AddressLookup;
pub(crate) use antinomie_triage::tone;
pub(crate) use antinomie_triage::{TriageInput, PAGE_ROWS_RANGE, STORED_ROWS};
pub(crate) use tone::Tone;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Summary,
    Properties,
    Detection,
    Process,
    Files,
    Network,
    Bpf,
    Ioc,
}

/// What a table's filter bar holds besides the filter and the pager.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bar {
    Plain,
    /// The Hide stdio, Hide library and Failed attempts toggles.
    Files,
    /// Tier and category chips, Show INFO and Show hidden.
    Findings,
    /// The same chips for the graph, which has no pages.
    Graph,
    /// The Open Packets button, enabled when the run has a capture.
    Network {
        packets: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessTab {
    Tree,
    Suspicious,
    Graph,
}

/// The Network tabs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NewTab {
    Endpoints,
    Domains,
    Urls,
    Tls,
}

/// The time the refresh loop schedules by. Production adds nothing; a test
/// moves it forward instead of sleeping through the refresh interval.
#[derive(Clone, Copy, Default)]
pub(super) struct Clock {
    skew: Duration,
}

impl Clock {
    pub(super) fn now(self) -> Instant {
        Instant::now() + self.skew
    }

    #[cfg(test)]
    pub(super) fn advance(&mut self, by: Duration) {
        self.skew += by;
    }
}

pub(crate) struct TriageView {
    properties: properties::View,
    detection: detection::View,
    section: Section,
    process: ProcessTab,
    files: FileTab,
    /// The File activity window of the Files section.
    file_history: file_activity::Window,
    /// The Per-file history tab is chosen instead of one of [`FileTab`].
    history_tab: bool,
    /// The Files section shows the per-file table, its first tab.
    by_file: bool,
    new_tab: NewTab,
    /// The IOC section.
    ioc: ioc_view::View,
    /// Case-insensitive substring for rule, process, summary, or evidence.
    /// Invocation chosen from a Suspicious activity row.
    selected_call_id: Option<trace::InvocationKey>,
    /// Archive directory and owned pcap, so a different capture starts a new index.
    scan_key: Option<String>,
    scan_cancel: Option<Arc<AtomicBool>>,
    /// The run's digest is being built in the background, and how far it has
    /// got: the window waits for it instead of reading the run a second time.
    digest_wait: Option<String>,
    scan_rx: Option<Receiver<(u64, Result<ArchiveScan, String>)>>,
    /// Result generation. A late index from a previous capture is discarded.
    scan_generation: u64,
    pending_generation: Option<u64>,
    scan: Option<ArchiveScan>,
    scan_error: Option<String>,
    last_refresh: Option<Instant>,
    next_refresh: Option<Instant>,
    clock: Clock,
    refresh_requested: bool,
    /// A refresh arrived while an index was already running.
    refresh_queued: bool,
    /// The pending refresh comes from the timer, not from the user.
    timer_refresh: bool,
    /// The last index began after the run ended.
    scan_began_finished: bool,
    /// The read in flight is a timer's: it finds the recording as it was or
    /// replaces the index on screen. The views keep showing that index.
    scan_is_timer: bool,
    /// What the last written run digest was made from.
    digested: Option<String>,
    /// The Summary's ATT&CK list with the fingerprint it was made for.
    /// Where a click in the Summary's ATT&CK list asked to go, taken by the
    /// next `summary::show`.
    attack_jump: Option<attack::Jump>,
    attacked: Option<(
        String,
        Vec<antinomie_monitor_core::report::Technique>,
        Vec<attack::Detail>,
    )>,
    /// Pass of the last frame that drew a pane using the index.
    shown_pass: Option<u64>,
    refresh_seconds: u64,
    bpf_export_status: String,
    scan_request: ScanRequest,
    /// The graph's window, selection and folded lanes.
    graph: graph::State,
    /// The graph in its own window.
    graph_window: graph::Window,
    /// How findings are spaced along the graph's time axis.
    graph_spacing: graph::Spacing,
    /// A spacing chosen in the graph, for the app's settings.
    graph_spacing_changed: Option<graph::Spacing>,
    /// The Summary strip's open or closed choice, for the session.
    strip: graph::Strip,
    /// Which HIGH rules of the run on screen already raised a toast.
    high_watch: graph::HighWatch,
    /// Toast for a HIGH finding of a live run (Settings › Notifications).
    toast_high: bool,
    /// When a hidden pane last had its live run read for the toast.
    hidden_poll: Option<Instant>,
    /// A finding the Suspicious table should scroll to when it is next drawn.
    table_focus: Option<trace::InvocationKey>,
    filter_drafts: [String; SLOTS],
    packet_jump: Option<u64>,
    packet_capture: Option<std::path::PathBuf>,
    /// Open Packets was pressed: show the run's capture, no frame chosen.
    open_packets: bool,
    /// A process Details asked to filter Trace to that process: the filter.
    trace_scope: Option<String>,
    context_key: Option<String>,
    details_directory: Option<std::path::PathBuf>,
    /// Absolute guest paths in the run's Changed files, for the Disks tab.
    changed_paths: Arc<std::collections::BTreeSet<String>>,
    /// The words for the selected run's network route.
    route: crate::route_ui::RouteText,
    /// The selected run's notes, shown at the bottom of the Summary.
    notes: Vec<String>,
    /// The Summary's Run artifacts box: what the selected run saved.
    run_box: crate::app::samples_page::detail::RunBoxState,
    /// An artifact of the Run artifacts box the user asked to open.
    open_artifact: Option<crate::app::samples_page::detail::ArtifactOpen>,
    /// Export report: the dialog, its choices and the running export.
    report: report_export::Dialog,
    /// The Summary's Relationships box and the data derived for it.
    summary_state: summary::SummaryState,
    /// The base image and last screenshot of the selected run.
    run_facts: summary::RunFacts,
}

impl TriageView {
    /// Open Export report… when the Triage bar is next drawn.
    pub(crate) fn request_report(&mut self) {
        self.report.requested = true;
    }
}

/// The colour of a cell's text in the theme that is active now, whichever
/// one the row was indexed in.
trait CellColor {
    fn color(&self) -> egui::Color32;
}

impl CellColor for Cell {
    fn color(&self) -> egui::Color32 {
        theme::tone(self.tone)
    }
}

impl Default for TriageView {
    fn default() -> Self {
        Self {
            properties: properties::View::default(),
            detection: detection::View::default(),
            section: Section::Summary,
            process: ProcessTab::Tree,
            files: FileTab::Opened,
            file_history: Default::default(),
            history_tab: false,
            by_file: true,
            new_tab: NewTab::Endpoints,
            ioc: ioc_view::View::default(),
            selected_call_id: None,
            scan_key: None,
            scan_cancel: None,
            digest_wait: None,
            scan_rx: None,
            scan_generation: 0,
            pending_generation: None,
            scan: None,
            scan_error: None,
            last_refresh: None,
            next_refresh: None,
            clock: Clock::default(),
            refresh_requested: false,
            refresh_queued: false,
            timer_refresh: false,
            scan_began_finished: false,
            scan_is_timer: false,
            digested: None,
            attack_jump: None,
            attacked: None,
            shown_pass: None,
            refresh_seconds: 5,
            bpf_export_status: String::new(),
            scan_request: ScanRequest::default(),
            graph: graph::State::default(),
            graph_window: graph::Window::default(),
            graph_spacing: graph::Spacing::default(),
            graph_spacing_changed: None,
            strip: graph::Strip::default(),
            high_watch: graph::HighWatch::default(),
            toast_high: false,
            hidden_poll: None,
            table_focus: None,
            filter_drafts: Default::default(),
            packet_jump: None,
            packet_capture: None,
            open_packets: false,
            trace_scope: None,
            context_key: None,
            details_directory: None,
            changed_paths: Arc::default(),
            route: crate::route_ui::RouteText::default(),
            notes: Vec::new(),
            run_box: Default::default(),
            open_artifact: None,
            report: report_export::Dialog::default(),
            summary_state: Default::default(),
            run_facts: Default::default(),
        }
    }
}

impl TriageView {
    /// Saved evidence was deleted: read the run's index again, so counts and
    /// badges drop what is gone.
    pub(crate) fn evidence_deleted(&mut self) {
        self.detection.evidence_deleted();
        self.request_refresh();
    }

    /// Maintain the selected run's index even when the Triage pane is hidden.
    /// Identity changes cancel old jobs; refreshes coalesce into one next scan.
    pub(crate) fn set_address_lookup(&mut self, mode: AddressLookup) {
        if self.scan_request.address_lookup != mode {
            self.scan_request.address_lookup = mode;
            self.request_refresh();
        }
    }

    /// The spacing the graph opens with, from the app's settings.
    pub(crate) fn set_graph_spacing(&mut self, spacing: graph::Spacing) {
        self.graph_spacing = spacing;
    }

    /// A spacing chosen in the graph, to save in the settings.
    pub(crate) fn take_graph_spacing(&mut self) -> Option<graph::Spacing> {
        self.graph_spacing_changed.take()
    }

    /// The selected run's network route, shown in the Summary and Network.
    pub(crate) fn set_route_text(&mut self, route: crate::route_ui::RouteText) {
        self.route = route;
    }

    /// The selected run's notes: the Summary lists them in its Notes section
    /// instead of between the pane's other warnings.
    pub(crate) fn set_notes(&mut self, notes: Vec<String>) {
        self.notes = notes;
    }

    /// The selected run, for the Summary's Run artifacts box: its cores,
    /// memory dumps, capture segments and trigger log.
    pub(crate) fn set_run_artifacts(
        &mut self,
        run: &antinomie_monitor_core::RunSummary,
        live: bool,
    ) {
        let ended = self.run_ended_ms();
        self.run_box.refresh(run, live, ended);
    }

    /// The run on screen with its network calls, for the Packets list's
    /// Made by column; none until its index has been made.
    pub(crate) fn net_attribution(
        &self,
    ) -> Option<(
        String,
        std::sync::Arc<antinomie_triage::net_attr::NetAttribution>,
    )> {
        let attribution = self.scan.as_ref()?.attribution.clone()?;
        let (_, _, run) = self.scan_request.identity.as_ref()?;
        Some((run.clone(), attribution))
    }

    /// An artifact the Run artifacts box was asked to open, once.
    pub(crate) fn take_open_artifact(
        &mut self,
    ) -> Option<crate::app::samples_page::detail::ArtifactOpen> {
        self.open_artifact.take()
    }

    /// Settings › Notifications: raise a toast for a HIGH finding of a live run.
    pub(crate) fn set_toast_high(&mut self, on: bool) {
        self.toast_high = on;
    }

    /// The absolute guest paths of the selected run's Changed files (observed
    /// operations). Rebuilt when the run's index is, never per frame.
    pub(crate) fn changed_paths(&self) -> Arc<std::collections::BTreeSet<String>> {
        self.changed_paths.clone()
    }

    /// Show the Properties section.
    pub(crate) fn show_properties(&mut self) {
        self.section = Section::Properties;
    }

    /// Show one indicator in the IOC section (see `ioc_view`).
    pub(crate) fn show_indicator(&mut self, ty: &str, value: &str, path: &str) {
        self.show_ioc_indicator(ty, value, path);
    }

    /// Show Detection on `engine`'s tab, filtered to the rule `rule_id`.
    pub(crate) fn show_rule(&mut self, engine: &str, rule_id: &str) {
        self.section = Section::Detection;
        self.detection.focus_rule(engine, rule_id);
    }

    /// Show one path in Files › Changed files: the table is filtered to it.
    pub(crate) fn show_changed_path(&mut self, ctx: &egui::Context, path: &str) {
        self.section = Section::Files;
        self.files = FileTab::Changed;
        self.history_tab = false;
        self.by_file = false;
        // A quote or backslash cannot be written in the filter's string.
        if !path.contains(['"', '\\']) && !path.chars().any(char::is_control) {
            let draft = format!("file.path == \"{path}\"");
            ctx.data_mut(|data| {
                data.insert_temp(
                    egui::Id::new(("triage-filter-draft", FileTab::Changed.slot())),
                    draft,
                );
            });
        }
    }

    /// Show one file in Files › Per-file history, with its reconstruction
    /// (where its bytes can be saved) open when `reconstruct`.
    pub(crate) fn show_file_history(&mut self, path: &str, reconstruct: bool) {
        self.section = Section::Files;
        self.history_tab = true;
        self.by_file = false;
        if reconstruct {
            self.file_history.reconstruct(path);
        } else {
            self.file_history.open_on(path);
        }
    }

    /// A path the Disks tab diff was asked to show from the Details.
    pub(crate) fn take_disk_jump(&self, ctx: &egui::Context) -> Option<String> {
        ctx.data_mut(|data| {
            data.remove_temp::<String>(egui::Id::new(crate::disk_view::DIFF_JUMP_KEY))
        })
    }

    pub(crate) fn tick(&mut self, ctx: &egui::Context, input: TriageInput<'_>) {
        let key = report_export::context_key(&input);
        if self.context_key.as_deref() != Some(&key) {
            self.stop_scan();
            details::clear(ctx);
            self.graph_window.close();
            self.context_key = Some(key);
        }
        if self.details_directory.as_deref() != input.archive {
            self.ioc.reset_run(input.archive);
        }
        self.details_directory = input.archive.map(Path::to_path_buf);
        self.ioc_tick(ctx);
        self.properties.tick(ctx, &input);
        self.detection
            .set_index(self.index_state(input.archive.is_some()));
        self.detection.tick(ctx, &input);
        self.scan_request.apply_input(&input);
        self.follow_report(&input);
        if input.archive.is_some() {
            self.schedule_refresh(ctx, input.run_finished);
        }
        self.ensure_scan(
            input.archive,
            input.pcap,
            input.pcap_open,
            input.vm_id,
            input.boot_id,
            input.run_id,
        );
        self.poll_scan(ctx);
        self.digest_tick();
        // A coalesced refresh starts in the same frame the previous scan ends.
        if self.refresh_requested {
            self.ensure_scan(
                input.archive,
                input.pcap,
                input.pcap_open,
                input.vm_id,
                input.boot_id,
                input.run_id,
            );
        }
    }
    /// Draw the open finding Details windows. Called once per frame, whichever
    /// triage section is showing.
    pub(crate) fn show_finding_windows(&mut self, ctx: &egui::Context) {
        self.detection.show_windows(ctx);
        self.show_graph_window(ctx);
        self.show_relations_window(ctx);
        self.show_report_dialog(ctx);
    }

    /// `Some(call_id)` on the frame a Suspicious activity row is clicked.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        input: TriageInput<'_>,
    ) -> Option<trace::InvocationKey> {
        if input.run_id.is_none() {
            self.tick(ui.ctx(), TriageInput::empty());
            no_run(ui);
            return None;
        }
        self.mark_shown(ui.ctx());
        presentation::navigation(self, ui, &input);
        self.tick(ui.ctx(), input);
        self.digest_banner(ui);
        if self.section == Section::Summary {
            summary::show(self, ui, &input);
            return self.take_navigation(ui.ctx());
        }
        if self.section == Section::Properties {
            self.properties.show(ui, &input);
            return self.take_navigation(ui.ctx());
        }
        if self.section == Section::Detection {
            self.detection.show(ui, self.scan.as_ref());
            return self.take_navigation(ui.ctx());
        }
        if self.section == Section::Ioc {
            self.ioc_section(ui, &input);
            return self.take_navigation(ui.ctx());
        }
        if self.section == Section::Bpf {
            self.refresh_row(ui, &input);
        }
        // The body of a table section is a page that scrolls when its filters
        // and notes leave a table under `MIN_TABLE_HEIGHT` of room: the pane
        // itself has no scroll area, so a table pushed below its bottom edge
        // could not be reached. The tables keep their own scroll area, sized
        // to what is left of the pane.
        let viewport = ui.available_height();
        let page = egui::Id::new(("triage-page", std::mem::discriminant(&self.section)));
        let jump = egui::ScrollArea::vertical()
            .id_salt(page)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_height(viewport);
                match self.section {
                    Section::Summary | Section::Properties | Section::Detection | Section::Ioc => {
                        None
                    }
                    Section::Process => self.process(ui, &input),
                    Section::Files => {
                        self.files(ui, &input);
                        None
                    }
                    Section::Network => {
                        crate::widgets::fact_line(ui, "Route", &self.route.headline);
                        self.new_network(ui, &input);
                        None
                    }
                    Section::Bpf => {
                        let indexed = self.scan.as_ref().map(|scan| scan.bpf.as_slice());
                        if self.scan.as_ref().is_some_and(|scan| scan.bpf_omitted > 0) {
                            crate::activity::info(ui, "Some BPF observations exceed the preview limit; original syscall evidence remains available.");
                        }
                        bpf_view(ui, &input, indexed);
                        None
                    }
                }
            })
            .inner;
        jump.or_else(|| self.take_navigation(ui.ctx()))
    }

    pub(crate) fn details(&mut self, ui: &mut egui::Ui) -> Option<trace::InvocationKey> {
        self.mark_shown(ui.ctx());
        details::show(self, ui);
        self.take_navigation(ui.ctx())
    }

    /// The scanned input whose row was clicked in Detection, if any.
    pub(crate) fn take_open_input(&self, ctx: &egui::Context) -> Option<OpenInput> {
        let id = egui::Id::new(OPEN_INPUT);
        ctx.data_mut(|data| {
            let input = data.get_temp::<OpenInput>(id);
            data.remove::<OpenInput>(id);
            input
        })
    }

    pub(crate) fn take_details_focus(&self, ctx: &egui::Context) -> bool {
        ctx.data_mut(|data| data.remove_temp::<bool>(egui::Id::new("triage-details-focus")))
            .unwrap_or(false)
    }

    fn take_navigation(&mut self, ctx: &egui::Context) -> Option<trace::InvocationKey> {
        self.packet_jump =
            ctx.data_mut(|data| data.remove_temp::<u64>(egui::Id::new("triage-packet-jump")));
        self.packet_capture = ctx.data_mut(|data| {
            data.remove_temp::<std::path::PathBuf>(egui::Id::new("triage-packet-capture"))
        });
        self.open_packets = ctx
            .data_mut(|data| data.remove_temp::<bool>(egui::Id::new(network::OPEN_PACKETS)))
            .unwrap_or(false);
        self.trace_scope = ctx.data_mut(|data| {
            data.remove_temp::<String>(egui::Id::new(process_details::TRACE_SCOPE))
        });
        if let Some(pid) = ctx
            .data_mut(|data| data.remove_temp::<u64>(egui::Id::new(process_details::PROCESS_SCOPE)))
        {
            self.scope_to_pid(ctx, Section::Process, pid);
        }
        ctx.data_mut(|data| {
            data.remove_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
        })
    }

    /// Original PCAP frame requested from a selected HTTP/DNS evidence row.
    pub(crate) fn take_packet_jump(&mut self) -> Option<u64> {
        self.packet_jump.take()
    }
    /// The Open Packets button was pressed.
    pub(crate) fn take_open_packets(&mut self) -> bool {
        std::mem::take(&mut self.open_packets)
    }
    /// The Trace filter a process's Details asked for.
    pub(crate) fn take_trace_scope(&mut self) -> Option<String> {
        self.trace_scope.take()
    }
    pub(crate) fn take_packet_capture(&mut self) -> Option<std::path::PathBuf> {
        self.packet_capture.take()
    }
    pub(crate) fn set_rules(
        &mut self,
        data_dir: &std::path::Path,
        automatic: bool,
        profile: &str,
        generation: u64,
    ) {
        self.detection.settings.rules_root = data_dir.display().to_string();
        self.detection.automatic = automatic;
        if self.detection.registry_for != generation || self.detection.registry.is_none() {
            self.detection.profile = profile.to_owned();
        }
        self.detection.rules_generation = generation;
    }

    /// When the selected run's process tree ended (host Unix ms), from the index on screen.
    pub(crate) fn run_ended_ms(&self) -> Option<u64> {
        self.scan.as_ref().and_then(|scan| scan.ended_ms)
    }

    /// Processes the index on screen saw no exit for: still alive when the recording stopped.
    pub(crate) fn alive_processes(&self) -> Option<u64> {
        let scan = self.scan.as_ref()?;
        let pids: std::collections::BTreeSet<u32> = scan
            .process
            .iter()
            .filter(|node| node.state == "exit not recorded")
            .map(|node| node.pid)
            .collect();
        Some(pids.len() as u64)
    }

    /// A note on a changed file asked for the setting that raises a rebuild limit.
    pub(crate) fn take_open_rebuild_limit(&mut self, ctx: &egui::Context) -> bool {
        ctx.data_mut(|data| {
            data.remove_temp::<bool>(egui::Id::new(change_view::OPEN_REBUILD_LIMIT))
                .unwrap_or(false)
        })
    }

    /// What Triage is doing now, for the Jobs window: preparing the recording,
    /// detection scans and the online Check.
    pub(crate) fn running_jobs(&self) -> Vec<crate::jobs::Job> {
        let mut out = Vec::new();
        if self.preparing() {
            out.push(
                crate::jobs::Job::new("triage-index", "Triage", "preparing the recording")
                    .state("Indexing")
                    .flag(self.scan_cancel.clone())
                    .open(crate::workspace::Panel::Triage),
            );
        }
        out.extend(self.detection.running_jobs());
        out.extend(self.ioc.running_jobs());
        out
    }

    pub(crate) fn take_rule_manager(&mut self) -> bool {
        std::mem::take(&mut self.detection.open_manager)
    }

    pub(crate) fn detection_settings(
        &mut self,
    ) -> &mut antinomie_monitor_core::analysis::detection::Settings {
        &mut self.detection.settings
    }

    fn process(
        &mut self,
        ui: &mut egui::Ui,
        input: &TriageInput<'_>,
    ) -> Option<trace::InvocationKey> {
        self.process_tabs(ui);
        match self.process {
            ProcessTab::Tree => {
                if let Some(scan) = &self.scan {
                    process_mermaid::copy_button(ui, &scan.process);
                    process_tree_nodes(
                        ui,
                        &scan.process,
                        scan.clock_anchor.or(input.clock_anchor),
                        &scan.suspicious,
                    );
                } else {
                    let suspicious =
                        suspicious_output(input.invocations, rules::Options::default()).tasks;
                    let nodes = process_nodes(input.invocations);
                    process_mermaid::copy_button(ui, &nodes);
                    process_tree_nodes(ui, &nodes, input.clock_anchor, &suspicious);
                }
                None
            }
            ProcessTab::Suspicious => {
                if let Some(scan) = &self.scan {
                    self.suspicious_findings(ui, scan.findings.clone(), scan.findings_omitted)
                } else {
                    self.suspicious(ui, input.invocations)
                }
            }
            ProcessTab::Graph => {
                self.graph_tab(ui);
                None
            }
        }
    }

    fn suspicious(
        &mut self,
        ui: &mut egui::Ui,
        invocations: &[InvocationSummary],
    ) -> Option<trace::InvocationKey> {
        self.suspicious_findings(ui, suspicious_rows(invocations), 0)
    }

    fn suspicious_findings(
        &mut self,
        ui: &mut egui::Ui,
        mut findings: Vec<Finding>,
        omitted: u64,
    ) -> Option<trace::InvocationKey> {
        if omitted > 0 {
            crate::activity::info(
                ui,
                format!("{omitted} rule matches are available on other query pages."),
            );
        }
        if let Some(scan) = &self.scan {
            for note in &scan.finding_notes {
                crate::activity::warning(ui, note.clone());
            }
        }
        self.query_bar(
            ui,
            0,
            FINDING_FIELDS,
            "finding.tier == high",
            (findings.len(), findings.len() as u64 + omitted),
            Bar::Findings,
        );
        let clock = self
            .scan
            .as_ref()
            .and_then(|scan| scan.clock_anchor)
            .or(self.scan_request.clock_anchor);
        let start = self.run_start();
        for finding in &mut findings {
            rules::stamp(finding, clock, start);
        }
        let rows = if self.scan.is_some() {
            findings
        } else {
            let view = self.scan_request.finding_view;
            let mut rows = filter_findings(findings, &self.scan_request.filters[0]);
            rows.retain(|row| rules::view_keeps(&view, &row.values));
            rows
        };
        let clicked = finding_table(
            ui,
            "triage-findings",
            rules::HEADERS,
            &rows,
            self.selected_call_id,
            self.table_focus.take(),
        );
        self.finding_requests(ui.ctx());
        if let Some(call_id) = clicked {
            self.selected_call_id = Some(call_id);
        }
        None
    }

    /// The filter bar of a table: the filter, then one row with the section's
    /// own controls (`bar`) and the pager.
    fn query_bar(
        &mut self,
        ui: &mut egui::Ui,
        index: usize,
        fields: &[FieldSpec<'_>],
        example: &str,
        (retained, total): (usize, u64),
        bar: Bar,
    ) {
        let draft_id = egui::Id::new(("triage-filter-draft", index));
        if let Some(draft) = ui
            .ctx()
            .data_mut(|data| data.remove_temp::<String>(draft_id))
        {
            self.filter_drafts[index] = draft;
        }
        let table_id = TABLE_IDS[index];
        if let Some(sort) = sorting::take_request(ui.ctx(), table_id) {
            // The sort runs on the full rows; a compact table draws a subset.
            self.scan_request.sorts[index] = sort.map(|mut sort| {
                sort.column = if index == 3 && self.section == Section::Network {
                    net_tabs::stored_url_column(sort.column)
                } else {
                    file_tabs::full_column(index, sort.column)
                };
                sort
            });
            self.scan_request.offsets[index] = 0;
            self.request_query_refresh();
        }
        ui.ctx().data_mut(|data| {
            data.insert_temp(egui::Id::new(("triage-filter-target", table_id)), draft_id);
        });
        ui.push_id(("triage-filter", index), |ui| {
            query::filter_edit_fields(
                ui,
                &mut self.filter_drafts[index],
                example,
                ui.available_width(),
                fields,
                &[],
            )
        });
        ui.ctx()
            .data_mut(|data| data.insert_temp(draft_id, self.filter_drafts[index].clone()));
        let compiled = query::compile_table(&self.filter_drafts[index], fields);
        if let Some(error) = compiled.error {
            crate::activity::inline_only(
                ui,
                crate::activity::Level::Warn,
                format!("{error}; showing the last valid filter"),
            );
        } else if self.scan_request.filters[index] != self.filter_drafts[index] {
            self.scan_request.filters[index] = self.filter_drafts[index].clone();
            self.scan_request.offsets[index] = 0;
            self.request_query_refresh();
        }
        if self.scan_key.is_some() || bar != Bar::Plain {
            ui.horizontal_wrapped(|ui| {
                if bar == Bar::Files {
                    self.file_toggles(ui);
                }
                if matches!(bar, Bar::Findings | Bar::Graph) {
                    self.finding_chips(ui);
                }
                if self.scan_key.is_some() && bar != Bar::Graph {
                    self.pager(ui, index, retained, total);
                }
                if let Bar::Network { packets } = bar {
                    network::open_packets_button(ui, packets);
                }
            });
        }
    }

    fn pager(&mut self, ui: &mut egui::Ui, index: usize, retained: usize, total: u64) {
        let offset = self.scan_request.offsets[index];
        let rows = self.scan_request.rows();
        let text = if offset == 0 && (retained as u64) < total {
            // The table stops at its page size: say so, and where to change it.
            format!(
                "first {} of {} matched (page size {}, Settings > Advanced)",
                crate::values::thousands(retained as u64),
                crate::values::thousands(total),
                crate::values::thousands(rows as u64)
            )
        } else {
            format!(
                "{}–{} of {} matched; page size {}",
                if retained == 0 { 0 } else { offset + 1 },
                offset + retained,
                crate::values::thousands(total),
                crate::values::thousands(rows as u64)
            )
        };
        ui.colored_label(theme::muted(), text);
        if ui
            .add_enabled(
                offset > 0 && self.scan_rx.is_none(),
                egui::Button::new("Previous"),
            )
            .clicked()
        {
            self.scan_request.offsets[index] = offset.saturating_sub(rows);
            self.request_query_refresh();
        }
        if ui
            .add_enabled(
                (offset + retained) < total as usize && self.scan_rx.is_none(),
                egui::Button::new("Next"),
            )
            .clicked()
        {
            self.scan_request.offsets[index] = offset + rows;
            self.request_query_refresh();
        }
    }
}

pub(crate) use not_started::not_started_panel;
pub(crate) use report_export::NotStartedRun;

/// Triage without a run selected: what it shows and how to get a run.
pub(crate) fn no_run(ui: &mut egui::Ui) {
    crate::widgets::info_panel(
        ui,
        &crate::widgets::InfoPanel {
            icon: egui_phosphor::regular::SHIELD_WARNING,
            title: "Select a run to view its triage",
            about: "Triage reads what a run recorded: the process tree, suspicious activity, \
                    files, network, eBPF, rule matches and file properties.",
            steps_title: "To triage a run",
            steps: &[
                "Start the VM.",
                "Open Run → Run program.",
                "Select the run in the list above or in Run History.",
            ],
        },
    );
}

impl Drop for TriageView {
    fn drop(&mut self) {
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests;
