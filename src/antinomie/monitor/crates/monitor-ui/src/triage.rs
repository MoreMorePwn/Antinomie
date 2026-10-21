// SPDX-License-Identifier: MIT
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
use antinomie_monitor_core::{EventSummary, InvocationSummary};
use eframe::egui::{self, RichText};
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

mod archive_scan;
mod auditd_events;
mod bpf_notes;
mod counts;
mod descriptors;
mod details;
mod detection;
mod file_category;
#[cfg(test)]
mod file_category_tests;
mod file_content;
mod file_events;
mod file_location;
mod file_tabs;
mod file_visibility;
mod files;
mod findings;
mod kernel_records;
mod network;
mod network_index;
mod normalized;
mod pcap_scan;
mod presentation;
mod process_details;
mod process_tree;
mod properties;
mod refresh;
#[cfg(test)]
mod refresh_tests;
mod sigma_events;
#[cfg(test)]
mod sigma_events_tests;
mod sorting;
pub(crate) use sorting::{current as sort_current, header as sort_header};
mod summary;
mod table;
#[cfg(test)]
mod torture_qa;
use self::{
    archive_scan::*, bpf_notes::*, descriptors::*, file_category::FILE_FIELDS, file_events::*,
    findings::*, pcap_scan::*, process_tree::*, refresh::*, table::*,
};
pub(crate) use network::AddressLookup;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Summary,
    Properties,
    Detection,
    Process,
    Files,
    Network,
    Bpf,
}

/// What a table's filter bar holds besides the filter and the pager.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bar {
    Plain,
    /// The Hide stdio, Hide library and Failed attempts toggles.
    Files,
    /// The Open Packets button, enabled when the run has a capture.
    Network {
        packets: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessTab {
    Tree,
    Suspicious,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FileTab {
    Opened,
    Created,
    Read,
    Written,
    Deleted,
    Renamed,
    Executed,
    Attributes,
    Probed,
    Other,
    Changed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NetTab {
    Ips,
    Hosts,
    Http,
    Dns,
    Sessions,
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
    network: NetTab,
    /// Case-insensitive substring for rule, process, summary, or evidence.
    /// Invocation chosen from a Suspicious activity row.
    selected_call_id: Option<trace::InvocationKey>,
    /// Archive directory and owned pcap, so a different capture starts a new index.
    scan_key: Option<String>,
    scan_cancel: Option<Arc<AtomicBool>>,
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
    /// Pass of the last frame that drew a pane using the index.
    shown_pass: Option<u64>,
    refresh_seconds: u64,
    bpf_export_status: String,
    scan_request: ScanRequest,
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
}

impl Default for TriageView {
    fn default() -> Self {
        Self {
            properties: properties::View::default(),
            detection: detection::View::default(),
            section: Section::Summary,
            process: ProcessTab::Tree,
            files: FileTab::Opened,
            network: NetTab::Http,
            selected_call_id: None,
            scan_key: None,
            scan_cancel: None,
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
            shown_pass: None,
            refresh_seconds: 5,
            bpf_export_status: String::new(),
            scan_request: ScanRequest::default(),
            filter_drafts: Default::default(),
            packet_jump: None,
            packet_capture: None,
            open_packets: false,
            trace_scope: None,
            context_key: None,
            details_directory: None,
            changed_paths: Arc::default(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TriageInput<'a> {
    pub analysis: Option<&'a antinomie_monitor_core::AnalysisReport>,
    pub invocations: &'a [InvocationSummary],
    pub vm_id: Option<&'a str>,
    pub boot_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    /// Saved recording directory. `None` for a live session or a single loaded page.
    pub archive: Option<&'a Path>,
    /// Pcap that belongs to this run. Absent means no packet index, not another capture.
    pub pcap: Option<&'a Path>,
    /// The pcap is still being written. The index reads the bytes present now.
    pub pcap_open: bool,
    pub clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    pub started_ms: Option<u64>,
    pub root_cookie: u64,
    pub run_finished: bool,
    /// The selected recording belongs to the currently running VM boot.
    pub current_boot: bool,
}

impl<'a> TriageInput<'a> {
    pub(crate) fn empty() -> Self {
        Self {
            analysis: None,
            invocations: &[],
            vm_id: None,
            boot_id: None,
            run_id: None,
            archive: None,
            pcap: None,
            pcap_open: false,
            clock_anchor: None,
            started_ms: None,
            root_cookie: 0,
            run_finished: false,
            current_boot: false,
        }
    }
    #[cfg(test)]
    fn page(invocations: &'a [InvocationSummary]) -> Self {
        Self {
            analysis: None,
            invocations,
            vm_id: None,
            boot_id: None,
            run_id: None,
            archive: None,
            pcap: None,
            pcap_open: false,
            clock_anchor: None,
            started_ms: None,
            root_cookie: 0,
            run_finished: false,
            current_boot: false,
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

    /// The absolute guest paths of the selected run's Changed files (observed
    /// operations). Rebuilt when the run's index is, never per frame.
    pub(crate) fn changed_paths(&self) -> Arc<std::collections::BTreeSet<String>> {
        self.changed_paths.clone()
    }

    /// Show the Properties section.
    pub(crate) fn show_properties(&mut self) {
        self.section = Section::Properties;
    }

    /// Show one path in Files › Changed files: the table is filtered to it.
    pub(crate) fn show_changed_path(&mut self, ctx: &egui::Context, path: &str) {
        self.section = Section::Files;
        self.files = FileTab::Changed;
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

    /// A path the Disks tab diff was asked to show from the Details.
    pub(crate) fn take_disk_jump(&self, ctx: &egui::Context) -> Option<String> {
        ctx.data_mut(|data| {
            data.remove_temp::<String>(egui::Id::new(crate::disk_view::DIFF_JUMP_KEY))
        })
    }

    pub(crate) fn tick(&mut self, ctx: &egui::Context, input: TriageInput<'_>) {
        let key = format!(
            "{}\n{}\n{}\n{}",
            input.vm_id.unwrap_or(""),
            input.boot_id.unwrap_or(""),
            input.run_id.unwrap_or(""),
            input
                .archive
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        );
        if self.context_key.as_deref() != Some(&key) {
            self.stop_scan();
            details::clear(ctx);
            self.context_key = Some(key);
        }
        self.details_directory = input.archive.map(Path::to_path_buf);
        self.properties.tick(ctx, &input);
        self.detection.tick(ctx, &input);
        self.scan_request.clock_anchor = input.clock_anchor;
        self.scan_request.started_ms = input.started_ms;
        self.scan_request.root_cookie = input.root_cookie;
        self.scan_request.run_finished = input.run_finished;
        self.scan_request.identity = input
            .vm_id
            .zip(input.boot_id)
            .zip(input.run_id)
            .map(|((vm, boot), run)| (vm.into(), boot.into(), run.into()));
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
    }

    /// `Some(call_id)` on the frame a Suspicious activity row is clicked.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        input: TriageInput<'_>,
    ) -> Option<trace::InvocationKey> {
        if input.run_id.is_none() {
            self.tick(ui.ctx(), TriageInput::empty());
            ui.weak("Select a program run to view triage.");
            return None;
        }
        self.mark_shown(ui.ctx());
        presentation::navigation(self, ui, &input);
        self.tick(ui.ctx(), input);
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
        if self.section == Section::Bpf {
            self.refresh_row(ui, &input);
        }
        let jump = match self.section {
            Section::Summary | Section::Properties | Section::Detection => None,
            Section::Process => {
                presentation::heading(ui, "Process activity", "");
                self.process(ui, &input)
            }
            Section::Files => {
                presentation::heading(ui, "File activity", "");
                self.files(ui, &input);
                None
            }
            Section::Network => {
                presentation::heading(ui, "Network activity", "");
                self.network(ui, &input);
                None
            }
            Section::Bpf => {
                presentation::heading(
                    ui,
                    "eBPF & seccomp",
                    "Captured programs, filters and their syscall evidence",
                );
                let indexed = self.scan.as_ref().map(|scan| scan.bpf.as_slice());
                if self.scan.as_ref().is_some_and(|scan| scan.bpf_omitted > 0) {
                    crate::activity::warning(ui, "Some BPF observations exceed the preview limit; original syscall evidence remains available.");
                }
                bpf_view(ui, &input, indexed);
                None
            }
        };
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
                    process_tree_nodes(
                        ui,
                        &scan.process,
                        scan.clock_anchor.or(input.clock_anchor),
                        &scan.suspicious,
                    );
                } else {
                    let mut suspicious = Suspicious::new();
                    for finding in suspicious_rows(input.invocations) {
                        tally(&mut suspicious, &finding.values);
                    }
                    process_tree_nodes(
                        ui,
                        &process_nodes(input.invocations),
                        input.clock_anchor,
                        &suspicious,
                    );
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
        }
    }

    fn network(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        self.network_tabs(ui);
        let index = match self.network {
            NetTab::Ips => 6,
            NetTab::Hosts => 7,
            NetTab::Http => 3,
            NetTab::Dns => 4,
            NetTab::Sessions => SESSION_SLOT,
        };
        let fields = match self.network {
            NetTab::Ips => network::IP_FIELDS,
            NetTab::Hosts => network::HOST_FIELDS,
            NetTab::Http => HTTP_FIELDS,
            NetTab::Dns => DNS_FIELDS,
            NetTab::Sessions => network::SESSION_FIELDS,
        };
        let example = match self.network {
            NetTab::Ips => "network.country == US",
            NetTab::Hosts => "network.hostname contains update",
            NetTab::Http => "http.method == GET",
            NetTab::Dns => "dns.name contains example",
            NetTab::Sessions => "session.alpn contains h2",
        };
        let (count, omitted) = self
            .scan
            .as_ref()
            .map_or((0, 0), |scan| match self.network {
                NetTab::Ips => (scan.ips.len(), scan.ips_omitted),
                NetTab::Hosts => (scan.hosts.len(), scan.hosts_omitted),
                NetTab::Http => (scan.http.len(), scan.http_omitted),
                NetTab::Dns => (scan.dns.len(), scan.dns_omitted),
                NetTab::Sessions => (scan.sessions.len(), scan.sessions_omitted),
            });
        let packets = input.pcap.is_some();
        self.query_bar(
            ui,
            index,
            fields,
            example,
            (count, count as u64 + omitted),
            Bar::Network { packets },
        );
        let Some(scan) = &self.scan else {
            theme::loading_weak(ui, "Indexing this run’s capture…");
            return;
        };
        if let Some(warning) = &scan.network_warning {
            crate::activity::warning(ui, warning);
        }
        match self.network {
            NetTab::Ips => {
                ui.weak(match self.scan_request.address_lookup {
                    AddressLookup::Tshark => "Local addresses show “-” and “local network”. Other rows use local TShark GeoIP data when it is configured.",
                    AddressLookup::Whois => "Local addresses show “-” and “local network”. Public addresses use dig and whois on this machine.",
                    AddressLookup::TsharkThenWhois => "Local addresses show “-” and “local network”. Public addresses use local TShark GeoIP, then dig and whois when country or organization is missing.",
                });
                table(
                    ui,
                    "triage-ips",
                    &["IP", "Country", "Organization"],
                    &scan.ips,
                );
            }
            NetTab::Hosts => table(
                ui,
                "triage-hosts",
                &[
                    "Hostname",
                    "Resolved / connected IPs",
                    "First seen",
                    "Last seen",
                    "Requests",
                    "Source",
                ],
                &scan.hosts,
            ),
            NetTab::Http => table(ui, "triage-http", HTTP_HEADERS, &scan.http),
            NetTab::Dns => table(ui, "triage-dns", DNS_HEADERS, &scan.dns),
            NetTab::Sessions => {
                ui.weak("TLS and QUIC hellos and SSH banners as TShark parsed them, without keys. Encrypted content stays encrypted.");
                table(ui, "triage-sessions", SESSION_HEADERS, &scan.sessions)
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
            crate::activity::warning(
                ui,
                format!("{omitted} rule matches are available on other query pages."),
            );
        }
        self.query_controls(
            ui,
            0,
            FINDING_FIELDS,
            "finding.severity == high",
            findings.len(),
            findings.len() as u64 + omitted,
        );
        let clock = self
            .scan
            .as_ref()
            .and_then(|scan| scan.clock_anchor)
            .or(self.scan_request.clock_anchor);
        for finding in &mut findings {
            finding.cells[5].text = crate::time_format::guest_ns(
                clock,
                files::number(&finding.values, "event.time_ns"),
            );
        }
        let rows = if self.scan.is_some() {
            findings
        } else {
            filter_findings(findings, &self.scan_request.filters[0])
        };
        let clicked = finding_table(
            ui,
            "triage-findings",
            &[
                "Rule",
                "Severity",
                "Process",
                "Summary",
                "Source",
                "Time",
                "Confidence",
                "Evidence",
                "Version",
                "Outcome",
            ],
            &rows,
            self.selected_call_id,
        );
        if let Some(call_id) = clicked {
            self.selected_call_id = Some(call_id);
        }
        None
    }

    fn query_controls(
        &mut self,
        ui: &mut egui::Ui,
        index: usize,
        fields: &[FieldSpec<'_>],
        example: &str,
        retained: usize,
        total: u64,
    ) {
        self.query_bar(ui, index, fields, example, (retained, total), Bar::Plain);
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
        let table_id = [
            "triage-findings",
            "triage-opened",
            "triage-changed",
            "triage-http",
            "triage-dns",
            "triage-read",
            "triage-ips",
            "triage-hosts",
            "triage-created",
            "triage-written",
            "triage-deleted",
            "triage-renamed",
            "triage-executed",
            "triage-attributes",
            "triage-probed",
            "triage-other",
        ][index];
        if let Some(sort) = sorting::take_request(ui.ctx(), table_id) {
            // The sort runs on the full rows; a compact table draws a subset.
            self.scan_request.sorts[index] = sort.map(|mut sort| {
                sort.column = file_tabs::full_column(index, sort.column);
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
            crate::activity::warning(ui, format!("{error}; showing the last valid filter"));
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
                if self.scan_key.is_some() {
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
        ui.colored_label(
            theme::muted(),
            format!(
                "{}–{} of {total} matched; page size {STORED_ROWS}",
                if retained == 0 { 0 } else { offset + 1 },
                offset + retained
            ),
        );
        if ui
            .add_enabled(
                offset > 0 && self.scan_rx.is_none(),
                egui::Button::new("Previous"),
            )
            .clicked()
        {
            self.scan_request.offsets[index] = offset.saturating_sub(STORED_ROWS);
            self.request_query_refresh();
        }
        if ui
            .add_enabled(
                (offset + retained) < total as usize && self.scan_rx.is_none(),
                egui::Button::new("Next"),
            )
            .clicked()
        {
            self.scan_request.offsets[index] = offset + STORED_ROWS;
            self.request_query_refresh();
        }
    }
}

impl Drop for TriageView {
    fn drop(&mut self) {
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
struct Cell {
    text: String,
    /// Taken from the palette of `theme`; read it through [`Cell::color`].
    color: egui::Color32,
    theme: theme::Theme,
    mono: bool,
    values: Vec<(&'static str, RowValue)>,
}

impl Cell {
    /// The text color in the theme that is active now, whichever one the row
    /// was indexed in.
    fn color(&self) -> egui::Color32 {
        theme::translate(self.color, self.theme, theme::theme())
    }
}

#[cfg(test)]
struct LimitedRows {
    rows: Vec<Vec<Cell>>,
    /// The loaded page is not truncated. Callers still observe this as false.
    stopped_early: bool,
}

#[derive(Clone)]
struct Finding {
    key: trace::InvocationKey,
    cells: Vec<Cell>,
    call_id: u64,
    values: Vec<(&'static str, RowValue)>,
}

const PROCESS_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::number("process.depth", "Observed tree depth"),
    FieldSpec::number("process.ppid", "Observed parent process ID"),
    FieldSpec::number("process.parent_cookie", "Observed stable parent identity"),
    FieldSpec::number("process.pid", "Observed TGID"),
    FieldSpec::number("process.tid", "Observed thread ID"),
    FieldSpec::number("process.cookie", "Stable task cookie"),
    FieldSpec::number(
        "process.suspicious",
        "Suspicious observations in this process",
    ),
    FieldSpec::text("process.exe", "Latest successful captured executable"),
    FieldSpec::tags("process.argv", "Captured exec argument strings"),
    FieldSpec::text(
        "process.state",
        "Recorded task exit, separately from tree completion",
    ),
    FieldSpec::number("process.first_ns", "First observed monotonic ns"),
    FieldSpec::number("process.last_ns", "Last observed monotonic ns"),
];

/// x86-64: clone, fork, vfork, clone3. `CLONE_THREAD` stays inside the parent.
/// `clone` reads that bit from `args[0]`. `clone3`'s `args[0]` is a pointer, so
/// its flags come only from a captured `clone_args` flags field.
const CLONE: u64 = 56;
const FORK: u64 = 57;
const VFORK: u64 = 58;
const CLONE3: u64 = 435;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const AT_FDCWD: u64 = (-100i64) as u64;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TaskKey {
    pid: u32,
    cookie: u64,
}

#[derive(Default)]
struct TaskNode {
    parent: Option<TaskKey>,
    comm: String,
    /// Fork return created this pid before any event identified its cookie.
    provisional: bool,
    tid: u32,
    root: bool,
    call_id: Option<trace::InvocationKey>,
    first_ns: Option<u64>,
    last_ns: Option<u64>,
    argv: Vec<String>,
    state: String,
    exec_history: Vec<String>,
    /// Joined argv of the committed exec, only when the whole vector was captured.
    command_line: Option<String>,
    /// The same vector kept as arguments, for the auditd `PROCTITLE` record.
    proctitle: Option<Vec<String>>,
}

enum Spawn {
    /// A new process. The returned pid is the child.
    Process,
    /// A thread, or clone3 whose flags were not captured. No parent/child edge.
    Skip,
}

struct ProcessNode {
    parent: Option<TaskKey>,
    call_id: Option<trace::InvocationKey>,
    depth: usize,
    pid: u32,
    cookie: u64,
    comm: String,
    parent_missing: bool,
    tid: u32,
    argv: Vec<String>,
    first_ns: Option<u64>,
    last_ns: Option<u64>,
    state: String,
    exec_history: Vec<String>,
}

const FINDING_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("finding.rule", "Stable activity rule"),
    FieldSpec::number("finding.version", "Rule version"),
    FieldSpec::text("finding.severity", "Activity severity, not malware verdict"),
    FieldSpec::text("finding.confidence", "Evidence confidence: high or limited"),
    FieldSpec::text("finding.source", "Rule reference"),
    FieldSpec::text("finding.summary", "Matching facts"),
    FieldSpec::boolean("finding.attempted", "A syscall attempt was recorded"),
    FieldSpec::boolean(
        "finding.success",
        "Observed nonnegative syscall exit; missing without exit",
    ),
    FieldSpec::number("process.pid", "Observed PID"),
    FieldSpec::text(
        "process.exe",
        "Captured executable active at this observation",
    ),
    FieldSpec::number("process.tid", "Observed TID"),
    FieldSpec::number("process.cookie", "Stable task cookie"),
    FieldSpec::number("event.id", "Original invocation ID"),
    FieldSpec::number("stream.id", "Recorded stream identity"),
    FieldSpec::number("syscall.ret", "Observed signed syscall return"),
    FieldSpec::number("event.time_ns", "Guest monotonic nanoseconds"),
    FieldSpec::tags("entry.tag", "Unavailable without a finding annotation"),
];

const HTTP_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Owning capture segment"),
    FieldSpec::number("frame.number", "Original request frame"),
    FieldSpec::number("frame.time_us", "Captured Unix microseconds"),
    FieldSpec::text("network.endpoints", "Recorded source and destination"),
    FieldSpec::text("http.method", "Request method"),
    FieldSpec::text("http.host", "Cleartext Host header"),
    FieldSpec::text("http.uri", "Cleartext request URI"),
    FieldSpec::text("http.version", "Observed HTTP version"),
    FieldSpec::number(
        "http.status",
        "Correlated response code; missing if unavailable",
    ),
    FieldSpec::boolean("entry.complete", "Decoded request completeness"),
    FieldSpec::text(
        "network.attribution",
        "Unknown unless socket identity supports exact attribution",
    ),
];
const DNS_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Owning capture segment"),
    FieldSpec::number("frame.number", "Original query frame"),
    FieldSpec::number("frame.time_us", "Captured Unix microseconds"),
    FieldSpec::text("network.endpoints", "Recorded source and destination"),
    FieldSpec::number("dns.id", "Transaction ID"),
    FieldSpec::text("dns.name", "Queried domain"),
    FieldSpec::text("dns.type", "Query type"),
    FieldSpec::text("dns.class", "Query class"),
    FieldSpec::text("dns.protocol", "UDP or TCP"),
    FieldSpec::number("dns.rcode", "Observed response code"),
    FieldSpec::tags("dns.answers", "Observed response answers"),
    FieldSpec::boolean("dns.retry", "Retry when backed by decoder evidence"),
];

#[derive(Clone, Default)]
struct ScanRequest {
    event_cache: Option<normalized::Cache>,
    sorts: [Option<sorting::Spec>; SLOTS],
    file_visibility: file_visibility::FileVisibility,
    owned_pcap: bool,
    clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    started_ms: Option<u64>,
    ended_ms: Option<u64>,
    root_cookie: u64,
    address_lookup: AddressLookup,
    run_finished: bool,
    /// Stamp of the index on screen; a recording with the same stamp is not read again.
    unchanged_since: Option<String>,
    identity: Option<(String, String, String)>,
    offsets: [usize; SLOTS],
    filters: [String; SLOTS],
}

const STORED_ROWS: usize = 2000;
/// Query tables with their own filter, sort and page: findings 0, opened 1,
/// changed 2, http 3, dns 4, read 5, ips 6, hosts 7, the file categories 8 to
/// 15, then the TLS, QUIC and SSH sessions.
const SLOTS: usize = 17;
/// Operation tabs with their own slot after the original eight.
const FILE_TABS: usize = 8;
const SESSION_SLOT: usize = 16;

struct FindingJournal {
    temp: std::path::PathBuf,
    destination: std::path::PathBuf,
    file: std::fs::File,
    size: u64,
}

/// One file tab's rows kept in memory, and the matches left out of them.
#[derive(Default)]
struct FileRows {
    rows: Vec<Vec<Cell>>,
    omitted: u64,
}

struct ArchiveScan {
    /// [`source_stamp`] of the recording when this index began.
    stamp: String,
    event_cache: Option<normalized::Cache>,
    counts: normalized::Counts,
    network_counts: Option<(u64, u64, u64)>,
    event_journal: Option<antinomie_monitor_core::analysis::detection::JournalSummary>,
    event_error: Option<String>,
    #[cfg(test)]
    coverage: String,
    clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    file_changes: Vec<files::Change>,
    bpf: Vec<BpfNote>,
    bpf_omitted: u64,
    read: Vec<Vec<Cell>>,
    read_omitted: u64,
    partial: bool,
    process: Vec<ProcessNode>,
    /// Suspicious observations per task, before the findings filter and page.
    suspicious: Suspicious,
    findings: Vec<Finding>,
    findings_omitted: u64,
    opened: Vec<Vec<Cell>>,
    opened_omitted: u64,
    changed: Vec<Vec<Cell>>,
    changed_omitted: u64,
    /// Operation tabs after Opened, in [`FileTab::slot`] order from slot 8.
    file_tabs: [FileRows; FILE_TABS],
    http: Vec<Vec<Cell>>,
    http_omitted: u64,
    dns: Vec<Vec<Cell>>,
    dns_omitted: u64,
    ips: Vec<Vec<Cell>>,
    ips_omitted: u64,
    hosts: Vec<Vec<Cell>>,
    hosts_omitted: u64,
    sessions: Vec<Vec<Cell>>,
    sessions_omitted: u64,
    network_warning: Option<String>,
}

struct PacketSpool {
    directory: std::path::PathBuf,
    rows: std::fs::File,
    offsets: std::fs::File,
    size: u64,
}

struct PacketIndex {
    /// Frame, destination IP and hostname counts before UI queries.
    counts: Option<(u64, u64, u64)>,
    coverage: String,
    http: Vec<Vec<Cell>>,
    http_omitted: u64,
    dns: Vec<Vec<Cell>>,
    dns_omitted: u64,
    ips: Vec<Vec<Cell>>,
    ips_omitted: u64,
    hosts: Vec<Vec<Cell>>,
    hosts_omitted: u64,
    sessions: Vec<Vec<Cell>>,
    sessions_omitted: u64,
    network_warning: Option<String>,
}

#[derive(Default)]
struct FdState {
    /// Images tracked in observation order, keyed by stable task identity.
    process_images: std::collections::BTreeMap<TaskKey, TaskNode>,
    /// `(owner cookie, owner pid, fd)` → path text captured for that descriptor.
    opened: std::collections::BTreeMap<(u64, u32, u64), String>,
    /// Child task → the task whose descriptor table it shares (`CLONE_FILES`).
    share: std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    /// Child task → the task whose working directory it shares (`CLONE_FS`).
    fs_share: std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    cwd: std::collections::BTreeMap<(u64, u32), String>,
    cwd_unverified: std::collections::BTreeSet<(u64, u32)>,
    cloexec: std::collections::BTreeSet<(u64, u32, u64)>,
    /// What the Sigma journal tracks beyond descriptors: sockets, known paths, DNS answers.
    journal: sigma_events::State,
}

enum DupKind {
    Return,
    Argument,
}

struct BpfNote {
    heading: String,
    outcome: String,
    /// Request phrase for a lifecycle step. Load, socket, and seccomp lines
    /// include `fd {result}` when the exit result is >= 0. Attach does too,
    /// unless an argument matches an earlier successful `BPF_PROG_LOAD` fd.
    lifecycle: Option<String>,
    /// Disassembly when the instruction image was identified exactly.
    translation: Option<String>,
    /// Classic socket-filter and seccomp bytes. Absent when no image was isolated.
    dump: Option<String>,
    /// Raw bytes, hash, and the identity fields that were present.
    export: Option<String>,
    /// Captured instruction bytes, when an image was isolated.
    bytes: Option<Vec<u8>>,
    identity: bpf::BpfIdentity,
}

#[cfg(test)]
mod tests;
