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
#[cfg(test)]
use antinomie_monitor_core::network::NetworkPacket;
use antinomie_monitor_core::{EventSummary, InvocationSummary};
use eframe::egui::{self, RichText};
mod archive_scan;
mod bpf_notes;
mod descriptors;
mod details;
mod detection;
mod file_content;
mod file_events;
mod file_visibility;
mod files;
mod findings;
mod network;
mod network_index;
mod normalized;
mod pcap_scan;
mod presentation;
mod process_tree;
mod properties;
mod sorting;
mod summary;
mod table;
#[cfg(test)]
mod traffic;
#[cfg(test)]
use self::traffic::*;
use self::{
    archive_scan::*, bpf_notes::*, descriptors::*, file_events::*, findings::*, pcap_scan::*,
    process_tree::*, table::*,
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessTab {
    Tree,
    Suspicious,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileTab {
    Opened,
    Read,
    Changed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NetTab {
    Ips,
    Hosts,
    Http,
    Dns,
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
    refresh_requested: bool,
    /// A refresh arrived while an index was already running.
    refresh_queued: bool,
    refresh_seconds: u64,
    bpf_export_status: String,
    scan_request: ScanRequest,
    filter_drafts: [String; 8],
    packet_jump: Option<u64>,
    packet_capture: Option<std::path::PathBuf>,
    context_key: Option<String>,
    details_directory: Option<std::path::PathBuf>,
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
            refresh_requested: false,
            refresh_queued: false,
            refresh_seconds: 5,
            bpf_export_status: String::new(),
            scan_request: ScanRequest::default(),
            filter_drafts: Default::default(),
            packet_jump: None,
            packet_capture: None,
            context_key: None,
            details_directory: None,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TriageInput<'a> {
    pub analysis: Option<&'a antinomie_monitor_core::AnalysisReport>,
    pub invocations: &'a [InvocationSummary],
    #[cfg(test)]
    pub packets: &'a [NetworkPacket],
    /// Ethernet frames parallel to `packets`. Absent when the list has no payload.
    #[cfg(test)]
    pub frames: Option<&'a [Vec<u8>]>,
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
}

impl<'a> TriageInput<'a> {
    pub(crate) fn empty() -> Self {
        Self {
            analysis: None,
            invocations: &[],
            #[cfg(test)]
            packets: &[],
            #[cfg(test)]
            frames: None,
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
        }
    }
    #[cfg(test)]
    fn page(invocations: &'a [InvocationSummary], packets: &'a [NetworkPacket]) -> Self {
        Self {
            analysis: None,
            invocations,
            packets,
            frames: None,
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
        }
    }
}

impl TriageView {
    /// Maintain the selected run's index even when the Triage pane is hidden.
    /// Identity changes cancel old jobs; refreshes coalesce into one next scan.
    pub(crate) fn set_address_lookup(&mut self, mode: AddressLookup) {
        if self.scan_request.address_lookup != mode {
            self.scan_request.address_lookup = mode;
            self.refresh_requested = true;
        }
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
            if self.next_refresh.is_some_and(|due| Instant::now() >= due) {
                self.refresh_requested = true;
                self.next_refresh = None;
            }
            ctx.request_repaint_after(Duration::from_secs(self.refresh_seconds));
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
        presentation::navigation(self, ui);
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
        ui.horizontal_wrapped(|ui| {
            if self.section == Section::Files {
                let visibility = &mut self.scan_request.file_visibility;
                let changed = ui.checkbox(&mut visibility.hide_standard_io, "Hide stdin, stdout, stderr").changed()
                    | ui.checkbox(&mut visibility.hide_libraries, "Hide library").changed();
                if changed {
                    for index in [1, 2, 5] { self.scan_request.offsets[index] = 0; }
                    self.request_query_refresh();
                }
            }
            if ui
                .add_enabled(input.archive.is_some(), egui::Button::new("Refresh"))
                .on_disabled_hover_text("A whole-run index starts after the recording is saved")
                .clicked()
            {
                self.refresh_requested = true;
                self.ensure_scan(
                    input.archive,
                    input.pcap,
                    input.pcap_open,
                    input.vm_id,
                    input.boot_id,
                    input.run_id,
                );
            }
            ui.label("Every");
            if ui
                .add(
                    egui::DragValue::new(&mut self.refresh_seconds)
                        .range(1..=300)
                        .suffix(" s"),
                )
                .changed()
            {
                self.refresh_seconds = self.refresh_seconds.clamp(1, 300);
                self.next_refresh =
                    Some(Instant::now() + Duration::from_secs(self.refresh_seconds));
            }
            ui.colored_label(theme::muted(), self.refresh_status(&input));
            if self.section == Section::Network {
                ui.weak("PCAP time").on_hover_text("Packet timestamps use QEMU's capture clock, displayed in the host timezone. They may differ from the host run clock; capture ownership determines which run is indexed.");
            } else {
                ui.weak("Host time").on_hover_text("Times use the host timezone. ~ marks a guest event time estimated from a host receipt/start anchor, including transport latency.");
            }
        });
        let jump = match self.section {
            Section::Summary | Section::Properties | Section::Detection => None,
            Section::Process => {
                presentation::heading(
                    ui,
                    "Process activity",
                    "Process relationships and observed behavior",
                );
                self.process(ui, &input)
            }
            Section::Files => {
                presentation::heading(
                    ui,
                    "File activity",
                    "Observed access, captured reads and file changes",
                );
                self.files(ui, &input);
                None
            }
            Section::Network => {
                presentation::heading(
                    ui,
                    "Network activity",
                    "Destinations, hosts and recorded requests",
                );
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
                    ui.colored_label(theme::warn(), "Some BPF observations exceed the preview limit; original syscall evidence remains available.");
                }
                bpf_view(ui, &input, indexed);
                None
            }
        };
        jump.or_else(|| self.take_navigation(ui.ctx()))
    }

    pub(crate) fn details(&mut self, ui: &mut egui::Ui) -> Option<trace::InvocationKey> {
        details::show(self, ui);
        self.take_navigation(ui.ctx())
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
        ctx.data_mut(|data| {
            data.remove_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
        })
    }

    /// Original PCAP frame requested from a selected HTTP/DNS evidence row.
    pub(crate) fn take_packet_jump(&mut self) -> Option<u64> {
        self.packet_jump.take()
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
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.process, ProcessTab::Tree, "Process tree");
            ui.selectable_value(
                &mut self.process,
                ProcessTab::Suspicious,
                "Suspicious activity",
            );
        });
        match self.process {
            ProcessTab::Tree => {
                if let Some(scan) = &self.scan {
                    process_tree_nodes(ui, &scan.process, scan.clock_anchor.or(input.clock_anchor));
                } else {
                    process_tree_nodes(ui, &process_nodes(input.invocations), input.clock_anchor);
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

    fn files(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.files, FileTab::Opened, "Opened files");
            ui.selectable_value(&mut self.files, FileTab::Read, "Read files");
            ui.selectable_value(&mut self.files, FileTab::Changed, "Changed files");
        });
        let index = match self.files {
            FileTab::Opened => 1,
            FileTab::Read => 5,
            FileTab::Changed => 2,
        };
        let (retained, total) = self.scan.as_ref().map_or((0, 0), |scan| {
            let (rows, omitted) = match self.files {
                FileTab::Opened => (&scan.opened, scan.opened_omitted),
                FileTab::Read => (&scan.read, scan.read_omitted),
                FileTab::Changed => (&scan.changed, scan.changed_omitted),
            };
            (rows.len(), rows.len() as u64 + omitted)
        });
        self.query_controls(ui, index, FILE_FIELDS, retained, total);
        let Some(scan) = &self.scan else {
            ui.weak("Indexing this run’s files…");
            return;
        };
        let clock = scan.clock_anchor.or(input.clock_anchor);
        match self.files {
            FileTab::Opened => {
                let rows: Vec<_> = scan
                    .opened
                    .iter()
                    .map(|row| files::opened_row(row, clock))
                    .collect();
                table(
                    ui,
                    "triage-opened",
                    &["Time", "Path", "Process (PID / TID)", "Result", "Evidence"],
                    &rows,
                );
            }
            FileTab::Read => {
                let mut rows = scan.read.clone();
                for row in &mut rows {
                    row[0].text = crate::time_format::guest_ns(
                        clock,
                        files::number(&row[0].values, "event.time_ns"),
                    );
                }
                table(
                    ui,
                    "triage-read",
                    &[
                        "Time",
                        "Path",
                        "Process (PID / TID)",
                        "Transferred / content",
                        "Result",
                        "Evidence",
                    ],
                    &rows,
                );
            }
            FileTab::Changed => {
                egui::ScrollArea::horizontal()
                    .id_salt("changed-file-columns")
                    .show(ui, |ui| {
                        ui.set_min_width(930.0);
                        table_rows(
                            ui,
                            "triage-changed",
                            &[
                                "Time",
                                "Path",
                                "Process (PID / TID)",
                                "Diff count",
                                "Evidence",
                            ],
                            &scan.changed,
                        );
                    });
                details::refresh(
                    ui.ctx(),
                    "triage-changed",
                    &[
                        "Time",
                        "Path",
                        "Process (PID / TID)",
                        "Diff count",
                        "Evidence",
                    ],
                    &scan.changed,
                );
            }
        }
    }

    fn network(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.network, NetTab::Ips, "IPs");
            ui.selectable_value(&mut self.network, NetTab::Hosts, "Hosts");
            ui.selectable_value(&mut self.network, NetTab::Http, "HTTP");
            ui.selectable_value(&mut self.network, NetTab::Dns, "DNS");
        });
        let index = match self.network {
            NetTab::Ips => 6,
            NetTab::Hosts => 7,
            NetTab::Http => 3,
            NetTab::Dns => 4,
        };
        let fields = match self.network {
            NetTab::Ips => network::IP_FIELDS,
            NetTab::Hosts => network::HOST_FIELDS,
            NetTab::Http => HTTP_FIELDS,
            NetTab::Dns => DNS_FIELDS,
        };
        let (count, omitted) = self
            .scan
            .as_ref()
            .map_or((0, 0), |scan| match self.network {
                NetTab::Ips => (scan.ips.len(), scan.ips_omitted),
                NetTab::Hosts => (scan.hosts.len(), scan.hosts_omitted),
                NetTab::Http => (scan.http.len(), scan.http_omitted),
                NetTab::Dns => (scan.dns.len(), scan.dns_omitted),
            });
        self.query_controls(ui, index, fields, count, count as u64 + omitted);
        let Some(scan) = &self.scan else {
            ui.weak("Indexing this run’s capture…");
            return;
        };
        if let Some(warning) = &scan.network_warning {
            ui.colored_label(theme::warn(), warning);
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
        }
        let _ = input;
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
        ui.colored_label(
            theme::muted(),
            "A row is a rule match with its source. It is not a verdict that the sample is malicious.",
        );
        if omitted > 0 {
            ui.colored_label(
                theme::warn(),
                format!("{omitted} rule matches are available on other query pages."),
            );
        }
        self.query_controls(
            ui,
            0,
            FINDING_FIELDS,
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
        retained: usize,
        total: u64,
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
        ][index];
        if let Some(sort) = sorting::take_request(ui.ctx(), table_id) {
            self.scan_request.sorts[index] = sort;
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
                "Filter observed fields",
                ui.available_width(),
                fields,
                &[],
            )
        });
        ui.ctx()
            .data_mut(|data| data.insert_temp(draft_id, self.filter_drafts[index].clone()));
        let compiled = query::compile_table(&self.filter_drafts[index], fields);
        if let Some(error) = compiled.error {
            ui.colored_label(
                theme::warn(),
                format!("{error}; showing the last valid filter"),
            );
        } else if self.scan_request.filters[index] != self.filter_drafts[index] {
            self.scan_request.filters[index] = self.filter_drafts[index].clone();
            self.scan_request.offsets[index] = 0;
            self.request_query_refresh();
        }
        if self.scan_key.is_some() {
            let offset = self.scan_request.offsets[index];
            ui.horizontal_wrapped(|ui| {
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
            });
        }
    }

    fn request_query_refresh(&mut self) {
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.pending_generation = None;
        self.refresh_requested = true;
    }

    fn refresh_status(&self, input: &TriageInput<'_>) -> String {
        if self.scan_rx.is_some() {
            return self.last_refresh.map_or_else(
                || "Indexing the saved recording".into(),
                |when| {
                    format!(
                        "Refreshing; showing index from {} s ago",
                        when.elapsed().as_secs()
                    )
                },
            );
        }
        if let Some(error) = &self.scan_error {
            return format!("Refresh failed: {error}");
        }
        if let Some(when) = self.last_refresh {
            return format!(
                "Refreshed {} s ago{}",
                when.elapsed().as_secs(),
                if self.scan.as_ref().is_some_and(|scan| scan.partial) {
                    "; partial evidence"
                } else {
                    ""
                }
            );
        }
        if input.archive.is_some() {
            "Waiting to index the saved recording".into()
        } else {
            "Waiting for recorded evidence".into()
        }
    }

    fn ensure_scan(
        &mut self,
        archive: Option<&Path>,
        pcap: Option<&Path>,
        pcap_open: bool,
        vm_id: Option<&str>,
        boot_id: Option<&str>,
        run_id: Option<&str>,
    ) {
        let Some(path) = archive else {
            if self.scan_key.is_some() || self.scan_rx.is_some() {
                self.stop_scan();
            }
            return;
        };
        let key = format!(
            "{}\n{}\n{}\n{}\n{}",
            path.display(),
            pcap.map(|file| file.display().to_string())
                .unwrap_or_default(),
            vm_id.unwrap_or(""),
            boot_id.unwrap_or(""),
            run_id.unwrap_or("")
        );
        if self.scan_key.as_deref() != Some(key.as_str()) {
            self.stop_scan();
            self.scan_key = Some(key);
            self.refresh_requested = true;
        }
        if self.scan_rx.is_some() {
            if self.refresh_requested {
                self.refresh_queued = true;
                self.refresh_requested = false;
            }
            return;
        }
        if !self.refresh_requested {
            return;
        }
        self.refresh_requested = false;
        self.refresh_queued = false;
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let directory = path.to_path_buf();
        let pcap = pcap.map(Path::to_path_buf);
        let cancel_thread = Arc::clone(&cancel);
        let mut request = self.scan_request.clone();
        request.event_cache = self.scan.as_ref().and_then(|scan| scan.event_cache.clone());
        self.scan_generation = self.scan_generation.saturating_add(1);
        let generation = self.scan_generation;
        if std::thread::Builder::new()
            .name("triage-index".into())
            .spawn(move || {
                let _ = tx.send((
                    generation,
                    scan_archive_query(
                        &directory,
                        pcap.as_deref(),
                        pcap_open,
                        &cancel_thread,
                        &request,
                    ),
                ));
            })
            .is_err()
        {
            self.scan_error = Some("could not start the saved-recording index".into());
            return;
        }
        self.pending_generation = Some(generation);
        self.scan_cancel = Some(cancel);
        self.scan_rx = Some(rx);
        self.next_refresh = Some(Instant::now() + Duration::from_secs(self.refresh_seconds));
    }

    fn poll_scan(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.scan_rx else {
            return;
        };
        match rx.try_recv() {
            Ok((generation, result)) => {
                self.scan_rx = None;
                self.scan_cancel = None;
                if self.pending_generation == Some(generation) {
                    match result {
                        Ok(scan) => {
                            if self.selected_call_id.is_some_and(|call_id| {
                                !scan.findings.iter().any(|finding| finding.key == call_id)
                            }) {
                                self.selected_call_id = None;
                            }
                            self.scan = Some(scan);
                            self.scan_error = None;
                            self.last_refresh = Some(Instant::now());
                        }
                        Err(error) if error == "cancelled" => {}
                        Err(error) => self.scan_error = Some(error),
                    }
                }
                if self.refresh_queued {
                    self.refresh_queued = false;
                    self.refresh_requested = true;
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.scan_error =
                    Some("saved-recording index stopped before reporting a result".into());
                self.scan_rx = None;
                if self.refresh_queued {
                    self.refresh_queued = false;
                    self.refresh_requested = true;
                }
            }
        }
    }

    fn stop_scan(&mut self) {
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.scan_generation = self.scan_generation.saturating_add(1);
        self.pending_generation = None;
        self.scan_key = None;
        self.scan_cancel = None;
        self.scan_rx = None;
        self.scan = None;
        self.scan_error = None;
        self.last_refresh = None;
        self.next_refresh = None;
        self.refresh_requested = false;
        self.refresh_queued = false;
        self.selected_call_id = None;
        self.bpf_export_status.clear();
        self.packet_jump = None;
        self.packet_capture = None;
        self.scan_request.offsets = [0; 8];
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
    color: egui::Color32,
    mono: bool,
    values: Vec<(&'static str, RowValue)>,
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

const FILE_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text(
        "process.exe",
        "Captured executable active at this file operation",
    ),
    FieldSpec::boolean(
        "file.standard_io",
        "Changed-file group contains only operations on stdin/stdout/stderr",
    ),
    FieldSpec::number(
        "file.diff_count",
        "Known differing bytes; gaps are separate",
    ),
    FieldSpec::boolean(
        "file.complete",
        "Original and final contents fully available",
    ),
    FieldSpec::number("file.read_size", "Successful read length"),
    FieldSpec::text("file.content", "Captured transferred content preview"),
    FieldSpec::text(
        "file.path",
        "Path as displayed; inferred names label their uncertainty",
    ),
    FieldSpec::text("file.old_path", "Captured old rename path"),
    FieldSpec::text("file.new_path", "Captured new rename path"),
    FieldSpec::number(
        "file.fd",
        "Observed descriptor; missing without success/provenance",
    ),
    FieldSpec::text("file.operation", "Observed syscall operation"),
    FieldSpec::text("file.access", "Requested access/creation flags"),
    FieldSpec::boolean(
        "file.success",
        "Observed syscall outcome; missing without exit",
    ),
    FieldSpec::number(
        "file.written_size",
        "Successful written octets, not requested length",
    ),
    FieldSpec::number(
        "file.requested_size",
        "Requested scalar write length in octets",
    ),
    FieldSpec::number("file.offset", "Captured pwrite offset in octets"),
    FieldSpec::number("file.count", "One observed operation per evidence row"),
    FieldSpec::number("process.pid", "Observed PID"),
    FieldSpec::number("process.tid", "Observed TID"),
    FieldSpec::number("process.cookie", "Stable task cookie"),
    FieldSpec::number("event.id", "Original invocation ID"),
    FieldSpec::number("stream.id", "Recorded stream identity"),
    FieldSpec::number("event.time_ns", "Guest monotonic nanoseconds"),
    FieldSpec::number("syscall.ret", "Signed observed exit result"),
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
    sorts: [Option<sorting::Spec>; 8],
    file_visibility: file_visibility::FileVisibility,
    owned_pcap: bool,
    clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    started_ms: Option<u64>,
    ended_ms: Option<u64>,
    root_cookie: u64,
    address_lookup: AddressLookup,
    run_finished: bool,
    identity: Option<(String, String, String)>,
    offsets: [usize; 8],
    filters: [String; 8],
}

const STORED_ROWS: usize = 2000;

struct FindingJournal {
    temp: std::path::PathBuf,
    destination: std::path::PathBuf,
    file: std::fs::File,
    size: u64,
}

struct ArchiveScan {
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
    findings: Vec<Finding>,
    findings_omitted: u64,
    opened: Vec<Vec<Cell>>,
    opened_omitted: u64,
    changed: Vec<Vec<Cell>>,
    changed_omitted: u64,
    http: Vec<Vec<Cell>>,
    http_omitted: u64,
    dns: Vec<Vec<Cell>>,
    dns_omitted: u64,
    ips: Vec<Vec<Cell>>,
    ips_omitted: u64,
    hosts: Vec<Vec<Cell>>,
    hosts_omitted: u64,
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
