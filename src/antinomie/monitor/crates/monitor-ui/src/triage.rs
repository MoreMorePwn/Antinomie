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
mod details;
mod file_content;
mod file_visibility;
mod files;
mod network;
mod properties;
mod sorting;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Properties,
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
    context_key: Option<String>,
    details_directory: Option<std::path::PathBuf>,
}

impl Default for TriageView {
    fn default() -> Self {
        Self {
            properties: properties::View::default(),
            section: Section::Process,
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
        ui.horizontal_wrapped(|ui| {
            for (section, label) in [
                (Section::Properties, "Properties"),
                (Section::Process, "Process"),
                (Section::Files, "Files"),
                (Section::Network, "Network activity"),
                (Section::Bpf, "eBPF"),
            ] {
                ui.selectable_value(&mut self.section, section, label);
            }
        });
        ui.separator();
        self.tick(ui.ctx(), input);
        if self.section == Section::Properties {
            self.properties.show(ui, &input);
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
            Section::Properties => None, // Its independent controls are rendered above.
            Section::Process => self.process(ui, &input),
            Section::Files => {
                self.files(ui, &input);
                None
            }
            Section::Network => {
                self.network(ui, &input);
                None
            }
            Section::Bpf => {
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
        ctx.data_mut(|data| {
            data.remove_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))
        })
    }

    /// Original PCAP frame requested from a selected HTTP/DNS evidence row.
    pub(crate) fn take_packet_jump(&mut self) -> Option<u64> {
        self.packet_jump.take()
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
                ui.weak("Country and organization use local TShark GeoIP data when configured.");
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
        let request = self.scan_request.clone();
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

fn cell(text: impl Into<String>, color: egui::Color32, mono: bool) -> Cell {
    Cell {
        text: text.into(),
        color,
        mono,
        values: Vec::new(),
    }
}

/// Keep the unresolved directory reason in Details while shortening table text.
fn display_cell(text: &str) -> String {
    text.replace("(relative, cwd not recorded)", "(relative)")
        .replace("(relative, dirfd not recorded)", "(relative)")
}

#[cfg(test)]
struct LimitedRows {
    rows: Vec<Vec<Cell>>,
    /// The loaded page is not truncated. Callers still observe this as false.
    stopped_early: bool,
}

#[cfg(test)]
fn push_limited(limited: &mut LimitedRows, row: Vec<Cell>) -> bool {
    limited.rows.push(row);
    true
}

fn column_widths<'a>(
    ui: &egui::Ui,
    headers: &[&str],
    rows: impl Iterator<Item = &'a [Cell]> + Clone,
) -> Vec<f32> {
    headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            let (minimum, maximum) = match *header {
                "Endpoint" | "Endpoints" => (360.0_f32, 900.0_f32),
                "Path" | "URI" | "Hostname" | "Transferred / content" | "Argv" => (250.0, 650.0),
                "Time" | "First seen" | "Last seen" => (230.0, 500.0),
                "Host" => (160.0, 400.0),
                "Summary" => (360.0, 800.0),
                _ => (100.0, 320.0),
            };
            let heading = ui.fonts(|fonts| {
                fonts
                    .layout_no_wrap(
                        (*header).to_owned(),
                        egui::TextStyle::Body.resolve(ui.style()),
                        theme::text(),
                    )
                    .size()
                    .x
            }) + 24.0;
            let content = rows
                .clone()
                .take(128)
                .filter_map(|row| row.get(index))
                .max_by_key(|cell| cell.text.chars().count())
                .map_or(0.0, |cell| {
                    let font = if cell.mono {
                        egui::TextStyle::Monospace.resolve(ui.style())
                    } else {
                        egui::TextStyle::Body.resolve(ui.style())
                    };
                    ui.fonts(|fonts| {
                        fonts
                            .layout_no_wrap(cell.text.chars().take(256).collect(), font, cell.color)
                            .size()
                            .x
                    }) + 24.0
                });
            content.max(minimum).max(heading).min(maximum.max(heading))
        })
        .collect()
}

fn table(ui: &mut egui::Ui, id: &str, headers: &[&str], rows: &[Vec<Cell>]) {
    egui::ScrollArea::horizontal()
        .id_salt((id, "columns"))
        .auto_shrink([false, true])
        .show(ui, |ui| table_rows(ui, id, headers, rows));
    details::refresh(ui.ctx(), id, headers, rows);
}

fn evidence_key(row: &[Cell]) -> String {
    let identity = evidence_values_key(
        row.first()
            .map(|cell| cell.values.as_slice())
            .unwrap_or_default(),
    );
    if identity.is_empty() {
        row.iter()
            .map(|cell| cell.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        identity
    }
}

fn evidence_values_key(values: &[(&str, RowValue)]) -> String {
    values
        .iter()
        .filter(|(name, _)| {
            matches!(
                *name,
                "event.id"
                    | "stream.id"
                    | "frame.number"
                    | "dns.name"
                    | "http.uri"
                    | "process.cookie"
                    | "finding.rule"
            )
        })
        .map(|(name, value)| format!("{name}:{value:?}"))
        .collect::<Vec<_>>()
        .join("/")
}

fn request_evidence_jump(ctx: &egui::Context, values: &[(&str, RowValue)]) {
    if let Some(key) = files::number(values, "stream.id")
        .zip(files::number(values, "process.cookie"))
        .zip(files::number(values, "event.id"))
    {
        let ((stream, task), call) = key;
        ctx.data_mut(|data| {
            data.insert_temp(egui::Id::new("triage-call-jump"), (stream, task, call))
        });
    } else if let Some(frame) = files::number(values, "frame.number") {
        ctx.data_mut(|data| data.insert_temp(egui::Id::new("triage-packet-jump"), frame));
    }
}

fn table_rows(ui: &mut egui::Ui, id: &str, headers: &[&str], rows: &[Vec<Cell>]) {
    use egui_extras::{Column, TableBuilder};
    if rows.is_empty() {
        ui.colored_label(theme::muted(), "Nothing recorded for this view.");
        return;
    }
    let widths = column_widths(ui, headers, rows.iter().map(Vec::as_slice));
    let order = sorting::order(ui.ctx(), id, headers, rows.iter().map(Vec::as_slice));
    ui.set_width(
        (widths.iter().sum::<f32>()
            + ui.spacing().item_spacing.x * headers.len().saturating_sub(1) as f32
            + 16.0)
            .max(ui.available_width()),
    );
    let row_height = ui.text_style_height(&egui::TextStyle::Body).max(14.0) + 8.0;
    let selected_id = egui::Id::new(("triage-selected-row", id));
    let selected = ui.ctx().data(|data| data.get_temp::<String>(selected_id));
    let filter_id = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new(("triage-filter-target", id))));
    let max_height = ui.available_height().max(60.0);
    let mut builder = TableBuilder::new(ui)
        .id_salt(("triage-062", id))
        .striped(true)
        .resizable(true)
        .vscroll(true)
        .max_scroll_height(max_height)
        .min_scrolled_height(0.0)
        .sense(egui::Sense::click());
    for (index, width) in widths.into_iter().enumerate() {
        let minimum = if matches!(headers[index], "Time" | "Endpoint" | "Endpoints") {
            width
        } else {
            64.0
        };
        builder = if index + 1 == headers.len() {
            builder.column(Column::remainder().at_least(width))
        } else {
            builder.column(Column::initial(width).at_least(minimum).resizable(true))
        };
    }
    builder
        .header(row_height, |mut header| {
            for (column, title) in headers.iter().enumerate() {
                header.col(|ui| {
                    sorting::header(ui, id, column, title);
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let cells = &rows[order
                    .as_ref()
                    .map_or(row.index(), |order| order[row.index()])];
                let key = evidence_key(cells);
                row.set_selected(selected.as_ref() == Some(&key));
                for cell in cells {
                    row.col(|ui| {
                        let mut text = RichText::new(display_cell(&cell.text)).color(cell.color);
                        if cell.mono {
                            text = text.monospace();
                        }
                        ui.add(
                            egui::Label::new(text)
                                .truncate()
                                .selectable(false)
                                .sense(egui::Sense::hover()),
                        );
                    });
                }
                if row.response().clicked() {
                    details::select(&row.response().ctx, id, headers, cells);
                    details::clicked(&row.response().ctx, id);
                    row.response()
                        .ctx
                        .data_mut(|data| data.insert_temp(selected_id, key));
                }
                if row.response().double_clicked() {
                    request_evidence_jump(
                        &row.response().ctx,
                        cells
                            .first()
                            .map(|cell| cell.values.as_slice())
                            .unwrap_or_default(),
                    );
                }
                if let Some(filter_id) = filter_id {
                    row.response().context_menu(|ui| {
                        query::table_row_menu(
                            ui,
                            filter_id,
                            cells
                                .first()
                                .map(|cell| cell.values.as_slice())
                                .unwrap_or_default(),
                        );
                    });
                }
            });
        });
}

#[derive(Clone)]
struct Finding {
    key: trace::InvocationKey,
    cells: Vec<Cell>,
    call_id: u64,
    values: Vec<(&'static str, RowValue)>,
}

/// Suspicious-activity rows. A click returns that invocation's `call_id`.
fn finding_table(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Finding],
    selected: Option<trace::InvocationKey>,
) -> Option<trace::InvocationKey> {
    let clicked = egui::ScrollArea::horizontal()
        .id_salt((id, "columns"))
        .auto_shrink([false, true])
        .show(ui, |ui| finding_table_rows(ui, id, headers, rows, selected))
        .inner;
    details::refresh_findings(ui.ctx(), id, headers, rows);
    clicked
}

fn finding_table_rows(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Finding],
    selected: Option<trace::InvocationKey>,
) -> Option<trace::InvocationKey> {
    use egui_extras::{Column, TableBuilder};
    if rows.is_empty() {
        ui.colored_label(theme::muted(), "Nothing recorded for this view.");
        return None;
    }
    let widths = column_widths(ui, headers, rows.iter().map(|row| row.cells.as_slice()));
    let order = sorting::order(
        ui.ctx(),
        id,
        headers,
        rows.iter().map(|row| row.cells.as_slice()),
    );
    ui.set_width(
        (widths.iter().sum::<f32>()
            + ui.spacing().item_spacing.x * headers.len().saturating_sub(1) as f32
            + 16.0)
            .max(ui.available_width()),
    );
    let mut clicked = None;
    let filter_id = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new(("triage-filter-target", id))));
    let row_height = ui.text_style_height(&egui::TextStyle::Body).max(14.0) + 8.0;
    let max_height = ui.available_height().max(60.0);
    let mut builder = TableBuilder::new(ui)
        .id_salt(("triage-062", id))
        .striped(true)
        .resizable(true)
        .vscroll(true)
        .max_scroll_height(max_height)
        .min_scrolled_height(0.0)
        .sense(egui::Sense::click());
    for (index, width) in widths.into_iter().enumerate() {
        builder = if index + 1 == headers.len() {
            builder.column(Column::remainder().at_least(width))
        } else {
            builder.column(Column::initial(width).at_least(64.0).resizable(true))
        };
    }
    builder
        .header(row_height, |mut header| {
            for (column, title) in headers.iter().enumerate() {
                header.col(|ui| {
                    sorting::header(ui, id, column, title);
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let finding = &rows[order
                    .as_ref()
                    .map_or(row.index(), |order| order[row.index()])];
                row.set_selected(selected == Some(finding.key));
                for cell in &finding.cells {
                    row.col(|ui| {
                        let mut text = RichText::new(&cell.text).color(cell.color);
                        if cell.mono {
                            text = text.monospace();
                        }
                        ui.add(
                            egui::Label::new(text)
                                .truncate()
                                .selectable(false)
                                .sense(egui::Sense::hover()),
                        );
                    });
                }
                if row.response().clicked() {
                    clicked = Some(finding.key);
                    let mut cells = finding.cells.clone();
                    if let Some(first) = cells.first_mut() {
                        first.values.clone_from(&finding.values);
                    }
                    details::select(&row.response().ctx, id, headers, &cells);
                    details::clicked(&row.response().ctx, id);
                }
                if row.response().double_clicked() {
                    request_evidence_jump(&row.response().ctx, &finding.values);
                }
                if let Some(filter_id) = filter_id {
                    row.response()
                        .context_menu(|ui| query::table_row_menu(ui, filter_id, &finding.values));
                }
            });
        });
    clicked
}

fn process_tree_nodes(
    ui: &mut egui::Ui,
    nodes: &[ProcessNode],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) {
    let sorted = ui
        .ctx()
        .data(|data| {
            data.get_temp::<sorting::Spec>(egui::Id::new(("triage-sort", "triage-process")))
        })
        .is_some();
    let rows = nodes
        .iter()
        .map(|node| {
            let mut row = vec![
                cell(
                    format!(
                        "{}{}",
                        if sorted {
                            String::new()
                        } else {
                            "│ ".repeat(node.depth.min(16))
                        },
                        process_label(node)
                    ),
                    theme::value(theme::ValueKind::Pointer),
                    true,
                ),
                cell(
                    node.comm.clone(),
                    theme::value(theme::ValueKind::Name),
                    true,
                ),
                cell(node.tid.to_string(), theme::text(), true),
                cell(node.argv.join(" "), theme::text(), false),
                cell(
                    crate::time_format::guest_ns(clock, node.first_ns),
                    theme::text(),
                    true,
                ),
                cell(
                    crate::time_format::guest_ns(clock, node.last_ns),
                    theme::text(),
                    true,
                ),
                cell(&node.state, theme::text(), false),
                cell(node.exec_history.join(" → "), theme::text(), false),
            ];
            row[0].values = vec![
                (
                    "event.id",
                    node.call_id
                        .map_or(RowValue::Missing, |id| RowValue::Number(i128::from(id.2))),
                ),
                ("process.pid", RowValue::Number(i128::from(node.pid))),
                ("process.tid", RowValue::Number(i128::from(node.tid))),
                ("process.cookie", RowValue::Number(i128::from(node.cookie))),
                ("process.depth", RowValue::Number(node.depth as i128)),
                (
                    "process.ppid",
                    node.parent.map_or(RowValue::Missing, |parent| {
                        RowValue::Number(i128::from(parent.pid))
                    }),
                ),
                (
                    "process.parent_cookie",
                    node.parent
                        .filter(|parent| parent.cookie != 0)
                        .map_or(RowValue::Missing, |parent| {
                            RowValue::Number(i128::from(parent.cookie))
                        }),
                ),
                (
                    "stream.id",
                    node.call_id
                        .map_or(RowValue::Missing, |key| RowValue::Number(i128::from(key.0))),
                ),
                (
                    "process.exe",
                    if node.comm == "?" {
                        RowValue::Missing
                    } else {
                        text_value(&node.comm)
                    },
                ),
                (
                    "process.argv",
                    if node.argv.is_empty() {
                        RowValue::Missing
                    } else {
                        RowValue::List(node.argv.clone())
                    },
                ),
                ("process.state", RowValue::Text(node.state.clone())),
                (
                    "process.first_ns",
                    node.first_ns
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                (
                    "process.last_ns",
                    node.last_ns
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
            ];
            row
        })
        .collect::<Vec<_>>();
    ui.ctx().data_mut(|data| {
        data.insert_temp(
            egui::Id::new(("triage-filter-target", "triage-process")),
            ui.id().with(("table-filter", "triage-process")),
        )
    });
    let compiled = query::table_filter(
        ui,
        "triage-process",
        "Filter process identity, executable or state",
        PROCESS_FIELDS,
        &[],
    );
    let filtered = rows
        .into_iter()
        .filter(|row| compiled.keep_table(&row[0].values))
        .collect::<Vec<_>>();
    table(
        ui,
        "triage-process",
        &[
            "Process",
            "Executable",
            "TID",
            "Argv",
            "First seen",
            "Last seen",
            "Task outcome",
            "Exec history",
        ],
        &filtered,
    );
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

fn process_nodes(invocations: &[InvocationSummary]) -> Vec<ProcessNode> {
    let mut nodes = std::collections::BTreeMap::new();
    observe_processes(&mut nodes, invocations);
    finish_processes(nodes)
}

fn observe_processes(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    invocations: &[InvocationSummary],
) {
    for invocation in invocations {
        let entry = invocation.entry.as_ref();
        let exit = invocation.exit.as_ref();
        let Some(event) = entry
            .or(exit)
            .or(invocation.async_events.first())
            .or(invocation.task_exit.as_ref())
        else {
            continue;
        };
        if event.pid == 0 {
            continue;
        }
        let key = adopt_task(nodes, event);
        if let Some(node) = nodes.get_mut(&key) {
            node.tid = event.tid;
            if invocation.call_id != 0 {
                node.call_id.get_or_insert(trace::key(invocation));
            }
            node.root |= event.root_task_cookie != 0 && event.task_cookie == event.root_task_cookie;
            for observed in invocation
                .entry
                .iter()
                .chain(invocation.exit.iter())
                .chain(invocation.async_events.iter())
                .chain(invocation.task_exit.iter())
            {
                node.first_ns = Some(node.first_ns.map_or(observed.timestamp_ns, |time| {
                    time.min(observed.timestamp_ns)
                }));
                node.last_ns = Some(node.last_ns.map_or(observed.timestamp_ns, |time| {
                    time.max(observed.timestamp_ns)
                }));
            }
            if invocation.task_exit.is_some() {
                node.state = format!("task exit {:?}", invocation.task_exit_status());
            } else if node.state.is_empty() {
                node.state = "exit not recorded".into();
            }
        }
        if committed_exec(invocation) {
            if let Some(comm) = program_name(entry, exit).or_else(|| {
                invocation
                    .async_events
                    .iter()
                    .find_map(|event| program_name(Some(event), None))
            }) {
                let node = nodes.get_mut(&key).unwrap();
                node.comm = comm.clone();
                if node.exec_history.last() != Some(&comm) {
                    if node.exec_history.len() < 128 {
                        node.exec_history.push(comm);
                    } else if node
                        .exec_history
                        .last()
                        .is_some_and(|text| text != "further exec history omitted")
                    {
                        node.exec_history
                            .push("further exec history omitted".into());
                    }
                }
                node.argv = entry
                    .into_iter()
                    .chain(exit)
                    .chain(invocation.async_events.iter())
                    .flat_map(|event| &event.fields)
                    .filter(|field| field.key.contains("argv"))
                    .filter_map(path_text)
                    .collect();
            }
        }
        let args = entry
            .and_then(|event| event.args)
            .or(exit.and_then(|event| event.args));
        if !matches!(
            spawn_kind(invocation, event.syscall_nr, args),
            Some(Spawn::Process)
        ) {
            continue;
        }
        let Some(child) = exit
            .and_then(|event| event.result)
            .or(entry.and_then(|event| event.result))
            .filter(|result| *result > 0)
            .map(|result| result as u32)
        else {
            continue;
        };
        link_child(nodes, key, child);
    }
}

fn finish_processes(nodes: std::collections::BTreeMap<TaskKey, TaskNode>) -> Vec<ProcessNode> {
    let mut children: std::collections::BTreeMap<TaskKey, Vec<TaskKey>> =
        std::collections::BTreeMap::new();
    let mut roots = Vec::new();
    for (key, node) in &nodes {
        match node
            .parent
            .filter(|parent| nodes.contains_key(parent) && parent != key)
        {
            Some(parent) => children.entry(parent).or_default().push(*key),
            None => roots.push(*key),
        }
    }
    let mut found = Vec::new();
    fn walk(
        key: TaskKey,
        depth: usize,
        nodes: &std::collections::BTreeMap<TaskKey, TaskNode>,
        children: &std::collections::BTreeMap<TaskKey, Vec<TaskKey>>,
        found: &mut Vec<ProcessNode>,
        seen: &mut std::collections::BTreeSet<TaskKey>,
    ) {
        let mut pending = vec![(key, depth)];
        while let Some((key, depth)) = pending.pop() {
            if !seen.insert(key) {
                continue;
            }
            let Some(node) = nodes.get(&key) else {
                continue;
            };
            found.push(ProcessNode {
                parent: node.parent,
                depth,
                call_id: node.call_id,
                pid: key.pid,
                cookie: key.cookie,
                comm: node.comm.clone(),
                parent_missing: depth == 0 && !node.root,
                tid: node.tid,
                argv: node.argv.clone(),
                first_ns: node.first_ns,
                last_ns: node.last_ns,
                state: node.state.clone(),
                exec_history: node.exec_history.clone(),
            });
            if let Some(kids) = children.get(&key) {
                for child in kids.iter().rev() {
                    pending.push((*child, depth.saturating_add(1)));
                }
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for key in roots {
        walk(key, 0, &nodes, &children, &mut found, &mut seen);
    }
    for key in nodes.keys() {
        if !seen.contains(key) {
            walk(*key, 0, &nodes, &children, &mut found, &mut seen);
        }
    }
    found
}

/// Identity is `(task_cookie, pid)` when the cookie is non-zero. A fork child
/// seen only as a returned pid keeps cookie 0 until one of its own events
/// supplies a cookie. A real cookie-0 event is not later rewritten as some
/// other cookie.
fn adopt_task(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    event: &EventSummary,
) -> TaskKey {
    let key = TaskKey {
        pid: event.pid,
        cookie: event.task_cookie,
    };
    if key.cookie != 0 {
        let provisional_key = TaskKey {
            pid: key.pid,
            cookie: 0,
        };
        let migrate = nodes
            .get(&provisional_key)
            .is_some_and(|node| node.provisional)
            && !nodes.contains_key(&key);
        if migrate {
            let mut node = nodes.remove(&provisional_key).unwrap();
            node.provisional = false;
            nodes.insert(key, node);
            return key;
        }
    }
    let node = nodes.entry(key).or_insert_with(|| TaskNode {
        parent: None,
        comm: "?".into(),
        provisional: false,
        ..TaskNode::default()
    });
    if key.cookie == 0 {
        node.provisional = false;
    }
    key
}

fn link_child(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    parent: TaskKey,
    child_pid: u32,
) {
    if child_pid == 0 || child_pid == parent.pid {
        return;
    }
    let inherited = nodes
        .get(&parent)
        .filter(|node| node.comm != "?")
        .map(|node| (node.comm.clone(), node.argv.clone()));
    let candidates: Vec<TaskKey> = nodes
        .iter()
        .filter(|(key, node)| key.pid == child_pid && **key != parent && node.parent.is_none())
        .map(|(key, _)| *key)
        .collect();
    match candidates.as_slice() {
        [child] => {
            if let Some(node) = nodes.get_mut(child) {
                node.parent = Some(parent);
                node.provisional = false;
                if node.comm == "?" {
                    if let Some((comm, argv)) = &inherited {
                        node.comm.clone_from(comm);
                        node.argv.clone_from(argv);
                    }
                }
            }
        }
        [] => {
            let child = TaskKey {
                pid: child_pid,
                cookie: 0,
            };
            match nodes.get_mut(&child) {
                Some(node) if node.parent.is_none() => node.parent = Some(parent),
                Some(_) => {}
                None => {
                    nodes.insert(
                        child,
                        TaskNode {
                            parent: Some(parent),
                            comm: inherited
                                .as_ref()
                                .map_or_else(|| "?".into(), |image| image.0.clone()),
                            argv: inherited
                                .as_ref()
                                .map_or_else(Vec::new, |image| image.1.clone()),
                            provisional: true,
                            ..TaskNode::default()
                        },
                    );
                }
            }
        }
        _ => {}
    }
}

fn spawn_kind(invocation: &InvocationSummary, nr: u64, args: Option<[u64; 6]>) -> Option<Spawn> {
    match nr {
        FORK | VFORK => Some(Spawn::Process),
        CLONE => Some(if args.is_some_and(|args| args[0] & CLONE_THREAD != 0) {
            Spawn::Skip
        } else {
            Spawn::Process
        }),
        CLONE3 => Some(match clone3_is_thread(invocation) {
            Some(true) => Spawn::Skip,
            Some(false) => Spawn::Process,
            None => Spawn::Skip,
        }),
        _ => None,
    }
}

/// `Some` when a captured field key contains both `clone_args` and `flags`
/// and its bytes are a 4- or 8-byte little-endian integer. `None` means the
/// recording has no usable flags, so the caller must not invent an edge.
fn clone3_is_thread(invocation: &InvocationSummary) -> Option<bool> {
    let field = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(invocation.async_events.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key.contains("clone_args") && field.key.contains("flags"))?;
    let bytes = trace::covered_preview(field);
    let flags = match bytes.len() {
        4 => u64::from(u32::from_le_bytes(bytes.try_into().ok()?)),
        8 => u64::from_le_bytes(bytes.try_into().ok()?),
        _ => return None,
    };
    Some(flags & CLONE_THREAD != 0)
}

fn program_name(entry: Option<&EventSummary>, exit: Option<&EventSummary>) -> Option<String> {
    entry.into_iter().chain(exit).find_map(|event| {
        event
            .fields
            .iter()
            .filter(|field| path_key(&field.key))
            .find_map(path_text)
    })
}

fn committed_exec(invocation: &InvocationSummary) -> bool {
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(&invocation.async_events)
        .any(|event| {
            event.fields.iter().any(|field| {
                field.key == "lifecycle.exec_commit"
                    && field.complete
                    && trace::covered_preview(field).len() >= 8
            })
        })
        || trace::representative(invocation)
            .is_some_and(|event| matches!(event.syscall_nr, 59 | 322))
            && succeeded(invocation)
}

fn process_image<'a>(files: &'a FdState, event: &EventSummary) -> Option<&'a str> {
    files
        .process_images
        .get(&TaskKey {
            pid: event.pid,
            cookie: event.task_cookie,
        })
        .map(|node| node.comm.as_str())
        .filter(|image| !image.is_empty() && *image != "?")
}

fn process_identity(pid: u32, tid: u32, image: Option<&str>) -> String {
    let name = image
        .and_then(|image| image.rsplit('/').find(|part| !part.is_empty()))
        .unwrap_or("Unknown");
    format!("{name} ({pid} / {tid})")
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

fn process_label(node: &ProcessNode) -> String {
    let cookie = if node.cookie == 0 {
        "unknown".to_string()
    } else {
        node.cookie.to_string()
    };
    let mut text = format!("pid {} cookie {cookie}", node.pid);
    if node.parent_missing {
        text.push_str("  parent not in this trace");
    }
    text
}

#[cfg(test)]
fn process_tree_lines(invocations: &[InvocationSummary]) -> Vec<String> {
    process_nodes(invocations)
        .into_iter()
        .map(|node| {
            format!(
                "{}{}  {}",
                "  ".repeat(node.depth),
                process_label(&node),
                node.comm
            )
        })
        .collect()
}

fn preview_line(event: &EventSummary) -> String {
    event
        .fields
        .iter()
        .find_map(|field| {
            let text = String::from_utf8_lossy(crate::trace::covered_preview(field))
                .trim_end_matches('\0')
                .trim()
                .to_owned();
            (!text.is_empty()).then_some(text)
        })
        .unwrap_or_else(|| event.syscall_name.clone())
}

fn hit(
    rule: &str,
    severity: &str,
    process: String,
    summary: String,
    source: &str,
    event: &EventSummary,
    invocation: &InvocationSummary,
) -> Finding {
    let color = if severity == "high" {
        theme::error()
    } else {
        theme::warn()
    };
    let time = if event.timestamp_ns == 0 {
        "—".to_string()
    } else {
        event.timestamp_ns.to_string()
    };
    Finding {
        key: trace::key(invocation),
        call_id: invocation.call_id,
        values: vec![
            ("finding.rule", RowValue::Text(rule.into())),
            ("finding.version", RowValue::Number(1)),
            ("finding.severity", RowValue::Text(severity.into())),
            (
                "finding.confidence",
                RowValue::Text(
                    if event.complete && invocation.exit.as_ref().is_some_and(|exit| exit.complete)
                    {
                        "high"
                    } else {
                        "limited"
                    }
                    .into(),
                ),
            ),
            ("finding.source", RowValue::Text(source.into())),
            ("finding.summary", RowValue::Text(summary.clone())),
            ("finding.attempted", RowValue::Bool(true)),
            (
                "finding.success",
                invocation
                    .exit
                    .as_ref()
                    .and_then(|exit| exit.result)
                    .map_or(RowValue::Missing, |ret| RowValue::Bool(ret >= 0)),
            ),
            (
                "syscall.ret",
                invocation
                    .exit
                    .as_ref()
                    .and_then(|exit| exit.result)
                    .map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
            ),
            ("event.id", RowValue::Number(i128::from(invocation.call_id))),
            (
                "stream.id",
                RowValue::Number(i128::from(invocation.stream_id)),
            ),
            (
                "event.time_ns",
                RowValue::Number(i128::from(event.timestamp_ns)),
            ),
            ("process.pid", RowValue::Number(i128::from(event.pid))),
            ("process.tid", RowValue::Number(i128::from(event.tid))),
            (
                "process.cookie",
                RowValue::Number(i128::from(invocation.task_cookie)),
            ),
            ("entry.tag", RowValue::Missing),
        ],
        cells: vec![
            cell(rule, color, false),
            cell(severity, color, false),
            cell(process, theme::text(), true),
            cell(summary, theme::text(), false),
            cell(source, theme::muted(), false),
            cell(time, theme::text(), true),
            cell(confidence(invocation), theme::text(), false),
            cell(
                format!("syscall {} call {}", event.syscall_name, invocation.call_id),
                theme::text(),
                true,
            ),
            cell("1", theme::text(), true),
            cell(outcome(invocation), theme::text(), false),
        ],
    }
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
    sorts: [Option<sorting::Spec>; 8],
    file_visibility: file_visibility::FileVisibility,
    owned_pcap: bool,
    clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    started_ms: Option<u64>,
    ended_ms: Option<u64>,
    root_cookie: u64,
    run_finished: bool,
    identity: Option<(String, String, String)>,
    offsets: [usize; 8],
    filters: [String; 8],
}

fn confidence(invocation: &InvocationSummary) -> &'static str {
    if invocation
        .entry
        .as_ref()
        .is_some_and(|event| event.complete)
        && invocation.exit.as_ref().is_some_and(|event| event.complete)
    {
        "high"
    } else {
        "limited"
    }
}

fn call_args(invocation: &InvocationSummary) -> Option<[u64; 6]> {
    invocation
        .entry
        .as_ref()
        .and_then(|event| event.args)
        .or_else(|| invocation.exit.as_ref().and_then(|event| event.args))
}

fn outcome(invocation: &InvocationSummary) -> String {
    invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .map_or("exit not recorded".to_string(), |result| {
            if result < 0 {
                format!("failed ({result})")
            } else {
                format!("returned {result}")
            }
        })
}

/// `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER)`. Another level with optname 26 is not a match.
fn classic_socket_filter(event: &EventSummary, args: [u64; 6]) -> bool {
    (event.syscall_name == "setsockopt" || event.syscall_nr == 54) && args[1] == 1 && args[2] == 26
}

fn filter_findings(rows: Vec<Finding>, filter: &str) -> Vec<Finding> {
    let compiled = query::compile_table(filter, FINDING_FIELDS);
    rows.into_iter()
        .filter(|row| compiled.keep_table(&row.values))
        .collect()
}

fn suspicious_rows(invocations: &[InvocationSummary]) -> Vec<Finding> {
    suspicious_rows_state(invocations, None)
}
fn suspicious_rows_state(
    invocations: &[InvocationSummary],
    files: Option<&FdState>,
) -> Vec<Finding> {
    let mut rows = Vec::new();
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        let args = event.args.or(call_args(invocation)).unwrap_or([0; 6]);
        let process = process_identity(
            event.pid,
            event.tid,
            files.and_then(|files| process_image(files, event)),
        );
        let outcome = outcome(invocation);
        if matches!(event.syscall_nr, 9 | 10) && args.get(2).is_some_and(|prot| prot & 7 == 7) {
            rows.push(hit(
                if succeeded(invocation) {
                    "memory.rwx"
                } else {
                    "memory.rwx_attempt"
                },
                "high",
                process.clone(),
                format!("{} prot {:#x}; {outcome}", event.syscall_name, args[2]),
                "MITRE ATT&CK T1055",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 59 | 322) {
            rows.push(hit(
                "process.exec",
                "medium",
                process.clone(),
                format!("{} {outcome}", preview_line(event)),
                "MITRE ATT&CK T1059.004",
                event,
                invocation,
            ));
            let paths = path_list(invocation);
            if paths.first().is_some_and(|path| {
                matches!(
                    path.rsplit('/').next().unwrap_or(""),
                    "sh" | "bash"
                        | "dash"
                        | "zsh"
                        | "python"
                        | "python3"
                        | "perl"
                        | "ruby"
                        | "node"
                )
            }) {
                rows.push(hit(
                    "process.interpreter",
                    "medium",
                    process.clone(),
                    format!(
                        "captured interpreter/shell path {}; {outcome}",
                        paths.join(", ")
                    ),
                    "MITRE ATT&CK T1059",
                    event,
                    invocation,
                ));
            }
            let memfd = files.and_then(|files| {
                let owner = table_owner(files, invocation.task_cookie, event.tid);
                (event.syscall_nr == 322 && args[4] & 0x1000 != 0)
                    .then(|| files.opened.get(&(owner.0, owner.1, args[0])))
                    .flatten()
                    .filter(|path| path.starts_with("memfd:"))
                    .cloned()
            });
            if let Some(memfd) = memfd {
                rows.push(hit(
                    "process.memfd_exec",
                    "high",
                    process.clone(),
                    format!("execveat AT_EMPTY_PATH references observed {memfd}; {outcome}"),
                    "MITRE ATT&CK T1620",
                    event,
                    invocation,
                ));
            }
        }
        if event.syscall_nr == 101 {
            rows.push(hit(
                "process.ptrace",
                "high",
                process.clone(),
                outcome.clone(),
                "MITRE ATT&CK T1055.008",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 310 | 311) {
            rows.push(hit(
                "process.vm_rw",
                "high",
                process.clone(),
                format!("{} {outcome}", event.syscall_name),
                "MITRE ATT&CK T1055.009",
                event,
                invocation,
            ));
        }
        if event.syscall_nr == 319 {
            rows.push(hit(
                "process.memfd",
                "medium",
                process.clone(),
                outcome.clone(),
                "MITRE ATT&CK DET0508",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 175 | 313) {
            rows.push(hit(
                "persistence.module",
                "high",
                process.clone(),
                format!("{} {outcome}", event.syscall_name),
                "MITRE ATT&CK T1547.006",
                event,
                invocation,
            ));
        }
        if matches!(
            event.syscall_nr,
            105 | 106 | 113 | 114 | 117 | 119 | 122 | 123 | 126 | 130
        ) {
            rows.push(hit(
                "privilege.change",
                "medium",
                process.clone(),
                format!("{} args {args:x?}; {outcome}", event.syscall_name),
                "Observed credential/capability change attempt",
                event,
                invocation,
            ));
        }
        if (event.syscall_nr == 317 && args[0] == 1)
            || (event.syscall_nr == 157 && args[0] == 22 && args[1] == 2)
        {
            rows.push(hit(
                "bpf.seccomp_filter",
                "medium",
                process.clone(),
                format!("classic seccomp filter installation; {outcome}"),
                "Linux seccomp filter interface",
                event,
                invocation,
            ));
        }
        let file_path = files
            .map(|files| displayed_path(invocation, event, files))
            .unwrap_or_else(|| path_list(invocation).join(", "));
        let notable = [
            "/etc/",
            "/root/.ssh/",
            "/var/spool/cron/",
            "/usr/lib/systemd/",
            "/lib/systemd/",
        ]
        .iter()
        .any(|prefix| file_path.starts_with(prefix))
            || (file_path.starts_with("/home/")
                && ["/.ssh/", "/.config/", "/.bashrc", "/.profile"]
                    .iter()
                    .any(|part| file_path.contains(part)));
        let write_like = matches!(
            event.syscall_name.as_str(),
            "write"
                | "writev"
                | "pwrite64"
                | "pwritev"
                | "pwritev2"
                | "truncate"
                | "ftruncate"
                | "rename"
                | "renameat"
                | "renameat2"
                | "unlink"
                | "unlinkat"
                | "chmod"
                | "fchmod"
                | "chown"
                | "fchown"
        ) || open_flags(invocation, event)
            .is_some_and(|flags| flags & (0x40 | 0x200) != 0);
        if notable && write_like {
            rows.push(hit(
                "persistence.config_write",
                "medium",
                process.clone(),
                format!(
                    "{} at notable configuration/persistence path {file_path}; {outcome}",
                    event.syscall_name
                ),
                "Observed configuration location; normal administrative use can be benign",
                event,
                invocation,
            ));
        }
        if let Some(command) = bpf::command_name(event) {
            if matches!(
                command,
                "BPF_PROG_LOAD" | "BPF_PROG_ATTACH" | "BPF_PROG_DETACH"
            ) {
                rows.push(hit(
                    "bpf.program",
                    "medium",
                    process.clone(),
                    format!("{command}; {outcome}"),
                    "Fournier, Afchain, Baubeau, Black Hat USA 2021",
                    event,
                    invocation,
                ));
            }
        }
        if classic_socket_filter(event, args) {
            rows.push(hit(
                "bpf.socket_filter",
                "medium",
                process.clone(),
                format!("classic socket filter; {outcome}"),
                "McCanne and Jacobson, USENIX 1993",
                event,
                invocation,
            ));
        }
    }
    rows
}

#[cfg(test)]
fn file_rows(invocations: &[InvocationSummary], names: &[&str]) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    // Successful opens are remembered for this slice only. A fork, vfork, or
    // process clone copies the parent's descriptors unless CLONE_FILES shares
    // one table. CLONE_FS shares the working directory; CLONE_FILES does not.
    // Later closes change only the task that owns the descriptor table.
    let mut files = FdState::default();
    let cookies = task_cookies(invocations);
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        remember_cwd(&mut files, invocation, event);
        remember_open(&mut files, invocation, event);
        apply_dup(&mut files, invocation, event);
        forget_closed(&mut files, invocation, event);
        inherit_open_fds(&mut files, invocation, event, &cookies);
        if let Some(row) = file_event_row(&files, invocation, event, names) {
            if !push_limited(&mut limited, row) {
                break;
            }
        }
    }
    limited
}

fn file_event_row(
    files: &FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
    names: &[&str],
) -> Option<Vec<Cell>> {
    let changed_view = names.contains(&"write");
    let flags = open_flags(invocation, event);
    let creates = OPEN_NAMES.contains(&event.syscall_name.as_str())
        && flags.is_some_and(|flags| flags & (0x40 | 0x200) != 0);
    if !names.iter().any(|name| event.syscall_name == *name) && !(changed_view && creates) {
        return None;
    }
    if matches!(event.syscall_name.as_str(), "mmap" | "mmap2") {
        let writable = call_args(invocation).is_some_and(|args| args[2] & 2 != 0);
        let private = call_args(invocation)
            .and_then(|args| args.get(3).copied())
            .is_some_and(|flags| flags & MAP_PRIVATE != 0);
        if !writable || private {
            return None;
        }
    }
    let path = displayed_path(invocation, event, files);
    let result = invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "—".into());
    let mut row = vec![
        cell(
            if path.is_empty() {
                "—".to_string()
            } else {
                path
            },
            theme::text(),
            true,
        ),
        cell(
            process_identity(event.pid, event.tid, process_image(files, event)),
            theme::text(),
            true,
        ),
        cell(
            {
                let fd = file_fd(invocation, event);
                fd.parse()
                    .ok()
                    .and_then(crate::values::standard_fd_name)
                    .map_or_else(|| fd.clone(), |name| format!("{fd} ({name})"))
            },
            theme::value(theme::ValueKind::Number),
            true,
        ),
        cell(
            event.syscall_name.clone(),
            theme::value(theme::ValueKind::Name),
            false,
        ),
        cell(result, theme::text(), true),
        cell(file_outcome(invocation), theme::text(), false),
    ];
    let paths = path_list(invocation);
    let ret = invocation.exit.as_ref().and_then(|exit| exit.result);
    let writing = matches!(
        event.syscall_name.as_str(),
        "write" | "writev" | "pwrite64" | "pwritev" | "pwritev2"
    );
    let written = writing.then_some(ret).flatten().filter(|ret| *ret >= 0);
    let requested = matches!(event.syscall_name.as_str(), "write" | "pwrite64")
        .then(|| call_args(invocation).map(|args| args[2]))
        .flatten();
    let access = flags
        .map(|flags| {
            format!(
                "{} flags {flags:#x}",
                match flags & 3 {
                    0 => "read",
                    1 => "write",
                    2 => "read/write",
                    _ => "unknown",
                }
            )
        })
        .unwrap_or_else(|| "—".into());
    row[0].values = vec![
        (
            "process.exe",
            process_image(files, event)
                .map_or(RowValue::Missing, |image| RowValue::Text(image.into())),
        ),
        (
            "file.path",
            paths
                .first()
                .cloned()
                .or_else(|| (row[0].text != "—").then(|| row[0].text.clone()))
                .map_or(RowValue::Missing, RowValue::Text),
        ),
        (
            "file.old_path",
            if matches!(
                event.syscall_name.as_str(),
                "rename" | "renameat" | "renameat2"
            ) {
                named_path(invocation, event, &["oldname", "old_path"])
                    .map_or(RowValue::Missing, RowValue::Text)
            } else {
                RowValue::Missing
            },
        ),
        (
            "file.new_path",
            if matches!(
                event.syscall_name.as_str(),
                "rename" | "renameat" | "renameat2"
            ) {
                named_path(invocation, event, &["newname", "new_path"])
                    .map_or(RowValue::Missing, RowValue::Text)
            } else {
                RowValue::Missing
            },
        ),
        (
            "file.fd",
            file_fd(invocation, event)
                .parse::<i128>()
                .map_or(RowValue::Missing, RowValue::Number),
        ),
        ("file.operation", RowValue::Text(event.syscall_name.clone())),
        (
            "file.access",
            if flags.is_some() {
                RowValue::Text(access.clone())
            } else {
                RowValue::Missing
            },
        ),
        (
            "file.success",
            ret.map_or(RowValue::Missing, |ret| RowValue::Bool(ret >= 0)),
        ),
        (
            "file.written_size",
            written.map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
        ),
        (
            "file.requested_size",
            requested.map_or(RowValue::Missing, |size| RowValue::Number(i128::from(size))),
        ),
        (
            "file.offset",
            if event.syscall_name == "pwrite64" {
                call_args(invocation).map_or(RowValue::Missing, |args| {
                    RowValue::Number(i128::from(args[3] as i64))
                })
            } else {
                RowValue::Missing
            },
        ),
        ("file.count", RowValue::Number(1)),
        ("process.pid", RowValue::Number(i128::from(event.pid))),
        ("process.tid", RowValue::Number(i128::from(event.tid))),
        (
            "process.cookie",
            RowValue::Number(i128::from(invocation.task_cookie)),
        ),
        ("event.id", RowValue::Number(i128::from(invocation.call_id))),
        (
            "stream.id",
            RowValue::Number(i128::from(invocation.stream_id)),
        ),
        (
            "event.time_ns",
            RowValue::Number(i128::from(event.timestamp_ns)),
        ),
        (
            "syscall.ret",
            ret.map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
        ),
    ];
    row.extend([
        cell(access, theme::text(), false),
        cell(event.timestamp_ns.to_string(), theme::text(), true),
        cell(
            written.map_or("—".into(), |size| size.to_string()),
            theme::text(),
            true,
        ),
        cell(
            requested.map_or("—".into(), |size| size.to_string()),
            theme::text(),
            true,
        ),
        cell(paths.join(" → "), theme::text(), true),
        cell(format!("call {}", invocation.call_id), theme::text(), true),
        cell(event.timestamp_ns.to_string(), theme::text(), true),
        cell("1", theme::text(), true),
    ]);
    Some(row)
}

fn open_flags(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    match event.syscall_name.as_str() {
        "creat" => Some(0x241),
        "open" => call_args(invocation).map(|args| args[1]),
        "openat" => call_args(invocation).map(|args| args[2]),
        "openat2" => invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .flat_map(|event| &event.fields)
            .find(|field| field.key.ends_with(".flags"))
            .and_then(|field| trace::covered_preview(field).get(..8))
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes),
        _ => None,
    }
}

const OPEN_NAMES: &[&str] = &["open", "openat", "openat2", "creat", "memfd_create"];
const CHANGE_NAMES: &[&str] = &[
    "write",
    "writev",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "truncate",
    "ftruncate",
    "mkdir",
    "mkdirat",
    "rmdir",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "fchmodat2",
    "mmap",
    "mmap2",
    "msync",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "utime",
    "utimes",
    "futimesat",
    "utimensat",
    "mknod",
    "mknodat",
    "fallocate",
    "sendfile",
    "copy_file_range",
    "splice",
];
const STORED_ROWS: usize = 2000;

struct FindingJournal {
    temp: std::path::PathBuf,
    destination: std::path::PathBuf,
    file: std::fs::File,
    size: u64,
}
impl FindingJournal {
    fn new(directory: &Path) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temp = directory.join(format!(
            ".triage-findings-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = std::fs::OpenOptions::new()
            .mode(0o600)
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            temp,
            destination: directory.join("triage-findings-v1.jsonl"),
            file,
            size: 0,
        })
    }
    fn push(&mut self, finding: &Finding) -> Result<(), String> {
        use std::io::Write;
        let facts = finding
            .values
            .iter()
            .map(|(name, value)| {
                let value = match value {
                    RowValue::Number(value) => serde_json::to_value(value)
                        .unwrap_or_else(|_| serde_json::Value::String(value.to_string())),
                    RowValue::Text(value) => serde_json::Value::String(value.clone()),
                    RowValue::Bool(value) => serde_json::Value::Bool(*value),
                    RowValue::List(value) => serde_json::json!(value),
                    RowValue::Missing => serde_json::Value::Null,
                };
                ((*name).to_owned(), value)
            })
            .collect::<serde_json::Map<_, _>>();
        let row = serde_json::to_vec(&serde_json::json!({"format_version":1, "evidence_call_id":finding.call_id, "facts":facts}))
            .map_err(|error| error.to_string())?;
        if self.size.saturating_add(row.len() as u64 + 1) > 256 * 1024 * 1024 {
            return Err("finding journal exceeded 256 MiB; prior journal retained".into());
        }
        self.file
            .write_all(&row)
            .and_then(|()| self.file.write_all(b"\n"))
            .map_err(|error| error.to_string())?;
        self.size += row.len() as u64 + 1;
        Ok(())
    }
    fn publish(&mut self) -> Result<(), String> {
        self.file.sync_all().map_err(|error| error.to_string())?;
        std::fs::rename(&self.temp, &self.destination).map_err(|error| error.to_string())?;
        std::fs::File::open(
            self.destination
                .parent()
                .ok_or("finding journal directory missing")?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
    }
}
impl Drop for FindingJournal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.temp);
    }
}

struct ArchiveScan {
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

/// Walk every saved invocation page. Display tables keep at most [`STORED_ROWS`]
/// matches; the coverage line counts anything left out. Cancellation stops
/// between pages and does not claim the recording was fully indexed.
#[cfg(test)]
fn scan_archive(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    cancel: &AtomicBool,
) -> Result<ArchiveScan, String> {
    scan_archive_query(
        directory,
        pcap,
        pcap_open,
        &Arc::new(AtomicBool::new(cancel.load(Ordering::Relaxed))),
        &ScanRequest::default(),
    )
}

fn scan_archive_query(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
) -> Result<ArchiveScan, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let directory = std::fs::canonicalize(directory).map_err(|error| error.to_string())?;
    if !directory.join("telemetry.raw").is_file() {
        return Err(
            "saved recording has no telemetry.raw; the visible page was not treated as the whole run"
                .into(),
        );
    }
    let recording = antinomie_monitor_core::recording::Recording {
        directory,
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let facts = request
        .identity
        .as_ref()
        .map(|(vm, boot, run)| {
            antinomie_monitor_core::recording::run_filter_facts(&recording.directory, run, vm, boot)
        })
        .transpose()?;
    let mut clock_anchor = request.clock_anchor;
    let started_ms = request
        .started_ms
        .or_else(|| facts.as_ref().and_then(|facts| facts.started_ms));
    let scoped = |call: &&InvocationSummary| {
        request.root_cookie == 0
            || trace::representative(call)
                .or(call.task_exit.as_ref())
                .is_some_and(|event| event.root_task_cookie == request.root_cookie)
    };
    let total = recording.invocation_count_cancellable(None, cancel).ok();
    let mut cookie_sets = std::collections::BTreeMap::new();
    let mut nodes = std::collections::BTreeMap::new();
    let mut finding_page = sorting::Page::new(request, 0, cancel);
    let finding_query = query::compile_table(&request.filters[0], FINDING_FIELDS);
    let (seen, complete, issues) = walk_pages(&recording, cancel, |page| {
        let page: Vec<_> = page.iter().filter(scoped).cloned().collect();
        if clock_anchor.is_none() {
            clock_anchor = started_ms
                .zip(
                    page.iter()
                        .filter_map(trace::representative)
                        .map(|event| event.timestamp_ns)
                        .min(),
                )
                .and_then(|(host_ms, guest_ns)| {
                    Some(antinomie_monitor_core::HostClockAnchor {
                        guest_ns,
                        host_us: host_ms.checked_mul(1000)?,
                    })
                });
        }
        note_cookie_sets(&mut cookie_sets, &page);
        observe_processes(&mut nodes, &page);
        Ok(())
    })?;
    let cookies = resolve_cookies(&cookie_sets);
    let (mut journal, mut journal_error) = match FindingJournal::new(&recording.directory) {
        Ok(journal) => (Some(journal), None),
        Err(error) => (None, Some(error)),
    };
    let mut files = FdState::default();
    let mut open_page = sorting::Page::new(request, 1, cancel);
    let mut change_page = sorting::Page::new(request, 2, cancel);
    let mut file_index = files::FileIndex::default();
    let mut bpf_calls = Vec::new();
    let mut bpf_size = 0usize;
    let mut bpf_omitted = 0;
    let mut read_page = sorting::Page::new(request, 5, cancel);
    let read_query = query::compile_table(&request.filters[5], FILE_FIELDS);
    let open_query = query::compile_table(&request.filters[1], FILE_FIELDS);
    let change_query = query::compile_table(&request.filters[2], FILE_FIELDS);
    let (_, files_complete, _) = walk_pages(&recording, cancel, |page| {
        for invocation in page.iter().filter(scoped) {
            observe_processes(&mut files.process_images, std::slice::from_ref(invocation));
            let Some(event) = trace::representative(invocation) else {
                continue;
            };
            if call_args(invocation).is_some_and(|args| bpf_command(event, args).is_some()) {
                let size = invocation
                    .entry
                    .iter()
                    .chain(invocation.exit.iter())
                    .flat_map(|event| &event.fields)
                    .map(|field| field.preview.len() + field.key.len() + field.ranges.len() * 16)
                    .sum::<usize>();
                if bpf_calls.len() < STORED_ROWS && bpf_size.saturating_add(size) <= 8 * 1024 * 1024
                {
                    bpf_size += size;
                    bpf_calls.push(invocation.clone());
                } else {
                    bpf_omitted += 1;
                }
            }
            for mut finding in suspicious_rows_state(std::slice::from_ref(invocation), Some(&files))
            {
                finding.values.push((
                    "process.exe",
                    process_image(&files, event)
                        .map_or(RowValue::Missing, |image| RowValue::Text(image.into())),
                ));
                if let Some(writer) = &mut journal {
                    if let Err(error) = writer.push(&finding) {
                        journal_error = Some(error);
                        journal = None;
                    }
                }
                if finding_query.keep_table(&finding.values) {
                    finding_page.push(finding)?;
                }
            }
            remember_cwd(&mut files, invocation, event);
            remember_open(&mut files, invocation, event);
            apply_dup(&mut files, invocation, event);
            forget_closed(&mut files, invocation, event);
            inherit_open_fds(&mut files, invocation, event, &cookies);
            if let Some(row) = file_event_row(&files, invocation, event, OPEN_NAMES) {
                if request.file_visibility.keeps(&row) && open_query.keep_table(&row[0].values) {
                    open_page.push(row)?;
                }
            }
            if let Some(row) =
                file_index.observe(&files, invocation, event, Some(&recording.directory))
            {
                if request.file_visibility.keeps(&row) && read_query.keep_table(&row[0].values) {
                    read_page.push(row)?;
                }
            }
        }
        Ok(())
    })?;
    let bpf_identity = request.identity.as_ref();
    let bpf = bpf_notes(&TriageInput {
        invocations: &bpf_calls,
        vm_id: bpf_identity.map(|id| id.0.as_str()),
        boot_id: bpf_identity.map(|id| id.1.as_str()),
        run_id: bpf_identity.map(|id| id.2.as_str()),
        clock_anchor,
        ..TriageInput::empty()
    });
    let omitted_files = file_index.omitted_files;
    let file_changes: Vec<_> = file_index
        .finish()
        .into_iter()
        .filter(|change| {
            let row = change.row(clock_anchor);
            request.file_visibility.keeps(&row) && change_query.keep_table(&row[0].values)
        })
        .collect();
    for change in &file_changes {
        change_page.push(change.row(clock_anchor))?;
    }
    let (findings, findings_omitted, _) = finding_page.finish()?;
    let (opened, opened_omitted, _) = open_page.finish()?;
    let (read, read_omitted, _) = read_page.finish()?;
    let (changed, changed_omitted, _) = change_page.finish()?;
    let complete = complete && files_complete;
    if complete && !cancel.load(Ordering::Relaxed) {
        if let Some(writer) = &mut journal {
            if let Err(error) = writer.publish() {
                journal_error = Some(error);
            }
        }
    }
    let mut coverage = format!(
        "indexed {seen} saved calls{}; findings stored {}, omitted {findings_omitted}; opened stored {}, omitted {opened_omitted}; changed stored {}, omitted {changed_omitted}",
        total
            .map(|count| format!(" of {count}"))
            .unwrap_or_else(|| " (saved total unavailable)".into()),
        findings.len(),
        opened.len(),
        changed.len()
    );
    if !complete {
        coverage.push_str("; scan stopped before the end of telemetry.raw");
    }
    if !issues.is_empty() {
        coverage.push_str(&format!("; {} archive read issues", issues.len()));
    }
    if let Some(error) = journal_error {
        coverage.push_str(&format!(
            "; finding journal persistence unavailable: {error}"
        ));
    }
    let mut network_request = request.clone();
    network_request.owned_pcap = pcap
        .map(|path| network::owned_capture(&recording.directory, request.identity.as_ref(), path))
        .transpose()?
        .unwrap_or(false);
    network_request.started_ms = started_ms;
    network_request.ended_ms = facts.as_ref().and_then(|facts| facts.ended_ms);
    let estimated_end =
        !network_request.owned_pcap && request.run_finished && network_request.ended_ms.is_none();
    if estimated_end {
        network_request.ended_ms = nodes
            .values()
            .filter_map(|node| node.last_ns)
            .max()
            .and_then(|ns| clock_anchor.and_then(|clock| clock.host_us(ns)))
            .map(|us| us / 1000);
    }
    let mut network =
        match pcap {
            Some(path) => scan_pcap_query(path, pcap_open, cancel, &network_request)
                .unwrap_or_else(|error| PacketIndex {
                    coverage: format!("pcap index failed: {error}"),
                    http: Vec::new(),
                    http_omitted: 0,
                    dns: Vec::new(),
                    dns_omitted: 0,
                    ips: Vec::new(),
                    ips_omitted: 0,
                    hosts: Vec::new(),
                    hosts_omitted: 0,
                    network_warning: Some(format!("Network index unavailable: {error}")),
                }),
            None => PacketIndex {
                coverage:
                    "no pcap is recorded for this run; the loaded packet preview was not used"
                        .into(),
                http: Vec::new(),
                http_omitted: 0,
                dns: Vec::new(),
                dns_omitted: 0,
                ips: Vec::new(),
                ips_omitted: 0,
                hosts: Vec::new(),
                hosts_omitted: 0,
                network_warning: Some("No network capture is available for this run.".into()),
            },
        };
    if estimated_end && network.network_warning.is_none() {
        network.network_warning =
            Some("Network end time is estimated from this run’s last retained syscall.".into());
    }
    coverage.push_str(". ");
    coverage.push_str(&network.coverage);
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    Ok(ArchiveScan {
        clock_anchor,
        bpf,
        bpf_omitted,
        file_changes: file_changes
            .into_iter()
            .skip(request.offsets[2])
            .take(STORED_ROWS)
            .collect(),
        read,
        read_omitted,
        partial: !complete
            || omitted_files > 0
            || !issues.is_empty()
            || network.coverage.contains("failed")
            || pcap_open,
        #[cfg(test)]
        coverage,
        process: finish_processes(nodes),
        findings,
        findings_omitted,
        opened,
        opened_omitted,
        changed,
        changed_omitted,
        http: network.http,
        http_omitted: network.http_omitted,
        dns: network.dns,
        dns_omitted: network.dns_omitted,
        ips: network.ips,
        ips_omitted: network.ips_omitted,
        hosts: network.hosts,
        hosts_omitted: network.hosts_omitted,
        network_warning: network.network_warning,
    })
}

const TSHARK_FIELDS: &[&str] = &[
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.version",
    "http.response.code",
    "http.response_in",
    "http.request_in",
    "dns.id",
    "dns.qry.name",
    "dns.qry.type",
    "dns.qry.class",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.resp.name",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.response_in",
    "dns.response_to",
    "dns.retransmission",
    "ip.geoip.dst_country",
    "ipv6.geoip.dst_country",
    "ip.geoip.dst_org",
    "ipv6.geoip.dst_org",
    "tls.handshake.extensions_server_name",
];
const HTTP_HEADERS: &[&str] = &[
    "Frame",
    "Time",
    "Endpoint",
    "Method",
    "Host",
    "URI",
    "Response",
    "Response frame",
];
const DNS_HEADERS: &[&str] = &[
    "Frame",
    "Endpoint",
    "Qname",
    "Qtype",
    "Rcode",
    "Answers",
    "Response frame",
];

struct PacketSpool {
    directory: std::path::PathBuf,
    rows: std::fs::File,
    offsets: std::fs::File,
    size: u64,
}
impl PacketSpool {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "antinomie-triage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| error.to_string())?;
        let create = |name| {
            std::fs::OpenOptions::new()
                .mode(0o600)
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .map_err(|error| error.to_string())
        };
        let result = (|| {
            Ok(Self {
                rows: create("rows.tsv")?,
                offsets: create("frames.idx")?,
                directory: directory.clone(),
                size: 0,
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(directory);
        }
        result
    }
    fn push(&mut self, line: &str) -> Result<(), String> {
        use std::io::Write;
        let fields = tsv_fields(line)?;
        let frame = fields
            .first()
            .and_then(|number| number.parse::<u64>().ok())
            .ok_or("TShark frame ID is missing")?;
        let size = u64::try_from(line.len()).map_err(|_| "metadata line size overflow")? + 1;
        if self.size.saturating_add(size) > 512 * 1024 * 1024 {
            return Err(
                "Triage metadata scratch limit (512 MiB) exceeded; index incomplete".into(),
            );
        }
        self.offsets
            .write_all(&frame.to_le_bytes())
            .and_then(|()| self.offsets.write_all(&self.size.to_le_bytes()))
            .map_err(|error| error.to_string())?;
        self.rows
            .write_all(line.as_bytes())
            .and_then(|()| self.rows.write_all(b"\n"))
            .map_err(|error| error.to_string())?;
        self.size += size;
        Ok(())
    }
}
impl Drop for PacketSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn tsv_fields(line: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut value = String::new();
    let mut chars = line.trim_end_matches(['\r', '\n']).chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                value.push('"');
            }
            '"' => quoted = !quoted,
            '\t' if !quoted => {
                values.push(std::mem::take(&mut value));
            }
            _ => value.push(ch),
        }
    }
    if quoted {
        return Err("TShark field quote was truncated".into());
    }
    values.push(value);
    Ok(values)
}

fn epoch_us(value: &str) -> Option<u64> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let seconds = seconds.parse::<u64>().ok()?;
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut fraction = fraction.chars().take(6).collect::<String>();
    while fraction.len() < 6 {
        fraction.push('0');
    }
    seconds
        .checked_mul(1_000_000)?
        .checked_add(fraction.parse().ok()?)
}

fn spool_response(
    frame: u64,
    offsets: &mut std::fs::File,
    rows: &mut std::io::BufReader<std::fs::File>,
) -> Result<Vec<String>, String> {
    use std::io::{BufRead, Read, Seek, SeekFrom};
    let count = offsets.metadata().map_err(|error| error.to_string())?.len() / 16;
    let (mut low, mut high) = (0, count);
    let mut entry = [0u8; 16];
    while low < high {
        let mid = low + (high - low) / 2;
        offsets
            .seek(SeekFrom::Start(mid * 16))
            .and_then(|_| offsets.read_exact(&mut entry))
            .map_err(|error| error.to_string())?;
        let id = u64::from_le_bytes(
            entry[..8]
                .try_into()
                .map_err(|_| "metadata index frame length")?,
        );
        match id.cmp(&frame) {
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
            std::cmp::Ordering::Equal => {
                let offset = u64::from_le_bytes(
                    entry[8..]
                        .try_into()
                        .map_err(|_| "metadata index offset length")?,
                );
                rows.seek(SeekFrom::Start(offset))
                    .map_err(|error| error.to_string())?;
                let mut line = String::new();
                rows.read_line(&mut line)
                    .map_err(|error| error.to_string())?;
                return tsv_fields(&line);
            }
        }
    }
    Ok(Vec::new())
}

fn spool_packet_fields(
    identity: &antinomie_monitor_core::packet_filter::CaptureIdentity,
    live: bool,
    cancel: &Arc<AtomicBool>,
    geoip: bool,
) -> Result<
    (
        Arc<std::sync::Mutex<PacketSpool>>,
        antinomie_monitor_core::packet_filter::StreamExtent,
    ),
    String,
> {
    let spool = Arc::new(std::sync::Mutex::new(PacketSpool::new()?));
    let writer = Arc::clone(&spool);
    let fields: Vec<_> = TSHARK_FIELDS
        .iter()
        .enumerate()
        .filter(|(at, _)| geoip || !(31..35).contains(at))
        .map(|(_, field)| *field)
        .collect();
    let extent = antinomie_monitor_core::packet_filter::stream_fields(
        identity,
        "(ip || ipv6) && !tcp.analysis.retransmission",
        &fields,
        live,
        Arc::clone(cancel),
        move |line| {
            let mut spool = writer.lock().map_err(|_| "metadata spool lock poisoned")?;
            if geoip {
                spool.push(line)
            } else {
                let mut fields = tsv_fields(line)?;
                if fields.len() != TSHARK_FIELDS.len() - 4 {
                    return Err("TShark returned a different field layout".into());
                }
                for _ in 0..4 {
                    fields.insert(31, String::new());
                }
                let padded = fields
                    .iter()
                    .map(|field| format!("\"{}\"", field.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join("\t");
                spool.push(&padded)
            }
        },
    )?;
    Ok((spool, extent))
}

/// TShark reassembles the complete saved PCAP or an owned complete-record live
/// prefix. Output is disk-backed; response lookups use a fixed-size binary
/// index and memory holds only one query page. Source PCAP is unchanged.
fn scan_pcap_query(
    path: &Path,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
) -> Result<PacketIndex, String> {
    if !request.owned_pcap && request.identity.is_some() && request.started_ms.is_none() {
        return Err(
            "host start time unavailable; network evidence cannot be scoped to this run".into(),
        );
    }
    if !request.owned_pcap
        && request.identity.is_some()
        && request.run_finished
        && request.ended_ms.is_none()
    {
        return Err(
            "host end time unavailable; network evidence cannot be scoped to this run".into(),
        );
    }
    use std::io::{BufRead, BufReader};
    let identity = antinomie_monitor_core::packet_filter::CaptureIdentity::read(path)?;
    let (spool, extent) = match spool_packet_fields(&identity, pcap_open, cancel, true) {
        Err(error) if error.contains("geoip") && !cancel.load(Ordering::Relaxed) => {
            spool_packet_fields(&identity, pcap_open, cancel, false)?
        }
        result => result?,
    };
    let state = spool.lock().map_err(|_| "metadata spool lock poisoned")?;
    let mut rows = BufReader::new(
        std::fs::File::open(state.directory.join("rows.tsv")).map_err(|error| error.to_string())?,
    );
    let mut responses = BufReader::new(
        std::fs::File::open(state.directory.join("rows.tsv")).map_err(|error| error.to_string())?,
    );
    let mut offsets = std::fs::File::open(state.directory.join("frames.idx"))
        .map_err(|error| error.to_string())?;
    let mut index = PacketIndex {
        coverage: String::new(),
        http: Vec::new(),
        http_omitted: 0,
        dns: Vec::new(),
        dns_omitted: 0,
        ips: Vec::new(),
        ips_omitted: 0,
        hosts: Vec::new(),
        hosts_omitted: 0,
        network_warning: None,
    };
    let mut inventory = network::Inventory::default();
    let mut http_page = sorting::Page::new(request, 3, cancel);
    let mut dns_page = sorting::Page::new(request, 4, cancel);
    let http_query = query::compile_table(&request.filters[3], HTTP_FIELDS);
    let dns_query = query::compile_table(&request.filters[4], DNS_FIELDS);
    let mut line = String::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        line.clear();
        if rows
            .read_line(&mut line)
            .map_err(|error| error.to_string())?
            == 0
        {
            break;
        }
        let fields = tsv_fields(&line)?;
        if fields.len() != TSHARK_FIELDS.len() {
            return Err("TShark returned a different field layout".into());
        }
        let field = |at: usize| fields[at].as_str();
        let frame = field(0)
            .parse::<u64>()
            .map_err(|_| "invalid TShark frame number")?;
        let time = epoch_us(field(1));
        if !network::in_window(request, time) {
            continue;
        }
        let destination = if field(4).is_empty() {
            field(5)
        } else {
            field(4)
        };
        inventory.destination(
            destination,
            frame,
            if field(31).is_empty() {
                field(32)
            } else {
                field(31)
            },
            if field(33).is_empty() {
                field(34)
            } else {
                field(33)
            },
        );
        for hostname in field(35).split('\u{1f}').filter(|name| !name.is_empty()) {
            inventory.host(hostname, frame, time, &[destination.into()], "TLS SNI");
        }
        let endpoints = format!(
            "{}:{} → {}:{}",
            if field(2).is_empty() {
                field(3)
            } else {
                field(2)
            },
            if field(6).is_empty() {
                field(8)
            } else {
                field(6)
            },
            if field(4).is_empty() {
                field(5)
            } else {
                field(4)
            },
            if field(7).is_empty() {
                field(9)
            } else {
                field(7)
            }
        );
        if !field(11).is_empty() {
            let methods = field(11).split('\u{1f}').collect::<Vec<_>>();
            let response_frames = field(16)
                .split('\u{1f}')
                .filter_map(|id| id.parse::<u64>().ok())
                .collect::<Vec<_>>();
            for (at, method) in methods.iter().enumerate() {
                let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
                let response = match response_frames.get(at).copied() {
                    Some(frame) => spool_response(frame, &mut offsets, &mut responses)?,
                    None => Vec::new(),
                };
                let status = response
                    .get(15)
                    .and_then(|value| value.split('\u{1f}').next())
                    .and_then(|value| value.parse::<u16>().ok());
                let mut row = vec![
                    cell(format!("#{frame}"), theme::text(), true),
                    cell(
                        time.map_or("Unavailable".into(), crate::time_format::short_time_us),
                        theme::text(),
                        true,
                    ),
                    cell(&endpoints, theme::text(), true),
                    cell(*method, theme::text(), false),
                    cell(item(12), theme::text(), false),
                    cell(item(13), theme::text(), false),
                    cell(item(14), theme::text(), false),
                    cell(
                        status.map_or("—".into(), |status| status.to_string()),
                        theme::text(),
                        true,
                    ),
                    cell(field(16), theme::text(), true),
                    cell("unknown", theme::text(), false),
                    cell("decoded; capture gaps unknown", theme::text(), false),
                ];
                row[0].values = vec![
                    ("frame.number", RowValue::Number(i128::from(frame))),
                    (
                        "frame.time_us",
                        time.map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                    ),
                    ("network.endpoints", RowValue::Text(endpoints.clone())),
                    ("http.method", RowValue::Text((*method).into())),
                    ("http.host", text_value(item(12))),
                    ("http.uri", text_value(item(13))),
                    ("http.version", text_value(item(14))),
                    (
                        "http.status",
                        status.map_or(RowValue::Missing, |status| {
                            RowValue::Number(i128::from(status))
                        }),
                    ),
                    ("entry.complete", RowValue::Missing),
                    ("network.attribution", RowValue::Text("unknown".into())),
                ];
                inventory.host(item(12), frame, time, &[destination.into()], "HTTP");
                // Keep protocol/version metadata in typed filters, but only requested display columns.
                row.remove(10);
                row.remove(9);
                row.remove(6);
                if http_query.keep_table(&row[0].values) {
                    http_page.push(row)?;
                }
            }
        }
        if !field(19).is_empty() && tshark_boolean(field(22)) == Some(false) {
            let response_frame = field(28)
                .split('\u{1f}')
                .next()
                .and_then(|id| id.parse::<u64>().ok());
            let response = match response_frame {
                Some(frame) => spool_response(frame, &mut offsets, &mut responses)?,
                None => Vec::new(),
            };
            let rcode = response.get(23).and_then(|value| value.parse::<u16>().ok());
            let answers = [24, 25, 26, 27]
                .iter()
                .filter_map(|at| response.get(*at))
                .filter(|text| !text.is_empty())
                .flat_map(|text| text.split('\u{1f}').map(str::to_owned))
                .collect::<Vec<_>>();
            for (at, name) in field(19).split('\u{1f}').enumerate() {
                let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
                let id = field(18).split('\u{1f}').next().and_then(parse_integer);
                let protocol = if field(6).is_empty() { "UDP" } else { "TCP" };
                let retry = tshark_boolean(field(30));
                let mut row = vec![
                    cell(format!("#{frame}"), theme::text(), true),
                    cell(
                        time.map_or("Unavailable".into(), crate::time_format::short_time_us),
                        theme::text(),
                        true,
                    ),
                    cell(&endpoints, theme::text(), true),
                    cell(field(18), theme::text(), true),
                    cell(name, theme::text(), false),
                    cell(network::qtype(item(20)), theme::text(), false),
                    cell(item(21), theme::text(), false),
                    cell(protocol, theme::text(), false),
                    cell(
                        rcode.map_or("—".into(), |code| code.to_string()),
                        theme::text(),
                        true,
                    ),
                    cell(answers.join(", "), theme::text(), false),
                    cell(field(28), theme::text(), true),
                    cell(
                        match retry {
                            Some(true) => "retry",
                            Some(false) => "query",
                            None => "—",
                        },
                        theme::text(),
                        false,
                    ),
                ];
                row[0].values = vec![
                    ("frame.number", RowValue::Number(i128::from(frame))),
                    (
                        "frame.time_us",
                        time.map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                    ),
                    ("network.endpoints", RowValue::Text(endpoints.clone())),
                    ("dns.id", id.map_or(RowValue::Missing, RowValue::Number)),
                    ("dns.name", RowValue::Text(name.into())),
                    ("dns.type", text_value(&network::qtype(item(20)))),
                    ("dns.class", text_value(item(21))),
                    ("dns.protocol", RowValue::Text(protocol.into())),
                    (
                        "dns.rcode",
                        rcode.map_or(RowValue::Missing, |code| RowValue::Number(i128::from(code))),
                    ),
                    ("dns.answers", RowValue::List(answers.clone())),
                    ("dns.retry", retry.map_or(RowValue::Missing, RowValue::Bool)),
                ];
                let addresses: Vec<_> = answers
                    .iter()
                    .filter(|answer| answer.parse::<std::net::IpAddr>().is_ok())
                    .cloned()
                    .collect();
                inventory.host(name, frame, time, &addresses, "DNS lookup");
                for at in [11, 7, 6, 3, 1] {
                    row.remove(at);
                }
                if dns_query.keep_table(&row[0].values) {
                    dns_page.push(row)?;
                }
            }
        }
    }
    let (ips, hosts) = inventory.rows();
    let (http, http_omitted, http_count) = http_page.finish()?;
    let (dns, dns_omitted, dns_count) = dns_page.finish()?;
    index.http = http;
    index.http_omitted = http_omitted;
    index.dns = dns;
    index.dns_omitted = dns_omitted;
    for (slot, rows, fields) in [
        (6, ips, network::IP_FIELDS),
        (7, hosts, network::HOST_FIELDS),
    ] {
        let query = query::compile_table(&request.filters[slot], fields);
        let mut page = sorting::Page::new(request, slot, cancel);
        for row in rows
            .into_iter()
            .filter(|row| query.keep_table(&row[0].values))
        {
            page.push(row)?;
        }
        let (rows, omitted, _) = page.finish()?;
        if slot == 6 {
            index.ips = rows;
            index.ips_omitted = omitted;
        } else {
            index.hosts = rows;
            index.hosts_omitted = omitted;
        }
    }
    if inventory.omitted > 0 {
        index.network_warning = Some(
            "Network inventory retention limit reached; packet evidence remains available.".into(),
        );
    }
    index.coverage = format!("TShark HTTP/1 and DNS/UDP/TCP; {} capture frames; complete-record extent {}/{} octets; HTTP matches {http_count}, DNS matches {dns_count}; response correlation uses decoder frame links; attribution unknown. HTTPS, HTTP/2, HTTP/3 and encrypted DNS unavailable{}",
        extent.packet_count, extent.complete_extent, extent.file_size,
        if pcap_open { "; live prefix watermark; final capture requires reanalysis" } else { "" });
    Ok(index)
}
fn text_value(text: &str) -> RowValue {
    if text.is_empty() {
        RowValue::Missing
    } else {
        RowValue::Text(text.into())
    }
}

/// TShark releases format FT_BOOLEAN as textual True/False or numeric 1/0.
/// An absent, malformed or mixed repeated field stays unknown.
fn tshark_boolean(text: &str) -> Option<bool> {
    let mut value = None;
    for item in text.split('\u{1f}') {
        let next = match item {
            "1" => true,
            "0" => false,
            text if text.eq_ignore_ascii_case("true") => true,
            text if text.eq_ignore_ascii_case("false") => false,
            _ => return None,
        };
        if value.is_some_and(|value| value != next) {
            return None;
        }
        value = Some(next);
    }
    value
}
fn parse_integer(text: &str) -> Option<i128> {
    if let Some(hex) = text.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

#[cfg(test)]
const PACKET_BOUND: usize = 4096;

struct PacketIndex {
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

/// Read the owned pcap to the end, or to [`PACKET_BOUND`] frames. Reconstruction
/// uses those frames. A later frame is counted and not decoded.
#[cfg(test)]
fn scan_pcap(path: &Path, pcap_open: bool, cancel: &AtomicBool) -> Result<PacketIndex, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    if !path.is_file() {
        return Err("pcap path is not a file".into());
    }
    let mut offset = 0u64;
    let mut number = 0u64;
    let mut held: Vec<(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)> = Vec::new();
    let mut omitted = 0u64;
    let mut stopped = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }
        let page = antinomie_monitor_core::network::read_page(path, offset, number, 256)?;
        if page.packets.is_empty() {
            break;
        }
        for packet in page.packets {
            if held.len() >= PACKET_BOUND {
                omitted += 1;
                continue;
            }
            let bytes = antinomie_monitor_core::network::frame(path, packet.offset)?;
            held.push((packet, bytes));
        }
        if page.next_offset <= offset {
            break;
        }
        offset = page.next_offset;
        number = page.next_number;
    }
    let captured: Vec<_> = held
        .iter()
        .map(
            |(packet, bytes)| antinomie_monitor_core::network::CapturedFrame {
                number: packet.number,
                time_us: packet.time_us,
                bytes,
            },
        )
        .collect();
    let built = antinomie_monitor_core::network::reconstruct(&captured);
    let mut http = Vec::new();
    let mut http_omitted = 0u64;
    for request in &built.http {
        if http.len() >= STORED_ROWS {
            http_omitted += 1;
            continue;
        }
        http.push(http_index_row(request, &held));
    }
    let mut dns = Vec::new();
    let mut dns_omitted = 0u64;
    for query in &built.dns {
        if dns.len() >= STORED_ROWS {
            dns_omitted += 1;
            continue;
        }
        dns.push(dns_index_row(query, &held));
    }
    let mut coverage = format!(
        "pcap frames read {}, omitted {omitted}; retransmissions dropped {}; HTTPS segments {}; HTTP/2 prefaces {}; HTTP requests stored {}, omitted {http_omitted}; DNS requests stored {}, omitted {dns_omitted}",
        held.len(),
        built.retransmissions_dropped,
        built.https_segments,
        built.http2_prefaces,
        http.len(),
        dns.len()
    );
    if stopped {
        coverage.push_str("; scan stopped before the end of the pcap");
    } else if pcap_open {
        coverage.push_str(
            "; the capture file was read to its current end; a live capture may still grow",
        );
    }
    Ok(PacketIndex {
        coverage,
        http,
        http_omitted,
        dns,
        dns_omitted,
        ips: Vec::new(),
        ips_omitted: 0,
        hosts: Vec::new(),
        hosts_omitted: 0,
        network_warning: None,
    })
}

#[cfg(test)]
fn packet_ends(
    number: Option<u64>,
    held: &[(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)],
) -> String {
    number
        .and_then(|number| held.iter().find(|(packet, _)| packet.number == number))
        .map(|(packet, _)| format!("{} → {}", packet.source, packet.destination))
        .unwrap_or_else(|| "—".into())
}

#[cfg(test)]
fn http_index_row(
    request: &antinomie_monitor_core::network::ReconstructedHttp,
    held: &[(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)],
) -> Vec<Cell> {
    let mut row = flow(
        request
            .request_frames
            .first()
            .map(|number| format!("#{number}"))
            .unwrap_or_else(|| "—".into()),
        packet_ends(request.request_frames.first().copied(), held),
        format!("{} {} {}", request.method, request.uri, request.version),
    );
    row.push(cell(
        request
            .status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "—".into()),
        theme::text(),
        false,
    ));
    row.push(cell("—".to_string(), theme::text(), true));
    row
}

#[cfg(test)]
fn dns_index_row(
    query: &antinomie_monitor_core::network::ReconstructedDns,
    held: &[(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)],
) -> Vec<Cell> {
    let detail = if query.answers.is_empty() {
        format!("{} {} {}", query.name, query.qtype, query.class_name)
    } else {
        format!(
            "{} {} {} → {}",
            query.name,
            query.qtype,
            query.class_name,
            query.answers.join(", ")
        )
    };
    let mut row = flow(
        query
            .query_frames
            .first()
            .map(|number| format!("#{number}"))
            .unwrap_or_else(|| "—".into()),
        packet_ends(query.query_frames.first().copied(), held),
        detail,
    );
    let kind = if query.retry {
        "retry"
    } else if query.rcode.is_some() {
        "response"
    } else {
        "query"
    };
    row.push(cell(
        format!("{kind} {}", query.protocol),
        theme::text(),
        false,
    ));
    row
}

fn walk_pages(
    recording: &antinomie_monitor_core::recording::Recording,
    cancel: &AtomicBool,
    mut each: impl FnMut(&[InvocationSummary]) -> Result<(), String>,
) -> Result<(u64, bool, Vec<String>), String> {
    let mut offset = 0u64;
    let mut seen = 0u64;
    let mut issues = Vec::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok((seen, false, issues));
        }
        let page = match recording.invocation_page_cancellable(offset, 256, cancel) {
            Ok(page) => page,
            Err(error) => {
                let text = error.to_string();
                if text.contains("cancelled") {
                    return Ok((seen, false, issues));
                }
                return Err(text);
            }
        };
        seen += page.invocations.len() as u64;
        issues.extend(page.issues);
        each(&page.invocations)?;
        match page.next_offset {
            Some(next) if next > offset => offset = next,
            Some(_) => return Err("archive cursor did not advance".into()),
            None => return Ok((seen, true, issues)),
        }
    }
}

fn note_cookie_sets(
    sets: &mut std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>>,
    invocations: &[InvocationSummary],
) {
    for invocation in invocations {
        for event in invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
        {
            if event.tid == 0 {
                continue;
            }
            sets.entry(event.tid)
                .or_default()
                .insert(invocation.task_cookie);
        }
    }
}

fn resolve_cookies(
    sets: &std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>>,
) -> std::collections::BTreeMap<u32, u64> {
    sets.iter()
        .filter(|(_, cookies)| cookies.len() == 1)
        .map(|(pid, cookies)| (*pid, cookies.iter().next().copied().unwrap_or(0)))
        .collect()
}

/// Successful `open`, `openat` and `openat2` return the new descriptor.
/// Every other file operation uses the argument whose schema name is `fd`.
fn file_fd(invocation: &InvocationSummary, event: &EventSummary) -> String {
    if OPEN_NAMES.contains(&event.syscall_name.as_str()) {
        return invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .filter(|result| *result >= 0)
            .map(|result| result.to_string())
            .unwrap_or_else(|| "—".into());
    }
    fd_argument(invocation, event)
        .map(|fd| {
            if fd == u64::from(u32::MAX) || fd == u64::MAX {
                "—".to_string()
            } else {
                fd.to_string()
            }
        })
        .unwrap_or_else(|| "—".into())
}

/// The `fd` argument. `mmap2` is not in the x86-64 table; its descriptor is
/// still argument 4, the same slot `mmap` names `fd`.
fn fd_argument(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    let args = call_args(invocation)?;
    if matches!(event.syscall_name.as_str(), "copy_file_range" | "splice") {
        return Some(args[2]);
    }
    if event.syscall_name == "sendfile" {
        return Some(args[0]);
    }
    let index = (0..args.len())
        .find(|index| trace::argument_name(event.syscall_nr, *index) == "fd")
        .or_else(|| matches!(event.syscall_name.as_str(), "mmap" | "mmap2").then_some(4))?;
    (index < args.len()).then_some(args[index])
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

fn table_owner(files: &FdState, cookie: u64, pid: u32) -> (u64, u32) {
    follow_share(&files.share, cookie, pid)
}

fn fs_owner(files: &FdState, cookie: u64, pid: u32) -> (u64, u32) {
    follow_share(&files.fs_share, cookie, pid)
}

fn follow_share(
    share: &std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    cookie: u64,
    pid: u32,
) -> (u64, u32) {
    let mut key = (cookie, pid);
    for _ in 0..8 {
        match share.get(&key) {
            Some(next) if *next != key => key = *next,
            _ => break,
        }
    }
    key
}

fn file_outcome(invocation: &InvocationSummary) -> String {
    match invocation.exit.as_ref().and_then(|exit| exit.result) {
        Some(result) if result >= 0 => "successful".into(),
        Some(_) => "failed attempt".into(),
        None => "exit not recorded".into(),
    }
}

fn succeeded(invocation: &InvocationSummary) -> bool {
    invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .is_some_and(|result| result >= 0)
}

fn remember_open(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if event.syscall_name == "memfd_create" && succeeded(invocation) {
        if let Some(fd) = invocation.exit.as_ref().and_then(|exit| exit.result) {
            let owner = table_owner(files, invocation.task_cookie, event.tid);
            let name = event
                .fields
                .iter()
                .find_map(path_text)
                .unwrap_or_else(|| "unnamed".into());
            let key = (owner.0, owner.1, fd as u64);
            files.opened.insert(key, format!("memfd:{name}"));
            if call_args(invocation).is_some_and(|args| args[1] & 1 != 0) {
                files.cloexec.insert(key);
            }
        }
        return;
    }
    if !OPEN_NAMES.contains(&event.syscall_name.as_str()) {
        return;
    }
    if !succeeded(invocation) {
        return;
    }
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    let key = (cookie, pid, result as u64);
    let paths = path_list(invocation);
    if paths.is_empty() {
        files.opened.remove(&key);
    } else {
        files
            .opened
            .insert(key, displayed_path(invocation, event, files));
    }
    if open_flags(invocation, event).is_some_and(|flags| flags & 0x80000 != 0) {
        files.cloexec.insert(key);
    } else {
        files.cloexec.remove(&key);
    }
}

fn remember_cwd(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if !matches!(event.syscall_name.as_str(), "chdir" | "fchdir" | "getcwd") {
        return;
    }
    let owner = fs_owner(files, invocation.task_cookie, event.tid);
    if invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .is_some_and(|ret| ret < 0)
    {
        return;
    }
    if !succeeded(invocation) {
        files.cwd.remove(&owner);
        files.cwd_unverified.insert(owner);
        return;
    }
    let path = match event.syscall_name.as_str() {
        "getcwd" => path_list(invocation)
            .into_iter()
            .next()
            .filter(|path| path.starts_with('/')),
        "chdir" => path_list(invocation)
            .into_iter()
            .next()
            .and_then(|path| resolve_chdir(files, owner, path)),
        "fchdir" => call_args(invocation).and_then(|args| {
            let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
            files
                .opened
                .get(&(cookie, pid, args[0]))
                .cloned()
                .filter(|path| path.starts_with('/'))
        }),
        _ => None,
    };
    if let Some(path) = path {
        files.cwd.insert(owner, path);
        if event.syscall_name == "getcwd" {
            files.cwd_unverified.remove(&owner);
        } else {
            files.cwd_unverified.insert(owner);
        }
    } else {
        files.cwd.remove(&owner);
        files.cwd_unverified.insert(owner);
    }
}

/// An absolute chdir is stored as given. A relative chdir is applied to the
/// task's current directory. Without a recorded directory the relative change
/// is left unknown instead of being treated as an absolute path.
fn resolve_chdir(files: &FdState, owner: (u64, u32), path: String) -> Option<String> {
    if path.starts_with('/') {
        return Some(path);
    }
    let base = files.cwd.get(&owner)?;
    Some(join_cwd(base, &path))
}

fn join_cwd(base: &str, relative: &str) -> String {
    // chdir resolves '..' after symlinks. Lexical normalization would invent
    // a physical working directory, so retain the literal observed components.
    format!("{}/{relative}", base.trim_end_matches('/'))
}

/// `dup` returns the new descriptor. `dup2` and `dup3` name it in argument 1.
fn apply_dup(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if event.syscall_name == "fcntl" && succeeded(invocation) {
        if let Some(args) = call_args(invocation) {
            if args[1] == 2 {
                let owner = table_owner(files, invocation.task_cookie, event.tid);
                let key = (owner.0, owner.1, args[0]);
                if args[2] & 1 != 0 {
                    files.cloexec.insert(key);
                } else {
                    files.cloexec.remove(&key);
                }
                return;
            }
        }
    }
    let kind = match (event.syscall_nr, event.syscall_name.as_str()) {
        (32, _) | (_, "dup") => DupKind::Return,
        (33, _) | (_, "dup2") | (292, _) | (_, "dup3") => DupKind::Argument,
        (_, "fcntl") if call_args(invocation).is_some_and(|args| matches!(args[1], 0 | 1030)) => {
            DupKind::Return
        }
        _ => return,
    };
    if !succeeded(invocation) {
        return;
    }
    let Some(args) = call_args(invocation) else {
        return;
    };
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    let new_fd = match kind {
        DupKind::Return => result as u64,
        DupKind::Argument => args[1],
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    let Some(path) = files.opened.get(&(cookie, pid, args[0])).cloned() else {
        files.opened.remove(&(cookie, pid, new_fd));
        return;
    };
    files.opened.insert((cookie, pid, new_fd), path);
    let key = (cookie, pid, new_fd);
    if new_fd != args[0] {
        files.cloexec.remove(&key);
    }
    if event.syscall_name == "dup3" && args[2] & 0x80000 != 0 {
        files.cloexec.insert(key);
    }
    if event.syscall_name == "fcntl" && args[1] == 1030 {
        files.cloexec.insert(key);
    }
}

enum DupKind {
    Return,
    Argument,
}

/// One cookie per pid when every event for that pid shares it. Two cookies
/// for one pid are not a guess: the caller uses 0.
#[cfg(test)]
fn task_cookies(invocations: &[InvocationSummary]) -> std::collections::BTreeMap<u32, u64> {
    let mut sets: std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>> =
        std::collections::BTreeMap::new();
    for invocation in invocations {
        for event in invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
        {
            if event.tid == 0 {
                continue;
            }
            sets.entry(event.tid)
                .or_default()
                .insert(invocation.task_cookie);
        }
    }
    sets.into_iter()
        .filter_map(|(pid, cookies)| {
            (cookies.len() == 1).then(|| (pid, cookies.into_iter().next().unwrap()))
        })
        .collect()
}

/// A successful `close` drops that task's descriptor only.
fn forget_closed(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if matches!(event.syscall_name.as_str(), "execve" | "execveat") && succeeded(invocation) {
        detach_files(files, invocation.task_cookie, event.tid);
        let owner = table_owner(files, invocation.task_cookie, event.tid);
        let closed = files
            .cloexec
            .iter()
            .filter(|(cookie, tid, _)| (*cookie, *tid) == owner)
            .copied()
            .collect::<Vec<_>>();
        for key in closed {
            files.opened.remove(&key);
            files.cloexec.remove(&key);
        }
        return;
    }
    if event.syscall_name == "close_range" && succeeded(invocation) {
        if let Some(args) = call_args(invocation) {
            if args[2] & 2 != 0 {
                detach_files(files, invocation.task_cookie, event.tid);
            }
            let owner = table_owner(files, invocation.task_cookie, event.tid);
            let keys = files
                .opened
                .keys()
                .filter(|(cookie, tid, fd)| {
                    (*cookie, *tid) == owner && *fd >= args[0] && *fd <= args[1]
                })
                .copied()
                .collect::<Vec<_>>();
            for key in keys {
                if args[2] & 4 != 0 {
                    files.cloexec.insert(key);
                } else {
                    files.opened.remove(&key);
                    files.cloexec.remove(&key);
                }
            }
        }
        return;
    }
    if event.syscall_name != "close" && event.syscall_nr != 3 {
        return;
    }
    if invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .is_some_and(|ret| ret < 0)
    {
        return;
    }
    let Some(fd) = fd_argument(invocation, event) else {
        return;
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    files.opened.remove(&(cookie, pid, fd));
    files.cloexec.remove(&(cookie, pid, fd));
}

fn detach_files(files: &mut FdState, cookie: u64, tid: u32) {
    let owner = table_owner(files, cookie, tid);
    if owner == (cookie, tid) {
        let sharers = files
            .share
            .keys()
            .copied()
            .filter(|(c, t)| table_owner(files, *c, *t) == owner)
            .collect::<Vec<_>>();
        if let Some(new_owner) = sharers.first().copied() {
            copy_files(files, owner, new_owner);
            files.share.remove(&new_owner);
            for sharer in sharers.into_iter().skip(1) {
                files.share.insert(sharer, new_owner);
            }
        }
    } else {
        copy_files(files, owner, (cookie, tid));
        files.share.remove(&(cookie, tid));
    }
}
fn copy_files(files: &mut FdState, source: (u64, u32), target: (u64, u32)) {
    let entries = files
        .opened
        .iter()
        .filter(|((cookie, tid, _), _)| (*cookie, *tid) == source)
        .map(|((_, _, fd), path)| (*fd, path.clone()))
        .collect::<Vec<_>>();
    for (fd, path) in entries {
        files.opened.insert((target.0, target.1, fd), path);
        if files.cloexec.contains(&(source.0, source.1, fd)) {
            files.cloexec.insert((target.0, target.1, fd));
        }
    }
}

/// Snapshot the parent's open descriptors onto the new process. The child
/// keeps its own entries; a later close does not edit the parent.
fn inherit_open_fds(
    files: &mut FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
    cookies: &std::collections::BTreeMap<u32, u64>,
) {
    if !matches!(event.syscall_nr, FORK | VFORK | CLONE | CLONE3)
        || (event.syscall_nr == CLONE3 && clone3_flags(invocation).is_none())
    {
        return;
    }
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    if result <= 0 {
        return;
    }
    let Some(child_pid) = u32::try_from(result).ok() else {
        return;
    };
    let child_cookie = cookies.get(&child_pid).copied().unwrap_or(0);
    if child_pid == event.tid && child_cookie == invocation.task_cookie {
        return;
    }
    let parent = table_owner(files, invocation.task_cookie, event.tid);
    if shares_files(invocation, event) {
        files.share.insert((child_cookie, child_pid), parent);
    } else {
        copy_files(files, parent, (child_cookie, child_pid));
    }
    let directory = fs_owner(files, invocation.task_cookie, event.tid);
    if shares_fs(invocation, event) {
        files.fs_share.insert((child_cookie, child_pid), directory);
    } else if let Some(cwd) = files.cwd.get(&directory).cloned() {
        files.cwd.entry((child_cookie, child_pid)).or_insert(cwd);
        if files.cwd_unverified.contains(&directory) {
            files.cwd_unverified.insert((child_cookie, child_pid));
        }
    }
}

fn shares_files(invocation: &InvocationSummary, event: &EventSummary) -> bool {
    clone_flag(invocation, event, CLONE_FILES)
}

fn shares_fs(invocation: &InvocationSummary, event: &EventSummary) -> bool {
    clone_flag(invocation, event, CLONE_FS)
}

fn clone_flag(invocation: &InvocationSummary, event: &EventSummary, flag: u64) -> bool {
    match event.syscall_nr {
        CLONE => call_args(invocation).is_some_and(|args| args[0] & flag != 0),
        CLONE3 => clone3_flags(invocation).is_some_and(|flags| flags & flag != 0),
        _ => false,
    }
}

fn clone3_flags(invocation: &InvocationSummary) -> Option<u64> {
    let field = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(invocation.async_events.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key.contains("clone_args") && field.key.contains("flags"))?;
    let bytes = trace::covered_preview(field);
    match bytes.len() {
        4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn displayed_path(invocation: &InvocationSummary, event: &EventSummary, files: &FdState) -> String {
    if matches!(event.syscall_name.as_str(), "renameat" | "renameat2") {
        let args = call_args(invocation);
        let old = named_path(invocation, event, &["oldname", "old_path"])
            .map(|path| {
                resolve_path_dirfd(&path, invocation, event, files, args.map(|args| args[0]))
            })
            .unwrap_or_else(|| "—".into());
        let new = named_path(invocation, event, &["newname", "new_path"])
            .map(|path| {
                resolve_path_dirfd(&path, invocation, event, files, args.map(|args| args[2]))
            })
            .unwrap_or_else(|| "—".into());
        return format!("{old} → {new}");
    }
    if event.syscall_name == "memfd_create" {
        return event
            .fields
            .iter()
            .find_map(path_text)
            .map(|name| format!("memfd:{name}"))
            .unwrap_or_else(|| "memfd:unnamed".into());
    }
    let own = path_list(invocation);
    if !own.is_empty() {
        return own
            .iter()
            .enumerate()
            .map(|(index, path)| {
                if index == 1 && matches!(event.syscall_name.as_str(), "renameat" | "renameat2") {
                    resolve_path_dirfd(
                        path,
                        invocation,
                        event,
                        files,
                        call_args(invocation).map(|args| args[2]),
                    )
                } else {
                    resolve_path(path, invocation, event, files)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
    }
    if matches!(event.syscall_name.as_str(), "mmap" | "mmap2") {
        let anonymous = call_args(invocation)
            .is_some_and(|args| args.get(3).is_some_and(|flags| flags & MAP_ANONYMOUS != 0));
        if anonymous {
            return "—".into();
        }
        if let Some(fd) = fd_argument(invocation, event) {
            if fd != u64::MAX {
                let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
                if let Some(path) = files.opened.get(&(cookie, pid, fd)) {
                    return path.clone();
                }
            }
        }
        return "—".into();
    }
    if let Some(fd) = fd_argument(invocation, event) {
        let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
        if let Some(path) = files.opened.get(&(cookie, pid, fd)) {
            return path.clone();
        }
    }
    // Trace text is not a path. An uncaptured filename stays unknown.
    "—".into()
}

fn resolve_path(
    path: &str,
    invocation: &InvocationSummary,
    event: &EventSummary,
    files: &FdState,
) -> String {
    resolve_path_dirfd(
        path,
        invocation,
        event,
        files,
        dirfd_argument(invocation, event),
    )
}
fn resolve_path_dirfd(
    path: &str,
    invocation: &InvocationSummary,
    event: &EventSummary,
    files: &FdState,
    dirfd: Option<u64>,
) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    if event.syscall_name.ends_with("at") || event.syscall_name.ends_with("at2") {
        if let Some(dirfd) = dirfd {
            if dirfd != AT_FDCWD {
                return match files.opened.get(&(cookie, pid, dirfd)) {
                    Some(base) if base.starts_with('/') => format!(
                        "{}/{path} (lexical dirfd path; symlinks unknown)",
                        base.split(" (lexical").next().unwrap_or(base)
                    ),
                    _ => format!("{path} (relative, dirfd not recorded)"),
                };
            }
        }
    }
    let directory = fs_owner(files, invocation.task_cookie, event.tid);
    match files.cwd.get(&directory) {
        Some(cwd) => format!("{cwd}/{path} (lexical cwd path; symlinks unknown)"),
        None => format!("{path} (relative, cwd not recorded)"),
    }
}

fn dirfd_argument(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    let args = call_args(invocation)?;
    let index = (0..args.len()).find(|index| {
        matches!(
            trace::argument_name(event.syscall_nr, *index),
            "dfd" | "dirfd" | "olddfd"
        )
    })?;
    (index < args.len()).then_some(args[index])
}

fn path_key(key: &str) -> bool {
    key.split(['.', '[', ']']).any(|part| {
        matches!(
            part,
            "path" | "pathname" | "filename" | "oldname" | "newname" | "old_path" | "new_path"
        )
    })
}

fn named_path(
    invocation: &InvocationSummary,
    event: &EventSummary,
    names: &[&str],
) -> Option<String> {
    let arguments = (0..6)
        .filter(|index| names.contains(&trace::argument_name(event.syscall_nr, *index)))
        .map(|index| format!("arg{index}."))
        .collect::<Vec<_>>();
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| &event.fields)
        .filter(|field| {
            path_key(&field.key)
                && (field.key.split('.').any(|part| names.contains(&part))
                    || arguments.iter().any(|prefix| field.key.starts_with(prefix)))
        })
        .find_map(path_text)
}

fn path_text(field: &antinomie_monitor_core::FieldSummary) -> Option<String> {
    let bytes = trace::covered_preview(field);
    let end = bytes.iter().rposition(|byte| *byte != 0)?;
    let text = std::str::from_utf8(&bytes[..=end]).ok()?.trim();
    if text.is_empty()
        || text.chars().any(char::is_control)
        || text.contains('=')
        || text.contains("uncaptured")
    {
        return None;
    }
    Some(text.to_string())
}

fn path_list(invocation: &InvocationSummary) -> Vec<String> {
    let mut paths = Vec::new();
    for event in invocation.entry.iter().chain(invocation.exit.iter()) {
        for field in &event.fields {
            if !path_key(&field.key)
                && !(event.syscall_name == "getcwd" && field.key.split('.').any(|key| key == "buf"))
            {
                continue;
            }
            if let Some(text) = path_text(field) {
                if !paths.contains(&text) {
                    paths.push(text);
                }
            }
        }
    }
    paths
}

#[cfg(test)]
fn flow(frame: impl Into<String>, ends: impl Into<String>, detail: impl Into<String>) -> Vec<Cell> {
    vec![
        cell(frame, theme::value(theme::ValueKind::Number), true),
        cell(ends, theme::text(), true),
        cell(detail, theme::text(), false),
    ]
}

#[cfg(test)]
fn http_rows(input: &TriageInput<'_>) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    let Some(built) = reconstruct_input(input) else {
        return limited;
    };
    for request in built.http {
        let packet = request
            .request_frames
            .first()
            .and_then(|number| input.packets.iter().find(|packet| packet.number == *number));
        let ends = packet
            .map(|packet| format!("{} → {}", packet.source, packet.destination))
            .unwrap_or_else(|| "—".into());
        let mut row = flow(
            request
                .request_frames
                .first()
                .map(|number| format!("#{number}"))
                .unwrap_or_else(|| "—".into()),
            ends,
            format!("{} {} {}", request.method, request.uri, request.version),
        );
        row.push(cell(
            request
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "—".into()),
            theme::text(),
            false,
        ));
        row.push(cell(
            packet
                .map(|packet| http_process(packet, input.invocations))
                .unwrap_or_else(|| "—".into()),
            theme::text(),
            true,
        ));
        if !push_limited(&mut limited, row) {
            break;
        }
    }
    limited
}

#[cfg(test)]
fn reconstruct_input(
    input: &TriageInput<'_>,
) -> Option<antinomie_monitor_core::network::Reconstruction> {
    let frames = input.frames?;
    if frames.is_empty() || frames.len() > input.packets.len() {
        return None;
    }
    let captured: Vec<_> = input
        .packets
        .iter()
        .zip(frames.iter())
        .map(
            |(packet, bytes)| antinomie_monitor_core::network::CapturedFrame {
                number: packet.number,
                time_us: packet.time_us,
                bytes,
            },
        )
        .collect();
    Some(antinomie_monitor_core::network::reconstruct(&captured))
}

/// Process of a connect or sendto whose path or info text contains this
/// packet's destination address and destination port. Port text alone is
/// not enough. Anything else is an em dash.
#[cfg(test)]
fn http_process(packet: &NetworkPacket, invocations: &[InvocationSummary]) -> String {
    let Some(port) = packet.dst_port else {
        return "—".into();
    };
    let address = packet_address(packet);
    if address.is_empty() {
        return "—".into();
    }
    let port_text = port.to_string();
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        if !connects_or_sends(event) {
            continue;
        }
        if mentions_endpoint(invocation, &address, &port_text) {
            return format!(
                "ambiguous: endpoint candidate pid {} tid {}",
                event.pid, event.tid
            );
        }
    }
    "—".into()
}

#[cfg(test)]
fn packet_address(packet: &NetworkPacket) -> String {
    if let Some(ip) = packet.dst_ip {
        return ip.to_string();
    }
    let destination = packet.destination.trim();
    if let Some(port) = packet.dst_port {
        let suffix = format!(":{port}");
        if let Some(host) = destination.strip_suffix(&suffix) {
            let host = host
                .strip_prefix('[')
                .and_then(|text| text.strip_suffix(']'))
                .unwrap_or(host)
                .trim();
            if !host.is_empty() {
                return host.to_string();
            }
        }
    }
    destination.to_string()
}

#[cfg(test)]
fn connects_or_sends(event: &EventSummary) -> bool {
    matches!(event.syscall_name.as_str(), "connect" | "sendto")
        || matches!(event.syscall_nr, 42 | 44)
}

#[cfg(test)]
fn mentions_endpoint(invocation: &InvocationSummary, address: &str, port: &str) -> bool {
    let info = trace::info(invocation);
    path_list(invocation)
        .iter()
        .any(|path| contains_address_and_port(path, address, port))
        || contains_address_and_port(&info, address, port)
}

#[cfg(test)]
fn contains_address_and_port(text: &str, address: &str, port: &str) -> bool {
    text.contains(address) && text.contains(port)
}

#[cfg(test)]
fn dns_rows(input: &TriageInput<'_>) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    let Some(built) = reconstruct_input(input) else {
        return limited;
    };
    for query in built.dns {
        let packet = query
            .query_frames
            .first()
            .and_then(|number| input.packets.iter().find(|packet| packet.number == *number));
        let ends = packet
            .map(|packet| format!("{} → {}", packet.source, packet.destination))
            .unwrap_or_else(|| "—".into());
        let detail = if query.answers.is_empty() {
            format!("{} {} {}", query.name, query.qtype, query.class_name)
        } else {
            format!(
                "{} {} {} → {}",
                query.name,
                query.qtype,
                query.class_name,
                query.answers.join(", ")
            )
        };
        let mut row = flow(
            query
                .query_frames
                .first()
                .map(|number| format!("#{number}"))
                .unwrap_or_else(|| "—".into()),
            ends,
            detail,
        );
        let kind = if query.retry {
            "retry"
        } else if query.rcode.is_some() {
            "response"
        } else {
            "query"
        };
        row.push(cell(
            format!("{kind} {}", query.protocol),
            theme::text(),
            false,
        ));
        if !push_limited(&mut limited, row) {
            break;
        }
    }
    limited
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

fn bpf_notes(input: &TriageInput<'_>) -> Vec<BpfNote> {
    let mut notes = Vec::new();
    // File descriptors returned by successful BPF_PROG_LOAD calls in this slice.
    let mut program_fds = Vec::<(u64, i64)>::new();
    for invocation in input.invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        if event.syscall_name == "close" && succeeded(invocation) {
            if let Some(fd) = call_args(invocation).and_then(|args| i64::try_from(args[0]).ok()) {
                program_fds.retain(|key| *key != (invocation.task_cookie, fd));
            }
        }
        let recorded_args = event.args.or_else(|| call_args(invocation));
        let args = recorded_args.unwrap_or([0; 6]);
        let Some(command) = bpf_command(event, args) else {
            continue;
        };
        let image = instruction_image(invocation, command);
        let (translation, dump, export, bytes, identity) = if let Some(bytes) = image.as_deref() {
            let action = if command == "BPF_PROG_LOAD" {
                "load"
            } else if command == "BPF_PROG_ATTACH" || command == "SO_ATTACH_FILTER" {
                "attach"
            } else {
                command
            };
            let identity = bpf::BpfIdentity {
                stream_id: invocation.stream_id,
                vm_id: input.vm_id.map(str::to_owned),
                boot_id: input.boot_id.map(str::to_owned),
                run_id: input.run_id.map(str::to_owned),
                cookie: Some(invocation.task_cookie),
                pid: Some(event.pid),
                tid: Some(event.tid),
                timestamp_ns: (event.timestamp_ns != 0).then_some(event.timestamp_ns),
                action: action.to_owned(),
                source_syscall: event.syscall_name.clone(),
                event_id: Some(invocation.call_id),
                result: invocation.exit.as_ref().and_then(|exit| exit.result),
                attachment_kind: if command == "SO_ATTACH_FILTER" {
                    "classic socket filter"
                } else if classic_image(command) {
                    "classic seccomp filter"
                } else {
                    "eBPF program"
                }
                .into(),
                declared_instruction_count: captured_integer(
                    invocation,
                    if classic_image(command) {
                        "len"
                    } else {
                        "insn_cnt"
                    },
                ),
                fd: if command == "BPF_PROG_LOAD" {
                    invocation
                        .exit
                        .as_ref()
                        .and_then(|exit| exit.result)
                        .filter(|ret| *ret >= 0)
                } else if command == "SO_ATTACH_FILTER" {
                    recorded_args.and_then(|args| i64::try_from(args[0]).ok())
                } else {
                    captured_integer(invocation, "attach_bpf_fd")
                        .and_then(|fd| i64::try_from(fd).ok())
                },
                capture_issues: invocation
                    .entry
                    .iter()
                    .chain(invocation.exit.iter())
                    .flat_map(|event| event.issues.iter().cloned())
                    .chain(
                        invocation
                            .entry
                            .iter()
                            .chain(invocation.exit.iter())
                            .flat_map(|event| &event.fields)
                            .filter(|field| !field.complete)
                            .map(|field| {
                                format!(
                                    "{} incomplete ({}/{:?} captured octets)",
                                    field.key, field.captured_len, field.logical_len
                                )
                            }),
                    )
                    .collect(),
                ..bpf::BpfIdentity::default()
            };
            let exported = bpf::export_capture(bytes, &identity);
            let translation = if classic_image(command) {
                bpf::translate_classic_explained(
                    bytes,
                    if command == "SO_ATTACH_FILTER" {
                        bpf::ClassicContext::Socket
                    } else if matches!(
                        command,
                        "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER" | "PR_SET_SECCOMP"
                    ) {
                        bpf::ClassicContext::Seccomp
                    } else {
                        bpf::ClassicContext::Unknown
                    },
                )
            } else {
                bpf::translate_explained(bytes)
            };
            let dump = classic_image(command).then(|| bpf::dump(bytes));
            (
                Some(translation),
                dump,
                Some(exported),
                Some(bytes.to_vec()),
                identity,
            )
        } else {
            (None, None, None, None, bpf::BpfIdentity::default())
        };
        let result = invocation.exit.as_ref().and_then(|exit| exit.result);
        notes.push(BpfNote {
            heading: format!("{}  tid {}  {command}", event.syscall_name, event.tid),
            outcome: outcome(invocation),
            lifecycle: attach_of_loaded(command, invocation, &program_fds)
                .or_else(|| bpf_lifecycle(command, result)),
            translation,
            dump,
            export,
            bytes,
            identity,
        });
        if command == "BPF_PROG_LOAD" {
            if let Some(fd) = result.filter(|result| *result >= 0) {
                program_fds.push((invocation.task_cookie, fd));
            }
        }
    }
    notes
}

fn captured_integer(invocation: &InvocationSummary, member: &str) -> Option<u64> {
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| &event.fields)
        .filter(|field| field.key.rsplit('.').next() == Some(member))
        .find_map(|field| {
            let bytes = trace::covered_preview(field);
            match bytes.len() {
                2 => bytes.try_into().ok().map(u16::from_le_bytes).map(u64::from),
                4 => bytes.try_into().ok().map(u32::from_le_bytes).map(u64::from),
                8 => bytes.try_into().ok().map(u64::from_le_bytes),
                _ => None,
            }
        })
}

/// `attach requested of fd N` when a recorded argument is a program fd from
/// an earlier successful load in this slice. No fd is guessed from a pointer.
fn attach_of_loaded(
    command: &str,
    invocation: &InvocationSummary,
    program_fds: &[(u64, i64)],
) -> Option<String> {
    if command != "BPF_PROG_ATTACH" {
        return None;
    }
    let fd = i64::try_from(captured_integer(invocation, "attach_bpf_fd")?).ok()?;
    program_fds
        .contains(&(invocation.task_cookie, fd))
        .then(|| {
            format!(
                "{} of observed loaded fd {fd}",
                if succeeded(invocation) {
                    "attached"
                } else {
                    "attach attempted"
                }
            )
        })
}

fn bpf_lifecycle(command: &str, result: Option<i64>) -> Option<String> {
    let action = match command {
        "BPF_PROG_LOAD" => "load",
        "BPF_PROG_ATTACH" => "attach",
        "BPF_PROG_DETACH" => "detach",
        "SO_ATTACH_FILTER" => "socket attachment",
        "SECCOMP_SET_MODE_STRICT"
        | "SECCOMP_SET_MODE_FILTER"
        | "SECCOMP_MODE_STRICT"
        | "SECCOMP_MODE_FILTER"
        | "PR_SET_SECCOMP" => "seccomp installation",
        _ => return None,
    };
    Some(match result {
        Some(fd) if command == "BPF_PROG_LOAD" && fd >= 0 => format!("loaded program fd {fd}"),
        Some(0) => format!("{action} successful"),
        Some(ret) if ret < 0 => format!("{action} failed ({ret})"),
        Some(ret) => format!("{action} returned {ret}; interpretation depends on recorded flags"),
        None => format!("{action} attempted; exit not recorded"),
    })
}

fn classic_image(command: &str) -> bool {
    matches!(
        command,
        "SO_ATTACH_FILTER" | "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER"
    )
}

fn bpf_command(event: &EventSummary, args: [u64; 6]) -> Option<&'static str> {
    if let Some(command) = bpf::command_name(event) {
        return Some(command);
    }
    if classic_socket_filter(event, args) {
        return Some("SO_ATTACH_FILTER");
    }
    if event.syscall_name == "seccomp" || event.syscall_nr == 317 {
        return match args[0] {
            0 => Some("SECCOMP_SET_MODE_STRICT"),
            1 => Some("SECCOMP_SET_MODE_FILTER"),
            _ => None,
        };
    }
    if (event.syscall_name == "prctl" || event.syscall_nr == 157) && args[0] == 22 {
        return Some(match args[1] {
            1 => "SECCOMP_MODE_STRICT",
            2 => "SECCOMP_MODE_FILTER",
            _ => "PR_SET_SECCOMP",
        });
    }
    None
}

/// Exact captured instruction arrays. A buffer whose name merely contains
/// `prog`, `buf` or `insns` is not a program image, and a short preview is
/// not padded out to the declared length.
fn instruction_image(invocation: &InvocationSummary, command: &str) -> Option<Vec<u8>> {
    let (key, layout) = match command {
        "BPF_PROG_LOAD" => ("arg1.attr.insns", "bpf_insn[]"),
        "SO_ATTACH_FILTER" => ("arg3.optval.filter", "sock_filter[]"),
        "SECCOMP_SET_MODE_FILTER" | "SECCOMP_MODE_FILTER" => {
            ("arg2.program.filter", "sock_filter[]")
        }
        _ => return None,
    };
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key == key && layout_is(&field.layout, layout))
        .and_then(isolated_instructions)
}

fn layout_is(layout: &str, name: &str) -> bool {
    layout == name || layout.ends_with(&format!("/{name}"))
}

fn isolated_instructions(field: &antinomie_monitor_core::FieldSummary) -> Option<Vec<u8>> {
    let logical = field.logical_len?;
    if !field.complete
        || logical == 0
        || !logical.is_multiple_of(8)
        || field.captured_len != logical
    {
        return None;
    }
    if field.ranges.as_slice() != [(0, logical)] {
        return None;
    }
    let bytes = trace::covered_preview(field);
    if bytes.len() as u64 != logical {
        return None;
    }
    Some(bytes.to_vec())
}

fn bpf_view(ui: &mut egui::Ui, input: &TriageInput<'_>, indexed: Option<&[BpfNote]>) {
    let page_notes;
    let notes = if let Some(notes) = indexed {
        notes
    } else {
        page_notes = bpf_notes(input);
        page_notes.as_slice()
    };
    if notes.is_empty() {
        ui.colored_label(
            theme::muted(),
            "No bpf syscall, classic socket filter, or seccomp install was recorded.",
        );
        return;
    }
    let rows: Vec<_> = notes
        .iter()
        .map(|note| bpf_row(note, input.clock_anchor))
        .collect();
    table(
        ui,
        "triage-bpf",
        &["Time", "Observation", "Outcome", "Evidence"],
        &rows,
    );
}

fn bpf_row(note: &BpfNote, clock: Option<antinomie_monitor_core::HostClockAnchor>) -> Vec<Cell> {
    let mut row = vec![
        cell(
            crate::time_format::guest_ns(clock, note.identity.timestamp_ns),
            theme::text(),
            true,
        ),
        cell(&note.heading, theme::text(), false),
        cell(&note.outcome, theme::text(), false),
        cell(
            note.identity
                .event_id
                .map_or("Unavailable".into(), |id| format!("call {id}")),
            theme::text(),
            true,
        ),
    ];
    row[0].values = vec![
        (
            "event.id",
            note.identity
                .event_id
                .map_or(RowValue::Missing, |id| RowValue::Number(i128::from(id))),
        ),
        (
            "process.cookie",
            note.identity
                .cookie
                .map_or(RowValue::Missing, |id| RowValue::Number(i128::from(id))),
        ),
        (
            "stream.id",
            RowValue::Number(i128::from(note.identity.stream_id)),
        ),
    ];
    row
}

fn bpf_detail(ui: &mut egui::Ui, note: &BpfNote, directory: Option<&Path>, status: &mut String) {
    if !status.is_empty() {
        ui.label(status.as_str());
    }
    if let Some(line) = &note.lifecycle {
        ui.label(line);
    }
    if note.translation.is_none() && note.dump.is_none() {
        ui.weak("The instruction image was not isolated.");
    }
    for text in [&note.translation, &note.dump, &note.export]
        .into_iter()
        .flatten()
    {
        ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
    }
    if let (Some(bytes), Some(directory)) = (&note.bytes, directory) {
        if ui.button("Export binary and JSON").clicked() {
            *status = match bpf::write_export(&directory.join("bpf"), bytes, &note.identity) {
                Ok((binary, metadata)) => {
                    format!("Wrote {} and {}", binary.display(), metadata.display())
                }
                Err(error) => error,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires X11 native rendering; synthetic triage evidence fixture"]
    fn native_triage_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct Fixture {
            view: TriageView,
            deadline: Instant,
            details_width: f32,
        }
        impl eframe::App for Fixture {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                egui::SidePanel::right("shared-details-fixture")
                    .exact_width(self.details_width)
                    .show(ctx, |ui| {
                        ui.heading("Details");
                        self.view.details(ui);
                    });
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("Run triage — synthetic fixture");
                    let _ = self.view.show(
                        ui,
                        TriageInput {
                            vm_id: Some("vm"),
                            boot_id: Some("boot"),
                            run_id: Some("run"),
                            ..TriageInput::empty()
                        },
                    );
                });
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let temp = PacketSpool::new().unwrap();
        let mut raw = Vec::new();
        write_rwx_calls(&mut raw, 0..3);
        std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
        let scene = std::env::var("ANTINOMIE_TRIAGE_QA_SCENE").unwrap_or_else(|_| "changed".into());
        let pcap = temp.directory.join("fixture.pcap");
        std::fs::write(
            &pcap,
            if scene == "http" {
                http_pcap()
            } else {
                dns_pcap()
            },
        )
        .unwrap();
        let mut scan =
            scan_archive(&temp.directory, Some(&pcap), false, &AtomicBool::new(false)).unwrap();
        let clock = Some(antinomie_monitor_core::HostClockAnchor {
            guest_ns: 0,
            host_us: 1_700_000_000_000_000,
        });
        scan.clock_anchor = clock;
        let mut calls = [
            path_call(1, 2, "open", 3, "/tmp/analysis-note.txt"),
            call(1, 0, "read", 5),
            call(1, 0, "read", 0),
            call(1, 18, "pwrite64", 2),
        ];
        calls[0].entry.as_mut().unwrap().args = Some([0, 2, 0, 0, 0, 0]);
        calls[1].entry.as_mut().unwrap().args = Some([3, 0, 5, 0, 0, 0]);
        calls[1]
            .exit
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.data", "", b"hello"));
        calls[2].entry.as_mut().unwrap().args = Some([3, 0, 5, 0, 0, 0]);
        calls[3].entry.as_mut().unwrap().args = Some([3, 0, 2, 1, 0, 0]);
        calls[3]
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.data", "", b"XY"));
        let mut state = FdState::default();
        let mut index = files::FileIndex::default();
        for (at, call) in calls.iter_mut().enumerate() {
            call.call_id = at as u64 + 1;
            for event in call.entry.iter_mut().chain(call.exit.iter_mut()) {
                event.call_id = call.call_id;
                event.timestamp_ns = at as u64 * 1_000_000_000;
            }
            let event = trace::representative(call).unwrap();
            remember_open(&mut state, call, event);
            if let Some(row) = file_event_row(&state, call, event, OPEN_NAMES) {
                scan.opened.push(row);
            }
            if let Some(row) = index.observe(&state, call, event, None) {
                scan.read.push(row);
            }
        }
        scan.file_changes = index.finish();
        scan.changed = scan
            .file_changes
            .iter()
            .map(|change| change.row(clock))
            .collect();
        let mut view = TriageView::default();
        view.scan = Some(scan);
        view.last_refresh = Some(Instant::now());
        view.context_key = Some("vm\nboot\nrun\n".into());
        match scene.as_str() {
            "findings" => {
                view.section = Section::Process;
                view.process = ProcessTab::Suspicious;
            }
            "read" => {
                view.section = Section::Files;
                view.files = FileTab::Read;
            }
            "changed" => {
                view.section = Section::Files;
                view.files = FileTab::Changed;
            }
            "http" => {
                view.section = Section::Network;
                view.network = NetTab::Http;
            }
            "dns" => {
                view.section = Section::Network;
                view.network = NetTab::Dns;
            }
            "hosts" => {
                view.section = Section::Network;
                view.network = NetTab::Hosts;
            }
            _ => {
                view.section = Section::Process;
            }
        }
        let width = std::env::var("ANTINOMIE_TRIAGE_QA_WIDTH")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(1280)
            .clamp(420, 1920);
        let font = if width < 700 { 24.0 } else { 16.0 };
        eframe::run_native(
            "Antinomie Triage QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size([width as f32, 880.0])
                    .with_position([16.0, 16.0]),
                persist_window: false,
                persistence_path: Some(temp.directory.join("native-ui.ron")),
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11();
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                theme::text_size(&cc.egui_ctx, font);
                let initial = view.scan.as_ref().and_then(|scan| match scene.as_str() {
                    "changed" => scan.changed.first().cloned().map(|row| {
                        (
                            "triage-changed",
                            vec!["Time", "Path", "PID / TID", "Diff count", "Evidence"],
                            row,
                        )
                    }),
                    "read" => scan.read.first().cloned().map(|row| {
                        (
                            "triage-read",
                            vec![
                                "Time",
                                "Path",
                                "PID / TID",
                                "Transferred / content",
                                "Result",
                                "Evidence",
                            ],
                            row,
                        )
                    }),
                    "http" => scan
                        .http
                        .first()
                        .cloned()
                        .map(|row| ("triage-http", HTTP_HEADERS.to_vec(), row)),
                    "dns" => scan
                        .dns
                        .first()
                        .cloned()
                        .map(|row| ("triage-dns", DNS_HEADERS.to_vec(), row)),
                    "hosts" => scan.hosts.first().cloned().map(|row| {
                        (
                            "triage-hosts",
                            vec![
                                "Hostname",
                                "Resolved / connected IPs",
                                "First seen",
                                "Last seen",
                                "Requests",
                                "Source",
                            ],
                            row,
                        )
                    }),
                    "findings" => scan.findings.first().map(|finding| {
                        let mut row = finding.cells.clone();
                        row[0].values.clone_from(&finding.values);
                        (
                            "triage-findings",
                            vec![
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
                            row,
                        )
                    }),
                    _ => None,
                });
                if let Some((table_id, headers, row)) = initial {
                    details::select(&cc.egui_ctx, table_id, &headers, &row);
                    let selected = evidence_key(&row);
                    cc.egui_ctx.data_mut(|data| {
                        data.insert_temp(egui::Id::new(("triage-selected-row", table_id)), selected)
                    });
                }
                Ok(Box::new(Fixture {
                    view,
                    deadline: Instant::now() + Duration::from_secs(10),
                    details_width: (width as f32 * 0.38).min(420.0),
                }))
            }),
        )
        .unwrap();
    }

    #[test]
    fn evidence_navigation_uses_stream_task_and_call_identity() {
        let context = egui::Context::default();
        let values = [
            ("stream.id", RowValue::Number(7)),
            ("process.cookie", RowValue::Number(9)),
            ("event.id", RowValue::Number(1)),
        ];
        request_evidence_jump(&context, &values);
        assert_eq!(
            context
                .data_mut(|data| data
                    .remove_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))),
            Some((7, 9, 1))
        );
        let first = call(9, 0, "read", 1);
        let other = call(10, 0, "read", 1);
        let query = query::compile_note("stream.id == 1 && process.cookie == 9 && call.id == 1");
        assert!(query.error.is_none());
        assert!(query.keep(&first));
        assert!(!query.keep(&other));
        request_evidence_jump(&context, &[("frame.number", RowValue::Number(520))]);
        assert_eq!(
            context.data_mut(|data| data.remove_temp::<u64>(egui::Id::new("triage-packet-jump"))),
            Some(520)
        );
    }

    #[test]
    fn double_click_table_text_requests_its_exact_evidence() {
        for packet in [false, true] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut c = cell("click this evidence", theme::text(), false);
            c.values = if packet {
                vec![("frame.number", RowValue::Number(520))]
            } else {
                vec![
                    ("stream.id", RowValue::Number(7)),
                    ("process.cookie", RowValue::Number(9)),
                    ("event.id", RowValue::Number(1)),
                ]
            };
            let rows = vec![vec![c]];
            let draw = |events, time| {
                ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(900.0, 600.0),
                        )),
                        events,
                        time: Some(time),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            table(ui, "pointer-evidence", &["Evidence"], &rows)
                        });
                    },
                )
            };
            for n in 0..3 {
                draw(vec![], f64::from(n) * 0.01);
            }
            let out = draw(vec![], 0.04);
            let pos = crate::app::tests::texts(&out)
                .into_iter()
                .find(|(text, _)| text == "click this evidence")
                .unwrap()
                .1
                .center();
            for (index, pressed) in [true, false, true, false].into_iter().enumerate() {
                draw(
                    vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    0.1 + index as f64 * 0.05,
                );
            }
            if packet {
                assert_eq!(
                    ctx.data(|data| data.get_temp::<u64>(egui::Id::new("triage-packet-jump"))),
                    Some(520)
                );
            } else {
                assert_eq!(
                    ctx.data(|data| data
                        .get_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))),
                    Some((7, 9, 1))
                );
            }
        }
    }

    #[test]
    fn saved_run_scope_excludes_another_root_in_the_same_raw_archive() {
        let temp = PacketSpool::new().unwrap();
        let mut raw = Vec::new();
        write_rwx_calls(&mut raw, 0..2);
        // Rewrite only the second invocation's inherited root cookie.
        let mut at = 0;
        while at < raw.len() {
            let size = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
            if u64::from_le_bytes(raw[at + 4 + 40..at + 4 + 48].try_into().unwrap()) == 1 {
                raw[at + 4 + 128..at + 4 + 136].copy_from_slice(&99u64.to_le_bytes());
            }
            at += 4 + size;
        }
        std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
        let request = ScanRequest {
            root_cookie: 55,
            ..Default::default()
        };
        let scan = scan_archive_query(
            &temp.directory,
            None,
            false,
            &Arc::new(AtomicBool::new(false)),
            &request,
        )
        .unwrap();
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.findings[0].key, (1, 55, 0));
        assert_eq!(scan.process.len(), 1);
    }

    #[test]
    fn network_rows_are_bounded_to_the_run_host_time_window() {
        let temp = PacketSpool::new().unwrap();
        let path = temp.directory.join("dns.pcap");
        std::fs::write(&path, dns_pcap()).unwrap();
        let request = ScanRequest {
            started_ms: Some(u64::MAX / 1000),
            ..Default::default()
        };
        let scan =
            scan_pcap_query(&path, false, &Arc::new(AtomicBool::new(false)), &request).unwrap();
        assert!(
            scan.http.is_empty()
                && scan.dns.is_empty()
                && scan.ips.is_empty()
                && scan.hosts.is_empty()
        );
    }

    #[test]
    fn network_field_stream_without_geoip_preserves_dns_and_original_frames() {
        use std::io::{BufRead, BufReader};
        let temp = PacketSpool::new().unwrap();
        let path = temp.directory.join("dns.pcap");
        std::fs::write(&path, dns_pcap()).unwrap();
        let identity = antinomie_monitor_core::packet_filter::CaptureIdentity::read(&path).unwrap();
        let (spool, _) =
            spool_packet_fields(&identity, false, &Arc::new(AtomicBool::new(false)), false)
                .unwrap();
        let state = spool.lock().unwrap();
        let file = std::fs::File::open(state.directory.join("rows.tsv")).unwrap();
        let rows: Vec<_> = BufReader::new(file)
            .lines()
            .map(|line| tsv_fields(&line.unwrap()).unwrap())
            .collect();
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|row| row.len() == TSHARK_FIELDS.len()));
        assert_eq!(rows[0][0], "1");
        assert_eq!(rows[0][19], "example.com");
        assert!(rows[0][31..35].iter().all(String::is_empty));
    }

    #[test]
    fn tshark_boolean_formats_preserve_missing_and_reject_malformed_or_mixed_values() {
        for text in ["False", "false", "FALSE", "0", "False\u{1f}0"] {
            assert_eq!(tshark_boolean(text), Some(false));
        }
        for text in ["True", "true", "TRUE", "1", "True\u{1f}1"] {
            assert_eq!(tshark_boolean(text), Some(true));
        }
        for text in ["", "2", "Falsehood", " True ", "False\u{1f}True", "0\u{1f}"] {
            assert_eq!(tshark_boolean(text), None, "{text:?}");
        }
    }

    #[test]
    fn real_tshark_dns_ipv4_ipv6_and_retry_rows_preserve_original_frames_and_responses() {
        if !std::process::Command::new("tshark")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }
        let temp = PacketSpool::new().unwrap();
        let path = temp.directory.join("dns.pcap");
        std::fs::write(&path, dns_pcap()).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        for live in [false, true] {
            let index = scan_pcap_query(&path, live, &cancel, &ScanRequest::default()).unwrap();
            assert_eq!(index.dns.len(), 3, "{}", index.coverage);
            assert_eq!(
                index
                    .dns
                    .iter()
                    .map(|row| row[0].text.as_str())
                    .collect::<Vec<_>>(),
                ["#1", "#2", "#4"]
            );
            assert!(index.dns.iter().all(|row| row[2].text == "example.com"));
            assert_eq!(index.dns[0][6].text, "3");
            assert_eq!(index.dns[2][6].text, "5");
            assert!(index.dns[0][5].text.contains("93.184.216.34"));
            assert!(index.dns[2][1].text.contains("::1"));
            assert_eq!(index.dns[0][3].text, "A");
            assert!(!index.ips.is_empty());
            assert_eq!(index.hosts.len(), 1);
            assert!(
                index.dns[1][0]
                    .values
                    .iter()
                    .any(|(name, value)| *name == "dns.retry"
                        && matches!(value, RowValue::Bool(true)))
            );
        }
        let mut request = ScanRequest::default();
        request.filters[4] = "dns.retry == true".into();
        let index = scan_pcap_query(&path, false, &cancel, &request).unwrap();
        assert_eq!(index.dns.len(), 1);
        assert_eq!(index.dns[0][0].text, "#2");
    }

    fn dns_pcap() -> Vec<u8> {
        fn message(response: bool) -> Vec<u8> {
            let mut bytes = Vec::new();
            for word in [
                0x1234u16,
                if response { 0x8180 } else { 0x0100 },
                1,
                u16::from(response),
                0,
                0,
            ] {
                bytes.extend(word.to_be_bytes());
            }
            bytes.extend(b"\x07example\x03com\0");
            bytes.extend(1u16.to_be_bytes());
            bytes.extend(1u16.to_be_bytes());
            if response {
                bytes.extend([0xc0, 0x0c]);
                bytes.extend(1u16.to_be_bytes());
                bytes.extend(1u16.to_be_bytes());
                bytes.extend(60u32.to_be_bytes());
                bytes.extend(4u16.to_be_bytes());
                bytes.extend([93, 184, 216, 34]);
            }
            bytes
        }
        fn frame(response: bool, ipv6: bool) -> Vec<u8> {
            let payload = message(response);
            let mut udp = Vec::new();
            udp.extend(if response { 53u16 } else { 5353u16 }.to_be_bytes());
            udp.extend(if response { 5353u16 } else { 53u16 }.to_be_bytes());
            udp.extend(((payload.len() + 8) as u16).to_be_bytes());
            udp.extend([0; 2]);
            udp.extend(payload);
            let mut bytes = vec![0; 12];
            if ipv6 {
                bytes.extend(0x86ddu16.to_be_bytes());
                let local = "::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
                let remote = "2001:db8::53"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets();
                bytes.extend(0x60000000u32.to_be_bytes());
                bytes.extend((udp.len() as u16).to_be_bytes());
                bytes.extend([17, 64]);
                bytes.extend(if response { remote } else { local });
                bytes.extend(if response { local } else { remote });
            } else {
                bytes.extend(0x0800u16.to_be_bytes());
                bytes.extend([0x45, 0]);
                bytes.extend(((udp.len() + 20) as u16).to_be_bytes());
                bytes.extend([0; 4]);
                bytes.extend([64, 17]);
                bytes.extend([0; 2]);
                bytes.extend(if response {
                    [8, 8, 8, 8]
                } else {
                    [10, 0, 2, 15]
                });
                bytes.extend(if response {
                    [10, 0, 2, 15]
                } else {
                    [8, 8, 8, 8]
                });
            }
            bytes.extend(udp);
            bytes
        }
        let frames = [
            frame(false, false),
            frame(false, false),
            frame(true, false),
            frame(false, true),
            frame(true, true),
        ];
        let mut bytes = http_pcap()[..24].to_vec();
        for (index, frame) in frames.iter().enumerate() {
            bytes.extend((1_700_000_000u32 + index as u32).to_le_bytes());
            bytes.extend(0u32.to_le_bytes());
            bytes.extend((frame.len() as u32).to_le_bytes());
            bytes.extend((frame.len() as u32).to_le_bytes());
            bytes.extend(frame);
        }
        bytes
    }

    #[test]
    fn quoted_packet_fields_and_epoch_times_preserve_exact_values() {
        assert_eq!(
            tsv_fields("\"GET\"\t\"/a\tb\"\"c\"\t\"\"").unwrap(),
            ["GET", "/a\tb\"c", ""]
        );
        assert!(tsv_fields("\"truncated").is_err());
        assert_eq!(epoch_us("123.123456789"), Some(123_123456));
        assert_eq!(epoch_us("0.000001"), Some(1));
        assert_eq!(epoch_us("18446744073709551615.999999"), None);
        assert_eq!(epoch_us("1.bad"), None);
    }

    fn write_rwx_calls(raw: &mut dyn std::io::Write, calls: std::ops::Range<u64>) {
        for call in calls {
            for phase in [1u8, 2] {
                for fragment in [1u8, 5] {
                    let mut body = vec![0u8; if fragment == 1 { 120 } else { 32 }];
                    if fragment == 1 {
                        body[16..24].copy_from_slice(&7u64.to_le_bytes());
                        body[24..32].copy_from_slice(&(MAP_PRIVATE | MAP_ANONYMOUS).to_le_bytes());
                        if phase == 2 {
                            body[49] = 1;
                            body[56..64].copy_from_slice(&4096u64.to_le_bytes());
                        }
                    }
                    let mut packet = vec![0u8; 136];
                    packet[..4].copy_from_slice(b"ANTT");
                    packet[4..6].copy_from_slice(&1u16.to_le_bytes());
                    packet[6..8].copy_from_slice(&1u16.to_le_bytes());
                    packet[8..10].copy_from_slice(&136u16.to_le_bytes());
                    packet[10..12].copy_from_slice(&1u16.to_le_bytes());
                    packet[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
                    packet[20..24].copy_from_slice(&1u32.to_le_bytes());
                    packet[24..32].copy_from_slice(&1u64.to_le_bytes());
                    packet[32..40].copy_from_slice(&55u64.to_le_bytes());
                    packet[40..48].copy_from_slice(&call.to_le_bytes());
                    packet[48..56].copy_from_slice(&(call * 2 + u64::from(phase)).to_le_bytes());
                    packet[56..64].copy_from_slice(
                        &(call * 4 + u64::from(phase) + u64::from(fragment)).to_le_bytes(),
                    );
                    packet[64..72].copy_from_slice(&(call * 10 + u64::from(phase)).to_le_bytes());
                    packet[72..76].copy_from_slice(&55u32.to_le_bytes());
                    packet[76..80].copy_from_slice(&55u32.to_le_bytes());
                    packet[88..96].copy_from_slice(&9u64.to_le_bytes());
                    packet[96..98].copy_from_slice(&1u16.to_le_bytes());
                    packet[98] = phase;
                    packet[99] = fragment;
                    packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
                    packet[128..136].copy_from_slice(&55u64.to_le_bytes());
                    packet.extend(body);
                    raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
                    raw.write_all(&packet).unwrap();
                }
            }
        }
    }

    #[test]
    fn hidden_tick_refreshes_growing_archive_preserves_selection_and_rejects_prior_run() {
        fn input<'a>(archive: &'a Path, run: &'a str) -> TriageInput<'a> {
            TriageInput {
                analysis: None,
                invocations: &[],
                packets: &[],
                frames: None,
                vm_id: Some("vm"),
                boot_id: Some("boot"),
                run_id: Some(run),
                archive: Some(archive),
                pcap: None,
                pcap_open: false,
                clock_anchor: None,
                started_ms: None,
                root_cookie: 0,
                run_finished: false,
            }
        }
        fn wait(
            view: &mut TriageView,
            ctx: &egui::Context,
            archive: &Path,
            run: &str,
            count: usize,
        ) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                // Intentionally never call show: another panel owns the workspace.
                view.tick(ctx, input(archive, run));
                if view
                    .scan
                    .as_ref()
                    .is_some_and(|scan| scan.findings.len() == count)
                    && view.scan_rx.is_none()
                {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "hidden index stalled: {:?}",
                    view.scan_error
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let first = PacketSpool::new().unwrap();
        let second = PacketSpool::new().unwrap();
        let mut raw = std::fs::File::create(first.directory.join("telemetry.raw")).unwrap();
        write_rwx_calls(&mut raw, 0..1);
        raw.sync_all().unwrap();
        let ctx = egui::Context::default();
        let mut view = TriageView::default();
        view.refresh_seconds = 1;
        view.scan_request.filters[0] = "finding.rule == \"memory.rwx\"".into();
        wait(&mut view, &ctx, &first.directory, "first", 1);
        view.selected_call_id = Some((1, 55, 0));
        let first_refresh = view.last_refresh.unwrap();
        write_rwx_calls(&mut raw, 1..2);
        raw.sync_all().unwrap();
        wait(&mut view, &ctx, &first.directory, "first", 2);
        assert!(view.last_refresh.unwrap() > first_refresh);
        assert_eq!(view.selected_call_id, Some((1, 55, 0)));
        assert_eq!(
            view.scan_request.filters[0],
            "finding.rule == \"memory.rwx\""
        );
        // Hold a completed worker reply to exercise refresh pressure deterministically.
        view.refresh_requested = true;
        view.ensure_scan(
            Some(&first.directory),
            None,
            false,
            Some("vm"),
            Some("boot"),
            Some("first"),
        );
        let actual = view.scan_rx.take().unwrap();
        let (held_tx, held_rx) = mpsc::channel();
        view.scan_rx = Some(held_rx);
        let generation = view.scan_generation;
        for _ in 0..100 {
            view.refresh_requested = true;
            view.tick(&ctx, input(&first.directory, "first"));
            assert_eq!(view.scan_generation, generation);
        }
        assert!(view.refresh_queued);
        held_tx
            .send(actual.recv_timeout(Duration::from_secs(5)).unwrap())
            .unwrap();
        view.tick(&ctx, input(&first.directory, "first"));
        assert_eq!(view.scan_generation, generation + 1);
        let stale_cancel = Arc::clone(view.scan_cancel.as_ref().unwrap());
        let mut other = std::fs::File::create(second.directory.join("telemetry.raw")).unwrap();
        write_rwx_calls(&mut other, 7..8);
        other.sync_all().unwrap();
        view.tick(&ctx, input(&second.directory, "second"));
        assert!(stale_cancel.load(Ordering::Relaxed));
        assert!(view.scan.is_none());
        assert!(view.selected_call_id.is_none());
        wait(&mut view, &ctx, &second.directory, "second", 1);
        assert_eq!(view.scan.as_ref().unwrap().findings[0].call_id, 7);
    }

    #[test]
    fn complete_retained_archive_query_pages_every_rwx_finding_and_persists_facts() {
        let temp = PacketSpool::new().unwrap();
        let mut raw = std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap();
        write_rwx_calls(&mut raw, 0..2051);
        raw.sync_all().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let first = scan_archive_query(
            &temp.directory,
            None,
            false,
            &cancel,
            &ScanRequest::default(),
        )
        .unwrap();
        assert_eq!(first.findings.len(), STORED_ROWS);
        assert_eq!(first.findings_omitted, 51);
        let mut request = ScanRequest::default();
        request.offsets[0] = STORED_ROWS;
        request.filters[0] = "finding.rule == \"memory.rwx\" && finding.success == true".into();
        let second = scan_archive_query(&temp.directory, None, false, &cancel, &request).unwrap();
        assert_eq!(second.findings.len(), 51);
        assert_eq!(second.findings_omitted, STORED_ROWS as u64);
        assert!(second
            .findings
            .iter()
            .all(|finding| finding.call_id >= STORED_ROWS as u64));
        let journal =
            std::fs::read_to_string(temp.directory.join("triage-findings-v1.jsonl")).unwrap();
        assert_eq!(journal.lines().count(), 2051);
        let fact: serde_json::Value =
            serde_json::from_str(journal.lines().next().unwrap()).unwrap();
        assert_eq!(fact["facts"]["finding.rule"], "memory.rwx");
        assert_eq!(fact["facts"]["finding.version"], 1);
        assert_eq!(fact["facts"]["finding.success"], true);
    }

    #[test]
    fn relative_chdir_retains_symlink_components_and_unknown_fchdir_invalidates_cwd() {
        let start = path_call(1, 80, "chdir", 0, "/tmp/link");
        let relative = path_call(1, 80, "chdir", 0, "../child");
        let mut opened = path_call(1, 257, "openat", 4, "note");
        opened.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
        let rows = file_rows(&[start.clone(), relative, opened.clone()], OPEN_NAMES);
        assert_eq!(
            rows.rows[0][0].text,
            "/tmp/link/../child/note (lexical cwd path; symlinks unknown)"
        );
        let mut moved = call(1, 81, "fchdir", 0);
        moved.entry.as_mut().unwrap().args = Some([99, 0, 0, 0, 0, 0]);
        let rows = file_rows(&[start, moved, opened], OPEN_NAMES);
        assert_eq!(rows.rows[0][0].text, "note (relative, cwd not recorded)");
    }

    #[test]
    fn exec_cloexec_and_shared_tables_keep_parent_descriptor_provenance_separate() {
        let mut opened = path_call(1, 257, "openat", 7, "/etc/test");
        opened.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0x80000, 0, 0, 0]);
        let mut clone = call(1, CLONE, "clone", 42);
        clone.entry.as_mut().unwrap().args = Some([CLONE_FILES, 0, 0, 0, 0, 0]);
        let exec = path_call(42, 59, "execve", 0, "/bin/true");
        let mut child = call(42, 1, "write", 3);
        child.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let mut parent = call(1, 1, "write", 3);
        parent.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(&[opened, clone, exec, child, parent], &["write"]);
        assert_eq!(rows.rows[0][0].text, "—");
        assert_eq!(rows.rows[1][0].text, "/etc/test");
        assert_eq!(rows.rows[1][8].text, "3");
    }

    #[test]
    fn tshark_saved_and_live_prefix_index_use_all_capture_frames() {
        if std::process::Command::new("tshark")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let temp = PacketSpool::new().unwrap();
        let path = temp.directory.join("capture.pcap");
        std::fs::write(&path, http_pcap()).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        for live in [false, true] {
            let index = scan_pcap_query(&path, live, &cancel, &ScanRequest::default()).unwrap();
            assert_eq!(index.http.len(), 1);
            assert_eq!(index.http[0][3].text, "GET");
            assert_eq!(index.http[0][4].text, "example.com");
            assert_eq!(index.http[0][5].text, "/");
            assert!(index
                .coverage
                .contains("HTTPS, HTTP/2, HTTP/3 and encrypted DNS unavailable"));
        }
    }
    use antinomie_monitor_core::{
        network::NetworkPacket, EventSummary, FieldSummary, InvocationSummary,
    };

    fn page_notes(invocations: &[InvocationSummary]) -> Vec<BpfNote> {
        bpf_notes(&TriageInput::page(invocations, &[]))
    }

    #[test]
    fn saved_recording_from_env_is_indexed_when_present() {
        let Ok(dir) = std::env::var("ANTINOMIE_RECORDING") else {
            return;
        };
        let scan = scan_archive(Path::new(&dir), None, false, &AtomicBool::new(false))
            .unwrap_or_else(|error| panic!("index failed: {error}"));
        assert!(scan.coverage.contains("indexed "), "{}", scan.coverage);
        assert!(
            scan.coverage.contains(" of ") || scan.coverage.contains("saved total unavailable"),
            "{}",
            scan.coverage
        );
        let _ = std::fs::write("/tmp/antinomie-index-coverage.txt", &scan.coverage);
        let files = scan
            .opened
            .iter()
            .chain(scan.changed.iter())
            .map(|row| {
                row.iter()
                    .map(|cell| cell.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write("/tmp/antinomie-fd-rows.txt", files);
        let findings = scan
            .findings
            .iter()
            .map(|finding| {
                finding
                    .cells
                    .iter()
                    .map(|cell| cell.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write("/tmp/antinomie-findings.txt", findings);
        let recording = antinomie_monitor_core::recording::Recording {
            directory: std::fs::canonicalize(&dir).unwrap(),
            manifest: serde_json::Value::Null,
            events: Vec::new(),
        };
        let mut offset = 0u64;
        let mut bpf = String::new();
        loop {
            let page = recording.invocation_page(offset, 256).unwrap();
            for invocation in &page.invocations {
                let Some(event) = invocation.entry.as_ref().or(invocation.exit.as_ref()) else {
                    continue;
                };
                if event.syscall_name.contains("bpf")
                    || event.syscall_name.contains("seccomp")
                    || event.syscall_name == "setsockopt"
                {
                    bpf.push_str(&format!(
                        "{} result {:?} args {:?}\n",
                        event.syscall_name,
                        invocation.exit.as_ref().and_then(|exit| exit.result),
                        event.args
                    ));
                }
            }
            match page.next_offset {
                Some(next) if next > offset => offset = next,
                _ => break,
            }
        }
        if bpf.is_empty() {
            bpf.push_str("no bpf, seccomp, or setsockopt call in this recording\n");
        }
        let _ = std::fs::write("/tmp/antinomie-bpf-scan.txt", bpf);
    }

    #[test]
    fn pcap_index_reconstructs_http_and_states_coverage() {
        let dir = std::env::temp_dir().join(format!("antinomie-pcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.pcap");
        std::fs::write(&path, http_pcap()).unwrap();
        let index = scan_pcap(&path, false, &AtomicBool::new(false))
            .unwrap_or_else(|error| panic!("pcap index failed: {error}"));
        assert!(
            index.coverage.contains("pcap frames read 1"),
            "{}",
            index.coverage
        );
        assert!(
            index.coverage.contains("HTTPS segments 0")
                && index.coverage.contains("HTTP/2 prefaces 0"),
            "{}",
            index.coverage
        );
        assert_eq!(index.http.len(), 1);
        assert!(index.http[0].iter().any(|cell| cell.text.contains("GET /")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saved_pcap_from_env_is_indexed_when_present() {
        let Ok(path) = std::env::var("ANTINOMIE_PCAP") else {
            return;
        };
        let index = scan_pcap(Path::new(&path), false, &AtomicBool::new(false))
            .unwrap_or_else(|error| panic!("pcap index failed: {error}"));
        assert!(
            index.coverage.contains("pcap frames read"),
            "{}",
            index.coverage
        );
        assert!(
            index.coverage.contains("Unavailable: HTTPS"),
            "{}",
            index.coverage
        );
        let _ = std::fs::write("/tmp/antinomie-pcap-coverage.txt", &index.coverage);
    }

    fn http_pcap() -> Vec<u8> {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut tcp = Vec::new();
        tcp.extend(40000u16.to_be_bytes());
        tcp.extend(80u16.to_be_bytes());
        tcp.extend(1u32.to_be_bytes());
        tcp.extend(0u32.to_be_bytes());
        tcp.push(0x50);
        tcp.push(0x18);
        tcp.extend(0u16.to_be_bytes());
        tcp.extend(0u16.to_be_bytes());
        tcp.extend(0u16.to_be_bytes());
        tcp.extend(payload);
        let total = (20 + tcp.len()) as u16;
        let mut ip = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 2, 15, 93, 184, 216, 34,
        ];
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend(tcp);
        let mut frame = vec![0; 12];
        frame.extend(0x0800u16.to_be_bytes());
        frame.extend(ip);
        let mut pcap = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0,
            0,
        ];
        let len = frame.len() as u32;
        pcap.extend(0u32.to_le_bytes());
        pcap.extend(0u32.to_le_bytes());
        pcap.extend(len.to_le_bytes());
        pcap.extend(len.to_le_bytes());
        pcap.extend(frame);
        pcap
    }

    #[test]
    fn missing_raw_archive_is_not_treated_as_a_whole_run() {
        let dir = std::env::temp_dir().join(format!("antinomie-triage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let Err(error) = scan_archive(&dir, None, false, &AtomicBool::new(false)) else {
            panic!("a directory without telemetry.raw must not count as a whole-run index");
        };
        assert!(error.contains("telemetry.raw"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    pub(super) fn call(pid: u32, nr: u64, name: &str, result: i64) -> InvocationSummary {
        InvocationSummary {
            stream_id: 1,
            task_cookie: u64::from(pid),
            call_id: 1,
            entry: Some(EventSummary {
                root_task_cookie: 1,
                stream_id: 1,
                task_cookie: u64::from(pid),
                call_id: 1,
                event_seq: 1,
                phase: 1,
                syscall_nr: nr,
                syscall_name: name.into(),
                pid,
                tid: pid,
                cpu: 0,
                timestamp_ns: 0,
                args: Some([0; 6]),
                result: None,
                complete: true,
                issues: Vec::new(),
                fields: Vec::new(),
            }),
            exit: Some(EventSummary {
                root_task_cookie: 1,
                stream_id: 1,
                task_cookie: u64::from(pid),
                call_id: 1,
                event_seq: 2,
                phase: 2,
                syscall_nr: nr,
                syscall_name: name.into(),
                pid,
                tid: pid,
                cpu: 0,
                timestamp_ns: 1,
                args: None,
                result: Some(result),
                complete: true,
                issues: Vec::new(),
                fields: Vec::new(),
            }),
            async_events: Vec::new(),
            task_exit: None,
        }
    }

    pub(super) fn captured(key: &str, layout: &str, data: &[u8]) -> FieldSummary {
        let len = data.len() as u64;
        FieldSummary {
            object_id: 1,
            key: key.into(),
            layout: layout.into(),
            logical_len: Some(len),
            captured_len: len,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: data.to_vec(),
            raw_path: None,
            ranges: vec![(0, len)],
        }
    }

    fn packet(number: u64, protocol: &str, info: &str, port: Option<u16>) -> NetworkPacket {
        NetworkPacket {
            number,
            protocol: protocol.into(),
            info: info.into(),
            source: "10.0.0.1".into(),
            destination: "10.0.0.2".into(),
            dst_port: port,
            ..NetworkPacket::default()
        }
    }

    #[test]
    fn fork_indents_the_child_under_its_parent() {
        let lines = process_tree_lines(&[call(1, FORK, "fork", 42), call(42, 59, "execve", 0)]);
        assert_eq!(
            lines,
            vec![
                "pid 1 cookie 1  ?".to_string(),
                "  pid 42 cookie 42  ?".to_string()
            ]
        );
    }

    fn with_cookie(pid: u32, cookie: u64) -> InvocationSummary {
        let mut row = call(pid, 1, "write", 0);
        row.task_cookie = cookie;
        for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
            event.task_cookie = cookie;
        }
        row
    }

    #[test]
    fn same_pid_two_cookies_are_two_process_nodes() {
        let lines = process_tree_lines(&[with_cookie(7, 100), with_cookie(7, 200)]);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines.iter().any(|line| line.contains("pid 7 cookie 100")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("pid 7 cookie 200")),
            "{lines:?}"
        );
    }

    #[test]
    fn failed_exec_does_not_replace_the_program() {
        let mut started = call(3, 59, "execve", 0);
        started
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/old\0"));
        let mut failed = call(3, 59, "execve", -2);
        failed
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/new\0"));
        let lines = process_tree_lines(&[started, failed]);
        assert!(
            lines.iter().any(|line| line.contains("/bin/old")),
            "{lines:?}"
        );
        assert!(
            lines.iter().all(|line| !line.contains("/bin/new")),
            "{lines:?}"
        );

        let mut again = call(3, 59, "execve", 0);
        again
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/old\0"));
        let mut pending = call(3, 322, "execveat", 0);
        pending.exit = None;
        pending.entry.as_mut().unwrap().fields.push(captured(
            "arg1.pathname",
            "",
            b"/bin/pending\0",
        ));
        let lines = process_tree_lines(&[again, pending]);
        assert!(
            lines.iter().any(|line| line.contains("/bin/old")),
            "{lines:?}"
        );
        assert!(
            lines.iter().all(|line| !line.contains("/bin/pending")),
            "{lines:?}"
        );

        let mut rejected = call(4, 59, "execve", -13);
        rejected.entry.as_mut().unwrap().fields.push(captured(
            "arg0.pathname",
            "",
            b"/bin/rejected\0",
        ));
        let lines = process_tree_lines(&[rejected]);
        assert!(
            lines.iter().all(|line| !line.contains("/bin/rejected")),
            "{lines:?}"
        );
    }

    #[test]
    fn exec_commit_without_syscall_exit_names_image_and_fork_inherits_it() {
        let mut exec = call(3, 59, "execve", 0);
        exec.entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/old\0"));
        let mut commit = exec.exit.take().unwrap();
        commit.phase = 3;
        commit
            .fields
            .push(captured("lifecycle.exec_commit", "", &[0; 8]));
        exec.async_events.push(commit);
        let fork = call(3, FORK, "fork", 42);
        let child = call(42, 0, "read", 0);
        let nodes = process_nodes(&[exec.clone(), fork, child]);
        assert_eq!(
            nodes.iter().find(|node| node.pid == 3).unwrap().comm,
            "/bin/old"
        );
        assert_eq!(
            nodes.iter().find(|node| node.pid == 42).unwrap().comm,
            "/bin/old"
        );
        exec.async_events[0].fields[0].complete = false;
        assert_eq!(process_nodes(&[exec])[0].comm, "?");
    }

    #[test]
    fn file_process_labels_follow_exec_time_without_guessing_unknown_or_reused_pid() {
        let mut files = FdState::default();
        let mut first = call(3, 59, "execve", 0);
        first
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/old\0"));
        observe_processes(&mut files.process_images, &[first]);
        let read = call(3, 0, "read", 0);
        let event = trace::representative(&read).unwrap();
        assert_eq!(
            process_identity(event.pid, event.tid, process_image(&files, event)),
            "old (3 / 3)"
        );
        let mut next = call(3, 59, "execve", 0);
        next.entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", b"/bin/new\0"));
        observe_processes(&mut files.process_images, &[next]);
        assert_eq!(
            process_identity(event.pid, event.tid, process_image(&files, event)),
            "new (3 / 3)"
        );
        let mut reused = event.clone();
        reused.task_cookie += 100;
        assert!(process_image(&files, &reused).is_none());
    }

    #[test]
    fn clone3_thread_flags_create_no_child() {
        let mut threaded = call(1, CLONE3, "clone3", 99);
        threaded.entry.as_mut().unwrap().args = Some([0x1000, 88, 0, 0, 0, 0]);
        threaded.entry.as_mut().unwrap().fields.push(captured(
            "arg0.clone_args.flags",
            "u64",
            &CLONE_THREAD.to_le_bytes(),
        ));
        let lines = process_tree_lines(&[threaded]);
        assert!(
            lines.iter().all(|line| !line.contains("pid 99")),
            "{lines:?}"
        );

        let mut spawned = call(1, CLONE3, "clone3", 77);
        spawned.entry.as_mut().unwrap().args = Some([CLONE_THREAD, 88, 0, 0, 0, 0]);
        spawned.entry.as_mut().unwrap().fields.push(captured(
            "arg0.clone_args.flags",
            "u64",
            &0u64.to_le_bytes(),
        ));
        let lines = process_tree_lines(&[spawned]);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("pid 77") && line.starts_with("  ")),
            "{lines:?}"
        );

        let mut missing = call(1, CLONE3, "clone3", 66);
        missing.entry.as_mut().unwrap().args = Some([0, 88, 0, 0, 0, 0]);
        let lines = process_tree_lines(&[missing]);
        assert!(
            lines.iter().all(|line| !line.contains("pid 66")),
            "{lines:?}"
        );
    }

    #[test]
    fn child_whose_parent_pid_is_absent_contains_parent_not_in_this_trace() {
        let lines = process_tree_lines(&[call(42, 1, "write", 0)]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("parent not in this trace"),
            "{}",
            lines[0]
        );
        assert!(lines[0].starts_with("pid 42"), "{}", lines[0]);
    }

    #[test]
    fn write_fd_argument_is_shown_not_the_return() {
        let mut write = call(9, 1, "write", 100);
        write.entry.as_mut().unwrap().args = Some([5, 0x1000, 100, 0, 0, 0]);
        let rows = file_rows(&[write], &["write"]);
        assert_eq!(rows.rows.len(), 1);
        assert!(!rows.stopped_early);
        assert_eq!(rows.rows[0][2].text, "5");
        assert_eq!(rows.rows[0][4].text, "100");
        assert_ne!(rows.rows[0][0].text, "100");

        let mut opened = call(9, 257, "openat", 7);
        opened
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.path", "", b"/etc/passwd\0"));
        let rows = file_rows(&[opened], &["openat"]);
        assert_eq!(rows.rows[0][0].text, "/etc/passwd");
        assert_eq!(rows.rows[0][2].text, "7");

        let failed = call(9, 2, "open", -2);
        assert_eq!(file_rows(&[failed], &["open"]).rows[0][2].text, "—");

        let unlinked = call(9, 87, "unlink", 0);
        assert_eq!(file_rows(&[unlinked], &["unlink"]).rows[0][2].text, "—");
    }

    #[test]
    fn dns_port_argument_does_not_create_a_row() {
        let mut write = call(3, 1, "write", 53);
        write.entry.as_mut().unwrap().args = Some([53, 0, 53, 0, 0, 0]);
        let mut send = call(3, 44, "sendto", 53);
        send.entry.as_mut().unwrap().args = Some([53, 0, 53, 0, 0, 16]);
        let packets = [
            packet(1, "ICMP", "type 8", Some(53)),
            packet(2, "DNS", "standard query A example.com", None),
            packet(3, "TCP", "53 → 40000", Some(53)),
            packet(4, "UDP", "9 → 9", Some(9)),
        ];
        let rows = dns_rows(&TriageInput::page(&[write, send], &packets));
        assert!(rows.rows.is_empty());
        assert!(!rows.stopped_early);
    }

    #[test]
    fn http_request_includes_get_and_skips_the_status_line() {
        let packets = [
            packet(1, "http", "HTTP/1.1 200 OK", Some(80)),
            packet(2, "http", "GET / HTTP/1.1", Some(80)),
            packet(3, "TCP", "GET /hidden HTTP/1.1", Some(80)),
        ];
        let mut response = call(4, 1, "write", 0);
        response.entry.as_mut().unwrap().fields.push(captured(
            "arg1.data",
            "",
            b"HTTP/1.1 200 OK\r\n",
        ));
        let mut request = call(4, 1, "write", 0);
        request.entry.as_mut().unwrap().fields.push(captured(
            "arg1.data",
            "",
            b"GET /index.html HTTP/1.1\r\n",
        ));
        let rows = http_rows(&TriageInput::page(&[response, request], &packets));
        assert!(
            rows.rows.is_empty(),
            "packet info and syscall text are not a reconstructed request"
        );
    }

    #[test]
    fn bpf_program_finding_skips_maps_and_requires_socket_level() {
        let mut load = call(1, 321, "bpf", 3);
        load.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut create = call(1, 321, "bpf", -1);
        create.entry.as_mut().unwrap().args = Some([0, 0, 0, 0, 0, 0]);
        let mut attached = call(1, 54, "setsockopt", 0);
        attached.entry.as_mut().unwrap().args = Some([4, 1, 26, 0, 0, 0]);
        let mut other = call(1, 54, "setsockopt", 0);
        other.entry.as_mut().unwrap().args = Some([4, 6, 26, 0, 0, 0]);
        let rules: Vec<_> = suspicious_rows(&[load, create, attached, other])
            .into_iter()
            .map(|row| row.cells[0].text.clone())
            .collect();
        assert_eq!(rules, ["bpf.program", "bpf.socket_filter"]);

        let mut bytes = call(1, 321, "bpf", 0);
        bytes.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        bytes.entry.as_mut().unwrap().fields.push(captured(
            "buf",
            "linux-6.12.94/x86_64/bpf_insn[]",
            &[0xb7, 0, 0, 0, 0, 0, 0, 0],
        ));
        let notes = page_notes(&[bytes]);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].heading.contains("BPF_PROG_LOAD"));
        assert!(notes[0].translation.is_none());
        assert_eq!(notes[0].outcome, "returned 0");
        assert_eq!(notes[0].lifecycle.as_deref(), Some("loaded program fd 0"));

        let mut image = call(1, 321, "bpf", 0);
        image.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        image.entry.as_mut().unwrap().fields.push(captured(
            "arg1.attr.insns",
            "linux-6.12.94/x86_64/bpf_insn[]",
            &[0xb7, 0, 0, 0, 0, 0, 0, 0],
        ));
        let notes = page_notes(&[image]);
        let text = notes[0].translation.as_deref().unwrap_or("");
        assert!(text.contains("mov64 r0, 0"), "{text}");

        let mut filter = call(1, 317, "seccomp", 0);
        filter.entry.as_mut().unwrap().args = Some([1, 0, 0, 0, 0, 0]);
        let notes = page_notes(&[filter]);
        assert!(notes[0].heading.contains("SECCOMP_SET_MODE_FILTER"));
        assert!(notes[0].translation.is_none());
        assert_eq!(
            notes[0].lifecycle.as_deref(),
            Some("seccomp installation successful")
        );

        let mut prctl = call(1, 157, "prctl", 0);
        prctl.entry.as_mut().unwrap().args = Some([22, 2, 0, 0, 0, 0]);
        assert!(page_notes(&[prctl])[0]
            .heading
            .contains("SECCOMP_MODE_FILTER"));

        let mut lookup = call(1, 321, "bpf", 0);
        lookup.entry.as_mut().unwrap().args = Some([1, 0, 0, 0, 0, 0]);
        assert!(page_notes(&[lookup.clone()])[0]
            .heading
            .contains("BPF_MAP_LOOKUP_ELEM"));
        assert!(page_notes(&[lookup.clone()])[0].lifecycle.is_none());
        assert!(suspicious_rows(&[lookup]).is_empty());

        let mut denied = call(1, 321, "bpf", -13);
        denied.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[denied])[0].lifecycle.as_deref(),
            Some("load failed (-13)")
        );
        let mut pending = call(1, 321, "bpf", 4);
        pending.exit = None;
        pending.entry.as_mut().unwrap().args = Some([8, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[pending])[0].lifecycle.as_deref(),
            Some("attach attempted; exit not recorded")
        );
        let mut attached_prog = call(1, 321, "bpf", 7);
        attached_prog.entry.as_mut().unwrap().args = Some([8, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[attached_prog])[0].lifecycle.as_deref(),
            Some("attach returned 7; interpretation depends on recorded flags")
        );
        let mut detach = call(1, 321, "bpf", 0);
        detach.entry.as_mut().unwrap().args = Some([9, 0, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[detach])[0].lifecycle.as_deref(),
            Some("detach successful")
        );
        let mut socket = call(1, 54, "setsockopt", 0);
        socket.entry.as_mut().unwrap().args = Some([4, 1, 26, 0, 0, 0]);
        assert_eq!(
            page_notes(&[socket])[0].lifecycle.as_deref(),
            Some("socket attachment successful")
        );
    }

    #[test]
    fn write_fd_copied_at_fork_is_not_shared_with_parent() {
        let mut opened = call(1, 257, "openat", 7);
        opened
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.path", "", b"/etc/passwd\0"));
        let forked = call(1, FORK, "fork", 42);
        let mut child_write = call(42, 1, "write", 3);
        child_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(
            &[opened.clone(), forked.clone(), child_write.clone()],
            &["write"],
        );
        assert_eq!(rows.rows[0][0].text, "/etc/passwd");
        assert_eq!(rows.rows[0][2].text, "7");

        let mut child_close = call(42, 3, "close", 0);
        child_close.entry.as_mut().unwrap().args = Some([7, 0, 0, 0, 0, 0]);
        let mut parent_write = call(1, 1, "write", 3);
        parent_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(
            &[
                opened.clone(),
                forked,
                child_close,
                child_write,
                parent_write,
            ],
            &["write"],
        );
        assert_eq!(rows.rows.len(), 2);
        assert!(!rows.rows[0][0].text.contains("/etc/passwd"));
        assert_eq!(rows.rows[1][0].text, "/etc/passwd");

        let mut thread = call(1, CLONE, "clone", 99);
        thread.entry.as_mut().unwrap().args = Some([CLONE_THREAD, 0, 0, 0, 0, 0]);
        let mut thread_write = call(99, 1, "write", 3);
        thread_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(&[opened.clone(), thread, thread_write], &["write"]);
        assert_eq!(rows.rows[0][0].text, "/etc/passwd");

        let mut missing = call(1, CLONE3, "clone3", 77);
        missing.entry.as_mut().unwrap().args = Some([0, 88, 0, 0, 0, 0]);
        let mut missing_write = call(77, 1, "write", 3);
        missing_write.entry.as_mut().unwrap().args = Some([7, 0, 3, 0, 0, 0]);
        let rows = file_rows(&[opened, missing, missing_write], &["write"]);
        assert!(!rows.rows[0][0].text.contains("/etc/passwd"));
    }

    pub(super) fn path_call(
        pid: u32,
        nr: u64,
        name: &str,
        result: i64,
        path: &str,
    ) -> InvocationSummary {
        let mut row = call(pid, nr, name, result);
        let mut bytes = path.as_bytes().to_vec();
        bytes.push(0);
        row.entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg0.pathname", "", &bytes));
        row
    }

    #[test]
    fn clone_files_does_not_share_cwd_and_relative_chdir_is_applied() {
        let start = path_call(1, 80, "chdir", 0, "/tmp");
        let mut files_only = call(1, CLONE, "clone", 42);
        files_only.entry.as_mut().unwrap().args = Some([CLONE_FILES, 0, 0, 0, 0, 0]);
        let parent_move = path_call(1, 80, "chdir", 0, "later");
        let mut child_open = call(42, 257, "openat", 3);
        child_open.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
        child_open
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.path", "", b"note\0"));
        let rows = file_rows(&[start, files_only, parent_move, child_open], &["openat"]);
        assert_eq!(rows.rows.len(), 1, "{}", rows.rows.len());
        assert_eq!(
            rows.rows[0][0].text,
            "/tmp/note (lexical cwd path; symlinks unknown)"
        );

        let start = path_call(1, 80, "chdir", 0, "/tmp");
        let relative = path_call(1, 80, "chdir", 0, "sub");
        let mut opened = call(1, 257, "openat", 4);
        opened.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
        opened
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.path", "", b"note\0"));
        let rows = file_rows(&[start, relative, opened], &["openat"]);
        assert_eq!(
            rows.rows[0][0].text,
            "/tmp/sub/note (lexical cwd path; symlinks unknown)"
        );

        let start = path_call(1, 80, "chdir", 0, "/tmp");
        let mut shared = call(1, CLONE, "clone", 42);
        shared.entry.as_mut().unwrap().args = Some([CLONE_FILES | CLONE_FS, 0, 0, 0, 0, 0]);
        let parent_move = path_call(1, 80, "chdir", 0, "/var");
        let mut child_open = call(42, 257, "openat", 3);
        child_open.entry.as_mut().unwrap().args = Some([AT_FDCWD, 0, 0, 0, 0, 0]);
        child_open
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.path", "", b"note\0"));
        let rows = file_rows(&[start, shared, parent_move, child_open], &["openat"]);
        assert_eq!(
            rows.rows[0][0].text,
            "/var/note (lexical cwd path; symlinks unknown)"
        );
    }

    #[test]
    fn private_writable_mmap_is_not_a_changed_file() {
        let mut private = call(1, 9, "mmap", 0x1000);
        private.entry.as_mut().unwrap().args = Some([0, 4096, 2, MAP_PRIVATE, 3, 0]);
        let mut shared = call(1, 9, "mmap", 0x2000);
        shared.entry.as_mut().unwrap().args = Some([0, 4096, 2, 1, 3, 0]);
        let rows = file_rows(&[private, shared], &["mmap"]);
        assert_eq!(rows.rows.len(), 1, "{}", rows.rows.len());
        assert_eq!(rows.rows[0][3].text, "mmap");
    }

    #[test]
    fn http_request_process_needs_address_and_port() {
        let packets = [packet(2, "http", "GET / HTTP/1.1", Some(80))];
        let mut port_only = call(5, 44, "sendto", 0);
        port_only
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.buf", "", b"port 80\0"));
        assert_eq!(
            http_rows(&TriageInput::page(&[port_only.clone()], &packets))
                .rows
                .len(),
            0
        );
        assert_eq!(http_process(&packets[0], &[port_only]), "—");

        let mut connect = call(4, 42, "connect", 0);
        connect
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.addr", "", b"10.0.0.2:80\0"));
        assert_eq!(
            http_process(&packets[0], &[connect]),
            "ambiguous: endpoint candidate pid 4 tid 4"
        );
    }

    #[test]
    fn bpf_program_attach_uses_the_loaded_fd() {
        let mut load = call(1, 321, "bpf", 6);
        load.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut attach = call(1, 321, "bpf", 0);
        attach.entry.as_mut().unwrap().args = Some([8, 6, 0, 0, 0, 0]);
        let notes = page_notes(&[load.clone(), attach]);
        assert_eq!(notes[0].lifecycle.as_deref(), Some("loaded program fd 6"));
        assert_eq!(notes[1].lifecycle.as_deref(), Some("attach successful"));
        assert_eq!(suspicious_rows(&[load])[0].cells[8].text, "1");

        let mut other = call(1, 321, "bpf", 7);
        other.entry.as_mut().unwrap().args = Some([8, 4, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[other])[0].lifecycle.as_deref(),
            Some("attach returned 7; interpretation depends on recorded flags")
        );

        let mut denied = call(1, 321, "bpf", -13);
        denied.entry.as_mut().unwrap().args = Some([5, 0, 0, 0, 0, 0]);
        let mut attach_exit = call(1, 321, "bpf", 3);
        attach_exit.entry.as_mut().unwrap().args = Some([8, 3, 0, 0, 0, 0]);
        assert_eq!(
            page_notes(&[denied, attach_exit])[1].lifecycle.as_deref(),
            Some("attach returned 3; interpretation depends on recorded flags")
        );
    }
}
