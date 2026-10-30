// SPDX-License-Identifier: GPL-3.0-only
//! When the index of the selected run is read again, and what a read costs.
use super::*;

/// How often a live run is read while its pane is hidden and the HIGH toast is on.
pub(super) const HIDDEN_POLL: Duration = Duration::from_secs(15);

/// The answer of an index thread that found the recording as the last index saw it.
pub(super) const UNCHANGED: &str = "unchanged";

const HOST_TIME_NOTE: &str = "Times use the host timezone. ~ marks a guest event time estimated from a host receipt/start anchor, including transport latency.";
const NETWORK_TIME_NOTE: &str = "Packet timestamps use QEMU's capture clock, displayed in the host timezone. They may differ from the host run clock; capture ownership determines which run is indexed.";

/// Format of the file indexes built from a recording: which tabs exist and
/// what their rows and counts mean. It is part of the source stamp, so an
/// index made by an older format is never mistaken for current and is
/// rebuilt from the recording.
pub(super) const FILE_INDEX_VERSION: u32 = 3;

/// What an index of the recording depends on, as a string: size and
/// modification time of the files it reads, and the request facts that
/// change its meaning. Equal strings mean a new index would be the same.
pub(super) fn source_stamp(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    request: &ScanRequest,
) -> String {
    use std::os::unix::fs::MetadataExt;
    let file = |path: &Path| {
        std::fs::metadata(path).map_or_else(
            |_| "-".to_owned(),
            |meta| {
                format!(
                    "{}.{}.{}.{}",
                    meta.len(),
                    meta.mtime(),
                    meta.mtime_nsec(),
                    meta.ino()
                )
            },
        )
    };
    let mut stamp = format!(
        "files-v{FILE_INDEX_VERSION}|{pcap_open}|{}|{:?}|{}|{:?}|{}/{}",
        request.run_finished,
        request.started_ms,
        request.root_cookie,
        request
            .clock_anchor
            .map(|clock| (clock.guest_ns, clock.host_us)),
        request.write_limits.per_file,
        request.write_limits.per_run,
    );
    for name in [
        "telemetry.raw",
        "artifacts.json",
        "run.json",
        "manifest.json",
    ] {
        stamp.push('|');
        stamp.push_str(&file(&directory.join(name)));
    }
    // What the IOC list depends on besides the recording: the datasets, the
    // false positives, the online answers kept with the run and the sample.
    if let Some(dir) = &request.data_dir {
        stamp.push_str(&format!(
            "|ioc={}|{}",
            ioc_scan::signature(dir),
            file(&dir.join("known-false-positives.json"))
        ));
    }
    stamp.push_str(&format!(
        "|{}|{}",
        file(&directory.join("ioc-online.json")),
        request
            .report
            .as_ref()
            .map_or_else(String::new, |report| format!(
                "{}.{:?}.{}",
                report.id,
                report.state,
                report
                    .sections
                    .iter()
                    .map(|s| s.entries.len())
                    .sum::<usize>()
            ))
    ));
    if let Some(pcap) = pcap {
        stamp.push_str(&format!("|{}={}", pcap.display(), file(pcap)));
    }
    stamp
}

impl TriageView {
    /// A new index for the user's query, page or Refresh button: always read in full.
    pub(super) fn request_refresh(&mut self) {
        self.refresh_requested = true;
        self.timer_refresh = false;
    }

    pub(super) fn request_query_refresh(&mut self) {
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.pending_generation = None;
        self.request_refresh();
    }

    /// The pane is on screen this frame: the index of a live run is kept current.
    pub(super) fn mark_shown(&mut self, ctx: &egui::Context) {
        self.shown_pass = Some(ctx.cumulative_pass_nr());
    }

    fn shown(&self, ctx: &egui::Context) -> bool {
        self.shown_pass
            .is_some_and(|pass| ctx.cumulative_pass_nr().saturating_sub(pass) <= 2)
    }

    /// Decide whether the index of the selected run is read again now.
    ///
    /// | Run | Pane | Re-read |
    /// | --- | --- | --- |
    /// | live | shown | every `refresh_seconds`, if the recording grew |
    /// | live | hidden | not until it is shown or the run ends |
    /// | ended | any | once, if the last index began while it was live |
    ///
    /// The "grew" check runs with the index thread (see [`source_stamp`]), so
    /// a live run that did not change is not re-read and nothing is written
    /// into its directory.
    pub(super) fn schedule_refresh(&mut self, ctx: &egui::Context, run_finished: bool) {
        let idle = self.scan_rx.is_none() && !self.refresh_requested && !self.refresh_queued;
        if run_finished {
            self.next_refresh = None;
            if idle && !self.scan_began_finished && self.scan_key.is_some() {
                self.refresh_requested = true;
                self.timer_refresh = true;
            }
            return;
        }
        ctx.request_repaint_after(Duration::from_secs(self.refresh_seconds));
        if self.next_refresh.is_some_and(|due| self.clock.now() >= due) {
            let now = self.clock.now();
            // With the toast on, a live run is read now and then even when the
            // pane is hidden, so a HIGH finding is announced when it happens.
            let watching = self.toast_high
                && self
                    .hidden_poll
                    .is_none_or(|at| now.saturating_duration_since(at) >= HIDDEN_POLL);
            if idle && (self.shown(ctx) || watching) {
                if !self.shown(ctx) {
                    self.hidden_poll = Some(now);
                }
                self.refresh_requested = true;
                self.timer_refresh = true;
                self.next_refresh = None;
            } else {
                self.next_refresh =
                    Some(self.clock.now() + Duration::from_secs(self.refresh_seconds));
            }
        }
    }

    /// The Refresh, interval and status row of the sections that keep it.
    pub(super) fn refresh_row(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(input.archive.is_some(), egui::Button::new("Refresh"))
                .on_disabled_hover_text("A whole-run index starts after the recording is saved")
                .clicked()
            {
                self.refresh_now(input);
            }
            ui.label("Every");
            self.interval_edit(ui);
            if self.scan_rx.is_some() {
                theme::spinner(ui);
            }
            let status = ui.colored_label(theme::muted(), self.refresh_status(input));
            if let Some(why) = self.incomplete_why() {
                status.on_hover_text(why);
            }
        });
    }

    fn refresh_now(&mut self, input: &TriageInput<'_>) {
        self.request_refresh();
        self.ensure_scan(
            input.archive,
            input.pcap,
            input.pcap_open,
            input.vm_id,
            input.boot_id,
            input.run_id,
        );
    }

    fn interval_edit(&mut self, ui: &mut egui::Ui) {
        if ui
            .add(
                egui::DragValue::new(&mut self.refresh_seconds)
                    .range(1..=300)
                    .suffix(" s"),
            )
            .changed()
        {
            self.refresh_seconds = self.refresh_seconds.clamp(1, 300);
            self.next_refresh = Some(self.clock.now() + Duration::from_secs(self.refresh_seconds));
        }
    }

    /// The one status at the right of the tab bar, for the sections that have
    /// no refresh row: a menu with Refresh now and the interval. The text
    /// reads `Refreshed 12 s ago · every 5 s`. Returns whether it fits in
    /// `room`, so the caller can place it on its own line instead.
    pub(super) fn refresh_trail(
        &mut self,
        ui: &mut egui::Ui,
        input: &TriageInput<'_>,
        room: Option<f32>,
    ) -> bool {
        let mut text = format!(
            "{} · every {} s",
            self.refresh_status(input),
            self.refresh_seconds
        );
        if text.chars().count() > 64 {
            text = text.chars().take(63).collect::<String>() + "…";
        }
        let rich = RichText::new(text).small().color(theme::muted());
        if let Some(room) = room {
            let width = ui.fonts(|fonts| {
                fonts
                    .layout_no_wrap(
                        rich.text().to_owned(),
                        egui::TextStyle::Small.resolve(ui.style()),
                        theme::muted(),
                    )
                    .size()
                    .x
            });
            // The label, the menu button's padding and the spinner.
            if width + 56.0 > room {
                return false;
            }
        }
        ui.scope(|ui| {
            let widgets = &mut ui.visuals_mut().widgets;
            for style in [&mut widgets.inactive, &mut widgets.noninteractive] {
                style.weak_bg_fill = egui::Color32::TRANSPARENT;
                style.bg_stroke = egui::Stroke::NONE;
            }
            ui.menu_button(rich, |ui| {
                if ui
                    .add_enabled(input.archive.is_some(), egui::Button::new("Refresh now"))
                    .on_disabled_hover_text("A whole-run index starts after the recording is saved")
                    .clicked()
                {
                    self.refresh_now(input);
                    ui.close_menu();
                }
                ui.horizontal(|ui| {
                    ui.label("Every");
                    self.interval_edit(ui);
                });
                if let Some(why) = self.incomplete_why() {
                    ui.add(
                        egui::Label::new(RichText::new(why).small().color(theme::warn())).wrap(),
                    );
                }
                ui.weak(if self.section == Section::Network {
                    NETWORK_TIME_NOTE
                } else {
                    HOST_TIME_NOTE
                });
            });
            if self.scan_rx.is_some() {
                theme::spinner(ui);
            }
        });
        true
    }

    /// Why the index is incomplete, one sentence for a tooltip; `None` when it
    /// is whole.
    pub(super) fn incomplete_why(&self) -> Option<String> {
        let scan = self.scan.as_ref().filter(|scan| scan.partial)?;
        Some(if scan.partial_reasons.is_empty() {
            "Part of this run's evidence is not in the index.".to_owned()
        } else {
            format!("Incomplete because {}.", scan.partial_reasons.join("; "))
        })
    }

    pub(super) fn refresh_status(&self, input: &TriageInput<'_>) -> String {
        if self.scan_rx.is_some() {
            return self.last_refresh.map_or_else(
                || "Indexing the saved recording".into(),
                |when| {
                    format!(
                        "Refreshing; showing index from {} s ago",
                        self.clock.now().saturating_duration_since(when).as_secs()
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
                self.clock.now().saturating_duration_since(when).as_secs(),
                if self.scan.as_ref().is_some_and(|scan| scan.partial) {
                    "; incomplete"
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

    pub(super) fn ensure_scan(
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
            self.request_refresh();
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
        request.ioc_cache = self
            .scan
            .as_ref()
            .and_then(|scan| scan.ioc.as_ref())
            .map(|ioc| ioc.cache.clone());
        // Only a timer refresh may find the recording as it was; the index
        // thread then answers `UNCHANGED` without reading or writing.
        if std::mem::take(&mut self.timer_refresh) {
            request.unchanged_since = self.scan.as_ref().map(|scan| scan.stamp.clone());
        }
        self.scan_began_finished = request.run_finished;
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
        self.next_refresh = Some(self.clock.now() + Duration::from_secs(self.refresh_seconds));
    }

    pub(super) fn poll_scan(&mut self, ctx: &egui::Context) {
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
                            let run = self.scan_request.identity.as_ref().map(|id| id.2.clone());
                            if let Some(run) = run {
                                // A scan that began while the run was going is a live one.
                                self.high_watch.observe(
                                    ctx,
                                    &run,
                                    !self.scan_began_finished,
                                    self.toast_high,
                                    &scan.graph.high,
                                );
                            }
                            if self.selected_call_id.is_some_and(|call_id| {
                                !scan.findings.iter().any(|finding| finding.key == call_id)
                            }) {
                                self.selected_call_id = None;
                            }
                            self.changed_paths = Arc::new(
                                scan.file_changes
                                    .iter()
                                    .filter_map(|change| {
                                        crate::disk_view::normalize_guest_path(&change.path)
                                    })
                                    .collect(),
                            );
                            self.scan = Some(scan);
                            self.scan_error = None;
                            self.last_refresh = Some(self.clock.now());
                        }
                        Err(error) if error == "cancelled" => {}
                        Err(error) if error == UNCHANGED => {
                            self.last_refresh = Some(self.clock.now())
                        }
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

    pub(super) fn stop_scan(&mut self) {
        if let Some(cancel) = &self.scan_cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        self.scan_generation = self.scan_generation.saturating_add(1);
        self.pending_generation = None;
        self.scan_key = None;
        self.scan_cancel = None;
        self.scan_rx = None;
        self.scan = None;
        self.changed_paths = Arc::default();
        self.scan_error = None;
        self.last_refresh = None;
        self.next_refresh = None;
        self.refresh_requested = false;
        self.refresh_queued = false;
        self.timer_refresh = false;
        self.scan_began_finished = false;
        self.hidden_poll = None;
        self.selected_call_id = None;
        self.bpf_export_status.clear();
        self.packet_jump = None;
        self.packet_capture = None;
        self.scan_request.offsets = [0; SLOTS];
    }
}
