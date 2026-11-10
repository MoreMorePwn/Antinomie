// SPDX-License-Identifier: GPL-3.0-only
//! The refresh of the index on screen: when it is read again, and the row of
//! controls. What makes an index out of date is in `antinomie_triage::refresh`.
use super::*;

pub(super) use antinomie_triage::refresh::*;

/// How often a live run is read while its pane is hidden and the HIGH toast is on.
pub(super) const HIDDEN_POLL: Duration = Duration::from_secs(15);

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

    /// A new index is being prepared and the views have nothing current to
    /// show: not a timer's read of a recording that may not have changed.
    pub(super) fn preparing(&self) -> bool {
        self.scan_rx.is_some() && !self.scan_is_timer
    }

    /// The index on screen was built while the VM still held the recording
    /// open and says only that it is still being saved.
    fn scan_waits_for_saving(&self) -> bool {
        self.scan.as_ref().is_some_and(|scan| {
            scan.partial_reasons
                .iter()
                .any(|reason| reason == archive_scan::STILL_SAVING)
        })
    }

    /// Where the event index of the selected run stands, for the Detection
    /// scans that wait on it.
    pub(super) fn index_state(&self, has_run: bool) -> detection::IndexState {
        use detection::IndexState;
        if !has_run {
            return IndexState::Unknown;
        }
        let Some(scan) = self.scan.as_ref() else {
            return IndexState::Building;
        };
        if self.scan_waits_for_saving() {
            IndexState::Saving
        } else if let Some(error) = &scan.event_error {
            IndexState::Failed(error.clone())
        } else {
            IndexState::Ready
        }
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
            if idle && !self.scan_began_finished && self.scan_key.is_some() {
                self.next_refresh = None;
                self.refresh_requested = true;
                self.timer_refresh = true;
                return;
            }
            // The program ended but the VM has not saved the recording's
            // totals yet: the index said so instead of calling it incomplete,
            // and reads it again once they are there. A timer refresh costs
            // nothing while the recording is as the index saw it.
            if self.scan_waits_for_saving() {
                ctx.request_repaint_after(Duration::from_secs(self.refresh_seconds));
                let now = self.clock.now();
                match self.next_refresh {
                    None => {
                        self.next_refresh = Some(now + Duration::from_secs(self.refresh_seconds));
                    }
                    Some(due) if now >= due && idle => {
                        self.next_refresh = None;
                        self.refresh_requested = true;
                        self.timer_refresh = true;
                    }
                    Some(_) => {}
                }
            } else {
                self.next_refresh = None;
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
        let mut text = if self.auto_refreshing(input) {
            format!(
                "{} · every {} s",
                self.refresh_status(input),
                self.refresh_seconds
            )
        } else {
            self.refresh_status(input)
        };
        if text.chars().count() > 64 {
            text = text.chars().take(63).collect::<String>() + "…";
        }
        if let Some(room) = room {
            let measure = |ui: &egui::Ui, text: &str| {
                ui.fonts_mut(|fonts| {
                    fonts
                        .layout_no_wrap(
                            text.to_owned(),
                            egui::TextStyle::Small.resolve(ui.style()),
                            theme::muted(),
                        )
                        .size()
                        .x
                })
            };
            // The label, the menu button's padding and the spinner.
            let room = room - 56.0;
            if measure(ui, &text) > room {
                // Cut the state in the middle, so the interval stays at the
                // end, before the status goes under the tab bar.
                let (state, interval) = text.rsplit_once(" · ").unwrap_or((text.as_str(), ""));
                let mut state: Vec<char> = state.chars().collect();
                let fitted = loop {
                    if state.len() < 14 {
                        return false;
                    }
                    state.pop();
                    let cut = format!("{}… · {interval}", state.iter().collect::<String>());
                    if measure(ui, &cut) <= room {
                        break cut;
                    }
                };
                text = fitted;
            }
        }
        let rich = RichText::new(text).small().color(theme::muted());
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
                    ui.close();
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

    /// A timer reads the index again: the run is still going, or its
    /// recording has not yet saved its totals.
    fn auto_refreshing(&self, input: &TriageInput<'_>) -> bool {
        !input.run_finished || self.scan_waits_for_saving()
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
            let incomplete = if self.scan.as_ref().is_some_and(|scan| scan.partial) {
                "; incomplete"
            } else {
                ""
            };
            let age = self.clock.now().saturating_duration_since(when);
            // A finished run is read once and not again by a timer: a counter
            // of seconds since that read would only grow. Say when it was read.
            if !self.auto_refreshing(input) {
                let read = (crate::time_format::now_ms() / 1000).saturating_sub(age.as_secs());
                return format!(
                    "Read at {}{incomplete}",
                    crate::time_format::time_of_day(read)
                );
            }
            return format!("Refreshed {} s ago{incomplete}", age.as_secs());
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
            digest_job::queue().window_reads(None);
            if self.scan_key.is_some() || self.scan_rx.is_some() {
                self.stop_scan();
            }
            return;
        };
        digest_job::queue().window_reads(Some(path));
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
        // The run's digest is being built in the background: that build reads
        // the run, and a second read beside it would double the memory a large
        // recording takes. Show how far it has got; the request stays.
        match digest_job::queue().status(path) {
            digest_job::Status::Building(line) => {
                self.digest_wait = Some(line);
                return;
            }
            // Not started: this window reads the run itself, and writes its digest.
            digest_job::Status::Queued => digest_job::queue().release(path),
            digest_job::Status::Idle => {}
        }
        self.digest_wait = None;
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
        let timer = std::mem::take(&mut self.timer_refresh);
        self.scan_is_timer = timer && self.scan.is_some();
        if timer {
            request.unchanged_since = self.scan.as_ref().map(|scan| scan.stamp.clone());
        }
        // The index of the run stays for the report that follows.
        request.keep_index = true;
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
                self.scan_is_timer = false;
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
        self.scan_is_timer = false;
        self.hidden_poll = None;
        self.selected_call_id = None;
        self.bpf_export_status.clear();
        self.packet_jump = None;
        self.packet_capture = None;
        self.scan_request.offsets = [0; SLOTS];
    }
}
