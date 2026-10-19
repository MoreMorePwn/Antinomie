// SPDX-License-Identifier: MIT
//! When the index of the selected run is read again, and what a read costs.
use super::*;

/// The answer of an index thread that found the recording as the last index saw it.
pub(super) const UNCHANGED: &str = "unchanged";

/// Format of the file indexes built from a recording: which tabs exist and
/// what their rows and counts mean. It is part of the source stamp, so an
/// index made by an older format is never mistaken for current and is
/// rebuilt from the recording.
pub(super) const FILE_INDEX_VERSION: u32 = 2;

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
        "files-v{FILE_INDEX_VERSION}|{pcap_open}|{}|{:?}|{}|{:?}",
        request.run_finished,
        request.started_ms,
        request.root_cookie,
        request
            .clock_anchor
            .map(|clock| (clock.guest_ns, clock.host_us)),
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
        if self.next_refresh.is_some_and(|due| Instant::now() >= due) {
            if idle && self.shown(ctx) {
                self.refresh_requested = true;
                self.timer_refresh = true;
                self.next_refresh = None;
            } else {
                self.next_refresh =
                    Some(Instant::now() + Duration::from_secs(self.refresh_seconds));
            }
        }
    }

    pub(super) fn refresh_status(&self, input: &TriageInput<'_>) -> String {
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
        self.next_refresh = Some(Instant::now() + Duration::from_secs(self.refresh_seconds));
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
                        Err(error) if error == UNCHANGED => {
                            self.last_refresh = Some(Instant::now())
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
        self.scan_error = None;
        self.last_refresh = None;
        self.next_refresh = None;
        self.refresh_requested = false;
        self.refresh_queued = false;
        self.timer_refresh = false;
        self.scan_began_finished = false;
        self.selected_call_id = None;
        self.bpf_export_status.clear();
        self.packet_jump = None;
        self.packet_capture = None;
        self.scan_request.offsets = [0; SLOTS];
    }
}
