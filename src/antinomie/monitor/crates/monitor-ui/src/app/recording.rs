// SPDX-License-Identifier: GPL-3.0-only
//! Reading saved recordings through the archive worker.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListingKind {
    Runs,
    Captures,
}

impl MonitorApp {
    pub(super) fn queue_archive(&mut self, request: Request) {
        let listing_kind = |request: &Request| match request {
            Request::ListVm { .. } => Some(ListingKind::Runs),
            Request::ListCaptures { .. } => Some(ListingKind::Captures),
            _ => None,
        };
        let newer_listing = listing_kind(&request);
        if let Some(old) = self.pending_archive.replace(request) {
            // Only a newer request for the same list makes the old one redundant.
            if newer_listing.is_none() || newer_listing != listing_kind(&old) {
                self.supersede(old);
            }
        }
    }

    /// A queued read that will not run: whoever waits on it is told, or the
    /// read is asked for again.
    fn supersede(&mut self, old: Request) {
        match old {
            Request::ProcessTree { run_id, .. }
                if self.run_tree_pending.as_ref() == Some(&run_id) =>
            {
                self.run_tree_pending = None;
            }
            Request::Invocations {
                generation, cancel, ..
            } => {
                cancel.store(true, Ordering::Relaxed);
                if generation == self.archive_generation {
                    self.archive_pending = false;
                    self.archive_error = Some("Read superseded".into());
                }
            }
            Request::Captured { generation, .. } if generation == self.inspector.generation => {
                self.inspector.pending = false;
                self.inspector.error = Some("Read superseded".into());
            }
            Request::AsyncObservations {
                generation, cancel, ..
            } => {
                cancel.store(true, Ordering::Relaxed);
                self.inspector.fail_async(generation, "Read superseded");
            }
            Request::Specimen {
                view_key,
                generation,
                ..
            } => self.fail_analysis_read(&view_key, generation, "Read superseded"),
            // A superseded listing read is simply asked for again.
            Request::Listing { view_key, .. } => {
                if let Some(view) = self.analysis_views.get_mut(&view_key) {
                    view.listing_pending = None;
                }
            }
            // A run or capture list that is replaced is asked for again.
            Request::ListVm { .. } => self.history_sync.refresh_due = true,
            Request::ListCaptures { .. } => self.history_sync.captures_refresh_due = true,
            _ => {}
        }
    }

    /// The selection changed: reads made for the old selection end. A read a
    /// view still waits on (an analysis preview or listing, a run list) stays
    /// queued, because the new selection does not change its answer.
    fn end_selection_reads(&mut self) {
        let Some(request) = self.pending_archive.take() else {
            return;
        };
        match request {
            Request::Invocations { .. }
            | Request::Captured { .. }
            | Request::AsyncObservations { .. }
            | Request::ProcessTree { .. } => self.supersede(request),
            // The view that asked is gone, so nothing waits for the answer.
            Request::Specimen { ref view_key, .. } | Request::Listing { ref view_key, .. }
                if !self.analysis_views.contains_key(view_key) => {}
            keep => self.pending_archive = Some(keep),
        }
    }

    pub(super) fn flush_archive(&mut self) {
        let Some(request) = self.pending_archive.take() else {
            return;
        };
        let Some(worker) = &self.archive else {
            self.archive_pending = false;
            self.inspector.pending = false;
            self.archive_error = Some("Archive worker unavailable".into());
            match request {
                Request::ProcessTree { run_id, .. } => {
                    self.run_tree_pending = None;
                    self.run_tree = Some((run_id, Err("Archive worker unavailable".into())));
                }
                Request::Specimen {
                    view_key,
                    generation,
                    ..
                } => self.fail_analysis_read(&view_key, generation, "Archive worker unavailable"),
                Request::Listing { view_key, .. } => {
                    self.fail_listing_read(&view_key, "Archive worker unavailable")
                }
                Request::AsyncObservations { generation, .. } => self
                    .inspector
                    .fail_async(generation, "Archive worker unavailable"),
                _ => {}
            }
            return;
        };
        match worker.try_request(request) {
            Ok(()) => {}
            Err(error) => match *error {
                std::sync::mpsc::TrySendError::Full(request) => {
                    self.pending_archive = Some(request)
                }
                std::sync::mpsc::TrySendError::Disconnected(request) => {
                    self.archive_pending = false;
                    self.inspector.pending = false;
                    self.archive_error = Some("Archive worker disconnected".into());
                    match request {
                        Request::ProcessTree { run_id, .. } => {
                            self.run_tree_pending = None;
                            self.run_tree =
                                Some((run_id, Err("Archive worker disconnected".into())));
                        }
                        Request::Specimen {
                            view_key,
                            generation,
                            ..
                        } => self.fail_analysis_read(
                            &view_key,
                            generation,
                            "Archive worker disconnected",
                        ),
                        Request::Listing { view_key, .. } => {
                            self.fail_listing_read(&view_key, "Archive worker disconnected")
                        }
                        Request::AsyncObservations { generation, .. } => self
                            .inspector
                            .fail_async(generation, "Archive worker disconnected"),
                        _ => {}
                    }
                }
            },
        }
    }

    fn fail_listing_read(&mut self, view_key: &str, reason: &str) {
        if let Some(view) = self.analysis_views.get_mut(view_key) {
            view.listing_pending = None;
            view.listing = Some(Err(reason.into()));
        }
    }

    pub(super) fn select_run(&mut self, id: Option<String>) {
        self.selected_capture = None;
        self.selected_process = None;
        self.archive_selected = false;
        self.selected_analysis = None;
        self.analysis_views.remove("workspace");
        self.selected_run = id;
        self.run_tree = None;
        self.end_selection_reads();
        self.run_tree_pending = None;
        self.reset_trace_selection();
        if self.offline_run().is_some() {
            self.request_page(0);
        }
    }

    pub(super) fn reset_trace_selection(&mut self) {
        if let Some(cancel) = self.archive_read_cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.selected_event = None;
        self.trace_evidence = None;
        self.inspector.clear();
        self.inspector.end_async();
        if matches!(
            self.pending_archive,
            Some(
                Request::Invocations { .. }
                    | Request::Captured { .. }
                    | Request::AsyncObservations { .. }
            )
        ) {
            if let Some(old) = self.pending_archive.take() {
                self.supersede(old);
            }
        }
        self.archive_generation = self.archive_generation.wrapping_add(1);
        self.archive_page.clear();
        self.archive_page_generation = 0;
        self.archive_previous.clear();
        self.archive_next = None;
        self.archive_total = None;
        self.archive_source_total = None;
        self.archive_offset = 0;
        self.archive_pending = false;
        self.archive_error = None;
    }

    pub(super) fn request_page(&mut self, offset: u64) {
        let Some(directory) = self.trace_archive_directory() else {
            return;
        };
        self.archive_generation = self.archive_generation.wrapping_add(1);
        if let Some(cancel) = self.archive_read_cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.archive_read_cancel = Some(Arc::clone(&cancel));
        self.archive_hidden_categories = if self.trace_evidence.is_some() {
            Vec::new()
        } else {
            self.settings.hidden_trace_categories.clone()
        };
        self.archive_pending = false;
        self.archive_error = None;
        let request = Request::Invocations {
            generation: self.archive_generation,
            directory,
            offset,
            limit: self.settings.trace_page_size,
            capture: self.selected_capture.is_some(),
            pid: self.selected_process,
            query: self.applied_filter.clone(),
            hidden_categories: self.archive_hidden_categories.clone(),
            cancel,
        };
        self.queue_archive(request);
        self.archive_pending = true;
    }

    pub(super) fn next_archive_page(&mut self) {
        if let Some(offset) = self.archive_next {
            self.archive_previous.push(self.archive_offset);
            self.request_page(offset);
        }
    }

    pub(super) fn reopen(&mut self, run: RunSummary) {
        let live = run_in_live_session(&self.snapshot, &run);
        let reserved = usize::from(self.pending_launch.is_some());
        let consumes_slot = self.terminals.get(&run.id).is_none_or(|terminal| {
            !terminal.open && !run_in_live_session(&self.snapshot, &terminal.run)
        });
        if consumes_slot && available_terminal_slots(&self.terminals, &self.snapshot) <= reserved {
            self.report_warning(terminal_capacity_message());
            return;
        }
        if let Some(terminal) = self.terminals.get_mut(&run.id) {
            terminal.open = true;
            terminal.terminal.invalidate_resize();
            if live {
                terminal.dirty = true;
                terminal.snapshot_error = None;
            } else {
                terminal.begin_replay();
            }
            return;
        }
        if self.terminals.len() >= TERMINAL_VIEW_LIMIT {
            let reclaim = self
                .terminals
                .iter()
                .find(|(_, terminal)| {
                    !terminal.open && !run_in_live_session(&self.snapshot, &terminal.run)
                })
                .map(|(id, _)| id.clone());
            if let Some(id) = reclaim {
                self.terminals.remove(&id);
            }
        }
        if self.terminals.len() >= TERMINAL_VIEW_LIMIT {
            self.report_warning(terminal_capacity_message());
            return;
        }
        let mut terminal = RunTerminal::new(run.clone());
        if !live {
            terminal.begin_replay();
        } else {
            terminal.dirty = true;
        }
        self.terminals.insert(run.id.clone(), terminal);
    }

    pub(super) fn focus_trace(&mut self) {
        self.focus_panel = Some(Panel::Trace);
    }

    pub(super) fn select_capture(&mut self, id: String, archive: bool) {
        self.selected_run = None;
        self.reset_trace_selection();
        if self.selected_capture.as_ref() != Some(&id) {
            self.selected_process = None;
        }
        if !self.snapshot.capture_processes.contains_key(&id)
            && self
                .archived_processes
                .as_ref()
                .is_none_or(|(loaded, _)| *loaded != id)
        {
            if let Some(capture) = self.capture(&id) {
                let processes =
                    antinomie_monitor_core::capture::capture_processes(&capture.directory);
                self.archived_processes = Some((id.clone(), processes));
            }
        }
        self.selected_capture = Some(id);
        self.archive_selected = archive;
        if self.trace_archive_directory().is_some() {
            self.request_page(0);
        }
        if archive {
            self.focus_trace();
        }
    }

    pub(super) fn select_archive_run(&mut self, id: String) {
        self.select_run(Some(id));
        self.archive_selected = true;
        self.request_page(0);
        self.focus_trace();
    }

    pub(super) fn handle_archive_answer(&mut self, answer: Answer) {
        match answer {
            Answer::ListCaptures {
                vm_id,
                generation,
                result,
            } => {
                if self.selected.as_ref() != Some(&vm_id) {
                    return;
                }
                if generation != self.history_generation {
                    self.history_sync.captures_refresh_due = true;
                    return;
                }
                match result {
                    Ok(captures) => self.capture_history = captures,
                    Err(error) => {
                        self.status = format!("Capture History: {error}");
                        self.log("ERROR", self.status.clone());
                    }
                }
            }
            Answer::Listing {
                view_key,
                generation,
                result,
            } => {
                let Some(view) = self.analysis_views.get_mut(&view_key) else {
                    return;
                };
                if view
                    .listing_pending
                    .as_ref()
                    .is_some_and(|(pending, ..)| *pending == generation)
                {
                    view.listing_pending = None;
                    let report_id = view.report_id.clone();
                    view.listing = Some(result.and_then(|page| {
                        if report_id.as_deref() != Some(page.report_id.as_str()) {
                            return Err("Listing page identity mismatch".into());
                        }
                        Ok(page)
                    }));
                }
            }
            Answer::Specimen {
                view_key,
                generation,
                report_id,
                offset,
                data_len,
                result,
            } => {
                if let Some(view) = self.analysis_views.get_mut(&view_key) {
                    if view.report_id.as_deref() != Some(&report_id)
                        || view.pending != Some((generation, offset, data_len))
                    {
                        return;
                    }
                    view.pending = None;
                    view.preview = Some(result.and_then(|page| {
                        if page.report_id != report_id
                            || page.offset != offset
                            || page.data.len() != data_len
                        {
                            return Err("Specimen preview identity mismatch".into());
                        }
                        Ok(page)
                    }));
                }
            }
            Answer::ListVm {
                vm_id,
                generation,
                result,
                checked,
                retained,
            } => {
                if self.selected.as_ref() != Some(&vm_id) {
                    return;
                }
                if generation != self.history_generation {
                    self.history_sync.refresh_due = true;
                    return;
                }
                match result {
                    Ok(runs) => self.accept_run_listing(runs, checked, retained),
                    Err(error) => {
                        self.status = format!("History: {error}");
                        self.log("ERROR", self.status.clone());
                    }
                }
            }
            #[cfg(test)]
            Answer::List(result) => match result {
                Ok(mut runs) => {
                    runs.extend(
                        self.history
                            .iter()
                            .filter(|run| run.id.starts_with("archive:"))
                            .cloned(),
                    );
                    self.history = runs;
                }
                Err(error) => {
                    self.status = format!("History: {error}");
                    self.log("ERROR", self.status.clone());
                }
            },
            Answer::Invocations {
                generation,
                offset,
                total,
                source_total,
                result,
            } if generation == self.archive_generation
                && self.trace_archive_directory().is_some() =>
            {
                self.archive_pending = false;
                match result {
                    Ok(page) => {
                        self.archive_total = total;
                        self.archive_source_total = source_total;
                        self.archive_page = page.invocations;
                        self.archive_page_generation = generation;
                        if self.selected_event.is_some_and(|selected| {
                            !self
                                .archive_page
                                .iter()
                                .any(|row| trace::key(row) == selected)
                        }) {
                            self.selected_event = None;
                            self.inspector.clear();
                        }
                        self.archive_offset = offset;
                        self.archive_next = page.next_offset;
                        self.archive_error =
                            (!page.issues.is_empty()).then(|| page.issues.join("; "));
                    }
                    Err(error) => self.archive_error = Some(error),
                }
            }
            Answer::Totals { key, result } => {
                let Some(directory) = self.trace_archive_directory() else {
                    return;
                };
                let current = crate::archive::totals_key(
                    &directory,
                    self.selected_capture.is_some(),
                    self.selected_process,
                    &self.applied_filter,
                    &self.archive_hidden_categories,
                );
                // Counts of the view being shown; those of an earlier filter are dropped.
                if key == current {
                    match result {
                        Ok((total, source_total)) => {
                            self.archive_total = Some(total);
                            self.archive_source_total = Some(source_total);
                        }
                        Err(error) => {
                            self.archive_error = Some(format!("Counting matches: {error}"))
                        }
                    }
                }
            }
            Answer::ProcessTree { run_id, result } => {
                if self.run_tree_pending.as_ref() == Some(&run_id)
                    && self.selected_run.as_ref() == Some(&run_id)
                {
                    self.run_tree_pending = None;
                    self.run_tree = Some((run_id, result));
                }
            }
            Answer::Captured {
                generation,
                offset,
                result,
            } if generation == self.inspector.generation => {
                self.inspector.pending = false;
                match result {
                    Ok(data) => {
                        self.inspector.data = data;
                        self.inspector.data_offset = offset;
                        self.inspector.error = None;
                    }
                    Err(error) => self.inspector.error = Some(error),
                }
            }
            Answer::AsyncObservations {
                generation,
                call,
                result,
            } => self.inspector.async_answer(generation, call, result),
            Answer::Terminal {
                run_id,
                generation,
                result,
            } => {
                if let Some(terminal) = self.terminals.get_mut(&run_id) {
                    if terminal.generation != generation {
                        return;
                    }
                    terminal.replay_pending = false;
                    match result {
                        Ok(replay) => {
                            for record in replay.page.records {
                                match record {
                                    TerminalRecord::Output(data) => {
                                        terminal.terminal.process(&data)
                                    }
                                    TerminalRecord::Resize { rows, cols } => {
                                        terminal.terminal.replay_resize(rows, cols)
                                    }
                                    TerminalRecord::Eof => terminal.run.terminal_eof = true,
                                }
                            }
                            terminal.replay_offset = replay.page.next_offset;
                            if let Some(warning) = replay.screen_warning {
                                terminal.replay_error = Some(warning.clone());
                                self.report_warning(warning);
                            }
                        }
                        Err(error) => {
                            terminal.replay_offset = None;
                            terminal.replay_error = Some(error.clone());
                            self.report_error(format!("Terminal history: {error}"));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    pub(super) fn drain_archive(&mut self) {
        for _ in 0..8 {
            let Some(answer) = self.archive.as_ref().and_then(|worker| worker.receive()) else {
                break;
            };
            self.handle_archive_answer(answer);
        }
        self.refresh_history_when_idle();
        // At most one disk request is queued; closed history views pause their replay.
        if self.pending_archive.is_some() {
            return;
        }
        for terminal in self.terminals.values_mut() {
            let on_screen = terminal
                .last_paint
                .is_some_and(|painted| painted.elapsed() < Duration::from_secs(1));
            if (!terminal.open && !on_screen) || terminal.replay_pending {
                continue;
            }
            if let Some(offset) = terminal.replay_offset {
                if let Some(worker) = &self.archive {
                    if worker
                        .request(Request::Terminal {
                            run_id: terminal.run.id.clone(),
                            generation: terminal.generation,
                            directory: terminal.run.directory.clone(),
                            offset,
                        })
                        .is_ok()
                    {
                        terminal.replay_pending = true;
                    }
                }
            }
        }
    }
}
