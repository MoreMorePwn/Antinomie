// SPDX-License-Identifier: GPL-3.0-only
//! Background scans of a saved recording and the finding journal they write.
use super::segments::{
    guest_names, name_launched, run_segments, segment_facts, segments_stamp, walk_segments,
};
use super::*;

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
            destination: directory.join("triage-findings-v2.jsonl"),
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
        let row = serde_json::to_vec(&serde_json::json!({"format_version":2, "evidence_call_id":finding.call_id, "facts":facts}))
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

/// Walk every saved invocation page. Display tables keep at most [`STORED_ROWS`]
/// matches; the coverage line counts anything left out. Cancellation stops
/// between pages and does not claim the recording was fully indexed.
#[cfg(test)]
pub(super) fn scan_archive(
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
        &ScanRequest {
            // The fixtures are one run; a request without a root is a capture of the whole VM.
            root_cookie: 55,
            ..ScanRequest::default()
        },
    )
}

pub(super) fn scan_archive_query(
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
    // A run that lived through transport reconnects is read whole, segment by
    // segment, oldest first; the run's directory is the newest.
    let segments = run_segments(&directory, request);
    // Taken before anything is read: a recording that grows meanwhile differs next time.
    let mut stamp = source_stamp(&directory, pcap, pcap_open, request);
    stamp.push_str(&segments_stamp(&segments));
    if request.unchanged_since.as_deref() == Some(stamp.as_str()) {
        return Err(UNCHANGED.into());
    }
    if !directory.join("telemetry.raw").is_file() {
        return Err(
            "saved recording has no telemetry.raw; the visible page was not treated as the whole run"
                .into(),
        );
    }
    let recordings: Vec<_> = segments
        .iter()
        .map(|segment| antinomie_monitor_core::recording::Recording {
            directory: segment.directory.clone(),
            manifest: serde_json::Value::Null,
            events: Vec::new(),
        })
        .collect();
    let recording = recordings.last().ok_or("no recording segment")?;
    let facts = segment_facts(&segments, request)?;
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
    let total = recordings
        .iter()
        .map(|recording| recording.invocation_count_cancellable(None, cancel).ok())
        .sum::<Option<u64>>();
    // The root's stream and its first credentials, for its launch.
    let mut root_stream = None;
    let mut root_creds = None;
    let mut root_call = None;
    let mut cookie_sets = std::collections::BTreeMap::new();
    let mut nodes = std::collections::BTreeMap::new();
    let mut finding_page = sorting::Page::new(request, 0, cancel);
    let finding_query = query::compile_table(&request.filters[0], FINDING_FIELDS);
    let mut engine = rules::Engine::new(rules::Options {
        show_info: request.finding_view.show_info,
        capture_all: request.root_cookie == 0,
        packed: request.packed.clone(),
    });
    let mut scoped_count = 0;
    // Calls whose saved async observations the pages only preview, and how many.
    let (mut async_partial, mut async_omitted) = (0u64, 0u64);
    let (seen, complete, issues) = walk_segments(&recordings, cancel, |segment, page| {
        let page: Vec<_> = page.iter().filter(scoped).cloned().collect();
        for call in page
            .iter()
            .filter(|call| request.root_cookie != 0 && call.task_cookie == request.root_cookie)
        {
            root_stream.get_or_insert((segment, call.stream_id));
            root_call.get_or_insert(trace::key(call));
            if root_creds.is_none() {
                root_creds = call
                    .kernel_notes
                    .iter()
                    .find_map(antinomie_monitor_core::kernel_notes::credentials);
            }
        }
        scoped_count += page.len() as u64;
        for call in page.iter().filter(|call| call.async_omitted() > 0) {
            async_partial += 1;
            async_omitted = async_omitted.saturating_add(call.async_omitted());
        }
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
    // The launch, read from the segment that holds the root's first call.
    let launch = root_stream.and_then(|(segment, stream)| {
        recordings[segment]
            .launch_record_cancellable(stream, request.root_cookie, cancel)
            .ok()
            .flatten()
    });
    if let Some(launch) = &launch {
        name_launched(&mut nodes, launch, request.root_cookie);
    }
    let cookies = resolve_cookies(&cookie_sets);
    let mut counts = normalized::Counts {
        calls: scoped_count,
        ..Default::default()
    };
    let mut event_error = None;
    let source_key = normalized::source_key(&recording.directory, pcap, pcap_open, request);
    let cached_events = normalized::reuse(
        request.event_cache.as_ref(),
        source_key.as_ref(),
        &recording.directory,
    );
    let mut event_journal = request
        .identity
        .as_ref()
        .filter(|_| request.root_cookie != 0 && cached_events.is_none())
        .and_then(|(vm, boot, run)| {
            let identity = antinomie_monitor_core::analysis::detection::Identity {
                vm_id: vm.clone(),
                boot_id: boot.clone(),
                run_id: run.clone(),
                root_cookie: request.root_cookie,
            };
            match antinomie_monitor_core::analysis::detection::EventJournal::new(
                &recording.directory,
                &identity,
            ) {
                Ok(journal) => Some(journal),
                Err(error) => {
                    event_error = Some(error);
                    None
                }
            }
        });
    let (mut journal, mut journal_error) = match FindingJournal::new(&recording.directory) {
        Ok(journal) => (Some(journal), None),
        Err(error) => (None, Some(error)),
    };
    let mut files = FdState::default();
    files.journal.launch_cwd = facts.as_ref().and_then(|facts| facts.launch_cwd.clone());
    files.journal.root_cookie = request.root_cookie;
    files.journal.hashes_writes = facts.as_ref().is_some_and(|facts| facts.hashed_writes);
    files.journal.names = guest_names(&recording.directory, request);
    if let Some(launch) = &launch {
        name_launched(&mut files.process_images, launch, request.root_cookie);
        if let (Some(writer), Some(first)) = (&mut event_journal, root_call) {
            let evidence = antinomie_monitor_core::analysis::detection::Evidence::Call {
                stream: first.0,
                cookie: first.1,
                call: first.2,
            };
            if let Err(error) =
                normalized::launch(writer, &files, launch, root_creds.as_ref(), evidence)
            {
                event_error = Some(error);
                event_journal = None;
            }
        }
    }
    let mut pending = Vec::new();
    let mut change_page = sorting::Page::new(request, 2, cancel);
    let mut file_index = files::FileIndex::default();
    file_index.set_write_limits(request.write_limits);
    let mut bpf_calls = Vec::new();
    let mut bpf_size = 0usize;
    let mut bpf_omitted = 0;
    let mut read_page = sorting::Page::new(request, 5, cancel);
    let read_query = query::compile_table(&request.filters[5], FILE_FIELDS);
    let change_query = query::compile_table(&request.filters[2], FILE_FIELDS);
    let mut tabs = file_tabs::TabSink::new(request, cancel);
    let mut reach = async_files::Reach::default();
    let mut attributed = async_files::Attributed::default();
    // One call, traced (`real`) or standing for an io_uring or AIO request.
    let mut observe = |segment: usize,
                       invocation: &InvocationSummary,
                       real: bool|
     -> Result<(), String> {
        file_index.begin_segment(segment);
        let recording = &recordings[segment];
        if real {
            observe_processes(&mut files.process_images, std::slice::from_ref(invocation));
        }
        let Some(event) = trace::representative(invocation) else {
            return Ok(());
        };
        if real && call_args(invocation).is_some_and(|args| bpf_command(event, args).is_some()) {
            let size = invocation
                .entry
                .iter()
                .chain(invocation.exit.iter())
                .flat_map(|event| &event.fields)
                .map(|field| field.preview.len() + field.key.len() + field.ranges.len() * 16)
                .sum::<usize>();
            if bpf_calls.len() < STORED_ROWS && bpf_size.saturating_add(size) <= 8 * 1024 * 1024 {
                bpf_size += size;
                bpf_calls.push(invocation.clone());
            } else {
                bpf_omitted += 1;
            }
        }
        engine.observe(invocation, &files, Some(&recording.directory), !real);
        sigma_events::seed_launch_cwd(&mut files, event);
        remember_cwd(&mut files, invocation, event);
        remember_open(&mut files, invocation, event);
        apply_dup(&mut files, invocation, event);
        forget_closed(&mut files, invocation, event);
        inherit_open_fds(&mut files, invocation, event, &cookies);
        // Classified before the call is tracked: "created" means the path
        // was not seen before this call.
        let hits = file_category::classify(&files, invocation, event);
        if let Some(writer) = &mut event_journal {
            if let Err(error) =
                normalized::call(writer, &mut pending, &mut files, invocation, event)
            {
                event_error = Some(error);
                event_journal = None;
            }
        }
        if event_journal.is_none() {
            // The journal tracks seen paths itself; without it, do it here.
            sigma_events::track(&mut files, invocation, event);
        }
        tabs.observe(request, &mut counts, &files, invocation, event, &hits)?;
        // Pages the call wrote back or unmapped were copied before its own change.
        if real {
            let directory = Some(recording.directory.as_path());
            file_index.observe_mapped(&files, invocation, event, directory, true);
        }
        if let Some(row) =
            file_index.observe_with(&files, invocation, event, Some(&recording.directory), &hits)
        {
            // Failed reads are listed with their result.
            counts.reads += 1;
            if request.file_visibility.keeps_with(&row, true)
                && read_query.keep_table(&row[0].values)
            {
                read_page.push(row)?;
            }
        }
        if real {
            let directory = Some(recording.directory.as_path());
            file_index.observe_mapped(&files, invocation, event, directory, false);
            file_index.observe_hashes(&files, invocation, event);
        }
        Ok(())
    };
    let (_, files_complete, _) = walk_segments(&recordings, cancel, |segment, page| {
        let recording = &recordings[segment];
        for submitted in page.iter().filter(scoped) {
            // Requests a ring's own thread submitted, once the calls reach
            // their time.
            for call in attributed.due(segment, submitted) {
                observe(segment, &call, false)?;
            }
            attributed.read(recording, segment, submitted, &mut reach, cancel);
            // The file requests an io_uring ring or AIO context carried,
            // after the call that submitted them, as the calls they stand for.
            let requests = async_files::expand(recording, submitted, &mut reach, cancel);
            observe(segment, submitted, true)?;
            for request in &requests {
                observe(segment, request, false)?;
            }
        }
        Ok(())
    })?;
    for (segment, call) in attributed.rest() {
        observe(segment, &call, false)?;
    }
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
    let (all_changes, mut activity) = file_index.finish_all();
    super::file_activity::resolve_earlier(
        &mut activity,
        &segments
            .iter()
            .map(|segment| (segment.directory.clone(), segment.boot_id.clone()))
            .collect::<Vec<_>>(),
        None,
        request.before_copy.as_deref(),
    );
    let ioc_files: Vec<files::IocFile> = all_changes
        .iter()
        .filter_map(files::Change::ioc_file)
        .collect();
    counts.changed = all_changes.iter().filter(|change| change.real()).count() as u64;
    let file_changes: Vec<_> = all_changes
        .into_iter()
        .filter(|change| {
            let row = change.row(clock_anchor);
            request.file_visibility.keeps(&row) && change_query.keep_table(&row[0].values)
        })
        .collect();
    for change in &file_changes {
        change_page.push(change.row(clock_anchor))?;
    }
    let (read, read_omitted, _) = read_page.finish()?;
    let (changed, changed_omitted, _) = change_page.finish()?;
    let (opened, file_tabs) = tabs.finish()?;
    let FileRows {
        rows: opened,
        omitted: opened_omitted,
    } = opened;
    let complete = complete && files_complete;
    let mut network_request = request.clone();
    network_request.owned_pcap = pcap
        .map(|path| network::owned_capture(&recording.directory, request.identity.as_ref(), path))
        .transpose()?
        .unwrap_or(false);
    network_request.started_ms = started_ms;
    network_request.segments = segments
        .iter()
        .take(segments.len().saturating_sub(1))
        .map(|segment| (segment.directory.clone(), segment.boot_id.clone()))
        .collect();
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
    let mut network = match pcap {
        Some(path) => network_index::collect(
            &recording.directory,
            path,
            pcap_open,
            cancel,
            &network_request,
            &mut |path, kind, row, destination, port| {
                let http = match kind {
                    RowKind::Http => true,
                    RowKind::Dns => false,
                    RowKind::Session => {
                        // Sessions have a table and no detection input.
                        counts.sessions += 1;
                        if let Some(first) = row.first() {
                            engine.frame(
                                rules::FrameKind::Session,
                                &first.values,
                                destination,
                                port,
                                clock_anchor,
                            );
                        }
                        return Ok(());
                    }
                };
                if http {
                    counts.http += 1;
                } else {
                    counts.dns += 1;
                }
                if !http {
                    files.journal.learn_dns(row);
                }
                if let Some(first) = row.first() {
                    engine.frame(
                        if http {
                            rules::FrameKind::Http
                        } else {
                            rules::FrameKind::Dns
                        },
                        &first.values,
                        destination,
                        port,
                        clock_anchor,
                    );
                }
                if let Some(writer) = &mut event_journal {
                    if let Err(error) =
                        normalized::packet(writer, path, row, http, destination, port)
                    {
                        event_error = Some(error);
                        event_journal = None;
                    }
                }
                Ok(())
            },
        )
        .unwrap_or_else(|error| PacketIndex {
            counts: None,
            coverage: format!("pcap index failed: {error}"),
            network_warning: Some(format!("Network index unavailable: {error}")),
            ..PacketIndex::default()
        }),
        None => PacketIndex {
            counts: None,
            coverage: "no pcap is recorded for this run; the loaded packet preview was not used"
                .into(),
            network_warning: Some("No network capture was saved for this run.".into()),
            ..PacketIndex::default()
        },
    };
    if let Some(writer) = &mut event_journal {
        if let Err(error) = normalized::flush_creations(writer, &mut files) {
            event_error = Some(error);
        }
        let held = std::mem::take(&mut pending);
        if let Err(error) = normalized::flush_connections(writer, held, &files, clock_anchor) {
            event_error = Some(error);
            event_journal = None;
        }
    }
    if estimated_end && network.network_warning.is_none() {
        network.network_warning =
            Some("Network end time is estimated from this run’s last retained syscall.".into());
    }
    // A cloud profile's metadata service wrote what it saw into the run's folder.
    if let Some(report) = antinomie_monitor_core::route::read_metadata_report(&recording.directory)
    {
        engine.cloud_report(&report, clock_anchor);
    }
    // The IOC list: the capture's indicators, the calls', the sample's and the
    // files'; matched against the datasets, and the matches listed as findings.
    let capture_state = match (pcap, network.counts) {
        (None, _) => ioc_scan::Capture::Off,
        (Some(_), Some(_)) => ioc_scan::Capture::Read,
        (Some(_), None) => ioc_scan::Capture::Failed(
            network
                .network_warning
                .clone()
                .unwrap_or_else(|| "it could not be indexed".into()),
        ),
    };
    let ioc = ioc_scan::build(
        ioc_scan::Gathered {
            collector: std::mem::take(&mut network.ioc),
            log: engine.take_ioc(),
            files: ioc_files,
            report: request.report.as_deref(),
            clock: clock_anchor,
            capture: capture_state,
            frames: network.counts.map(|counts| counts.0),
            disk: Default::default(),
        },
        request.data_dir.as_deref(),
        &recording.directory,
        request.ioc_cache.as_ref(),
        cancel,
    )?;
    let (known, online) = ioc_scan::run_inputs(request.data_dir.as_deref(), &recording.directory);
    let verdicts = ioc_scan::verdicts(&ioc, &known, &online);
    ioc_scan::list_findings(&mut engine, &ioc, &verdicts, clock_anchor);
    ioc_scan::annotate(&mut network.new_tabs, &network.http, &ioc, &verdicts);
    let output = engine.finish(&files);
    let process = finish_processes(nodes);
    let mut graph = graph::Collector::new(&process, request.finding_view);
    for mark in &output.info {
        graph.count_info(&request.finding_view, mark);
    }
    counts.findings = output.badge;
    counts.finding_tiers = output.tiers;
    counts.findings_hidden = output.hidden;
    counts.findings_suppressed = output.suppressed;
    counts.findings_capped = output.capped;
    let finding_notes = output.notes;
    let suspicious = output.tasks;
    for finding in output.rows {
        if let Some(writer) = &mut journal {
            if let Err(error) = writer.push(&finding) {
                journal_error = Some(error);
                journal = None;
            }
        }
        let in_table = rules::view_keeps(&request.finding_view, &finding.values)
            && finding_query.keep_table(&finding.values);
        graph.push(&finding, in_table);
        if in_table {
            finding_page.push(finding)?;
        }
    }
    let graph = graph.finish();
    let (findings, findings_omitted, _) = finding_page.finish()?;
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
    if recordings.len() > 1 {
        coverage.push_str(&format!(
            "; read {} recording segments of this run, split by {} transport reconnect{}",
            recordings.len(),
            recordings.len() - 1,
            if recordings.len() == 2 { "" } else { "s" }
        ));
    }
    if async_partial > 0 {
        coverage.push_str(&format!(
            "; {async_omitted} saved async observations on {async_partial} calls are past the {} each call previews and were not scanned for processes, network or detection",
            antinomie_monitor_core::ASYNC_PREVIEW_LIMIT
        ));
    }
    if reach.requests > 0 {
        coverage.push_str(&format!(
            "; {} io_uring/AIO file requests read as system calls",
            reach.requests
        ));
    }
    if reach.unread_calls > 0 {
        coverage.push_str(&format!(
            "; file requests of {} calls were not all read ({} requests, past the scan limit or unreadable)",
            reach.unread_calls, reach.unread_requests
        ));
    }
    if let Some(error) = journal_error {
        coverage.push_str(&format!(
            "; finding journal persistence unavailable: {error}"
        ));
    }
    coverage.push_str(". ");
    coverage.push_str(&network.coverage);
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let stable_source =
        source_key == normalized::source_key(&recording.directory, pcap, pcap_open, request);
    let mut reasons = incomplete_reasons(&Source {
        scan_complete: complete,
        stable: stable_source,
        issues: issues.len(),
        facts: facts.as_ref(),
        run_finished: request.run_finished,
        capture_open: pcap_open,
        network_warning: network.network_warning.as_deref(),
    });
    let event_journal = event_journal
        .and_then(
            |journal| match journal.finish_because(reasons.is_empty(), &reasons) {
                Ok(summary) => Some(summary),
                Err(error) => {
                    event_error = Some(error);
                    None
                }
            },
        )
        .or(cached_events);
    let event_cache = if stable_source {
        normalized::cache(source_key, event_journal.as_ref(), &recording.directory)
    } else {
        None
    };
    Ok(ArchiveScan {
        stamp,
        event_cache,
        counts,
        network_counts: network.counts,
        event_journal,
        event_error,
        clock_anchor,
        bpf,
        bpf_omitted,
        file_activity: Arc::new(activity),
        file_changes: file_changes
            .into_iter()
            .skip(request.offsets[2])
            .take(STORED_ROWS)
            .collect(),
        read,
        read_omitted,
        partial_reasons: {
            if omitted_files > 0 {
                reasons.push(format!(
                    "{omitted_files} files are left out of the file list"
                ));
            }
            reasons.clone()
        },
        partial: !complete
            || omitted_files > 0
            || !issues.is_empty()
            || facts
                .as_ref()
                .is_some_and(|facts| facts.complete != Some(true))
            || network.coverage.contains("failed")
            || network.network_warning.is_some()
            || pcap_open,
        #[cfg(test)]
        coverage,
        process,
        suspicious,
        findings,
        findings_omitted,
        graph,
        finding_notes,
        opened,
        opened_omitted,
        changed,
        changed_omitted,
        file_tabs,
        http: network.http,
        http_omitted: network.http_omitted,
        new_tabs: network.new_tabs,
        ioc: Some(Arc::new(ioc)),
        network_warning: network.network_warning,
    })
}

/// What the event index was built from, for saying why it may be partial.
struct Source<'a> {
    scan_complete: bool,
    stable: bool,
    issues: usize,
    facts: Option<&'a antinomie_monitor_core::recording::RunFilterFacts>,
    run_finished: bool,
    capture_open: bool,
    network_warning: Option<&'a str>,
}

/// Why the run's events may be only part of what happened, in plain words;
/// empty when the index is complete. The Sigma scan repeats these.
fn incomplete_reasons(source: &Source<'_>) -> Vec<String> {
    let mut reasons = Vec::new();
    if !source.run_finished {
        reasons.push("the run was still recording".to_owned());
    }
    if !source.scan_complete {
        reasons.push("the saved telemetry could not be read to its end".to_owned());
    }
    if source.issues > 0 {
        reasons.push(format!(
            "{} saved pages of telemetry could not be read",
            source.issues
        ));
    }
    if !source.stable {
        reasons.push("the recording changed while it was being read".to_owned());
    }
    match source.facts {
        None => reasons.push("the run's saved details could not be read".to_owned()),
        Some(facts) if facts.complete != Some(true) => {
            if let Some(lost) = facts.transport_loss.filter(|lost| *lost > 0) {
                reasons.push(format!(
                    "telemetry was lost before it reached the host ({lost} dropped)"
                ));
            }
            if let Some(lost) = facts.storage_loss.filter(|lost| *lost > 0) {
                reasons.push(format!("saving dropped {lost} packets of telemetry"));
            }
            if facts.transport_loss.unwrap_or(0) == 0 && facts.storage_loss.unwrap_or(0) == 0 {
                reasons.push(
                    "the recording is marked incomplete (saving stopped or the recording quota \
                     was reached, so only a retained prefix was kept)"
                        .to_owned(),
                );
            }
        }
        Some(_) => {}
    }
    if source.capture_open {
        reasons.push("the network capture was still open".to_owned());
    }
    if let Some(warning) = source.network_warning {
        reasons.push(format!(
            "network warning: {}",
            warning.trim_end_matches('.')
        ));
    }
    reasons
}

#[cfg(test)]
mod reason_tests {
    use super::*;

    fn source() -> Source<'static> {
        Source {
            scan_complete: true,
            stable: true,
            issues: 0,
            facts: None,
            run_finished: true,
            capture_open: false,
            network_warning: None,
        }
    }

    #[test]
    fn a_complete_source_has_no_reason_and_each_cause_names_itself() {
        let complete = antinomie_monitor_core::recording::RunFilterFacts {
            complete: Some(true),
            ..Default::default()
        };
        let whole = Source {
            facts: Some(&complete),
            ..source()
        };
        assert!(incomplete_reasons(&whole).is_empty());
        let lossy = antinomie_monitor_core::recording::RunFilterFacts {
            complete: Some(false),
            transport_loss: Some(7),
            storage_loss: Some(0),
            ..Default::default()
        };
        let reasons = incomplete_reasons(&Source {
            facts: Some(&lossy),
            run_finished: false,
            capture_open: true,
            network_warning: Some("capture failed."),
            ..source()
        });
        assert_eq!(
            reasons,
            [
                "the run was still recording",
                "telemetry was lost before it reached the host (7 dropped)",
                "the network capture was still open",
                "network warning: capture failed",
            ]
        );
        let quota = antinomie_monitor_core::recording::RunFilterFacts {
            complete: Some(false),
            transport_loss: Some(0),
            storage_loss: Some(0),
            ..Default::default()
        };
        let reasons = incomplete_reasons(&Source {
            facts: Some(&quota),
            ..source()
        });
        assert!(reasons[0].contains("retained prefix"), "{reasons:?}");
    }
}
