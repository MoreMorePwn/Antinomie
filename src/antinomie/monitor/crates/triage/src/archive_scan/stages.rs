// SPDX-License-Identifier: GPL-3.0-only
//! The phases of one archive scan, each a step over the state the one before left.
use super::segments::{
    guest_names, name_launched, run_segments, segment_facts, segments_stamp, walk_segments,
};
use super::*;
use antinomie_monitor_core::recording::{Recording, RunFilterFacts, RunSegment};

/// What the scan holds between its phases.
pub struct Scan {
    pub directory: std::path::PathBuf,
    pub segments: Vec<RunSegment>,
    pub stamp: String,
    pub recordings: Vec<Recording>,
    pub facts: Option<RunFilterFacts>,
    pub clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    pub started_ms: Option<u64>,
    pub total: Option<u64>,
    pub cookies: std::collections::BTreeMap<u32, u64>,
    pub nodes: std::collections::BTreeMap<TaskKey, TaskNode>,
    pub scoped_count: u64,
    pub async_partial: u64,
    pub async_omitted: u64,
    pub seen: u64,
    pub complete: bool,
    pub issues: Vec<String>,
    pub counts: normalized::Counts,
    pub event_error: Option<String>,
    pub source_key: Option<String>,
    pub cached_events: Option<antinomie_monitor_core::analysis::detection::JournalSummary>,
    pub event_journal: Option<antinomie_monitor_core::analysis::detection::EventJournal>,
    pub journal: Option<FindingJournal>,
    pub journal_error: Option<String>,
    pub files: FdState,
    pub engine: rules::Engine,
}

/// What the file phase hands on.
pub struct FileOut {
    pub pending: Vec<antinomie_monitor_core::analysis::detection::Event>,
    pub read: Vec<Vec<Cell>>,
    pub read_omitted: u64,
    pub changed: Vec<Vec<Cell>>,
    pub changed_omitted: u64,
    pub opened: Vec<Vec<Cell>>,
    pub opened_omitted: u64,
    pub file_tabs: [FileRows; 8],
    pub files_complete: bool,
    pub omitted_files: u64,
    pub activity: file_activity::Activity,
    pub read_hashes: file_activity::ReadHashes,
    pub written_files: Vec<antinomie_monitor_core::run_digest::WrittenFile>,
    pub ioc_files: Vec<files::IocFile>,
    pub file_changes: Vec<files::Change>,
    pub bpf: Vec<BpfNote>,
    pub bpf_omitted: u64,
    pub last_failed: Option<FailedStep>,
    pub signals: run_end::SignalNotes,
    pub schema_gaps: std::collections::BTreeMap<String, u64>,
    pub reach: async_files::Reach,
}

/// What the network phase hands on.
pub struct NetworkOut {
    pub network: PacketIndex,
    pub run_ended_ms: Option<u64>,
    pub root_crash: Option<String>,
}

/// The calls of the root being scanned, or of every task when there is none.
pub fn in_scope(request: &ScanRequest) -> impl Fn(&&InvocationSummary) -> bool + '_ {
    |call: &&InvocationSummary| {
        request.root_cookie == 0
            || trace::representative(call)
                .or(call.task_exit.as_ref())
                .is_some_and(|event| event.root_task_cookie == request.root_cookie)
    }
}

/// Open the recording: its segments, processes and launch, and the journals the scan writes.
pub fn open_scan(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
) -> Result<Scan, String> {
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
        // With each segment's manifest: its guest architecture names the calls.
        .map(|segment| antinomie_monitor_core::recording::Recording::raw(&segment.directory))
        .collect();
    let recording = recordings.last().ok_or("no recording segment")?;
    let facts = segment_facts(&segments, request)?;
    let mut clock_anchor = request.clock_anchor;
    let started_ms = request
        .started_ms
        .or_else(|| facts.as_ref().and_then(|facts| facts.started_ms));
    let scoped = in_scope(request);
    request.phase(scan_progress::Phase::Indexing, 0);
    let total = recordings
        .iter()
        .map(|recording| recording.invocation_count_cancellable(None, cancel).ok())
        .sum::<Option<u64>>();
    request.phase(scan_progress::Phase::Reading, total.unwrap_or(0));
    // The root's stream and its first credentials, for its launch.
    let mut root_stream = None;
    let mut root_creds = None;
    let mut root_call = None;
    let mut cookie_sets = std::collections::BTreeMap::new();
    let mut nodes = std::collections::BTreeMap::new();
    let engine = rules::Engine::new(rules::Options {
        show_info: request.finding_view.show_info,
        capture_all: request.root_cookie == 0,
        packed: request.packed.clone(),
        cloud_profile: cloud_profile(&directory),
    });
    let mut scoped_count = 0;
    // Calls whose saved async observations the pages only preview, and how many.
    let (mut async_partial, mut async_omitted) = (0u64, 0u64);
    let (seen, complete, issues) = walk_segments(&recordings, cancel, |segment, page| {
        request.advance(page.len());
        let page: Vec<_> = page.iter().filter(&scoped).cloned().collect();
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
    // The root is named after what the launch request asked for when the
    // recording has no launch record naming it.
    let requested = segments::requested_launch(request.launch.as_ref(), launch.as_ref());
    let named = requested
        .as_ref()
        .or(launch.as_ref().filter(|launch| launch.path.is_some()));
    if let Some(named) = named {
        name_launched(&mut nodes, named, request.root_cookie);
    }
    let cookies = resolve_cookies(&cookie_sets);
    let counts = normalized::Counts {
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
        .filter(|_| request.root_cookie != 0 && cached_events.is_none() && !request.read_only)
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
    // A scan that was killed (a timed-out export that ended the process) left
    // its temporary files; the journals clean up after themselves otherwise.
    // A read-only scan (the query API) writes no journal and removes nothing.
    if !request.read_only {
        antinomie_monitor_core::analysis::detection::remove_stale_temporaries(
            &recording.directory,
            antinomie_monitor_core::analysis::detection::STALE_TEMPORARY,
        );
    }
    let (journal, journal_error) = if request.read_only {
        (None, None)
    } else {
        match FindingJournal::new(&recording.directory) {
            Ok(journal) => (Some(journal), None),
            Err(error) => (None, Some(error)),
        }
    };
    let mut files = FdState {
        settled_parents: process_tree::settled_parents(&nodes),
        ..FdState::default()
    };
    files.journal.launch_cwd = facts.as_ref().and_then(|facts| facts.launch_cwd.clone());
    files.journal.root_cookie = request.root_cookie;
    files.journal.hashes_writes = facts.as_ref().is_some_and(|facts| facts.hashed_writes);
    files.journal.names = guest_names(&recording.directory, request);
    if let Some(named) = named {
        name_launched(&mut files.process_images, named, request.root_cookie);
    }
    if let Some(launch) = &launch {
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
    Ok(Scan {
        directory,
        segments,
        stamp,
        recordings,
        facts,
        clock_anchor,
        started_ms,
        total,
        cookies,
        nodes,
        scoped_count,
        async_partial,
        async_omitted,
        seen,
        complete,
        issues,
        counts,
        event_error,
        source_key,
        cached_events,
        event_journal,
        journal,
        journal_error,
        files,
        engine,
    })
}

impl Scan {
    /// Walk the saved calls again for the files they touched.
    pub fn read_files(
        &mut self,
        cancel: &Arc<AtomicBool>,
        request: &ScanRequest,
    ) -> Result<FileOut, String> {
        let clock_anchor = self.clock_anchor;
        let Scan {
            recordings,
            segments,
            cookies,
            counts,
            event_error,
            event_journal,
            files,
            engine,
            ..
        } = self;
        let (files, mut event_journal, counts) = (files, event_journal, counts);
        let scoped = in_scope(request);
        // The last install-like call the kernel refused: "openat /var/run/x ENOENT".
        let mut last_failed: Option<FailedStep> = None;
        // Signals the calls sent, and the parent-death signals they asked for.
        let mut signals = run_end::SignalNotes::default();
        // Fields the guest had no argument decoder for, by call: the recorder's "schema gaps".
        let mut schema_gaps: std::collections::BTreeMap<String, u64> = Default::default();
        let mut pending = Vec::new();
        let mut change_page = sorting::Page::new(request, 2, cancel);
        let mut file_index = files::FileIndex::default();
        file_index.set_write_limits(request.write_limits);
        file_index.set_retention(request.retention);
        file_index.set_kernel_revision(request.kernel_revision);
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
            if real && call_args(invocation).is_some_and(|args| bpf_command(event, args).is_some())
            {
                let size = invocation
                    .entry
                    .iter()
                    .chain(invocation.exit.iter())
                    .flat_map(|event| &event.fields)
                    .map(|field| field.preview.len() + field.key.len() + field.ranges.len() * 16)
                    .sum::<usize>();
                if bpf_calls.len() < request.rows()
                    && bpf_size.saturating_add(size) <= 8 * 1024 * 1024
                {
                    bpf_size += size;
                    bpf_calls.push(invocation.clone());
                } else {
                    bpf_omitted += 1;
                }
            }
            engine.observe(invocation, files, Some(&recording.directory), !real);
            sigma_events::seed_launch_cwd(files, event);
            remember_cwd(files, invocation, event);
            remember_open(files, invocation, event);
            apply_dup(files, invocation, event);
            forget_closed(files, invocation, event);
            inherit_open_fds(files, invocation, event, cookies);
            // Classified before the call is tracked: "created" means the path
            // was not seen before this call.
            let hits = file_category::classify(files, invocation, event);
            if real {
                note_failed_step(&mut last_failed, files, invocation, event);
                signals.observe(invocation, event);
                note_schema_gaps(&mut schema_gaps, invocation, event);
            }
            if let Some(writer) = &mut event_journal {
                if let Err(error) = normalized::call(writer, &mut pending, files, invocation, event)
                {
                    *event_error = Some(error);
                    *event_journal = None;
                }
            }
            if event_journal.is_none() {
                // The journal tracks seen paths itself; without it, do it here.
                sigma_events::track(files, invocation, event);
            }
            tabs.observe(request, counts, files, invocation, event, &hits)?;
            // Pages the call wrote back or unmapped were copied before its own change.
            if real {
                let directory = Some(recording.directory.as_path());
                file_index.observe_mapped(files, invocation, event, directory, true);
            }
            if let Some(row) =
                file_index.observe_with(files, invocation, event, Some(&recording.directory), &hits)
            {
                // Failed reads are listed with their result while Failed attempts is on.
                let failed_read = file_visibility::FileVisibility::failed(&row);
                if failed_read {
                    counts.failed_attempts += 1;
                    counts.visibility[file_visibility::visibility_slot(FileTab::Read)]
                        .note_failed(&row);
                }
                if !failed_read || request.file_visibility.show_failed {
                    counts.reads += 1;
                    counts.visibility[file_visibility::visibility_slot(FileTab::Read)].add(
                        request.file_visibility,
                        &row,
                        true,
                    );
                    if request.file_visibility.keeps_with(&row, true)
                        && read_query.keep_table(&row[0].values)
                    {
                        read_page.push(row)?;
                    }
                }
            }
            if real {
                let directory = Some(recording.directory.as_path());
                file_index.observe_mapped(files, invocation, event, directory, false);
                file_index.observe_hashes(files, invocation, event);
            }
            Ok(())
        };
        if let Some(progress) = &request.progress {
            progress.next(scan_progress::Phase::Files);
        }
        let (_, files_complete, _) = walk_segments(recordings, cancel, |segment, page| {
            request.advance(page.len());
            let recording = &recordings[segment];
            for submitted in page.iter().filter(&scoped) {
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
        let segment_dirs: Vec<_> = segments
            .iter()
            .map(|segment| (segment.directory.clone(), segment.boot_id.clone()))
            .collect();
        super::file_activity::resolve_earlier(
            &mut activity,
            &segment_dirs,
            None,
            request.before_copy.as_deref(),
        );
        // Files the run only read or ran: their hashes come from the starting
        // disk, here in the scan's thread and once the run is over.
        let read_hashes = if request.run_finished {
            super::file_activity::hash_read(&mut activity, &segment_dirs, None, cancel)
        } else {
            Default::default()
        };
        let written_files: Vec<_> = all_changes
            .iter()
            .filter_map(files::Change::written_file)
            .take(antinomie_monitor_core::run_digest::MAX_ROWS)
            .collect();
        let ioc_files: Vec<files::IocFile> = all_changes
            .iter()
            .filter_map(files::Change::ioc_file)
            .collect();
        counts.changed = all_changes.iter().filter(|change| change.real()).count() as u64;
        let file_changes: Vec<_> = all_changes
            .into_iter()
            .filter(|change| {
                let row = change.row(clock_anchor);
                counts.visibility[file_visibility::visibility_slot(FileTab::Changed)]
                    .note_failed(&row);
                if request.file_visibility.show_failed
                    || !file_visibility::FileVisibility::failed(&row)
                {
                    counts.visibility[file_visibility::visibility_slot(FileTab::Changed)].add(
                        request.file_visibility,
                        &row,
                        request.file_visibility.show_failed,
                    );
                }
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
        Ok(FileOut {
            pending,
            read,
            read_omitted,
            changed,
            changed_omitted,
            opened,
            opened_omitted,
            file_tabs,
            files_complete,
            omitted_files,
            activity,
            read_hashes,
            written_files,
            ioc_files,
            file_changes,
            bpf,
            bpf_omitted,
            last_failed,
            signals,
            schema_gaps,
            reach,
        })
    }

    /// Index the capture, then settle what the events and the metadata service saw.
    pub fn read_network(
        &mut self,
        pending: &mut Vec<antinomie_monitor_core::analysis::detection::Event>,
        pcap: Option<&Path>,
        pcap_open: bool,
        cancel: &Arc<AtomicBool>,
        request: &ScanRequest,
    ) -> Result<NetworkOut, String> {
        let clock_anchor = self.clock_anchor;
        let Scan {
            directory,
            recordings,
            segments,
            facts,
            started_ms,
            nodes,
            scoped_count,
            counts,
            event_error,
            event_journal,
            files,
            engine,
            ..
        } = self;
        let (files, mut event_journal) = (files, event_journal);
        let started_ms = *started_ms;
        let recording = recordings.last().ok_or("no recording segment")?;
        let mut network_request = request.clone();
        network_request.owned_pcap = pcap
            .map(|path| {
                network::owned_capture(&recording.directory, request.identity.as_ref(), path)
            })
            .transpose()?
            .unwrap_or(false);
        network_request.started_ms = started_ms;
        // What made each flow: the network calls the rules pass has seen.
        network_request.attribution = Some(Arc::new(
            net_attr::NetAttribution::from_log(engine.net_calls(), clock_anchor)
                .within(started_ms, facts.as_ref().and_then(|facts| facts.ended_ms))
                .with_gateway(request.guest_gateway),
        ));
        network_request.segments = segments
            .iter()
            .take(segments.len().saturating_sub(1))
            .map(|segment| (segment.directory.clone(), segment.boot_id.clone()))
            .collect();
        network_request.ended_ms = facts.as_ref().and_then(|facts| facts.ended_ms);
        let estimated_end = !network_request.owned_pcap
            && request.run_finished
            && network_request.ended_ms.is_none();
        if estimated_end {
            network_request.ended_ms = nodes
                .values()
                .filter_map(|node| node.last_ns)
                .max()
                .and_then(|ns| clock_anchor.and_then(|clock| clock.host_us(ns)))
                .map(|us| us / 1000);
        }
        let run_ended_ms = network_request.ended_ms;
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
                            *event_error = Some(error);
                            *event_journal = None;
                        }
                    }
                    Ok(())
                },
            )
            .unwrap_or_else(|error| PacketIndex {
                counts: None,
                coverage: format!(
                    "pcap index failed: {}",
                    antinomie_monitor_core::disk_start::without_host_paths(&error.to_string())
                ),
                network_warning: Some(format!(
                    "Network index unavailable: {}",
                    antinomie_monitor_core::disk_start::without_host_paths(&error.to_string())
                )),
                ..PacketIndex::default()
            }),
            None => PacketIndex {
                counts: None,
                coverage:
                    "no pcap is recorded for this run; the loaded packet preview was not used"
                        .into(),
                network_warning: Some("No network capture was saved for this run.".into()),
                ..PacketIndex::default()
            },
        };
        if let Some(writer) = &mut event_journal {
            if let Err(error) = normalized::flush_creations(writer, files) {
                *event_error = Some(error);
            }
            let held = std::mem::take(pending);
            if let Err(error) = normalized::flush_connections(writer, held, files, clock_anchor) {
                *event_error = Some(error);
                *event_journal = None;
            }
        }
        if estimated_end && network.network_warning.is_none() {
            network.network_warning =
                Some("Network end time is estimated from this run’s last retained syscall.".into());
        }
        // A cloud profile's metadata service wrote what it saw into the run's folder.
        if let Some(report) =
            antinomie_monitor_core::route::read_metadata_report(&recording.directory)
        {
            engine.cloud_report(&report, clock_anchor);
        }
        // The host found copies of the program running outside the tree.
        if let Some(copies) = persisted_copies(&recording.directory) {
            engine.persisted_copies(&copies);
        }
        // A program that died of a signal before its first recorded call leaves no
        // calls to judge: say so, with the signal, instead of an empty report.
        let root_crash = (*scoped_count == 0)
            .then(|| root_exit_signal(directory))
            .flatten()
            .map(|signal| match truncated_elf_note(directory) {
                // The identification of the file says why it died so early.
                Some(note) => format!("{signal}, and the static analysis of the file says: {note}"),
                None => signal,
            });
        if let Some(text) = &root_crash {
            engine.root_crash(text, clock_anchor);
        }
        Ok(NetworkOut {
            network,
            run_ended_ms,
            root_crash,
        })
    }

    /// Match the indicators, list the findings and assemble the scan.
    pub fn finish(
        self,
        file_out: FileOut,
        network_out: NetworkOut,
        pcap: Option<&Path>,
        pcap_open: bool,
        cancel: &Arc<AtomicBool>,
        request: &ScanRequest,
    ) -> Result<ArchiveScan, String> {
        let Scan {
            stamp,
            recordings,
            facts,
            clock_anchor,
            nodes,
            seen,
            complete,
            issues,
            total,
            async_partial,
            async_omitted,
            mut counts,
            mut event_error,
            source_key,
            cached_events,
            event_journal,
            mut journal,
            mut journal_error,
            files,
            mut engine,
            ..
        } = self;
        let FileOut {
            read,
            read_omitted,
            changed,
            changed_omitted,
            opened,
            opened_omitted,
            file_tabs,
            files_complete,
            omitted_files,
            activity,
            read_hashes,
            written_files,
            ioc_files,
            file_changes,
            bpf,
            bpf_omitted,
            last_failed,
            mut signals,
            schema_gaps,
            reach,
            ..
        } = file_out;
        let NetworkOut {
            mut network,
            run_ended_ms,
            root_crash,
        } = network_out;
        let recording = recordings.last().ok_or("no recording segment")?;
        let mut finding_page = sorting::Page::new(request, 0, cancel);
        let finding_query = query::compile_table(&request.filters[0], FINDING_FIELDS);
        let complete = complete && files_complete;
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
                collector: std::mem::take(&mut network.ioc).with_gateway(request.guest_gateway),
                log: engine.take_ioc(),
                files: ioc_files,
                read_hashes,
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
        let (known, online) =
            ioc_scan::run_inputs(request.data_dir.as_deref(), &recording.directory);
        let verdicts = ioc_scan::verdicts(&ioc, &known, &online);
        ioc_scan::list_findings(&mut engine, &ioc, &verdicts, clock_anchor);
        ioc_scan::annotate(&mut network.new_tabs, &network.http, &ioc, &verdicts);
        let output = engine.finish(&files);
        let mut process = finish_processes(nodes);
        if root_crash.is_some() {
            settle_crashed_start(&mut process, &recording.directory);
        }
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
        let mut flagged_paths = crate::file_shown::Flags::new();
        for finding in output.rows {
            let tier = crate::file_shown::text_of(&finding.values, "finding.tier")
                .and_then(rules::Tier::from_tag)
                .filter(|tier| *tier != rules::Tier::Info);
            if let Some(tier) = tier {
                let text = |key| crate::file_shown::text_of(&finding.values, key);
                if let Some(object) = text("finding.object") {
                    let rule = text("finding.rule").unwrap_or_default();
                    crate::file_shown::flag(&mut flagged_paths, object, tier, rule);
                }
            }
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
            recording_open: request.recording_open,
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
        Ok(ArchiveScan::new(ScanData {
            stamp,
            whole_run: crate::is_whole_run(request),
            ended_ms: run_ended_ms,
            event_cache,
            counts,
            network_counts: network.counts,
            event_journal,
            event_error,
            clock_anchor,
            bpf,
            bpf_omitted,
            written_files,
            file_activity: Arc::new(activity),
            file_changes: file_changes
                .into_iter()
                .skip(request.offsets[2])
                .take(request.rows())
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
            #[cfg(any(test, feature = "test-support"))]
            coverage,
            process,
            suspicious,
            findings,
            findings_omitted,
            flagged_paths,
            graph,
            finding_notes,
            opened,
            opened_omitted,
            changed,
            changed_omitted,
            file_tabs,
            http: network.http,
            http_omitted: network.http_omitted,
            attribution: network.attribution.take(),
            new_tabs: network.new_tabs,
            ioc: Some(Arc::new(ioc)),
            network_warning: network.network_warning,
            root_crash,
            last_failed_step: last_failed.map(|step| step.text),
            signals: {
                signals.run_flags = execution_flags(&recording.directory);
                signals.persisted = persisted_copies(&recording.directory);
                signals.network_wait = network_wait(&recording.directory);
                signals
            },
            schema_gaps: {
                let mut gaps: Vec<_> = schema_gaps.into_iter().collect();
                gaps.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                gaps
            },
        }))
    }
}

/// A program that died of a signal before its first recorded call has a
/// process row without an exit record: show the run's own end instead of
/// "running", the signal for the program and "ended with the run" for the
/// rest.
pub(crate) fn settle_crashed_start(process: &mut [ProcessNode], directory: &Path) {
    let Some(status) = root_exit_status(directory) else {
        return;
    };
    for node in process
        .iter_mut()
        .filter(|node| !node.thread && !node.state.starts_with("task exit"))
        .filter(|node| node.in_call.is_none())
    {
        if node.parent.is_none() || node.parent_missing || node.depth == 0 {
            node.state = format!("task exit, {}", crate::values::task_end(&status));
            if let antinomie_monitor_core::WaitStatus::Signaled { signal, .. } = status {
                node.end_signal = Some(signal);
            }
        } else {
            node.state = "task exit, ended with the run".into();
        }
    }
}
