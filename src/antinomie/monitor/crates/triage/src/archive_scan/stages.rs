// SPDX-License-Identifier: GPL-3.0-only
//! The phases of one archive scan, each a step over the state the one before left.
use super::file_pass::{FileState, Sinks};
use super::live::{Plan, ProcessPass};
pub(crate) use super::run_record::{launch_sha256, no_capture_note, settle_crashed_start};
use super::segments::{
    guest_names, name_launched, run_segments, segment_facts, segments_stamp, walk_segments_from,
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
    /// Every task's parent as the whole recording settled it.
    pub settled: std::collections::BTreeMap<TaskKey, TaskKey>,
    /// What pass 1 settled that pass 2 reads besides the cookies and parents
    /// (a live refresh resumes only when it is the same, ANT-T0602).
    pub settled_facts: String,
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
    open_scan_planned(
        directory,
        pcap,
        pcap_open,
        cancel,
        request,
        &mut Plan::default(),
    )
}

/// [`open_scan`] that resumes pass 1 from `plan`'s snapshot and decides where
/// this scan's snapshot is taken. [`live::RESTART`] when the snapshot does not
/// hold for the recording: the caller scans it whole.
pub fn open_scan_planned(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
    plan: &mut Plan,
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
    let started_ms = request
        .started_ms
        .or_else(|| facts.as_ref().and_then(|facts| facts.started_ms));
    let scoped = in_scope(request);
    request.phase(scan_progress::Phase::Indexing, 0);
    let total = recordings
        .iter()
        .map(|recording| recording.invocation_count_cancellable(None, cancel).ok())
        .sum::<Option<u64>>();
    // Each segment's extent before a call is read, and whether the snapshot
    // being resumed holds for the recording as it is now.
    let resuming = plan.resuming();
    plan.prepare(&recordings, cancel);
    if resuming && !plan.resuming() {
        return Err(live::RESTART.into());
    }
    request.phase(scan_progress::Phase::Reading, total.unwrap_or(0));
    let mut pass = plan
        .resume
        .as_mut()
        .map(|snapshot| std::mem::take(&mut snapshot.pass1))
        .unwrap_or_else(|| ProcessPass {
            clock_anchor: request.clock_anchor,
            ..ProcessPass::default()
        });
    let engine = rules::Engine::new(rules::Options {
        show_info: request.finding_view.show_info,
        capture_all: request.root_cookie == 0,
        packed: request.packed.clone(),
        cloud_profile: cloud_profile(&directory),
    });
    let mut last = None;
    let (_, complete, found) = walk_segments_from(
        &recordings,
        plan.start,
        cancel,
        request.stop.as_deref(),
        |segment, page| {
            request.advance(page.len());
            let in_scope: Vec<&InvocationSummary> = page.iter().filter(&scoped).collect();
            pass.anchor(started_ms, &in_scope);
            for call in page {
                plan.before_pass1(&pass, segment, call);
                if scoped(&call) {
                    pass.observe(request, segment, call);
                }
                pass.seen += 1;
                last = Some((segment, trace::key(call)));
            }
            Ok(())
        },
    )?;
    if complete {
        plan.after_pass1(&pass, last);
    }
    // The anchor a full scan reads from the first page with a call: a
    // resumed pass kept the one its snapshot had, which holds only if the
    // first page still gives the same.
    if plan.resuming() && request.clock_anchor.is_none() && started_ms.is_some() {
        let mut fresh = ProcessPass::default();
        live::first_anchor(&recordings, &scoped, started_ms, cancel, &mut fresh);
        if fresh.clock_anchor != pass.clock_anchor {
            live::why("the clock anchor of the first page changed");
            return Err(live::RESTART.into());
        }
    }
    for issue in found {
        if pass.issues.len() < 32 && !pass.issues.contains(&issue) {
            pass.issues.push(issue);
        }
    }
    let ProcessPass {
        root_stream,
        root_creds,
        root_call,
        cookie_sets,
        mut nodes,
        scoped_count,
        async_partial,
        async_omitted,
        clock_anchor,
        seen,
        issues,
    } = pass;
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
        // A live run's refresh resumes pass 2 from a snapshot, which the
        // journal's writer is not part of: its events are written by the
        // full scan once the run has ended (ANT-T0602).
        .filter(|_| {
            request.root_cookie != 0 && cached_events.is_none() && !request.read_only && !plan.keep
        })
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
    let settled = process_tree::settled_parents(&nodes);
    let mut files = FdState {
        settled_parents: settled.clone(),
        ..FdState::default()
    };
    files.journal.launch_cwd = facts.as_ref().and_then(|facts| facts.launch_cwd.clone());
    files.journal.root_cookie = request.root_cookie;
    files.journal.hashes_writes = facts.as_ref().is_some_and(|facts| facts.hashed_writes);
    files.journal.names = guest_names(&recording.directory, request);
    if let Some(named) = named {
        name_launched(&mut files.process_images, named, request.root_cookie);
    }
    files.journal.launch_image = named
        .and_then(|named| named.path.clone())
        .zip(launch.as_ref().and_then(launch_sha256));
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
    // What pass 2 starts from besides the calls: a snapshot whose prefix
    // was read with other facts, or asked the whole recording for a cookie or
    // a parent that is now another, is not resumed.
    let settled_facts = format!(
        "{named:?}|{:?}|{}|{:?}|{}|{clock_anchor:?}|{:?}",
        files.journal.launch_cwd,
        files.journal.hashes_writes,
        files.journal.names,
        files.journal.root_cookie,
        files.journal.launch_image
    );
    if let Some(snapshot) = &plan.resume {
        if !live::lookups_hold(snapshot, &settled_facts, &cookies, &settled) {
            return Err(live::RESTART.into());
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
        settled,
        settled_facts,
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
        self.read_files_planned(cancel, request, &mut Plan::default())
    }

    /// [`Self::read_files`] from `plan`'s snapshot when it resumes one, taking
    /// this scan's snapshot at the plan's mark.
    pub fn read_files_planned(
        &mut self,
        cancel: &Arc<AtomicBool>,
        request: &ScanRequest,
        plan: &mut Plan,
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
        let scoped = in_scope(request);
        // A resumed refresh starts from the snapshot's state, with what pass 1
        // settled from the whole recording now; its tables are made from the
        // kept rows, so it fills no page.
        let resumed = plan.resume.take();
        let rows_only = resumed.is_some();
        plan.resumed = rows_only;
        let mut state = match resumed {
            Some(snapshot) => {
                let tap = request
                    .tap
                    .as_ref()
                    .ok_or("a resumed refresh keeps its rows")?;
                if !Arc::ptr_eq(tap, &snapshot.tap) {
                    return Err(live::RESTART.into());
                }
                tap.rewind(&snapshot.tap_marks)?;
                let mut state = snapshot.pass2;
                state.files.settled_parents = std::mem::take(&mut files.settled_parents);
                state.counts.calls = counts.calls;
                state
            }
            None => FileState::new(
                std::mem::take(files),
                std::mem::replace(engine, rules::Engine::new(Default::default())),
                counts.clone(),
                request,
            ),
        };
        let mut change_page = sorting::Page::new(request, 2, cancel);
        let change_query = query::compile_table(&request.filters[2], FILE_FIELDS);
        let mut tabs = file_tabs::TabSink::new(request, cancel);
        tabs.keep_pages = !rows_only;
        let mut sinks = Sinks {
            tabs,
            read_page: (!rows_only).then(|| sorting::Page::new(request, 5, cancel)),
            read_query: query::compile_table(&request.filters[5], FILE_FIELDS),
            event_journal,
            event_error,
            pending: Vec::new(),
        };
        let marks = || {
            request
                .tap
                .as_ref()
                .map(|tap| tap.marks())
                .unwrap_or_default()
        };
        if let Some(stop) = &request.stop {
            stop.second_pass();
        }
        if let Some(progress) = &request.progress {
            progress.next(scan_progress::Phase::Files);
        }
        let (_, files_complete, _) = walk_segments_from(
            recordings,
            plan.start,
            cancel,
            request.stop.as_deref(),
            |segment, page| {
                request.advance(page.len());
                let recording = &recordings[segment];
                for submitted in page {
                    if plan.takes_before(segment, submitted) {
                        plan.pass2_at = Some((state.clone(), marks()));
                    }
                    if scoped(&submitted) {
                        state.walk_call(
                            &mut sinks, request, cookies, recording, segment, submitted, cancel,
                        )?;
                    }
                    if plan.takes_after(segment, submitted) {
                        plan.pass2_at = Some((state.clone(), marks()));
                    }
                }
                Ok(())
            },
        )?;
        for (segment, call) in state.attributed.rest() {
            let recording = &recordings[segment];
            state.observe(
                &mut sinks, request, cookies, recording, segment, &call, false,
            )?;
        }
        let Sinks {
            tabs,
            read_page,
            pending,
            ..
        } = sinks;
        let FileState {
            files: state_files,
            engine: state_engine,
            file_index,
            reach,
            counts: state_counts,
            last_failed,
            signals,
            schema_gaps,
            bpf_calls,
            bpf_omitted,
            ..
        } = state;
        *files = state_files;
        *engine = state_engine;
        *counts = state_counts;
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
        counts.changed = all_changes.iter().filter(|change| change.counted()).count() as u64;
        // The Changed files tab lists the files `counted` means, the refused
        // attempts at such files when failures are shown, and standard I/O
        // when it is not hidden; devices, `/proc`, `/sys`, directories and
        // unnamed descriptors are not files the run changed.
        let counted: Vec<_> = all_changes
            .into_iter()
            .filter(|change| {
                change.standard_io
                    || files::counted_file(&change.path, change.path_known, false, change.directory)
            })
            .collect();
        let kept_at = file_visibility::settle_changes(
            &counted,
            request.file_visibility,
            clock_anchor,
            &mut counts.visibility[file_visibility::visibility_slot(FileTab::Changed)],
        );
        let mut listed = Vec::new();
        for &at in &kept_at {
            let row = counted[at].row(clock_anchor);
            if change_query.keep_table(&row[0].values) {
                if !rows_only {
                    change_page.push(row)?;
                }
                listed.push(at);
            }
        }
        let file_changes: Vec<_> = listed
            .iter()
            .skip(request.offsets[2])
            .take(request.rows())
            .map(|at| counted[*at].clone())
            .collect();
        // Before the chips: a later Files chip is answered from these.
        if let Some(tap) = &request.tap {
            tap.keep_changes(counted);
        }
        let (read, read_omitted) = match read_page {
            Some(page) => {
                let (read, omitted, _) = page.finish()?;
                (read, omitted)
            }
            None => (Vec::new(), 0),
        };
        let (mut changed, changed_omitted, _) = change_page.finish()?;
        crate::inetsim::label_stand_in_files(&mut changed);
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
        let sweeps = engine.sweeps();
        network_request.sweeps = (!sweeps.is_empty()).then(|| Arc::new(sweeps));
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
            None => {
                // No capture by design is a note, not a gap; only a capture
                // that should have been there is a warning.
                let note = no_capture_note(&recording.directory);
                PacketIndex {
                    counts: None,
                    coverage:
                        "no pcap is recorded for this run; the loaded packet preview was not used"
                            .into(),
                    network_warning: note
                        .is_none()
                        .then(|| "No network capture was saved for this run.".into()),
                    network_note: note,
                    ..PacketIndex::default()
                }
            }
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
        // The InetSim route's built-in services logged their sessions and transfers.
        if let Some(report) =
            antinomie_monitor_core::route::read_inetsim_report(&recording.directory)
        {
            engine.inetsim_report(&report, clock_anchor);
            crate::inetsim::feed(&mut network.ioc, &report);
            network.new_tabs.inetsim = crate::inetsim::rows(&report);
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
            })
            .map(|signal| crate::archive_scan::no_call_clause(directory, &signal));
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
        let log = engine.take_ioc();
        let sweeps = crate::sweeps::Sweeps::of(&log);
        let mut ioc = ioc_scan::build(
            ioc_scan::Gathered {
                collector: std::mem::take(&mut network.ioc).with_gateway(request.guest_gateway),
                log,
                files: ioc_files,
                read_hashes,
                report: request.report.as_deref(),
                clock: clock_anchor,
                capture: capture_state,
                frames: network.counts.map(|counts| counts.0),
                disk: Default::default(),
                sample_sha256: files
                    .journal
                    .launch_image
                    .as_ref()
                    .map(|(_, sha)| sha.clone()),
            },
            request.data_dir.as_deref(),
            &recording.directory,
            request.ioc_cache.as_ref(),
            cancel,
        )?;
        let (known, online) =
            ioc_scan::run_inputs(request.data_dir.as_deref(), &recording.directory);
        // A scanner's addresses are one row; each was matched on its own.
        ioc.indicators = sweeps.fold(
            std::mem::take(&mut ioc.indicators),
            &ioc.scan,
            &online,
            clock_anchor,
        );
        let verdicts = ioc_scan::verdicts(&ioc, &known, &online);
        ioc_scan::list_findings(&mut engine, &ioc, &verdicts, clock_anchor);
        ioc_scan::annotate(&mut network.new_tabs, &network.http, &ioc, &verdicts);
        // With a tap the engine settles its rows both ways (Show INFO on and
        // off); the one the request asks for is this scan's output.
        let (output, other_output) = if request.tap.is_some() {
            let (this, other) = engine.finish_both(&files);
            (this, Some(other))
        } else {
            (engine.finish(&files), None)
        };
        // What a later filter, sort, page, Files chip or Show INFO of this run
        // is answered from.
        let kept_variants = other_output.map(|other| {
            let variant = |output: &rules::Output| row_index::InfoVariant {
                findings: output.rows.clone(),
                info: output.info.clone(),
                badge: output.badge,
                tiers: output.tiers,
                hidden: output.hidden,
                suppressed: output.suppressed,
                capped: output.capped,
                suspicious: output.tasks.clone(),
                flagged_paths: crate::file_shown::flagged(&output.rows),
            };
            let mut variants = [
                row_index::InfoVariant::default(),
                row_index::InfoVariant::default(),
            ];
            variants[usize::from(request.finding_view.show_info)] = variant(&output);
            variants[usize::from(!request.finding_view.show_info)] = variant(&other);
            variants
        });
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
        let flagged_paths = crate::file_shown::flagged(&output.rows);
        let mut tally = crate::digest::Tally::default();
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
                tally.push(&finding);
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
        let rows = match (&request.tap, kept_variants) {
            (Some(tap), Some(variants)) if complete => tap.seal(request, variants, verdicts),
            _ => None,
        };
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
        let budget_reached = request.stop.as_ref().and_then(|stop| stop.reason());
        if let Some(why) = &budget_reached {
            reasons.insert(0, why.clone());
        }
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
            shown: rows.is_some().then(|| requery::Shown::of(request)),
            rows,
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
            file_changes,
            read,
            read_omitted,
            budget_reached: budget_reached.is_some(),
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
            behaviour: Some(tally.finish()),
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
            launch_image: files.journal.launch_image.clone(),
            network_warning: network.network_warning,
            network_note: network.network_note,
            root_crash,
            last_failed_step: last_failed.map(|step| step.text),
            signals: {
                signals.run_flags = execution_flags(&recording.directory);
                signals.persisted = persisted_copies(&recording.directory);
                signals.persistence_start = persistence_start(&recording.directory);
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
