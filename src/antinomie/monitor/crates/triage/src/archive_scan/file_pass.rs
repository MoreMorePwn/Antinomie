// SPDX-License-Identifier: GPL-3.0-only
//! Pass 2 of a scan one call at a time: the state it carries from call to call
//! ([`FileState`], which a live refresh keeps as a snapshot and resumes from,
//! ANT-T0602) and the tables it fills as it goes ([`Sinks`], which it does not).
use super::*;
use antinomie_monitor_core::analysis::detection::{Event, EventJournal};

/// What pass 2 holds between two calls. Every field is part of a snapshot:
/// a field whose type is not `Clone` does not compile, so nothing a later
/// change adds can be left out of one.
#[derive(Clone)]
pub struct FileState {
    pub files: FdState,
    pub engine: rules::Engine,
    pub file_index: files::FileIndex,
    pub attributed: async_files::Attributed,
    pub reach: async_files::Reach,
    pub counts: normalized::Counts,
    /// The last install-like call the kernel refused: "openat /var/run/x ENOENT".
    pub last_failed: Option<FailedStep>,
    /// Signals the calls sent, and the parent-death signals they asked for.
    pub signals: run_end::SignalNotes,
    /// Fields the guest had no argument decoder for, by call: the recorder's "schema gaps".
    pub schema_gaps: std::collections::BTreeMap<String, u64>,
    pub bpf_calls: Vec<InvocationSummary>,
    pub bpf_size: usize,
    pub bpf_omitted: u64,
}

/// What pass 2 writes as it goes, outside the state a snapshot holds.
pub struct Sinks<'a> {
    pub tabs: file_tabs::TabSink,
    /// The Read table's page; `None` when the tables are made from the kept rows.
    pub read_page: Option<sorting::Page<Vec<Cell>>>,
    pub read_query: query::Compiled,
    pub event_journal: &'a mut Option<EventJournal>,
    pub event_error: &'a mut Option<String>,
    pub pending: Vec<Event>,
}

impl FileState {
    pub fn new(
        files: FdState,
        engine: rules::Engine,
        counts: normalized::Counts,
        request: &ScanRequest,
    ) -> Self {
        let mut file_index = files::FileIndex::default();
        file_index.set_write_limits(request.write_limits);
        file_index.set_retention(request.retention);
        file_index.set_kernel_revision(request.kernel_revision);
        Self {
            files,
            engine,
            file_index,
            attributed: Default::default(),
            reach: Default::default(),
            counts,
            last_failed: None,
            signals: Default::default(),
            schema_gaps: Default::default(),
            bpf_calls: Vec::new(),
            bpf_size: 0,
            bpf_omitted: 0,
        }
    }

    /// One call, traced (`real`) or standing for an io_uring or AIO request.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        sinks: &mut Sinks<'_>,
        request: &ScanRequest,
        cookies: &std::collections::BTreeMap<u32, u64>,
        recording: &antinomie_monitor_core::recording::Recording,
        segment: usize,
        invocation: &InvocationSummary,
        real: bool,
    ) -> Result<(), String> {
        let Self {
            files,
            engine,
            file_index,
            counts,
            last_failed,
            signals,
            schema_gaps,
            bpf_calls,
            bpf_size,
            bpf_omitted,
            ..
        } = self;
        file_index.begin_segment(segment);
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
            if bpf_calls.len() < request.rows() && bpf_size.saturating_add(size) <= 8 * 1024 * 1024
            {
                *bpf_size += size;
                bpf_calls.push(invocation.clone());
            } else {
                *bpf_omitted += 1;
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
            note_failed_step(last_failed, files, invocation, event);
            signals.observe(invocation, event);
            note_schema_gaps(schema_gaps, invocation, event);
        }
        if let Some(writer) = sinks.event_journal.as_mut() {
            if let Err(error) =
                normalized::call(writer, &mut sinks.pending, files, invocation, event)
            {
                *sinks.event_error = Some(error);
                *sinks.event_journal = None;
            }
        }
        if sinks.event_journal.is_none() {
            // The journal tracks seen paths itself; without it, do it here.
            sigma_events::track(files, invocation, event);
        }
        sinks
            .tabs
            .observe(request, counts, files, invocation, event, &hits)?;
        // Pages the call wrote back or unmapped were copied before its own change.
        if real {
            let directory = Some(recording.directory.as_path());
            file_index.observe_mapped(files, invocation, event, directory, true);
        }
        if let Some(row) =
            file_index.observe_with(files, invocation, event, Some(&recording.directory), &hits)
        {
            // Every read is kept before the chips: a later Files chip is
            // answered from these rows (ANT-T0592).
            if let Some(tap) = &request.tap {
                tap.push(5, &row);
            }
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
                if request.file_visibility.keeps_with(&row, true) {
                    if let Some(page) = &mut sinks.read_page {
                        if sinks.read_query.keep_table(&row[0].values) {
                            page.push(row)?;
                        }
                    }
                }
            }
        }
        if real {
            let directory = Some(recording.directory.as_path());
            file_index.observe_mapped(files, invocation, event, directory, false);
            file_index.observe_hashes(files, invocation, event);
        }
        Ok(())
    }

    /// One call the walk reached, with the requests it stands for: those a
    /// ring's own thread submitted that are due by its time, the ones it
    /// carried, and itself.
    #[allow(clippy::too_many_arguments)]
    pub fn walk_call(
        &mut self,
        sinks: &mut Sinks<'_>,
        request: &ScanRequest,
        cookies: &std::collections::BTreeMap<u32, u64>,
        recording: &antinomie_monitor_core::recording::Recording,
        segment: usize,
        submitted: &InvocationSummary,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        // Requests a ring's own thread submitted, once the calls reach their time.
        for call in self.attributed.due(segment, submitted) {
            self.observe(sinks, request, cookies, recording, segment, &call, false)?;
        }
        let Self {
            attributed, reach, ..
        } = self;
        attributed.read(recording, segment, submitted, reach, cancel);
        // The file requests an io_uring ring or AIO context carried, after the
        // call that submitted them, as the calls they stand for.
        let requests = async_files::expand(recording, submitted, reach, cancel);
        self.observe(sinks, request, cookies, recording, segment, submitted, true)?;
        for call in &requests {
            self.observe(sinks, request, cookies, recording, segment, call, false)?;
        }
        Ok(())
    }
}
