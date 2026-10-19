// SPDX-License-Identifier: MIT
//! Background scans of a saved recording and the finding journal they write.
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
        &ScanRequest::default(),
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
    // Taken before anything is read: a recording that grows meanwhile differs next time.
    let stamp = source_stamp(&directory, pcap, pcap_open, request);
    if request.unchanged_since.as_deref() == Some(stamp.as_str()) {
        return Err(UNCHANGED.into());
    }
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
    let mut scoped_count = 0;
    // Calls whose saved async observations the pages only preview, and how many.
    let (mut async_partial, mut async_omitted) = (0u64, 0u64);
    let (seen, complete, issues) = walk_pages(&recording, cancel, |page| {
        let page: Vec<_> = page.iter().filter(scoped).cloned().collect();
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
                counts.findings += 1;
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
            if let Some(writer) = &mut event_journal {
                if let Err(error) = normalized::call(writer, &files, invocation, event) {
                    event_error = Some(error);
                    event_journal = None;
                }
            }
            if let Some(row) = file_event_row(&files, invocation, event, OPEN_NAMES) {
                counts.opened += 1;
                if request.file_visibility.keeps(&row) && open_query.keep_table(&row[0].values) {
                    open_page.push(row)?;
                }
            }
            if let Some(row) =
                file_index.observe(&files, invocation, event, Some(&recording.directory))
            {
                counts.reads += 1;
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
    let all_changes = file_index.finish();
    counts.changed = all_changes.len() as u64;
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
    if async_partial > 0 {
        coverage.push_str(&format!(
            "; {async_omitted} saved async observations on {async_partial} calls are past the {} each call previews and were not scanned",
            antinomie_monitor_core::ASYNC_PREVIEW_LIMIT
        ));
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
    let mut network = match pcap {
        Some(path) => network_index::collect(
            &recording.directory,
            path,
            pcap_open,
            cancel,
            &network_request,
            &mut |path, http, row, destination, port| {
                if http {
                    counts.http += 1;
                } else {
                    counts.dns += 1;
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
            counts: None,
            coverage: "no pcap is recorded for this run; the loaded packet preview was not used"
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
    let stable_source =
        source_key == normalized::source_key(&recording.directory, pcap, pcap_open, request);
    let event_journal = event_journal
        .and_then(|journal| {
            match journal.finish(
                complete
                    && stable_source
                    && issues.is_empty()
                    && facts
                        .as_ref()
                        .is_some_and(|facts| facts.complete == Some(true))
                    && request.run_finished
                    && !pcap_open
                    && network.network_warning.is_none(),
            ) {
                Ok(summary) => Some(summary),
                Err(error) => {
                    event_error = Some(error);
                    None
                }
            }
        })
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
            || facts
                .as_ref()
                .is_some_and(|facts| facts.complete != Some(true))
            || network.coverage.contains("failed")
            || network.network_warning.is_some()
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
