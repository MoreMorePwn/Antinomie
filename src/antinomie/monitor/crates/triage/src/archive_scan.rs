// SPDX-License-Identifier: GPL-3.0-only
//! Background scans of a saved recording and the finding journal they write.
use super::*;

pub mod stages;
#[cfg(test)]
mod timing;

impl FindingJournal {
    pub fn new(directory: &Path) -> Result<Self, String> {
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
    pub fn push(&mut self, finding: &Finding) -> Result<(), String> {
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
    pub fn publish(&mut self) -> Result<(), String> {
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
#[cfg(any(test, feature = "test-support"))]
pub fn scan_archive(
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

pub fn scan_archive_query(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
) -> Result<ArchiveScan, String> {
    if let Some(done) = &request.reuse {
        return Ok(done.clone());
    }
    // The index of a large recording is built on this thread, in the first
    // call that counts the calls: it tells the request's progress as it goes.
    let opened = match &request.progress {
        Some(progress) => {
            let progress = Arc::clone(progress);
            antinomie_monitor_core::recording::with_index_progress(
                move |done, total| progress.set(scan_progress::Phase::Indexing, done, total),
                || stages::open_scan(directory, pcap, pcap_open, cancel, request),
            )
        }
        None => stages::open_scan(directory, pcap, pcap_open, cancel, request),
    };
    let mut scan = opened?;
    let mut files = scan.read_files(cancel, request)?;
    request.phase(scan_progress::Phase::Settling, 0);
    let network = scan.read_network(&mut files.pending, pcap, pcap_open, cancel, request)?;
    let done = scan.finish(files, network, pcap, pcap_open, cancel, request)?;
    if request.keep_index {
        scan_cache::remember(directory, &done);
    }
    Ok(done)
}

/// Count the fields of this call the guest had no decoder for (status
/// NO_DECODER), under the call's name, the field and, for `ioctl`, the request.
pub fn note_schema_gaps(
    gaps: &mut std::collections::BTreeMap<String, u64>,
    invocation: &InvocationSummary,
    event: &EventSummary,
) {
    let mut keys = std::collections::BTreeSet::new();
    for field in invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|phase| &phase.fields)
        .filter(|field| field.status == Some(4))
    {
        keys.insert(field.key.as_str());
    }
    for key in keys {
        let name = event.syscall_name.as_str();
        let label = match (name, call_args(invocation)) {
            ("ioctl", Some(args)) => format!("ioctl request {:#x} ({key})", args[1]),
            ("arch_prctl" | "prctl" | "fcntl" | "futex", Some(args)) => {
                format!("{name} selector {:#x} ({key})", args[0])
            }
            _ => format!("{name} ({key})"),
        };
        let count = gaps.entry(label).or_insert(0);
        *count = count.saturating_add(1);
    }
}

/// A call that tried to make, change or run something and was refused.
pub struct FailedStep {
    pub text: String,
}

/// Remember `invocation` as the run's last failing step when it is a refused
/// create, write, delete, rename, link, permission change or exec. Reads and
/// probes (a library search, a `stat`) fail all the time and say nothing.
pub fn note_failed_step(
    last: &mut Option<FailedStep>,
    files: &FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
) {
    let file_category::Outcome::Failed(ret) = file_category::outcome(invocation) else {
        return;
    };
    let name = event.syscall_name.as_str();
    let makes = match name {
        "open" | "openat" | "openat2" | "creat" => file_events::open_flags(invocation, event)
            .is_some_and(|flags| flags & 0o3 != 0 || flags & 0o100 != 0),
        "mkdir" | "mkdirat" | "mknod" | "mknodat" | "unlink" | "unlinkat" | "rmdir" | "rename"
        | "renameat" | "renameat2" | "link" | "linkat" | "symlink" | "symlinkat" | "chmod"
        | "fchmodat" | "chown" | "fchownat" | "truncate" | "execve" | "execveat" => true,
        _ => false,
    };
    if !makes {
        return;
    }
    let path = sigma_events::paths(files, invocation, event)
        .into_iter()
        .next()
        .map(|used| used.name)
        .unwrap_or_default();
    let errno = crate::values::errno_name(ret.unsigned_abs())
        .map_or_else(|| ret.to_string(), str::to_owned);
    let text = if path.is_empty() {
        format!("{name} {errno}")
    } else {
        format!("{name} {path} {errno}")
    };
    *last = Some(FailedStep { text });
}

/// Said instead of a cause while the VM still holds the recording open.
pub const STILL_SAVING: &str =
    "the recording is still being saved (its totals are written when the VM stops)";

/// What the event index was built from, for saying why it may be partial.
pub struct Source<'a> {
    pub scan_complete: bool,
    pub stable: bool,
    pub issues: usize,
    pub facts: Option<&'a antinomie_monitor_core::recording::RunFilterFacts>,
    pub run_finished: bool,
    /// The VM boot that recorded the run is still up.
    pub recording_open: bool,
    pub capture_open: bool,
    pub network_warning: Option<&'a str>,
}

/// Why the run's events may be only part of what happened, in plain words;
/// empty when the index is complete. The Sigma scan repeats these.
pub fn incomplete_reasons(source: &Source<'_>) -> Vec<String> {
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
        // The recording's totals (what was lost, whether saving stopped) are
        // written when the VM stops. Until then nothing says it is incomplete.
        Some(facts)
            if facts.complete != Some(true)
                && source.recording_open
                && facts.transport_loss.is_none()
                && facts.storage_loss.is_none() =>
        {
            reasons.push(STILL_SAVING.to_owned());
        }
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

/// Whether the run's guest looked like a cloud instance (the machine record in
/// `run.json` names a `cloud-` profile).
pub fn cloud_profile(directory: &Path) -> bool {
    std::fs::read(directory.join("run.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|run| {
            run.pointer("/machine/profile")
                .and_then(|profile| profile.as_str().map(|text| text.starts_with("cloud-")))
        })
        .unwrap_or(false)
}

/// The signal that ended the run's program and whether it dumped core, from
/// the run's `run.json` (`execution.root_exit`).
pub fn root_exit_signal(directory: &Path) -> Option<String> {
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).ok()?).ok()?;
    let status: antinomie_monitor_core::WaitStatus =
        serde_json::from_value(run.pointer("/execution/root_exit")?.clone()).ok()?;
    crash_text(&status)
}

/// The run status flags the guest reported, from the run's `run.json`
/// (`execution.flags`); `None` when the file has none.
pub fn execution_flags(directory: &Path) -> Option<u64> {
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).ok()?).ok()?;
    run.pointer("/execution/flags")?.as_u64()
}

/// The words for a fatal signal; `None` for a normal exit.
pub fn crash_text(status: &antinomie_monitor_core::WaitStatus) -> Option<String> {
    let antinomie_monitor_core::WaitStatus::Signaled {
        signal,
        core_dumped,
    } = status
    else {
        return None;
    };
    let name = match signal {
        4 => "SIGILL (illegal instruction)",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS (bus error)",
        8 => "SIGFPE (arithmetic error)",
        9 => "SIGKILL",
        11 => "SIGSEGV (segmentation fault)",
        15 => "SIGTERM",
        31 => "SIGSYS (bad system call)",
        other => return Some(format!("signal {other}")),
    };
    Some(if *core_dumped {
        format!("{name}, core dumped")
    } else {
        name.to_owned()
    })
}

#[cfg(test)]
pub mod reason_tests {
    use super::*;

    fn source() -> Source<'static> {
        Source {
            scan_complete: true,
            stable: true,
            issues: 0,
            facts: None,
            run_finished: true,
            recording_open: false,
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

    #[test]
    fn a_recording_the_vm_still_holds_is_being_saved_not_incomplete() {
        // The manifest has no totals yet: no health, no completion flag.
        let unsaved = antinomie_monitor_core::recording::RunFilterFacts::default();
        let reasons = incomplete_reasons(&Source {
            facts: Some(&unsaved),
            recording_open: true,
            ..source()
        });
        assert_eq!(reasons, [STILL_SAVING]);
        // The same manifest of a run whose VM is gone says what it always did.
        let reasons = incomplete_reasons(&Source {
            facts: Some(&unsaved),
            ..source()
        });
        assert!(reasons[0].contains("retained prefix"), "{reasons:?}");
        // Saved totals that show a loss are still reported as a loss.
        let lossy = antinomie_monitor_core::recording::RunFilterFacts {
            complete: Some(false),
            transport_loss: Some(3),
            storage_loss: Some(0),
            ..Default::default()
        };
        let reasons = incomplete_reasons(&Source {
            facts: Some(&lossy),
            recording_open: true,
            ..source()
        });
        assert!(reasons[0].contains("3 dropped"), "{reasons:?}");
    }
}
