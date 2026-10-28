// SPDX-License-Identifier: GPL-3.0-only
//! Looking up the earlier bytes of the files a run changed on the run's
//! starting disk (see `antinomie_monitor_core::file_before`). Only the files
//! the run wrote to or changed are asked, up to a bound; each answer is a
//! small sandboxed read of the disk's inode and size, and the bytes
//! themselves are read later, on demand.
use super::{Activity, Earlier};
use antinomie_monitor_core::file_before::{Before, Resolver, Wanted};
use antinomie_monitor_core::file_before_store::Writer;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Files asked at most per run; the rest show "not looked up".
pub(in crate::triage) const LOOKUP_LIMIT: usize = 300;

/// Ask the starting disk about the changed files of `activity`. `segments`
/// are the run's recording folders, oldest first; `executable` serves the
/// disk reader (`None`: this program). With `copy`, the earlier bytes are
/// read from the starting disk only and added to the boot's recording.
pub(in crate::triage) fn resolve(
    activity: &mut Activity,
    segments: &[(PathBuf, String)],
    executable: Option<PathBuf>,
    copy: Option<&Mutex<Writer>>,
) {
    let mut resolver = Resolver::new(segments, executable);
    if copy.is_some() {
        resolver = resolver.disk_only();
    }
    let mut asked = 0;
    for file in &mut activity.files {
        let wrote = file.writes.tally.kept + file.writes.tally.skipped() > 0;
        if !(wrote || file.changed()) || file.failed_only {
            continue;
        }
        if asked >= LOOKUP_LIMIT {
            file.earlier = Some(Earlier {
                before: Before::Unavailable(format!(
                    "not looked up: only the first {LOOKUP_LIMIT} changed files are"
                )),
                file: None,
            });
            continue;
        }
        asked += 1;
        let (before, source) = resolver.resolve(&Wanted {
            path: &file.path,
            names: &file.names,
            key: file.identity,
            created: file.created,
            first_segment: file.first_segment,
            last_segment: file.last_segment,
        });
        if let Some(copy) = copy
            && let Ok(mut writer) = copy.lock()
        {
            writer.record(
                &file.path,
                &file.names,
                file.identity,
                &before,
                source.as_ref(),
            );
        }
        file.earlier = Some(Earlier {
            before,
            file: source,
        });
    }
}

/// One line for the window: where the file's earlier bytes stand.
pub(super) fn describe(earlier: &Earlier) -> String {
    use antinomie_monitor_core::byte_size::file_size;
    match &earlier.before {
        Before::Created => {
            "Earlier bytes: none, the run created this file (it started empty)".into()
        }
        Before::OnDisk { size, exact } => format!(
            "Earlier bytes: {} on the starting disk, read when asked{}",
            file_size(*size),
            if *exact {
                " (the file's inode was checked against the disk)"
            } else {
                " (matched by path only: the guest recorded no inode)"
            }
        ),
        Before::TooLarge(size) => format!(
            "Earlier bytes: not offered, the file was {} on the starting disk (limit {})",
            file_size(*size),
            file_size(antinomie_monitor_core::file_before::SIZE_CAP)
        ),
        Before::Recorded { size, exact } => format!(
            "Earlier bytes: {} kept in this recording{}",
            file_size(*size),
            if *exact {
                " (the file's inode was checked against the disk)"
            } else {
                " (matched by path only: the guest recorded no inode)"
            }
        ),
        Before::NotCopied { size, sha256, why } => format!(
            "Earlier bytes: not captured, the file was {} ({why}){}",
            file_size(*size),
            sha256
                .as_ref()
                .map(|sha| format!("; SHA-256 {sha}"))
                .unwrap_or_default()
        ),
        Before::Elsewhere(why) => format!("Earlier bytes: not on the starting disk: {why}"),
        Before::Unavailable(why) => format!("Earlier bytes: unavailable: {why}"),
    }
}

/// Copy the earlier bytes of the files a finished boot's runs changed into
/// the boot's recording (see `antinomie_monitor_core::file_before_store`).
/// The core calls this once per boot, before the sealed layer is merged; it
/// reads each run of the boot as the window would and asks the starting disk
/// about every changed file.
pub fn copy_boot(job: &antinomie_monitor_core::file_before_store::Job) -> Result<(), String> {
    use crate::triage::{archive_scan::scan_archive_query, ScanRequest};
    use std::sync::{atomic::AtomicBool, Arc};
    let writer = Arc::new(Mutex::new(Writer::open(
        &job.boot_dir,
        &job.boot_id,
        antinomie_monitor_core::file_before_store::limits(),
    )));
    // The boot's runs: in its own folder or, as the app lays them out, in the
    // recording's `runs` folder next to `boots`.
    let mut folders = vec![job.boot_dir.join("runs")];
    if let Some(root) = job.boot_dir.parent().and_then(Path::parent) {
        folders.push(root.join("runs"));
    }
    let mut runs: Vec<PathBuf> = folders
        .iter()
        .filter_map(|folder| std::fs::read_dir(folder).ok())
        .flat_map(|dir| dir.filter_map(Result::ok).map(|entry| entry.path()))
        .collect();
    runs.sort();
    let (mut complete, mut note) = (true, None);
    let cancel = Arc::new(AtomicBool::new(false));
    for run_dir in runs {
        let summary = std::fs::read(run_dir.join("run.json"))
            .ok()
            .and_then(|bytes| {
                serde_json::from_slice::<antinomie_monitor_core::RunSummary>(&bytes).ok()
            });
        let Some(summary) = summary else {
            complete = false;
            note = Some(format!("{} has no readable run record", run_dir.display()));
            continue;
        };
        if summary.boot_id != job.boot_id {
            continue;
        }
        let request = ScanRequest {
            root_cookie: summary.root_task_cookie,
            clock_anchor: summary.clock_anchor,
            started_ms: summary.started_ms,
            run_finished: true,
            identity: Some((
                summary.vm_id.clone(),
                summary.boot_id.clone(),
                summary.id.clone(),
            )),
            before_copy: Some(Arc::clone(&writer)),
            ..Default::default()
        };
        if let Err(why) = scan_archive_query(&run_dir, None, false, &cancel, &request) {
            complete = false;
            note = Some(format!("{}: {why}", run_dir.display()));
        }
    }
    let mut writer = writer.lock().map_err(|_| "copy state".to_owned())?;
    writer.finish(complete, note)
}
