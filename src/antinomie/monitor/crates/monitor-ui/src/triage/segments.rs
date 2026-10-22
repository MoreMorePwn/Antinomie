// SPDX-License-Identifier: GPL-3.0-only
//! A run read whole: its recording segments, its launch and the guest's names.
//!
//! A transport reconnect seals a run's recording and continues the same run in
//! a new segment under the new boot. Triage reads every segment, oldest first,
//! with one file index, one process tree and one detection journal, so a file
//! written before the reconnect and deleted after it is one story; the
//! boundary is marked where a story crosses it.
use super::*;
use antinomie_monitor_core::recording::{LaunchRecord, Recording, RunFilterFacts, RunSegment};

/// The segments of the run in `directory`, oldest first, ending with it. A
/// run without an identity (a test or an old page) is just its directory.
pub(super) fn run_segments(directory: &Path, request: &ScanRequest) -> Vec<RunSegment> {
    let single = || {
        vec![RunSegment {
            directory: directory.to_path_buf(),
            boot_id: request
                .identity
                .as_ref()
                .map(|(_, boot, _)| boot.clone())
                .unwrap_or_default(),
        }]
    };
    let Some((vm, _, run)) = request
        .identity
        .as_ref()
        .filter(|_| request.root_cookie != 0)
    else {
        return single();
    };
    antinomie_monitor_core::recording::run_segments(directory, run, vm)
        .ok()
        .filter(|found| found.last().is_some_and(|last| last.directory == directory))
        .unwrap_or_else(single)
}

/// What the earlier segments add to the index stamp: a segment that changed
/// (it should not: it is sealed) is read again.
pub(super) fn segments_stamp(segments: &[RunSegment]) -> String {
    use std::os::unix::fs::MetadataExt;
    let mut stamp = String::new();
    for segment in segments.iter().rev().skip(1) {
        let raw = std::fs::metadata(segment.directory.join("telemetry.raw")).map_or_else(
            |_| "-".to_owned(),
            |meta| format!("{}.{}.{}", meta.len(), meta.mtime(), meta.ino()),
        );
        stamp.push_str(&format!("|segment {}={raw}", segment.directory.display()));
    }
    stamp
}

/// The run's saved facts over all its segments: identity checked in each,
/// the start, directory and hashing of the first, completeness of the newest
/// unless an earlier segment lost records.
pub(super) fn segment_facts(
    segments: &[RunSegment],
    request: &ScanRequest,
) -> Result<Option<RunFilterFacts>, String> {
    let Some((vm, _, run)) = request.identity.as_ref() else {
        return Ok(None);
    };
    let mut all = Vec::new();
    for segment in segments {
        all.push(antinomie_monitor_core::recording::run_filter_facts(
            &segment.directory,
            run,
            vm,
            &segment.boot_id,
        )?);
    }
    let Some(mut facts) = all.pop() else {
        return Ok(None);
    };
    if let Some(first) = all.first() {
        facts.started_ms = first.started_ms.or(facts.started_ms);
        facts.launch_cwd = first.launch_cwd.clone().or(facts.launch_cwd);
        facts.hashed_writes |= first.hashed_writes;
    }
    if all
        .iter()
        .any(|earlier| earlier.transport_loss != Some(0) || earlier.storage_loss != Some(0))
    {
        facts.complete = Some(false);
    }
    Ok(Some(facts))
}

/// [`walk_pages`] over every segment in order; `each` learns which segment a
/// page came from. Complete only when every segment was read to its end.
pub(super) fn walk_segments(
    recordings: &[Recording],
    cancel: &AtomicBool,
    mut each: impl FnMut(usize, &[InvocationSummary]) -> Result<(), String>,
) -> Result<(u64, bool, Vec<String>), String> {
    let (mut seen, mut issues) = (0u64, Vec::new());
    for (index, recording) in recordings.iter().enumerate() {
        let (count, complete, found) = walk_pages(recording, cancel, |page| each(index, page))?;
        seen += count;
        for issue in found {
            if issues.len() < 32 && !issues.contains(&issue) {
                issues.push(issue);
            }
        }
        if !complete {
            return Ok((seen, false, issues));
        }
    }
    Ok((seen, true, issues))
}

/// The guest's user and group names for this run: given (tests), or read from
/// the base its disk came from. `None` when they cannot be read; ids then stay
/// numeric.
pub(super) fn guest_names(
    directory: &Path,
    request: &ScanRequest,
) -> Option<Arc<antinomie_monitor_core::guest_names::GuestNames>> {
    if let Some(names) = &request.guest_names {
        return Some(Arc::clone(names));
    }
    let data_dir = request.data_dir.as_deref()?;
    let (vm, _, _) = request.identity.as_ref()?;
    antinomie_monitor_core::guest_names::for_run(data_dir, vm, directory)
        .ok()
        .flatten()
        .filter(|names| !names.is_empty())
}

/// Name the root task after the program the run launched: the kernel started
/// it without a traced execve, so no call names it. A later exec of the root
/// keeps its own name; the launched image stays first in its history.
pub(super) fn name_launched(
    nodes: &mut std::collections::BTreeMap<TaskKey, TaskNode>,
    launch: &LaunchRecord,
    root_cookie: u64,
) {
    let Some(path) = launch.path.as_ref().filter(|_| root_cookie != 0) else {
        return;
    };
    let node = nodes
        .entry(TaskKey {
            pid: launch.pid,
            cookie: root_cookie,
        })
        .or_insert_with(|| TaskNode {
            comm: "?".into(),
            ..TaskNode::default()
        });
    node.root = true;
    if node.exec_history.first() != Some(path) && node.exec_history.len() < 128 {
        node.exec_history.insert(0, path.clone());
    }
    if node.comm == "?" || node.comm.is_empty() {
        node.comm = path.clone();
        if let Some(argv) = &launch.argv {
            node.argv = argv.clone();
            node.command_line = Some(argv.join(" "));
            node.proctitle = Some(argv.clone());
        }
    }
}
