// SPDX-License-Identifier: MIT
//! The recording segments of one run.
//!
//! A transport reconnect seals a run's recording and continues the same run
//! (same id) in a new boot timeline: `<rec>/runs/<id>` holds the first segment
//! and `<rec>/boots/<boot>/runs/<id>` each later one. The boot folder of a
//! continuation says which boot it continues (`resume-boundary.json`,
//! `source_boot_id`, no `snapshot_id`). A snapshot restore starts a new run
//! with its own id and is never chained here.
use super::*;
use std::collections::BTreeMap;

/// Boot folders looked at for one run.
const BOOTS_MAX_COUNT: usize = 4096;
/// Segments followed back from the newest.
const SEGMENTS_MAX_COUNT: usize = 256;

/// One recording segment of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSegment {
    pub directory: PathBuf,
    pub boot_id: String,
}

/// The boot a reconnected boot continues, from its boundary file; `None` for
/// a fresh boot or a snapshot restore.
fn continued_boot(root: &Path, boot_id: &str) -> Option<String> {
    let path = root
        .join("boots")
        .join(boot_id)
        .join("resume-boundary.json");
    let file = archive_io::open_regular(root, &path).ok()?;
    let mut encoded = Vec::new();
    file.take(64 * 1024).read_to_end(&mut encoded).ok()?;
    let boundary: serde_json::Value = serde_json::from_slice(&encoded).ok()?;
    if !boundary
        .get("snapshot_id")
        .is_none_or(serde_json::Value::is_null)
        || boundary.get("boot_id").and_then(serde_json::Value::as_str) != Some(boot_id)
    {
        return None;
    }
    boundary
        .get("source_boot_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// The recording folder `<rec>` a run segment directory belongs to.
fn recording_root(directory: &Path) -> Option<PathBuf> {
    let runs = directory.parent()?;
    if runs.file_name()? != "runs" {
        return None;
    }
    let above = runs.parent()?;
    let boots = above.parent()?;
    if boots.file_name().is_some_and(|name| name == "boots") {
        return boots.parent().map(Path::to_path_buf);
    }
    Some(above.to_path_buf())
}

/// Every recording segment of the run recorded in `directory` (any of its
/// segments, usually the newest), oldest first and ending with the newest
/// one this chain reaches. A run that never reconnected has one: itself.
///
/// | Argument | Meaning |
/// |---|---|
/// | `directory` | A segment of the run: `<rec>/runs/<id>` or `<rec>/boots/<boot>/runs/<id>` |
/// | `run_id`, `vm_id` | The run's identity, which every segment must carry |
pub fn run_segments(
    directory: &Path,
    run_id: &str,
    vm_id: &str,
) -> Result<Vec<RunSegment>, RecordingError> {
    let directory = fs::canonicalize(directory)?;
    let root = recording_root(&directory).ok_or(RecordingError::Limit(
        "run directory is not inside a VM recording folder",
    ))?;
    let current = saved_run(&root, &directory, vm_id)?
        .filter(|run| run.id == run_id)
        .ok_or(RecordingError::Limit(
            "run record does not match its identity",
        ))?;
    let mut found = vec![RunSegment {
        directory: directory.clone(),
        boot_id: current.boot_id.clone(),
    }];
    if current.segments() == 1 {
        return Ok(found);
    }
    // Every record of this run, by the boot it was recorded in.
    let mut by_boot = BTreeMap::new();
    let mut candidates = vec![root.join("runs").join(run_id)];
    if let Ok(boots) = fs::read_dir(root.join("boots")) {
        for boot in boots.flatten().take(BOOTS_MAX_COUNT) {
            candidates.push(boot.path().join("runs").join(run_id));
        }
    }
    for candidate in candidates {
        if candidate == directory || !candidate.is_dir() {
            continue;
        }
        if let Ok(Some(run)) = saved_run(&root, &candidate, vm_id)
            && run.id == run_id
        {
            by_boot.insert(run.boot_id.clone(), candidate);
        }
    }
    let mut boot = current.boot_id;
    while found.len() < SEGMENTS_MAX_COUNT {
        let Some(previous) = continued_boot(&root, &boot) else {
            break;
        };
        let Some(segment) = by_boot.remove(&previous) else {
            break;
        };
        found.push(RunSegment {
            directory: segment,
            boot_id: previous.clone(),
        });
        boot = previous;
    }
    found.reverse();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_run(directory: &Path, run: &str, boot: &str, notes: &[&str]) {
        fs::create_dir_all(directory).unwrap();
        let summary = serde_json::json!({
            "id": run, "vm_id": "vm", "boot_id": boot, "session_id": 1,
            "root_task_cookie": 9, "pid": 1, "request": ExecRequest::default(),
            "directory": directory, "terminal_eof": false, "state": "Finished",
            "recording_error": null, "notes": notes,
        });
        fs::write(directory.join("run.json"), summary.to_string()).unwrap();
    }

    fn boundary(root: &Path, boot: &str, source: &str, snapshot: Option<&str>) {
        let directory = root.join("boots").join(boot);
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("resume-boundary.json"),
            serde_json::json!({"format":1,"snapshot_id":snapshot,"source_boot_id":source,"boot_id":boot})
                .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn a_reconnected_run_reads_its_segments_in_order_and_a_restore_is_not_one() {
        let root = std::env::temp_dir().join(format!("ant-segments-{}", storage::unique_id()));
        let note = |segment: u32| {
            format!(
                "Recording continues after a transport reconnect (recording segment {segment}); the earlier part is kept in the recording of boot x"
            )
        };
        let (two, three) = (note(2), note(3));
        write_run(&root.join("runs/run"), "run", "boot-a", &[]);
        write_run(
            &root.join("boots/boot-b/runs/run"),
            "run",
            "boot-b",
            &[&two],
        );
        write_run(
            &root.join("boots/boot-c/runs/run"),
            "run",
            "boot-c",
            &[&two, &three],
        );
        boundary(&root, "boot-b", "boot-a", None);
        boundary(&root, "boot-c", "boot-b", None);
        // A restored snapshot continues the run under a new id: not a segment.
        write_run(
            &root.join("boots/boot-d/runs/other"),
            "other",
            "boot-d",
            &[],
        );
        boundary(&root, "boot-d", "boot-c", Some("snap"));
        let segments = run_segments(&root.join("boots/boot-c/runs/run"), "run", "vm").unwrap();
        let boots: Vec<_> = segments.iter().map(|s| s.boot_id.as_str()).collect();
        assert_eq!(boots, ["boot-a", "boot-b", "boot-c"]);
        assert!(segments[0].directory.ends_with("runs/run"));
        // From the middle, the chain ends there.
        let middle = run_segments(&root.join("boots/boot-b/runs/run"), "run", "vm").unwrap();
        assert_eq!(middle.len(), 2);
        // A single segment is just itself; a wrong identity is refused.
        assert_eq!(
            run_segments(&root.join("runs/run"), "run", "vm")
                .unwrap()
                .len(),
            1
        );
        assert!(run_segments(&root.join("runs/run"), "other", "vm").is_err());
        // A missing link ends the chain instead of guessing.
        fs::remove_file(root.join("boots/boot-b/resume-boundary.json")).unwrap();
        let cut = run_segments(&root.join("boots/boot-c/runs/run"), "run", "vm").unwrap();
        assert_eq!(cut.len(), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
