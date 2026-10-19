// SPDX-License-Identifier: MIT
//! Deleting saved network captures and process cores.
//!
//! The recording folder is the only place anything is removed from, and only
//! at the places the recorder itself writes these items:
//! `boots/<boot>/network.pcap`, `boots/<boot>/network/<capture>.pcap`,
//! `core-captures/<id>`, `runs/<run>/core` and `core-dumps/<id>`. A path is
//! canonicalized, refused when it climbs with `..`, is a symbolic link or
//! resolves outside the folder, and must match one of those places. The
//! run records that name a removed item are updated so they read as deleted
//! rather than pointing at a file that is gone.
use crate::{RunArtifactState, RunArtifacts, network};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

/// Entries counted by [`measure`] before it stops.
const MEASURE_LIMIT: usize = 50_000;

/// What a deletion removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Removed {
    /// The item's own name: the capture or core identity.
    pub name: String,
    /// The boot recording the item belongs to, when its place names one.
    pub boot_id: Option<String>,
    /// The run whose on-exit core this was.
    pub run_id: Option<String>,
    /// The bytes of the pcap or core file the recording quota counted.
    pub counted: u64,
    /// Every byte removed, sidecars included.
    pub bytes: u64,
    /// Files and directories removed.
    pub entries: usize,
}

impl Removed {
    /// Give a deleted capture's bytes back to the boot's recording quota.
    pub(crate) fn release_network(&self, done: &mut u64, total: &mut u64) {
        *done = done.saturating_sub(self.counted);
        *total = total.saturating_sub(self.counted);
    }

    /// Give a deleted core's bytes back to the boot's recording quota; `run`
    /// is the on-exit owner's own count, when it is still tracked.
    pub(crate) fn release_core(&self, stored: &mut u64, run: Option<&mut u64>) {
        *stored = stored.saturating_sub(self.counted);
        if let Some(run) = run {
            *run = run.saturating_sub(self.counted);
        }
    }
}

/// What [`measure`] found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Measured {
    pub bytes: u64,
    pub entries: usize,
    /// The count stopped at a limit; the figures are lower bounds.
    pub truncated: bool,
}

/// The size of a file, or of a directory tree, without following symbolic
/// links.
pub fn measure(path: &Path) -> Measured {
    let mut found = Measured::default();
    let mut stack = vec![path.to_path_buf()];
    while let Some(next) = stack.pop() {
        if found.entries >= MEASURE_LIMIT {
            found.truncated = true;
            break;
        }
        let Ok(metadata) = fs::symlink_metadata(&next) else {
            continue;
        };
        found.entries += 1;
        if metadata.is_dir() {
            for entry in fs::read_dir(&next).into_iter().flatten().flatten() {
                stack.push(entry.path());
            }
        } else {
            found.bytes = found.bytes.saturating_add(metadata.len());
        }
    }
    found
}

/// `path` inside one of `roots`: the canonical item and its components
/// relative to that root.
fn confine(roots: &[PathBuf], path: &Path) -> Result<(PathBuf, Vec<String>), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("the path is not a plain absolute path".into());
    }
    let name = path.file_name().ok_or("the path has no file name")?;
    let parent = path.parent().ok_or("the path has no folder")?;
    let parent =
        fs::canonicalize(parent).map_err(|error| format!("{}: {error}", path.display()))?;
    let item = parent.join(name);
    match fs::symlink_metadata(&item) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "{} is a symbolic link; it is not deleted",
                item.display()
            ));
        }
        Ok(_) => {}
        Err(error) => return Err(format!("{}: {error}", item.display())),
    }
    for root in roots {
        let Ok(root) = fs::canonicalize(root) else {
            continue;
        };
        if let Ok(relative) = item.strip_prefix(&root) {
            let parts = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect();
            return Ok((item, parts));
        }
    }
    Err(format!(
        "{} is outside this VM's recording folders",
        path.display()
    ))
}

/// Remove one entry; a symbolic link is unlinked, never followed.
fn remove_entry(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
    .map_err(|error| format!("{}: {error}", path.display()))
}

/// Rewrite every run record of `roots` for which `edit` returns true.
fn update_runs(roots: &[PathBuf], edit: impl Fn(&mut RunArtifacts) -> bool) -> Result<(), String> {
    let mut failures = Vec::new();
    for root in roots {
        for run in fs::read_dir(root.join("runs"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let directory = run.path();
            let Ok(Some(mut artifacts)) = RunArtifacts::load(&directory) else {
                continue;
            };
            if edit(&mut artifacts)
                && let Err(error) =
                    crate::storage::atomic_json(&directory.join("artifacts.json"), &artifacts)
            {
                failures.push(format!("{}: {error}", directory.display()));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the item was deleted but its run records could not be updated: {}",
            failures.join("; ")
        ))
    }
}

fn same_file(recorded: &Path, item: &Path) -> bool {
    recorded == item
        || (recorded.file_name() == item.file_name()
            && recorded
                .parent()
                .and_then(|parent| fs::canonicalize(parent).ok())
                == item.parent().map(Path::to_path_buf))
}

/// Delete a network capture: its pcap, then every `<capture>.*` file beside it
/// (the summary, the `.metadata` annotation folder and any derived index),
/// and drop it from the runs that listed it.
pub(crate) fn remove_network_capture(roots: &[PathBuf], file: &Path) -> Result<Removed, String> {
    let (item, parts) = confine(roots, file)?;
    let (boot, stem) = match parts.as_slice() {
        [boots, boot, name] if boots == "boots" && name == network::PCAP_FILE => {
            (boot.clone(), "network".to_owned())
        }
        [boots, boot, folder, name] if boots == "boots" && folder == network::CAPTURE_DIR => {
            match name.strip_suffix(".pcap").filter(|stem| !stem.is_empty()) {
                Some(stem) => (boot.clone(), stem.to_owned()),
                None => return Err("this is not a network capture".into()),
            }
        }
        _ => return Err("this is not a network capture of the recording".into()),
    };
    let metadata = fs::symlink_metadata(&item).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("the capture is not a regular file".into());
    }
    let folder = item.parent().ok_or("the capture has no folder")?;
    let prefix = format!("{stem}.");
    let mut siblings: Vec<PathBuf> = fs::read_dir(folder)
        .map_err(|error| format!("{}: {error}", folder.display()))?
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .map(|entry| entry.path())
        .filter(|path| *path != item)
        .collect();
    siblings.sort();
    let mut removed = Removed {
        name: stem,
        boot_id: Some(boot),
        counted: metadata.len(),
        bytes: metadata.len(),
        entries: 1,
        ..Removed::default()
    };
    remove_entry(&item)?;
    let mut failures = Vec::new();
    for sibling in siblings {
        let bytes = measure(&sibling).bytes;
        match remove_entry(&sibling) {
            Ok(()) => {
                removed.bytes = removed.bytes.saturating_add(bytes);
                removed.entries += 1;
            }
            Err(error) => failures.push(error),
        }
    }
    update_runs(roots, |artifacts| {
        let before = artifacts.network_captures.len();
        artifacts
            .network_captures
            .retain(|recorded| !same_file(recorded, &item));
        let changed = artifacts.network_captures.len() != before;
        if changed
            && artifacts.network_captures.is_empty()
            && !artifacts.network_state.in_progress()
            && artifacts.network_state != RunArtifactState::Disabled
        {
            artifacts.network_deleted = true;
        }
        changed
    })?;
    if failures.is_empty() {
        Ok(removed)
    } else {
        Err(format!(
            "the capture was deleted but some related files remain: {}",
            failures.join("; ")
        ))
    }
}

/// Delete a process core's directory, whichever kind it is, without touching
/// an imported core's original file, and mark a run's core deleted.
pub(crate) fn remove_process_core(roots: &[PathBuf], directory: &Path) -> Result<Removed, String> {
    let (item, parts) = confine(roots, directory)?;
    let (name, boot_id, run_id) = match parts.as_slice() {
        [folder, id] if folder == "core-captures" => (
            id.clone(),
            crate::core_capture::load(&item)
                .ok()
                .map(|core| core.boot_id),
            None,
        ),
        [folder, run, core] if folder == "runs" && core == "core" => {
            let artifacts = item
                .parent()
                .and_then(|run| RunArtifacts::load(run).ok().flatten());
            (
                run.clone(),
                artifacts.map(|artifacts| artifacts.boot_id),
                Some(run.clone()),
            )
        }
        [folder, id] if folder == "core-dumps" => (id.clone(), None, None),
        _ => return Err("this is not a core of the recording".into()),
    };
    let metadata = fs::symlink_metadata(&item).map_err(|error| error.to_string())?;
    if !metadata.is_dir() {
        return Err("the core is not a directory".into());
    }
    let counted = if run_id.is_some() || parts[0] == "core-captures" {
        fs::symlink_metadata(item.join("process.elf"))
            .ok()
            .filter(fs::Metadata::is_file)
            .map_or(0, |elf| elf.len())
    } else {
        0
    };
    let measured = measure(&item);
    remove_entry(&item)?;
    if run_id.is_some()
        && let Some(run) = item.parent()
        && let Ok(Some(mut artifacts)) = RunArtifacts::load(run)
        && !artifacts.core_state.in_progress()
        && artifacts.core_state != RunArtifactState::Disabled
    {
        artifacts.core_dump = None;
        artifacts.core_state = RunArtifactState::Disabled;
        artifacts.core_deleted = true;
        crate::storage::atomic_json(&run.join("artifacts.json"), &artifacts).map_err(|error| {
            format!("the core was deleted but its run record could not be updated: {error}")
        })?;
    }
    Ok(Removed {
        name,
        boot_id,
        run_id,
        counted,
        bytes: measured.bytes,
        entries: measured.entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{atomic_json, unique_id};

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!("ant-evidence-delete-{}", unique_id()));
        fs::create_dir_all(&root).unwrap();
        fs::canonicalize(root).unwrap()
    }

    fn capture(root: &Path, boot: &str, id: &str) -> PathBuf {
        let dir = root.join("boots").join(boot).join("network");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{id}.pcap"));
        fs::write(&file, vec![1u8; 100]).unwrap();
        fs::write(dir.join(format!("{id}.json")), b"{}").unwrap();
        fs::create_dir_all(dir.join(format!("{id}.metadata"))).unwrap();
        fs::write(dir.join(format!("{id}.metadata/annotation.json")), b"{}").unwrap();
        fs::write(dir.join(format!("{id}.pcap.idx")), b"idx").unwrap();
        // A neighbour that must stay.
        fs::write(dir.join(format!("{id}x.pcap")), b"other").unwrap();
        file
    }

    fn run(root: &Path, id: &str, captures: Vec<PathBuf>) -> PathBuf {
        let dir = root.join("runs").join(id);
        fs::create_dir_all(&dir).unwrap();
        atomic_json(
            &dir.join("artifacts.json"),
            &RunArtifacts {
                run_id: id.into(),
                vm_id: "vm".into(),
                boot_id: "b1".into(),
                network_captures: captures,
                network_state: RunArtifactState::Complete,
                core_dump: Some(dir.join("core/process.elf")),
                core_state: RunArtifactState::Complete,
                ..RunArtifacts::default()
            },
        )
        .unwrap();
        dir
    }

    #[test]
    fn a_capture_goes_with_its_sidecars_and_its_runs_read_it_as_deleted() {
        let root = temp_root();
        let file = capture(&root, "b1", "abc");
        let run_dir = run(&root, "r1", vec![file.clone()]);
        let removed = remove_network_capture(std::slice::from_ref(&root), &file).unwrap();
        let dir = file.parent().unwrap();
        assert!(!file.exists());
        for name in ["abc.json", "abc.metadata", "abc.pcap.idx"] {
            assert!(!dir.join(name).exists(), "{name}");
        }
        assert!(dir.join("abcx.pcap").exists());
        assert_eq!(removed.counted, 100);
        assert_eq!(removed.bytes, 100 + 2 + 2 + 3);
        assert_eq!(removed.boot_id.as_deref(), Some("b1"));
        let artifacts = RunArtifacts::load(&run_dir).unwrap().unwrap();
        assert!(artifacts.network_captures.is_empty());
        assert_eq!(artifacts.network_state, RunArtifactState::Complete);
        assert!(artifacts.network_deleted);
        assert_eq!(artifacts.network_label(), "Deleted");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_whole_boot_capture_is_deleted_without_the_boots_other_captures() {
        let root = temp_root();
        let kept = capture(&root, "b1", "abc");
        let whole = root.join("boots/b1/network.pcap");
        fs::write(&whole, b"pcap").unwrap();
        fs::create_dir_all(root.join("boots/b1/network.metadata")).unwrap();
        let removed = remove_network_capture(std::slice::from_ref(&root), &whole).unwrap();
        assert_eq!(removed.name, "network");
        assert!(!whole.exists() && !root.join("boots/b1/network.metadata").exists());
        assert!(kept.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deleting_frees_the_recording_quota() {
        let removed = Removed {
            counted: 100,
            ..Removed::default()
        };
        let (mut done, mut total) = (250, 300);
        removed.release_network(&mut done, &mut total);
        assert_eq!((done, total), (150, 200));
        let (mut stored, mut run) = (150, 40);
        removed.release_core(&mut stored, Some(&mut run));
        assert_eq!((stored, run), (50, 0));
    }

    #[test]
    fn cores_of_every_kind_are_deleted_and_a_runs_core_reads_as_deleted() {
        let root = temp_root();
        let manual = root.join("core-captures/m1");
        let imported = root.join("core-dumps/i1");
        let run_dir = run(&root, "r1", vec![]);
        let on_exit = run_dir.join("core");
        for dir in [&manual, &imported, &on_exit] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join("process.elf"), vec![0u8; 64]).unwrap();
            fs::write(dir.join("metadata.json"), b"{}").unwrap();
        }
        let roots = std::slice::from_ref(&root);
        let removed = remove_process_core(roots, &on_exit).unwrap();
        assert_eq!(
            (removed.counted, removed.run_id.as_deref()),
            (64, Some("r1"))
        );
        assert_eq!(removed.boot_id.as_deref(), Some("b1"));
        let artifacts = RunArtifacts::load(&run_dir).unwrap().unwrap();
        assert_eq!(artifacts.core_state, RunArtifactState::Disabled);
        assert!(artifacts.core_deleted);
        assert_eq!(artifacts.core_label(), "Deleted");
        assert_eq!(artifacts.core_dump, None);
        assert_eq!(remove_process_core(roots, &manual).unwrap().counted, 64);
        assert_eq!(remove_process_core(roots, &imported).unwrap().counted, 0);
        assert!(!manual.exists() && !imported.exists() && !on_exit.exists());
        assert!(run_dir.join("artifacts.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nothing_outside_the_recording_folders_or_its_layout_is_deleted() {
        let root = temp_root();
        let outside = temp_root();
        let file = capture(&root, "b1", "abc");
        let roots = std::slice::from_ref(&root);
        let traversal = root.join("boots/b1/network/../network/abc.pcap");
        assert!(remove_network_capture(roots, &traversal).is_err());
        let foreign = capture(&outside, "b1", "zzz");
        assert!(
            remove_network_capture(roots, &foreign)
                .unwrap_err()
                .contains("outside")
        );
        assert!(foreign.exists());
        let telemetry = root.join("runs/r1/telemetry.raw");
        fs::create_dir_all(telemetry.parent().unwrap()).unwrap();
        fs::write(&telemetry, b"keep").unwrap();
        assert!(remove_network_capture(roots, &telemetry).is_err());
        assert!(remove_process_core(roots, &root.join("runs/r1")).is_err());
        assert!(telemetry.exists() && file.exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn symbolic_links_are_refused_and_never_followed_out_of_the_folder() {
        use std::os::unix::fs::symlink;
        let root = temp_root();
        let outside = temp_root();
        let victim = outside.join("victim.pcap");
        fs::write(&victim, b"precious").unwrap();
        let roots = std::slice::from_ref(&root);
        let dir = root.join("boots/b1/network");
        fs::create_dir_all(&dir).unwrap();
        symlink(&victim, dir.join("link.pcap")).unwrap();
        assert!(
            remove_network_capture(roots, &dir.join("link.pcap"))
                .unwrap_err()
                .contains("symbolic link")
        );
        symlink(&outside, root.join("boots/b2")).unwrap();
        fs::create_dir_all(outside.join("network")).unwrap();
        fs::write(outside.join("network/x.pcap"), b"precious").unwrap();
        assert!(remove_network_capture(roots, &root.join("boots/b2/network/x.pcap")).is_err());
        fs::create_dir_all(root.join("core-captures")).unwrap();
        symlink(&outside, root.join("core-captures/m1")).unwrap();
        assert!(remove_process_core(roots, &root.join("core-captures/m1")).is_err());
        let core = root.join("core-dumps/i1");
        fs::create_dir_all(&core).unwrap();
        symlink(&victim, core.join("source")).unwrap();
        remove_process_core(roots, &core).unwrap();
        assert!(!core.exists());
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert!(outside.join("network/x.pcap").exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    /// The `RunArtifacts` and `RunArtifactState` of 0.6.2, byte for byte.
    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum OldState {
        Disabled,
        WaitingForTreeExit,
        WaitingForRootExit,
        Recording,
        Queued,
        InProgress,
        Complete,
        Partial,
        Interrupted,
        Failed,
    }

    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct OldArtifacts {
        run_id: String,
        vm_id: String,
        boot_id: String,
        network_captures: Vec<PathBuf>,
        network_state: OldState,
        memory_dump: Option<PathBuf>,
        memory_state: OldState,
        core_dump: Option<PathBuf>,
        core_state: OldState,
        issues: Vec<String>,
    }

    #[test]
    fn a_record_written_after_a_delete_still_parses_as_0_6_2_and_new_code_says_deleted() {
        let root = temp_root();
        let file = capture(&root, "b1", "abc");
        let run_dir = run(&root, "r1", vec![file.clone()]);
        fs::create_dir_all(run_dir.join("core")).unwrap();
        fs::write(run_dir.join("core/process.elf"), b"elf").unwrap();
        let roots = std::slice::from_ref(&root);
        remove_network_capture(roots, &file).unwrap();
        remove_process_core(roots, &run_dir.join("core")).unwrap();
        let text = fs::read_to_string(run_dir.join("artifacts.json")).unwrap();
        let old: OldArtifacts = serde_json::from_str(&text).unwrap();
        assert!(old.network_captures.is_empty());
        assert_eq!(old.network_state, OldState::Complete);
        assert_eq!(old.core_state, OldState::Disabled);
        assert_eq!(old.core_dump, None);
        let new = RunArtifacts::load(&run_dir).unwrap().unwrap();
        assert_eq!(
            (new.network_label(), new.core_label()),
            ("Deleted", "Deleted")
        );
        // A record that never saw a delete writes neither field.
        let fresh = serde_json::to_string(&RunArtifacts::default()).unwrap();
        assert!(!fresh.contains("deleted"), "{fresh}");
        fs::remove_dir_all(root).unwrap();
    }
}
