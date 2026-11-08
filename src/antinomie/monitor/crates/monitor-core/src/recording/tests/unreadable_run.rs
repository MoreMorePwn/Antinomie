// SPDX-License-Identifier: GPL-3.0-only
//! A saved run never vanishes from the history (ANT-T0415). The first case is
//! the shape of the real report: a check added later with Analyse more lives
//! only in the analysis sidecar, after the sections the run was saved with.
use super::*;
use crate::analysis::{AnalysisKind, AnalysisSelection, AnalysisState};

fn report(kinds: &[AnalysisKind]) -> crate::analysis::AnalysisReport {
    let selection = AnalysisSelection {
        enabled: true,
        checks: kinds.to_vec(),
        time_limit_minutes: 0,
        limits: Default::default(),
    };
    let mut report = crate::analysis::jobs::new_report("/tmp/sample", &selection);
    report.state = AnalysisState::Complete;
    report
}

fn location(root: &Path) -> VmLocations {
    VmLocations {
        vm_id: "vm".into(),
        disk_directory: root.join("disk"),
        recording_directory: root.to_path_buf(),
        recording_directories: vec![root.to_path_buf()],
    }
}

fn write_run(root: &Path, name: &str, analysis: &crate::analysis::AnalysisReport) -> PathBuf {
    let directory = root.join("runs").join(name);
    fs::create_dir_all(directory.join("analysis")).unwrap();
    let run = serde_json::json!({
        "id": name, "vm_id": "vm", "boot_id": "boot", "session_id": 0,
        "root_task_cookie": 7, "pid": 1, "request": ExecRequest::default(),
        "directory": directory, "terminal_eof": true, "state": "Stopped",
        "notes": [], "recording_error": null, "execution": null,
        "analysis": analysis,
    });
    fs::write(directory.join("run.json"), run.to_string()).unwrap();
    directory
}

fn tempdir(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-unreadable-{tag}-{}", storage::unique_id()));
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn a_check_added_later_only_in_the_sidecar_keeps_the_run_listed() {
    let root = tempdir("later");
    let saved = report(&[AnalysisKind::Metadata, AnalysisKind::Strings]);
    let directory = write_run(&root, "bpfdoor", &saved);
    let mut grown = report(&[
        AnalysisKind::Metadata,
        AnalysisKind::Strings,
        AnalysisKind::Disassembly,
    ]);
    grown.id = saved.id.clone();
    fs::write(
        directory.join("analysis/report.json"),
        serde_json::to_vec(&grown).unwrap(),
    )
    .unwrap();
    let listed = list_runs_read_only(&location(&root)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, "bpfdoor");
    assert_eq!(listed[0].analysis.as_ref().unwrap().sections.len(), 3);
    assert!(listed[0].notes.is_empty());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_sidecar_that_does_not_match_the_run_is_noted_not_a_reason_to_hide_it() {
    let root = tempdir("mismatch");
    let saved = report(&[AnalysisKind::Metadata, AnalysisKind::Strings]);
    let directory = write_run(&root, "odd", &saved);
    let mut other = report(&[AnalysisKind::Metadata]);
    other.id = saved.id.clone();
    fs::write(
        directory.join("analysis/report.json"),
        serde_json::to_vec(&other).unwrap(),
    )
    .unwrap();
    let listed = list_runs_read_only(&location(&root)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].analysis.as_ref().unwrap().sections.len(), 2);
    assert!(listed[0].notes[0].contains("does not match run"));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_run_record_that_cannot_be_read_is_listed_with_the_reason() {
    let root = tempdir("broken");
    write_run(&root, "good", &report(&[AnalysisKind::Metadata]));
    let broken = root.join("runs/broken");
    fs::create_dir_all(&broken).unwrap();
    fs::write(broken.join("run.json"), b"{ not json").unwrap();
    let huge = root.join("runs/huge");
    fs::create_dir_all(&huge).unwrap();
    fs::write(huge.join("run.json"), vec![b' '; 1024 * 1024 + 1]).unwrap();
    let listed = list_runs_read_only(&location(&root)).unwrap();
    assert_eq!(listed.len(), 3);
    for name in ["broken", "huge"] {
        let run = listed.iter().find(|run| run.id == name).unwrap();
        assert!(
            run.recording_error
                .as_ref()
                .unwrap()
                .starts_with("run record unreadable:")
        );
        assert_eq!(run.directory, root.canonicalize().unwrap().join("runs").join(name));
        assert!(!run.state.ended_normally());
    }
    // Listing wrote nothing into the damaged folders.
    assert_eq!(fs::read(broken.join("run.json")).unwrap(), b"{ not json");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_run_of_another_vm_is_still_not_listed() {
    let root = tempdir("other");
    let directory = write_run(&root, "theirs", &report(&[AnalysisKind::Metadata]));
    let text = fs::read_to_string(directory.join("run.json"))
        .unwrap()
        .replace("\"vm_id\":\"vm\"", "\"vm_id\":\"other\"");
    fs::write(directory.join("run.json"), text).unwrap();
    assert!(list_runs_read_only(&location(&root)).unwrap().is_empty());
    fs::remove_dir_all(&root).unwrap();
}
