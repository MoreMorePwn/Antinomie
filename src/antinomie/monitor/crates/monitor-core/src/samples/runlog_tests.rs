// SPDX-License-Identifier: GPL-3.0-only
//! The entries a run writes to its sample's log: one test per kind.
use super::*;
use crate::run_digest::{Lineage, LineageFile, RunDigest};
use std::{fs, path::PathBuf};

fn setup(name: &str) -> (PathBuf, Library, String, RunLog) {
    let root =
        std::env::temp_dir().join(format!("ant-runlog-{name}-{}", crate::storage::unique_id()));
    fs::create_dir_all(&root).unwrap();
    let mut library = Library::open(&root).unwrap();
    let sha = library
        .add_bytes(
            b"#!/bin/sh\necho run\n",
            NewSample {
                name: "run.sh".into(),
                ..NewSample::default()
            },
        )
        .unwrap()
        .sha256;
    let sample = SampleRef {
        sha256: sha.clone(),
        name: "run.sh".into(),
    };
    let log = RunLog::new(&root, &sample, "r9", "vm-one");
    (root, library, sha, log)
}

fn kinds(library: &Library, sha: &str) -> Vec<(String, String, String)> {
    library
        .custody_entries(sha)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.kind, entry.by, entry.detail))
        .collect()
}

#[test]
fn a_run_start_names_the_vm_and_its_setup() {
    let (root, library, sha, log) = setup("start");
    log.started("base Debian, device profile Fair, network Isolated, booted from the disk".into());
    let entries = kinds(&library, &sha);
    let (kind, by, detail) = entries.last().unwrap();
    assert_eq!((kind.as_str(), by.as_str()), ("run_started", "app"));
    assert!(detail.contains("vm-one") && detail.contains("device profile Fair"));
    assert!(library.custody_check(&sha).unwrap().ok());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn terminal_input_keeps_a_byte_count_per_line_and_never_the_text() {
    let (root, library, sha, mut log) = setup("typed");
    log.typed(b"pass");
    log.typed(b"word123\r");
    log.typed(b"ls");
    log.flush_typed();
    log.flush_typed();
    let entries = kinds(&library, &sha);
    let typed: Vec<_> = entries
        .iter()
        .filter(|(kind, ..)| kind == "terminal_input")
        .collect();
    assert_eq!(typed.len(), 2);
    assert!(typed[0].2.contains("\"bytes\":12"), "{}", typed[0].2);
    assert!(typed[1].2.contains("\"bytes\":2"));
    assert!(typed[0].1 == "analyst");
    let all: String = entries.iter().map(|entry| entry.2.clone()).collect();
    assert!(!all.contains("word123") && !all.contains("pass"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn analyst_actions_each_make_an_entry_by_the_analyst() {
    let (root, library, sha, mut log) = setup("actions");
    log.typed(b"id");
    log.action(ActionKind::Kill, "Stop: SIGTERM issued to the run");
    log.action(ActionKind::SnapshotRestore, "snapshot s1 restored");
    log.action(ActionKind::NetworkChange, "Isolated to NAT");
    log.action(ActionKind::ClockMove, "+2 days");
    let entries = kinds(&library, &sha);
    let tail: Vec<_> = entries
        .iter()
        .skip_while(|(kind, ..)| kind != "terminal_input")
        .collect();
    // Pending typing is written before the action it preceded.
    assert_eq!(tail.len(), 5);
    assert_eq!(tail[0].0, "terminal_input");
    for entry in &tail[1..] {
        assert_eq!((entry.0.as_str(), entry.1.as_str()), ("action", "analyst"));
    }
    assert!(tail[1].2.contains("kill") && tail[2].2.contains("snapshot_restore"));
    assert!(library.custody_check(&sha).unwrap().ok());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_run_end_carries_counts_and_the_trace_hash() {
    let (root, library, sha, mut log) = setup("end");
    let file = root.join("trace.raw");
    fs::write(&file, b"abc").unwrap();
    let hash = file_sha256(&file).unwrap();
    assert_eq!(
        hash,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(file_sha256(&root.join("missing")).is_none());
    log.typed(b"x");
    log.ended(format!("3 records saved, 0 lost; recording SHA-256 {hash}"));
    let entries = kinds(&library, &sha);
    let end = entries.last().unwrap();
    assert_eq!((end.0.as_str(), end.1.as_str()), ("run_ended", "app"));
    assert!(end.2.contains(&hash));
    // Typing left over is written before the end.
    assert_eq!(entries[entries.len() - 2].0, "terminal_input");
    let _ = fs::remove_dir_all(root);
}

fn file(path: &str, sha: &str, roles: &[&str], writer: &str) -> LineageFile {
    LineageFile {
        path: path.into(),
        sha256: sha.into(),
        roles: roles.iter().map(|role| role.to_string()).collect(),
        writer: writer.into(),
    }
}

#[test]
fn activity_lines_name_a_dropped_copy_a_derived_file_and_a_self_delete() {
    let sha = "a".repeat(64);
    let other = "b".repeat(64);
    let files = vec![
        file("/tmp/run.sh", &sha, &["sample", "deleted"], ""),
        file("/var/tmp/copy.sh", &sha, &["created"], "/tmp/run.sh"),
        file(
            "/var/tmp/payload",
            &other,
            &["written at close"],
            "/tmp/run.sh",
        ),
        file("/var/tmp/unrelated", &other, &["created"], "/usr/bin/apt"),
        file("/var/tmp/nohash", "", &["created"], "/tmp/run.sh"),
    ];
    let lines = super::activity::lines(&sha, &files);
    assert_eq!(
        lines,
        vec![
            "deleted itself (/tmp/run.sh)".to_string(),
            "dropped a copy of itself at /var/tmp/copy.sh".to_string(),
            format!("dropped /var/tmp/payload (SHA-256 {other})"),
        ]
    );
}

#[test]
fn run_activity_is_written_once_by_the_sample_from_the_runs_digest() {
    let (root, mut library, sha, _log) = setup("activity");
    let directory = root.join("runs").join("r9");
    fs::create_dir_all(&directory).unwrap();
    let run = SeenRun {
        sha256: sha.clone(),
        vm_id: "vm1".into(),
        vm_name: "vm-one".into(),
        run_id: "r9".into(),
        started_ms: Some(1),
        exit: "Exit 0".into(),
        directory: directory.display().to_string(),
    };
    // No digest yet: nothing to add, and the run is still indexed.
    assert_eq!(library.index_runs(std::slice::from_ref(&run)).unwrap(), 1);
    assert!(kinds(&library, &sha).iter().all(|e| e.0 != "activity"));
    RunDigest::update(&directory, |digest| {
        digest.lineage = Some(Lineage {
            files: vec![
                file("/tmp/run.sh", &sha, &["sample", "deleted"], ""),
                file("/tmp/drop", &"c".repeat(64), &["created"], "/tmp/run.sh"),
            ],
            execs: Vec::new(),
        });
    })
    .unwrap();
    assert_eq!(library.index_runs(std::slice::from_ref(&run)).unwrap(), 0);
    library.index_runs(std::slice::from_ref(&run)).unwrap();
    let activity: Vec<_> = kinds(&library, &sha)
        .into_iter()
        .filter(|entry| entry.0 == "activity")
        .collect();
    assert_eq!(activity.len(), 2, "{activity:?}");
    assert!(activity.iter().all(|entry| entry.1 == "sample (run r9)"));
    assert!(activity[0].2.contains("deleted itself"));
    assert!(library.custody_check(&sha).unwrap().ok());
    let _ = fs::remove_dir_all(root);
}
