// SPDX-License-Identifier: GPL-3.0-only
//! Notes with references, deleting a run, and the artefact tables.
use super::*;
use crate::{BackendOptions, ExecRequest, RunArtifactState, RunArtifacts, RunState, RunSummary};
use std::collections::BTreeSet;

fn temp(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ant-features-{name}-{}",
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

const SCRIPT: &[u8] = b"#!/bin/sh\necho hello\n";

fn added(library: &mut Library, bytes: &[u8]) -> String {
    library
        .add_bytes(bytes, NewSample::default())
        .unwrap()
        .sha256
}

fn reference(kind: RefKind, target: &str, label: &str) -> NoteRef {
    NoteRef::new(kind, target, label)
}

#[test]
fn notes_keep_their_references_and_every_change_reaches_the_custody_log() {
    let root = temp("notes");
    let mut library = Library::open(&root).unwrap();
    let sha = added(&mut library, SCRIPT);
    let refs = vec![
        reference(RefKind::Run, "vm1/r14", "Run 14"),
        reference(RefKind::Process, "vm1/r14/1418", "sh 1418"),
        // The same target twice is one reference.
        reference(RefKind::Run, "vm1/r14", "Run 14"),
    ];
    let first = library.add_note(&sha, "  drops /tmp/.x  ", &refs).unwrap();
    let second = library
        .add_note(
            &sha,
            "second",
            &[reference(RefKind::Custody, "3", "Entry 3")],
        )
        .unwrap();
    let notes = library.notes(&sha).unwrap();
    assert_eq!(
        notes.iter().map(|n| n.id).collect::<Vec<_>>(),
        [second, first]
    );
    let found = notes.iter().find(|n| n.id == first).unwrap();
    assert_eq!(found.text, "drops /tmp/.x");
    assert_eq!(found.refs.len(), 2);
    assert_eq!(found.refs[1].number(), Some(1418));
    assert_eq!(found.refs[0].run(), Some(("vm1", "r14")));

    library
        .edit_note(first, "drops /tmp/.x and removes itself", &refs[..1])
        .unwrap();
    library.delete_note(second).unwrap();
    let after = library.notes(&sha).unwrap();
    assert_eq!(after.len(), 1);
    assert!(after[0].edited_ms.is_some());
    assert_eq!(after[0].refs.len(), 1);

    // Three kinds of entry, in order, with the hash of the text and no text.
    let events: Vec<_> = library
        .events(&sha)
        .unwrap()
        .into_iter()
        .filter(|row| row.event.key().starts_with("note_"))
        .collect();
    assert_eq!(
        events.iter().map(|row| row.event.key()).collect::<Vec<_>>(),
        ["note_added", "note_added", "note_edited", "note_deleted"]
    );
    let CustodyEvent::NoteAdded { hash, refs, .. } = &events[0].event else {
        panic!("not a note event");
    };
    assert_eq!(hash, &note_text_hash("drops /tmp/.x"));
    assert_eq!(refs, "Run 14; sh 1418");
    assert!(
        events
            .iter()
            .all(|row| !row.event.detail().contains("drops"))
    );
    // The log still verifies with the new kinds in it.
    assert!(library.custody_check(&sha).unwrap().ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_bad_note_is_refused_and_notes_follow_the_sample_out_of_the_library() {
    let root = temp("notes-bad");
    let mut library = Library::open(&root).unwrap();
    let sha = added(&mut library, SCRIPT);
    assert!(library.add_note(&sha, "   ", &[]).is_err());
    assert!(library.add_note(&sha, "a\u{7}b", &[]).is_err());
    assert!(
        library
            .add_note(&sha, &"x".repeat(MAX_NOTE + 1), &[])
            .is_err()
    );
    let many: Vec<_> = (0..=MAX_REFS)
        .map(|n| reference(RefKind::Custody, &n.to_string(), "e"))
        .collect();
    assert!(library.add_note(&sha, "ok", &many).is_err());
    assert!(
        library
            .add_note(&sha, "ok", &[reference(RefKind::Run, "", "x")])
            .is_err()
    );
    assert!(library.add_note(&"0".repeat(64), "ok", &[]).is_err());
    assert!(library.edit_note(999, "ok", &[]).is_err());
    assert!(library.delete_note(999).is_err());
    let id = library
        .add_note(&sha, "kept", &[reference(RefKind::Custody, "1", "Entry 1")])
        .unwrap();
    assert!(id > 0);
    library.purge(&sha).unwrap();
    let rows: i64 = library
        .connection
        .query_row("SELECT COUNT(*) FROM note_ref", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0, "references go with the note");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_library_of_the_earlier_layout_opens_unchanged_and_gets_the_new_tables() {
    let root = temp("layout");
    let mut library = Library::open(&root).unwrap();
    let sha = added(&mut library, SCRIPT);
    let events = library.events(&sha).unwrap().len();
    drop(library);
    // Make it look like layout 1: no new tables, the older version number.
    let database = samples_dir(&root).join(library::DATABASE);
    let connection = library::connect(&database).unwrap();
    connection
        .execute_batch(
            "DROP TABLE note_ref; DROP TABLE note; DROP TABLE artifact; DROP TABLE file_hash;
             UPDATE meta SET value='1' WHERE key='schema';",
        )
        .unwrap();
    drop(connection);
    let mut library = Library::open(&root).unwrap();
    assert_eq!(library.events(&sha).unwrap().len(), events);
    assert!(library.get(&sha).unwrap().is_some());
    library.add_note(&sha, "works now", &[]).unwrap();
    let version: String = library
        .connection
        .query_row("SELECT value FROM meta WHERE key='schema'", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, "2");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn artefacts_are_named_by_kind_and_short_hash_and_the_sidecar_is_read_with_care() {
    assert_eq!(short_hash(&"9c41e2a0".repeat(8)), "9c41e2a0");
    assert_eq!(short_hash(""), "–");
    let dir = temp("sidecar");
    assert!(saved_items(&dir).is_empty());
    record_saved(
        &dir,
        SavedItem {
            kind: SavedKind::File,
            name: "dropper".into(),
            path: "saved/dropper".into(),
            sha256: "ab".repeat(32),
            size: 12,
            rule: "Save dropped files".into(),
            context: "sh 1418".into(),
        },
    )
    .unwrap();
    record_saved(
        &dir,
        SavedItem {
            kind: SavedKind::Snapshot,
            name: "before-unlink".into(),
            path: String::new(),
            sha256: String::new(),
            size: 0,
            rule: "Snapshot before unlink".into(),
            context: String::new(),
        },
    )
    .unwrap();
    let items = saved_items(&dir);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].artifact_kind().label(), "Saved file");
    assert_eq!(items[1].artifact_kind().label(), "VM snapshot");
    assert_eq!(items[0].because(), "Rule: Save dropped files");
    assert_eq!(items[0].file_in(&dir), Some(dir.join("saved/dropper")));
    // A path that climbs out of the run's folder names nothing.
    let climbing = SavedItem {
        path: "../../etc/passwd".into(),
        ..items[0].clone()
    };
    assert_eq!(climbing.file_in(&dir), None);
    // Garbage and an oversized sidecar read as nothing.
    fs::write(dir.join(SAVED_FILE), b"not json").unwrap();
    assert!(saved_items(&dir).is_empty());
    fs::write(dir.join(SAVED_FILE), vec![b' '; (2 << 20) as usize]).unwrap();
    assert!(saved_items(&dir).is_empty());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_file_hash_is_cached_until_the_file_changes() {
    let root = temp("hash");
    let library = Library::open(&root).unwrap();
    let file = root.join("core");
    fs::write(&file, b"first").unwrap();
    assert_eq!(library.cached_artifact_hash(&file), None);
    let first = library.artifact_hash(&file).unwrap();
    assert_eq!(first, crate::storage::sha256_hex(b"first"));
    assert_eq!(library.cached_artifact_hash(&file), Some(first));
    fs::write(&file, b"second, longer").unwrap();
    assert_eq!(library.cached_artifact_hash(&file), None);
    assert_eq!(
        library.artifact_hash(&file).unwrap(),
        crate::storage::sha256_hex(b"second, longer")
    );
    // A memory dump is a folder; its memory.elf is what is hashed.
    let dump = root.join("memory/dump1");
    fs::create_dir_all(&dump).unwrap();
    fs::write(dump.join("memory.elf"), b"ram").unwrap();
    fs::write(dump.join("dump.json"), b"{}").unwrap();
    assert_eq!(
        library.artifact_hash(&dump).unwrap(),
        crate::storage::sha256_hex(b"ram")
    );
    fs::remove_dir_all(root).unwrap();
}

/// A recording with a sample's run: the run folder, a core in it, an exit
/// memory dump and a capture beside it, and a second run of the same boot.
struct Recording {
    root: PathBuf,
    options: BackendOptions,
    library: Library,
    sha: String,
    other_sha: String,
}

const VM: &str = "vm1";

impl Recording {
    fn new(name: &str) -> Self {
        let root = temp(name);
        let options = BackendOptions {
            data_dir: root.clone(),
            ..BackendOptions::default()
        };
        let mut library = Library::open(&root).unwrap();
        let sha = added(&mut library, SCRIPT);
        let other_sha = added(&mut library, b"#!/bin/sh\necho other\n");
        fs::create_dir_all(root.join(VM)).unwrap();
        let config = crate::VmConfig {
            id: VM.into(),
            name: "vm one".into(),
            ..crate::VmConfig::default()
        };
        fs::write(
            root.join(VM).join("config.json"),
            serde_json::to_vec(&config).unwrap(),
        )
        .unwrap();
        Self {
            root,
            options,
            library,
            sha,
            other_sha,
        }
    }

    fn recording(&self) -> PathBuf {
        fs::canonicalize(self.root.join(VM)).unwrap()
    }

    /// Write run `id` of `sample`.
    fn run(&self, id: &str, sample: &str, artifacts: RunArtifacts) -> PathBuf {
        let dir = self.recording().join("runs").join(id);
        fs::create_dir_all(&dir).unwrap();
        let summary = RunSummary {
            environment: None,
            started_ms: Some(1000),
            clock_anchor: None,
            id: id.into(),
            vm_id: VM.into(),
            boot_id: "boot1".into(),
            session_id: 1,
            root_task_cookie: 2,
            pid: 3,
            request: ExecRequest {
                sample: Some(SampleRef {
                    sha256: sample.into(),
                    name: "install.sh".into(),
                }),
                ..ExecRequest::default()
            },
            directory: dir.clone(),
            terminal_eof: false,
            state: RunState::Finished,
            notes: Vec::new(),
            machine: None,
            route: None,
            recording_error: None,
            execution: None,
            analysis: None,
        };
        fs::write(dir.join("run.json"), serde_json::to_vec(&summary).unwrap()).unwrap();
        fs::write(
            dir.join("artifacts.json"),
            serde_json::to_vec(&artifacts).unwrap(),
        )
        .unwrap();
        dir
    }

    fn core(&self, id: &str, bytes: &[u8]) -> PathBuf {
        let core = self.recording().join("runs").join(id).join("core");
        fs::write(&core, bytes).unwrap();
        core
    }

    fn memory(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let dump = self.recording().join("memory").join(name);
        fs::create_dir_all(&dump).unwrap();
        fs::write(dump.join("memory.elf"), bytes).unwrap();
        fs::write(dump.join("dump.json"), b"{}").unwrap();
        dump
    }

    fn capture(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let dir = self.recording().join("boots/boot1/network");
        fs::create_dir_all(&dir).unwrap();
        let pcap = dir.join(name);
        fs::write(&pcap, bytes).unwrap();
        pcap
    }
}

fn artifacts(core: Option<&Path>, memory: Option<&Path>, captures: &[&Path]) -> RunArtifacts {
    RunArtifacts {
        core_dump: core.map(Path::to_path_buf),
        core_state: RunArtifactState::Complete,
        memory_dump: memory.map(Path::to_path_buf),
        memory_state: RunArtifactState::Complete,
        network_captures: captures.iter().map(|p| p.to_path_buf()).collect(),
        network_state: RunArtifactState::Complete,
        ..RunArtifacts::default()
    }
}

fn keys(keep: &[&str]) -> BTreeSet<String> {
    keep.iter().map(|key| (*key).to_owned()).collect()
}

#[test]
fn the_plan_lists_each_artefact_with_its_kind_hash_and_where_it_is() {
    let rec = Recording::new("plan");
    let core = {
        let dir = rec.run("r14", &rec.sha.clone(), RunArtifacts::default());
        let core = dir.join("core");
        fs::write(&core, b"core bytes").unwrap();
        core
    };
    let memory = rec.memory("d1", b"ram bytes");
    let pcap = rec.capture("cap.pcap", b"packets");
    rec.run(
        "r14",
        &rec.sha.clone(),
        artifacts(Some(&core), Some(&memory), &[&pcap]),
    );
    let plan = plan_run_deletion(&rec.options, &rec.sha, VM, "r14").unwrap();
    let by_kind = |kind: ArtifactKind| plan.items.iter().find(|i| i.kind == kind).unwrap();
    assert_eq!(by_kind(ArtifactKind::Core).place, ArtifactPlace::InFolder);
    assert_eq!(
        by_kind(ArtifactKind::Core).hash,
        crate::storage::sha256_hex(b"core bytes")
    );
    assert_eq!(by_kind(ArtifactKind::Memory).place, ArtifactPlace::Outside);
    assert_eq!(
        by_kind(ArtifactKind::Memory).hash,
        crate::storage::sha256_hex(b"ram bytes")
    );
    assert_eq!(by_kind(ArtifactKind::Capture).place, ArtifactPlace::Outside);
    assert_eq!(
        by_kind(ArtifactKind::Core).title().len(),
        "Core dump 12345678".len()
    );
    // Refused for a run of another sample, or a name that is not one.
    assert!(plan_run_deletion(&rec.options, &rec.other_sha, VM, "r14").is_err());
    assert!(plan_run_deletion(&rec.options, &rec.sha, VM, "../runs/r14").is_err());
    assert!(plan_run_deletion(&rec.options, &rec.sha, VM, "nope").is_err());
    fs::remove_dir_all(&rec.root).unwrap();
}

#[test]
fn deleting_a_run_keeps_what_was_chosen_and_records_the_rest() {
    let rec = Recording::new("delete");
    let dir = rec.run("r14", &rec.sha.clone(), RunArtifacts::default());
    let core = dir.join("core");
    fs::write(&core, b"core bytes").unwrap();
    fs::write(dir.join("triage-digest.json"), b"{\"digest\":1}").unwrap();
    fs::write(dir.join("events.bin"), vec![1u8; (5 << 20) as usize]).unwrap();
    let memory = rec.memory("d1", b"ram bytes");
    let pcap = rec.capture("cap.pcap", b"packets");
    rec.run(
        "r14",
        &rec.sha.clone(),
        artifacts(Some(&core), Some(&memory), &[&pcap]),
    );
    // A snapshot a rule took stays with the VM.
    record_saved(
        &dir,
        SavedItem {
            kind: SavedKind::Snapshot,
            name: "before-unlink".into(),
            path: String::new(),
            sha256: String::new(),
            size: 0,
            rule: "Snapshot".into(),
            context: String::new(),
        },
    )
    .unwrap();
    let plan = plan_run_deletion(&rec.options, &rec.sha, VM, "r14").unwrap();
    let core_hash = crate::storage::sha256_hex(b"core bytes");
    let ram_hash = crate::storage::sha256_hex(b"ram bytes");

    // Refused while the run is live; nothing changes.
    assert!(
        delete_run(&rec.options, &plan, &keys(&[]), "vm one", true)
            .unwrap_err()
            .contains("still running")
    );
    assert!(dir.is_dir());

    // Keep the memory dump, delete the core, leave the capture.
    let done = delete_run(&rec.options, &plan, &keys(&["memory/d1"]), "vm one", false).unwrap();
    assert_eq!((done.kept, done.deleted), (1, 1));
    assert!(!dir.exists(), "the run folder is gone");
    assert!(!memory.exists(), "the dump moved");
    assert!(
        rec.library
            .artifacts_dir()
            .join(&ram_hash)
            .join("memory.elf")
            .is_file()
    );
    assert!(
        pcap.is_file(),
        "a file outside the run's folder stays unless kept"
    );
    assert!(rec.recording().join("runs").is_dir());

    let rows = rec.library.artifacts(&rec.sha).unwrap();
    let find = |kind: ArtifactKind| rows.iter().find(|r| r.kind == kind).unwrap();
    assert_eq!(find(ArtifactKind::Memory).fate, ArtifactFate::Kept);
    assert_eq!(
        find(ArtifactKind::Memory).stored,
        rec.library.artifacts_dir().join(&ram_hash)
    );
    assert_eq!(find(ArtifactKind::Core).fate, ArtifactFate::Deleted);
    assert_eq!(find(ArtifactKind::Core).hash, core_hash);
    assert_eq!(find(ArtifactKind::Capture).fate, ArtifactFate::WithVm);
    assert_eq!(find(ArtifactKind::Snapshot).fate, ArtifactFate::WithVm);

    // The run's record stays with the sample: small files, not the recording.
    let record = &done.record;
    assert!(record.join("run.json").is_file());
    assert!(record.join("triage-digest.json").is_file());
    assert!(!record.join("events.bin").exists());
    assert!(!record.join("core").exists());

    // The custody log says what happened, by kind and short hash.
    let last = rec.library.events(&rec.sha).unwrap().pop().unwrap();
    let detail = last.event.detail();
    assert_eq!(last.event.key(), "run_deleted");
    assert!(
        detail.contains(&format!("kept memory dump {}", &ram_hash[..8])),
        "{detail}"
    );
    assert!(
        detail.contains(&format!("deleted core dump {}", &core_hash[..8])),
        "{detail}"
    );
    assert!(rec.library.custody_check(&rec.sha).unwrap().ok());
    fs::remove_dir_all(&rec.root).unwrap();
}

#[test]
fn a_deleted_run_is_listed_again_from_its_record() {
    let mut rec = Recording::new("retained");
    let dir = rec.run("r1", &rec.sha.clone(), RunArtifacts::default());
    rec.library
        .index_runs(&[SeenRun {
            sha256: rec.sha.clone(),
            vm_id: VM.into(),
            vm_name: "vm one".into(),
            run_id: "r1".into(),
            started_ms: Some(1000),
            exit: "Exit 0".into(),
            directory: dir.display().to_string(),
        }])
        .unwrap();
    let plan = plan_run_deletion(&rec.options, &rec.sha, VM, "r1").unwrap();
    delete_run(&rec.options, &plan, &keys(&[]), "vm one", false).unwrap();
    assert!(!dir.exists());
    let retained = rec.library.retained_runs(&rec.sha).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].id, "r1");
    assert!(retained[0].directory.starts_with(rec.library.record_dir()));
    assert!(retained[0].directory.join("run.json").is_file());
    fs::remove_dir_all(&rec.root).unwrap();
}

#[test]
fn nothing_outside_the_runs_own_files_is_ever_deleted() {
    let rec = Recording::new("confined");
    // Things that must survive: a sibling run, its files, a capture and a dump
    // it shares with the run being deleted, and files outside the recording.
    let sibling = rec.run("r2", &rec.other_sha.clone(), RunArtifacts::default());
    let sibling_core = rec.core("r2", b"sibling core");
    let shared_pcap = rec.capture("shared.pcap", b"shared packets");
    let outside = rec.root.join("precious");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("file"), b"keep me").unwrap();
    let outside_file = rec.root.join("precious.txt");
    fs::write(&outside_file, b"keep me too").unwrap();
    let sample_archive = rec.library.archive_path(&rec.sha).unwrap();
    rec.run(
        "r2",
        &rec.other_sha.clone(),
        artifacts(Some(&sibling_core), None, &[&shared_pcap]),
    );

    // The run to delete names the shared capture, a file outside the
    // recording, the library's archive and a folder with a climbing path.
    let dir = rec.run("r1", &rec.sha.clone(), RunArtifacts::default());
    let own = dir.join("core");
    let climbing = dir.join("../../precious");
    let mut hostile = artifacts(Some(&own), Some(&outside), &[&shared_pcap, &outside_file]);
    hostile.network_captures.push(sample_archive.clone());
    hostile.network_captures.push(climbing);
    let sha = rec.sha.clone();
    let make = |rec: &Recording| {
        let dir = rec.run("r1", &sha, hostile.clone());
        fs::write(dir.join("core"), b"own core").unwrap();
        dir
    };
    // Only the run's own core is offered for deletion; the shared capture
    // stays with the VM and the rest is not listed at all. Whatever is chosen,
    // nothing else is touched.
    let all = BTreeSet::from(["core/core".to_owned(), "capture/shared.pcap".to_owned()]);
    for choice in [BTreeSet::new(), all] {
        let dir = make(&rec);
        let plan = plan_run_deletion(&rec.options, &rec.sha, VM, "r1").unwrap();
        let places: Vec<_> = plan.items.iter().map(|i| (i.kind, i.place)).collect();
        assert_eq!(
            places,
            [
                (ArtifactKind::Core, ArtifactPlace::InFolder),
                (ArtifactKind::Capture, ArtifactPlace::WithVm),
            ]
        );
        delete_run(&rec.options, &plan, &choice, "vm one", false).unwrap();
        assert!(!dir.exists());
        assert!(sibling.is_dir() && sibling_core.is_file());
        assert!(shared_pcap.is_file());
        assert!(outside.join("file").is_file() && outside_file.is_file());
        assert!(sample_archive.is_file());
    }
    fs::remove_dir_all(&rec.root).unwrap();
}

#[test]
fn a_linked_run_folder_is_never_followed() {
    let rec = Recording::new("link");
    let victim = rec.root.join("victim");
    fs::create_dir_all(&victim).unwrap();
    fs::write(victim.join("data"), b"important").unwrap();
    // The run id names a link to a folder that holds a valid-looking run.
    let target = rec.root.join("elsewhere");
    fs::create_dir_all(&target).unwrap();
    let real = rec.run("real", &rec.sha.clone(), RunArtifacts::default());
    fs::copy(real.join("run.json"), target.join("run.json")).unwrap();
    let runs = rec.recording().join("runs");
    std::os::unix::fs::symlink(&target, runs.join("linked")).unwrap();
    assert!(plan_run_deletion(&rec.options, &rec.sha, VM, "linked").is_err());
    assert!(target.join("run.json").is_file());
    // A link inside the folder is removed as a link, not followed.
    std::os::unix::fs::symlink(&victim, real.join("shortcut")).unwrap();
    let plan = plan_run_deletion(&rec.options, &rec.sha, VM, "real").unwrap();
    delete_run(&rec.options, &plan, &keys(&[]), "vm one", false).unwrap();
    assert!(!real.exists());
    assert!(victim.join("data").is_file());
    fs::remove_dir_all(&rec.root).unwrap();
}

#[test]
fn a_kept_file_already_in_the_library_is_not_overwritten() {
    let rec = Recording::new("repeat");
    let first = rec.run("r1", &rec.sha.clone(), RunArtifacts::default());
    let core = first.join("core");
    fs::write(&core, b"same core").unwrap();
    rec.run("r1", &rec.sha.clone(), artifacts(Some(&core), None, &[]));
    let second = rec.run("r2", &rec.sha.clone(), RunArtifacts::default());
    let core2 = second.join("core");
    fs::write(&core2, b"same core").unwrap();
    rec.run("r2", &rec.sha.clone(), artifacts(Some(&core2), None, &[]));
    let hash = crate::storage::sha256_hex(b"same core");
    for run in ["r1", "r2"] {
        let plan = plan_run_deletion(&rec.options, &rec.sha, VM, run).unwrap();
        delete_run(&rec.options, &plan, &keys(&["core/core"]), "vm one", false).unwrap();
    }
    let stored = rec.library.artifacts_dir().join(&hash);
    assert_eq!(fs::read(stored).unwrap(), b"same core");
    let rows = rec.library.artifacts(&rec.sha).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.fate == ArtifactFate::Kept));
    fs::remove_dir_all(&rec.root).unwrap();
}

#[test]
fn a_record_keeps_the_process_tree_for_the_runs_tab() {
    let dir = std::env::temp_dir().join(format!(
        "antinomie-saved-tree-{}",
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&dir).unwrap();
    assert!(saved_process_tree(&dir).is_none());
    let tree: SavedTree = (
        vec![crate::capture_processes::CaptureProcess {
            pid: 7,
            name: "sh".into(),
            ..Default::default()
        }],
        vec!["lifecycle records were lost".to_owned()],
    );
    crate::storage::atomic_json(&dir.join(PROCESS_TREE_FILE), &tree).unwrap();
    let (processes, issues) = saved_process_tree(&dir).expect("read back");
    assert_eq!((processes[0].pid, processes[0].name.as_str()), (7, "sh"));
    assert_eq!(issues, ["lifecycle records were lost"]);
    fs::remove_dir_all(&dir).unwrap();
}
