// SPDX-License-Identifier: GPL-3.0-only
//! The sample window's notes with references, Delete run… and the artifact
//! rows for VM snapshots, saved files and the files of deleted runs.
use super::samples_detail::{save_digest, save_run, until, window};
use super::*;
use crate::app::samples_page::SamplesPage;
use antinomie_monitor_core::samples::{
    record_saved, Library, NoteRef, RefKind, SavedItem, SavedKind,
};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 820.0);

fn run_ref(id: &str, label: &str) -> NoteRef {
    NoteRef::new(RefKind::Run, format!("vm/{id}"), label)
}

fn frames(app: &mut MonitorApp, ctx: &egui::Context, count: usize) {
    for _ in 0..count {
        render(app, ctx, SIZE);
    }
}

fn loaded(app: &MonitorApp) -> bool {
    app.samples_page.detail_probe().is_some()
}

#[test]
fn a_menu_asks_for_a_note_and_it_reaches_the_tab_the_summary_and_the_custody_log() {
    let (mut app, ctx, sha, root) = window("features-notes");
    until(&mut app, &ctx, loaded);
    // A menu item leaves a request; the page opens the editor with it.
    SamplesPage::ask_note(&ctx, run_ref("r1", "Run 1"));
    frames(&mut app, &ctx, 2);
    let (refs, editing) = app
        .samples_page
        .note_editor_refs()
        .expect("the editor opens");
    assert_eq!(refs, ["Run 1"]);
    assert!(!editing);
    app.save_open_note("  runs the dropper twice  ");
    assert!(app.samples_page.note_editor_refs().is_none());
    until(&mut app, &ctx, |app| {
        !app.samples_page.detail_notes().is_empty()
    });
    let notes = app.samples_page.detail_notes();
    assert_eq!(notes[0].1, "runs the dropper twice");
    assert_eq!(notes[0].2, ["Run 1"]);
    // Summary (Latest note) and the Notes tab draw with it.
    frames(&mut app, &ctx, 3);
    app.samples_page.show_notes_tab();
    frames(&mut app, &ctx, 3);
    // The custody log has an entry for it, with the hash of the text.
    let library = Library::open(&root).unwrap();
    let events = library.events(&sha).unwrap();
    let added = events
        .iter()
        .find(|row| row.event.key() == "note_added")
        .expect("a custody entry");
    assert!(added.event.detail().contains("refers to Run 1"));
    assert!(!added.event.detail().contains("dropper"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_note_is_edited_and_deleted_and_each_change_is_in_the_custody_log() {
    let (mut app, ctx, sha, root) = window("features-notes-edit");
    until(&mut app, &ctx, loaded);
    SamplesPage::ask_note(&ctx, run_ref("r2", "Run 2"));
    frames(&mut app, &ctx, 2);
    app.save_open_note("first");
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_notes().len() == 1
    });
    let note = app.samples_page.detail_notes().remove(0);
    let data_note = {
        let library = Library::open(&root).unwrap();
        library.notes(&sha).unwrap().remove(0)
    };
    app.samples_page.edit_note(&data_note);
    let (refs, editing) = app.samples_page.note_editor_refs().unwrap();
    assert!(editing);
    assert_eq!(refs, ["Run 2"]);
    app.save_open_note("first, corrected");
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_notes()[0].1 == "first, corrected"
    });
    let mut library = Library::open(&root).unwrap();
    library.delete_note(note.0).unwrap();
    app.samples_page.refresh();
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_notes().is_empty()
    });
    let keys: Vec<_> = library
        .events(&sha)
        .unwrap()
        .iter()
        .map(|row| row.event.key())
        .filter(|key| key.starts_with("note_"))
        .collect();
    assert_eq!(keys, ["note_added", "note_edited", "note_deleted"]);
    frames(&mut app, &ctx, 2);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_picker_offers_every_category_and_a_typed_search_spans_them() {
    let (mut app, ctx, sha, root) = window("features-picker");
    // Triage left indicators for run r1.
    let run = save_run(&root, &sha, "install.sh", "r1", 1_000, true);
    save_digest(&run, "high", true);
    app.samples_page.refresh();
    until(&mut app, &ctx, |app| {
        app.samples_page
            .detail_probe()
            .is_some_and(|(runs, _, _)| runs == 2)
    });
    SamplesPage::ask_note(&ctx, run_ref("r1", "Run 1"));
    frames(&mut app, &ctx, 2);
    let counts = app.samples_page.picker_counts();
    let count = |name: &str| counts.iter().find(|(label, _)| *label == name).unwrap().1;
    assert_eq!(count("Runs"), 2);
    assert_eq!(count("Processes"), 2);
    assert_eq!(count("IoC"), 2);
    assert!(count("Custody entries") >= 1);
    assert!(count("Lineage nodes") >= 1);
    // Typing before a category is picked searches all of them, with the
    // category named in each result.
    let found = app.samples_page.picker_search("update.example");
    assert_eq!(found.len(), 1);
    assert!(found[0].starts_with("IoC · "));
    assert!(!app.samples_page.picker_search("run").is_empty());
    assert!(app.samples_page.picker_search("zzz-nothing").is_empty());
    // The editor draws with its picker open.
    frames(&mut app, &ctx, 3);
    let _ = std::fs::remove_dir_all(root);
}

/// A run folder with a core dump and a rule-saved file and snapshot.
fn run_with_files(root: &std::path::Path, sha: &str, id: &str, started: u64) -> RunSummary {
    let run = save_run(root, sha, "install.sh", id, started, false);
    let core = run.directory.join("core");
    std::fs::write(&core, format!("core of {id}")).unwrap();
    let saved = run.directory.join("saved");
    std::fs::create_dir_all(&saved).unwrap();
    std::fs::write(saved.join("dropper"), format!("dropper of {id}")).unwrap();
    let artifacts = antinomie_monitor_core::RunArtifacts {
        run_id: run.id.clone(),
        vm_id: run.vm_id.clone(),
        boot_id: run.boot_id.clone(),
        core_dump: Some(core),
        core_state: antinomie_monitor_core::RunArtifactState::Complete,
        ..antinomie_monitor_core::RunArtifacts::default()
    };
    std::fs::write(
        run.directory.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    record_saved(
        &run.directory,
        SavedItem {
            kind: SavedKind::File,
            name: "dropper".into(),
            path: "saved/dropper".into(),
            sha256: String::new(),
            size: 0,
            rule: "Save dropped files".into(),
            context: "sh 1418".into(),
        },
    )
    .unwrap();
    record_saved(
        &run.directory,
        SavedItem {
            kind: SavedKind::Snapshot,
            name: "before-unlink".into(),
            path: String::new(),
            sha256: "cd".repeat(32),
            size: 0,
            rule: "Snapshot before unlink".into(),
            context: String::new(),
        },
    )
    .unwrap();
    run
}

fn outputs(app: &MonitorApp) -> Vec<(String, usize, String, Option<u64>)> {
    app.samples_page.detail_outputs()
}

#[test]
fn snapshots_and_saved_files_are_artifact_kinds_with_their_availability() {
    let (mut app, ctx, sha, root) = window("features-kinds");
    run_with_files(&root, &sha, "r1", 1_000);
    app.samples_page.refresh();
    until(&mut app, &ctx, |app| {
        outputs(app).iter().any(|row| row.0 == "VM snapshot")
    });
    let rows = outputs(&app);
    let kinds: Vec<_> = rows
        .iter()
        .map(|row| (row.0.as_str(), row.2.as_str()))
        .collect();
    assert!(kinds.contains(&("Core dump", "InRun")), "{kinds:?}");
    assert!(kinds.contains(&("Saved file", "InRun")), "{kinds:?}");
    assert!(kinds.contains(&("VM snapshot", "WithVm")), "{kinds:?}");
    // The table draws, and hashes are read off the UI thread.
    for _ in 0..30 {
        frames(&mut app, &ctx, 1);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = std::fs::remove_dir_all(root);
}

fn wait_for_dialog(app: &mut MonitorApp, ctx: &egui::Context, stage: &str) {
    until(app, ctx, |app| {
        app.samples_page.delete_run_stage().as_deref() == Some(stage)
    });
}

#[test]
fn deleting_a_run_keeps_the_last_of_each_kind_and_the_run_stays_listed() {
    let (mut app, ctx, sha, root) = window("features-delete");
    let first = run_with_files(&root, &sha, "r1", 1_000);
    // A second run has a core of its own: so the first is not the last core.
    run_with_files(&root, &sha, "r2", 9_000);
    app.samples_page.refresh();
    until(&mut app, &ctx, |app| {
        outputs(app)
            .iter()
            .filter(|row| row.0 == "Core dump")
            .count()
            == 2
    });
    app.start_delete_run_for_test(&ctx, 1);
    wait_for_dialog(&mut app, &ctx, "ready");
    let rows = app.samples_page.delete_run_rows();
    let titles: Vec<_> = rows.iter().map(|row| row.0.as_str()).collect();
    assert!(titles.iter().any(|t| t.starts_with("Core dump ")));
    assert!(titles.iter().any(|t| t.starts_with("Saved file ")));
    assert!(titles.iter().any(|t| t.starts_with("VM snapshot ")));
    // The snapshot is not the analyst's to choose; the core and the file
    // have another of their kind in run 2, so they start as Delete.
    for (title, choosable, keep) in &rows {
        if title.starts_with("VM snapshot") {
            assert!(!choosable);
        } else {
            assert!(*choosable && !keep, "{title}");
        }
    }
    app.samples_page.delete_run_set_all(false);
    app.samples_page.delete_run_set_all(true);
    assert!(app
        .samples_page
        .delete_run_rows()
        .iter()
        .all(|row| !row.1 || row.2));
    // Keep the core, delete the saved file.
    app.samples_page.delete_run_set_all(false);
    app.confirm_delete_run();
    until(&mut app, &ctx, |app| {
        app.samples_page.delete_run_stage().is_none()
    });
    assert!(!first.directory.exists());
    assert!(
        root.join("vm/runs/r2").is_dir(),
        "the other run is untouched"
    );
    until(&mut app, &ctx, |app| {
        app.samples_page
            .detail_probe()
            .is_some_and(|(runs, _, _)| runs == 2)
            && outputs(app).iter().any(|row| row.2 == "Deleted")
    });
    // Run 1 is still listed (from its record), as are its files: the
    // snapshot stays with the VM and the others read "Deleted by you".
    assert_eq!(app.samples_page.detail_run_ids().len(), 2);
    let rows = outputs(&app);
    assert!(rows
        .iter()
        .any(|r| r.0 == "VM snapshot" && r.1 == 1 && r.2 == "WithVm"));
    assert!(rows
        .iter()
        .any(|r| r.0 == "Core dump" && r.1 == 1 && r.2 == "Deleted"));
    assert!(rows
        .iter()
        .any(|r| r.0 == "Core dump" && r.1 == 2 && r.2 == "InRun"));
    frames(&mut app, &ctx, 3);
    let library = Library::open(&root).unwrap();
    let last = library.events(&sha).unwrap().pop().unwrap();
    assert_eq!(last.event.key(), "run_deleted");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_last_core_of_a_sample_is_kept_by_default_in_the_library() {
    let (mut app, ctx, sha, root) = window("features-delete-keep");
    let only = run_with_files(&root, &sha, "r1", 1_000);
    app.samples_page.refresh();
    until(&mut app, &ctx, |app| {
        outputs(app).iter().any(|row| row.0 == "Core dump")
    });
    app.start_delete_run_for_test(&ctx, 1);
    wait_for_dialog(&mut app, &ctx, "ready");
    let rows = app.samples_page.delete_run_rows();
    for (title, choosable, keep) in &rows {
        assert!(!choosable || *keep, "{title} is the last of its kind");
    }
    frames(&mut app, &ctx, 3);
    app.confirm_delete_run();
    until(&mut app, &ctx, |app| {
        app.samples_page.delete_run_stage().is_none()
    });
    until(&mut app, &ctx, |app| {
        outputs(app)
            .iter()
            .any(|row| row.0 == "Core dump" && row.2.starts_with("Kept"))
    });
    let kept = root.join("samples/artefacts");
    let hash = antinomie_monitor_core::storage::sha256_hex(b"core of r1");
    assert_eq!(std::fs::read(kept.join(hash)).unwrap(), b"core of r1");
    assert!(!only.directory.exists());
    frames(&mut app, &ctx, 3);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_run_that_is_running_cannot_be_deleted() {
    let (mut app, ctx, sha, root) = window("features-delete-live");
    let run = run_with_files(&root, &sha, "r1", 1_000);
    app.samples_page.refresh();
    until(&mut app, &ctx, loaded);
    assert!(!app.sample_run_live(&run));
    let mut live = run.clone();
    live.state = RunState::Running;
    app.snapshot.runs.push(live);
    assert!(app.sample_run_live(&run));
    // The core refuses too, whatever the dialog allowed.
    let plan =
        antinomie_monitor_core::samples::plan_run_deletion(&app.options, &sha, "vm", "r1").unwrap();
    let refused = antinomie_monitor_core::samples::delete_run(
        &app.options,
        &plan,
        &Default::default(),
        "Debian",
        true,
    );
    assert!(refused.unwrap_err().contains("still running"));
    assert!(run.directory.is_dir());
    let _ = std::fs::remove_dir_all(root);
}

/// Data a screenshot scene needs before the window opens (see
/// `samples_shots`): notes, saved files and snapshots, and a recording with a
/// memory dump and a capture beside the first run.
pub(super) fn qa_data(data: &std::path::Path, sha: &str, scene: &str, first: &RunSummary) {
    if matches!(scene, "kinds" | "delete_run") {
        let recording = data.join("vm");
        let memory = recording.join("memory/dump1");
        std::fs::create_dir_all(&memory).unwrap();
        std::fs::write(memory.join("memory.elf"), vec![7u8; 2_000_000]).unwrap();
        let pcap = recording.join("boots/boot1/network/capture.pcap");
        std::fs::create_dir_all(pcap.parent().unwrap()).unwrap();
        std::fs::write(&pcap, vec![9u8; 300_000]).unwrap();
        let core = first.directory.join("core");
        std::fs::write(&core, vec![5u8; 120_000]).unwrap();
        let saved = first.directory.join("saved");
        std::fs::create_dir_all(&saved).unwrap();
        std::fs::write(saved.join("dropper"), vec![3u8; 40_000]).unwrap();
        let artifacts = antinomie_monitor_core::RunArtifacts {
            run_id: first.id.clone(),
            vm_id: first.vm_id.clone(),
            boot_id: "boot1".into(),
            core_dump: Some(core),
            core_state: antinomie_monitor_core::RunArtifactState::Complete,
            memory_dump: Some(memory),
            memory_state: antinomie_monitor_core::RunArtifactState::Complete,
            network_captures: vec![pcap],
            network_state: antinomie_monitor_core::RunArtifactState::Complete,
            ..antinomie_monitor_core::RunArtifacts::default()
        };
        std::fs::write(
            first.directory.join("artifacts.json"),
            serde_json::to_vec(&artifacts).unwrap(),
        )
        .unwrap();
        record_saved(
            &first.directory,
            SavedItem {
                kind: SavedKind::File,
                name: "dropper".into(),
                path: "saved/dropper".into(),
                sha256: String::new(),
                size: 0,
                rule: "Save dropped files".into(),
                context: "sh 1418".into(),
            },
        )
        .unwrap();
        record_saved(
            &first.directory,
            SavedItem {
                kind: SavedKind::Snapshot,
                name: "before-unlink".into(),
                path: String::new(),
                sha256: "9c41e2a0".repeat(8),
                size: 0,
                rule: "Snapshot before unlink".into(),
                context: String::new(),
            },
        )
        .unwrap();
    }
    if matches!(scene, "notes" | "note_editor") {
        let mut library = Library::open(data).unwrap();
        library
            .add_note(
                sha,
                "Writes /tmp/.x and starts it. The second copy is the one that talks to \
                 198.51.100.7, so look at that process first.",
                &[
                    NoteRef::new(RefKind::Run, "vm/r1", "Run 1"),
                    NoteRef::new(RefKind::Process, "vm/r1/4242", "sh 4242 · run 1"),
                    NoteRef::new(
                        RefKind::Indicator,
                        "endpoint:198.51.100.7:80",
                        "198.51.100.7:80 (endpoint)",
                    ),
                ],
            )
            .unwrap();
        library
            .add_note(
                sha,
                "Memory dump taken after exit; the config is still readable in it.",
                &[
                    NoteRef::new(
                        RefKind::Artifact,
                        "memory/vm/r1/memory",
                        "Memory dump 5a1f09c2 · run 1",
                    ),
                    NoteRef::new(RefKind::Custody, "1", "Custody entry 1 · Added"),
                    NoteRef::new(RefKind::Run, "vm/gone/r9", "Run 9"),
                ],
            )
            .unwrap();
    }
}

/// The part of a scene that needs the sample's data read: the note editor
/// with its picker, or the Delete run… dialog.
pub(super) fn qa_after(app: &mut MonitorApp, ctx: &egui::Context, scene: &str) {
    match scene {
        "note_editor" => app
            .samples_page
            .start_note_for_test(run_ref("r1", "Run 1"), true),
        "delete_run" => app.start_delete_run_for_test(ctx, 1),
        _ => {}
    }
}
