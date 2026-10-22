// SPDX-License-Identifier: GPL-3.0-only
//! The Disks tab inside the application: its place among the tabs, what it
//! shows for a running or a stopped VM, the commands its buttons send and the
//! shared Details dock.
use super::*;
use antinomie_monitor_core::disks::{
    CurrentDiskView, DiskJobProgress, DiskJobPurpose, DiskJobStage, DiskMeasure, DiskSourceRecord,
    Ext4State,
};

fn stopped_vm(app: &mut MonitorApp) {
    observer_fixture(app);
    app.snapshot.active_vm = None;
    app.snapshot.state = VmState::Stopped;
}

fn shown_texts(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2) -> Vec<String> {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    texts(&render(app, ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

fn measure() -> DiskMeasure {
    DiskMeasure {
        vm_id: "vm".into(),
        source: DiskSourceRecord {
            active_layer: "disk.qcow2".into(),
            ..DiskSourceRecord::default()
        },
        logical_size: 16 * 1024 * 1024 * 1024,
        allocated_estimate: 2 * 1024 * 1024 * 1024,
        free_space: 40 * 1024 * 1024 * 1024,
        sparse_supported: true,
        measured_ms: 1,
        directory: PathBuf::from("/home/user/rec/disks"),
        quota: 4 * 1024 * 1024 * 1024,
        error: None,
        partitions: None,
        partition_error: None,
        partition: None,
    }
}

#[test]
fn the_disks_tab_sits_between_memory_and_core_dumps() {
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let tab = |name: &str| {
        texts(&output)
            .into_iter()
            .find(|(text, _)| text == name)
            .unwrap_or_else(|| panic!("tab {name}"))
            .1
            .center()
            .x
    };
    assert!(tab("Memory") < tab("Disks") && tab("Disks") < tab("Core dumps"));
}

#[test]
fn a_running_vm_shows_the_notice_and_stop_vm_sends_the_toolbars_stop() {
    let mut app = app();
    observer_fixture(&mut app);
    app.focus_panel = Some(Panel::Disks);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    let shown = shown_texts(&mut app, &ctx, size);
    for expected in [
        "Current disk (VM off)",
        "VM running — stop it to inspect",
        "Disk inspection and new dumps need the VM to be off. Saved dumps stay available in the list.",
    ] {
        assert!(shown.iter().any(|text| text == expected), "{expected:?} in {shown:?}");
    }
    assert!(
        !app.submitted
            .iter()
            .any(|command| matches!(command, Command::MeasureDisk { .. })),
        "{:?}",
        app.submitted
    );
    let stop = format!("{} Stop VM", egui_phosphor::regular::STOP);
    click_label(&mut app, &ctx, size, &stop);
    assert!(matches!(app.submitted.last(), Some(Command::Stop)));
}

#[test]
fn a_stopped_vm_measures_once_and_open_sends_the_open_command() {
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    shown_texts(&mut app, &ctx, size);
    let measures = |app: &MonitorApp| {
        app.submitted
            .iter()
            .filter(
                |command| matches!(command, Command::MeasureDisk { vm_id, .. } if vm_id == "vm"),
            )
            .count()
    };
    assert_eq!(measures(&app), 1, "{:?}", app.submitted);
    shown_texts(&mut app, &ctx, size);
    assert_eq!(measures(&app), 1, "asked once");

    app.snapshot.disk_measure = Some(measure());
    let shown = shown_texts(&mut app, &ctx, size);
    assert!(
        shown
            .iter()
            .any(|text| text == "16.0 GiB logical · ≈ 2.0 GiB allocated"),
        "{shown:?}"
    );
    click_label(&mut app, &ctx, size, "Open");
    assert!(matches!(
        app.submitted.last(),
        Some(Command::OpenCurrentDisk { vm_id, .. }) if vm_id == "vm"
    ));
    // A measurement of another VM is not shown for this one.
    app.snapshot.disk_measure = Some(DiskMeasure {
        vm_id: "other".into(),
        ..measure()
    });
    let shown = shown_texts(&mut app, &ctx, size);
    assert!(
        shown.iter().any(|text| text == "Measuring the disk…"),
        "{shown:?}"
    );
}

#[test]
fn a_job_of_this_vm_shows_progress_and_cancel_sends_the_cancel_command() {
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    app.snapshot.disk_measure = Some(measure());
    app.snapshot.disk_job = Some(DiskJobProgress {
        vm_id: "vm".into(),
        purpose: DiskJobPurpose::View,
        stage: DiskJobStage::Converting { percent: 46.0 },
        estimate: 2 * 1024 * 1024 * 1024,
        started_ms: 1,
    });
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    let shown = shown_texts(&mut app, &ctx, size);
    assert!(
        shown.iter().any(|text| text == "Reading the disk… 46 %"),
        "{shown:?}"
    );
    click_label(&mut app, &ctx, size, "Cancel");
    assert!(matches!(
        app.submitted.last(),
        Some(Command::CancelDiskJob { vm_id }) if vm_id == "vm"
    ));
}

fn open_view(app: &mut MonitorApp) {
    // The image does not exist: the readers report that, nothing is spawned.
    app.snapshot.current_disk = Some(CurrentDiskView {
        vm_id: "vm".into(),
        view_id: "view-1".into(),
        image: PathBuf::from("/home/user/rec/disks/.scratch-view-1/root.ext4"),
        extract_dir: PathBuf::from("/home/user/rec/disks/extracted/view-1"),
        taken_ms: 1_800_000_000_000,
        source: DiskSourceRecord {
            active_layer: "disk.qcow2".into(),
            ..DiskSourceRecord::default()
        },
        fs_state: Ext4State::NotClean,
        logical_size: 16 * 1024 * 1024 * 1024,
        allocated_size: 100 * 1024 * 1024,
        kept_as: None,
    });
}

#[test]
fn an_open_view_shows_its_header_and_close_sends_the_close_command() {
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    open_view(&mut app);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    let shown = shown_texts(&mut app, &ctx, size);
    assert!(
        shown
            .iter()
            .any(|text| text.starts_with("Current disk (VM off) · read ")
                && text.ends_with("not cleanly unmounted · disk.qcow2")),
        "{shown:?}"
    );
    assert!(
        shown.iter().any(|text| text.contains("forced off")),
        "{shown:?}"
    );
    click_label(&mut app, &ctx, size, "Close");
    assert!(matches!(
        app.submitted.last(),
        Some(Command::CloseCurrentDisk { vm_id }) if vm_id == "vm"
    ));
}

#[test]
fn the_view_vanishing_because_the_vm_started_leaves_a_note_and_the_stop_shortcut() {
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    open_view(&mut app);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    shown_texts(&mut app, &ctx, size);
    // The backend closed the view and the VM is running.
    app.snapshot.current_disk = None;
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    let shown = shown_texts(&mut app, &ctx, size);
    assert!(
        shown
            .iter()
            .any(|text| text == "Current disk view closed: VM started. Saved dumps stay available."),
        "{shown:?}"
    );
}

#[test]
fn the_details_dock_follows_the_disks_tab() {
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    open_view(&mut app);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    let shown = shown_texts(&mut app, &ctx, size);
    // Details are the view's own: where it came from and its filesystem state
    // (the dock is short, so the rows further down are scrolled out).
    for expected in ["Current disk (VM off)", "Source layer", "Filesystem state"] {
        assert!(
            shown.iter().any(|text| text == expected),
            "{expected:?} in {shown:?}"
        );
    }
}

#[test]
fn dump_disk_and_keep_as_dump_send_their_commands_with_the_hash_settings() {
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    app.snapshot.disk_measure = Some(measure());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1600.0, 900.0);
    let dump = format!("{} Dump disk", egui_phosphor::regular::HARD_DRIVES);
    // The defaults: the image is hashed, the layers are not.
    click_label(&mut app, &ctx, size, &dump);
    assert!(matches!(
        app.submitted.last(),
        Some(Command::DumpDisk { vm_id, hash: true, layer_digests: false, .. }) if vm_id == "vm"
    ));
    // The Settings toggles travel with the command.
    let mut app = self::app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    app.snapshot.disk_measure = Some(measure());
    app.settings.disks.dump_hash = false;
    app.settings.disks.source_digests = true;
    click_label(&mut app, &ctx, size, &dump);
    assert!(matches!(
        app.submitted.last(),
        Some(Command::DumpDisk {
            hash: false,
            layer_digests: true,
            ..
        })
    ));
    // Keep as dump, from the open view.
    let mut app = self::app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    open_view(&mut app);
    app.snapshot.disk_measure = Some(measure());
    click_label(&mut app, &ctx, size, "Keep as dump");
    assert!(matches!(
        app.submitted.last(),
        Some(Command::KeepCurrentDiskAsDump { vm_id, hash: true, layer_digests: false })
            if vm_id == "vm"
    ));
}

#[test]
fn deleting_a_dump_asks_first_then_sends_delete_evidence_for_its_folder() {
    use crate::evidence_delete::Kind;
    let mut app = app();
    stopped_vm(&mut app);
    app.focus_panel = Some(Panel::Disks);
    let root = std::env::temp_dir().join(format!("ant-app-disk-delete-{}", std::process::id()));
    let dir = root.join("disks").join("dump-1");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("root.ext4"), vec![0u8; 4096]).unwrap();
    let dump = antinomie_monitor_core::disks::dump::DiskDump {
        id: "dump-1".into(),
        vm_id: "vm".into(),
        vm_name: "Debian".into(),
        file: "root.ext4".into(),
        finished_ms: Some(2),
        started_ms: 1,
        dir: dir.clone(),
        ..Default::default()
    };
    let ctx = egui::Context::default();
    theme::install(&ctx);
    app.disk_action(
        &ctx,
        Some(crate::disk_view::DiskAction::Delete(Box::new(dump.clone()))),
    );
    assert!(app.submitted.is_empty(), "asked, not sent");
    let Some(Confirm::DeleteEvidence(deletion)) = app.confirm.take() else {
        panic!("a confirmation")
    };
    assert_eq!(deletion.kind, Kind::Disk);
    assert_eq!(deletion.title(), "Delete disk dump");
    assert!(
        deletion.text().contains("disk image"),
        "{}",
        deletion.text()
    );
    assert!(deletion.text().contains("can't be undone"));
    // An imported image's own file is said to stay.
    let imported = crate::evidence_delete::Deletion::disk(&dir, "evidence.ext4", true);
    assert_eq!(imported.kind, Kind::ImportedDisk);
    assert!(imported.text().contains("original image file stays"));
    app.submit_delete_evidence(deletion.clone());
    let [Command::DeleteEvidence {
        vm_id,
        item: antinomie_monitor_core::EvidenceItem::DiskDump { directory },
        confirmed: true,
    }] = &app.submitted[..]
    else {
        panic!("one DeleteEvidence of a disk dump: {:?}", app.submitted);
    };
    assert_eq!(vm_id, "vm");
    assert_eq!(directory, &dir);
    assert!(
        dir.join("root.ext4").exists(),
        "the backend deletes, not the UI"
    );
    // Once the backend deleted it the tab forgets it.
    app.evidence_deleted(&deletion);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_settings_offer_the_dump_hash_and_source_digest_toggles() {
    let mut app = app();
    stopped_vm(&mut app);
    app.settings_open = true;
    app.settings_page = super::super::settings_window::SettingsPage::Disks;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let shown = shown_texts(&mut app, &ctx, egui::vec2(1600.0, 1000.0));
    for label in ["SHA-256 of each disk dump", "SHA-256 of each source layer"] {
        assert!(shown.iter().any(|text| text == label), "{label}: {shown:?}");
    }
    assert!(app.settings.disks.dump_hash && !app.settings.disks.source_digests);
}

#[test]
fn the_diff_and_triage_changed_files_link_to_each_other_through_the_app() {
    use crate::disk_view::{DiskAction, DIFF_JUMP_KEY};
    use antinomie_monitor_core::disks::reader::{DiffEntry, DiffResults, DiffStatus, DiskEntry};
    let mut app = app();
    stopped_vm(&mut app);
    let ctx = egui::Context::default();
    // Disks to Triage: the Changed files tab, filtered to the path.
    app.disk_action(&ctx, Some(DiskAction::ShowInTriage("/etc/passwd".into())));
    assert_eq!(app.focus_panel, Some(Panel::Triage));
    let draft =
        ctx.data(|data| data.get_temp::<String>(egui::Id::new(("triage-filter-draft", 2usize))));
    assert_eq!(draft.as_deref(), Some("file.path == \"/etc/passwd\""));

    // Triage to Disks: with a diff open, the path is selected there.
    let file = DiskEntry {
        name: "passwd".into(),
        addressable: true,
        kind: antinomie_monitor_core::disks::reader::DiskEntryKind::File,
        size: 10,
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 1,
        atime: 1,
        ctime: 1,
        link_target: None,
    };
    let results = DiffResults {
        entries: vec![DiffEntry {
            path: "/etc/passwd".into(),
            status: DiffStatus::Added,
            before: None,
            after: Some(file),
            reasons: Vec::new(),
        }],
        added: 1,
        ..DiffResults::default()
    };
    app.disk_view.show_diff_for_test(&ctx, results);
    app.focus_panel = None;
    ctx.data_mut(|data| data.insert_temp(egui::Id::new(DIFF_JUMP_KEY), "/etc/passwd".to_string()));
    app.apply_triage_navigation(&ctx, None);
    assert_eq!(app.focus_panel, Some(Panel::Disks));
    assert_eq!(
        app.disk_view.diff_selected_path_for_test().as_deref(),
        Some("/etc/passwd")
    );
    // A path the diff does not list moves nothing.
    app.focus_panel = None;
    ctx.data_mut(|data| data.insert_temp(egui::Id::new(DIFF_JUMP_KEY), "/not/there".to_string()));
    app.apply_triage_navigation(&ctx, None);
    assert_eq!(app.focus_panel, None);
}
