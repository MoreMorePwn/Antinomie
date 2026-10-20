// SPDX-License-Identifier: MIT
//! Headless tests of the Disks tab's third phase: checkpoint sources,
//! partitions, diff, content Find, the qcow2 import and the Triage links.
use super::*;
use crate::disk_view::{
    diff::{Against, Diff, Stage},
    source,
};
use antinomie_monitor_core::{
    disks::{
        partition::{Partition, PartitionFs, PartitionTable, TableKind},
        reader::{DiffEntry, DiffReason, DiffResults, DiffStatus},
        DiskSourceKind,
    },
    VmCheckpoint, VmSnapshotConsistency, VmSnapshotMode,
};

fn checkpoint(id: &str, name: &str, created: u64, deleted: bool) -> VmCheckpoint {
    VmCheckpoint {
        id: id.into(),
        parent_id: None,
        name: name.into(),
        description: String::new(),
        created_unix_ms: created,
        mode: VmSnapshotMode::Disk,
        consistency: VmSnapshotConsistency::Stopped,
        config: VmConfig::default(),
        disk_size: 0,
        memory_size: 0,
        compatible: true,
        compatibility_note: None,
        deleted,
    }
}

fn checkpoint_measure(id: &str, name: &str) -> DiskMeasure {
    let mut measure = measure();
    measure.source.kind = DiskSourceKind::Checkpoint {
        id: id.into(),
        name: name.into(),
    };
    measure
}

fn partition(index: u32, fs: PartitionFs, root: bool, length: u64) -> Partition {
    Partition {
        index,
        start: u64::from(index) * 1024 * 1024,
        length,
        kind: if fs == PartitionFs::Ext4 {
            "Linux filesystem".into()
        } else {
            "Linux swap".into()
        },
        name: format!("part{index}"),
        fs,
        root,
        linux: true,
    }
}

fn partitioned(partitions: Vec<Partition>, chosen: Option<u32>) -> DiskMeasure {
    let mut measure = measure();
    measure.partitions = Some(PartitionTable {
        kind: TableKind::Gpt,
        partitions,
        skipped: 0,
    });
    measure.partition = chosen;
    measure
}

#[test]
fn the_source_picker_offers_saved_checkpoints_and_never_deleted_ones() {
    let checkpoints = vec![
        checkpoint("a", "older", 1_000, false),
        checkpoint("b", "newest", 3_000, false),
        checkpoint("c", "gone", 2_000, true),
    ];
    let offered: Vec<_> = source::offered(&checkpoints)
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(offered, ["newest", "older"]);
    assert_eq!(
        source::checkpoint_label(&checkpoints[1])
            .split(" · ")
            .last(),
        Some("stopped")
    );
}

#[test]
fn choosing_a_checkpoint_measures_it_and_names_the_entry_after_it() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.checkpoints = vec![checkpoint("cp-1", "before-run", 1_800_000_000_000, false)];
    scene.measure = Some(measure());
    let mut view = DiskView {
        checkpoints: scene.checkpoints.clone(),
        ..DiskView::default()
    };
    // The first frame measures the current disk (it already has an answer).
    scene.settle(&mut view, &ctx);
    view.waiting = None;
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Current disk (VM off)"), "{texts:?}");
    assert!(has(&texts, "Source"));

    // Another source: the old measurement is not shown, a new one is asked.
    view.pick_source(DiskSourceSpec::Checkpoint("cp-1".into()));
    let (_, action) = scene.frame(&mut view, &ctx, Vec::new());
    assert_eq!(
        action,
        Some(DiskAction::Measure(Pick::of_source(
            DiskSourceSpec::Checkpoint("cp-1".into())
        )))
    );
    view.waiting = None;
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Disk at before-run (VM off)"), "{texts:?}");
    assert!(has(&texts, "Measuring the disk…"), "{texts:?}");
    assert!(!has(&texts, "16.0 GiB logical · ≈ 1.9 GiB allocated"));

    // Its measurement arrives: the card is for the checkpoint.
    scene.measure = Some(checkpoint_measure("cp-1", "before-run"));
    view.waiting = None;
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        has(&texts, "Disk at before-run of Debian QA (VM off)"),
        "{texts:?}"
    );
    assert!(has(&texts, "16.0 GiB logical · ≈ 1.9 GiB allocated"));
    assert_eq!(
        scene.click(&mut view, &ctx, "Open"),
        Some(DiskAction::Open(Pick::of_source(
            DiskSourceSpec::Checkpoint("cp-1".into())
        )))
    );
    // The same rule as the current disk: with the VM running, nothing is offered.
    scene.vm_off = false;
    scene.can_stop = true;
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("need the VM to be off")),
        "{texts:?}"
    );
}

#[test]
fn a_dump_of_a_checkpoint_says_which_in_its_row_and_details() {
    let recordings = Recordings::new();
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let dump = recordings.dump("cp-dump", 1_800_000_000_000, |dump| {
        dump.source.kind = DiskSourceKind::Checkpoint {
            id: "cp-1".into(),
            name: "before-run".into(),
        };
        dump.source.partition = Some(partition(2, PartitionFs::Ext4, true, 8 << 20));
    });
    let mut view = DiskView::default();
    view.scan(&scene.roots);
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("disk at before-run") && text.contains("partition 2")),
        "{texts:?}"
    );
    select_dump(&mut view, &scene, &dump);
    let (details, _) = scene.details(&mut view, &ctx);
    // Details without a selected file show the dump's record.
    view.selection = None;
    let (details2, _) = scene.details(&mut view, &ctx);
    let all: Vec<_> = details.into_iter().chain(details2).collect();
    assert!(has(&all, "Disk at before-run"), "{all:?}");
    assert!(has(&all, "Partition"), "{all:?}");
}

#[test]
fn a_partitioned_disk_lists_its_partitions_and_marks_the_unsupported_ones() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.measure = Some(partitioned(
        vec![
            partition(1, PartitionFs::Other, false, 4 << 20),
            partition(2, PartitionFs::Ext4, true, 8 << 20),
            partition(3, PartitionFs::Ext4, false, 6 << 20),
        ],
        Some(2),
    ));
    let mut view = DiskView {
        measured_for: Some(("vm".into(), true, Pick::default())),
        ..DiskView::default()
    };
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        has(&texts, "GPT partition table · 3 partitions"),
        "{texts:?}"
    );
    assert!(
        texts.iter().any(|text| text == "unsupported filesystem"),
        "{texts:?}"
    );
    assert!(has(&texts, "Save partition to host…"));
    // The default (the root) is what Open uses.
    assert_eq!(
        scene.click(&mut view, &ctx, "Open"),
        Some(DiskAction::Open(Pick::default()))
    );
    // Choosing the other ext4 partition measures it again.
    view.waiting = None;
    let label = "3 · part3 · 6.0 MiB · Linux filesystem";
    scene.click(&mut view, &ctx, label);
    let (_, action) = scene.frame(&mut view, &ctx, Vec::new());
    assert_eq!(
        action,
        Some(DiskAction::Measure(Pick {
            source: DiskSourceSpec::Current,
            partition: Some(3)
        }))
    );
}

#[test]
fn a_disk_without_an_ext4_partition_is_unsupported_not_openable() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.measure = Some(partitioned(
        vec![partition(1, PartitionFs::Other, false, 4 << 20)],
        None,
    ));
    let mut view = DiskView {
        measured_for: Some(("vm".into(), true, Pick::default())),
        ..DiskView::default()
    };
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("unsupported filesystem: no ext2/3/4 partition")),
        "{texts:?}"
    );
    // Neither Open nor Dump disk is offered as an action.
    assert_eq!(scene.click(&mut view, &ctx, "Open"), None);
    assert!(view
        .dump_blocked(&DiskContext {
            vm: scene.vm.as_ref(),
            recordings: None,
            recording_roots: &[],
            qemu_img: Path::new("qemu-img"),
            vm_off: true,
            can_stop_vm: false,
            current_disk: None,
            measure: scene.measure.as_ref(),
            job: None,
            reference: None,
            checkpoints: &[],
            triage_paths: &scene.triage_paths,
            other_job: false,
            font_size: 16.0,
            settings: &mut DiskSettings::default(),
        })
        .is_some_and(|reason| reason.contains("unsupported filesystem")));
    // The row says so too.
    assert!(has(
        &scene.settle(&mut view, &ctx),
        "unsupported filesystem"
    ));
}

#[test]
fn saving_a_partition_asks_the_backend_with_the_chosen_file() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = DiskView::default();
    let (sender, receiver) = std::sync::mpsc::channel();
    view.partition_save = Some(dump_actions::PartitionSave::new(
        DiskSourceSpec::Base,
        1,
        receiver,
    ));
    sender
        .send(Ok(Some(PathBuf::from("/home/user/partition-1.bin"))))
        .unwrap();
    let (_, action) = scene.frame(&mut view, &ctx, Vec::new());
    assert_eq!(
        action,
        Some(DiskAction::SavePartition {
            source: DiskSourceSpec::Base,
            partition: 1,
            path: PathBuf::from("/home/user/partition-1.bin"),
        })
    );
    assert!(view.partition_save.is_none());
    // A closed chooser asks for nothing.
    let (sender, receiver) = std::sync::mpsc::channel();
    view.partition_save = Some(dump_actions::PartitionSave::new(
        DiskSourceSpec::Base,
        1,
        receiver,
    ));
    sender.send(Ok(None)).unwrap();
    assert_eq!(scene.frame(&mut view, &ctx, Vec::new()).1, None);
}

// --- diff -----------------------------------------------------------------

fn side(kind: DiskEntryKind, size: u64) -> DiskEntry {
    entry("x", kind, size, 0o644)
}

fn change(path: &str, status: DiffStatus, reasons: &[DiffReason]) -> DiffEntry {
    let file = side(DiskEntryKind::File, 10);
    DiffEntry {
        path: path.into(),
        status,
        before: (status != DiffStatus::Added).then(|| file.clone()),
        after: (status != DiffStatus::Deleted).then_some(file),
        reasons: reasons.to_vec(),
    }
}

fn results() -> DiffResults {
    DiffResults {
        entries: vec![
            change("/etc/new-file", DiffStatus::Added, &[]),
            change("/etc/passwd", DiffStatus::Changed, &[DiffReason::Size]),
            change("/lib/libc.so.6", DiffStatus::Changed, &[DiffReason::Time]),
            change("/home/user/notes.txt", DiffStatus::Deleted, &[]),
            DiffEntry {
                path: "/opt".into(),
                status: DiffStatus::Added,
                before: None,
                after: Some(side(DiskEntryKind::Dir, 0)),
                reasons: Vec::new(),
            },
        ],
        added: 2,
        deleted: 1,
        changed: 2,
        scanned: 321,
        ..DiffResults::default()
    }
}

fn diffing(scene: &mut Scene) -> DiskView {
    let mut view = opened(scene, root_entries());
    view.diff = Some(Diff::new(
        Against::Source(DiskSourceSpec::Base),
        "Base image".into(),
        Stage::Running,
    ));
    view
}

#[test]
fn a_diff_lists_changes_with_badges_totals_and_filters() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = diffing(&mut scene);
    // While the reader works: a spinner and Cancel, no rows.
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Comparing the two images…"), "{texts:?}");
    assert!(has(&texts, "Cancel"));

    view.diff_finished(&ctx, Ok(results()));
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.starts_with("Changes in Current disk since Base image")),
        "{texts:?}"
    );
    assert!(has(&texts, "+2 added") && has(&texts, "−1 deleted") && has(&texts, "~2 changed"));
    assert!(has(&texts, "· 321 entries compared"));
    for wanted in [
        "+  /etc/new-file",
        "~  /etc/passwd   [size]",
        "~  /lib/libc.so.6   [time]",
        "−  /home/user/notes.txt",
    ] {
        assert!(has(&texts, wanted), "{wanted:?} in {texts:?}");
    }
    assert!(
        texts.iter().any(|text| text.contains("Block evidence")),
        "{texts:?}"
    );
    // The paths are published for Triage, files only.
    let published = ctx
        .data(|data| data.get_temp::<Arc<BTreeSet<String>>>(egui::Id::new(DIFF_PATHS_KEY)))
        .expect("published");
    assert!(published.contains("/etc/passwd") && !published.contains("/opt"));

    // Filters.
    scene.click(&mut view, &ctx, "Deleted");
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "−  /home/user/notes.txt"));
    assert!(!has(&texts, "+  /etc/new-file"));
    scene.click(&mut view, &ctx, "All");
    view.diff.as_mut().unwrap().filter.hide_metadata = true;
    view.diff.as_mut().unwrap().dirty = true;
    let texts = scene.settle(&mut view, &ctx);
    assert!(!has(&texts, "~  /lib/libc.so.6   [time]"), "{texts:?}");
    assert!(has(&texts, "~  /etc/passwd   [size]"));
    view.diff.as_mut().unwrap().filter.hide_metadata = false;
    view.diff.as_mut().unwrap().filter.text = "NEW-".into();
    view.diff.as_mut().unwrap().dirty = true;
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "+  /etc/new-file") && !has(&texts, "~  /etc/passwd   [size]"));
}

#[test]
fn a_diff_row_fills_the_details_with_both_sides_and_the_triage_link() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.triage_paths = Arc::new(["/etc/passwd".to_string()].into_iter().collect());
    let mut view = diffing(&mut scene);
    view.diff_finished(&ctx, Ok(results()));
    scene.settle(&mut view, &ctx);
    // A row that Triage also lists carries the marker.
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.starts_with("~  /etc/passwd") && text.ends_with("◆ in Triage")),
        "{texts:?}"
    );
    assert!(!texts
        .iter()
        .any(|text| text.starts_with("+  /etc/new-file") && text.contains("Triage")));
    scene.click(&mut view, &ctx, "~  /etc/passwd   [size]   ◆ in Triage");
    assert_eq!(
        view.diff.as_ref().unwrap().entry().unwrap().path,
        "/etc/passwd"
    );
    // The selected file is selected in the image too: Extract and Info work.
    assert_eq!(view.selection.as_ref().unwrap().path, "/etc/passwd");
    let (details, _) = scene.details(&mut view, &ctx);
    for wanted in [
        "Disk difference",
        "Changed: size",
        "Before (reference)",
        "After (this image)",
        "Block evidence: the path differs between the two images.",
        "The selected run's Changed files (observed operations) lists it too.",
    ] {
        assert!(has(&details, wanted), "{wanted:?} in {details:?}");
    }
    assert_eq!(
        scene.click_details(&mut view, &ctx, "Show in Triage › Changed files"),
        Some(DiskAction::ShowInTriage("/etc/passwd".into()))
    );
    // A path Triage does not list says so, with no link.
    view.diff.as_mut().unwrap().select_path("/etc/new-file");
    view.sync_diff_selection();
    let (details, _) = scene.details(&mut view, &ctx);
    assert!(
        has(&details, "Not in the selected run's Changed files."),
        "{details:?}"
    );
    assert!(!has(&details, "Show in Triage › Changed files"));
    // A deleted file exists only in the reference: its Details are the diff.
    view.diff
        .as_mut()
        .unwrap()
        .select_path("/home/user/notes.txt");
    view.sync_diff_selection();
    assert!(view.selection.is_none());
    let (details, _) = scene.details(&mut view, &ctx);
    assert!(has(&details, "Deleted since the reference"), "{details:?}");
}

#[test]
fn triage_can_reveal_a_path_and_closing_the_diff_withdraws_the_paths() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = diffing(&mut scene);
    // Before the results are in, the request waits for them.
    assert!(view.reveal_diff("/etc/passwd"));
    view.diff_finished(&ctx, Ok(results()));
    assert_eq!(
        view.diff
            .as_ref()
            .unwrap()
            .entry()
            .map(|entry| entry.path.as_str()),
        Some("/etc/passwd")
    );
    assert!(view.reveal_diff("/etc/new-file"));
    assert!(!view.reveal_diff("/not/in/the/diff"));
    scene.click(&mut view, &ctx, "Close diff");
    assert!(view.diff.is_none());
    assert!(ctx
        .data(|data| data.get_temp::<Arc<BTreeSet<String>>>(egui::Id::new(DIFF_PATHS_KEY)))
        .is_none());
    // Nothing to reveal in without a diff.
    assert!(!view.reveal_diff("/etc/passwd"));
}

#[test]
fn a_bounded_or_failed_diff_says_so() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = diffing(&mut scene);
    let mut limited = results();
    limited.truncated = true;
    limited.timed_out = true;
    limited.unreadable = 2;
    view.diff_finished(&ctx, Ok(limited));
    let texts = scene.settle(&mut view, &ctx);
    for part in [
        "Only the first 5 differences are listed",
        "time or entry limit",
        "2 folder(s) could not be read",
    ] {
        assert!(
            texts.iter().any(|text| text.contains(part)),
            "{part} in {texts:?}"
        );
    }
    let mut view = diffing(&mut scene);
    view.diff_finished(&ctx, Err("the reference image: damaged filesystem".into()));
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text.contains("damaged filesystem")),
        "{texts:?}"
    );
}

#[test]
fn comparing_with_a_checkpoint_asks_the_backend_for_a_reference_then_starts_the_reader() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.checkpoints = vec![checkpoint("cp-1", "before-run", 1, false)];
    let mut view = opened(&mut scene, root_entries());
    view.checkpoints = scene.checkpoints.clone();
    let source = DiskSourceSpec::Checkpoint("cp-1".into());
    // The menu's choice, made directly.
    let mut action = None;
    let _ = ctx.run(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            let cx = DiskContext {
                vm: scene.vm.as_ref(),
                recordings: None,
                recording_roots: &[],
                qemu_img: Path::new("qemu-img"),
                vm_off: true,
                can_stop_vm: false,
                current_disk: scene.view.as_ref(),
                measure: None,
                job: None,
                reference: None,
                checkpoints: &scene.checkpoints,
                triage_paths: &scene.triage_paths,
                other_job: false,
                font_size: 16.0,
                settings: &mut scene.settings,
            };
            view.start_compare(ui.ctx(), &cx, Against::Source(source.clone()));
            action = view.action.take();
        });
    });
    assert_eq!(action, Some(DiskAction::Reference(source.clone())));
    assert!(matches!(
        view.diff.as_ref().unwrap().stage,
        Stage::Reference { .. }
    ));
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Reading Disk at before-run…"), "{texts:?}");
    // The backend's job runs, then the reference image is there.
    scene.job = Some(DiskJobProgress {
        vm_id: "vm".into(),
        purpose: DiskJobPurpose::Reference,
        stage: DiskJobStage::Converting { percent: 40.0 },
        estimate: 1,
        started_ms: 1,
    });
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "Reading Disk at before-run… 40 %"), "{texts:?}");
    scene.job = None;
    let mut reference = open_view(Ext4State::Clean);
    reference.view_id = "ref".into();
    reference.source.kind = DiskSourceKind::Checkpoint {
        id: "cp-1".into(),
        name: "before-run".into(),
    };
    scene.reference = Some(reference);
    scene.frame(&mut view, &ctx, Vec::new());
    assert!(matches!(
        view.diff.as_ref().unwrap().stage,
        Stage::Running | Stage::Failed(_)
    ));
    // A job that ended without a reference is a failure, not a hang.
    let mut view = opened(&mut scene, root_entries());
    scene.reference = None;
    view.diff = Some(Diff::new(
        Against::Source(DiskSourceSpec::Base),
        "Base image".into(),
        Stage::Reference { seen: true },
    ));
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text.contains("could not be read")),
        "{texts:?}"
    );
}

// --- content Find ----------------------------------------------------------

#[test]
fn content_find_queues_a_bounded_search_and_shows_where_it_hit() {
    use antinomie_monitor_core::disks::reader::FoundEntry;
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.find.query = "the milk".into();
    view.find.mode = find::Mode::ContentAnyCase;
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts.iter().any(|text| text
            .starts_with("Content search reads regular files: at most the first 16.0 MiB")
            && text.contains("512 MiB in all")
            && text.contains("60 s")),
        "{texts:?}"
    );
    scene.click(&mut view, &ctx, "Find");
    let (_, job) = view.search_queue.last().expect("a search is queued");
    assert!(matches!(
        &job.request,
        DiskRequest::Find { query: FindQuery { pattern, mode: FindMode::ContentAnyCase } } if pattern == "the milk"
    ));
    assert!(view.find.running);

    view.accept(
        &ctx,
        worker::Answer {
            token: *view.purposes.keys().next_back().unwrap(),
            reply: Ok(Ok(DiskAnswer::Found(FindResults {
                query: FindQuery {
                    pattern: "the milk".into(),
                    mode: FindMode::ContentAnyCase,
                },
                matches: vec![FoundEntry {
                    path: "/home/user/notes.txt".into(),
                    kind: DiskEntryKind::File,
                    offset: Some(9),
                    snippet: Some("remember the milk.".into()),
                }],
                truncated: false,
                timed_out: false,
                scanned: 30,
                files_read: 12,
                bytes_read: 3 * 1024 * 1024,
                partial_files: 2,
                byte_limit_reached: true,
            }))),
            placed: None,
        },
    );
    let texts = scene.settle(&mut view, &ctx);
    assert!(has(&texts, "at byte 9: remember the milk."), "{texts:?}");
    assert!(
        texts
            .iter()
            .any(|text| text.contains("12 files read, 3.0 MiB")
                && text.contains("2 larger than the per-file limit")),
        "{texts:?}"
    );
    assert!(
        texts
            .iter()
            .any(|text| text.contains("limit on bytes read ended the search")),
        "{texts:?}"
    );
}

#[test]
fn a_running_content_search_can_be_cancelled() {
    let ctx = context();
    let mut scene = Scene::stopped();
    let mut view = opened(&mut scene, root_entries());
    load_root(&mut view, root_entries());
    view.find.query = "needle".into();
    view.find.mode = find::Mode::Content;
    scene.click(&mut view, &ctx, "Find");
    assert!(view.find.running && !view.search_queue.is_empty());
    scene.click(&mut view, &ctx, "Cancel");
    assert!(!view.find.running);
    assert!(view.search_queue.is_empty());
    assert!(!view.purposes.values().any(|p| matches!(p, Purpose::Find)));
    assert!(view.restart_search);
    // The next search can start at once.
    let texts = scene.settle(&mut view, &ctx);
    assert!(!has(&texts, "Searching…"));
    assert_eq!(find::Mode::ALL.len(), 5);
    assert!(find::Mode::ALL.iter().filter(|m| m.is_content()).count() == 2);
}

// --- qcow2 import ----------------------------------------------------------

#[test]
fn a_qcow2_file_is_handed_to_the_backend_not_read_by_the_tab() {
    let recordings = Recordings::new();
    let ctx = context();
    let mut scene = Scene::with_dumps(&recordings);
    let mut view = DiskView::default();
    scene.settle(&mut view, &ctx);
    scene.click(
        &mut view,
        &ctx,
        &format!("{} Import image…", egui_phosphor::regular::FILE_ARROW_UP),
    );
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("converted into a new dump by qemu-img inside the sandbox")),
        "{texts:?}"
    );
    let qcow2 = recordings.0.join("disk.qcow2");
    let mut bytes = b"QFI\xfb".to_vec();
    bytes.extend(vec![0u8; 4096]);
    std::fs::write(&qcow2, bytes).unwrap();
    view.import.as_mut().unwrap().path = qcow2.display().to_string();
    assert_eq!(
        scene.click(&mut view, &ctx, "Import"),
        Some(DiskAction::ImportQcow2(qcow2.clone()))
    );
    assert!(view.import.is_none());
    // Another job running: the dialog stays open and says why.
    scene.settle(&mut view, &ctx);
    view.open_import();
    view.import.as_mut().unwrap().path = qcow2.display().to_string();
    scene.job = Some(DiskJobProgress {
        vm_id: "vm".into(),
        purpose: DiskJobPurpose::Import,
        stage: DiskJobStage::Converting { percent: 30.0 },
        estimate: 1 << 20,
        started_ms: 1,
    });
    assert_eq!(scene.click(&mut view, &ctx, "Import"), None);
    assert!(view
        .import
        .as_ref()
        .unwrap()
        .error
        .as_deref()
        .is_some_and(|e| e.contains("Another disk job")));
}

#[test]
fn an_import_job_shows_progress_and_cancel_above_any_entry() {
    let ctx = context();
    let mut scene = Scene::stopped();
    scene.measure = Some(measure());
    scene.job = Some(DiskJobProgress {
        vm_id: "vm".into(),
        purpose: DiskJobPurpose::Import,
        stage: DiskJobStage::Converting { percent: 42.0 },
        estimate: 1 << 20,
        started_ms: 1,
    });
    let mut view = DiskView::default();
    let texts = scene.settle(&mut view, &ctx);
    assert!(
        has(&texts, "Converting the qcow2 image in the sandbox… 42 %"),
        "{texts:?}"
    );
    assert!(has(&texts, "converting… 42 %"), "{texts:?}");
    assert_eq!(
        scene.click(&mut view, &ctx, "Cancel"),
        Some(DiskAction::Cancel)
    );
}
