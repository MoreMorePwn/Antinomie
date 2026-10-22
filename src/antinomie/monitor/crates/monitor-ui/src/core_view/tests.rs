// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use antinomie_monitor_core::core_dump::{CoreMapping, CoreThread, MappedFile};

pub(super) struct Fixture {
    pub(super) view: CoreView,
    pub(super) directory: PathBuf,
}

fn wait_catalog(view: &mut CoreView) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while view.catalog_job.is_some() {
        view.poll_catalog();
        assert!(Instant::now() < deadline, "catalog worker did not finish");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn timed_refresh(view: &mut CoreView, active: bool) {
    let now = view.catalog_checked.unwrap_or_else(Instant::now) + Duration::from_secs(5);
    view.refresh_catalog_if_due(active, now);
    assert!(
        view.catalog_job.is_some(),
        "a due refresh starts without clicking Refresh"
    );
    wait_catalog(view);
}

fn growing_elf(path: &Path) -> usize {
    // Two real PRSTATUS notes and two PT_LOAD mappings; the second load is
    // advertised as 32 octets but initially only its first 16 are retained.
    let note_offset = 64 + 3 * 56;
    let payload_offset = note_offset + 2 * 356;
    let mut data = vec![0u8; payload_offset + 32];
    data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    data[16..18].copy_from_slice(&4u16.to_le_bytes());
    data[18..20].copy_from_slice(&62u16.to_le_bytes());
    data[32..40].copy_from_slice(&64u64.to_le_bytes());
    data[54..56].copy_from_slice(&56u16.to_le_bytes());
    data[56..58].copy_from_slice(&3u16.to_le_bytes());
    data[64..68].copy_from_slice(&4u32.to_le_bytes());
    data[72..80].copy_from_slice(&(note_offset as u64).to_le_bytes());
    data[96..104].copy_from_slice(&712u64.to_le_bytes());
    for index in 0..2 {
        let header = 120 + index * 56;
        data[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        data[header + 4..header + 8].copy_from_slice(&5u32.to_le_bytes());
        data[header + 8..header + 16]
            .copy_from_slice(&((payload_offset + index * 16) as u64).to_le_bytes());
        data[header + 16..header + 24]
            .copy_from_slice(&(0x400000u64 + index as u64 * 0x1000).to_le_bytes());
        data[header + 32..header + 40]
            .copy_from_slice(&(if index == 0 { 16u64 } else { 32u64 }).to_le_bytes());
        data[header + 40..header + 48].copy_from_slice(&4096u64.to_le_bytes());
        let note = note_offset + index * 356;
        data[note..note + 4].copy_from_slice(&5u32.to_le_bytes());
        data[note + 4..note + 8].copy_from_slice(&336u32.to_le_bytes());
        data[note + 8..note + 12].copy_from_slice(&1u32.to_le_bytes());
        data[note + 12..note + 17].copy_from_slice(b"CORE\0");
        data[note + 52..note + 56].copy_from_slice(&(77u32 + index as u32).to_le_bytes());
    }
    fs::write(path, &data).unwrap();
    data.len()
}

#[test]
fn live_catalog_tracks_real_capture_lifecycle_without_resetting_selection() {
    use antinomie_monitor_core::RunArtifactState as State;
    let mut fixture = Fixture::new();
    let roots = vec![fixture.directory.clone()];
    fixture.view.set_catalog_scope(&roots, Some("chosen"));
    let selected = fixture.directory.join("runs/live/core");
    fs::create_dir_all(&selected).unwrap();
    fixture.view.selected = None;
    fixture.view.selected_directory = Some(selected.clone());
    fixture.view.code = "saved code".into();
    fixture.view.notes_query = "pid == 123".into();
    fixture.view.hide_list = true;
    for state in [
        State::WaitingForRootExit,
        State::InProgress,
        State::Complete,
    ] {
        let artifacts = antinomie_monitor_core::RunArtifacts {
            vm_id: "chosen".into(),
            boot_id: "boot".into(),
            run_id: "live".into(),
            core_state: state,
            core_dump: (state != State::WaitingForRootExit).then(|| selected.join("process.elf")),
            ..Default::default()
        };
        fs::write(
            selected.parent().unwrap().join("artifacts.json"),
            serde_json::to_vec(&artifacts).unwrap(),
        )
        .unwrap();
        // Deliberately not an ELF: catalog discovery must never parse it.
        if state != State::WaitingForRootExit {
            fs::write(selected.join("process.elf"), b"unfinished prefix").unwrap();
        }
        timed_refresh(&mut fixture.view, true);
        assert_eq!(fixture.view.acquired[0].state, state);
        assert_eq!(fixture.view.selected_directory.as_ref(), Some(&selected));
        assert!(fixture.view.selected.is_none() && fixture.view.job.is_none());
        assert_eq!(fixture.view.code, "saved code");
        assert_eq!(fixture.view.notes_query, "pid == 123");
        assert!(fixture.view.hide_list);
    }
    assert!(fixture.view.catalog_issues.is_empty());
    assert_eq!(fixture.view.catalog_interval(false), None);
    assert_eq!(
        fixture.view.catalog_interval(true),
        Some(Duration::from_secs(5))
    );
    assert!(!selected.join("metadata.json").exists());
}

#[test]
fn live_manual_metadata_refresh_keeps_loaded_inspection_and_filters() {
    use antinomie_monitor_core::RunArtifactState as State;
    let mut fixture = Fixture::new();
    fixture
        .view
        .set_catalog_scope(&[fixture.directory.clone()], Some("chosen"));
    fixture.view.selected_directory = Some(fixture.directory.clone());
    fixture.view.thread_index = 1;
    fixture.view.code = "saved analysis".into();
    fixture.view.notes_query = "NT_FILE".into();
    let directory = fixture.directory.join("core-captures/manual");
    fs::create_dir_all(&directory).unwrap();
    let mut capture = ProcessCoreCapture {
        format: 1,
        id: "manual".into(),
        vm_id: "chosen".into(),
        boot_id: "boot".into(),
        source_run_id: None,
        restored_from_capture_id: None,
        target: antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 42,
            tgid: 123,
            start_boot_ns: 1,
        },
        directory: directory.clone(),
        file: None,
        state: State::WaitingForRootExit,
        phase: ProcessCorePhase::Admission,
        stored_size: 0,
        guest_size: None,
        sha256: None,
        pause_released: None,
        max_size: 1024 * 1024,
        timeout_ms: 5000,
        nonce: [1, 2],
        guest_handle: None,
        guest_status: None,
        issue: None,
        requested_max_size: None,
        guest_max_size: None,
        stored_bytes: None,
        expected_size: None,
        allocated_size: None,
        reason: None,
    };
    for (phase, state) in [
        (ProcessCorePhase::Admission, State::WaitingForRootExit),
        (ProcessCorePhase::Transfer, State::InProgress),
        (ProcessCorePhase::Finished, State::Complete),
    ] {
        capture.phase = phase;
        capture.state = state;
        if phase == ProcessCorePhase::Finished {
            capture.file = Some(directory.join("process.elf"));
            capture.stored_size = 64;
            capture.guest_size = Some(64);
            capture.sha256 = Some("0".repeat(64));
            capture.pause_released = Some(true);
            fs::write(directory.join("process.elf"), [0; 64]).unwrap();
        }
        fs::write(
            directory.join("core.json"),
            serde_json::to_vec(&capture).unwrap(),
        )
        .unwrap();
        timed_refresh(&mut fixture.view, true);
        assert_eq!(fixture.view.manual[0].phase, phase);
        assert_eq!(fixture.view.manual[0].state, state);
        assert_eq!(
            fixture.view.selected_directory.as_ref(),
            Some(&fixture.directory)
        );
        assert_eq!(
            fixture.view.selected.as_ref().unwrap().core.threads[fixture.view.thread_index].tid,
            102
        );
        assert!(fixture.view.page.is_some());
        assert_eq!(fixture.view.code, "saved analysis");
        assert_eq!(fixture.view.notes_query, "NT_FILE");
        assert!(fixture.view.job.is_none());
    }
    assert!(fixture.view.catalog_issues.is_empty());
    assert_eq!(fixture.view.catalog_interval(false), None);
}

#[test]
fn initial_open_is_adopted_but_old_prefix_page_is_rejected() {
    let mut fixture = Fixture::new();
    let record = fixture.view.selected.as_ref().unwrap().clone();
    fixture
        .view
        .start(move || Ok(opened_reply(record, String::new())));
    fixture
        .view
        .set_catalog_scope(&[fixture.directory.clone()], Some("chosen"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while fixture.view.job.is_some() {
        fixture.view.poll();
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        fixture.view.selected.as_ref().unwrap().core.threads[0].tid,
        101
    );
    let (release, wait) = mpsc::sync_channel(1);
    fixture.view.start(move || {
        wait.recv().unwrap();
        Ok(Reply::Page(0x400000, vec![Some(0x90)]))
    });
    fixture.view.selected_stamp = None;
    release.send(()).unwrap();
    while fixture.view.job.is_some() {
        fixture.view.poll();
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        fixture.view.page.is_none(),
        "old prefix page cannot undo metadata invalidation"
    );
}

#[test]
fn growing_selected_core_refreshes_prefix_and_preserves_loaded_view() {
    let mut fixture = Fixture::new();
    fixture
        .view
        .set_catalog_scope(&[fixture.directory.clone()], Some("chosen"));
    let file = fixture.directory.join("growing.elf");
    let initial_size = growing_elf(&file);
    let mut record = fixture.view.selected.take().unwrap();
    record.core = CoreDump::open(&file).unwrap();
    fixture.view.selected_stamp = core_file_stamp(&file);
    fixture.view.selected_directory = Some(record.dir.clone());
    fixture.view.selected = Some(record);
    fixture.view.thread_index = 1;
    fixture.view.mapping_index = 1;
    fixture.view.window_offset = 16;
    fixture.view.code = "retained disassembly".into();
    fixture.view.code_address = "401010".into();
    fixture.view.notes_query = "tid == 78".into();
    fixture.view.tab = Tab::Code;
    fixture.view.hide_list = true;
    timed_refresh(&mut fixture.view, true);
    let catalog_stamp = fixture.view.catalog_stamp;
    assert!(
        fixture.view.page.is_some(),
        "unchanged source preserves cached page"
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(&[0x90; 16])
        .unwrap();
    timed_refresh(&mut fixture.view, true);
    let core = &fixture.view.selected.as_ref().unwrap().core;
    assert_eq!(core.source_size, initial_size as u64 + 16);
    assert_eq!(core.threads[fixture.view.thread_index].tid, 78);
    assert_eq!(core.mappings[fixture.view.mapping_index].start, 0x401000);
    assert_eq!(core.mappings[1].available_size, 32);
    assert_eq!(fixture.view.window_offset, 16);
    assert_eq!(fixture.view.code, "retained disassembly");
    assert_eq!(fixture.view.code_address, "401010");
    assert_eq!(fixture.view.notes_query, "tid == 78");
    assert!(fixture.view.tab == Tab::Code && fixture.view.hide_list);
    assert_eq!(
        fixture.view.catalog_stamp, catalog_stamp,
        "source refresh works with unchanged catalog metadata"
    );
    assert!(fixture.view.page.is_none() && fixture.view.job.is_none());
    // Malformed changed prefixes retain the last valid view and retry later.
    fs::write(&file, b"invalid ELF").unwrap();
    timed_refresh(&mut fixture.view, true);
    assert_eq!(
        fixture.view.selected.as_ref().unwrap().core.source_size,
        initial_size as u64 + 16
    );
    assert!(fixture.view.status.starts_with("Core metadata refresh:"));
}

#[test]
fn parsed_size_mismatch_remains_dirty_even_with_equal_file_stamp() {
    let fixture = Fixture::new();
    let file = fixture.directory.join("growing.elf");
    growing_elf(&file);
    let record = acquired_record(&file).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(&[0; 16])
        .unwrap();
    let current = core_file_stamp(&file);
    assert!(matches!(
        opened_reply(record.clone(), String::new()),
        Reply::Open(_, _, None)
    ));
    let refresh = selected_core_refresh(SelectedCoreProbe {
        directory: record.dir,
        source: file,
        source_size: record.core.source_size,
        stamp: current,
    });
    assert_eq!(
        refresh.core.unwrap().unwrap().source_size,
        current.unwrap().file_size
    );
}

#[test]
fn late_catalog_reply_is_rejected_for_vm_and_roots_and_current_refresh_is_queued() {
    let mut fixture = Fixture::new();
    let original_roots = vec![fixture.directory.clone()];
    for (roots, vm) in [
        (original_roots.clone(), "other-vm"),
        (vec![fixture.directory.join("other-root")], "chosen"),
    ] {
        fixture
            .view
            .set_catalog_scope(&original_roots, Some("chosen"));
        let (sender, receiver) = mpsc::sync_channel(1);
        let stale = CatalogReply {
            generation: fixture.view.catalog_generation,
            roots: original_roots.clone(),
            vm_id: Some("chosen".into()),
            catalog: Ok(CoreCatalog {
                acquired: vec![AcquiredCore {
                    vm_id: "chosen".into(),
                    boot_id: "boot".into(),
                    run_id: "stale".into(),
                    directory: fixture.directory.join("old"),
                    file: None,
                    state: antinomie_monitor_core::RunArtifactState::WaitingForRootExit,
                    deleted: None,
                    sizes: None,
                }],
                ..Default::default()
            }),
            stamp: Some(123),
            selected: None,
        };
        fixture.view.catalog_job = Some(receiver);
        fixture.view.set_catalog_scope(&roots, Some(vm));
        fixture.view.refresh_catalog_if_due(true, Instant::now());
        sender.send(stale).unwrap();
        fixture.view.poll_catalog();
        assert!(fixture.view.acquired.is_empty());
        assert!(fixture.view.catalog_checked.is_none());
        fixture.view.refresh_catalog_if_due(true, Instant::now());
        wait_catalog(&mut fixture.view);
        assert!(fixture.view.acquired.is_empty());
    }
}

#[test]
fn previous_vm_inspection_finishes_files_without_applying_open_code_or_decompiled() {
    let mut fixture = Fixture::new();
    let roots = vec![fixture.directory.clone()];
    for reply in [
        opened_reply(
            fixture.view.selected.as_ref().unwrap().clone(),
            "old open".into(),
        ),
        Reply::Code("old code".into()),
        Reply::Decompiled("old decompilation".into()),
    ] {
        fixture.view.set_catalog_scope(&roots, Some("previous"));
        let output = fixture.directory.join("completed-worker-output");
        let worker_output = output.clone();
        let (release, wait) = mpsc::sync_channel(1);
        fixture.view.start(move || {
            wait.recv().unwrap();
            fs::write(worker_output, b"retained old operation output").unwrap();
            Ok(reply)
        });
        fixture.view.set_catalog_scope(&roots, Some("current"));
        fixture.view.code = "current selection".into();
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while fixture.view.job.is_some() {
            fixture.view.poll();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(fs::read(&output).unwrap(), b"retained old operation output");
        assert!(fixture.view.selected.is_none());
        assert_eq!(fixture.view.code, "current selection");
        assert!(fixture.view.functions.is_empty());
    }
}

#[test]
fn acquired_catalog_finds_unopened_partial_cores_and_scopes_the_vm() {
    let fixture = Fixture::new();
    for (id, vm_id, state, with_file) in [
        (
            "partial",
            "chosen",
            antinomie_monitor_core::RunArtifactState::Partial,
            true,
        ),
        (
            "waiting",
            "chosen",
            antinomie_monitor_core::RunArtifactState::WaitingForRootExit,
            false,
        ),
        (
            "other",
            "other-vm",
            antinomie_monitor_core::RunArtifactState::Complete,
            true,
        ),
    ] {
        let directory = fixture.directory.join("runs").join(id);
        fs::create_dir_all(directory.join("core")).unwrap();
        let file = directory.join("core/process.elf");
        if with_file {
            fs::write(&file, b"unfinished ELF prefix").unwrap();
        }
        let artifacts = antinomie_monitor_core::RunArtifacts {
            run_id: id.into(),
            vm_id: vm_id.into(),
            boot_id: "boot".into(),
            core_state: state,
            core_dump: with_file.then_some(file),
            ..Default::default()
        };
        fs::write(
            directory.join("artifacts.json"),
            serde_json::to_vec(&artifacts).unwrap(),
        )
        .unwrap();
    }
    let first = catalog(std::slice::from_ref(&fixture.directory), Some("chosen")).unwrap();
    assert!(first.imported.is_empty());
    assert_eq!(first.acquired.len(), 2);
    assert!(first
        .acquired
        .iter()
        .any(|core| core.run_id == "partial" && core.file.is_some()));
    assert!(first
        .acquired
        .iter()
        .any(|core| core.run_id == "waiting" && core.file.is_none()));
    assert!(
        !fixture.directory.join("core-dumps").exists(),
        "discovery must not import or parse incomplete ELF files"
    );
}

#[test]
fn a_deleted_on_exit_core_is_listed_as_a_deleted_row() {
    let fixture = Fixture::new();
    let directory = fixture.directory.join("runs/gone");
    fs::create_dir_all(directory.join("core")).unwrap();
    // What the backend writes once the user deleted the run's core.
    let artifacts = antinomie_monitor_core::RunArtifacts {
        run_id: "gone".into(),
        vm_id: "chosen".into(),
        boot_id: "boot".into(),
        core_state: antinomie_monitor_core::RunArtifactState::Disabled,
        core_deleted: true,
        ..Default::default()
    };
    fs::write(
        directory.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    let found = catalog(std::slice::from_ref(&fixture.directory), Some("chosen")).unwrap();
    assert_eq!(found.acquired.len(), 1);
    assert_eq!(found.acquired[0].status(), artifacts.core_label());
    assert_eq!(found.acquired[0].status(), "Deleted");
    assert!(found.acquired[0].file.is_none());
}

#[test]
fn reopening_acquired_core_reuses_its_directory_and_available_prefix() {
    let fixture = Fixture::new();
    let directory = fixture.directory.join("runs/root/core");
    fs::create_dir_all(&directory).unwrap();
    let file = directory.join("process.elf");
    let mut data = vec![0u8; 64 + 56 + 12 + 8 + 336];
    data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    data[16..18].copy_from_slice(&4u16.to_le_bytes());
    data[18..20].copy_from_slice(&62u16.to_le_bytes());
    data[32..40].copy_from_slice(&64u64.to_le_bytes());
    data[54..56].copy_from_slice(&56u16.to_le_bytes());
    data[56..58].copy_from_slice(&1u16.to_le_bytes());
    data[64..68].copy_from_slice(&4u32.to_le_bytes());
    data[72..80].copy_from_slice(&120u64.to_le_bytes());
    data[96..104].copy_from_slice(&356u64.to_le_bytes());
    data[120..124].copy_from_slice(&5u32.to_le_bytes());
    data[124..128].copy_from_slice(&336u32.to_le_bytes());
    data[128..132].copy_from_slice(&1u32.to_le_bytes());
    data[132..137].copy_from_slice(b"CORE\0");
    data[172..176].copy_from_slice(&77u32.to_le_bytes());
    fs::write(&file, data).unwrap();
    let mut first = acquired_record(&file).unwrap();
    first.label = "Renamed acquisition".into();
    first.tags = "interesting, partial".into();
    first.save().unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    let second = acquired_record(&file).unwrap();
    assert_eq!(first.dir, directory);
    assert_eq!(second.dir, first.dir);
    assert_eq!(second.core.threads[0].tid, 77);
    assert_eq!(second.label, "Renamed acquisition");
    assert_eq!(second.tags, "interesting, partial");
    assert_eq!(second.core.source_size, first.core.source_size + 1);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
    assert!(!fixture.directory.join("core-dumps").exists());
    let mut wrong = second;
    wrong.core.source = fixture.directory.join("another-core.elf");
    wrong.save().unwrap();
    assert!(acquired_record(&file)
        .unwrap_err()
        .contains("identity does not match"));
}
impl Fixture {
    pub(super) fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "antinomie-core-ui-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let source = directory.join("synthetic-memory.bin");
        fs::write(&source, [0x90; 4096]).unwrap();
        // Deliberately synthetic domain metadata: parser qualification is
        // tested in monitor-core; these tests qualify view interaction.
        let record = CoreRecord {
            dir: directory.clone(),
            label: "Synthetic process core".into(),
            tags: String::new(),
            core: CoreDump {
                source,
                source_size: 4096,
                threads: [101, 102]
                    .into_iter()
                    .map(|tid| CoreThread {
                        tid,
                        parent_pid: 100,
                        signal: 11,
                        registers: vec![
                            ("rip".into(), 0x400000),
                            ("rsp".into(), 0x400080),
                            ("rax".into(), u64::from(tid)),
                        ],
                    })
                    .collect(),
                mappings: vec![CoreMapping {
                    start: 0x400000,
                    memory_size: 64 * 1024 * 1024,
                    file_offset: 0,
                    captured_size: 4096,
                    available_size: 4096,
                    flags: 5,
                }],
                files: vec![MappedFile {
                    start: 0x400000,
                    end: 0x401000,
                    file_offset: 0,
                    path: "/synthetic/sample".into(),
                }],
                auxv: vec![(9, 0x400000)],
                notes: vec!["Synthetic NT_PRSTATUS / NT_FILE / AUXV evidence".into()],
                warnings: vec![
                    "Remaining mapping pages were omitted from this synthetic capture".into(),
                ],
            },
        };
        let mut page = vec![None; PAGE_SIZE * 2];
        page[..4096].fill(Some(0x90));
        let mut view = CoreView::default();
        view.selected = Some(record.clone());
        view.records = vec![record];
        view.code_address = "400000".into();
        view.page = Some((0x400000, page));
        Self { view, directory }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

pub(super) fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    fn collect(shape: &egui::epaint::Shape, result: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::epaint::Shape::Text(text) => result.push((
                text.galley.text().to_owned(),
                egui::Rect::from_min_size(text.pos, text.galley.size()),
            )),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, result);
                }
            }
            _ => {}
        }
    }
    let mut result = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut result);
    }
    result
}
pub(super) fn render(
    ctx: &egui::Context,
    view: &mut CoreView,
    size: egui::Vec2,
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    let roots = view.roots.clone();
    let vm_id = view.vm_id.clone();
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(
                    ui,
                    &roots,
                    vm_id.as_deref(),
                    false,
                    CoreControls {
                        unavailable: Some("Start a supported VM to dump a process core."),
                        captures: &[],
                        can_cancel: false,
                        boot_id: None,
                    },
                )
            });
        },
    )
}
pub(super) fn settle(
    ctx: &egui::Context,
    view: &mut CoreView,
    size: egui::Vec2,
) -> egui::FullOutput {
    let mut output = render(ctx, view, size, Vec::new());
    for _ in 0..3 {
        output = render(ctx, view, size, Vec::new());
    }
    output
}
pub(super) fn click(
    ctx: &egui::Context,
    view: &mut CoreView,
    size: egui::Vec2,
    position: egui::Pos2,
) {
    for events in [
        vec![egui::Event::PointerMoved(position)],
        vec![egui::Event::PointerButton {
            pos: position,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        }],
        vec![egui::Event::PointerButton {
            pos: position,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }],
    ] {
        render(ctx, view, size, events);
    }
}

#[test]
fn sidebar_selection_shows_unfinished_capture_without_old_core_context() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 24.0);
    let size = egui::vec2(800.0, 1000.0);
    let mut fixture = Fixture::new();
    let directory = fixture.directory.join("runs/waiting/core");
    fixture.view.acquired.push(AcquiredCore {
        vm_id: "fixture-vm".into(),
        boot_id: "fixture-boot".into(),
        run_id: "waiting".into(),
        directory: directory.clone(),
        file: None,
        state: antinomie_monitor_core::RunArtifactState::WaitingForRootExit,
        deleted: None,
        sizes: None,
    });
    let output = settle(&ctx, &mut fixture.view, size);
    let content = texts(&output);
    let row = content
        .iter()
        .find(|(text, _)| text == "Run waiting")
        .unwrap()
        .1;
    let context = content
        .iter()
        .find(|(text, _)| text == "Context")
        .unwrap()
        .1;
    assert!(
        row.max.x < context.min.x,
        "capture list stays left of analysis"
    );
    assert!(!content.iter().any(|(text, _)| text == "Core file"));
    click(&ctx, &mut fixture.view, size, row.center());
    let output = settle(&ctx, &mut fixture.view, size);
    assert_eq!(fixture.view.selected_directory.as_ref(), Some(&directory));
    assert!(fixture.view.selected.is_none() && fixture.view.job.is_none());
    let content = texts(&output);
    assert!(content
        .iter()
        .any(|(text, _)| text.contains("No core file is recorded yet")));
    assert!(!content.iter().any(|(text, _)| text == "rip"));
    assert!(
        fixture.view.records.len() == 1,
        "waiting selection keeps imported evidence"
    );
}

#[test]
fn unfinished_manual_core_shows_recorded_status_without_stale_context() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let directory = fixture.directory.join("core-captures/live");
    fs::create_dir_all(&directory).unwrap();
    fixture.view.select_manual(ProcessCoreCapture {
        format: 1,
        id: "live".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        source_run_id: Some("run".into()),
        restored_from_capture_id: None,
        target: antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 42,
            tgid: 101,
            start_boot_ns: 100,
        },
        directory: directory.clone(),
        file: None,
        state: antinomie_monitor_core::RunArtifactState::InProgress,
        phase: ProcessCorePhase::GuestCapture,
        stored_size: 0,
        guest_size: None,
        sha256: None,
        pause_released: Some(false),
        max_size: 64 * 1024 * 1024,
        timeout_ms: 5000,
        nonce: [1, 2],
        guest_handle: Some(7),
        guest_status: None,
        issue: None,
        requested_max_size: None,
        guest_max_size: None,
        stored_bytes: None,
        expected_size: None,
        allocated_size: None,
        reason: None,
    });
    let output = settle(&ctx, &mut fixture.view, egui::vec2(1280.0, 900.0));
    let content = texts(&output);
    assert_eq!(fixture.view.selected_directory.as_ref(), Some(&directory));
    assert!(fixture.view.selected.is_none() && fixture.view.job.is_none());
    assert!(content
        .iter()
        .any(|(text, _)| text == "Capture pause has not been released yet"));
    assert!(content
        .iter()
        .any(|(text, _)| text.contains("does not wait for process exit")));
    assert!(!content.iter().any(|(text, _)| text == "rip"));
    assert!(content.iter().any(|(text, _)| text.contains("Dump core")));
    assert_eq!(fixture.view.records.len(), 1);
}

#[test]
fn import_fields_live_in_dialog_and_cancel_preserves_selection() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 24.0);
    let size = egui::vec2(800.0, 1000.0);
    let mut fixture = Fixture::new();
    fixture.view.roots = vec![fixture.directory.clone()];
    let original = fixture.view.selected.as_ref().unwrap().dir.clone();
    let output = settle(&ctx, &mut fixture.view, size);
    let content = texts(&output);
    assert!(!content.iter().any(|(text, _)| text == "Core file"));
    let import = content
        .iter()
        .find(|(text, _)| text.contains("Import core…"))
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, import);
    assert!(fixture.view.import_open);
    let output = settle(&ctx, &mut fixture.view, size);
    let content = texts(&output);
    for label in [
        "Import process core",
        "Core file",
        "Browse…",
        "Recording folder",
        "Import core",
    ] {
        let rect = content
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing {label}"))
            .1;
        assert!(
            rect.min.x >= 0.0 && rect.max.x <= size.x && rect.max.y <= size.y,
            "{label} stays reachable"
        );
    }
    let cancel = content
        .iter()
        .find(|(text, _)| text == "Cancel")
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, cancel);
    assert!(!fixture.view.import_open && fixture.view.job.is_none());
    assert_eq!(fixture.view.selected.as_ref().unwrap().dir, original);
    assert!(
        fixture.view.code.is_empty(),
        "opening import dialog does not run analysis"
    );
}

#[test]
fn thread_context_and_mapping_controls_render_at_narrow_large_font() {
    for (size, font) in [
        (egui::vec2(1280.0, 900.0), 16.0),
        (egui::vec2(800.0, 1000.0), 24.0),
    ] {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        crate::theme::text_size(&ctx, font);
        let mut fixture = Fixture::new();
        let output = settle(&ctx, &mut fixture.view, size);
        let content = texts(&output);
        assert!(content
            .iter()
            .any(|(text, _)| text.contains("TID 101") && text.contains("signal 11")));
        assert!(content.iter().any(|(text, _)| text == "rip"));
        assert!(content.iter().any(|(text, _)| text == "0x0000000000400000"));
        for label in ["Context", "Memory mappings", "Disassembly"] {
            let (_, rect) = content
                .iter()
                .find(|(text, _)| text == label)
                .unwrap_or_else(|| panic!("missing {label}"));
            assert!(
                rect.min.x >= 0.0 && rect.max.x <= size.x && rect.max.y <= size.y,
                "{label} must stay reachable at {size:?}, {font} pt: {rect:?}"
            );
        }
        for (text, rect) in content
            .iter()
            .filter(|(text, _)| text == "Copy" || text == egui_phosphor::regular::MEMORY)
        {
            assert!(
                rect.max.x <= size.x && rect.max.y <= size.y,
                "register action {text} stays reachable: {rect:?}"
            );
        }
        assert!(fixture.view.job.is_none());
        fixture.view.thread_index = 1;
        let output = settle(&ctx, &mut fixture.view, size);
        assert!(texts(&output)
            .iter()
            .any(|(text, _)| text.contains("TID 102")));
        fixture.view.tab = Tab::Mappings;
        let output = settle(&ctx, &mut fixture.view, size);
        let content = texts(&output);
        for label in ["Previous span", "Next span", "Jump"] {
            let (_, rect) = content
                .iter()
                .find(|(text, _)| text == label)
                .unwrap_or_else(|| panic!("missing {label}"));
            assert!(
                rect.max.x <= size.x && rect.max.y <= size.y,
                "mapping control {label} must stay reachable: {rect:?}"
            );
        }
        assert!(content
            .iter()
            .any(|(text, _)| text.contains("4096 / 67108864 octets captured")));
        assert!(content.iter().any(|(text, _)| text.contains("90 90")));
        let font_id = egui::TextStyle::Monospace.resolve(&ctx.style());
        let row_height = ctx.fonts(|fonts| fonts.row_height(&font_id));
        for (text, rect) in content
            .iter()
            .filter(|(text, _)| text.starts_with("000000000040") && text.contains("90 90"))
        {
            assert!(
                rect.height() <= row_height + 0.5,
                "one address must occupy one monospace row at {font} pt: {} high for {text}",
                rect.height()
            );
        }
        assert!(fixture.view.code.is_empty() && fixture.view.functions.is_empty());
    }
}

#[test]
fn long_disassembly_lines_scroll_horizontally_without_wrapping_at_large_font() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 24.0);
    let mut fixture = Fixture::new();
    fixture.view.tab = Tab::Code;
    fixture.view.code = "0000000000400000  mov rax, qword ptr fs:[0x0000000000000028]\n0000000000400009  mov qword ptr [rsp+0x0000000000000010], rax".into();
    let output = settle(&ctx, &mut fixture.view, egui::vec2(800.0, 1000.0));
    let content = texts(&output);
    for label in ["Disassemble captured code", "Decompile with Ghidra"] {
        let rect = content
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing {label}"))
            .1;
        assert!(
            rect.max.x <= 800.0 && rect.max.y <= 1000.0,
            "{label} stays reachable: {rect:?}"
        );
    }
    let font_id = egui::TextStyle::Monospace.resolve(&ctx.style());
    let row_height = ctx.fonts(|fonts| fonts.row_height(&font_id));
    let instruction_rows: Vec<_> = content
        .iter()
        .filter(|(text, _)| text.starts_with("000000000040000"))
        .collect();
    assert!(
        instruction_rows.len() >= 2,
        "both instruction addresses are rendered"
    );
    for (text, rect) in &instruction_rows {
        assert!(
            rect.height() <= row_height + 0.5,
            "one instruction occupies one row; got {} high for {text}",
            rect.height()
        );
    }
    assert!(
        fixture.view.job.is_none(),
        "rendering retained code never starts analysis"
    );
}

#[test]
fn long_decompiled_lines_scroll_horizontally_at_large_font() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 24.0);
    let mut fixture = Fixture::new();
    fixture.view.tab = Tab::Code;
    fixture.view.show_decompiled = true;
    fixture.view.code_function = Some(0);
    fixture.view.functions.push(CoreFunction {
        address: 0x400000,
        size: 16,
        name: "FUN_00400000".into(),
    });
    let line = "return CONCAT44((int)(in_RAX >> 0x20), (int)uVar3) & 0x7fffffffffffffff;";
    fixture.view.function_bodies.push(line.into());
    fixture.view.code = line.into();
    let output = settle(&ctx, &mut fixture.view, egui::vec2(800.0, 900.0));
    let content = texts(&output);
    let (_, rect) = content
        .iter()
        .find(|(text, _)| text == line)
        .expect("retained decompiled line is rendered");
    let font_id = egui::TextStyle::Monospace.resolve(&ctx.style());
    let row_height = ctx.fonts(|fonts| fonts.row_height(&font_id));
    assert!(
        rect.height() <= row_height + 0.5,
        "decompiled line stays one visual row: {rect:?}"
    );
    assert!(
        rect.max.x > 800.0,
        "long line extends beyond the viewport for horizontal scrolling: {rect:?}"
    );
    assert!(
        fixture.view.job.is_none(),
        "viewing saved decompilation starts no job"
    );
}

#[test]
fn viewing_code_does_not_decode_until_disassemble_is_clicked() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut fixture = Fixture::new();
    fixture.view.tab = Tab::Code;
    let output = settle(&ctx, &mut fixture.view, size);
    assert!(fixture.view.job.is_none());
    assert!(fixture.view.code.is_empty() && fixture.view.functions.is_empty());
    assert!(!fixture.directory.join("disassembly.txt").exists());
    assert!(!fixture.directory.join("functions.txt").exists());
    let content = texts(&output);
    assert!(content
        .iter()
        .any(|(text, _)| text.contains("No functions indexed")));
    let position = content
        .iter()
        .find(|(text, _)| text == "Disassemble captured code")
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, position);
    assert!(
        fixture.view.job.is_some(),
        "only an explicit decode action starts the worker"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while fixture.view.job.is_some() && std::time::Instant::now() < deadline {
        fixture.view.poll();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        fixture.view.job.is_none(),
        "bounded synthetic disassembly completes"
    );
    assert!(fixture.view.code.contains("nop"));
    assert!(fixture.directory.join("disassembly.txt").is_file());
    assert!(fixture.view.functions.is_empty());
    assert!(!fixture.directory.join("functions.txt").exists());
    let shown = texts(&settle(&ctx, &mut fixture.view, size));
    assert!(shown.iter().any(|(text, _)| text.contains("nop")));
    assert!(shown
        .iter()
        .all(|(text, _)| !text.contains("Function index is")
            && !text.contains("It is not an original source symbol")
            && !text.contains("It is not a complete list of the core")));
}

#[test]
fn disassemble_uses_captured_executable_bytes_when_rip_is_absent() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut fixture = Fixture::new();
    fixture.view.tab = Tab::Code;
    fixture.view.code_address.clear();
    fixture.view.selected.as_mut().unwrap().core.threads[0].registers[0].1 = 0x1;
    let output = settle(&ctx, &mut fixture.view, size);
    let position = texts(&output)
        .iter()
        .find(|(text, _)| text == "Disassemble captured code")
        .unwrap()
        .1
        .center();
    click(&ctx, &mut fixture.view, size, position);
    assert!(fixture.view.job.is_some());
    assert!(fixture.view.status.contains("Disassembling 0x400000"));
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while fixture.view.job.is_some() && std::time::Instant::now() < deadline {
        fixture.view.poll();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(fixture.view.code.contains("nop"), "{}", fixture.view.status);
    assert_eq!(fixture.view.code_address, "400000");
}

#[test]
fn mapping_choices_use_recovered_names_and_mark_unknown_duplicates() {
    let fixture = Fixture::new();
    let core = &fixture.view.selected.as_ref().unwrap().core;
    let choices = mapping_choices(core);
    assert!(
        choices[0].0.starts_with("mmap 400000-") && choices[0].0.contains("r-x [sample]"),
        "{}",
        choices[0].0
    );
    assert!(choices[0].1.contains("/synthetic/sample"));
    let mut unnamed = core.clone();
    unnamed.files.clear();
    assert!(
        mapping_choices(&unnamed)[0].0.contains("r-x [unknown]"),
        "{}",
        mapping_choices(&unnamed)[0].0
    );
    assert!(mapping_choices(&unnamed)[0].1.contains("No NT_FILE name"));
    let mut duplicated = core.clone();
    duplicated.mappings.push(CoreMapping {
        start: 0x500000,
        memory_size: 0x1000,
        file_offset: 0,
        captured_size: 16,
        available_size: 16,
        flags: 5,
    });
    duplicated
        .files
        .push(antinomie_monitor_core::core_dump::MappedFile {
            start: 0x500000,
            end: 0x501000,
            file_offset: 0,
            path: "/synthetic/sample".into(),
        });
    let choices = mapping_choices(&duplicated);
    assert!(choices[0].0.contains("400000-"), "{}", choices[0].0);
    assert!(choices[1].0.contains("500000-"), "{}", choices[1].0);
    assert!(choices
        .iter()
        .all(|(label, tip)| label.contains("[sample]") && tip == "/synthetic/sample"));
    let mut ambiguous = core.clone();
    let mut overlapping = ambiguous.files[0].clone();
    overlapping.path = "/other/module".into();
    ambiguous.files.push(overlapping);
    let choices = mapping_choices(&ambiguous);
    assert!(choices[0]
        .0
        .contains("[/synthetic/sample (+1 file extents)]"));
    assert!(choices[0].1.contains("/synthetic/sample"));
    assert_eq!(captured_code_origin(&unnamed, ""), Ok(0x400000));
    unnamed.mappings[0].flags = 4;
    unnamed.threads[0].registers.clear();
    assert!(captured_code_origin(&unnamed, "").is_err());
}

#[test]
fn mapping_filter_clears_hidden_hexdump_and_preserves_missing_paths() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let record = fixture.view.selected.as_ref().unwrap().clone();
    for (draft, index) in [
        (
            "memory.permissions == \"r-x\" && memory.available == true",
            0,
        ),
        ("memory.permissions == \"rw-\"", usize::MAX),
    ] {
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let id = ui
                    .id()
                    .with(("table-filter", ("core-mappings", &record.dir)));
                ui.data_mut(|data| data.insert_temp(id, draft.to_owned()));
                fixture.view.mappings(ui, &record);
            });
        });
        assert_eq!(fixture.view.mapping_index, index);
    }
    assert!(fixture.view.page.is_none());
    let mut unknown = record.core.clone();
    unknown.files.clear();
    assert!(crate::query::compile_table(
        "missing(memory.path) && memory.start == 4194304 && memory.captured_size == 4096",
        MAPPING_FIELDS
    )
    .keep_table(&mapping_filter_row(&unknown, &unknown.mappings[0])));
    let mut unavailable = unknown.mappings[0].clone();
    unavailable.available_size = 0;
    assert!(crate::query::compile_table(
        "memory.available == false && memory.captured_size == 0",
        MAPPING_FIELDS
    )
    .keep_table(&mapping_filter_row(&unknown, &unavailable)));
    let function = CoreFunction {
        name: "FUN_fffffffffffffffe".into(),
        address: u64::MAX - 1,
        size: 0,
    };
    assert!(crate::query::compile_table(
        "function.address == 0xfffffffffffffffe && function.size == 0 && missing(function.kind)",
        FUNCTION_FIELDS
    )
    .keep_table(&function_filter_row(&function)));
}

#[test]
fn ghidra_mappings_record_sparse_extent_without_zero_fill() {
    let directory = std::env::temp_dir().join(format!(
        "antinomie-ghidra-mappings-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = RemoveDir(&directory);
    let mapping = CoreMapping {
        start: 0x400000,
        memory_size: 64 * 1024 * 1024,
        file_offset: 0,
        captured_size: 8192,
        available_size: 4096,
        flags: 5,
    };
    assert!(mapping.available_size < mapping.memory_size);
    write_ghidra_mappings(&directory, std::slice::from_ref(&mapping)).unwrap();
    let path = directory.join("ghidra-mappings.txt");
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text, "400000 67108864 8192 4096 r-x\n");
    assert!(
        fs::metadata(&path).unwrap().len() < mapping.memory_size,
        "ghidra-mappings.txt records extents and does not pad holes with zero bytes"
    );
}

#[test]
fn failed_status_must_not_accept_an_old_export() {
    let directory = std::env::temp_dir().join(format!(
        "antinomie-ghidra-export-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let _cleanup = RemoveDir(&directory);
    let export = directory.join("decompiled.txt");
    let body = "@@ANTINOMIE-FUNCTION\t64\t1\told\nvoid old(void) {}\n";
    fs::write(&export, body).unwrap();
    let previous = fs::metadata(&export).unwrap().modified().ok();
    let error = accept_ghidra_export(false, &export, previous)
        .expect_err("failed status must not accept an old export");
    assert!(
        !error.contains("void old") && !error.contains("@@ANTINOMIE-FUNCTION"),
        "{error}"
    );
    assert_eq!(fs::read_to_string(&export).unwrap(), body);
}

struct RemoveDir<'a>(&'a Path);

impl Drop for RemoveDir<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.0);
    }
}

#[test]
#[ignore = "native X11 core-view preview, synthetic metadata, exits automatically"]
fn native_core_view_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct FixtureApp {
        fixture: Fixture,
        deadline: std::time::Instant,
    }
    impl eframe::App for FixtureApp {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
                self.fixture.view.show(
                    ui,
                    &[],
                    None,
                    false,
                    CoreControls {
                        unavailable: Some("Preview"),
                        captures: &[],
                        can_cancel: false,
                        boot_id: None,
                    },
                )
            });
            if std::time::Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let small = std::env::var_os("ANTINOMIE_CORE_QA_SMALL").is_some();
    let seconds = std::env::var("ANTINOMIE_CORE_QA_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(1, 120);
    let tab = var("ANTINOMIE_CORE_QA_TAB");
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => crate::theme::Theme::Light,
        "blue" => crate::theme::Theme::Blue,
        _ => crate::theme::Theme::Dark,
    };
    let size = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some([w.parse::<f32>().ok()?, h.parse::<f32>().ok()?]))
        .unwrap_or(if small {
            [800.0, 900.0]
        } else {
            [1280.0, 900.0]
        });
    let decompiled = std::env::var_os("ANTINOMIE_CORE_QA_DECOMPILED").is_some();
    eframe::run_native(
        "Antinomie Core View QA — synthetic evidence",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size(size),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::apply_theme(&cc.egui_ctx, theme_choice);
            crate::theme::text_size(&cc.egui_ctx, if small { 24.0 } else { 16.0 });
            let mut fixture = Fixture::new();
            fill_qa_core(&mut fixture, decompiled);
            fixture.view.tab = match tab.as_str() {
                "mappings" => Tab::Mappings,
                "code" => Tab::Code,
                "strings" => Tab::Strings,
                "notes" => Tab::Notes,
                _ => Tab::Context,
            };
            Ok(Box::new(FixtureApp {
                fixture,
                deadline: std::time::Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .unwrap();
}

/// Enough synthetic evidence for the tables of a screenshot: more mappings,
/// functions with decoded code, and a few hundred strings in the core's memory.
fn fill_qa_core(fixture: &mut Fixture, decompiled: bool) {
    let mut record = fixture.view.selected.clone().unwrap();
    let mut memory = Vec::new();
    for n in 0..300 {
        memory
            .extend_from_slice(format!("/usr/lib/x86_64-linux-gnu/module-{n:03}.so\0").as_bytes());
        memory.extend_from_slice(b"GET /beacon HTTP/1.1\0\0\0");
    }
    fs::write(&record.core.source, &memory).unwrap();
    record.core.source_size = memory.len() as u64;
    record.core.mappings[0].captured_size = memory.len() as u64;
    record.core.mappings[0].available_size = memory.len() as u64;
    for (index, (flags, start)) in [
        (6, 0x7f00_0000_0000u64),
        (5, 0x7f00_0020_0000),
        (4, 0x7ffc_1d39_0000),
    ]
    .into_iter()
    .enumerate()
    {
        record.core.mappings.push(CoreMapping {
            start,
            memory_size: 0x21000 * (index as u64 + 1),
            file_offset: 0,
            captured_size: 4096,
            available_size: 4096,
            flags,
        });
    }
    record.core.files.push(MappedFile {
        start: 0x7f00_0020_0000,
        end: 0x7f00_0022_1000,
        file_offset: 0,
        path: "/usr/lib/x86_64-linux-gnu/libc.so.6".into(),
    });
    fixture.view.records = vec![record.clone()];
    fixture.view.selected = Some(record);
    let names = [
        "_start",
        "main",
        "beacon_loop",
        "fetch_stage2",
        "decrypt_config",
        "persist",
    ];
    fixture.view.functions = names
        .iter()
        .enumerate()
        .map(|(index, name)| CoreFunction {
            address: 0x400000 + index as u64 * 0x40,
            size: 0x40,
            name: (*name).into(),
        })
        .collect();
    fixture.view.code_function = Some(2);
    let mut code = String::from("x86-64 process memory at 0x400000; linear decoding\n");
    for (index, address) in (0u64..).map(|n| 0x400000 + n * 4).take(60).enumerate() {
        let (mnemonic, operands) = match index % 5 {
            0 => ("push", "rbp"),
            1 => ("mov", "rbp, rsp"),
            2 => ("call", "0x401200"),
            3 => ("jne", "0x400010"),
            _ => ("ret", ""),
        };
        code.push_str(&format!("{address:016x}  {mnemonic} {operands}\n"));
    }
    fixture.view.code = code;
    fixture.view.remember_asm_counts();
    if decompiled {
        fixture.view.function_bodies = names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let mut body = format!("void {name}(void)\n{{\n");
                for line in 0..index * 3 + 2 {
                    body.push_str(&format!("  local_{line} = FUN_{line:04x}(0x{line:x});\n"));
                }
                body + "  return;\n}\n"
            })
            .collect();
        fixture.view.show_decompiled = true;
    }
}

#[test]
#[ignore = "native X11; opens a genuine process core and waits for a Disassemble click"]
fn native_genuine_core_disassemble() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    let source = PathBuf::from(
        std::env::var("ANTINOMIE_GENUINE_CORE")
            .expect("Set ANTINOMIE_GENUINE_CORE to a retained native process ELF core"),
    );
    assert!(
        source.is_file(),
        "genuine core missing: {}",
        source.display()
    );
    let existing = std::env::var_os("ANTINOMIE_CORE_QA_RECORD_DIR").map(PathBuf::from);
    let (root, record) = if let Some(directory) = existing {
        let root = directory
            .parent()
            .and_then(Path::parent)
            .expect("QA record is nested under a core-dumps catalog")
            .to_owned();
        assert_eq!(
            directory.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new("core-dumps"))
        );
        let record = core_dump::list_records(std::slice::from_ref(&root))
            .expect("list existing owned QA records")
            .into_iter()
            .find(|record| record.dir == directory)
            .expect("requested QA record is in its catalog");
        assert_eq!(record.core.source, fs::canonicalize(&source).unwrap());
        (root, record)
    } else {
        let root = std::env::temp_dir().join(format!(
            "antinomie-native-core-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let record = CoreRecord::import(&source, &root).expect("import genuine core by reference");
        (root, record)
    };
    let status_path = PathBuf::from("/tmp/antinomie-genuine-core-status");
    struct App {
        view: CoreView,
        root: PathBuf,
        deadline: Instant,
        status_path: PathBuf,
    }
    impl eframe::App for App {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = self.view.show(
                    ui,
                    std::slice::from_ref(&self.root),
                    Some("qa"),
                    false,
                    CoreControls {
                        unavailable: Some("Preview does not capture a live process"),
                        captures: &[],
                        can_cancel: false,
                        boot_id: None,
                    },
                );
            });
            crate::evidence::dialogs(ctx);
            let code_lines = self
                .view
                .code
                .lines()
                .filter(|line| !line.is_empty())
                .count();
            let _ = fs::write(
                &self.status_path,
                format!(
                    "status={}\ncode_lines={code_lines}\njob={}\n",
                    self.view.status.replace('\n', " "),
                    self.view.job.is_some()
                ),
            );
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    let small = std::env::var_os("ANTINOMIE_CORE_QA_SMALL").is_some();
    let font = std::env::var("ANTINOMIE_CORE_QA_FONT")
        .ok()
        .and_then(|value| value.parse::<f32>().ok())
        .unwrap_or(if small { 24.0 } else { 16.0 });
    let seconds = std::env::var("ANTINOMIE_CORE_QA_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(90)
        .clamp(1, 180);
    let tab = std::env::var("ANTINOMIE_CORE_QA_TAB").unwrap_or_else(|_| "code".into());
    eframe::run_native(
        "Antinomie Genuine Core",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size(if small {
                    [800.0, 900.0]
                } else {
                    [1280.0, 900.0]
                })
                .with_position([40.0, 40.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::text_size(&cc.egui_ctx, font);
            let mut view = CoreView::default();
            view.selected_directory = Some(record.dir.clone());
            view.tab = match tab.as_str() {
                "mappings" => Tab::Mappings,
                "notes" => Tab::Notes,
                "context" => Tab::Context,
                _ => Tab::Code,
            };
            view.records.push(record.clone());
            view.open(&record.core.source);
            Ok(Box::new(App {
                view,
                root,
                deadline: Instant::now() + Duration::from_secs(seconds),
                status_path,
            }))
        }),
    )
    .unwrap();
}

/// One frame with the given cancel controls; returns the text rectangles and
/// the action the panel asks for.
fn frame_with_cancel(
    ctx: &egui::Context,
    view: &mut CoreView,
    events: Vec<egui::Event>,
    can_cancel: bool,
    boot_id: Option<&str>,
) -> (Vec<(String, egui::Rect)>, Option<CoreAction>) {
    let roots = view.roots.clone();
    let vm_id = view.vm_id.clone();
    let mut action = None;
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 800.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                action = view.show(
                    ui,
                    &roots,
                    vm_id.as_deref(),
                    false,
                    CoreControls {
                        unavailable: None,
                        captures: &[],
                        can_cancel,
                        boot_id,
                    },
                );
            });
        },
    );
    (texts(&output), action)
}

#[test]
fn cancel_process_core_shows_only_while_a_capture_is_in_progress_and_cancels_that_run() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let mut view = std::mem::take(&mut fixture.view);
    let core = |state| AcquiredCore {
        vm_id: "fixture-vm".into(),
        boot_id: "fixture-boot".into(),
        run_id: "waiting".into(),
        directory: fixture.directory.join("runs/waiting/core"),
        file: None,
        state,
        deleted: None,
        sizes: None,
    };
    let button = |texts: &[(String, egui::Rect)]| {
        texts
            .iter()
            .find(|(text, _)| text == "Cancel process core")
            .map(|(_, rect)| *rect)
    };
    let boot = Some("fixture-boot");
    // Nothing captured, then a finished core: no button.
    for _ in 0..2 {
        assert!(button(&frame_with_cancel(&ctx, &mut view, Vec::new(), true, boot).0).is_none());
    }
    view.acquired
        .push(core(antinomie_monitor_core::RunArtifactState::Complete));
    for _ in 0..2 {
        assert!(button(&frame_with_cancel(&ctx, &mut view, Vec::new(), true, boot).0).is_none());
    }
    // In progress: the button shows, unless the VM cannot cancel or the core
    // belongs to another boot.
    view.acquired[0] = core(antinomie_monitor_core::RunArtifactState::WaitingForRootExit);
    for _ in 0..2 {
        frame_with_cancel(&ctx, &mut view, Vec::new(), true, boot);
    }
    assert!(button(&frame_with_cancel(&ctx, &mut view, Vec::new(), false, boot).0).is_none());
    assert!(
        button(&frame_with_cancel(&ctx, &mut view, Vec::new(), true, Some("other-boot")).0)
            .is_none()
    );
    let position = button(&frame_with_cancel(&ctx, &mut view, Vec::new(), true, boot).0)
        .expect("a capture is in progress")
        .center();
    let mut asked = None;
    for pressed in [None, Some(true), Some(false)] {
        let events = match pressed {
            None => vec![egui::Event::PointerMoved(position)],
            Some(pressed) => vec![egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            }],
        };
        asked = frame_with_cancel(&ctx, &mut view, events, true, boot)
            .1
            .or(asked);
    }
    assert!(matches!(asked, Some(CoreAction::CancelRun(run)) if run == "waiting"));
}

/// Right-click the row whose text is `detail`, then click Delete…. Returns
/// whether the menu had the item, and the action the click asked for.
fn right_click_delete(
    ctx: &egui::Context,
    view: &mut CoreView,
    detail: &str,
    boot: Option<&str>,
) -> (bool, Option<CoreAction>) {
    let find = |texts: &[(String, egui::Rect)], needle: &str| {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, rect)| rect.center())
    };
    let mut texts = Vec::new();
    for _ in 0..3 {
        texts = frame_with_cancel(ctx, view, Vec::new(), false, boot).0;
    }
    let point = find(&texts, detail).expect("the row");
    let event = |pos, button, pressed| egui::Event::PointerButton {
        pos,
        button,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    let secondary = egui::PointerButton::Secondary;
    for events in [
        vec![egui::Event::PointerMoved(point)],
        vec![event(point, secondary, true)],
        vec![event(point, secondary, false)],
        vec![],
        vec![],
    ] {
        texts = frame_with_cancel(ctx, view, events, false, boot).0;
    }
    let Some(item) = find(&texts, "Delete…") else {
        return (false, None);
    };
    let primary = egui::PointerButton::Primary;
    let mut asked = None;
    for events in [
        vec![egui::Event::PointerMoved(item)],
        vec![event(item, primary, true)],
        vec![event(item, primary, false)],
        vec![],
    ] {
        asked = frame_with_cancel(ctx, view, events, false, boot)
            .1
            .or(asked);
    }
    (true, asked)
}

fn acquired_core(
    fixture: &Fixture,
    state: antinomie_monitor_core::RunArtifactState,
) -> AcquiredCore {
    AcquiredCore {
        vm_id: "fixture-vm".into(),
        boot_id: "fixture-boot".into(),
        run_id: "r1".into(),
        directory: fixture.directory.join("runs/r1/core"),
        file: None,
        state,
        deleted: None,
        sizes: None,
    }
}

#[test]
fn a_finished_core_has_a_delete_item_that_asks_to_delete_its_directory() {
    use antinomie_monitor_core::RunArtifactState::Complete;
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let mut view = std::mem::take(&mut fixture.view);
    let core = acquired_core(&fixture, Complete);
    std::fs::create_dir_all(&core.directory).unwrap();
    std::fs::write(core.directory.join("process.elf"), [0u8; 2048]).unwrap();
    let directory = core.directory.clone();
    view.acquired.push(core);
    let (present, asked) = right_click_delete(&ctx, &mut view, "Complete", Some("fixture-boot"));
    assert!(present);
    let Some(CoreAction::Delete(deletion)) = asked else {
        panic!("Delete… asks the app to delete");
    };
    assert_eq!(
        deletion.item,
        antinomie_monitor_core::EvidenceItem::ProcessCore {
            directory: directory.clone()
        }
    );
    assert_eq!(deletion.size, "2048 bytes (2.0 KB)");
    assert!(directory.exists(), "asking deletes nothing");
}

#[test]
fn an_imported_core_deletes_only_its_results() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let view = std::mem::take(&mut fixture.view);
    let mut view = view;
    let (present, asked) = right_click_delete(&ctx, &mut view, "2 threads · 1 mappings", None);
    assert!(present);
    let Some(CoreAction::Delete(deletion)) = asked else {
        panic!("Delete… asks the app to delete");
    };
    assert_eq!(deletion.kind, crate::evidence_delete::Kind::ImportedCore);
    assert!(deletion.text().contains("original core file stays"));
}

#[test]
fn a_core_still_being_captured_cannot_be_deleted() {
    use antinomie_monitor_core::RunArtifactState::WaitingForRootExit;
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let mut view = std::mem::take(&mut fixture.view);
    view.acquired
        .push(acquired_core(&fixture, WaitingForRootExit));
    let detail = "Waiting for root process exit";
    let (present, asked) = right_click_delete(&ctx, &mut view, detail, Some("fixture-boot"));
    assert!(present, "the item is shown, disabled");
    assert!(asked.is_none(), "a disabled item asks for nothing");
    // The same record of an earlier boot is a stale leftover, not a capture.
    let (_, asked) = right_click_delete(&ctx, &mut view, detail, Some("later-boot"));
    assert!(matches!(asked, Some(CoreAction::Delete(_))));
}

#[test]
fn a_deleted_core_leaves_the_list_and_clears_the_viewer() {
    use antinomie_monitor_core::RunArtifactState::Complete;
    let mut fixture = Fixture::new();
    let mut view = std::mem::take(&mut fixture.view);
    let core = acquired_core(&fixture, Complete);
    view.selected_directory = Some(core.directory.clone());
    view.acquired.push(core.clone());
    view.forget_core(&core.directory);
    // The run's row stays, as a Deleted one with nothing left to open.
    assert_eq!(view.acquired.len(), 1);
    assert_eq!(view.acquired[0].status(), "Deleted");
    assert!(view.acquired[0].file.is_none());
    assert!(view.selected.is_none() && view.selected_directory.is_none());
    // The imported record the fixture opened goes the same way.
    let dir = fixture.directory.clone();
    view.forget_core(&dir);
    assert!(view.records.is_empty() && view.selected.is_none());
}
