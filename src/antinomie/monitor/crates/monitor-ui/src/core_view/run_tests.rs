// SPDX-License-Identifier: GPL-3.0-only
//! Trigger cores in the list, and the Run line of each core.
use super::list_rows::Link;
use super::tests::{settle, texts, Fixture};
use super::*;
use antinomie_monitor_core::provenance::Certainty;

const RUN: &str = "f9c3d854547992ccfc7f6670b3cc7866";

/// The shape of the evaluation's BPFDoor run: Core dump on exit off, one
/// trigger core (partial) taken by `c2.bpf_backdoor`.
fn bpfdoor_artifacts(directory: &Path) -> antinomie_monitor_core::RunArtifacts {
    let run = directory.join("runs").join(RUN);
    let capture = directory.join("core-captures/0179-7e9a");
    fs::create_dir_all(&capture).unwrap();
    fs::write(capture.join("process.elf"), b"\x7fELF partial").unwrap();
    let artifacts: antinomie_monitor_core::RunArtifacts =
        serde_json::from_value(serde_json::json!({
            "run_id": RUN, "vm_id": "chosen", "boot_id": "boot",
            "core_state": "disabled",
            "trigger_dumps": [{
                "at_ms": 1,
                "finding": {"rule": "c2.bpf_backdoor", "summary": "", "tier": "high",
                    "pid": 1352, "tid": 1352, "task_cookie": 2, "stream_id": 1, "call_id": 19,
                    "guest_ns": 1, "syscall": "setsockopt"},
                "core": {"state": "partial", "path": capture.join("process.elf"),
                    "capture_id": "0179-7e9a", "size": 115608}
            }]
        }))
        .unwrap();
    fs::create_dir_all(&run).unwrap();
    fs::write(
        run.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    artifacts
}

fn names() -> crate::run_link::RunNames {
    crate::run_link::RunNames::of(&[crate::run_link::test_run(RUN, "/tmp/bpfdoor.elf")])
}

#[test]
fn a_trigger_core_is_listed_though_core_dump_on_exit_is_off() {
    let fixture = Fixture::new();
    bpfdoor_artifacts(&fixture.directory);
    // A stopped VM: the catalog is read from disk, with no live captures.
    let found = catalog(std::slice::from_ref(&fixture.directory), Some("chosen")).unwrap();
    assert_eq!(
        found.acquired.len(),
        1,
        "the exit core is off, the trigger core is not"
    );
    let core = &found.acquired[0];
    assert_eq!(
        core.trigger.as_deref(),
        Some("Trigger: c2.bpf_backdoor (High)")
    );
    assert_eq!(core.run_id, RUN);
    assert!(core.file.is_some());
    assert_eq!(core.status_text(), "Partial capture \u{b7} 112.9 KiB");
    let provenance = core.provenance.as_ref().unwrap();
    assert_eq!(provenance.certainty, Certainty::Exact);
    assert_eq!(provenance.pid, Some(1352));
    assert_eq!(provenance.task_cookie, Some(2));
    // Another VM's runs stay out.
    assert!(
        catalog(std::slice::from_ref(&fixture.directory), Some("other"))
            .unwrap()
            .acquired
            .is_empty()
    );
}

#[test]
fn the_list_shows_the_trigger_and_the_run_line_and_a_click_on_it_opens_the_run() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let mut view = std::mem::take(&mut fixture.view);
    view.records.clear();
    view.selected = None;
    view.roots = vec![fixture.directory.clone()];
    view.vm_id = Some("chosen".into());
    bpfdoor_artifacts(&fixture.directory);
    view.set_runs(
        &std::sync::Arc::new(vec![crate::run_link::test_run(RUN, "/tmp/bpfdoor.elf")]),
        Some(RUN.into()),
    );
    let size = egui::vec2(900.0, 700.0);
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut shown;
    loop {
        shown = texts(&settle(&ctx, &mut view, size));
        if shown
            .iter()
            .any(|(text, _)| text.contains("c2.bpf_backdoor"))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the trigger core never listed: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let find = |needle: &str| {
        shown
            .iter()
            .find(|(text, _)| text.contains(needle))
            .unwrap_or_else(|| panic!("no {needle:?} in {shown:?}"))
            .1
    };
    // Named by its process and rule (item 37), not "Trigger: ...".
    find("PID 1352 (bpfdoor.elf) \u{b7} c2.bpf_backdoor");
    let run_line = find("Run: f9c3d854 \u{b7} bpfdoor.elf");
    // The count includes the core; This run only is a checkbox.
    find("1 / 1 cores");
    find("This run only");
    // A click on the run line asks for the run, not for the core.
    let at = run_line.center();
    let mut asked = None;
    let button = |pressed| egui::Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    for events in [
        vec![egui::Event::PointerMoved(at)],
        vec![button(true)],
        vec![button(false)],
    ] {
        let roots = view.roots.clone();
        let vm = view.vm_id.clone();
        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    if let Some(action) = view.show(
                        ui,
                        &roots,
                        vm.as_deref(),
                        false,
                        // As `settle` draws it, so the rows are where they were.
                        CoreControls {
                            unavailable: Some("Start a supported VM to dump a process core."),
                            captures: &[],
                            can_cancel: false,
                            boot_id: None,
                        },
                    ) {
                        asked = Some(action);
                    }
                });
            },
        );
    }
    assert!(
        matches!(&asked, Some(CoreAction::OpenRun(run)) if run == RUN),
        "a click on the Run line opens the run: asked={} selected={:?} at={at:?} line={run_line:?}",
        asked.is_some(),
        view.selected_directory
    );
}

#[test]
fn this_run_only_keeps_the_cores_of_the_run_selected_in_triage() {
    let mut view = CoreView::default();
    let hit = Link {
        run: Some(RUN.into()),
        live: Vec::new(),
        certainty: Certainty::Exact,
    };
    let other = Link {
        run: Some("other".into()),
        live: Vec::new(),
        certainty: Certainty::Exact,
    };
    let none = Link {
        run: None,
        live: Vec::new(),
        certainty: Certainty::Unknown,
    };
    // Off: everything. On with no run selected: everything too.
    assert!(view.of_this_run(&other));
    view.this_run_only = true;
    assert!(view.of_this_run(&other));
    view.triage_run = Some(RUN.into());
    assert!(view.of_this_run(&hit));
    assert!(!view.of_this_run(&other));
    assert!(!view.of_this_run(&none));
    // It follows the selection.
    view.triage_run = Some("other".into());
    assert!(view.of_this_run(&other) && !view.of_this_run(&hit));
}

#[test]
fn the_run_line_says_not_in_a_run_for_imports_and_old_cores() {
    let mut view = CoreView::default();
    view.run_names = names();
    let none = Link {
        run: None,
        live: Vec::new(),
        certainty: Certainty::Unknown,
    };
    let cell = view.cell_of(&none);
    assert_eq!(cell.line().text, "Run: Not in a run");
    assert!(!cell.line().clickable);
    let exact = Link {
        run: Some(RUN.into()),
        live: Vec::new(),
        certainty: Certainty::Exact,
    };
    let cell = view.cell_of(&exact);
    assert_eq!(cell.line().text, "Run: f9c3d854 \u{b7} bpfdoor.elf");
    assert!(cell.line().clickable);
}

const CAPTURE: &str = "01763121824000000000-7e9a";

/// A trigger core as a running VM writes it: a manual capture in its boot's
/// folder (`boots/<boot>/core-captures/<id>`), named by its run's record.
fn trigger_core_in_boot(directory: &Path) -> ProcessCoreCapture {
    use antinomie_monitor_core::provenance::{Certainty, FoundBy, Origin, Provenance};
    let capture = directory.join("boots/boot/core-captures").join(CAPTURE);
    fs::create_dir_all(&capture).unwrap();
    fs::write(capture.join("process.elf"), [0u8; 64]).unwrap();
    let core = ProcessCoreCapture {
        format: 1,
        id: CAPTURE.into(),
        vm_id: "chosen".into(),
        boot_id: "boot".into(),
        source_run_id: None,
        restored_from_capture_id: None,
        target: antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 2,
            tgid: 1352,
            start_boot_ns: 1,
        },
        directory: capture.clone(),
        file: Some(capture.join("process.elf")),
        state: antinomie_monitor_core::RunArtifactState::Complete,
        phase: ProcessCorePhase::Finished,
        stored_size: 64,
        guest_size: Some(64),
        sha256: Some("0".repeat(64)),
        pause_released: Some(true),
        max_size: 1024 * 1024,
        timeout_ms: 5000,
        nonce: [1, 2],
        guest_handle: None,
        guest_status: None,
        issue: None,
        requested_max_size: None,
        guest_max_size: None,
        provenance: Some(Provenance {
            vm_id: "chosen".into(),
            boot_id: Some("boot".into()),
            run_id: Some(RUN.into()),
            origin: Origin::Trigger,
            certainty: Certainty::Exact,
            pid: Some(1352),
            finding: Some(FoundBy {
                rule: "c2.bpf_backdoor".into(),
                tier: antinomie_monitor_core::dump_trigger::TriggerTier::High,
            }),
            from_ms: 1_763_121_824_000,
            ..Provenance::default()
        }),
        stored_bytes: None,
        expected_size: None,
        allocated_size: None,
        reason: None,
        read_nonresident: false,
        coverage: None,
        note: None,
    };
    fs::write(
        capture.join("core.json"),
        serde_json::to_vec(&core).unwrap(),
    )
    .unwrap();
    let run = directory.join("runs").join(RUN);
    fs::create_dir_all(&run).unwrap();
    let artifacts: antinomie_monitor_core::RunArtifacts =
        serde_json::from_value(serde_json::json!({
            "run_id": RUN, "vm_id": "chosen", "boot_id": "boot",
            "core_state": "disabled",
            "trigger_dumps": [{
                "at_ms": 1_763_121_824_000u64,
                "finding": {"rule": "c2.bpf_backdoor", "summary": "", "tier": "high",
                    "pid": 1352, "tid": 1352, "task_cookie": 2, "stream_id": 1, "call_id": 19,
                    "guest_ns": 1, "syscall": "setsockopt"},
                "core": {"state": "complete", "path": capture.join("process.elf"),
                    "capture_id": CAPTURE, "size": 64}
            }]
        }))
        .unwrap();
    fs::write(
        run.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    core
}

const NAME: &str = "PID 1352 (bpfdoor.elf) \u{b7} c2.bpf_backdoor \u{b7} 2025-11-14 12:03:44";

#[test]
fn a_trigger_core_a_boot_took_is_one_entry_with_its_process_and_its_rule() {
    let fixture = Fixture::new();
    let core = trigger_core_in_boot(&fixture.directory);
    // Read from disk (a stopped VM): the boot's capture is the one entry,
    // and the run's record only adds the rule and the run.
    let found = catalog(std::slice::from_ref(&fixture.directory), Some("chosen")).unwrap();
    assert_eq!(found.manual.len(), 1, "{:?}", found.issues);
    assert!(found.acquired.is_empty(), "no second, trigger-only entry");
    assert_eq!(
        found.triggers,
        vec![(
            core.directory.clone(),
            ("c2.bpf_backdoor".into(), RUN.into())
        )]
    );
    // A running VM: the live capture and the run's trigger row (the catalog
    // has not read the boot's folder yet) fold into one.
    let mut view = CoreView::default();
    view.run_names = names();
    view.manual = vec![core.clone()];
    view.acquired = vec![AcquiredCore {
        vm_id: "chosen".into(),
        boot_id: "boot".into(),
        run_id: RUN.into(),
        directory: core.directory.clone(),
        file: core.file.clone(),
        state: antinomie_monitor_core::RunArtifactState::Complete,
        deleted: None,
        sizes: None,
        trigger: Some("Trigger: c2.bpf_backdoor (High)".into()),
        note: None,
        provenance: core.provenance.clone(),
    }];
    view.fold_trigger_twins();
    assert!(view.acquired.is_empty());
    assert_eq!(view.manual_name(&core), NAME);
    assert_eq!(
        crate::dump_names::origin(
            view.manual_provenance(&core).as_ref(),
            &view.run_names,
            crate::dump_names::DumpKind::Core
        ),
        "Run f9c3d854 (bpfdoor.elf) \u{b7} dump trigger, c2.bpf_backdoor (High)"
    );
    // A record from before provenance: the run's record gives the rule.
    let mut old = core.clone();
    old.provenance = None;
    view.trigger_twins.insert(
        old.directory.clone(),
        ("c2.bpf_backdoor".into(), RUN.into()),
    );
    assert_eq!(view.manual_name(&old), NAME);
}

#[test]
fn the_list_shows_one_row_named_by_process_rule_and_time_and_the_toolbar_too() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut fixture = Fixture::new();
    let mut view = std::mem::take(&mut fixture.view);
    view.records.clear();
    view.selected = None;
    view.roots = vec![fixture.directory.clone()];
    view.vm_id = Some("chosen".into());
    let core = trigger_core_in_boot(&fixture.directory);
    view.set_runs(
        &std::sync::Arc::new(vec![crate::run_link::test_run(RUN, "/tmp/bpfdoor.elf")]),
        Some(RUN.into()),
    );
    view.selected_directory = Some(core.directory.clone());
    let size = egui::vec2(900.0, 700.0);
    let deadline = Instant::now() + Duration::from_secs(20);
    let shown = loop {
        let shown = texts(&settle(&ctx, &mut view, size));
        if shown
            .iter()
            .any(|(text, _)| text.contains("c2.bpf_backdoor"))
        {
            break shown;
        }
        assert!(Instant::now() < deadline, "never listed: {shown:?}");
        std::thread::sleep(Duration::from_millis(20));
    };
    let named = shown.iter().filter(|(text, _)| text == NAME).count();
    // The row and the toolbar title; never a second row or "process.elf".
    assert_eq!(named, 2, "{shown:?}");
    assert!(
        !shown.iter().any(|(text, _)| text.starts_with("Trigger:")),
        "{shown:?}"
    );
    assert!(
        shown.iter().any(|(text, _)| text == "1 / 1 cores"),
        "{shown:?}"
    );
}

#[test]
fn an_opened_core_says_where_it_came_from_above_its_path() {
    use antinomie_monitor_core::provenance::Provenance;
    let names = names();
    let record = |dir: &str, provenance: Option<Provenance>| CoreRecord {
        dir: PathBuf::from(dir),
        label: "process.elf".into(),
        tags: String::new(),
        core: CoreDump {
            source: PathBuf::from(dir).join("process.elf"),
            source_size: 0,
            threads: Vec::new(),
            mappings: Vec::new(),
            files: Vec::new(),
            auxv: Vec::new(),
            notes: Vec::new(),
            warnings: Vec::new(),
            machine: 62,
        },
        provenance,
    };
    let exit = record(
        "/rec/runs/r/core",
        Some(Provenance::run_exit("chosen", "boot", RUN, 0)),
    );
    assert_eq!(
        core_origin(&exit, &names),
        "Run f9c3d854 (bpfdoor.elf) \u{b7} core dump on exit"
    );
    let by_hand = record(
        "/rec/boots/b/core-captures/c",
        Some(Provenance::by_hand("chosen", "boot", Some(RUN), Vec::new(), 1).of_process(7, 1)),
    );
    assert_eq!(
        core_origin(&by_hand, &names),
        "Run f9c3d854 (bpfdoor.elf) \u{b7} Dump core"
    );
    // An import saved before provenance is known by its folder.
    let imported = record("/rec/core-dumps/0001", None);
    assert_eq!(core_origin(&imported, &names), "Imported");
    let ctx = egui::Context::default();
    let mut name = String::new();
    let mut by_hand_name = String::new();
    let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
        name = opened_name(ui, &imported, &names);
        by_hand_name = opened_name(ui, &by_hand, &names);
    });
    assert_eq!(name, "process.elf", "an import keeps its file name");
    assert!(
        by_hand_name.starts_with("PID 7 (bpfdoor.elf) \u{b7} "),
        "{by_hand_name}"
    );
}
