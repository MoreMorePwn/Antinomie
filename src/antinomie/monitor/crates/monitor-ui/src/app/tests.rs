// SPDX-License-Identifier: MIT
use super::{session::*, trace_view::*, *};
mod analysis;
mod analysis_sections;
mod async_browse;
mod bases;
mod capture;
mod chrome;
mod clipboard;
mod details_scroll;
mod disks;
mod evidence_delete;
mod file_drop;
mod fps_counter;
mod getting_started;
mod history;
mod large_runs;
mod launch;
mod layout;
mod memory_probe;
mod network;
mod pending;
mod rules_startup;
mod run_kill;
mod run_selection;
mod scanned_inputs;
mod startup;
mod stealth;
mod terminal_windows;
mod terminals;
mod trace_filters;
mod trace_paging;
mod trace_run_selector;
mod trace_sort;
mod trace_view;
mod upload;
mod vm_dialog;
mod workspace;

use antinomie_monitor_core::RunIn;

pub(crate) fn app() -> MonitorApp {
    let exec = ExecRequest::default();
    // Trace behavior fixtures explicitly open Trace; production opens Summary.
    let mut layout = WorkspaceLayout::default();
    layout.focus(Panel::Trace);
    MonitorApp {
        performance: Default::default(),
        backend: None,
        snapshot: Snapshot::default(),
        selected: None,
        selected_base: None,
        settings: Settings::default(),
        options: BackendOptions::default(),
        settings_open: false,
        create_open: false,
        config_open: false,
        launch_open: false,
        upload_open: false,
        draft: VmConfig::default(),
        confirm: None,
        clipboard_request: None,
        pending_kill: None,
        draft_generation: 0,
        folder_picker: FolderPicker::new(),
        status: String::new(),
        credentials: CredentialForm::default(),
        import_open: false,
        import_directory: String::new(),
        download_open: false,
        build_open: false,
        about_open: false,
        tools_open: false,
        rules_open: false,
        rules_ui: crate::rules_window::Model::default(),
        rules_summary: String::new(),
        rules_generation: 0,
        vm_snapshots: crate::snapshots::SnapshotManager::default(),
        samples: crate::samples_view::SamplesView::default(),
        dependencies: crate::dependencies_window::DependenciesWindow::ready_for_test(),
        getting_started: Default::default(),
        show_older_bases: false,
        build_wizard: build_wizard::BuildWizard::default(),
        name_action: None,
        filter: String::new(),
        applied_filter: String::new(),
        trace_sort: None,
        selected_event: None,
        trace_evidence: None,
        selected_run: None,
        selected_capture: None,
        selected_process: None,
        transport_open: false,
        stealth_open: false,
        network_view: Default::default(),
        memory_view: Default::default(),
        disk_view: Default::default(),
        core_view: Default::default(),
        triage: Default::default(),
        cpu_history: Default::default(),
        triage_pcap: Default::default(),
        run_labels: Default::default(),
        run_tree: None,
        run_tree_pending: None,
        archive_total: None,
        archive_source_total: None,
        evidence_jobs: Default::default(),
        details_follow: Default::default(),
        archived_processes: None,
        capture_history: Vec::new(),
        capture_tab: false,
        process_picker: captures::ProcessPicker::default(),
        pending_observer: None,
        pending_core: None,
        pending_network: None,
        pending_deletions: Vec::new(),
        selected_analysis: None,
        analysis_windows: BTreeMap::new(),
        analysis_directories: BTreeMap::new(),
        pending_analysis_sections: Vec::new(),
        analysis_views: BTreeMap::new(),
        analysis_generation: 0,
        archive_selected: false,
        history_generation: 0,
        run_filter: RunFilter::All,
        run_query: String::new(),
        applied_run_query: String::new(),
        run_query_error: None,
        terminals: BTreeMap::new(),
        archive: None,
        pending_archive: None,
        history: Vec::new(),
        history_sync: Default::default(),
        archive_generation: 0,
        archive_page_generation: 0,
        archive_page: Vec::new(),
        archive_offset: 0,
        archive_next: None,
        archive_previous: Vec::new(),
        archive_pending: false,
        archive_error: None,
        archive_read_cancel: None,
        archive_hidden_categories: Vec::new(),
        inspector: Inspector::default(),
        data_windows: crate::data_view::DataWindows::default(),
        layout,
        focus_panel: None,
        activity: Default::default(),
        activity_notices_due: true,
        status_notice: None,
        env: exec.env.join("\n"),
        exec,
        args: String::new(),
        source: String::new(),
        destination: "/tmp/program".into(),
        executable: false,
        overwrite: false,
        upload_browser: Default::default(),
        explorer_browser: Default::default(),
        pending_upload: None,
        pending_launch: None,
        pending_launch_context: None,
        pending_sessions: BTreeMap::new(),
        stale_command_ids: VecDeque::new(),
        backend_disconnected: false,
        error_status_mark: None,
        run_list_cache: None,
        run_selector_cache: Default::default(),
        started: Instant::now(),
        smoke: None,
        closing: false,
        submitted: Vec::new(),
        launch_action_rects: None,
    }
}

pub(crate) fn upload_app() -> MonitorApp {
    let mut app = app();
    app.snapshot.vms.push(VmConfig {
        id: "vm".into(),
        name: "Active fixture".into(),
        ..Default::default()
    });
    app.selected = Some("vm".into());
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.boot_id = Some("boot".into());
    app.snapshot.capture_dir = Some(PathBuf::from("/tmp/session"));
    app.source = "/tmp/host file".into();
    app.destination = "/tmp/guest file".into();
    app.open_upload();
    app
}

pub(super) fn explorer_fixture(app: &mut MonitorApp, root: &std::path::Path) {
    app.upload_open = false;
    app.settings.explorer_root = Some(root.to_owned());
    app.explorer_browser.reset(root.to_owned());
}

pub(super) fn wait_for_label(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    size: egui::Vec2,
    label: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if texts(&render(app, ctx, size))
            .iter()
            .any(|(text, _)| text == label)
        {
            break;
        }
        assert!(Instant::now() < deadline, "missing {label}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn secondary_click_label(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    size: egui::Vec2,
    label: &str,
) {
    let pos = texts(&render(app, ctx, size))
        .into_iter()
        .find(|(text, _)| text == label)
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events: vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Secondary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
}

pub(super) fn event(phase: u8, cpu: u32) -> antinomie_monitor_core::EventSummary {
    antinomie_monitor_core::EventSummary {
        root_task_cookie: 7,
        stream_id: 1,
        task_cookie: 3,
        call_id: 2,
        event_seq: u64::from(phase),
        phase,
        syscall_nr: 0,
        syscall_name: "read".into(),
        pid: 42,
        tid: 42,
        cpu,
        timestamp_ns: 1000,
        args: Some([3, 0x1000, 8, 0, 0, 0]),
        result: (phase == 2).then_some(4),
        complete: true,
        issues: Vec::new(),
        fields: Vec::new(),
    }
}

pub(super) fn run(id: &str) -> RunSummary {
    RunSummary {
        started_ms: None,
        clock_anchor: None,
        id: id.into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 7,
        pid: 42,
        request: ExecRequest::default(),
        directory: PathBuf::new(),
        terminal_eof: false,
        state: RunState::Running,
        notes: Vec::new(),
        recording_error: None,
        execution: None,
        analysis: None,
    }
}

pub(super) fn observer_fixture(app: &mut MonitorApp) {
    app.selected = Some("vm".into());
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.boot_id = Some("boot".into());
    app.snapshot.guest_kernel = Some(antinomie_monitor_core::GuestKernel {
        revision: Some(11),
        source: None,
        release: None,
    });
    app.snapshot.vms.push(VmConfig {
        id: "vm".into(),
        name: "Capture QA".into(),
        ..VmConfig::default()
    });
}
pub(super) fn observer(id: &str, state: CaptureState) -> CaptureSummary {
    CaptureSummary {
        started_ms: None,
        id: id.into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        capture_cookie: 42,
        scope: antinomie_monitor_core::CaptureScope::AllUserspace,
        directory: PathBuf::from(format!("/capture/{id}")),
        state,
        recording_error: None,
        start_ns: Some(1),
        stop_ns: None,
        incomplete_reason: Some("Admission stop does not fence delivery".into()),
    }
}

pub(super) fn render(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    size: egui::Vec2,
) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            ..Default::default()
        },
        |ctx| app.draw(ctx),
    )
}

pub(crate) fn workspace(app: &mut MonitorApp) -> &mut WorkspaceLayout {
    &mut app.layout
}

pub(crate) fn draw_input(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    input: egui::RawInput,
) -> egui::FullOutput {
    ctx.run(input, |ctx| app.draw(ctx))
}

pub(crate) fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    fn collect(shape: &egui::Shape, clip: egui::Rect, texts: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::Shape::Text(text) => {
                let rect = text.visual_bounding_rect();
                if clip.contains_rect(rect) {
                    // Dock tab names carry padding spaces.
                    texts.push((text.galley.text().trim().to_owned(), rect));
                }
            }
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, clip, texts);
                }
            }
            _ => {}
        }
    }
    let mut texts = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, shape.clip_rect, &mut texts);
    }
    texts
}

pub(super) fn click_label(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    size: egui::Vec2,
    label: &str,
) {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    let output = render(app, ctx, size);
    let visible = texts(&output);
    let pos = visible
        .iter()
        .find(|(text, _)| text == label)
        .unwrap_or_else(|| panic!("missing or clipped {label}: {visible:?}"))
        .1
        .center();
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events: vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
}

pub(super) fn test_base(id: &str, fixed_display: bool) -> BaseSummary {
    BaseSummary {
        id: id.into(),
        label: "Linux 6.12.94".into(),
        directory: PathBuf::from(format!("/bases/{id}")),
        guest: None,
        min_ram_mib: 256,
        min_disk_gib: 1,
        fixed_display,
        size_bytes: 0,
        revision: Some(APP_REVISION),
        min_app_version: None,
        built_with: None,
    }
}

pub(super) fn catalog_base(
    label: &str,
    revision: Option<u32>,
) -> antinomie_monitor_core::RemoteBase {
    antinomie_monitor_core::RemoteBase {
        identity: format!("{label:0<64}"),
        label: label.into(),
        kind: "busybox".into(),
        kernel_version: "6.12.94".into(),
        fixed_display: true,
        min_ram_mib: 256,
        min_disk_gib: 1,
        total_size: 1024 * 1024,
        revision,
        min_app_version: None,
        built_with: None,
    }
}

pub(super) fn base_summary_for_revision(revision: Option<u32>) -> BaseSummary {
    BaseSummary {
        id: "b".repeat(64),
        label: "Debian".into(),
        directory: PathBuf::from("/bases/b"),
        guest: None,
        min_ram_mib: 256,
        min_disk_gib: 1,
        fixed_display: true,
        size_bytes: 0,
        revision,
        min_app_version: None,
        built_with: None,
    }
}

pub(super) fn press(
    app: &mut MonitorApp,
    ctx: &egui::Context,
    size: egui::Vec2,
    key: egui::Key,
    modifiers: egui::Modifiers,
) {
    let _ = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            modifiers,
            events: vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            }],
            ..Default::default()
        },
        |ctx| app.draw(ctx),
    );
}

/// The color of the first text shape that reads `label`.
pub(super) fn text_color(output: &egui::FullOutput, label: &str) -> Option<egui::Color32> {
    fn find(shape: &egui::Shape, label: &str) -> Option<egui::Color32> {
        match shape {
            egui::Shape::Text(text) if text.galley.text() == label => Some(
                text.galley
                    .job
                    .sections
                    .first()
                    .map_or(text.fallback_color, |section| section.format.color),
            ),
            egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, label)),
            _ => None,
        }
    }
    output
        .shapes
        .iter()
        .find_map(|shape| find(&shape.shape, label))
}

pub(super) fn analysis_setup_fixture() -> MonitorApp {
    let mut app = app();
    app.snapshot.state = VmState::Running;
    app.selected = Some("vm".into());
    app.snapshot.active_vm = app.selected.clone();
    let vm = VmConfig {
        id: "vm".into(),
        name: "Analysis QA".into(),
        ..VmConfig::default()
    };
    app.snapshot.vms.push(vm);
    app.launch_open = true;
    app.exec.path = "/usr/bin/sample".into();
    app.exec.analysis.enabled = true;
    app.exec.analysis.checks = vec![
        antinomie_monitor_core::AnalysisKind::Metadata,
        antinomie_monitor_core::AnalysisKind::Structures,
    ];
    app
}

pub(super) fn section_report(id: &str, marker: &str) -> antinomie_monitor_core::AnalysisReport {
    use antinomie_monitor_core::{
        AnalysisEntry, AnalysisKind, AnalysisReport, AnalysisSection, AnalysisSectionState,
        AnalysisState,
    };
    AnalysisReport {
        id: id.into(),
        state: AnalysisState::Partial,
        source_path: format!("/fixture/{marker}"),
        specimen_sha256: None,
        specimen_len: Some(4096),
        reason: Some("Synthetic UI fixture; no analyzer was run".into()),
        sections: vec![
            AnalysisSection {
                kind: AnalysisKind::Metadata,
                state: AnalysisSectionState::Complete,
                summary: format!("{marker} metadata"),
                tools: Vec::new(),
                listing: None,
                entries: vec![AnalysisEntry {
                    label: "Identity".into(),
                    value: marker.into(),
                    offset: None,
                    record: None,
                }],
            },
            AnalysisSection {
                kind: AnalysisKind::Structures,
                state: AnalysisSectionState::Unavailable,
                summary: format!("{marker} structures unavailable"),
                tools: Vec::new(),
                listing: None,
                entries: Vec::new(),
            },
            AnalysisSection {
                kind: AnalysisKind::Strings,
                state: AnalysisSectionState::Partial,
                summary: "Bounded synthetic rows".into(),
                tools: Vec::new(),
                listing: None,
                entries: (0..2048)
                    .map(|index| AnalysisEntry {
                        label: format!("Row {index}"),
                        value: "Synthetic evidence".into(),
                        offset: Some(index),
                        record: None,
                    })
                    .collect(),
            },
        ],
    }
}

/// A pcap of a DNS query (UDP 5353 → 53) and a TCP SYN (40000 → 80).
pub(super) fn test_pcap() -> Vec<u8> {
    fn frame(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0x52, 0x55, 10, 0, 2, 2, 0x52, 0x54, 0, 0x12, 0x34, 0x56, 8, 0,
        ];
        let total = (20 + transport.len()) as u16;
        frame.extend([0x45, 0]);
        frame.extend(total.to_be_bytes());
        frame.extend([0, 0, 0x40, 0, 64, protocol, 0, 0, 10, 0, 2, 15, 10, 0, 2, 3]);
        frame.extend(transport);
        frame
    }
    let mut dns = vec![0x14, 0xe9, 0, 53, 0, 37, 0, 0];
    dns.extend([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    dns.extend(b"\x07example\x03com\x00\x00\x01\x00\x01");
    let mut syn = vec![0x9c, 0x40, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02];
    syn.extend([0; 6]);
    let mut file = Vec::new();
    file.extend(0xa1b2c3d4u32.to_le_bytes());
    file.extend([2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    file.extend(65535u32.to_le_bytes());
    file.extend(1u32.to_le_bytes());
    for frame in [frame(17, &dns), frame(6, &syn)] {
        file.extend(1_800_000_000u32.to_le_bytes());
        file.extend(0u32.to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend(frame);
    }
    file
}
mod stale_controls;
