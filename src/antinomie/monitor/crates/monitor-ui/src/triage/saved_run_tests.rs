// SPDX-License-Identifier: GPL-3.0-only
//! Golden test of design 1.4 U3 (card P2-3a): the index a headless caller gets
//! from a saved run's record (`antinomie_triage::SavedRun`) is the index the
//! GUI makes when the run is selected, with the settings the app hands it.
use super::tests::{http_pcap, write_rwx_calls};
use super::*;
use antinomie_monitor_core::{ExecRequest, RunState, RunSummary};

/// A saved run: RWX mapping calls under root cookie 55, an HTTP capture its
/// artifact list names, and its record.
fn saved_run(spool: &PacketSpool) -> RunSummary {
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..3);
    std::fs::write(spool.directory.join("telemetry.raw"), raw).unwrap();
    let pcap = spool.directory.join("network.pcap");
    std::fs::write(&pcap, http_pcap()).unwrap();
    let artifacts = antinomie_monitor_core::RunArtifacts {
        run_id: "run-golden".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        network_captures: vec![pcap],
        network_state: antinomie_monitor_core::RunArtifactState::Complete,
        ..Default::default()
    };
    std::fs::write(
        spool.directory.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    let run = RunSummary {
        environment: None,
        reduced: None,
        boot_wait: None,
        triggers: None,
        stopped_by_user: false,
        stopped_at_ms: None,
        persisted: None,
        started_ms: Some(1_792_000_000_000),
        clock_anchor: None,
        id: "run-golden".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 55,
        pid: 42,
        request: ExecRequest {
            path: "/tmp/sample".into(),
            args: vec!["--flag".into()],
            ..ExecRequest::default()
        },
        directory: spool.directory.clone(),
        terminal_eof: false,
        state: RunState::Finished,
        notes: Vec::new(),
        machine: None,
        route: None,
        recording_error: None,
        execution: None,
        analysis: None,
    };
    std::fs::write(
        spool.directory.join("run.json"),
        serde_json::to_vec(&run).unwrap(),
    )
    .unwrap();
    run
}

/// What the tables and the export read from an index.
fn fingerprint(scan: &ArchiveScan) -> String {
    let rows = |rows: &[Vec<Cell>]| -> Vec<String> {
        rows.iter()
            .map(|row| {
                row.iter()
                    .map(|cell| cell.text.as_str())
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .collect()
    };
    let findings: Vec<Vec<Cell>> = scan.findings.iter().map(|f| f.cells.clone()).collect();
    format!(
        "{:#?}",
        (
            &scan.stamp,
            scan.partial,
            scan.counts.finding_tiers,
            rows(&findings),
            scan.process.len(),
            rows(&scan.changed),
            rows(&scan.opened),
            rows(&scan.read),
            rows(&scan.new_tabs.endpoints),
            rows(&scan.new_tabs.domains),
            rows(&scan.new_tabs.urls),
            scan.ioc.as_ref().map(|ioc| ioc
                .indicators
                .iter()
                .map(|indicator| indicator.value.clone())
                .collect::<Vec<_>>()),
        )
    )
}

#[test]
fn a_saved_run_indexes_as_the_gui_indexes_the_selected_run() {
    let spool = PacketSpool::new().unwrap();
    let run = saved_run(&spool);
    let pcap = spool.directory.join("network.pcap");

    // The GUI: the input app.rs makes for the selected run of a stopped VM,
    // and the settings the app hands Triage (its defaults).
    let ctx = egui::Context::default();
    let mut view = TriageView::default();
    view.refresh_seconds = 3600;
    view.set_address_lookup(AddressLookup::Tshark);
    view.set_data_dir(&spool.directory);
    view.set_write_limits(
        antinomie_monitor_core::settings::EngineSettings::default().write_limits(),
    );
    view.set_page_rows(STORED_ROWS as u32);
    view.set_rebuild_limits(DEFAULT_REBUILD_FILE_MIB, DEFAULT_REBUILD_RUN_MIB);
    view.set_launch(Some(&run));
    view.set_kernel_revision(None);
    let input = TriageInput {
        analysis: run.analysis.as_ref(),
        invocations: &[],
        vm_id: Some(&run.vm_id),
        boot_id: Some(&run.boot_id),
        run_id: Some(&run.id),
        archive: Some(&run.directory),
        pcap: Some(&pcap),
        pcap_open: false,
        clock_anchor: run.clock_anchor,
        started_ms: run.started_ms,
        root_cookie: run.root_task_cookie,
        run_finished: true,
        current_boot: false,
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while view.scan.is_none() || view.scan_rx.is_some() {
        let _ = ctx.run_ui(egui::RawInput::default(), |root| {
            view.tick(root.ctx(), input);
        });
        assert!(Instant::now() < deadline, "the GUI's index never arrived");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(view.scan_error, None);
    let gui = fingerprint(view.scan.as_ref().unwrap());

    // Headless: the run's record and the same settings.
    let saved = antinomie_triage::SavedRun::new(
        run.clone(),
        antinomie_triage::TriageSettings {
            data_dir: Some(spool.directory.clone()),
            ..Default::default()
        },
    );
    assert_eq!(saved.pcap.as_deref(), Some(pcap.as_path()));
    let headless = saved.scan(&Arc::new(AtomicBool::new(false))).unwrap();
    assert_eq!(fingerprint(&headless), gui);
    assert!(!headless.findings.is_empty() && !headless.process.is_empty());
}
