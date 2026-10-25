// SPDX-License-Identifier: GPL-3.0-only
//! Opt-in whole-recording QA using the same triage index and table renderers.
use super::*;

#[test]
#[ignore = "requires ANTINOMIE_TORTURE_RUN and ANTINOMIE_TORTURE_REPORT; optional ANTINOMIE_TORTURE_PCAP"]
fn recorded_torture_triage() {
    let directory = std::path::PathBuf::from(std::env::var_os("ANTINOMIE_TORTURE_RUN").unwrap());
    let output = std::path::PathBuf::from(std::env::var_os("ANTINOMIE_TORTURE_REPORT").unwrap());
    let pcap = std::env::var_os("ANTINOMIE_TORTURE_PCAP").map(std::path::PathBuf::from);
    let run: antinomie_monitor_core::RunSummary =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).unwrap()).unwrap();
    let request = ScanRequest {
        root_cookie: run.root_task_cookie,
        clock_anchor: run.clock_anchor,
        started_ms: run.started_ms,
        run_finished: true,
        owned_pcap: pcap.is_some(),
        identity: Some((run.vm_id.clone(), run.boot_id.clone(), run.id.clone())),
        ..Default::default()
    };
    let started = Instant::now();
    let scan = scan_archive_query(
        &directory,
        pcap.as_deref(),
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
    )
    .unwrap();
    let indexed_seconds = started.elapsed().as_secs_f64();
    let mut report = serde_json::json!({
        "indexed_seconds": indexed_seconds,
        "coverage": scan.coverage, "partial": scan.partial,
        "event_error": scan.event_error, "event_journal": scan.event_journal,
        "process_rows": scan.process.len(), "findings": scan.findings.len(), "findings_omitted": scan.findings_omitted,
        "opened": scan.opened.len(), "opened_omitted": scan.opened_omitted,
        "read": scan.read.len(), "read_omitted": scan.read_omitted,
        "changed": scan.changed.len(), "changed_omitted": scan.changed_omitted,
        "bpf": scan.bpf.len(), "bpf_omitted": scan.bpf_omitted,
        "http": scan.http.len(), "http_omitted": scan.http_omitted,
        "dns": scan.counts.dns, "network_counts": scan.network_counts, "network_warning": scan.network_warning,
    });
    let mut view = TriageView::default();
    view.scan = Some(scan);
    let ctx = egui::Context::default();
    let input = TriageInput {
        vm_id: Some(&run.vm_id),
        boot_id: Some(&run.boot_id),
        run_id: Some(&run.id),
        archive: Some(&directory),
        root_cookie: run.root_task_cookie,
        run_finished: true,
        ..TriageInput::empty()
    };
    let mut frames = Vec::new();
    // All non-engine triage tables, repeated after font/table warmup. No live
    // backend, outbound enrichment or detection scans are started by this probe.
    for pass in 0..3 {
        for pane in 0..10 {
            let started = Instant::now();
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1280.0, 820.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| match pane {
                        0 => {
                            view.process = ProcessTab::Tree;
                            view.process(ui, &input);
                        }
                        1 => {
                            view.process = ProcessTab::Suspicious;
                            view.process(ui, &input);
                        }
                        2..=4 => {
                            view.files =
                                [FileTab::Opened, FileTab::Read, FileTab::Changed][pane - 2];
                            view.files(ui, &input);
                        }
                        5..=8 => {
                            view.new_tab = [
                                NewTab::Endpoints,
                                NewTab::Domains,
                                NewTab::Urls,
                                NewTab::Tls,
                            ][pane - 5];
                            view.new_network(ui, &input);
                        }
                        _ => summary::show(&mut view, ui, &input),
                    });
                },
            );
            if pass > 0 {
                frames.push(
                    serde_json::json!({"pane":pane,"ms":started.elapsed().as_secs_f64()*1000.0}),
                );
            }
        }
    }
    report["render_frames"] = serde_json::json!(frames);
    std::fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}
