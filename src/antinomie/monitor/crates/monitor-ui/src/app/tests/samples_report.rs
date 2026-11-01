// SPDX-License-Identifier: GPL-3.0-only
//! Export report… for a library sample: the report the Samples window's data
//! makes (every run, lineage, merged indicators, credits, custody), the
//! files the window writes, and the Exported entry it adds to the custody log.
use super::samples_detail::{save_digest, save_run, until};
use super::*;
use crate::app::samples_page::SamplesPage;
use antinomie_monitor_core::report::sample::Format;
use antinomie_monitor_core::samples::Library;

fn vms() -> Vec<(String, String)> {
    vec![("vm".into(), "Debian".into())]
}

/// The fixture library with two runs that have digests and one that has not.
fn fixture(name: &str) -> (PathBuf, String, BackendOptions) {
    let root = super::samples_list::temp(name);
    let (script, _, _) = super::samples_list::fixture(&root);
    let first = save_run(&root, &script, "install.sh", "r1", 1_000, true);
    let second = save_run(&root, &script, "install.sh", "r2", 9_000, false);
    save_run(&root, &script, "install.sh", "r3", 10_000, false);
    save_digest(&first, "medium", false);
    save_digest(&second, "high", true);
    let options = BackendOptions {
        data_dir: root.clone(),
        ..BackendOptions::default()
    };
    (root, script, options)
}

#[test]
fn the_report_holds_every_part_of_the_sample_window() {
    let (root, script, options) = fixture("report-build");
    let report = SamplesPage::report_for_test(&options, &vms(), &script).unwrap();
    assert_eq!(report.sample.sha256, script);
    assert_eq!(report.sample.name, "install.sh");
    assert!(report.sample.tags.iter().any(|t| t.value == "malicious"));
    assert!(!report.sample.origins.is_empty());
    // Runs in start order, each with its own assessment; run 3 was never read.
    let runs: Vec<(usize, &str, &str)> = report
        .runs
        .iter()
        .map(|r| (r.number, r.run_id.as_str(), r.assessment.as_str()))
        .collect();
    assert_eq!(
        runs,
        [
            (1, "r1", "matched_indicators"),
            (2, "r2", "matched_indicators"),
            (3, "r3", "not_read")
        ]
    );
    assert_eq!(report.runs[0].vm_name, "Debian");
    assert_eq!(report.assessment(), "matched_indicators");
    // Static analysis from the newest finished report (run 1).
    assert!(report.static_analysis.available);
    assert_eq!(report.static_analysis.from_run, Some(1));
    assert!(report
        .static_analysis
        .checks
        .iter()
        .any(|c| c.state == "complete"));
    // The YARA rule of run 2, merged, with the engine and the family.
    let yara = report
        .detections
        .iter()
        .find(|h| h.rule_id == "cron_dropper")
        .unwrap();
    assert_eq!(
        (
            yara.engine.as_str(),
            yara.family.as_str(),
            yara.runs.clone()
        ),
        ("YARA", "CronDropper", vec![2])
    );
    // Indicators merged across the runs.
    assert!(
        report
            .indicators
            .iter()
            .any(|i| i.value == "198.51.100.7:80" && i.runs == [1, 2]),
        "{:?}",
        report.indicators
    );
    assert!(report
        .indicators
        .iter()
        .any(|i| i.value == "update.example.test" && i.matched));
    assert!(report.attack.iter().any(|t| t.id == "T1053.003"));
    // Lineage: the dropped sample is a child of the library.
    assert!(
        report
            .lineage
            .children
            .iter()
            .any(|c| c.kind == "library sample" || c.kind == "captured file"),
        "{:?}",
        report.lineage
    );
    assert!(report.lineage.parents.is_empty() && report.lineage.reason.contains("No parent"));
    // The custody log with its verification.
    assert!(report.custody.verified && report.custody.entries as usize == report.custody.log.len());
    assert!(report.custody.log.iter().all(|r| r.state == "verified"));
    assert!(report
        .remarks
        .iter()
        .any(|r| r.contains("have not been read by Triage")));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_window_writes_the_files_and_notes_the_export_in_the_custody_log() {
    let (root, script, options) = fixture("report-write");
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.options.data_dir = root.clone();
    app.snapshot.vms.push(VmConfig {
        id: "vm".into(),
        name: "Debian".into(),
        ..VmConfig::default()
    });
    app.rules_ui.set_packs_for_test(Vec::new());
    app.open_library(crate::workspace::LibraryPage::Samples);
    until(&mut app, &ctx, |app| app.samples_page.is_loaded());
    // The list's menu opens it for a sample whose window is not open.
    app.samples_page.open_report_for(&script, "install.sh");
    assert!(app.samples_page.report_open());
    let before = Library::open(&root).unwrap().events(&script).unwrap().len();
    let out = root.join("reports-out");
    app.samples_page.start_report_for_test(
        &ctx,
        &options,
        &vms(),
        &[Format::Html, Format::Json, Format::Markdown, Format::Stix],
        out.to_str().unwrap(),
    );
    until(&mut app, &ctx, |app| {
        app.samples_page.report_written().is_some() || app.samples_page.report_failure().is_some()
    });
    assert_eq!(app.samples_page.report_failure(), None);
    let files = app.samples_page.report_written().unwrap();
    assert_eq!(files.len(), 4);
    let json = std::fs::read_to_string(
        files
            .iter()
            .find(|p| {
                p.to_string_lossy().ends_with(".json") && !p.to_string_lossy().contains(".stix.")
            })
            .unwrap(),
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schema"], "antinomie-sample-report");
    assert_eq!(value["runs"].as_array().unwrap().len(), 3);
    // Defanged by default in the readable formats, raw in the exchange ones.
    let html = std::fs::read_to_string(
        files
            .iter()
            .find(|p| p.to_string_lossy().ends_with(".html"))
            .unwrap(),
    )
    .unwrap();
    assert!(html.contains("198[.]51[.]100[.]7:80") && !html.contains("198.51.100.7:80"));
    assert!(json.contains("198.51.100.7:80"));
    let events = Library::open(&root).unwrap().events(&script).unwrap();
    assert_eq!(events.len(), before + 1);
    assert_eq!(events.last().unwrap().event.key(), "exported");
    assert!(Library::open(&root)
        .unwrap()
        .custody_check(&script)
        .unwrap()
        .ok());
    // The sample window reads the log again.
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_sample_that_left_the_library_fails_with_a_message() {
    let (root, _, options) = fixture("report-missing");
    let error = SamplesPage::report_for_test(&options, &vms(), &"0f".repeat(32)).unwrap_err();
    assert!(error.contains("no longer in the library"), "{error}");
    let _ = std::fs::remove_dir_all(root);
}
