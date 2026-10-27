// SPDX-License-Identifier: GPL-3.0-only
//! The sample window: its Summary, Runs and Custody log tabs, and the jump
//! from a run row to Triage in the run's own VM.
use super::*;
use antinomie_monitor_core::{
    strings_regex::Category, AnalysisEntry, AnalysisKind, AnalysisReport, AnalysisSection,
    AnalysisSectionState, AnalysisState,
};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 820.0);

fn until(app: &mut MonitorApp, ctx: &egui::Context, ready: impl Fn(&MonitorApp) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        render(app, ctx, SIZE);
        if ready(app) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready(app),
        "the window did not settle: {}",
        app.samples_page.detail_state()
    );
}

fn strings_section() -> AnalysisSection {
    let entry = |offset: u64, text: &str| AnalysisEntry {
        label: "ASCII".into(),
        value: text.into(),
        offset: Some(offset),
        record: None,
    };
    let mut section = AnalysisSection::new(AnalysisKind::Strings);
    section.state = AnalysisSectionState::Complete;
    section.summary = "8 strings".into();
    section.entries = vec![
        entry(0x10, "fetching http://198.51.100.7/payload.sh now"),
        entry(0x80, "connect to 203.0.113.5 port 4444"),
        entry(0x100, "write /etc/cron.d/update-helper"),
        entry(0x140, "plain text with nothing in it"),
        entry(0x180, "GCC: (Debian 12.2.0-14) 12.2.0"),
    ];
    section
}

/// A run of `sha` on VM `vm` saved under `root`, with a static report when
/// `report` is set.
pub(super) fn save_run(
    root: &std::path::Path,
    sha: &str,
    name: &str,
    id: &str,
    started: u64,
    report: bool,
) -> RunSummary {
    let directory = root.join("vm").join("runs").join(id);
    std::fs::create_dir_all(&directory).unwrap();
    // The VM's folder is found by its config.
    let vm = VmConfig {
        id: "vm".into(),
        name: "Debian".into(),
        ..VmConfig::default()
    };
    std::fs::write(
        root.join("vm").join("config.json"),
        serde_json::to_vec(&vm).unwrap(),
    )
    .unwrap();
    let mut run = super::run(id);
    run.started_ms = Some(started);
    run.state = RunState::Finished;
    run.directory = directory.clone();
    run.request.path = "/tmp/install.sh".into();
    run.request.sample = Some(antinomie_monitor_core::samples::SampleRef {
        sha256: sha.into(),
        name: name.into(),
    });
    if report {
        let analysis = AnalysisReport {
            id: format!("rep-{id}"),
            state: AnalysisState::Complete,
            source_path: "/tmp/install.sh".into(),
            specimen_sha256: Some(sha.into()),
            specimen_len: Some(4096),
            reason: None,
            sections: vec![strings_section()],
            layer: None,
            specimen_source: None,
        };
        std::fs::create_dir_all(directory.join("analysis")).unwrap();
        std::fs::write(
            directory.join("analysis").join("report.json"),
            serde_json::to_vec(&analysis).unwrap(),
        )
        .unwrap();
        run.analysis = Some(analysis);
    }
    std::fs::write(
        directory.join("run.json"),
        serde_json::to_vec(&run).unwrap(),
    )
    .unwrap();
    run
}

/// What Triage would have kept for `run` of the sample: a high finding with
/// a technique and a VM check, a YARA hit and two indicators.
pub(super) fn save_digest(run: &RunSummary, tier: &str, hit: bool) {
    use antinomie_monitor_core::run_digest::{
        Behaviour, BehaviourHit, DetectionHit, EvasionCheck, IndicatorEntry, RunDigest,
    };
    RunDigest::update(&run.directory, |digest| {
        digest.behaviour = Some(Behaviour {
            highest: tier.into(),
            rules: vec![BehaviourHit {
                rule: "persistence.cron".into(),
                tier: tier.into(),
                category: "persistence".into(),
                attack: vec!["T1053.003".into()],
                count: 1,
                first_ns: 1,
            }],
            evasion: vec![EvasionCheck {
                category: "Virtual machine".into(),
                rule: "evasion.sandbox_probe".into(),
                object: "/sys/class/dmi/id/product_name".into(),
                summary: "read: Standard PC (Q35 + ICH9, 2009)".into(),
                process: "/bin/sh".into(),
                count: 1,
            }],
        });
        digest.detections = Some(if hit {
            vec![DetectionHit {
                engine: "YARA".into(),
                rule_id: "cron_dropper".into(),
                title: "cron_dropper".into(),
                severity: "high".into(),
                mitre: vec!["T1053.003".into()],
                count: 1,
            }]
        } else {
            Vec::new()
        });
        digest.indicators = Some(vec![
            IndicatorEntry {
                ty: "endpoint".into(),
                value: "198.51.100.7:80".into(),
                matched: false,
            },
            IndicatorEntry {
                ty: "domain".into(),
                value: "update.example.test".into(),
                matched: true,
            },
        ]);
    })
    .unwrap();
}

fn window(name: &str) -> (MonitorApp, egui::Context, String, PathBuf) {
    let root = super::samples_list::temp(name);
    let (script, _, _) = super::samples_list::fixture(&root);
    // Replace the fixture's invented runs by runs that exist on disk.
    save_run(&root, &script, "install.sh", "r1", 1_000, true);
    save_run(&root, &script, "install.sh", "r2", 9_000, false);
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
    app.samples_page.open_detail(&script);
    (app, ctx, script, root)
}

#[test]
fn the_window_reads_the_runs_and_scans_the_static_report() {
    let (mut app, ctx, _, root) = window("detail-read");
    until(&mut app, &ctx, |app| {
        matches!(app.samples_page.detail_probe(), Some((_, _, Some(_))))
    });
    let (runs, report, strings) = app.samples_page.detail_probe().unwrap();
    assert_eq!(runs, 2);
    assert!(report);
    let (interesting, matches, total) = strings.unwrap();
    // The URL, the address and the persistence path; the rest is not.
    assert!(interesting >= 2, "{interesting} interesting strings");
    assert!(matches >= interesting);
    assert!(total >= matches as u64);
    // Newest first.
    assert_eq!(app.samples_page.detail_run_ids(), ["r2", "r1"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_summary_adds_up_the_runs_triage_digests() {
    let root = super::samples_list::temp("detail-digest");
    let (script, _, _) = super::samples_list::fixture(&root);
    let first = save_run(&root, &script, "install.sh", "r1", 1_000, false);
    let second = save_run(&root, &script, "install.sh", "r2", 9_000, false);
    // Run 3 was never opened in Triage.
    save_run(&root, &script, "install.sh", "r3", 10_000, false);
    save_digest(&first, "medium", false);
    save_digest(&second, "high", true);
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
    app.samples_page.open_detail(&script);
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_rollup().is_some()
    });
    let rollup = app.samples_page.detail_rollup().unwrap();
    assert_eq!((rollup.runs, rollup.triaged, rollup.detected), (3, 2, 2));
    assert_eq!(rollup.highest, Some(("high".into(), vec![2])));
    assert_eq!(rollup.rules.len(), 1);
    assert_eq!(rollup.rules[0].runs, [2]);
    assert_eq!(rollup.tactics[0].tactic, "Persistence");
    assert_eq!(rollup.tactics[0].techniques[0].runs, [1, 2]);
    assert_eq!(rollup.evasion[0].checks[0].runs, [1, 2]);
    let indicators = rollup.indicators.unwrap();
    assert_eq!(
        (
            indicators.total,
            indicators.in_every_run,
            indicators.matched
        ),
        (2, 2, 1)
    );
    // The page draws with the sections present.
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn every_tab_draws_and_the_back_link_returns_to_the_list() {
    let (mut app, ctx, _, root) = window("detail-tabs");
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_probe().is_some()
    });
    for tab in ["summary", "runs", "custody", "summary"] {
        app.samples_page.show_detail_tab(tab);
        for _ in 0..3 {
            render(&mut app, &ctx, SIZE);
        }
    }
    assert!(app.samples_page.detail_open());
    app.samples_page.close_detail();
    render(&mut app, &ctx, SIZE);
    assert!(!app.samples_page.detail_open());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_run_opens_in_the_triage_of_its_own_vm() {
    let (mut app, ctx, _, root) = window("detail-open");
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_probe().is_some()
    });
    let run = save_run(&root, &"aa".repeat(32), "x", "rx", 5_000, false);
    app.selected = Some("other".into());
    app.open_sample_run(&run, crate::workspace::Panel::Triage, None);
    app.advance_run_open();
    // The VM is selected and its history asked for; the run is not there yet.
    assert_eq!(app.selected.as_deref(), Some("vm"));
    assert!(app.samples_page.open_run_pending());
    app.history.push(run);
    app.advance_run_open();
    assert!(!app.samples_page.open_run_pending());
    assert_eq!(app.selected_run.as_deref(), Some("rx"));
    assert_eq!(app.focus_panel, Some(crate::workspace::Panel::Triage));
    let _ = Category::Network;
    let _ = std::fs::remove_dir_all(root);
}
