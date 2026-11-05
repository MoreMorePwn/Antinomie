// SPDX-License-Identifier: GPL-3.0-only
//! The Summary as drawn: its sections in order, the header, the Key findings,
//! clicks that leave it, and the layout at the largest text.
use super::*;
use crate::app::tests::texts;
use antinomie_monitor_core::{
    AnalysisEntry, AnalysisKind, AnalysisReport, AnalysisSection, AnalysisSectionState,
    AnalysisState,
};

fn node(
    pid: u32,
    cookie: u64,
    parent: Option<(u32, u64)>,
    comm: &str,
    argv: &[&str],
    ns: u64,
) -> ProcessNode {
    ProcessNode {
        parent: parent.map(|(pid, cookie)| TaskKey { pid, cookie }),
        call_id: None,
        depth: usize::from(parent.is_some()),
        pid,
        cookie,
        comm: comm.into(),
        parent_missing: false,
        tid: pid,
        argv: argv.iter().map(|a| (*a).to_owned()).collect(),
        first_ns: Some(ns),
        last_ns: Some(ns + 1_000_000_000),
        state: "task exit, 0".into(),
        end_signal: None,
        exec_history: vec![comm.into()],
        thread: false,
        renames: Vec::new(),
        in_call: None,
        forked: false,
        record: Default::default(),
    }
}

fn finding(rule: &str, tier: &str, ns: u64, pid: u32, cookie: u64, object: &str) -> Finding {
    let mut cells: Vec<Cell> = rules::HEADERS
        .iter()
        .map(|header| table::cell(*header, theme::text(), false))
        .collect();
    cells[0].text = rule.into();
    cells[rules::COL_TIER].text = tier.into();
    Finding {
        key: (1, 2, ns),
        cells,
        call_id: ns,
        values: vec![
            ("finding.rule", RowValue::Text(rule.into())),
            ("finding.tier", RowValue::Text(tier.into())),
            (
                "finding.category",
                RowValue::Text(rule.split('.').next().unwrap_or("").into()),
            ),
            ("finding.count", RowValue::Number(3)),
            ("finding.first_ns", RowValue::Number(i128::from(ns))),
            ("finding.object", RowValue::Text(object.into())),
            (
                "finding.summary",
                RowValue::Text(format!("{rule} on {object}. Details follow.")),
            ),
            ("process.pid", RowValue::Number(i128::from(pid))),
            ("process.cookie", RowValue::Number(i128::from(cookie))),
        ],
    }
}

fn analysis() -> AnalysisReport {
    let entry = |label: &str, value: &str| AnalysisEntry {
        label: label.into(),
        value: value.into(),
        offset: None,
        record: None,
    };
    AnalysisReport {
        id: "r".into(),
        state: AnalysisState::Complete,
        source_path: "/tmp/demo-all".into(),
        specimen_sha256: Some("3f9a".repeat(16)),
        specimen_len: Some(812 * 1024),
        reason: None,
        sections: vec![AnalysisSection {
            kind: AnalysisKind::Identification,
            state: AnalysisSectionState::Complete,
            summary: String::new(),
            entries: vec![entry(
                "format: file magic",
                "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped",
            )],
            tools: Vec::new(),
            listing: None,
            disassembly: None,
            limits: Vec::new(),
        }],
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits: None,
    }
}

/// A view with a scan of synthetic processes and findings.
fn fixture() -> (PacketSpool, TriageView) {
    let files = PacketSpool::new().unwrap();
    let mut raw = std::fs::File::create(files.directory.join("telemetry.raw")).unwrap();
    super::super::tests::write_rwx_calls(&mut raw, 0..1);
    raw.sync_all().unwrap();
    let mut scan = scan_archive(&files.directory, None, false, &AtomicBool::new(false)).unwrap();
    scan.process = vec![
        node(401, 1, None, "demo-all", &["ps", "aux"], 1_000_000),
        node(420, 4, Some((401, 1)), "sh", &["sh"], 2_000_000),
        node(421, 5, Some((401, 1)), "curl", &["curl"], 3_000_000),
    ];
    scan.findings = vec![
        finding(
            "persistence.cron",
            "high",
            2_100_000_000,
            401,
            1,
            "/etc/cron.d/apt-update",
        ),
        finding(
            "injection.ptrace_poke",
            "high",
            4_000_000_000,
            401,
            1,
            "pid 418 poke",
        ),
        finding(
            "execution.dropped_exec",
            "high",
            1_200_000_000,
            401,
            1,
            "/tmp/.x/kdev",
        ),
        finding(
            "injection.ld_preload_env",
            "medium",
            3_300_000_000,
            420,
            4,
            "/tmp/.x/hook.so",
        ),
        finding(
            "execution.download_cradle",
            "medium",
            1_000_000_000,
            421,
            5,
            "45.9.148.9:80",
        ),
        finding(
            "evasion.history_clear",
            "medium",
            3_400_000_000,
            420,
            4,
            "HISTFILE=/dev/null",
        ),
        finding("discovery.system_info", "low", 500_000_000, 420, 4, "uname"),
        finding("discovery.process_enum", "low", 600_000_000, 420, 4, "ps"),
        finding("discovery.user_enum", "info", 0, 420, 4, "id"),
    ];
    scan.counts.finding_tiers = [3, 3, 2, 21];
    let mut view = TriageView::default();
    view.scan = Some(scan);
    (files, view)
}

fn draw_at(
    ctx: &egui::Context,
    view: &mut TriageView,
    size: egui::Vec2,
    events: Vec<egui::Event>,
    time: f64,
    analysis: Option<&AntinomieReport>,
) -> egui::FullOutput {
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            time: Some(time),
            events,
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
                let input = TriageInput {
                    analysis,
                    ..TriageInput::empty()
                };
                show(view, ui, &input);
            });
        },
    )
}

type AntinomieReport = AnalysisReport;

fn settle(
    ctx: &egui::Context,
    view: &mut TriageView,
    size: egui::Vec2,
    analysis: Option<&AnalysisReport>,
) -> egui::FullOutput {
    let mut out = draw_at(ctx, view, size, vec![], 0.0, analysis);
    for n in 1..4 {
        out = draw_at(ctx, view, size, vec![], f64::from(n) * 0.02, analysis);
    }
    out
}

fn context(font: f32) -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    theme::text_size(&ctx, font);
    ctx
}

/// The lowest place `wanted` is drawn (a title can also be a small label above).
fn y(out: &egui::FullOutput, wanted: &str) -> f32 {
    texts(out)
        .into_iter()
        .filter(|(text, _)| text == wanted)
        .map(|(_, rect)| rect.min.y)
        .reduce(f32::max)
        .unwrap_or_else(|| panic!("{wanted:?} not drawn in {:?}", texts(out)))
}

fn has(out: &egui::FullOutput, wanted: &str) -> bool {
    texts(out).iter().any(|(text, _)| text == wanted)
}

fn click(ctx: &egui::Context, view: &mut TriageView, size: egui::Vec2, at: egui::Pos2) {
    for (n, pressed) in [true, false].into_iter().enumerate() {
        draw_at(
            ctx,
            view,
            size,
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            1.0 + n as f64 * 0.02,
            None,
        );
    }
}

const WIDE: egui::Vec2 = egui::vec2(1280.0, 2600.0);

#[test]
fn the_sections_come_in_the_order_of_the_design() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let order = [
        "Key findings",
        "Indicators",
        "Relationships",
        "Processes of interest",
        "Files",
        "Network",
        "Detection engines",
        "IOC datasets",
    ];
    let ys: Vec<f32> = order.iter().map(|title| y(&out, title)).collect();
    assert!(
        ys.windows(2).all(|pair| pair[0] < pair[1]),
        "{order:?} at {ys:?}"
    );
    // The header leads, and the old sections are gone.
    assert!(y(&out, "Family candidates") < ys[0]);
    for gone in [
        "Observed activity",
        "Behavior & files",
        "Network evidence",
        "Detection evidence",
    ] {
        assert!(!has(&out, gone), "{gone}");
    }
}

#[test]
fn the_header_names_the_sample_the_tiers_and_what_the_detections_say() {
    let (_files, mut view) = fixture();
    let report = analysis();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, Some(&report));
    assert!(has(&out, "demo-all"));
    assert!(
        has(&out, "ELF 64-bit x86-64 \u{b7} static \u{b7} 812 KiB"),
        "{:?}",
        texts(&out)
    );
    assert!(has(&out, "SHA-256 3f9a\u{2026}3f9a"));
    for tile in ["3 HIGH", "3 MEDIUM", "2 LOW", "21 info"] {
        assert!(has(&out, tile), "{tile}");
    }
    assert!(has(&out, "\u{26a0} argv/image mismatch in 1 process"));
    assert!(has(&out, "none named by a detection"));
    // Tags from the rules that fired: persistence, injection, discovery.
    for tag in ["persistence", "injection", "discovery", "downloader"] {
        assert!(has(&out, tag), "{tag} in {:?}", texts(&out));
    }
    // No verdict words.
    for word in ["malicious", "Malicious", "score", "Verdict"] {
        assert!(
            !texts(&out).iter().any(|(text, _)| text.contains(word)),
            "{word}"
        );
    }
}

#[test]
fn key_findings_are_six_by_tier_then_first_time_and_all_n_opens_the_table() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let rows = [
        "execution.dropped_exec",
        "persistence.cron",
        "injection.ptrace_poke",
        "execution.download_cradle",
        "injection.ld_preload_env",
        "evasion.history_clear",
    ];
    let ys: Vec<f32> = rows
        .iter()
        .map(|rule| y(&out, rules::rule_title(rule)))
        .collect();
    assert!(
        ys.windows(2).all(|pair| pair[0] < pair[1]),
        "{rows:?} at {ys:?}"
    );
    // The LOW rows and the INFO row do not fit in six.
    assert!(!has(&out, rules::rule_title("discovery.system_info")));
    assert!(!has(&out, rules::rule_title("discovery.user_enum")));
    assert!(has(&out, "\u{d7}3"));
    let all = texts(&out)
        .into_iter()
        .find(|(text, _)| text == "all 8 \u{2192}")
        .expect("all 8")
        .1;
    click(&ctx, &mut view, WIDE, all.center());
    assert!(view.section == Section::Process && view.process == ProcessTab::Suspicious);
}

#[test]
fn a_tier_tile_opens_suspicious_activity_on_that_tier() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let tile = texts(&out)
        .into_iter()
        .find(|(text, _)| text == "2 LOW")
        .unwrap()
        .1;
    click(&ctx, &mut view, WIDE, tile.center());
    assert!(view.section == Section::Process && view.process == ProcessTab::Suspicious);
    assert!(view.scan_request.finding_view.tier_on(rules::Tier::Low));
    assert!(!view.scan_request.finding_view.tier_on(rules::Tier::High));
}

#[test]
fn a_process_of_interest_opens_the_process_tree_on_it() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let link = texts(&out)
        .into_iter()
        .find(|(text, _)| text == "demo-all (401) \u{26a0}")
        .expect("a process of interest")
        .1;
    click(&ctx, &mut view, WIDE, link.center());
    assert!(view.section == Section::Process && view.process == ProcessTab::Tree);
}

#[test]
fn the_relationships_box_toggles_to_the_timeline() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, "Open full graph") && has(&out, "Graph"));
    let tab = texts(&out)
        .into_iter()
        .find(|(text, _)| text == "Timeline")
        .unwrap()
        .1;
    click(&ctx, &mut view, WIDE, tab.center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(!has(&out, "Open full graph"));
    assert!(
        has(&out, "demo-all (401) \u{26a0}"),
        "the root's lane: {:?}",
        texts(&out)
    );
}

#[test]
fn the_layout_holds_at_the_largest_text_in_a_small_window() {
    for (size, font) in [
        (egui::vec2(1280.0, 2600.0), 16.0),
        (egui::vec2(800.0, 3600.0), 24.0),
    ] {
        let (_files, mut view) = fixture();
        let report = analysis();
        let ctx = context(font);
        let out = settle(&ctx, &mut view, size, Some(&report));
        for (text, rect) in texts(&out) {
            assert!(
                rect.right() <= size.x + 1.0,
                "{text:?} runs past the window ({}) at {font} pt",
                rect.right()
            );
        }
        for title in [
            "Key findings",
            "Indicators",
            "Relationships",
            "Detection engines",
        ] {
            assert!(has(&out, title), "{title} at {font} pt");
        }
    }
}
