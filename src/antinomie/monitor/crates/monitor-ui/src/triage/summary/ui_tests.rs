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
            (
                "finding.technique",
                RowValue::List(match rule {
                    "persistence.cron" => vec!["T1053.003".to_owned()],
                    "injection.ptrace_poke" => vec!["T1055.008".to_owned()],
                    _ => Vec::new(),
                }),
            ),
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
    ];
    let ys: Vec<f32> = order.iter().map(|title| y(&out, title)).collect();
    assert!(
        ys.windows(2).all(|pair| pair[0] < pair[1]),
        "{order:?} at {ys:?}"
    );
    // The header leads, and the old sections are gone.
    assert!(!has(&out, "IOC datasets"), "the IOC datasets box is gone");
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
        .filter(|(text, _)| text == "demo-all (401)")
        .map(|(_, rect)| rect)
        .reduce(|a, b| if b.min.y > a.min.y { b } else { a })
        .expect("a process of interest");
    click(&ctx, &mut view, WIDE, link.center());
    assert!(view.section == Section::Process && view.process == ProcessTab::Tree);
}

/// The lowest place `wanted` is drawn, as `y` does.
fn find(out: &egui::FullOutput, wanted: &str) -> egui::Rect {
    texts(out)
        .into_iter()
        .filter(|(text, _)| text == wanted)
        .map(|(_, rect)| rect)
        .reduce(|a, b| if b.min.y > a.min.y { b } else { a })
        .unwrap_or_else(|| panic!("{wanted:?} not drawn in {:?}", texts(out)))
}

fn starting(out: &egui::FullOutput, prefix: &str) -> Option<(String, egui::Rect)> {
    texts(out)
        .into_iter()
        .find(|(text, _)| text.starts_with(prefix))
}

fn circles(out: &egui::FullOutput) -> Vec<egui::Pos2> {
    fn walk(shape: &egui::Shape, found: &mut Vec<egui::Pos2>) {
        match shape {
            egui::Shape::Circle(circle) => found.push(circle.center),
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    for clipped in &out.shapes {
        walk(&clipped.shape, &mut found);
    }
    found
}

fn wheel(ctx: &egui::Context, view: &mut TriageView, size: egui::Vec2, at: egui::Pos2, dy: f32) {
    draw_at(
        ctx,
        view,
        size,
        vec![
            egui::Event::PointerMoved(at),
            egui::Event::MouseWheel {
                phase: egui::TouchPhase::Move,
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, dy),
                modifiers: egui::Modifiers::NONE,
            },
        ],
        2.0,
        None,
    );
}

/// The fixture with forty more children of the root, and `lows` more LOW findings.
fn crowded(children: u32, lows: u32) -> (PacketSpool, TriageView) {
    let (files, mut view) = fixture();
    let scan = view.scan.as_mut().unwrap();
    for n in 0..children {
        scan.process.push(node(
            1000 + n,
            100 + u64::from(n),
            Some((401, 1)),
            "ls",
            &["ls"],
            5_000_000 + u64::from(n),
        ));
    }
    for n in 0..lows {
        scan.findings.push(finding(
            &format!("discovery.extra{n:02}"),
            "low",
            700_000_000 + u64::from(n),
            420,
            4,
            "x",
        ));
    }
    (files, view)
}

#[test]
fn refresh_is_an_icon_and_open_properties_is_gone() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, egui_phosphor::regular::ARROW_CLOCKWISE));
    assert!(!has(&out, "Refresh") && !has(&out, "Open properties"));
}

#[test]
fn a_findings_description_is_on_a_line_below_its_row() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let title = find(&out, rules::rule_title("execution.dropped_exec"));
    let (_, why) =
        starting(&out, "A program that the run itself wrote").expect("the description line");
    assert!(why.min.y > title.max.y - 2.0, "{why:?} under {title:?}");
    assert!(why.min.x <= title.min.x + 1.0, "starts at the row's left");
}

#[test]
fn show_more_lists_every_finding_in_a_scrolling_list_and_show_less_folds_it() {
    let (_files, mut view) = crowded(0, 12);
    let ctx = context(16.0);
    let size = egui::vec2(1280.0, 1600.0);
    let out = settle(&ctx, &mut view, size, None);
    let first = rules::rule_title("execution.dropped_exec");
    assert!(has(&out, "Show more (14)"), "{:?}", texts(&out));
    assert!(!has(&out, "discovery.extra05"));
    click(&ctx, &mut view, size, find(&out, "Show more (14)").center());
    let out = settle(&ctx, &mut view, size, None);
    assert!(has(&out, "Show less"));
    let before = find(&out, first).min.y;
    // The list holds more than it shows: the last row is below the cut.
    assert!(!has(&out, "discovery.extra11"), "{:?}", texts(&out));
    wheel(&ctx, &mut view, size, find(&out, first).center(), -400.0);
    let out = settle(&ctx, &mut view, size, None);
    let moved = texts(&out)
        .into_iter()
        .find(|(text, _)| text == first)
        .map(|(_, rect)| rect.min.y);
    assert!(
        moved.is_none_or(|y| y < before - 20.0),
        "{moved:?} {before}"
    );
    assert!(has(&out, "discovery.extra11"), "scrolled to the end");
    click(&ctx, &mut view, size, find(&out, "Show less").center());
    let out = settle(&ctx, &mut view, size, None);
    assert!(has(&out, "Show more (14)"));
}

fn with_indicators(view: &mut TriageView) {
    let mut all = indicators::tests::sample();
    for n in 0..6 {
        all.push(indicators::tests::indicator(
            antinomie_monitor_core::ioc::indicator::Type::Endpoint,
            &format!("10.1.1.{n}:443"),
        ));
    }
    view.scan.as_mut().unwrap().ioc = Some(std::sync::Arc::new(
        crate::triage::ioc_scan::IocScan::for_tests(all),
    ));
}

#[test]
fn indicators_are_a_tree_with_show_more_and_the_dataset_line_in_its_header() {
    let (_files, mut view) = fixture();
    with_indicators(&mut view);
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    for title in ["Endpoints (7)", "DNS names (1)", "URLs (2)", "Files (1)"] {
        assert!(has(&out, title), "{title}: {:?}", texts(&out));
    }
    let ys = ["Endpoints (7)", "DNS names (1)", "URLs (2)", "Files (1)"].map(|t| y(&out, t));
    assert!(ys.windows(2).all(|pair| pair[0] < pair[1]), "{ys:?}");
    assert!(has(&out, "Copy all") && has(&out, "Export"));
    // Five endpoints show; the other two wait behind "Show 2 more".
    assert!(has(&out, "45.9.148.9:80") && has(&out, "10.1.1.3:443"));
    assert!(!has(&out, "10.1.1.5:443"));
    click(&ctx, &mut view, WIDE, find(&out, "Show 2 more").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, "10.1.1.5:443") && has(&out, "Show fewer"));
    // "x of y indicators matched" sits in the Indicators header row.
    let (line, rect) = starting(&out, "0 of ").expect("the dataset line");
    assert!(line.contains("indicators matched"), "{line}");
    assert!((rect.center().y - find(&out, "Indicators").center().y).abs() < 14.0);
    assert!(!has(&out, "Open IOC") && !has(&out, "IOC datasets"));
    // A branch folds.
    click(&ctx, &mut view, WIDE, find(&out, "Endpoints (7)").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(!has(&out, "10.1.1.3:443"), "{:?}", texts(&out));
}

#[test]
fn the_relationships_box_is_compact_or_full_and_has_no_timeline() {
    let (_files, mut view) = crowded(40, 0);
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, "Compact") && has(&out, "Full"));
    for gone in ["Timeline", "Graph", "Open full graph"] {
        assert!(!has(&out, gone), "{gone}");
    }
    let count = |out: &egui::FullOutput| -> (usize, usize) {
        let (line, _) = texts(out)
            .into_iter()
            .find(|(text, _)| text.contains(" nodes. Processes to the right"))
            .expect("the node count");
        let words: Vec<&str> = line.split_whitespace().collect();
        (words[0].parse().unwrap(), words[2].parse().unwrap())
    };
    let (shown, total) = count(&out);
    assert_eq!(total, 44, "43 processes and the injected-into pid 418");
    // The root, fifteen of the children and what joins them.
    assert!(shown < total && shown >= 16, "{shown} of {total}");
    // The base verbs on the edges.
    assert!(has(&out, "exec") && !has(&out, "execed") && !has(&out, "forked"));
    click(&ctx, &mut view, WIDE, find(&out, "Full").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert_eq!(count(&out), (44, 44));
    click(&ctx, &mut view, WIDE, find(&out, "Compact").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert_eq!(count(&out).0, shown);
}

#[test]
fn a_level_is_one_column_however_many_nodes_it_has() {
    let (_files, mut view) = crowded(40, 0);
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    click(&ctx, &mut view, WIDE, find(&out, "Full").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    let ls: Vec<egui::Rect> = texts(&out)
        .into_iter()
        .filter(|(text, _)| text.contains(" ls ("))
        .map(|(_, rect)| rect)
        .collect();
    assert!(ls.len() >= 6, "{} visible", ls.len());
    assert!(
        ls.iter().all(|r| (r.min.x - ls[0].min.x).abs() < 0.5),
        "one column: {ls:?}"
    );
}

#[test]
fn the_zoom_controls_stay_inside_the_box_at_every_width() {
    for width in [420.0, 800.0, 1280.0] {
        let (_files, mut view) = fixture();
        let ctx = context(16.0);
        let size = egui::vec2(width, 2600.0);
        let out = settle(&ctx, &mut view, size, None);
        let relations = find(&out, "Relationships");
        for control in ["\u{2212}", "+", "Fit"] {
            let rect = find(&out, control);
            // The page's frame keeps 12 points of margin plus its own border.
            assert!(
                rect.right() <= width - 12.0,
                "{control} at {width}: {rect:?}"
            );
            assert!(rect.left() >= relations.left(), "{control} at {width}");
        }
    }
}

#[test]
fn the_wheel_scrolls_the_page_outside_the_graph() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let size = egui::vec2(1280.0, 700.0);
    let out = settle(&ctx, &mut view, size, None);
    let before = y(&out, "Key findings");
    wheel(&ctx, &mut view, size, egui::pos2(300.0, 200.0), -300.0);
    let out = settle(&ctx, &mut view, size, None);
    let after = texts(&out)
        .into_iter()
        .find(|(text, _)| text == "Key findings")
        .map(|(_, rect)| rect.min.y);
    assert!(
        after.is_none_or(|y| y < before - 50.0),
        "{after:?} {before}"
    );
}

#[test]
fn the_attack_list_is_folded_after_the_rows_and_its_mermaid_copy_is_at_the_left() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let (_, list) = starting(&out, "MITRE ATT&CK techniques (").expect("the folded list");
    assert!(list.min.y > y(&out, "Network") && list.min.y < y(&out, "Detection engines"));
    assert!(!has(&out, "Tactic colours"), "folded");
    click(&ctx, &mut view, WIDE, list.center());
    let out = settle(&ctx, &mut view, WIDE, None);
    let mermaid = texts(&out)
        .into_iter()
        .filter(|(text, _)| text.contains("Mermaid"))
        .map(|(_, rect)| rect)
        .next_back()
        .expect("Mermaid");
    assert!(mermaid.min.y > list.min.y, "the list's own button");
    assert!(mermaid.min.x < 200.0, "left: {mermaid:?}");
}

#[test]
fn processes_of_interest_share_one_line_with_room_between_dot_count_and_name() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let count = find(&out, "\u{d7}3");
    let name = find(&out, "demo-all (401)");
    assert!((count.min.y - name.min.y).abs() < 0.6, "{count:?} {name:?}");
    assert!(
        (count.center().y - name.center().y).abs() < 1.6,
        "{count:?} {name:?}"
    );
    assert!(name.left() - count.right() >= 8.0, "room before the name");
    let dot = circles(&out)
        .into_iter()
        .find(|c| {
            c.x < count.left() && count.left() - c.x < 24.0 && (c.y - count.center().y).abs() < 6.0
        })
        .expect("the tier dot before the count");
    assert!(count.left() - dot.x >= 8.0, "room after the dot");
    assert!((dot.y - name.center().y).abs() <= 3.0, "{dot:?} {name:?}");
}

#[test]
fn detection_engines_are_cards_without_a_table() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let from = y(&out, "Detection engines");
    let rows: Vec<String> = texts(&out)
        .into_iter()
        .filter(|(_, rect)| rect.min.y >= from)
        .map(|(text, _)| text)
        .collect();
    for header in ["Rule", "Matches", "Severity", "Occurrences"] {
        assert!(
            !rows.iter().any(|text| text == header),
            "{header}: {rows:?}"
        );
    }
    assert!(rows.iter().any(|text| text == "Open results"));
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
