// SPDX-License-Identifier: GPL-3.0-only
//! The Summary as drawn: its sections in order, the header, the Key findings,
//! clicks that leave it, and the layout at the largest text.
use super::*;
use crate::app::tests::texts;
use antinomie_monitor_core::mitre::Tactic;
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
            view.show_relations_window(&root.ctx().clone());
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
    assert!(
        !texts(&out)
            .iter()
            .any(|(text, _)| text.contains("argv/image")),
        "the rule reports it"
    );
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
fn a_click_on_a_cut_description_shows_all_of_it_and_another_folds_it() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let (cut, at) = starting(&out, "A program that the run itself wrote").expect("the description");
    assert!(cut.ends_with('\u{2026}'), "{cut:?} shows it was cut");
    assert!(!cut.contains("second stage"));
    let section = view.section;
    click(&ctx, &mut view, WIDE, at.center());
    let out = settle(&ctx, &mut view, WIDE, None);
    let (whole, at) =
        starting(&out, "A program that the run itself wrote").expect("the description");
    assert!(whole.contains("second stage looks like this."), "{whole:?}");
    assert!(
        view.section == section,
        "the description folds, it does not open the finding"
    );
    click(&ctx, &mut view, WIDE, at.center());
    let out = settle(&ctx, &mut view, WIDE, None);
    let (again, _) =
        starting(&out, "A program that the run itself wrote").expect("the description");
    assert_eq!(again, cut);
}

/// The colour a text was drawn in (its first section's).
fn colour(out: &egui::FullOutput, wanted: &str) -> egui::Color32 {
    format_of(out, wanted).color
}

fn format_of(out: &egui::FullOutput, wanted: &str) -> egui::text::TextFormat {
    fn walk(shape: &egui::Shape, wanted: &str, found: &mut Option<egui::text::TextFormat>) {
        match shape {
            egui::Shape::Text(text) if text.galley.text().trim() == wanted => {
                found.get_or_insert_with(|| text.galley.job.sections[0].format.clone());
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, wanted, found)),
            _ => {}
        }
    }
    let mut found = None;
    for shape in &out.shapes {
        walk(&shape.shape, wanted, &mut found);
    }
    found.unwrap_or_else(|| panic!("{wanted:?} not drawn in {:?}", texts(out)))
}

/// Every filled rectangle: its place and its fill.
fn rects(out: &egui::FullOutput) -> Vec<(egui::Rect, egui::Color32)> {
    fn walk(shape: &egui::Shape, found: &mut Vec<(egui::Rect, egui::Color32)>) {
        match shape {
            egui::Shape::Rect(rect) => found.push((rect.rect, rect.fill)),
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    for shape in &out.shapes {
        walk(&shape.shape, &mut found);
    }
    found
}

/// A scroll bar between `top` and `bottom`, right of `text_right`: a narrow
/// rectangle, drawn although the list is not being scrolled.
fn has_scroll_bar(out: &egui::FullOutput, top: f32, bottom: f32, text_right: f32) -> bool {
    rects(out).into_iter().any(|(rect, _)| {
        rect.width() >= 3.0
            && rect.width() <= 16.0
            && rect.height() >= 8.0
            && rect.top() >= top - 12.0
            && rect.bottom() <= bottom + 4.0
            && rect.left() > text_right
    })
}

#[test]
fn show_more_turns_the_findings_into_one_scroll_area_of_the_same_height() {
    let (_files, mut view) = crowded(0, 12);
    let ctx = context(16.0);
    let size = egui::vec2(1280.0, 1600.0);
    let out = settle(&ctx, &mut view, size, None);
    let first = rules::rule_title("execution.dropped_exec");
    assert!(has(&out, "Show more (14)"), "{:?}", texts(&out));
    assert!(!has(&out, "discovery.extra05"));
    let top = find(&out, first).min.y;
    let button = find(&out, "Show more (14)");
    click(&ctx, &mut view, size, button.center());
    let out = settle(&ctx, &mut view, size, None);
    assert!(has(&out, "Show less"));
    // The first six stay where they were, and the button after the list is
    // where it was: the list took the space of the six rows.
    assert!(has(&out, first));
    assert!((find(&out, first).min.y - top).abs() < 1.0);
    let less = find(&out, "Show less");
    assert!(
        (less.min.y - button.min.y).abs() < 6.0,
        "{less:?} {button:?}"
    );
    // No inset box any more; the scroll bar is drawn at the right edge.
    let right = find(&out, first).right();
    assert!(
        has_scroll_bar(&out, top, less.min.y, right),
        "the bar is always drawn"
    );
    assert!(!has(&out, "discovery.extra11"), "{:?}", texts(&out));
    let middle = egui::pos2(300.0, (top + less.min.y) / 2.0);
    for _ in 0..3 {
        wheel(&ctx, &mut view, size, middle, -600.0);
    }
    let out = settle(&ctx, &mut view, size, None);
    assert!(
        has(&out, "discovery.extra11"),
        "a finding past the sixth: {:?}",
        texts(&out)
    );
    click(&ctx, &mut view, size, find(&out, "Show less").center());
    let out = settle(&ctx, &mut view, size, None);
    assert!(has(&out, "Show more (14)") && !has(&out, "discovery.extra11"));
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
    let shut_more = find(&out, "Show 2 more");
    click(&ctx, &mut view, WIDE, shut_more.center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, "Show fewer"));
    // The branch is one scroll area of the five rows' height, with its bar.
    let list_top = find(&out, "45.9.148.9:80").min.y;
    let fewer = find(&out, "Show fewer");
    assert!(
        (fewer.min.y - shut_more.min.y).abs() < 6.0,
        "{fewer:?} {shut_more:?}"
    );
    assert!(has_scroll_bar(
        &out,
        list_top,
        fewer.min.y,
        find(&out, "10.1.1.3:443").right()
    ));
    wheel(
        &ctx,
        &mut view,
        WIDE,
        egui::pos2(300.0, (list_top + fewer.min.y) / 2.0),
        -400.0,
    );
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(
        has(&out, "10.1.1.5:443"),
        "{list_top} {fewer:?} {:?}",
        texts(&out)
    );
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
            .find(|(text, _)| text.contains(" nodes. Each process"))
            .expect("the node count");
        let words: Vec<&str> = line.split_whitespace().collect();
        (words[0].parse().unwrap(), words[2].parse().unwrap())
    };
    let (shown, total) = count(&out);
    assert_eq!(total, 44, "43 processes and the injected-into pid 418");
    // The forty `ls` are one group, so the box shows few boxes.
    assert!(shown < total && shown >= 4, "{shown} of {total}");
    // The base verbs on the edges.
    assert!(has(&out, "exec") && !has(&out, "execed") && !has(&out, "forked"));
    click(&ctx, &mut view, WIDE, find(&out, "Full").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    // Full starts closed: the root and what is under it.
    assert!(count(&out).0 < 44, "{:?}", count(&out));
    click(&ctx, &mut view, WIDE, find(&out, "Expand all").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert_eq!(count(&out), (44, 44));
    // Compact and back keeps what was opened.
    click(&ctx, &mut view, WIDE, find(&out, "Compact").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    click(&ctx, &mut view, WIDE, find(&out, "Full").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert_eq!(count(&out), (44, 44));
    click(&ctx, &mut view, WIDE, find(&out, "Compact").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    assert_eq!(count(&out).0, shown);
}

#[test]
fn a_wide_level_is_laid_out_in_lanes_when_its_group_is_open() {
    let (_files, mut view) = crowded(40, 0);
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    // Shut, the forty are one box.
    assert!(
        texts(&out).iter().any(|(t, _)| t.ends_with("ls \u{d7}40")),
        "{:?}",
        texts(&out)
    );
    click(&ctx, &mut view, WIDE, find(&out, "Full").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    click(&ctx, &mut view, WIDE, find(&out, "Expand all").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    // The view was fitted to the closed graph: fit it to the open one.
    click(&ctx, &mut view, WIDE, find(&out, "Fit").center());
    let out = settle(&ctx, &mut view, WIDE, None);
    let ls: Vec<egui::Rect> = texts(&out)
        .into_iter()
        .filter(|(text, _)| text.contains(" ls ("))
        .map(|(_, rect)| rect)
        .collect();
    assert!(ls.len() >= 6, "{} visible", ls.len());
    let mut columns: Vec<i32> = ls.iter().map(|r| r.min.x as i32).collect();
    columns.sort_unstable();
    columns.dedup();
    assert!(columns.len() > 1, "more than one lane: {ls:?}");
}

/// The clip rectangle and the place of the text `wanted`, as the page drew it.
fn shape_of(out: &egui::FullOutput, wanted: &str) -> (egui::Rect, egui::Rect) {
    try_shape(out, wanted).unwrap_or_else(|| panic!("{wanted:?} not drawn"))
}

fn try_shape(out: &egui::FullOutput, wanted: &str) -> Option<(egui::Rect, egui::Rect)> {
    fn walk(shape: &egui::Shape, wanted: &str) -> Option<egui::Rect> {
        match shape {
            egui::Shape::Text(text) if text.galley.text().trim() == wanted => {
                Some(text.visual_bounding_rect())
            }
            egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| walk(shape, wanted)),
            _ => None,
        }
    }
    out.shapes
        .iter()
        .filter_map(|clipped| walk(&clipped.shape, wanted).map(|rect| (clipped.clip_rect, rect)))
        .next_back()
}

#[test]
fn the_zoom_controls_are_clipped_with_the_box_when_the_page_scrolls() {
    let (_files, mut view) = fixture();
    let ctx = context(16.0);
    let size = egui::vec2(1280.0, 700.0);
    let mut out = settle(&ctx, &mut view, size, None);
    let (page, _) = shape_of(&out, "Key findings");
    // Scroll the page past the box a little at a time; in every frame the
    // controls that are drawn are clipped to the page.
    let (mut seen, mut crossed) = (false, false);
    for _ in 0..200 {
        for control in ["Fit", "+", "\u{2212}", "100%"] {
            if let Some((clip, rect)) = try_shape(&out, control) {
                seen = true;
                crossed |= rect.top() < page.top();
                assert!(
                    clip.top() >= page.top() - 0.5 && clip.bottom() <= page.bottom() + 0.5,
                    "{control} at {rect:?} is clipped to {clip:?}, the page to {page:?}"
                );
            }
        }
        wheel(&ctx, &mut view, size, egui::pos2(300.0, 200.0), -15.0);
        out = settle(&ctx, &mut view, size, None);
    }
    assert!(seen, "the controls were drawn at some point");
    assert!(crossed, "the page scrolled past the top of the box");
}

#[test]
fn the_open_in_window_button_opens_the_relationships_in_a_window() {
    let (_files, mut view) = fixture();
    view.scan_request.identity = Some(("vm".into(), "boot".into(), "run-a".into()));
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let title = find(&out, "Relationships");
    let button = texts(&out)
        .into_iter()
        .find(|(text, rect)| {
            text == egui_phosphor::regular::ARROW_SQUARE_OUT
                && (rect.center().y - title.center().y).abs() < 14.0
        })
        .map(|(_, rect)| rect)
        .expect("the button in the box header");
    let before = texts(&out).iter().filter(|(t, _)| t == "Compact").count();
    assert!(!view.summary_state.window_open);
    click(&ctx, &mut view, WIDE, button.center());
    assert!(view.summary_state.window_open);
    // A window animates in: time runs on.
    let mut out = draw_at(&ctx, &mut view, WIDE, vec![], 3.0, None);
    for n in 1..4 {
        out = draw_at(
            &ctx,
            &mut view,
            WIDE,
            vec![],
            3.0 + f64::from(n) * 0.05,
            None,
        );
    }
    let after = texts(&out).iter().filter(|(t, _)| t == "Compact").count();
    assert_eq!(after, before + 1, "the window has the same controls");
}

/// The fixture with `count` more processes of different names below the root.
fn sprawl(count: u32) -> (PacketSpool, TriageView) {
    let (files, mut view) = fixture();
    let scan = view.scan.as_mut().unwrap();
    for n in 0..count {
        let parent = if n < 30 { 1 } else { 1000 + (n - 30) / 4 };
        let cookie = if n < 30 {
            1
        } else {
            100 + u64::from((n - 30) / 4)
        };
        scan.process.push(node(
            1000 + n,
            100 + u64::from(n),
            Some((if n < 30 { 401 } else { parent }, cookie)),
            &format!("tool{n}"),
            &["x"],
            5_000_000 + u64::from(n),
        ));
    }
    (files, view)
}

#[test]
fn full_draws_a_big_run_instead_of_nothing() {
    let (_files, mut view) = sprawl(2500);
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    click(&ctx, &mut view, WIDE, find(&out, "Full").center());
    let mut out = settle(&ctx, &mut view, WIDE, None);
    // A big graph is laid out on a thread: wait for it.
    for _ in 0..250 {
        if !has(&out, "Laying out\u{2026}") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        out = settle(&ctx, &mut view, WIDE, None);
    }
    assert!(!has(&out, "Laying out\u{2026}"), "never finished");
    // Opened, a big run still draws about 800 nodes, and says so.
    click(&ctx, &mut view, WIDE, find(&out, "Expand all").center());
    let mut out = settle(&ctx, &mut view, WIDE, None);
    for _ in 0..250 {
        if starting(&out, "8").is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        out = settle(&ctx, &mut view, WIDE, None);
    }
    let (note, _) = starting(&out, "8").expect("the count line");
    assert!(
        note.contains(" of 2,5") && note.contains(" nodes.") && note.contains("About 800"),
        "{note}"
    );
    let names = texts(&out)
        .into_iter()
        .filter(|(text, _)| text.contains(" tool"))
        .count();
    assert!(names >= 8, "{names} nodes drawn");
}

#[test]
fn a_process_with_no_recorded_name_is_named_by_its_image() {
    let (_files, mut view) = fixture();
    let scan = view.scan.as_mut().unwrap();
    for n in 0..30u32 {
        let mut task = node(
            1000 + n,
            100 + u64::from(n),
            Some((401, 1)),
            "?",
            &["ps", "aux"],
            5_000_000,
        );
        task.comm = "?".into();
        scan.process.push(task);
    }
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(
        texts(&out).iter().any(|(t, _)| t.ends_with("ps \u{d7}30")),
        "{:?}",
        texts(&out)
    );
    assert!(!texts(&out).iter().any(|(t, _)| t.contains("? (")));
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

/// The Summary with crowded Key findings and Indicators, for screenshots
/// under Xvfb. `ANTINOMIE_QA_OPEN=1` opens every "Show more" box.
#[test]
#[ignore = "requires owned isolated X11; Summary screenshot fixture"]
fn native_summary_boxes_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        view: TriageView,
        deadline: std::time::Instant,
        frames: u32,
        _files: PacketSpool,
    }
    impl eframe::App for Fixture {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = root.ctx().clone();
            // Open the boxes after a few shut frames, as a click would.
            self.frames += 1;
            if self.frames == 5 && std::env::var_os("ANTINOMIE_QA_OPEN").is_some() {
                self.view.summary_state.keys_open = true;
                self.view.summary_state.more = [true; 4];
            }
            egui::CentralPanel::default().show(root, |ui| {
                let input = TriageInput::empty();
                show(&mut self.view, ui, &input);
            });
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    let (files, mut view) = crowded(0, 12);
    with_indicators(&mut view);
    view.section = Section::Summary;
    eframe::run_native(
        "Antinomie summary QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1000.0, 2500.0])
                .with_position([16.0, 16.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::text_size(&cc.egui_ctx, theme::qa_text_size(15.0));
            Ok(Box::new(Fixture {
                view,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(8),
                frames: 0,
                _files: files,
            }))
        }),
    )
    .unwrap();
}

#[test]
fn indicator_parts_have_their_own_colours_and_a_hover_shows_they_click() {
    let (_files, mut view) = fixture();
    with_indicators(&mut view);
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    let link = ctx.global_style().visuals.hyperlink_color;
    let accent = theme::palette().accent;
    for value in [
        "45.9.148.9:80",
        "pool.minexmr.com",
        "http://45.9.148.9/hook.so",
        "/tmp/.x/kdevtmpfsi",
    ] {
        let format = format_of(&out, value);
        assert_eq!(format.color, theme::text(), "{value}");
        assert!(![link, accent].contains(&format.color), "{value}");
        assert_eq!(
            format.font_id.family,
            egui::FontFamily::Monospace,
            "{value}"
        );
        assert_eq!(format.underline, egui::Stroke::NONE, "{value} at rest");
    }
    // The place, the type and the hash are secondary: muted.
    for note in ["NL \u{b7} AS49870 Alsycon", "executable"] {
        if has(&out, note) {
            assert_eq!(colour(&out, note), theme::muted(), "{note}");
        }
    }
    assert_eq!(colour(&out, "executable"), theme::muted());
    // The branch titles have a colour of their own: not the text colour, not
    // the link or heading blue, and a different one for each category.
    let mut seen = Vec::new();
    for (at, title) in ["Endpoints (7)", "DNS names (1)", "URLs (2)", "Files (1)"]
        .into_iter()
        .enumerate()
    {
        let c = colour(&out, title);
        assert_eq!(c, theme::category(at), "{title}");
        assert!(
            ![link, accent, theme::heading(), theme::text()].contains(&c),
            "{title}"
        );
        assert!(!seen.contains(&c), "{title}");
        seen.push(c);
    }
    // Hover: underline and the pointing hand.
    let at = find(&out, "pool.minexmr.com").center();
    let mut out = settle(&ctx, &mut view, WIDE, None);
    for n in 0..3 {
        out = draw_at(
            &ctx,
            &mut view,
            WIDE,
            vec![egui::Event::PointerMoved(at)],
            2.0 + f64::from(n) * 0.02,
            None,
        );
    }
    assert_ne!(
        format_of(&out, "pool.minexmr.com").underline,
        egui::Stroke::NONE
    );
    assert_eq!(
        out.platform_output.cursor_icon,
        egui::CursorIcon::PointingHand
    );
}

/// The coloured sections of the first drawn text that contains `needle`:
/// each piece of text with its colour.
fn sections_of(out: &egui::FullOutput, needle: &str) -> Vec<(String, egui::Color32)> {
    fn walk(shape: &egui::Shape, needle: &str, found: &mut Vec<(String, egui::Color32)>) {
        match shape {
            egui::Shape::Text(text) if found.is_empty() && text.galley.text().contains(needle) => {
                let all = text.galley.text();
                for section in &text.galley.job.sections {
                    found.push((
                        all[section.byte_range.start.0..section.byte_range.end.0].to_owned(),
                        section.format.color,
                    ));
                }
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, needle, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    for shape in &out.shapes {
        walk(&shape.shape, needle, &mut found);
    }
    assert!(
        !found.is_empty(),
        "{needle:?} not drawn in {:?}",
        texts(out)
    );
    found
}

/// Numbers are in the text colour, every other word muted, and there are
/// at least `numbers` of them.
fn numbers_strong_words_muted(out: &egui::FullOutput, needle: &str, numbers: usize) {
    let mut seen = 0;
    for (text, color) in sections_of(out, needle) {
        let word = text.trim().trim_matches('\u{b7}').trim();
        if word.is_empty() {
            continue;
        }
        if word.parse::<u64>().is_ok() {
            assert_eq!(color, theme::text(), "{word} in {needle}");
            seen += 1;
        } else {
            assert_eq!(color, theme::muted(), "{word} in {needle}");
        }
    }
    assert!(seen >= numbers, "{needle}: {seen} numbers");
}

#[test]
fn the_one_line_rows_have_strong_numbers_and_muted_words() {
    let (_files, mut view) = fixture();
    view.scan.as_mut().unwrap().counts.http = 4;
    view.scan.as_mut().unwrap().network_counts = Some((641, 2, 3));
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    numbers_strong_words_muted(&out, "created", 4);
    numbers_strong_words_muted(&out, "HTTP", 3);
    numbers_strong_words_muted(&out, "syscalls", 2);
    let tactic = Tactic::ALL
        .into_iter()
        .map(|tactic| tactic.name())
        .find(|name| texts(&out).iter().any(|(t, _)| t.starts_with(name)))
        .expect("a tactic row");
    numbers_strong_words_muted(&out, tactic, 1);
    // The three rows read the same: number (text colour) against word (muted).
    assert_ne!(theme::text(), theme::muted());
}

mod fold;
mod scroll;

/// A view of a Merlin-like run: one Elastic family rule among twelve weak
/// community and wrong-platform matches (the detections of the evaluation's
/// Merlin run), and base image traffic beside a stand-in address.
fn merlin_view() -> (PacketSpool, TriageView) {
    use antinomie_monitor_core::analysis::detection::{
        Engine, Finding as Match, Identity, Report, Source, State,
    };
    use antinomie_monitor_core::ioc::indicator::Type;
    #[derive(serde::Deserialize)]
    struct Run {
        run: String,
        hits: Vec<antinomie_monitor_core::run_digest::DetectionHit>,
    }
    let runs: Vec<Run> =
        serde_json::from_str(include_str!("../family_fixtures/runs.json")).unwrap();
    let hits = runs.into_iter().find(|r| r.run == "6d58d777").unwrap().hits;
    let (files, mut view) = fixture();
    let mut report = Report::empty(
        Engine::Yara,
        Identity {
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            run_id: "run".into(),
            root_cookie: 1,
        },
    );
    report.state = State::Complete;
    for hit in hits.iter().filter(|hit| hit.engine == "YARA") {
        let at = match report.sources.iter().position(|s| s.name == hit.source) {
            Some(at) => at,
            None => {
                report.sources.push(Source {
                    name: hit.source.clone(),
                    version: String::new(),
                    license: String::new(),
                    sha256: String::new(),
                    data: String::new(),
                });
                report.sources.len() - 1
            }
        };
        report.findings.push(
            serde_json::from_value::<Match>(serde_json::json!({
                "rule_id": hit.rule_id,
                "title": hit.title,
                "severity": hit.severity,
                "source": format!("s{at}"),
                "license": hit.license,
                "author": hit.author,
                "mitre": [],
                "count": 1,
                "evidence": [],
                "details": "Matched the specimen's bytes.",
            }))
            .unwrap(),
        );
    }
    view.detection.results[0] = Some(Ok(report));
    view.detection.rows(0);
    let mut all = indicators::tests::sample();
    let mut ntp = indicators::tests::indicator(Type::Endpoint, "198.18.0.2:123");
    ntp.noise = Some("NTP, the base image's clock sync".into());
    let mut pool = indicators::tests::indicator(Type::Domain, "1.debian.pool.ntp.org");
    pool.noise = Some("1.debian.pool.ntp.org is looked up by the base image".into());
    let mut apt = indicators::tests::indicator(Type::Endpoint, "198.18.0.7:443");
    apt.noise = Some(
        "198.18.0.7 is the address the base image's lookup of metadata.ftp-master.debian.org got"
            .into(),
    );
    let mut name = indicators::tests::indicator(Type::Domain, "metadata.ftp-master.debian.org");
    name.noise = Some("metadata.ftp-master.debian.org is looked up by the base image".into());
    let mut c2 = indicators::tests::indicator(Type::Endpoint, "198.18.0.1:8443");
    c2.stand_in = Some("apache-update.ddns.net".into());
    all.extend([ntp, pool, apt, name, c2]);
    view.scan.as_mut().unwrap().ioc = Some(std::sync::Arc::new(
        crate::triage::ioc_scan::IocScan::for_tests(all),
    ));
    (files, view)
}

#[test]
fn a_merlin_run_names_merlin_folds_the_weak_matches_and_the_background() {
    let (_files, mut view) = merlin_view();
    let ctx = context(16.0);
    let out = settle(&ctx, &mut view, WIDE, None);
    assert!(has(&out, "Merlin"), "{:?}", texts(&out));
    for fragment in ["MassHunt", "Unique", "IoT", "Stackstrings", "Remcos"] {
        assert!(
            !texts(&out)
                .iter()
                .any(|(t, _)| t.contains(fragment) && t.len() < 30),
            "{fragment}"
        );
    }
    assert!(
        has(&out, "1 strong \u{b7} 12 weak or generic"),
        "{:?}",
        texts(&out)
    );
    assert!(has(&out, "Base image background: NTP, apt (2)"));
    assert!(has(&out, "Base image background: NTP, apt (2)"));
    assert!(has(&out, "198.18.0.1:8443"));
    assert!(has(&out, "\u{2192} apache-update.ddns.net"));
    // The totals stay: the card counts every rule.
    assert!(has(&out, "13"), "{:?}", texts(&out));
}

/// The Merlin-like Summary (`ANTINOMIE_TRIAGE_QA_SCENE=summary`, default) or
/// its Detection > YARA page (`detection`), for screenshots under Xvfb;
/// `ANTINOMIE_QA_OPEN=1` opens the folded groups.
#[test]
#[ignore = "requires owned isolated X11; family candidates / background / weak matches fixture"]
fn native_family_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        view: TriageView,
        detection: bool,
        deadline: std::time::Instant,
        frames: u32,
        _files: PacketSpool,
    }
    impl eframe::App for Fixture {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = root.ctx().clone();
            self.frames += 1;
            egui::CentralPanel::default().show(root, |ui| {
                let input = TriageInput::empty();
                if self.detection {
                    self.view.detection.show(ui, self.view.scan.as_ref());
                } else {
                    show(&mut self.view, ui, &input);
                }
            });
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    let (files, mut view) = merlin_view();
    view.section = Section::Summary;
    let detection = std::env::var("ANTINOMIE_TRIAGE_QA_SCENE").as_deref() == Ok("detection");
    eframe::run_native(
        "Antinomie family QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1000.0, if detection { 900.0 } else { 1500.0 }])
                .with_position([16.0, 16.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::text_size(&cc.egui_ctx, theme::qa_text_size(15.0));
            Ok(Box::new(Fixture {
                view,
                detection,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(40),
                frames: 0,
                _files: files,
            }))
        }),
    )
    .unwrap();
}

/// The user's run 4ccf6396: six processes of interest, the first with a name
/// of about 70 characters, left a wide gap under the row.
fn long_interest() -> Vec<relations::model::Interest> {
    use crate::triage::rules::Tier;
    let item = |pid: u32, label: &str, tier: Tier, findings: u32| relations::model::Interest {
        key: (pid, u64::from(pid)),
        label: label.into(),
        tier: Some(tier),
        findings,
        warn: false,
    };
    vec![
        item(
            1351,
            "d1cdeea8-d1cdeea8a081397632c0522476da2122f93c71cb14a36ad4 (1351)",
            Tier::High,
            3,
        ),
        item(1355, "systemctl (1355)", Tier::High, 1),
        item(1352, "sh (1352)", Tier::Low, 1),
        item(1353, "which (1353)", Tier::Low, 1),
        item(1354, "sh (1354)", Tier::Low, 1),
        item(1379, "sh (1379)", Tier::Low, 1),
    ]
}

#[test]
fn many_long_processes_of_interest_stay_a_compact_row() {
    let (_files, view) = fixture();
    let scan = view.scan.as_ref().unwrap();
    for width in [1920.0_f32, 1280.0, 760.0] {
        let ctx = context(16.0);
        let mut height = 0.0;
        let mut out = None;
        for _ in 0..4 {
            out = Some(ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 600.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        let mut acts = Vec::new();
                        height = ui
                            .scope(|ui| panels::interest_row(ui, &long_interest(), scan, &mut acts))
                            .response
                            .rect
                            .height();
                    });
                },
            ));
        }
        let line = ctx.global_style().spacing.interact_size.y;
        // Six items and the count fit in two lines on a wide row and wrap to
        // four in a narrow one (760); an item with a line of its own would
        // take seven or more.
        let lines = if width > 1000.0 { 3.4 } else { 5.8 };
        assert!(
            height <= line * lines,
            "{height} tall at {width}: a gap under the row"
        );
        for (text, rect) in texts(&out.unwrap()) {
            assert!(rect.right() <= width, "{text:?} past the window");
        }
    }
}

/// The Summary's one-line rows with the long process list of run 4ccf6396,
/// for screenshots under Xvfb. `ANTINOMIE_QA_LEGACY=1` draws the processes
/// the way they were drawn before 0.8.3 (each in a nested row of its own).
#[test]
#[ignore = "requires owned isolated X11; Summary rows screenshot fixture"]
fn native_interest_row_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        view: TriageView,
        deadline: std::time::Instant,
        legacy: bool,
        _files: PacketSpool,
    }
    impl eframe::App for Fixture {
        fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
            let ctx = root.ctx().clone();
            egui::CentralPanel::default().show(root, |ui| {
                let mut acts = Vec::new();
                presentation::frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    panels::attack_row(ui, 0, &[]);
                    if self.legacy {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            ui.label(
                                egui::RichText::new("Processes of interest")
                                    .strong()
                                    .color(theme::heading()),
                            );
                            for item in long_interest() {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 10.0;
                                    let color = item.tier.map_or(theme::muted(), |t| t.color());
                                    ui.add(
                                        crate::widgets::dot::DotLabel::new(
                                            color,
                                            format!("\u{d7}{}", item.findings),
                                        )
                                        .text_color(color),
                                    );
                                    rows::item(ui, &[rows::Part::Value(&item.label)], "Open");
                                });
                            }
                            rows::counted_item(
                                ui,
                                &[("of 8 processes".to_owned(), false)],
                                "Open the Process tree",
                            );
                        });
                    } else {
                        panels::interest_row(
                            ui,
                            &long_interest(),
                            self.view.scan.as_ref().unwrap(),
                            &mut acts,
                        );
                    }
                    panels::files_row(ui, self.view.scan.as_ref().unwrap(), &mut acts);
                    panels::network_row(ui, self.view.scan.as_ref().unwrap(), &mut acts);
                });
            });
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    let (files, view) = fixture();
    let width = std::env::var("ANTINOMIE_QA_WIDTH")
        .ok()
        .and_then(|value| value.parse::<f32>().ok())
        .unwrap_or(1280.0);
    let legacy = std::env::var("ANTINOMIE_QA_LEGACY").is_ok_and(|value| value == "1");
    eframe::run_native(
        "Antinomie summary rows QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([width, 220.0])
                .with_position([16.0, 16.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::text_size(&cc.egui_ctx, 16.0);
            Ok(Box::new(Fixture {
                view,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
                legacy,
                _files: files,
            }))
        }),
    )
    .unwrap();
}
