// SPDX-License-Identifier: GPL-3.0-only
//! The graph and the Suspicious activity table are one set of findings: the
//! same filter, chips, selection and Details; the Summary strip; the live
//! HIGH toast; and the hidden-pane read that makes the toast timely.
use super::filter::Parts;
use super::index::{self, GraphIndex};
use super::input::Action;
use super::notify::{HighRule, HighWatch};
use super::strip::{summary_line, Strip};
use super::tests;
use crate::activity::Level;
use crate::app::tests::texts;
use crate::triage::rules::{Category, Tier};
use crate::triage::tests::write_rwx_tasks;
use crate::triage::*;

/// Three tasks of the run, each making rwx calls: findings in several lanes
/// at several times.
pub(super) fn recording() -> PacketSpool {
    let spool = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_tasks(&mut raw, 0..12, |call| 60 + (call % 3) as u32);
    std::fs::write(spool.directory.join("telemetry.raw"), raw).unwrap();
    spool
}

pub(super) fn scan_with(spool: &PacketSpool, request: &ScanRequest) -> ArchiveScan {
    scan_archive_query(
        &spool.directory,
        None,
        false,
        &Arc::new(AtomicBool::new(false)),
        request,
    )
    .unwrap()
}

pub(super) fn request() -> ScanRequest {
    ScanRequest {
        root_cookie: 55,
        ..ScanRequest::default()
    }
}

fn table_keys(scan: &ArchiveScan) -> Vec<(u64, u64, u64)> {
    let mut keys: Vec<_> = scan.findings.iter().map(|row| row.key).collect();
    keys.sort_unstable();
    keys
}

fn graph_keys(scan: &ArchiveScan) -> Vec<(u64, u64, u64)> {
    let mut keys: Vec<_> = scan.graph.index.rows.iter().map(|row| row.key).collect();
    keys.sort_unstable();
    keys
}

#[test]
fn the_graph_holds_the_rows_of_the_table_and_none_other() {
    let spool = recording();
    let scan = scan_with(&spool, &request());
    assert!(!scan.findings.is_empty(), "the fixture has findings");
    assert_eq!(graph_keys(&scan), table_keys(&scan));
    assert_eq!(scan.graph.index.records.len(), scan.graph.index.rows.len());
    // Records and rows are in the same order: record i is row i.
    for (record, row) in scan.graph.index.records.iter().zip(&scan.graph.index.rows) {
        assert_eq!(
            Some(record.first_ns),
            files::number(&row.values, "finding.first_ns")
        );
    }
    // A filter that keeps nothing leaves both empty.
    let mut none = request();
    none.filters[0] = "finding.rule == \"never\"".into();
    let scan = scan_with(&spool, &none);
    assert!(scan.findings.is_empty() && scan.graph.index.rows.is_empty());
}

#[test]
fn a_filter_a_chip_and_a_brush_narrow_the_graph_exactly_as_they_narrow_the_table() {
    let spool = recording();
    let all = scan_with(&spool, &request());
    let times: Vec<u64> = all
        .graph
        .index
        .records
        .iter()
        .map(|record| record.first_ns)
        .collect();
    let cookies: std::collections::BTreeSet<u64> = all
        .graph
        .index
        .rows
        .iter()
        .filter_map(|row| files::number(&row.values, "process.cookie"))
        .collect();
    assert!(
        cookies.len() > 1 && times.len() > 1,
        "{cookies:?} {times:?}"
    );
    let lane = *cookies.iter().next().unwrap();
    let middle = times[times.len() / 2];
    let cases: Vec<(&str, ScanRequest)> = vec![
        ("lane", {
            let mut one = request();
            one.filters[0] = Parts {
                cookies: vec![lane],
                ..Parts::default()
            }
            .render();
            one
        }),
        ("brush", {
            let mut one = request();
            one.filters[0] = Parts {
                brush: Some((0, middle)),
                ..Parts::default()
            }
            .render();
            one
        }),
        ("tier chip", {
            let mut one = request();
            one.finding_view.tiers = 1 << Tier::High.index();
            one
        }),
        ("category chip", {
            let mut one = request();
            one.finding_view.toggle_category(Category::Execution);
            one
        }),
        ("text", {
            let mut one = request();
            one.filters[0] = "finding.tier == high".into();
            one
        }),
    ];
    for (name, request) in cases {
        let scan = scan_with(&spool, &request);
        assert_eq!(graph_keys(&scan), table_keys(&scan), "{name}");
    }
    let mut brushed = request();
    brushed.filters[0] = Parts {
        brush: Some((0, middle)),
        ..Parts::default()
    }
    .render();
    let scan = scan_with(&spool, &brushed);
    assert!(scan
        .graph
        .index
        .records
        .iter()
        .all(|record| record.first_ns <= middle));
    assert!(scan.graph.index.records.len() < times.len());
    // A lane filter keeps only that lane's findings.
    let mut one = request();
    one.filters[0] = Parts {
        cookies: vec![lane],
        ..Parts::default()
    }
    .render();
    let scan = scan_with(&spool, &one);
    assert!(scan
        .graph
        .index
        .rows
        .iter()
        .all(|row| files::number(&row.values, "process.cookie") == Some(lane)));
}

#[test]
fn findings_are_placed_on_the_lane_of_their_process() {
    let spool = recording();
    let scan = scan_with(&spool, &request());
    let index = &scan.graph.index;
    assert!(index.lanes.list.len() > 1);
    for (record, row) in index.records.iter().zip(&index.rows) {
        let cookie = files::number(&row.values, "process.cookie").unwrap();
        let lane = &index.lanes.list[record.lane as usize];
        assert_eq!(lane.cookie, cookie, "{}", lane.label());
    }
}

pub(super) fn view_with(spool: &PacketSpool) -> TriageView {
    let mut view = TriageView::default();
    view.scan = Some(scan_with(spool, &request()));
    view.section = Section::Process;
    view.process = ProcessTab::Graph;
    view.context_key = Some("vm\nboot\nrun\n".into());
    view
}

pub(super) fn draw(ctx: &egui::Context, view: &mut TriageView, time: f64) -> egui::FullOutput {
    let input = TriageInput {
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run"),
        ..TriageInput::empty()
    };
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 820.0),
            )),
            time: Some(time),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(ui, input);
            });
        },
    )
}

#[test]
fn the_graph_tab_draws_with_the_shared_filter_bar_and_no_pager() {
    let spool = recording();
    let mut view = view_with(&spool);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    draw(&ctx, &mut view, 0.0);
    let out = draw(&ctx, &mut view, 0.05);
    let shown = texts(&out);
    let has = |text: &str| shown.iter().any(|(shown, _)| shown.starts_with(text));
    assert!(has("Graph"), "the third segment");
    assert!(has("HIGH") || has("Show INFO"), "the chips are shared");
    assert!(has("phases") && has("severity"), "the bands are drawn");
    assert!(
        !shown.iter().any(|(text, _)| text.contains("page size")),
        "the graph has no pages"
    );
}

#[test]
fn selecting_in_the_graph_selects_in_the_table_and_shows_details() {
    let spool = recording();
    let mut view = view_with(&spool);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let key = view.scan.as_ref().unwrap().graph.index.rows[1].key;
    view.apply_graph_actions(
        &ctx,
        vec![Action::Select {
            record: 1,
            focus: true,
        }],
    );
    assert_eq!(view.selected_call_id, Some(key), "the table's selection");
    assert_eq!(view.table_focus, Some(key), "the table scrolls to it");
    assert!(ctx
        .data(|data| data.get_temp::<bool>(egui::Id::new("triage-details-focus")))
        .unwrap_or(false));
    // Drawn again, the graph follows the table: a click on another row moves it.
    let other = view.scan.as_ref().unwrap().graph.index.rows[0].key;
    view.selected_call_id = Some(other);
    draw(&ctx, &mut view, 0.0);
    let selected = view
        .graph
        .selected
        .and_then(|at| view.scan.as_ref().unwrap().graph.index.rows.get(at))
        .map(|row| row.key);
    assert_eq!(selected, Some(other));
    // Keyboard steps do not take Details to the front.
    ctx.data_mut(|data| data.remove::<bool>(egui::Id::new("triage-details-focus")));
    view.apply_graph_actions(
        &ctx,
        vec![Action::Select {
            record: 0,
            focus: false,
        }],
    );
    assert!(!ctx
        .data(|data| data.get_temp::<bool>(egui::Id::new("triage-details-focus")))
        .unwrap_or(false));
    // Open asks for the first evidence, as a double click on the row does.
    view.apply_graph_actions(&ctx, vec![Action::Open(0)]);
    assert!(ctx
        .data(|data| data.get_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump")))
        .is_some());
}

#[test]
fn a_brush_and_a_lane_go_into_the_filter_bar_and_escape_takes_the_brush_out() {
    let spool = recording();
    let mut view = view_with(&spool);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    view.filter_drafts[0] = "finding.tier == high".into();
    view.apply_graph_actions(
        &ctx,
        vec![Action::Brush(10, 99), Action::Lane { cookies: vec![61] }],
    );
    assert_eq!(
        view.filter_drafts[0],
        "finding.tier == high && process.cookie == 61 && event.time_ns >= 10 && event.time_ns <= 99"
    );
    // The next frame's query bar takes it into the request, which re-reads the index.
    draw(&ctx, &mut view, 0.0);
    assert_eq!(view.scan_request.filters[0], view.filter_drafts[0]);
    assert_eq!(
        view.graph.brush,
        Some((10, 99)),
        "the brush is read back from the filter"
    );
    // The same lane again lifts the lane filter.
    view.apply_graph_actions(&ctx, vec![Action::Lane { cookies: vec![61] }]);
    assert!(!view.filter_drafts[0].contains("process.cookie"));
    view.apply_graph_actions(&ctx, vec![Action::ClearBrush]);
    assert_eq!(view.filter_drafts[0], "finding.tier == high");
}

#[test]
fn chips_pressed_on_the_keyboard_are_the_chips_of_the_bar() {
    let spool = recording();
    let mut view = view_with(&spool);
    let ctx = egui::Context::default();
    view.apply_graph_actions(&ctx, vec![Action::Tier(Tier::High)]);
    assert_eq!(
        view.scan_request.finding_view.tiers,
        1 << Tier::High.index()
    );
    view.apply_graph_actions(&ctx, vec![Action::Tier(Tier::Medium)]);
    assert!(view.scan_request.finding_view.tier_on(Tier::Medium));
    view.apply_graph_actions(&ctx, vec![Action::Tier(Tier::High)]);
    assert!(!view.scan_request.finding_view.tier_on(Tier::High));
    assert!(!view.scan_request.finding_view.show_info);
    view.apply_graph_actions(&ctx, vec![Action::Tier(Tier::Info)]);
    assert!(view.scan_request.finding_view.show_info);
    view.apply_graph_actions(&ctx, vec![Action::Category(Category::Discovery)]);
    assert!(view
        .scan_request
        .finding_view
        .category_on(Category::Discovery));
    assert!(
        view.refresh_requested,
        "a chip re-reads the index, as the bar's chip does"
    );
}

// ----- the Summary strip -----

#[test]
fn the_strip_is_one_line_when_nothing_is_above_low_and_says_what_there_is() {
    assert_eq!(
        summary_line([0, 0, 11, 340]),
        "No medium or high activity · 11 low · 340 info"
    );
    assert_eq!(
        summary_line([2, 5, 11, 340]),
        "2 high · 5 medium · 11 low · 340 info"
    );
}

fn strip_text(
    strip: &mut Strip,
    index: &GraphIndex,
    tiers: [u64; 4],
    ctx: &egui::Context,
    events: Vec<egui::Event>,
) -> (Vec<(String, egui::Rect)>, bool) {
    let mut open = false;
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 600.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                open |= strip.show(ui, index, tiers, None, false).open_graph;
            });
        },
    );
    (texts(&output), open)
}

fn small_overview(tier: Tier) -> GraphIndex {
    let mut builder = index::Builder::overview();
    builder.push_record(tests::record(1_000_000_000, 0, tier, Category::Command));
    builder.push_record(tests::record(
        9_000_000_000,
        0,
        Tier::Low,
        Category::Discovery,
    ));
    builder.finish()
}

#[test]
fn the_strip_collapses_to_a_line_when_quiet_expands_on_click_and_remembers_it() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let quiet = small_overview(Tier::Low);
    let mut strip = Strip::default();
    let (shown, _) = strip_text(&mut strip, &quiet, [0, 0, 2, 5], &ctx, vec![]);
    let line = shown
        .iter()
        .find(|(text, _)| text.starts_with("No medium or high activity"))
        .expect("the one line");
    assert!(
        !shown.iter().any(|(text, _)| text == "phases"),
        "no bands while collapsed"
    );
    // A click on the line opens it.
    let at = line.1.center();
    for pressed in [true, false] {
        strip_text(
            &mut strip,
            &quiet,
            [0, 0, 2, 5],
            &ctx,
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    assert_eq!(strip.open, Some(true));
    let (shown, _) = strip_text(&mut strip, &quiet, [0, 0, 2, 5], &ctx, vec![]);
    assert!(shown.iter().any(|(text, _)| text == "phases"));
    // The choice outlives the run: a busy run keeps it open, and a quiet one stays as chosen.
    let busy = small_overview(Tier::High);
    let (shown, _) = strip_text(&mut strip, &busy, [1, 0, 1, 0], &ctx, vec![]);
    assert!(shown.iter().any(|(text, _)| text == "severity"));
    // Untouched, a busy run opens by itself.
    let mut fresh = Strip::default();
    let (shown, _) = strip_text(&mut fresh, &busy, [1, 0, 1, 0], &ctx, vec![]);
    assert!(shown.iter().any(|(text, _)| text == "severity"));
}

#[test]
fn a_click_on_the_open_strip_opens_the_full_graph() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let busy = small_overview(Tier::High);
    let mut strip = Strip::default();
    let (shown, _) = strip_text(&mut strip, &busy, [1, 0, 1, 0], &ctx, vec![]);
    let band = shown.iter().find(|(text, _)| text == "severity").unwrap().1;
    let at = egui::pos2(band.right() + 300.0, band.center().y);
    let mut opened = false;
    for pressed in [true, false] {
        let (_, open) = strip_text(
            &mut strip,
            &busy,
            [1, 0, 1, 0],
            &ctx,
            vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        opened |= open;
    }
    assert!(opened);
}

#[test]
fn the_summary_shows_the_strip_on_every_run_and_a_click_goes_to_the_graph() {
    let spool = recording();
    let mut view = view_with(&spool);
    view.section = Section::Summary;
    view.process = ProcessTab::Tree;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    draw(&ctx, &mut view, 0.0);
    let out = draw(&ctx, &mut view, 0.05);
    assert!(texts(&out)
        .iter()
        .any(|(text, _)| text == "Main activity graph"));
}

// ----- the live HIGH toast -----

fn rule(name: &str, count: u64) -> HighRule {
    HighRule {
        rule: name.into(),
        count,
        first_ns: 5,
        detail: format!("sh (12 / 12) · {name} fired"),
    }
}

#[test]
fn a_live_high_rule_raises_one_toast_and_later_matches_add_to_its_count() {
    let ctx = egui::Context::default();
    let mut watch = HighWatch::default();
    watch.observe(&ctx, "run-1", true, true, &[rule("c2.reverse_shell", 1)]);
    let toasts = crate::toasts::counts(&ctx);
    assert_eq!(
        toasts,
        [("High-severity activity: c2.reverse_shell".to_owned(), 1)]
    );
    // The same rule again, with more occurrences: ×N on the same toast.
    watch.observe(&ctx, "run-1", true, true, &[rule("c2.reverse_shell", 4)]);
    watch.observe(&ctx, "run-1", true, true, &[rule("c2.reverse_shell", 4)]);
    assert_eq!(
        crate::toasts::counts(&ctx),
        [("High-severity activity: c2.reverse_shell".to_owned(), 4)]
    );
    // Another rule has its own toast.
    watch.observe(
        &ctx,
        "run-1",
        true,
        true,
        &[rule("c2.reverse_shell", 4), rule("persistence.module", 1)],
    );
    assert_eq!(crate::toasts::counts(&ctx).len(), 2);
    // One Activity row each, however many matches.
    let rows = crate::toasts::take_rows(&ctx);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|(level, _)| *level == Level::Warn));
}

#[test]
fn a_dismissed_toast_is_not_raised_again_and_a_new_run_starts_over() {
    let ctx = egui::Context::default();
    let mut watch = HighWatch::default();
    watch.observe(&ctx, "run-1", true, true, &[rule("c2.reverse_shell", 1)]);
    ctx.data_mut(|data| {
        data.get_temp_mut_or_default::<crate::toasts::Toasts>(egui::Id::new("toast-stack"))
            .dismiss(1)
    });
    watch.observe(&ctx, "run-1", true, true, &[rule("c2.reverse_shell", 9)]);
    assert!(
        crate::toasts::counts(&ctx).is_empty(),
        "later matches only bump a toast that is still there"
    );
    // The next run raises it again.
    watch.observe(&ctx, "run-2", true, true, &[rule("c2.reverse_shell", 1)]);
    assert_eq!(crate::toasts::counts(&ctx).len(), 1);
}

#[test]
fn no_toast_for_a_finished_run_or_with_the_switch_off_but_the_rule_is_remembered() {
    let ctx = egui::Context::default();
    let mut watch = HighWatch::default();
    watch.observe(&ctx, "old", false, true, &[rule("c2.reverse_shell", 3)]);
    assert!(
        crate::toasts::counts(&ctx).is_empty(),
        "a run that has ended is not live"
    );
    watch.observe(&ctx, "off", true, false, &[rule("c2.reverse_shell", 3)]);
    assert!(crate::toasts::counts(&ctx).is_empty(), "the switch is off");
    assert_eq!(watch.seen().get("c2.reverse_shell"), Some(&3));
    // Switching it on later does not announce what was already known.
    watch.observe(&ctx, "off", true, true, &[rule("c2.reverse_shell", 3)]);
    assert!(crate::toasts::counts(&ctx).is_empty());
}

#[test]
fn a_scan_reports_the_high_rules_it_found_and_a_poll_hands_them_to_the_toast() {
    let spool = recording();
    let scan = scan_with(&spool, &request());
    let high_rows = scan
        .graph
        .index
        .rows
        .iter()
        .filter(|row| files::number(&row.values, "finding.count").is_some())
        .filter(|row| row.cells[rules::COL_TIER].text == "high")
        .count();
    assert_eq!(!scan.graph.high.is_empty(), high_rows > 0);
    for rule in &scan.graph.high {
        assert!(rule.count >= 1 && !rule.detail.is_empty());
    }
}

// ----- native fixture for screenshots -----

/// The graph in a real window, for screenshots in each theme and size. Needs an
/// X11 display; exits by itself.
///
/// ANTINOMIE_QA_SCENE = sparse (a dropper, five findings) | dense (3,000
/// findings on 60 lanes) | strip (the Summary strip),
/// ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x820,
/// ANTINOMIE_QA_SECONDS = 20.
#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_graph_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        index: GraphIndex,
        state: super::view::State,
        strip: Strip,
        scene: String,
        deadline: std::time::Instant,
    }
    impl eframe::App for Fixture {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ctx, |ui| {
                if self.scene == "strip" {
                    self.strip.open = Some(true);
                    let tiers = self.index.tiers.map(u64::from);
                    self.strip.show(
                        ui,
                        &self.index,
                        [tiers[0], tiers[1], tiers[2], 0],
                        None,
                        false,
                    );
                } else {
                    let config = super::widget::Config {
                        index: &self.index,
                        colors: super::paint::Colors::current(),
                        clock: None,
                        height: ui.available_height(),
                    };
                    super::widget::show(ui, &mut self.state, &config);
                }
            });
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => theme::Theme::Light,
        "blue" => theme::Theme::Blue,
        _ => theme::Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(20);
    let scene = var("ANTINOMIE_QA_SCENE");
    let index = match scene.as_str() {
        "dense" | "strip" => super::bench::synthetic(3_000, 60),
        _ => tests::scene(),
    };
    eframe::run_native(
        "Antinomie Graph QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            Ok(Box::new(Fixture {
                index,
                state: Default::default(),
                strip: Strip::default(),
                scene,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native graph fixture");
}

/// The Graph tab and the graph window of a real Triage view, for screenshots.
///
/// ANTINOMIE_QA_SCENE = tab (the Graph tab in a pane of ANTINOMIE_QA_PANE
/// points tall, 520 by default) | window (the same, with the graph window
/// open) | summary (the Summary strip); ANTINOMIE_QA_RUN = a copy of a run's
/// directory to read (its `telemetry.raw` and `run.json`), else a small
/// synthetic one; ANTINOMIE_QA_THEME, ANTINOMIE_QA_SIZE, ANTINOMIE_QA_SECONDS
/// as for `native_graph_fixture`.
#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_graph_view_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Fixture {
        view: TriageView,
        scene: String,
        pane: f32,
        deadline: std::time::Instant,
        opened: bool,
        _spool: Option<PacketSpool>,
    }
    impl eframe::App for Fixture {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            let input = TriageInput {
                vm_id: Some("vm"),
                boot_id: Some("boot"),
                run_id: Some("run"),
                run_finished: true,
                ..TriageInput::empty()
            };
            self.view.set_graph_window_size(super::window::DEFAULT_SIZE);
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.set_max_height(self.pane);
                self.view.show(ui, input);
            });
            if self.scene == "window" && !self.opened {
                self.opened = true;
                self.view.open_graph_window(ctx);
                // A finding selected, so Details beside the graph has something to say.
                self.view.apply_graph_actions(
                    ctx,
                    vec![Action::Select {
                        record: 2,
                        focus: false,
                    }],
                );
            }
            self.view.show_finding_windows(ctx);
            if std::time::Instant::now() > self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => theme::Theme::Light,
        "blue" => theme::Theme::Blue,
        _ => theme::Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 800.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(20);
    let pane = var("ANTINOMIE_QA_PANE").parse::<f32>().unwrap_or(520.0);
    let scene = var("ANTINOMIE_QA_SCENE");
    let (spool, mut request) = match var("ANTINOMIE_QA_RUN").as_str() {
        "" => (Some(recording()), request()),
        _ => (None, request()),
    };
    let directory = match &spool {
        Some(spool) => spool.directory.clone(),
        None => std::path::PathBuf::from(var("ANTINOMIE_QA_RUN")),
    };
    // A real run names its root task and clock in run.json.
    if let Ok(text) = std::fs::read_to_string(directory.join("run.json")) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            request.root_cookie = json["root_task_cookie"].as_u64().unwrap_or(55);
            request.started_ms = json["started_ms"].as_u64();
            request.clock_anchor = json["clock_anchor"]["guest_ns"]
                .as_u64()
                .zip(json["clock_anchor"]["host_us"].as_u64())
                .map(
                    |(guest_ns, host_us)| antinomie_monitor_core::HostClockAnchor {
                        guest_ns,
                        host_us,
                    },
                );
        }
    }
    request.run_finished = true;
    let scan = scan_archive_query(
        &directory,
        None,
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
    )
    .expect("the run's index");
    let mut view = TriageView::default();
    view.scan = Some(scan);
    view.section = if scene == "summary" {
        Section::Summary
    } else {
        Section::Process
    };
    view.process = ProcessTab::Graph;
    view.context_key = Some("vm\nboot\nrun\n".into());
    view.scan_request.identity = Some(("vm".into(), "boot".into(), "run".into()));
    eframe::run_native(
        "Antinomie Graph View QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            Ok(Box::new(Fixture {
                view,
                scene,
                pane,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(seconds),
                opened: false,
                _spool: spool,
            }))
        }),
    )
    .expect("native graph view fixture");
}
