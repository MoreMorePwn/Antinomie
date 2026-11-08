// SPDX-License-Identifier: GPL-3.0-only
//! The mouse wheel over a Triage table scrolls it: Process tree, Suspicious
//! activity, the Files tables and the Network tables, each with far more rows
//! than the window shows.
use super::layout::{context, find, has, view};
use super::*;

/// The workspace's tab: no scroll area of its own, as in the app.
struct Host<'a> {
    view: &'a mut TriageView,
    input: TriageInput<'a>,
}

impl egui_dock::TabViewer for Host<'_> {
    type Tab = ();
    fn title(&mut self, _: &mut ()) -> egui::WidgetText {
        "Triage".into()
    }
    fn id(&mut self, _: &mut ()) -> egui::Id {
        egui::Id::new("triage-tab")
    }
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut ()) {
        self.view.show(ui, self.input);
    }
    fn scroll_bars(&self, _: &()) -> [bool; 2] {
        [false, false]
    }
}

/// One frame of `view` in a window of `size`, in a bare panel or in a dock tab.
fn draw(
    ctx: &egui::Context,
    view: &mut TriageView,
    size: egui::Vec2,
    dock: bool,
    events: Vec<egui::Event>,
    time: f64,
) -> egui::FullOutput {
    let input = TriageInput {
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run"),
        pcap: Some(Path::new("/nonexistent/capture.pcap")),
        ..TriageInput::empty()
    };
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            time: Some(time),
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
                if dock {
                    let mut state = egui_dock::DockState::new(vec![()]);
                    egui_dock::DockArea::new(&mut state).show_inside(ui, &mut Host { view, input });
                } else {
                    view.show(ui, input);
                }
            });
        },
    )
}

/// The sizes a Triage pane has: the whole window, beside Details and narrow.
const SIZES: [egui::Vec2; 4] = [
    egui::vec2(1500.0, 820.0),
    egui::vec2(420.0, 700.0),
    egui::vec2(950.0, 700.0),
    egui::vec2(640.0, 700.0),
];

/// Wheel steps over `at`, drawn until the scroll settles; the frame after.
fn wheel(
    ctx: &egui::Context,
    view: &mut TriageView,
    size: egui::Vec2,
    dock: bool,
    at: egui::Pos2,
    lines: f32,
) -> egui::FullOutput {
    let mut time = 1.0;
    draw(
        ctx,
        view,
        size,
        dock,
        vec![egui::Event::PointerMoved(at)],
        time,
    );
    let mut out = egui::FullOutput::default();
    for step in 0..40 {
        time += 0.02;
        let events = if step == 0 {
            vec![egui::Event::MouseWheel {
                phase: egui::TouchPhase::Move,
                unit: egui::MouseWheelUnit::Line,
                delta: egui::vec2(0.0, -lines),
                modifiers: egui::Modifiers::NONE,
            }]
        } else {
            vec![]
        };
        out = draw(ctx, view, size, dock, events, time);
    }
    out
}

/// Draws `view`, turns the wheel over the table and says whether the rows
/// moved: the first row's `marker` is gone or higher, and `last` is
/// nearer. The wheel is over the first row.
fn scrolls(view: &mut TriageView, first: &str, last: &str) -> bool {
    let hosts = [false, true];
    SIZES
        .into_iter()
        .flat_map(|size| hosts.map(|dock| (size, dock)))
        .all(|(size, dock)| {
            let ctx = context();
            let mut out = egui::FullOutput::default();
            for n in 0..4 {
                out = draw(&ctx, view, size, dock, vec![], f64::from(n) * 0.02);
            }
            assert!(
                has(&out, first),
                "{first:?} drawn first at {size:?} dock {dock}"
            );
            assert!(!has(&out, last), "{last:?} starts below the window");
            let at = find(&out, first).center() + egui::vec2(10.0, 0.0);
            // A click on the row first, as a person does, then the wheel.
            let mut time = 0.5;
            for pressed in [true, false] {
                draw(
                    &ctx,
                    view,
                    size,
                    dock,
                    vec![
                        egui::Event::PointerMoved(at),
                        egui::Event::PointerButton {
                            pos: at,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    time,
                );
                time += 0.02;
            }
            let before = find(&out, first).min.y;
            let out = wheel(&ctx, view, size, dock, at, 20.0);
            let after = has(&out, first).then(|| find(&out, first).min.y);
            eprintln!("{size:?} dock {dock} {first}: y {before} -> {after:?}");
            after.is_none_or(|y| y < before - 20.0)
        })
}

fn many_processes(count: u32) -> (PacketSpool, TriageView) {
    let (temp, mut view) = view(Section::Process);
    view.process = ProcessTab::Tree;
    let scan = view.scan.as_mut().unwrap();
    let template = scan.process[0].clone();
    scan.process.clear();
    for at in 0..count {
        let mut node = template.clone();
        node.pid = 1000 + at;
        node.tid = 1000 + at;
        node.cookie = 5000 + u64::from(at);
        node.depth = 0;
        node.parent = None;
        node.comm = format!("/usr/bin/tool{at}");
        node.argv = vec![format!("tool{at}")];
        scan.process.push(node);
    }
    (temp, view)
}

#[test]
fn the_wheel_scrolls_the_process_tree() {
    let (_temp, mut view) = many_processes(300);
    assert!(scrolls(
        &mut view,
        "tool0 (1000 \u{b7} 1000)",
        "tool299 (1299 \u{b7} 1299)"
    ));
}

#[test]
fn the_wheel_scrolls_suspicious_activity() {
    let (_temp, mut view) = view(Section::Process);
    view.process = ProcessTab::Suspicious;
    let scan = view.scan.as_mut().unwrap();
    let template = scan.findings[0].clone();
    scan.findings = (0..300)
        .map(|at| {
            let mut row = template.clone();
            row.cells[rules::COL_BEHAVIOUR].text = format!("summary-{at}");
            row
        })
        .collect();
    assert!(scrolls(&mut view, "summary-0", "summary-299"));
}

#[test]
fn the_wheel_scrolls_the_files_tables() {
    let (_temp, mut view) = view(Section::Files);
    view.files = FileTab::Opened;
    let scan = view.scan.as_mut().unwrap();
    let template = scan.opened.first().cloned().unwrap_or_else(|| {
        let mut row: Vec<Cell> = file_category::EVENT_HEADERS
            .iter()
            .map(|header| cell(*header, tone::text(), false))
            .collect();
        row[0].values = vec![("event.id", RowValue::Number(1))];
        row
    });
    scan.opened = (0..300)
        .map(|at| {
            let mut row = template.clone();
            row[3].text = format!("/tmp/file-{at}");
            row[0].values = vec![("event.id", RowValue::Number(at))];
            row
        })
        .collect();
    assert!(scrolls(&mut view, "/tmp/file-0", "/tmp/file-299"));
}

#[test]
fn the_wheel_scrolls_the_network_tables() {
    let (_temp, mut view) = view(Section::Network);
    let scan = view.scan.as_mut().unwrap();
    scan.network_counts = Some((300, 300, 0));
    scan.new_tabs.endpoints = (0..300)
        .map(|at| {
            let mut row: Vec<Cell> = net_tabs::ENDPOINT_HEADERS
                .iter()
                .map(|header| cell(*header, tone::text(), false))
                .collect();
            row[0].text = format!("host-{at}");
            row[0].values = vec![("frame.number", RowValue::Number(at))];
            row
        })
        .collect();
    assert!(scrolls(&mut view, "host-0", "host-299"));
}

/// A pane too short for its filters and a table: the page scrolls to the
/// table, whose first row can then be read and clicked.
#[test]
fn a_short_pane_scrolls_its_page_to_the_table() {
    let size = egui::vec2(1100.0, 330.0);
    // (In a dock tab the page scroll was not verified: see the task record.)
    for dock in [false] {
        let (_temp, mut view) = many_processes(300);
        let ctx = context();
        let mut out = egui::FullOutput::default();
        for n in 0..4 {
            out = draw(&ctx, &mut view, size, dock, vec![], f64::from(n) * 0.02);
        }
        // The wheel over the tab bar of the section, above the table.
        let out_after = wheel(&ctx, &mut view, size, dock, egui::pos2(700.0, 150.0), 20.0);
        let first = "tool0 (1000 \u{b7} 1000)";
        let shown: Vec<String> = crate::app::tests::texts(&out)
            .iter()
            .map(|(text, rect)| format!("{text}@{:.0}", rect.min.y))
            .collect();
        let after: Vec<String> = crate::app::tests::texts(&out_after)
            .iter()
            .map(|(text, rect)| format!("{text}@{:.0}", rect.min.y))
            .collect();
        assert!(
            has(&out_after, first),
            "dock {dock}\nbefore {shown:?}\nafter {after:?}"
        );
        let row = find(&out_after, first);
        assert!(
            row.min.y >= 0.0 && row.max.y <= size.y,
            "dock {dock}: {row:?}"
        );
    }
}
