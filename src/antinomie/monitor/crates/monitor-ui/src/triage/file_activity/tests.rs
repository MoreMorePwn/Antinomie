// SPDX-License-Identifier: GPL-3.0-only
//! The File activity graph and window: how a file's calls become nodes on
//! lanes, the list's filters, and the tab through a real egui pass.
use super::graph::{self, NODES_MAX};
use super::window::{content_text, run_text, Order, Window};
use super::*;
use eframe::egui::{self, Pos2, Rect};

fn event(time: u64, kind: Kind, process: u32) -> Event {
    Event {
        time,
        key: (1, 2, time),
        process,
        kind,
        operation: match kind {
            Kind::Write => "pwrite64".into(),
            other => other.verb().to_owned(),
        },
        success: Some(true),
        result: "Success (0)".into(),
        offset: None,
        len: None,
        content: Vec::new(),
        content_gap: false,
        extends: false,
        via: None,
        other_path: None,
        note: String::new(),
    }
}

fn file(path: &str, first_ns: u64, events: Vec<Event>) -> FileActivity {
    FileActivity {
        path: path.into(),
        path_known: true,
        names: Vec::new(),
        identity: None,
        first_ns,
        last_ns: events.last().map_or(first_ns, |event| event.time),
        events,
        omitted: 0,
        standard_io: false,
        created: false,
        deleted: false,
        failed_only: false,
        contents: Contents::default(),
        hashes: Vec::new(),
        writes: Default::default(),
    }
}

/// Two processes: a dropper that writes a file and a shell that renames and
/// deletes it, plus a library, a standard stream and a file only read.
pub(in crate::triage) fn activity() -> Activity {
    let mut dropped = file(
        "/tmp/payload",
        10,
        vec![
            event(10, Kind::Create, 0),
            {
                let mut write = event(11, Kind::Write, 0);
                write.offset = Some(0);
                write.len = Some(4);
                write.content = b"\x7fELF".to_vec();
                write
            },
            {
                let mut write = event(12, Kind::Write, 0);
                write.offset = Some(4);
                write.len = Some(2);
                write.content = b"hi".to_vec();
                write.extends = true;
                write
            },
            {
                let mut rename = event(13, Kind::Rename, 1);
                rename.other_path = Some("/tmp/.payload".into());
                rename
            },
            event(14, Kind::Delete, 1),
        ],
    );
    dropped.created = true;
    dropped.deleted = true;
    let mut library = file("/usr/lib/libc.so.6", 5, vec![event(5, Kind::Read, 0)]);
    library.contents = Contents::default();
    let mut stdout = file("stdout", 6, vec![event(6, Kind::Write, 0)]);
    stdout.standard_io = true;
    Activity {
        files: vec![
            library,
            stdout,
            file(
                "/etc/hosts",
                8,
                vec![event(8, Kind::Open, 0), event(9, Kind::Read, 0)],
            ),
            dropped,
        ],
        processes: vec![
            (100, Some("/tmp/dropper".into())),
            (101, Some("/bin/sh".into())),
        ],
        omitted_files: 0,
        omitted_events: 0,
        written: Default::default(),
        limits: Default::default(),
    }
}

#[test]
fn a_run_of_the_same_call_by_the_same_process_is_one_node_on_its_processs_lane() {
    let activity = activity();
    let layout = graph::layout(&activity.files[3]);
    let steps: Vec<_> = layout
        .nodes
        .iter()
        .map(|node| (node.kind, node.events.clone(), node.lane))
        .collect();
    assert_eq!(
        steps,
        [
            (Kind::Create, 0..1, 0),
            (Kind::Write, 1..3, 0),
            (Kind::Rename, 3..4, 1),
            (Kind::Delete, 4..5, 1),
        ]
    );
    assert_eq!(layout.lanes, [0, 1], "one lane for each process");
}

#[test]
fn a_refused_call_is_its_own_node_and_a_process_change_splits_a_run() {
    let mut refused = event(2, Kind::Write, 0);
    refused.success = Some(false);
    let writes = file(
        "/tmp/x",
        1,
        vec![
            event(1, Kind::Write, 0),
            refused,
            event(3, Kind::Write, 0),
            event(4, Kind::Write, 1),
        ],
    );
    let layout = graph::layout(&writes);
    let shape: Vec<_> = layout
        .nodes
        .iter()
        .map(|node| (node.failed, node.events.len(), node.lane))
        .collect();
    assert_eq!(
        shape,
        [(false, 1, 0), (true, 1, 0), (false, 1, 0), (false, 1, 1)]
    );
}

#[test]
fn the_calls_past_the_node_limit_share_one_last_node() {
    let events: Vec<_> = (0..300)
        .map(|time| {
            let kind = if time % 2 == 0 {
                Kind::Read
            } else {
                Kind::Write
            };
            event(time, kind, 0)
        })
        .collect();
    let layout = graph::layout(&file("/tmp/busy", 0, events));
    assert_eq!(layout.nodes.len(), NODES_MAX + 1);
    let last = layout.nodes.last().unwrap();
    assert!(last.rest);
    assert_eq!(last.events, NODES_MAX..300);
    assert!(layout.nodes[..NODES_MAX].iter().all(|node| !node.rest));
}

#[test]
fn the_list_hides_streams_and_libraries_filters_by_name_and_orders() {
    let activity = activity();
    let mut window = Window::default();
    let paths = |window: &Window| -> Vec<&str> {
        window
            .shown(&activity)
            .into_iter()
            .map(|index| activity.files[index].path.as_str())
            .collect()
    };
    // Stdio and library files are hidden at first; the rest is by first call.
    assert_eq!(paths(&window), ["/etc/hosts", "/tmp/payload"]);
    window.hide_standard_io = false;
    window.hide_libraries = false;
    assert_eq!(
        paths(&window),
        ["/usr/lib/libc.so.6", "stdout", "/etc/hosts", "/tmp/payload"]
    );
    window.changed_only = true;
    assert_eq!(paths(&window), ["stdout", "/tmp/payload"]);
    window.changed_only = false;
    window.filter = "PAYLOAD".into();
    assert_eq!(paths(&window), ["/tmp/payload"]);
    // A name the file was renamed to finds it too.
    let mut renamed = activity.clone();
    renamed.files[3].names.push("/var/spool/x".into());
    window.filter = "spool".into();
    assert_eq!(window.shown(&renamed), [3]);
    window.filter.clear();
    window.order = Order::Path;
    assert_eq!(paths(&window)[0], "/etc/hosts");
    window.order = Order::Calls;
    assert_eq!(paths(&window)[0], "/tmp/payload", "five calls");
    window.order = Order::Last;
    assert_eq!(paths(&window)[0], "/tmp/payload");
}

#[test]
fn content_and_changed_bytes_are_worded_without_inventing_anything() {
    let mut write = event(1, Kind::Write, 0);
    write.len = Some(6);
    write.content = b"ab\n\x01".to_vec();
    write.content_gap = true;
    assert_eq!(content_text(&write), "ab\\n\\x01 …");
    write.content.clear();
    assert_eq!(content_text(&write), "not captured");
    write.success = Some(false);
    assert_eq!(content_text(&write), "");
    write.len = None;
    assert_eq!(content_text(&write), "");
    let run = ByteRun {
        offset: 0x10,
        before: vec![Some(b'A'), None],
        after: vec![Some(b'B'), Some(0)],
    };
    assert_eq!(
        run_text(&run, Some(0x100)),
        "0x00000010  41 ?? → 42 00  |B.|"
    );
    let added = ByteRun {
        offset: 8,
        before: vec![None],
        after: vec![Some(b'z')],
    };
    assert_eq!(run_text(&added, Some(8)), "added 0x00000008  ∅ → 7a  |z|");
    assert_eq!(run_text(&added, None), "0x00000008  ?? → 7a  |z|");
}

#[test]
fn a_file_summary_names_its_stages_in_order_with_counts() {
    let activity = activity();
    assert_eq!(
        activity.files[3].summary(),
        "create → write 2× → rename → delete"
    );
    assert_eq!(activity.process_label(1), "101 /bin/sh");
    assert_eq!(activity.process_label(9), "unknown process");
}

struct Harness {
    ctx: egui::Context,
    window: Window,
    time: f64,
    size: egui::Vec2,
}

const SIZE: egui::Vec2 = egui::vec2(1400.0, 900.0);

impl Harness {
    fn new() -> Self {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let window = Window::default();
        Self {
            ctx,
            window,
            time: 0.0,
            size: SIZE,
        }
    }

    fn frame_sized(&mut self, activity: &Activity, size: egui::Vec2) -> Vec<(String, Rect)> {
        self.size = size;
        self.frame(activity, Vec::new())
    }

    fn frame(&mut self, activity: &Activity, events: Vec<egui::Event>) -> Vec<(String, Rect)> {
        self.time += 0.05;
        let window = &mut self.window;
        let output = self.ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, self.size)),
                events,
                time: Some(self.time),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| window.show(ui, Some(activity), None));
            },
        );
        fn collect(shape: &egui::epaint::Shape, out: &mut Vec<(String, Rect)>) {
            match shape {
                egui::epaint::Shape::Text(text) => out.push((
                    text.galley.text().to_owned(),
                    Rect::from_min_size(text.pos, text.galley.size()),
                )),
                egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, &mut found);
        }
        found
    }

    fn settle(&mut self, activity: &Activity) -> Vec<(String, Rect)> {
        let mut shown = Vec::new();
        for _ in 0..4 {
            shown = self.frame(activity, Vec::new());
        }
        shown
    }

    fn click(&mut self, activity: &Activity, at: Pos2) {
        for pressed in [true, false] {
            self.frame(
                activity,
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
        self.time += 1.0;
    }
}

impl Harness {
    fn double_click(&mut self, activity: &Activity, at: Pos2) {
        for _ in 0..2 {
            for pressed in [true, false] {
                self.frame(
                    activity,
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
        }
        self.time += 1.0;
    }
}

fn center(shown: &[(String, Rect)], text: &str) -> Pos2 {
    shown
        .iter()
        .find(|(shown, _)| shown == text)
        .unwrap_or_else(|| {
            panic!(
                "{text:?} not drawn in {:?}",
                shown.iter().map(|s| &s.0).collect::<Vec<_>>()
            )
        })
        .1
        .center()
}

#[test]
fn choosing_a_file_draws_its_graph_and_choosing_a_node_lists_its_calls() {
    let activity = activity();
    let mut harness = Harness::new();
    let shown = harness.settle(&activity);
    assert!(shown.iter().any(|(text, _)| text == "/tmp/payload"));
    assert!(
        !shown
            .iter()
            .any(|(text, _)| text == "stdout" || text == "/usr/lib/libc.so.6"),
        "stdio and libraries start hidden"
    );
    assert!(shown
        .iter()
        .any(|(text, _)| text.starts_with("Select a file")));
    // Choose the dropped file.
    harness.click(&activity, center(&shown, "/tmp/payload"));
    let shown = harness.settle(&activity);
    assert_eq!(harness.window.chosen(), (Some("/tmp/payload"), None));
    for label in ["create", "write ×2", "rename", "delete"] {
        assert!(shown.iter().any(|(text, _)| text == label), "{label}");
    }
    assert!(shown.iter().any(|(text, _)| text == "created by the run"));
    assert!(shown.iter().any(|(text, _)| text == "deleted"));
    assert!(shown.iter().any(|(text, _)| text == "All calls"));
    // Both processes have a lane.
    assert!(shown.iter().any(|(text, _)| text.contains("/tmp/dropper")));
    assert!(shown.iter().any(|(text, _)| text.contains("/bin/sh")));
    // The writes: where, how long, and what was written.
    assert!(shown.iter().any(|(text, _)| text == "0x4"));
    assert!(shown.iter().any(|(text, _)| text.contains("hi")));
    assert!(shown
        .iter()
        .any(|(text, _)| text.contains("[extends the file]")));
    // Choose the write node.
    harness.click(&activity, center(&shown, "write ×2"));
    let shown = harness.settle(&activity);
    assert_eq!(harness.window.chosen().1, Some(1));
    assert!(shown
        .iter()
        .any(|(text, _)| text == "Calls in the chosen step"));
    assert!(
        !shown.iter().any(|(text, _)| text.contains("/tmp/.payload")),
        "the rename is not among the chosen writes"
    );
}

#[test]
fn a_call_row_shows_in_details_and_a_double_click_opens_its_original_syscall() {
    let activity = activity();
    let mut harness = Harness::new();
    harness.window.open_on("/tmp/payload");
    let shown = harness.settle(&activity);
    assert_eq!(harness.window.chosen().0, Some("/tmp/payload"));
    assert!(shown.iter().any(|(text, _)| text == "write ×2"));
    let first_write = shown
        .iter()
        .find(|(text, _)| text == "pwrite64")
        .map(|(_, rect)| rect.center())
        .unwrap();
    // One click selects the row and brings Details forward: it opens nothing.
    harness.click(&activity, first_write);
    let selected = harness.ctx.data(|data| {
        data.get_temp::<String>(egui::Id::new((
            "triage-selected-row",
            super::window::CALLS_TABLE,
        )))
    });
    assert!(selected.is_some(), "the clicked call is the selected row");
    assert_eq!(
        harness
            .ctx
            .data(|data| data.get_temp::<bool>(egui::Id::new("triage-details-focus"))),
        Some(true),
        "Details come forward"
    );
    assert_eq!(
        harness
            .ctx
            .data(|data| data.get_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump"))),
        None
    );
    // A double click opens the original syscall, as in the other tables.
    harness.double_click(&activity, first_write);
    let jump = harness
        .ctx
        .data(|data| data.get_temp::<trace::InvocationKey>(egui::Id::new("triage-call-jump")));
    assert_eq!(jump, Some((1, 2, 11)));
}

#[test]
fn a_call_row_carries_what_the_original_syscall_is_found_by_and_all_seven_columns() {
    let activity = activity();
    let dropped = &activity.files[3];
    let cells = super::window::call_cells(&activity, &dropped.events[1], None);
    assert_eq!(cells.len(), 7);
    assert_eq!(cells[2].text, "pwrite64");
    assert_eq!(cells[4].text, "0x0");
    assert_eq!(cells[5].text, "4");
    let first = &cells[0].values;
    for (name, want) in [("stream.id", 1), ("process.cookie", 2), ("event.id", 11)] {
        assert!(
            first.iter().any(|(key, value)| *key == name
                && matches!(value, RowValue::Number(number) if *number == want)),
            "{name} in {first:?}"
        );
    }
}

#[test]
fn a_click_on_a_file_shows_it_in_details_and_an_empty_list_says_why() {
    let activity = activity();
    let mut harness = Harness::new();
    let shown = harness.settle(&activity);
    harness.click(&activity, center(&shown, "/tmp/payload"));
    assert_eq!(
        harness
            .ctx
            .data(|data| data.get_temp::<bool>(egui::Id::new("triage-details-focus"))),
        Some(true)
    );
    let cells = super::window::file_cells(&activity.files[3], None);
    let text = |at: usize| cells[at].text.as_str();
    assert_eq!(text(0), "/tmp/payload");
    assert!(text(5).starts_with("create"), "{}", text(5));
    assert_eq!(text(6), "created by the run, deleted");
    assert_eq!(text(4), "5");
    // With every file hidden the list says so, and with none it says that.
    harness.window.filter = "no such file".into();
    let shown = harness.settle(&activity);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "No file matches the filter"),
        "{:?}",
        shown.iter().map(|s| &s.0).collect::<Vec<_>>()
    );
    let mut empty = Harness::new();
    let nothing = Activity::default();
    let shown = empty.settle(&nothing);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "The run touched no files"),
        "{:?}",
        shown.iter().map(|s| &s.0).collect::<Vec<_>>()
    );
}

#[test]
fn a_long_process_name_is_cut_to_the_gutter_and_the_graph_leaves_it_room() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let font = egui::FontId::proportional(11.0);
    let long = "123456 /usr/lib/very/long/path/to/an/image/with/a/long/name";
    let width = 150.0;
    let _ = ctx.run(egui::RawInput::default(), |ctx| {
        let painter = ctx.layer_painter(egui::LayerId::background());
        let short = graph::fit(&painter, long, &font, width);
        assert!(short.ends_with('…') && short.len() < long.len(), "{short}");
        let measured = painter
            .layout_no_wrap(short.clone(), font.clone(), egui::Color32::WHITE)
            .size()
            .x;
        assert!(measured <= width, "{short} is {measured} wide");
        // A name that fits is left as it is.
        assert_eq!(graph::fit(&painter, "42 sh", &font, width), "42 sh");
        assert_eq!(graph::fit(&painter, "", &font, width), "");
        // Nothing fits in no room: only the ellipsis stays.
        assert_eq!(graph::fit(&painter, long, &font, 0.0), "…");
    });
}

#[test]
fn an_unindexed_run_says_so() {
    let mut harness = Harness::new();
    let window = &mut harness.window;
    let output = harness.ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| window.show(ui, None, None));
        },
    );
    assert!(!output.shapes.is_empty());
}

#[test]
fn a_narrow_pane_stacks_the_file_list_above_the_history() {
    let activity = activity();
    let mut harness = Harness::new();
    harness.window.open_on("/tmp/payload");
    let mut shown = Vec::new();
    for _ in 0..4 {
        shown = harness.frame_sized(&activity, egui::vec2(520.0, 900.0));
    }
    let list = shown
        .iter()
        .find(|(text, _)| text == "Filter by path")
        .expect("the filter")
        .1;
    let history = shown
        .iter()
        .find(|(text, _)| text == "All calls")
        .expect("the calls")
        .1;
    assert!(history.top() > list.bottom(), "{history:?} under {list:?}");
}
