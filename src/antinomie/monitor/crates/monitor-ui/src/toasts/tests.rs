// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::activity::Journal;

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

const SIZE: egui::Vec2 = egui::vec2(1000.0, 700.0);

fn run(ctx: &egui::Context, time: f64, events: Vec<egui::Event>) -> (egui::FullOutput, Vec<Panel>) {
    let mut followed = Vec::new();
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            time: Some(time),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |_| {});
            followed = show(ctx);
        },
    );
    (output, followed)
}

fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    fn collect(shape: &egui::Shape, texts: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::Shape::Text(text) => {
                texts.push((text.galley.text().into(), text.visual_bounding_rect()))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, texts)),
            _ => {}
        }
    }
    let mut texts = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut texts);
    }
    texts
}

fn find(texts: &[(String, egui::Rect)], label: &str) -> egui::Rect {
    texts
        .iter()
        .find(|(text, _)| text == label)
        .unwrap_or_else(|| panic!("missing {label:?}: {texts:?}"))
        .1
}

/// The stack after its first frames: the area sizes itself on the first.
fn settled(ctx: &egui::Context) -> egui::FullOutput {
    let mut output = egui::FullOutput::default();
    for frame in 0..4 {
        output = run(ctx, f64::from(frame) * 0.01, vec![]).0;
    }
    output
}

fn level_count(ctx: &egui::Context) -> usize {
    with(ctx, |toasts| toasts.items().len())
}

#[test]
fn a_pushed_toast_is_drawn_bottom_right_with_title_detail_action_and_close() {
    let ctx = context();
    push(
        &ctx,
        Level::Warn,
        "Rule trigger fired",
        "core on first outbound connect matched",
        Some(Action::open_activity()),
    );
    let output = settled(&ctx);
    let shown = texts(&output);
    let title = find(&shown, "Rule trigger fired");
    find(&shown, "core on first outbound connect matched");
    let action = find(&shown, "Open Activity");
    let close = find(&shown, egui_phosphor::regular::X);
    assert!(title.center().x > SIZE.x / 2.0 && title.center().y > SIZE.y / 2.0);
    assert!(
        close.max.x <= SIZE.x - MARGIN + 1.0,
        "inside the right margin"
    );
    assert!(action.max.y <= SIZE.y - 8.0, "above the bottom edge");
    assert!(action.min.y > title.max.y);
}

#[test]
fn the_stack_sits_above_the_status_bar() {
    let ctx = context();
    set_floor(&ctx, SIZE.y - 40.0);
    push(&ctx, Level::Error, "Failed", "boom", None);
    let output = settled(&ctx);
    let detail = find(&texts(&output), "boom");
    assert!(detail.max.y < SIZE.y - 40.0 - 8.0, "{detail:?}");
}

#[test]
fn timers_follow_the_level_and_errors_stay() {
    let mut toasts = Toasts::default();
    toasts.add(Level::Info, "i", "", None, false);
    toasts.add(Level::Warn, "w", "", None, false);
    toasts.add(Level::Error, "e", "", None, false);
    assert_eq!(toasts.items()[0].left, Some(6.0));
    assert_eq!(toasts.items()[1].left, Some(12.0));
    assert_eq!(toasts.items()[2].left, None);
    toasts.tick(5.9);
    assert_eq!(toasts.items().len(), 3);
    toasts.tick(0.2);
    let titles: Vec<_> = toasts
        .items()
        .iter()
        .map(|toast| toast.title.as_str())
        .collect();
    assert_eq!(titles, ["w", "e"], "info left after 6 s");
    toasts.tick(5.8);
    assert_eq!(toasts.items().len(), 2, "a warning stays just under 12 s");
    toasts.tick(0.3);
    let titles: Vec<_> = toasts
        .items()
        .iter()
        .map(|toast| toast.title.as_str())
        .collect();
    assert_eq!(titles, ["e"], "warning left after 12 s");
    toasts.tick(3600.0);
    assert_eq!(toasts.items().len(), 1, "an error stays until dismissed");
    let id = toasts.items()[0].id;
    toasts.dismiss(id);
    assert!(toasts.items().is_empty());
}

#[test]
fn hovering_a_toast_pauses_its_timer_and_leaving_resumes_it() {
    let ctx = context();
    push(&ctx, Level::Info, "Saved", "report.html", None);
    // The frame clock: egui's stable_dt follows the time between frames.
    let on = find(&texts(&settled(&ctx)), "Saved").center();
    let hover = vec![egui::Event::PointerMoved(on)];
    let mut time = 0.1;
    for _ in 0..3 {
        run(&ctx, time, hover.clone());
        time += 0.05;
    }
    let before = with(&ctx, |toasts| toasts.items()[0].left).unwrap();
    assert!(with(&ctx, |toasts| toasts.items()[0].hovered));
    for _ in 0..10 {
        run(&ctx, time, hover.clone());
        time += 0.5;
    }
    let held = with(&ctx, |toasts| toasts.items()[0].left).unwrap();
    assert!(
        (before - held).abs() < 0.2,
        "paused while hovered: {before} -> {held}"
    );
    let away = vec![egui::Event::PointerMoved(egui::pos2(5.0, 5.0))];
    for _ in 0..4 {
        run(&ctx, time, away.clone());
        time += 0.5;
    }
    let after = with(&ctx, |toasts| {
        toasts.items().first().and_then(|toast| toast.left)
    });
    assert!(
        after.is_none_or(|left| left < held - 0.5),
        "resumed: {held} -> {after:?}"
    );
}

#[test]
fn repeats_merge_into_one_toast_with_a_count_and_restart_the_timer() {
    let mut toasts = Toasts::default();
    toasts.add(Level::Warn, "Capture gap", "10 packets", None, false);
    toasts.tick(10.0);
    for _ in 0..4 {
        toasts.add(Level::Warn, "Capture gap", "10 packets", None, false);
    }
    toasts.add(Level::Warn, "Capture gap", "11 packets", None, false);
    assert_eq!(toasts.items().len(), 2);
    assert_eq!(toasts.items()[0].count, 5);
    assert_eq!(
        toasts.items()[0].left,
        Some(12.0),
        "seen again, so it stays"
    );
    assert_eq!(toasts.items()[1].count, 1);
}

#[test]
fn a_count_chip_is_drawn_for_a_merged_toast() {
    let ctx = context();
    for _ in 0..3 {
        push(&ctx, Level::Error, "Upload failed", "no route", None);
    }
    let output = settled(&ctx);
    find(&texts(&output), "×3");
    assert_eq!(level_count(&ctx), 1);
}

#[test]
fn only_the_newest_toasts_are_shown_and_waiting_ones_keep_their_time() {
    let mut toasts = Toasts::default();
    for index in 0..VISIBLE + 2 {
        toasts.add(Level::Info, &format!("t{index}"), "", None, false);
    }
    toasts.tick(3.0);
    assert_eq!(
        toasts.items()[0].left,
        Some(6.0),
        "waiting toasts do not age"
    );
    assert_eq!(toasts.items()[2].left, Some(3.0));
}

#[test]
fn every_toast_is_an_activity_row_and_the_counts_follow() {
    let ctx = context();
    let mut journal = Journal::default();
    push(&ctx, Level::Warn, "Low space", "2 GiB left", None);
    push(&ctx, Level::Error, "Export failed", "disk full", None);
    notify(&ctx, Level::Info, "Saved: report.html");
    journal.ingest(&ctx);
    assert_eq!(journal.counts(), (1, 1));
    assert_eq!(
        journal.messages(),
        [
            "Low space: 2 GiB left",
            "Export failed: disk full",
            "Saved: report.html"
        ]
    );
    journal.ingest(&ctx);
    assert_eq!(journal.messages().len(), 3, "rows are taken once");
}

#[test]
fn warnings_and_errors_logged_to_activity_become_toasts_but_info_does_not() {
    let ctx = context();
    let mut journal = Journal::default();
    journal.log("INFO", "Session Running".into());
    journal.log("WARN", "Capture: 3 packets lost".into());
    journal.log("ERROR", "Failed: Host folder: denied".into());
    journal.ingest(&ctx);
    let shown = with(&ctx, |toasts| {
        toasts
            .items()
            .iter()
            .map(|toast| (toast.level, toast.title.clone(), toast.detail.clone()))
            .collect::<Vec<_>>()
    });
    assert_eq!(
        shown,
        [
            (
                Level::Warn,
                "Capture".to_owned(),
                "3 packets lost".to_owned()
            ),
            (
                Level::Error,
                "Action failed".to_owned(),
                "Host folder: denied".to_owned()
            ),
        ]
    );
    assert_eq!(
        journal.messages().len(),
        3,
        "the toast does not add a second row"
    );
}

#[test]
fn the_same_event_arriving_twice_at_once_is_one_toast_without_a_count() {
    let ctx = context();
    let mut journal = Journal::default();
    journal.log("ERROR", "VM did not start".into());
    journal.log("ERROR", "VM did not start".into());
    journal.ingest(&ctx);
    with(&ctx, |toasts| {
        assert_eq!(toasts.items().len(), 1);
        assert_eq!(toasts.items()[0].count, 1);
    });
}

#[test]
fn quiet_notices_and_state_labels_do_not_toast() {
    let ctx = context();
    let mut journal = Journal::default();
    crate::activity::report_quiet(&ctx, Level::Warn, "Recording incomplete for run 1");
    let _ = ctx.run(Default::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            crate::activity::warning(ui, "Stop the VM to change these settings.");
        });
    });
    journal.ingest(&ctx);
    assert_eq!(journal.counts(), (2, 0), "both are in Activity");
    assert_eq!(level_count(&ctx), 0);
}

#[test]
fn clicking_the_action_follows_it_and_dismisses_the_toast() {
    let ctx = context();
    push(
        &ctx,
        Level::Error,
        "Export failed",
        "disk full",
        Some(Action::open_activity()),
    );
    let output = settled(&ctx);
    let at = find(&texts(&output), "Open Activity").center();
    let mut followed = Vec::new();
    for (index, pressed) in [None, Some(true), Some(false)].into_iter().enumerate() {
        let mut events = vec![egui::Event::PointerMoved(at)];
        if let Some(pressed) = pressed {
            events.push(egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            });
        }
        followed.extend(run(&ctx, 0.2 + index as f64 * 0.05, events).1);
    }
    assert_eq!(followed, [Panel::Activity]);
    assert_eq!(level_count(&ctx), 0);
}

#[test]
fn the_close_button_dismisses_one_toast() {
    let ctx = context();
    push(&ctx, Level::Error, "One", "a", None);
    push(&ctx, Level::Error, "Two", "b", None);
    let output = settled(&ctx);
    let shown = texts(&output);
    let at = shown
        .iter()
        .filter(|(text, _)| text == egui_phosphor::regular::X)
        .min_by(|a, b| a.1.min.y.total_cmp(&b.1.min.y))
        .unwrap()
        .1
        .center();
    for (index, pressed) in [None, Some(true), Some(false)].into_iter().enumerate() {
        let mut events = vec![egui::Event::PointerMoved(at)];
        if let Some(pressed) = pressed {
            events.push(egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            });
        }
        run(&ctx, 0.2 + index as f64 * 0.05, events);
    }
    let left = with(&ctx, |toasts| {
        toasts
            .items()
            .iter()
            .map(|toast| toast.title.clone())
            .collect::<Vec<_>>()
    });
    assert_eq!(left, ["Two"], "the first (upper) toast was dismissed");
}

#[test]
fn the_stack_moves_off_a_window_it_would_cover() {
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE);
    let size = egui::vec2(380.0, 120.0);
    let free = placement(screen, 660.0, size, &[]);
    assert_eq!(free, (SIZE.x - MARGIN, 652.0));
    // A dialog whose footer buttons sit in the bottom-right corner.
    let dialog = egui::Rect::from_min_max(egui::pos2(300.0, 576.0), egui::pos2(980.0, 640.0));
    let moved = placement(screen, 660.0, size, &[dialog]);
    let stack = egui::Rect::from_min_max(
        egui::pos2(moved.0 - size.x, moved.1 - size.y),
        egui::pos2(moved.0, moved.1),
    );
    assert!(!stack.intersects(dialog), "{stack:?} vs {dialog:?}");
    assert!(screen.contains_rect(stack));
}

#[test]
fn messages_split_into_a_title_and_a_detail() {
    assert_eq!(
        split(Level::Error, "Failed: no route"),
        ("Action failed".into(), "no route".into())
    );
    assert_eq!(
        split(Level::Warn, "Recording incomplete: saving stopped"),
        ("Recording incomplete".into(), "saving stopped".into())
    );
    assert_eq!(
        split(Level::Error, "Something went wrong"),
        ("Error".into(), "Something went wrong".into())
    );
    assert_eq!(
        split(
            Level::Warn,
            "See https://x.test: unreachable. A very long sentence follows here"
        ),
        (
            "Warning".into(),
            "See https://x.test: unreachable. A very long sentence follows here".into()
        )
    );
}

#[test]
fn a_failed_status_leaves_the_view_as_a_toast_and_a_success_stays() {
    let ctx = context();
    let mut status = Some(("Saved".to_owned(), false));
    take_failure(&ctx, &mut status);
    assert!(status.is_some());
    assert_eq!(level_count(&ctx), 0);
    status = Some(("Could not read the dump".to_owned(), true));
    take_failure(&ctx, &mut status);
    assert!(status.is_none());
    assert_eq!(level_count(&ctx), 1);
}

/// One frame in which the app reports `message` (or not), then logs it.
fn frame_reporting(ctx: &egui::Context, journal: &mut Journal, time: f64, message: Option<&str>) {
    let _ = ctx.run(
        egui::RawInput {
            time: Some(time),
            ..Default::default()
        },
        |ctx| {
            if let Some(message) = message {
                crate::activity::report(ctx, Level::Error, message);
            }
            journal.ingest(ctx);
        },
    );
}

fn counts(ctx: &egui::Context) -> Vec<u32> {
    with(ctx, |toasts| {
        toasts.items().iter().map(|toast| toast.count).collect()
    })
}

#[test]
fn a_condition_reported_every_frame_is_one_toast() {
    let ctx = context();
    let mut journal = Journal::default();
    for frame in 0..5 {
        frame_reporting(
            &ctx,
            &mut journal,
            f64::from(frame),
            Some("Export: disk full"),
        );
    }
    assert_eq!(counts(&ctx), [1]);
}

#[test]
fn a_retry_that_fails_again_counts_while_shown_and_raises_a_new_toast_after_dismissal() {
    let ctx = context();
    let mut journal = Journal::default();
    frame_reporting(&ctx, &mut journal, 0.0, Some("Export: disk full"));
    assert_eq!(counts(&ctx), [1]);
    // The same row is not written twice within a second.
    std::thread::sleep(Duration::from_millis(1100));
    frame_reporting(&ctx, &mut journal, 1.0, None);
    frame_reporting(&ctx, &mut journal, 2.0, Some("Export: disk full"));
    assert_eq!(counts(&ctx), [2], "repeat while visible counts");
    let id = with(&ctx, |toasts| toasts.items()[0].id);
    with(&ctx, |toasts| toasts.dismiss(id));
    std::thread::sleep(Duration::from_millis(1100));
    frame_reporting(&ctx, &mut journal, 3.0, None);
    frame_reporting(&ctx, &mut journal, 4.0, Some("Export: disk full"));
    assert_eq!(counts(&ctx), [1], "after dismissal it is a new toast");
    assert_eq!(
        journal.counts(),
        (0, 3),
        "each occurrence is an Activity row"
    );
}

#[test]
fn push_and_take_failure_follow_the_same_rule() {
    let ctx = context();
    push(&ctx, Level::Error, "Failed", "boom", None);
    push(&ctx, Level::Error, "Failed", "boom", None);
    assert_eq!(counts(&ctx), [2]);
    let id = with(&ctx, |toasts| toasts.items()[0].id);
    with(&ctx, |toasts| toasts.dismiss(id));
    let mut status = Some(("Failed: boom".to_owned(), true));
    take_failure(&ctx, &mut status);
    take_failure(&ctx, &mut Some(("Failed: boom".to_owned(), true)));
    assert_eq!(counts(&ctx), [2]);
}
