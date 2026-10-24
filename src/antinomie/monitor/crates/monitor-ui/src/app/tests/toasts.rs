// SPDX-License-Identifier: GPL-3.0-only
//! Warnings and errors reach the user as toasts, not in their old places.
use super::*;
use crate::activity::Level;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn frames(app: &mut MonitorApp, ctx: &egui::Context, count: u32) -> egui::FullOutput {
    let mut output = egui::FullOutput::default();
    for frame in 0..count {
        output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                time: Some(f64::from(frame) * 0.02),
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
    output
}

fn toasts(ctx: &egui::Context) -> Vec<(Level, String, String)> {
    crate::toasts::snapshot(ctx)
}

fn shown(output: &egui::FullOutput, needle: &str) -> Vec<egui::Rect> {
    texts(output)
        .into_iter()
        .filter(|(text, _)| text.contains(needle))
        .map(|(_, rect)| rect)
        .collect()
}

#[test]
fn a_reported_error_is_a_toast_an_activity_row_and_not_the_status_line() {
    let mut app = app();
    let ctx = context();
    app.report_error("Host folder: permission denied".into());
    let output = frames(&mut app, &ctx, 4);
    assert_eq!(
        toasts(&ctx),
        [(
            Level::Error,
            "Host folder".into(),
            "permission denied".into()
        )]
    );
    assert_eq!(app.activity.counts(), (0, 1), "one row, from the event");
    let seen = shown(&output, "permission denied");
    assert_eq!(seen.len(), 1, "only the toast shows it: {seen:?}");
    assert!(seen[0].min.x > SIZE.x / 2.0, "bottom right: {:?}", seen[0]);
}

#[test]
fn a_failed_command_result_is_a_toast_not_a_failed_status_line() {
    let mut app = app();
    let ctx = context();
    app.status = "Failed: guest agent unreachable".into();
    app.log("ERROR", app.status.clone());
    let output = frames(&mut app, &ctx, 4);
    assert_eq!(
        toasts(&ctx),
        [(
            Level::Error,
            "Action failed".into(),
            "guest agent unreachable".into()
        )]
    );
    assert_eq!(shown(&output, "guest agent unreachable").len(), 1);
}

#[test]
fn a_plain_status_message_stays_in_the_status_line() {
    let mut app = app();
    let ctx = context();
    app.status = "Request queued".into();
    let output = frames(&mut app, &ctx, 4);
    assert!(toasts(&ctx).is_empty());
    let seen = shown(&output, "Request queued");
    assert_eq!(seen.len(), 1);
    assert!(seen[0].min.y > SIZE.y - 60.0, "in the bar: {:?}", seen[0]);
}

#[test]
fn a_backend_error_is_a_toast_and_the_bar_keeps_only_the_saving_state() {
    let mut app = app();
    let ctx = context();
    app.snapshot.last_error = Some("VM did not start".into());
    app.snapshot.health.persistence_error = Some("disk full".into());
    app.activity_notices_due = true;
    let output = frames(&mut app, &ctx, 4);
    let levels: Vec<_> = toasts(&ctx).into_iter().map(|toast| toast.2).collect();
    assert!(
        levels.contains(&"VM did not start".to_owned()),
        "{levels:?}"
    );
    assert_eq!(
        shown(&output, "VM did not start").len(),
        1,
        "no copy in the bar"
    );
    assert!(
        shown(&output, "Saving stopped: disk full")
            .iter()
            .any(|rect| rect.min.y > SIZE.y - 60.0),
        "saving stopped is a state of the bar"
    );
}

#[test]
fn a_vm_that_started_with_a_setting_changed_warns_once_in_the_start_log() {
    let mut app = app();
    let ctx = context();
    let line = "Stealth setting not applied: SATA (AHCI) not supported by this base: virtio will be used; the base boots from virtio only";
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.stealth_fallbacks = vec![line.into()];
    app.activity_notices_due = true;
    frames(&mut app, &ctx, 4);
    let warned: Vec<_> = toasts(&ctx)
        .into_iter()
        .filter(|toast| toast.1 == "Stealth setting not applied")
        .collect();
    assert_eq!(warned.len(), 1, "{:?}", toasts(&ctx));
    assert!(warned[0]
        .2
        .starts_with("SATA (AHCI) not supported by this base"));
    assert_eq!(app.activity.counts().0, 1, "and in the Activity log");
    // A VM that started as configured says nothing.
    let mut quiet = super::app();
    let ctx = context();
    quiet.snapshot.active_vm = Some("vm".into());
    quiet.activity_notices_due = true;
    frames(&mut quiet, &ctx, 4);
    assert!(toasts(&ctx).is_empty());
}

#[test]
fn what_belongs_to_one_run_stays_in_activity_and_its_view() {
    let mut app = app();
    let ctx = context();
    let mut run = run("run-1");
    run.recording_error = Some("disk full".into());
    app.snapshot.runs.push(run);
    app.activity_notices_due = true;
    frames(&mut app, &ctx, 2);
    assert!(toasts(&ctx).is_empty());
    assert_eq!(app.activity.counts(), (1, 0));
}

#[test]
fn the_activity_tab_shows_warnings_and_errors_as_two_chips() {
    let mut app = app();
    app.activity.log("WARN", "a".into());
    app.activity.log("WARN", "b".into());
    app.activity.log("ERROR", "c".into());
    let egui::WidgetText::LayoutJob(job) = app.activity_title() else {
        panic!("rich title")
    };
    let palette = theme::palette();
    let chips: Vec<_> = job
        .sections
        .iter()
        .filter(|section| section.format.background != egui::Color32::TRANSPARENT)
        .map(|section| {
            (
                job.text[section.byte_range.clone()].trim().to_owned(),
                section.format.color,
                section.format.background,
            )
        })
        .collect();
    assert_eq!(
        chips,
        [
            ("2".into(), palette.warn, palette.warn_bg),
            ("1".into(), palette.error, palette.error_bg),
        ]
    );
}

#[test]
fn toasts_are_drawn_whatever_panes_are_open() {
    let mut app = app();
    let ctx = context();
    crate::toasts::notify(&ctx, Level::Error, "Export: disk full");
    frames(&mut app, &ctx, 3);
    assert_eq!(toasts(&ctx).len(), 1, "shown whatever panes are open");
}
