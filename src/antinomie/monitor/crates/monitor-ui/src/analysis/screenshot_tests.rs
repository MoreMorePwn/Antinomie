// SPDX-License-Identifier: GPL-3.0-only
//! The Run form's Timed Screenshot section (ANT-T0487, item 19).
use super::*;

fn output(
    ctx: &egui::Context,
    request: &mut ExecRequest,
    available: bool,
    events: Vec<egui::Event>,
) -> Vec<(String, egui::Rect)> {
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 400.0),
            )),
            events,
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default()
                .show(root, |ui| screenshot_selection(ui, request, available));
        },
    );
    crate::app::tests::texts(&output)
}

fn render(ctx: &egui::Context, request: &mut ExecRequest, available: bool) -> Vec<String> {
    output(ctx, request, available, Vec::new())
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

#[test]
fn a_vm_without_a_readable_screen_clears_the_choice_and_says_why() {
    let ctx = egui::Context::default();
    let mut request = ExecRequest {
        screenshot_every_s: Some(30),
        screenshot_max_pictures: Some(40),
        ..ExecRequest::default()
    };
    let texts = render(&ctx, &mut request, false);
    assert_eq!(request.screenshot_every_s, None);
    assert_eq!(request.screenshot_max_pictures, None);
    assert!(texts
        .iter()
        .any(|t| t.starts_with("Timed screenshots read")));
}

#[test]
fn a_readable_screen_keeps_the_interval_and_shows_the_section() {
    let ctx = egui::Context::default();
    let mut request = ExecRequest {
        screenshot_every_s: Some(30),
        ..ExecRequest::default()
    };
    let texts = render(&ctx, &mut request, true);
    assert_eq!(request.screenshot_every_s, Some(30));
    assert!(texts.iter().any(|t| t == "Timed Screenshot"), "{texts:?}");
    assert!(texts.iter().any(|t| t == "Take screenshots"), "{texts:?}");
    assert!(texts.iter().any(|t| t.contains("30")), "{texts:?}");
    // The limits show, at their defaults; the old sentence is gone.
    assert!(texts.iter().any(|t| t.contains("500")), "{texts:?}");
    assert!(texts.iter().any(|t| t.contains("256")), "{texts:?}");
    assert!(
        !texts.iter().any(|t| t.contains("Pictures go to")),
        "{texts:?}"
    );
    assert!(!texts.iter().any(|t| t.contains("Take a screenshot every")));
    // Defaults stay out of the request.
    assert_eq!(request.screenshot_max_pictures, None);
    assert_eq!(request.screenshot_max_mib, None);
}

/// The interval shows (greyed) before the box is ticked; ticking it takes
/// the interval shown.
#[test]
fn off_by_default_with_the_interval_already_shown() {
    assert_eq!(ExecRequest::default().screenshot_every_s, None);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest::default();
    render(&ctx, &mut request, true);
    let shown = output(&ctx, &mut request, true, Vec::new());
    assert_eq!(request.screenshot_every_s, None);
    assert!(shown.iter().any(|(t, _)| t.contains("10")), "{shown:?}");
    let tick = shown
        .iter()
        .find(|(t, _)| t == "Take screenshots")
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        output(
            &ctx,
            &mut request,
            true,
            vec![
                egui::Event::PointerMoved(tick),
                egui::Event::PointerButton {
                    pos: tick,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    assert_eq!(request.screenshot_every_s, Some(10));
}

/// Limits other than the defaults reach the request.
#[test]
fn the_limits_the_user_sets_reach_the_request() {
    let ctx = egui::Context::default();
    let mut request = ExecRequest {
        screenshot_every_s: Some(5),
        screenshot_max_pictures: Some(40),
        screenshot_max_mib: Some(64),
        ..ExecRequest::default()
    };
    let texts = render(&ctx, &mut request, true);
    assert!(texts.iter().any(|t| t.contains("40")), "{texts:?}");
    assert_eq!(request.screenshot_max_pictures, Some(40));
    assert_eq!(request.screenshot_max_mib, Some(64));
    // Off, the limits leave the request.
    request.screenshot_every_s = None;
    render(&ctx, &mut request, true);
    assert_eq!(request.screenshot_max_pictures, None);
}
