// SPDX-License-Identifier: GPL-3.0-only
//! The Run form's timed screenshots choice (ANT-T0487).
use super::*;

fn render(ctx: &egui::Context, request: &mut ExecRequest, available: bool) -> Vec<String> {
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 400.0),
            )),
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default()
                .show(root, |ui| screenshot_selection(ui, request, available));
        },
    );
    crate::app::tests::texts(&output)
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

#[test]
fn a_vm_without_a_readable_screen_clears_the_choice_and_says_why() {
    let ctx = egui::Context::default();
    let mut request = ExecRequest {
        screenshot_every_s: Some(30),
        ..ExecRequest::default()
    };
    let texts = render(&ctx, &mut request, false);
    assert_eq!(request.screenshot_every_s, None);
    assert!(texts
        .iter()
        .any(|t| t.starts_with("Timed screenshots read")));
}

#[test]
fn a_readable_screen_keeps_the_interval_and_shows_the_box() {
    let ctx = egui::Context::default();
    let mut request = ExecRequest {
        screenshot_every_s: Some(30),
        ..ExecRequest::default()
    };
    let texts = render(&ctx, &mut request, true);
    assert_eq!(request.screenshot_every_s, Some(30));
    assert!(texts.iter().any(|t| t == "Take a screenshot every"));
    assert!(texts.iter().any(|t| t.contains("30 s")), "{texts:?}");
    assert!(texts.iter().any(|t| t.contains("at most 500 pictures")));
}

#[test]
fn off_by_default() {
    assert_eq!(ExecRequest::default().screenshot_every_s, None);
    let ctx = egui::Context::default();
    let mut request = ExecRequest::default();
    let texts = render(&ctx, &mut request, true);
    assert_eq!(request.screenshot_every_s, None);
    assert!(!texts.iter().any(|t| t.contains(" s")), "{texts:?}");
}
