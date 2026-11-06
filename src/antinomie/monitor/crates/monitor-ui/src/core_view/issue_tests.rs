// SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn a_standing_issue_is_reported_once_until_the_list_is_reloaded_or_it_changes() {
    let ctx = egui::Context::default();
    let mut view = CoreView::default();
    view.catalog_issues = vec!["Run a: broken".into()];
    assert_eq!(view.report_new_issues(&ctx), 1);
    for _ in 0..5 {
        assert_eq!(view.report_new_issues(&ctx), 0, "no repeat per frame");
    }
    view.catalog_issues.push("Run b: other".into());
    assert_eq!(view.report_new_issues(&ctx), 1, "a new issue is reported");
    view.set_catalog_scope(&[], Some("vm"));
    view.set_catalog_scope(&[], Some("other"));
    view.catalog_issues = vec!["Run a: broken".into()];
    assert_eq!(view.report_new_issues(&ctx), 1, "a reload reports again");
}

#[test]
fn the_legacy_arm_reply_record_reads_in_plain_words() {
    let stored = "process-core arm: invalid acquisition reply length or padding";
    let text = catalog::plain_issue(stored);
    assert_eq!(
        text,
        "This run's core dump record is from an older guest and can't be listed"
    );
    assert_eq!(catalog::plain_issue("something else"), "something else");
}

#[test]
fn capture_issues_are_plain_lines_without_a_close_button() {
    let ctx = egui::Context::default();
    let mut view = CoreView::default();
    view.catalog_issues = vec!["Run a: broken".into(), "Run b: other".into()];
    let frame = |view: &mut CoreView, n: u32, events: Vec<egui::Event>| {
        ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 700.0),
                )),
                time: Some(f64::from(n) * 0.02),
                events,
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| view.analysis(ui));
            },
        )
    };
    let out = frame(&mut view, 0, Vec::new());
    let header = rect_of(&out, "Capture issues (2)").expect("the header");
    let at = header.center();
    for (n, pressed) in [(1, true), (2, false)] {
        frame(
            &mut view,
            n,
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
    let mut texts = Vec::new();
    for n in 3..8 {
        texts = shown(&frame(&mut view, n, Vec::new()));
    }
    assert!(
        texts.iter().any(|text| text == "Run a: broken"),
        "{texts:?}"
    );
    assert!(texts.iter().any(|text| text == "Run b: other"), "{texts:?}");
    assert!(
        !texts.iter().any(|text| text == "\u{d7}"),
        "no close button in {texts:?}"
    );
}

fn rect_of(output: &egui::FullOutput, wanted: &str) -> Option<egui::Rect> {
    fn find(shape: &egui::Shape, wanted: &str) -> Option<egui::Rect> {
        match shape {
            egui::Shape::Text(text) if text.galley.text() == wanted => {
                Some(text.visual_bounding_rect())
            }
            egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, wanted)),
            _ => None,
        }
    }
    output
        .shapes
        .iter()
        .find_map(|shape| find(&shape.shape, wanted))
}

fn shown(output: &egui::FullOutput) -> Vec<String> {
    fn collect(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut out);
    }
    out
}
