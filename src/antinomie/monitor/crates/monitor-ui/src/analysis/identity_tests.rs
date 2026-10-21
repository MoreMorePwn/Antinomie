// SPDX-License-Identifier: MIT
use super::*;

fn render(
    ctx: &egui::Context,
    request: &mut ExecRequest,
    events: Vec<egui::Event>,
    width: f32,
) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(width, 500.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| identity_fields(ui, request));
        },
    )
}

fn find(output: &egui::FullOutput, label: &str) -> Option<egui::Rect> {
    output.shapes.iter().find_map(|shape| match &shape.shape {
        egui::Shape::Text(text) if text.galley.text() == label => Some(text.visual_bounding_rect()),
        _ => None,
    })
}

fn click(ctx: &egui::Context, request: &mut ExecRequest, point: egui::Pos2) -> egui::FullOutput {
    let mut output = render(ctx, request, vec![], 600.0);
    for pressed in [true, false] {
        output = render(
            ctx,
            request,
            vec![
                egui::Event::PointerMoved(point),
                egui::Event::PointerButton {
                    pos: point,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            600.0,
        );
    }
    output
}

#[test]
fn launch_user_presets_set_both_ids_and_custom_values_survive_snapshot() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut request = ExecRequest {
        path: "/bin/true".into(),
        uid: 42,
        gid: 43,
        ..Default::default()
    };
    let mut output = render(&ctx, &mut request, vec![], 600.0);
    for _ in 0..3 {
        output = render(&ctx, &mut request, vec![], 600.0);
    }
    for (current, choice, id) in [("Custom", "Root", 0), ("Root", "Normal user", 1000)] {
        let point = find(&output, current).unwrap().center();
        let _ = click(&ctx, &mut request, point);
        for _ in 0..3 {
            output = render(&ctx, &mut request, vec![], 600.0);
        }
        let point = find(&output, choice).unwrap().center();
        let _ = click(&ctx, &mut request, point);
        for _ in 0..3 {
            output = render(&ctx, &mut request, vec![], 600.0);
        }
        assert_eq!((request.uid, request.gid), (id, id));
        let sent = snapshot(&request, "", "", false).unwrap();
        assert_eq!((sent.uid, sent.gid), (id, id));
    }
    request.uid = 7;
    output = render(&ctx, &mut request, vec![], 600.0);
    assert!(find(&output, "Custom").is_some());
    let sent = snapshot(&request, "", "", false).unwrap();
    assert_eq!((sent.uid, sent.gid), (7, 1000));
}

#[test]
fn launch_user_controls_wrap_in_a_narrow_large_text_pane() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    crate::theme::text_size(&ctx, 24.0);
    let mut request = ExecRequest {
        uid: 1000,
        gid: 1000,
        ..Default::default()
    };
    let mut output = render(&ctx, &mut request, vec![], 320.0);
    for _ in 0..3 {
        output = render(&ctx, &mut request, vec![], 320.0);
    }
    for label in ["Normal user", "UID", "GID"] {
        let rect = find(&output, label).unwrap();
        assert!(
            rect.left() >= 0.0 && rect.right() <= 320.0,
            "{label}: {rect:?}"
        );
    }
}

#[test]
fn uid_and_gid_stay_on_one_line_at_every_width() {
    for width in [260.0, 300.0, 330.0, 360.0, 420.0, 600.0] {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut request = ExecRequest {
            uid: 1000,
            gid: 1000,
            ..Default::default()
        };
        let mut output = render(&ctx, &mut request, vec![], width);
        for _ in 0..4 {
            output = render(&ctx, &mut request, vec![], width);
        }
        let uid = find(&output, "UID").unwrap();
        let gid = find(&output, "GID").unwrap();
        let mut values: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == "1000" => {
                    Some(text.visual_bounding_rect())
                }
                _ => None,
            })
            .collect();
        values.sort_by(|a, b| a.left().total_cmp(&b.left()));
        assert_eq!(values.len(), 2, "width {width}");
        for rect in [gid, values[0], values[1]] {
            assert!(
                (rect.center().y - uid.center().y).abs() < 4.0,
                "width {width}: {rect:?} is not on the UID line {uid:?}"
            );
        }
        assert!(values[1].right() <= width, "width {width}: {:?}", values[1]);
    }
}
