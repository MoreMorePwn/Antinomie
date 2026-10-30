// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn frame(
    ctx: &egui::Context,
    size: Vec2,
    events: Vec<egui::Event>,
    maximized: bool,
) -> egui::FullOutput {
    let mut raw = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
        events,
        ..Default::default()
    };
    raw.viewports
        .get_mut(&egui::ViewportId::ROOT)
        .unwrap()
        .maximized = Some(maximized);
    ctx.run(raw, |ctx| {
        show(ctx, "Antinomie custom title bar");
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE)
            .show(ctx, |ui| {
                ui.label("Window contents");
                ui.interact(
                    ui.max_rect(),
                    egui::Id::new("terminal-keyboard-focus"),
                    Sense::click(),
                );
            });
        resize(ctx);
    })
}

fn click(pos: Pos2, pressed: bool) -> egui::Event {
    egui::Event::PointerButton {
        pos,
        pressed,
        button: egui::PointerButton::Primary,
        modifiers: egui::Modifiers::NONE,
    }
}

#[test]
fn controls_send_native_commands_without_changing_keyboard_focus() {
    for theme in theme::Theme::ALL {
        for (index, expected) in [
            ViewportCommand::Minimized(true),
            ViewportCommand::Maximized(true),
            ViewportCommand::Close,
        ]
        .into_iter()
        .enumerate()
        {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::apply_theme(&ctx, theme);
            let size = egui::vec2(800.0, 500.0);
            let focus = egui::Id::new("terminal-keyboard-focus");
            frame(&ctx, size, vec![], false);
            frame(&ctx, size, vec![], false);
            ctx.memory_mut(|m| m.request_focus(focus));
            frame(&ctx, size, vec![], false);
            let pos = egui::pos2(
                size.x - (2 - index) as f32 * BUTTON_WIDTH - BUTTON_WIDTH / 2.0,
                17.0,
            );
            frame(
                &ctx,
                size,
                vec![egui::Event::PointerMoved(pos), click(pos, true)],
                false,
            );
            let output = frame(&ctx, size, vec![click(pos, false)], false);
            assert_eq!(
                ctx.memory(|m| m.focused()),
                Some(focus),
                "caption buttons must preserve terminal focus"
            );
            assert!(
                output.viewport_output[&egui::ViewportId::ROOT]
                    .commands
                    .contains(&expected),
                "{theme:?}, control {index}"
            );
            assert!(!output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|c| matches!(
                    c,
                    ViewportCommand::StartDrag | ViewportCommand::BeginResize(_)
                )));
        }
    }
}

#[test]
fn maximize_restores_and_double_clicks_use_current_viewport_state() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(800.0, 500.0);
    frame(&ctx, size, vec![], true);
    frame(&ctx, size, vec![], true);
    let pos = egui::pos2(size.x - 1.5 * BUTTON_WIDTH, 17.0);
    frame(
        &ctx,
        size,
        vec![egui::Event::PointerMoved(pos), click(pos, true)],
        true,
    );
    let output = frame(&ctx, size, vec![click(pos, false)], true);
    assert!(output.viewport_output[&egui::ViewportId::ROOT]
        .commands
        .contains(&ViewportCommand::Maximized(false)));
    // A new gesture sequence: the restore click above must not count as the
    // first click of this independently tested title-bar double click.
    let ctx = egui::Context::default();
    theme::install(&ctx);
    frame(&ctx, size, vec![], false);
    frame(&ctx, size, vec![], false);
    let title = egui::pos2(200.0, 17.0);
    frame(
        &ctx,
        size,
        vec![egui::Event::PointerMoved(title), click(title, true)],
        false,
    );
    frame(&ctx, size, vec![click(title, false)], false);
    frame(&ctx, size, vec![click(title, true)], false);
    let output = frame(&ctx, size, vec![click(title, false)], false);
    assert!(output.viewport_output[&egui::ViewportId::ROOT]
        .commands
        .contains(&ViewportCommand::Maximized(true)));
}

#[test]
fn narrow_large_text_header_and_resize_targets_stay_inside_the_window() {
    for theme in theme::Theme::ALL {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::apply_theme(&ctx, theme);
        theme::text_size(&ctx, 24.0);
        let size = egui::vec2(360.0, 220.0);
        let output = frame(&ctx, size, vec![], false);
        assert!(
            content_rect(&ctx).top() >= 34.0,
            "floating panes must leave the caption accessible"
        );
        let screen = Rect::from_min_size(Pos2::ZERO, size);
        for (rect, _, _) in resize_regions(screen) {
            assert!(screen.contains_rect(rect));
        }
        for shape in output.shapes {
            if let egui::Shape::LineSegment { points, .. } = shape.shape {
                assert!(points.iter().all(|p| p.x >= 0.0 && p.x <= size.x));
            }
        }
        assert_eq!(crate::native_options().viewport.decorations, Some(false));
    }
}

#[test]
fn resize_handles_do_not_cover_content_or_exist_while_maximized() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(800.0, 500.0);
    frame(&ctx, size, vec![], false);
    frame(&ctx, size, vec![], false);
    let corner = egui::pos2(798.0, 498.0);
    let output = frame(
        &ctx,
        size,
        vec![egui::Event::PointerMoved(corner), click(corner, true)],
        false,
    );
    assert!(output.viewport_output[&egui::ViewportId::ROOT]
        .commands
        .contains(&ViewportCommand::BeginResize(
            egui::ResizeDirection::SouthEast
        )));
    frame(&ctx, size, vec![click(corner, false)], false);
    let output = frame(
        &ctx,
        size,
        vec![egui::Event::PointerMoved(corner), click(corner, true)],
        true,
    );
    assert!(!output.viewport_output[&egui::ViewportId::ROOT]
        .commands
        .iter()
        .any(|c| matches!(c, ViewportCommand::BeginResize(_))));
    assert!(!resize_regions(Rect::from_min_size(Pos2::ZERO, size))
        .iter()
        .any(|(r, _, _)| r.contains(egui::pos2(400.0, 250.0))));
}

#[test]
#[ignore = "requires isolated X11 and native mouse automation; exits after Close or 40 seconds"]
fn native_custom_title_bar_controls() {
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use winit::platform::x11::EventLoopBuilderExtX11;
    #[derive(Default)]
    struct Evidence {
        moved: bool,
        resized: bool,
        maximized: bool,
        restored: bool,
        borderless: bool,
    }
    struct Qa {
        evidence: Arc<Mutex<Evidence>>,
        start: Instant,
    }
    impl eframe::App for Qa {
        fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
            if ctx.input(|i| i.pointer.button_pressed(egui::PointerButton::Primary)) {
                eprintln!(
                    "native press {:?}; screen {:?}; viewport {:?}",
                    ctx.input(|i| i.pointer.hover_pos()),
                    ctx.screen_rect(),
                    ctx.input(|i| (i.viewport().maximized, i.viewport().inner_rect))
                );
            }
            show(ctx, "Antinomie — Custom title bar QA");
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Native window controls");
                ui.label(
                    "Drag the title bar; resize a corner; maximize, restore, minimize and close.",
                );
                ui.label(
                    "The buttons use native operations and keep the existing close-event path.",
                );
            });
            resize(ctx);
            ctx.input(|i| {
                if let (Some(outer), Some(inner)) =
                    (i.viewport().outer_rect, i.viewport().inner_rect)
                {
                    let mut e = self.evidence.lock().unwrap();
                    e.borderless |= outer.min.distance(inner.min) < 2.0;
                    if i.viewport().maximized == Some(true) {
                        e.maximized = true;
                    } else if e.maximized {
                        e.restored = true;
                    } else {
                        e.moved |= outer.min.x > 170.0 && outer.min.y > 150.0;
                        e.resized |= inner.width() > 850.0 && inner.height() > 540.0;
                    }
                }
            });
            if self.start.elapsed() >= Duration::from_secs(40) {
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(20));
        }
    }
    let evidence = Arc::new(Mutex::new(Evidence::default()));
    let result = evidence.clone();
    eframe::run_native(
        "Antinomie Custom Title Bar QA",
        eframe::NativeOptions {
            viewport: builder(egui::ViewportBuilder::default())
                .with_inner_size([800.0, 500.0])
                .with_position([120.0, 120.0])
                .with_min_inner_size([360.0, 220.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|b| {
                b.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(Qa {
                evidence,
                start: Instant::now(),
            }))
        }),
    )
    .expect("native title bar fixture");
    let e = result.lock().unwrap();
    eprintln!(
        "borderless={} moved={} resized={} maximized={} restored={}",
        e.borderless, e.moved, e.resized, e.maximized, e.restored
    );
    assert!(e.borderless && e.moved && e.resized && e.maximized && e.restored);
}

#[test]
fn fps_counter_slot_sits_left_of_the_window_buttons() {
    let ctx = egui::Context::default();
    let _ = ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(800.0, 600.0))),
            ..Default::default()
        },
        |ctx| show(ctx, "Antinomie"),
    );
    let (height, left) = caption_slot(&ctx);
    assert!(height > 0.0);
    assert_eq!(left, 800.0 - 3.0 * BUTTON_WIDTH);
}
