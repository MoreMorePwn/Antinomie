// SPDX-License-Identifier: MIT
//! Dialog and window sizing.
use super::*;

#[test]
fn loss_counter_labels_and_values_have_their_own_definition_tooltips() {
    let mut app = app();
    app.snapshot.health.dropped = 7;
    app.snapshot.health.ui_dropped = 11;
    app.snapshot.health.storage_dropped_packets = 17;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx.style_mut(|style| {
        style.interaction.tooltip_delay = 0.0;
        style.interaction.tooltip_grace_time = 0.0;
    });
    let size = egui::vec2(1280.0, 900.0);
    for (label, value, description) in [
        ("TRL", "7", "Transport loss"),
        ("UIL", "11", "User interface loss"),
        ("STL", "17", "Storage loss"),
    ] {
        for target in [label, value] {
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            let pos = texts(&render(&mut app, &ctx, size))
                .iter()
                .find(|(text, _)| text == target)
                .unwrap()
                .1
                .center();
            let mut output = egui::FullOutput::default();
            for _ in 0..12 {
                output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        events: vec![egui::Event::PointerMoved(pos)],
                        ..Default::default()
                    },
                    |ctx| app.draw(ctx),
                );
            }
            assert!(
                texts(&output)
                    .iter()
                    .any(|(text, _)| text.contains(description)),
                "missing {label} tooltip over {target}: {:?}",
                texts(&output)
            );
        }
    }
}

#[test]
fn spawned_terminal_window_does_not_expand_each_frame() {
    for (size, font_size) in [
        (egui::vec2(1280.0, 900.0), 16.0),
        (egui::vec2(800.0, 600.0), 24.0),
    ] {
        let mut app = app();
        app.terminals
            .insert("growing".into(), RunTerminal::new(run("growing")));
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, font_size);
        ctx.set_embed_viewports(true);
        let id = egui::Id::new(("workspace-fallback", 1_usize));
        let mut settled = None;
        for frame in 0..90 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    time: Some(frame as f64 / 60.0),
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
            let rect = ctx
                .memory(|memory| memory.area_rect(id))
                .expect("spawned terminal fallback");
            if frame == 2 {
                settled = Some(rect.size());
            }
            if frame > 2 {
                let first = settled.unwrap();
                assert!((rect.width()-first.x).abs() <= 1.0 && (rect.height()-first.y).abs() <= 1.0,
                    "spawned terminal grows at {size:?}/{font_size}, frame {frame}: {first:?} -> {:?}", rect.size());
            }
        }
    }
}

#[test]
fn tool_dialogs_do_not_keep_growing_after_their_initial_layout() {
    for dialog in [
        Dialog::Vm,
        Dialog::Launch,
        Dialog::Upload,
        Dialog::Settings,
        Dialog::Import,
        Dialog::Download,
        Dialog::Transport,
        Dialog::About,
    ] {
        for (size, font_size) in [
            (egui::vec2(1280.0, 900.0), 16.0),
            (egui::vec2(800.0, 600.0), 24.0),
        ] {
            let mut app = app();
            match dialog {
                Dialog::Vm => app.new_image(),
                Dialog::Launch => app.launch_open = true,
                Dialog::Upload => app.open_upload(),
                Dialog::Settings => app.settings_open = true,
                Dialog::Import => app.import_open = true,
                Dialog::Download => app.download_open = true,
                Dialog::Transport => {
                    app.new_image();
                    app.transport_open = true;
                }
                Dialog::About => app.about_open = true,
                _ => unreachable!(),
            }
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font_size);
            let mut settled = None;
            for frame in 0..90 {
                let _ = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        time: Some(frame as f64 / 60.0),
                        ..Default::default()
                    },
                    |ctx| app.draw(ctx),
                );
                let rect = ctx
                    .memory(|memory| memory.area_rect(dialog.window_id()))
                    .unwrap_or_else(|| panic!("missing {dialog:?}"));
                if frame == 2 {
                    settled = Some(rect.size());
                }
                if frame > 2 {
                    let first = settled.unwrap();
                    assert!((rect.width()-first.x).abs() <= 1.0 && (rect.height()-first.y).abs() <= 1.0,
                        "{dialog:?} grows at {size:?}/{font_size}, frame {frame}: {first:?} -> {:?}", rect.size());
                }
            }
        }
    }
}

#[test]
fn vm_network_section_warns_only_for_disconnected_mode() {
    let mut app = app();
    app.new_image();
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for mode in 0..3 {
        app.draft.isolated_network = mode == 1;
        app.draft.nat = mode == 2;
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let visible = texts(&render(&mut app, &ctx, size));
        assert!(visible
            .iter()
            .any(|(text, _)| text == "Network and telemetry"));
        assert_eq!(
            visible
                .iter()
                .any(|(text, _)| text.contains("Disconnected: network capture is unavailable")),
            mode == 0
        );
    }
}
