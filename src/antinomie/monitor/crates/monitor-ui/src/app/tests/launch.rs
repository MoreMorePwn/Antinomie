// SPDX-License-Identifier: MIT
//! Health messages and launch settings.
use super::*;

#[test]
fn long_health_messages_do_not_overlap_figures_and_keep_full_hover_text() {
    let error = "guest command 25713 timed out: outcome unknown; run status polling paused until its reply arrives or transport reconnects";
    let closing = "Waiting for guest shutdown and recording finalization…";
    for (width, font_size) in [(1280.0, 16.0), (800.0, 24.0)] {
        for shutting_down in [false, true] {
            let mut app = app();
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font_size);
            ctx.style_mut(|style| {
                style.interaction.tooltip_delay = 0.0;
                style.interaction.tooltip_grace_time = 0.0;
            });
            app.closing = shutting_down;
            let message = if shutting_down { closing } else { error };
            if !shutting_down {
                app.snapshot.last_error = Some(error.into());
                // The error has just arrived: no newer status message yet.
                app.error_status_mark = Some(app.status.clone());
            }
            let size = egui::vec2(width, 900.0);
            let mut output = egui::FullOutput::default();
            for frame in 0..4 {
                output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        time: Some(frame as f64),
                        ..Default::default()
                    },
                    |ctx| app.health(ctx),
                );
            }
            let visible = texts(&output);
            let message_rect = visible
                .iter()
                .find(|(text, _)| text == message)
                .unwrap_or_else(|| {
                    panic!("missing bounded message at {width}/{font_size}: {visible:?}")
                })
                .1;
            let mut figure_rects = Vec::new();
            let app_label = format!("Antinomie {APP_VERSION}");
            for label in ["TRL", "UIL", "STL", "CAP 0.0/4 GiB", &app_label] {
                let rect = visible
                    .iter()
                    .find(|(text, _)| text == label)
                    .unwrap_or_else(|| panic!("missing figure {label}: {visible:?}"))
                    .1;
                assert!(
                    rect.min.x >= 0.0 && rect.max.x <= width,
                    "figure remains inside viewport"
                );
                assert!(
                    !rect.intersects(message_rect),
                    "message overlaps {label}: {message_rect:?} / {rect:?}"
                );
                figure_rects.push(rect);
            }
            assert!(
                message_rect.max.x
                    < figure_rects
                        .iter()
                        .map(|rect| rect.min.x)
                        .fold(f32::INFINITY, f32::min)
            );
            assert!(
                message_rect.height() <= font_size * 1.6,
                "status stays one compact row"
            );
            let mut hovered = output;
            for frame in 4..8 {
                hovered = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        time: Some(frame as f64),
                        events: vec![egui::Event::PointerMoved(message_rect.center())],
                        ..Default::default()
                    },
                    |ctx| app.health(ctx),
                );
            }
            assert!(
                texts(&hovered)
                    .iter()
                    .any(|(text, rect)| text == message && rect.min.y < message_rect.min.y),
                "hover preserves the complete message above the footer"
            );
        }
    }
}

#[test]
fn launch_controls_edit_create_and_save_owned_configurations() {
    let mut app = app();
    app.snapshot.bases.push(test_base("capable", true));
    app.new_image();
    app.draft.disk_root = Some("/disks".into());
    app.draft.recording_root = Some("/recordings".into());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for label in [
        "Auto",
        "1920 x 1080",
        "Fullscreen",
        "Fit to window",
        "Default",
        "TCG",
        "Default",
        "max",
        "Create VM",
    ] {
        click_label(&mut app, &ctx, size, label);
    }
    let mut created = app
        .submitted
        .iter()
        .find_map(|command| match command {
            Command::Create(vm) => Some(vm.clone()),
            _ => None,
        })
        .expect("create command");
    assert_eq!(
        created.launch,
        VmLaunchOptions {
            resolution: DisplayResolution::R1920x1080,
            fullscreen: true,
            fit_to_window: true,
            acceleration: VmAcceleration::Tcg,
            cpu_model: VmCpuModel::Max,
        }
    );
    assert_eq!(created.disk_root, Some(PathBuf::from("/disks")));
    assert_eq!(created.recording_root, Some(PathBuf::from("/recordings")));
    assert!(!app.create_open);
    created.id = "created".into();
    app.selected = Some(created.id.clone());
    app.snapshot.vms.push(created.clone());
    app.configure_vm();
    assert_eq!(app.draft.launch, created.launch);
    for label in [
        "1920 x 1080",
        "1280 x 800",
        "max",
        "qemu64",
        "Save configuration",
    ] {
        click_label(&mut app, &ctx, size, label);
    }
    let saved = app
        .submitted
        .iter()
        .find_map(|command| match command {
            Command::Save(vm) => Some(vm),
            _ => None,
        })
        .expect("save command");
    assert_eq!(saved.launch.resolution, DisplayResolution::R1280x800);
    assert_eq!(saved.launch.cpu_model, VmCpuModel::Qemu64);
    assert!(saved.launch.fullscreen && saved.launch.fit_to_window);
    assert_eq!(saved.launch.acceleration, VmAcceleration::Tcg);
    assert_eq!(saved.disk_root, created.disk_root);
    assert_eq!(saved.recording_root, created.recording_root);
    assert!(!app.config_open);
}

#[test]
fn invalid_launch_options_explain_create_and_save_rejection() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for (acceleration, force_tcg) in [
        (VmAcceleration::Tcg, false),
        (VmAcceleration::Default, true),
        (VmAcceleration::Kvm, true),
    ] {
        let mut app = app();
        app.new_image();
        app.options.force_tcg = force_tcg;
        app.draft.launch.cpu_model = VmCpuModel::Host;
        app.draft.launch.acceleration = acceleration;
        app.credentials.password = "private-test-secret".into();
        let error = app.create_vm().unwrap_err();
        assert!(error.contains("requires KVM"));
        assert!(!error.contains(&app.credentials.password));
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        assert!(texts(&output).iter().any(|(text, _)| text == &error));
        click_label(&mut app, &ctx, size, "Create VM");
        assert!(app.submitted.is_empty());
        assert!(app.create_open);

        app.create_open = false;
        app.draft.id = "saved".into();
        app.snapshot.vms.push(app.draft.clone());
        app.config_open = true;
        assert_eq!(app.save_vm(app.draft.clone()).unwrap_err(), error);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        assert!(texts(&output).iter().any(|(text, _)| text == &error));
        click_label(&mut app, &ctx, size, "Save configuration");
        assert!(app.submitted.is_empty());
        assert!(app.config_open);
    }
}

#[test]
fn launch_settings_save_requires_a_stopped_existing_vm() {
    let mut app = app();
    app.draft.id = "vm".into();
    app.snapshot.vms.push(app.draft.clone());
    app.snapshot.active_vm = Some("vm".into());
    app.config_open = true;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    theme::text_size(&ctx, 24.0);
    let size = egui::vec2(1280.0, 900.0);
    click_label(&mut app, &ctx, size, "Fullscreen");
    click_label(&mut app, &ctx, size, "Save configuration");
    assert!(!app.draft.launch.fullscreen);
    assert!(app
        .save_vm(app.draft.clone())
        .unwrap_err()
        .contains("Stop this VM"));
    assert!(app.submitted.is_empty());
    app.snapshot.active_vm = None;
    app.snapshot.vms.clear();
    assert!(app
        .save_vm(app.draft.clone())
        .unwrap_err()
        .contains("no longer available"));
    assert!(app.submitted.is_empty());
}

#[test]
fn trace_coloring_is_on_by_default_and_old_settings_still_load() {
    let settings = Settings::default();
    assert!(settings.trace_colors);
    assert!(settings.hidden_trace_categories.is_empty());
    // Groups hidden from the earlier color legend are not carried over.
    let earlier: Settings = serde_json::from_str(r#"{"hidden_trace_groups": ["File"]}"#).unwrap();
    assert!(earlier.hidden_trace_categories.is_empty());
    let old: Settings =
        serde_json::from_str(r#"{"bundle": "", "quota_gib": 4, "timeout": 10, "font_size": 16.0}"#)
            .unwrap();
    assert!(old.trace_colors);
}
