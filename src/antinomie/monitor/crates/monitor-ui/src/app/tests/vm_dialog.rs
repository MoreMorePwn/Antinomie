// SPDX-License-Identifier: MIT
//! New VM and VM settings dialogs.
use super::*;

#[test]
fn fixed_resolution_requires_a_capable_base_for_create_and_save() {
    let mut app = app();
    app.snapshot.bases = vec![test_base("legacy", false), test_base("capable", true)];
    app.new_image();
    app.draft.base_identity = Some("legacy".into());
    app.draft.launch.resolution = DisplayResolution::R1280x720;
    let error = app.create_vm().unwrap_err();
    assert!(error.contains("Select a refreshed base or choose Auto"));
    assert!(app.submitted.is_empty());
    app.draft.id = "vm".into();
    app.snapshot.vms.push(app.draft.clone());
    assert_eq!(app.save_vm(app.draft.clone()).unwrap_err(), error);
    assert!(app.submitted.is_empty());

    let ctx = egui::Context::default();
    theme::install(&ctx);
    for _ in 0..3 {
        render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
    }
    let output = render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
    assert!(texts(&output).iter().any(|(text, _)| text == &error));

    app.draft.base_identity = Some("missing".into());
    assert_eq!(app.create_vm().unwrap_err(), error);
    app.draft.base_identity = Some("capable".into());
    assert!(app.create_validation_error(false).is_none());
    assert!(app.save_validation_error(&app.draft).is_none());
    app.draft.base_identity = Some("legacy".into());
    app.draft.launch.resolution = DisplayResolution::Auto;
    assert!(app.create_validation_error(false).is_none());
    assert!(app.save_validation_error(&app.draft).is_none());
}

#[test]
fn new_vm_prefers_capable_bases_and_existing_defaults_remain_implicit() {
    let mut app = app();
    app.snapshot.bases = vec![test_base("legacy", false), test_base("capable", true)];
    app.settings.bundle = "/bases/legacy".into();
    app.new_image();
    assert_eq!(app.draft.base_identity.as_deref(), Some("capable"));
    let legacy = VmConfig {
        id: "legacy-vm".into(),
        ..VmConfig::default()
    };
    app.create_open = false;
    app.selected = Some(legacy.id.clone());
    app.snapshot.vms.push(legacy.clone());
    app.configure_vm();
    let ctx = egui::Context::default();
    theme::install(&ctx);
    for _ in 0..3 {
        render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
    }
    assert!(app.draft.base_identity.is_none());
    assert_eq!(app.snapshot.vms[0], legacy);
    assert!(app.save_validation_error(&app.draft).is_none());
    app.draft.launch.resolution = DisplayResolution::R1280x720;
    assert!(app.fixed_display_error(&app.draft).is_some());
    app.snapshot.bases[0].fixed_display = true;
    assert!(app.fixed_display_error(&app.draft).is_none());

    app.settings.bundle = "/bases/capable".into();
    app.new_image();
    assert_eq!(app.draft.base_identity.as_deref(), Some("capable"));
    app.snapshot.bases[0].fixed_display = false;
    app.snapshot.bases[1].fixed_display = false;
    app.settings.bundle = "/bases/legacy".into();
    app.new_image();
    assert_eq!(app.draft.base_identity.as_deref(), Some("legacy"));
    assert_eq!(
        base_choice_label(&app.snapshot.bases[0]),
        format!(
            "Linux 6.12.94 · Antinomie {} (legacy)",
            antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
        )
    );
    app.snapshot.bases[1].fixed_display = true;
    assert_eq!(
        base_choice_label(&app.snapshot.bases[1]),
        format!(
            "Linux 6.12.94 · Antinomie {}",
            antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
        )
    );
}

#[test]
fn default_base_selection_preserves_guest_profile_and_backend_fallback() {
    let mut app = app();
    let mut custom = test_base("custom", false);
    custom.guest = Some(antinomie_monitor_core::GuestProfile {
        id: "custom".into(),
        label: "Custom guest".into(),
        min_ram_mib: 256,
        min_disk_gib: 1,
        requires_credentials: false,
        graphical: false,
    });
    app.snapshot.bases = vec![custom.clone(), test_base("busybox", true)];
    app.settings.bundle = "/bases/custom".into();
    app.new_image();
    assert_eq!(app.draft.base_identity.as_deref(), Some("custom"));
    assert_eq!(selected_base(&app.snapshot, None).unwrap().id, "busybox");
    assert_eq!(
        preferred_new_base(&app.snapshot, "/missing-source")
            .unwrap()
            .id,
        "busybox"
    );

    custom.id = "refreshed-custom".into();
    custom.directory = "/bases/refreshed-custom".into();
    custom.fixed_display = true;
    app.snapshot.bases.push(custom);
    app.new_image();
    assert_eq!(app.draft.base_identity.as_deref(), Some("refreshed-custom"));
}

#[test]
fn password_widget_does_not_retain_undo_history() {
    let ctx = egui::Context::default();
    let mut password = "first-private-password".to_owned();
    for text in ["first-private-password", "second-private-password", ""] {
        password.clear();
        password.push_str(text);
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default()
                .show(ctx, |ui| password_input(ui, &mut password, "private_qa"));
        });
        let state =
            egui::widgets::text_edit::TextEditState::load(&ctx, egui::Id::new("private_qa"))
                .unwrap();
        assert!(state
            .undoer()
            .undo(&(Default::default(), String::new()))
            .is_none());
    }
}

#[test]
fn creation_guards_explain_rejection_without_submitting() {
    let mut app = app();
    app.new_image();
    app.draft.name.clear();
    assert_eq!(app.create_vm().unwrap_err(), "Enter a VM name");
    assert!(app.submitted.is_empty());

    app.draft.name = "New VM".into();
    app.snapshot.active_vm = Some("running".into());
    assert_eq!(
        app.create_vm().unwrap_err(),
        "Stop the running VM before creating another VM"
    );
    assert!(app.submitted.is_empty());
    app.snapshot.active_vm = None;
    assert!(app.create_validation_error(false).is_none());
    assert!(app
        .create_validation_error(true)
        .unwrap()
        .contains("8..128"));
    app.credentials.password = "test-secret-only".into();
    assert_eq!(
        app.create_validation_error(true).unwrap(),
        "password confirmation does not match"
    );
    app.credentials.confirmation = app.credentials.password.clone();
    assert!(app.create_validation_error(true).is_none());
    app.credentials.username = "root".into();
    assert!(app
        .create_validation_error(true)
        .unwrap()
        .contains("non-root"));
    app.create_vm().unwrap();
    assert!(app
        .submitted
        .iter()
        .any(|command| matches!(command, Command::Create(_))));
}

#[test]
fn default_folder_paths_are_visible_without_changing_automatic_choices() {
    let mut app = app();
    app.options.data_dir = "/vm-data".into();
    app.new_image();
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    assert_eq!(
        texts(&output)
            .iter()
            .filter(|(text, _)| text == "/vm-data")
            .count(),
        2
    );
    assert!(app.draft.disk_root.is_none());
    assert!(app.draft.recording_root.is_none());

    app.draft.disk_root = Some("/disks".into());
    render(&mut app, &ctx, size);
    let output = render(&mut app, &ctx, size);
    assert_eq!(
        texts(&output)
            .iter()
            .filter(|(text, _)| text == "/disks")
            .count(),
        2
    );
    assert!(app.draft.recording_root.is_none());

    app.draft.recording_root = Some("/captures".into());
    let output = render(&mut app, &ctx, size);
    assert!(texts(&output).iter().any(|(text, _)| text == "/captures"));
    assert_eq!(app.draft.disk_root, Some(PathBuf::from("/disks")));
}

#[test]
fn editing_and_clearing_folder_text_preserves_automatic_fallback() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut path = None;
    let mut picker = FolderPicker::new();
    let mut status = String::new();
    let mut draw = |path: &mut Option<PathBuf>, events: Vec<egui::Event>| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(640.0, 480.0),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    directory_input(
                        ui,
                        path,
                        std::path::Path::new("/automatic"),
                        &mut picker,
                        FolderTarget {
                            generation: 0,
                            kind: FolderKind::Disk,
                        },
                        &mut status,
                    );
                });
            },
        )
    };
    draw(&mut path, vec![]);
    let output = draw(&mut path, vec![]);
    let pos = texts(&output)
        .iter()
        .find(|(text, _)| text == "/automatic")
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        draw(
            &mut path,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    let select_all = || egui::Event::Key {
        key: egui::Key::A,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers {
            ctrl: true,
            command: true,
            ..Default::default()
        },
    };
    draw(
        &mut path,
        vec![select_all(), egui::Event::Text("/chosen".into())],
    );
    assert_eq!(path, Some(PathBuf::from("/chosen")));

    draw(
        &mut path,
        vec![
            select_all(),
            egui::Event::Key {
                key: egui::Key::Backspace,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            },
        ],
    );
    assert!(path.is_none());
    let output = draw(&mut path, vec![]);
    assert!(texts(&output).iter().any(|(text, _)| text == "/automatic"));
    assert!(path.is_none());
}

#[test]
fn snapshot_decision_blocks_global_shortcuts_without_editor_focus() {
    let mut app = app();
    app.selected = Some("vm".into());
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.vm_snapshot_trees.insert(
        "vm".into(),
        antinomie_monitor_core::VmSnapshotTree {
            vm_id: "vm".into(),
            capabilities: antinomie_monitor_core::VmSnapshotCapabilities {
                can_create_disk: true,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    app.vm_snapshots.bind("vm", "Test VM");
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    click_label(&mut app, &ctx, size, "New snapshot…");
    assert!(app.vm_snapshots.decision_open());
    ctx.memory_mut(|memory| {
        if let Some(id) = memory.focused() {
            memory.surrender_focus(id);
        }
    });
    let _ = ctx.run(
        egui::RawInput {
            events: vec![egui::Event::Key {
                key: keys::RUN_PROGRAM.logical_key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: keys::RUN_PROGRAM.modifiers,
            }],
            modifiers: keys::RUN_PROGRAM.modifiers,
            ..Default::default()
        },
        |ctx| app.shortcuts(ctx),
    );
    assert!(!app.launch_open);
    app.vm_snapshots.close();
    let _ = ctx.run(
        egui::RawInput {
            events: vec![egui::Event::Key {
                key: keys::RUN_PROGRAM.logical_key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: keys::RUN_PROGRAM.modifiers,
            }],
            modifiers: keys::RUN_PROGRAM.modifiers,
            ..Default::default()
        },
        |ctx| app.shortcuts(ctx),
    );
    assert!(app.launch_open);
}

#[test]
fn existing_vm_recording_default_uses_registered_disk_location() {
    let mut app = app();
    app.draft.id = "legacy".into();
    app.snapshot.vms.push(app.draft.clone());
    app.snapshot
        .vm_locations
        .push(antinomie_monitor_core::VmLocations {
            vm_id: "legacy".into(),
            disk_directory: "/legacy/vms/legacy".into(),
            recording_directory: "/legacy/vms/legacy".into(),
            recording_directories: vec!["/legacy/vms/legacy".into()],
        });
    app.config_open = true;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    assert_eq!(
        texts(&output)
            .iter()
            .filter(|(text, _)| text == "/legacy/vms")
            .count(),
        2
    );
    assert!(app.draft.disk_root.is_none());
    assert!(app.draft.recording_root.is_none());
}

#[test]
fn running_vm_creation_error_remains_visible_outside_disabled_form() {
    let mut app = app();
    app.new_image();
    app.snapshot.active_vm = Some("running".into());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text == "Stop the running VM before creating another VM"));
}

#[test]
fn debian_credentials_are_transient_and_creation_uses_validated_api() {
    let mut app = app();
    app.snapshot
        .bases
        .push(antinomie_monitor_core::BaseSummary {
            id: "debian".into(),
            label: "Debian 13 (Xfce)".into(),
            directory: "/bases/debian".into(),
            min_ram_mib: 2048,
            min_disk_gib: 8,
            fixed_display: true,
            size_bytes: 0,
            revision: Some(APP_REVISION),
            min_app_version: None,
            built_with: None,
            stealth_support: Vec::new(),
            guest: Some(antinomie_monitor_core::GuestProfile {
                id: "debian-xfce".into(),
                label: "Debian 13 (Xfce)".into(),
                min_ram_mib: 2048,
                min_disk_gib: 8,
                requires_credentials: true,
                graphical: true,
            }),
        });
    app.new_image();
    app.draft.base_identity = Some("debian".into());
    app.draft.launch.resolution = DisplayResolution::R1600x900;
    assert!(app.create_vm().is_err());
    app.credentials.password = "test-password-only".into();
    app.credentials.confirmation = "wrong-password".into();
    assert!(app.create_vm().is_err());
    app.credentials.confirmation = app.credentials.password.clone();
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..4 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let pos = texts(&output)
        .iter()
        .find(|(text, _)| text == "Create VM")
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events: vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
    assert!(!app.create_open);
    assert!(app
        .submitted
        .iter()
        .any(|command| matches!(command, Command::CreateWithCredentials { vm, .. } if vm.launch.resolution == DisplayResolution::R1600x900)));
    assert!(app.credentials.password.is_empty());
    assert!(app.credentials.confirmation.is_empty());
    assert!(!format!("{:?}", app.submitted).contains("test-password-only"));
    assert!(!serde_json::to_string(&app.settings)
        .unwrap()
        .contains("password"));
    app.credentials.password = "discard-on-new-vm".into();
    app.new_image();
    assert!(app.credentials.password.is_empty());
}

#[test]
fn debian_new_vm_dialog_fits_large_text_and_enforces_profile_minima() {
    let mut app = app();
    app.snapshot
        .bases
        .push(antinomie_monitor_core::BaseSummary {
            id: "debian".into(),
            label: "Debian 13 (Xfce)".into(),
            directory: "/bases/debian".into(),
            min_ram_mib: 2048,
            min_disk_gib: 8,
            fixed_display: true,
            size_bytes: 0,
            revision: Some(APP_REVISION),
            min_app_version: None,
            built_with: None,
            stealth_support: Vec::new(),
            guest: Some(antinomie_monitor_core::GuestProfile {
                id: "debian-xfce".into(),
                label: "Debian 13 (Xfce)".into(),
                min_ram_mib: 2048,
                min_disk_gib: 8,
                requires_credentials: true,
                graphical: true,
            }),
        });
    app.new_image();
    app.draft.ram_mib = 256;
    app.draft.disk_gib = 1;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    app.settings.font_size = 24.0;
    theme::text_size(&ctx, 24.0);
    for _ in 0..4 {
        render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
    }
    let output = render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
    assert_eq!(app.draft.ram_mib, 2048);
    assert_eq!(app.draft.disk_gib, 8);
    let visible = texts(&output);
    for label in [
        "Resolution",
        "Fullscreen",
        "Fit to window",
        "Acceleration",
        "CPU model",
        "Username",
        "Password",
        "Confirm password",
        "Create VM",
    ] {
        assert!(
            visible.iter().any(|(text, _)| text == label),
            "missing or clipped {label}"
        );
    }
    let fit = visible
        .iter()
        .find(|(text, _)| text == "Fit to window")
        .unwrap()
        .1;
    let acceleration = visible
        .iter()
        .find(|(text, _)| text == "Acceleration")
        .unwrap()
        .1;
    assert!(
        fit.bottom() < acceleration.top(),
        "fit checkbox overlaps acceleration row"
    );
    assert!(
        visible
            .iter()
            .any(|(text, _)| text.contains("password must be 8..128")),
        "visible dialog text: {visible:?}"
    );
}

#[test]
#[ignore = "requires X11 native rendering; exits after 20 seconds"]
fn native_debian_setup_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
        }
    }
    eframe::run_native(
        "Antinomie Debian Setup QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 900.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(|cc| {
            theme::install(&cc.egui_ctx);
            let mut app = app();
            app.snapshot
                .bases
                .push(antinomie_monitor_core::BaseSummary {
                    id: "debian".into(),
                    label: "Debian 13 (Xfce)".into(),
                    directory: "/bases/debian".into(),
                    min_ram_mib: 2048,
                    min_disk_gib: 8,
                    fixed_display: true,
                    size_bytes: 0,
                    revision: Some(APP_REVISION),
                    min_app_version: None,
                    built_with: None,
                    stealth_support: Vec::new(),
                    guest: Some(antinomie_monitor_core::GuestProfile {
                        id: "debian-xfce".into(),
                        label: "Debian 13 (Xfce)".into(),
                        min_ram_mib: 2048,
                        min_disk_gib: 8,
                        requires_credentials: true,
                        graphical: true,
                    }),
                });
            app.new_image();
            app.settings.font_size = 24.0;
            theme::text_size(&cc.egui_ctx, 24.0);
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(20),
            }))
        }),
    )
    .unwrap();
}
