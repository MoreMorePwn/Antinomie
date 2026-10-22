// SPDX-License-Identifier: GPL-3.0-only
//! Upload dialog, file explorer and the upload-then-run handoff.
use super::*;

#[test]
fn upload_and_run_waits_for_matching_success_without_executing() {
    let mut app = upload_app();
    app.args = "--keep-this-setting".into();
    app.request_upload(true);
    let id = app.pending_upload.as_ref().unwrap().id;
    assert!(matches!(&app.submitted[0], Command::Upload {
        destination, executable: true, overwrite: false, ..
    } if destination == "/tmp/guest file"));
    assert!(!app.launch_open);
    app.complete_upload(id + 1, true);
    assert!(app.pending_upload.is_some() && !app.launch_open);
    // A later edit cannot change the destination of the queued transfer.
    app.destination = "/tmp/another".into();
    app.complete_upload(id, true);
    assert!(app.launch_open && !app.upload_open);
    assert_eq!(app.exec.path, "/tmp/guest file");
    assert_eq!(app.args, "--keep-this-setting");
    assert!(!app
        .submitted
        .iter()
        .any(|command| matches!(command, Command::Execute(_))));
}

#[test]
fn upload_failure_plain_upload_and_closed_handoffs_never_open_run() {
    for (run_after, success, close) in [
        (true, false, false),
        (false, true, false),
        (true, true, true),
    ] {
        let mut app = upload_app();
        app.request_upload(run_after);
        let id = app.pending_upload.as_ref().unwrap().id;
        if close {
            app.close_dialog(Dialog::Upload);
        }
        app.complete_upload(id, success);
        assert!(app.pending_upload.is_none() && !app.launch_open);
        assert_eq!(app.submitted.len(), 1);
    }
}

#[test]
fn upload_handoff_rejects_changed_vm_boot_recording_selection_and_shutdown() {
    for change in 0..6 {
        let mut app = upload_app();
        app.request_upload(true);
        let id = app.pending_upload.as_ref().unwrap().id;
        match change {
            0 => app.snapshot.active_vm = Some("other".into()),
            1 => app.snapshot.boot_id = Some("restored".into()),
            2 => app.snapshot.capture_dir = Some(PathBuf::from("/tmp/restored")),
            3 => app.selected = Some("other".into()),
            4 => app.snapshot.state = VmState::Stopping,
            _ => app.closing = true,
        }
        app.complete_upload(id, true);
        assert!(!app.launch_open, "change {change}");
        assert!(app.pending_upload.is_none());
    }
}

#[test]
fn upload_overwrite_confirmation_freezes_action_and_session() {
    for change_session in [false, true] {
        let mut app = upload_app();
        app.overwrite = true;
        app.request_upload(true);
        assert!(app.submitted.is_empty());
        let Some(Confirm::Upload(intent)) = app.confirm.take() else {
            panic!("confirmation")
        };
        app.destination = "/tmp/edited".into();
        if change_session {
            app.snapshot.capture_dir = Some(PathBuf::from("/tmp/restored"));
        }
        app.submit_upload(intent, true);
        if change_session {
            assert!(app.submitted.is_empty() && app.pending_upload.is_none());
        } else {
            assert!(matches!(&app.submitted[0], Command::Upload {
                destination, overwrite: true, executable: true, ..
            } if destination == "/tmp/guest file"));
            let id = app.pending_upload.as_ref().unwrap().id;
            app.complete_upload(id, true);
            assert!(app.launch_open);
        }
    }
}

#[test]
fn upload_rejects_duplicates_and_stopped_guests() {
    let mut app = upload_app();
    app.request_upload(true);
    app.request_upload(true);
    assert_eq!(app.submitted.len(), 1);
    let mut stopped = upload_app();
    stopped.snapshot.state = VmState::Stopped;
    stopped.request_upload(true);
    assert!(stopped.submitted.is_empty() && stopped.pending_upload.is_none());
}

#[test]
fn upload_preserves_exact_selected_host_path() {
    let mut app = upload_app();
    let path = PathBuf::from("/tmp/ folder / file with trailing space ");
    app.upload_browser.selected = Some(path.clone());
    app.source = path.to_string_lossy().into_owned();
    app.request_upload(false);
    assert!(matches!(&app.submitted[0], Command::Upload { source, .. } if source == &path));
}

#[test]
fn upload_buttons_pointer_clicks_chain_to_run_at_normal_and_large_fonts() {
    for (size, font_size) in [
        (egui::vec2(1280.0, 900.0), 16.0),
        (egui::vec2(800.0, 700.0), 24.0),
    ] {
        let mut app = upload_app();
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, font_size);
        click_label(&mut app, &ctx, size, "Upload and Run");
        let id = app
            .pending_upload
            .as_ref()
            .expect("button submits upload")
            .id;
        app.complete_upload(id, true);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let visible = texts(&render(&mut app, &ctx, size));
        assert!(visible.iter().any(|(text, _)| text == "Run program"));
        assert!(!visible.iter().any(|(text, _)| text == "Upload file"));
        assert_eq!(app.exec.path, "/tmp/guest file");
    }
}

#[test]
fn upload_file_picker_keeps_exact_path_and_rejects_stale_or_pending_choices() {
    let fixture = upload_browser::tests::Fixture::new();
    let directory = fixture.0.join("nested samples");
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join(" sample script.sh ");
    std::fs::write(&path, b"#!/bin/sh\necho test\n").unwrap();
    let other = fixture.0.join("other");
    std::fs::write(&other, b"other").unwrap();
    let mut app = upload_app();
    let generation = app.upload_browser.generation;
    let original = app.source.clone();
    app.accept_upload_file(generation + 1, path.clone());
    assert_eq!(app.source, original);
    app.accept_upload_file(generation, directory);
    assert_eq!(app.source, original);
    app.accept_upload_file(generation, path.clone());
    assert_eq!(app.upload_browser.selected.as_ref(), Some(&path));
    assert_eq!(app.source, path.to_str().unwrap());
    assert_eq!(app.destination, "/tmp/ sample script.sh ");
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let visible = texts(&render(&mut app, &ctx, size));
    assert!(visible.iter().any(|(text, _)| text == "Choose file…"));
    assert!(!visible.iter().any(|(text, _)| text == "nested samples"));
    assert!(!visible
        .iter()
        .any(|(text, _)| text == "Choose host folder…"));
    click_label(&mut app, &ctx, size, "Upload and Run");
    assert!(matches!(&app.submitted[0], Command::Upload { source, .. } if source == &path));
    app.accept_upload_file(generation, other.clone());
    assert_eq!(app.upload_browser.selected.as_ref(), Some(&path));
    app.complete_upload(app.pending_upload.as_ref().unwrap().id, false);
    app.close_upload();
    app.accept_upload_file(generation, other.clone());
    assert_eq!(app.upload_browser.selected.as_ref(), Some(&path));
    app.open_upload();
    app.accept_upload_file(generation, other);
    assert_eq!(app.upload_browser.selected.as_ref(), Some(&path));
}

#[test]
fn explorer_persists_root_and_old_preferences_remain_compatible() {
    let old: Settings = serde_json::from_str("{}").unwrap();
    assert!(old.explorer_root.is_none() && !old.explorer_collapsed);
    let settings = Settings {
        explorer_root: Some(PathBuf::from("/tmp/host folder")),
        explorer_collapsed: true,
        ..Settings::default()
    };
    let loaded: Settings =
        serde_json::from_str(&serde_json::to_string(&settings).unwrap()).unwrap();
    assert_eq!(loaded.explorer_root, settings.explorer_root);
    assert!(loaded.explorer_collapsed);
}

#[test]
fn explorer_remains_below_the_library_with_folded_lists_and_large_fonts() {
    for (size, font_size) in [
        (egui::vec2(1280.0, 900.0), 16.0),
        (egui::vec2(800.0, 600.0), 24.0),
    ] {
        for library_folded in [false, true] {
            let mut app = app();
            app.settings.library_collapsed = library_folded;
            app.snapshot.bases = (0..12)
                .map(|index| test_base(&format!("base {index}"), true))
                .collect();
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font_size);
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            let visible = texts(&render(&mut app, &ctx, size));
            let rect = |name: &str| {
                visible
                    .iter()
                    .find(|(text, _)| text == name)
                    .unwrap_or_else(|| panic!("missing {name} at {size:?}: {visible:?}"))
                    .1
            };
            let last = if library_folded {
                "Library"
            } else {
                "Analysis tools"
            };
            assert!(rect("Explorer").top() > rect(last).bottom());
            assert!(rect("Choose folder…").bottom() < size.y);
            click_label(&mut app, &ctx, size, "Explorer");
            assert!(app.settings.explorer_collapsed);
        }
    }
}

#[test]
fn explorer_file_double_click_only_opens_upload_then_run_on_matching_success() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("sidebar-sample.sh");
    std::fs::write(&path, b"#!/bin/sh\necho explorer\n").unwrap();
    let mut app = upload_app();
    explorer_fixture(&mut app, &fixture.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    wait_for_label(&mut app, &ctx, size, "sidebar-sample.sh");
    click_label(&mut app, &ctx, size, "sidebar-sample.sh");
    assert!(app.submitted.is_empty());
    click_label(&mut app, &ctx, size, "sidebar-sample.sh");
    assert!(app.submitted.is_empty());
    assert!(app.upload_open && !app.launch_open);
    assert_eq!(app.source, path.to_str().unwrap());
    click_label(&mut app, &ctx, size, "Upload and Run");
    assert_eq!(app.submitted.len(), 1);
    assert!(matches!(&app.submitted[0], Command::Upload {
        source, destination, executable: true, ..
    } if source == &path && destination == "/tmp/sidebar-sample.sh"));
    let id = app.pending_upload.as_ref().unwrap().id;
    app.send_explorer_file(path);
    assert_eq!(app.submitted.len(), 1);
    app.complete_upload(id, true);
    assert!(app.launch_open && !app.upload_open);
    assert_eq!(app.exec.path, "/tmp/sidebar-sample.sh");
    assert!(!app
        .submitted
        .iter()
        .any(|command| matches!(command, Command::Execute(_))));
}

#[test]
fn explorer_file_context_menu_sends_and_stopped_guests_cannot_send() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("context-sample.sh");
    std::fs::write(&path, b"test").unwrap();
    let mut app = upload_app();
    explorer_fixture(&mut app, &fixture.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    wait_for_label(&mut app, &ctx, size, "context-sample.sh");
    secondary_click_label(&mut app, &ctx, size, "context-sample.sh");
    let visible = texts(&render(&mut app, &ctx, size));
    assert!(visible.iter().any(|(text, _)| text == "Open Directory"));
    click_label(&mut app, &ctx, size, "Send and Run");
    assert!(app.submitted.is_empty());
    assert!(app.upload_open && !app.launch_open);
    click_label(&mut app, &ctx, size, "Upload and Run");
    assert_eq!(app.submitted.len(), 1);
    app.complete_upload(app.pending_upload.as_ref().unwrap().id, false);
    assert!(!app.launch_open);
    app.snapshot.state = VmState::Stopped;
    app.send_explorer_file(path);
    assert_eq!(app.submitted.len(), 1);
}

#[test]
fn explorer_selection_does_not_change_upload_file_selection() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("shared-file.txt");
    std::fs::write(&path, b"test").unwrap();
    let mut app = upload_app();
    explorer_fixture(&mut app, &fixture.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    wait_for_label(&mut app, &ctx, size, "shared-file.txt");
    click_label(&mut app, &ctx, size, "shared-file.txt");
    assert_eq!(app.explorer_browser.selected, Some(path));
    assert!(app.upload_browser.selected.is_none());
}

#[test]
fn opening_upload_hides_an_existing_run_dialog_and_never_submits() {
    let mut app = upload_app();
    app.upload_open = false;
    app.launch_open = true;
    app.open_upload();
    assert!(app.upload_open && !app.launch_open);
    assert!(app.submitted.is_empty());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let visible = texts(&render(&mut app, &ctx, size));
    assert!(visible.iter().any(|(text, _)| text == "Upload file"));
    assert!(!visible.iter().any(|(text, _)| text == "Run program"));
}
