// SPDX-License-Identifier: MIT
//! Dropping a host file onto the main window: overlay, Upload form and refusals.
use super::*;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 900.0);

fn input(hovered: Vec<Option<PathBuf>>, dropped: Vec<Option<PathBuf>>) -> egui::RawInput {
    egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
        hovered_files: hovered
            .into_iter()
            .map(|path| egui::HoveredFile {
                path,
                ..Default::default()
            })
            .collect(),
        dropped_files: dropped
            .into_iter()
            .map(|path| egui::DroppedFile {
                path,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn ready_context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

/// A running VM without the Upload dialog open, as before any drop.
fn running_app() -> MonitorApp {
    let mut app = upload_app();
    app.upload_open = false;
    app.source.clear();
    app.destination = "/tmp/program".into();
    app
}

fn drop_files(app: &mut MonitorApp, files: Vec<Option<PathBuf>>) {
    let ctx = ready_context();
    draw_input(app, &ctx, input(Vec::new(), files));
}

fn has_text(output: &egui::FullOutput, wanted: &str) -> bool {
    texts(output).iter().any(|(text, _)| text == wanted)
}

#[test]
fn hovering_a_file_shows_the_target_vm_and_nothing_otherwise() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("sample.bin");
    std::fs::write(&path, b"data").unwrap();
    let mut app = running_app();
    let ctx = ready_context();
    let idle = draw_input(&mut app, &ctx, input(Vec::new(), Vec::new()));
    assert!(!has_text(
        &idle,
        "Drop a file to upload it to Active fixture"
    ));
    for light in [false, true] {
        theme::apply(&ctx, light);
        let hover = draw_input(&mut app, &ctx, input(vec![Some(path.clone())], Vec::new()));
        assert!(has_text(
            &hover,
            "Drop a file to upload it to Active fixture"
        ));
        // Hovering never changes the form.
        assert!(!app.upload_open && app.source.is_empty());
    }
    theme::apply(&ctx, false);
}

#[test]
fn hover_explains_a_missing_vm_several_files_and_a_pending_upload() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("sample.bin");
    std::fs::write(&path, b"data").unwrap();
    let ctx = ready_context();
    let mut stopped = running_app();
    stopped.snapshot.state = VmState::Stopped;
    let output = draw_input(
        &mut stopped,
        &ctx,
        input(vec![Some(path.clone())], Vec::new()),
    );
    assert!(has_text(&output, "A running VM is required to upload"));
    let mut app = running_app();
    let output = draw_input(
        &mut app,
        &ctx,
        input(vec![Some(path.clone()), Some(path.clone())], Vec::new()),
    );
    assert!(has_text(&output, "Drop one file at a time"));
    let output = draw_input(
        &mut app,
        &ctx,
        input(vec![Some(fixture.0.clone())], Vec::new()),
    );
    assert!(has_text(&output, "Folders cannot be uploaded"));
    app.overwrite = false;
    app.request_upload(false);
    assert!(app.pending_upload.is_some());
    let output = draw_input(&mut app, &ctx, input(vec![Some(path)], Vec::new()));
    assert!(has_text(&output, "An upload is already in progress"));
}

#[test]
fn hover_without_a_path_still_offers_the_drop() {
    let mut app = running_app();
    let ctx = ready_context();
    let output = draw_input(&mut app, &ctx, input(vec![None], Vec::new()));
    assert!(has_text(
        &output,
        "Drop a file to upload it to Active fixture"
    ));
}

#[test]
fn dropping_one_file_opens_upload_filled_in_without_submitting() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join(" dropped sample.bin ");
    std::fs::write(&path, b"not executed").unwrap();
    let mut app = running_app();
    // The production defaults of the Upload dialog; the fixture turns them off.
    (app.executable, app.overwrite) = (true, true);
    drop_files(&mut app, vec![Some(path.clone())]);
    assert!(app.upload_open);
    assert_eq!(app.source, path.to_str().unwrap());
    assert_eq!(app.destination, "/tmp/ dropped sample.bin ");
    assert_eq!(app.upload_browser.selected.as_ref(), Some(&path));
    assert!(app.executable && app.overwrite);
    assert!(app.submitted.is_empty() && app.pending_upload.is_none());
    assert!(app.confirm.is_none());
    // The dialog is shown and only the user's Upload press asks to send.
    let ctx = ready_context();
    click_label(&mut app, &ctx, SIZE, "Upload");
    assert!(matches!(app.confirm, Some(Confirm::Upload(_))));
    assert!(app.submitted.is_empty());
}

#[test]
fn dropping_a_file_keeps_an_existing_guest_directory() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("tool");
    std::fs::write(&path, b"x").unwrap();
    let mut app = running_app();
    app.destination = "/opt/bin/old".into();
    drop_files(&mut app, vec![Some(path)]);
    assert_eq!(app.destination, "/opt/bin/tool");
}

#[test]
fn dropping_several_files_or_a_folder_leaves_the_form_alone_and_says_why() {
    let fixture = upload_browser::tests::Fixture::new();
    let first = fixture.0.join("one");
    let second = fixture.0.join("two");
    std::fs::write(&first, b"1").unwrap();
    std::fs::write(&second, b"2").unwrap();
    let folder = fixture.0.join("folder");
    std::fs::create_dir(&folder).unwrap();
    for (files, expected) in [
        (
            vec![Some(first.clone()), Some(second)],
            "one file at a time",
        ),
        (
            vec![Some(first.clone()), Some(folder.clone())],
            "one file at a time",
        ),
        (vec![Some(folder)], "Folders cannot be uploaded"),
        (vec![None], "no host file path"),
        (vec![Some(fixture.0.join("missing"))], "regular files"),
    ] {
        let mut app = running_app();
        let (source, destination) = (app.source.clone(), app.destination.clone());
        drop_files(&mut app, files);
        assert!(!app.upload_open, "{expected}");
        assert!(app.status.contains(expected), "{expected}: {}", app.status);
        assert_eq!(
            (app.source.clone(), app.destination.clone()),
            (source, destination)
        );
        assert!(app.upload_browser.selected.is_none() && app.submitted.is_empty());
    }
}

#[test]
fn dropping_while_an_upload_is_pending_keeps_its_form() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("another");
    std::fs::write(&path, b"x").unwrap();
    let mut app = upload_app();
    app.overwrite = false;
    app.request_upload(false);
    assert!(app.pending_upload.is_some());
    let (source, destination) = (app.source.clone(), app.destination.clone());
    drop_files(&mut app, vec![Some(path)]);
    assert_eq!(
        (app.source.clone(), app.destination.clone()),
        (source, destination)
    );
    assert!(app.status.contains("already in progress"), "{}", app.status);
    assert_eq!(app.submitted.len(), 1);
}

#[test]
fn dropping_without_a_running_vm_only_shows_a_notice() {
    let fixture = upload_browser::tests::Fixture::new();
    let path = fixture.0.join("sample");
    std::fs::write(&path, b"x").unwrap();
    let mut app = running_app();
    app.snapshot.state = VmState::Stopped;
    drop_files(&mut app, vec![Some(path.clone())]);
    assert!(!app.upload_open && app.source.is_empty());
    assert!(
        app.status.contains("running VM is required"),
        "{}",
        app.status
    );
    let mut closing = running_app();
    closing.closing = true;
    drop_files(&mut closing, vec![Some(path)]);
    assert!(!closing.upload_open);
}
