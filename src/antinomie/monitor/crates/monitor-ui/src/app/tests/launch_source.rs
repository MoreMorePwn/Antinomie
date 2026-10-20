// SPDX-License-Identifier: MIT
//! Run program: the Source choice (a guest path or an uploaded host file),
//! the arguments placeholder and the window's fit.
use super::*;
use crate::analysis::LaunchSource;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn settle(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2) -> egui::FullOutput {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    render(app, ctx, size)
}

fn click(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2, pos: egui::Pos2) {
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
}

fn press_run(app: &mut MonitorApp, ctx: &egui::Context) {
    settle(app, ctx, SIZE);
    let run = app.launch_action_rects.expect("run button").0.center();
    click(app, ctx, SIZE, run);
}

fn shown(output: &egui::FullOutput) -> Vec<String> {
    texts(output).into_iter().map(|(text, _)| text).collect()
}

#[test]
fn guest_path_is_the_default_source_and_run_sends_that_executable() {
    let ctx = context();
    let mut app = analysis_setup_fixture();
    app.exec.path = "/opt/in-guest/sample".into();
    app.source = "/home/me/ignored".into();
    assert_eq!(app.launch_source, LaunchSource::Guest);
    press_run(&mut app, &ctx);
    assert!(
        matches!(app.submitted.last(), Some(Command::Execute(request)) if request.path == "/opt/in-guest/sample"),
        "{:?}",
        app.submitted
    );
    assert!(!app
        .submitted
        .iter()
        .any(|command| matches!(command, Command::Upload { .. })));
}

#[test]
fn upload_source_uploads_the_host_file_as_executable_and_then_waits_for_run() {
    let ctx = context();
    let mut app = analysis_setup_fixture();
    app.snapshot.boot_id = Some("boot".into());
    app.launch_source = LaunchSource::Upload;
    app.source = "/home/me/dropper.elf".into();
    app.destination = "/tmp/dropper.elf".into();
    app.overwrite = false;
    app.args = "-v".into();
    press_run(&mut app, &ctx);
    assert!(
        matches!(app.submitted.last(), Some(Command::Upload {
            source, destination, executable: true, overwrite: false
        }) if source == std::path::Path::new("/home/me/dropper.elf")
            && destination == "/tmp/dropper.elf"),
        "{:?}",
        app.submitted
    );
    assert!(
        !app.submitted
            .iter()
            .any(|command| matches!(command, Command::Execute(_))),
        "uploading never runs the program by itself"
    );
    assert!(app.launch_open, "the dialog waits for the upload");
    let id = app.pending_upload.as_ref().expect("pending upload").id;
    app.complete_upload(id, true);
    // The file is in the guest: the dialog continues from its path and the
    // settings made so far.
    assert_eq!(app.launch_source, LaunchSource::Guest);
    assert_eq!(app.exec.path, "/tmp/dropper.elf");
    assert_eq!(app.args, "-v");
    assert!(app.launch_open);
    press_run(&mut app, &ctx);
    assert!(
        matches!(app.submitted.last(), Some(Command::Execute(request))
            if request.path == "/tmp/dropper.elf" && request.args == ["-v"]),
        "{:?}",
        app.submitted
    );
}

#[test]
fn the_source_row_switches_between_the_two_choices() {
    let ctx = context();
    let mut app = analysis_setup_fixture();
    let visible = shown(&settle(&mut app, &ctx, SIZE));
    for label in ["Source", "Guest path", "Upload", "Executable"] {
        assert!(
            visible.iter().any(|text| text == label),
            "{label}: {visible:?}"
        );
    }
    assert!(!visible.iter().any(|text| text == "Host file"));
    assert!(!visible.iter().any(|text| text == "Profile"));
    let output = settle(&mut app, &ctx, SIZE);
    let upload = texts(&output)
        .into_iter()
        .find(|(text, _)| text == "Upload")
        .unwrap()
        .1
        .center();
    click(&mut app, &ctx, SIZE, upload);
    assert_eq!(app.launch_source, LaunchSource::Upload);
    let visible = shown(&settle(&mut app, &ctx, SIZE));
    for label in ["Host file", "Choose…"] {
        assert!(
            visible.iter().any(|text| text == label),
            "{label}: {visible:?}"
        );
    }
    assert!(!visible.iter().any(|text| text == "Executable"));
}

#[test]
fn the_chosen_host_file_fills_the_upload_source_while_the_run_dialog_is_open() {
    let mut app = analysis_setup_fixture();
    app.launch_source = LaunchSource::Upload;
    let dir = std::env::temp_dir().join(format!("antinomie-launch-source-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sample.bin");
    std::fs::write(&file, b"x").unwrap();
    let generation = app.upload_browser.generation;
    app.accept_upload_file(generation, file.clone());
    assert_eq!(app.source, file.to_string_lossy());
    assert!(app.destination.ends_with("/sample.bin"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_arguments_placeholder_shows_the_rule_then_an_example_on_each_line() {
    let ctx = context();
    let mut app = analysis_setup_fixture();
    app.args.clear();
    let visible = texts(&settle(&mut app, &ctx, SIZE));
    let placeholder = crate::analysis::ARGUMENT_PLACEHOLDER;
    assert!(
        visible.iter().any(|(text, _)| text == placeholder),
        "placeholder missing: {visible:?}"
    );
    let lines: Vec<&str> = placeholder.lines().collect();
    assert_eq!(lines[0], "One argument per line", "the rule comes first");
    assert_eq!(&lines[1..], ["--config", "/tmp/sample.conf", "-v"]);
    // Typing replaces the placeholder.
    app.args = "--real".into();
    let visible = shown(&settle(&mut app, &ctx, SIZE));
    assert!(!visible.iter().any(|text| text == placeholder));
}

#[test]
fn the_run_window_fits_a_short_screen_and_keeps_its_footer() {
    for size in [egui::vec2(1280.0, 820.0), egui::vec2(1000.0, 700.0)] {
        for source in [LaunchSource::Guest, LaunchSource::Upload] {
            let ctx = context();
            let mut app = analysis_setup_fixture();
            app.launch_source = source;
            let visible = texts(&settle(&mut app, &ctx, size));
            let (run, analyze) = app.launch_action_rects.expect("buttons");
            assert!(
                run.bottom() <= size.y && analyze.bottom() <= size.y && run.right() <= size.x,
                "{source:?} at {size:?}: {run:?}"
            );
            let cancel = visible
                .iter()
                .find(|(text, _)| text == "Cancel")
                .expect("Cancel")
                .1;
            assert!(cancel.bottom() <= size.y);
            for (t, r) in &visible {
                if r.right() > size.x - 10.0 {
                    eprintln!("WIDE {t:?} {r:?}");
                }
            }
            let window = ctx
                .memory(|memory| memory.area_rect(Dialog::Launch.window_id()))
                .expect("window");
            assert!(
                window.bottom() <= size.y && window.right() <= size.x,
                "{source:?} {size:?} {window:?}"
            );
        }
    }
}
