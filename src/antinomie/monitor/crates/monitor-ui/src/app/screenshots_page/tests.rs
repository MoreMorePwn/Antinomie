// SPDX-License-Identifier: GPL-3.0-only
//! Opening a picture over the current page, and the run link of a series.
use super::*;
use crate::app::tests::{app, texts};

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

fn shot(path: &str, run_id: Option<&str>) -> Shot {
    Shot {
        path: PathBuf::from(path),
        vm_id: "vm".into(),
        vm_name: "Analysis".into(),
        ms: 1_792_000_001_400,
        run: Some("timed screenshots of run dropper.sh".into()),
        run_id: run_id.map(str::to_owned),
        rel_ms: Some(1_400),
    }
}

fn frame(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<(String, egui::Rect)> {
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            ..Default::default()
        },
        |root| app.screenshot_windows(&root.ctx().clone()),
    );
    texts(&output)
}

#[test]
fn a_picture_opened_from_triage_shows_in_its_viewer_without_opening_the_page() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut app = app();
    app.screenshots_page
        .shots
        .push(shot("/nonexistent/t+000001.4s.png", Some("run-1")));
    app.screenshots_page.loaded = true;
    app.open_screenshot_path(&ctx, PathBuf::from("/nonexistent/t+000001.4s.png"));
    assert!(
        app.take_library_pages().is_empty(),
        "the Screenshots page is not opened"
    );
    frame(&mut app, &ctx);
    let shown = frame(&mut app, &ctx);
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "Screenshot: t+000001.4s.png"),
        "{shown:?}"
    );
}

#[test]
fn a_picture_before_the_folders_are_read_opens_once_they_are_and_not_when_missing() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut app = app();
    app.open_screenshot_path(&ctx, PathBuf::from("/nonexistent/t+000001.4s.png"));
    assert!(app.take_library_pages().is_empty());
    assert!(app.screenshots_page.open_when_loaded.is_some());
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.screenshots_page.open_when_loaded.is_some() && std::time::Instant::now() < until {
        frame(&mut app, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        app.screenshots_page.open_when_loaded.is_none(),
        "the scan finished"
    );
    assert!(
        app.screenshots_page.viewer.is_none(),
        "a missing picture is not opened"
    );
    assert!(app.take_library_pages().is_empty());
}

#[test]
fn a_series_is_listed_with_the_id_of_its_run_and_a_plain_picture_with_the_run_before_it() {
    let folder = std::env::temp_dir().join(format!("antinomie-shots-{}", std::process::id()));
    let run_dir = folder.join("run");
    let vm_dir = folder.join("vm");
    std::fs::create_dir_all(run_dir.join("screenshots")).unwrap();
    std::fs::create_dir_all(vm_dir.join("screenshots")).unwrap();
    std::fs::write(
        run_dir
            .join("screenshots")
            .join(antinomie_monitor_core::timed_shots::file_name(5_000)),
        b"x",
    )
    .unwrap();
    std::fs::write(
        vm_dir
            .join("screenshots")
            .join("vm-screen-20300101-000000.png"),
        b"x",
    )
    .unwrap();
    let started = 1_000;
    let shots = scan(
        vec![Target {
            vm_id: "vm".into(),
            vm_name: "Analysis".into(),
            folders: vec![vm_dir.clone()],
        }],
        vec![("vm".into(), started, "dropper.sh".into(), "run-7".into())],
        vec![TimedRun {
            id: "run-7".into(),
            vm_id: "vm".into(),
            vm_name: "Analysis".into(),
            label: "dropper.sh".into(),
            started_ms: started,
            directory: run_dir.clone(),
        }],
    );
    let _ = std::fs::remove_dir_all(&folder);
    assert_eq!(shots.len(), 2, "{}", shots.len());
    for shot in &shots {
        assert_eq!(shot.run_id.as_deref(), Some("run-7"));
    }
    assert!(shots.iter().any(|s| s.rel_ms.is_some()));
}

#[test]
fn a_picture_with_no_run_before_it_has_no_run_link() {
    let folder = std::env::temp_dir().join(format!("antinomie-shots-none-{}", std::process::id()));
    std::fs::create_dir_all(folder.join("screenshots")).unwrap();
    std::fs::write(
        folder
            .join("screenshots")
            .join("vm-screen-20300101-000000.png"),
        b"x",
    )
    .unwrap();
    let shots = scan(
        vec![Target {
            vm_id: "vm".into(),
            vm_name: "Analysis".into(),
            folders: vec![folder.clone()],
        }],
        Vec::new(),
        Vec::new(),
    );
    let _ = std::fs::remove_dir_all(&folder);
    assert_eq!(shots.len(), 1);
    assert_eq!(shots[0].run_id, None);
    assert_eq!(shots[0].run, None);
}

#[test]
fn the_run_heading_of_a_group_is_a_link_that_opens_the_run() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut page = ScreenshotsPage::default();
    page.shots.push(shot("/nonexistent/a.png", Some("run-1")));
    page.loaded = true;
    let run = |page: &mut ScreenshotsPage, events: Vec<egui::Event>| {
        let mut act = None;
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                events,
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    act = act.take().or(page.gallery(ui));
                });
            },
        );
        (act, texts(&output))
    };
    for _ in 0..3 {
        run(&mut page, vec![]);
    }
    let (_, shown) = run(&mut page, vec![]);
    let heading = shown
        .iter()
        .find(|(text, _)| text == "timed screenshots of run dropper.sh")
        .unwrap_or_else(|| panic!("{shown:?}"))
        .1;
    let pos = heading.center();
    let mut found = None;
    for pressed in [true, false] {
        let (act, _) = run(
            &mut page,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                },
            ],
        );
        found = found.or(act);
    }
    assert!(matches!(found, Some(Act::OpenRun(id)) if id == "run-1"));
}
