// SPDX-License-Identifier: MIT
//! Right-click Delete: the confirmation, the backend command and what the app
//! forgets once the backend has deleted the files.
use super::*;
use crate::evidence_delete::{Deletion, Kind};

fn capture_deletion(test: &str) -> Deletion {
    let dir = std::env::temp_dir().join(format!("ant-app-delete-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("cap.pcap");
    std::fs::write(&file, vec![0u8; 2048]).unwrap();
    Deletion::network(&file, "Whole boot of today")
}

fn draw(app: &mut MonitorApp, ctx: &egui::Context, events: Vec<egui::Event>) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 800.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| app.draw(ctx),
    )
}

fn centre(output: &egui::FullOutput, label: &str) -> egui::Pos2 {
    texts(output)
        .into_iter()
        .find(|(text, _)| text == label)
        .unwrap_or_else(|| panic!("{label} is shown"))
        .1
        .center()
}

fn click(app: &mut MonitorApp, ctx: &egui::Context, at: egui::Pos2) {
    for pressed in [None, Some(true), Some(false)] {
        let event = match pressed {
            None => egui::Event::PointerMoved(at),
            Some(pressed) => egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            },
        };
        draw(app, ctx, vec![event]);
    }
}

#[test]
fn the_confirmation_names_the_item_and_its_size_and_says_it_cannot_be_undone() {
    let mut app = app();
    let deletion = capture_deletion("confirmation");
    app.ask_delete_evidence(deletion.clone());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = draw(&mut app, &ctx, vec![]);
    }
    let shown: String = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(shown.contains("Delete network capture"));
    assert!(shown.contains("Whole boot of today"));
    assert!(shown.contains("2048 bytes (2.0 KB)"));
    assert!(shown.contains("can't be undone"));
    assert!(
        app.submitted.is_empty(),
        "nothing is sent before confirming"
    );
    std::fs::remove_dir_all(deletion.path().parent().unwrap()).unwrap();
}

#[test]
fn cancelling_sends_nothing_and_keeps_the_files() {
    let mut app = app();
    app.selected = Some("vm".into());
    let deletion = capture_deletion("cancel");
    app.ask_delete_evidence(deletion.clone());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = draw(&mut app, &ctx, vec![]);
    }
    let at = centre(&output, "Cancel");
    click(&mut app, &ctx, at);
    assert!(app.confirm.is_none());
    assert!(app.submitted.is_empty());
    assert!(deletion.path().exists());
    std::fs::remove_dir_all(deletion.path().parent().unwrap()).unwrap();
}

#[test]
fn confirming_sends_one_backend_command_and_the_ui_touches_no_file() {
    let mut app = app();
    app.selected = Some("vm".into());
    let deletion = capture_deletion("confirm");
    app.ask_delete_evidence(deletion.clone());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut output = egui::FullOutput::default();
    for _ in 0..3 {
        output = draw(&mut app, &ctx, vec![]);
    }
    let at = centre(&output, "Delete");
    click(&mut app, &ctx, at);
    assert!(app.confirm.is_none());
    let [Command::DeleteEvidence {
        vm_id,
        item,
        confirmed,
    }] = &app.submitted[..]
    else {
        panic!("one DeleteEvidence command: {:?}", app.submitted);
    };
    assert_eq!(vm_id, "vm");
    assert_eq!(*item, deletion.item);
    assert!(*confirmed);
    assert!(deletion.path().exists(), "the backend deletes, not the UI");
    assert_eq!(app.pending_deletions.len(), 1);
    std::fs::remove_dir_all(deletion.path().parent().unwrap()).unwrap();
}

#[test]
fn a_deleted_capture_is_forgotten_by_the_network_view() {
    let mut app = app();
    let deletion = capture_deletion("forget");
    let file = deletion.path().to_path_buf();
    app.network_view.open(Some(file.clone()));
    app.evidence_deleted(&deletion);
    assert!(app.network_view.loaded_path().is_none());
    // The answer of a failed deletion changes nothing.
    app.network_view.open(Some(file.clone()));
    app.pending_deletions.push((7, deletion.clone()));
    assert_eq!(app.take_pending_deletion(7), Some(deletion.clone()));
    assert!(app.take_pending_deletion(7).is_none());
    assert_eq!(app.network_view.loaded_path(), Some(file.as_path()));
    assert_eq!(deletion.kind, Kind::Network);
    std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
}
