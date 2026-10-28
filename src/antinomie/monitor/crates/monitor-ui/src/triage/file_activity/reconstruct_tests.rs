// SPDX-License-Identifier: GPL-3.0-only
//! The File Reconstruction window through a real egui pass: the controls, the
//! byte map, the byte history, the hash check and the save.
use super::reconstruct::{self, Open};
use super::tests::activity;
use super::*;
use antinomie_monitor_core::file_reconstruct::{sha256_hex, Action, Start, Step};
use antinomie_monitor_core::file_writes::{Extent, Gap, Piece, Source};
use eframe::egui::{self, Pos2, Rect};

fn kept(offset: u64, bytes: &[u8]) -> Extent {
    Extent {
        offset,
        len: bytes.len() as u64,
        piece: Piece::Kept(Source::Inline(bytes.to_vec())),
    }
}

/// A created file written in two calls, a hole the kernel did not capture, and
/// the guest's hash of the finished file.
fn fixture() -> (Activity, usize) {
    let mut activity = activity();
    let index = activity
        .files
        .iter()
        .position(|file| file.path == "/tmp/payload")
        .unwrap();
    let file = &mut activity.files[index];
    for (time, action) in [
        (11, Action::Write(vec![kept(0, b"#!/bin/sh\n")])),
        (12, Action::Write(vec![kept(10, b"id\n")])),
    ] {
        file.timeline.push(Step {
            time_ns: time,
            event: Some((time - 10) as u32),
            order: None,
            action,
        });
    }
    file.hashes.push(HashNote {
        time: 13,
        moment: "closed after write",
        sha256: Some(sha256_hex(b"#!/bin/sh\nid\n")),
        changed: false,
        skipped: None,
    });
    (activity, index)
}

/// The synthetic runs of the screenshots: `modified` (a crontab the run
/// changed, over its before-image, with the guest's hash), `gaps` (a file
/// whose earlier bytes are not known, with reads, a write the kernel did not
/// capture and a shared mapping).
pub(in crate::triage) fn scene(name: &str) -> (Activity, Start) {
    let mut activity = activity();
    let before = b"# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n";
    let index = activity
        .files
        .iter()
        .position(|file| file.path == "/tmp/payload")
        .unwrap();
    let file = &mut activity.files[index];
    file.path = "/etc/crontab".into();
    file.created = false;
    file.deleted = false;
    file.timeline = Default::default();
    let steps: Vec<(u64, Action)> = if name == "gaps" {
        vec![
            (11, Action::Read(vec![kept(0, &before[..48])])),
            (
                12,
                Action::Write(vec![kept(64, b"* * * * * root /tmp/payload\n")]),
            ),
            (
                13,
                Action::Write(vec![Extent {
                    offset: 100,
                    len: 20,
                    piece: Piece::NotCaptured(Gap::FileCap),
                }]),
            ),
            (
                14,
                Action::Mapping {
                    offset: 144,
                    len: 12,
                },
            ),
        ]
    } else {
        vec![
            (11, Action::Read(vec![kept(0, &before[..36])])),
            (12, Action::Write(vec![kept(50, b"/bin/bash")])),
            (
                13,
                Action::Write(vec![kept(
                    before.len() as u64,
                    b"* * * * * root /tmp/payload\n",
                )]),
            ),
        ]
    };
    let mut expected = before.to_vec();
    if name != "gaps" {
        expected[50..59].copy_from_slice(b"/bin/bash");
        expected.extend(b"* * * * * root /tmp/payload\n");
    }
    file.hashes = vec![HashNote {
        time: 20,
        moment: "closed after write",
        sha256: Some(sha256_hex(&expected)),
        changed: false,
        skipped: None,
    }];
    for (at, (time, action)) in steps.into_iter().enumerate() {
        file.timeline.push(Step {
            time_ns: time,
            event: Some(at as u32 % 3),
            order: None,
            action,
        });
    }
    let start = if name == "gaps" {
        Start {
            size: Some(160),
            source: None,
        }
    } else {
        Start {
            size: Some(before.len() as u64),
            source: Some(Source::Inline(before.to_vec())),
        }
    };
    (activity, start)
}

struct Harness {
    ctx: egui::Context,
    time: f64,
}

impl Harness {
    fn new() -> Self {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        Self { ctx, time: 0.0 }
    }

    fn frame(
        &mut self,
        open: &mut Open,
        activity: &Activity,
        file: &FileActivity,
        directory: Option<&std::path::Path>,
        events: Vec<egui::Event>,
    ) -> Vec<(String, Rect)> {
        self.time += 0.05;
        let output = self.ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1300.0, 800.0))),
                events,
                time: Some(self.time),
                ..Default::default()
            },
            |ctx| {
                open.show(ctx, activity, file, None, directory);
            },
        );
        fn collect(shape: &egui::epaint::Shape, out: &mut Vec<(String, Rect)>) {
            match shape {
                egui::epaint::Shape::Text(text) => out.push((
                    text.galley.text().to_owned(),
                    Rect::from_min_size(text.pos, text.galley.size()),
                )),
                egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, &mut found);
        }
        found
    }

    fn settle(
        &mut self,
        open: &mut Open,
        activity: &Activity,
        file: &FileActivity,
        directory: Option<&std::path::Path>,
    ) -> Vec<(String, Rect)> {
        let mut shown = Vec::new();
        for _ in 0..4 {
            shown = self.frame(open, activity, file, directory, Vec::new());
        }
        shown
    }

    fn click(
        &mut self,
        open: &mut Open,
        activity: &Activity,
        file: &FileActivity,
        directory: Option<&std::path::Path>,
        at: Pos2,
    ) {
        for pressed in [true, false] {
            self.frame(
                open,
                activity,
                file,
                directory,
                vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
    }
}

fn find<'a>(shown: &'a [(String, Rect)], text: &str) -> &'a Rect {
    &shown
        .iter()
        .find(|(shown, _)| shown.contains(text))
        .unwrap_or_else(|| {
            panic!(
                "{text:?} not drawn in {:#?}",
                shown.iter().map(|s| &s.0).collect::<Vec<_>>()
            )
        })
        .1
}

#[test]
fn the_window_opens_at_the_end_and_shows_the_bytes_and_the_call() {
    let (activity, index) = fixture();
    let file = &activity.files[index];
    let mut open = Open::new(file);
    let mut harness = Harness::new();
    let shown = harness.settle(&mut open, &activity, file, None);
    find(&shown, "File reconstruction");
    find(&shown, "/tmp/payload");
    find(&shown, "Call 2 of 2");
    // "#!" and the later "id" are on the map.
    find(&shown, "2f");
    find(&shown, "wrote 3 B at 0xa");
}

#[test]
fn stepping_back_hides_what_the_later_call_wrote() {
    let (activity, index) = fixture();
    let file = &activity.files[index];
    let mut open = Open::new(file);
    let mut harness = Harness::new();
    harness.settle(&mut open, &activity, file, None);
    // Left arrow with the pointer over the window.
    let over = Pos2::new(600.0, 300.0);
    harness.frame(
        &mut open,
        &activity,
        file,
        None,
        vec![egui::Event::PointerMoved(over)],
    );
    harness.frame(
        &mut open,
        &activity,
        file,
        None,
        vec![egui::Event::PointerMoved(over)],
    );
    let key = |key| egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Default::default(),
    };
    harness.frame(
        &mut open,
        &activity,
        file,
        None,
        vec![key(egui::Key::ArrowLeft)],
    );
    let shown = harness.settle(&mut open, &activity, file, None);
    find(&shown, "Call 1 of 2");
    assert!(!shown.iter().any(|(text, _)| text.contains("wrote 3 B")));
    // The three bytes of the second write are not in the file yet.
    assert_eq!(open_size(&open), 10);
}

fn open_size(open: &Open) -> u64 {
    open.size()
}

#[test]
fn a_clicked_byte_shows_when_it_was_learned() {
    let (activity, index) = fixture();
    let file = &activity.files[index];
    let mut open = Open::new(file);
    let mut harness = Harness::new();
    let shown = harness.settle(&mut open, &activity, file, None);
    // The first byte of the dump: "23".
    let first = *shown
        .iter()
        .find(|(text, _)| text == "23")
        .map(|(_, rect)| rect)
        .expect("first byte");
    harness.click(&mut open, &activity, file, None, first.center());
    let shown = harness.settle(&mut open, &activity, file, None);
    find(&shown, "Byte 0x0");
    find(&shown, "written = 23");
}

#[test]
fn the_hash_check_matches_the_guests_hash_when_every_byte_is_known() {
    let (activity, index) = fixture();
    let file = &activity.files[index];
    let mut open = Open::new(file);
    let mut harness = Harness::new();
    let shown = harness.settle(&mut open, &activity, file, None);
    let button = find(&shown, "Hash this state").center();
    harness.click(&mut open, &activity, file, None, button);
    let mut text = Vec::new();
    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        text = harness.frame(&mut open, &activity, file, None, Vec::new());
        if text
            .iter()
            .any(|(text, _)| text.contains("matches the guest"))
        {
            break;
        }
    }
    find(&text, "matches the guest's hash");
}

#[test]
fn a_file_with_a_gap_has_no_hash_and_the_map_marks_it() {
    let (mut activity, index) = fixture();
    let file = &mut activity.files[index];
    file.timeline.push(Step {
        time_ns: 12,
        event: None,
        order: None,
        action: Action::Write(vec![Extent {
            offset: 13,
            len: 4,
            piece: Piece::NotCaptured(Gap::FileCap),
        }]),
    });
    let file = &activity.files[index];
    let mut open = Open::new(file);
    let mut harness = Harness::new();
    let shown = harness.settle(&mut open, &activity, file, None);
    find(&shown, "## ## ## ##");
    let button = find(&shown, "Hash this state").center();
    harness.click(&mut open, &activity, file, None, button);
    let mut text = Vec::new();
    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        text = harness.frame(&mut open, &activity, file, None, Vec::new());
        if text.iter().any(|(text, _)| text.contains("No hash")) {
            break;
        }
    }
    find(&text, "No hash: 4 bytes have no value");
}

#[test]
fn a_save_writes_the_bytes_and_a_mask() {
    let (mut activity, index) = fixture();
    activity.files[index].timeline.push(Step {
        time_ns: 13,
        event: None,
        order: None,
        action: Action::Write(vec![Extent {
            offset: 15,
            len: 1,
            piece: Piece::NotCaptured(Gap::RunCap),
        }]),
    });
    let file = &activity.files[index];
    let directory =
        std::env::temp_dir().join(format!("ant-reconstruct-save-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let mut open = Open::new(file);
    let mut harness = Harness::new();
    let shown = harness.settle(&mut open, &activity, file, Some(&directory));
    let button = find(&shown, "Save reconstruction").center();
    harness.click(&mut open, &activity, file, Some(&directory), button);
    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(10));
        harness.frame(&mut open, &activity, file, Some(&directory), Vec::new());
        if directory
            .join("reconstructed")
            .read_dir()
            .is_ok_and(|mut d| d.nth(1).is_some())
        {
            break;
        }
    }
    let name = reconstruct::save_name("/tmp/payload", file.first_ns);
    let saved = std::fs::read(directory.join("reconstructed").join(format!("{name}.bin"))).unwrap();
    let mask = std::fs::read(directory.join("reconstructed").join(format!("{name}.mask"))).unwrap();
    assert_eq!(saved, b"#!/bin/sh\nid\n\0\0\0");
    assert_eq!(mask, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2]);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn a_files_tab_row_with_a_path_offers_the_reconstruction() {
    use crate::triage::RowValue;
    let values = [("file.path", RowValue::Text("/tmp/payload".into()))];
    assert_eq!(
        reconstruct::row_path("triage-created", &values).as_deref(),
        Some("/tmp/payload")
    );
    assert_eq!(reconstruct::row_path("triage-findings", &values), None);
    assert_eq!(
        reconstruct::row_path("triage-opened", &[("file.path", RowValue::Missing)]),
        None
    );
    assert_eq!(reconstruct::save_name("/etc/a b/c.d", 7), "etc_a_b_c.d-7");
}

#[test]
fn the_per_file_history_opens_the_reconstruction_from_its_button_and_from_a_row_request() {
    let (activity, _) = fixture();
    let mut window = Window::default();
    window.reconstruct("/tmp/payload");
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut time = 0.0;
    let mut run = |window: &mut Window| {
        time += 0.05;
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1400.0, 900.0))),
                time: Some(time),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| window.show(ui, Some(&activity), None, None));
            },
        );
    };
    for _ in 0..3 {
        run(&mut window);
    }
    assert!(window.reconstruction().is_some());
    assert_eq!(window.reconstruction().unwrap().key().0, "/tmp/payload");
}
