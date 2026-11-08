// SPDX-License-Identifier: GPL-3.0-only
//! The per-file table of Triage > Files: its rows, the chain of what happened
//! and the table through a real egui pass.
use super::overview::{self, chain, size_change};
use super::tests::activity;
use super::window::Window;
use super::*;
use crate::triage::file_shown::Notes;
use eframe::egui::{self, Pos2, Rect};

fn event(time: u64, kind: Kind) -> Event {
    let mut event = super::tests::event(time, kind, 0);
    event.operation = kind.verb().to_owned();
    event
}

#[test]
fn the_chain_says_what_happened_in_order_with_sizes_and_the_mode() {
    let mut write = event(2, Kind::Write);
    write.len = Some(812 * 1024);
    let mut chmod = event(3, Kind::Attributes);
    chmod.operation = "fchmodat".into();
    chmod.note = "+x".into();
    let mut refused = event(4, Kind::Exec);
    refused.success = Some(false);
    let file = super::tests::file(
        "/tmp/dropped",
        1,
        vec![
            event(1, Kind::Create),
            event(1, Kind::Open),
            write,
            chmod,
            refused,
            event(5, Kind::Exec),
            event(6, Kind::Delete),
        ],
    );
    assert_eq!(
        chain(&file),
        "created \u{2192} written 812 KiB \u{2192} chmod +x \u{2192} executed \u{2192} deleted"
    );
    // A file only opened and read.
    let mut read = event(2, Kind::Read);
    read.len = Some(10);
    let looked = super::tests::file("/etc/hosts", 1, vec![event(1, Kind::Open), read]);
    assert_eq!(chain(&looked), "read 10 B");
    let probed = super::tests::file("/etc/x", 1, vec![event(1, Kind::Probe)]);
    assert_eq!(chain(&probed), "only looked at");
    let mut refused = super::tests::file("/etc/y", 1, vec![event(1, Kind::Open)]);
    refused.events[0].success = Some(false);
    refused.failed_only = true;
    assert_eq!(chain(&refused), "every call refused");
}

#[test]
fn the_size_column_merges_before_and_after() {
    let mut file = super::tests::file("/tmp/a", 1, vec![event(1, Kind::Create)]);
    file.created = true;
    file.contents.final_size = Some(812 * 1024);
    assert_eq!(size_change(&file), "0 B \u{2192} 812 KiB");
    file.contents.original_size = Some(812 * 1024);
    assert_eq!(size_change(&file), "812 KiB");
    file.created = false;
    file.contents.original_size = None;
    file.contents.final_size = None;
    assert_eq!(size_change(&file), "unknown");
}

#[test]
fn a_file_row_has_the_columns_badges_type_digest_and_warning() {
    let mut activity = activity();
    activity.files[3].names.push("/tmp/.payload".into());
    let hash = "cd".repeat(32);
    activity.files[3].hashes.push(HashNote {
        time: 14,
        moment: "before delete",
        sha256: Some(hash.clone()),
        changed: false,
        skipped: None,
    });
    let mut flagged = file_shown::Flags::new();
    file_shown::flag(
        &mut flagged,
        "/tmp/payload",
        rules::Tier::High,
        "execution.dropped_exec",
    );
    let notes = Notes {
        start: Some(10),
        flagged: &flagged,
    };
    let row = overview::cells(&activity, &activity.files[3], &notes, None);
    let text: Vec<&str> = row.iter().map(|cell| cell.text.as_str()).collect();
    assert_eq!(overview::HEADERS.len(), row.len());
    assert_eq!(overview::HEADERS[1], "Tags");
    assert_eq!(text[0], "/tmp/payload");
    // The path is only the path; its tags are in the next column.
    assert!(row[0].badges.is_empty());
    assert_eq!(text[1], "");
    assert_eq!(
        text[2],
        "created \u{2192} written 6 B \u{2192} renamed \u{2192} deleted"
    );
    assert_eq!(text[3], "dropper (100 \u{b7} 100) +1");
    assert_eq!(text[4], "+0.000 s \u{2192} +0.000 s");
    assert_eq!(text[5], "0 B \u{2192} unknown");
    assert_eq!(text[6], "ELF");
    assert_eq!(text[7], format!("{}\u{2026}", &hash[..12]));
    let badges: Vec<&str> = row[1].badges.iter().map(|b| b.text.as_str()).collect();
    assert_eq!(
        badges,
        ["/tmp", "+1 names", "High \u{b7} Dropped file executed"]
    );
    assert!(text.iter().all(|text| !text.contains('\u{26a0}')));
    assert_eq!(row[7].note.as_deref(), Some(hash.as_str()));
    // A file no finding names has no finding tag.
    let none = file_shown::Flags::new();
    let plain = Notes {
        start: Some(10),
        flagged: &none,
    };
    let row = overview::cells(&activity, &activity.files[3], &plain, None);
    let badges: Vec<&str> = row[1].badges.iter().map(|b| b.text.as_str()).collect();
    assert_eq!(badges, ["/tmp", "+1 names"]);
}

#[test]
fn the_table_draws_its_headers_and_a_row_for_each_shown_file() {
    let activity = activity();
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut window = Window::default();
    let flagged = file_shown::Flags::new();
    let mut texts: Vec<String> = Vec::new();
    for _ in 0..3 {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1400.0, 700.0))),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    window.overview(
                        ui,
                        Some(&activity),
                        &Notes {
                            start: Some(5),
                            flagged: &flagged,
                        },
                        None,
                    )
                });
            },
        );
        texts.clear();
        fn collect(shape: &egui::epaint::Shape, out: &mut Vec<String>) {
            match shape {
                egui::epaint::Shape::Text(text) => out.push(text.galley.text().to_owned()),
                egui::epaint::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        for shape in &output.shapes {
            collect(&shape.shape, &mut texts);
        }
    }
    for header in overview::HEADERS {
        assert!(
            texts.iter().any(|text| text.starts_with(header)),
            "{header} in {texts:?}"
        );
    }
    // Stdio and libraries start hidden: the dropped file and /etc/hosts stay.
    assert!(texts.iter().any(|text| text == "/tmp/payload"));
    assert!(texts.iter().any(|text| text == "/etc/hosts"));
    assert!(!texts.iter().any(|text| text == "/usr/lib/libc.so.6"));
    assert!(texts.iter().any(|text| text == "2 / 4 rows"), "{texts:?}");
    assert!(
        texts.iter().any(|text| text == "/tmp"),
        "the location badge"
    );
}
