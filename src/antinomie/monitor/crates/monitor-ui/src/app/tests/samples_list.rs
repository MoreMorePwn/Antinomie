// SPDX-License-Identifier: GPL-3.0-only
//! Library › Samples: the flat list, its filters, the Add file dialog and the
//! Run History Sample column.
use super::*;
use antinomie_monitor_core::samples::{
    self, Library, NewOrigin, NewSample, OriginKind, SeenRun, Tag, TagKind,
};

const SIZE: egui::Vec2 = egui::vec2(1700.0, 820.0);

pub(super) fn temp(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ant-ui-samples-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

const SCRIPT: &[u8] = b"#!/bin/sh\necho install\n";

fn elf(seed: u8) -> Vec<u8> {
    let mut bytes = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
    bytes.extend((0..2048u32).map(|n| (n as u8).wrapping_mul(seed)));
    bytes
}

fn added(path: &str) -> NewSample {
    NewSample {
        origin: NewOrigin {
            kind: OriginKind::Added,
            path: path.into(),
            ..NewOrigin::default()
        },
        ..NewSample::default()
    }
}

/// Frames until `ready` holds (the page reads the library on a thread).
fn until(app: &mut MonitorApp, ctx: &egui::Context, ready: impl Fn(&MonitorApp) -> bool) {
    // Time-based: a busy machine runs frames fast and the thread slowly.
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        render(app, ctx, SIZE);
        if ready(app) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ready(app), "the page did not settle");
}

/// Three samples: `install.sh` (a parent, run twice), `.x` (dropped by
/// `install.sh`) and `notes.txt` (never run, tagged).
pub(super) fn fixture(root: &std::path::Path) -> (String, String, String) {
    let mut library = Library::open(root).unwrap();
    let script = library
        .add_bytes(
            SCRIPT,
            NewSample {
                description: "Cron installer".into(),
                ..added("/cases/install.sh")
            },
        )
        .unwrap()
        .sha256;
    let dropped = library
        .add_bytes(
            &elf(3),
            NewSample {
                origin: NewOrigin {
                    kind: OriginKind::Dropped,
                    parent: script.clone(),
                    path: "/tmp/.x".into(),
                    run_id: "r1".into(),
                    ..NewOrigin::default()
                },
                ..NewSample::default()
            },
        )
        .unwrap()
        .sha256;
    let plain = library
        .add_bytes(b"just some notes\n", added("/cases/notes.txt"))
        .unwrap()
        .sha256;
    library
        .set_tags(
            &script,
            &[
                Tag::new(TagKind::Verdict, "malicious"),
                Tag::new(TagKind::Category, "dropper"),
                Tag::new(TagKind::Technique, "T1053.003 Scheduled Task/Job: Cron"),
            ],
        )
        .unwrap();
    library
        .set_tags(&plain, &[Tag::new(TagKind::Verdict, "benign")])
        .unwrap();
    let run = |sha: &str, id: &str, started: u64, exit: &str| SeenRun {
        sha256: sha.into(),
        vm_id: "vm".into(),
        vm_name: "Debian".into(),
        run_id: id.into(),
        started_ms: Some(started),
        exit: exit.into(),
        directory: format!("/runs/{id}"),
    };
    // After the samples were added, so the runs decide the order.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    library
        .index_runs(&[
            run(&script, "r1", now + 1_000, "Exit 0"),
            run(&script, "r2", now + 9_000, "Exit 0"),
            run(&dropped, "r1b", now + 5_000, "Signal 9"),
        ])
        .unwrap();
    (script, dropped, plain)
}

fn open_page(root: &std::path::Path) -> (MonitorApp, egui::Context) {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.options.data_dir = root.to_path_buf();
    app.rules_ui.set_packs_for_test(Vec::new());
    app.open_library(crate::workspace::LibraryPage::Samples);
    until(&mut app, &ctx, |app| app.samples_page.is_loaded());
    (app, ctx)
}

fn names(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    let shown = texts(&render(app, ctx, SIZE));
    ["install.sh", ".x", "notes.txt"]
        .into_iter()
        .filter(|name| shown.iter().any(|(text, _)| text == name))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_list_is_flat_latest_run_first_with_counts_and_a_never_run_mark() {
    let root = temp("list");
    fixture(&root);
    let (mut app, ctx) = open_page(&root);
    // Latest run first (install.sh r2, then .x r1b), then the sample never run.
    assert_eq!(
        app.samples_page
            .rows()
            .iter()
            .map(|row| row.record.name.as_str())
            .collect::<Vec<_>>(),
        ["install.sh", ".x", "notes.txt"]
    );
    let shown = texts(&render(&mut app, &ctx, SIZE));
    for expected in [
        "Name",
        "Description",
        "Tags",
        "Runs",
        "Parents / children",
        "Latest run",
        "SHA-256",
        "Cron installer",
        "Exit 0",
        "Signal 9",
        "never run",
        "– / 1",
        "1 / –",
        "malicious",
        "dropper",
        "+1",
        "benign",
    ] {
        assert!(
            shown.iter().any(|(text, _)| text == expected),
            "missing {expected}: {shown:?}"
        );
    }
    // The sidebar counts the library.
    assert_eq!(app.samples_page.count(), 3);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn search_tags_and_roots_only_narrow_the_list() {
    let root = temp("filters");
    let (script, _, _) = fixture(&root);
    let (mut app, ctx) = open_page(&root);
    assert_eq!(names(&mut app, &ctx), ["install.sh", ".x", "notes.txt"]);
    // Name, description, tag text and a SHA-256 prefix all find install.sh.
    for query in ["INSTALL", "cron installer", "dropper", &script[..10]] {
        app.samples_page.set_query(query);
        assert_eq!(names(&mut app, &ctx), ["install.sh"], "{query}");
    }
    app.samples_page.set_query("zzz");
    assert!(names(&mut app, &ctx).is_empty());
    app.samples_page.set_query("");
    // Every selected tag must be present (AND).
    app.samples_page
        .toggle_tag(Tag::new(TagKind::Verdict, "malicious"));
    assert_eq!(names(&mut app, &ctx), ["install.sh"]);
    app.samples_page
        .toggle_tag(Tag::new(TagKind::Verdict, "benign"));
    assert!(names(&mut app, &ctx).is_empty());
    app.samples_page.clear_tags();
    // Roots only keeps samples with no known parent: .x was dropped.
    app.samples_page.set_roots_only(true);
    assert_eq!(names(&mut app, &ctx), ["install.sh", "notes.txt"]);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn add_file_reads_the_hash_without_running_and_a_known_hash_adds_an_origin() {
    let root = temp("add");
    let files = temp("add-files");
    fixture(&root);
    let (mut app, ctx) = open_page(&root);
    let fresh = files.join("update-helper");
    std::fs::write(&fresh, elf(5)).unwrap();
    let again = files.join("copy-of-install.sh");
    std::fs::write(&again, SCRIPT).unwrap();
    // A new file.
    app.samples_page.open_add(Some(&fresh));
    until(&mut app, &ctx, |app| app.samples_page.add_ready());
    let shown = texts(&render(&mut app, &ctx, SIZE));
    for expected in ["update-helper", "elf · x86-64", "No"] {
        assert!(
            shown.iter().any(|(text, _)| text == expected),
            "missing {expected}: {shown:?}"
        );
    }
    click_label(&mut app, &ctx, SIZE, "Add");
    until(&mut app, &ctx, |app| !app.samples_page.add_open());
    until(&mut app, &ctx, |app| app.samples_page.count() == 4);
    assert!(fresh.exists(), "the original stays unless asked");
    // The same bytes as install.sh: no second row, one more origin.
    app.samples_page.open_add(Some(&again));
    until(&mut app, &ctx, |app| app.samples_page.add_ready());
    let shown = texts(&render(&mut app, &ctx, SIZE));
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "Yes: this adds an origin"),
        "{shown:?}"
    );
    click_label(&mut app, &ctx, SIZE, "Add");
    until(&mut app, &ctx, |app| !app.samples_page.add_open());
    until(&mut app, &ctx, |app| {
        app.samples_page
            .notice_text()
            .is_some_and(|text| text.starts_with("Already in Samples"))
    });
    assert_eq!(app.samples_page.count(), 4);
    let library = Library::open(&root).unwrap();
    let hash = antinomie_monitor_core::storage::sha256_hex(SCRIPT);
    assert_eq!(library.origins(&hash).unwrap().len(), 2);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(files).unwrap();
}

#[test]
fn deleting_the_original_needs_the_box_and_removes_only_that_file() {
    let root = temp("delete-original");
    let files = temp("delete-original-files");
    let (mut app, ctx) = open_page(&root);
    let file = files.join("incident.sh");
    std::fs::write(&file, SCRIPT).unwrap();
    app.samples_page.open_add(Some(&file));
    assert!(!app.samples_page.delete_original_ticked());
    until(&mut app, &ctx, |app| app.samples_page.add_ready());
    app.samples_page.tick_delete_original();
    click_label(&mut app, &ctx, SIZE, "Add");
    until(&mut app, &ctx, |app| !app.samples_page.add_open());
    assert!(!file.exists());
    let hash = antinomie_monitor_core::storage::sha256_hex(SCRIPT);
    let library = Library::open(&root).unwrap();
    assert!(library.verify(&hash).unwrap().is_ok());
    assert!(library
        .events(&hash)
        .unwrap()
        .iter()
        .any(|row| row.event.label() == "Original deleted"));
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(files).unwrap();
}

#[test]
fn the_explorer_adds_a_file_to_samples_through_the_dialog() {
    let root = temp("explorer");
    let mut app = app();
    app.options.data_dir = root.clone();
    app.add_explorer_file(PathBuf::from("/cases/update-helper"));
    assert!(app.samples_page.add_open());
    assert_eq!(
        app.take_library_pages(),
        vec![crate::workspace::LibraryPage::Samples]
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn run_history_names_the_library_sample_each_run_executed() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.selected = Some("vm".into());
    let mut with = run("with-sample");
    with.vm_id = "vm".into();
    with.request.sample = Some(samples::SampleRef {
        sha256: "a".repeat(64),
        name: "install.sh".into(),
    });
    let mut without = run("plain");
    without.vm_id = "vm".into();
    app.history = vec![with, without];
    app.layout.focus(Panel::RunHistory);
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown = texts(&render(&mut app, &ctx, SIZE));
    for expected in ["Sample", "install.sh"] {
        assert!(
            shown.iter().any(|(text, _)| text == expected),
            "missing {expected}: {shown:?}"
        );
    }
}
