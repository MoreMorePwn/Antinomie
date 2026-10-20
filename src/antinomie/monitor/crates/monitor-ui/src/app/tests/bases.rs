// SPDX-License-Identifier: MIT
//! Base catalog, base rows and section headers.
use super::*;

#[test]
fn download_catalog_prioritizes_current_bases_and_hides_older_ones() {
    let mut app = app();
    app.download_open = true;
    app.snapshot.remote_bases = vec![
        catalog_base("old", Some(9)),
        catalog_base("future", Some(APP_REVISION + 1)),
        catalog_base("current", Some(APP_REVISION)),
        catalog_base("legacy", None),
    ];
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let visible = texts(&render(&mut app, &ctx, size));
    assert!(visible.iter().any(|(text, _)| text
        == &format!(
            "current · Antinomie {}",
            antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
        )));
    assert!(!visible
        .iter()
        .any(|(text, _)| text.starts_with("old ·") || text == "legacy"));
    let current = visible
        .iter()
        .find(|(text, _)| text.starts_with("current ·"))
        .unwrap()
        .1;
    let future = visible.iter().find(|(text, _)| text == "future").unwrap().1;
    assert!(current.top() < future.top());
    click_label(&mut app, &ctx, size, "Show older bases (2)");
    let visible = texts(&render(&mut app, &ctx, size));
    assert!(visible
        .iter()
        .any(|(text, _)| text == "old · Antinomie 0.1.0"));
    assert!(visible.iter().any(|(text, _)| text == "legacy"));
    assert_eq!(
        RevisionStatus::of_base(Some(APP_REVISION), Some("0.3.0")),
        RevisionStatus::Current
    );
}

#[test]
fn cancel_remains_reachable_when_the_active_base_is_hidden_or_removed() {
    for size in [egui::vec2(800.0, 600.0), egui::vec2(1440.0, 900.0)] {
        let mut app = app();
        app.download_open = true;
        let old = catalog_base("old", Some(APP_REVISION - 1));
        app.snapshot.download = Some(antinomie_monitor_core::DownloadStatus {
            identity: old.identity.clone(),
            label: old.label.clone(),
            received: 128,
            total: old.total_size,
            ..Default::default()
        });
        app.snapshot.remote_bases = vec![old, catalog_base("current", Some(APP_REVISION))];
        let ctx = egui::Context::default();
        theme::install(&ctx);
        click_label(&mut app, &ctx, size, "Cancel");
        assert!(matches!(
            app.submitted.last(),
            Some(Command::CancelDownload)
        ));
        app.snapshot.remote_bases.clear();
        app.submitted.clear();
        click_label(&mut app, &ctx, size, "Cancel");
        assert!(matches!(
            app.submitted.last(),
            Some(Command::CancelDownload)
        ));
        app.snapshot.download.as_mut().unwrap().installing = true;
        app.submitted.clear();
        click_label(&mut app, &ctx, size, "Cancel");
        assert!(
            app.submitted.is_empty(),
            "installation must finish before another action"
        );
    }
}

#[test]
fn startup_checking_does_not_show_a_missing_base_warning() {
    let mut app = app();
    app.snapshot.bases_checking = true;
    open_bases_page(&mut app);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let visible = texts(&render(&mut app, &ctx, size));
    assert!(visible
        .iter()
        .any(|(text, _)| text == "Checking base images…"));
    assert!(!visible.iter().any(|(text, _)| text == "No base images"));
    app.snapshot.bases_checking = false;
    assert!(texts(&render(&mut app, &ctx, size))
        .iter()
        .any(|(text, _)| text == "No base images"));
}

#[test]
fn base_labels_name_outdated_newer_and_unrecorded_revisions() {
    let mut base = base_summary_for_revision(Some(APP_REVISION));
    assert_eq!(
        base_choice_label(&base),
        format!(
            "Debian · Antinomie {}",
            antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
        )
    );
    base.revision = Some(APP_REVISION - 1);
    assert!(base_choice_label(&base).ends_with(", outdated"));
    base.revision = Some(APP_REVISION + 1);
    assert!(base_choice_label(&base).contains("needs a newer Antinomie"));
    base.revision = None;
    assert!(base_choice_label(&base).contains("built before versioning"));
}

/// Click a sortable header: its text may carry the sort arrow.
fn click_header(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2, title: &str) {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    let pos = texts(&render(app, ctx, size))
        .iter()
        .find(|(text, _)| text.starts_with(title))
        .unwrap_or_else(|| panic!("missing header {title}"))
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
}

fn open_bases_page(app: &mut MonitorApp) {
    app.open_library(crate::workspace::LibraryPage::BaseImages);
}

#[test]
fn base_rows_sort_by_header_and_a_click_only_selects() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = app();
    let mut alpha = test_base("first", true);
    alpha.label = "Alpha".into();
    alpha.size_bytes = 5 << 30;
    let mut beta = test_base("second", true);
    beta.label = "Beta".into();
    beta.size_bytes = 1 << 30;
    app.snapshot.bases = vec![alpha, beta];
    open_bases_page(&mut app);
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let row_top = |app: &mut MonitorApp, name: &str| {
        texts(&render(app, &ctx, size))
            .iter()
            .find(|(text, _)| text.starts_with(name))
            .unwrap_or_else(|| panic!("missing {name}"))
            .1
            .top()
    };
    assert!(row_top(&mut app, "Alpha") < row_top(&mut app, "Beta"));
    click_header(&mut app, &ctx, size, "Size");
    assert!(
        row_top(&mut app, "Beta") < row_top(&mut app, "Alpha"),
        "the smaller base comes first"
    );
    click_header(&mut app, &ctx, size, "Size");
    assert!(row_top(&mut app, "Alpha") < row_top(&mut app, "Beta"));
    let target = texts(&render(&mut app, &ctx, size))
        .iter()
        .find(|(text, _)| text.starts_with("Beta"))
        .unwrap()
        .1
        .center();
    let click = |pressed| egui::Event::PointerButton {
        pos: target,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::default(),
    };
    for events in [
        vec![egui::Event::PointerMoved(target)],
        vec![click(true)],
        vec![click(false)],
    ] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
    assert_eq!(app.selected_base.as_deref(), Some("second"));
    // Selecting a base starts nothing: no dialog, no command.
    assert!(app.submitted.is_empty());
    assert!(app.confirm.is_none());
    click_label(&mut app, &ctx, size, "New VM from this base…");
    assert!(app.create_open, "the selected base's action opens New VM");
}

#[test]
fn the_base_images_page_adds_a_base_by_import_download_or_build() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    type Opened = fn(&MonitorApp) -> bool;
    let buttons: [(&str, Opened); 3] = [
        ("Import base…", |app| app.import_open),
        ("Build base…", |app| app.build_open),
        ("Download base…", |app| app.download_open),
    ];
    for (label, opened) in buttons {
        let mut app = app();
        open_bases_page(&mut app);
        click_label(&mut app, &ctx, size, label);
        assert!(opened(&app), "{label}");
    }
}
