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

#[test]
fn base_rows_are_left_aligned_and_a_click_only_selects() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = app();
    app.snapshot.bases = vec![test_base("first", true), test_base("second", true)];
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let texts = texts(&render(&mut app, &ctx, size));
    let rows: Vec<_> = texts
        .iter()
        .filter(|(text, _)| {
            text.contains(&format!(
                "Linux 6.12.94 · Antinomie {}",
                antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
            ))
        })
        .map(|(_, rect)| *rect)
        .collect();
    let title = texts
        .iter()
        .find(|(text, _)| text == "Base images")
        .expect("base images title")
        .1;
    assert_eq!(rows.len(), 2);
    // Left-aligned with the section title (after the row's status
    // mark), not centred in the sidebar.
    assert!(
        rows.iter().all(|row| row.left() < title.left() + 16.0),
        "{rows:?} {title:?}"
    );
    let target = rows[1].center();
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
}

#[test]
fn section_headers_share_a_layout_and_the_add_control_lights_on_hover() {
    fn lit(output: &egui::FullOutput, point: egui::Pos2) -> bool {
        fn find(shape: &egui::Shape, point: egui::Pos2) -> bool {
            match shape {
                egui::Shape::Rect(rect) => {
                    rect.fill == theme::primary() && rect.rect.contains(point)
                }
                egui::Shape::Vec(shapes) => shapes.iter().any(|shape| find(shape, point)),
                _ => false,
            }
        }
        output.shapes.iter().any(|shape| find(&shape.shape, point))
    }
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = app();
    app.snapshot.bases = vec![test_base("first", true)];
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let shown = texts(&output);
    let header = |title: &str| {
        let title = shown
            .iter()
            .find(|(text, _)| text == title)
            .unwrap_or_else(|| panic!("missing {title}"))
            .1;
        let add = shown
            .iter()
            .find(|(text, rect)| {
                text == egui_phosphor::regular::PLUS
                    && rect.center().y > title.top()
                    && rect.center().y < title.bottom()
            })
            .unwrap_or_else(|| panic!("missing + beside {title:?}"))
            .1;
        (title, add)
    };
    let (vm_title, vm_add) = header("Virtual machines");
    let (base_title, base_add) = header("Base images");
    // Glyph side bearings differ by about a pixel between the two titles.
    assert!(
        (vm_title.left() - base_title.left()).abs() < 2.0,
        "{vm_title:?} {base_title:?}"
    );
    assert!((vm_add.center().x - base_add.center().x).abs() < 0.5);
    assert!((vm_add.height() - base_add.height()).abs() < 0.5);
    assert!(!lit(&output, base_add.center()));

    let target = base_add.center();
    let frame = |app: &mut MonitorApp, events| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        )
    };
    let _ = frame(&mut app, vec![egui::Event::PointerMoved(target)]);
    let hovered = frame(&mut app, vec![]);
    assert!(lit(&hovered, target), "hovered + must light up");
    let click = |pressed| egui::Event::PointerButton {
        pos: target,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::default(),
    };
    let _ = frame(&mut app, vec![click(true)]);
    let _ = frame(&mut app, vec![click(false)]);
    let opened = frame(&mut app, vec![]);
    assert!(texts(&opened)
        .iter()
        .any(|(text, _)| text == "Import base…"));
    assert!(lit(&opened, target), "+ stays lit while its menu is open");
}
