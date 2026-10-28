// SPDX-License-Identifier: GPL-3.0-only
//! The custody log in the Samples page: the sample window's tab with its
//! verify banner and check column, the log across all samples with its
//! filters, and Export custody record….
use super::*;
use antinomie_monitor_core::samples::{verify_record, ExportFormat};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 820.0);

fn until(app: &mut MonitorApp, ctx: &egui::Context, ready: impl Fn(&MonitorApp) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        render(app, ctx, SIZE);
        if ready(app) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ready(app), "the page did not settle");
}

fn page(name: &str) -> (MonitorApp, egui::Context, String, PathBuf) {
    let root = super::samples_list::temp(name);
    let (script, _, _) = super::samples_list::fixture(&root);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.options.data_dir = root.clone();
    app.rules_ui.set_packs_for_test(Vec::new());
    app.open_library(crate::workspace::LibraryPage::Samples);
    until(&mut app, &ctx, |app| app.samples_page.is_loaded());
    (app, ctx, script, root)
}

fn on_screen(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
    let output = render(app, ctx, SIZE);
    texts(&output).into_iter().map(|(text, _)| text).collect()
}

fn has(texts: &[String], needle: &str) -> bool {
    texts.iter().any(|text| text.contains(needle))
}

fn tamper(root: &std::path::Path, sql: &str) {
    let connection =
        rusqlite::Connection::open(root.join("samples").join("library.sqlite")).unwrap();
    connection.execute_batch(sql).unwrap();
}

#[test]
fn the_tab_verifies_the_chain_and_marks_an_edited_entry() {
    let (mut app, ctx, script, root) = page("custody-tab");
    app.samples_page.open_detail(&script);
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_custody().is_some()
    });
    let (entries, ok, at) = app.samples_page.detail_custody().unwrap();
    assert!(entries >= 2 && ok && at.is_none());
    app.samples_page.show_detail_tab("custody");
    let shown = on_screen(&mut app, &ctx);
    assert!(has(&shown, "Log verified."), "{shown:?}");
    assert!(has(&shown, "Tamper-evident"), "{shown:?}");
    assert!(!has(&shown, "unverified"));

    // Edit the first entry on disk, then Verify (read and check again).
    tamper(
        &root,
        "UPDATE custody_entry SET by='someone' WHERE seq=1 AND sha256=(SELECT sha256 FROM sample WHERE name='install.sh')",
    );
    app.samples_page.refresh();
    until(&mut app, &ctx, |app| {
        app.samples_page
            .detail_custody()
            .is_some_and(|(_, ok, _)| !ok)
    });
    assert_eq!(app.samples_page.detail_custody().unwrap().2, Some(1));
    let shown = on_screen(&mut app, &ctx);
    assert!(has(&shown, "Entry 1 changed."), "{shown:?}");
    assert!(has(&shown, "changed") && has(&shown, "unverified"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_global_log_filters_by_kind_and_text_and_flags_a_broken_library() {
    let (mut app, ctx, script, root) = page("custody-all");
    app.samples_page.open_custody_all();
    until(&mut app, &ctx, |app| {
        app.samples_page
            .custody_all_ref()
            .is_some_and(|view| view.probe().is_some())
    });
    let (rows, samples, ok) = app.samples_page.custody_all_mut().unwrap().probe().unwrap();
    assert!(rows >= 3 && samples == 3 && ok);
    let shown = on_screen(&mut app, &ctx);
    assert!(has(&shown, "All logs verified."), "{shown:?}");
    assert!(has(&shown, "install.sh"));

    let view = app.samples_page.custody_all_mut().unwrap();
    view.set_query("notes.txt");
    let narrowed = view.visible();
    assert!(narrowed > 0 && narrowed < rows);
    view.set_query("");
    view.toggle_kind("edited");
    until(&mut app, &ctx, |app| {
        app.samples_page
            .custody_all_ref()
            .and_then(|view| view.probe())
            .is_some_and(|(now, _, _)| now < rows)
    });
    // A log removed behind the app's back.
    tamper(
        &root,
        &format!("DELETE FROM custody_entry WHERE sha256='{script}'"),
    );
    app.samples_page.custody_all_mut().unwrap().refresh();
    until(&mut app, &ctx, |app| {
        app.samples_page
            .custody_all_ref()
            .and_then(|view| view.probe())
            .is_some_and(|(_, _, ok)| !ok)
    });
    let shown = on_screen(&mut app, &ctx);
    assert!(has(&shown, "did not verify"), "{shown:?}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_export_is_written_checked_and_noted_in_the_log() {
    let (mut app, ctx, script, root) = page("custody-export");
    app.samples_page.open_detail(&script);
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_custody().is_some()
    });
    let before = app.samples_page.detail_custody().unwrap().0;
    app.samples_page.open_export_for_test();
    let out = root.join("exports").join("record.json");
    {
        let dialog = app.samples_page.export_mut().unwrap();
        dialog.set_format(ExportFormat::Json);
        dialog.set_destination(&out);
        dialog.begin(&ctx, &root);
    }
    until(&mut app, &ctx, |app| {
        app.samples_page
            .export_ref()
            .is_some_and(|dialog| dialog.outcome().is_some())
    });
    let done = app.samples_page.export_mut().unwrap().outcome().cloned();
    let done = done.unwrap().unwrap();
    assert!(done.verified && done.path == out);
    let checked = verify_record(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(checked.check.ok());
    assert!(out.with_file_name("verify-custody.py").is_file());
    // The window reads the log again and lists the export.
    until(&mut app, &ctx, |app| {
        app.samples_page
            .detail_custody()
            .is_some_and(|(entries, ok, _)| entries == before + 1 && ok)
    });
    let _ = std::fs::remove_dir_all(root);
}
