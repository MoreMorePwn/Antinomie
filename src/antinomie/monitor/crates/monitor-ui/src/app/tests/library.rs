// SPDX-License-Identifier: GPL-3.0-only
//! The sidebar's Library section and the pages it opens in the main area.
use super::*;
use antinomie_monitor_core::ruleset::InstalledPack;

const SIZE: egui::Vec2 = egui::vec2(1280.0, 820.0);

pub(super) fn installed_pack(id: &str, engine: &str, enabled: bool) -> InstalledPack {
    InstalledPack {
        id: id.into(),
        engine: engine.into(),
        name: format!("Pack {id}"),
        version: "1".into(),
        enabled,
        sha256: String::new(),
        upstream_revision: String::new(),
        upstream_url: String::new(),
        license: "MIT".into(),
        evidence: Vec::new(),
        limits: Vec::new(),
        versions: vec!["1".into()],
        source: None,
        app: String::new(),
        engine_requirement: String::new(),
    }
}

fn settle(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<(String, egui::Rect)> {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    texts(&render(app, ctx, SIZE))
}

fn beside(shown: &[(String, egui::Rect)], name: &str) -> Vec<String> {
    let row = shown
        .iter()
        .find(|(text, _)| text == name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .1;
    shown
        .iter()
        .filter(|(text, rect)| {
            text != name
                && rect.left() > row.right()
                && rect.right() < 258.0
                && (rect.center().y - row.center().y).abs() < 6.0
        })
        .map(|(text, _)| text.clone())
        .collect()
}

#[test]
fn the_library_counts_images_and_installed_packs_and_tools_have_no_count() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.snapshot.bases = vec![test_base("a", true), test_base("b", true)];
    let shown = settle(&mut app, &ctx);
    assert_eq!(beside(&shown, "Base images"), ["2"]);
    assert_eq!(
        beside(&shown, "Detection rules"),
        ["…"],
        "before the registry is read"
    );
    assert!(beside(&shown, "Analysis tools").is_empty());
    app.rules_ui.set_packs_for_test(vec![
        installed_pack("one", "yara", true),
        installed_pack("two", "ids", false),
    ]);
    // Installed packs count, enabled or not.
    assert_eq!(
        beside(&settle(&mut app, &ctx), "Detection rules"),
        ["2 packs"]
    );
    app.rules_ui
        .set_packs_for_test(vec![installed_pack("one", "yara", true)]);
    assert_eq!(
        beside(&settle(&mut app, &ctx), "Detection rules"),
        ["1 pack"]
    );
}

#[test]
fn each_library_entry_opens_its_page_in_the_main_area() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.rules_ui.set_packs_for_test(Vec::new());
    let shown = settle(&mut app, &ctx);
    assert!(!shown.iter().any(|(text, _)| text == "Import base…"));
    click_label(&mut app, &ctx, SIZE, "Base images");
    let shown = settle(&mut app, &ctx);
    assert!(
        shown.iter().any(|(text, _)| text == "Import base…"),
        "{shown:?}"
    );
    click_label(&mut app, &ctx, SIZE, "Analysis tools");
    let shown = settle(&mut app, &ctx);
    assert!(shown
        .iter()
        .any(|(text, _)| text.starts_with("Static analysis uses these tools")));
    click_label(&mut app, &ctx, SIZE, "Detection rules");
    let shown = settle(&mut app, &ctx);
    assert!(shown.iter().any(|(text, _)| text == "YARA"), "{shown:?}");
    // Nothing opened a window.
    assert!(!app.download_open && !app.import_open);
}

#[test]
fn links_to_the_old_windows_open_the_pages() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.open_library(crate::workspace::LibraryPage::Tools);
    let shown = settle(&mut app, &ctx);
    assert!(shown
        .iter()
        .any(|(text, _)| text.starts_with("Static analysis uses these tools")));
    assert!(
        app.library_requests.is_empty(),
        "the workspace took the request"
    );
}
