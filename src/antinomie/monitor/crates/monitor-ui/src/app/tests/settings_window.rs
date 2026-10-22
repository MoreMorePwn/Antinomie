// SPDX-License-Identifier: GPL-3.0-only
//! The Settings window: a page list, one page at a time, a footer that stays
//! in view on a short screen, and the settings it keeps.
use super::*;
use crate::app::settings_window::SettingsPage;

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn shown(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2) -> Vec<(String, egui::Rect)> {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    texts(&render(app, ctx, size))
}

fn has(shown: &[(String, egui::Rect)], label: &str) -> bool {
    shown.iter().any(|(text, _)| text == label)
}

#[test]
fn address_lookup_defaults_to_tshark_geoip_only_and_is_kept() {
    use crate::triage::AddressLookup;
    assert_eq!(
        Settings::default().address_lookup,
        AddressLookup::Tshark,
        "the default is TShark GeoIP only"
    );
    let old: Settings = serde_json::from_str("{}").unwrap();
    assert_eq!(old.address_lookup, AddressLookup::Tshark);
    for mode in [
        AddressLookup::Tshark,
        AddressLookup::Whois,
        AddressLookup::TsharkThenWhois,
    ] {
        let settings = Settings {
            address_lookup: mode,
            ..Settings::default()
        };
        let saved = serde_json::to_string(&settings).unwrap();
        let loaded: Settings = serde_json::from_str(&saved).unwrap();
        assert_eq!(loaded.address_lookup, mode);
    }
}

#[test]
fn the_lookup_page_offers_the_three_modes_with_tshark_selected() {
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    app.settings_page = SettingsPage::NetworkLookup;
    let visible = shown(&mut app, &ctx, egui::vec2(1280.0, 820.0));
    for label in [
        "TShark GeoIP only",
        "dig and whois only",
        "TShark GeoIP, then dig and whois when unavailable",
    ] {
        assert!(has(&visible, label), "{label}: {visible:?}");
    }
    assert_eq!(
        app.settings.address_lookup,
        crate::triage::AddressLookup::Tshark
    );
}

#[test]
fn the_page_list_has_no_keyboard_page_and_each_page_shows_its_settings() {
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    let size = egui::vec2(1280.0, 820.0);
    let visible = shown(&mut app, &ctx, size);
    for page in SettingsPage::ALL {
        assert!(has(&visible, page.label()), "{}: {visible:?}", page.label());
    }
    assert!(!has(&visible, "Keyboard"));
    click_label(&mut app, &ctx, size, "Network lookup");
    assert_eq!(app.settings_page, SettingsPage::NetworkLookup);
    for (page, label) in [
        (SettingsPage::Appearance, "Theme"),
        (SettingsPage::Recording, "Process cores: default budget"),
        (
            SettingsPage::Detection,
            "Scan retained evidence when it is ready",
        ),
        (SettingsPage::NetworkLookup, "Address lookup"),
        (SettingsPage::AnalysisTools, "Manage tools…"),
        (SettingsPage::Disks, "Extraction limit"),
        (SettingsPage::Advanced, "Show FPS counter"),
    ] {
        app.settings_page = page;
        let visible = shown(&mut app, &ctx, size);
        assert!(
            has(&visible, label),
            "{label} on {}: {visible:?}",
            page.label()
        );
    }
}

#[test]
fn the_footer_and_the_page_stay_inside_a_short_screen() {
    for size in [egui::vec2(1280.0, 820.0), egui::vec2(1000.0, 700.0)] {
        for page in SettingsPage::ALL {
            let ctx = context();
            let mut app = app();
            app.settings_open = true;
            app.settings_page = page;
            let visible = shown(&mut app, &ctx, size);
            for button in ["Save settings", "Close"] {
                let rect = visible
                    .iter()
                    .find(|(text, _)| text == button)
                    .unwrap_or_else(|| panic!("{button} hidden on {page:?} at {size:?}"))
                    .1;
                assert!(
                    rect.bottom() <= size.y && rect.right() <= size.x,
                    "{button} off screen on {page:?} at {size:?}: {rect:?}"
                );
            }
            let window = ctx
                .memory(|memory| memory.area_rect(Dialog::Settings.window_id()))
                .expect("window");
            assert!(
                window.bottom() <= size.y && window.right() <= size.x,
                "{page:?} at {size:?}: {window:?}"
            );
        }
    }
}

#[test]
fn recording_and_detection_options_are_kept_in_the_saved_settings() {
    let settings = Settings {
        core_budget_mib: 96,
        timeout: 30,
        quota_gib: 8,
        automatic_detection: false,
        outbound_catalog: true,
        show_fps: true,
        disks: crate::disk_view::DiskSettings {
            dump_hash: false,
            ..Default::default()
        },
        ..Settings::default()
    };
    let saved = serde_json::to_string(&settings).unwrap();
    let loaded: Settings = serde_json::from_str(&saved).unwrap();
    assert_eq!(loaded.core_budget_mib, 96);
    assert_eq!(loaded.timeout, 30);
    assert_eq!(loaded.quota_gib, 8);
    assert!(!loaded.automatic_detection && loaded.outbound_catalog && loaded.show_fps);
    assert!(!loaded.disks.dump_hash);
}
