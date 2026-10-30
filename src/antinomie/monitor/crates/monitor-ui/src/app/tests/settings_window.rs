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
fn the_text_size_default_is_18_and_old_settings_still_at_16_move_once() {
    assert_eq!(Settings::default().font_size, 18.0);
    // Saved before settings had a version: no version field, size 16.
    let mut old: Settings = serde_json::from_str(r#"{"font_size":16.0}"#).unwrap();
    assert_eq!(old.settings_version, 0);
    old.migrate();
    assert_eq!((old.font_size, old.settings_version), (18.0, 1));
    // The person picks 16 again afterwards: it stays.
    old.font_size = 16.0;
    old.migrate();
    assert_eq!(old.font_size, 16.0);
    // A size the person chose before the migration stays too.
    let mut chosen: Settings = serde_json::from_str(r#"{"font_size":14.0}"#).unwrap();
    chosen.migrate();
    assert_eq!(chosen.font_size, 14.0);
    // Settings saved by this version carry the version.
    let saved = serde_json::to_string(&Settings::default()).unwrap();
    let mut current: Settings = serde_json::from_str(&saved).unwrap();
    assert_eq!(current.settings_version, 1);
    current.font_size = 16.0;
    current.migrate();
    assert_eq!(current.font_size, 16.0);
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
        (SettingsPage::NetworkRoutes, "Default route"),
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

#[test]
fn the_graph_spacing_defaults_to_equal_events_and_the_choice_is_kept() {
    use crate::triage::GraphSpacing;
    assert_eq!(Settings::default().graph_spacing, GraphSpacing::Events);
    // A settings file from before the choice existed gets the default.
    let old: Settings = serde_json::from_str(r#"{"bundle": "", "quota_gib": 4}"#).unwrap();
    assert_eq!(old.graph_spacing, GraphSpacing::Events);
    // The choice is saved by name and read back.
    let chosen = Settings {
        graph_spacing: GraphSpacing::Time,
        ..Settings::default()
    };
    let text = serde_json::to_string(&chosen).unwrap();
    assert!(text.contains(r#""graph_spacing":"time""#), "{text}");
    assert_eq!(
        serde_json::from_str::<Settings>(&text)
            .unwrap()
            .graph_spacing,
        GraphSpacing::Time
    );
}

#[test]
fn the_routes_page_shows_every_route_and_says_openvpn_is_unsupported() {
    let ctx = context();
    let mut app = app();
    // The page by itself on a tall screen: in the Settings window its lower
    // sections are scrolled out of view.
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 2400.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.routes_page(ui));
        },
    );
    let visible = texts(&output);
    for label in [
        "Default route",
        "Tor",
        "VPN (WireGuard)",
        "SOCKS5 proxy",
        "InetSim (fake services)",
        "Configuration file",
        "Password",
        "Save routes",
    ] {
        assert!(has(&visible, label), "{label}: {visible:?}");
    }
    assert!(visible.iter().any(|(text, _)| text.contains("OpenVPN")));
    // Nothing is saved until Save routes is pressed, and nothing changed yet.
    assert!(!app.routes.dirty_for_tests());
}

#[test]
fn the_routes_page_shows_install_version_and_status_of_tor_and_wireproxy() {
    use antinomie_monitor_core::analysis_tools::ToolStatus;
    let ctx = context();
    let mut app = app();
    let tool = |id: &str, name: &str, version: &str, installed: Option<&str>| ToolStatus {
        id: id.into(),
        name: name.into(),
        purpose: "a route program".into(),
        version: version.into(),
        size: 4_000_000,
        system: None,
        installed: installed.map(str::to_owned),
        installed_path: installed.map(|_| "/home/analyst/tools/tool".to_owned()),
    };
    app.snapshot.analysis_tools = vec![
        tool("tor", "Tor", "0.4.9.14 (Expert Bundle 15.0.26)", None),
        tool("wireproxy", "wireproxy", "1.1.3", Some("1.1.3")),
    ];
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 2400.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.routes_page(ui));
        },
    );
    let visible = texts(&output);
    // Tor is not installed: Install with its version; wireproxy is: its
    // version and Remove. The default Tor mode is Antinomie's own tor.
    assert!(
        visible
            .iter()
            .any(|(text, _)| text == "Install 0.4.9.14 · 3.8 MB"),
        "{visible:?}"
    );
    assert!(has(&visible, "Not installed"), "{visible:?}");
    assert!(
        has(&visible, "Installed by Antinomie (1.1.3)"),
        "{visible:?}"
    );
    assert!(has(&visible, "Remove"), "{visible:?}");
    // Where Antinomie's copy is saved, and no exact byte count on the button.
    assert!(has(&visible, "/home/analyst/tools/tool"), "{visible:?}");
    assert!(
        !visible.iter().any(|(text, _)| text.contains(" bytes")),
        "{visible:?}"
    );
    assert!(
        visible
            .iter()
            .any(|(text, _)| text.contains("Antinomie runs its own tor")),
        "{visible:?}"
    );
    assert!(
        has(&visible, "Use a SOCKS address (a Tor you already run)"),
        "{visible:?}"
    );
}

#[test]
fn the_routes_page_is_in_the_settings_list_and_opens() {
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    let size = egui::vec2(1280.0, 820.0);
    let visible = shown(&mut app, &ctx, size);
    assert!(has(&visible, "Network routes"), "{visible:?}");
    click_label(&mut app, &ctx, size, "Network routes");
    assert_eq!(app.settings_page, SettingsPage::NetworkRoutes);
    let visible = shown(&mut app, &ctx, size);
    assert!(
        has(&visible, "Default route") && has(&visible, "Tor"),
        "{visible:?}"
    );
}

#[test]
fn the_run_form_names_the_fixed_network_of_a_vm_that_is_not_routed() {
    use antinomie_monitor_core::{route::RouteKind, VmNetwork};
    let ctx = context();
    let mut request = ExecRequest {
        route: Some(RouteKind::Tor),
        ..ExecRequest::default()
    };
    let _ = ctx.run(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            crate::route_ui::selector(
                ui,
                &mut request,
                &crate::route_ui::RouteChoice::fixed(VmNetwork::Nat),
            )
        });
    });
    assert_eq!(request.route, None);
}
