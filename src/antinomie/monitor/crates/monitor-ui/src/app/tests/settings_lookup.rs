// SPDX-License-Identifier: GPL-3.0-only
//! Settings > Network lookup: the database status shows only "Database found"
//! with the details in a tooltip, and the SOCKS5 password field is as wide as
//! the other fields of its form.
use super::*;
use antinomie_monitor_core::geoip::{Database, Kind, Origin, Status};

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

#[test]
fn the_database_details_are_only_in_the_tooltip() {
    let ctx = context();
    let status = Status {
        databases: vec![
            Database {
                path: PathBuf::from("/data/tools/geoip/dbip-asn-lite.mmdb"),
                kind: Kind::Asn,
                name: "DBIP-ASN-Lite (compat=GeoLite2-ASN)".into(),
                origin: Origin::Managed,
            },
            Database {
                path: PathBuf::from("/data/tools/geoip/dbip-country-lite.mmdb"),
                kind: Kind::Country,
                name: "DBIP-Country-Lite".into(),
                origin: Origin::Managed,
            },
        ],
        ..Status::default()
    };
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 400.0),
            )),
            ..Default::default()
        },
        |ui| {
            crate::tools_page::geoip_status(ui, Some(&status));
        },
    );
    let visible = texts(&output);
    assert!(visible.iter().any(|(text, _)| text == "Database found"));
    assert!(
        !visible
            .iter()
            .any(|(text, _)| text.contains("compat=") || text.contains(".mmdb")),
        "{visible:?}"
    );
    let none = Status::default();
    let output = ctx.run_ui(egui::RawInput::default(), |ui| {
        crate::tools_page::geoip_status(ui, Some(&none));
    });
    assert!(texts(&output).iter().any(|(text, _)| text == "No database"));
}

#[test]
fn the_socks5_password_is_as_wide_as_the_other_fields() {
    let ctx = context();
    let mut widths = Vec::new();
    let (mut text, mut other) = (String::new(), String::new());
    let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
        let host = ui.add(
            super::super::widgets::text_field(&mut other).desired_width(theme::edit_width(260.0)),
        );
        let password =
            super::super::dialogs::password_input_width(ui, &mut text, "wide_test", 260.0);
        widths.push((host.rect.width(), password.rect.width()));
    });
    let (host, password) = widths[0];
    assert!((password - host).abs() < 0.5, "{host} {password}");
}
