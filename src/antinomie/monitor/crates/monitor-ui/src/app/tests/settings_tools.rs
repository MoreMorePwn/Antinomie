// SPDX-License-Identifier: GPL-3.0-only
//! Settings > Analysis tools and the tool rows: a time for each tool with a
//! reset that names the default, and the choice of Antinomie's own copy of a tool the
//! system has.
use super::*;
use crate::app::settings_window::SettingsPage;
use antinomie_monitor_core::{analysis_tools::ToolStatus, TimedTool};

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

fn has(visible: &[(String, egui::Rect)], label: &str) -> bool {
    visible.iter().any(|(text, _)| text == label)
}

#[test]
fn each_tool_has_a_time_with_its_default_and_a_reset() {
    let ctx = context();
    let size = egui::vec2(1280.0, 800.0);
    let mut app = app();
    app.settings_open = true;
    app.settings_page = SettingsPage::AnalysisTools;
    app.snapshot.analysis_tools = vec![ToolStatus {
        id: "capa".into(),
        name: "capa".into(),
        version: "1".into(),
        installed: Some("1".into()),
        ..Default::default()
    }];
    let visible = shown(&mut app, &ctx, size);
    // The defaults are what each tool had before.
    for (tool, default) in [
        (TimedTool::Capa, 240),
        (TimedTool::Binwalk, 180),
        (TimedTool::Yara, 60),
    ] {
        assert_eq!(tool.default_seconds(), default);
        // The default is in the Reset button's tooltip, not on the page.
        assert!(
            !visible
                .iter()
                .any(|(text, _)| text.starts_with("Default (")),
            "{visible:?}"
        );
    }
    assert_eq!(
        app.settings.analysis_limits.timeouts.get(TimedTool::Capa),
        0
    );
    // A set time is kept in the settings, and Reset brings the default back.
    app.settings
        .analysis_limits
        .timeouts
        .set(TimedTool::Capa, 300);
    shown(&mut app, &ctx, size);
    click_label(&mut app, &ctx, size, "Reset");
    assert_eq!(
        app.settings.analysis_limits.timeouts.get(TimedTool::Capa),
        0
    );
}

#[test]
fn the_times_persist_and_old_settings_still_load() {
    let old: Settings = serde_json::from_str(r#"{"quota_gib": 4}"#).unwrap();
    assert!(old.analysis_limits.timeouts == Default::default());
    assert!(old.own_tools.is_empty() && old.shortcuts.is_empty());
    let mut settings = Settings::default();
    settings.analysis_limits.timeouts.set(TimedTool::Floss, 900);
    settings
        .analysis_limits
        .timeouts
        .set(TimedTool::Ghidra, 1200);
    settings.own_tools.insert("capa".into());
    let saved = serde_json::to_string(&settings).unwrap();
    let loaded: Settings = serde_json::from_str(&saved).unwrap();
    assert_eq!(loaded.analysis_limits.timeouts.get(TimedTool::Floss), 900);
    assert_eq!(loaded.analysis_limits.timeouts.get(TimedTool::Ghidra), 1200);
    assert_eq!(loaded.analysis_limits.timeouts.get(TimedTool::Capa), 0);
    assert!(loaded.own_tools.contains("capa"));
}

#[test]
fn a_tool_the_system_has_offers_its_own_copy_and_the_choice_is_kept() {
    let ctx = context();
    let size = egui::vec2(1280.0, 800.0);
    let mut app = app();
    app.snapshot.analysis_tools = vec![
        ToolStatus {
            id: "capa".into(),
            name: "capa".into(),
            version: "9".into(),
            size: 1024,
            system: Some("/usr/bin/capa".into()),
            ..Default::default()
        },
        ToolStatus {
            id: "floss".into(),
            name: "FLOSS".into(),
            version: "3".into(),
            size: 1024,
            ..Default::default()
        },
    ];
    app.open_library(crate::workspace::LibraryPage::Tools);
    let visible = shown(&mut app, &ctx, size);
    // Only the tool the system has gets the choice, once.
    let boxes = visible
        .iter()
        .filter(|(text, _)| text == "Use Antinomie's own copy instead")
        .count();
    assert_eq!(boxes, 1, "{visible:?}");
    assert!(app.settings.own_tools.is_empty());
    click_label(&mut app, &ctx, size, "Use Antinomie's own copy instead");
    assert!(
        app.settings.own_tools.contains("capa"),
        "{:?}",
        app.settings.own_tools
    );
    // Chosen and not installed: the row offers the install.
    let visible = shown(&mut app, &ctx, size);
    assert!(
        visible
            .iter()
            .filter(|(text, _)| text.starts_with("Install 9"))
            .count()
            == 1,
        "{visible:?}"
    );
}

#[test]
fn each_detection_engine_has_a_time_with_its_default_and_a_reset() {
    use antinomie_monitor_core::analysis::detection::EngineTime;
    let ctx = context();
    let size = egui::vec2(1280.0, 800.0);
    let mut app = app();
    app.settings_open = true;
    app.settings_page = SettingsPage::Detection;
    let mut visible = shown(&mut app, &ctx, size);
    // The Detection page is short enough to show every engine's line.
    for (engine, default) in [
        (EngineTime::Yara, 100),
        (EngineTime::Ids, 100),
        (EngineTime::Sigma, 110),
        (EngineTime::Tshark, 300),
    ] {
        assert_eq!(engine.default_seconds(), default);
        assert!(
            has(&visible, engine.label()),
            "{}: {visible:?}",
            engine.label()
        );
    }
    assert!(
        !visible
            .iter()
            .any(|(text, _)| text.starts_with("Default (")),
        "{visible:?}"
    );
    assert_eq!(
        app.triage
            .detection_settings()
            .timeouts
            .get(EngineTime::Yara),
        0
    );
    // A set time travels with the detection settings that are saved, and
    // Reset brings the default back.
    app.triage
        .detection_settings()
        .timeouts
        .set(EngineTime::Yara, 240);
    visible = shown(&mut app, &ctx, size);
    assert!(has(&visible, "Reset"));
    let saved = serde_json::to_string(app.triage.detection_settings()).unwrap();
    let back: antinomie_monitor_core::analysis::detection::Settings =
        serde_json::from_str(&saved).unwrap();
    assert_eq!(back.timeouts.get(EngineTime::Yara), 240);
    click_label(&mut app, &ctx, size, "Reset");
    assert_eq!(
        app.triage
            .detection_settings()
            .timeouts
            .get(EngineTime::Yara),
        0
    );
}
