// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use antinomie_monitor_core::ruleset;

#[test]
fn startup_reloads_local_selection_without_opening_the_manager() {
    let root = std::env::temp_dir().join(format!(
        "ant-start-rules-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("fixture.yar");
    // Test-only rule, never bundled or used as a production starter collection.
    std::fs::write(
        &file,
        "rule StartupKept { condition: true }\nrule StartupDisabled { condition: false }\n",
    )
    .unwrap();
    let enabled = ruleset::import_group(&root, "Enabled fixture", "yara", &file).unwrap();
    let disabled = ruleset::import_group(&root, "Disabled fixture", "yara", &file).unwrap();
    ruleset::set_group_enabled(&root, &disabled, false).unwrap();
    let rule = ruleset::group_index(&root, &enabled)
        .unwrap()
        .into_iter()
        .find(|rule| rule.name == "StartupDisabled")
        .unwrap();
    ruleset::set_rule_enabled(&root, &format!("group:{enabled}"), &rule.id, false).unwrap();
    let before = ruleset::load_registry(&root).unwrap();
    let ctx = egui::Context::default();
    for _ in 0..2 {
        // Each app starts with persisted settings that omit the runtime root.
        let mut app = app();
        app.options.data_dir = root.clone();
        app.settings.triage_detection.rules_root.clear();
        app.configure_detection();
        assert_eq!(
            app.triage.detection_settings().rules_root,
            root.display().to_string()
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while !app.rules_summary.contains("Enabled fixture") {
            app.poll_rules(&ctx);
            assert!(Instant::now() < deadline, "{}", app.rules_summary);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.library_requests.is_empty());
        assert!(!app.rules_summary.contains("Disabled fixture"));
        assert!(app.rules_generation > 0);
        let selection = ruleset::snapshot(&root, "yara", &ruleset::ToolConfig::default()).unwrap();
        assert_eq!(
            selection.enabled_rules, 1,
            "saved per-rule and group toggles govern the effective scan"
        );
        assert!(app.settings.outbound_catalog == Settings::default().outbound_catalog);
    }
    let after = ruleset::load_registry(&root).unwrap();
    assert_eq!(after.disabled, before.disabled);
    assert_eq!(
        after.groups.iter().map(|g| g.enabled).collect::<Vec<_>>(),
        vec![true, false]
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unreadable_registry_is_visible_and_not_retried_each_frame() {
    let root = std::env::temp_dir().join(format!(
        "ant-bad-rules-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("rules")).unwrap();
    std::fs::write(root.join("rules/registry.json"), b"{").unwrap();
    let mut app = app();
    app.options.data_dir = root.clone();
    let ctx = egui::Context::default();
    let deadline = Instant::now() + Duration::from_secs(60);
    while app.rules_summary != "Rules registry unavailable" {
        app.poll_rules(&ctx);
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let generation = app.rules_generation;
    for _ in 0..20 {
        app.poll_rules(&ctx);
    }
    assert_eq!(
        app.rules_generation, generation,
        "do not start an unbounded retry loop"
    );
    assert!(app.library_requests.is_empty());
    std::fs::remove_dir_all(root).unwrap();
}
