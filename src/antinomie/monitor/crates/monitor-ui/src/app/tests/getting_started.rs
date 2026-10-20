// SPDX-License-Identifier: MIT
//! Help > Getting started: when it opens, what it remembers, the install
//! command and the dependency list.
use super::*;
use crate::getting_started::Step;
use antinomie_monitor_core::dependencies::{
    self, Check, Dependency, KvmAdvice, PackageManager, Report,
};

const SIZE: egui::Vec2 = egui::vec2(1280.0, 900.0);

/// An app whose data folder is empty and that has heard from its backend.
fn fresh_app(name: &str) -> (MonitorApp, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "ant-getting-started-{name}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut app = app();
    app.options.data_dir = root.clone();
    app.getting_started.snapshot_seen = true;
    (app, root)
}

fn settle(app: &mut MonitorApp) {
    // The dependency check runs on a worker; wait for it to finish. The bound
    // only catches a hang: it runs host tools, which a loaded machine delays.
    let deadline = Instant::now() + Duration::from_secs(120);
    while app.dependencies.checking() {
        app.dependencies.poll();
        assert!(Instant::now() < deadline, "dependency check did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn check(dependency: Dependency, name: &'static str, missing: bool) -> Check {
    Check {
        dependency,
        name,
        purpose: "test",
        problem: missing.then(|| format!("{name} is missing or not executable")),
        hint: "",
        optional: !matches!(dependency, Dependency::Qemu | Dependency::Curl),
        wrong_version: false,
    }
}

/// Click the lowest text on screen that reads `label`.
fn click_lowest_label(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2, label: &str) {
    for _ in 0..3 {
        render(app, ctx, size);
    }
    let visible = texts(&render(app, ctx, size));
    let pos = visible
        .iter()
        .filter(|(text, _)| text == label)
        .max_by(|a, b| a.1.center().y.total_cmp(&b.1.center().y))
        .unwrap_or_else(|| panic!("missing {label}: {visible:?}"))
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

fn shown(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
    for _ in 0..3 {
        render(app, ctx, SIZE);
    }
    texts(&render(app, ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

#[test]
fn a_fresh_data_dir_opens_it_once_at_launch() {
    let (mut app, root) = fresh_app("fresh");
    app.getting_started_tick();
    assert!(app.getting_started.open);
    assert!(app.settings.getting_started.seen);
    // Closed by the user, it stays closed on later frames and launches.
    app.getting_started.open = false;
    app.getting_started_tick();
    assert!(!app.getting_started.open);
    let saved = serde_json::to_string(&app.settings).unwrap();
    let (mut later, _) = fresh_app("again");
    later.settings = serde_json::from_str(&saved).unwrap();
    later.getting_started_tick();
    assert!(!later.getting_started.open);
    settle(&mut app);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_vm_a_base_or_a_finished_flag_keeps_it_closed() {
    let (mut with_vm, _) = fresh_app("vm");
    with_vm.snapshot.vms.push(VmConfig::default());
    with_vm.getting_started_tick();
    assert!(!with_vm.getting_started.open);

    let (mut with_base, _) = fresh_app("base");
    with_base.snapshot.bases.push(test_base("base", true));
    with_base.getting_started_tick();
    assert!(!with_base.getting_started.open);

    let (mut finished, _) = fresh_app("finished");
    finished.settings.getting_started.finished = true;
    finished.getting_started_tick();
    assert!(!finished.getting_started.open);

    let (mut off, _) = fresh_app("off");
    off.settings.getting_started.dont_show = true;
    off.getting_started_tick();
    assert!(!off.getting_started.open);
}

#[test]
fn it_waits_for_the_backend_before_judging_a_first_launch() {
    let (mut app, _) = fresh_app("wait");
    app.getting_started.snapshot_seen = false;
    app.getting_started_tick();
    assert!(!app.getting_started.open && !app.getting_started.decided);
    app.getting_started.snapshot_seen = true;
    app.snapshot.bases_checking = true;
    app.getting_started_tick();
    assert!(!app.getting_started.open && !app.getting_started.decided);
    // The listing finds a base: this is not a first launch.
    app.snapshot.bases_checking = false;
    app.snapshot.bases.push(test_base("base", true));
    app.getting_started_tick();
    assert!(app.getting_started.decided && !app.getting_started.open);
}

#[test]
fn the_help_menu_reopens_it_at_any_time() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("help");
    app.settings.getting_started.finished = true;
    app.settings.getting_started.dont_show = true;
    app.getting_started_tick();
    assert!(!app.getting_started.open);
    click_label(&mut app, &ctx, SIZE, "Help");
    click_label(&mut app, &ctx, SIZE, "Getting started");
    assert!(app.getting_started.open);
    let text = shown(&mut app, &ctx);
    for step in Step::ALL {
        assert!(
            text.iter().any(|label| label.ends_with(step.title())),
            "{} missing: {text:?}",
            step.title()
        );
    }
    // Escape closes it like every other window.
    press(
        &mut app,
        &ctx,
        SIZE,
        egui::Key::Escape,
        egui::Modifiers::NONE,
    );
    assert!(!app.getting_started.open);
    settle(&mut app);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn opening_it_reads_the_host_again_and_does_not_open_the_dependencies_window() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("recheck");
    app.snapshot.bases.push(test_base("installed", true));
    app.open_getting_started();
    assert!(app.dependencies.checking());
    settle(&mut app);
    assert!(!app.dependencies.open, "a quiet recheck never opens it");
    let text = shown(&mut app, &ctx);
    assert!(
        text.iter().any(|label| label.contains("is installed")),
        "an installed base shows as done: {text:?}"
    );
    let facts = app.getting_started_facts();
    assert_eq!(facts.bases, 1);
    assert!(facts.dependencies_ready.is_some());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn skipping_and_finishing_are_remembered() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("skip");
    app.getting_started.open = true;
    click_label(&mut app, &ctx, SIZE, "Skip this step");
    assert!(app.settings.getting_started.is_skipped(Step::Base));
    assert_eq!(app.getting_started.step, Step::Vm);
    click_label(&mut app, &ctx, SIZE, "Next");
    assert_eq!(app.getting_started.step, Step::Dependencies);
    app.getting_started.step = Step::Finish;
    // "Finish" is also the last step's tab: the button is the lower one.
    click_lowest_label(&mut app, &ctx, SIZE, "Finish");
    assert!(app.settings.getting_started.finished);
    assert!(!app.getting_started.open, "it never blocks the app");
    // Saved with the other settings and read back at the next launch.
    let saved = serde_json::to_string(&app.settings).unwrap();
    let back: Settings = serde_json::from_str(&saved).unwrap();
    assert!(back.getting_started.finished);
    assert!(back.getting_started.is_skipped(Step::Base));
    assert_eq!(back.getting_started.remembered_step(), Step::Finish);
    assert!(!back.getting_started.opens_on_launch(0, 0));
    settle(&mut app);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn dont_show_again_is_remembered_and_the_window_can_still_be_closed() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("never");
    app.getting_started.open = true;
    click_label(&mut app, &ctx, SIZE, "Don't show again");
    assert!(app.settings.getting_started.dont_show);
    app.getting_started.open = false;
    let back: Settings =
        serde_json::from_str(&serde_json::to_string(&app.settings).unwrap()).unwrap();
    assert!(!back.getting_started.opens_on_launch(0, 0));
    let _ = std::fs::remove_dir_all(root);
}

fn report(checks: Vec<Check>, kvm: KvmAdvice) -> Report {
    Report {
        checks,
        package_manager: Some(PackageManager::Apt),
        kvm,
    }
}

#[test]
fn the_dependency_step_lists_the_file_chooser_and_one_install_command() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("deps");
    app.dependencies =
        crate::dependencies_window::DependenciesWindow::with_report_for_test(report(
            vec![
                check(Dependency::Qemu, "QEMU", true),
                check(Dependency::Tshark, "TShark", false),
                check(Dependency::Wireshark, "Wireshark", true),
                check(Dependency::FileChooser, "File chooser (Zenity)", true),
            ],
            KvmAdvice::Ready,
        ));
    app.getting_started.open = true;
    app.getting_started.step = Step::Dependencies;
    let text = shown(&mut app, &ctx);
    assert!(
        text.iter().any(|label| label == "File chooser (Zenity)"),
        "{text:?}"
    );
    assert!(text.iter().any(|label| label == "Found"), "{text:?}");
    assert!(text.iter().any(|label| label == "Missing"), "{text:?}");
    assert!(
        text.iter().any(|label| label == "Optional, not installed"),
        "{text:?}"
    );
    // Only the missing packages, once, and no group step.
    assert!(
        text.iter()
            .any(|label| label == "sudo apt install qemu-system-x86 wireshark zenity"),
        "{text:?}"
    );
    assert!(
        !text.iter().any(|label| label.contains("usermod")),
        "{text:?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_kvm_group_step_shows_only_when_kvm_needs_it() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    for (kvm, expected) in [
        (KvmAdvice::AddToGroup, true),
        (KvmAdvice::SignInAgain, false),
        (KvmAdvice::NoDevice, false),
        (KvmAdvice::Ready, false),
    ] {
        let (mut app, root) = fresh_app("kvm");
        app.dependencies = crate::dependencies_window::DependenciesWindow::with_report_for_test(
            report(vec![check(Dependency::Curl, "curl", true)], kvm),
        );
        app.getting_started.open = true;
        app.getting_started.step = Step::Dependencies;
        let text = shown(&mut app, &ctx);
        let command = text
            .iter()
            .find(|label| label.starts_with("sudo apt install"));
        assert_eq!(
            command.map(|label| label.ends_with("sudo usermod -aG kvm $USER")),
            Some(expected),
            "{kvm:?}: {text:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn the_app_dependencies_window_lists_the_explorer_file_chooser() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    // The real check, so the entry cannot be dropped from `check` unnoticed.
    let checked = dependencies::check(&BackendOptions::default());
    let chooser = checked
        .checks
        .iter()
        .find(|check| check.dependency == Dependency::FileChooser)
        .expect("the file chooser is checked");
    assert!(chooser.optional && chooser.purpose.contains("Explorer"));
    let name = chooser.name;
    let (mut app, root) = fresh_app("chooser");
    // A report that has this one entry, so that the window's scroll area
    // shows it whatever this computer has installed.
    app.dependencies =
        crate::dependencies_window::DependenciesWindow::with_report_for_test(report(
            vec![check(Dependency::FileChooser, name, true)],
            KvmAdvice::Ready,
        ));
    app.dependencies.open = true;
    let text = shown(&mut app, &ctx);
    assert!(text.iter().any(|label| label == name), "{text:?}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_vm_step_creates_a_vm_with_the_new_vm_defaults() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("vmstep");
    app.snapshot.bases.push(test_base("base", true));
    app.getting_started.open = true;
    app.getting_started.step = Step::Vm;
    click_label(&mut app, &ctx, SIZE, "Create VM");
    let created = app.submitted.iter().find_map(|command| match command {
        Command::Create(vm) => Some(vm.clone()),
        _ => None,
    });
    let vm = created.expect("a Create command was sent");
    assert_eq!(vm.base_identity.as_deref(), Some("base"));
    assert!(vm.stealth.preset != antinomie_monitor_core::stealth::StealthPreset::Transparent);
    assert!(vm.ram_mib >= 256 && vm.cpus >= 1);
    assert!(app.getting_started.vm_pending.is_some());
    // The New VM dialog's own draft was not touched.
    assert!(!app.create_open);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn install_all_missing_queues_only_missing_tools_and_one_runs_at_a_time() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("tools");
    let tool = |id: &str, installed: bool| antinomie_monitor_core::analysis_tools::ToolStatus {
        id: id.into(),
        name: id.into(),
        purpose: "test".into(),
        version: "1".into(),
        size: 1024,
        system: None,
        installed: installed.then(|| "1".into()),
    };
    // The first-launch rule has been applied; it would recheck the host.
    app.getting_started.decided = true;
    app.snapshot.analysis_tools = vec![tool("have", true), tool("one", false), tool("two", false)];
    app.getting_started.open = true;
    app.getting_started.step = Step::Tools;
    click_label(&mut app, &ctx, SIZE, "Install all missing");
    app.getting_started_tick();
    let installs = |app: &MonitorApp| {
        app.submitted
            .iter()
            .filter_map(|command| match command {
                Command::InstallTool { id } => Some(id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(installs(&app), ["one"]);
    // The second waits until the first reports it has finished.
    app.getting_started_tick();
    assert_eq!(installs(&app), ["one"]);
    app.snapshot.tool_install = Some(antinomie_monitor_core::analysis_tools::ToolInstall {
        id: "one".into(),
        name: "one".into(),
        stage: "done".into(),
        received: 1,
        total: 1,
        finished: true,
        error: None,
    });
    app.getting_started_tick();
    assert_eq!(installs(&app), ["one", "two"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_rules_step_offers_catalog_packs_and_downloads_only_when_allowed() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("rules");
    app.rules_ui
        .set_catalog_for_test(antinomie_monitor_core::ruleset::Catalog {
            schema: antinomie_monitor_core::ruleset::CATALOG_SCHEMA,
            packs: vec![antinomie_monitor_core::ruleset::PackEntry {
                id: "yara-test".into(),
                engine: "yara".into(),
                name: "Test YARA pack".into(),
                version: "1".into(),
                upstream_revision: "r".into(),
                upstream_url: "https://example.invalid/".into(),
                download_url: "https://example.invalid/pack.zip".into(),
                sha256: "0".repeat(64),
                size: 2048,
                app: "0.7.0".into(),
                engine_requirement: "any".into(),
                rules: 7,
                helpers: 0,
                license: "MIT".into(),
                evidence: Vec::new(),
                limits: Vec::new(),
            }],
            sources: Vec::new(),
        });
    app.getting_started.open = true;
    app.getting_started.step = Step::Rules;
    let text = shown(&mut app, &ctx);
    assert!(
        text.iter().any(|label| label == "Test YARA pack"),
        "{text:?}"
    );
    assert!(
        text.iter()
            .any(|label| label.starts_with("Downloads are off")),
        "nothing is contacted until downloads are allowed: {text:?}"
    );
    assert!(app.getting_started.rule_queue.is_empty());
    app.settings.outbound_catalog = true;
    click_label(&mut app, &ctx, SIZE, "Download selected");
    assert_eq!(app.getting_started.rule_queue, ["yara-test"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_rules_step_has_engine_tabs_and_a_pack_with_terms_starts_unticked() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("rules-tabs");
    let (mut value, _) = crate::rules_window::source_tests::catalog_value();
    value["packs"][0]["notices"] = serde_json::json!(["Read the terms before you download."]);
    let catalog = antinomie_monitor_core::ruleset::validate_catalog(&value).unwrap();
    app.rules_ui.set_catalog_for_test(catalog);
    app.getting_started.open = true;
    app.getting_started.step = Step::Rules;
    let text = shown(&mut app, &ctx);
    for engine in ["YARA", "IDS", "Sigma"] {
        assert!(
            text.iter().any(|label| label == engine),
            "{engine}: {text:?}"
        );
    }
    assert!(text.iter().any(|label| label == "Forge Core"), "{text:?}");
    assert!(text.iter().any(|label| label.starts_with("Read the terms")));
    // Another engine's tab shows its own packs.
    click_label(&mut app, &ctx, SIZE, "IDS");
    let text = shown(&mut app, &ctx);
    assert!(!text.iter().any(|label| label == "Forge Core"), "{text:?}");
    assert!(text
        .iter()
        .any(|label| label.contains("no pack for this engine")));
    click_label(&mut app, &ctx, SIZE, "YARA");
    // Terms to read: unticked, so even with downloads allowed nothing queues
    // until the pack is ticked on purpose.
    assert_eq!(app.getting_started.rules_chosen, Some(Default::default()));
    app.settings.outbound_catalog = true;
    click_label(&mut app, &ctx, SIZE, "Download selected");
    assert!(app.getting_started.rule_queue.is_empty());
    click_label(&mut app, &ctx, SIZE, "Forge Core");
    click_label(&mut app, &ctx, SIZE, "Download selected");
    assert_eq!(app.getting_started.rule_queue, ["forge-core"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_rules_step_still_asks_before_any_download() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let (mut app, root) = fresh_app("rules-consent");
    app.getting_started.open = true;
    app.getting_started.step = Step::Rules;
    assert!(!app.settings.outbound_catalog);
    let text = shown(&mut app, &ctx);
    assert!(text
        .iter()
        .any(|label| label.starts_with("Downloads are off")));
    click_label(&mut app, &ctx, SIZE, "Check the catalog");
    assert!(
        !app.rules_ui.is_busy(),
        "checking needs the permission first"
    );
    click_label(&mut app, &ctx, SIZE, "Allow downloads");
    assert!(app.settings.outbound_catalog);
    let _ = std::fs::remove_dir_all(root);
}
