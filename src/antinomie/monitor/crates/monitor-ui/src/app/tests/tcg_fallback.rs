// SPDX-License-Identifier: GPL-3.0-only
//! A host without KVM: the Use TCG actions, the Warning level and the one
//! toast when a VM falls back to TCG.
use super::*;
use antinomie_monitor_core::{
    dependencies::{Check, Dependency, Report},
    AcceleratorUsed, StartSettings, VmAcceleration, VmCpuModel,
};

const SIZE: egui::Vec2 = egui::vec2(1280.0, 900.0);
const NO_KVM: &str = "cannot open /dev/kvm: No such file or directory (os error 2)";

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn check(dependency: Dependency, name: &'static str, problem: Option<&str>) -> Check {
    Check {
        dependency,
        name,
        purpose: "test",
        problem: problem.map(str::to_owned),
        hint: "test fix",
        optional: false,
        wrong_version: false,
    }
}

fn without_kvm() -> crate::dependencies_window::DependenciesWindow {
    crate::dependencies_window::DependenciesWindow::with_report_for_test(Report {
        checks: vec![
            check(Dependency::Qemu, "QEMU", None),
            check(Dependency::Kvm, "KVM access", Some(NO_KVM)),
        ],
        ..Report::default()
    })
}

fn vm(acceleration: VmAcceleration) -> VmConfig {
    let mut vm = VmConfig {
        id: "lab".into(),
        name: "Lab".into(),
        ..VmConfig::default()
    };
    vm.launch.acceleration = acceleration;
    vm
}

#[test]
fn missing_kvm_is_a_warning_and_missing_qemu_stays_an_error() {
    let window = without_kvm();
    let report = window.report().unwrap();
    assert!(
        !report.has_missing(),
        "KVM alone is not a missing requirement"
    );
    assert_eq!(report.warnings().len(), 1);
    let qemu = Report {
        checks: vec![check(Dependency::Qemu, "QEMU", Some("missing"))],
        ..Report::default()
    };
    assert!(qemu.has_missing() && qemu.warnings().is_empty());
}

#[test]
fn the_dependencies_window_names_the_cost_and_offers_both_tcg_actions() {
    let ctx = context();
    let mut app = app();
    app.dependencies = without_kvm();
    app.dependencies.open = true;
    app.snapshot.vms = vec![vm(VmAcceleration::Kvm)];
    app.selected = Some("lab".into());
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown: Vec<String> = texts(&render(&mut app, &ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    let has = |needle: &str| shown.iter().any(|text| text.contains(needle));
    assert!(has("Warning"), "{shown:?}");
    assert!(has("10 to 50 times"), "{shown:?}");
    assert!(has("Use TCG for Lab"), "{shown:?}");
    assert!(has("Use TCG when KVM is unavailable"), "{shown:?}");
    assert!(!has("Unavailable"), "KVM is not an unavailable requirement");
}

#[test]
fn use_tcg_for_this_vm_saves_the_vm_with_tcg_and_a_cpu_model_that_runs_there() {
    let mut app = app();
    let mut lab = vm(VmAcceleration::Kvm);
    lab.launch.cpu_model = VmCpuModel::Host;
    app.snapshot.vms = vec![lab];
    app.selected = Some("lab".into());
    app.apply_tcg_choice(false, true);
    let saved = app
        .submitted
        .iter()
        .find_map(|command| match command {
            Command::Save(vm) => Some(vm.clone()),
            _ => None,
        })
        .expect("the VM is saved");
    assert_eq!(saved.launch.acceleration, VmAcceleration::Tcg);
    assert_eq!(saved.launch.cpu_model, VmCpuModel::Default);
    assert!(saved.launch.validate().is_ok());
}

#[test]
fn use_tcg_when_kvm_is_unavailable_is_saved_with_the_settings() {
    let mut app = app();
    // On for a new install; an old file's saved "off" stays off.
    assert!(app.settings.start.kvm_fallback);
    let old: Settings = serde_json::from_str(r#"{"start": {"kvm_fallback": false}}"#).unwrap();
    assert!(!old.start.kvm_fallback);
    let unset: Settings = serde_json::from_str(r#"{"start": {"tcg_multiplier": 12}}"#).unwrap();
    assert!(unset.start.kvm_fallback && unset.start.tcg_multiplier == 12);
    app.settings.start.kvm_fallback = false;
    app.apply_tcg_choice(true, false);
    assert!(app.settings.start.kvm_fallback && app.options.start.kvm_fallback);
    assert!(app.submitted.iter().any(|command| matches!(
        command,
        Command::UpdateOptions { start, .. } if start.kvm_fallback
    )));
}

#[test]
fn the_vm_dialog_warns_when_default_or_kvm_cannot_use_kvm_and_offers_tcg() {
    let ctx = context();
    let mut app = app();
    app.dependencies = without_kvm();
    assert_eq!(app.kvm_problem().as_deref(), Some(NO_KVM));
    app.snapshot.bases = vec![test_base("capable", true)];
    app.new_image();
    app.draft.base_identity = Some("capable".into());
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown: Vec<String> = texts(&render(&mut app, &ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    let has = |needle: &str| shown.iter().any(|text| text.contains(needle));
    assert!(has("This VM will start with TCG"), "{shown:?}");
    assert!(has("Use TCG for this VM"), "{shown:?}");
    app.draft.launch.acceleration = VmAcceleration::Kvm;
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown: Vec<String> = texts(&render(&mut app, &ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(
        shown
            .iter()
            .any(|text| text.contains("This VM will not start with KVM")),
        "{shown:?}"
    );
    app.draft.launch.acceleration = VmAcceleration::Tcg;
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown = texts(&render(&mut app, &ctx, SIZE));
    assert!(
        !shown
            .iter()
            .any(|(text, _)| text.contains("KVM is not available")),
        "TCG needs no warning"
    );
}

#[test]
fn a_fallback_to_tcg_raises_one_warning_toast_per_start() {
    let ctx = context();
    let mut app = app();
    let warning = format!(
        "KVM is not available on this host ({NO_KVM}); Lab runs with TCG software emulation, so expect much slower performance."
    );
    let starting = |accelerator| antinomie_monitor_core::Snapshot {
        accelerator,
        ..Default::default()
    };
    let fallen_back = Some(AcceleratorUsed {
        record: "tcg (KVM unavailable)".into(),
        fallback_warning: Some(warning.clone()),
        guest_wait_factor: 10.0,
    });
    let mut activity = Vec::new();
    app.accept_snapshot(starting(fallen_back.clone()), &mut activity);
    assert_eq!(activity, [("WARN", warning.clone())]);
    // The same boot's later snapshots say nothing more.
    let mut again = Vec::new();
    app.accept_snapshot(starting(fallen_back.clone()), &mut again);
    assert!(again.is_empty(), "{again:?}");
    // A start with TCG chosen explicitly has nothing to warn about.
    let mut explicit = Vec::new();
    app.accept_snapshot(starting(None), &mut Vec::new());
    app.accept_snapshot(
        starting(Some(AcceleratorUsed {
            record: "tcg".into(),
            fallback_warning: None,
            guest_wait_factor: 10.0,
        })),
        &mut explicit,
    );
    assert!(explicit.is_empty());
    // The next start warns again.
    app.accept_snapshot(starting(None), &mut Vec::new());
    let mut next = Vec::new();
    app.accept_snapshot(starting(fallen_back), &mut next);
    assert_eq!(next, [("WARN", warning.clone())]);
    // Logged, it is a Warning toast naming the cost and a row in Activity.
    app.log("WARN", warning);
    for _ in 0..4 {
        render(&mut app, &ctx, SIZE);
    }
    let toasts = crate::toasts::snapshot(&ctx);
    assert_eq!(toasts.len(), 1, "{toasts:?}");
    assert_eq!(toasts[0].0, crate::activity::Level::Warn);
    assert!(toasts[0].2.contains("expect much slower performance"));
    assert_eq!(app.activity.counts(), (1, 0));
}

#[test]
fn settings_advanced_has_the_start_timeouts_and_the_multiplier() {
    let ctx = context();
    let mut app = app();
    app.settings_open = true;
    app.settings_page = super::super::settings_window::SettingsPage::Advanced;
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown: Vec<String> = texts(&render(&mut app, &ctx, SIZE))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    let has = |needle: &str| shown.iter().any(|text| text.contains(needle));
    assert!(has("VM start and guest connection timeouts"), "{shown:?}");
    assert!(has("TCG multiplier"), "{shown:?}");
    assert!(has("Use TCG when KVM is unavailable"), "{shown:?}");
    // The number is 200 s on an idle host; a loaded one stretches it
    // (/proc/loadavg), so the test does not pin it.
    assert!(has("waits up to "), "{shown:?}");
    let defaults = StartSettings::default();
    assert_eq!(
        (defaults.guest_connect_secs, defaults.tcg_multiplier),
        (20, 10)
    );
}

#[test]
fn a_slow_start_shows_what_is_waited_for_and_clears_when_it_ends() {
    let ctx = context();
    let mut app = app();
    let note = "Waiting for a slow TCG boot: the guest has not connected after 31 s (waiting up to 200 s; host load 9.50).";
    app.snapshot.state = VmState::Starting;
    app.snapshot.start_note = Some(note.into());
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown = texts(&render(&mut app, &ctx, SIZE));
    assert!(
        shown
            .iter()
            .any(|(text, _)| text.contains("Waiting for a slow TCG boot")),
        "{shown:?}"
    );
    app.snapshot.state = VmState::Running;
    for _ in 0..3 {
        render(&mut app, &ctx, SIZE);
    }
    let shown = texts(&render(&mut app, &ctx, SIZE));
    assert!(
        !shown
            .iter()
            .any(|(text, _)| text.contains("Waiting for a slow TCG boot")),
        "a running VM shows no start note"
    );
}
