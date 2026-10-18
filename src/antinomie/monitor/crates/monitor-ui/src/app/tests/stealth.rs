// SPDX-License-Identifier: MIT
//! VM configuration > Stealth profile.
use super::*;
use antinomie_monitor_core::stealth::{StealthPreset, StealthProfile, MACHINES};

fn shown(app: &mut MonitorApp, size: egui::Vec2) -> Vec<String> {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    for _ in 0..3 {
        render(app, &ctx, size);
    }
    let output = render(app, &ctx, size);
    texts(&output).into_iter().map(|(text, _)| text).collect()
}

#[test]
fn new_vms_look_like_a_desktop_and_saved_vms_keep_qemu_defaults() {
    let mut app = app();
    app.new_image();
    let stealth = &app.draft.stealth;
    assert_eq!(stealth.preset, StealthPreset::RealisticDesktop);
    assert!(stealth.identity_enabled && stealth.hide_hypervisor && stealth.hide_kvm);
    assert_ne!(stealth.rating(), "certain");
    assert!(app.create_validation_error(false).is_none());
    // A configuration saved before stealth profiles reads as Transparent.
    let mut saved = serde_json::to_value(VmConfig::default()).unwrap();
    saved.as_object_mut().unwrap().remove("stealth");
    let legacy: VmConfig = serde_json::from_value(saved).unwrap();
    assert_eq!(legacy.stealth, StealthProfile::transparent());
    assert_eq!(legacy.stealth.rating(), "certain");
}

#[test]
fn edits_make_the_profile_custom_and_presets_stay_named() {
    let before = StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD");
    let mut edited = before.clone();
    edited.hpet = !edited.hpet;
    crate::app::stealth::settle_preset(&before, &mut edited);
    assert_eq!(edited.preset, StealthPreset::Custom);

    let mut switched = before.for_preset(StealthPreset::RealisticLaptop, "AuthenticAMD");
    crate::app::stealth::settle_preset(&before, &mut switched);
    assert_eq!(switched.preset, StealthPreset::RealisticLaptop);
    let laptop = MACHINES
        .iter()
        .find(|machine| machine.id == switched.identity.profile)
        .expect("a built-in laptop");
    assert_eq!(laptop.cpu_vendor, "AuthenticAMD");

    let mut unchanged = before.clone();
    crate::app::stealth::settle_preset(&before, &mut unchanged);
    assert_eq!(unchanged.preset, StealthPreset::RealisticDesktop);
}

#[test]
fn invalid_entries_block_create_and_save() {
    let mut app = app();
    app.new_image();
    app.draft.stealth.mac = "not a mac".into();
    assert!(app
        .create_validation_error(false)
        .unwrap()
        .contains("MAC address"));
    app.draft.id = "vm".into();
    app.snapshot.vms.push(app.draft.clone());
    assert!(app
        .save_validation_error(&app.draft)
        .unwrap()
        .contains("MAC address"));
    app.draft.stealth.new_mac();
    assert!(app.save_validation_error(&app.draft).is_none());
}

#[test]
fn dialog_shows_the_preset_and_the_window_its_sections() {
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    app.new_image();
    let texts = shown(&mut app, size);
    assert!(
        texts.iter().any(|text| text == "Realistic desktop"),
        "{texts:?}"
    );
    assert!(!texts.iter().any(|text| text.contains("Detected as a VM")));

    app.stealth_open = true;
    let texts = shown(&mut app, size);
    for section in [
        "Stealth profile",
        "Hardware identity",
        "Firmware and ACPI",
        "CPU",
        "Network",
    ] {
        assert!(
            texts.iter().any(|text| text == section),
            "{section} missing: {texts:?}"
        );
    }
    assert!(app.dialog_open(Dialog::Stealth));
    // Closing the VM dialog closes its stealth window too.
    app.create_open = false;
    shown(&mut app, size);
    assert!(!app.dialog_open(Dialog::Stealth));
}

#[test]
fn a_running_vm_shows_its_profile_read_only() {
    let size = egui::vec2(1280.0, 900.0);
    let mut app = app();
    let vm = VmConfig {
        id: "vm".into(),
        name: "VM".into(),
        ..VmConfig::default()
    };
    app.snapshot.vms.push(vm.clone());
    app.snapshot.active_vm = Some(vm.id.clone());
    app.selected = Some(vm.id);
    app.configure_vm();
    app.stealth_open = true;
    let texts = shown(&mut app, size);
    assert!(texts
        .iter()
        .any(|text| text == "Stop the VM to change its hardware."));
    assert_eq!(app.draft.stealth, StealthProfile::transparent());
}

#[test]
fn summary_configure_opens_the_vm_dialog_for_a_stopped_vm() {
    let size = egui::vec2(1280.0, 900.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    let vm = VmConfig {
        id: "vm".into(),
        name: "VM".into(),
        ..VmConfig::default()
    };
    app.snapshot.vms.push(vm.clone());
    app.selected = Some(vm.id.clone());
    app.focus_panel = Some(Panel::Summary);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let flag = egui::Id::new(crate::summary::configuration::CONFIGURE);
    ctx.data_mut(|data| data.insert_temp(flag, true));
    render(&mut app, &ctx, size);
    assert!(app.config_open);
    assert_eq!(app.draft.id, "vm");

    // A running VM keeps its dialog closed; the flag is consumed either way.
    app.config_open = false;
    app.snapshot.active_vm = Some(vm.id);
    ctx.data_mut(|data| data.insert_temp(flag, true));
    render(&mut app, &ctx, size);
    assert!(!app.config_open);
    assert_eq!(ctx.data_mut(|data| data.get_temp::<bool>(flag)), None);
}
