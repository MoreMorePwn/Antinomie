// SPDX-License-Identifier: GPL-3.0-only
//! VM configuration > Device profile.
use super::*;
use antinomie_monitor_core::stealth::{StealthPreset, StealthProfile, MACHINES};

fn cloud_advice_frame(
    ctx: &egui::Context,
    vm: &mut VmConfig,
    events: Vec<egui::Event>,
) -> egui::FullOutput {
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(640.0, 480.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                crate::app::stealth::launch_advice(ui, vm);
            });
        },
    )
}

#[test]
fn cloud_advice_preserves_saved_policies_until_the_routed_button_is_clicked() {
    use antinomie_monitor_core::{stealth::CLOUDS, VmNetwork};
    for (nat, isolated_network, routed) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut vm = VmConfig {
            id: "saved-cloud".into(),
            nat,
            isolated_network,
            routed,
            stealth: StealthProfile::cloud_vps(&CLOUDS[0]),
            ..Default::default()
        };
        let before = serde_json::to_value(&vm).unwrap();
        let mut output = cloud_advice_frame(&ctx, &mut vm, vec![]);
        for _ in 0..3 {
            output = cloud_advice_frame(&ctx, &mut vm, vec![]);
        }
        assert_eq!(serde_json::to_value(&vm).unwrap(), before);
        let labels = texts(&output);
        let button = labels
            .iter()
            .find(|(text, _)| text == "Use Routed for cloud metadata");
        if routed {
            assert!(button.is_none());
        } else {
            let pos = button.expect("Routed must be offered").1.center();
            for pressed in [true, false] {
                cloud_advice_frame(
                    &ctx,
                    &mut vm,
                    vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
            assert_eq!(vm.network(), VmNetwork::Routed);
            let mut expected = before;
            expected["nat"] = false.into();
            expected["isolated_network"] = false.into();
            expected["routed"] = true.into();
            assert_eq!(serde_json::to_value(&vm).unwrap(), expected);
        }
    }
}

#[test]
fn chipset_fallback_is_visible_before_launch_at_the_ram_boundary() {
    use antinomie_monitor_core::stealth::CLOUDS;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut vm = VmConfig {
        ram_mib: 2816,
        stealth: StealthProfile::cloud_vps(&CLOUDS[0]),
        ..Default::default()
    };
    for _ in 0..3 {
        cloud_advice_frame(&ctx, &mut vm, vec![]);
    }
    let output = cloud_advice_frame(&ctx, &mut vm, vec![]);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text.contains("q35 will be used")));
    vm.ram_mib = 2815;
    let output = cloud_advice_frame(&ctx, &mut vm, vec![]);
    assert!(!texts(&output)
        .iter()
        .any(|(text, _)| text.contains("q35 will be used")));
}

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
    // A configuration saved before device profiles reads as Transparent.
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
        "Device profile",
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

// ----- settings the base or the host cannot give -----

const SATA_LINE: &str = "SATA (AHCI) not supported by this base: virtio will be used";

/// A VM asking for SATA on a base with the given support, in the New VM dialog.
fn sata_on_base(support: &[&str], others: &[(&str, &str, &[&str])]) -> MonitorApp {
    use antinomie_monitor_core::stealth::{DiskBus, Firmware, NatNetwork};
    let mut app = app();
    let mut base = test_base("base", true);
    base.label = "Current base".into();
    base.stealth_support = support.iter().map(|item| (*item).to_owned()).collect();
    app.snapshot.bases.push(base);
    for (id, label, support) in others {
        let mut other = test_base(id, true);
        other.label = (*label).into();
        other.stealth_support = support.iter().map(|item| (*item).to_owned()).collect();
        app.snapshot.bases.push(other);
    }
    app.new_image();
    app.draft.base_identity = Some("base".into());
    // Settings every host has, so only the base decides.
    let stealth = &mut app.draft.stealth;
    stealth.disk_bus = DiskBus::Sata;
    stealth.firmware = Firmware::Bios;
    stealth.smt = false;
    stealth.nat = NatNetwork::default();
    stealth.usb = true;
    app
}

#[test]
fn the_window_says_on_the_setting_itself_that_it_falls_back() {
    let size = egui::vec2(1280.0, 900.0);
    let mut app = sata_on_base(&[], &[]);
    app.stealth_open = true;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    // At the top, where a closed section does not hide it.
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(
        lines
            .iter()
            .any(|text| text.contains("1 setting will not be applied") && text.contains(SATA_LINE)),
        "{lines:?}"
    );
    assert!(!lines.iter().any(|text| text.starts_with("Use base")));
    // Open the section holding the Disk bus: the line is on the setting.
    click_label(&mut app, &ctx, size, "Storage and devices");
    for _ in 0..2 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    let inline = lines
        .iter()
        .filter(|text| text.ends_with(SATA_LINE) && !text.contains('\n'))
        .count();
    assert_eq!(inline, 1, "beside the Disk bus: {lines:?}");
    assert!(
        lines
            .iter()
            .any(|text| text.contains("boots from virtio only")),
        "and why: {lines:?}"
    );
}

#[test]
fn the_vm_dialog_row_and_the_sidebar_carry_a_warning_badge() {
    let size = egui::vec2(1280.0, 900.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = sata_on_base(&[], &[]);
    let fallbacks = app.draft_stealth_fallbacks();
    assert_eq!(fallbacks.len(), 1);
    assert_eq!(fallbacks[0].summary, SATA_LINE);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(
        lines
            .iter()
            .any(|text| text.ends_with("1 setting falls back")),
        "the Stealth row of the dialog: {lines:?}"
    );
    // The VM in the sidebar list.
    let mut vm = app.draft.clone();
    vm.id = "vm".into();
    vm.name = "Saved VM".into();
    app.snapshot.vms.push(vm);
    app.create_open = false;
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(
        lines
            .iter()
            .any(|text| text.contains("Device profile fallback")),
        "the sidebar row: {lines:?}"
    );
}

#[test]
fn a_base_that_supports_every_setting_shows_no_warning_anywhere() {
    let size = egui::vec2(1280.0, 900.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = sata_on_base(&["uefi", "sata", "nvme", "dhcp"], &[]);
    assert!(app.draft_stealth_fallbacks().is_empty());
    app.stealth_open = true;
    let mut vm = app.draft.clone();
    vm.id = "vm".into();
    app.snapshot.vms.push(vm);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    click_label(&mut app, &ctx, size, "Storage and devices");
    let output = render(&mut app, &ctx, size);
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(
        !lines.iter().any(|text| text.contains("will not be applied")
            || text.contains("Device profile fallback")
            || text.contains("fall back")
            || text.contains("falls back")
            || text.contains("not supported by")),
        "{lines:?}"
    );
}

#[test]
fn another_installed_base_that_supports_the_setting_is_offered_and_switches_the_vm() {
    let size = egui::vec2(1280.0, 900.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = sata_on_base(
        &[],
        &[
            ("plain", "Plain base", &[]),
            ("sata", "SATA base", &["sata", "uefi", "dhcp"]),
        ],
    );
    app.stealth_open = true;
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    click_label(&mut app, &ctx, size, "Storage and devices");
    for _ in 0..2 {
        render(&mut app, &ctx, size);
    }
    click_label(&mut app, &ctx, size, "Use base SATA base");
    assert_eq!(app.draft.base_identity.as_deref(), Some("sata"));
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    assert!(app.draft_stealth_fallbacks().is_empty());
    let output = render(&mut app, &ctx, size);
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(!lines.iter().any(|text| text.starts_with("Use base")));
}

#[test]
fn without_a_supporting_base_installed_no_switch_is_offered() {
    let size = egui::vec2(1280.0, 900.0);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = sata_on_base(&[], &[("plain", "Plain base", &[])]);
    app.stealth_open = true;
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    click_label(&mut app, &ctx, size, "Storage and devices");
    let output = render(&mut app, &ctx, size);
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(
        lines.iter().any(|text| text.ends_with(SATA_LINE)),
        "{lines:?}"
    );
    assert!(!lines.iter().any(|text| text.starts_with("Use base")));
}

#[test]
fn the_run_header_lists_what_the_vm_started_without() {
    let mut sample = run("run-1");
    let line = "Device profile setting not applied: SATA (AHCI) not supported by this base: virtio will be used; the base boots from virtio only";
    sample.notes.push(line.into());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 400.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| crate::run_recording::show(ui, &sample));
        },
    );
    let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
    assert!(
        lines.iter().any(|text| text == &format!("Note: {line}")),
        "{lines:?}"
    );
    assert!(crate::run_recording::tooltip(&sample).contains("SATA (AHCI) not supported"));
}

#[test]
fn the_vm_dialog_keeps_its_width_for_every_device_profile() {
    use antinomie_monitor_core::stealth::CLOUDS;
    let size = egui::vec2(1600.0, 1000.0);
    let mut width = None;
    let profiles = StealthPreset::ALL
        .iter()
        .map(|&preset| StealthProfile::realistic(preset, "GenuineIntel"))
        .chain(CLOUDS.iter().map(StealthProfile::cloud_vps));
    for profile in profiles {
        for network in [(false, false), (true, false), (false, true)] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut app = app();
            app.new_image();
            app.draft.stealth = profile.clone();
            (app.draft.nat, app.draft.routed) = network;
            for _ in 0..4 {
                render(&mut app, &ctx, size);
            }
            let rect = ctx
                .memory(|memory| memory.area_rect(Dialog::Vm.window_id()))
                .expect("the VM dialog is open");
            let expected = *width.get_or_insert(rect.width());
            assert!(
                (rect.width() - expected).abs() < 1.0,
                "{:?} on {network:?}: {} wide, others {expected}",
                profile.preset,
                rect.width()
            );
        }
    }
}
