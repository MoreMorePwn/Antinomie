// SPDX-License-Identifier: GPL-3.0-only
//! The Device profile window (ANT-T0550): hints, width, uptime and the IoT preset.
use super::*;

const SIZE: egui::Vec2 = egui::vec2(1600.0, 1500.0);
const AWAY: egui::Pos2 = egui::pos2(2.0, SIZE.y - 2.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx.global_style_mut(|style| {
        style.interaction.tooltip_delay = 0.0;
        style.interaction.tooltip_grace_time = 0.0;
    });
    ctx
}

fn input(events: Vec<egui::Event>) -> egui::RawInput {
    egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
        events,
        ..Default::default()
    }
}

fn hover_at(app: &mut MonitorApp, ctx: &egui::Context, pos: egui::Pos2) -> egui::FullOutput {
    let mut output = egui::FullOutput::default();
    for _ in 0..12 {
        output = draw_input(app, ctx, input(vec![egui::Event::PointerMoved(pos)]));
    }
    output
}

/// Clicks the last text `label` drawn (the window is above the main view,
/// whose trace has a CPU column too).
fn click_last(app: &mut MonitorApp, ctx: &egui::Context, label: &str) {
    let output = hover_at(app, ctx, AWAY);
    let pos = texts(&output)
        .into_iter()
        .rfind(|(text, _)| text == label)
        .unwrap_or_else(|| panic!("{label} not drawn"))
        .1
        .center();
    for pressed in [true, false] {
        draw_input(
            app,
            ctx,
            input(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]),
        );
    }
    // Away long enough after the click for a tooltip to show again.
    hover_at(app, ctx, AWAY);
}

/// Opens the window's preset list (the text right of "Preset"; the Chassis
/// list shows "Desktop" too).
fn open_presets(app: &mut MonitorApp, ctx: &egui::Context) {
    let found = texts(&hover_at(app, ctx, AWAY));
    let preset = found
        .iter()
        .rfind(|(text, _)| text == "Preset")
        .expect("the window's Preset row")
        .1;
    let pos = found
        .iter()
        .filter(|(text, rect)| {
            text != "Preset"
                && (rect.center().y - preset.center().y).abs() < 6.0
                && rect.left() > preset.right()
        })
        .map(|(_, rect)| rect.center())
        .next()
        .expect("the preset list beside it");
    for pressed in [true, false] {
        draw_input(
            app,
            ctx,
            input(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]),
        );
    }
    hover_at(app, ctx, AWAY);
}

/// The hints missing when the help icon beside each label is hovered:
/// `(label, part of its tip)`. The control itself shows nothing.
fn missing_tips(app: &mut MonitorApp, ctx: &egui::Context, cases: &[(&str, &str)]) -> Vec<String> {
    let mut missing = Vec::new();
    for &(label, tip) in cases {
        let output = hover_at(app, ctx, AWAY);
        let found = texts(&output);
        let Some((_, rect)) = found.iter().rfind(|(text, _)| text == label) else {
            missing.push(format!("{label}: not drawn"));
            continue;
        };
        // A tooltip is text that shows only while the control is hovered.
        let on_control = texts(&hover_at(app, ctx, rect.center()));
        if on_control
            .iter()
            .any(|(text, _)| text.contains(tip) && !found.iter().any(|(away, _)| away == text))
        {
            missing.push(format!("{label}: still a tooltip on the control"));
        }
        let Some(icon) = found
            .iter()
            .filter(|(text, icon)| {
                text == egui_phosphor::regular::QUESTION
                    && (icon.center().y - rect.center().y).abs() < 10.0
                    && icon.left() > rect.right()
            })
            .min_by(|a, b| a.1.left().total_cmp(&b.1.left()))
            .map(|(_, icon)| *icon)
        else {
            missing.push(format!("{label}: no help icon"));
            continue;
        };
        let shown = texts(&hover_at(app, ctx, icon.center()));
        if !shown.iter().any(|(text, _)| text.contains(tip)) {
            missing.push(format!("{label}: no help {tip:?}"));
        }
    }
    missing
}

/// Each section's hints: `(section, [(label, part of its tip)])`.
const CASES: [(&str, &[(&str, &str)]); 6] = [
    ("Hardware identity", &[("Randomize serials", "New serials")]),
    (
        "Firmware and ACPI",
        &[("VMware backdoor port", "Only VMware VMs")],
    ),
    (
        "CPU",
        &[("Hide the KVM signature", "small timekeeping cost")],
    ),
    (
        "Network",
        &[("Random", "vendor prefix"), ("Home", "192.168.1.0/24")],
    ),
    (
        "Storage and devices",
        &[("An empty SATA CD-ROM drive", "SCSI inquiry")],
    ),
    (
        "Clock",
        &[
            ("Real-time clock in local time", "Linux PCs keep it in UTC"),
            ("Catch up on missed clock ticks", "count RTC interrupts"),
        ],
    ),
];

/// Opens each section in turn (Hardware identity is open already), checks
/// its hints and closes it again.
fn missing_in_sections(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
    let mut missing = Vec::new();
    for (section, cases) in CASES {
        let opens = section != "Hardware identity";
        if opens {
            click_last(app, ctx, section);
        }
        missing.extend(missing_tips(app, ctx, cases));
        if opens {
            click_last(app, ctx, section);
        }
    }
    missing
}

#[test]
fn every_hint_in_the_device_profile_window_shows_on_hover() {
    let ctx = context();
    let mut app = app();
    app.new_image();
    app.stealth_open = true;
    let missing = missing_in_sections(&mut app, &ctx);
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn a_running_vms_read_only_profile_still_shows_its_hints() {
    let ctx = context();
    let mut app = app();
    let vm = VmConfig {
        id: "vm".into(),
        name: "VM".into(),
        stealth: antinomie_monitor_core::stealth::StealthProfile::realistic(
            antinomie_monitor_core::stealth::StealthPreset::RealisticDesktop,
            "GenuineIntel",
        ),
        ..VmConfig::default()
    };
    app.snapshot.vms.push(vm.clone());
    app.snapshot.active_vm = Some(vm.id.clone());
    app.selected = Some(vm.id);
    app.configure_vm();
    app.stealth_open = true;
    let shown = lines(&mut app, &ctx);
    assert!(shown
        .iter()
        .any(|text| text == "Stop the VM to change its hardware."));
    // The sections open and the hints of their disabled entries show.
    let missing = missing_in_sections(&mut app, &ctx);
    assert!(missing.is_empty(), "{missing:?}");
}

// ----- item 10: the window keeps its width -----

fn window_width(ctx: &egui::Context) -> f32 {
    ctx.memory(|memory| memory.area_rect(egui::Id::new("vm_stealth")))
        .expect("the Device profile window is open")
        .width()
}

const R22: [&str; 6] = ["uefi", "sata", "nvme", "dhcp", "facade", "uptime"];

/// A New VM dialog on an arm64 base (`debian`: a Debian one) with its
/// Device profile window open.
fn arm_app(debian: bool) -> MonitorApp {
    let mut app = app();
    let mut base = test_base("arm", true);
    base.arch = antinomie_monitor_core::GuestArch::AARCH64;
    base.stealth_support = R22.iter().map(|item| (*item).to_owned()).collect();
    if debian {
        base.label = "Debian 13 Minimal".into();
        base.guest = Some(antinomie_monitor_core::GuestProfile {
            id: "debian-minimal".into(),
            label: "Debian Minimal".into(),
            min_ram_mib: 256,
            min_disk_gib: 1,
            requires_credentials: false,
            graphical: false,
        });
    }
    app.snapshot.bases.push(base);
    app.new_image();
    app.draft.base_identity = Some("arm".into());
    app.stealth_open = true;
    app
}

#[test]
fn opening_firmware_and_acpi_keeps_the_windows_width() {
    use antinomie_monitor_core::stealth::Firmware;
    for arm in [true, false] {
        let ctx = context();
        let mut app = if arm {
            arm_app(false)
        } else {
            let mut app = app();
            app.new_image();
            app.draft.stealth.firmware = Firmware::UefiSecureBoot;
            app.stealth_open = true;
            app
        };
        hover_at(&mut app, &ctx, AWAY);
        let settled = window_width(&ctx);
        hover_at(&mut app, &ctx, AWAY);
        hover_at(&mut app, &ctx, AWAY);
        let before = window_width(&ctx);
        // It opens at its own width (the dialog helper's min_width, which
        // used to be dropped), not narrower.
        assert!(before >= 520.0, "arm64 {arm}: opens {before} wide");
        assert!(
            (before - settled).abs() < 2.0,
            "arm64 {arm}: {settled} wide, then {before} without a click"
        );
        click_last(&mut app, &ctx, "Firmware and ACPI");
        let output = hover_at(&mut app, &ctx, AWAY);
        let lines: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
        assert!(
            lines.iter().any(|text| text.contains(if arm {
                "the PC devices"
            } else {
                "the guest sees Secure Boot on"
            })),
            "{lines:?}"
        );
        let after = window_width(&ctx);
        // The window took up to 80 % of the screen before (1280 pt here);
        // a long list label (Secure Boot) or note no longer widens it.
        assert!(
            (after - before).abs() <= 4.0,
            "arm64 {arm}: {before} wide, {after} with Firmware and ACPI open"
        );
        assert!(after < SIZE.x * 0.4, "{after}");
        // And it stays there.
        hover_at(&mut app, &ctx, AWAY);
        assert!((window_width(&ctx) - after).abs() < 1.0);
    }
}

// ----- item 8: Uptime -----

fn type_text(app: &mut MonitorApp, ctx: &egui::Context, text: &str) {
    draw_input(
        app,
        ctx,
        input(vec![
            egui::Event::Key {
                key: egui::Key::A,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::COMMAND,
            },
            egui::Event::Text(text.into()),
        ]),
    );
    hover_at(app, ctx, AWAY);
}

fn lines(app: &mut MonitorApp, ctx: &egui::Context) -> Vec<String> {
    texts(&hover_at(app, ctx, AWAY))
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

#[test]
fn the_uptime_is_typed_or_drawn_in_the_recommended_range() {
    use antinomie_monitor_core::stealth::{boot_age_text, StealthPreset, StealthProfile};
    let ctx = context();
    let mut app = app();
    app.new_image();
    app.draft.stealth = StealthProfile::realistic(StealthPreset::RealisticServer, "GenuineIntel");
    app.stealth_open = true;
    click_last(&mut app, &ctx, "Clock");
    let shown = lines(&mut app, &ctx);
    assert!(shown.iter().any(|text| text == "Uptime"), "{shown:?}");
    assert!(
        shown
            .iter()
            .any(|text| text == "Recommended for a server: 3 d 0 h to 120 d 0 h"),
        "{shown:?}"
    );
    assert!(!shown
        .iter()
        .any(|text| text.contains("Booted a while ago") || text.contains("Draw again")));
    // Typed: the age follows the text.
    let field = boot_age_text(app.draft.stealth.boot_age_s);
    click_last(&mut app, &ctx, &field);
    type_text(&mut app, &ctx, "2 d 5 h");
    assert_eq!(app.draft.stealth.boot_age_s, 2 * 86_400 + 5 * 3_600);
    // An uptime is the preset's own draw: the server stays a server.
    assert_eq!(app.draft.stealth.preset, StealthPreset::RealisticServer);
    let shown = lines(&mut app, &ctx);
    assert!(
        shown
            .iter()
            .any(|text| text == "Outside the recommended range for a server"),
        "{shown:?}"
    );
    // Not an uptime: said, and the age stays.
    type_text(&mut app, &ctx, "soon");
    assert_eq!(app.draft.stealth.boot_age_s, 2 * 86_400 + 5 * 3_600);
    let shown = lines(&mut app, &ctx);
    assert!(
        shown.iter().any(|text| text.contains("is not an uptime")),
        "{shown:?}"
    );
    // The dice: a random uptime in the range, and the text shows it.
    click_last(&mut app, &ctx, egui_phosphor::regular::DICE_FIVE);
    let age = app.draft.stealth.boot_age_s;
    assert!((3 * 86_400..=120 * 86_400).contains(&age), "{age}");
    let shown = lines(&mut app, &ctx);
    assert!(shown.contains(&boot_age_text(age)), "{shown:?}");
    assert!(!shown.iter().any(|text| text.contains("is not an uptime")));
    // Its help icon says what the dice does.
    let help = texts(&hover_at(&mut app, &ctx, AWAY))
        .into_iter()
        .filter(|(text, _)| text == egui_phosphor::regular::QUESTION)
        .map(|(_, rect)| rect)
        .collect::<Vec<_>>();
    let tips: Vec<String> = help
        .iter()
        .flat_map(|rect| texts(&hover_at(&mut app, &ctx, rect.center())))
        .map(|(text, _)| text)
        .collect();
    assert!(
        tips.iter().any(|text| text.contains("press the dice")),
        "{tips:?}"
    );
}

// ----- item 13: the IoT preset -----

#[test]
fn the_iot_preset_is_offered_on_arm64_and_disabled_on_x86() {
    use antinomie_monitor_core::stealth::StealthPreset;
    const IOT: &str = "IoT device (Raspberry Pi)";
    let ctx = context();
    let mut app = arm_app(false);
    open_presets(&mut app, &ctx);
    click_last(&mut app, &ctx, IOT);
    assert_eq!(app.draft.stealth.preset, StealthPreset::Iot);
    let shown = lines(&mut app, &ctx);
    assert!(
        shown
            .iter()
            .any(|text| text.starts_with("Shown as: Raspberry Pi")),
        "{shown:?}"
    );
    // On BusyBox already: no suggestion.
    assert!(!shown.iter().any(|text| text.starts_with("Suggested base")));

    // An x86-64 VM lists it disabled, with the reason.
    let ctx = context();
    let mut app = super::app();
    app.snapshot.bases.push(test_base("pc", true));
    app.new_image();
    app.draft.base_identity = Some("pc".into());
    app.stealth_open = true;
    open_presets(&mut app, &ctx);
    let output = hover_at(&mut app, &ctx, AWAY);
    let found = texts(&output);
    let item = found
        .iter()
        .rfind(|(text, _)| text == IOT)
        .unwrap_or_else(|| panic!("listed: {found:?}"))
        .1;
    let tip = texts(&hover_at(&mut app, &ctx, item.center()));
    assert!(
        tip.iter().any(|(text, _)| text.contains("arm64 only")),
        "{tip:?}"
    );
    click_last(&mut app, &ctx, IOT);
    assert_eq!(app.draft.stealth.preset, StealthPreset::RealisticDesktop);
}

#[test]
fn an_iot_vm_on_debian_is_offered_the_busybox_base() {
    use antinomie_monitor_core::stealth::StealthProfile;
    let ctx = context();
    let mut app = arm_app(true);
    let mut busybox = test_base("busybox-arm", true);
    busybox.label = "BusyBox".into();
    busybox.arch = antinomie_monitor_core::GuestArch::AARCH64;
    busybox.stealth_support = R22.iter().map(|item| (*item).to_owned()).collect();
    app.snapshot.bases.push(busybox);
    app.draft.stealth = StealthProfile::iot();
    let shown = lines(&mut app, &ctx);
    assert!(
        shown
            .iter()
            .any(|text| text.starts_with("Suggested base: BusyBox (arm64)")),
        "{shown:?}"
    );
    click_last(&mut app, &ctx, "Use base BusyBox");
    assert_eq!(app.draft.base_identity.as_deref(), Some("busybox-arm"));
}

// ----- item 6: the Routed button's help -----

#[test]
fn the_routed_buttons_help_icon_says_what_it_does() {
    use antinomie_monitor_core::stealth::{StealthProfile, CLOUDS};
    let ctx = context();
    let mut app = app();
    app.new_image();
    app.draft.stealth = StealthProfile::cloud_vps(&CLOUDS[0]);
    (app.draft.nat, app.draft.routed, app.draft.isolated_network) = (true, false, false);
    let output = hover_at(&mut app, &ctx, AWAY);
    let found = texts(&output);
    let button = found
        .iter()
        .find(|(text, _)| text == "Use Routed for cloud metadata")
        .expect("offered")
        .1;
    let icon = found
        .iter()
        .filter(|(text, rect)| {
            text == egui_phosphor::regular::QUESTION
                && (rect.center().y - button.center().y).abs() < 8.0
                && rect.left() > button.right()
        })
        .map(|(_, rect)| *rect)
        .next()
        .expect("a help icon beside the button");
    let tip = texts(&hover_at(&mut app, &ctx, icon.center()));
    assert!(
        tip.iter().any(|(text, _)| text.contains("route gateway"))
            && tip
                .iter()
                .any(|(text, _)| text.contains("sets the VM's Network to Routed")),
        "{tip:?}"
    );
}

// ----- item 11: Still visible follows the configuration -----

#[test]
fn still_visible_follows_the_vms_network() {
    let ctx = context();
    let mut app = app();
    app.new_image();
    app.draft.stealth = antinomie_monitor_core::stealth::StealthProfile::transparent();
    (app.draft.nat, app.draft.routed, app.draft.isolated_network) = (true, false, false);
    app.stealth_open = true;
    click_last(&mut app, &ctx, "Still visible");
    let shown = lines(&mut app, &ctx);
    assert!(
        shown
            .iter()
            .any(|text| text.contains("virtio network card")),
        "{shown:?}"
    );
    app.draft.nat = false;
    app.draft.routed = false;
    app.draft.isolated_network = false;
    let shown = lines(&mut app, &ctx);
    assert!(
        !shown
            .iter()
            .any(|text| text.contains("virtio network card")),
        "{shown:?}"
    );
    assert!(shown.iter().any(|text| text.contains("a fresh boot")));
}

// ----- sweep follow-up: arm64 draws no uptime -----

#[test]
fn an_arm64_vm_draws_no_uptime_and_shows_the_field_disabled_with_its_note() {
    const IOT: &str = "IoT device (Raspberry Pi)";
    let ctx = context();
    let mut app = arm_app(false);
    open_presets(&mut app, &ctx);
    click_last(&mut app, &ctx, IOT);
    assert_eq!(app.draft.stealth.boot_age_s, 0, "a fresh pick draws none");
    click_last(&mut app, &ctx, "Clock");
    let shown = lines(&mut app, &ctx);
    assert!(
        !shown.iter().any(|text| text.contains("not applied")),
        "no warning line for a fresh pick: {shown:?}"
    );
    assert!(shown.iter().any(|text| text == "a fresh boot"), "{shown:?}");
    assert!(!shown.iter().any(|text| text.starts_with("Recommended for")));
    // The field is disabled: a click does not turn it on.
    click_last(&mut app, &ctx, "Uptime");
    assert_eq!(app.draft.stealth.boot_age_s, 0);
    // Its help icon (on the Uptime row) says why.
    let output = hover_at(&mut app, &ctx, AWAY);
    let found = texts(&output);
    let row = found
        .iter()
        .rfind(|(text, _)| text == "Uptime")
        .expect("the Uptime row")
        .1;
    let icon = found
        .iter()
        .filter(|(text, rect)| {
            text == egui_phosphor::regular::QUESTION
                && (rect.center().y - row.center().y).abs() < 8.0
                && rect.left() > row.right()
        })
        .map(|(_, rect)| *rect)
        .min_by(|a, b| a.left().total_cmp(&b.left()))
        .expect("a help icon on the Uptime row");
    let tip: Vec<String> = texts(&hover_at(&mut app, &ctx, icon.center()))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(
        tip.iter()
            .any(|text| text == "A fresh boot is shown on arm64"),
        "icon {icon:?} row {row:?}: {tip:?}"
    );
    // A profile that already holds an uptime keeps it and says so.
    app.draft.stealth.boot_age_s = 5 * 86_400;
    let shown = lines(&mut app, &ctx);
    assert!(
        shown
            .iter()
            .any(|text| text.contains("not applied on arm64")),
        "{shown:?}"
    );
    assert_eq!(app.draft.stealth.boot_age_s, 5 * 86_400);
}
