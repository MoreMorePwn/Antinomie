// SPDX-License-Identifier: GPL-3.0-only
//! ANT-T0550: the preset names, the IoT preset, typed uptimes and a Still
//! visible list that follows the VM's configuration.
use super::*;
use crate::api::{BaseSummary, GuestArch, VmConfig, VmNetwork};

fn base(arch: GuestArch, support: &[&str]) -> BaseSummary {
    BaseSummary {
        id: "base".into(),
        label: "BusyBox".into(),
        directory: std::path::PathBuf::new(),
        guest: None,
        min_ram_mib: 0,
        min_disk_gib: 0,
        fixed_display: true,
        arch,
        size_bytes: 0,
        revision: None,
        min_app_version: None,
        built_with: None,
        stealth_support: support.iter().map(|item| (*item).to_owned()).collect(),
    }
}

const R22: &[&str] = &["uefi", "sata", "nvme", "dhcp", "facade", "uptime"];

fn has(list: &[&str], part: &str) -> bool {
    list.iter().any(|item| item.contains(part))
}

#[test]
fn preset_names_have_no_realistic_prefix_and_keep_their_stored_names() {
    for preset in StealthPreset::ALL {
        assert!(!preset.label().contains("Realistic"), "{}", preset.label());
        assert!(!preset.label().contains("as before"), "{}", preset.label());
    }
    assert_eq!(StealthPreset::Transparent.label(), "Normal QEMU");
    assert_eq!(StealthPreset::RealisticDesktop.label(), "Desktop");
    assert_eq!(
        serde_json::to_value(StealthPreset::Transparent).unwrap(),
        "Transparent"
    );
    assert_eq!(
        serde_json::to_value(StealthPreset::RealisticServer).unwrap(),
        "RealisticServer"
    );
    let old: StealthPreset = serde_json::from_value("Transparent".into()).unwrap();
    assert_eq!(old, StealthPreset::Transparent);
    // Runs saved before keep their text; the app names them as it does now.
    for (recorded, shown) in [
        ("Transparent QEMU (as before)", "Normal QEMU"),
        ("Transparent QEMU", "Normal QEMU"),
        ("Realistic desktop", "Desktop"),
        ("Realistic laptop", "Laptop"),
        ("Realistic server", "Server"),
        ("Cloud VPS", "Cloud VPS"),
        ("Desktop", "Desktop"),
    ] {
        assert_eq!(StealthPreset::recorded_label(recorded), shown);
    }
}

#[test]
fn a_typed_uptime_is_read_within_the_guest_kernels_bounds() {
    for (text, seconds) in [
        ("3 d 4 h", 3 * 86_400 + 4 * 3_600),
        ("5 h 12 min", 5 * 3_600 + 12 * 60),
        ("5h12m", 5 * 3_600 + 12 * 60),
        ("90 min", 5_400),
        ("2 days, 1 hour", 2 * 86_400 + 3_600),
        ("  120 D ", 120 * 86_400),
        ("1 min", 60),
    ] {
        assert_eq!(parse_boot_age(text), Ok(seconds), "{text}");
    }
    // What the window shows reads back as the same age.
    for seconds in [60, 3 * 3_600, 5 * 3_600 + 12 * 60, 3 * 86_400 + 4 * 3_600] {
        assert_eq!(parse_boot_age(&boot_age_text(seconds)), Ok(seconds));
    }
    for text in [
        "",
        "3",
        "abc",
        "3 weeks",
        "30 s",
        "0 min",
        "1100 d",
        "99999999999999999999 d",
    ] {
        assert!(parse_boot_age(text).is_err(), "{text}");
    }
    assert_eq!(parse_boot_age("1098 d"), Ok(BOOT_AGE_MAX_S));
    assert!(parse_boot_age("1098 d 1 min").is_err());
    let mut profile = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
    profile.boot_age_s = BOOT_AGE_MAX_S;
    assert!(profile.validate().is_ok());
    profile.boot_age_s = BOOT_AGE_MAX_S + 1;
    assert!(profile.validate().is_err());
}

#[test]
fn the_iot_preset_is_a_raspberry_pi_that_is_always_on() {
    let profile = StealthProfile::default().for_preset(StealthPreset::Iot, "GenuineIntel");
    profile.validate().unwrap();
    assert_eq!(profile.preset, StealthPreset::Iot);
    assert_eq!(profile.firmware, Firmware::Bios);
    assert!(profile.identity_enabled && profile.cloud.is_empty());
    assert_eq!(profile.identity.system_uuid.len(), 36);
    assert_eq!(
        StealthProfile::realistic(StealthPreset::Iot, "x").preset,
        StealthPreset::Iot
    );
    // A Pi 4 or 5 on its device tree, whether the VM could boot UEFI or not.
    for uefi in [true, false] {
        let machine = arm64::presented(&profile, uefi).unwrap();
        assert_eq!(machine.kind, ArmKind::Board);
        assert!(machine.tree.unwrap().model.starts_with("Raspberry Pi"));
    }
    // Up for days to months, always running on BusyBox; Debian's watchdogs
    // keep Auto at Suspend there.
    assert_eq!(BootAge::of(&profile), BootAge::Server);
    let (low, high) = BootAge::Server.range();
    assert!((low..=high).contains(&profile.boot_age_s));
    assert_eq!(profile.resolved_clock(false), ClockModel::Continuous);
    assert_eq!(profile.resolved_clock(true), ClockModel::Suspend);
    // No desktop facade or cloud state.
    assert!(launch::facade_options(&profile, false).is_empty());
    assert!(profile.cloud_provider().is_none());
    // The same VM keeps its board; a new one may draw the other.
    assert_eq!(
        arm64::presented(&profile, false).unwrap().id,
        arm64::presented(&profile.clone(), false).unwrap().id
    );
}

#[test]
fn an_x86_vm_cannot_present_the_iot_device_and_starts_as_normal_qemu() {
    let profile = StealthProfile::iot();
    assert!(StealthPreset::Iot.unavailable(GuestArch::X86_64).is_some());
    assert!(StealthPreset::Iot.unavailable(GuestArch::AARCH64).is_none());
    for preset in StealthPreset::ALL {
        if *preset != StealthPreset::Iot {
            assert!(preset.unavailable(GuestArch::X86_64).is_none());
        }
    }
    let fallbacks = profile.arch_fallbacks(GuestArch::X86_64);
    assert_eq!(fallbacks.len(), 1, "{fallbacks:?}");
    let fallback = &fallbacks[0];
    assert_eq!(fallback.setting, FallbackSetting::Preset);
    assert!(
        fallback.summary.contains("arm64 only"),
        "{}",
        fallback.summary
    );
    assert_eq!(
        profile.for_arch(GuestArch::X86_64),
        StealthProfile::transparent()
    );

    let vm = VmConfig {
        base_identity: Some("base".into()),
        stealth: profile.clone(),
        ..VmConfig::default()
    };
    let x86 = vm_fallbacks(&vm, &[base(GuestArch::X86_64, R22)], &HostSupport::all());
    assert_eq!(x86.len(), 1, "{x86:?}");
    assert_eq!(x86[0].setting, FallbackSetting::Preset);
    // On arm64 only its uptime is not applied (see the arm64 test below).
    let arm = vm_fallbacks(&vm, &[base(GuestArch::AARCH64, R22)], &HostSupport::all());
    assert_eq!(
        arm.iter()
            .map(|fallback| fallback.setting)
            .collect::<Vec<_>>(),
        [FallbackSetting::Uptime],
        "{arm:?}"
    );
    // Its list is Normal QEMU's.
    assert_eq!(
        profile.still_visible(&VmView::default()),
        StealthProfile::transparent().still_visible(&VmView::default())
    );
}

#[test]
fn the_x86_list_follows_the_network_display_chipset_and_cpu() {
    let mut profile = StealthProfile::transparent();
    let nat = VmView::default();
    let list = profile.still_visible(&nat);
    assert!(has(&list, "52:54:00:12:34:56") && has(&list, "virtio network card"));
    assert!(has(&list, "10.0.2.x"));
    assert!(has(&list, "QEMU's standard VGA"));
    assert!(has(&list, "q35 chipset"));
    assert!(has(&list, "one socket per CPU"));
    // A disconnected VM has no network card to give away.
    let off = VmView {
        network: VmNetwork::Disconnected,
        ..nat
    };
    let list = profile.still_visible(&off);
    assert!(!has(&list, "52:54:00") && !has(&list, "virtio network card"));
    assert!(!has(&list, "10.0.2.x"));
    // A fixed resolution is virtio-gpu.
    let list = profile.still_visible(&VmView {
        display: Display::VirtioGpu,
        ..nat
    });
    assert!(has(&list, "virtio-gpu") && !has(&list, "standard VGA"));
    // i440FX, one socket of N cores, no HPET, a brand over passthrough.
    profile.machine = MachineType::Pc;
    profile.realistic_topology = true;
    profile.hpet = false;
    profile.cpu_passthrough = true;
    profile.cpu_brand = "Intel(R) Core(TM) i5".into();
    let list = profile.still_visible(&nat);
    assert!(has(&list, "i440FX chipset") && !has(&list, "q35"));
    assert!(!has(&list, "one socket per CPU"));
    assert!(has(&list, "no HPET timer"));
    assert!(has(&list, "behind the brand string"));
    assert!(!has(&list, "QEMU CPU model name"));
    // The provider's CPU name belongs to a cloud profile only.
    assert!(!has(&list, "provider's CPU name"));
    // QEMU's ACPI creator ID is listed once the identity hides the rest.
    assert!(!has(&list, "BXPC"));
    profile.identity_enabled = true;
    assert!(has(&profile.still_visible(&nat), "BXPC"));
}

#[test]
fn the_facade_entries_need_a_facade_base_and_debians_need_debian() {
    let profile = StealthProfile::realistic(StealthPreset::RealisticLaptop, "GenuineIntel");
    if launch::facade_options(&profile, false).is_empty() {
        return;
    }
    let busybox = profile.still_visible(&VmView::default());
    assert!(has(&busybox, "I/O ports"));
    assert!(!has(&busybox, "udev's device database"));
    let debian = profile.still_visible(&VmView {
        debian: true,
        ..VmView::default()
    });
    assert!(has(&debian, "udev's device database"));
    let old = profile.still_visible(&VmView {
        facade: false,
        ..VmView::default()
    });
    assert!(!has(&old, "I/O ports") && has(&old, "Red Hat PCI subsystem IDs"));
}

#[test]
fn the_cloud_metadata_entry_goes_away_on_a_routed_network() {
    let profile = StealthProfile::cloud_vps(&CLOUDS[0]);
    let nat = profile.still_visible(&VmView::default());
    assert!(has(&nat, "no metadata service"));
    assert!(has(&nat, "provider's CPU name"));
    let routed = profile.still_visible(&VmView {
        network: VmNetwork::Routed,
        ..VmView::default()
    });
    assert!(!has(&routed, "metadata"));
}

#[test]
fn the_arm64_list_follows_the_machine_uptime_kpti_and_card() {
    let arm = VmView {
        arch: GuestArch::AARCH64,
        display: Display::VirtioGpu,
        ..VmView::default()
    };
    // Normal QEMU: QEMU's own card, address and disk; a fresh boot.
    let plain = StealthProfile::transparent();
    let list = plain.still_visible(&arm);
    assert!(has(&list, "dummy-virt"));
    assert!(has(&list, "virtio network card") && has(&list, "52:54:00"));
    assert!(has(&list, "virtio disk vda"));
    assert!(has(&list, "a fresh boot"));
    assert!(!has(&list, "KPTI"));
    assert!(has(
        &plain.still_visible(&VmView {
            fast_emulation: true,
            ..arm
        }),
        "KPTI"
    ));
    // The IoT device: the board's entries; a fresh boot, as the arm64 guest
    // ignores a boot age (it says so beside Uptime).
    let iot = StealthProfile::iot();
    assert!(iot.boot_age_s > 0);
    let list = iot.still_visible(&arm);
    assert!(has(&list, "BCM2711/BCM2712"), "{list:?}");
    assert!(!has(&list, "virtio network card") && !has(&list, "dummy-virt"));
    assert!(has(&list, "a fresh boot"), "{list:?}");
    assert_eq!(iot.for_arch(GuestArch::AARCH64).boot_age_s, 0);
    assert_eq!(iot.for_arch(GuestArch::AARCH64).identity, iot.identity);
    let fallbacks = iot.arch_fallbacks(GuestArch::AARCH64);
    assert_eq!(fallbacks.len(), 1);
    assert_eq!(fallbacks[0].setting, FallbackSetting::Uptime);
    assert!(fallbacks[0].summary.contains("fresh boot"));
    // No other base of the architecture is offered for it.
    let bases = [base(GuestArch::AARCH64, &[]), {
        let mut other = base(GuestArch::AARCH64, R22);
        other.id = "other".into();
        other
    }];
    assert!(
        base_supporting(
            &iot,
            FallbackSetting::Uptime,
            Some("base"),
            &bases,
            &HostSupport::all()
        )
        .is_none()
    );
    // A workstation without UEFI is shown as a board, and says so.
    let desktop = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
    assert!(has(&desktop.still_visible(&arm), "AAVMF"));
    let no_uefi = desktop.still_visible(&VmView { uefi: false, ..arm });
    assert!(has(&no_uefi, "BCM2711/BCM2712") && !has(&no_uefi, "AAVMF"));
    // No x86 entry on arm64.
    assert!(!has(&list, "CPUID") && !has(&list, "KVM"));
}

#[test]
fn the_view_reads_the_vm_and_its_base() {
    let mut vm = VmConfig {
        nat: true,
        ..VmConfig::default()
    };
    let x86 = base(GuestArch::X86_64, &[]);
    let view = VmView::of(&vm, Some(&x86), true);
    assert_eq!(view.network, VmNetwork::Nat);
    assert!(!view.facade && !view.uefi && !view.debian);
    assert_eq!(view.display, Display::StdVga);
    vm.launch.resolution = crate::api::DisplayResolution::R1280x800;
    assert_eq!(
        VmView::of(&vm, Some(&x86), true).display,
        Display::VirtioGpu
    );
    let arm = base(GuestArch::AARCH64, R22);
    let view = VmView::of(&vm, Some(&arm), true);
    assert!(view.uefi && view.facade);
    assert!(!VmView::of(&vm, Some(&arm), false).uefi);
}

#[test]
fn a_custom_profile_on_a_server_keeps_the_server_uptime_range() {
    let mut server = StealthProfile::realistic(StealthPreset::RealisticServer, "GenuineIntel");
    server.preset = StealthPreset::Custom;
    assert_eq!(BootAge::of(&server), BootAge::Server);
    let mut desktop = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
    desktop.preset = StealthPreset::Custom;
    assert_eq!(BootAge::of(&desktop), BootAge::Desktop);
}

#[test]
fn a_preset_picked_for_an_arm64_vm_draws_no_uptime_but_a_held_one_stays() {
    // Freshly picked on arm64 (every preset, IoT too): no uptime, so no
    // "not applied" line; on x86-64 the preset's draw stays.
    for &preset in StealthPreset::ALL {
        let drawn = StealthProfile::transparent()
            .for_preset(preset, "GenuineIntel")
            .drawn_for(GuestArch::AARCH64);
        assert_eq!(drawn.boot_age_s, 0, "{preset:?}");
        assert!(
            drawn.arch_fallbacks(GuestArch::AARCH64).is_empty(),
            "{preset:?}: {:?}",
            drawn.arch_fallbacks(GuestArch::AARCH64)
        );
    }
    let x86 = StealthProfile::transparent()
        .for_preset(StealthPreset::RealisticServer, "GenuineIntel")
        .drawn_for(GuestArch::X86_64);
    assert!(x86.boot_age_s > 0);
    // A profile that already holds an uptime keeps it stored (an x86-64 VM
    // uses it) and arm64 says it is not applied.
    let held = StealthProfile::iot();
    assert!(held.boot_age_s > 0);
    let fallbacks = held.arch_fallbacks(GuestArch::AARCH64);
    assert_eq!(fallbacks[0].setting, FallbackSetting::Uptime);
    assert_eq!(
        held.for_arch(GuestArch::X86_64).preset,
        StealthPreset::Transparent
    );
}

#[test]
fn a_new_vm_on_an_arm64_base_starts_as_the_iot_device() {
    // ANT-T0555 item 3.
    assert_eq!(
        StealthPreset::default_for(GuestArch::AARCH64),
        StealthPreset::Iot
    );
    assert_eq!(
        StealthPreset::default_for(GuestArch::X86_64),
        StealthPreset::RealisticDesktop
    );
    let arm = StealthProfile::new_vm(GuestArch::AARCH64, "GenuineIntel");
    assert_eq!(arm.preset, StealthPreset::Iot);
    assert_eq!(arm.boot_age_s, 0, "an arm64 guest takes no uptime");
    assert!(arm.arch_fallbacks(GuestArch::AARCH64).is_empty());
    let x86 = StealthProfile::new_vm(GuestArch::X86_64, "GenuineIntel");
    assert_eq!(x86.preset, StealthPreset::RealisticDesktop);
}

/// The size lines of `profile` for a VM of that size.
fn hints(profile: &StealthProfile, cpus: u16, ram_gib: u32, disk_gib: u32) -> Vec<String> {
    resource_hints(profile, cpus, ram_gib * 1024, disk_gib)
}

#[test]
fn the_size_lines_follow_the_profile_and_name_its_machines() {
    // ANT-T0555 item 4: each profile's own normal range.
    let desktop = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
    let laptop = StealthProfile::realistic(StealthPreset::RealisticLaptop, "GenuineIntel");
    let server = StealthProfile::realistic(StealthPreset::RealisticServer, "GenuineIntel");
    let cloud = StealthProfile::realistic(StealthPreset::CloudVps, "GenuineIntel");
    let iot = StealthProfile::iot();
    assert_eq!(TypicalSize::of(&desktop), &PC_SIZE);
    assert_eq!(TypicalSize::of(&laptop), &PC_SIZE);
    assert_eq!(TypicalSize::of(&StealthProfile::transparent()), &PC_SIZE);
    assert_eq!(TypicalSize::of(&server), &SERVER_SIZE);
    assert_eq!(TypicalSize::of(&cloud), &CLOUD_SIZE);
    assert_eq!(TypicalSize::of(&iot), &IOT_SIZE);
    // The IoT device on x86-64 starts as Normal QEMU: a PC's lines.
    assert_eq!(TypicalSize::of(&iot.for_arch(GuestArch::X86_64)), &PC_SIZE);
    // A Custom profile on a catalog server keeps the server's.
    let mut custom = server.clone();
    custom.preset = StealthPreset::Custom;
    assert_eq!(TypicalSize::of(&custom), &SERVER_SIZE);

    // Desktop and laptop: as before (checks flag 1 CPU, under 4 GiB, under
    // 60 GiB).
    for pc in [&desktop, &laptop] {
        assert_eq!(
            hints(pc, 1, 2, 20),
            [
                "1 CPU: checks flag fewer than 2; PCs have 4 to 16 threads",
                "under 4 GiB RAM: checks flag it; PCs have 8 to 32 GiB",
                "a disk under 60 GiB: checks flag it; PCs have 256 GiB or more (a BusyBox \
                 base grows its filesystem on the first boot: for 256 GiB about 400 MiB of \
                 image and two minutes)",
            ]
        );
        assert!(hints(pc, 2, 4, 60).is_empty());
        assert!(hints(pc, 64, 512, 2048).is_empty(), "no upper bound");
    }

    // Raspberry Pi: 1 to 8 GiB of RAM, flagged outside; a disk under 8 GiB.
    assert!(hints(&iot, 4, 1, 8).is_empty());
    assert!(hints(&iot, 4, 4, 32).is_empty());
    assert!(hints(&iot, 4, 8, 128).is_empty());
    assert!(hints(&iot, 4, 8, 1024).is_empty(), "a USB SSD is fine");
    assert_eq!(
        resource_hints(&iot, 4, 512, 4),
        [
            "under 1 GiB RAM: Raspberry Pis have 1 to 8 GiB",
            "a disk under 8 GiB: Raspberry Pis have 16 to 128 GiB (a microSD card, or a USB \
             SSD up to 500 GB)",
        ]
    );
    assert_eq!(
        hints(&iot, 4, 16, 32),
        ["over 8 GiB RAM: Raspberry Pis have 1 to 8 GiB"]
    );
    assert_eq!(hints(&iot, 1, 2, 32), ["1 CPU: Raspberry Pis have 4 cores"]);

    // Cloud VPS: 1 vCPU is an ordinary plan; 1 to 64 GiB, 20 to 200 GiB.
    assert!(hints(&cloud, 1, 1, 20).is_empty());
    assert!(hints(&cloud, 8, 64, 200).is_empty());
    assert_eq!(
        resource_hints(&cloud, 1, 512, 10),
        [
            "under 1 GiB RAM: cloud VPS instances have 1 to 64 GiB",
            "a disk under 20 GiB: cloud VPS instances have 20 to 200 GiB",
        ]
    );
    assert_eq!(
        hints(&cloud, 2, 128, 500),
        [
            "over 64 GiB RAM: cloud VPS instances have 1 to 64 GiB",
            "a disk over 200 GiB: cloud VPS instances have 20 to 200 GiB",
        ]
    );

    // Server: 8 GiB, 240 GiB and 4 CPUs at least.
    assert!(hints(&server, 4, 8, 240).is_empty());
    let lines = hints(&server, 2, 4, 100);
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[0], "2 CPUs: servers have 8 to 64 threads");
    assert_eq!(lines[1], "under 8 GiB RAM: servers have 16 to 256 GiB");
    assert!(
        lines[2].starts_with("a disk under 240 GiB: servers have 480 GiB or more"),
        "{lines:?}"
    );

    // The VM dialog's hints say the same ranges.
    assert_eq!(
        IOT_SIZE.ram_help(),
        "Raspberry Pis have 1 to 8 GiB (flagged under 1 GiB or over 8 GiB)"
    );
    assert_eq!(
        PC_SIZE.ram_help(),
        "PCs have 8 to 32 GiB (checks flag under 4 GiB)"
    );
    assert_eq!(
        CLOUD_SIZE.cpu_help(),
        "cloud VPS instances have 1 to 16 vCPUs"
    );
    assert!(PC_SIZE.disk_help().ends_with("two minutes"));
}
