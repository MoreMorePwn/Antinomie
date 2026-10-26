// SPDX-License-Identifier: GPL-3.0-only
use super::launch::*;
use super::smbios::*;
use super::*;
use crate::storage::unique_id;
use std::process::Command;

#[test]
fn presets_fill_a_realistic_identity_matching_the_host_cpu() {
    let amd = StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD");
    assert_eq!(amd.identity.profile, "lenovo-m75q-gen2");
    let intel = StealthProfile::realistic(StealthPreset::RealisticLaptop, "GenuineIntel");
    assert_eq!(intel.identity.profile, "dell-latitude-5420");
    assert_eq!(intel.identity.chassis_type, 10);
    let server = StealthProfile::realistic(StealthPreset::RealisticServer, "unknown");
    assert_eq!(server.identity.chassis_type, 23);
    for profile in [&amd, &intel, &server] {
        profile.validate().unwrap();
        assert!(profile.mac.starts_with("3c:fd:fe:"));
        assert_eq!(profile.rating(), "unlikely");
        assert_eq!(profile.identity.system_uuid.len(), 36);
    }
    // Two VMs never share their serials or MAC address.
    assert_ne!(
        amd.identity.system_serial,
        StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD")
            .identity
            .system_serial
    );
    assert_ne!(
        amd.mac,
        StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD").mac
    );
}

#[test]
fn transparent_keeps_qemu_launch_options_and_rates_certain() {
    let profile = StealthProfile::transparent();
    assert_eq!(profile.rating(), "certain");
    assert_eq!(smp_option(&profile, 4), "4");
    assert_eq!(nic_option(&profile), "virtio-net-pci,netdev=net0");
    assert_eq!(nic_option_for(&profile, None), "virtio-net-pci,netdev=net0");
    // A base that names its NIC by slot gets it there, any model.
    let onboard = BaseSupport::from_list(&["dhcp".into(), "onboardnic".into()]);
    assert!(onboard.onboard_nic && BaseSupport::all().onboard_nic);
    assert_eq!(profile.nic_slot(), NicSlot::Ich);
    assert_eq!(
        nic_option_for(&profile, Some(profile.nic_slot())),
        "virtio-net-pci,netdev=net0,addr=0x19"
    );
    let mut intel = profile.clone();
    intel.nic = NicModel::E1000e;
    assert_eq!(
        nic_option_for(&intel, Some(NicSlot::Pch)),
        "e1000e,netdev=net0,addr=0x1f.0x6"
    );
    assert_eq!(cpu_option(&profile, None, true, 4), None);
    assert_eq!(
        cpu_option(&profile, Some("max"), true, 4).as_deref(),
        Some("max")
    );
    assert_eq!(machine_options(&profile), "");
    // Old saved configurations have no profile and stay transparent.
    let old: StealthProfile = serde_json::from_str("{}").unwrap();
    assert_eq!(old, StealthProfile::transparent());
}

#[test]
fn realistic_options_hide_the_hypervisor_and_carry_the_identity() {
    let mut profile = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
    // Two threads per core add TOPOEXT on an AMD host.
    profile.smt = false;
    assert_eq!(
        cpu_option(&profile, None, true, 4).as_deref(),
        Some("host,host-cache-info=on,-hypervisor,kvm=off,pmu=on")
    );
    assert!(
        cpu_option(&profile, None, false, 4)
            .unwrap()
            .starts_with("max,model-id=")
    );
    assert_eq!(smp_option(&profile, 4), "4,sockets=1,cores=4,threads=1");
    assert!(nic_option(&profile).starts_with("e1000e,netdev=net0,mac=3c:fd:fe:"));
    let machine = machine_options(&profile);
    assert!(machine.contains(",vmport=off"));
    assert!(machine.contains(",usb=on"));
    assert!(machine.contains(",x-oem-id=DELL  "));
    let mut local = profile.clone();
    local.new_local_mac();
    let first = u8::from_str_radix(&local.mac[..2], 16).unwrap();
    assert_eq!(first & 3, 2, "{}", local.mac);
    assert!(local.validate().is_ok());
    let dir = std::env::temp_dir().join(format!("ant-stealth-{}", unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut command = Command::new("qemu");
    apply(&mut command, &profile, &dir).unwrap();
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(
        args.iter()
            .any(|arg| arg.starts_with("type=1,manufacturer=Dell Inc.,product=OptiPlex 7090"))
    );
    assert!(
        args.iter()
            .any(|arg| arg.starts_with("virtio-blk-pci.serial=S6PXNF0T"))
    );
    let chassis = std::fs::read(dir.join("smbios-chassis.bin")).unwrap();
    assert_eq!(&chassis[..6], &[3, 0x16, 0, 3, 1, 3]);
    assert!(chassis.ends_with(b"Default string\0\0"));
    // The BIOS table: no VM bit, Dell's strings, release 1.21.
    let bios = std::fs::read(dir.join("smbios-bios.bin")).unwrap();
    assert_eq!(&bios[..6], &[0, 0x1a, 0, 0, 1, 2]);
    assert_eq!(bios[8], 3);
    assert_eq!(bios[0x13] & 0x10, 0, "the virtual machine bit is clear");
    assert_eq!(bios[0x0a] & 0x08, 0, "characteristics are listed");
    assert_eq!(&bios[0x14..0x16], &[1, 21]);
    assert_eq!(&bios[0x1a..], b"Dell Inc.\x001.21.0\x0008/14/2024\x00\x00");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn smbios_strings_are_numbered_and_empty_ones_are_zero() {
    assert_eq!(
        string_set(&["", "a", "bc"]),
        (vec![0, 1, 2], b"a\0bc\0\0".to_vec())
    );
    assert_eq!(string_set(&["", ""]), (vec![0, 0], b"\0\0".to_vec()));
    assert_eq!(bios_release("S21 Ver. 02.15.00"), Some((21, 2)));
    assert_eq!(bios_release("A1"), None);
    let bios = bios_table(&MachineIdentity::default(), false);
    assert_eq!(bios.len(), 0x1a + 2);
    assert_eq!((bios[0x14], bios[0x15]), (0xff, 0xff));
}

#[test]
fn commas_are_escaped_and_bad_addresses_are_refused() {
    let mut profile = StealthProfile::realistic(StealthPreset::RealisticServer, "AuthenticAMD");
    assert!(machine_options(&profile).contains("x-oem-id=SUPERM"));
    let dir = std::env::temp_dir().join(format!("ant-stealth-{}", unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut command = Command::new("qemu");
    apply(&mut command, &profile, &dir).unwrap();
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let bios = std::fs::read(dir.join("smbios-bios.bin")).unwrap();
    assert!(
        bios.windows(24)
            .any(|part| part == b"American Megatrends Inc.")
    );
    assert!(!args.iter().any(|arg| arg.starts_with("type=0")));
    std::fs::remove_dir_all(dir).unwrap();
    profile.identity.bios_vendor = "Vendor, Inc.".into();
    assert_eq!(escape(&profile.identity.bios_vendor), "Vendor,, Inc.");
    profile.mac = "01:00:00:00:00:01".into();
    assert!(profile.validate().is_err());
    profile.mac = "zz".into();
    assert!(profile.validate().is_err());
    profile.mac.clear();
    profile.identity.system_uuid = "not-a-uuid".into();
    assert!(profile.validate().unwrap_err().contains("UUID"));
    profile.identity.system_uuid = uuid();
    profile.identity.memory_part = "line\nbreak".into();
    assert!(profile.validate().is_err());
}

fn launch_args(profile: &StealthProfile) -> Vec<String> {
    let dir = std::env::temp_dir().join(format!("ant-stealth-{}", unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut command = Command::new("qemu");
    apply(&mut command, profile, &dir).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn profiles_saved_before_these_entries_launch_as_before() {
    // A 0.6.2 Realistic profile: none of the firmware, disk, topology,
    // pointer, clock or NAT entries.
    let mut saved = serde_json::to_value(StealthProfile::realistic(
        StealthPreset::RealisticDesktop,
        "GenuineIntel",
    ))
    .unwrap();
    for key in [
        "firmware",
        "disk_bus",
        "disk_media",
        "smt",
        "pointer",
        "smbios_entry",
        "cpu_model",
        "cpu_brand",
        "model_cache_info",
        "kvm_clock",
        "smm",
        "rtc_clock",
        "rtc_driftfix",
        "cdrom",
        "nat",
    ] {
        saved.as_object_mut().unwrap().remove(key);
    }
    for key in [
        "disk_model",
        "disk_firmware",
        "disk_wwn",
        "oem_strings",
        "nic_subsystem",
    ] {
        saved["identity"].as_object_mut().unwrap().remove(key);
    }
    let old: StealthProfile = serde_json::from_value(saved).unwrap();
    assert_eq!(old.firmware, Firmware::Bios);
    assert_eq!(old.disk_bus, DiskBus::Virtio);
    assert!(!old.smt && !old.cdrom && old.smm && old.kvm_clock);
    assert_eq!(smp_option(&old, 4), "4,sockets=1,cores=4,threads=1");
    assert_eq!(
        disk_args(&old, "/d.qcow2"),
        [
            "-drive",
            "file=/d.qcow2,format=qcow2,if=virtio,id=osdisk,node-name=antinomie-disk"
        ]
    );
    let machine = machine_options(&old);
    assert!(
        machine.ends_with(",smbios-entry-point-type=64,x-oem-id=DELL  ,x-oem-table-id=CBX3    ")
    );
    assert!(!machine.contains("smm"));
    assert_eq!(netdev_option("user,id=net0", &old), "user,id=net0");
    assert!(nic_option(&old).starts_with("e1000e,netdev=net0,mac=3c:fd:fe:"));
    assert!(!nic_option(&old).contains("subsys"));
    let args = launch_args(&old);
    assert!(
        !args
            .iter()
            .any(|arg| arg.starts_with("type=11") || arg == "-rtc")
    );
    assert!(!args.iter().any(|arg| arg.starts_with("ide-cd,")));
}

#[test]
fn realistic_hardware_entries_become_launch_options() {
    let mut profile = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
    assert_eq!(profile.firmware, Firmware::Uefi);
    assert_eq!(profile.nat, NatNetwork::home());
    assert_eq!(smp_option(&profile, 4), "4,sockets=1,cores=2,threads=2");
    assert_eq!(smp_option(&profile, 3), "3,sockets=1,cores=3,threads=1");
    let sata = disk_args(&profile, "/d.qcow2");
    assert_eq!(
        sata[1],
        "file=/d.qcow2,format=qcow2,if=none,id=osdisk,node-name=antinomie-disk"
    );
    let wwn = format!(",wwn=0x{},rotation_rate=1", profile.identity.disk_wwn);
    assert!(sata[3].starts_with(
        "ide-hd,drive=osdisk,bus=ide.0,model=Samsung SSD 870 EVO 500GB,serial=S6PXNF0T"
    ));
    assert!(
        sata[3].contains(",ver=SVT02B6Q") && sata[3].ends_with(&wwn),
        "{}",
        sata[3]
    );
    assert_eq!(profile.identity.disk_wwn.len(), 16);
    // Dell's onboard card carries Dell's subsystem IDs (1028:0a61).
    assert!(nic_option(&profile).ends_with(",subsys_ven=4136,subsys=2657"));
    assert_eq!(
        netdev_option("user,id=net0,restrict=on", &profile),
        "user,id=net0,restrict=on,net=192.168.1.0/24,host=192.168.1.1,dns=192.168.1.10,dhcpstart=192.168.1.100"
    );
    let args = launch_args(&profile);
    assert!(args.iter().any(|arg| arg == "type=11,value=Dell System,value=1[0A61],value=3[1.0],value=12[www.dell.com],value=14[1],value=15[0]"));
    profile.disk_bus = DiskBus::Nvme;
    profile.disk_media = DiskMedia::Hdd;
    let nvme = disk_args(&profile, "/d.qcow2").join(" ");
    assert!(nvme.contains("nvme,drive=osdisk,serial=S6PXNF0T"));
    assert!(nvme.ends_with(",use-intel-id=on"));
    profile.disk_bus = DiskBus::Sata;
    assert!(
        disk_args(&profile, "/d")
            .last()
            .unwrap()
            .ends_with("rotation_rate=7200")
    );
    profile.cdrom = true;
    profile.rtc_clock = RtcClock::Vm;
    profile.rtc_driftfix = true;
    profile.rtc_localtime = true;
    profile.smm = false;
    profile.smbios_entry = SmbiosEntry::Bits32;
    let args = launch_args(&profile);
    assert!(
        args.windows(2)
            .any(|pair| pair == ["-rtc", "base=localtime,clock=vm,driftfix=slew"])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["-device", "ide-cd,bus=ide.1"])
    );
    let machine = machine_options(&profile);
    assert!(machine.contains(",smm=off") && machine.contains("smbios-entry-point-type=32"));
    profile.firmware = Firmware::UefiSecureBoot;
    assert!(machine_options(&profile).contains(",smm=on"));
    // The BIOS table says "UEFI is supported" under OVMF.
    assert_eq!(bios_table(&profile.identity, true)[0x13], 0x0f);
    assert_eq!(pointer_args(&profile), ["-device", "virtio-tablet-pci"]);
    profile.pointer = Pointer::Ps2;
    assert!(pointer_args(&profile).is_empty());
}

#[test]
fn a_named_cpu_model_carries_its_brand_and_caches() {
    let mut profile = StealthProfile::realistic(StealthPreset::RealisticServer, "AuthenticAMD");
    profile.cpu_passthrough = false;
    profile.hide_kvm = false;
    profile.kvm_clock = false;
    profile.smt = false;
    profile.cpu_model = "EPYC-Rome-v4".into();
    profile.cpu_brand = "AMD Ryzen 5 3600 6-Core Processor".into();
    profile.model_cache_info = true;
    assert_eq!(
        cpu_option(&profile, Some("max"), true, 4).as_deref(),
        Some(
            "EPYC-Rome-v4,model-id=AMD Ryzen 5 3600 6-Core Processor,legacy-cache=off,l3-cache=on,-hypervisor,-kvmclock,pmu=on"
        )
    );
    assert!(profile.giveaways().contains(&"KVM CPUID signature"));
    profile.cpu_model = "EPYC,host".into();
    assert!(profile.validate().is_err());
}

#[test]
fn entries_the_base_or_host_lacks_fall_back() {
    let profile = StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD");
    let (same, notes) = profile.fitted(&BaseSupport::all(), &HostSupport::all());
    assert_eq!((same, notes.len()), (profile.clone(), 0));
    // An older base: no field in its bundle.json.
    let host = HostSupport {
        ovmf: Err("no OVMF".into()),
        ovmf_secure_boot: Err("no OVMF".into()),
        smt: Err("no TOPOEXT".into()),
    };
    let (fitted, notes) = profile.fitted(&BaseSupport::from_list(&[]), &host);
    assert_eq!(fitted.firmware, Firmware::Bios);
    assert_eq!(fitted.disk_bus, DiskBus::Virtio);
    assert_eq!(fitted.nat, NatNetwork::default());
    assert!(!fitted.smt);
    assert_eq!(notes.len(), 4, "{notes:?}");
    assert!(notes[0].contains("transport page"));
    // A new base on a host without OVMF.
    let base = BaseSupport::from_list(&["uefi".into(), "sata".into(), "dhcp".into()]);
    let (fitted, notes) = profile.fitted(&base, &host);
    assert_eq!(
        (fitted.firmware, fitted.disk_bus),
        (Firmware::Bios, DiskBus::Sata)
    );
    assert!(notes[0].contains("no OVMF"));
    let mut secure = profile.clone();
    secure.firmware = Firmware::UefiSecureBoot;
    secure.smm = false;
    secure.disk_bus = DiskBus::Nvme;
    secure.pointer = Pointer::UsbTablet;
    secure.usb = false;
    let (fitted, notes) = secure.fitted(&base, &HostSupport::all());
    assert!(fitted.smm);
    assert_eq!(fitted.disk_bus, DiskBus::Virtio);
    assert_eq!(fitted.pointer, Pointer::VirtioTablet);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert!(super::smt_clean("GenuineIntel", "").is_ok());
    assert!(super::smt_clean("AuthenticAMD", "fpu sse topoext svm").is_ok());
    assert!(super::smt_clean("AuthenticAMD", "fpu sse svm").is_err());
}

#[test]
fn nat_networks_are_private_with_distinct_hosts() {
    assert!(NatNetwork::home().validate().is_ok());
    assert!(NatNetwork::default().validate().is_ok());
    let with = |network: &str, gateway: &str, dns: &str, start: &str| NatNetwork {
        network: network.into(),
        gateway: gateway.into(),
        dns: dns.into(),
        dhcp_start: start.into(),
    };
    assert!(
        with("172.20.0.0/16", "172.20.0.1", "172.20.0.2", "172.20.1.10")
            .validate()
            .is_ok()
    );
    for bad in [
        with("8.8.8.0/24", "8.8.8.1", "8.8.8.2", "8.8.8.100"),
        with(
            "192.168.1.1/24",
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.100",
        ),
        with(
            "192.168.1.0/24",
            "192.168.1.1",
            "192.168.1.1",
            "192.168.1.100",
        ),
        with(
            "192.168.1.0/24",
            "192.168.1.1",
            "192.168.2.2",
            "192.168.1.100",
        ),
        with(
            "192.168.1.0/24",
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.255",
        ),
        with(
            "192.168.1.0/31",
            "192.168.1.0",
            "192.168.1.1",
            "192.168.1.1",
        ),
        with("192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.100"),
        with("10.0.0.0/7", "10.0.0.1", "10.0.0.2", "10.0.0.100"),
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}

#[test]
fn ovmf_descriptors_are_matched_by_interface_and_features() {
    let dir = std::env::temp_dir().join(format!("ant-ovmf-{}", unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (code, vars) = (dir.join("CODE.fd"), dir.join("VARS.fd"));
    std::fs::write(&code, b"code").unwrap();
    std::fs::write(&vars, b"vars").unwrap();
    let descriptor = |features: &[&str], machines: &[&str]| {
        serde_json::json!({
            "interface-types": ["uefi"],
            "mapping": {"device": "flash",
                "executable": {"filename": code, "format": "raw"},
                "nvram-template": {"filename": vars, "format": "raw"}},
            "targets": [{"architecture": "x86_64", "machines": machines}],
            "features": features,
        })
    };
    let plain = descriptor(&["acpi-s3"], &["pc-i440fx-*", "pc-q35-*"]);
    let secure = descriptor(
        &["secure-boot", "enrolled-keys", "requires-smm"],
        &["pc-q35-*"],
    );
    let unenrolled = descriptor(&["secure-boot", "requires-smm"], &["pc-q35-*"]);
    assert_eq!(
        super::firmware::matches(&plain, false),
        Some((code.clone(), vars.clone()))
    );
    assert_eq!(super::firmware::matches(&plain, true), None);
    assert_eq!(
        super::firmware::matches(&secure, true),
        Some((code.clone(), vars.clone()))
    );
    assert_eq!(super::firmware::matches(&secure, false), None);
    assert_eq!(super::firmware::matches(&unenrolled, true), None);
    assert_eq!(
        super::firmware::matches(&descriptor(&[], &["pc-i440fx-*"]), false),
        None
    );
    assert_eq!(
        super::firmware::matches(&descriptor(&["amd-sev-es"], &["pc-q35-*"]), false),
        None
    );
    // The VM copies the template once and keeps its own store.
    let ovmf = Ovmf {
        code,
        vars_template: vars,
        descriptor: dir.join("60-x.json"),
    };
    let store = super::firmware::vm_vars(&ovmf, &dir, false).unwrap();
    assert_eq!(std::fs::read(&store).unwrap(), b"vars");
    std::fs::write(&store, b"boot entries").unwrap();
    assert_eq!(super::firmware::vm_vars(&ovmf, &dir, false).unwrap(), store);
    assert_eq!(std::fs::read(&store).unwrap(), b"boot entries");
    std::fs::remove_dir_all(dir).unwrap();
}

fn base_named(id: &str, support: &[&str]) -> crate::api::BaseSummary {
    crate::api::BaseSummary {
        id: id.into(),
        label: id.into(),
        directory: std::path::PathBuf::new(),
        guest: None,
        min_ram_mib: 0,
        min_disk_gib: 0,
        fixed_display: false,
        size_bytes: 0,
        revision: None,
        min_app_version: None,
        built_with: None,
        stealth_support: support.iter().map(|item| (*item).to_owned()).collect(),
    }
}

/// A profile that asks for every setting `fitted` can change.
fn asks_for_everything() -> StealthProfile {
    let mut profile = StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD");
    profile.firmware = Firmware::UefiSecureBoot;
    profile.disk_bus = DiskBus::Sata;
    profile.nat = NatNetwork::home();
    profile.smt = true;
    profile.realistic_topology = true;
    profile.pointer = Pointer::UsbTablet;
    profile.usb = false;
    profile
}

#[test]
fn every_setting_fitted_can_change_is_listed_with_a_line_for_the_setting() {
    let profile = asks_for_everything();
    let host = HostSupport {
        ovmf: Ok(()),
        ovmf_secure_boot: Ok(()),
        smt: Err("no TOPOEXT".into()),
    };
    let fallbacks = profile.fallbacks(&BaseSupport::from_list(&[]), &host);
    let settings: Vec<_> = fallbacks.iter().map(|fallback| fallback.setting).collect();
    assert_eq!(
        settings,
        [
            FallbackSetting::Firmware,
            FallbackSetting::DiskBus,
            FallbackSetting::Nat,
            FallbackSetting::Smt,
            FallbackSetting::Pointer
        ]
    );
    let line = |setting| {
        fallbacks
            .iter()
            .find(|fallback| fallback.setting == setting)
            .unwrap()
            .summary
            .clone()
    };
    assert_eq!(
        line(FallbackSetting::DiskBus),
        "SATA (AHCI) not supported by this base: virtio will be used"
    );
    assert!(line(FallbackSetting::Firmware).ends_with("BIOS will be used"));
    assert!(line(FallbackSetting::Nat).contains("10.0.2.0/24 will be used"));
    assert!(line(FallbackSetting::Smt).contains("this host"));
    assert!(line(FallbackSetting::Pointer).contains("virtio tablet will be used"));
    // The same entries `fitted` changes, and its notes are these.
    let (fitted, notes) = profile.fitted(&BaseSupport::from_list(&[]), &host);
    assert_eq!(notes.len(), fallbacks.len());
    assert_eq!(fitted.disk_bus, DiskBus::Virtio);
    assert_eq!(fitted.firmware, Firmware::Bios);
    assert_eq!(fitted.pointer, Pointer::VirtioTablet);
    assert!(!fitted.smt);
    // What the start log and the run's notes carry names the setting and why.
    let log = fallbacks[1].log_line();
    assert!(log.starts_with("Stealth setting not applied: SATA (AHCI) not supported by this base"));
    assert!(log.contains("rebuild a BusyBox base"));
}

#[test]
fn a_base_and_host_that_support_everything_ask_for_no_fallback() {
    let profile = asks_for_everything();
    let mut profile = profile;
    profile.usb = true;
    let support = BaseSupport::from_list(&["uefi".into(), "sata".into(), "dhcp".into()]);
    assert!(profile.fallbacks(&support, &HostSupport::all()).is_empty());
    assert!(
        profile
            .fallbacks(&BaseSupport::all(), &HostSupport::all())
            .is_empty()
    );
    let (_, fallbacks) = profile.fitted_with(&BaseSupport::all(), &HostSupport::all());
    assert!(fallbacks.is_empty());
}

#[test]
fn a_vm_on_a_base_without_a_support_list_falls_back_and_one_with_it_does_not() {
    let mut vm = crate::api::VmConfig {
        stealth: StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel"),
        ..Default::default()
    };
    vm.stealth.disk_bus = DiskBus::Sata;
    vm.stealth.firmware = Firmware::Bios;
    vm.stealth.nat = NatNetwork::default();
    let old = base_named("old", &[]);
    let new = base_named("new", &["sata", "uefi", "dhcp"]);
    vm.base_identity = Some("old".into());
    let bases = [old.clone(), new.clone()];
    let host = HostSupport::all();
    let found = vm_fallbacks(&vm, &bases, &host);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].setting, FallbackSetting::DiskBus);
    // The one base that supports it is offered; the VM's own is not.
    let offered = base_supporting(
        &vm.stealth,
        FallbackSetting::DiskBus,
        Some("old"),
        &bases,
        &host,
    );
    assert_eq!(offered.map(|base| base.id.as_str()), Some("new"));
    assert!(
        base_supporting(
            &vm.stealth,
            FallbackSetting::DiskBus,
            Some("old"),
            std::slice::from_ref(&old),
            &host
        )
        .is_none()
    );
    vm.base_identity = Some("new".into());
    assert!(vm_fallbacks(&vm, &bases, &host).is_empty());
    // A base that is not installed has nothing to compare with.
    vm.base_identity = Some("gone".into());
    assert!(vm_fallbacks(&vm, &bases, &host).is_empty());
}

#[test]
fn the_nic_slot_follows_the_chipset_of_the_machine_the_profile_copies() {
    // Every machine says where its chipset's LAN is: Intel's 100 series and
    // later at 00:1f.6, AMD's (no LAN on bus 0) at the ICH's 00:19.0.
    let expected = [
        ("dell-optiplex-7090", NicSlot::Pch),
        ("hp-elitedesk-800-g6", NicSlot::Pch),
        ("lenovo-m75q-gen2", NicSlot::Ich),
        ("hp-elitedesk-805-g8", NicSlot::Ich),
        ("dell-latitude-5420", NicSlot::Pch),
        ("lenovo-t14-gen3-amd", NicSlot::Ich),
        ("supermicro-x12sth", NicSlot::Eno1),
        ("supermicro-h12ssl", NicSlot::Eno1),
    ];
    assert_eq!(MACHINES.len(), expected.len());
    for (id, slot) in expected {
        let machine = MACHINES.iter().find(|machine| machine.id == id).unwrap();
        let mut profile = StealthProfile::transparent();
        profile.use_machine(machine);
        assert_eq!(profile.nic_slot(), slot, "{id}");
        // The chipset's I219 only on Intel machines that have one.
        if slot == NicSlot::Pch {
            assert_eq!(machine.cpu_vendor, "GenuineIntel", "{id}");
        }
        // The identity switched off, or edited away from a known machine:
        // the ICH's slot, as for Transparent.
        profile.identity_enabled = false;
        assert_eq!(profile.nic_slot(), NicSlot::Ich);
        profile.identity_enabled = true;
        profile.identity.profile.clear();
        assert_eq!(profile.nic_slot(), NicSlot::Ich);
    }
    // The presets: Intel hosts get the PCH's slot (a server: the board's
    // LAN by index), AMD hosts the ICH's.
    for (kind, vendor, slot) in [
        (
            StealthPreset::RealisticDesktop,
            "GenuineIntel",
            NicSlot::Pch,
        ),
        (StealthPreset::RealisticLaptop, "GenuineIntel", NicSlot::Pch),
        (
            StealthPreset::RealisticServer,
            "GenuineIntel",
            NicSlot::Eno1,
        ),
        (
            StealthPreset::RealisticDesktop,
            "AuthenticAMD",
            NicSlot::Ich,
        ),
        (StealthPreset::RealisticLaptop, "AuthenticAMD", NicSlot::Ich),
        (
            StealthPreset::RealisticServer,
            "AuthenticAMD",
            NicSlot::Eno1,
        ),
    ] {
        assert_eq!(StealthProfile::realistic(kind, vendor).nic_slot(), slot);
    }
    assert_eq!(StealthProfile::transparent().nic_slot(), NicSlot::Ich);
    // The interface names udev gives each slot, and back.
    for (slot, address, name) in [
        (NicSlot::Ich, "addr=0x19", "enp0s25"),
        (NicSlot::Pch, "addr=0x1f.0x6", "enp0s31f6"),
        (NicSlot::Eno1, "addr=0x19,acpi-index=1", "eno1"),
    ] {
        assert_eq!((slot.address(), slot.interface()), (address, name));
        assert_eq!(NicSlot::from_interface(name), Some(slot));
    }
    assert_eq!(NicSlot::from_interface("eth0"), None);
}
