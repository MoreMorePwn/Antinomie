// SPDX-License-Identifier: GPL-3.0-only
use super::launch::*;
use super::*;
use crate::storage::unique_id;
use std::process::Command;

fn provider(id: &str) -> &'static CloudProvider {
    CloudProvider::find(id).unwrap()
}

#[test]
fn chipset_advice_matches_the_transport_boundary_without_changing_the_profile() {
    let pc = MachineType::Pc;
    for ram in [256u64 << 20, 2816u64 << 20, 8192u64 << 20] {
        let (effective, note) = pc.for_ram(ram);
        let falls_back = ram >= 2816 << 20;
        assert_eq!(effective == MachineType::Q35, falls_back);
        assert_eq!(note.is_some(), falls_back);
        assert_eq!(MachineType::Q35.for_ram(ram), (MachineType::Q35, None));
    }
    assert_eq!(pc.for_ram((2816 << 20) - 1), (pc, None));
    assert_eq!(pc, MachineType::Pc);
}

fn args_of(profile: &StealthProfile, ram_mib: u32) -> (Vec<String>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("ant-cloud-{}", unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut command = Command::new("qemu");
    apply(&mut command, profile, &dir, ram_mib, 2).unwrap();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    (args, dir)
}

#[test]
fn every_provider_is_a_valid_profile_with_the_hypervisor_left_visible() {
    for provider in CLOUDS {
        let profile = StealthProfile::cloud_vps(provider);
        profile.validate().unwrap();
        assert_eq!(profile.preset, StealthPreset::CloudVps);
        assert_eq!(profile.cloud_provider().unwrap().id, provider.id);
        assert!(!profile.hide_hypervisor && !profile.hide_kvm && profile.kvm_clock);
        let cpu = cpu_option(&profile, None, true, 2).unwrap_or_default();
        assert!(
            !cpu.contains("-hypervisor") && !cpu.contains("kvm=off") && !cpu.contains("-kvmclock"),
            "{cpu}"
        );
        assert_eq!(profile.rating(), "unlikely");
        assert!(
            profile
                .giveaways()
                .iter()
                .all(|text| !text.contains("CPUID hypervisor flag"))
        );
        assert_eq!(profile.nic, NicModel::VirtioNet);
        assert_eq!(profile.disk_bus, DiskBus::Virtio);
        assert_eq!(profile.firmware, Firmware::Bios);
        assert!(profile.nat.validate().is_ok() && !profile.nat.network.is_empty());
        match provider.mac_prefix {
            Some([a, b, c]) => assert!(
                profile
                    .mac
                    .starts_with(&format!("{a:02x}:{b:02x}:{c:02x}:")),
                "{}",
                profile.mac
            ),
            None => assert_eq!(
                u8::from_str_radix(&profile.mac[..2], 16).unwrap() & 3,
                2,
                "{}",
                profile.mac
            ),
        }
    }
}

#[test]
fn the_chipset_follows_the_provider() {
    let machine = |id: &str| machine_options(&StealthProfile::cloud_vps(provider(id)));
    assert_eq!(
        StealthProfile::cloud_vps(provider("cloud-tencent-cvm"))
            .machine
            .qemu(),
        "pc"
    );
    assert_eq!(
        StealthProfile::cloud_vps(provider("cloud-alibaba-ecs"))
            .machine
            .qemu(),
        "pc"
    );
    assert_eq!(
        StealthProfile::cloud_vps(provider("cloud-digitalocean-droplet"))
            .machine
            .qemu(),
        "pc"
    );
    assert_eq!(
        StealthProfile::cloud_vps(provider("cloud-vultr-vc2"))
            .machine
            .qemu(),
        "q35"
    );
    // Tencent's guests have the VMware mouse port; the others do not.
    assert!(!machine("cloud-tencent-cvm").contains("vmport=off"));
    assert!(machine("cloud-vultr-vc2").contains("vmport=off"));
    assert_eq!(
        StealthProfile::cloud_vps(provider("cloud-tencent-cvm")).nic_slot(),
        NicSlot::Pc
    );
    assert_eq!(NicSlot::Pc.address(), "addr=0x3");
    assert_eq!(NicSlot::from_interface("ens3"), Some(NicSlot::Pc));
    assert_eq!(
        StealthProfile::cloud_vps(provider("cloud-vultr-vc2")).nic_slot(),
        NicSlot::Ich
    );
}

#[test]
fn tencent_firmware_strings_are_the_providers_and_say_virtual_machine() {
    let profile = StealthProfile::cloud_vps(provider("cloud-tencent-cvm"));
    let (args, dir) = args_of(&profile, 2048);
    assert!(
        args.iter()
            .any(|arg| arg.starts_with("type=1,manufacturer=Tencent Cloud,product=CVM,version=3.0"))
    );
    let bios = std::fs::read(dir.join("smbios-bios.bin")).unwrap();
    assert_eq!(bios[0x13] & 0x10, 0x10, "the virtual machine bit is set");
    assert!(bios.windows(7).any(|part| part == b"SeaBIOS"));
    assert!(
        bios.windows(30)
            .any(|part| part.starts_with(b"seabios-1.9.1-qemu-project.org"))
    );
    // Chassis type 1 (Other), QEMU's maker.
    let chassis = std::fs::read(dir.join("smbios-chassis.bin")).unwrap();
    assert_eq!(chassis[5], 1);
    assert!(chassis.windows(4).any(|part| part == b"QEMU"));
    // One DIMM of the VM's size, made by the provider's string.
    let memory = std::fs::read(dir.join("smbios-memory-0.bin")).unwrap();
    assert_eq!(u16::from_le_bytes([memory[0x0c], memory[0x0d]]), 2048);
    assert!(memory.windows(7).any(|part| part == b"Smdbmds"));
    assert!(!dir.join("smbios-memory-1.bin").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn processor_table_names_the_providers_maker_and_machine_type() {
    let profile = StealthProfile::cloud_vps(provider("cloud-alibaba-ecs"));
    let (args, dir) = args_of(&profile, 1024);
    // The type 4 table is the last of the processor's files; hosts whose CPU
    // /proc/cpuinfo does not describe write QEMU's option instead.
    let table = (0..4)
        .map(|index| dir.join(format!("smbios-processor-{index}.bin")))
        .rfind(|path| path.exists());
    if let Some(table) = table {
        let bytes = std::fs::read(table).unwrap();
        assert!(bytes.windows(13).any(|part| part == b"Alibaba Cloud"));
        assert!(bytes.windows(13).any(|part| part == b"pc-i440fx-2.1"));
        assert!(!bytes.windows(5).any(|part| part == b"Intel"));
    } else {
        assert!(args.iter().any(|arg| arg.starts_with("type=4")));
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn instance_state_is_per_vm_and_stable() {
    let provider = provider("cloud-tencent-cvm");
    let uuid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    let id = provider.instance_id(uuid);
    assert_eq!(id, provider.instance_id(uuid));
    assert!(id.starts_with("ins-") && id.len() == 12, "{id}");
    assert_ne!(
        id,
        provider.instance_id("1f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
    );
    let files = provider.state_files(&id, &provider.hostname(&id), 2_000_000_000);
    let find = |path: &str| files.iter().find(|file| file.path == path).unwrap();
    assert_eq!(
        find("/var/lib/cloud/data/instance-id").content,
        format!("{id}\n").into_bytes()
    );
    assert!(String::from_utf8_lossy(&find("/var/log/cloud-init.log").content).contains(&id));
    assert!(
        files
            .iter()
            .any(|file| file.path.starts_with("/usr/local/qcloud/"))
    );
    // Inert stubs and text, never a provider's binary; aged, not new.
    assert!(
        files
            .iter()
            .all(|file| file.content.len() < 4096 && file.mtime < 2_000_000_000)
    );
    assert_eq!(
        find(&format!("/home/{}/.bash_history", "ubuntu")).owner,
        Owner::User
    );
    // wtmp: whole 384-byte records, the last one an ended login.
    let wtmp = &find("/var/log/wtmp").content;
    assert!(wtmp.len() % 384 == 0 && wtmp.len() >= 5 * 384);
    assert_eq!(
        i16::from_le_bytes([wtmp[wtmp.len() - 384], wtmp[wtmp.len() - 383]]),
        8
    );
    let root = super::CloudProvider::find("cloud-vultr-vc2").unwrap();
    assert!(
        root.state_files("x", "h", 2_000_000_000)
            .iter()
            .any(|file| file.path == "/root/.bash_history")
    );
}

#[test]
fn stored_plan_hints_match_only_their_recorded_sizes() {
    let digitalocean = provider("cloud-digitalocean-droplet");
    assert_eq!(digitalocean.plan_for(1, 1024).unwrap().name, "s-1vcpu-1gb");
    assert!(digitalocean.plan_for(3, 1000).is_none());
    for provider in CLOUDS {
        assert!(!provider.plans.is_empty());
    }
}

#[test]
fn rerandomize_keeps_a_clouds_serial_form_and_a_machine_switch_leaves_the_cloud() {
    let mut profile = StealthProfile::cloud_vps(provider("cloud-digitalocean-droplet"));
    let before = profile.identity.clone();
    profile.identity.rerandomize();
    assert_ne!(before.system_uuid, profile.identity.system_uuid);
    assert_eq!(profile.identity.system_serial.len(), 9);
    assert!(
        profile
            .identity
            .system_serial
            .chars()
            .all(|c| c.is_ascii_digit())
    );
    profile.use_machine(&MACHINES[0]);
    assert!(profile.cloud.is_empty() && profile.machine == MachineType::Q35);
    let mut unknown = StealthProfile::cloud_vps(provider("cloud-vultr-vc2"));
    unknown.cloud = "cloud-nowhere".into();
    assert!(unknown.validate().is_err());
}

#[test]
fn a_profile_saved_before_the_cloud_presets_loads_as_q35_without_a_cloud() {
    let json = serde_json::to_value(StealthProfile::transparent()).unwrap();
    let mut old = json.as_object().unwrap().clone();
    old.remove("machine");
    old.remove("cloud");
    let loaded: StealthProfile = serde_json::from_value(old.into()).unwrap();
    assert_eq!(loaded.machine, MachineType::Q35);
    assert!(loaded.cloud.is_empty());
}
