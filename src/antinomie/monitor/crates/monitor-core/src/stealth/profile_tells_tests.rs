// SPDX-License-Identifier: GPL-3.0-only
//! ANT-T0201: what each kind of profile tells a guest about its CPU and
//! chassis (eval run 1, G6): the QEMU arguments and SMBIOS tables of the
//! default profile, every cloud provider and every machine.
use super::launch::*;
use super::*;
use crate::storage::unique_id;
use std::{collections::BTreeMap, process::Command};

fn launch(profile: &StealthProfile) -> (Vec<String>, BTreeMap<String, Vec<u8>>) {
    let dir = std::env::temp_dir().join(format!("ant-tells-{}", unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut command = Command::new("qemu");
    apply(&mut command, profile, &dir, 2048, 2).unwrap();
    let tables = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            (name, std::fs::read(entry.path()).unwrap())
        })
        .collect();
    std::fs::remove_dir_all(dir).unwrap();
    let args = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    (args, tables)
}

/// The type 3 table's (chassis type, manufacturer, version).
fn chassis(tables: &BTreeMap<String, Vec<u8>>) -> (u8, String, String) {
    let table = &tables["smbios-chassis.bin"];
    assert_eq!(table[0], 3);
    let strings: Vec<String> = table[usize::from(table[1])..]
        .split(|byte| *byte == 0)
        .map(|text| String::from_utf8_lossy(text).into_owned())
        .collect();
    let text = |number: u8| {
        if number == 0 {
            String::new()
        } else {
            strings[usize::from(number) - 1].clone()
        }
    };
    (table[5], text(table[4]), text(table[6]))
}

#[test]
fn the_default_profile_stays_plainly_qemu() {
    let profile = StealthProfile::transparent();
    let (args, tables) = launch(&profile);
    assert!(tables.is_empty());
    assert!(!args.iter().any(|arg| arg == "-smbios"));
    assert_eq!(cpu_option(&profile, None, true, 2), None);
    assert!(
        profile
            .giveaways()
            .iter()
            .any(|text| text.contains("QEMU in the SMBIOS"))
    );
}

#[test]
fn every_cloud_provider_has_its_own_cpu_name_for_each_host_vendor() {
    for provider in CLOUDS {
        let (intel, amd) = provider.cpu_brand;
        assert!(!intel.is_empty() && !amd.is_empty() && intel != amd);
        for brand in [intel, amd] {
            assert!(brand.len() <= 64, "{brand}");
            for tell in ["QEMU", "Virtual", "Ryzen", "Standard PC"] {
                assert!(!brand.contains(tell), "{}: {brand}", provider.id);
            }
        }
        assert_eq!(provider.cpu_brand_for("GenuineIntel"), intel);
        assert_eq!(provider.cpu_brand_for("AuthenticAMD"), amd);
        assert_eq!(provider.cpu_brand_for("HygonGenuine"), amd);
        assert_eq!(provider.cpu_brand_for(""), intel);
        assert!(
            intel.contains("Intel") || intel.starts_with("DO-"),
            "{intel}"
        );
        assert!(amd.contains("AMD") || amd.starts_with("DO-"), "{amd}");
    }
}

#[test]
fn a_cloud_profile_names_the_providers_cpu_not_the_hosts() {
    for provider in CLOUDS {
        let profile = StealthProfile::cloud_vps(provider);
        let expected = provider.cpu_brand_for(&host_cpu_vendor());
        assert_eq!(profile.cloud_cpu_brand().as_deref(), Some(expected));
        let with_kvm = cpu_option(&profile, None, true, 2).unwrap();
        assert!(with_kvm.starts_with("host,"), "{with_kvm}");
        assert!(
            with_kvm.contains(&format!(",model-id={expected}")),
            "{with_kvm}"
        );
        let without_kvm = cpu_option(&profile, None, false, 2).unwrap();
        assert!(
            without_kvm.starts_with(&format!("max,model-id={expected}")),
            "{without_kvm}"
        );
        // The hypervisor stays visible, as on the provider's machines.
        assert!(!with_kvm.contains("-hypervisor") && !with_kvm.contains("kvm=off"));
        // An edited name wins over the provider's.
        let mut edited = profile.clone();
        edited.cpu_brand = "Custom CPU".into();
        assert_eq!(edited.cloud_cpu_brand(), None);
    }
}

#[test]
fn a_cloud_profile_has_the_catalogs_chassis_and_processor_strings() {
    for provider in CLOUDS {
        let profile = StealthProfile::cloud_vps(provider);
        let (_, tables) = launch(&profile);
        let (kind, maker, _) = chassis(&tables);
        assert_eq!(kind, provider.chassis_type, "{}", provider.id);
        assert_eq!(maker, provider.chassis_manufacturer, "{}", provider.id);
        // The processor table shows the provider's maker and version, not the
        // host's brand.
        let processor = tables
            .iter()
            .find(|(name, table)| name.starts_with("smbios-processor") && table[0] == 4)
            .map(|(_, table)| String::from_utf8_lossy(table).into_owned())
            .unwrap();
        assert!(processor.contains(provider.cpu_manufacturer), "{processor}");
        assert!(processor.contains(provider.cpu_version), "{processor}");
        assert!(!processor.contains("Ryzen"), "{processor}");
    }
}

#[test]
fn a_machine_profile_has_its_own_chassis_and_the_hosts_cpu_name() {
    for machine in MACHINES {
        let mut profile = StealthProfile::realistic(machine.kind, &host_cpu_vendor());
        profile.use_machine(machine);
        let (_, tables) = launch(&profile);
        let (kind, maker, _) = chassis(&tables);
        assert_eq!(kind, profile.identity.chassis_type.max(1), "{}", machine.id);
        assert_ne!(kind, 1, "{}: chassis Other is QEMU's", machine.id);
        assert!(
            !maker.contains("QEMU") && !maker.is_empty(),
            "{}: {maker}",
            machine.id
        );
        assert_eq!(
            maker, profile.identity.system_manufacturer,
            "{}",
            machine.id
        );
        // The CPU is the host's, passed through whole; no brand override.
        let cpu = cpu_option(&profile, None, true, 4).unwrap();
        assert!(
            cpu.starts_with("host,") && !cpu.contains("model-id"),
            "{cpu}"
        );
        assert_eq!(profile.cloud_cpu_brand(), None);
        let (without_kvm, _) = (cpu_option(&profile, None, false, 4).unwrap(), ());
        let host = host_cpuinfo("model name").unwrap_or_default();
        assert!(host.is_empty() || without_kvm.contains(&host.replace(',', ",,")));
    }
}
