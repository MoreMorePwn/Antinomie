// SPDX-License-Identifier: GPL-3.0-only
//! The environment a run started in, saved with the run so a result can be
//! read against it: the VM and its hardware, the base image and kernel, the
//! rule packs and tools installed, and the app. A run saved before this
//! existed has none, and the Runs tab says so.
use crate::api::{GuestArch, GuestKernel, VmConfig, VmNetwork};
use serde::{Deserialize, Serialize};

/// What was in place when the run was launched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunEnvironment {
    pub vm_name: String,
    pub cpus: u16,
    pub ram_mib: u32,
    pub disk_gib: u32,
    /// How the VM's network card is connected ("Routed", "NAT", "Isolated").
    pub network: String,
    pub stealth: String,
    /// The router of the guest's own network, when the VM's profile gives it
    /// one (the default 10.0.2.2 is not written): the address the base's DHCP
    /// client talks to. Written only when set, so older records keep their hash.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub guest_gateway: String,
    /// The accelerator the boot actually used (`kvm`, `tcg`, or `tcg (KVM
    /// unavailable)`). Written only when known, so a run record made before
    /// this (and its hash) is what it was.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub accelerator: String,
    /// The base image's display name and identity (a SHA-256).
    pub base_name: String,
    pub base_identity: String,
    pub base_revision: Option<u32>,
    pub kernel_release: String,
    pub kernel_revision: Option<u32>,
    /// The guest's architecture. Written only when it is not x86-64, so an
    /// x86-64 run's record (and its hash) is what it always was.
    #[serde(skip_serializing_if = "GuestArch::is_x86_64")]
    pub arch: GuestArch,
    /// SHA-256 of the patch series the kernel was built from.
    pub patch_series: String,
    /// Installed rule packs, "name version", enabled ones only.
    pub rule_packs: Vec<String>,
    /// Analysis tools that were available, "name version".
    pub tools: Vec<String>,
    pub app_version: String,
    /// SHA-256 over every field above, so two runs started in the same
    /// environment can be told apart from two that were not.
    pub hash: String,
}

/// What the caller reads from the session; the module reads the rule packs
/// and tools itself.
pub struct Inputs<'a> {
    pub vm: &'a VmConfig,
    pub base_name: Option<&'a str>,
    pub base_identity: Option<&'a str>,
    pub base_revision: Option<u32>,
    pub kernel: Option<&'a GuestKernel>,
    /// The boot's accelerator record, when the session knows it.
    pub accelerator: Option<&'a str>,
    pub data_dir: &'a std::path::Path,
}

impl RunEnvironment {
    pub fn capture(inputs: &Inputs<'_>) -> Self {
        let vm = inputs.vm;
        let mut rule_packs: Vec<String> = crate::ruleset::load_registry(inputs.data_dir)
            .map(|registry| {
                registry
                    .packs
                    .iter()
                    .filter(|pack| pack.enabled)
                    .map(|pack| format!("{} {}", pack.name, pack.version))
                    .collect()
            })
            .unwrap_or_default();
        rule_packs.sort();
        let mut tools: Vec<String> = crate::analysis_tools::statuses(inputs.data_dir)
            .into_iter()
            .filter_map(|tool| {
                let version = tool.installed.as_deref().or(tool.system.as_deref())?;
                // A system tool is a path, not a version.
                let version = if tool.installed.is_some() {
                    version
                } else {
                    "system"
                };
                Some(format!("{} {version}", tool.name))
            })
            .collect();
        tools.sort();
        let mut environment = Self {
            vm_name: vm.name.clone(),
            cpus: vm.cpus,
            ram_mib: vm.ram_mib,
            disk_gib: vm.disk_gib,
            network: match vm.network() {
                VmNetwork::Disconnected => "Disconnected",
                VmNetwork::Isolated => "Isolated",
                VmNetwork::Routed => "Routed",
                VmNetwork::Nat => "NAT",
            }
            .into(),
            stealth: vm.stealth.preset.label().into(),
            guest_gateway: if vm.stealth.nat.network.is_empty() {
                String::new()
            } else {
                vm.stealth.nat.gateway.clone()
            },
            accelerator: inputs.accelerator.unwrap_or_default().into(),
            base_name: inputs
                .base_name
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                // A base without a display name is still named by its identity.
                .or_else(|| {
                    inputs
                        .base_identity
                        .filter(|identity| !identity.is_empty())
                        .map(|identity| identity.chars().take(8).collect())
                })
                .unwrap_or_default(),
            base_identity: inputs.base_identity.unwrap_or_default().into(),
            base_revision: inputs.base_revision,
            kernel_release: inputs
                .kernel
                .and_then(|kernel| kernel.release.clone())
                .unwrap_or_default(),
            kernel_revision: inputs.kernel.and_then(|kernel| kernel.revision),
            arch: inputs.kernel.map(|kernel| kernel.arch).unwrap_or_default(),
            patch_series: inputs
                .kernel
                .and_then(|kernel| kernel.source.clone())
                .unwrap_or_default(),
            rule_packs,
            tools,
            app_version: crate::api::APP_VERSION.into(),
            hash: String::new(),
        };
        environment.hash = environment.compute_hash();
        environment
    }

    /// The hash of every field but `hash`.
    pub fn compute_hash(&self) -> String {
        let mut copy = self.clone();
        copy.hash.clear();
        let bytes = serde_json::to_vec(&copy).unwrap_or_default();
        crate::storage::sha256_hex(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(vm: &'a VmConfig, dir: &'a std::path::Path) -> Inputs<'a> {
        Inputs {
            vm,
            base_name: Some("debian-xfce"),
            base_identity: Some("ab"),
            base_revision: Some(18),
            kernel: None,
            accelerator: None,
            data_dir: dir,
        }
    }

    fn vm() -> VmConfig {
        serde_json::from_str(
            r#"{"id":"a","name":"lab","cpus":2,"ram_mib":2048,"disk_gib":20,"nat":true}"#,
        )
        .unwrap()
    }

    #[test]
    fn the_hash_follows_every_field_and_ignores_itself() {
        let dir = std::env::temp_dir().join(format!("ant-env-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vm = vm();
        let mut first = RunEnvironment::capture(&inputs(&vm, &dir));
        assert_eq!(first.hash, first.compute_hash());
        assert_eq!(first.network, "NAT");
        let same = RunEnvironment::capture(&inputs(&vm, &dir));
        assert_eq!(first.hash, same.hash);
        first.cpus = 4;
        assert_ne!(first.hash, first.compute_hash());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_guest_network_gateway_is_recorded_only_when_the_profile_sets_one() {
        let dir = std::env::temp_dir().join(format!("ant-env-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut vm = vm();
        let plain = RunEnvironment::capture(&inputs(&vm, &dir));
        assert_eq!(plain.guest_gateway, "");
        // An unset gateway leaves the record, and so its hash, as it was.
        assert!(
            !serde_json::to_string(&plain)
                .unwrap()
                .contains("guest_gateway")
        );
        vm.stealth.nat = crate::stealth::NatNetwork::home();
        let home = RunEnvironment::capture(&inputs(&vm, &dir));
        assert_eq!(home.guest_gateway, "192.168.1.1");
        assert_ne!(home.hash, plain.hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_base_without_a_name_is_named_by_its_short_identity() {
        let dir = std::env::temp_dir().join(format!("ant-env-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vm = vm();
        let mut given = inputs(&vm, &dir);
        given.base_name = None;
        given.base_identity = Some("12a308586cb1ffeedbeef");
        assert_eq!(RunEnvironment::capture(&given).base_name, "12a30858");
        given.base_name = Some(" ");
        assert_eq!(RunEnvironment::capture(&given).base_name, "12a30858");
        given.base_name = Some("Debian 13 (Minimal)");
        assert_eq!(
            RunEnvironment::capture(&given).base_name,
            "Debian 13 (Minimal)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_older_run_summary_without_the_field_reads_as_none() {
        let environment: RunEnvironment = serde_json::from_str("{}").unwrap();
        assert!(environment.hash.is_empty());
        assert!(environment.vm_name.is_empty());
        assert_eq!(environment.arch, GuestArch::X86_64);
    }

    #[test]
    fn only_a_foreign_architecture_is_written() {
        let mut environment = RunEnvironment::default();
        let x86 = serde_json::to_value(&environment).unwrap();
        assert!(x86.get("arch").is_none());
        environment.arch = GuestArch::AARCH64;
        let arm64 = serde_json::to_value(&environment).unwrap();
        assert_eq!(arm64["arch"]["machine"], 183);
        let read: RunEnvironment = serde_json::from_value(arm64).unwrap();
        assert_eq!(read.arch, GuestArch::AARCH64);
        assert_ne!(
            environment.compute_hash(),
            RunEnvironment::default().compute_hash()
        );
    }

    #[test]
    fn the_accelerator_is_recorded_only_when_known_and_changes_the_hash() {
        let dir = std::env::temp_dir().join(format!("ant-env-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let vm = vm();
        let plain = RunEnvironment::capture(&inputs(&vm, &dir));
        assert!(
            serde_json::to_value(&plain)
                .unwrap()
                .get("accelerator")
                .is_none()
        );
        let mut with = inputs(&vm, &dir);
        with.accelerator = Some("tcg (KVM unavailable)");
        let tcg = RunEnvironment::capture(&with);
        assert_eq!(
            serde_json::to_value(&tcg).unwrap()["accelerator"],
            "tcg (KVM unavailable)"
        );
        assert_ne!(plain.hash, tcg.hash);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
