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
            base_name: inputs.base_name.unwrap_or_default().into(),
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
}
