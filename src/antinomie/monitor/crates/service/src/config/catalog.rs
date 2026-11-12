// SPDX-License-Identifier: GPL-3.0-only
//! What `config validate` needs to know about the lane VM: whether it exists,
//! how its network card is wired, and which snapshots it has (design 4.4).

use antinomie_monitor_core::api::{VmConfig, VmNetwork};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmNet {
    Disconnected,
    Isolated,
    Routed,
    Nat,
}

impl VmNet {
    /// The spelling `vm.network` of a policy uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Isolated => "isolated",
            Self::Routed => "routed",
            Self::Nat => "nat",
        }
    }
}

/// What a policy is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmFacts {
    pub id: String,
    pub name: String,
    pub network: VmNet,
    pub ram_mib: u32,
    pub base_identity: Option<String>,
    /// The device profile as the engine spells it, when it is a plain name.
    pub stealth: Option<String>,
    pub snapshots: Vec<String>,
    /// The snapshots of `snapshots` that hold the disk only (no memory): a
    /// `snapshot_full` revert to one of them boots the guest cold.
    pub disk_snapshots: Vec<String>,
}

/// The VMs of a data directory, read without starting the engine.
pub trait VmCatalog {
    /// A VM by name or id.
    fn find(&self, name: &str) -> Option<VmFacts>;
}

/// A catalogue that knows no VM: the checks that need one are skipped (a
/// machine without a data directory still validates the files themselves).
pub struct NoVms;

impl VmCatalog for NoVms {
    fn find(&self, _: &str) -> Option<VmFacts> {
        None
    }
}

/// The VMs on disk: `<data>/<dir>/config.json` and `<data>/vms/<dir>/config.json`
/// (a VM with its disk elsewhere is not found; `lane_vm` must be one the data
/// directory holds).
pub struct DiskVms {
    dirs: Vec<PathBuf>,
}

impl DiskVms {
    pub fn open(data_dir: &Path) -> Self {
        let mut dirs = Vec::new();
        for root in [data_dir.to_path_buf(), data_dir.join("vms")] {
            if let Ok(entries) = std::fs::read_dir(&root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.join("config.json").is_file() {
                        dirs.push(path);
                    }
                }
            }
        }
        dirs.sort();
        Self { dirs }
    }

    /// Whether the directory holds a VM catalogue the checks can use.
    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty()
    }
}

/// The names of the VM's snapshots, and of those that hold the disk only.
fn snapshot_names(dir: &Path) -> (Vec<String>, Vec<String>) {
    let Ok(text) = std::fs::read_to_string(dir.join("snapshots.json")) else {
        return (Vec::new(), Vec::new());
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (Vec::new(), Vec::new());
    };
    let mut names = Vec::new();
    let mut disk = Vec::new();
    for node in value["nodes"].as_array().into_iter().flatten() {
        let checkpoint = &node["checkpoint"];
        let Some(name) = checkpoint["name"].as_str() else {
            continue;
        };
        names.push(name.to_owned());
        if checkpoint["mode"]
            .as_str()
            .is_some_and(|mode| mode.eq_ignore_ascii_case("disk"))
        {
            disk.push(name.to_owned());
        }
    }
    (names, disk)
}

impl VmCatalog for DiskVms {
    fn find(&self, name: &str) -> Option<VmFacts> {
        for dir in &self.dirs {
            let Ok(text) = std::fs::read_to_string(dir.join("config.json")) else {
                continue;
            };
            let Ok(vm) = serde_json::from_str::<VmConfig>(&text) else {
                continue;
            };
            if vm.name != name && vm.id != name {
                continue;
            }
            let stealth = serde_json::to_value(&vm.stealth)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned));
            let (snapshots, disk_snapshots) = snapshot_names(dir);
            return Some(VmFacts {
                id: vm.id.clone(),
                name: vm.name.clone(),
                network: match vm.network() {
                    VmNetwork::Disconnected => VmNet::Disconnected,
                    VmNetwork::Isolated => VmNet::Isolated,
                    VmNetwork::Routed => VmNet::Routed,
                    VmNetwork::Nat => VmNet::Nat,
                },
                ram_mib: vm.ram_mib,
                base_identity: vm.base_identity.clone(),
                stealth,
                snapshots,
                disk_snapshots,
            });
        }
        None
    }
}
