// SPDX-License-Identifier: GPL-3.0-only
//! What the `base`, `vm` and `snapshot` commands share: the objects they print,
//! how a person names a VM, base or snapshot, the confirmation rule for
//! destructive commands, and the waits for a booted guest.
use crate::{
    engine::DirectEngine,
    error::{CliError, ErrorCode},
};
use antinomie_monitor_core::{
    BaseSummary, Command, Snapshot, VmCheckpoint, VmConfig, VmNetwork, VmSnapshotConsistency,
    VmSnapshotMode, VmState, stealth::StealthPreset,
};
use serde_json::{Value, json};
use std::time::Duration;

/// How long a guest may take to boot and answer when `--timeout` is not given
/// (design 4.1, `boot_s`, with room for software emulation).
pub const BOOT_WAIT: Duration = Duration::from_secs(600);

/// How long the installed bases may take to be listed after the engine starts.
pub const BASES_WAIT: Duration = Duration::from_secs(300);

/// A destructive command refuses without `--yes`.
pub fn confirm(yes: bool, what: &str) -> Result<(), CliError> {
    if yes {
        Ok(())
    } else {
        Err(CliError::invalid(format!("{what}; pass --yes to confirm")).with_field("yes"))
    }
}

pub fn network_name(network: VmNetwork) -> &'static str {
    match network {
        VmNetwork::Disconnected => "disconnected",
        VmNetwork::Isolated => "isolated",
        VmNetwork::Routed => "routed",
        VmNetwork::Nat => "nat",
    }
}

pub fn parse_network(name: &str) -> Result<VmNetwork, CliError> {
    match name {
        "disconnected" => Ok(VmNetwork::Disconnected),
        "isolated" => Ok(VmNetwork::Isolated),
        "routed" => Ok(VmNetwork::Routed),
        "nat" => Ok(VmNetwork::Nat),
        other => Err(CliError::invalid(format!(
            "unknown network {other:?}; use disconnected, isolated, routed or nat"
        ))
        .with_field("network")),
    }
}

pub fn preset_name(preset: StealthPreset) -> &'static str {
    match preset {
        StealthPreset::RealisticDesktop => "realistic-desktop",
        StealthPreset::RealisticLaptop => "realistic-laptop",
        StealthPreset::RealisticServer => "realistic-server",
        StealthPreset::CloudVps => "cloud-vps",
        StealthPreset::Transparent => "transparent",
        StealthPreset::Custom => "custom",
    }
}

/// The presets `vm create --stealth` takes. `cloud-vps` needs a provider
/// choice and `custom` a hand-made profile; both are made in the app.
pub fn parse_preset(name: &str) -> Result<StealthPreset, CliError> {
    match name.trim_start_matches("realistic-") {
        "desktop" => Ok(StealthPreset::RealisticDesktop),
        "laptop" => Ok(StealthPreset::RealisticLaptop),
        "server" => Ok(StealthPreset::RealisticServer),
        "transparent" => Ok(StealthPreset::Transparent),
        other => Err(CliError::invalid(format!(
            "unknown stealth preset {other:?}; use realistic-desktop, realistic-laptop, \
             realistic-server or transparent (cloud-vps and custom profiles are made in the app)"
        ))
        .with_field("stealth")),
    }
}

pub fn state_name(state: &VmState) -> &'static str {
    match state {
        VmState::Stopped => "stopped",
        VmState::Starting => "starting",
        VmState::Running => "running",
        VmState::Stopping => "stopping",
        VmState::Failed => "failed",
    }
}

/// The state of VM `id`: the engine runs one VM at a time, so any other is stopped.
pub fn vm_state(snapshot: &Snapshot, id: &str) -> &'static str {
    if snapshot.active_vm.as_deref() == Some(id) {
        state_name(&snapshot.state)
    } else {
        "stopped"
    }
}

pub fn live_checkpoints<'a>(snapshot: &'a Snapshot, vm_id: &str) -> Vec<&'a VmCheckpoint> {
    snapshot
        .vm_snapshot_trees
        .get(vm_id)
        .map(|tree| tree.nodes.iter().filter(|node| !node.deleted).collect())
        .unwrap_or_default()
}

/// A VM as a result object.
pub fn vm_value(vm: &VmConfig, snapshot: &Snapshot) -> Value {
    json!({
        "id": vm.id,
        "name": vm.name,
        "base": vm.base_identity,
        "cpus": vm.cpus,
        "ram_mib": vm.ram_mib,
        "disk_gib": vm.disk_gib,
        "network": network_name(vm.network()),
        "stealth": preset_name(vm.stealth.preset),
        "state": vm_state(snapshot, &vm.id),
        "snapshots": live_checkpoints(snapshot, &vm.id).len(),
    })
}

pub fn base_value(base: &BaseSummary) -> Value {
    json!({
        "id": base.id,
        "label": base.label,
        "arch": base.arch.label(),
        "size_bytes": base.size_bytes,
        "min_ram_mib": base.min_ram_mib,
        "min_disk_gib": base.min_disk_gib,
        "revision": base.revision,
        "min_app_version": base.min_app_version,
        "built_with": base.built_with,
        "guest": base.guest.as_ref().map(|guest| json!({
            "id": guest.id,
            "label": guest.label,
            "requires_credentials": guest.requires_credentials,
            "graphical": guest.graphical,
        })),
        "directory": base.directory,
    })
}

pub fn checkpoint_value(node: &VmCheckpoint, active: Option<&str>) -> Value {
    json!({
        "id": node.id,
        "parent_id": node.parent_id,
        "name": node.name,
        "description": node.description,
        "created_ms": node.created_unix_ms,
        "mode": match node.mode {
            VmSnapshotMode::Disk => "disk",
            VmSnapshotMode::Full => "full",
        },
        "consistency": match node.consistency {
            VmSnapshotConsistency::Stopped => "stopped",
            VmSnapshotConsistency::CrashConsistent => "crash_consistent",
            VmSnapshotConsistency::Paused => "paused",
        },
        "disk_size": node.disk_size,
        "memory_size": node.memory_size,
        "compatible": node.compatible,
        "compatibility_note": node.compatibility_note,
        "active": active == Some(node.id.as_str()),
    })
}

/// The one item of `candidates` that `key` names: exactly, or as the start of
/// exactly one. `kind` words the refusal.
fn pick<'a, T>(
    kind: &str,
    key: &str,
    candidates: &'a [T],
    names: impl Fn(&T) -> Vec<&str>,
    minimum_prefix: usize,
) -> Result<&'a T, CliError> {
    if let Some(exact) = candidates
        .iter()
        .find(|candidate| names(candidate).contains(&key))
    {
        return Ok(exact);
    }
    let matches: Vec<&T> = if key.len() >= minimum_prefix {
        candidates
            .iter()
            .filter(|candidate| names(candidate).iter().any(|name| name.starts_with(key)))
            .collect()
    } else {
        Vec::new()
    };
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(CliError::not_found(format!("no {kind} {key:?}")).with_field(kind.to_owned())),
        _ => Err(CliError::new(
            ErrorCode::InvalidArgument,
            format!("{key:?} names more than one {kind}; give more of it"),
        )
        .with_field(kind.to_owned())),
    }
}

/// A VM by identity or by name (a unique start of either).
pub fn find_vm<'a>(snapshot: &'a Snapshot, key: &str) -> Result<&'a VmConfig, CliError> {
    if let Some(vm) = snapshot.vms.iter().find(|vm| vm.id == key) {
        return Ok(vm);
    }
    pick(
        "vm",
        key,
        &snapshot.vms,
        |vm| vec![vm.id.as_str(), vm.name.as_str()],
        1,
    )
}

/// A base by identity (the start of one, from 4 characters) or by label.
pub fn find_base<'a>(snapshot: &'a Snapshot, key: &str) -> Result<&'a BaseSummary, CliError> {
    pick(
        "base",
        key,
        &snapshot.bases,
        |base| vec![base.id.as_str(), base.label.as_str()],
        4,
    )
}

/// A snapshot of a VM by identity or name.
pub fn find_checkpoint<'a>(
    snapshot: &'a Snapshot,
    vm_id: &str,
    key: &str,
) -> Result<&'a VmCheckpoint, CliError> {
    let nodes = live_checkpoints(snapshot, vm_id);
    pick(
        "snapshot",
        key,
        &nodes,
        |node| vec![node.id.as_str(), node.name.as_str()],
        1,
    )
    .copied()
}

/// Wait for the installed bases to be listed.
pub fn wait_bases(engine: &mut DirectEngine, limit: Option<Duration>) -> Result<(), CliError> {
    engine.wait_until(
        "the installed bases to be listed",
        Some(limit.unwrap_or(BASES_WAIT)),
        |snapshot| !snapshot.bases_checking,
    )
}

/// Wait until VM `vm_id` runs and its guest has answered.
pub fn wait_guest(
    engine: &mut DirectEngine,
    vm_id: &str,
    limit: Option<Duration>,
) -> Result<(), CliError> {
    let vm = vm_id.to_owned();
    engine.wait_until(
        "the guest to answer",
        Some(limit.unwrap_or(BOOT_WAIT)),
        move |snapshot| {
            snapshot.active_vm.as_deref() == Some(vm.as_str())
                && snapshot.state == VmState::Running
                && snapshot.guest_kernel.is_some()
        },
    )
}

/// Wait until the running guest `vm_id` has finished booting (`AwaitBoot`):
/// its own root file system is mounted, so the initramfs no longer grows it
/// to the VM's disk, and a systemd guest has finished start-up. The guest
/// answers long before; a VM stopped or saved then keeps a half-grown file
/// system that crashes the guest kernel at the next boot (ANT-T0476). The
/// engine bounds the wait (`start.boot_wait_secs`, stretched under TCG).
pub fn await_boot(engine: &mut DirectEngine, vm_id: &str) -> Result<String, CliError> {
    engine.command(
        Command::AwaitBoot {
            vm_id: vm_id.to_owned(),
        },
        None,
    )
}

/// The running guest's kernel as a result member.
pub fn guest_value(snapshot: &Snapshot) -> Value {
    match &snapshot.guest_kernel {
        Some(kernel) => json!({
            "revision": kernel.revision,
            "release": kernel.release,
            "arch": kernel.arch,
        }),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(id: &str, name: &str) -> VmConfig {
        VmConfig {
            id: id.into(),
            name: name.into(),
            ..VmConfig::default()
        }
    }

    #[test]
    fn a_vm_is_found_by_identity_name_or_a_unique_start() {
        let snapshot = Snapshot {
            vms: vec![vm("lane_ab12", "Lane"), vm("lab_cd34", "Lab")],
            ..Snapshot::default()
        };
        assert_eq!(find_vm(&snapshot, "lane_ab12").unwrap().name, "Lane");
        assert_eq!(find_vm(&snapshot, "Lab").unwrap().id, "lab_cd34");
        assert_eq!(find_vm(&snapshot, "lane").unwrap().id, "lane_ab12");
        let both = find_vm(&snapshot, "la").unwrap_err();
        assert_eq!(both.exit.code(), 4);
        let none = find_vm(&snapshot, "zzz").unwrap_err();
        assert_eq!(none.exit.code(), 3);
    }

    #[test]
    fn a_short_base_prefix_is_not_enough() {
        let base = |id: &str| BaseSummary {
            id: id.into(),
            label: format!("label-{id}"),
            directory: Default::default(),
            guest: None,
            min_ram_mib: 0,
            min_disk_gib: 0,
            fixed_display: false,
            arch: Default::default(),
            size_bytes: 0,
            revision: None,
            min_app_version: None,
            built_with: None,
            stealth_support: vec![],
        };
        let snapshot = Snapshot {
            bases: vec![base("abcdef1234"), base("abxyz98765")],
            ..Snapshot::default()
        };
        assert_eq!(find_base(&snapshot, "abcd").unwrap().id, "abcdef1234");
        assert_eq!(find_base(&snapshot, "abc").unwrap_err().exit.code(), 3);
        assert_eq!(find_base(&snapshot, "ab").unwrap_err().exit.code(), 3);
        assert_eq!(
            find_base(&snapshot, "label-abxyz98765").unwrap().id,
            "abxyz98765"
        );
    }

    #[test]
    fn destructive_commands_refuse_without_yes_and_say_so() {
        let error = confirm(false, "deleting VM x destroys its disk").unwrap_err();
        assert_eq!(error.exit.code(), 4);
        assert_eq!(error.field.as_deref(), Some("yes"));
        assert!(error.message.contains("--yes"));
        assert!(confirm(true, "x").is_ok());
    }

    #[test]
    fn network_and_preset_names_round_trip() {
        for name in ["disconnected", "isolated", "routed", "nat"] {
            assert_eq!(network_name(parse_network(name).unwrap()), name);
        }
        assert!(parse_network("wifi").is_err());
        for name in [
            "realistic-desktop",
            "realistic-laptop",
            "realistic-server",
            "transparent",
        ] {
            assert_eq!(preset_name(parse_preset(name).unwrap()), name);
        }
        assert_eq!(
            parse_preset("desktop").unwrap(),
            StealthPreset::RealisticDesktop
        );
        assert!(parse_preset("cloud-vps").is_err());
    }

    #[test]
    fn only_the_active_vm_has_a_state() {
        let mut snapshot = Snapshot {
            active_vm: Some("a".into()),
            state: VmState::Running,
            ..Snapshot::default()
        };
        assert_eq!(vm_state(&snapshot, "a"), "running");
        assert_eq!(vm_state(&snapshot, "b"), "stopped");
        snapshot.active_vm = None;
        assert_eq!(vm_state(&snapshot, "a"), "stopped");
    }
}
