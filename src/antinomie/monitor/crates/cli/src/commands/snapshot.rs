// SPDX-License-Identifier: GPL-3.0-only
//! `snapshot list/create/restore/delete` (design 3.4.2): the checkpoints of a
//! VM. A snapshot is a point the VM can return to; a Disk snapshot keeps the
//! disk, a Full one also the memory of the running guest.
//!
//! In direct mode a running VM ends with the command, so `create --mode full`
//! boots the VM first, and `restore` shows the restored guest answering and
//! then stops it.
use super::machine::{
    checkpoint_value, confirm, find_checkpoint, find_vm, guest_value, live_checkpoints, wait_bases,
    wait_guest,
};
use crate::{
    context::Context,
    engine::{DirectEngine, wait_error},
    error::{CliError, ErrorCode},
    output::{Reply, table},
};
use antinomie_monitor_core::{Command, SnapshotRequest, VmSnapshotMode};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use std::time::Duration;

#[derive(Subcommand, Debug)]
pub enum Snapshot {
    /// List a VM's snapshots.
    List { vm: String },
    /// Take a snapshot of a VM.
    Create(Create),
    /// Return a VM to a snapshot, boot it and stop it again.
    Restore(Restore),
    /// Delete (hide) a snapshot; layers other snapshots need stay on disk.
    Delete {
        vm: String,
        /// The snapshot identity or name.
        id: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Mode {
    /// The disk of the stopped VM; restoring boots the guest afresh.
    Disk,
    /// Disk and memory of the running guest; restoring resumes it.
    Full,
}

#[derive(Args, Debug)]
pub struct Create {
    pub vm: String,
    /// The snapshot's name.
    pub name: String,
    #[arg(long, value_enum, default_value = "disk")]
    pub mode: Mode,
    #[arg(long, default_value = "")]
    pub description: String,
}

#[derive(Args, Debug)]
pub struct Restore {
    pub vm: String,
    /// The snapshot identity or name.
    pub id: String,
    /// Boot the guest from the snapshot's disk instead of resuming a Full
    /// snapshot's memory (a Disk snapshot always boots).
    #[arg(long)]
    pub cold_boot: bool,
    /// Confirm: the VM's current state is replaced.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(snapshot: &Snapshot, context: &Context) -> Result<Reply, CliError> {
    let mut engine = DirectEngine::start(context)?;
    let outcome = dispatch(snapshot, context, &mut engine);
    engine.finish();
    outcome
}

fn dispatch(
    command: &Snapshot,
    context: &Context,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let limit = context.timeout();
    wait_bases(engine, limit)?;
    match command {
        Snapshot::List { vm } => list(vm, limit, engine),
        Snapshot::Create(arguments) => create(arguments, limit, engine),
        Snapshot::Restore(arguments) => restore(arguments, limit, engine),
        Snapshot::Delete { vm, id, yes } => delete(vm, id, *yes, limit, engine),
    }
}

fn refresh(
    vm_id: &str,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<(), CliError> {
    engine
        .command(
            Command::RefreshVmSnapshots {
                vm_id: vm_id.to_owned(),
            },
            limit,
        )
        .map(|_| ())
}

fn list(vm: &str, limit: Option<Duration>, engine: &mut DirectEngine) -> Result<Reply, CliError> {
    let vm_id = find_vm(engine.snapshot(), vm)?.id.clone();
    refresh(&vm_id, limit, engine)?;
    let snapshot = engine.snapshot();
    let active = snapshot
        .vm_snapshot_trees
        .get(&vm_id)
        .and_then(|tree| tree.active_parent_id.clone());
    let nodes = live_checkpoints(snapshot, &vm_id);
    let items = nodes
        .iter()
        .map(|node| checkpoint_value(node, active.as_deref()))
        .collect();
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|node| {
            vec![
                node.id.clone(),
                node.name.clone(),
                match node.mode {
                    VmSnapshotMode::Disk => "disk".into(),
                    VmSnapshotMode::Full => "full".into(),
                },
                format!("{} MiB", node.disk_size / (1 << 20)),
                if active.as_deref() == Some(node.id.as_str()) {
                    "current".into()
                } else {
                    "-".into()
                },
            ]
        })
        .collect();
    let human = if rows.is_empty() {
        "no snapshots\n".to_owned()
    } else {
        table(&["ID", "NAME", "MODE", "DISK", ""], &rows)
    };
    Ok(Reply::list(items, None).with_human(human))
}

fn create(
    arguments: &Create,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let vm_id = find_vm(engine.snapshot(), &arguments.vm)?.id.clone();
    if arguments.name.trim().is_empty() {
        return Err(CliError::invalid("the snapshot needs a name").with_field("name"));
    }
    let mode = match arguments.mode {
        Mode::Disk => VmSnapshotMode::Disk,
        Mode::Full => VmSnapshotMode::Full,
    };
    refresh(&vm_id, limit, engine)?;
    if mode == VmSnapshotMode::Disk {
        check_capability(engine, &vm_id, mode)?;
    }
    let before: Vec<String> = live_checkpoints(engine.snapshot(), &vm_id)
        .iter()
        .map(|node| node.id.clone())
        .collect();
    let full = mode == VmSnapshotMode::Full;
    if full {
        // A Full snapshot is taken of the running guest, once it answers.
        engine.command(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            limit,
        )?;
        wait_guest(engine, &vm_id, limit)?;
        refresh(&vm_id, limit, engine)?;
        if let Err(error) = check_capability(engine, &vm_id, mode) {
            let _ = engine.waiter().stop_vm(&vm_id, limit);
            return Err(error);
        }
    }
    let request = SnapshotRequest {
        name: arguments.name.clone(),
        description: arguments.description.clone(),
        mode,
    };
    let taken = engine.command(
        Command::CreateVmSnapshot {
            vm_id: vm_id.clone(),
            request,
        },
        limit,
    );
    if full {
        // Stop the VM whether or not the snapshot worked.
        let stopped = engine.waiter().stop_vm(&vm_id, limit).map_err(wait_error);
        let message = taken?;
        stopped?;
        return finish_create(engine, &vm_id, &before, message, true, limit);
    }
    finish_create(engine, &vm_id, &before, taken?, false, limit)
}

/// The engine says why a snapshot of this kind cannot be taken now.
fn check_capability(
    engine: &DirectEngine,
    vm_id: &str,
    mode: VmSnapshotMode,
) -> Result<(), CliError> {
    let capabilities = engine
        .snapshot()
        .vm_snapshot_trees
        .get(vm_id)
        .map(|tree| tree.capabilities.clone())
        .unwrap_or_default();
    let can = match mode {
        VmSnapshotMode::Disk => capabilities.can_create_disk,
        VmSnapshotMode::Full => capabilities.can_create_full,
    };
    match capabilities.reason {
        Some(reason) if !can => Err(CliError::new(ErrorCode::PreconditionFailed, reason)),
        _ => Ok(()),
    }
}

fn finish_create(
    engine: &mut DirectEngine,
    vm_id: &str,
    before: &[String],
    message: String,
    stopped: bool,
    limit: Option<Duration>,
) -> Result<Reply, CliError> {
    // The engine's list is as old as its last refresh: read the new
    // checkpoint from a current one (it printed `"snapshot": null`).
    let _ = refresh(vm_id, limit, engine);
    let active = engine
        .snapshot()
        .vm_snapshot_trees
        .get(vm_id)
        .and_then(|tree| tree.active_parent_id.clone());
    let created = live_checkpoints(engine.snapshot(), vm_id)
        .into_iter()
        .find(|node| !before.contains(&node.id))
        .map(|node| checkpoint_value(node, active.as_deref()));
    let human = match &created {
        Some(node) => format!(
            "{message}: {} ({}){}\n",
            node["name"].as_str().unwrap_or(""),
            node["id"].as_str().unwrap_or(""),
            if stopped {
                "; the VM was stopped again"
            } else {
                ""
            }
        ),
        None => format!("{message}\n"),
    };
    Ok(Reply::value(json!({"message": message, "snapshot": created})).with_human(human))
}

fn restore(
    arguments: &Restore,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let vm_id = find_vm(engine.snapshot(), &arguments.vm)?.id.clone();
    refresh(&vm_id, limit, engine)?;
    let (id, name, mode) = {
        let node = find_checkpoint(engine.snapshot(), &vm_id, &arguments.id)?;
        (node.id.clone(), node.name.clone(), node.mode)
    };
    confirm(
        arguments.yes,
        &format!("restoring {name:?} replaces the current state of the VM"),
    )?;
    let began = std::time::Instant::now();
    let message = engine.command(
        Command::RestoreVmSnapshot {
            vm_id: vm_id.clone(),
            snapshot_id: id.clone(),
            boot_from_disk: arguments.cold_boot,
            save_current: None,
            confirmed: true,
            switch_profile: false,
        },
        limit,
    )?;
    // The restore starts the VM (a Disk restore boots it, a Full one resumes it).
    wait_guest(engine, &vm_id, limit)?;
    let restored_s = began.elapsed().as_secs_f64();
    let guest = guest_value(engine.snapshot());
    engine.waiter().stop_vm(&vm_id, limit).map_err(wait_error)?;
    let resumed = mode == VmSnapshotMode::Full && !arguments.cold_boot;
    Ok(Reply::value(json!({
        "vm": vm_id,
        "snapshot": id,
        "message": message,
        "resumed": resumed,
        "guest_kernel": guest,
        "restored_s": (restored_s * 10.0).round() / 10.0,
        "stopped_on_exit": true,
    }))
    .with_human(format!(
        "{message}\nthe guest answered {restored_s:.1} s after the restore; the VM was stopped again\n"
    )))
}

fn delete(
    vm: &str,
    id: &str,
    yes: bool,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let vm_id = find_vm(engine.snapshot(), vm)?.id.clone();
    refresh(&vm_id, limit, engine)?;
    let (id, name) = {
        let node = find_checkpoint(engine.snapshot(), &vm_id, id)?;
        (node.id.clone(), node.name.clone())
    };
    confirm(
        yes,
        &format!("deleting the snapshot {name:?} cannot be undone"),
    )?;
    let message = engine.command(
        Command::DeleteVmSnapshot {
            vm_id,
            snapshot_id: id.clone(),
            confirmed: true,
        },
        limit,
    )?;
    Ok(Reply::value(json!({"deleted": id, "message": message})).with_human(format!("{message}\n")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: Snapshot,
    }

    #[test]
    fn the_grammar_takes_the_documented_flags() {
        let create = Wrapper::try_parse_from([
            "x",
            "create",
            "vm1",
            "clean",
            "--mode",
            "full",
            "--description",
            "d",
        ])
        .unwrap();
        assert!(matches!(
            create.command,
            Snapshot::Create(Create {
                mode: Mode::Full,
                ..
            })
        ));
        let restore =
            Wrapper::try_parse_from(["x", "restore", "vm1", "s1", "--cold-boot", "--yes"]).unwrap();
        assert!(matches!(
            restore.command,
            Snapshot::Restore(Restore {
                cold_boot: true,
                yes: true,
                ..
            })
        ));
        assert!(Wrapper::try_parse_from(["x", "create", "vm1", "n", "--mode", "x"]).is_err());
    }
}
