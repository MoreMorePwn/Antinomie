// SPDX-License-Identifier: GPL-3.0-only
//! `vm list/create/start/stop/status/reset/duplicate/delete` (design 3.4.2).
//!
//! In direct mode the VM lives in this process: the engine stops it when the
//! command ends. `vm start` therefore boots the guest, proves it answers and
//! stops it again, unless `--hold` keeps it up; leaving a VM running between
//! commands is what the daemon is for.
use super::{
    auto::link,
    machine::{
        BOOT_WAIT, confirm, find_base, find_vm, guest_value, network_name, parse_network,
        parse_preset, preset_name, vm_state, vm_value, wait_bases, wait_guest,
    },
};
use crate::{
    context::Context,
    engine::DirectEngine,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use antinomie_monitor_core::{
    Command, GuestCredentials, Snapshot, VmConfig, VmNetwork,
    stealth::{StealthPreset, StealthProfile, host_cpu_vendor},
};
use clap::{Args, Subcommand};
use serde_json::json;
use std::{io::BufRead, time::Duration};

#[derive(Subcommand, Debug)]
pub enum Vm {
    /// List the VMs.
    List,
    /// Create a VM from an installed base.
    Create(Create),
    /// Boot a VM, wait for the guest to answer, and stop it again (or hold it).
    /// Under TCG the start waits are stretched by `--tcg-multiplier`.
    Start(Start),
    /// Stop the VM and wait until its recording is final.
    Stop { id: String },
    /// Show a VM: state, boot, guest kernel, snapshots, pending disk layer.
    Status { id: String },
    /// Reset a VM's disk to its base; refused when the VM has snapshots.
    Reset {
        id: String,
        /// Confirm: the disk is replaced.
        #[arg(long)]
        yes: bool,
    },
    /// Copy a VM with an independent disk and no history.
    Duplicate { id: String, name: String },
    /// Delete a VM's disk and configuration (recordings stay).
    Delete {
        id: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
pub struct Create {
    /// The VM's name.
    pub name: String,
    /// The base (identity, start of it, or label); optional when exactly one is installed.
    #[arg(long, value_name = "ID")]
    pub base: Option<String>,
    /// Virtual CPUs.
    #[arg(long, default_value_t = 4)]
    pub cpus: u16,
    /// Guest RAM in MiB.
    #[arg(long, default_value_t = 2048, value_name = "N")]
    pub ram_mib: u32,
    /// Disk size in GiB.
    #[arg(long, default_value_t = 8, value_name = "N")]
    pub disk_gib: u32,
    /// disconnected, isolated, routed or nat. Only a routed VM lets each run
    /// choose its route.
    #[arg(long, default_value = "disconnected", value_name = "NETWORK")]
    pub network: String,
    /// What the guest sees of the machine: realistic-desktop, realistic-laptop,
    /// realistic-server or transparent.
    #[arg(long, default_value = "realistic-desktop", value_name = "PRESET")]
    pub stealth: String,
    /// Guest account name (bases that need an account).
    #[arg(long, default_value = "analyst", value_name = "NAME")]
    pub user: String,
    /// Read the guest account password from standard input (one line). It is
    /// never taken from the command line.
    #[arg(long)]
    pub password_stdin: bool,
}

#[derive(Args, Debug)]
pub struct Start {
    pub id: String,
    /// Wait for the guest to answer. Always on in direct mode.
    #[arg(long)]
    pub wait: bool,
    /// Keep the VM running this many seconds before stopping it; without a
    /// number, until interrupted (exit 130).
    #[arg(long, num_args = 0..=1, default_missing_value = "0", value_name = "SECONDS")]
    pub hold: Option<u64>,
}

pub fn run(vm: &Vm, context: &Context) -> Result<Reply, CliError> {
    // A daemon owns the engine: it lists its VMs (`vm.list`) and the command
    // takes no lock. The other commands need the lock for themselves.
    if matches!(vm, Vm::List)
        && let Some(mut client) = link::daemon(context)?
    {
        return list_through(&mut client);
    }
    // The password is read before the engine starts, so a missing one fails fast.
    let password = match vm {
        Vm::Create(arguments) if arguments.password_stdin => Some(read_password()?),
        _ => None,
    };
    let mut engine = DirectEngine::start(context)?;
    let outcome = dispatch(vm, context, &mut engine, password);
    engine.finish();
    outcome
}

fn dispatch(
    vm: &Vm,
    context: &Context,
    engine: &mut DirectEngine,
    password: Option<String>,
) -> Result<Reply, CliError> {
    let limit = context.timeout();
    wait_bases(engine, limit)?;
    match vm {
        Vm::List => Ok(list(engine.snapshot())),
        Vm::Create(arguments) => create(arguments, password, limit, engine),
        Vm::Start(arguments) => start(arguments, limit, engine),
        Vm::Stop { id } => stop(id, limit, engine),
        Vm::Status { id } => status(id, engine.snapshot()),
        Vm::Reset { id, yes } => reset(id, *yes, limit, engine),
        Vm::Duplicate { id, name } => duplicate(id, name, limit, engine),
        Vm::Delete { id, yes } => delete(id, *yes, limit, engine),
    }
}

/// One line from standard input, without its line ending.
pub(crate) fn read_password() -> Result<String, CliError> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| CliError::internal(format!("reading the password: {error}")))?;
    let password = line.trim_end_matches(['\n', '\r']).to_owned();
    if password.is_empty() {
        return Err(CliError::invalid("no password on standard input").with_field("password-stdin"));
    }
    Ok(password)
}

fn list(snapshot: &Snapshot) -> Reply {
    let items = snapshot
        .vms
        .iter()
        .map(|vm| vm_value(vm, snapshot))
        .collect();
    let rows: Vec<Vec<String>> = snapshot
        .vms
        .iter()
        .map(|vm| {
            vec![
                vm.id.clone(),
                vm.name.clone(),
                vm.base_identity
                    .as_deref()
                    .map_or("-".into(), |base| base.chars().take(12).collect()),
                vm.cpus.to_string(),
                format!("{} MiB", vm.ram_mib),
                format!("{} GiB", vm.disk_gib),
                network_name(vm.network()).to_owned(),
                vm_state(snapshot, &vm.id).to_owned(),
            ]
        })
        .collect();
    let human = if rows.is_empty() {
        "no VMs\n".to_owned()
    } else {
        table(
            &[
                "ID", "NAME", "BASE", "CPUS", "RAM", "DISK", "NETWORK", "STATE",
            ],
            &rows,
        )
    };
    Reply::list(items, None).with_human(human)
}

/// `vm list` from the daemon: the contract's `VmSummary` objects.
fn list_through(client: &mut antinomie_service::server::client::Client) -> Result<Reply, CliError> {
    let reply = link::call(client, "vm.list", json!({}))?;
    let items = reply["vms"].as_array().cloned().unwrap_or_default();
    let cell = |value: &serde_json::Value, short: bool| match value.as_str() {
        Some(text) if short => text.chars().take(12).collect(),
        Some(text) => text.to_owned(),
        None => "-".to_owned(),
    };
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|vm| {
            vec![
                cell(&vm["id"], false),
                cell(&vm["name"], false),
                cell(&vm["base_identity"], true),
                cell(&vm["lane"], false),
            ]
        })
        .collect();
    let human = if rows.is_empty() {
        "no VMs\n".to_owned()
    } else {
        table(&["ID", "NAME", "BASE", "LANE"], &rows)
    };
    Ok(Reply::list(items, None).with_human(human))
}

/// The VM config a `vm create` asks for, before the engine's own checks.
pub fn config_for(arguments: &Create, base_identity: String) -> Result<VmConfig, CliError> {
    let network = parse_network(&arguments.network)?;
    let preset = parse_preset(&arguments.stealth)?;
    let stealth = if preset == StealthPreset::Transparent {
        StealthProfile::transparent()
    } else {
        StealthProfile::realistic(preset, &host_cpu_vendor())
    };
    if arguments.name.trim().is_empty() {
        return Err(CliError::invalid("the VM needs a name").with_field("name"));
    }
    Ok(VmConfig {
        name: arguments.name.clone(),
        cpus: arguments.cpus,
        ram_mib: arguments.ram_mib,
        disk_gib: arguments.disk_gib,
        nat: network == VmNetwork::Nat,
        isolated_network: network == VmNetwork::Isolated,
        routed: network == VmNetwork::Routed,
        base_identity: Some(base_identity),
        stealth,
        ..VmConfig::default()
    })
}

/// The engine command of a `vm create`: the base (named, or the only one),
/// the config, and the guest account when the base needs one.
pub(crate) fn create_command(
    arguments: &Create,
    snapshot: &Snapshot,
    password: Option<String>,
) -> Result<Command, CliError> {
    let base = match &arguments.base {
        Some(key) => find_base(snapshot, key)?,
        None => match snapshot.bases.as_slice() {
            [only] => only,
            [] => {
                return Err(CliError::new(
                    ErrorCode::PreconditionFailed,
                    "no base is installed; run `base install DIR` or `base download ID` first",
                ));
            }
            _ => {
                return Err(CliError::invalid(
                    "several bases are installed; name one with --base (see `base list`)",
                )
                .with_field("base"));
            }
        },
    };
    let needs_account = base
        .guest
        .as_ref()
        .is_some_and(|guest| guest.requires_credentials);
    let vm = config_for(arguments, base.id.clone())?;
    let command = match (needs_account, password) {
        (true, Some(password)) => Command::CreateWithCredentials {
            vm,
            credentials: GuestCredentials::new(arguments.user.clone(), password)
                .map_err(|message| CliError::invalid(message).with_field("password-stdin"))?,
        },
        (true, None) => {
            return Err(CliError::invalid(
                "this base needs a guest account: pass --password-stdin and give the password on standard input",
            )
            .with_field("password-stdin"));
        }
        (false, Some(_)) => {
            return Err(CliError::invalid(
                "this base does not take a guest account; leave --password-stdin out",
            )
            .with_field("password-stdin"));
        }
        (false, None) => Command::Create(vm),
    };
    Ok(command)
}

fn create(
    arguments: &Create,
    password: Option<String>,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    // The flags are checked before anything is looked up.
    config_for(arguments, String::new())?;
    let snapshot = engine.snapshot();
    let command = create_command(arguments, snapshot, password)?;
    let before: Vec<String> = snapshot.vms.iter().map(|vm| vm.id.clone()).collect();
    let message = engine.command(command, limit)?;
    let created = engine
        .snapshot()
        .vms
        .iter()
        .find(|vm| !before.contains(&vm.id))
        .map(|vm| vm_value(vm, engine.snapshot()));
    let human = match &created {
        Some(vm) => format!(
            "{message}: {} ({})\n",
            vm["name"].as_str().unwrap_or(""),
            vm["id"].as_str().unwrap_or("")
        ),
        None => format!("{message}\n"),
    };
    Ok(Reply::value(json!({"message": message, "vm": created})).with_human(human))
}

fn start(
    arguments: &Start,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let (id, name) = {
        let vm = find_vm(engine.snapshot(), &arguments.id)?;
        (vm.id.clone(), vm.name.clone())
    };
    let began = std::time::Instant::now();
    engine.command(Command::Start { vm_id: id.clone() }, limit)?;
    wait_guest(engine, &id, limit)?;
    let booted_s = began.elapsed().as_secs_f64();
    let boot_id = engine.snapshot().boot_id.clone();
    let guest = guest_value(engine.snapshot());
    let state = vm_state(engine.snapshot(), &id);
    if let Some(seconds) = arguments.hold {
        hold(engine, seconds)?;
    }
    let stop_limit = limit.or(Some(BOOT_WAIT * 3));
    engine
        .waiter()
        .stop_vm(&id, stop_limit)
        .map_err(crate::engine::wait_error)?;
    let held_s = began.elapsed().as_secs_f64() - booted_s;
    Ok(Reply::value(json!({
        "vm": id,
        "name": name,
        "state": state,
        "boot_id": boot_id,
        "guest_kernel": guest,
        "booted_s": (booted_s * 10.0).round() / 10.0,
        "held_s": (held_s * 10.0).round() / 10.0,
        "stopped_on_exit": true,
    }))
    .with_human(match arguments.hold {
        Some(_) => format!(
            "{name} ({id}) booted in {booted_s:.1} s, the guest answered; held {held_s:.0} s, then stopped\n"
        ),
        None => format!(
            "{name} ({id}) booted in {booted_s:.1} s, the guest answered; stopped again (a VM ends with this command; use --hold to keep it)\n"
        ),
    }))
}

/// Keep the VM up for `seconds`, or until a signal when it is 0.
fn hold(engine: &mut DirectEngine, seconds: u64) -> Result<(), CliError> {
    let until = (seconds > 0).then(|| std::time::Instant::now() + Duration::from_secs(seconds));
    loop {
        if until.is_some_and(|until| std::time::Instant::now() >= until) {
            return Ok(());
        }
        engine.pump(Duration::from_millis(200))?;
    }
}

fn stop(id: &str, limit: Option<Duration>, engine: &mut DirectEngine) -> Result<Reply, CliError> {
    let (id, name) = {
        let vm = find_vm(engine.snapshot(), id)?;
        (vm.id.clone(), vm.name.clone())
    };
    if engine.snapshot().active_vm.as_deref() != Some(id.as_str()) {
        return Ok(Reply::value(json!({"vm": id, "state": "stopped", "changed": false}))
            .with_human(format!(
                "{name} is not running in this process; in direct mode a VM ends with the command that started it\n"
            )));
    }
    engine
        .waiter()
        .stop_vm(&id, limit)
        .map_err(crate::engine::wait_error)?;
    Ok(
        Reply::value(json!({"vm": id, "state": "stopped", "changed": true}))
            .with_human(format!("{name} stopped; its recording is final\n")),
    )
}

fn status(id: &str, snapshot: &Snapshot) -> Result<Reply, CliError> {
    let vm = find_vm(snapshot, id)?;
    let mut value = vm_value(vm, snapshot);
    let active = snapshot.active_vm.as_deref() == Some(vm.id.as_str());
    let layer = snapshot
        .disk_layers
        .iter()
        .find(|layer| layer.vm_id == vm.id)
        .map(|layer| format!("{:?}", layer.phase).to_ascii_lowercase());
    let directory = snapshot
        .vm_locations
        .iter()
        .find(|location| location.vm_id == vm.id)
        .map(|location| location.disk_directory.clone());
    let object = value.as_object_mut().expect("a VM object");
    object.insert(
        "boot_id".into(),
        json!(active.then(|| snapshot.boot_id.clone()).flatten()),
    );
    object.insert(
        "guest_kernel".into(),
        if active {
            guest_value(snapshot)
        } else {
            json!(null)
        },
    );
    object.insert("disk_layer".into(), json!(layer));
    object.insert("directory".into(), json!(directory));
    let human = block(&[
        ("id", vm.id.clone()),
        ("name", vm.name.clone()),
        ("state", vm_state(snapshot, &vm.id).to_owned()),
        (
            "base",
            vm.base_identity.clone().unwrap_or_else(|| "-".into()),
        ),
        (
            "machine",
            format!(
                "{} CPUs, {} MiB RAM, {} GiB disk, {}, {}",
                vm.cpus,
                vm.ram_mib,
                vm.disk_gib,
                network_name(vm.network()),
                preset_name(vm.stealth.preset)
            ),
        ),
        (
            "snapshots",
            super::machine::live_checkpoints(snapshot, &vm.id)
                .len()
                .to_string(),
        ),
        (
            "disk layer",
            value["disk_layer"].as_str().unwrap_or("none").to_owned(),
        ),
    ]);
    Ok(Reply::value(value).with_human(human))
}

fn reset(
    id: &str,
    yes: bool,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let (id, name) = {
        let vm = find_vm(engine.snapshot(), id)?;
        (vm.id.clone(), vm.name.clone())
    };
    confirm(
        yes,
        &format!("resetting {name:?} replaces its disk with the base"),
    )?;
    let message = engine.command(
        Command::Reset {
            vm_id: id.clone(),
            confirmed: true,
        },
        limit,
    )?;
    Ok(Reply::value(json!({"vm": id, "message": message})).with_human(format!("{message}\n")))
}

fn duplicate(
    id: &str,
    name: &str,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let source = find_vm(engine.snapshot(), id)?.id.clone();
    if name.trim().is_empty() {
        return Err(CliError::invalid("the copy needs a name").with_field("name"));
    }
    let before: Vec<String> = engine
        .snapshot()
        .vms
        .iter()
        .map(|vm| vm.id.clone())
        .collect();
    let message = engine.command(
        Command::Duplicate {
            vm_id: source,
            name: name.to_owned(),
        },
        limit,
    )?;
    let copy = engine
        .snapshot()
        .vms
        .iter()
        .find(|vm| !before.contains(&vm.id))
        .map(|vm| vm_value(vm, engine.snapshot()));
    Ok(Reply::value(json!({"message": message, "vm": copy})).with_human(format!("{message}\n")))
}

fn delete(
    id: &str,
    yes: bool,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let (id, name) = {
        let vm = find_vm(engine.snapshot(), id)?;
        (vm.id.clone(), vm.name.clone())
    };
    confirm(
        yes,
        &format!("deleting {name:?} destroys its disk and configuration"),
    )?;
    let message = engine.command(
        Command::Delete {
            vm_id: id.clone(),
            confirmed: true,
        },
        limit,
    )?;
    Ok(Reply::value(json!({"deleted": id, "message": message})).with_human(format!("{message}\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_arguments(extra: &[&str]) -> Create {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            create: Create,
        }
        let mut all = vec!["x", "lane"];
        all.extend_from_slice(extra);
        Wrapper::parse_from(all).create
    }

    #[test]
    fn the_network_flag_sets_exactly_one_network() {
        for (name, expected) in [
            ("disconnected", VmNetwork::Disconnected),
            ("isolated", VmNetwork::Isolated),
            ("routed", VmNetwork::Routed),
            ("nat", VmNetwork::Nat),
        ] {
            let config = config_for(&create_arguments(&["--network", name]), "b".into()).unwrap();
            assert_eq!(config.network(), expected, "{name}");
        }
    }

    #[test]
    fn a_config_carries_the_flags_and_the_chosen_profile() {
        let config = config_for(
            &create_arguments(&[
                "--cpus",
                "2",
                "--ram-mib",
                "1024",
                "--disk-gib",
                "4",
                "--stealth",
                "transparent",
            ]),
            "base1".into(),
        )
        .unwrap();
        assert_eq!(
            (
                config.name.as_str(),
                config.cpus,
                config.ram_mib,
                config.disk_gib
            ),
            ("lane", 2, 1024, 4)
        );
        assert_eq!(config.base_identity.as_deref(), Some("base1"));
        assert_eq!(config.stealth.preset, StealthPreset::Transparent);
        let desktop = config_for(&create_arguments(&[]), "b".into()).unwrap();
        assert_eq!(desktop.stealth.preset, StealthPreset::RealisticDesktop);
    }

    #[test]
    fn bad_flags_are_refused_before_the_engine_is_asked() {
        assert!(config_for(&create_arguments(&["--network", "wifi"]), "b".into()).is_err());
        assert!(config_for(&create_arguments(&["--stealth", "cloud-vps"]), "b".into()).is_err());
        let blank = Create {
            name: "  ".into(),
            ..create_arguments(&[])
        };
        assert!(config_for(&blank, "b".into()).is_err());
    }

    #[test]
    fn the_password_is_not_a_command_line_flag() {
        use clap::CommandFactory;
        let command = crate::args::Cli::command();
        let create = command
            .find_subcommand("vm")
            .and_then(|vm| vm.find_subcommand("create"))
            .expect("vm create");
        let names: Vec<&str> = create
            .get_arguments()
            .filter_map(|a| a.get_long())
            .collect();
        assert!(names.contains(&"password-stdin"));
        assert!(!names.contains(&"password"));
    }
}
