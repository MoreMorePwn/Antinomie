// SPDX-License-Identifier: GPL-3.0-only
//! `auto init` (design 3.4.4, 4.5.3; card P3-5b): the lane VM, its clean
//! snapshot, `service/lanes/lane-N.json`, and, for lane 1 with another VM
//! name or snapshot than the defaults, the `[lanes]` table of a new
//! `service.toml`. The presets need no file: five are built in.
//!
//! It runs in this process and takes the lane's data folder for itself, so it
//! is refused with exit 21 while the daemon (or the window) owns the folder:
//! stop the daemon first. The VM is created routed (each job picks its route;
//! nothing leaves between runs), never NAT and never isolated.
//!
//! `--lane N` (ANT-T0455 card C; 1 to 4, default 1) makes lane N for a daemon
//! with `daemon.lanes = N` or more. Lane 1's VM lives in the data folder;
//! lane N's in `<data>/lanes/N/`, built on a base of the data folder (lane N
//! never installs one). Its default VM name is `auto-N`.
use super::link::api;
use crate::{
    commands::{
        machine::wait_bases,
        vm::{Create, create_command, read_password},
    },
    context::Context,
    engine::DirectEngine,
    error::CliError,
    output::Reply,
};
use antinomie_service::{
    api::ids::LaneId,
    config::{DiskVms, service::Lanes},
    lane::{
        LaneDir,
        provision::{CLEAN_SNAPSHOT, InitPlan, init_lane},
    },
};
use clap::Args;
use serde_json::json;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Args, Debug)]
pub struct Init {
    /// The base (identity, start of it, or label); optional when exactly one is installed.
    #[arg(long, value_name = "ID")]
    pub base: Option<String>,
    /// The lane to make: 1 (the data folder) to 4 (`<data>/lanes/N/`), for
    /// `daemon.lanes` in service.toml.
    #[arg(long, value_name = "N", default_value_t = 1,
          value_parser = clap::value_parser!(u32).range(1..=i64::from(antinomie_service::config::service::MAX_LANES)))]
    pub lane: u32,
    /// The lane VM's name (`[lanes] vm` of service.toml for lane 1)
    /// [default: auto-N].
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, default_value_t = 2)]
    pub cpus: u16,
    #[arg(long, default_value_t = 4096, value_name = "N")]
    pub ram_mib: u32,
    #[arg(long, default_value_t = 40, value_name = "N")]
    pub disk_gib: u32,
    /// realistic-desktop, realistic-laptop, realistic-server or transparent.
    #[arg(long, default_value = "realistic-desktop", value_name = "PRESET")]
    pub stealth: String,
    /// Guest account name (bases that need an account).
    #[arg(long, default_value = "analyst", value_name = "NAME")]
    pub user: String,
    /// Read the guest account password from standard input (one line).
    #[arg(long)]
    pub password_stdin: bool,
    /// The clean snapshot's name (`[lanes] revert_to` of service.toml).
    #[arg(long, default_value = CLEAN_SNAPSHOT)]
    pub snapshot: String,
    /// Replace an existing lane with a new VM (for a new base). The old VM
    /// is kept; delete it with `vm delete` when you no longer need it.
    #[arg(long)]
    pub replace: bool,
}

/// The `[lanes]` table of a `service.toml` for a lane VM and its clean
/// snapshot; `None` when both are the defaults.
pub fn lanes_table(vm_name: &str, snapshot: &str) -> Option<String> {
    let defaults = Lanes::default();
    (vm_name != defaults.vm || snapshot != defaults.revert_to).then(|| {
        format!(
            "[lanes]\nvm        = {}\nrevert_to = {}\n",
            toml_string(vm_name),
            toml_string(snapshot)
        )
    })
}

fn toml_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

pub fn run(arguments: &Init, context: &Context) -> Result<Reply, CliError> {
    let lane = LaneId::new(arguments.lane);
    let name = arguments
        .name
        .clone()
        .unwrap_or_else(|| format!("auto-{}", arguments.lane));
    let password = if arguments.password_stdin {
        Some(read_password()?)
    } else {
        None
    };
    let create = Create {
        name: name.clone(),
        base: arguments.base.clone(),
        cpus: arguments.cpus,
        ram_mib: arguments.ram_mib,
        disk_gib: arguments.disk_gib,
        network: "routed".into(),
        stealth: arguments.stealth.clone(),
        user: arguments.user.clone(),
        password_stdin: arguments.password_stdin,
    };
    let data_dir = context.data_dir().to_path_buf();
    let report =
        antinomie_service::config::validate::load(&data_dir, &DiskVms::open(&data_dir), None);
    // The revision the node's own presets need (a built-in one that takes
    // a core, like Deep, fails its run on an older guest instead).
    let own = || report.presets.values().filter(|p| !p.built_in);
    let need_revision = own()
        .any(|p| p.preset.dumps.trigger().is_some_and(|plan| plan.core))
        .then_some(16)
        .or_else(|| {
            own()
                .any(|p| p.preset.dumps.core_dump_on_exit)
                .then_some(15)
        });
    let mut engine = DirectEngine::start_lane(context, Some(&lane))?;
    let made = (|| {
        wait_bases(&mut engine, context.timeout())?;
        let command = create_command(&create, engine.snapshot(), password)?;
        let base = match &command {
            antinomie_monitor_core::Command::Create(vm)
            | antinomie_monitor_core::Command::CreateWithCredentials { vm, .. } => {
                vm.base_identity.clone().unwrap_or_default()
            }
            _ => String::new(),
        };
        let plan = InitPlan {
            lane: lane.clone(),
            create: command,
            vm_name: name.clone(),
            base_identity: base,
            snapshot: arguments.snapshot.clone(),
            replace: arguments.replace,
            need_revision,
        };
        let lanes = LaneDir::new(&data_dir.join("service"));
        let logger = context.logger;
        init_lane(engine.waiter(), &lanes, &plan, &mut |text| {
            logger.info(text)
        })
        .map_err(api)
    })();
    engine.finish();
    let made = made?;
    // Lane 1 with another VM name or snapshot: the lanes of service.toml
    // point at it (a new file only; an existing one is the operator's).
    let mut written = None;
    let mut hint = None;
    let service = data_dir.join("service.toml");
    let configured = report.service.as_ref().map(|s| s.lanes.clone());
    if arguments.lane == 1
        && let Some(table) = lanes_table(&name, &arguments.snapshot)
    {
        if !service.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&service)
                .and_then(|mut file| std::io::Write::write_all(&mut file, table.as_bytes()))
                .map_err(|e| CliError::io(&service, &e))?;
            written = Some(service.clone());
        } else if configured.is_none_or(|l| l.vm != name || l.revert_to != arguments.snapshot) {
            hint = Some(table);
        }
    }
    let mut human = format!(
        "lane {} is ready: VM {} ({}), clean snapshot {} ({}), base {}\nfirst boot answered in {:.1} s, guest revision {}\n",
        made.lane,
        made.vm_name,
        made.vm_id,
        made.snapshot_name,
        made.snapshot_id,
        made.base_identity.chars().take(12).collect::<String>(),
        made.boot_ms as f64 / 1000.0,
        made.guest_revision
            .map_or("unknown".into(), |r| r.to_string()),
    );
    if let Some(path) = &written {
        human.push_str(&format!(
            "{} written: [lanes] vm and revert_to point at this lane\n",
            path.display()
        ));
    }
    if let Some(table) = &hint {
        human.push_str(&format!(
            "set the lanes of service.toml to this lane:\n{table}"
        ));
    }
    if let Some(old) = &made.replaced_vm {
        human.push_str(&format!(
            "the lane's old VM {old} is kept; set [lanes] vm in service.toml to {:?} and delete the old VM when done\n",
            made.vm_name
        ));
    }
    if arguments.lane > 1 {
        human.push_str(&format!(
            "lane {} runs when service.toml has [daemon] lanes = {} or more; it takes the runs of the lane group when its base is the lane VM's\n",
            made.lane, arguments.lane
        ));
    }
    Ok(Reply::value(json!({"lane": made, "service_written": written})).with_human(human))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn lane_takes_one_to_four_and_refuses_five() {
        let parse = |lane: &str| {
            crate::args::Cli::try_parse_from(["antinomie-cli", "auto", "init", "--lane", lane])
        };
        for bad in ["0", "5"] {
            let error = parse(bad)
                .err()
                .unwrap_or_else(|| panic!("--lane {bad} parsed"));
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{bad}: {error}"
            );
            assert!(error.to_string().contains("1..=4"), "{error}");
        }
        for good in ["1", "4"] {
            assert!(parse(good).is_ok(), "--lane {good}");
        }
    }

    #[test]
    fn the_lanes_table_points_at_the_lane_and_validates() {
        assert_eq!(lanes_table("auto-1", "auto-clean"), None);
        let text = lanes_table("lane \"x\"", "clean-1").unwrap();
        assert!(text.contains("vm        = \"lane \\\"x\\\"\""), "{text}");
        assert!(text.contains("revert_to = \"clean-1\""), "{text}");
        let (config, problems) =
            antinomie_service::config::validate::parse_service("service.toml", &text);
        assert!(problems.is_empty(), "{problems:?}");
        let lanes = config.unwrap().lanes;
        assert_eq!(
            (lanes.vm.as_str(), lanes.revert_to.as_str()),
            ("lane \"x\"", "clean-1")
        );
    }
}
