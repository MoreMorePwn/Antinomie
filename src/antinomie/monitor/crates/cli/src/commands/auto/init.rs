// SPDX-License-Identifier: GPL-3.0-only
//! `auto init` (design 3.4.4, 4.5.3; card P3-5b): the lane VM, its clean
//! snapshot, `service/lanes/lane-N.json`, and a default policy when there is
//! none.
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
    config::{DEFAULT_POLICY, DiskVms},
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
    /// The lane VM's name (the policy's `vm.lane_vm`) [default: auto-N].
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
    /// The clean snapshot's name (the policy's `vm.revert_to`).
    #[arg(long, default_value = CLEAN_SNAPSHOT)]
    pub snapshot: String,
    /// Replace an existing lane with a new VM (for a new base). The old VM
    /// is kept; delete it with `vm delete` when you no longer need it.
    #[arg(long)]
    pub replace: bool,
}

/// The shipped policy, pointed at this lane.
pub fn default_policy(vm_name: &str, snapshot: &str) -> String {
    DEFAULT_POLICY
        .replace(
            "lane_vm      = \"auto-1\"",
            &format!("lane_vm      = {}", toml_string(vm_name)),
        )
        .replace(
            "revert_to    = \"auto-clean\"",
            &format!("revert_to    = {}", toml_string(snapshot)),
        )
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
    let need_revision = report
        .policies
        .values()
        .any(|p| p.policy.evidence.trigger().is_some_and(|plan| plan.core))
        .then_some(16)
        .or_else(|| {
            report
                .policies
                .values()
                .any(|p| p.policy.evidence.core_dump)
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
    // A first lane gets the shipped policy, pointed at its VM.
    let policies = data_dir.join("policies");
    let mut written = None;
    let has_policy = std::fs::read_dir(&policies).is_ok_and(|mut entries| {
        entries.any(|e| e.is_ok_and(|e| e.path().extension().is_some_and(|x| x == "toml")))
    });
    if !has_policy {
        std::fs::create_dir_all(&policies).map_err(|e| CliError::io(&policies, &e))?;
        let path = policies.join("default.toml");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| {
                std::io::Write::write_all(
                    &mut file,
                    default_policy(&name, &arguments.snapshot).as_bytes(),
                )
            })
            .map_err(|e| CliError::io(&path, &e))?;
        written = Some(path);
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
            "policy written: {} (accepts ELF x86-64 only; edit [sample] accept_types to add scripts)\n",
            path.display()
        ));
    }
    if let Some(old) = &made.replaced_vm {
        human.push_str(&format!(
            "the lane's old VM {old} is kept; set vm.lane_vm in your policies to {:?} and delete the old VM when done\n",
            made.vm_name
        ));
    }
    if arguments.lane > 1 {
        human.push_str(&format!(
            "lane {} runs when service.toml has [daemon] lanes = {} or more; it takes the jobs whose policy's lane VM has its base\n",
            made.lane, arguments.lane
        ));
    }
    Ok(Reply::value(json!({"lane": made, "policy_written": written})).with_human(human))
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
    fn the_default_policy_points_at_the_lane_and_still_validates() {
        let text = default_policy("lane \"x\"", "clean-1");
        assert!(text.contains("lane_vm      = \"lane \\\"x\\\"\""));
        assert!(text.contains("revert_to    = \"clean-1\""));
        let (policy, problems) = antinomie_service::config::validate::parse_policy(
            "default",
            "policies/default.toml",
            &text,
            &antinomie_service::config::NoVms,
        );
        assert!(
            policy.is_some()
                && problems
                    .iter()
                    .all(|p| p.severity != antinomie_service::config::Severity::Error),
            "{problems:?}"
        );
    }
}
