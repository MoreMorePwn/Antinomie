// SPDX-License-Identifier: GPL-3.0-only
//! `auto lane list/reset/unquarantine` (design 3.4.4; card P3-5b). With a
//! daemon they go to it (the lane's own thread does the work, when no run
//! runs); without one `list` reads the lane files and the other two take the
//! lane's data folder for this command. With several lanes (ANT-T0455 card
//! C) `list` shows every lane, and `--lane lane-N` picks the lane the other
//! two work on (lane N's own engine).
use super::link::{self, api};
use crate::{
    context::Context,
    engine::DirectEngine,
    error::CliError,
    output::{Reply, table},
};
use antinomie_service::{
    api::ids::LaneId,
    lane::{LaneDir, ProcFs, provision},
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};

#[derive(Subcommand, Debug)]
pub enum Lane {
    /// The lanes, their VM, quarantine and what keeps them from a run.
    List,
    /// Revert the lane VM to its clean snapshot now; lifts a quarantine
    /// when the revert works.
    Reset(LaneArgs),
    /// Lift a quarantine without reverting, when the checks pass (the clean
    /// snapshot is there, the VM is stopped, nothing is pending).
    Unquarantine(LaneArgs),
}

#[derive(Args, Debug)]
pub struct LaneArgs {
    /// The lane, `lane-N` (or N) [default: lane-1].
    #[arg(long)]
    pub lane: Option<String>,
    /// Confirm (`reset` needs it; `unquarantine` accepts it and does not).
    #[arg(long)]
    pub yes: bool,
}

fn lane_id(text: Option<&str>) -> Result<LaneId, CliError> {
    match text {
        None => Ok(LaneId::new(1)),
        Some(number) if number.parse::<u32>().is_ok_and(|n| n >= 1) => {
            Ok(LaneId::new(number.parse().unwrap_or(1)))
        }
        Some(text) => LaneId::try_from(text.to_owned()).map_err(|_| {
            CliError::invalid(format!("{text:?} is not a lane (lane-1, lane-2, ...)"))
                .with_field("lane")
        }),
    }
}

fn rows(lanes: &Value) -> String {
    let rows: Vec<Vec<String>> = lanes
        .as_array()
        .into_iter()
        .flatten()
        .map(|l| {
            let text = |key: &str| match &l[key] {
                Value::Null => "-".to_owned(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            vec![
                text("lane"),
                format!("{} {}", text("vm_name"), text("vm_id")),
                text("quarantine"),
                text("busy_with"),
                l["problems"]
                    .as_array()
                    .map(|p| {
                        p.iter()
                            .filter_map(|x| x.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .filter(|p| !p.is_empty())
                    .unwrap_or_else(|| "ready".into()),
            ]
        })
        .collect();
    if rows.is_empty() {
        "no lane; run `antinomie-cli auto init`\n".into()
    } else {
        table(&["LANE", "VM", "QUARANTINE", "RUN", "CHECKS"], &rows)
    }
}

pub fn run(command: &Lane, context: &Context) -> Result<Reply, CliError> {
    let (op, args) = match command {
        Lane::List => ("lane.list", None),
        Lane::Reset(args) => ("lane.reset", Some(args)),
        Lane::Unquarantine(args) => ("lane.unquarantine", Some(args)),
    };
    if let Some(args) = args
        && op == "lane.reset"
        && !args.yes
    {
        return Err(
            CliError::invalid("`auto lane reset` reverts the lane VM; confirm with --yes")
                .with_field("yes"),
        );
    }
    let lane = lane_id(args.and_then(|a| a.lane.as_deref()))?;
    let lanes = LaneDir::new(&context.data_dir().join("service"));
    let answer = match link::daemon(context)? {
        Some(mut client) => link::call(&mut client, op, json!({"lane": lane}))?,
        None if op == "lane.list" => {
            serde_json::to_value(provision::list_lanes(&lanes, None).map_err(api)?)
                .unwrap_or_default()
        }
        None => {
            let mut engine = DirectEngine::start_lane(context, Some(&lane))?;
            let logger = context.logger;
            let done = if op == "lane.reset" {
                provision::reset_lane(engine.waiter(), &lanes, &lane, &ProcFs, &mut |t| {
                    logger.info(t)
                })
            } else {
                provision::unquarantine_lane(engine.waiter(), &lanes, &lane)
            };
            engine.finish();
            serde_json::to_value(done.map_err(api)?).unwrap_or_default()
        }
    };
    let human = if answer.is_array() {
        rows(&answer)
    } else {
        rows(&json!([answer]))
    };
    Ok(match answer {
        Value::Array(items) => Reply::list(items, None).with_human(human),
        other => Reply::value(other).with_human(human),
    })
}
