// SPDX-License-Identifier: GPL-3.0-only
//! The lane operations of the local socket (design 3.4.4 `auto lane ...`;
//! card P3-5b). They are an addition to the operations of 5.3, which has none
//! for lanes: `lane.list` needs `runs.see_all`; `lane.reset` and
//! `lane.unquarantine` need `lanes.reset` and are carried out by the lane's own thread (it owns the
//! engine) when no job runs.

use super::service::{Service, params, to_value};
use crate::{
    api::{error::ApiError, ids::LaneId, ops::Permission},
    lane::provision,
    server::CallContext,
};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

/// The parameters of every lane op: the lane (default the first).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneParams {
    #[serde(default)]
    pub lane: Option<LaneId>,
}

/// How long a reset may take (a restore, a boot, a stop and the settling).
const RESET_WAIT: Duration = Duration::from_secs(900);
const CHECK_WAIT: Duration = Duration::from_secs(60);

/// `Some` for a `lane.*` op, `None` for any other.
pub(super) fn call(
    service: &Service,
    op: &str,
    value: Value,
    ctx: &CallContext,
) -> Option<Result<Value, ApiError>> {
    let need = match op {
        "lane.list" => Permission::RunsSeeAll,
        "lane.reset" | "lane.unquarantine" => Permission::LanesReset,
        _ if op.starts_with("lane.") => {
            return Some(Err(ApiError::invalid_argument(
                "op",
                format!("unknown operation {op:?}"),
            )));
        }
        _ => return None,
    };
    if let Err(error) = ctx.caller.require(need) {
        return Some(Err(error));
    }
    Some(serve(service, op, value))
}

fn serve(service: &Service, op: &str, value: Value) -> Result<Value, ApiError> {
    let _: LaneParams = params(value.clone())?;
    match op {
        "lane.list" => {
            // Each lane is checked against its own engine's snapshot; a lane
            // that does not run here says why.
            let snapshots: Vec<(LaneId, antinomie_monitor_core::Snapshot)> = service
                .slots
                .iter()
                .map(|slot| {
                    (
                        slot.lane.clone(),
                        crate::store::lock(&slot.view).lanes.clone(),
                    )
                })
                .collect();
            let mut list = provision::list_lanes_with(&service.lanes, &|lane| {
                snapshots
                    .iter()
                    .find(|(id, _)| id == lane)
                    .map(|(_, snapshot)| snapshot)
            })?;
            for summary in &mut list {
                if service.slot(&summary.lane).is_none() {
                    let why = service
                        .left_out
                        .iter()
                        .find(|left| left.lane == summary.lane)
                        .map_or_else(
                            || "not started: beyond daemon.lanes".to_owned(),
                            |left| format!("not started: {}", left.reason),
                        );
                    summary.problems.push(why);
                }
            }
            to_value(&list)
        }
        "lane.reset" => service.lane_op(op, value, RESET_WAIT),
        _ => service.lane_op(op, value, CHECK_WAIT),
    }
}
