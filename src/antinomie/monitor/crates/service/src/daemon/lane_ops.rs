// SPDX-License-Identifier: GPL-3.0-only
//! The lane operations of the local socket (design 3.4.4 `auto lane ...`;
//! card P3-5b). They are an addition to the operations of 5.3, which has none
//! for lanes: `lane.list` needs `read`; `lane.reset` and `lane.unquarantine`
//! need `manage` and are carried out by the lane's own thread (it owns the
//! engine) when no job runs.

use super::service::{Service, params, to_value};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ids::LaneId,
        ops::Scope,
    },
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
        "lane.list" => Scope::Read,
        "lane.reset" | "lane.unquarantine" => Scope::Manage,
        _ if op.starts_with("lane.") => {
            return Some(Err(ApiError::invalid_argument(
                "op",
                format!("unknown operation {op:?}"),
            )));
        }
        _ => return None,
    };
    if !ctx.caller.has(need) {
        return Some(Err(ApiError::new(
            ErrorCode::Forbidden,
            "this lane operation needs another scope",
        )));
    }
    Some(serve(service, op, value))
}

fn serve(service: &Service, op: &str, value: Value) -> Result<Value, ApiError> {
    let _: LaneParams = params(value.clone())?;
    match op {
        "lane.list" => {
            let snapshot = crate::store::lock(&service.view).lanes.clone();
            to_value(&provision::list_lanes(&service.lanes, Some(&snapshot))?)
        }
        "lane.reset" => service.lane_op(op, value, RESET_WAIT),
        _ => service.lane_op(op, value, CHECK_WAIT),
    }
}
