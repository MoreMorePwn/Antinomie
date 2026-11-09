// SPDX-License-Identifier: GPL-3.0-only
//! The watch folders' operations of the local socket (card P4-2): `watch.list`
//! and `watch.scan`. They are an addition to the operations of 5.3 (which has
//! none for `auto watch`), named like the lane operations.

use super::service::{Service, to_value};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ops::Scope,
    },
    server::CallContext,
};
use serde_json::Value;
use std::time::Duration;

/// `Some` for `watch.list` and `watch.scan`; `None` for any other op.
pub(super) fn call(
    service: &Service,
    op: &str,
    _value: Value,
    ctx: &CallContext,
) -> Option<Result<Value, ApiError>> {
    let need = match op {
        "watch.list" => Scope::Read,
        "watch.scan" => Scope::Manage,
        _ if op.starts_with("watch.") => {
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
            "this operation needs another scope",
        )));
    }
    Some(match op {
        "watch.list" => to_value(&service.watch.list()),
        _ => to_value(&service.watch.scan_now(Duration::from_secs(30))),
    })
}
