// SPDX-License-Identifier: GPL-3.0-only
//! The lane operations of the local socket (`lane.*`): the lane cards fill
//! them in; until then they are `unsupported`.

use super::service::Service;
use crate::{
    api::error::{ApiError, ErrorCode},
    server::CallContext,
};
use serde_json::Value;

/// `Some` for a `lane.*` op, `None` for any other.
pub(super) fn call(
    _service: &Service,
    op: &str,
    _value: Value,
    _ctx: &CallContext,
) -> Option<Result<Value, ApiError>> {
    op.starts_with("lane.").then(|| {
        Err(ApiError::new(
            ErrorCode::Unsupported,
            format!("{op} is not served by this daemon"),
        ))
    })
}
