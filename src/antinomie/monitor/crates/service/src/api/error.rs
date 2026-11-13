// SPDX-License-Identifier: GPL-3.0-only
//! `ApiError` (design 5.7, 5.12.8): the one error every failed operation
//! returns. The code table is a single enum.

use super::ops::Permission;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// The error codes. `unauthenticated` and `forbidden` are added by the HTTP
/// layer only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidArgument,
    Unauthenticated,
    Forbidden,
    /// The caller lacks a permission; `details.needs` names it.
    PermissionDenied,
    /// The preset (in 0.9.0: the policy) is unknown, retired or not offered
    /// to the caller; `details.preset` names it.
    PresetDenied,
    /// A value is above the caller's limit; `details.field` and
    /// `details.limit` name it.
    LimitExceeded,
    /// The node does not have what the request needs (a route, a lane, a
    /// tool); `details.what` names it.
    UnavailableOnNode,
    NotFound,
    Conflict,
    PreconditionFailed,
    PayloadTooLarge,
    QuotaExceeded,
    Unavailable,
    Unsupported,
    Internal,
}

impl ErrorCode {
    pub const ALL: [Self; 15] = [
        Self::InvalidArgument,
        Self::Unauthenticated,
        Self::Forbidden,
        Self::PermissionDenied,
        Self::PresetDenied,
        Self::LimitExceeded,
        Self::UnavailableOnNode,
        Self::NotFound,
        Self::Conflict,
        Self::PreconditionFailed,
        Self::PayloadTooLarge,
        Self::QuotaExceeded,
        Self::Unavailable,
        Self::Unsupported,
        Self::Internal,
    ];

    /// The suggested HTTP status (the binding is ANT-T0192's).
    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidArgument => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden | Self::PermissionDenied | Self::PresetDenied | Self::LimitExceeded => {
                403
            }
            Self::NotFound => 404,
            Self::Conflict | Self::UnavailableOnNode => 409,
            Self::PreconditionFailed => 412,
            Self::PayloadTooLarge => 413,
            Self::QuotaExceeded => 429,
            Self::Unsupported => 501,
            Self::Unavailable => 503,
            Self::Internal => 500,
        }
    }
}

/// The values of `details.reason` the contract names (5.7, 5.12.1, 5.12.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorReason {
    /// `conflict`: the recording grew or the filter changed.
    CursorStale,
    /// `precondition_failed`: earlier file bytes while the layer is pending.
    LayerPending,
    /// `precondition_failed`: a Triage read of a recording still being written;
    /// `details.phase` says which phase.
    RecordingOpen,
    /// `quota_exceeded`: too many heavy reads; `details.retry_after_s`.
    HeavyReadLimit,
    /// `unavailable`: a read passed its deadline and was cancelled.
    ReadTimeout,
    /// `unsupported`: a desktop run mode in a v1 job.
    RunModeNotInV1,
    /// `unsupported`: the core needs a newer guest revision.
    GuestRevision,
    /// `not_found`: the run never produced that data.
    NotRecorded,
    /// `internal`: the Triage scan failed; the next call may start it again.
    ScanFailed,
    /// `internal`: the recording is corrupt or its index cannot be built.
    RecordingUnreadable,
    /// `quota_exceeded`: the connection has 16 requests in flight (or the
    /// socket 256) (local socket, 5.9).
    TooManyRequests,
    /// `quota_exceeded`: requests come faster than the socket's rate;
    /// `details.retry_after_s`.
    RateLimited,
    /// `unavailable`: the socket serves 64 connections already.
    TooManyConnections,
    /// `quota_exceeded`: 64 subscriptions of this client or 256 in all (A18).
    TooManySubscriptions,
    /// `unavailable`: the daemon is stopping; queued jobs stay queued.
    ServiceStopping,
    /// `unavailable`: a request was cancelled by `{"op": "cancel"}` or by the
    /// connection closing.
    Cancelled,
}

/// The error of a failed operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    /// The offending request field, when one is to blame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub retryable: bool,
    /// `reason`, `position`, `retry_after_s`, `phase`, `log` and so on.
    #[serde(default)]
    pub details: Map<String, Value>,
}

/// The wire form: `{"error": {...}}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorBody {
    pub error: ApiError,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        // Retrying can help only when waiting, not when the request is wrong.
        let retryable = matches!(code, ErrorCode::QuotaExceeded | ErrorCode::Unavailable);
        Self {
            code,
            message: message.into(),
            field: None,
            retryable,
            details: Map::new(),
        }
    }

    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub fn with_reason(mut self, reason: ErrorReason) -> Self {
        self.details.insert(
            "reason".into(),
            serde_json::to_value(reason).unwrap_or(Value::Null),
        );
        self
    }

    pub fn with_detail(mut self, key: &str, value: Value) -> Self {
        self.details.insert(key.to_owned(), value);
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// `details.reason`, when it is one the contract names.
    pub fn reason(&self) -> Option<ErrorReason> {
        serde_json::from_value(self.details.get("reason")?.clone()).ok()
    }

    pub fn body(self) -> ErrorBody {
        ErrorBody { error: self }
    }

    // The constructors of the conditions the contract spells out.

    pub fn invalid_argument(field: &str, message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message).with_field(field)
    }

    pub fn not_found(what: &str) -> Self {
        Self::new(ErrorCode::NotFound, format!("{what} not found"))
    }

    pub fn cursor_stale() -> Self {
        Self::new(
            ErrorCode::Conflict,
            "the recording or the filter changed; restart from the first page",
        )
        .with_reason(ErrorReason::CursorStale)
    }

    pub fn layer_pending() -> Self {
        Self::new(
            ErrorCode::PreconditionFailed,
            "the earlier file bytes are not copied into the recording yet",
        )
        .with_reason(ErrorReason::LayerPending)
        .retryable(true)
    }

    pub fn recording_open(phase: &str) -> Self {
        Self::new(
            ErrorCode::PreconditionFailed,
            "the recording is still being written",
        )
        .with_reason(ErrorReason::RecordingOpen)
        .with_detail("phase", json!(phase))
        .retryable(true)
    }

    pub fn heavy_read_limit(retry_after_s: u64) -> Self {
        Self::new(ErrorCode::QuotaExceeded, "too many heavy reads in flight")
            .with_reason(ErrorReason::HeavyReadLimit)
            .with_detail("retry_after_s", json!(retry_after_s))
    }

    pub fn read_timeout() -> Self {
        Self::new(
            ErrorCode::Unavailable,
            "the read passed its deadline and was cancelled",
        )
        .with_reason(ErrorReason::ReadTimeout)
    }

    pub fn not_recorded(what: &str) -> Self {
        Self::new(ErrorCode::NotFound, format!("the run recorded no {what}"))
            .with_reason(ErrorReason::NotRecorded)
    }

    /// The caller lacks every one of `needs` (one is enough): the message
    /// names them, `details.needs` lists their keys.
    pub fn permission_denied(needs: &[Permission]) -> Self {
        let names: Vec<String> = needs
            .iter()
            .map(|p| format!("{} ({})", p.key(), p.name()))
            .collect();
        Self::new(
            ErrorCode::PermissionDenied,
            format!("this needs the permission {}", names.join(" or ")),
        )
        .with_detail(
            "needs",
            Value::Array(needs.iter().map(|p| json!(p.key())).collect()),
        )
    }

    /// The node does not have `what` (`details.what`).
    pub fn unavailable_on_node(what: &str, message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnavailableOnNode, message).with_detail("what", json!(what))
    }

    pub fn recording_unreadable(text: &str) -> Self {
        Self::new(ErrorCode::Internal, text).with_reason(ErrorReason::RecordingUnreadable)
    }

    /// A core needs a newer guest revision.
    pub fn guest_revision(needed: u32) -> Self {
        Self::new(
            ErrorCode::Unsupported,
            format!("this needs guest revision {needed} or newer"),
        )
        .with_reason(ErrorReason::GuestRevision)
    }

    /// A byte range above its limit.
    pub fn payload_too_large(limit: u64) -> Self {
        Self::new(
            ErrorCode::PayloadTooLarge,
            format!("the range is above the limit of {limit} bytes"),
        )
        .with_detail("limit", json!(limit))
    }

    /// The Triage scan failed; the next call may start it again.
    pub fn scan_failed() -> Self {
        Self::new(ErrorCode::Internal, "the Triage scan failed")
            .with_reason(ErrorReason::ScanFailed)
            .retryable(true)
    }
}

impl From<super::spec::SpecError> for ApiError {
    fn from(error: super::spec::SpecError) -> Self {
        Self::invalid_argument(&error.field, error.message)
    }
}

impl From<super::spec::Unsupported> for ApiError {
    fn from(error: super::spec::Unsupported) -> Self {
        Self::new(ErrorCode::Unsupported, "not available in API version 1")
            .with_field(error.field)
            .with_reason(ErrorReason::RunModeNotInV1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_form_matches_the_contract_example() {
        let error = ApiError::new(
            ErrorCode::UnavailableOnNode,
            "route tor is not set up on this node",
        )
        .with_field("overrides.route");
        let value = serde_json::to_value(error.body()).unwrap();
        assert_eq!(
            value,
            json!({"error": {"code": "unavailable_on_node",
                "message": "route tor is not set up on this node",
                "field": "overrides.route", "retryable": false, "details": {}}})
        );
    }

    #[test]
    fn http_statuses_follow_the_table() {
        let table = [
            (ErrorCode::InvalidArgument, 400),
            (ErrorCode::Unauthenticated, 401),
            (ErrorCode::Forbidden, 403),
            (ErrorCode::PermissionDenied, 403),
            (ErrorCode::PresetDenied, 403),
            (ErrorCode::LimitExceeded, 403),
            (ErrorCode::UnavailableOnNode, 409),
            (ErrorCode::NotFound, 404),
            (ErrorCode::Conflict, 409),
            (ErrorCode::PreconditionFailed, 412),
            (ErrorCode::PayloadTooLarge, 413),
            (ErrorCode::QuotaExceeded, 429),
            (ErrorCode::Unavailable, 503),
            (ErrorCode::Unsupported, 501),
            (ErrorCode::Internal, 500),
        ];
        assert_eq!(table.len(), ErrorCode::ALL.len());
        for (code, status) in table {
            assert_eq!(code.http_status(), status);
        }
    }

    /// The table of design 5.12.8, row by row.
    #[test]
    fn the_read_error_table_maps_to_codes_and_reasons() {
        let table: [(ApiError, ErrorCode, Option<ErrorReason>); 10] = [
            (ApiError::not_found("run"), ErrorCode::NotFound, None),
            (
                ApiError::cursor_stale(),
                ErrorCode::Conflict,
                Some(ErrorReason::CursorStale),
            ),
            (
                ApiError::layer_pending(),
                ErrorCode::PreconditionFailed,
                Some(ErrorReason::LayerPending),
            ),
            (
                ApiError::not_recorded("capture"),
                ErrorCode::NotFound,
                Some(ErrorReason::NotRecorded),
            ),
            (
                ApiError::guest_revision(15),
                ErrorCode::Unsupported,
                Some(ErrorReason::GuestRevision),
            ),
            (
                ApiError::payload_too_large(65_536),
                ErrorCode::PayloadTooLarge,
                None,
            ),
            (
                ApiError::heavy_read_limit(5),
                ErrorCode::QuotaExceeded,
                Some(ErrorReason::HeavyReadLimit),
            ),
            (
                ApiError::read_timeout(),
                ErrorCode::Unavailable,
                Some(ErrorReason::ReadTimeout),
            ),
            (
                ApiError::recording_unreadable("bad manifest"),
                ErrorCode::Internal,
                Some(ErrorReason::RecordingUnreadable),
            ),
            (
                ApiError::scan_failed(),
                ErrorCode::Internal,
                Some(ErrorReason::ScanFailed),
            ),
        ];
        for (error, code, reason) in table {
            assert_eq!(error.code, code, "{error:?}");
            assert_eq!(error.reason(), reason, "{error:?}");
        }
        assert_eq!(
            ApiError::heavy_read_limit(5).details["retry_after_s"],
            json!(5)
        );
    }

    #[test]
    fn reasons_round_trip_through_details() {
        let error = ApiError::cursor_stale();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
        let error = ApiError::recording_open("live");
        assert_eq!(error.details["phase"], json!("live"));
    }

    #[test]
    fn a_permission_refusal_names_what_it_needs() {
        let error = ApiError::permission_denied(&[Permission::RouteTor]);
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(error.details["needs"], json!(["route.tor"]));
        assert!(error.message.contains("route.tor (Tor route)"), "{error:?}");
        assert!(!error.retryable);
        let either = ApiError::permission_denied(&[Permission::RunsSubmit, Permission::SamplesAdd]);
        assert_eq!(
            either.details["needs"],
            json!(["runs.submit", "samples.add"])
        );
        assert!(either.message.contains(" or "), "{either:?}");
        let node = ApiError::unavailable_on_node("route", "no route is set up");
        assert_eq!(node.code, ErrorCode::UnavailableOnNode);
        assert_eq!(node.details["what"], json!("route"));
        assert_eq!(node.code.http_status(), 409);
    }

    #[test]
    fn the_new_codes_have_their_wire_names_and_policy_denied_is_gone() {
        let names: Vec<String> = ErrorCode::ALL
            .iter()
            .map(|c| {
                serde_json::to_value(c)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        for name in [
            "permission_denied",
            "preset_denied",
            "limit_exceeded",
            "unavailable_on_node",
        ] {
            assert!(names.iter().any(|n| n == name), "{name}");
        }
        assert!(!names.iter().any(|n| n == "policy_denied"));
        assert!(serde_json::from_value::<ErrorCode>(json!("policy_denied")).is_err());
    }
}
