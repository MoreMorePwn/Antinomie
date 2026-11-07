// SPDX-License-Identifier: GPL-3.0-only
//! The error object of design 5.7 as the CLI reports it, and its exit code.
//!
//! `ErrorCode` holds the codes a local command can produce. The HTTP-only
//! codes (`unauthenticated`, `forbidden`) are not here. When the service crate
//! gets its own `ApiError` (card P3-1), a conversion into `CliError` replaces
//! the constructors that name codes directly.
use crate::exit::Exit;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidArgument,
    PolicyDenied,
    /// A local file or directory refuses access (CLI only; exit 5).
    PermissionDenied,
    NotFound,
    Conflict,
    PreconditionFailed,
    PayloadTooLarge,
    QuotaExceeded,
    Unavailable,
    Unsupported,
    /// A required tool is missing (CLI only; exit 20).
    DependencyMissing,
    /// A check ran and found damage: a sample archive that does not match its
    /// hash, a custody chain that does not verify (CLI only; exit 1).
    VerificationFailed,
    Internal,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::PolicyDenied => "policy_denied",
            ErrorCode::PermissionDenied => "permission_denied",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::PreconditionFailed => "precondition_failed",
            ErrorCode::PayloadTooLarge => "payload_too_large",
            ErrorCode::QuotaExceeded => "quota_exceeded",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::DependencyMissing => "dependency_missing",
            ErrorCode::VerificationFailed => "verification_failed",
            ErrorCode::Internal => "internal",
        }
    }

    /// The exit code of design 3.3 for a failure with this code.
    pub const fn exit(self) -> Exit {
        match self {
            ErrorCode::InvalidArgument
            | ErrorCode::PreconditionFailed
            | ErrorCode::Conflict
            | ErrorCode::PayloadTooLarge => Exit::Invalid,
            ErrorCode::NotFound => Exit::NotFound,
            ErrorCode::PolicyDenied | ErrorCode::PermissionDenied => Exit::Denied,
            ErrorCode::QuotaExceeded => Exit::Quota,
            ErrorCode::Unavailable => Exit::Busy,
            ErrorCode::DependencyMissing => Exit::Dependency,
            ErrorCode::Unsupported | ErrorCode::Internal | ErrorCode::VerificationFailed => {
                Exit::Failed
            }
        }
    }
}

/// A failed command: the error object plus the exit code it ends with. Boxed
/// so that every `Result<_, CliError>` stays small.
#[derive(Clone, Debug)]
pub struct CliError(Box<ErrorBody>);

impl std::ops::Deref for CliError {
    type Target = ErrorBody;
    fn deref(&self) -> &ErrorBody {
        &self.0
    }
}

impl std::ops::DerefMut for CliError {
    fn deref_mut(&mut self) -> &mut ErrorBody {
        &mut self.0
    }
}

#[derive(Clone, Debug)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    pub field: Option<String>,
    pub retryable: bool,
    pub details: Value,
    pub exit: Exit,
    /// Text a human run prints on standard output before the error line (for
    /// example the table of checks of `doctor`).
    pub human_output: Option<String>,
}

impl CliError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self(Box::new(ErrorBody {
            code,
            message: message.into(),
            field: None,
            retryable: matches!(code, ErrorCode::Unavailable | ErrorCode::QuotaExceeded),
            details: json!({}),
            exit: code.exit(),
            human_output: None,
        }))
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// Bad command line arguments (clap's own failures): exit 2, not 4.
    pub fn usage(message: impl Into<String>) -> Self {
        let mut error = Self::invalid(message);
        error.exit = Exit::Usage;
        error
    }

    /// A failure of a local file operation on `path`.
    pub fn io(path: &std::path::Path, error: &std::io::Error) -> Self {
        let code = match error.kind() {
            std::io::ErrorKind::NotFound => ErrorCode::NotFound,
            std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            _ => ErrorCode::Internal,
        };
        Self::new(code, format!("{}: {error}", path.display()))
    }

    /// A failure of `Backend::new`: a data directory owned by another process
    /// is `unavailable` (exit 21) and names the owner; anything else is a
    /// plain failure carrying the engine's text.
    pub fn from_engine_start(data_dir: &std::path::Path, message: &str) -> Self {
        use antinomie_monitor_core::data_owner;
        if message.starts_with(data_owner::IN_USE) {
            let owner = data_owner::read_record(data_dir);
            return Self::new(ErrorCode::Unavailable, message)
                .with_details(json!({"data_dir": data_dir, "owner": owner}));
        }
        Self::internal(message)
    }

    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    pub fn with_exit(mut self, exit: Exit) -> Self {
        self.exit = exit;
        self
    }

    pub fn with_human_output(mut self, text: String) -> Self {
        self.human_output = Some(text);
        self
    }

    /// The `error` member of the JSON envelope (design 5.7).
    pub fn to_value(&self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("code".into(), self.code.as_str().into());
        object.insert("message".into(), self.message.clone().into());
        if let Some(field) = &self.field {
            object.insert("field".into(), field.clone().into());
        }
        object.insert("retryable".into(), self.retryable.into());
        object.insert("details".into(), self.details.clone());
        Value::Object(object)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_map_to_the_exit_codes_of_the_design() {
        let table = [
            (ErrorCode::InvalidArgument, 4),
            (ErrorCode::PreconditionFailed, 4),
            (ErrorCode::Conflict, 4),
            (ErrorCode::PayloadTooLarge, 4),
            (ErrorCode::NotFound, 3),
            (ErrorCode::PolicyDenied, 5),
            (ErrorCode::PermissionDenied, 5),
            (ErrorCode::QuotaExceeded, 22),
            (ErrorCode::Unavailable, 21),
            (ErrorCode::DependencyMissing, 20),
            (ErrorCode::Unsupported, 1),
            (ErrorCode::Internal, 1),
            (ErrorCode::VerificationFailed, 1),
        ];
        for (code, exit) in table {
            assert_eq!(code.exit().code(), exit, "{}", code.as_str());
            assert_eq!(CliError::new(code, "x").exit.code(), exit);
        }
    }

    #[test]
    fn usage_errors_exit_two_but_keep_the_invalid_argument_code() {
        let error = CliError::usage("unknown flag");
        assert_eq!(error.exit.code(), 2);
        assert_eq!(error.code.as_str(), "invalid_argument");
    }

    #[test]
    fn the_error_object_has_the_members_of_design_5_7() {
        let error = CliError::not_found("no such sample")
            .with_field("sha256")
            .with_details(json!({"reason": "x"}));
        assert_eq!(
            error.to_value(),
            json!({"code": "not_found", "message": "no such sample", "field": "sha256",
                   "retryable": false, "details": {"reason": "x"}})
        );
        let plain = CliError::internal("boom").to_value();
        assert!(plain.get("field").is_none());
    }

    #[test]
    fn a_directory_in_use_is_exit_21_and_names_the_owner() {
        use antinomie_monitor_core::data_owner;
        let message = format!("{} by the Antinomie window (pid 7)", data_owner::IN_USE);
        let error = CliError::from_engine_start(std::path::Path::new("/nonexistent"), &message);
        assert_eq!(error.exit.code(), 21);
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.message.contains("pid 7"));
        assert!(error.details["owner"].is_null());
        assert_eq!(
            CliError::from_engine_start(std::path::Path::new("/x"), "disk full")
                .exit
                .code(),
            1
        );
    }

    #[test]
    fn unavailable_and_quota_are_retryable() {
        assert!(CliError::new(ErrorCode::Unavailable, "x").retryable);
        assert!(CliError::new(ErrorCode::QuotaExceeded, "x").retryable);
        assert!(!CliError::new(ErrorCode::NotFound, "x").retryable);
    }

    #[test]
    fn io_errors_map_by_kind() {
        let path = std::path::Path::new("/x");
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert_eq!(CliError::io(path, &missing).exit.code(), 3);
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(CliError::io(path, &denied).exit.code(), 5);
    }
}
