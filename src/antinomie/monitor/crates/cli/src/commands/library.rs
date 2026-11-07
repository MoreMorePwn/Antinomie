// SPDX-License-Identifier: GPL-3.0-only
//! Opening the sample library for the `sample` and `custody` commands.
//!
//! These commands need no engine lock (design 2.3): the library is short-lived
//! SQLite with a busy timeout, so they work beside a running window or daemon.
use crate::error::{CliError, ErrorCode};
use antinomie_monitor_core::samples::{DATABASE, Library, samples_dir};
use std::path::Path;

/// The library of `data_dir` for a command that only reads. A data directory
/// with no library yet is `None`; nothing is created.
pub fn open_existing(data_dir: &Path) -> Result<Option<Library>, CliError> {
    if !samples_dir(data_dir).join(DATABASE).is_file() {
        return Ok(None);
    }
    Library::open(data_dir).map(Some).map_err(library_error)
}

/// The library of `data_dir` for a command that writes; created if absent.
pub fn open_for_write(data_dir: &Path) -> Result<Library, CliError> {
    Library::open(data_dir).map_err(library_error)
}

/// A library error text as an error object: the library has no error type, so
/// the known phrases map to `not_found` and `invalid_argument`.
pub fn library_error(message: String) -> CliError {
    let lower = message.to_ascii_lowercase();
    let code = if lower.contains("not in the library") || lower.contains("no such sample") {
        ErrorCode::NotFound
    } else if lower.contains("is not a ")
        || lower.contains("a tag is ")
        || lower.contains("larger than")
        || lower.contains("at most")
    {
        ErrorCode::InvalidArgument
    } else if lower.contains("permission denied") {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::Internal
    };
    CliError::new(code, message)
}

/// A SHA-256 as the commands take it: 64 hex digits, any case, lowercased.
pub fn parse_sha256(text: &str) -> Result<String, CliError> {
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(
            CliError::invalid(format!("{text:?} is not a SHA-256 (64 hex digits)"))
                .with_field("sha256"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_checked_and_lowercased() {
        let upper = "AB".repeat(32);
        assert_eq!(parse_sha256(&upper).unwrap(), "ab".repeat(32));
        assert_eq!(parse_sha256("abc").unwrap_err().exit.code(), 4);
        assert!(parse_sha256(&"g".repeat(64)).is_err());
    }

    #[test]
    fn library_errors_map_to_codes() {
        let code = |text: &str| library_error(text.into()).code;
        assert_eq!(
            code("this sample is not in the library"),
            ErrorCode::NotFound
        );
        assert_eq!(code("\"x\" is not a verdict"), ErrorCode::InvalidArgument);
        assert_eq!(code("disk I/O error"), ErrorCode::Internal);
    }

    #[test]
    fn a_data_directory_without_a_library_opens_nothing_and_creates_nothing() {
        let root = std::env::temp_dir().join(format!("ant-cli-lib-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        assert!(open_existing(&root).unwrap().is_none());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
