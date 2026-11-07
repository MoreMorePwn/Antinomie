// SPDX-License-Identifier: GPL-3.0-only
//! The mapping of the engine's read errors to `ApiError` (design 5.12.8).
//! Host paths are removed from every text that leaves.

use super::{pool::cancelled, scrub::Scrub};
use crate::api::error::{ApiError, ErrorCode};
use antinomie_monitor_core::recording::RecordingError;

/// An engine read error as the API's. The engine says "archive read
/// cancelled" when the cancel flag stopped it; the pool turns that into
/// `read_timeout` when the deadline set the flag.
pub fn recording_error(error: &RecordingError, scrub: &Scrub) -> ApiError {
    match error {
        RecordingError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            ApiError::not_found("recording file")
        }
        RecordingError::Limit(text) if text.contains("cancelled") => cancelled(),
        RecordingError::Limit(text) if text.starts_with("cursor beyond") => ApiError::new(
            ErrorCode::Conflict,
            "the recording changed; restart from the first page",
        )
        .with_reason(crate::api::error::ErrorReason::CursorStale),
        RecordingError::MissingRange => ApiError::invalid_argument(
            "offset",
            "the range includes bytes the recording did not capture",
        ),
        other => ApiError::recording_unreadable(&scrub.text(&other.to_string())),
    }
}

/// An engine error that is plain text (analysis, library, packet filter).
pub fn text_error(text: &str, scrub: &Scrub) -> ApiError {
    if text.contains("cancelled") {
        return cancelled();
    }
    ApiError::recording_unreadable(&scrub.text(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::error::ErrorReason;
    use std::path::Path;

    #[test]
    fn the_engines_errors_map_to_the_contracts() {
        let scrub = Scrub::new(Path::new("/srv/ant"), &[]);
        let missing = RecordingError::Io(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(recording_error(&missing, &scrub).code, ErrorCode::NotFound);
        let stopped = RecordingError::Limit("archive read cancelled");
        assert_eq!(
            recording_error(&stopped, &scrub).code,
            ErrorCode::Unavailable
        );
        let beyond = RecordingError::Limit("cursor beyond raw archive");
        assert_eq!(
            recording_error(&beyond, &scrub).reason(),
            Some(ErrorReason::CursorStale)
        );
        let broken = RecordingError::Limit("invalid raw packet length at /srv/ant/vm/x");
        let error = recording_error(&broken, &scrub);
        assert_eq!(error.reason(), Some(ErrorReason::RecordingUnreadable));
        assert!(!error.message.contains("/srv/ant"), "{}", error.message);
        assert_eq!(
            recording_error(&RecordingError::MissingRange, &scrub).code,
            ErrorCode::InvalidArgument
        );
    }
}
