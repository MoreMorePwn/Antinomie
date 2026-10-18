// SPDX-License-Identifier: MIT
//! What it means that the recording quota is reached.
//!
//! The quota bounds what one VM boot may save: raw telemetry, assembled
//! objects, terminal journals, screens and artifacts. Reaching it is a
//! boot-wide, permanent condition (the limit is read when the VM starts), but
//! it is not a failure of the data already saved: archives of programs that
//! have ended and captures that are closed stay as they are, and only
//! recordings still open stop growing. The cause is one message, the same in
//! every place that reports it.
use crate::byte_size::file_size;

/// The text every recording reports once the quota is reached.
pub(crate) fn message(quota_size: u64) -> String {
    format!(
        "recording quota of {} reached: new telemetry, objects and terminal output are no longer saved \
         for this VM boot; everything saved before is intact. Raise the quota in Settings and restart the VM to record more",
        file_size(quota_size)
    )
}

/// True for a refusal that comes from the quota (or the disk's own quota).
pub(crate) fn is_quota_error(error: &str) -> bool {
    error.contains("quota")
}

/// The quota state of one VM boot.
#[derive(Default)]
pub(crate) struct QuotaState {
    /// Set when the quota was reached; the text reported to the frontend.
    pub reached: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_names_the_limit_and_the_kept_data() {
        let text = message(4 * 1024 * 1024 * 1024);
        assert!(text.contains("4294967296 bytes (4.0 GB)"));
        assert!(text.contains("everything saved before is intact"));
        assert!(is_quota_error(&text));
    }

    #[test]
    fn only_quota_refusals_are_quota_errors() {
        for error in [
            "host object quota exhausted; saving stopped",
            "capture quota exhausted; terminal saving stopped",
            "Disk quota exceeded (os error 122)",
        ] {
            assert!(is_quota_error(error));
        }
        assert!(!is_quota_error("No space left on device (os error 28)"));
        assert!(!is_quota_error("capture write failed: input/output error"));
    }
}
