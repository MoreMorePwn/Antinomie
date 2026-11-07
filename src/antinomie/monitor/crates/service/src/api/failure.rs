// SPDX-License-Identifier: GPL-3.0-only
//! `Failure` (design 5.4.5): why a job failed or was rejected. The code table
//! is one enum; its stage and default retry hint are data on the enum.

use super::job::Stage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    SampleMissing,
    SampleTooLarge,
    SampleTypeDenied,
    SampleArchDenied,
    DuplicateDenied,
    PolicyDenied,
    QuotaExceeded,
    DependencyMissing,
    NoBase,
    NoVm,
    HostResources,
    VmStartFailed,
    GuestUnreachable,
    RevertFailed,
    LaneChanged,
    UploadFailed,
    LaunchFailed,
    GuestLost,
    RecordingFailed,
    AnalysisFailed,
    Cancelled,
    Internal,
}

/// Whether a retry could succeed without a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryHint {
    Yes,
    No,
    /// `launch_failed`.
    Depends,
    /// `internal`.
    Maybe,
}

impl FailureCode {
    pub const ALL: [Self; 22] = [
        Self::SampleMissing,
        Self::SampleTooLarge,
        Self::SampleTypeDenied,
        Self::SampleArchDenied,
        Self::DuplicateDenied,
        Self::PolicyDenied,
        Self::QuotaExceeded,
        Self::DependencyMissing,
        Self::NoBase,
        Self::NoVm,
        Self::HostResources,
        Self::VmStartFailed,
        Self::GuestUnreachable,
        Self::RevertFailed,
        Self::LaneChanged,
        Self::UploadFailed,
        Self::LaunchFailed,
        Self::GuestLost,
        Self::RecordingFailed,
        Self::AnalysisFailed,
        Self::Cancelled,
        Self::Internal,
    ];

    /// The stages this code belongs to (the table of 5.4.5). `cancelled` and
    /// `internal` belong to any stage: the slice is empty.
    pub fn stages(self) -> &'static [Stage] {
        use Stage::*;
        match self {
            Self::SampleMissing
            | Self::SampleTooLarge
            | Self::SampleTypeDenied
            | Self::SampleArchDenied
            | Self::DuplicateDenied
            | Self::QuotaExceeded
            | Self::DependencyMissing
            | Self::HostResources => &[Prechecks],
            Self::PolicyDenied => &[Prechecks, Provision],
            Self::NoBase | Self::NoVm | Self::VmStartFailed | Self::LaneChanged => &[Provision],
            Self::GuestUnreachable => &[Provision, Launch],
            Self::RevertFailed => &[Provision, Cleanup],
            Self::UploadFailed => &[Upload],
            Self::LaunchFailed => &[Launch],
            Self::GuestLost => &[Run, Collect],
            Self::RecordingFailed => &[Collect],
            Self::AnalysisFailed => &[Analyse, Report],
            Self::Cancelled | Self::Internal => &[],
        }
    }

    pub fn retry_hint(self) -> RetryHint {
        match self {
            Self::QuotaExceeded
            | Self::DependencyMissing
            | Self::HostResources
            | Self::VmStartFailed
            | Self::GuestUnreachable
            | Self::UploadFailed
            | Self::GuestLost
            | Self::RecordingFailed
            | Self::AnalysisFailed => RetryHint::Yes,
            Self::LaunchFailed => RetryHint::Depends,
            Self::Internal => RetryHint::Maybe,
            Self::SampleMissing
            | Self::SampleTooLarge
            | Self::SampleTypeDenied
            | Self::SampleArchDenied
            | Self::DuplicateDenied
            | Self::PolicyDenied
            | Self::NoBase
            | Self::NoVm
            | Self::RevertFailed
            | Self::LaneChanged
            | Self::Cancelled => RetryHint::No,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Failure {
    pub code: FailureCode,
    /// One sentence for people.
    pub message: String,
    /// The stage that failed.
    pub stage: Stage,
    pub retryable: bool,
    /// The engine's own error text, truncated to 2 KiB, host paths removed for
    /// remote callers.
    pub detail: Option<String>,
}

/// The longest `Failure.detail`, in bytes.
pub const MAX_DETAIL_BYTES: usize = 2048;

impl Failure {
    /// A failure whose `retryable` follows the code's hint (`Depends` and
    /// `Maybe` default to false) and whose detail is cut to 2 KiB on a
    /// character boundary.
    pub fn new(code: FailureCode, stage: Stage, message: &str, detail: Option<&str>) -> Self {
        Self {
            code,
            message: message.to_owned(),
            stage,
            retryable: code.retry_hint() == RetryHint::Yes,
            detail: detail.map(|text| {
                let mut end = text.len().min(MAX_DETAIL_BYTES);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text[..end].to_owned()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_distinct_wire_name() {
        let names: std::collections::BTreeSet<_> = FailureCode::ALL
            .iter()
            .map(|code| {
                serde_json::to_value(code)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(names.len(), 22);
        assert!(names.contains("sample_arch_denied") && names.contains("no_base"));
    }

    #[test]
    fn detail_is_cut_on_a_character_boundary() {
        let text = "é".repeat(2000);
        let failure = Failure::new(FailureCode::UploadFailed, Stage::Upload, "x", Some(&text));
        assert!(failure.detail.unwrap().len() <= MAX_DETAIL_BYTES);
        assert!(failure.retryable);
    }
}
