// SPDX-License-Identifier: GPL-3.0-only
//! `Failure` (design 5.4.5): why a run failed or was rejected. The code table
//! is one enum; its stage and default retry hint are data on the enum.

use super::run::Stage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    SampleMissing,
    SampleTooLarge,
    SampleTypeDenied,
    SampleArchDenied,
    DuplicateDenied,
    PermissionDenied,
    PresetDenied,
    LimitExceeded,
    UnavailableOnNode,
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
    // The run's host stages passed their deadline (ANT-T0471): the running
    // items were stopped (`timed_out`), the queued ones never started. (A
    // plain comment: a doc comment would make the schema's enum a `oneOf`.)
    DeadlineExceeded,
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
    pub const ALL: [Self; 26] = [
        Self::SampleMissing,
        Self::SampleTooLarge,
        Self::SampleTypeDenied,
        Self::SampleArchDenied,
        Self::DuplicateDenied,
        Self::PermissionDenied,
        Self::PresetDenied,
        Self::LimitExceeded,
        Self::UnavailableOnNode,
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
        Self::DeadlineExceeded,
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
            | Self::PermissionDenied
            | Self::LimitExceeded
            | Self::UnavailableOnNode
            | Self::QuotaExceeded
            | Self::DependencyMissing
            | Self::HostResources => &[Prechecks],
            Self::PresetDenied => &[Prechecks, Provision],
            Self::NoBase | Self::NoVm | Self::VmStartFailed | Self::LaneChanged => &[Provision],
            Self::GuestUnreachable => &[Provision, Launch],
            Self::RevertFailed => &[Provision, Cleanup],
            Self::UploadFailed => &[Upload],
            Self::LaunchFailed => &[Launch],
            Self::GuestLost => &[Run, Collect],
            Self::RecordingFailed => &[Collect],
            Self::AnalysisFailed | Self::DeadlineExceeded => &[Analyse, Report],
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
            Self::Internal | Self::DeadlineExceeded => RetryHint::Maybe,
            Self::SampleMissing
            | Self::SampleTooLarge
            | Self::SampleTypeDenied
            | Self::SampleArchDenied
            | Self::DuplicateDenied
            | Self::PermissionDenied
            | Self::PresetDenied
            | Self::LimitExceeded
            | Self::UnavailableOnNode
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
    /// The request field to blame, for a refusal (`overrides.route`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// What a refusal names: `needs` (the permissions, for
    /// `permission_denied`), `preset`, `limit`, `what` (for
    /// `unavailable_on_node`).
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub details: Map<String, Value>,
    /// The engine's own error text, truncated to 2 KiB, host paths removed for
    /// remote callers.
    pub detail: Option<String>,
    /// The run record a failed launch left (Run History lists it as "Failed to
    /// start"); `None` when the failure is not a launch, or when the launch
    /// kept no record (nothing was captured).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
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
            field: None,
            details: Map::new(),
            detail: detail.map(|text| {
                let mut end = text.len().min(MAX_DETAIL_BYTES);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text[..end].to_owned()
            }),
            run_id: None,
        }
    }

    /// The same failure naming the run record it left.
    pub fn with_run(mut self, run_id: &str) -> Self {
        self.run_id = Some(run_id.to_owned());
        self
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
        assert_eq!(names.len(), FailureCode::ALL.len());
        assert!(names.contains("sample_arch_denied") && names.contains("no_base"));
        for name in [
            "permission_denied",
            "preset_denied",
            "limit_exceeded",
            "unavailable_on_node",
        ] {
            assert!(names.contains(name), "{name}");
        }
        assert!(!names.contains("policy_denied"));
    }

    #[test]
    fn detail_is_cut_on_a_character_boundary() {
        let text = "é".repeat(2000);
        let failure = Failure::new(FailureCode::UploadFailed, Stage::Upload, "x", Some(&text));
        assert!(failure.detail.unwrap().len() <= MAX_DETAIL_BYTES);
        assert!(failure.retryable);
    }
}
