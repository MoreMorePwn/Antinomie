// SPDX-License-Identifier: GPL-3.0-only
//! How a process core's sizes and the reason it is incomplete read in the list
//! and the details: requested, accepted, expected and saved bytes.
use antinomie_monitor_core::{
    CoreReason, ProcessCoreCapture, ProcessCorePhase, RunArtifactState, RunArtifacts,
};

/// What a run's exit core recorded about its sizes and reason.
#[derive(Clone, Default, serde::Serialize)]
pub(super) struct CoreSizes {
    pub requested: Option<u64>,
    pub accepted: Option<u64>,
    pub expected: Option<u64>,
    pub saved: Option<u64>,
    pub logical: Option<u64>,
    pub reason: Option<CoreReason>,
}

impl CoreSizes {
    pub(super) fn of(artifacts: &RunArtifacts) -> Option<Self> {
        let sizes = Self {
            requested: artifacts.core_requested_size,
            accepted: artifacts.core_accepted_size,
            expected: artifacts.core_expected_size,
            saved: artifacts.core_saved_size,
            logical: artifacts.core_logical_size,
            reason: artifacts.core_reason.clone(),
        };
        (sizes.requested.is_some() || sizes.logical.is_some() || sizes.reason.is_some())
            .then_some(sizes)
    }
}

/// "Complete · 480 MiB", "Partial · 64 MiB of 134.7 MiB · budget reached",
/// "Failed · host disk: ..." for a core whose outcome is final.
fn outcome(
    state: RunArtifactState,
    logical: Option<u64>,
    expected: Option<u64>,
    reason: Option<&CoreReason>,
) -> Option<String> {
    match state {
        RunArtifactState::Complete => Some(format!(
            "Complete · {}",
            crate::values::short_size(logical.or(expected)?)
        )),
        RunArtifactState::Partial => {
            let saved = crate::values::short_size(logical?);
            let of = expected.map_or(String::new(), |size| {
                format!(" of {}", crate::values::short_size(size))
            });
            let why = reason.map_or(String::new(), |reason| {
                format!(" · {}", reason.code.label())
            });
            Some(format!("Partial · {saved}{of}{why}"))
        }
        RunArtifactState::Failed => {
            reason.map(|reason| format!("Failed · {}: {}", reason.code.label(), reason.text))
        }
        _ => None,
    }
}

pub(super) fn acquired_status(
    state: RunArtifactState,
    sizes: Option<&CoreSizes>,
) -> Option<String> {
    let sizes = sizes?;
    outcome(state, sizes.logical, sizes.expected, sizes.reason.as_ref())
}

pub(super) fn manual_status(core: &ProcessCoreCapture) -> String {
    match core.phase {
        ProcessCorePhase::Admission => "Requesting capture".into(),
        ProcessCorePhase::UnknownAdmission => "Admission outcome unknown; checking status".into(),
        ProcessCorePhase::GuestCapture => {
            "Capturing process; waiting for resume confirmation".into()
        }
        ProcessCorePhase::Transfer => core.guest_size.map_or_else(
            || format!("Saving {}", crate::values::short_size(core.stored_size)),
            |size| {
                format!(
                    "Saving {} / {}",
                    crate::values::short_size(core.stored_size),
                    crate::values::short_size(size)
                )
            },
        ),
        ProcessCorePhase::Seal => "Finalizing retained core".into(),
        ProcessCorePhase::Finished => outcome(
            core.state,
            Some(core.stored_size),
            core.expected_size.or(core.guest_size),
            core.reason.as_ref(),
        )
        .unwrap_or_else(|| crate::app::core_capture_status(core.state).into()),
    }
}

/// The two-line "Requested ... Expected ..." block, for hover and details.
pub(super) fn details(
    requested: Option<u64>,
    accepted: Option<u64>,
    guest_max: Option<u64>,
    expected: Option<u64>,
    saved: Option<u64>,
    logical: Option<u64>,
    reason: Option<&CoreReason>,
) -> Option<String> {
    requested?;
    let mut first = vec![format!(
        "Requested {}",
        crate::values::short_size(requested?)
    )];
    if let Some(size) = accepted {
        first.push(format!("Accepted {}", crate::values::short_size(size)));
    }
    if let Some(size) = guest_max {
        first.push(format!("Guest max {}", crate::values::short_size(size)));
    }
    let mut second = Vec::new();
    if let Some(size) = expected {
        second.push(format!(
            "Expected {} (ELF)",
            crate::values::short_size(size)
        ));
    }
    match (saved, logical) {
        (Some(saved), Some(logical)) => second.push(format!(
            "Saved {} stored, {} file",
            crate::values::short_size(saved),
            crate::values::short_size(logical)
        )),
        (None, Some(logical)) => {
            second.push(format!("Saved {} file", crate::values::short_size(logical)))
        }
        _ => {}
    }
    if let Some(reason) = reason {
        second.push(reason.text.clone());
    }
    Some(format!("{}\n{}", first.join(" · "), second.join(" · ")))
}

pub(super) fn manual_details(core: &ProcessCoreCapture) -> Option<String> {
    details(
        core.requested_max_size
            .or(Some(core.max_size))
            .map(u64::from),
        Some(u64::from(core.max_size)),
        core.guest_max_size,
        core.expected_size.or(core.guest_size),
        core.allocated_size,
        (core.stored_size > 0).then_some(core.stored_size),
        core.reason.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::CoreReasonCode;

    #[test]
    fn sizes_read_in_mib() {
        assert_eq!(crate::values::short_size(64 << 20), "64.0 MiB");
        assert_eq!(crate::values::short_size(134_660_096), "128.4 MiB");
        assert_eq!(crate::values::short_size(100), "100 bytes");
    }

    #[test]
    fn a_cut_core_names_what_it_saved_and_why() {
        let reason = CoreReason::new(CoreReasonCode::Budget, Some(-27), "budget spent");
        assert_eq!(
            outcome(
                RunArtifactState::Partial,
                Some(64 << 20),
                Some(134_660_096),
                Some(&reason)
            )
            .unwrap(),
            "Partial · 64.0 MiB of 128.4 MiB · budget reached"
        );
        assert_eq!(
            outcome(RunArtifactState::Complete, Some(480 << 20), None, None).unwrap(),
            "Complete · 480.0 MiB"
        );
        let disk = CoreReason::new(
            CoreReasonCode::HostDisk,
            None,
            "needs 480 MiB, 200 MiB free",
        );
        assert_eq!(
            outcome(RunArtifactState::Failed, None, None, Some(&disk)).unwrap(),
            "Failed · host disk: needs 480 MiB, 200 MiB free"
        );
        assert!(outcome(RunArtifactState::Failed, None, None, None).is_none());
    }

    #[test]
    fn details_have_requested_accepted_expected_and_saved() {
        let text = details(
            Some(256 << 20),
            Some(256 << 20),
            Some(384 << 20),
            Some(134_660_096),
            Some(134_660_096),
            Some(134_660_096),
            None,
        )
        .unwrap();
        assert!(
            text.starts_with("Requested 256.0 MiB · Accepted 256.0 MiB · Guest max 384.0 MiB\n")
        );
        assert!(text.contains("Expected 128.4 MiB (ELF) · Saved 128.4 MiB stored, 128.4 MiB file"));
        assert!(details(None, None, None, None, None, None, None).is_none());
    }
}
