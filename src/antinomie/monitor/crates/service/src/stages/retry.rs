// SPDX-License-Identifier: GPL-3.0-only
//! Which failures a job retries, and after how long (design 4.7.2).
//!
//! A failure is retried when all of these hold:
//!
//! 1. its code is in the preset's `retry_on` (default `vm_start_failed`,
//!    `guest_unreachable`, `upload_failed`, `guest_lost`);
//! 2. its code is not **permanent**. Some errors cannot be cured by running
//!    the same job again, and the preset cannot make them retryable: a bad
//!    sample or preset, a missing base or VM, a revert that failed (the lane
//!    is quarantined instead), a changed lane, a cancel, a desktop run with a
//!    core dump. `launch_failed` is permanent unless the engine's words name a
//!    transient cause (terminal capacity);
//! 3. `guest_lost` and `recording_failed` happen at most once per job: a
//!    sample that kills the guest twice is final, and the job says so;
//! 4. the job has an attempt left (the store decides: `max_attempts`).
//!
//! The wait before the next attempt is the preset's `backoff_s` list (the
//! first entry after the first failure, the last entry for every later one),
//! plus or minus 20 percent. The jitter comes from the job id and the attempt,
//! so it is spread across jobs and repeatable in a test.
use crate::{
    api::{failure::Failure, failure::FailureCode, ids::JobId},
    config::preset::Retry,
};
use std::hash::{Hash, Hasher};

/// Why a failure is final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalReason {
    /// The preset does not list the code.
    NotListed,
    /// Running the same job again cannot help.
    Permanent,
    /// The same code already ended an earlier attempt and it is allowed once.
    Repeated,
}

impl FinalReason {
    pub fn text(self) -> &'static str {
        match self {
            Self::NotListed => "the policy does not retry this failure",
            Self::Permanent => "this failure cannot be cured by running the job again",
            Self::Repeated => "the same failure happened in an earlier attempt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Put the job back in the queue; wait this long first.
    Retry {
        backoff_s: u32,
    },
    Final(FinalReason),
}

/// Codes no preset can make retryable.
fn permanent(code: FailureCode) -> bool {
    matches!(
        code,
        FailureCode::SampleMissing
            | FailureCode::SampleTooLarge
            | FailureCode::SampleTypeDenied
            | FailureCode::SampleArchDenied
            | FailureCode::DuplicateDenied
            | FailureCode::PermissionDenied
            | FailureCode::PresetDenied
            | FailureCode::LimitExceeded
            | FailureCode::UnavailableOnNode
            | FailureCode::NoBase
            | FailureCode::NoVm
            | FailureCode::RevertFailed
            | FailureCode::LaneChanged
            | FailureCode::Cancelled
            // Waits, not attempts (4.7.2); the stage returns `Wait` for them.
            | FailureCode::QuotaExceeded
            | FailureCode::DependencyMissing
            | FailureCode::HostResources
    )
}

/// Codes that happen at most once per job.
fn once(code: FailureCode) -> bool {
    matches!(code, FailureCode::GuestLost | FailureCode::RecordingFailed)
}

/// Does the engine's text name a cause that goes away by itself? The only one
/// the design names is the terminal capacity.
pub fn transient_launch(failure: &Failure) -> bool {
    let text = format!(
        "{} {}",
        failure.message,
        failure.detail.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    ["capacity", "too many terminals", "terminal limit"]
        .iter()
        .any(|needle| text.contains(needle))
}

/// `history` is the codes of the job's earlier failed attempts, oldest first.
pub fn decide(failure: &Failure, policy: &Retry, history: &[FailureCode], job: &JobId) -> Decision {
    let code = failure.code;
    if permanent(code) {
        return Decision::Final(FinalReason::Permanent);
    }
    if !policy.retry_on.contains(&code) {
        return Decision::Final(FinalReason::NotListed);
    }
    if code == FailureCode::LaunchFailed && !transient_launch(failure) {
        return Decision::Final(FinalReason::Permanent);
    }
    if once(code) && history.contains(&code) {
        return Decision::Final(FinalReason::Repeated);
    }
    Decision::Retry {
        backoff_s: backoff(policy, history.len() + 1, job),
    }
}

/// The wait before the next attempt after the `failures`-th failure.
pub fn backoff(policy: &Retry, failures: usize, job: &JobId) -> u32 {
    let Some(last) = policy.backoff_s.len().checked_sub(1) else {
        return 0;
    };
    let base = policy.backoff_s[(failures - 1).min(last)];
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (job.as_str(), failures).hash(&mut hasher);
    // 0..=40 percent, centred on zero.
    let jitter = i64::try_from(hasher.finish() % 41).unwrap_or(0) - 20;
    let value = i64::from(base) * (100 + jitter) / 100;
    u32::try_from(value.max(0)).unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::job::Stage;

    fn failure(code: FailureCode) -> Failure {
        Failure::new(code, Stage::Run, "x", None)
    }

    fn job() -> JobId {
        JobId::from_parts(1, [0; 10])
    }

    #[test]
    fn listed_transient_codes_are_retried_with_the_first_backoff() {
        let policy = Retry::default();
        for code in [
            FailureCode::VmStartFailed,
            FailureCode::GuestUnreachable,
            FailureCode::UploadFailed,
            FailureCode::GuestLost,
        ] {
            match decide(&failure(code), &policy, &[], &job()) {
                Decision::Retry { backoff_s } => {
                    assert!(
                        (24..=36).contains(&backoff_s),
                        "30 s plus or minus 20 percent: {backoff_s}"
                    );
                }
                other => panic!("{code:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_code_the_policy_does_not_list_is_final() {
        let policy = Retry::default();
        assert_eq!(
            decide(&failure(FailureCode::RecordingFailed), &policy, &[], &job()),
            Decision::Final(FinalReason::NotListed)
        );
        assert_eq!(
            decide(&failure(FailureCode::Internal), &policy, &[], &job()),
            Decision::Final(FinalReason::NotListed)
        );
    }

    #[test]
    fn permanent_codes_stay_final_even_when_the_policy_lists_them() {
        let policy = Retry {
            retry_on: FailureCode::ALL.to_vec(),
            ..Retry::default()
        };
        for code in [
            FailureCode::SampleMissing,
            FailureCode::SampleTypeDenied,
            FailureCode::PermissionDenied,
            FailureCode::PresetDenied,
            FailureCode::LimitExceeded,
            FailureCode::UnavailableOnNode,
            FailureCode::NoBase,
            FailureCode::NoVm,
            FailureCode::RevertFailed,
            FailureCode::LaneChanged,
            FailureCode::Cancelled,
            FailureCode::DependencyMissing,
        ] {
            assert_eq!(
                decide(&failure(code), &policy, &[], &job()),
                Decision::Final(FinalReason::Permanent),
                "{code:?}"
            );
        }
    }

    #[test]
    fn launch_failed_is_retried_only_for_a_transient_cause() {
        let mut policy = Retry::default();
        policy.retry_on.push(FailureCode::LaunchFailed);
        let refused = Failure::new(
            FailureCode::LaunchFailed,
            Stage::Launch,
            "the launch request is refused",
            Some("a core dump needs run_in app_terminal"),
        );
        assert_eq!(
            decide(&refused, &policy, &[], &job()),
            Decision::Final(FinalReason::Permanent)
        );
        let busy = Failure::new(
            FailureCode::LaunchFailed,
            Stage::Launch,
            "the guest refused to start the program",
            Some("terminal capacity reached"),
        );
        assert!(matches!(
            decide(&busy, &policy, &[], &job()),
            Decision::Retry { .. }
        ));
        // Not listed: final whatever the text says.
        assert_eq!(
            decide(&busy, &Retry::default(), &[], &job()),
            Decision::Final(FinalReason::NotListed)
        );
    }

    #[test]
    fn guest_lost_and_recording_failed_are_allowed_once() {
        let mut policy = Retry::default();
        policy.retry_on.push(FailureCode::RecordingFailed);
        for code in [FailureCode::GuestLost, FailureCode::RecordingFailed] {
            assert!(matches!(
                decide(&failure(code), &policy, &[], &job()),
                Decision::Retry { .. }
            ));
            assert_eq!(
                decide(&failure(code), &policy, &[code], &job()),
                Decision::Final(FinalReason::Repeated)
            );
        }
        // Another earlier code does not count.
        assert!(matches!(
            decide(
                &failure(FailureCode::GuestLost),
                &policy,
                &[FailureCode::UploadFailed],
                &job()
            ),
            Decision::Retry { .. }
        ));
    }

    #[test]
    fn the_backoff_list_is_walked_then_its_last_entry_repeats() {
        let policy = Retry {
            max_attempts: 5,
            backoff_s: vec![30, 120],
            retry_on: vec![],
        };
        let j = job();
        assert!((24..=36).contains(&backoff(&policy, 1, &j)));
        assert!((96..=144).contains(&backoff(&policy, 2, &j)));
        assert!((96..=144).contains(&backoff(&policy, 9, &j)));
        let none = Retry {
            backoff_s: vec![],
            ..policy
        };
        assert_eq!(backoff(&none, 1, &j), 0);
    }

    #[test]
    fn the_jitter_is_spread_over_jobs_and_repeatable() {
        let policy = Retry {
            max_attempts: 3,
            backoff_s: vec![1000],
            retry_on: vec![],
        };
        let mut seen = std::collections::BTreeSet::new();
        for n in 0..40u8 {
            let id = JobId::from_parts(u64::from(n), [n; 10]);
            let a = backoff(&policy, 1, &id);
            assert_eq!(a, backoff(&policy, 1, &id));
            assert!((800..=1200).contains(&a));
            seen.insert(a);
        }
        assert!(seen.len() > 10, "{seen:?}");
    }
}
