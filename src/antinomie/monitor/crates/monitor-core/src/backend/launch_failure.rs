// SPDX-License-Identifier: GPL-3.0-only
//! Wording of a failed program launch: what is known and what is not.
use super::RequestError;
use crate::{LAUNCH_OUTCOME_UNKNOWN, RunState};

const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const ETXTBSY: i32 = 26;

/// How the text of a launch the guest rejected begins.
pub(super) const REJECTED: &str = "launch rejected by the guest, nothing was started";

/// A launch the guest answered with an error: it did not happen, and the text
/// says why as far as the error number tells. The state is the run's end:
/// failed to start for a rejection, unconfirmed when no usable answer came.
pub(super) fn launch_failure(error: RequestError, path: &str, cwd: &str) -> (RunState, String) {
    match error {
        RequestError::Rejected { status, message } => {
            let cause = match status.checked_neg() {
                Some(ENOENT) => format!(
                    "{message}; the program {path:?} or the working directory {cwd:?} does not exist in the guest"
                ),
                Some(ETXTBSY) => format!(
                    "{message}; the program file is still open for writing, for example by an upload that has not finished"
                ),
                Some(EACCES) => format!(
                    "{message}; the program or a directory on its path is not accessible to the selected user"
                ),
                _ => message,
            };
            (RunState::FailedToStart, format!("{REJECTED}: {cause}"))
        }
        RequestError::TimedOut(message) | RequestError::Failed(message) => {
            (RunState::LaunchUnconfirmed, launch_unknown(&message))
        }
    }
}

/// A launch whose answer never came or could not be read: the program may be running.
pub(super) fn launch_unknown(error: &str) -> String {
    format!("execution acknowledgement failed: {error}; {LAUNCH_OUTCOME_UNKNOWN}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(status: i32) -> RequestError {
        RequestError::Rejected {
            status,
            message: "guest command 0x20: reason".into(),
        }
    }

    #[test]
    fn a_guest_rejection_is_definite_and_names_the_candidates() {
        let (state, text) = launch_failure(rejected(-2), "/tmp/x", "/work");
        assert_eq!(state, RunState::FailedToStart);
        assert!(text.contains("nothing was started"));
        assert!(text.contains("\"/tmp/x\"") && text.contains("\"/work\""));
        assert!(!text.contains("may be unknown"));
        let (_, busy) = launch_failure(rejected(-26), "/tmp/x", "/");
        assert!(busy.contains("still open for writing"));
        assert!(!busy.contains("may be unknown"));
        let (_, other) = launch_failure(rejected(-12), "/tmp/x", "/");
        assert!(other.contains("nothing was started") && other.contains("reason"));
    }

    #[test]
    fn unanswered_or_malformed_launches_stay_unknown() {
        for error in [
            RequestError::TimedOut("guest command 7 timed out".into()),
            RequestError::Failed("VM exited while waiting for command reply".into()),
        ] {
            let (state, text) = launch_failure(error, "/tmp/x", "/");
            assert_eq!(state, RunState::LaunchUnconfirmed);
            assert!(text.ends_with("launch outcome may be unknown"), "{text}");
            // A saved record of it reads the same way.
            assert_eq!(
                RunState::Unknown.settled(0, Some(&text)),
                RunState::LaunchUnconfirmed
            );
        }
        assert!(launch_unknown("invalid execution reply").contains("may be unknown"));
    }
}
