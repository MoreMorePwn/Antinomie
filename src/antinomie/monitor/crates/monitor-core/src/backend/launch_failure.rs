// SPDX-License-Identifier: GPL-3.0-only
//! Wording of a failed program launch: what is known and what is not.
use super::RequestError;
use crate::{LAUNCH_OUTCOME_UNKNOWN, RunState};

const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const ETXTBSY: i32 = 26;
const ENOEXEC: i32 = 8;
const EFAULT: i32 = 14;

/// How the text of a launch the guest rejected begins.
pub(super) const REJECTED: &str = "launch rejected by the guest, nothing was started";

/// A launch the guest answered with an error: it did not happen, and the text
/// says why as far as the error number tells. The state is the run's end:
/// failed to start for a rejection, unconfirmed when no usable answer came.
///
/// `host` is the uploaded program's copy on the host. An exec that fails with
/// "Bad address" or "Exec format error" on a cut-off ELF says so instead.
pub(super) fn launch_failure(
    error: RequestError,
    path: &str,
    cwd: &str,
    host: Option<&std::path::Path>,
) -> (RunState, String) {
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
                Some(EFAULT | ENOEXEC) => host
                    .and_then(crate::analysis::file_truncation_note)
                    .map_or_else(
                        || message.clone(),
                        |note| format!("{note} The guest could not run it ({message})"),
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
        let (state, text) = launch_failure(rejected(-2), "/tmp/x", "/work", None);
        assert_eq!(state, RunState::FailedToStart);
        assert!(text.contains("nothing was started"));
        assert!(text.contains("\"/tmp/x\"") && text.contains("\"/work\""));
        assert!(!text.contains("may be unknown"));
        let (_, busy) = launch_failure(rejected(-26), "/tmp/x", "/", None);
        assert!(busy.contains("still open for writing"));
        assert!(!busy.contains("may be unknown"));
        let (_, other) = launch_failure(rejected(-12), "/tmp/x", "/", None);
        assert!(other.contains("nothing was started") && other.contains("reason"));
    }

    #[test]
    fn a_bad_address_on_a_cut_off_elf_says_the_file_is_truncated() {
        let dir = std::env::temp_dir().join(format!("ant-launch-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 0x200 bytes on disk; the one loadable segment says 0x4000.
        let mut cut = crate::analysis::elf64_fixture(0x200, 0x4000, 0x100, false);
        cut.truncate(0x200);
        std::fs::write(dir.join("cut"), &cut).unwrap();
        std::fs::write(dir.join("whole"), vec![0u8; 16]).unwrap();
        let bad_address = || RequestError::Rejected {
            status: -14,
            message: "Bad address (os error 14)".into(),
        };
        let (state, text) = launch_failure(bad_address(), "/tmp/x", "/", Some(&dir.join("cut")));
        assert_eq!(state, RunState::FailedToStart);
        assert!(
            text.contains("This ELF is truncated: its segments need"),
            "{text}"
        );
        assert!(text.contains("get a full copy"), "{text}");
        // Not an ELF, or no host file: the guest's own words stay.
        let (_, plain) = launch_failure(bad_address(), "/tmp/x", "/", Some(&dir.join("whole")));
        assert!(plain.ends_with("Bad address (os error 14)"), "{plain}");
        let (_, none) = launch_failure(bad_address(), "/tmp/x", "/", None);
        assert!(none.ends_with("Bad address (os error 14)"), "{none}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unanswered_or_malformed_launches_stay_unknown() {
        for error in [
            RequestError::TimedOut("guest command 7 timed out".into()),
            RequestError::Failed("VM exited while waiting for command reply".into()),
        ] {
            let (state, text) = launch_failure(error, "/tmp/x", "/", None);
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
