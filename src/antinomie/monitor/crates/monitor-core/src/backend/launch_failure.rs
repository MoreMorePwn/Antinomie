// SPDX-License-Identifier: GPL-3.0-only
//! Wording of a failed program launch: what is known and what is not.
use super::RequestError;
use crate::analysis::HostHead;
use crate::{LAUNCH_OUTCOME_UNKNOWN, RunState};

const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const ETXTBSY: i32 = 26;
const ENOEXEC: i32 = 8;
const EFAULT: i32 = 14;

/// How the text of a launch the guest rejected begins.
pub(super) const REJECTED: &str = crate::LAUNCH_REJECTED;

/// A launch the guest answered with an error: it did not happen, and the text
/// says why as far as the error number tells. The state is the run's end:
/// failed to start for a rejection, unconfirmed when no usable answer came.
///
/// `host` is the front of the program's copy on the host, and `guest` the
/// VM's architecture. The host reads the ELF headers to say what the guest's
/// error number cannot: a missing interpreter (the guest reports it as a
/// missing program), an old-ABI or wrong-architecture program, a cut-off file.
/// The guest's own text is kept.
pub(super) fn launch_failure(
    error: RequestError,
    path: &str,
    cwd: &str,
    host: Option<&HostHead>,
    guest: Option<crate::api::GuestArch>,
) -> (RunState, String) {
    match error {
        RequestError::Rejected { status, message } => {
            let errno = status.checked_neg();
            let notes = host.map(|head| head.launch_notes(guest));
            let explain = |interpreter: bool| {
                let sentences = notes.as_ref()?.sentences(interpreter);
                (!sentences.is_empty()).then(|| sentences.join(" "))
            };
            let cause = match errno {
                Some(ENOENT) => explain(true).map_or_else(
                    || {
                        format!(
                            "{message}; the program {path:?} or the working directory {cwd:?} does not exist in the guest"
                        )
                    },
                    |note| format!("{note} {HOST_SAYS} The guest said: {message}"),
                ),
                Some(ETXTBSY) => format!(
                    "{message}; the program file is still open for writing, for example by an upload that has not finished"
                ),
                Some(EACCES) => format!(
                    "{message}; the program or a directory on its path is not accessible to the selected user"
                ),
                Some(EFAULT | ENOEXEC) => explain(false).map_or_else(
                    || message.clone(),
                    |note| format!("{note} {HOST_SAYS} The guest said: {message}"),
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

/// Where the text of a refused launch names the run record it left, after
/// the run's id: "... [run record: 5f32...]".
const RECORD_MARK: &str = " [run record: ";

/// `text` naming the run record a refused launch left in Run History.
pub(super) fn with_run_record(text: &str, run_id: &str) -> String {
    format!("{text}{RECORD_MARK}{run_id}]")
}

/// A refused launch's text split into what the guest and host said and the
/// id of the run record it names, if it names one.
pub fn split_run_record(text: &str) -> (&str, Option<&str>) {
    match text.rsplit_once(RECORD_MARK) {
        Some((said, rest)) => match rest.strip_suffix(']') {
            Some(id) if !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()) => {
                (said, Some(id))
            }
            _ => (text, None),
        },
        None => (text, None),
    }
}

/// Said after a host-made explanation, so it is not taken for the guest's.
const HOST_SAYS: &str = "(Identified on the host from the program's ELF headers.)";

/// A launch whose answer never came or could not be read: the program may be running.
pub(super) fn launch_unknown(error: &str) -> String {
    format!("execution acknowledgement failed: {error}; {LAUNCH_OUTCOME_UNKNOWN}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::GuestArch;

    fn rejected(status: i32) -> RequestError {
        RequestError::Rejected {
            status,
            message: "guest command 0x20: reason".into(),
        }
    }

    fn rejected_text(status: i32, message: &str) -> RequestError {
        RequestError::Rejected {
            status,
            message: message.into(),
        }
    }

    /// A small 32-bit little-endian ELF: `machine`, `flags`, an optional
    /// interpreter, one PT_LOAD of `load` bytes, `len` bytes on disk.
    fn elf32(machine: u16, flags: u32, interp: Option<&str>, load: u32, len: usize) -> Vec<u8> {
        let mut f = vec![0u8; len.max(0x200)];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 1;
        f[5] = 1;
        f[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        f[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
        f[0x18..0x1c].copy_from_slice(&0x10100u32.to_le_bytes());
        f[0x1c..0x20].copy_from_slice(&52u32.to_le_bytes());
        f[0x24..0x28].copy_from_slice(&flags.to_le_bytes());
        f[0x2a..0x2c].copy_from_slice(&32u16.to_le_bytes());
        let count: u16 = if interp.is_some() { 2 } else { 1 };
        f[0x2c..0x2e].copy_from_slice(&count.to_le_bytes());
        let mut at = 52;
        let mut put = |f: &mut Vec<u8>, kind: u32, offset: u32, filesz: u32| {
            f[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            f[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
            f[at + 8..at + 12].copy_from_slice(&(0x10000 + offset).to_le_bytes());
            f[at + 16..at + 20].copy_from_slice(&filesz.to_le_bytes());
            at += 32;
        };
        if let Some(path) = interp {
            put(&mut f, 3, 0x180, path.len() as u32 + 1);
            f[0x180..0x180 + path.len()].copy_from_slice(path.as_bytes());
        }
        put(&mut f, 1, 0, load);
        f.truncate(len.max(0x200));
        f
    }

    const EABI5: u32 = 0x0500_0400;
    const HF_LOADER: &str = "/lib/ld-linux-armhf.so.3";

    fn fail(status: i32, bytes: &[u8], guest: GuestArch) -> String {
        let head = HostHead::of_bytes(bytes);
        launch_failure(
            rejected_text(status, "guest said this"),
            "/tmp/x",
            "/",
            Some(&head),
            Some(guest),
        )
        .1
    }

    #[test]
    fn a_guest_rejection_is_definite_and_names_the_candidates() {
        let (state, text) = launch_failure(rejected(-2), "/tmp/x", "/work", None, None);
        assert_eq!(state, RunState::FailedToStart);
        assert!(text.contains("nothing was started"));
        assert!(text.contains("\"/tmp/x\"") && text.contains("\"/work\""));
        assert!(!text.contains("may be unknown"));
        let (_, busy) = launch_failure(rejected(-26), "/tmp/x", "/", None, None);
        assert!(busy.contains("still open for writing"));
        assert!(!busy.contains("may be unknown"));
        let (_, other) = launch_failure(rejected(-12), "/tmp/x", "/", None, None);
        assert!(other.contains("nothing was started") && other.contains("reason"));
    }

    #[test]
    fn a_run_record_is_named_and_split_back_out() {
        let text = with_run_record("launch rejected: x", "5f32ab");
        assert!(text.ends_with("[run record: 5f32ab]"), "{text}");
        assert_eq!(
            split_run_record(&text),
            ("launch rejected: x", Some("5f32ab"))
        );
        assert_eq!(split_run_record("plain text"), ("plain text", None));
        assert_eq!(
            split_run_record("a [run record: no good]"),
            ("a [run record: no good]", None)
        );
    }

    #[test]
    fn a_static_arm32_program_gets_no_host_explanation() {
        // Nothing stands out: the guest's own words (and the old candidates) stay.
        let hello = elf32(40, EABI5, None, 0x200, 0x200);
        let text = fail(-2, &hello, GuestArch::AARCH64);
        assert!(text.contains("does not exist in the guest"), "{text}");
        assert!(!text.contains("Identified on the host"), "{text}");
    }

    #[test]
    fn a_missing_interpreter_is_named_not_reported_as_a_missing_program() {
        let hf = elf32(40, EABI5, Some(HF_LOADER), 0x200, 0x200);
        let text = fail(-2, &hf, GuestArch::AARCH64);
        assert!(text.contains(HF_LOADER), "{text}");
        assert!(text.contains("not in this guest's base"), "{text}");
        assert!(text.contains("Identified on the host"), "{text}");
        assert!(text.contains("The guest said: guest said this"), "{text}");
        assert!(!text.contains("does not exist"), "{text}");
    }

    #[test]
    fn an_old_abi_arm_program_is_named_on_arm64_and_only_there() {
        let oabi = elf32(40, 0, None, 0x200, 0x200);
        let text = fail(-8, &oabi, GuestArch::AARCH64);
        assert!(text.contains("old-ABI ARM (EABI0/OABI)"), "{text}");
        assert!(text.contains("arm64 kernel cannot run"), "{text}");
        assert!(text.contains("The guest said: guest said this"), "{text}");
        // An EABI5 program of the same shape is not blamed on the ABI.
        let eabi5 = elf32(40, EABI5, None, 0x200, 0x200);
        assert!(!fail(-8, &eabi5, GuestArch::AARCH64).contains("old-ABI"));
        assert!(!fail(-8, &oabi, GuestArch::X86_64).contains("old-ABI"));
    }

    #[test]
    fn a_truncated_arm_program_says_so_and_the_guest_errno_stays() {
        // 0x200 bytes on disk; the one loadable segment says 0x4000.
        let cut = elf32(40, EABI5, None, 0x4000, 0x200);
        let text = fail(-14, &cut, GuestArch::AARCH64);
        assert!(
            text.contains("This ELF is truncated: its segments need"),
            "{text}"
        );
        assert!(text.contains("get a full copy"), "{text}");
        assert!(
            text.contains("Bad address") || text.contains("guest said this"),
            "{text}"
        );
    }

    #[test]
    fn a_program_for_another_architecture_is_named() {
        let mips = elf32(8, 0, None, 0x200, 0x200);
        let text = fail(-8, &mips, GuestArch::AARCH64);
        assert!(text.contains("wrong architecture for this VM"), "{text}");
        assert!(text.contains("MIPS") && text.contains("AArch64"), "{text}");
        // x86 on the x86 guest is unchanged: the plain guest text.
        let x86 = crate::analysis::elf64_fixture(0x200, 0x200, 0x100, false);
        let (_, plain) = launch_failure(
            rejected_text(-14, "Bad address (os error 14)"),
            "/tmp/x",
            "/",
            Some(&HostHead::of_bytes(&x86)),
            Some(GuestArch::X86_64),
        );
        assert!(plain.ends_with("Bad address (os error 14)"), "{plain}");
        // A 32-bit ARM program on arm64 is not a wrong architecture.
        let arm = elf32(40, EABI5, None, 0x200, 0x200);
        assert!(!fail(-8, &arm, GuestArch::AARCH64).contains("wrong architecture"));
    }

    #[test]
    fn a_bad_address_on_a_cut_off_x86_elf_says_the_file_is_truncated() {
        let dir = std::env::temp_dir().join(format!("ant-launch-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cut = crate::analysis::elf64_fixture(0x200, 0x4000, 0x100, false);
        cut.truncate(0x200);
        std::fs::write(dir.join("cut"), &cut).unwrap();
        std::fs::write(dir.join("whole"), vec![0u8; 16]).unwrap();
        let bad_address = || rejected_text(-14, "Bad address (os error 14)");
        let cut_head = HostHead::of_file(&dir.join("cut"));
        let (state, text) = launch_failure(
            bad_address(),
            "/tmp/x",
            "/",
            cut_head.as_ref(),
            Some(GuestArch::X86_64),
        );
        assert_eq!(state, RunState::FailedToStart);
        assert!(
            text.contains("This ELF is truncated: its segments need"),
            "{text}"
        );
        // Not an ELF, or no host file: the guest's own words stay.
        let whole = HostHead::of_file(&dir.join("whole"));
        let (_, plain) = launch_failure(bad_address(), "/tmp/x", "/", whole.as_ref(), None);
        assert!(plain.ends_with("Bad address (os error 14)"), "{plain}");
        let (_, none) = launch_failure(bad_address(), "/tmp/x", "/", None, None);
        assert!(none.ends_with("Bad address (os error 14)"), "{none}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unanswered_or_malformed_launches_stay_unknown() {
        for error in [
            RequestError::TimedOut("guest command 7 timed out".into()),
            RequestError::Failed("VM exited while waiting for command reply".into()),
        ] {
            let (state, text) = launch_failure(error, "/tmp/x", "/", None, None);
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
