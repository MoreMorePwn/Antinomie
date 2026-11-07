// SPDX-License-Identifier: GPL-3.0-only
//! What a program's own words say about why it stopped at once: the dynamic
//! loader names the library it could not find when a program exits 127.
use crate::WaitStatus;

/// How much of the front of the terminal transcript is searched. The loader
/// speaks before the program does anything else.
pub(crate) const TRANSCRIPT_HEAD: u64 = 256 * 1024;

const MARK: &str = "error while loading shared libraries: ";
const TAIL: &str = ": cannot open shared object file";

/// The library the dynamic loader could not open, from the terminal
/// transcript's text: `error while loading shared libraries: X: cannot open
/// shared object file: No such file or directory`.
pub(crate) fn missing_library(transcript: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(transcript);
    let after = &text[text.find(MARK)? + MARK.len()..];
    let name = &after[..after.find(TAIL)?];
    // A library name is a file name: no spaces, escapes or path breaks.
    let valid = !name.is_empty()
        && name.len() <= 255
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '/'));
    valid.then(|| name.to_owned())
}

/// The note of a run whose root exited 127 and whose transcript names a
/// missing library; `None` for any other exit.
pub(crate) fn exit_127_note(exit: Option<&WaitStatus>, transcript: &[u8]) -> Option<String> {
    if !matches!(exit, Some(WaitStatus::Exited { code: 127 })) {
        return None;
    }
    let library = missing_library(transcript)?;
    Some(format!(
        "Exited 127: the library {library} is not in the guest."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOADER: &[u8] = b"$ /tmp/miner\r\n/tmp/miner: error while loading shared libraries: libhwloc.so.15: cannot open shared object file: No such file or directory\r\n$ ";

    #[test]
    fn the_loader_message_names_the_missing_library() {
        assert_eq!(missing_library(LOADER).as_deref(), Some("libhwloc.so.15"));
        assert_eq!(missing_library(b"nothing to see"), None);
        // Cut off before the library's name ends, or an odd name: nothing.
        assert_eq!(
            missing_library(b"error while loading shared libraries: libx.so.1"),
            None
        );
        assert_eq!(
            missing_library(
                b"error while loading shared libraries: bad name\x1b[0m: cannot open shared object file"
            ),
            None
        );
    }

    #[test]
    fn only_an_exit_of_127_gets_the_note() {
        let exited = |code| Some(WaitStatus::Exited { code });
        assert_eq!(
            exit_127_note(exited(127).as_ref(), LOADER).as_deref(),
            Some("Exited 127: the library libhwloc.so.15 is not in the guest.")
        );
        assert_eq!(exit_127_note(exited(1).as_ref(), LOADER), None);
        assert_eq!(exit_127_note(None, LOADER), None);
        assert_eq!(
            exit_127_note(exited(127).as_ref(), b"command not found"),
            None
        );
        let signalled = Some(WaitStatus::Signaled {
            signal: 11,
            core_dumped: false,
        });
        assert_eq!(exit_127_note(signalled.as_ref(), LOADER), None);
    }
}
