// SPDX-License-Identifier: GPL-3.0-only
//! Looking up the earlier bytes of the files a run changed on the run's
//! starting disk (see `antinomie_monitor_core::file_before`). Only the files
//! the run wrote to or changed are asked, up to a bound; each answer is a
//! small sandboxed read of the disk's inode and size, and the bytes
//! themselves are read later, on demand.
use super::{Activity, Earlier};
use antinomie_monitor_core::file_before::{Before, Resolver, Wanted};
use std::path::PathBuf;

/// Files asked at most per run; the rest show "not looked up".
pub(in crate::triage) const LOOKUP_LIMIT: usize = 300;

/// Ask the starting disk about the changed files of `activity`. `segments`
/// are the run's recording folders, oldest first; `executable` serves the
/// disk reader (`None`: this program).
pub(in crate::triage) fn resolve(
    activity: &mut Activity,
    segments: &[(PathBuf, String)],
    executable: Option<PathBuf>,
) {
    let mut resolver = Resolver::new(segments, executable);
    let mut asked = 0;
    for file in &mut activity.files {
        let wrote = file.writes.tally.kept + file.writes.tally.skipped() > 0;
        if !(wrote || file.changed()) || file.failed_only {
            continue;
        }
        if asked >= LOOKUP_LIMIT {
            file.earlier = Some(Earlier {
                before: Before::Unavailable(format!(
                    "not looked up: only the first {LOOKUP_LIMIT} changed files are"
                )),
                file: None,
            });
            continue;
        }
        asked += 1;
        let (before, source) = resolver.resolve(&Wanted {
            path: &file.path,
            names: &file.names,
            key: file.identity,
            created: file.created,
            first_segment: file.first_segment,
            last_segment: file.last_segment,
        });
        file.earlier = Some(Earlier {
            before,
            file: source,
        });
    }
}

/// One line for the window: where the file's earlier bytes stand.
pub(super) fn describe(earlier: &Earlier) -> String {
    use antinomie_monitor_core::byte_size::file_size;
    match &earlier.before {
        Before::Created => {
            "Earlier bytes: none, the run created this file (it started empty)".into()
        }
        Before::OnDisk { size, exact } => format!(
            "Earlier bytes: {} on the starting disk, read when asked{}",
            file_size(*size),
            if *exact {
                " (the file's inode was checked against the disk)"
            } else {
                " (matched by path only: the guest recorded no inode)"
            }
        ),
        Before::TooLarge(size) => format!(
            "Earlier bytes: not offered, the file was {} on the starting disk (limit {})",
            file_size(*size),
            file_size(antinomie_monitor_core::file_before::SIZE_CAP)
        ),
        Before::Elsewhere(why) => format!("Earlier bytes: not on the starting disk: {why}"),
        Before::Unavailable(why) => format!("Earlier bytes: unavailable: {why}"),
    }
}
