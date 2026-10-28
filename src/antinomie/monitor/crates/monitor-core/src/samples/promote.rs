// SPDX-License-Identifier: GPL-3.0-only
//! Promoting a file a run left in a VM into the library. The only bytes read
//! are bytes that already exist: today that is a disk dump saved for the run
//! (read with the sandboxed disk reader, nothing is mounted or run). When the
//! run has no readable dump the file cannot be promoted and the dialog says so.
use super::MAX_SAMPLE;
use std::path::Path;

/// The disk dump a run's file can be read from, when there is one.
pub fn dump_label(run_directory: &Path) -> Option<String> {
    let dump = crate::ioc::disk::newest_dump(run_directory)?;
    Some(if dump.vm_name.is_empty() {
        dump.id
    } else {
        format!("{} ({})", dump.id, dump.vm_name)
    })
}

/// The file at `guest_path` in the newest readable disk dump of the run.
/// `run_directory` is the run's folder; the dump is found in its recording.
pub fn extract_from_dump(run_directory: &Path, guest_path: &str) -> Result<Vec<u8>, String> {
    extract_with(
        &crate::analysis::jobs::worker_executable()?,
        run_directory,
        guest_path,
    )
}

/// [`extract_from_dump`] with an explicit disk-reader program (the app's own
/// binary; tests that are not the app name it).
pub fn extract_with(
    executable: &Path,
    run_directory: &Path,
    guest_path: &str,
) -> Result<Vec<u8>, String> {
    use crate::disks::reader::{DiskAnswer, DiskRequest, ReadError, Reader};
    let dump = crate::ioc::disk::newest_dump(run_directory)
        .ok_or_else(|| "this run has no disk dump that can be read".to_owned())?;
    let scratch = crate::ioc::disk::scratch(run_directory)?;
    let result = (|| {
        let mut reader = Reader::with_executable(executable.to_path_buf(), &dump.path(), &scratch)?;
        match reader.request(DiskRequest::Extract {
            path: guest_path.to_owned(),
            max_len: MAX_SAMPLE,
        })? {
            Ok(DiskAnswer::Extracted(_)) => {
                let out = scratch.join(reader.last_request_id().to_string());
                std::fs::read(&out).map_err(|error| error.to_string())
            }
            Err(ReadError::NotFound) => Err(format!("{guest_path} is not in the disk dump")),
            Err(error) => Err(format!("{guest_path}: {error}")),
            Ok(other) => Err(format!("{guest_path}: unexpected answer {other:?}")),
        }
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_without_a_dump_offers_no_source_and_extraction_says_why() {
        let dir = std::env::temp_dir().join(format!("ant-promote-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dump_label(&dir).is_none());
        let error = extract_from_dump(&dir, "/tmp/.x").unwrap_err();
        assert!(error.contains("no disk dump"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
