// SPDX-License-Identifier: GPL-3.0-only
//! Run lists and member opens that write nothing and take no lock (design
//! 2.3, 5.12.2). A service or a CLI beside a GUI reads finished recordings
//! through these; the listings in the parent module may repair a stale
//! analysis, which writes into the run's folder.
use super::*;

/// Where every VM of the data directory keeps its disk and recordings
/// (deleted VMs with retained recordings included).
pub fn read_only_locations(options: &BackendOptions) -> Result<Vec<VmLocations>, RecordingError> {
    crate::locations::all_locations(options)
        .map_err(|error| RecordingError::Io(std::io::Error::other(error)))
}

/// The runs recorded for one VM, newest first, at most 1024. Nothing is
/// written into any run folder.
pub fn list_runs_read_only(location: &VmLocations) -> Result<Vec<RunSummary>, RecordingError> {
    Ok(newest_runs(list_location_runs(
        &location.recording_directories,
        &location.vm_id,
        false,
    )?))
}

/// The run `run_id` that was recorded in boot `boot_id` of this VM, or `None`.
/// A run that lived through a reconnect has one record per boot; the boot says
/// which. Nothing is written.
pub fn find_run_read_only(
    location: &VmLocations,
    boot_id: &str,
    run_id: &str,
) -> Result<Option<RunSummary>, RecordingError> {
    for directory in &location.recording_directories {
        let Ok(root) = fs::canonicalize(directory) else {
            continue;
        };
        for candidate in [
            root.join("runs").join(run_id),
            root.join("boots").join(boot_id).join("runs").join(run_id),
        ] {
            if !candidate.join("run.json").is_file() {
                continue;
            }
            if let Some(run) = saved_run_with(&root, &candidate, &location.vm_id, false)?
                && run.id == run_id
                && run.boot_id == boot_id
            {
                return Ok(Some(run));
            }
        }
    }
    Ok(None)
}

/// Open the regular file `relative` under `root` for reading. A symlink, a
/// device, a FIFO or a path that leaves `root` is refused.
pub fn open_member(root: &Path, relative: &Path) -> std::io::Result<File> {
    archive_io::open_regular(root, relative)
}

impl Recording {
    /// The call `(stream, task, call)` of the retained stream with its entry,
    /// exit, task end and bounded async preview, or `None` when the indexed
    /// prefix holds no such call. The index is the rebuildable cache outside
    /// the recording; nothing is written into the recording.
    pub fn invocation_by_identity_cancellable(
        &self,
        identity: (u64, u64, u64),
        cancel: &AtomicBool,
    ) -> Result<Option<(InvocationSummary, Vec<String>)>, RecordingError> {
        retry_index_busy(cancel, || {
            let (connection, _) = archive_index(&self.directory, cancel)?;
            let boundary = super::matching::indexed_boundary(&connection)?;
            let key = key_blob(identity);
            let known: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM invocations WHERE key=?1 AND first_offset<?2)",
                    rusqlite::params![key, boundary as i64],
                    |row| row.get(0),
                )
                .map_err(RecordingError::from)?;
            if !known {
                return Ok(None);
            }
            let mut reader = super::call_reader::CallReader::open(
                &self.directory,
                &connection,
                boundary,
                self.guest_arch(),
            )?;
            let call = reader.call(&key, cancel)?;
            Ok(call.map(|call| (call, reader.take_issues())))
        })
    }
}
