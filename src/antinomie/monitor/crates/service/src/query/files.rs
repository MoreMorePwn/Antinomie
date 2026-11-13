// SPDX-License-Identifier: GPL-3.0-only
//! `recording.files.list`, `recording.files.versions` and
//! `recording.files.content` (design 5.12.3 class T, card Q-4). The rows are
//! the File activity tables of the Triage scan; a changed file's versions are
//! the earlier bytes the recording copied (`file-before/`) and the later bytes
//! the scan rebuilt from the recorded writes.

use super::{
    convert::base64,
    page::{Page, PageRequest, Single},
    request::{FileContentParams, FileVersionsParams, FilesListParams},
    scan::Scanned,
    service::{Opened, QueryService},
    tables::{self, Cut, V, Values},
    types::*,
};
use crate::api::{
    error::{ApiError, ErrorCode},
    job::RecordingPhase,
    ops::Permission,
};
use antinomie_monitor_core::{
    disk_start::DiskStart, file_before::Before, file_before_store::Store,
};
use antinomie_triage::{
    Cell, ScanData, file_activity::FileActivity, file_category::FILE_FIELDS, files::Change,
};
use sha2::{Digest, Sha256};

/// Bytes `recording.files.content` returns in one call.
const CONTENT_LIMIT: u64 = 1 << 20;

fn digest_id(prefix: &str, parts: &[&str]) -> String {
    let digest = Sha256::digest(parts.join("\0").as_bytes());
    let hex: String = digest[..10].iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}_{hex}")
}

/// The id of a changed file: the run and the name it was first met under.
pub(super) fn changed_id(opened: &Opened, change: &Change) -> String {
    let inode = change
        .identity
        .map(|key| format!("{}:{}", key.dev, key.ino))
        .unwrap_or_default();
    digest_id("fil", &[opened.key.as_str(), &change.path, &inode])
}

fn version_id(file_id: &str, kind: VersionKind) -> String {
    let kind = match kind {
        VersionKind::Earlier => "earlier",
        VersionKind::Later => "later",
    };
    digest_id("ver", &[file_id, kind])
}

/// The stored rows of one operation tab of the scan.
fn operation_rows(scan: &ScanData, tab: FileTab) -> (&[Vec<Cell>], u64) {
    match tab {
        FileTab::Opened => (&scan.opened, scan.opened_omitted),
        FileTab::Read => (&scan.read, scan.read_omitted),
        FileTab::Changed => (&scan.changed, scan.changed_omitted),
        other => {
            let slot = match other {
                FileTab::Created => 8,
                FileTab::Written => 9,
                FileTab::Deleted => 10,
                FileTab::Renamed => 11,
                FileTab::Executed => 12,
                FileTab::Attributes => 13,
                FileTab::Probed => 14,
                _ => 15,
            };
            let tab = &scan.file_tabs[slot - 8];
            (&tab.rows, tab.omitted)
        }
    }
}

pub(super) fn operation_row(opened: &Opened, values: &Values) -> FileOperationRow {
    let v = V(values);
    let call = CallRef {
        stream: U64(v.u64("stream.id")),
        task: U64(v.u64("process.cookie")),
        call: U64(v.u64("event.id")),
    };
    let path = v.opt_text("file.path");
    let guest_ns = v.u64("event.time_ns");
    let content: String = v.text("file.content").chars().take(256).collect();
    FileOperationRow {
        file_id: digest_id(
            "fop",
            &[
                opened.key.as_str(),
                &call.stream.0.to_string(),
                &call.task.0.to_string(),
                &call.call.0.to_string(),
                &v.text("file.path"),
                &v.text("file.operation"),
            ],
        ),
        path_known: path.is_some(),
        path: path.unwrap_or_default(),
        old_path: v.opt_text("file.old_path"),
        new_path: v.opt_text("file.new_path"),
        operation: v.text("file.operation"),
        via: serde_json::from_value(serde_json::Value::String(v.text("file.via")))
            .unwrap_or(FileVia::Syscall),
        success: v.flag("file.success"),
        access: v.text("file.access"),
        fd: v.number("file.fd").and_then(|n| i64::try_from(n).ok()),
        read_size: v.opt_u64("file.read_size"),
        written_size: v.opt_u64("file.written_size"),
        requested_size: v.opt_u64("file.requested_size"),
        offset: v.opt_u64("file.offset").map(U64),
        count: v.u64("file.count").max(1),
        interpreter: v.opt_text("file.interpreter"),
        content_gap: false,
        content,
        process: ProcessRef {
            pid: v.u32("process.pid"),
            tid: v.u32("process.tid"),
            cookie: call.task,
            exe: v.opt_text("process.exe"),
        },
        guest_ns,
        ts_ms: opened.ts_ms(guest_ns),
        call,
    }
}

fn earlier_state(file: Option<&FileActivity>, phase: RecordingPhase) -> EarlierState {
    let Some(earlier) = file.and_then(|file| file.earlier.as_ref()) else {
        return if phase == RecordingPhase::Finalizing {
            EarlierState::Pending
        } else {
            EarlierState::Unavailable
        };
    };
    match &earlier.before {
        Before::Created => EarlierState::Created,
        Before::Recorded { .. } | Before::OnDisk { .. } => EarlierState::Copied,
        Before::TooLarge(_) | Before::NotCopied { .. } => EarlierState::NotCopied,
        Before::Elsewhere(_) => EarlierState::Elsewhere,
        Before::Unavailable(_) => EarlierState::Unavailable,
    }
}

/// The activity record of the file a change is about.
fn activity_of<'a>(scan: &'a ScanData, change: &Change) -> Option<&'a FileActivity> {
    scan.file_activity
        .files
        .iter()
        .find(|file| file.path == change.path)
}

fn changed_row(
    opened: &Opened,
    scan: &ScanData,
    change: &Change,
    values: &Values,
) -> FileChangedRow {
    let v = V(values);
    let activity = activity_of(scan, change);
    let tally = activity.map(|file| file.writes.tally);
    let complete = v.flag("file.complete").unwrap_or(false);
    let reconstruction = if complete {
        Reconstruction::Complete
    } else if change.original.is_empty() && change.final_data.is_empty() {
        Reconstruction::NotReconstructed
    } else {
        Reconstruction::Incomplete
    };
    let mut names = vec![change.path.clone()];
    names.extend(change.names.iter().cloned());
    FileChangedRow {
        file_id: changed_id(opened, change),
        path: change.path.clone(),
        names,
        inode: v.opt_text("file.inode"),
        standard_io: change.standard_io,
        created: change.categories.contains("Created"),
        deleted: change.deleted,
        original_size: change.original_size,
        final_size: change.final_size,
        diff_count: change.diff_count() as u64,
        complete,
        reconstruction,
        bytes_written: tally.map_or(0, |t| t.kept + t.skipped()),
        bytes_not_captured: tally.map_or(0, |t| t.skipped() - t.offset_unknown),
        bytes_unknown: tally.map_or(0, |t| t.offset_unknown),
        guest_sha256: change.hash.as_ref().and_then(|hash| hash.sha256_hex()),
        earlier: earlier_state(activity, opened.phase.phase),
        first_guest_ns: change.first_ns,
        last_guest_ns: change
            .operations
            .iter()
            .map(|operation| operation.time)
            .max()
            .unwrap_or(change.first_ns)
            .max(change.first_ns),
    }
}

impl QueryService {
    /// `recording.files.list`.
    pub(super) fn files_list(&self, params: &FilesListParams) -> Result<Page<FileRow>, ApiError> {
        tables::check_sort(params.sort.as_ref(), FILE_FIELDS)?;
        let compiled = tables::compile_q(params.q.as_deref(), FILE_FIELDS)?;
        let opened = self.open_run(&params.run_key)?;
        let binding = opened.binding(&(params.tab, &params.q), &params.sort);
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => {
                return Ok(Page::building(
                    opened.generation,
                    opened.phase.phase,
                    building,
                ));
            }
            Ok(scanned) => scanned,
        };
        let scan = &scanned.scan;
        let (rows, omitted) = operation_rows(scan, params.tab);
        let mut base: Vec<usize> = (0..rows.len()).collect();
        if params.tab.is_operation_tab() {
            base.sort_by_key(|at| V(tables::values_of(&rows[*at])).u64("event.time_ns"));
        } else {
            base.sort_by(|a, b| {
                V(tables::values_of(&rows[*a]))
                    .text("file.path")
                    .cmp(&V(tables::values_of(&rows[*b])).text("file.path"))
            });
        }
        let values: Vec<&Values> = base
            .iter()
            .map(|at| tables::values_of(&rows[*at]))
            .collect();
        let order: Vec<usize> = tables::select(
            values.iter().copied(),
            &compiled,
            |_| true,
            params.sort.as_ref(),
        )
        .into_iter()
        .map(|at| base[at])
        .collect();
        let cut = Cut {
            request: &PageRequest {
                limit: params.limit,
                cursor: params.cursor.clone(),
            },
            max: self.settings.rows().1,
            binding,
            omitted,
            untrusted: true,
        };
        tables::page_of(&opened, &order, &cut, |at| {
            let values = tables::values_of(&rows[at]);
            match params.tab {
                FileTab::Changed => match scan.file_changes.get(at) {
                    Some(change) => FileRow::Changed(changed_row(&opened, scan, change, values)),
                    None => FileRow::Operation(operation_row(&opened, values)),
                },
                _ => FileRow::Operation(operation_row(&opened, values)),
            }
        })
    }

    fn change_of<'a>(
        &self,
        opened: &Opened,
        scanned: &'a Scanned,
        file_id: &str,
    ) -> Result<&'a Change, ApiError> {
        scanned
            .scan
            .file_changes
            .iter()
            .find(|change| changed_id(opened, change) == file_id)
            .ok_or_else(|| ApiError::not_found("file"))
    }

    /// The recording's copy of a file's earlier bytes.
    fn earlier_store(&self, opened: &Opened) -> Option<Store> {
        let boot = DiskStart::boot_dir(&opened.dir, &opened.run.boot_id)?;
        Store::open(&boot)
    }

    /// `recording.files.versions`.
    pub(super) fn files_versions(
        &self,
        params: &FileVersionsParams,
    ) -> Result<Single<FileVersions>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => {
                return Ok(Single::building(
                    opened.generation,
                    opened.phase.phase,
                    building,
                ));
            }
            Ok(scanned) => scanned,
        };
        let change = self.change_of(&opened, &scanned, &params.file_id)?;
        let activity = activity_of(&scanned.scan, change);
        let id = changed_id(&opened, change);
        let state = earlier_state(activity, opened.phase.phase);
        let (size, sha256, reason) = match activity.and_then(|f| f.earlier.as_ref()) {
            Some(earlier) => match &earlier.before {
                Before::Created => (0, None, None),
                Before::Recorded { size, .. } | Before::OnDisk { size, .. } => (*size, None, None),
                Before::NotCopied { size, sha256, why } => {
                    (*size, sha256.clone(), Some(self.scrub.text(why)))
                }
                Before::TooLarge(size) => (
                    *size,
                    None,
                    Some("the file is larger than the earlier-bytes limit".to_owned()),
                ),
                Before::Elsewhere(why) | Before::Unavailable(why) => {
                    (0, None, Some(self.scrub.text(why)))
                }
            },
            None => (
                0,
                None,
                Some(
                    if state == EarlierState::Pending {
                        "the earlier bytes are not copied into the recording yet"
                    } else {
                        "the earlier bytes were not looked up"
                    }
                    .to_owned(),
                ),
            ),
        };
        let earlier_ok = matches!(state, EarlierState::Copied | EarlierState::Created);
        let later_size = change.final_size.unwrap_or(0);
        let later_ok = change.final_size.is_some()
            && !change.deleted
            && change.final_data.len() as u64 == later_size;
        let versions = FileVersions {
            versions: vec![
                FileVersion {
                    version_id: version_id(&id, VersionKind::Earlier),
                    kind: VersionKind::Earlier,
                    size,
                    sha256,
                    available: earlier_ok,
                    status: state,
                    reason: if earlier_ok { None } else { reason },
                },
                FileVersion {
                    version_id: version_id(&id, VersionKind::Later),
                    kind: VersionKind::Later,
                    size: later_size,
                    sha256: change.hash.as_ref().and_then(|hash| hash.sha256_hex()),
                    available: later_ok,
                    status: EarlierState::Copied,
                    reason: (!later_ok)
                        .then(|| "the recorded writes do not cover the whole file".to_owned()),
                },
            ],
        };
        Ok(opened.single(versions, true))
    }

    /// `recording.files.content`.
    pub(super) fn files_content(
        &self,
        params: &FileContentParams,
        ctx: &super::ReadContext,
    ) -> Result<Single<BytesReply>, ApiError> {
        ctx.require(Permission::EvidenceView)?;
        let (offset, len) = params
            .range
            .as_ref()
            .map_or((0, CONTENT_LIMIT), |range| (range.offset, range.len));
        if len > CONTENT_LIMIT {
            return Err(ApiError::payload_too_large(CONTENT_LIMIT));
        }
        let opened = self.open_run(&params.run_key)?;
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => {
                return Ok(Single::building(
                    opened.generation,
                    opened.phase.phase,
                    building,
                ));
            }
            Ok(scanned) => scanned,
        };
        let (change, kind) = scanned
            .scan
            .file_changes
            .iter()
            .find_map(|change| {
                let id = changed_id(&opened, change);
                [VersionKind::Earlier, VersionKind::Later]
                    .into_iter()
                    .find(|kind| version_id(&id, *kind) == params.version_id)
                    .map(|kind| (change, kind))
            })
            .ok_or_else(|| ApiError::not_found("file version"))?;
        let bytes = match kind {
            VersionKind::Later => {
                let size = change.final_size.unwrap_or(0);
                let end = offset.saturating_add(len).min(size);
                (offset..end)
                    .map(|at| change.final_data.get(&at).copied())
                    .collect::<Option<Vec<u8>>>()
                    .ok_or_else(|| {
                        ApiError::invalid_argument(
                            "range",
                            "the range includes bytes the recording did not capture",
                        )
                    })?
            }
            VersionKind::Earlier => {
                let activity = activity_of(&scanned.scan, change);
                if earlier_state(activity, opened.phase.phase) == EarlierState::Pending {
                    return Err(ApiError::layer_pending());
                }
                let store = self
                    .earlier_store(&opened)
                    .ok_or_else(|| ApiError::not_recorded("earlier file bytes"))?;
                store
                    .read(&change.path, offset, len)
                    .map_err(|error| ApiError::new(ErrorCode::NotFound, self.scrub.text(&error)))?
            }
        };
        let reply = BytesReply {
            offset: U64(offset),
            len: bytes.len() as u64,
            data_b64: base64(&bytes),
        };
        Ok(opened.single(reply, true))
    }
}
