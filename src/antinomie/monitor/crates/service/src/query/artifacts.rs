// SPDX-License-Identifier: GPL-3.0-only
//! `recording.artifact.list`, `recording.artifact.get`, `recording.network.
//! captures` and `recording.cores.list` (design 5.12.3): the files a run kept
//! and the retained evidence it links in `artifacts.json`.
//!
//! The listing is a scan of the recording folder that follows no symlink and
//! opens every file with the engine's confined open. `telemetry.raw`,
//! `manifest.json`, `events.json` and the `objects/` store are the recorder's
//! internal format and are not listed. A host path is never part of a reply.

use super::{
    context::ReadContext,
    convert::base64,
    page::{Page, Single},
    request::{ArtifactGetParams, RunParams},
    service::{Opened, QueryService},
    types::*,
};
use crate::api::{
    error::ApiError,
    ids::{RecordingArtifactId, Sha256Hex},
    ops::Scope,
};
use antinomie_monitor_core::{
    RunArtifactState, RunArtifacts, core_dump::CoreDump, network::NetworkCapture, network_link,
    recording::open_member,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

/// Files hashed in a listing; bigger ones list no `sha256`.
const HASH_LIMIT: u64 = 8 << 20;
/// Entries one recording lists.
const LIST_LIMIT: usize = 4096;

/// One listed file, with where to open it.
pub(super) struct Entry {
    pub(super) id: RecordingArtifactId,
    pub(super) kind: RecordingArtifactKind,
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) root: PathBuf,
    pub(super) relative: PathBuf,
}

/// The recording folder a run folder lives in.
fn recording_root(run_dir: &Path) -> Option<PathBuf> {
    let runs = run_dir.parent()?;
    if runs.file_name()? != "runs" {
        return None;
    }
    let above = runs.parent()?;
    let boots = above.parent()?;
    if boots.file_name().is_some_and(|name| name == "boots") {
        return boots.parent().map(Path::to_path_buf);
    }
    Some(above.to_path_buf())
}

/// A stable id for a file of a run: the hash of the run, kind and name.
fn artifact_id(
    run: &super::key::RunKey,
    kind: RecordingArtifactKind,
    name: &str,
) -> RecordingArtifactId {
    let digest = Sha256::digest(format!("{}\0{kind:?}\0{name}", run.as_str()).as_bytes());
    let mut time = [0u8; 8];
    time[2..].copy_from_slice(&digest[..6]);
    let mut random = [0u8; 10];
    random.copy_from_slice(&digest[6..16]);
    RecordingArtifactId::from_parts(u64::from_be_bytes(time), random)
}

/// A regular file `path` that lies under `root`, as the path relative to it.
/// A symlink anywhere, a missing file or an escape gives `None`.
fn confined(root: &Path, path: &Path) -> Option<(PathBuf, u64)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    let relative = canonical.strip_prefix(root).ok()?.to_path_buf();
    Some((relative, meta.len()))
}

fn artifact_state(state: RunArtifactState) -> ArtifactState {
    super::runs::artifact_status(state, true).state
}

impl QueryService {
    pub(super) fn artifacts_json(&self, opened: &Opened) -> Option<RunArtifacts> {
        RunArtifacts::load(&opened.dir).ok().flatten()
    }

    /// The network captures of the run as `(absolute path, capture_id)`: how a
    /// Triage row's capture is named in a reply.
    pub(super) fn capture_paths(&self, opened: &Opened) -> Vec<(String, String)> {
        self.recording_entries(opened)
            .into_iter()
            .filter(|entry| entry.kind == RecordingArtifactKind::NetworkCapture)
            .map(|entry| {
                (
                    entry
                        .root
                        .join(&entry.relative)
                        .to_string_lossy()
                        .into_owned(),
                    entry.id.to_string(),
                )
            })
            .collect()
    }

    /// Every file of the run a caller may fetch, in `name` order.
    pub(super) fn recording_entries(&self, opened: &Opened) -> Vec<Entry> {
        let mut entries: Vec<Entry> = Vec::new();
        let run_dir = &opened.dir;
        let root = recording_root(run_dir).and_then(|r| fs::canonicalize(r).ok());
        let mut add = |kind: RecordingArtifactKind,
                       root: &Path,
                       relative: PathBuf,
                       size: u64,
                       name: String| {
            if entries.len() < LIST_LIMIT
                && !entries.iter().any(|e| e.kind == kind && e.name == name)
            {
                entries.push(Entry {
                    id: artifact_id(&opened.key, kind, &name),
                    kind,
                    name,
                    size,
                    root: root.to_path_buf(),
                    relative,
                });
            }
        };
        use RecordingArtifactKind as K;
        for (kind, name) in [
            (K::TerminalJournal, "terminal.journal"),
            (K::TerminalScreen, "terminal-screen.ansi"),
            (K::RunRecord, "run.json"),
            (K::ArtifactsRecord, "artifacts.json"),
            (K::TriageDigest, "triage-digest.json"),
            (K::AnalysisReport, "analysis/report.json"),
        ] {
            if let Some((relative, size)) = confined(run_dir, &run_dir.join(name)) {
                add(kind, run_dir, relative, size, name.to_owned());
            }
        }
        if let Ok(listings) = fs::read_dir(run_dir.join("analysis/listings")) {
            let mut files: Vec<PathBuf> = listings.flatten().map(|e| e.path()).collect();
            files.sort();
            for path in files
                .into_iter()
                .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            {
                if let Some((relative, size)) = confined(run_dir, &path) {
                    let name = relative.to_string_lossy().into_owned();
                    add(K::AnalysisReport, run_dir, relative, size, name);
                }
            }
        }
        // The timed screenshots of the run, oldest first (`screenshots/t+...png`).
        for shot in antinomie_monitor_core::timed_shots::list(run_dir) {
            if let Some((relative, size)) = confined(run_dir, &shot.path) {
                let name = relative.to_string_lossy().into_owned();
                add(K::Screenshot, run_dir, relative, size, name);
            }
        }
        if let Some(root) = &root {
            if let Some(links) = self.artifacts_json(opened) {
                if !links.network_deleted {
                    for path in &links.network_captures {
                        if let Some((relative, size)) = confined(root, path)
                            && relative.extension().is_some_and(|e| e == "pcap")
                        {
                            let name = relative.to_string_lossy().into_owned();
                            add(K::NetworkCapture, root, relative, size, name);
                        }
                    }
                }
                if let Some(memory) = &links.memory_dump {
                    for file in ["dump.json", "memory.elf"] {
                        if let Some((relative, size)) = confined(root, &memory.join(file)) {
                            let name = relative.to_string_lossy().into_owned();
                            add(K::MemoryDump, root, relative, size, name);
                        }
                    }
                }
                if let Some(core) = links.core_dump.as_ref().filter(|_| !links.core_deleted)
                    && let Some((relative, size)) = confined(root, core)
                {
                    let name = relative.to_string_lossy().into_owned();
                    add(K::CoreDump, root, relative, size, name);
                }
            }
            // The boot's earlier-bytes store: an index and one blob per file.
            let store = root
                .join("boots")
                .join(&opened.run.boot_id)
                .join("file-before");
            if let Ok(listing) = fs::read_dir(&store) {
                let mut files: Vec<PathBuf> = listing.flatten().map(|e| e.path()).collect();
                files.sort();
                for path in files {
                    if let Some((relative, size)) = confined(root, &path) {
                        let name = relative.to_string_lossy().into_owned();
                        add(K::FileBefore, root, relative, size, name);
                    }
                }
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    fn sha256_of(entry: &Entry) -> Option<Sha256Hex> {
        if entry.size > HASH_LIMIT {
            return None;
        }
        let mut file = open_member(&entry.root, &entry.relative).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buffer).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Sha256Hex::try_from(hex).ok()
    }

    /// `recording.artifact.list`.
    pub(super) fn artifact_list(
        &self,
        params: &RunParams,
    ) -> Result<Page<RecordingArtifact>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let entries = self.recording_entries(&opened);
        let items: Vec<RecordingArtifact> = entries
            .iter()
            .map(|entry| RecordingArtifact {
                id: entry.id.clone(),
                kind: entry.kind,
                name: entry.name.clone(),
                size: entry.size,
                sha256: Self::sha256_of(entry),
                sensitive: entry.kind.sensitive(),
                run_time_ms: (entry.kind == RecordingArtifactKind::Screenshot)
                    .then(|| {
                        entry
                            .relative
                            .file_name()
                            .and_then(|name| name.to_str())
                            .and_then(antinomie_monitor_core::timed_shots::parse_name)
                    })
                    .flatten(),
            })
            .collect();
        let total = items.len() as u64;
        Ok(opened.counted_page(items, total, false))
    }

    /// `recording.artifact.get`: a range of one file, at most 1 MiB. A capture,
    /// memory dump, core or file copy needs the sensitive scope.
    pub(super) fn artifact_get(
        &self,
        params: &ArtifactGetParams,
        ctx: &ReadContext,
    ) -> Result<Single<BytesReply>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let entry = self
            .recording_entries(&opened)
            .into_iter()
            .find(|entry| entry.id == params.artifact_id)
            .ok_or_else(|| ApiError::not_found("artifact"))?;
        if entry.kind.sensitive() {
            ctx.require(Scope::ArtifactsSensitive)?;
        }
        let max = u64::from(self.settings.limits.byte_read.content);
        let (offset, len) = match params.range {
            Some(range) => (range.offset, range.len),
            None => (0, entry.size),
        };
        if len > max {
            return Err(ApiError::payload_too_large(max));
        }
        if offset > entry.size {
            return Err(ApiError::invalid_argument(
                "range",
                "starts past the end of the file",
            ));
        }
        let want = len.min(entry.size - offset);
        let mut file = open_member(&entry.root, &entry.relative)
            .map_err(|_| ApiError::not_found("artifact"))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| ApiError::not_found("artifact"))?;
        let mut bytes = Vec::with_capacity(want as usize);
        file.take(want)
            .read_to_end(&mut bytes)
            .map_err(|_| ApiError::not_found("artifact"))?;
        let reply = BytesReply {
            offset: super::types::U64(offset),
            len: bytes.len() as u64,
            data_b64: base64(&bytes),
        };
        if entry.kind.sensitive() {
            self.audit_read(ctx, "recording.artifact.get", &params.run_key, reply.len);
        }
        Ok(opened.single(reply, entry.kind != RecordingArtifactKind::NetworkCapture))
    }

    /// `recording.network.captures`.
    pub(super) fn network_captures(&self, params: &RunParams) -> Result<Page<Capture>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let links = self
            .artifacts_json(&opened)
            .ok_or_else(|| ApiError::not_recorded("network capture"))?;
        let entries = self.recording_entries(&opened);
        let captures: Vec<&Entry> = entries
            .iter()
            .filter(|entry| entry.kind == RecordingArtifactKind::NetworkCapture)
            .collect();
        if captures.is_empty() {
            return Err(ApiError::not_recorded("network capture"));
        }
        // The order of `artifacts.json` is the segment order.
        let mut ordered: Vec<(u32, &Entry)> = Vec::new();
        for (segment, path) in links.network_captures.iter().enumerate() {
            if let Some(entry) = captures
                .iter()
                .find(|entry| path.ends_with(&entry.relative))
            {
                ordered.push((segment as u32, entry));
            }
        }
        let last = ordered.len().saturating_sub(1);
        // Which run each segment belongs to, from the runs' own records: this
        // run lists its segments (exact); any other run live while one was
        // written is linked by time.
        let saved: Vec<Option<NetworkCapture>> = ordered
            .iter()
            .map(|(_, entry)| network_link::saved_capture(&entry.root.join(&entry.relative)))
            .collect();
        let runs = antinomie_monitor_core::recording::list_runs_read_only(&opened.location)
            .unwrap_or_default();
        let windows = network_link::run_windows(&runs);
        let known: Vec<NetworkCapture> = saved.iter().flatten().cloned().collect();
        let items: Vec<Capture> = ordered
            .iter()
            .enumerate()
            .map(|(at, (segment, entry))| Capture {
                capture_id: entry.id.to_string(),
                segment: *segment,
                size: entry.size,
                packets: saved[at].as_ref().and_then(|capture| capture.packets),
                first_ms: saved[at].as_ref().map(|capture| capture.started_ms),
                last_ms: saved[at].as_ref().and_then(|capture| capture.stopped_ms),
                link: Some(capture_link(
                    &opened.key,
                    saved[at].as_ref(),
                    &windows,
                    &known,
                )),
                // Only the newest segment can still be recording.
                state: if at == last {
                    artifact_state(links.network_state)
                } else {
                    ArtifactState::Complete
                },
                path: None,
            })
            .collect();
        let total = items.len() as u64;
        Ok(opened.counted_page(items, total, false))
    }

    /// `recording.cores.list`: metadata only. Registers, mappings and memory
    /// are not sent.
    pub(super) fn cores_list(&self, params: &RunParams) -> Result<Page<CoreInfo>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let links = self
            .artifacts_json(&opened)
            .ok_or_else(|| ApiError::not_recorded("core"))?;
        let root = recording_root(&opened.dir).and_then(|r| fs::canonicalize(r).ok());
        let mut items: Vec<CoreInfo> = Vec::new();
        if let Some(core) = links.core_dump.as_ref().filter(|_| !links.core_deleted) {
            let opened_core = root
                .as_deref()
                .and_then(|root| confined(root, core))
                .and_then(|(relative, _)| {
                    let full = root.as_deref()?.join(relative);
                    CoreDump::open(&full).ok()
                });
            let mut warnings: Vec<String> = Vec::new();
            if let Some(dump) = &opened_core {
                warnings.extend(dump.warnings.iter().map(|w| self.scrub.text(w)));
            } else {
                warnings.push("the core file could not be read".into());
            }
            items.push(CoreInfo {
                core_id: "exit".into(),
                state: artifact_state(links.core_state),
                reason: links
                    .core_reason
                    .as_ref()
                    .map(|reason| self.scrub.text(&reason.text)),
                requested_size: links.core_requested_size,
                accepted_size: links.core_accepted_size,
                expected_size: links.core_expected_size,
                saved_size: links.core_saved_size,
                logical_size: links.core_logical_size,
                threads: opened_core.as_ref().map(|dump| dump.threads.len() as u64),
                mappings: opened_core.as_ref().map(|dump| dump.mappings.len() as u64),
                warnings,
            });
        }
        for trigger in &links.trigger_dumps {
            if let Some(dump) = &trigger.core {
                items.push(CoreInfo {
                    core_id: format!("trigger-{}", trigger.at_ms),
                    state: artifact_state(dump.state),
                    reason: None,
                    requested_size: None,
                    accepted_size: None,
                    expected_size: None,
                    saved_size: dump.size,
                    logical_size: None,
                    threads: None,
                    mappings: None,
                    warnings: dump.error.iter().map(|e| self.scrub.text(e)).collect(),
                });
            }
        }
        if items.is_empty() {
            return Err(ApiError::not_recorded("core"));
        }
        items.sort_by(|a, b| a.core_id.cmp(&b.core_id));
        let total = items.len() as u64;
        Ok(opened.counted_page(items, total, true))
    }
}

/// The link of one segment of the run `key`: the run lists it, so it is the
/// run's (exact), whatever its own summary says; other runs live in its
/// window are listed by time.
fn capture_link(
    key: &super::key::RunKey,
    saved: Option<&NetworkCapture>,
    windows: &[network_link::RunWindow],
    known: &[NetworkCapture],
) -> CaptureLink {
    let (_, _, run_id) = key.parts();
    let run_id: String = run_id;
    let others = |link: &antinomie_monitor_core::provenance::Provenance| -> Vec<String> {
        link.live_runs
            .iter()
            .filter(|id| **id != run_id)
            .cloned()
            .collect()
    };
    let live_runs = saved
        .map(|capture| {
            // The run owns the segment: the link of the same file with this run
            // taken as its owner lists the others.
            let mut windows = windows.to_vec();
            let name = capture
                .file
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if let Some(window) = windows.iter_mut().find(|window| window.run_id == run_id)
                && !window.owned.contains(&name)
            {
                window.owned.push(name);
            }
            others(&network_link::link(capture, &windows, known))
        })
        .unwrap_or_default();
    CaptureLink {
        certainty: LinkCertainty::Exact,
        run_id: Some(run_id),
        live_runs,
    }
}
