// SPDX-License-Identifier: MIT
use super::*;
use crate::{
    RunArtifacts,
    packet_filter::{AnalysisSnapshot, CaptureIdentity, snapshot_for_analysis},
};
use std::{
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(test)]
thread_local! {
    static PROVENANCE_FAIL: std::cell::RefCell<std::collections::BTreeSet<&'static str>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

#[cfg(test)]
pub(crate) fn fail_provenance(op: &'static str) {
    PROVENANCE_FAIL.with(|ops| {
        ops.borrow_mut().insert(op);
    });
}

fn provenance_failed(op: &str) -> bool {
    #[cfg(test)]
    {
        PROVENANCE_FAIL.with(|ops| ops.borrow_mut().remove(op))
    }
    #[cfg(not(test))]
    {
        let _ = op;
        false
    }
}

/// Selection captured when a scan is admitted. The worker reads this copy and
/// does not take another snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FrozenSelection {
    pub digest: String,
    pub directory: Option<PathBuf>,
    pub enabled_rules: u64,
    pub excluded_rules: u64,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub engine: Engine,
    pub identity: Identity,
    pub directory: PathBuf,
    pub settings: Settings,
    pub source_digest: Option<String>,
    /// Set at admission. `None` means the worker may snapshot itself.
    #[serde(default)]
    pub frozen: Option<FrozenSelection>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RuleFile {
    pub path: PathBuf,
    pub name: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Capture {
    pub path: PathBuf,
    pub original: PathBuf,
    pub complete: bool,
    pub packets: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Staged {
    #[serde(flatten)]
    pub request: Request,
    pub sigma_sources: Vec<RuleFile>,
    pub yara_sources: Vec<RuleFile>,
    pub ids_sources: Vec<RuleFile>,
    pub captures: Vec<Capture>,
    pub journal: Option<PathBuf>,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub selection: String,
    #[serde(default)]
    pub no_rules: bool,
    #[serde(default)]
    pub include_dir: Option<PathBuf>,
    /// Inputs staging could not prepare; the scan lists them as skipped.
    #[serde(default)]
    pub skipped_inputs: Vec<super::ScannedInput>,
}

fn text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "detector path is not UTF-8".into())
}

fn read_bounded(root: &Path, path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = crate::archive_io::open_regular(root, path).map_err(|error| error.to_string())?;
    let mut data = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() > limit {
        return Err(format!(
            "{} exceeds the {limit} octet input limit",
            path.display()
        ));
    }
    Ok(data)
}

fn validate_run(request: &Request) -> Result<(), String> {
    if request.identity.root_cookie == 0 {
        return Err("one program run is required".into());
    }
    let data = read_bounded(&request.directory, Path::new("run.json"), REPORT_LIMIT)?;
    let run: serde_json::Value =
        serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    for (key, expected) in [
        ("id", &request.identity.run_id),
        ("vm_id", &request.identity.vm_id),
        ("boot_id", &request.identity.boot_id),
    ] {
        if run.get(key).and_then(serde_json::Value::as_str) != Some(expected.as_str()) {
            return Err("detector run identity mismatch".into());
        }
    }
    if run
        .get("root_task_cookie")
        .and_then(serde_json::Value::as_u64)
        != Some(request.identity.root_cookie)
    {
        return Err("detector root identity mismatch".into());
    }
    Ok(())
}

fn host_path(value: &str) -> PathBuf {
    value
        .strip_prefix("~/")
        .and_then(|tail| std::env::var_os("HOME").map(|base| PathBuf::from(base).join(tail)))
        .unwrap_or_else(|| PathBuf::from(value))
}

fn stage_rules(
    value: &str,
    extensions: &[&str],
    work: &Path,
    cancel: &AtomicBool,
) -> Result<Vec<RuleFile>, String> {
    if value.is_empty() {
        return Ok(vec![]);
    }
    let root = host_path(value)
        .canonicalize()
        .map_err(|error| format!("local rules: {error}"))?;
    let anchor = if root.is_file() {
        root.parent().ok_or("rules have no parent")?.to_path_buf()
    } else {
        root.clone()
    };
    let mut pending = vec![(root, 0)];
    let mut files = Vec::new();
    let mut visited = 0;
    while let Some((path, depth)) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        visited += 1;
        if visited > 65_536 || depth > 16 {
            return Err("local rule traversal exceeds its entry/depth budget".into());
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                if entry.file_name() != ".git" {
                    pending.push((entry.path(), depth + 1));
                }
                if pending.len() > 65_536 {
                    return Err("too many entries in local rule directory".into());
                }
            }
        } else if metadata.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extensions.contains(&extension.to_ascii_lowercase().as_str())
                })
        {
            files.push(path);
            if files.len() > 4096 {
                return Err("local rule selection exceeds 4096 files".into());
            }
        }
    }
    files.sort();
    let mut total = 0;
    let mut staged = Vec::new();
    for (index, source) in files.into_iter().enumerate() {
        let data = read_bounded(&anchor, &source, 32 * 1024 * 1024)?;
        total += data.len();
        if total > 200 * 1024 * 1024 {
            return Err("local rule source exceeds 200 MiB".into());
        }
        let target = work.join(format!("rules-{index}.{}", extensions[0]));
        fs::write(&target, &data).map_err(|error| error.to_string())?;
        staged.push(RuleFile {
            path: target,
            name: source
                .strip_prefix(&anchor)
                .unwrap_or(&source)
                .display()
                .to_string(),
            sha256: crate::storage::sha256_hex(&data),
        });
    }
    if staged.is_empty() {
        return Err("no supported rule files in the selected location".into());
    }
    Ok(staged)
}

pub(super) fn owned_artifacts(request: &Request) -> Result<Option<RunArtifacts>, String> {
    let artifacts = RunArtifacts::load(&request.directory)?;
    if artifacts.as_ref().is_some_and(|artifacts| {
        artifacts.run_id != request.identity.run_id
            || artifacts.vm_id != request.identity.vm_id
            || artifacts.boot_id != request.identity.boot_id
    }) {
        return Err("detector artifact identity mismatch".into());
    }
    Ok(artifacts)
}

fn managed_sources(
    request: &Request,
    work: &Path,
    extensions: &[&str],
    cancel: &AtomicBool,
    staged: &mut Staged,
) -> Result<Vec<RuleFile>, String> {
    if request.settings.rules_root.is_empty() {
        return Ok(vec![]);
    }
    let engine = match request.engine {
        Engine::Yara => "yara",
        Engine::Ids => "ids",
        Engine::Sigma => "sigma",
    };
    let snap = if let Some(frozen) = &request.frozen {
        frozen.clone()
    } else {
        let live = crate::ruleset::snapshot(
            &host_path(&request.settings.rules_root),
            engine,
            &crate::ruleset::ToolConfig::from_sigma_setting(
                &request.settings.effective_sigma_python(),
            ),
        )?;
        FrozenSelection {
            digest: live.digest,
            directory: live.directory,
            enabled_rules: live.enabled_rules,
            excluded_rules: live.excluded_rules,
            warnings: live.warnings,
        }
    };
    staged.selection = snap.digest;
    staged.warnings.extend(snap.warnings);
    staged.no_rules = snap.enabled_rules == 0 && snap.excluded_rules == 0;
    let Some(directory) = snap.directory else {
        return Ok(vec![]);
    };
    let dest = work.join("selection");
    copy_regular(&directory, &dest)?;
    staged.include_dir = Some(dest.clone());
    let mut pending = vec![dest];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let meta = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("managed rules contain a link".into());
        }
        if meta.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| error.to_string())? {
                pending.push(entry.map_err(|error| error.to_string())?.path());
            }
            continue;
        }
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if extensions.contains(&extension.as_str())
            || path.ends_with("classification.config")
            || path.ends_with("reference.config")
        {
            let data = fs::read(&path).map_err(|error| error.to_string())?;
            files.push(RuleFile {
                name: path
                    .strip_prefix(work)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
                sha256: crate::storage::sha256_hex(&data),
                path,
            });
        }
    }
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(files)
}

fn copy_regular(source: &Path, dest: &Path) -> Result<(), String> {
    crate::storage::private_dir(dest).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("managed rules contain a link".into());
        }
        let target = dest.join(entry.file_name());
        if meta.is_dir() {
            copy_regular(&entry.path(), &target)?;
        } else if meta.is_file() {
            fs::copy(entry.path(), target).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn stage(
    mut request: Request,
    work: &Path,
    cancel: &Arc<AtomicBool>,
) -> Result<(Staged, Vec<AnalysisSnapshot>, Vec<PathBuf>), String> {
    let mut staged = Staged {
        request: request.clone(),
        sigma_sources: vec![],
        yara_sources: vec![],
        ids_sources: vec![],
        captures: vec![],
        journal: None,
        skipped_inputs: vec![],
        warnings: vec![],
        selection: String::new(),
        no_rules: false,
        include_dir: None,
    };
    let (configured, extensions) = match request.engine {
        Engine::Yara => (&request.settings.yara_rules, &["yar", "yara"][..]),
        Engine::Ids => (&request.settings.ids_rules, &["rules"][..]),
        Engine::Sigma => (&request.settings.sigma_rules, &["yml", "yaml", "json"][..]),
    };
    let extra = match stage_rules(configured, extensions, work, cancel) {
        Ok(extra) => extra,
        Err(error) => {
            staged.warnings.push(error);
            vec![]
        }
    };
    let managed = managed_sources(&request, work, extensions, cancel, &mut staged)?;
    let mut snapshots = Vec::new();
    let mut read_only = vec![request.directory.clone()];
    match request.engine {
        Engine::Yara => {
            staged.yara_sources = managed;
            staged.yara_sources.extend(extra);
            if let Some(artifacts) = owned_artifacts(&request)?
                && (request.settings.scan_memory || request.settings.scan_recovered)
            {
                if let Some(directory) = artifacts.memory_dump {
                    read_only.push(directory);
                }
                if let Some(core) = artifacts.core_dump {
                    read_only.push(core);
                }
            }
        }
        Engine::Ids => {
            staged.ids_sources = managed;
            staged.ids_sources.extend(extra);
            let artifacts = owned_artifacts(&request)?;
            let mut total = 0u64;
            if let Some(artifacts) = artifacts {
                let live = artifacts.network_state != crate::RunArtifactState::Complete;
                for path in artifacts.network_captures {
                    if cancel.load(Ordering::Relaxed) {
                        return Err("cancelled".into());
                    }
                    let result = (|| {
                        let identity = CaptureIdentity::read(&path)?;
                        if total.saturating_add(identity.file_size) > 2 * 1024 * 1024 * 1024 {
                            return Err(
                                "owned capture input exceeds the 2 GiB analysis budget".into()
                            );
                        }
                        let snapshot = snapshot_for_analysis(&identity, live, Arc::clone(cancel))?;
                        total += identity.file_size;
                        let complete = !live && snapshot.complete_extent() == identity.file_size;
                        staged.captures.push(Capture {
                            path: snapshot.path().to_path_buf(),
                            original: path.clone(),
                            complete,
                            packets: snapshot.packet_count(),
                        });
                        read_only.push(snapshot.path().to_path_buf());
                        snapshots.push(snapshot);
                        Ok::<_, String>(())
                    })();
                    if let Err(error) = result {
                        staged.warnings.push(format!("{}: {error}", path.display()));
                        staged.skipped_inputs.push(
                            super::ScannedInput::new(super::InputKind::Capture, &path)
                                .sized()
                                .skipped(error),
                        );
                    }
                }
            }
        }
        Engine::Sigma => {
            staged.sigma_sources = managed;
            staged.sigma_sources.extend(extra);
            let data = read_bounded(
                &request.directory,
                Path::new(JOURNAL_FILE),
                128 * 1024 * 1024,
            )?;
            let digest = crate::storage::sha256_hex(&data);
            if request
                .source_digest
                .as_ref()
                .is_some_and(|expected| *expected != digest)
            {
                return Err("the triage event index changed; retry with its current prefix".into());
            }
            request.source_digest = Some(digest);
            let path = work.join(JOURNAL_FILE);
            fs::write(&path, &data).map_err(|error| error.to_string())?;
            staged.journal = Some(path);
            let configured = request.settings.effective_sigma_python();
            if !configured.is_empty() {
                let python = host_path(&configured);
                let root = python
                    .parent()
                    .and_then(Path::parent)
                    .filter(|root| root.join("pyvenv.cfg").is_file());
                read_only.push(root.map_or_else(|| python.clone(), Path::to_path_buf));
                request.settings.sigma_python = text(&python)?;
            }
        }
    }
    let selected = match request.engine {
        Engine::Yara => staged.yara_sources.len(),
        Engine::Ids => staged.ids_sources.len(),
        Engine::Sigma => staged.sigma_sources.len(),
    };
    if selected > 0 {
        staged.no_rules = false;
    } else if request.settings.rules_root.is_empty() && configured.is_empty() {
        staged.no_rules = true;
    }
    staged.request = request;
    Ok((staged, snapshots, read_only))
}

fn validate_report(report: &Report, request: &Request) -> Result<(), String> {
    if report.identity != request.identity
        || report.engine != request.engine
        || report.findings.len() > MATCH_LIMIT
        || report.sources.len() > 4098
        || report.skipped.len() > 1000
        || report.warnings.len() > 1024
    {
        return Err("detector report identity/count mismatch".into());
    }
    if let Some(inputs) = &report.inputs
        && (inputs.len() > super::inputs::INPUT_LIMIT
            || inputs.iter().any(|input| !input.bounded()))
    {
        return Err("detector input list exceeds bounds".into());
    }
    let mut evidence_count = 0usize;
    for finding in &report.findings {
        evidence_count += finding.evidence.len();
        if finding.rule_id.len() > 8192
            || finding.title.len() > 8192
            || finding.details.len() > 8192
            || finding.rule_text.len() > super::RULE_TEXT_LIMIT
            || finding.source.len() > 8192
            || finding.license.len() > 8192
            || finding.severity.len() > 1024
            || finding.evidence.len() > MATCH_LIMIT
            || finding.mitre.len() > 128
            || finding.mitre.iter().any(|value| value.len() > 128)
        {
            return Err("detector finding exceeds bounds".into());
        }
    }
    if evidence_count > 160_000
        || report
            .skipped
            .iter()
            .chain(&report.warnings)
            .any(|text| text.len() > 16384)
        || report.sources.iter().any(|source| {
            source.name.len() > 8192
                || source.version.len() > 8192
                || source.license.len() > 8192
                || source.data.len() > 8192
                || source.sha256.len() > 64
        })
    {
        return Err("detector metadata exceeds bounds".into());
    }
    Ok(())
}

/// Execute one engine against a frozen, run-scoped input and save its JSON result.
///
/// | Argument | Meaning |
/// |---|---|
/// | `request` | Run identity, retained directory, local rules and chosen engine. |
/// | `cancel` | Shared cancellation; sandbox descendants are reaped before return. |
pub fn run(request: Request, cancel: &Arc<AtomicBool>) -> Result<Report, String> {
    run_with_progress(request, cancel, None)
}

/// [`run`], publishing coalesced [`ScanProgress`] values while the sandbox runs.
/// `progress` is the phase channel. A full or dropped receiver does not fail the scan.
pub fn run_with_progress(
    request: Request,
    cancel: &Arc<AtomicBool>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
) -> Result<Report, String> {
    let executable = super::super::jobs::worker_executable()?;
    run_program(request, cancel, &executable, progress)
}

fn run_program(
    mut request: Request,
    cancel: &Arc<AtomicBool>,
    executable: &Path,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
) -> Result<Report, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    request.directory = request
        .directory
        .canonicalize()
        .map_err(|error| error.to_string())?;
    validate_run(&request)?;
    let work = std::env::temp_dir().join(format!("ant-detection-{}", crate::storage::unique_id()));
    crate::storage::private_dir(&work).map_err(|error| error.to_string())?;
    let stop_progress = Arc::new(AtomicBool::new(false));
    let progress_watcher = progress.map(|tx| {
        let path = work.join("progress.json");
        let cancel = Arc::clone(cancel);
        let stop = Arc::clone(&stop_progress);
        std::thread::Builder::new()
            .name("triage-detector-progress".into())
            .spawn(move || watch_progress(&path, &cancel, &stop, &tx))
            .ok()
    });
    let mut attempted = false;
    let result = (|| {
        let (staged, _snapshots, mut read_only) = stage(request.clone(), &work, cancel)?;
        read_only.push(executable.to_path_buf());
        let input = work.join("request.json");
        crate::storage::atomic_json(&input, &staged)?;
        let output = work.join("report.json");
        attempted = true;
        super::super::jobs::run_sandboxed(
            executable,
            &[
                "--antinomie-detection-worker".into(),
                text(&input)?,
                text(&output)?,
            ],
            &work,
            &read_only,
            &[("ANTINOMIE_ISOLATED_WORKER", "1")],
            Duration::from_secs(180),
            cancel,
        )?;
        let data = read_bounded(&work, Path::new("report.json"), REPORT_LIMIT)?;
        let mut report: Report =
            serde_json::from_slice(&data).map_err(|error| error.to_string())?;
        validate_report(&report, &request)?;
        merge_staged_warnings(&mut report, &staged.warnings);
        Ok(report)
    })();
    let directory = result_directory(&request.directory, request.engine);
    let diagnostics = if attempted {
        fs::read_dir(&work)
            .map_err(|error| error.to_string())
            .and_then(|entries| {
                let entries = entries
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
                let log = entries
                    .into_iter()
                    .find(|entry| {
                        entry.file_name().to_str().is_some_and(|name| {
                            name.starts_with("ghidra-") && name.ends_with(".log")
                        })
                    })
                    .ok_or("Sandbox diagnostics log is unavailable")?;
                read_bounded(&work, &log.path(), 2 * 1024 * 1024)
            })
            .and_then(|data| {
                crate::storage::private_dir(&directory).map_err(|error| error.to_string())?;
                fs::write(directory.join("worker.log"), data).map_err(|error| error.to_string())
            })
    } else {
        Ok(())
    };
    let result = match (result, diagnostics) {
        (Ok(mut report), Err(error)) => {
            report
                .warnings
                .push(format!("Detector diagnostics unavailable: {error}"));
            Ok(report)
        }
        (Err(error), Err(log)) => Err(format!("{error}; detector diagnostics unavailable: {log}")),
        (Err(error), Ok(())) if attempted => Err(format!(
            "{error}; retained detector log: {}",
            directory.join("worker.log").display()
        )),
        (result, Ok(())) => result,
    };
    stop_progress.store(true, Ordering::Relaxed);
    if let Some(watcher) = progress_watcher.flatten() {
        let _ = watcher.join();
    }
    let result = match (result, fs::remove_dir_all(&work)) {
        (Ok(mut report), Err(error)) => {
            report
                .warnings
                .push(format!("Temporary detector output cleanup failed: {error}"));
            Ok(report)
        }
        (Err(error), Err(cleanup)) => Err(format!("{error}; detector cleanup: {cleanup}")),
        (result, Ok(())) => result,
    };
    result.map(|report| commit_provenance(&request, &directory, report))
}

fn commit_provenance(request: &Request, directory: &Path, mut report: Report) -> Report {
    let needs_manifest = !request.settings.rules_root.is_empty() && !report.selection.is_empty();
    let manifest_path = directory.join("selection-manifest.json");
    let mut manifest_error = None;
    if needs_manifest {
        let engine = match request.engine {
            Engine::Yara => "yara",
            Engine::Ids => "ids",
            Engine::Sigma => "sigma",
        };
        let source = Path::new(&request.settings.rules_root)
            .join("rules/profiles")
            .join(engine)
            .join(&report.selection)
            .join("manifest.json");
        if provenance_failed("manifest-read") {
            manifest_error =
                Some("Could not read selection manifest: injected read failure".into());
        } else if !source.is_file() {
            manifest_error = Some(format!(
                "Could not read selection manifest: {} is missing",
                source.display()
            ));
        } else {
            match fs::read(&source).and_then(|data| {
                serde_json::from_slice::<serde_json::Value>(&data)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            }) {
                Ok(mut manifest) => {
                    manifest["evidence_key"] =
                        serde_json::Value::String(report.evidence_key.clone());
                    manifest["report_engine"] =
                        serde_json::json!(format!("{:?}", request.engine).to_ascii_lowercase());
                    manifest["run_id"] = serde_json::json!(request.identity.run_id);
                    manifest["vm_id"] = serde_json::json!(request.identity.vm_id);
                    manifest["boot_id"] = serde_json::json!(request.identity.boot_id);
                    manifest["root_cookie"] = serde_json::json!(request.identity.root_cookie);
                    if provenance_failed("manifest-write") {
                        manifest_error = Some(
                            "Could not save selection manifest: injected write failure".into(),
                        );
                    } else if let Err(error) = crate::storage::private_dir(directory)
                        .map_err(|error| error.to_string())
                        .and_then(|()| crate::storage::atomic_json(&manifest_path, &manifest))
                    {
                        manifest_error =
                            Some(format!("Could not save selection manifest: {error}"));
                    }
                }
                Err(error) => {
                    manifest_error = Some(format!("Could not read selection manifest: {error}"));
                }
            }
        }
    }
    if let Some(error) = manifest_error {
        report.warnings.push(error);
        report.provenance_saved = Some(false);
        if report.state == State::Complete {
            report.state = State::Partial;
        }
        return report;
    }
    report.provenance_saved = Some(true);
    let previous_report = fs::read(directory.join("report.json")).ok();
    let previous_manifest = fs::read(&manifest_path).ok();
    let write_error = if provenance_failed("report-write") {
        Some("injected write failure".to_owned())
    } else {
        crate::storage::private_dir(directory)
            .map_err(|error| error.to_string())
            .and_then(|()| crate::storage::atomic_json(&directory.join("report.json"), &report))
            .err()
    };
    if let Some(error) = write_error {
        report
            .warnings
            .push(format!("Could not save detector result: {error}"));
        report.provenance_saved = Some(false);
        if report.state == State::Complete {
            report.state = State::Partial;
        }
        if needs_manifest {
            match previous_manifest {
                Some(bytes) => {
                    let _ = fs::write(&manifest_path, bytes);
                }
                None => {
                    let _ = fs::remove_file(&manifest_path);
                }
            }
        }
        if let Some(bytes) = previous_report {
            let _ = fs::write(directory.join("report.json"), bytes);
        }
    }
    report
}

/// Load a retained engine report after checking its run identity and bounds.
pub fn load(request: &Request) -> Result<Report, String> {
    validate_run(request)?;
    let directory = result_directory(&request.directory, request.engine);
    let data = read_bounded(&directory, Path::new("report.json"), REPORT_LIMIT)?;
    let report = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    validate_report(&report, request)?;
    Ok(report)
}

/// Read a bounded byte preview only from evidence owned by the selected run.
pub fn read_evidence(request: &Request, evidence: &Evidence) -> Result<Vec<u8>, String> {
    use std::io::{Seek, SeekFrom};
    validate_run(request)?;
    let Evidence::Bytes {
        path,
        offset: Some(offset),
        report_id,
        block,
        ..
    } = evidence
    else {
        return Err("This match has no byte location".into());
    };
    if let Some(id) = report_id {
        if *path != request.directory.join("analysis/specimen") {
            return Err("Specimen evidence path mismatch".into());
        }
        let directory = request.directory.join("analysis");
        let report = super::super::jobs::open_report(&directory)?;
        if block.as_ref().is_none_or(|block| {
            report
                .specimen_sha256
                .as_ref()
                .is_none_or(|sha| !sha.eq_ignore_ascii_case(&block.sha256))
        }) {
            return Err(
                "Specimen identity changed since this rule matched; rescan this run".into(),
            );
        }
        let len = report
            .specimen_len
            .ok_or("Specimen size unavailable")?
            .saturating_sub(*offset)
            .min(256) as usize;
        if len == 0 {
            return Err("Byte location is outside specimen".into());
        }
        return super::super::specimen::read_specimen_range(&directory, id, *offset, len)
            .map(|page| page.data);
    }
    let artifacts = owned_artifacts(request)?.ok_or("Run artifacts unavailable")?;
    let anchor = if artifacts.core_dump.as_ref() == Some(path) {
        path.parent().map(Path::to_path_buf)
    } else {
        artifacts.memory_dump.filter(|root| {
            path.strip_prefix(root).is_ok_and(|relative| {
                relative == Path::new("memory.elf")
                    || relative
                        .components()
                        .any(|component| component.as_os_str() == "files")
            })
        })
    };
    let anchor = anchor.ok_or("Bytes do not belong to a recorded run artifact")?;
    let mut file =
        crate::archive_io::open_regular(&anchor, path).map_err(|error| error.to_string())?;
    let block = block
        .as_ref()
        .ok_or("This older match has no retained byte digest; rescan before previewing")?;
    if block.size > 64 * 1024 * 1024
        || *offset < block.offset
        || offset
            .checked_sub(block.offset)
            .is_none_or(|relative| relative >= block.size)
    {
        return Err("Byte location exceeds its verified block".into());
    }
    file.seek(SeekFrom::Start(block.offset))
        .map_err(|error| error.to_string())?;
    let mut data = Vec::new();
    file.take(block.size + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    data.truncate(block.size as usize);
    if data.len() as u64 != block.size || crate::storage::sha256_hex(&data) != block.sha256 {
        return Err("Retained bytes changed since this rule matched; rescan this run".into());
    }
    let relative = (*offset - block.offset) as usize;
    Ok(data[relative..data.len().min(relative + 256)].to_vec())
}

pub fn result_directory(run: &Path, engine: Engine) -> PathBuf {
    run.join("triage-detection").join(match engine {
        Engine::Yara => "yara",
        Engine::Ids => "ids",
        Engine::Sigma => "sigma",
    })
}

pub(super) struct ProgressWriter {
    path: PathBuf,
    rules_loaded: u64,
    coalescer: super::ProgressCoalescer,
}

impl ProgressWriter {
    pub(super) fn new(work: &Path) -> Self {
        Self {
            path: work.join("progress.json"),
            rules_loaded: 0,
            coalescer: super::ProgressCoalescer::new(Duration::from_millis(250)),
        }
    }

    pub(super) fn set_rules(&mut self, count: u64) {
        self.rules_loaded = count;
    }

    pub(super) fn stage(&mut self, target: ScanTarget) {
        let progress = ScanProgress {
            target,
            rules_loaded: self.rules_loaded,
        };
        self.coalescer.force(Instant::now());
        write_progress(&self.path, &progress);
    }

    pub(super) fn note(&mut self, target: ScanTarget) {
        let progress = ScanProgress {
            target,
            rules_loaded: self.rules_loaded,
        };
        if let Some(progress) = self.coalescer.push(progress, Instant::now()) {
            write_progress(&self.path, &progress);
        }
    }

    pub(super) fn flush(&mut self) {
        if let Some(progress) = self.coalescer.poll(Instant::now() + Duration::from_secs(1)) {
            write_progress(&self.path, &progress);
        }
    }
}

pub(super) fn write_progress(path: &Path, progress: &ScanProgress) {
    let _ = crate::storage::atomic_json(path, progress);
}

/// Reads `progress.json` until `cancel` or `stop`. Cancellation closes the
/// phase channel without another update.
fn watch_progress(
    path: &Path,
    cancel: &AtomicBool,
    stop: &AtomicBool,
    tx: &std::sync::mpsc::Sender<ScanProgress>,
) {
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    let mut seen = Vec::<u8>::new();
    while !stop.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
        if let Ok(bytes) = fs::read(path)
            && bytes != seen
        {
            seen = bytes;
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            if let Ok(progress) = serde_json::from_slice::<ScanProgress>(&seen)
                && tx.send(progress).is_err()
            {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

fn sigma(staged: &Staged, work: &Path) -> Result<Report, String> {
    if staged.no_rules || staged.sigma_sources.is_empty() && staged.warnings.is_empty() {
        let mut report = Report::empty(Engine::Sigma, staged.request.identity.clone());
        report.state = State::NoRules;
        report.warnings.push("No rules enabled".into());
        report.selection = staged.selection.clone();
        return Ok(report);
    }
    if staged.sigma_sources.is_empty() {
        let mut report = Report::unavailable(
            Engine::Sigma,
            staged.request.identity.clone(),
            "No compatible Sigma rules were evaluated.",
        );
        report.selection = staged.selection.clone();
        return Ok(report);
    }
    let original = staged.request.directory.join(JOURNAL_FILE);
    let Some(journal) = &staged.journal else {
        let mut report = Report::empty(Engine::Sigma, staged.request.identity.clone());
        report.state = State::Missing;
        report
            .warnings
            .push("Evidence missing: the captured event journal is not ready.".into());
        report.input(
            super::ScannedInput::new(super::InputKind::EventJournal, &original)
                .skipped("the captured event journal is not ready"),
        );
        if staged.request.settings.partial {
            report.state = State::Partial;
            report
                .warnings
                .push("Partial: this scan used an incomplete event prefix.".into());
        }
        return Ok(report);
    };
    let script = work.join("sigma_scan.py");
    fs::write(&script, include_bytes!("../../../assets/sigma_scan.py"))
        .map_err(|error| error.to_string())?;
    let input = work.join("sigma-request.json");
    crate::storage::atomic_json(&input, staged)?;
    let output = work.join("sigma-report.json");
    let python = crate::ruleset::sigma_interpreter(&staged.request.settings.sigma_python);
    let python = text(&python)?;
    let result = super::super::tools::run_with(
        &python,
        &[
            "-I",
            &text(&script)?,
            &text(journal)?,
            &text(&input)?,
            &text(&output)?,
        ],
        &[],
        Duration::from_secs(110),
        64 * 1024,
        true,
    )?;
    let input = super::inputs::journal_input(
        &original,
        journal,
        staged.request.source_digest.as_deref(),
        staged.request.settings.partial,
    );
    if !result.success || result.timed_out {
        let mut report = Report::unavailable(
            Engine::Sigma,
            staged.request.identity.clone(),
            "Local Sigma adapter failed or timed out; inspect the detector log.",
        );
        report.input(input.skipped("the Sigma adapter failed or timed out"));
        return Ok(report);
    }
    let data = read_bounded(work, Path::new("sigma-report.json"), REPORT_LIMIT)?;
    let mut report: Report = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    report.inputs = Some(vec![input]);
    Ok(report)
}

/// Internal isolated-process entry point; no desktop or provider is opened.
pub fn worker_main_if_requested() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args
        .get(1)
        .is_none_or(|arg| arg != "--antinomie-detection-worker")
    {
        return None;
    }
    let result = (|| {
        if args.len() != 4 || std::env::var("ANTINOMIE_ISOLATED_WORKER").as_deref() != Ok("1") {
            return Err("detector worker requires isolation".into());
        }
        use rustix::process::{Resource, Rlimit, setrlimit};
        for (resource, maximum) in [(Resource::Fsize, 256 * 1024 * 1024), (Resource::Cpu, 150)] {
            setrlimit(
                resource,
                Rlimit {
                    current: Some(maximum),
                    maximum: Some(maximum),
                },
            )
            .map_err(|error| error.to_string())?;
        }
        let input = PathBuf::from(&args[2]);
        let work = input.parent().ok_or("detector input has no parent")?;
        let data = read_bounded(work, &input, REPORT_LIMIT)?;
        let staged: Staged = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
        let mut report = match staged.request.engine {
            Engine::Yara => super::yara::scan(&staged, work)?,
            Engine::Ids => super::ids::scan(&staged, work)?,
            Engine::Sigma => sigma(&staged, work)?,
        };
        if report.selection.is_empty() {
            report.selection = staged.selection.clone();
        }
        if report.evidence_key.is_empty() {
            report.evidence_key = staged.request.settings.evidence_key.clone();
        }
        if staged.request.settings.partial && report.state == State::Complete {
            report.state = State::Partial;
            report
                .warnings
                .push("Partial: this scan used evidence that was still being captured.".into());
        }
        merge_staged_warnings(&mut report, &staged.warnings);
        validate_report(&report, &staged.request)?;
        let data = serde_json::to_vec(&report).map_err(|error| error.to_string())?;
        if data.len() > REPORT_LIMIT {
            return Err("detector report exceeds 32 MiB".into());
        }
        fs::write(&args[3], data).map_err(|error| error.to_string())
    })();
    if let Err(error) = &result {
        eprintln!("detector worker: {error}");
    }
    Some(i32::from(result.is_err()))
}

/// Worker and parent may see the same selection diagnostics; merge idempotently.
fn merge_staged_warnings(report: &mut Report, warnings: &[String]) {
    if !warnings.is_empty() && report.state == State::Complete {
        report.state = State::Partial;
    }
    let mut seen = std::collections::BTreeSet::new();
    report
        .warnings
        .retain(|warning| seen.insert(warning.clone()));
    for warning in warnings {
        if seen.insert(warning.clone()) {
            report.warnings.push(warning.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_warnings_are_not_duplicated_between_worker_and_parent() {
        let mut report = Report::empty(
            Engine::Ids,
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        );
        report.skipped_rules = 26;
        report.warnings = vec!["engine warning".into(), "engine warning".into()];
        let staged: Vec<_> = (1..=26)
            .map(|sid| format!("sid {sid}: requires a TLS fingerprint keyword"))
            .collect();
        merge_staged_warnings(&mut report, &staged);
        let worker = report.warnings.clone();
        merge_staged_warnings(&mut report, &staged);
        assert_eq!(report.warnings, worker);
        assert_eq!(report.warnings.len(), 27);
        assert_eq!(report.warnings[0], "engine warning");
        assert_eq!(report.warnings[1], staged[0]);
        assert_eq!(report.warnings[26], staged[25]);
        assert_eq!(report.skipped_rules, 26);
        assert_eq!(report.state, State::Partial);
        merge_staged_warnings(&mut report, &["different capture warning".into()]);
        assert_eq!(report.warnings.len(), 28);
    }

    #[test]
    fn a_cancelled_progress_watch_publishes_nothing() {
        let cancel = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let started = Instant::now();
        watch_progress(Path::new("/no/such/progress.json"), &cancel, &stop, &tx);
        assert!(started.elapsed() < Duration::from_millis(200));
        drop(tx);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    #[ignore = "requires explicit built monitor executable and optional QA Python venv"]
    fn complete_job_driver_retains_reports_and_bounded_diagnostics() {
        let program = PathBuf::from(
            std::env::var_os("ANTINOMIE_DETECTION_QA_BINARY").expect("set the built monitor path"),
        );
        let python =
            std::env::var("ANTINOMIE_DETECTION_QA_PYTHON").expect("set QA venv/bin/python");
        let directory =
            std::env::temp_dir().join(format!("ant-detector-job-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&directory.join("analysis")).unwrap();
        let identity = Identity {
            vm_id: "v".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            root_cookie: 1,
        };
        crate::storage::atomic_json(
            &directory.join("run.json"),
            &serde_json::json!({"id":"r","vm_id":"v","boot_id":"b","root_task_cookie":1}),
        )
        .unwrap();
        let specimen = b"xxxFIXTURE_MARKER";
        fs::write(directory.join("analysis/specimen"), specimen).unwrap();
        crate::storage::atomic_json(&directory.join("analysis/report.json"), &serde_json::json!({"id":"fixture-artifact","state":"complete","source_path":"/fixture/sample","specimen_sha256":crate::storage::sha256_hex(specimen),"specimen_len":specimen.len(),"reason":null,"sections":[]})).unwrap();
        let rules = directory.join("fixture.yar");
        fs::write(
            &rules,
            "rule fixture { strings: $a = \"FIXTURE_MARKER\" condition: $a }",
        )
        .unwrap();
        let mut journal = EventJournal::new(&directory, &identity).unwrap();
        journal
            .push(Event {
                category: "process_creation".into(),
                fields: BTreeMap::from([("Image".into(), "/bin/sh".into())]),
                evidence: Evidence::Call {
                    stream: 1,
                    cookie: 1,
                    call: 1,
                },
            })
            .unwrap();
        journal.finish(true).unwrap();
        for engine in [Engine::Yara, Engine::Ids, Engine::Sigma] {
            let request = Request {
                engine,
                identity: identity.clone(),
                directory: directory.clone(),
                settings: Settings {
                    yara_rules: rules.display().to_string(),
                    sigma_python: python.clone(),
                    ..Default::default()
                },
                source_digest: None,
                frozen: None,
            };
            let report = run_program(
                request.clone(),
                &Arc::new(AtomicBool::new(false)),
                &program,
                None,
            )
            .unwrap();
            assert!(
                report
                    .warnings
                    .iter()
                    .all(|warning| !warning.contains("diagnostics unavailable")),
                "{:?}",
                report.warnings
            );
            assert!(
                result_directory(&directory, engine)
                    .join("worker.log")
                    .metadata()
                    .unwrap()
                    .len()
                    <= 2 * 1024 * 1024
            );
            assert_eq!(load(&request).unwrap().identity, identity);
            if engine != Engine::Ids {
                assert!(!report.findings.is_empty(), "{:?}", report);
            }
            eprintln!(
                "{engine:?}: {:?}; {} matched rules; saved report and diagnostics",
                report.state,
                report.findings.len()
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn byte_preview_rejects_changed_bytes_wrong_run_and_unowned_paths() {
        let directory = std::env::temp_dir().join(format!(
            "ant-detector-preview-{}",
            crate::storage::unique_id()
        ));
        let memory = directory.join("memory");
        crate::storage::private_dir(&memory.join("files")).unwrap();
        let path = memory.join("files/recovered");
        let data = b"0123456789";
        fs::write(&path, data).unwrap();
        let identity = Identity {
            vm_id: "v".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            root_cookie: 1,
        };
        crate::storage::atomic_json(
            &directory.join("run.json"),
            &serde_json::json!({"id":"r","vm_id":"v","boot_id":"b","root_task_cookie":1}),
        )
        .unwrap();
        crate::storage::atomic_json(&directory.join("artifacts.json"), &serde_json::json!({"run_id":"r","vm_id":"v","boot_id":"b","network_captures":[],"network_state":"complete","memory_dump":memory,"memory_state":"complete","core_dump":null,"core_state":"complete","issues":[]})).unwrap();
        let mut request = Request {
            engine: Engine::Yara,
            identity,
            directory: directory.clone(),
            settings: Settings::default(),
            source_digest: None,
            frozen: None,
        };
        let evidence = Evidence::Bytes {
            path: path.clone(),
            offset: Some(3),
            address: None,
            report_id: None,
            block: Some(ByteSource {
                offset: 0,
                size: data.len() as u64,
                sha256: crate::storage::sha256_hex(data),
            }),
        };
        assert_eq!(read_evidence(&request, &evidence).unwrap(), b"3456789");
        fs::write(&path, b"changed!!!").unwrap();
        assert!(
            read_evidence(&request, &evidence)
                .unwrap_err()
                .contains("changed")
        );
        request.identity.run_id = "other".into();
        assert!(
            read_evidence(&request, &evidence)
                .unwrap_err()
                .contains("identity")
        );
        request.identity.run_id = "r".into();
        let mut outside = evidence;
        if let Evidence::Bytes { path, .. } = &mut outside {
            *path = directory.join("unowned");
        }
        fs::write(directory.join("unowned"), data).unwrap();
        assert!(
            read_evidence(&request, &outside)
                .unwrap_err()
                .contains("belong")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn frozen_selection_is_copied_without_reading_the_live_registry() {
        let directory =
            std::env::temp_dir().join(format!("ant-frozen-{}", crate::storage::unique_id()));
        let frozen_dir = directory.join("frozen");
        crate::storage::private_dir(&frozen_dir).unwrap();
        fs::write(
            frozen_dir.join("kept.yar"),
            "rule Kept { condition: true }\n",
        )
        .unwrap();
        let work = directory.join("work");
        crate::storage::private_dir(&work).unwrap();
        let request = Request {
            engine: Engine::Yara,
            identity: Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
            directory: directory.clone(),
            settings: Settings {
                rules_root: directory.join("missing-registry").display().to_string(),
                ..Default::default()
            },
            source_digest: None,
            frozen: Some(FrozenSelection {
                digest: "frozen-digest".into(),
                directory: Some(frozen_dir),
                enabled_rules: 1,
                excluded_rules: 0,
                warnings: vec!["kept".into()],
            }),
        };
        let mut staged = Staged {
            request: request.clone(),
            sigma_sources: vec![],
            yara_sources: vec![],
            ids_sources: vec![],
            captures: vec![],
            journal: None,
            skipped_inputs: vec![],
            warnings: vec![],
            selection: String::new(),
            no_rules: false,
            include_dir: None,
        };
        let files = managed_sources(
            &request,
            &work,
            &["yar", "yara"],
            &AtomicBool::new(false),
            &mut staged,
        )
        .unwrap();
        assert_eq!(staged.selection, "frozen-digest");
        assert_eq!(files.len(), 1);
        assert!(work.join("selection/kept.yar").is_file());
        assert!(staged.warnings.iter().any(|warning| warning == "kept"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_manifest_write_failure_keeps_the_previous_report() {
        let root = std::env::temp_dir().join(format!("ant-prov-{}", crate::storage::unique_id()));
        let rules = root.join("rules");
        let profile = rules.join("profiles/yara/digest-1");
        fs::create_dir_all(&profile).unwrap();
        fs::write(
            profile.join("manifest.json"),
            br#"{"schema":1,"digest":"digest-1"}"#,
        )
        .unwrap();
        let directory = root.join("run");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("report.json"), b"{\"previous\":true}").unwrap();
        let request = Request {
            engine: Engine::Yara,
            identity: Identity {
                vm_id: "vm".into(),
                boot_id: "boot".into(),
                run_id: "run".into(),
                root_cookie: 7,
            },
            directory: directory.clone(),
            settings: Settings {
                rules_root: root.display().to_string(),
                evidence_key: "ready:test".into(),
                ..Default::default()
            },
            source_digest: None,
            frozen: None,
        };
        let mut report = Report::empty(Engine::Yara, request.identity.clone());
        report.selection = "digest-1".into();
        report.evidence_key = "ready:test".into();
        fail_provenance("manifest-write");
        let saved = commit_provenance(&request, &directory, report);
        assert_eq!(saved.provenance_saved, Some(false));
        assert_eq!(saved.state, State::Partial);
        assert!(
            saved
                .warnings
                .iter()
                .any(|warning| warning.contains("selection manifest")),
            "{:?}",
            saved.warnings
        );
        assert_eq!(
            fs::read(directory.join("report.json")).unwrap(),
            b"{\"previous\":true}"
        );
        assert!(!directory.join("selection-manifest.json").is_file());
        let committed = commit_provenance(&request, &directory, {
            let mut report = Report::empty(Engine::Yara, request.identity.clone());
            report.selection = "digest-1".into();
            report.evidence_key = "ready:test".into();
            report
        });
        assert_eq!(committed.provenance_saved, Some(true));
        assert_eq!(committed.state, State::Complete);
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join("selection-manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["run_id"], "run");
        assert_eq!(manifest["evidence_key"], "ready:test");
        let reopened =
            serde_json::from_slice::<Report>(&fs::read(directory.join("report.json")).unwrap())
                .unwrap();
        assert_eq!(reopened.selection, "digest-1");
        assert_eq!(reopened.provenance_saved, Some(true));
        fail_provenance("report-write");
        let interrupted = commit_provenance(&request, &directory, {
            let mut report = Report::empty(Engine::Yara, request.identity.clone());
            report.selection = "digest-1".into();
            report
        });
        assert_eq!(interrupted.provenance_saved, Some(false));
        assert_eq!(
            reopened.selection,
            serde_json::from_slice::<Report>(&fs::read(directory.join("report.json")).unwrap())
                .unwrap()
                .selection
        );
        let _ = fs::remove_dir_all(&root);
    }
}
