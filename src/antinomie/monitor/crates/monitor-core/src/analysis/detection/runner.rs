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
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub engine: Engine,
    pub identity: Identity,
    pub directory: PathBuf,
    pub settings: Settings,
    pub source_digest: Option<String>,
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
        let data = read_bounded(&anchor, &source, 1024 * 1024)?;
        total += data.len();
        if total > 32 * 1024 * 1024 {
            return Err("local rule source exceeds 32 MiB".into());
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

fn builtin(work: &Path, file: &str, data: &[u8], name: &str) -> Result<RuleFile, String> {
    let path = work.join(file);
    fs::write(&path, data).map_err(|error| error.to_string())?;
    Ok(RuleFile {
        path,
        name: name.into(),
        sha256: crate::storage::sha256_hex(data),
    })
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
        warnings: vec![],
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
    let mut snapshots = Vec::new();
    let mut read_only = vec![request.directory.clone()];
    match request.engine {
        Engine::Yara => {
            staged.yara_sources = extra;
            if let Some(artifacts) = owned_artifacts(&request)? {
                if request.settings.scan_memory || request.settings.scan_recovered {
                    if let Some(directory) = artifacts.memory_dump {
                        read_only.push(directory);
                    }
                    if let Some(core) = artifacts.core_dump {
                        read_only.push(core);
                    }
                }
            }
        }
        Engine::Ids => {
            staged.ids_sources.push(builtin(
                work,
                "antinomie.rules",
                include_bytes!("../../../assets/rules/antinomie-ids.rules"),
                "Antinomie IDS 0.6.2 / MIT",
            )?);
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
                    }
                }
            }
        }
        Engine::Sigma => {
            staged.sigma_sources.push(builtin(
                work,
                "antinomie-sigma.yml",
                include_bytes!("../../../assets/rules/antinomie-sigma.yml"),
                "Antinomie Sigma 0.6.2 / MIT",
            )?);
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
            if !request.settings.sigma_python.is_empty() {
                let python = host_path(&request.settings.sigma_python);
                let root = python
                    .parent()
                    .and_then(Path::parent)
                    .filter(|root| root.join("pyvenv.cfg").is_file());
                read_only.push(root.map_or_else(|| python.clone(), Path::to_path_buf));
                request.settings.sigma_python = text(&python)?;
            }
        }
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
    let mut evidence_count = 0usize;
    for finding in &report.findings {
        evidence_count += finding.evidence.len();
        if finding.rule_id.len() > 8192
            || finding.title.len() > 8192
            || finding.details.len() > 8192
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
pub fn run(mut request: Request, cancel: &Arc<AtomicBool>) -> Result<Report, String> {
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
    let result = (|| {
        let (staged, _snapshots, mut read_only) = stage(request.clone(), &work, cancel)?;
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        read_only.push(executable.clone());
        let input = work.join("request.json");
        crate::storage::atomic_json(&input, &staged)?;
        let output = work.join("report.json");
        super::super::jobs::run_sandboxed(
            &executable,
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
        if !staged.warnings.is_empty() && report.state == State::Complete {
            report.state = State::Partial;
        }
        report.warnings.extend(staged.warnings);
        let directory = result_directory(&request.directory, request.engine);
        match crate::storage::private_dir(&directory)
            .map_err(|error| error.to_string())
            .and_then(|()| {
                crate::storage::atomic_json(&directory.join("report.json"), &report)
                    .map_err(|error| error.to_string())
            }) {
            Ok(()) => {}
            Err(error) => report
                .warnings
                .push(format!("Could not save detector result: {error}")),
        }
        Ok(report)
    })();
    let directory = result_directory(&request.directory, request.engine);
    let diagnostics =
        read_bounded(&work, Path::new("worker.log"), 2 * 1024 * 1024).and_then(|data| {
            crate::storage::private_dir(&directory).map_err(|error| error.to_string())?;
            fs::write(directory.join("worker.log"), data).map_err(|error| error.to_string())
        });
    let result = match (result, diagnostics) {
        (Ok(mut report), Err(error)) => {
            report
                .warnings
                .push(format!("Detector diagnostics unavailable: {error}"));
            Ok(report)
        }
        (Err(error), Err(log)) => Err(format!("{error}; detector diagnostics unavailable: {log}")),
        (result, Ok(())) => result,
    };
    match (result, fs::remove_dir_all(&work)) {
        (Ok(mut report), Err(error)) => {
            report
                .warnings
                .push(format!("Temporary detector output cleanup failed: {error}"));
            Ok(report)
        }
        (Err(error), Err(cleanup)) => Err(format!("{error}; detector cleanup: {cleanup}")),
        (result, Ok(())) => result,
    }
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

fn sigma(staged: &Staged, work: &Path) -> Result<Report, String> {
    let Some(journal) = &staged.journal else {
        return Ok(Report::unavailable(
            Engine::Sigma,
            staged.request.identity.clone(),
            "Refresh triage to produce a captured-event index.",
        ));
    };
    let script = work.join("sigma_scan.py");
    fs::write(&script, include_bytes!("../../../assets/sigma_scan.py"))
        .map_err(|error| error.to_string())?;
    let input = work.join("sigma-request.json");
    crate::storage::atomic_json(&input, staged)?;
    let output = work.join("sigma-report.json");
    let python = if staged.request.settings.sigma_python.is_empty() {
        "/usr/bin/python3"
    } else {
        &staged.request.settings.sigma_python
    };
    let result = super::super::tools::run_with(
        python,
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
    if !result.success || result.timed_out {
        return Ok(Report::unavailable(
            Engine::Sigma,
            staged.request.identity.clone(),
            "Local Sigma adapter failed or timed out; inspect the detector log.",
        ));
    }
    let data = read_bounded(work, Path::new("sigma-report.json"), REPORT_LIMIT)?;
    serde_json::from_slice(&data).map_err(|error| error.to_string())
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
        let report = match staged.request.engine {
            Engine::Yara => super::yara::scan(&staged, work)?,
            Engine::Ids => super::ids::scan(&staged, work)?,
            Engine::Sigma => sigma(&staged, work)?,
        };
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
