// SPDX-License-Identifier: GPL-3.0-only
//! Detection (YARA, IDS and Sigma) for one run, without a window (design 1.4
//! U4): the names the results are stored under, the run identity a result
//! belongs to, the evidence key that says which evidence a scan may read, the
//! scan request, and the rule selection frozen when a scan is admitted. The
//! engines run in the core (`antinomie_monitor_core::analysis::detection`);
//! the Detection tab that schedules and draws them is the GUI's.
use crate::TriageInput;
use antinomie_monitor_core::analysis::detection::Finding;
use antinomie_monitor_core::analysis::detection::{
    self as engine, Engine, FrozenSelection, Identity, Report, Request, ScanProgress, Settings,
};
use antinomie_monitor_core::ruleset;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The engines in the order the Detection tab and the digest list them.
pub const ENGINES: [Engine; 3] = [Engine::Yara, Engine::Ids, Engine::Sigma];

/// The engine's name in the digest, the report and on screen.
pub fn name(engine: Engine) -> &'static str {
    match engine {
        Engine::Yara => "YARA",
        Engine::Ids => "IDS",
        Engine::Sigma => "Sigma",
    }
}

/// The name the rules' folder and the managed selection use for `engine`.
pub fn engine_key(engine: Engine) -> &'static str {
    match engine {
        Engine::Yara => "yara",
        Engine::Ids => "ids",
        Engine::Sigma => "sigma",
    }
}

/// The rule pack a finding came from: the report's source it points at
/// (`s0`), else its own source without the digest (`Pack sha256:...`).
pub fn pack_name(report: &Report, finding: &Finding) -> String {
    let index = finding
        .source
        .strip_prefix('s')
        .and_then(|index| index.parse::<usize>().ok());
    if let Some(source) = index.and_then(|index| report.sources.get(index)) {
        return source.name.clone();
    }
    finding
        .source
        .split_once(" sha256:")
        .map_or(finding.source.as_str(), |(name, _)| name)
        .to_owned()
}

/// Where the selected run's event index (the Sigma journal) stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum IndexState {
    /// No run, or the index has not started.
    #[default]
    Unknown,
    /// Being built.
    Building,
    /// Built from a recording the VM still holds open and has not saved.
    Saving,
    /// The journal could not be written; the words say why.
    Failed(String),
    /// Built from a saved recording.
    Ready,
}

/// The run folder and identity a detection result of the run in `input`
/// belongs to; `None` without a saved recording or a run root.
pub fn identity(input: &TriageInput<'_>) -> Option<(PathBuf, Identity)> {
    input
        .archive
        .zip(input.vm_id.zip(input.boot_id).zip(input.run_id))
        .filter(|_| input.root_cookie != 0)
        .map(|(directory, ((vm, boot), run))| {
            (
                directory.to_path_buf(),
                Identity {
                    vm_id: vm.into(),
                    boot_id: boot.into(),
                    run_id: run.into(),
                    root_cookie: input.root_cookie,
                },
            )
        })
}

/// The scan request of `engine` for the run at `directory`, with no frozen
/// selection yet ([`freeze`] adds it at admission).
pub fn request(
    engine: Engine,
    (directory, identity): (&Path, &Identity),
    settings: &Settings,
    source_digest: Option<String>,
) -> Request {
    Request {
        engine,
        identity: identity.clone(),
        directory: directory.to_path_buf(),
        settings: settings.clone(),
        source_digest,
        frozen: None,
    }
}

/// The files the evidence key is made of: digests and whether they exist.
/// The GUI answers from its caches and computes a digest off its thread
/// (`None` until then); [`DiskFiles`] reads them now.
pub trait EvidenceFiles {
    /// The SHA-256 of the file at `path`, `missing` when it is not a regular
    /// file, `None` while it is being computed.
    fn digest(&mut self, path: &Path) -> Option<String>;
    /// Whether `path` is a regular file.
    fn present(&mut self, path: &Path) -> bool;
}

/// [`EvidenceFiles`] read from the disk when asked.
pub struct DiskFiles;

impl EvidenceFiles for DiskFiles {
    fn digest(&mut self, path: &Path) -> Option<String> {
        if !self.present(path) {
            return Some("missing".into());
        }
        Some(
            antinomie_monitor_core::storage::sha256_file_hex(path)
                .unwrap_or_else(|_| "unreadable".into()),
        )
    }

    fn present(&mut self, path: &Path) -> bool {
        std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
    }
}

/// The run is on a VM that is up and its recording is not saved yet (the
/// index has not seen it saved), so a scan would only see a prefix.
pub fn waits_for_saving(current_boot: bool, index: &IndexState) -> bool {
    current_boot
        && matches!(
            index,
            IndexState::Unknown | IndexState::Building | IndexState::Saving
        )
}

/// The evidence key of `engine` for the run in `input`: which evidence
/// generation a scan may read. `ready:...` when the evidence is there and
/// final; otherwise `wait:...`, `missing:...` or `failed:...` with the reason.
/// A saved result whose key and selection are the current ones is not
/// scanned again. `index` is where the run's event index stands, and
/// `current_boot` whether the VM boot that recorded the run is still up.
pub fn evidence_key(
    engine: Engine,
    input: &TriageInput<'_>,
    settings: &Settings,
    (index, current_boot): (&IndexState, bool),
    files: &mut dyn EvidenceFiles,
) -> String {
    match engine {
        Engine::Yara => {
            let Some(analysis) = input.analysis else {
                return "wait:sample".into();
            };
            let archive = match yara_archive(input, files) {
                Ok(archive) => archive,
                Err(wait) => return wait,
            };
            format!(
                "ready:yara:{}:{}:{archive}:mem={}:recovered={}",
                analysis.id,
                analysis.specimen_sha256.as_deref().unwrap_or(""),
                settings.scan_memory,
                settings.scan_recovered
            )
        }
        Engine::Ids => match (input.pcap, input.pcap_open) {
            (None, _) => "missing:pcap".into(),
            (Some(_), true) => "wait:pcap".into(),
            // The run's recording is not saved yet: the capture may still
            // be closing and the run's own totals are not written.
            (Some(_), false) if waits_for_saving(current_boot, index) => "wait:saved".into(),
            (Some(path), false) => {
                let Some(digest) = files.digest(path) else {
                    return "wait:digest".into();
                };
                format!(
                    "ready:pcap:{}:{digest}:{}",
                    path.display(),
                    input.run_id.unwrap_or("")
                )
            }
        },
        Engine::Sigma => {
            if !input.run_finished {
                return "wait:journal".into();
            }
            let Some(archive) = input.archive else {
                return format!("ready:journal:{}:no-archive", input.run_id.unwrap_or(""));
            };
            if *index == IndexState::Saving {
                return "wait:saved".into();
            }
            let journal = archive.join(engine::JOURNAL_FILE);
            if !files.present(&journal) {
                // No journal to scan: say why in words, never scan a
                // missing file.
                return match index {
                    IndexState::Failed(why) => format!("failed:index:{why}"),
                    IndexState::Ready => "missing:journal".into(),
                    _ => "wait:index".into(),
                };
            }
            let Some(digest) = files.digest(&journal) else {
                return "wait:digest".into();
            };
            format!("ready:journal:{}:{digest}", input.run_id.unwrap_or(""))
        }
    }
}

/// The part of the YARA evidence key that names the run's own files: the
/// artifact list, the event journal and the written-programs index, by digest
/// (`Err` with the wait key while a digest is being computed).
fn yara_archive(input: &TriageInput<'_>, files: &mut dyn EvidenceFiles) -> Result<String, String> {
    let Some(archive) = input.archive else {
        return Ok("no-archive".into());
    };
    let artifacts = files.digest(&archive.join("artifacts.json"));
    let journal = files.digest(&archive.join(engine::JOURNAL_FILE));
    // The programs the run wrote, once Triage has kept them.
    let written = files.digest(
        &archive
            .join(engine::written::FOLDER)
            .join(engine::written::INDEX),
    );
    match (artifacts, journal, written) {
        (Some(artifacts), Some(journal), Some(written)) => {
            Ok(format!("{artifacts}:{journal}:{written}"))
        }
        _ => Err("wait:digest".into()),
    }
}

/// The evidence key of `engine` for a saved, finished run ([`detect_saved`]:
/// the daemon's jobs and `antinomie-cli detect`). It is [`evidence_key`],
/// except for YARA over a run whose launch selected no guest static analysis
/// (every Auto-mode job): no analysis record will ever come, so instead of
/// waiting for one the key names the library sample the run executed, and the
/// scan reads that sample from the library in place of a guest specimen,
/// with what the run left (written programs, dumps, recovered files).
pub fn saved_evidence_key(
    engine: Engine,
    saved: &crate::SavedRun,
    settings: &Settings,
    files: &mut dyn EvidenceFiles,
) -> String {
    let input = saved.input();
    if engine != Engine::Yara || input.analysis.is_some() {
        return evidence_key(engine, &input, settings, (&IndexState::Ready, false), files);
    }
    let archive = match yara_archive(&input, files) {
        Ok(archive) => archive,
        Err(wait) => return wait,
    };
    let sample = saved
        .run
        .request
        .sample
        .as_ref()
        .map_or("none", |sample| sample.sha256.as_str());
    format!(
        "ready:yara:library:{sample}:{archive}:mem={}:recovered={}",
        settings.scan_memory, settings.scan_recovered
    )
}

/// The managed rule registry under `rules_root` (the data directory), its
/// indexes brought to the current layout first.
pub fn registry(rules_root: &Path) -> Result<ruleset::Registry, String> {
    ruleset::migrate_indexes(rules_root)?;
    ruleset::load_registry(rules_root)
}

/// Freeze the rule selection of `request`'s engine, as the scan is admitted:
/// the worker reads this copy and takes no snapshot of its own. A request
/// with no managed rules (`rules_root` empty) is left as it is.
pub fn freeze(
    request: &mut Request,
    registry: &ruleset::Registry,
    cancel: &Arc<AtomicBool>,
) -> Result<(), String> {
    if request.settings.rules_root.is_empty() {
        return Ok(());
    }
    let data_dir = PathBuf::from(&request.settings.rules_root);
    let _ = ruleset::reap_staging(&data_dir, Duration::from_secs(3600));
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let tools = ruleset::ToolConfig::from_sigma_setting(&request.settings.effective_sigma_python());
    let facts = ruleset::tool_facts(&tools);
    let snap = ruleset::snapshot_from(
        &data_dir,
        engine_key(request.engine),
        registry,
        &facts,
        Some(cancel),
    )?;
    request.frozen = Some(FrozenSelection {
        digest: snap.digest,
        directory: snap.directory,
        enabled_rules: snap.enabled_rules,
        excluded_rules: snap.excluded_rules,
        warnings: snap.warnings,
    });
    Ok(())
}

/// The detection settings of a process with no window: `settings.json`'s
/// (its defaults when there is none), with the data directory's managed
/// rules, as the GUI binds them.
pub fn headless_settings(data_dir: &Path) -> Result<Settings, String> {
    let mut settings = antinomie_monitor_core::settings::load(data_dir)?
        .unwrap_or_default()
        .triage_detection;
    settings.rules_root = data_dir.display().to_string();
    Ok(settings)
}

/// Whether the engine's result is saved in the run's folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// In `triage-detection/<engine>/`, as the Detection tab keeps it.
    Save,
    /// Nothing is written into the run's folder.
    Discard,
}

/// Run one engine over the run of `request` with no window: the registry,
/// the frozen selection, the scan. `progress` receives the scan's phases.
pub fn scan(
    mut request: Request,
    keep: Keep,
    cancel: &Arc<AtomicBool>,
    progress: Option<std::sync::mpsc::Sender<ScanProgress>>,
) -> Result<Report, String> {
    if !request.settings.rules_root.is_empty() {
        let registry = registry(Path::new(&request.settings.rules_root))?;
        freeze(&mut request, &registry, cancel)?;
    }
    match keep {
        Keep::Save => engine::run_with_progress(request, cancel, progress),
        Keep::Discard => engine::run_unsaved(request, cancel, progress),
    }
}

/// Why a scan waits, shown under its progress bar; empty for a key that
/// needs no words.
pub fn evidence_note(key: &str) -> String {
    match key {
        "wait:sample" => {
            "The scan starts once the sample file is verified (hash check pending).".into()
        }
        "wait:pcap" => "Waiting for the PCAP segment to finish.".into(),
        "wait:journal" => "Waiting for the run to finish its event journal.".into(),
        "wait:digest" => "Hashing retained evidence before the scan.".into(),
        "wait:saved" => "Waiting for the recording to be saved.".into(),
        "wait:index" => "Waiting for the run's event index to be built.".into(),
        "missing:journal" => {
            "The run's event journal was not built, so Sigma has nothing to scan. This is not a clean result.".into()
        }
        key if key.starts_with("failed:index:") => format!(
            "The run's event journal is incomplete: {}. Sigma was not run; this is not a clean result.",
            &key["failed:index:".len()..]
        ),
        "missing:pcap" => {
            "Collection disabled or no PCAP was saved. This is not a clean result.".into()
        }
        _ => String::new(),
    }
}

/// One engine's outcome over a saved run ([`detect_saved`]).
#[derive(Clone, Debug)]
pub enum Outcome {
    Scanned(Box<Report>),
    /// The evidence is not there or not final: the evidence key and its words.
    Skipped(String, String),
    Failed(String),
}

/// Run `engines` over the saved run `saved`, as the Detection tab does for the
/// run on screen and `detect` does on the command line: the same evidence key,
/// request and frozen rule selection, the same sandboxed engines.
/// `scan` is the run's finished index (the Sigma journal is built by it).
/// `note` receives one line per engine. Nothing is written into the run's
/// folder with [`Keep::Discard`]; [`Keep::Save`] keeps each result where the
/// Detection tab keeps it.
pub fn detect_saved(
    saved: &crate::SavedRun,
    finished: &crate::ArchiveScan,
    engines: &[Engine],
    settings: &Settings,
    keep: Keep,
    cancel: &Arc<AtomicBool>,
    note: &dyn Fn(&str),
) -> Result<Vec<(Engine, Outcome)>, String> {
    let input = saved.input();
    let (directory, identity) =
        identity(&input).ok_or_else(|| "the run has no recorded program to scan".to_owned())?;
    // The programs and libraries the run wrote go beside the run first, so
    // YARA reads them; a scan that keeps nothing leaves the folder alone.
    if matches!(keep, Keep::Save) && finished.whole_run {
        let _ = crate::written_export::export(
            &saved.run.directory,
            &finished.file_activity,
            finished.partial,
        );
    }
    let mut outcomes = Vec::new();
    for engine in engines {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let key = saved_evidence_key(*engine, saved, settings, &mut DiskFiles);
        if !key.starts_with("ready:") {
            let words = evidence_note(&key);
            note(&format!("{}: not scanned: {words}", name(*engine)));
            outcomes.push((*engine, Outcome::Skipped(key, words)));
            continue;
        }
        let mut engine_settings = settings.clone();
        engine_settings.evidence_key = key;
        engine_settings.partial = false;
        let request = request(*engine, (&directory, &identity), &engine_settings, None);
        note(&format!("{}: scanning", name(*engine)));
        let outcome = match scan(request, keep, cancel, None) {
            Ok(report) => Outcome::Scanned(Box::new(report)),
            Err(error) => Outcome::Failed(error),
        };
        outcomes.push((*engine, outcome));
    }
    Ok(outcomes)
}

/// Add the engines' results to the run's digest, as the GUI does once it shows
/// them: what `outcomes` scanned, and for the other engines what the recording
/// already keeps.
pub fn save_digest(
    saved: &crate::SavedRun,
    scan: &crate::ArchiveScan,
    settings: &Settings,
    outcomes: &[(Engine, Outcome)],
) -> Result<(), String> {
    let input = saved.input();
    let (directory, identity) =
        identity(&input).ok_or_else(|| "the run has no recorded program to scan".to_owned())?;
    let results =
        ENGINES.map(
            |wanted| match outcomes.iter().find(|(engine, _)| *engine == wanted) {
                Some((_, Outcome::Scanned(report))) => Some(Ok((**report).clone())),
                Some((_, Outcome::Failed(error))) => Some(Err(error.clone())),
                _ => engine::load(&request(wanted, (&directory, &identity), settings, None))
                    .ok()
                    .map(Ok),
            },
        );
    crate::digest::Update::of(scan, crate::digest::detections(&results)).write(&saved.run.directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Digests answered at once, with no file read.
    struct Fixed;

    impl EvidenceFiles for Fixed {
        fn digest(&mut self, _: &Path) -> Option<String> {
            Some("d".into())
        }

        fn present(&mut self, _: &Path) -> bool {
            true
        }
    }

    fn saved(analysis: bool) -> crate::SavedRun {
        let request = antinomie_monitor_core::ExecRequest {
            sample: Some(antinomie_monitor_core::samples::SampleRef {
                sha256: "ab".repeat(32),
                name: "dropper".into(),
            }),
            ..Default::default()
        };
        let mut run: antinomie_monitor_core::RunSummary =
            serde_json::from_value(serde_json::json!({
                "id": "r", "vm_id": "v", "boot_id": "b", "session_id": 1,
                "root_task_cookie": 7, "pid": 700, "request": request,
                "directory": "/runs/r", "terminal_eof": true,
                "state": "Finished", "recording_error": null, "started_ms": 1_000,
            }))
            .unwrap();
        if analysis {
            run.analysis = Some(
                serde_json::from_value(serde_json::json!({
                    "id": "a", "state": "complete", "source_path": "/tmp/x",
                    "specimen_sha256": "cd".repeat(32), "specimen_len": 1,
                    "reason": null, "sections": [],
                }))
                .unwrap(),
            );
        }
        crate::SavedRun::new(run, crate::TriageSettings::default())
    }

    #[test]
    fn a_saved_run_without_guest_analysis_is_ready_for_yara_by_its_library_sample() {
        let settings = Settings::default();
        let key = saved_evidence_key(Engine::Yara, &saved(false), &settings, &mut Fixed);
        assert!(
            key.starts_with(&format!("ready:yara:library:{}:", "ab".repeat(32))),
            "{key}"
        );
        // The window's key is unchanged: with no analysis record it waits.
        let run = saved(false);
        let input = run.input();
        let window = evidence_key(
            Engine::Yara,
            &input,
            &settings,
            (&IndexState::Ready, false),
            &mut Fixed,
        );
        assert_eq!(window, "wait:sample");
        // A run with a guest analysis keeps the key the window uses.
        let run = saved(true);
        let input = run.input();
        assert_eq!(
            saved_evidence_key(Engine::Yara, &run, &settings, &mut Fixed),
            evidence_key(
                Engine::Yara,
                &input,
                &settings,
                (&IndexState::Ready, false),
                &mut Fixed
            )
        );
    }
}
