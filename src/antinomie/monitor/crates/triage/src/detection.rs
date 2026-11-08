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
            let archive = match input.archive {
                Some(archive) => {
                    let artifacts = files.digest(&archive.join("artifacts.json"));
                    let journal = files.digest(&archive.join(engine::JOURNAL_FILE));
                    match (artifacts, journal) {
                        (Some(artifacts), Some(journal)) => format!("{artifacts}:{journal}"),
                        _ => return "wait:digest".into(),
                    }
                }
                None => "no-archive".into(),
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
