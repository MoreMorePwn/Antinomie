// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use antinomie_monitor_core::analysis::detection::{
    self as engine, Engine, Evidence, Finding, Identity, Report, State,
};
use std::path::{Path, PathBuf};

mod cards;
mod coverage;
mod finding;
mod header;
pub(in crate::triage) use header::ScanActivity;
mod inputs;
mod journal;
mod selection;

use cards::{card_summary, match_cards, severity_color};
use finding::{byte_preview, evidence_list, evidence_values, WindowKey};
use selection::SelectionDigests;

const FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("finding.rule", "Engine rule identifier"),
    FieldSpec::text("finding.title", "Rule title"),
    FieldSpec::text("finding.severity", "Rule-supplied severity"),
    FieldSpec::text("finding.source", "Rule namespace or local source"),
    FieldSpec::text("finding.license", "Rule license metadata"),
    FieldSpec::text("finding.author", "Authors supplied by the rule"),
    FieldSpec::tags("finding.mitre", "Rule-supplied ATT&CK references"),
    FieldSpec::number("finding.count", "Matched events or byte targets/blocks"),
    FieldSpec::text("finding.engine", "YARA, IDS or Sigma"),
    FieldSpec::number("stream.id", "Original syscall stream"),
    FieldSpec::number("process.cookie", "Original stable task identity"),
    FieldSpec::number("event.id", "Original syscall invocation"),
    FieldSpec::number("frame.number", "Original packet frame"),
    FieldSpec::text("capture.path", "Owning capture segment"),
    FieldSpec::text("evidence.path", "Retained byte source"),
    FieldSpec::number(
        "evidence.offset",
        "Matched file offset; missing for file-level conditions",
    ),
    FieldSpec::number("evidence.address", "Known process virtual address"),
    FieldSpec::text("evidence.report", "Retained specimen report identity"),
    FieldSpec::text("evidence.block", "Verified scanned block digest and extent"),
];
const HEADERS: &[&str] = &[
    "Rule",
    "Title",
    "Severity",
    "Occurrences",
    "MITRE",
    "Source",
    "License",
    "Author",
];
const ENGINES: [Engine; 3] = [Engine::Yara, Engine::Ids, Engine::Sigma];
const TABLES: [&str; 3] = ["triage-yara", "triage-ids", "triage-sigma"];
pub(super) fn name(engine: Engine) -> &'static str {
    match engine {
        Engine::Yara => "YARA",
        Engine::Ids => "IDS",
        Engine::Sigma => "Sigma",
    }
}
fn attribution(author: &str) -> &str {
    if author.is_empty() {
        "unknown"
    } else {
        author
    }
}

fn evidence_note(key: &str) -> String {
    match key {
        "wait:sample" => "Waiting for the verified sample.".into(),
        "wait:pcap" => "Waiting for the PCAP segment to finish.".into(),
        "wait:journal" => "Waiting for the run to finish its event journal.".into(),
        "wait:digest" => "Hashing retained evidence before the scan.".into(),
        "missing:pcap" => {
            "Collection disabled or no PCAP was saved. This is not a clean result.".into()
        }
        _ => String::new(),
    }
}

#[derive(Clone, Default)]
struct AttemptBudget {
    attempts: u8,
    key: String,
    ready_at: Option<std::time::Instant>,
}

impl AttemptBudget {
    fn observe(&mut self, key: &str) {
        if self.key != key {
            self.key = key.to_owned();
            self.attempts = 0;
            self.ready_at = None;
        }
    }

    fn allow(&self, now: std::time::Instant) -> bool {
        self.attempts < 3 && self.ready_at.is_none_or(|at| now >= at)
    }

    /// Counts this admission. A later failure does not add another count.
    fn admit(&mut self, now: std::time::Instant) {
        self.attempts = self.attempts.saturating_add(1);
        let pause = Duration::from_millis(400 * u64::from(self.attempts));
        self.ready_at = Some(now + pause);
    }

    fn automatic_success(&mut self) {
        self.attempts = 0;
        self.ready_at = None;
    }
}

/// How long the size and time of an evidence file are trusted before the
/// disk is asked again. Detection looks at them every frame.
const STAT_KEEP: Duration = Duration::from_secs(1);

struct FileDigest {
    len: u64,
    modified: u128,
    digest: String,
}

fn engine_key(engine: Engine) -> &'static str {
    match engine {
        Engine::Yara => "yara",
        Engine::Ids => "ids",
        Engine::Sigma => "sigma",
    }
}
type Loaded = [Option<Report>; 3];
type BytePreview = Result<(Evidence, Vec<u8>), String>;
pub(super) struct Counts {
    pub rules: u64,
    pub occurrences: u128,
    references: std::collections::BTreeSet<String>,
}
enum Reply {
    Loaded {
        epoch: u64,
        loaded: Box<Loaded>,
    },
    Scanned {
        epoch: u64,
        generation: u64,
        index: usize,
        result: Box<Result<Report, String>>,
    },
}

struct RegistryMsg {
    epoch: u64,
    result: Result<RegistryPayload, String>,
}

struct RegistryPayload {
    registry: antinomie_monitor_core::ruleset::Registry,
    sets: [Vec<antinomie_monitor_core::ruleset::EngineSet>; 3],
}

struct PendingScan {
    engine: Engine,
    digest: Option<String>,
    partial: bool,
    evidence_key: String,
    automatic: bool,
    generation: u64,
    epoch: u64,
}

enum Admit {
    Started,
    Preparing,
    Failed,
}

#[derive(Default)]
pub(super) struct View {
    pub settings: engine::Settings,
    pub selected: Engine,
    identity: Option<(PathBuf, Identity)>,
    pub results: [Option<Result<Report, String>>; 3],
    pub counts: [Option<Counts>; 3],
    pub references: std::collections::BTreeSet<String>,
    rows: [Vec<Vec<Cell>>; 3],
    filtered: [Vec<Vec<Cell>>; 3],
    applied: [Option<String>; 3],
    rx: Option<Receiver<Reply>>,
    cancel: Option<Arc<AtomicBool>>,
    busy: Option<usize>,
    byte_rx: Option<Receiver<BytePreview>>,
    bytes: Option<BytePreview>,
    pending_byte: Option<Evidence>,
    pub automatic: bool,
    pub profile: String,
    pub open_manager: bool,
    /// A rule the Matches table is to be filtered to when it next shows (set
    /// by the sample window, which opens a run on one rule's hit).
    pending_rule: Option<String>,
    pub rules_generation: u64,
    seen_generation: u64,
    auto_key: [String; 3],
    scanned_generation: [u64; 3],
    notes: [String; 3],
    budgets: [AttemptBudget; 3],
    auto_started: [bool; 3],
    digests: std::collections::BTreeMap<String, FileDigest>,
    /// Size and modification time of evidence files, with when they were read.
    stats: std::collections::BTreeMap<String, (Instant, Option<(u64, u128)>)>,
    digest_rx: Option<Receiver<(String, u64, u128, String)>>,
    digest_cache: [String; 3],
    digest_generation: u64,
    /// The selection digests being computed off the UI thread.
    selection_rx: Option<Receiver<SelectionDigests>>,
    /// Tool facts the cached digests were computed with.
    digest_facts: Option<antinomie_monitor_core::ruleset::ToolFacts>,
    ready_key: [String; 3],
    pub(super) registry: Option<antinomie_monitor_core::ruleset::Registry>,
    pub(super) registry_for: u64,
    registry_rx: Option<Receiver<RegistryMsg>>,
    pending: Option<PendingScan>,
    epoch: u64,
    phase: [String; 3],
    progress: [Option<engine::ScanProgress>; 3],
    progress_rx: Option<Receiver<engine::ScanProgress>>,
    sets: [Vec<antinomie_monitor_core::ruleset::EngineSet>; 3],
    /// Whether each engine's rule-set list is expanded.
    sets_open: [bool; 3],
    /// Whether each engine's scanned-input list is expanded.
    inputs_open: [bool; 3],
    /// Which captures and cores in the scanned-input list are gone from disk.
    presence: inputs::Presence,
    /// Findings whose Details window is open.
    windows: Vec<WindowKey>,
    /// The read-only viewer of the normalized event journal.
    journal: journal::Viewer,
    /// Converts guest times in the viewer, from the selected recording.
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
}

/// An input's caveat above the findings: how Sigma events are converted is a
/// plain note, anything else an input says (an IDS limit) stays a warning.
fn input_note(ui: &mut egui::Ui, text: &str) {
    if text == antinomie_monitor_core::analysis::detection::SIGMA_COVERAGE_WARNING {
        ui.add(egui::Label::new(egui::RichText::new(text).color(theme::text())).wrap());
    } else {
        crate::activity::warning(ui, text);
    }
}

impl View {
    /// Saved evidence was deleted: look at the listed captures and cores again.
    pub(super) fn evidence_deleted(&mut self) {
        self.presence.invalidate();
    }
    fn reset(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.epoch = self.epoch.wrapping_add(1);
        self.rx = None;
        self.busy = None;
        self.pending = None;
        self.registry_rx = None;
        self.byte_rx = None;
        self.pending_byte = None;
        self.bytes = None;
        self.windows.clear();
        self.journal.close();
        self.results = Default::default();
        self.counts = Default::default();
        self.references.clear();
        self.stats.clear();
        self.presence.invalidate();
        self.rows = Default::default();
        self.filtered = Default::default();
        self.applied = Default::default();
        self.auto_key = Default::default();
        self.notes = Default::default();
        self.budgets = Default::default();
        self.auto_started = Default::default();
        for phase in &mut self.phase {
            if !phase.is_empty() {
                *phase = "canceled".into();
            }
        }
        self.progress = Default::default();
        self.progress_rx = None;
        // Installed rule configuration is independent of the selected run.
        // Keep its set rows with the cached registry; otherwise a run change
        // shows zero enabled sets while fresh_registry still accepts the cache.
    }
    fn request(&self, engine: Engine, digest: Option<String>) -> Option<engine::Request> {
        self.identity
            .as_ref()
            .map(|(directory, identity)| engine::Request {
                engine,
                identity: identity.clone(),
                directory: directory.clone(),
                settings: self.settings.clone(),
                source_digest: digest,
                frozen: None,
            })
    }
    pub(super) fn rows(&mut self, index: usize) {
        self.counts[index] = self.results[index]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .filter(|report| report.state != State::Unavailable || !report.findings.is_empty())
            .map(|report| Counts {
                rules: report.findings.len() as u64,
                occurrences: report
                    .findings
                    .iter()
                    .map(|finding| u128::from(finding.count))
                    .sum(),
                references: report
                    .findings
                    .iter()
                    .flat_map(|finding| &finding.mitre)
                    .cloned()
                    .collect(),
            });
        self.references = self
            .counts
            .iter()
            .flatten()
            .flat_map(|counts| &counts.references)
            .cloned()
            .collect();
        self.applied[index] = None;
        self.rows[index] = self.results[index]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|report| {
                report
                    .findings
                    .iter()
                    .map(|finding| {
                        let mut row = vec![
                            cell(&finding.rule_id, theme::text(), true),
                            cell(&finding.title, theme::text(), false),
                            cell(&finding.severity, severity_color(&finding.severity), false),
                            cell(finding.count.to_string(), theme::text(), true),
                            cell(finding.mitre.join(", "), theme::text(), true),
                            cell(&finding.source, theme::text(), false),
                            cell(&finding.license, theme::muted(), false),
                            cell(attribution(&finding.author), theme::text(), false),
                        ];
                        row[0].values = vec![
                            ("finding.rule", RowValue::Text(finding.rule_id.clone())),
                            ("finding.title", RowValue::Text(finding.title.clone())),
                            ("finding.severity", RowValue::Text(finding.severity.clone())),
                            ("finding.source", RowValue::Text(finding.source.clone())),
                            ("finding.license", RowValue::Text(finding.license.clone())),
                            (
                                "finding.author",
                                RowValue::Text(attribution(&finding.author).to_owned()),
                            ),
                            ("finding.count", RowValue::Number(i128::from(finding.count))),
                            ("finding.mitre", RowValue::List(finding.mitre.clone())),
                            ("finding.engine", RowValue::Text(name(report.engine).into())),
                        ];
                        if let Some(evidence) = finding.evidence.first() {
                            row[0].values.extend(evidence_values(evidence));
                        }
                        row
                    })
                    .collect()
            })
            .unwrap_or_default();
    }
    /// Show `engine`'s tab, filtered to the rule `rule_id` once it draws.
    pub(super) fn focus_rule(&mut self, engine: &str, rule_id: &str) {
        if let Some(found) = ENGINES
            .iter()
            .find(|candidate| name(**candidate).eq_ignore_ascii_case(engine))
        {
            self.selected = *found;
        }
        self.pending_rule = Some(rule_id.to_owned());
    }
    pub fn tick(&mut self, ctx: &egui::Context, input: &TriageInput<'_>) {
        self.clock = input.clock_anchor;
        let identity = input
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
            });
        if self.identity != identity {
            self.reset();
            self.identity = identity;
            if let Some(request) = self.request(Engine::Yara, None) {
                let (tx, rx) = mpsc::sync_channel(1);
                let ctx = ctx.clone();
                let epoch = self.epoch;
                match std::thread::Builder::new()
                    .name("triage-detector-load".into())
                    .spawn(move || {
                        let loaded = ENGINES.map(|engine| {
                            let mut request = request.clone();
                            request.engine = engine;
                            engine::load(&request).ok()
                        });
                        let _ = tx.send(Reply::Loaded {
                            epoch,
                            loaded: Box::new(loaded),
                        });
                        ctx.request_repaint_of(egui::ViewportId::ROOT);
                    }) {
                    Ok(_) => self.rx = Some(rx),
                    Err(error) => {
                        self.phase[0] = "failed".into();
                        self.results[0] = Some(Err(error.to_string()));
                    }
                }
            }
        }
        if let Some(rx) = &self.registry_rx {
            match rx.try_recv() {
                Ok(message) => {
                    self.registry_rx = None;
                    if message.epoch == self.epoch {
                        match message.result {
                            Ok(payload) => {
                                self.profile = antinomie_monitor_core::ruleset::profile_label_of(
                                    &payload.registry,
                                );
                                self.sets = payload.sets;
                                self.registry = Some(payload.registry);
                                self.registry_for = self.rules_generation;
                                self.digest_generation = u64::MAX;
                            }
                            Err(error) => {
                                self.phase = ["failed".into(), "failed".into(), "failed".into()];
                                self.results[0] = Some(Err(error));
                                self.pending = None;
                            }
                        }
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.registry_rx = None;
                    if self.pending.is_some() {
                        self.phase = ["failed".into(), "failed".into(), "failed".into()];
                        self.results[0] =
                            Some(Err("Rules registry worker ended without a result".into()));
                        self.pending = None;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.rx.is_none() {
            if let Some(pending) = self.pending.take() {
                let current =
                    pending.epoch == self.epoch && pending.generation == self.rules_generation;
                let registry = if current {
                    self.fresh_registry().cloned()
                } else {
                    None
                };
                if let Some(registry) = registry {
                    let index = ENGINES
                        .iter()
                        .position(|candidate| *candidate == pending.engine)
                        .unwrap_or(0);
                    self.settings.partial = pending.partial;
                    self.settings.evidence_key = pending.evidence_key.clone();
                    if let Some(request) = self.request(pending.engine, pending.digest.clone()) {
                        match self.launch(ctx, request, Some(registry), index, pending.automatic) {
                            Admit::Started if pending.automatic => {
                                self.auto_key[index] = pending.evidence_key;
                                self.scanned_generation[index] = pending.generation;
                                self.budgets[index].admit(std::time::Instant::now());
                            }
                            Admit::Failed if pending.automatic => {
                                self.budgets[index].admit(std::time::Instant::now());
                            }
                            _ => {}
                        }
                    }
                } else if current {
                    self.pending = Some(pending);
                }
            }
        }
        self.drain_progress();
        if let Some(rx) = &self.rx {
            let reply = match rx.try_recv() {
                Ok(reply) => Some(Ok(reply)),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Detector worker ended without a result".to_owned()))
                }
            };
            if let Some(reply) = reply {
                match reply {
                    Ok(Reply::Loaded { epoch, loaded }) => {
                        if epoch == self.epoch {
                            self.results = (*loaded).map(|report| report.map(Ok));
                            for index in 0..3 {
                                self.rows(index);
                            }
                        }
                    }
                    Ok(Reply::Scanned {
                        epoch,
                        generation,
                        index,
                        result,
                    }) => {
                        if epoch != self.epoch || generation != self.rules_generation {
                            self.phase[index] = "canceled".into();
                            self.progress[index] = None;
                        } else {
                            let automatic = self.auto_started[index];
                            self.auto_started[index] = false;
                            if result.is_ok() {
                                if automatic {
                                    self.budgets[index].automatic_success();
                                }
                                self.phase[index].clear();
                            } else if matches!(result.as_ref(), Err(error) if error == "cancelled")
                            {
                                self.phase[index] = "canceled".into();
                            } else {
                                self.phase[index] = "failed".into();
                                if automatic && self.budgets[index].attempts < 3 {
                                    self.auto_key[index].clear();
                                }
                            }
                            self.results[index] = Some(*result);
                            self.rows(index);
                            self.progress[index] = None;
                        }
                    }
                    Err(error) => {
                        let index = self.busy.unwrap_or(0);
                        self.phase[index] = "failed".into();
                        self.results[index] = Some(Err(error));
                        self.progress[index] = None;
                    }
                }
                self.rx = None;
                self.progress_rx = None;
                self.cancel = None;
                self.busy = None;
            }
        }
        if let Some(evidence) = ctx.data_mut(|data| {
            let id = egui::Id::new("triage-byte-jump");
            let evidence = data.get_temp::<Evidence>(id);
            data.remove::<Evidence>(id);
            evidence
        }) {
            self.read_bytes(ctx, evidence);
        }
        if let Some(rx) = &self.byte_rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.bytes = Some(result);
                    self.byte_rx = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.bytes = Some(Err("Byte preview worker ended without a result".into()));
                    self.byte_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let pending = self
            .byte_rx
            .is_none()
            .then(|| self.pending_byte.take())
            .flatten();
        if let Some(evidence) = pending {
            self.read_bytes(ctx, evidence);
        }
        if let Some(rx) = &self.digest_rx {
            match rx.try_recv() {
                Ok((id, len, modified, digest)) => {
                    self.digests.insert(
                        id,
                        FileDigest {
                            len,
                            modified,
                            digest,
                        },
                    );
                    self.digest_rx = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.digest_rx = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.consider_auto(ctx, input);
        if self.rx.is_some()
            || self.byte_rx.is_some()
            || self.digest_rx.is_some()
            || self.selection_rx.is_some()
            || self.registry_rx.is_some()
            || self.pending.is_some()
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    /// Size and modification time of a regular file, `None` if it is not one.
    /// Read from the disk at most once per [`STAT_KEEP`].
    fn stat(&mut self, id: &str, path: &Path) -> Option<(u64, u128)> {
        if let Some((at, found)) = self.stats.get(id) {
            if at.elapsed() < STAT_KEEP {
                return *found;
            }
        }
        let found = std::fs::metadata(path)
            .ok()
            .filter(|meta| meta.is_file())
            .map(|meta| {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|time| time.as_nanos())
                    .unwrap_or(0);
                (meta.len(), modified)
            });
        self.stats.insert(id.to_owned(), (Instant::now(), found));
        found
    }
    fn cached_file_digest(&mut self, ctx: &egui::Context, path: &Path) -> Option<String> {
        let id = path.display().to_string();
        let Some((len, modified)) = self.stat(&id, path) else {
            return Some("missing".into());
        };
        if let Some(cached) = self.digests.get(&id) {
            if cached.len == len && cached.modified == modified {
                return Some(cached.digest.clone());
            }
        }
        if self.digest_rx.is_none() {
            let path = path.to_path_buf();
            let (tx, rx) = mpsc::sync_channel(1);
            let ctx = ctx.clone();
            if std::thread::Builder::new()
                .name("triage-evidence-hash".into())
                .spawn(move || {
                    let digest = antinomie_monitor_core::storage::sha256_file_hex(&path)
                        .unwrap_or_else(|_| "unreadable".into());
                    let _ = tx.send((id, len, modified, digest));
                    ctx.request_repaint_of(egui::ViewportId::ROOT);
                })
                .is_ok()
            {
                self.digest_rx = Some(rx);
            }
        }
        None
    }
    fn evidence_identity(
        &mut self,
        ctx: &egui::Context,
        engine: Engine,
        input: &TriageInput<'_>,
    ) -> String {
        match engine {
            Engine::Yara => {
                let Some(analysis) = input.analysis else {
                    return "wait:sample".into();
                };
                let archive = match input.archive {
                    Some(archive) => {
                        let artifacts =
                            self.cached_file_digest(ctx, &archive.join("artifacts.json"));
                        let journal =
                            self.cached_file_digest(ctx, &archive.join(engine::JOURNAL_FILE));
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
                    self.settings.scan_memory,
                    self.settings.scan_recovered
                )
            }
            Engine::Ids => match (input.pcap, input.pcap_open) {
                (None, _) => "missing:pcap".into(),
                (Some(_), true) => "wait:pcap".into(),
                (Some(path), false) => {
                    let Some(digest) = self.cached_file_digest(ctx, path) else {
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
                let Some(digest) =
                    self.cached_file_digest(ctx, &archive.join(engine::JOURNAL_FILE))
                else {
                    return "wait:digest".into();
                };
                format!("ready:journal:{}:{digest}", input.run_id.unwrap_or(""))
            }
        }
    }
    fn consider_auto(&mut self, ctx: &egui::Context, input: &TriageInput<'_>) {
        if self.seen_generation != self.rules_generation {
            self.seen_generation = self.rules_generation;
            self.digest_generation = u64::MAX;
        }
        for (index, engine) in ENGINES.iter().enumerate() {
            let key = self.evidence_identity(ctx, *engine, input);
            self.ready_key[index] = key.clone();
            self.notes[index] = evidence_note(&key);
            let digest = self.current_digest(ctx, index);
            if digest == "preparing" {
                self.phase[index] = "preparing".into();
                continue;
            }
            if key.starts_with("ready:") {
                self.budgets[index].observe(&format!("{key}|{digest}"));
            }
            let saved_matches = match &self.results[index] {
                Some(Ok(report)) => {
                    !report.selection.is_empty()
                        && report.selection == digest
                        && report.evidence_key == key
                }
                _ => false,
            };
            if saved_matches && self.auto_key[index].is_empty() {
                self.auto_key[index] = key;
                self.scanned_generation[index] = self.rules_generation;
                continue;
            }
            if !self.automatic || self.rx.is_some() || !key.starts_with("ready:") {
                continue;
            }
            let now = std::time::Instant::now();
            if !self.budgets[index].allow(now) {
                if let Some(at) = self.budgets[index].ready_at {
                    if let Some(wait) = at.checked_duration_since(now) {
                        ctx.request_repaint_after(wait);
                    }
                }
                continue;
            }
            if self.auto_key[index] == key
                && self.scanned_generation[index] == self.rules_generation
            {
                continue;
            }
            match self.start_engine(ctx, *engine, None, false, &key, true) {
                Admit::Started => {
                    self.auto_key[index] = key;
                    self.scanned_generation[index] = self.rules_generation;
                    self.budgets[index].admit(now);
                }
                Admit::Preparing => {}
                Admit::Failed => {
                    self.budgets[index].admit(now);
                }
            }
            break;
        }
    }
    fn fresh_registry(&self) -> Option<&antinomie_monitor_core::ruleset::Registry> {
        self.registry
            .as_ref()
            .filter(|_| self.registry_for == self.rules_generation)
    }
    fn request_registry(&mut self, ctx: &egui::Context) {
        if self.registry_rx.is_some() || self.settings.rules_root.is_empty() {
            return;
        }
        let dir = PathBuf::from(&self.settings.rules_root);
        let epoch = self.epoch;
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        match std::thread::Builder::new()
            .name("triage-rules-registry".into())
            .spawn(move || {
                let result = (|| {
                    antinomie_monitor_core::ruleset::migrate_indexes(&dir)?;
                    let registry = antinomie_monitor_core::ruleset::load_registry(&dir)?;
                    let sets = ["yara", "ids", "sigma"].map(|engine| {
                        antinomie_monitor_core::ruleset::engine_sets(&dir, &registry, engine)
                    });
                    Ok(RegistryPayload { registry, sets })
                })();
                let _ = tx.send(RegistryMsg { epoch, result });
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => self.registry_rx = Some(rx),
            Err(error) => {
                self.phase = ["failed".into(), "failed".into(), "failed".into()];
                self.results[0] = Some(Err(error.to_string()));
            }
        }
    }
    fn start(&mut self, ctx: &egui::Context, digest: Option<String>, partial: bool) {
        let index = ENGINES
            .iter()
            .position(|candidate| *candidate == self.selected)
            .unwrap_or(0);
        let key = self.ready_key[index].clone();
        let _ = self.start_engine(ctx, self.selected, digest, partial, &key, false);
    }
    fn start_engine(
        &mut self,
        ctx: &egui::Context,
        engine: Engine,
        digest: Option<String>,
        partial: bool,
        evidence_key: &str,
        automatic: bool,
    ) -> Admit {
        let index = ENGINES
            .iter()
            .position(|candidate| *candidate == engine)
            .unwrap_or(0);
        let pending = PendingScan {
            engine,
            digest: digest.clone(),
            partial,
            evidence_key: evidence_key.to_owned(),
            automatic,
            generation: self.rules_generation,
            epoch: self.epoch,
        };
        if self.rx.is_some() {
            self.pending = Some(pending);
            self.phase[index] = "queued".into();
            return Admit::Preparing;
        }
        self.settings.partial = partial;
        self.settings.evidence_key = evidence_key.to_owned();
        let Some(request) = self.request(engine, digest) else {
            self.phase[index] = "failed".into();
            return Admit::Failed;
        };
        if request.settings.rules_root.is_empty() {
            return self.launch(ctx, request, None, index, automatic);
        }
        let Some(registry) = self.fresh_registry().cloned() else {
            self.pending = Some(pending);
            self.phase[index] = "preparing".into();
            self.request_registry(ctx);
            return Admit::Preparing;
        };
        self.launch(ctx, request, Some(registry), index, automatic)
    }
    fn launch(
        &mut self,
        ctx: &egui::Context,
        mut request: engine::Request,
        registry: Option<antinomie_monitor_core::ruleset::Registry>,
        index: usize,
        automatic: bool,
    ) -> Admit {
        self.auto_started[index] = automatic;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = mpsc::sync_channel(1);
        let (progress_tx, progress_rx) = mpsc::channel();
        let ctx = ctx.clone();
        let epoch = self.epoch;
        let generation = self.rules_generation;
        let root = request.settings.rules_root.clone();
        let tools = antinomie_monitor_core::ruleset::ToolConfig::from_sigma_setting(
            &request.settings.effective_sigma_python(),
        );
        let engine_name = engine_key(request.engine).to_owned();
        match std::thread::Builder::new()
            .name("triage-detector".into())
            .spawn(move || {
                let result = (|| {
                    if !root.is_empty() {
                        let registry =
                            registry.ok_or_else(|| "rules registry was not captured".to_owned())?;
                        let data_dir = Path::new(&root);
                        let _ = antinomie_monitor_core::ruleset::reap_staging(
                            data_dir,
                            Duration::from_secs(3600),
                        );
                        if worker_cancel.load(Ordering::Relaxed) {
                            return Err("cancelled".into());
                        }
                        let facts = antinomie_monitor_core::ruleset::tool_facts(&tools);
                        let snap = antinomie_monitor_core::ruleset::snapshot_from(
                            data_dir,
                            &engine_name,
                            &registry,
                            &facts,
                            Some(&worker_cancel),
                        )?;
                        request.frozen = Some(engine::FrozenSelection {
                            digest: snap.digest,
                            directory: snap.directory,
                            enabled_rules: snap.enabled_rules,
                            excluded_rules: snap.excluded_rules,
                            warnings: snap.warnings,
                        });
                    }
                    engine::run_with_progress(request, &worker_cancel, Some(progress_tx))
                })();
                let _ = tx.send(Reply::Scanned {
                    epoch,
                    generation,
                    index,
                    result: Box::new(result),
                });
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => {
                self.rx = Some(rx);
                self.progress_rx = Some(progress_rx);
                self.progress[index] = None;
                self.cancel = Some(cancel);
                self.busy = Some(index);
                self.phase[index] = "running".into();
                Admit::Started
            }
            Err(error) => {
                self.phase[index] = "failed".into();
                self.results[index] = Some(Err(error.to_string()));
                Admit::Failed
            }
        }
    }
    fn read_bytes(&mut self, ctx: &egui::Context, evidence: Evidence) {
        if self.byte_rx.is_some() {
            self.pending_byte = Some(evidence);
            return;
        }
        let Some(request) = self.request(Engine::Yara, None) else {
            return;
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        self.bytes = None;
        match std::thread::Builder::new()
            .name("triage-match-bytes".into())
            .spawn(move || {
                let result =
                    engine::read_evidence(&request, &evidence).map(|data| (evidence, data));
                let _ = tx.send(result);
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => self.byte_rx = Some(rx),
            Err(error) => self.bytes = Some(Err(error.to_string())),
        }
    }
    fn drain_progress(&mut self) {
        let mut latest = None;
        let mut dead = false;
        if let Some(rx) = &self.progress_rx {
            loop {
                match rx.try_recv() {
                    Ok(progress) => latest = Some(progress),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        dead = true;
                        break;
                    }
                }
            }
        }
        if dead {
            self.progress_rx = None;
        }
        if let Some(progress) = latest {
            if let Some(index) = self.busy {
                self.progress[index] = Some(progress);
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, scan: Option<&ArchiveScan>) {
        if self.fresh_registry().is_none() {
            self.request_registry(ui.ctx());
        }
        self.engine_tabs(ui);
        let index = ENGINES
            .iter()
            .position(|engine| *engine == self.selected)
            .unwrap_or(0);
        self.rule_sets(ui, index);
        self.scanned_inputs(ui, index, scan);
        let scanning = self.is_scanning(index);
        self.scan_controls(ui, index, scan, scanning);
        if scanning {
            self.scan_progress(ui, index);
        }
        self.notes_line(ui, index);
        self.coverage_section(ui, index);

        if self.selected == Engine::Sigma {
            if let Some(error) = scan.and_then(|scan| scan.event_error.as_ref()) {
                crate::activity::warning(ui, error);
            }
        }
        let Some(result) = &self.results[index] else {
            if !scanning {
                ui.weak("Not scanned.");
            }
            return;
        };
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                crate::activity::warning(ui, error);
                return;
            }
        };
        if self.selected == Engine::Sigma
            && report
                .source_digest
                .as_ref()
                .zip(scan.and_then(|scan| scan.event_journal.as_ref()))
                .is_some_and(|(digest, journal)| *digest != journal.sha256)
        {
            crate::activity::warning(
                ui,
                "Recorded events changed after this result. Scan again to update it.",
            );
        }
        // The journal row carries the same words; this keeps them in view.
        if let Some(warning) = report
            .inputs
            .iter()
            .flatten()
            .map(|input| input.warning.as_str())
            .find(|warning| !warning.is_empty())
        {
            input_note(ui, warning);
        }
        if report.findings.is_empty() {
            ui.weak(match report.state {
                State::Complete
                    if report.inputs.as_ref().is_some_and(|inputs| {
                        inputs
                            .iter()
                            .any(|input| input.outcome != engine::InputOutcome::Succeeded)
                    }) =>
                {
                    "No rule matched the inputs that were scanned. Some inputs were not; see Scanned inputs."
                }
                State::Complete => "No matches.",
                State::NoRules => "No rules enabled. This is not a clean scan.",
                State::Missing => "Evidence missing. This is not a clean scan.",
                State::Skipped => header::SKIPPED_NOTE,
                _ => "No retained matches. Coverage is incomplete or unavailable.",
            });
        }
        let draft_id = ui.id().with(("table-filter", TABLES[index]));
        // A quote or backslash cannot be written in the filter's string.
        if let Some(rule) = self
            .pending_rule
            .take()
            .filter(|rule| !rule.contains(['"', '\\']) && !rule.chars().any(char::is_control))
        {
            let draft = format!("finding.rule == \"{rule}\"");
            ui.data_mut(|data| data.insert_temp(draft_id, draft));
        }
        let filter =
            query::table_filter(ui, TABLES[index], "finding.severity == high", FIELDS, &[]);
        let draft = ui
            .data(|data| data.get_temp::<String>(draft_id))
            .unwrap_or_default();
        ui.ctx().data_mut(|data| {
            data.insert_temp(
                egui::Id::new(("triage-filter-target", TABLES[index])),
                draft_id,
            )
        });
        if self.applied[index].as_ref() != Some(&draft) {
            self.filtered[index] = self.rows[index]
                .iter()
                .filter(|row| filter.keep_table(&row[0].values))
                .cloned()
                .collect();
            self.applied[index] = Some(draft);
        }
        let opened = match_cards(ui, report, TABLES[index], &self.filtered[index]);
        table(ui, TABLES[index], HEADERS, &self.filtered[index]);
        if let Some(key) = opened {
            self.open_window(key);
        }
    }
    pub fn details(&mut self, ui: &mut egui::Ui, values: &[(&str, RowValue)]) {
        let text = |name: &str| {
            values.iter().find_map(|(key, value)| {
                if *key == name {
                    if let RowValue::Text(value) = value {
                        Some(value.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        };
        let Some(index) = ENGINES
            .iter()
            .position(|engine| Some(name(*engine)) == text("finding.engine"))
        else {
            return;
        };
        let Some(Ok(report)) = &self.results[index] else {
            return;
        };
        let Some(finding) = report
            .findings
            .iter()
            .find(|finding| Some(finding.rule_id.as_str()) == text("finding.rule"))
        else {
            return;
        };
        // The rule text, metadata and every location live in the Details window.
        ui.add(egui::Label::new(card_summary(report.engine, finding)).wrap());
        let window = ui.button("Details…").clicked().then(|| WindowKey {
            engine: index,
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
        });
        for reference in &finding.mitre {
            let url = format!(
                "https://attack.mitre.org/techniques/{}/",
                reference.replace('.', "/")
            );
            ui.add(egui::Label::new(&url).wrap());
            if ui.small_button(format!("Copy {reference} link")).clicked() {
                ui.ctx().copy_text(url);
            }
        }
        let mut selected = None;
        let scanned = report.source_digest.clone();
        egui::CollapsingHeader::new(format!("Evidence locations ({})", finding.evidence.len()))
            .default_open(true)
            .show(ui, |ui| {
                selected =
                    evidence_list(ui, report.engine, finding, "detection-evidence-hits", 240.0);
            });
        byte_preview(ui, self.bytes.as_ref(), self.byte_rx.is_some(), finding);
        if let Some(key) = window {
            self.open_window(key);
        }
        if let Some(pick) = selected {
            self.open_pick(ui.ctx(), scanned, pick);
        }
    }
}

impl Drop for View {
    fn drop(&mut self) {
        self.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changing_run_keeps_rule_sets_with_the_cached_registry() {
        let mut view = View::default();
        view.registry = Some(antinomie_monitor_core::ruleset::Registry::default());
        view.rules_generation = 7;
        view.registry_for = 7;
        view.sets[0] = vec![antinomie_monitor_core::ruleset::EngineSet {
            name: "Installed fixture".into(),
            revision: "1".into(),
            enabled: true,
            rules: 3,
            source: String::new(),
        }];
        view.auto_key[0] = "old-run-evidence".into();
        view.reset();
        assert!(view.fresh_registry().is_some());
        assert_eq!(
            view.sets[0].len(),
            1,
            "registry and visible rule sets must remain consistent"
        );
        assert!(view.sets[0][0].enabled);
        assert!(
            view.auto_key[0].is_empty(),
            "run-specific scan identity must reset"
        );
    }

    pub(super) fn finding(rule: &str, title: &str, evidence: Vec<Evidence>) -> Finding {
        Finding {
            rule_id: rule.into(),
            title: title.into(),
            severity: "high".into(),
            source: "s0".into(),
            license: "MIT".into(),
            author: "A".into(),
            mitre: vec![],
            count: evidence.len() as u64,
            evidence,
            events: vec![],
            details: "readable summary".into(),
            rule_text: String::new(),
        }
    }

    pub(super) fn report(findings: Vec<Finding>) -> Report {
        let mut report = Report::empty(
            Engine::Yara,
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        );
        report.findings = findings;
        report
    }

    /// Run `frames` UI frames and return the last one's shapes, so windows
    /// and their sizing pass have been painted.
    pub(super) fn frames(
        ctx: &egui::Context,
        frames: usize,
        mut run: impl FnMut(&egui::Context),
    ) -> Vec<egui::epaint::ClippedShape> {
        let mut shapes = Vec::new();
        for _ in 0..frames {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 800.0),
                    )),
                    ..Default::default()
                },
                &mut run,
            );
            shapes = output.shapes;
        }
        shapes
    }

    pub(super) fn each_galley(
        shape: &egui::epaint::Shape,
        visit: &mut impl FnMut(&egui::epaint::Galley),
    ) {
        match shape {
            egui::epaint::Shape::Text(text) => visit(&text.galley),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    each_galley(shape, visit);
                }
            }
            _ => {}
        }
    }

    pub(super) fn each_galley_rect(shape: &egui::Shape, found: &mut impl FnMut(&str, egui::Rect)) {
        match shape {
            egui::Shape::Text(text) => found(text.galley.text(), text.visual_bounding_rect()),
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    each_galley_rect(shape, found);
                }
            }
            _ => {}
        }
    }

    pub(super) fn rendered_text(shapes: &[egui::epaint::ClippedShape]) -> String {
        let mut texts = Vec::new();
        for shape in shapes {
            each_galley(&shape.shape, &mut |galley| {
                texts.push(galley.text().to_owned())
            });
        }
        texts.join("\n")
    }
    #[test]
    fn run_change_cancels_detector_and_discards_stale_results() {
        let mut view = View::default();
        let ctx = egui::Context::default();
        view.identity = Some((
            "/old".into(),
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        ));
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel(1);
        view.cancel = Some(Arc::clone(&cancel));
        view.rx = Some(rx);
        view.tick(&ctx, &TriageInput::empty());
        assert!(cancel.load(Ordering::Relaxed));
        assert!(tx
            .send(Reply::Loaded {
                epoch: 0,
                loaded: Box::default(),
            })
            .is_err());
        assert!(view.results.iter().all(Option::is_none));
    }

    #[test]
    fn automatic_attempts_stop_at_three_and_a_manual_scan_does_not_refill_them() {
        let mut budget = AttemptBudget::default();
        let start = std::time::Instant::now();
        budget.observe("ready:one");
        assert!(budget.allow(start));
        budget.admit(start);
        assert_eq!(budget.attempts, 1);
        assert!(!budget.allow(start));
        budget.admit(start + Duration::from_millis(500));
        budget.admit(start + Duration::from_secs(2));
        assert_eq!(budget.attempts, 3);
        assert!(!budget.allow(start + Duration::from_secs(30)));
        // A manual result does not call automatic_success or admit.
        assert_eq!(budget.attempts, 3);
        budget.automatic_success();
        assert_eq!(budget.attempts, 0);
        budget.admit(start);
        budget.observe("ready:two");
        assert_eq!(budget.attempts, 0);
        assert!(budget.allow(start));
    }

    #[test]
    fn same_size_rewrite_changes_the_evidence_digest() {
        let dir = std::env::temp_dir().join(format!("ant-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("evidence.bin");
        std::fs::write(&path, b"aaaa").unwrap();
        let first = antinomie_monitor_core::storage::sha256_file_hex(&path).unwrap();
        std::fs::write(&path, b"bbbb").unwrap();
        let second = antinomie_monitor_core::storage::sha256_file_hex(&path).unwrap();
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_selection_digest_is_computed_off_the_ui_thread() {
        let dir = std::env::temp_dir().join(format!("ant-ui-digest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = egui::Context::default();
        let mut view = View::default();
        view.settings.rules_root = dir.display().to_string();
        view.registry = Some(antinomie_monitor_core::ruleset::Registry::default());
        view.registry_for = view.rules_generation;
        let mut first = None;
        let mut digest = String::new();
        for _ in 0..400 {
            digest = view.current_digest(&ctx, 0);
            if first.is_none() && view.selection_rx.is_some() {
                // The call that started the work did not wait for it.
                first = Some(digest.clone());
            }
            if digest != "preparing" {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(first.as_deref(), Some("preparing"));
        assert_eq!(digest.len(), 64, "{digest}");
        assert_eq!(
            view.current_digest(&ctx, 0),
            digest,
            "kept for the generation"
        );
        assert!(view.selection_rx.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// How long this thread spent runnable but waiting for a core, from the
    /// scheduler, or `None` where it does not say.
    fn run_queue_wait() -> Option<Duration> {
        let stat = std::fs::read_to_string("/proc/thread-self/schedstat").ok()?;
        let nanos: u64 = stat.split_whitespace().nth(1)?.parse().ok()?;
        Some(Duration::from_nanos(nanos))
    }

    /// How long `work` kept the calling thread, less the time the thread was
    /// ready to run and the host had no core for it. A UI thread that waits
    /// on a lock, a disk or a join is still counted, which is what "blocking"
    /// means; a busy machine that does not schedule the thread is not.
    fn held_up(work: impl FnOnce()) -> Duration {
        let (started, waiting) = (std::time::Instant::now(), run_queue_wait());
        work();
        let elapsed = started.elapsed();
        match (waiting, run_queue_wait()) {
            (Some(before), Some(after)) => elapsed.saturating_sub(after.saturating_sub(before)),
            _ => elapsed,
        }
    }

    #[test]
    fn snapshot_preparation_does_not_block_ui_frames() {
        let dir = std::env::temp_dir().join(format!("ant-ui-prep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let yara = Path::new("/tmp/antinomie-rules-r3/packs/yara-forge-core-20261004.tar.gz");
        let et = Path::new("/tmp/antinomie-rules-r3/packs/emerging-threats-open.tar.gz");
        if !yara.is_file() || !et.is_file() {
            eprintln!("prepared YARA and ET archives are absent; UI timing was not measured");
            return;
        }
        let bytes = std::fs::read(yara).unwrap();
        let sha = antinomie_monitor_core::storage::sha256_hex(&bytes);
        let entry = antinomie_monitor_core::ruleset::PackEntry {
            id: "yara-forge-core".into(),
            engine: "yara".into(),
            name: "YARA-Forge Core".into(),
            version: "ui".into(),
            upstream_revision: "20261004".into(),
            upstream_url: "https://github.com/YARAHQ/yara-forge".into(),
            download_url: "https://example.invalid/yara.tar.gz".into(),
            sha256: sha,
            size: bytes.len() as u64,
            app: ">=0.6.2".into(),
            engine_requirement: "YARA-X 1.21".into(),
            rules: 2094,
            helpers: 2,
            license: "per-rule".into(),
            evidence: vec!["sample".into()],
            limits: Vec::new(),
        };
        antinomie_monitor_core::ruleset::install_archive(&dir, &entry, &bytes).unwrap();
        let engine = if et.is_file() {
            let bytes = std::fs::read(et).unwrap();
            let sha = antinomie_monitor_core::storage::sha256_hex(&bytes);
            let entry = antinomie_monitor_core::ruleset::PackEntry {
                id: "emerging-threats-open".into(),
                engine: "ids".into(),
                name: "Emerging Threats Open".into(),
                version: "ui".into(),
                upstream_revision: "et".into(),
                upstream_url: "https://rules.emergingthreats.net/".into(),
                download_url: "https://example.invalid/et.tar.gz".into(),
                sha256: sha,
                size: bytes.len() as u64,
                app: ">=0.6.2".into(),
                engine_requirement: "Suricata 7".into(),
                rules: 1,
                helpers: 0,
                license: "mixed".into(),
                evidence: vec!["pcap".into()],
                limits: Vec::new(),
            };
            antinomie_monitor_core::ruleset::install_archive(&dir, &entry, &bytes).unwrap();
            Engine::Ids
        } else {
            Engine::Yara
        };
        let mut view = View::default();
        view.settings.rules_root = dir.display().to_string();
        view.rules_generation = 1;
        view.identity = Some((
            dir.clone(),
            Identity {
                vm_id: "vm".into(),
                boot_id: "boot".into(),
                run_id: "run".into(),
                root_cookie: 1,
            },
        ));
        let ctx = egui::Context::default();
        let input = TriageInput {
            vm_id: Some("vm"),
            boot_id: Some("boot"),
            run_id: Some("run"),
            archive: Some(&dir),
            root_cookie: 1,
            run_finished: true,
            ..TriageInput::empty()
        };
        let wait = std::time::Instant::now();
        while view.registry.is_none() {
            view.tick(&ctx, &input);
            assert!(
                wait.elapsed() < Duration::from_secs(120),
                "{}",
                view.phase[0]
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut admission = None;
        let admitted = held_up(|| {
            admission = Some(view.start_engine(&ctx, engine, None, false, "ready:pack", false))
        });
        assert!(matches!(admission, Some(Admit::Started)));
        assert!(
            admitted < Duration::from_millis(80),
            "admitting the scan blocked the UI thread for {admitted:?}"
        );
        view.rules_generation = view.rules_generation.saturating_add(1);
        let mut frames = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while view.rx.is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "preparation did not finish"
            );
            frames.push(held_up(|| {
                let _ = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(800.0, 480.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            view.show(ui, None);
                        });
                    },
                );
                view.tick(&ctx, &input);
            }));
            std::thread::sleep(Duration::from_millis(5));
        }
        let slowest = frames.iter().copied().max().unwrap_or_default();
        assert!(
            slowest < Duration::from_millis(150),
            "slowest UI frame during preparation was {slowest:?} across {} frames",
            frames.len()
        );
        assert!(view.results.iter().all(|result| result.is_none()));
        assert!(!frames.is_empty(), "preparation produced no UI frames");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
