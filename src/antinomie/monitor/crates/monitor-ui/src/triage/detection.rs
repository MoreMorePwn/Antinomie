// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use antinomie_monitor_core::analysis::detection::{
    self as engine, Engine, Evidence, Finding, Identity, Report, State,
};
use std::path::{Path, PathBuf};

mod cards;
mod coverage;
mod finding;
pub(super) use finding::pack_name;
mod header;
pub(in crate::triage) use header::ScanActivity;
mod inputs;
mod journal;
mod kept;
mod scan;
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
/// What an empty result of a complete scan says when some inputs were not
/// scanned: how many, and the reasons the scan recorded for them. `None`
/// when every input was scanned.
pub(super) fn return_note(inputs: Option<&[engine::ScannedInput]>) -> Option<String> {
    let inputs = inputs?;
    let skipped: Vec<_> = inputs
        .iter()
        .filter(|input| input.outcome != engine::InputOutcome::Succeeded)
        .collect();
    if skipped.is_empty() {
        return None;
    }
    let scanned = inputs.len() - skipped.len();
    let mut reasons: Vec<String> = Vec::new();
    for input in &skipped {
        let reason = input.reason.trim();
        let reason = if reason.is_empty() {
            "no reason was recorded"
        } else {
            reason
        };
        if !reasons.iter().any(|known| known == reason) {
            reasons.push(reason.to_owned());
        }
    }
    let shown: Vec<_> = reasons.iter().take(3).cloned().collect();
    let more = reasons.len().saturating_sub(shown.len());
    let mut why = shown.join("; ");
    if more > 0 {
        why.push_str(&format!("; and {more} more"));
    }
    let noun = |count: usize| if count == 1 { "input" } else { "inputs" };
    Some(format!(
        "No rule matched the {scanned} {} that {} scanned. {} of {} {} {} not scanned ({why}). \
         An input is left out when it is too large, of a type the engine cannot read, or cut off \
         by the time limit; Scanned inputs gives the reason for each.",
        noun(scanned),
        if scanned == 1 { "was" } else { "were" },
        skipped.len(),
        inputs.len(),
        noun(inputs.len()),
        if skipped.len() == 1 { "was" } else { "were" },
    ))
}
fn attribution(author: &str) -> &str {
    if author.is_empty() {
        "unknown"
    } else {
        author
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
    /// The saved results of the last runs shown, so a run shown again has
    /// them at once instead of reading them back behind a progress bar.
    kept: Vec<(Identity, [Option<Report>; 3])>,
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
    /// An ATT&CK technique the Matches table is to be filtered to when it next
    /// shows (set by the Summary's ATT&CK list).
    pending_technique: Option<String>,
    pub rules_generation: u64,
    seen_generation: u64,
    auto_key: [String; 3],
    scanned_generation: [u64; 3],
    notes: [String; 3],
    /// Per engine: why the last background re-scan was not taken over.
    kept_note: [String; 3],
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
    /// The scans in flight or being prepared, for the Jobs window.
    pub(super) fn running_jobs(&self) -> Vec<crate::jobs::Job> {
        let mut out = Vec::new();
        for (index, engine) in ENGINES.into_iter().enumerate() {
            // A phase word alone can be left over; the worker or the waiting
            // request is what makes it a job.
            let waiting = self.pending.as_ref().is_some_and(|p| p.engine == engine);
            if self.busy != Some(index) && !waiting {
                continue;
            }
            let state = match self.phase[index].as_str() {
                "queued" => "Queued".to_owned(),
                "preparing" => "Preparing the rules".to_owned(),
                _ => match &self.progress[index] {
                    Some(progress) => format!(
                        "Scanning, {} rules loaded",
                        antinomie_monitor_core::analysis::detection::group_digits(
                            progress.rules_loaded
                        )
                    ),
                    None => "Scanning".to_owned(),
                },
            };
            let mut job = crate::jobs::Job::new(
                format!("scan:{}", name(engine)),
                "Detection scan",
                format!("{} rules on the run", name(engine)),
            )
            .state(state)
            .open(crate::workspace::Panel::Triage);
            if self.busy == Some(index) {
                job = job.flag(self.cancel.clone());
            }
            out.push(job);
        }
        out
    }

    /// Saved evidence was deleted: look at the listed captures and cores again.
    pub(super) fn evidence_deleted(&mut self) {
        self.presence.invalidate();
        self.kept.clear();
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
        self.kept_note = Default::default();
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
    /// Why an automatic scan's `result` must not replace the complete result
    /// of `index` that is shown, or `None` when it may.
    fn kept_reason(&self, index: usize, result: &Result<Report, String>) -> Option<String> {
        let Some(Ok(shown)) = &self.results[index] else {
            return None;
        };
        if shown.state != State::Complete {
            return None;
        }
        let why = match result {
            Err(error) if error == "cancelled" => return None,
            Err(error) => error.clone(),
            Ok(report) if report.state == State::Complete => return None,
            Ok(report) => report
                .warnings
                .first()
                .cloned()
                .unwrap_or_else(|| "the engine could not evaluate the evidence".into()),
        };
        Some(format!(
            "A background re-scan did not complete ({why}). The earlier result is kept; press Scan to try again."
        ))
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
    /// Show `engine`'s tab, filtered to the rules that cite `technique`.
    pub(super) fn focus_technique(&mut self, engine: &str, technique: &str) {
        self.focus_rule(engine, "");
        self.pending_rule = None;
        self.pending_technique = Some(technique.to_owned());
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
        if self.identity != identity && self.switch_identity(identity) {
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
                            // A background re-scan that failed or could not
                            // evaluate (an engine tool that did not answer) never
                            // replaces a complete result that is on screen.
                            let kept = automatic
                                .then(|| self.kept_reason(index, &result))
                                .flatten();
                            if let Some(reason) = kept {
                                self.kept_note[index] = reason;
                            } else {
                                self.kept_note[index].clear();
                                self.results[index] = Some(*result);
                                self.rows(index);
                            }
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
    /// The whole Detection page in one vertical scroll area, so a section that
    /// grows (the list of rules not applied, a long match list) scrolls the
    /// page instead of running past the bottom of the pane.
    pub fn show(&mut self, ui: &mut egui::Ui, scan: Option<&ArchiveScan>) {
        let viewport = ui.available_height();
        egui::ScrollArea::vertical()
            .id_salt("detection-page")
            .auto_shrink([false, false])
            .show(ui, |ui| self.show_page(ui, scan, viewport));
    }
    fn show_page(&mut self, ui: &mut egui::Ui, scan: Option<&ArchiveScan>, viewport: f32) {
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
                crate::activity::error(
                    ui,
                    format!("The event journal could not be written: {error}"),
                );
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
                crate::activity::error(ui, format!("The scan failed: {error}. Scan again."));
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
                State::Complete => {
                    return_note(report.inputs.as_deref()).unwrap_or_else(|| "No matches.".into())
                }
                State::NoRules => "No rules enabled. This is not a clean scan.".into(),
                State::Missing => "Evidence missing. This is not a clean scan.".into(),
                State::Skipped => header::SKIPPED_NOTE.into(),
                _ => "No retained matches. Coverage is incomplete or unavailable.".into(),
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
        if let Some(technique) = self
            .pending_technique
            .take()
            .filter(|id| id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.'))
        {
            let draft = format!("finding.mitre == \"{technique}\"");
            ui.data_mut(|data| data.insert_temp(draft_id, draft));
        }
        let filter =
            query::table_filter(ui, TABLES[index], "finding.severity == high", FIELDS, &[]);
        // Room between the filter and the start of the matches.
        ui.add_space(12.0);
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
        let opened = match_cards(
            ui,
            report,
            TABLES[index],
            &self.filtered[index],
            &mut self.settings.match_sort,
        );
        ui.add_space(8.0);
        // The page scrolls, so the table is given a height of its own.
        ui.scope(|ui| {
            ui.set_max_height((viewport * 0.7).max(240.0));
            table(ui, TABLES[index], HEADERS, &self.filtered[index]);
        });
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
    use super::kept::KEPT_RUNS;
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
            "registry and visible rule packs must remain consistent"
        );
        assert!(view.sets[0][0].enabled);
        assert!(
            view.auto_key[0].is_empty(),
            "run-specific scan identity must reset"
        );
    }

    fn run(id: &str) -> Option<(PathBuf, Identity)> {
        Some((
            PathBuf::from(format!("/runs/{id}")),
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: id.into(),
                root_cookie: 1,
            },
        ))
    }

    #[test]
    fn a_run_shown_again_has_its_saved_results_at_once_and_deleted_evidence_forgets_them() {
        // Item 22: coming back to a run read its results again behind the
        // preparing bar. A run shown a moment ago needs no read.
        let mut view = View::default();
        assert!(view.switch_identity(run("a")), "first time: read from disk");
        view.results[0] = Some(Ok(report(vec![finding("r1", "Rule one", Vec::new())])));
        assert!(
            view.switch_identity(run("b")),
            "another run: read from disk"
        );
        assert!(view.results.iter().all(Option::is_none));
        assert!(!view.switch_identity(run("a")), "back to a: from memory");
        assert!(matches!(&view.results[0], Some(Ok(report)) if report.findings.len() == 1));
        assert!(view.results[1].is_none());
        // Run b showed nothing saved, so it is not kept.
        assert!(view.switch_identity(run("b")));
        // Deleted evidence: every kept result is read again.
        view.evidence_deleted();
        assert!(view.switch_identity(run("a")));
        // A failed read is never kept as a result.
        view.results[0] = Some(Err("unreadable".into()));
        view.switch_identity(run("b"));
        assert!(view.switch_identity(run("a")));
        // At most KEPT_RUNS runs are kept; the oldest goes first.
        for index in 0..=KEPT_RUNS {
            view.switch_identity(run(&format!("r{index}")));
            view.results[0] = Some(Ok(report(Vec::new())));
        }
        view.switch_identity(run("last"));
        assert!(view.switch_identity(run("r0")), "the oldest was dropped");
        assert!(!view.switch_identity(run(&format!("r{KEPT_RUNS}"))));
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
        mut run: impl FnMut(&mut egui::Ui),
    ) -> Vec<egui::epaint::ClippedShape> {
        let mut shapes = Vec::new();
        for _ in 0..frames {
            let output = ctx.run_ui(
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
                let _ = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(800.0, 480.0),
                        )),
                        ..Default::default()
                    },
                    |root| {
                        egui::CentralPanel::default().show(root, |ui| {
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

    #[test]
    fn the_empty_result_says_how_many_inputs_were_not_scanned_and_why() {
        let input = |outcome, reason: &str| {
            let mut input = engine::ScannedInput::new(engine::InputKind::Capture, "/r/a");
            input.outcome = outcome;
            input.reason = reason.into();
            input
        };
        use engine::InputOutcome::{Failed, Skipped, Succeeded};
        assert!(return_note(None).is_none());
        assert!(return_note(Some(&[input(Succeeded, "")])).is_none());
        let note = return_note(Some(&[
            input(Succeeded, ""),
            input(Skipped, "memory scanning is off"),
            input(Failed, "timed out after 60 s"),
            input(Skipped, "memory scanning is off"),
        ]))
        .unwrap();
        assert!(
            note.starts_with("No rule matched the 1 input that was scanned."),
            "{note}"
        );
        assert!(note.contains("3 of 4 inputs were not scanned"), "{note}");
        assert!(
            note.contains("memory scanning is off; timed out after 60 s"),
            "{note}"
        );
        assert!(note.contains("too large"), "{note}");
        assert!(note.contains("time limit"), "{note}");
        assert!(note.contains("Scanned inputs"), "{note}");
    }

    #[test]
    fn a_failed_background_rescan_keeps_the_complete_result_on_screen() {
        let mut view = View::default();
        view.results[2] = Some(Ok(report(vec![finding("r", "Rule", vec![])])));
        // The report helper is complete; an automatic scan that failed or could
        // not evaluate does not replace it.
        assert!(view
            .kept_reason(2, &Err("Sigma tool timed out".into()))
            .is_some());
        let mut empty = report(vec![]);
        empty.state = State::Unavailable;
        empty.warnings = vec!["No Sigma rule was evaluated: probe unknown".into()];
        let why = view.kept_reason(2, &Ok(empty)).unwrap();
        assert!(why.contains("earlier result is kept"), "{why}");
        assert!(why.contains("probe unknown"), "{why}");
        // A complete result, a cancel, or nothing on screen is taken over.
        assert!(view.kept_reason(2, &Ok(report(vec![]))).is_none());
        assert!(view.kept_reason(2, &Err("cancelled".into())).is_none());
        assert!(view.kept_reason(1, &Err("boom".into())).is_none());
        // A result that was not complete is replaced by the new one.
        let mut limited = report(vec![]);
        limited.state = State::Unavailable;
        view.results[2] = Some(Ok(limited));
        assert!(view.kept_reason(2, &Err("boom".into())).is_none());
    }

    #[test]
    fn an_unanswered_tool_probe_holds_back_the_automatic_scan() {
        use antinomie_monitor_core::ruleset::{ToolFacts, ToolProbe};
        let mut view = View::default();
        assert!(!view.tool_unanswered(2));
        let found = ToolProbe::Found {
            identity: "x".into(),
            version: "1".into(),
        };
        let mut facts = ToolFacts {
            app: String::new(),
            yara: String::new(),
            suricata: found.clone(),
            sigma: ToolProbe::Unknown("did not answer".into()),
            sigma_python: PathBuf::new(),
        };
        view.digest_facts = Some(facts.clone());
        assert!(view.tool_unanswered(2));
        assert!(!view.tool_unanswered(1));
        assert!(!view.tool_unanswered(0));
        facts.sigma = found;
        view.digest_facts = Some(facts);
        assert!(!view.tool_unanswered(2));
    }
}
