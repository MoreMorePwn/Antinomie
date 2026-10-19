// SPDX-License-Identifier: MIT
//! What a detection scan passed to its rules: one row per input, with how
//! much of it was evaluated.
use super::*;

/// Rows a report keeps (a run can recover thousands of files).
pub(super) const INPUT_LIMIT: usize = 10_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// The verified sample, as static analysis stored it.
    #[default]
    Executable,
    CoreDump,
    MemoryDump,
    RecoveredFile,
    /// A run-owned PCAP segment.
    Capture,
    /// The normalized event journal Sigma reads.
    EventJournal,
}

impl InputKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Executable => "Executable",
            Self::CoreDump => "Process core",
            Self::MemoryDump => "Memory dump",
            Self::RecoveredFile => "Recovered file",
            Self::Capture => "Capture",
            Self::EventJournal => "Event journal",
        }
    }
}

/// What happened to one input. There are exactly three outcomes, and an
/// input problem never makes the engine's whole result partial.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputOutcome {
    /// The engine ran to completion on this input. `reason` may carry a note
    /// ("scanned the 1,234 packets captured so far").
    #[default]
    #[serde(alias = "scanned")]
    Succeeded,
    /// The engine ran and failed; `reason` says how (exit code, signal or
    /// timeout, with the engine's own error lines).
    Failed,
    /// Not scanned, for the known `reason`.
    Skipped,
}

/// The outcome names of reports saved by earlier releases. `partial` no
/// longer exists; see [`legacy_partial`].
#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum SavedOutcome {
    #[default]
    #[serde(alias = "scanned")]
    Succeeded,
    Failed,
    Skipped,
    Partial,
}

/// Older reports called an input `partial` when the engine stopped early or
/// when it finished with a caveat. Which one is only in the reason text: a
/// reason that describes a failure (failed, timed out, could not, changed,
/// budget, error) becomes Failed, so the saved result stays honest; any other
/// partial row was a completed scan with a caveat and becomes Succeeded with
/// that caveat kept as its note.
fn legacy_partial(reason: &str) -> InputOutcome {
    let lower = reason.to_ascii_lowercase();
    let failure = [
        "failed",
        "timed out",
        "could not",
        "changed",
        "budget",
        "error",
        "exceed",
    ];
    if failure.iter().any(|word| lower.contains(word)) {
        InputOutcome::Failed
    } else {
        InputOutcome::Succeeded
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, from = "SavedInput")]
pub struct ScannedInput {
    pub kind: InputKind,
    pub path: PathBuf,
    /// Shown instead of the file name when set (the sample's original name).
    pub name: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub outcome: InputOutcome,
    /// Why the input failed or was skipped, or a note on a success.
    pub reason: String,
    /// Coverage facts: memory blocks and gaps, packets, events per category.
    pub detail: String,
    /// A caveat on how far this input's result can be trusted.
    pub warning: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SavedInput {
    kind: InputKind,
    path: PathBuf,
    name: String,
    size: Option<u64>,
    sha256: Option<String>,
    outcome: SavedOutcome,
    reason: String,
    detail: String,
    warning: String,
}

impl From<SavedInput> for ScannedInput {
    fn from(saved: SavedInput) -> Self {
        let outcome = match saved.outcome {
            SavedOutcome::Succeeded => InputOutcome::Succeeded,
            SavedOutcome::Failed => InputOutcome::Failed,
            SavedOutcome::Skipped => InputOutcome::Skipped,
            SavedOutcome::Partial => legacy_partial(&saved.reason),
        };
        Self {
            kind: saved.kind,
            path: saved.path,
            name: saved.name,
            size: saved.size,
            sha256: saved.sha256,
            outcome,
            reason: saved.reason,
            detail: saved.detail,
            warning: saved.warning,
        }
    }
}

impl ScannedInput {
    pub fn new(kind: InputKind, path: impl Into<PathBuf>) -> Self {
        Self {
            kind,
            path: path.into(),
            ..Self::default()
        }
    }

    /// The file's current size, when it can be read.
    pub(super) fn sized(mut self) -> Self {
        self.size = fs::metadata(&self.path).ok().map(|metadata| metadata.len());
        self
    }

    pub(super) fn size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub(super) fn sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }

    pub(super) fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// A completed scan that carries a note.
    pub(super) fn note(mut self, note: impl Into<String>) -> Self {
        self.reason = note.into();
        self
    }

    pub(super) fn failed(mut self, reason: impl Into<String>) -> Self {
        self.outcome = InputOutcome::Failed;
        self.reason = reason.into();
        self
    }

    pub(super) fn warning(mut self, warning: impl Into<String>) -> Self {
        self.warning = warning.into();
        self
    }

    pub(super) fn skipped(mut self, reason: impl Into<String>) -> Self {
        self.outcome = InputOutcome::Skipped;
        self.reason = reason.into();
        self
    }

    pub(super) fn bounded(&self) -> bool {
        self.path.as_os_str().len() <= 4096
            && self.name.len() <= 4096
            && self.reason.len() <= 4096
            && self.detail.len() <= 4096
            && self.warning.len() <= 4096
            && self.sha256.as_ref().is_none_or(|sha256| sha256.len() <= 64)
    }
}

impl Report {
    /// Record one input; past the row limit the input only counts as omitted.
    pub(super) fn input(&mut self, input: ScannedInput) {
        let inputs = self.inputs.get_or_insert_with(Vec::new);
        if inputs.len() < INPUT_LIMIT {
            inputs.push(input);
        } else {
            self.omitted_evidence += 1;
        }
    }
}

/// Memory rows: blocks scanned and mapped ranges that were not captured.
pub(super) fn memory_input(
    kind: InputKind,
    path: &Path,
    result: &Result<(), String>,
    blocks: u64,
    gaps: u64,
) -> ScannedInput {
    let detail = format!(
        "{} {} of up to 64 MiB · {} {} not captured",
        group_digits(blocks),
        if blocks == 1 { "block" } else { "blocks" },
        group_digits(gaps),
        if gaps == 1 { "range" } else { "ranges" }
    );
    let input = ScannedInput::new(kind, path).sized();
    // Reading stopped on an error or a budget: the engine did not finish this
    // dump, whether or not some blocks were scanned first.
    if let Err(error) = result
        && blocks == 0
    {
        return input.failed(error.clone());
    }
    let input = input.detail(detail);
    match result {
        Err(error) => input.failed(format!(
            "stopped after {} {}: {error}",
            group_digits(blocks),
            if blocks == 1 { "block" } else { "blocks" }
        )),
        Ok(()) if gaps > 0 => input.note("mapped ranges missing from the dump were excluded"),
        Ok(()) => input,
    }
}

#[derive(Deserialize)]
struct JournalLine {
    kind: String,
    #[serde(default)]
    event: Option<JournalEvent>,
    #[serde(default)]
    complete: Option<bool>,
    #[serde(default)]
    omitted: Option<u64>,
}

#[derive(Deserialize)]
struct JournalEvent {
    category: String,
}

/// Shown on the journal row and beside the Sigma results: the events are a
/// translation, so a rule written for a real Sysmon or auditd log can find less
/// than it would there.
pub const SIGMA_COVERAGE_WARNING: &str = "Sigma events are converted from the syscall trace and may not cover everything a Sysmon or auditd log would contain.";

/// The journal row. The adapter ran on whatever the journal held, so the row
/// succeeds even when the journal is a prefix or has unmapped categories or
/// missing fields; what was left out is a note, and the coverage warning is
/// always shown.
pub(super) fn journal_input(
    original: &Path,
    copy: &Path,
    sha256: Option<&str>,
    partial: bool,
) -> ScannedInput {
    let mut input = ScannedInput::new(InputKind::EventJournal, original);
    let Ok(text) = fs::read_to_string(copy) else {
        return input.skipped("the event journal could not be read");
    };
    input = input.size(text.len() as u64);
    if let Some(sha256) = sha256 {
        input = input.sha256(sha256);
    }
    let mut categories = BTreeMap::<String, u64>::new();
    let mut end = None;
    for line in text.lines() {
        let Ok(line) = serde_json::from_str::<JournalLine>(line) else {
            continue;
        };
        match (line.kind.as_str(), line.event) {
            ("event", Some(event)) => *categories.entry(event.category).or_default() += 1,
            ("end", _) => end = Some((line.complete.unwrap_or(false), line.omitted.unwrap_or(0))),
            _ => {}
        }
    }
    let detail = super::journal::category_detail(&categories);
    input = input.detail(detail).warning(SIGMA_COVERAGE_WARNING);
    match end {
        None => input.note("the journal has no end record; it was still being written"),
        Some((_, omitted)) if omitted > 0 => input.note(format!(
            "{} oversized events were left out of the journal",
            group_digits(omitted)
        )),
        Some((false, _)) => input.note("the journal does not cover every recorded call"),
        Some((true, _)) if partial => input.note("events were still being captured"),
        Some((true, _)) => input,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_rows_count_events_per_category_and_notice_an_open_journal() {
        let dir = std::env::temp_dir().join(format!("ant-inputs-{}", crate::storage::unique_id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(JOURNAL_FILE);
        let event = |category: &str| {
            format!(
                "{{\"kind\":\"event\",\"event\":{{\"category\":\"{category}\",\"fields\":{{}},\"evidence\":{{\"kind\":\"call\",\"stream\":1,\"cookie\":1,\"call\":1}}}}}}\n"
            )
        };
        let body = format!(
            "{{\"kind\":\"header\"}}\n{}{}{}",
            event("process_creation"),
            event("file_event"),
            event("process_creation")
        );
        fs::write(&path, &body).unwrap();
        let open = journal_input(&path, &path, Some("ab"), false);
        // An open journal was still evaluated: a note, not a failure.
        assert_eq!(open.outcome, InputOutcome::Succeeded);
        assert!(open.reason.contains("no end record"), "{}", open.reason);
        assert_eq!(open.detail, "3 events · process_creation 2 · file_event 1");
        fs::write(
            &path,
            format!("{body}{{\"kind\":\"end\",\"complete\":true,\"events\":3,\"omitted\":0}}\n"),
        )
        .unwrap();
        let whole = journal_input(&path, &path, Some("ab"), false);
        assert_eq!(whole.outcome, InputOutcome::Succeeded);
        assert!(whole.reason.is_empty());
        assert_eq!(whole.sha256.as_deref(), Some("ab"));
        let live = journal_input(&path, &path, None, true);
        assert_eq!(live.outcome, InputOutcome::Succeeded);
        assert_eq!(live.reason, "events were still being captured");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn memory_rows_say_what_was_left_out() {
        let path = Path::new("/nonexistent/core");
        let whole = memory_input(InputKind::CoreDump, path, &Ok(()), 2, 0);
        assert_eq!(whole.outcome, InputOutcome::Succeeded);
        assert_eq!(
            whole.detail,
            "2 blocks of up to 64 MiB · 0 ranges not captured"
        );
        let gaps = memory_input(InputKind::CoreDump, path, &Ok(()), 2, 3);
        assert_eq!(gaps.outcome, InputOutcome::Succeeded);
        assert!(gaps.reason.contains("missing from the dump"));
        let stopped = memory_input(InputKind::MemoryDump, path, &Err("budget".into()), 1, 0);
        assert_eq!(
            (stopped.outcome, stopped.reason.as_str()),
            (InputOutcome::Failed, "stopped after 1 block: budget")
        );
        let none = memory_input(InputKind::MemoryDump, path, &Err("budget".into()), 0, 0);
        assert_eq!(
            (none.outcome, none.reason.as_str()),
            (InputOutcome::Failed, "budget")
        );
        assert!(none.detail.is_empty(), "a failed dump has no block counts");
    }

    #[test]
    fn reports_saved_before_inputs_load_without_a_list() {
        let identity = Identity {
            vm_id: "v".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            root_cookie: 1,
        };
        let mut value = serde_json::to_value(Report::empty(Engine::Yara, identity)).unwrap();
        value.as_object_mut().unwrap().remove("inputs");
        let old: Report = serde_json::from_value(value).unwrap();
        assert!(old.inputs.is_none());
    }

    #[test]
    fn a_journal_with_unmapped_categories_succeeds_and_carries_the_coverage_warning() {
        let dir = std::env::temp_dir().join(format!("ant-inputs-{}", crate::storage::unique_id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(JOURNAL_FILE);
        // A category no Sigma rule maps to, and no fields at all.
        fs::write(
            &path,
            concat!(
                "{\"kind\":\"header\"}\n",
                "{\"kind\":\"event\",\"event\":{\"category\":\"unmapped_thing\",\"fields\":{},\"evidence\":{\"kind\":\"call\",\"stream\":1,\"cookie\":1,\"call\":1}}}\n",
                "{\"kind\":\"end\",\"complete\":true,\"events\":1,\"omitted\":0}\n",
            ),
        )
        .unwrap();
        let input = journal_input(&path, &path, None, false);
        assert_eq!(input.outcome, InputOutcome::Succeeded);
        assert_eq!(input.warning, SIGMA_COVERAGE_WARNING);
        assert!(input.warning.contains("Sysmon or auditd"));
        // Even a prefix of the journal is a success with the same warning.
        assert_eq!(
            journal_input(&path, &path, None, true).warning,
            SIGMA_COVERAGE_WARNING
        );
        // An unreadable journal was never scanned and has nothing to warn about.
        let missing = journal_input(&path, &dir.join("absent"), None, false);
        assert_eq!(missing.outcome, InputOutcome::Skipped);
        assert!(missing.warning.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    /// Reports saved before the outcome change name `scanned` and `partial`.
    /// `scanned` is Succeeded. `partial` meant either "the engine failed or
    /// stopped" or "it finished with a caveat"; only the reason says which, so
    /// a failure-worded reason maps to Failed (the saved result stays honest
    /// about the Suricata run that failed) and any other becomes Succeeded
    /// with the old reason kept as its note.
    #[test]
    fn rows_saved_with_the_old_outcomes_still_load() {
        let load = |outcome: &str, reason: &str| -> ScannedInput {
            serde_json::from_value(serde_json::json!({
                "kind": "capture", "path": "/r/a.pcap", "outcome": outcome, "reason": reason,
            }))
            .unwrap()
        };
        let scanned = load("scanned", "");
        assert_eq!(scanned.outcome, InputOutcome::Succeeded);
        let failed = load(
            "partial",
            "Suricata failed or timed out; alerts are partial",
        );
        assert_eq!(failed.outcome, InputOutcome::Failed);
        assert_eq!(
            failed.reason,
            "Suricata failed or timed out; alerts are partial"
        );
        for reason in [
            "alerts could not be read: invalid EVE record",
            "memory scan reached its time / 512 MiB input budget",
        ] {
            assert_eq!(
                load("partial", reason).outcome,
                InputOutcome::Failed,
                "{reason}"
            );
        }
        for reason in [
            "still being captured; the complete prefix was scanned",
            "mapped ranges missing from the dump were excluded",
            "events were still being captured",
            "",
        ] {
            let caveat = load("partial", reason);
            assert_eq!(caveat.outcome, InputOutcome::Succeeded, "{reason}");
            assert_eq!(caveat.reason, reason);
        }
        assert_eq!(load("skipped", "x").outcome, InputOutcome::Skipped);
        // Rows now saved round-trip, and a whole old report loads.
        let row = ScannedInput::new(InputKind::Capture, "/r/a.pcap").failed("exited with code 1");
        let text = serde_json::to_string(&row).unwrap();
        assert!(text.contains("\"failed\""), "{text}");
        assert_eq!(serde_json::from_str::<ScannedInput>(&text).unwrap(), row);
        let identity = Identity {
            vm_id: "v".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            root_cookie: 1,
        };
        let mut value = serde_json::to_value(Report::empty(Engine::Ids, identity)).unwrap();
        value["inputs"] = serde_json::json!([{"kind": "capture", "path": "/r/a.pcap", "outcome": "partial", "reason": "Suricata failed or timed out; alerts are partial", "detail": "0 packets"}]);
        let old: Report = serde_json::from_value(value).unwrap();
        assert_eq!(old.inputs.unwrap()[0].outcome, InputOutcome::Failed);
    }
}
