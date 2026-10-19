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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputOutcome {
    #[default]
    Scanned,
    /// Evaluated in part; `reason` says what was left out.
    Partial,
    /// Not evaluated; `reason` says why.
    Skipped,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannedInput {
    pub kind: InputKind,
    pub path: PathBuf,
    /// Shown instead of the file name when set (the sample's original name).
    pub name: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub outcome: InputOutcome,
    pub reason: String,
    /// Coverage facts: memory blocks and gaps, packets, events per category.
    pub detail: String,
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

    pub(super) fn partial(mut self, reason: impl Into<String>) -> Self {
        self.outcome = InputOutcome::Partial;
        self.reason = reason.into();
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
    if let Err(error) = result
        && blocks == 0
    {
        return input.skipped(error.clone());
    }
    let input = input.detail(detail);
    match result {
        Err(error) => input.partial(error.clone()),
        Ok(()) if gaps > 0 => input.partial("mapped ranges missing from the dump were excluded"),
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

/// The journal row: events per category and whether the journal is whole.
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
    input = input.detail(detail);
    match end {
        None => input.partial("the journal has no end record; it was still being written"),
        Some((_, omitted)) if omitted > 0 => input.partial(format!(
            "{} oversized events were left out of the journal",
            group_digits(omitted)
        )),
        Some((false, _)) => input.partial("the journal does not cover every recorded call"),
        Some((true, _)) if partial => input.partial("events were still being captured"),
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
        assert_eq!(open.outcome, InputOutcome::Partial);
        assert_eq!(open.detail, "3 events · process_creation 2 · file_event 1");
        fs::write(
            &path,
            format!("{body}{{\"kind\":\"end\",\"complete\":true,\"events\":3,\"omitted\":0}}\n"),
        )
        .unwrap();
        let whole = journal_input(&path, &path, Some("ab"), false);
        assert_eq!(whole.outcome, InputOutcome::Scanned);
        assert_eq!(whole.sha256.as_deref(), Some("ab"));
        assert_eq!(
            journal_input(&path, &path, None, true).outcome,
            InputOutcome::Partial
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn memory_rows_say_what_was_left_out() {
        let path = Path::new("/nonexistent/core");
        let whole = memory_input(InputKind::CoreDump, path, &Ok(()), 2, 0);
        assert_eq!(whole.outcome, InputOutcome::Scanned);
        assert_eq!(
            whole.detail,
            "2 blocks of up to 64 MiB · 0 ranges not captured"
        );
        let gaps = memory_input(InputKind::CoreDump, path, &Ok(()), 2, 3);
        assert_eq!(gaps.outcome, InputOutcome::Partial);
        let stopped = memory_input(InputKind::MemoryDump, path, &Err("budget".into()), 1, 0);
        assert_eq!(
            (stopped.outcome, stopped.reason.as_str()),
            (InputOutcome::Partial, "budget")
        );
        let none = memory_input(InputKind::MemoryDump, path, &Err("budget".into()), 0, 0);
        assert_eq!(none.outcome, InputOutcome::Skipped);
        assert!(none.detail.is_empty(), "a skipped dump has no block counts");
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
}
