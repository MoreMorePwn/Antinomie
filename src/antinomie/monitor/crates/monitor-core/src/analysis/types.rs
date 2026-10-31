// SPDX-License-Identifier: GPL-3.0-only
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisKind {
    Metadata,
    Structures,
    Strings,
    /// The built-in and custom regex patterns, matched over the strings.
    /// Its own choice, though its matches are listed in the Regex matches tab.
    Regex,
    Entropy,
    Hardening,
    Rules,
    Identification,
    Capabilities,
    Disassembly,
    Decompilation,
    /// Signatures of embedded files and data found by binwalk.
    Embedded,
    /// Decoded, stack and tight strings recovered by FLOSS.
    Floss,
    /// Packer detection and the layers unpacking recovered from the file.
    Unpacking,
}

impl AnalysisKind {
    pub const TRIAGE: &'static [Self] = &[
        Self::Metadata,
        Self::Structures,
        Self::Strings,
        Self::Regex,
        Self::Entropy,
        Self::Hardening,
        Self::Rules,
        Self::Identification,
        Self::Capabilities,
        Self::Embedded,
        Self::Unpacking,
    ];
    pub const DEEP: &'static [Self] = &[Self::Disassembly, Self::Decompilation, Self::Floss];

    pub fn label(self) -> &'static str {
        match self {
            Self::Metadata => "File metadata and hashes",
            Self::Structures => "Headers, sections, imports and exports",
            Self::Strings => "Strings",
            Self::Regex => "Regex matches",
            Self::Entropy => "Entropy",
            Self::Hardening => "Hardening indicators",
            Self::Rules => "Rule matches",
            Self::Identification => "Compiler and packer identification",
            Self::Capabilities => "Capabilities",
            Self::Disassembly => "Disassembly",
            Self::Decompilation => "Decompilation",
            Self::Embedded => "Embedded content",
            Self::Floss => "FLOSS strings (decoded, stack, tight)",
            Self::Unpacking => "Unpacking (packer and unpacked layers)",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "SelectionWire", into = "SelectionWire")]
pub struct AnalysisSelection {
    pub enabled: bool,
    pub checks: Vec<AnalysisKind>,
    /// Minutes each analysis tool may run; 0 leaves each tool its own limit
    /// (capa 4, FLOSS 8, binwalk 3, the decompiler 14).
    pub time_limit_minutes: u32,
}

/// Longest time limit a run may ask for, in minutes.
pub const TIME_LIMIT_MAX_MINUTES: u32 = 480;

/// The seconds a time limit setting asks each analysis tool for; none when
/// the setting is 0 and every tool keeps its own limit.
pub fn time_limit_seconds(minutes: u32) -> Option<u64> {
    (minutes > 0).then(|| u64::from(minutes.min(TIME_LIMIT_MAX_MINUTES)) * 60)
}

/// How a selection is stored. `regex_split` marks a selection written after
/// Regex matches became their own check: one without it, saved while Regex
/// matches were part of Strings, gets Regex added once when it is read, and
/// is written back with the mark so a later unchecking sticks.
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct SelectionWire {
    enabled: bool,
    checks: Vec<AnalysisKind>,
    regex_split: bool,
    time_limit_minutes: u32,
}

impl Default for SelectionWire {
    fn default() -> Self {
        Self {
            enabled: false,
            checks: AnalysisKind::TRIAGE.to_vec(),
            regex_split: false,
            time_limit_minutes: 0,
        }
    }
}

impl From<SelectionWire> for AnalysisSelection {
    fn from(wire: SelectionWire) -> Self {
        let mut checks = wire.checks;
        let strings = checks
            .iter()
            .any(|kind| matches!(kind, AnalysisKind::Strings | AnalysisKind::Floss));
        if !wire.regex_split && strings && !checks.contains(&AnalysisKind::Regex) {
            checks.push(AnalysisKind::Regex);
        }
        Self {
            enabled: wire.enabled,
            checks,
            time_limit_minutes: wire.time_limit_minutes,
        }
    }
}

impl From<AnalysisSelection> for SelectionWire {
    fn from(selection: AnalysisSelection) -> Self {
        Self {
            enabled: selection.enabled,
            checks: selection.checks,
            regex_split: true,
            time_limit_minutes: selection.time_limit_minutes,
        }
    }
}

impl Default for AnalysisSelection {
    fn default() -> Self {
        Self {
            enabled: false,
            checks: AnalysisKind::TRIAGE.to_vec(),
            time_limit_minutes: 0,
        }
    }
}

impl AnalysisSelection {
    pub fn validate(&self) -> Result<(), String> {
        if self.checks.len() > AnalysisKind::TRIAGE.len() + AnalysisKind::DEEP.len() {
            return Err("more analyses selected than exist".into());
        }
        for (index, kind) in self.checks.iter().enumerate() {
            if self.checks[..index].contains(kind) {
                return Err("duplicate analysis selection".into());
            }
        }
        if self.time_limit_minutes > TIME_LIMIT_MAX_MINUTES {
            return Err(format!(
                "the analysis time limit is at most {TIME_LIMIT_MAX_MINUTES} minutes"
            ));
        }
        if self.enabled && self.checks.is_empty() {
            return Err("select at least one static analysis".into());
        }
        if self.checks.contains(&AnalysisKind::Regex)
            && !self
                .checks
                .iter()
                .any(|kind| matches!(kind, AnalysisKind::Strings | AnalysisKind::Floss))
        {
            return Err("Regex matches need Strings or FLOSS strings".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisState {
    Acquiring,
    Queued,
    Running,
    Complete,
    Partial,
    Unavailable,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSectionState {
    Pending,
    Running,
    Complete,
    Partial,
    Unavailable,
    /// The tool ran out of its time limit and was stopped. Whatever it had
    /// found by then is kept. Reports from before this state existed record
    /// the same case as `Unavailable`.
    Timeout,
}

impl AnalysisSectionState {
    /// The section may hold rows: it finished, in whole or in part.
    pub fn has_result(self) -> bool {
        matches!(self, Self::Complete | Self::Partial | Self::Timeout)
    }
}

/// Which bound cut a category's result short, and so where it is changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisLimitKind {
    /// A tool was stopped at its time limit (Settings > Analysis).
    Time,
    /// More rows than the report or a listing keeps.
    Rows,
    /// A file, a tool's output or a listing was bigger than the analysis reads.
    Size,
    /// Text of a row or a list inside it was cut to its bound.
    Text,
    /// The file itself is inconsistent (a range past its end, unreadable tables).
    Input,
}

/// One bound a category met, said plainly for the person reading the report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisLimit {
    pub kind: AnalysisLimitKind,
    pub text: String,
    /// For a time limit, the seconds the tool was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisEntry {
    pub label: String,
    pub value: String,
    pub offset: Option<u64>,
    /// Optional revision-1 structured evidence; missing on legacy reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<AnalysisRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisRange {
    /// File offset and length, in octets.
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisAddressKind {
    FileOffset,
    ObjectAddress,
    RelativeVirtualAddress,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisLocation {
    pub kind: AnalysisAddressKind,
    pub value: u64,
    /// Present only when the parser establishes a corresponding file range.
    pub file_range: Option<AnalysisRange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisRecord {
    pub revision: u16,
    /// Nonzero, stable within one report section, including truncation.
    pub id: u64,
    pub location: Option<AnalysisLocation>,
    pub data: AnalysisData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnalysisData {
    Field {
        group: String,
    },
    Section {
        name: String,
        address: u64,
        virtual_size: u64,
        file_size: Option<u64>,
        raw_flags: String,
        flags: Vec<String>,
    },
    Symbol {
        name: String,
        kind: String,
        scope: String,
        undefined: bool,
        address: Option<u64>,
        size: u64,
    },
    Import {
        name: Option<String>,
        library: Option<String>,
        ordinal: Option<u64>,
    },
    Export {
        name: Option<String>,
        ordinal: Option<u64>,
        address: Option<u64>,
    },
    String {
        encoding: String,
        byte_len: u64,
        retained_len: u64,
    },
    Entropy {
        range: AnalysisRange,
        /// Shannon entropy in thousandths of a bit per octet, 0..=8000.
        milli_bits: u32,
    },
    Property {
        scope: String,
        observed: String,
        evidence: String,
    },
    /// One decoded machine instruction; `function` names the containing
    /// symbol when one covers the address.
    Instruction {
        address: u64,
        bytes: String,
        mnemonic: String,
        operands: String,
        function: Option<String>,
        /// A symbol naming this address other than a function start (Ghidra
        /// listing only).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        /// Where this instruction refers to: call and jump targets, data it
        /// reads or writes (Ghidra listing only).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        targets: Vec<AnalysisReference>,
        /// Who refers to this address; the first few only (Ghidra listing only).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        xrefs: Vec<AnalysisReference>,
    },
    /// Start of a function in a disassembly or decompilation listing.
    Function {
        name: String,
        address: u64,
        size: u64,
    },
    /// One line of decompiled source; the entry value is the line text.
    SourceLine {
        function: String,
        address: Option<u64>,
        line: u32,
    },
    /// A rule that matched; the entry value lists the matched strings.
    RuleMatch {
        rule: String,
        namespace: String,
        tags: Vec<String>,
        ruleset: String,
    },
    /// A capability reported by a capability engine (for example capa).
    Capability {
        name: String,
        namespace: String,
        attack: Vec<String>,
        mbc: Vec<String>,
    },
    /// A signature of embedded content at a file offset (binwalk); the entry
    /// value is the signature's description.
    Signature {
        offset: u64,
        description: String,
    },
    /// A string FLOSS recovered. `origin` is "decoded", "stack", "tight" or
    /// "language" (Go and Rust strings); the entry value is the text. The
    /// addresses are the ones FLOSS reports for its own load of the file:
    /// `function` is the routine that built or decoded the string and
    /// `address` the place it was seen. A language string has neither and
    /// is located by file offset instead.
    FlossString {
        origin: String,
        encoding: String,
        function: Option<u64>,
        address: Option<u64>,
    },
    /// One phase of the unpack chain: the file as it came (index 0) or a layer
    /// an unpacker recovered from the one before. The entry value describes it.
    Layer {
        index: u32,
        /// "original", "UPX", "UPX (header repaired)".
        method: String,
        sha256: String,
        size: u64,
        /// The layer this one was unpacked from.
        parent: Option<u32>,
        /// The packer found in this layer, when there is one.
        packer: Option<String>,
        /// The layer's file in the report's artifacts (`layer-N.bin`).
        file: Option<String>,
        /// The report of this layer's own static analysis, once it is queued.
        report_id: Option<String>,
        note: String,
    },
    /// A compiler, language, linker, packer or protector identification;
    /// the entry value is the evidence.
    Identification {
        category: String,
        name: String,
        version: Option<String>,
    },
}

/// What a reference does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisReferenceKind {
    Call,
    Jump,
    Data,
    Other,
}

/// One reference between two addresses of the listing; `address` is the other
/// end (the target of a `targets` entry, the source of an `xrefs` entry), as
/// an object address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReference {
    pub address: u64,
    pub kind: AnalysisReferenceKind,
}

/// A category result too large for the report, kept beside it as JSON lines
/// of `AnalysisEntry` and read in pages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisListing {
    pub rows: u64,
    pub bytes: u64,
    /// The tool output or the listing bound cut the result short.
    pub truncated: bool,
}

/// The order a listing is read in: the table column and the direction.
/// Strings columns are Offset (0), Encoding (1), Length (2) and Text (3).
/// The other tables' columns differ by view (sections, symbols, ...), so
/// their sort names its column in `field` instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListingSort {
    pub column: usize,
    pub descending: bool,
    pub field: Option<StructureField>,
}

/// A column of the Structures and other record tables to sort by. Numbers order numerically
/// and come before rows that have none; the rest order as text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructureField {
    Name,
    Value,
    Address,
    Offset,
    VirtualSize,
    FileSize,
    Flags,
    Library,
    Ordinal,
    Kind,
    Scope,
    Defined,
    Size,
}

/// One page of a listing, optionally filtered by a case-insensitive query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisListingPage {
    pub report_id: String,
    pub kind: AnalysisKind,
    pub query: String,
    /// The order of the matching rows; `None` is the listing's own order.
    pub sort: Option<ListingSort>,
    /// Index of the first returned row among the matching rows.
    pub start: u64,
    /// Matching rows in the whole listing.
    pub total: u64,
    /// Listing row index and entry.
    pub rows: Vec<(u64, AnalysisEntry)>,
    /// Every function of a disassembly or decompilation listing with the number
    /// of lines under it, counted over the whole listing whatever the query.
    pub functions: Vec<AnalysisFunctionLines>,
}

/// How many lines one function has in a disassembly (instructions) or
/// decompilation (source lines) listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisFunctionLines {
    pub name: String,
    pub address: u64,
    pub lines: u64,
}

/// Bounded read-only specimen preview returned by the host archive API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisSpecimenPage {
    pub report_id: String,
    pub offset: u64,
    pub total_len: u64,
    pub data: Vec<u8>,
}

pub const ANALYSIS_PREVIEW_MAX_SIZE: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSection {
    pub kind: AnalysisKind,
    pub state: AnalysisSectionState,
    pub summary: String,
    pub entries: Vec<AnalysisEntry>,
    /// Engines and tools that produced this category, with versions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
    /// The complete result when it is kept beside the report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing: Option<AnalysisListing>,
    /// The disassembly listing Ghidra exported during the same run as this
    /// decompilation, kept beside the report as `ghidra-disassembly.jsonl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<AnalysisDisassembly>,
    /// The bounds this category met; empty for a result nothing cut short.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<AnalysisLimit>,
}

/// Ghidra's disassembly listing, exported by the same run as the decompilation
/// (so it covers every architecture Ghidra supports). Rows are `Instruction`
/// and `Function` records like the Disassembly category's own listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisDisassembly {
    pub listing: AnalysisListing,
    /// The tool and its version, for example "Ghidra 12.2".
    pub tool: String,
    /// Ghidra's language id, for example "x86:LE:64:default".
    pub language: String,
    /// "little" or "big".
    pub endian: String,
    pub pointer_bits: u32,
    pub functions: u64,
    pub instructions: u64,
    /// Why the listing stops short, empty when it is whole.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl AnalysisSection {
    pub fn new(kind: AnalysisKind) -> Self {
        Self {
            kind,
            state: AnalysisSectionState::Pending,
            summary: String::new(),
            entries: Vec::new(),
            tools: Vec::new(),
            listing: None,
            disassembly: None,
            limits: Vec::new(),
        }
    }
}

/// What a report is the analysis of when it is not a file of its own: a layer
/// that unpacking recovered from another report's file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisLayer {
    /// The report of the packed file.
    pub parent_id: String,
    /// Position in the unpack chain; the packed file is 0.
    pub index: u32,
    pub method: String,
    pub parent_sha256: String,
}

/// Where the specimen of a run's analysis came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecimenSource {
    /// The file the user uploaded, still on the host: copied into the run's
    /// specimen store and used because its hash equals the one the guest
    /// recorded.
    HostCopy,
    /// Read back from the guest.
    Guest,
}

impl SpecimenSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::HostCopy => "host copy, hash matched guest",
            Self::Guest => "fetched from guest",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub id: String,
    pub state: AnalysisState,
    pub source_path: String,
    pub specimen_sha256: Option<String>,
    /// Complete acquired specimen length, in octets.
    pub specimen_len: Option<u64>,
    pub reason: Option<String>,
    pub sections: Vec<AnalysisSection>,
    /// Set when this analysis is of a layer unpacked from another report's file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<AnalysisLayer>,
    /// Where the specimen came from; only the host sets it. The evidence
    /// identity is the guest-recorded hash whichever it was. None for a report
    /// from before this was recorded and for a host file with no guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub specimen_source: Option<SpecimenSource>,
    /// Seconds each tool of the checks still pending may run, when the run
    /// asked for a limit of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_limit_seconds: Option<u64>,
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    fn read(json: &str) -> AnalysisSelection {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_selection_saved_before_the_split_gets_regex_once() {
        let old = read(r#"{"enabled":true,"checks":["strings","entropy"]}"#);
        assert_eq!(
            old.checks,
            [
                AnalysisKind::Strings,
                AnalysisKind::Entropy,
                AnalysisKind::Regex
            ]
        );
        let floss = read(r#"{"enabled":true,"checks":["floss"]}"#);
        assert_eq!(floss.checks, [AnalysisKind::Floss, AnalysisKind::Regex]);
        // No strings, no regex.
        let none = read(r#"{"enabled":true,"checks":["entropy"]}"#);
        assert_eq!(none.checks, [AnalysisKind::Entropy]);
        // A missing field is the default, which already has it.
        assert_eq!(read("{}").checks, AnalysisKind::TRIAGE);
    }

    #[test]
    fn the_migration_is_idempotent_and_leaves_a_later_choice_alone() {
        let old = read(r#"{"enabled":true,"checks":["strings"]}"#);
        let saved = serde_json::to_string(&old).unwrap();
        assert_eq!(read(&saved), old);
        // The user unchecks Regex, saves, and reloads: it stays off.
        let mut chosen = old;
        chosen.checks.retain(|kind| *kind != AnalysisKind::Regex);
        let saved = serde_json::to_string(&chosen).unwrap();
        assert_eq!(read(&saved).checks, [AnalysisKind::Strings]);
        assert_eq!(read(&serde_json::to_string(&read(&saved)).unwrap()), chosen);
    }

    #[test]
    fn the_time_limit_is_saved_with_a_selection_and_is_optional_in_old_ones() {
        assert_eq!(
            read(r#"{"enabled":true,"checks":["strings"]}"#).time_limit_minutes,
            0
        );
        let mut chosen = read("{}");
        chosen.time_limit_minutes = 12;
        let saved = serde_json::to_string(&chosen).unwrap();
        assert_eq!(read(&saved).time_limit_minutes, 12);
        assert_eq!(time_limit_seconds(12), Some(720));
        assert_eq!(time_limit_seconds(0), None);
        assert_eq!(
            time_limit_seconds(u32::MAX),
            Some(u64::from(TIME_LIMIT_MAX_MINUTES) * 60)
        );
        chosen.time_limit_minutes = TIME_LIMIT_MAX_MINUTES + 1;
        assert!(chosen.validate().is_err());
        chosen.time_limit_minutes = TIME_LIMIT_MAX_MINUTES;
        assert!(chosen.validate().is_ok());
    }
}
