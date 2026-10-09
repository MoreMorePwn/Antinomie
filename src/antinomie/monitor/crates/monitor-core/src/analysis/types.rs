// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisKind {
    Metadata,
    Structures,
    Strings,
    Entropy,
    Hardening,
    Rules,
    Identification,
    Capabilities,
    Disassembly,
    Decompilation,
}

impl AnalysisKind {
    pub const TRIAGE: &'static [Self] = &[
        Self::Metadata,
        Self::Structures,
        Self::Strings,
        Self::Entropy,
        Self::Hardening,
        Self::Rules,
        Self::Identification,
        Self::Capabilities,
    ];
    pub const DEEP: &'static [Self] = &[Self::Disassembly, Self::Decompilation];

    pub fn label(self) -> &'static str {
        match self {
            Self::Metadata => "File metadata and hashes",
            Self::Structures => "Headers, sections, imports and exports",
            Self::Strings => "Strings",
            Self::Entropy => "Entropy",
            Self::Hardening => "Hardening indicators",
            Self::Rules => "Rule matches",
            Self::Identification => "Compiler and packer identification",
            Self::Capabilities => "Capabilities",
            Self::Disassembly => "Disassembly",
            Self::Decompilation => "Decompilation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisSelection {
    pub enabled: bool,
    pub checks: Vec<AnalysisKind>,
}

impl Default for AnalysisSelection {
    fn default() -> Self {
        Self {
            enabled: false,
            checks: AnalysisKind::TRIAGE.to_vec(),
        }
    }
}

impl AnalysisSelection {
    pub fn validate(&self) -> Result<(), String> {
        if self.checks.len() > 10 {
            return Err("at most ten analyses may be selected".into());
        }
        for (index, kind) in self.checks.iter().enumerate() {
            if self.checks[..index].contains(kind) {
                return Err("duplicate analysis selection".into());
            }
        }
        if self.enabled && self.checks.is_empty() {
            return Err("select at least one static analysis".into());
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
    Complete,
    Partial,
    Unavailable,
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
    /// A compiler, language, linker, packer or protector identification;
    /// the entry value is the evidence.
    Identification {
        category: String,
        name: String,
        version: Option<String>,
    },
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

/// One page of a listing, optionally filtered by a case-insensitive query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisListingPage {
    pub report_id: String,
    pub kind: AnalysisKind,
    pub query: String,
    /// Index of the first returned row among the matching rows.
    pub start: u64,
    /// Matching rows in the whole listing.
    pub total: u64,
    /// Listing row index and entry.
    pub rows: Vec<(u64, AnalysisEntry)>,
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
}
