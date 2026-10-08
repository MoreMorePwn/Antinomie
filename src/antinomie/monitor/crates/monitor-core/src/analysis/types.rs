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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSection {
    pub kind: AnalysisKind,
    pub state: AnalysisSectionState,
    pub summary: String,
    pub entries: Vec<AnalysisEntry>,
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
