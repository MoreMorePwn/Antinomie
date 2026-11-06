// SPDX-License-Identifier: GPL-3.0-only
//! Reading a MalwareBazaar record without ever failing on one bad field.
//!
//! The API returns `null` for most things it does not know (`last_seen`,
//! `imphash`, `comment`, `intelligence.mail`, a YARA rule's `author`), lists
//! where an object is usual (`Spamhaus_HBL`) and `null` inside vendor objects
//! (`family_name`). Every value is read on its own: a field that is missing,
//! null or of an unexpected shape is left out, and the rest of the record is
//! kept.
use super::SampleInfo;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One YARA rule that matched the sample, as MalwareBazaar lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct YaraHit {
    pub rule_name: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub reference: Option<String>,
}

/// What MalwareBazaar's partners say about a sample (hash lookups only).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Intel {
    /// ClamAV signature names.
    pub clamav: Vec<String>,
    /// The family Triage named, such as `prometei_elf`.
    pub triage_family: Option<String>,
    pub triage_score: Option<String>,
    pub triage_link: Option<String>,
    pub yara: Vec<YaraHit>,
    /// Every vendor that has an entry, whatever its shape.
    pub vendors: Vec<String>,
    /// A reporter's comment.
    pub comment: Option<String>,
    pub last_seen: Option<String>,
}

impl Intel {
    pub fn is_empty(&self) -> bool {
        *self == Intel::default()
    }

    /// Plain lines for a tooltip: what the partners named, nothing more.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(family) = &self.triage_family {
            lines.push(match &self.triage_score {
                Some(score) => format!("Triage family: {family} (score {score})"),
                None => format!("Triage family: {family}"),
            });
        }
        if !self.clamav.is_empty() {
            lines.push(format!("ClamAV: {}", self.clamav.join(", ")));
        }
        if !self.yara.is_empty() {
            let names: Vec<&str> = self
                .yara
                .iter()
                .map(|rule| rule.rule_name.as_str())
                .collect();
            lines.push(format!("YARA rules: {}", names.join(", ")));
        }
        lines
    }
}

impl SampleInfo {
    /// What the sample window's family cell says on hover: the family, the
    /// tags and what the partners named. None when MalwareBazaar sent no
    /// partner facts (a search listing).
    pub fn partner_text(&self) -> Option<String> {
        let intel = self.intel.as_ref()?;
        let mut lines = vec![format!(
            "Family: {}",
            self.signature.as_deref().unwrap_or("—")
        )];
        if !self.tags.is_empty() {
            lines.push(format!("Tags: {}", self.tags.join(", ")));
        }
        lines.extend(intel.lines());
        Some(lines.join("\n"))
    }
}

/// A value as text: strings, numbers and booleans; null and the rest is none.
pub(super) fn text(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(text) => text.trim().to_owned(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => return None,
    };
    (!text.is_empty()).then_some(text)
}

fn texts(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(|item| text(Some(item))).collect(),
        _ => Vec::new(),
    }
}

fn number(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(number)) => number.as_u64().unwrap_or(0),
        Some(Value::String(text)) => text.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn yara(value: Option<&Value>) -> Vec<YaraHit> {
    let Some(Value::Array(rules)) = value else {
        return Vec::new();
    };
    rules
        .iter()
        .filter_map(|rule| {
            Some(YaraHit {
                rule_name: text(rule.get("rule_name"))?,
                author: text(rule.get("author")),
                description: text(rule.get("description")),
                reference: text(rule.get("reference")),
            })
        })
        .collect()
}

fn intel(record: &Value) -> Intel {
    let triage = record.pointer("/vendor_intel/Triage");
    // A vendor entry may be an object, a list of objects or something new.
    let vendors = match record.get("vendor_intel") {
        Some(Value::Object(vendors)) => vendors
            .iter()
            .filter(|(_, entry)| !entry.is_null())
            .map(|(name, _)| name.clone())
            .collect(),
        _ => Vec::new(),
    };
    Intel {
        clamav: texts(record.pointer("/intelligence/clamav")),
        triage_family: text(triage.and_then(|t| t.get("malware_family"))),
        triage_score: text(triage.and_then(|t| t.get("score"))),
        triage_link: text(triage.and_then(|t| t.get("link"))),
        yara: yara(record.get("yara_rules")),
        vendors,
        comment: text(record.get("comment")),
        last_seen: text(record.get("last_seen")),
    }
}

impl SampleInfo {
    /// One record of a MalwareBazaar reply. Never fails: each field that is
    /// null, missing or of another type is simply left empty.
    pub fn from_bazaar(record: &Value) -> SampleInfo {
        let intel = intel(record);
        SampleInfo {
            sha256_hash: text(record.get("sha256_hash")).unwrap_or_default(),
            sha1_hash: text(record.get("sha1_hash")).unwrap_or_default(),
            md5_hash: text(record.get("md5_hash")).unwrap_or_default(),
            file_name: text(record.get("file_name")).unwrap_or_default(),
            file_size: number(record.get("file_size")),
            file_type: text(record.get("file_type")).unwrap_or_default(),
            file_type_mime: text(record.get("file_type_mime")).unwrap_or_default(),
            signature: text(record.get("signature")),
            tags: texts(record.get("tags")),
            first_seen: text(record.get("first_seen")).unwrap_or_default(),
            reporter: text(record.get("reporter")).unwrap_or_default(),
            file_arch: text(record.get("file_arch")),
            intel: (!intel.is_empty()).then_some(intel),
        }
    }
}

/// The records of a reply's `data`: a list, or one record. Anything else is
/// no records.
pub(super) fn records(data: &Value) -> Vec<SampleInfo> {
    match data {
        Value::Array(records) => records
            .iter()
            .filter(|record| record.is_object())
            .map(SampleInfo::from_bazaar)
            .collect(),
        Value::Object(_) => vec![SampleInfo::from_bazaar(data)],
        _ => Vec::new(),
    }
}
