// SPDX-License-Identifier: MIT
//! Community and custom rule packs under the Antinomie data directory.
//!
//! Production scans read only what this manager has installed and enabled.
//! Opening the manager does not download anything; catalog fetches and pack
//! installs are separate calls. Compiled YARA rules and converted Sigma queries
//! are not stored here — they are derived when a scan starts.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

mod catalog;
mod engines;
mod files;
mod groups;
mod ids;
mod index;
mod packs;
mod registry;
mod requirements;
mod selection;
mod sigma;
mod yara;

pub use self::{
    catalog::*, groups::*, index::*, packs::*, registry::*, requirements::*, selection::*,
};
use self::{files::*, ids::*, sigma::*, yara::*};
pub use engines::{
    DEFAULT_SIGMA_PYTHON, ToolConfig, ToolFacts, ToolProbe, refresh_tool_facts, sigma_interpreter,
    tool_facts, try_tool_facts,
};

pub const CATALOG_SCHEMA: u32 = 1;
/// Public rules bucket. This is not the dataset repository of the same name.
pub const CATALOG_URL: &str =
    "https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve/catalog.json";

const ENGINES: [&str; 3] = ["yara", "ids", "sigma"];
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MEMBERS: usize = 8_000;

/// Current derived-index parser. Indexes from the defective YARA lexer are 0.
pub const INDEX_PARSER: u32 = 2;

#[cfg(test)]
thread_local! {
    static FAIL_ONCE: std::cell::RefCell<BTreeSet<&'static str>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };
}

/// Fail the next matching operation on this thread only.
#[cfg(test)]
pub(crate) fn fail_once(op: &'static str) {
    FAIL_ONCE.with(|ops| {
        ops.borrow_mut().insert(op);
    });
}

#[cfg(test)]
fn take_fail(op: &str) -> bool {
    FAIL_ONCE.with(|ops| ops.borrow_mut().remove(op))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackEntry {
    pub id: String,
    pub engine: String,
    pub name: String,
    pub version: String,
    pub upstream_revision: String,
    pub upstream_url: String,
    pub download_url: String,
    pub sha256: String,
    pub size: u64,
    pub app: String,
    pub engine_requirement: String,
    pub rules: u64,
    pub helpers: u64,
    pub license: String,
    pub evidence: Vec<String>,
    pub limits: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    pub schema: u32,
    pub packs: Vec<PackEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    pub schema: u32,
    pub packs: Vec<InstalledPack>,
    pub groups: Vec<CustomGroup>,
    /// Stable key (`pack:<id>` or `group:<id>`) to disabled rule ids.
    pub disabled: BTreeMap<String, BTreeSet<String>>,
    /// Increases on every successful registry write.
    #[serde(default)]
    pub generation: u64,
    /// Disabled ids that no longer name one rule after an index rebuild.
    #[serde(default)]
    pub obsolete_disabled: BTreeMap<String, Vec<String>>,
    /// Why each obsolete id was dropped, by key and id.
    #[serde(default)]
    pub obsolete_reasons: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstalledPack {
    pub id: String,
    pub engine: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub sha256: String,
    pub upstream_revision: String,
    pub upstream_url: String,
    pub license: String,
    pub evidence: Vec<String>,
    pub limits: Vec<String>,
    /// Versions retained on disk, newest selection is `version`.
    pub versions: Vec<String>,
    /// Application requirement recorded for `version` when it was installed.
    #[serde(default)]
    pub app: String,
    /// Engine requirement recorded for `version` when it was installed. Empty
    /// in registries written before requirements were retained.
    #[serde(default)]
    pub engine_requirement: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomGroup {
    pub id: String,
    pub name: String,
    pub engine: String,
    pub revision: u64,
    pub enabled: bool,
    pub tags: Vec<String>,
    /// Soft-deleted groups stay on disk so older scan reports keep a source.
    pub deleted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedRule {
    pub id: String,
    pub name: String,
    pub file: String,
    pub helper: bool,
    pub tags: Vec<String>,
    pub severity: String,
    pub license: String,
    pub source_url: String,
    pub condition: String,
    pub references: Vec<String>,
    pub evidence: Vec<String>,
    pub compatible: bool,
    pub reason: String,
    /// SHA-256 of the rule body. Empty on indexes written before body hashes.
    #[serde(default)]
    pub content_sha256: String,
    /// Rule identifiers this rule's condition references. Empty for non-YARA rules.
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndexFile {
    #[serde(default)]
    parser: u32,
    rules: Vec<IndexedRule>,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub directory: Option<PathBuf>,
    pub digest: String,
    pub warnings: Vec<String>,
    pub enabled_rules: u64,
    pub excluded_rules: u64,
}

pub fn rules_root(data_dir: &Path) -> PathBuf {
    data_dir.join("rules")
}

fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && id.len() <= 64
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A single directory or file name. Absolute paths and separators are rejected
/// before `Path::join`, which would otherwise replace the managed root.
fn path_component(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 80 {
        return Err(format!("{label} is empty or too long"));
    }
    if value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || Path::new(value).is_absolute()
    {
        return Err(format!("{label} is not a single path component"));
    }
    Ok(())
}

fn clip(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn slug(name: &str) -> String {
    let mut out = String::new();
    for character in name.chars().flat_map(|c| c.to_lowercase()) {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            out.push(character);
        } else if (character == '-' || character == ' ' || character == '_')
            && !out.ends_with('-')
            && !out.is_empty()
        {
            out.push('-');
        }
        if out.len() == 48 {
            break;
        }
    }
    if out.is_empty() { "group".into() } else { out }
}

#[cfg(test)]
mod tests;
