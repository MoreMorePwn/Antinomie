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

pub const CATALOG_SCHEMA: u32 = 1;
/// Public rules bucket. This is not the dataset repository of the same name.
pub const CATALOG_URL: &str =
    "https://huggingface.co/buckets/MoreMorePwn/antinomie-rules/resolve/catalog.json";

const ENGINES: [&str; 3] = ["yara", "ids", "sigma"];
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MEMBERS: usize = 8_000;
const SIGMA_CATEGORIES: [&str; 9] = [
    "process_creation",
    "file_event",
    "file_delete",
    "file_rename",
    "file_access",
    "dns_query",
    "http_request",
    "antinomie_bpf",
    "antinomie_file_metadata",
];

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

pub fn validate_catalog(value: &Value) -> Result<Catalog, String> {
    let object = value.as_object().ok_or("catalog must be a JSON object")?;
    let schema = required_u64(object, "schema")?;
    if schema != u64::from(CATALOG_SCHEMA) {
        return Err(format!("unsupported rules catalog schema {schema}"));
    }
    let packs = object
        .get("packs")
        .and_then(Value::as_array)
        .ok_or("catalog packs must be an array")?;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for pack in packs {
        let entry = pack_entry(pack)?;
        if !seen.insert(entry.id.clone()) {
            return Err(format!("duplicate pack id {}", entry.id));
        }
        entries.push(entry);
    }
    Ok(Catalog {
        schema: CATALOG_SCHEMA,
        packs: entries,
    })
}

fn pack_entry(value: &Value) -> Result<PackEntry, String> {
    let object = value.as_object().ok_or("pack entry must be an object")?;
    let engine = required_string(object, "engine")?;
    if !ENGINES.contains(&engine.as_str()) {
        return Err(format!("unknown rules engine {engine}"));
    }
    let id = required_string(object, "id")?;
    if !valid_id(&id) {
        return Err(format!("pack id {id} is not a stable identifier"));
    }
    let version = required_string(object, "version")?;
    path_component(&version, "version")?;
    let sha256 = required_string(object, "sha256")?;
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("pack {id} checksum is not SHA-256"));
    }
    Ok(PackEntry {
        id,
        engine,
        name: required_string(object, "name")?,
        version,
        upstream_revision: required_string(object, "upstream_revision")?,
        upstream_url: required_string(object, "upstream_url")?,
        download_url: required_string(object, "download_url")?,
        sha256: sha256.to_ascii_lowercase(),
        size: required_u64(object, "size")?,
        app: required_string(object, "app")?,
        engine_requirement: required_string(object, "engine_requirement")?,
        rules: required_u64(object, "rules")?,
        helpers: required_u64(object, "helpers")?,
        license: required_string(object, "license")?,
        evidence: string_list(object, "evidence")?,
        limits: string_list(object, "limits")?,
    })
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, String> {
    match object.get(key) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::Null) => Err(format!("{key} is null")),
        Some(_) => Err(format!("{key} must be a string")),
        None => Err(format!("missing {key}")),
    }
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, String> {
    match object.get(key) {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| format!("{key} must be a non-negative integer")),
        Some(Value::Null) => Err(format!("{key} is null")),
        Some(_) => Err(format!("{key} must be an integer")),
        None => Err(format!("missing {key}")),
    }
}

/// Missing and JSON null both mean an empty list. Any other type is an error.
fn string_list(object: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{key} entries must be strings"))
            })
            .collect(),
        Some(_) => Err(format!("{key} must be an array or null")),
    }
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

fn registry_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

pub fn load_registry(data_dir: &Path) -> Result<Registry, String> {
    let path = rules_root(data_dir).join("registry.json");
    if !path.is_file() {
        return Ok(Registry {
            schema: 1,
            ..Registry::default()
        });
    }
    let data = fs::read(&path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&data).map_err(|error| format!("rules registry: {error}"))
}

fn save_registry(data_dir: &Path, registry: &Registry) -> Result<(), String> {
    let root = rules_root(data_dir);
    crate::storage::private_dir(&root).map_err(|error| error.to_string())?;
    crate::storage::atomic_json(&root.join("registry.json"), registry)
}

pub fn load_catalog(data_dir: &Path) -> Result<Option<Catalog>, String> {
    let path = rules_root(data_dir).join("catalog.json");
    if !path.is_file() {
        return Ok(None);
    }
    let data = fs::read(&path).map_err(|error| error.to_string())?;
    let value: Value = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    validate_catalog(&value).map(Some)
}

pub fn store_catalog(data_dir: &Path, catalog: &Catalog) -> Result<(), String> {
    let root = rules_root(data_dir);
    crate::storage::private_dir(&root).map_err(|error| error.to_string())?;
    crate::storage::atomic_json(&root.join("catalog.json"), catalog)
}

pub fn profile_label(data_dir: &Path) -> String {
    let Ok(registry) = load_registry(data_dir) else {
        return "Rules registry is unreadable".into();
    };
    let mut parts = Vec::new();
    for pack in registry.packs.iter().filter(|pack| pack.enabled) {
        parts.push(format!("{} {}", pack.name, pack.version));
    }
    for group in registry
        .groups
        .iter()
        .filter(|group| group.enabled && !group.deleted)
    {
        parts.push(format!("{} r{}", group.name, group.revision));
    }
    if parts.is_empty() {
        "No rules enabled".into()
    } else {
        parts.join(" · ")
    }
}

/// Verify `bytes` against the catalog entry and install that version.
/// A failed install leaves any previous version selected.
pub fn install_archive(data_dir: &Path, entry: &PackEntry, bytes: &[u8]) -> Result<(), String> {
    let _lock = registry_lock();
    if bytes.len() as u64 != entry.size {
        return Err(format!(
            "download size {} does not match catalog size {}",
            bytes.len(),
            entry.size
        ));
    }
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err("download exceeds the archive byte limit".into());
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != entry.sha256 {
        return Err("download checksum does not match the catalog".into());
    }
    path_component(&entry.engine, "engine")?;
    path_component(&entry.id, "id")?;
    path_component(&entry.version, "version")?;
    let root = rules_root(data_dir);
    let version_dir = root
        .join("packs")
        .join(&entry.engine)
        .join(&entry.id)
        .join(&entry.version);
    if !version_dir.starts_with(&root) {
        return Err("pack destination escapes the rules directory".into());
    }
    if version_dir.join("manifest.json").is_file() {
        return reuse_version(data_dir, &version_dir, entry);
    }
    let staging = rules_root(data_dir)
        .join("staging")
        .join(crate::storage::unique_id());
    let unpacked = staging.join("tree");
    let result = (|| {
        crate::storage::private_dir(&unpacked).map_err(|error| error.to_string())?;
        unpack_archive(bytes, &unpacked)?;
        index_tree(&unpacked, &entry.engine)?;
        if entry.engine == "yara" {
            compile_yara_tree(&unpacked)?;
        }
        let manifest = serde_json::json!({
            "pack": entry,
            "installed_archive_sha256": entry.sha256,
        });
        crate::storage::atomic_json(&unpacked.join("manifest.json"), &manifest)?;
        if let Some(parent) = version_dir.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        fs::rename(&unpacked, &version_dir).map_err(|error| error.to_string())?;
        switch_version(data_dir, entry)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
        if version_dir.is_dir() && !version_dir.join("manifest.json").is_file() {
            let _ = fs::remove_dir_all(&version_dir);
        }
    } else {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn reuse_version(data_dir: &Path, version_dir: &Path, entry: &PackEntry) -> Result<(), String> {
    let data = fs::read(version_dir.join("manifest.json")).map_err(|error| error.to_string())?;
    let value: Value = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    let stored = value
        .get("installed_archive_sha256")
        .and_then(Value::as_str)
        .unwrap_or("");
    if stored != entry.sha256 {
        return Err(format!(
            "version {} is immutable and already contains checksum {stored}",
            entry.version
        ));
    }
    let stored_entry = value
        .get("pack")
        .cloned()
        .ok_or("retained manifest has no pack provenance")?;
    let stored_entry: PackEntry =
        serde_json::from_value(stored_entry).map_err(|error| error.to_string())?;
    switch_version(data_dir, &stored_entry)
}

fn switch_version(data_dir: &Path, entry: &PackEntry) -> Result<(), String> {
    let mut registry = load_registry(data_dir)?;
    if let Some(installed) = registry.packs.iter_mut().find(|pack| pack.id == entry.id) {
        if installed.engine != entry.engine {
            return Err(format!(
                "pack {} is already installed for {}",
                entry.id, installed.engine
            ));
        }
        if !installed
            .versions
            .iter()
            .any(|version| version == &entry.version)
        {
            installed.versions.push(entry.version.clone());
        }
        installed.version = entry.version.clone();
        installed.sha256 = entry.sha256.clone();
        installed.upstream_revision = entry.upstream_revision.clone();
        installed.name = entry.name.clone();
        installed.license = entry.license.clone();
        installed.evidence = entry.evidence.clone();
        installed.limits = entry.limits.clone();
        installed.upstream_url = entry.upstream_url.clone();
    } else {
        registry.packs.push(InstalledPack {
            id: entry.id.clone(),
            engine: entry.engine.clone(),
            name: entry.name.clone(),
            version: entry.version.clone(),
            enabled: true,
            sha256: entry.sha256.clone(),
            upstream_revision: entry.upstream_revision.clone(),
            upstream_url: entry.upstream_url.clone(),
            license: entry.license.clone(),
            evidence: entry.evidence.clone(),
            limits: entry.limits.clone(),
            versions: vec![entry.version.clone()],
        });
    }
    save_registry(data_dir, &registry)
}

pub fn rollback(data_dir: &Path, id: &str, version: &str) -> Result<(), String> {
    let _lock = registry_lock();
    path_component(version, "version")?;
    let registry = load_registry(data_dir)?;
    let engine = registry
        .packs
        .iter()
        .find(|pack| pack.id == id)
        .map(|pack| pack.engine.clone())
        .ok_or_else(|| format!("pack {id} is not installed"))?;
    let known = registry
        .packs
        .iter()
        .find(|pack| pack.id == id)
        .is_some_and(|pack| pack.versions.iter().any(|kept| kept == version));
    if !known {
        return Err(format!("version {version} is not retained"));
    }
    let dir = rules_root(data_dir)
        .join("packs")
        .join(&engine)
        .join(id)
        .join(version);
    let data = fs::read(dir.join("manifest.json"))
        .map_err(|_| format!("retained version {version} is missing its files"))?;
    let value: Value = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    let stored: PackEntry = serde_json::from_value(
        value
            .get("pack")
            .cloned()
            .ok_or("retained manifest has no pack provenance")?,
    )
    .map_err(|error| error.to_string())?;
    if stored.version != version || stored.id != id {
        return Err("retained manifest does not match the requested version".into());
    }
    switch_version(data_dir, &stored)
}

pub fn set_pack_enabled(data_dir: &Path, id: &str, enabled: bool) -> Result<(), String> {
    let _lock = registry_lock();
    let mut registry = load_registry(data_dir)?;
    let pack = registry
        .packs
        .iter_mut()
        .find(|pack| pack.id == id)
        .ok_or_else(|| format!("pack {id} is not installed"))?;
    pack.enabled = enabled;
    save_registry(data_dir, &registry)
}

pub fn set_group_enabled(data_dir: &Path, id: &str, enabled: bool) -> Result<(), String> {
    let _lock = registry_lock();
    let mut registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter_mut()
        .find(|group| group.id == id && !group.deleted)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    group.enabled = enabled;
    save_registry(data_dir, &registry)
}

pub fn set_rule_enabled(
    data_dir: &Path,
    key: &str,
    rule_id: &str,
    enabled: bool,
) -> Result<(), String> {
    let _lock = registry_lock();
    let mut registry = load_registry(data_dir)?;
    let slot = registry.disabled.entry(key.to_owned()).or_default();
    if enabled {
        slot.remove(rule_id);
    } else {
        slot.insert(rule_id.to_owned());
    }
    if slot.is_empty() {
        registry.disabled.remove(key);
    }
    save_registry(data_dir, &registry)
}

pub fn rename_group(data_dir: &Path, id: &str, name: &str) -> Result<(), String> {
    let _lock = registry_lock();
    let name = name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err("group name must be 1–80 characters".into());
    }
    let mut registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter_mut()
        .find(|group| group.id == id && !group.deleted)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    group.name = name.to_owned();
    save_registry(data_dir, &registry)
}

/// Copy a file or directory into a new managed revision.
/// The original path is not watched after this returns.
pub fn import_group(
    data_dir: &Path,
    name: &str,
    engine: &str,
    source: &Path,
) -> Result<String, String> {
    let _lock = registry_lock();
    if !ENGINES.contains(&engine) {
        return Err(format!("unknown rules engine {engine}"));
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err("group name must be 1–80 characters".into());
    }
    let mut registry = load_registry(data_dir)?;
    let id = slug(name);
    let revision = registry
        .groups
        .iter()
        .filter(|group| group.id == id)
        .map(|group| group.revision)
        .max()
        .unwrap_or(0)
        + 1;
    let dest = rules_root(data_dir)
        .join("custom")
        .join(&id)
        .join(revision.to_string());
    if dest.exists() {
        return Err("group revision already exists".into());
    }
    let staging = rules_root(data_dir)
        .join("staging")
        .join(crate::storage::unique_id());
    let result = (|| {
        crate::storage::private_dir(&staging).map_err(|error| error.to_string())?;
        copy_import(source, &staging)?;
        index_tree(&staging, engine)?;
        if let Some(parent) = dest.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        fs::rename(&staging, &dest).map_err(|error| error.to_string())?;
        if let Some(group) = registry.groups.iter_mut().find(|group| group.id == id) {
            group.revision = revision;
            group.engine = engine.to_owned();
            group.name = name.to_owned();
            group.deleted = false;
        } else {
            registry.groups.push(CustomGroup {
                id: id.clone(),
                name: name.to_owned(),
                engine: engine.to_owned(),
                revision,
                enabled: true,
                tags: Vec::new(),
                deleted: false,
            });
        }
        save_registry(data_dir, &registry)?;
        Ok(id)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

pub fn delete_group(data_dir: &Path, id: &str, remove_files: bool) -> Result<(), String> {
    let _lock = registry_lock();
    let mut registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter_mut()
        .find(|group| group.id == id)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    group.enabled = false;
    group.deleted = true;
    save_registry(data_dir, &registry)?;
    if remove_files {
        let dir = rules_root(data_dir).join("custom").join(id);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub fn set_group_tags(data_dir: &Path, id: &str, tags: Vec<String>) -> Result<(), String> {
    let _lock = registry_lock();
    let mut registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter_mut()
        .find(|group| group.id == id && !group.deleted)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    group.tags = tags;
    save_registry(data_dir, &registry)
}

pub fn selection_digest(data_dir: &Path, engine: &str) -> String {
    let Ok(registry) = load_registry(data_dir) else {
        return "unreadable".into();
    };
    digest_of(&registry, engine)
}

pub fn snapshot(data_dir: &Path, engine: &str) -> Result<Snapshot, String> {
    let _lock = registry_lock();
    let registry = load_registry(data_dir)?;
    let digest = digest_of(&registry, engine);
    let directory = rules_root(data_dir)
        .join("profiles")
        .join(engine)
        .join(&digest);
    if directory.join(".complete").is_file() {
        let note = fs::read_to_string(directory.join("warnings.txt")).unwrap_or_default();
        let counts = fs::read_to_string(directory.join("counts.txt")).unwrap_or_default();
        let mut parts = counts.split_whitespace();
        let enabled_rules = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let excluded_rules = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        return Ok(Snapshot {
            directory: (enabled_rules > 0).then_some(directory),
            digest,
            warnings: note
                .lines()
                .map(str::to_owned)
                .filter(|l| !l.is_empty())
                .collect(),
            enabled_rules,
            excluded_rules,
        });
    }
    let staging = rules_root(data_dir)
        .join("staging")
        .join(crate::storage::unique_id());
    let built = (|| {
        crate::storage::private_dir(&staging).map_err(|error| error.to_string())?;
        let mut counts = SelectionCount {
            seen: BTreeSet::new(),
            warnings: Vec::new(),
            enabled: 0,
            excluded: 0,
        };
        for pack in registry
            .packs
            .iter()
            .filter(|pack| pack.enabled && pack.engine == engine)
        {
            let root = rules_root(data_dir)
                .join("packs")
                .join(&pack.engine)
                .join(&pack.id)
                .join(&pack.version);
            let disabled = registry
                .disabled
                .get(&format!("pack:{}", pack.id))
                .cloned()
                .unwrap_or_default();
            copy_selected(
                engine,
                &root,
                &staging.join("pack").join(&pack.id),
                &disabled,
                &mut counts,
            )?;
        }
        for group in registry
            .groups
            .iter()
            .filter(|group| group.enabled && !group.deleted && group.engine == engine)
        {
            let root = rules_root(data_dir)
                .join("custom")
                .join(&group.id)
                .join(group.revision.to_string());
            let disabled = registry
                .disabled
                .get(&format!("group:{}", group.id))
                .cloned()
                .unwrap_or_default();
            copy_selected(
                engine,
                &root,
                &staging.join("group").join(&group.id),
                &disabled,
                &mut counts,
            )?;
        }
        fs::write(
            staging.join("counts.txt"),
            format!("{} {}\n", counts.enabled, counts.excluded),
        )
        .map_err(|error| error.to_string())?;
        fs::write(staging.join("warnings.txt"), counts.warnings.join("\n"))
            .map_err(|error| error.to_string())?;
        let manifest = serde_json::json!({
            "schema": 1,
            "engine": engine,
            "engine_identity": engine_identity(engine),
            "digest": digest,
            "enabled_rules": counts.enabled,
            "excluded_rules": counts.excluded,
            "warnings": counts.warnings,
            "packs": registry.packs.iter().filter(|pack| pack.engine == engine).collect::<Vec<_>>(),
            "groups": registry.groups.iter().filter(|group| group.engine == engine).collect::<Vec<_>>(),
            "disabled": registry.disabled,
        });
        crate::storage::atomic_json(&staging.join("manifest.json"), &manifest)?;
        fs::write(staging.join(".complete"), b"ok").map_err(|error| error.to_string())?;
        if let Some(parent) = directory.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        if directory.exists() {
            let _ = fs::remove_dir_all(&directory);
        }
        fs::rename(&staging, &directory).map_err(|error| error.to_string())?;
        Ok(Snapshot {
            directory: (counts.enabled > 0).then_some(directory),
            digest,
            warnings: counts.warnings,
            enabled_rules: counts.enabled,
            excluded_rules: counts.excluded,
        })
    })();
    if built.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    built
}

/// Copy the enabled YARA snapshot into `dest` for the static-analysis sandbox.
pub fn publish_static(data_dir: &Path, dest: &Path) -> Result<(), String> {
    let snap = snapshot(data_dir, "yara")?;
    if dest.exists() {
        fs::remove_dir_all(dest).map_err(|error| error.to_string())?;
    }
    let Some(source) = snap.directory else {
        return Ok(());
    };
    copy_tree_regular(&source, dest)
}

pub fn pack_index(data_dir: &Path, engine: &str, id: &str) -> Result<Vec<IndexedRule>, String> {
    let registry = load_registry(data_dir)?;
    let pack = registry
        .packs
        .iter()
        .find(|pack| pack.id == id && pack.engine == engine)
        .ok_or_else(|| format!("pack {id} is not installed"))?;
    read_index(
        &rules_root(data_dir)
            .join("packs")
            .join(engine)
            .join(id)
            .join(&pack.version),
    )
}

pub fn group_index(data_dir: &Path, id: &str) -> Result<Vec<IndexedRule>, String> {
    let registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter()
        .find(|group| group.id == id)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    read_index(
        &rules_root(data_dir)
            .join("custom")
            .join(id)
            .join(group.revision.to_string()),
    )
}

fn rule_fingerprint(rule: &IndexedRule) -> String {
    if rule.content_sha256.is_empty() {
        rule.condition.clone()
    } else {
        rule.content_sha256.clone()
    }
}

pub fn diff_pack(data_dir: &Path, id: &str, older: &str) -> Result<PackDiff, String> {
    let registry = load_registry(data_dir)?;
    let pack = registry
        .packs
        .iter()
        .find(|pack| pack.id == id)
        .ok_or_else(|| format!("pack {id} is not installed"))?;
    let current = read_index(
        &rules_root(data_dir)
            .join("packs")
            .join(&pack.engine)
            .join(id)
            .join(&pack.version),
    )?;
    let previous = read_index(
        &rules_root(data_dir)
            .join("packs")
            .join(&pack.engine)
            .join(id)
            .join(older),
    )?;
    let old_ids: BTreeMap<_, _> = previous
        .iter()
        .map(|rule| (rule.id.clone(), rule_fingerprint(rule)))
        .collect();
    let new_ids: BTreeSet<_> = current.iter().map(|rule| rule.id.clone()).collect();
    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    for rule in &current {
        match old_ids.get(&rule.id) {
            None => added.push(rule.id.clone()),
            Some(before) if before != &rule_fingerprint(rule) => changed.push(rule.id.clone()),
            Some(_) => {}
        }
    }
    for id in old_ids.keys() {
        if !new_ids.contains(id) {
            removed.push(id.clone());
        }
    }
    let mut conflicts = Vec::new();
    let mut seen = BTreeSet::new();
    for rule in &current {
        if !seen.insert(rule.id.clone()) {
            conflicts.push(rule.id.clone());
        }
    }
    Ok(PackDiff {
        added,
        removed,
        changed,
        conflicts,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub conflicts: Vec<String>,
}

fn digest_of(registry: &Registry, engine: &str) -> String {
    let mut material = String::new();
    for pack in &registry.packs {
        if pack.engine == engine {
            let disabled = registry
                .disabled
                .get(&format!("pack:{}", pack.id))
                .map(|ids| ids.iter().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            material.push_str(&format!(
                "pack {} {} {} {} {}\n",
                pack.id, pack.version, pack.enabled, pack.sha256, disabled
            ));
        }
    }
    for group in &registry.groups {
        if group.engine == engine {
            let disabled = registry
                .disabled
                .get(&format!("group:{}", group.id))
                .map(|ids| ids.iter().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            material.push_str(&format!(
                "group {} {} {} {} {}\n",
                group.id,
                group.revision,
                group.enabled && !group.deleted,
                group.engine,
                disabled
            ));
        }
    }
    material.push_str(&engine_identity(engine));
    material.push('\n');
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

fn read_index(root: &Path) -> Result<Vec<IndexedRule>, String> {
    let data = fs::read(root.join("index.json")).map_err(|error| error.to_string())?;
    let index: IndexFile = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    Ok(index.rules)
}

struct SelectionCount {
    seen: BTreeSet<String>,
    warnings: Vec<String>,
    enabled: u64,
    excluded: u64,
}

fn copy_selected(
    engine: &str,
    root: &Path,
    dest: &Path,
    disabled: &BTreeSet<String>,
    counts: &mut SelectionCount,
) -> Result<(), String> {
    if !root.is_dir() {
        counts
            .warnings
            .push(format!("{} is missing; it was not scanned", root.display()));
        return Ok(());
    }
    copy_support(root, dest)?;
    let rules = read_index(root)?;
    let mut by_file: BTreeMap<String, Vec<&IndexedRule>> = BTreeMap::new();
    for rule in &rules {
        by_file.entry(rule.file.clone()).or_default().push(rule);
    }
    for (file, group) in by_file {
        let source_path = root.join(&file);
        let text = fs::read_to_string(&source_path).unwrap_or_default();
        if text.trim().is_empty() {
            counts.excluded += group.len() as u64;
            counts.warnings.push(format!(
                "{file}: source is empty; indexed rules were not emitted"
            ));
            continue;
        }
        if engine == "yara" && !includes_are_safe(&text) {
            counts.excluded += group.len() as u64;
            counts.warnings.push(format!(
                "{file}: an include path escapes the pack root or is not a relative file"
            ));
            continue;
        }
        let mut kept = Vec::new();
        for rule in group {
            if !rule.compatible {
                counts.excluded += 1;
                counts
                    .warnings
                    .push(format!("{}: {}", rule.id, rule.reason));
                continue;
            }
            if disabled.contains(&rule.id) {
                counts.excluded += 1;
                if rule.helper {
                    counts
                        .warnings
                        .push(format!("{file}: helper {} is disabled", rule.id));
                }
                continue;
            }
            let blocked: Vec<_> = rule
                .depends_on
                .iter()
                .filter(|dependency| disabled.contains(*dependency))
                .cloned()
                .collect();
            if !blocked.is_empty() {
                counts.excluded += 1;
                counts.warnings.push(format!(
                    "{}: depends on disabled rule {}",
                    rule.id,
                    blocked.join(", ")
                ));
                continue;
            }
            if !counts.seen.insert(rule.id.clone()) {
                counts.excluded += 1;
                counts.warnings.push(format!(
                    "{}: duplicate rule id; the later copy was not evaluated",
                    rule.id
                ));
                continue;
            }
            kept.push(rule);
        }
        if kept.is_empty() {
            continue;
        }
        let in_file = rules.iter().filter(|rule| rule.file == file).count();
        let body = if kept.len() == in_file {
            text.clone()
        } else {
            filter_rules(
                engine,
                &text,
                &kept.iter().map(|rule| rule.id.as_str()).collect::<Vec<_>>(),
            )
        };
        let emitted = emitted_ids(engine, &body);
        let mut wrote = false;
        for rule in &kept {
            if emitted.contains(&rule.id) {
                counts.enabled += 1;
                wrote = true;
            } else {
                counts.excluded += 1;
                counts.warnings.push(format!(
                    "{}: selected but absent from the emitted {file}",
                    rule.id
                ));
            }
        }
        if !wrote {
            continue;
        }
        let target = dest.join(&file);
        if let Some(parent) = target.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        fs::write(&target, body).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn emitted_ids(engine: &str, text: &str) -> BTreeSet<String> {
    match engine {
        "yara" => yara_blocks(text)
            .into_iter()
            .map(|(name, _, _)| name)
            .collect(),
        "sigma" => text
            .split("\n---\n")
            .filter_map(|doc| meta_line(doc, "id"))
            .collect(),
        _ => ids_blocks(text).into_iter().map(|(sid, _)| sid).collect(),
    }
}

fn engine_identity(engine: &str) -> String {
    match engine {
        "yara" => format!("yara-x {}", yara_x::VERSION),
        "ids" => suricata_identity(),
        "sigma" => "pysigma-sqlite".into(),
        other => other.to_owned(),
    }
}

fn suricata_identity() -> String {
    static CACHED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CACHED
        .get_or_init(|| {
            for path in [
                "/usr/bin/suricata",
                "/usr/sbin/suricata",
                "/usr/local/bin/suricata",
            ] {
                if !Path::new(path).is_file() {
                    continue;
                }
                if let Ok(output) = std::process::Command::new(path).arg("-V").output() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let line = text.lines().next().unwrap_or("").trim();
                    if !line.is_empty() {
                        return line.to_owned();
                    }
                }
            }
            "suricata-absent".into()
        })
        .clone()
}

fn copy_support(root: &Path, dest: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => return Err(error.to_string()),
        };
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if meta.file_type().is_symlink() {
                return Err(format!("{} is a symlink", path.display()));
            }
            if meta.is_dir() {
                pending.push(path);
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let support = matches!(
                name.as_ref(),
                "classification.config"
                    | "reference.config"
                    | "LICENSE"
                    | "NOTICE"
                    | "BSD-License.txt"
            ) || name.ends_with(".txt");
            if !support {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map_err(|_| format!("{} escapes the pack root", path.display()))?;
            let target = dest.join(rel);
            if let Some(parent) = target.parent() {
                crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
            }
            fs::copy(&path, &target).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn filter_rules(engine: &str, text: &str, ids: &[&str]) -> String {
    let mut out = String::new();
    match engine {
        "yara" => {
            for line in text.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("import ") || trimmed.starts_with("include ") {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            for (name, body, _) in yara_blocks(text) {
                if ids.contains(&name.as_str()) {
                    out.push_str(&body);
                    out.push('\n');
                }
            }
        }
        "sigma" => {
            for doc in text.split("\n---\n") {
                let id = meta_line(doc, "id").unwrap_or_default();
                if ids.contains(&id.as_str()) {
                    if !out.is_empty() {
                        out.push_str("\n---\n");
                    }
                    out.push_str(doc);
                }
            }
        }
        _ => {
            for (sid, body) in ids_blocks(text) {
                if ids.contains(&sid.as_str()) {
                    out.push_str(&body);
                    out.push('\n');
                }
            }
        }
    }
    out
}

fn includes_are_safe(text: &str) -> bool {
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("include ") else {
            continue;
        };
        let path = rest.trim().trim_matches(|c| c == '"' || c == '\'');
        let path = Path::new(path);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return false;
        }
    }
    true
}

fn unpack_archive(bytes: &[u8], dest: &Path) -> Result<(), String> {
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err("archive exceeds the compressed byte limit".into());
    }
    let free = scratch_free(dest)?;
    if free < 1024 * 1024 {
        return Err(format!(
            "not enough scratch space ({free} bytes free); the previous selection was kept"
        ));
    }
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(false);
    let mut members = 0usize;
    let mut expanded = 0u64;
    for entry in archive.entries().map_err(|error| error.to_string())? {
        members += 1;
        if members > MAX_MEMBERS {
            return Err("archive has too many members".into());
        }
        let mut entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.header().entry_type();
        let raw = entry
            .path()
            .map_err(|error| error.to_string())?
            .into_owned();
        let rel = safe_relative(&raw)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        if !matches!(kind, tar::EntryType::Regular | tar::EntryType::Directory) {
            return Err(format!(
                "archive entry {} is not a regular file",
                rel.display()
            ));
        }
        let declared = entry.header().size().map_err(|error| error.to_string())?;
        if declared > MAX_FILE_BYTES {
            return Err(format!("{} exceeds the per-file byte limit", rel.display()));
        }
        expanded = expanded.saturating_add(declared);
        if expanded > MAX_EXPANDED_BYTES {
            return Err("archive exceeds the expanded byte limit".into());
        }
        let target = dest.join(&rel);
        reject_symlink_destination(dest, &target)?;
        if kind == tar::EntryType::Directory {
            crate::storage::private_dir(&target).map_err(|error| error.to_string())?;
            continue;
        }
        if let Some(parent) = target.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        let mut file = fs::File::create(&target)
            .map_err(|error| format!("write {}: {error}", rel.display()))?;
        std::io::copy(&mut entry, &mut file)
            .map_err(|error| format!("write {}: {error}", rel.display()))?;
        file.sync_all()
            .map_err(|error| format!("fsync {}: {error}", rel.display()))?;
    }
    Ok(())
}

fn scratch_free(path: &Path) -> Result<u64, String> {
    let stat = rustix::fs::statvfs(path).map_err(|error| error.to_string())?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

fn reject_symlink_destination(root: &Path, target: &Path) -> Result<(), String> {
    let mut cursor = target.to_path_buf();
    loop {
        if cursor
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            return Err(format!("{} is a symlink", cursor.display()));
        }
        if cursor == root {
            break;
        }
        if !cursor.pop() {
            break;
        }
    }
    Ok(())
}

fn safe_relative(path: &Path) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "archive path {} escapes the pack root",
                    path.display()
                ));
            }
        }
    }
    Ok(out)
}

fn copy_import(source: &Path, dest: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
    if meta.file_type().is_symlink() {
        return Err("import root is a link".into());
    }
    if meta.is_file() {
        let name = source.file_name().ok_or("import file has no name")?;
        fs::copy(source, dest.join(name)).map_err(|error| error.to_string())?;
        return Ok(());
    }
    if !meta.is_dir() {
        return Err("import source is not a file or directory".into());
    }
    let root = source.canonicalize().map_err(|error| error.to_string())?;
    copy_checked(&root, &root, dest, 0)
}

fn copy_checked(root: &Path, dir: &Path, dest: &Path, depth: u32) -> Result<(), String> {
    if depth > 16 {
        return Err("import directory is too deep".into());
    }
    crate::storage::private_dir(dest).map_err(|error| error.to_string())?;
    let mut count = 0;
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        count += 1;
        if count > 8192 {
            return Err("import directory has too many entries".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} is a link", path.display()));
        }
        let canon = path.canonicalize().map_err(|error| error.to_string())?;
        if !canon.starts_with(root) {
            return Err(format!("{} escapes the import root", path.display()));
        }
        let name = entry.file_name();
        if meta.is_dir() {
            copy_checked(root, &path, &dest.join(name), depth + 1)?;
        } else if meta.is_file() {
            fs::copy(&path, dest.join(name)).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn copy_tree_regular(source: &Path, dest: &Path) -> Result<(), String> {
    crate::storage::private_dir(dest).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("snapshot contains a link".into());
        }
        let target = dest.join(entry.file_name());
        if meta.is_dir() {
            copy_tree_regular(&entry.path(), &target)?;
        } else if meta.is_file() {
            fs::copy(entry.path(), target).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn index_tree(root: &Path, engine: &str) -> Result<(), String> {
    let mut files = Vec::new();
    collect_files(root, &mut files, 0)?;
    let mut rules = Vec::new();
    let mut seen = BTreeSet::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "index.json" || rel == "manifest.json" {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        if !includes_are_safe(&text) {
            rules.push(IndexedRule {
                id: rel.clone(),
                name: rel.clone(),
                file: rel,
                helper: false,
                tags: Vec::new(),
                severity: String::new(),
                license: String::new(),
                source_url: String::new(),
                condition: String::new(),
                references: Vec::new(),
                evidence: Vec::new(),
                compatible: false,
                reason: "include path escapes the pack root".into(),
                content_sha256: String::new(),
                depends_on: Vec::new(),
            });
            continue;
        }
        let parsed = match engine {
            "yara" if rel.ends_with(".yar") || rel.ends_with(".yara") => parse_yara(&text),
            "ids" if rel.ends_with(".rules") => parse_ids(&text),
            "sigma" if rel.ends_with(".yml") || rel.ends_with(".yaml") => parse_sigma(&text),
            _ => Vec::new(),
        };
        if parsed.is_empty()
            && rule_file(engine, &rel)
            && text.lines().any(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
        {
            return Err(format!("{rel}: no rules were indexed"));
        }
        for mut rule in parsed {
            rule.file = rel.clone();
            if !seen.insert(rule.id.clone()) {
                rule.compatible = false;
                rule.reason = "duplicate rule id in this pack".into();
            }
            rules.push(rule);
        }
    }
    let index = IndexFile { rules };
    crate::storage::atomic_json(&root.join("index.json"), &index)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>, depth: u32) -> Result<(), String> {
    if depth > 16 {
        return Err("pack directory is too deep".into());
    }
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} is a link", path.display()));
        }
        if meta.is_dir() {
            collect_files(&path, out, depth + 1)?;
        } else if meta.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn rule_file(engine: &str, rel: &str) -> bool {
    match engine {
        "yara" => rel.ends_with(".yar") || rel.ends_with(".yara"),
        "ids" => rel.ends_with(".rules"),
        "sigma" => rel.ends_with(".yml") || rel.ends_with(".yaml"),
        _ => false,
    }
}

fn compile_yara_tree(root: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    collect_files(root, &mut files, 0)?;
    let mut compiler = yara_x::Compiler::new();
    compiler.relaxed_re_syntax(true);
    compiler.add_include_dir(root);
    let mut sources = 0u32;
    for path in files {
        if !path
            .extension()
            .is_some_and(|ext| ext == "yar" || ext == "yara")
        {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        if text.trim().is_empty() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("rules.yar")
            .to_owned();
        let code = yara_x::SourceCode::from(text.as_str()).with_origin(&name);
        compiler
            .add_source(code)
            .map_err(|error| format!("YARA-X rejected {name}: {error}"))?;
        sources += 1;
    }
    if sources == 0 {
        return Err("YARA pack produced no compilable source".into());
    }
    let _rules = compiler.build();
    Ok(())
}

fn parse_yara(text: &str) -> Vec<IndexedRule> {
    yara_blocks(text)
        .into_iter()
        .map(|(name, body, helper)| IndexedRule {
            id: name.clone(),
            name,
            file: String::new(),
            helper,
            tags: Vec::new(),
            severity: String::new(),
            license: meta_in(&body, "license"),
            source_url: meta_in(&body, "source_url"),
            condition: clip(&meta_in(&body, "description"), 180),
            references: reference_list(&body),
            evidence: vec!["sample".into(), "memory".into(), "recovered-file".into()],
            compatible: true,
            reason: String::new(),
            content_sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            depends_on: yara_dependencies(&body),
        })
        .collect()
}

fn yara_blocks(text: &str) -> Vec<(String, String, bool)> {
    let bytes = text.as_bytes();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if let Some((name, helper, brace)) = yara_header(text, i)
            && let Some(end) = yara_rule_end(bytes, brace)
        {
            blocks.push((name, text[i..end].to_owned(), helper));
            i = end;
            continue;
        }
        i += 1;
    }
    blocks
}

fn yara_header(text: &str, index: usize) -> Option<(String, bool, usize)> {
    let bytes = text.as_bytes();
    if index > 0 {
        let prev = bytes[index - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' {
            return None;
        }
    }
    let rest = &text[index..];
    let helper = rest.starts_with("private ");
    let mut rest = if helper {
        &rest["private ".len()..]
    } else {
        rest
    };
    if rest.starts_with("global ") {
        rest = &rest["global ".len()..];
    }
    let rest = rest.strip_prefix("rule ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    let name_at = text.len() - rest.len();
    let brace = text[name_at + name.len()..].find('{')? + name_at + name.len();
    Some((name, helper, brace))
}

/// End index after the rule's closing brace. Strings and comments do not
/// affect the brace depth, so an indented `}` still closes the rule.
fn yara_rule_end(bytes: &[u8], brace: usize) -> Option<usize> {
    let mut i = brace;
    let mut depth = 0i32;
    let mut seen = false;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if byte == b'"' || byte == b'\'' {
            let quote = byte;
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(bytes.len());
            continue;
        }
        if byte == b'{' {
            depth += 1;
            seen = true;
        } else if byte == b'}' {
            depth -= 1;
            if seen && depth == 0 {
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}

fn yara_dependencies(body: &str) -> Vec<String> {
    let Some(pos) = body.find("condition:") else {
        return Vec::new();
    };
    let mut condition = body[pos + "condition:".len()..].to_owned();
    if let Some(end) = condition.rfind('}') {
        condition.truncate(end);
    }
    let mut names = Vec::new();
    let mut current = String::new();
    for byte in condition.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            current.push(byte as char);
            continue;
        }
        push_dependency(&mut names, &current);
        current.clear();
    }
    push_dependency(&mut names, &current);
    names.sort();
    names.dedup();
    names
}

fn push_dependency(names: &mut Vec<String>, token: &str) {
    const KEYWORDS: &[&str] = &[
        "and",
        "or",
        "not",
        "any",
        "all",
        "them",
        "of",
        "for",
        "in",
        "at",
        "filesize",
        "entrypoint",
        "true",
        "false",
        "defined",
        "matches",
        "contains",
        "icontains",
        "startswith",
        "istartswith",
        "endswith",
        "iendswith",
        "iequals",
        "uint8",
        "uint16",
        "uint32",
        "int8",
        "int16",
        "int32",
    ];
    if token.len() > 1
        && token
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && !KEYWORDS.contains(&token)
    {
        names.push(token.to_owned());
    }
}

fn parse_ids(text: &str) -> Vec<IndexedRule> {
    ids_blocks(text)
        .into_iter()
        .map(|(sid, body)| {
            let (compatible, reason) = ids_support(&body);
            IndexedRule {
                id: sid.clone(),
                name: ids_msg(&body).unwrap_or_else(|| format!("sid {sid}")),
                file: String::new(),
                helper: false,
                tags: Vec::new(),
                severity: ids_field(&body, "classtype").unwrap_or_default(),
                license: String::new(),
                source_url: ids_field(&body, "reference").unwrap_or_default(),
                condition: clip(&body, 180),
                references: Vec::new(),
                evidence: vec!["pcap".into()],
                compatible,
                reason,
                content_sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
                depends_on: Vec::new(),
            }
        })
        .collect()
}

fn ids_blocks(text: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if current.is_empty() && !ids_action(trimmed) {
            continue;
        }
        current.push_str(line);
        current.push('\n');
        if trimmed.ends_with(')') {
            if let Some(sid) = ids_field(&current, "sid") {
                blocks.push((sid, current.clone()));
            }
            current.clear();
        }
    }
    blocks
}

fn ids_action(line: &str) -> bool {
    line.starts_with("alert ")
        || line.starts_with("drop ")
        || line.starts_with("pass ")
        || line.starts_with("reject ")
}

fn ids_support(body: &str) -> (bool, String) {
    if body.contains("dataset:") {
        return (false, "requires an external dataset".into());
    }
    if body.contains("ja3.") || body.contains("ja3s.") || body.contains("ja4.") {
        return (
            false,
            "requires a TLS fingerprint keyword that is not part of the bundled Suricata configuration".into(),
        );
    }
    (true, String::new())
}

fn ids_field(body: &str, key: &str) -> Option<String> {
    let marker = format!("{key}:");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start();
    let end = rest.find([';', ',']).unwrap_or(rest.len());
    let value = rest[..end].trim().trim_matches('"').to_owned();
    (!value.is_empty()).then_some(value)
}

fn ids_msg(body: &str) -> Option<String> {
    let start = body.find("msg:\"")? + 5;
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

fn parse_sigma(text: &str) -> Vec<IndexedRule> {
    text.split("\n---\n")
        .filter(|doc| doc.contains("title:"))
        .map(|doc| {
            let id = meta_line(doc, "id").unwrap_or_else(|| "missing-id".into());
            let category = meta_line(doc, "category").unwrap_or_default();
            let product = meta_line(doc, "product").unwrap_or_default();
            let (compatible, reason) = sigma_support(&product, &category, doc);
            IndexedRule {
                id: id.clone(),
                name: meta_line(doc, "title").unwrap_or_else(|| id.clone()),
                file: String::new(),
                helper: false,
                tags: sigma_tags(doc),
                severity: meta_line(doc, "level").unwrap_or_default(),
                license: meta_line(doc, "license").unwrap_or_default(),
                source_url: String::new(),
                condition: clip(&meta_line(doc, "description").unwrap_or_default(), 180),
                references: sigma_refs(doc),
                evidence: vec![category.clone()],
                compatible,
                reason,
                content_sha256: format!("{:x}", Sha256::digest(doc.as_bytes())),
                depends_on: Vec::new(),
            }
        })
        .collect()
}

fn sigma_support(product: &str, category: &str, doc: &str) -> (bool, String) {
    if !product.is_empty() && product != "linux" {
        return (
            false,
            format!("product {product} is not a captured Linux event"),
        );
    }
    if !SIGMA_CATEGORIES.contains(&category) {
        return (
            false,
            format!("category {category} is not a captured event category"),
        );
    }
    if doc.contains("\ncorrelation:") || doc.starts_with("correlation:") {
        return (
            false,
            "correlation rules are not a single journal query".into(),
        );
    }
    let unknown = sigma_unknown_fields(doc);
    if !unknown.is_empty() {
        return (
            false,
            format!("fields outside the captured schema: {}", unknown.join(", ")),
        );
    }
    if doc.contains("CommandLine:") || doc.contains("CommandLine|") {
        return (
            true,
            "CommandLine is recorded only when the argument vector is complete; a missing value is not invented and does not satisfy negation".into(),
        );
    }
    (true, String::new())
}

fn sigma_unknown_fields(doc: &str) -> Vec<String> {
    const KNOWN: &[&str] = &[
        "Image",
        "CommandLine",
        "ProcessId",
        "ThreadId",
        "TargetFilename",
        "SourceFilename",
        "QueryName",
        "QueryType",
        "ResponseCode",
        "DestinationIp",
        "DestinationPort",
        "HttpMethod",
        "HttpHost",
        "HttpUri",
        "Syscall",
        "Operation",
        "Result",
        "TransferredSize",
        "BpfCommand",
        "Mode",
        "Setuid",
    ];
    let mut unknown = Vec::new();
    let mut detection = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("detection:") {
            detection = true;
            continue;
        }
        if detection && !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
            break;
        }
        if !detection {
            continue;
        }
        let Some((key, _)) = trimmed.split_once(':') else {
            continue;
        };
        let field = key.split('|').next().unwrap_or(key).trim();
        if field.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && !KNOWN.contains(&field)
            && !unknown.iter().any(|seen| seen == field)
        {
            unknown.push(field.to_owned());
        }
    }
    unknown
}

fn meta_line(doc: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in doc.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix(&prefix) {
            let value = value
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_owned();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn meta_in(body: &str, key: &str) -> String {
    let marker = format!("{key} =");
    body.lines()
        .find_map(|line| {
            let trimmed = line.trim().trim_end_matches(',');
            trimmed.strip_prefix(&marker).map(|value| {
                value
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_owned()
            })
        })
        .unwrap_or_default()
}

fn reference_list(body: &str) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(value) = body.lines().find_map(|line| {
        line.trim()
            .strip_prefix("reference =")
            .map(|value| value.trim().trim_matches('"').to_owned())
    }) && !value.is_empty()
    {
        refs.push(value);
    }
    refs
}

fn sigma_tags(doc: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut in_tags = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("tags:") {
            in_tags = true;
            continue;
        }
        if in_tags && trimmed.starts_with("- ") {
            tags.push(trimmed[2..].to_owned());
            if tags.len() == 12 {
                break;
            }
        } else if in_tags && !trimmed.is_empty() {
            break;
        }
    }
    tags
}

fn sigma_refs(doc: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut in_refs = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("references:") {
            in_refs = true;
            continue;
        }
        if in_refs && let Some(value) = trimmed.strip_prefix("- ") {
            refs.push(value.to_owned());
        } else if in_refs && !trimmed.is_empty() {
            break;
        }
    }
    refs
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
mod tests {
    use super::*;
    use std::io::Write;

    fn entry(sha: &str, size: u64) -> PackEntry {
        PackEntry {
            id: "sample".into(),
            engine: "yara".into(),
            name: "Sample".into(),
            version: "1".into(),
            upstream_revision: "abc".into(),
            upstream_url: "https://example.invalid/rules".into(),
            download_url: "https://example.invalid/sample.tar.gz".into(),
            sha256: sha.into(),
            size,
            app: ">=0.6.2".into(),
            engine_requirement: "YARA-X 1.21".into(),
            rules: 1,
            helpers: 0,
            license: "example".into(),
            evidence: vec!["sample".into()],
            limits: Vec::new(),
        }
    }

    fn archive(files: &[(&str, &str)]) -> Vec<u8> {
        let mut raw = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut raw);
            for (name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, *name, data.as_bytes())
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoded = Vec::new();
        {
            let mut gzip = flate2::write::GzEncoder::new(&mut encoded, flate2::Compression::fast());
            gzip.write_all(&raw).unwrap();
            gzip.finish().unwrap();
        }
        encoded
    }

    #[test]
    fn catalog_rejects_missing_malformed_and_accepts_null_lists() {
        let missing = serde_json::json!({"schema": 1, "packs": [{}]});
        assert!(validate_catalog(&missing).unwrap_err().contains("missing"));
        let bad = serde_json::json!({"schema": 1, "packs": "nope"});
        assert!(validate_catalog(&bad).is_err());
        let unknown = serde_json::json!({"schema": 2, "packs": []});
        assert!(validate_catalog(&unknown).unwrap_err().contains("schema"));
        let ok = serde_json::json!({
            "schema": 1,
            "packs": [{
                "id": "core",
                "engine": "sigma",
                "name": "Sigma",
                "version": "1",
                "upstream_revision": "c0ffee",
                "upstream_url": "https://example.invalid",
                "download_url": "https://example.invalid/a.tar.gz",
                "sha256": "ab".repeat(32),
                "size": 1,
                "app": ">=0.6.2",
                "engine_requirement": "pySigma",
                "rules": 1,
                "helpers": 0,
                "license": "see NOTICE",
                "evidence": null,
                "limits": null
            }]
        });
        let catalog = validate_catalog(&ok).unwrap();
        assert!(catalog.packs[0].limits.is_empty());
        assert!(catalog.packs[0].evidence.is_empty());
    }

    #[test]
    fn bad_checksum_and_path_escape_keep_the_previous_pack() {
        let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
        let rule = "rule Keep { condition: true }\n";
        let good = archive(&[("keep.yar", rule)]);
        let sha = format!("{:x}", Sha256::digest(&good));
        let mut listed = entry(&sha, good.len() as u64);
        install_archive(&dir, &listed, &good).unwrap();
        listed.version = "2".into();
        let broken = b"not-the-archive".to_vec();
        listed.size = broken.len() as u64;
        listed.sha256 = format!("{:x}", Sha256::digest(&broken));
        // Checksum matches the bytes but they are not a gzip archive.
        let error = install_archive(&dir, &listed, &broken).unwrap_err();
        assert!(!error.is_empty());
        let registry = load_registry(&dir).unwrap();
        assert_eq!(registry.packs[0].version, "1");
        assert!(dir.join("rules/packs/yara/sample/1/keep.yar").is_file());
        assert!(!dir.join("rules/packs/yara/sample/2").exists());

        let payload = b"owned";
        let mut header = [0u8; 512];
        header[..13].copy_from_slice(b"../escape.yar");
        {
            let mut put = |offset: usize, value: u64, width: usize| {
                let text = format!("{:0width$o} ", value, width = width - 1);
                header[offset..offset + width].copy_from_slice(&text.as_bytes()[..width]);
            };
            put(100, 0o644, 8);
            put(108, 0, 8);
            put(116, 0, 8);
            put(124, payload.len() as u64, 12);
            put(136, 0, 12);
        }
        header[156] = b'0';
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        let mut raw = header.to_vec();
        raw.extend_from_slice(payload);
        raw.resize(512 + 512, 0);
        raw.extend_from_slice(&[0u8; 1024]);
        let mut escaped = Vec::new();
        {
            let mut gzip = flate2::write::GzEncoder::new(&mut escaped, flate2::Compression::fast());
            gzip.write_all(&raw).unwrap();
            gzip.finish().unwrap();
        }
        listed.version = "3".into();
        listed.size = escaped.len() as u64;
        listed.sha256 = format!("{:x}", Sha256::digest(&escaped));
        assert!(
            install_archive(&dir, &listed, &escaped)
                .unwrap_err()
                .contains("escapes")
        );
        assert_eq!(load_registry(&dir).unwrap().packs[0].version, "1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_helper_is_not_reported_as_a_successful_compile() {
        let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
        let source = "private rule Helper { condition: true }\nrule Uses { condition: Helper }\nrule Other { condition: true }\n";
        let bytes = archive(&[("pack.yar", source)]);
        let sha = format!("{:x}", Sha256::digest(&bytes));
        let listed = entry(&sha, bytes.len() as u64);
        install_archive(&dir, &listed, &bytes).unwrap();
        set_rule_enabled(&dir, "pack:sample", "Helper", false).unwrap();
        let snap = snapshot(&dir, "yara").unwrap();
        assert_eq!(snap.enabled_rules, 1);
        let emitted =
            fs::read_to_string(snap.directory.unwrap().join("pack/sample/pack.yar")).unwrap();
        assert!(emitted.contains("rule Other"));
        assert!(!emitted.contains("rule Uses"));
        assert!(
            snap.warnings
                .iter()
                .any(|warning| warning.contains("Helper"))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_is_a_copy_and_rejects_a_link() {
        let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
        let source = dir.join("incoming");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("local.yar"), "rule Local { condition: true }\n").unwrap();
        let id = import_group(&dir, "Local group", "yara", &source).unwrap();
        fs::write(
            source.join("local.yar"),
            "rule Changed { condition: false }\n",
        )
        .unwrap();
        let stored =
            fs::read_to_string(dir.join(format!("rules/custom/{id}/1/local.yar"))).unwrap();
        assert!(stored.contains("rule Local"));
        let link = dir.join("linked");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(
            import_group(&dir, "Linked", "yara", &link)
                .unwrap_err()
                .contains("link")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_ids_rules_are_marked_and_not_both_selected() {
        let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
        let first = "alert tcp any any -> any any (msg:\"one\"; sid:10; rev:1;)\n";
        let second = "alert tcp any any -> any any (msg:\"two\"; sid:10; rev:2;)\n";
        let bytes = archive(&[("a.rules", first), ("b.rules", second)]);
        let mut listed = entry(&format!("{:x}", Sha256::digest(&bytes)), bytes.len() as u64);
        listed.engine = "ids".into();
        listed.id = "et".into();
        install_archive(&dir, &listed, &bytes).unwrap();
        let index = pack_index(&dir, "ids", "et").unwrap();
        assert!(
            index
                .iter()
                .any(|rule| !rule.compatible && rule.reason.contains("duplicate"))
        );
        let snap = snapshot(&dir, "ids").unwrap();
        assert_eq!(snap.enabled_rules, 1);
        assert!(
            snap.warnings
                .iter()
                .any(|warning| warning.contains("duplicate"))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepared_community_packs_install_and_select() {
        let Some(catalog_path) = std::env::var_os("ANTINOMIE_RULES_CATALOG") else {
            return;
        };
        let catalog_path = PathBuf::from(catalog_path);
        let value: Value = serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
        let catalog = validate_catalog(&value).unwrap();
        let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
        for entry in &catalog.packs {
            let packs_dir = catalog_path.parent().unwrap().join("packs");
            let bytes = fs::read_dir(&packs_dir)
                .unwrap()
                .find_map(|item| {
                    let path = item.ok()?.path();
                    if !path.is_file() {
                        return None;
                    }
                    let bytes = fs::read(&path).ok()?;
                    (format!("{:x}", Sha256::digest(&bytes)) == entry.sha256).then_some(bytes)
                })
                .expect("pack archive");
            install_archive(&dir, entry, &bytes).unwrap();
            let snap = snapshot(&dir, &entry.engine).unwrap();
            assert!(snap.enabled_rules > 0, "{}", entry.id);
            if entry.engine == "ids" {
                let root = snap.directory.as_ref().unwrap();
                let malware = root.join("pack/emerging-threats-open/rules/emerging-malware.rules");
                let text = fs::read_to_string(&malware).expect("malware rules were not emitted");
                assert!(
                    text.len() > 1_000_000,
                    "emerging-malware.rules was truncated to {} bytes",
                    text.len()
                );
                assert!(ids_blocks(&text).len() > 10_000);
                assert!(
                    root.join("pack/emerging-threats-open/rules/classification.config")
                        .is_file()
                        || root.join("rules/classification.config").is_file()
                        || root
                            .join("pack/emerging-threats-open/classification.config")
                            .is_file(),
                    "classification.config was not copied"
                );
            }
            if entry.engine == "sigma" {
                assert!(
                    snap.warnings
                        .iter()
                        .any(|warning| warning.contains("not a captured")),
                    "sigma exclusions were not reported"
                );
            }
        }
        let yara = snapshot(&dir, "yara").unwrap();
        assert!(yara.enabled_rules > 1_000);
        set_pack_enabled(&dir, "yara-forge-core", false).unwrap();
        let after = snapshot(&dir, "yara").unwrap();
        assert_eq!(after.enabled_rules, 0);
        assert!(after.directory.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_path_rollback_and_ids_message_keep_their_bytes() {
        let absolute = serde_json::json!({
            "schema": 1,
            "packs": [{
                "id": "core",
                "engine": "yara",
                "name": "Core",
                "version": "/tmp/outside",
                "upstream_revision": "1",
                "upstream_url": "https://example.invalid",
                "download_url": "https://example.invalid/a.tar.gz",
                "sha256": "ab".repeat(32),
                "size": 1,
                "app": ">=0.6.2",
                "engine_requirement": "YARA-X",
                "rules": 1,
                "helpers": 0,
                "license": "example"
            }]
        });
        assert!(validate_catalog(&absolute).unwrap_err().contains("version"));

        let dir = std::env::temp_dir().join(format!("ant-rules-{}", crate::storage::unique_id()));
        let first = archive(&[("keep.yar", "rule First { condition: true }\n")]);
        let second = archive(&[("keep.yar", "rule Second { condition: false }\n")]);
        let mut listed = entry(&format!("{:x}", Sha256::digest(&first)), first.len() as u64);
        install_archive(&dir, &listed, &first).unwrap();
        listed.version = "2".into();
        listed.upstream_revision = "rev-2".into();
        listed.sha256 = format!("{:x}", Sha256::digest(&second));
        listed.size = second.len() as u64;
        install_archive(&dir, &listed, &second).unwrap();
        rollback(&dir, "sample", "1").unwrap();
        let restored = &load_registry(&dir).unwrap().packs[0];
        assert_eq!(restored.version, "1");
        assert_eq!(restored.sha256, format!("{:x}", Sha256::digest(&first)));
        assert_ne!(restored.upstream_revision, "rev-2");

        let indented = dir.join("indented.yar");
        fs::write(
            &indented,
            "rule ValidIndented {\n    condition: true\n    }\n",
        )
        .unwrap();
        let id = import_group(&dir, "indented", "yara", &indented).unwrap();
        let indexed = group_index(&dir, &id).unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].id, "ValidIndented");

        let ids = dir.join("custom.rules");
        fs::write(
            &ids,
            "alert tcp any any -> any any (msg:\"this rule matches\"; sid:1; rev:1;)\nalert tcp any any -> any any (msg:\"second\"; sid:2; rev:1;)\n",
        )
        .unwrap();
        let group = import_group(&dir, "custom", "ids", &ids).unwrap();
        set_rule_enabled(&dir, &format!("group:{group}"), "2", false).unwrap();
        let snap = snapshot(&dir, "ids").unwrap();
        let body = fs::read_to_string(
            snap.directory
                .unwrap()
                .join("group")
                .join(&group)
                .join("custom.rules"),
        )
        .unwrap();
        assert!(body.contains("sid:1"));
        assert!(!body.contains("sid:2"));
        assert_eq!(snap.enabled_rules, 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
