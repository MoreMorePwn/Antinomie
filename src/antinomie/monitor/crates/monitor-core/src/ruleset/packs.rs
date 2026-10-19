// SPDX-License-Identifier: MIT
//! Installing, switching and comparing community pack versions.
use super::*;

/// Verify `bytes` against the catalog entry and install that version.
/// A failed install leaves any previous version selected.
pub fn install_archive(data_dir: &Path, entry: &PackEntry, bytes: &[u8]) -> Result<(), String> {
    let _lock = registry_lock(data_dir);
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
        switch_version(data_dir, entry, None)
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
    switch_version(
        data_dir,
        &stored_entry,
        retained_source(version_dir)?.as_ref(),
    )
}

pub(super) fn switch_version(
    data_dir: &Path,
    entry: &PackEntry,
    source: Option<&SourceProvenance>,
) -> Result<(), String> {
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
        installed.app = entry.app.clone();
        installed.engine_requirement = entry.engine_requirement.clone();
        installed.source = source.cloned();
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
            source: source.cloned(),
            app: entry.app.clone(),
            engine_requirement: entry.engine_requirement.clone(),
        });
    }
    save_registry(data_dir, &registry)
}

pub fn rollback(data_dir: &Path, id: &str, version: &str) -> Result<(), String> {
    let _lock = registry_lock(data_dir);
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
    let stored = retained_entry(data_dir, &engine, id, version)?;
    let dir = rules_root(data_dir)
        .join("packs")
        .join(&engine)
        .join(id)
        .join(version);
    switch_version(data_dir, &stored, retained_source(&dir)?.as_ref())
}

/// The catalog entry recorded with an installed version. It does not change
/// when the live catalog does.
pub(super) fn retained_entry(
    data_dir: &Path,
    engine: &str,
    id: &str,
    version: &str,
) -> Result<PackEntry, String> {
    path_component(engine, "engine")?;
    path_component(id, "id")?;
    path_component(version, "version")?;
    let dir = rules_root(data_dir)
        .join("packs")
        .join(engine)
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
    if stored.version != version || stored.id != id || stored.engine != engine {
        return Err("retained manifest does not match the requested version".into());
    }
    Ok(stored)
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

/// Remove an installed pack and every retained version of it.
///
/// Scans that already ran keep their own record of what they used; the pack's
/// toggles go with it. A pack that is not installed is an error.
pub fn remove_pack(data_dir: &Path, id: &str) -> Result<(), String> {
    let _lock = registry_lock(data_dir);
    path_component(id, "id")?;
    let mut registry = load_registry(data_dir)?;
    let at = registry
        .packs
        .iter()
        .position(|pack| pack.id == id)
        .ok_or_else(|| format!("pack {id} is not installed"))?;
    let pack = registry.packs.remove(at);
    path_component(&pack.engine, "engine")?;
    let key = format!("pack:{id}");
    registry.disabled.remove(&key);
    registry.obsolete_disabled.remove(&key);
    registry.obsolete_reasons.remove(&key);
    save_registry(data_dir, &registry)?;
    let dir = rules_root(data_dir)
        .join("packs")
        .join(&pack.engine)
        .join(id);
    if dir.is_dir() {
        fs::remove_dir_all(&dir).map_err(|error| {
            format!(
                "{id} was removed from the list but {} could not be deleted: {error}",
                dir.display()
            )
        })?;
    }
    Ok(())
}
