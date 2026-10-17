// SPDX-License-Identifier: MIT
//! Selection profiles a scan reads: digests, snapshots and their manifests.
use super::*;

/// Digest of the profile [`snapshot_from`] builds for the same inputs.
pub fn selection_digest_of(
    data_dir: &Path,
    registry: &Registry,
    engine: &str,
    facts: &ToolFacts,
) -> String {
    digest_of(data_dir, registry, engine, facts)
}

/// Build the profile for the current registry, probing the tools in `tools`.
pub fn snapshot(data_dir: &Path, engine: &str, tools: &ToolConfig) -> Result<Snapshot, String> {
    let registry = load_registry(data_dir)?;
    snapshot_from(data_dir, engine, &registry, &tool_facts(tools), None)
}

/// Build the profile for `registry`, which was captured when the scan was admitted.
/// A later registry write is not read. `facts` describe the tools the scan runs.
/// `cancel` abandons the staging directory.
pub fn snapshot_from(
    data_dir: &Path,
    engine: &str,
    registry: &Registry,
    facts: &ToolFacts,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Snapshot, String> {
    let _lock = registry_lock();
    if cancelled(cancel) {
        return Err("cancelled".into());
    }
    let digest = digest_of(data_dir, registry, engine, facts);
    let directory = rules_root(data_dir)
        .join("profiles")
        .join(engine)
        .join(&digest);
    if directory.join(".complete").is_file()
        && fs::read_to_string(directory.join("manifest.json"))
            .unwrap_or_default()
            .contains("\"enabled_ids\"")
    {
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
            enabled_ids: Vec::new(),
            excluded_ids: Vec::new(),
        };
        for pack in registry
            .packs
            .iter()
            .filter(|pack| pack.enabled && pack.engine == engine)
        {
            let (_, _, status) = requirement_of(data_dir, pack, facts);
            if status != RequirementStatus::Satisfied {
                counts.warnings.push(format!(
                    "{} {} was not evaluated: {status}",
                    pack.id, pack.version
                ));
                counts.excluded += 1;
                counts
                    .excluded_ids
                    .push(format!("pack:{}:{status}", pack.id));
                continue;
            }
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
            "engine_identity": facts.identity(engine),
            "engine_version": facts.identity(engine),
            "sigma_python": (engine == "sigma").then(|| facts.sigma_python.display().to_string()),
            "app_version": crate::api::APP_VERSION,
            "digest": digest,
            "enabled_rules": counts.enabled,
            "excluded_rules": counts.excluded,
            "enabled_ids": counts.enabled_ids,
            "excluded_ids": counts.excluded_ids,
            "exclusion_reasons": counts.warnings,
            "warnings": counts.warnings,
            "support_hashes": support_hashes(&staging)?,
            "sigma_counts": sigma_selection_counts(engine, &counts.warnings, counts.enabled),
            "packs": registry.packs.iter().filter(|pack| pack.engine == engine).map(|pack| {
                let (app, requirement, status) = requirement_of(data_dir, pack, facts);
                serde_json::json!({
                    "id": pack.id,
                    "version": pack.version,
                    "upstream_revision": pack.upstream_revision,
                    "archive_sha256": pack.sha256,
                    "source": pack.source,
                    "enabled": pack.enabled,
                    "app_requirement": app,
                    "engine_requirement": requirement,
                    "requirement_status": status.to_string(),
                })
            }).collect::<Vec<_>>(),
            "groups": registry.groups.iter().filter(|group| group.engine == engine).map(|group| serde_json::json!({
                "id": group.id,
                "revision": group.revision,
                "enabled": group.enabled && !group.deleted,
            })).collect::<Vec<_>>(),
            "disabled": registry.disabled,
        });
        crate::storage::atomic_json(&staging.join("manifest.json"), &manifest)?;
        fs::write(staging.join(".complete"), b"ok").map_err(|error| error.to_string())?;
        if cancelled(cancel) {
            return Err("cancelled".into());
        }
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

pub(super) fn cancelled(cancel: Option<&std::sync::atomic::AtomicBool>) -> bool {
    cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
}

/// Remove staging directories left by a crashed or canceled preparation.
pub fn reap_staging(data_dir: &Path, older_than: std::time::Duration) -> Result<u32, String> {
    let staging = rules_root(data_dir).join("staging");
    if !staging.is_dir() {
        return Ok(0);
    }
    let now = std::time::SystemTime::now();
    let mut removed = 0u32;
    for entry in fs::read_dir(&staging).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let meta = entry.metadata().map_err(|error| error.to_string())?;
        let old = meta
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= older_than);
        if old && meta.is_dir() {
            fs::remove_dir_all(entry.path()).map_err(|error| error.to_string())?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn publish_static(data_dir: &Path, dest: &Path) -> Result<(), String> {
    let snap = snapshot(data_dir, "yara", &ToolConfig::default())?;
    if dest.exists() {
        fs::remove_dir_all(dest).map_err(|error| error.to_string())?;
    }
    let Some(source) = snap.directory else {
        return Ok(());
    };
    copy_tree_regular(&source, dest)
}

fn support_hashes(root: &Path) -> Result<Vec<serde_json::Value>, String> {
    let mut files = Vec::new();
    collect_files(root, &mut files, 0)?;
    let mut hashes = Vec::new();
    for path in files {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !is_support_file(name) {
            continue;
        }
        let digest = crate::storage::sha256_file_hex(&path).map_err(|error| {
            format!(
                "support file {}: {error}",
                path.strip_prefix(root).unwrap_or(&path).display()
            )
        })?;
        hashes.push(serde_json::json!({
            "path": path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/"),
            "sha256": digest,
        }));
    }
    Ok(hashes)
}

fn is_support_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "license"
        || lower == "notice"
        || lower == "copying"
        || name == "classification.config"
        || name == "reference.config"
        || name.ends_with(".txt")
        || name.ends_with(".md")
}

fn sigma_selection_counts(
    engine: &str,
    warnings: &[String],
    accepted: u64,
) -> Option<serde_json::Value> {
    if engine != "sigma" {
        return None;
    }
    let category_rejected = warnings
        .iter()
        .filter(|warning| warning.contains("not a captured"))
        .count();
    let backend_rejected = warnings
        .iter()
        .filter(|warning| {
            warning.contains("outside the captured schema") || warning.contains("correlation")
        })
        .count();
    Some(serde_json::json!({
        "category_accepted": accepted,
        "category_rejected": category_rejected,
        "backend_rejected": backend_rejected,
    }))
}

fn digest_of(data_dir: &Path, registry: &Registry, engine: &str, facts: &ToolFacts) -> String {
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
    material.push_str(&format!("index-parser {INDEX_PARSER}\n"));
    for pack in registry
        .packs
        .iter()
        .filter(|pack| pack.engine == engine && pack.enabled)
    {
        let (app, requirement, status) = requirement_of(data_dir, pack, facts);
        material.push_str(&format!(
            "requirement {} {} {app} {requirement} {status}\n",
            pack.id, pack.version
        ));
    }
    material.push_str(&facts.identity(engine));
    material.push('\n');
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

struct SelectionCount {
    seen: BTreeSet<String>,
    warnings: Vec<String>,
    enabled: u64,
    excluded: u64,
    enabled_ids: Vec<String>,
    excluded_ids: Vec<String>,
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
    let blocked = dependency_closure(&rules, disabled);
    let mut by_file: BTreeMap<String, Vec<&IndexedRule>> = BTreeMap::new();
    for rule in &rules {
        by_file.entry(rule.file.clone()).or_default().push(rule);
    }
    for (file, group) in by_file {
        let source_path = root.join(&file);
        let text = fs::read_to_string(&source_path).unwrap_or_default();
        if text.trim().is_empty() {
            counts.excluded += group.len() as u64;
            counts
                .excluded_ids
                .extend(group.iter().map(|rule| rule.id.clone()));
            counts.warnings.push(format!(
                "{file}: source is empty; indexed rules were not emitted"
            ));
            continue;
        }
        if engine == "yara" && !includes_are_safe(&text) {
            counts.excluded += group.len() as u64;
            counts
                .excluded_ids
                .extend(group.iter().map(|rule| rule.id.clone()));
            counts.warnings.push(format!(
                "{file}: an include path escapes the pack root or is not a relative file"
            ));
            continue;
        }
        let mut kept = Vec::new();
        for rule in group {
            if !rule.compatible {
                counts.excluded += 1;
                counts.excluded_ids.push(rule.id.clone());
                counts
                    .warnings
                    .push(format!("{}: {}", rule.id, rule.reason));
                continue;
            }
            if disabled.contains(&rule.id) {
                counts.excluded += 1;
                counts.excluded_ids.push(rule.id.clone());
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
                .filter(|dependency| blocked.contains(*dependency))
                .cloned()
                .collect();
            if !blocked.is_empty() {
                counts.excluded += 1;
                counts.excluded_ids.push(rule.id.clone());
                counts.warnings.push(format!(
                    "{}: depends on disabled rule {}",
                    rule.id,
                    blocked.join(", ")
                ));
                continue;
            }
            if !counts.seen.insert(rule.id.clone()) {
                counts.excluded += 1;
                counts.excluded_ids.push(rule.id.clone());
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
                &kept
                    .iter()
                    .map(|rule| {
                        if engine == "yara" {
                            rule.name.as_str()
                        } else {
                            rule.id.as_str()
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let emitted = emitted_ids(engine, &body);
        let mut wrote = false;
        for rule in &kept {
            let declared = if engine == "yara" {
                rule.name.as_str()
            } else {
                rule.id.as_str()
            };
            if emitted.contains(declared) {
                counts.enabled += 1;
                counts.enabled_ids.push(rule.id.clone());
                wrote = true;
            } else {
                counts.excluded += 1;
                counts.excluded_ids.push(rule.id.clone());
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

fn dependency_closure(rules: &[IndexedRule], disabled: &BTreeSet<String>) -> BTreeSet<String> {
    let mut blocked = disabled.clone();
    loop {
        let mut grew = false;
        for rule in rules {
            if blocked.contains(&rule.id) {
                continue;
            }
            if rule
                .depends_on
                .iter()
                .any(|dependency| blocked.contains(dependency))
            {
                blocked.insert(rule.id.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    blocked
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

pub(super) fn filter_rules(engine: &str, text: &str, ids: &[&str]) -> String {
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

/// One installed pack or custom group, with the rules that are turned on inside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineSet {
    pub name: String,
    pub revision: String,
    pub enabled: bool,
    /// Compatible, non-helper rules that are not disabled and whose dependencies are enabled.
    pub rules: u64,
    /// Where the rules were fetched from, for a pack installed from a source.
    pub source: String,
}

/// Installed packs, then custom groups, for one engine. Disabled sets stay in the list.
pub fn engine_sets(data_dir: &Path, registry: &Registry, engine: &str) -> Vec<EngineSet> {
    let mut sets = Vec::new();
    for pack in registry.packs.iter().filter(|pack| pack.engine == engine) {
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
        sets.push(EngineSet {
            name: pack.name.clone(),
            revision: pack.version.clone(),
            enabled: pack.enabled,
            rules: count_enabled(&root, &disabled),
            source: pack
                .source
                .as_ref()
                .map(SourceProvenance::line)
                .unwrap_or_default(),
        });
    }
    for group in registry
        .groups
        .iter()
        .filter(|group| group.engine == engine && !group.deleted)
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
        sets.push(EngineSet {
            name: group.name.clone(),
            revision: format!("r{}", group.revision),
            enabled: group.enabled,
            rules: count_enabled(&root, &disabled),
            source: String::new(),
        });
    }
    sets
}

fn count_enabled(root: &Path, disabled: &BTreeSet<String>) -> u64 {
    let Ok(rules) = read_index(root) else {
        return 0;
    };
    let blocked = dependency_closure(&rules, disabled);
    let mut seen = BTreeSet::new();
    let mut count = 0u64;
    for rule in &rules {
        if rule.helper || !rule.compatible {
            continue;
        }
        if disabled.contains(&rule.id) || rule.depends_on.iter().any(|id| blocked.contains(id)) {
            continue;
        }
        if seen.insert(rule.id.clone()) {
            count += 1;
        }
    }
    count
}
