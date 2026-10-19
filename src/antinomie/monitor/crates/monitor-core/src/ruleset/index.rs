// SPDX-License-Identifier: MIT
//! Derived rule indexes and their migration between parser versions.
use super::*;

pub(super) fn read_index(root: &Path) -> Result<Vec<IndexedRule>, String> {
    let data = fs::read(root.join("index.json")).map_err(|error| error.to_string())?;
    let index: IndexFile = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    Ok(index.rules)
}

pub(super) fn includes_are_safe(text: &str) -> bool {
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

pub(super) fn index_tree(root: &Path, engine: &str) -> Result<(), String> {
    write_index(&root.join("index.json"), &build_index(root, engine)?)
}

/// Index name a migration writes beside the current index before promoting it.
pub(super) const STAGED_INDEX: &str = "index.next.json";

fn write_index(path: &Path, index: &IndexFile) -> Result<(), String> {
    #[cfg(test)]
    if take_fail("index-write") {
        return Err("No space left on device".into());
    }
    crate::storage::atomic_json(path, index)
}

fn build_index(root: &Path, engine: &str) -> Result<IndexFile, String> {
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
        if rel == "index.json" || rel == "manifest.json" || rel == STAGED_INDEX {
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
            if engine != "yara" && !seen.insert(rule.id.clone()) {
                rule.compatible = false;
                rule.reason = "duplicate rule id in this pack".into();
            }
            rules.push(rule);
        }
    }
    if engine == "yara" {
        qualify_yara_namespaces(&mut rules);
    }
    Ok(IndexFile {
        parser: INDEX_PARSER,
        rules,
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexMigration {
    pub rebuilt: Vec<String>,
    pub current: Vec<String>,
    pub obsolete: Vec<String>,
}

/// Rebuild indexes written by an older parser from the installed files.
/// A second call does not rewrite a current index.
///
/// Every retained version is rebuilt, but disabled rules are reconciled only
/// against the selected pack version or group revision: a historical index
/// never drops a toggle for a rule that exists only in the selected one.
/// Rebuilt indexes are staged beside the current file and promoted only after
/// the registry is saved, so a failure leaves the previous index and toggles,
/// and the next call finishes the staged work instead of starting over.
pub fn migrate_indexes(data_dir: &Path) -> Result<IndexMigration, String> {
    let _lock = registry_lock(data_dir);
    let mut registry = load_registry(data_dir)?;
    let mut report = IndexMigration::default();
    let mut targets = Vec::new();
    for pack in &registry.packs {
        for version in &pack.versions {
            if path_component(version, "version").is_err() {
                continue;
            }
            targets.push(Target {
                key: format!("pack:{}", pack.id),
                engine: pack.engine.clone(),
                root: rules_root(data_dir)
                    .join("packs")
                    .join(&pack.engine)
                    .join(&pack.id)
                    .join(version),
                selected: *version == pack.version,
            });
        }
    }
    for group in &registry.groups {
        let base = rules_root(data_dir).join("custom").join(&group.id);
        let Ok(entries) = fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                targets.push(Target {
                    key: format!("group:{}", group.id),
                    engine: group.engine.clone(),
                    selected: entry.file_name() == group.revision.to_string().as_str(),
                    root: entry.path(),
                });
            }
        }
    }
    // Registries from before requirements were retained take them from each
    // selected version's own manifest, never from the live catalog.
    let mut registry_changed = false;
    for pack in registry
        .packs
        .iter_mut()
        .filter(|pack| pack.engine_requirement.is_empty())
    {
        if let Ok(entry) = retained_entry(data_dir, &pack.engine, &pack.id, &pack.version)
            && !entry.engine_requirement.is_empty()
        {
            pack.app = entry.app;
            pack.engine_requirement = entry.engine_requirement;
            registry_changed = true;
        }
    }
    let mut staged = Vec::new();
    for target in targets {
        let label = target
            .root
            .strip_prefix(rules_root(data_dir))
            .unwrap_or(&target.root)
            .display()
            .to_string();
        let next = target.root.join(STAGED_INDEX);
        let rules = if let Some(index) = read_staged(&next)? {
            index.rules
        } else {
            let index_path = target.root.join("index.json");
            if !index_path.is_file() {
                continue;
            }
            let data = fs::read(&index_path).map_err(|error| error.to_string())?;
            let parsed: IndexFile = serde_json::from_slice(&data)
                .map_err(|error| format!("{}: {error}", index_path.display()))?;
            if parsed.parser >= INDEX_PARSER {
                report.current.push(label);
                continue;
            }
            let index = build_index(&target.root, &target.engine)?;
            write_index(&next, &index)?;
            index.rules
        };
        if target.selected
            && let Some(disabled) = registry.disabled.get_mut(&target.key)
        {
            let obsolete = reconcile_disabled(disabled, &rules);
            if !obsolete.is_empty() {
                registry_changed = true;
                let reasons = registry
                    .obsolete_reasons
                    .entry(target.key.clone())
                    .or_default();
                for (id, reason) in &obsolete {
                    report
                        .obsolete
                        .push(format!("{} {id}: {reason}", target.key));
                    reasons.insert(id.clone(), format!("{label}: {reason}"));
                }
                let kept = registry
                    .obsolete_disabled
                    .entry(target.key.clone())
                    .or_default();
                for (id, _) in obsolete {
                    if !kept.contains(&id) {
                        kept.push(id);
                    }
                }
            }
        }
        staged.push((next, target.root.join("index.json"), label));
    }
    if registry_changed {
        save_registry(data_dir, &registry)?;
    }
    for (next, current, label) in staged {
        #[cfg(test)]
        if take_fail("index-promote") {
            return Err("interrupted".into());
        }
        fs::rename(&next, &current).map_err(|error| format!("{label}: {error}"))?;
        report.rebuilt.push(label);
    }
    Ok(report)
}

pub(super) struct Target {
    /// Disabled-set key: `pack:<id>` or `group:<id>`.
    key: String,
    engine: String,
    root: PathBuf,
    /// The selected pack version or group revision.
    selected: bool,
}

/// A staged index left by an interrupted migration. One from another parser
/// is discarded and rebuilt.
fn read_staged(path: &Path) -> Result<Option<IndexFile>, String> {
    if !path.is_file() {
        return Ok(None);
    }
    let parsed = fs::read(path)
        .ok()
        .and_then(|data| serde_json::from_slice::<IndexFile>(&data).ok())
        .filter(|index| index.parser == INDEX_PARSER);
    if parsed.is_none() {
        fs::remove_file(path).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(parsed)
}

/// Keep ids that name a rule in `rules` and remap a bare name that names
/// exactly one. Returns the others with the reason they were dropped; they are
/// never applied to a different rule.
fn reconcile_disabled(
    disabled: &mut BTreeSet<String>,
    rules: &[IndexedRule],
) -> Vec<(String, String)> {
    let ids: BTreeSet<_> = rules.iter().map(|rule| rule.id.as_str()).collect();
    let mut next = BTreeSet::new();
    let mut obsolete = Vec::new();
    for id in disabled.iter() {
        if ids.contains(id.as_str()) {
            next.insert(id.clone());
            continue;
        }
        let named: Vec<_> = rules
            .iter()
            .filter(|rule| rule.name == *id)
            .map(|rule| rule.id.clone())
            .collect();
        match named.len() {
            1 => {
                next.insert(named[0].clone());
            }
            0 => obsolete.push((id.clone(), "no rule has this id or name".into())),
            count => obsolete.push((
                id.clone(),
                format!("the name matches {count} rules in different namespaces"),
            )),
        }
    }
    *disabled = next;
    obsolete
}

fn qualify_yara_namespaces(rules: &mut [IndexedRule]) {
    let mut files_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for rule in rules.iter().filter(|rule| rule.compatible) {
        files_of
            .entry(rule.name.clone())
            .or_default()
            .insert(rule.file.clone());
    }
    for rule in rules.iter_mut() {
        let shared = files_of
            .get(&rule.name)
            .is_some_and(|files| files.len() > 1);
        if shared {
            rule.id = format!("{}/{}", rule.file, rule.name);
        }
        for dependency in &mut rule.depends_on {
            if files_of
                .get(dependency)
                .is_some_and(|files| files.len() > 1)
            {
                *dependency = format!("{}/{dependency}", rule.file);
            }
        }
    }
}

fn rule_file(engine: &str, rel: &str) -> bool {
    match engine {
        "yara" => rel.ends_with(".yar") || rel.ends_with(".yara"),
        "ids" => rel.ends_with(".rules"),
        "sigma" => rel.ends_with(".yml") || rel.ends_with(".yaml"),
        _ => false,
    }
}

pub(super) fn compile_yara_tree(root: &Path) -> Result<(), String> {
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
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        compiler.new_namespace(&name);
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
