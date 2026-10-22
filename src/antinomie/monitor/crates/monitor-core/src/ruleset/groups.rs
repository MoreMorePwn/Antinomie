// SPDX-License-Identifier: GPL-3.0-only
//! Custom rule groups imported from local files.
use super::*;

pub fn rename_group(data_dir: &Path, id: &str, name: &str) -> Result<(), String> {
    let _lock = registry_lock(data_dir);
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
    let _lock = registry_lock(data_dir);
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

/// Replace the rules of an existing group with a new managed revision.
/// The previous revision directory stays on disk.
pub fn replace_group_revision(data_dir: &Path, id: &str, source: &Path) -> Result<u64, String> {
    let _lock = registry_lock(data_dir);
    let mut registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter()
        .find(|group| group.id == id && !group.deleted)
        .ok_or_else(|| format!("group {id} is not installed"))?
        .clone();
    let revision = group.revision.saturating_add(1);
    let dest = rules_root(data_dir)
        .join("custom")
        .join(&group.id)
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
        publish_group_revision(
            data_dir,
            &mut registry,
            &group.id,
            &group.engine,
            revision,
            &staging,
            &dest,
        )
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// Add files or remove rule ids by publishing a new revision.
/// The previous revision directory is not modified.
pub fn revise_group(
    data_dir: &Path,
    id: &str,
    add: Option<&Path>,
    remove_ids: &[String],
) -> Result<u64, String> {
    let _lock = registry_lock(data_dir);
    let mut registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter()
        .find(|group| group.id == id && !group.deleted)
        .ok_or_else(|| format!("group {id} is not installed"))?
        .clone();
    let current = rules_root(data_dir)
        .join("custom")
        .join(&group.id)
        .join(group.revision.to_string());
    if !current.is_dir() {
        return Err("the current group revision is missing".into());
    }
    let revision = group.revision.saturating_add(1);
    let dest = rules_root(data_dir)
        .join("custom")
        .join(&group.id)
        .join(revision.to_string());
    if dest.exists() {
        return Err("group revision already exists".into());
    }
    let staging = rules_root(data_dir)
        .join("staging")
        .join(crate::storage::unique_id());
    let result = (|| {
        copy_tree_regular(&current, &staging)?;
        if let Some(source) = add {
            copy_import(source, &staging)?;
        }
        if !remove_ids.is_empty() {
            remove_rules(&staging, &group.engine, remove_ids)?;
        }
        publish_group_revision(
            data_dir,
            &mut registry,
            &group.id,
            &group.engine,
            revision,
            &staging,
            &dest,
        )
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn publish_group_revision(
    data_dir: &Path,
    registry: &mut Registry,
    id: &str,
    engine: &str,
    revision: u64,
    staging: &Path,
    dest: &Path,
) -> Result<u64, String> {
    let _ = fs::remove_file(staging.join("index.json"));
    index_tree(staging, engine)?;
    if engine == "yara" {
        let mut sources = Vec::new();
        collect_files(staging, &mut sources, 0)?;
        if sources.iter().any(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yar" || ext == "yara")
        }) {
            compile_yara_tree(staging)?;
        }
    }
    if let Some(parent) = dest.parent() {
        crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
    }
    fs::rename(staging, dest).map_err(|error| error.to_string())?;
    let group = registry
        .groups
        .iter_mut()
        .find(|group| group.id == id)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    group.revision = revision;
    group.deleted = false;
    save_registry(data_dir, registry)?;
    Ok(revision)
}

fn remove_rules(root: &Path, engine: &str, ids: &[String]) -> Result<(), String> {
    let drop_ids: BTreeSet<_> = ids.iter().cloned().collect();
    let rules = read_index(root).unwrap_or_default();
    let mut files: BTreeMap<String, Vec<&IndexedRule>> = BTreeMap::new();
    for rule in &rules {
        files.entry(rule.file.clone()).or_default().push(rule);
    }
    for (file, group) in files {
        let removing: Vec<_> = group
            .iter()
            .filter(|rule| drop_ids.contains(&rule.id))
            .copied()
            .collect();
        if removing.is_empty() {
            continue;
        }
        let path = root.join(&file);
        if removing.len() == group.len() {
            fs::remove_file(&path).map_err(|error| error.to_string())?;
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
        let keep: Vec<&str> = group
            .iter()
            .filter(|rule| !drop_ids.contains(&rule.id))
            .map(|rule| {
                if engine == "yara" {
                    rule.name.as_str()
                } else {
                    rule.id.as_str()
                }
            })
            .collect();
        fs::write(&path, filter_rules(engine, &text, &keep)).map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub fn delete_group(data_dir: &Path, id: &str, remove_files: bool) -> Result<(), String> {
    let _lock = registry_lock(data_dir);
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
    let _lock = registry_lock(data_dir);
    let mut registry = load_registry(data_dir)?;
    let group = registry
        .groups
        .iter_mut()
        .find(|group| group.id == id && !group.deleted)
        .ok_or_else(|| format!("group {id} is not installed"))?;
    group.tags = tags;
    save_registry(data_dir, &registry)
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
