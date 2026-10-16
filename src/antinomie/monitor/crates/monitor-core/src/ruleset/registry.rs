// SPDX-License-Identifier: MIT
//! The registry of installed packs and groups, and rule toggles.
use super::*;

pub(super) fn registry_lock() -> std::sync::MutexGuard<'static, ()> {
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

pub(super) fn save_registry(data_dir: &Path, registry: &Registry) -> Result<(), String> {
    #[cfg(test)]
    if take_fail("registry-write") {
        return Err("No space left on device".into());
    }
    let root = rules_root(data_dir);
    crate::storage::private_dir(&root).map_err(|error| error.to_string())?;
    let mut stored = registry.clone();
    let previous = load_registry(data_dir)
        .map(|current| current.generation)
        .unwrap_or(0);
    stored.generation = previous.max(stored.generation).saturating_add(1);
    crate::storage::atomic_json(&root.join("registry.json"), &stored)
}

pub fn profile_label(data_dir: &Path) -> String {
    let Ok(registry) = load_registry(data_dir) else {
        return "Rules registry is unreadable".into();
    };
    profile_label_of(&registry)
}

pub fn profile_label_of(registry: &Registry) -> String {
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
