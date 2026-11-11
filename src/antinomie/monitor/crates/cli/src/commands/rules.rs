// SPDX-License-Identifier: GPL-3.0-only
//! `rules list/enable/disable` over the registry the core keeps in the data
//! directory (`ruleset/registry.rs`): installed packs and custom groups, and
//! whether each is enabled. Listing reads the registry; changing it takes the
//! engine lock, so it never races a window or a daemon.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, table},
};
use antinomie_monitor_core::{
    data_owner::{self, OwnerClaim, OwnerKind},
    ruleset::{Registry, load_registry, set_group_enabled, set_pack_enabled},
};
use clap::Subcommand;
use serde_json::{Value, json};

#[derive(Subcommand, Debug)]
pub enum Rules {
    /// List installed rule packs and groups and whether they are enabled.
    List {
        /// Only this engine: yara, sigma or ids (Suricata).
        #[arg(long)]
        engine: Option<String>,
    },
    /// Enable a pack or group. Use `pack:ID` or `group:ID` when an id names both.
    Enable { id: String },
    /// Disable a pack or group.
    Disable { id: String },
}

pub fn run(rules: &Rules, context: &Context) -> Result<Reply, CliError> {
    match rules {
        Rules::List { engine } => list(engine.as_deref(), context),
        Rules::Enable { id } => set(id, true, context),
        Rules::Disable { id } => set(id, false, context),
    }
}

/// The registry of `data_dir`; an absent directory has none installed.
fn registry(context: &Context) -> Result<Registry, CliError> {
    load_registry(context.data_dir()).map_err(|message| CliError::new(ErrorCode::Internal, message))
}

fn engine_matches(entry: &str, wanted: &str) -> bool {
    let wanted = wanted.to_ascii_lowercase();
    let wanted = if wanted == "suricata" { "ids" } else { &wanted };
    entry.eq_ignore_ascii_case(wanted)
}

fn entries(registry: &Registry) -> Vec<Value> {
    let disabled = |key: &str| registry.disabled.get(key).map_or(0, |rules| rules.len());
    let mut items = Vec::new();
    for pack in &registry.packs {
        let key = format!("pack:{}", pack.id);
        items.push(json!({
            "key": key, "kind": "pack", "id": pack.id, "engine": pack.engine,
            "name": pack.name, "version": pack.version, "enabled": pack.enabled,
            "disabled_rules": disabled(&key),
        }));
    }
    for group in registry.groups.iter().filter(|group| !group.deleted) {
        let key = format!("group:{}", group.id);
        items.push(json!({
            "key": key, "kind": "group", "id": group.id, "engine": group.engine,
            "name": group.name, "version": format!("r{}", group.revision),
            "enabled": group.enabled, "disabled_rules": disabled(&key),
        }));
    }
    items
}

fn list(engine: Option<&str>, context: &Context) -> Result<Reply, CliError> {
    let registry = registry(context)?;
    let items: Vec<Value> = entries(&registry)
        .into_iter()
        .filter(|item| {
            engine
                .is_none_or(|wanted| engine_matches(item["engine"].as_str().unwrap_or(""), wanted))
        })
        .collect();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            let text = |key: &str| item[key].as_str().unwrap_or("").to_owned();
            vec![
                text("key"),
                text("engine"),
                if item["enabled"] == true {
                    "enabled"
                } else {
                    "disabled"
                }
                .to_owned(),
                text("version"),
                text("name"),
            ]
        })
        .collect();
    let human = if rows.is_empty() {
        "No rule packs or groups are installed.\n".to_owned()
    } else {
        table(&["id", "engine", "state", "version", "name"], &rows)
    };
    Ok(Reply::list(items, None).with_human(human))
}

/// Which entry `id` names: `pack:ID`, `group:ID` or a bare id of exactly one.
fn resolve(registry: &Registry, id: &str) -> Result<(&'static str, String), CliError> {
    let found = |kind: &'static str, id: &str| -> bool {
        match kind {
            "pack" => registry.packs.iter().any(|pack| pack.id == id),
            _ => registry
                .groups
                .iter()
                .any(|group| group.id == id && !group.deleted),
        }
    };
    let (kind, bare) = match id.split_once(':') {
        Some(("pack", bare)) => (Some("pack"), bare),
        Some(("group", bare)) => (Some("group"), bare),
        _ => (None, id),
    };
    let kinds: Vec<&'static str> = match kind {
        Some(kind) => vec![kind],
        None => vec!["pack", "group"],
    };
    let hits: Vec<&'static str> = kinds.into_iter().filter(|kind| found(kind, bare)).collect();
    match hits.as_slice() {
        [one] => Ok((one, bare.to_owned())),
        [] => Err(CliError::not_found(format!(
            "no installed pack or group {id:?}; `rules list` shows them"
        ))
        .with_field("id")),
        _ => Err(CliError::invalid(format!(
            "{id:?} names a pack and a group; use pack:{id} or group:{id}"
        ))
        .with_field("id")),
    }
}

fn set(id: &str, enabled: bool, context: &Context) -> Result<Reply, CliError> {
    // Resolve before locking: a name that matches nothing creates nothing.
    let (kind, bare) = resolve(&registry(context)?, id)?;
    let data = context.data_dir();
    let claim = OwnerClaim {
        kind: OwnerKind::Cli,
        socket: None,
        lane: None,
    };
    let _lock = data_owner::lock_data_dir(data, &claim)
        .map_err(|message| CliError::from_engine_start(data, &message))?;
    let result = match kind {
        "pack" => set_pack_enabled(data, &bare, enabled),
        _ => set_group_enabled(data, &bare, enabled),
    };
    result.map_err(|message| CliError::new(ErrorCode::Internal, message))?;
    let key = format!("{kind}:{bare}");
    Ok(
        Reply::value(json!({"key": key, "kind": kind, "id": bare, "enabled": enabled})).with_human(
            format!(
                "{key} is now {}.\n",
                if enabled { "enabled" } else { "disabled" }
            ),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::ruleset::{CustomGroup, InstalledPack};

    fn pack(id: &str, engine: &str, enabled: bool) -> InstalledPack {
        InstalledPack {
            id: id.into(),
            engine: engine.into(),
            name: format!("Pack {id}"),
            version: "1.0".into(),
            enabled,
            sha256: String::new(),
            upstream_revision: String::new(),
            upstream_url: String::new(),
            license: String::new(),
            evidence: vec![],
            limits: vec![],
            versions: vec![],
            source: None,
            app: String::new(),
            engine_requirement: String::new(),
        }
    }

    fn group(id: &str, engine: &str, deleted: bool) -> CustomGroup {
        CustomGroup {
            id: id.into(),
            name: format!("Group {id}"),
            engine: engine.into(),
            revision: 3,
            enabled: true,
            tags: vec![],
            deleted,
        }
    }

    fn sample() -> Registry {
        let mut registry = Registry {
            schema: 1,
            packs: vec![pack("p1", "yara", true), pack("both", "sigma", false)],
            groups: vec![
                group("g1", "yara", false),
                group("both", "sigma", false),
                group("gone", "yara", true),
            ],
            ..Registry::default()
        };
        registry
            .disabled
            .insert("pack:p1".into(), ["r1".to_owned(), "r2".to_owned()].into());
        registry
    }

    #[test]
    fn entries_list_packs_and_live_groups_with_disabled_counts() {
        let items = entries(&sample());
        let keys: Vec<&str> = items.iter().map(|i| i["key"].as_str().unwrap()).collect();
        assert_eq!(keys, ["pack:p1", "pack:both", "group:g1", "group:both"]);
        assert_eq!(items[0]["disabled_rules"], 2);
        assert_eq!(items[0]["enabled"], true);
        assert_eq!(items[2]["version"], "r3");
    }

    #[test]
    fn ids_resolve_unambiguously() {
        let registry = sample();
        assert_eq!(resolve(&registry, "p1").unwrap(), ("pack", "p1".into()));
        assert_eq!(resolve(&registry, "g1").unwrap(), ("group", "g1".into()));
        assert_eq!(
            resolve(&registry, "group:both").unwrap(),
            ("group", "both".into())
        );
        assert_eq!(resolve(&registry, "both").unwrap_err().exit.code(), 4);
        assert_eq!(resolve(&registry, "gone").unwrap_err().exit.code(), 3);
        assert_eq!(resolve(&registry, "pack:g1").unwrap_err().exit.code(), 3);
    }

    #[test]
    fn engine_filter_treats_suricata_as_ids() {
        assert!(engine_matches("ids", "suricata"));
        assert!(engine_matches("yara", "YARA"));
        assert!(!engine_matches("sigma", "yara"));
    }
}
