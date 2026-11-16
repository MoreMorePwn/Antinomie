// SPDX-License-Identifier: GPL-3.0-only
//! `rules catalog|install|update` (ANT-T0556): the catalog's rule packs
//! without the window, through the core calls Tools > Rules uses
//! (`ruleset::refresh_catalog`, `install_source` with the pack's default
//! options, `download_archive` and `install_archive` for a hosted archive,
//! `source_update` for an update). Each install is checked, filtered and
//! indexed before the registry changes, so a failure keeps the pack as it
//! was. Running the command is the consent to download (the window asks for
//! "Allow downloads" first). No engine lock: the registry has its own.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, table},
    signals,
};
use antinomie_monitor_core::ruleset::{self, Catalog, Curl, InstalledPack};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Ctrl-C sets the flag while `work` runs.
fn cancellable<T>(work: impl FnOnce(&Arc<AtomicBool>) -> T) -> T {
    signals::install();
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (cancel, done) = (Arc::clone(&cancel), Arc::clone(&done));
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                if signals::interrupted() {
                    cancel.store(true, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let out = work(&cancel);
    done.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    out
}

fn fetch_catalog(context: &Context, cancel: &AtomicBool) -> Result<Catalog, CliError> {
    context
        .logger
        .info(&format!("checking the catalog at {}", ruleset::CATALOG_URL));
    ruleset::refresh_catalog(
        context.data_dir(),
        ruleset::CATALOG_URL,
        &Curl::new(context.options.curl.clone()),
        cancel,
    )
    .map_err(|e| CliError::new(ErrorCode::Unavailable, format!("the catalog: {e}")))
}

fn installed(context: &Context) -> Result<Vec<InstalledPack>, CliError> {
    ruleset::load_registry(context.data_dir())
        .map(|registry| registry.packs)
        .map_err(|message| CliError::new(ErrorCode::Internal, message))
}

/// Every pack of `catalog`: (id, engine, name, version, kind).
fn entries(catalog: &Catalog) -> Vec<(String, String, String, String, &'static str)> {
    let mut out: Vec<_> = catalog
        .sources
        .iter()
        .map(|pack| {
            (
                pack.id.clone(),
                pack.engine.clone(),
                pack.name.clone(),
                pack.version(&pack.default_options()),
                "source",
            )
        })
        .collect();
    out.extend(catalog.packs.iter().map(|entry| {
        (
            entry.id.clone(),
            entry.engine.clone(),
            entry.name.clone(),
            entry.version.clone(),
            "archive",
        )
    }));
    out
}

/// `rules catalog`: what the catalog offers and what is installed.
pub fn catalog(context: &Context) -> Result<Reply, CliError> {
    let catalog = cancellable(|cancel| fetch_catalog(context, cancel))?;
    let packs = installed(context)?;
    let have = |id: &str| packs.iter().find(|pack| pack.id == id);
    let items: Vec<Value> = entries(&catalog)
        .into_iter()
        .map(|(id, engine, name, version, kind)| {
            json!({"id": id, "engine": engine, "name": name, "version": version,
                   "kind": kind, "installed": have(&id).map(|pack| pack.version.clone())})
        })
        .collect();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            let text = |key: &str| item[key].as_str().unwrap_or("-").to_owned();
            vec![
                text("id"),
                text("engine"),
                text("version"),
                text("installed"),
                text("name"),
            ]
        })
        .collect();
    Ok(Reply::list(items, None).with_human(table(
        &["ID", "ENGINE", "CATALOG", "INSTALLED", "NAME"],
        &rows,
    )))
}

/// What to install for `id`: the catalog's source pack with its default
/// options (or `options` for an update), else its hosted archive.
fn install_one(
    context: &Context,
    catalog: &Catalog,
    id: &str,
    options: Option<BTreeSet<String>>,
    cancel: &AtomicBool,
) -> Result<String, String> {
    let data = context.data_dir();
    let curl = Curl::new(context.options.curl.clone());
    if let Some(pack) = catalog.sources.iter().find(|pack| pack.id == id) {
        let options = options.unwrap_or_else(|| pack.default_options());
        let logger = context.logger;
        let done = ruleset::install_source(data, pack, &options, &curl, cancel, &mut |line| {
            logger.info(&format!("{id}: {line}"))
        })?;
        return Ok(if done.already_installed {
            format!(
                "{} {} was already installed; selected it again",
                pack.name, done.version
            )
        } else {
            format!(
                "{} {} installed with {} rules",
                pack.name, done.version, done.rules
            )
        });
    }
    if let Some(entry) = catalog.packs.iter().find(|entry| entry.id == id) {
        context
            .logger
            .info(&format!("{id}: downloading {}", entry.download_url));
        let bytes = ruleset::download_archive(data, entry, &curl, cancel)?;
        ruleset::install_archive(data, entry, &bytes)?;
        return Ok(format!("{} {} installed", entry.name, entry.version));
    }
    Err(format!(
        "the catalog has no pack {id:?}; `rules catalog` lists them"
    ))
}

/// The outcome of several installs: every message, or the failures.
fn outcome(done: Vec<(String, Result<String, String>)>) -> Result<Reply, CliError> {
    let failed: Vec<String> = done
        .iter()
        .filter_map(|(id, result)| result.as_ref().err().map(|e| format!("{id}: {e}")))
        .collect();
    if !failed.is_empty() {
        return Err(CliError::new(ErrorCode::Unavailable, failed.join("; ")));
    }
    let lines: Vec<String> = done
        .into_iter()
        .filter_map(|(_, result)| result.ok())
        .collect();
    let mut human = lines.join("\n");
    if human.is_empty() {
        human = "Every installed pack is at the catalog's version.".into();
    }
    human.push('\n');
    Ok(Reply::value(json!({"done": lines})).with_human(human))
}

/// `rules install ID...`.
pub fn install(ids: &[String], context: &Context) -> Result<Reply, CliError> {
    cancellable(|cancel| {
        let catalog = fetch_catalog(context, cancel)?;
        let known: Vec<String> = entries(&catalog).into_iter().map(|e| e.0).collect();
        if let Some(unknown) = ids.iter().find(|id| !known.contains(id)) {
            return Err(CliError::not_found(format!(
                "the catalog has no pack {unknown:?}; it has {}",
                known.join(", ")
            ))
            .with_field("id"));
        }
        let mut done = Vec::new();
        for id in ids {
            if cancel.load(Ordering::Relaxed) {
                done.push((id.clone(), Err("cancelled".to_owned())));
                continue;
            }
            done.push((id.clone(), install_one(context, &catalog, id, None, cancel)));
        }
        outcome(done)
    })
}

/// The installed packs `update` installs again: a source pack the catalog
/// pins at another revision or filter (with the options it was installed
/// with), a hosted archive at another version. Only `ids` when given.
pub fn updates(
    catalog: &Catalog,
    packs: &[InstalledPack],
    ids: &[String],
) -> Vec<(String, Option<BTreeSet<String>>)> {
    packs
        .iter()
        .filter(|pack| ids.is_empty() || ids.contains(&pack.id))
        .filter_map(|pack| {
            if let Some(entry) = ruleset::source_update(catalog, pack) {
                let options = pack
                    .source
                    .as_ref()
                    .map(|source| source.options.iter().cloned().collect())
                    .unwrap_or_default();
                return Some((entry.id.clone(), Some(options)));
            }
            catalog
                .packs
                .iter()
                .find(|entry| entry.id == pack.id && entry.version != pack.version)
                .map(|entry| (entry.id.clone(), None))
        })
        .collect()
}

/// `rules update [ID...]`.
pub fn update(ids: &[String], context: &Context) -> Result<Reply, CliError> {
    cancellable(|cancel| {
        let catalog = fetch_catalog(context, cancel)?;
        let packs = installed(context)?;
        if let Some(unknown) = ids.iter().find(|id| !packs.iter().any(|p| &p.id == *id)) {
            return Err(CliError::not_found(format!(
                "no installed pack {unknown:?}; `rules list` shows them"
            ))
            .with_field("id"));
        }
        let mut done = Vec::new();
        for (id, options) in updates(&catalog, &packs, ids) {
            if cancel.load(Ordering::Relaxed) {
                done.push((id, Err("cancelled".to_owned())));
                continue;
            }
            let result = install_one(context, &catalog, &id, options, cancel);
            done.push((id, result));
        }
        outcome(done)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(id: &str, version: &str) -> InstalledPack {
        serde_json::from_value(json!({
            "id": id, "engine": "yara", "name": id, "version": version, "enabled": true,
            "sha256": "", "upstream_revision": "", "upstream_url": "", "license": "",
            "evidence": [], "limits": [], "versions": [], "source": null, "app": "",
            "engine_requirement": "",
        }))
        .unwrap()
    }

    #[test]
    fn update_takes_hosted_archives_at_another_version_and_only_the_named() {
        let catalog: Catalog = serde_json::from_value(json!({
            "schema": 1, "sources": [],
            "packs": [
                {"id": "old", "engine": "yara", "name": "Old", "version": "2",
                 "upstream_revision": "", "upstream_url": "", "download_url": "",
                 "sha256": "", "size": 1, "app": "", "engine_requirement": "", "rules": 1,
                 "helpers": 0, "license": "", "evidence": [], "limits": []},
                {"id": "same", "engine": "yara", "name": "Same", "version": "1",
                 "upstream_revision": "", "upstream_url": "", "download_url": "",
                 "sha256": "", "size": 1, "app": "", "engine_requirement": "", "rules": 1,
                 "helpers": 0, "license": "", "evidence": [], "limits": []}
            ]
        }))
        .unwrap();
        let packs = [
            installed("old", "1"),
            installed("same", "1"),
            installed("gone", "1"),
        ];
        let ids: Vec<String> = updates(&catalog, &packs, &[])
            .into_iter()
            .map(|u| u.0)
            .collect();
        assert_eq!(ids, ["old"]);
        assert!(updates(&catalog, &packs, &["same".into()]).is_empty());
        assert_eq!(entries(&catalog).len(), 2);
    }
}
