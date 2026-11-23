// SPDX-License-Identifier: GPL-3.0-only
//! `tools list|install|update` (ANT-T0556): the optional static-analysis tools
//! (capa, FLOSS, Ghidra with its Java runtime, Detect It Easy, UPX and the
//! others of Tools > Analysis tools) without the window. The same code as the
//! desktop app (`antinomie_monitor_core::analysis_tools`): the same pinned
//! downloads, SHA-256 checks and `<data>/tools/<id>/` layout, resumed when a
//! download was cut. A system copy takes precedence where the app's does.
//!
//! No engine lock: a daemon may serve meanwhile, and each analysis looks its
//! tools up when it starts, so a tool installed now is used by the next one.
//! Installs of this command are one at a time per data folder
//! (`<data>/tools/.cli-install.lock`). The network routes' programs (Tor,
//! wireproxy) are set up with the routes, not here.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, table},
    signals,
};
use antinomie_monitor_core::analysis_tools::{self, ToolStatus};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Subcommand, Debug)]
pub enum Tools {
    /// List the analysis tools: the version Antinomie installs, the one it
    /// installed, and a system copy that takes precedence.
    List,
    /// Download, check (SHA-256) and unpack tools into <data>/tools/<id>, as
    /// Tools > Analysis tools does: capa, floss, ghidra, die, upx, ...
    Install {
        /// Tool ids (`tools list`).
        #[arg(required = true, value_name = "ID")]
        ids: Vec<String>,
    },
    /// Install again each tool Antinomie installed whose version is not the
    /// one this app pins (only the named ones when ids are given).
    Update {
        /// Tool ids (`tools list`); without one, every tool that needs it.
        #[arg(value_name = "ID")]
        ids: Vec<String>,
    },
}

pub fn run(tools: &Tools, context: &Context) -> Result<Reply, CliError> {
    match tools {
        Tools::List => list(context),
        Tools::Install { ids } => install(ids, false, context),
        Tools::Update { ids } => install(ids, true, context),
    }
}

/// The tools this command manages: every package but the routes' programs.
fn managed(data: &std::path::Path) -> Vec<ToolStatus> {
    analysis_tools::statuses(data)
        .into_iter()
        .filter(|tool| !analysis_tools::is_route_tool(&tool.id))
        .collect()
}

fn tool_value(tool: &ToolStatus) -> Value {
    json!({
        "id": tool.id, "name": tool.name, "purpose": tool.purpose,
        "version": tool.version, "size": tool.size,
        "installed": tool.installed, "installed_path": tool.installed_shown,
        "system": tool.system, "available": tool.available(),
        "update": tool.installed.as_ref().is_some_and(|v| *v != tool.version),
    })
}

fn list(context: &Context) -> Result<Reply, CliError> {
    let tools = managed(context.data_dir());
    let rows: Vec<Vec<String>> = tools
        .iter()
        .map(|tool| {
            vec![
                tool.id.clone(),
                tool.name.clone(),
                tool.installed.clone().unwrap_or_else(|| "-".into()),
                tool.system.clone().unwrap_or_else(|| "-".into()),
                tool.version.clone(),
                antinomie_monitor_core::byte_size::short_size(tool.size),
            ]
        })
        .collect();
    let items: Vec<Value> = tools.iter().map(tool_value).collect();
    Ok(Reply::list(items, None).with_human(table(
        &["ID", "NAME", "INSTALLED", "SYSTEM", "PINNED", "DOWNLOAD"],
        &rows,
    )))
}

/// Which tools `ids` names; for `update` without ids, every tool Antinomie
/// installed at another version than the pinned one.
fn chosen(ids: &[String], update: bool, tools: &[ToolStatus]) -> Result<Vec<String>, CliError> {
    if update && ids.is_empty() {
        return Ok(tools
            .iter()
            .filter(|tool| tool.installed.as_ref().is_some_and(|v| *v != tool.version))
            .map(|tool| tool.id.clone())
            .collect());
    }
    let mut out = Vec::new();
    for id in ids {
        let id = id.trim().to_ascii_lowercase();
        if !tools.iter().any(|tool| tool.id == id) {
            return Err(CliError::not_found(format!(
                "no analysis tool {id:?}; the tools are {}",
                tools
                    .iter()
                    .map(|tool| tool.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .with_field("id"));
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

fn install(ids: &[String], update: bool, context: &Context) -> Result<Reply, CliError> {
    let data = context.data_dir();
    let wanted = chosen(ids, update, &managed(data))?;
    if wanted.is_empty() {
        return Ok(Reply::value(json!({"installed": [], "failed": []}))
            .with_human("Every installed tool is at the version this app pins.\n".into()));
    }
    antinomie_monitor_core::distribution::curl_version(&context.options.curl).map_err(|e| {
        CliError::new(
            ErrorCode::DependencyMissing,
            format!("curl is needed to download the tools: {e}"),
        )
    })?;
    let dir = analysis_tools::tools_dir(data);
    std::fs::create_dir_all(&dir).map_err(|e| CliError::io(&dir, &e))?;
    let lock_path = dir.join(".cli-install.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| CliError::io(&lock_path, &e))?;
    lock.try_lock().map_err(|_| {
        CliError::new(
            ErrorCode::Conflict,
            "another `tools install` is running for this data directory",
        )
    })?;
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
    let logger = context.logger;
    let mut installed = Vec::new();
    let mut failed = Vec::new();
    for id in &wanted {
        if cancel.load(Ordering::Relaxed) {
            failed.push(json!({"id": id, "error": "cancelled"}));
            continue;
        }
        let mut shown = String::new();
        let result = analysis_tools::install(
            &context.options.curl,
            data,
            id,
            &cancel,
            |stage, received, total| {
                let line = match stage.strip_prefix("note:") {
                    Some(note) => note.to_owned(),
                    None => format!("{id}: {stage} {}%", received * 100 / total.max(1) / 10 * 10),
                };
                if line != shown {
                    logger.info(&line);
                    shown = line;
                }
            },
        );
        match result {
            Ok(()) => {
                logger.info(&format!("{id} installed"));
                installed.push(id.clone());
            }
            Err(error) => failed.push(json!({"id": id, "error": error})),
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    let tools: Vec<Value> = managed(data)
        .iter()
        .filter(|tool| wanted.contains(&tool.id))
        .map(tool_value)
        .collect();
    if !failed.is_empty() {
        let text = failed
            .iter()
            .map(|f| {
                format!(
                    "{}: {}",
                    f["id"].as_str().unwrap_or(""),
                    f["error"].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CliError::new(
            ErrorCode::Unavailable,
            format!("not installed: {text}"),
        ));
    }
    let mut human = String::new();
    for tool in &tools {
        human.push_str(&format!(
            "{} {} installed in {}\n",
            tool["name"].as_str().unwrap_or(""),
            tool["installed"].as_str().unwrap_or(""),
            tool["installed_path"].as_str().unwrap_or("")
        ));
    }
    Ok(Reply::value(json!({"installed": installed, "tools": tools})).with_human(human))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(id: &str, installed: Option<&str>, pinned: &str) -> ToolStatus {
        ToolStatus {
            id: id.into(),
            name: id.into(),
            version: pinned.into(),
            installed: installed.map(str::to_owned),
            ..ToolStatus::default()
        }
    }

    #[test]
    fn the_cli_manages_the_static_tools_and_not_the_routes_programs() {
        let dir = std::env::temp_dir().join(format!(
            "ant-cli-tools-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ids: Vec<String> = managed(&dir).into_iter().map(|t| t.id).collect();
        for wanted in ["capa", "floss", "ghidra", "die"] {
            assert!(ids.iter().any(|id| id == wanted), "{wanted}: {ids:?}");
        }
        assert!(!ids.iter().any(|id| id == "tor" || id == "wireproxy"));
    }

    #[test]
    fn install_takes_known_ids_and_update_the_outdated_ones() {
        let tools = [
            tool("capa", Some("9.3.0"), "9.4.0"),
            tool("floss", Some("3.1.1"), "3.1.1"),
            tool("ghidra", None, "12.0"),
        ];
        assert_eq!(
            chosen(
                &["CAPA".into(), "capa".into(), "ghidra".into()],
                false,
                &tools
            )
            .unwrap(),
            ["capa", "ghidra"]
        );
        let error = chosen(&["tor".into()], false, &tools).unwrap_err();
        assert_eq!(error.exit.code(), 3);
        assert!(error.to_string().contains("capa, floss, ghidra"), "{error}");
        assert_eq!(chosen(&[], true, &tools).unwrap(), ["capa"]);
        assert_eq!(chosen(&["floss".into()], true, &tools).unwrap(), ["floss"]);
    }
}
