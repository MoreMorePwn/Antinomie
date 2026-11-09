// SPDX-License-Identifier: GPL-3.0-only
//! `auto watch list/scan` (design 3.4.4; card P4-2). With a daemon they are
//! calls to it; without one `watch list` reads `service.toml`.
use super::{link, render::clean};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, table},
};
use clap::Subcommand;
use serde_json::{Value, json};

#[derive(Subcommand, Debug)]
pub enum Watch {
    /// The watch folders of the daemon: their state, the files taken and
    /// refused. Without a daemon: the folders `service.toml` names.
    List,
    /// Scan every watch folder now (a file is still taken only after its size
    /// has been steady for 3 seconds). Needs the daemon.
    Scan,
}

fn cell(value: &Value, key: &str) -> String {
    match &value[key] {
        Value::Null => "-".into(),
        Value::String(text) => clean(text),
        other => other.to_string(),
    }
}

fn watch_text(list: &Value) -> String {
    let rows: Vec<Vec<String>> = list["folders"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| {
            let refused = f["refused"].as_array().map_or(0, Vec::len);
            let detail = match f["detail"].as_str() {
                Some(text) => format!(" ({})", clean(text)),
                None => String::new(),
            };
            vec![
                cell(f, "path"),
                cell(f, "policy"),
                format!("{}{detail}", cell(f, "state")),
                cell(f, "taken"),
                cell(f, "rejected"),
                refused.to_string(),
                cell(f, "pending"),
            ]
        })
        .collect();
    if rows.is_empty() {
        return "no watch folder is configured ([[inbox.watch]] in service.toml)\n".into();
    }
    let mut out = table(
        &[
            "FOLDER", "POLICY", "STATE", "TAKEN", "REJECTED", "REFUSED", "WAITING",
        ],
        &rows,
    );
    for folder in list["folders"].as_array().into_iter().flatten() {
        for refusal in folder["refused"].as_array().into_iter().flatten() {
            out.push_str(&format!(
                "  refused {}: {}\n",
                cell(refusal, "name"),
                cell(refusal, "reason")
            ));
        }
    }
    out
}

pub fn watch(command: &Watch, context: &Context) -> Result<Reply, CliError> {
    let list = match (link::daemon(context)?, command) {
        (Some(mut client), Watch::List) => link::call(&mut client, "watch.list", json!({}))?,
        (Some(mut client), Watch::Scan) => link::call(&mut client, "watch.scan", json!({}))?,
        (None, Watch::Scan) => {
            return Err(CliError::new(
                ErrorCode::Unavailable,
                "`auto watch scan` needs a running daemon (`antinomie-cli auto daemon`)",
            ));
        }
        (None, Watch::List) => {
            let config = super::daemon::load_config(None, context.data_dir())?;
            let folders: Vec<Value> = config
                .inbox
                .watch
                .iter()
                .map(|w| {
                    json!({
                        "path": w.path, "policy": w.policy, "state": "daemon not running",
                        "detail": null, "taken": 0, "rejected": 0, "refused": [],
                        "pending": 0,
                    })
                })
                .collect();
            json!({ "folders": folders })
        }
    };
    let items = list["folders"].as_array().cloned().unwrap_or_default();
    Ok(Reply::list(items, None).with_human(watch_text(&list)))
}
