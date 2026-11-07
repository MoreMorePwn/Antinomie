// SPDX-License-Identifier: GPL-3.0-only
//! `config path`, `config get` and `config set` over `settings.json` (design
//! 2.4.1, card P1-2). `config validate` arrives with card P3-3.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use antinomie_monitor_core::{
    data_owner::{self, OwnerClaim, OwnerKind},
    settings::{self, EngineSettings},
};
use clap::Subcommand;
use serde_json::{Value, json};
use std::os::unix::fs::DirBuilderExt;

#[derive(Subcommand, Debug)]
pub enum Config {
    /// Print the paths of `settings.json`, `service.toml` and `policies/`.
    Path,
    /// Print one setting, or all of them. A dotted KEY reaches into an object
    /// (`disks.hide_dotfiles`). Reads the file; takes no lock.
    Get { key: Option<String> },
    /// Change one setting. VALUE is JSON when it parses (`true`, `12`), else
    /// text. Takes the engine lock, so it refuses while a window or daemon runs.
    Set { key: String, value: String },
}

/// The settings in the data directory; the defaults when no front end has
/// written the file yet. A file that cannot be read is an error.
fn current(context: &Context) -> Result<EngineSettings, CliError> {
    settings::load(context.data_dir())
        .map(Option::unwrap_or_default)
        .map_err(|message| {
            CliError::new(ErrorCode::PreconditionFailed, message).with_field("settings")
        })
}

fn show(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn get(key: Option<&str>, context: &Context) -> Result<Reply, CliError> {
    let settings = current(context)?;
    let key = key.unwrap_or("");
    let value = settings
        .get(key)
        .map_err(|message| CliError::not_found(message).with_field("key"))?;
    let human = match (&value, key.is_empty()) {
        (Value::Object(map), true) => {
            let rows: Vec<Vec<String>> = map
                .iter()
                .map(|(name, value)| vec![name.clone(), show(value)])
                .collect();
            table(&["setting", "value"], &rows)
        }
        _ => format!("{}\n", show(&value)),
    };
    let result = if key.is_empty() {
        json!({"settings": value})
    } else {
        json!({"key": key, "value": value})
    };
    Ok(Reply::value(result).with_human(human))
}

fn set(key: &str, text: &str, context: &Context) -> Result<Reply, CliError> {
    let data = context.data_dir();
    // Check the change before locking: a bad key or value touches nothing.
    let mut settings = current(context)?;
    settings
        .set(key, text)
        .map_err(|message| CliError::invalid(message).with_field("key"))?;
    // A first `config set` may be the first thing to use the directory.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data)
        .map_err(|error| CliError::internal(format!("{}: {error}", data.display())))?;
    let claim = OwnerClaim {
        kind: OwnerKind::Cli,
        socket: None,
    };
    let _lock = data_owner::lock_data_dir(data, &claim)
        .map_err(|message| CliError::from_engine_start(data, &message))?;
    // Read again under the lock so a write between the two reads is not lost.
    let mut settings = current(context)?;
    settings
        .set(key, text)
        .map_err(|message| CliError::invalid(message).with_field("key"))?;
    settings::save(data, &settings).map_err(CliError::internal)?;
    let value = settings.get(key).unwrap_or(Value::Null);
    Ok(Reply::value(json!({"key": key, "value": value}))
        .with_human(format!("{key} = {}\n", show(&value))))
}

pub fn run(config: &Config, context: &Context) -> Result<Reply, CliError> {
    match config {
        Config::Get { key } => get(key.as_deref(), context),
        Config::Set { key, value } => set(key, value, context),
        Config::Path => {
            let data = context.data_dir();
            let paths = [
                ("data_dir", data.to_path_buf()),
                ("settings", data.join("settings.json")),
                ("service", data.join("service.toml")),
                ("policies", data.join("policies")),
            ];
            let pairs: Vec<(&str, String)> = paths
                .iter()
                .map(|(key, path)| (*key, path.display().to_string()))
                .collect();
            let value = json!({
                "data_dir": paths[0].1,
                "settings": paths[1].1,
                "service": paths[2].1,
                "policies": paths[3].1,
            });
            Ok(Reply::value(value).with_human(block(&pairs)))
        }
    }
}
