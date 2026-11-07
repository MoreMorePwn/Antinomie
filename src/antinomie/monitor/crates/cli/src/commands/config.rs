// SPDX-License-Identifier: GPL-3.0-only
//! `config path`. `config get/set/validate` arrive with cards P1-2 and P3-3.
use crate::{
    context::Context,
    error::CliError,
    output::{Reply, block},
};
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum Config {
    /// Print the paths of `settings.json`, `service.toml` and `policies/`.
    Path,
}

pub fn run(config: &Config, context: &Context) -> Result<Reply, CliError> {
    match config {
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
