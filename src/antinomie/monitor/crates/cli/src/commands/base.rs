// SPDX-License-Identifier: GPL-3.0-only
//! `base list/install/download/build/delete` (design 3.4.2): the installed
//! bases and the commands that add or remove one. Each is one engine command
//! run in this process under the data-directory lock.
use super::machine::{BASES_WAIT, base_value, confirm, find_base, wait_bases};
use crate::{
    context::Context,
    engine::DirectEngine,
    error::{CliError, ErrorCode},
    output::{Reply, table},
};
use antinomie_monitor_core::{
    Command, Snapshot,
    build::{BUILD_PROFILES, BuildMode, BuildOptions, BuildRequest},
    settings,
};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Subcommand, Debug)]
pub enum Base {
    /// List the installed bases, or with --remote the ones the catalog offers.
    List(List),
    /// Install a base from a boot-bundle folder.
    Install {
        /// The folder holding the bundle (`bundle.json`, kernel, disk).
        dir: PathBuf,
    },
    /// Download a base from the catalog (needs `outbound_catalog`).
    Download(Download),
    /// Build a base on this machine.
    Build(Build),
    /// Delete an installed base; refused while a VM uses it.
    Delete {
        /// The base identity (or the start of it, 4 characters or more) or its label.
        id: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
pub struct List {
    /// Fetch and list the bases the public catalog advertises (needs
    /// `outbound_catalog`; uses the network).
    #[arg(long)]
    pub remote: bool,
}

#[derive(Args, Debug)]
pub struct Download {
    /// The catalog identity (see `base list --remote`), or the start of it.
    pub id: String,
    /// Wait for the download. Always on in direct mode: leaving would cancel it.
    #[arg(long)]
    pub wait: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Engine {
    Automatic,
    Native,
    Podman,
    Docker,
    Qemu,
}

#[derive(Args, Debug)]
pub struct Build {
    /// What to build: busybox, debian-minimal or debian-xfce.
    #[arg(long, default_value = "busybox", value_name = "PROFILE")]
    pub profile: String,
    /// Where the build runs.
    #[arg(long, value_enum, default_value = "automatic")]
    pub engine: Engine,
    /// Display name of the base (default: automatic).
    #[arg(long)]
    pub name: Option<String>,
    /// Wait for the build. Always on in direct mode: leaving would cancel it.
    #[arg(long)]
    pub wait: bool,
}

pub fn run(base: &Base, context: &Context) -> Result<Reply, CliError> {
    let mut engine = DirectEngine::start(context)?;
    let outcome = dispatch(base, context, &mut engine);
    engine.finish();
    outcome
}

fn dispatch(base: &Base, context: &Context, engine: &mut DirectEngine) -> Result<Reply, CliError> {
    let limit = context.timeout();
    wait_bases(engine, limit)?;
    match base {
        Base::List(arguments) => list(arguments, limit, engine),
        Base::Install { dir } => install(dir, limit, engine),
        Base::Download(arguments) => download(arguments, limit, engine),
        Base::Build(arguments) => build_base(arguments, limit, engine),
        Base::Delete { id, yes } => delete(id, *yes, limit, engine),
    }
}

fn bases_table(snapshot: &Snapshot) -> String {
    let rows: Vec<Vec<String>> = snapshot
        .bases
        .iter()
        .map(|base| {
            vec![
                base.id.chars().take(12).collect(),
                base.label.clone(),
                base.arch.label().to_owned(),
                format!("{} MiB", base.size_bytes / (1 << 20)),
                base.revision.map_or("-".into(), |r| r.to_string()),
            ]
        })
        .collect();
    if rows.is_empty() {
        return "no bases installed\n".into();
    }
    table(&["ID", "LABEL", "ARCH", "SIZE", "REVISION"], &rows)
}

fn list(
    arguments: &List,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    if arguments.remote {
        refresh_catalog(limit, engine)?;
        let installed: Vec<String> = engine
            .snapshot()
            .bases
            .iter()
            .map(|base| base.id.clone())
            .collect();
        let items: Vec<Value> = engine
            .snapshot()
            .remote_bases
            .iter()
            .map(|base| {
                json!({
                    "id": base.identity,
                    "label": base.label,
                    "kind": base.kind,
                    "kernel_version": base.kernel_version,
                    "min_ram_mib": base.min_ram_mib,
                    "min_disk_gib": base.min_disk_gib,
                    "total_size": base.total_size,
                    "revision": base.revision,
                    "installed": installed.contains(&base.identity),
                })
            })
            .collect();
        let rows: Vec<Vec<String>> = engine
            .snapshot()
            .remote_bases
            .iter()
            .map(|base| {
                vec![
                    base.identity.chars().take(12).collect(),
                    base.label.clone(),
                    base.kind.clone(),
                    format!("{} MiB", base.total_size / (1 << 20)),
                    if installed.contains(&base.identity) {
                        "installed".into()
                    } else {
                        "-".into()
                    },
                ]
            })
            .collect();
        let human = if rows.is_empty() {
            "the catalog lists no bases\n".to_owned()
        } else {
            table(&["ID", "LABEL", "KIND", "SIZE", ""], &rows)
        };
        return Ok(Reply::list(items, None).with_human(human));
    }
    let items = engine.snapshot().bases.iter().map(base_value).collect();
    Ok(Reply::list(items, None).with_human(bases_table(engine.snapshot())))
}

/// The catalog is the one thing a base command fetches from the network, so
/// it follows the same switch as the window.
fn require_outbound_catalog(data_dir: &std::path::Path) -> Result<(), CliError> {
    let settings = settings::load(data_dir)
        .map_err(CliError::internal)?
        .unwrap_or_default();
    if settings.outbound_catalog {
        Ok(())
    } else {
        Err(CliError::new(
            ErrorCode::PolicyDenied,
            "fetching the base catalog is off: run `antinomie-cli config set outbound_catalog true` to allow it",
        ))
    }
}

fn refresh_catalog(limit: Option<Duration>, engine: &mut DirectEngine) -> Result<(), CliError> {
    require_outbound_catalog(engine.data_dir())?;
    engine.command(Command::RefreshRemoteBases, limit)?;
    engine.wait_until(
        "the base catalog",
        Some(limit.unwrap_or(BASES_WAIT)),
        |snapshot| !snapshot.remote_refreshing,
    )?;
    match &engine.snapshot().remote_error {
        Some(error) => Err(CliError::new(
            ErrorCode::Unavailable,
            format!("the base catalog could not be fetched: {error}"),
        )),
        None => Ok(()),
    }
}

fn installed_ids(snapshot: &Snapshot) -> Vec<String> {
    snapshot.bases.iter().map(|base| base.id.clone()).collect()
}

/// The bases that appeared since `before`, as result objects.
fn new_bases(snapshot: &Snapshot, before: &[String]) -> Vec<Value> {
    snapshot
        .bases
        .iter()
        .filter(|base| !before.contains(&base.id))
        .map(base_value)
        .collect()
}

fn install(
    dir: &std::path::Path,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let directory =
        std::fs::canonicalize(dir).map_err(|error| CliError::io(dir, &error).with_field("dir"))?;
    let before = installed_ids(engine.snapshot());
    let message = engine.command(Command::ImportBase { directory }, limit)?;
    wait_bases(engine, limit)?;
    let added = new_bases(engine.snapshot(), &before);
    let human = match added.first() {
        Some(base) => format!("{message}: {}\n", base["label"].as_str().unwrap_or("")),
        None => format!("{message} (it was already installed)\n"),
    };
    Ok(Reply::value(json!({"message": message, "installed": added})).with_human(human))
}

fn download(
    arguments: &Download,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    refresh_catalog(limit, engine)?;
    let remote = &engine.snapshot().remote_bases;
    let identity = match remote.iter().find(|base| base.identity == arguments.id) {
        Some(base) => base.identity.clone(),
        None => {
            let starts: Vec<&str> = remote
                .iter()
                .filter(|base| arguments.id.len() >= 4 && base.identity.starts_with(&arguments.id))
                .map(|base| base.identity.as_str())
                .collect();
            match starts.as_slice() {
                [one] => (*one).to_owned(),
                [] => {
                    return Err(CliError::not_found(format!(
                        "the catalog has no base {:?}; see `base list --remote`",
                        arguments.id
                    ))
                    .with_field("id"));
                }
                _ => {
                    return Err(CliError::invalid(format!(
                        "{:?} names more than one catalog base; give more of it",
                        arguments.id
                    ))
                    .with_field("id"));
                }
            }
        }
    };
    let before = installed_ids(engine.snapshot());
    engine.command(Command::DownloadBase { identity }, limit)?;
    engine.wait_until(
        "the base download",
        limit,
        |snapshot| matches!(&snapshot.download, Some(status) if status.finished || status.error.is_some()),
    )?;
    if let Some(error) = engine
        .snapshot()
        .download
        .as_ref()
        .and_then(|status| status.error.clone())
    {
        return Err(CliError::new(
            ErrorCode::Unavailable,
            format!("the download failed: {error}"),
        ));
    }
    wait_bases(engine, limit)?;
    let added = new_bases(engine.snapshot(), &before);
    Ok(
        Reply::value(json!({"installed": added})).with_human(format!(
            "downloaded and installed {}\n",
            added
                .first()
                .and_then(|base| base["label"].as_str())
                .unwrap_or("the base")
        )),
    )
}

fn build_base(
    arguments: &Build,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let Some(profile) = BUILD_PROFILES
        .iter()
        .find(|profile| profile.id == arguments.profile)
    else {
        let known: Vec<&str> = BUILD_PROFILES.iter().map(|profile| profile.id).collect();
        return Err(CliError::invalid(format!(
            "unknown build profile {:?}; use {}",
            arguments.profile,
            known.join(", ")
        ))
        .with_field("profile"));
    };
    let mut options = BuildOptions::defaults(profile.kind);
    if let Some(name) = &arguments.name {
        options.name = name.clone();
    }
    let request = BuildRequest {
        profile: profile.id.to_owned(),
        mode: match arguments.engine {
            Engine::Automatic => BuildMode::Automatic,
            Engine::Native => BuildMode::Native,
            Engine::Podman => BuildMode::Podman,
            Engine::Docker => BuildMode::Docker,
            Engine::Qemu => BuildMode::Qemu,
        },
        options,
        arch: Default::default(),
    };
    let before = installed_ids(engine.snapshot());
    engine.command(Command::BuildBase { request }, limit)?;
    engine.wait_until(
        "the base build",
        limit,
        |snapshot| matches!(&snapshot.build, Some(status) if status.finished || status.error.is_some()),
    )?;
    let status = engine.snapshot().build.clone();
    if let Some(error) = status.as_ref().and_then(|status| status.error.clone()) {
        return Err(
            CliError::new(ErrorCode::Internal, format!("the build failed: {error}"))
                .with_details(json!({"log": status.and_then(|status| status.log_path)})),
        );
    }
    wait_bases(engine, limit)?;
    let added = new_bases(engine.snapshot(), &before);
    Ok(Reply::value(json!({"installed": added})).with_human("base built and installed\n".into()))
}

fn delete(
    id: &str,
    yes: bool,
    limit: Option<Duration>,
    engine: &mut DirectEngine,
) -> Result<Reply, CliError> {
    let base = find_base(engine.snapshot(), id)?;
    let (identity, label) = (base.id.clone(), base.label.clone());
    confirm(
        yes,
        &format!("deleting base {label:?} removes it from this machine"),
    )?;
    let message = engine.command(
        Command::DeleteBase {
            identity: identity.clone(),
            confirmed: true,
        },
        limit,
    )?;
    Ok(
        Reply::value(json!({"deleted": identity, "message": message}))
            .with_human(format!("{message}\n")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_profiles_are_the_ones_the_help_names() {
        let ids: Vec<&str> = BUILD_PROFILES.iter().map(|profile| profile.id).collect();
        for id in ["busybox", "debian-minimal", "debian-xfce"] {
            assert!(ids.contains(&id), "{id}");
        }
    }

    #[test]
    fn the_catalog_stays_off_until_the_setting_allows_it() {
        let root = std::env::temp_dir().join(format!("ant-cli-base-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let error = require_outbound_catalog(&root).unwrap_err();
        assert_eq!(error.exit.code(), 5);
        assert!(error.message.contains("outbound_catalog"));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
