// SPDX-License-Identifier: GPL-3.0-only
//! `auto watch list/scan`, `auto gc` and `auto delete` (design 3.4.4; cards
//! P4-2, P4-3). With a daemon they are calls to it; without one `watch list`
//! reads `service.toml`, and `gc` and `delete` take the data folder for the
//! command (nothing holds a recording open then, so nothing is skipped for an
//! open read).
use super::{
    jobs::job_id,
    link::{self, api},
    render::clean,
};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, table},
};
use antinomie_monitor_core::samples::MAX_SAMPLE;
use antinomie_service::{
    clock::{Clock, SystemClock},
    intake::staging::StagingStore,
    retention::{self, GcReport, RealRuns, Retention},
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Subcommand, Debug)]
pub enum Watch {
    /// The watch folders of the daemon: their state, the files taken and
    /// refused. Without a daemon: the folders `service.toml` names.
    List,
    /// Scan every watch folder now (a file is still taken only after its size
    /// has been steady for 3 seconds). Needs the daemon.
    Scan,
}

#[derive(Args, Debug)]
pub struct Gc {
    /// Print what retention would delete and delete nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct Delete {
    pub job: String,
    /// Also delete the job's recording (through the same run deletion the
    /// window uses); the sample stays in the library either way.
    #[arg(long)]
    pub with_recording: bool,
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

fn gc_text(report: &Value) -> String {
    let dry = report["dry_run"].as_bool().unwrap_or(false);
    let mut out = String::new();
    let actions = report["actions"].as_array().cloned().unwrap_or_default();
    if actions.is_empty() {
        out.push_str(if dry {
            "nothing would be deleted\n"
        } else {
            "nothing to delete\n"
        });
    } else {
        let rows: Vec<Vec<String>> = actions
            .iter()
            .map(|a| {
                vec![
                    cell(a, "kind"),
                    cell(a, "job"),
                    cell(a, "run"),
                    cell(a, "bytes"),
                    cell(a, "detail"),
                ]
            })
            .collect();
        out.push_str(&format!(
            "{}:\n",
            if dry { "would delete" } else { "deleted" }
        ));
        out.push_str(&table(&["WHAT", "JOB", "RUN", "BYTES", "WHY"], &rows));
        out.push_str(&format!(
            "{} {} bytes\n",
            if dry { "would free" } else { "freed" },
            report["freed_bytes"]
        ));
    }
    for skip in report["skipped"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "skipped {} {}: {}\n",
            cell(skip, "kind"),
            cell(skip, "job"),
            cell(skip, "why")
        ));
    }
    for error in report["errors"].as_array().into_iter().flatten() {
        out.push_str(&format!("error: {}\n", clean(error.as_str().unwrap_or(""))));
    }
    out
}

/// A pass over the data folder taken for this command.
fn need_data_dir(context: &Context) -> Result<(), CliError> {
    if context.data_dir().is_dir() {
        Ok(())
    } else {
        Err(CliError::not_found(format!(
            "no data folder at {}",
            context.data_dir().display()
        )))
    }
}

fn gc_direct(context: &Context, dry_run: bool) -> Result<GcReport, CliError> {
    need_data_dir(context)?;
    let (store, _guard) = link::locked_store(context)?;
    let config = super::daemon::load_config(None, context.data_dir())?;
    let runs = RealRuns {
        options: &context.options,
        query: None,
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let inbox = config.inbox_dir(context.data_dir());
    let staging = StagingStore::open(&inbox, context.data_dir(), Arc::clone(&clock), MAX_SAMPLE)
        .ok()
        .map(|(staging, _)| staging);
    let logger = context.logger;
    let log = move |line: &str| logger.info(line);
    let report = Retention {
        store: &store,
        runs: &runs,
        config: config.retention.clone(),
        rejected_dir: inbox.join("rejected"),
        processed_dir: inbox.join("processed"),
        processed_keep_days: config.inbox.processed_keep_days,
        uploads: staging.as_ref().map(|s| s as &dyn retention::Uploads),
        now_ms: clock.now_ms(),
        log: &log,
    }
    .run(dry_run);
    Ok(report)
}

pub fn gc(arguments: &Gc, context: &Context) -> Result<Reply, CliError> {
    let report = match link::daemon(context)? {
        Some(mut client) => link::call(
            &mut client,
            "gc.run",
            json!({ "dry_run": arguments.dry_run }),
        )?,
        None => serde_json::to_value(gc_direct(context, arguments.dry_run)?).unwrap_or_default(),
    };
    let human = gc_text(&report);
    Ok(Reply::value(report).with_human(human))
}

pub fn delete(arguments: &Delete, context: &Context) -> Result<Reply, CliError> {
    let id = job_id(&arguments.job)?;
    let deleted = match link::daemon(context)? {
        Some(mut client) => link::call(
            &mut client,
            "job.delete",
            json!({"job_id": id, "with_recording": arguments.with_recording}),
        )?,
        None => {
            need_data_dir(context)?;
            let (store, _guard) = link::locked_store(context)?;
            let runs = RealRuns {
                options: &context.options,
                query: None,
            };
            let logger = context.logger;
            retention::delete_job(
                &store,
                &runs,
                &id,
                arguments.with_recording,
                &move |line: &str| logger.info(line),
            )
            .map_err(api)?;
            json!({"deleted": true})
        }
    };
    let human = format!("deleted {id}\n");
    Ok(Reply::value(deleted).with_human(human))
}
