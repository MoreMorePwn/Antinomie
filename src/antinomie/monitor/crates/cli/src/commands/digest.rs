// SPDX-License-Identifier: GPL-3.0-only
//! `digest RUN` and `digest --pending` (ANT-T0400): build the Triage digest of
//! a finished run that has none, the way the window and the Auto lane do
//! (`antinomie_triage::digest_job`): a streamed read of the recording within a
//! size and time budget, marked partial when the budget ended it or telemetry
//! was lost, never twice, and safe to run again after an interruption (the file
//! is written whole at the end). It writes the digest into the run's folder, so
//! it takes the data-directory lock as `detect --save` does.
use super::recording::{RUN_HELP, find_run, list_all_runs};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, table},
    signals,
};
use antinomie_monitor_core::{
    RunSummary,
    data_owner::{self, OwnerClaim, OwnerKind},
};
use antinomie_triage::digest_job::{self, Budget, Built, Status};
use clap::Args;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Args, Debug)]
pub struct Digest {
    #[arg(help = RUN_HELP, required_unless_present = "pending", conflicts_with = "pending")]
    pub run: Option<String>,
    /// Build the digest of every finished run that has none (or whose digest
    /// was made while its recording was still being written), one at a time.
    #[arg(long)]
    pub pending: bool,
    /// Most calls of a run one digest reads before it is marked partial.
    #[arg(long, value_name = "CALLS", default_value_t = digest_job::MAX_CALLS)]
    pub max_calls: u64,
    /// Most seconds one digest may take before it is marked partial.
    #[arg(long, value_name = "SECONDS", default_value_t = digest_job::MAX_TIME.as_secs())]
    pub max_seconds: u64,
}

fn word(built: &Result<Built, String>) -> (&'static str, Vec<String>) {
    match built {
        Ok(Built::Whole) => ("built", Vec::new()),
        Ok(Built::Partial(reasons)) => ("built_partial", reasons.clone()),
        Ok(Built::Current) => ("current", Vec::new()),
        Ok(Built::Busy) => ("busy", Vec::new()),
        Ok(Built::Failed(reason)) => ("unreadable", vec![reason.clone()]),
        Err(error) => ("failed", vec![error.clone()]),
    }
}

fn build_one(
    context: &Context,
    run: &RunSummary,
    budget: Budget,
    cancel: &Arc<AtomicBool>,
) -> Result<Built, String> {
    let queue = digest_job::queue();
    let directory = run.directory.clone();
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (cancel, done) = (Arc::clone(cancel), Arc::clone(&done));
        let logger = context.logger;
        let label = run.id.clone();
        std::thread::spawn(move || {
            let (mut last, mut waited) = (String::new(), Duration::ZERO);
            while !done.load(Ordering::Relaxed) {
                if signals::interrupted() {
                    cancel.store(true, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(100));
                waited += Duration::from_millis(100);
                if waited >= Duration::from_secs(2) {
                    waited = Duration::ZERO;
                    if let Status::Building(line) = digest_job::queue().status(&directory)
                        && line != last
                    {
                        logger.info(&format!("digest of run {label}: {line}"));
                        last = line;
                    }
                }
            }
        })
    };
    let result = queue.build_blocking(
        digest_job::Job {
            run: run.clone(),
            options: context.options.clone(),
            budget,
        },
        cancel,
    );
    done.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    result
}

pub fn run(arguments: &Digest, context: &Context) -> Result<Reply, CliError> {
    let data = context.data_dir();
    let claim = OwnerClaim {
        kind: OwnerKind::Cli,
        socket: None,
    };
    let _lock = data_owner::lock_data_dir(data, &claim)
        .map_err(|message| CliError::from_engine_start(data, &message))?;
    signals::install();
    let budget = Budget {
        calls: arguments.max_calls.max(1),
        time: Duration::from_secs(arguments.max_seconds),
    };
    let runs: Vec<RunSummary> = match &arguments.run {
        Some(text) => vec![find_run(context, text)?],
        None => digest_job::pending(list_all_runs(context)?),
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let mut rows = Vec::new();
    for run in &runs {
        if cancel.load(Ordering::Relaxed) || signals::interrupted() {
            return Err(
                CliError::new(ErrorCode::Internal, "interrupted while building digests")
                    .with_exit(crate::exit::Exit::Interrupted),
            );
        }
        // A named run that has nothing to read says why, not "current".
        if arguments.run.is_some() && run.root_task_cookie == 0 {
            return Err(CliError::new(
                ErrorCode::PreconditionFailed,
                format!(
                    "run {} has no recorded program: there is nothing to digest",
                    run.id
                ),
            )
            .with_field("run"));
        }
        let built = build_one(context, run, budget, &cancel);
        if built.as_ref().err().is_some_and(|e| e == "cancelled") {
            return Err(
                CliError::new(ErrorCode::Internal, "interrupted while building digests")
                    .with_exit(crate::exit::Exit::Interrupted),
            );
        }
        let (state, reasons) = word(&built);
        rows.push(json!({
            "run_id": run.id, "vm_id": run.vm_id, "boot_id": run.boot_id,
            "state": state, "reasons": reasons,
        }));
    }
    let human = if rows.is_empty() {
        "no finished run is waiting for a digest\n".to_owned()
    } else {
        table(
            &["RUN", "DIGEST", "NOTES"],
            &rows
                .iter()
                .map(|row| {
                    vec![
                        row["run_id"].as_str().unwrap_or("").to_owned(),
                        row["state"].as_str().unwrap_or("").to_owned(),
                        row["reasons"]
                            .as_array()
                            .map(|r| {
                                r.iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join("; ")
                            })
                            .unwrap_or_default(),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    };
    Ok(Reply::value(json!({"runs": rows})).with_human(human))
}
