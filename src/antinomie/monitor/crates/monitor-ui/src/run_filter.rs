// SPDX-License-Identifier: MIT
//! Typed run-history fields share one registry for validation and completion.
use crate::query::{FieldSpec, RowValue};
use antinomie_monitor_core::recording::RunFilterFacts;
use antinomie_monitor_core::{annotations::Annotation, RunSummary, WaitStatus};
use eframe::egui;
use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

type FactsBatch = Vec<(String, Result<RunFilterFacts, String>)>;

#[derive(Default)]
struct FactsCache {
    values: BTreeMap<String, Result<RunFilterFacts, String>>,
    pending: Option<mpsc::Receiver<FactsBatch>>,
    refreshed: Option<Instant>,
}

/// Refresh sidecars on one background worker; painting reads only cached values.
pub(crate) fn refresh_facts(ui: &egui::Ui, runs: &[RunSummary]) {
    let key = egui::Id::new("run-filter-facts");
    let state = ui.ctx().data_mut(|data| {
        data.get_temp_mut_or_default::<Arc<Mutex<FactsCache>>>(key)
            .clone()
    });
    let Ok(mut cache) = state.lock() else {
        return;
    };
    if let Some(result) = cache
        .pending
        .as_ref()
        .and_then(|receiver| receiver.try_recv().ok())
    {
        cache.pending = None;
        for (id, facts) in result {
            cache.values.insert(id, facts);
        }
        if cache.values.len() > 2048 {
            cache
                .values
                .retain(|id, _| runs.iter().any(|run| &run.id == id));
        }
    }
    let missing = runs.iter().any(|run| !cache.values.contains_key(&run.id));
    if cache.pending.is_some()
        || (!missing
            && cache
                .refreshed
                .is_some_and(|last| last.elapsed() < Duration::from_secs(5)))
    {
        return;
    }
    let identities: Vec<_> = runs
        .iter()
        .take(1024)
        .map(|run| {
            (
                run.id.clone(),
                run.vm_id.clone(),
                run.boot_id.clone(),
                run.directory.clone(),
            )
        })
        .collect();
    let (sender, receiver) = mpsc::sync_channel(1);
    let context = ui.ctx().clone();
    match std::thread::Builder::new()
        .name("run-metadata".into())
        .spawn(move || {
            let rows = identities
                .into_iter()
                .map(|(id, vm, boot, directory)| {
                    let result = antinomie_monitor_core::recording::run_filter_facts(
                        &directory, &id, &vm, &boot,
                    );
                    (id, result)
                })
                .collect();
            let _ = sender.send(rows);
            context.request_repaint();
        }) {
        Ok(worker) => {
            drop(worker);
            cache.pending = Some(receiver);
            cache.refreshed = Some(Instant::now());
        }
        Err(error) => {
            cache.refreshed = Some(Instant::now());
            for run in runs {
                cache
                    .values
                    .insert(run.id.clone(), Err(format!("run metadata worker: {error}")));
            }
        }
    }
}

pub(crate) fn append_facts(
    ui: &egui::Ui,
    run: &RunSummary,
    row: &mut Vec<(&'static str, RowValue)>,
) {
    let state = ui
        .ctx()
        .data(|data| data.get_temp::<Arc<Mutex<FactsCache>>>(egui::Id::new("run-filter-facts")));
    let facts = state.and_then(|state| {
        state
            .lock()
            .ok()
            .and_then(|cache| cache.values.get(&run.id).cloned())
    });
    let facts = match facts {
        Some(Ok(facts)) => facts,
        _ => return,
    };
    let number = |value: Option<u64>| {
        value.map_or(RowValue::Missing, |value| RowValue::Number(value.into()))
    };
    let boolean = |value: Option<bool>| value.map_or(RowValue::Missing, RowValue::Bool);
    row.extend([
        ("run.started_ms", number(facts.started_ms)),
        ("entry.time_ms", number(facts.started_ms)),
        ("run.ended_ms", number(facts.ended_ms)),
        (
            "run.duration_ms",
            number(
                facts
                    .started_ms
                    .zip(facts.ended_ms)
                    .and_then(|(start, end)| end.checked_sub(start)),
            ),
        ),
        ("entry.size", number(facts.saved_size)),
        ("entry.complete", boolean(facts.complete)),
        ("run.has_core", boolean(facts.has_core)),
        ("run.has_memory", boolean(facts.has_memory)),
        ("run.has_network", boolean(facts.has_network)),
        ("run.loss.transport", number(facts.transport_loss)),
        ("run.loss.ui", number(facts.ui_loss)),
        ("run.loss.storage", number(facts.storage_loss)),
    ]);
}

pub(crate) fn fields() -> Vec<FieldSpec<'static>> {
    let mut fields = crate::query::LABEL_FIELDS.to_vec();
    fields.extend([
        FieldSpec::text("run.path", "Launched executable"),
        FieldSpec::tags("run.args", "Recorded argv elements"),
        FieldSpec::number(
            "run.started_ms",
            "Recorded start time; missing on legacy records",
        ),
        FieldSpec::number(
            "run.ended_ms",
            "Recorded tree completion time; missing until observed",
        ),
        FieldSpec::number("run.duration_ms", "Recorded elapsed wallclock time"),
        FieldSpec::text(
            "run.root_exit",
            "Root exit outcome separate from tree state",
        ),
        FieldSpec::text("run.tree_state", "Authoritative process-tree status"),
        FieldSpec::number("run.child_count", "Observed total descendants"),
        FieldSpec::boolean("run.has_static", "Retained static report exists"),
        FieldSpec::boolean("run.has_core", "A retained core artifact exists"),
        FieldSpec::boolean("run.has_memory", "A retained memory artifact exists"),
        FieldSpec::boolean("run.has_network", "Retained network artifacts exist"),
        FieldSpec::number(
            "run.loss.transport",
            "Boot-scope transport loss at run finalization",
        ),
        FieldSpec::number("run.loss.ui", "Boot-scope UI loss at run finalization"),
        FieldSpec::number(
            "run.loss.storage",
            "Boot-scope storage loss at run finalization",
        ),
        FieldSpec::number("process.cookie", "Boot-scoped root process cookie"),
        FieldSpec::number("process.pid", "Root process ID"),
        FieldSpec::number("process.tgid", "Root thread-group ID"),
        FieldSpec::number("process.uid", "Requested launch user ID"),
        FieldSpec::number("process.gid", "Requested launch group ID"),
        FieldSpec::text("process.exe", "Launched root executable"),
        FieldSpec::tags("process.argv", "Recorded launch arguments"),
        FieldSpec::text("process.state", "Authoritative root tree state"),
        FieldSpec::text("id", "Recorded run identity"),
        FieldSpec::text("name", "Annotation name"),
        FieldSpec::text("path", "Launched executable"),
        FieldSpec::text("args", "Launch arguments"),
        FieldSpec::text("cwd", "Launch working directory"),
        FieldSpec::text("state", "Saved recording state"),
        FieldSpec::text("status", "Process tree status"),
        FieldSpec::text("error", "Recording failure; missing on success"),
        FieldSpec::number("pid", "Launched root process ID"),
        FieldSpec::number("uid", "Launch user ID"),
        FieldSpec::number("gid", "Launch group ID"),
        FieldSpec::number("task", "Boot-scoped root task cookie"),
        FieldSpec::number("session.id", "Run session identity"),
        FieldSpec::number("tree.live", "Authoritative living task count"),
        FieldSpec::number("tree.total", "Authoritative total task count"),
        FieldSpec::number(
            "root.exit_code",
            "Normal root exit code; missing for other outcomes",
        ),
        FieldSpec::number(
            "root.signal",
            "Root termination signal; missing on normal exit",
        ),
        FieldSpec::boolean("terminal.eof", "Terminal stream has ended"),
        FieldSpec::boolean(
            "analysis.available",
            "Retained static-analysis report exists",
        ),
        FieldSpec::boolean(
            "capture.network",
            "Run requested whole-tree network capture",
        ),
        FieldSpec::boolean(
            "capture.memory_on_exit",
            "Run requested VM RAM on tree exit",
        ),
        FieldSpec::boolean("capture.core_on_exit", "Run requested process core on exit"),
    ]);
    fields
}

pub(crate) fn row(
    run: &RunSummary,
    annotation: Option<&Annotation>,
    status: &str,
) -> Vec<(&'static str, RowValue)> {
    let name = annotation.map_or("", |annotation| annotation.name.as_str());
    let tags = annotation.map_or(&[][..], |annotation| annotation.tags.as_slice());
    let mut row = crate::query::label_row(&run.id, name, &run.request.path, tags);
    let state = format!("{:?}", run.state);
    let name = if name.is_empty() {
        RowValue::Missing
    } else {
        RowValue::Text(name.into())
    };
    let live = run
        .execution
        .as_ref()
        .map_or(RowValue::Missing, |execution| {
            RowValue::Number(execution.live_task_count.into())
        });
    let total = run
        .execution
        .as_ref()
        .map_or(RowValue::Missing, |execution| {
            RowValue::Number(execution.total_task_count.into())
        });
    let (exit, signal) = match run
        .execution
        .as_ref()
        .and_then(|execution| execution.root_exit.as_ref())
    {
        Some(WaitStatus::Exited { code }) => (RowValue::Number((*code).into()), RowValue::Missing),
        Some(WaitStatus::Signaled { signal, .. }) => {
            (RowValue::Missing, RowValue::Number((*signal).into()))
        }
        None => (RowValue::Missing, RowValue::Missing),
    };
    row.extend([
        ("run.path", RowValue::Text(run.request.path.clone())),
        ("run.args", RowValue::List(run.request.args.clone())),
        ("run.tree_state", RowValue::Text(status.into())),
        (
            "run.root_exit",
            run.execution
                .as_ref()
                .and_then(|execution| execution.root_exit.as_ref())
                .map_or(RowValue::Missing, |outcome| {
                    RowValue::Text(match outcome {
                        WaitStatus::Exited { code } => format!("exit {code}"),
                        WaitStatus::Signaled { signal, .. } => format!("signal {signal}"),
                    })
                }),
        ),
        (
            "run.child_count",
            run.execution
                .as_ref()
                .map_or(RowValue::Missing, |execution| {
                    RowValue::Number(execution.total_task_count.saturating_sub(1).into())
                }),
        ),
        ("run.has_static", RowValue::Bool(run.analysis.is_some())),
        (
            "process.cookie",
            RowValue::Number(run.root_task_cookie.into()),
        ),
        ("process.pid", RowValue::Number(run.pid.into())),
        ("process.tgid", RowValue::Number(run.pid.into())),
        ("process.uid", RowValue::Number(run.request.uid.into())),
        ("process.gid", RowValue::Number(run.request.gid.into())),
        ("process.exe", RowValue::Text(run.request.path.clone())),
        ("process.argv", RowValue::List(run.request.args.clone())),
        ("process.state", RowValue::Text(status.into())),
        ("entry.kind", RowValue::Text("run".into())),
        ("id", RowValue::Text(run.id.clone())),
        ("name", name),
        ("path", RowValue::Text(run.request.path.clone())),
        ("args", RowValue::Text(run.request.args.join(" "))),
        ("cwd", RowValue::Text(run.request.cwd.clone())),
        ("entry.state", RowValue::Text(state.clone())),
        ("state", RowValue::Text(state)),
        ("status", RowValue::Text(status.into())),
        (
            "error",
            run.recording_error
                .as_ref()
                .map_or(RowValue::Missing, |error| RowValue::Text(error.clone())),
        ),
        ("vm.id", RowValue::Text(run.vm_id.clone())),
        ("boot.id", RowValue::Text(run.boot_id.clone())),
        ("run.id", RowValue::Text(run.id.clone())),
        ("pid", RowValue::Number(run.pid.into())),
        ("uid", RowValue::Number(run.request.uid.into())),
        ("gid", RowValue::Number(run.request.gid.into())),
        ("task", RowValue::Number(run.root_task_cookie.into())),
        ("session.id", RowValue::Number(run.session_id.into())),
        ("tree.live", live),
        ("tree.total", total),
        ("root.exit_code", exit),
        ("root.signal", signal),
        ("terminal.eof", RowValue::Bool(run.terminal_eof)),
        ("analysis.available", RowValue::Bool(run.analysis.is_some())),
        (
            "capture.network",
            RowValue::Bool(run.request.capture_network),
        ),
        (
            "capture.memory_on_exit",
            RowValue::Bool(run.request.memory_dump_on_exit),
        ),
        (
            "capture.core_on_exit",
            RowValue::Bool(run.request.core_dump_on_exit),
        ),
    ]);
    row
}
