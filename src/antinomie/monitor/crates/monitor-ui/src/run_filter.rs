// SPDX-License-Identifier: GPL-3.0-only
//! Typed run-history fields share one registry for validation and completion.
use crate::query::{compile_table_with, Aliases, FieldSpec, RowValue};
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

/// Old spellings of Run History fields. They are not offered anywhere; a
/// filter that uses one is rewritten to the canonical field on the right.
pub(crate) const ALIASES: Aliases<'static> = Aliases {
    fields: &[
        ("id", "entry.id"),
        ("run.id", "entry.id"),
        ("name", "entry.name"),
        ("tags", "tag"),
        ("entry.tag", "tag"),
        ("path", "process.exe"),
        ("run.path", "process.exe"),
        ("entry.path", "process.exe"),
        ("args", "process.argv"),
        ("run.args", "process.argv"),
        ("cwd", "process.cwd"),
        ("pid", "process.pid"),
        ("process.tgid", "process.pid"),
        ("task", "process.cookie"),
        ("uid", "process.uid"),
        ("gid", "process.gid"),
        ("state", "run.state"),
        ("status", "run.state"),
        ("entry.state", "run.state"),
        ("run.tree_state", "run.state"),
        ("process.state", "run.state"),
        ("error", "run.error"),
        ("entry.time_ms", "run.started_ms"),
        ("analysis.available", "run.has_static"),
    ],
    value: old_value,
};

/// What older filters compared against: the saved state's Debug name, and
/// the root exit in lower case. Both now read as the Run History columns do.
fn old_value(field: &str, value: &str) -> Option<String> {
    match field {
        "run.state" => match value {
            "StopRequested" => Some("Stop requested".into()),
            "TerminalClosed" => Some("PTY closed".into()),
            "Finalized" => Some("Recording ended".into()),
            _ => None,
        },
        "run.root_exit" => {
            let (word, rest) = value.split_once(' ')?;
            let word = match word {
                "exit" => "Exit",
                "signal" => "Signal",
                _ => return None,
            };
            Some(format!("{word} {rest}"))
        }
        _ => None,
    }
}

pub(crate) fn compile(filter: &str, fields: &[FieldSpec<'_>]) -> crate::query::Compiled {
    compile_table_with(filter, fields, &ALIASES)
}

pub(crate) fn fields() -> Vec<FieldSpec<'static>> {
    vec![
        FieldSpec::text("entry.kind", "Evidence category"),
        FieldSpec::text("entry.id", "Recorded run identity"),
        FieldSpec::text("entry.name", "Annotation name"),
        FieldSpec::tags("tag", "Stored annotation tags"),
        FieldSpec::text("vm.id", "Recorded VM identity"),
        FieldSpec::text("boot.id", "Recorded boot identity"),
        FieldSpec::number("session.id", "Run session identity"),
        FieldSpec::text("process.exe", "Launched root executable"),
        FieldSpec::tags("process.argv", "Recorded launch arguments"),
        FieldSpec::text("process.cwd", "Launch working directory"),
        FieldSpec::number("process.pid", "Root process ID"),
        FieldSpec::number("process.cookie", "Boot-scoped root task cookie"),
        FieldSpec::number("process.uid", "Requested launch user ID"),
        FieldSpec::number("process.gid", "Requested launch group ID"),
        FieldSpec::text(
            "run.state",
            "Run state as the State column shows it, for example Recording ended",
        ),
        FieldSpec::text(
            "run.root_exit",
            "Root exit as the Root exit column shows it, for example Exit 0",
        ),
        FieldSpec::number(
            "root.exit_code",
            "Normal root exit code; missing for other outcomes",
        ),
        FieldSpec::number(
            "root.signal",
            "Root termination signal; missing on normal exit",
        ),
        FieldSpec::text("run.error", "Recording failure; missing on success"),
        FieldSpec::number(
            "run.started_ms",
            "Recorded start time; missing on legacy records",
        ),
        FieldSpec::number(
            "run.ended_ms",
            "Recorded tree completion time; missing until observed",
        ),
        FieldSpec::number("run.duration_ms", "Recorded elapsed wallclock time"),
        FieldSpec::number("run.child_count", "Observed total descendants"),
        FieldSpec::number("tree.live", "Authoritative living task count"),
        FieldSpec::number("tree.total", "Authoritative total task count"),
        FieldSpec::number("entry.size", "Saved extent in octets"),
        FieldSpec::boolean("entry.complete", "Evidence completeness"),
        FieldSpec::boolean("run.has_static", "Retained static-analysis report exists"),
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
        FieldSpec::boolean("terminal.eof", "Terminal stream has ended"),
        FieldSpec::boolean(
            "capture.network",
            "Run requested whole-tree network capture",
        ),
        FieldSpec::boolean(
            "capture.memory_on_exit",
            "Run requested VM RAM on tree exit",
        ),
        FieldSpec::boolean("capture.core_on_exit", "Run requested process core on exit"),
    ]
}

pub(crate) fn row(
    run: &RunSummary,
    annotation: Option<&Annotation>,
    status: &str,
    root_exit: impl Into<String>,
) -> Vec<(&'static str, RowValue)> {
    let name = annotation.map_or("", |annotation| annotation.name.as_str());
    let tags = annotation.map_or(&[][..], |annotation| annotation.tags.as_slice());
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
    vec![
        ("entry.kind", RowValue::Text("run".into())),
        ("entry.id", RowValue::Text(run.id.clone())),
        ("entry.name", name),
        ("tag", RowValue::List(tags.into())),
        ("vm.id", RowValue::Text(run.vm_id.clone())),
        ("boot.id", RowValue::Text(run.boot_id.clone())),
        ("session.id", RowValue::Number(run.session_id.into())),
        ("process.exe", RowValue::Text(run.request.path.clone())),
        ("process.argv", RowValue::List(run.request.args.clone())),
        ("process.cwd", RowValue::Text(run.request.cwd.clone())),
        ("process.pid", RowValue::Number(run.pid.into())),
        (
            "process.cookie",
            RowValue::Number(run.root_task_cookie.into()),
        ),
        ("process.uid", RowValue::Number(run.request.uid.into())),
        ("process.gid", RowValue::Number(run.request.gid.into())),
        ("run.state", RowValue::Text(status.into())),
        ("run.root_exit", RowValue::Text(root_exit.into())),
        ("root.exit_code", exit),
        ("root.signal", signal),
        (
            "run.error",
            run.recording_error
                .as_ref()
                .map_or(RowValue::Missing, |error| RowValue::Text(error.clone())),
        ),
        (
            "run.child_count",
            run.execution
                .as_ref()
                .map_or(RowValue::Missing, |execution| {
                    RowValue::Number(execution.total_task_count.saturating_sub(1).into())
                }),
        ),
        ("tree.live", live),
        ("tree.total", total),
        ("run.has_static", RowValue::Bool(run.analysis.is_some())),
        ("terminal.eof", RowValue::Bool(run.terminal_eof)),
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{ExecRequest, RunExecution, RunState};

    fn run(id: &str, pid: u32, state: RunState) -> RunSummary {
        let request = ExecRequest {
            path: format!("/bin/{id}"),
            args: vec![format!("--{id}")],
            cwd: format!("/work/{id}"),
            uid: pid,
            gid: pid + 1,
            ..ExecRequest::default()
        };
        RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: id.into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: u64::from(pid) + 1000,
            pid,
            request,
            directory: std::path::PathBuf::new(),
            terminal_eof: false,
            state,
            recording_error: Some(format!("failed {id}")),
            route: None,
            execution: Some(RunExecution {
                generation: 1,
                live_task_count: 0,
                pending_async_count: 0,
                flags: 0,
                root_wait_status: None,
                root_exit: Some(WaitStatus::Exited { code: 0 }),
                async_loss_count: 0,
                total_task_count: 3,
            }),
            analysis: None,
            notes: Vec::new(),
        }
    }

    fn matches(filter: &str, run: &RunSummary) -> bool {
        let compiled = compile(filter, &fields());
        assert!(compiled.error.is_none(), "{filter}: {:?}", compiled.error);
        let status = match run.state {
            RunState::Finalized => "Recording ended",
            RunState::TerminalClosed => "PTY closed",
            RunState::StopRequested => "Stop requested",
            _ => "Running",
        };
        let root = match &run.execution.as_ref().unwrap().root_exit {
            Some(WaitStatus::Exited { code }) => format!("Exit {code}"),
            Some(WaitStatus::Signaled {
                signal,
                core_dumped,
            }) => format!(
                "Signal {signal}{}",
                if *core_dumped { " (core)" } else { "" }
            ),
            None => "Unknown".into(),
        };
        compiled.keep_table(&row(run, None, status, root))
    }

    /// A filter on `field` that the first run satisfies and the second does not.
    fn clause(field: &str, value: &RowValue) -> Option<String> {
        match value {
            RowValue::Number(number) => Some(format!("{field} == {number}")),
            RowValue::Text(text) => Some(format!("{field} == \"{text}\"")),
            RowValue::List(items) => Some(format!("{field} contains \"{}\"", items.first()?)),
            RowValue::Bool(_) | RowValue::Missing => None,
        }
    }

    #[test]
    fn every_old_name_filters_the_same_runs_as_its_canonical_field() {
        let first = run("one", 42, RunState::Running);
        let second = run("two", 43, RunState::TerminalClosed);
        let values = row(&first, None, "Running", "Exit 0");
        let mut checked = 0;
        for (old, canonical) in ALIASES.fields {
            let Some((_, value)) = values.iter().find(|(name, _)| name == canonical) else {
                continue;
            };
            let Some(old_clause) = clause(old, value) else {
                continue;
            };
            let canonical_clause = clause(canonical, value).unwrap();
            for candidate in [&first, &second] {
                assert_eq!(
                    matches(&old_clause, candidate),
                    matches(&canonical_clause, candidate),
                    "{old} and {canonical}"
                );
            }
            // `args` joined the arguments into one text; it is the list now.
            assert!(matches(&old_clause, &first), "{old_clause}");
            assert!(!matches(&old_clause, &second), "{old_clause}");
            checked += 1;
        }
        assert!(checked >= 15, "only {checked} aliases were exercised");
    }

    #[test]
    fn old_names_are_hidden_and_every_field_has_a_value() {
        let names: Vec<_> = fields().iter().map(|field| field.name).collect();
        for (old, canonical) in ALIASES.fields {
            assert!(!names.contains(old), "{old} is offered");
            assert!(
                names.contains(canonical),
                "{canonical} is not a Run History field"
            );
        }
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len());
        let first = run("one", 42, RunState::Running);
        let values = row(&first, None, "Running", "Exit 0");
        for name in &names {
            let known = values.iter().any(|(field, _)| field == name)
                || name.starts_with("run.loss.")
                || matches!(
                    *name,
                    "run.started_ms"
                        | "run.ended_ms"
                        | "run.duration_ms"
                        | "run.has_core"
                        | "run.has_memory"
                        | "run.has_network"
                        | "entry.size"
                        | "entry.complete"
                );
            assert!(known, "{name} has no value in the row");
        }
    }

    #[test]
    fn state_filters_use_the_run_history_labels_and_keep_the_old_debug_names() {
        let ended = run("one", 42, RunState::Finalized);
        let closed = run("two", 43, RunState::TerminalClosed);
        let running = run("three", 44, RunState::Running);
        for filter in [
            "run.state == \"Recording ended\"",
            "state == \"Recording ended\"",
            "status == \"Recording ended\"",
            "process.state == \"Recording ended\"",
            "run.tree_state == \"Recording ended\"",
            "entry.state == \"Finalized\"",
            "state == \"Finalized\"",
            "run.state in {\"Finalized\", \"Stopped\"}",
        ] {
            assert!(matches(filter, &ended), "{filter}");
            assert!(!matches(filter, &closed), "{filter}");
            assert!(!matches(filter, &running), "{filter}");
        }
        assert!(matches("state == \"TerminalClosed\"", &closed));
        assert!(matches("run.state == \"PTY closed\"", &closed));
    }

    #[test]
    fn root_exit_reads_as_the_run_history_column_does() {
        let mut exited = run("one", 42, RunState::Finalized);
        let mut killed = run("two", 43, RunState::Finalized);
        killed.execution.as_mut().unwrap().root_exit = Some(WaitStatus::Signaled {
            signal: 9,
            core_dumped: true,
        });
        assert!(matches("run.root_exit == \"Exit 0\"", &exited));
        assert!(matches("run.root_exit == \"exit 0\"", &exited));
        assert!(matches("run.root_exit == \"Signal 9 (core)\"", &killed));
        assert!(!matches("run.root_exit == \"Exit 0\"", &killed));
        exited.execution.as_mut().unwrap().root_exit = None;
        assert!(matches("run.root_exit == \"Unknown\"", &exited));
    }

    #[test]
    fn the_placeholder_example_is_a_valid_run_filter() {
        let compiled = compile(
            "process.exe contains \"sample\" && run.has_static",
            &fields(),
        );
        assert!(compiled.error.is_none());
    }
}
