// SPDX-License-Identifier: GPL-3.0-only
//! What the report says of the run itself, read from the run's record
//! (`run.json`) the way the app reads it: the state in the Run line's words,
//! how the root program ended, the command, the route and the environment the
//! run was recorded on. The sample is the library sample the run recorded in
//! its request, not whatever the static analysis opened: a shell running a
//! one-liner is not the sample, and a library preloaded into it is named as
//! the library it is.
use super::*;
use antinomie_monitor_core::{
    report::{Fact, RunInfo, SampleInfo},
    RunSummary, WaitStatus,
};

/// Longest command the overview shows.
const COMMAND_CHARS: usize = 400;

/// The job with its run and sample facts read from the run's record. A
/// record that cannot be read leaves the job as it was.
pub(super) fn apply(job: &Job, scan: &ArchiveScan) -> Job {
    let mut job = job.clone();
    let Some(run) = read_run(&job.archive) else {
        return job;
    };
    let alive = scan
        .process
        .iter()
        .filter(|node| node.state == "exit not recorded")
        .map(|node| node.pid)
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64;
    job.run = run_info(&job.run, &run, scan.ended_ms, alive, job.now_ms);
    job.sample = sample(&job, &run);
    // The command is the run's own account when the sample is not what was
    // started: no library sample, or a library preloaded into another program.
    if job
        .sample
        .as_ref()
        .is_none_or(|sample| !sample.role.is_empty())
    {
        job.run.command = command(&run);
    }
    job
}

fn read_run(archive: &Path) -> Option<RunSummary> {
    serde_json::from_slice(&std::fs::read(archive.join("run.json")).ok()?).ok()
}

/// "exit 0" or "signal 11 (SIGSEGV)".
pub(super) fn exit_text(status: &WaitStatus) -> String {
    match status {
        WaitStatus::Exited { code } => format!("exit {code}"),
        WaitStatus::Signaled { signal, .. } => {
            format!(
                "signal {signal} ({})",
                super::super::run_end::signal_name(*signal)
            )
        }
    }
}

/// The run block of the report.
/// Also the entry for a run that never started (its short report calls this
/// with the run's record): the state then reads "Not started: <reason>".
pub(super) fn run_info(
    base: &RunInfo,
    run: &RunSummary,
    ended_ms: Option<u64>,
    alive: u64,
    now_ms: u64,
) -> RunInfo {
    let root = run
        .execution
        .as_ref()
        .and_then(|status| status.root_exit.as_ref());
    let end = if run.state.is_live() {
        None
    } else {
        run.stopped_at_ms.or(ended_ms)
    };
    RunInfo {
        started_ms: run.started_ms.or(base.started_ms),
        finished: !run.state.is_live(),
        state: if run.state == antinomie_monitor_core::RunState::FailedToStart {
            // A run that never started: the reason is the whole account.
            format!(
                "Not started: {}",
                run.recording_error
                    .as_deref()
                    .unwrap_or("no reason was recorded")
            )
        } else {
            crate::run_state_line::describe(run, now_ms, ended_ms, Some(alive))
        },
        exit: root.map(exit_text).unwrap_or_default(),
        stopped_by_user: run.stopped_by_user,
        ended_ms: if run.state.is_live() { None } else { ended_ms },
        duration_ms: run.started_ms.zip(end).map(|(s, e)| e.saturating_sub(s)),
        route: run
            .route
            .as_ref()
            .map(|route| route.label.clone())
            .unwrap_or_default(),
        environment: environment(run),
        ..base.clone()
    }
}

/// The program and arguments the run started, clipped.
fn command(run: &RunSummary) -> String {
    let mut text = run.request.path.clone();
    for arg in &run.request.args {
        text.push(' ');
        if arg.chars().any(|c| c.is_whitespace() || c == '\'') {
            text.push_str(&format!("'{}'", arg.replace('\'', "'\\''")));
        } else {
            text.push_str(arg);
        }
    }
    let text: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().count() > COMMAND_CHARS {
        let cut: String = text.chars().take(COMMAND_CHARS).collect();
        format!("{cut}...")
    } else {
        text
    }
}

/// The sample of the run: the recorded library sample, or the library an
/// `LD_PRELOAD` names when that is a library sample; otherwise none.
fn sample(job: &Job, run: &RunSummary) -> Option<SampleInfo> {
    if let Some(recorded) = run
        .request
        .sample
        .as_ref()
        .filter(|sample| sample.sha256.len() == 64)
    {
        let size = job
            .sample
            .as_ref()
            .filter(|known| known.sha256 == recorded.sha256)
            .and_then(|known| known.size);
        return Some(SampleInfo {
            name: recorded.name.clone(),
            sha256: recorded.sha256.clone(),
            size,
            role: String::new(),
        });
    }
    // A program of the base image (a shell running a one-liner) is not the
    // sample, whatever the static analysis opened; any other file is the
    // sample the run was started from, library or not.
    let base = [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/lib/",
    ]
    .iter()
    .any(|dir| run.request.path.starts_with(dir));
    let fallback = || job.sample.clone().filter(|_| !base);
    // `L=$(ls /tmp/40b5127c-*)`: the file is named by the library's own
    // name, which starts with the first eight digits of its hash.
    let Some(data_dir) = job.data_dir.as_deref() else {
        return fallback();
    };
    let text = std::iter::once(run.request.path.as_str())
        .chain(run.request.args.iter().map(String::as_str))
        .chain(run.request.env.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    if !text.contains("LD_PRELOAD") {
        return fallback();
    }
    let prefixes: Vec<String> = text
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .filter(|word| word.len() >= 8 && word[..8].bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|word| word[..8].to_ascii_lowercase())
        .collect();
    let Ok(library) = antinomie_monitor_core::samples::Library::open(data_dir) else {
        return fallback();
    };
    let Ok(all) = library.list() else {
        return fallback();
    };
    let found: Vec<_> = all
        .iter()
        .filter(|record| {
            prefixes
                .iter()
                .any(|prefix| record.sha256.starts_with(prefix))
        })
        .collect();
    let [record] = found.as_slice() else {
        return fallback();
    };
    Some(SampleInfo {
        name: record.name.clone(),
        sha256: record.sha256.clone(),
        size: Some(record.size),
        role: "preloaded library".into(),
    })
}

/// [`sample`] and [`command`] for the re-export check.
#[cfg(test)]
pub(super) fn sample_for_test(job: &Job, run: &RunSummary) -> Option<SampleInfo> {
    sample(job, run)
}

#[cfg(test)]
pub(super) fn command_for_test(run: &RunSummary) -> String {
    command(run)
}

/// What the run was recorded on, from the run record.
fn environment(run: &RunSummary) -> Vec<Fact> {
    let mut out = Vec::new();
    if let Some(env) = &run.environment {
        let mut base = env.base_name.clone();
        if let Some(revision) = env.base_revision {
            base.push_str(&format!(" rev {revision}"));
        }
        out.push(Fact::new("Base image", base));
        let mut kernel = env.kernel_release.clone();
        if let Some(revision) = env.kernel_revision {
            kernel.push_str(&format!(" (patch revision {revision})"));
        }
        out.push(Fact::new("Kernel", kernel));
        out.push(Fact::new(
            "Virtual machine",
            format!(
                "{}: {} CPU, {} MiB RAM, {} network",
                env.vm_name, env.cpus, env.ram_mib, env.network
            ),
        ));
        out.push(Fact::new("Stealth profile", env.stealth.clone()));
        if !env.rule_packs.is_empty() {
            // "name version": the version is often a long snapshot id.
            let packs: Vec<String> = env
                .rule_packs
                .iter()
                .map(|pack| match pack.rsplit_once(' ') {
                    Some((name, version)) if version.chars().count() > 16 => {
                        format!("{name} {}...", version.chars().take(13).collect::<String>())
                    }
                    _ => pack.clone(),
                })
                .collect();
            out.push(Fact::new("Rule packs", packs.join("; ")));
        }
        if !env.tools.is_empty() {
            out.push(Fact::new("Tools", env.tools.join("; ")));
        }
    }
    if let Some(route) = &run.route {
        out.push(Fact::new("Network route", route.label.clone()));
    }
    if let Some(machine) = &run.machine {
        if !machine.machine.is_empty() {
            out.push(Fact::new("Guest looked like", machine.machine.clone()));
        }
    }
    out.retain(|fact| !fact.value.trim().is_empty());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{ExecRequest, RunExecution, RunState};

    fn record(state: RunState, root: Option<WaitStatus>) -> RunSummary {
        let mut run = crate::run_link::test_run("r1", "/bin/sh");
        run.state = state;
        run.started_ms = Some(1_000_000);
        run.execution = Some(RunExecution {
            generation: 1,
            live_task_count: 0,
            pending_async_count: 0,
            flags: 0,
            root_wait_status: None,
            root_exit: root,
            async_loss_count: 0,
            total_task_count: 2,
        });
        run
    }

    #[test]
    fn a_run_the_person_stopped_says_so_with_its_time_and_exit() {
        let mut run = record(RunState::Stopped, Some(WaitStatus::Exited { code: 0 }));
        run.stopped_by_user = true;
        run.stopped_at_ms = Some(1_000_000 + 385_000);
        let info = run_info(&RunInfo::default(), &run, Some(1_000_000 + 386_000), 0, 0);
        assert_eq!(info.state, "Stopped by you at 6 min 25 s · root exited 0");
        assert_eq!(info.exit, "exit 0");
        assert!(info.stopped_by_user && info.finished);
        assert_eq!(info.duration_ms, Some(385_000));
        assert_eq!(info.ended_ms, Some(1_386_000));
    }

    #[test]
    fn a_crash_and_a_failed_exit_are_not_just_finished() {
        let run = record(
            RunState::Finished,
            Some(WaitStatus::Signaled {
                signal: 11,
                core_dumped: false,
            }),
        );
        let info = run_info(&RunInfo::default(), &run, Some(1_000_160), 0, 0);
        assert_eq!(info.exit, "signal 11 (SIGSEGV)");
        assert!(info.state.contains("signal 11"), "{}", info.state);
        let run = record(RunState::Finished, Some(WaitStatus::Exited { code: 255 }));
        let info = run_info(&RunInfo::default(), &run, Some(1_080_000), 0, 0);
        assert_eq!(info.state, "Ran for 1 min 20 s · exit 255");
    }

    #[test]
    fn a_run_that_never_started_says_why() {
        let mut run = record(RunState::FailedToStart, None);
        run.recording_error = Some("Tor route not ready".into());
        let info = run_info(&RunInfo::default(), &run, None, 0, 0);
        assert_eq!(info.state, "Not started: Tor route not ready");
    }

    #[test]
    fn a_vm_stop_with_the_tree_alive_reads_as_cut_short() {
        let mut run = record(RunState::Finalized, None);
        run.execution.as_mut().unwrap().live_task_count = 2;
        let info = run_info(&RunInfo::default(), &run, Some(1_060_000), 2, 0);
        assert!(info.state.starts_with("Ended by VM stop"), "{}", info.state);
    }

    #[test]
    fn a_shell_one_liner_is_a_command() {
        let mut run = record(RunState::Finished, Some(WaitStatus::Exited { code: 0 }));
        run.request = ExecRequest {
            path: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "L=$(ls /tmp/40b5127c-* | head -n 1); export LD_PRELOAD=$L; ls".into(),
            ],
            ..ExecRequest::default()
        };
        assert!(command(&run).starts_with("/bin/sh -c '"));
        assert!(command(&run).contains("LD_PRELOAD=$L"));
    }
}
