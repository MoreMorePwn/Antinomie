// SPDX-License-Identifier: GPL-3.0-only
//! `run exec SAMPLE` (design 3.4.3): upload one library sample into a VM, run it,
//! and wait until its recording is complete and settled. The low-level form of
//! what an Auto job does: no revert, no triage, no report. It is for debugging
//! a lane and for trying a program in a VM from a script.
//!
//! The work is the service crate's run waiter ([`Waiter::exec`]); this file is
//! the grammar, the request, the event lines and the result.
use super::{
    analyze::parse_checks,
    library::{library_error, open_existing, open_for_write, parse_sha256},
    machine::{find_vm, vm_value},
    run_read,
};
use crate::{
    context::Context,
    engine::{DirectEngine, wait_error},
    error::{CliError, ErrorCode},
    exit::Exit,
    output::{Reply, block},
};
use antinomie_monitor_core::{
    AnalysisSelection, Command, ExecRequest, RunIn, RunSummary, Snapshot, WaitStatus,
    dump_trigger::DumpTrigger,
    route::RouteKind,
    samples::{NewOrigin, NewSample, SampleRecord, SampleRef},
};
use antinomie_service::{
    api::{
        event::{Event, EventBody, EventScope},
        failure::Failure,
        job::Outcome,
    },
    config::policy::{TriggerKind, TriggerSetting, trigger_plan},
    waiter::{BOOT_WAIT, EndReason, RunPlan, RunReport, load_artifacts, trigger::TriggerReport},
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Subcommand, Debug)]
pub enum Run {
    /// Upload a library sample into a VM, run it and wait for a settled recording.
    Exec(Exec),
    /// List the recorded runs of the data directory; no engine lock needed.
    /// Asks the daemon when one answers.
    List(run_read::List),
    /// Show one run: its state, phase and artifacts; `--summary` adds the
    /// Triage summary. No engine lock needed. Asks the daemon when one answers.
    Show(run_read::Show),
    /// Write a run's recording as NDJSON and evidence files into --out. No
    /// engine lock needed. Asks the daemon when one answers; the files are
    /// written by this command, never by the daemon.
    Export(run_read::Export),
}

#[derive(Args, Debug)]
pub struct Exec {
    /// The sample: its SHA-256 (see `sample list`), or a file, which is added
    /// to the library first.
    pub sample: String,
    /// The VM; optional when exactly one exists.
    #[arg(long, value_name = "ID")]
    pub vm: Option<String>,
    /// Boot the VM when it is stopped (otherwise a stopped VM is refused).
    /// A Debian guest is given the boot wait before the program starts;
    /// under TCG every wait is stretched by the TCG multiplier (see the
    /// global `--boot-wait` and `--tcg-multiplier`).
    #[arg(long)]
    pub start: bool,
    /// Arguments for the program. More can follow `--`.
    #[arg(long, num_args = 1.., value_name = "ARG")]
    pub args: Vec<String>,
    /// Environment for the program, as K=V; repeat for several. Without a PATH,
    /// the usual one is set.
    #[arg(long = "env", value_name = "K=V")]
    pub env: Vec<String>,
    /// Treat the sample as a shared library: upload it, then run PROGRAM (a path
    /// in the guest) with `LD_PRELOAD` set to the uploaded library, instead of
    /// running the sample itself. The run is linked to the library sample.
    #[arg(long = "load-into", value_name = "PROGRAM")]
    pub load_into: Option<String>,
    /// Who runs it: `user` (UID 1000, the default), `root`, or UID:GID.
    #[arg(long = "as", default_value = "user", value_name = "WHO")]
    pub who: String,
    /// Where the program's network traffic goes on a routed VM: drop,
    /// internet, inet_sim, tor, vpn or socks5 (default: the VM's setting).
    #[arg(long, value_name = "ROUTE")]
    pub route: Option<String>,
    /// Seconds the program may run before it is told to stop.
    #[arg(long, default_value_t = 300, value_name = "S")]
    pub timeout_run: u64,
    /// Record the VM's network traffic for the run.
    #[arg(long)]
    pub net_capture: bool,
    /// Take the VM's memory when the program's tree has ended.
    #[arg(long)]
    pub memory_dump: bool,
    /// Take a core of the program before its address space exits.
    #[arg(long)]
    pub core_dump: bool,
    /// Take a dump while the program runs, when the live Triage rules match
    /// at this tier or above (low, medium or high; default off). What it takes
    /// is --dump-kind. The program is not stopped. The result's `triggers`
    /// says what fired (rule, tier, dump state and path) or that it was armed
    /// and nothing matched. Needs a revision-16 base for a core.
    #[arg(long = "dump-trigger", value_name = "TIER")]
    pub dump_trigger: Option<String>,
    /// What --dump-trigger takes: core (the process that made the call, the
    /// default), memory (the VM's RAM) or both. Bounded by the core budget
    /// and the memory cap of the UI's defaults.
    #[arg(long = "dump-kind", value_name = "KIND", requires = "dump_trigger")]
    pub dump_kind: Option<String>,
    /// Run the guest-side static analysis too, with these checks (comma
    /// separated; see `analyze --help`).
    #[arg(long = "static", value_delimiter = ',', value_name = "CHECKS")]
    pub static_checks: Vec<String>,
    /// Wait for the result. Always on in direct mode: leaving would stop the VM.
    #[arg(long)]
    pub wait: bool,
    /// Print the progress as it happens, one event (design 5.5) per line, then
    /// the result; implies `-o ndjson`.
    #[arg(long)]
    pub events: bool,
    /// More arguments for the program, after `--`.
    #[arg(last = true, value_name = "ARG")]
    pub trailing: Vec<String>,
}

impl Run {
    pub fn streams_events(&self) -> bool {
        match self {
            Run::Exec(exec) => exec.events,
            Run::List(_) | Run::Show(_) | Run::Export(_) => false,
        }
    }
}

pub fn run(command: &Run, context: &Context) -> Result<Reply, CliError> {
    match command {
        Run::Exec(arguments) => exec(arguments, context),
        Run::List(arguments) => run_read::list(arguments, context),
        Run::Show(arguments) => run_read::show(arguments, context),
        Run::Export(arguments) => run_read::export(arguments, context),
    }
}

/// Who runs the program: `user` is the guest account, 1000.
pub fn parse_identity(text: &str) -> Result<(u32, u32), CliError> {
    match text {
        "user" => Ok((1000, 1000)),
        "root" => Ok((0, 0)),
        other => {
            let parsed = other
                .split_once(':')
                .and_then(|(uid, gid)| Some((uid.parse::<u32>().ok()?, gid.parse::<u32>().ok()?)));
            parsed.ok_or_else(|| {
                CliError::invalid(format!(
                    "{other:?} is not user, root or UID:GID (two numbers)"
                ))
                .with_field("as")
            })
        }
    }
}

pub fn parse_route(text: &str) -> Result<RouteKind, CliError> {
    serde_json::from_value(Value::String(text.to_ascii_lowercase().replace('-', "_"))).map_err(
        |_| {
            CliError::invalid(format!(
                "unknown route {text:?}; use drop, internet, inet_sim, tor, vpn or socks5"
            ))
            .with_field("route")
        },
    )
}

/// The launch the flags ask for. `path` and `sample` are filled in by the waiter.
pub fn request_for(arguments: &Exec) -> Result<ExecRequest, CliError> {
    let (uid, gid) = parse_identity(&arguments.who)?;
    let mut env = arguments.env.clone();
    for item in &env {
        if !item.contains('=') || item.starts_with('=') {
            return Err(CliError::invalid(format!("{item:?} is not K=V")).with_field("env"));
        }
    }
    if let Some(program) = &arguments.load_into
        && !program.starts_with('/')
    {
        return Err(CliError::invalid(format!(
            "{program:?} is not an absolute path in the guest (for example /bin/sh)"
        ))
        .with_field("load-into"));
    }
    if !env.iter().any(|item| item.starts_with("PATH=")) {
        env.push("PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into());
    }
    let analysis = if arguments.static_checks.is_empty() {
        AnalysisSelection::default()
    } else {
        AnalysisSelection {
            enabled: true,
            checks: parse_checks(&arguments.static_checks)?,
            ..AnalysisSelection::default()
        }
    };
    let dump_trigger = trigger_for(arguments)?;
    let mut args = arguments.args.clone();
    args.extend(arguments.trailing.iter().cloned());
    let request = ExecRequest {
        path: "/tmp/placeholder".into(),
        args,
        cwd: "/tmp".into(),
        env,
        uid,
        gid,
        analysis,
        run_in: RunIn::AppTerminal,
        capture_network: arguments.net_capture,
        memory_dump_on_exit: arguments.memory_dump,
        core_dump_on_exit: arguments.core_dump,
        route: arguments.route.as_deref().map(parse_route).transpose()?,
        core_max_size: dump_trigger
            .as_ref()
            .is_some_and(|plan| plan.core)
            .then_some(DEFAULT_TRIGGER_CORE_MIB << 20),
        core_timeout_ms: dump_trigger
            .as_ref()
            .is_some_and(|plan| plan.core)
            .then_some(antinomie_service::stages::plan::CORE_TIMEOUT_MS),
        dump_trigger,
        ..ExecRequest::default()
    };
    request.validate().map_err(CliError::invalid)?;
    Ok(request)
}

/// The core budget of a trigger core, the policy default (`core_max_mib`).
const DEFAULT_TRIGGER_CORE_MIB: u32 = 64;

/// The dump trigger the flags ask for; `None` (off) without `--dump-trigger`
/// or with `--dump-trigger off`.
pub fn trigger_for(arguments: &Exec) -> Result<Option<DumpTrigger>, CliError> {
    let Some(text) = arguments.dump_trigger.as_deref() else {
        return Ok(None);
    };
    let setting = TriggerSetting::parse(text).ok_or_else(|| {
        CliError::invalid(format!(
            "{text:?} is not a dump trigger tier; use {}",
            TriggerSetting::NAMES
        ))
        .with_field("dump-trigger")
    })?;
    let kind = match arguments.dump_kind.as_deref() {
        None => TriggerKind::default(),
        Some(text) => TriggerKind::parse(text).ok_or_else(|| {
            CliError::invalid(format!(
                "{text:?} is not a dump kind; use {}",
                TriggerKind::NAMES
            ))
            .with_field("dump-kind")
        })?,
    };
    Ok(trigger_plan(setting, kind))
}

/// The library record the argument names: a SHA-256, or a file added now.
fn resolve_sample(text: &str, data_dir: &Path) -> Result<SampleRecord, CliError> {
    if let Ok(sha256) = parse_sha256(text) {
        let library = open_existing(data_dir)?.ok_or_else(|| {
            CliError::not_found(format!("the sample {sha256} is not in the library"))
                .with_field("sample")
        })?;
        return library.get(&sha256).map_err(library_error)?.ok_or_else(|| {
            CliError::not_found(format!("the sample {sha256} is not in the library"))
                .with_field("sample")
        });
    }
    let path = PathBuf::from(text);
    let path = std::fs::canonicalize(&path)
        .map_err(|error| CliError::io(&path, &error).with_field("sample"))?;
    if !path.is_file() {
        return Err(
            CliError::invalid(format!("{} is not a regular file", path.display()))
                .with_field("sample"),
        );
    }
    let mut library = open_for_write(data_dir)?;
    let added = library
        .add_file(
            &path,
            NewSample {
                origin: NewOrigin::default(),
                ..Default::default()
            },
            false,
        )
        .map_err(|message| CliError::invalid(message).with_field("sample"))?;
    library
        .get(&added.sha256)
        .map_err(library_error)?
        .ok_or_else(|| CliError::internal("the sample was added but cannot be read back"))
}

fn exec(arguments: &Exec, context: &Context) -> Result<Reply, CliError> {
    let request = request_for(arguments)?;
    let record = resolve_sample(&arguments.sample, context.data_dir())?;
    if record.removed_ms.is_some() {
        return Err(CliError::new(
            ErrorCode::PreconditionFailed,
            "the sample's archive was removed from the library; add the file again",
        )
        .with_field("sample"));
    }
    let mut engine = DirectEngine::start(context)?;
    let outcome = exec_on(arguments, context, &mut engine, request, &record);
    engine.finish();
    outcome
}

fn pick_vm(snapshot: &Snapshot, key: Option<&str>) -> Result<String, CliError> {
    match key {
        Some(key) => Ok(find_vm(snapshot, key)?.id.clone()),
        None => match snapshot.vms.as_slice() {
            [only] => Ok(only.id.clone()),
            [] => Err(
                CliError::not_found("there is no VM; create one with `vm create`").with_field("vm"),
            ),
            _ => Err(CliError::invalid("several VMs exist; name one with --vm").with_field("vm")),
        },
    }
}

fn exec_on(
    arguments: &Exec,
    context: &Context,
    engine: &mut DirectEngine,
    request: ExecRequest,
    record: &SampleRecord,
) -> Result<Reply, CliError> {
    let vm_id = pick_vm(engine.snapshot(), arguments.vm.as_deref())?;
    let plan = RunPlan {
        vm_id: vm_id.clone(),
        sample: SampleRef {
            sha256: record.sha256.clone(),
            name: record.name.clone(),
        },
        guest_path: record.guest_path(),
        request: request.clone(),
        load_into: arguments.load_into.clone(),
        start_vm: arguments.start,
        run_limit: Duration::from_secs(arguments.timeout_run),
        boot_limit: BOOT_WAIT,
    };
    // The tools are checked before anything is started.
    engine.require_tools(&Command::Execute(request))?;
    if arguments.start && engine.snapshot().active_vm.as_deref() != Some(vm_id.as_str()) {
        engine.require_tools(&Command::Start {
            vm_id: vm_id.clone(),
        })?;
    }
    if let Some(limit) = context.timeout() {
        engine.waiter().deadline_in(limit);
    }
    let mut stream = EventStream::new(arguments.events);
    let report = engine
        .waiter()
        .exec(&plan, &load_artifacts, &mut |body| stream.emit(body))
        .map_err(wait_error)?;
    let output = engine
        .waiter()
        .terminal(report.run.as_ref().map_or("", |run| run.id.as_str()))
        .cloned()
        .unwrap_or_default();
    let vm = find_vm(engine.snapshot(), &vm_id)
        .ok()
        .map(|vm| vm_value(vm, engine.snapshot()));
    Ok(reply(&report, record, vm, &output))
}

/// Writes events as they happen when `--events` is on.
struct EventStream {
    on: bool,
    seq: u64,
}

impl EventStream {
    fn new(on: bool) -> Self {
        Self { on, seq: 0 }
    }

    fn emit(&mut self, body: EventBody) {
        if !self.on {
            return;
        }
        let ephemeral = body.is_ephemeral();
        if !ephemeral {
            self.seq += 1;
        }
        let event = Event {
            seq: (!ephemeral).then_some(self.seq),
            gseq: None,
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            scope: EventScope::Job,
            job_id: None,
            body,
        };
        let mut line = serde_json::to_string(&event).expect("an event serializes");
        line.push('\n');
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }
}

fn snake(text: &str) -> String {
    let mut out = String::new();
    for (index, c) in text.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn state_text(run: &RunSummary) -> String {
    snake(&format!("{:?}", run.state))
}

fn exit_value(run: &RunSummary) -> Value {
    match run.execution.as_ref().and_then(|e| e.root_exit.as_ref()) {
        Some(WaitStatus::Exited { code }) => json!({"kind": "exited", "code": code}),
        Some(WaitStatus::Signaled {
            signal,
            core_dumped,
        }) => json!({"kind": "signaled", "signal": signal, "core_dumped": core_dumped}),
        None => Value::Null,
    }
}

fn outcome_text(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Succeeded => "succeeded",
        Outcome::Partial => "partial",
        Outcome::Failed => "failed",
        Outcome::Cancelled => "cancelled",
        Outcome::Rejected => "rejected",
    }
}

/// A waited run that did not succeed ends with the code of a waited job.
pub fn exit_for(outcome: Outcome) -> Exit {
    match outcome {
        Outcome::Succeeded => Exit::Ok,
        Outcome::Partial => Exit::JobPartial,
        Outcome::Failed => Exit::JobFailed,
        Outcome::Cancelled => Exit::JobCancelled,
        Outcome::Rejected => Exit::JobRejected,
    }
}

fn seconds(ms: Option<u64>) -> String {
    ms.map_or("-".into(), |ms| format!("{:.1} s", ms as f64 / 1000.0))
}

fn failure_text(failure: &Failure) -> String {
    match &failure.detail {
        Some(detail) => {
            format!("{} ({:?}): {}", failure.message, failure.code, detail).replace("Failure", "")
        }
        None => format!("{} ({:?})", failure.message, failure.code),
    }
}

/// The human lines of the run's dump trigger.
fn trigger_lines(report: &TriggerReport) -> Vec<(&'static str, String)> {
    let mut lines = Vec::new();
    let what = match (report.armed.memory, report.armed.core) {
        (true, true) => "memory and core",
        (true, false) => "memory",
        _ => "core",
    };
    lines.push((
        "dump trigger",
        format!(
            "{what} at {} or higher: {}",
            report.armed.tier,
            if report.fired {
                "fired"
            } else {
                "did not fire"
            }
        ),
    ));
    for record in &report.records {
        let dumps: Vec<String> = [("core", &record.core), ("memory", &record.memory)]
            .into_iter()
            .filter_map(|(name, dump)| {
                let dump = dump.as_ref()?;
                let mut text = format!("{name} {}", dump.state);
                if let Some(path) = &dump.path {
                    text.push_str(&format!(" at {path}"));
                }
                if let Some(error) = &dump.error {
                    text.push_str(&format!(" ({error})"));
                }
                Some(text)
            })
            .collect();
        lines.push((
            "trigger",
            format!(
                "{} ({}) by process {} ({}): {}",
                record.rule,
                record.tier,
                record.pid,
                record.syscall,
                dumps.join(", ")
            ),
        ));
    }
    for note in &report.notes {
        lines.push(("trigger note", note.clone()));
    }
    lines
}

/// The result object of a finished `run exec`.
fn reply(
    report: &RunReport,
    record: &SampleRecord,
    vm: Option<Value>,
    output: &antinomie_service::waiter::TerminalTail,
) -> Reply {
    let text = String::from_utf8_lossy(&output.bytes).into_owned();
    let run = report.run.as_ref().map(|run| {
        json!({
            "id": run.id,
            "state": state_text(run),
            "pid": run.pid,
            "directory": run.directory,
            "started_ms": run.started_ms,
            "end_reason": report.end_reason.map(|reason| match reason {
                EndReason::Exited => "exited",
                EndReason::RunLimit => "run_limit",
            }),
            "exit": exit_value(run),
            "live_tasks": run.execution.as_ref().map(|e| e.live_task_count),
            "stopped_by_user": run.stopped_by_user,
            "route": run.route.as_ref().map(|route| route.label.clone()),
        })
    });
    let artifacts = report.artifacts.as_ref().map(|artifacts| {
        json!({
            "network": serde_json::to_value(artifacts.network_state).unwrap_or(Value::Null),
            "memory": serde_json::to_value(artifacts.memory_state).unwrap_or(Value::Null),
            "core": serde_json::to_value(artifacts.core_state).unwrap_or(Value::Null),
            "network_captures": artifacts.network_captures,
            "memory_dump": artifacts.memory_dump,
            "core_dump": artifacts.core_dump,
        })
    });
    let timings = &report.timings;
    let result = json!({
        "outcome": outcome_text(report.outcome),
        "failure": report.failure,
        "vm": vm,
        "sample": {"sha256": record.sha256, "name": record.name},
        "run": run,
        "artifacts": artifacts,
        "triggers": report.triggers,
        "warnings": report.warnings.iter()
            .map(|w| json!({"code": w.code, "text": w.text}))
            .collect::<Vec<_>>(),
        "stages_ms": {
            "provision": timings.provision_ms,
            "upload": timings.upload_ms,
            "launch": timings.launch_ms,
            "run": timings.run_ms,
            "collect": timings.collect_ms,
        },
        "recording_settled": report.settled,
        "output": text,
        "output_dropped_bytes": output.dropped,
    });
    let mut pairs: Vec<(&str, String)> = vec![
        ("outcome", outcome_text(report.outcome).to_owned()),
        ("sample", format!("{} ({})", record.name, record.sha256)),
    ];
    if let Some(failure) = &report.failure {
        pairs.push(("failure", failure_text(failure)));
    }
    if let Some(run) = &report.run {
        let how = match report.end_reason {
            Some(EndReason::RunLimit) => ", stopped at the run limit",
            Some(EndReason::Exited) => ", ended by itself",
            None => "",
        };
        let exit = match run.execution.as_ref().and_then(|e| e.root_exit.as_ref()) {
            Some(WaitStatus::Exited { code }) => format!(", exit {code}"),
            Some(WaitStatus::Signaled { signal, .. }) => format!(", signal {signal}"),
            None => String::new(),
        };
        pairs.push(("run", format!("{} {}{exit}{how}", run.id, state_text(run))));
    }
    pairs.push((
        "stages",
        format!(
            "provision {}, upload {}, launch {}, run {}, collect {}",
            seconds(timings.provision_ms),
            seconds(timings.upload_ms),
            seconds(timings.launch_ms),
            seconds(timings.run_ms),
            seconds(timings.collect_ms)
        ),
    ));
    if let Some(artifacts) = &report.artifacts {
        pairs.push((
            "evidence",
            format!(
                "network {:?}, memory {:?}, core {:?}",
                artifacts.network_state, artifacts.memory_state, artifacts.core_state
            )
            .to_ascii_lowercase(),
        ));
    }
    if let Some(triggers) = &report.triggers {
        pairs.extend(trigger_lines(triggers));
    }
    for warning in &report.warnings {
        pairs.push(("warning", format!("{}: {}", warning.code, warning.text)));
    }
    pairs.push((
        "recording",
        if report.settled {
            "final (the VM is stopped, no disk layer pending)".into()
        } else {
            "not settled".into()
        },
    ));
    let mut human = block(&pairs);
    if !text.is_empty() {
        human.push_str("output:\n");
        human.push_str(&text);
        if !text.ends_with('\n') {
            human.push('\n');
        }
    }
    Reply::value(result)
        .with_human(human)
        .with_exit(exit_for(report.outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        run: Run,
    }

    fn parse(extra: &[&str]) -> Exec {
        let sha = "ab".repeat(32);
        let mut all = vec!["x", "exec", sha.as_str()];
        all.extend_from_slice(extra);
        let Run::Exec(exec) = Wrapper::parse_from(all).run else {
            panic!("not an exec")
        };
        exec
    }

    #[test]
    fn who_runs_the_program() {
        assert_eq!(parse_identity("user").unwrap(), (1000, 1000));
        assert_eq!(parse_identity("root").unwrap(), (0, 0));
        assert_eq!(parse_identity("1001:1002").unwrap(), (1001, 1002));
        for bad in ["admin", "1000", "a:b", "1000:"] {
            assert!(parse_identity(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_flags_make_the_launch() {
        let exec = parse(&[
            "--as",
            "root",
            "--env",
            "A=1",
            "--route",
            "inet_sim",
            "--net-capture",
            "--memory-dump",
            "--args",
            "one",
            "two",
            "--",
            "-x",
        ]);
        let request = request_for(&exec).unwrap();
        assert_eq!((request.uid, request.gid), (0, 0));
        assert_eq!(request.args, ["one", "two", "-x"]);
        assert_eq!(request.cwd, "/tmp");
        assert!(request.capture_network && request.memory_dump_on_exit);
        assert!(!request.core_dump_on_exit && !request.analysis.enabled);
        assert_eq!(request.route, Some(RouteKind::InetSim));
        assert_eq!(request.run_in, RunIn::AppTerminal);
        assert_eq!(request.env[0], "A=1");
        assert!(request.env.iter().any(|item| item.starts_with("PATH=")));
    }

    #[test]
    fn a_path_in_the_environment_is_kept_and_a_bad_pair_is_refused() {
        let exec = parse(&["--env", "PATH=/x"]);
        let request = request_for(&exec).unwrap();
        assert_eq!(request.env, ["PATH=/x"]);
        for bad in ["NOEQUALS", "=v"] {
            let exec = parse(&["--env", bad]);
            assert_eq!(request_for(&exec).unwrap_err().exit.code(), 4, "{bad}");
        }
    }

    #[test]
    fn load_into_needs_an_absolute_guest_path() {
        let exec = parse(&["--load-into", "/bin/sh"]);
        assert_eq!(exec.load_into.as_deref(), Some("/bin/sh"));
        assert!(request_for(&exec).is_ok());
        let relative = parse(&["--load-into", "sh"]);
        assert_eq!(request_for(&relative).unwrap_err().exit.code(), 4);
    }

    #[test]
    fn static_checks_turn_the_guest_analysis_on() {
        let exec = parse(&["--static", "metadata,strings"]);
        let request = request_for(&exec).unwrap();
        assert!(request.analysis.enabled);
        assert_eq!(request.analysis.checks.len(), 2);
        assert!(request_for(&parse(&["--static", "nonsense"])).is_err());
    }

    #[test]
    fn a_core_dump_in_a_desktop_is_not_asked_here_but_validate_still_runs() {
        let exec = parse(&["--core-dump"]);
        assert!(request_for(&exec).unwrap().core_dump_on_exit);
    }

    #[test]
    fn the_dump_trigger_is_off_unless_asked() {
        let request = request_for(&parse(&[])).unwrap();
        assert!(request.dump_trigger.is_none());
        assert!(request.core_max_size.is_none() && request.core_timeout_ms.is_none());
        let off = request_for(&parse(&["--dump-trigger", "off"])).unwrap();
        assert!(off.dump_trigger.is_none());
    }

    #[test]
    fn the_dump_trigger_flags_make_the_plan() {
        use antinomie_monitor_core::dump_trigger::TriggerTier;
        let request = request_for(&parse(&["--dump-trigger", "high"])).unwrap();
        let plan = request.dump_trigger.unwrap();
        assert_eq!(plan.min_tier, TriggerTier::High);
        assert!(plan.core && !plan.memory);
        assert_eq!(request.core_max_size, Some(64 << 20));
        assert_eq!(request.core_timeout_ms, Some(5000));
        for (kind, memory, core) in [
            ("core", false, true),
            ("memory", true, false),
            ("Both", true, true),
        ] {
            let request =
                request_for(&parse(&["--dump-trigger", "Medium", "--dump-kind", kind])).unwrap();
            let plan = request.dump_trigger.unwrap();
            assert_eq!(plan.min_tier, TriggerTier::Medium, "{kind}");
            assert_eq!((plan.memory, plan.core), (memory, core), "{kind}");
            // A memory-only trigger asks for no core budget.
            assert_eq!(request.core_max_size.is_some(), core, "{kind}");
        }
    }

    #[test]
    fn a_bad_tier_or_kind_is_refused_and_a_kind_needs_a_trigger() {
        for args in [
            ["--dump-trigger", "urgent"].as_slice(),
            ["--dump-trigger", "high", "--dump-kind", "all"].as_slice(),
        ] {
            let error = request_for(&parse(args)).unwrap_err();
            assert_eq!(error.exit.code(), 4, "{args:?}");
        }
        let sha = "ab".repeat(32);
        assert!(
            Wrapper::try_parse_from(["x", "exec", sha.as_str(), "--dump-kind", "core"]).is_err()
        );
    }

    #[test]
    fn the_result_tells_what_the_trigger_did() {
        use antinomie_service::{
            api::job::{JobDump, JobTrigger},
            waiter::trigger::Armed,
        };
        let fired = TriggerReport {
            armed: Armed {
                tier: "high".into(),
                memory: false,
                core: true,
            },
            fired: true,
            records: vec![JobTrigger {
                rule: "persistence.cron".into(),
                tier: "high".into(),
                summary: String::new(),
                syscall: "openat".into(),
                pid: 7,
                at_ms: 1,
                memory: None,
                core: Some(JobDump {
                    state: "partial".into(),
                    size: Some(10),
                    capture_id: None,
                    error: None,
                    path: Some("/runs/r/core".into()),
                }),
            }],
            missed: 0,
            skipped: 0,
            lost: 0,
            notes: Vec::new(),
        };
        let lines = trigger_lines(&fired);
        assert_eq!(lines[0].1, "core at high or higher: fired");
        assert_eq!(
            lines[1].1,
            "persistence.cron (high) by process 7 (openat): core partial at /runs/r/core"
        );
        let quiet = TriggerReport {
            fired: false,
            records: Vec::new(),
            notes: vec!["armed, nothing matched".into()],
            ..fired
        };
        let lines = trigger_lines(&quiet);
        assert_eq!(lines[0].1, "core at high or higher: did not fire");
        assert_eq!(
            lines[1],
            ("trigger note", "armed, nothing matched".to_owned())
        );
    }

    #[test]
    fn routes_use_the_engine_names() {
        for (text, kind) in [
            ("drop", RouteKind::Drop),
            ("inet_sim", RouteKind::InetSim),
            ("inet-sim", RouteKind::InetSim),
            ("TOR", RouteKind::Tor),
            ("socks5", RouteKind::Socks5),
        ] {
            assert_eq!(parse_route(text).unwrap(), kind, "{text}");
        }
        assert!(parse_route("wifi").is_err());
    }

    #[test]
    fn a_waited_run_exits_like_a_waited_job() {
        assert_eq!(exit_for(Outcome::Succeeded).code(), 0);
        assert_eq!(exit_for(Outcome::Partial).code(), 11);
        assert_eq!(exit_for(Outcome::Failed).code(), 10);
    }

    #[test]
    fn events_are_only_streamed_when_asked_and_only_events_force_ndjson() {
        assert!(Run::Exec(parse(&["--events"])).streams_events());
        assert!(!Run::Exec(parse(&[])).streams_events());
    }
}
