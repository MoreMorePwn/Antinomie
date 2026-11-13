// SPDX-License-Identifier: GPL-3.0-only
//! The `auto` commands that look at and act on runs (design 3.4.4; card
//! P3-6b): `status`, `list`, `wait`, `events`, `result`, `artifacts`,
//! `fetch`, `cancel`, `retry`, `queue`, `preset list` (the presets). Each goes to the
//! daemon when one answers, else to the job store (see [`super::link`]).
use super::{
    link::{self, api},
    render,
};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    output::{Reply, table},
};
use antinomie_service::{
    api::{event::Event, ids::RunId, ops::RunListParams, run::Run, status::PauseReason},
    server::client::{Client, Streamed},
    store::Store,
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn run_id(text: &str) -> Result<RunId, CliError> {
    RunId::try_from(text.to_owned()).map_err(|_| {
        CliError::invalid(format!("{text:?} is not a run id (r_...)")).with_field("run")
    })
}

fn job_of(value: Value) -> Result<Run, CliError> {
    serde_json::from_value(value).map_err(|e| CliError::internal(format!("run: {e}")))
}

fn value(job: &impl serde::Serialize) -> Value {
    serde_json::to_value(job).unwrap_or(Value::Null)
}

/// `auto status [RUN]`.
#[derive(Args, Debug)]
pub struct Status {
    /// A run; without one, the queue and the lanes.
    pub run: Option<String>,
}

/// `auto list`.
#[derive(Args, Debug)]
pub struct List {
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,
    #[arg(long, value_name = "OUTCOME")]
    pub outcome: Option<String>,
    #[arg(long, value_name = "HEX")]
    pub sha256: Option<String>,
    /// A label `KEY` or `KEY=VALUE` of the spec.
    #[arg(long, value_name = "LABEL")]
    pub label: Option<String>,
    /// Only runs newer than this: `30m`, `24h`, `7d`, or a time in Unix ms.
    #[arg(long, value_name = "WHEN")]
    pub since: Option<String>,
    #[arg(long, default_value_t = 50)]
    pub limit: u32,
    #[arg(long)]
    pub cursor: Option<String>,
}

/// `auto wait RUN...`.
#[derive(Args, Debug)]
pub struct Wait {
    #[arg(required = true)]
    pub runs: Vec<String>,
    /// Exit 30, 31 or 32 for a succeeded run labelled suspicious, malicious or
    /// inconclusive.
    #[arg(long)]
    pub verdict_exit: bool,
}

/// `auto events [RUN]`.
#[derive(Args, Debug)]
pub struct Events {
    /// The run; with `--all`, none.
    pub run: Option<String>,
    /// Every run and the engine (resume by `gseq`).
    #[arg(long, conflicts_with = "run")]
    pub all: bool,
    /// Resume after this `seq` (one run) or `gseq` (`--all`).
    #[arg(long, value_name = "SEQ")]
    pub since: Option<u64>,
    /// Keep printing events as they happen (one run: until it ends).
    #[arg(long)]
    pub follow: bool,
    /// Only these event types, comma-separated (`run.state,run.stage`).
    #[arg(long, value_name = "T,...", value_delimiter = ',')]
    pub types: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RunArg {
    pub run: String,
}

#[derive(Args, Debug)]
pub struct Cancel {
    pub run: String,
    #[arg(long)]
    pub reason: Option<String>,
}

#[derive(Args, Debug)]
pub struct Rerun {
    pub run: String,
    /// Another preset, as it is now, instead of the run's own options.
    #[arg(long)]
    pub preset: Option<String>,
    /// Change one option, a dotted preset key (`program.run_time_s=60`,
    /// `network.route=inet_sim`); the value is JSON when it parses, else
    /// text.
    #[arg(long = "override", value_name = "KEY=VALUE")]
    pub overrides: Vec<String>,
}

#[derive(Args, Debug)]
pub struct Fetch {
    pub run: String,
    /// `html`, `pdf`, `json`, `misp`, `stix`, `md` (or `report.html` ...), or
    /// another artifact kind (`report.bundle`).
    pub kind: String,
    /// A file or a folder to write to; `-` writes to standard output.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Queue {
    /// The queue and the lanes.
    Status,
    /// Start no new run (the runs in progress finish).
    Pause,
    /// Start runs again.
    Resume,
}

#[derive(Subcommand, Debug)]
pub enum Preset {
    /// Every preset, with what its options need.
    List,
    /// One preset with every option, as its file has them.
    Show {
        /// The preset's name (`standard`, ...).
        name: String,
    },
}

/// `--since` of `auto list`.
pub fn since_ms(text: &str, now_ms: u64) -> Result<u64, CliError> {
    let bad = || {
        CliError::invalid(format!("{text:?}: use 30m, 24h, 7d or Unix milliseconds"))
            .with_field("since")
    };
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    let factor = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return text.parse().map_err(|_| bad()),
    };
    let amount: u64 = digits.parse().map_err(|_| bad())?;
    Ok(now_ms.saturating_sub(amount.saturating_mul(factor)))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn job_reply(job: &Value) -> Reply {
    Reply::value(job.clone()).with_human(render::job_text(job))
}

pub fn status(arguments: &Status, context: &Context) -> Result<Reply, CliError> {
    match &arguments.run {
        Some(text) => {
            let id = run_id(text)?;
            let job = get(context, &id)?;
            Ok(job_reply(&value(&job)))
        }
        None => queue(&Queue::Status, context),
    }
}

/// One run, from the daemon or the store.
pub fn get(context: &Context, id: &RunId) -> Result<Run, CliError> {
    match link::daemon(context)? {
        Some(mut client) => job_of(link::call(&mut client, "run.get", json!({"run_id": id}))?),
        None => link::read_store(context)?.get(id).map_err(api),
    }
}

pub fn list(arguments: &List, context: &Context) -> Result<Reply, CliError> {
    let mut params = json!({"limit": arguments.limit});
    for (key, value) in [
        ("state", &arguments.state),
        ("outcome", &arguments.outcome),
        ("sha256", &arguments.sha256),
        ("label", &arguments.label),
        ("cursor", &arguments.cursor),
    ] {
        if let Some(value) = value {
            params[key] = json!(value);
        }
    }
    if let Some(since) = &arguments.since {
        params["since_ms"] = json!(since_ms(since, now_ms())?);
    }
    let listed = match link::daemon(context)? {
        Some(mut client) => link::call(&mut client, "run.list", params)?,
        None => {
            let params: RunListParams =
                serde_json::from_value(params).map_err(|e| CliError::invalid(e.to_string()))?;
            value(
                &link::read_store(context)?
                    .list(&params, None)
                    .map_err(api)?,
            )
        }
    };
    let jobs = listed["runs"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = jobs.iter().map(render::job_row).collect();
    let human = if rows.is_empty() {
        "no runs\n".into()
    } else {
        table(
            &["RUN", "STATE", "STAGE", "LABEL", "SAMPLE", "PRESET"],
            &rows,
        )
    };
    let cursor = listed["next_cursor"].as_str().map(str::to_owned);
    Ok(Reply::list(jobs, cursor).with_human(human))
}

/// Wait until `id` is terminal: through a run stream when a client is given,
/// else by reading the store twice a second. `None` when the limit passed.
pub fn wait_terminal(
    client: Option<&mut Client>,
    store: Option<&Store>,
    id: &RunId,
    limit: Option<Duration>,
    on_event: &mut dyn FnMut(&Event),
) -> Result<Run, CliError> {
    match (client, store) {
        (Some(client), _) => {
            client.deadline_in(limit);
            let ended = client.subscribe(json!({"run_id": id}), &mut |line| {
                if let Streamed::Event(event) = line {
                    on_event(&event);
                }
                true
            });
            client.deadline_in(None);
            match ended {
                Ok(_) | Err(antinomie_service::server::client::ClientError::TimedOut) => {}
                Err(other) => return Err(link::client(other)),
            }
            job_of(link::call(client, "run.get", json!({"run_id": id}))?)
        }
        (None, Some(store)) => {
            let until = limit.map(|limit| Instant::now() + limit);
            let mut after = 0;
            loop {
                let (events, next) = store.events_list(id, after, 500).map_err(api)?;
                for event in &events {
                    on_event(event);
                }
                after = next;
                let job = store.get(id).map_err(api)?;
                if job.state.is_terminal() || until.is_some_and(|u| Instant::now() >= u) {
                    return Ok(job);
                }
                if crate::signals::interrupted() {
                    return Err(CliError::internal("interrupted").with_exit(Exit::Interrupted));
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        (None, None) => Err(CliError::internal("no way to reach the run")),
    }
}

pub fn wait(arguments: &Wait, context: &Context) -> Result<Reply, CliError> {
    crate::signals::install();
    let ids: Vec<RunId> = arguments
        .runs
        .iter()
        .map(|t| run_id(t))
        .collect::<Result<_, _>>()?;
    let mut client = link::daemon(context)?;
    let store = match client {
        Some(_) => None,
        None => Some(link::read_store(context)?),
    };
    let began = Instant::now();
    let mut jobs = Vec::new();
    let mut exits = Vec::new();
    for id in &ids {
        let left = context.timeout().map(|t| t.saturating_sub(began.elapsed()));
        let job = wait_terminal(client.as_mut(), store.as_ref(), id, left, &mut |_| {})?;
        exits.push(render::job_exit(&job, arguments.verdict_exit));
        jobs.push(value(&job));
    }
    let exit = render::worst(&exits);
    if jobs.len() == 1 {
        return Ok(job_reply(&jobs[0]).with_exit(exit));
    }
    let human: String = jobs
        .iter()
        .map(render::job_text)
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Reply::list(jobs, None).with_human(human).with_exit(exit))
}

/// Print one event as an NDJSON line as it happens.
pub fn print_event(event: &Event) {
    let mut line = serde_json::to_vec(event).unwrap_or_default();
    line.push(b'\n');
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&line);
    let _ = out.flush();
}

pub fn events(arguments: &Events, context: &Context) -> Result<Reply, CliError> {
    crate::signals::install();
    let job = match (&arguments.run, arguments.all) {
        (Some(text), _) => Some(run_id(text)?),
        (None, true) => None,
        (None, false) => {
            return Err(CliError::invalid("name a run, or --all for every run").with_field("run"));
        }
    };
    let mut params = json!({});
    if let Some(job) = &job {
        params["run_id"] = json!(job);
        if let Some(since) = arguments.since {
            params["since_seq"] = json!(since);
        }
    } else if let Some(since) = arguments.since {
        params["since_gseq"] = json!(since);
    }
    if !arguments.types.is_empty() {
        params["types"] = json!(arguments.types);
    }
    let client = link::daemon(context)?;
    match (client, arguments.follow, &job) {
        (Some(mut client), true, _) => {
            client.deadline_in(context.timeout());
            let mut hello = None;
            let ended = client.subscribe(params, &mut |line| {
                match line {
                    Streamed::Event(event) => print_event(&event),
                    Streamed::Hello(h) => hello = Some(h),
                    Streamed::Ping => {}
                }
                true
            });
            let result = match ended {
                Ok(result) => result,
                Err(antinomie_service::server::client::ClientError::TimedOut) => {
                    json!({"timed_out": true})
                }
                Err(other) => return Err(link::client(other)),
            };
            Ok(Reply::value(json!({"end": result, "hello": hello})))
        }
        (Some(mut client), false, Some(job)) => {
            let mut events = Vec::new();
            let mut after = arguments.since.unwrap_or(0);
            loop {
                let page = link::call(
                    &mut client,
                    "events.list",
                    json!({"run_id": job, "after_seq": after, "limit": 1000}),
                )?;
                let batch = page["events"].as_array().cloned().unwrap_or_default();
                if batch.is_empty() {
                    break;
                }
                after = page["next_seq"].as_u64().unwrap_or(after);
                events.extend(batch);
            }
            Ok(event_list(events, &arguments.types))
        }
        (Some(_), false, None) => Err(CliError::invalid(
            "--all needs --follow (the stored events of every run are a stream)",
        )),
        (None, follow, Some(job)) => {
            let store = link::read_store(context)?;
            if follow {
                let finished =
                    wait_terminal(None, Some(&store), job, context.timeout(), &mut |e| {
                        if wanted(e, &arguments.types) && e.seq > arguments.since {
                            print_event(e);
                        }
                    })?;
                return Ok(Reply::value(json!({"end": {"state": finished.state}})));
            }
            let (events, _) = store
                .events_list(job, arguments.since.unwrap_or(0), 1000)
                .map_err(api)?;
            Ok(event_list(
                events.iter().map(value).collect(),
                &arguments.types,
            ))
        }
        (None, _, None) => Err(CliError::new(
            ErrorCode::Unavailable,
            "the all-runs stream needs a running daemon",
        )),
    }
}

fn wanted(event: &Event, types: &[String]) -> bool {
    types.is_empty() || {
        let kind = value(&event.body)["type"].as_str().unwrap_or("").to_owned();
        types.contains(&kind)
    }
}

fn event_list(events: Vec<Value>, types: &[String]) -> Reply {
    let events: Vec<Value> = events
        .into_iter()
        .filter(|e| types.is_empty() || types.iter().any(|t| e["type"] == json!(t)))
        .collect();
    let human: String = events
        .iter()
        .map(|e| {
            format!(
                "{:>5} {:<15} {}\n",
                e["seq"],
                e["type"].as_str().unwrap_or(""),
                render::clean(&e["data"].to_string())
            )
        })
        .collect();
    Reply::list(events, None).with_human(human)
}

/// An artifact's file: the daemon's path (checked to be inside the data
/// folder), or the store's location resolved inside the run directory.
fn artifact_paths(
    context: &Context,
    client: Option<&mut Client>,
    job: &Run,
) -> Result<Vec<Value>, CliError> {
    let data = context
        .data_dir()
        .canonicalize()
        .map_err(|e| CliError::io(context.data_dir(), &e))?;
    let mut out = Vec::new();
    match client {
        Some(client) => {
            for artifact in &job.artifacts {
                let got = link::call(client, "artifact.get", json!({"artifact_id": artifact.id}))?;
                let path = PathBuf::from(got["path"].as_str().unwrap_or_default());
                if !path.starts_with(&data) {
                    return Err(CliError::internal(format!(
                        "the daemon named a file outside the data folder: {}",
                        path.display()
                    )));
                }
                out.push(json!({"artifact": artifact, "path": path}));
            }
        }
        None => {
            let store = link::read_store(context)?;
            for artifact in &job.artifacts {
                let (_, location) = store.artifact(&artifact.id).map_err(api)?;
                let path = antinomie_service::daemon::artifacts::resolve(
                    &store.job_dir(&job.id),
                    &location,
                )
                .map_err(api)?;
                out.push(json!({"artifact": artifact, "path": path}));
            }
        }
    }
    Ok(out)
}

/// `auto result RUN`: the run's outcome, label and report files.
pub fn result(arguments: &RunArg, context: &Context) -> Result<Reply, CliError> {
    let id = run_id(&arguments.run)?;
    let mut client = link::daemon(context)?;
    let job = match client.as_mut() {
        Some(client) => job_of(link::call(client, "run.get", json!({"run_id": id}))?)?,
        None => link::read_store(context)?.get(&id).map_err(api)?,
    };
    let files = artifact_paths(context, client.as_mut(), &job)?;
    let mut human = render::job_text(&value(&job));
    if !files.is_empty() {
        human.push_str("reports:\n");
        for file in &files {
            human.push_str(&format!(
                "  {:<14} {}\n",
                file["artifact"]["kind"].as_str().unwrap_or(""),
                file["path"].as_str().unwrap_or("")
            ));
        }
    }
    Ok(Reply::value(json!({"run": job, "files": files})).with_human(human))
}

pub fn artifacts(arguments: &RunArg, context: &Context) -> Result<Reply, CliError> {
    let id = run_id(&arguments.run)?;
    let list = match link::daemon(context)? {
        Some(mut client) => {
            link::call(&mut client, "artifact.list", json!({"run_id": id}))?["artifacts"].clone()
        }
        None => value(&link::read_store(context)?.artifacts(&id).map_err(api)?),
    };
    let items = list.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|a| {
            vec![
                a["id"].as_str().unwrap_or("").into(),
                a["kind"].as_str().unwrap_or("").into(),
                render::clean(a["name"].as_str().unwrap_or("")),
                a["size"].to_string(),
                a["sensitive"].to_string(),
            ]
        })
        .collect();
    let human = table(&["ARTIFACT", "KIND", "NAME", "SIZE", "SENSITIVE"], &rows);
    Ok(Reply::list(items, None).with_human(human))
}

pub fn fetch(arguments: &Fetch, context: &Context) -> Result<Reply, CliError> {
    let id = run_id(&arguments.run)?;
    let kind = if arguments.kind.contains('.') {
        arguments.kind.clone()
    } else {
        format!("report.{}", arguments.kind)
    };
    let mut client = link::daemon(context)?;
    let job = match client.as_mut() {
        Some(client) => job_of(link::call(client, "run.get", json!({"run_id": id}))?)?,
        None => link::read_store(context)?.get(&id).map_err(api)?,
    };
    let files = artifact_paths(context, client.as_mut(), &job)?;
    let file = files
        .iter()
        .find(|f| f["artifact"]["kind"] == json!(kind))
        .ok_or_else(|| CliError::not_found(format!("run {id} has no {kind} artifact")))?;
    let source = PathBuf::from(file["path"].as_str().unwrap_or_default());
    let name = file["artifact"]["name"].as_str().unwrap_or("artifact");
    if arguments.out.as_deref() == Some(Path::new("-")) {
        let bytes = std::fs::read(&source).map_err(|e| CliError::io(&source, &e))?;
        let _ = std::io::stdout().write_all(&bytes);
        return Ok(
            Reply::value(json!({"written": "-", "size": bytes.len()})).with_human(String::new())
        );
    }
    let target = match &arguments.out {
        Some(path) if path.is_dir() => path.join(name),
        Some(path) => path.clone(),
        None => PathBuf::from(name),
    };
    std::fs::copy(&source, &target).map_err(|e| CliError::io(&target, &e))?;
    Ok(
        Reply::value(
            json!({"written": target, "kind": kind, "sha256": file["artifact"]["sha256"]}),
        )
        .with_human(format!("{kind} written to {}\n", target.display())),
    )
}

pub fn cancel(arguments: &Cancel, context: &Context) -> Result<Reply, CliError> {
    let id = run_id(&arguments.run)?;
    let job = match link::daemon(context)? {
        Some(mut client) => link::call(
            &mut client,
            "run.cancel",
            json!({"run_id": id, "reason": arguments.reason}),
        )?,
        None => {
            let (store, _guard) = link::locked_store(context)?;
            value(
                &store
                    .cancel(&id, arguments.reason.as_deref(), &link::me())
                    .map_err(api)?,
            )
        }
    };
    Ok(job_reply(&job))
}

/// `--override TABLE.KEY=VALUE` as overrides (a partial preset).
pub fn overrides(pairs: &[String]) -> Result<Value, CliError> {
    let mut out = json!({});
    for pair in pairs {
        let bad =
            || CliError::invalid(format!("{pair:?} is not TABLE.KEY=VALUE")).with_field("override");
        let (key, text) = pair.split_once('=').ok_or_else(bad)?;
        let value = serde_json::from_str(text).unwrap_or_else(|_| json!(text));
        let path: Vec<&str> = key.split('.').collect();
        if path.iter().any(|part| part.is_empty()) {
            return Err(bad());
        }
        let mut slot = &mut out;
        for part in &path[..path.len() - 1] {
            if !slot[*part].is_object() {
                slot[*part] = json!({});
            }
            slot = &mut slot[*part];
        }
        slot[path[path.len() - 1]] = value;
    }
    Ok(out)
}

pub fn rerun(arguments: &Rerun, context: &Context) -> Result<Reply, CliError> {
    let id = run_id(&arguments.run)?;
    let mut params = json!({"run_id": id});
    if let Some(preset) = &arguments.preset {
        params["preset"] = json!(preset);
    }
    if !arguments.overrides.is_empty() {
        params["overrides"] = overrides(&arguments.overrides)?;
    }
    let Some(mut client) = link::daemon(context)? else {
        return Err(CliError::new(
            ErrorCode::Unavailable,
            "`auto rerun` needs a running daemon (`antinomie-cli auto daemon`)",
        ));
    };
    let job = link::call(&mut client, "run.rerun", params)?;
    Ok(job_reply(&job))
}

pub fn queue(command: &Queue, context: &Context) -> Result<Reply, CliError> {
    let status = match (link::daemon(context)?, command) {
        (Some(mut client), Queue::Status) => link::call(&mut client, "queue.status", json!({}))?,
        (Some(mut client), Queue::Pause) => link::call(&mut client, "queue.pause", json!({}))?,
        (Some(mut client), Queue::Resume) => link::call(&mut client, "queue.resume", json!({}))?,
        (None, Queue::Status) => {
            let store = link::read_store(context)?;
            let counts = store.counts().map_err(api)?;
            let reason = store.pause_reason().map_err(api)?;
            json!({
                "paused": reason.is_some(), "pause_reason": reason,
                "queued": counts.queued, "running": counts.running,
                "lanes": [], "owner": "none",
            })
        }
        (None, change) => {
            let (store, _guard) = link::locked_store(context)?;
            let reason = matches!(change, Queue::Pause).then_some(PauseReason::Operator);
            store.set_pause(reason).map_err(api)?;
            json!({"paused": reason.is_some(), "pause_reason": reason, "owner": "none"})
        }
    };
    Ok(Reply::value(status.clone()).with_human(render::queue_text(&status)))
}

pub fn preset(command: &Preset, context: &Context) -> Result<Reply, CliError> {
    let list = match (link::daemon(context)?, command) {
        (Some(mut client), Preset::Show { name }) => {
            let preset = link::call(&mut client, "preset.get", json!({"name": name}))?;
            return Ok(preset_reply(preset));
        }
        (None, Preset::Show { name }) => {
            let preset = local_presets(context)
                .detail(name)
                .ok_or_else(|| CliError::not_found(format!("there is no preset {name}")))?;
            return Ok(preset_reply(value(&preset)));
        }
        (Some(mut client), Preset::List) => {
            link::call(&mut client, "preset.list", json!({}))?["presets"].clone()
        }
        (None, Preset::List) => value(&local_presets(context).list_for(&link::me())),
    };
    let items = list.as_array().cloned().unwrap_or_default();
    let words = |v: &Value| {
        v.as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|p| {
            let mut needs = words(&p["needs"]);
            if needs.is_empty() {
                needs = "-".into();
            }
            if p["unavailable"].as_array().is_some_and(|u| !u.is_empty()) {
                needs.push_str(" (not on this node)");
            }
            vec![
                p["name"].as_str().unwrap_or("").into(),
                render::clean(p["title"].as_str().unwrap_or("")),
                needs,
                render::clean(p["description"].as_str().unwrap_or("")),
            ]
        })
        .collect();
    Ok(Reply::list(items, None)
        .with_human(table(&["PRESET", "TITLE", "NEEDS", "DESCRIPTION"], &rows)))
}

/// The presets of the data folder, read in this process (no daemon).
fn local_presets(context: &Context) -> antinomie_service::config::PresetSet {
    antinomie_service::config::validate::load(
        context.data_dir(),
        &antinomie_service::config::DiskVms::open(context.data_dir()),
        None,
    )
    .preset_set()
}

/// `auto preset show`: the preset as JSON, and `table.key = value` lines
/// for people.
fn preset_reply(preset: Value) -> Reply {
    let mut human = String::new();
    for (key, value) in preset.as_object().into_iter().flatten() {
        match value {
            Value::Object(table) => {
                for (name, item) in table {
                    let item = render::clean(&item.to_string());
                    human.push_str(&format!("{key}.{name} = {item}\n"));
                }
            }
            other => {
                let other = render::clean(&other.to_string());
                human.push_str(&format!("{key} = {other}\n"));
            }
        }
    }
    Reply::value(preset).with_human(human)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_takes_units_or_milliseconds() {
        let now = 10_000_000_000;
        assert_eq!(since_ms("30m", now).unwrap(), now - 1_800_000);
        assert_eq!(since_ms("24h", now).unwrap(), now - 86_400_000);
        assert_eq!(since_ms("7d", now).unwrap(), now - 604_800_000);
        assert_eq!(since_ms("1794000000000", now).unwrap(), 1_794_000_000_000);
        for bad in ["", "h", "5x", "-3h", "1.5d"] {
            assert!(since_ms(bad, now).is_err(), "{bad}");
        }
    }

    #[test]
    fn overrides_are_json_when_they_parse() {
        let value = overrides(&[
            "program.run_time_s=60".into(),
            "network.route=inet_sim".into(),
            "program.arguments=[\"a\"]".into(),
        ])
        .unwrap();
        assert_eq!(
            value,
            json!({"program": {"run_time_s": 60, "arguments": ["a"]},
                   "network": {"route": "inet_sim"}})
        );
        assert!(overrides(&["nokey".into()]).is_err());
        assert!(overrides(&["program..x=1".into()]).is_err());
    }
}
