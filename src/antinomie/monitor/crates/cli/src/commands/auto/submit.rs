// SPDX-License-Identifier: GPL-3.0-only
//! `auto submit` (design 3.4.4; card P3-6b).
//!
//! With a daemon the file is uploaded over the socket (`upload.begin`, `put`
//! in pieces of 768 KiB, `finish` with the SHA-256 computed here, so the
//! daemon checks it), then `job.submit` names the upload. `--wait` waits for
//! the job's end through its event stream, `--follow` prints the events as
//! NDJSON as they happen, `--verdict-exit` waits and turns the label of a
//! succeeded job into the exit code, `--out DIR` copies the report files.
//!
//! Without a daemon (direct mode) the command owns the data folder itself
//! (owner kind `cli`, no socket), runs the queue in this process until the
//! job has ended, and exits with the job's code: "pass an ELF, get a report".
//! A job queued before it runs first. Ctrl-C stops it as the daemon's stop
//! does: a job in the VM goes back to the queue (exit 130).
use super::{
    jobs::{self, print_event},
    link::{self, api},
    render,
};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    output::Reply,
    signals,
};
use antinomie_monitor_core::{
    Backend,
    data_owner::{OwnerClaim, OwnerKind},
};
use antinomie_service::{
    api::{event::Event, job::Job, ops::EventsSubscribeParams, status::Owner},
    daemon::{Daemon, Exit as DaemonExit, Setup},
    server::{CallContext, Handler, b64, client::Client, limits::Limits, subscribe},
};
use clap::Args;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

/// The raw bytes of one `upload.put` (Base64 makes them 1 MiB at most).
const PIECE: usize = 768 * 1024;

#[derive(Args, Debug)]
pub struct Submit {
    /// The file to analyse. It is read once and stored in the library; the
    /// original is not changed.
    #[arg(required_unless_present = "sha256", conflicts_with = "sha256")]
    pub file: Option<PathBuf>,
    /// A sample already in the library, by its SHA-256.
    #[arg(long, value_name = "HEX")]
    pub sha256: Option<String>,
    /// The policy [default: default].
    #[arg(long)]
    pub policy: Option<String>,
    /// 0 to 9; higher starts first (the policy sets a ceiling).
    #[arg(long)]
    pub priority: Option<u8>,
    /// A label of the job (repeatable).
    #[arg(long = "label", value_name = "KEY=VALUE")]
    pub labels: Vec<String>,
    /// The run limit in seconds (the policy's `max_run_s` is the ceiling).
    #[arg(long, value_name = "SECONDS")]
    pub timeout_run: Option<u32>,
    /// Program arguments.
    #[arg(long, num_args = 1.., allow_hyphen_values = true, value_name = "ARG")]
    pub args: Vec<String>,
    /// An environment entry (repeatable; the policy must allow them).
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,
    /// `user`, `root` or `UID:GID`.
    #[arg(long = "as", value_name = "WHO")]
    pub run_as: Option<String>,
    /// `drop` or `inet_sim`.
    #[arg(long, value_name = "ROUTE")]
    pub route: Option<String>,
    /// Static checks on the host: `none`, `triage`, or names (`strings,entropy`).
    #[arg(long = "static", value_name = "CHECKS", conflicts_with = "no_static")]
    pub static_checks: Option<String>,
    #[arg(long)]
    pub no_static: bool,
    /// Report formats: html, pdf, json, misp, stix, md (`--format` is the
    /// output format of this command).
    #[arg(long, value_name = "F,...", value_delimiter = ',')]
    pub formats: Vec<String>,
    /// Also write the evidence bundle zip (`--bundle` is the boot bundle).
    #[arg(long)]
    pub evidence_bundle: bool,
    #[arg(long, conflicts_with = "no_defang")]
    pub defang: bool,
    #[arg(long)]
    pub no_defang: bool,
    /// The same key and spec within 24 hours returns the first job.
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: Option<String>,
    /// The file name the job shows [default: the file's name].
    #[arg(long)]
    pub name: Option<String>,
    /// Wait until the job has ended; exit with its code.
    #[arg(long)]
    pub wait: bool,
    /// Print the job's events as NDJSON until it has ended (implies --wait).
    #[arg(long)]
    pub follow: bool,
    /// Wait, and exit 30, 31 or 32 when the succeeded job is labelled
    /// suspicious, malicious or inconclusive.
    #[arg(long)]
    pub verdict_exit: bool,
    /// Copy the report files into this folder once the job has ended
    /// (implies --wait).
    #[arg(long, value_name = "DIR")]
    pub out: Option<PathBuf>,
}

impl Submit {
    fn waits(&self) -> bool {
        self.wait || self.follow || self.verdict_exit || self.out.is_some()
    }
}

fn pairs(list: &[String], field: &str) -> Result<serde_json::Map<String, Value>, CliError> {
    let mut out = serde_json::Map::new();
    for pair in list {
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            CliError::invalid(format!("{pair:?} is not KEY=VALUE")).with_field(field)
        })?;
        out.insert(key.to_owned(), json!(value));
    }
    Ok(out)
}

/// The spec of the job, without its sample.
pub fn spec_of(arguments: &Submit) -> Result<Value, CliError> {
    let mut spec = json!({"sample": {}});
    let mut overrides = serde_json::Map::new();
    if let Some(policy) = &arguments.policy {
        spec["policy"] = json!(policy);
    }
    if let Some(priority) = arguments.priority {
        spec["priority"] = json!(priority);
    }
    if !arguments.labels.is_empty() {
        spec["labels"] = Value::Object(pairs(&arguments.labels, "label")?);
    }
    if let Some(key) = &arguments.idempotency_key {
        spec["idempotency_key"] = json!(key);
    }
    if let Some(name) = &arguments.name {
        spec["name"] = json!(name);
    }
    if let Some(seconds) = arguments.timeout_run {
        overrides.insert("timeout_s".into(), json!(seconds));
    }
    if !arguments.args.is_empty() {
        overrides.insert("args".into(), json!(arguments.args));
    }
    if !arguments.env.is_empty() {
        overrides.insert("env".into(), json!(arguments.env));
    }
    if let Some(who) = &arguments.run_as {
        let value = match who.as_str() {
            "user" | "root" => json!(who),
            ids => {
                let (uid, gid) = ids
                    .split_once(':')
                    .and_then(|(u, g)| Some((u.parse::<u32>().ok()?, g.parse::<u32>().ok()?)))
                    .ok_or_else(|| {
                        CliError::invalid("--as takes user, root or UID:GID").with_field("as")
                    })?;
                json!({"uid": uid, "gid": gid})
            }
        };
        overrides.insert("run_as".into(), value);
    }
    if let Some(route) = &arguments.route {
        overrides.insert("route".into(), json!(route));
    }
    if arguments.no_static {
        overrides.insert("static_checks".into(), json!("none"));
    } else if let Some(checks) = &arguments.static_checks {
        let value = match checks.as_str() {
            "none" | "triage" => json!(checks),
            list => json!(list.split(',').map(str::trim).collect::<Vec<_>>()),
        };
        overrides.insert("static_checks".into(), value);
    }
    if !arguments.formats.is_empty() {
        overrides.insert("reports".into(), json!(arguments.formats));
    }
    if arguments.evidence_bundle {
        overrides.insert("report_bundle".into(), json!(true));
    }
    if arguments.defang || arguments.no_defang {
        overrides.insert("report_defang".into(), json!(arguments.defang));
    }
    if !overrides.is_empty() {
        spec["overrides"] = Value::Object(overrides);
    }
    Ok(spec)
}

/// The file's name as an upload name: control characters and `/` dropped,
/// 128 bytes at most.
fn upload_name(path: &Path) -> Option<String> {
    let name: String = path
        .file_name()?
        .to_string_lossy()
        .chars()
        .filter(|c| !c.is_control() && *c != '/')
        .collect();
    let mut end = name.len().min(128);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    (!name[..end].is_empty()).then(|| name[..end].to_owned())
}

fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    let meta = std::fs::metadata(path).map_err(|e| CliError::io(path, &e))?;
    if !meta.is_file() {
        return Err(
            CliError::invalid(format!("{} is not a regular file", path.display()))
                .with_field("file"),
        );
    }
    let limit = antinomie_monitor_core::samples::MAX_SAMPLE;
    if meta.len() > limit {
        return Err(CliError::new(
            ErrorCode::PayloadTooLarge,
            format!(
                "{} is {} bytes; a sample may be at most {limit}",
                path.display(),
                meta.len()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(path)
        .and_then(|f| f.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|e| CliError::io(path, &e))?;
    Ok(bytes)
}

/// Upload `path` to the daemon; the upload id and the file's SHA-256.
pub(crate) fn upload(
    client: &mut Client,
    path: &Path,
    context: &Context,
) -> Result<(String, String), CliError> {
    let bytes = read_file(path)?;
    let sha = hex(&Sha256::digest(&bytes));
    let mut begin = json!({"size": bytes.len(), "sha256": sha});
    if let Some(name) = upload_name(path) {
        begin["name"] = json!(name);
    }
    let begun = link::call(client, "upload.begin", begin)?;
    let id = begun["upload_id"].as_str().unwrap_or_default().to_owned();
    let mut offset = 0usize;
    for piece in bytes.chunks(PIECE) {
        link::call(
            client,
            "upload.put",
            json!({"upload_id": id, "offset": offset, "data": b64::encode(piece)}),
        )?;
        offset += piece.len();
    }
    link::call(client, "upload.finish", json!({"upload_id": id}))?;
    context
        .logger
        .debug(&format!("uploaded {} bytes as {id}", bytes.len()));
    Ok((id, sha))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn copy_reports(files: &[Value], out: &Path) -> Result<Vec<Value>, CliError> {
    std::fs::create_dir_all(out).map_err(|e| CliError::io(out, &e))?;
    let mut written = Vec::new();
    for file in files {
        let kind = file["artifact"]["kind"].as_str().unwrap_or("");
        if !kind.starts_with("report.") {
            continue;
        }
        let source = PathBuf::from(file["path"].as_str().unwrap_or_default());
        let name = file["artifact"]["name"].as_str().unwrap_or("report");
        let target = out.join(name);
        std::fs::copy(&source, &target).map_err(|e| CliError::io(&target, &e))?;
        written.push(json!({"kind": kind, "path": target}));
    }
    Ok(written)
}

/// The reply for a submitted (and maybe waited) job.
fn finish(job: &Job, replayed: bool, files: Vec<Value>, waited: bool, verdict_exit: bool) -> Reply {
    let value = serde_json::to_value(job).unwrap_or(Value::Null);
    let mut human = render::job_text(&value);
    for file in &files {
        human.push_str(&format!(
            "{:<11} {}\n",
            file["kind"].as_str().unwrap_or("report:"),
            file["path"].as_str().unwrap_or("")
        ));
    }
    let exit = if job.state == antinomie_service::api::job::JobState::Rejected {
        Exit::JobRejected
    } else if waited {
        render::job_exit(job, verdict_exit)
    } else {
        Exit::Ok
    };
    Reply::value(json!({"job": value, "replayed": replayed, "reports": files}))
        .with_human(human)
        .with_exit(exit)
}

pub fn run(arguments: &Submit, context: &Context) -> Result<Reply, CliError> {
    let mut spec = spec_of(arguments)?;
    match link::daemon(context)? {
        Some(mut client) => {
            match (&arguments.file, &arguments.sha256) {
                (Some(path), _) => {
                    spec["sample"]["upload_id"] = json!(upload(&mut client, path, context)?.0);
                    if spec.get("name").is_none()
                        && let Some(name) = upload_name(path)
                    {
                        spec["name"] = json!(name);
                    }
                }
                (None, Some(sha)) => spec["sample"]["sha256"] = json!(sha),
                (None, None) => unreachable!("clap requires one"),
            }
            let submitted = link::call(&mut client, "job.submit", spec)?;
            let replayed = submitted["replayed"].as_bool().unwrap_or(false);
            let mut job: Job = serde_json::from_value(submitted)
                .map_err(|e| CliError::internal(format!("job: {e}")))?;
            if arguments.waits() && !job.state.is_terminal() {
                let follow = arguments.follow;
                job = jobs::wait_terminal(
                    Some(&mut client),
                    None,
                    &job.id,
                    context.timeout(),
                    &mut |event| {
                        if follow {
                            print_event(event)
                        }
                    },
                )?;
            }
            let mut files = Vec::new();
            if let Some(out) = &arguments.out {
                let paths = artifact_files(&mut client, &job, context)?;
                files = copy_reports(&paths, out)?;
            }
            Ok(finish(
                &job,
                replayed,
                files,
                arguments.waits(),
                arguments.verdict_exit,
            ))
        }
        None => direct(arguments, spec, context),
    }
}

fn artifact_files(
    client: &mut Client,
    job: &Job,
    context: &Context,
) -> Result<Vec<Value>, CliError> {
    let data = context
        .data_dir()
        .canonicalize()
        .map_err(|e| CliError::io(context.data_dir(), &e))?;
    let mut out = Vec::new();
    for artifact in &job.artifacts {
        let got = link::call(client, "artifact.get", json!({"artifact_id": artifact.id}))?;
        let path = PathBuf::from(got["path"].as_str().unwrap_or_default());
        if !path.starts_with(&data) {
            return Err(CliError::internal(
                "the daemon named a file outside the data folder",
            ));
        }
        out.push(json!({"artifact": artifact, "path": path}));
    }
    Ok(out)
}

/// Direct mode: the queue in this process until the job has ended.
fn direct(arguments: &Submit, mut spec: Value, context: &Context) -> Result<Reply, CliError> {
    let data_dir = context.data_dir().to_path_buf();
    match (&arguments.file, &arguments.sha256) {
        (Some(path), _) => {
            let absolute = std::fs::canonicalize(path).map_err(|e| CliError::io(path, &e))?;
            spec["sample"]["path"] = json!(absolute);
        }
        (None, Some(sha)) => spec["sample"]["sha256"] = json!(sha),
        (None, None) => unreachable!("clap requires one"),
    }
    let config = super::daemon::load_config(None, &data_dir)?;
    let mut options = context.options.clone();
    options.owner = OwnerClaim {
        kind: OwnerKind::Cli,
        socket: None,
        lane: None,
    };
    let backend = Backend::new(options.clone())
        .map_err(|message| CliError::from_engine_start(&data_dir, &message))?;
    signals::install_daemon();
    let logger = context.logger;
    let setup = Setup {
        options,
        socket: None,
        owner: Owner::CliDirect,
        host_grace: Duration::from_secs(u64::from(config.daemon.shutdown_host_grace_s)),
        limits: Limits::default(),
        log: Arc::new(move |line: &str| logger.info(line)),
        config,
    };
    let mut daemon = Daemon::start(setup, backend)
        .map_err(|message| CliError::new(ErrorCode::Unavailable, message))?;
    let service = Arc::clone(daemon.service());
    let submitted = service.call("job.submit", spec, &CallContext::in_process(link::me()));
    let submitted = match submitted {
        Ok(value) => value,
        Err(error) => {
            stop(daemon)?;
            return Err(api(error));
        }
    };
    let job: Job = serde_json::from_value(submitted.clone())
        .map_err(|e| CliError::internal(format!("job: {e}")))?;
    let id = job.id.clone();
    // The events, printed as they happen.
    let stopping = Arc::new(AtomicBool::new(false));
    let follower = arguments.follow.then(|| {
        let service = Arc::clone(&service);
        let stopping = Arc::clone(&stopping);
        let id = id.clone();
        std::thread::spawn(move || {
            let params = EventsSubscribeParams {
                job_id: Some(id),
                ..EventsSubscribeParams::default()
            };
            let mut sink = |reply: &antinomie_service::api::ops::Reply| {
                if let Some(event) = &reply.event {
                    print_event(event as &Event);
                }
                Ok(())
            };
            let _ = subscribe::stream(
                service.store(),
                0,
                &params,
                &link::me(),
                service.hello(),
                &Limits::default(),
                &AtomicBool::new(false),
                &stopping,
                &mut sink,
            );
        })
    });
    let began = Instant::now();
    let limit = context.timeout();
    let exit = daemon.supervise(&signals::DaemonSignals::new(), &|service| {
        limit.is_some_and(|l| began.elapsed() >= l)
            || service.store.get(&id).is_ok_and(|j| j.state.is_terminal())
    });
    stopping.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(follower) = follower {
        let _ = follower.join();
    }
    let job = service.store.get(&id).map_err(api)?;
    let mut files = Vec::new();
    if let Some(out) = &arguments.out {
        let mut paths = Vec::new();
        for artifact in &job.artifacts {
            let (_, location) = service.store.artifact(&artifact.id).map_err(api)?;
            let path = antinomie_service::daemon::artifacts::resolve(
                &service.store.job_dir(&job.id),
                &location,
            )
            .map_err(api)?;
            paths.push(json!({"artifact": artifact, "path": path}));
        }
        files = copy_reports(&paths, out)?;
    }
    drop(service);
    stop(daemon)?;
    let replayed = submitted["replayed"].as_bool().unwrap_or(false);
    // Direct mode always waits.
    let reply = finish(&job, replayed, files, true, arguments.verdict_exit);
    Ok(match exit {
        DaemonExit::Hurried => reply.with_exit(Exit::Interrupted),
        _ if signals::interrupted() => reply.with_exit(Exit::Interrupted),
        _ => reply,
    })
}

fn stop(daemon: Daemon<Backend>) -> Result<(), CliError> {
    let mut backend = daemon
        .finish()
        .map_err(|error| CliError::internal(error.message))?;
    let _ = backend.shutdown();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        submit: Submit,
    }

    fn parse(args: &[&str]) -> Submit {
        let mut all = vec!["submit"];
        all.extend_from_slice(args);
        Wrapper::try_parse_from(all).unwrap().submit
    }

    #[test]
    fn the_flags_become_the_spec_of_the_contract() {
        let spec = spec_of(&parse(&[
            "f.elf",
            "--policy",
            "fast",
            "--priority",
            "7",
            "--label",
            "ci=yes",
            "--timeout-run",
            "60",
            "--as",
            "1000:100",
            "--route",
            "inet_sim",
            "--static",
            "strings,entropy",
            "--formats",
            "html,json",
            "--evidence-bundle",
            "--no-defang",
            "--idempotency-key",
            "k1",
            "--args",
            "-v",
            "x",
        ]))
        .unwrap();
        assert_eq!(
            spec,
            json!({
                "sample": {}, "policy": "fast", "priority": 7, "labels": {"ci": "yes"},
                "idempotency_key": "k1",
                "overrides": {
                    "timeout_s": 60, "args": ["-v", "x"], "run_as": {"uid": 1000, "gid": 100},
                    "route": "inet_sim", "static_checks": ["strings", "entropy"],
                    "reports": ["html", "json"], "report_bundle": true, "report_defang": false
                }
            })
        );
        let spec: antinomie_service::api::spec::JobSpec = serde_json::from_value({
            let mut s = spec;
            s["sample"]["sha256"] = json!("ab".repeat(32));
            s
        })
        .unwrap();
        assert_eq!(spec.overrides.timeout_s, Some(60));
    }

    #[test]
    fn the_flags_that_wait_and_the_ones_that_collide_are_kept_apart() {
        assert!(!parse(&["f"]).waits());
        assert!(parse(&["f", "--follow"]).waits());
        assert!(parse(&["f", "--verdict-exit"]).waits());
        assert!(parse(&["f", "--out", "d"]).waits());
        assert!(Wrapper::try_parse_from(["submit"]).is_err());
        assert!(Wrapper::try_parse_from(["submit", "f", "--sha256", "aa"]).is_err());
        assert!(Wrapper::try_parse_from(["submit", "f", "--defang", "--no-defang"]).is_err());
        assert!(spec_of(&parse(&["f", "--as", "nobody"])).is_err());
        assert!(spec_of(&parse(&["f", "--label", "novalue"])).is_err());
    }

    #[test]
    fn an_upload_name_has_no_path_or_control_characters() {
        assert_eq!(upload_name(Path::new("/x/ok.sh")).as_deref(), Some("ok.sh"));
        assert_eq!(
            upload_name(Path::new("/x/a\u{1b}[2Jb")).as_deref(),
            Some("a[2Jb")
        );
        let long = format!("/x/{}", "é".repeat(100));
        assert!(upload_name(Path::new(&long)).unwrap().len() <= 128);
    }
}
