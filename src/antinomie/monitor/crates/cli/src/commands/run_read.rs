// SPDX-License-Identifier: GPL-3.0-only
//! `recording list`, `recording show` and `recording export` (design 3.4.3,
//! 5.12.10): look at the recordings of the data directory through the
//! read-only query API, the one the web pages use. No engine lock, nothing written into a recording; the
//! export writes only under `--out`.
use super::{query::Client, recording::RUN_HELP};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use clap::{Args, Subcommand};
use serde_json::{Map, Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

/// The parts `run export --part` takes, in the order they are written.
pub const PARTS: [&str; 10] = [
    "trace",
    "processes",
    "findings",
    "indicators",
    "files",
    "network",
    "timeline",
    "analysis",
    "custody",
    "artifacts",
];

/// The parts that need the Triage index of the run (the window's tables):
/// building it reads the whole recording, which for a very large one takes
/// long. `--no-triage` leaves them out.
pub const TRIAGE_PARTS: [&str; 5] = ["findings", "indicators", "files", "network", "timeline"];

/// Bytes of one file version or artifact an export fetches.
const BYTES_CAP: u64 = 64 << 20;
/// What `--sensitive` fetches besides: the captured argument bytes of calls
/// (fields and bytes in all) and the frames of the captures (packets in all).
/// An export that reaches a cap says so in its file list (`truncated`).
const CAPTURED_FIELDS_CAP: usize = 10_000;
const CAPTURED_BYTES_CAP: u64 = 256 << 20;
const PACKETS_CAP: usize = 100_000;
/// `recording.captured.read` returns at most this many bytes per call.
const CAPTURED_CHUNK: u64 = 64 << 10;

/// What an export asks of the query API: the CLI's client, or a fake in a test.
trait Reads {
    fn call(&self, op: &str, params: Value) -> Result<Value, CliError>;
}

impl Reads for Client<'_> {
    fn call(&self, op: &str, params: Value) -> Result<Value, CliError> {
        Client::call(self, op, params)
    }
}

/// `recording ...`: the recordings of the data directory (a recording is
/// what the engine captured while a program ran; `run exec` makes one, and so
/// does every run of Auto mode).
#[derive(Subcommand, Debug)]
pub enum Recording {
    /// List the recordings of the data directory; no engine lock needed.
    /// Asks the daemon when one answers.
    List(List),
    /// Show one recording: its state, phase and artifacts; `--summary` adds
    /// the Triage summary. No engine lock needed. Asks the daemon when one
    /// answers.
    Show(Show),
    /// Write a recording as NDJSON and evidence files into --out. No engine
    /// lock needed. Asks the daemon when one answers; the files are written by
    /// this command, never by the daemon.
    Export(Export),
}

pub fn run(command: &Recording, context: &Context) -> Result<Reply, CliError> {
    match command {
        Recording::List(arguments) => list(arguments, context),
        Recording::Show(arguments) => show(arguments, context),
        Recording::Export(arguments) => export(arguments, context),
    }
}

#[derive(Args, Debug)]
pub struct List {
    /// Only runs of this VM.
    #[arg(long, value_name = "ID")]
    pub vm: Option<String>,
    /// Only runs of this library sample (SHA-256).
    #[arg(long, value_name = "SHA256")]
    pub sample: Option<String>,
    /// Only recordings made by this run of Auto mode (`r_...`).
    #[arg(long, value_name = "RUN")]
    pub run: Option<String>,
    /// Only runs in this state (running, finished, stopped, interrupted, ...).
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,
    /// Only runs started since then: a span such as 90m, 24h or 7d, or a Unix
    /// time in milliseconds.
    #[arg(long, value_name = "SPAN")]
    pub since: Option<String>,
    /// Rows to return (1 to 500).
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Where the last page stopped (`next_cursor`).
    #[arg(long, value_name = "CURSOR")]
    pub cursor: Option<String>,
}

#[derive(Args, Debug)]
pub struct Show {
    #[arg(help = RUN_HELP)]
    pub run: String,
    /// Add the Triage summary (`recording.summary`); indexes the run first.
    #[arg(long)]
    pub summary: bool,
}

#[derive(Args, Debug)]
pub struct Export {
    #[arg(help = RUN_HELP)]
    pub run: String,
    /// Parts to write, comma separated: trace, processes, findings,
    /// indicators, files, network, timeline, analysis, custody, artifacts.
    /// Default: all but the bytes of sensitive evidence.
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    pub part: Vec<String>,
    /// Also write the bytes the sample produced: the frames of the recorded
    /// packets (part network), the captured bytes of calls (part trace), the
    /// capture, memory and core files and file copies (part artifacts) and the
    /// contents of changed files (part files). With a daemon each read is
    /// written to its service log.
    #[arg(long)]
    pub sensitive: bool,
    /// Leave out the parts that need the Triage index (findings, indicators,
    /// files, network, timeline), so a very large recording is not indexed
    /// in full. Naming one of them with --part is an error.
    #[arg(long)]
    pub no_triage: bool,
    /// The folder to write into; created when missing. Nothing is written
    /// anywhere else.
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
}

/// `--since` as Unix milliseconds.
pub fn parse_since(text: &str, now_ms: u64) -> Result<u64, CliError> {
    let bad = || {
        CliError::invalid(format!(
            "{text:?} is not a span such as 90m, 24h or 7d, or a Unix time in milliseconds"
        ))
        .with_field("since")
    };
    let text = text.trim();
    if let Some(last) = text.chars().last().filter(|c| c.is_ascii_alphabetic()) {
        let number: u64 = text[..text.len() - 1].parse().map_err(|_| bad())?;
        let seconds = match last {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(bad()),
        };
        return Ok(now_ms.saturating_sub(number.saturating_mul(seconds * 1000)));
    }
    text.parse().map_err(|_| bad())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub fn list(arguments: &List, context: &Context) -> Result<Reply, CliError> {
    let mut params = Map::new();
    let mut put = |name: &str, value: Option<Value>| {
        if let Some(value) = value {
            params.insert(name.into(), value);
        }
    };
    put("vm_id", arguments.vm.as_ref().map(|v| json!(v)));
    put("sample_sha256", arguments.sample.as_ref().map(|v| json!(v)));
    put("from_run", arguments.run.as_ref().map(|v| json!(v)));
    put("state", arguments.state.as_ref().map(|v| json!(v)));
    put(
        "since_ms",
        arguments
            .since
            .as_deref()
            .map(|text| parse_since(text, now_ms()))
            .transpose()?
            .map(|v| json!(v)),
    );
    put("limit", arguments.limit.map(|v| json!(v)));
    put("cursor", arguments.cursor.as_ref().map(|v| json!(v)));
    let page = Client::new(context)?.call("recording.list", Value::Object(params))?;
    let items = page["items"].as_array().cloned().unwrap_or_default();
    let next = page["next_cursor"].as_str().map(str::to_owned);
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|run| {
            vec![
                text(&run["run_id"]).chars().take(8).collect(),
                text(&run["vm_id"]),
                state_cell(run),
                text(&run["phase"]),
                time(&run["started_ms"]),
                text(&run["program"]),
            ]
        })
        .collect();
    let mut human = table(
        &["RUN", "VM", "STATE", "PHASE", "STARTED", "PROGRAM"],
        &rows,
    );
    if let Some(next) = &next {
        human.push_str(&format!("more: --cursor {next}\n"));
    }
    Ok(Reply::list(items, next).with_human(human))
}

pub fn show(arguments: &Show, context: &Context) -> Result<Reply, CliError> {
    let client = Client::new(context)?;
    let key = client.resolve(&arguments.run)?;
    let params = json!({"recording_key": key});
    let reply = client.call("recording.get", params.clone())?;
    let mut value = reply["value"].clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("generation".into(), reply["generation"].clone());
    }
    if arguments.summary {
        let summary = client.call("recording.summary", params)?;
        value["summary"] = summary["value"].clone();
    }
    let human = show_text(&value);
    Ok(Reply::value(value).with_human(human))
}

/// The STATE cell: `held` while the run is held open for a persisted copy
/// (its `state` still says how the tree ended), else the state.
fn state_cell(run: &Value) -> String {
    if run["held"].is_string() {
        "held".into()
    } else {
        text(&run["state"])
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn time(value: &Value) -> String {
    value.as_u64().map_or_else(
        || "-".into(),
        |ms| crate::logging::iso_time(ms).replace('T', " "),
    )
}

fn show_text(run: &Value) -> String {
    let mut out = block(&[
        ("run", text(&run["run_id"])),
        ("run key", text(&run["recording_key"])),
        ("vm", text(&run["vm_id"])),
        ("boot", text(&run["boot_id"])),
        ("state", text(&run["state"])),
        ("held", text(&run["held"])),
        ("phase", text(&run["phase"])),
        ("started", time(&run["started_ms"])),
        ("ended", time(&run["ended_ms"])),
        ("program", text(&run["program"])),
        ("sample", text(&run["sample_sha256"])),
        ("exit", text(&run["exit"])),
        ("generation", text(&run["generation"])),
        ("directory", text(&run["directory"])),
    ]);
    if let Some(summary) = run.get("summary").filter(|s| s.is_object()) {
        let counts = &summary["counts"];
        out.push_str(&format!(
            "\nassessment: {} (highest tier {})\ncounts: {} processes · {} findings · {} indicators ({} matched) · {} techniques · {} files changed · {} endpoints · {} domains\n{}\n",
            text(&summary["assessment"]),
            text(&summary["highest_tier"]),
            text(&counts["processes"]),
            text(&counts["findings"]),
            text(&counts["indicators"]),
            text(&counts["indicators_matched"]),
            text(&counts["techniques"]),
            text(&counts["files_changed"]),
            text(&counts["endpoints"]),
            text(&counts["domains"]),
            text(&summary["basis"]),
        ));
    }
    out
}

// ---------------------------------------------------------------------
// run export

/// One file of an export.
struct Out {
    root: PathBuf,
    files: Vec<Value>,
}

impl Out {
    fn open(&mut self, name: &str) -> Result<(fs::File, PathBuf), CliError> {
        let path = self.root.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| CliError::io(parent, &e))?;
        }
        let file = fs::File::create(&path).map_err(|e| CliError::io(&path, &e))?;
        Ok((file, path))
    }

    fn lines(&mut self, name: &str, items: &[Value]) -> Result<(), CliError> {
        let (mut file, path) = self.open(name)?;
        for item in items {
            serde_json::to_writer(&mut file, item)
                .map_err(|e| CliError::internal(e.to_string()))?;
            file.write_all(b"\n").map_err(|e| CliError::io(&path, &e))?;
        }
        self.files.push(json!({"file": name, "rows": items.len()}));
        Ok(())
    }

    fn bytes(&mut self, name: &str, data: &[u8]) -> Result<(), CliError> {
        let (mut file, path) = self.open(name)?;
        file.write_all(data).map_err(|e| CliError::io(&path, &e))?;
        self.files.push(json!({"file": name, "bytes": data.len()}));
        Ok(())
    }
}

/// A file name that cannot leave the folder: the last component, with
/// anything but `[A-Za-z0-9._-]` replaced.
fn safe_name(name: &str) -> String {
    let last = Path::new(name)
        .file_name()
        .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());
    let cleaned: String = last
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    match cleaned.as_str() {
        "" | "." | ".." => "file".to_owned(),
        _ => cleaned.chars().take(96).collect(),
    }
}

/// Every page of an operation, as the items.
fn all_pages(
    client: &dyn Reads,
    op: &str,
    params: Value,
    partial: &mut bool,
) -> Result<Vec<Value>, CliError> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    // A page that does not fit a socket line (2 MiB) is asked again with a
    // quarter of the rows; the cursor stays valid because the limit is not part of it.
    let mut limit: Option<u64> = None;
    loop {
        let mut request = params.clone();
        if let Some(object) = request.as_object_mut() {
            if let Some(cursor) = &cursor {
                object.insert("cursor".into(), json!(cursor));
            }
            if let Some(limit) = limit {
                object.insert("limit".into(), json!(limit));
            }
        }
        let page = match client.call(op, request) {
            Err(error) if error.code == ErrorCode::PayloadTooLarge && limit != Some(1) => {
                limit = Some(limit.map_or(100, |limit| (limit / 4).max(1)));
                continue;
            }
            other => other?,
        };
        if page["partial"] == json!(true) {
            *partial = true;
        }
        items.extend(page["items"].as_array().cloned().unwrap_or_default());
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => return Ok(items),
        }
    }
}

/// The bytes of a ranged read, in calls of at most 1 MiB.
fn ranged(client: &dyn Reads, op: &str, params: &Value, size: u64) -> Result<Vec<u8>, CliError> {
    use base64_lite::decode;
    let mut data = Vec::new();
    let mut offset = 0u64;
    let size = size.min(BYTES_CAP);
    while offset < size {
        let len = (size - offset).min(1 << 20);
        let mut request = params.clone();
        request["range"] = json!({"offset": offset, "len": len});
        let reply = client.call(op, request)?;
        let chunk = decode(reply["value"]["data_b64"].as_str().unwrap_or_default());
        if chunk.is_empty() {
            break;
        }
        offset += chunk.len() as u64;
        data.extend(chunk);
    }
    Ok(data)
}

/// Standard base64, as the replies carry bytes.
mod base64_lite {
    pub fn decode(text: &str) -> Vec<u8> {
        let value = |c: u8| match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        };
        let mut out = Vec::with_capacity(text.len() / 4 * 3);
        let (mut acc, mut bits) = (0u32, 0u32);
        for byte in text.bytes() {
            let Some(v) = value(byte) else { continue };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }
}

pub fn export(arguments: &Export, context: &Context) -> Result<Reply, CliError> {
    let mut parts: Vec<&str> = Vec::new();
    if arguments.part.is_empty() {
        parts.extend(
            PARTS
                .iter()
                .filter(|part| !(arguments.no_triage && TRIAGE_PARTS.contains(part))),
        );
    }
    for name in &arguments.part {
        let name = name.trim();
        match PARTS.iter().find(|part| **part == name) {
            Some(part) if arguments.no_triage && TRIAGE_PARTS.contains(part) => {
                return Err(CliError::invalid(format!(
                    "--no-triage leaves the part {part:?} out; it needs the Triage index"
                ))
                .with_field("part"));
            }
            Some(part) => {
                if !parts.contains(part) {
                    parts.push(part);
                }
            }
            None => {
                return Err(CliError::invalid(format!(
                    "unknown part {name:?}; use {}",
                    PARTS.join(", ")
                ))
                .with_field("part"));
            }
        }
    }
    if arguments.out.exists() && !arguments.out.is_dir() {
        return Err(CliError::invalid(format!(
            "{} exists and is not a folder",
            arguments.out.display()
        ))
        .with_field("out"));
    }
    let client = Client::new(context)?;
    let key = client.resolve(&arguments.run)?;
    fs::create_dir_all(&arguments.out).map_err(|e| CliError::io(&arguments.out, &e))?;
    let mut out = Out {
        root: arguments.out.clone(),
        files: Vec::new(),
    };
    let params = json!({"recording_key": key});
    let mut partial = false;
    export_parts(
        &parts,
        &client,
        &params,
        arguments.sensitive,
        &mut out,
        &mut partial,
        RETRY_PAUSE,
    )?;
    let value = json!({
        "recording_key": key,
        "out": arguments.out,
        "parts": parts,
        "triage": !arguments.no_triage,
        "files": out.files,
        "partial": partial,
    });
    let human = format!(
        "wrote {} files to {}{}\n",
        out.files.len(),
        arguments.out.display(),
        if partial {
            " (the recording is partial)"
        } else {
            ""
        }
    );
    Ok(Reply::value(value).with_human(human))
}

/// Pause before a read that passed its deadline is asked again.
const RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(2);
/// How many times a read that passed its deadline is asked again. Every
/// read has its own deadline (the service's, per page), so an export of many
/// parts never shares one; a slow page that passed it gets a fresh one, and
/// the Triage index and the caches the first try warmed make it faster.
const READ_RETRIES: u32 = 2;

fn is_read_timeout(error: &CliError) -> bool {
    error.code == ErrorCode::Unavailable && error.details["reason"] == json!("read_timeout")
}

/// Asks again a read that passed its own deadline, and names the read that
/// ran out when it still does.
struct Patient<'a> {
    inner: &'a dyn Reads,
    pause: std::time::Duration,
}

impl Reads for Patient<'_> {
    fn call(&self, op: &str, params: Value) -> Result<Value, CliError> {
        let mut tries = 0;
        loop {
            match self.inner.call(op, params.clone()) {
                Err(error) if is_read_timeout(&error) => {
                    if tries >= READ_RETRIES {
                        let mut details = error.details.clone();
                        details["op"] = json!(op);
                        let mut named = CliError::new(
                            error.code,
                            format!("the read {op} passed its deadline {} times", tries + 1),
                        )
                        .with_details(details);
                        named.exit = error.exit;
                        return Err(named);
                    }
                    tries += 1;
                    std::thread::sleep(self.pause);
                }
                other => return other,
            }
        }
    }
}

/// Every part in turn, each read under its own deadline. A part that cannot
/// be read says which one (`details.part`) in the error.
fn export_parts(
    parts: &[&str],
    client: &dyn Reads,
    params: &Value,
    sensitive: bool,
    out: &mut Out,
    partial: &mut bool,
    pause: std::time::Duration,
) -> Result<(), CliError> {
    let patient = Patient {
        inner: client,
        pause,
    };
    for part in parts {
        export_part(part, &patient, params, sensitive, out, partial).map_err(|mut error| {
            if is_read_timeout(&error) || error.details.get("op").is_some() {
                error.message = format!("export part {part}: {}", error.message);
                error.details["part"] = json!(part);
                let done: Vec<&str> = parts.iter().take_while(|p| *p != part).copied().collect();
                error.details["parts_done"] = json!(done);
            }
            error
        })?;
    }
    Ok(())
}

/// The files of one part.
fn export_part(
    part: &str,
    client: &dyn Reads,
    run: &Value,
    sensitive: bool,
    out: &mut Out,
    partial: &mut bool,
) -> Result<(), CliError> {
    let with = |extra: Value| {
        let mut params = run.clone();
        if let (Some(base), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
            base.extend(extra.clone());
        }
        params
    };
    let mut rows = |client: &dyn Reads, op: &str, params: Value| -> Result<Vec<Value>, CliError> {
        all_pages(client, op, params, partial)
    };
    match part {
        "trace" => {
            let items = rows(client, "recording.trace.page", run.clone())?;
            out.lines("trace.ndjson", &items)?;
            if sensitive {
                export_captured(client, run, &items, out)?;
            }
        }
        "processes" => {
            let items = rows(client, "recording.process.tree", run.clone())?;
            out.lines("processes.ndjson", &items)?;
        }
        "findings" => {
            let items = rows(client, "recording.findings.list", run.clone())?;
            out.lines("findings.ndjson", &items)?;
        }
        "indicators" => {
            let items = rows(client, "recording.indicators.list", run.clone())?;
            out.lines("indicators.ndjson", &items)?;
        }
        "files" => {
            for tab in [
                "opened",
                "created",
                "read",
                "written",
                "deleted",
                "renamed",
                "executed",
                "attributes",
                "probed",
                "other",
                "changed",
            ] {
                let items = rows(client, "recording.files.list", with(json!({"tab": tab})))?;
                out.lines(&format!("files-{tab}.ndjson"), &items)?;
                if sensitive && tab == "changed" {
                    export_file_contents(client, run, &items, out)?;
                }
            }
        }
        "network" => {
            let summary = client.call("recording.network.summary", run.clone())?;
            out.lines("network-summary.ndjson", &[summary["value"].clone()])?;
            for tab in ["endpoints", "domains", "urls", "tls", "dns", "http"] {
                let items = rows(client, "recording.network.list", with(json!({"tab": tab})))?;
                out.lines(&format!("network-{tab}.ndjson"), &items)?;
            }
            match client.call("recording.network.captures", run.clone()) {
                Ok(page) => {
                    let items = page["items"].as_array().cloned().unwrap_or_default();
                    out.lines("network-captures.ndjson", &items)?;
                }
                Err(error) if error.code == ErrorCode::NotFound => {}
                Err(error) => return Err(error),
            }
            if sensitive {
                export_packets(client, run, out, partial)?;
            }
        }
        "timeline" => {
            let items = rows(client, "recording.timeline", run.clone())?;
            out.lines("timeline.ndjson", &items)?;
        }
        "analysis" => match client.call("recording.analysis.list", run.clone()) {
            Ok(page) => {
                let sections = page["items"].as_array().cloned().unwrap_or_default();
                out.lines("analysis.ndjson", &sections)?;
                for section in &sections {
                    let kind = text(&section["kind"]);
                    if section["rows"].as_u64().unwrap_or(0) == 0 {
                        continue;
                    }
                    let items = rows(
                        client,
                        "recording.analysis.section",
                        with(json!({"kind": kind})),
                    )?;
                    out.lines(&format!("analysis-{}.ndjson", safe_name(&kind)), &items)?;
                }
            }
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(error),
        },
        "custody" => {
            let items = rows(client, "recording.custody.list", run.clone())?;
            out.lines("custody.ndjson", &items)?;
        }
        "artifacts" => {
            let items = rows(client, "recording.artifact.list", run.clone())?;
            out.lines("artifacts.ndjson", &items)?;
            for item in &items {
                let is_sensitive = item["sensitive"] == json!(true);
                if is_sensitive && !sensitive {
                    continue;
                }
                let size = item["size"].as_u64().unwrap_or(0);
                let id = text(&item["id"]);
                let data = ranged(
                    client,
                    "recording.artifact.get",
                    &with(json!({"artifact_id": id})),
                    size,
                )?;
                out.bytes(
                    &format!(
                        "artifacts/{}-{}",
                        id.chars().take(12).collect::<String>(),
                        safe_name(&text(&item["name"]))
                    ),
                    &data,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The captured argument bytes of the calls (`--sensitive`, part `trace`):
/// one file `captured/<stream>-<task>-<call>-e<event>-<key>` per field and
/// `captured.ndjson` naming each. Only calls whose row shows captured bytes
/// are opened. The bytes are fetched with `recording.captured.read`, which
/// the daemon checks and logs as a sensitive read.
fn export_captured(
    reads: &dyn Reads,
    run: &Value,
    rows: &[Value],
    out: &mut Out,
) -> Result<(), CliError> {
    let (mut fields, mut total, mut truncated) = (0usize, 0u64, false);
    let mut index = Vec::new();
    'rows: for row in rows {
        let shows_bytes = row["args_preview"].as_array().is_some_and(|args| {
            args.iter()
                .any(|a| a["captured_len"].as_u64().unwrap_or(0) > 0)
        });
        if !shows_bytes {
            continue;
        }
        let mut request = run.clone();
        request["ref"] = row["ref"].clone();
        let call = match reads.call("recording.trace.get", request) {
            Ok(call) => call,
            Err(error) if error.code == ErrorCode::NotFound => continue,
            Err(error) => return Err(error),
        };
        let invocation = &call["value"];
        let mut events: Vec<&Value> = ["entry", "exit", "task_exit"]
            .iter()
            .map(|name| &invocation[*name])
            .filter(|event| event.is_object())
            .collect();
        for list in ["async_events", "kernel_notes"] {
            events.extend(invocation[list].as_array().into_iter().flatten());
        }
        for event in events {
            for field in event["fields"].as_array().into_iter().flatten() {
                let size = field["captured_len"].as_u64().unwrap_or(0);
                if size == 0 {
                    continue;
                }
                if fields >= CAPTURED_FIELDS_CAP || total >= CAPTURED_BYTES_CAP {
                    truncated = true;
                    break 'rows;
                }
                let mut data = Vec::new();
                while (data.len() as u64) < size.min(CAPTURED_BYTES_CAP - total) {
                    let want = (size - data.len() as u64).min(CAPTURED_CHUNK);
                    let mut request = run.clone();
                    request["field"] = field["field"].clone();
                    request["offset"] = json!(data.len().to_string());
                    request["len"] = json!(want);
                    let reply = reads.call("recording.captured.read", request)?;
                    let chunk = base64_lite::decode(
                        reply["value"]["data_b64"].as_str().unwrap_or_default(),
                    );
                    if chunk.is_empty() {
                        break;
                    }
                    data.extend(chunk);
                }
                let name = format!(
                    "captured/{}-{}-{}-e{}-{}",
                    text(&row["ref"]["stream"]),
                    text(&row["ref"]["task"]),
                    text(&row["ref"]["call"]),
                    text(&event["event_seq"]),
                    safe_name(&text(&field["key"]))
                );
                out.bytes(&name, &data)?;
                total += data.len() as u64;
                fields += 1;
                index.push(json!({
                    "ref": row["ref"], "event_seq": event["event_seq"], "key": field["key"],
                    "arg": field["arg"], "layout": field["layout"],
                    "captured_len": field["captured_len"], "complete": field["complete"],
                    "file": name, "bytes": data.len(),
                }));
            }
        }
    }
    if !index.is_empty() || truncated {
        out.lines("captured.ndjson", &index)?;
        if truncated && let Some(last) = out.files.last_mut() {
            last["truncated"] = json!(true);
        }
    }
    Ok(())
}

/// The frames of the captures (`--sensitive`, part `network`): one file
/// `network-packets-<capture>.ndjson` per capture, a line `{n, frame_len,
/// bytes_b64}` per packet, fetched with `recording.network.packet`.
fn export_packets(
    reads: &dyn Reads,
    run: &Value,
    out: &mut Out,
    partial: &mut bool,
) -> Result<(), CliError> {
    let captures = match reads.call("recording.network.captures", run.clone()) {
        Ok(page) => page["items"].as_array().cloned().unwrap_or_default(),
        Err(error) if error.code == ErrorCode::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut count = 0usize;
    for capture in &captures {
        let id = text(&capture["capture_id"]);
        let mut params = run.clone();
        params["capture_id"] = json!(id);
        let listed = all_pages(reads, "recording.network.packets", params, partial)?;
        let mut lines = Vec::new();
        let mut truncated = false;
        for packet in &listed {
            if count >= PACKETS_CAP {
                truncated = true;
                break;
            }
            let mut request = run.clone();
            request["capture_id"] = json!(id);
            request["n"] = packet["n"].clone();
            let reply = reads.call("recording.network.packet", request)?;
            let detail = &reply["value"];
            lines.push(json!({
                "n": packet["n"],
                "frame_len": detail["frame_len"],
                "bytes_b64": detail["bytes"],
            }));
            count += 1;
        }
        // The id is the service's, but it is still only ever a file name.
        let flat: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .take(64)
            .collect();
        let name = format!("network-packets-{flat}.ndjson");
        out.lines(&name, &lines)?;
        if truncated && let Some(last) = out.files.last_mut() {
            last["truncated"] = json!(true);
        }
    }
    Ok(())
}

/// The contents of the changed files whose versions are available.
fn export_file_contents(
    client: &dyn Reads,
    run: &Value,
    changed: &[Value],
    out: &mut Out,
) -> Result<(), CliError> {
    for file in changed {
        let id = text(&file["file_id"]);
        let mut request = run.clone();
        request["file_id"] = json!(id);
        let versions = match client.call("recording.files.versions", request) {
            Ok(versions) => versions,
            Err(error) if error.code == ErrorCode::NotFound => continue,
            Err(error) => return Err(error),
        };
        for version in versions["value"]["versions"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if version["available"] != json!(true) {
                continue;
            }
            let mut params = run.clone();
            params["version_id"] = version["version_id"].clone();
            let data = ranged(
                client,
                "recording.files.content",
                &params,
                version["size"].as_u64().unwrap_or(0),
            )?;
            out.bytes(
                &format!(
                    "files/{}-{}-{}",
                    id,
                    text(&version["kind"]),
                    safe_name(&text(&file["path"]))
                ),
                &data,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_run_lists_as_held_and_shows_why() {
        let held = json!({"run_id": "r", "state": "finished", "held": "Held: persisted copy running (pid 1050, .e)"});
        assert_eq!(state_cell(&held), "held");
        assert!(show_text(&held).contains("Held: persisted copy running (pid 1050, .e)"));
        assert_eq!(state_cell(&json!({"state": "finished"})), "finished");
    }

    #[test]
    fn since_is_a_span_or_a_unix_time() {
        assert_eq!(
            parse_since("24h", 100_000_000).unwrap(),
            100_000_000 - 86_400_000
        );
        assert_eq!(
            parse_since("90m", 10_000_000).unwrap(),
            10_000_000 - 5_400_000
        );
        assert_eq!(parse_since("1700000000000", 5).unwrap(), 1_700_000_000_000);
        assert_eq!(parse_since("7d", 1).unwrap(), 0, "never below zero");
        for bad in ["", "h", "5x", "-3", "1.5h"] {
            assert!(parse_since(bad, 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_exported_name_cannot_leave_the_folder() {
        assert_eq!(safe_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_name("/abs/x.bin"), "x.bin");
        assert_eq!(safe_name(".."), "file");
        assert_eq!(safe_name("a b$c"), "a_b_c");
        assert_eq!(safe_name(""), "file");
    }

    /// Answers from a script and remembers what was asked.
    struct Fake {
        asked: std::cell::RefCell<Vec<(String, Value)>>,
    }

    impl Reads for Fake {
        fn call(&self, op: &str, params: Value) -> Result<Value, CliError> {
            self.asked
                .borrow_mut()
                .push((op.to_owned(), params.clone()));
            let b64 = |bytes: &[u8]| {
                const A: &[u8; 64] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let mut out = String::new();
                for chunk in bytes.chunks(3) {
                    let n = chunk
                        .iter()
                        .enumerate()
                        .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
                    for i in 0..4 {
                        if i <= chunk.len() {
                            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                        } else {
                            out.push('=');
                        }
                    }
                }
                out
            };
            Ok(match op {
                "recording.trace.get" => json!({"value": {
                    "ref": params["ref"],
                    "entry": {"event_seq": "7", "fields": [
                        {"field": "obj:path", "key": "path", "arg": 0, "layout": "cstring",
                         "captured_len": 150000, "complete": true},
                        {"field": "obj:none", "key": "none", "captured_len": 0}
                    ]},
                    "exit": null, "task_exit": null,
                    "async_events": [], "kernel_notes": []
                }}),
                "recording.captured.read" => {
                    let offset: usize = params["offset"].as_str().unwrap().parse().unwrap();
                    let len = params["len"].as_u64().unwrap() as usize;
                    // The read size is the service's: 64 KiB at most.
                    assert!(len <= 65536, "{len}");
                    let bytes: Vec<u8> = (offset..offset + len).map(|i| (i % 251) as u8).collect();
                    json!({"value": {"offset": offset.to_string(), "len": len, "data_b64": b64(&bytes)}})
                }
                "recording.network.captures" => json!({"items": [{"capture_id": "cap/1"}]}),
                "recording.network.packets" => {
                    json!({"items": [{"n": 1}, {"n": 2}, {"n": 3}], "next_cursor": null})
                }
                "recording.network.packet" => {
                    let n = params["n"].as_u64().unwrap() as u8;
                    json!({"value": {"n": n, "frame_len": 3, "bytes": b64(&[n, n, n])}})
                }
                other => panic!("unexpected {other}"),
            })
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ant-t421-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Times out `fail_first` times on `slow_op`, then answers.
    struct Slow {
        slow_op: &'static str,
        fail_first: std::cell::Cell<u32>,
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl Reads for Slow {
        fn call(&self, op: &str, _params: Value) -> Result<Value, CliError> {
            self.asked.borrow_mut().push(op.to_owned());
            if op == self.slow_op && self.fail_first.get() > 0 {
                self.fail_first.set(self.fail_first.get() - 1);
                return Err(CliError::new(
                    ErrorCode::Unavailable,
                    "the read passed its deadline and was cancelled",
                )
                .with_details(json!({"reason": "read_timeout"})));
            }
            Ok(json!({"items": [{"n": 1}], "next_cursor": null}))
        }
    }

    #[test]
    fn a_slow_read_gets_its_own_fresh_deadline_and_the_export_goes_on() {
        let dir = scratch("slow-retry");
        let slow = Slow {
            slow_op: "recording.trace.page",
            fail_first: 2.into(),
            asked: Default::default(),
        };
        let mut out = Out {
            root: dir.clone(),
            files: Vec::new(),
        };
        let mut partial = false;
        export_parts(
            &["trace", "processes", "findings", "indicators"],
            &slow,
            &json!({"recording_key": "k"}),
            false,
            &mut out,
            &mut partial,
            std::time::Duration::ZERO,
        )
        .unwrap();
        assert_eq!(out.files.len(), 4);
        assert_eq!(slow.asked.borrow().len(), 3 + 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_read_that_keeps_timing_out_names_the_part_and_the_read() {
        let dir = scratch("slow-name");
        let slow = Slow {
            slow_op: "recording.findings.list",
            fail_first: 99.into(),
            asked: Default::default(),
        };
        let mut out = Out {
            root: dir.clone(),
            files: Vec::new(),
        };
        let mut partial = false;
        let error = export_parts(
            &["trace", "processes", "findings", "indicators"],
            &slow,
            &json!({"recording_key": "k"}),
            false,
            &mut out,
            &mut partial,
            std::time::Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(
            error.message.starts_with("export part findings:"),
            "{}",
            error.message
        );
        assert_eq!(error.details["part"], json!("findings"));
        assert_eq!(error.details["op"], json!("recording.findings.list"));
        assert_eq!(error.details["reason"], json!("read_timeout"));
        assert_eq!(error.details["parts_done"], json!(["trace", "processes"]));
        assert_eq!(out.files.len(), 2, "the finished parts stay written");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn captured_call_bytes_are_read_in_chunks_and_written_under_out() {
        let dir = scratch("captured");
        let fake = Fake {
            asked: Default::default(),
        };
        let mut out = Out {
            root: dir.clone(),
            files: Vec::new(),
        };
        let run = json!({"recording_key": "k"});
        let rows = vec![
            json!({"ref": {"stream": "1", "task": "2", "call": "3"},
                   "args_preview": [{"key": "path", "captured_len": 150000}]}),
            // No captured bytes in the row: the call is not even opened.
            json!({"ref": {"stream": "1", "task": "2", "call": "4"},
                   "args_preview": [{"key": "fd", "captured_len": 0}]}),
        ];
        export_captured(&fake, &run, &rows, &mut out).unwrap();
        let data = fs::read(dir.join("captured/1-2-3-e7-path")).unwrap();
        assert_eq!(data.len(), 150_000);
        assert!(data.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
        let asked = fake.asked.borrow();
        assert_eq!(
            asked
                .iter()
                .filter(|(op, _)| op == "recording.trace.get")
                .count(),
            1
        );
        assert_eq!(
            asked
                .iter()
                .filter(|(op, _)| op == "recording.captured.read")
                .count(),
            3,
            "150000 bytes at 64 KiB a read"
        );
        let index = fs::read_to_string(dir.join("captured.ndjson")).unwrap();
        assert!(index.contains("captured/1-2-3-e7-path") && index.contains("150000"));
        assert_eq!(out.files.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn packet_frames_are_written_one_line_each_per_capture() {
        let dir = scratch("packets");
        let fake = Fake {
            asked: Default::default(),
        };
        let mut out = Out {
            root: dir.clone(),
            files: Vec::new(),
        };
        let mut partial = false;
        export_packets(
            &fake,
            &json!({"recording_key": "k"}),
            &mut out,
            &mut partial,
        )
        .unwrap();
        // The capture id is made safe as a file name.
        let text = fs::read_to_string(dir.join("network-packets-cap_1.ndjson")).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1]["n"], 2);
        assert_eq!(lines[1]["frame_len"], 3);
        assert_eq!(
            base64_lite::decode(lines[2]["bytes_b64"].as_str().unwrap()),
            [3, 3, 3]
        );
        assert!(out.files[0].get("truncated").is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn base64_decodes_standard_text() {
        assert_eq!(base64_lite::decode("aGVsbG8="), b"hello");
        assert_eq!(base64_lite::decode(""), b"");
    }
}
