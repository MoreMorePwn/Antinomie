// SPDX-License-Identifier: GPL-3.0-only
//! `run list`, `run show` and `run export` (design 3.4.3, 5.12.10): look at the
//! recordings of the data directory through the read-only query API, the one
//! the web pages use. No engine lock, nothing written into a recording; the
//! export writes only under `--out`.
use super::{query::Client, recording::RUN_HELP};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use clap::Args;
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

#[derive(Args, Debug)]
pub struct List {
    /// Only runs of this VM.
    #[arg(long, value_name = "ID")]
    pub vm: Option<String>,
    /// Only runs of this library sample (SHA-256).
    #[arg(long, value_name = "SHA256")]
    pub sample: Option<String>,
    /// Only runs made by this job.
    #[arg(long, value_name = "JOB")]
    pub job: Option<String>,
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
    /// Also write the bytes the sample produced: captured packets, memory and
    /// core dumps, file copies and the contents of changed files.
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
    put("job_id", arguments.job.as_ref().map(|v| json!(v)));
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
    let page = Client::new(context)?.call("recording.run.list", Value::Object(params))?;
    let items = page["items"].as_array().cloned().unwrap_or_default();
    let next = page["next_cursor"].as_str().map(str::to_owned);
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|run| {
            vec![
                text(&run["run_id"]).chars().take(8).collect(),
                text(&run["vm_id"]),
                text(&run["state"]),
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
    let params = json!({"run_key": key});
    let reply = client.call("recording.run.get", params.clone())?;
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
        ("run key", text(&run["run_key"])),
        ("vm", text(&run["vm_id"])),
        ("boot", text(&run["boot_id"])),
        ("state", text(&run["state"])),
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
    client: &Client<'_>,
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
fn ranged(client: &Client<'_>, op: &str, params: &Value, size: u64) -> Result<Vec<u8>, CliError> {
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
    let params = json!({"run_key": key});
    let mut partial = false;
    for part in &parts {
        export_part(
            part,
            &client,
            &params,
            arguments.sensitive,
            &mut out,
            &mut partial,
        )?;
    }
    let value = json!({
        "run_key": key,
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

/// The files of one part.
fn export_part(
    part: &str,
    client: &Client<'_>,
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
    let mut rows = |client: &Client<'_>, op: &str, params: Value| -> Result<Vec<Value>, CliError> {
        all_pages(client, op, params, partial)
    };
    match part {
        "trace" => {
            let items = rows(client, "recording.trace.page", run.clone())?;
            out.lines("trace.ndjson", &items)?;
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

/// The contents of the changed files whose versions are available.
fn export_file_contents(
    client: &Client<'_>,
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

    #[test]
    fn base64_decodes_standard_text() {
        assert_eq!(base64_lite::decode("aGVsbG8="), b"hello");
        assert_eq!(base64_lite::decode(""), b"");
    }
}
