// SPDX-License-Identifier: GPL-3.0-only
//! `sample add/list/show/tag/verify/remove` (design 3.4.3). The commands work
//! on the library directly and need no engine lock, so they run beside a
//! window or a daemon. Results use the `Sample` object of design 5.4.7.
//!
//! `add`, `list`, `show` and `tag` go to the daemon when one answers at the
//! socket (`sample.list`, `sample.get`, `sample.tag`; `add` uploads the file,
//! then calls `sample.add`) and run the same library code in this process
//! otherwise. `verify` and `remove` stay in this process: they work on
//! archives. `add --delete-original` deletes the file in the CLI, after the
//! daemon reported the same SHA-256.
use super::{
    auto::{link, submit::upload},
    library::{library_error, open_existing, open_for_write, parse_sha256},
};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    output::{Reply, block, table},
};
use antinomie_monitor_core::samples::{Library, NewOrigin, NewSample, Tag, TagKind, Verification};
use antinomie_service::{
    api::ops::{SampleGetParams, SampleListParams},
    library as service_library,
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Sample {
    /// Add files to the library (hashed and archived, never run).
    Add(Add),
    /// List samples, newest first.
    List(List),
    /// Show one sample.
    Show(Show),
    /// Add or remove tags.
    Tag(TagArgs),
    /// Read archives back and compare their SHA-256.
    Verify {
        /// One sample; default: every sample that has an archive.
        sha256: Option<String>,
    },
    /// Delete a sample's archive (the record and its custody log stay).
    Remove {
        sha256: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
pub struct Add {
    #[arg(required = true, value_name = "FILE")]
    pub files: Vec<PathBuf>,
    /// Library name (one file only; default: the file name).
    #[arg(long)]
    pub name: Option<String>,
    /// Tag as KIND=VALUE (verdict, category, technique, custom) or a bare custom value.
    #[arg(long = "tag", value_name = "K=V")]
    pub tags: Vec<String>,
    /// Delete the original after the archive read back and matched.
    #[arg(long)]
    pub delete_original: bool,
}

#[derive(Args, Debug)]
pub struct List {
    /// Text in the name, SHA-256, type, architecture or a tag.
    #[arg(long)]
    pub q: Option<String>,
    /// Only samples with this tag (KIND=VALUE); repeat to require several.
    #[arg(long = "tag", value_name = "K=V")]
    pub tags: Vec<String>,
    /// At most this many samples.
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
    /// Continue after the `next_cursor` of an earlier page.
    #[arg(long)]
    pub cursor: Option<String>,
    /// Include samples whose archive was removed.
    #[arg(long)]
    pub all: bool,
    /// Fill `custody_ok` by checking every chain (otherwise it is null).
    #[arg(long)]
    pub custody: bool,
}

#[derive(Args, Debug)]
pub struct Show {
    pub sha256: String,
    /// Add the routes that brought the sample in.
    #[arg(long)]
    pub origins: bool,
    /// Add the custody events.
    #[arg(long)]
    pub events: bool,
    /// Add the runs the library knows.
    #[arg(long)]
    pub runs: bool,
}

#[derive(Args, Debug)]
pub struct TagArgs {
    pub sha256: String,
    #[arg(required = true, value_name = "TAG")]
    pub tags: Vec<String>,
    /// Remove the tags instead of adding them.
    #[arg(long)]
    pub remove: bool,
}

pub fn run(sample: &Sample, context: &Context) -> Result<Reply, CliError> {
    let data = context.data_dir();
    match sample {
        Sample::Add(arguments) => add(arguments, context),
        Sample::List(arguments) => list(arguments, context),
        Sample::Show(arguments) => show(arguments, context),
        Sample::Tag(arguments) => match link::daemon(context)? {
            Some(mut client) => tag_through(arguments, &mut client),
            None => tag(arguments, open_for_write(data)?),
        },
        Sample::Verify { sha256 } => verify(sha256.as_deref(), open_existing(data)?),
        Sample::Remove { sha256, yes } => remove(sha256, *yes, open_existing(data)?),
    }
}

/// `KIND=VALUE` as a tag; a bare value is a custom tag.
pub fn parse_tag(text: &str) -> Result<Tag, CliError> {
    let (kind, value) = match text.split_once('=') {
        Some(("verdict", value)) => (TagKind::Verdict, value),
        Some(("category", value)) => (TagKind::Category, value),
        Some(("technique", value)) => (TagKind::Technique, value),
        Some(("custom", value)) => (TagKind::Custom, value),
        Some((kind, _)) => {
            return Err(CliError::invalid(format!(
                "unknown tag kind {kind:?}; use verdict, category, technique or custom"
            ))
            .with_field("tag"));
        }
        None => (TagKind::Custom, text),
    };
    let tag = Tag::new(kind, value);
    tag.validate()
        .map_err(|message| CliError::invalid(message).with_field("tag"))?;
    Ok(tag)
}

fn tag_value(tag: &Tag) -> Value {
    json!({"kind": tag.kind, "value": tag.value})
}

/// `sample add`: through the daemon (an upload, then `sample.add`) when one
/// answers at the socket, else straight into the library in this process.
fn add(arguments: &Add, context: &Context) -> Result<Reply, CliError> {
    if arguments.name.is_some() && arguments.files.len() > 1 {
        return Err(CliError::invalid("--name names one sample; give one file").with_field("name"));
    }
    let tags: Vec<Tag> = arguments
        .tags
        .iter()
        .map(|text| parse_tag(text))
        .collect::<Result<_, _>>()?;
    let mut adder = match link::daemon(context)? {
        Some(client) => Adder::Daemon(Box::new(client)),
        None => Adder::Library(Box::new(open_for_write(context.data_dir())?)),
    };
    let mut items = Vec::new();
    let mut failures = 0;
    let mut first_failure: Option<CliError> = None;
    for path in &arguments.files {
        match adder.add(path, arguments, &tags, context) {
            Ok(item) => items.push(item),
            Err(error) => {
                failures += 1;
                items.push(json!({"path": path, "ok": false, "error": error.to_value()}));
                first_failure.get_or_insert(error);
            }
        }
    }
    render_added(items, failures, first_failure)
}

/// Where `sample add` puts a file.
enum Adder {
    Library(Box<Library>),
    Daemon(Box<antinomie_service::server::client::Client>),
}

impl Adder {
    /// One file: the item the command prints for it.
    fn add(
        &mut self,
        path: &PathBuf,
        arguments: &Add,
        tags: &[Tag],
        context: &Context,
    ) -> Result<Value, CliError> {
        match self {
            Self::Library(library) => {
                let new = NewSample {
                    name: arguments.name.clone().unwrap_or_default(),
                    tags: tags.to_vec(),
                    origin: NewOrigin::default(),
                    ..Default::default()
                };
                let added = library
                    .add_file(path, new, arguments.delete_original)
                    .map_err(library_error)?;
                let record = library.get(&added.sha256).map_err(library_error)?;
                let mut item =
                    json!({"path": path, "ok": true, "sha256": added.sha256, "new": added.new});
                if let Some(record) = record {
                    item["name"] = record.name.into();
                    item["size"] = record.size.into();
                    item["type"] = record.file_type.to_ascii_lowercase().into();
                }
                Ok(item)
            }
            Self::Daemon(client) => {
                // The daemon opens no file a client names: the file goes up
                // as an upload (hashed here and checked there), then is added.
                let (id, sha256) = upload(client, path, context)?;
                let mut params = json!({"sample": {"upload_id": id}});
                if let Some(name) = &arguments.name {
                    params["name"] = json!(name);
                }
                if !tags.is_empty() {
                    params["tags"] = tags.iter().map(tag_value).collect();
                }
                let sample = link::call(client, "sample.add", params)?;
                if arguments.delete_original && sample["sha256"].as_str() == Some(sha256.as_str()) {
                    std::fs::remove_file(path).map_err(|e| CliError::io(path, &e))?;
                }
                Ok(json!({
                    "path": path, "ok": true, "sha256": sample["sha256"],
                    "new": sample["new"], "name": sample["name"],
                    "size": sample["size"], "type": sample["type"],
                }))
            }
        }
    }
}

fn render_added(
    items: Vec<Value>,
    failures: usize,
    first_failure: Option<CliError>,
) -> Result<Reply, CliError> {
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            vec![
                item["sha256"].as_str().unwrap_or("-").to_owned(),
                match (item["ok"].as_bool(), item["new"].as_bool()) {
                    (Some(true), Some(true)) => "added".to_owned(),
                    (Some(true), _) => "already in the library".to_owned(),
                    _ => format!(
                        "FAILED: {}",
                        item["error"]["message"].as_str().unwrap_or("")
                    ),
                },
                item["path"].as_str().unwrap_or("").to_owned(),
            ]
        })
        .collect();
    let text = table(&["sha256", "result", "file"], &rows);
    match first_failure {
        None => Ok(Reply::list(items, None).with_human(text)),
        Some(first) => Err(CliError::new(
            first.code,
            format!(
                "{failures} of {} files were not added: {}",
                items.len(),
                first.message
            ),
        )
        .with_details(json!({"items": items}))
        .with_human_output(text)),
    }
}

/// `sample.list` through the daemon or from the library in this process.
fn list(arguments: &List, context: &Context) -> Result<Reply, CliError> {
    let params = SampleListParams {
        q: arguments.q.clone(),
        tag: None,
        tags: (!arguments.tags.is_empty()).then(|| arguments.tags.clone()),
        all: arguments.all.then_some(true),
        custody: arguments.custody.then_some(true),
        limit: Some(arguments.limit.try_into().unwrap_or(u32::MAX)),
        cursor: arguments.cursor.clone(),
    };
    let reply = match link::daemon(context)? {
        Some(mut client) => {
            let value = serde_json::to_value(&params)
                .map_err(|error| CliError::internal(error.to_string()))?;
            link::call(&mut client, "sample.list", value)?
        }
        None => {
            let existing = open_existing(context.data_dir())?;
            let scanned = service_library::scan_if(&existing, &context.options);
            service_library::list_with_runs(existing.as_ref(), &params, &scanned)
                .map_err(link::api)?
        }
    };
    let page: Vec<Value> = reply["samples"].as_array().cloned().unwrap_or_default();
    let next = reply["next_cursor"].as_str().map(str::to_owned);
    if page.is_empty() && next.is_none() && arguments.cursor.is_none() {
        return Ok(Reply::list(Vec::new(), None).with_human("No samples.\n".into()));
    }
    let rows: Vec<Vec<String>> = page.iter().map(row).collect();
    let mut text = table(&["sha256", "size", "type", "arch", "runs", "name"], &rows);
    if let Some(next) = &next {
        text.push_str(&format!("more: --cursor {next}\n"));
    }
    Ok(Reply::list(page, next).with_human(text))
}

fn row(sample: &Value) -> Vec<String> {
    vec![
        sample["sha256"].as_str().unwrap_or("").to_owned(),
        sample["size"].to_string(),
        sample["type"].as_str().unwrap_or("").to_owned(),
        sample["architecture"].as_str().unwrap_or("-").to_owned(),
        sample["run_count"].to_string(),
        sample["name"].as_str().unwrap_or("").to_owned(),
    ]
}

fn missing_library(sha256: &str) -> CliError {
    CliError::not_found(format!("sample {sha256} is not in the library")).with_field("sha256")
}

fn show(arguments: &Show, context: &Context) -> Result<Reply, CliError> {
    let sha256 = parse_sha256(&arguments.sha256)?;
    let params = SampleGetParams {
        sha256: antinomie_service::api::ids::Sha256Hex::try_from(sha256.clone())
            .map_err(|e| CliError::invalid(e.to_string()).with_field("sha256"))?,
        origins: arguments.origins.then_some(true),
        events: arguments.events.then_some(true),
        runs: arguments.runs.then_some(true),
    };
    let value = match link::daemon(context)? {
        Some(mut client) => {
            let value = serde_json::to_value(&params)
                .map_err(|error| CliError::internal(error.to_string()))?;
            link::call(&mut client, "sample.get", value)?
        }
        None => {
            let existing = open_existing(context.data_dir())?;
            let scanned = service_library::scan_if(&existing, &context.options);
            service_library::get_with_runs(existing.as_ref(), &params, &scanned)
                .map_err(link::api)?
        }
    };
    let human = block(&[
        ("sha256", text_of(&value["sha256"])),
        ("name", text_of(&value["name"])),
        ("size", text_of(&value["size"])),
        ("type", text_of(&value["type"])),
        (
            "architecture",
            value["architecture"].as_str().unwrap_or("-").to_owned(),
        ),
        (
            "tags",
            value["tags"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| text_of(&t["value"]))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ("runs", text_of(&value["run_count"])),
        ("custody", text_of(&value["custody"])),
        (
            "archive",
            if value["removed_ms"].is_null() {
                "present"
            } else {
                "removed"
            }
            .to_owned(),
        ),
    ]);
    Ok(Reply::value(value).with_human(human))
}

fn text_of(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `sample tag` through the daemon: the tags become the current ones with the
/// changes applied (`sample.tag` sets the whole list).
fn tag_through(
    arguments: &TagArgs,
    client: &mut antinomie_service::server::client::Client,
) -> Result<Reply, CliError> {
    let sha256 = parse_sha256(&arguments.sha256)?;
    let changes: Vec<Tag> = arguments
        .tags
        .iter()
        .map(|text| parse_tag(text))
        .collect::<Result<_, _>>()?;
    let current = link::call(client, "sample.get", json!({"sha256": sha256}))?;
    let mut tags: Vec<Tag> = current["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| {
            let kind = serde_json::from_value::<TagKind>(t["kind"].clone()).ok()?;
            Some(Tag::new(kind, t["value"].as_str()?))
        })
        .collect();
    for change in changes {
        if arguments.remove {
            tags.retain(|tag| !(tag.kind == change.kind && tag.value == change.value));
        } else if !tags
            .iter()
            .any(|tag| tag.kind == change.kind && tag.value == change.value)
        {
            tags.push(change);
        }
    }
    let answer = link::call(
        client,
        "sample.tag",
        json!({"sha256": sha256, "tags": tags.iter().map(tag_value).collect::<Vec<_>>()}),
    )?;
    let tags = answer["tags"].as_array().cloned().unwrap_or_default();
    let human = tags
        .iter()
        .map(|t| format!("{}={}\n", text_of(&t["kind"]), text_of(&t["value"])))
        .collect::<String>();
    Ok(Reply::value(json!({"sha256": sha256, "tags": tags})).with_human(human))
}

fn tag(arguments: &TagArgs, mut library: Library) -> Result<Reply, CliError> {
    let sha256 = parse_sha256(&arguments.sha256)?;
    let changes: Vec<Tag> = arguments
        .tags
        .iter()
        .map(|text| parse_tag(text))
        .collect::<Result<_, _>>()?;
    let mut tags = library.tags(&sha256).map_err(library_error)?;
    if !library.contains(&sha256).map_err(library_error)? {
        return Err(missing_library(&sha256));
    }
    for change in changes {
        if arguments.remove {
            tags.retain(|tag| !(tag.kind == change.kind && tag.value == change.value));
        } else if !tags
            .iter()
            .any(|tag| tag.kind == change.kind && tag.value == change.value)
        {
            tags.push(change);
        }
    }
    library.set_tags(&sha256, &tags).map_err(library_error)?;
    let tags = library.tags(&sha256).map_err(library_error)?;
    let human = tags
        .iter()
        .map(|t| {
            format!(
                "{}={}\n",
                serde_json::to_value(t.kind)
                    .unwrap_or_default()
                    .as_str()
                    .unwrap_or(""),
                t.value
            )
        })
        .collect::<String>();
    Ok(Reply::value(json!({
        "sha256": sha256,
        "tags": tags.iter().map(tag_value).collect::<Vec<_>>(),
    }))
    .with_human(human))
}

fn status(result: &Verification) -> (&'static str, String) {
    match result {
        Verification::Matches => ("matches", String::new()),
        Verification::Missing => ("missing", "the archive is missing".into()),
        Verification::Mismatch(detail) => ("mismatch", detail.clone()),
    }
}

fn verify(sha256: Option<&str>, library: Option<Library>) -> Result<Reply, CliError> {
    let one = sha256.map(parse_sha256).transpose()?;
    let Some(mut library) = library else {
        return match one {
            Some(sha256) => Err(missing_library(&sha256)),
            None => Ok(Reply::list(Vec::new(), None).with_human("No samples.\n".into())),
        };
    };
    let results = match &one {
        Some(sha256) => vec![(
            sha256.clone(),
            library.verify(sha256).map_err(library_error)?,
        )],
        None => library.verify_all().map_err(library_error)?,
    };
    let items: Vec<Value> = results
        .iter()
        .map(|(sha256, result)| {
            let (state, detail) = status(result);
            json!({"sha256": sha256, "status": state, "ok": result.is_ok(), "detail": detail})
        })
        .collect();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|i| {
            vec![
                i["sha256"].as_str().unwrap_or("").to_owned(),
                i["status"].as_str().unwrap_or("").to_owned(),
                i["detail"].as_str().unwrap_or("").to_owned(),
            ]
        })
        .collect();
    let text = table(&["sha256", "status", "detail"], &rows);
    let bad = items.iter().filter(|i| i["ok"] == false).count();
    if bad == 0 {
        return Ok(Reply::list(items, None).with_human(text));
    }
    Err(CliError::new(
        ErrorCode::VerificationFailed,
        format!(
            "{bad} of {} archives do not match their SHA-256",
            items.len()
        ),
    )
    .with_details(json!({"items": items}))
    .with_human_output(text))
}

fn remove(sha256: &str, yes: bool, library: Option<Library>) -> Result<Reply, CliError> {
    let sha256 = parse_sha256(sha256)?;
    if !yes {
        return Err(CliError::invalid(
            "removing deletes the archive of the sample; the record and custody log stay. Add --yes to confirm",
        )
        .with_field("yes"));
    }
    let mut library = library.ok_or_else(|| missing_library(&sha256))?;
    library.remove(&sha256).map_err(library_error)?;
    Ok(Reply::value(json!({"sha256": sha256, "removed": true}))
        .with_human(format!("Removed the archive of {sha256}.\n")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{Environment, execute},
        exit::Exit,
    };
    use serde_json::Value;
    use std::{ffi::OsString, path::Path};

    /// A data directory and a folder of files to add, removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!("ant-cli-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("files")).unwrap();
            Self(root)
        }
        fn data(&self) -> String {
            self.0.join("data").display().to_string()
        }
        fn file(&self, name: &str, bytes: &[u8]) -> String {
            let path = self.0.join("files").join(name);
            std::fs::write(&path, bytes).unwrap();
            path.display().to_string()
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cli(scratch: &Scratch, args: &[&str]) -> (Exit, Value) {
        let mut all: Vec<OsString> = ["antinomie-cli", "-o", "json", "--data-dir"]
            .iter()
            .map(OsString::from)
            .collect();
        all.push(scratch.data().into());
        all.extend(args.iter().map(OsString::from));
        let environment = Environment {
            stdout_is_terminal: false,
            stderr_is_terminal: false,
            no_color: true,
            home: None,
        };
        let (exit, out) = execute(all, &environment);
        (
            exit,
            serde_json::from_str(&out.stdout).unwrap_or(Value::Null),
        )
    }

    /// A tiny ELF header: enough for the type and architecture detection.
    fn elf(extra: u8) -> Vec<u8> {
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        bytes.resize(18, 0);
        bytes[16] = 2; // ET_EXEC
        bytes[18 - 2] = 2;
        bytes.extend_from_slice(&[0x3e, 0, 1, 0, 0, 0]);
        bytes.resize(64, extra);
        bytes
    }

    #[test]
    fn nothing_is_created_by_reading_an_empty_data_directory() {
        let scratch = Scratch::new("empty");
        let (exit, value) = cli(&scratch, &["sample", "list"]);
        assert_eq!(exit, Exit::Ok);
        assert_eq!(value["result"]["items"], serde_json::json!([]));
        assert!(!Path::new(&scratch.data()).exists());
        let (exit, value) = cli(&scratch, &["sample", "show", &"a".repeat(64)]);
        assert_eq!(exit.code(), 3);
        assert_eq!(value["error"]["code"], "not_found");
    }

    #[test]
    fn add_list_show_tag_verify_remove_round_trip() {
        let scratch = Scratch::new("roundtrip");
        let first = scratch.file("one.bin", &elf(1));
        let second = scratch.file("two.bin", b"#!/bin/sh\necho hi\n");

        let (exit, added) = cli(
            &scratch,
            &[
                "sample",
                "add",
                &first,
                &second,
                "--tag",
                "category=miner",
                "--tag",
                "lab",
            ],
        );
        assert_eq!(exit, Exit::Ok, "{added}");
        let items = added["result"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["new"], true);
        let sha_elf = items[0]["sha256"].as_str().unwrap().to_owned();
        let sha_sh = items[1]["sha256"].as_str().unwrap().to_owned();
        assert_eq!(sha_elf.len(), 64);

        // The same bytes again are not new.
        let (_, again) = cli(&scratch, &["sample", "add", &first]);
        assert_eq!(again["result"]["items"][0]["new"], false);

        // Section 5.4.7 members, in the Sample object.
        let (_, listed) = cli(&scratch, &["sample", "list"]);
        let samples = listed["result"]["items"].as_array().unwrap();
        assert_eq!(samples.len(), 2);
        let elf_sample = samples
            .iter()
            .find(|s| s["sha256"] == sha_elf.as_str())
            .unwrap();
        for key in [
            "sha256",
            "size",
            "type",
            "architecture",
            "name",
            "tags",
            "first_seen_ms",
            "run_count",
            "last_job",
            "custody_ok",
        ] {
            assert!(elf_sample.get(key).is_some(), "missing {key}");
        }
        assert_eq!(elf_sample["type"], "elf");
        assert_eq!(elf_sample["architecture"], "x86-64");
        assert_eq!(elf_sample["name"], "one.bin");
        assert_eq!(elf_sample["run_count"], 0);
        assert!(elf_sample["last_job"].is_null() && elf_sample["custody_ok"].is_null());
        assert_eq!(elf_sample["tags"].as_array().unwrap().len(), 2);

        // Filters.
        let (_, by_tag) = cli(&scratch, &["sample", "list", "--tag", "category=miner"]);
        assert_eq!(by_tag["result"]["items"].as_array().unwrap().len(), 2);
        let (_, none) = cli(&scratch, &["sample", "list", "--tag", "verdict=malicious"]);
        assert!(none["result"]["items"].as_array().unwrap().is_empty());
        let (_, by_q) = cli(&scratch, &["sample", "list", "--q", "TWO"]);
        assert_eq!(by_q["result"]["items"][0]["sha256"], sha_sh.as_str());
        let (_, checked) = cli(&scratch, &["sample", "list", "--custody"]);
        assert!(
            checked["result"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["custody_ok"] == true)
        );

        // Paging.
        let (_, page) = cli(&scratch, &["sample", "list", "--limit", "1"]);
        assert_eq!(page["result"]["items"].as_array().unwrap().len(), 1);
        let cursor = page["result"]["next_cursor"].as_str().unwrap().to_owned();
        let (_, rest) = cli(
            &scratch,
            &["sample", "list", "--limit", "1", "--cursor", &cursor],
        );
        assert_eq!(rest["result"]["items"].as_array().unwrap().len(), 1);
        assert!(rest["result"]["next_cursor"].is_null());
        assert_ne!(
            page["result"]["items"][0]["sha256"],
            rest["result"]["items"][0]["sha256"]
        );
        let (exit, _) = cli(&scratch, &["sample", "list", "--cursor", "junk"]);
        assert_eq!(exit.code(), 4);

        // Show with detail.
        let (exit, shown) = cli(
            &scratch,
            &[
                "sample",
                "show",
                &sha_elf.to_ascii_uppercase(),
                "--origins",
                "--events",
                "--runs",
            ],
        );
        assert_eq!(exit, Exit::Ok);
        let result = &shown["result"];
        assert_eq!(result["custody_ok"], true);
        assert_eq!(result["origins"][0]["kind"], "added");
        assert!(!result["events"].as_array().unwrap().is_empty());
        assert_eq!(result["runs"], serde_json::json!([]));
        assert_eq!(result["sha1"].as_str().unwrap().len(), 40);

        // Tags.
        let (_, tagged) = cli(
            &scratch,
            &[
                "sample",
                "tag",
                &sha_elf,
                "verdict=suspicious",
                "category=miner",
            ],
        );
        assert_eq!(tagged["result"]["tags"].as_array().unwrap().len(), 3);
        let (_, untagged) = cli(
            &scratch,
            &[
                "sample",
                "tag",
                &sha_elf,
                "lab",
                "category=miner",
                "--remove",
            ],
        );
        assert_eq!(
            untagged["result"]["tags"],
            serde_json::json!([{"kind": "verdict", "value": "suspicious"}])
        );
        let (exit, bad) = cli(&scratch, &["sample", "tag", &sha_elf, "verdict=great"]);
        assert_eq!(exit.code(), 4);
        assert_eq!(bad["error"]["field"], "tag");
        let (exit, _) = cli(&scratch, &["sample", "tag", &"0".repeat(64), "x"]);
        assert_eq!(exit.code(), 3);

        // Verify: all, one.
        let (exit, verified) = cli(&scratch, &["sample", "verify"]);
        assert_eq!(exit, Exit::Ok);
        assert_eq!(verified["result"]["items"].as_array().unwrap().len(), 2);
        assert!(
            verified["result"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|i| i["status"] == "matches")
        );
        let (exit, _) = cli(&scratch, &["sample", "verify", &sha_sh]);
        assert_eq!(exit, Exit::Ok);

        // A damaged archive: exit 1 with the status named.
        let archive =
            antinomie_monitor_core::samples::archive_path(Path::new(&scratch.data()), &sha_sh)
                .unwrap();
        std::fs::write(&archive, b"not a zip").unwrap();
        let (exit, damaged) = cli(&scratch, &["sample", "verify", &sha_sh]);
        assert_eq!(exit.code(), 1);
        assert_eq!(damaged["error"]["code"], "verification_failed");
        assert_eq!(
            damaged["error"]["details"]["items"][0]["status"],
            "mismatch"
        );

        // Remove needs --yes; the record stays and the archive goes.
        let (exit, refused) = cli(&scratch, &["sample", "remove", &sha_elf]);
        assert_eq!(exit.code(), 4);
        assert_eq!(refused["error"]["field"], "yes");
        let (exit, _) = cli(&scratch, &["sample", "remove", &sha_elf, "--yes"]);
        assert_eq!(exit, Exit::Ok);
        let (_, visible) = cli(&scratch, &["sample", "list"]);
        assert_eq!(visible["result"]["items"].as_array().unwrap().len(), 1);
        let (_, everything) = cli(&scratch, &["sample", "list", "--all"]);
        assert_eq!(everything["result"]["items"].as_array().unwrap().len(), 2);
        let (_, gone) = cli(&scratch, &["sample", "show", &sha_elf]);
        assert!(gone["result"]["removed_ms"].is_u64());
        let _ = scratch.path();
    }

    #[test]
    fn add_reports_each_file_and_fails_when_one_does() {
        let scratch = Scratch::new("addfail");
        let good = scratch.file("good.bin", b"hello");
        let missing = scratch
            .path()
            .join("files")
            .join("missing.bin")
            .display()
            .to_string();
        let (exit, value) = cli(&scratch, &["sample", "add", &good, &missing]);
        assert_ne!(exit, Exit::Ok);
        assert_eq!(value["ok"], false);
        let items = value["error"]["details"]["items"].as_array().unwrap();
        assert_eq!(items[0]["ok"], true);
        assert_eq!(items[1]["ok"], false);
        // The good file was added anyway.
        let (_, listed) = cli(&scratch, &["sample", "list"]);
        assert_eq!(listed["result"]["items"].as_array().unwrap().len(), 1);
        // --name with several files is refused before anything is added.
        let (exit, _) = cli(&scratch, &["sample", "add", &good, &good, "--name", "x"]);
        assert_eq!(exit.code(), 4);
    }

    #[test]
    fn delete_original_removes_the_file_after_it_is_archived() {
        let scratch = Scratch::new("delete");
        let file = scratch.file("gone.bin", b"to be archived");
        let (exit, _) = cli(
            &scratch,
            &[
                "sample",
                "add",
                &file,
                "--delete-original",
                "--name",
                "kept",
            ],
        );
        assert_eq!(exit, Exit::Ok);
        assert!(!Path::new(&file).exists());
        let (_, listed) = cli(&scratch, &["sample", "list"]);
        assert_eq!(listed["result"]["items"][0]["name"], "kept");
    }

    #[test]
    fn tags_parse_by_kind() {
        assert_eq!(parse_tag("lab").unwrap().kind, TagKind::Custom);
        assert_eq!(parse_tag("custom=a=b").unwrap().value, "a=b");
        assert_eq!(
            parse_tag("technique=T1053.003 Cron").unwrap().kind,
            TagKind::Technique
        );
        assert!(parse_tag("shade=red").is_err());
        assert!(parse_tag("technique=nope").is_err());
        assert!(parse_tag("").is_err());
    }
}
