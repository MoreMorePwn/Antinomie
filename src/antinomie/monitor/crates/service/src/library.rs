// SPDX-License-Identifier: GPL-3.0-only
//! The sample library and its custody chains as the API serves them
//! (design 5.3: `sample.list`, `sample.get`, `sample.tag`, `sample.download`,
//! `custody.verify`). The daemon answers these over the socket and the CLI
//! calls the same functions in direct mode, so both return the same objects.
//!
//! The library is short-lived SQLite with a busy timeout (design 2.3): it
//! needs no engine lock and works beside a window or a daemon. A data
//! directory with no library yet reads as empty and is never created by a
//! read.

use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ops::{
            ByteRange, CustodyVerifyParams, SampleDownloadParams, SampleGetParams,
            SampleListParams, SampleTagParams,
        },
    },
    server::b64,
};
use antinomie_monitor_core::samples::{
    ChainCheck, CustodyEvent, DATABASE, Library, SampleRecord, Tag, TagKind, arch_label,
    samples_dir,
};
use serde_json::{Value, json};
use std::{
    io::{Read, Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// The most samples one `sample.list` returns.
pub const MAX_LIST: u32 = 1000;
/// The default page of `sample.list`.
pub const DEFAULT_LIST: u32 = 100;
/// The longest range one `sample.download` returns (Base64 in a 2 MiB line).
pub const MAX_RANGE: u64 = 1 << 20;

/// A library error text as an API error: the library has no error type, so
/// the known phrases map to `not_found` and `invalid_argument`.
pub fn library_error(message: String) -> ApiError {
    let lower = message.to_ascii_lowercase();
    let code = if lower.contains("not in the library") || lower.contains("no such sample") {
        ErrorCode::NotFound
    } else if lower.contains("is not a ")
        || lower.contains("a tag is ")
        || lower.contains("larger than")
        || lower.contains("at most")
    {
        ErrorCode::InvalidArgument
    } else {
        ErrorCode::Internal
    };
    ApiError::new(code, message)
}

fn missing(sha256: &str) -> ApiError {
    ApiError::new(
        ErrorCode::NotFound,
        format!("sample {sha256} is not in the library"),
    )
    .with_field("sha256")
}

/// The library of `data_dir` for a read. A data directory with no library
/// yet is `None`; nothing is created.
pub fn open_existing(data_dir: &Path) -> Result<Option<Library>, ApiError> {
    if !samples_dir(data_dir).join(DATABASE).is_file() {
        return Ok(None);
    }
    Library::open(data_dir).map(Some).map_err(library_error)
}

/// `KIND=VALUE` as a tag; a bare value is a custom tag.
pub fn parse_tag(text: &str) -> Result<Tag, ApiError> {
    let (kind, value) = match text.split_once('=') {
        Some(("verdict", value)) => (TagKind::Verdict, value),
        Some(("category", value)) => (TagKind::Category, value),
        Some(("technique", value)) => (TagKind::Technique, value),
        Some(("custom", value)) => (TagKind::Custom, value),
        Some((kind, _)) => {
            return Err(ApiError::invalid_argument(
                "tag",
                format!("unknown tag kind {kind:?}; use verdict, category, technique or custom"),
            ));
        }
        None => (TagKind::Custom, text),
    };
    let tag = Tag::new(kind, value);
    tag.validate()
        .map_err(|message| ApiError::invalid_argument("tag", message))?;
    Ok(tag)
}

/// A tag of the contract (`{kind, value}`) as the library's.
pub fn tag_of_api(tag: &crate::api::status::Tag) -> Result<Tag, ApiError> {
    let kind = match tag.kind.as_str() {
        "verdict" => TagKind::Verdict,
        "category" => TagKind::Category,
        "technique" => TagKind::Technique,
        "custom" => TagKind::Custom,
        other => {
            return Err(ApiError::invalid_argument(
                "tags",
                format!("unknown tag kind {other:?}; use verdict, category, technique or custom"),
            ));
        }
    };
    let out = Tag::new(kind, tag.value.clone());
    out.validate()
        .map_err(|message| ApiError::invalid_argument("tags", message))?;
    Ok(out)
}

fn tag_value(tag: &Tag) -> Value {
    json!({"kind": tag.kind, "value": tag.value})
}

/// The `Sample` object of design 5.4.7. `last_job` is null until Auto mode
/// records jobs; `custody_ok` is null when no chain check was made.
pub fn sample_value(
    record: &SampleRecord,
    tags: &[Tag],
    run_count: usize,
    custody_ok: Option<bool>,
) -> Value {
    json!({
        "sha256": record.sha256,
        "size": record.size,
        "type": record.file_type.to_ascii_lowercase(),
        "architecture": (!record.arch.is_empty()).then(|| arch_label(&record.arch)),
        "name": record.name,
        "tags": tags.iter().map(tag_value).collect::<Vec<_>>(),
        "first_seen_ms": record.added_ms,
        "run_count": run_count,
        "last_job": Value::Null,
        "custody_ok": custody_ok,
    })
}

fn matches_query(value: &Value, query: &str) -> bool {
    let needle = query.to_ascii_lowercase();
    let mut texts = vec![
        value["sha256"].as_str().unwrap_or("").to_owned(),
        value["name"].as_str().unwrap_or("").to_owned(),
        value["type"].as_str().unwrap_or("").to_owned(),
        value["architecture"].as_str().unwrap_or("").to_owned(),
    ];
    if let Some(tags) = value["tags"].as_array() {
        texts.extend(
            tags.iter()
                .filter_map(|t| t["value"].as_str())
                .map(str::to_owned),
        );
    }
    texts
        .iter()
        .any(|text| text.to_ascii_lowercase().contains(&needle))
}

fn has_tags(tags: &[Tag], wanted: &[Tag]) -> bool {
    wanted.iter().all(|want| {
        tags.iter()
            .any(|tag| tag.kind == want.kind && tag.value == want.value)
    })
}

/// `v1.<offset>`: where the next page starts in the newest-first order.
fn parse_cursor(cursor: Option<&str>) -> Result<usize, ApiError> {
    match cursor {
        None => Ok(0),
        Some(text) => text
            .strip_prefix("v1.")
            .and_then(|offset| offset.parse().ok())
            .ok_or_else(|| {
                ApiError::invalid_argument("cursor", "the cursor is not one this service returned")
            }),
    }
}

/// `sample.list`: `{samples, next_cursor}`, newest first.
pub fn list(library: Option<&Library>, params: &SampleListParams) -> Result<Value, ApiError> {
    let limit = params.limit.unwrap_or(DEFAULT_LIST);
    if limit == 0 || limit > MAX_LIST {
        return Err(ApiError::invalid_argument(
            "limit",
            format!("limit is 1 to {MAX_LIST}"),
        ));
    }
    let limit = limit as usize;
    let mut wanted = Vec::new();
    for text in params.tag.iter().chain(params.tags.iter().flatten()) {
        wanted.push(parse_tag(text)?);
    }
    let offset = parse_cursor(params.cursor.as_deref())?;
    let Some(library) = library else {
        return Ok(json!({"samples": [], "next_cursor": Value::Null}));
    };
    let tags = library.all_tags().map_err(library_error)?;
    let runs = library.run_stats().map_err(library_error)?;
    let checks = if params.custody == Some(true) {
        Some(library.custody_check_all().map_err(library_error)?)
    } else {
        None
    };
    let mut matching = Vec::new();
    for record in library.list().map_err(library_error)? {
        if record.removed_ms.is_some() && params.all != Some(true) {
            continue;
        }
        let own = tags.get(&record.sha256).map_or(&[][..], Vec::as_slice);
        if !has_tags(own, &wanted) {
            continue;
        }
        let custody_ok = checks.as_ref().map(|all| {
            all.samples
                .get(&record.sha256)
                .is_none_or(|check| check.ok())
        });
        let count = runs.get(&record.sha256).map_or(0, |stats| stats.count);
        let value = sample_value(&record, own, count, custody_ok);
        if params.q.as_deref().is_none_or(|q| matches_query(&value, q)) {
            matching.push(value);
        }
    }
    let end = (offset + limit).min(matching.len());
    let page: Vec<Value> = matching.get(offset..end).unwrap_or_default().to_vec();
    let next = (end < matching.len()).then(|| format!("v1.{end}"));
    Ok(json!({"samples": page, "next_cursor": next}))
}

/// `sample.get`: the `Sample` object plus the hashes, the description and,
/// on request, the origins, the custody events and the runs.
pub fn get(library: Option<&Library>, params: &SampleGetParams) -> Result<Value, ApiError> {
    let sha256 = params.sha256.as_str();
    let library = library.ok_or_else(|| missing(sha256))?;
    let record = library
        .get(sha256)
        .map_err(library_error)?
        .ok_or_else(|| missing(sha256))?;
    let tags = library.tags(sha256).map_err(library_error)?;
    let runs = library.runs_of(sha256).map_err(library_error)?;
    let check = library.custody_check(sha256).map_err(library_error)?;
    let mut value = sample_value(&record, &tags, runs.len(), Some(check.ok()));
    value["sha1"] = record.sha1.clone().into();
    value["md5"] = record.md5.clone().into();
    value["description"] = record.description.clone().into();
    value["removed_ms"] = record.removed_ms.into();
    value["custody"] = check.summary().into();
    if params.origins == Some(true) {
        let origins = library.origins(sha256).map_err(library_error)?;
        value["origins"] = origins
            .iter()
            .map(|o| {
                json!({
                    "kind": o.kind.as_str(), "source": o.source, "detail": o.detail,
                    "name": o.name, "path": o.path, "vm_id": o.vm_id, "vm_name": o.vm_name,
                    "run_id": o.run_id, "parent": o.parent, "at_ms": o.at_ms,
                    "before_custody": o.before_custody,
                })
            })
            .collect();
    }
    if params.events == Some(true) {
        let events = library.events(sha256).map_err(library_error)?;
        value["events"] = events
            .iter()
            .map(|e| {
                json!({
                    "seq": e.seq, "at_ms": e.at_ms, "by": e.by, "kind": e.event.key(),
                    "label": e.event.label(), "detail": e.event.detail(),
                    "before_chain": e.before_chain, "hash": e.hash,
                })
            })
            .collect();
    }
    if params.runs == Some(true) {
        value["runs"] = runs
            .iter()
            .map(|r| {
                json!({
                    "vm_id": r.vm_id, "vm_name": r.vm_name, "run_id": r.run_id,
                    "started_ms": r.started_ms, "exit": r.exit,
                })
            })
            .collect();
    }
    Ok(value)
}

/// `sample.tag`: the tags become exactly `params.tags`; the answer is the
/// `Sample` object. `actor` is who the custody log names (`local:<uid>` for a
/// socket caller).
pub fn set_tags(data_dir: &Path, actor: &str, params: &SampleTagParams) -> Result<Value, ApiError> {
    let sha256 = params.sha256.as_str();
    let tags: Vec<Tag> = params
        .tags
        .iter()
        .map(tag_of_api)
        .collect::<Result<_, _>>()?;
    let mut library = Library::open(data_dir)
        .and_then(|library| library.with_actor(actor))
        .map_err(library_error)?;
    if !library.contains(sha256).map_err(library_error)? {
        return Err(missing(sha256));
    }
    library
        .set_tags_as(sha256, &tags, actor)
        .map_err(library_error)?;
    let record = library
        .get(sha256)
        .map_err(library_error)?
        .ok_or_else(|| missing(sha256))?;
    let tags = library.tags(sha256).map_err(library_error)?;
    let runs = library.runs_of(sha256).map_err(library_error)?;
    Ok(sample_value(&record, &tags, runs.len(), None))
}

/// `sample.download`: a range of the library archive (an AES-256 zip with the
/// password `infected`; never the plaintext). The first range of a download
/// (`offset` 0) writes the custody event `exported`. The path is built from
/// the library's own archive location for a SHA-256 that was checked to be 64
/// hex digits; the file is opened with `O_NOFOLLOW`.
pub fn download(
    data_dir: &Path,
    actor: &str,
    params: &SampleDownloadParams,
) -> Result<Value, ApiError> {
    let sha256 = params.sha256.as_str();
    let library = Library::open(data_dir)
        .and_then(|library| library.with_actor(actor))
        .map_err(library_error)?;
    let record = library
        .get(sha256)
        .map_err(library_error)?
        .ok_or_else(|| missing(sha256))?;
    if record.removed_ms.is_some() {
        return Err(ApiError::new(
            ErrorCode::NotFound,
            "the archive of this sample was removed",
        )
        .with_field("sha256"));
    }
    let path = library.archive_path(sha256).map_err(library_error)?;
    let range = params.range.unwrap_or(ByteRange {
        offset: 0,
        len: MAX_RANGE,
    });
    if range.len > MAX_RANGE {
        return Err(ApiError::payload_too_large(MAX_RANGE).with_field("range.len"));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|_| ApiError::not_found("sample archive"))?;
    let meta = file
        .metadata()
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    if !meta.is_file() {
        return Err(ApiError::not_found("sample archive"));
    }
    let size = meta.len();
    if range.offset > size {
        return Err(ApiError::invalid_argument("range.offset", "past the end"));
    }
    file.seek(SeekFrom::Start(range.offset))
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(range.len)
        .read_to_end(&mut bytes)
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    if range.offset == 0 {
        let head = library
            .custody_check(sha256)
            .map(|check| check.head)
            .unwrap_or_default();
        library
            .record_event(
                sha256,
                actor,
                CustodyEvent::Exported {
                    format: "archive".into(),
                    signed: "unsigned".into(),
                    head,
                },
            )
            .map_err(|e| ApiError::new(ErrorCode::Internal, e))?;
    }
    Ok(json!({
        "sha256": sha256,
        "format": "zip-aes256",
        "password": "infected",
        "size": size,
        "range": {"offset": range.offset, "len": bytes.len(), "data": b64::encode(&bytes)},
    }))
}

fn chain_value(sha256: &str, check: &ChainCheck) -> Value {
    json!({
        "sha256": sha256, "ok": check.ok(), "entries": check.entries,
        "head": check.head, "problem": serde_json::to_value(&check.problem).unwrap_or(Value::Null),
        "summary": check.summary(),
    })
}

/// `custody.verify`: `{ok, head, problems[]}` of the contract, plus the
/// numbers the CLI prints. One sample: its chain (`sha256`, `entries`,
/// `problem`). No sample: the library index and every chain (`index`,
/// `samples`, `broken`).
pub fn custody_verify(
    library: Option<&Library>,
    params: &CustodyVerifyParams,
) -> Result<Value, ApiError> {
    match &params.sha256 {
        Some(sha256) => {
            let sha256 = sha256.as_str();
            let library = library.ok_or_else(|| missing(sha256))?;
            if !library.contains(sha256).map_err(library_error)? {
                return Err(missing(sha256));
            }
            let check = library.custody_check(sha256).map_err(library_error)?;
            let mut value = chain_value(sha256, &check);
            value["problems"] = if check.ok() {
                json!([])
            } else {
                json!([check.summary()])
            };
            Ok(value)
        }
        None => {
            let Some(library) = library else {
                return Ok(json!({
                    "ok": true, "head": Value::Null, "problems": [],
                    "index": {"records": 0, "ok": true}, "samples": [], "broken": [],
                }));
            };
            let check = library.custody_check_all().map_err(library_error)?;
            let samples: Vec<Value> = check
                .samples
                .iter()
                .map(|(sha, c)| chain_value(sha, c))
                .collect();
            let broken: Vec<&str> = check.broken();
            let index_ok = check.index.problem.is_none();
            let mut problems = Vec::new();
            if !index_ok {
                problems.push("the library index does not verify".to_owned());
            }
            problems.extend(
                broken
                    .iter()
                    .map(|sha| format!("the chain of {sha} is broken")),
            );
            Ok(json!({
                "ok": index_ok && broken.is_empty(),
                "head": check.index.head,
                "problems": problems,
                "index": {
                    "records": check.index.records, "head": check.index.head, "ok": index_ok,
                    "problem": serde_json::to_value(&check.index.problem).unwrap_or(Value::Null),
                },
                "samples": samples,
                "broken": broken,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_parse_by_kind() {
        assert_eq!(parse_tag("lab").unwrap().kind, TagKind::Custom);
        assert_eq!(parse_tag("custom=a=b").unwrap().value, "a=b");
        assert_eq!(
            parse_tag("technique=T1053.003 Cron").unwrap().kind,
            TagKind::Technique
        );
        for bad in ["shade=red", "technique=nope", "", "verdict=great"] {
            assert!(parse_tag(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn library_errors_map_to_codes() {
        let code = |text: &str| library_error(text.into()).code;
        assert_eq!(
            code("this sample is not in the library"),
            ErrorCode::NotFound
        );
        assert_eq!(code("\"x\" is not a verdict"), ErrorCode::InvalidArgument);
        assert_eq!(code("disk I/O error"), ErrorCode::Internal);
    }

    #[test]
    fn a_data_directory_without_a_library_reads_empty_and_stays_empty() {
        let root = std::env::temp_dir().join(format!("ant-svc-lib-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        assert!(open_existing(&root).unwrap().is_none());
        let listed = list(None, &SampleListParams::default()).unwrap();
        assert_eq!(listed["samples"], json!([]));
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
