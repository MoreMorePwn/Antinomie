// SPDX-License-Identifier: MIT
//! Bounded, read-only pages of the normalized event journal Sigma evaluates.
//!
//! The journal is published by atomic rename and never appended to, so a read
//! sees one fixed file. Each page is a full bounded pass over it: the pass
//! also yields the whole-journal counts, end record and SHA-256, which is how
//! a page is tied to the digest a scan recorded.
use super::{Event, Evidence, Identity, JOURNAL_FILE, JOURNAL_VERSION, JOURNAL_VERSION_MIN};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

/// Event rows in one page.
pub const PAGE_SIZE: usize = 100;
/// Largest journal read (octets); the writer stops before this.
const MAX_FILE: u64 = 128 * 1024 * 1024;
/// Longest record (octets) the writer produces, including its newline.
const MAX_LINE: u64 = 64 * 1024;
/// Events the Sigma adapter accepts.
const MAX_EVENTS: u64 = 1_000_000;
const MAX_CATEGORIES: usize = 64;

/// The event a page must contain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Focus {
    /// A one-based ordinal, as recorded with a Sigma finding. Needs the
    /// journal the scan read, so it is refused when the digest differs.
    Event(u64),
    /// The first event recorded for a call or packet. Used for findings saved
    /// before ordinals were kept; one source can have several events.
    Source(Evidence),
}

#[derive(Clone, Debug)]
pub struct Query {
    /// Run folder holding the journal.
    pub directory: PathBuf,
    /// Identity the journal header must carry.
    pub identity: Identity,
    /// Journal digest recorded by the scan being inspected, if any.
    pub scanned: Option<String>,
    /// Exact category, or empty for all.
    pub category: String,
    /// Case-insensitive text found in a category, field name or value.
    pub text: String,
    /// First matching row of the page. Replaced by the page holding `focus`.
    pub offset: usize,
    pub focus: Option<Focus>,
}

#[derive(Clone, Debug)]
pub struct Row {
    /// One-based position in the journal; Sigma's `_event_id`.
    pub id: u64,
    pub event: Event,
}

/// The end record, as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct End {
    pub complete: bool,
    pub events: u64,
    pub omitted: u64,
}

#[derive(Clone, Debug)]
pub struct Page {
    pub rows: Vec<Row>,
    /// Matching-row index of the first row.
    pub offset: usize,
    /// Rows matching the filter, over the whole journal.
    pub matching: u64,
    /// Events read, unfiltered.
    pub events: u64,
    pub categories: BTreeMap<String, u64>,
    pub format_version: u64,
    pub end: Option<End>,
    /// Why only part of the file could be shown; empty when all of it was read.
    pub warnings: Vec<String>,
    pub sha256: String,
    pub size: u64,
    /// Whether the digest equals `Query::scanned`; `None` without one.
    pub scanned_match: Option<bool>,
    /// Events sharing a `Focus::Source`; above one the match is ambiguous.
    pub source_matches: u64,
}

impl Page {
    /// Every captured call was normalized and the file was read to its end.
    pub fn complete(&self) -> bool {
        self.warnings.is_empty()
            && self
                .end
                .is_some_and(|end| end.complete && end.omitted == 0 && end.events == self.events)
    }

    /// Events the writer left out (oversized or past its size bound).
    pub fn omitted(&self) -> u64 {
        self.end.map_or(0, |end| end.omitted)
    }
}

/// `3 events · process_creation 2 · file_event 1`, most frequent first.
pub fn category_detail(categories: &BTreeMap<String, u64>) -> String {
    let mut counted: Vec<_> = categories.iter().collect();
    counted.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let total: u64 = counted.iter().map(|(_, count)| **count).sum();
    let mut detail = format!(
        "{} {}",
        super::group_digits(total),
        if total == 1 { "event" } else { "events" }
    );
    for (category, count) in counted {
        detail.push_str(&format!(" · {category} {}", super::group_digits(*count)));
    }
    detail
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_lowercase(),
        other => other.to_string().to_lowercase(),
    }
}

fn contains_text(event: &Event, needle: &str) -> bool {
    event.category.to_lowercase().contains(needle)
        || event.fields.iter().any(|(name, value)| {
            name.to_lowercase().contains(needle) || value_text(value).contains(needle)
        })
}

fn within_schema(event: &Event, categories: &BTreeMap<String, u64>) -> bool {
    event.category.len() <= 64
        && event.fields.len() <= 64
        && event.inferred.len() <= 64
        && event.inferred.iter().all(|name| name.len() <= 64)
        && matches!(
            event.evidence,
            Evidence::Call { .. } | Evidence::Packet { .. }
        )
        && event
            .fields
            .iter()
            .all(|(name, value)| name.len() <= 64 && value.to_string().len() <= 8192)
        && (categories.contains_key(&event.category) || categories.len() < MAX_CATEGORIES)
}

fn end_record(value: &Value) -> Option<End> {
    Some(End {
        complete: value["complete"].as_bool()?,
        events: value["events"].as_u64()?,
        omitted: value["omitted"].as_u64()?,
    })
}

/// Read one page and the whole-journal facts off the interactive thread.
///
/// | Argument | Meaning |
/// | --- | --- |
/// | `query` | Run folder and identity, optional scanned digest, filter, row offset and focus |
/// | `cancel` | Checked before every record; set it to abandon the read |
///
/// The file is opened read-only as a regular member of the run folder and is
/// never written. Memory holds at most `2 * PAGE_SIZE` events of at most 64 KiB
/// each; the file is bounded to 128 MiB and 1,000,000 events. A header that is
/// missing or belongs to another run, or an over-long record, is an error. A
/// malformed record or missing end keeps the valid prefix and says so in
/// `warnings`. `Focus::Event` is refused when the digest differs from
/// `query.scanned`, because the ordinal then names a different event.
pub fn read_page(query: &Query, cancel: &AtomicBool) -> Result<Page, String> {
    if query.category.len() > 64 || query.text.len() > 512 || query.offset > MAX_EVENTS as usize {
        return Err("journal query exceeds its bounds".into());
    }
    let file =
        crate::archive_io::open_regular(&query.directory, &query.directory.join(JOURNAL_FILE))
            .map_err(|error| format!("event journal: {error}"))?;
    if file.metadata().map_err(|error| error.to_string())?.len() > MAX_FILE {
        return Err("event journal exceeds 128 MiB".into());
    }
    let mut reader = BufReader::new(file);
    let mut hash = Sha256::new();
    let mut line = Vec::with_capacity(MAX_LINE as usize + 1);
    let mut size = 0_u64;
    let mut headed = false;
    let mut format_version = 0;
    let mut end = None;
    let mut ended = false;
    let mut stopped = false;
    let mut warnings = Vec::new();
    let mut categories = BTreeMap::<String, u64>::new();
    let mut events = 0_u64;
    let mut matching = 0_u64;
    let mut rows = Vec::new();
    // Rows since the last page boundary, kept until a focus is found.
    let mut window = VecDeque::new();
    let mut offset = query.offset;
    let mut focused = query.focus.is_none();
    let mut source_matches = 0_u64;
    let needle = query.text.to_lowercase();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("journal read cancelled".into());
        }
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if read as u64 > MAX_LINE || size > MAX_FILE {
            return Err("event journal record or file exceeds its bound".into());
        }
        hash.update(&line);
        // After the first bad record the rest is only hashed, so the digest
        // still describes the whole file.
        if stopped {
            continue;
        }
        let mut stop = |reason: String| {
            warnings.push(reason);
            stopped = true;
        };
        if line.last() != Some(&b'\n') {
            stop("The journal ends in an unfinished record; its valid part is shown".into());
            continue;
        }
        let value: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(error) => {
                stop(format!(
                    "A journal record is invalid; the part before it is shown: {error}"
                ));
                continue;
            }
        };
        if !headed {
            let identity = serde_json::from_value::<Identity>(value["identity"].clone()).ok();
            format_version = value["format_version"].as_u64().unwrap_or(0);
            if value["kind"] != "header"
                || !(JOURNAL_VERSION_MIN..=JOURNAL_VERSION).contains(&format_version)
                || identity.as_ref() != Some(&query.identity)
            {
                return Err("the event journal belongs to another run or format".into());
            }
            headed = true;
            continue;
        }
        if ended {
            stop("The journal has records after its end record; they are not shown".into());
            continue;
        }
        if value["kind"] == "end" {
            end = end_record(&value);
            ended = true;
            continue;
        }
        if value["kind"] != "event" || events >= MAX_EVENTS {
            stop("The journal has an unsupported record or too many events".into());
            continue;
        }
        let event: Event = match serde_json::from_value(value["event"].clone()) {
            Ok(event) if within_schema(&event, &categories) => event,
            Ok(_) => {
                stop("An event is outside the captured field and category limits".into());
                continue;
            }
            Err(error) => {
                stop(format!("An event record is invalid: {error}"));
                continue;
            }
        };
        events += 1;
        *categories.entry(event.category.clone()).or_default() += 1;
        let by_source =
            matches!(&query.focus, Some(Focus::Source(source)) if *source == event.evidence);
        source_matches += u64::from(by_source);
        if (!query.category.is_empty() && event.category != query.category)
            || (!needle.is_empty() && !contains_text(&event, &needle))
        {
            continue;
        }
        let index = (matching as usize).min(usize::MAX - 1);
        matching += 1;
        let row = Row { id: events, event };
        if focused {
            if index >= offset && index < offset.saturating_add(PAGE_SIZE) {
                rows.push(row);
            }
            continue;
        }
        if index.is_multiple_of(PAGE_SIZE) {
            window.clear();
        }
        let found = match &query.focus {
            Some(Focus::Event(id)) => row.id == *id,
            _ => by_source,
        };
        window.push_back(row);
        if found {
            offset = index / PAGE_SIZE * PAGE_SIZE;
            rows.extend(window.drain(..));
            focused = true;
        }
    }
    if !headed {
        return Err("the event journal has no header".into());
    }
    let sha256 = format!("{:x}", hash.finalize());
    let scanned_match = query.scanned.as_ref().map(|scanned| *scanned == sha256);
    if !focused {
        return Err("the event is not in this journal".into());
    }
    if matches!(query.focus, Some(Focus::Event(_))) && scanned_match == Some(false) {
        return Err(
            "the journal changed after this scan, so its event numbers no longer apply; scan again"
                .into(),
        );
    }
    if end.is_none() && warnings.is_empty() {
        warnings.push("The journal has no end record; it may have been cut short".into());
    }
    if let Some(end) = end.filter(|end| end.events != events) {
        warnings.push(format!(
            "The end record counts {} events but {} were read",
            end.events, events
        ));
    }
    Ok(Page {
        rows,
        offset,
        matching,
        events,
        categories,
        format_version,
        end,
        warnings,
        sha256,
        size,
        scanned_match,
        source_matches,
    })
}

#[cfg(test)]
mod tests;
