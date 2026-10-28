// SPDX-License-Identifier: GPL-3.0-only
//! The rules of the custody hash chain, as pure functions over entries.
//!
//! The library checks the rows of its database with them, and the record
//! verifier checks an exported record with them, so a record and the library
//! agree on what "verified" means. `verify-custody.py` (bundled with every
//! JSON export) is the same rules in Python for a machine without Antinomie.
//!
//! Every sample has a chain: entry N holds the SHA-256 of entry N-1 (the
//! first holds 64 zeros) and its own hash covers all its fields and that
//! link. The library index chain records, for every entry appended anywhere,
//! the sample, the entry number and the entry's hash; it also records purges.
//! Editing an entry breaks its hash. Removing or reordering entries breaks
//! the links. Rewriting a whole chain still breaks the index, which names
//! every entry's hash; rewriting both leaves only a head hash the analyst
//! kept elsewhere. That makes the log tamper-evident, not tamper-proof.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The link of the first entry of a chain.
pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const ENTRY_TAG: &str = "antinomie-custody-entry-v1";
const INDEX_TAG: &str = "antinomie-custody-index-v1";

/// One entry of a sample's chain, as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub at_ms: u64,
    pub by: String,
    /// The event's kind key.
    pub kind: String,
    /// The event as JSON text, exactly as hashed.
    pub detail: String,
    /// The entry was brought in from the plain event list of an earlier
    /// build: it was recorded before the custody log existed.
    pub before_chain: bool,
    pub prev: String,
    pub hash: String,
}

/// One record of the library index chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexRecord {
    pub seq: u64,
    pub at_ms: u64,
    /// `head` (an entry was appended to a sample's chain) or `purge`.
    pub kind: String,
    pub sha256: String,
    pub entry_seq: u64,
    pub entry_hash: String,
    pub prev: String,
    pub hash: String,
}

fn field(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value.as_bytes());
    out.push(b'\n');
}

fn digest(fields: &[&str]) -> String {
    let mut bytes = Vec::new();
    for value in fields {
        field(&mut bytes, value);
    }
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The hash an entry must carry.
pub fn entry_hash(sha256: &str, entry: &Entry) -> String {
    digest(&[
        ENTRY_TAG,
        sha256,
        &entry.seq.to_string(),
        &entry.at_ms.to_string(),
        &entry.by,
        &entry.kind,
        if entry.before_chain { "1" } else { "0" },
        &entry.detail,
        &entry.prev,
    ])
}

/// The hash an index record must carry.
pub fn index_hash(record: &IndexRecord) -> String {
    digest(&[
        INDEX_TAG,
        &record.seq.to_string(),
        &record.at_ms.to_string(),
        &record.kind,
        &record.sha256,
        &record.entry_seq.to_string(),
        &record.entry_hash,
        &record.prev,
    ])
}

/// What is wrong with a chain, and at which entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    /// The first entry that cannot be trusted.
    pub at: u64,
    pub text: String,
}

/// How an entry stands after a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    Verified,
    Changed,
    /// After the first problem: the links no longer vouch for it.
    Unverified,
}

/// The result of checking one sample's chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainCheck {
    pub entries: u64,
    /// The hash of the last entry (zeros for an empty chain).
    pub head: String,
    pub problem: Option<Problem>,
}

impl ChainCheck {
    pub fn ok(&self) -> bool {
        self.problem.is_none()
    }

    pub fn state_of(&self, seq: u64) -> EntryState {
        match &self.problem {
            None => EntryState::Verified,
            Some(problem) if seq < problem.at => EntryState::Verified,
            Some(problem) if seq == problem.at => EntryState::Changed,
            Some(_) => EntryState::Unverified,
        }
    }

    /// One line for a banner or a log.
    pub fn summary(&self) -> String {
        match &self.problem {
            None if self.entries == 0 => "No entries".into(),
            None => format!(
                "{} entries, every link matches; head {}",
                self.entries,
                short(&self.head)
            ),
            Some(problem) => {
                let mut text = problem.text.clone();
                if let Some(first) = text.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                text
            }
        }
    }
}

/// The first eight hex digits of a hash.
pub fn short(hash: &str) -> &str {
    hash.get(..8).unwrap_or(hash)
}

fn note(problem: &mut Option<Problem>, at: u64, text: String) {
    if problem.as_ref().is_none_or(|known| at < known.at) {
        *problem = Some(Problem { at, text });
    }
}

/// Check one sample's chain. `entries` are in storage order; `heads` are the
/// library index's `head` records for this sample since its last purge.
pub fn check_chain(sha256: &str, entries: &[Entry], heads: &[&IndexRecord]) -> ChainCheck {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by_key(|entry| entry.seq);
    let mut problem = None;
    let mut previous = ZERO.to_owned();
    for (expected, entry) in (1u64..).zip(sorted.iter()) {
        if entry.seq != expected {
            note(
                &mut problem,
                expected,
                format!("entry {expected} is missing"),
            );
            break;
        }
        if entry_hash(sha256, entry) != entry.hash {
            note(
                &mut problem,
                entry.seq,
                format!("entry {} was edited after it was written", entry.seq),
            );
            break;
        }
        if entry.prev != previous {
            if entry.seq == 1 {
                note(
                    &mut problem,
                    1,
                    "the first entry does not start the chain".into(),
                );
            } else {
                note(
                    &mut problem,
                    entry.seq - 1,
                    format!(
                        "entry {} was replaced: entry {} records another hash for it",
                        entry.seq - 1,
                        entry.seq
                    ),
                );
            }
            break;
        }
        previous = entry.hash.clone();
    }
    let count = sorted.last().map_or(0, |entry| entry.seq);
    let last_indexed = heads.iter().map(|head| head.entry_seq).max().unwrap_or(0);
    if sorted.is_empty() && last_indexed > 0 {
        note(
            &mut problem,
            1,
            format!("the whole log is gone; the library index recorded {last_indexed} entries"),
        );
    } else {
        for head in heads {
            match sorted.iter().find(|entry| entry.seq == head.entry_seq) {
                None => note(
                    &mut problem,
                    head.entry_seq,
                    format!(
                        "entry {} is gone; the library index recorded it",
                        head.entry_seq
                    ),
                ),
                Some(entry) if entry.hash != head.entry_hash => note(
                    &mut problem,
                    entry.seq,
                    format!(
                        "entry {} differs from what the library index recorded",
                        entry.seq
                    ),
                ),
                Some(_) => {}
            }
        }
        if count > last_indexed {
            note(
                &mut problem,
                last_indexed + 1,
                format!("entry {} is not in the library index", last_indexed + 1),
            );
        }
    }
    ChainCheck {
        entries: count,
        head: sorted
            .last()
            .map_or_else(|| ZERO.to_owned(), |entry| entry.hash.clone()),
        problem,
    }
}

/// The result of checking the library index chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexCheck {
    pub records: u64,
    pub head: String,
    pub problem: Option<Problem>,
}

/// Check the library index chain: contiguous numbers, links and hashes.
pub fn check_index(records: &[IndexRecord]) -> IndexCheck {
    let mut sorted: Vec<&IndexRecord> = records.iter().collect();
    sorted.sort_by_key(|record| record.seq);
    let mut problem = None;
    let mut previous = ZERO.to_owned();
    for (expected, record) in (1u64..).zip(sorted.iter()) {
        if record.seq != expected {
            note(
                &mut problem,
                expected,
                format!("index record {expected} is missing"),
            );
            break;
        }
        if index_hash(record) != record.hash {
            note(
                &mut problem,
                record.seq,
                format!("index record {} was edited", record.seq),
            );
            break;
        }
        if record.prev != previous {
            note(
                &mut problem,
                record.seq.saturating_sub(1).max(1),
                format!("index record {} was replaced", record.seq.saturating_sub(1)),
            );
            break;
        }
        previous = record.hash.clone();
    }
    IndexCheck {
        records: sorted.last().map_or(0, |record| record.seq),
        head: sorted
            .last()
            .map_or_else(|| ZERO.to_owned(), |record| record.hash.clone()),
        problem,
    }
}

/// The index records that vouch for `sha256`'s present chain: its `head`
/// records after its last `purge`.
pub fn heads_of<'a>(sha256: &str, index: &'a [IndexRecord]) -> Vec<&'a IndexRecord> {
    let mut sorted: Vec<&IndexRecord> = index
        .iter()
        .filter(|record| record.sha256 == sha256)
        .collect();
    sorted.sort_by_key(|record| record.seq);
    let start = sorted
        .iter()
        .rposition(|record| record.kind == "purge")
        .map_or(0, |at| at + 1);
    sorted
        .into_iter()
        .skip(start)
        .filter(|record| record.kind == "head")
        .collect()
}

/// Check an exported record: the chain as [`check_chain`] does, and every
/// index record's own hash. `index` is what the record carries.
pub fn check_record(sha256: &str, entries: &[Entry], index: &[IndexRecord]) -> ChainCheck {
    let mut check = check_chain(sha256, entries, &heads_of(sha256, index));
    for record in index {
        if index_hash(record) != record.hash {
            note(
                &mut check.problem,
                record.entry_seq.max(1),
                format!("index record {} was edited", record.seq),
            );
        }
    }
    check
}
