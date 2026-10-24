// SPDX-License-Identifier: GPL-3.0-only
//! The list of known false positives: values someone looked at and decided are
//! not a threat, with the reason. The IOC window files a match here with
//! "Mark as false positive" and shows a listed match as "Known FP"; a future
//! Hunting window can use the same list through the same few functions.
//!
//! An entry has a value, a type (the same kinds the IOC window uses), an
//! optional dataset and a reason. Without a dataset it excuses the value
//! whichever dataset lists it; with one, only that dataset's records. The
//! list is `<data dir>/known-false-positives.json`.
use crate::ioc::Kind;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const FILE: &str = "known-false-positives.json";
/// Most entries kept.
pub const MAX_ENTRIES: usize = 10_000;
/// Longest reason kept, in characters.
pub const MAX_REASON_LEN: usize = 500;

/// One excused value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// In the normal form of its kind.
    pub value: String,
    pub kind: Kind,
    /// A feed id (`threatfox`, `urlhaus`, ...), or `None` for any dataset.
    #[serde(default)]
    pub dataset: Option<String>,
    pub reason: String,
    /// Unix seconds when it was added.
    #[serde(default)]
    pub added_unix: u64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Stored {
    schema: u32,
    entries: Vec<Entry>,
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

/// Every entry, oldest first. A missing or unreadable file is an empty list.
pub fn load(data_dir: &Path) -> Vec<Entry> {
    std::fs::read(path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Stored>(&bytes).ok())
        .map(|stored| stored.entries)
        .unwrap_or_default()
}

fn store(data_dir: &Path, entries: Vec<Entry>) -> Result<(), String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|error| format!("{}: {error}", data_dir.display()))?;
    crate::storage::atomic_json(&path(data_dir), &Stored { schema: 1, entries })
}

fn same(a: &Entry, kind: Kind, value: &str, dataset: Option<&str>) -> bool {
    a.kind == kind && a.value == value && a.dataset.as_deref() == dataset
}

/// Add an entry; the same value, type and dataset replaces the old entry (and
/// its reason). The value is put into its normal form first.
pub fn add(
    data_dir: &Path,
    kind: Kind,
    value: &str,
    dataset: Option<&str>,
    reason: &str,
    now_unix: u64,
) -> Result<(), String> {
    let value = kind
        .normalize(value)
        .ok_or_else(|| format!("{value:?} is not a {}", kind.id()))?;
    let mut entries = load(data_dir);
    entries.retain(|entry| !same(entry, kind, &value, dataset));
    if entries.len() >= MAX_ENTRIES {
        return Err(format!("the list is full ({MAX_ENTRIES} entries)"));
    }
    entries.push(Entry {
        value,
        kind,
        dataset: dataset.map(str::to_owned),
        reason: reason.trim().chars().take(MAX_REASON_LEN).collect(),
        added_unix: now_unix,
    });
    store(data_dir, entries)
}

/// Remove the entry for exactly this value, type and dataset; `false` when
/// there was none.
pub fn remove(
    data_dir: &Path,
    kind: Kind,
    value: &str,
    dataset: Option<&str>,
) -> Result<bool, String> {
    let value = kind.normalize(value).unwrap_or_else(|| value.to_owned());
    let mut entries = load(data_dir);
    let before = entries.len();
    entries.retain(|entry| !same(entry, kind, &value, dataset));
    if entries.len() == before {
        return Ok(false);
    }
    store(data_dir, entries)?;
    Ok(true)
}

/// The entry that excuses `value` of `kind` as listed by `dataset`: one for
/// that dataset first, else one for any dataset.
pub fn find<'a>(entries: &'a [Entry], kind: Kind, value: &str, dataset: &str) -> Option<&'a Entry> {
    let value = kind.normalize(value)?;
    let mut any = None;
    for entry in entries
        .iter()
        .filter(|e| e.kind == kind && e.value == value)
    {
        match entry.dataset.as_deref() {
            Some(name) if name == dataset => return Some(entry),
            None => any = any.or(Some(entry)),
            Some(_) => {}
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ant-fp-{name}-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn entries_are_added_replaced_found_and_removed() {
        let dir = dir("list");
        assert!(load(&dir).is_empty());
        add(
            &dir,
            Kind::Domain,
            "POOL.NTP.example.",
            None,
            "Time pool.",
            100,
        )
        .unwrap();
        add(
            &dir,
            Kind::IpPort,
            "203.0.113.123:123",
            Some("threatfox"),
            "NTP",
            101,
        )
        .unwrap();
        let entries = load(&dir);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, "pool.ntp.example");
        // Any dataset for the first, only ThreatFox for the second.
        assert!(find(&entries, Kind::Domain, "pool.ntp.example", "urlhaus").is_some());
        assert!(find(&entries, Kind::IpPort, "203.0.113.123:123", "threatfox").is_some());
        assert!(find(&entries, Kind::IpPort, "203.0.113.123:123", "feodo").is_none());
        assert!(find(&entries, Kind::Domain, "other.example", "urlhaus").is_none());
        // The same key replaces its reason.
        add(
            &dir,
            Kind::Domain,
            "pool.ntp.example",
            None,
            "  New reason  ",
            200,
        )
        .unwrap();
        let entries = load(&dir);
        assert_eq!(entries.len(), 2);
        let again = find(&entries, Kind::Domain, "pool.ntp.example", "x").unwrap();
        assert_eq!(
            (again.reason.as_str(), again.added_unix),
            ("New reason", 200)
        );
        assert!(remove(&dir, Kind::Domain, "POOL.ntp.example", None).unwrap());
        assert!(!remove(&dir, Kind::Domain, "pool.ntp.example", None).unwrap());
        assert_eq!(load(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_dataset_entry_wins_over_an_any_dataset_entry() {
        let dir = dir("pick");
        add(&dir, Kind::Domain, "a.example", None, "general", 1).unwrap();
        add(
            &dir,
            Kind::Domain,
            "a.example",
            Some("urlhaus"),
            "specific",
            2,
        )
        .unwrap();
        let entries = load(&dir);
        assert_eq!(
            find(&entries, Kind::Domain, "a.example", "urlhaus")
                .unwrap()
                .reason,
            "specific"
        );
        assert_eq!(
            find(&entries, Kind::Domain, "a.example", "threatfox")
                .unwrap()
                .reason,
            "general"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_value_that_is_not_its_kind_is_refused_and_a_long_reason_is_cut() {
        let dir = dir("bad");
        assert!(add(&dir, Kind::Sha256, "abc", None, "x", 1).is_err());
        assert!(load(&dir).is_empty());
        add(
            &dir,
            Kind::Md5,
            "87221652a79fc3c9b04cde0b335fdd5b",
            None,
            &"é".repeat(900),
            1,
        )
        .unwrap();
        assert_eq!(load(&dir)[0].reason.chars().count(), MAX_REASON_LEN);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_damaged_file_reads_as_an_empty_list_and_is_replaced_on_the_next_add() {
        let dir = dir("damaged");
        std::fs::write(path(&dir), b"{ not json").unwrap();
        assert!(load(&dir).is_empty());
        add(&dir, Kind::Domain, "a.example", None, "ok", 1).unwrap();
        assert_eq!(load(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
