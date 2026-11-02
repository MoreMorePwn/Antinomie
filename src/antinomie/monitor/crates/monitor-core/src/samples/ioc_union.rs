// SPDX-License-Identifier: GPL-3.0-only
//! Every indicator of every run of a sample, one row per unique indicator,
//! from the runs' Triage digests: which runs had it, how it was observed,
//! when, and which stored abuse.ch records matched it. Pure: it only reads
//! digests, so the sample window, the exports and the report agree.
use crate::run_digest::{IndicatorEntry, IndicatorHit, RunDigest};
use std::collections::{BTreeMap, BTreeSet};

/// One run's sighting of an indicator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub run: usize,
    pub entry: IndicatorEntry,
}

/// One indicator, in the runs that had it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampleIoc {
    /// `endpoint`, `domain`, `url`, `tls` or `file`.
    pub ty: String,
    pub value: String,
    /// A file's path in the guest (part of its identity); empty otherwise.
    pub path: String,
    /// Ascending by run number.
    pub sightings: Vec<Sighting>,
}

/// The union over the runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Union {
    pub rows: Vec<SampleIoc>,
    /// Runs whose digest has an indicator list.
    pub listed: Vec<usize>,
    /// Runs without one: never read by Triage, or read without indicators.
    pub unlisted: Vec<usize>,
    /// Listed runs whose digest was written before 0.8.2 and so has no
    /// sources, times or hits.
    pub plain: Vec<usize>,
}

/// Add up the runs' digests (`None`: never read by Triage).
pub fn union(runs: &[(usize, Option<&RunDigest>)]) -> Union {
    let mut out = Union::default();
    let mut map: BTreeMap<(String, String, String), SampleIoc> = BTreeMap::new();
    for (number, digest) in runs {
        let Some(list) = digest.and_then(|digest| digest.indicators.as_ref()) else {
            out.unlisted.push(*number);
            continue;
        };
        out.listed.push(*number);
        if !list.is_empty() && list.iter().all(|entry| entry.sources.is_empty()) {
            out.plain.push(*number);
        }
        for entry in list {
            let path = if entry.ty == "file" {
                entry.path.clone()
            } else {
                String::new()
            };
            let row = map
                .entry((entry.ty.clone(), entry.value.clone(), path.clone()))
                .or_insert_with(|| SampleIoc {
                    ty: entry.ty.clone(),
                    value: entry.value.clone(),
                    path,
                    sightings: Vec::new(),
                });
            if !row.sightings.iter().any(|seen| seen.run == *number) {
                row.sightings.push(Sighting {
                    run: *number,
                    entry: entry.clone(),
                });
            }
        }
    }
    out.rows = map.into_values().collect();
    for row in &mut out.rows {
        row.sightings.sort_by_key(|seen| seen.run);
    }
    out.rows.sort_by(|a, b| {
        b.matched()
            .cmp(&a.matched())
            .then_with(|| kind_rank(&a.ty).cmp(&kind_rank(&b.ty)))
            .then_with(|| a.value.cmp(&b.value))
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

/// The order of the kinds in the chips and the table.
pub const KINDS: [(&str, &str); 5] = [
    ("domain", "Domains"),
    ("endpoint", "Endpoints"),
    ("url", "URLs"),
    ("file", "Files"),
    ("tls", "TLS"),
];

fn kind_rank(ty: &str) -> usize {
    KINDS
        .iter()
        .position(|(id, _)| *id == ty)
        .unwrap_or(KINDS.len())
}

/// The plural label of a kind id.
pub fn kind_label(ty: &str) -> &str {
    KINDS
        .iter()
        .find(|(id, _)| *id == ty)
        .map_or(ty, |(_, label)| label)
}

impl SampleIoc {
    pub fn runs(&self) -> Vec<usize> {
        self.sightings.iter().map(|seen| seen.run).collect()
    }

    pub fn matched(&self) -> bool {
        self.sightings.iter().any(|seen| seen.entry.matched)
    }

    /// Seen in all of the `listed` runs.
    pub fn in_every_run(&self, listed: usize) -> bool {
        listed > 0 && self.sightings.len() == listed
    }

    pub fn first_us(&self) -> Option<u64> {
        self.sightings
            .iter()
            .filter_map(|seen| seen.entry.first_us)
            .min()
    }

    pub fn last_us(&self) -> Option<u64> {
        self.sightings
            .iter()
            .filter_map(|seen| seen.entry.last_us)
            .max()
    }

    /// How it was observed, over all runs, in words.
    pub fn observed(&self) -> Vec<String> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        for seen in &self.sightings {
            let entry = &seen.entry;
            let has = |source: &str| entry.sources.iter().any(|have| have == source);
            match self.ty.as_str() {
                "domain" => {
                    for (key, text) in [
                        ("DNS", "DNS query"),
                        ("SNI", "TLS server name"),
                        ("HTTP Host", "HTTP Host header"),
                        ("sample string", "string in the sample"),
                    ] {
                        if entry.sub.contains(key) {
                            out.insert(text.to_owned());
                        }
                    }
                }
                "endpoint" => {
                    if has("syscall") {
                        out.insert("connect".to_owned());
                    }
                    if has("pcap") {
                        out.insert("packets".to_owned());
                    }
                }
                "url" => {
                    out.insert("HTTP request".to_owned());
                }
                "tls" => {
                    out.insert("TLS handshake".to_owned());
                }
                _ => {
                    for role in &entry.roles {
                        out.insert(
                            match role.as_str() {
                                "created" | "written at close" => "file write",
                                "changed" => "file changed",
                                "deleted" => "file deleted",
                                "executed" => "executed",
                                "sample" => "the sample itself",
                                other => other,
                            }
                            .to_owned(),
                        );
                    }
                    if has("static") && entry.roles.is_empty() {
                        out.insert("hash of the sample".to_owned());
                    }
                }
            }
        }
        out.into_iter().collect()
    }

    /// The stored dataset records that matched it in any run, once each.
    pub fn hits(&self) -> Vec<IndicatorHit> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for sighting in &self.sightings {
            for hit in &sighting.entry.hits {
                if seen.insert((hit.dataset.clone(), hit.record_id.clone())) {
                    out.push(hit.clone());
                }
            }
        }
        out
    }

    /// The processes that made it, `name · pid`.
    pub fn processes(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .sightings
            .iter()
            .map(|seen| seen.entry.process.clone())
            .filter(|process| !process.is_empty())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// A private, loopback or local address or name: nothing a feed can list.
    pub fn private(&self) -> bool {
        self.sightings.iter().any(|seen| {
            matches!(
                seen.entry.not_checked.as_str(),
                "private address" | "local name"
            )
        })
    }

    /// The guest's own infrastructure: the base image's traffic, or the
    /// emulated network's own addresses (10.0.2.x).
    pub fn guest_infrastructure(&self) -> bool {
        self.sightings
            .iter()
            .all(|seen| !seen.entry.noise.is_empty())
            || (self.ty == "endpoint" && self.value.starts_with("10.0.2."))
    }

    /// The row's second line from the newest sighting.
    pub fn sub(&self) -> &str {
        self.sightings
            .iter()
            .rev()
            .map(|seen| seen.entry.sub.as_str())
            .find(|sub| !sub.is_empty())
            .unwrap_or("")
    }

    /// What the search box looks in.
    pub fn haystack(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.ty,
            self.value,
            self.path,
            self.sub(),
            self.processes().join(" ")
        )
        .to_lowercase()
    }
}
