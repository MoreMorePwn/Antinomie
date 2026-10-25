// SPDX-License-Identifier: GPL-3.0-only
//! Matching a run's indicators against the stored datasets and deciding what
//! each indicator's verdict is: Matched, Known FP, No match or Not checked.
//!
//! Matching is offline: one pass over each stored feed looks for every value
//! the run could be matched by ([`scan_datasets`]). A verdict
//! ([`evaluate`]) then needs only that scan, the known false positives and
//! any online answers the person asked for, so changing a false-positive
//! entry never rereads a feed.
use super::{
    feeds::{self, FeedStatus},
    indicator::{Indicator, Lookup, Type},
    kind::Kind,
    records::{self, Hit, Record, Wanted},
};
use crate::known_fp;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::atomic::AtomicBool};

/// A feed the scan could read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedFeed {
    pub id: &'static str,
    pub name: &'static str,
    /// `YYYY-MM-DD` the copy was fetched.
    pub date: String,
    pub fetched_unix: u64,
}

/// The result of one pass over the stored datasets.
#[derive(Clone, Debug, Default)]
pub struct Scan {
    pub hits: Vec<Hit>,
    /// Feeds that were read (switched on, with a stored copy).
    pub loaded: Vec<LoadedFeed>,
    /// Feeds that failed to read, with the reason.
    pub errors: Vec<(&'static str, String)>,
    /// Hit positions by the value they answer.
    pub(super) index: std::collections::HashMap<(Kind, String), Vec<usize>>,
}

impl Scan {
    fn reindex(&mut self) {
        self.index.clear();
        for (at, hit) in self.hits.iter().enumerate() {
            self.index
                .entry((hit.kind, hit.value.clone()))
                .or_default()
                .push(at);
        }
    }

    /// The hits that answer one value.
    fn answers(&self, lookup: &Lookup) -> impl Iterator<Item = &Hit> {
        self.index
            .get(&(lookup.kind, lookup.value.clone()))
            .into_iter()
            .flatten()
            .map(|&at| &self.hits[at])
    }
}

/// Look for the values of `indicators` in every usable stored feed.
pub fn scan_datasets(
    data_dir: &Path,
    indicators: &[Indicator],
    cancel: &AtomicBool,
) -> Result<Scan, String> {
    let mut wanted = Wanted::default();
    for indicator in indicators {
        for lookup in &indicator.lookups {
            wanted.add(lookup.kind, lookup.value.clone());
        }
    }
    let mut scan = Scan::default();
    for status in feeds::status(data_dir).iter().filter(|s| s.usable()) {
        let (Some(meta), Some(path)) = (&status.meta, feeds::data_path(data_dir, status.feed))
        else {
            continue;
        };
        if !wanted.is_empty()
            && let Err(error) = records::scan(&path, status.feed, &wanted, cancel, &mut scan.hits)
        {
            if error == "cancelled" {
                return Err(error);
            }
            scan.errors.push((status.feed.id, error));
            continue;
        }
        scan.loaded.push(loaded(status, meta));
    }
    scan.reindex();
    Ok(scan)
}

fn loaded(status: &FeedStatus, meta: &feeds::FeedMeta) -> LoadedFeed {
    LoadedFeed {
        id: status.feed.id,
        name: status.feed.name,
        date: meta.date(),
        fetched_unix: meta.fetched_unix,
    }
}

/// The feeds that can answer for a type of indicator.
pub fn coverage(ty: Type) -> &'static [&'static str] {
    match ty {
        Type::Endpoint => &["threatfox", "feodo", "urlhaus"],
        Type::Domain => &["threatfox", "urlhaus"],
        Type::Url => &["urlhaus", "threatfox"],
        Type::Tls => &["sslbl-ja3", "sslbl-cert", "threatfox", "urlhaus"],
        Type::File => &["urlhaus-payloads", "threatfox"],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Matched,
    KnownFp,
    NoMatch,
    NotChecked,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::Matched => "Matched",
            Outcome::KnownFp => "Known FP",
            Outcome::NoMatch => "No match",
            Outcome::NotChecked => "Not checked",
        }
    }
}

/// A dataset record that answers one of an indicator's values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub lookup: Lookup,
    pub record: Record,
    /// Found by the online check, not in the stored datasets.
    pub online_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub outcome: Outcome,
    /// Records that count, best first.
    pub matches: Vec<Match>,
    /// The match a known false positive excuses, and the entry that does.
    pub excused: Option<(Match, known_fp::Entry)>,
    /// The dataset date the verdict carries.
    pub date: Option<String>,
    /// Feeds that answered and feeds that could have.
    pub feeds_used: usize,
    pub feeds_needed: usize,
    /// Why nothing was checked.
    pub why: String,
}

impl Verdict {
    fn bare(outcome: Outcome) -> Self {
        Self {
            outcome,
            matches: Vec::new(),
            excused: None,
            date: None,
            feeds_used: 0,
            feeds_needed: 0,
            why: String::new(),
        }
    }

    fn not_checked(why: impl Into<String>) -> Self {
        Self {
            why: why.into(),
            ..Self::bare(Outcome::NotChecked)
        }
    }

    pub fn primary(&self) -> Option<&Match> {
        self.matches.first()
    }

    /// Whether the verdict is partial: some feeds that could answer were not loaded.
    pub fn partial(&self) -> bool {
        self.feeds_used < self.feeds_needed
    }
}

/// Answers the online check gave, by lookup.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineResults {
    pub entries: Vec<OnlineEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineEntry {
    pub kind: Kind,
    pub value: String,
    pub at_unix: u64,
    /// Empty: abuse.ch knows nothing of it.
    pub records: Vec<OnlineRecord>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineRecord {
    pub dataset: String,
    pub record_id: String,
    pub family: String,
    pub confidence: Option<u8>,
    pub first_seen: String,
    pub detail: String,
    pub reference: String,
}

impl OnlineRecord {
    pub fn to_record(&self) -> Record {
        Record {
            feed: self.dataset.clone(),
            record_id: self.record_id.clone(),
            family: self.family.clone(),
            confidence: self.confidence,
            first_seen: self.first_seen.clone(),
            detail: self.detail.clone(),
            reference: self.reference.clone(),
        }
    }
}

impl OnlineResults {
    pub fn entry(&self, kind: Kind, value: &str) -> Option<&OnlineEntry> {
        self.entries
            .iter()
            .find(|entry| entry.kind == kind && entry.value == value)
    }

    /// Keep the newest answer for each value.
    pub fn insert(&mut self, entry: OnlineEntry) {
        self.entries
            .retain(|have| !(have.kind == entry.kind && have.value == entry.value));
        self.entries.push(entry);
    }
}

fn better(a: &Match, b: &Match) -> std::cmp::Ordering {
    // Higher confidence first, then the newer report.
    b.record
        .confidence
        .cmp(&a.record.confidence)
        .then_with(|| b.record.first_seen.cmp(&a.record.first_seen))
        .then_with(|| a.record.feed.cmp(&b.record.feed))
}

/// The verdict of one indicator.
pub fn evaluate(
    indicator: &Indicator,
    scan: &Scan,
    fp: &[known_fp::Entry],
    online: &OnlineResults,
) -> Verdict {
    if scan.loaded.is_empty() {
        return Verdict::not_checked("no datasets downloaded");
    }
    if let Some(why) = &indicator.not_checked {
        return Verdict::not_checked(why.clone());
    }
    let needed = coverage(indicator.ty);
    let used: Vec<&LoadedFeed> = scan
        .loaded
        .iter()
        .filter(|feed| needed.contains(&feed.id))
        .collect();
    if used.is_empty() {
        return Verdict::not_checked("feed not loaded");
    }
    if indicator.ty == Type::Tls && !used.iter().any(|feed| feed.id.starts_with("sslbl")) {
        return Verdict::not_checked("SSLBL not loaded");
    }
    let mut verdict = Verdict {
        feeds_used: used.len(),
        feeds_needed: needed.len(),
        ..Verdict::bare(Outcome::NoMatch)
    };
    verdict.date = used.iter().map(|feed| feed.date.clone()).min();
    let mut counted = Vec::new();
    let mut excused = Vec::new();
    for lookup in &indicator.lookups {
        for hit in scan.answers(lookup) {
            let found = Match {
                lookup: lookup.clone(),
                record: hit.record.clone(),
                online_at: None,
            };
            match known_fp::find(fp, hit.kind, &hit.value, &hit.record.feed) {
                Some(entry) => excused.push((found, entry.clone())),
                None => counted.push(found),
            }
        }
    }
    if counted.is_empty() {
        for lookup in &indicator.lookups {
            let Some(entry) = online.entry(lookup.kind, &lookup.value) else {
                continue;
            };
            for record in &entry.records {
                let found = Match {
                    lookup: lookup.clone(),
                    record: record.to_record(),
                    online_at: Some(entry.at_unix),
                };
                match known_fp::find(fp, lookup.kind, &lookup.value, &record.dataset) {
                    Some(excuse) => excused.push((found, excuse.clone())),
                    None => counted.push(found),
                }
            }
        }
    }
    counted.sort_by(better);
    excused.sort_by(|a, b| better(&a.0, &b.0));
    if !counted.is_empty() {
        verdict.outcome = Outcome::Matched;
        if let Some(first) = counted.first()
            && first.online_at.is_none()
        {
            verdict.date = scan
                .loaded
                .iter()
                .find(|feed| feed.id == first.record.feed)
                .map(|feed| feed.date.clone())
                .or(verdict.date);
        }
        verdict.matches = counted;
    } else if let Some(first) = excused.into_iter().next() {
        verdict.outcome = Outcome::KnownFp;
        verdict.excused = Some(first);
    }
    verdict
}

/// Counts of verdicts, for tabs and the Summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub matched: usize,
    pub known_fp: usize,
    pub no_match: usize,
    pub not_checked: usize,
}

impl Counts {
    pub fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Matched => self.matched += 1,
            Outcome::KnownFp => self.known_fp += 1,
            Outcome::NoMatch => self.no_match += 1,
            Outcome::NotChecked => self.not_checked += 1,
        }
    }

    pub fn all(&self) -> usize {
        self.matched + self.known_fp + self.no_match + self.not_checked
    }
}

/// The verdicts of all indicators, in the same order.
pub fn evaluate_all(
    indicators: &[Indicator],
    scan: &Scan,
    fp: &[known_fp::Entry],
    online: &OnlineResults,
) -> Vec<Verdict> {
    indicators
        .iter()
        .map(|indicator| evaluate(indicator, scan, fp, online))
        .collect()
}

/// Counts per type.
pub fn counts(indicators: &[Indicator], verdicts: &[Verdict]) -> BTreeMap<Type, Counts> {
    let mut out: BTreeMap<Type, Counts> = BTreeMap::new();
    for (indicator, verdict) in indicators.iter().zip(verdicts) {
        out.entry(indicator.ty).or_default().add(verdict.outcome);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_keys::Secret;
    use crate::ioc::{
        download::update_all,
        indicator::{Collector, Evidence, Hashes, Jump, Process, Seen, Source, TlsFacts, Via},
        records::fixtures::*,
    };
    use crate::ruleset::Fetcher;
    use std::{net::IpAddr, path::PathBuf};

    struct Fixtures;

    impl Fetcher for Fixtures {
        fn fetch(
            &self,
            url: &str,
            dest: &Path,
            _max: u64,
            _cancel: &AtomicBool,
            _progress: &mut dyn FnMut(u64),
        ) -> Result<(), String> {
            let feed = feeds::FEEDS.iter().find(|feed| feed.owns(url)).unwrap();
            let text = match feed.id {
                "threatfox" => THREATFOX,
                "urlhaus" => URLHAUS,
                "urlhaus-payloads" => PAYLOADS,
                "feodo" => FEODO,
                "sslbl-ja3" => SSLBL_JA3,
                _ => SSLBL_CERT,
            };
            std::fs::write(dest, text).map_err(|error| error.to_string())
        }
    }

    fn data_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ant-verdict-{name}-{}",
            crate::storage::unique_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn packet(frame: u64) -> Seen {
        Seen {
            time_us: Some(frame),
            evidence: Some(Evidence {
                source: Source::Pcap,
                label: format!("Packets · frame {frame}"),
                jump: Jump::Packet {
                    capture: "run.pcap".into(),
                    frame,
                },
            }),
            ..Seen::default()
        }
    }

    /// The invented run of the mockup: some indicators of every type.
    fn run() -> Vec<Indicator> {
        let mut c = Collector::default();
        let a = Process {
            pid: 1412,
            cookie: 1412,
            name: "kworkerd".into(),
        };
        let call = Seen {
            process: Some(a),
            ok: Some(true),
            time_us: Some(3),
            ..Seen::default()
        };
        c.endpoint(ip("203.0.113.45"), 443, "tcp", Source::Syscall, call);
        c.endpoint(ip("198.51.100.77"), 80, "tcp", Source::Pcap, packet(1022));
        c.endpoint(ip("203.0.113.123"), 123, "udp", Source::Pcap, packet(52));
        c.endpoint(
            ip("203.0.113.200"),
            4444,
            "tcp",
            Source::Static,
            Seen::default(),
        );
        c.endpoint(ip("10.0.2.3"), 53, "udp", Source::Pcap, packet(3));
        c.domain(
            "c2.update-cdn.example",
            Via::Dns,
            &[ip("203.0.113.45")],
            Source::Pcap,
            packet(188),
        );
        c.domain("pool.ntp.example", Via::Dns, &[], Source::Pcap, packet(47));
        c.domain(
            "gate.kd-relay.example",
            Via::Dns,
            &[],
            Source::Pcap,
            packet(1190),
        );
        c.url(
            "POST",
            "c2.update-cdn.example",
            "/gate.php",
            "HTTP/1.1",
            Some(200),
            Some((ip("203.0.113.45"), 443)),
            Source::Pcap,
            packet(270),
        );
        c.url(
            "GET",
            "cdn.fastmirror.example",
            "/bin/x86_64/.kd",
            "HTTP/1.1",
            Some(200),
            Some((ip("198.51.100.77"), 80)),
            Source::Pcap,
            packet(1030),
        );
        c.url(
            "GET",
            "gate.kd-relay.example",
            "/ping",
            "HTTP/2",
            None,
            None,
            Source::Pcap,
            packet(1196),
        );
        c.tls(
            (ip("203.0.113.45"), 443),
            TlsFacts {
                sni: "c2.update-cdn.example".into(),
                ja3: "f6d64cbcb6dead5e8e864400f056fa32".into(),
                cert_sha1: "2f22765d04931a078909145ca628d2264c852d7d".into(),
                ..TlsFacts::default()
            },
            Source::Pcap,
            packet(215),
        );
        c.file(
            "/tmp/.X11-unix/.kd",
            "created",
            Some(Hashes {
                sha256: "f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa".into(),
                md5: "87221652a79fc3c9b04cde0b335fdd5b".into(),
                sha1: "fbe0c7a10f88830329b843444e239faff412172d".into(),
            }),
            Source::Disk,
            Seen::default(),
        );
        c.file(
            "/var/tmp/.upd.sh",
            "deleted",
            None,
            Source::Syscall,
            Seen::default(),
        );
        c.finish()
    }

    fn outcome<'a>(all: &'a [Indicator], verdicts: &'a [Verdict], key: &str) -> &'a Verdict {
        let at = all
            .iter()
            .position(|i| i.key.contains(key))
            .unwrap_or_else(|| panic!("no {key}"));
        &verdicts[at]
    }

    fn installed(name: &str) -> PathBuf {
        let dir = data_dir(name);
        let outcomes = update_all(
            &dir,
            &Secret::new("fixture-key"),
            &Fixtures,
            &AtomicBool::new(false),
            &mut |_| {},
        );
        assert!(outcomes.iter().all(|o| o.result.is_ok()));
        dir
    }

    #[test]
    fn a_run_is_matched_against_all_six_feeds() {
        let dir = installed("all");
        let all = run();
        let scan = scan_datasets(&dir, &all, &AtomicBool::new(false)).unwrap();
        assert_eq!(scan.loaded.len(), 6);
        let verdicts = evaluate_all(&all, &scan, &[], &OnlineResults::default());
        let today = feeds::date_text(feeds::now_unix());
        let e1 = outcome(&all, &verdicts, "203.0.113.45:443");
        assert_eq!(e1.outcome, Outcome::Matched);
        assert_eq!(e1.date.as_deref(), Some(today.as_str()));
        // ThreatFox (75) outranks the no-confidence feeds.
        assert_eq!(e1.primary().unwrap().record.feed, "threatfox");
        assert_eq!(e1.primary().unwrap().record.family, "Mirai");
        assert!(e1.matches.len() >= 2, "threatfox and feodo list it");
        assert_eq!(
            outcome(&all, &verdicts, "198.51.100.77:80")
                .primary()
                .unwrap()
                .record
                .feed,
            "urlhaus"
        );
        assert_eq!(
            outcome(&all, &verdicts, "203.0.113.200:4444").outcome,
            Outcome::NoMatch
        );
        assert_eq!(
            outcome(&all, &verdicts, "10.0.2.3:53").outcome,
            Outcome::NotChecked
        );
        assert_eq!(
            outcome(&all, &verdicts, "c2.update-cdn.example")
                .primary()
                .unwrap()
                .record
                .record_id,
            "1831207"
        );
        assert_eq!(
            outcome(&all, &verdicts, "gate.kd-relay.example").outcome,
            Outcome::NoMatch
        );
        assert_eq!(
            outcome(&all, &verdicts, "POST c2.update-cdn.example/gate.php").outcome,
            Outcome::Matched
        );
        assert_eq!(
            outcome(&all, &verdicts, "GET cdn.fastmirror.example/bin")
                .primary()
                .unwrap()
                .record
                .record_id,
            "3350921"
        );
        let tls = all.iter().position(|i| i.ty == Type::Tls).unwrap();
        assert_eq!(verdicts[tls].outcome, Outcome::Matched);
        assert!(
            verdicts[tls]
                .matches
                .iter()
                .any(|m| m.lookup.kind == Kind::Ja3)
        );
        assert!(
            verdicts[tls]
                .matches
                .iter()
                .any(|m| m.lookup.kind == Kind::CertSha1)
        );
        let kd = all
            .iter()
            .position(|i| i.path == "/tmp/.X11-unix/.kd")
            .unwrap();
        assert_eq!(verdicts[kd].outcome, Outcome::Matched);
        let gone = all
            .iter()
            .position(|i| i.path == "/var/tmp/.upd.sh")
            .unwrap();
        assert_eq!(verdicts[gone].outcome, Outcome::NotChecked);
        assert_eq!(verdicts[gone].why, "no content kept");
        let by_type = counts(&all, &verdicts);
        assert_eq!(by_type[&Type::Endpoint].not_checked, 1);
        assert!(by_type[&Type::Endpoint].matched >= 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_known_false_positive_is_not_counted_as_matched_but_keeps_its_record() {
        let dir = installed("fp");
        let all = run();
        let scan = scan_datasets(&dir, &all, &AtomicBool::new(false)).unwrap();
        known_fp::add(
            &dir,
            Kind::IpPort,
            "203.0.113.123:123",
            None,
            "Public time servers.",
            5,
        )
        .unwrap();
        known_fp::add(
            &dir,
            Kind::Domain,
            "pool.ntp.example",
            Some("urlhaus"),
            "Time pool.",
            6,
        )
        .unwrap();
        // An entry for another dataset does not excuse this one.
        known_fp::add(
            &dir,
            Kind::Domain,
            "c2.update-cdn.example",
            Some("urlhaus"),
            "wrong dataset",
            7,
        )
        .unwrap();
        let fp = known_fp::load(&dir);
        let verdicts = evaluate_all(&all, &scan, &fp, &OnlineResults::default());
        let ntp = outcome(&all, &verdicts, "203.0.113.123:123");
        assert_eq!(ntp.outcome, Outcome::KnownFp);
        assert!(ntp.matches.is_empty());
        let (shown, entry) = ntp.excused.as_ref().unwrap();
        assert_eq!(entry.reason, "Public time servers.");
        assert_eq!(
            shown.record.record_id, "1411873",
            "the record it would have matched"
        );
        assert_eq!(
            outcome(&all, &verdicts, "pool.ntp.example").outcome,
            Outcome::KnownFp
        );
        assert_eq!(
            outcome(&all, &verdicts, "c2.update-cdn.example").outcome,
            Outcome::Matched
        );
        let by_type = counts(&all, &verdicts);
        assert_eq!(by_type[&Type::Endpoint].known_fp, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_run_endpoint_is_matched_by_each_ip_source_on_its_own() {
        let all = run();
        let all_feeds = [
            "threatfox",
            "urlhaus",
            "urlhaus-payloads",
            "feodo",
            "sslbl-ja3",
            "sslbl-cert",
        ];
        // (the only feed left on, the endpoint it must match)
        for (only, endpoint) in [
            ("feodo", "203.0.113.45:443"),
            ("threatfox", "203.0.113.45:443"),
            ("urlhaus", "198.51.100.77:80"),
        ] {
            let dir = installed("ip-source");
            for id in all_feeds.iter().filter(|id| **id != only) {
                feeds::set_enabled(&dir, id, false).unwrap();
            }
            let scan = scan_datasets(&dir, &all, &AtomicBool::new(false)).unwrap();
            assert_eq!(scan.loaded.len(), 1, "{only}");
            let verdicts = evaluate_all(&all, &scan, &[], &OnlineResults::default());
            let found = outcome(&all, &verdicts, endpoint);
            assert_eq!(found.outcome, Outcome::Matched, "{only}: {found:?}");
            assert_eq!(found.primary().unwrap().record.feed, only);
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn missing_or_partial_datasets_change_the_verdict_honestly() {
        let all = run();
        // Nothing downloaded: every row reads Not checked.
        let empty = data_dir("none");
        let scan = scan_datasets(&empty, &all, &AtomicBool::new(false)).unwrap();
        let verdicts = evaluate_all(&all, &scan, &[], &OnlineResults::default());
        assert!(
            verdicts
                .iter()
                .all(|v| v.outcome == Outcome::NotChecked && v.why == "no datasets downloaded")
        );
        // SSLBL and Feodo switched off: TLS rows are not checked, others use
        // fewer feeds.
        let dir = installed("partial");
        for id in ["feodo", "sslbl-ja3", "sslbl-cert"] {
            feeds::set_enabled(&dir, id, false).unwrap();
        }
        let scan = scan_datasets(&dir, &all, &AtomicBool::new(false)).unwrap();
        assert_eq!(scan.loaded.len(), 3);
        let verdicts = evaluate_all(&all, &scan, &[], &OnlineResults::default());
        let tls = all.iter().position(|i| i.ty == Type::Tls).unwrap();
        assert_eq!(
            (verdicts[tls].outcome, verdicts[tls].why.as_str()),
            (Outcome::NotChecked, "SSLBL not loaded")
        );
        let e = outcome(&all, &verdicts, "203.0.113.200:4444");
        assert_eq!(e.outcome, Outcome::NoMatch);
        assert!(
            e.partial() && e.feeds_used == 2 && e.feeds_needed == 3,
            "{e:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(empty);
    }

    #[test]
    fn an_old_dataset_date_is_what_the_verdict_carries() {
        let dir = installed("old");
        // Make the ThreatFox copy 41 days old.
        let feed = feeds::feed("threatfox").unwrap();
        let mut meta = feeds::status(&dir)[0].meta.clone().unwrap();
        meta.fetched_unix -= 41 * 86_400;
        let path = feeds::root(&dir)
            .join("feeds")
            .join(feed.id)
            .join("meta.json");
        std::fs::write(&path, serde_json::to_vec(&meta).unwrap()).unwrap();
        let all = run();
        let scan = scan_datasets(&dir, &all, &AtomicBool::new(false)).unwrap();
        let verdicts = evaluate_all(&all, &scan, &[], &OnlineResults::default());
        let miss = outcome(&all, &verdicts, "203.0.113.200:4444");
        assert_eq!(
            miss.date.as_deref(),
            Some(meta.date().as_str()),
            "the oldest feed that answered"
        );
        let hit = outcome(&all, &verdicts, "203.0.113.45:443");
        assert_eq!(
            hit.date.as_deref(),
            Some(meta.date().as_str()),
            "the date of the feed that matched"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_online_answer_counts_only_without_an_offline_match_and_is_marked_online() {
        let dir = installed("online");
        let all = run();
        let scan = scan_datasets(&dir, &all, &AtomicBool::new(false)).unwrap();
        let mut online = OnlineResults::default();
        online.insert(OnlineEntry {
            kind: Kind::IpPort,
            value: "203.0.113.200:4444".into(),
            at_unix: 1_000,
            records: vec![OnlineRecord {
                dataset: "threatfox".into(),
                record_id: "1844011".into(),
                family: "elf.gafgyt".into(),
                confidence: Some(50),
                first_seen: "2026-10-20".into(),
                detail: "ip:port · botnet_cc".into(),
                reference: "threatfox.abuse.ch/ioc/1844011/".into(),
            }],
        });
        // Also an online record for something the datasets already match.
        online.insert(OnlineEntry {
            kind: Kind::IpPort,
            value: "203.0.113.45:443".into(),
            at_unix: 1_000,
            records: vec![OnlineRecord {
                dataset: "threatfox".into(),
                record_id: "999".into(),
                ..Default::default()
            }],
        });
        let verdicts = evaluate_all(&all, &scan, &[], &online);
        let found = outcome(&all, &verdicts, "203.0.113.200:4444");
        assert_eq!(found.outcome, Outcome::Matched);
        assert_eq!(found.primary().unwrap().online_at, Some(1_000));
        let offline = outcome(&all, &verdicts, "203.0.113.45:443");
        assert!(offline.matches.iter().all(|m| m.online_at.is_none()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
