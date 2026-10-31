// SPDX-License-Identifier: GPL-3.0-only
//! The IOC list of a run, built inside the archive scan: what the capture
//! showed (from TShark, collected while the capture was indexed), what the
//! recorded calls did, the sample and the files it left; then matched against
//! the stored abuse.ch datasets, and the matches listed with the detections.
use super::*;
use super::{files::IocFile, rules::ioc as log};
use antinomie_monitor_core::{
    ioc::{
        feeds,
        indicator::{
            Collector, Evidence, Hashes, Indicator, Jump, Process, Seen, Source, Type, Via,
        },
        strings::{self, Found},
        verdict::{self, OnlineResults, Outcome, Scan, Verdict},
    },
    known_fp,
};

/// Strings of the sample read for network values.
const STRING_LIMIT: usize = 50_000;
/// Values taken from them.
const FOUND_LIMIT: usize = 2_000;

/// Whether the run's capture was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Capture {
    Read,
    /// No packet capture was recorded for this run.
    Off,
    Failed(String),
}

/// The indicators of a run with the datasets' answer.
pub(super) struct IocScan {
    pub indicators: Vec<Indicator>,
    pub scan: Arc<Scan>,
    /// Observations dropped past the limits.
    pub omitted: u64,
    pub capture: Capture,
    /// The run's capture, for the "where it came from" lines.
    pub frames: Option<u64>,
    /// What the next scan can reuse while the indicators and datasets stay.
    pub cache: Cache,
    /// What hashing the files from a saved disk dump did, in words.
    pub disk_notes: Vec<String>,
}

/// The answer kept between scans while nothing it depends on changes.
#[derive(Clone)]
pub(super) struct Cache {
    key: String,
    scan: Arc<Scan>,
    disk: Option<DiskCache>,
}

/// Hashes taken from a disk dump, kept while the dump and the files stay.
#[derive(Clone)]
pub(super) struct DiskCache {
    key: String,
    hashes: Arc<std::collections::BTreeMap<String, Hashes>>,
    notes: Vec<String>,
}

/// Everything the scan has gathered for the IOC list.
pub(super) struct Gathered<'a> {
    pub collector: Collector,
    pub log: log::Log,
    pub files: Vec<IocFile>,
    pub report: Option<&'a antinomie_monitor_core::AnalysisReport>,
    pub clock: Option<antinomie_monitor_core::HostClockAnchor>,
    pub capture: Capture,
    pub frames: Option<u64>,
    /// SHA-256 and MD5 of files, from a saved disk dump of the machine.
    pub disk: std::collections::BTreeMap<String, Hashes>,
}

/// A line that says which datasets were read: feed ids with fetch time and switch.
pub(super) fn signature(data_dir: &std::path::Path) -> String {
    feeds::status(data_dir)
        .iter()
        .map(|status| {
            format!(
                "{}:{}:{}",
                status.feed.id,
                status.meta.as_ref().map_or(0, |meta| meta.fetched_unix),
                u8::from(status.enabled)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn host_us(clock: Option<antinomie_monitor_core::HostClockAnchor>, ns: u64) -> Option<u64> {
    clock.and_then(|clock| clock.host_us(ns))
}

fn guest_ns(clock: Option<antinomie_monitor_core::HostClockAnchor>, us: u64) -> u64 {
    clock
        .and_then(|clock| {
            let delta = (i128::from(us) - i128::from(clock.host_us)) * 1000;
            u64::try_from(i128::from(clock.guest_ns) + delta).ok()
        })
        .unwrap_or(0)
}

fn process(who: &log::Who) -> Process {
    Process {
        pid: who.pid,
        cookie: who.cookie,
        name: who
            .image
            .as_deref()
            .and_then(|image| image.rsplit('/').find(|part| !part.is_empty()))
            .unwrap_or("unknown")
            .to_owned(),
    }
}

fn call_evidence(who: &log::Who, what: &str) -> Evidence {
    Evidence {
        source: Source::Syscall,
        label: format!("Syscall Trace · {what} #{}", who.call_id),
        jump: Jump::Call {
            stream: who.stream,
            cookie: who.cookie,
            call: who.call_id,
        },
    }
}

fn hashes(sha256: &str) -> Hashes {
    Hashes {
        sha256: sha256.to_owned(),
        ..Hashes::default()
    }
}

/// The sample's digests as static analysis stored them.
fn sample_hashes(report: &antinomie_monitor_core::AnalysisReport) -> Option<Hashes> {
    use antinomie_monitor_core::AnalysisKind;
    let sha256 = report.specimen_sha256.clone()?;
    let entry = |label: &str| {
        report
            .sections
            .iter()
            .find(|section| section.kind == AnalysisKind::Metadata)
            .and_then(|section| section.entries.iter().find(|entry| entry.label == label))
            .map(|entry| entry.value.clone())
            .unwrap_or_default()
    };
    Some(Hashes {
        sha256,
        md5: entry("MD5"),
        sha1: entry("SHA-1"),
    })
}

fn sample_strings(report: &antinomie_monitor_core::AnalysisReport) -> String {
    use antinomie_monitor_core::AnalysisKind;
    let mut text = String::new();
    for entry in report
        .sections
        .iter()
        .filter(|section| section.kind == AnalysisKind::Strings)
        .flat_map(|section| section.entries.iter())
        .take(STRING_LIMIT)
    {
        text.push_str(&entry.value);
        text.push('\n');
    }
    text
}

fn feed(gathered: &mut Gathered<'_>) {
    let clock = gathered.clock;
    for call in &gathered.log.connections {
        let seen = Seen {
            time_us: host_us(clock, call.who.time_ns),
            evidence: Some(call_evidence(&call.who, call.name)),
            ok: Some(call.ok),
            process: Some(process(&call.who)),
            note: None,
        };
        gathered.collector.endpoint(
            call.ip,
            call.port,
            if call.udp { "udp" } else { "tcp" },
            Source::Syscall,
            seen,
        );
    }
    for run in &gathered.log.executed {
        let seen = Seen {
            time_us: host_us(clock, run.who.time_ns),
            evidence: Some(call_evidence(&run.who, "execve")),
            ok: Some(true),
            process: Some(process(&run.who)),
            note: run.why.as_ref().map(|why| format!("no hash: {why}")),
        };
        gathered.collector.file(
            &run.path,
            "executed",
            run.sha256.as_deref().map(hashes),
            Source::Syscall,
            seen,
        );
    }
    for file in &gathered.files {
        for role in &file.roles {
            let who = log::Who {
                cookie: file.cookie,
                pid: file.pid,
                image: file.image.clone(),
                time_ns: file.time_ns,
                stream: file.stream,
                call_id: file.call_id,
            };
            let on_disk = gathered.disk.get(&file.path).cloned();
            let (hash, from_disk) = match (&file.sha256, on_disk) {
                // The guest and the dump agree: both digests, both sources.
                (Some(sha), Some(disk)) if disk.sha256 == *sha => (Some(disk.clone()), Some(disk)),
                (Some(sha), disk) => (Some(hashes(sha)), disk),
                (None, Some(disk)) => (Some(disk.clone()), Some(disk)),
                (None, None) => (None, None),
            };
            let seen = Seen {
                time_us: host_us(clock, file.time_ns),
                evidence: Some(call_evidence(&who, "file call")),
                ok: Some(true),
                process: Some(process(&who)),
                note: file
                    .why
                    .as_ref()
                    .filter(|_| hash.is_none())
                    .map(|why| format!("no hash: {why}")),
            };
            gathered
                .collector
                .file(&file.path, role, hash, Source::Syscall, seen);
            if let Some(disk) = from_disk {
                gathered.collector.file(
                    &file.path,
                    role,
                    Some(disk),
                    Source::Disk,
                    Seen::default(),
                );
            }
        }
    }
    if let Some(report) = gathered.report {
        if let Some(sample) = sample_hashes(report) {
            let path = if report.source_path.is_empty() {
                "(sample)"
            } else {
                report.source_path.as_str()
            };
            gathered.collector.file(
                path,
                "sample",
                Some(sample),
                Source::Static,
                Seen::default(),
            );
        }
        let text = sample_strings(report);
        let sighting = || Seen {
            evidence: Some(Evidence {
                source: Source::Static,
                label: "Properties › Strings".into(),
                jump: Jump::Text,
            }),
            ..Seen::default()
        };
        for found in strings::scan(&text, FOUND_LIMIT) {
            match found {
                Found::Endpoint(ip, port) => {
                    gathered
                        .collector
                        .endpoint(ip, port, "tcp", Source::Static, sighting());
                }
                Found::Domain(name) => {
                    gathered
                        .collector
                        .domain(&name, Via::Sample, &[], Source::Static, sighting());
                }
                Found::Url(url) => {
                    if let Some(parts) = antinomie_monitor_core::ioc::kind::url_parts(&url) {
                        if parts.address().is_none() {
                            gathered.collector.domain(
                                &parts.host,
                                Via::Sample,
                                &[],
                                Source::Static,
                                sighting(),
                            );
                        } else if let Some(ip) = parts.address() {
                            gathered.collector.endpoint(
                                ip,
                                parts.effective_port(),
                                "tcp",
                                Source::Static,
                                sighting(),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn cache_key(indicators: &[Indicator], signature: &str) -> String {
    let mut lookups: Vec<String> = indicators
        .iter()
        .flat_map(|indicator| &indicator.lookups)
        .map(|lookup| format!("{}={}", lookup.kind.id(), lookup.value))
        .collect();
    lookups.sort_unstable();
    lookups.dedup();
    let mut text = String::new();
    for lookup in &lookups {
        text.push_str(lookup);
        text.push('\n');
    }
    text.push_str(signature);
    antinomie_monitor_core::storage::sha256_hex(text.as_bytes())
}

/// Finish the indicators and match them. The datasets are read only when the
/// values to look for or the datasets themselves changed since `cache`.
pub(super) fn build(
    mut gathered: Gathered<'_>,
    data_dir: Option<&std::path::Path>,
    run_dir: &std::path::Path,
    cache: Option<&Cache>,
    cancel: &AtomicBool,
) -> Result<IocScan, String> {
    let disk = disk_hashes(
        run_dir,
        &gathered.files,
        cache.and_then(|cache| cache.disk.as_ref()),
        cancel,
    )?;
    if let Some(disk) = &disk {
        gathered.disk = (*disk.hashes).clone();
    }
    let disk_notes = disk
        .as_ref()
        .map(|disk| disk.notes.clone())
        .unwrap_or_default();
    feed(&mut gathered);
    let omitted = gathered.collector.omitted + gathered.log.omitted;
    let capture = gathered.capture;
    let frames = gathered.frames;
    let indicators = gathered.collector.finish();
    let signature = data_dir.map(signature).unwrap_or_default();
    let key = cache_key(&indicators, &signature);
    let scan = match cache.filter(|cache| cache.key == key) {
        Some(cache) => cache.scan.clone(),
        None => Arc::new(match data_dir {
            Some(dir) => verdict::scan_datasets(dir, &indicators, cancel)?,
            None => Scan::default(),
        }),
    };
    Ok(IocScan {
        indicators,
        scan: scan.clone(),
        omitted,
        capture,
        frames,
        cache: Cache { key, scan, disk },
        disk_notes,
    })
}

/// SHA-256 and MD5 of the files the run created or changed, read from the
/// newest saved disk dump of the run's recording, when there is one. The
/// answer is kept while the dump and the file list stay the same.
fn disk_hashes(
    run_dir: &std::path::Path,
    files: &[IocFile],
    previous: Option<&DiskCache>,
    cancel: &AtomicBool,
) -> Result<Option<DiskCache>, String> {
    use antinomie_monitor_core::ioc::disk;
    let Some(dump) = disk::newest_dump(run_dir) else {
        return Ok(None);
    };
    let mut paths: Vec<String> = files
        .iter()
        .filter(|file| {
            !file.roles.contains(&"deleted")
                && file
                    .roles
                    .iter()
                    .any(|role| matches!(*role, "created" | "changed" | "written at close"))
        })
        .map(|file| file.path.clone())
        .collect();
    paths.sort();
    paths.dedup();
    let key = antinomie_monitor_core::storage::sha256_hex(
        format!("{}|{}", dump.id, paths.join("\n")).as_bytes(),
    );
    if let Some(previous) = previous.filter(|previous| previous.key == key) {
        return Ok(Some(previous.clone()));
    }
    if paths.is_empty() {
        return Ok(None);
    }
    let label = if dump.vm_name.is_empty() {
        dump.id.clone()
    } else {
        format!("{} ({})", dump.id, dump.vm_name)
    };
    let work = |out: &std::path::Path| -> Result<disk::Hashed, String> {
        let mut hasher = disk::ImageHasher::open(&dump.path(), out)?;
        disk::hash_paths(&mut hasher, &paths, cancel)
    };
    let outcome = disk::scratch(run_dir).and_then(|out| {
        let outcome = work(&out);
        let _ = std::fs::remove_dir_all(&out);
        outcome
    });
    let (hashes, notes) = match outcome {
        Ok(done) => {
            let mut notes = vec![format!(
                "{} of {} files hashed from the disk dump {label}",
                done.hashes.len(),
                paths.len()
            )];
            if !done.skipped.is_empty() {
                notes.push(format!(
                    "{} not hashed: no content kept or over the size limit",
                    done.skipped.len()
                ));
            }
            if done.left_out > 0 {
                notes.push(format!(
                    "{} more files were left out (at most {} are hashed)",
                    done.left_out,
                    disk::FILE_LIMIT
                ));
            }
            (done.hashes, notes)
        }
        Err(error) if error == "cancelled" => return Err(error),
        Err(error) => (
            std::collections::BTreeMap::new(),
            vec![format!("The disk dump {label} could not be read: {error}")],
        ),
    };
    Ok(Some(DiskCache {
        key,
        hashes: Arc::new(hashes),
        notes,
    }))
}

/// The verdicts under the person's false-positive list and the online answers
/// kept with the run.
pub(super) fn verdicts(
    ioc: &IocScan,
    fp: &[known_fp::Entry],
    online: &OnlineResults,
) -> Vec<Verdict> {
    verdict::evaluate_all(&ioc.indicators, &ioc.scan, fp, online)
}

/// The tier a match is listed at: a confident or unrated match is HIGH.
fn tier_of(confidence: Option<u8>) -> rules::Tier {
    match confidence {
        None => rules::Tier::High,
        Some(confidence) if confidence >= 75 => rules::Tier::High,
        Some(confidence) if confidence >= 50 => rules::Tier::Medium,
        Some(_) => rules::Tier::Low,
    }
}

/// List every match as a finding, so it shows with the detections.
pub(super) fn list_findings(
    engine: &mut rules::Engine,
    ioc: &IocScan,
    verdicts: &[Verdict],
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) {
    for (indicator, verdict) in ioc.indicators.iter().zip(verdicts) {
        if verdict.outcome != Outcome::Matched {
            continue;
        }
        let Some(found) = verdict.primary() else {
            continue;
        };
        let record = &found.record;
        let name = match indicator.ty {
            Type::File => format!("{} ({})", indicator.value, indicator.path),
            _ => indicator.value.clone(),
        };
        let family = if record.family.is_empty() {
            String::new()
        } else {
            format!(": {}", record.family)
        };
        let summary = format!(
            "{} {name} is listed by {}{family}{}",
            indicator.ty.label().trim_end_matches('s').to_lowercase(),
            dataset_name(&record.feed),
            record
                .confidence
                .map_or(String::new(), |confidence| format!(
                    " ({confidence}% confidence)"
                )),
        );
        let mut detail = vec![
            format!(
                "Dataset: {} · record {}",
                dataset_name(&record.feed),
                record.record_id
            ),
            format!("Record: {}", record.detail),
            format!("Reported: {}", record.first_seen),
            format!("Reference: {}", record.reference),
        ];
        detail.push(match found.online_at {
            Some(_) => "Found by the online check, not in the local datasets.".to_owned(),
            None => format!(
                "Offline match against the dataset dated {}.",
                verdict.date.clone().unwrap_or_default()
            ),
        });
        let evidence = indicator
            .evidence
            .iter()
            .find_map(|evidence| match &evidence.jump {
                Jump::Packet { capture, frame } => Some(log::Evidence::Packet {
                    capture: capture.clone(),
                    frame: *frame,
                }),
                Jump::Call { stream, call, .. } => Some(log::Evidence::Call {
                    stream: *stream,
                    call_id: *call,
                }),
                Jump::Text => None,
            });
        let Some(evidence) = evidence else {
            continue;
        };
        engine.ioc_match(log::IocHit {
            object: format!("{} {}", indicator.ty.id(), indicator.key),
            summary,
            detail,
            tier: tier_of(record.confidence),
            evidence,
            time_ns: indicator.first_us.map_or(0, |us| guest_ns(clock, us)),
            who: indicator.process.as_ref().map(|process| log::Who {
                cookie: process.cookie,
                pid: process.pid,
                image: Some(process.name.clone()),
                ..log::Who::default()
            }),
        });
    }
}

fn verdict_cell(verdict: &Verdict) -> Cell {
    let online = verdict
        .primary()
        .is_some_and(|found| found.online_at.is_some());
    let (text, color) = match verdict.outcome {
        Outcome::Matched => (
            if online {
                "Matched · online"
            } else {
                "Matched"
            },
            theme::error(),
        ),
        Outcome::KnownFp => ("Known FP", theme::blue()),
        Outcome::NoMatch => ("No match", theme::text()),
        Outcome::NotChecked => ("Not checked", theme::muted()),
    };
    table::cell(text, color, false)
}

/// The destination address of a row's `src:port → dst:port` endpoints.
fn destination_of(endpoints: &str) -> Option<String> {
    let (_, destination) = endpoints.split_once(" → ")?;
    let (ip, _) = destination.rsplit_once(':')?;
    Some(ip.trim_matches(['[', ']']).to_owned())
}

fn text_of<'a>(values: &'a [(&'static str, RowValue)], name: &str) -> &'a str {
    values
        .iter()
        .find_map(|(key, value)| match (*key, value) {
            (key, RowValue::Text(text)) if key == name => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("")
}

/// Add the IOC column to the rebuilt Network tabs, and build the URLs tab
/// from the HTTP rows.
pub(super) fn annotate(
    tabs: &mut NewTabs,
    http: &[Vec<Cell>],
    ioc: &IocScan,
    verdicts: &[Verdict],
) {
    use antinomie_monitor_core::ioc::indicator::{domain_key, endpoint_key, tls_key, url_key};
    let index: std::collections::HashMap<(Type, &str), usize> = ioc
        .indicators
        .iter()
        .enumerate()
        .map(|(at, indicator)| ((indicator.ty, indicator.key.as_str()), at))
        .collect();
    // The verdict goes in the column after the name, so it is on screen without
    // scrolling; the HTTP rows keep their 0.7.0 columns and end with it.
    let mark = |row: &mut Vec<Cell>, found: Option<usize>, column: usize| {
        let cell = found.map_or_else(
            || table::cell("—", theme::muted(), false),
            |at| verdict_cell(&verdicts[at]),
        );
        row.insert(column.min(row.len()), cell);
        if let (Some(at), Some(first)) = (found, row.first_mut()) {
            first
                .values
                .push(("ioc.id", RowValue::Text(ioc.indicators[at].id())));
        }
    };
    for row in &mut tabs.endpoints {
        let values = row
            .first()
            .map(|cell| cell.values.clone())
            .unwrap_or_default();
        let found = text_of(&values, "network.ip")
            .parse::<std::net::IpAddr>()
            .ok()
            .zip(
                match values.iter().find(|(key, _)| *key == "network.port") {
                    Some((_, RowValue::Number(port))) => u16::try_from(*port).ok(),
                    _ => None,
                },
            )
            .and_then(|(ip, port)| {
                index
                    .get(&(Type::Endpoint, endpoint_key(ip, port).as_str()))
                    .copied()
            });
        mark(row, found, 1);
    }
    for row in &mut tabs.domains {
        let name = domain_key(text_of(
            row.first()
                .map(|cell| cell.values.as_slice())
                .unwrap_or_default(),
            "network.hostname",
        ));
        let found = index.get(&(Type::Domain, name.as_str())).copied();
        mark(row, found, 1);
    }
    for row in &mut tabs.tls {
        let values = row
            .first()
            .map(|cell| cell.values.clone())
            .unwrap_or_default();
        let key = tls_key(
            text_of(&values, "tls.sni"),
            text_of(&values, "tls.endpoint"),
            text_of(&values, "tls.ja3"),
        );
        let found = index.get(&(Type::Tls, key.as_str())).copied();
        mark(row, found, 2);
    }
    // Frame, Time, Endpoint, IOC, then the 0.7.0 columns without the response frame
    // and with the version before the response.
    tabs.urls = http
        .iter()
        .map(|source| {
            let values = source
                .first()
                .map(|cell| cell.values.clone())
                .unwrap_or_default();
            let host = text_of(&values, "http.host");
            let host = if host.is_empty() {
                destination_of(text_of(&values, "network.endpoints")).unwrap_or_default()
            } else {
                host.to_owned()
            };
            let key = url_key(
                text_of(&values, "http.method"),
                &host,
                text_of(&values, "http.uri"),
            );
            let found = index.get(&(Type::Url, key.as_str())).copied();
            let mut row: Vec<Cell> = source.iter().take(7).cloned().collect();
            row.insert(
                6,
                table::cell(text_of(&values, "http.version"), theme::text(), false),
            );
            mark(&mut row, found, 3);
            row
        })
        .collect();
}

/// A feed's name for people.
pub(super) fn dataset_name(id: &str) -> &str {
    feeds::feed(id).map_or(id, |feed| feed.name)
}

/// The online answers and false positives to read for a run.
pub(super) fn run_inputs(
    data_dir: Option<&std::path::Path>,
    run_dir: &std::path::Path,
) -> (Vec<known_fp::Entry>, OnlineResults) {
    (
        data_dir.map(known_fp::load).unwrap_or_default(),
        antinomie_monitor_core::ioc::online::load(run_dir),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{
        ioc::indicator::{Collector, Type},
        AnalysisEntry, AnalysisKind, AnalysisReport, AnalysisSection, AnalysisState,
    };

    fn who(pid: u32, image: &str, call: u64) -> log::Who {
        log::Who {
            cookie: u64::from(pid),
            pid,
            image: Some(image.into()),
            time_ns: call * 1_000,
            stream: 1,
            call_id: call,
        }
    }

    fn connection(pid: u32, ip: &str, port: u16, ok: bool, call: u64) -> log::Connection {
        log::Connection {
            ip: ip.parse().unwrap(),
            port,
            udp: false,
            ok,
            who: who(pid, "/usr/bin/kworkerd", call),
            name: "connect",
        }
    }

    fn report() -> AnalysisReport {
        let mut metadata = AnalysisSection::new(AnalysisKind::Metadata);
        for (label, value) in [
            ("MD5", "5e8ff9bf55ba3508199d22e984129be6"),
            ("SHA-1", "8151325dcdbae9e0ff95f9f9658432dbedfdb209"),
        ] {
            metadata.entries.push(AnalysisEntry {
                label: label.into(),
                value: value.into(),
                offset: None,
                record: None,
            });
        }
        let mut found = AnalysisSection::new(AnalysisKind::Strings);
        for text in [
            "connect to 203.0.113.200:4444",
            "c2.update-cdn.example",
            "libc.so.6",
        ] {
            found.entries.push(AnalysisEntry {
                label: "ascii".into(),
                value: text.into(),
                offset: Some(0x4a2f10),
                record: None,
            });
        }
        AnalysisReport {
            id: "r".into(),
            state: AnalysisState::Complete,
            source_path: "/home/user/kworkerd".into(),
            specimen_sha256: Some(
                "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf".into(),
            ),
            specimen_len: Some(10),
            reason: None,
            sections: vec![metadata, found],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
            limits: None,
        }
    }

    fn file(path: &str, roles: &[&'static str], sha256: Option<&str>) -> IocFile {
        IocFile {
            path: path.into(),
            roles: roles.to_vec(),
            sha256: sha256.map(str::to_owned),
            why: sha256
                .is_none()
                .then(|| "file is 300 MiB, over the 256 MiB limit".into()),
            pid: 1420,
            image: Some("/tmp/.kd".into()),
            stream: 1,
            cookie: 1420,
            call_id: 77,
            time_ns: 5_000,
        }
    }

    fn gathered<'a>(
        log: log::Log,
        files: Vec<IocFile>,
        report: Option<&'a AnalysisReport>,
        disk: std::collections::BTreeMap<String, Hashes>,
    ) -> Gathered<'a> {
        Gathered {
            collector: Collector::default(),
            log,
            files,
            report,
            clock: None,
            capture: Capture::Off,
            frames: None,
            disk,
        }
    }

    const SHA: &str = "f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa";

    #[test]
    fn calls_the_sample_strings_and_files_become_indicators() {
        let report = report();
        let run = std::env::temp_dir().join(format!("ant-ioc-scan-{}", std::process::id()));
        std::fs::create_dir_all(&run).unwrap();
        let log = log::Log {
            connections: vec![
                connection(1412, "203.0.113.45", 443, true, 3),
                connection(1412, "203.0.113.45", 443, false, 4),
                // Two processes reached this one.
                connection(1412, "198.51.100.77", 80, true, 5),
                connection(1420, "198.51.100.77", 80, true, 6),
            ],
            executed: vec![log::Executed {
                path: "/tmp/.kd".into(),
                sha256: Some(SHA.into()),
                why: None,
                who: who(1420, "/tmp/.kd", 9),
            }],
            omitted: 0,
        };
        let disk = std::collections::BTreeMap::from([(
            "/etc/cron.d/kd-update".to_owned(),
            Hashes {
                sha256: "c374eea599bb3c50ed4432ef57aee1263cdc3c83d1c1a3c4d7e19eef1af8439b".into(),
                md5: "9d3bb895f22bf0afa958d68c2a58ded7".into(),
                sha1: String::new(),
            },
        )]);
        let files = vec![
            file("/etc/cron.d/kd-update", &["changed"], None),
            file("/tmp/big", &["created"], None),
            file("/var/tmp/.upd.sh", &["deleted"], None),
        ];
        let ioc = build(
            gathered(log, files, Some(&report), disk),
            None,
            &run,
            None,
            &AtomicBool::new(false),
        )
        .unwrap();
        let find = |ty: Type, key: &str| -> &Indicator {
            ioc.indicators
                .iter()
                .find(|i| i.ty == ty && i.key.contains(key))
                .unwrap_or_else(|| panic!("no {ty:?} {key}"))
        };
        // One process, and its failed attempt is counted and said.
        let first = find(Type::Endpoint, "203.0.113.45:443");
        assert_eq!(first.process.as_ref().map(|p| p.pid), Some(1412));
        assert!(
            first.details[0].1.contains("1 succeeded, 1 failed"),
            "{:?}",
            first.details
        );
        // Two processes: none is named.
        let shared = find(Type::Endpoint, "198.51.100.77:80");
        assert!(shared.process.is_none());
        assert_eq!(shared.candidates.len(), 2);
        // The sample's strings: an address never contacted and a name, not the library.
        let never = find(Type::Endpoint, "203.0.113.200:4444");
        assert!(never.sources.contains(&Source::Static) && never.sources.len() == 1);
        assert!(never.process.is_none());
        find(Type::Domain, "c2.update-cdn.example");
        assert!(!ioc.indicators.iter().any(|i| i.key.contains("libc.so")));
        // Files: the sample with all three digests, the executed program by SHA-256.
        let sample = find(Type::File, "af2bdbe1");
        assert_eq!(sample.roles, ["sample"]);
        assert_eq!(
            sample.hashes.as_ref().unwrap().md5,
            "5e8ff9bf55ba3508199d22e984129be6"
        );
        let run_file = find(Type::File, SHA);
        assert_eq!(run_file.path, "/tmp/.kd");
        assert_eq!(run_file.process.as_ref().map(|p| p.pid), Some(1420));
        assert!(run_file.lookups.iter().any(|l| l.value == SHA));
        // Hashed from the dump: both digests, two sources.
        let cron = find(Type::File, "c374eea5");
        assert_eq!(
            cron.hashes.as_ref().unwrap().md5,
            "9d3bb895f22bf0afa958d68c2a58ded7"
        );
        assert!(cron.sources.contains(&Source::Disk) && cron.sources.contains(&Source::Syscall));
        // No content kept: listed, not checked, with the reason.
        let big = find(Type::File, "- /tmp/big");
        assert_eq!(big.not_checked.as_deref(), Some("no content kept"));
        assert!(big
            .details
            .iter()
            .any(|(_, line)| line.contains("over the 256 MiB limit")));
        assert_eq!(find(Type::File, "- /var/tmp/.upd.sh").roles, ["deleted"]);
        assert_eq!(ioc.capture, Capture::Off);
        let _ = std::fs::remove_dir_all(run);
    }

    #[test]
    fn the_datasets_are_read_once_while_nothing_changes() {
        let data = std::env::temp_dir().join(format!("ant-ioc-scan-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let feed = feeds::feed("feodo").unwrap();
        let dir = data.join("ioc").join("feeds").join(feed.id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("data-1-a.txt"),
            r#"[{"ip_address":"203.0.113.45","port":443,"status":"online","first_seen":"2026-08-19 10:00:00","malware":"Dridex"}]"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("meta.json"),
            serde_json::json!({"schema":1,"id":feed.id,"file":"data-1-a.txt","fetched_unix":1_000,
                "records":1,"size":60,"sha256":"ab".repeat(32),"url":feed.url})
            .to_string(),
        )
        .unwrap();
        let run = data.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let log = || log::Log {
            connections: vec![connection(1412, "203.0.113.45", 443, true, 3)],
            ..log::Log::default()
        };
        let cancel = AtomicBool::new(false);
        let first = build(
            gathered(log(), Vec::new(), None, Default::default()),
            Some(&data),
            &run,
            None,
            &cancel,
        )
        .unwrap();
        let verdicts = verdicts(&first, &[], &OnlineResults::default());
        assert_eq!(verdicts[0].outcome, Outcome::Matched);
        assert_eq!(verdicts[0].date.as_deref(), Some("1970-01-01"));
        // The same values and datasets: the answer is reused, not read again.
        let again = build(
            gathered(log(), Vec::new(), None, Default::default()),
            Some(&data),
            &run,
            Some(&first.cache),
            &cancel,
        )
        .unwrap();
        assert!(Arc::ptr_eq(&first.scan, &again.scan));
        // A different set of values is a different question.
        let more = log::Log {
            connections: vec![connection(1412, "203.0.113.46", 443, true, 3)],
            ..log::Log::default()
        };
        let other = build(
            gathered(more, Vec::new(), None, Default::default()),
            Some(&data),
            &run,
            Some(&first.cache),
            &cancel,
        )
        .unwrap();
        assert!(!Arc::ptr_eq(&first.scan, &other.scan));
        // A dataset switched off changes the key too.
        feeds::set_enabled(&data, "feodo", false).unwrap();
        let off = build(
            gathered(log(), Vec::new(), None, Default::default()),
            Some(&data),
            &run,
            Some(&first.cache),
            &cancel,
        )
        .unwrap();
        assert!(!Arc::ptr_eq(&first.scan, &off.scan));
        assert!(off.scan.loaded.is_empty());
        let _ = std::fs::remove_dir_all(data);
    }

    #[test]
    fn a_match_is_listed_at_a_tier_that_follows_its_confidence() {
        assert_eq!(tier_of(None), rules::Tier::High);
        assert_eq!(tier_of(Some(100)), rules::Tier::High);
        assert_eq!(tier_of(Some(75)), rules::Tier::High);
        assert_eq!(tier_of(Some(74)), rules::Tier::Medium);
        assert_eq!(tier_of(Some(50)), rules::Tier::Medium);
        assert_eq!(tier_of(Some(49)), rules::Tier::Low);
    }

    #[test]
    fn the_datasets_signature_follows_fetch_time_and_the_switch() {
        let data = std::env::temp_dir().join(format!("ant-ioc-scan-sig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).unwrap();
        let none = signature(&data);
        assert!(none.contains("threatfox:0:1"), "{none}");
        feeds::set_enabled(&data, "threatfox", false).unwrap();
        assert!(signature(&data).contains("threatfox:0:0"));
        let _ = std::fs::remove_dir_all(data);
    }
}
