// SPDX-License-Identifier: GPL-3.0-only
//! Reading the stored feeds: one parser per feed format, streaming, so a
//! 300 MB file is never held in memory. A line is first reduced to the values
//! it could be matched by; the rest of the record is built only for a line
//! that someone asked about.
use super::{
    feeds::{Feed, Format},
    kind::{self, Kind},
};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

/// Longest line read; a longer one is skipped.
const MAX_LINE_LEN: u64 = 1024 * 1024;
/// Most records kept for one value.
pub const HITS_PER_KEY: usize = 6;

/// One dataset record, as a verdict shows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// The feed's id.
    pub feed: String,
    /// The record's id in the dataset.
    pub record_id: String,
    pub family: String,
    /// 0 to 100 when the feed gives one.
    pub confidence: Option<u8>,
    /// `YYYY-MM-DD`.
    pub first_seen: String,
    /// What kind of record it is, in words.
    pub detail: String,
    /// Where abuse.ch shows it.
    pub reference: String,
}

/// The values to look for, by kind. Values are in normal form.
#[derive(Clone, Debug, Default)]
pub struct Wanted {
    sets: HashMap<Kind, HashSet<String>>,
}

impl Wanted {
    pub fn add(&mut self, kind: Kind, value: String) {
        self.sets.entry(kind).or_default().insert(value);
    }

    pub fn contains(&self, kind: Kind, value: &str) -> bool {
        self.sets.get(&kind).is_some_and(|set| set.contains(value))
    }

    pub fn is_empty(&self) -> bool {
        self.sets.values().all(HashSet::is_empty)
    }

    pub fn len(&self) -> usize {
        self.sets.values().map(HashSet::len).sum()
    }
}

/// A record that answers a wanted value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub kind: Kind,
    pub value: String,
    pub record: Record,
}

/// What a pass over one feed found.
#[derive(Debug, Default)]
pub struct Scanned {
    /// Lines that were records.
    pub records: u64,
    /// Lines that were neither records nor comments.
    pub skipped: u64,
}

/// Split one CSV line. Fields may be quoted (`"a, b"`), separated by a comma
/// and optional spaces; a doubled quote inside a quoted field is kept as two.
pub fn split_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let bytes = line.as_bytes();
    let mut at = 0;
    loop {
        while at < bytes.len() && bytes[at] == b' ' {
            at += 1;
        }
        if at < bytes.len() && bytes[at] == b'"' {
            let start = at + 1;
            let mut end = start;
            loop {
                match bytes[end..].iter().position(|&b| b == b'"') {
                    None => {
                        end = bytes.len();
                        break;
                    }
                    Some(offset) => {
                        end += offset;
                        if bytes.get(end + 1) == Some(&b'"') {
                            end += 2;
                        } else {
                            break;
                        }
                    }
                }
            }
            fields.push(&line[start..end]);
            at = (end + 1).min(bytes.len());
            while at < bytes.len() && bytes[at] != b',' {
                at += 1;
            }
        } else {
            let end = bytes[at..]
                .iter()
                .position(|&b| b == b',')
                .map_or(bytes.len(), |offset| at + offset);
            fields.push(line[at..end].trim_end());
            at = end;
        }
        if at >= bytes.len() {
            break;
        }
        at += 1;
    }
    fields
}

fn squash(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Column positions found by name.
struct Columns(Vec<String>);

impl Columns {
    fn new(names: &[&str]) -> Self {
        Self(names.iter().map(|name| squash(name)).collect())
    }

    fn at(&self, aliases: &[&str]) -> Option<usize> {
        aliases
            .iter()
            .find_map(|alias| self.0.iter().position(|name| name == alias))
    }
}

/// A feed's columns, by what each means.
#[derive(Clone, Debug)]
enum Layout {
    ThreatFox {
        first: usize,
        id: usize,
        value: usize,
        kind: usize,
        threat: usize,
        malware: usize,
        printable: usize,
        confidence: usize,
    },
    Urlhaus {
        id: usize,
        added: usize,
        url: usize,
        threat: usize,
        tags: usize,
    },
    Payloads {
        first: usize,
        url: Option<usize>,
        sha256: Option<usize>,
        md5: Option<usize>,
        signature: Option<usize>,
        filetype: Option<usize>,
    },
    SslIp {
        first: usize,
        ip: usize,
        port: usize,
        reason: Option<usize>,
    },
    SslJa3 {
        md5: usize,
        first: usize,
        reason: usize,
    },
    SslCert {
        date: usize,
        sha1: usize,
        reason: usize,
    },
}

impl Layout {
    fn defaults(feed: &Feed) -> Option<Self> {
        let names: &[&str] = match feed.id {
            "threatfox" => &[
                "first_seen_utc",
                "ioc_id",
                "ioc_value",
                "ioc_type",
                "threat_type",
                "fk_malware",
                "malware_alias",
                "malware_printable",
                "last_seen_utc",
                "confidence_level",
            ],
            "urlhaus" | "urlhaus-recent" => &[
                "id",
                "dateadded",
                "url",
                "url_status",
                "last_online",
                "threat",
                "tags",
            ],
            "urlhaus-payloads" => &["firstseen", "url", "filetype", "md5", "sha256", "signature"],
            "sslbl-ip" => &["firstseen", "dstip", "dstport"],
            "sslbl-ja3" => &["ja3_md5", "firstseen", "lastseen", "listingreason"],
            "sslbl-cert" => &["listingdate", "sha1", "listingreason"],
            _ => return None,
        };
        Self::from_names(feed, names)
    }

    fn from_names(feed: &Feed, names: &[&str]) -> Option<Self> {
        let columns = Columns::new(names);
        Some(match feed.id {
            "threatfox" => Self::ThreatFox {
                first: columns.at(&["firstseenutc", "firstseen"])?,
                id: columns.at(&["iocid", "id"])?,
                value: columns.at(&["iocvalue"])?,
                kind: columns.at(&["ioctype"])?,
                threat: columns.at(&["threattype"]).unwrap_or(usize::MAX),
                malware: columns.at(&["fkmalware"]).unwrap_or(usize::MAX),
                printable: columns.at(&["malwareprintable"]).unwrap_or(usize::MAX),
                confidence: columns.at(&["confidencelevel"]).unwrap_or(usize::MAX),
            },
            "urlhaus" | "urlhaus-recent" => Self::Urlhaus {
                id: columns.at(&["id"]).unwrap_or(usize::MAX),
                added: columns
                    .at(&["dateadded", "firstseen"])
                    .unwrap_or(usize::MAX),
                url: columns.at(&["url"])?,
                threat: columns.at(&["threat"]).unwrap_or(usize::MAX),
                tags: columns.at(&["tags"]).unwrap_or(usize::MAX),
            },
            "urlhaus-payloads" => {
                let sha256 = columns.at(&["sha256", "sha256hash"]);
                let md5 = columns.at(&["md5", "md5hash"]);
                if sha256.is_none() && md5.is_none() {
                    return None;
                }
                Self::Payloads {
                    first: columns
                        .at(&["firstseen", "firstseenutc", "dateadded"])
                        .unwrap_or(usize::MAX),
                    url: columns.at(&["url"]),
                    sha256,
                    md5,
                    signature: columns.at(&["signature", "malware"]),
                    filetype: columns.at(&["filetype"]),
                }
            }
            "sslbl-ip" => Self::SslIp {
                first: columns.at(&["firstseen"]).unwrap_or(usize::MAX),
                ip: columns.at(&["dstip", "ip"])?,
                port: columns.at(&["dstport", "port"])?,
                reason: columns.at(&["listingreason", "malware"]),
            },
            "sslbl-ja3" => Self::SslJa3 {
                md5: columns.at(&["ja3md5", "ja3"])?,
                first: columns.at(&["firstseen"]).unwrap_or(usize::MAX),
                reason: columns.at(&["listingreason"]).unwrap_or(usize::MAX),
            },
            "sslbl-cert" => Self::SslCert {
                date: columns
                    .at(&["listingdate", "firstseen"])
                    .unwrap_or(usize::MAX),
                sha1: columns.at(&["sha1", "sha1fingerprint"])?,
                reason: columns.at(&["listingreason"]).unwrap_or(usize::MAX),
            },
            _ => return None,
        })
    }
}

fn field<'a>(fields: &[&'a str], at: usize) -> &'a str {
    fields.get(at).copied().unwrap_or("")
}

/// `YYYY-MM-DD` from the start of a timestamp, or the text as it is.
fn day(text: &str) -> String {
    let text = text.trim();
    match text.get(..10) {
        Some(day)
            if day.as_bytes().iter().enumerate().all(|(at, b)| match at {
                4 | 7 => *b == b'-',
                _ => b.is_ascii_digit(),
            }) =>
        {
            day.to_owned()
        }
        _ => text.to_owned(),
    }
}

impl Layout {
    /// The values a line could be matched by.
    fn keys(&self, fields: &[&str], out: &mut Vec<(Kind, String)>) {
        out.clear();
        match self {
            Self::ThreatFox { value, kind, .. } => {
                let kind = match field(fields, *kind) {
                    "ip:port" => Kind::IpPort,
                    "domain" => Kind::Domain,
                    "url" => Kind::Url,
                    "md5_hash" => Kind::Md5,
                    "sha256_hash" => Kind::Sha256,
                    "sha1_hash" => Kind::Sha1,
                    _ => return,
                };
                if let Some(value) = kind.normalize(field(fields, *value)) {
                    out.push((kind, value));
                }
            }
            Self::Urlhaus { url, .. } => {
                if let Some(parts) = kind::url_parts(field(fields, *url)) {
                    out.push((Kind::Url, parts.canonical()));
                    match parts.address() {
                        Some(ip) => {
                            out.push((Kind::IpPort, kind::ip_port(ip, parts.effective_port())))
                        }
                        None => {
                            if let Some(host) = Kind::Domain.normalize(&parts.host) {
                                out.push((Kind::Domain, host));
                            }
                        }
                    }
                }
            }
            Self::Payloads { sha256, md5, .. } => {
                if let Some(value) = sha256.and_then(|at| Kind::Sha256.normalize(field(fields, at)))
                {
                    out.push((Kind::Sha256, value));
                }
                if let Some(value) = md5.and_then(|at| Kind::Md5.normalize(field(fields, at))) {
                    out.push((Kind::Md5, value));
                }
            }
            Self::SslIp { ip, port, .. } => {
                if let (Ok(ip), Ok(port)) = (
                    field(fields, *ip).trim().parse::<std::net::IpAddr>(),
                    field(fields, *port).trim().parse::<u16>(),
                ) {
                    out.push((Kind::IpPort, kind::ip_port(ip, port)));
                }
            }
            Self::SslJa3 { md5, .. } => {
                if let Some(value) = Kind::Ja3.normalize(field(fields, *md5)) {
                    out.push((Kind::Ja3, value));
                }
            }
            Self::SslCert { sha1, .. } => {
                if let Some(value) = Kind::CertSha1.normalize(field(fields, *sha1)) {
                    out.push((Kind::CertSha1, value));
                }
            }
        }
    }

    /// The record behind a line, for the value of `hit` kind that matched.
    fn record(&self, feed: &Feed, fields: &[&str], hit: Kind) -> Record {
        let mut record = Record {
            feed: feed.id.to_owned(),
            ..Record::default()
        };
        match self {
            Self::ThreatFox {
                first,
                id,
                kind,
                threat,
                malware,
                printable,
                confidence,
                ..
            } => {
                record.record_id = field(fields, *id).to_owned();
                let name = field(fields, *printable);
                record.family = if name.is_empty() || name == "Unknown malware" {
                    field(fields, *malware).to_owned()
                } else {
                    name.to_owned()
                };
                record.confidence = field(fields, *confidence).trim().parse::<u8>().ok();
                record.first_seen = day(field(fields, *first));
                record.detail = format!("{} · {}", field(fields, *kind), field(fields, *threat));
                record.reference = format!("threatfox.abuse.ch/ioc/{}/", record.record_id);
            }
            Self::Urlhaus {
                id,
                added,
                url,
                threat,
                tags,
            } => {
                record.record_id = field(fields, *id).to_owned();
                let tags = field(fields, *tags).replace(',', ", ");
                record.family = if tags.trim().is_empty() {
                    field(fields, *threat).to_owned()
                } else {
                    tags
                };
                record.first_seen = day(field(fields, *added));
                let host = kind::url_parts(field(fields, *url))
                    .map(|parts| parts.host)
                    .unwrap_or_default();
                if hit == Kind::Url {
                    record.detail = format!("url · {}", field(fields, *threat));
                    record.reference = format!("urlhaus.abuse.ch/url/{}/", record.record_id);
                } else {
                    record.detail = format!("host · {}", field(fields, *threat));
                    record.reference = format!("urlhaus.abuse.ch/host/{host}/");
                }
            }
            Self::Payloads {
                first,
                url,
                sha256,
                signature,
                filetype,
                ..
            } => {
                let hash = sha256.map(|at| field(fields, at)).unwrap_or("");
                record.record_id = hash.chars().take(12).collect();
                record.family = signature
                    .map(|at| field(fields, at).to_owned())
                    .unwrap_or_default();
                record.first_seen = day(field(fields, *first));
                let host = url
                    .and_then(|at| kind::url_parts(field(fields, at)))
                    .map(|parts| parts.host)
                    .unwrap_or_default();
                let kind_text = filetype.map(|at| field(fields, at)).unwrap_or("");
                record.detail = match (kind_text.is_empty(), host.is_empty()) {
                    (false, false) => format!("served as {kind_text} from {host}"),
                    (true, false) => format!("served from {host}"),
                    (false, true) => format!("served as {kind_text}"),
                    (true, true) => "served by a URLhaus URL".to_owned(),
                };
                record.reference = format!("urlhaus.abuse.ch/browse.php?search={hash}");
            }
            Self::SslIp {
                first,
                ip,
                port,
                reason,
            } => {
                record.record_id = Kind::IpPort
                    .normalize(&format!("{}:{}", field(fields, *ip), field(fields, *port)))
                    .unwrap_or_default();
                record.family = reason
                    .map(|at| field(fields, at).to_owned())
                    .filter(|text| !text.is_empty())
                    .unwrap_or_else(|| "botnet C2".to_owned());
                record.first_seen = day(field(fields, *first));
                record.detail = "TLS server IP:port".into();
                record.reference = "sslbl.abuse.ch/blacklist/".into();
            }
            Self::SslJa3 { md5, first, reason } => {
                record.record_id = field(fields, *md5).to_owned();
                record.family = field(fields, *reason).to_owned();
                record.first_seen = day(field(fields, *first));
                record.detail = "JA3 fingerprint".into();
                record.reference = format!("sslbl.abuse.ch/ja3-fingerprints/{}/", record.record_id);
            }
            Self::SslCert { date, sha1, reason } => {
                record.record_id = field(fields, *sha1).to_owned();
                record.family = field(fields, *reason).to_owned();
                record.first_seen = day(field(fields, *date));
                record.detail = "certificate SHA-1".into();
                record.reference =
                    format!("sslbl.abuse.ch/ssl-certificates/sha1/{}/", record.record_id);
            }
        }
        record
    }
}

/// When a comment line names the columns, the layout it describes.
fn header_layout(feed: &Feed, line: &str) -> Option<Layout> {
    let body = line.trim_start_matches('#').trim();
    let names = split_line(body);
    if names.len() < 2 {
        return None;
    }
    Layout::from_names(feed, &names)
}

fn read_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> std::io::Result<Option<bool>> {
    buffer.clear();
    let read = reader
        .by_ref()
        .take(MAX_LINE_LEN)
        .read_until(b'\n', buffer)?;
    if read == 0 {
        return Ok(None);
    }
    let complete = buffer.last() == Some(&b'\n');
    if !complete && read as u64 >= MAX_LINE_LEN {
        // Drop the rest of an over-long line.
        let mut rest = Vec::new();
        loop {
            rest.clear();
            let more = reader
                .by_ref()
                .take(MAX_LINE_LEN)
                .read_until(b'\n', &mut rest)?;
            if more == 0 || rest.last() == Some(&b'\n') {
                break;
            }
        }
        return Ok(Some(false));
    }
    Ok(Some(true))
}

/// Go through a stored feed. `on_line` gets the values of every record and,
/// when it asks for the record, the record too. Returns how many lines were
/// records.
pub fn walk(
    path: &Path,
    feed: &Feed,
    cancel: &AtomicBool,
    mut on_record: impl FnMut(&[(Kind, String)], &dyn Fn(Kind) -> Record),
) -> Result<Scanned, String> {
    if feed.format == Format::FeodoJson {
        return walk_feodo(path, feed, cancel, &mut on_record);
    }
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut layout: Option<Layout> = None;
    let mut header_seen = false;
    let mut scanned = Scanned::default();
    let mut buffer = Vec::new();
    let mut keys: Vec<(Kind, String)> = Vec::new();
    let mut count = 0u32;
    while let Some(complete) = read_line(&mut reader, &mut buffer)
        .map_err(|error| format!("{}: {error}", path.display()))?
    {
        count = count.wrapping_add(1);
        if count.is_multiple_of(4096) && cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if !complete {
            scanned.skipped += 1;
            continue;
        }
        let text = String::from_utf8_lossy(&buffer);
        let line = text.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if !header_seen && let Some(found) = header_layout(feed, line) {
                layout = Some(found);
                header_seen = true;
            }
            continue;
        }
        if layout.is_none() {
            layout = Layout::defaults(feed);
        }
        let fields = split_line(line);
        if !header_seen {
            // Some files name their columns in the first line, not in a comment.
            header_seen = true;
            if let Some(found) = Layout::from_names(feed, &fields) {
                layout = Some(found);
                continue;
            }
        }
        let Some(layout) = &layout else {
            return Err(format!("{}: the columns are not recognised", feed.name));
        };
        layout.keys(&fields, &mut keys);
        if keys.is_empty() {
            scanned.skipped += 1;
            continue;
        }
        scanned.records += 1;
        on_record(&keys, &|hit| layout.record(feed, &fields, hit));
    }
    Ok(scanned)
}

fn walk_feodo(
    path: &Path,
    feed: &Feed,
    cancel: &AtomicBool,
    on_record: &mut impl FnMut(&[(Kind, String)], &dyn Fn(Kind) -> Record),
) -> Result<Scanned, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} is not valid JSON: {error}", feed.name))?;
    let entries = value
        .as_array()
        .or_else(|| value.get("blocklist").and_then(|list| list.as_array()))
        .ok_or_else(|| format!("{} is not a list of entries", feed.name))?;
    let mut scanned = Scanned::default();
    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let text = |name: &str| entry.get(name).and_then(|v| v.as_str()).unwrap_or("");
        let port = entry.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
        let key = u16::try_from(port)
            .ok()
            .zip(text("ip_address").parse::<std::net::IpAddr>().ok())
            .map(|(port, ip)| kind::ip_port(ip, port));
        let Some(key) = key else {
            scanned.skipped += 1;
            continue;
        };
        scanned.records += 1;
        let record = Record {
            feed: feed.id.to_owned(),
            record_id: key.clone(),
            family: text("malware").to_owned(),
            confidence: None,
            first_seen: day(text("first_seen")),
            detail: format!("C2 · {}", text("status")),
            reference: format!("feodotracker.abuse.ch/browse/host/{}/", text("ip_address")),
        };
        on_record(&[(Kind::IpPort, key)], &|_| record.clone());
    }
    Ok(scanned)
}

/// Find the wanted values in one stored feed.
pub fn scan(
    path: &Path,
    feed: &Feed,
    wanted: &Wanted,
    cancel: &AtomicBool,
    hits: &mut Vec<Hit>,
) -> Result<Scanned, String> {
    let mut per_key: HashMap<(Kind, String), usize> = HashMap::new();
    walk(path, feed, cancel, |keys, build| {
        for (kind, value) in keys {
            if !wanted.contains(*kind, value) {
                continue;
            }
            let seen = per_key.entry((*kind, value.clone())).or_default();
            if *seen >= HITS_PER_KEY {
                continue;
            }
            *seen += 1;
            hits.push(Hit {
                kind: *kind,
                value: value.clone(),
                record: build(*kind),
            });
        }
    })
}

/// How many records a file holds (used to check a download).
pub fn count(path: &Path, feed: &Feed, cancel: &AtomicBool) -> Result<Scanned, String> {
    walk(path, feed, cancel, |_, _| {})
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Small files in the feeds' real formats, with reserved example values.
    pub const THREATFOX: &str = "################################################################\n\
# abuse.ch ThreatFox IOCs (fixture)\n\
################################################################\n\
#\n\
# \"first_seen_utc\", \"ioc_id\", \"ioc_value\", \"ioc_type\", \"threat_type\", \"fk_malware\", \"malware_alias\", \"malware_printable\", \"last_seen_utc\", \"confidence_level\", \"reference\", \"tags\", \"anonymous\", \"reporter\"\n\
\"2026-09-02 10:11:12\", \"1831204\", \"203.0.113.45:443\", \"ip:port\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\", \"None\", \"mirai\", \"0\", \"reporter1\"\n\
\"2026-09-02 10:11:13\", \"1831207\", \"c2.update-cdn.example\", \"domain\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\", \"None\", \"mirai\", \"0\", \"reporter1\"\n\
\"2026-09-02 10:11:14\", \"1831230\", \"http://c2.update-cdn.example/gate.php\", \"url\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\", \"None\", \"\", \"0\", \"reporter1\"\n\
\"2025-03-14 01:02:03\", \"1411873\", \"203.0.113.123:123\", \"ip:port\", \"botnet_cc\", \"unknown\", \"\", \"Unknown malware\", \"\", \"25\", \"None\", \"\", \"0\", \"reporter2\"\n\
\"2026-10-01 00:00:01\", \"1844000\", \"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa\", \"sha256_hash\", \"payload\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"100\", \"None\", \"\", \"0\", \"reporter3\"\n\
\"2026-10-01 00:00:02\", \"1844001\", \"87221652a79fc3c9b04cde0b335fdd5b\", \"md5_hash\", \"payload\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"100\", \"None\", \"\", \"0\", \"reporter3\"\n\
\"2026-10-01 00:00:03\", \"1844002\", \"not a value\", \"envelope\", \"payload\", \"x\", \"\", \"X\", \"\", \"100\", \"None\", \"\", \"0\", \"reporter3\"\n";

    pub const URLHAUS: &str = "################################################################\n\
# abuse.ch URLhaus database dump (fixture)\n\
################################################################\n\
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n\
\"3350918\",\"2026-10-11 08:00:00\",\"http://198.51.100.77/x\",\"online\",\"2026-10-12 08:00:00\",\"malware_download\",\"mirai,elf\",\"https://urlhaus.abuse.ch/url/3350918/\",\"r\"\n\
\"3350919\",\"2026-10-11 08:00:01\",\"http://cdn.fastmirror.example/\",\"online\",\"2026-10-12 08:00:00\",\"malware_download\",\"mirai,elf\",\"https://urlhaus.abuse.ch/url/3350919/\",\"r\"\n\
\"3350921\",\"2026-10-11 08:00:02\",\"http://cdn.fastmirror.example/bin/x86_64/.kd\",\"online\",\"2026-10-12 08:00:00\",\"malware_download\",\"mirai,elf\",\"https://urlhaus.abuse.ch/url/3350921/\",\"r\"\n\
\"2210044\",\"2024-11-30 08:00:00\",\"http://pool.ntp.example/a\",\"offline\",\"2024-12-01 08:00:00\",\"malware_download\",\"\",\"https://urlhaus.abuse.ch/url/2210044/\",\"r\"\n";

    pub const PAYLOADS: &str = "# firstseen,url,filetype,md5,sha256,signature\n\
\"2026-10-11 08:00:02\",\"http://cdn.fastmirror.example/bin/x86_64/.kd\",\"elf\",\"87221652a79fc3c9b04cde0b335fdd5b\",\"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa\",\"Mirai\"\n\
\"2026-10-12 09:00:00\",\"http://198.51.100.77/y\",\"elf\",\"011134986548f3458aa3e7e2a7fceb8d\",\"0000000000000000000000000000000000000000000000000000000000000001\",\"\"\n";

    pub const FEODO: &str = "[{\"ip_address\":\"203.0.113.45\",\"port\":443,\"status\":\"online\",\"hostname\":null,\"as_number\":64500,\"as_name\":\"EXAMPLE\",\"country\":\"US\",\"first_seen\":\"2026-08-01 00:00:00\",\"last_online\":\"2026-10-20\",\"malware\":\"Dridex\"},{\"ip_address\":\"198.51.100.23\",\"port\":8443,\"status\":\"offline\",\"first_seen\":\"2026-07-01 00:00:00\",\"malware\":\"QakBot\"},{\"ip_address\":\"bad\",\"port\":1}]";

    pub const SSLBL_IP: &str = "################################################################\n\
# abuse.ch SSLBL SSL IP Blacklist (fixture)\n\
################################################################\n\
#\n\
# Firstseen,DstIP,DstPort\n\
2026-08-19 10:00:00,203.0.113.45,443\n\
2026-08-20 10:00:00,198.51.100.23,8443\n";

    pub const SSLBL_JA3: &str = "# ja3_md5,Firstseen,Lastseen,Listingreason\n\
f6d64cbcb6dead5e8e864400f056fa32,2026-08-19 10:00:00,2026-10-01 10:00:00,Gafgyt C&C\n";

    pub const SSLBL_CERT: &str = "# Listingdate,SHA1,Listingreason\n\
2026-08-19 10:00:00,2f22765d04931a078909145ca628d2264c852d7d,Gafgyt C&C\n";
}

#[cfg(test)]
mod tests {
    use super::{fixtures::*, *};
    use crate::ioc::feeds::feed;

    fn file(name: &str, text: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ant-ioc-rec-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn wanted(items: &[(Kind, &str)]) -> Wanted {
        let mut wanted = Wanted::default();
        for (kind, value) in items {
            wanted.add(*kind, kind.normalize(value).unwrap());
        }
        wanted
    }

    fn scan_text(feed_id: &str, text: &str, items: &[(Kind, &str)]) -> (Vec<Hit>, Scanned) {
        let feed = feed(feed_id).unwrap();
        let path = file(feed.file, text);
        let mut hits = Vec::new();
        let scanned = scan(
            &path,
            feed,
            &wanted(items),
            &AtomicBool::new(false),
            &mut hits,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        (hits, scanned)
    }

    #[test]
    fn the_csv_splitter_handles_quotes_spaces_and_empty_fields() {
        assert_eq!(
            split_line("\"a\", \"b, c\", \"\", d ,e"),
            ["a", "b, c", "", "d", "e"]
        );
        assert_eq!(split_line("1,,3"), ["1", "", "3"]);
        assert_eq!(split_line("\"say \"\"hi\"\"\",x"), ["say \"\"hi\"\"", "x"]);
        assert_eq!(split_line("\"unterminated"), ["unterminated"]);
        assert_eq!(split_line(""), [""]);
    }

    #[test]
    fn threatfox_records_match_by_kind_and_carry_their_details() {
        let (hits, scanned) = scan_text(
            "threatfox",
            THREATFOX,
            &[
                (Kind::IpPort, "203.0.113.45:443"),
                (Kind::Domain, "C2.Update-CDN.example"),
                (Kind::Url, "http://c2.update-cdn.example/gate.php"),
                (
                    Kind::Sha256,
                    "f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa",
                ),
                (Kind::IpPort, "203.0.113.200:4444"),
            ],
        );
        assert_eq!(scanned.records, 6);
        assert_eq!(scanned.skipped, 1, "the envelope row is not a value kind");
        assert_eq!(hits.len(), 4);
        let ip = hits.iter().find(|hit| hit.kind == Kind::IpPort).unwrap();
        assert_eq!(ip.record.record_id, "1831204");
        assert_eq!(ip.record.family, "Mirai");
        assert_eq!(ip.record.confidence, Some(75));
        assert_eq!(ip.record.first_seen, "2026-09-02");
        assert_eq!(ip.record.detail, "ip:port · botnet_cc");
        assert_eq!(ip.record.reference, "threatfox.abuse.ch/ioc/1831204/");
    }

    #[test]
    fn an_unknown_malware_name_falls_back_to_the_family_id() {
        let (hits, _) = scan_text(
            "threatfox",
            THREATFOX,
            &[(Kind::IpPort, "203.0.113.123:123")],
        );
        assert_eq!(hits[0].record.family, "unknown");
        assert_eq!(hits[0].record.confidence, Some(25));
    }

    #[test]
    fn urlhaus_lists_urls_and_their_hosts() {
        let (hits, scanned) = scan_text(
            "urlhaus",
            URLHAUS,
            &[
                (Kind::Url, "cdn.fastmirror.example/bin/x86_64/.kd"),
                (Kind::Domain, "cdn.fastmirror.example"),
                (Kind::IpPort, "198.51.100.77:80"),
                (Kind::IpPort, "198.51.100.77:81"),
            ],
        );
        assert_eq!(scanned.records, 4);
        let kinds: Vec<_> = hits
            .iter()
            .map(|hit| (hit.kind, hit.record.record_id.as_str()))
            .collect();
        assert!(kinds.contains(&(Kind::Url, "3350921")));
        assert!(kinds.contains(&(Kind::Domain, "3350919")));
        assert!(kinds.contains(&(Kind::IpPort, "3350918")));
        let host = hits.iter().find(|hit| hit.kind == Kind::IpPort).unwrap();
        assert_eq!(host.record.detail, "host · malware_download");
        assert_eq!(host.record.family, "mirai, elf");
        assert_eq!(
            host.record.reference,
            "urlhaus.abuse.ch/host/198.51.100.77/"
        );
        assert!(!hits.iter().any(|hit| hit.value == "198.51.100.77:81"));
    }

    #[test]
    fn payload_hashes_match_by_either_digest() {
        let (hits, _) = scan_text(
            "urlhaus-payloads",
            PAYLOADS,
            &[
                (
                    Kind::Sha256,
                    "F66025C51E65B02FFDAF55EA9460656A0B79598CB7DB1514DC7A23A81B4CF1AA",
                ),
                (Kind::Md5, "011134986548f3458aa3e7e2a7fceb8d"),
            ],
        );
        assert_eq!(hits.len(), 2);
        let sha = hits.iter().find(|hit| hit.kind == Kind::Sha256).unwrap();
        assert_eq!(sha.record.family, "Mirai");
        assert_eq!(
            sha.record.detail,
            "served as elf from cdn.fastmirror.example"
        );
    }

    #[test]
    fn feodo_and_sslbl_feeds_are_read() {
        let (hits, scanned) = scan_text("feodo", FEODO, &[(Kind::IpPort, "203.0.113.45:443")]);
        assert_eq!((hits.len(), scanned.records, scanned.skipped), (1, 2, 1));
        assert_eq!(hits[0].record.family, "Dridex");
        assert_eq!(hits[0].record.first_seen, "2026-08-01");
        let (hits, _) = scan_text(
            "sslbl-ip",
            SSLBL_IP,
            &[(Kind::IpPort, "198.51.100.23:8443")],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record.first_seen, "2026-08-20");
        let (hits, _) = scan_text(
            "sslbl-ja3",
            SSLBL_JA3,
            &[(Kind::Ja3, "f6d64cbcb6dead5e8e864400f056fa32")],
        );
        assert_eq!(hits[0].record.family, "Gafgyt C&C");
        let (hits, _) = scan_text(
            "sslbl-cert",
            SSLBL_CERT,
            &[(Kind::CertSha1, "2F22765D04931A078909145CA628D2264C852D7D")],
        );
        assert_eq!(hits[0].record.reference.split('/').next_back(), Some(""));
        assert!(hits[0].record.reference.contains("2f22765d"));
    }

    #[test]
    fn a_file_without_a_header_uses_the_default_columns() {
        let text = "\"2026-10-11 08:00:02\",\"http://x.example/a\",\"elf\",\"87221652a79fc3c9b04cde0b335fdd5b\",\"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa\",\"Mirai\"\n";
        let (hits, scanned) = scan_text(
            "urlhaus-payloads",
            text,
            &[(Kind::Md5, "87221652a79fc3c9b04cde0b335fdd5b")],
        );
        assert_eq!((hits.len(), scanned.records), (1, 1));
    }

    #[test]
    fn at_most_a_few_records_are_kept_for_one_value() {
        let mut text = String::from("# Firstseen,DstIP,DstPort\n");
        for day in 1..20 {
            text.push_str(&format!("2026-08-{day:02} 00:00:00,203.0.113.45,443\n"));
        }
        let (hits, scanned) = scan_text("sslbl-ip", &text, &[(Kind::IpPort, "203.0.113.45:443")]);
        assert_eq!(scanned.records, 19);
        assert_eq!(hits.len(), HITS_PER_KEY);
    }

    #[test]
    fn a_cancelled_pass_stops() {
        let feed = feed("sslbl-ip").unwrap();
        let mut text = String::from("# Firstseen,DstIP,DstPort\n");
        for _ in 0..10_000 {
            text.push_str("2026-08-01 00:00:00,203.0.113.45,443\n");
        }
        let path = file(feed.file, &text);
        let cancel = AtomicBool::new(true);
        assert_eq!(count(&path, feed, &cancel).unwrap_err(), "cancelled");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn day_helper_keeps_the_date_part() {
        assert_eq!(day("2026-10-11 08:00:02"), "2026-10-11");
        assert_eq!(day("yesterday"), "yesterday");
    }
}
