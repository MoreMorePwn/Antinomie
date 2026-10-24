// SPDX-License-Identifier: GPL-3.0-only
//! The online check: ask abuse.ch about values the stored datasets do not
//! list. It sends indicator values (never files) to threatfox-api.abuse.ch and
//! urlhaus-api.abuse.ch, so it runs only when the person has switched it on
//! for this session and pressed the button; the switch is never saved.
//!
//! Only public values that had no offline match are sent: a private address,
//! a local name, a value a known false positive excuses or a value the
//! datasets already match is not. JA3 and certificate fingerprints have no
//! abuse.ch query and are never sent.
use super::{
    indicator::{Indicator, Lookup},
    kind::Kind,
    verdict::{OnlineEntry, OnlineRecord, OnlineResults, Outcome, Verdict},
};
use crate::api_keys::{self, Secret};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
};

pub const THREATFOX_API: &str = "https://threatfox-api.abuse.ch/api/v1/";
pub const URLHAUS_HOST: &str = "https://urlhaus-api.abuse.ch/v1/host/";
pub const URLHAUS_URL: &str = "https://urlhaus-api.abuse.ch/v1/url/";
pub const URLHAUS_PAYLOAD: &str = "https://urlhaus-api.abuse.ch/v1/payload/";
/// Most values sent by one press of the button.
pub const MAX_LOOKUPS: usize = 50;
const FILE_NAME: &str = "ioc-online.json";
const MAX_REPLY: u64 = 2 * 1024 * 1024;

/// What a request carries.
pub enum Body<'a> {
    Json(&'a str),
    Form(&'a [(&'a str, &'a str)]),
}

/// Sends one request and returns the reply text.
pub trait Transport {
    fn post(&self, url: &str, body: Body<'_>, key: &Secret) -> Result<String, String>;
}

/// The system `curl`: the key goes on standard input, the reply is bounded.
pub struct CurlTransport {
    pub curl: PathBuf,
}

impl Transport for CurlTransport {
    fn post(&self, url: &str, body: Body<'_>, key: &Secret) -> Result<String, String> {
        let host = crate::ruleset::https_host(url)?;
        if !crate::ruleset::is_abusech_host(&host) {
            return Err(format!("{host} is not an abuse.ch host"));
        }
        crate::dependencies::require_tool(&self.curl, "curl")?;
        let mut command = crate::http_fetch::command(
            &self.curl,
            &crate::http_fetch::Options {
                fail: false,
                ..crate::http_fetch::Options::new(30, MAX_REPLY)
            },
        );
        command.args(["-X", "POST", "-H", "@-", "--write-out", "\n%{http_code}"]);
        match body {
            Body::Json(text) => {
                command.args(["--data-binary", text]);
            }
            Body::Form(fields) => {
                for (name, value) in fields {
                    command
                        .arg("--data-urlencode")
                        .arg(format!("{name}={value}"));
                }
            }
        }
        let mut child = command
            .arg(url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("curl: {error}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let mut headers = format!("Auth-Key: {}\n", key.expose());
            if matches!(body, Body::Json(_)) {
                headers.push_str("Content-Type: application/json\n");
            }
            if let Err(error) = stdin.write_all(headers.as_bytes()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(api_keys::redact(&format!("curl: {error}"), &[key]));
            }
        }
        let mut reply = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = stdout.take(MAX_REPLY + 8).read_to_end(&mut reply);
        }
        let done = child.wait_with_output().map_err(|e| format!("curl: {e}"))?;
        if !done.status.success() {
            let message = String::from_utf8_lossy(&done.stderr).into_owned();
            let message = api_keys::redact(&message, &[key]);
            return Err(format!(
                "abuse.ch: {}",
                message.lines().last().unwrap_or("request failed").trim()
            ));
        }
        let at = reply
            .iter()
            .rposition(|byte| *byte == b'\n')
            .ok_or("abuse.ch gave no HTTP status")?;
        let status: u16 = std::str::from_utf8(&reply[at + 1..])
            .ok()
            .and_then(|code| code.trim().parse().ok())
            .ok_or("abuse.ch gave an invalid HTTP status")?;
        reply.truncate(at);
        match status {
            200..=299 => Ok(String::from_utf8_lossy(&reply).into_owned()),
            401 | 403 => Err("abuse.ch refused the Auth-Key".into()),
            429 => Err("abuse.ch asks to slow down (HTTP 429); try later".into()),
            other => Err(format!("abuse.ch answered HTTP {other}")),
        }
    }
}

/// The values worth sending for an indicator: public, with no offline match,
/// of a kind abuse.ch can be asked about.
pub fn eligible(indicator: &Indicator, verdict: &Verdict) -> Vec<Lookup> {
    if verdict.outcome != Outcome::NoMatch {
        return Vec::new();
    }
    indicator
        .lookups
        .iter()
        .filter(|lookup| {
            matches!(
                lookup.kind,
                Kind::IpPort | Kind::Domain | Kind::Url | Kind::Sha256 | Kind::Md5
            )
        })
        .cloned()
        .collect()
}

fn text(value: &Value, name: &str) -> String {
    match value.get(name) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

fn day(text: &str) -> String {
    text.get(..10).unwrap_or(text).to_owned()
}

fn status_error(source: &str, status: &str) -> String {
    match status {
        "unauthorized" | "unknown_auth_key" | "wrong_auth_key" | "missing_auth_key"
        | "user_blacklisted" => "abuse.ch refused the Auth-Key".into(),
        other => format!("{source} answered {other}"),
    }
}

/// Parse a ThreatFox answer.
pub fn parse_threatfox(reply: &str) -> Result<Vec<OnlineRecord>, String> {
    let value: Value = serde_json::from_str(reply)
        .map_err(|error| format!("ThreatFox reply is not JSON: {error}"))?;
    match value.get("query_status").and_then(Value::as_str) {
        Some("ok") => {}
        Some("no_result" | "no_results") => return Ok(Vec::new()),
        Some(other) => return Err(status_error("ThreatFox", other)),
        None => return Err("ThreatFox reply has no status".into()),
    }
    let rows = value
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(rows
        .iter()
        .take(6)
        .map(|row| {
            let id = text(row, "id");
            let family = {
                let printable = text(row, "malware_printable");
                if printable.is_empty() || printable == "Unknown malware" {
                    text(row, "malware")
                } else {
                    printable
                }
            };
            OnlineRecord {
                dataset: "threatfox".into(),
                family,
                confidence: row
                    .get("confidence_level")
                    .and_then(Value::as_u64)
                    .and_then(|c| u8::try_from(c).ok()),
                first_seen: day(&text(row, "first_seen")),
                detail: format!("{} · {}", text(row, "ioc_type"), text(row, "threat_type")),
                reference: format!("threatfox.abuse.ch/ioc/{id}/"),
                record_id: id,
            }
        })
        .collect())
}

/// Parse a URLhaus host, URL or payload answer.
pub fn parse_urlhaus(reply: &str) -> Result<Vec<OnlineRecord>, String> {
    let value: Value = serde_json::from_str(reply)
        .map_err(|error| format!("URLhaus reply is not JSON: {error}"))?;
    match value.get("query_status").and_then(Value::as_str) {
        Some("ok") => {}
        Some(
            "no_results"
            | "no_result"
            | "invalid_host"
            | "invalid_url"
            | "invalid_sha256_hash"
            | "invalid_md5_hash",
        ) => {
            return Ok(Vec::new());
        }
        Some(other) => return Err(status_error("URLhaus", other)),
        None => return Err("URLhaus reply has no status".into()),
    }
    let tags = |row: &Value| -> String {
        row.get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    if let Some(urls) = value.get("urls").and_then(Value::as_array) {
        for row in urls.iter().take(6) {
            let id = text(row, "id");
            out.push(OnlineRecord {
                dataset: "urlhaus".into(),
                family: tags(row),
                confidence: None,
                first_seen: day(&text(row, "date_added")),
                detail: format!("url · {}", text(row, "threat")),
                reference: format!("urlhaus.abuse.ch/url/{id}/"),
                record_id: id,
            });
        }
    } else if value.get("sha256_hash").is_some() || value.get("md5_hash").is_some() {
        let hash = text(&value, "sha256_hash");
        out.push(OnlineRecord {
            dataset: "urlhaus-payloads".into(),
            record_id: hash.chars().take(12).collect(),
            family: text(&value, "signature"),
            confidence: None,
            first_seen: day(&text(&value, "firstseen")),
            detail: format!("served as {}", text(&value, "file_type")),
            reference: format!("urlhaus.abuse.ch/browse.php?search={hash}"),
        });
    } else {
        let id = text(&value, "id");
        out.push(OnlineRecord {
            dataset: "urlhaus".into(),
            family: tags(&value),
            confidence: None,
            first_seen: day(&text(&value, "date_added")),
            detail: format!("url · {}", text(&value, "threat")),
            reference: format!("urlhaus.abuse.ch/url/{id}/"),
            record_id: id,
        });
    }
    Ok(out)
}

/// Ask abuse.ch about one value.
pub fn ask(
    transport: &dyn Transport,
    key: &Secret,
    lookup: &Lookup,
) -> Result<Vec<OnlineRecord>, String> {
    let threatfox = |body: String| -> Result<Vec<OnlineRecord>, String> {
        parse_threatfox(&transport.post(THREATFOX_API, Body::Json(&body), key)?)
    };
    let search = |term: &str| {
        serde_json::json!({"query": "search_ioc", "search_term": term, "exact_match": true})
            .to_string()
    };
    let mut out = Vec::new();
    match lookup.kind {
        Kind::IpPort => {
            out.extend(threatfox(search(&lookup.value))?);
            let host = lookup
                .value
                .rsplit_once(':')
                .map_or(lookup.value.as_str(), |(h, _)| h);
            let host = host.trim_matches(['[', ']']);
            out.extend(parse_urlhaus(&transport.post(
                URLHAUS_HOST,
                Body::Form(&[("host", host)]),
                key,
            )?)?);
        }
        Kind::Domain => {
            out.extend(threatfox(search(&lookup.value))?);
            out.extend(parse_urlhaus(&transport.post(
                URLHAUS_HOST,
                Body::Form(&[("host", &lookup.value)]),
                key,
            )?)?);
        }
        Kind::Url => {
            out.extend(threatfox(search(&lookup.value))?);
            let url = format!("http://{}", lookup.value);
            out.extend(parse_urlhaus(&transport.post(
                URLHAUS_URL,
                Body::Form(&[("url", &url)]),
                key,
            )?)?);
        }
        Kind::Sha256 | Kind::Md5 => {
            out.extend(threatfox(
                serde_json::json!({"query": "search_hash", "hash": lookup.value}).to_string(),
            )?);
            let field = if lookup.kind == Kind::Sha256 {
                "sha256_hash"
            } else {
                "md5_hash"
            };
            out.extend(parse_urlhaus(&transport.post(
                URLHAUS_PAYLOAD,
                Body::Form(&[(field, &lookup.value)]),
                key,
            )?)?);
        }
        Kind::Sha1 | Kind::Ja3 | Kind::CertSha1 => {}
    }
    Ok(out)
}

/// What a press of the button did.
#[derive(Debug, Default)]
pub struct Checked {
    pub asked: usize,
    pub found: usize,
    /// Values left out because of [`MAX_LOOKUPS`].
    pub skipped: usize,
    pub error: Option<String>,
}

/// Ask about each value in turn and add the answers to `results`. Stops at
/// the first error (a refused key would be refused again).
pub fn check(
    transport: &dyn Transport,
    key: &Secret,
    lookups: &[Lookup],
    now_unix: u64,
    results: &mut OnlineResults,
    cancel: &AtomicBool,
) -> Checked {
    let mut done = Checked::default();
    let mut unique: Vec<&Lookup> = Vec::new();
    for lookup in lookups {
        // JA3 and certificate fingerprints have no abuse.ch query: never sent.
        let askable = matches!(
            lookup.kind,
            Kind::IpPort | Kind::Domain | Kind::Url | Kind::Sha256 | Kind::Md5
        );
        if askable && !unique.contains(&lookup) {
            unique.push(lookup);
        }
    }
    done.skipped = unique.len().saturating_sub(MAX_LOOKUPS);
    for lookup in unique.into_iter().take(MAX_LOOKUPS) {
        if cancel.load(Ordering::Relaxed) {
            done.error = Some("cancelled".into());
            break;
        }
        match ask(transport, key, lookup) {
            Ok(records) => {
                done.asked += 1;
                done.found += usize::from(!records.is_empty());
                results.insert(OnlineEntry {
                    kind: lookup.kind,
                    value: lookup.value.clone(),
                    at_unix: now_unix,
                    records,
                });
            }
            Err(error) => {
                done.error = Some(api_keys::redact(&error, &[key]));
                break;
            }
        }
    }
    done
}

/// The answers kept with a run: `<run dir>/ioc-online.json`.
pub fn load(run_dir: &Path) -> OnlineResults {
    std::fs::read(run_dir.join(FILE_NAME))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(run_dir: &Path, results: &OnlineResults) -> Result<(), String> {
    crate::storage::atomic_json(&run_dir.join(FILE_NAME), results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::{
        indicator::{Collector, Seen, Source, Via},
        verdict::{Scan, evaluate},
    };
    use std::cell::RefCell;

    #[derive(Default)]
    struct Recorder {
        sent: RefCell<Vec<(String, String)>>,
        replies: RefCell<Vec<Result<String, String>>>,
    }

    impl Transport for Recorder {
        fn post(&self, url: &str, body: Body<'_>, key: &Secret) -> Result<String, String> {
            assert!(!key.is_empty());
            let text = match body {
                Body::Json(text) => text.to_owned(),
                Body::Form(fields) => fields
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&"),
            };
            self.sent.borrow_mut().push((url.to_owned(), text));
            self.replies
                .borrow_mut()
                .pop()
                .unwrap_or_else(|| Ok(r#"{"query_status":"no_result"}"#.into()))
        }
    }

    const THREATFOX_HIT: &str = r#"{"query_status":"ok","data":[{"id":"1844011","ioc":"198.51.100.23:8443","threat_type":"botnet_cc","ioc_type":"ip:port","malware":"elf.gafgyt","malware_printable":"Gafgyt","confidence_level":50,"first_seen":"2026-10-20 10:00:00 UTC","reference":null}]}"#;
    const URLHAUS_HOST_HIT: &str = r#"{"query_status":"ok","host":"198.51.100.77","urls":[{"id":"3350918","urlhaus_reference":"https://urlhaus.abuse.ch/url/3350918/","url_status":"online","date_added":"2026-10-11 08:00:00 UTC","threat":"malware_download","tags":["elf","mirai"]}]}"#;
    const URLHAUS_PAYLOAD_HIT: &str = r#"{"query_status":"ok","md5_hash":"87221652a79fc3c9b04cde0b335fdd5b","sha256_hash":"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa","file_type":"elf","firstseen":"2026-10-11 08:00:02","signature":"Mirai"}"#;

    #[test]
    fn replies_are_read_in_their_real_shapes() {
        let records = parse_threatfox(THREATFOX_HIT).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].family, "Gafgyt");
        assert_eq!(records[0].confidence, Some(50));
        assert_eq!(records[0].first_seen, "2026-10-20");
        assert_eq!(records[0].reference, "threatfox.abuse.ch/ioc/1844011/");
        assert!(
            parse_threatfox(
                r#"{"query_status":"no_result","data":"Your search did not yield any results"}"#
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            parse_threatfox(r#"{"query_status":"unauthorized"}"#).unwrap_err(),
            "abuse.ch refused the Auth-Key"
        );
        assert!(parse_threatfox("<html>").is_err());
        let host = parse_urlhaus(URLHAUS_HOST_HIT).unwrap();
        assert_eq!(
            (host[0].family.as_str(), host[0].record_id.as_str()),
            ("elf, mirai", "3350918")
        );
        let payload = parse_urlhaus(URLHAUS_PAYLOAD_HIT).unwrap();
        assert_eq!(payload[0].dataset, "urlhaus-payloads");
        assert_eq!(payload[0].family, "Mirai");
        assert!(
            parse_urlhaus(r#"{"query_status":"no_results"}"#)
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_urlhaus(r#"{"query_status":"unknown_auth_key"}"#)
                .unwrap_err()
                .contains("Auth-Key")
        );
    }

    fn ip(text: &str) -> std::net::IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn only_public_values_without_an_offline_match_are_eligible() {
        let mut c = Collector::default();
        c.endpoint(
            ip("198.51.100.23"),
            8443,
            "tcp",
            Source::Pcap,
            Seen::default(),
        );
        c.endpoint(ip("10.0.2.15"), 22, "tcp", Source::Pcap, Seen::default());
        c.domain(
            "printer.local",
            Via::Dns,
            &[],
            Source::Pcap,
            Seen::default(),
        );
        c.domain(
            "gate.kd-relay.example",
            Via::Dns,
            &[],
            Source::Pcap,
            Seen::default(),
        );
        c.tls(
            (ip("198.51.100.23"), 8443),
            super::super::indicator::TlsFacts {
                ja3: "8f5bbb228478771191352a5f5120dc87".into(),
                ..Default::default()
            },
            Source::Pcap,
            Seen::default(),
        );
        let all = c.finish();
        // A scan with a feed loaded and no hits: everything checkable is No match.
        let scan = Scan {
            loaded: ["threatfox", "urlhaus", "sslbl-ip", "sslbl-ja3", "feodo"]
                .iter()
                .map(|id| {
                    let feed = crate::ioc::feeds::feed(id).unwrap();
                    crate::ioc::verdict::LoadedFeed {
                        id: feed.id,
                        name: feed.name,
                        date: "2026-10-22".into(),
                        fetched_unix: 0,
                    }
                })
                .collect(),
            ..Scan::default()
        };
        let mut sent = Vec::new();
        for indicator in &all {
            let verdict = evaluate(indicator, &scan, &[], &OnlineResults::default());
            sent.extend(eligible(indicator, &verdict).into_iter().map(|l| l.value));
        }
        sent.sort();
        sent.dedup();
        assert_eq!(
            sent,
            ["198.51.100.23:8443", "gate.kd-relay.example"],
            "no private address, local name or JA3: {sent:?}"
        );
    }

    #[test]
    fn an_ip_is_asked_of_threatfox_and_the_urlhaus_host_and_answers_are_kept() {
        let recorder = Recorder::default();
        recorder
            .replies
            .borrow_mut()
            .push(Ok(URLHAUS_HOST_HIT.into()));
        recorder.replies.borrow_mut().push(Ok(THREATFOX_HIT.into()));
        let key = Secret::new("online-test-key-1234");
        let mut results = OnlineResults::default();
        let lookups = vec![
            Lookup {
                kind: Kind::IpPort,
                value: "198.51.100.23:8443".into(),
            },
            Lookup {
                kind: Kind::IpPort,
                value: "198.51.100.23:8443".into(),
            },
            Lookup {
                kind: Kind::Ja3,
                value: "8f5bbb228478771191352a5f5120dc87".into(),
            },
        ];
        let done = check(
            &recorder,
            &key,
            &lookups,
            1_000,
            &mut results,
            &AtomicBool::new(false),
        );
        assert_eq!(
            (done.asked, done.found, done.skipped),
            (1, 1, 0),
            "the repeat is asked once, JA3 asks nothing: {done:?}"
        );
        assert!(done.error.is_none());
        let sent = recorder.sent.borrow();
        assert_eq!(sent[0].0, THREATFOX_API);
        assert!(sent[0].1.contains("\"search_term\":\"198.51.100.23:8443\""));
        assert!(sent[0].1.contains("\"exact_match\":true"));
        assert_eq!(
            sent[1],
            (URLHAUS_HOST.to_owned(), "host=198.51.100.23".to_owned())
        );
        let entry = results.entry(Kind::IpPort, "198.51.100.23:8443").unwrap();
        assert_eq!((entry.at_unix, entry.records.len()), (1_000, 2));
    }

    #[test]
    fn a_hash_is_asked_of_the_payload_endpoints_and_a_refused_key_stops_the_run() {
        let recorder = Recorder::default();
        let key = Secret::new("online-test-key-1234");
        let mut results = OnlineResults::default();
        let lookups = [
            Lookup {
                kind: Kind::Sha256,
                value: "f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa".into(),
            },
            Lookup {
                kind: Kind::Domain,
                value: "a.example".into(),
            },
        ];
        recorder
            .replies
            .borrow_mut()
            .push(Ok(r#"{"query_status":"no_results"}"#.into()));
        recorder
            .replies
            .borrow_mut()
            .push(Ok(r#"{"query_status":"no_result"}"#.into()));
        let done = check(
            &recorder,
            &key,
            &lookups[..1],
            5,
            &mut results,
            &AtomicBool::new(false),
        );
        assert_eq!((done.asked, done.found), (1, 0));
        let sent = recorder.sent.borrow().clone();
        assert!(sent[0].1.contains("search_hash"));
        assert_eq!(sent[1].0, URLHAUS_PAYLOAD);
        assert!(sent[1].1.starts_with("sha256_hash="));
        assert!(
            results
                .entry(Kind::Sha256, &lookups[0].value)
                .unwrap()
                .records
                .is_empty(),
            "no result is recorded too"
        );
        // A refused key ends the pass and the message holds no key.
        let refusing = Recorder::default();
        refusing.replies.borrow_mut().push(Err(
            "abuse.ch refused the Auth-Key online-test-key-1234".into(),
        ));
        let done = check(
            &refusing,
            &key,
            &lookups[1..],
            6,
            &mut results,
            &AtomicBool::new(false),
        );
        assert_eq!(done.asked, 0);
        let error = done.error.unwrap();
        assert!(
            error.contains("refused") && !error.contains("online-test-key"),
            "{error}"
        );
    }

    #[test]
    fn at_most_fifty_values_are_sent_and_the_rest_are_counted() {
        let recorder = Recorder::default();
        let key = Secret::new("online-test-key-1234");
        let lookups: Vec<Lookup> = (0..60)
            .map(|n| Lookup {
                kind: Kind::Domain,
                value: format!("host{n}.example"),
            })
            .collect();
        let mut results = OnlineResults::default();
        let done = check(
            &recorder,
            &key,
            &lookups,
            1,
            &mut results,
            &AtomicBool::new(false),
        );
        assert_eq!((done.asked, done.skipped), (MAX_LOOKUPS, 10));
        assert_eq!(recorder.sent.borrow().len(), MAX_LOOKUPS * 2);
    }

    #[test]
    fn answers_are_kept_with_the_run_and_hold_no_key() {
        let dir = std::env::temp_dir().join(format!("ant-online-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load(&dir).entries.is_empty());
        let mut results = OnlineResults::default();
        results.insert(OnlineEntry {
            kind: Kind::Domain,
            value: "a.example".into(),
            at_unix: 9,
            records: Vec::new(),
        });
        save(&dir, &results).unwrap();
        assert_eq!(load(&dir), results);
        assert!(
            !std::fs::read_to_string(dir.join(FILE_NAME))
                .unwrap()
                .contains("Auth")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_curl_transport_sends_the_key_on_stdin_to_abuse_ch_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("ant-online-curl-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-curl.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{a}'\ncat > '{s}'\nprintf '{{\"query_status\":\"no_result\"}}\\n200'\n",
                a = dir.join("args.txt").display(),
                s = dir.join("stdin.txt").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let transport = CurlTransport { curl: script };
        let key = Secret::new("curl-online-secret-77");
        let reply = transport
            .post(
                THREATFOX_API,
                Body::Json("{\"query\":\"search_ioc\"}"),
                &key,
            )
            .unwrap();
        assert!(reply.contains("no_result"));
        let args = std::fs::read_to_string(dir.join("args.txt")).unwrap();
        let stdin = std::fs::read_to_string(dir.join("stdin.txt")).unwrap();
        assert!(!args.contains("secret"), "{args}");
        assert!(stdin.contains("Auth-Key: curl-online-secret-77"));
        assert!(stdin.contains("Content-Type: application/json"));
        let error = transport
            .post("https://example.com/api", Body::Json("{}"), &key)
            .unwrap_err();
        assert!(error.contains("not an abuse.ch host"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
