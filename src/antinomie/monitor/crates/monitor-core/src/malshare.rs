//! MalShare (malshare.com), the second sample source: free API keys, 2000
//! calls a day, samples served as the files themselves.
//!
//! The key travels in the request's URL, so curl reads the URL from its
//! standard input (`-K -`) and the key never appears on a command line. A
//! downloaded file is held in memory, checked against its SHA-256 and written
//! straight into an encrypted archive ([`samples::store_bytes`]); it is never
//! written to the host as itself. MalShare's terms ask that it is credited as
//! the samples' source: every sample from it is recorded as from MalShare.
use crate::samples::{self, SampleInfo, StoredSample};
use serde_json::Value;
use std::{
    collections::HashSet,
    io::{Read, Write},
    path::Path,
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// MalShare's API: GET requests with the key and an action in the query.
pub const API: &str = "https://malshare.com/api.php";
/// Where a free API key is made.
pub const KEYS: &str = "https://malshare.com/register.php";
/// Search and list replies larger than this are refused.
const MAX_REPLY: u64 = 32 * 1024 * 1024;

/// `text` for a URL query.
fn encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// A GET to MalShare; at most `max` bytes of reply. The URL, which holds the
/// key, is given to curl on its standard input.
fn get(curl: &Path, key: &str, params: &[(&str, &str)], max: u64) -> Result<Vec<u8>, String> {
    crate::dependencies::require_tool(curl, "curl")?;
    let key = key.trim();
    if key.is_empty() {
        return Err("set a MalShare API key first".into());
    }
    if !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("a MalShare API key is letters and digits only".into());
    }
    let mut url = format!("{API}?api_key={key}");
    for (name, value) in params {
        url.push_str(&format!("&{name}={}", encode(value)));
    }
    // The HTTP status is reported through --write-out, so errors are not
    // turned into failures here.
    let mut child = crate::http_fetch::command(
        curl,
        &crate::http_fetch::Options {
            fail: false,
            follow: true,
            ..crate::http_fetch::Options::new(300, max.saturating_add(16))
        },
    )
    .args(["-K", "-", "--write-out", "\n%{http_code}"])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .map_err(|e| format!("curl: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        // curl's config syntax: the value quoted, with \ and " escaped.
        if let Err(error) = writeln!(
            stdin,
            "url = \"{}\"",
            url.replace('\\', "\\\\").replace('"', "\\\"")
        ) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("MalShare request configuration: {error}"));
        }
    }
    let mut body = Vec::new();
    if let Some(stdout) = child.stdout.take()
        && let Err(error) = stdout.take(max + 6).read_to_end(&mut body)
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("MalShare response read: {error}"));
    }
    if body.len() as u64 > max + 4 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("MalShare's reply is larger than {} MiB", max >> 20));
    }
    let done = child.wait_with_output().map_err(|e| format!("curl: {e}"))?;
    if !done.status.success() {
        let message = String::from_utf8_lossy(&done.stderr).replace(key, "[redacted]");
        return Err(format!(
            "MalShare: {}",
            message.lines().last().unwrap_or("request failed").trim()
        ));
    }
    let at = body
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or("MalShare request did not report an HTTP status")?;
    let status = std::str::from_utf8(&body[at + 1..])
        .ok()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("MalShare request reported an invalid HTTP status")?;
    body.truncate(at);
    if !(200..300).contains(&status) {
        return Err(match status {
            400 | 401 => format!("MalShare HTTP {status}: API request or key refused"),
            403 => "MalShare HTTP 403: access refused by the service or its edge protection".into(),
            404 => "MalShare HTTP 404: requested sample or endpoint unavailable".into(),
            429 => "MalShare HTTP 429: request quota exceeded; try later".into(),
            _ => format!("MalShare HTTP {status}: request failed; try later"),
        });
    }
    if !params
        .iter()
        .any(|(name, value)| *name == "action" && *value == "getfile")
        && let Some(message) = refusal(&body)
    {
        return Err(message.replace(key, "[redacted]"));
    }
    Ok(body)
}

/// Ask MalShare for the key's daily limit: a cheap call that fails when the
/// key is refused. Used by Tools > API keys > Test.
pub fn check_key(curl: &Path, key: &str) -> Result<(), String> {
    get(curl, key, &[("action", "getlimit")], 64 * 1024).map(|_| ())
}

/// MalShare answers a refusal (a bad key, the daily limit, an unknown
/// sample) as a line of text: that text, when `body` is one.
fn refusal(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?.trim();
    if text.is_empty() {
        return Some("MalShare sent an empty reply".into());
    }
    let first = text.as_bytes()[0];
    if first == b'{' || first == b'[' {
        return None;
    }
    let line: String = text
        .lines()
        .next()
        .unwrap_or(text)
        .chars()
        .take(160)
        .collect();
    // "User specified in `api_key` GET variable does not exist" (HTTP 400).
    if line.contains("api_key") || line.to_ascii_lowercase().contains("invalid api key") {
        return Some("MalShare refused the API key".into());
    }
    Some(format!("MalShare: {line}"))
}

/// The JSON values in `body`: an array, one object, or objects one after
/// another (as `search` answers).
fn objects(body: &[u8]) -> Result<Vec<Value>, String> {
    let mut found = Vec::new();
    for value in serde_json::Deserializer::from_slice(body).into_iter::<Value>() {
        match value.map_err(|e| format!("MalShare reply: {e}"))? {
            Value::Array(items) => found.extend(items),
            other => found.push(other),
        }
    }
    Ok(found)
}

/// A field of a MalShare object, whatever case its name is in (`md5`, `MD5`).
fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_object()?
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn text(value: &Value, name: &str) -> Option<String> {
    match field(value, name)? {
        Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_owned()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// `seconds` since 1970 as `YYYY-MM-DD HH:MM:SS` (UTC), as MalwareBazaar
/// writes dates.
fn utc(seconds: i64) -> String {
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Civil date from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The host of a source URL, as a tag.
fn host(source: &str) -> Option<String> {
    let rest = source.split_once("://").map_or(source, |(_, rest)| rest);
    let host = rest.split(['/', ':', '?']).next()?.trim();
    (!host.is_empty() && host.len() <= 64).then(|| host.to_ascii_lowercase())
}

/// A sample as MalShare lists it (`details`, `search`, `type`, `getlist`).
fn info(value: &Value, file_type: Option<&str>) -> Option<SampleInfo> {
    let sha256 = text(value, "sha256")?.to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut sources: Vec<String> = match field(value, "sources") {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    };
    sources.extend(text(value, "source"));
    let name = match field(value, "filenames") {
        Some(Value::Array(names)) => names
            .iter()
            .find_map(|name| name.as_str().map(str::to_owned)),
        _ => None,
    }
    .or_else(|| {
        // The last part of where it was found, when that names a file.
        sources.iter().find_map(|source| {
            let path = source
                .split_once("://")
                .map_or(source.as_str(), |(_, rest)| rest);
            let (_, path) = path.split_once('/')?;
            let last = path
                .split(['?', '#'])
                .next()?
                .trim_end_matches('/')
                .rsplit('/')
                .next()?;
            (!last.is_empty() && last.len() <= 80).then(|| last.to_owned())
        })
    })
    .unwrap_or_else(|| sha256[..16].to_owned());
    let mut tags: Vec<String> = sources.iter().filter_map(|source| host(source)).collect();
    tags.sort();
    tags.dedup();
    Some(SampleInfo {
        md5_hash: text(value, "md5").unwrap_or_default().to_ascii_lowercase(),
        sha1_hash: text(value, "sha1")
            .map(|hash| hash.to_ascii_lowercase())
            .filter(|hash| hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_default(),
        file_name: name,
        file_type: text(value, "f_type")
            .or_else(|| text(value, "type"))
            .or_else(|| file_type.map(str::to_owned))
            .unwrap_or_default()
            .to_ascii_lowercase(),
        file_size: field(value, "size")
            .and_then(|size| size.as_u64().or_else(|| size.as_str()?.parse().ok()))
            .unwrap_or_default(),
        first_seen: field(value, "added")
            .and_then(|time| time.as_i64().or_else(|| time.as_str()?.parse().ok()))
            .map(utc)
            .unwrap_or_default(),
        reporter: "MalShare".into(),
        tags,
        sha256_hash: sha256,
        ..SampleInfo::default()
    })
}

fn hash_sample(hash: &str, file_type: Option<&str>) -> Option<SampleInfo> {
    let hash = hash.trim().to_ascii_lowercase();
    if !matches!(hash.len(), 32 | 40 | 64) || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut sample = SampleInfo {
        file_type: file_type.unwrap_or("").to_ascii_lowercase(),
        file_name: hash[..8.min(hash.len())].to_owned(),
        reporter: "MalShare".into(),
        ..SampleInfo::default()
    };
    match hash.len() {
        32 => sample.md5_hash = hash,
        40 => sample.sha1_hash = hash,
        64 => {
            sample.file_name = hash[..16].to_owned();
            sample.sha256_hash = hash;
        }
        _ => return None,
    }
    // No hash was stored: do not return an empty identity.
    if sample.md5_hash.is_empty() && sample.sha1_hash.is_empty() && sample.sha256_hash.is_empty() {
        return None;
    }
    Some(sample)
}

/// A sample with no MD5, SHA-1, or SHA-256 is not a catalog row.
fn identified(sample: &SampleInfo) -> bool {
    !sample.md5_hash.is_empty() || !sample.sha1_hash.is_empty() || !sample.sha256_hash.is_empty()
}

fn remember(found: &mut Vec<SampleInfo>, sample: Option<SampleInfo>) {
    if let Some(sample) = sample.filter(identified) {
        found.push(sample);
    }
}

/// SHA-256, else SHA-1, else MD5. A row with none of them has no key.
fn sample_key(sample: &SampleInfo) -> Option<String> {
    let (kind, hash) = if !sample.sha256_hash.is_empty() {
        ("sha256", sample.sha256_hash.as_str())
    } else if !sample.sha1_hash.is_empty() {
        ("sha1", sample.sha1_hash.as_str())
    } else if !sample.md5_hash.is_empty() {
        ("md5", sample.md5_hash.as_str())
    } else {
        return None;
    };
    Some(format!("{kind}:{}", hash.to_ascii_lowercase()))
}

/// Keep the first row for each hash. A row whose hashes are all empty stays.
fn dedupe(samples: Vec<SampleInfo>) -> Vec<SampleInfo> {
    let mut seen = HashSet::new();
    let mut kept = Vec::with_capacity(samples.len());
    for sample in samples {
        if let Some(key) = sample_key(&sample)
            && !seen.insert(key)
        {
            continue;
        }
        kept.push(sample);
    }
    kept
}

/// MalShare `details` already takes an MD5, a SHA-1, or a SHA-256.
fn details_accepts(hash: &str) -> bool {
    matches!(hash.len(), 32 | 40 | 64) && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_len(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn infos(body: &[u8], file_type: Option<&str>, limit: u32) -> Result<Vec<SampleInfo>, String> {
    if let Some(refused) = refusal(body) {
        return Err(refused);
    }
    let mut found = Vec::new();
    for (row, value) in objects(body)?.into_iter().enumerate() {
        let before = found.len();
        match &value {
            Value::String(hash) => remember(&mut found, hash_sample(hash, file_type)),
            Value::Object(object) => {
                if let Some(Value::Array(items)) = object
                    .iter()
                    .find_map(|(key, value)| key.eq_ignore_ascii_case("hashes").then_some(value))
                {
                    for (index, item) in items.iter().enumerate() {
                        let sample = item
                            .as_str()
                            .and_then(|hash| hash_sample(hash, file_type))
                            .or_else(|| info(item, file_type));
                        if sample.is_none() {
                            return Err(format!(
                                "MalShare reply row {}, hash {}: invalid sample identity",
                                row + 1,
                                index + 1
                            ));
                        }
                        remember(&mut found, sample);
                    }
                    continue;
                }
                remember(&mut found, info(&value, file_type));
            }
            _ => {}
        }
        if found.len() == before {
            return Err(format!(
                "MalShare reply row {}: expected a sample with a valid hash; response was not treated as an empty catalog",
                row + 1
            ));
        }
    }
    let mut found = dedupe(found);
    found.truncate(limit as usize);
    Ok(found)
}

/// The samples of one file type MalShare received in the last 24 hours. Its
/// type names (`ELF`, `PE32`…) are matched without regard to case.
fn of_type(
    curl: &Path,
    key: &str,
    wanted: &str,
    limit: u32,
) -> Result<Option<(String, Vec<SampleInfo>)>, String> {
    let types = get(curl, key, &[("action", "gettypes")], MAX_REPLY)?;
    if let Some(refused) = refusal(&types) {
        return Err(refused);
    }
    let name = type_name(&types, wanted)?;
    let Some(name) = name else {
        return Ok(None);
    };
    let body = get(curl, key, &[("action", "type"), ("type", &name)], MAX_REPLY)?;
    Ok(Some((name.clone(), infos(&body, Some(&name), limit)?)))
}

fn type_name(body: &[u8], wanted: &str) -> Result<Option<String>, String> {
    let mut names = Vec::new();
    for value in objects(body)? {
        match value {
            Value::String(name) => names.push(name),
            Value::Object(types) if types.values().all(|v| v.as_u64().is_some()) => {
                names.extend(types.into_iter().map(|(name, _)| name));
            }
            _ => return Err("MalShare file-type reply has an unsupported format".into()),
        }
    }
    Ok(names
        .into_iter()
        .find(|name| name.eq_ignore_ascii_case(wanted)))
}

/// One search box, as for MalwareBazaar: empty lists the newest ELF samples
/// (what the guests can run; MalShare's lists cover its last day); a hash
/// looks that sample up; a file type (`elf`, `pe32`) lists that type's
/// newest; anything else is searched in MalShare's hashes, sources and file
/// names.
pub fn find(
    curl: &Path,
    key: &str,
    text: &str,
    limit: u32,
) -> Result<(String, Vec<SampleInfo>), String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(match of_type(curl, key, "elf", limit)? {
            Some((_, found)) => ("Last 24 hours, ELF samples (upstream order)".into(), found),
            None => ("No new ELF samples".into(), Vec::new()),
        });
    }
    if details_accepts(text) {
        let body = get(
            curl,
            key,
            &[("action", "details"), ("hash", text)],
            MAX_REPLY,
        )?;
        return Ok((format!("Hash {text}"), infos(&body, None, limit)?));
    }
    if !text.contains(char::is_whitespace)
        && text.len() <= 16
        && let Some((name, found)) = of_type(curl, key, text, limit)?
    {
        return Ok((format!("Last 24 hours, file type {name}"), found));
    }
    let body = get(
        curl,
        key,
        &[("action", "search"), ("query", text)],
        MAX_REPLY,
    )?;
    Ok((format!("Search {text}"), infos(&body, None, limit)?))
}

/// The newest samples of every type: MalShare lists hashes only, so their
/// type and name are unknown until a search or a download.
pub fn newest_all(curl: &Path, key: &str, limit: u32) -> Result<(String, Vec<SampleInfo>), String> {
    let body = get(curl, key, &[("action", "getlist")], MAX_REPLY)?;
    Ok((
        "Last 24 hours, all types (upstream order)".into(),
        infos(&body, None, limit)?,
    ))
}

/// Official dated SHA-256 lists, one small file per day. These are public
/// metadata, not sample downloads. Days are `YYYY-MM-DD`. The newest 1000
/// unique hashes are returned by descending archive day. The upstream list
/// has no within-day timestamps; within-day ordering is unknown.
pub fn dated_hashes(
    curl: &Path,
    cache: &Path,
    start: &str,
    end: &str,
    limit: usize,
) -> Result<(String, Vec<SampleInfo>), String> {
    let result = dated_catalog(
        curl,
        cache,
        Some((start, end)),
        false,
        limit,
        &AtomicBool::new(false),
        |_| {},
    )?;
    Ok((result.listing(), result.samples))
}

/// Coverage of a bounded metadata-only job. Successful days are resumable
/// checkpoints; failed days never become empty successful cache entries.
pub struct DatedCatalog {
    pub samples: Vec<SampleInfo>,
    pub requested_days: usize,
    pub scanned_days: usize,
    pub cached_days: usize,
    pub failed_days: Vec<String>,
    pub cancelled: bool,
    pub range: String,
    pub limited: bool,
}
impl DatedCatalog {
    /// Describe archive-day ordering and exact scan coverage.
    pub fn listing(&self) -> String {
        format!(
            "{}{} SHA-256 rows; {}; {} of {} days scanned ({} cached), {} unavailable{}; archive-day order, within-day order unknown",
            self.samples.len(),
            if self.limited {
                " (newest-day limit)"
            } else {
                ""
            },
            self.range,
            self.scanned_days,
            self.requested_days,
            self.cached_days,
            self.failed_days.len(),
            if self.cancelled {
                "; cancelled, retry resumes cache"
            } else {
                ""
            }
        )
    }
}

/// Metadata job status without sample contents.
#[derive(Clone, Debug)]
pub struct CatalogProgress {
    pub day: String,
    pub done_days: usize,
    pub total_days: usize,
    pub cached_days: usize,
    pub failed_days: usize,
}

/// Read 1–366 inclusive calendar days, or all cached metadata when range is
/// absent. Offline never invokes curl. Retain at most 1000 rows while validating
/// every selected day. Cancellation returns partial rows and durable checkpoints.
pub fn dated_catalog(
    curl: &Path,
    cache: &Path,
    range: Option<(&str, &str)>,
    offline: bool,
    limit: usize,
    cancel: &AtomicBool,
    mut progress: impl FnMut(CatalogProgress),
) -> Result<DatedCatalog, String> {
    if !(1..=1000).contains(&limit) {
        return Err("metadata limit is 1 through 1000".into());
    }
    let mut days = if let Some((start, end)) = range {
        let (start, end) = (parse_day(start)?, parse_day(end)?);
        if end < start {
            return Err("the end date is before the start date".into());
        }
        if end - start >= 366 {
            return Err("range is at most 366 inclusive days".into());
        }
        (start..=end).collect::<Vec<_>>()
    } else {
        cached_calendar_days(cache)?
    };
    days.sort_unstable_by(|a, b| b.cmp(a));
    let range_label = match (days.last(), days.first()) {
        (Some(first), Some(last)) => format!(
            "{} through {}{}",
            format_day(*first),
            format_day(*last),
            if range.is_none() {
                " (all cached metadata; not all upstream history)"
            } else {
                ""
            }
        ),
        _ => "all cached metadata (no cached days)".into(),
    };
    let mut result = DatedCatalog {
        samples: Vec::new(),
        requested_days: days.len(),
        scanned_days: 0,
        cached_days: 0,
        failed_days: Vec::new(),
        cancelled: false,
        range: range_label,
        limited: false,
    };
    let mut selected = HashSet::new();
    for day in days {
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        let label = format_day(day);
        let cached = cache.join(format!("{label}.sha256.txt"));
        let cached_body = read_daily_cache(&cached);
        let from_cache = cached_body.is_ok();
        let body = match cached_body {
            Ok(body) => Ok(body),
            Err(error) if offline || range.is_none() => Err(error),
            Err(_) => {
                let url = format!(
                    "https://malshare.com/daily/{label}/malshare_fileList.{label}.sha256.txt"
                );
                fetch_public(curl, &url, DAILY_SIZE, cancel).and_then(|body| {
                    validate_daily(&body)?;
                    publish_daily(cache, &cached, &body)?;
                    Ok(body)
                })
            }
        };
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        let backoff = body
            .as_ref()
            .err()
            .is_some_and(|error| error.contains("backoff"));
        match body {
            Ok(body) => {
                result.scanned_days += 1;
                result.cached_days += usize::from(from_cache);
                let text = std::str::from_utf8(&body).map_err(|_| "dated list is not UTF-8")?;
                let mut samples = hashes_from_daily(&label, text);
                samples.sort_unstable_by(|a, b| a.sha256_hash.cmp(&b.sha256_hash));
                for sample in samples {
                    if selected.contains(&sample.sha256_hash) {
                        continue;
                    }
                    if result.samples.len() < limit {
                        selected.insert(sample.sha256_hash.clone());
                        result.samples.push(sample);
                    } else {
                        result.limited = true;
                    }
                }
            }
            Err(error) => result.failed_days.push(format!("{label}: {error}")),
        }
        progress(CatalogProgress {
            day: label,
            done_days: result.scanned_days + result.failed_days.len(),
            total_days: result.requested_days,
            cached_days: result.cached_days,
            failed_days: result.failed_days.len(),
        });
        if backoff {
            break;
        }
    }
    Ok(result)
}
const DAILY_SIZE: u64 = 1024 * 1024;
const CACHED_DAY_BOUND: usize = 8192;

/// UTC source timestamp in the catalog's YYYY-MM-DD HH:MM:SS format.
/// A date-only archive label has no exact timestamp and returns None.
pub fn catalog_timestamp_ms(text: &str) -> Option<u64> {
    if text.len() != 19 || text.as_bytes().get(10) != Some(&b' ') {
        return None;
    }
    let day = parse_day(text.get(..10)?).ok()?;
    let time = text.get(11..)?.split(':').collect::<Vec<_>>();
    if time.len() != 3
        || time
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let (hour, minute, second) = (
        time[0].parse::<i64>().ok()?,
        time[1].parse::<i64>().ok()?,
        time[2].parse::<i64>().ok()?,
    );
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    u64::try_from(
        day.checked_mul(86_400)?
            .checked_add(hour * 3600 + minute * 60 + second)?,
    )
    .ok()?
    .checked_mul(1000)
}

/// UTC archive-calendar preset, including today.
pub fn recent_date_range(day_count: u32) -> Result<(String, String), String> {
    if !(1..=366).contains(&day_count) {
        return Err("date preset is 1 through 366 days".into());
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let today = i64::try_from(seconds / 86_400).map_err(|_| "host date is out of range")?;
    Ok((
        format_day(today - i64::from(day_count) + 1),
        format_day(today),
    ))
}
fn cached_calendar_days(cache: &Path) -> Result<Vec<i64>, String> {
    if !cache.exists() {
        return Ok(Vec::new());
    }
    let mut days = Vec::new();
    for entry in std::fs::read_dir(cache).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".sha256.txt"))
        else {
            continue;
        };
        let Ok(day) = parse_day(name) else { continue };
        if days.len() == CACHED_DAY_BOUND {
            return Err("more than 8192 cached days; select a range".into());
        }
        days.push(day);
    }
    Ok(days)
}
fn validate_daily(body: &[u8]) -> Result<(), String> {
    if body.len() as u64 > DAILY_SIZE {
        return Err("dated list is larger than 1 MiB".into());
    }
    let text = std::str::from_utf8(body).map_err(|_| "dated list is not UTF-8")?;
    if text
        .lines()
        .any(|line| !line.trim().is_empty() && !hex_len(line.trim(), 64))
    {
        return Err("dated list contains an invalid SHA-256 line (not cached)".into());
    }
    Ok(())
}
fn read_daily_cache(path: &Path) -> Result<Vec<u8>, String> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|error| format!("cache unavailable: {error}"))?;
    if !meta.file_type().is_file() || meta.len() > DAILY_SIZE {
        return Err("cache is not a regular bounded metadata file".into());
    }
    let mut body = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(DAILY_SIZE + 1)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    validate_daily(&body)?;
    Ok(body)
}
fn publish_daily(cache: &Path, path: &Path, body: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(cache).map_err(|error| error.to_string())?;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temp = cache.join(format!(
        ".daily-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(body).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::rename(&temp, path).map_err(|error| error.to_string())?;
        std::fs::File::open(cache)
            .and_then(|file| file.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
fn fetch_public(curl: &Path, url: &str, max: u64, cancel: &AtomicBool) -> Result<Vec<u8>, String> {
    crate::dependencies::require_tool(curl, "curl")?;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let mut child = crate::http_fetch::command(
        curl,
        &crate::http_fetch::Options {
            connect_timeout: 10,
            ..crate::http_fetch::Options::new(30, 1_048_576)
        },
    )
    .args(["--write-out", "\n%{http_code}", url])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|error| format!("curl: {error}"))?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("curl stdout unavailable".into());
    };
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut body = Vec::new();
        let result = stdout
            .take(max + 5)
            .read_to_end(&mut body)
            .map(|_| body)
            .map_err(|error| error.to_string());
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(35);
    let outcome = loop {
        if cancel.load(Ordering::Relaxed) {
            break Err("cancelled".into());
        }
        if Instant::now() >= deadline {
            break Err("dated list request timed out".into());
        }
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(result) => break result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break Err("metadata reader stopped".into());
            }
        }
    };
    if outcome
        .as_ref()
        .map_or(true, |body| body.len() as u64 > max + 4)
    {
        let _ = child.kill();
    }
    let done = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline => {
                let _ = child.kill();
                break child.wait().map_err(|error| error.to_string());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(error.to_string());
            }
        }
    };
    let _ = reader.join();
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let mut body = outcome?;
    let status_start = body.iter().rposition(|byte| *byte == b'\n');
    let http = status_start
        .and_then(|at| std::str::from_utf8(&body[at + 1..]).ok())
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("metadata request did not report HTTP status")?;
    body.truncate(status_start.ok_or("metadata HTTP status missing")?);
    if body.len() as u64 > max {
        return Err("dated list is larger than 1 MiB".into());
    }
    let status = done?;
    if !status.success() {
        if http == 429 || http == 503 {
            return Err(format!(
                "HTTP {http}: rate limit/service backoff; retry resumes cached days"
            ));
        }
        if http == 404 {
            return Err("HTTP 404: this archive day is unavailable (not cached as empty)".into());
        }
        return Err(match status.code() {
            Some(22) => {
                "upstream HTTP error (missing day, rate limit or refusal); retry later".into()
            }
            Some(28) => "upstream metadata timeout; retry resumes cached days".into(),
            code => format!("metadata request failed ({code:?}); retry resumes cached days"),
        });
    }
    if !(200..300).contains(&http) {
        return Err(format!("metadata HTTP {http}; reply not cached"));
    }
    Ok(body)
}

pub(crate) fn hashes_from_daily(day: &str, text: &str) -> Vec<SampleInfo> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let hash = line.trim().to_ascii_lowercase();
        if hash.len() == 64
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            && seen.insert(hash.clone())
        {
            found.push(SampleInfo {
                sha256_hash: hash,
                file_type: "unknown".into(),
                reporter: "MalShare".into(),
                // Archive date is a date-only observation, not first-seen time.
                tags: vec![format!("archive-date:{day}")],
                ..SampleInfo::default()
            });
        }
    }
    found
}

fn parse_day(text: &str) -> Result<i64, String> {
    let text = text.trim();
    let parts: Vec<_> = text.split('-').collect();
    if text.len() != 10
        || parts.len() != 3
        || parts[0].len() != 4
        || parts[1].len() != 2
        || parts[2].len() != 2
        || !parts
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("dates are YYYY-MM-DD".into());
    }
    let year: i32 = parts[0]
        .parse()
        .map_err(|_| "dates are YYYY-MM-DD".to_string())?;
    let month: u32 = parts[1]
        .parse()
        .map_err(|_| "dates are YYYY-MM-DD".to_string())?;
    let day: u32 = parts[2]
        .parse()
        .map_err(|_| "dates are YYYY-MM-DD".to_string())?;
    days_from_civil(year, month, day).ok_or_else(|| "dates are YYYY-MM-DD".into())
}

fn format_day(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=9999).contains(&year) || !(1..=month_days).contains(&day) {
        return None;
    }
    let year = year as i64 - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe as i64 - 719468)
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month as u32, day as u32)
}

/// Download one sample, check it and keep it encrypted with its record.
pub fn download(
    curl: &Path,
    key: &str,
    data_dir: &Path,
    info: &SampleInfo,
) -> Result<StoredSample, String> {
    use sha2::{Digest, Sha256};
    let mut record = info.clone();
    if !hex_len(&record.sha256_hash, 64) {
        // MD5 keeps the details lookup. SHA-1 uses that same lookup only
        // because it already accepts an arbitrary hash; otherwise stop.
        let lookup = if hex_len(&record.md5_hash, 32) {
            record.md5_hash.clone()
        } else if hex_len(&record.sha1_hash, 40) && details_accepts(&record.sha1_hash) {
            record.sha1_hash.clone()
        } else {
            return Err("MalShare download needs a resolved SHA-256".into());
        };
        let sha1_only = !hex_len(&record.md5_hash, 32);
        let body = get(
            curl,
            key,
            &[("action", "details"), ("hash", &lookup)],
            MAX_REPLY,
        )?;
        let hinted = (!record.file_type.is_empty()).then_some(record.file_type.as_str());
        let Some(resolved) = infos(&body, hinted, 1)?.into_iter().next() else {
            return Err(if sha1_only {
                "MalShare download needs a resolved SHA-256".into()
            } else {
                "MalShare has no SHA-256 for this hash".into()
            });
        };
        let sha1_placeholder = record.md5_hash.is_empty()
            && record.sha1_hash.len() >= 8
            && record.file_name == record.sha1_hash[..8];
        if record.file_name.is_empty() || record.file_name == record.md5_hash || sha1_placeholder {
            record.file_name = resolved.file_name;
        }
        if record.file_type.is_empty() {
            record.file_type = resolved.file_type;
        }
        if record.md5_hash.is_empty() {
            record.md5_hash = resolved.md5_hash;
        }
        if record.sha1_hash.is_empty() {
            record.sha1_hash = resolved.sha1_hash;
        }
        // Only a SHA-256 the details reply actually carried. Never invent one.
        if hex_len(&resolved.sha256_hash, 64) {
            record.sha256_hash = resolved.sha256_hash;
        }
        if !hex_len(&record.sha256_hash, 64) {
            return Err(if sha1_only {
                "MalShare download needs a resolved SHA-256".into()
            } else {
                "MalShare has no SHA-256 for this hash".into()
            });
        }
    }
    let info = &record;
    let hash = info.sha256_hash.to_ascii_lowercase();
    if hash.is_empty() || !hex_len(&hash, 64) {
        return Err("MalShare download needs a resolved SHA-256".into());
    }
    let mut bytes = get(
        curl,
        key,
        &[("action", "getfile"), ("hash", &hash)],
        samples::MAX_SAMPLE,
    )?;
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest != hash {
        // Not the sample: most likely a refusal in words.
        let reason = (bytes.len() < 4096)
            .then(|| refusal(&bytes))
            .flatten()
            .unwrap_or_else(|| "MalShare sent a file that does not match its SHA-256".into());
        bytes.fill(0);
        return Err(reason.replace(key.trim(), "[redacted]"));
    }
    let stored = samples::store_bytes(data_dir, info, &bytes, "MalShare");
    bytes.fill(0);
    stored
}

#[cfg(test)]
mod reply_tests;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancel_reaps_metadata_process_promptly_and_rate_limit_preserves_resume() {
        use super::reply_tests::{retry_busy, script};
        let dir = TestDir::new();
        let pid_file = dir.path().join("pid");
        let curl = script(
            dir.path(),
            "curl-sleep",
            &format!(
                "#!/bin/sh\necho $$ > '{}'\nexec /bin/sleep 30\n",
                pid_file.display()
            ),
        );
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let worker_cancel = std::sync::Arc::clone(&cancel);
        let signal = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            worker_cancel.store(true, Ordering::Relaxed);
        });
        assert_eq!(
            retry_busy(|| fetch_public(
                &curl,
                "https://malshare.com/daily/test",
                DAILY_SIZE,
                &cancel
            )),
            Err("cancelled".into())
        );
        signal.join().unwrap();
        // How fast it happened does not matter, only that curl is gone and was
        // waited for: its process table entry no longer exists.
        if let Ok(pid) = std::fs::read_to_string(&pid_file) {
            assert!(!Path::new(&format!("/proc/{}", pid.trim())).exists());
        }
        let curl = script(
            dir.path(),
            "curl-429",
            "#!/bin/sh\nprintf '\\n429'\nexit 22\n",
        );
        let cache = dir.path().join("cache");
        let result = retry_busy(|| {
            let result = dated_catalog(
                &curl,
                &cache,
                Some(("2026-10-06", "2026-10-12")),
                false,
                1000,
                &AtomicBool::new(false),
                |_| {},
            )?;
            match result.failed_days.first() {
                Some(day) if day.contains("Text file busy") => Err(day.clone()),
                _ => Ok(result),
            }
        })
        .unwrap();
        assert_eq!(result.failed_days.len(), 1);
        assert_eq!(result.requested_days, 7);
        assert_eq!(result.scanned_days, 0);
        assert!(result.failed_days[0].contains("429"));
        assert!(!cache.exists());
    }
    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "antinomie-malshare-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn calendar_dates_reject_rollover_and_noncanonical_input() {
        assert_eq!(catalog_timestamp_ms("1970-01-01 00:00:00"), Some(0));
        assert_eq!(
            catalog_timestamp_ms("2000-02-29 00:00:00"),
            Some(951_782_400_000)
        );
        assert_eq!(catalog_timestamp_ms("2026-02-31 00:00:00"), None);
        assert_eq!(catalog_timestamp_ms("2026-10-12"), None);
        assert_eq!(catalog_timestamp_ms("2026-10-12 24:00:00"), None);
        for invalid in [
            "2026-02-29",
            "2026-02-31",
            "1900-02-29",
            "2026-04-31",
            "2026-0-10",
            "2026-01-00",
            "0000-01-01",
            "2026-1-01",
            "+2026-01-01",
            "2026-01-01/",
        ] {
            assert!(parse_day(invalid).is_err(), "{invalid}");
        }
        for valid in [
            "2000-02-29",
            "2024-02-29",
            "2026-12-31",
            "0001-01-01",
            "9999-12-31",
        ] {
            assert_eq!(format_day(parse_day(valid).unwrap()), valid);
        }
    }

    #[test]
    fn cached_range_covers_all_days_deduplicates_and_caps_newest_day_rows() {
        let dir = TestDir::new();
        let mut hashes = String::new();
        for id in 0..1100 {
            hashes.push_str(&format!("{id:064x}\n"));
        }
        std::fs::write(dir.path().join("2026-10-12.sha256.txt"), hashes).unwrap();
        std::fs::write(
            dir.path().join("2026-10-11.sha256.txt"),
            format!("{:064x}\n{:064x}\n", 0, 2000),
        )
        .unwrap();
        let mut statuses = Vec::new();
        let result = dated_catalog(
            Path::new("/tool-does-not-exist"),
            dir.path(),
            Some(("2026-10-10", "2026-10-12")),
            true,
            1000,
            &AtomicBool::new(false),
            |status| statuses.push(status),
        )
        .unwrap();
        assert_eq!(result.samples.len(), 1000);
        assert!(result.limited);
        assert_eq!(result.scanned_days, 2);
        assert_eq!(result.requested_days, 3);
        assert_eq!(result.failed_days.len(), 1);
        assert_eq!(statuses.last().unwrap().done_days, 3);
        assert!(
            result
                .samples
                .iter()
                .all(|sample| sample.tags == ["archive-date:2026-10-12"])
        );
        assert_eq!(result.samples[0].sha256_hash, format!("{:064x}", 0));
        assert!(
            !result
                .samples
                .iter()
                .any(|sample| sample.sha256_hash == format!("{:064x}", 2000))
        );
    }

    #[test]
    fn cancellation_preserves_checkpoints_and_offline_all_cached_resumes() {
        let dir = TestDir::new();
        let hash = "a".repeat(64);
        publish_daily(
            dir.path(),
            &dir.path().join("2026-10-12.sha256.txt"),
            hash.as_bytes(),
        )
        .unwrap();
        publish_daily(
            dir.path(),
            &dir.path().join("2026-10-11.sha256.txt"),
            hash.as_bytes(),
        )
        .unwrap();
        let cancel = AtomicBool::new(false);
        let partial = dated_catalog(
            Path::new("no-curl"),
            dir.path(),
            Some(("2026-10-11", "2026-10-12")),
            true,
            1000,
            &cancel,
            |_| cancel.store(true, Ordering::Relaxed),
        )
        .unwrap();
        assert!(partial.cancelled);
        assert_eq!(partial.scanned_days, 1);
        let result = dated_catalog(
            Path::new("no-curl"),
            dir.path(),
            None,
            true,
            1000,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert_eq!(result.scanned_days, 2);
        assert_eq!(result.cached_days, 2);
        assert_eq!(result.samples.len(), 1);
        assert!(!result.cancelled);
        assert!(result.range.contains("all cached metadata"));
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn corrupt_cache_is_not_a_successful_empty_day() {
        let dir = TestDir::new();
        std::fs::write(
            dir.path().join("2026-10-12.sha256.txt"),
            b"<html>rate limit</html>",
        )
        .unwrap();
        let result = dated_catalog(
            Path::new("no-curl"),
            dir.path(),
            None,
            true,
            1000,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert_eq!(result.scanned_days, 0);
        assert_eq!(result.failed_days.len(), 1);
        assert!(validate_daily(&[0xff]).is_err());
        assert!(
            dated_catalog(
                Path::new("no-curl"),
                dir.path(),
                Some(("2026-01-01", "2027-01-02")),
                true,
                1,
                &AtomicBool::new(false),
                |_| {}
            )
            .is_err()
        );
        assert!(
            dated_hashes(
                Path::new("no-curl"),
                dir.path(),
                "2026-10-12",
                "2026-10-12",
                0
            )
            .is_err()
        );
    }

    #[test]
    fn dated_hash_lines_keep_unknown_type_and_drop_duplicates() {
        let day = "2026-10-12";
        let hash = "ab".repeat(32);
        let text = format!("{hash}\n{hash}\nnot-a-hash\n{}\n", "cd".repeat(32));
        let found = hashes_from_daily(day, &text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].file_type, "unknown");
        assert!(found[0].first_seen.is_empty());
        assert_eq!(found[0].reporter, "MalShare");
        assert_eq!(found[0].tags, [format!("archive-date:{day}")]);
        assert_eq!(
            parse_day("2026-10-12").unwrap() - parse_day("2026-10-01").unwrap(),
            11
        );
    }

    #[test]
    fn replies_are_read_in_any_shape() {
        let sha = "a".repeat(64);
        // details: one object with upper-case names.
        let details = format!(
            r#"{{"MD5":"{}","SHA1":"{}","SHA256":"{sha}","SSDEEP":"3:x:y","F_TYPE":"ELF","SOURCES":["http://203.0.113.9:8080/bins/x86_64.bin"]}}"#,
            "b".repeat(32),
            "c".repeat(40)
        );
        let found = infos(details.as_bytes(), None, 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file_type, "elf");
        assert_eq!(found[0].file_name, "x86_64.bin");
        assert_eq!(found[0].tags, ["203.0.113.9"]);
        assert_eq!(found[0].reporter, "MalShare");
        // search: objects one after another, lower-case names, a timestamp.
        let search = format!(
            r#"{{"md5":"{m}","sha256":"{sha}","type":"PE32","added":1760169600,"source":"https://example.org/a"}}
               {{"md5":"{m}","sha256":"{other}","type":"ELF","added":0}}"#,
            m = "d".repeat(32),
            other = "e".repeat(64)
        );
        let found = infos(search.as_bytes(), None, 10).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].first_seen, "2025-10-11 08:00:00");
        assert_eq!(found[1].first_seen, "1970-01-01 00:00:00");
        // type: an array of hashes, the type taken from the request.
        let listed = format!(
            r#"[{{"md5":"{}","sha1":"{}","sha256":"{sha}"}}]"#,
            "1".repeat(32),
            "2".repeat(40)
        );
        let found = infos(listed.as_bytes(), Some("ELF"), 10).unwrap();
        assert_eq!(
            (found[0].file_type.as_str(), found[0].file_name.len()),
            ("elf", 16)
        );
        // A refusal in words, and entries without a usable SHA-256.
        assert_eq!(
            infos(
                b"User specified in `api_key` GET variable does not exist",
                None,
                10
            ),
            Err("MalShare refused the API key".into())
        );
        assert_eq!(
            infos(
                b"Over Request Limit.  Please wait until tomorrow\n",
                None,
                10
            ),
            Err("MalShare: Over Request Limit.  Please wait until tomorrow".into())
        );
        assert!(infos(br#"[{"sha256":"zz"}]"#, None, 10).is_err());
        let hashes = format!(r#"["{}","{}"]"#, "f".repeat(32), "ab".repeat(32));
        let found = infos(hashes.as_bytes(), Some("ELF"), 10).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].md5_hash.len(), 32);
        assert!(found[0].sha256_hash.is_empty());
        assert_eq!(found[0].file_type, "elf");
        assert_eq!(found[1].sha256_hash.len(), 64);
        let wrapped = format!(r#"{{"hashes":["{}"]}}"#, "9".repeat(32));
        assert_eq!(infos(wrapped.as_bytes(), None, 10).unwrap().len(), 1);
        let types = br#"["ELF","PE32"]"#;
        let names: Vec<String> = objects(types)
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
        assert_eq!(names, ["ELF", "PE32"]);
    }

    #[test]
    fn urls_and_dates_are_written_safely() {
        assert_eq!(encode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(host("hxxp://Example.ORG:80/x"), Some("example.org".into()));
        assert_eq!(host("plain-name"), Some("plain-name".into()));
    }

    #[test]
    fn duplicate_hashes_keep_the_first_row() {
        let sha = "a".repeat(64);
        let other = "b".repeat(64);
        let md5 = "c".repeat(32);
        let sha1 = "d".repeat(40);
        let body = format!(
            r#"[
                {{"sha256":"{sha}","md5":"{md5}","filenames":["first"]}},
                {{"sha256":"{sha}","md5":"{}","filenames":["second"]}},
                {{"sha256":"{other}","filenames":["third"]}},
                "{md5}",
                "{sha1}",
                "{sha1}"
            ]"#,
            "e".repeat(32)
        );
        let found = infos(body.as_bytes(), None, 10).unwrap();
        assert_eq!(found.len(), 4);
        assert_eq!(found[0].file_name, "first");
        assert_eq!(found[0].sha256_hash, sha);
        assert_eq!(found[1].sha256_hash, other);
        assert_eq!(found[2].md5_hash, md5);
        assert!(found[2].sha256_hash.is_empty());
        assert_eq!(found[3].sha1_hash, sha1);
        assert!(found[3].sha256_hash.is_empty());
        let empty = SampleInfo::default();
        assert_eq!(dedupe(vec![empty.clone(), empty]).len(), 2);
    }

    #[test]
    fn a_sha1_hash_is_stored_on_the_sample() {
        let hash = "a".repeat(40);
        let sample = hash_sample(&hash, None).expect("40 hex chars");
        assert_eq!(sample.sha1_hash, hash);
        assert!(sample.sha256_hash.is_empty());
        assert!(sample.md5_hash.is_empty());
        assert_eq!(sample.file_name, hash[..8]);
        assert!(sample.file_type.is_empty());
    }
}
