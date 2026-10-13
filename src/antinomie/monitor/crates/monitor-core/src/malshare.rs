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
    process::{Command, Stdio},
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
    let mut child = Command::new(curl)
        .args(["-sS", "--proto", "=https", "--max-time", "300", "-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("curl: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        // curl's config syntax: the value quoted, with \ and " escaped.
        let _ = writeln!(
            stdin,
            "url = \"{}\"",
            url.replace('\\', "\\\\").replace('"', "\\\"")
        );
    }
    let mut body = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout
            .take(max + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("curl: {e}"))?;
    }
    if body.len() as u64 > max {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("MalShare's reply is larger than {} MiB", max >> 20));
    }
    let done = child.wait_with_output().map_err(|e| format!("curl: {e}"))?;
    if !done.status.success() {
        let message = String::from_utf8_lossy(&done.stderr);
        return Err(format!(
            "MalShare: {}",
            message.lines().last().unwrap_or("request failed").trim()
        ));
    }
    Ok(body)
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
        first_seen: field(value, "added")
            .and_then(Value::as_i64)
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
    for value in objects(body)? {
        match &value {
            Value::String(hash) => remember(&mut found, hash_sample(hash, file_type)),
            Value::Object(object) => {
                if let Some(Value::Array(items)) = object
                    .iter()
                    .find_map(|(key, value)| key.eq_ignore_ascii_case("hashes").then_some(value))
                {
                    for item in items {
                        if let Some(hash) = item.as_str() {
                            remember(&mut found, hash_sample(hash, file_type));
                        }
                    }
                    continue;
                }
                remember(&mut found, info(&value, file_type));
            }
            _ => {}
        }
        if found.len() >= limit as usize {
            break;
        }
    }
    found.truncate(limit as usize);
    Ok(dedupe(found))
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
    let name = objects(&types)?
        .iter()
        .flat_map(|value| match value {
            Value::String(name) => vec![name.clone()],
            Value::Object(types) => types.keys().cloned().collect(),
            _ => Vec::new(),
        })
        .find(|name| name.eq_ignore_ascii_case(wanted));
    let Some(name) = name else {
        return Ok(None);
    };
    let body = get(curl, key, &[("action", "type"), ("type", &name)], MAX_REPLY)?;
    Ok(Some((name.clone(), infos(&body, Some(&name), limit)?)))
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
            Some((_, found)) => ("Newest ELF samples, last 24 hours".into(), found),
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
        return Ok((format!("File type {name}"), found));
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
        "Newest uploads, all types".into(),
        infos(&body, None, limit)?,
    ))
}

/// Official dated SHA-256 lists, one small file per day. These are public
/// metadata, not sample downloads. Days are `YYYY-MM-DD`. The newest 1000
/// unique hashes in the range are returned, newest day first.
pub fn dated_hashes(
    curl: &Path,
    cache: &Path,
    start: &str,
    end: &str,
    limit: usize,
) -> Result<(String, Vec<SampleInfo>), String> {
    let start = parse_day(start)?;
    let end = parse_day(end)?;
    if end < start {
        return Err("the end date is before the start date".into());
    }
    if end - start > 31 {
        return Err("a MalShare date range is at most 31 days".into());
    }
    fs_create(cache)?;
    let mut merged = Vec::new();
    let mut seen = HashSet::new();
    let mut day = end;
    loop {
        let label = format_day(day);
        let cached = cache.join(format!("{label}.sha256.txt"));
        let text = if cached.is_file() {
            std::fs::read_to_string(&cached).map_err(|error| error.to_string())?
        } else {
            let url = format!(
                "https://malshare.com/daily/{label}/malshare_fileList.{label}.sha256.txt"
            );
            let body = fetch_public(curl, &url, 1024 * 1024)?;
            let text = String::from_utf8_lossy(&body).into_owned();
            std::fs::write(&cached, &text).map_err(|error| error.to_string())?;
            text
        };
        for info in hashes_from_daily(&label, &text) {
            if seen.insert(info.sha256_hash.clone()) {
                merged.push(info);
            }
            if merged.len() == limit {
                break;
            }
        }
        if merged.len() == limit || day == start {
            break;
        }
        day -= 1;
    }
    Ok((
        format!(
            "Newest {} dated SHA-256 hashes, {} through {} (not the last-24-hours list)",
            merged.len(),
            format_day(start),
            format_day(end)
        ),
        merged,
    ))
}

fn fs_create(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|error| error.to_string())
}

fn fetch_public(curl: &Path, url: &str, max: u64) -> Result<Vec<u8>, String> {
    crate::dependencies::require_tool(curl, "curl")?;
    let mut child = Command::new(curl)
        .args(["-fsS", "--proto", "=https", "--max-time", "30", url])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("curl: {error}"))?;
    let mut body = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout
            .take(max + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("curl: {error}"))?;
    }
    let done = child.wait_with_output().map_err(|error| format!("curl: {error}"))?;
    if body.len() as u64 > max {
        return Err("MalShare dated list is larger than 1 MiB".into());
    }
    if !done.status.success() {
        let error = String::from_utf8_lossy(&done.stderr);
        return Err(format!(
            "MalShare dated list HTTP failed: {}",
            error.trim()
        ));
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
                first_seen: day.to_owned(),
                ..SampleInfo::default()
            });
        }
    }
    found
}

fn parse_day(text: &str) -> Result<i64, String> {
    let parts: Vec<_> = text.trim().split('-').collect();
    if parts.len() != 3 {
        return Err("dates are YYYY-MM-DD".into());
    }
    let year: i32 = parts[0].parse().map_err(|_| "dates are YYYY-MM-DD".to_string())?;
    let month: u32 = parts[1].parse().map_err(|_| "dates are YYYY-MM-DD".to_string())?;
    let day: u32 = parts[2].parse().map_err(|_| "dates are YYYY-MM-DD".to_string())?;
    days_from_civil(year, month, day).ok_or_else(|| "dates are YYYY-MM-DD".into())
}

fn format_day(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
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
        return Err(reason);
    }
    let stored = samples::store_bytes(data_dir, info, &bytes, "MalShare");
    bytes.fill(0);
    stored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dated_hash_lines_keep_unknown_type_and_drop_duplicates() {
        let day = "2026-10-12";
        let hash = "ab".repeat(32);
        let text = format!("{hash}\n{hash}\nnot-a-hash\n{}\n", "cd".repeat(32));
        let found = hashes_from_daily(day, &text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].file_type, "unknown");
        assert_eq!(found[0].first_seen, day);
        assert_eq!(parse_day("2026-10-12").unwrap() - parse_day("2026-10-01").unwrap(), 11);
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
        assert!(infos(br#"[{"sha256":"zz"}]"#, None, 10).unwrap().is_empty());
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
