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

fn infos(body: &[u8], file_type: Option<&str>, limit: u32) -> Result<Vec<SampleInfo>, String> {
    if let Some(refused) = refusal(body) {
        return Err(refused);
    }
    Ok(objects(body)?
        .iter()
        .filter_map(|value| info(value, file_type))
        .take(limit as usize)
        .collect())
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
        .filter_map(Value::as_object)
        .flat_map(|types| types.keys().cloned().collect::<Vec<_>>())
        .find(|name| name.eq_ignore_ascii_case(wanted));
    let Some(name) = name else {
        return Ok(None);
    };
    let body = get(curl, key, &[("action", "type"), ("type", &name)], MAX_REPLY)?;
    Ok(Some((name.clone(), infos(&body, Some(&name), limit)?)))
}

/// One search box, as for MalwareBazaar: empty lists the ELF samples of the
/// last 24 hours (what the guests can run); a hash looks that sample up; a
/// file type (`elf`, `pe32`) lists that type's last 24 hours; anything else
/// is searched in MalShare's hashes, sources and file names.
pub fn find(
    curl: &Path,
    key: &str,
    text: &str,
    limit: u32,
) -> Result<(String, Vec<SampleInfo>), String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(match of_type(curl, key, "elf", limit)? {
            Some((_, found)) => ("Newest ELF samples (24 hours)".into(), found),
            None => ("No ELF samples in the last 24 hours".into(), Vec::new()),
        });
    }
    if matches!(text.len(), 32 | 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit()) {
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
        return Ok((format!("File type {name} (24 hours)"), found));
    }
    let body = get(
        curl,
        key,
        &[("action", "search"), ("query", text)],
        MAX_REPLY,
    )?;
    Ok((format!("Search {text}"), infos(&body, None, limit)?))
}

/// Download one sample, check it and keep it encrypted with its record.
pub fn download(
    curl: &Path,
    key: &str,
    data_dir: &Path,
    info: &SampleInfo,
) -> Result<StoredSample, String> {
    use sha2::{Digest, Sha256};
    let hash = info.sha256_hash.to_ascii_lowercase();
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
    }

    #[test]
    fn urls_and_dates_are_written_safely() {
        assert_eq!(encode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(host("hxxp://Example.ORG:80/x"), Some("example.org".into()));
        assert_eq!(host("plain-name"), Some("plain-name".into()));
    }
}
