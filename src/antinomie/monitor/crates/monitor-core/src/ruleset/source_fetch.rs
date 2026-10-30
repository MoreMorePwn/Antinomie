// SPDX-License-Identifier: GPL-3.0-only
//! Downloading upstream rule files: HTTPS only, bounded, cancellable, and
//! limited to the hosts the catalog names.
use super::*;
use std::{
    io::Read,
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Redirects followed for one download.
const MAX_REDIRECTS: usize = 5;
/// Seconds one download may take.
const DOWNLOAD_TIMEOUT: u64 = 900;

/// Fetches one URL into a file. A failed or cancelled fetch leaves no usable file.
pub trait Fetcher {
    /// Download `url` into `dest`, at most `max_size` bytes. `progress` receives
    /// the bytes received so far.
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        max_size: u64,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<(), String>;
}

/// The system `curl`. Each hop is a separate process so that every redirect
/// target is checked against the allowed hosts before it is requested.
///
/// The URL goes to curl on its standard input as a configuration (`-K -`),
/// never on the command line: an abuse.ch export URL carries the Auth-Key in
/// its path. Every message that names a URL shows it through [`redact_url`].
#[derive(Clone, Debug)]
pub struct Curl {
    program: PathBuf,
}

impl Default for Curl {
    fn default() -> Self {
        Self {
            program: PathBuf::from("curl"),
        }
    }
}

/// Whether `host` is an abuse.ch service.
pub fn is_abusech_host(host: &str) -> bool {
    host == "abuse.ch" || host.ends_with(".abuse.ch")
}

/// `text` with the key of every `/exports/<key>/` URL path replaced by
/// `****`, wherever the URL appears in it.
pub fn redact_url(text: &str) -> String {
    const MARK: &str = "/exports/";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        let after = at + MARK.len();
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        match tail.find('/') {
            Some(end) if tail[..end].chars().all(|c| !c.is_whitespace() && c != '"') => {
                out.push_str("****");
                rest = &tail[end..];
            }
            _ => {
                // No closing slash: the rest of the token is the key.
                let end = tail
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .unwrap_or(tail.len());
                out.push_str("****");
                rest = &tail[end..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// What an HTTP status means for an abuse.ch download, in words: what is
/// wrong, and what to do about it.
fn status_text(host: &str, code: u32, url: &str) -> Option<String> {
    if !is_abusech_host(host) {
        return None;
    }
    Some(match code {
        401 => "abuse.ch now requires an Auth-Key for this download (HTTP 401): the request was refused because the Auth-Key is missing or was rejected. Set a free key (auth.abuse.ch) in Tools > API keys, then try again".to_owned(),
        403 => "abuse.ch rejected the Auth-Key (HTTP 403); check it in Tools > API keys, or get a free one at auth.abuse.ch".to_owned(),
        404 => format!(
            "abuse.ch has no file at {} (HTTP 404); the export may have moved or been renamed, so update Antinomie",
            redact_url(url)
        ),
        410 => "abuse.ch has retired this endpoint (HTTP 410); update Antinomie".to_owned(),
        429 => "abuse.ch asks to slow down (HTTP 429); try again later".to_owned(),
        500..=599 => format!("abuse.ch had a problem answering (HTTP {code}); try again later"),
        _ => return None,
    })
}

impl Curl {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    fn hop(
        &self,
        url: &str,
        dest: &Path,
        max_size: u64,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<Hop, String> {
        let _ = fs::remove_file(dest);
        // The configuration is one `url = "..."` line; a quote, backslash or
        // line break in a URL would end it early.
        if url.chars().any(|c| c.is_control() || c == '"' || c == '\\') {
            return Err(format!(
                "{} contains unacceptable characters",
                redact_url(url)
            ));
        }
        let shown = redact_url(url);
        // Redirects are followed by hand so that each target is checked.
        let mut command = crate::http_fetch::command(
            &self.program,
            &crate::http_fetch::Options {
                fail: false,
                ..crate::http_fetch::Options::new(DOWNLOAD_TIMEOUT as u32, max_size)
            },
        );
        command
            .args([
                "--speed-limit",
                "1024",
                "--speed-time",
                "60",
                "--user-agent",
                concat!("Antinomie-rules/", env!("CARGO_PKG_VERSION")),
                "--write-out",
                "%{http_code} %{redirect_url}",
                "--output",
            ])
            .arg(dest)
            .args(["-K", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|error| format!("curl: {}", redact_url(&error.to_string())))?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            if let Err(error) = writeln!(stdin, "url = \"{url}\"") {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("curl: {}", redact_url(&error.to_string())));
            }
        }
        let started = Instant::now();
        let status = loop {
            if cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(dest);
                return Err("cancelled".into());
            }
            let received = fs::metadata(dest).map(|meta| meta.len()).unwrap_or(0);
            progress(received);
            if received > max_size {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(dest);
                return Err(format!(
                    "{shown} sent more than the {max_size} bytes allowed"
                ));
            }
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(status) => break status,
                None if started.elapsed() > Duration::from_secs(DOWNLOAD_TIMEOUT + 30) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(dest);
                    return Err(format!("{shown} timed out"));
                }
                None => std::thread::sleep(Duration::from_millis(100)),
            }
        };
        let mut out = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.by_ref().take(4096).read_to_string(&mut out);
        }
        let mut err = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.by_ref().take(4096).read_to_string(&mut err);
        }
        if !status.success() {
            let _ = fs::remove_file(dest);
            let err = redact_url(&err);
            let reason = err.lines().last().unwrap_or("").trim();
            return Err(if reason.is_empty() {
                format!("download failed ({status})")
            } else {
                format!("download failed: {reason}")
            });
        }
        let mut parts = out.trim().splitn(2, ' ');
        let code: u32 = parts
            .next()
            .and_then(|code| code.parse().ok())
            .ok_or("the server gave no HTTP status")?;
        let redirect = parts.next().unwrap_or("").trim().to_owned();
        Ok(Hop { code, redirect })
    }
}

struct Hop {
    code: u32,
    redirect: String,
}

impl Fetcher for Curl {
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        max_size: u64,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(u64),
    ) -> Result<(), String> {
        let origin = https_host(url)?;
        let mut current = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            let hop = self.hop(&current, dest, max_size, cancel, progress)?;
            match hop.code {
                200 => return Ok(()),
                301 | 302 | 303 | 307 | 308 => {
                    let host = https_host(&hop.redirect).map_err(|_| {
                        format!(
                            "{} redirected to a location that is not allowed",
                            redact_url(&current)
                        )
                    })?;
                    if !host_allowed(&origin, &host) {
                        let _ = fs::remove_file(dest);
                        return Err(format!(
                            "{} redirected to {host}, which is not one of its hosts",
                            redact_url(url)
                        ));
                    }
                    current = hop.redirect;
                }
                code => {
                    let _ = fs::remove_file(dest);
                    if let Some(meaning) = status_text(&origin, code, &current) {
                        return Err(meaning);
                    }
                    return Err(format!("{} answered HTTP {code}", redact_url(&current)));
                }
            }
        }
        let _ = fs::remove_file(dest);
        Err(format!("{} redirected too many times", redact_url(url)))
    }
}

/// Largest catalog the monitor reads.
pub const MAX_CATALOG_BYTES: u64 = 4 * 1024 * 1024;

/// Download the catalog at `url`, validate it and keep it as the local copy.
/// A catalog that does not validate replaces nothing.
pub fn refresh_catalog(
    data_dir: &Path,
    url: &str,
    fetcher: &dyn Fetcher,
    cancel: &AtomicBool,
) -> Result<Catalog, String> {
    let staging = rules_root(data_dir)
        .join("staging")
        .join(crate::storage::unique_id());
    crate::storage::private_dir(&staging).map_err(|error| error.to_string())?;
    let file = staging.join("catalog.json");
    let result = (|| {
        fetcher.fetch(url, &file, MAX_CATALOG_BYTES, cancel, &mut |_| {})?;
        let bytes = fs::read(&file).map_err(|error| error.to_string())?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("the catalog is not valid JSON: {error}"))?;
        let catalog = validate_catalog(&value)?;
        store_catalog(data_dir, &catalog)?;
        Ok(catalog)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Download a catalog entry's archive through `fetcher` into a private staging
/// directory under the rules root (mode 0700, a unique name) and return its
/// bytes. The staging directory is always removed; the caller verifies the
/// bytes (`install_archive` checks size and SHA-256).
pub fn download_archive(
    data_dir: &Path,
    entry: &PackEntry,
    fetcher: &dyn Fetcher,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let max_size = entry.size.min(MAX_ARCHIVE_BYTES);
    let staging = rules_root(data_dir)
        .join("staging")
        .join(crate::storage::unique_id());
    crate::storage::private_dir(&staging).map_err(|error| error.to_string())?;
    let file = staging.join("archive");
    let result = (|| {
        fetcher.fetch(&entry.download_url, &file, max_size, cancel, &mut |_| {})?;
        fs::read(&file).map_err(|error| error.to_string())
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Every host Antinomie may contact for rules: the catalog's host, then the
/// hosts of each source pack the catalog lists (including redirect targets).
pub fn contacted_hosts(catalog: Option<&Catalog>) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    if let Ok(host) = https_host(CATALOG_URL) {
        hosts.insert(host);
    }
    if let Some(catalog) = catalog {
        for pack in &catalog.sources {
            hosts.extend(pack.hosts());
        }
    }
    hosts.into_iter().collect()
}
