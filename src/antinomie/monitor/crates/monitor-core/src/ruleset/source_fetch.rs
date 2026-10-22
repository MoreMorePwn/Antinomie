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
        // Redirects are followed by hand so that each target is checked.
        let mut child = crate::http_fetch::command(
            &self.program,
            &crate::http_fetch::Options {
                fail: false,
                ..crate::http_fetch::Options::new(DOWNLOAD_TIMEOUT as u32, max_size)
            },
        )
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
        .arg("--url")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("curl: {error}"))?;
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
                return Err(format!("{url} sent more than the {max_size} bytes allowed"));
            }
            match child.try_wait().map_err(|error| error.to_string())? {
                Some(status) => break status,
                None if started.elapsed() > Duration::from_secs(DOWNLOAD_TIMEOUT + 30) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(dest);
                    return Err(format!("{url} timed out"));
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
                        format!("{current} redirected to a location that is not allowed")
                    })?;
                    if !host_allowed(&origin, &host) {
                        let _ = fs::remove_file(dest);
                        return Err(format!(
                            "{url} redirected to {host}, which is not one of its hosts"
                        ));
                    }
                    current = hop.redirect;
                }
                code => {
                    let _ = fs::remove_file(dest);
                    return Err(format!("{current} answered HTTP {code}"));
                }
            }
        }
        let _ = fs::remove_file(dest);
        Err(format!("{url} redirected too many times"))
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
