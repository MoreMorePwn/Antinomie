// SPDX-License-Identifier: GPL-3.0-only
//! Public base distribution over the Hugging Face bucket.
//!
//! Bases are advertised in an `index.json` catalog at the bucket root. The
//! application fetches the catalog, then downloads a base's files anonymously
//! and installs the bundle. Transport is the external `curl` binary so the core
//! keeps no TLS dependency; a missing `curl` is reported as an explicit tool
//! alert rather than silently failing.
//!
//! The catalog format and the checks on a download are described in
//! `docs/security.md` (Downloads and their checks).

use crate::storage::Bundle;
use serde::Deserialize;

use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::{Command as ProcessCommand, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// Public default bucket (`.../resolve` is the anonymous file endpoint).
pub const DEFAULT_REMOTE_BASE: &str =
    "https://huggingface.co/buckets/MoreMorePwn/antinomie-bases/resolve";

/// Catalog file name at the bucket root.
pub const CATALOG_FILE: &str = "index.json";

/// The parsed catalog. Unknown fields are ignored so the bucket can grow.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Catalog {
    pub schema: u32,
    pub updated: String,
    pub bucket: String,
    pub bases: Vec<CatalogBase>,
}

/// One advertised base.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct CatalogBase {
    pub identity: String,
    pub label: String,
    pub kind: String,
    pub guest: String,
    pub kernel_version: String,
    pub schema_id: u32,
    pub fixed_display: bool,
    pub min_ram_mib: u32,
    pub min_disk_gib: u32,
    pub total_size: u64,
    pub created: String,
    /// Antinomie patch revision of the base's kernel; absent for older bases.
    pub antinomie_revision: Option<u32>,
    /// Patch-series SHA-256, present together with the revision.
    pub antinomie_source: Option<String>,
    /// Antinomie version that built the base.
    pub built_with: Option<String>,
    /// Oldest Antinomie version that can run the base.
    pub min_app_version: Option<String>,
    /// The guest architecture, named as `Bundle.arch` is (`"arm64"`); absent
    /// for x86-64.
    pub arch: Option<String>,
    pub files: Vec<CatalogFile>,
}

impl CatalogBase {
    /// The guest architecture of the base: an absent `arch` is x86-64.
    pub fn guest_arch(&self) -> crate::api::GuestArch {
        match self.arch.as_deref() {
            Some("arm64" | "aarch64") => crate::api::GuestArch::AARCH64,
            _ => crate::api::GuestArch::X86_64,
        }
    }

    /// The least RAM a VM on the base needs: the catalog's figure, and for an
    /// arm64 base never less than the arm64 machine's floor.
    pub fn min_ram_floor_mib(&self) -> u32 {
        if self.guest_arch() == crate::api::GuestArch::AARCH64 {
            self.min_ram_mib.max(crate::vm::VIRT_MIN_RAM_MIB)
        } else {
            self.min_ram_mib
        }
    }
}

/// The newest base of `kind` for the guest architecture `arch` (the highest
/// Antinomie revision, then the latest creation time): a catalog lists the
/// architectures side by side, so the tie of a revision is never broken by
/// position.
pub fn newest_base<'a>(
    bases: &'a [CatalogBase],
    kind: &str,
    arch: crate::api::GuestArch,
) -> Option<&'a CatalogBase> {
    bases
        .iter()
        .filter(|base| base.kind == kind && base.guest_arch() == arch)
        .max_by(|a, b| (a.antinomie_revision, &a.created).cmp(&(b.antinomie_revision, &b.created)))
}

/// One file of a base.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct CatalogFile {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// Catalog schema version this build understands.
pub const SUPPORTED_SCHEMA: u32 = 1;

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// Reject a malformed or unsafe catalog before any file is downloaded.
pub fn validate_catalog(catalog: &Catalog) -> Result<(), String> {
    if catalog.schema != SUPPORTED_SCHEMA {
        return Err(format!(
            "unsupported base catalog schema {} (expected {SUPPORTED_SCHEMA})",
            catalog.schema
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for base in &catalog.bases {
        if !is_hex64(&base.identity) {
            return Err(format!(
                "base catalog has invalid identity {:?}",
                base.identity
            ));
        }
        if !seen.insert(&base.identity) {
            return Err(format!("base catalog repeats identity {}", base.identity));
        }
        if base.label.trim().is_empty() {
            return Err(format!("base {} has no label", base.identity));
        }
        match (&base.antinomie_revision, &base.antinomie_source) {
            (None, None) => {}
            (Some(revision), Some(source))
                if crate::api::parse_source_id(&format!("{revision}:{source}")).is_some() => {}
            _ => {
                return Err(format!(
                    "base {} has an invalid Antinomie revision or source",
                    base.identity
                ));
            }
        }
        for version in [&base.built_with, &base.min_app_version]
            .into_iter()
            .flatten()
        {
            if crate::api::Version::parse(version).is_none() {
                return Err(format!(
                    "base {} has an invalid Antinomie version {version:?}",
                    base.identity
                ));
            }
        }
        if base.files.is_empty() {
            return Err(format!("base {} lists no files", base.identity));
        }
        let mut names = std::collections::HashSet::new();
        for file in &base.files {
            if !safe_file_name(&file.name) {
                return Err(format!(
                    "base {} has unsafe file name {:?}",
                    base.identity, file.name
                ));
            }
            if !names.insert(&file.name) {
                return Err(format!(
                    "base {} repeats file {:?}",
                    base.identity, file.name
                ));
            }
            if !is_hex64(&file.sha256) {
                return Err(format!(
                    "base {} file {} has invalid sha256",
                    base.identity, file.name
                ));
            }
        }
    }
    Ok(())
}

/// Parse and validate a catalog document.
pub fn parse_catalog(bytes: &[u8]) -> Result<Catalog, String> {
    let catalog: Catalog = serde_json::from_slice(bytes)
        .map_err(|error| format!("base catalog is not valid JSON: {error}"))?;
    validate_catalog(&catalog)?;
    Ok(catalog)
}

fn joined(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path)
}

/// Confirm `curl` is runnable, returning its version banner or a tool alert.
pub fn curl_version(curl: &Path) -> Result<String, String> {
    let output = ProcessCommand::new(curl)
        .arg("--version")
        .output()
        .map_err(|_| {
            format!(
                "curl is required to download bases but was not found at {}; install curl and retry",
                curl.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!("{} --version failed", curl.display()));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("curl")
        .to_string())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let checksum = crate::storage::sha256_uncached(file)?;
    Ok(checksum.iter().map(|b| format!("{b:02x}")).collect())
}

/// Fetch a URL to `destination` with retries, following redirects. `curl -C -`
/// resumes an existing partial file. Returns the child so callers can poll
/// progress; the caller must wait on it.
/// Largest single download (a base disk or a cloud image), in bytes.
const DOWNLOAD_MAX_SIZE: u64 = 16 << 30;

pub(crate) fn spawn_download(
    curl: &Path,
    url: &str,
    destination: &Path,
    extra: &[String],
) -> Result<std::process::Child, String> {
    crate::dependencies::require_tool(curl, "curl")?;
    // HTTPS only, also across redirects. There is no overall time limit (a
    // base is gigabytes); a stalled mirror (under 1 KiB/s for a minute) fails
    // over to a retry instead.
    crate::http_fetch::command(
        curl,
        &crate::http_fetch::Options {
            max_time: None,
            max_filesize: Some(DOWNLOAD_MAX_SIZE),
            follow: true,
            ..crate::http_fetch::Options::new(0, 0)
        },
    )
    .args([
        "--retry",
        "3",
        "--retry-delay",
        "2",
        "--retry-all-errors",
        "--speed-limit",
        "1024",
        "--speed-time",
        "60",
        "-C",
        "-",
    ])
    .args(extra)
    .arg("-o")
    .arg(destination)
    .arg(url)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .map_err(|e| format!("starting curl: {e}"))
}

/// What a finished `curl` download means: `Ok`, or the end of its diagnostics.
pub(crate) fn download_result(
    child: &mut std::process::Child,
    status: std::process::ExitStatus,
    url: &str,
) -> Result<(), String> {
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let detail = stderr.lines().last().unwrap_or("").trim();
    Err(format!(
        "download failed for {url}{}",
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    ))
}

/// Download `url` to `destination` (see [`spawn_download`]) and wait for it,
/// calling `tick` about every `interval` for progress. A set `cancel` kills
/// curl within a few tens of milliseconds, whatever the server is doing, and
/// the error is "`what` cancelled"; the caller removes what was written.
pub(crate) fn fetch_file(
    curl: &Path,
    url: &str,
    destination: &Path,
    cancel: &AtomicBool,
    what: &str,
    interval: Duration,
    tick: impl FnMut(),
) -> Result<(), String> {
    let mut child = spawn_download(curl, url, destination, &[])?;
    match crate::cancel::wait_every(&mut child, cancel, interval, tick)? {
        None => Err(format!("{what} cancelled")),
        Some(status) => download_result(&mut child, status, url),
    }
}

fn file_len(path: &Path) -> u64 {
    fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

/// Download one base into `staging`, verifying size and SHA-256, and return the
/// loaded (uninstalled) bundle. `progress` receives `(received, total)` bytes;
/// `note` hears "Resuming ..." or "Starting ... again: ..." lines.
///
/// A file that fails its hash is removed and fetched once more from scratch,
/// so a corrupted partial cannot wedge the download. A cancel (or a network
/// failure) keeps `staging` with the partial file and its record, so the next
/// download of the same base resumes (see [`crate::resume`]). `staging` is
/// never where the app looks for installed bases.
pub fn download_base(
    curl: &Path,
    remote_base: &str,
    base: &CatalogBase,
    staging: &Path,
    cancel: &AtomicBool,
    progress: impl FnMut(u64, u64),
    note: &mut dyn FnMut(&str),
) -> Result<Bundle, String> {
    download_files(curl, remote_base, base, staging, cancel, progress, note)
}

/// Bytes of partial downloads kept in `staging`.
pub fn kept_bytes(staging: &Path) -> u64 {
    fs::read_dir(staging).map_or(0, |entries| {
        entries
            .flatten()
            .filter_map(|entry| entry.metadata().ok())
            .filter(|meta| meta.is_file())
            .map(|meta| meta.len())
            .sum()
    })
}

/// Remove kept partial downloads of bases the catalog no longer lists.
pub fn prune_partials(downloads: &Path, catalog: &Catalog) {
    let Ok(entries) = fs::read_dir(downloads) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !catalog.bases.iter().any(|base| base.identity == name) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn download_files(
    curl: &Path,
    remote_base: &str,
    base: &CatalogBase,
    staging: &Path,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
    note: &mut dyn FnMut(&str),
) -> Result<Bundle, String> {
    let total: u64 = base.files.iter().map(|file| file.size).sum();
    fs::create_dir_all(staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let finished_size = |except: Option<&str>| -> u64 {
        base.files
            .iter()
            .filter(|other| Some(other.name.as_str()) != except)
            .filter(|other| {
                let path = staging.join(&other.name);
                path.is_file() && file_len(&path) == other.size
            })
            .map(|other| other.size)
            .sum()
    };
    for file in &base.files {
        if cancel.load(Ordering::Relaxed) {
            return Err("download cancelled".into());
        }
        let destination = staging.join(&file.name);
        let url = joined(
            remote_base,
            &format!("bases/{}/{}", base.identity, file.name),
        );
        let already_done = file_len(&destination) == file.size
            && sha256_file(&destination)
                .map(|hash| hash == file.sha256)
                .unwrap_or(false);
        let key = format!(
            "{}/{}:{}:{}",
            base.identity, file.name, file.size, file.sha256
        );
        let item = crate::resume::Item {
            label: &base.label,
            key: &key,
            size: Some(file.size),
        };
        if !already_done {
            crate::resume::fetch(
                curl,
                &url,
                &destination,
                &item,
                cancel,
                "download",
                Duration::from_millis(100),
                || {
                    let done = finished_size(Some(&file.name)) + file_len(&destination);
                    progress(done.min(total), total);
                },
                note,
            )?;
        }
        // A resumed file can be complete but corrupt; start over once, from zero.
        let matches =
            file_len(&destination) == file.size && sha256_file(&destination)? == file.sha256;
        if !matches {
            crate::resume::discard(&destination);
            note(&format!(
                "Starting {} again: {} failed its SHA-256 check",
                base.label, file.name
            ));
            crate::resume::fetch(
                curl,
                &url,
                &destination,
                &item,
                cancel,
                "download",
                Duration::from_millis(100),
                || progress(file_len(&destination).min(total), total),
                &mut |_| {},
            )?;
            if file_len(&destination) != file.size || sha256_file(&destination)? != file.sha256 {
                crate::resume::discard(&destination);
                return Err(format!(
                    "{} failed integrity check after download",
                    file.name
                ));
            }
        }
        progress(finished_size(None).min(total), total);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("download cancelled".into());
    }
    progress(total, total);
    let bundle = Bundle::load(staging)?;
    Ok(bundle)
}

/// Fetch and validate the catalog. A set `cancel` stops the transfer at once;
/// nothing is kept, and the catalog the app already has stays as it was.
pub fn fetch_catalog(
    curl: &Path,
    remote_base: &str,
    cancel: &AtomicBool,
) -> Result<Catalog, String> {
    curl_version(curl)?;
    let url = joined(remote_base, CATALOG_FILE);
    let temp = std::env::temp_dir().join(format!(
        "antinomie-catalog-{}-{}.json",
        std::process::id(),
        crate::storage::unique_id()
    ));
    let result = (|| -> Result<Catalog, String> {
        fetch_file(
            curl,
            &url,
            &temp,
            cancel,
            "catalog refresh",
            Duration::from_secs(3600),
            || {},
        )?;
        let bytes = fs::read(&temp).map_err(|e| format!("{}: {e}", temp.display()))?;
        parse_catalog(&bytes)
    })();
    let _ = fs::remove_file(&temp);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    fn sha256(path: &Path) -> String {
        sha256_file(path).unwrap()
    }

    fn sample_catalog(root: &Path) -> String {
        let identity = "0".repeat(64);
        let dir = root.join("bases").join(&identity);
        let files: Vec<(&str, &[u8])> = vec![
            ("kernel", b"kernel-bytes"),
            ("initrd", b"initrd-bytes"),
            ("base.qcow2", b"not-really-a-disk"),
        ];
        for (name, bytes) in &files {
            write(&dir.join(name), bytes);
        }
        let bundle = serde_json::json!({
            "kernel": "kernel",
            "base_disk": "base.qcow2",
            "initrd": "initrd",
            "kernel_append": "console=ttyS0",
            "kernel_version": "6.12.94",
            "schema_id": 1,
        });
        write(
            &dir.join("bundle.json"),
            serde_json::to_vec_pretty(&bundle).unwrap().as_slice(),
        );
        let mut entries = vec![];
        for name in ["kernel", "initrd", "base.qcow2", "bundle.json"] {
            let path = dir.join(name);
            entries.push(serde_json::json!({
                "name": name,
                "size": fs::metadata(&path).unwrap().len(),
                "sha256": sha256(&path),
            }));
        }
        serde_json::json!({
            "schema": 1,
            "bucket": "test",
            "bases": [{
                "identity": identity,
                "label": "Test",
                "files": entries,
            }]
        })
        .to_string()
    }

    fn staging(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "antinomie-dist-test-{label}-{}-{}",
            std::process::id(),
            crate::storage::unique_id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rejects_bad_catalog_fields() {
        let mut catalog = Catalog {
            schema: 1,
            bases: vec![CatalogBase {
                identity: "not-hex".into(),
                label: "x".into(),
                files: vec![CatalogFile {
                    name: "kernel".into(),
                    size: 1,
                    sha256: "a".repeat(64),
                }],
                ..CatalogBase::default()
            }],
            ..Catalog::default()
        };
        assert!(validate_catalog(&catalog).is_err());
        catalog.bases[0].identity = "0".repeat(64);
        catalog.bases[0].files[0].name = "../escape".into();
        assert!(validate_catalog(&catalog).is_err());
        catalog.bases[0].files[0].name = "kernel".into();
        assert!(validate_catalog(&catalog).is_ok());
        catalog.schema = 99;
        assert!(validate_catalog(&catalog).is_err());
    }

    #[test]
    fn parses_catalog_and_ignores_unknown_fields() {
        let text = r#"{
            "schema": 1,
            "future": true,
            "bases": [{
                "identity": "0000000000000000000000000000000000000000000000000000000000000000",
                "label": "Test",
                "extra": 3,
                "files": [{"name":"kernel","size":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","note":"x"}]
            }]
        }"#;
        let catalog = parse_catalog(text.as_bytes()).unwrap();
        assert_eq!(catalog.bases.len(), 1);
        assert_eq!(catalog.bases[0].files[0].name, "kernel");
        assert_eq!(catalog.bases[0].antinomie_revision, None);
    }

    #[test]
    fn catalog_revision_and_source_come_together() {
        let catalog = |extra: &str| {
            format!(
                r#"{{"schema":1,"bases":[{{"identity":"{}","label":"T",{extra}
                "files":[{{"name":"kernel","size":1,"sha256":"{}"}}]}}]}}"#,
                "0".repeat(64),
                "a".repeat(64)
            )
        };
        let source = "c".repeat(64);
        let parsed = parse_catalog(
            catalog(&format!(
                r#""antinomie_revision":9,"antinomie_source":"{source}","#
            ))
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(parsed.bases[0].antinomie_revision, Some(9));
        let versioned =
            parse_catalog(catalog(r#""min_app_version":"0.2.0","built_with":"0.2.1","#).as_bytes())
                .unwrap();
        assert_eq!(versioned.bases[0].min_app_version.as_deref(), Some("0.2.0"));
        for extra in [
            r#""antinomie_revision":9,"#.to_string(),
            format!(r#""antinomie_source":"{source}","#),
            format!(r#""antinomie_revision":0,"antinomie_source":"{source}","#),
            r#""antinomie_revision":9,"antinomie_source":"xyz","#.to_string(),
            r#""min_app_version":"0.2","#.to_string(),
            r#""built_with":"v0.1.0","#.to_string(),
        ] {
            assert!(
                parse_catalog(catalog(&extra).as_bytes()).is_err(),
                "{extra}"
            );
        }
    }

    #[test]
    fn downloads_and_verifies_over_file_url() {
        if crate::build::which("curl").is_none() {
            return;
        }
        let source = staging("source");
        let text = sample_catalog(&source);
        let catalog = parse_catalog(text.as_bytes()).unwrap();
        let remote = format!("file://{}", source.display());
        let target = staging("target");
        let cancel = AtomicBool::new(false);
        let mut last = 0;
        let bundle = download_base(
            Path::new("curl"),
            &remote,
            &catalog.bases[0],
            &target,
            &cancel,
            |received, total| {
                assert!(received <= total);
                last = received;
            },
            &mut |_| {},
        )
        .unwrap();
        assert!(bundle.kernel.ends_with("kernel"));
        assert_eq!(
            last,
            catalog.bases[0].files.iter().map(|f| f.size).sum::<u64>()
        );
        assert_eq!(
            sha256(&target.join("base.qcow2")),
            catalog.bases[0]
                .files
                .iter()
                .find(|f| f.name == "base.qcow2")
                .unwrap()
                .sha256
        );
    }

    #[test]
    fn a_cancelled_download_keeps_its_partial_and_the_next_one_resumes_it() {
        let source = staging("cancel-source");
        let catalog = parse_catalog(sample_catalog(&source).as_bytes()).unwrap();
        let remote = format!("file://{}", source.display());
        let target = staging("cancel-target");
        let cancel = AtomicBool::new(false);
        let error = download_base(
            Path::new("curl"),
            &remote,
            &catalog.bases[0],
            &target,
            &cancel,
            |received, _| {
                if received >= catalog.bases[0].files[0].size {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
            &mut |_| {},
        )
        .unwrap_err();
        assert_eq!(error, "download cancelled");
        assert!(target.exists(), "the staging folder keeps what arrived");
        cancel.store(false, Ordering::Relaxed);
        download_base(
            Path::new("curl"),
            &remote,
            &catalog.bases[0],
            &target,
            &cancel,
            |_, _| {},
            &mut |_| {},
        )
        .unwrap();
        assert!(target.join("bundle.json").is_file());
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(target).unwrap();
    }

    #[test]
    fn partials_of_bases_the_catalog_dropped_are_pruned() {
        let source = staging("prune-source");
        let catalog = parse_catalog(sample_catalog(&source).as_bytes()).unwrap();
        let downloads = staging("prune-downloads");
        let kept = downloads.join(&catalog.bases[0].identity);
        let gone = downloads.join("f".repeat(64));
        for dir in [&kept, &gone] {
            write(&dir.join("kernel"), b"partial");
        }
        prune_partials(&downloads, &catalog);
        assert!(kept.is_dir() && !gone.exists());
        assert_eq!(kept_bytes(&kept), 7);
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(downloads).unwrap();
    }

    #[test]
    fn cancellation_during_final_verification_prevents_completion() {
        let source = staging("final-cancel-source");
        let catalog = parse_catalog(sample_catalog(&source).as_bytes()).unwrap();
        let remote = format!("file://{}", source.display());
        let target = staging("final-cancel-target");
        let cancel = AtomicBool::new(false);
        let error = download_base(
            Path::new("curl"),
            &remote,
            &catalog.bases[0],
            &target,
            &cancel,
            |received, total| {
                if received == total {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
            &mut |_| {},
        )
        .unwrap_err();
        assert_eq!(error, "download cancelled");
        fs::remove_dir_all(source).unwrap();
    }

    #[test]
    fn rejects_hash_mismatch() {
        if crate::build::which("curl").is_none() {
            return;
        }
        let source = staging("bad-source");
        let text = sample_catalog(&source);
        let mut catalog = parse_catalog(text.as_bytes()).unwrap();
        catalog.bases[0].files[0].sha256 = "b".repeat(64);
        let remote = format!("file://{}", source.display());
        let target = staging("bad-target");
        let cancel = AtomicBool::new(false);
        let error = download_base(
            Path::new("curl"),
            &remote,
            &catalog.bases[0],
            &target,
            &cancel,
            |_, _| {},
            &mut |_| {},
        )
        .unwrap_err();
        assert!(error.contains("integrity"), "{error}");
    }

    fn fixture_catalog() -> Catalog {
        let files = || serde_json::json!([{"name": "kernel", "size": 1, "sha256": "c".repeat(64)}]);
        let text = serde_json::json!({
            "schema": 1,
            "bases": [
                {"identity": "1".repeat(64), "label": "BusyBox x86-64", "kind": "busybox",
                 "min_ram_mib": 256, "antinomie_revision": 22, "antinomie_source": "a".repeat(64), "files": files(), "created": "2026-11-11T21:29:00Z"},
                {"identity": "2".repeat(64), "label": "BusyBox arm64", "kind": "busybox",
                 "arch": "arm64", "min_ram_mib": 256, "antinomie_revision": 22, "antinomie_source": "a".repeat(64), "files": files(),
                 "created": "2026-11-11T22:08:00Z"},
                {"identity": "3".repeat(64), "label": "Debian x86-64", "kind": "debian",
                 "antinomie_revision": 22, "antinomie_source": "a".repeat(64), "files": files(), "created": "2026-11-11T23:00:00Z"},
                {"identity": "4".repeat(64), "label": "BusyBox old", "kind": "busybox",
                 "antinomie_revision": 21, "antinomie_source": "a".repeat(64), "files": files(), "created": "2026-11-05T10:00:00Z"},
            ]
        });
        parse_catalog(text.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn newest_base_picks_by_architecture_not_by_position_or_time() {
        use crate::api::GuestArch;
        let mut catalog = fixture_catalog();
        let x86 = newest_base(&catalog.bases, "busybox", GuestArch::X86_64).unwrap();
        assert_eq!(x86.label, "BusyBox x86-64");
        let arm = newest_base(&catalog.bases, "busybox", GuestArch::AARCH64).unwrap();
        assert_eq!(arm.label, "BusyBox arm64");
        // The arm64 entry listed last, or created last, never wins for x86-64.
        catalog.bases.reverse();
        let x86 = newest_base(&catalog.bases, "busybox", GuestArch::X86_64).unwrap();
        assert_eq!(x86.label, "BusyBox x86-64");
        assert!(newest_base(&catalog.bases, "gnome", GuestArch::X86_64).is_none());
    }

    #[test]
    fn an_arm64_catalog_entry_shows_at_least_the_arm64_minimum() {
        let catalog = fixture_catalog();
        let remote: Vec<_> = catalog
            .bases
            .iter()
            .map(crate::api::RemoteBase::from)
            .collect();
        assert_eq!(remote[0].min_ram_mib, 256);
        assert_eq!(remote[1].min_ram_mib, 512);
    }

    #[test]
    #[ignore = "network: hits the public Hugging Face bucket"]
    fn fetches_real_bucket_catalog_and_downloads_reference_base() {
        if crate::build::which("curl").is_none() {
            return;
        }
        let catalog = fetch_catalog(
            Path::new("curl"),
            DEFAULT_REMOTE_BASE,
            &AtomicBool::new(false),
        )
        .expect("catalog");
        assert!(validate_catalog(&catalog).is_ok());
        // The newest x86-64 BusyBox: the one for the current contract revision.
        let base = newest_base(&catalog.bases, "busybox", crate::api::GuestArch::X86_64)
            .expect("x86-64 busybox base present");
        let target = staging("real");
        let bundle = download_base(
            Path::new("curl"),
            DEFAULT_REMOTE_BASE,
            base,
            &target,
            &AtomicBool::new(false),
            |_, _| {},
            &mut |_| {},
        )
        .expect("download");
        assert!(bundle.base_disk.ends_with("base.qcow2"));
        assert_eq!(
            sha256(&target.join("bundle.json")),
            base.files
                .iter()
                .find(|file| file.name == "bundle.json")
                .unwrap()
                .sha256
        );
    }
}
