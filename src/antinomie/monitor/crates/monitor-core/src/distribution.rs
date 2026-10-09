//! Public base distribution over the Hugging Face bucket.
//!
//! Bases are advertised in an `index.json` catalog at the bucket root. The
//! application fetches the catalog, then downloads a base's files anonymously
//! and installs the bundle. Transport is the external `curl` binary so the core
//! keeps no TLS dependency; a missing `curl` is reported as an explicit tool
//! alert rather than silently failing.
//!
//! Contract: `Documentation/Antinomie/Hugging Face Base Distribution.md`.

use crate::storage::Bundle;
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
    pub files: Vec<CatalogFile>,
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

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut digest = Sha256::new();
    let mut chunk = [0u8; 65536];
    loop {
        let len = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if len == 0 {
            break;
        }
        digest.update(&chunk[..len]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Fetch a URL to `destination` with retries, following redirects. `curl -C -`
/// resumes an existing partial file. Returns the child so callers can poll
/// progress; the caller must wait on it.
pub(crate) fn spawn_download(
    curl: &Path,
    url: &str,
    destination: &Path,
) -> Result<std::process::Child, String> {
    ProcessCommand::new(curl)
        // A stalled mirror (under 1 KiB/s for a minute) fails over to a retry.
        .args([
            "-fL",
            "--retry",
            "3",
            "--retry-delay",
            "2",
            "--retry-all-errors",
            "--connect-timeout",
            "30",
            "--speed-limit",
            "1024",
            "--speed-time",
            "60",
            "-C",
            "-",
            "-o",
        ])
        .arg(destination)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("starting curl: {e}"))
}

fn wait_download(child: &mut std::process::Child, url: &str) -> Result<(), String> {
    let status = child.wait().map_err(|e| e.to_string())?;
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

fn file_len(path: &Path) -> u64 {
    fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

/// Download one base into `staging`, verifying size and SHA-256, and return the
/// loaded (uninstalled) bundle. `progress` receives `(received, total)` bytes.
///
/// If a resumed file fails its hash, the file is removed and retried once from
/// scratch so a corrupted partial cannot wedge the download.
pub fn download_base(
    curl: &Path,
    remote_base: &str,
    base: &CatalogBase,
    staging: &Path,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<Bundle, String> {
    let total: u64 = base.files.iter().map(|file| file.size).sum();
    fs::create_dir_all(staging).map_err(|e| format!("{}: {e}", staging.display()))?;

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
        if !already_done {
            let mut child = spawn_download(curl, &url, &destination)?;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("download cancelled".into());
                }
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                let completed: u64 = base
                    .files
                    .iter()
                    .filter(|other| other.name != file.name)
                    .filter(|other| {
                        let path = staging.join(&other.name);
                        path.is_file() && file_len(&path) == other.size
                    })
                    .map(|other| other.size)
                    .sum::<u64>();
                progress((completed + file_len(&destination)).min(total), total);
                std::thread::sleep(Duration::from_millis(100));
            }
            wait_download(&mut child, &url)?;
        }
        // A resumed file can be complete but corrupt; retry once from scratch.
        let matches =
            file_len(&destination) == file.size && sha256_file(&destination)? == file.sha256;
        if !matches {
            let _ = fs::remove_file(&destination);
            let mut child = spawn_download(curl, &url, &destination)?;
            while child.try_wait().ok().flatten().is_none() {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("download cancelled".into());
                }
                progress(file_len(&destination).min(total), total);
                std::thread::sleep(Duration::from_millis(100));
            }
            wait_download(&mut child, &url)?;
            if file_len(&destination) != file.size || sha256_file(&destination)? != file.sha256 {
                return Err(format!(
                    "{} failed integrity check after download",
                    file.name
                ));
            }
        }
        progress(
            base.files
                .iter()
                .filter(|other| {
                    staging.join(&other.name).is_file()
                        && file_len(&staging.join(&other.name)) == other.size
                })
                .map(|other| other.size)
                .sum::<u64>()
                .min(total),
            total,
        );
    }
    progress(total, total);
    let bundle = Bundle::load(staging)?;
    Ok(bundle)
}

/// Fetch and validate the catalog.
pub fn fetch_catalog(curl: &Path, remote_base: &str) -> Result<Catalog, String> {
    curl_version(curl)?;
    let url = joined(remote_base, CATALOG_FILE);
    let temp = std::env::temp_dir().join(format!(
        "antinomie-catalog-{}-{}.json",
        std::process::id(),
        crate::storage::unique_id()
    ));
    let result = (|| -> Result<Catalog, String> {
        let mut child = spawn_download(curl, &url, &temp)?;
        wait_download(&mut child, &url)?;
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
        )
        .unwrap_err();
        assert!(error.contains("integrity"), "{error}");
    }

    #[test]
    #[ignore = "network: hits the public Hugging Face bucket"]
    fn fetches_real_bucket_catalog_and_downloads_reference_base() {
        if crate::build::which("curl").is_none() {
            return;
        }
        let catalog = fetch_catalog(Path::new("curl"), DEFAULT_REMOTE_BASE).expect("catalog");
        assert!(validate_catalog(&catalog).is_ok());
        // The newest BusyBox: the one for the current contract revision.
        let base = catalog
            .bases
            .iter()
            .filter(|base| base.kind == "busybox")
            .max_by_key(|base| base.antinomie_revision)
            .expect("busybox base present");
        let target = staging("real");
        let bundle = download_base(
            Path::new("curl"),
            DEFAULT_REMOTE_BASE,
            base,
            &target,
            &AtomicBool::new(false),
            |_, _| {},
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
