// SPDX-License-Identifier: MIT
//! Installing a schema 2 pack: fetch from upstream, verify, filter locally,
//! index, and register the result like any other pack version.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// What a source install learned about one download.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchedSource {
    pub url: String,
    pub host: String,
    /// SHA-256 of the bytes received.
    pub download_sha256: String,
    pub size: u64,
    /// Files kept from this download.
    pub files: u64,
    /// SHA-256 over the sorted `path hash` lines of the kept files.
    pub file_digest: String,
    /// Every kept file matched the hash the catalog pinned.
    pub verified: bool,
    /// Kept files that differ from the catalog (rolling sources only).
    pub changed_files: u64,
}

/// Where an installed pack came from. Kept in the registry and in the
/// version's manifest, and copied into each scan's selection manifest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProvenance {
    pub homepage: String,
    pub license: String,
    #[serde(default)]
    pub license_url: String,
    pub revision: String,
    pub revision_kind: String,
    /// Option ids that were on for this install.
    #[serde(default)]
    pub options: Vec<String>,
    pub plan_digest: String,
    /// Seconds since the Unix epoch when the files were fetched.
    #[serde(default)]
    pub fetched_unix: u64,
    pub sources: Vec<FetchedSource>,
    /// Rules kept and rules the local filter removed.
    pub kept_rules: u64,
    pub dropped_rules: u64,
    /// What the filter kept and removed, in words.
    #[serde(default)]
    pub summary: Vec<String>,
    /// Anything the person should know, such as a rolling source that changed.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl SourceProvenance {
    /// A short line for lists: the project, the pin and the license.
    pub fn line(&self) -> String {
        let host = self
            .homepage
            .strip_prefix("https://")
            .unwrap_or(&self.homepage);
        format!(
            "{host} · {} {} · {}",
            self.revision_kind, self.revision, self.license
        )
    }
}

/// What the local filter kept and removed.
#[derive(Debug, Default)]
pub struct FilterReport {
    pub kept: u64,
    pub helpers: u64,
    pub dropped: BTreeMap<String, u64>,
    pub kept_by: BTreeMap<String, u64>,
    pub examples: Vec<String>,
}

impl FilterReport {
    pub(super) fn omit(&mut self, reason: &str, count: u64) {
        if count > 0 {
            *self.dropped.entry(reason.to_owned()).or_default() += count;
        }
    }

    fn dropped_total(&self) -> u64 {
        self.dropped.values().sum()
    }

    fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.kept > 0 || self.helpers > 0 {
            let by: Vec<String> = self
                .kept_by
                .iter()
                .map(|(basis, count)| format!("{count} by {basis}"))
                .collect();
            let helpers = if self.helpers > 0 {
                format!(" and {} helper rules", self.helpers)
            } else {
                String::new()
            };
            let by = if by.is_empty() {
                String::new()
            } else {
                format!(" ({})", by.join(", "))
            };
            lines.push(format!("Kept {} rules{helpers}{by}.", self.kept));
        }
        for (reason, count) in &self.dropped {
            lines.push(format!("Removed {count} because {reason}."));
        }
        lines
    }
}

/// The result of an install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceInstall {
    pub version: String,
    pub rules: u64,
    pub helpers: u64,
    pub provenance: SourceProvenance,
    /// The version was already installed, so nothing was downloaded.
    pub already_installed: bool,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|age| age.as_secs())
        .unwrap_or(0)
}

fn digest_of_files(files: &[SourceFile]) -> String {
    let mut lines: Vec<String> = files
        .iter()
        .map(|file| format!("{} {}", file.path, file.sha256))
        .collect();
    lines.sort();
    format!("{:x}", Sha256::digest(lines.join("\n").as_bytes()))
}

/// License files kept beside the rules whatever the filter.
const NOTICE_NAMES: [&str; 5] = ["LICENSE", "LICENSE.txt", "COPYING", "NOTICE", "NOTICE.txt"];

fn is_support_name(name: &str, support: &[String]) -> bool {
    support.iter().any(|wanted| wanted == name)
}

/// Fetch `pack` from upstream with `options` on and install it as a pack version.
///
/// Downloads happen outside the registry lock; the registry changes only after
/// every file has been verified, filtered and indexed, so a failure leaves the
/// previous selection in place. Nothing downloaded is executed. `progress`
/// receives short status lines.
pub fn install_source(
    data_dir: &Path,
    pack: &SourcePack,
    options: &BTreeSet<String>,
    fetcher: &dyn Fetcher,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<SourceInstall, String> {
    check_source_pack(pack)?;
    let unknown = pack.unknown_options(options);
    if !unknown.is_empty() {
        return Err(format!("unknown option {}", unknown.join(", ")));
    }
    let version = pack.version(options);
    path_component(&pack.engine, "engine")?;
    path_component(&pack.id, "id")?;
    path_component(&version, "version")?;
    let root = rules_root(data_dir);
    let version_dir = root
        .join("packs")
        .join(&pack.engine)
        .join(&pack.id)
        .join(&version);
    if version_dir.join("manifest.json").is_file() {
        let _lock = registry_lock();
        let stored = retained_entry(data_dir, &pack.engine, &pack.id, &version)?;
        let provenance = retained_source(&version_dir)?;
        switch_version(data_dir, &stored, provenance.as_ref())?;
        return Ok(SourceInstall {
            version,
            rules: stored.rules,
            helpers: stored.helpers,
            provenance: provenance.unwrap_or_default(),
            already_installed: true,
        });
    }
    let staging = root.join("staging").join(crate::storage::unique_id());
    let result = build_tree(
        data_dir, pack, options, &version, &staging, fetcher, cancel, progress,
    );
    let outcome = match result {
        Ok(built) => {
            let _lock = registry_lock();
            finish_install(data_dir, &version_dir, &staging, built)
        }
        Err(error) => Err(error),
    };
    let _ = fs::remove_dir_all(&staging);
    if outcome.is_err() && version_dir.is_dir() && !version_dir.join("manifest.json").is_file() {
        let _ = fs::remove_dir_all(&version_dir);
    }
    outcome
}

struct Built {
    entry: PackEntry,
    provenance: SourceProvenance,
}

fn finish_install(
    data_dir: &Path,
    version_dir: &Path,
    staging: &Path,
    built: Built,
) -> Result<SourceInstall, String> {
    #[cfg(test)]
    if take_fail("source-install") {
        return Err("No space left on device".into());
    }
    let tree = staging.join("tree");
    if let Some(parent) = version_dir.parent() {
        crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
    }
    fs::rename(&tree, version_dir).map_err(|error| error.to_string())?;
    switch_version(data_dir, &built.entry, Some(&built.provenance))?;
    Ok(SourceInstall {
        version: built.entry.version.clone(),
        rules: built.entry.rules,
        helpers: built.entry.helpers,
        provenance: built.provenance,
        already_installed: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_tree(
    data_dir: &Path,
    pack: &SourcePack,
    options: &BTreeSet<String>,
    version: &str,
    staging: &Path,
    fetcher: &dyn Fetcher,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<Built, String> {
    let _ = data_dir;
    let downloads = staging.join("downloads");
    let extracted = staging.join("extracted");
    let tree = staging.join("tree");
    for dir in [&downloads, &extracted, &tree] {
        crate::storage::private_dir(dir).map_err(|error| error.to_string())?;
    }
    let free = rustix::fs::statvfs(staging)
        .map(|stat| stat.f_bavail.saturating_mul(stat.f_frsize))
        .map_err(|error| error.to_string())?;
    let needed = pack.download_size().saturating_mul(3).max(8 * 1024 * 1024);
    if free < needed {
        return Err(format!(
            "not enough scratch space ({free} bytes free, about {needed} needed); the previous selection was kept"
        ));
    }
    let accept_unlisted = |path: &str| unlisted_ok(&pack.filter, path);
    let mut fetched = Vec::new();
    let mut kept_files: Vec<(String, SourceFile)> = Vec::new();
    let mut notes = Vec::new();
    let mut expanded = 0u64;
    let total = pack.sources.len();
    for (index, source) in pack.sources.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let name = source
            .url
            .rsplit('/')
            .next()
            .unwrap_or(&source.url)
            .to_owned();
        let destination = downloads.join(format!("{index}.download"));
        let label = format!("Downloading {name} ({} of {total})", index + 1);
        progress(&label);
        let mut last = 0u64;
        fetcher.fetch(
            &source.url,
            &destination,
            download_limit(source),
            cancel,
            &mut |received| {
                if received / (256 * 1024) != last / (256 * 1024) {
                    progress(&format!(
                        "{label}: {} of about {}",
                        human_bytes(received),
                        human_bytes(source.size)
                    ));
                }
                last = received;
            },
        )?;
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        progress(&format!("Verifying {name}"));
        let target = extracted.join(index.to_string());
        crate::storage::private_dir(&target).map_err(|error| error.to_string())?;
        let size = fs::metadata(&destination)
            .map(|meta| meta.len())
            .unwrap_or(0);
        let got = extract(
            &destination,
            source,
            &target,
            &accept_unlisted,
            &mut expanded,
        )?;
        let verified = got.changed == 0 && got.missing == 0 && got.unlisted == 0;
        if !verified {
            notes.push(format!(
                "{name} is a rolling download and differs from the catalog: {} files changed, {} new, {} gone.",
                got.changed, got.unlisted, got.missing
            ));
        }
        fetched.push(FetchedSource {
            url: source.url.clone(),
            host: https_host(&source.url)?,
            download_sha256: got.download_sha256,
            size,
            files: got.files.len() as u64,
            file_digest: digest_of_files(&got.files),
            verified,
            changed_files: got.changed,
        });
        for file in got.files {
            kept_files.push((format!("{index}/{}", file.path), file));
        }
        let _ = fs::remove_file(&destination);
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    progress("Filtering rules");
    let include_unlicensed = options.contains("include-unlicensed");
    let mut report = FilterReport::default();
    let mut written = BTreeSet::new();
    let mut write = |path: &str, text: &str| -> Result<(), String> {
        checked_member_path(path)?;
        if !written.insert(path.to_owned()) {
            return Err(format!("two downloads provide {path}"));
        }
        let target = tree.join(path);
        if let Some(parent) = target.parent() {
            crate::storage::private_dir(parent).map_err(|error| error.to_string())?;
        }
        fs::write(&target, text).map_err(|error| format!("write {path}: {error}"))
    };
    for (key, file) in &kept_files {
        let name = file.path.rsplit('/').next().unwrap_or(&file.path);
        if NOTICE_NAMES.contains(&name) {
            write(&file.path, &read_text(&extracted, key)?)?;
        }
    }
    match &pack.filter {
        SourceFilter::YaraForge(filter) => {
            for (key, _) in &kept_files {
                if !key.ends_with(".yar") && !key.ends_with(".yara") {
                    continue;
                }
                let text = read_text(&extracted, key)?;
                let outcome = filter_yara_forge(&text, filter, include_unlicensed, cancel)?;
                report.kept += outcome.report.kept;
                report.helpers += outcome.report.helpers;
                for (reason, count) in outcome.report.dropped {
                    report.omit(&reason, count);
                }
                for (basis, count) in outcome.report.kept_by {
                    *report.kept_by.entry(basis).or_default() += count;
                }
                report.examples.extend(outcome.report.examples);
                for file in outcome.files {
                    write(&file.path, &file.text)?;
                }
            }
        }
        SourceFilter::Sigma(filter) => {
            for (key, file) in &kept_files {
                if !file.path.ends_with(".yml") && !file.path.ends_with(".yaml") {
                    continue;
                }
                let text = read_text(&extracted, key)?.replace("\r\n", "\n");
                if let Some(kept) = filter_sigma_file(&text, filter, &mut report) {
                    write(&file.path, &kept)?;
                }
            }
        }
        SourceFilter::Copy {
            extensions,
            support,
        } => {
            for (key, file) in &kept_files {
                let name = file.path.rsplit('/').next().unwrap_or(&file.path);
                let rule = extensions
                    .iter()
                    .any(|ext| file.path.ends_with(ext.as_str()));
                if !rule && !is_support_name(name, support) || NOTICE_NAMES.contains(&name) {
                    continue;
                }
                // Rule files from different sources share one flat namespace
                // only when their names differ; the catalog lists each once.
                let bytes = fs::read(extracted.join(key)).map_err(|error| error.to_string())?;
                let text = String::from_utf8_lossy(&bytes);
                write(&file.path, &text)?;
            }
        }
    }
    if written.is_empty() {
        return Err("the filter kept no rules; nothing was installed".into());
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    progress("Checking and indexing rules");
    let source_note = format!(
        "{}\nRevision: {} ({})\nLicense: {}\n{}\nFetched from:\n{}\n",
        pack.name,
        pack.revision,
        pack.revision_kind,
        pack.license,
        pack.license_url,
        pack.sources
            .iter()
            .map(|source| format!("  {}", source.url))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    fs::write(tree.join("SOURCE.txt"), source_note).map_err(|error| error.to_string())?;
    index_tree(&tree, &pack.engine)?;
    if pack.engine == "yara" {
        compile_yara_tree(&tree)?;
    }
    let indexed = read_index(&tree)?;
    let helpers = indexed.iter().filter(|rule| rule.helper).count() as u64;
    let rules = indexed.len() as u64 - helpers;
    if matches!(pack.filter, SourceFilter::Copy { .. }) {
        report.kept = rules;
        report.helpers = helpers;
    }
    let mut summary = report.lines();
    if !report.examples.is_empty() {
        summary.push(format!(
            "Example compile errors: {}",
            report.examples.join(" | ")
        ));
    }
    let digest = pack.plan_digest(options);
    let mut all_files: Vec<SourceFile> = kept_files.into_iter().map(|(_, file)| file).collect();
    all_files.sort_by(|a, b| a.path.cmp(&b.path));
    let provenance = SourceProvenance {
        homepage: pack.homepage.clone(),
        license: pack.license.clone(),
        license_url: pack.license_url.clone(),
        revision: pack.revision.clone(),
        revision_kind: pack.revision_kind.clone(),
        options: options.iter().cloned().collect(),
        plan_digest: digest.clone(),
        fetched_unix: now_unix(),
        sources: fetched,
        kept_rules: report.kept,
        dropped_rules: report.dropped_total(),
        summary,
        notes,
    };
    let entry = PackEntry {
        id: pack.id.clone(),
        engine: pack.engine.clone(),
        name: pack.name.clone(),
        version: version.to_owned(),
        upstream_revision: pack.revision.clone(),
        upstream_url: pack.homepage.clone(),
        download_url: pack.sources[0].url.clone(),
        sha256: digest.clone(),
        size: provenance.sources.iter().map(|source| source.size).sum(),
        app: pack.app.clone(),
        engine_requirement: pack.engine_requirement.clone(),
        rules,
        helpers,
        license: pack.license.clone(),
        evidence: pack.evidence.clone(),
        limits: pack.limits.clone(),
    };
    let manifest = serde_json::json!({
        "pack": entry,
        "installed_archive_sha256": digest,
        "source": provenance,
        "source_files": all_files,
    });
    crate::storage::atomic_json(&tree.join("manifest.json"), &manifest)?;
    Ok(Built { entry, provenance })
}

fn read_text(extracted: &Path, key: &str) -> Result<String, String> {
    let bytes = fs::read(extracted.join(key)).map_err(|error| error.to_string())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Unlisted files a rolling download may add under its rule paths.
fn unlisted_ok(filter: &SourceFilter, path: &str) -> bool {
    match filter {
        SourceFilter::Copy { extensions, .. } => {
            extensions.iter().any(|ext| path.ends_with(ext.as_str()))
        }
        SourceFilter::Sigma(_) => path.ends_with(".yml") || path.ends_with(".yaml"),
        SourceFilter::YaraForge(_) => path.ends_with(".yar"),
    }
}

fn human_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{} KB", bytes.div_ceil(1024))
    }
}

/// The provenance recorded in a retained version's manifest.
pub(super) fn retained_source(version_dir: &Path) -> Result<Option<SourceProvenance>, String> {
    let data = fs::read(version_dir.join("manifest.json")).map_err(|error| error.to_string())?;
    let value: Value = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    match value.get("source") {
        None | Some(Value::Null) => Ok(None),
        Some(source) => serde_json::from_value(source.clone())
            .map(Some)
            .map_err(|error| format!("retained manifest provenance: {error}")),
    }
}

/// The catalog entry that updates an installed source pack, when the catalog
/// pins a different revision or the filters changed.
pub fn source_update<'a>(catalog: &'a Catalog, pack: &InstalledPack) -> Option<&'a SourcePack> {
    let entry = catalog.sources.iter().find(|entry| entry.id == pack.id)?;
    let options: BTreeSet<String> = pack
        .source
        .as_ref()
        .map(|source| source.options.iter().cloned().collect())
        .unwrap_or_default();
    (entry.version(&options) != pack.version).then_some(entry)
}
