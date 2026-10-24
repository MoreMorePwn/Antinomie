// SPDX-License-Identifier: GPL-3.0-only
//! Schema 2 of the rules catalog: sources, not archives.
//!
//! The catalog lists where each rule collection lives upstream, the exact
//! revision it was pinned at, the SHA-256 of every file that is kept and how
//! to filter the files locally. Antinomie hosts only this index; the rules are
//! fetched from their publishers, verified and filtered on this machine.
use super::*;

/// Version of the local filters. It is part of an installed pack's version, so
/// a filter change produces a new version instead of rewriting an old one.
pub const FILTER_REVISION: u32 = 1;

/// Compressed bytes accepted from one source download.
pub const MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
/// Files one source may list.
const MAX_SOURCE_FILES: usize = 8_000;
/// Sources one pack may list.
const MAX_PACK_SOURCES: usize = 64;

const FORMATS: [&str; 3] = ["file", "zip", "tar.gz"];
const REVISION_KINDS: [&str; 3] = ["release", "commit", "rolling"];

/// One rule collection and where to fetch it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePack {
    pub id: String,
    pub engine: String,
    pub name: String,
    /// The publisher's project page.
    pub homepage: String,
    /// What the collection is licensed under, in words.
    pub license: String,
    #[serde(default)]
    pub license_url: String,
    /// The pin: a release tag or date, or a git commit.
    pub revision: String,
    /// `release`, `commit` or `rolling` (the publisher serves no fixed revision).
    pub revision_kind: String,
    pub app: String,
    pub engine_requirement: String,
    /// Approximate rule counts with the default options.
    pub rules: u64,
    #[serde(default)]
    pub helpers: u64,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub limits: Vec<String>,
    pub sources: Vec<SourceFetch>,
    pub filter: SourceFilter,
    /// Choices a person makes per install. All are off unless `default` says so.
    #[serde(default)]
    pub options: Vec<SourceOption>,
    /// Plain-language terms shown before the download, for example a license restriction.
    #[serde(default)]
    pub notices: Vec<String>,
}

/// One HTTPS download: a release asset, a tarball at a commit or a rules file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFetch {
    pub url: String,
    /// `file` (the download is the rule file), `zip` or `tar.gz`.
    pub format: String,
    /// Expected download size in bytes; the download is cut off past it.
    pub size: u64,
    /// SHA-256 of the whole download. Empty when the publisher does not keep
    /// the bytes stable, for example a tarball generated at a commit.
    #[serde(default)]
    pub sha256: String,
    /// The publisher updates this URL in place, so hashes may legitimately
    /// differ later. A difference is recorded, not rejected.
    #[serde(default)]
    pub rolling: bool,
    /// Leading path components removed from archive members.
    #[serde(default)]
    pub strip: u32,
    /// Directories inside the download that hold rules (a trailing slash).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Every file that is kept, with its SHA-256.
    pub files: Vec<SourceFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceOption {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub default: bool,
    /// Shown whenever the option is on.
    #[serde(default)]
    pub warning: String,
}

/// How downloaded files become an installed pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SourceFilter {
    /// Keep files with these extensions and the named support files.
    Copy {
        #[serde(default)]
        extensions: Vec<String>,
        #[serde(default)]
        support: Vec<String>,
    },
    /// Split a YARA-Forge package by source repository and apply licenses.
    YaraForge(YaraForgeFilter),
    /// Keep Sigma rules whose log source is listed.
    Sigma(SigmaFilter),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraForgeFilter {
    /// A rule's own `license` meta is allowed when it starts with one of these.
    pub allowed_licenses: Vec<String>,
    /// Repository licenses that allow local use of the rules.
    pub allowed_repository_licenses: Vec<String>,
    /// Repository URL to its license. `none` means the repository has no
    /// license file; a repository missing from this table is treated the same way.
    pub repository_licenses: BTreeMap<String, RepositoryLicense>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryLicense {
    /// An SPDX identifier, or `none`.
    pub license: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaFilter {
    pub keep: Vec<SigmaLogsource>,
}

/// A log source a pack keeps. Empty fields match anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigmaLogsource {
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub service: String,
}

/// Hosts a redirect from `host` may reach. Everything else is refused.
pub fn redirect_hosts(host: &str) -> Vec<&'static str> {
    const GITHUB: [&str; 5] = [
        "github.com",
        "codeload.github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    ];
    const HUGGING_FACE: [&str; 4] = [
        "huggingface.co",
        "cdn-lfs.huggingface.co",
        "cas-bridge.xethub.hf.co",
        "cdn-lfs-us-1.hf.co",
    ];
    if GITHUB.contains(&host) {
        GITHUB.to_vec()
    } else if HUGGING_FACE.contains(&host) || host.ends_with(".hf.co") {
        let mut hosts = HUGGING_FACE.to_vec();
        hosts.sort_unstable();
        hosts
    } else {
        Vec::new()
    }
}

/// Whether a download from `origin` may be redirected to `target`.
pub fn host_allowed(origin: &str, target: &str) -> bool {
    target == origin
        || redirect_hosts(origin).contains(&target)
        || (redirect_hosts(origin).contains(&"huggingface.co") && target.ends_with(".hf.co"))
}

/// The host of an HTTPS URL, or why it is not acceptable.
pub fn https_host(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("{} is not an https URL", super::redact_url(url)))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty()
        || authority.contains('@')
        || authority.contains(':')
        || authority.starts_with('.')
        || authority.ends_with('.')
        || !authority
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        || !authority.contains('.')
    {
        return Err(format!(
            "{} has an unacceptable host",
            super::redact_url(url)
        ));
    }
    if url.chars().any(|c| c.is_control() || c == ' ' || c == '\\') {
        return Err(format!(
            "{} contains unacceptable characters",
            super::redact_url(url)
        ));
    }
    Ok(authority.to_owned())
}

impl SourcePack {
    /// Every host this pack's downloads contact, including the redirect
    /// targets a download may be served from.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts = BTreeSet::new();
        for source in &self.sources {
            if let Ok(host) = https_host(&source.url) {
                for target in redirect_hosts(&host) {
                    hosts.insert(target.to_owned());
                }
                hosts.insert(host);
            }
        }
        hosts.into_iter().collect()
    }

    /// Hosts named in the catalog URLs themselves, without redirect targets.
    pub fn primary_hosts(&self) -> Vec<String> {
        let hosts: BTreeSet<_> = self
            .sources
            .iter()
            .filter_map(|source| https_host(&source.url).ok())
            .collect();
        hosts.into_iter().collect()
    }

    pub fn download_size(&self) -> u64 {
        self.sources.iter().map(|source| source.size).sum()
    }

    /// Option ids on when the person changes nothing.
    pub fn default_options(&self) -> BTreeSet<String> {
        self.options
            .iter()
            .filter(|option| option.default)
            .map(|option| option.id.clone())
            .collect()
    }

    /// Digest of everything that decides what an install produces: the pinned
    /// inputs, the filter, the chosen options and the filter revision.
    pub fn plan_digest(&self, options: &BTreeSet<String>) -> String {
        let plan = serde_json::json!({
            "plan": 1,
            "filter_revision": FILTER_REVISION,
            "id": self.id,
            "revision": self.revision,
            "filter": self.filter,
            "options": options,
            "sources": self.sources.iter().map(|source| serde_json::json!({
                "url": source.url,
                "format": source.format,
                "strip": source.strip,
                "sha256": source.sha256,
                "files": source.files,
            })).collect::<Vec<_>>(),
        });
        format!("{:x}", Sha256::digest(plan.to_string().as_bytes()))
    }

    /// The installed version name for these options.
    pub fn version(&self, options: &BTreeSet<String>) -> String {
        format!("{}-{}", self.revision, &self.plan_digest(options)[..12])
    }

    /// Option ids that are not declared by this pack.
    pub fn unknown_options(&self, options: &BTreeSet<String>) -> Vec<String> {
        options
            .iter()
            .filter(|id| !self.options.iter().any(|option| &option.id == *id))
            .cloned()
            .collect()
    }
}

pub(super) fn validate_source_pack(value: &Value) -> Result<SourcePack, String> {
    let pack: SourcePack = serde_json::from_value(value.clone()).map_err(|error| {
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("a pack entry");
        format!("{id}: {error}")
    })?;
    check_source_pack(&pack).map_err(|error| format!("{}: {error}", pack.id))?;
    Ok(pack)
}

pub(super) fn check_source_pack(pack: &SourcePack) -> Result<(), String> {
    if !valid_id(&pack.id) {
        return Err("the id is not a stable identifier".into());
    }
    if !ENGINES.contains(&pack.engine.as_str()) {
        return Err(format!("unknown rules engine {}", pack.engine));
    }
    for (label, value) in [
        ("name", &pack.name),
        ("license", &pack.license),
        ("app", &pack.app),
        ("engine_requirement", &pack.engine_requirement),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{label} is empty"));
        }
    }
    https_host(&pack.homepage)?;
    if !pack.license_url.is_empty() {
        https_host(&pack.license_url)?;
    }
    path_component(&pack.revision, "revision")?;
    if !REVISION_KINDS.contains(&pack.revision_kind.as_str()) {
        return Err(format!("unknown revision kind {}", pack.revision_kind));
    }
    if pack.sources.is_empty() || pack.sources.len() > MAX_PACK_SOURCES {
        return Err("a pack lists between 1 and 64 sources".into());
    }
    let mut urls = BTreeSet::new();
    for source in &pack.sources {
        check_source_fetch(source)?;
        if !urls.insert(source.url.as_str()) {
            return Err(format!("{} is listed twice", source.url));
        }
    }
    let mut options = BTreeSet::new();
    for option in &pack.options {
        if !valid_id(&option.id) || option.label.trim().is_empty() {
            return Err(format!("option {:?} is not valid", option.id));
        }
        if !options.insert(option.id.as_str()) {
            return Err(format!("option {} is listed twice", option.id));
        }
    }
    match (&pack.filter, pack.engine.as_str()) {
        (SourceFilter::YaraForge(filter), "yara") => {
            if filter.allowed_licenses.is_empty() {
                return Err("the YARA filter allows no licenses".into());
            }
            for url in filter.repository_licenses.keys() {
                https_host(url)?;
            }
        }
        (SourceFilter::YaraForge(_), _) => {
            return Err("the YARA-Forge filter belongs to a YARA pack".into());
        }
        (SourceFilter::Sigma(filter), "sigma") => {
            if filter.keep.is_empty() {
                return Err("the Sigma filter keeps no log source".into());
            }
        }
        (SourceFilter::Sigma(_), _) => {
            return Err("the Sigma filter belongs to a Sigma pack".into());
        }
        (
            SourceFilter::Copy {
                extensions,
                support,
            },
            _,
        ) => {
            if extensions.is_empty() && support.is_empty() {
                return Err("the copy filter keeps nothing".into());
            }
        }
    }
    Ok(())
}

fn check_source_fetch(source: &SourceFetch) -> Result<(), String> {
    https_host(&source.url)?;
    if !FORMATS.contains(&source.format.as_str()) {
        return Err(format!("unknown download format {}", source.format));
    }
    if source.size == 0 || source.size > MAX_SOURCE_BYTES {
        return Err(format!("{} has an unacceptable size", source.url));
    }
    if !source.sha256.is_empty() && !is_sha256(&source.sha256) {
        return Err(format!("{} checksum is not SHA-256", source.url));
    }
    if source.files.is_empty() && !source.rolling {
        return Err(format!("{} lists no files to keep", source.url));
    }
    if source.files.len() > MAX_SOURCE_FILES {
        return Err(format!("{} lists too many files", source.url));
    }
    if source.format == "file" && (source.files.len() != 1 || source.strip != 0) {
        return Err(format!("{} is a single file download", source.url));
    }
    if source.strip > 8 {
        return Err(format!("{} strips too many path components", source.url));
    }
    let mut seen = BTreeSet::new();
    for file in &source.files {
        checked_member_path(&file.path)?;
        if !is_sha256(&file.sha256) {
            return Err(format!("{} checksum is not SHA-256", file.path));
        }
        if !seen.insert(file.path.as_str()) {
            return Err(format!("{} is listed twice", file.path));
        }
    }
    for prefix in &source.paths {
        checked_member_path(prefix.trim_end_matches('/'))?;
    }
    if source.rolling && source.paths.is_empty() && source.format != "file" {
        return Err(format!("{} is rolling and names no rule paths", source.url));
    }
    Ok(())
}

pub(super) fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// A relative path with only normal components.
pub(super) fn checked_member_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 400
        || path.contains('\\')
        || path.contains('\0')
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(format!("{path:?} is not a safe relative path"));
    }
    Ok(())
}
