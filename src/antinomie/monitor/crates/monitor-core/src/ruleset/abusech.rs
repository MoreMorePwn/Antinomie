// SPDX-License-Identifier: GPL-3.0-only
//! The abuse.ch Suricata rule packs, which abuse.ch regenerates in place about
//! every five minutes. Each is a pack of the IDS engine, installed through the
//! same path as any source pack, with two differences that come from the
//! publisher: the pin is the snapshot that was just downloaded (its SHA-256
//! and its "Last updated" stamp), and a check for a newer snapshot is a
//! download of the file, made at most once in [`MIN_CHECK_SECONDS`] seconds
//! per pack. ThreatFox and URLhaus send their packs as `.tar.gz` archives and
//! only with the abuse.ch Auth-Key, which is part of the URL path; the key is
//! kept out of every message and every stored URL. The `.rules` members of an
//! archive are joined into one rules text, which is what is cached, pinned and
//! installed. The "aggressive" variants, which abuse.ch itself warns produce
//! false positives, are not offered.
use super::*;
use crate::api_keys::{self, Secret};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

/// abuse.ch rebuilds these files about every five minutes; a pack is not asked
/// for more often than that.
pub const MIN_CHECK_SECONDS: u64 = 300;
/// Largest rules text accepted, as a download and after unpacking.
const MAX_RULES_BYTES: u64 = 32 * 1024 * 1024;
/// Largest download (an archive of rules) accepted.
const MAX_DOWNLOAD_BYTES: u64 = 32 * 1024 * 1024;
/// Entries read from one archive before it is refused.
const MAX_ARCHIVE_ENTRIES: usize = 2_000;
/// Rules files taken from one archive.
const MAX_RULES_FILES: usize = 64;
const CHECKS_FILE: &str = "checks.json";

/// One pack abuse.ch publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivePack {
    /// The pack id; `abuse-ch-sslbl` is the certificate pack shipped earlier.
    pub id: &'static str,
    pub name: &'static str,
    /// The rules file or archive; `{key}` is where the Auth-Key goes.
    pub url: &'static str,
    pub homepage: &'static str,
    pub license: &'static str,
    pub license_url: &'static str,
    /// The download needs the abuse.ch Auth-Key.
    pub needs_key: bool,
    /// abuse.ch has stopped filling this pack: an empty file is an answer,
    /// not a failure.
    pub retired_if_empty: bool,
    /// What the pack matches, in words.
    pub matches: &'static str,
    pub limits: &'static [&'static str],
}

impl LivePack {
    /// The URL to request, with the key in its place.
    pub fn url_for(&self, key: &Secret) -> Result<String, String> {
        crate::ioc::feeds::url_with_key(self.url, self.needs_key, key)
    }

    /// The URL as it may be shown or stored: `****` for the key.
    pub fn url_display(&self) -> String {
        self.url.replace("{key}", "****")
    }

    /// Whether `url` is this pack's URL with some key in it.
    pub fn owns(&self, url: &str) -> bool {
        crate::ioc::feeds::template_owns(self.url, url)
    }

    /// The name of the rules file the pack is stored as.
    fn rules_file(&self) -> String {
        let last = self.url.rsplit('/').next().unwrap_or("rules.rules");
        let stem = ["tar.gz", "zip", "rules"]
            .iter()
            .find_map(|ext| last.strip_suffix(&format!(".{ext}")))
            .unwrap_or(last);
        format!("{stem}.rules")
    }
}

const CC0: &str = "CC0 1.0: abuse.ch states the dataset may be used for commercial and non-commercial purposes without limitation.";
const FAIR_USE: &str = "abuse.ch fair use: free to use with an Auth-Key; see the project's terms.";
const REGENERATED: &str = "abuse.ch regenerates this file about every five minutes, so the pack is a snapshot; Check for updates compares it with the live file.";

/// The packs, in the order they are listed.
pub const LIVE_PACKS: [LivePack; 6] = [
    LivePack {
        id: "abuse-ch-threatfox",
        name: "abuse.ch ThreatFox",
        url: "https://threatfox-api.abuse.ch/v2/files/exports/{key}/threatfox_suricata.tar.gz",
        homepage: "https://threatfox.abuse.ch/",
        license: FAIR_USE,
        license_url: "https://threatfox.abuse.ch/faq/",
        needs_key: true,
        retired_if_empty: false,
        matches: "botnet C2 IP:port, domains and URLs reported to ThreatFox",
        limits: &[
            REGENERATED,
            "Entries expire after six months, so the list stays short.",
        ],
    },
    LivePack {
        id: "abuse-ch-urlhaus",
        name: "abuse.ch URLhaus",
        url: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/urlhaus_ids.tar.gz",
        homepage: "https://urlhaus.abuse.ch/",
        license: FAIR_USE,
        license_url: "https://urlhaus.abuse.ch/api/",
        needs_key: true,
        retired_if_empty: false,
        matches: "exact HTTP URLs that serve malware",
        limits: &[
            REGENERATED,
            "Matches the exact URL of a request, so only cleartext HTTP is seen.",
        ],
    },
    LivePack {
        id: "abuse-ch-feodo",
        name: "abuse.ch Feodo Tracker",
        url: "https://feodotracker.abuse.ch/downloads/feodotracker.rules",
        homepage: "https://feodotracker.abuse.ch/",
        license: CC0,
        license_url: "https://feodotracker.abuse.ch/blocklist/",
        needs_key: false,
        retired_if_empty: false,
        matches: "botnet C2 IP:port of the Dridex, Emotet, TrickBot and QakBot families",
        limits: &[
            REGENERATED,
            "The aggressive variant (all IPs ever listed) is not offered because abuse.ch warns of false positives.",
        ],
    },
    LivePack {
        id: "abuse-ch-sslbl-ip",
        name: "abuse.ch SSLBL botnet C2 IPs",
        url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.rules",
        homepage: "https://sslbl.abuse.ch/",
        license: CC0,
        license_url: "https://sslbl.abuse.ch/blacklist/",
        needs_key: false,
        retired_if_empty: true,
        matches: "TLS connections to botnet C2 servers by IP:port",
        limits: &[
            REGENERATED,
            "The aggressive variant is not offered because abuse.ch warns of false positives.",
            "abuse.ch now serves this file with its header and no entries; the Feodo Tracker pack and dataset list botnet C2 IPs.",
        ],
    },
    LivePack {
        id: "abuse-ch-sslbl-ja3",
        name: "abuse.ch SSLBL JA3 fingerprints",
        url: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules",
        homepage: "https://sslbl.abuse.ch/",
        license: CC0,
        license_url: "https://sslbl.abuse.ch/blacklist/",
        needs_key: false,
        retired_if_empty: true,
        matches: "TLS clients by JA3 fingerprint",
        limits: &[
            REGENERATED,
            "abuse.ch now serves this file empty; the JA3 list lives on in the IOC datasets (SSLBL JA3).",
            "Rules that use a JA3 keyword are reported and not loaded when Suricata has no JA3 support.",
        ],
    },
    LivePack {
        id: "abuse-ch-sslbl",
        name: "abuse.ch SSL certificate blacklist",
        url: "https://sslbl.abuse.ch/blacklist/sslblacklist.rules",
        homepage: "https://sslbl.abuse.ch/",
        license: CC0,
        license_url: "https://sslbl.abuse.ch/blacklist/",
        needs_key: false,
        retired_if_empty: false,
        matches: "TLS certificate SHA-1 fingerprints of botnet C2 servers",
        limits: &[
            REGENERATED,
            "Rules that use a JA3 or other TLS fingerprint keyword are reported and not loaded.",
        ],
    },
];

/// The pack with this id.
pub fn live_pack(id: &str) -> Option<&'static LivePack> {
    LIVE_PACKS.iter().find(|pack| pack.id == id)
}

/// A downloaded snapshot of a rules file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checked {
    /// Unix seconds when it was downloaded.
    pub at_unix: u64,
    pub sha256: String,
    pub size: u64,
    /// abuse.ch's "Last updated" time of the file as `YYYYMMDDTHHMMSSZ`, or
    /// `snapshot` when the file states none.
    pub stamp: String,
    pub rules: u64,
}

impl Checked {
    /// The pin the pack is installed at: unique to this content.
    pub fn revision(&self) -> String {
        format!("{}-{}", self.stamp, &self.sha256[..8])
    }

    /// Seconds until the pack may be asked for again.
    pub fn wait(&self, now_unix: u64) -> u64 {
        (self.at_unix + MIN_CHECK_SECONDS).saturating_sub(now_unix)
    }
}

/// How an installed pack compares with the last snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveStatus {
    NotInstalled,
    /// Installed, and no newer snapshot has been looked for.
    Unchecked,
    /// The last snapshot is what is installed.
    Current,
    UpdateAvailable,
    /// abuse.ch has stopped filling this pack; its file is empty.
    Retired,
}

/// What the installed copy is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveInstalled {
    pub version: String,
    pub sha256: String,
    pub fetched_unix: u64,
    pub rules: u64,
    pub enabled: bool,
}

#[derive(Clone, Debug)]
pub struct LiveState {
    pub pack: &'static LivePack,
    pub installed: Option<LiveInstalled>,
    pub checked: Option<Checked>,
    pub status: LiveStatus,
}

fn live_dir(data_dir: &Path) -> PathBuf {
    rules_root(data_dir).join("live")
}

fn cache_path(data_dir: &Path, pack: &LivePack) -> PathBuf {
    live_dir(data_dir).join(format!("{}.rules", pack.id))
}

fn read_checks(data_dir: &Path) -> BTreeMap<String, Checked> {
    fs::read(live_dir(data_dir).join(CHECKS_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Every abuse.ch pack with what is installed and the last snapshot looked at.
pub fn live_states(data_dir: &Path, registry: &Registry) -> Vec<LiveState> {
    let checks = read_checks(data_dir);
    LIVE_PACKS
        .iter()
        .map(|pack| {
            let installed = registry
                .packs
                .iter()
                .find(|installed| installed.id == pack.id)
                .map(|installed| LiveInstalled {
                    version: installed.version.clone(),
                    sha256: installed
                        .source
                        .as_ref()
                        .and_then(|source| source.sources.first())
                        .map(|fetched| fetched.download_sha256.clone())
                        .unwrap_or_default(),
                    fetched_unix: installed
                        .source
                        .as_ref()
                        .map_or(0, |source| source.fetched_unix),
                    rules: installed
                        .source
                        .as_ref()
                        .map_or(0, |source| source.kept_rules),
                    enabled: installed.enabled,
                });
            let checked = checks.get(pack.id).cloned();
            let status = match (&installed, &checked) {
                (_, Some(checked)) if pack.retired_if_empty && checked.rules == 0 => {
                    LiveStatus::Retired
                }
                (None, _) => LiveStatus::NotInstalled,
                (Some(_), None) => LiveStatus::Unchecked,
                (Some(installed), Some(checked)) if installed.sha256 == checked.sha256 => {
                    LiveStatus::Current
                }
                (Some(_), Some(_)) => LiveStatus::UpdateAvailable,
            };
            LiveState {
                pack,
                installed,
                checked,
                status,
            }
        })
        .collect()
}

/// The `Last updated` time abuse.ch writes in the file's header.
fn stamp_of(text: &str) -> String {
    for line in text.lines().take(40) {
        let Some(rest) = line.split("Last updated:").nth(1) else {
            continue;
        };
        let digits: String = rest
            .trim()
            .chars()
            .take(19)
            .filter(char::is_ascii_digit)
            .collect();
        if digits.len() == 14 {
            return format!("{}T{}Z", &digits[..8], &digits[8..]);
        }
    }
    "snapshot".into()
}

/// Rules in a file: the non-comment lines that start with an action.
fn rule_count(text: &str) -> u64 {
    text.lines()
        .map(str::trim_start)
        .filter(|line| {
            ["alert ", "drop ", "reject ", "pass "]
                .iter()
                .any(|action| line.starts_with(action))
        })
        .count() as u64
}

/// Describe a rules text, or why it is not one. A pack abuse.ch has retired
/// may be empty or hold only comments; anything else without rules is an error.
fn inspect(path: &Path, now_unix: u64, retired_if_empty: bool) -> Result<Checked, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let rules = rule_count(&text);
    let only_comments = text
        .lines()
        .map(str::trim)
        .all(|line| line.is_empty() || line.starts_with('#'));
    if rules == 0 && !(retired_if_empty && only_comments && bytes.len() < 64 * 1024) {
        let start: String = text.chars().filter(|c| !c.is_control()).take(80).collect();
        return Err(format!(
            "the download holds no rules (it starts with {start:?})"
        ));
    }
    Ok(Checked {
        at_unix: now_unix,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        size: bytes.len() as u64,
        stamp: stamp_of(&text),
        rules,
    })
}

/// A relative archive member path with no `..`, no root and no drive.
fn safe_member(raw: &str) -> bool {
    !raw.is_empty()
        && !raw.starts_with('/')
        && !raw.contains('\\')
        && !raw.contains('\0')
        && !raw.split('/').any(|part| part == "..")
        && !raw.as_bytes().get(1).is_some_and(|b| *b == b':')
}

/// Take one member's bytes if the total stays within the limit.
fn take_member(reader: &mut impl Read, name: &str, total: &mut u64) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    reader
        .take(MAX_RULES_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("{name}: {error}"))?;
    *total = total.saturating_add(data.len() as u64);
    if data.len() as u64 > MAX_RULES_BYTES || *total > MAX_RULES_BYTES {
        return Err("the archive holds more rules text than the limit".into());
    }
    Ok(data)
}

/// The rules text of a download: the file itself, or every `.rules` member of
/// a `.tar.gz` or `.zip` archive joined in name order. Members that are not
/// plain files, that are not `.rules`, or whose path leaves the archive are
/// skipped; sizes and counts are bounded.
fn rules_text(download: &Path) -> Result<Vec<u8>, String> {
    let mut magic = [0u8; 4];
    let read = fs::File::open(download)
        .and_then(|mut file| file.read(&mut magic))
        .map_err(|error| error.to_string())?;
    let magic = &magic[..read];
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total = 0u64;
    if magic.starts_with(&[0x1f, 0x8b]) {
        let file = fs::File::open(download).map_err(|error| error.to_string())?;
        let decoder = flate2::read::GzDecoder::new(file).take(4 * MAX_RULES_BYTES);
        let mut archive = tar::Archive::new(decoder);
        archive.set_preserve_permissions(false);
        let entries = archive
            .entries()
            .map_err(|error| format!("the archive cannot be read: {error}"))?;
        for (seen, entry) in entries.enumerate() {
            if seen >= MAX_ARCHIVE_ENTRIES {
                return Err("the archive holds too many entries".into());
            }
            let mut entry =
                entry.map_err(|error| format!("the archive cannot be read: {error}"))?;
            if entry.header().entry_type() != tar::EntryType::Regular {
                continue;
            }
            let name = entry
                .path()
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .into_owned();
            if !safe_member(&name) || !name.ends_with(".rules") {
                continue;
            }
            if members.len() >= MAX_RULES_FILES {
                return Err("the archive holds too many rules files".into());
            }
            let data = take_member(&mut entry, &name, &mut total)?;
            members.push((name, data));
        }
    } else if magic.starts_with(b"PK") {
        let file = fs::File::open(download).map_err(|error| error.to_string())?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|error| format!("the archive cannot be read: {error}"))?;
        if archive.len() > MAX_ARCHIVE_ENTRIES {
            return Err("the archive holds too many entries".into());
        }
        for at in 0..archive.len() {
            let mut member = archive
                .by_index(at)
                .map_err(|error| format!("the archive cannot be read: {error}"))?;
            let name = member.name().to_owned();
            if !member.is_file()
                || member
                    .unix_mode()
                    .is_some_and(|mode| mode & 0o170000 == 0o120000)
                || !safe_member(&name)
                || !name.ends_with(".rules")
            {
                continue;
            }
            if members.len() >= MAX_RULES_FILES {
                return Err("the archive holds too many rules files".into());
            }
            let data = take_member(&mut member, &name, &mut total)?;
            members.push((name, data));
        }
    } else {
        let mut data = fs::read(download).map_err(|error| error.to_string())?;
        if data.len() as u64 > MAX_RULES_BYTES {
            return Err("the download is larger than the limit".into());
        }
        data.shrink_to_fit();
        return Ok(data);
    }
    if members.is_empty() {
        return Err("the archive holds no .rules file".into());
    }
    members.sort_by(|a, b| a.0.cmp(&b.0));
    let mut joined = Vec::with_capacity(total as usize + members.len());
    for (_, data) in members {
        joined.extend_from_slice(&data);
        if joined.last() != Some(&b'\n') {
            joined.push(b'\n');
        }
    }
    Ok(joined)
}

/// Look for a newer snapshot: download the file unless the last look was less
/// than [`MIN_CHECK_SECONDS`] ago, in which case that answer is returned and
/// nothing is requested. The bool says whether the network was used.
#[allow(clippy::too_many_arguments)]
pub fn check_live(
    data_dir: &Path,
    pack: &LivePack,
    key: &Secret,
    fetcher: &dyn Fetcher,
    now_unix: u64,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<(Checked, bool), String> {
    let url = pack
        .url_for(key)
        .map_err(|error| format!("{}: {error}", pack.name))?;
    let checks = read_checks(data_dir);
    if let Some(last) = checks.get(pack.id)
        && last.wait(now_unix) > 0
        && last.at_unix <= now_unix
        && cache_path(data_dir, pack).is_file()
    {
        return Ok((last.clone(), false));
    }
    let staging = rules_root(data_dir)
        .join("staging")
        .join(crate::storage::unique_id());
    crate::storage::private_dir(&staging).map_err(|error| error.to_string())?;
    let result = (|| {
        let file = staging.join("download");
        progress(&format!("Checking {}", pack.name));
        fetcher.fetch(&url, &file, MAX_DOWNLOAD_BYTES, cancel, &mut |_| {})?;
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let text = staging.join("rules.txt");
        fs::write(&text, rules_text(&file)?).map_err(|error| error.to_string())?;
        let checked = inspect(&text, now_unix, pack.retired_if_empty)?;
        crate::storage::private_dir(&live_dir(data_dir)).map_err(|error| error.to_string())?;
        fs::rename(&text, cache_path(data_dir, pack)).map_err(|error| error.to_string())?;
        let mut checks = read_checks(data_dir);
        checks.insert(pack.id.to_owned(), checked.clone());
        crate::storage::atomic_json(&live_dir(data_dir).join(CHECKS_FILE), &checks)?;
        Ok((checked, true))
    })();
    let _ = fs::remove_dir_all(&staging);
    result.map_err(|error: String| {
        if error == "cancelled" {
            format!("{}: cancelled", pack.name)
        } else {
            let error = api_keys::redact(&redact_url(&error), &[key]);
            format!("{}: {error}", pack.name)
        }
    })
}

/// The source pack for one snapshot.
pub fn live_source_pack(pack: &LivePack, checked: &Checked) -> SourcePack {
    let file = pack.rules_file();
    SourcePack {
        id: pack.id.to_owned(),
        engine: "ids".into(),
        name: pack.name.to_owned(),
        homepage: pack.homepage.to_owned(),
        license: pack.license.to_owned(),
        license_url: pack.license_url.to_owned(),
        revision: checked.revision(),
        revision_kind: "rolling".into(),
        app: ">=0.7.0".into(),
        engine_requirement: "Suricata 7".into(),
        rules: checked.rules,
        helpers: 0,
        evidence: vec!["pcap".into()],
        limits: pack.limits.iter().map(|text| (*text).to_owned()).collect(),
        sources: vec![SourceFetch {
            url: pack.url_display(),
            format: "file".into(),
            size: checked.size.max(1),
            sha256: checked.sha256.clone(),
            rolling: false,
            strip: 0,
            paths: Vec::new(),
            files: vec![SourceFile {
                path: file,
                sha256: checked.sha256.clone(),
            }],
        }],
        filter: SourceFilter::Copy {
            extensions: vec![".rules".into()],
            support: Vec::new(),
        },
        options: Vec::new(),
        notices: Vec::new(),
    }
}

/// Serves the file a check already downloaded, so installing it asks the
/// publisher for nothing more.
struct Cached(PathBuf);

impl Fetcher for Cached {
    fn fetch(
        &self,
        _url: &str,
        dest: &Path,
        max_size: u64,
        _cancel: &AtomicBool,
        _progress: &mut dyn FnMut(u64),
    ) -> Result<(), String> {
        let size = fs::metadata(&self.0)
            .map_err(|error| format!("{}: {error}", self.0.display()))?
            .len();
        if size > max_size {
            return Err("the checked file is larger than expected".into());
        }
        fs::copy(&self.0, dest)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Install (or update to) the newest snapshot. A snapshot looked at less than
/// five minutes ago is installed without another request; an older one is
/// fetched first. The previous version stays selected if anything fails.
#[allow(clippy::too_many_arguments)]
pub fn install_live(
    data_dir: &Path,
    pack: &LivePack,
    key: &Secret,
    fetcher: &dyn Fetcher,
    now_unix: u64,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<SourceInstall, String> {
    let (checked, _) = check_live(
        data_dir,
        pack,
        key,
        fetcher,
        now_unix,
        cancel,
        &mut *progress,
    )?;
    if pack.retired_if_empty && checked.rules == 0 {
        return Err(format!(
            "{} is retired upstream: abuse.ch now serves an empty rules file, so there is nothing to install",
            pack.name
        ));
    }
    let cache = cache_path(data_dir, pack);
    let have = crate::storage::sha256_file_hex(&cache)?;
    if have != checked.sha256 {
        return Err(format!(
            "{}: the checked file changed on disk; check again",
            pack.name
        ));
    }
    let source = live_source_pack(pack, &checked);
    install_source(
        data_dir,
        &source,
        &BTreeSet::new(),
        &Cached(cache),
        cancel,
        progress,
    )
    .map_err(|error| format!("{} was not installed: {error}", pack.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const SIP: &str = "# abuse.ch SSLBL botnet C2 IP rules (fixture)\n# Last updated: 2026-10-22 10:15:00 UTC\n\
alert tls $HOME_NET any -> [203.0.113.45] 443 (msg:\"ABUSE.ch Botnet C2 (Gafgyt)\"; flow:established,to_server; reference:url,sslbl.abuse.ch/ip/203.0.113.45; sid:902202; rev:1;)\n\
alert tls $HOME_NET any -> [198.51.100.23] 8443 (msg:\"ABUSE.ch Botnet C2 (QakBot)\"; flow:established,to_server; sid:902203; rev:1;)\n";

    struct Server {
        body: RefCell<Result<Vec<u8>, String>>,
        calls: RefCell<u32>,
        urls: RefCell<Vec<String>>,
    }

    impl Server {
        fn new(body: &str) -> Self {
            Self::bytes(body.as_bytes().to_vec())
        }

        fn bytes(body: Vec<u8>) -> Self {
            Self {
                body: RefCell::new(Ok(body)),
                calls: RefCell::new(0),
                urls: RefCell::new(Vec::new()),
            }
        }

        fn say(&self, body: Result<String, String>) {
            *self.body.borrow_mut() = body.map(String::into_bytes);
        }
    }

    impl Fetcher for Server {
        fn fetch(
            &self,
            url: &str,
            dest: &Path,
            _max: u64,
            _cancel: &AtomicBool,
            _progress: &mut dyn FnMut(u64),
        ) -> Result<(), String> {
            *self.calls.borrow_mut() += 1;
            self.urls.borrow_mut().push(url.to_owned());
            match &*self.body.borrow() {
                Ok(bytes) => fs::write(dest, bytes).map_err(|error| error.to_string()),
                Err(error) => Err(error.clone()),
            }
        }
    }

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ant-live-{name}-{}", crate::storage::unique_id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn quiet(_: &str) {}

    #[test]
    fn the_pack_table_matches_the_card() {
        assert_eq!(LIVE_PACKS.len(), 6);
        assert_eq!(
            LIVE_PACKS
                .iter()
                .filter(|pack| pack.retired_if_empty)
                .map(|pack| pack.id)
                .collect::<Vec<_>>(),
            ["abuse-ch-sslbl-ip", "abuse-ch-sslbl-ja3"]
        );
        let ids: Vec<_> = LIVE_PACKS.iter().map(|pack| pack.id).collect();
        assert!(
            ids.contains(&"abuse-ch-sslbl"),
            "the shipped certificate pack keeps its id"
        );
        for pack in &LIVE_PACKS {
            assert!(!pack.url.contains("aggressive"), "{}", pack.id);
            assert!(https_host(&pack.url_display()).is_ok_and(|host| is_abusech_host(&host)));
            assert_eq!(
                pack.needs_key,
                pack.id.ends_with("threatfox") || pack.id.ends_with("urlhaus")
            );
            assert_eq!(pack.url.contains("{key}"), pack.needs_key, "{}", pack.id);
            assert!(!pack.url_display().contains("{key}"));
            assert!(pack.rules_file().ends_with(".rules"), "{}", pack.id);
            let source = live_source_pack(
                pack,
                &Checked {
                    at_unix: 0,
                    sha256: "ab".repeat(32),
                    size: 10,
                    stamp: "snapshot".into(),
                    rules: 1,
                },
            );
            check_source_pack(&source).unwrap();
        }
    }

    #[test]
    fn a_header_stamp_and_the_rule_count_are_read() {
        assert_eq!(stamp_of(SIP), "20261022T101500Z");
        assert_eq!(
            stamp_of("alert tcp any any -> any any (sid:1;)"),
            "snapshot"
        );
        assert_eq!(rule_count(SIP), 2);
        assert_eq!(rule_count("# alert is only a comment\n"), 0);
    }

    #[test]
    fn a_check_downloads_once_and_not_again_within_five_minutes() {
        let dir = dir("throttle");
        let pack = live_pack("abuse-ch-sslbl-ip").unwrap();
        let server = Server::new(SIP);
        let cancel = AtomicBool::new(false);
        let (first, used) = check_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_000,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert!(used);
        assert_eq!((first.rules, first.stamp.as_str()), (2, "20261022T101500Z"));
        assert_eq!(first.wait(1_100), 200);
        let (again, used) = check_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_100,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert!(!used);
        assert_eq!(again, first);
        assert_eq!(*server.calls.borrow(), 1);
        let (_, used) = check_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_000 + MIN_CHECK_SECONDS,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert!(used, "after five minutes it asks again");
        assert_eq!(*server.calls.borrow(), 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_pack_that_needs_the_key_is_refused_before_any_request() {
        let dir = dir("key");
        let pack = live_pack("abuse-ch-threatfox").unwrap();
        let server = Server::new(SIP);
        let error = check_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1,
            &AtomicBool::new(false),
            &mut quiet,
        )
        .unwrap_err();
        assert!(error.contains("needs the abuse.ch Auth-Key"), "{error}");
        assert_eq!(*server.calls.borrow(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bad_download_is_refused_and_the_last_snapshot_stays() {
        let dir = dir("bad");
        let pack = live_pack("abuse-ch-sslbl-ip").unwrap();
        let server = Server::new(SIP);
        let cancel = AtomicBool::new(false);
        let (good, _) = check_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_000,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        for body in [
            Ok("<html>Too many requests</html>".to_owned()),
            Err("download failed: timeout".to_owned()),
        ] {
            server.say(body);
            let error = check_live(
                &dir,
                pack,
                &Secret::default(),
                &server,
                5_000,
                &cancel,
                &mut quiet,
            )
            .unwrap_err();
            assert!(
                error.starts_with("abuse.ch SSLBL botnet C2 IPs:"),
                "{error}"
            );
        }
        assert_eq!(read_checks(&dir).get(pack.id), Some(&good));
        assert_eq!(
            crate::storage::sha256_file_hex(&cache_path(&dir, pack)).unwrap(),
            good.sha256
        );
        // An empty file is a refused download for a pack abuse.ch still fills,
        // while the retired SSLBL IP pack answers with one.
        let live = live_pack("abuse-ch-sslbl").unwrap();
        let empty = Server::new("");
        let error = check_live(
            &dir,
            live,
            &Secret::default(),
            &empty,
            5_000,
            &cancel,
            &mut quiet,
        )
        .unwrap_err();
        assert!(
            error.starts_with("abuse.ch SSL certificate blacklist:"),
            "{error}"
        );
        let (retired, _) = check_live(
            &dir,
            pack,
            &Secret::default(),
            &empty,
            9_000,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert_eq!(retired.rules, 0, "a header-only file is the retired answer");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn install_then_update_on_demand_with_age_and_status() {
        let dir = dir("install");
        let pack = live_pack("abuse-ch-sslbl-ip").unwrap();
        let server = Server::new(SIP);
        let cancel = AtomicBool::new(false);
        let registry = || load_registry(&dir).unwrap();
        assert_eq!(
            live_states(&dir, &registry())[3].status,
            LiveStatus::NotInstalled
        );
        let installed = install_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_000,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert_eq!(installed.rules, 2);
        assert!(!installed.already_installed);
        assert_eq!(
            *server.calls.borrow(),
            1,
            "install used the checked file, not a second request"
        );
        let state = &live_states(&dir, &registry())[3];
        assert_eq!(state.status, LiveStatus::Current);
        let shown = state.installed.as_ref().unwrap();
        assert!(
            shown.version.starts_with("20261022T101500Z-"),
            "{}",
            shown.version
        );
        assert_eq!(shown.rules, 2);
        assert!(shown.fetched_unix > 0);
        // abuse.ch publishes a new snapshot.
        let newer = SIP
            .replace("10:15:00", "10:20:00")
            .replace("sid:902203", "sid:902204");
        server.say(Ok(newer));
        let (_, used) = check_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_100,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert!(
            !used,
            "the 5-minute rule holds even with a newer file waiting"
        );
        assert_eq!(
            live_states(&dir, &registry())[3].status,
            LiveStatus::Current
        );
        let (_, used) = check_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_400,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert!(used);
        assert_eq!(
            live_states(&dir, &registry())[3].status,
            LiveStatus::UpdateAvailable
        );
        let updated = install_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_400,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert!(updated.version.starts_with("20261022T102000Z-"));
        assert_eq!(
            live_states(&dir, &registry())[3].status,
            LiveStatus::Current
        );
        // The same snapshot again is already installed.
        let again = install_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_500,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        assert!(again.already_installed);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_install_keeps_the_installed_version() {
        let dir = dir("keep");
        let pack = live_pack("abuse-ch-sslbl-ip").unwrap();
        let server = Server::new(SIP);
        let cancel = AtomicBool::new(false);
        install_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            1_000,
            &cancel,
            &mut quiet,
        )
        .unwrap();
        let before = load_registry(&dir).unwrap().packs[0].version.clone();
        server.say(Err("download failed: Could not resolve host".into()));
        let error = install_live(
            &dir,
            pack,
            &Secret::default(),
            &server,
            2_000,
            &cancel,
            &mut quiet,
        )
        .unwrap_err();
        assert!(error.contains("Could not resolve host"), "{error}");
        assert_eq!(load_registry(&dir).unwrap().packs[0].version, before);
        let _ = fs::remove_dir_all(dir);
    }

    const KEY: &str = "abc123-very-secret-9f3a";

    fn key() -> Secret {
        Secret::new(KEY)
    }

    fn rule(sid: u32) -> String {
        format!(
            "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ABUSE.ch fixture\"; sid:{sid}; rev:1;)\n"
        )
    }

    /// A `.tar.gz` of `(name, kind, bytes)`: kind `f` file, `l` symlink.
    fn tar_gz(entries: &[(&str, char, Vec<u8>)]) -> Vec<u8> {
        let mut raw = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut raw);
            for (name, kind, data) in entries {
                let mut header = tar::Header::new_gnu();
                // Written straight into the header so a `..` path can be made.
                header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
                header.set_mode(0o644);
                if *kind == 'l' {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_link_name("/etc/passwd").unwrap();
                    header.set_size(0);
                    header.set_cksum();
                    builder.append(&header, std::io::empty()).unwrap();
                } else {
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(data.len() as u64);
                    header.set_cksum();
                    builder.append(&header, data.as_slice()).unwrap();
                }
            }
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &raw).unwrap();
        gz.finish().unwrap()
    }

    fn file(name: &str, text: &str) -> (String, char, Vec<u8>) {
        (name.to_owned(), 'f', text.as_bytes().to_vec())
    }

    fn pick(archive: Vec<u8>) -> Result<String, String> {
        let dir = dir("unpack");
        let path = dir.join("download");
        fs::write(&path, archive).unwrap();
        let result = rules_text(&path).map(|bytes| String::from_utf8(bytes).unwrap());
        let _ = fs::remove_dir_all(dir);
        result
    }

    fn entries(list: &[(String, char, Vec<u8>)]) -> Vec<u8> {
        let borrowed: Vec<(&str, char, Vec<u8>)> = list
            .iter()
            .map(|(name, kind, data)| (name.as_str(), *kind, data.clone()))
            .collect();
        tar_gz(&borrowed)
    }

    #[test]
    fn a_tar_gz_gives_its_rules_files_joined_and_nothing_else() {
        let archive = entries(&[
            file("pack/b.rules", &rule(2)),
            file("pack/a.rules", &rule(1)),
            file("pack/README.txt", "not rules"),
            file("pack/threatfox.csv", "x,y"),
            ("pack/link.rules".to_owned(), 'l', Vec::new()),
        ]);
        let text = pick(archive).unwrap();
        assert_eq!(
            text,
            format!("{}{}", rule(1), rule(2)),
            "name order, rules only"
        );
        assert!(!text.contains("not rules"));
    }

    #[test]
    fn an_archive_member_that_leaves_the_archive_is_skipped() {
        let archive = entries(&[
            file("../escape.rules", &rule(9)),
            file("/etc/absolute.rules", &rule(8)),
            file("a/../../up.rules", &rule(7)),
            file("ok.rules", &rule(1)),
        ]);
        assert_eq!(pick(archive).unwrap(), rule(1));
        let only_bad = entries(&[file("../escape.rules", &rule(9))]);
        let error = pick(only_bad).unwrap_err();
        assert!(error.contains("no .rules file"), "{error}");
    }

    #[test]
    fn an_archive_over_the_limits_is_refused() {
        let big = vec![b'#'; (MAX_RULES_BYTES + 1) as usize];
        let error = pick(entries(&[("big.rules".to_owned(), 'f', big)])).unwrap_err();
        assert!(error.contains("more rules text"), "{error}");
        let many: Vec<_> = (0..=MAX_RULES_FILES)
            .map(|n| file(&format!("r{n:03}.rules"), &rule(n as u32)))
            .collect();
        let error = pick(entries(&many)).unwrap_err();
        assert!(error.contains("too many rules files"), "{error}");
        let flood: Vec<_> = (0..=MAX_ARCHIVE_ENTRIES)
            .map(|n| file(&format!("n{n}.txt"), ""))
            .collect();
        let error = pick(entries(&flood)).unwrap_err();
        assert!(error.contains("too many entries"), "{error}");
        let error = pick(vec![0x1f, 0x8b, 1, 2, 3]).unwrap_err();
        assert!(error.contains("cannot be read"), "{error}");
    }

    #[test]
    fn a_zip_gives_its_rules_files_too() {
        use zip::write::SimpleFileOptions;
        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            for (name, text) in [("x/one.rules", rule(5)), ("x/skip.txt", "no".into())] {
                writer
                    .start_file(name, SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut writer, text.as_bytes()).unwrap();
            }
            writer.finish().unwrap();
        }
        assert_eq!(pick(out.into_inner()).unwrap(), rule(5));
    }

    #[test]
    fn a_keyed_pack_is_requested_with_the_key_and_stored_without_it() {
        let dir = dir("keyed");
        let pack = live_pack("abuse-ch-threatfox").unwrap();
        let server = Server::bytes(entries(&[file("threatfox_suricata.rules", SIP)]));
        let cancel = AtomicBool::new(false);
        let installed =
            install_live(&dir, pack, &key(), &server, 1_000, &cancel, &mut quiet).unwrap();
        assert_eq!(installed.rules, 2);
        assert_eq!(
            server.urls.borrow().as_slice(),
            [format!(
                "https://threatfox-api.abuse.ch/v2/files/exports/{KEY}/threatfox_suricata.tar.gz"
            )]
        );
        let registry = load_registry(&dir).unwrap();
        let source = registry.packs[0].source.as_ref().unwrap();
        assert!(
            source.sources[0].url.contains("/exports/****/"),
            "{}",
            source.sources[0].url
        );
        // Nothing the pack wrote under the data directory holds the key.
        fn walk(path: &Path, found: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(path).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, found);
                } else if fs::read(&path)
                    .map(|bytes| String::from_utf8_lossy(&bytes).contains(KEY))
                    .unwrap_or(false)
                {
                    found.push(path);
                }
            }
        }
        let mut found = Vec::new();
        walk(&dir, &mut found);
        assert!(found.is_empty(), "the key was written to {found:?}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_pack_download_never_shows_the_key() {
        let dir = dir("leak");
        let pack = live_pack("abuse-ch-urlhaus").unwrap();
        let url = pack.url_for(&key()).unwrap();
        let server = Server::new("");
        let cancel = AtomicBool::new(false);
        for echo in [
            format!("download failed: {url} answered HTTP 500"),
            format!("curl: (6) Could not resolve host while fetching {KEY}"),
        ] {
            server.say(Err(echo));
            let error =
                check_live(&dir, pack, &key(), &server, 1, &cancel, &mut quiet).unwrap_err();
            assert!(!error.contains(KEY), "{error}");
            assert!(error.starts_with("abuse.ch URLhaus:"), "{error}");
        }
        let error = check_live(
            &dir,
            pack,
            &Secret::new("has space"),
            &server,
            1,
            &cancel,
            &mut quiet,
        )
        .unwrap_err();
        assert!(error.contains("characters a URL cannot carry"), "{error}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn an_empty_ja3_or_ip_pack_is_retired_not_failed() {
        let dir = dir("retired");
        let cancel = AtomicBool::new(false);
        let mut cases = Vec::new();
        for id in ["abuse-ch-sslbl-ja3", "abuse-ch-sslbl-ip"] {
            for body in [
                "",
                "# abuse.ch SSLBL\n# Last updated: 2026-10-22 10:15:00 UTC\n",
            ] {
                cases.push((live_pack(id).unwrap(), body));
            }
        }
        for (pack, body) in cases {
            let server = Server::new(body);
            let (checked, _) = check_live(
                &dir,
                pack,
                &Secret::default(),
                &server,
                1_000,
                &cancel,
                &mut quiet,
            )
            .unwrap();
            assert_eq!(checked.rules, 0);
            let registry = load_registry(&dir).unwrap();
            let state = live_states(&dir, &registry)
                .into_iter()
                .find(|state| state.pack.id == pack.id)
                .unwrap();
            assert_eq!(state.status, LiveStatus::Retired);
            let error = install_live(
                &dir,
                pack,
                &Secret::default(),
                &server,
                1_000,
                &cancel,
                &mut quiet,
            )
            .unwrap_err();
            assert!(error.contains("retired upstream"), "{error}");
            let _ = fs::remove_dir_all(dir.join("rules"));
        }
        // HTML in place of the pack is still an error, and so is an empty
        // file from any other pack.
        let pack = live_pack("abuse-ch-sslbl-ip").unwrap();
        let html = Server::new("<html>Too many requests</html>");
        assert!(
            check_live(
                &dir,
                pack,
                &Secret::default(),
                &html,
                9_000,
                &cancel,
                &mut quiet
            )
            .is_err()
        );
        let other = live_pack("abuse-ch-sslbl").unwrap();
        let empty = Server::new("");
        assert!(
            check_live(
                &dir,
                other,
                &Secret::default(),
                &empty,
                9_000,
                &cancel,
                &mut quiet
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(dir);
    }
}
