// SPDX-License-Identifier: GPL-3.0-only
//! The abuse.ch Suricata rule packs, which abuse.ch regenerates in place about
//! every five minutes. Each is a pack of the IDS engine, installed through the
//! same path as any source pack, with two differences that come from the
//! publisher: the pin is the snapshot that was just downloaded (its SHA-256
//! and its "Last updated" stamp), and a check for a newer snapshot is a
//! download of the file, made at most once in [`MIN_CHECK_SECONDS`] seconds
//! per pack. ThreatFox and URLhaus send their files only with the abuse.ch
//! Auth-Key. The "aggressive" variants, which abuse.ch itself warns produce
//! false positives, are not offered.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// abuse.ch rebuilds these files about every five minutes; a pack is not asked
/// for more often than that.
pub const MIN_CHECK_SECONDS: u64 = 300;
/// Largest rules file accepted.
const MAX_RULES_BYTES: u64 = 32 * 1024 * 1024;
const CHECKS_FILE: &str = "checks.json";

/// One pack abuse.ch publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivePack {
    /// The pack id; `abuse-ch-sslbl` is the certificate pack shipped earlier.
    pub id: &'static str,
    pub name: &'static str,
    /// The rules file.
    pub url: &'static str,
    pub homepage: &'static str,
    pub license: &'static str,
    pub license_url: &'static str,
    /// The download needs the abuse.ch Auth-Key.
    pub needs_key: bool,
    /// What the pack matches, in words.
    pub matches: &'static str,
    pub limits: &'static [&'static str],
}

const CC0: &str = "CC0 1.0: abuse.ch states the dataset may be used for commercial and non-commercial purposes without limitation.";
const FAIR_USE: &str = "abuse.ch fair use: free to use with an Auth-Key; see the project's terms.";
const REGENERATED: &str = "abuse.ch regenerates this file about every five minutes, so the pack is a snapshot; Check for updates compares it with the live file.";

/// The packs, in the order they are listed.
pub const LIVE_PACKS: [LivePack; 6] = [
    LivePack {
        id: "abuse-ch-threatfox",
        name: "abuse.ch ThreatFox",
        url: "https://threatfox.abuse.ch/downloads/threatfox_suricata.rules",
        homepage: "https://threatfox.abuse.ch/",
        license: FAIR_USE,
        license_url: "https://threatfox.abuse.ch/faq/",
        needs_key: true,
        matches: "botnet C2 IP:port, domains and URLs reported to ThreatFox",
        limits: &[
            REGENERATED,
            "Entries expire after six months, so the list stays short.",
        ],
    },
    LivePack {
        id: "abuse-ch-urlhaus",
        name: "abuse.ch URLhaus",
        url: "https://urlhaus.abuse.ch/downloads/urlhaus_suricata.rules",
        homepage: "https://urlhaus.abuse.ch/",
        license: FAIR_USE,
        license_url: "https://urlhaus.abuse.ch/api/",
        needs_key: true,
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
        matches: "TLS connections to botnet C2 servers by IP:port",
        limits: &[
            REGENERATED,
            "The aggressive variant is not offered because abuse.ch warns of false positives.",
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
        matches: "TLS clients by JA3 fingerprint",
        limits: &[
            REGENERATED,
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

/// Describe a downloaded file, or why it is not a rules file.
fn inspect(path: &Path, now_unix: u64) -> Result<Checked, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let rules = rule_count(&text);
    if rules == 0 {
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

/// Look for a newer snapshot: download the file unless the last look was less
/// than [`MIN_CHECK_SECONDS`] ago, in which case that answer is returned and
/// nothing is requested. The bool says whether the network was used.
#[allow(clippy::too_many_arguments)]
pub fn check_live(
    data_dir: &Path,
    pack: &LivePack,
    key_present: bool,
    fetcher: &dyn Fetcher,
    now_unix: u64,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<(Checked, bool), String> {
    if pack.needs_key && !key_present {
        return Err(format!(
            "{} needs the abuse.ch Auth-Key; set it in Tools > API keys",
            pack.name
        ));
    }
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
        fetcher.fetch(pack.url, &file, MAX_RULES_BYTES, cancel, &mut |_| {})?;
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let checked = inspect(&file, now_unix)?;
        crate::storage::private_dir(&live_dir(data_dir)).map_err(|error| error.to_string())?;
        fs::rename(&file, cache_path(data_dir, pack)).map_err(|error| error.to_string())?;
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
            format!("{}: {error}", pack.name)
        }
    })
}

/// The source pack for one snapshot.
pub fn live_source_pack(pack: &LivePack, checked: &Checked) -> SourcePack {
    let file = pack
        .url
        .rsplit('/')
        .next()
        .unwrap_or("rules.rules")
        .to_owned();
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
            url: pack.url.to_owned(),
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
    key_present: bool,
    fetcher: &dyn Fetcher,
    now_unix: u64,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<SourceInstall, String> {
    let (checked, _) = check_live(
        data_dir,
        pack,
        key_present,
        fetcher,
        now_unix,
        cancel,
        &mut *progress,
    )?;
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
        body: RefCell<Result<String, String>>,
        calls: RefCell<u32>,
    }

    impl Server {
        fn new(body: &str) -> Self {
            Self {
                body: RefCell::new(Ok(body.to_owned())),
                calls: RefCell::new(0),
            }
        }
    }

    impl Fetcher for Server {
        fn fetch(
            &self,
            _url: &str,
            dest: &Path,
            _max: u64,
            _cancel: &AtomicBool,
            _progress: &mut dyn FnMut(u64),
        ) -> Result<(), String> {
            *self.calls.borrow_mut() += 1;
            match &*self.body.borrow() {
                Ok(text) => fs::write(dest, text).map_err(|error| error.to_string()),
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
        let ids: Vec<_> = LIVE_PACKS.iter().map(|pack| pack.id).collect();
        assert!(
            ids.contains(&"abuse-ch-sslbl"),
            "the shipped certificate pack keeps its id"
        );
        for pack in &LIVE_PACKS {
            assert!(!pack.url.contains("aggressive"), "{}", pack.id);
            assert!(https_host(pack.url).is_ok_and(|host| is_abusech_host(&host)));
            assert_eq!(
                pack.needs_key,
                pack.id.ends_with("threatfox") || pack.id.ends_with("urlhaus")
            );
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
        let (first, used) =
            check_live(&dir, pack, false, &server, 1_000, &cancel, &mut quiet).unwrap();
        assert!(used);
        assert_eq!((first.rules, first.stamp.as_str()), (2, "20261022T101500Z"));
        assert_eq!(first.wait(1_100), 200);
        let (again, used) =
            check_live(&dir, pack, false, &server, 1_100, &cancel, &mut quiet).unwrap();
        assert!(!used);
        assert_eq!(again, first);
        assert_eq!(*server.calls.borrow(), 1);
        let (_, used) = check_live(
            &dir,
            pack,
            false,
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
            false,
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
        let (good, _) = check_live(&dir, pack, false, &server, 1_000, &cancel, &mut quiet).unwrap();
        for body in [
            Ok("<html>Too many requests</html>".to_owned()),
            Ok(String::new()),
            Err("download failed: timeout".to_owned()),
        ] {
            *server.body.borrow_mut() = body;
            let error =
                check_live(&dir, pack, false, &server, 5_000, &cancel, &mut quiet).unwrap_err();
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
        let installed =
            install_live(&dir, pack, false, &server, 1_000, &cancel, &mut quiet).unwrap();
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
        *server.body.borrow_mut() = Ok(newer);
        let (_, used) = check_live(&dir, pack, false, &server, 1_100, &cancel, &mut quiet).unwrap();
        assert!(
            !used,
            "the 5-minute rule holds even with a newer file waiting"
        );
        assert_eq!(
            live_states(&dir, &registry())[3].status,
            LiveStatus::Current
        );
        let (_, used) = check_live(&dir, pack, false, &server, 1_400, &cancel, &mut quiet).unwrap();
        assert!(used);
        assert_eq!(
            live_states(&dir, &registry())[3].status,
            LiveStatus::UpdateAvailable
        );
        let updated = install_live(&dir, pack, false, &server, 1_400, &cancel, &mut quiet).unwrap();
        assert!(updated.version.starts_with("20261022T102000Z-"));
        assert_eq!(
            live_states(&dir, &registry())[3].status,
            LiveStatus::Current
        );
        // The same snapshot again is already installed.
        let again = install_live(&dir, pack, false, &server, 1_500, &cancel, &mut quiet).unwrap();
        assert!(again.already_installed);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_install_keeps_the_installed_version() {
        let dir = dir("keep");
        let pack = live_pack("abuse-ch-sslbl-ip").unwrap();
        let server = Server::new(SIP);
        let cancel = AtomicBool::new(false);
        install_live(&dir, pack, false, &server, 1_000, &cancel, &mut quiet).unwrap();
        let before = load_registry(&dir).unwrap().packs[0].version.clone();
        *server.body.borrow_mut() = Err("download failed: Could not resolve host".into());
        let error =
            install_live(&dir, pack, false, &server, 2_000, &cancel, &mut quiet).unwrap_err();
        assert!(error.contains("Could not resolve host"), "{error}");
        assert_eq!(load_registry(&dir).unwrap().packs[0].version, before);
        let _ = fs::remove_dir_all(dir);
    }
}
