// SPDX-License-Identifier: GPL-3.0-only
//! The abuse.ch datasets Antinomie keeps on this machine: which feeds there
//! are, where each is stored, and what is known about the stored copy.
//!
//! Layout under `<data dir>/ioc/`:
//!
//! * `feeds/<id>/meta.json` names the current data file and records when it
//!   was fetched, how many records it holds and its SHA-256. It is the commit
//!   point: a new data file is complete before `meta.json` points at it.
//! * `feeds/<id>/data-<n>.txt` is the feed as plain text (a zip download is
//!   unpacked on the way in).
//! * `feeds/<id>/last-error.json` is the reason the last update failed, until
//!   an update succeeds.
//! * `settings.json` lists the feeds switched off.
//! * `staging/` holds downloads in progress and is emptied afterwards.
use crate::api_keys::Secret;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// A dataset older than this many days gets a warning.
pub const STALE_DAYS: u64 = 14;
const META_FILE: &str = "meta.json";
const ERROR_FILE: &str = "last-error.json";
const SETTINGS_FILE: &str = "settings.json";
const SECONDS_PER_DAY: u64 = 86_400;

/// How a feed is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Comma separated values with `#` comment lines.
    Csv,
    /// Feodo Tracker's JSON array.
    FeodoJson,
}

/// How the feed's terms read, for the Rule manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terms {
    /// CC0: any use.
    Cc0,
    /// Free to use under abuse.ch's fair use terms, with an Auth-Key.
    FairUse,
}

/// One dataset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feed {
    /// Stable name: a folder name, and what a verdict records.
    pub id: &'static str,
    pub name: &'static str,
    /// The file as abuse.ch names it.
    pub file: &'static str,
    /// Where it is fetched. A feed that needs the Auth-Key has `{key}` in
    /// the path (abuse.ch export URLs carry it there); never display or log
    /// this with a key in it: use [`Feed::url_display`].
    pub url: &'static str,
    /// What the feed can match.
    pub used_for: &'static str,
    pub home: &'static str,
    pub format: Format,
    pub terms: Terms,
    /// The download needs the abuse.ch Auth-Key.
    pub needs_key: bool,
    /// Usual size of the plain text, in bytes; limits are derived from it.
    pub expected_size: u64,
    /// Switched on until the person says otherwise. A smaller alternative to
    /// another feed is off until it is asked for.
    pub default_on: bool,
}

const KEY_MARK: &str = "{key}";

impl Feed {
    /// The URL to fetch, with the key in it. It goes to curl on standard input
    /// and nowhere else.
    pub fn url_for(&self, key: &Secret) -> Result<String, String> {
        url_with_key(self.url, self.needs_key, key)
    }

    /// The URL as it may be shown: `/exports/****/` for the key.
    pub fn url_display(&self) -> String {
        self.url.replace(KEY_MARK, "****")
    }

    /// Whether `url` is this feed's URL with some key in it.
    pub fn owns(&self, url: &str) -> bool {
        template_owns(self.url, url)
    }

    /// Most bytes one download may send.
    pub fn download_limit(&self) -> u64 {
        self.expected_size.saturating_mul(4).max(8 * 1024 * 1024)
    }

    /// Most bytes the plain text may have after unpacking.
    pub fn text_limit(&self) -> u64 {
        self.expected_size.saturating_mul(6).max(16 * 1024 * 1024)
    }

    pub fn license(&self) -> &'static str {
        match self.terms {
            Terms::Cc0 => "CC0 1.0: any use",
            Terms::FairUse => "abuse.ch fair use; free Auth-Key required",
        }
    }
}

/// `template` with the key put into its `{key}` place. A key that is not a
/// plain path segment is refused, so it cannot change the URL.
pub fn url_with_key(template: &str, needs_key: bool, key: &Secret) -> Result<String, String> {
    if !needs_key {
        return Ok(template.to_owned());
    }
    let key = key.expose();
    if key.is_empty() {
        return Err("needs the abuse.ch Auth-Key; set it in Tools > API keys".into());
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
    {
        return Err("the saved Auth-Key has characters a URL cannot carry; set it again in Tools > API keys".into());
    }
    Ok(template.replace(KEY_MARK, key))
}

/// Whether `url` is `template` with a path segment where `{key}` is.
pub fn template_owns(template: &str, url: &str) -> bool {
    match template.split_once(KEY_MARK) {
        None => template == url,
        Some((head, tail)) => {
            url.len() > head.len() + tail.len()
                && url.starts_with(head)
                && url.ends_with(tail)
                && !url[head.len()..url.len() - tail.len()].contains('/')
        }
    }
}

/// The feeds, in the order the Rule manager lists them. The seven datasets of
/// the Rule manager come first; the last is the smaller URLhaus list.
pub const FEEDS: [Feed; 8] = [
    Feed {
        id: "threatfox",
        name: "ThreatFox",
        file: "full.csv",
        url: "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip",
        used_for: "IP:port, domains, URLs, file hashes",
        home: "https://threatfox.abuse.ch/",
        format: Format::Csv,
        terms: Terms::FairUse,
        needs_key: true,
        expected_size: 118 * 1024 * 1024,
        default_on: true,
    },
    Feed {
        id: "urlhaus",
        name: "URLhaus dump",
        file: "full.csv",
        url: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/full.csv.zip",
        used_for: "URLs, hosts",
        home: "https://urlhaus.abuse.ch/",
        format: Format::Csv,
        terms: Terms::FairUse,
        needs_key: true,
        expected_size: 204 * 1024 * 1024,
        default_on: true,
    },
    Feed {
        id: "urlhaus-payloads",
        name: "URLhaus payloads",
        file: "payload.csv",
        url: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/payload.csv.zip",
        used_for: "SHA-256 and MD5 of served files",
        home: "https://urlhaus.abuse.ch/",
        format: Format::Csv,
        terms: Terms::FairUse,
        needs_key: true,
        expected_size: 312 * 1024 * 1024,
        default_on: true,
    },
    Feed {
        id: "feodo",
        name: "Feodo Tracker",
        file: "ipblocklist.json",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        used_for: "botnet C2 IP:port",
        home: "https://feodotracker.abuse.ch/",
        format: Format::FeodoJson,
        terms: Terms::Cc0,
        needs_key: false,
        expected_size: 512 * 1024,
        default_on: true,
    },
    Feed {
        id: "sslbl-ip",
        name: "SSLBL IP",
        file: "sslipblacklist.csv",
        url: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        used_for: "TLS server IP:port",
        home: "https://sslbl.abuse.ch/",
        format: Format::Csv,
        terms: Terms::Cc0,
        needs_key: false,
        expected_size: 512 * 1024,
        default_on: true,
    },
    Feed {
        id: "sslbl-ja3",
        name: "SSLBL JA3",
        file: "ja3_fingerprints.csv",
        url: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
        used_for: "JA3 client fingerprints",
        home: "https://sslbl.abuse.ch/",
        format: Format::Csv,
        terms: Terms::Cc0,
        needs_key: false,
        expected_size: 256 * 1024,
        default_on: true,
    },
    Feed {
        id: "sslbl-cert",
        name: "SSLBL certificates",
        file: "sslblacklist.csv",
        url: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        used_for: "certificate SHA-1",
        home: "https://sslbl.abuse.ch/",
        format: Format::Csv,
        terms: Terms::Cc0,
        needs_key: false,
        expected_size: 1024 * 1024,
        default_on: true,
    },
    Feed {
        id: "urlhaus-recent",
        name: "URLhaus recent",
        file: "recent.csv",
        url: "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        used_for: "URLs, hosts added in the last 30 days (smaller than the dump)",
        home: "https://urlhaus.abuse.ch/",
        format: Format::Csv,
        terms: Terms::FairUse,
        needs_key: true,
        expected_size: 8 * 1024 * 1024,
        default_on: false,
    },
];

/// The feed with this id.
pub fn feed(id: &str) -> Option<&'static Feed> {
    FEEDS.iter().find(|feed| feed.id == id)
}

/// `<data dir>/ioc`.
pub fn root(data_dir: &Path) -> PathBuf {
    data_dir.join("ioc")
}

pub(super) fn feed_dir(data_dir: &Path, feed: &Feed) -> PathBuf {
    root(data_dir).join("feeds").join(feed.id)
}

pub(super) fn staging_dir(data_dir: &Path) -> PathBuf {
    root(data_dir).join("staging")
}

/// What is known about a stored copy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FeedMeta {
    pub schema: u32,
    pub id: String,
    /// The data file in the feed's folder.
    pub file: String,
    pub fetched_unix: u64,
    pub records: u64,
    /// Size of the plain text, in bytes.
    pub size: u64,
    pub sha256: String,
    /// Where it came from (never carries a key).
    pub url: String,
}

impl FeedMeta {
    /// Whole days since the copy was fetched.
    pub fn age_days(&self, now_unix: u64) -> u64 {
        now_unix.saturating_sub(self.fetched_unix) / SECONDS_PER_DAY
    }

    pub fn stale(&self, now_unix: u64) -> bool {
        self.age_days(now_unix) > STALE_DAYS
    }

    /// `YYYY-MM-DD` (UTC) of the fetch: the date every verdict carries.
    pub fn date(&self) -> String {
        date_text(self.fetched_unix)
    }
}

/// `YYYY-MM-DD` for Unix seconds.
pub fn date_text(unix: u64) -> String {
    let days = (unix / SECONDS_PER_DAY) as i64;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|age| age.as_secs())
        .unwrap_or(0)
}

/// One feed as the Rule manager and the IOC window show it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedStatus {
    pub feed: &'static Feed,
    pub meta: Option<FeedMeta>,
    pub enabled: bool,
    /// Why the last update failed; cleared by a successful one.
    pub last_error: Option<String>,
}

impl FeedStatus {
    /// A copy is stored and the feed is switched on.
    pub fn usable(&self) -> bool {
        self.meta.is_some() && self.enabled
    }
}

pub(super) fn read_meta(data_dir: &Path, feed: &Feed) -> Option<FeedMeta> {
    let dir = feed_dir(data_dir, feed);
    let meta: FeedMeta = serde_json::from_slice(&fs::read(dir.join(META_FILE)).ok()?).ok()?;
    // A data file name is a plain name in the feed's folder.
    let plain =
        !meta.file.is_empty() && !meta.file.contains(['/', '\\']) && dir.join(&meta.file).is_file();
    plain.then_some(meta)
}

/// The stored plain text of a feed.
pub fn data_path(data_dir: &Path, feed: &Feed) -> Option<PathBuf> {
    let meta = read_meta(data_dir, feed)?;
    Some(feed_dir(data_dir, feed).join(meta.file))
}

pub(super) fn write_meta(data_dir: &Path, feed: &Feed, meta: &FeedMeta) -> Result<(), String> {
    crate::storage::atomic_json(&feed_dir(data_dir, feed).join(META_FILE), meta)
}

pub(super) fn write_error(data_dir: &Path, feed: &Feed, error: Option<&str>) {
    let path = feed_dir(data_dir, feed).join(ERROR_FILE);
    match error {
        Some(error) => {
            if crate::storage::private_dir(&feed_dir(data_dir, feed)).is_ok() {
                let _ = crate::storage::atomic_json(
                    &path,
                    &serde_json::json!({"at": now_unix(), "error": error}),
                );
            }
        }
        None => {
            let _ = fs::remove_file(path);
        }
    }
}

fn read_error(data_dir: &Path, feed: &Feed) -> Option<String> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(feed_dir(data_dir, feed).join(ERROR_FILE)).ok()?).ok()?;
    value.get("error")?.as_str().map(str::to_owned)
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    disabled: BTreeSet<String>,
    /// Feeds that are off by default and were switched on.
    enabled: BTreeSet<String>,
}

impl Settings {
    fn is_on(&self, feed: &Feed) -> bool {
        if feed.default_on {
            !self.disabled.contains(feed.id)
        } else {
            self.enabled.contains(feed.id)
        }
    }
}

fn read_settings(data_dir: &Path) -> Settings {
    fs::read(root(data_dir).join(SETTINGS_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Switch a feed on or off. A feed that is off is not downloaded by
/// "update all" and is not used for matching, but its copy stays.
pub fn set_enabled(data_dir: &Path, id: &str, enabled: bool) -> Result<(), String> {
    feed(id).ok_or_else(|| format!("no dataset named {id}"))?;
    let mut settings = read_settings(data_dir);
    if enabled {
        settings.disabled.remove(id);
        settings.enabled.insert(id.to_owned());
    } else {
        settings.disabled.insert(id.to_owned());
        settings.enabled.remove(id);
    }
    crate::storage::private_dir(&root(data_dir)).map_err(|error| error.to_string())?;
    crate::storage::atomic_json(&root(data_dir).join(SETTINGS_FILE), &settings)
}

/// Every feed with what is stored for it.
pub fn status(data_dir: &Path) -> Vec<FeedStatus> {
    let settings = read_settings(data_dir);
    FEEDS
        .iter()
        .map(|feed| FeedStatus {
            feed,
            meta: read_meta(data_dir, feed),
            enabled: settings.is_on(feed),
            last_error: read_error(data_dir, feed),
        })
        .collect()
}

/// A line for a status bar: the age of the oldest copy and a warning when it
/// is over [`STALE_DAYS`] days. `None` when nothing is stored.
pub fn age_line(statuses: &[FeedStatus], now_unix: u64) -> Option<String> {
    let oldest = statuses
        .iter()
        .filter(|status| status.usable())
        .filter_map(|status| status.meta.as_ref())
        .map(|meta| meta.age_days(now_unix))
        .max()?;
    Some(if oldest > STALE_DAYS {
        format!("datasets are {oldest} days old; update them")
    } else {
        format!("datasets are {oldest} days old")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_ages_follow_the_fetch_time() {
        assert_eq!(date_text(0), "1970-01-01");
        assert_eq!(date_text(1_792_000_000), "2026-10-14");
        assert_eq!(date_text(951_782_400), "2000-02-29");
        let meta = FeedMeta {
            fetched_unix: 1_000_000,
            ..Default::default()
        };
        assert_eq!(meta.age_days(1_000_000 + 14 * SECONDS_PER_DAY), 14);
        assert!(!meta.stale(1_000_000 + 14 * SECONDS_PER_DAY));
        assert!(meta.stale(1_000_000 + 15 * SECONDS_PER_DAY));
        assert!(!meta.stale(1_000_000 - 5));
    }

    #[test]
    fn a_keyed_url_carries_the_key_in_its_path_and_shows_it_as_stars() {
        let feed = feed("threatfox").unwrap();
        let key = Secret::new("abc123DEF-456_789.xyz");
        let url = feed.url_for(&key).unwrap();
        assert_eq!(
            url,
            "https://threatfox-api.abuse.ch/v2/files/exports/abc123DEF-456_789.xyz/full.csv.zip"
        );
        assert_eq!(
            feed.url_display(),
            "https://threatfox-api.abuse.ch/v2/files/exports/****/full.csv.zip"
        );
        assert!(
            feed.owns(&url)
                && !feed.owns("https://threatfox-api.abuse.ch/v2/files/exports/a/b/full.csv.zip")
        );
        assert!(!feed.owns("https://threatfox-api.abuse.ch/v2/files/exports//full.csv.zip"));
        // No key, or one that could change the URL, makes no URL.
        assert!(feed.url_for(&Secret::default()).is_err());
        for bad in ["a/b", "a?b", "a#b", "a b", "a\"b", "a\\b", "..%2f"] {
            assert!(feed.url_for(&Secret::new(bad)).is_err(), "{bad}");
        }
        // A feed with no key in its URL is the URL itself, whatever key is given.
        let plain = self::feed("feodo").unwrap();
        assert_eq!(plain.url_for(&key).unwrap(), plain.url);
        assert!(plain.owns(plain.url));
    }

    #[test]
    fn the_feed_table_is_complete_and_keeps_keys_out_of_urls() {
        assert_eq!(FEEDS.len(), 8);
        let mut ids: Vec<_> = FEEDS.iter().map(|feed| feed.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 8);
        for feed in &FEEDS {
            assert!(feed.url.starts_with("https://"), "{}", feed.id);
            assert!(!feed.url.contains(['?', '@', '=']), "{}", feed.id);
            assert!(crate::ruleset::is_abusech_host(
                &crate::ruleset::https_host(&feed.url_display()).unwrap()
            ));
            assert!(feed.download_limit() >= feed.expected_size);
            // The key is in the path of a keyed feed's URL, and only there.
            assert_eq!(feed.url.contains("{key}"), feed.needs_key, "{}", feed.id);
            assert!(!feed.url_display().contains("{key}"));
            if feed.needs_key {
                assert!(
                    !feed.url.contains("downloads/") && !feed.url.contains("/export/"),
                    "{}: the retired endpoints",
                    feed.id
                );
                assert!(feed.url.contains("-api.abuse.ch/v2/files/exports/{key}/"));
            }
        }
        assert!(FEEDS.iter().filter(|feed| feed.needs_key).count() == 4);
        assert_eq!(FEEDS.iter().filter(|feed| !feed.default_on).count(), 1);
    }
}
