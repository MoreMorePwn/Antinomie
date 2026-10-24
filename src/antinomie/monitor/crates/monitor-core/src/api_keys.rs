// SPDX-License-Identifier: GPL-3.0-only
//! The one place API keys are kept: Tools > API keys.
//!
//! Keys live in `<data dir>/api-keys.json`, written with mode 0600 through a
//! temporary file that is created 0600 too, so no moment exists in which the
//! file can be read by another user. A key is never part of a run export, a
//! report, a log line, a catalog or a saved download URL: callers hand it to
//! `curl` on its standard input, and [`redact`] removes it from any error
//! text that could echo it. Only the last four characters are ever displayed
//! ([`masked`]).
//!
//! The abuse.ch Auth-Key is one key for every abuse.ch service (MalwareBazaar,
//! ThreatFox, URLhaus), so it is one entry here.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const KEYS_FILE: &str = "api-keys.json";
const USE_FILE: &str = "api-key-use.json";
/// Longest key accepted.
const MAX_KEY_LEN: usize = 256;
/// Keys shorter than this show no characters at all.
const MASK_MIN_LEN: usize = 8;

/// A key the application knows how to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiKey {
    /// The abuse.ch Auth-Key: MalwareBazaar, ThreatFox, URLhaus.
    Abusech,
    MalShare,
}

impl ApiKey {
    pub const ALL: [ApiKey; 2] = [ApiKey::Abusech, ApiKey::MalShare];

    /// The stable name in the key file.
    pub fn id(self) -> &'static str {
        match self {
            ApiKey::Abusech => "abusech",
            ApiKey::MalShare => "malshare",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ApiKey::Abusech => "abuse.ch Auth-Key",
            ApiKey::MalShare => "MalShare API key",
        }
    }

    /// Where a free key is made.
    pub fn keys_url(self) -> &'static str {
        match self {
            ApiKey::Abusech => crate::samples::BAZAAR_KEYS,
            ApiKey::MalShare => crate::malshare::KEYS,
        }
    }

    /// The features that use this key, in words.
    pub fn features(self) -> &'static [&'static str] {
        match self {
            ApiKey::Abusech => &[
                "Malware samples (MalwareBazaar)",
                "IOC datasets: ThreatFox, URLhaus (Rule manager > IOC)",
                "abuse.ch Suricata rule packs (Rule manager > IDS)",
                "IOC online check (Triage > IOC)",
            ],
            ApiKey::MalShare => &["Malware samples (MalShare)"],
        }
    }

    /// Why `value` cannot be this key, or `None` when it can.
    pub fn check(self, value: &str) -> Option<String> {
        if value.is_empty() {
            return Some("the key is empty".into());
        }
        if value.len() > MAX_KEY_LEN {
            return Some(format!("a key is at most {MAX_KEY_LEN} characters"));
        }
        if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Some("a key has no spaces or line breaks".into());
        }
        match self {
            ApiKey::MalShare if !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) => {
                Some("a MalShare API key is letters and digits only".into())
            }
            ApiKey::Abusech if !value.is_ascii() => {
                Some("an abuse.ch Auth-Key is plain ASCII".into())
            }
            _ => None,
        }
    }
}

/// A secret that does not print itself: `{:?}` shows only that one is held.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The text, for the one place that hands it to a program.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "Secret(empty)"
        } else {
            "Secret(…)"
        })
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Stored {
    schema: u32,
    keys: BTreeMap<String, String>,
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(KEYS_FILE)
}

fn load(data_dir: &Path) -> Stored {
    migrate_legacy(data_dir);
    fs::read(path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Stored>(&bytes).ok())
        .unwrap_or_default()
}

fn store(data_dir: &Path, stored: &mut Stored) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|error| format!("{}: {error}", data_dir.display()))?;
    stored.schema = 1;
    // `atomic_json` creates its temporary file 0600 before writing a byte.
    crate::storage::atomic_json(&path(data_dir), stored)
}

/// Keys older versions kept in `samples/api-keys.json` move here once, and
/// the old file is deleted.
fn migrate_legacy(data_dir: &Path) {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Legacy {
        malwarebazaar: String,
        malshare: String,
    }
    let old = crate::samples::samples_dir(data_dir).join(KEYS_FILE);
    let Ok(bytes) = fs::read(&old) else {
        return;
    };
    let legacy: Legacy = serde_json::from_slice(&bytes).unwrap_or_default();
    let mut stored: Stored = fs::read(path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    for (key, value) in [
        (ApiKey::Abusech, legacy.malwarebazaar),
        (ApiKey::MalShare, legacy.malshare),
    ] {
        let value = value.trim().to_owned();
        if !value.is_empty() && key.check(&value).is_none() {
            stored.keys.entry(key.id().into()).or_insert(value);
        }
    }
    if store(data_dir, &mut stored).is_ok() {
        let _ = fs::remove_file(old);
    }
}

/// The saved key, or an empty secret.
pub fn get(data_dir: &Path, key: ApiKey) -> Secret {
    Secret(load(data_dir).keys.remove(key.id()).unwrap_or_default())
}

/// Whether a key is saved.
pub fn is_set(data_dir: &Path, key: ApiKey) -> bool {
    !get(data_dir, key).is_empty()
}

/// Save a key (surrounding spaces are dropped); an unusable one is refused
/// and nothing changes.
pub fn set(data_dir: &Path, key: ApiKey, value: &str) -> Result<(), String> {
    let value = value.trim();
    if let Some(problem) = key.check(value) {
        return Err(problem);
    }
    let mut stored = load(data_dir);
    stored.keys.insert(key.id().into(), value.to_owned());
    store(data_dir, &mut stored)
}

/// Forget a key.
pub fn clear(data_dir: &Path, key: ApiKey) -> Result<(), String> {
    let mut stored = load(data_dir);
    if stored.keys.remove(key.id()).is_none() {
        return Ok(());
    }
    store(data_dir, &mut stored)?;
    let mut used = load_use(data_dir);
    if used.remove(key.id()).is_some() {
        let _ = crate::storage::atomic_json(&data_dir.join(USE_FILE), &used);
    }
    Ok(())
}

/// How a saved key is shown: `…a91f`, or just "set" for a short one.
pub fn masked(key: &Secret) -> String {
    let text = key.expose();
    if text.chars().count() < MASK_MIN_LEN {
        return "set".into();
    }
    let tail: Vec<char> = text.chars().rev().take(4).collect();
    format!("…{}", tail.into_iter().rev().collect::<String>())
}

/// `text` with every occurrence of the given keys replaced, for error text
/// that a server or a program could echo back.
pub fn redact(text: &str, keys: &[&Secret]) -> String {
    let mut out = text.to_owned();
    for key in keys {
        let key = key.expose();
        if key.len() >= 4 {
            out = out.replace(key, "[redacted]");
        }
    }
    out
}

fn load_use(data_dir: &Path) -> BTreeMap<String, u64> {
    fs::read(data_dir.join(USE_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Note that a feature just used the key (a time, never the key).
pub fn record_use(data_dir: &Path, key: ApiKey) {
    let mut used = load_use(data_dir);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|age| age.as_millis() as u64)
        .unwrap_or(0);
    used.insert(key.id().into(), now);
    let _ = crate::storage::atomic_json(&data_dir.join(USE_FILE), &used);
}

/// Unix milliseconds of the key's last use.
pub fn last_used(data_dir: &Path, key: ApiKey) -> Option<u64> {
    load_use(data_dir).get(key.id()).copied()
}

/// Ask the service whether it accepts the key. The one network call of this
/// module; it runs when the person presses Test.
pub fn test(curl: &Path, key: ApiKey, secret: &Secret) -> Result<String, String> {
    let result = match key {
        ApiKey::Abusech => crate::samples::search(
            curl,
            secret.expose(),
            &crate::samples::Query::Tag("Mirai".into()),
            1,
        )
        .map(|_| "abuse.ch accepted the Auth-Key".to_owned()),
        ApiKey::MalShare => crate::malshare::check_key(curl, secret.expose())
            .map(|()| "MalShare accepted the API key".to_owned()),
    };
    result.map_err(|error| redact(&error, &[secret]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ant-api-keys-{name}-{}",
            crate::storage::unique_id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_saved_key_is_owner_only_and_shows_four_characters() {
        let dir = temp("save");
        set(&dir, ApiKey::Abusech, "  secret-key-a91f  ").unwrap();
        let mode = fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let key = get(&dir, ApiKey::Abusech);
        assert_eq!(key.expose(), "secret-key-a91f");
        assert_eq!(masked(&key), "…a91f");
        assert_eq!(masked(&Secret::new("short")), "set");
        assert!(!format!("{key:?}").contains("secret"));
        assert!(is_set(&dir, ApiKey::Abusech));
        assert!(!is_set(&dir, ApiKey::MalShare));
        clear(&dir, ApiKey::Abusech).unwrap();
        assert!(!is_set(&dir, ApiKey::Abusech));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unusable_keys_are_refused_and_change_nothing() {
        let dir = temp("refuse");
        set(&dir, ApiKey::MalShare, "abc123def456").unwrap();
        for bad in ["", "has space", "line\nbreak", "ünï", &"x".repeat(300)] {
            assert!(set(&dir, ApiKey::Abusech, bad).is_err(), "{bad:?}");
        }
        assert!(set(&dir, ApiKey::MalShare, "not-alphanumeric").is_err());
        assert_eq!(get(&dir, ApiKey::MalShare).expose(), "abc123def456");
        assert!(!is_set(&dir, ApiKey::Abusech));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn keys_from_the_samples_folder_move_once_and_the_old_file_goes() {
        let dir = temp("legacy");
        let samples = crate::samples::samples_dir(&dir);
        fs::create_dir_all(&samples).unwrap();
        fs::write(
            samples.join(KEYS_FILE),
            br#"{"malwarebazaar":"old-bazaar-key-1234","malshare":"oldshare99"}"#,
        )
        .unwrap();
        assert_eq!(get(&dir, ApiKey::Abusech).expose(), "old-bazaar-key-1234");
        assert_eq!(get(&dir, ApiKey::MalShare).expose(), "oldshare99");
        assert!(!samples.join(KEYS_FILE).exists());
        let mode = fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn use_times_hold_no_key_and_clear_with_it() {
        let dir = temp("use");
        set(&dir, ApiKey::Abusech, "use-time-key-0001").unwrap();
        assert_eq!(last_used(&dir, ApiKey::Abusech), None);
        record_use(&dir, ApiKey::Abusech);
        assert!(last_used(&dir, ApiKey::Abusech).is_some());
        let text = fs::read_to_string(dir.join(USE_FILE)).unwrap();
        assert!(!text.contains("use-time-key"));
        clear(&dir, ApiKey::Abusech).unwrap();
        assert_eq!(last_used(&dir, ApiKey::Abusech), None);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn error_text_loses_the_key() {
        let key = Secret::new("abcd1234efgh");
        assert_eq!(
            redact("GET /?k=abcd1234efgh failed", &[&key]),
            "GET /?k=[redacted] failed"
        );
        assert_eq!(
            redact("nothing here", &[&Secret::default()]),
            "nothing here"
        );
        let ids: Vec<_> = ApiKey::ALL.iter().map(|key| key.id()).collect();
        assert_eq!(ids, ["abusech", "malshare"]);
    }
}
