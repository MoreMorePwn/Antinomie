// SPDX-License-Identifier: GPL-3.0-only
//! The monthly DB-IP Lite refresh: asking which month is published, and
//! taking a month newer than the one pinned in the app.
//!
//! DB-IP publishes one file per month (`dbip-country-lite-2026-11.mmdb.gz`),
//! keeps the earlier months, and offers no signature. The month pinned in
//! `analysis_tools::PACKAGES` is checked against its SHA-256 as every managed
//! tool is. A newer month cannot be, so it is taken on first sight over HTTPS,
//! its SHA-256 recorded in `tool.json` (`"pinned": false`), and the app says so.
use super::{UNPACK_LIMIT, gunzip_file, managed_dir};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const BASE: &str = "https://download.db-ip.com/free";
/// The two databases of the managed copy and the names they are kept under
/// (the same names `PACKAGES` unpacks to).
const FILES: [(&str, &str); 2] = [
    ("country", "dbip-country-lite.mmdb"),
    ("asn", "dbip-asn-lite.mmdb"),
];

/// The newest month DB-IP publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Latest {
    /// "2026-12".
    pub month: String,
}

fn url(kind: &str, month: &str) -> String {
    format!("{BASE}/dbip-{kind}-lite-{month}.mmdb.gz")
}

/// This month and the one before, "YYYY-MM", in UTC.
fn recent_months() -> [String; 2] {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() / 86_400) as i64;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    let (previous_year, previous) = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };
    [
        format!("{year:04}-{month:02}"),
        format!("{previous_year:04}-{previous:02}"),
    ]
}

fn published(curl: &Path, month: &str) -> bool {
    FILES.iter().all(|(kind, _)| {
        Command::new(curl)
            .args([
                "-sfI",
                "--max-time",
                "20",
                "--proto",
                "=https",
                &url(kind, month),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

/// Ask DB-IP which month is the newest it publishes (this month's files are
/// there from the 1st; before that, last month's). Two small HEAD requests per
/// database; nothing is downloaded.
pub fn check_latest(curl: &Path) -> Result<Latest, String> {
    for month in recent_months() {
        if published(curl, &month) {
            return Ok(Latest { month });
        }
    }
    Err("DB-IP did not answer, or publishes no file for this or last month".into())
}

fn sha256(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let digest = crate::storage::sha256_uncached(file)?;
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Download `month` of both databases into `<data>/tools/geoip`, replacing the
/// managed copy once everything is unpacked and recognised as a database.
/// `progress` hears `(stage, received, total)` like a tool installation. The
/// downloads resume after a cancel (see [`crate::resume`]).
pub fn update_latest(
    curl: &Path,
    data_dir: &Path,
    month: &str,
    cancel: &AtomicBool,
    progress: impl FnMut(&str, u64, u64),
) -> Result<(), String> {
    let progress = std::cell::RefCell::new(progress);
    // The size of the pinned month stands in for the total: close enough for a bar.
    let estimate = crate::analysis_tools::package(super::TOOL_ID).map_or(0, |p| p.size());
    if month.len() != 7 || !month.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return Err("not a month".into());
    }
    crate::storage::ensure_data_dir(data_dir)?;
    let tools = crate::analysis_tools::tools_dir(data_dir);
    let staging = tools.join(".downloads").join("geoip-latest");
    fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let mut hashes = serde_json::Map::new();
    let mut total = 0u64;
    let mut files = Vec::new();
    for (kind, name) in FILES {
        let address = url(kind, month);
        let archive = staging.join(format!("{kind}-{month}.mmdb.gz"));
        let item = crate::resume::Item {
            label: "DB-IP Lite",
            key: &address,
            size: None,
        };
        let before = total;
        crate::resume::fetch(
            curl,
            &address,
            &archive,
            &item,
            cancel,
            "tool installation",
            Duration::from_millis(200),
            || {
                let received = fs::metadata(&archive).map_or(0, |m| m.len());
                (progress.borrow_mut())("download", (before + received).min(estimate), estimate);
            },
            &mut |line| (progress.borrow_mut())(&format!("note:{line}"), before, estimate),
        )?;
        total += fs::metadata(&archive).map_or(0, |m| m.len());
        (progress.borrow_mut())("verify", total.min(estimate), estimate);
        hashes.insert(format!("sha256_{kind}"), sha256(&archive)?.into());
        files.push((archive, name));
    }
    (progress.borrow_mut())("unpack", estimate, estimate);
    let partial = tools.join(".geoip.partial");
    let _ = fs::remove_dir_all(&partial);
    fs::create_dir_all(&partial).map_err(|e| e.to_string())?;
    let built = (|| -> Result<(), String> {
        for (archive, name) in &files {
            let target = partial.join(name);
            gunzip_file(archive, &target, UNPACK_LIMIT, cancel)?;
            if super::database_type(&target).is_none() {
                return Err(format!("{name} is not a MaxMind-format database"));
            }
        }
        let mut manifest = serde_json::Map::new();
        manifest.insert("id".into(), super::TOOL_ID.into());
        manifest.insert("version".into(), month.into());
        manifest.insert("pinned".into(), false.into());
        manifest.extend(hashes);
        fs::write(
            partial.join("tool.json"),
            serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    })();
    if cancel.load(Ordering::Relaxed) || built.is_err() {
        let _ = fs::remove_dir_all(&partial);
        return built.and(Err("tool installation cancelled".into()));
    }
    let directory = managed_dir(data_dir);
    let _ = fs::remove_dir_all(&directory);
    fs::rename(&partial, &directory).map_err(|e| e.to_string())?;
    let _ = fs::remove_dir_all(&staging);
    (progress.borrow_mut())("done", estimate, estimate);
    Ok(())
}
