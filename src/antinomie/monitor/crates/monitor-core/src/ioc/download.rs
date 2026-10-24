// SPDX-License-Identifier: GPL-3.0-only
//! Downloading and updating the feeds. Updates are always asked for; nothing
//! here runs by itself. A feed is downloaded into a private staging folder,
//! unpacked, checked, and only then published by atomically replacing its
//! `meta.json`. Any failure leaves the previous copy exactly as it was and
//! records which feed failed and why.
use super::{
    feeds::{self, Feed, FeedMeta},
    records,
};
use crate::ruleset::Fetcher;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};

/// Staging folders older than this are leftovers of a crash.
const STALE_STAGING: Duration = Duration::from_secs(24 * 3600);
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

/// What an update of one feed ended with.
#[derive(Debug)]
pub struct Outcome {
    pub feed: &'static Feed,
    pub result: Result<FeedMeta, String>,
}

fn sweep_staging(data_dir: &Path) {
    let Ok(entries) = fs::read_dir(feeds::staging_dir(data_dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let old = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| SystemTime::now().duration_since(time).ok())
            .is_some_and(|age| age > STALE_STAGING);
        if old {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Copy `from` to `to`, refusing more than `limit` bytes; returns the length
/// and the SHA-256 of what was copied.
fn copy_limited(
    mut from: impl Read,
    to: &Path,
    limit: u64,
    what: &str,
) -> Result<(u64, String), String> {
    let mut out = File::create(to).map_err(|error| format!("{}: {error}", to.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = from
            .read(&mut buffer)
            .map_err(|error| format!("reading {what}: {error}"))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > limit {
            return Err(format!("{what} is larger than the {limit} bytes allowed"));
        }
        hash.update(&buffer[..read]);
        out.write_all(&buffer[..read])
            .map_err(|error| format!("{}: {error}", to.display()))?;
    }
    out.sync_all()
        .map_err(|error| format!("{}: {error}", to.display()))?;
    Ok((total, format!("{:x}", hash.finalize())))
}

/// Turn a download into the feed's plain text in `text`.
fn unpack(download: &Path, text: &Path, feed: &Feed) -> Result<(u64, String), String> {
    let mut file =
        File::open(download).map_err(|error| format!("{}: {error}", download.display()))?;
    let mut magic = [0u8; 4];
    let read = file
        .read(&mut magic)
        .map_err(|error| format!("{}: {error}", download.display()))?;
    drop(file);
    if &magic[..read] != ZIP_MAGIC {
        let file = File::open(download).map_err(|error| error.to_string())?;
        return copy_limited(file, text, feed.text_limit(), feed.file);
    }
    let file = File::open(download).map_err(|error| error.to_string())?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|error| format!("the zip download cannot be read: {error}"))?;
    let wanted = (0..archive.len()).find(|&at| {
        archive.by_index_raw(at).is_ok_and(|entry| {
            let name = entry.name().to_ascii_lowercase();
            !entry.is_dir()
                && [".csv", ".txt", ".json"]
                    .iter()
                    .any(|ext| name.ends_with(ext))
        })
    });
    let at = wanted.ok_or("the zip download holds no .csv, .txt or .json file")?;
    let entry = archive
        .by_index(at)
        .map_err(|error| format!("the zip download cannot be read: {error}"))?;
    copy_limited(entry, text, feed.text_limit(), feed.file)
}

fn free_space(path: &Path) -> Result<u64, String> {
    rustix::fs::statvfs(path)
        .map(|stat| stat.f_bavail.saturating_mul(stat.f_frsize))
        .map_err(|error| error.to_string())
}

/// Download and install one feed. `key_present` says whether an Auth-Key is
/// saved; a feed that needs one is refused before any request is made.
pub fn update_feed(
    data_dir: &Path,
    feed: &'static Feed,
    key_present: bool,
    fetcher: &dyn Fetcher,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<FeedMeta, String> {
    let result = update_inner(data_dir, feed, key_present, fetcher, cancel, progress);
    match &result {
        Ok(_) => feeds::write_error(data_dir, feed, None),
        Err(error) if error == "cancelled" => {}
        Err(error) => feeds::write_error(data_dir, feed, Some(error)),
    }
    result.map_err(|error| {
        if error == "cancelled" {
            format!("{}: cancelled; the previous copy was kept", feed.name)
        } else {
            format!("{}: {error}; the previous copy was kept", feed.name)
        }
    })
}

fn update_inner(
    data_dir: &Path,
    feed: &'static Feed,
    key_present: bool,
    fetcher: &dyn Fetcher,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Result<FeedMeta, String> {
    if feed.needs_key && !key_present {
        return Err("needs the abuse.ch Auth-Key; set it in Tools > API keys".into());
    }
    sweep_staging(data_dir);
    let staging = feeds::staging_dir(data_dir).join(crate::storage::unique_id());
    crate::storage::private_dir(&staging).map_err(|error| error.to_string())?;
    let result = (|| {
        let needed = feed.download_limit().saturating_add(feed.text_limit());
        let free = free_space(&staging)?;
        if free < needed {
            return Err(format!(
                "not enough free space ({} MB free, about {} MB needed)",
                free >> 20,
                needed >> 20
            ));
        }
        let download = staging.join("download");
        let name = feed.name;
        let mut last = 0u64;
        progress(&format!("Downloading {name}"));
        fetcher.fetch(
            feed.url,
            &download,
            feed.download_limit(),
            cancel,
            &mut |received| {
                if received >> 21 != last >> 21 {
                    progress(&format!(
                        "Downloading {name}: {} MB of about {} MB",
                        received >> 20,
                        feed.expected_size >> 20
                    ));
                }
                last = received;
            },
        )?;
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        progress(&format!("Checking {name}"));
        let text = staging.join("text");
        let (size, sha256) = unpack(&download, &text, feed)?;
        let _ = fs::remove_file(&download);
        let scanned = records::count(&text, feed, cancel)?;
        if scanned.records == 0 {
            return Err("the file holds no records".into());
        }
        if scanned.skipped > scanned.records {
            return Err(format!(
                "the file does not look like {} ({} of {} lines were not records)",
                feed.file,
                scanned.skipped,
                scanned.skipped + scanned.records
            ));
        }
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        // Publish: the new data file is complete before meta.json names it.
        let dir = feeds::feed_dir(data_dir, feed);
        crate::storage::private_dir(&dir).map_err(|error| error.to_string())?;
        let fetched = feeds::now_unix();
        let file = format!("data-{fetched}-{}.txt", &crate::storage::unique_id()[..8]);
        fs::rename(&text, dir.join(&file)).map_err(|error| format!("{file}: {error}"))?;
        let meta = FeedMeta {
            schema: 1,
            id: feed.id.to_owned(),
            file: file.clone(),
            fetched_unix: fetched,
            records: scanned.records,
            size,
            sha256,
            url: feed.url.to_owned(),
        };
        if let Err(error) = feeds::write_meta(data_dir, feed, &meta) {
            let _ = fs::remove_file(dir.join(&file));
            return Err(error);
        }
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("data-") && name != file.as_str() {
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(meta)
    })();
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Update every feed that is switched on, one after another. A failure does
/// not stop the others and keeps its feed's previous copy.
pub fn update_all(
    data_dir: &Path,
    key_present: bool,
    fetcher: &dyn Fetcher,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&str),
) -> Vec<Outcome> {
    let statuses = feeds::status(data_dir);
    let total = statuses.iter().filter(|status| status.enabled).count();
    let mut outcomes = Vec::new();
    for status in statuses.iter().filter(|status| status.enabled) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let number = outcomes.len() + 1;
        let result = update_feed(
            data_dir,
            status.feed,
            key_present,
            fetcher,
            cancel,
            &mut |line| progress(&format!("{line} ({number} of {total})")),
        );
        outcomes.push(Outcome {
            feed: status.feed,
            result,
        });
    }
    outcomes
}

/// One sentence for the status line: how many feeds were updated and which
/// failed.
pub fn summary(outcomes: &[Outcome]) -> String {
    let done = outcomes
        .iter()
        .filter(|outcome| outcome.result.is_ok())
        .count();
    let failed: Vec<String> = outcomes
        .iter()
        .filter_map(|outcome| outcome.result.as_ref().err().cloned())
        .collect();
    if failed.is_empty() {
        format!(
            "Updated {done} dataset{}.",
            if done == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "Updated {done} of {}. Failed: {}",
            outcomes.len(),
            failed.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api_keys::Secret,
        ioc::records::fixtures::*,
        ruleset::{Curl, Fetcher},
    };
    use std::{cell::RefCell, collections::BTreeMap, os::unix::fs::PermissionsExt, path::PathBuf};

    /// A fetcher that serves canned bytes (or a failure) per feed URL and
    /// counts the requests.
    #[derive(Default)]
    struct Mock {
        serve: BTreeMap<String, Result<Vec<u8>, String>>,
        calls: RefCell<Vec<String>>,
    }

    impl Mock {
        fn with(mut self, feed: &str, body: Result<Vec<u8>, String>) -> Self {
            self.serve
                .insert(feeds::feed(feed).unwrap().url.to_owned(), body);
            self
        }
    }

    impl Fetcher for Mock {
        fn fetch(
            &self,
            url: &str,
            dest: &Path,
            max_size: u64,
            _cancel: &AtomicBool,
            progress: &mut dyn FnMut(u64),
        ) -> Result<(), String> {
            self.calls.borrow_mut().push(url.to_owned());
            match self.serve.get(url) {
                Some(Ok(bytes)) => {
                    assert!(bytes.len() as u64 <= max_size);
                    fs::write(dest, bytes).map_err(|error| error.to_string())?;
                    progress(bytes.len() as u64);
                    Ok(())
                }
                Some(Err(error)) => Err(error.clone()),
                None => Err(format!("{url} answered HTTP 404")),
            }
        }
    }

    fn data_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ant-ioc-{name}-{}", crate::storage::unique_id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn zip_of(name: &str, text: &str) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut out = std::io::Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(&mut out);
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(text.as_bytes()).unwrap();
        writer.finish().unwrap();
        out.into_inner()
    }

    fn all_fixtures() -> Mock {
        Mock::default()
            .with("threatfox", Ok(zip_of("full.csv", THREATFOX)))
            .with("urlhaus", Ok(zip_of("csv.txt", URLHAUS)))
            .with("urlhaus-payloads", Ok(PAYLOADS.as_bytes().to_vec()))
            .with("feodo", Ok(FEODO.as_bytes().to_vec()))
            .with("sslbl-ip", Ok(SSLBL_IP.as_bytes().to_vec()))
            .with("sslbl-ja3", Ok(SSLBL_JA3.as_bytes().to_vec()))
            .with("sslbl-cert", Ok(SSLBL_CERT.as_bytes().to_vec()))
    }

    fn quiet(_: &str) {}

    #[test]
    fn update_all_installs_every_feed_and_records_counts_and_dates() {
        let dir = data_dir("all");
        let cancel = AtomicBool::new(false);
        let outcomes = update_all(&dir, true, &all_fixtures(), &cancel, &mut quiet);
        assert_eq!(outcomes.len(), 7);
        assert!(
            outcomes.iter().all(|outcome| outcome.result.is_ok()),
            "{outcomes:?}"
        );
        assert_eq!(summary(&outcomes), "Updated 7 datasets.");
        let statuses = feeds::status(&dir);
        let threatfox = &statuses[0];
        let meta = threatfox.meta.as_ref().unwrap();
        assert_eq!(meta.records, 6);
        assert_eq!(meta.date(), feeds::date_text(feeds::now_unix()));
        assert_eq!(meta.sha256.len(), 64);
        assert!(!meta.url.contains('?'));
        assert!(threatfox.last_error.is_none());
        // The zip was unpacked: the stored file is the CSV itself.
        let stored = fs::read_to_string(feeds::data_path(&dir, threatfox.feed).unwrap()).unwrap();
        assert!(stored.contains("c2.update-cdn.example"));
        assert!(statuses.iter().all(|status| status.usable()));
        assert!(
            !feeds::age_line(&statuses, feeds::now_unix())
                .unwrap()
                .contains("update them")
        );
        let stale_clock = feeds::now_unix() + 15 * 86_400;
        assert!(
            feeds::age_line(&statuses, stale_clock)
                .unwrap()
                .contains("update them")
        );
        // Nothing is left in staging.
        let staging = feeds::staging_dir(&dir);
        assert_eq!(
            fs::read_dir(staging)
                .map(|entries| entries.count())
                .unwrap_or(0),
            0
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_update_keeps_the_previous_copy_and_names_the_feed() {
        let dir = data_dir("keep");
        let cancel = AtomicBool::new(false);
        let first = update_all(&dir, true, &all_fixtures(), &cancel, &mut quiet);
        assert!(first.iter().all(|outcome| outcome.result.is_ok()));
        let before = feeds::status(&dir)[4].meta.clone().unwrap();
        // SSLBL IP now fails; the others succeed with new content.
        let mut broken = all_fixtures();
        broken.serve.insert(
            feeds::feed("sslbl-ip").unwrap().url.into(),
            Err("download failed: Could not resolve host".into()),
        );
        let second = update_all(&dir, true, &broken, &cancel, &mut quiet);
        let text = summary(&second);
        assert!(
            text.starts_with("Updated 6 of 7. Failed: SSLBL IP:"),
            "{text}"
        );
        assert!(text.contains("the previous copy was kept"), "{text}");
        let after = &feeds::status(&dir)[4];
        assert_eq!(
            after.meta.as_ref(),
            Some(&before),
            "the old copy is untouched"
        );
        assert!(
            after
                .last_error
                .as_ref()
                .unwrap()
                .contains("Could not resolve")
        );
        assert!(
            fs::read_to_string(feeds::data_path(&dir, after.feed).unwrap())
                .unwrap()
                .contains("203.0.113.45")
        );
        // A later success clears the failure.
        let third = update_all(&dir, true, &all_fixtures(), &cancel, &mut quiet);
        assert!(third.iter().all(|outcome| outcome.result.is_ok()));
        assert!(feeds::status(&dir)[4].last_error.is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bad_download_never_replaces_a_good_copy() {
        let dir = data_dir("bad");
        let cancel = AtomicBool::new(false);
        let feed = feeds::feed("sslbl-cert").unwrap();
        let good = Mock::default().with("sslbl-cert", Ok(SSLBL_CERT.as_bytes().to_vec()));
        update_feed(&dir, feed, false, &good, &cancel, &mut quiet).unwrap();
        let before = feeds::status(&dir)[6].meta.clone().unwrap();
        for body in [
            b"<html><body>429 Too Many Requests</body></html>".to_vec(),
            Vec::new(),
            b"# only comments\n# nothing else\n".to_vec(),
            zip_of("readme.pdf", "x"),
        ] {
            let bad = Mock::default().with("sslbl-cert", Ok(body));
            let error = update_feed(&dir, feed, false, &bad, &cancel, &mut quiet).unwrap_err();
            assert!(error.starts_with("SSLBL certificates:"), "{error}");
            assert_eq!(feeds::status(&dir)[6].meta.as_ref(), Some(&before));
        }
        let leftovers: Vec<_> = fs::read_dir(feeds::feed_dir(&dir, feed))
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("data-"))
            .collect();
        assert_eq!(leftovers, std::slice::from_ref(&before.file));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_feed_that_needs_the_key_makes_no_request_without_one() {
        let dir = data_dir("nokey");
        let cancel = AtomicBool::new(false);
        let mock = all_fixtures();
        let outcomes = update_all(&dir, false, &mock, &cancel, &mut quiet);
        let ok: Vec<_> = outcomes
            .iter()
            .filter(|outcome| outcome.result.is_ok())
            .map(|outcome| outcome.feed.id)
            .collect();
        assert_eq!(ok, ["feodo", "sslbl-ip", "sslbl-ja3", "sslbl-cert"]);
        let calls = mock.calls.borrow();
        assert_eq!(
            calls.len(),
            4,
            "no request for a feed that needs the key: {calls:?}"
        );
        let text = summary(&outcomes);
        assert!(
            text.contains("ThreatFox: needs the abuse.ch Auth-Key"),
            "{text}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_feed_switched_off_is_skipped_by_update_all() {
        let dir = data_dir("off");
        feeds::set_enabled(&dir, "feodo", false).unwrap();
        assert!(feeds::set_enabled(&dir, "nope", false).is_err());
        let mock = all_fixtures();
        let outcomes = update_all(&dir, true, &mock, &AtomicBool::new(false), &mut quiet);
        assert_eq!(outcomes.len(), 6);
        assert!(outcomes.iter().all(|outcome| outcome.feed.id != "feodo"));
        let status = &feeds::status(&dir)[3];
        assert!(!status.enabled && status.meta.is_none() && !status.usable());
        feeds::set_enabled(&dir, "feodo", true).unwrap();
        assert!(feeds::status(&dir)[3].enabled);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_cancelled_update_changes_nothing_and_is_not_recorded_as_a_failure() {
        let dir = data_dir("cancel");
        let feed = feeds::feed("feodo").unwrap();
        let cancel = AtomicBool::new(true);
        let mock = Mock::default().with("feodo", Ok(FEODO.as_bytes().to_vec()));
        let error = update_feed(&dir, feed, true, &mock, &cancel, &mut quiet).unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
        let status = &feeds::status(&dir)[3];
        assert!(status.meta.is_none() && status.last_error.is_none());
        let _ = fs::remove_dir_all(dir);
    }

    /// A stand-in for curl that records what it was given and serves a file.
    fn fake_curl(dir: &Path, body: &Path) -> PathBuf {
        let script = dir.join("fake-curl.sh");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 out=\n\
                 prev=\n\
                 for arg in \"$@\"; do\n\
                   if [ \"$prev\" = --output ]; then out=$arg; fi\n\
                   prev=$arg\n\
                 done\n\
                 printf '%s\\n' \"$@\" > '{args}'\n\
                 cat > '{stdin}'\n\
                 cp '{body}' \"$out\"\n\
                 printf '200 '\n",
                args = dir.join("args.txt").display(),
                stdin = dir.join("stdin.txt").display(),
                body = body.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[test]
    fn the_auth_key_goes_to_abuse_ch_on_stdin_and_never_on_the_command_line() {
        let dir = data_dir("curl");
        let body = dir.join("body.csv");
        fs::write(&body, SSLBL_CERT).unwrap();
        let curl =
            Curl::new(fake_curl(&dir, &body)).with_auth_key(Secret::new("abc123-very-secret-9f3a"));
        let cancel = AtomicBool::new(false);
        // The shown Debug text of the fetcher carries no key.
        assert!(!format!("{curl:?}").contains("secret"));
        let feed = feeds::feed("sslbl-cert").unwrap();
        let meta = update_feed(&dir, feed, true, &curl, &cancel, &mut quiet).unwrap();
        assert_eq!(meta.records, 1);
        let args = fs::read_to_string(dir.join("args.txt")).unwrap();
        let stdin = fs::read_to_string(dir.join("stdin.txt")).unwrap();
        assert!(
            !args.contains("secret"),
            "the key is on the command line: {args}"
        );
        assert!(args.contains("@-"));
        assert_eq!(stdin.trim(), "Auth-Key: abc123-very-secret-9f3a");
        // Another host gets no key at all.
        let mut text = String::new();
        let other = dir.join("other.csv");
        curl.fetch(
            "https://example.com/x.csv",
            &other,
            1 << 20,
            &cancel,
            &mut |_| {},
        )
        .unwrap();
        text.push_str(&fs::read_to_string(dir.join("stdin.txt")).unwrap());
        assert_eq!(text.trim(), "");
        let args = fs::read_to_string(dir.join("args.txt")).unwrap();
        assert!(!args.contains("@-"), "{args}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn the_stored_files_and_errors_carry_no_key() {
        let dir = data_dir("nosecret");
        let feed = feeds::feed("threatfox").unwrap();
        let key = "never-store-this-key-0000";
        let mock = Mock::default().with(
            "threatfox",
            Err(crate::api_keys::redact(
                &format!("download failed: Auth-Key: {key}"),
                &[&Secret::new(key)],
            )),
        );
        let error =
            update_feed(&dir, feed, true, &mock, &AtomicBool::new(false), &mut quiet).unwrap_err();
        assert!(!error.contains(key));
        let stored =
            fs::read_to_string(feeds::feed_dir(&dir, feed).join("last-error.json")).unwrap();
        assert!(!stored.contains(key));
        let _ = fs::remove_dir_all(dir);
    }
}
