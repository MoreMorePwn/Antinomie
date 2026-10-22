// SPDX-License-Identifier: GPL-3.0-only
//! Download policy: HTTPS only, redirects stay on the publisher's hosts.
use super::source_fixture::*;
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicBool;

/// A stand-in `curl`: answers by URL without touching the network.
fn fake_curl(dir: &Path) -> Curl {
    let script = dir.join("curl");
    fs::write(
        &script,
        r#"#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift;;
    --url) url="$2"; shift;;
  esac
  shift
done
case "$url" in
  *bounce-ok*) printf '302 https://release-assets.githubusercontent.com/payload';;
  *bounce-away*) printf '302 https://evil.example.org/payload';;
  *bounce-plain*) printf '302 http://github.com/payload';;
  *loop*) printf '302 https://github.com/loop';;
  *missing*) printf '404 ';;
  *big*) head -c 5000 /dev/zero > "$out"; printf '200 ';;
  *) printf 'payload' > "$out"; printf '200 ';;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    Curl::new(script)
}

fn get(curl: &Curl, dir: &Path, url: &str, max: u64) -> Result<Vec<u8>, String> {
    let dest = dir.join("out.bin");
    curl.fetch(url, &dest, max, &no_cancel(), &mut |_| {})?;
    fs::read(dest).map_err(|error| error.to_string())
}

#[test]
fn redirects_may_only_reach_the_publishers_hosts() {
    let dir = temp_dir("policy");
    let curl = fake_curl(&dir);
    assert_eq!(
        get(&curl, &dir, "https://github.com/a/direct", 100).unwrap(),
        b"payload"
    );
    // The release CDN is one of GitHub's hosts.
    assert_eq!(
        get(&curl, &dir, "https://github.com/a/bounce-ok", 100).unwrap(),
        b"payload"
    );
    let away = get(&curl, &dir, "https://github.com/a/bounce-away", 100).unwrap_err();
    assert!(
        away.contains("evil.example.org") && away.contains("not one of its hosts"),
        "{away}"
    );
    assert!(
        !dir.join("out.bin").exists(),
        "a refused download leaves no file"
    );
    let plain = get(&curl, &dir, "https://github.com/a/bounce-plain", 100).unwrap_err();
    assert!(plain.contains("not allowed"), "{plain}");
    // A host with no CDN list may not be redirected anywhere else.
    let other = get(&curl, &dir, "https://rules.example.org/bounce-ok", 100).unwrap_err();
    assert!(other.contains("not one of its hosts"), "{other}");
    assert!(
        get(&curl, &dir, "https://github.com/a/loop", 100)
            .unwrap_err()
            .contains("too many")
    );
    assert!(
        get(&curl, &dir, "https://github.com/a/missing", 100)
            .unwrap_err()
            .contains("HTTP 404")
    );
    assert!(
        get(&curl, &dir, "http://github.com/a/direct", 100)
            .unwrap_err()
            .contains("https")
    );
    let large = get(&curl, &dir, "https://github.com/a/big", 100).unwrap_err();
    assert!(large.contains("more than"), "{large}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_cancelled_fetch_stops_without_a_file() {
    let dir = temp_dir("policy-cancel");
    let curl = fake_curl(&dir);
    let cancel = AtomicBool::new(true);
    let dest = dir.join("out.bin");
    let error = curl
        .fetch(
            "https://github.com/a/direct",
            &dest,
            100,
            &cancel,
            &mut |_| {},
        )
        .unwrap_err();
    assert_eq!(error, "cancelled");
    assert!(!dest.exists());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn hosts_are_plain_https_names() {
    assert_eq!(
        https_host("https://sslbl.abuse.ch/blacklist/x.rules").unwrap(),
        "sslbl.abuse.ch"
    );
    for bad in [
        "http://a.example/x",
        "https://",
        "https://localhost/x",
        "https://a.example:8443/x",
        "https://u:p@a.example/x",
        "https://A.example/x",
        "https://a.example/ x",
        "https://a_b.example/x",
        "ftp://a.example/x",
    ] {
        assert!(https_host(bad).is_err(), "{bad}");
    }
    assert!(host_allowed("huggingface.co", "cas-bridge.xethub.hf.co"));
    assert!(host_allowed("huggingface.co", "anything.hf.co"));
    assert!(!host_allowed("github.com", "anything.hf.co"));
    assert!(host_allowed("codeload.github.com", "github.com"));
    assert!(!host_allowed("sslbl.abuse.ch", "github.com"));
}

#[test]
fn the_catalog_refresh_validates_before_replacing_the_local_copy() {
    let dir = temp_dir("refresh");
    let (pack, _) = forge_pack();
    let good = serde_json::json!({"schema": 2, "packs": [pack]}).to_string();
    let url = "https://example.invalid/catalog.json";
    let fetched = refresh_catalog(
        &dir,
        url,
        &Fixture::default().with(url, good.clone().into_bytes()),
        &no_cancel(),
    )
    .unwrap();
    assert_eq!(fetched.sources.len(), 1);
    assert_eq!(load_catalog(&dir).unwrap().unwrap(), fetched);
    // An answer that does not validate leaves the stored catalog alone.
    let bad = serde_json::json!({"schema": 2, "packs": [{"id": "x"}]}).to_string();
    let error = refresh_catalog(
        &dir,
        url,
        &Fixture::default().with(url, bad.into_bytes()),
        &no_cancel(),
    )
    .unwrap_err();
    assert!(error.contains("x:"), "{error}");
    let error = refresh_catalog(
        &dir,
        url,
        &Fixture::default().with(url, b"<html>".to_vec()),
        &no_cancel(),
    )
    .unwrap_err();
    assert!(error.contains("not valid JSON"), "{error}");
    assert_eq!(load_catalog(&dir).unwrap().unwrap(), fetched);
    let staging = rules_root(&dir).join("staging");
    assert!(fs::read_dir(staging).unwrap().next().is_none());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_consent_names_every_host_the_catalog_can_contact() {
    let (pack, _) = forge_pack();
    let none = contacted_hosts(None);
    assert!(none.contains(&"huggingface.co".to_owned()));
    assert!(!none.contains(&"github.com".to_owned()));
    let catalog = Catalog {
        schema: 2,
        packs: Vec::new(),
        sources: vec![pack],
    };
    let hosts = contacted_hosts(Some(&catalog));
    for host in ["huggingface.co", "github.com", "codeload.github.com"] {
        assert!(hosts.contains(&host.to_owned()), "{host}: {hosts:?}");
    }
}

#[test]
fn a_pack_download_stages_in_a_private_directory_and_leaves_nothing_behind() {
    let data = temp_dir("pack-download");
    let body = b"archive bytes".to_vec();
    let mut pack = entry(&sha(&body), body.len() as u64);
    pack.download_url = "https://example.invalid/sample.tar.gz".into();
    let fixture = Fixture::default().with(&pack.download_url, body.clone());
    let bytes =
        download_archive(&data, &pack, &fixture, &AtomicBool::new(false)).expect("download");
    assert_eq!(bytes, body);
    // The staging area lives under the rules root, not in the shared temp dir.
    let staging = rules_root(&data).join("staging");
    assert!(staging.is_dir());
    assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    // The unique directory the file is written into is private.
    struct Probe(std::sync::Mutex<Option<u32>>);
    impl Fetcher for Probe {
        fn fetch(
            &self,
            _: &str,
            dest: &Path,
            _: u64,
            _: &AtomicBool,
            _: &mut dyn FnMut(u64),
        ) -> Result<(), String> {
            let mode = fs::metadata(dest.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            *self.0.lock().unwrap() = Some(mode & 0o777);
            fs::write(dest, b"x").map_err(|e| e.to_string())
        }
    }
    let probe = Probe(Default::default());
    download_archive(&data, &pack, &probe, &AtomicBool::new(false)).unwrap();
    assert_eq!(*probe.0.lock().unwrap(), Some(0o700));
    // A cancelled or refused download is an error and leaves no file either.
    let cancelled = AtomicBool::new(true);
    assert!(download_archive(&data, &pack, &fixture, &cancelled).is_err());
    let missing = Fixture::default();
    assert!(download_archive(&data, &pack, &missing, &AtomicBool::new(false)).is_err());
    assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    let _ = fs::remove_dir_all(&data);
}
