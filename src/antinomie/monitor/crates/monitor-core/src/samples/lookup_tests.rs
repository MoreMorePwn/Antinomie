// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::samples::{NewOrigin, NewSample, OriginKind};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

/// A curl that answers `body` and logs what it was asked, the way the real
/// one is called: the form on its command line, the key on stdin.
fn fake_curl(dir: &Path, body: &str) -> PathBuf {
    std::fs::write(dir.join("body.json"), body).unwrap();
    let script = dir.join("fake-curl.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{args}'\ncat >> '{stdin}'\ncat '{body}'\n",
            args = dir.join("args.txt").display(),
            stdin = dir.join("stdin.txt").display(),
            body = dir.join("body.json").display(),
        ),
    )
    .unwrap();
    crate::test_exec::make_executable(&script, 0o755);
    script
}

fn folder(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ant-lookup-{name}-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn imported(dir: &Path) -> String {
    Library::open(dir)
        .unwrap()
        .add_bytes(
            b"#!/bin/sh\necho packed-payload-fixture\n",
            NewSample {
                origin: NewOrigin {
                    kind: OriginKind::Added,
                    source: "Add file".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap()
        .sha256
}

fn reply(sha256: &str, signature: &str) -> String {
    format!(
        r#"{{"query_status":"ok","data":[{{"sha256_hash":"{sha256}","file_type":"elf","signature":"{signature}","tags":["elf","P2PInfect"]}}]}}"#
    )
}

fn asked(dir: &Path) -> bool {
    dir.join("args.txt").exists()
}

#[test]
fn nothing_is_sent_when_the_lookup_is_off_or_no_key_is_set() {
    let dir = folder("off");
    let sha = imported(&dir);
    let curl = fake_curl(&dir, &reply(&sha, "P2PInfect"));
    let cancel = AtomicBool::new(false);
    assert_eq!(
        lookup_imported(&dir, &curl, "secret-key-1", false, &sha, &cancel).unwrap(),
        Lookup::Off
    );
    assert_eq!(
        lookup_imported(&dir, &curl, " ", true, &sha, &cancel).unwrap(),
        Lookup::NoKey
    );
    assert!(!asked(&dir), "curl was never started");
    assert!(recorded_info(&dir, &sha).is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_listed_file_keeps_the_signature_as_a_looked_up_record() {
    let dir = folder("found");
    let sha = imported(&dir);
    let curl = fake_curl(&dir, &reply(&sha, "P2PInfect"));
    let cancel = AtomicBool::new(false);
    let found = lookup_imported(&dir, &curl, "secret-key-2", true, &sha, &cancel).unwrap();
    assert_eq!(
        found,
        Lookup::Recorded {
            signature: Some("P2PInfect".into()),
            tags: 2
        }
    );
    assert_eq!(
        found.notice().as_deref(),
        Some("MalwareBazaar names it P2PInfect")
    );
    let info = recorded_info(&dir, &sha).unwrap();
    assert_eq!(info.signature.as_deref(), Some("P2PInfect"));
    assert!(info.looked_up);
    // The hash went in the form; the key went on stdin, never on the command
    // line; nothing of the file did.
    let args = std::fs::read_to_string(dir.join("args.txt")).unwrap();
    assert!(args.contains(&format!("hash={sha}")), "{args}");
    assert!(!args.contains("secret-key-2"));
    assert!(!args.contains("packed-payload-fixture"));
    let stdin = std::fs::read_to_string(dir.join("stdin.txt")).unwrap();
    assert!(stdin.contains("Auth-Key: secret-key-2"));
    // The sample's family column and custody log follow.
    let library = Library::open(&dir).unwrap();
    assert_eq!(library.get(&sha).unwrap().unwrap().family, "P2PInfect");
    let edits: Vec<_> = library.events(&sha).unwrap();
    assert!(
        edits.iter().any(|row| matches!(
            &row.event,
            CustodyEvent::Edited { what } if what.contains("looked up by hash")
        )),
        "{edits:?}"
    );
    // A second lookup finds the record and asks nothing.
    std::fs::remove_file(dir.join("args.txt")).unwrap();
    assert_eq!(
        lookup_imported(&dir, &curl, "secret-key-2", true, &sha, &cancel).unwrap(),
        Lookup::Known
    );
    assert!(!asked(&dir));
    drop(library);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_unknown_file_or_another_hash_in_the_reply_records_nothing() {
    let dir = folder("unknown");
    let sha = imported(&dir);
    let cancel = AtomicBool::new(false);
    let missing = fake_curl(&dir, r#"{"query_status":"hash_not_found"}"#);
    assert_eq!(
        lookup_imported(&dir, &missing, "k", true, &sha, &cancel).unwrap(),
        Lookup::NotListed
    );
    let other = fake_curl(&dir, &reply(&"ab".repeat(32), "Mirai"));
    assert_eq!(
        lookup_imported(&dir, &other, "k", true, &sha, &cancel).unwrap(),
        Lookup::NotListed
    );
    assert!(recorded_info(&dir, &sha).is_none());
    assert!(lookup_imported(&dir, &other, "k", true, "xyz", &cancel).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_downloaded_sample_is_not_asked_about_again() {
    let dir = folder("known");
    let cancel = AtomicBool::new(false);
    let info = SampleInfo {
        signature: Some("Mirai".into()),
        ..Default::default()
    };
    let sha = Library::open(&dir)
        .unwrap()
        .add_bytes(
            b"\x7fELF-downloaded-fixture",
            NewSample {
                info: Some(info),
                origin: NewOrigin {
                    kind: OriginKind::Download,
                    source: "MalwareBazaar".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap()
        .sha256;
    let curl = fake_curl(&dir, "{}");
    assert_eq!(
        lookup_imported(&dir, &curl, "k", true, &sha, &cancel).unwrap(),
        Lookup::Known
    );
    assert!(!asked(&dir));
    std::fs::remove_dir_all(&dir).unwrap();
}
