// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use rusqlite::params;
use std::{fs, path::PathBuf, process::Command};

fn temp(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ant-custody-{name}-{}",
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

/// A library with one sample that has five entries.
fn library_with_log(name: &str) -> (PathBuf, Library, String) {
    let root = temp(name);
    let mut library = Library::open(&root).unwrap();
    let added = library
        .add_bytes(
            b"#!/bin/sh\necho custody\n",
            NewSample {
                name: "custody.sh".into(),
                ..NewSample::default()
            },
        )
        .unwrap();
    let sha = added.sha256;
    library
        .set_text(&sha, "custody.sh", "first description")
        .unwrap();
    library
        .record_event(
            &sha,
            "analyst",
            CustodyEvent::Sent {
                vm: "vm1".into(),
                path: "/tmp/x".into(),
            },
        )
        .unwrap();
    library
        .record_event(
            &sha,
            "app",
            CustodyEvent::SeenInRun {
                vm: "vm1".into(),
                run: "7".into(),
            },
        )
        .unwrap();
    (root, library, sha)
}

fn update(library: &Library, sql: &str, args: &[&dyn rusqlite::ToSql]) {
    library.connection.execute(sql, args).unwrap();
}

#[test]
fn entries_are_chained_and_the_index_names_each_head() {
    let (_, library, sha) = library_with_log("chain");
    let entries = library.custody_entries(&sha).unwrap();
    assert!(entries.len() >= 4, "{entries:?}");
    assert_eq!(entries[0].prev, chain_check::ZERO);
    for pair in entries.windows(2) {
        assert_eq!(pair[1].prev, pair[0].hash);
        assert_eq!(pair[1].seq, pair[0].seq + 1);
    }
    for entry in &entries {
        assert_eq!(chain_check::entry_hash(&sha, entry), entry.hash);
        assert!(!entry.before_chain);
    }
    let check = library.custody_check(&sha).unwrap();
    assert!(check.ok(), "{check:?}");
    assert_eq!(check.entries, entries.len() as u64);
    assert_eq!(check.head, entries.last().unwrap().hash);
    let index = library.custody_index().unwrap();
    assert_eq!(index.len(), entries.len());
    assert_eq!(index.last().unwrap().entry_hash, check.head);
    let all = library.custody_check_all().unwrap();
    assert!(all.ok(), "{all:?}");
    assert_eq!(all.index.head, index.last().unwrap().hash);
    // The listing carries the chain fields.
    let rows = library.events(&sha).unwrap();
    assert_eq!(rows[1].prev, rows[0].hash);
}

#[test]
fn an_edited_entry_is_found_at_that_entry() {
    let (_, library, sha) = library_with_log("edit");
    update(
        &library,
        "UPDATE custody_entry SET by='nobody' WHERE sha256=?1 AND seq=2",
        &[&sha],
    );
    let check = library.custody_check(&sha).unwrap();
    let problem = check.problem.clone().unwrap();
    assert_eq!(problem.at, 2, "{problem:?}");
    assert_eq!(check.state_of(1), EntryState::Verified);
    assert_eq!(check.state_of(2), EntryState::Changed);
    assert_eq!(check.state_of(3), EntryState::Unverified);
    assert!(check.summary().starts_with("Entry 2"));
    assert_eq!(
        library.custody_check_all().unwrap().broken(),
        [sha.as_str()]
    );
}

#[test]
fn a_removed_entry_in_the_middle_is_found() {
    let (_, library, sha) = library_with_log("remove");
    update(
        &library,
        "DELETE FROM custody_entry WHERE sha256=?1 AND seq=3",
        &[&sha],
    );
    let problem = library.custody_check(&sha).unwrap().problem.unwrap();
    assert_eq!(problem.at, 3, "{problem:?}");
    assert!(problem.text.contains("missing"), "{problem:?}");
}

#[test]
fn removed_last_entries_are_found_through_the_index() {
    let (_, library, sha) = library_with_log("tail");
    let last = library.custody_entries(&sha).unwrap().len() as i64;
    update(
        &library,
        "DELETE FROM custody_entry WHERE sha256=?1 AND seq=?2",
        &[&sha, &last],
    );
    // The chain alone is intact; the index remembers the entry.
    let problem = library.custody_check(&sha).unwrap().problem.unwrap();
    assert_eq!(problem.at, last as u64, "{problem:?}");
    assert!(problem.text.contains("library index"), "{problem:?}");
}

#[test]
fn reordered_entries_are_found() {
    let (_, library, sha) = library_with_log("reorder");
    update(
        &library,
        "UPDATE custody_entry SET seq=99 WHERE sha256=?1 AND seq=2",
        &[&sha],
    );
    update(
        &library,
        "UPDATE custody_entry SET seq=2 WHERE sha256=?1 AND seq=3",
        &[&sha],
    );
    update(
        &library,
        "UPDATE custody_entry SET seq=3 WHERE sha256=?1 AND seq=99",
        &[&sha],
    );
    let problem = library.custody_check(&sha).unwrap().problem.unwrap();
    assert_eq!(problem.at, 2, "{problem:?}");
}

#[test]
fn a_whole_rewritten_chain_is_caught_by_the_index() {
    let (_, library, sha) = library_with_log("rewrite");
    let mut entries = library.custody_entries(&sha).unwrap();
    entries[1].by = "someone else".into();
    let mut previous = entries[0].hash.clone();
    for entry in entries.iter_mut().skip(1) {
        entry.prev = previous.clone();
        entry.hash = chain_check::entry_hash(&sha, entry);
        previous = entry.hash.clone();
        update(
            &library,
            "UPDATE custody_entry SET by=?3, prev=?4, hash=?5 WHERE sha256=?1 AND seq=?2",
            &[
                &sha,
                &(entry.seq as i64),
                &entry.by,
                &entry.prev,
                &entry.hash,
            ],
        );
    }
    let problem = library.custody_check(&sha).unwrap().problem.unwrap();
    assert_eq!(problem.at, 2, "{problem:?}");
    assert!(problem.text.contains("library index"), "{problem:?}");
}

#[test]
fn a_removed_sample_log_is_found_through_the_index_chain() {
    let (_, library, sha) = library_with_log("whole");
    update(
        &library,
        "DELETE FROM custody_entry WHERE sha256=?1",
        &[&sha],
    );
    let all = library.custody_check_all().unwrap();
    assert!(all.index.problem.is_none());
    assert_eq!(all.broken(), [sha.as_str()]);
    let problem = all.samples[&sha].problem.clone().unwrap();
    assert!(problem.text.contains("whole log is gone"), "{problem:?}");
}

#[test]
fn an_edited_or_cut_index_is_found() {
    let (_, library, _) = library_with_log("index");
    update(
        &library,
        "UPDATE custody_index SET entry_seq=entry_seq+1 WHERE seq=2",
        &[],
    );
    assert_eq!(
        library
            .custody_check_all()
            .unwrap()
            .index
            .problem
            .unwrap()
            .at,
        2
    );
    let (_, library, _) = library_with_log("index2");
    update(&library, "DELETE FROM custody_index WHERE seq=2", &[]);
    assert_eq!(
        library
            .custody_check_all()
            .unwrap()
            .index
            .problem
            .unwrap()
            .at,
        2
    );
}

#[test]
fn a_purge_is_recorded_in_the_index_and_leaves_no_alarm() {
    let (root, mut library, sha) = library_with_log("purge");
    let archive = library.archive_path(&sha).unwrap();
    assert!(archive.is_file());
    library.purge(&sha).unwrap();
    assert!(!archive.exists());
    assert!(library.get(&sha).unwrap().is_none());
    assert!(library.custody_entries(&sha).unwrap().is_empty());
    let all = library.custody_check_all().unwrap();
    assert!(all.ok(), "{all:?}");
    assert!(!all.samples.contains_key(&sha));
    let index = library.custody_index().unwrap();
    let purge = index.last().unwrap();
    assert_eq!(
        (purge.kind.as_str(), purge.sha256.as_str()),
        ("purge", sha.as_str())
    );
    assert!(purge.entry_seq >= 4);
    // The same bytes added again start a new chain that checks out.
    let mut library = Library::open(&root).unwrap();
    library
        .add_bytes(b"#!/bin/sh\necho custody\n", NewSample::default())
        .unwrap();
    let all = library.custody_check_all().unwrap();
    assert!(all.ok(), "{all:?}");
    assert_eq!(all.samples[&sha].entries, 1);
}

#[test]
fn remove_keeps_the_log_and_adds_a_removed_entry() {
    let (_, mut library, sha) = library_with_log("removed");
    let before = library.custody_entries(&sha).unwrap().len();
    library.remove(&sha).unwrap();
    let rows = library.events(&sha).unwrap();
    assert_eq!(rows.len(), before + 1);
    assert_eq!(rows.last().unwrap().event, CustodyEvent::Removed);
    assert!(library.custody_check(&sha).unwrap().ok());
}

#[test]
fn plain_events_are_migrated_once_and_marked() {
    let root = temp("migrate");
    let sha = "ab".repeat(32);
    {
        // The library of an earlier build: plain rows, no chain.
        let library = Library::open_with(&root, std::sync::Arc::new(NoCustody)).unwrap();
        library
            .connection
            .execute("DELETE FROM meta WHERE key='custody_migrated'", [])
            .unwrap();
        for (at, by, event) in [
            (
                1_000_u64,
                "analyst",
                CustodyEvent::Added {
                    origin: "Added from this computer".into(),
                },
            ),
            (2_000, "app", CustodyEvent::Removed),
        ] {
            library
                .connection
                .execute(
                    "INSERT INTO event(sha256, at_ms, by, kind, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![sha, at as i64, by, event.label(), serde_json::to_string(&event).unwrap()],
                )
                .unwrap();
        }
        library
            .connection
            .execute(
                "INSERT INTO event(sha256, at_ms, by, kind, detail) VALUES (?1, 3, 'app', 'x', 'not json')",
                [&sha],
            )
            .unwrap();
    }
    let library = Library::open(&root).unwrap();
    let rows = library.events(&sha).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.before_chain));
    assert_eq!((rows[0].at_ms, rows[0].by.as_str()), (1_000, "analyst"));
    assert!(library.custody_check_all().unwrap().ok());
    // Opened again: nothing is brought in twice.
    drop(library);
    let library = Library::open(&root).unwrap();
    assert_eq!(library.events(&sha).unwrap().len(), 2);
    // Entries made now are not marked.
    library.note(&sha, "app", CustodyEvent::Removed).unwrap();
    let rows = library.events(&sha).unwrap();
    assert_eq!(rows.len(), 3);
    assert!(!rows[2].before_chain && rows[1].before_chain);
    assert!(library.custody_check(&sha).unwrap().ok());
    // The plain rows stay.
    let plain: i64 = library
        .connection
        .query_row("SELECT COUNT(*) FROM event", [], |row| row.get(0))
        .unwrap();
    assert_eq!(plain, 3);
}

#[test]
fn terminal_input_keeps_a_size_never_the_text() {
    let (_, library, sha) = library_with_log("redact");
    let secret = b"hunter2-super-secret\n";
    library
        .record_event(&sha, "analyst", CustodyEvent::terminal_input("7", secret))
        .unwrap();
    let entry = library.custody_entries(&sha).unwrap().pop().unwrap();
    assert!(!entry.detail.contains("hunter2"), "{}", entry.detail);
    let row = library.events(&sha).unwrap().pop().unwrap();
    assert_eq!(
        row.event,
        CustodyEvent::TerminalInput {
            run: "7".into(),
            bytes: secret.len() as u64
        }
    );
    assert!(row.event.detail().contains("not recorded"));
    // The export carries no text either.
    let (value, _) = library.custody_record(&sha).unwrap();
    assert!(!value.to_string().contains("hunter2"));
}

#[test]
fn free_text_loses_control_characters_and_is_capped() {
    let (_, library, sha) = library_with_log("clean");
    library
        .record_event(
            &sha,
            "app",
            CustodyEvent::Activity {
                run: "1".into(),
                detail: format!("a\u{1b}[31mb\nc{}", "x".repeat(custody::MAX_TEXT * 2)),
            },
        )
        .unwrap();
    let entry = library.custody_entries(&sha).unwrap().pop().unwrap();
    assert!(!entry.detail.contains('\u{1b}') && !entry.detail.contains("\\n"));
    assert!(entry.detail.len() < custody::MAX_TEXT + 200);
    assert!(library.custody_check(&sha).unwrap().ok());
}

fn python() -> Option<&'static str> {
    std::path::Path::new("/usr/bin/python3")
        .is_file()
        .then_some("/usr/bin/python3")
}

fn run_verifier(record: &std::path::Path) -> Option<(i32, String)> {
    let verifier = record.with_file_name(VERIFIER_NAME);
    let output = Command::new(python()?)
        .args(["-I"])
        .arg(&verifier)
        .arg(record)
        .output()
        .unwrap();
    Some((
        output.status.code().unwrap(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

#[test]
fn a_json_export_verifies_in_rust_and_in_the_bundled_verifier() {
    let (root, mut library, sha) = library_with_log("export");
    let dest = root.join("out").join("record.json");
    let exported = library
        .export_custody(&sha, ExportFormat::Json, &dest, None)
        .unwrap();
    assert!(exported.verified && exported.signature.is_none());
    assert_eq!(
        exported.verifier.as_ref().unwrap(),
        &dest.with_file_name(VERIFIER_NAME)
    );
    let text = fs::read_to_string(&dest).unwrap();
    let checked = verify_record(&text).unwrap();
    assert!(checked.check.ok(), "{checked:?}");
    assert_eq!(checked.check.head, exported.head);
    if let Some((code, out)) = run_verifier(&dest) {
        assert_eq!(code, 0, "{out}");
        assert!(out.contains(&exported.head), "{out}");
        assert!(out.contains("not tamper-proof"), "{out}");
    }
    // The export is itself in the log, after the head it contains.
    let rows = library.events(&sha).unwrap();
    assert!(matches!(
        &rows.last().unwrap().event,
        CustodyEvent::Exported { head, signed, .. } if *head == exported.head && signed == "unsigned"
    ));
    assert!(library.custody_check(&sha).unwrap().ok());
}

/// Edit the exported record the way a person would, and see both checkers
/// name the same entry.
fn tampered(text: &str, change: impl Fn(&mut serde_json::Value)) -> String {
    let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
    change(&mut value);
    serde_json::to_string_pretty(&value).unwrap()
}

#[test]
fn an_edited_removed_or_reordered_export_fails_both_checkers() {
    let (root, mut library, sha) = library_with_log("tamper");
    let dest = root.join("record.json");
    library
        .export_custody(&sha, ExportFormat::Json, &dest, None)
        .unwrap();
    let good = fs::read_to_string(&dest).unwrap();
    type Edit = Box<dyn Fn(&mut serde_json::Value)>;
    let cases: [(&str, Edit, u64); 4] = [
        (
            "edited",
            Box::new(|v| v["entries"][1]["by"] = "someone".into()),
            2,
        ),
        (
            "removed",
            Box::new(|v| {
                v["entries"].as_array_mut().unwrap().remove(2);
            }),
            3,
        ),
        (
            "tail cut",
            Box::new(|v| {
                v["entries"].as_array_mut().unwrap().pop();
            }),
            4,
        ),
        (
            "reordered",
            Box::new(|v| {
                // Entry 3's content under entry 2's number and the reverse.
                let (second, third) = (v["entries"][1].clone(), v["entries"][2].clone());
                v["entries"][1] = third;
                v["entries"][1]["seq"] = 2.into();
                v["entries"][2] = second;
                v["entries"][2]["seq"] = 3.into();
            }),
            2,
        ),
    ];
    for (name, change, at) in cases {
        let text = tampered(&good, change);
        let checked = verify_record(&text).unwrap();
        assert_eq!(
            checked.check.problem.as_ref().map(|p| p.at),
            Some(at),
            "{name}: {checked:?}"
        );
        let file = root.join(format!("{name}.json").replace(' ', "-"));
        fs::write(&file, &text).unwrap();
        if let Some((code, out)) = run_verifier(&file) {
            assert_eq!(code, 1, "{name}: {out}");
            assert!(
                out.contains(&format!("entry {at} changed")),
                "{name}: {out}"
            );
        }
    }
    // Not a record at all.
    assert!(verify_record("{\"format\": \"other\"}").is_err());
}

#[test]
fn an_html_export_embeds_the_record_and_survives_hostile_text() {
    let (root, mut library, sha) = library_with_log("html");
    library
        .record_event(
            &sha,
            "app",
            CustodyEvent::Activity {
                run: "1".into(),
                detail: "</script><img src=x onerror=alert(1)>".into(),
            },
        )
        .unwrap();
    let dest = root.join("record.html");
    let exported = library
        .export_custody(&sha, ExportFormat::Html, &dest, None)
        .unwrap();
    assert!(exported.verifier.is_none());
    let page = fs::read_to_string(&dest).unwrap();
    assert!(!page.contains("<img src=x"), "unescaped text in the page");
    assert_eq!(page.matches("</script>").count(), 1);
    assert!(page.contains("not tamper-proof"));
    let checked = verify_record(&page).unwrap();
    assert!(checked.check.ok(), "{checked:?}");
    if let Some(python) = python() {
        // The bundled verifier reads the HTML too.
        let verifier = root.join(VERIFIER_NAME);
        fs::write(&verifier, VERIFIER).unwrap();
        let status = Command::new(python)
            .arg("-I")
            .arg(&verifier)
            .arg(&dest)
            .status()
            .unwrap();
        assert!(status.success());
    }
}

#[test]
fn a_broken_log_is_exported_marked_and_the_verifier_agrees() {
    let (root, mut library, sha) = library_with_log("brokenexport");
    update(
        &library,
        "UPDATE custody_entry SET by='x' WHERE sha256=?1 AND seq=2",
        &[&sha],
    );
    let dest = root.join("record.json");
    let exported = library
        .export_custody(&sha, ExportFormat::Json, &dest, None)
        .unwrap();
    assert!(!exported.verified);
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&dest).unwrap()).unwrap();
    assert_eq!(value["status"]["verified"], false);
    assert_eq!(value["status"]["problem"]["at"], 2);
    let file = root.join("record.html");
    library
        .export_custody(&sha, ExportFormat::Html, &file, None)
        .unwrap();
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains("Log broken at entry 2")
    );
}

#[test]
fn a_signature_is_made_by_the_analysts_own_tool() {
    let (root, mut library, sha) = library_with_log("sign");
    // A stand-in for minisign: it checks it was called the way minisign is.
    let stub = root.join("minisign");
    fs::write(
        &stub,
        "#!/bin/sh\n[ \"$1\" = -S ] && [ \"$2\" = -s ] && [ \"$4\" = -m ] && [ \"$6\" = -x ] || exit 3\necho signed-by-stub > \"$7\"\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let key = root.join("minisign.key");
    fs::write(&key, "untrusted comment: test\n").unwrap();
    let file = root.join("a.json");
    fs::write(&file, "{}").unwrap();
    let with = SignWith {
        signer: Signer::Minisign,
        key: key.clone(),
    };
    let signature = sign_file(&with, &file, Some(&stub)).unwrap();
    assert_eq!(signature, root.join("a.json.minisig"));
    assert_eq!(
        fs::read_to_string(&signature).unwrap().trim(),
        "signed-by-stub"
    );
    // A missing key and a failing tool are errors; the export is not left behind.
    let missing = SignWith {
        signer: Signer::Ssh,
        key: root.join("none"),
    };
    assert!(
        sign_file(&missing, &file, None)
            .unwrap_err()
            .contains("does not exist")
    );
    let dest = root.join("signed.json");
    let error = library
        .export_custody(
            &sha,
            ExportFormat::Json,
            &dest,
            Some(&SignWith {
                signer: Signer::Minisign,
                key: key.clone(),
            }),
        )
        .unwrap_err();
    assert!(error.contains("minisign"), "{error}");
    assert!(!dest.exists(), "an unsigned export must not stay");
    assert!(
        !library
            .events(&sha)
            .unwrap()
            .iter()
            .any(|row| matches!(row.event, CustodyEvent::Exported { .. }))
    );
}

#[test]
fn an_ssh_signature_checks_with_ssh_keygen() {
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        return;
    }
    let (root, mut library, sha) = library_with_log("ssh");
    let key = root.join("id_test");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let dest = root.join("signed.json");
    let exported = library
        .export_custody(
            &sha,
            ExportFormat::Json,
            &dest,
            Some(&SignWith {
                signer: Signer::Ssh,
                key: key.clone(),
            }),
        )
        .unwrap();
    let signature = exported.signature.unwrap();
    let check = |file: &std::path::Path| {
        Command::new("ssh-keygen")
            .args(["-Y", "check-novalidate", "-n", SSH_NAMESPACE, "-s"])
            .arg(&signature)
            .stdin(fs::File::open(file).unwrap())
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(check(&dest));
    // An edited export no longer matches its signature.
    let edited = root.join("edited.json");
    fs::write(
        &edited,
        fs::read_to_string(&dest)
            .unwrap()
            .replace("custody.sh", "other.sh"),
    )
    .unwrap();
    assert!(!check(&edited));
    assert!(matches!(
        &library.events(&sha).unwrap().last().unwrap().event,
        CustodyEvent::Exported { signed, .. } if signed.contains("SSH")
    ));
}

#[test]
fn the_global_log_filters_by_kind_and_text() {
    let (_, mut library, sha) = library_with_log("global");
    let other = library
        .add_bytes(
            b"second sample\n",
            NewSample {
                name: "second.bin".into(),
                ..NewSample::default()
            },
        )
        .unwrap()
        .sha256;
    let all = library.custody_log(&CustodyQuery::default()).unwrap();
    assert!(all.iter().any(|row| row.sha256 == other));
    assert!(all.iter().any(|row| row.sha256 == sha));
    assert!(
        all.windows(2)
            .all(|pair| pair[0].row.at_ms >= pair[1].row.at_ms)
    );
    let sent = library
        .custody_log(&CustodyQuery {
            kinds: ["sent".to_owned()].into(),
            ..CustodyQuery::default()
        })
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].name, "custody.sh");
    let text = library
        .custody_log(&CustodyQuery {
            text: "SECOND".into(),
            ..CustodyQuery::default()
        })
        .unwrap();
    assert!(!text.is_empty() && text.iter().all(|row| row.sha256 == other));
    let limited = library
        .custody_log(&CustodyQuery {
            limit: 2,
            ..CustodyQuery::default()
        })
        .unwrap();
    assert_eq!(limited.len(), 2);
}
