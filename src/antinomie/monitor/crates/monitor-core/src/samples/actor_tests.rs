// SPDX-License-Identifier: GPL-3.0-only
//! Actor identity and the `automation` entry kind (card P3-7, design 4.11).
use super::*;
use std::{fs, path::PathBuf, process::Command};

fn setup(name: &str) -> (PathBuf, Library) {
    let root =
        std::env::temp_dir().join(format!("ant-actor-{name}-{}", crate::storage::unique_id()));
    fs::create_dir_all(&root).unwrap();
    let library = Library::open(&root).unwrap();
    (root, library)
}

fn sample(name: &str) -> NewSample {
    NewSample {
        name: name.into(),
        ..NewSample::default()
    }
}

fn entries(library: &Library, sha: &str) -> Vec<(String, String)> {
    settle_custody();
    library
        .custody_entries(sha)
        .unwrap()
        .into_iter()
        .map(|e| (e.kind, e.by))
        .collect()
}

#[test]
fn the_caller_is_the_actor_of_an_intake() {
    let (root, mut library) = setup("intake");
    let bytes = b"#!/bin/sh\necho actor\n";
    let added = library
        .add_bytes_as(bytes, sample("actor.sh"), "auto:policy-default")
        .unwrap();
    assert_eq!(
        entries(&library, &added.sha256),
        [("added".to_owned(), "auto:policy-default".to_owned())]
    );
    // The same bytes again by another caller: an origin, under that caller.
    library
        .add_bytes_as(bytes, sample("actor.sh"), "web:alice")
        .unwrap();
    library
        .add_bytes_as(bytes, sample("actor.sh"), "local:1000")
        .unwrap();
    let by: Vec<_> = entries(&library, &added.sha256)
        .into_iter()
        .map(|e| e.1)
        .collect();
    assert_eq!(by, ["auto:policy-default", "web:alice", "local:1000"]);
    // The GUI's calls still say `app`.
    library.add_bytes(bytes, sample("actor.sh")).unwrap();
    assert_eq!(entries(&library, &added.sha256).last().unwrap().1, "app");
    assert!(library.custody_check(&added.sha256).unwrap().ok());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_name_the_log_does_not_accept_writes_nothing() {
    let (root, mut library) = setup("invalid");
    for bad in ["", "root", "local:abc", "web:\n", "x".repeat(300).as_str()] {
        let error = library.add_bytes_as(b"data", sample("x"), bad).unwrap_err();
        assert!(error.contains("not a custody actor"), "{bad:?}: {error}");
    }
    assert!(library.list().unwrap().is_empty(), "nothing was added");
    assert!(Library::open(&root).unwrap().with_actor("nobody").is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn events_the_library_writes_for_a_job_carry_its_actor() {
    let (root, library) = setup("events");
    let mut library = library.with_actor("auto:policy-ci").unwrap();
    let sha = library.add_bytes(b"data", sample("d")).unwrap().sha256;
    library
        .record_push(
            &sha,
            Push {
                vm_id: "v".into(),
                vm_name: "vm".into(),
                path: "/tmp/x".into(),
                at_ms: 5,
            },
        )
        .unwrap();
    let by: Vec<_> = entries(&library, &sha);
    assert_eq!(
        by,
        [
            ("added".to_owned(), "auto:policy-ci".to_owned()),
            ("sent".to_owned(), "auto:policy-ci".to_owned())
        ]
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_run_log_names_the_caller_for_the_program_and_the_analyst_for_the_person() {
    let (root, mut library) = setup("runlog");
    let sha = library.add_bytes(b"data", sample("d")).unwrap().sha256;
    let reference = SampleRef {
        sha256: sha.clone(),
        name: "d".into(),
    };
    let mut log = RunLog::with_actor(&root, &reference, "r1", "vm", "auto:policy-ci");
    log.started("setup".into());
    log.typed(b"ls\n");
    log.ended("done".into());
    let kinds: Vec<_> = entries(&library, &sha).into_iter().skip(1).collect();
    assert_eq!(
        kinds,
        [
            ("run_started".to_owned(), "auto:policy-ci".to_owned()),
            ("terminal_input".to_owned(), "analyst".to_owned()),
            ("run_ended".to_owned(), "auto:policy-ci".to_owned()),
        ]
    );
    let _ = fs::remove_dir_all(root);
}

fn automation() -> CustodyEvent {
    CustodyEvent::Automation {
        job: "j_0123456789ABCDEFGHJKMNPQRS".into(),
        policy: "default".into(),
        policy_digest: "ab".repeat(32),
        route: "drop".into(),
        submitted_by: "local:1000".into(),
    }
}

#[test]
fn the_automation_kind_is_listed_labelled_and_stored() {
    assert_eq!(KINDS.len(), 21);
    assert!(KINDS.contains(&("automation", "Automation")));
    let event = automation();
    assert_eq!(event.key(), "automation");
    assert_eq!(event.label(), "Automation");
    assert_eq!(
        event.detail(),
        "Job j_0123456789ABCDEFGHJKMNPQRS, policy default (abababab), route drop, submitted by local:1000"
    );
    // Every key an event can have is a listed kind.
    for kind in KINDS {
        assert_ne!(custody::label_of(kind.0), "Unknown event", "{}", kind.0);
    }
    // Text in the fields is cleaned like any other.
    let dirty = CustodyEvent::Automation {
        job: "j\u{1b}[31m".into(),
        policy: "p".into(),
        policy_digest: "d".into(),
        route: "drop".into(),
        submitted_by: "local:1".into(),
    };
    assert!(!dirty.stored().unwrap().contains('\u{1b}'));
}

#[test]
fn an_automation_entry_chains_exports_and_verifies_everywhere() {
    let (root, mut library) = setup("automation");
    let sha = library
        .add_bytes_as(b"#!/bin/sh\necho x\n", sample("x.sh"), "local:1000")
        .unwrap()
        .sha256;
    library
        .record_event(&sha, "auto:policy-default", automation())
        .unwrap();
    let rows = library.events(&sha).unwrap();
    assert!(
        matches!(&rows.last().unwrap().event, CustodyEvent::Automation { route, .. } if route == "drop")
    );
    assert_eq!(rows.last().unwrap().by, "auto:policy-default");
    assert!(library.custody_check(&sha).unwrap().ok());

    let dest = root.join("out").join("record.json");
    let exported = library
        .export_custody(&sha, ExportFormat::Json, &dest, None)
        .unwrap();
    assert!(exported.verified);
    let text = fs::read_to_string(&dest).unwrap();
    assert!(verify_record(&text).unwrap().check.ok());
    assert!(text.contains("\"automation\""));

    if std::path::Path::new("/usr/bin/python3").is_file() {
        let verifier = dest.with_file_name(VERIFIER_NAME);
        let run = |record: &std::path::Path| {
            let out = Command::new("/usr/bin/python3")
                .arg("-I")
                .arg(&verifier)
                .arg(record)
                .output()
                .unwrap();
            (
                out.status.code().unwrap(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
            )
        };
        let (code, out) = run(&dest);
        assert_eq!(code, 0, "{out}");
        assert!(!out.contains("note:"), "a known kind needs no note: {out}");
        // Editing the automation entry after the fact is found.
        let edited = text.replace("\\\"route\\\":\\\"drop\\\"", "\\\"route\\\":\\\"tor\\\"");
        assert_ne!(edited, text);
        let bad = root.join("edited.json");
        fs::write(&bad, edited).unwrap();
        assert_eq!(run(&bad).0, 1);
    }
    let _ = fs::remove_dir_all(root);
}
