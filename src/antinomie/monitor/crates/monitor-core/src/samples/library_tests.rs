// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::sync::{Arc, Mutex};

fn temp(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ant-library-{name}-{}",
        crate::storage::unique_id()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn sha(bytes: &[u8]) -> String {
    crate::storage::sha256_hex(bytes)
}

const SCRIPT: &[u8] = b"#!/bin/sh\necho hello\n";

fn elf() -> Vec<u8> {
    let mut bytes = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
    bytes.extend((0..4096u32).map(|n| (n * 7 % 251) as u8));
    bytes
}

/// An archive as the old layout kept it: one AES zip at the folder's top.
fn legacy_archive(root: &Path, bytes: &[u8]) -> String {
    let hash = sha(bytes);
    let dir = samples_dir(root);
    fs::create_dir_all(&dir).unwrap();
    let mut writer =
        zip::ZipWriter::new(fs::File::create(dir.join(format!("{hash}.zip"))).unwrap());
    writer
        .start_file(
            "x.bin",
            zip::write::SimpleFileOptions::default()
                .with_aes_encryption(zip::AesMode::Aes128, ARCHIVE_PASSWORD),
        )
        .unwrap();
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap();
    hash
}

fn legacy_record(root: &Path, hash: &str, source: &str, pushes: Vec<Push>) {
    let record = StoredSample {
        info: SampleInfo {
            sha256_hash: hash.into(),
            file_name: "miner.elf".into(),
            file_type: "elf".into(),
            file_arch: Some("x86_64".into()),
            signature: Some("Kinsing".into()),
            file_size: 4116,
            ..SampleInfo::default()
        },
        source: source.into(),
        downloaded_ms: 1_700_000_000_000,
        pushes,
    };
    fs::write(
        samples_dir(root).join(format!("{hash}.json")),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
}

fn added_from(path: &str) -> NewSample {
    NewSample {
        origin: NewOrigin {
            kind: OriginKind::Added,
            path: path.into(),
            ..NewOrigin::default()
        },
        ..NewSample::default()
    }
}

#[test]
fn a_file_is_archived_by_its_hash_and_the_same_bytes_add_an_origin() {
    let root = temp("add");
    let first = root.join("install.sh");
    let second = root.join("copy-of-install");
    fs::write(&first, SCRIPT).unwrap();
    fs::write(&second, SCRIPT).unwrap();
    let mut library = Library::open(&root).unwrap();
    let probe = library.probe_file(&first).unwrap();
    assert_eq!(
        (probe.size, probe.file_type.as_str(), probe.known),
        (SCRIPT.len() as u64, "sh", false)
    );
    assert_eq!(probe.sha256, sha(SCRIPT));
    let added = library
        .add_file(
            &first,
            NewSample {
                description: "installer".into(),
                tags: vec![Tag::new(TagKind::Verdict, "malicious")],
                ..added_from("")
            },
            false,
        )
        .unwrap();
    assert!(added.new && added.sha256 == probe.sha256);
    assert!(library.probe_file(&second).unwrap().known);
    let again = library.add_file(&second, added_from(""), false).unwrap();
    assert!(!again.new && again.sha256 == added.sha256);
    // One sample, two origins, two aliases, and one archive in its shard.
    assert_eq!(library.list().unwrap().len(), 1);
    let origins = library.origins(&added.sha256).unwrap();
    assert_eq!(origins.len(), 2);
    assert!(origins.iter().all(|origin| !origin.before_custody));
    let aliases = library.aliases(&added.sha256).unwrap();
    assert_eq!(
        aliases.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
        ["install.sh", "copy-of-install"]
    );
    let archive = library.archive_path(&added.sha256).unwrap();
    assert_eq!(
        archive.parent().unwrap().file_name().unwrap().to_str(),
        Some(&added.sha256[..2])
    );
    assert!(
        !fs::read(&archive)
            .unwrap()
            .windows(SCRIPT.len())
            .any(|w| w == SCRIPT)
    );
    let record = library.get(&added.sha256).unwrap().unwrap();
    assert_eq!(
        (
            record.name.as_str(),
            record.description.as_str(),
            record.file_type.as_str()
        ),
        ("install.sh", "installer", "sh")
    );
    assert_eq!(record.sha1.len(), 40);
    assert_eq!(record.md5.len(), 32);
    // Both originals are still there: nothing was deleted without asking.
    assert!(first.is_file() && second.is_file());
    let events: Vec<_> = library
        .events(&added.sha256)
        .unwrap()
        .into_iter()
        .map(|row| row.event.label())
        .collect();
    assert_eq!(events, ["Added", "Origin added"]);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_original_is_deleted_only_after_the_archive_reads_back() {
    let root = temp("delete-original");
    let file = root.join("dropper.sh");
    fs::write(&file, SCRIPT).unwrap();
    let mut library = Library::open(&root).unwrap();
    let added = library.add_file(&file, added_from(""), true).unwrap();
    assert!(!file.exists());
    assert!(library.verify(&added.sha256).unwrap().is_ok());
    assert_eq!(library.open_bytes(&added.sha256).unwrap(), SCRIPT);
    let logged = library.events(&added.sha256).unwrap();
    assert!(logged.iter().any(|row| matches!(
        &row.event,
        CustodyEvent::OriginalDeleted { path } if path.ends_with("dropper.sh")
    )));
    // Too large, a directory or a missing file are refused before anything is kept.
    assert!(library.add_file(&root, added_from(""), false).is_err());
    assert!(
        library
            .add_file(&root.join("none"), added_from(""), true)
            .is_err()
    );
    assert_eq!(library.list().unwrap().len(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn old_records_migrate_once_with_their_pushes_and_keep_their_json() {
    let root = temp("migrate");
    let bytes = elf();
    let hash = legacy_archive(&root, &bytes);
    legacy_record(
        &root,
        &hash,
        "MalwareBazaar",
        vec![Push {
            vm_id: "vm1".into(),
            vm_name: "Debian".into(),
            path: "/tmp/m".into(),
            at_ms: 5,
        }],
    );
    // A record without its archive stays where it is; a stray file is ignored.
    let orphan = "b".repeat(64);
    legacy_record(&root, &orphan, "MalShare", Vec::new());
    fs::write(samples_dir(&root).join("acknowledged.json"), b"{}").unwrap();
    {
        let library = Library::open(&root).unwrap();
        let record = library.get(&hash).unwrap().unwrap();
        assert_eq!(
            (
                record.name.as_str(),
                record.family.as_str(),
                record.arch.as_str()
            ),
            ("miner.elf", "Kinsing", "x86_64")
        );
        let origin = &library.origins(&hash).unwrap()[0];
        assert!(origin.before_custody && origin.kind == OriginKind::Download);
        assert_eq!(origin.source, "MalwareBazaar");
        assert_eq!(library.pushes(&hash).unwrap()[0].vm_name, "Debian");
        assert_eq!(library.events(&hash).unwrap()[0].event.label(), "Migrated");
        assert!(library.verify(&hash).unwrap().is_ok());
    }
    let dir = samples_dir(&root);
    assert!(!dir.join(format!("{hash}.zip")).exists());
    assert!(dir.join(&hash[..2]).join(format!("{hash}.zip")).is_file());
    assert!(dir.join("legacy").join(format!("{hash}.json")).is_file());
    assert!(dir.join(format!("{orphan}.json")).is_file());
    assert!(dir.join("acknowledged.json").is_file());
    // Opening again changes nothing.
    let library = Library::open(&root).unwrap();
    assert_eq!(library.list().unwrap().len(), 1);
    assert_eq!(library.origins(&hash).unwrap().len(), 1);
    assert_eq!(library.pushes(&hash).unwrap().len(), 1);
    assert_eq!(stored(&root).len(), 1);
    assert_eq!(stored(&root)[0].source, "MalwareBazaar");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_interrupted_migration_finishes_without_duplicates() {
    let root = temp("interrupted");
    // The rows were written, then the app stopped before the archive moved.
    {
        let mut library = Library::open_with(&root, Arc::new(NoCustody)).unwrap();
        let hash = legacy_archive(&root, &elf());
        legacy_record(&root, &hash, "MalShare", Vec::new());
        let record: StoredSample = serde_json::from_slice(
            &fs::read(samples_dir(&root).join(format!("{hash}.json"))).unwrap(),
        )
        .unwrap();
        assert!(library.insert_migrated(&hash, &record).unwrap());
        assert!(!library.insert_migrated(&hash, &record).unwrap());
        assert!(!library.archive_path(&hash).unwrap().exists());
    }
    let hash = sha(&elf());
    let library = Library::open(&root).unwrap();
    assert_eq!(library.list().unwrap().len(), 1);
    assert_eq!(library.origins(&hash).unwrap().len(), 1);
    assert!(library.verify(&hash).unwrap().is_ok());
    assert!(
        samples_dir(&root)
            .join("legacy")
            .join(format!("{hash}.json"))
            .is_file()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verify_finds_missing_and_wrong_archives_and_refuses_to_send_them() {
    let root = temp("verify");
    let mut library = Library::open(&root).unwrap();
    let one = library
        .add_bytes(SCRIPT, added_from("/x/one"))
        .unwrap()
        .sha256;
    let other_bytes = elf();
    let two = library
        .add_bytes(&other_bytes, added_from("/x/two"))
        .unwrap()
        .sha256;
    // The archive of `two` is replaced by the archive of `one`.
    fs::copy(
        library.archive_path(&one).unwrap(),
        library.archive_path(&two).unwrap(),
    )
    .unwrap();
    assert!(library.verify(&one).unwrap().is_ok());
    assert!(matches!(
        library.verify(&two).unwrap(),
        Verification::Mismatch(_)
    ));
    assert!(library.open_bytes(&two).is_err());
    fs::remove_file(library.archive_path(&one).unwrap()).unwrap();
    assert_eq!(library.verify(&one).unwrap(), Verification::Missing);
    assert!(library.open_bytes(&one).is_err());
    let all = library.verify_all().unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|(_, result)| !result.is_ok()));
    assert!(
        library
            .events(&two)
            .unwrap()
            .iter()
            .any(|row| matches!(&row.event, CustodyEvent::Verified { ok: false, .. }))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn archives_without_a_record_are_found_again() {
    let root = temp("found");
    let hash = {
        let mut library = Library::open(&root).unwrap();
        library
            .add_bytes(SCRIPT, added_from("/x/s"))
            .unwrap()
            .sha256
    };
    // The database is lost; the archive is not.
    for suffix in ["", "-journal"] {
        let _ = fs::remove_file(samples_dir(&root).join(format!("{DATABASE_NAME}{suffix}")));
    }
    let mut library = Library::open(&root).unwrap();
    assert!(library.list().unwrap().is_empty());
    let results = library.verify_all().unwrap();
    assert_eq!(results, vec![(hash.clone(), Verification::Matches)]);
    assert_eq!(library.origins(&hash).unwrap()[0].kind, OriginKind::Found);
    fs::remove_dir_all(root).unwrap();
}

const DATABASE_NAME: &str = library::DATABASE;

#[test]
fn removing_keeps_the_record_and_adding_again_restores_the_archive() {
    let root = temp("remove");
    let mut library = Library::open(&root).unwrap();
    let hash = library
        .add_bytes(SCRIPT, added_from("/x/a"))
        .unwrap()
        .sha256;
    library
        .set_tags(&hash, &[Tag::new(TagKind::Custom, "keep-me")])
        .unwrap();
    library.remove(&hash).unwrap();
    assert!(!library.contains(&hash).unwrap());
    assert!(!library.archive_path(&hash).unwrap().exists());
    assert!(library.open_bytes(&hash).is_err());
    assert!(stored(&root).is_empty());
    let record = library.get(&hash).unwrap().unwrap();
    assert!(record.removed_ms.is_some());
    assert_eq!(library.tags(&hash).unwrap().len(), 1);
    let again = library.add_bytes(SCRIPT, added_from("/x/b")).unwrap();
    assert!(again.new);
    assert!(library.contains(&hash).unwrap());
    assert!(library.verify(&hash).unwrap().is_ok());
    assert_eq!(library.origins(&hash).unwrap().len(), 2);
    assert_eq!(library.tags(&hash).unwrap()[0].value, "keep-me");
    assert!(library.remove(&"c".repeat(64)).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tags_are_checked_ordered_and_custom_ones_get_a_palette_colour() {
    let root = temp("tags");
    let mut library = Library::open(&root).unwrap();
    let hash = library
        .add_bytes(SCRIPT, added_from("/x/a"))
        .unwrap()
        .sha256;
    let tags = [
        Tag::new(TagKind::Custom, "needs-second-look"),
        Tag::new(TagKind::Category, "miner"),
        Tag::new(TagKind::Verdict, "suspicious"),
        Tag::new(TagKind::Technique, "T1053.003 Cron"),
        Tag {
            kind: TagKind::Custom,
            value: "pink-one".into(),
            color: "pink".into(),
        },
    ];
    library.set_tags(&hash, &tags).unwrap();
    let kept = library.tags(&hash).unwrap();
    assert_eq!(
        kept.iter().map(|tag| tag.kind).collect::<Vec<_>>(),
        [
            TagKind::Verdict,
            TagKind::Category,
            TagKind::Technique,
            TagKind::Custom,
            TagKind::Custom
        ]
    );
    assert_eq!(
        kept.iter()
            .find(|tag| tag.value == "needs-second-look")
            .unwrap()
            .color,
        TAG_COLORS[0]
    );
    // More than one verdict is allowed (decided in round 3), unknown ones are not.
    library
        .set_tags(
            &hash,
            &[
                Tag::new(TagKind::Verdict, "malicious"),
                Tag::new(TagKind::Verdict, "benign"),
            ],
        )
        .unwrap();
    assert_eq!(library.tags(&hash).unwrap().len(), 2);
    for bad in [
        Tag::new(TagKind::Verdict, "scary"),
        Tag::new(TagKind::Category, "virus"),
        Tag::new(TagKind::Custom, ""),
        Tag::new(TagKind::Custom, "a\nb"),
        Tag::new(TagKind::Technique, "cron"),
        Tag::new(TagKind::Technique, "T10530 Cron"),
        Tag {
            kind: TagKind::Custom,
            value: "x".into(),
            color: "mauve".into(),
        },
    ] {
        assert!(library.set_tags(&hash, &[bad]).is_err());
    }
    assert_eq!(library.tags(&hash).unwrap().len(), 2);
    assert!(library.set_tags(&"d".repeat(64), &[]).is_err());
    library
        .set_text(&hash, "renamed.sh", "line one\nline two")
        .unwrap();
    let record = library.get(&hash).unwrap().unwrap();
    assert_eq!(record.name, "renamed.sh");
    assert!(library.set_text(&hash, "bad\nname", "").is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn every_change_reaches_the_custody_sink() {
    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, String)>>);
    impl CustodySink for Recorder {
        fn record(
            &self,
            sha256: &str,
            by: &str,
            _: u64,
            event: &CustodyEvent,
        ) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((sha256.to_owned(), format!("{by}:{}", event.label())));
            Ok(())
        }
    }
    let root = temp("sink");
    let sink = Arc::new(Recorder::default());
    let mut library = Library::open_with(&root, sink.clone()).unwrap();
    let hash = library
        .add_bytes(SCRIPT, added_from("/x/a"))
        .unwrap()
        .sha256;
    library
        .record_push(
            &hash,
            Push {
                vm_name: "Debian".into(),
                path: "/tmp/a".into(),
                ..Push::default()
            },
        )
        .unwrap();
    library.set_tags(&hash, &[]).unwrap();
    library.verify(&hash).unwrap();
    library.remove(&hash).unwrap();
    let seen: Vec<String> = sink
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|(_, e)| e.clone())
        .collect();
    assert_eq!(
        seen,
        [
            "app:Added",
            "app:Sent into VM",
            "analyst:Edited",
            "app:Verified",
            "analyst:Removed"
        ]
    );
    assert!(sink.0.lock().unwrap().iter().all(|(sha, _)| *sha == hash));
    // The default sink wrote nothing, since this one replaced it.
    assert!(library.events(&hash).unwrap().is_empty());
    // A sink that fails is reported, and the change stands.
    struct Failing;
    impl CustodySink for Failing {
        fn record(&self, _: &str, _: &str, _: u64, _: &CustodyEvent) -> Result<(), String> {
            Err("disk full".into())
        }
    }
    let mut library = Library::open_with(&root, Arc::new(Failing)).unwrap();
    let error = library
        .add_bytes(b"#!/bin/sh\nexit 1\n", added_from("/x/b"))
        .unwrap_err();
    assert!(error.contains("saved, but") && error.contains("disk full"));
    assert_eq!(library.list().unwrap().len(), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn types_come_from_magic_and_a_newer_library_is_refused() {
    let elf = elf();
    assert_eq!(detect_type(&elf), ("elf", Some("x86_64")));
    assert_eq!(detect_type(b"#!/usr/bin/env python3\n"), ("py", None));
    assert_eq!(detect_type(b"#!/bin/bash\n"), ("sh", None));
    assert_eq!(detect_type(b"#! /usr/bin/env bash\n"), ("sh", None));
    assert_eq!(detect_type(b"#!/usr/bin/tclsh\n"), ("script", None));
    assert_eq!(detect_type(b"MZ\x90\0"), ("exe", None));
    assert_eq!(detect_type(b"PK\x03\x04"), ("zip", None));
    assert_eq!(detect_type(b"plain text"), ("data", None));
    let root = temp("newer");
    drop(Library::open(&root).unwrap());
    let connection = library::connect(&samples_dir(&root).join(library::DATABASE)).unwrap();
    connection
        .execute("UPDATE meta SET value='99' WHERE key='schema'", [])
        .unwrap();
    drop(connection);
    assert!(
        Library::open(&root)
            .unwrap_err()
            .contains("newer Antinomie")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_launch_of_a_sent_program_names_its_sample() {
    let root = temp("identify");
    let mut library = Library::open(&root).unwrap();
    let hash = library
        .add_bytes(SCRIPT, added_from("/x/a.sh"))
        .unwrap()
        .sha256;
    let path = format!("/tmp/{}-a.sh", &hash[..12]);
    library
        .record_push(
            &hash,
            Push {
                vm_id: "vm1".into(),
                vm_name: "Debian".into(),
                path: path.clone(),
                ..Push::default()
            },
        )
        .unwrap();
    let found = library.identify_run("vm1", &path, &[]).unwrap().unwrap();
    assert_eq!(
        (found.sha256.as_str(), found.name.as_str()),
        (hash.as_str(), "a.sh")
    );
    // A script run through its interpreter, in the right VM only.
    let through_sh = library
        .identify_run("vm1", "/bin/sh", std::slice::from_ref(&path))
        .unwrap();
    assert_eq!(through_sh.unwrap().sha256, hash);
    assert!(library.identify_run("vm2", &path, &[]).unwrap().is_none());
    assert!(
        library
            .identify_run("vm1", "/bin/ls", &[])
            .unwrap()
            .is_none()
    );
    assert!(
        library
            .identify_run("vm1", "/bin/sh", &["-c".into(), path.clone()])
            .unwrap()
            .is_none()
    );
    library.remove(&hash).unwrap();
    assert!(library.identify_run("vm1", &path, &[]).unwrap().is_none());
    fs::remove_dir_all(root).unwrap();
}

fn run(sha256: &str, id: &str, vm: &str, started: u64, exit: &str) -> SeenRun {
    SeenRun {
        sha256: sha256.into(),
        vm_id: vm.into(),
        vm_name: format!("VM {vm}"),
        run_id: id.into(),
        started_ms: Some(started),
        exit: exit.into(),
        directory: format!("/runs/{id}"),
    }
}

#[test]
fn runs_across_vms_are_counted_and_noted_once() {
    let root = temp("runs");
    let mut library = Library::open(&root).unwrap();
    let one = library
        .add_bytes(SCRIPT, added_from("/x/a.sh"))
        .unwrap()
        .sha256;
    let two = library
        .add_bytes(&elf(), added_from("/x/b"))
        .unwrap()
        .sha256;
    let stranger = "e".repeat(64);
    let runs = [
        run(&one, "r1", "vmA", 100, "Running"),
        run(&one, "r2", "vmB", 300, "Exit 0"),
        run(&two, "r3", "vmA", 200, "killed by SIGKILL"),
        // Not a library sample: skipped.
        run(&stranger, "r4", "vmA", 400, "Exit 0"),
    ];
    assert_eq!(library.index_runs(&runs).unwrap(), 3);
    // Seen again: the exit is refreshed, no new note.
    let again = [run(&one, "r1", "vmA", 100, "Exit 1")];
    assert_eq!(library.index_runs(&again).unwrap(), 0);
    let stats = library.run_stats().unwrap();
    assert_eq!(stats[&one].count, 2);
    assert_eq!(stats[&one].latest.as_ref().unwrap().run_id, "r2");
    assert_eq!(
        stats[&two].latest.as_ref().unwrap().exit,
        "killed by SIGKILL"
    );
    assert!(!stats.contains_key(&stranger));
    let listed = library.runs_of(&one).unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|r| (r.run_id.as_str(), r.exit.as_str()))
            .collect::<Vec<_>>(),
        [("r2", "Exit 0"), ("r1", "Exit 1")]
    );
    let seen = library
        .events(&one)
        .unwrap()
        .into_iter()
        .filter(|row| matches!(row.event, CustodyEvent::SeenInRun { .. }))
        .count();
    assert_eq!(seen, 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parents_and_children_come_from_origins_that_name_a_parent() {
    let root = temp("lineage");
    let mut library = Library::open(&root).unwrap();
    let parent = library
        .add_bytes(SCRIPT, added_from("/x/install.sh"))
        .unwrap()
        .sha256;
    let child_bytes = elf();
    let child = library
        .add_bytes(
            &child_bytes,
            NewSample {
                origin: NewOrigin {
                    kind: OriginKind::Dropped,
                    parent: parent.clone(),
                    run_id: "r1".into(),
                    path: "/tmp/.x".into(),
                    ..NewOrigin::default()
                },
                ..NewSample::default()
            },
        )
        .unwrap()
        .sha256;
    // The same child dropped again in another run is still one parent.
    library
        .add_bytes(
            &child_bytes,
            NewSample {
                origin: NewOrigin {
                    kind: OriginKind::Dropped,
                    parent: parent.clone(),
                    run_id: "r2".into(),
                    path: "/tmp/.y".into(),
                    ..NewOrigin::default()
                },
                ..NewSample::default()
            },
        )
        .unwrap();
    let counts = library.lineage_counts().unwrap();
    assert_eq!(counts[&child], (1, 0));
    assert_eq!(counts[&parent], (0, 1));
    // The child's aliases name both paths and runs.
    let aliases = library.aliases(&child).unwrap();
    assert_eq!(aliases.len(), 2);
    assert_eq!(aliases[0].seen, "run r1");
    let tags = library.all_tags().unwrap();
    assert!(tags.is_empty());
    library
        .set_tags(&child, &[Tag::new(TagKind::Category, "dropper")])
        .unwrap();
    assert_eq!(library.all_tags().unwrap()[&child].len(), 1);
    fs::remove_dir_all(root).unwrap();
}
