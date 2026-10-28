// SPDX-License-Identifier: GPL-3.0-only
//! A file's earlier bytes from a run's starting disk, with the real
//! `--disk-reader` worker of the `antinomie-monitor` binary: a small ext4
//! base built with `mkfs.ext4 -d` (holding /etc/crontab and
//! /etc/ld.so.preload), converted to qcow2, with the VM's overlay and a
//! checkpoint layer on top as the app lays them out. Skipped without
//! bubblewrap, qemu-img or e2fsprogs.
use antinomie_monitor_core::{
    disk_start::{DiskStart, Start, Via},
    file_before::{Before, Resolver, Wanted},
    file_before_store::Writer,
    file_writes::{Before as Under, Limits, Writes},
    kernel_notes::FileKey,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const CRONTAB: &[u8] = b"# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n";
const PRELOAD: &[u8] = b"/usr/lib/libgood.so\n";

fn tool(name: &str) -> Option<PathBuf> {
    ["/sbin", "/usr/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
}

fn qemu_img(args: &[&std::ffi::OsStr]) {
    let status = Command::new("qemu-img").args(args).output().unwrap().status;
    assert!(status.success(), "{args:?}");
}

fn stat(debugfs: &Path, image: &Path, path: &str) -> FileKey {
    let output = Command::new(debugfs)
        .arg("-R")
        .arg(format!("stat {path}"))
        .arg(image)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let field = |name: &str| -> u64 {
        let at = text.find(name).unwrap();
        text[at + name.len()..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    FileKey {
        dev: 0x801,
        ino: field("Inode:"),
        generation: field("Generation:") as u32,
    }
}

#[test]
fn a_modified_files_earlier_bytes_match_the_base_image() {
    let (Some(mkfs), Some(debugfs)) = (tool("mkfs.ext4"), tool("debugfs")) else {
        eprintln!("skipped: e2fsprogs is needed");
        return;
    };
    if !Path::new("/usr/bin/bwrap").is_file()
        || !Path::new("/usr/bin/prlimit").is_file()
        || Command::new("qemu-img").arg("--version").output().is_err()
    {
        eprintln!("skipped: bubblewrap, prlimit and qemu-img are needed");
        return;
    }
    let root = std::env::temp_dir().join(format!("ant-file-before-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("etc")).unwrap();
    fs::create_dir_all(tree.join("dev/shm")).unwrap();
    fs::write(tree.join("etc/crontab"), CRONTAB).unwrap();
    fs::write(tree.join("etc/ld.so.preload"), PRELOAD).unwrap();
    let raw = root.join("base.raw");
    fs::File::create(&raw).unwrap().set_len(16 << 20).unwrap();
    assert!(Command::new(mkfs)
        .args(["-q", "-F", "-b", "4096", "-d"])
        .arg(&tree)
        .arg(&raw)
        .status()
        .unwrap()
        .success());
    let crontab = stat(&debugfs, &raw, "/etc/crontab");
    let preload = stat(&debugfs, &raw, "/etc/ld.so.preload");
    let base = root.join("base.qcow2");
    qemu_img(&[
        "convert".as_ref(),
        "-f".as_ref(),
        "raw".as_ref(),
        "-O".as_ref(),
        "qcow2".as_ref(),
        raw.as_os_str(),
        base.as_os_str(),
    ]);
    fs::remove_file(&raw).unwrap();
    // The VM's writable overlay, empty at the boot's start.
    let active = root.join("disk.qcow2");
    qemu_img(&[
        "create".as_ref(),
        "-q".as_ref(),
        "-f".as_ref(),
        "qcow2".as_ref(),
        "-b".as_ref(),
        base.as_os_str(),
        "-F".as_ref(),
        "qcow2".as_ref(),
        active.as_os_str(),
    ]);

    // The boot records its starting disk; the run's folder is inside it.
    let boot = root.join("rec/boots/b1");
    let run = boot.join("runs/r1");
    fs::create_dir_all(&run).unwrap();
    let start = DiskStart::capture(&active, "b1", Via::Start);
    assert!(matches!(start.start, Start::Frozen(_)), "{start:?}");
    start.save(&boot).unwrap();

    // Then the run changes the files: the overlay fills up. The starting
    // disk is untouched, so the earlier bytes still read.
    let status = Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", "write -P 0x41 0 4096"])
        .arg(&active)
        .output()
        .unwrap()
        .status;
    assert!(status.success());

    let app = Path::new(env!("CARGO_BIN_EXE_antinomie-monitor")).to_path_buf();
    let mut resolver = Resolver::new(&[(run.clone(), "b1".into())], Some(app.clone()));
    let wanted = |path: &'static str, key: Option<FileKey>, created: bool| Wanted {
        path,
        names: &[],
        key,
        created,
        first_segment: 0,
        last_segment: 0,
    };
    let (before, file) = resolver.resolve(&wanted("/etc/crontab", Some(crontab), false));
    if let Before::Unavailable(why) = &before {
        if why.contains("namespace") || why.contains("sandbox") || why.contains("isolation") {
            eprintln!("skipped: {why}");
            let _ = fs::remove_dir_all(&root);
            return;
        }
    }
    assert_eq!(
        before,
        Before::OnDisk {
            size: CRONTAB.len() as u64,
            exact: true
        }
    );
    let file = file.unwrap();
    assert_eq!(file.disk.read(&file.path, 0, 4096).unwrap(), CRONTAB);

    // The run wrote 8 bytes at offset 10; laid over the earlier bytes, the
    // file reads as before except there, and the bytes under it still read.
    let (before, file) = resolver.resolve(&wanted("/etc/ld.so.preload", Some(preload), false));
    assert_eq!(
        before,
        Before::OnDisk {
            size: PRELOAD.len() as u64,
            exact: true
        }
    );
    let file = file.unwrap();
    let mut writes = Writes::default();
    let mut budget = antinomie_monitor_core::file_writes::Budget::default();
    writes.add(
        &mut budget,
        Some(10),
        8,
        vec![antinomie_monitor_core::file_writes::Captured {
            rel: 0,
            len: 8,
            source: antinomie_monitor_core::file_writes::Source::Inline(b"EVIL.so\n".to_vec()),
        }],
    );
    let under = Under {
        size: PRELOAD.len() as u64,
        source: antinomie_monitor_core::file_writes::Source::Disk {
            file: file.clone(),
            at: 0,
        },
    };
    let mut expect = PRELOAD.to_vec();
    expect[10..18].copy_from_slice(b"EVIL.so\n");
    assert_eq!(
        writes
            .read_over(Some(&under), 0, PRELOAD.len() as u64)
            .unwrap(),
        expect
    );
    assert_eq!(file.disk.read(&file.path, 0, 4096).unwrap(), PRELOAD);

    // The File Reconstruction map over the real disk: the same bytes, the
    // hash of the modified file, and the history of a byte under the write.
    {
        use antinomie_monitor_core::file_reconstruct::{
            sha256_hex, Action, Event, Reconstruction, Start as Begin, State, Step, Timeline,
        };
        let mut timeline = Timeline::default();
        timeline.push(Step {
            time_ns: 5,
            event: None,
            order: None,
            action: Action::Write(writes.extents().to_vec()),
        });
        let begin = Begin::from_earlier(Some(&before), Some(&file));
        let mut map = Reconstruction::new(begin, &timeline);
        assert_eq!(map.counts().before, PRELOAD.len() as u64);
        map.goto(1);
        assert_eq!(map.bytes(0, expect.len() as u64).unwrap(), expect);
        assert_eq!(map.sha256().unwrap(), sha256_hex(&expect));
        assert_eq!(map.row(12, 1)[0].state, State::Written);
        assert_eq!(map.row(0, 1)[0].state, State::Before);
        let history: Vec<Event> = map.history(12).iter().map(|h| h.event).collect();
        assert_eq!(history, [Event::Start, Event::Written]);
    }

    // Created by the run: starts empty. A path the disk does not hold (tmpfs).
    assert_eq!(
        resolver.resolve(&wanted("/etc/new", None, true)).0,
        Before::Created
    );
    // An open with O_CREAT the trace took for a creation, on a file that was
    // there (the inode matches the disk's): not a creation. A name the disk
    // does not hold, or holds as another inode, is.
    assert_eq!(
        resolver
            .resolve(&wanted("/etc/crontab", Some(crontab), true))
            .0,
        Before::OnDisk {
            size: CRONTAB.len() as u64,
            exact: true
        }
    );
    let nowhere = FileKey {
        ino: 99_999,
        ..crontab
    };
    assert_eq!(
        resolver.resolve(&wanted("/etc/new", Some(nowhere), true)).0,
        Before::Created
    );
    assert_eq!(
        resolver
            .resolve(&wanted("/etc/crontab", Some(preload), true))
            .0,
        Before::Created
    );
    assert!(matches!(
        resolver.resolve(&wanted("/dev/shm/x", None, false)).0,
        Before::Elsewhere(_)
    ));
    // Another file's inode at the crontab's path: not the file the run saw.
    assert!(matches!(
        resolver
            .resolve(&wanted("/etc/crontab", Some(preload), false))
            .0,
        Before::Elsewhere(_)
    ));
    // The guest recorded no inode: the path alone matches.
    assert_eq!(
        resolver.resolve(&wanted("/etc/crontab", None, false)).0,
        Before::OnDisk {
            size: CRONTAB.len() as u64,
            exact: false
        }
    );
    // Used both before and after a restore: no single starting disk.
    let later = root.join("rec/boots/b2/runs/r1");
    fs::create_dir_all(&later).unwrap();
    DiskStart {
        boot_id: "b2".into(),
        via: Via::Restore,
        ..start.clone()
    }
    .save(later.parent().unwrap().parent().unwrap())
    .unwrap();
    let mut two = Resolver::new(
        &[(run.clone(), "b1".into()), (later, "b2".into())],
        Some(app.clone()),
    );
    let spans = Wanted {
        last_segment: 1,
        ..wanted("/etc/crontab", Some(crontab), false)
    };
    assert!(matches!(two.resolve(&spans).0, Before::Unavailable(why) if why.contains("restore")));
    let after = Wanted {
        first_segment: 1,
        last_segment: 1,
        ..wanted("/etc/crontab", Some(crontab), false)
    };
    assert!(matches!(two.resolve(&after).0, Before::OnDisk { .. }));

    // A boot with no record, and a base that is gone.
    let bare = root.join("bare/runs/r1");
    fs::create_dir_all(&bare).unwrap();
    let mut none = Resolver::new(&[(bare, "b0".into())], Some(app.clone()));
    assert!(matches!(
        none.resolve(&wanted("/etc/crontab", None, false)).0,
        Before::Unavailable(why) if why.contains("not recorded")
    ));

    // The boot is over: the earlier bytes of the changed files are copied
    // into its recording, from the starting disk only. The preload fits the
    // caps; the crontab (109 bytes) is over the per-file cap of 100.
    let limits = Limits {
        per_file: 100,
        per_run: 1 << 20,
    };
    let mut writer = Writer::open(&boot, "b1", limits);
    let mut disk = Resolver::new(&[(run.clone(), "b1".into())], Some(app.clone())).disk_only();
    for (path, key) in [("/etc/crontab", crontab), ("/etc/ld.so.preload", preload)] {
        let (found, source) = disk.resolve(&wanted(path, Some(key), false));
        writer.record(path, &[], Some(key), &found, source.as_ref());
    }
    let (found, source) = disk.resolve(&wanted("/dev/shm/x", None, false));
    writer.record("/dev/shm/x", &[], None, &found, source.as_ref());
    writer.finish(true, None).unwrap();
    // A second boot with roomy caps keeps both.
    let boot2 = root.join("rec/boots/b3");
    let run2 = boot2.join("runs/r1");
    fs::create_dir_all(&run2).unwrap();
    DiskStart {
        boot_id: "b3".into(),
        ..start.clone()
    }
    .save(&boot2)
    .unwrap();
    let mut roomy = Writer::open(&boot2, "b3", Limits::default());
    let mut disk2 = Resolver::new(&[(run2.clone(), "b3".into())], Some(app.clone())).disk_only();
    for (path, key) in [("/etc/crontab", crontab), ("/etc/ld.so.preload", preload)] {
        let (found, source) = disk2.resolve(&wanted(path, Some(key), false));
        roomy.record(path, &[], Some(key), &found, source.as_ref());
    }
    roomy.finish(true, None).unwrap();

    // The base goes away; the recording reads on its own, byte for byte.
    fs::remove_file(&base).unwrap();
    let mut gone = Resolver::new(&[(run.clone(), "b1".into())], Some(app.clone()));
    let (found, file) = gone.resolve(&wanted("/etc/ld.so.preload", Some(preload), false));
    assert_eq!(
        found,
        Before::Recorded {
            size: PRELOAD.len() as u64,
            exact: true
        }
    );
    let file = file.unwrap();
    assert_eq!(file.disk.read(&file.path, 0, 4096).unwrap(), PRELOAD);
    let under = Under {
        size: PRELOAD.len() as u64,
        source: antinomie_monitor_core::file_writes::Source::Disk {
            file: file.clone(),
            at: 0,
        },
    };
    let mut writes = Writes::default();
    let mut budget = antinomie_monitor_core::file_writes::Budget::default();
    writes.add(
        &mut budget,
        Some(10),
        8,
        vec![antinomie_monitor_core::file_writes::Captured {
            rel: 0,
            len: 8,
            source: antinomie_monitor_core::file_writes::Source::Inline(b"EVIL.so\n".to_vec()),
        }],
    );
    assert_eq!(
        writes
            .read_over(Some(&under), 0, PRELOAD.len() as u64)
            .unwrap(),
        expect
    );
    // Over the cap: size and hash only.
    match gone
        .resolve(&wanted("/etc/crontab", Some(crontab), false))
        .0
    {
        Before::NotCopied { size, sha256, why } => {
            assert_eq!(size, CRONTAB.len() as u64);
            assert_eq!(
                sha256.as_deref(),
                Some(antinomie_monitor_core::storage::sha256_hex(CRONTAB).as_str())
            );
            assert!(why.contains("per-file cap"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        gone.resolve(&wanted("/dev/shm/x", None, false)).0,
        Before::Elsewhere(_)
    ));
    let mut roomy = Resolver::new(&[(run2, "b3".into())], Some(app.clone()));
    let (found, file) = roomy.resolve(&wanted("/etc/crontab", Some(crontab), false));
    assert!(matches!(found, Before::Recorded { .. }));
    let file = file.unwrap();
    assert_eq!(file.disk.read(&file.path, 0, 4096).unwrap(), CRONTAB);
    // A file the recording was not asked about falls back to the disk, which is gone.
    let mut other = Resolver::new(&[(run.clone(), "b1".into())], Some(app.clone()));
    assert!(matches!(
        other.resolve(&wanted("/etc/hosts", None, false)).0,
        Before::Unavailable(why) if why.contains("gone")
    ));
    let _ = fs::remove_dir_all(&root);
}
