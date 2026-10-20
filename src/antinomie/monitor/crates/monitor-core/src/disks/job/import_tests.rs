// SPDX-License-Identifier: MIT
//! Importing a qcow2 image in the sandbox.
use super::{
    import::{Qcow2Facts, check_info},
    *,
};
use crate::disks::{
    DiskSourceKind, disks_dir,
    fixture::{EXT4_START, Fixture, Scheme, require_tools},
    reader::{DiskAnswer, DiskRequest, image::Image},
    sandbox::{Account, qemu_img_in_sandbox, sandboxed_qemu_img},
};
use serde_json::json;
use std::process::Command;

fn sandbox_available() -> bool {
    Path::new("/usr/bin/bwrap").is_file()
        && Path::new("/usr/bin/prlimit").is_file()
        && sandboxed_qemu_img(Path::new("qemu-img")).is_ok()
        && {
            // User namespaces can be disabled on a host.
            let account = Account::new().unwrap();
            let fixture = Fixture::new();
            qemu_img_in_sandbox(
                &sandboxed_qemu_img(Path::new("qemu-img")).unwrap(),
                account.passwd(),
                None,
                &fixture.root,
                &["--version".into()],
            )
            .output()
            .is_ok_and(|output| output.status.success())
        }
}

macro_rules! require_sandbox {
    () => {
        require_tools!();
        if !sandbox_available() {
            eprintln!("skipped: bubblewrap or qemu-img under /usr is unavailable");
            return;
        }
    };
}

fn qcow2_of(fixture: &Fixture, raw: &Path, name: &str, backing: Option<&Path>) -> PathBuf {
    let target = fixture.path(name);
    let mut command = Command::new("qemu-img");
    command.args(["convert", "-f", "raw", "-O", "qcow2"]);
    if let Some(backing) = backing {
        command.arg("-B").arg(backing).args(["-F", "qcow2"]);
    }
    let output = command.arg(raw).arg(&target).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    target
}

fn spec(fixture: &Fixture, source: &Path, hash: bool) -> ImportSpec {
    ImportSpec {
        qemu_img: PathBuf::from("qemu-img"),
        vm_id: "vm-1".into(),
        vm_name: "Fixture".into(),
        source: source.to_path_buf(),
        disks_dir: disks_dir(&fixture.root),
        hash,
    }
}

fn run(spec: ImportSpec) -> Result<DiskDump, String> {
    let mut job = Job::import_qcow2(spec).unwrap();
    assert_eq!(job.purpose, DiskJobPurpose::Import);
    assert!(!job.holds_chain);
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(result) = job.finish() {
            return result.map(|result| match result {
                JobResult::Dumped(dump) => *dump,
                other => panic!("{other:?}"),
            });
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the import did not end"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn dump_folders(fixture: &Fixture) -> Vec<String> {
    fs::read_dir(disks_dir(&fixture.root))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn passwd_of(image: &Path, fixture: &Fixture) -> String {
    let out = fixture.path("probe-out");
    let _ = fs::remove_dir_all(&out);
    fs::create_dir(&out).unwrap();
    let reader = Image::open(image, &out);
    match reader
        .handle(
            1,
            DiskRequest::Extract {
                path: "/etc/passwd".into(),
                max_len: 4096,
            },
        )
        .unwrap()
    {
        DiskAnswer::Extracted(_) => fs::read_to_string(out.join("1")).unwrap(),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_info_of_an_imported_qcow2_is_judged() {
    let good = json!({"format": "qcow2", "virtual-size": 33554432u64, "actual-size": 1000});
    assert_eq!(
        check_info(&good).unwrap(),
        Qcow2Facts {
            virtual_size: 33554432,
            actual_size: 1000
        }
    );
    let backing = json!({"format": "qcow2", "virtual-size": 10, "backing-filename": "/etc/shadow"});
    let error = check_info(&backing).unwrap_err();
    assert!(
        error.contains("backing file") && error.contains("/etc/shadow"),
        "{error}"
    );
    // A control character in the name is not shown.
    let sneaky = json!({"format": "qcow2", "virtual-size": 10, "backing-filename": "a\u{1b}[31mb"});
    assert!(!check_info(&sneaky).unwrap_err().contains('\u{1b}'));
    let external = json!({"format": "qcow2", "virtual-size": 10,
        "format-specific": {"type": "qcow2", "data": {"data-file": "/dev/sda"}}});
    assert!(
        check_info(&external)
            .unwrap_err()
            .contains("external data file")
    );
    let encrypted = json!({"format": "qcow2", "virtual-size": 10, "encrypted": true});
    assert!(check_info(&encrypted).unwrap_err().contains("encrypted"));
    let huge = json!({"format": "qcow2", "virtual-size": u64::MAX});
    assert!(check_info(&huge).unwrap_err().contains("limited"));
    let empty = json!({"format": "qcow2", "virtual-size": 0});
    assert!(check_info(&empty).is_err());
    assert!(check_info(&json!({"format": "raw", "virtual-size": 10})).is_err());
    assert!(check_info(&json!({})).is_err());
}

#[test]
fn a_qcow2_is_converted_in_the_sandbox_into_a_standalone_dump() {
    require_sandbox!();
    let fixture = Fixture::new();
    let source = qcow2_of(&fixture, &fixture.standard_image(), "import.qcow2", None);
    let before = fs::read(&source).unwrap();
    let dump = run(spec(&fixture, &source, true)).unwrap();
    assert!(dump.complete() && !dump.imported);
    assert_eq!(dump.source.kind, DiskSourceKind::Imported);
    assert_eq!(dump.fs_state, Ext4State::Clean);
    assert_eq!(dump.logical_size, 32 * 1024 * 1024);
    assert_eq!(dump.source.layers.len(), 1);
    assert_eq!(dump.source.partition, None);
    let image = dump.path();
    assert_eq!(fs::metadata(&image).unwrap().len(), 32 * 1024 * 1024);
    assert!(fs::metadata(&image).unwrap().blocks() * 512 < 32 * 1024 * 1024);
    assert_eq!(dump.sha256.as_deref(), Some(sha256_of(&image).as_str()));
    assert_eq!(
        passwd_of(&image, &fixture),
        "root:x:0:0:root:/root:/bin/sh\n"
    );
    // Listed like any dump; the folder holds only the image and the record.
    assert_eq!(
        crate::disks::dump::list(std::slice::from_ref(&fixture.root)).len(),
        1
    );
    let mut files: Vec<_> = fs::read_dir(&dump.dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(files, ["dump.json", "root.ext4"]);
    // The source file was only read.
    assert_eq!(fs::read(&source).unwrap(), before);
}

fn sha256_of(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn a_qcow2_whose_backing_file_is_outside_is_refused_and_leaves_nothing() {
    require_sandbox!();
    let fixture = Fixture::new();
    let outside = fixture.path("outside");
    fs::create_dir(&outside).unwrap();
    let raw = fixture.standard_image();
    let parent = qcow2_of(&fixture, &raw, "outside/parent.qcow2", None);
    let child = qcow2_of(&fixture, &raw, "child.qcow2", Some(&parent));
    let error = run(spec(&fixture, &child, false)).unwrap_err();
    assert!(
        error.contains("backing file") && error.contains("parent.qcow2"),
        "{error}"
    );
    assert!(
        dump_folders(&fixture).is_empty(),
        "{:?}",
        dump_folders(&fixture)
    );

    // Even without that check the sandbox cannot reach the file: converting
    // the child inside it fails to open its backing file.
    let account = Account::new().unwrap();
    let qemu_img = sandboxed_qemu_img(Path::new("qemu-img")).unwrap();
    let scratch = fixture.path("scratch");
    fs::create_dir(&scratch).unwrap();
    let output = qemu_img_in_sandbox(
        &qemu_img,
        account.passwd(),
        Some(&child),
        &scratch,
        &[
            "convert",
            "-f",
            "qcow2",
            "-O",
            "raw",
            "/input",
            "/out/leak.raw",
        ]
        .map(Into::into),
    )
    .output()
    .unwrap();
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(
        message.contains("backing") || message.contains("Could not open"),
        "{message}"
    );
    assert!(
        !scratch.join("leak.raw").exists()
            || fs::metadata(scratch.join("leak.raw")).unwrap().len() == 0
    );
}

#[test]
fn a_partitioned_qcow2_is_carved_to_its_ext4_partition() {
    require_sandbox!();
    let fixture = Fixture::new();
    let ext4 = fixture.standard_image();
    for scheme in [Scheme::Gpt, Scheme::Mbr] {
        let disk = fixture.partitioned("disk.raw", scheme, &ext4);
        let source = qcow2_of(&fixture, &disk, "disk.qcow2", None);
        let dump = run(spec(&fixture, &source, false)).unwrap();
        let partition = dump.source.partition.clone().expect("a partition");
        assert_eq!(
            (partition.index, partition.start),
            (2, EXT4_START),
            "{scheme:?}"
        );
        assert_eq!(dump.logical_size, 32 * 1024 * 1024);
        assert_eq!(
            passwd_of(&dump.path(), &fixture),
            "root:x:0:0:root:/root:/bin/sh\n"
        );
        // The whole-disk intermediate is gone.
        assert!(!dump.dir.join("disk.raw.tmp").exists());
        fs::remove_file(&source).unwrap();
        crate::disks::dump::delete(&dump).unwrap();
    }
}

#[test]
fn a_qcow2_without_ext4_is_unsupported_and_other_files_are_refused() {
    require_sandbox!();
    let fixture = Fixture::new();
    let blank = fixture.path("blank.raw");
    fs::write(&blank, vec![0x11u8; 8 * 1024 * 1024]).unwrap();
    let source = qcow2_of(&fixture, &blank, "blank.qcow2", None);
    let error = run(spec(&fixture, &source, false)).unwrap_err();
    assert!(error.contains("unsupported filesystem"), "{error}");
    assert!(dump_folders(&fixture).is_empty());
    // A raw image is not a qcow2.
    let error = run(spec(&fixture, &fixture.standard_image(), false)).unwrap_err();
    assert!(error.contains("not a qcow2"), "{error}");
    let error = run(spec(&fixture, &fixture.path("missing.qcow2"), false)).unwrap_err();
    assert!(error.contains("missing.qcow2"), "{error}");
    assert!(dump_folders(&fixture).is_empty());
}

#[test]
fn cancelling_an_import_leaves_no_folder() {
    require_sandbox!();
    let fixture = Fixture::new();
    let source = qcow2_of(&fixture, &fixture.standard_image(), "import.qcow2", None);
    let mut job = Job::import_qcow2(spec(&fixture, &source, true)).unwrap();
    job.cancel();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let result = loop {
        if let Some(result) = job.finish() {
            break result;
        }
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    };
    match result {
        Err(error) => {
            assert_eq!(error, "cancelled");
            assert!(dump_folders(&fixture).is_empty());
        }
        // The job may have finished before it saw the flag.
        Ok(JobResult::Dumped(dump)) => assert!(dump.complete()),
        Ok(other) => panic!("{other:?}"),
    }
}

#[test]
fn a_converter_that_grows_past_its_limit_is_stopped() {
    let fixture = Fixture::new();
    let run = Run {
        estimate: Arc::new(AtomicU64::new(0)),
        stage: Arc::new(Mutex::new(DiskJobStage::Measuring)),
        cancel: Arc::new(AtomicBool::new(false)),
    };
    let output = fixture.path("expanding.raw");
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!(
            "dd if=/dev/zero of={} bs=1M count=40 2>/dev/null; sleep 30",
            output.display()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let started = std::time::Instant::now();
    let error = run
        .wait_watching(&mut child, Some((&output, 4 * 1024 * 1024)))
        .unwrap_err();
    assert!(error.contains("grew past"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(20));
}
