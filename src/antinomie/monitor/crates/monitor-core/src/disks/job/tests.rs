// SPDX-License-Identifier: MIT
use super::*;
use crate::disks::{
    DISKS_DIR, Ext4State, disks_dir,
    fixture::{Fixture, require_tools},
    reader::{DiskAnswer, DiskRequest, image::Image},
};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Command,
    time::Instant,
};

fn spec(fixture: &Fixture, top: &Path) -> JobSpec {
    JobSpec {
        qemu_img: PathBuf::from("qemu-img"),
        vm_id: "vm-1".into(),
        vm_dir: fixture.root.clone(),
        top: top.to_path_buf(),
        source: DiskSourceRecord::default(),
        disks_dir: disks_dir(&fixture.root),
        quota: 0,
    }
}

fn plan(hash: bool, layer_digests: bool) -> DumpPlan {
    DumpPlan {
        vm_name: "Fixture".into(),
        system: "Linux 6.12.94 · Test".into(),
        hash,
        layer_digests,
    }
}

fn sha256sum(path: &Path) -> String {
    let output = Command::new("sha256sum").arg(path).output().unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

fn dumped(result: Result<JobResult, String>) -> DiskDump {
    match result.unwrap() {
        JobResult::Dumped(dump) => *dump,
        other => panic!("{other:?}"),
    }
}

fn folders(fixture: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(disks_dir(&fixture.root))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// A one-layer qcow2 of an image whose superblock says it was not unmounted.
fn forced_off_disk(fixture: &Fixture) -> PathBuf {
    let tree = fixture.standard_tree("forced-tree");
    let raw = fixture.ext4("forced.ext4", &tree, &["ssv state 0"]);
    let top = fixture.path("forced.qcow2");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2"])
            .arg(&raw)
            .arg(&top)
            .status()
            .unwrap()
            .success()
    );
    top
}

fn wait(job: &mut Job) -> Result<JobResult, String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(result) = job.finish() {
            return result;
        }
        assert!(Instant::now() < deadline, "the disk job did not finish");
        thread::sleep(Duration::from_millis(20));
    }
}

fn scratch_folders(fixture: &Fixture) -> Vec<String> {
    fs::read_dir(disks_dir(&fixture.root))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(".scratch-"))
                .collect()
        })
        .unwrap_or_default()
}

fn running(marker: &str) -> bool {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| fs::read(entry.path().join("cmdline")).ok())
        .any(|cmdline| String::from_utf8_lossy(&cmdline).contains(marker))
}

#[test]
fn progress_lines_parse_to_percentages() {
    assert_eq!(parse_progress("    (12.34/100%)"), Some(12.34));
    assert_eq!(parse_progress("(0.00/100%)"), Some(0.0));
    assert_eq!(parse_progress("    (100.00/100%)  "), Some(100.0));
    assert_eq!(parse_progress("(50/200%)"), Some(25.0));
    for bad in [
        "",
        "(",
        "12.3%",
        "(a/b%)",
        "(1/0%)",
        "(nan/100%)",
        "(-5/100%)x",
        "done",
    ] {
        let parsed = parse_progress(bad);
        assert!(
            parsed.is_none() || bad == "(-5/100%)x" && false,
            "{bad:?}: {parsed:?}"
        );
    }
    assert_eq!(parse_progress("(-5/100%)"), Some(0.0));
}

#[test]
fn a_measure_job_reports_without_writing_anything() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut job = Job::measure(spec(&fixture, &top)).unwrap();
    let JobResult::Measured(measured) = wait(&mut job).unwrap() else {
        panic!("measured")
    };
    assert_eq!(measured.error, None);
    assert_eq!(measured.logical_size, 32 * 1024 * 1024);
    assert!(scratch_folders(&fixture).is_empty());
    assert_eq!(job.purpose, DiskJobPurpose::Measure);
}

#[test]
fn a_view_job_flattens_the_chain_into_a_readable_sparse_image() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut job = Job::view(spec(&fixture, &top)).unwrap();
    let JobResult::Opened(view) = wait(&mut job).unwrap() else {
        panic!("opened")
    };
    assert_eq!(view.vm_id, "vm-1");
    assert_eq!(view.fs_state, Ext4State::Clean);
    assert_eq!(view.logical_size, 32 * 1024 * 1024);
    assert_eq!(fs::metadata(&view.image).unwrap().len(), view.logical_size);
    // Sparse: far less allocated than the 32 MiB logical size.
    assert!(
        view.allocated_size < view.logical_size / 2,
        "{}",
        view.allocated_size
    );
    assert_eq!(view.source.layers.len(), 3);
    // Scratch folder: private, one image, no partial file.
    let folder = view.image.parent().unwrap();
    assert!(folder.ends_with(format!(".scratch-{}", view.view_id)));
    assert_eq!(
        fs::metadata(folder).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let names: Vec<_> = fs::read_dir(folder)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, [IMAGE_FILE]);
    assert!(
        view.extract_dir
            .starts_with(disks_dir(&fixture.root).join("extracted"))
    );

    // The top layer's content: files from every layer, including the newest.
    let out = fixture.path("out");
    fs::create_dir(&out).unwrap();
    let image = Image::open(&view.image, &out);
    for file in ["/etc/layer-1", "/etc/layer-2", "/etc/passwd"] {
        let answer = image
            .handle(
                1,
                DiskRequest::Info {
                    path: file.into(),
                    hash_cap: 1 << 20,
                },
            )
            .unwrap();
        assert!(matches!(answer, DiskAnswer::Info(_)), "{file}");
    }
    let DiskAnswer::Extracted(_) = image
        .handle(
            2,
            DiskRequest::Extract {
                path: "/etc/layer-2".into(),
                max_len: 1 << 20,
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        fs::read_to_string(out.join("2")).unwrap(),
        "written in layer 2\n"
    );
    // The conversion matches `qemu-img convert` of the chain, byte for byte.
    let reference = fixture.path("reference.raw");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "qcow2", "-O", "raw"])
            .arg(&top)
            .arg(&reference)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read(&view.image).unwrap(),
        fs::read(&reference).unwrap()
    );
    // The chain was only read.
    assert!(
        Command::new("qemu-img")
            .arg("check")
            .arg(&top)
            .status()
            .unwrap()
            .success()
    );
    assert!(disks_dir(&fixture.root).starts_with(&fixture.root) && DISKS_DIR == "disks");
}

#[test]
fn the_estimate_is_within_ten_percent_of_the_allocated_image() {
    require_tools!();
    let fixture = Fixture::new();
    let tree = fixture.standard_tree("tree");
    // A few MiB of data that does not compress to zeros.
    let data: Vec<u8> = (0..20u32 * 1024 * 1024)
        .map(|n| (n.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    fs::write(tree.join("home/user/data.bin"), data).unwrap();
    let raw = fixture.ext4("big.ext4", &tree, &[]);
    let top = fixture.path("big.qcow2");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2"])
            .arg(&raw)
            .arg(&top)
            .status()
            .unwrap()
            .success()
    );
    let mut job = Job::view(spec(&fixture, &top)).unwrap();
    let JobResult::Opened(view) = wait(&mut job).unwrap() else {
        panic!()
    };
    let measured = measure::measure(
        Path::new("qemu-img"),
        "vm-1",
        &fixture.root,
        &top,
        DiskSourceRecord::default(),
        &disks_dir(&fixture.root),
    );
    let (estimate, actual) = (
        measured.allocated_estimate as f64,
        view.allocated_size as f64,
    );
    assert!(
        (estimate - actual).abs() / actual <= 0.10,
        "estimate {estimate} vs allocated {actual}"
    );
}

/// A stand-in `qemu-img` that answers `info` and `map`, and `convert` with a
/// progress line and a long sleep, so cancel has something to kill.
fn slow_qemu_img(fixture: &Fixture, marker: &str) -> PathBuf {
    let path = fixture.path("qemu-img-slow");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
case "$1" in
info) echo '[{{"filename":"{top}","format":"qcow2","virtual-size":33554432,"actual-size":4096}}]' ;;
map) echo '[{{"start":0,"length":4096,"depth":0,"present":true,"zero":false,"data":true}}]' ;;
convert) printf '    (12.34/100%%)\r'; exec /usr/bin/sleep {marker} ;;
esac
"#,
            top = fixture.path("top.qcow2").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn cancel_kills_the_converter_and_leaves_no_scratch() {
    let fixture = Fixture::new();
    let mut spec = spec(&fixture, &fixture.path("top.qcow2"));
    spec.qemu_img = slow_qemu_img(&fixture, "51515");
    let mut job = Job::view(spec).unwrap();
    // The progress line reaches the stage.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let DiskJobStage::Converting { percent } = job.progress().stage
            && (percent - 12.34).abs() < 0.01
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no progress: {:?}",
            job.progress()
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(running("51515"));
    assert_eq!(scratch_folders(&fixture).len(), 1);
    assert_eq!(job.progress().purpose, DiskJobPurpose::View);
    assert_eq!(job.progress().estimate, 4096);
    job.cancel();
    assert_eq!(wait(&mut job).unwrap_err(), "cancelled");
    thread::sleep(Duration::from_millis(100));
    assert!(!running("51515"), "the converter was left running");
    assert!(scratch_folders(&fixture).is_empty());
}

#[test]
fn dropping_a_running_job_stops_its_converter() {
    let fixture = Fixture::new();
    let mut spec = spec(&fixture, &fixture.path("top.qcow2"));
    spec.qemu_img = slow_qemu_img(&fixture, "52525");
    let job = Job::view(spec).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !running("52525") {
        assert!(Instant::now() < deadline, "converter never started");
        thread::sleep(Duration::from_millis(20));
    }
    drop(job);
    thread::sleep(Duration::from_millis(100));
    assert!(!running("52525"));
    assert!(scratch_folders(&fixture).is_empty());
}

#[test]
fn a_leftover_scratch_folder_is_swept_before_a_new_view() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let leftover = disks_dir(&fixture.root).join(".scratch-crashed");
    fs::create_dir_all(&leftover).unwrap();
    fs::write(leftover.join("root.ext4.part"), vec![1u8; 4096]).unwrap();
    let mut job = Job::view(spec(&fixture, &top)).unwrap();
    wait(&mut job).unwrap();
    assert!(!leftover.exists());
    assert_eq!(scratch_folders(&fixture).len(), 1);
}

#[test]
fn a_disk_without_ext4_is_refused_and_leaves_nothing() {
    require_tools!();
    let fixture = Fixture::new();
    let raw = fixture.path("blank.raw");
    fs::write(&raw, vec![0u8; 8 * 1024 * 1024]).unwrap();
    let top = fixture.path("blank.qcow2");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2"])
            .arg(&raw)
            .arg(&top)
            .status()
            .unwrap()
            .success()
    );
    let mut job = Job::view(spec(&fixture, &top)).unwrap();
    let error = wait(&mut job).unwrap_err();
    assert!(
        error.contains("ext2/3/4") || error.contains("unsupported"),
        "{error}"
    );
    assert!(scratch_folders(&fixture).is_empty());
}

#[test]
fn a_disk_held_by_another_process_fails_on_qemus_own_lock() {
    require_tools!();
    if crate::dependencies::executable(Path::new("qemu-io")).is_none() {
        eprintln!("skipped: qemu-io is needed");
        return;
    }
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut holder = Command::new("qemu-io")
        .args(["-f", "qcow2", "-c", "sleep 20000"])
        .arg(&top)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(500));
    let mut job = Job::view(spec(&fixture, &top)).unwrap();
    let result = wait(&mut job);
    let _ = holder.kill();
    let _ = holder.wait();
    let error = result.unwrap_err();
    assert!(
        error.contains("appears to be running or another program holds its disk"),
        "{error}"
    );
    assert!(error.contains("lock"), "{error}");
    assert!(scratch_folders(&fixture).is_empty());
}

#[test]
fn the_converter_dies_with_the_thread_that_started_it() {
    // `setpriv --pdeathsig KILL`: an app crash ends every thread, and with
    // them any converter attached to the chain. The signal follows the
    // spawning thread, which is how it is tested here.
    if crate::dependencies::executable(Path::new("setpriv")).is_none() {
        eprintln!("skipped: setpriv is needed");
        return;
    }
    let fixture = Fixture::new();
    let script = slow_qemu_img(&fixture, "53535");
    let (release, released) = std::sync::mpsc::channel::<()>();
    let spawner = thread::spawn(move || {
        let mut command = measure::qemu_img_command(&script);
        command.arg("convert").stdout(Stdio::null());
        let child = command.spawn().unwrap();
        // Stay alive until the converter is really running (its death
        // signal is set by then), then end.
        let _ = released.recv();
        child
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !running("53535") {
        assert!(Instant::now() < deadline, "the converter never started");
        thread::sleep(Duration::from_millis(20));
    }
    release.send(()).unwrap();
    let mut child = spawner.join().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while running("53535") {
        assert!(
            Instant::now() < deadline,
            "the converter outlived its parent"
        );
        thread::sleep(Duration::from_millis(20));
    }
    // Killed by the signal: reap it.
    assert!(!child.wait().unwrap().success());
}

#[test]
fn a_dump_job_writes_a_finished_standalone_image_and_its_sidecar() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut job = Job::dump(spec(&fixture, &top), plan(true, false)).unwrap();
    assert_eq!(job.purpose, DiskJobPurpose::Dump);
    let dump = dumped(wait(&mut job));
    assert_eq!(dump.vm_id, "vm-1");
    assert_eq!(dump.vm_name, "Fixture");
    assert_eq!(dump.system, "Linux 6.12.94 · Test");
    assert_eq!(dump.fs_state, Ext4State::Clean);
    assert!(dump.complete() && dump.browsable() && !dump.imported);
    assert_eq!(dump.logical_size, 32 * 1024 * 1024);
    assert_eq!(dump.source.layers.len(), 3);
    assert!(
        dump.source
            .layers
            .iter()
            .all(|layer| layer.sha256.is_none())
    );
    // The folder holds the image and the sidecar, nothing partial, 0700.
    assert_eq!(folders(&fixture), [dump.id.as_str()]);
    let mut names: Vec<_> = fs::read_dir(&dump.dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["dump.json", "root.ext4"]);
    assert_eq!(
        fs::metadata(&dump.dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // Standalone, sparse, byte for byte what the chain flattens to.
    let image = dump.path();
    assert_eq!(fs::metadata(&image).unwrap().len(), dump.logical_size);
    assert!(dump.allocated_size.unwrap() < dump.logical_size / 2);
    let reference = fixture.path("reference.raw");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "qcow2", "-O", "raw"])
            .arg(&top)
            .arg(&reference)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read(&image).unwrap(), fs::read(&reference).unwrap());
    // SHA-256 agrees with sha256sum and the sidecar round-trips through list.
    assert_eq!(dump.sha256.as_deref(), Some(sha256sum(&image).as_str()));
    let listed = crate::disks::dump::list(std::slice::from_ref(&fixture.root));
    assert_eq!(listed, std::slice::from_ref(&dump));
    // It opens in the reader, and host tools read it.
    assert_eq!(read_state(&image).unwrap(), Ext4State::Clean);
    let debugfs = Command::new("/sbin/debugfs")
        .args(["-R", "cat /etc/layer-2"])
        .arg(&image)
        .output();
    if let Ok(output) = debugfs {
        assert_eq!(output.stdout, b"written in layer 2\n");
    }
    // A dump leaves no view behind and the chain untouched.
    assert!(scratch_folders(&fixture).is_empty());
    assert!(
        Command::new("qemu-img")
            .arg("check")
            .arg(&top)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn a_forced_off_disk_dumps_as_not_cleanly_unmounted() {
    require_tools!();
    let fixture = Fixture::new();
    let top = forced_off_disk(&fixture);
    let mut job = Job::dump(spec(&fixture, &top), plan(false, false)).unwrap();
    let dump = dumped(wait(&mut job));
    assert_eq!(dump.fs_state, Ext4State::NotClean);
    // Hashing is optional: none was asked for.
    assert_eq!(dump.sha256, None);
    assert_eq!(read_state(&dump.path()).unwrap(), Ext4State::NotClean);
}

#[test]
fn layer_digests_are_recorded_only_when_asked_for() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut job = Job::dump(spec(&fixture, &top), plan(true, true)).unwrap();
    let dump = dumped(wait(&mut job));
    assert_eq!(dump.source.layers.len(), 3);
    for layer in &dump.source.layers {
        let file = fixture.root.join(&layer.filename);
        assert_eq!(layer.sha256.as_deref(), Some(sha256sum(&file).as_str()));
        assert_eq!(layer.size, fs::metadata(&file).unwrap().len());
    }
    assert_ne!(dump.source.layers[0].sha256, dump.source.layers[2].sha256);
}

#[test]
fn a_dump_over_the_quota_is_refused_before_anything_is_written() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut limited = spec(&fixture, &top);
    limited.quota = 64 * 1024;
    let mut job = Job::dump(limited.clone(), plan(true, false)).unwrap();
    let error = wait(&mut job).unwrap_err();
    assert!(error.contains("recording quota"), "{error}");
    assert!(crate::quota::is_quota_error(&error), "{error}");
    assert!(error.contains("Settings"), "{error}");
    assert!(
        folders(&fixture).is_empty(),
        "nothing written: {:?}",
        folders(&fixture)
    );
    // The quota is only a ceiling on dumps: a view of the same disk opens,
    // and a quota above the estimate lets the dump through.
    let mut job = Job::view(limited).unwrap();
    assert!(matches!(wait(&mut job), Ok(JobResult::Opened(_))));
    let mut roomy = spec(&fixture, &top);
    roomy.quota = 4 * 1024 * 1024 * 1024;
    let mut job = Job::dump(roomy, plan(false, false)).unwrap();
    dumped(wait(&mut job));
}

#[test]
fn a_measure_carries_the_quota_and_explains_a_refusal() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut limited = spec(&fixture, &top);
    limited.quota = 64 * 1024;
    let mut job = Job::measure(limited).unwrap();
    let JobResult::Measured(measured) = wait(&mut job).unwrap() else {
        panic!()
    };
    assert_eq!(measured.quota, 64 * 1024);
    // Open is not blocked, the dump is.
    assert_eq!(measured.error, None);
    assert!(measured.quota_error().unwrap().contains("recording quota"));
    let none = DiskMeasure {
        allocated_estimate: 1 << 40,
        quota: 0,
        ..DiskMeasure::default()
    };
    assert_eq!(none.quota_error(), None);
}

#[test]
fn a_dump_that_does_not_fit_the_free_space_is_refused_naming_the_folder() {
    let measure = DiskMeasure {
        allocated_estimate: 3 << 30,
        logical_size: 16 << 30,
        free_space: 1 << 30,
        sparse_supported: true,
        directory: PathBuf::from("/recordings/vm/disks"),
        ..DiskMeasure::default()
    };
    let error = measure.space_error().unwrap();
    assert!(error.contains("/recordings/vm/disks"), "{error}");
    assert!(
        error.contains("3.1 GiB") && error.contains("1.0 GiB"),
        "{error}"
    );
    // Without hole support the whole logical size must fit.
    let dense = DiskMeasure {
        sparse_supported: false,
        free_space: 8 << 30,
        ..measure
    };
    assert!(dense.space_error().unwrap().contains("sparse"));
}

#[test]
fn cancelling_a_dump_removes_its_folder_and_leaves_no_record() {
    let fixture = Fixture::new();
    let mut spec = spec(&fixture, &fixture.path("top.qcow2"));
    spec.qemu_img = slow_qemu_img(&fixture, "54545");
    let mut job = Job::dump(spec, plan(true, false)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !running("54545") {
        assert!(Instant::now() < deadline, "converter never started");
        thread::sleep(Duration::from_millis(20));
    }
    // While converting, the folder exists but is not a listed dump.
    assert_eq!(folders(&fixture).len(), 1);
    assert!(crate::disks::dump::list(std::slice::from_ref(&fixture.root)).is_empty());
    job.cancel();
    assert_eq!(wait(&mut job).unwrap_err(), "cancelled");
    thread::sleep(Duration::from_millis(100));
    assert!(!running("54545"));
    assert!(folders(&fixture).is_empty());
}

#[test]
fn dropping_a_running_dump_leaves_no_folder() {
    let fixture = Fixture::new();
    let mut spec = spec(&fixture, &fixture.path("top.qcow2"));
    spec.qemu_img = slow_qemu_img(&fixture, "55555");
    let job = Job::dump(spec, plan(true, false)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !running("55555") {
        assert!(Instant::now() < deadline, "converter never started");
        thread::sleep(Duration::from_millis(20));
    }
    drop(job);
    thread::sleep(Duration::from_millis(100));
    assert!(!running("55555"));
    assert!(folders(&fixture).is_empty());
}

#[test]
fn a_failed_dump_removes_its_folder() {
    require_tools!();
    let fixture = Fixture::new();
    let raw = fixture.path("blank.raw");
    fs::write(&raw, vec![0u8; 8 * 1024 * 1024]).unwrap();
    let top = fixture.path("blank.qcow2");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2"])
            .arg(&raw)
            .arg(&top)
            .status()
            .unwrap()
            .success()
    );
    let mut job = Job::dump(spec(&fixture, &top), plan(true, false)).unwrap();
    let error = wait(&mut job).unwrap_err();
    assert!(
        error.contains("ext2/3/4") || error.contains("unsupported"),
        "{error}"
    );
    assert!(folders(&fixture).is_empty());
}

#[test]
fn a_crash_mid_dump_leaves_a_folder_that_is_never_listed_and_is_swept() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    // What a killed app leaves: an image being written, no dump.json.
    let crashed = disks_dir(&fixture.root).join("crashed");
    fs::create_dir_all(&crashed).unwrap();
    fs::write(crashed.join("root.ext4.part"), vec![7u8; 8192]).unwrap();
    assert!(crate::disks::dump::list(std::slice::from_ref(&fixture.root)).is_empty());
    let mut job = Job::dump(spec(&fixture, &top), plan(false, false)).unwrap();
    let dump = dumped(wait(&mut job));
    assert!(!crashed.exists());
    assert_eq!(folders(&fixture), [dump.id]);
}

fn open_view(fixture: &Fixture, top: &Path) -> CurrentDiskView {
    let mut job = Job::view(spec(fixture, top)).unwrap();
    match wait(&mut job).unwrap() {
        JobResult::Opened(view) => view,
        other => panic!("{other:?}"),
    }
}

/// A `qemu-img` that fails every conversion, to show a step runs none.
fn no_convert_qemu_img(fixture: &Fixture) -> PathBuf {
    let path = fixture.path("qemu-img-no-convert");
    fs::write(
        &path,
        "#!/bin/sh\ncase \"$1\" in convert) echo 'a second conversion ran' >&2; exit 1 ;; esac\nexec qemu-img \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn keeping_a_view_renames_it_without_a_second_conversion() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let view = open_view(&fixture, &top);
    let before = fs::metadata(&view.image).unwrap();
    let old_folder = view.image.parent().unwrap().to_path_buf();
    let mut keep_spec = spec(&fixture, &top);
    keep_spec.qemu_img = no_convert_qemu_img(&fixture);
    let mut job = Job::keep(keep_spec, plan(true, false), view.clone()).unwrap();
    assert_eq!(job.purpose, DiskJobPurpose::Keep);
    let JobResult::Kept(dump, kept) = wait(&mut job).unwrap() else {
        panic!("kept")
    };
    // Same inode: renamed, not copied. The scratch folder is gone.
    let after = fs::metadata(dump.path()).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert!(!old_folder.exists());
    assert_eq!(kept.image, dump.path());
    let (dump, kept) = (*dump, *kept);
    assert_eq!(kept.kept_as.as_deref(), Some(dump.id.as_str()));
    assert_eq!(kept.view_id, view.view_id);
    assert_eq!(kept.extract_dir, view.extract_dir);
    assert!(dump.complete() && dump.browsable());
    assert_eq!(dump.fs_state, Ext4State::Clean);
    assert_eq!(
        dump.sha256.as_deref(),
        Some(sha256sum(&dump.path()).as_str())
    );
    assert_eq!(dump.source, view.source);
    assert_eq!(dump.logical_size, view.logical_size);
    assert_eq!(
        crate::disks::dump::list(std::slice::from_ref(&fixture.root)),
        std::slice::from_ref(&dump)
    );
    assert_eq!(folders(&fixture), [dump.id.as_str()]);
    // The kept image still reads, and closing the view keeps the dump.
    assert!(
        Image::open(&kept.image, &fixture.path("o"))
            .handle(1, DiskRequest::Probe)
            .is_ok()
    );
    crate::disks::remove_scratch(&kept);
    assert!(dump.path().is_file());
    // Keeping again is refused.
    let mut again = Job::keep(spec(&fixture, &top), plan(true, false), kept).unwrap();
    assert!(wait(&mut again).unwrap_err().contains("already kept"));
    assert_eq!(folders(&fixture), [dump.id]);
}

#[test]
fn keeping_applies_the_quota_ceiling_to_the_views_allocation() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let view = open_view(&fixture, &top);
    let mut limited = spec(&fixture, &top);
    limited.quota = 64 * 1024;
    let mut job = Job::keep(limited, plan(true, false), view.clone()).unwrap();
    let error = wait(&mut job).unwrap_err();
    assert!(error.contains("recording quota"), "{error}");
    // The view is untouched.
    assert!(view.image.is_file());
    assert_eq!(folders(&fixture), [format!(".scratch-{}", view.view_id)]);
}

#[test]
fn keeping_refuses_an_image_that_is_not_a_scratch_view_of_these_recordings() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let mut view = open_view(&fixture, &top);
    let elsewhere = fixture.path("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::copy(&view.image, elsewhere.join("root.ext4")).unwrap();
    view.image = elsewhere.join("root.ext4");
    let mut job = Job::keep(spec(&fixture, &top), plan(false, false), view).unwrap();
    assert!(wait(&mut job).unwrap_err().contains("scratch image"));
    assert!(elsewhere.join("root.ext4").exists());
    // A scratch folder that is not directly under this VM's disks folder.
    let mut view = open_view(&fixture, &top);
    let nested = disks_dir(&fixture.root).join("nested/.scratch-x");
    fs::create_dir_all(&nested).unwrap();
    fs::copy(&view.image, nested.join("root.ext4")).unwrap();
    view.image = nested.join("root.ext4");
    let mut job = Job::keep(spec(&fixture, &top), plan(false, false), view).unwrap();
    assert!(wait(&mut job).unwrap_err().contains("scratch image"));
}

fn idle_run(cancelled: bool) -> Run {
    Run {
        estimate: Arc::new(AtomicU64::new(0)),
        stage: Arc::new(Mutex::new(DiskJobStage::Measuring)),
        cancel: Arc::new(AtomicBool::new(cancelled)),
    }
}

#[test]
fn cancelling_a_keep_abandons_the_hash_and_leaves_the_view_open() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let view = open_view(&fixture, &top);
    let result = idle_run(true).keep(&spec(&fixture, &top), &plan(true, false), &view);
    assert_eq!(result.unwrap_err(), "cancelled");
    assert!(view.image.is_file());
    assert_eq!(folders(&fixture), [format!(".scratch-{}", view.view_id)]);
    // Without the hash stage the cancel is still honoured before the rename.
    let result = idle_run(true).keep(&spec(&fixture, &top), &plan(false, false), &view);
    assert_eq!(result.unwrap_err(), "cancelled");
    assert!(view.image.is_file());
    assert!(crate::disks::dump::list(std::slice::from_ref(&fixture.root)).is_empty());
}

#[test]
fn promotion_falls_back_to_a_copy_when_the_rename_crosses_filesystems() {
    let fixture = Fixture::new();
    let from = fixture.path("from");
    let to = fixture.path("to");
    fs::create_dir_all(&from).unwrap();
    let exdev = || io::Error::from_raw_os_error(rustix::io::Errno::XDEV.raw_os_error());
    let copied = promote(
        &from,
        &to,
        |_, _| Err(exdev()),
        |to| fs::write(to.join("root.ext4"), b"copied").map_err(|e| e.to_string()),
    )
    .unwrap();
    // Copied, not renamed: the source folder stays, the new one is private.
    assert!(!copied && from.exists());
    assert_eq!(fs::read(to.join("root.ext4")).unwrap(), b"copied");
    assert_eq!(
        fs::metadata(&to).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // A failed copy removes the half-made folder.
    let other = fixture.path("other");
    let error = promote(
        &from,
        &other,
        |_, _| Err(exdev()),
        |_| Err("disk full".into()),
    );
    assert_eq!(error.unwrap_err(), "disk full");
    assert!(!other.exists() && from.exists());
    // Any other rename error is reported, and nothing is copied.
    let denied = promote(
        &from,
        &fixture.path("denied"),
        |_, _| Err(io::Error::from_raw_os_error(13)),
        |_| panic!("no copy"),
    );
    assert!(denied.is_err());
    // A real rename moves the folder.
    let moved = fixture.path("moved");
    assert!(
        promote(
            &from,
            &moved,
            |a, b| fs::rename(a, b),
            |_| panic!("no copy")
        )
        .unwrap()
    );
    assert!(moved.exists() && !from.exists());
}

#[test]
fn the_copy_fallback_makes_a_sparse_identical_raw_image() {
    require_tools!();
    let fixture = Fixture::new();
    let top = fixture.chain();
    let view = open_view(&fixture, &top);
    let target = fixture.path("copy");
    fs::create_dir_all(&target).unwrap();
    idle_run(false)
        .copy_raw(
            &spec(&fixture, &top),
            &view.image,
            &target,
            view.logical_size,
        )
        .unwrap();
    let copy = target.join("root.ext4");
    assert_eq!(fs::read(&copy).unwrap(), fs::read(&view.image).unwrap());
    assert!(fs::metadata(&copy).unwrap().blocks() * 512 < view.logical_size / 2);
    assert!(!target.join("root.ext4.part").exists());
    // A size mismatch is caught.
    let short = fixture.path("short");
    fs::create_dir_all(&short).unwrap();
    let error = idle_run(false)
        .copy_raw(&spec(&fixture, &top), &view.image, &short, 1234)
        .unwrap_err();
    assert!(error.contains("bytes"), "{error}");
}
