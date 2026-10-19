// SPDX-License-Identifier: MIT
use super::*;
use crate::disks::{
    DISKS_DIR, Ext4State, disks_dir,
    fixture::{Fixture, require_tools},
    reader::{DiskAnswer, DiskRequest, image::Image},
};
use std::{os::unix::fs::PermissionsExt, process::Command, time::Instant};

fn spec(fixture: &Fixture, top: &Path) -> JobSpec {
    JobSpec {
        qemu_img: PathBuf::from("qemu-img"),
        vm_id: "vm-1".into(),
        vm_dir: fixture.root.clone(),
        top: top.to_path_buf(),
        source: DiskSourceRecord::default(),
        disks_dir: disks_dir(&fixture.root),
    }
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
