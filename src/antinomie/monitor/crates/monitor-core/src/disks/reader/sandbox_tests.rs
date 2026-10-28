// SPDX-License-Identifier: GPL-3.0-only
//! The reader's sandbox: what a compromised worker could reach, probed with a
//! shell run in the same bubblewrap command line, and the worker's lifecycle.
use super::{
    client::{sandbox_base, sandbox_command},
    *,
};
use crate::disks::{fixture::Fixture, sandbox::Account};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, time::Duration};

fn sandbox_available() -> bool {
    if !Path::new("/usr/bin/bwrap").is_file() || !Path::new("/usr/bin/prlimit").is_file() {
        return false;
    }
    let fixture = Fixture::new();
    let image = fixture.path("probe-image");
    let out = fixture.path("probe-out");
    fs::write(&image, b"x").unwrap();
    fs::create_dir(&out).unwrap();
    let account = Account::new().unwrap();
    let mut command = sandbox_base(
        Path::new("/usr/bin/true"),
        &image,
        None,
        &[],
        &out,
        account.passwd(),
    );
    command.arg("/usr/bin/true");
    command.output().is_ok_and(|output| output.status.success())
}

macro_rules! require_sandbox {
    () => {
        if !sandbox_available() {
            eprintln!("skipped: bubblewrap user namespaces are unavailable");
            return;
        }
    };
}

#[test]
fn the_command_line_uses_the_shared_profile_with_the_reader_binds() {
    let args: Vec<String> = sandbox_command(
        Path::new("/opt/antinomie-monitor"),
        Path::new("/data/root.ext4"),
        Some(Path::new("/data/before.ext4")),
        &[],
        Path::new("/data/out"),
        Path::new("/run/account/passwd"),
    )
    .get_args()
    .map(|arg| arg.to_string_lossy().into_owned())
    .collect();
    for flag in [
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ] {
        assert!(args.iter().any(|arg| arg == flag), "{flag}");
    }
    let has = |window: &[&str]| args.windows(window.len()).any(|found| found == window);
    // The shared profile: /usr read-only, an empty account, a bounded /tmp.
    assert!(has(&["--ro-bind", "/usr", "/usr"]));
    assert!(has(&["--ro-bind", "/run/account/passwd", "/etc/passwd"]));
    assert!(has(&["--tmpfs", "/tmp"]));
    // The reader's own binds: the image read-only, `/out` the only writable.
    assert!(has(&["--ro-bind", "/data/root.ext4", "/image"]));
    assert!(has(&["--ro-bind", "/opt/antinomie-monitor", "/worker"]));
    assert!(has(&["--ro-bind", "/data/before.ext4", "/other"]));
    assert!(has(&["--bind", "/data/out", "/out"]));
    let writable: Vec<_> = args
        .windows(3)
        .filter(|window| window[0] == "--bind" || window[0] == "--dev-bind")
        .map(|window| window[2].as_str())
        .collect();
    assert!(
        writable
            .iter()
            .all(|path| path.starts_with("/dev/") || *path == "/out"),
        "{writable:?}"
    );
    // The mounts are made read-only before the worker runs, under prlimit.
    let position = |needle: &str| args.iter().position(|arg| arg == needle).unwrap();
    assert!(position("--remount-ro") > position("/out"));
    assert!(position("/usr/bin/prlimit") > position("--remount-ro"));
    assert!(has(&["--core=0", "--", "/worker", "--disk-reader"]));
    assert!(args.iter().any(|arg| arg.starts_with("--as=")));
    assert!(args.iter().any(|arg| arg == "--nofile=64"));
    assert!(has(&["--setenv", "ANTINOMIE_ISOLATED_WORKER", "1"]));
}

#[test]
fn the_sandbox_confines_a_compromised_worker() {
    require_sandbox!();
    let fixture = Fixture::new();
    let image = fixture.path("image");
    fs::write(&image, b"not really an image").unwrap();
    let out = fixture.path("out");
    fs::create_dir(&out).unwrap();
    let secret = fixture.path("host-secret");
    fs::write(&secret, "the host's private data").unwrap();
    let script = format!(
        r#"
echo "image-write:$(echo x > /image 2>/dev/null && echo WRITABLE || echo readonly)"
echo "etc-write:$(/usr/bin/touch /etc/x 2>/dev/null && echo WRITABLE || echo readonly)"
echo "usr-write:$(/usr/bin/touch /usr/x 2>/dev/null && echo WRITABLE || echo readonly)"
echo "worker-write:$(echo x > /worker 2>/dev/null && echo WRITABLE || echo readonly)"
echo "root-write:$(/usr/bin/touch /x 2>/dev/null && echo WRITABLE || echo readonly)"
echo "out-write:$(/usr/bin/touch /out/ok 2>/dev/null && echo writable || echo READONLY)"
echo "tmp-write:$(/usr/bin/touch /tmp/ok 2>/dev/null && echo writable || echo READONLY)"
echo "secret:$(/usr/bin/cat '{secret}' 2>/dev/null || echo hidden)"
echo "home:$(/usr/bin/ls /home 2>/dev/null | /usr/bin/wc -l)"
echo "interfaces:$(/usr/bin/tail -n +3 /proc/net/dev | /usr/bin/cut -d: -f1 | /usr/bin/tr -d ' ' | /usr/bin/tr '\n' ,)"
echo "processes:$(/usr/bin/ls /proc | /usr/bin/grep -c '^[0-9][0-9]*$')"
echo "account:$(/usr/bin/cat /etc/passwd)"
echo "shm:$(/usr/bin/ls /dev/shm 2>/dev/null && echo VISIBLE || echo hidden)"
echo "env:$(/usr/bin/env | /usr/bin/sort | /usr/bin/tr '\n' ' ')"
echo "capabilities:$(/usr/bin/grep CapEff /proc/self/status)"
echo "limits:$(/usr/bin/grep -E '^(Max address space|Max open files|Max core file size)' /proc/self/limits | /usr/bin/tr -s ' ' | /usr/bin/tr '\n' ';')"
"#,
        secret = secret.display()
    );
    let account = Account::new().unwrap();
    let mut command = sandbox_base(
        Path::new("/usr/bin/true"),
        &image,
        None,
        &[],
        &out,
        account.passwd(),
    );
    command.args(["/usr/bin/sh", "-c", &script]);
    let output = command.output().unwrap();
    let report = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{report}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fact = |name: &str| {
        report
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}:")))
            .unwrap_or_else(|| panic!("{name} in {report}"))
    };
    for name in [
        "image-write",
        "etc-write",
        "usr-write",
        "worker-write",
        "root-write",
    ] {
        assert_eq!(fact(name), "readonly", "{name}\n{report}");
    }
    assert_eq!(fact("out-write"), "writable");
    assert_eq!(fact("tmp-write"), "writable");
    assert_eq!(fact("secret"), "hidden");
    assert_eq!(fact("home"), "0");
    assert_eq!(fact("account"), "nobody:x:65534:65534::/tmp:/bin/false");
    assert_eq!(fact("shm"), "hidden");
    // Only a loopback device in a private network namespace.
    assert!(matches!(fact("interfaces"), "" | "lo,"), "{report}");
    // A private PID namespace: the shell, its helpers.
    assert!(fact("processes").parse::<u32>().unwrap() < 10, "{report}");
    // No inherited environment, no capabilities.
    let env = fact("env");
    assert!(
        !env.contains("HOME=/home") && !env.contains("USER="),
        "{env}"
    );
    assert!(env.contains("ANTINOMIE_ISOLATED_WORKER=1"));
    assert!(fact("capabilities").ends_with("0000000000000000"));
    let limits = fact("limits");
    assert!(limits.contains("2147483648"), "{limits}");
    assert!(limits.contains("Max open files 64 64"), "{limits}");
    assert!(limits.contains("Max core file size 0 0"), "{limits}");
    // The image was only read.
    assert_eq!(fs::read(&image).unwrap(), b"not really an image");
    assert_eq!(
        fs::metadata(out.join("ok")).unwrap().permissions().mode() & 0o777 & 0o022,
        0
    );
}

fn script_worker(fixture: &Fixture, body: &str) -> std::path::PathBuf {
    let path = fixture.path("worker.sh");
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A `sleep` argument unique to this test process, so a worker is found by
/// its command line even while other test runs use the same sandbox.
fn marker(base: u32) -> String {
    format!("{base}.{}", std::process::id())
}

/// Run `body` on its own thread and fail, instead of hanging the suite, when
/// it takes longer than a minute: a reader that cannot stop its worker would
/// otherwise block on the worker's pipes for ever.
fn within_a_minute(body: impl FnOnce() + Send + 'static) {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        body();
        let _ = done.send(());
    });
    match finished.recv_timeout(Duration::from_secs(60)) {
        Ok(()) => {}
        // The body panicked (its sender dropped): report that, not a timeout.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("the test body panicked"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("hung: the reader did not stop its worker within a minute")
        }
    }
}

fn process_running(marker: &str) -> bool {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| fs::read(entry.path().join("cmdline")).ok())
        .any(|cmdline| String::from_utf8_lossy(&cmdline).contains(marker))
}

/// Whether no process carries `marker` any more. A killed worker is reaped a
/// moment after the kill, and how long that takes depends on the host, so this
/// waits for it, not for a fixed time.
fn gone(marker: &str) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while process_running(marker) {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

#[test]
fn a_stalled_worker_is_killed_and_the_next_request_starts_a_new_one() {
    require_sandbox!();
    within_a_minute(|| {
        let fixture = Fixture::new();
        let image = fixture.path("image");
        fs::write(&image, b"x").unwrap();
        // A worker that never answers.
        let worker = script_worker(&fixture, &format!("exec /usr/bin/sleep {}", marker(31337)));
        let mut reader = Reader::with_executable(worker, &image, &fixture.path("out")).unwrap();
        reader.set_timeout(Duration::from_millis(800));
        let error = reader.request(DiskRequest::Probe).unwrap_err();
        assert!(error.contains("did not answer in time"), "{error}");
        assert!(gone(&marker(31337)), "the stalled worker was left running");

        // A worker that dies at once reports why (its stderr), then is replaced.
        let dying = script_worker(&fixture, "echo 'cannot start' >&2; exit 3");
        let mut reader = Reader::with_executable(dying, &image, &fixture.path("out")).unwrap();
        reader.set_timeout(Duration::from_secs(5));
        let error = reader.request(DiskRequest::Probe).unwrap_err();
        assert!(
            error.contains("stopped") && error.contains("cannot start"),
            "{error}"
        );
        let again = reader.request(DiskRequest::Probe).unwrap_err();
        assert!(again.contains("cannot start"), "{again}");
    });
}

#[test]
fn dropping_the_reader_stops_its_worker() {
    require_sandbox!();
    within_a_minute(|| {
        let fixture = Fixture::new();
        let image = fixture.path("image");
        fs::write(&image, b"x").unwrap();
        let worker = script_worker(&fixture, &format!("exec /usr/bin/sleep {}", marker(41414)));
        let mut reader = Reader::with_executable(worker, &image, &fixture.path("out")).unwrap();
        reader.set_timeout(Duration::from_millis(300));
        let _ = reader.request(DiskRequest::Probe);
        drop(reader);
        assert!(gone(&marker(41414)));
    });
}

#[test]
fn cancelling_a_diff_or_a_content_search_kills_its_reader_at_once() {
    require_sandbox!();
    within_a_minute(|| {
        let fixture = Fixture::new();
        let (image, other) = (fixture.path("image"), fixture.path("other"));
        fs::write(&image, b"x").unwrap();
        fs::write(&other, b"y").unwrap();
        // A worker that never answers, like a diff of two enormous images.
        let worker = script_worker(&fixture, &format!("exec /usr/bin/sleep {}", marker(61616)));
        let mut reader =
            Reader::with_executable_and_other(worker, &image, Some(&other), &fixture.path("out"))
                .unwrap();
        let abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        reader.set_abort_flag(abort.clone());
        let flag = abort.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        let started = std::time::Instant::now();
        let error = reader.request(DiskRequest::Diff).unwrap_err();
        canceller.join().unwrap();
        assert!(error.starts_with("cancelled"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(gone(&marker(61616)), "the reader was left running");
        // The same flag stops a content search before it starts working.
        let error = reader
            .request(DiskRequest::Find {
                query: FindQuery {
                    pattern: "needle".into(),
                    mode: FindMode::Content,
                },
            })
            .unwrap_err();
        assert!(error.starts_with("cancelled"), "{error}");
        assert!(gone(&marker(61616)));
    });
}
