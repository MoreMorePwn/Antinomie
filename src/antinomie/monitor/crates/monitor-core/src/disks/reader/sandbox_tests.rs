// SPDX-License-Identifier: MIT
//! The reader's sandbox: what a compromised worker could reach, probed with a
//! shell run in the same bubblewrap command line, and the worker's lifecycle.
use super::{client::sandbox_base, *};
use crate::disks::fixture::Fixture;
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
    let mut command = sandbox_base(Path::new("/usr/bin/true"), &image, &out);
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
echo "env:$(/usr/bin/env | /usr/bin/sort | /usr/bin/tr '\n' ' ')"
echo "capabilities:$(/usr/bin/grep CapEff /proc/self/status)"
echo "limits:$(/usr/bin/grep -E '^(Max address space|Max open files|Max core file size)' /proc/self/limits | /usr/bin/tr -s ' ' | /usr/bin/tr '\n' ';')"
"#,
        secret = secret.display()
    );
    let mut command = sandbox_base(Path::new("/usr/bin/true"), &image, &out);
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

fn process_running(marker: &str) -> bool {
    fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter_map(|entry| fs::read(entry.path().join("cmdline")).ok())
        .any(|cmdline| String::from_utf8_lossy(&cmdline).contains(marker))
}

#[test]
fn a_stalled_worker_is_killed_and_the_next_request_starts_a_new_one() {
    require_sandbox!();
    let fixture = Fixture::new();
    let image = fixture.path("image");
    fs::write(&image, b"x").unwrap();
    // A worker that never answers.
    let worker = script_worker(&fixture, "exec /usr/bin/sleep 31337");
    let mut reader = Reader::with_executable(worker, &image, &fixture.path("out")).unwrap();
    reader.set_timeout(Duration::from_millis(800));
    let error = reader.request(DiskRequest::Probe).unwrap_err();
    assert!(error.contains("did not answer in time"), "{error}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !process_running("31337"),
        "the stalled worker was left running"
    );

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
}

#[test]
fn dropping_the_reader_stops_its_worker() {
    require_sandbox!();
    let fixture = Fixture::new();
    let image = fixture.path("image");
    fs::write(&image, b"x").unwrap();
    let worker = script_worker(&fixture, "exec /usr/bin/sleep 41414");
    let mut reader = Reader::with_executable(worker, &image, &fixture.path("out")).unwrap();
    reader.set_timeout(Duration::from_millis(300));
    let _ = reader.request(DiskRequest::Probe);
    drop(reader);
    std::thread::sleep(Duration::from_millis(300));
    assert!(!process_running("41414"));
}
