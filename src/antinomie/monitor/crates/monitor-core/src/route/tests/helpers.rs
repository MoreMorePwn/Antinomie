// SPDX-License-Identifier: GPL-3.0-only
//! Helpers that die with the app, and the PID files that let the next start
//! end the ones a killed app left behind. The helpers are `sleep` stand-ins;
//! every test ends only the PIDs it recorded itself.
use super::scratch;
use crate::route::helpers::{
    end_group, parse_record, parse_start_time, reap_stale, spawn, start_time, write_record,
};
use std::{
    path::Path,
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

fn sleeper() -> Command {
    let mut command = Command::new("sleep");
    command.arg("60");
    command
}

fn alive(pid: u32) -> bool {
    start_time(pid).is_some()
}

fn wait_gone(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(pid) {
        if Instant::now() > deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
    true
}

/// The process group of `pid` (field 5 of its stat).
fn group_of(pid: u32) -> u32 {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    text[text.rfind(')').unwrap() + 1..]
        .split_whitespace()
        .nth(2)
        .unwrap()
        .parse()
        .unwrap()
}

fn files(dir: &Path) -> usize {
    std::fs::read_dir(dir).map_or(0, |entries| entries.count())
}

fn end(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn the_start_time_is_read_after_a_command_name_with_spaces_and_brackets() {
    let stat = "42 (we) ird) (name) S 1 42 42 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 987654 \
                1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
    assert_eq!(parse_start_time(stat), Some(987654));
    assert_eq!(parse_start_time(&stat.replace(") S ", ") Z ")), None);
    assert_eq!(parse_start_time("garbage"), None);
    assert_eq!(parse_start_time("1 (x) S 1 2"), None);
    assert!(start_time(std::process::id()).is_some());
}

#[test]
fn a_helper_leads_its_own_group_and_is_recorded_while_it_runs() {
    let dir = scratch("helper-record");
    let helpers = dir.join("helpers");
    let (child, record) = spawn(sleeper(), &helpers, "sleep").unwrap();
    let pid = child.id();
    assert_eq!(group_of(pid), pid, "its own process group");
    assert_ne!(group_of(pid), group_of(std::process::id()));
    let file = helpers.join(format!("sleep-{pid}.pid"));
    let text = std::fs::read_to_string(&file).unwrap();
    assert_eq!(parse_record(&text), Some((pid, start_time(pid).unwrap())));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(record);
    assert!(!file.exists(), "the record goes with the helper");
    end(child);
    assert!(wait_gone(pid));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_helper_cannot_be_started_when_it_cannot_be_recorded() {
    let dir = scratch("helper-norecord");
    let blocker = dir.join("file");
    std::fs::write(&blocker, b"").unwrap();
    let error = spawn(sleeper(), &blocker.join("helpers"), "sleep")
        .err()
        .unwrap();
    assert!(error.contains("helpers"), "{error}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_cleanup_ends_a_recorded_helper_with_its_start_time_and_its_children() {
    let dir = scratch("helper-reap");
    let helpers = dir.join("helpers");
    // A shell that leads a group and has a child of its own.
    let mut command = Command::new("sh");
    command.args(["-c", "sleep 60 & wait"]);
    let (child, record) = spawn(command, &helpers, "sh").unwrap();
    let pid = child.id();
    std::mem::forget(record); // as if the app died: the file stays
    let grandchild = loop {
        // The shell's child, found by the group it shares (ours: recorded
        // through the group of the PID we started).
        let found = std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .find(|p| *p != pid && start_time(*p).is_some() && group_of(*p) == pid);
        if let Some(found) = found {
            break found;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let ended = reap_stale(&helpers);
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert!(ended[0].contains(&pid.to_string()));
    assert!(wait_gone(grandchild), "the helper's child died with it");
    let mut child = child;
    child.wait().unwrap();
    assert!(!alive(pid));
    assert_eq!(files(&helpers), 0, "the file is removed");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_reused_pid_is_not_touched() {
    let dir = scratch("helper-reused");
    let helpers = dir.join("helpers");
    let (child, record) = spawn(sleeper(), &helpers, "sleep").unwrap();
    let pid = child.id();
    std::mem::forget(record);
    // The file says another process once had this PID: another start time.
    let file = helpers.join(format!("sleep-{pid}.pid"));
    let real = start_time(pid).unwrap();
    std::fs::write(&file, format!("{pid} {}\n", real + 1)).unwrap();
    assert!(reap_stale(&helpers).is_empty());
    assert!(
        alive(pid),
        "a process with another start time is left alone"
    );
    assert!(!file.exists(), "the stale file is removed");
    end(child);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn files_of_helpers_that_are_gone_or_malformed_are_removed_and_others_kept() {
    let dir = scratch("helper-gone");
    let helpers = dir.join("helpers");
    std::fs::create_dir_all(&helpers).unwrap();
    let (child, record) = spawn(sleeper(), &helpers, "sleep").unwrap();
    let pid = child.id();
    let started = start_time(pid).unwrap();
    drop(record);
    end(child);
    assert!(wait_gone(pid));
    std::fs::write(
        helpers.join(format!("gone-{pid}.pid")),
        format!("{pid} {started}\n"),
    )
    .unwrap();
    std::fs::write(helpers.join("bad.pid"), "not a record").unwrap();
    std::fs::write(helpers.join("extra.pid"), "1 2 3").unwrap();
    std::fs::write(helpers.join("note.txt"), "keep").unwrap();
    assert!(reap_stale(&helpers).is_empty());
    assert_eq!(files(&helpers), 1);
    assert!(helpers.join("note.txt").exists());
    assert!(reap_stale(&dir.join("missing")).is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_process_that_is_gone_leaves_no_record() {
    let dir = scratch("helper-nowrite");
    let mut child = sleeper().spawn().unwrap();
    let pid = child.id();
    let _ = child.kill();
    child.wait().unwrap();
    drop(write_record(&dir, "sleep", pid).unwrap());
    assert_eq!(files(&dir), 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// Run by the test below in a child copy of this test program, which plays
/// "the app": it starts a helper, reports its PID, and waits to be killed.
#[test]
fn app_role_for_the_death_signal_test() {
    let (Some(dir), Some(report)) = (
        std::env::var_os("ANT_TEST_HELPER_DIR"),
        std::env::var_os("ANT_TEST_HELPER_REPORT"),
    ) else {
        return;
    };
    let (child, record) = spawn(sleeper(), Path::new(&dir), "sleep").unwrap();
    std::fs::write(&report, child.id().to_string()).unwrap();
    // Leaked on purpose: nothing cleans up, as in a SIGKILL.
    std::mem::forget((child, record));
    thread::sleep(Duration::from_secs(120));
}

#[test]
fn a_helper_dies_when_the_app_is_killed() {
    let dir = scratch("helper-pdeathsig");
    let helpers = dir.join("helpers");
    let report = dir.join("pid");
    let mut app = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "route::tests::helpers::app_role_for_the_death_signal_test",
            "--nocapture",
        ])
        .env("ANT_TEST_HELPER_DIR", &helpers)
        .env("ANT_TEST_HELPER_REPORT", &report)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&report)
            .ok()
            .and_then(|t| t.parse::<u32>().ok())
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the stand-in app did not start");
        thread::sleep(Duration::from_millis(20));
    };
    assert!(alive(pid));
    app.kill().unwrap();
    app.wait().unwrap();
    assert!(wait_gone(pid), "the helper outlived the app");
    // Its file stays (nothing ran to remove it); the next start clears it.
    assert_eq!(files(&helpers), 1);
    assert!(reap_stale(&helpers).is_empty(), "nothing left to end");
    assert_eq!(files(&helpers), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_helper_started_from_a_short_lived_thread_outlives_that_thread() {
    let dir = scratch("helper-thread");
    let helpers = dir.join("helpers");
    let spawned = {
        let helpers = helpers.clone();
        thread::spawn(move || spawn(sleeper(), &helpers, "sleep").unwrap())
            .join()
            .unwrap()
    };
    thread::sleep(Duration::from_millis(300));
    let (child, record) = spawned;
    assert!(
        alive(child.id()),
        "the death signal follows the spawner, not this thread"
    );
    drop(record);
    let pid = child.id();
    end_group(pid);
    let mut child = child;
    child.wait().unwrap();
    let _ = std::fs::remove_dir_all(dir);
}
