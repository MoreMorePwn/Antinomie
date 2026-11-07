// SPDX-License-Identifier: GPL-3.0-only
//! The built binary: exit codes, the JSON envelope and the worker roles.
use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args(args)
        .env_remove("ANTINOMIE_ISOLATED_WORKER")
        .output()
        .expect("antinomie-cli runs")
}

/// Each sandboxed worker role is served by this binary: started without its
/// sandbox it refuses with its own message (exit 1), instead of falling
/// through to the argument parser (exit 2).
#[test]
fn the_four_analysis_worker_roles_are_served() {
    let roles = [
        (
            &["--antinomie-detection-worker", "a", "b"][..],
            "detector worker requires isolation",
        ),
        (
            &["--antinomie-properties-worker", "a", "b", "c"][..],
            "property worker requires isolation",
        ),
        (
            &["--antinomie-analysis-worker"][..],
            "private worker requires the analysis sandbox",
        ),
        (&["--disk-reader"][..], "disk reader requires its sandbox"),
    ];
    for (args, message) in roles {
        let output = cli(args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains(message), "{args:?}: {stderr}");
    }
}

#[test]
fn version_and_config_path_work() {
    let version = cli(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("antinomie-cli "));
    let path = cli(&["--data-dir", "/nonexistent", "-o", "json", "config", "path"]);
    assert_eq!(path.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&path.stdout).unwrap();
    assert_eq!(value["ok"], true);
}

#[test]
fn doctor_reports_checks_and_a_missing_required_tool_is_exit_20() {
    let ok = cli(&[
        "-o",
        "json",
        "doctor",
        "--require",
        "curl",
        "--qemu",
        "/bin/true",
    ]);
    let value: serde_json::Value = serde_json::from_slice(&ok.stdout).unwrap();
    assert!(value["ok"].is_boolean());
    assert_eq!(
        ok.status.code(),
        Some(if value["ok"] == true { 0 } else { 20 })
    );
    // An explicit requirement on a QEMU that is not there: always exit 20.
    let missing = cli(&[
        "-o",
        "json",
        "doctor",
        "--require",
        "qemu",
        "--qemu",
        "/nonexistent/qemu",
    ]);
    assert_eq!(missing.status.code(), Some(20));
    let value: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "dependency_missing");
    assert_eq!(value["error"]["details"]["missing"][0], "qemu");
    assert!(
        value["error"]["details"]["checks"]
            .as_array()
            .unwrap()
            .len()
            > 1
    );
}

#[test]
fn capabilities_has_the_api_version_and_a_usage_error_is_exit_2() {
    let capabilities = cli(&["-o", "json", "capabilities"]);
    assert_eq!(capabilities.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&capabilities.stdout).unwrap();
    assert_eq!(value["result"]["api_version"], 1);
    assert_eq!(value["result"]["lanes"], 1);
    let bad = cli(&["-o", "json", "no-such-command"]);
    assert_eq!(bad.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert_eq!(value["ok"], false);
}

/// A directory whose lock another process holds is reported by `doctor` with
/// the record that process wrote, and a stale record is ignored.
#[test]
fn doctor_names_the_owner_of_the_data_directory() {
    use antinomie_monitor_core::data_owner::{self, OwnerClaim, OwnerKind};
    let root = std::env::temp_dir().join(format!("ant-cli-owner-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let data = root.to_str().unwrap();
    let report = |args: &[&str]| -> serde_json::Value {
        let mut all = vec![
            "-o",
            "json",
            "--data-dir",
            data,
            "doctor",
            "--require",
            "curl",
        ];
        all.extend_from_slice(args);
        let output = cli(&all);
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if value["ok"] == true {
            value["result"]["data_dir"].clone()
        } else {
            value["error"]["details"]["data_dir"].clone()
        }
    };
    // A stale record and no lock: ignored.
    let mut stale = data_owner::record_for(&OwnerClaim {
        kind: OwnerKind::Gui,
        socket: None,
    });
    stale.pid = 4_000_000_000;
    data_owner::write_record(&root, &stale).unwrap();
    assert_eq!(report(&["--qemu", "/bin/true"])["owned"], false);
    // Hold the lock as this test process and record it.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(".app-owner.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let mut record = data_owner::record_for(&OwnerClaim {
        kind: OwnerKind::Daemon,
        socket: None,
    });
    record.pid = std::process::id();
    data_owner::write_record(&root, &record).unwrap();
    let owned = report(&["--qemu", "/bin/true"]);
    assert_eq!(owned["owned"], true);
    assert_eq!(owned["owner"]["pid"], std::process::id());
    assert_eq!(owned["owner"]["kind"], "daemon");
    std::fs::remove_dir_all(&root).unwrap();
}
