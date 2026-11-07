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
