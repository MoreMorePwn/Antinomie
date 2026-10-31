// SPDX-License-Identifier: GPL-3.0-only
//! `--install-base` failures from the real binary: a plain `Error: ...` line on
//! standard error and exit code 1, never the Debug form of a startup error.
use std::{fs, process::Command};

fn run(directory: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_antinomie-monitor"))
        .arg("--data-dir")
        .arg(directory.join("data"))
        .args(extra)
        .output()
        .expect("run antinomie-monitor")
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("antinomie-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn install_base_failure_prints_a_plain_message_and_exits_one() {
    let dir = scratch("cli-missing");
    let output = run(
        &dir,
        &["--install-base", dir.join("no-such-base").to_str().unwrap()],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.starts_with("Error: "), "{stderr}");
    assert!(
        !stderr.contains("AppCreation") && !stderr.contains("Custom"),
        "{stderr}"
    );
}

#[test]
fn install_base_reports_an_unreadable_manifest_as_one_plain_line() {
    let dir = scratch("cli-newer");
    let base = dir.join("base");
    fs::create_dir_all(&base).unwrap();
    // The revision refusal text
    // is covered by the core tests; this checks the output shape.
    fs::write(base.join("bundle.json"), b"{}").unwrap();
    let output = run(&dir, &["--install-base", base.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("Error: "), "{stderr}");
}
