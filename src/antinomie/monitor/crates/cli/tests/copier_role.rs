// SPDX-License-Identifier: GPL-3.0-only
//! The earlier-bytes copier is served by `antinomie-cli` (ANT-T0356): the core
//! re-runs the running program with `--copy-earlier-bytes` when a boot ends,
//! and until now only a binary named `antinomie-monitor` did that.
use antinomie_monitor_core::file_before_store::{COPY_FLAG, Store};
use std::process::Command;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("antinomie-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_cli_serves_the_copy_role_and_completes_the_boot_folder() {
    let root = scratch("copier");
    let boot = root.join("boots").join("boot-1");
    // A boot with no runs still gets its index, marked complete.
    std::fs::create_dir_all(&boot).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args([COPY_FLAG])
        .arg(&boot)
        .args(["boot-1", "1048576", "4194304"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let store = Store::open(&boot).expect("the boot folder has an index");
    assert!(store.index.complete, "{:?}", store.index.note);
    assert_eq!(store.index.boot_id, "boot-1");
    assert_eq!(store.index.per_file, 1_048_576);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_run_with_no_readable_record_leaves_the_copy_incomplete_not_failed() {
    let root = scratch("copier-bad-run");
    let boot = root.join("boots").join("boot-2");
    std::fs::create_dir_all(boot.join("runs").join("broken")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .arg(COPY_FLAG)
        .arg(&boot)
        .args(["boot-2", "1048576", "4194304"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let store = Store::open(&boot).unwrap();
    assert!(!store.index.complete);
    assert!(store.index.note.as_deref().unwrap_or("").contains("broken"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_copy_role_refuses_missing_arguments_with_its_own_message() {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .arg(COPY_FLAG)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: --copy-earlier-bytes"));
}
