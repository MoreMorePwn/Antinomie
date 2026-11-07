// SPDX-License-Identifier: GPL-3.0-only
//! `config get` and `config set` through the built binary.
use serde_json::Value;
use std::process::Command;

fn cli(data: &std::path::Path, tail: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args(["-o", "json", "--data-dir", data.to_str().unwrap(), "config"])
        .args(tail)
        .output()
        .expect("antinomie-cli runs");
    let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output.status.code().unwrap_or(-1), value)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("ant-cli-config-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn set_writes_the_shared_file_and_get_reads_it_without_a_lock() {
    let root = scratch("roundtrip");
    let data = root.join("data");
    // No file yet: the defaults, and nothing is created by reading.
    let (code, quota) = cli(&data, &["get", "quota_gib"]);
    assert_eq!(code, 0, "{quota}");
    assert_eq!(quota["result"]["value"], 4);
    assert!(!data.exists());

    let (code, set) = cli(&data, &["set", "quota_gib", "12"]);
    assert_eq!(code, 0, "{set}");
    assert_eq!(set["result"]["value"], 12);
    cli(&data, &["set", "disks.hide_dotfiles", "true"]);
    cli(&data, &["set", "bundle", "/srv/bases"]);
    let (_, all) = cli(&data, &["get"]);
    assert_eq!(all["result"]["settings"]["quota_gib"], 12);
    assert_eq!(all["result"]["settings"]["disks"]["hide_dotfiles"], true);
    assert_eq!(all["result"]["settings"]["bundle"], "/srv/bases");
    // The lock was released again and the file is private.
    assert!(!data.join("run").join("owner.json").exists());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(data.join("settings.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // A bad key or value changes nothing and is exit 4.
    for (key, value) in [("nope", "1"), ("quota_gib", "0"), ("quota_gib", "lots")] {
        let (code, error) = cli(&data, &["set", key, value]);
        assert_eq!(code, 4, "{key}={value}: {error}");
        assert_eq!(error["error"]["code"], "invalid_argument");
    }
    let (_, after) = cli(&data, &["get", "quota_gib"]);
    assert_eq!(after["result"]["value"], 12);
    let (code, missing) = cli(&data, &["get", "nope"]);
    assert_eq!(code, 3, "{missing}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn set_refuses_while_another_process_owns_the_directory_and_a_broken_file_is_kept() {
    let root = scratch("busy");
    let data = root.join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("settings.json"), "{ broken").unwrap();
    let (code, error) = cli(&data, &["get", "quota_gib"]);
    assert_eq!(code, 4, "{error}");
    let (code, _) = cli(&data, &["set", "quota_gib", "5"]);
    assert_eq!(code, 4);
    assert_eq!(
        std::fs::read(data.join("settings.json")).unwrap(),
        b"{ broken"
    );

    std::fs::write(data.join("settings.json"), r#"{"quota_gib": 6}"#).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(data.join(".app-owner.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let (code, busy) = cli(&data, &["set", "quota_gib", "5"]);
    assert_eq!(code, 21, "{busy}");
    let (code, read) = cli(&data, &["get", "quota_gib"]);
    assert_eq!(code, 0);
    assert_eq!(read["result"]["value"], 6);
    drop(lock);
    std::fs::remove_dir_all(&root).unwrap();
}
