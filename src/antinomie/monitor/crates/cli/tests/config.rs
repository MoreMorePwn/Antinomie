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

fn write(data: &std::path::Path, name: &str, text: &str) {
    let path = data.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const PRESET: &str = r#"
title = "CI"
[program]
run_time_s = 120
[network]
route = "inet_sim"
"#;

#[test]
fn validate_accepts_good_files_and_a_data_directory_with_none() {
    let root = scratch("validate-ok");
    let data = root.join("data");
    // Nothing written yet: the defaults and the built-in presets, with a
    // warning that the lane VM is not made yet.
    let (code, out) = cli(&data, &["validate"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["result"]["ok"], true);
    assert_eq!(out["result"]["problems"][0]["severity"], "warning");
    assert_eq!(
        out["result"]["presets"],
        serde_json::json!([
            "deep",
            "interactive",
            "live-network",
            "quick-look",
            "standard"
        ])
    );
    assert!(!data.exists(), "validate reads only");

    write(&data, "service.toml", "[queue]\nmax_queued = 10\n");
    write(&data, "presets/ci.toml", PRESET);
    write(&data, "presets/nightly.toml", PRESET);
    let (code, out) = cli(&data, &["validate"]);
    assert_eq!(code, 0, "{out}");
    let presets = out["result"]["presets"].as_array().unwrap();
    assert_eq!(presets.len(), 7, "{out}");
    let files = out["result"]["files"].to_string();
    assert!(
        files.contains("presets/ci.toml") && files.contains("built-in/standard"),
        "{files}"
    );
    // The lane VM is not in this data directory: a warning, not an error.
    let warnings = out["result"]["problems"].as_array().unwrap();
    assert!(warnings.iter().all(|p| p["severity"] == "warning"), "{out}");
    assert!(
        warnings
            .iter()
            .any(|p| p["message"].as_str().unwrap().contains("auto-1"))
    );
    let (code, one) = cli(&data, &["validate", "--preset", "ci"]);
    assert_eq!(code, 0, "{one}");
    assert_eq!(one["result"]["presets"], serde_json::json!(["ci"]));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn validate_reports_every_problem_with_its_line_and_exits_4() {
    let root = scratch("validate-bad");
    let data = root.join("data");
    write(&data, "service.toml", "[daemon]\nlanes = 5\n");
    write(
        &data,
        "presets/bad.toml",
        "title = \"Bad\"\n[network]\nroute = \"internet\"\n[program]\nrun_time_s = 9000\n",
    );
    write(&data, "presets/typo.toml", "[repart]\nx = 1\n");
    let (code, out) = cli(&data, &["validate"]);
    assert_eq!(code, 4, "{out}");
    assert_eq!(out["error"]["code"], "invalid_argument");
    let problems = out["error"]["details"]["problems"].as_array().unwrap();
    let find = |file: &str, needle: &str| {
        problems
            .iter()
            .find(|p| p["file"] == file && p["message"].as_str().unwrap().contains(needle))
            .unwrap_or_else(|| panic!("{file}: {needle}: {problems:?}"))
            .clone()
    };
    assert_eq!(find("service.toml", "must be 1 to 4")["line"], 2);
    assert_eq!(
        find("presets/bad.toml", "not set up on this node")["line"],
        3
    );
    assert_eq!(find("presets/bad.toml", "5 to 1800 seconds")["line"], 5);
    assert_eq!(find("presets/typo.toml", "unknown field")["line"], 1);
    assert_eq!(
        find("presets/typo.toml", "unknown field")["severity"],
        "error"
    );

    // --preset limits the preset checks to one file; the service file is still read.
    let (code, one) = cli(&data, &["validate", "--preset", "typo"]);
    assert_eq!(code, 4);
    let files: Vec<_> = one["error"]["details"]["problems"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["file"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        files.contains(&"presets/typo.toml".to_owned())
            && !files.contains(&"presets/bad.toml".to_owned())
    );
    let (code, none) = cli(&data, &["validate", "--preset", "nothing"]);
    assert_eq!(code, 4, "{none}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn validate_prints_file_line_and_message_for_a_person() {
    let root = scratch("validate-human");
    let data = root.join("data");
    write(
        &data,
        "presets/bad.toml",
        "title = \"Bad\"\n\n[accepts]\nmax_sample_mib = 999\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args([
            "-o",
            "human",
            "--data-dir",
            data.to_str().unwrap(),
            "config",
            "validate",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("presets/bad.toml:4:1: error: accepts.max_sample_mib: must be 1 to 256"),
        "{text}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn validate_refuses_a_0_9_0_policies_folder_naming_the_new_keys() {
    let root = scratch("validate-policies");
    let data = root.join("data");
    write(
        &data,
        "policies/default.toml",
        "[run]\ntimeout_s = 300\nallow_root = false\n",
    );
    let (code, out) = cli(&data, &["validate"]);
    assert_eq!(code, 4, "{out}");
    let text = out["error"]["details"]["problems"].to_string();
    assert!(text.contains("policies/ is replaced by presets/"), "{text}");
    assert!(text.contains("program.run_time_s"), "{text}");
    assert!(text.contains("run.as_root"), "{text}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_api_key_is_read_from_stdin_stored_private_and_never_printed() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    // A key of the right shape that no service knows.
    const KEY: &str = "fake-cli-key-for-tests-9a1f";
    let root = scratch("api-key");
    let data = root.join("data");
    let run = |tail: &[&str], input: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
            .args([
                "-o",
                "json",
                "--data-dir",
                data.to_str().unwrap(),
                "config",
                "api-key",
            ])
            .args(tail)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("antinomie-cli runs");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!text.contains(KEY), "the key was printed: {text}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output.status.code().unwrap_or(-1), value)
    };
    let (code, set) = run(&["set", "abusech"], &format!("{KEY}\n"));
    assert_eq!(code, 0, "{set}");
    assert_eq!(set["result"]["shown"], "…9a1f");
    let file = data.join("api-keys.json");
    let mode = std::fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(std::fs::read_to_string(&file).unwrap().contains(KEY));
    let (code, shown) = run(&["show"], "");
    assert_eq!(code, 0, "{shown}");
    assert_eq!(shown["result"]["keys"][0]["key"], "abusech");
    assert_eq!(shown["result"]["keys"][0]["stored"], true);
    // A key with a space is refused and changes nothing.
    let (code, bad) = run(&["set", "abusech"], "two words\n");
    assert_eq!(code, 4, "{bad}");
    assert!(std::fs::read_to_string(&file).unwrap().contains(KEY));
    let (code, _) = run(&["clear", "abusech"], "");
    assert_eq!(code, 0);
    let (_, shown) = run(&["show"], "");
    assert_eq!(shown["result"]["keys"][0]["stored"], false);
    let _ = std::fs::remove_dir_all(root);
}
