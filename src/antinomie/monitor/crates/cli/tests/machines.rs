// SPDX-License-Identifier: GPL-3.0-only
//! `base`, `vm` and `snapshot` through the built binary, on a scratch data
//! directory and no QEMU: the listings, the refusal paths and the exit codes.
//! Booting a guest is checked on the PC (the task record has the output).
use antinomie_monitor_core::VmConfig;
use serde_json::Value;
use std::{path::Path, process::Command};

fn cli(data: &Path, args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args(["-o", "json", "--data-dir", data.to_str().unwrap()])
        .args(args)
        .output()
        .expect("antinomie-cli runs");
    let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output.status.code().unwrap_or(-1), value)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("ant-cli-vm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// A data directory holding one saved VM, `lane`, with no disk: enough for
/// the commands that list, show and refuse.
fn with_vm(name: &str) -> std::path::PathBuf {
    let data = scratch(name).join("data");
    let dir = data.join("lane");
    std::fs::create_dir_all(&dir).unwrap();
    let vm = VmConfig {
        id: "lane".into(),
        name: "Lane".into(),
        cpus: 2,
        ram_mib: 512,
        disk_gib: 1,
        routed: true,
        ..VmConfig::default()
    };
    std::fs::write(dir.join("config.json"), serde_json::to_vec(&vm).unwrap()).unwrap();
    data
}

fn error_code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("")
}

#[test]
fn an_empty_data_directory_lists_no_bases_and_no_vms() {
    let data = scratch("empty").join("data");
    for group in ["base", "vm"] {
        let (code, reply) = cli(&data, &[group, "list"]);
        assert_eq!(code, 0, "{reply}");
        assert_eq!(reply["result"]["items"], serde_json::json!([]));
    }
}

#[test]
fn a_saved_vm_is_listed_and_shown_as_stopped() {
    let data = with_vm("list");
    let (code, listed) = cli(&data, &["vm", "list"]);
    assert_eq!(code, 0, "{listed}");
    let item = &listed["result"]["items"][0];
    assert_eq!(item["id"], "lane");
    assert_eq!(item["network"], "routed");
    assert_eq!(item["state"], "stopped");
    assert_eq!(item["cpus"], 2);
    let (code, status) = cli(&data, &["vm", "status", "Lane"]);
    assert_eq!(code, 0, "{status}");
    assert_eq!(status["result"]["id"], "lane");
    assert!(status["result"]["disk_layer"].is_null());
    let (code, stop) = cli(&data, &["vm", "stop", "lane"]);
    assert_eq!(code, 0, "{stop}");
    assert_eq!(stop["result"]["changed"], false);
}

#[test]
fn every_destructive_command_refuses_without_yes_and_changes_nothing() {
    let data = with_vm("yes");
    for args in [&["vm", "delete", "lane"][..], &["vm", "reset", "lane"][..]] {
        let (code, reply) = cli(&data, args);
        assert_eq!(code, 4, "{args:?}: {reply}");
        assert_eq!(error_code(&reply), "invalid_argument");
        assert_eq!(reply["error"]["field"], "yes");
        assert!(
            reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("--yes"),
            "{reply}"
        );
    }
    assert!(data.join("lane").join("config.json").is_file());
    let (code, _) = cli(&data, &["vm", "list"]);
    assert_eq!(code, 0);
}

#[test]
fn unknown_things_are_not_found_and_the_exit_code_says_so() {
    let data = with_vm("missing");
    for args in [
        &["vm", "status", "nope"][..],
        &["vm", "start", "nope"][..],
        &["vm", "delete", "nope", "--yes"][..],
        &["snapshot", "list", "nope"][..],
        &["snapshot", "restore", "nope", "x", "--yes"][..],
        &["base", "delete", "nonexistent", "--yes"][..],
    ] {
        let (code, reply) = cli(&data, args);
        assert_eq!(code, 3, "{args:?}: {reply}");
        assert_eq!(error_code(&reply), "not_found");
    }
}

#[test]
fn creating_a_vm_needs_a_base_and_valid_flags() {
    let data = scratch("create").join("data");
    let (code, reply) = cli(&data, &["vm", "create", "x"]);
    assert_eq!(code, 4, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no base"),
        "{reply}"
    );
    for flags in [&["--network", "wifi"][..], &["--stealth", "cloud-vps"][..]] {
        let mut args = vec!["vm", "create", "x"];
        args.extend_from_slice(flags);
        let (code, reply) = cli(&data, &args);
        // A bad flag is refused before the engine is asked, base or not.
        assert!(code == 4, "{flags:?}: {code} {reply}");
    }
}

#[test]
fn the_remote_catalog_stays_off_until_the_setting_allows_it() {
    let data = scratch("catalog").join("data");
    for args in [
        &["base", "list", "--remote"][..],
        &["base", "download", "abcd1234"][..],
    ] {
        let (code, reply) = cli(&data, args);
        assert_eq!(code, 5, "{args:?}: {reply}");
        assert_eq!(error_code(&reply), "unavailable_on_node");
    }
}

#[test]
fn a_directory_owned_by_another_process_is_exit_21() {
    // The ownership record is P1-3's; here only that the new commands report it.
    let data = with_vm("busy");
    let hold = antinomie_monitor_core::Backend::new(antinomie_monitor_core::BackendOptions {
        data_dir: data.clone(),
        ..Default::default()
    })
    .expect("the test holds the lock");
    let (code, reply) = cli(&data, &["vm", "list"]);
    assert_eq!(code, 21, "{reply}");
    assert_eq!(error_code(&reply), "unavailable");
    drop(hold);
}

#[test]
fn a_daemon_serves_vm_list_only_and_the_flag_without_one_is_unavailable() {
    let data = with_vm("daemon");
    // `vm list` is a read the daemon serves; with none running, --daemon fails.
    let (code, reply) = cli(&data, &["--daemon", "vm", "list"]);
    assert_eq!(code, 21, "{reply}");
    assert_eq!(error_code(&reply), "unavailable");
    // A command that changes a VM runs in its own process, never in the daemon.
    let (code, reply) = cli(&data, &["--daemon", "vm", "stop", "vm-1"]);
    assert_eq!(code, 1, "{reply}");
    assert_eq!(error_code(&reply), "unsupported");
}

#[test]
fn run_exec_refuses_what_it_can_before_the_engine_starts() {
    let data = with_vm("exec");
    for (args, code) in [
        (&["run", "exec", &"ab".repeat(32)][..], 3),
        (&["run", "exec", "/no/such/file"][..], 3),
        (&["run", "exec", &"ab".repeat(32), "--as", "admin"][..], 4),
        (
            &["run", "exec", &"ab".repeat(32), "--env", "NOEQUALS"][..],
            4,
        ),
        (&["run", "exec", &"ab".repeat(32), "--route", "wifi"][..], 4),
    ] {
        let (exit, reply) = cli(&data, args);
        assert_eq!(exit, code, "{args:?}: {reply}");
    }
}

#[test]
fn run_exec_with_events_speaks_ndjson_even_when_json_was_asked() {
    let data = with_vm("events");
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args(["-o", "json", "--data-dir", data.to_str().unwrap()])
        .args(["run", "exec", "/no/such/file", "--events"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    let line: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert!(line.get("error").is_some(), "{text}");
    assert!(line.get("api_version").is_none(), "{text}");
}
