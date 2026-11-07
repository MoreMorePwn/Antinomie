// SPDX-License-Identifier: GPL-3.0-only
//! `analyze` and `rules` through the built binary.
use antinomie_monitor_core::ruleset::{CustomGroup, Registry, rules_root};
use serde_json::Value;
use std::{path::Path, process::Command};

fn cli(args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .args(args)
        .output()
        .expect("antinomie-cli runs");
    let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    (output.status.code().unwrap_or(-1), value)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("ant-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn group(id: &str, engine: &str) -> CustomGroup {
    CustomGroup {
        id: id.into(),
        name: format!("Group {id}"),
        engine: engine.into(),
        revision: 1,
        enabled: true,
        tags: vec![],
        deleted: false,
    }
}

#[test]
fn rules_list_enable_disable_use_the_registry() {
    let root = scratch("rules");
    let data = root.join("data");
    std::fs::create_dir_all(rules_root(&data)).unwrap();
    let registry = Registry {
        schema: 1,
        groups: vec![group("mine", "yara"), group("sig", "sigma")],
        ..Registry::default()
    };
    std::fs::write(
        rules_root(&data).join("registry.json"),
        serde_json::to_vec(&registry).unwrap(),
    )
    .unwrap();
    let data_arg = data.to_str().unwrap();
    let base = ["-o", "json", "--data-dir", data_arg, "rules"];
    let run = |tail: &[&str]| {
        let mut all = base.to_vec();
        all.extend_from_slice(tail);
        cli(&all)
    };

    let (code, listed) = run(&["list"]);
    assert_eq!(code, 0);
    assert_eq!(listed["result"]["items"].as_array().unwrap().len(), 2);
    let (_, yara) = run(&["list", "--engine", "yara"]);
    assert_eq!(yara["result"]["items"][0]["key"], "group:mine");

    let (code, off) = run(&["disable", "mine"]);
    assert_eq!(code, 0, "{off}");
    assert_eq!(off["result"]["enabled"], false);
    let (_, after) = run(&["list", "--engine", "yara"]);
    assert_eq!(after["result"]["items"][0]["enabled"], false);
    // The lock is released and the record removed again.
    assert!(!data.join("run").join("owner.json").exists());
    let (code, _) = run(&["enable", "group:mine"]);
    assert_eq!(code, 0);
    let (_, back) = run(&["list", "--engine", "yara"]);
    assert_eq!(back["result"]["items"][0]["enabled"], true);

    let (code, missing) = run(&["enable", "nope"]);
    assert_eq!(code, 3);
    assert_eq!(missing["error"]["code"], "not_found");

    // A directory owned by another process refuses the change and names it.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(data.join(".app-owner.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let (code, busy) = run(&["disable", "mine"]);
    assert_eq!(code, 21);
    assert_eq!(busy["error"]["code"], "unavailable");
    // Listing still works beside the owner.
    let (code, _) = run(&["list"]);
    assert_eq!(code, 0);
    drop(lock);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn rules_list_of_a_directory_without_a_registry_is_empty() {
    let root = scratch("norules");
    let data = root.join("data");
    let (code, value) = cli(&[
        "-o",
        "json",
        "--data-dir",
        data.to_str().unwrap(),
        "rules",
        "list",
    ]);
    assert_eq!(code, 0);
    assert_eq!(value["result"]["items"], serde_json::json!([]));
    assert!(!data.exists());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn analyze_reports_a_host_file_and_copies_the_report_folder() {
    if !Path::new("/usr/bin/bwrap").exists() {
        eprintln!("skipped: bubblewrap is not installed");
        return;
    }
    let root = scratch("analyze");
    let sample = root.join("sample.bin");
    std::fs::copy("/bin/true", &sample).unwrap();
    let data = root.join("data");
    let out = root.join("out");
    let (code, value) = cli(&[
        "-o",
        "json",
        "--data-dir",
        data.to_str().unwrap(),
        "--timeout",
        "240",
        "analyze",
        sample.to_str().unwrap(),
        "--checks",
        "metadata,strings,entropy",
        "--out",
        out.to_str().unwrap(),
    ]);
    if code == 20 {
        eprintln!("skipped: the analysis sandbox is not usable here: {value}");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(code, 0, "{value}");
    let result = &value["result"];
    assert!(matches!(
        result["state"].as_str(),
        Some("complete" | "partial")
    ));
    let sha = result["specimen_sha256"].as_str().unwrap();
    assert_eq!(sha.len(), 64);
    let kinds: Vec<&str> = result["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"metadata") && kinds.contains(&"entropy"),
        "{kinds:?}"
    );
    assert!(Path::new(result["directory"].as_str().unwrap()).is_dir());
    let copy = Path::new(result["copies"][0].as_str().unwrap());
    assert!(copy.starts_with(&out) && copy.is_dir());
    // The data directory is free again.
    assert!(!data.join("run").join("owner.json").exists());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn analyze_refuses_bad_arguments_before_starting_the_engine() {
    let root = scratch("analyze-bad");
    let data = root.join("data");
    let data_arg = data.to_str().unwrap();
    let (code, missing) = cli(&[
        "-o",
        "json",
        "--data-dir",
        data_arg,
        "analyze",
        "/nonexistent/file",
    ]);
    assert_eq!(code, 3);
    assert_eq!(missing["error"]["field"], "file");
    let file = root.join("f");
    std::fs::write(&file, b"x").unwrap();
    let (code, _) = cli(&[
        "-o",
        "json",
        "--data-dir",
        data_arg,
        "analyze",
        file.to_str().unwrap(),
        "--checks",
        "bogus",
    ]);
    assert_eq!(code, 4);
    let (code, _) = cli(&[
        "-o",
        "json",
        "--data-dir",
        data_arg,
        "analyze",
        root.to_str().unwrap(),
    ]);
    assert_eq!(code, 4);
    assert!(!data.exists());
    std::fs::remove_dir_all(&root).unwrap();
}
