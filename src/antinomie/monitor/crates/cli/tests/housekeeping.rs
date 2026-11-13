// SPDX-License-Identifier: GPL-3.0-only
//! `auto watch`, `auto gc` and `auto delete` on the built binary, without a
//! daemon (cards P4-2, P4-3).
use std::{path::Path, process::Command};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-cli-hk-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli(data: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_antinomie-cli"))
        .env_remove("ANTINOMIE_ISOLATED_WORKER")
        .env("HOME", data)
        .env("XDG_DATA_HOME", data.join("xdg-data"))
        .env("XDG_CONFIG_HOME", data.join("xdg-config"))
        .env("XDG_CACHE_HOME", data.join("xdg-cache"))
        .arg("--data-dir")
        .arg(data.join("data"))
        .args(["-o", "json"])
        .args(args)
        .output()
        .expect("antinomie-cli runs");
    let stdout = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    (
        output.status.code(),
        stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn watch_list_without_a_daemon_names_the_configured_folders() {
    let root = scratch("watch-list");
    std::fs::create_dir_all(root.join("data")).unwrap();
    std::fs::write(
        root.join("data/service.toml"),
        "[[inbox.watch]]\npath = \"/srv/drop/one\"\npreset = \"standard\"\n[[inbox.watch]]\npath = \"/srv/drop/two\"\n",
    )
    .unwrap();
    let (code, out, err) = cli(&root, &["auto", "watch", "list"]);
    assert_eq!(code, Some(0), "{err}");
    let items = out["items"]
        .as_array()
        .or(out["result"]["items"].as_array())
        .unwrap_or_else(|| panic!("{out}"));
    assert_eq!(items.len(), 2, "{out}");
    assert_eq!(items[0]["path"], "/srv/drop/one");
    assert_eq!(items[0]["state"], "daemon not running");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn watch_scan_needs_a_daemon() {
    let root = scratch("watch-scan");
    let (code, out, err) = cli(&root, &["auto", "watch", "scan"]);
    assert_eq!(code, Some(21), "{err}");
    assert_eq!(out["ok"], false);
    assert!(
        out["error"]["message"]
            .as_str()
            .unwrap()
            .contains("needs a running daemon"),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn gc_on_an_empty_data_folder_plans_nothing_and_a_bad_job_id_is_refused() {
    let root = scratch("gc");
    // No data folder: nothing to look at.
    let (code, _, _) = cli(&root, &["auto", "gc", "--dry-run"]);
    assert_eq!(code, Some(3));
    std::fs::create_dir_all(root.join("data")).unwrap();
    let (code, out, err) = cli(&root, &["auto", "gc", "--dry-run"]);
    assert_eq!(code, Some(0), "{err}");
    let report = if out["result"].is_object() {
        &out["result"]
    } else {
        &out
    };
    assert_eq!(report["dry_run"], true, "{out}");
    assert_eq!(report["actions"].as_array().unwrap().len(), 0);
    let (code, _, err) = cli(&root, &["auto", "delete", "not-a-job"]);
    assert_eq!(code, Some(4), "{err}");
    let (code, _, err) = cli(&root, &["auto", "delete", "j_01ARZ3NDEKTSV4RRFFQ69G5FAV"]);
    assert_eq!(code, Some(3), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}
