// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::os::unix::fs::PermissionsExt;

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-settings-{name}-{}", storage::unique_id()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn a_missing_file_is_not_an_error_and_a_missing_field_is_its_default() {
    let dir = scratch("missing");
    assert_eq!(load(&dir), Ok(None));
    std::fs::write(path(&dir), r#"{"quota_gib": 9}"#).unwrap();
    let loaded = load(&dir).unwrap().unwrap();
    assert_eq!(loaded.quota_gib, 9);
    assert_eq!(
        EngineSettings {
            quota_gib: 9,
            ..EngineSettings::default()
        },
        loaded
    );
}

#[test]
fn an_unreadable_file_is_reported_and_left_alone() {
    let dir = scratch("corrupt");
    std::fs::write(path(&dir), "{ not json").unwrap();
    let error = load(&dir).unwrap_err();
    assert!(error.contains("settings.json"), "{error}");
    assert_eq!(std::fs::read(path(&dir)).unwrap(), b"{ not json");
    // A value outside its range is as unusable as bad JSON.
    std::fs::write(path(&dir), r#"{"shutdown_timeout_s": 500}"#).unwrap();
    assert!(load(&dir).unwrap_err().contains("shutdown_timeout_s"));
    // A newer file is never read as if it were ours.
    std::fs::write(path(&dir), r#"{"settings_version": 9}"#).unwrap();
    assert!(load(&dir).unwrap_err().contains("newer"));
}

#[test]
fn only_the_process_that_holds_the_lock_writes_and_unknown_fields_survive() {
    let dir = scratch("write");
    let settings = EngineSettings::default();
    assert!(save(&dir, &settings).unwrap_err().contains("lock"));
    assert!(!path(&dir).exists());
    let guard = data_owner::lock_data_dir(&dir, &Default::default()).unwrap();
    std::fs::write(
        path(&dir),
        r#"{"quota_gib": 7, "from_the_future": {"a": [1, 2]}}"#,
    )
    .unwrap();
    let mut loaded = load(&dir).unwrap().unwrap();
    loaded.automatic_detection = false;
    save(&dir, &loaded).unwrap();
    let text = std::fs::read_to_string(path(&dir)).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["from_the_future"]["a"][1], 2);
    assert_eq!(value["quota_gib"], 7);
    assert_eq!(value["automatic_detection"], false);
    assert_eq!(
        std::fs::metadata(path(&dir)).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(guard);
    assert!(save(&dir, &loaded).is_err());
}

#[test]
fn get_and_set_reach_nested_keys_and_refuse_bad_values() {
    let mut settings = EngineSettings::default();
    assert_eq!(settings.get("quota_gib").unwrap(), 4);
    assert_eq!(settings.get("disks.hash_cap_mib").unwrap(), 64);
    assert!(settings.get("nope").is_err());
    settings.set("quota_gib", "12").unwrap();
    settings.set("disks.hide_dotfiles", "true").unwrap();
    settings.set("bundle", "/srv/images").unwrap();
    settings.set("address_lookup", "whois").unwrap();
    assert_eq!(settings.quota_gib, 12);
    assert!(settings.disks.hide_dotfiles);
    assert_eq!(settings.bundle, "/srv/images");
    assert_eq!(settings.address_lookup, AddressLookup::Whois);
    let before = settings.clone();
    for (key, value) in [
        ("quota_gib", "0"),
        ("quota_gib", "many"),
        ("shutdown_timeout_s", "121"),
        ("analysis_time_limit_minutes", "481"),
        ("address_lookup", "carrier-pigeon"),
        ("disks.unknown", "1"),
        ("brand_new", "1"),
        ("settings_version", "2"),
        ("", "1"),
    ] {
        assert!(settings.set(key, value).is_err(), "{key}={value}");
    }
    assert_eq!(settings, before);
}

#[test]
fn a_daemon_never_looks_symbols_up_online() {
    assert!(EngineSettings::default().memory_online_symbols);
    assert!(!EngineSettings::default().for_daemon().memory_online_symbols);
}

#[test]
fn the_file_caps_and_options_follow_the_settings() {
    let settings = EngineSettings {
        file_write_file_mib: 2,
        file_before_run_mib: 5,
        quota_gib: 3,
        shutdown_timeout_s: 30,
        ..Default::default()
    };
    assert_eq!(settings.write_limits().per_file, 2 << 20);
    assert_eq!(settings.before_limits().per_run, 5 << 20);
    let mut options = crate::BackendOptions::default();
    settings.apply_to(&mut options);
    assert_eq!(options.capture_quota_size, 3 << 30);
    assert_eq!(options.shutdown_timeout.as_secs(), 30);
}
