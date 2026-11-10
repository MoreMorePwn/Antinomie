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
    let lookup = EngineSettings {
        sample_hash_lookup: true,
        ..EngineSettings::default()
    };
    assert!(!EngineSettings::default().sample_hash_lookup);
    assert!(!lookup.for_daemon().sample_hash_lookup);
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

#[test]
fn the_start_settings_are_shared_and_default_when_absent() {
    // A file without them: the defaults, and they are not written back.
    let settings = EngineSettings::default();
    assert_eq!(settings.start(), crate::api::StartSettings::default());
    assert!(settings.to_value().get("start").is_none());
    // They can still be read and set by key.
    assert_eq!(settings.get("start.tcg_multiplier").unwrap(), 10);
    let mut changed = settings.clone();
    changed.set("start.tcg_multiplier", "25").unwrap();
    changed.set("start.boot_wait_secs", "120").unwrap();
    assert_eq!(changed.start().tcg_multiplier, 25);
    assert_eq!(changed.start().boot_wait_secs, 120);
    assert_eq!(changed.start().guest_connect_secs, 20);
    // Out of range is refused and changes nothing.
    assert!(changed.set("start.tcg_multiplier", "0").is_err());
    assert!(changed.set("start.boot_wait_secs", "601").is_err());
    assert_eq!(changed.start().tcg_multiplier, 25);
    // The network wait defaults to 30 s, can be turned off, and is bounded.
    assert_eq!(changed.start().network_wait_secs, 30);
    changed.set("start.network_wait_secs", "0").unwrap();
    assert_eq!(changed.start().network_wait_secs, 0);
    assert!(changed.set("start.network_wait_secs", "601").is_err());
    // A partial section reads the rest as defaults; the options take it.
    let dir = scratch("start");
    std::fs::write(path(&dir), r#"{"start": {"boot_wait_secs": 90}}"#).unwrap();
    let loaded = load(&dir).unwrap().unwrap();
    assert_eq!(loaded.start().boot_wait_secs, 90);
    assert_eq!(loaded.start().tcg_multiplier, 10);
    let mut options = crate::BackendOptions::default();
    loaded.apply_to(&mut options);
    assert_eq!(options.start.boot_wait_secs, 90);
    std::fs::write(path(&dir), r#"{"start": {"tcg_multiplier": 500}}"#).unwrap();
    assert!(load(&dir).unwrap_err().contains("TCG multiplier"));
}
