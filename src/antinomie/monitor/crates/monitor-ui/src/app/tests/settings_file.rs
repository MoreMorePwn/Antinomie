// SPDX-License-Identifier: GPL-3.0-only
//! The migration of the window's stored settings into `<data>/settings.json`.
use super::*;
use crate::app::settings_file::SettingsFile;
use antinomie_monitor_core::{
    data_owner,
    settings::{self, AddressLookup},
};

fn scratch(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ant-ui-settings-{name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// What a user who changed every shared setting has stored in eframe.
fn customised() -> Settings {
    let mut settings = Settings {
        bundle: "/srv/bases".into(),
        quota_gib: 40,
        core_budget_mib: 512,
        analysis_time_limit_minutes: 7,
        file_write_file_mib: 11,
        file_write_run_mib: 22,
        file_before_file_mib: 33,
        file_before_run_mib: 44,
        timeout: 45,
        memory_online_symbols: false,
        sample_hash_lookup: true,
        automatic_detection: false,
        outbound_catalog: true,
        address_lookup: AddressLookup::TsharkThenWhois,
        ..Settings::default()
    };
    settings.triage_detection.sigma_python = "/opt/py/bin/python".into();
    settings.triage_detection.yara_rules = "/rules/yara".into();
    settings.triage_detection.scan_memory = true;
    settings.analysis_limits.rows = 123;
    settings.disks.hide_dotfiles = true;
    settings.disks.extract_cap_mib = 17;
    settings.report_export.formats.clear();
    settings
}

#[test]
fn the_first_start_writes_every_stored_shared_value_into_the_file() {
    let dir = scratch("migrate");
    // The stored copy goes through eframe's JSON, as it does on disk.
    let stored = serde_json::to_string(&customised()).unwrap();
    let mut settings: Settings = serde_json::from_str(&stored).unwrap();
    let mut file = SettingsFile::open(&dir, &mut settings);
    assert!(file.error.is_none());
    assert!(!settings::path(&dir).exists());
    // Without the lock nothing is written.
    assert_eq!(file.persist(&dir, &settings), None);
    assert!(!settings::path(&dir).exists());
    let _lock = data_owner::lock_data_dir(&dir, &Default::default()).unwrap();
    assert_eq!(file.persist(&dir, &settings), None);
    let written = settings::load(&dir).unwrap().unwrap();
    let expected = customised().engine();
    assert_eq!(written, expected);
    assert_eq!(written.quota_gib, 40);
    assert_eq!(written.shutdown_timeout_s, 45);
    assert_eq!(written.bundle, "/srv/bases");
    assert!(written.triage_detection.scan_memory);
    assert_eq!(written.triage_detection.sigma_python, "/opt/py/bin/python");
    assert_eq!(written.address_lookup, AddressLookup::TsharkThenWhois);
    assert!(!written.memory_online_symbols);
    assert!(written.sample_hash_lookup);
    assert!(written.disks.hide_dotfiles && written.disks.extract_cap_mib == 17);
}

#[test]
fn a_settings_blob_from_before_any_of_this_migrates_with_defaults_for_what_it_lacks() {
    let dir = scratch("old");
    let mut settings: Settings =
        serde_json::from_str(r#"{"quota_gib": 9, "timeout": 30, "font_size": 16.0}"#).unwrap();
    let mut file = SettingsFile::open(&dir, &mut settings);
    let _lock = data_owner::lock_data_dir(&dir, &Default::default()).unwrap();
    assert_eq!(file.persist(&dir, &settings), None);
    let written = settings::load(&dir).unwrap().unwrap();
    assert_eq!(written.quota_gib, 9);
    assert_eq!(written.shutdown_timeout_s, 30);
    assert_eq!(
        written.core_budget_mib,
        settings::EngineSettings::default().core_budget_mib
    );
    assert!(written.memory_online_symbols);
    assert!(
        !written.sample_hash_lookup,
        "off unless the user turns it on"
    );
}

#[test]
fn once_the_file_exists_it_wins_and_the_window_writes_changes_back() {
    let dir = scratch("wins");
    let _lock = data_owner::lock_data_dir(&dir, &Default::default()).unwrap();
    std::fs::write(
        settings::path(&dir),
        r#"{"quota_gib": 77, "from_the_future": true}"#,
    )
    .unwrap();
    let mut settings = customised();
    let mut file = SettingsFile::open(&dir, &mut settings);
    assert_eq!(settings.quota_gib, 77);
    // The file did not say: its default, not the stored value.
    assert_eq!(settings.timeout, 10);
    assert_eq!(file.persist(&dir, &settings), None);
    settings.automatic_detection = false;
    settings.quota_gib = 78;
    assert_eq!(file.persist(&dir, &settings), None);
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(settings::path(&dir)).unwrap()).unwrap();
    assert_eq!(value["quota_gib"], 78);
    assert_eq!(value["automatic_detection"], false);
    assert_eq!(value["from_the_future"], true);
}

#[test]
fn a_corrupt_file_is_reported_and_never_replaced() {
    let dir = scratch("corrupt");
    std::fs::write(settings::path(&dir), "{ broken").unwrap();
    let _lock = data_owner::lock_data_dir(&dir, &Default::default()).unwrap();
    let mut settings = customised();
    let mut file = SettingsFile::open(&dir, &mut settings);
    assert!(file.error.as_deref().unwrap().contains("settings.json"));
    // The window keeps its own copy for the session.
    assert_eq!(settings.quota_gib, 40);
    settings.quota_gib = 41;
    assert_eq!(file.persist(&dir, &settings), None);
    assert_eq!(std::fs::read(settings::path(&dir)).unwrap(), b"{ broken");
}

#[test]
fn the_start_waits_are_shared_and_a_file_without_them_keeps_the_windows() {
    let dir = scratch("start");
    let _lock = data_owner::lock_data_dir(&dir, &Default::default()).unwrap();
    // A file written before the start waits were shared: the window's own
    // stay, and the next write adds them.
    std::fs::write(settings::path(&dir), r#"{"quota_gib": 5}"#).unwrap();
    let mut settings = customised();
    settings.start.tcg_multiplier = 30;
    settings.start.boot_wait_secs = 200;
    let mut file = SettingsFile::open(&dir, &mut settings);
    assert_eq!(settings.start.tcg_multiplier, 30);
    assert_eq!(file.persist(&dir, &settings), None);
    let written = settings::load(&dir).unwrap().unwrap();
    assert_eq!(written.start().tcg_multiplier, 30);
    assert_eq!(written.start().boot_wait_secs, 200);
    // A file that has them (`antinomie-cli config set start.…`) wins.
    std::fs::write(
        settings::path(&dir),
        r#"{"start": {"tcg_multiplier": 12, "boot_wait_secs": 90}}"#,
    )
    .unwrap();
    let mut settings = customised();
    SettingsFile::open(&dir, &mut settings);
    assert_eq!(settings.start.tcg_multiplier, 12);
    assert_eq!(settings.start.boot_wait_secs, 90);
}
