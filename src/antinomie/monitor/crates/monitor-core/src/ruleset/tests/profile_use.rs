// SPDX-License-Identifier: GPL-3.0-only
//! A static job reads its rule profile in place and pruning respects it (ANT-T0618, AN-04).
use super::*;
use std::time::{Duration, SystemTime};

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ant-profile-use-{name}-{}",
        crate::storage::unique_id()
    ))
}

fn install_sample(dir: &Path) {
    let bytes = archive(&[("one.yar", "rule Real { condition: true }\n")]);
    let mut pack = entry("unused", 0);
    pack.sha256 = crate::storage::sha256_hex(&bytes);
    pack.size = bytes.len() as u64;
    install_archive(dir, &pack, &bytes).unwrap();
}

/// A complete profile folder as an old selection left it, last used `age` ago.
fn old_profile(dir: &Path, name: &str, age: Duration) -> PathBuf {
    let path = rules_root(dir).join("profiles/yara").join(name);
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("manifest.json"), "{}").unwrap();
    let complete = fs::File::create(path.join(".complete")).unwrap();
    complete.set_modified(SystemTime::now() - age).unwrap();
    path
}

#[test]
fn a_static_job_marks_the_profile_and_the_marker_ends_with_the_job() {
    let dir = temp("mark");
    install_sample(&dir);
    let job = dir.join("runs/r1/analyses/a1");
    fs::create_dir_all(&job).unwrap();
    let used = use_static_profile(&dir, &job).unwrap().expect("a profile");
    assert!(used.directory().join(".complete").is_file());
    assert!(used.directory().join("manifest.json").is_file());
    // Nothing was copied into the job folder.
    assert!(!job.join("rules").exists());
    let markers = used.directory().parent().unwrap().join(".in-use");
    assert_eq!(fs::read_dir(&markers).unwrap().count(), 1);
    // A second job on the same profile has its own marker.
    let other = use_static_profile(&dir, &job).unwrap().unwrap();
    assert_eq!(other.digest(), used.digest());
    assert_eq!(fs::read_dir(&markers).unwrap().count(), 2);
    drop(used);
    assert_eq!(fs::read_dir(&markers).unwrap().count(), 1);
    drop(other);
    assert_eq!(fs::read_dir(&markers).unwrap().count(), 0);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn no_enabled_rule_means_no_profile_to_mount() {
    let dir = temp("none");
    fs::create_dir_all(rules_root(&dir)).unwrap();
    fs::write(
        rules_root(&dir).join("registry.json"),
        r#"{"schema":1,"packs":[],"groups":[],"disabled":{}}"#,
    )
    .unwrap();
    assert!(use_static_profile(&dir, &dir).unwrap().is_none());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn pruning_keeps_the_newest_the_recent_and_every_profile_a_job_uses() {
    let dir = temp("prune");
    let day = Duration::from_secs(24 * 3600);
    // Four newest are kept whatever their age; then: old and unused (goes),
    // old and used by this live process (stays), old with a dead owner (goes),
    // young (stays).
    let mut keep = Vec::new();
    for index in 0..4u64 {
        keep.push(old_profile(
            &dir,
            &format!("new{index}"),
            day * (10 + index as u32),
        ));
    }
    let used = old_profile(&dir, "used", day * 30);
    let orphan = old_profile(&dir, "orphan", day * 31);
    let unused = old_profile(&dir, "unused", day * 32);
    let markers = rules_root(&dir).join("profiles/yara/.in-use");
    fs::create_dir_all(&markers).unwrap();
    fs::write(
        markers.join("used.1"),
        format!("{} job\n", std::process::id()),
    )
    .unwrap();
    fs::write(markers.join("orphan.1"), "4294967 job\n").unwrap();
    let removed = prune_profiles(&dir, "yara").unwrap();
    assert_eq!(removed, 2);
    assert!(keep.iter().all(|path| path.is_dir()));
    assert!(used.is_dir());
    assert!(!orphan.is_dir());
    assert!(!unused.is_dir());
    // The marker of a dead owner was swept; the live one stayed.
    assert!(markers.join("used.1").is_file());
    assert!(!markers.join("orphan.1").exists());
    // A profile used in the last day stays, and counts among the newest four:
    // the oldest of the kept ones is now the fifth and goes.
    let young = old_profile(&dir, "young", Duration::from_secs(60));
    assert_eq!(prune_profiles(&dir, "yara").unwrap(), 1);
    assert!(young.is_dir() && used.is_dir());
    assert!(!keep[3].is_dir() && keep[2].is_dir());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_yara_profile_needs_no_sigma_or_suricata_probe() {
    let dir = temp("facts");
    install_sample(&dir);
    let missing = ToolConfig::from_sigma_setting(dir.join("no-python").to_str().unwrap());
    let facts = tool_facts_for("yara", &missing);
    assert!(matches!(facts.sigma, ToolProbe::Unknown(_)));
    assert!(matches!(facts.suricata, ToolProbe::Unknown(_)));
    // The digest does not depend on the tools the engine does not use.
    let registry = load_registry(&dir).unwrap();
    assert_eq!(
        selection_digest_of(&dir, &registry, "yara", &facts),
        selection_digest_of(&dir, &registry, "yara", &tool_facts(&ToolConfig::default()))
    );
    let _ = fs::remove_dir_all(&dir);
}
