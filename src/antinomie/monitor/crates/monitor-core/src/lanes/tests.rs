// SPDX-License-Identifier: GPL-3.0-only
//! Lane folders: path resolution, the start checks and the shared writers'
//! refusals (ANT-T0455 card B). The engines themselves: `engine_tests.rs`.
use super::*;
use crate::data_owner::{OwnerClaim, OwnerKind};
use std::sync::atomic::AtomicBool;

pub(super) struct Tree {
    pub root: PathBuf,
    /// Lane 1's data folder, canonical.
    pub shared: PathBuf,
}

impl Tree {
    pub fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("ant-lanes-{name}-{}", crate::storage::unique_id()));
        let shared = root.join("data");
        crate::storage::private_dir(&shared).unwrap();
        let shared = fs::canonicalize(shared).unwrap();
        Self { root, shared }
    }

    /// Lane `n`'s folder with its record, as its engine leaves it.
    pub fn lane(&self, n: u32) -> PathBuf {
        let dir = lane_dir(&self.shared, n);
        crate::storage::private_dir(&dir).unwrap();
        write_marker(&dir, &LaneMarker { schema: 1, lane: n }).unwrap();
        dir
    }

    pub fn options(&self, lane: Option<u32>) -> BackendOptions {
        let data_dir = lane.map_or(self.shared.clone(), |n| lane_dir(&self.shared, n));
        BackendOptions {
            bundle_dir: self.root.join("missing-build"),
            shared_root: lane.map(|_| self.shared.clone()),
            owner: OwnerClaim {
                kind: OwnerKind::Daemon,
                socket: None,
                lane,
            },
            data_dir,
            ..BackendOptions::default()
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn refused(result: Result<impl std::fmt::Debug, String>) -> String {
    let error = result.unwrap_err();
    assert!(is_refusal(&error), "{error}");
    error
}

#[test]
fn a_plain_folder_keeps_its_own_shared_folders() {
    let tree = Tree::new("plain");
    let data = &tree.shared;
    assert_eq!(lane_of(data).unwrap(), None);
    assert_eq!(shared_root(data), *data);
    assert_eq!(crate::samples::samples_dir(data), data.join("samples"));
    assert_eq!(crate::ruleset::rules_root(data), data.join("rules"));
    assert_eq!(crate::analysis_tools::tools_dir(data), data.join("tools"));
    assert_eq!(crate::ioc::feeds::root(data), data.join("ioc"));
    assert_eq!(bases_dir(data), data.join("bases"));
    assert_eq!(
        crate::memory::plugins_dir(data),
        data.join("volatility-plugins")
    );
    assert!(lanes(data).is_empty() && !has_lanes(data));
    refuse_in_lane(data, SharedWrite::RuleUpdate).unwrap();
}

#[test]
fn a_lane_folder_resolves_every_shared_folder_into_lane_1s() {
    let tree = Tree::new("resolve");
    let lane = tree.lane(3);
    let data = &tree.shared;
    assert_eq!(
        lane_of(&lane).unwrap(),
        Some(Lane {
            lane: 3,
            shared_root: data.clone(),
            data_dir: lane.clone(),
        })
    );
    assert_eq!(crate::samples::samples_dir(&lane), data.join("samples"));
    assert_eq!(crate::ruleset::rules_root(&lane), data.join("rules"));
    assert_eq!(crate::analysis_tools::tools_dir(&lane), data.join("tools"));
    assert_eq!(crate::ioc::feeds::root(&lane), data.join("ioc"));
    assert_eq!(bases_dir(&lane), data.join("bases"));
    assert_eq!(
        crate::memory::plugins_dir(&lane),
        data.join("volatility-plugins")
    );
    // A spelling with `..` and a trailing `.` resolves the same.
    let spelled = data.join("lanes/3/../3/.");
    assert_eq!(shared_root(&spelled), *data);
    // Lane 1 sees its lanes.
    tree.lane(2);
    let found: Vec<u32> = lanes(data).iter().map(|lane| lane.lane).collect();
    assert_eq!(found, [2, 3]);
    assert!(has_lanes(data) && has_lanes(&lane));
}

#[test]
fn a_moved_tree_keeps_its_lanes_pointing_at_the_moved_lane_1() {
    let tree = Tree::new("moved");
    tree.lane(2);
    let moved = tree.root.join("elsewhere");
    fs::rename(&tree.shared, &moved).unwrap();
    let moved = fs::canonicalize(moved).unwrap();
    assert_eq!(shared_root(&moved.join("lanes/2")), moved);
    assert_eq!(
        crate::samples::samples_dir(&moved.join("lanes/2")),
        moved.join("samples")
    );
}

#[test]
fn a_record_out_of_place_or_unreadable_is_an_error_and_still_refuses_writes() {
    let tree = Tree::new("bad-record");
    // Lane 4's record in folder 5.
    let wrong = lane_dir(&tree.shared, 5);
    crate::storage::private_dir(&wrong).unwrap();
    crate::storage::atomic_json(&wrong.join(MARKER_FILE), &LaneMarker { schema: 1, lane: 4 })
        .unwrap();
    assert!(lane_of(&wrong).unwrap_err().contains("lane 4"));
    // Not under `lanes/` at all.
    let stray = tree.root.join("stray");
    crate::storage::private_dir(&stray).unwrap();
    crate::storage::atomic_json(&stray.join(MARKER_FILE), &LaneMarker { schema: 1, lane: 2 })
        .unwrap();
    assert!(lane_of(&stray).is_err());
    let garbage = tree.lane(6);
    fs::write(garbage.join(MARKER_FILE), b"{not json").unwrap();
    assert!(lane_of(&garbage).is_err());
    // An unreadable record resolves nowhere new, but it is still a lane:
    // writers refuse it, and a caller that must not miss a lane fails.
    assert_eq!(shared_root(&garbage), garbage);
    let error = refused(refuse_in_lane(&garbage, SharedWrite::FeedUpdate));
    assert!(error.contains("in a lane data folder"), "{error}");
    assert!(lanes_checked(&tree.shared).is_err());
    assert!(lanes(&tree.shared).is_empty());
}

#[test]
fn the_start_check_matches_lane_root_and_folder() {
    let tree = Tree::new("start");
    // A plain engine on a plain folder, and a lane engine on its own folder.
    assert_eq!(check_start(&tree.options(None)).unwrap(), None);
    let lane = tree.options(Some(2));
    crate::storage::private_dir(&lane.data_dir).unwrap();
    assert_eq!(
        check_start(&lane).unwrap(),
        Some(LaneMarker { schema: 1, lane: 2 })
    );
    // A lane without the root, a root without a lane, lane 0, lane 1 (the
    // data folder itself), a lane too high.
    let mut options = tree.options(Some(2));
    options.shared_root = None;
    assert!(
        check_start(&options)
            .unwrap_err()
            .contains("needs the shared root")
    );
    let mut options = tree.options(Some(2));
    options.owner.lane = None;
    assert!(check_start(&options).unwrap_err().contains("names no lane"));
    let mut options = tree.options(Some(2));
    options.owner.lane = Some(0);
    assert!(check_start(&options).is_err());
    options.owner.lane = Some(1);
    assert!(check_start(&options).unwrap_err().contains("between 2 and"));
    options.owner.lane = Some(MAX_LANE + 1);
    assert!(check_start(&options).is_err());
    // Lane 3 on lane 2's folder.
    let mut options = tree.options(Some(2));
    options.owner.lane = Some(3);
    assert!(check_start(&options).unwrap_err().contains("must be"));
    // Lane 2's folder once its record is written: a plain engine (the
    // window) is sent to lane 1, and lane 3 cannot take it.
    tree.lane(2);
    let mut plain = tree.options(Some(2));
    plain.owner.lane = None;
    plain.shared_root = None;
    let error = check_start(&plain).unwrap_err();
    assert!(
        error.contains("lane 2") && error.contains("open"),
        "{error}"
    );
    fs::rename(lane_dir(&tree.shared, 2), lane_dir(&tree.shared, 3)).unwrap();
    assert!(lane_of(&lane_dir(&tree.shared, 3)).is_err());
    // A root that is itself a lane.
    let nested = tree.lane(4);
    let mut options = tree.options(Some(2));
    options.shared_root = Some(nested);
    assert!(check_start(&options).unwrap_err().contains("itself a lane"));
}

#[test]
fn the_rule_feed_tool_geoip_and_base_writers_refuse_a_lane_folder() {
    let tree = Tree::new("writers");
    let lane = tree.lane(2);
    let cancel = AtomicBool::new(false);
    refused(crate::ruleset::set_pack_enabled(&lane, "pack", false));
    refused(crate::ruleset::set_group_enabled(&lane, "group", false));
    refused(crate::ruleset::delete_group(&lane, "group", true));
    refused(crate::ruleset::remove_pack(&lane, "pack"));
    refused(crate::ruleset::rollback(&lane, "pack", "1"));
    refused(crate::ruleset::rename_group(&lane, "group", "name"));
    refused(crate::strings_regex::Config::default().save(&lane));
    refused(crate::ioc::feeds::set_enabled(&lane, "feodo", false));
    refused(crate::analysis_tools::install(
        Path::new("/nonexistent/curl"),
        &lane,
        "capa",
        &cancel,
        |_, _, _| {},
    ));
    refused(crate::analysis_tools::remove(&lane, "capa"));
    refused(crate::geoip::update_latest(
        Path::new("/nonexistent/curl"),
        &lane,
        "2026-10",
        &cancel,
        |_, _, _| {},
    ));
    // Nothing was written into lane 1's folders or the lane's.
    for folder in ["rules", "ioc", "tools"] {
        assert!(!tree.shared.join(folder).exists(), "{folder}");
        assert!(!lane.join(folder).exists(), "{folder}");
    }
    let fp = |dir: &Path| {
        crate::known_fp::add(
            dir,
            crate::ioc::Kind::Domain,
            "pool.ntp.example",
            None,
            "Time.",
            1,
        )
    };
    refused(fp(&lane));
    // Lane 1 itself is the writer, and the lane reads what it wrote.
    crate::ioc::feeds::set_enabled(&tree.shared, "feodo", false).unwrap();
    fp(&tree.shared).unwrap();
    assert_eq!(crate::known_fp::load(&lane).len(), 1);
    // A lane reads the rules and leaves their upkeep to lane 1.
    assert_eq!(
        crate::ruleset::migrate_indexes(&lane).unwrap(),
        Default::default()
    );
    assert_eq!(
        crate::ruleset::reap_staging(&lane, std::time::Duration::ZERO).unwrap(),
        0
    );
    // The lane reads lane 1's feed settings.
    let feodo = crate::ioc::feeds::status(&lane)
        .into_iter()
        .find(|status| status.feed.id == "feodo")
        .unwrap();
    assert!(!feodo.enabled);
}

#[test]
fn a_refusal_names_the_action_and_the_lane() {
    let text = LaneRefusal {
        lane: Some(2),
        action: SharedWrite::DeleteBase,
    }
    .to_string();
    assert_eq!(
        text,
        format!("deleting a base is refused on lane 2: {SHARED_WRITER}")
    );
    assert!(is_refusal(&text) && !is_refusal("base is used by 1 VM(s): a"));
}

#[test]
fn a_folder_with_lanes_is_not_migrated() {
    let tree = Tree::new("migrate");
    fs::write(tree.shared.join("settings.json"), b"{}").unwrap();
    tree.lane(2);
    let destination = tree.root.join("new");
    let error = crate::storage::migrate_data(&tree.shared, &destination).unwrap_err();
    assert!(error.contains("lanes"), "{error}");
    let error = crate::storage::migrate_data(&lane_dir(&tree.shared, 2), &destination).unwrap_err();
    assert!(error.contains("lanes"), "{error}");
    assert!(!destination.exists());
}

#[test]
fn a_lane_reads_lane_1s_engine_and_route_settings_and_never_writes_them() {
    let tree = Tree::new("settings");
    let lane = tree.lane(3);
    assert_eq!(
        crate::settings::path(&lane),
        tree.shared.join(crate::settings::FILE)
    );
    let mut settings = crate::settings::EngineSettings::default();
    settings.quota_gib = 7;
    crate::storage::atomic_json(&tree.shared.join(crate::settings::FILE), &settings).unwrap();
    assert_eq!(crate::settings::load(&lane).unwrap().unwrap().quota_gib, 7);
    refused(crate::settings::save(&lane, &settings));
    let routes = crate::route::RouteConfig {
        allow_lan: true,
        ..Default::default()
    };
    crate::storage::private_dir(&tree.shared.join("network")).unwrap();
    crate::storage::atomic_json(&tree.shared.join("network").join("routes.json"), &routes).unwrap();
    assert_eq!(crate::route::load_config(&lane).unwrap(), routes);
    refused(crate::route::save_config(&lane, &routes));
    assert!(!lane.join("settings.json").exists() && !lane.join("network").exists());
}

#[test]
fn the_base_lock_is_lane_1s_and_one_holder_at_a_time() {
    let tree = Tree::new("base-lock");
    let lane = tree.lane(2);
    let held = base_lock(&lane, std::time::Duration::ZERO)
        .unwrap()
        .expect("free");
    assert!(tree.shared.join("run").join(BASE_LOCK_FILE).is_file());
    assert!(
        base_lock(&tree.shared, std::time::Duration::from_millis(50))
            .unwrap()
            .is_none(),
        "lane 1 waits for the lane's holder"
    );
    drop(held);
    assert!(
        base_lock(&tree.shared, std::time::Duration::ZERO)
            .unwrap()
            .is_some()
    );
}
