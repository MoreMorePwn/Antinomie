// SPDX-License-Identifier: GPL-3.0-only
//! `service.toml`, the presets (built in and `presets/*.toml`) and their
//! validation (card P3-3, presets of ANT-T0490): the format, unknown keys,
//! the node ceilings, the keys 0.9.0 reserves, the lanes of `service.toml`
//! against the lane VM, and the refusal of a 0.9.0 `policies/` folder.

// `ApiError` is the contract's error type (large by design, see the crate root).
#![allow(clippy::result_large_err)]

use antinomie_service::config::{
    NoVms, PresetLookup, PresetSet, Severity, SharedPresets, VmCatalog, VmFacts, VmNet,
    builtin::{BUILT_IN, STANDARD},
    preset::{Preset, User},
    validate::{self, parse_preset, parse_service},
};
use std::{fs, path::PathBuf};

struct Vms(Vec<VmFacts>);

impl VmCatalog for Vms {
    fn find(&self, name: &str) -> Option<VmFacts> {
        self.0.iter().find(|vm| vm.name == name).cloned()
    }
}

fn lane(network: VmNet, snapshots: &[&str]) -> Vms {
    Vms(vec![VmFacts {
        id: "vm-1".into(),
        name: "auto-1".into(),
        network,
        ram_mib: 2048,
        base_identity: None,
        stealth: None,
        snapshots: snapshots.iter().map(|s| s.to_string()).collect(),
        disk_snapshots: Vec::new(),
    }])
}

/// The errors of a preset file `presets/p.toml`.
fn problems(text: &str) -> Vec<String> {
    let (_, problems) = parse_preset("p", "presets/p.toml", text);
    problems
        .iter()
        .filter(|p| p.severity == Severity::Error)
        .map(|p| p.to_string())
        .collect()
}

fn with(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "{from} is not in the text");
    text.replacen(from, to, 1)
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-svc-config-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("presets")).unwrap();
    root
}

/// The errors of `load` on a data folder with this `service.toml`.
fn lane_problems(service: &str, catalog: &dyn VmCatalog) -> Vec<String> {
    let root = scratch(&format!("lanes-{}", service.len()));
    fs::write(root.join("service.toml"), service).unwrap();
    let report = validate::load(&root, catalog, None);
    let _ = fs::remove_dir_all(&root);
    report
        .problems
        .iter()
        .filter(|p| p.severity == Severity::Error)
        .map(|p| p.to_string())
        .collect()
}

#[test]
fn the_five_built_in_presets_parse_and_pass_every_check() {
    let names: Vec<&str> = BUILT_IN.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "standard",
            "quick-look",
            "deep",
            "interactive",
            "live-network"
        ]
    );
    let set = PresetSet::built_in();
    assert_eq!(set.len(), 5);
    for (name, text) in BUILT_IN {
        // As a file under another name, each passes every check but the
        // live route (no route is set up on this node).
        let (loaded, found) = parse_preset("copy", "presets/copy.toml", text);
        let errors: Vec<String> = found
            .iter()
            .filter(|p| p.severity == Severity::Error)
            .map(|p| p.to_string())
            .collect();
        if name == "live-network" {
            assert_eq!(errors.len(), 1, "{errors:?}");
            assert!(errors[0].contains("route tor is not set up on this node"));
        } else {
            assert!(errors.is_empty(), "{name}: {errors:?}");
        }
        assert!(
            found.iter().all(|p| p.severity == Severity::Error),
            "{name} warns: {found:?}"
        );
        let built = set.get(name).unwrap();
        assert!(built.built_in);
        assert_eq!(built.preset, loaded.unwrap().preset);
        assert!(validate::reserved(&built.preset).is_empty(), "{name}");
    }
    // Standard is every default, written out.
    assert_eq!(
        set.get("standard").unwrap().preset,
        Preset {
            title: "Standard".into(),
            description: "Five minutes, nothing leaves the lab, HTML and JSON report".into(),
            ..Preset::default()
        }
    );
}

#[test]
fn the_built_in_presets_hold_the_values_of_the_specification() {
    use antinomie_service::api::spec::{ReportFormat, Route, StaticCheck};
    use antinomie_service::config::preset::TRIAGE_CHECKS;
    let set = PresetSet::built_in();
    let get = |name: &str| set.get(name).unwrap().preset.clone();
    let (standard, quick, deep, interactive, live) = (
        get("standard"),
        get("quick-look"),
        get("deep"),
        get("interactive"),
        get("live-network"),
    );
    let run_times: Vec<u32> = [&standard, &quick, &deep, &interactive, &live]
        .iter()
        .map(|p| p.program.run_time_s)
        .collect();
    assert_eq!(run_times, [300, 120, 900, 600, 600]);
    let routes: Vec<Route> = [&standard, &quick, &deep, &interactive, &live]
        .iter()
        .map(|p| p.network.route.clone())
        .collect();
    assert_eq!(
        routes,
        [
            Route::Drop,
            Route::Drop,
            Route::InetSim,
            Route::Drop,
            Route::Tor
        ]
    );
    assert!(
        [&standard, &quick, &deep, &interactive, &live]
            .iter()
            .all(|p| p.network.capture)
    );
    // Static analysis.
    assert_eq!(standard.static_analysis.checks(), TRIAGE_CHECKS);
    assert_eq!(
        quick.static_analysis.checks(),
        [
            StaticCheck::Metadata,
            StaticCheck::Strings,
            StaticCheck::Hardening,
            StaticCheck::Rules,
            StaticCheck::Identification
        ]
    );
    assert_eq!(deep.static_analysis.checks().len(), 14);
    // Detection: YARA, Sigma, IDS / YARA / all / YARA, Sigma / YARA, IDS.
    let engines = |p: &Preset| (p.detection.yara, p.detection.sigma, p.detection.ids);
    assert_eq!(engines(&standard), (true, true, true));
    assert_eq!(engines(&quick), (true, false, false));
    assert_eq!(engines(&deep), (true, true, true));
    assert_eq!(engines(&interactive), (true, true, false));
    assert_eq!(engines(&live), (true, false, true));
    // Deep: the dumps and the report.
    assert!(deep.dumps.core_dump_on_exit && deep.dumps.dump_when_suspicious);
    let trigger = deep.dumps.trigger().unwrap();
    assert!(trigger.memory && trigger.core);
    assert_eq!(
        trigger.min_tier,
        antinomie_monitor_core::dump_trigger::TriggerTier::Medium
    );
    assert_eq!(
        deep.report.formats,
        [ReportFormat::Html, ReportFormat::Json, ReportFormat::Pdf]
    );
    assert!(deep.report.bundle);
    // Allow taking control: off for Quick look only.
    assert!(!quick.vm.allow_control);
    assert!(standard.vm.allow_control && deep.vm.allow_control);
    assert!(interactive.vm.allow_control && live.vm.allow_control);
}

#[test]
fn the_listing_names_what_each_built_in_preset_needs() {
    use antinomie_service::api::ops::{Caller, Permission};
    let set = PresetSet::built_in();
    let plain = Caller::new("local:1", &[Permission::RunsSubmit]);
    let listed = set.list_for(&plain);
    let find = |name: &str| listed.iter().find(|p| p.name == name).unwrap();
    assert!(find("standard").needs.is_empty());
    assert!(find("quick-look").needs.is_empty());
    assert_eq!(
        find("deep").needs,
        [Permission::EvidenceCoreDump, Permission::EvidenceMemoryDump]
    );
    assert_eq!(find("deep").missing, find("deep").needs);
    assert_eq!(find("live-network").needs, [Permission::RouteTor]);
    assert_eq!(
        find("live-network").unavailable,
        ["route tor is not set up on this node; live routes arrive with 0.9.1"]
    );
    assert_eq!(find("standard").title, "Standard");
    assert!(find("standard").built_in);
    let owner = Caller::with_every_permission("local:0");
    assert!(set.list_for(&owner).iter().all(|p| p.missing.is_empty()));
}

#[test]
fn an_empty_preset_is_standard_and_valid() {
    assert_eq!(problems(""), Vec::<String>::new());
    let (loaded, _) = parse_preset("p", "presets/p.toml", "");
    assert_eq!(loaded.unwrap().preset, Preset::default());
}

#[test]
fn unknown_keys_are_errors_with_a_line_number() {
    let text = with(STANDARD, "[report]\n", "[report]\nformats_typo = 1\n");
    let found = problems(&text);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("unknown field `formats_typo`"),
        "{found:?}"
    );
    assert!(found[0].starts_with("presets/p.toml:"), "{found:?}");
    let line = text
        .lines()
        .position(|l| l.starts_with("formats_typo"))
        .unwrap()
        + 1;
    assert!(
        found[0].contains(&format!(":{line}:")),
        "{found:?} line {line}"
    );
    // Also in a nested table and in service.toml.
    let found = problems("[static_analysis.limits]\nrows = 5\n");
    assert!(found[0].contains("unknown field `rows`"), "{found:?}");
    let (_, found) = parse_service("service.toml", "[daemon]\nlanes = 1\nthreads = 2\n");
    assert!(found[0].message.contains("unknown field `threads`"));
    assert_eq!(found[0].line, Some(3));
}

#[test]
fn a_0_9_0_policy_key_in_a_preset_names_its_new_home() {
    let found = problems(
        "[run]\ntimeout_s = 60\nallow_root = true\n[network]\nallowed_routes = [\"drop\"]\n",
    );
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(
        found.iter().any(|f| f.contains("presets/p.toml:2:")
            && f.contains("run.timeout_s")
            && f.contains("`program.run_time_s`")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("the permission `run.as_root`"))
    );
    assert!(found.iter().any(|f| f.contains("network.allowed_routes")));
    let found = problems("[vm]\nrevert_after = true\n");
    assert!(found[0].contains("never acted on"), "{found:?}");
}

#[test]
fn the_node_ceilings_and_ranges_are_enforced() {
    for (text, key) in [
        ("[program]\nrun_time_s = 4\n", "program.run_time_s"),
        ("[program]\nrun_time_s = 1801\n", "program.run_time_s"),
        (
            "[accepts]\nmax_sample_mib = 257\n",
            "accepts.max_sample_mib",
        ),
        ("[accepts]\nmax_sample_mib = 0\n", "accepts.max_sample_mib"),
        ("[accepts]\ntypes = [\"pdf\"]\n", "accepts.types"),
        ("[accepts]\narch = []\n", "accepts.arch"),
        (
            "[program]\nworking_directory = \"tmp\"\n",
            "program.working_directory",
        ),
        ("[program]\nguest_path = \"/tmp/\"\n", "program.guest_path"),
        ("[program]\nenvironment = [\"=x\"]\n", "program.environment"),
        ("[dumps]\ncore_budget_mib = 32\n", "dumps.core_budget_mib"),
        ("[dumps]\ncore_budget_mib = 1025\n", "dumps.core_budget_mib"),
        ("[dumps]\ncore_deadline_ms = 0\n", "dumps.core_deadline_ms"),
        ("[dumps]\nmax_dumps = 9\n", "dumps.max_dumps"),
        ("[dumps]\ndumps_apart_s = 3601\n", "dumps.dumps_apart_s"),
        (
            "[dumps]\ndump_when_suspicious = true\ntrigger_core = false\n",
            "dumps.dump_when_suspicious",
        ),
        (
            "[static_analysis]\ntime_limit_per_tool_min = 481\n",
            "static_analysis.time_limit_per_tool_min",
        ),
        (
            "[static_analysis]\ntriage_checks = [\"floss\"]\n",
            "static_analysis.triage_checks",
        ),
        (
            "[static_analysis]\ndeep_checks = [\"strings\"]\n",
            "static_analysis.deep_checks",
        ),
        (
            "[static_analysis.limits]\nrows_per_check = 10\n",
            "static_analysis.limits.rows_per_check",
        ),
        (
            "[static_analysis.limits]\nfloss_largest_file_mib = 65\n",
            "static_analysis.limits.floss_largest_file_mib",
        ),
        ("[vm]\nlane_group = \"a b\"\n", "vm.lane_group"),
        ("offered_to = [\"Lead\"]\n", "offered_to"),
        ("[retry]\nmax_attempts = 0\n", "retry.max_attempts"),
        ("[retry]\nmax_attempts = 11\n", "retry.max_attempts"),
        ("[retry]\nbackoff_s = [30, 3601]\n", "retry.backoff_s"),
        (
            "[retry]\nbackoff_s = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]\n",
            "retry.backoff_s",
        ),
    ] {
        let found = problems(text);
        assert_eq!(found.len(), 1, "{text}: {found:?}");
        assert!(found[0].contains(key), "{text}: {found:?}");
    }
    // The edges are accepted.
    for text in [
        "[program]\nrun_time_s = 5\n",
        "[program]\nrun_time_s = 1800\nuser = \"nobody\"\n",
        "[program]\nuser = \"custom\"\nuid = 0\ngid = 0\n",
        "[dumps]\ncore_budget_mib = 1024\nmax_dumps = 8\ndumps_apart_s = 0\n",
        "[static_analysis]\ntime_limit_per_tool_min = 480\nghidra_disassembly = true\n",
        "[accepts]\ntypes = [\"any\"]\narch = [\"any\"]\nmax_sample_mib = 256\n",
        "[retry]\nmax_attempts = 10\nbackoff_s = [0, 3600]\n",
    ] {
        assert_eq!(problems(text), Vec::<String>::new(), "{text}");
    }
    let (loaded, _) = parse_preset("p", "presets/p.toml", "[program]\nuser = \"nobody\"\n");
    assert_eq!(loaded.unwrap().preset.program.user, User::Nobody);
}

#[test]
fn reserved_keys_are_accepted_at_their_default_only() {
    // Every reserved key written at its default: Standard is valid.
    assert_eq!(problems(STANDARD), Vec::<String>::new());
    for (text, key) in [
        ("[program]\nsource = \"guest_path\"\n", "program.source"),
        (
            "[program]\nexecutable = \"/bin/ls\"\n",
            "program.executable",
        ),
        (
            "[program]\npreload = [{ sample = \"ab\", how = \"ld_preload\" }]\n",
            "program.preload",
        ),
        (
            "[program]\nextra_files = [{ sample = \"ab\", guest_path = \"/tmp/x\" }]\n",
            "program.extra_files",
        ),
        ("[program]\nrun_in = \"guest_desktop\"\n", "program.run_in"),
        ("[record]\nscope = \"whole_vm\"\n", "record.scope"),
        (
            "[record]\nscreenshot_every_s = 30\n",
            "record.screenshot_every_s",
        ),
        (
            "[network]\nprivate_addresses = true\n",
            "network.private_addresses",
        ),
        ("[network]\nabuse_filter = false\n", "network.abuse_filter"),
        ("[dumps]\ndisk_dump = true\n", "dumps.disk_dump"),
        (
            "[static_analysis]\nrebuilt_file_mib = 8\n",
            "static_analysis.rebuilt_file_mib",
        ),
        (
            "[static_analysis]\nrebuilt_run_mib = 8\n",
            "static_analysis.rebuilt_run_mib",
        ),
        (
            "[triage]\nwritten_per_file_mib = 8\n",
            "triage.written_per_file_mib",
        ),
        (
            "[triage]\nwritten_per_run_mib = 8\n",
            "triage.written_per_run_mib",
        ),
        (
            "[triage]\nearlier_per_file_mib = 8\n",
            "triage.earlier_per_file_mib",
        ),
        (
            "[triage]\nearlier_per_run_mib = 8\n",
            "triage.earlier_per_run_mib",
        ),
        (
            "[detection]\nscan_every_min = 2\n",
            "detection.scan_every_min",
        ),
        ("[report]\nsections = [\"summary\"]\n", "report.sections"),
        ("[vm]\nkeep_on_failure = true\n", "vm.keep_on_failure"),
    ] {
        let found = problems(text);
        assert_eq!(found.len(), 1, "{text}: {found:?}");
        assert!(found[0].contains(key), "{found:?}");
        assert!(found[0].contains("0.9.1"), "{found:?}");
    }
}

#[test]
fn a_live_route_is_not_set_up_on_this_node() {
    for route in ["internet", "nat", "tor", "vpn", "vpn:work", "socks5:p"] {
        let found = problems(&format!("[network]\nroute = \"{route}\"\n"));
        assert_eq!(found.len(), 1, "{route}: {found:?}");
        assert!(found[0].contains("not set up on this node"), "{found:?}");
        assert!(found[0].contains(route), "{found:?}");
    }
    assert_eq!(
        problems("[network]\nroute = \"inet_sim\"\n"),
        Vec::<String>::new()
    );
    let found = problems("[network]\nroute = \"carrier_pigeon\"\n");
    assert!(found[0].contains("unknown route"), "{found:?}");
}

#[test]
fn a_required_stage_the_preset_skips_is_an_error() {
    let skip_all = "[static_analysis]\nenabled = false\n[triage]\nenabled = false\n\
                    [detection]\nyara = false\nsigma = false\nids = false\n";
    let found = problems(skip_all);
    assert!(
        found
            .iter()
            .any(|f| f.contains("required but this preset skips it")),
        "{found:?}"
    );
    assert_eq!(
        problems(&format!("required_stages = []\n{skip_all}")),
        Vec::<String>::new()
    );
}

#[test]
fn preset_names_must_be_safe_and_not_built_in_or_custom() {
    for bad in ["", ".hidden", "UPPER", "a b", "a/b", "custom"] {
        assert!(!validate::valid_preset_name(bad), "{bad}");
    }
    assert!(validate::valid_preset_name("ci-fast_2.0"));
    let (_, found) = parse_preset("Bad Name", "presets/x.toml", "");
    assert!(
        found
            .iter()
            .any(|p| p.message.contains("not a valid preset name"))
    );
    let (_, found) = parse_preset("standard", "presets/standard.toml", STANDARD);
    assert!(
        found
            .iter()
            .any(|p| p.message.contains("built-in preset and read-only")),
        "{found:?}"
    );
}

#[test]
fn the_digest_is_the_sha256_of_the_file() {
    let (preset, _) = parse_preset("mine", "presets/mine.toml", STANDARD);
    let digest = preset.unwrap().digest;
    assert_eq!(digest.len(), 64);
    let again = parse_preset("mine", "presets/mine.toml", &format!("{STANDARD}\n"))
        .0
        .unwrap()
        .digest;
    assert_ne!(digest, again);
}

#[test]
fn the_dump_trigger_takes_a_tier_and_what_to_take() {
    use antinomie_monitor_core::dump_trigger::TriggerTier;
    let (loaded, _) = parse_preset(
        "p",
        "presets/p.toml",
        "[dumps]\ndump_when_suspicious = true\nminimum_tier = \"low\"\n\
         trigger_memory_dump = true\ntrigger_core = false\nread_non_resident_pages = true\n",
    );
    let dumps = loaded.unwrap().preset.dumps;
    let trigger = dumps.trigger().unwrap();
    assert_eq!(trigger.min_tier, TriggerTier::Low);
    assert!(trigger.memory && !trigger.core);
    let found = problems("[dumps]\nminimum_tier = \"extreme\"\n");
    assert!(found[0].contains("minimum_tier") || found[0].contains("unknown variant"));
    // Non-resident pages need a trigger core: a warning otherwise.
    let (_, found) = parse_preset(
        "p",
        "presets/p.toml",
        "[dumps]\nread_non_resident_pages = true\n",
    );
    assert!(
        found.iter().any(|p| p.severity == Severity::Warning
            && p.to_string().contains("dumps.read_non_resident_pages")),
        "{found:?}"
    );
}

#[test]
fn the_lanes_of_service_toml_are_checked_against_the_lane_vm() {
    let clean = lane(VmNet::Routed, &["auto-clean"]);
    assert_eq!(lane_problems("", &clean), Vec::<String>::new());
    // Without the VM the lane checks are a warning, not an error.
    assert_eq!(lane_problems("", &NoVms), Vec::<String>::new());
    // snapshot_* needs the named snapshot.
    let found = lane_problems("", &lane(VmNet::Routed, &["other"]));
    assert!(
        found
            .iter()
            .any(|f| f.contains("no snapshot named `auto-clean`")),
        "{found:?}"
    );
    // reset is refused when the VM has snapshots and fine without.
    let reset = "[lanes]\nrevert = \"reset\"\n";
    let found = lane_problems(reset, &clean);
    assert!(
        found
            .iter()
            .any(|f| f.contains("reset is refused") && f.contains("snapshot_disk")),
        "{found:?}"
    );
    assert_eq!(
        lane_problems(reset, &lane(VmNet::Routed, &[])),
        Vec::<String>::new()
    );
    // The VM's network must be the lanes', and NAT never.
    let found = lane_problems("", &lane(VmNet::Isolated, &["auto-clean"]));
    assert!(
        found
            .iter()
            .any(|f| f.contains("is isolated, the lanes require routed")),
        "{found:?}"
    );
    let found = lane_problems("[lanes]\nnetwork = \"nat\"\n", &NoVms);
    assert!(
        found.iter().any(|f| f.contains("nat is never valid")),
        "{found:?}"
    );
    // stealth is checked, never applied.
    let mut vms = lane(VmNet::Routed, &["auto-clean"]);
    vms.0[0].stealth = Some("plain".into());
    let found = lane_problems("[lanes]\nstealth = \"realistic_desktop\"\n", &vms);
    assert!(
        found.iter().any(|f| f.contains("lanes.stealth")),
        "{found:?}"
    );
    // snapshot_full over a disk-only snapshot (BH-12, ANT-T0465).
    let mut vms = lane(VmNet::Routed, &["auto-clean"]);
    vms.0[0].disk_snapshots = vec!["auto-clean".into()];
    let full = "[lanes]\nrevert = \"snapshot_full\"\n";
    assert!(
        lane_problems(full, &vms)
            .iter()
            .any(|f| f.contains("holds the disk only"))
    );
    assert!(
        !lane_problems(full, &clean)
            .iter()
            .any(|f| f.contains("holds the disk only"))
    );
}

#[test]
fn a_preset_needs_a_lane_group_and_a_routed_vm_of_this_node() {
    let root = scratch("node");
    fs::write(
        root.join("presets").join("sim.toml"),
        "[network]\nroute = \"inet_sim\"\n",
    )
    .unwrap();
    fs::write(
        root.join("presets").join("arm.toml"),
        "[vm]\nlane_group = \"arm64\"\n",
    )
    .unwrap();
    let report = validate::load(&root, &lane(VmNet::Isolated, &["auto-clean"]), None);
    let messages: Vec<String> = report.errors().map(|p| p.to_string()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("presets/arm.toml")
                && m.contains("lane group `arm64` is not set up")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("presets/sim.toml") && m.contains("only drop is possible")),
        "{messages:?}"
    );
    assert!(!report.presets.contains_key("arm") && !report.presets.contains_key("sim"));
    // Another lane group in service.toml makes arm the usable one.
    fs::write(root.join("service.toml"), "[lanes]\ngroup = \"arm64\"\n").unwrap();
    let report = validate::load(&root, &NoVms, None);
    assert!(report.presets.contains_key("arm"));
    assert_eq!(report.preset_set().lane_group(), "arm64");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn load_reads_the_data_directory_and_checks_across_files() {
    let root = scratch("load");
    fs::write(root.join("presets").join("mine.toml"), STANDARD).unwrap();
    fs::write(
        root.join("presets").join("broken.toml"),
        "[accepts]\nmax_sample_mib = 0\n",
    )
    .unwrap();
    fs::write(root.join("presets").join("notes.txt"), "ignored").unwrap();
    fs::write(
        root.join("service.toml"),
        "[[inbox.watch]]\npath = \"/srv/drop\"\npreset = \"missing\"\n",
    )
    .unwrap();
    let report = validate::load(&root, &NoVms, None);
    assert!(report.has_errors());
    assert!(report.presets.contains_key("mine"));
    assert!(report.presets.contains_key("standard"), "the built-in ones");
    assert_eq!(report.presets.len(), 6);
    // A preset with errors is not loaded.
    assert!(!report.presets.contains_key("broken"));
    let messages: Vec<String> = report.problems.iter().map(|p| p.to_string()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("presets/broken.toml:2:")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("service.toml:3:")
                && m.contains("preset `missing` does not exist")),
        "{messages:?}"
    );

    // --preset NAME checks one file (or built-in preset) only; an unknown
    // name is an error.
    let one = validate::load(&root, &NoVms, Some("mine"));
    assert!(!one.has_errors(), "{:?}", one.problems);
    assert_eq!(one.presets.len(), 1);
    let built = validate::load(&root, &NoVms, Some("deep"));
    assert!(!built.has_errors() && built.presets.contains_key("deep"));
    let none = validate::load(&root, &NoVms, Some("nothing"));
    assert!(none.errors().any(|p| p.message == "no such preset"));

    // An empty directory is the five built-in presets.
    let empty = scratch("empty");
    let report = validate::load(&empty, &NoVms, None);
    assert!(!report.has_errors(), "{:?}", report.problems);
    assert_eq!(report.presets.len(), 5);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&empty);
}

#[test]
fn a_0_9_0_policies_folder_is_refused_naming_each_new_key() {
    let root = scratch("migrate");
    fs::create_dir_all(root.join("policies")).unwrap();
    fs::write(
        root.join("policies").join("default.toml"),
        "description = \"x\"\n[run]\ntimeout_s = 300\nargs_allowed = true\n\
         [evidence]\ncore_dump = false\n[access]\nscopes = [\"submit\"]\n\
         [limits]\nmax_jobs_per_day = 500\n",
    )
    .unwrap();
    let report = validate::load(&root, &NoVms, None);
    assert!(report.has_errors());
    let messages: Vec<String> = report.errors().map(|p| p.to_string()).collect();
    assert!(
        messages[0].contains("policies/ is replaced by presets/"),
        "{messages:?}"
    );
    for (key, home) in [
        ("run.timeout_s", "`program.run_time_s`"),
        (
            "run.args_allowed",
            "removed: a run may always change `program.arguments`",
        ),
        ("evidence.core_dump", "now `dumps.core_dump_on_exit`"),
        ("access.scopes", "removed: the caller's permissions decide"),
        ("limits.max_jobs_per_day", "`max_runs_per_day`"),
    ] {
        assert!(
            messages
                .iter()
                .any(|m| m.starts_with("policies/default.toml:")
                    && m.contains(key)
                    && m.contains(home)),
            "{key}: {messages:?}"
        );
    }
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn watch_folders_take_preset_and_refuse_the_0_9_0_keys() {
    let (config, found) = parse_service(
        "service.toml",
        "[[inbox.watch]]\npath = \"/srv/a\"\npreset = \"deep\"\npreset_by_dir = true\n",
    );
    assert!(found.is_empty(), "{found:?}");
    let watch = &config.unwrap().inbox.watch[0];
    assert_eq!(watch.preset, "deep");
    assert!(watch.preset_by_dir);
    let (config, _) = parse_service("service.toml", "[[inbox.watch]]\npath = \"/srv/a\"\n");
    assert_eq!(config.unwrap().inbox.watch[0].preset, "standard");
    let (_, found) = parse_service(
        "service.toml",
        "[[inbox.watch]]\npath = \"/srv/a\"\npolicy = \"default\"\npolicy_by_dir = true\n",
    );
    let messages: Vec<String> = found.iter().map(|p| p.to_string()).collect();
    assert!(
        messages.iter().any(|m| m.contains("renamed `preset`")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("renamed `preset_by_dir`")),
        "{messages:?}"
    );
    // [queue] wait_s replaces the policy's limits.wait_s.
    let (config, _) = parse_service("service.toml", "");
    assert_eq!(config.unwrap().queue.wait_s, 3600);
    let (_, found) = parse_service("service.toml", "[queue]\nwait_s = 0\n");
    assert!(found.iter().any(|p| p.to_string().contains("queue.wait_s")));
}

#[test]
fn a_reload_replaces_the_set_and_a_bad_reload_keeps_it() {
    let root = scratch("reload");
    let file = root.join("presets").join("mine.toml");
    fs::write(&file, STANDARD).unwrap();
    let shared = SharedPresets::new(Default::default());
    assert_eq!(shared.reload(&root, &NoVms).unwrap(), 6);
    let frozen = shared.get("mine").unwrap();
    assert_eq!(frozen.preset.program.run_time_s, 300);

    // An edit that is valid: the new set has the new digest, the held Arc the old.
    fs::write(
        &file,
        with(STANDARD, "run_time_s = 300", "run_time_s = 120"),
    )
    .unwrap();
    shared.reload(&root, &NoVms).unwrap();
    let fresh = shared.get("mine").unwrap();
    assert_eq!(fresh.preset.program.run_time_s, 120);
    assert_ne!(fresh.digest, frozen.digest);
    assert_eq!(frozen.preset.program.run_time_s, 300);

    // A broken edit changes nothing.
    fs::write(&file, "nonsense = 1").unwrap();
    assert!(shared.reload(&root, &NoVms).is_err());
    assert_eq!(shared.get("mine").unwrap().digest, fresh.digest);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn service_toml_checks_lanes_safety_and_watch_folders() {
    let (config, found) = parse_service("service.toml", "");
    assert!(found.is_empty() && config.is_some());
    let config = config.unwrap();
    assert_eq!(config.queue.max_queued, 1000);
    assert_eq!(config.resources.min_free_disk_gib, 20);
    assert!(config.resources.require_kvm);
    assert_eq!(config.retention.jobs_days, 90);
    assert_eq!(config.host_workers(), 2);
    assert_eq!(config.host_time_factor(), 2.0);
    assert_eq!(config.min_free_ram_mib(2048), 4096);
    assert_eq!(
        config.socket_path(std::path::Path::new("/d")),
        PathBuf::from("/d/run/antinomie.sock")
    );

    let text = "[daemon]\nlanes = 5\n[safety]\nunsafe_routes_ack = \"I understand\"\n\
                [[inbox.watch]]\npath = \"relative\"\n[[inbox.watch]]\npath = \"/srv/a\"\ndelete_after = \"keep\"\n";
    let (_, found) = parse_service("service.toml", text);
    let messages: Vec<String> = found.iter().map(|p| p.to_string()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains(":2:") && m.contains("must be 1 to 4")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("reserved: no live route")),
        "{messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("absolute path")),
        "{messages:?}"
    );
}

#[test]
fn lanes_are_one_by_default_and_one_to_four_when_set() {
    let (config, found) = parse_service("service.toml", "");
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(config.unwrap().daemon.lanes, 1);
    for lanes in 1..=4 {
        let (config, found) =
            parse_service("service.toml", &format!("[daemon]\nlanes = {lanes}\n"));
        assert!(found.is_empty(), "{lanes}: {found:?}");
        assert_eq!(config.unwrap().daemon.lanes, lanes);
    }
    for lanes in [0, 5, 64] {
        let (_, found) = parse_service("service.toml", &format!("[daemon]\nlanes = {lanes}\n"));
        assert!(
            found
                .iter()
                .any(|p| p.key.as_deref() == Some("daemon.lanes") && p.message.contains("1 to 4")),
            "{lanes}: {found:?}"
        );
    }
}

#[test]
fn host_workers_and_the_time_factor_are_bounded() {
    let (config, found) = parse_service(
        "service.toml",
        "[daemon]\nhost_workers = 3\nhost_time_factor = 2.5\n",
    );
    assert!(found.is_empty(), "{found:?}");
    let config = config.unwrap();
    assert_eq!(config.host_workers(), 3);
    assert_eq!(config.host_time_factor(), 2.5);
    for (text, key) in [
        ("[daemon]\nhost_workers = 0\n", "daemon.host_workers"),
        ("[daemon]\nhost_workers = 9\n", "daemon.host_workers"),
        (
            "[daemon]\nhost_time_factor = 0.5\n",
            "daemon.host_time_factor",
        ),
        (
            "[daemon]\nhost_time_factor = 21.0\n",
            "daemon.host_time_factor",
        ),
    ] {
        let (_, found) = parse_service("service.toml", text);
        assert!(
            found
                .iter()
                .any(|p| p.severity == Severity::Error && p.to_string().contains(key)),
            "{text}: {found:?}"
        );
    }
}

#[test]
fn webhooks_are_refused_as_not_part_of_0_9_0() {
    let hook = "[[notify.webhooks]]\nurl = \"https://example.org/x\"\nsecret_file = \"/s\"\n";
    let (_, found) = parse_service("service.toml", hook);
    assert!(
        found
            .iter()
            .any(|p| p.severity == Severity::Error && p.message.contains("not supported in 0.9.0")),
        "{found:?}"
    );
}

#[test]
fn a_changed_scan_cache_is_refused_and_the_other_query_keys_are_accepted() {
    let (_, found) = parse_service("service.toml", "[query]\nscan_cache_mib = 512\n");
    assert!(
        found
            .iter()
            .any(|p| p.severity == Severity::Error && p.message.contains("not supported in 0.9.0")),
        "{found:?}"
    );
    let (config, found) = parse_service(
        "service.toml",
        "[query]\nscan_cache_mib = 1024\nlight_concurrency = 4\nheavy_timeout_s = 30\n",
    );
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(config.unwrap().query.light_concurrency, 4);
}

#[test]
fn processed_keep_days_and_the_results_mode_have_defaults_and_are_checked() {
    use antinomie_service::config::service::ResultsMode;
    let (config, found) = parse_service("service.toml", "");
    assert!(found.is_empty());
    let config = config.unwrap();
    assert_eq!(config.inbox.processed_keep_days, 7);
    assert_eq!(config.results.mode, ResultsMode::Private);
    assert_eq!(
        (
            ResultsMode::Private.file_mode(),
            ResultsMode::Private.dir_mode()
        ),
        (0o600, 0o700)
    );
    assert_eq!(
        (
            ResultsMode::Group.file_mode(),
            ResultsMode::Group.dir_mode()
        ),
        (0o640, 0o750)
    );

    let (config, found) = parse_service(
        "service.toml",
        "[inbox]\nprocessed_keep_days = 30\n[results]\nmode = \"group\"\n",
    );
    assert!(found.is_empty(), "{found:?}");
    let config = config.unwrap();
    assert_eq!(config.inbox.processed_keep_days, 30);
    assert_eq!(config.results.mode, ResultsMode::Group);

    // A keep time of zero and a mode that does not exist are errors, the
    // second with the line it is on.
    let (_, found) = parse_service("service.toml", "[inbox]\nprocessed_keep_days = 0\n");
    assert!(
        found.iter().any(|p| p.message.contains("at least 1 day")
            && p.to_string().contains("processed_keep_days")),
        "{found:?}"
    );
    let (config, found) = parse_service("service.toml", "[results]\nmode = \"world\"\n");
    assert!(config.is_none());
    let text = found[0].to_string();
    assert!(text.contains(":2:") && text.contains("world"), "{text}");
}

/// BH-08 (bug hunt 0.9.0): `max_recordings_gib = 0` is a cap of 0 bytes, so
/// every pass deletes every finished job's recording; it must be refused
/// like the other zero sizes and periods.
#[test]
fn bh_08_a_recordings_cap_of_zero_is_refused() {
    let (_, found) = parse_service("service.toml", "[retention]\nmax_recordings_gib = 0\n");
    assert!(
        found
            .iter()
            .any(|p| p.severity == antinomie_service::config::Severity::Error),
        "{found:?}"
    );
}

/// ANT-T0471: the grace between SIGTERM and SIGKILL of a stopped host work
/// item: 30 s by default, 0 to 600.
#[test]
fn t0471_the_stop_grace_defaults_to_30_s_and_is_bounded() {
    let (config, found) = parse_service("service.toml", "");
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(config.unwrap().daemon.stop_grace_s, 30);
    for (text, ok) in [
        ("[daemon]\nstop_grace_s = 0\n", true),
        ("[daemon]\nstop_grace_s = 600\n", true),
        ("[daemon]\nstop_grace_s = 601\n", false),
    ] {
        let (_, found) = parse_service("service.toml", text);
        let refused = found.iter().any(|p| {
            p.severity == Severity::Error && p.to_string().contains("daemon.stop_grace_s")
        });
        assert_eq!(refused, !ok, "{text}: {found:?}");
    }
}

#[test]
fn limits_per_caller_are_unset_by_default_and_checked_when_set() {
    let (config, found) = parse_service("service.toml", "");
    assert!(found.is_empty());
    let config = config.unwrap();
    // No limit of the owner's own, and no daily limit.
    assert!(config.limits.local.is_empty());
    assert_eq!(config.limits.local.max_runs_per_day, None);

    let text = "[limits.local]\npriority_max = 8\nmax_queued = 20\nmax_running = 1\n\
                max_runs_per_day = 50\nmax_run_s = 900\n\
                [[inbox.watch]]\npath = \"/srv/a\"\npriority_max = 2\n";
    let (config, found) = parse_service("service.toml", text);
    assert!(found.is_empty(), "{found:?}");
    let config = config.unwrap();
    assert_eq!(config.limits.local.priority_max, Some(8));
    assert_eq!(config.limits.local.max_runs_per_day, Some(50));
    assert_eq!(config.inbox.watch[0].priority_max, Some(2));

    let text = "[limits.local]\npriority_max = 10\nmax_queued = 0\nmax_running = 0\n\
                max_runs_per_day = 0\nmax_run_s = 4\n\
                [[inbox.watch]]\npath = \"/srv/a\"\npriority_max = 12\n";
    let (_, found) = parse_service("service.toml", text);
    let messages: Vec<String> = found.iter().map(|p| p.to_string()).collect();
    for key in [
        "limits.local.priority_max",
        "limits.local.max_queued",
        "limits.local.max_running",
        "limits.local.max_runs_per_day",
        "limits.local.max_run_s",
        "inbox.watch.0.priority_max",
    ] {
        assert!(
            messages.iter().any(|m| m.contains(key)),
            "{key}: {messages:?}"
        );
    }
    // An unknown key of the table is an error.
    let (_, found) = parse_service("service.toml", "[limits.local]\nmax_jobs_per_day = 5\n");
    assert!(!found.is_empty());
}
