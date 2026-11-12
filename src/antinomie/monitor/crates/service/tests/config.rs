// SPDX-License-Identifier: GPL-3.0-only
//! `service.toml`, `policies/*.toml` and their validation (card P3-3, design
//! 2.4.2 and 4.4): unknown keys, ceilings, the v1 routes, and the checks that
//! need the lane VM.

// `ApiError` is the contract's error type (large by design, see the crate root).
#![allow(clippy::result_large_err)]

use antinomie_service::config::{
    DEFAULT_POLICY, NoVms, PolicyLookup, Severity, SharedPolicies, VmCatalog, VmFacts, VmNet,
    validate::{self, parse_policy, parse_service},
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

fn problems(text: &str, catalog: &dyn VmCatalog) -> Vec<String> {
    let (_, problems) = parse_policy("p", "policies/p.toml", text, catalog);
    problems
        .iter()
        .filter(|p| p.severity == Severity::Error)
        .map(|p| p.to_string())
        .collect()
}

fn with(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "{from} is not in the default policy");
    text.replacen(from, to, 1)
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-svc-config-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("policies")).unwrap();
    root
}

#[test]
fn the_shipped_default_policy_is_valid_on_a_clean_lane() {
    let catalog = lane(VmNet::Routed, &["auto-clean"]);
    assert_eq!(problems(DEFAULT_POLICY, &catalog), Vec::<String>::new());
    // Without a data directory the lane checks are skipped, not failed.
    assert_eq!(problems(DEFAULT_POLICY, &NoVms), Vec::<String>::new());
}

#[test]
fn an_empty_policy_takes_the_design_defaults_but_needs_a_lane_vm() {
    let found = problems("", &NoVms);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("vm.lane_vm is required"));
}

#[test]
fn unknown_keys_are_errors_with_a_line_number() {
    let text = with(DEFAULT_POLICY, "[report]\n", "[report]\nformats_typo = 1\n");
    let found = problems(&text, &NoVms);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("unknown field `formats_typo`"),
        "{found:?}"
    );
    assert!(found[0].starts_with("policies/p.toml:"), "{found:?}");
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
    let (_, found) = parse_service("service.toml", "[daemon]\nlanes = 1\nthreads = 2\n");
    assert!(found[0].message.contains("unknown field `threads`"));
    assert_eq!(found[0].line, Some(3));
}

#[test]
fn only_drop_and_inet_sim_routes_are_valid() {
    for route in ["internet", "tor", "vpn", "socks5"] {
        let text = with(
            DEFAULT_POLICY,
            r#"allowed_routes = ["drop", "inet_sim"]"#,
            &format!(r#"allowed_routes = ["drop", "{route}"]"#),
        );
        let found = problems(&text, &NoVms);
        assert_eq!(found.len(), 1, "{route}: {found:?}");
        assert!(found[0].contains("not in v1"), "{found:?}");
        assert!(found[0].contains(route), "{found:?}");
    }
    // The default route must be one of the allowed ones.
    let text = with(
        DEFAULT_POLICY,
        r#"allowed_routes = ["drop", "inet_sim"]"#,
        r#"allowed_routes = ["drop"]"#,
    );
    let text = with(
        &text,
        r#"route          = "drop""#,
        r#"route          = "inet_sim""#,
    );
    let found = problems(&text, &NoVms);
    assert!(
        found
            .iter()
            .any(|f| f.contains("not in network.allowed_routes")),
        "{found:?}"
    );
    // A spelling that is not a route at all is a parse error.
    let text = with(
        DEFAULT_POLICY,
        r#"route          = "drop""#,
        r#"route          = "wormhole""#,
    );
    assert!(problems(&text, &NoVms)[0].contains("unknown variant"));
}

#[test]
fn nat_is_never_valid() {
    let text = with(
        DEFAULT_POLICY,
        r#"network      = "routed""#,
        r#"network      = "nat""#,
    );
    let found = problems(&text, &NoVms);
    assert!(
        found.iter().any(|f| f.contains("nat is never valid")),
        "{found:?}"
    );
    // A lane VM that uses NAT is refused too.
    let found = problems(DEFAULT_POLICY, &lane(VmNet::Nat, &["auto-clean"]));
    assert!(found.iter().any(|f| f.contains("uses NAT")), "{found:?}");
}

#[test]
fn ceilings_are_enforced() {
    let cases = [
        (
            "max_sample_mib = 64",
            "max_sample_mib = 257",
            "sample.max_sample_mib",
        ),
        (
            "max_sample_mib = 64",
            "max_sample_mib = 0",
            "sample.max_sample_mib",
        ),
        (
            "max_run_s    = 1800",
            "max_run_s    = 1801",
            "1800 second maximum",
        ),
        (
            "timeout_s    = 300",
            "timeout_s    = 3",
            "at least 5 seconds",
        ),
        (
            "core_max_mib = 64",
            "core_max_mib = 1025",
            "engine maximum of 1024",
        ),
        (
            "# static_time_limit_min = 2",
            "static_time_limit_min = 481 #",
            "0 to 480",
        ),
        (
            "priority_max          = 5",
            "priority_max          = 10",
            "0 to 9",
        ),
        ("max_attempts = 2", "max_attempts = 0", "at least 1"),
        (
            "max_concurrent        = 1",
            "max_concurrent        = 2",
            "one lane per node",
        ),
        (
            r#"accept_types   = ["elf"]"#,
            r#"accept_types   = ["elf", "docx"]"#,
            "unknown type `docx`",
        ),
        (
            r#"accept_arch    = ["x86_64"]"#,
            r#"accept_arch    = ["z80"]"#,
            "unknown architecture",
        ),
        (
            r#"run_in       = "app_terminal""#,
            r#"run_in       = "guest_desktop""#,
            "app_terminal only",
        ),
        (
            r#"guest_dir    = "/tmp""#,
            r#"guest_dir    = "tmp""#,
            "absolute path",
        ),
    ];
    for (from, to, expect) in cases {
        let found = problems(&with(DEFAULT_POLICY, from, to), &NoVms);
        assert!(
            found.iter().any(|f| f.contains(expect)),
            "{from} -> {to}: {found:?}"
        );
    }
    // timeout above max_run_s, and root without allow_root.
    let text = with(DEFAULT_POLICY, "max_run_s    = 1800", "max_run_s    = 200");
    assert!(
        problems(&text, &NoVms)
            .iter()
            .any(|f| f.contains("above run.max_run_s"))
    );
    let text = with(
        DEFAULT_POLICY,
        r#"run_as       = "user""#,
        r#"run_as       = "root""#,
    );
    assert!(
        problems(&text, &NoVms)
            .iter()
            .any(|f| f.contains("allow_root"))
    );
}

#[test]
fn a_required_stage_the_policy_skips_is_an_error() {
    let text = with(
        DEFAULT_POLICY,
        r#"static_checks         = "triage""#,
        r#"static_checks         = "none""#,
    );
    let text = with(
        &text,
        "triage                = true",
        "triage                = false",
    );
    let text = with(
        &text,
        "detection             = { yara = true, sigma = true, ids = true }",
        "detection             = { yara = false, sigma = false, ids = false }",
    );
    let found = problems(&text, &NoVms);
    assert!(
        found
            .iter()
            .any(|f| f.contains("analyse stage is required")),
        "{found:?}"
    );
    // The same policy with the stage not required is fine.
    let text = with(
        &text,
        r#"required_stages       = ["analyse"]"#,
        "required_stages       = []",
    );
    assert_eq!(problems(&text, &NoVms), Vec::<String>::new());
}

#[test]
fn the_revert_mode_is_checked_against_the_lane_snapshots() {
    // snapshot_* needs the named snapshot.
    let found = problems(DEFAULT_POLICY, &lane(VmNet::Routed, &["other"]));
    assert!(
        found
            .iter()
            .any(|f| f.contains("no snapshot named `auto-clean`")),
        "{found:?}"
    );
    let found = problems(DEFAULT_POLICY, &lane(VmNet::Routed, &[]));
    assert!(
        found.iter().any(|f| f.contains("no snapshot named")),
        "{found:?}"
    );
    // reset is refused when the VM has snapshots (storage.rs:1227) and fine without.
    let reset = with(
        DEFAULT_POLICY,
        r#"revert       = "snapshot_disk""#,
        r#"revert       = "reset""#,
    );
    let found = problems(&reset, &lane(VmNet::Routed, &["auto-clean"]));
    assert!(
        found.iter().any(|f| f.contains("reset is refused")),
        "{found:?}"
    );
    assert_eq!(
        problems(&reset, &lane(VmNet::Routed, &[])),
        Vec::<String>::new()
    );
}

#[test]
fn the_lane_vm_must_match_the_policy_network() {
    let found = problems(DEFAULT_POLICY, &lane(VmNet::Isolated, &["auto-clean"]));
    assert!(
        found
            .iter()
            .any(|f| f.contains("is isolated, the policy requires routed")),
        "{found:?}"
    );
    // A policy that allows inet_sim needs a routed VM.
    let drop_only = with(
        DEFAULT_POLICY,
        r#"allowed_routes = ["drop", "inet_sim"]"#,
        r#"allowed_routes = ["drop"]"#,
    );
    let drop_only = with(
        &drop_only,
        r#"network      = "routed""#,
        r#"network      = "isolated""#,
    );
    assert_eq!(
        problems(&drop_only, &lane(VmNet::Isolated, &["auto-clean"])),
        Vec::<String>::new()
    );
    // stealth is checked, never applied.
    let mut vms = lane(VmNet::Routed, &["auto-clean"]);
    vms.0[0].stealth = Some("plain".into());
    let text = with(
        DEFAULT_POLICY,
        r#"revert_after = false"#,
        "revert_after = false\nstealth = \"realistic_desktop\"",
    );
    assert!(
        problems(&text, &vms)
            .iter()
            .any(|f| f.contains("vm.stealth"))
    );
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
        messages.iter().any(|m| m.contains("reserved: live routes")),
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

#[test]
fn load_reads_the_data_directory_and_checks_across_files() {
    let root = scratch("load");
    fs::write(root.join("policies").join("default.toml"), DEFAULT_POLICY).unwrap();
    fs::write(
        root.join("policies").join("broken.toml"),
        "[sample]\nmax_sample_mib = 0\n",
    )
    .unwrap();
    fs::write(root.join("policies").join("notes.txt"), "ignored").unwrap();
    fs::write(
        root.join("service.toml"),
        "[[inbox.watch]]\npath = \"/srv/drop\"\npolicy = \"missing\"\n",
    )
    .unwrap();
    let report = validate::load(&root, &NoVms, None);
    assert!(report.has_errors());
    assert!(report.policies.contains_key("default"));
    // A policy with errors is not loaded.
    assert!(!report.policies.contains_key("broken"));
    let messages: Vec<String> = report.problems.iter().map(|p| p.to_string()).collect();
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("policies/broken.toml:2:")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("service.toml:3:")
                && m.contains("policy `missing` does not exist")),
        "{messages:?}"
    );

    // --policy NAME checks one file only; an unknown name is an error.
    let one = validate::load(&root, &NoVms, Some("default"));
    assert!(!one.has_errors(), "{:?}", one.problems);
    let none = validate::load(&root, &NoVms, Some("nothing"));
    assert!(none.errors().any(|p| p.message == "no such policy"));

    // An empty directory is the defaults with a warning, not an error.
    let empty = scratch("empty");
    let report = validate::load(&empty, &NoVms, None);
    assert!(!report.has_errors());
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.severity == Severity::Warning)
    );
}

#[test]
fn a_reload_replaces_the_set_and_a_bad_reload_keeps_it() {
    let root = scratch("reload");
    let file = root.join("policies").join("default.toml");
    fs::write(&file, DEFAULT_POLICY).unwrap();
    let shared = SharedPolicies::new(Default::default());
    assert_eq!(shared.reload(&root, &NoVms).unwrap(), 1);
    let frozen = shared.get("default").unwrap();
    assert_eq!(frozen.policy.run.timeout_s, 300);

    // An edit that is valid: the new set has the new digest, the held Arc the old.
    fs::write(
        &file,
        with(DEFAULT_POLICY, "timeout_s    = 300", "timeout_s    = 120"),
    )
    .unwrap();
    shared.reload(&root, &NoVms).unwrap();
    let fresh = shared.get("default").unwrap();
    assert_eq!(fresh.policy.run.timeout_s, 120);
    assert_ne!(fresh.digest, frozen.digest);
    assert_eq!(frozen.policy.run.timeout_s, 300);

    // A broken edit changes nothing.
    fs::write(&file, "nonsense = 1").unwrap();
    assert!(shared.reload(&root, &NoVms).is_err());
    assert_eq!(shared.get("default").unwrap().digest, fresh.digest);
}

#[test]
fn the_digest_is_the_sha256_of_the_file() {
    let (policy, _) = parse_policy("default", "policies/default.toml", DEFAULT_POLICY, &NoVms);
    let digest = policy.unwrap().digest;
    assert_eq!(digest.len(), 64);
    let again = parse_policy(
        "default",
        "policies/default.toml",
        &format!("{DEFAULT_POLICY}\n"),
        &NoVms,
    )
    .0
    .unwrap()
    .digest;
    assert_ne!(digest, again);
}

#[test]
fn policy_names_must_be_safe() {
    for bad in ["", ".hidden", "UPPER", "a b", "a/b"] {
        assert!(!validate::valid_policy_name(bad), "{bad}");
    }
    assert!(validate::valid_policy_name("ci-fast_2.0"));
    let (_, found) = parse_policy("Bad Name", "policies/x.toml", DEFAULT_POLICY, &NoVms);
    assert!(
        found
            .iter()
            .any(|p| p.message.contains("not a valid policy name"))
    );
}

fn warnings(text: &str) -> Vec<String> {
    let (_, problems) = parse_policy("p", "policies/p.toml", text, &NoVms);
    problems
        .iter()
        .filter(|p| p.severity == Severity::Warning)
        .map(|p| p.to_string())
        .collect()
}

#[test]
fn the_dump_trigger_is_off_by_default_and_takes_a_tier_and_a_kind() {
    use antinomie_service::config::policy::{TriggerKind, TriggerSetting};
    let (loaded, found) = parse_policy("p", "policies/p.toml", DEFAULT_POLICY, &NoVms);
    assert!(
        found.iter().all(|p| p.severity != Severity::Error),
        "{found:?}"
    );
    let evidence = loaded.unwrap().policy.evidence;
    assert_eq!(evidence.dump_trigger, TriggerSetting::Off);
    assert!(evidence.trigger().is_none());
    for (tier, kind) in [("low", "core"), ("medium", "memory"), ("high", "both")] {
        let text = with(
            DEFAULT_POLICY,
            "dump_trigger      = \"off\"",
            &format!("dump_trigger = \"{tier}\""),
        );
        let text = with(
            &text,
            "dump_trigger_kind = \"core\"",
            &format!("dump_trigger_kind = \"{kind}\""),
        );
        assert_eq!(
            problems(&text, &NoVms),
            Vec::<String>::new(),
            "{tier} {kind}"
        );
        let (loaded, _) = parse_policy("p", "policies/p.toml", &text, &NoVms);
        let evidence = loaded.unwrap().policy.evidence;
        let plan = evidence.trigger().expect("armed");
        assert_eq!(plan.min_tier.label().to_ascii_lowercase(), tier);
        assert_eq!(
            (plan.memory, plan.core),
            match evidence.dump_trigger_kind {
                TriggerKind::Core => (false, true),
                TriggerKind::Memory => (true, false),
                TriggerKind::Both => (true, true),
            }
        );
    }
}

#[test]
fn a_bad_dump_trigger_value_or_budget_is_an_error() {
    for (value, wanted) in [
        ("urgent", "unknown variant `urgent`"),
        ("", "unknown variant"),
    ] {
        let text = with(
            DEFAULT_POLICY,
            "dump_trigger      = \"off\"",
            &format!("dump_trigger = \"{value}\""),
        );
        let found = problems(&text, &NoVms);
        assert!(
            found.iter().any(|p| p.contains(wanted)),
            "{value:?}: {found:?}"
        );
    }
    let text = with(
        DEFAULT_POLICY,
        "dump_trigger_kind = \"core\"",
        "dump_trigger_kind = \"disk\"",
    );
    assert!(
        problems(&text, &NoVms)
            .iter()
            .any(|p| p.contains("unknown variant `disk`"))
    );
    // A core trigger needs a core budget; a memory trigger does not.
    let armed = with(
        DEFAULT_POLICY,
        "dump_trigger      = \"off\"",
        "dump_trigger = \"high\"",
    );
    let no_budget = with(&armed, "core_max_mib = 64", "core_max_mib = 0");
    assert!(
        problems(&no_budget, &NoVms)
            .iter()
            .any(|p| p.contains("core_max_mib") && p.contains("at least 1"))
    );
    let memory = with(
        &no_budget,
        "dump_trigger_kind = \"core\"",
        "dump_trigger_kind = \"memory\"",
    );
    assert_eq!(problems(&memory, &NoVms), Vec::<String>::new());
}

#[test]
fn a_dump_kind_without_a_trigger_is_only_a_warning() {
    let text = with(
        DEFAULT_POLICY,
        "dump_trigger_kind = \"core\"",
        "dump_trigger_kind = \"both\"",
    );
    assert_eq!(problems(&text, &NoVms), Vec::<String>::new());
    assert!(
        warnings(&text)
            .iter()
            .any(|w| w.contains("dump_trigger_kind") && w.contains("no effect"))
    );
}

#[test]
fn core_nonresident_needs_a_core_trigger_and_is_a_warning_otherwise() {
    let on = with(
        DEFAULT_POLICY,
        "core_nonresident  = false",
        "core_nonresident  = true",
    );
    assert_eq!(problems(&on, &NoVms), Vec::<String>::new());
    assert!(
        warnings(&on)
            .iter()
            .any(|w| w.contains("core_nonresident") && w.contains("no effect"))
    );
    let armed = with(
        &on,
        "dump_trigger      = \"off\"",
        "dump_trigger      = \"high\"",
    );
    assert_eq!(problems(&armed, &NoVms), Vec::<String>::new());
    assert!(
        !warnings(&armed)
            .iter()
            .any(|w| w.contains("core_nonresident"))
    );
    let policy: antinomie_service::config::Policy = toml::from_str(&armed).unwrap();
    assert!(policy.evidence.core_nonresident);
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

/// BH-12, ANT-T0465: `snapshot_full` over a disk-only snapshot (what `auto
/// init` takes) cannot resume a guest; `config validate` refuses it.
#[test]
fn snapshot_full_over_a_disk_snapshot_is_refused() {
    let full = with(
        DEFAULT_POLICY,
        r#"revert       = "snapshot_disk""#,
        r#"revert       = "snapshot_full""#,
    );
    let mut vms = lane(VmNet::Routed, &["auto-clean"]);
    vms.0[0].disk_snapshots = vec!["auto-clean".into()];
    let (_, found) = parse_policy("p", "policies/p.toml", &full, &vms);
    assert!(
        found
            .iter()
            .any(|p| p.severity == Severity::Error
                && p.to_string().contains("holds the disk only")),
        "{found:?}"
    );
    // Over a full snapshot, nothing to say.
    let (_, found) = parse_policy(
        "p",
        "policies/p.toml",
        &full,
        &lane(VmNet::Routed, &["auto-clean"]),
    );
    assert!(
        !found
            .iter()
            .any(|p| p.to_string().contains("holds the disk only")),
        "{found:?}"
    );
}
