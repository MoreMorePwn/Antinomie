// SPDX-License-Identifier: GPL-3.0-only
//! From 0.9.0 policies to presets (the specification's "Every policy key and
//! its new home" and "Migration"). No converter ships: `config validate` and
//! the daemon refuse a `policies/` folder and name, for each key of each
//! file, where it went. A preset file that still uses a policy key is told
//! the same.

use toml::Value;

/// Where each key of a 0.9.0 policy went. A key whose name did not change
/// (`network.route`, `report.*`, `verdict.*`, `retry.*`) is not listed.
pub const NEW_HOMES: [(&str, &str); 45] = [
    ("description", "`title` and `description`"),
    ("sample.accept_types", "`accepts.types`"),
    ("sample.accept_arch", "`accepts.arch`"),
    ("sample.max_sample_mib", "`accepts.max_sample_mib`"),
    ("sample.on_duplicate", "`duplicates.on_duplicate`"),
    (
        "sample.reuse_across_policies",
        "`duplicates.reuse_across_presets`",
    ),
    (
        "vm.lane_vm",
        "`[lanes] vm` in service.toml; a preset names `vm.lane_group`",
    ),
    ("vm.base", "`vm.lane_group` (the lane VM fixes the base)"),
    ("vm.revert", "`[lanes] revert` in service.toml"),
    ("vm.revert_to", "`[lanes] revert_to` in service.toml"),
    ("vm.stealth", "`[lanes] stealth` in service.toml"),
    ("vm.network", "`[lanes] network` in service.toml"),
    (
        "vm.revert_after",
        "removed: it was never acted on; a lane is cleaned when the next run starts",
    ),
    ("run.timeout_s", "`program.run_time_s`"),
    (
        "run.max_run_s",
        "a limit of the caller; the node ceiling is 1800 seconds",
    ),
    (
        "run.run_as",
        "`program.user` (normal, root, nobody or custom with `uid`, `gid`)",
    ),
    ("run.allow_root", "the permission `run.as_root`"),
    ("run.run_in", "`program.run_in`"),
    (
        "run.guest_dir",
        "`program.guest_path` (`/tmp/{name}`) and `program.working_directory`",
    ),
    (
        "run.args_allowed",
        "removed: a run may always change `program.arguments` (it is then Custom)",
    ),
    (
        "run.env_allowed",
        "removed: a run may always change `program.environment` (it is then Custom)",
    ),
    ("run.allow_keep_on_failure", "the permission `run.keep_vm`"),
    (
        "network.allowed_routes",
        "removed: drop and inet_sim need no permission, a live route its `route.*` permission",
    ),
    ("evidence.memory_dump", "`dumps.memory_dump_on_exit`"),
    ("evidence.core_dump", "`dumps.core_dump_on_exit`"),
    ("evidence.core_max_mib", "`dumps.core_budget_mib`"),
    (
        "evidence.core_nonresident",
        "`dumps.read_non_resident_pages`",
    ),
    (
        "evidence.dump_trigger",
        "`dumps.dump_when_suspicious` and `dumps.minimum_tier`",
    ),
    (
        "evidence.dump_trigger_kind",
        "`dumps.trigger_memory_dump` and `dumps.trigger_core`",
    ),
    ("evidence.screenshot_every_s", "`record.screenshot_every_s`"),
    (
        "analysis.static_checks",
        "`static_analysis.enabled`, `triage_checks` and `deep_checks`",
    ),
    (
        "analysis.static_time_limit_min",
        "`static_analysis.time_limit_per_tool_min` (0: each tool's own)",
    ),
    (
        "analysis.required_checks",
        "`static_analysis.required_checks`",
    ),
    ("analysis.triage", "`triage.enabled`"),
    (
        "analysis.detection",
        "`detection.yara`, `detection.sigma` and `detection.ids`",
    ),
    ("analysis.required_stages", "`required_stages` (top level)"),
    ("analysis.online_ioc", "`detection.check_online`"),
    (
        "access.scopes",
        "removed: the caller's permissions decide; watch folders have `permissions`",
    ),
    (
        "access.clients",
        "`offered_to` (roles that see the preset; a list, not a lock)",
    ),
    (
        "limits.max_queued_per_client",
        "a limit of the caller (`max_queued`); the node's is `queue.per_client_queued`",
    ),
    (
        "limits.max_concurrent",
        "a limit of the caller (`max_running`)",
    ),
    (
        "limits.priority_max",
        "a limit of the caller (`priority_max`)",
    ),
    (
        "limits.max_jobs_per_day",
        "a limit of the caller (`max_runs_per_day`, unset: no daily limit)",
    ),
    ("limits.wait_s", "`queue.wait_s` in service.toml"),
    (
        "analysis",
        "`static_analysis`, `triage`, `detection` and `required_stages`",
    ),
];

/// What a problem says of a 0.9.0 policy key with this new home.
pub fn message(home: &str) -> String {
    if home.starts_with("removed") {
        format!("a 0.9.0 policy key, {home}")
    } else {
        format!("a 0.9.0 policy key, now {home}")
    }
}

/// The new home of a 0.9.0 policy key, or of its whole table.
pub fn new_home(key: &str) -> Option<&'static str> {
    NEW_HOMES
        .iter()
        .find(|(old, _)| *old == key)
        .map(|(_, home)| *home)
        .or(match key {
            "sample" => Some("`accepts` and `duplicates`"),
            "run" => Some("`program`"),
            "evidence" => Some("`dumps`"),
            "access" => Some("removed: permissions and `offered_to`"),
            "limits" => Some("limits of the caller and `queue.wait_s` in service.toml"),
            _ => None,
        })
}

/// The 0.9.0 policy keys of a parsed file, each with its new home, in the
/// order of their names. A table that presets do not have and whose keys are not
/// listed one by one is named as a whole.
pub fn old_keys(file: &Value) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let Some(table) = file.as_table() else {
        return out;
    };
    for (key, value) in table {
        if let Some(inner) = value.as_table() {
            let mut named = false;
            for inner_key in inner.keys() {
                let path = format!("{key}.{inner_key}");
                if let Some(home) = new_home(&path) {
                    out.push((path, home));
                    named = true;
                }
            }
            if !named && let Some(home) = new_home(key).filter(|_| is_policy_table(key)) {
                out.push((key.clone(), home));
            }
        } else if let Some(home) = new_home(key).filter(|_| key != "description") {
            out.push((key.clone(), home));
        }
    }
    out
}

/// Tables a 0.9.0 policy had and a preset does not.
fn is_policy_table(key: &str) -> bool {
    matches!(
        key,
        "sample" | "run" | "evidence" | "analysis" | "access" | "limits"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_policy_key_names_its_new_home() {
        let file: Value = toml::from_str(
            "description = \"x\"\n[run]\ntimeout_s = 60\nallow_root = true\n\
             [network]\nroute = \"drop\"\nallowed_routes = [\"drop\"]\n\
             [access]\nscopes = [\"submit\"]\n[limits]\nwait_s = 10\n[vm]\nrevert_after = true\n",
        )
        .unwrap();
        let keys: Vec<String> = old_keys(&file).into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            [
                "access.scopes",
                "limits.wait_s",
                "network.allowed_routes",
                "run.allow_root",
                "run.timeout_s",
                "vm.revert_after"
            ]
        );
        assert_eq!(new_home("run.timeout_s"), Some("`program.run_time_s`"));
        assert!(
            new_home("vm.revert_after")
                .unwrap()
                .contains("never acted on")
        );
        assert_eq!(new_home("network.route"), None);
    }
}
