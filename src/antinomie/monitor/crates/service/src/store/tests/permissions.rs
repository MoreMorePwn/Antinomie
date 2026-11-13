// SPDX-License-Identifier: GPL-3.0-only
//! `run.submit` against the caller's permissions (ANT-T0489, presets of
//! ANT-T0490): the check order of the access specification, the codes and
//! what each refusal names.

use super::*;
use crate::api::{
    ops::{Limits, Permission},
    spec::{Overrides, Route},
};
use crate::config::preset::User;
use antinomie_monitor_core::dump_trigger::TriggerTier;
use serde_json::{Value, json};

fn owner() -> Caller {
    Caller::with_every_permission("local:1000")
}

fn holding(extra: &[Permission]) -> Caller {
    let mut who = caller(1000);
    who.permissions.extend(extra.iter().copied());
    who
}

/// A spec of sample 1 with `overrides` (a partial preset).
pub(super) fn with(overrides: Value) -> RunRequest {
    RunRequest {
        overrides: Overrides(overrides.as_object().cloned().unwrap()),
        ..spec(1)
    }
}

fn failure_of(fx: &Fx, who: &Caller, spec: RunRequest) -> Failure {
    let job = fx.submit_as(who, spec).unwrap().run;
    assert_eq!(job.state, RunState::Rejected, "{:?}", job.failure);
    job.failure.unwrap()
}

#[test]
fn a_refusal_names_every_missing_permission_in_the_documented_order() {
    let fx = Fx::new("perm-order");
    let failure = failure_of(
        &fx,
        &caller(1000),
        with(json!({
            "dumps": {"memory_dump_on_exit": true, "core_dump_on_exit": true},
            "program": {"user": "root"},
            "network": {"route": "tor"}
        })),
    );
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(
        failure.details["needs"],
        json!([
            "route.tor",
            "run.as_root",
            "evidence.core_dump",
            "evidence.memory_dump"
        ])
    );
    // The field is the first missing permission's preset key.
    assert_eq!(failure.field.as_deref(), Some("network.route"));
    assert!(
        failure.message.contains("route.tor (Tor route)"),
        "{failure:?}"
    );
}

#[test]
fn permissions_come_before_the_node_and_the_node_before_the_limits() {
    let fx = Fx::new("perm-node-limit");
    let mut limited = owner();
    limited.limits = Limits {
        priority_max: Some(5),
        max_run_s: Some(600),
        ..Limits::default()
    };
    let tor_urgent = RunRequest {
        priority: Some(9),
        ..with(json!({"network": {"route": "tor"}}))
    };
    // Without route.tor: permission_denied, though the priority is too high.
    let mut lacking = caller(1000);
    lacking.limits = limited.limits.clone();
    let failure = failure_of(&fx, &lacking, tor_urgent.clone());
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(failure.details["needs"], json!(["route.tor"]));
    // With it: the node has no route set up, before the limit.
    let failure = failure_of(&fx, &limited, tor_urgent);
    assert_eq!(failure.code, FailureCode::UnavailableOnNode);
    assert_eq!(failure.field.as_deref(), Some("network.route"));
    assert_eq!(failure.details["what"], json!("route.tor"));
    // Only the priority: the caller's limit answers, naming it.
    let failure = failure_of(
        &fx,
        &limited,
        RunRequest {
            priority: Some(9),
            ..spec(1)
        },
    );
    assert_eq!(failure.code, FailureCode::LimitExceeded);
    assert_eq!(failure.field.as_deref(), Some("priority"));
    assert_eq!(
        failure.details,
        json!({"field": "priority", "limit": 5, "source": "caller"})
            .as_object()
            .unwrap()
            .clone()
    );
    let failure = failure_of(&fx, &limited, with(json!({"program": {"run_time_s": 601}})));
    assert_eq!(failure.code, FailureCode::LimitExceeded);
    assert_eq!(failure.field.as_deref(), Some("program.run_time_s"));
    assert_eq!(failure.details["limit"], json!(600));
    // A caller without limits: priority 9 is fine, 1800 s the node ceiling.
    let job = fx
        .submit_as(
            &owner(),
            RunRequest {
                priority: Some(9),
                ..with(json!({"program": {"run_time_s": 1800}}))
            },
        )
        .unwrap()
        .run;
    assert_eq!(job.state, RunState::Queued);
}

#[test]
fn an_unknown_preset_is_preset_denied_and_stores_nothing() {
    let fx = Fx::new("perm-preset");
    let error = fx
        .submit_as(
            &owner(),
            RunRequest {
                preset: Some("gone".into()),
                ..with(json!({"network": {"route": "tor"}}))
            },
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PresetDenied);
    assert_eq!(error.field.as_deref(), Some("preset"));
    assert_eq!(error.details["preset"], json!("gone"));
    assert_eq!(fx.store.counts().unwrap(), Default::default());
}

#[test]
fn every_live_route_needs_its_own_permission_then_the_node() {
    let fx = Fx::new("perm-routes");
    for (route, permission, key) in [
        ("internet", Permission::RouteInternet, "route.internet"),
        ("nat", Permission::RouteNat, "route.nat"),
        ("tor", Permission::RouteTor, "route.tor"),
        ("vpn:work", Permission::RouteVpn, "route.vpn"),
        ("socks5", Permission::RouteSocks5, "route.socks5"),
    ] {
        let asked = with(json!({"network": {"route": route}}));
        let failure = failure_of(&fx, &caller(1000), asked.clone());
        assert_eq!(failure.code, FailureCode::PermissionDenied, "{key}");
        assert_eq!(failure.details["needs"], json!([key]));
        // Another route's permission does not help.
        let other = if permission == Permission::RouteTor {
            Permission::RouteVpn
        } else {
            Permission::RouteTor
        };
        let failure = failure_of(&fx, &holding(&[other]), asked.clone());
        assert_eq!(failure.code, FailureCode::PermissionDenied, "{key}");
        let failure = failure_of(&fx, &holding(&[permission]), asked);
        assert_eq!(failure.code, FailureCode::UnavailableOnNode, "{key}");
        assert!(failure.message.contains("not set up on this node"));
    }
    // None (drop) and InetSim need no permission.
    for route in [Route::Drop, Route::InetSim] {
        let job = fx
            .submit_as(
                &caller(1000),
                with(json!({"network": {"route": route.to_string()}})),
            )
            .unwrap()
            .run;
        assert_eq!(job.state, RunState::Queued, "{route:?}");
        fx.store.cancel(&job.id, None, &caller(1000)).unwrap();
    }
}

#[test]
fn keeping_the_vm_needs_run_keep_vm_and_then_arrives_with_0_9_1() {
    let fx = Fx::new("perm-keep");
    let keep = with(json!({"vm": {"keep_on_failure": true}}));
    let failure = failure_of(&fx, &caller(1000), keep.clone());
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(failure.details["needs"], json!(["run.keep_vm"]));
    let failure = failure_of(&fx, &holding(&[Permission::RunKeepVm]), keep);
    assert_eq!(failure.code, FailureCode::UnavailableOnNode);
    assert_eq!(failure.field.as_deref(), Some("vm.keep_on_failure"));
    assert_eq!(failure.message, "keeping a VM arrives with 0.9.1");
    assert_eq!(failure.details["what"], json!("keep_vm"));
    // Asking not to keep it needs nothing.
    let job = fx
        .submit_as(
            &caller(1000),
            with(json!({"vm": {"keep_on_failure": false}})),
        )
        .unwrap()
        .run;
    assert_eq!(job.state, RunState::Queued);
}

#[test]
fn root_and_an_id_below_1000_need_run_as_root_and_nobody_does_not() {
    let fx = Fx::new("perm-ids");
    for (uid, gid) in [(0, 1000), (1000, 0), (999, 999)] {
        let asked = with(json!({"program": {"user": "custom", "uid": uid, "gid": gid}}));
        let failure = failure_of(&fx, &caller(1000), asked.clone());
        assert_eq!(failure.code, FailureCode::PermissionDenied);
        assert_eq!(failure.details["needs"], json!(["run.as_root"]));
        assert_eq!(failure.field.as_deref(), Some("program.user"));
        let job = fx
            .submit_as(&holding(&[Permission::RunAsRoot]), asked)
            .unwrap()
            .run;
        assert_eq!(job.state, RunState::Queued, "{uid}:{gid}");
    }
    let root = with(json!({"program": {"user": "root"}}));
    assert_eq!(
        failure_of(&fx, &caller(1000), root).details["needs"],
        json!(["run.as_root"])
    );
    for plain in [
        json!({"program": {"user": "custom", "uid": 1000, "gid": 1000}}),
        json!({"program": {"user": "nobody"}}),
    ] {
        assert_eq!(
            fx.submit_as(&caller(1000), with(plain)).unwrap().run.state,
            RunState::Queued
        );
    }
}

#[test]
fn the_run_is_checked_as_it_will_run_with_the_preset_values() {
    // The preset takes a core on exit: the run needs evidence.core_dump even
    // though the spec asks for nothing.
    let fx = Fx::with_policy("perm-defaults", |p| p.dumps.core_dump_on_exit = true);
    let failure = failure_of(&fx, &caller(1000), spec(1));
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(failure.details["needs"], json!(["evidence.core_dump"]));
    assert_eq!(failure.field.as_deref(), Some("dumps.core_dump_on_exit"));
    let job = fx
        .submit_as(&holding(&[Permission::EvidenceCoreDump]), spec(1))
        .unwrap()
        .run;
    assert_eq!(job.state, RunState::Queued);
    // Turning it off makes the run Custom, and it needs nothing.
    let off = fx
        .submit_as(
            &caller(1000),
            with(json!({"dumps": {"core_dump_on_exit": false}})),
        )
        .unwrap()
        .run;
    assert_eq!(off.state, RunState::Queued);
    assert_eq!(off.preset.name, "custom");

    // The dump trigger needs the permission of what it takes.
    let fx = Fx::with_policy("perm-trigger", |p| {
        p.dumps.dump_when_suspicious = true;
        p.dumps.minimum_tier = TriggerTier::Medium;
        p.dumps.trigger_memory_dump = true;
        p.detection.check_online = true;
    });
    let failure = failure_of(&fx, &caller(1000), spec(1));
    assert_eq!(
        failure.details["needs"],
        json!([
            "evidence.core_dump",
            "evidence.memory_dump",
            "lookup.online"
        ])
    );
    assert_eq!(failure.field.as_deref(), Some("dumps.trigger_core"));
    let all = holding(&[
        Permission::EvidenceCoreDump,
        Permission::EvidenceMemoryDump,
        Permission::LookupOnline,
    ]);
    assert_eq!(
        fx.submit_as(&all, spec(1)).unwrap().run.state,
        RunState::Queued
    );
}

#[test]
fn a_preset_locks_nothing_only_permissions_do() {
    // Arguments, environment, routes without risk and the user nobody were
    // switches or ceilings of a 0.9.0 policy; a preset only fills them in.
    let fx = Fx::with_policy("perm-nothing-locked", |p| p.program.user = User::Normal);
    let job = fx
        .submit_as(
            &caller(1000),
            with(json!({
                "program": {"arguments": ["-v"], "environment": ["A=1"], "user": "nobody",
                            "run_time_s": 1800},
                "network": {"route": "inet_sim"},
                "detection": {"ids": false},
                "dumps": {"core_budget_mib": 1024}
            })),
        )
        .unwrap()
        .run;
    assert_eq!(job.state, RunState::Queued, "{:?}", job.failure);
    // Values out of range are invalid_argument and store nothing.
    for (overrides, field) in [
        (
            json!({"program": {"run_time_s": 1801}}),
            "overrides.program.run_time_s",
        ),
        (
            json!({"program": {"run_time_s": 4}}),
            "overrides.program.run_time_s",
        ),
        (
            json!({"dumps": {"core_budget_mib": 2048}}),
            "overrides.dumps.core_budget_mib",
        ),
        (
            json!({"program": {"environment": ["NOEQUALS"]}}),
            "overrides.program.environment",
        ),
        (
            json!({"program": {"working_directory": "tmp"}}),
            "overrides.program.working_directory",
        ),
    ] {
        let error = fx.submit_as(&owner(), with(overrides)).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.field.as_deref(), Some(field));
    }
    assert_eq!(fx.store.counts().unwrap().queued, 1);
}

#[test]
fn cancel_needs_runs_submit_for_an_own_job_and_runs_manage_any_for_another() {
    let fx = Fx::new("perm-cancel");
    let job = fx.queued(1);
    let error = fx
        .store
        .cancel(&job.id, None, &Caller::new("local:1000", &[]))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        error.details["needs"],
        json!(["runs.submit", "runs.manage_any"])
    );
    let error = fx.store.cancel(&job.id, None, &caller(2000)).unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(error.details["needs"], json!(["runs.manage_any"]));
    let manager = Caller::new("local:2000", &[Permission::RunsManageAny]);
    let cancelled = fx.store.cancel(&job.id, None, &manager).unwrap();
    assert_eq!(cancelled.state, RunState::Cancelled);
    let own = fx.queued(2);
    let cancelled = fx
        .store
        .cancel(
            &own.id,
            None,
            &Caller::new("local:1000", &[Permission::RunsSubmit]),
        )
        .unwrap();
    assert_eq!(cancelled.state, RunState::Cancelled);
}
