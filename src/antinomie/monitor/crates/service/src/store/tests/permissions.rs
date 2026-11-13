// SPDX-License-Identifier: GPL-3.0-only
//! `job.submit` against the caller's permissions (ANT-T0489): the check order
//! of the access specification, the codes and what each refusal names.

use super::*;
use crate::api::{
    ops::Permission,
    spec::{CoreDump, Overrides, Route, RunAs, RunAsIds, RunAsName},
};
use crate::config::policy::{TriggerKind, TriggerSetting};
use serde_json::json;

fn owner() -> Caller {
    Caller::with_every_permission("local:1000")
}

fn holding(extra: &[Permission]) -> Caller {
    let mut who = caller(1000);
    who.permissions.extend(extra.iter().copied());
    who
}

fn with(overrides: Overrides) -> JobSpec {
    JobSpec {
        overrides,
        ..spec(1)
    }
}

fn failure_of(fx: &Fx, who: &Caller, spec: JobSpec) -> Failure {
    let job = fx.submit_as(who, spec).unwrap().job;
    assert_eq!(job.state, JobState::Rejected, "{:?}", job.failure);
    job.failure.unwrap()
}

#[test]
fn a_refusal_names_every_missing_permission_in_the_documented_order() {
    let fx = Fx::new("perm-order");
    let failure = failure_of(
        &fx,
        &caller(1000),
        with(Overrides {
            memory_dump: Some(true),
            run_as: Some(RunAs::Named(RunAsName::Root)),
            route: Some(Route::Tor),
            core_dump: Some(CoreDump::Switch(true)),
            ..Default::default()
        }),
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
    // The field is the first missing permission's.
    assert_eq!(failure.field.as_deref(), Some("overrides.route"));
    assert!(
        failure.message.contains("route.tor (Tor route)"),
        "{failure:?}"
    );
}

#[test]
fn permissions_come_before_the_node_and_the_node_before_the_limits() {
    let fx = Fx::new("perm-node-limit");
    let tor_urgent = JobSpec {
        priority: Some(9),
        ..with(Overrides {
            route: Some(Route::Tor),
            ..Default::default()
        })
    };
    // Without route.tor: permission_denied, though the priority is too high.
    let failure = failure_of(&fx, &caller(1000), tor_urgent.clone());
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(failure.details["needs"], json!(["route.tor"]));
    // With it: the node has no route set up, before the limit.
    let failure = failure_of(&fx, &owner(), tor_urgent);
    assert_eq!(failure.code, FailureCode::UnavailableOnNode);
    assert_eq!(failure.field.as_deref(), Some("overrides.route"));
    assert_eq!(failure.details["what"], json!("route.tor"));
    // Only the priority: the limit answers, naming it.
    let failure = failure_of(
        &fx,
        &owner(),
        JobSpec {
            priority: Some(9),
            ..spec(1)
        },
    );
    assert_eq!(failure.code, FailureCode::LimitExceeded);
    assert_eq!(failure.field.as_deref(), Some("priority"));
    assert_eq!(
        failure.details,
        json!({"field": "priority", "limit": 5, "source": "policy"})
            .as_object()
            .unwrap()
            .clone()
    );
    let failure = failure_of(
        &fx,
        &owner(),
        with(Overrides {
            timeout_s: Some(1801),
            ..Default::default()
        }),
    );
    assert_eq!(failure.code, FailureCode::LimitExceeded);
    assert_eq!(failure.details["limit"], json!(1800));
}

#[test]
fn the_preset_check_comes_before_the_permissions() {
    let mut fx = Fx::new("perm-preset");
    fx.policies = PolicySet::single(policy("default", |p| {
        p.access.clients = vec!["web:*".into()];
    }));
    let failure = failure_of(
        &fx,
        &caller(1000),
        with(Overrides {
            route: Some(Route::Tor),
            ..Default::default()
        }),
    );
    assert_eq!(failure.code, FailureCode::PresetDenied);
}

#[test]
fn every_live_route_needs_its_own_permission_then_the_node() {
    let fx = Fx::new("perm-routes");
    for (route, permission, key) in [
        (Route::Internet, Permission::RouteInternet, "route.internet"),
        (Route::Tor, Permission::RouteTor, "route.tor"),
        (Route::Vpn, Permission::RouteVpn, "route.vpn"),
        (Route::Socks5, Permission::RouteSocks5, "route.socks5"),
    ] {
        let asked = with(Overrides {
            route: Some(route),
            ..Default::default()
        });
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
                with(Overrides {
                    route: Some(route),
                    ..Default::default()
                }),
            )
            .unwrap()
            .job;
        assert_eq!(job.state, JobState::Queued, "{route:?}");
        fx.store.cancel(&job.id, None, &caller(1000)).unwrap();
    }
}

#[test]
fn keeping_the_vm_needs_run_keep_vm_and_then_arrives_with_0_9_1() {
    let fx = Fx::new("perm-keep");
    let keep = with(Overrides {
        keep_on_failure: Some(true),
        ..Default::default()
    });
    let failure = failure_of(&fx, &caller(1000), keep.clone());
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(failure.details["needs"], json!(["run.keep_vm"]));
    let failure = failure_of(&fx, &holding(&[Permission::RunKeepVm]), keep);
    assert_eq!(failure.code, FailureCode::UnavailableOnNode);
    assert_eq!(failure.field.as_deref(), Some("overrides.keep_on_failure"));
    assert_eq!(failure.message, "keeping a VM arrives with 0.9.1");
    assert_eq!(failure.details["what"], json!("keep_vm"));
    // Asking not to keep it needs nothing.
    let job = fx
        .submit_as(
            &caller(1000),
            with(Overrides {
                keep_on_failure: Some(false),
                ..Default::default()
            }),
        )
        .unwrap()
        .job;
    assert_eq!(job.state, JobState::Queued);
}

#[test]
fn an_id_below_1000_needs_run_as_root() {
    let fx = Fx::with_policy("perm-ids", |p| p.run.allow_root = true);
    for (uid, gid) in [(0, 1000), (1000, 0), (999, 999)] {
        let asked = with(Overrides {
            run_as: Some(RunAs::Ids(RunAsIds { uid, gid })),
            ..Default::default()
        });
        let failure = failure_of(&fx, &caller(1000), asked.clone());
        assert_eq!(failure.code, FailureCode::PermissionDenied);
        assert_eq!(failure.details["needs"], json!(["run.as_root"]));
        let job = fx
            .submit_as(&holding(&[Permission::RunAsRoot]), asked)
            .unwrap()
            .job;
        assert_eq!(job.state, JobState::Queued, "{uid}:{gid}");
    }
    let plain = with(Overrides {
        run_as: Some(RunAs::Ids(RunAsIds {
            uid: 1000,
            gid: 1000,
        })),
        ..Default::default()
    });
    assert_eq!(
        fx.submit_as(&caller(1000), plain).unwrap().job.state,
        JobState::Queued
    );
}

#[test]
fn the_run_is_checked_as_it_will_run_with_the_policy_defaults() {
    // The policy takes a core on exit: the run needs evidence.core_dump even
    // though the spec asks for nothing.
    let fx = Fx::with_policy("perm-defaults", |p| p.evidence.core_dump = true);
    let failure = failure_of(&fx, &caller(1000), spec(1));
    assert_eq!(failure.code, FailureCode::PermissionDenied);
    assert_eq!(failure.details["needs"], json!(["evidence.core_dump"]));
    assert_eq!(failure.field.as_deref(), Some("overrides.core_dump"));
    let job = fx
        .submit_as(&holding(&[Permission::EvidenceCoreDump]), spec(1))
        .unwrap()
        .job;
    assert_eq!(job.state, JobState::Queued);

    // The dump trigger needs the permission of what it would take.
    let fx = Fx::with_policy("perm-trigger", |p| {
        p.evidence.dump_trigger = TriggerSetting::Medium;
        p.evidence.dump_trigger_kind = TriggerKind::Both;
        p.analysis.online_ioc = true;
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
    assert_eq!(
        failure.field.as_deref(),
        Some("policy.evidence.dump_trigger_kind")
    );
    let all = holding(&[
        Permission::EvidenceCoreDump,
        Permission::EvidenceMemoryDump,
        Permission::LookupOnline,
    ]);
    assert_eq!(
        fx.submit_as(&all, spec(1)).unwrap().job.state,
        JobState::Queued
    );
}

#[test]
fn the_policy_ceilings_come_after_the_permissions_and_store_nothing() {
    let fx = Fx::new("perm-ceilings");
    // The owner holds run.as_root; the policy still forbids root.
    let error = fx
        .submit_as(
            &owner(),
            with(Overrides {
                run_as: Some(RunAs::Named(RunAsName::Root)),
                ..Default::default()
            }),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.field.as_deref(), Some("overrides.run_as"));
    let error = fx
        .submit_as(
            &caller(1000),
            with(Overrides {
                env: Some(vec!["A=1".into()]),
                ..Default::default()
            }),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.field.as_deref(), Some("overrides.env"));
    let error = fx
        .submit_as(
            &owner(),
            with(Overrides {
                memory_dump: Some(true),
                ..Default::default()
            }),
        )
        .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("overrides.memory_dump"));
    assert_eq!(fx.store.counts().unwrap(), Default::default());
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
    assert_eq!(cancelled.state, JobState::Cancelled);
    let own = fx.queued(2);
    let cancelled = fx
        .store
        .cancel(
            &own.id,
            None,
            &Caller::new("local:1000", &[Permission::RunsSubmit]),
        )
        .unwrap();
    assert_eq!(cancelled.state, JobState::Cancelled);
}
