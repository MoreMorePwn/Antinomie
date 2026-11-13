// SPDX-License-Identifier: GPL-3.0-only
//! Limits per caller (card P-A5): the priority ceiling, the queue and
//! running counts per client, and the daily count that exists only when set.

use super::*;
use crate::api::ops::Limits;

fn limited(uid: u32, limits: Limits) -> Caller {
    let mut who = caller(uid);
    who.limits = limits;
    who
}

#[test]
fn a_priority_above_the_ceiling_is_refused_and_one_within_it_is_kept() {
    let fx = Fx::new("limits-priority");
    let who = limited(
        1000,
        Limits {
            priority_max: Some(5),
            ..Limits::default()
        },
    );
    let ask = |n: u8, priority: u8| JobSpec {
        priority: Some(priority),
        ..spec(n)
    };
    // Urgent (8) is above the ceiling: refused, not lowered.
    let refused = fx.submit_as(&who, ask(1, 8)).unwrap();
    assert_eq!(refused.job.state, JobState::Rejected);
    let failure = refused.job.failure.unwrap();
    assert_eq!(failure.code, FailureCode::LimitExceeded);
    assert_eq!(failure.field.as_deref(), Some("priority"));
    assert_eq!(failure.details["limit"], serde_json::json!(5));
    assert_eq!(failure.details["source"], serde_json::json!("caller"));
    // Low (2), Normal (5) and the ceiling itself pass, as asked.
    for (n, priority) in [(2, 2), (3, 5), (4, 0)] {
        let job = fx.submit_as(&who, ask(n, priority)).unwrap().job;
        assert_eq!(job.state, JobState::Queued);
        assert_eq!(job.spec.priority, Some(priority));
    }
    // Nothing asked: Normal, or the ceiling when that is lower.
    let low = limited(
        1001,
        Limits {
            priority_max: Some(2),
            ..Limits::default()
        },
    );
    assert_eq!(
        fx.submit_as(&low, spec(5)).unwrap().job.spec.priority,
        Some(2)
    );
    // Another caller without a ceiling may ask for Urgent.
    let free = fx.submit_as(&caller(1002), ask(6, 8)).unwrap().job;
    assert_eq!(free.state, JobState::Queued);
}

#[test]
fn waiting_time_never_raises_a_priority() {
    let fx = Fx::new("limits-no-ageing");
    let low = fx
        .submit_as(
            &caller(1000),
            JobSpec {
                priority: Some(2),
                ..spec(1)
            },
        )
        .unwrap()
        .job;
    fx.clock.advance(48 * 3_600_000);
    let normal = fx.submit(spec(2)).job;
    let first = fx
        .store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(first.id, normal.id);
    assert_eq!(fx.store.get(&low.id).unwrap().spec.priority, Some(2));
}

#[test]
fn queued_runs_are_counted_per_caller_not_per_preset() {
    let mut fx = Fx::new("limits-queued");
    fx.limits = SubmitLimits {
        max_queued: 50,
        per_client_queued: 50,
        wait_s: 3600,
    };
    let alice = limited(
        1000,
        Limits {
            max_queued: Some(2),
            ..Limits::default()
        },
    );
    let bob = caller(1001);
    // The same preset, two callers.
    fx.submit_as(&alice, spec(1)).unwrap();
    fx.submit_as(&alice, spec(2)).unwrap();
    let error = fx.submit_as(&alice, spec(3)).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert!(error.message.contains("limit 2"));
    // Bob is not counted against her: more than her two pass.
    for n in 3..=6 {
        fx.submit_as(&bob, spec(n)).unwrap();
    }
}

#[test]
fn a_caller_at_max_running_waits_while_the_others_go_on() {
    let fx = Fx::new("limits-running");
    let alice = limited(
        1000,
        Limits {
            max_running: Some(1),
            ..Limits::default()
        },
    );
    // Submitted in this order (the clock moves so the order is certain).
    let a1 = fx.submit_as(&alice, spec(1)).unwrap().job;
    fx.clock.advance(10);
    let a2 = fx.submit_as(&alice, spec(2)).unwrap().job;
    fx.clock.advance(10);
    let b1 = fx.submit_as(&caller(1001), spec(3)).unwrap().job;
    let cap = |job: &Job| (job.client_id == "local:1000").then_some(1);
    let claim = || {
        fx.store
            .claim_next_within(&lane(), &cap, &mut |_| Eligibility::Ready)
            .unwrap()
    };
    assert_eq!(claim().unwrap().id, a1.id);
    // Her second run waits `quota`; Bob's is taken instead.
    assert_eq!(claim().unwrap().id, b1.id);
    assert!(claim().is_none());
    let waiting = fx.store.get(&a2.id).unwrap();
    assert_eq!(waiting.state, JobState::Queued);
    assert_eq!(waiting.waiting_for, Some(WaitingFor::Quota));
    // She finishes the first: the second is taken.
    fx.store.finish(&a1.id, Outcome::Succeeded, None).unwrap();
    assert_eq!(claim().unwrap().id, a2.id);
}

#[test]
fn the_daily_limit_is_off_by_default_and_counted_per_caller_when_set() {
    let fx = Fx::new("limits-daily");
    // Not set: any number of runs in a day.
    for _ in 1..=12 {
        let job = fx.submit_as(&caller(1000), spec(1)).unwrap().job;
        assert_eq!(job.state, JobState::Queued);
    }
    let alice = limited(
        1001,
        Limits {
            max_runs_per_day: Some(2),
            ..Limits::default()
        },
    );
    fx.submit_as(&alice, spec(1)).unwrap();
    fx.submit_as(&alice, spec(1)).unwrap();
    let refused = fx.submit_as(&alice, spec(1)).unwrap();
    assert_eq!(refused.job.state, JobState::Rejected);
    let failure = refused.job.failure.unwrap();
    assert_eq!(failure.code, FailureCode::LimitExceeded);
    assert_eq!(failure.field.as_deref(), Some("max_runs_per_day"));
    assert_eq!(failure.details["limit"], serde_json::json!(2));
    // The refused run did not count: another caller with the same limit has
    // her own two.
    let bob = limited(
        1002,
        Limits {
            max_runs_per_day: Some(2),
            ..Limits::default()
        },
    );
    fx.submit_as(&bob, spec(1)).unwrap();
    fx.submit_as(&bob, spec(1)).unwrap();
    // A day later her count starts again.
    fx.clock.advance(24 * 3_600_000 + 1);
    let again = fx.submit_as(&alice, spec(1)).unwrap().job;
    assert_eq!(again.state, JobState::Queued, "{:?}", again.failure);
}
