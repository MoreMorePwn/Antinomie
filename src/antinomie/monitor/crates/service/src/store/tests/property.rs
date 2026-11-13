// SPDX-License-Identifier: GPL-3.0-only
//! A property test over random sequences of operations (design 7.2, 8 row
//! P3-2): whatever is done, the store keeps its invariants.

use super::*;
use crate::api::{
    event::EventBody,
    failure::Failure,
    ids::RunId,
    run::{Outcome, Run, RunState, Stage, WaitingFor},
};
use crate::store::{machine, mirror::job_events};
use std::collections::HashMap;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const STAGES: [Stage; 8] = [
    Stage::Provision,
    Stage::Upload,
    Stage::Launch,
    Stage::Run,
    Stage::Collect,
    Stage::Analyse,
    Stage::Report,
    Stage::Cleanup,
];

fn check_invariants(fx: &Fx, seen: &mut HashMap<RunId, RunState>) {
    let all = fx
        .store
        .list(
            &crate::api::ops::RunListParams {
                limit: Some(200),
                ..Default::default()
            },
            None,
        )
        .unwrap()
        .runs;
    for job in &all {
        // State and outcome agree.
        assert_eq!(job.outcome, job.state.outcome(), "{:?}", job.state);
        assert_eq!(job.finished_ms.is_some(), job.state.is_terminal());
        // A stage only while a lane works on it; a wait only while queued.
        assert_eq!(
            job.stage.is_some(),
            matches!(job.state, RunState::Running | RunState::Cancelling),
            "{:?} {:?}",
            job.state,
            job.stage
        );
        if job.waiting_for.is_some() {
            assert_eq!(job.state, RunState::Queued);
        }
        assert_eq!(job.queue_position.is_some(), job.state == RunState::Queued);
        // Failed and rejected explain themselves; partial does not.
        match job.state {
            RunState::Failed | RunState::Rejected => assert!(job.failure.is_some()),
            RunState::Partial | RunState::Succeeded => assert!(job.failure.is_none()),
            _ => {}
        }
        // Every observed change is an edge of the diagram.
        if let Some(before) = seen.insert(job.id.clone(), job.state)
            && before != job.state
        {
            assert!(
                machine::allowed(before, job.state)
                    || (before == RunState::Queued && job.state == RunState::Queued),
                "{before:?} -> {:?}",
                job.state
            );
        }
        // Events: contiguous seq, created first, finished last and only for a terminal job.
        let events = job_events(&fx.store.conn(), &job.id).unwrap();
        let seqs: Vec<u64> = events.iter().map(|e| e.seq.unwrap()).collect();
        assert_eq!(
            seqs,
            (1..=events.len() as u64).collect::<Vec<_>>(),
            "gap in {}",
            job.id
        );
        assert!(matches!(events[0].body, EventBody::RunCreated { .. }));
        let finished = events
            .iter()
            .filter(|e| matches!(e.body, EventBody::RunFinished { .. }))
            .count();
        assert_eq!(
            finished,
            usize::from(job.state.is_terminal()),
            "{:?}",
            job.state
        );
        if job.state.is_terminal() {
            assert!(matches!(
                events.last().unwrap().body,
                EventBody::RunFinished { .. }
            ));
        }
    }
    let all_events = fx.store.events_since(0, 10_000).unwrap();
    let gseqs: Vec<u64> = all_events.iter().map(|e| e.gseq.unwrap()).collect();
    assert!(gseqs.windows(2).all(|w| w[0] < w[1]));
}

fn one_run(seed: u64) {
    let mut fx = Fx::with_policy(&format!("prop-{seed}"), |p| {
        p.retry.max_attempts = 3;
    });
    fx.store
        .conn()
        .pragma_update(None, "synchronous", "OFF")
        .unwrap();
    fx.limits = SubmitLimits {
        max_queued: 20,
        per_client_queued: 20,
        wait_s: 50,
    };
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut jobs: Vec<Run> = Vec::new();
    let mut seen = HashMap::new();
    for step in 0..120 {
        let pick = |rng: &mut Rng, jobs: &[Run]| {
            jobs.get(rng.below(jobs.len().max(1))).map(|j| j.id.clone())
        };
        match rng.below(12) {
            0..=2 => {
                let n = 1 + rng.below(12) as u8; // some samples do not exist: rejected
                let mut s = spec(n);
                s.priority = Some(rng.below(10) as u8);
                if let Ok(submitted) =
                    fx.store
                        .submit(&caller(1000 + rng.below(3) as u32), s, &fx.ctx())
                {
                    jobs.push(submitted.run);
                }
            }
            3 | 4 => {
                let wait = rng.below(4);
                let _ = fx.store.claim_next(&lane(), &mut |_| match wait {
                    0 => Eligibility::Wait(WaitingFor::Resources),
                    1 => Eligibility::Wait(WaitingFor::Lane),
                    _ => Eligibility::Ready,
                });
            }
            5 => {
                if let Some(id) = pick(&mut rng, &jobs) {
                    let _ = fx.store.begin_stage(&id, STAGES[rng.below(STAGES.len())]);
                }
            }
            6 => {
                if let Some(id) = pick(&mut rng, &jobs) {
                    let outcome = [
                        Outcome::Succeeded,
                        Outcome::Partial,
                        Outcome::Failed,
                        Outcome::Cancelled,
                    ][rng.below(4)];
                    let failure = (outcome == Outcome::Failed)
                        .then(|| Failure::new(FailureCode::Internal, Stage::Run, "x", None));
                    let _ = fx.store.finish(&id, outcome, failure);
                }
            }
            7 => {
                if let Some(id) = pick(&mut rng, &jobs) {
                    let _ = fx
                        .store
                        .cancel(&id, None, &caller(1000 + rng.below(3) as u32));
                }
            }
            8 => {
                if let Some(id) = pick(&mut rng, &jobs) {
                    let kind = [
                        RequeueKind::Retry,
                        RequeueKind::Shutdown,
                        RequeueKind::ServiceRestart,
                    ][rng.below(3)];
                    let backoff = [None, Some(10)][rng.below(2)];
                    let _ = fx.store.requeue(&id, kind, "random", None, backoff);
                }
            }
            9 => {
                if let Some(id) = pick(&mut rng, &jobs) {
                    let _ = fx.store.cancel_for_shutdown(&id);
                }
            }
            10 => {
                fx.clock.advance(rng.below(40_000) as u64);
                let _ = fx.store.expire_waits();
            }
            _ => {
                // The process dies and starts again.
                fx.reopen();
                fx.store
                    .conn()
                    .pragma_update(None, "synchronous", "OFF")
                    .unwrap();
                fx.store.recover().unwrap();
            }
        }
        check_invariants(&fx, &mut seen);
        let _ = step;
    }
    // At the end, recovery makes every mirror equal its table.
    fx.reopen();
    fx.store.recover().unwrap();
    for id in seen.keys() {
        let stored = job_events(&fx.store.conn(), id).unwrap();
        let text =
            std::fs::read_to_string(fx.store.job_dir(id).join("events.ndjson")).unwrap_or_default();
        assert_eq!(text.lines().count(), stored.len(), "mirror of {id}");
    }
    let _ = std::fs::remove_dir_all(&fx.dir);
}

#[test]
fn random_operation_sequences_keep_the_invariants() {
    for seed in 1..=10 {
        one_run(seed);
    }
}
