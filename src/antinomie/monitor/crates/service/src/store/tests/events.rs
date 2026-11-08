// SPDX-License-Identifier: GPL-3.0-only
//! The event log (design 5.5): ordered, gap-free, resumable, durable.

use super::*;
use crate::api::event::{EventBody, MetricsHealth, MetricsRun, MetricsVm};

fn run_one(fx: &Fx) -> JobId {
    let job = fx.running(1);
    fx.store.begin_stage(&job.id, Stage::Provision).unwrap();
    fx.store.finish(&job.id, Outcome::Succeeded, None).unwrap();
    job.id
}

#[test]
fn seq_counts_from_one_per_job_and_gseq_never_goes_back() {
    let fx = Fx::new("seq");
    let a = fx.queued(1);
    let b = fx.queued(2);
    let a = fx.store.cancel(&a.id, None, &caller(1000)).unwrap().id;
    let (events, next) = fx.store.events_list(&a, 0, 100).unwrap();
    let seqs: Vec<_> = events.iter().map(|e| e.seq.unwrap()).collect();
    assert_eq!(seqs, [1, 2, 3]);
    assert_eq!(next, 3);
    let (events_b, _) = fx.store.events_list(&b.id, 0, 100).unwrap();
    assert_eq!(events_b[0].seq, Some(1));
    // The all-jobs numbers interleave and only rise.
    let all = fx.store.events_since(0, 100).unwrap();
    let gseqs: Vec<_> = all.iter().map(|e| e.gseq.unwrap()).collect();
    assert!(gseqs.windows(2).all(|w| w[0] < w[1]), "{gseqs:?}");
    assert_eq!(fx.store.highest_gseq().unwrap(), *gseqs.last().unwrap());
    assert_eq!(all[0].scope, crate::api::event::EventScope::Job);
}

#[test]
fn a_reader_resumes_after_any_point_with_no_gap_and_no_duplicate() {
    let fx = Fx::new("resume");
    let id = run_one(&fx);
    let (all, _) = fx.store.events_list(&id, 0, 100).unwrap();
    assert!(all.len() >= 6);
    for cut in 0..=all.len() {
        let after = if cut == 0 {
            0
        } else {
            all[cut - 1].seq.unwrap()
        };
        let (rest, _) = fx.store.events_list(&id, after, 100).unwrap();
        assert_eq!(rest, all[cut..], "resume after seq {after}");
        let gafter = if cut == 0 {
            0
        } else {
            all[cut - 1].gseq.unwrap()
        };
        let again = fx.store.events_since(gafter, 1000).unwrap();
        assert_eq!(again, all[cut..], "resume after gseq {gafter}");
    }
    // Paging by limit sees every event exactly once.
    let mut seen = Vec::new();
    let mut cursor = 0;
    loop {
        let (page, next) = fx.store.events_list(&id, cursor, 2).unwrap();
        if page.is_empty() {
            break;
        }
        seen.extend(page);
        cursor = next;
    }
    assert_eq!(seen, all);
    // Unknown job.
    let missing = JobId::from_parts(1, [0; 10]);
    assert_eq!(
        fx.store.events_list(&missing, 0, 10).unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn the_job_ends_with_job_finished_and_nothing_follows() {
    let fx = Fx::new("finished");
    let id = run_one(&fx);
    let types = kinds(&fx, &id);
    assert_eq!(types.last().unwrap(), "job.finished");
    assert_eq!(types.iter().filter(|t| *t == "job.finished").count(), 1);
    assert!(fx.store.begin_stage(&id, Stage::Run).is_err());
    assert_eq!(kinds(&fx, &id), types);
}

#[test]
fn subscribers_get_committed_events_and_ephemeral_ones_are_not_stored() {
    let fx = Fx::new("subscribe");
    let receiver = fx.store.subscribe();
    let job = fx.queued(1);
    let created = receiver.try_recv().unwrap();
    assert!(matches!(created.body, EventBody::JobCreated { .. }));
    assert_eq!(
        (created.seq, created.job_id.clone()),
        (Some(1), Some(job.id.clone()))
    );
    // Ephemeral events are sent with no seq/gseq and never stored.
    fx.store.publish_ephemeral(
        &job.id,
        EventBody::JobProgress {
            stage: Stage::Upload,
            text: "10 MiB".into(),
            fraction: Some(0.5),
        },
    );
    fx.store.publish_ephemeral(
        &job.id,
        EventBody::JobMetrics {
            stage: Stage::Run,
            vm: MetricsVm::default(),
            run: MetricsRun {
                live_tasks: 1,
                recorded_events: None,
            },
            health: MetricsHealth {
                dropped: 0,
                shedding: false,
            },
        },
    );
    let progress = receiver.try_recv().unwrap();
    assert_eq!((progress.seq, progress.gseq), (None, None));
    receiver.try_recv().unwrap();
    assert_eq!(kinds(&fx, &job.id), ["job.created"]);
    // A write that fails sends nothing.
    fx.store
        .inject_fault(Fault::BeforeCommit, FaultAction::Fail);
    assert!(fx.store.cancel(&job.id, None, &caller(1000)).is_err());
    assert!(receiver.try_recv().is_err());
    // A dropped receiver does not stop the store.
    drop(receiver);
    fx.store.cancel(&job.id, None, &caller(1000)).unwrap();
}

#[test]
fn engine_events_have_their_own_sequence_and_are_pruned() {
    let fx = Fx::new("engine");
    for n in 0..3 {
        fx.store
            .emit_engine(EventBody::EngineAlert {
                code: "low_disk".into(),
                text: format!("{n}"),
            })
            .unwrap();
    }
    let all = fx.store.events_since(0, 100).unwrap();
    assert_eq!(all.len(), 3);
    assert!(
        all.iter()
            .all(|e| e.job_id.is_none() && e.scope == crate::api::event::EventScope::Engine)
    );
    assert_eq!(
        all.iter().map(|e| e.seq.unwrap()).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    // A new epoch restarts the engine seq but never reuses a gseq.
    let high = fx.store.highest_gseq().unwrap();
    let mut fx = fx;
    fx.reopen();
    fx.store
        .emit_engine(EventBody::EngineAlert {
            code: "x".into(),
            text: "y".into(),
        })
        .unwrap();
    let last = fx.store.events_since(high, 10).unwrap();
    assert_eq!((last[0].seq, last[0].gseq), (Some(1), Some(high + 1)));
    // Older than 7 days: pruned. Job events are kept.
    let job = fx.queued(1);
    fx.clock.advance(7 * 24 * 3600 * 1000 + 1);
    assert_eq!(fx.store.prune_engine_events().unwrap(), 4);
    assert_eq!(fx.store.events_since(0, 100).unwrap().len(), 1);
    assert_eq!(kinds(&fx, &job.id), ["job.created"]);
    // gseq still rises past what was deleted.
    assert!(fx.store.highest_gseq().unwrap() > high + 1);
}

#[test]
fn a_stored_event_reads_back_equal_to_what_was_sent() {
    let fx = Fx::new("roundtrip");
    let receiver = fx.store.subscribe();
    let job = fx.running(1);
    fx.store.add_warning(&job.id, "w", "text").unwrap();
    fx.store.finish(&job.id, Outcome::Succeeded, None).unwrap();
    let sent: Vec<_> = std::iter::from_fn(|| receiver.try_recv().ok()).collect();
    let (stored, _) = fx.store.events_list(&job.id, 0, 100).unwrap();
    assert_eq!(sent, stored);
}
