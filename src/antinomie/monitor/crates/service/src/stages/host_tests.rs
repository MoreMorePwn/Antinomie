// SPDX-License-Identifier: GPL-3.0-only
//! The host stages `analyse`, `report` and `cleanup` on a recording fixture
//! (card P3-5): the real Triage crate over a small recording written into a
//! scratch data directory, a `FakeEngine` for the static analysis, a manual
//! clock, and a wrapper that replaces one Triage step where a test needs a
//! failure, a hang or a cancel.
use super::{
    Hosted, StageStop,
    collect::CollectEnd,
    host::{HostTriage, RealTriage, SampleTags},
    tests::{MS, SECOND, W},
};
use crate::clock::Clock;
use crate::{
    api::{
        artifact::ArtifactKind,
        assessment::Label,
        event::{EventBody, StageStatus},
        failure::FailureCode,
        job::{EndReason, Job, JobRecording, JobRun, JobState, Outcome, RecordingPhase, Stage},
    },
    engine::FakeEngine,
    store::{
        JobPatch,
        tests::{lane, manager},
    },
    waiter::Waiter,
};
use antinomie_monitor_core::{
    BackendOptions, ExecRequest, RunState, RunSummary,
    analysis::detection::Engine as DetectionEngine, report::Choices, samples::SampleRef,
};
use antinomie_triage::{
    ArchiveScan, SavedRun, detection::Outcome as DetectOutcome, tests::write_rwx_calls,
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

pub(super) const RUN: &str = "5f3c9a10-run-fixture";

type Hook = Box<dyn Fn(&Arc<AtomicBool>) -> Result<(), String> + Send + Sync>;
type DetectHook =
    Box<dyn Fn() -> Result<Vec<(DetectionEngine, DetectOutcome)>, String> + Send + Sync>;

/// The real Triage with one step replaced.
#[derive(Default)]
pub(super) struct Hooked {
    pub(super) real: Option<RealTriage>,
    /// Runs before the scan; an `Err` is the scan's result.
    pub(super) index: Option<Hook>,
    pub(super) detect: Option<DetectHook>,
    pub(super) write_error: Option<String>,
    pub(super) datasets: u32,
    pub(super) scans: AtomicU32,
}

impl Hooked {
    fn real(&self) -> &RealTriage {
        self.real.as_ref().expect("a real triage")
    }
}

impl HostTriage for Hooked {
    fn open_run(&self, job: &Job) -> Result<SavedRun, String> {
        self.real().open_run(job)
    }

    fn index(&self, saved: &SavedRun, cancel: &Arc<AtomicBool>) -> Result<ArchiveScan, String> {
        self.scans.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = &self.index {
            hook(cancel)?;
        }
        self.real().index(saved, cancel)
    }

    fn detect(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        engines: &[DetectionEngine],
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<(DetectionEngine, DetectOutcome)>, String> {
        match &self.detect {
            Some(hook) => hook(),
            None => self.real().detect(saved, scan, engines, cancel),
        }
    }

    fn save_digest(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        outcomes: &[(DetectionEngine, DetectOutcome)],
    ) -> Result<(), String> {
        self.real().save_digest(saved, scan, outcomes)
    }

    fn ensure_digest(&self, job: &Job, cancel: &Arc<AtomicBool>) -> Result<Option<String>, String> {
        self.real().ensure_digest(job, cancel)
    }

    fn build(
        &self,
        saved: &SavedRun,
        scan: &ArchiveScan,
        choices: Choices,
        now_ms: u64,
    ) -> Result<super::host::Built, String> {
        self.real().build(saved, scan, choices, now_ms)
    }

    fn write(
        &self,
        built: super::host::Built,
        cancel: &Arc<AtomicBool>,
    ) -> Result<antinomie_monitor_core::report::export::Written, String> {
        if let Some(error) = &self.write_error {
            return Err(error.clone());
        }
        self.real().write(built, cancel)
    }

    fn ioc_datasets(&self) -> u32 {
        self.datasets
    }
}

/// A policy for host tests: no static analysis (the fake engine would have
/// to script it), no detection engines (no tools on the build machine).
pub(super) fn quiet(p: &mut crate::config::Policy) {
    p.analysis.static_checks =
        crate::api::spec::StaticChecks::Preset(crate::api::spec::StaticPreset::None);
    p.analysis.detection = crate::config::policy::Detection {
        yara: false,
        sigma: false,
        ids: false,
    };
}

pub(super) fn world(name: &str) -> W {
    world_with(name, |_| {})
}

pub(super) fn world_with(name: &str, edit: impl FnOnce(&mut crate::config::Policy)) -> W {
    let mut w = W::with(name, |p| {
        quiet(p);
        edit(p);
    });
    let hooked = Hooked {
        real: Some(real(&w)),
        ..Hooked::default()
    };
    w.triage = Box::new(hooked);
    w
}

pub(super) fn data_dir(w: &W) -> PathBuf {
    w.fx.dir.join("data")
}

fn real(w: &W) -> RealTriage {
    RealTriage::new(BackendOptions {
        data_dir: data_dir(w),
        ..BackendOptions::default()
    })
}

pub(super) fn run_dir(w: &W) -> PathBuf {
    data_dir(w).join("vm-1").join("runs").join(RUN)
}

/// Replace the triage double of `w` by `hooked` (with the real one inside).
pub(super) fn hook(w: &mut W, edit: impl FnOnce(&mut Hooked)) {
    let mut hooked = Hooked {
        real: Some(real(w)),
        ..Hooked::default()
    };
    edit(&mut hooked);
    w.triage = Box::new(hooked);
}

/// Write the recording of a finished run: RWX mapping calls under root
/// cookie 55 and its record (the CLI test's fixture).
pub(super) fn recording(w: &W, sample_sha: &str, telemetry: bool) -> PathBuf {
    let dir = run_dir(w);
    std::fs::create_dir_all(&dir).unwrap();
    if telemetry {
        let mut raw = Vec::new();
        write_rwx_calls(&mut raw, 0..3);
        std::fs::write(dir.join("telemetry.raw"), raw).unwrap();
    }
    let run = RunSummary {
        environment: None,
        reduced: None,
        boot_wait: None,
        triggers: None,
        stopped_by_user: false,
        stopped_at_ms: None,
        persisted: None,
        started_ms: Some(1_792_000_000_000),
        clock_anchor: None,
        id: RUN.into(),
        vm_id: "vm-1".into(),
        boot_id: "boot-1".into(),
        session_id: 1,
        root_task_cookie: 55,
        pid: 42,
        request: ExecRequest {
            path: "/tmp/sample".into(),
            sample: Some(SampleRef {
                sha256: sample_sha.into(),
                name: "fixture.elf".into(),
            }),
            ..ExecRequest::default()
        },
        directory: dir.clone(),
        terminal_eof: true,
        state: RunState::Finished,
        notes: Vec::new(),
        machine: None,
        route: None,
        recording_error: None,
        execution: None,
        analysis: None,
    };
    std::fs::write(dir.join("run.json"), serde_json::to_vec(&run).unwrap()).unwrap();
    dir
}

/// A running job with a finished recording, collected: the lane file has the
/// entry `collect` leaves.
pub(super) fn collected(w: &W, n: u8) -> Job {
    let job = w.fx.running(n);
    let dir = recording(w, job.sample.as_ref().unwrap().sha256.as_str(), true);
    attach(w, &job, &dir, EndReason::Exited);
    job
}

/// Point `job` at the recording in `dir` and mark its lane work collected.
pub(super) fn attach(w: &W, job: &Job, dir: &std::path::Path, end: EndReason) {
    w.fx.store
        .patch(
            &job.id,
            JobPatch {
                run: Some(JobRun {
                    run_id: RUN.into(),
                    started_ms: Some(1),
                    ended_ms: Some(2),
                    end_reason: Some(end),
                    exit: Some(0),
                    signal: None,
                    core_dumped: false,
                    triggers: Vec::new(),
                    trigger_notes: Vec::new(),
                    pending: Vec::new(),
                }),
                recording: Some(JobRecording {
                    vm_id: "vm-1".into(),
                    boot_id: "boot-1".into(),
                    run_id: RUN.into(),
                    run_key: "vm-1:boot-1:5f3c9a10-run-fixture".into(),
                    phase: RecordingPhase::Complete,
                    directory: Some(dir.display().to_string()),
                }),
                ..JobPatch::default()
            },
        )
        .unwrap();
    w.lanes
        .update(&lane(), |file| {
            file.begin_work(job.id.clone(), job.attempt, 1);
            file.collected(2);
        })
        .unwrap();
}

pub(super) fn end_ok() -> CollectEnd {
    CollectEnd {
        outcome: Outcome::Succeeded,
        warnings: Vec::new(),
        pending: Vec::new(),
        artifacts: None,
        cancelled: false,
    }
}

pub(super) fn host(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Job) -> Hosted {
    w.stages(waiter).host(job, &end_ok())
}

fn finished(hosted: Hosted) -> Job {
    match hosted {
        Hosted::Finished(job) => *job,
        other => panic!("{other:?}"),
    }
}

pub(super) fn stage_events(w: &W, job: &Job) -> Vec<(Stage, StageStatus)> {
    w.fx.store
        .events_list(&job.id, 0, 1000)
        .unwrap()
        .0
        .into_iter()
        .filter_map(|e| match e.body {
            EventBody::JobStage { stage, status, .. } => Some((stage, status)),
            _ => None,
        })
        .collect()
}

fn warnings(w: &W, job: &Job) -> Vec<String> {
    w.job(&job.id)
        .warnings
        .into_iter()
        .map(|x| x.code)
        .collect()
}

// ---- the happy path -----------------------------------------------------

#[test]
fn a_collected_job_is_analysed_reported_and_finished() {
    let w = world("host-ok");
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Succeeded);
    assert_eq!(done.outcome, Some(Outcome::Succeeded));

    // The assessment: the facts, a label and the sentence that produced it.
    let a = done.assessment.as_ref().expect("an assessment");
    assert!(a.label.is_some() && !a.basis.is_empty());
    assert_ne!(a.label, Some(Label::Inconclusive), "{}", a.basis);
    assert!(a.counts.processes >= 1, "{a:?}");
    assert!(
        a.basis.contains("No indicator datasets were loaded"),
        "no datasets: {}",
        a.basis
    );
    assert_eq!(a.ioc_dataset_count, 0);

    // The reports are in the job directory, under their stable names, with
    // the hash and size of the bytes on disk.
    let sha8: String = job
        .sample
        .as_ref()
        .unwrap()
        .sha256
        .as_str()
        .chars()
        .take(8)
        .collect();
    let dir = w.fx.store.job_dir(&job.id).join("artifacts");
    let mut names: Vec<_> = done.artifacts.iter().map(|a| a.name.clone()).collect();
    names.sort();
    assert_eq!(
        names,
        [format!("report-{sha8}.html"), format!("report-{sha8}.json")]
    );
    for artifact in &done.artifacts {
        let bytes = std::fs::read(dir.join(&artifact.name)).unwrap();
        assert_eq!(artifact.size, bytes.len() as u64);
        use sha2::{Digest, Sha256};
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(artifact.sha256.as_str(), hash);
        assert!(!artifact.sensitive);
    }
    let html = done
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::ReportHtml)
        .unwrap();
    let json = done
        .artifacts
        .iter()
        .find(|a| a.kind == ArtifactKind::ReportJson)
        .unwrap();
    assert!(!html.raw_indicators, "the policy defangs HTML");
    assert!(json.raw_indicators, "JSON keeps indicators raw");
    // No other file of the writer's own names is left behind.
    let mut on_disk: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    assert_eq!(on_disk, names);

    // Nothing was written into the recording beyond the digest and index
    // Triage keeps there; in particular no report.
    let rec = run_dir(&w);
    assert!(!rec.join("report").exists());
    assert!(rec.join(antinomie_monitor_core::run_digest::FILE).is_file());

    // The stages, in order, each finished; the lane forgot the job; the copy.
    assert_eq!(
        stage_events(&w, &job)
            .into_iter()
            .filter(|(s, _)| *s >= Stage::Analyse)
            .collect::<Vec<_>>(),
        [
            (Stage::Analyse, StageStatus::Started),
            (Stage::Analyse, StageStatus::Finished),
            (Stage::Report, StageStatus::Started),
            (Stage::Report, StageStatus::Finished),
            (Stage::Cleanup, StageStatus::Started),
            (Stage::Cleanup, StageStatus::Finished),
        ]
    );
    assert!(w.lane_file().collected.is_empty());
    let copy: Job = serde_json::from_slice(
        &std::fs::read(w.fx.store.job_dir(&job.id).join("job.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(copy.state, JobState::Succeeded);
    assert_eq!(copy.assessment, done.assessment);
    // No VM command was needed.
    assert!(waiter.engine_mut().sent_names().is_empty());
}

#[test]
fn the_assessment_event_is_sent_once_and_the_label_follows_the_policy_rules() {
    let w = world_with("host-rules", |p| {
        p.verdict.rule = vec![crate::config::policy::VerdictRule {
            when: "counts.processes >= 1".into(),
            label: Label::Malicious,
            score: Some(88),
        }];
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    let a = done.assessment.unwrap();
    assert_eq!((a.label, a.score), (Some(Label::Malicious), Some(88)));
    assert!(a.basis.contains("counts.processes >= 1"));
    let sent =
        w.fx.store
            .events_list(&job.id, 0, 1000)
            .unwrap()
            .0
            .into_iter()
            .filter(|e| matches!(e.body, EventBody::JobAssessment { .. }))
            .count();
    assert_eq!(sent, 1);
}

#[test]
fn tag_library_writes_the_label_and_the_policy_onto_the_sample_and_is_off_by_default() {
    let w = world_with("host-tags", |p| {
        p.verdict.tag_library = true;
        p.verdict.rule = vec![crate::config::policy::VerdictRule {
            when: "counts.processes >= 1".into(),
            label: Label::Suspicious,
            score: None,
        }];
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    let sha = done.sample.as_ref().unwrap().sha256.to_string();
    let tags = w.tags.0.lock().unwrap().clone();
    assert_eq!(
        tags,
        vec![
            (sha.clone(), "auto:policy=default".to_owned()),
            (sha, "auto:label=suspicious".to_owned())
        ]
    );
    // Off (the default): nothing is written.
    let quiet = world("host-notags");
    let job = collected(&quiet, 1);
    let mut waiter = quiet.engine(|_| {});
    finished(host(&quiet, &mut waiter, &job));
    assert!(quiet.tags.0.lock().unwrap().is_empty());
}

#[test]
fn a_digest_detection_with_a_high_yara_severity_makes_the_job_malicious() {
    let w = world("host-yara");
    let job = collected(&w, 1);
    antinomie_monitor_core::run_digest::RunDigest::update(&run_dir(&w), |digest| {
        digest.detections = Some(vec![antinomie_monitor_core::run_digest::DetectionHit {
            engine: "YARA".into(),
            rule_id: "fixture_rule".into(),
            title: "fixture_rule".into(),
            severity: "high".into(),
            count: 2,
            ..Default::default()
        }]);
    })
    .unwrap();
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    let a = done.assessment.unwrap();
    assert_eq!(a.label, Some(Label::Malicious), "{}", a.basis);
    assert!(a.basis.contains("fixture_rule"), "{}", a.basis);
    assert_eq!(a.detections.len(), 1);
    // Triage kept the digest's detection when no engine ran.
    let digest = antinomie_monitor_core::run_digest::RunDigest::read(&run_dir(&w)).unwrap();
    assert_eq!(digest.detections.unwrap().len(), 1);
}

#[test]
fn a_run_that_did_not_complete_is_inconclusive_and_the_datasets_note_follows_the_probe() {
    let mut w = world("host-lost");
    hook(&mut w, |h| h.datasets = 2);
    let job = collected(&w, 1);
    // The run ended with the guest: the label cannot be given.
    attach(&w, &job, &run_dir(&w), EndReason::GuestLost);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    let a = done.assessment.unwrap();
    assert_eq!(a.label, Some(Label::Inconclusive));
    assert!(a.basis.contains("did not complete"), "{}", a.basis);
    assert!(!a.basis.contains("datasets"), "two datasets were loaded");
    assert_eq!(a.ioc_dataset_count, 2);
}

// ---- skips --------------------------------------------------------------

#[test]
fn a_policy_without_formats_skips_report_and_a_policy_without_work_skips_analyse() {
    let w = world_with("host-skip", |p| p.report.formats = Vec::new());
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert!(done.artifacts.is_empty());
    assert!(
        done.assessment.is_some(),
        "the label does not need a report"
    );
    let stages = stage_events(&w, &job);
    assert!(
        stages.contains(&(Stage::Report, StageStatus::Skipped)),
        "{stages:?}"
    );
    assert!(!w.fx.store.job_dir(&job.id).join("artifacts").exists());

    let w = world_with("host-skip2", |p| {
        p.analysis.triage = false;
        p.analysis.required_stages = Vec::new();
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    let stages = stage_events(&w, &job);
    assert!(
        stages.contains(&(Stage::Analyse, StageStatus::Skipped)),
        "{stages:?}"
    );
    assert_eq!(done.assessment.unwrap().label, Some(Label::Inconclusive));
    // Triage did not run, so there is nothing to report either.
    assert_eq!(done.state, JobState::Partial);
    assert!(warnings(&w, &job).contains(&"report_failed".to_owned()));
}

// ---- failures -----------------------------------------------------------

#[test]
fn a_missing_recording_fails_a_required_analyse_stage() {
    let w = world("host-gone");
    let job = w.fx.running(1);
    // The job names a recording that is not there.
    attach(&w, &job, &run_dir(&w), EndReason::Exited);
    let mut waiter = w.engine(|_| {});
    let Hosted::Failed(done) = host(&w, &mut waiter, &job) else {
        panic!("a failed job");
    };
    let failure = done.failure.unwrap();
    assert_eq!(failure.code, FailureCode::AnalysisFailed);
    assert_eq!(failure.stage, Stage::Analyse);
    assert_eq!(done.state, JobState::Failed);
    assert!(w.lane_file().collected.is_empty(), "the lane let it go");
    // The recording is the engine's to keep: the job did not touch it.
    assert!(!w.fx.store.job_dir(&job.id).join("artifacts").exists());
    assert_eq!(
        stage_events(&w, &job).last(),
        Some(&(Stage::Analyse, StageStatus::Failed))
    );
}

#[test]
fn a_failed_scan_in_a_stage_the_policy_does_not_require_is_a_warning_and_partial() {
    let mut w = world_with("host-soft", |p| p.analysis.required_stages = Vec::new());
    hook(&mut w, |h| {
        h.index = Some(Box::new(|_| Err("the index is damaged".into())))
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Partial);
    let codes = warnings(&w, &job);
    assert!(codes.contains(&"analysis_failed".to_owned()), "{codes:?}");
    assert!(codes.contains(&"report_failed".to_owned()), "{codes:?}");
    let texts: Vec<_> = w
        .job(&job.id)
        .warnings
        .into_iter()
        .map(|x| x.text)
        .collect();
    assert!(
        texts.iter().any(|t| t.contains("the index is damaged")),
        "{texts:?}"
    );
    // The label exists and says that it could not judge.
    let a = done.assessment.unwrap();
    assert_eq!(a.label, Some(Label::Inconclusive));
    assert!(a.basis.contains("Triage did not run"));
    assert!(done.artifacts.is_empty());
}

#[test]
fn a_run_whose_scan_failed_still_gets_its_digest_and_a_partial_one_is_a_warning() {
    let mut w = world_with("host-digest", |p| p.analysis.required_stages = Vec::new());
    hook(&mut w, |h| {
        h.index = Some(Box::new(|_| Err("the index is damaged".into())))
    });
    let job = collected(&w, 1);
    // Telemetry was lost: the recording says so in its manifest.
    std::fs::write(
        run_dir(&w).join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "run": {"id": RUN, "vm_id": "vm-1", "boot_id": "boot-1"},
            "health": {"dropped": 1_180_000u64, "storage_dropped_packets": 0},
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(
        !run_dir(&w)
            .join(antinomie_monitor_core::run_digest::FILE)
            .exists()
    );
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Partial);
    let digest = antinomie_monitor_core::run_digest::RunDigest::read(&run_dir(&w))
        .expect("the digest was built although the scan failed");
    let coverage = digest.coverage.unwrap();
    assert!(coverage.partial, "{coverage:?}");
    assert!(coverage.reasons.iter().any(|r| r.contains("dropped")));
    assert!(warnings(&w, &job).contains(&"digest_incomplete".to_owned()));
}

#[test]
fn a_report_that_cannot_be_written_fails_a_required_report_and_degrades_otherwise() {
    let mut w = world_with("host-write", |p| {
        p.analysis.required_stages = vec![Stage::Analyse, Stage::Report];
    });
    hook(&mut w, |h| {
        h.write_error = Some("no space left on device".into())
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let Hosted::Failed(done) = host(&w, &mut waiter, &job) else {
        panic!("failed");
    };
    let failure = done.failure.unwrap();
    assert_eq!(
        (failure.code, failure.stage),
        (FailureCode::AnalysisFailed, Stage::Report)
    );
    assert!(failure.detail.unwrap().contains("no space left"));
    assert!(
        done.assessment.is_some(),
        "the assessment was already stored"
    );

    let mut w = world("host-write2");
    hook(&mut w, |h| {
        h.write_error = Some("no space left on device".into())
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Partial);
    assert!(warnings(&w, &job).contains(&"report_failed".to_owned()));
}

#[test]
fn a_scan_that_never_ends_is_stopped_at_analyse_s() {
    let mut w = world("host-timeout");
    let clock = w.fx.clock.clone();
    hook(&mut w, |h| {
        h.index = Some(Box::new(move |cancel| {
            // The scan has been going for a quarter of an hour.
            clock.advance(901_000);
            while !cancel.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err("cancelled".into())
        }));
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let Hosted::Failed(done) = host(&w, &mut waiter, &job) else {
        panic!("failed");
    };
    let failure = done.failure.unwrap();
    assert_eq!(failure.code, FailureCode::AnalysisFailed);
    assert!(
        failure.detail.unwrap().contains("did not finish in time"),
        "the worker was cancelled and joined"
    );
}

#[test]
fn a_cancel_during_the_scan_ends_the_job_cancelled_and_keeps_the_recording() {
    use std::sync::{Mutex, mpsc};
    let mut w = world("host-cancel");
    let job = collected(&w, 1);
    // The scan asks the test thread to cancel the job, then waits to be told.
    let (ask, asked) = mpsc::channel::<()>();
    let (ack, acked) = mpsc::channel::<()>();
    let acked = Mutex::new(acked);
    hook(&mut w, |h| {
        h.index = Some(Box::new(move |cancel| {
            ask.send(()).unwrap();
            acked.lock().unwrap().recv().unwrap();
            while !cancel.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err("cancelled".into())
        }));
    });
    let store = &w.fx.store;
    let id = job.id.clone();
    let hosted = std::thread::scope(|scope| {
        scope.spawn(move || {
            if asked
                .recv_timeout(std::time::Duration::from_secs(20))
                .is_ok()
            {
                store.cancel(&id, Some("test"), &manager()).unwrap();
                let _ = ack.send(());
            }
        });
        let mut waiter = w.engine(|_| {});
        host(&w, &mut waiter, &job)
    });
    let Hosted::Cancelled(done) = hosted else {
        panic!("cancelled: {hosted:?}");
    };
    assert_eq!(done.state, JobState::Cancelled);
    assert!(
        run_dir(&w).join("run.json").is_file(),
        "the recording is kept"
    );
    assert!(w.lane_file().collected.is_empty());
}

#[test]
fn a_cancel_before_the_stages_start_is_honoured_and_a_shutdown_cancel_requeues() {
    let w = world("host-cancel0");
    let job = collected(&w, 1);
    w.fx.store
        .cancel(&job.id, Some("test"), &manager())
        .unwrap();
    let mut waiter = w.engine(|_| {});
    let Hosted::Cancelled(done) = host(&w, &mut waiter, &job) else {
        panic!("cancelled");
    };
    assert_eq!(done.state, JobState::Cancelled);
    assert!(done.artifacts.is_empty() && done.assessment.is_none());

    let w = world("host-shutdown");
    let job = collected(&w, 1);
    w.fx.store.cancel_for_shutdown(&job.id).unwrap();
    let mut waiter = w.engine(|_| {});
    assert!(matches!(host(&w, &mut waiter, &job), Hosted::Requeued));
    assert_eq!(w.job(&job.id).state, JobState::Queued);
    assert!(w.lane_file().collected.is_empty());
}

#[test]
fn analysis_failed_is_repeated_in_place_when_the_policy_retries_it() {
    let mut w = world_with("host-retry", |p| {
        p.retry.retry_on.push(FailureCode::AnalysisFailed);
        p.retry.max_attempts = 3;
    });
    let calls = Arc::new(AtomicU32::new(0));
    let seen = calls.clone();
    hook(&mut w, |h| {
        h.index = Some(Box::new(move |_| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                Err("a transient fault".into())
            } else {
                Ok(())
            }
        }));
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Succeeded);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(warnings(&w, &job), ["analysis_retry"]);
    assert_eq!(
        w.job(&job.id).attempt,
        1,
        "no VM run: the attempt is the same"
    );
    assert_eq!(done.artifacts.len(), 2);
    // Both runs of the stage are recorded under one stage row each.
    let analyse: Vec<_> = stage_events(&w, &job)
        .into_iter()
        .filter(|(s, _)| *s == Stage::Analyse)
        .collect();
    assert_eq!(analyse.len(), 4, "{analyse:?}");
}

#[test]
fn without_the_retry_the_first_failure_ends_the_job() {
    let mut w = world("host-noretry");
    let calls = Arc::new(AtomicU32::new(0));
    let seen = calls.clone();
    hook(&mut w, |h| {
        h.index = Some(Box::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err("fault".into())
        }));
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    assert!(matches!(host(&w, &mut waiter, &job), Hosted::Failed(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// ---- detection ----------------------------------------------------------

#[test]
fn engines_run_after_the_scan_and_a_failed_or_skipped_one_is_reported() {
    let mut w = world_with("host-detect", |p| {
        p.analysis.detection.yara = true;
        p.analysis.detection.ids = true;
        p.analysis.required_stages = Vec::new();
    });
    hook(&mut w, |h| {
        h.detect = Some(Box::new(|| {
            Ok(vec![
                (
                    DetectionEngine::Yara,
                    DetectOutcome::Failed("rules are broken".into()),
                ),
                (
                    DetectionEngine::Ids,
                    DetectOutcome::Skipped(
                        "wait:pcap".into(),
                        "Waiting for the PCAP segment.".into(),
                    ),
                ),
            ])
        }));
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Partial, "an engine that failed");
    let all = w.job(&job.id).warnings;
    assert!(
        all.iter()
            .any(|x| x.code == "analysis_failed" && x.text.contains("rules are broken")),
        "{all:?}"
    );
    assert!(
        all.iter()
            .any(|x| x.code == "detection_skipped" && x.text.contains("PCAP")),
        "{all:?}"
    );
    // The assessment is there all the same: the scan worked.
    assert_ne!(done.assessment.unwrap().label, Some(Label::Inconclusive));
}

#[test]
fn a_required_stage_fails_when_an_engine_fails() {
    let mut w = world_with("host-detect2", |p| p.analysis.detection.yara = true);
    hook(&mut w, |h| {
        h.detect = Some(Box::new(|| {
            Ok(vec![(
                DetectionEngine::Yara,
                DetectOutcome::Failed("boom".into()),
            )])
        }));
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let Hosted::Failed(done) = host(&w, &mut waiter, &job) else {
        panic!("failed");
    };
    assert!(done.failure.unwrap().detail.unwrap().contains("boom"));
}

// ---- static analysis through the engine --------------------------------

fn report_entry(id: &str, state: &str) -> antinomie_monitor_core::analysis::AnalysisReport {
    serde_json::from_value(serde_json::json!({
        "id": id, "state": state, "source_path": "sample:x", "sections": [],
    }))
    .unwrap()
}

fn static_policy(p: &mut crate::config::Policy) {
    p.analysis.static_checks = crate::api::spec::StaticChecks::Names(vec![
        crate::api::spec::StaticCheck::Metadata,
        crate::api::spec::StaticCheck::Strings,
    ]);
    p.analysis.static_time_limit_min = 1;
    p.analysis.required_stages = Vec::new();
}

#[test]
fn the_static_analysis_of_the_library_copy_goes_through_the_engine() {
    let w = world_with("host-static", static_policy);
    let job = collected(&w, 1);
    let mut waiter = w.engine(|fake| {
        fake.on("AnalyzeSample")
            .after(100 * MS)
            .then(3 * SECOND, |s| {
                s.analysis_reports.push(report_entry("rep-1", "complete"))
            })
            .ok("rep-1");
    });
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Succeeded);
    let sent = waiter.engine_mut().sent();
    assert_eq!(sent.len(), 1);
    let text = format!("{:?}", sent[0]);
    assert!(
        text.contains("AnalyzeSample") && text.contains("Metadata") && text.contains("Strings"),
        "{text}"
    );
    assert!(text.contains(&job.sample.as_ref().unwrap().sha256.to_string()));
}

#[test]
fn a_refused_or_unfinished_static_analysis_is_a_problem_not_a_stop() {
    // Refused.
    let w = world_with("host-static-refused", static_policy);
    let job = collected(&w, 1);
    let mut waiter = w.engine(|fake| {
        fake.on("AnalyzeSample").fail("bubblewrap is not usable");
    });
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Partial);
    let texts: Vec<_> = w
        .job(&job.id)
        .warnings
        .into_iter()
        .map(|x| x.text)
        .collect();
    assert!(texts.iter().any(|t| t.contains("bubblewrap")), "{texts:?}");
    assert!(
        !done.artifacts.is_empty(),
        "triage and the report still ran"
    );

    // Never finishes: tools x limit x 60 + 60 = 180 s for two tools at 1 minute.
    let w = world_with("host-static-slow", static_policy);
    let job = collected(&w, 1);
    let began = w.fx.clock.now_ms();
    let mut waiter = w.engine(|fake| {
        fake.on("AnalyzeSample")
            .then(SECOND, |s| {
                s.analysis_reports.push(report_entry("rep-1", "running"))
            })
            .ok("rep-1");
    });
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Partial);
    let took = (w.fx.clock.now_ms() - began) / 1000;
    assert!(
        (180..260).contains(&took),
        "static_s was waited out: {took} s"
    );
    assert!(
        w.job(&job.id)
            .warnings
            .iter()
            .any(|x| x.text.contains("did not finish within 180"))
    );

    // Finished partly: a warning, the job is partial.
    let w = world_with("host-static-part", static_policy);
    let job = collected(&w, 1);
    let mut waiter = w.engine(|fake| {
        fake.on("AnalyzeSample")
            .then(SECOND, |s| {
                s.analysis_reports.push(report_entry("rep-1", "partial"))
            })
            .ok("rep-1");
    });
    let done = finished(host(&w, &mut waiter, &job));
    assert_eq!(done.state, JobState::Partial);
}

#[test]
fn a_required_stage_fails_on_a_static_analysis_problem() {
    let w = world_with("host-static-req", |p| {
        static_policy(p);
        p.analysis.required_stages = vec![Stage::Analyse];
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|fake| {
        fake.on("AnalyzeSample").fail("no room");
    });
    let Hosted::Failed(done) = host(&w, &mut waiter, &job) else {
        panic!("failed");
    };
    assert_eq!(done.failure.unwrap().code, FailureCode::AnalysisFailed);
}

fn report_with_sections(
    id: &str,
    state: &str,
    sections: &[(&str, &str)],
) -> antinomie_monitor_core::analysis::AnalysisReport {
    let sections: Vec<_> = sections
        .iter()
        .map(|(kind, state)| {
            serde_json::json!({
                "kind": kind, "state": state, "summary": "", "entries": [],
            })
        })
        .collect();
    serde_json::from_value(serde_json::json!({
        "id": id, "state": state, "source_path": "sample:x", "sections": sections,
    }))
    .unwrap()
}

fn analyse_with(
    name: &str,
    required_stage: bool,
    required_checks: Vec<crate::api::spec::StaticCheck>,
    report: antinomie_monitor_core::analysis::AnalysisReport,
) -> (W, Job, Hosted) {
    let w = world_with(name, |p| {
        static_policy(p);
        if required_stage {
            p.analysis.required_stages = vec![Stage::Analyse];
        }
        p.analysis.required_checks = required_checks;
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(move |fake| {
        fake.on("AnalyzeSample")
            .then(SECOND, move |s| s.analysis_reports.push(report.clone()))
            .ok("rep-1");
    });
    let hosted = host(&w, &mut waiter, &job);
    (w, job, hosted)
}

#[test]
fn a_timed_out_optional_check_makes_the_job_partial_even_when_analyse_is_required() {
    let report = report_with_sections(
        "rep-1",
        "partial",
        &[("metadata", "complete"), ("strings", "timeout")],
    );
    let (w, job, hosted) = analyse_with("host-static-timeout", true, Vec::new(), report);
    let done = finished(hosted);
    assert_eq!(done.state, JobState::Partial);
    assert!(done.failure.is_none());
    let warnings = w.job(&job.id).warnings;
    assert!(
        warnings.iter().any(|x| x.code == "static_check_incomplete"
            && x.text.contains("strings check ran out of time")),
        "{warnings:?}"
    );
    assert!(!warnings.iter().any(|x| x.code == "analysis_failed"));
    assert!(
        !done.artifacts.is_empty(),
        "triage and the report still ran"
    );
}

#[test]
fn a_required_check_that_times_out_fails_the_analyse_stage() {
    let report = report_with_sections(
        "rep-1",
        "partial",
        &[("metadata", "complete"), ("strings", "timeout")],
    );
    let (_, _, hosted) = analyse_with(
        "host-static-required",
        true,
        vec![crate::api::spec::StaticCheck::Strings],
        report,
    );
    let Hosted::Failed(done) = hosted else {
        panic!("failed");
    };
    let failure = done.failure.unwrap();
    assert_eq!(failure.code, FailureCode::AnalysisFailed);
    assert!(failure.detail.unwrap().contains("strings check"));

    // A required check that is not the one that timed out changes nothing.
    let report = report_with_sections(
        "rep-1",
        "partial",
        &[("metadata", "complete"), ("strings", "timeout")],
    );
    let (_, _, hosted) = analyse_with(
        "host-static-required-other",
        true,
        vec![crate::api::spec::StaticCheck::Metadata],
        report,
    );
    assert_eq!(finished(hosted).state, JobState::Partial);
}

#[test]
fn static_checks_that_all_finish_leave_the_job_succeeded() {
    let report = report_with_sections(
        "rep-1",
        "complete",
        &[("metadata", "complete"), ("strings", "complete")],
    );
    let (w, job, hosted) = analyse_with(
        "host-static-clean",
        true,
        vec![crate::api::spec::StaticCheck::Strings],
        report,
    );
    let done = finished(hosted);
    assert_eq!(done.state, JobState::Succeeded);
    assert!(w.job(&job.id).warnings.is_empty());
}

// ---- a crash, and the resume at analyse --------------------------------

#[test]
fn an_engine_that_dies_leaves_the_job_for_the_resume_and_the_resume_finishes_it() {
    let w = world_with("host-resume", static_policy);
    let job = collected(&w, 1);
    // The engine goes away while the static analysis is asked for.
    let mut waiter = w.engine(|fake| {
        fake.on("AnalyzeSample").die();
    });
    let hosted = host(&w, &mut waiter, &job);
    assert!(matches!(hosted, Hosted::Aborted(_)), "{hosted:?}");
    let stuck = w.job(&job.id);
    assert_eq!(stuck.state, JobState::Running);
    assert_eq!(
        w.lane_file().collected.len(),
        1,
        "the entry stays: the resume needs it"
    );
    assert!(stuck.artifacts.is_empty());

    // A new process: the resume runs the stages again from analyse. The
    // stage was left started; entering it again is allowed.
    let mut fresh = w.engine(|fake| {
        fake.on("AnalyzeSample")
            .then(SECOND, |s| {
                s.analysis_reports.push(report_entry("rep-1", "complete"))
            })
            .ok("rep-1");
    });
    let done = finished(w.stages(&mut fresh).resume_host(&stuck));
    assert_eq!(done.state, JobState::Succeeded);
    assert_eq!(done.artifacts.len(), 2);
    assert!(w.lane_file().collected.is_empty());
    let analyse: Vec<_> = stage_events(&w, &job)
        .into_iter()
        .filter(|(s, _)| *s == Stage::Analyse)
        .collect();
    assert_eq!(
        analyse,
        [
            (Stage::Analyse, StageStatus::Started),
            (Stage::Analyse, StageStatus::Started),
            (Stage::Analyse, StageStatus::Finished),
        ]
    );
}

#[test]
fn the_resume_reads_incomplete_evidence_as_partial() {
    let mut w = world("host-resume-partial");
    w.evidence = Box::new(|_| {
        Ok(Some(antinomie_monitor_core::RunArtifacts {
            network_state: antinomie_monitor_core::RunArtifactState::Partial,
            memory_state: antinomie_monitor_core::RunArtifactState::Disabled,
            core_state: antinomie_monitor_core::RunArtifactState::Disabled,
            ..antinomie_monitor_core::RunArtifacts::default()
        }))
    });
    let job = collected(&w, 1);
    let mut waiter = w.engine(|_| {});
    let done = finished(w.stages(&mut waiter).resume_host(&job));
    assert_eq!(done.state, JobState::Partial);
}

#[test]
fn a_stage_that_finished_cannot_be_entered_twice_in_an_attempt() {
    let w = world("host-twice");
    let job = collected(&w, 1);
    let store = &w.fx.store;
    store.begin_stage(&job.id, Stage::Analyse).unwrap();
    store.end_stage(&job.id, StageStatus::Finished).unwrap();
    let error = store.begin_stage(&job.id, Stage::Analyse).unwrap_err();
    assert!(error.to_string().contains("already ran"));
    // A failed one may be entered again.
    store.begin_stage(&job.id, Stage::Report).unwrap();
    store.end_stage(&job.id, StageStatus::Failed).unwrap();
    store.begin_stage(&job.id, Stage::Report).unwrap();
}

// Keep the helpers the other test files of this module reuse.
#[allow(dead_code)]
fn _uses(_: &dyn SampleTags, _: StageStop) {}
