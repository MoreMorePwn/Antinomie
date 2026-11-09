// SPDX-License-Identifier: GPL-3.0-only
//! The daemon's operations (in-process and as a socket client would call
//! them), the lane loop with a scripted lane, and the shutdown rules.

use super::{
    Controls, EngineView, Phase, Stopping,
    lane::{JobEnd, LaneCommand, LaneLoop, LaneRunner, Periods},
    service::Service,
    shutdown_step,
};
use crate::{
    api::{
        artifact::{ArtifactKind, MediaType},
        error::{ApiError, ErrorCode, ErrorReason},
        ids::{JobId, Sha256Hex},
        job::{Job, JobState, Outcome},
        ops::{Caller, Scope},
        status::{Accelerator, Owner},
    },
    clock::SystemClock,
    config::{LoadedPolicy, Policy, PolicySet, ServiceConfig, SharedPolicies, service::Shutdown},
    intake::{Intake, staging::StagingStore},
    lane::LaneDir,
    query::QueryService,
    server::{CallContext, Handler, Transport, b64, local_caller},
    store::{Eligibility, NewArtifact, RequeueKind, Store, tests::scratch},
};
use antinomie_monitor_core::BackendOptions;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, RwLock, mpsc},
    time::{Duration, Instant},
};

pub(super) const SCRIPT: &[u8] = b"#!/bin/sh\necho hello\n";

pub(super) struct Svc {
    pub(super) dir: PathBuf,
    pub(super) service: Arc<Service>,
    _wake: mpsc::Receiver<()>,
    commands: mpsc::Receiver<LaneCommand>,
}

impl Drop for Svc {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) fn svc(name: &str, edit: impl FnOnce(&mut Policy)) -> Svc {
    let dir = scratch(&format!("daemon-{name}"));
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let store = Arc::new(Store::open(&data.join("service")).unwrap());
    let mut policy = Policy::default();
    policy.vm.lane_vm = Some("auto-1".into());
    policy.sample.accept_types = vec!["sh".into(), "elf".into()];
    edit(&mut policy);
    let policies = Arc::new(SharedPolicies::new(PolicySet::single(LoadedPolicy {
        name: "default".into(),
        digest: "digest".into(),
        policy,
    })));
    let (staging, _) = StagingStore::open(
        &data.join("inbox"),
        &data,
        Arc::new(SystemClock),
        antinomie_monitor_core::samples::MAX_SAMPLE,
    )
    .unwrap();
    let intake = Arc::new(Intake::new(&data, Arc::new(staging), Some(512)));
    let options = BackendOptions {
        data_dir: data.clone(),
        ..BackendOptions::default()
    };
    let (wake, wake_rx) = mpsc::channel();
    let (commands, commands_rx) = mpsc::channel();
    let service = Arc::new(Service {
        data_dir: data.clone(),
        query: QueryService::new(options.clone()),
        options,
        config: RwLock::new(ServiceConfig::default()),
        store,
        policies,
        intake,
        lanes: LaneDir::new(&data.join("service")),
        owner: Owner::Daemon,
        view: Arc::new(Mutex::new(EngineView::default())),
        phase: Arc::new(Mutex::new(Phase::Idle)),
        controls: Arc::new(Controls::default()),
        wake: Mutex::new(wake),
        commands: Mutex::new(commands),
        accelerator: Accelerator::Kvm,
        watch: Default::default(),
        log: Arc::new(|_: &str| {}),
    });
    Svc {
        dir,
        service,
        _wake: wake_rx,
        commands: commands_rx,
    }
}

pub(super) fn me() -> Caller {
    local_caller(rustix::process::geteuid().as_raw())
}

pub(super) fn socket_ctx() -> CallContext {
    CallContext {
        caller: me(),
        cancel: Default::default(),
        transport: Transport::Socket,
    }
}

pub(super) fn call(svc: &Svc, op: &str, params: Value) -> Result<Value, ApiError> {
    svc.service.call(op, params, &socket_ctx())
}

/// Upload `bytes` the way a socket client does and return the upload id.
fn upload(svc: &Svc, bytes: &[u8]) -> String {
    let begun = call(
        svc,
        "upload.begin",
        json!({"size": bytes.len(), "name": "ok.sh"}),
    )
    .unwrap();
    let id = begun["upload_id"].as_str().unwrap().to_owned();
    let mut offset = 0;
    for chunk in bytes.chunks(7) {
        let put = call(
            svc,
            "upload.put",
            json!({"upload_id": id, "offset": offset, "data": b64::encode(chunk)}),
        )
        .unwrap();
        offset += chunk.len();
        assert_eq!(put["received"], offset);
    }
    let finished = call(svc, "upload.finish", json!({"upload_id": id})).unwrap();
    assert_eq!(finished["size"], bytes.len());
    id
}

pub(super) fn submit_upload(svc: &Svc) -> Job {
    let id = upload(svc, SCRIPT);
    let reply = call(svc, "job.submit", json!({"sample": {"upload_id": id}})).unwrap();
    assert_eq!(reply["replayed"], false);
    serde_json::from_value(reply).unwrap()
}

#[test]
fn an_upload_becomes_a_queued_job_and_a_client_path_is_never_opened() {
    let svc = svc("upload", |_| {});
    let job = submit_upload(&svc);
    assert_eq!(job.state, JobState::Queued, "{:?}", job.failure);
    assert_eq!(job.sample.as_ref().unwrap().kind, "sh");
    assert_eq!(job.client_id, me().client_id);

    // Over the socket a path is refused, whatever it names.
    let outside = svc.dir.join("outside.sh");
    std::fs::write(&outside, SCRIPT).unwrap();
    for path in [
        outside.display().to_string(),
        "/etc/passwd".into(),
        "../../x".into(),
    ] {
        let error = call(&svc, "job.submit", json!({"sample": {"path": path}})).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.field.as_deref(), Some("sample.path"));
    }
    // In the same process (direct mode) the command's own file is read.
    let direct = svc
        .service
        .call(
            "job.submit",
            json!({"sample": {"path": outside}}),
            &CallContext::in_process(me()),
        )
        .unwrap();
    assert_eq!(direct["state"], "queued");
}

#[test]
fn upload_put_refuses_text_that_is_not_base64_and_chunks_above_one_mebibyte() {
    let svc = svc("putrefuse", |_| {});
    let begun = call(&svc, "upload.begin", json!({"size": 3 << 20})).unwrap();
    let id = begun["upload_id"].as_str().unwrap();
    let error = call(
        &svc,
        "upload.put",
        json!({"upload_id": id, "offset": 0, "data": "not base64!"}),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("data"));
    let big = b64::encode(&vec![0u8; (1 << 20) + 1]);
    let error = call(
        &svc,
        "upload.put",
        json!({"upload_id": id, "offset": 0, "data": big}),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    // Out of order.
    let error = call(
        &svc,
        "upload.put",
        json!({"upload_id": id, "offset": 5, "data": "QUJD"}),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    // Unknown members are named.
    let error = call(&svc, "upload.begin", json!({"size": 3, "evil": 1})).unwrap_err();
    assert_eq!(error.field.as_deref(), Some("evil"));
}

#[test]
fn unknown_reserved_and_unserved_ops_are_told_apart() {
    let svc = svc("ops", |_| {});
    assert_eq!(
        call(&svc, "nope", json!({})).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    for reserved in [
        "run.exec",
        "terminal.input",
        "settings.set",
        "vm.create",
        "base.delete",
    ] {
        assert_eq!(
            call(&svc, reserved, json!({})).unwrap_err().code,
            ErrorCode::Unsupported,
            "{reserved}"
        );
    }
    for unserved in ["vm.list", "base.list", "sample.list", "job.delete"] {
        assert_eq!(
            call(&svc, unserved, json!({})).unwrap_err().code,
            ErrorCode::Unsupported,
            "{unserved}"
        );
    }
    assert_eq!(
        call(&svc, "events.subscribe", json!({})).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[test]
fn every_op_checks_its_scope() {
    let svc = svc("scopes", |_| {});
    let reader = CallContext {
        caller: Caller {
            client_id: "local:1".into(),
            scopes: vec![Scope::Read],
            policies: vec![],
        },
        cancel: Default::default(),
        transport: Transport::Socket,
    };
    for (op, params) in [
        ("job.submit", json!({"sample": {"sha256": "00".repeat(32)}})),
        ("upload.begin", json!({"size": 1})),
        ("queue.pause", json!({})),
        (
            "job.retry",
            json!({"job_id": "j_01ARZ3NDEKTSV4RRFFQ69G5FAV"}),
        ),
    ] {
        assert_eq!(
            svc.service.call(op, params, &reader).unwrap_err().code,
            ErrorCode::Forbidden,
            "{op}"
        );
    }
    assert!(svc.service.call("queue.status", json!({}), &reader).is_ok());
}

#[test]
fn a_stopping_daemon_refuses_new_work_and_still_answers_reads() {
    let svc = svc("stopping", |_| {});
    let job = submit_upload(&svc);
    svc.service.controls.begin_stop();
    let error = call(&svc, "upload.begin", json!({"size": 4})).unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(error.reason(), Some(ErrorReason::ServiceStopping));
    let got = call(&svc, "job.get", json!({"job_id": job.id})).unwrap();
    assert_eq!(got["state"], "queued");
    let health = call(&svc, "health", json!({})).unwrap();
    assert_eq!(health["ready"], false);
    assert!(health["reasons"].to_string().contains("stopping"));
}

#[test]
fn a_retry_is_a_new_job_that_repeats_a_finished_one_with_the_overrides() {
    let svc = svc("retry", |_| {});
    let job = submit_upload(&svc);
    let error = call(&svc, "job.retry", json!({"job_id": job.id})).unwrap_err();
    assert_eq!(error.code, ErrorCode::PreconditionFailed);
    let store = &svc.service.store;
    let running = store
        .claim_next(&crate::store::tests::lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    store
        .finish(
            &running.id,
            Outcome::Failed,
            Some(crate::api::failure::Failure::new(
                crate::api::failure::FailureCode::GuestLost,
                crate::api::job::Stage::Run,
                "lost",
                None,
            )),
        )
        .unwrap();
    let again = call(
        &svc,
        "job.retry",
        json!({"job_id": job.id, "overrides": {"timeout_s": 30}}),
    )
    .unwrap();
    assert_eq!(again["state"], "queued");
    assert_eq!(again["repeat_of"], json!(job.id));
    assert_eq!(again["spec"]["overrides"]["timeout_s"], 30);
    assert_ne!(again["id"], json!(job.id));
    assert_eq!(again["sample"]["sha256"], json!(job.sample.unwrap().sha256));
    // Another client may not retry it.
    let stranger = CallContext {
        caller: Caller {
            client_id: "local:4242".into(),
            scopes: vec![Scope::Read, Scope::Submit],
            policies: vec![],
        },
        cancel: Default::default(),
        transport: Transport::Socket,
    };
    let error = svc
        .service
        .call("job.retry", json!({"job_id": job.id}), &stranger)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Forbidden);
}

#[test]
fn the_queue_pauses_and_resumes_and_capabilities_follow_the_policies() {
    let svc = svc("queue", |_| {});
    let paused = call(&svc, "queue.pause", json!({})).unwrap();
    assert_eq!(paused["paused"], true);
    assert_eq!(paused["pause_reason"], "operator");
    assert_eq!(paused["owner"], "daemon");
    let resumed = call(&svc, "queue.resume", json!({})).unwrap();
    assert_eq!(resumed["paused"], false);

    let caps = call(&svc, "capabilities", json!({})).unwrap();
    assert_eq!(caps["api_version"], 1);
    assert_eq!(caps["lanes"], 1);
    assert_eq!(caps["accept_types"], json!(["sh", "elf"]));
    assert_eq!(caps["routes"], json!(["drop", "inet_sim"]));
    // min(256 MiB, the policy's 64 MiB, a quarter of 512 MiB of lane RAM).
    assert_eq!(
        caps["max_sample_bytes"],
        crate::intake::size_limit(64, Some(512))
    );
    assert!(
        caps["features"]
            .as_array()
            .unwrap()
            .contains(&json!("events.resume"))
    );
    let policies = call(&svc, "policy.list", json!({})).unwrap();
    assert_eq!(policies["policies"][0]["name"], "default");
}

#[test]
fn health_says_why_the_daemon_is_not_ready() {
    let svc = svc("health", |_| {});
    let health = call(&svc, "health", json!({})).unwrap();
    assert_eq!(health["ok"], true);
    assert_eq!(health["ready"], false);
    assert!(health["reasons"].to_string().contains("auto init"));
    assert_eq!(health["owner"], "daemon");
    assert_eq!(health["engine"]["accelerator"], "kvm");
}

#[test]
fn an_artifact_is_served_by_path_and_range_and_never_outside_its_job() {
    let svc = svc("artifact", |_| {});
    submit_upload(&svc);
    let store = &svc.service.store;
    let job = store
        .claim_next(&crate::store::tests::lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    let dir = store.job_dir(&job.id).join("artifacts");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("report-1.html"), b"<html>report</html>").unwrap();
    let add = |location: &str| {
        store
            .add_artifact(
                &job.id,
                NewArtifact {
                    kind: ArtifactKind::ReportHtml,
                    name: "report-1.html".into(),
                    size: 19,
                    sha256: Sha256Hex::try_from("ab".repeat(32)).unwrap(),
                    media_type: MediaType::TextHtml,
                    raw_indicators: false,
                    location: location.into(),
                },
            )
            .unwrap()
    };
    let good = add("artifacts/report-1.html");
    let got = call(
        &svc,
        "artifact.get",
        json!({"artifact_id": good.id, "range": {"offset": 6, "len": 6}}),
    )
    .unwrap();
    assert!(
        got["path"]
            .as_str()
            .unwrap()
            .ends_with("artifacts/report-1.html")
    );
    assert_eq!(
        b64::decode(got["range"]["data"].as_str().unwrap().as_bytes(), 64).unwrap(),
        b"report"
    );
    let report = call(
        &svc,
        "report.get",
        json!({"job_id": job.id, "format": "html"}),
    )
    .unwrap();
    assert_eq!(report["artifact"]["id"], json!(good.id));
    let bad = add("../../../../etc/passwd");
    let error = call(&svc, "artifact.get", json!({"artifact_id": bad.id})).unwrap_err();
    assert_eq!(error.code, ErrorCode::Internal);
}

/// A lane that does what a script says, for the loop and the shutdown.
struct Scripted {
    store: Arc<Store>,
    controls: Arc<Controls>,
    lane: Duration,
    host: Duration,
    ran: Arc<Mutex<Vec<JobId>>>,
}

impl LaneRunner for Scripted {
    fn tick(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn eligibility(&mut self) -> Eligibility {
        Eligibility::Ready
    }
    fn run_job(&mut self, job: &Job, to_host: &mut dyn FnMut()) -> JobEnd {
        crate::store::lock(&self.ran).push(job.id.clone());
        let until = Instant::now() + self.lane;
        while Instant::now() < until {
            if self.store.get(&job.id).unwrap().state == JobState::Cancelling {
                if self.store.cancel_is_shutdown(&job.id).unwrap() {
                    self.store
                        .requeue(
                            &job.id,
                            RequeueKind::Shutdown,
                            "service_shutdown",
                            None,
                            None,
                        )
                        .unwrap();
                } else {
                    self.store
                        .finish(&job.id, Outcome::Cancelled, None)
                        .unwrap();
                }
                return JobEnd::Done;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        to_host();
        let until = Instant::now() + self.host;
        while Instant::now() < until {
            if self.controls.interrupted() {
                return JobEnd::Aborted;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.store
            .finish(&job.id, Outcome::Succeeded, None)
            .unwrap();
        JobEnd::Done
    }
    fn resume(&mut self, job: &Job) -> JobEnd {
        self.store
            .finish(&job.id, Outcome::Succeeded, None)
            .unwrap();
        JobEnd::Done
    }
    fn govern(&mut self, _: u64) {}
    fn command(&mut self, op: &str, _: Value) -> Result<Value, ApiError> {
        Ok(json!({"op": op}))
    }
}

/// The lane loop on its own thread with a scripted lane, and a supervisor
/// that runs `shutdown_step` once the stop begins.
struct Running {
    svc: Svc,
    ran: Arc<Mutex<Vec<JobId>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn start(svc: Svc, lane: Duration, host: Duration) -> Running {
    let ran = Arc::new(Mutex::new(Vec::new()));
    let (wake_tx, wake_rx) = mpsc::channel();
    *crate::store::lock(&svc.service.wake) = wake_tx;
    let (command_tx, command_rx) = mpsc::channel();
    *crate::store::lock(&svc.service.commands) = command_tx;
    let service = Arc::clone(&svc.service);
    let mut runner = Scripted {
        store: Arc::clone(&service.store),
        controls: Arc::clone(&service.controls),
        lane,
        host,
        ran: Arc::clone(&ran),
    };
    let thread = std::thread::spawn(move || {
        let mut janitor = || {};
        let log = |_: &str| {};
        let mut lane_loop = LaneLoop {
            lane: crate::store::tests::lane(),
            store: &service.store,
            controls: &service.controls,
            phase: &service.phase,
            wake: &wake_rx,
            commands: &command_rx,
            clock: Arc::new(SystemClock),
            periods: Periods {
                idle_wait: Duration::from_millis(20),
                ..Periods::default()
            },
            janitor: &mut janitor,
            log: &log,
        };
        lane_loop.run(&mut runner, &[]);
    });
    Running {
        svc,
        ran,
        thread: Some(thread),
    }
}

impl Running {
    fn store(&self) -> &Store {
        &self.svc.service.store
    }

    fn wait_for(&self, what: &str, mut done: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < until, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Stop as the supervisor does and wait for the lane to end.
    fn stop(&mut self, grace: Duration) -> Vec<String> {
        let service = &self.svc.service;
        service.controls.begin_stop();
        let mut state = Stopping::default();
        let mut lines = Vec::new();
        let thread = self.thread.take().unwrap();
        let until = Instant::now() + Duration::from_secs(20);
        while !thread.is_finished() {
            assert!(Instant::now() < until, "the lane never stopped");
            if let Some(line) = shutdown_step(service, &mut state, grace, Instant::now()) {
                lines.push(line);
            }
            let _ = crate::store::lock(&service.wake).send(());
            std::thread::sleep(Duration::from_millis(10));
        }
        thread.join().unwrap();
        lines
    }
}

#[test]
fn the_lane_runs_jobs_in_queue_order_and_a_submit_wakes_it() {
    let svc = svc("loop", |_| {});
    let first = submit_upload(&svc);
    let mut running = start(svc, Duration::ZERO, Duration::ZERO);
    running.wait_for("the first job", || {
        running.store().get(&first.id).unwrap().state == JobState::Succeeded
    });
    let second = submit_upload(&running.svc);
    running.wait_for("the second job", || {
        running.store().get(&second.id).unwrap().state == JobState::Succeeded
    });
    assert_eq!(*running.ran.lock().unwrap(), vec![first.id, second.id]);
    // A lane command is served while idle.
    let answer = running
        .svc
        .service
        .lane_op("lane.test", json!({}), Duration::from_secs(5));
    assert_eq!(answer.unwrap()["op"], "lane.test");
    running.stop(Duration::from_secs(1));
    let _ = &running.svc.commands;
}

#[test]
fn at_shutdown_a_job_in_its_lane_stages_goes_back_to_the_queue_uncounted() {
    let svc = svc("stoplane", |_| {});
    let job = submit_upload(&svc);
    let mut running = start(svc, Duration::from_secs(30), Duration::ZERO);
    running.wait_for("the lane stages", || {
        *running.svc.service.phase.lock().unwrap() == Phase::Lane(job.id.clone())
    });
    let lines = running.stop(Duration::from_secs(120));
    assert!(lines[0].contains("cancelled for shutdown"), "{lines:?}");
    let after = running.store().get(&job.id).unwrap();
    assert_eq!(after.state, JobState::Queued);
    let (events, _) = running.store().events_list(&job.id, 0, 1000).unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.body,
            crate::api::event::EventBody::JobRequeued { reason, .. } if reason.contains("shutdown")
        )),
        "{events:?}"
    );
    // The attempt is forgiven: the job still has every attempt of its policy.
    assert_eq!(after.max_attempts, 2);
    assert!(
        running
            .store()
            .previous_failures(&job.id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn at_shutdown_a_job_in_its_host_stages_is_let_finish() {
    let svc = svc("stophost", |_| {});
    let job = submit_upload(&svc);
    let mut running = start(svc, Duration::ZERO, Duration::from_millis(600));
    running.wait_for("the host stages", || {
        *running.svc.service.phase.lock().unwrap() == Phase::Host(job.id.clone())
    });
    let began = Instant::now();
    let lines = running.stop(Duration::from_secs(120));
    assert!(lines.is_empty(), "{lines:?}");
    assert!(began.elapsed() >= Duration::from_millis(300));
    assert_eq!(
        running.store().get(&job.id).unwrap().state,
        JobState::Succeeded
    );
    // No other job was started during the stop.
    assert_eq!(running.ran.lock().unwrap().len(), 1);
}

#[test]
fn a_host_stage_past_the_grace_is_interrupted_and_left_for_recovery() {
    let svc = svc("stopgrace", |_| {});
    let job = submit_upload(&svc);
    let mut running = start(svc, Duration::ZERO, Duration::from_secs(30));
    running.wait_for("the host stages", || {
        *running.svc.service.phase.lock().unwrap() == Phase::Host(job.id.clone())
    });
    let lines = running.stop(Duration::from_millis(200));
    assert!(lines[0].contains("resumes at analyse"), "{lines:?}");
    // Untouched: recovery finds it `running` with its collected entry.
    assert_eq!(
        running.store().get(&job.id).unwrap().state,
        JobState::Running
    );
}

#[test]
fn drain_lets_the_lane_stages_run_on_until_the_drain_timeout() {
    let svc = svc("drain", |_| {});
    {
        let mut config = svc.service.config.write().unwrap();
        config.daemon.shutdown = Shutdown::Drain;
        config.daemon.drain_timeout_s = 600;
    }
    let job = submit_upload(&svc);
    let second = submit_upload(&svc);
    let mut running = start(svc, Duration::from_millis(400), Duration::ZERO);
    running.wait_for("the lane stages", || {
        *running.svc.service.phase.lock().unwrap() == Phase::Lane(job.id.clone())
    });
    let lines = running.stop(Duration::from_secs(120));
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(
        running.store().get(&job.id).unwrap().state,
        JobState::Succeeded
    );
    // With the drain over, the step cancels.
    let service = &running.svc.service;
    assert_eq!(
        service.store.get(&second.id).unwrap().state,
        JobState::Queued
    );
    service
        .store
        .claim_next(&crate::store::tests::lane(), &mut |_| Eligibility::Ready)
        .unwrap();
    *service.phase.lock().unwrap() = Phase::Lane(second.id.clone());
    let mut state = Stopping {
        since: Some(Instant::now() - Duration::from_secs(601)),
        ..Stopping::default()
    };
    let line = shutdown_step(
        service,
        &mut state,
        Duration::from_secs(120),
        Instant::now(),
    );
    assert!(line.unwrap().contains("cancelled for shutdown"));
    assert_eq!(
        service.store.get(&second.id).unwrap().state,
        JobState::Cancelling
    );
}
