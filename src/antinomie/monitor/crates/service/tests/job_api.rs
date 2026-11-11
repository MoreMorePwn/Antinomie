// SPDX-License-Identifier: GPL-3.0-only
//! The wire forms of the job API (design section 5): every object and event
//! round-trips, and the spellings the contract names are the ones sent.

use antinomie_service::api::{
    artifact::{Artifact, ArtifactKind, MediaType},
    assessment::{Assessment, AssessmentKind, Counts, Label, Tier},
    event::{
        Event, EventBody, EventScope, Frame, Hello, HelloOwner, LaneState, MetricsHealth,
        MetricsRun, MetricsVm, StageStatus,
    },
    failure::{Failure, FailureCode},
    ids::{ArtifactId, JobId, LaneId, Sha256Hex},
    job::{
        EndReason, Job, JobRecording, JobRun, JobSample, JobState, JobVm, Outcome, PolicyRef,
        RecordingPhase, Revert, Stage, Submitted, WaitingFor,
    },
    ops::{Op, Reply, Request, Scope},
    spec::{
        CoreDump, JobSpec, Overrides, ReportFormat, Route, RunAs, RunAsName, StaticCheck,
        StaticChecks,
    },
};
use serde_json::json;

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn job_id() -> JobId {
    JobId::from_parts(1_794_000_000_000, [1; 10])
}

fn job(state: JobState) -> Job {
    Job {
        api_version: 1,
        id: job_id(),
        state,
        stage: None,
        waiting_for: Some(WaitingFor::LayerPending),
        outcome: state.outcome(),
        created_ms: 1,
        started_ms: None,
        finished_ms: None,
        queue_position: Some(0),
        attempt: 1,
        max_attempts: 2,
        client_id: "local:1000".into(),
        spec: serde_json::from_value(json!({"sample": {"sha256": SHA}})).unwrap(),
        sample: Some(JobSample {
            sha256: SHA.to_owned().try_into().unwrap(),
            size: 12,
            kind: "elf".into(),
            architecture: Some("x86_64".into()),
            name: "a.out".into(),
        }),
        policy: PolicyRef {
            name: "default".into(),
            digest: "d".into(),
        },
        lane: Some(LaneId::new(1)),
        vm: Some(JobVm {
            id: "vm".into(),
            name: "lane".into(),
            base_identity: None,
            revert: Revert::SnapshotDisk,
        }),
        run: Some(JobRun {
            run_id: "r".into(),
            started_ms: Some(2),
            ended_ms: Some(3),
            end_reason: Some(EndReason::TimeLimit),
            exit: None,
            signal: Some(9),
            core_dumped: false,
            triggers: Vec::new(),
            trigger_notes: Vec::new(),
            pending: Vec::new(),
        }),
        recording: Some(JobRecording {
            vm_id: "vm".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            run_key: "key".into(),
            phase: RecordingPhase::Finalizing,
            directory: None,
        }),
        assessment: None,
        artifacts: vec![],
        warnings: vec![],
        failure: None,
        repeat_of: None,
        labels: Default::default(),
        host_work: Vec::new(),
    }
}

#[test]
fn a_minimal_spec_parses_and_unknown_fields_are_refused() {
    let spec: JobSpec = serde_json::from_value(json!({"sample": {"sha256": SHA}})).unwrap();
    assert!(spec.validate_shape().is_ok());
    assert_eq!(
        serde_json::to_value(&spec).unwrap(),
        json!({"sample": {"sha256": SHA}})
    );
    let error = serde_json::from_value::<JobSpec>(json!({"sample": {"sha256": SHA}, "flavour": 1}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("flavour"), "{error}");
    let error = serde_json::from_value::<JobSpec>(
        json!({"sample": {"sha256": SHA}, "overrides": {"base": "x"}}),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("base"),
        "overrides.base was removed: {error}"
    );
}

#[test]
fn exactly_one_sample_source() {
    let none: JobSpec = serde_json::from_value(json!({"sample": {}})).unwrap();
    assert_eq!(none.validate_shape().unwrap_err().field, "sample");
    let two: JobSpec =
        serde_json::from_value(json!({"sample": {"sha256": SHA, "path": "/tmp/x"}})).unwrap();
    assert_eq!(two.validate_shape().unwrap_err().field, "sample");
    let bad_hash = serde_json::from_value::<JobSpec>(json!({"sample": {"sha256": "ABC"}}));
    assert!(bad_hash.is_err());
}

#[test]
fn the_full_override_set_round_trips_in_the_documented_spellings() {
    let value = json!({
        "sample": {"sha256": SHA},
        "name": "x.bin", "policy": "default", "priority": 9,
        "labels": {"case": "42"}, "idempotency_key": "k1",
        "overrides": {
            "timeout_s": 60, "args": ["-v"], "env": ["A=1"],
            "run_as": {"uid": 5, "gid": 6}, "run_in": "app_terminal", "route": "inet_sim",
            "network_capture": true, "memory_dump": false,
            "core_dump": {"max_mib": 64, "timeout_ms": 5000},
            "static_checks": ["metadata", "floss"], "static_time_limit_min": 2,
            "detection": {"yara": true, "sigma": false, "ids": true},
            "reports": ["html", "misp", "md"], "report_bundle": true, "report_defang": true,
            "keep_on_failure": false
        }
    });
    let spec: JobSpec = serde_json::from_value(value.clone()).unwrap();
    assert!(spec.validate_shape().is_ok());
    assert_eq!(serde_json::to_value(&spec).unwrap(), value);
    assert_eq!(
        spec.overrides.static_checks,
        Some(StaticChecks::Names(vec![
            StaticCheck::Metadata,
            StaticCheck::Floss
        ]))
    );
    assert_eq!(
        spec.overrides.run_as,
        Some(RunAs::Ids(antinomie_service::api::spec::RunAsIds {
            uid: 5,
            gid: 6
        }))
    );
    for text in ["user", "root"] {
        let run_as: RunAs = serde_json::from_value(json!(text)).unwrap();
        assert!(matches!(run_as, RunAs::Named(_)));
    }
    assert_eq!(
        serde_json::from_value::<StaticChecks>(json!("triage")).unwrap(),
        StaticChecks::Preset(antinomie_service::api::spec::StaticPreset::Triage)
    );
    assert_eq!(
        serde_json::from_value::<CoreDump>(json!(true)).unwrap(),
        CoreDump::Switch(true)
    );
    for route in ["drop", "internet", "inet_sim", "tor", "vpn", "socks5"] {
        let parsed: Route = serde_json::from_value(json!(route)).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), json!(route));
    }
    assert!(serde_json::from_value::<Route>(json!("inetsim")).is_err());
    assert!(serde_json::from_value::<ReportFormat>(json!("docx")).is_err());
}

#[test]
fn shape_limits_name_the_field() {
    let check = |extra: serde_json::Value| {
        let mut value = json!({"sample": {"sha256": SHA}});
        for (key, item) in extra.as_object().unwrap() {
            value[key] = item.clone();
        }
        let spec: JobSpec = serde_json::from_value(value).unwrap();
        spec.validate_shape().unwrap_err().field
    };
    assert_eq!(check(json!({"name": "a/b"})), "name");
    assert_eq!(check(json!({"name": ""})), "name");
    assert_eq!(check(json!({"priority": 10})), "priority");
    assert_eq!(check(json!({"labels": {"Bad": "x"}})), "labels");
    assert_eq!(
        check(json!({"idempotency_key": "tab\there"})),
        "idempotency_key"
    );
    assert_eq!(
        check(json!({"overrides": {"timeout_s": 4}})),
        "overrides.timeout_s"
    );
    assert_eq!(
        check(json!({"overrides": {"env": ["NOEQUALS"]}})),
        "overrides.env"
    );
    assert_eq!(
        check(json!({"overrides": {"static_time_limit_min": 481}})),
        "overrides.static_time_limit_min"
    );
}

#[test]
fn live_routes_and_desktop_modes_are_not_in_v1() {
    let spec: JobSpec =
        serde_json::from_value(json!({"sample": {"sha256": SHA}, "overrides": {"route": "tor"}}))
            .unwrap();
    assert!(
        spec.validate_shape().is_ok(),
        "a valid spelling is not invalid"
    );
    let unsupported = spec.v1_unsupported().unwrap();
    assert_eq!(unsupported.field, "overrides.route");
    assert_eq!(unsupported.reason, "live_route_not_in_v1");
    let spec = JobSpec {
        overrides: Overrides {
            route: Some(Route::InetSim),
            run_in: Some(antinomie_service::api::spec::RunIn::GuestDesktop),
            ..Overrides::default()
        },
        ..spec
    };
    assert_eq!(spec.v1_unsupported().unwrap().field, "overrides.run_in");
    let _ = RunAsName::User;
}

#[test]
fn a_job_round_trips_and_state_equals_outcome_once_terminal() {
    for state in [
        JobState::Queued,
        JobState::Running,
        JobState::Cancelling,
        JobState::Succeeded,
        JobState::Partial,
        JobState::Failed,
        JobState::Cancelled,
        JobState::Rejected,
    ] {
        let job = job(state);
        let value = serde_json::to_value(&job).unwrap();
        assert_eq!(value["api_version"], 1);
        assert_eq!(value["state"], serde_json::to_value(state).unwrap());
        assert_eq!(value["outcome"].is_null(), !state.is_terminal());
        if let Some(outcome) = state.outcome() {
            assert_eq!(JobState::from(outcome), state);
            assert_eq!(value["outcome"], value["state"]);
        }
        let back: Job = serde_json::from_value(value).unwrap();
        assert_eq!(back, job);
    }
    let value = serde_json::to_value(job(JobState::Queued)).unwrap();
    assert_eq!(value["sample"]["type"], "elf");
    assert_eq!(value["waiting_for"], "layer_pending");
    assert_eq!(value["vm"]["revert"], "snapshot_disk");
    assert_eq!(value["run"]["end_reason"], "time_limit");
    assert_eq!(value["recording"]["phase"], "finalizing");
    assert!(
        value["recording"].get("directory").is_none(),
        "local-only, absent when unset"
    );
}

#[test]
fn submitted_is_a_job_plus_replayed() {
    let submitted = Submitted {
        job: job(JobState::Queued),
        replayed: true,
    };
    let value = serde_json::to_value(&submitted).unwrap();
    assert_eq!(value["replayed"], true);
    assert_eq!(value["id"], serde_json::to_value(job_id()).unwrap());
    assert_eq!(
        serde_json::from_value::<Submitted>(value).unwrap(),
        submitted
    );
}

#[test]
fn stages_and_waits_use_the_documented_names() {
    let stages: Vec<_> = [
        Stage::Prechecks,
        Stage::Provision,
        Stage::Upload,
        Stage::Launch,
        Stage::Run,
        Stage::Collect,
        Stage::Analyse,
        Stage::Report,
        Stage::Cleanup,
    ]
    .iter()
    .map(|s| serde_json::to_value(s).unwrap())
    .collect();
    assert_eq!(
        stages,
        [
            "prechecks",
            "provision",
            "upload",
            "launch",
            "run",
            "collect",
            "analyse",
            "report",
            "cleanup"
        ]
        .map(|s| json!(s))
    );
    assert_eq!(
        serde_json::to_value(WaitingFor::LaneQuarantined).unwrap(),
        json!("lane_quarantined")
    );
    assert_eq!(
        serde_json::to_value(Revert::SnapshotFull).unwrap(),
        json!("snapshot_full")
    );
}

#[test]
fn artifact_kinds_keep_their_dotted_names_and_sensitivity() {
    let artifact = Artifact {
        id: ArtifactId::from_parts(5, [2; 10]),
        job_id: job_id(),
        kind: ArtifactKind::NetworkPcap,
        name: "net.pcap".into(),
        size: 9,
        sha256: Sha256Hex::try_from(SHA.to_owned()).unwrap(),
        media_type: MediaType::ApplicationPcap,
        sensitive: ArtifactKind::NetworkPcap.sensitive(),
        raw_indicators: false,
        created_ms: 7,
    };
    let value = serde_json::to_value(&artifact).unwrap();
    assert_eq!(value["kind"], "network.pcap");
    assert_eq!(value["media_type"], "application/vnd.tcpdump.pcap");
    assert_eq!(value["sensitive"], true);
    assert_eq!(serde_json::from_value::<Artifact>(value).unwrap(), artifact);
    assert!(
        !ArtifactKind::ReportJson.sensitive(),
        "reports are not sensitive"
    );
    assert!(ArtifactKind::ReportBundle.sensitive());
}

#[test]
fn an_assessment_round_trips() {
    let assessment = Assessment {
        assessment: AssessmentKind::SuspiciousBehaviour,
        highest_tier: Tier::Medium,
        label: Some(Label::CleanObserved),
        score: Some(40),
        families: vec![],
        counts: Counts::default(),
        key_behaviours: vec![],
        detections: vec![],
        techniques: vec!["T1059".into()],
        ioc_dataset_count: 0,
        basis: "x".into(),
    };
    let value = serde_json::to_value(&assessment).unwrap();
    assert_eq!(value["assessment"], "suspicious_behaviour");
    assert_eq!(value["label"], "clean_observed");
    assert_eq!(
        serde_json::from_value::<Assessment>(value).unwrap(),
        assessment
    );
}

#[test]
fn failures_follow_the_code_table() {
    let failure = Failure::new(FailureCode::GuestLost, Stage::Run, "gone", None);
    assert!(failure.retryable);
    assert_eq!(
        FailureCode::GuestLost.stages(),
        [Stage::Run, Stage::Collect]
    );
    assert!(!Failure::new(FailureCode::RevertFailed, Stage::Provision, "x", None).retryable);
    let value = serde_json::to_value(&failure).unwrap();
    assert_eq!(value["code"], "guest_lost");
    assert_eq!(serde_json::from_value::<Failure>(value).unwrap(), failure);
}

fn event(body: EventBody) -> Event {
    Event {
        seq: Some(3),
        gseq: Some(30),
        ts_ms: 9,
        scope: body.scope(),
        job_id: Some(job_id()),
        body,
    }
}

#[test]
fn every_event_type_has_its_documented_name_and_round_trips() {
    let bodies = vec![
        (
            "job.created",
            EventBody::JobCreated {
                job: Box::new(job(JobState::Queued)),
            },
        ),
        (
            "job.state",
            EventBody::JobState {
                state: JobState::Running,
                stage: Some(Stage::Run),
                waiting_for: None,
                attempt: 1,
                queue_position: None,
            },
        ),
        (
            "job.stage",
            EventBody::JobStage {
                stage: Stage::Collect,
                status: StageStatus::Finished,
                duration_ms: Some(12),
            },
        ),
        (
            "job.progress",
            EventBody::JobProgress {
                stage: Stage::Provision,
                text: "booting".into(),
                fraction: Some(0.5),
            },
        ),
        (
            "job.run",
            EventBody::JobRun {
                run_id: "r".into(),
                pid: Some(7),
                route: Route::Drop,
            },
        ),
        (
            "job.warning",
            EventBody::JobWarning {
                code: "tool_missing".into(),
                text: "capa".into(),
            },
        ),
        (
            "job.requeued",
            EventBody::JobRequeued {
                attempt: 2,
                reason: "guest_unreachable".into(),
            },
        ),
        (
            "job.finished",
            EventBody::JobFinished {
                outcome: Outcome::Failed,
                failure: Some(Failure::new(FailureCode::Internal, Stage::Run, "x", None)),
            },
        ),
        (
            "lane.state",
            EventBody::LaneState {
                lane: LaneId::new(1),
                state: LaneState::Quarantined,
                job_id: None,
                reason: Some("revert_failed".into()),
            },
        ),
        (
            "engine.alert",
            EventBody::EngineAlert {
                code: "low_disk".into(),
                text: "6 GiB left".into(),
            },
        ),
        (
            "job.metrics",
            EventBody::JobMetrics {
                stage: Stage::Run,
                vm: MetricsVm::default(),
                run: MetricsRun {
                    live_tasks: 2,
                    recorded_events: None,
                },
                health: MetricsHealth {
                    dropped: 0,
                    shedding: false,
                },
            },
        ),
    ];
    for (name, body) in bodies {
        let ephemeral = body.is_ephemeral();
        let event = event(body);
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["type"], name);
        assert!(value["data"].is_object(), "{name}: data is an object");
        assert_eq!(
            value["scope"],
            if name.starts_with("lane") || name.starts_with("engine") {
                "engine"
            } else {
                "job"
            }
        );
        let back: Event = serde_json::from_value(value).unwrap();
        assert_eq!(back, event, "{name}");
        assert_eq!(ephemeral, name == "job.progress" || name == "job.metrics");
    }
}

#[test]
fn ephemeral_events_carry_no_sequence() {
    let event = Event {
        seq: None,
        gseq: None,
        ts_ms: 1,
        scope: EventScope::Job,
        job_id: Some(job_id()),
        body: EventBody::JobProgress {
            stage: Stage::Upload,
            text: "x".into(),
            fraction: None,
        },
    };
    let value = serde_json::to_value(&event).unwrap();
    assert!(value.get("seq").is_none() && value.get("gseq").is_none());
}

#[test]
fn hello_and_ping_are_frames() {
    let hello = Frame::Hello(Hello {
        api_version: 1,
        app_version: "0.9.0".into(),
        owner: HelloOwner::Daemon,
        epoch: "e".into(),
        gseq: 0,
        truncated: false,
    });
    assert_eq!(
        serde_json::to_value(&hello).unwrap(),
        json!({"frame": "engine.hello", "data": {"api_version": 1, "app_version": "0.9.0",
            "owner": "daemon", "epoch": "e", "gseq": 0, "truncated": false}})
    );
    assert_eq!(
        serde_json::to_value(Frame::Ping {}).unwrap(),
        json!({"frame": "engine.ping", "data": {}})
    );
    assert_eq!(
        serde_json::from_value::<Frame>(json!({"frame": "engine.ping", "data": {}})).unwrap(),
        Frame::Ping {}
    );
}

#[test]
fn socket_requests_and_replies_use_the_documented_framing() {
    let request: Request = serde_json::from_value(
        json!({"id": 7, "op": "job.submit", "params": {"sample": {"sha256": SHA}}}),
    )
    .unwrap();
    assert_eq!(request.id, 7);
    assert_eq!(
        serde_json::from_value::<Op>(json!(request.op)).unwrap(),
        Op::JobSubmit
    );
    let ok = serde_json::to_value(Reply::ok(7, json!({"deleted": true}))).unwrap();
    assert_eq!(
        ok,
        json!({"id": 7, "ok": true, "result": {"deleted": true}})
    );
    let failed = serde_json::to_value(Reply::failed(
        7,
        antinomie_service::api::ApiError::not_found("job"),
    ))
    .unwrap();
    assert_eq!(failed["ok"], false);
    assert_eq!(failed["error"]["code"], "not_found");
    let line = serde_json::to_value(Reply::event(
        7,
        event(EventBody::EngineAlert {
            code: "c".into(),
            text: "t".into(),
        }),
    ))
    .unwrap();
    assert_eq!(line["event"]["type"], "engine.alert");
    assert!(line.get("ok").is_none());
    let hello_line: Reply =
        serde_json::from_value(json!({"id": 7, "frame": "engine.ping", "data": {}})).unwrap();
    assert_eq!(hello_line.frame, Some(Frame::Ping {}));
}

#[test]
fn every_op_spelling_round_trips_and_has_a_scope() {
    let names = [
        "capabilities",
        "health",
        "upload.begin",
        "upload.put",
        "upload.finish",
        "job.submit",
        "job.get",
        "job.list",
        "job.cancel",
        "job.retry",
        "job.delete",
        "events.subscribe",
        "events.list",
        "artifact.list",
        "artifact.get",
        "report.get",
        "sample.list",
        "sample.get",
        "sample.add",
        "sample.download",
        "sample.tag",
        "policy.list",
        "queue.status",
        "queue.pause",
        "queue.resume",
        "vm.list",
        "base.list",
        "custody.verify",
    ];
    for name in names {
        let op: Op = serde_json::from_value(json!(name)).unwrap();
        assert_eq!(serde_json::to_value(op).unwrap(), json!(name));
        let _ = op.scope();
    }
    assert_eq!(Op::SampleDownload.scope(), Scope::ArtifactsSensitive);
    assert_eq!(Op::JobCancel.scope(), Scope::Submit);
    assert_eq!(Op::QueuePause.scope(), Scope::Manage);
    assert_eq!(
        serde_json::to_value(Scope::ArtifactsSensitive).unwrap(),
        json!("artifacts:sensitive")
    );
    assert!(
        serde_json::from_value::<Op>(json!("run.list")).is_err(),
        "run.* is reserved"
    );
}
