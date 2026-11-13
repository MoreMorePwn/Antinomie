// SPDX-License-Identifier: GPL-3.0-only
//! The wire forms of the run API (design section 5): every object and event
//! round-trips, and the spellings the contract names are the ones sent.

use antinomie_service::api::{
    artifact::{Artifact, ArtifactKind, MediaType},
    assessment::{Assessment, AssessmentKind, Counts, Label, Tier},
    event::{
        Event, EventBody, EventScope, Frame, Hello, HelloOwner, LaneState, MetricsHealth,
        MetricsRun, MetricsVm, StageStatus,
    },
    failure::{Failure, FailureCode},
    ids::{ArtifactId, LaneId, RunId, Sha256Hex},
    ops::{Op, Permission, Reply, Request},
    run::{
        EndReason, Outcome, PresetRef, RecordingPhase, Revert, Run, RunProgram, RunRecording,
        RunSample, RunState, RunVm, Stage, Submitted, WaitingFor,
    },
    spec::{Overrides, ReportFormat, Route, RunRequest},
};
use serde_json::json;

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn job_id() -> RunId {
    RunId::from_parts(1_794_000_000_000, [1; 10])
}

fn job(state: RunState) -> Run {
    Run {
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
        request: serde_json::from_value(json!({"sample": {"sha256": SHA}})).unwrap(),
        sample: Some(RunSample {
            sha256: SHA.to_owned().try_into().unwrap(),
            size: 12,
            kind: "elf".into(),
            architecture: Some("x86_64".into()),
            name: "a.out".into(),
        }),
        preset: PresetRef {
            name: "custom".into(),
            digest: "d".into(),
            based_on: Some(antinomie_service::api::run::PresetBase {
                name: "standard".into(),
                digest: "s".into(),
            }),
            changes: vec!["program.run_time_s".into()],
        },
        settings: json!({"program": {"run_time_s": 60}}),
        permissions_used: vec![antinomie_service::api::run::PermissionUse {
            permission: antinomie_service::api::ops::Permission::EvidenceCoreDump,
            field: "dumps.core_dump_on_exit".into(),
            source: "caller".into(),
        }],
        lane: Some(LaneId::new(1)),
        vm: Some(RunVm {
            id: "vm".into(),
            name: "lane".into(),
            base_identity: None,
            revert: Revert::SnapshotDisk,
        }),
        program: Some(RunProgram {
            id: "r".into(),
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
        recording: Some(RunRecording {
            vm_id: "vm".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            recording_key: "key".into(),
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
    let spec: RunRequest = serde_json::from_value(json!({"sample": {"sha256": SHA}})).unwrap();
    assert!(spec.validate_shape().is_ok());
    assert_eq!(
        serde_json::to_value(&spec).unwrap(),
        json!({"sample": {"sha256": SHA}})
    );
    let error =
        serde_json::from_value::<RunRequest>(json!({"sample": {"sha256": SHA}, "flavour": 1}))
            .unwrap_err()
            .to_string();
    assert!(error.contains("flavour"), "{error}");
    // Overrides are a partial preset: a key outside its tables is refused
    // by the shape check (and a key inside one by admission).
    let spec = serde_json::from_value::<RunRequest>(
        json!({"sample": {"sha256": SHA}, "overrides": {"base": "x"}}),
    )
    .unwrap();
    assert_eq!(spec.validate_shape().unwrap_err().field, "overrides");
}

#[test]
fn exactly_one_sample_source() {
    let none: RunRequest = serde_json::from_value(json!({"sample": {}})).unwrap();
    assert_eq!(none.validate_shape().unwrap_err().field, "sample");
    let two: RunRequest =
        serde_json::from_value(json!({"sample": {"sha256": SHA, "path": "/tmp/x"}})).unwrap();
    assert_eq!(two.validate_shape().unwrap_err().field, "sample");
    let bad_hash = serde_json::from_value::<RunRequest>(json!({"sample": {"sha256": "ABC"}}));
    assert!(bad_hash.is_err());
}

#[test]
fn overrides_are_a_partial_preset_in_the_documented_spellings() {
    let value = json!({
        "sample": {"sha256": SHA},
        "name": "x.bin", "preset": "standard", "priority": 9,
        "labels": {"case": "42"}, "idempotency_key": "k1",
        "overrides": {
            "program": {"run_time_s": 60, "arguments": ["-v"], "environment": ["A=1"],
                        "user": "custom", "uid": 5, "gid": 6, "run_in": "app_terminal"},
            "network": {"route": "inet_sim", "capture": true},
            "dumps": {"memory_dump_on_exit": false, "core_budget_mib": 64,
                      "core_deadline_ms": 5000},
            "static_analysis": {"triage_checks": ["metadata"], "deep_checks": ["floss"],
                                "time_limit_per_tool_min": 2},
            "detection": {"yara": true, "sigma": false, "ids": true},
            "report": {"formats": ["html", "misp", "md"], "bundle": true, "defang": true},
            "vm": {"keep_on_failure": false}
        }
    });
    let spec: RunRequest = serde_json::from_value(value.clone()).unwrap();
    assert!(spec.validate_shape().is_ok());
    assert_eq!(serde_json::to_value(&spec).unwrap(), value);
    assert_eq!(spec.overrides.0["program"]["run_time_s"], json!(60));
    for route in [
        "drop",
        "internet",
        "inet_sim",
        "nat",
        "tor",
        "vpn",
        "vpn:work",
        "socks5",
        "socks5:proxy-1",
    ] {
        let parsed: Route = serde_json::from_value(json!(route)).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), json!(route));
    }
    assert_eq!(
        Route::parse("vpn:work"),
        Some(Route::Vpn(Some("work".into())))
    );
    for wrong in ["inetsim", "tor:x", "vpn:", "vpn:a b", "drop:x"] {
        assert!(
            serde_json::from_value::<Route>(json!(wrong)).is_err(),
            "{wrong}"
        );
    }
    assert!(serde_json::from_value::<ReportFormat>(json!("docx")).is_err());
}

#[test]
fn shape_limits_name_the_field() {
    let check = |extra: serde_json::Value| {
        let mut value = json!({"sample": {"sha256": SHA}});
        for (key, item) in extra.as_object().unwrap() {
            value[key] = item.clone();
        }
        let spec: RunRequest = serde_json::from_value(value).unwrap();
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
    // A 0.9.0 policy override is not a table of the preset format.
    assert_eq!(check(json!({"overrides": {"timeout_s": 4}})), "overrides");
    // The values are checked against the preset (admission).
    let spec: RunRequest = serde_json::from_value(
        json!({"sample": {"sha256": SHA}, "overrides": {"program": {"run_time_s": 4}}}),
    )
    .unwrap();
    assert!(spec.validate_shape().is_ok());
    let _ = Overrides::default();
}

#[test]
fn a_job_round_trips_and_state_equals_outcome_once_terminal() {
    for state in [
        RunState::Queued,
        RunState::Running,
        RunState::Cancelling,
        RunState::Succeeded,
        RunState::Partial,
        RunState::Failed,
        RunState::Cancelled,
        RunState::Rejected,
    ] {
        let job = job(state);
        let value = serde_json::to_value(&job).unwrap();
        assert_eq!(value["api_version"], 1);
        assert_eq!(value["state"], serde_json::to_value(state).unwrap());
        assert_eq!(value["outcome"].is_null(), !state.is_terminal());
        if let Some(outcome) = state.outcome() {
            assert_eq!(RunState::from(outcome), state);
            assert_eq!(value["outcome"], value["state"]);
        }
        let back: Run = serde_json::from_value(value).unwrap();
        assert_eq!(back, job);
    }
    let value = serde_json::to_value(job(RunState::Queued)).unwrap();
    assert_eq!(value["sample"]["type"], "elf");
    assert_eq!(value["waiting_for"], "layer_pending");
    assert_eq!(value["vm"]["revert"], "snapshot_disk");
    assert_eq!(value["program"]["end_reason"], "time_limit");
    assert_eq!(value["program"]["id"], "r");
    assert_eq!(value["preset"]["based_on"]["name"], "standard");
    assert_eq!(value["settings"]["program"]["run_time_s"], 60);
    assert_eq!(
        value["permissions_used"],
        json!([{"permission": "evidence.core_dump", "field": "dumps.core_dump_on_exit", "source": "caller"}])
    );
    assert!(value["id"].as_str().unwrap().starts_with("r_"));
    for old in ["spec", "policy", "run"] {
        assert!(value.get(old).is_none(), "{old} is not a member of a run");
    }
    assert_eq!(value["recording"]["phase"], "finalizing");
    assert!(
        value["recording"].get("directory").is_none(),
        "local-only, absent when unset"
    );
}

#[test]
fn submitted_is_a_job_plus_replayed() {
    let submitted = Submitted {
        run: job(RunState::Queued),
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
        run_id: job_id(),
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
        run_id: Some(job_id()),
        body,
    }
}

#[test]
fn every_event_type_has_its_documented_name_and_round_trips() {
    let bodies = vec![
        (
            "run.created",
            EventBody::RunCreated {
                run: Box::new(job(RunState::Queued)),
            },
        ),
        (
            "run.state",
            EventBody::RunState {
                state: RunState::Running,
                stage: Some(Stage::Run),
                waiting_for: None,
                attempt: 1,
                queue_position: None,
            },
        ),
        (
            "run.stage",
            EventBody::RunStage {
                stage: Stage::Collect,
                status: StageStatus::Finished,
                duration_ms: Some(12),
            },
        ),
        (
            "run.progress",
            EventBody::RunProgress {
                stage: Stage::Provision,
                text: "booting".into(),
                fraction: Some(0.5),
            },
        ),
        (
            "run.program",
            EventBody::RunProgram {
                program_id: "r".into(),
                pid: Some(7),
                route: Route::Drop,
            },
        ),
        (
            "run.warning",
            EventBody::RunWarning {
                code: "tool_missing".into(),
                text: "capa".into(),
            },
        ),
        (
            "run.requeued",
            EventBody::RunRequeued {
                attempt: 2,
                reason: "guest_unreachable".into(),
            },
        ),
        (
            "run.finished",
            EventBody::RunFinished {
                outcome: Outcome::Failed,
                failure: Some(Failure::new(FailureCode::Internal, Stage::Run, "x", None)),
            },
        ),
        (
            "lane.state",
            EventBody::LaneState {
                lane: LaneId::new(1),
                state: LaneState::Quarantined,
                run_id: None,
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
            "run.metrics",
            EventBody::RunMetrics {
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
                "run"
            }
        );
        let back: Event = serde_json::from_value(value).unwrap();
        assert_eq!(back, event, "{name}");
        assert_eq!(ephemeral, name == "run.progress" || name == "run.metrics");
    }
}

#[test]
fn ephemeral_events_carry_no_sequence() {
    let event = Event {
        seq: None,
        gseq: None,
        ts_ms: 1,
        scope: EventScope::Run,
        run_id: Some(job_id()),
        body: EventBody::RunProgress {
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
        json!({"id": 7, "op": "run.submit", "params": {"sample": {"sha256": SHA}}}),
    )
    .unwrap();
    assert_eq!(request.id, 7);
    assert_eq!(
        serde_json::from_value::<Op>(json!(request.op)).unwrap(),
        Op::RunSubmit
    );
    let ok = serde_json::to_value(Reply::ok(7, json!({"deleted": true}))).unwrap();
    assert_eq!(
        ok,
        json!({"id": 7, "ok": true, "result": {"deleted": true}})
    );
    let failed = serde_json::to_value(Reply::failed(
        7,
        antinomie_service::api::ApiError::not_found("run"),
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
        "run.submit",
        "run.get",
        "run.list",
        "run.cancel",
        "run.rerun",
        "run.delete",
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
        "preset.list",
        "preset.get",
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
        assert!(!op.needs().is_empty(), "{name}");
    }
    assert_eq!(Op::SampleDownload.needs(), [Permission::SamplesDownload]);
    assert_eq!(
        Op::RunCancel.needs(),
        [Permission::RunsSubmit, Permission::RunsManageAny]
    );
    assert_eq!(Op::QueuePause.needs(), [Permission::QueueManage]);
    assert_eq!(
        serde_json::to_value(Permission::EvidenceDownload).unwrap(),
        json!("evidence.download")
    );
    // No job API ships: the names before the rename are not operations.
    for old in [
        "job.submit",
        "job.get",
        "job.retry",
        "policy.list",
        "run.end",
    ] {
        assert!(serde_json::from_value::<Op>(json!(old)).is_err(), "{old}");
    }
    assert_eq!(Op::PresetGet.needs(), [Permission::RunsSubmit]);
    assert_eq!(Op::PresetList.needs(), [Permission::RunsSubmit]);
}
