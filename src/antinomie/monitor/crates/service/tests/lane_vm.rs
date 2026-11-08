// SPDX-License-Identifier: GPL-3.0-only
//! The lane stages `prechecks` to `launch` on a real VM (card P3-4b). Ignored
//! by default: it needs KVM, an installed base bundle and a private data
//! directory, and takes the machine's VM lock when run by the pipeline.
//!
//! ```text
//! ANTINOMIE_LANE_VM_BUNDLE=/path/to/bases/.../busybox \
//! ANTINOMIE_LANE_VM_DATA=/path/to/empty/private/dir \
//!   cargo test --release -p antinomie-service --test lane_vm -- --ignored --nocapture
//! ```
//!
//! It imports the bundle, creates the lane VM, takes the `auto-clean` Disk
//! snapshot, adds a benign shell script to the library, and runs two jobs
//! through `run_to_launch` on the real engine: the second job proves the
//! revert and the layer wait on a lane that has been used. The recorded QEMU
//! process must be the one that ends when the VM stops.

// `ApiError` is the contract's error type (large by design, see the crate root).
#![allow(clippy::result_large_err)]

use antinomie_monitor_core::{
    Backend, BackendOptions, Command, Snapshot, SnapshotRequest, VmConfig, VmSnapshotMode, VmState,
    samples::{Library, NewSample},
};
use antinomie_service::{
    api::{
        failure::FailureCode,
        ids::{LaneId, Sha256Hex},
        job::{EndReason, JobSample, JobState, RecordingPhase},
        ops::{Caller, Scope},
        spec::{JobSpec, SampleSource},
    },
    clock::SystemClock,
    config::{LoadedPolicy, Policy, PolicySet},
    lane::{LaneDir, LaneFile, ProcFs, Processes},
    stages::{
        Driven, Hosted, LaneEnv, LaneStages, NoHostChecks,
        host::{NoTags, RealTriage},
    },
    store::{Eligibility, IntakeError, SampleAdmission, Store, SubmitContext, SubmitLimits},
    waiter::{Phase, Waiter, phase},
};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

const SCRIPT: &str = "#!/bin/sh\necho lane-stage-check\nsleep 1\necho done\n";

struct Admit {
    sample: JobSample,
}

impl SampleAdmission for Admit {
    fn admit(
        &self,
        _: &SampleSource,
        _: Option<&str>,
        _: &LoadedPolicy,
        _: &str,
    ) -> Result<JobSample, IntakeError> {
        Ok(self.sample.clone())
    }
}

/// The Triage crate on the test's private data directory.
fn triage(data: &std::path::Path) -> RealTriage {
    RealTriage::new(BackendOptions {
        data_dir: data.to_path_buf(),
        ..BackendOptions::default()
    })
}

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is not set")))
}

fn settle(
    waiter: &mut Waiter<Backend>,
    what: &str,
    seconds: u64,
    done: impl FnMut(&Snapshot) -> bool,
) {
    waiter
        .wait_until(what, Some(Duration::from_secs(seconds)), done)
        .unwrap_or_else(|e| panic!("{what}: {e}"));
}

/// The engine, an imported base, the lane VM and its `auto-clean` snapshot, as
/// `auto init` will make them. Returns the waiter, the VM id, the snapshot id
/// and the base identity.
fn setup_lane(
    bundle: PathBuf,
    data: &std::path::Path,
) -> (Waiter<Backend>, String, String, Option<String>) {
    let backend = Backend::new(BackendOptions {
        data_dir: data.to_path_buf(),
        headless: true,
        force_tcg: std::env::var_os("ANTINOMIE_FORCE_TCG").is_some(),
        ..BackendOptions::default()
    })
    .expect("the engine starts");
    let mut waiter = Waiter::new(backend, Arc::new(SystemClock));
    waiter.first_snapshot(Duration::from_secs(30)).unwrap();

    // The lane, as `auto init` will make it.
    let before = waiter.snapshot().bases.len();
    waiter
        .command(
            Command::ImportBase { directory: bundle },
            Some(Duration::from_secs(600)),
        )
        .expect("import");
    settle(&mut waiter, "the base", 30, |s| s.bases.len() > before);
    let base = waiter.snapshot().bases.last().map(|b| b.id.clone());
    waiter
        .command(
            Command::Create(VmConfig {
                name: "lane-stages".into(),
                cpus: 2,
                ram_mib: 512,
                disk_gib: 2,
                base_identity: base.clone(),
                routed: true,
                ..VmConfig::default()
            }),
            Some(Duration::from_secs(900)),
        )
        .expect("create");
    settle(&mut waiter, "the VM", 30, |s| !s.vms.is_empty());
    let vm_id = waiter.snapshot().vms[0].id.clone();
    waiter
        .command(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            Some(Duration::from_secs(300)),
        )
        .expect("first boot");
    settle(&mut waiter, "the guest", 120, |s| {
        s.state == VmState::Running && s.guest_kernel.is_some()
    });
    waiter
        .stop_vm(&vm_id, Some(Duration::from_secs(600)))
        .expect("stop");
    waiter
        .command(
            Command::CreateVmSnapshot {
                vm_id: vm_id.clone(),
                request: SnapshotRequest {
                    name: "auto-clean".into(),
                    description: "lane stages test".into(),
                    mode: VmSnapshotMode::Disk,
                },
            },
            Some(Duration::from_secs(600)),
        )
        .expect("snapshot");
    settle(&mut waiter, "the snapshot", 30, |s| {
        s.vm_snapshot_trees
            .get(&vm_id)
            .is_some_and(|t| !t.nodes.is_empty())
    });
    let clean = waiter.snapshot().vm_snapshot_trees[&vm_id].nodes[0]
        .id
        .clone();

    (waiter, vm_id, clean, base)
}

#[test]
#[ignore = "needs KVM, a base bundle and a private data directory"]
fn the_stages_prechecks_to_launch_on_a_real_vm() {
    let bundle = env_path("ANTINOMIE_LANE_VM_BUNDLE");
    let data = env_path("ANTINOMIE_LANE_VM_DATA");
    std::fs::create_dir_all(&data).unwrap();
    let (mut waiter, vm_id, clean, base) = setup_lane(bundle, &data);

    let service = data.join("service");
    let lanes = LaneDir::new(&service);
    let now = 1_794_000_000_000;
    lanes
        .save(&LaneFile::new(
            LaneId::new(1),
            &vm_id,
            &clean,
            base.as_deref().unwrap_or("base"),
            now,
        ))
        .unwrap();

    // The sample: a benign script in the library.
    let mut library = Library::open(&data).expect("library");
    let added = library
        .add_bytes(
            SCRIPT.as_bytes(),
            NewSample {
                name: "lane-check.sh".into(),
                ..NewSample::default()
            },
        )
        .expect("add sample");
    let sample = JobSample {
        sha256: Sha256Hex::try_from(added.sha256.clone()).unwrap(),
        size: SCRIPT.len() as u64,
        kind: "sh".into(),
        architecture: None,
        name: "lane-check.sh".into(),
    };
    let mut policy = Policy::default();
    policy.vm.lane_vm = Some(vm_id.clone());
    policy.sample.accept_types = vec!["sh".into(), "elf".into()];
    policy.run.timeout_s = 30;
    let policies = PolicySet::single(LoadedPolicy {
        name: "default".into(),
        digest: "test".into(),
        policy,
    });
    let store = Store::open(&service).expect("store");
    let admit = Admit { sample };
    let caller = Caller {
        client_id: "local:1000".into(),
        scopes: vec![Scope::Read, Scope::Submit],
        policies: vec![],
    };

    let procs = ProcFs;
    for round in 1..=2 {
        let spec: JobSpec = serde_json::from_value(serde_json::json!({
            "sample": {"sha256": added.sha256},
            "labels": {"round": round.to_string()},
        }))
        .unwrap();
        // Same sample twice: the duplicate rule of the default policy is `run`.
        let submitted = store
            .submit(
                &caller,
                spec,
                &SubmitContext {
                    policies: &policies,
                    intake: &admit,
                    limits: SubmitLimits::default(),
                    on_duplicate: None,
                },
            )
            .expect("submit");
        assert_eq!(
            submitted.job.state,
            JobState::Queued,
            "{:?}",
            submitted.job.failure
        );

        let mut stages = LaneStages {
            waiter: &mut waiter,
            env: LaneEnv {
                store: &store,
                lanes: &lanes,
                policies: &policies,
                procs: &procs,
                host: &NoHostChecks,
                evidence: &antinomie_service::waiter::load_artifacts,
                triage: &triage(&data),
                tags: &NoTags,
            },
            lane: LaneId::new(1),
        };
        assert_eq!(stages.eligibility(), Eligibility::Ready, "round {round}");
        let job = store
            .claim_next(&LaneId::new(1), &mut |_| Eligibility::Ready)
            .unwrap()
            .expect("the job is claimed");
        let begun = std::time::Instant::now();
        let launched = match stages.run_to_launch(&job) {
            Ok(launched) => launched,
            Err(stop) => panic!("round {round}: {stop:?}"),
        };
        println!(
            "round {round}: prechecks to launch in {:.1} s, run {} pid {}",
            begun.elapsed().as_secs_f64(),
            launched.run.id,
            launched.run.pid
        );
        assert_eq!(
            launched.guest_path.len(),
            "/tmp/".len() + 8 + 1 + "lane-check.sh".len()
        );

        let stored = store.get(&job.id).unwrap();
        assert_eq!(stored.state, JobState::Running);
        assert!(stored.vm.is_some() && stored.run.is_some() && stored.recording.is_some());

        // The recorded process is the VM's QEMU.
        let record = lanes
            .load(&LaneId::new(1))
            .unwrap()
            .unwrap()
            .qemu
            .expect("a QEMU pid was recorded");
        let info = procs.info(record.pid).expect("the recorded process exists");
        assert!(info.argv[0].contains("qemu-system"), "{:?}", info.argv);
        assert!(info.argv.iter().any(|a| a.contains(&record.marker)));

        // Let the script finish, then stop the VM and settle it.
        let run_id = launched.run.id.clone();
        settle(stages.waiter, "the script to end", 60, |s| {
            s.runs
                .iter()
                .find(|r| r.id == run_id)
                .is_some_and(|r| phase(r) == Phase::Ended)
        });
        stages
            .waiter
            .stop_vm(&vm_id, Some(Duration::from_secs(1800)))
            .expect("stop");
        // QEMU is gone once the VM is stopped: the pid names no process of ours.
        assert!(
            procs
                .info(record.pid)
                .is_none_or(|i| i.start_ticks != record.start_ticks),
            "the recorded QEMU is still running after the stop"
        );
        // Job bookkeeping for the next round.
        store
            .finish(
                &job.id,
                antinomie_service::api::job::Outcome::Succeeded,
                None,
            )
            .unwrap();
        lanes.update(&LaneId::new(1), |f| f.end_work(now)).unwrap();
    }
    let _ = (FailureCode::Internal, BTreeMap::<u8, u8>::new());
    waiter.into_engine().shutdown().expect("shutdown");
}

/// A benign shell script in the library; the sample record for a job.
fn add_script(data: &std::path::Path, name: &str, script: &str) -> JobSample {
    let mut library = Library::open(data).expect("library");
    let added = library
        .add_bytes(
            script.as_bytes(),
            NewSample {
                name: name.into(),
                ..NewSample::default()
            },
        )
        .expect("add sample");
    JobSample {
        sha256: Sha256Hex::try_from(added.sha256).unwrap(),
        size: script.len() as u64,
        kind: "sh".into(),
        architecture: None,
        name: name.into(),
    }
}

#[test]
#[ignore = "needs KVM, a base bundle and a private data directory"]
fn whole_jobs_to_collect_with_a_run_limit_and_a_cancel_on_a_real_vm() {
    let bundle = env_path("ANTINOMIE_LANE_VM_BUNDLE");
    let data = env_path("ANTINOMIE_LANE_VM_DATA");
    std::fs::create_dir_all(&data).unwrap();
    let (mut waiter, vm_id, clean, base) = setup_lane(bundle, &data);
    let service = data.join("service");
    let lanes = LaneDir::new(&service);
    lanes
        .save(&LaneFile::new(
            LaneId::new(1),
            &vm_id,
            &clean,
            base.as_deref().unwrap_or("base"),
            1_794_000_000_000,
        ))
        .unwrap();
    let mut policy = Policy::default();
    policy.vm.lane_vm = Some(vm_id.clone());
    policy.sample.accept_types = vec!["sh".into()];
    policy.run.timeout_s = 60;
    // The host stages on the private data directory: a few static checks in
    // bubblewrap, the Triage scan, no detection engines (the private
    // directory has no rule packs), three report formats.
    policy.analysis.static_checks = antinomie_service::api::spec::StaticChecks::Names(vec![
        antinomie_service::api::spec::StaticCheck::Metadata,
        antinomie_service::api::spec::StaticCheck::Strings,
        antinomie_service::api::spec::StaticCheck::Entropy,
    ]);
    policy.analysis.static_time_limit_min = 1;
    policy.analysis.detection = antinomie_service::config::policy::Detection {
        yara: false,
        sigma: false,
        ids: false,
    };
    policy.report.formats = vec![
        antinomie_service::api::spec::ReportFormat::Html,
        antinomie_service::api::spec::ReportFormat::Json,
        antinomie_service::api::spec::ReportFormat::Md,
    ];
    let policies = PolicySet::single(LoadedPolicy {
        name: "default".into(),
        digest: "test".into(),
        policy,
    });
    let store = Store::open(&service).expect("store");
    let caller = Caller {
        client_id: "local:1000".into(),
        scopes: vec![Scope::Read, Scope::Submit],
        policies: vec![],
    };
    let procs = ProcFs;

    // job name, script, timeout_s, what must happen
    let jobs: [(&str, &str, u32); 3] = [
        (
            "ends.sh",
            // Benign: reads the account file, drops a copy of a system
            // binary into /tmp and makes it executable.
            "#!/bin/sh\necho whole-job\ncat /etc/passwd > /dev/null\ncp /bin/busybox /tmp/dropped.bin\nchmod +x /tmp/dropped.bin\necho note > /tmp/note.txt\nsleep 2\necho done\nexit 3\n",
            60,
        ),
        ("limit.sh", "#!/bin/sh\necho limit\nsleep 300\n", 15),
        ("cancel.sh", "#!/bin/sh\necho cancel\nsleep 300\n", 120),
    ];
    for (round, (name, script, timeout_s)) in jobs.iter().enumerate() {
        let sample = add_script(&data, name, script);
        let sha = sample.sha256.to_string();
        let spec: JobSpec = serde_json::from_value(serde_json::json!({
            "sample": {"sha256": sha},
            "overrides": {"timeout_s": timeout_s},
        }))
        .unwrap();
        let admit = Admit { sample };
        let submitted = store
            .submit(
                &caller,
                spec,
                &SubmitContext {
                    policies: &policies,
                    intake: &admit,
                    limits: SubmitLimits::default(),
                    on_duplicate: None,
                },
            )
            .expect("submit");
        assert_eq!(
            submitted.job.state,
            JobState::Queued,
            "{:?}",
            submitted.job.failure
        );
        let job = store
            .claim_next(&LaneId::new(1), &mut |_| Eligibility::Ready)
            .unwrap()
            .expect("the job is claimed");
        let began = std::time::Instant::now();
        let driven = std::thread::scope(|scope| {
            if *name == "cancel.sh" {
                // A user cancels the job while the program runs.
                scope.spawn(|| {
                    std::thread::sleep(Duration::from_secs(75));
                    store
                        .cancel(
                            &job.id,
                            Some("vm test"),
                            &Caller {
                                client_id: "local:1000".into(),
                                scopes: vec![Scope::Read, Scope::Submit],
                                policies: vec![],
                            },
                        )
                        .expect("cancel");
                });
            }
            let mut stages = LaneStages {
                waiter: &mut waiter,
                env: LaneEnv {
                    store: &store,
                    lanes: &lanes,
                    policies: &policies,
                    procs: &procs,
                    host: &NoHostChecks,
                    evidence: &antinomie_service::waiter::load_artifacts,
                    triage: &triage(&data),
                    tags: &NoTags,
                },
                lane: LaneId::new(1),
            };
            let driven = stages.drive(&job);
            if let Driven::Collected(end) = &driven {
                match stages.host(&job, end) {
                    Hosted::Finished(done) => println!(
                        "job {round} ({name}): host stages done, {:?}, label {:?}",
                        done.state,
                        done.assessment.as_ref().and_then(|a| a.label)
                    ),
                    other => panic!("host stages: {other:?}"),
                }
            }
            driven
        });
        let stored = store.get(&job.id).unwrap();
        let run = stored.run.clone().expect("a run");
        println!(
            "job {round} ({name}): {:.1} s, {:?}, state {:?}, run end {:?} exit {:?}, recording {:?}",
            began.elapsed().as_secs_f64(),
            std::mem::discriminant(&driven),
            stored.state,
            run.end_reason,
            run.exit,
            stored.recording.as_ref().map(|r| r.phase)
        );
        match *name {
            "ends.sh" => {
                assert!(matches!(driven, Driven::Collected(_)), "{driven:?}");
                assert_eq!(stored.state, JobState::Succeeded, "{:?}", stored.warnings);
                assert_eq!(run.end_reason, Some(EndReason::Exited));
                assert_eq!(run.exit, Some(3));
                let a = stored.assessment.as_ref().expect("an assessment");
                println!(
                    "ASSESSMENT: {:?} / tier {:?} / label {:?} / score {:?}\nBASIS: {}\nCOUNTS: {:?}",
                    a.assessment, a.highest_tier, a.label, a.score, a.basis, a.counts
                );
                for b in &a.key_behaviours {
                    println!(
                        "BEHAVIOUR: {:?} {} ({}) x{}",
                        b.tier, b.rule, b.category, b.count
                    );
                }
                assert!(stored.artifacts.len() == 3, "{:?}", stored.artifacts);
                for artifact in &stored.artifacts {
                    let path = store
                        .job_dir(&job.id)
                        .join("artifacts")
                        .join(&artifact.name);
                    let size = std::fs::metadata(&path).expect("report file").len();
                    println!(
                        "REPORT: {} ({} bytes, sha256 {})",
                        path.display(),
                        size,
                        artifact.sha256
                    );
                    assert_eq!(size, artifact.size);
                }
                assert!(store.job_dir(&job.id).join("job.json").is_file());
            }
            "limit.sh" => {
                assert!(matches!(driven, Driven::Collected(_)), "{driven:?}");
                assert_eq!(stored.state, JobState::Succeeded, "{:?}", stored.warnings);
                assert_eq!(run.end_reason, Some(EndReason::TimeLimit));
                println!(
                    "limit.sh label {:?}",
                    stored.assessment.as_ref().and_then(|a| a.label)
                );
            }
            _ => {
                assert!(matches!(driven, Driven::Cancelled), "{driven:?}");
                assert_eq!(stored.state, JobState::Cancelled);
                assert_eq!(run.end_reason, Some(EndReason::Stopped));
            }
        }
        if *name != "cancel.sh" {
            assert_eq!(
                stored.recording.as_ref().map(|r| r.phase),
                Some(RecordingPhase::Complete)
            );
        }
        // The lane is free, the VM stopped, nothing pending, no process left.
        let snapshot = waiter.snapshot();
        assert_eq!(snapshot.state, VmState::Stopped);
        assert!(snapshot.disk_layers.iter().all(|l| l.vm_id != vm_id));
        assert!(snapshot.recording_flush.is_none());
        let file = lanes.load(&LaneId::new(1)).unwrap().unwrap();
        assert!(file.current.is_none() && file.collected.is_empty() && file.qemu.is_none());
    }
    waiter.into_engine().shutdown().expect("shutdown");
}
