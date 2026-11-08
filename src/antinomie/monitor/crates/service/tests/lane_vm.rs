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
        job::{JobSample, JobState},
        ops::{Caller, Scope},
        spec::{JobSpec, SampleSource},
    },
    clock::SystemClock,
    config::{LoadedPolicy, Policy, PolicySet},
    lane::{LaneDir, LaneFile, ProcFs, Processes},
    stages::{LaneEnv, LaneStages, NoHostChecks},
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

#[test]
#[ignore = "needs KVM, a base bundle and a private data directory"]
fn the_stages_prechecks_to_launch_on_a_real_vm() {
    let bundle = env_path("ANTINOMIE_LANE_VM_BUNDLE");
    let data = env_path("ANTINOMIE_LANE_VM_DATA");
    std::fs::create_dir_all(&data).unwrap();

    let backend = Backend::new(BackendOptions {
        data_dir: data.clone(),
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
