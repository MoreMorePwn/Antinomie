// SPDX-License-Identifier: GPL-3.0-only
//! Tests of retention (T9 cases of card P4-3): real job store, the run
//! deletion faked so sizes, open reads and unfinished artifacts can be set.

use super::{GcReport, REJECTED_DAYS, RealRuns, Retention, RunState, Runs, delete_job};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        ids::JobId,
        job::{Job, JobRecording, Outcome, RecordingPhase, Stage},
    },
    config::service::Retention as Config,
    store::{JobPatch, tests::Fx},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::Mutex,
};

const DAY: u64 = 24 * 60 * 60 * 1000;
const GIB: u64 = 1 << 30;
const NOW: u64 = 1_794_000_000_000 + 400 * DAY;

#[derive(Default)]
struct FakeRuns {
    runs: Mutex<BTreeMap<String, (u64, bool)>>,
    open: Mutex<BTreeSet<String>>,
    deleted: Mutex<Vec<(String, String)>>,
    fail_for: Mutex<BTreeSet<String>>,
}

impl FakeRuns {
    fn put(&self, job: &JobId, bytes: u64, in_progress: bool) {
        self.runs
            .lock()
            .unwrap()
            .insert(job.to_string(), (bytes, in_progress));
    }
    fn deleted_jobs(&self) -> Vec<String> {
        self.deleted
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.0.clone())
            .collect()
    }
}

impl Runs for FakeRuns {
    fn inspect(&self, job: &Job) -> Result<RunState, String> {
        Ok(match self.runs.lock().unwrap().get(job.id.as_str()) {
            Some((bytes, in_progress)) => RunState::Present {
                bytes: *bytes,
                in_progress: *in_progress,
            },
            None => RunState::Gone,
        })
    }
    fn is_open(&self, job: &Job) -> bool {
        self.open.lock().unwrap().contains(job.id.as_str())
    }
    fn delete(&self, job: &Job, actor: &str) -> Result<u64, String> {
        if self.fail_for.lock().unwrap().contains(job.id.as_str()) {
            return Err("the engine refused".into());
        }
        let (bytes, _) = self
            .runs
            .lock()
            .unwrap()
            .remove(job.id.as_str())
            .ok_or("gone")?;
        self.deleted
            .lock()
            .unwrap()
            .push((job.id.to_string(), actor.to_owned()));
        Ok(bytes)
    }
}

struct Rig {
    fx: Fx,
    runs: FakeRuns,
    log: Mutex<Vec<String>>,
}

impl Rig {
    fn new(name: &str) -> Self {
        Self {
            fx: Fx::new(&format!("gc-{name}")),
            runs: FakeRuns::default(),
            log: Mutex::new(Vec::new()),
        }
    }

    /// An ended job that finished at `finished_ms` with a recording of
    /// `bytes` (none: no recording).
    fn ended(&self, outcome: Outcome, finished_ms: u64, bytes: Option<u64>) -> JobId {
        self.fx.clock.set(finished_ms.saturating_sub(1000));
        let job = self.fx.running(1);
        if let Some(bytes) = bytes {
            let dir = self.fx.dir.join("run").join(job.id.as_str());
            fs::create_dir_all(&dir).unwrap();
            self.fx
                .store
                .patch(
                    &job.id,
                    JobPatch {
                        recording: Some(JobRecording {
                            vm_id: "vm".into(),
                            boot_id: "boot".into(),
                            run_id: format!("r-{}", &job.id.as_str()[job.id.as_str().len() - 4..]),
                            run_key: "key".into(),
                            phase: RecordingPhase::Complete,
                            directory: Some(dir.display().to_string()),
                        }),
                        ..JobPatch::default()
                    },
                )
                .unwrap();
            self.runs.put(&job.id, bytes, false);
        }
        self.fx.clock.set(finished_ms);
        let failure = (outcome == Outcome::Failed)
            .then(|| Failure::new(FailureCode::LaunchFailed, Stage::Launch, "no", None));
        self.fx.store.finish(&job.id, outcome, failure).unwrap();
        job.id
    }

    fn config(&self) -> Config {
        Config::default()
    }

    fn run_with(&self, config: Config, dry_run: bool) -> GcReport {
        let log = |line: &str| self.log.lock().unwrap().push(line.to_owned());
        let rejected = self.fx.dir.join("rejected");
        Retention {
            store: &self.fx.store,
            runs: &self.runs,
            config,
            rejected_dir: rejected,
            uploads: None,
            now_ms: NOW,
            log: &log,
        }
        .run(dry_run)
    }

    fn run(&self, dry_run: bool) -> GcReport {
        self.run_with(self.config(), dry_run)
    }

    fn exists(&self, id: &JobId) -> bool {
        self.fx.store.get(id).is_ok()
    }
}

fn kinds(report: &GcReport) -> Vec<(String, Option<String>)> {
    report
        .actions
        .iter()
        .map(|a| (a.kind.clone(), a.job.clone()))
        .collect()
}

#[test]
fn a_recording_past_fourteen_days_goes_and_a_younger_one_stays() {
    let rig = Rig::new("age");
    let old = rig.ended(Outcome::Succeeded, NOW - 15 * DAY, Some(100));
    let young = rig.ended(Outcome::Succeeded, NOW - 13 * DAY, Some(100));
    let report = rig.run(false);
    assert_eq!(rig.runs.deleted_jobs(), [old.to_string()]);
    assert_eq!(
        kinds(&report),
        [("recording".to_owned(), Some(old.to_string()))]
    );
    assert!(report.actions[0].done);
    assert_eq!(report.freed_bytes, 100);
    assert!(rig.exists(&old) && rig.exists(&young), "records stay");
    assert!(
        rig.log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains(old.as_str()))
    );
}

#[test]
fn the_custody_actor_of_a_deletion_is_the_automation_actor_of_the_policy() {
    let rig = Rig::new("actor");
    rig.ended(Outcome::Succeeded, NOW - 20 * DAY, Some(1));
    rig.run(false);
    assert_eq!(rig.runs.deleted.lock().unwrap()[0].1, "auto:policy-default");
}

#[test]
fn a_dry_run_changes_nothing_and_says_what_it_would_do() {
    let rig = Rig::new("dry");
    let old = rig.ended(Outcome::Succeeded, NOW - 20 * DAY, Some(100));
    let ancient = rig.ended(Outcome::Succeeded, NOW - 100 * DAY, None);
    let report = rig.run(true);
    assert!(report.dry_run);
    assert!(rig.runs.deleted_jobs().is_empty());
    assert!(rig.exists(&old) && rig.exists(&ancient));
    assert!(report.actions.iter().all(|a| !a.done));
    let k = kinds(&report);
    assert!(
        k.contains(&("recording".into(), Some(old.to_string()))),
        "{k:?}"
    );
    assert!(
        k.contains(&("job".into(), Some(ancient.to_string()))),
        "{k:?}"
    );
    assert!(
        rig.log.lock().unwrap().is_empty(),
        "a dry run logs no deletion"
    );
    // For real, the same plan is carried out.
    let real = rig.run(false);
    assert_eq!(kinds(&real), k);
    assert!(real.actions.iter().all(|a| a.done));
    assert!(!rig.exists(&ancient));
}

#[test]
fn a_job_that_has_not_ended_is_never_touched() {
    let rig = Rig::new("running");
    rig.fx.clock.set(NOW - 200 * DAY);
    let running = rig.fx.running(1);
    // It has a recording, a very old one, and the recording is big.
    rig.fx
        .store
        .patch(
            &running.id,
            JobPatch {
                recording: Some(JobRecording {
                    vm_id: "vm".into(),
                    boot_id: "boot".into(),
                    run_id: "r-live".into(),
                    run_key: "key".into(),
                    phase: RecordingPhase::Live,
                    directory: None,
                }),
                ..JobPatch::default()
            },
        )
        .unwrap();
    rig.runs.put(&running.id, 999 * GIB, false);
    let queued = rig.fx.queued(2);
    let report = rig.run(false);
    assert!(report.actions.is_empty(), "{:?}", report.actions);
    assert!(rig.exists(&running.id) && rig.exists(&queued.id));
    assert!(rig.runs.deleted_jobs().is_empty());
    // Not even with a size cap of nothing.
    let mut config = rig.config();
    config.max_recordings_gib = 0;
    let report = rig.run_with(config, false);
    assert!(report.actions.is_empty());
    assert!(rig.runs.deleted_jobs().is_empty());
}

#[test]
fn a_recording_with_an_open_read_is_skipped_and_taken_when_the_read_ends() {
    let rig = Rig::new("lease");
    let old = rig.ended(Outcome::Succeeded, NOW - 20 * DAY, Some(100));
    rig.runs.open.lock().unwrap().insert(old.to_string());
    let report = rig.run(false);
    assert!(report.actions.is_empty());
    assert_eq!(report.skipped.len(), 1);
    assert!(report.skipped[0].why.contains("read of the run is open"));
    assert!(rig.runs.deleted_jobs().is_empty());
    rig.runs.open.lock().unwrap().clear();
    assert_eq!(rig.run(false).actions.len(), 1);
}

#[test]
fn a_run_whose_artifacts_are_still_being_written_is_skipped() {
    let rig = Rig::new("inprogress");
    let old = rig.ended(Outcome::Succeeded, NOW - 20 * DAY, Some(100));
    rig.runs.put(&old, 100, true);
    let report = rig.run(false);
    assert!(report.actions.is_empty());
    assert!(report.skipped[0].why.contains("still being written"));
}

#[test]
fn a_failed_jobs_recording_is_kept_until_the_job_record_goes() {
    let rig = Rig::new("keepfailed");
    rig.ended(Outcome::Failed, NOW - 30 * DAY, Some(100));
    let report = rig.run(false);
    assert!(report.actions.is_empty());
    assert!(report.skipped[0].why.contains("keep_failed"));
    // keep_failed off: it goes like any other.
    let mut config = rig.config();
    config.keep_failed = false;
    assert_eq!(rig.run_with(config, false).actions.len(), 1);
    // At jobs_days the record goes, and the recording with it.
    let rig = Rig::new("keepfailed2");
    let failed2 = rig.ended(Outcome::Failed, NOW - 91 * DAY, Some(50));
    let report = rig.run(false);
    let k = kinds(&report);
    assert_eq!(
        k,
        [
            ("recording".to_owned(), Some(failed2.to_string())),
            ("job".to_owned(), Some(failed2.to_string()))
        ]
    );
    assert!(!rig.exists(&failed2));
}

#[test]
fn above_the_cap_the_oldest_recordings_go_first_and_protected_ones_last() {
    let rig = Rig::new("cap");
    // Four 40-GiB recordings of the last two weeks and a failed one: 200 GiB
    // is the cap, 240 GiB are held.
    let failed = rig.ended(Outcome::Failed, NOW - 6 * DAY, Some(40 * GIB));
    let a = rig.ended(Outcome::Succeeded, NOW - 5 * DAY, Some(40 * GIB));
    let b = rig.ended(Outcome::Succeeded, NOW - 4 * DAY, Some(40 * GIB));
    let c = rig.ended(Outcome::Succeeded, NOW - 3 * DAY, Some(40 * GIB));
    let d = rig.ended(Outcome::Succeeded, NOW - 2 * DAY, Some(40 * GIB));
    let e = rig.ended(Outcome::Succeeded, NOW - DAY, Some(40 * GIB));
    let report = rig.run(false);
    // 240 GiB held, the cap is 200: one goes, the oldest not protected.
    assert_eq!(rig.runs.deleted_jobs(), [a.to_string()], "{report:?}");
    let mut config = rig.config();
    config.max_recordings_gib = 100;
    let report = rig.run_with(config, false);
    // 200 GiB held, now 100: three more (120 GiB would still be above), oldest first.
    assert_eq!(
        rig.runs.deleted_jobs(),
        [a.to_string(), b.to_string(), c.to_string(), d.to_string()],
        "{report:?}"
    );
    let mut config = rig.config();
    config.max_recordings_gib = 0;
    rig.run_with(config, false);
    let deleted = rig.runs.deleted_jobs();
    assert_eq!(deleted[4..], [e.to_string(), failed.to_string()]);
}

#[test]
fn a_cap_never_deletes_what_is_open_and_stops_when_it_cannot_reach_the_cap() {
    let rig = Rig::new("capopen");
    let a = rig.ended(Outcome::Succeeded, NOW - 5 * DAY, Some(2 * GIB));
    let b = rig.ended(Outcome::Succeeded, NOW - 4 * DAY, Some(2 * GIB));
    rig.runs.open.lock().unwrap().insert(a.to_string());
    let mut config = rig.config();
    config.max_recordings_gib = 1;
    let report = rig.run_with(config, false);
    assert_eq!(rig.runs.deleted_jobs(), [b.to_string()]);
    assert_eq!(report.skipped.len(), 1);
}

#[test]
fn a_job_record_goes_after_ninety_days_with_its_folder_and_events() {
    let rig = Rig::new("jobs");
    let old = rig.ended(Outcome::Succeeded, NOW - 91 * DAY, None);
    let young = rig.ended(Outcome::Succeeded, NOW - 89 * DAY, None);
    let folder = rig.fx.store.job_dir(&old);
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("job.json"), b"{}").unwrap();
    let report = rig.run(false);
    assert_eq!(kinds(&report), [("job".to_owned(), Some(old.to_string()))]);
    assert!(!rig.exists(&old));
    assert!(!folder.exists());
    assert!(rig.exists(&young));
    assert!(
        rig.fx.store.events_list(&old, 0, 10).is_err(),
        "its events are gone"
    );
}

#[test]
fn a_job_whose_recording_cannot_go_stays() {
    let rig = Rig::new("jobstays");
    let old = rig.ended(Outcome::Succeeded, NOW - 120 * DAY, Some(10));
    rig.runs.open.lock().unwrap().insert(old.to_string());
    let report = rig.run(false);
    assert!(rig.exists(&old));
    assert!(report.skipped.iter().any(|s| s.kind == "job"));
    assert!(rig.runs.deleted_jobs().is_empty());
}

#[test]
fn a_failed_deletion_is_reported_and_the_pass_goes_on() {
    let rig = Rig::new("fails");
    let a = rig.ended(Outcome::Succeeded, NOW - 20 * DAY, Some(10));
    let b = rig.ended(Outcome::Succeeded, NOW - 19 * DAY, Some(10));
    rig.runs.fail_for.lock().unwrap().insert(a.to_string());
    let report = rig.run(false);
    assert_eq!(rig.runs.deleted_jobs(), [b.to_string()]);
    assert_eq!(report.errors.len(), 1);
    assert!(report.errors[0].contains("the engine refused"));
}

#[test]
fn rejected_files_go_after_seven_days_and_only_plain_files() {
    let rig = Rig::new("rejected");
    let dir = rig.fx.dir.join("rejected");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("old.sh"), b"x").unwrap();
    fs::write(dir.join("old.sh.reason"), b"x").unwrap();
    fs::write(dir.join("new.sh"), b"x").unwrap();
    fs::create_dir(dir.join("subdir")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", dir.join("link")).unwrap();
    let eight_days = std::time::SystemTime::UNIX_EPOCH
        + std::time::Duration::from_millis(NOW - (REJECTED_DAYS + 1) * DAY);
    for name in ["old.sh", "old.sh.reason", "link"] {
        let file = fs::File::options().write(true).open(dir.join(name));
        if let Ok(file) = file {
            file.set_modified(eight_days).unwrap();
        }
    }
    // The fresh file is "now" in the test's clock.
    let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(NOW - DAY);
    fs::File::options()
        .write(true)
        .open(dir.join("new.sh"))
        .unwrap()
        .set_modified(now)
        .unwrap();
    let report = rig.run(false);
    let mut gone: Vec<_> = report
        .actions
        .iter()
        .filter(|a| a.kind == "rejected_file")
        .map(|a| a.detail.clone())
        .collect();
    gone.sort();
    assert_eq!(gone.len(), 2, "{gone:?}");
    assert!(!dir.join("old.sh").exists() && !dir.join("old.sh.reason").exists());
    assert!(dir.join("new.sh").exists());
    assert!(dir.join("subdir").is_dir());
    assert!(
        fs::symlink_metadata(dir.join("link")).is_ok(),
        "a link is left alone"
    );
}

#[test]
fn the_library_and_other_folders_are_never_touched() {
    let rig = Rig::new("library");
    let library = rig.fx.dir.join("library");
    fs::create_dir_all(&library).unwrap();
    fs::write(library.join("sample.zip"), b"archive").unwrap();
    let processed = rig.fx.dir.join("inbox").join("processed");
    fs::create_dir_all(&processed).unwrap();
    fs::write(processed.join("1-a.sh"), b"x").unwrap();
    rig.ended(Outcome::Succeeded, NOW - 500 * DAY, Some(10));
    rig.run(false);
    assert_eq!(fs::read(library.join("sample.zip")).unwrap(), b"archive");
    assert!(processed.join("1-a.sh").exists());
}

#[test]
fn job_delete_removes_an_ended_job_and_refuses_a_running_one() {
    let rig = Rig::new("jobdelete");
    let log = |_: &str| {};
    let done = rig.ended(Outcome::Succeeded, NOW - DAY, Some(10));
    delete_job(&rig.fx.store, &rig.runs, &done, false, &log).unwrap();
    assert!(!rig.exists(&done));
    assert!(
        rig.runs.deleted_jobs().is_empty(),
        "the recording stays unless asked"
    );

    rig.fx.clock.set(NOW);
    let running = rig.fx.running(1);
    let error = delete_job(&rig.fx.store, &rig.runs, &running.id, true, &log).unwrap_err();
    assert_eq!(error.code, crate::api::error::ErrorCode::Conflict);
    assert!(rig.exists(&running.id));
    let missing = JobId::try_from("j_01M6YKYH8ND7M6F3PB0X0D5VH9".to_owned()).unwrap();
    assert_eq!(
        delete_job(&rig.fx.store, &rig.runs, &missing, false, &log)
            .unwrap_err()
            .code,
        crate::api::error::ErrorCode::NotFound
    );
}

#[test]
fn job_delete_with_recording_deletes_it_first_and_respects_open_reads() {
    let rig = Rig::new("jobdelete2");
    let log = |_: &str| {};
    let id = rig.ended(Outcome::Succeeded, NOW - DAY, Some(10));
    rig.runs.open.lock().unwrap().insert(id.to_string());
    let error = delete_job(&rig.fx.store, &rig.runs, &id, true, &log).unwrap_err();
    assert_eq!(
        error.reason(),
        Some(crate::api::error::ErrorReason::RecordingOpen)
    );
    assert!(rig.exists(&id) && rig.runs.deleted_jobs().is_empty());
    rig.runs.open.lock().unwrap().clear();
    delete_job(&rig.fx.store, &rig.runs, &id, true, &log).unwrap();
    assert_eq!(rig.runs.deleted_jobs(), [id.to_string()]);
    assert!(!rig.exists(&id));
}

/// A finished job whose recording is said to be in `directory`.
fn job_with_folder(rig: &Rig, directory: &std::path::Path, run_id: &str) -> Job {
    let job = rig.fx.running(1);
    rig.fx
        .store
        .patch(
            &job.id,
            JobPatch {
                recording: Some(JobRecording {
                    vm_id: "vm".into(),
                    boot_id: "boot".into(),
                    run_id: run_id.into(),
                    run_key: "key".into(),
                    phase: RecordingPhase::Complete,
                    directory: Some(directory.display().to_string()),
                }),
                ..JobPatch::default()
            },
        )
        .unwrap();
    rig.fx
        .store
        .finish(&job.id, Outcome::Succeeded, None)
        .unwrap()
}

#[test]
fn the_real_runs_only_trust_a_plain_run_folder_inside_the_data_folder() {
    use antinomie_monitor_core::{BackendOptions, RunArtifactState, RunArtifacts};
    let rig = Rig::new("real");
    let data = rig.fx.dir.join("data");
    let outside = rig.fx.dir.join("outside");
    fs::create_dir_all(data.join("vm/runs/r1")).unwrap();
    fs::create_dir_all(outside.join("r5")).unwrap();
    fs::create_dir_all(outside.join("r6")).unwrap();
    fs::write(data.join("vm/runs/r1/run.json"), [0u8; 10]).unwrap();
    fs::write(outside.join("r5/precious"), b"x").unwrap();
    let options = BackendOptions {
        data_dir: data.clone(),
        ..BackendOptions::default()
    };
    let runs = RealRuns {
        options: &options,
        query: None,
    };
    let inspect = |dir: &std::path::Path, run: &str| runs.inspect(&job_with_folder(&rig, dir, run));

    // A plain folder of the run: its bytes, nothing in progress.
    assert_eq!(
        inspect(&data.join("vm/runs/r1"), "r1"),
        Ok(RunState::Present {
            bytes: 10,
            in_progress: false
        })
    );
    // A capture still being written.
    let artifacts = RunArtifacts {
        network_state: RunArtifactState::Recording,
        ..RunArtifacts::default()
    };
    fs::write(
        data.join("vm/runs/r1/artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        inspect(&data.join("vm/runs/r1"), "r1"),
        Ok(RunState::Present {
            in_progress: true,
            ..
        })
    ));
    // Gone is gone.
    assert_eq!(inspect(&data.join("vm/runs/r2"), "r2"), Ok(RunState::Gone));
    // A link in the place of the folder, a folder elsewhere, a link above it,
    // a name that is not the run's, a path that climbs: all refused.
    std::os::unix::fs::symlink(outside.join("r5"), data.join("vm/runs/r3")).unwrap();
    assert!(inspect(&data.join("vm/runs/r3"), "r3").is_err());
    assert!(inspect(&outside.join("r5"), "r5").is_err());
    std::os::unix::fs::symlink(&outside, data.join("vm/up")).unwrap();
    assert!(inspect(&data.join("vm/up/r6"), "r6").is_err());
    assert!(inspect(&data.join("vm/runs/r1"), "r9").is_err());
    assert!(inspect(&data.join("vm/runs/../runs/r1"), "r1").is_err());
    assert!(inspect(std::path::Path::new("relative/r1"), "r1").is_err());
    assert_eq!(fs::read(outside.join("r5/precious")).unwrap(), b"x");
}
