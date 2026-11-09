// SPDX-License-Identifier: GPL-3.0-only
//! Tests of the result drop and the command hook (T9 cases of card P4-4):
//! a real job store, real folders, real commands. Nothing here runs a sample.

use super::{
    Delivery, Marker, SWEEP_MS,
    hook::{self, OUTPUT_LIMIT},
};
use crate::{
    api::{
        artifact::{ArtifactKind, MediaType},
        assessment::{Assessment, AssessmentKind, Counts, Label, Tier},
        ids::{JobId, Sha256Hex},
        job::{Job, Outcome},
    },
    store::{NewArtifact, tests::Fx},
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

const T: u64 = 1_794_000_000_000;

struct Rig {
    fx: Fx,
    results: PathBuf,
    mode: std::cell::Cell<crate::config::service::ResultsMode>,
    alerts: Mutex<Vec<String>>,
    log: Mutex<Vec<String>>,
}

impl Rig {
    fn new(name: &str) -> Self {
        let fx = Fx::new(&format!("notify-{name}"));
        let results = fx.dir.join("results");
        Self {
            fx,
            results,
            mode: Default::default(),
            alerts: Mutex::new(Vec::new()),
            log: Mutex::new(Vec::new()),
        }
    }

    /// A job that ended `outcome`, with an html report, a json report and
    /// (sensitive) a packet capture in its folder.
    fn ended(&self, outcome: Outcome, label: Option<Label>) -> Job {
        let job = self.fx.running(1);
        let dir = self.fx.store.job_dir(&job.id);
        fs::create_dir_all(dir.join("artifacts")).unwrap();
        for (kind, name, location, bytes) in [
            (
                ArtifactKind::ReportHtml,
                "report-01010101.html",
                "artifacts/report-01010101.html",
                &b"<html>r</html>"[..],
            ),
            (
                ArtifactKind::ReportJson,
                "report-01010101.json",
                "artifacts/report-01010101.json",
                b"{\"r\":1}",
            ),
            (
                ArtifactKind::NetworkPcap,
                "run.pcap",
                "artifacts/run.pcap",
                b"PCAP-SECRET",
            ),
        ] {
            fs::write(dir.join(location), bytes).unwrap();
            self.fx
                .store
                .add_artifact(
                    &job.id,
                    NewArtifact {
                        kind,
                        name: name.into(),
                        size: bytes.len() as u64,
                        sha256: Sha256Hex::try_from("ab".repeat(32)).unwrap(),
                        media_type: MediaType::ApplicationOctetStream,
                        raw_indicators: false,
                        location: location.into(),
                    },
                )
                .unwrap();
        }
        if let Some(label) = label {
            self.fx
                .store
                .set_assessment(
                    &job.id,
                    &Assessment {
                        assessment: AssessmentKind::SuspiciousBehaviour,
                        highest_tier: Tier::Medium,
                        label: Some(label),
                        score: None,
                        families: vec![],
                        counts: Counts::default(),
                        key_behaviours: vec![],
                        detections: vec![],
                        techniques: vec![],
                        ioc_dataset_count: 0,
                        basis: "because".into(),
                    },
                )
                .unwrap();
        }
        self.fx.store.finish(&job.id, outcome, None).unwrap()
    }

    fn deliver_with(
        &self,
        id: &JobId,
        results: bool,
        hook: &[&str],
        timeout: Duration,
    ) -> super::Delivered {
        let log = |line: &str| self.log.lock().unwrap().push(line.to_owned());
        let alert = |code: &str, _: &str| self.alerts.lock().unwrap().push(code.to_owned());
        Delivery {
            store: &self.fx.store,
            results_dir: results.then(|| self.results.clone()),
            results_mode: self.mode.get(),
            on_finish: hook.iter().map(|s| (*s).to_owned()).collect(),
            hook_timeout: timeout,
            now_ms: T + 1000,
            log: &log,
            alert: &alert,
        }
        .deliver(id)
        .unwrap()
    }

    fn deliver(&self, id: &JobId, results: bool, hook: &[&str]) -> super::Delivered {
        self.deliver_with(id, results, hook, Duration::from_secs(10))
    }

    fn alerts(&self) -> Vec<String> {
        self.alerts.lock().unwrap().clone()
    }

    fn job_log(&self, id: &JobId) -> String {
        fs::read_to_string(self.fx.store.job_dir(id).join("job.log")).unwrap_or_default()
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[test]
fn the_result_drop_has_job_json_and_the_reports_but_not_the_sensitive_files() {
    let rig = Rig::new("drop");
    let job = rig.ended(Outcome::Succeeded, Some(Label::Suspicious));
    let done = rig.deliver(&job.id, true, &[]);
    let folder = done.drop.unwrap().unwrap();
    let day = folder
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(day.len(), 10, "{day}");
    assert_eq!(
        folder.file_name().unwrap().to_string_lossy(),
        format!("01010101-{}", job.id)
    );
    assert_eq!(
        names(&folder),
        ["job.json", "report-01010101.html", "report-01010101.json"]
    );
    let copy: serde_json::Value =
        serde_json::from_slice(&fs::read(folder.join("job.json")).unwrap()).unwrap();
    assert_eq!(copy["id"], job.id.as_str());
    assert_eq!(copy["state"], "succeeded");
    assert_eq!(
        fs::read(folder.join("report-01010101.html")).unwrap(),
        b"<html>r</html>"
    );
    assert!(
        names(folder.parent().unwrap())
            .iter()
            .all(|n| !n.starts_with('.')),
        "no partial left"
    );
    assert_eq!(
        fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(folder.join("job.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn the_group_mode_makes_a_drop_readable_by_the_group_and_never_writable() {
    use crate::config::service::ResultsMode;
    let rig = Rig::new("group");
    rig.mode.set(ResultsMode::Group);
    let job = rig.ended(Outcome::Succeeded, Some(Label::Suspicious));
    let folder = rig.deliver(&job.id, true, &[]).drop.unwrap().unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&folder), 0o750);
    assert_eq!(mode(folder.parent().unwrap()), 0o750);
    assert_eq!(mode(&rig.results), 0o750);
    assert_eq!(mode(&folder.join("job.json")), 0o640);
    assert_eq!(mode(&folder.join("report-01010101.html")), 0o640);
    assert!(
        !names(&folder).iter().any(|n| n.contains("pcap")),
        "sensitive files stay out in every mode"
    );
}

#[test]
fn a_drop_is_made_once_and_the_hook_runs_once() {
    let rig = Rig::new("once");
    let job = rig.ended(Outcome::Succeeded, None);
    let out = rig.fx.dir.join("hook-ran");
    let script = rig.fx.dir.join("hook.sh");
    fs::write(
        &script,
        format!("#!/bin/sh\n/bin/echo x >> {}\n", out.display()),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let hook = script.to_str().unwrap();
    rig.deliver(&job.id, true, &[hook]);
    let again = rig.deliver(&job.id, true, &[hook]);
    assert!(again.drop.is_none() && again.hook.is_none(), "{again:?}");
    assert_eq!(fs::read_to_string(&out).unwrap(), "x\n");
    let marker: Marker = serde_json::from_slice(
        &fs::read(rig.fx.store.job_dir(&job.id).join("notified.json")).unwrap(),
    )
    .unwrap();
    assert!(marker.results && marker.hook);
}

#[test]
fn nothing_configured_means_nothing_done_and_no_marker() {
    let rig = Rig::new("nothing");
    let job = rig.ended(Outcome::Succeeded, None);
    let done = rig.deliver(&job.id, false, &[]);
    assert!(done.drop.is_none() && done.hook.is_none());
    assert!(!rig.fx.store.job_dir(&job.id).join("notified.json").exists());
    assert!(!rig.results.exists());
}

#[test]
fn an_artifact_that_is_a_link_out_of_the_job_folder_is_never_copied() {
    let rig = Rig::new("evil-artifact");
    let job = rig.ended(Outcome::Succeeded, None);
    let secret = rig.fx.dir.join("secret.txt");
    fs::write(&secret, b"TOP SECRET").unwrap();
    let dir = rig.fx.store.job_dir(&job.id);
    fs::remove_file(dir.join("artifacts/report-01010101.html")).unwrap();
    symlink(&secret, dir.join("artifacts/report-01010101.html")).unwrap();
    let done = rig.deliver(&job.id, true, &[]);
    assert!(done.drop.unwrap().is_err());
    assert_eq!(rig.alerts(), ["result_drop_failed"]);
    // Nothing of the secret anywhere under the results, no partial folder.
    let mut found = Vec::new();
    let mut stack = vec![rig.results.clone()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).into_iter().flatten().flatten() {
            if e.path().is_dir() {
                stack.push(e.path());
            } else {
                found.push(e.path());
            }
        }
    }
    assert!(found.is_empty(), "{found:?}");
    // The job is what it was.
    assert_eq!(
        rig.fx.store.get(&job.id).unwrap().state,
        crate::api::job::JobState::Succeeded
    );
}

#[test]
fn a_results_folder_that_is_a_link_is_refused() {
    let rig = Rig::new("link-results");
    let job = rig.ended(Outcome::Succeeded, None);
    let real = rig.fx.dir.join("real");
    fs::create_dir_all(&real).unwrap();
    symlink(&real, &rig.results).unwrap();
    let done = rig.deliver(&job.id, true, &[]);
    assert!(done.drop.unwrap().is_err());
    assert!(names(&real).is_empty());
}

#[test]
fn a_failed_drop_is_tried_again_and_the_hook_does_not_run_twice() {
    let rig = Rig::new("retry-drop");
    let job = rig.ended(Outcome::Succeeded, None);
    let real = rig.fx.dir.join("real");
    fs::create_dir_all(&real).unwrap();
    symlink(&real, &rig.results).unwrap();
    let first = rig.deliver(&job.id, true, &["/bin/true"]);
    assert!(first.drop.unwrap().is_err() && first.hook.is_some());
    fs::remove_file(&rig.results).unwrap();
    let second = rig.deliver(&job.id, true, &["/bin/true"]);
    assert!(second.drop.unwrap().is_ok());
    assert!(second.hook.is_none(), "the hook already ran");
}

#[test]
fn the_hook_gets_exactly_five_variables_and_nothing_else() {
    let rig = Rig::new("env");
    let job = rig.ended(Outcome::Succeeded, Some(Label::Malicious));
    let done = rig.deliver(&job.id, false, &["/usr/bin/env"]);
    let run = done.hook.unwrap();
    assert!(run.succeeded(), "{run:?}");
    let text = String::from_utf8(run.stdout).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort();
    let sha = "01".repeat(32);
    let result = rig.fx.store.job_dir(&job.id).join("job.json");
    assert_eq!(
        lines,
        [
            format!("ANTINOMIE_JOB_ID={}", job.id).as_str(),
            "ANTINOMIE_LABEL=malicious",
            &format!("ANTINOMIE_RESULT_JSON={}", result.display()),
            &format!("ANTINOMIE_SHA256={sha}"),
            "ANTINOMIE_STATE=succeeded",
        ]
    );
    assert!(result.is_file(), "the file the variable names is there");
}

#[test]
fn the_label_and_hash_are_empty_for_a_job_without_them() {
    let rig = Rig::new("env-empty");
    let queued = rig.fx.queued(1);
    let job = rig
        .fx
        .store
        .cancel(&queued.id, Some("test"), &crate::store::tests::manager())
        .unwrap();
    assert_eq!(job.state, crate::api::job::JobState::Cancelled);
    let run = rig.deliver(&job.id, false, &["/usr/bin/env"]).hook.unwrap();
    let text = String::from_utf8(run.stdout).unwrap();
    assert!(text.contains("ANTINOMIE_LABEL=\n"), "{text}");
    assert!(text.contains("ANTINOMIE_STATE=cancelled\n"));
    assert!(text.contains("ANTINOMIE_RESULT_JSON="));
    assert!(
        rig.fx.store.job_dir(&job.id).join("job.json").is_file(),
        "made for the hook"
    );
}

#[test]
fn the_hook_is_never_run_through_a_shell() {
    let rig = Rig::new("noshell");
    let job = rig.ended(Outcome::Succeeded, None);
    let sentinel = rig.fx.dir.join("SENTINEL");
    let evil = format!("$(touch {})", sentinel.display());
    let backtick = format!("`touch {}`", sentinel.display());
    let semi = format!("a; touch {}", sentinel.display());
    let run = rig
        .deliver(
            &job.id,
            false,
            &[
                "/usr/bin/printf",
                "%s|",
                &evil,
                &backtick,
                &semi,
                "x y",
                "*",
            ],
        )
        .hook
        .unwrap();
    assert!(run.succeeded(), "{run:?}");
    assert_eq!(
        String::from_utf8(run.stdout).unwrap(),
        format!("{evil}|{backtick}|{semi}|x y|*|")
    );
    assert!(!sentinel.exists(), "no shell expanded anything");
}

#[test]
fn nothing_the_job_controls_reaches_the_hooks_arguments_or_environment() {
    let rig = Rig::new("hostile");
    let hostile = "$(touch pwned); `id`\n\x1b[31mred".to_owned();
    let mut spec = crate::store::tests::spec(1);
    spec.name = Some(hostile.clone());
    spec.labels.insert("note".into(), hostile.clone());
    let submitted = rig.fx.submit(spec);
    let started = rig
        .fx
        .store
        .claim_next(&crate::store::tests::lane(), &mut |_| {
            crate::store::Eligibility::Ready
        })
        .unwrap()
        .unwrap();
    assert_eq!(started.id, submitted.job.id);
    let job = rig
        .fx
        .store
        .finish(&started.id, Outcome::Succeeded, None)
        .unwrap();
    let run = rig.deliver(&job.id, false, &["/usr/bin/env"]).hook.unwrap();
    let text = String::from_utf8(run.stdout).unwrap();
    assert!(
        !text.contains("touch") && !text.contains('\x1b') && !text.contains("red"),
        "{text}"
    );
    assert_eq!(text.lines().count(), 5);
    assert!(!Path::new("/pwned").exists());
}

#[test]
fn the_hook_runs_as_the_daemons_user_with_no_input() {
    let rig = Rig::new("user");
    let job = rig.ended(Outcome::Succeeded, None);
    let run = rig
        .deliver(&job.id, false, &["/usr/bin/id", "-u"])
        .hook
        .unwrap();
    assert_eq!(
        String::from_utf8(run.stdout).unwrap().trim(),
        rustix::process::geteuid().as_raw().to_string()
    );
    let job2 = rig.ended(Outcome::Succeeded, None);
    let started = Instant::now();
    let run = rig
        .deliver(&job2.id, false, &["/usr/bin/cat"])
        .hook
        .unwrap();
    assert!(
        run.succeeded() && run.stdout.is_empty(),
        "stdin is /dev/null"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_hook_past_its_time_is_killed_with_what_it_started() {
    let rig = Rig::new("timeout");
    let job = rig.ended(Outcome::Succeeded, None);
    let pidfile = rig.fx.dir.join("child.pid");
    let script = rig.fx.dir.join("slow.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n/bin/sleep 120 &\n/bin/echo $! > {}\nwait\n",
            pidfile.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    let run = rig
        .deliver_with(
            &job.id,
            false,
            &[script.to_str().unwrap()],
            Duration::from_millis(1500),
        )
        .hook
        .unwrap();
    assert!(run.timed_out && !run.succeeded(), "{run:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(rig.alerts(), ["hook_failed"]);
    assert_eq!(
        rig.fx.store.get(&job.id).unwrap().state,
        crate::api::job::JobState::Succeeded,
        "a hook never fails a job"
    );
    // The sleep it started is gone too.
    let pid: i32 = fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists()
            || fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.contains(" Z ")),
        "the child of the hook is still running"
    );
}

#[test]
fn the_hooks_output_is_bounded_and_goes_to_job_log_without_control_characters() {
    let rig = Rig::new("output");
    let job = rig.ended(Outcome::Succeeded, None);
    let big = rig.deliver(
        &job.id,
        false,
        &["/usr/bin/head", "-c", "1000000", "/dev/zero"],
    );
    let run = big.hook.unwrap();
    assert!(run.succeeded());
    assert_eq!(run.stdout.len(), OUTPUT_LIMIT);
    let job2 = rig.ended(Outcome::Succeeded, None);
    let script = rig.fx.dir.join("talk.sh");
    fs::write(
        &script,
        "#!/bin/sh\n/usr/bin/printf 'hello\\033[31m red\\n'\n/usr/bin/printf 'oops\\n' >&2\nexit 3\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let run = rig
        .deliver(&job2.id, false, &[script.to_str().unwrap()])
        .hook
        .unwrap();
    assert_eq!(run.exit, Some(3));
    let log = rig.job_log(&job2.id);
    assert!(log.contains("hook on_finish: exited with code 3"), "{log}");
    assert!(log.contains("hook stdout: hello?[31m red"), "{log}");
    assert!(log.contains("hook stderr: oops"), "{log}");
    assert!(!log.contains('\x1b'));
    assert_eq!(rig.alerts(), ["hook_failed"]);
    let marker: Marker = serde_json::from_slice(
        &fs::read(rig.fx.store.job_dir(&job2.id).join("notified.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(marker.hook_exit, Some(3));
}

#[test]
fn a_hook_that_cannot_start_is_a_logged_alert_not_a_failure() {
    let rig = Rig::new("nostart");
    let job = rig.ended(Outcome::Succeeded, None);
    let run = rig
        .deliver(&job.id, true, &["/nonexistent/hook"])
        .hook
        .unwrap();
    assert!(run.error.is_some() && !run.succeeded());
    assert_eq!(rig.alerts(), ["hook_failed"]);
    assert!(
        rig.log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("could not be started"))
    );
    assert_eq!(
        rig.fx.store.get(&job.id).unwrap().state,
        crate::api::job::JobState::Succeeded
    );
}

#[test]
fn after_a_restart_the_last_day_is_delivered_and_older_jobs_are_not() {
    let rig = Rig::new("sweep");
    rig.fx.clock.set(T);
    let recent = rig.ended(Outcome::Succeeded, None);
    rig.fx.clock.set(T - 3 * SWEEP_MS);
    let old = rig.ended(Outcome::Succeeded, None);
    let log = |_: &str| {};
    let alert = |_: &str, _: &str| {};
    Delivery {
        store: &rig.fx.store,
        results_dir: Some(rig.results.clone()),
        results_mode: Default::default(),
        on_finish: vec![],
        hook_timeout: Duration::from_secs(5),
        now_ms: T + 1000,
        log: &log,
        alert: &alert,
    }
    .sweep();
    let delivered = |id: &JobId| rig.fx.store.job_dir(id).join("notified.json").exists();
    assert!(delivered(&recent.id));
    assert!(!delivered(&old.id));
}

#[test]
fn hook_run_without_a_command_is_an_error_not_a_panic() {
    let run = hook::run(&[], &[], Duration::from_secs(1));
    assert!(run.error.is_some());
}
