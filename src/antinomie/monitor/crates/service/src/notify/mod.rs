// SPDX-License-Identifier: GPL-3.0-only
//! Result files and the command hook (design 4.9.3, 4.10; card P4-4): what
//! the service does when a job ends, apart from the event stream.
//!
//! | Channel | Config | What happens |
//! |---|---|---|
//! | Result drop | `[results] dir` | `<dir>/<yyyy-mm-dd>/<sha8>-<runid>/` with `job.json` and the reports ([`results`]) |
//! | Command hook | `[notify] on_finish = ["/abs/path", "arg", ...]` | the argv is run directly, with a cleared environment holding the five `ANTINOMIE_*` variables, a 30 s limit, the output in `job.log` ([`hook`]) |
//!
//! Neither can fail a job: a job that ended has ended. A failure is a line
//! in the log and an `engine.alert` (`result_drop_failed`, `hook_failed`).
//! Delivery is at least once: `notified.json` in the job's folder records
//! what was delivered; a drop that failed, or a delivery cut short by a
//! crash, is made again at the next start for jobs that ended in the last 24
//! hours. Delivery runs on its own thread, one job after another, so a slow
//! hook never holds the lane.

pub mod calendar;
pub mod hook;
pub mod results;
#[cfg(test)]
mod tests;

use crate::{
    api::{
        ids::RunId,
        run::{Run, RunState},
    },
    store::{Store, mirror::write_private},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf, time::Duration,
};

/// Jobs that ended this long ago are still delivered after a restart.
pub const SWEEP_MS: u64 = 24 * 60 * 60 * 1000;
/// `job.log` stops growing past this.
pub const JOB_LOG_LIMIT: u64 = 5 << 20;
const MARKER: &str = "notified.json";

/// What has been delivered for a job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    #[serde(default)]
    pub results: bool,
    #[serde(default)]
    pub hook: bool,
    #[serde(default)]
    pub hook_exit: Option<i32>,
}

/// What a delivery did, for the log and the tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Delivered {
    pub drop: Option<Result<PathBuf, String>>,
    pub hook: Option<hook::HookRun>,
}

/// The delivery settings and the places to write.
pub struct Delivery<'a> {
    pub store: &'a Store,
    /// `[results] dir`.
    pub results_dir: Option<PathBuf>,
    /// `[results] mode`.
    pub results_mode: crate::config::service::ResultsMode,
    /// `[notify] on_finish`.
    pub on_finish: Vec<String>,
    pub hook_timeout: Duration,
    pub now_ms: u64,
    pub log: &'a dyn Fn(&str),
    /// Raised for a failed drop or hook.
    pub alert: &'a dyn Fn(&str, &str),
}

fn read_marker(store: &Store, id: &RunId) -> Marker {
    std::fs::read(store.job_dir(id).join(MARKER))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_marker(store: &Store, id: &RunId, marker: &Marker) {
    if let Ok(bytes) = serde_json::to_vec(marker) {
        let _ = write_private(&store.job_dir(id).join(MARKER), &bytes);
    }
}

/// Text for a log or `job.log`: control characters other than newline and
/// tab become `?`; a lone ESC cannot start an escape sequence.
pub fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| {
            if c == '\n' || c == '\t' || !c.is_control() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

impl Delivery<'_> {
    pub fn configured(&self) -> bool {
        self.results_dir.is_some() || !self.on_finish.is_empty()
    }

    /// Deliver what is configured and not yet delivered for the ended job
    /// `id`. `Err` only when the job cannot be read or has not ended.
    pub fn deliver(&self, id: &RunId) -> Result<Delivered, String> {
        let mut done = Delivered::default();
        if !self.configured() {
            return Ok(done);
        }
        let job = self.store.get(id).map_err(|e| e.message)?;
        if !job.state.is_terminal() {
            return Err(format!("job {id} has not ended"));
        }
        let mut marker = read_marker(self.store, id);
        // The hook reads this file: make sure it is there (a job that was
        // rejected or cancelled while queued never passed `cleanup`).
        let job_json = self.store.job_dir(id).join("job.json");
        if !job_json.is_file()
            && let Ok(bytes) = serde_json::to_vec_pretty(&job)
        {
            // Under a name of its own: `cleanup` writes the same file at the
            // same moment, with the same content.
            let temp = self.store.job_dir(id).join("job.json.notify");
            let _ = std::fs::create_dir_all(self.store.job_dir(id));
            let _ = write_private(&temp, &bytes).and_then(|()| std::fs::rename(&temp, &job_json));
        }
        if let Some(root) = &self.results_dir
            && !marker.results
        {
            let outcome = results::write(self.store, &job, root, self.results_mode, self.now_ms);
            match &outcome {
                Ok(path) => {
                    marker.results = true;
                    (self.log)(&format!(
                        "notify: job={id} result files in {}",
                        path.display()
                    ));
                }
                Err(error) => {
                    (self.log)(&format!(
                        "notify: job={id} result files not written: {error}"
                    ));
                    (self.alert)(
                        "result_drop_failed",
                        &format!("the result files of job {id} could not be written"),
                    );
                }
            }
            done.drop = Some(outcome);
        }
        if !self.on_finish.is_empty() && !marker.hook {
            let run = self.run_hook(&job, &job_json);
            marker.hook = true;
            marker.hook_exit = run.exit;
            done.hook = Some(run);
        }
        write_marker(self.store, id, &marker);
        Ok(done)
    }

    fn run_hook(&self, job: &Run, job_json: &std::path::Path) -> hook::HookRun {
        let label = job
            .assessment
            .as_ref()
            .and_then(|a| serde_json::to_value(a.label).ok())
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let state = serde_json::to_value(job.state)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        debug_assert!(job.state != RunState::Queued);
        let env = [
            ("ANTINOMIE_RUN_ID", job.id.to_string()),
            ("ANTINOMIE_STATE", state),
            ("ANTINOMIE_LABEL", label),
            (
                "ANTINOMIE_SHA256",
                job.sample
                    .as_ref()
                    .map(|s| s.sha256.to_string())
                    .unwrap_or_default(),
            ),
            ("ANTINOMIE_RESULT_JSON", job_json.display().to_string()),
        ];
        let run = hook::run(&self.on_finish, &env, self.hook_timeout);
        (self.log)(&format!(
            "notify: job={} on_finish hook {}",
            job.id,
            run.words()
        ));
        self.append_job_log(&job.id, &run);
        if !run.succeeded() {
            (self.alert)(
                "hook_failed",
                &format!("the on_finish hook for job {} {}", job.id, run.words()),
            );
        }
        run
    }

    /// The hook's output goes to the job's `job.log`, bounded.
    fn append_job_log(&self, id: &RunId, run: &hook::HookRun) {
        let path = self.store.job_dir(id).join("job.log");
        if std::fs::metadata(&path).is_ok_and(|m| m.len() >= JOB_LOG_LIMIT) {
            return;
        }
        let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
        else {
            return;
        };
        let mut text = format!("hook on_finish: {}\n", run.words());
        for (name, bytes) in [("stdout", &run.stdout), ("stderr", &run.stderr)] {
            if !bytes.is_empty() {
                for line in printable(bytes).lines() {
                    text.push_str(&format!("hook {name}: {line}\n"));
                }
            }
        }
        let _ = file.write_all(text.as_bytes());
    }

    /// Deliver for every job that ended in the last 24 hours and is not
    /// delivered yet (the start-up sweep).
    pub fn sweep(&self) {
        if !self.configured() {
            return;
        }
        let since = self.now_ms.saturating_sub(SWEEP_MS);
        let Ok(finished) = self.store.finished_jobs() else {
            return;
        };
        for (id, finished_ms) in finished {
            if finished_ms >= since {
                let _ = self.deliver(&id);
            }
        }
    }
}
