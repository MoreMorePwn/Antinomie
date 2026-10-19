use crate::{
    api::*,
    parser::Assembler,
    storage::{self, RawCapture},
};
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
};

/// General notes kept per run, plus one reserved async-loss note; maximum note length.
const MAX_NOTES: usize = 16;
const NOTE_LEN: usize = 512;

pub(crate) struct ProgramRun {
    pub summary: RunSummary,
    pub capture: RawCapture,
    pub assembler: Assembler,
    journal: File,
    transcript: File,
    terminal: vt100::Parser,
    terminal_len: u64,
    screen_len: u64,
    analysis_metadata_len: u64,
    pub sequence: u64,
    pub boot_bundle_identity: Option<String>,
    pub disk_base_identity: Option<String>,
    pub execution_generation: u64,
    /// Terminal READ requests that never received a reply before finalize.
    pub terminal_reads_unanswered: u64,
    /// The final screen prepared by [`Self::begin_finalize`], published by
    /// [`Self::complete_finalize`].
    pending_screen: Option<Result<Vec<u8>, String>>,
    started_ms: u64,
    ended_ms: Option<u64>,
}

impl ProgramRun {
    pub fn new(mut summary: RunSummary, quota: u64) -> Result<Self, String> {
        let started_ms = *summary.started_ms.get_or_insert_with(unix_ms);
        let capture = RawCapture::new(summary.directory.clone(), quota)?;
        let assembler =
            Assembler::new(summary.directory.join("objects"), quota).map_err(|e| e.to_string())?;
        let open = |name: &str| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(summary.directory.join(name))
                .map_err(|e| e.to_string())
        };
        let journal = open("terminal.journal")?;
        let transcript = open("terminal-transcript.raw")?;
        let mut run = Self {
            summary,
            capture,
            assembler,
            journal,
            transcript,
            terminal: vt100::Parser::new(24, 80, 0),
            terminal_len: 0,
            screen_len: 0,
            analysis_metadata_len: 0,
            sequence: 0,
            boot_bundle_identity: None,
            disk_base_identity: None,
            execution_generation: 0,
            terminal_reads_unanswered: 0,
            pending_screen: None,
            started_ms,
            ended_ms: None,
        };
        run.refresh_analysis_metadata()?;
        run.persist_summary()?;
        Ok(run)
    }
    pub fn stored_len(&self) -> u64 {
        self.capture
            .bytes
            .saturating_add(self.assembler.stored_len())
            .saturating_add(self.terminal_len)
            .saturating_add(self.screen_len)
            .saturating_add(self.analysis_metadata_len)
    }
    pub(crate) fn observe_clock(&mut self, guest_ns: u64) {
        self.summary
            .clock_anchor
            .get_or_insert_with(|| HostClockAnchor {
                guest_ns,
                host_us: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |duration| {
                        u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
                    }),
            });
    }
    /// Count only the new report's contribution to the two existing metadata files.
    pub fn refresh_analysis_metadata(&mut self) -> Result<(), String> {
        if self.summary.analysis.is_none() {
            self.analysis_metadata_len = 0;
            return Ok(());
        }
        let mut run = serde_json::to_value(&self.summary).map_err(|e| e.to_string())?;
        let mut manifest = serde_json::json!({"run":run.clone()});
        let reported_len = serde_json::to_vec_pretty(&run)
            .map_err(|e| e.to_string())?
            .len()
            + serde_json::to_vec_pretty(&manifest)
                .map_err(|e| e.to_string())?
                .len();
        run["analysis"] = serde_json::Value::Null;
        manifest["run"]["analysis"] = serde_json::Value::Null;
        let baseline_len = serde_json::to_vec_pretty(&run)
            .map_err(|e| e.to_string())?
            .len()
            + serde_json::to_vec_pretty(&manifest)
                .map_err(|e| e.to_string())?
                .len();
        self.analysis_metadata_len = reported_len.saturating_sub(baseline_len) as u64;
        Ok(())
    }
    /// Saves the summary and manifest on the background writer, so a slow
    /// `fsync` cannot stall telemetry draining while the VM runs. `finalize`
    /// writes the final versions synchronously, after any queued ones.
    pub fn persist_summary(&self) -> Result<(), String> {
        let run = storage::queue_json(&self.summary.directory.join("run.json"), &self.summary);
        let manifest = storage::queue_json(
            &self.summary.directory.join("manifest.json"),
            &self.manifest(),
        );
        run.and(manifest)
    }
    fn manifest(&self) -> serde_json::Value {
        serde_json::json!({"format":"ANTT run raw LE32","run":self.summary,"packets":self.capture.packets,"bytes":self.stored_len(),"persistence_error":self.summary.recording_error,"boot_bundle_identity":self.boot_bundle_identity,"disk_base_identity":self.disk_base_identity,"started_ms":self.started_ms,"ended_ms":self.ended_ms})
    }
    pub(crate) fn record_tree_completion(&mut self) {
        if self.summary.state == RunState::Finished {
            self.ended_ms.get_or_insert_with(unix_ms);
        }
    }
    pub(crate) fn record_async_loss(&mut self) {
        if let Some(status) = self
            .summary
            .execution
            .as_ref()
            .filter(|status| status.has_async_loss())
        {
            let note = format!(
                "{ASYNC_LOSS_NOTE_PREFIX}: last guest count {}, loss flag {}. Saving may continue, but observation completeness is not proven.",
                status.async_loss_count,
                status.flags & 16 != 0
            );
            if let Some(saved) = self
                .summary
                .notes
                .iter_mut()
                .find(|note| note.starts_with(ASYNC_LOSS_NOTE_PREFIX))
            {
                *saved = note;
            } else if self.summary.notes.len() <= MAX_NOTES {
                // A full general-note budget must not erase a known loss when
                // a later status query is unavailable. This one reserved note
                // is bounded by its fixed text and numeric status fields.
                self.summary.notes.push(note);
            }
        }
    }
    /// Complete only after EOF with every terminal READ reply received.
    pub fn terminal_complete(&self) -> bool {
        self.summary.terminal_eof && self.terminal_reads_unanswered == 0
    }
    pub fn terminal_issue(&self) -> Option<String> {
        if self.terminal_reads_unanswered > 0 {
            Some(format!(
                "{} terminal read replies never arrived; consumed output may be missing",
                self.terminal_reads_unanswered
            ))
        } else if !self.summary.terminal_eof {
            Some("VM ended before terminal EOF; terminal tail may be missing".into())
        } else {
            None
        }
    }
    pub fn storage_error(&mut self, error: impl Into<String>) {
        self.summary.recording_error.get_or_insert(error.into());
        self.assembler.stop_saving();
    }
    /// Record a fact about this run's recording that does not stop saving.
    /// At most [`MAX_NOTES`] distinct notes are kept.
    pub fn add_note(&mut self, note: impl Into<String>) {
        let note: String = note.into().chars().take(NOTE_LEN).collect();
        if self.summary.notes.len() < MAX_NOTES && !self.summary.notes.contains(&note) {
            self.summary.notes.push(note);
        }
    }
    /// The program tree has ended and its terminal is closed: no more telemetry
    /// or output is expected, so the run's archive is complete as it stands.
    pub fn recording_complete(&self) -> bool {
        self.summary.terminal_eof
            && matches!(
                self.summary.state,
                RunState::Finished | RunState::Stopped | RunState::Finalized
            )
    }
    fn journal(&mut self, kind: u8, data: &[u8], available: u64) -> Result<(), String> {
        if let Some(cause) = &self.summary.recording_error {
            return Err(format!("run saving already stopped: {cause}"));
        }
        let required = 5 + data.len() as u64 + if kind == 1 { data.len() as u64 } else { 0 };
        if required > available {
            self.storage_error("capture quota exhausted; terminal saving stopped");
            return Err("capture quota exhausted; terminal saving stopped".into());
        }
        let prior = self.terminal_len;
        let journal_prior = self.journal.stream_position().map_err(|e| e.to_string())?;
        let transcript_prior = self
            .transcript
            .stream_position()
            .map_err(|e| e.to_string())?;
        let result = self
            .journal
            .write_all(&[kind])
            .and_then(|_| self.journal.write_all(&(data.len() as u32).to_le_bytes()))
            .and_then(|_| self.journal.write_all(data))
            .and_then(|_| {
                if kind == 1 {
                    self.transcript.write_all(data)
                } else {
                    Ok(())
                }
            });
        match result {
            Ok(()) => {
                self.terminal_len = prior + required;
                Ok(())
            }
            Err(e) => {
                let journal_rollback = self.journal.set_len(journal_prior).and_then(|_| {
                    self.journal
                        .seek(SeekFrom::Start(journal_prior))
                        .map(|_| ())
                });
                let transcript_rollback =
                    self.transcript.set_len(transcript_prior).and_then(|_| {
                        self.transcript
                            .seek(SeekFrom::Start(transcript_prior))
                            .map(|_| ())
                    });
                let message = format!(
                    "terminal persistence failed: {e}; journal rollback {:?}; transcript rollback {:?}",
                    journal_rollback.err(),
                    transcript_rollback.err()
                );
                self.storage_error(message.clone());
                Err(message)
            }
        }
    }
    pub fn output(&mut self, data: &[u8], available: u64) -> Result<(), String> {
        self.sequence = self.sequence.saturating_add(1);
        self.terminal.process(data);
        self.journal(1, data, available)
    }
    pub fn resize(&mut self, rows: u16, cols: u16, available: u64) -> Result<(), String> {
        self.terminal.screen_mut().set_size(rows, cols);
        self.sequence = self.sequence.saturating_add(1);
        self.journal(
            2,
            &[rows.to_le_bytes(), cols.to_le_bytes()].concat(),
            available,
        )
    }
    pub fn screen_notification(&self) -> Notification {
        let (rows, cols) = self.terminal.screen().size();
        Notification::TerminalScreen {
            run_id: self.summary.id.clone(),
            sequence: self.sequence,
            rows,
            cols,
            data: self.terminal.screen().state_formatted(),
        }
    }
    pub fn eof(&mut self, available: u64) -> Result<(), String> {
        if self.summary.terminal_eof {
            return Ok(());
        }
        self.summary.terminal_eof = true;
        if self.summary.execution.is_none() && self.summary.state != RunState::StopRequested {
            self.summary.state = RunState::TerminalClosed;
        }
        // The summary records the closed terminal even when the journal refuses
        // its end mark, so a run whose saving stopped is not left looking open.
        let journal = self.journal(3, &[], available);
        let persisted = self.persist_summary();
        journal.and(persisted)
    }
    /// Saves the terminal screen on the background writer.
    pub fn save_screen(&mut self, available: u64) -> Result<(), String> {
        let screen = self.screen_bytes(available)?;
        self.screen_len = screen.len() as u64;
        storage::queue_bytes(&self.summary.directory.join("terminal-screen.ansi"), screen)
    }
    fn screen_bytes(&mut self, available: u64) -> Result<Vec<u8>, String> {
        if let Some(cause) = &self.summary.recording_error {
            return Err(format!(
                "run saving stopped ({cause}); final screen unavailable"
            ));
        }
        let screen = self.terminal.screen().state_formatted();
        if screen.len() as u64 > available + self.screen_len {
            self.storage_error("capture quota exhausted; terminal screen not saved");
            return Err("capture quota exhausted; terminal screen not saved".into());
        }
        Ok(screen)
    }
    /// First half of finalization, for the transport thread: the run's final
    /// state and times, and its final screen, with no wait for the disk.
    pub fn begin_finalize(&mut self, available: u64) {
        self.ended_ms.get_or_insert_with(unix_ms);
        if !matches!(self.summary.state, RunState::Finished | RunState::Stopped) {
            self.summary.state = RunState::Finalized;
        }
        let screen = self.screen_bytes(available);
        if let Ok(screen) = &screen {
            self.screen_len = screen.len() as u64;
        }
        self.pending_screen = Some(screen);
    }
    /// Second half, with the disk waits: the run's data is written and synced
    /// (raw packets, objects, screen, terminal journal and transcript) before
    /// `run.json` and `manifest.json` say it is final. Runs on a flush thread.
    pub fn complete_finalize(&mut self, state: &str, health: &Health) -> Result<(), String> {
        let screen = self
            .pending_screen
            .take()
            .unwrap_or_else(|| Err("final screen was not prepared".into()));
        let results = [
            self.capture.sync(),
            screen.and_then(|screen| {
                storage::atomic_bytes(
                    &self.summary.directory.join("terminal-screen.ansi"),
                    &screen,
                )
            }),
            self.journal.sync_all().map_err(|e| e.to_string()),
            self.transcript.sync_all().map_err(|e| e.to_string()),
            self.assembler.sync(),
        ];
        let result = results
            .into_iter()
            .find_map(Result::err)
            .map_or(Ok(()), Err);
        if let Err(error) = &result {
            self.storage_error(error.clone());
        }
        self.capture.final_health = Some(health.clone());
        storage::atomic_json(&self.summary.directory.join("run.json"), &self.summary)?;
        let (rows, cols) = self.terminal.screen().size();
        storage::atomic_json(
            &self.summary.directory.join("manifest.json"),
            &serde_json::json!({"format":"ANTT run raw LE32","run":self.summary,"packets":self.capture.packets,"bytes":self.stored_len(),"persistence_error":self.summary.recording_error,"final_state":state,"health":health,"terminal_rows":rows,"terminal_cols":cols,"terminal_complete":self.terminal_complete(),"terminal_issue":self.terminal_issue(),"quota_scope":"VM boot shared raw, fields, transcript, journal and screen","boot_bundle_identity":self.boot_bundle_identity,"disk_base_identity":self.disk_base_identity,"started_ms":self.started_ms,"ended_ms":self.ended_ms}),
        )?;
        result
    }
    #[cfg(test)]
    pub fn finalize(&mut self, available: u64, state: &str, health: &Health) -> Result<(), String> {
        self.begin_finalize(available);
        self.complete_finalize(state, health)
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_analysis_metadata_counts_both_persisted_copies() {
        let _disk = storage::slow_disk::SlowDisk::install();
        let directory =
            std::env::temp_dir().join(format!("ant-analysis-metadata-{}", storage::unique_id()));
        let summary = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "run".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 2,
            pid: 3,
            request: ExecRequest::default(),
            directory: directory.clone(),
            terminal_eof: false,
            state: RunState::Running,
            notes: Vec::new(),
            recording_error: None,
            execution: None,
            analysis: None,
        };
        let mut run = ProgramRun::new(summary, 1024 * 1024).unwrap();
        assert_eq!(run.stored_len(), 0);
        let mut report = crate::analysis::jobs::new_report(
            "/tmp/sample",
            &crate::analysis::AnalysisSelection::default(),
        );
        crate::analysis::jobs::fail(
            &mut report,
            crate::analysis::AnalysisState::Unavailable,
            "fixture has no acquisition",
        );
        run.summary.analysis = Some(report);
        run.refresh_analysis_metadata().unwrap();
        run.persist_summary().unwrap();
        storage::flush_json().unwrap();
        let mut increment = 0;
        for (filename, nested) in [("run.json", false), ("manifest.json", true)] {
            let mut encoded: serde_json::Value =
                serde_json::from_reader(File::open(directory.join(filename)).unwrap()).unwrap();
            let present = serde_json::to_vec_pretty(&encoded).unwrap().len();
            if nested {
                encoded["run"]["analysis"] = serde_json::Value::Null;
            } else {
                encoded["analysis"] = serde_json::Value::Null;
            }
            increment += present - serde_json::to_vec_pretty(&encoded).unwrap().len();
        }
        assert_eq!(run.stored_len(), increment as u64);
        assert!(increment > 0);
        drop(run);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn eof_and_execution_completion_do_not_stop_recording_or_erase_root_exit() {
        let directory =
            std::env::temp_dir().join(format!("ant-run-state-{}", storage::unique_id()));
        let execution = RunExecution {
            generation: 1,
            live_task_count: 1,
            pending_async_count: 0,
            flags: 1,
            root_wait_status: Some(7 << 8),
            root_exit: Some(WaitStatus::Exited { code: 7 }),
            async_loss_count: 0,
            total_task_count: 2,
        };
        let summary = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "run".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 2,
            pid: 3,
            request: ExecRequest::default(),
            directory: directory.clone(),
            terminal_eof: false,
            state: RunState::Running,
            notes: Vec::new(),
            recording_error: None,
            execution: Some(execution),
            analysis: None,
        };
        let mut run = ProgramRun::new(summary, 65536).unwrap();
        run.eof(65536).unwrap();
        assert_eq!(run.summary.state, RunState::Running);
        run.record_tree_completion();
        assert!(
            run.ended_ms.is_none(),
            "root exit and terminal EOF do not end a surviving tree"
        );
        let execution = run.summary.execution.as_mut().unwrap();
        execution.live_task_count = 0;
        execution.flags = 11;
        run.summary.state = RunState::Finished;
        run.record_tree_completion();
        let first_end = run.ended_ms;
        assert!(first_end.is_some());
        run.record_tree_completion();
        assert_eq!(run.ended_ms, first_end);
        assert!(
            run.capture
                .append(b"late telemetry after process completion")
        );
        assert!(run.output(b"late terminal tail", 65536).is_ok());
        run.finalize(65536, "vm-stop", &Health::default()).unwrap();
        assert_eq!(run.summary.state, RunState::Finished);
        let facts = crate::recording::run_filter_facts(&directory, "run", "vm", "boot").unwrap();
        assert_eq!(facts.ended_ms, first_end);
        assert!(facts.started_ms.unwrap() <= facts.ended_ms.unwrap());
        assert_eq!(facts.transport_loss, Some(0));
        assert!(
            crate::recording::run_filter_facts(&directory, "different", "vm", "boot")
                .unwrap_err()
                .contains("identity mismatch")
        );
        assert_eq!(
            run.summary.execution.as_ref().unwrap().root_exit,
            Some(WaitStatus::Exited { code: 7 })
        );
        drop(run);
        crate::storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn unanswered_terminal_reads_make_the_terminal_incomplete_even_after_eof() {
        let directory =
            std::env::temp_dir().join(format!("ant-terminal-reads-{}", storage::unique_id()));
        let summary = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "run".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 2,
            pid: 3,
            request: ExecRequest::default(),
            directory: directory.clone(),
            terminal_eof: false,
            state: RunState::Running,
            notes: Vec::new(),
            recording_error: None,
            execution: None,
            analysis: None,
        };
        let mut run = ProgramRun::new(summary, 65536).unwrap();
        run.eof(65536).unwrap();
        assert!(run.terminal_complete());
        assert_eq!(run.terminal_issue(), None);
        run.terminal_reads_unanswered = 2;
        run.finalize(65536, "vm-stop", &Health::default()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["terminal_complete"], false);
        assert_eq!(
            manifest["terminal_issue"],
            "2 terminal read replies never arrived; consumed output may be missing"
        );
        drop(run);
        crate::storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn headless_terminal_reopens_journal_screen_and_quota_failure_preserves_prefix() {
        let directory = std::env::temp_dir().join(format!("ant-terminal-{}", storage::unique_id()));
        let summary = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "run".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 2,
            pid: 3,
            request: ExecRequest::default(),
            directory: directory.clone(),
            terminal_eof: false,
            state: RunState::Running,
            notes: Vec::new(),
            recording_error: None,
            execution: None,
            analysis: None,
        };
        let mut run = ProgramRun::new(summary, 65536).unwrap();
        run.resize(4, 20, 65536).unwrap();
        run.output(b"hello\r\n\x1b[?1h", 65536).unwrap();
        run.eof(65536).unwrap();
        run.finalize(65536, "clean", &Health::default()).unwrap();
        let recording = crate::recording::open_recording(&directory).unwrap();
        let page = recording.terminal_replay(0, 3).unwrap();
        assert_eq!(page.records.len(), 3);
        assert!(page.next_offset.is_none());
        let mut parser = vt100::Parser::new(4, 20, 0);
        parser.process(&recording.terminal_screen().unwrap());
        assert!(parser.screen().contents().contains("hello"));
        assert!(parser.screen().application_cursor());
        let journal_len = std::fs::metadata(directory.join("terminal.journal"))
            .unwrap()
            .len();
        assert!(run.output(b"not retained", 0).is_err());
        assert_eq!(
            std::fs::metadata(directory.join("terminal.journal"))
                .unwrap()
                .len(),
            journal_len
        );
        assert_eq!(recording.terminal_replay(0, 3).unwrap().records.len(), 3);
        run.summary.recording_error = None;
        run.transcript = OpenOptions::new().write(true).open("/dev/full").unwrap();
        assert!(
            run.output(b"partial append must roll back", 65536)
                .unwrap_err()
                .contains("rollback")
        );
        assert_eq!(
            std::fs::metadata(directory.join("terminal.journal"))
                .unwrap()
                .len(),
            journal_len
        );
        assert_eq!(recording.terminal_replay(0, 3).unwrap().records.len(), 3);
        crate::storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
    fn open_run(name: &str) -> (ProgramRun, std::path::PathBuf) {
        let directory = std::env::temp_dir().join(format!("{name}-{}", storage::unique_id()));
        let summary = RunSummary {
            started_ms: None,
            clock_anchor: None,
            id: "run".into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 2,
            pid: 3,
            request: ExecRequest::default(),
            directory: directory.clone(),
            terminal_eof: false,
            state: RunState::Running,
            notes: Vec::new(),
            recording_error: None,
            execution: None,
            analysis: None,
        };
        (ProgramRun::new(summary, 65536).unwrap(), directory)
    }
    #[test]
    fn notes_are_information_and_never_stop_terminal_saving() {
        let (mut run, directory) = open_run("ant-run-notes");
        run.add_note("3 telemetry packets could not be assigned to this run");
        run.add_note("3 telemetry packets could not be assigned to this run");
        for n in 0..40 {
            run.add_note(format!("note {n}"));
        }
        assert_eq!(run.summary.notes.len(), MAX_NOTES);
        assert!(run.summary.recording_error.is_none());
        run.output(b"journal still works", 65536).unwrap();
        run.eof(65536).unwrap();
        run.finalize(65536, "clean", &Health::default()).unwrap();
        let journal = std::fs::metadata(directory.join("terminal.journal")).unwrap();
        assert!(journal.len() > 0);
        let saved: RunSummary =
            serde_json::from_reader(File::open(directory.join("run.json")).unwrap()).unwrap();
        assert_eq!(saved.notes.len(), MAX_NOTES);
        assert!(saved.recording_error.is_none());
        drop(run);
        crate::storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn async_loss_note_is_updated_once_persists_and_does_not_stop_saving() {
        let (mut run, directory) = open_run("ant-run-async-note");
        run.summary.execution = Some(RunExecution {
            generation: 1,
            live_task_count: 0,
            pending_async_count: 0,
            flags: 19,
            root_wait_status: Some(0),
            root_exit: Some(WaitStatus::Exited { code: 0 }),
            async_loss_count: 1,
            total_task_count: 1,
        });
        run.record_async_loss();
        run.summary.execution.as_mut().unwrap().async_loss_count = 9;
        run.record_async_loss();
        assert_eq!(run.summary.notes.len(), 1);
        assert!(run.summary.notes[0].contains("last guest count 9"));
        run.summary.notes.clear();
        for n in 0..MAX_NOTES {
            run.add_note(format!("general note {n}"));
        }
        run.record_async_loss();
        assert_eq!(run.summary.notes.len(), MAX_NOTES + 1);
        assert!(
            run.summary
                .notes
                .last()
                .unwrap()
                .contains("last guest count 9")
        );
        run.summary.execution = None;
        assert!(run.summary.has_async_loss());
        run.output(b"saving continues", 65536).unwrap();
        assert!(run.summary.recording_error.is_none());
        run.persist_summary().unwrap();
        storage::flush_json().unwrap();
        let saved: RunSummary =
            serde_json::from_reader(File::open(directory.join("run.json")).unwrap()).unwrap();
        assert!(saved.has_async_loss());
        assert_eq!(saved.notes, run.summary.notes);
        drop(run);
        storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn summaries_saved_before_notes_existed_still_load_and_omit_empty_notes() {
        let (run, directory) = open_run("ant-run-compat");
        let mut value = serde_json::to_value(&run.summary).unwrap();
        assert!(value.get("notes").is_none(), "empty notes are not written");
        let loaded: RunSummary = serde_json::from_value(value.clone()).unwrap();
        assert!(loaded.notes.is_empty());
        value["notes"] = serde_json::json!(["kept"]);
        let loaded: RunSummary = serde_json::from_value(value).unwrap();
        assert_eq!(loaded.notes, ["kept"]);
        drop(run);
        crate::storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn a_refused_end_mark_still_saves_the_closed_terminal_and_names_the_cause() {
        let _disk = storage::slow_disk::SlowDisk::install();
        let (mut run, directory) = open_run("ant-run-eof");
        run.storage_error("capture quota exhausted; terminal saving stopped");
        let error = run.eof(65536).unwrap_err();
        assert!(error.contains("capture quota exhausted"), "{error}");
        storage::flush_json().unwrap();
        let saved: RunSummary =
            serde_json::from_reader(File::open(directory.join("run.json")).unwrap()).unwrap();
        assert!(
            saved.terminal_eof,
            "the summary records the closed terminal"
        );
        assert_eq!(
            run.save_screen(65536).unwrap_err().matches("quota").count(),
            1
        );
        drop(run);
        crate::storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn only_an_ended_run_with_a_closed_terminal_is_complete() {
        let (mut run, directory) = open_run("ant-run-complete");
        assert!(!run.recording_complete());
        run.summary.state = RunState::Finished;
        assert!(!run.recording_complete());
        run.summary.terminal_eof = true;
        assert!(run.recording_complete());
        run.summary.state = RunState::TerminalClosed;
        assert!(!run.recording_complete());
        drop(run);
        crate::storage::settle_json_under(&directory);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
