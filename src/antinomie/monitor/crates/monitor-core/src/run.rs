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

pub(crate) struct ProgramRun {
    pub summary: RunSummary,
    pub capture: RawCapture,
    pub assembler: Assembler,
    journal: File,
    transcript: File,
    terminal: vt100::Parser,
    terminal_len: u64,
    screen_len: u64,
    pub sequence: u64,
    pub boot_bundle_identity: Option<String>,
    pub disk_base_identity: Option<String>,
    pub execution_generation: u64,
    /// Terminal READ requests that never received a reply before finalize.
    pub terminal_reads_unanswered: u64,
}

impl ProgramRun {
    pub fn new(summary: RunSummary, quota: u64) -> Result<Self, String> {
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
        let run = Self {
            summary,
            capture,
            assembler,
            journal,
            transcript,
            terminal: vt100::Parser::new(24, 80, 0),
            terminal_len: 0,
            screen_len: 0,
            sequence: 0,
            boot_bundle_identity: None,
            disk_base_identity: None,
            execution_generation: 0,
            terminal_reads_unanswered: 0,
        };
        run.persist_summary()?;
        Ok(run)
    }
    pub fn stored_len(&self) -> u64 {
        self.capture
            .bytes
            .saturating_add(self.assembler.stored_len())
            .saturating_add(self.terminal_len)
            .saturating_add(self.screen_len)
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
        serde_json::json!({"format":"ANTT run raw LE32","run":self.summary,"packets":self.capture.packets,"bytes":self.stored_len(),"persistence_error":self.summary.recording_error,"boot_bundle_identity":self.boot_bundle_identity,"disk_base_identity":self.disk_base_identity})
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
    fn journal(&mut self, kind: u8, data: &[u8], available: u64) -> Result<(), String> {
        if self.summary.recording_error.is_some() {
            return Err("run saving already stopped".into());
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
        self.terminal.set_size(rows, cols);
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
        self.journal(3, &[], available)?;
        self.persist_summary()
    }
    /// Saves the terminal screen on the background writer.
    pub fn save_screen(&mut self, available: u64) -> Result<(), String> {
        let screen = self.screen_bytes(available)?;
        self.screen_len = screen.len() as u64;
        storage::queue_bytes(&self.summary.directory.join("terminal-screen.ansi"), screen)
    }
    fn screen_bytes(&mut self, available: u64) -> Result<Vec<u8>, String> {
        if self.summary.recording_error.is_some() {
            return Err("run saving stopped; final screen unavailable".into());
        }
        let screen = self.terminal.screen().state_formatted();
        if screen.len() as u64 > available + self.screen_len {
            self.storage_error("capture quota exhausted; terminal screen not saved");
            return Err("capture quota exhausted; terminal screen not saved".into());
        }
        Ok(screen)
    }
    fn save_screen_now(&mut self, available: u64) -> Result<(), String> {
        let screen = self.screen_bytes(available)?;
        storage::atomic_bytes(
            &self.summary.directory.join("terminal-screen.ansi"),
            &screen,
        )?;
        self.screen_len = screen.len() as u64;
        Ok(())
    }
    pub fn finalize(&mut self, available: u64, state: &str, health: &Health) -> Result<(), String> {
        if !matches!(self.summary.state, RunState::Finished | RunState::Stopped) {
            self.summary.state = RunState::Finalized;
        }
        let results = [
            self.capture.sync(),
            self.save_screen_now(available),
            self.journal.sync_all().map_err(|e| e.to_string()),
            self.transcript.sync_all().map_err(|e| e.to_string()),
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
            &serde_json::json!({"format":"ANTT run raw LE32","run":self.summary,"packets":self.capture.packets,"bytes":self.stored_len(),"persistence_error":self.summary.recording_error,"final_state":state,"health":health,"terminal_rows":rows,"terminal_cols":cols,"terminal_complete":self.terminal_complete(),"terminal_issue":self.terminal_issue(),"quota_scope":"VM boot shared raw, fields, transcript, journal and screen","boot_bundle_identity":self.boot_bundle_identity,"disk_base_identity":self.disk_base_identity}),
        )?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            recording_error: None,
            execution: Some(execution),
        };
        let mut run = ProgramRun::new(summary, 65536).unwrap();
        run.eof(65536).unwrap();
        assert_eq!(run.summary.state, RunState::Running);
        let execution = run.summary.execution.as_mut().unwrap();
        execution.live_task_count = 0;
        execution.flags = 11;
        run.summary.state = RunState::Finished;
        assert!(
            run.capture
                .append(b"late telemetry after process completion")
        );
        assert!(run.output(b"late terminal tail", 65536).is_ok());
        run.finalize(65536, "vm-stop", &Health::default()).unwrap();
        assert_eq!(run.summary.state, RunState::Finished);
        assert_eq!(
            run.summary.execution.as_ref().unwrap().root_exit,
            Some(WaitStatus::Exited { code: 7 })
        );
        drop(run);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn unanswered_terminal_reads_make_the_terminal_incomplete_even_after_eof() {
        let directory =
            std::env::temp_dir().join(format!("ant-terminal-reads-{}", storage::unique_id()));
        let summary = RunSummary {
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
            recording_error: None,
            execution: None,
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
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn headless_terminal_reopens_journal_screen_and_quota_failure_preserves_prefix() {
        let directory = std::env::temp_dir().join(format!("ant-terminal-{}", storage::unique_id()));
        let summary = RunSummary {
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
            recording_error: None,
            execution: None,
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
        std::fs::remove_dir_all(directory).unwrap();
    }
}
