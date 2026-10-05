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
    pub fn persist_summary(&self) -> Result<(), String> {
        storage::atomic_json(&self.summary.directory.join("run.json"), &self.summary)?;
        storage::atomic_json(
            &self.summary.directory.join("manifest.json"),
            &serde_json::json!({"format":"ANTT run raw LE32","run":self.summary,"packets":self.capture.packets,"bytes":self.stored_len(),"persistence_error":self.summary.recording_error,"boot_bundle_identity":self.boot_bundle_identity,"disk_base_identity":self.disk_base_identity}),
        )
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
        if self.summary.state != RunState::StopRequested {
            self.summary.state = RunState::TerminalClosed;
        }
        self.journal(3, &[], available)?;
        self.persist_summary()
    }
    pub fn save_screen(&mut self, available: u64) -> Result<(), String> {
        if self.summary.recording_error.is_some() {
            return Err("run saving stopped; final screen unavailable".into());
        }
        let screen = self.terminal.screen().state_formatted();
        if screen.len() as u64 > available + self.screen_len {
            self.storage_error("capture quota exhausted; terminal screen not saved");
            return Err("capture quota exhausted; terminal screen not saved".into());
        }
        let path = self.summary.directory.join("terminal-screen.ansi");
        let temporary = self.summary.directory.join("terminal-screen.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(&screen)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        std::fs::rename(temporary, path).map_err(|e| e.to_string())?;
        self.screen_len = screen.len() as u64;
        Ok(())
    }
    pub fn finalize(&mut self, available: u64, state: &str, health: &Health) -> Result<(), String> {
        self.summary.state = RunState::Finalized;
        let results = [
            self.capture.sync(),
            self.save_screen(available),
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
        self.persist_summary()?;
        let (rows, cols) = self.terminal.screen().size();
        storage::atomic_json(
            &self.summary.directory.join("manifest.json"),
            &serde_json::json!({"format":"ANTT run raw LE32","run":self.summary,"packets":self.capture.packets,"bytes":self.stored_len(),"persistence_error":self.summary.recording_error,"final_state":state,"health":health,"terminal_rows":rows,"terminal_cols":cols,"terminal_complete":self.summary.terminal_eof,"terminal_issue":if self.summary.terminal_eof {None} else {Some("VM ended before terminal EOF; terminal tail may be missing")},"quota_scope":"VM boot shared raw, fields, transcript, journal and screen","boot_bundle_identity":self.boot_bundle_identity,"disk_base_identity":self.disk_base_identity}),
        )?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
