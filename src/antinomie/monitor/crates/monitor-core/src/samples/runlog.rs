// SPDX-License-Identifier: GPL-3.0-only
//! What a run writes to the custody log of the library sample it runs: its
//! start, what the analyst did to it, and its end. One [`RunLog`] belongs to
//! one run of one library sample (found by hash when the run is launched); a
//! run of anything else has none, so nothing here costs it anything.
//!
//! Every write is best effort. A custody log that cannot be written (the
//! library is locked, the disk is full) must never fail or slow a run, so the
//! error is dropped here and the Samples page's Verify says what is missing.
use super::{
    SampleRef,
    chain::ChainedEvents,
    custody::{ActionKind, CustodyEvent, CustodySink},
    library::{DATABASE, now_ms},
    samples_dir,
};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path, path::PathBuf};

/// The analyst, as the log names them.
const ANALYST: &str = "analyst";
/// The app, as the log names it.
const APP: &str = "app";

pub struct RunLog {
    database: PathBuf,
    sha256: String,
    run: String,
    vm: String,
    /// Bytes typed since the last entry. Only this number is ever kept.
    typed: u64,
}

impl RunLog {
    pub fn new(data_dir: &Path, sample: &SampleRef, run: &str, vm: &str) -> Self {
        Self {
            database: samples_dir(data_dir).join(DATABASE),
            sha256: sample.sha256.to_ascii_lowercase(),
            run: run.into(),
            vm: vm.into(),
            typed: 0,
        }
    }

    fn note(&self, by: &str, event: CustodyEvent) {
        let _ = ChainedEvents::new(&self.database).record(&self.sha256, by, now_ms(), &event);
    }

    /// The run started: what it ran on and under.
    pub fn started(&self, detail: String) {
        self.note(
            APP,
            CustodyEvent::RunStarted {
                vm: self.vm.clone(),
                run: self.run.clone(),
                detail,
            },
        );
    }

    /// Input went to the guest terminal. A line sent (Enter) writes an entry
    /// with the number of bytes typed since the last one; the text is not
    /// looked at beyond that.
    pub fn typed(&mut self, data: &[u8]) {
        self.typed = self.typed.saturating_add(data.len() as u64);
        if data.iter().any(|byte| matches!(byte, b'\r' | b'\n')) {
            self.flush_typed();
        }
    }

    /// Write what was typed and not yet noted.
    pub fn flush_typed(&mut self) {
        if self.typed > 0 {
            let bytes = std::mem::take(&mut self.typed);
            self.note(
                ANALYST,
                CustodyEvent::TerminalInput {
                    run: self.run.clone(),
                    bytes,
                },
            );
        }
    }

    /// The analyst did something to the running guest.
    pub fn action(&mut self, what: ActionKind, detail: &str) {
        self.flush_typed();
        self.note(
            ANALYST,
            CustodyEvent::Action {
                run: self.run.clone(),
                what,
                detail: detail.into(),
            },
        );
    }

    /// The run's recording is final: `detail` says how much and what hash.
    pub fn ended(&mut self, detail: String) {
        self.flush_typed();
        self.note(
            APP,
            CustodyEvent::RunEnded {
                vm: self.vm.clone(),
                run: self.run.clone(),
                detail,
            },
        );
    }
}

/// SHA-256 of a file read in blocks; `None` when it cannot be read.
pub fn file_sha256(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut block = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut block).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    Some(format!("{:x}", hasher.finalize()))
}
