// SPDX-License-Identifier: GPL-3.0-only
//! A background keyboard owner with short QMP connections between key chords.
use super::Qmp;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(crate) struct Job {
    pub boot_id: String,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<String, String>>>,
}

impl Job {
    pub fn start(
        path: PathBuf,
        boot_id: String,
        text: crate::clipboard::Text,
        epoch: Arc<AtomicU64>,
        stopping: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancelled = cancel.clone();
        let generation = epoch.load(Ordering::Acquire);
        let thread = thread::Builder::new().name("antinomie-vm-keyboard".into()).spawn(move || {
            let current = || !cancelled.load(Ordering::Relaxed)
                && !stopping.load(Ordering::Relaxed)
                && epoch.load(Ordering::Acquire) == generation;
            if !current() { return Err("Clipboard typing cancelled before connection".into()); }
            let mut typed = 0;
            for c in text.text.chars() {
                if !current() {
                    return Err(format!("Clipboard typing cancelled after {typed} keys; remaining text was not sent"));
                }
                // QEMU's socket admits one monitor client. Release it after
                // each chord so resource/capture/lifecycle commands can connect.
                let mut qmp = Qmp::connect(&path, Duration::from_secs(2))
                    .map_err(|e| format!("Clipboard typing stopped after {typed} keys: {e}"))?;
                if !current() {
                    return Err(format!("Clipboard typing cancelled after {typed} keys; remaining text was not sent"));
                }
                let (name, shifted) = crate::clipboard::key(c).ok_or("unsupported clipboard key")?;
                let mut keys = Vec::with_capacity(2);
                if shifted { keys.push(serde_json::json!({"type":"qcode","data":"shift"})); }
                keys.push(serde_json::json!({"type":"qcode","data":name}));
                let command = serde_json::json!({"execute":"send-key","arguments":{"keys":keys,"hold-time":10}});
                qmp.reply(&format!("{command}\n")).map_err(|e| format!(
                    "Clipboard typing stopped after {typed} acknowledged keys ({e}); last key outcome may be unknown; no retry"
                ))?;
                drop(qmp);
                typed += 1;
                // Wait beyond QEMU's key-up delay before the next key.
                thread::sleep(Duration::from_millis(25));
            }
            Ok(format!("Clipboard typing completed: {typed} keys sent (US layout)"))
        }).map_err(|e| format!("Clipboard typing worker: {e}"))?;
        Ok(Self {
            boot_id,
            cancel,
            thread: Some(thread),
        })
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn cancel_and_join(mut self) -> Result<String, String> {
        self.cancel();
        self.thread
            .take()
            .ok_or("Clipboard worker already joined")?
            .join()
            .unwrap_or_else(|_| Err("Clipboard typing worker panicked".into()))
    }

    pub fn poll(&mut self) -> Option<Result<String, String>> {
        if !self.thread.as_ref()?.is_finished() {
            return None;
        }
        Some(
            self.thread
                .take()?
                .join()
                .unwrap_or_else(|_| Err("Clipboard typing worker panicked".into())),
        )
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests;
