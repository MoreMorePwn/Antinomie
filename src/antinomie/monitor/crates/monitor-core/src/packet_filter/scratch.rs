// SPDX-License-Identifier: GPL-3.0-only
//! The private folder a packet snapshot and its row matches live in.
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) struct Scratch {
    pub(super) path: PathBuf,
}

impl Scratch {
    pub(super) fn new() -> Result<Self, String> {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        for _ in 0..32 {
            let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "antinomie-packet-{}-{stamp}-{serial}",
                std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("packet snapshot directory: {e}")),
            }
        }
        Err("could not create private packet snapshot directory".into())
    }
    pub(super) fn file(&self, name: &str) -> Result<File, String> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path.join(name))
            .map_err(|e| format!("packet snapshot file: {e}"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Nothing here is user evidence. On failure the OS retains only private
        // temporary files; the original capture is never a cleanup target.
        let _ = fs::remove_dir_all(&self.path);
    }
}
