// SPDX-License-Identifier: GPL-3.0-only
//! Time and randomness behind small seams, so tests can use a fake clock
//! (design 7.2: no timing-sensitive asserts) and the service builds ids
//! without a new crate (design 5.2).

use crate::api::ids::{ArtifactId, JobId, UploadId};
use std::{
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Wall-clock time in Unix milliseconds.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

/// A clock a test moves by hand.
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(start_ms: u64) -> Self {
        Self(AtomicU64::new(start_ms))
    }
    pub fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Ten random bytes from the kernel; if `/dev/urandom` cannot be read, a hash
/// of the time and a counter (ids stay unique, they are not secrets).
pub fn random_bytes() -> [u8; 10] {
    let mut bytes = [0u8; 10];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok()
    {
        return bytes;
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(SystemClock.now_ms().to_le_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::SeqCst).to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    bytes.copy_from_slice(&hasher.finalize()[..10]);
    bytes
}

pub fn new_job_id(now_ms: u64) -> JobId {
    JobId::from_parts(now_ms, random_bytes())
}

pub fn new_upload_id(now_ms: u64) -> UploadId {
    UploadId::from_parts(now_ms, random_bytes())
}

pub fn new_artifact_id(now_ms: u64) -> ArtifactId {
    ArtifactId::from_parts(now_ms, random_bytes())
}

/// A random id for an engine epoch (`engine.hello.epoch`): 20 hex characters.
pub fn new_epoch() -> String {
    random_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
