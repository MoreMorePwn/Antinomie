// SPDX-License-Identifier: GPL-3.0-only
//! `ReadContext` (design 5.12.1): who asks, the cancel flag and the deadline.
//! A dropped socket connection or HTTP request sets `cancel`, the engine's own
//! pattern (`recording.rs` takes an `&AtomicBool` in every long read).

use crate::api::{
    error::ApiError,
    ops::{Caller, Permission},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The caller, the cancel flag and the deadline of one read.
#[derive(Clone, Debug)]
pub struct ReadContext {
    pub caller: Caller,
    /// Set by the binding when the client goes away; the read stops at its
    /// next check and answers `unavailable`.
    pub cancel: Arc<AtomicBool>,
    /// When the read must be over. `None` takes the pool's default for the
    /// operation's class (10 s light, 60 s heavy).
    pub deadline: Option<Instant>,
}

impl ReadContext {
    pub fn new(caller: Caller) -> Self {
        Self {
            caller,
            cancel: Arc::new(AtomicBool::new(false)),
            deadline: None,
        }
    }

    /// A context whose read must end within `timeout` from now.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.deadline = Some(Instant::now() + timeout);
        self
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// `permission_denied` unless the caller holds `permission`.
    pub fn require(&self, permission: Permission) -> Result<(), ApiError> {
        self.caller.require(permission)
    }

    /// The caller of a local CLI that owns the data directory: the read
    /// permissions (`runs.see_all`, `evidence.view`).
    pub fn local_owner(client_id: &str) -> Self {
        Self::new(Caller::new(
            client_id,
            &[Permission::RunsSeeAll, Permission::EvidenceView],
        ))
    }
}
