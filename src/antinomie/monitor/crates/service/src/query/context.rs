// SPDX-License-Identifier: GPL-3.0-only
//! `ReadContext` (design 5.12.1): who asks, the cancel flag and the deadline.
//! A dropped socket connection or HTTP request sets `cancel`, the engine's own
//! pattern (`recording.rs` takes an `&AtomicBool` in every long read).

use crate::api::{
    error::{ApiError, ErrorCode},
    ops::{Caller, Scope},
};
use serde_json::json;
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

    /// `forbidden` unless the caller holds `scope`.
    pub fn require(&self, scope: Scope) -> Result<(), ApiError> {
        if self.caller.has(scope) {
            return Ok(());
        }
        let name = serde_json::to_value(scope)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        Err(ApiError::new(
            ErrorCode::Forbidden,
            format!("this read needs the {name} scope"),
        )
        .with_detail("scope", json!(name)))
    }

    /// The caller of a local CLI that owns the data directory: every read scope.
    pub fn local_owner(client_id: &str) -> Self {
        Self::new(Caller {
            client_id: client_id.to_owned(),
            scopes: vec![Scope::Read, Scope::ArtifactsSensitive],
            policies: Vec::new(),
        })
    }
}
