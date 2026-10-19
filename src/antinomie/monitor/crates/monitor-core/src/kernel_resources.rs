// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Kernel-native guest resource producer (contract revision 17 and later).
//!
//! The guest kernel answers `RESOURCES` with its latest completed sample and
//! refreshes it on its own worker, so a poll never blocks and never launches a
//! guest process. A request is idempotent: a lost or late reply is not replayed
//! and cannot consume anything. One request is in flight at a time; a reply
//! that arrives after its deadline is still owned and clears the error it caused.
//! Guest measurements are observations, not trusted against a compromised guest.
use crate::{api::GuestResources, control};
use std::time::{Duration, Instant};

/// First contract revision whose kernel produces resource samples itself.
pub(crate) const MIN_REVISION: u32 = 17;
/// Whether this guest kernel samples resources itself instead of needing the
/// temporary guest collector of older revisions.
pub(crate) fn kernel_produces(kernel: Option<&crate::api::GuestKernel>) -> bool {
    kernel
        .and_then(|kernel| kernel.revision)
        .is_some_and(|revision| revision >= MIN_REVISION)
}
const INTERVAL: Duration = Duration::from_secs(1);
const WARMUP_INTERVAL: Duration = Duration::from_millis(200);
const RETRY_INTERVAL: Duration = Duration::from_secs(2);
const DEADLINE: Duration = Duration::from_secs(4);
const STALE: Duration = Duration::from_secs(6);
const BLOCKED: u64 = 4000;
const MEMORY_VALID: u32 = 1;
const FILESYSTEM_VALID: u32 = 2;
const REFRESHING: u32 = 4;
const EOPNOTSUPP: i32 = -95;

struct Pending {
    id: u64,
    submitted: Instant,
}

#[derive(Default)]
pub(crate) struct KernelResources {
    pending: Option<Pending>,
    next: Option<Instant>,
    last: Option<(GuestResources, Instant, u64)>,
    kernel_sequence: u64,
    unsupported: bool,
    /// The in-flight reply belongs to a timeline that has ended.
    discard_pending: bool,
    error: Option<String>,
}

impl KernelResources {
    /// Return at most one new request; the caller assigns its transport id.
    pub(crate) fn command(&mut self, now: Instant) -> Option<(u32, Vec<u8>)> {
        if let Some(pending) = &self.pending {
            if now.duration_since(pending.submitted) > DEADLINE && self.error.is_none() {
                self.error = Some("guest resource reply is late; waiting without resending".into());
            }
            return None;
        }
        if self.unsupported || self.next.is_some_and(|next| now < next) {
            return None;
        }
        Some((control::RESOURCES, control::header(0)))
    }
    pub(crate) fn submitted(&mut self, id: u64, now: Instant) {
        self.pending = Some(Pending { id, submitted: now });
    }
    /// A failed submit leaves nothing in flight; try again after a pause.
    pub(crate) fn submit_failed(&mut self, error: String, now: Instant) {
        self.error = Some(error);
        self.next = Some(now + RETRY_INTERVAL);
    }
    /// A timeline boundary (snapshot, reconnect): drop every reading. The
    /// request already in flight is still consumed, but its answer is ignored.
    pub(crate) fn reset_timeline(&mut self) {
        let pending = self.pending.take();
        *self = Self {
            discard_pending: pending.is_some(),
            pending,
            ..Self::default()
        };
    }
    /// Consume only this producer's reply id, including late replies.
    pub(crate) fn reply(
        &mut self,
        id: u64,
        status: i32,
        payload: &[u8],
        boot_id: &str,
        now: Instant,
    ) -> bool {
        if self.pending.as_ref().is_none_or(|pending| pending.id != id) {
            return false;
        }
        self.pending = None;
        if std::mem::take(&mut self.discard_pending) {
            return true;
        }
        if status == EOPNOTSUPP {
            self.unsupported = true;
            self.error = Some("guest kernel does not provide resource sampling".into());
            return true;
        }
        let result = if status != 0 {
            Err(format!("guest resource command rejected: {status}"))
        } else {
            self.accept(payload, boot_id, now)
        };
        match result {
            Ok(warming) => {
                self.error = None;
                self.next = Some(now + if warming { WARMUP_INTERVAL } else { INTERVAL });
            }
            Err(error) => {
                self.error = Some(error);
                self.next = Some(now + RETRY_INTERVAL);
            }
        }
        true
    }
    /// Returns whether the kernel has not completed its first sample yet.
    fn accept(&mut self, payload: &[u8], boot_id: &str, now: Instant) -> Result<bool, String> {
        let parsed = parse(payload, boot_id)?;
        if parsed.sequence < self.kernel_sequence {
            return Err("guest resource sample sequence went backwards".into());
        }
        if parsed.sequence == 0 {
            return Ok(true);
        }
        self.kernel_sequence = parsed.sequence;
        let mut value = parsed.value;
        if parsed.refresh_pending_ms > BLOCKED {
            let blocked = format!(
                "guest resource refresh has been blocked for {} ms",
                parsed.refresh_pending_ms
            );
            value.error = Some(match value.error.take() {
                Some(issues) => format!("{issues}; {blocked}"),
                None => blocked,
            });
        }
        self.last = Some((value, now, parsed.age_ms));
        Ok(false)
    }
    pub(crate) fn sample(&self, boot_id: &str, unavailable: bool) -> GuestResources {
        let (mut sample, age) = match &self.last {
            Some((sample, seen, kernel_age)) => {
                let age = seen
                    .elapsed()
                    .saturating_add(Duration::from_millis(*kernel_age));
                (sample.clone(), Some(age))
            }
            None => (GuestResources::default(), None),
        };
        sample.boot_id = boot_id.into();
        sample.age_ms = age.map(|age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX));
        sample.stale = unavailable || self.error.is_some() || age.is_none_or(|age| age > STALE);
        if let Some(error) = &self.error {
            sample.error = Some(error.clone());
        }
        sample
    }
}

struct Parsed {
    sequence: u64,
    age_ms: u64,
    refresh_pending_ms: u64,
    value: GuestResources,
}

fn parse(payload: &[u8], boot_id: &str) -> Result<Parsed, String> {
    if payload.len() != control::RESOURCES_SIZE || payload[92..96] != [0; 4] {
        return Err("invalid guest resource reply".into());
    }
    let u64_at = |at: usize| u64::from_le_bytes(payload[at..at + 8].try_into().expect("8 bytes"));
    let u32_at = |at: usize| u32::from_le_bytes(payload[at..at + 4].try_into().expect("4 bytes"));
    let i32_at = |at: usize| i32::from_le_bytes(payload[at..at + 4].try_into().expect("4 bytes"));
    let (sequence, flags) = (u64_at(0), u32_at(16));
    if flags & !(MEMORY_VALID | FILESYSTEM_VALID | REFRESHING) != 0 {
        return Err("unknown guest resource flags".into());
    }
    let refresh_pending_ms = u64_at(80);
    if sequence == 0 {
        return Ok(Parsed {
            sequence,
            age_ms: 0,
            refresh_pending_ms,
            value: GuestResources::default(),
        });
    }
    let age_ms = u64_at(8);
    if age_ms == u64::MAX {
        return Err("guest resource sample has no age".into());
    }
    let mut value = GuestResources {
        boot_id: boot_id.into(),
        sample_sequence: sequence,
        ..GuestResources::default()
    };
    let mut issues = Vec::new();
    if flags & MEMORY_VALID != 0 {
        let (total, available) = (u64_at(24), u64_at(32));
        if total == 0 || available > total {
            return Err("invalid guest memory capacities".into());
        }
        value.memory_total_size = Some(total);
        value.memory_available_size = Some(available);
        value.memory_used_size = Some(total - available);
    } else {
        issues.push(format!(
            "guest memory accounting unavailable (errno {})",
            -i64::from(i32_at(88))
        ));
    }
    if flags & FILESYSTEM_VALID != 0 {
        let (total, free, available) = (u64_at(40), u64_at(48), u64_at(56));
        if free > total || available > free {
            return Err("invalid guest filesystem capacities".into());
        }
        value.root_total_size = Some(total);
        value.root_free_size = Some(free);
        value.root_available_size = Some(available);
        value.root_used_size = Some(total - free);
    } else {
        issues.push(format!(
            "guest root statfs unavailable (errno {})",
            -i64::from(i32_at(20))
        ));
    }
    if !issues.is_empty() {
        value.error = Some(issues.join("; "));
    }
    Ok(Parsed {
        sequence,
        age_ms,
        refresh_pending_ms,
        value,
    })
}

#[cfg(test)]
mod tests;
