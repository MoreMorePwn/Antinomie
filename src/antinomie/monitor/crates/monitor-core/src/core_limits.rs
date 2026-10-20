// SPDX-License-Identifier: MIT
//! What a guest accepts for a process core, and why a core is not complete.
//!
//! The guest derives its limits from its memory and advertises them (`CORE_CAPS`);
//! a guest without that opcode keeps the contract every earlier kernel had.
use serde::{Deserialize, Serialize};

const MIB: u64 = 1024 * 1024;
/// Largest budget this host will ask for, whatever a guest advertises.
pub const CORE_MAX_SUPPORTED: u64 = 1024 * MIB;
/// The ceiling and the deadline of a guest without `CORE_CAPS`.
pub const CORE_LEGACY_SIZE: u64 = 64 * MIB;
pub const CORE_LEGACY_TIMEOUT_MS: u32 = 5000;
/// Longest serialization deadline a guest may advertise.
pub const CORE_TIMEOUT_MAX_MS: u32 = 60_000;
/// Budget a request uses when nothing was chosen (before the guest's maximum applies).
pub const CORE_DEFAULT_BUDGET_MIB: u32 = 256;

/// What this guest's kernel accepts for process cores.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreLimits {
    /// False for a guest without `CORE_CAPS`: 64 MiB, 5000 ms, no stored-byte status.
    pub advertised: bool,
    /// Largest budget of one handle, in bytes.
    pub max_size: u64,
    /// What the budgets of all open handles may add up to.
    pub pool_size: u64,
    pub max_handles: u32,
    pub max_timeout_ms: u32,
    /// The guest's RAM, when it said.
    pub guest_ram: Option<u64>,
    /// Bytes an exit core allocates when it is armed.
    pub prealloc: u64,
    /// `CORE_STATUS` can append the stored byte count.
    pub stored_status: bool,
    /// The buffer grows while it is written: `-ENOMEM` means the budget was not reachable.
    pub chunked: bool,
    /// The guest polls every tick while a finished core is read.
    pub fast_read: bool,
}

impl CoreLimits {
    pub const LEGACY: Self = Self {
        advertised: false,
        max_size: CORE_LEGACY_SIZE,
        pool_size: 2 * CORE_LEGACY_SIZE,
        max_handles: 4,
        max_timeout_ms: CORE_LEGACY_TIMEOUT_MS,
        guest_ram: None,
        prealloc: CORE_LEGACY_SIZE,
        stored_status: false,
        chunked: false,
        fast_read: false,
    };

    /// Decode a `CORE_CAPS` reply (48 bytes).
    pub fn parse(reply: &[u8]) -> Result<Self, String> {
        use crate::parser::{u32_at, u64_at};
        if reply.len() != 48 {
            return Err("invalid process-core capability length".into());
        }
        let word = |offset| u32_at(reply, offset).map_err(|error| error.to_string());
        let wide = |offset| u64_at(reply, offset).map_err(|error| error.to_string());
        let flags = word(4)?;
        let limits = Self {
            advertised: true,
            max_size: wide(8)?,
            pool_size: wide(16)?,
            max_handles: word(24)?,
            max_timeout_ms: word(28)?,
            guest_ram: Some(wide(32)?),
            prealloc: wide(40)?,
            stored_status: flags & 2 != 0,
            chunked: flags & 8 != 0,
            fast_read: flags & 16 != 0,
        };
        if word(0)? != 1
            || flags & !0x1f != 0
            || flags & 5 != 5
            || !(CORE_LEGACY_SIZE..=CORE_MAX_SUPPORTED).contains(&limits.max_size)
            || limits.pool_size < limits.max_size
            || limits.max_handles != 4
            || !(CORE_LEGACY_TIMEOUT_MS..=CORE_TIMEOUT_MAX_MS).contains(&limits.max_timeout_ms)
            || limits.prealloc > limits.max_size
        {
            return Err("invalid process-core capability bounds".into());
        }
        Ok(limits)
    }

    /// The first rule a request breaks, in the order a user can act on them.
    pub fn check(&self, max_size: u64, timeout_ms: u32) -> Result<(), String> {
        if max_size == 0
            || max_size > CORE_MAX_SUPPORTED
            || timeout_ms == 0
            || timeout_ms > CORE_TIMEOUT_MAX_MS
        {
            return Err("process-core budget or deadline is outside the supported range".into());
        }
        if !self.advertised && max_size > CORE_LEGACY_SIZE {
            return Err(format!(
                "this guest's base accepts process cores up to 64 MiB; a base built with patch series 0039 or newer (Antinomie 0.7.0) is needed for {} MiB",
                max_size.div_ceil(MIB)
            ));
        }
        if max_size > self.max_size {
            let ram = self
                .guest_ram
                .map(|ram| format!(" (derived from its {} MiB of RAM)", ram / MIB))
                .unwrap_or_default();
            return Err(format!(
                "this guest accepts process cores up to {} MiB{ram}; requested {} MiB",
                self.max_size / MIB,
                max_size.div_ceil(MIB)
            ));
        }
        if timeout_ms > self.max_timeout_ms {
            return Err(format!(
                "process-core deadline of {timeout_ms} ms is above this guest's {} ms maximum",
                self.max_timeout_ms
            ));
        }
        Ok(())
    }

    /// `check` against what the guest said, or, before it has said, against the
    /// contract every guest accepts: a request inside it never has to wait.
    pub fn check_known(known: Option<Self>, max_size: u64, timeout_ms: u32) -> Result<(), String> {
        match known {
            Some(limits) => limits.check(max_size, timeout_ms),
            None if max_size <= CORE_LEGACY_SIZE && timeout_ms <= CORE_LEGACY_TIMEOUT_MS => {
                Self::LEGACY.check(max_size, timeout_ms)
            }
            None => Err(
                "the guest has not reported its process-core limits yet; retry in a moment".into(),
            ),
        }
    }

    /// A remembered default clamped to what this guest accepts, in bytes.
    pub fn effective_budget(&self, wanted_mib: u32) -> u32 {
        let wanted = u64::from(wanted_mib).max(1) * MIB;
        wanted.min(self.max_size).min(CORE_MAX_SUPPORTED) as u32
    }

    /// The deadline that goes with a budget: 5 s plus 10 ms per MiB, at most what
    /// the guest accepts (always 5 s on a guest without `CORE_CAPS`).
    pub fn default_timeout_ms(&self, budget: u64) -> u32 {
        if !self.advertised {
            return CORE_LEGACY_TIMEOUT_MS;
        }
        let scaled = 5000 + 10 * budget.div_ceil(MIB);
        scaled.clamp(5000, u64::from(self.max_timeout_ms)) as u32
    }
}

/// Why a core is not complete.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoreReasonCode {
    /// The stored-byte budget was reached.
    Budget,
    /// The guest could not allocate more memory for the copy.
    GuestMemory,
    /// The serialization deadline passed.
    Deadline,
    Canceled,
    /// More threads or mappings than the guest bounds, or a full extent table.
    Bounds,
    /// The file's logical extent would pass the guest's bound.
    Logical,
    /// Missing thread contexts or pages the policy leaves out.
    Coverage,
    /// A signal interrupted the acquisition.
    Interrupted,
    /// The guest's writer stopped for another reason.
    Writer,
    /// The recording quota ran out.
    Quota,
    /// The host disk has too little room.
    HostDisk,
    /// Writing the file failed.
    HostWrite,
    /// A snapshot, stop or reconnect boundary sealed the transfer.
    Sealed,
    Unsupported,
}

impl CoreReasonCode {
    /// A short label for a list row.
    pub fn label(self) -> &'static str {
        match self {
            Self::Budget => "budget reached",
            Self::GuestMemory => "guest memory",
            Self::Deadline => "deadline",
            Self::Canceled => "canceled",
            Self::Bounds => "guest bounds",
            Self::Logical => "extent bound",
            Self::Coverage => "coverage",
            Self::Interrupted => "interrupted",
            Self::Writer => "writer stopped",
            Self::Quota => "recording quota",
            Self::HostDisk => "host disk",
            Self::HostWrite => "host write",
            Self::Sealed => "sealed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreReason {
    pub code: CoreReasonCode,
    pub errno: Option<i32>,
    pub text: String,
}

impl CoreReason {
    pub fn new(code: CoreReasonCode, errno: Option<i32>, text: impl Into<String>) -> Self {
        Self {
            code,
            errno,
            text: text.into().chars().take(2048).collect(),
        }
    }
}

/// What the guest's terminal status says about a core, in the units a user reads.
pub struct CoreOutcome {
    pub state: u32,
    pub status: i32,
    /// The ELF-declared extent (`expected_size`) and the logical size reached.
    pub expected: u64,
    pub size: u64,
    /// Bytes the guest holds, when it said.
    pub stored: Option<u64>,
    pub flags: u32,
    pub budget: u64,
    pub limits: CoreLimits,
}

fn mib(size: u64) -> String {
    if size.is_multiple_of(MIB) {
        format!("{} MiB", size / MIB)
    } else {
        format!("{:.1} MiB", size as f64 / MIB as f64)
    }
}

/// The reason a terminal guest status gives for an incomplete core; None for a
/// complete one. The errno is the guest's, so each reading means one thing
/// (`ANTC_CORE_STATUS` documents the table).
pub fn guest_reason(outcome: &CoreOutcome) -> Option<CoreReason> {
    let errno = -outcome.status;
    if outcome.status == 0 {
        return (outcome.flags & 8 != 0).then(|| {
            CoreReason::new(
                CoreReasonCode::Coverage,
                None,
                "the file is complete but a thread context or resident pages are not covered",
            )
        });
    }
    let reached = mib(outcome.stored.unwrap_or(outcome.size.min(outcome.budget)));
    Some(match errno {
        27 => CoreReason::new(
            CoreReasonCode::Budget,
            Some(-27),
            format!(
                "stored-byte budget of {} reached at file offset {} of {} expected; mappings after it have no captured bytes{}",
                mib(outcome.budget),
                outcome.size,
                outcome.expected,
                if outcome.limits.advertised {
                    format!(
                        " - raise the core budget for this VM (guest maximum {})",
                        mib(outcome.limits.max_size)
                    )
                } else {
                    String::new()
                }
            ),
        ),
        12 if outcome.limits.chunked => CoreReason::new(
            CoreReasonCode::GuestMemory,
            Some(-12),
            format!(
                "guest ran out of memory after {reached} stored; the remaining bytes were not captured"
            ),
        ),
        110 => CoreReason::new(
            CoreReasonCode::Deadline,
            Some(-110),
            format!("the guest's serialization deadline passed after {reached} stored"),
        ),
        125 => CoreReason::new(
            CoreReasonCode::Canceled,
            Some(-125),
            "the capture was canceled",
        ),
        7 => CoreReason::new(
            CoreReasonCode::Bounds,
            Some(-7),
            "the process has more threads, mappings or extents than the guest bounds",
        ),
        75 => CoreReason::new(
            CoreReasonCode::Logical,
            Some(-75),
            "the core file would extend past the 16 GiB bound",
        ),
        61 => CoreReason::new(
            CoreReasonCode::Coverage,
            Some(-61),
            "thread contexts were lost or pages are unavailable under the resident-only policy",
        ),
        4 => CoreReason::new(
            CoreReasonCode::Interrupted,
            Some(-4),
            "a signal interrupted the acquisition",
        ),
        _ => CoreReason::new(
            CoreReasonCode::Writer,
            Some(-errno),
            format!("the guest stopped writing the core (error {errno})"),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(max: u64, flags: u32) -> Vec<u8> {
        let mut wire = vec![0; 48];
        wire[0..4].copy_from_slice(&1u32.to_le_bytes());
        wire[4..8].copy_from_slice(&flags.to_le_bytes());
        wire[8..16].copy_from_slice(&max.to_le_bytes());
        wire[16..24].copy_from_slice(&(2 * max).to_le_bytes());
        wire[24..28].copy_from_slice(&4u32.to_le_bytes());
        wire[28..32].copy_from_slice(&60_000u32.to_le_bytes());
        wire[32..40].copy_from_slice(&(2048 * MIB).to_le_bytes());
        wire[40..48].copy_from_slice(&CORE_LEGACY_SIZE.to_le_bytes());
        wire
    }

    #[test]
    fn capability_reply_is_decoded_and_bounded() {
        let limits = CoreLimits::parse(&caps(896 * MIB, 0x1f)).unwrap();
        assert!(limits.advertised && limits.stored_status && limits.chunked);
        assert_eq!(limits.max_size, 896 * MIB);
        assert_eq!(limits.guest_ram, Some(2048 * MIB));
        for len in [0, 47, 49] {
            assert!(CoreLimits::parse(&vec![0; len]).is_err());
        }
        assert!(CoreLimits::parse(&caps(2048 * MIB, 0x1f)).is_err());
        assert!(CoreLimits::parse(&caps(32 * MIB, 0x1f)).is_err());
        assert!(CoreLimits::parse(&caps(128 * MIB, 0x3f)).is_err());
        let mut bad = caps(128 * MIB, 0x1f);
        bad[0] = 2;
        assert!(CoreLimits::parse(&bad).is_err());
        let mut bad = caps(128 * MIB, 0x1f);
        bad[28..32].copy_from_slice(&60_001u32.to_le_bytes());
        assert!(CoreLimits::parse(&bad).is_err());
    }

    #[test]
    fn requests_are_refused_with_the_rule_they_break() {
        let legacy = CoreLimits::LEGACY;
        assert!(legacy.check(64 * MIB, 5000).is_ok());
        assert!(
            legacy
                .check(256 * MIB, 5000)
                .unwrap_err()
                .contains("up to 64 MiB")
        );
        assert!(legacy.check(64 * MIB, 5001).is_err());
        let limits = CoreLimits::parse(&caps(384 * MIB, 0x1f)).unwrap();
        assert!(limits.check(384 * MIB, 60_000).is_ok());
        assert!(
            limits
                .check(385 * MIB, 5000)
                .unwrap_err()
                .contains("up to 384 MiB")
        );
        assert!(limits.check(1024 * MIB + 1, 5000).is_err());
        assert!(limits.check(0, 5000).is_err() && limits.check(MIB, 0).is_err());
    }

    #[test]
    fn default_budget_and_deadline_follow_the_guest() {
        let limits = CoreLimits::parse(&caps(128 * MIB, 0x1f)).unwrap();
        assert_eq!(limits.effective_budget(256), (128 * MIB) as u32);
        assert_eq!(limits.effective_budget(64), (64 * MIB) as u32);
        assert_eq!(CoreLimits::LEGACY.effective_budget(256), (64 * MIB) as u32);
        assert_eq!(limits.default_timeout_ms(64 * MIB), 5640);
        assert_eq!(limits.default_timeout_ms(1024 * MIB), 15_240);
        assert_eq!(CoreLimits::LEGACY.default_timeout_ms(64 * MIB), 5000);
    }

    #[test]
    fn every_guest_errno_reads_as_one_reason() {
        let limits = CoreLimits::parse(&caps(384 * MIB, 0x1f)).unwrap();
        let reason = |status: i32, flags: u32| {
            guest_reason(&CoreOutcome {
                state: 4,
                status,
                expected: 134_660_096,
                size: 66_834_432,
                stored: Some(64 * MIB),
                flags,
                budget: 64 * MIB,
                limits,
            })
        };
        let budget = reason(-27, 8).unwrap();
        assert_eq!(budget.code, CoreReasonCode::Budget);
        assert!(budget.text.contains("64 MiB") && budget.text.contains("66834432"));
        assert!(budget.text.contains("134660096") && budget.text.contains("384 MiB"));
        for (status, code) in [
            (-12, CoreReasonCode::GuestMemory),
            (-110, CoreReasonCode::Deadline),
            (-125, CoreReasonCode::Canceled),
            (-7, CoreReasonCode::Bounds),
            (-75, CoreReasonCode::Logical),
            (-61, CoreReasonCode::Coverage),
            (-4, CoreReasonCode::Interrupted),
            (-5, CoreReasonCode::Writer),
        ] {
            assert_eq!(reason(status, 8).unwrap().code, code, "{status}");
        }
        assert_eq!(reason(0, 8).unwrap().code, CoreReasonCode::Coverage);
        assert!(reason(0, 0).is_none());
        let old = guest_reason(&CoreOutcome {
            state: 4,
            status: -12,
            expected: 1,
            size: 1,
            stored: None,
            flags: 8,
            budget: 64 * MIB,
            limits: CoreLimits::LEGACY,
        })
        .unwrap();
        assert_eq!(old.code, CoreReasonCode::Writer);
    }
}
