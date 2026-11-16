// SPDX-License-Identifier: GPL-3.0-only
//! The process's open-file limit (`RLIMIT_NOFILE`).
//!
//! A daemon with several lanes keeps every lane's engine in one process: the
//! VMs' network gateways, recordings, host tools and the job store all share
//! one descriptor table. Many distributions start a user process with a soft
//! limit of 1,024 while the hard limit is far higher, so the service and the
//! command line's direct mode raise their soft limit at start ([`raise`]),
//! and `doctor` reports a hard limit too low to raise it to [`WANTED`].
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

/// The soft limit a long-running front end raises itself to (or to the hard
/// limit, when that is lower).
pub const WANTED: u64 = 65_536;

/// A soft limit below this is called low by `doctor` and the daemon's log.
pub const LOW: u64 = 4_096;

/// The limit before and after [`raise`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Raised {
    /// The soft limit the process started with.
    pub before: u64,
    /// The soft limit now.
    pub after: u64,
    /// The hard limit (`None`: unlimited).
    pub hard: Option<u64>,
}

impl Raised {
    /// One line for a log: what the limit was and is.
    pub fn words(&self) -> String {
        let hard = self
            .hard
            .map_or_else(|| "unlimited".to_owned(), |hard| hard.to_string());
        if self.after > self.before {
            format!(
                "open-file limit raised from {} to {} (hard limit {hard})",
                self.before, self.after
            )
        } else {
            format!("open-file limit {} (hard limit {hard})", self.after)
        }
    }

    /// Whether the limit is still below [`LOW`] after the raise.
    pub fn low(&self) -> bool {
        self.after < LOW
    }
}

/// The soft and hard limit now.
pub fn limits() -> (Option<u64>, Option<u64>) {
    let limit = getrlimit(Resource::Nofile);
    (limit.current, limit.maximum)
}

/// The soft limit now (`None`: unlimited).
pub fn soft_limit() -> Option<u64> {
    limits().0
}

/// The soft limit `cap` would be raised to under the hard limit `hard`.
fn target(current: u64, hard: Option<u64>, cap: u64) -> u64 {
    let wanted = hard.map_or(cap, |hard| hard.min(cap));
    current.max(wanted)
}

/// Raise the soft limit to the hard limit, at most to `cap`; a soft limit
/// already above `cap` is left alone. Never lowers it.
pub fn raise(cap: u64) -> Result<Raised, String> {
    let (soft, hard) = limits();
    let Some(before) = soft else {
        return Ok(Raised {
            before: u64::MAX,
            after: u64::MAX,
            hard,
        });
    };
    let after = target(before, hard, cap);
    if after > before {
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(after),
                maximum: hard,
            },
        )
        .map_err(|error| format!("raising the open-file limit to {after}: {error}"))?;
    }
    Ok(Raised {
        before,
        after,
        hard,
    })
}

static AT_START: std::sync::OnceLock<Result<Raised, String>> = std::sync::OnceLock::new();

/// [`raise`] to [`WANTED`], once per process: the first call raises the
/// limit, every later one returns what that call did (for the daemon's log).
pub fn raise_at_start() -> Result<Raised, String> {
    AT_START.get_or_init(|| raise(WANTED)).clone()
}

/// How many descriptors the process has open (`/proc/self/fd`).
pub fn count() -> Option<u64> {
    let entries = std::fs::read_dir("/proc/self/fd").ok()?;
    // The directory handle itself is one of the entries.
    Some((entries.count() as u64).saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_is_the_hard_limit_up_to_the_cap_and_never_lower() {
        assert_eq!(target(1024, Some(524_288), WANTED), WANTED);
        assert_eq!(target(1024, Some(4096), WANTED), 4096);
        assert_eq!(target(1024, None, WANTED), WANTED);
        assert_eq!(target(100_000, Some(524_288), WANTED), 100_000);
        assert_eq!(target(1024, Some(1024), WANTED), 1024);
    }

    #[test]
    fn the_words_name_both_limits() {
        let raised = Raised {
            before: 1024,
            after: 65_536,
            hard: Some(524_288),
        };
        assert_eq!(
            raised.words(),
            "open-file limit raised from 1024 to 65536 (hard limit 524288)"
        );
        assert!(!raised.low());
        let kept = Raised {
            before: 1024,
            after: 1024,
            hard: Some(1024),
        };
        assert_eq!(kept.words(), "open-file limit 1024 (hard limit 1024)");
        assert!(kept.low());
    }

    #[test]
    fn count_reads_the_descriptor_table() {
        let _file = std::fs::File::open("/proc/self/stat").unwrap();
        assert!(count().unwrap() >= 1);
    }
}
