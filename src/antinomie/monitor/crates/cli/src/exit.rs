// SPDX-License-Identifier: GPL-3.0-only
//! The exit codes of `antinomie-cli` (design 3.3). The numbers are part of the
//! contract: scripts and CI steps gate on them.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Ok,
    Failed,
    Usage,
    NotFound,
    Invalid,
    Denied,
    JobFailed,
    JobPartial,
    JobCancelled,
    JobRejected,
    WaitTimeout,
    Dependency,
    Busy,
    Quota,
    Suspicious,
    Malicious,
    Inconclusive,
    Interrupted,
}

impl Exit {
    /// Every code, in table order.
    pub const ALL: [Exit; 18] = [
        Exit::Ok,
        Exit::Failed,
        Exit::Usage,
        Exit::NotFound,
        Exit::Invalid,
        Exit::Denied,
        Exit::JobFailed,
        Exit::JobPartial,
        Exit::JobCancelled,
        Exit::JobRejected,
        Exit::WaitTimeout,
        Exit::Dependency,
        Exit::Busy,
        Exit::Quota,
        Exit::Suspicious,
        Exit::Malicious,
        Exit::Inconclusive,
        Exit::Interrupted,
    ];

    pub const fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::Failed => 1,
            Exit::Usage => 2,
            Exit::NotFound => 3,
            Exit::Invalid => 4,
            Exit::Denied => 5,
            Exit::JobFailed => 10,
            Exit::JobPartial => 11,
            Exit::JobCancelled => 12,
            Exit::JobRejected => 13,
            Exit::WaitTimeout => 14,
            Exit::Dependency => 20,
            Exit::Busy => 21,
            Exit::Quota => 22,
            Exit::Suspicious => 30,
            Exit::Malicious => 31,
            Exit::Inconclusive => 32,
            Exit::Interrupted => 130,
        }
    }

    /// The name used in the design's table and in documentation.
    pub const fn name(self) -> &'static str {
        match self {
            Exit::Ok => "ok",
            Exit::Failed => "failed",
            Exit::Usage => "usage",
            Exit::NotFound => "not_found",
            Exit::Invalid => "invalid",
            Exit::Denied => "denied",
            Exit::JobFailed => "job_failed",
            Exit::JobPartial => "job_partial",
            Exit::JobCancelled => "job_cancelled",
            Exit::JobRejected => "job_rejected",
            Exit::WaitTimeout => "wait_timeout",
            Exit::Dependency => "dependency",
            Exit::Busy => "busy",
            Exit::Quota => "quota",
            Exit::Suspicious => "suspicious",
            Exit::Malicious => "malicious",
            Exit::Inconclusive => "inconclusive",
            Exit::Interrupted => "interrupted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers of design 3.3, spelled out so a change cannot pass quietly.
    #[test]
    fn codes_match_the_design_table() {
        let table: [(Exit, u8, &str); 18] = [
            (Exit::Ok, 0, "ok"),
            (Exit::Failed, 1, "failed"),
            (Exit::Usage, 2, "usage"),
            (Exit::NotFound, 3, "not_found"),
            (Exit::Invalid, 4, "invalid"),
            (Exit::Denied, 5, "denied"),
            (Exit::JobFailed, 10, "job_failed"),
            (Exit::JobPartial, 11, "job_partial"),
            (Exit::JobCancelled, 12, "job_cancelled"),
            (Exit::JobRejected, 13, "job_rejected"),
            (Exit::WaitTimeout, 14, "wait_timeout"),
            (Exit::Dependency, 20, "dependency"),
            (Exit::Busy, 21, "busy"),
            (Exit::Quota, 22, "quota"),
            (Exit::Suspicious, 30, "suspicious"),
            (Exit::Malicious, 31, "malicious"),
            (Exit::Inconclusive, 32, "inconclusive"),
            (Exit::Interrupted, 130, "interrupted"),
        ];
        assert_eq!(table.len(), Exit::ALL.len());
        for ((exit, code, name), listed) in table.iter().zip(Exit::ALL) {
            assert_eq!(*exit, listed);
            assert_eq!(exit.code(), *code);
            assert_eq!(exit.name(), *name);
        }
    }

    #[test]
    fn codes_are_unique() {
        let mut codes: Vec<u8> = Exit::ALL.iter().map(|exit| exit.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), Exit::ALL.len());
    }
}
