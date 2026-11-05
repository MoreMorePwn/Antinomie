// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Who sent the signal that ended a task, as a revision-21 guest records it
//! in the task-exit record beside the wait status (`lifecycle.signal.*`,
//! `lifecycle.kernel_log`).
//!
//! The guest keeps one record per thread group: taken when the signal was
//! sent if the send started the group exit (SIGKILL, a fatal signal nothing
//! catches), else when the fatal signal was delivered. `code`, `pid` and
//! `uid` are the `siginfo_t` members as the task would have read them; the
//! sender is the task whose call sent the signal, by its global TGID, and is
//! known only for a send by a call (`kill`, `tkill`, `tgkill`,
//! `rt_sigqueueinfo`, `pidfd_send_signal` and the kernel's sends on behalf of
//! the task's own call, such as SIGPIPE). The OOM killer's SIGKILL carries the
//! line the kernel logged for the kill. Older guests record none of this.
use crate::FieldSummary;
use serde::{Deserialize, Serialize};

/// `si_code` values the explanation names (`include/uapi/asm-generic/siginfo.h`).
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
pub const SI_QUEUE: i32 = -1;
pub const SI_TIMER: i32 = -2;
pub const SI_TKILL: i32 = -6;

/// The task whose call sent the signal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalSender {
    /// Its thread group ID in the guest's initial PID namespace.
    pub pid: u32,
    /// Its real UID in the initial user namespace.
    pub uid: u32,
    /// Its `comm` when it sent the signal (at most 15 bytes).
    pub comm: String,
}

/// The fatal signal of a task-exit record and what the guest knows of its origin.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatalSignal {
    pub signal: u8,
    /// `si_code` as the task would have read it.
    pub code: i32,
    /// `si_pid` and `si_uid`, zero where `si_code`'s layout has none.
    pub pid: i32,
    pub uid: u32,
    /// Recorded when the signal was sent (true) or when it was delivered.
    pub at_send: bool,
    pub sender: Option<SignalSender>,
    /// The kernel's out-of-memory killer sent it.
    pub oom: bool,
    /// The kernel's log line for the kill ("Out of memory: Killed process ...").
    pub kernel_log: Option<String>,
}

fn scalar(fields: &[FieldSummary], key: &str) -> Option<u64> {
    let field = fields.iter().find(|field| field.key == key)?;
    Some(u64::from_le_bytes(field.preview.get(..8)?.try_into().ok()?))
}

fn text(fields: &[FieldSummary], key: &str) -> Option<String> {
    let field = fields.iter().find(|field| field.key == key)?;
    let bytes = field
        .preview
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

impl FatalSignal {
    /// The record in the fields of a task-exit event, when the guest wrote one.
    pub fn from_fields(fields: &[FieldSummary]) -> Option<Self> {
        let signal = u8::try_from(scalar(fields, "lifecycle.signal.signo")?).ok()?;
        if !(1..=64).contains(&signal) {
            return None;
        }
        let sender = scalar(fields, "lifecycle.signal.sender_pid")
            .filter(|pid| *pid != 0)
            .map(|pid| SignalSender {
                pid: pid as u32,
                uid: scalar(fields, "lifecycle.signal.sender_uid").unwrap_or_default() as u32,
                comm: text(fields, "lifecycle.signal.sender_comm").unwrap_or_default(),
            });
        Some(Self {
            signal,
            code: scalar(fields, "lifecycle.signal.code").unwrap_or_default() as i32,
            pid: scalar(fields, "lifecycle.signal.pid").unwrap_or_default() as i32,
            uid: scalar(fields, "lifecycle.signal.uid").unwrap_or_default() as u32,
            at_send: scalar(fields, "lifecycle.signal.origin") == Some(1),
            sender,
            oom: scalar(fields, "lifecycle.signal.oom") == Some(1),
            kernel_log: text(fields, "lifecycle.kernel_log").filter(|line| !line.is_empty()),
        })
    }

    /// The kernel itself sent it: the OOM killer, a resource limit, a fault
    /// it delivers as a signal, or any other send without a sending task.
    pub fn from_kernel(&self) -> bool {
        self.oom || self.code == SI_KERNEL || (self.code > 0 && self.sender.is_none())
    }

    /// A signal the kernel raised for the task's own action (a positive
    /// `si_code`): the code's name and what it means, as "SEGV_MAPERR, an
    /// access to unmapped memory".
    pub fn fault(&self) -> Option<String> {
        if self.code <= 0 || self.code == SI_KERNEL {
            return None;
        }
        let (name, what) = match (self.signal, self.code) {
            (11, 1) => ("SEGV_MAPERR", "an access to unmapped memory"),
            (11, 2) => ("SEGV_ACCERR", "an access its mapping does not allow"),
            (11, _) => ("SEGV", "a memory access fault"),
            (7, 1) => ("BUS_ADRALN", "a misaligned access"),
            (7, 2) => ("BUS_ADRERR", "an access past the end of a mapped file"),
            (7, _) => ("BUS", "a bus error"),
            (4, _) => ("ILL", "an illegal instruction"),
            (8, 1) => ("FPE_INTDIV", "an integer division by zero"),
            (8, _) => ("FPE", "an arithmetic fault"),
            (5, 1) => ("TRAP_BRKPT", "a breakpoint instruction"),
            (5, 2) => ("TRAP_TRACE", "a single step"),
            (5, _) => ("TRAP", "a trap"),
            (31, 1) => ("SYS_SECCOMP", "a system call its seccomp filter kills"),
            (31, _) => ("SYS", "a bad system call"),
            _ => return Some(format!("si_code {}", self.code)),
        };
        Some(format!("{name}, {what}"))
    }

    /// `si_code` in words.
    pub fn code_name(&self) -> String {
        match self.code {
            SI_USER => "SI_USER".into(),
            SI_KERNEL => "SI_KERNEL".into(),
            SI_QUEUE => "SI_QUEUE".into(),
            SI_TIMER => "SI_TIMER".into(),
            -3 => "SI_MESGQ".into(),
            -4 => "SI_ASYNCIO".into(),
            -5 => "SI_SIGIO".into(),
            SI_TKILL => "SI_TKILL".into(),
            other => format!("si_code {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: &str, preview: Vec<u8>) -> FieldSummary {
        FieldSummary {
            arg: None,
            object_id: 1,
            key: key.into(),
            layout: String::new(),
            logical_len: Some(preview.len() as u64),
            captured_len: preview.len() as u64,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview,
            raw_path: None,
            ranges: Vec::new(),
            recapture: None,
            encoding: None,
        }
    }

    fn number(key: &str, value: i64) -> FieldSummary {
        field(key, value.to_le_bytes().to_vec())
    }

    #[test]
    fn a_kill_by_another_process_names_it() {
        let fields = [
            number("lifecycle.task_exit", 9),
            number("lifecycle.signal.signo", 9),
            number("lifecycle.signal.code", 0),
            number("lifecycle.signal.pid", 812),
            number("lifecycle.signal.uid", 1000),
            number("lifecycle.signal.origin", 1),
            number("lifecycle.signal.sender_pid", 812),
            number("lifecycle.signal.sender_uid", 1000),
            field("lifecycle.signal.sender_comm", b"killer".to_vec()),
        ];
        let fatal = FatalSignal::from_fields(&fields).unwrap();
        assert_eq!(fatal.signal, 9);
        assert!(fatal.at_send);
        assert!(!fatal.from_kernel());
        assert_eq!(
            fatal.sender,
            Some(SignalSender {
                pid: 812,
                uid: 1000,
                comm: "killer".into()
            })
        );
        assert_eq!(fatal.code_name(), "SI_USER");
    }

    #[test]
    fn the_oom_killer_is_the_kernel_with_its_log_line() {
        let fields = [
            number("lifecycle.signal.signo", 9),
            number("lifecycle.signal.code", 0x80),
            number("lifecycle.signal.pid", 0),
            number("lifecycle.signal.uid", 0),
            number("lifecycle.signal.origin", 1),
            number("lifecycle.signal.oom", 1),
            field(
                "lifecycle.kernel_log",
                b"Memory cgroup out of memory: Killed process 77 (hog)".to_vec(),
            ),
        ];
        let fatal = FatalSignal::from_fields(&fields).unwrap();
        assert!(fatal.oom && fatal.from_kernel() && fatal.sender.is_none());
        assert_eq!(
            fatal.kernel_log.as_deref(),
            Some("Memory cgroup out of memory: Killed process 77 (hog)")
        );
    }

    #[test]
    fn a_negative_code_survives_and_an_old_record_has_none() {
        let fields = [
            number("lifecycle.signal.signo", 11),
            number("lifecycle.signal.code", -6),
            number("lifecycle.signal.origin", 2),
        ];
        let fatal = FatalSignal::from_fields(&fields).unwrap();
        assert_eq!(fatal.code, SI_TKILL);
        assert_eq!(fatal.fault(), None);
        let segv = FatalSignal {
            signal: 11,
            code: 1,
            ..Default::default()
        };
        assert_eq!(
            segv.fault().as_deref(),
            Some("SEGV_MAPERR, an access to unmapped memory")
        );
        assert!(!fatal.at_send);
        assert!(FatalSignal::from_fields(&[number("lifecycle.task_exit", 9)]).is_none());
        assert!(FatalSignal::from_fields(&[number("lifecycle.signal.signo", 0)]).is_none());
    }
}
