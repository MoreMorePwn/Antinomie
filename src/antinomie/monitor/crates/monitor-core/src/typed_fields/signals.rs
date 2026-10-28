// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Signal layouts: `sigset_t` (one bit per signal, bit 0 = signal 1),
//! pselect6's sigset pack, `siginfo_t` (128 bytes; the union at offset 16 by
//! the kernel's `siginfo_layout()`), `struct sigevent` (64 bytes; the union at
//! 16 by `sigev_notify`) and `stack_t` (24 bytes). Offsets are the 64-bit
//! UAPI's (`asm-generic/siginfo.h`, `asm-generic/signal.h`).
use super::{Decoded, Shape, flags, i32_at, i64_at, named, pointer, u32_at, u64_at};

/// A signal number by name: `SIGTERM`, `SIG34` for real-time ones, the number
/// itself for 0 and anything past 64.
pub fn signal_name(number: u64) -> String {
    match u8::try_from(number) {
        Ok(number @ 1..=64) => crate::debug::signal_policy::signal_name(number),
        _ => number.to_string(),
    }
}

/// The signals in a set, by name; more than half of them set reads as the
/// complement, `~[SIGKILL SIGSTOP]`. A 4-byte set (rt_sigpending's short size)
/// holds signals 1-32.
pub(super) fn sigset(data: &[u8]) -> Option<Decoded> {
    let bits = match data.len() {
        8.. => 64,
        4..=7 => 32,
        _ => return None,
    };
    let mask = if bits == 64 {
        u64_at(data, 0)?
    } else {
        u64::from(u32_at(data, 0)?)
    };
    let set = mask.count_ones();
    let complement = set * 2 > bits;
    let mut decoded = Decoded::new(Shape::Set);
    decoded.complement = complement;
    for signal in 1..=u64::from(bits) {
        if (mask >> (signal - 1)) & 1 == u64::from(!complement) {
            decoded.push("", signal_name(signal));
        }
    }
    Some(decoded)
}

/// pselect6's sixth argument: `{const sigset_t *ss; size_t ss_len}`.
pub(super) fn argpack(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("ss", pointer(u64_at(data, 0)?));
    decoded.push("ss_len", u64_at(data, 8)?.to_string());
    Some(decoded)
}

const SI_CODES: &[(&str, i64)] = &[
    ("SI_USER", 0),
    ("SI_KERNEL", 0x80),
    ("SI_QUEUE", -1),
    ("SI_TIMER", -2),
    ("SI_MESGQ", -3),
    ("SI_ASYNCIO", -4),
    ("SI_SIGIO", -5),
    ("SI_TKILL", -6),
    ("SI_DETHREAD", -7),
    ("SI_ASYNCNL", -60),
];
const ILL_CODES: &[&str] = &[
    "ILL_ILLOPC",
    "ILL_ILLOPN",
    "ILL_ILLADR",
    "ILL_ILLTRP",
    "ILL_PRVOPC",
    "ILL_PRVREG",
    "ILL_COPROC",
    "ILL_BADSTK",
    "ILL_BADIADDR",
    "__ILL_BREAK",
    "__ILL_BNDMOD",
];
const FPE_CODES: &[&str] = &[
    "FPE_INTDIV",
    "FPE_INTOVF",
    "FPE_FLTDIV",
    "FPE_FLTOVF",
    "FPE_FLTUND",
    "FPE_FLTRES",
    "FPE_FLTINV",
    "FPE_FLTSUB",
    "__FPE_DECOVF",
    "__FPE_DECDIV",
    "__FPE_DECERR",
    "__FPE_INVASC",
    "__FPE_INVDEC",
    "FPE_FLTUNK",
    "FPE_CONDTRAP",
];
const SEGV_CODES: &[&str] = &[
    "SEGV_MAPERR",
    "SEGV_ACCERR",
    "SEGV_BNDERR",
    "SEGV_PKUERR",
    "SEGV_ACCADI",
    "SEGV_ADIDERR",
    "SEGV_ADIPERR",
    "SEGV_MTEAERR",
    "SEGV_MTESERR",
    "SEGV_CPERR",
];
const BUS_CODES: &[&str] = &[
    "BUS_ADRALN",
    "BUS_ADRERR",
    "BUS_OBJERR",
    "BUS_MCEERR_AR",
    "BUS_MCEERR_AO",
];
const TRAP_CODES: &[&str] = &[
    "TRAP_BRKPT",
    "TRAP_TRACE",
    "TRAP_BRANCH",
    "TRAP_HWBKPT",
    "TRAP_UNK",
    "TRAP_PERF",
];
const CLD_CODES: &[&str] = &[
    "CLD_EXITED",
    "CLD_KILLED",
    "CLD_DUMPED",
    "CLD_TRAPPED",
    "CLD_STOPPED",
    "CLD_CONTINUED",
];
const POLL_CODES: &[&str] = &[
    "POLL_IN", "POLL_OUT", "POLL_MSG", "POLL_ERR", "POLL_PRI", "POLL_HUP",
];
const SYS_CODES: &[&str] = &["SYS_SECCOMP", "SYS_USER_DISPATCH"];

const SIGILL: i32 = 4;
const SIGTRAP: i32 = 5;
const SIGBUS: i32 = 7;
const SIGFPE: i32 = 8;
const SIGSEGV: i32 = 11;
const SIGCHLD: i32 = 17;
const SIGPOLL: i32 = 29;
const SIGSYS: i32 = 31;

/// The `si_code` names a signal defines for codes 1 and up.
fn signal_codes(signo: i32) -> &'static [&'static str] {
    match signo {
        SIGILL => ILL_CODES,
        SIGFPE => FPE_CODES,
        SIGSEGV => SEGV_CODES,
        SIGBUS => BUS_CODES,
        SIGTRAP => TRAP_CODES,
        SIGCHLD => CLD_CODES,
        SIGPOLL => POLL_CODES,
        SIGSYS => SYS_CODES,
        _ => &[],
    }
}

fn si_code_name(signo: i32, code: i32) -> String {
    if let Some((name, _)) = SI_CODES.iter().find(|(_, value)| *value == i64::from(code)) {
        return (*name).to_owned();
    }
    usize::try_from(code)
        .ok()
        .and_then(|code| code.checked_sub(1))
        .and_then(|index| signal_codes(signo).get(index))
        .map_or_else(|| code.to_string(), |name| (*name).to_owned())
}

/// The union branch of a siginfo, as the kernel's `siginfo_layout()` picks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Branch {
    Kill,
    Timer,
    Rt,
    Chld,
    Fault,
    FaultMceErr,
    FaultBndErr,
    FaultPkuErr,
    FaultPerf,
    Poll,
    Sys,
}

fn branch(signo: i32, code: i32) -> Branch {
    const SI_USER: i32 = 0;
    const SI_KERNEL: i32 = 0x80;
    const SI_TIMER: i32 = -2;
    const SI_SIGIO: i32 = -5;
    if code > SI_USER && code < SI_KERNEL {
        let (limit, kind) = match signo {
            SIGILL | SIGFPE | SIGSEGV | SIGBUS | SIGTRAP => {
                (signal_codes(signo).len(), Branch::Fault)
            }
            SIGCHLD => (CLD_CODES.len(), Branch::Chld),
            SIGPOLL => (POLL_CODES.len(), Branch::Poll),
            SIGSYS => (SYS_CODES.len(), Branch::Sys),
            _ => (0, Branch::Kill),
        };
        let code_index = usize::try_from(code).unwrap_or(usize::MAX);
        if limit > 0 && code_index <= limit {
            return match (signo, code) {
                (SIGBUS, 4 | 5) => Branch::FaultMceErr,
                (SIGSEGV, 3) => Branch::FaultBndErr,
                (SIGSEGV, 4) => Branch::FaultPkuErr,
                (SIGTRAP, 6) => Branch::FaultPerf,
                _ => kind,
            };
        }
        // NSIGPOLL: a code no signal defines this far reads as poll.
        return if code_index <= POLL_CODES.len() {
            Branch::Poll
        } else {
            Branch::Kill
        };
    }
    match code {
        SI_TIMER => Branch::Timer,
        SI_SIGIO => Branch::Poll,
        code if code < 0 => Branch::Rt,
        _ => Branch::Kill,
    }
}

const POLL_BANDS: &[(&str, u64)] = &[
    ("POLLIN", 0x1),
    ("POLLPRI", 0x2),
    ("POLLOUT", 0x4),
    ("POLLERR", 0x8),
    ("POLLHUP", 0x10),
    ("POLLNVAL", 0x20),
    ("POLLRDNORM", 0x40),
    ("POLLRDBAND", 0x80),
    ("POLLWRNORM", 0x100),
    ("POLLWRBAND", 0x200),
    ("POLLMSG", 0x400),
];
const AUDIT_ARCHES: &[(&str, u64)] = &[
    ("AUDIT_ARCH_X86_64", 0xc000_003e),
    ("AUDIT_ARCH_I386", 0x4000_0003),
    ("AUDIT_ARCH_AARCH64", 0xc000_00b7),
    ("AUDIT_ARCH_ARM", 0x4000_0028),
    ("AUDIT_ARCH_RISCV64", 0xc000_00f3),
];

/// A `siginfo_t`: `si_signo`, `si_errno` when set, `si_code`, then the
/// members of the branch the signal and code select.
pub(super) fn siginfo(data: &[u8]) -> Option<Decoded> {
    let signo = i32_at(data, 0)?;
    let errno = i32_at(data, 4)?;
    let code = i32_at(data, 8)?;
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push(
        "si_signo",
        signal_name(u64::try_from(signo).unwrap_or(u64::MAX)),
    );
    if errno != 0 {
        decoded.push("si_errno", errno.to_string());
    }
    decoded.push("si_code", si_code_name(signo, code));
    // The members a short capture lacks are left out.
    let _ = branch_members(&mut decoded, data, signo, code);
    Some(decoded)
}

fn pid_uid(decoded: &mut Decoded, data: &[u8]) -> Option<()> {
    decoded.push("si_pid", i32_at(data, 16)?.to_string());
    decoded.push("si_uid", u32_at(data, 20)?.to_string());
    Some(())
}

/// The members of the union branch `signo` and `code` select.
fn branch_members(decoded: &mut Decoded, data: &[u8], signo: i32, code: i32) -> Option<()> {
    match branch(signo, code) {
        Branch::Kill => pid_uid(decoded, data)?,
        Branch::Rt => {
            pid_uid(decoded, data)?;
            decoded.push("si_value", pointer(u64_at(data, 24)?));
        }
        Branch::Timer => {
            decoded.push("si_timerid", i32_at(data, 16)?.to_string());
            decoded.push("si_overrun", i32_at(data, 20)?.to_string());
            decoded.push("si_value", pointer(u64_at(data, 24)?));
        }
        Branch::Chld => {
            pid_uid(decoded, data)?;
            let status = i32_at(data, 24)?;
            // CLD_EXITED carries the exit status, the others a signal.
            decoded.push(
                "si_status",
                if code == 1 {
                    status.to_string()
                } else {
                    signal_name(u64::try_from(status).unwrap_or(u64::MAX))
                },
            );
            decoded.push("si_utime", i64_at(data, 32)?.to_string());
            decoded.push("si_stime", i64_at(data, 40)?.to_string());
        }
        kind @ (Branch::Fault
        | Branch::FaultMceErr
        | Branch::FaultBndErr
        | Branch::FaultPkuErr
        | Branch::FaultPerf) => {
            decoded.push("si_addr", pointer(u64_at(data, 16)?));
            match kind {
                Branch::FaultMceErr => {
                    decoded.push("si_addr_lsb", i32_at(data, 24)?.to_string());
                }
                Branch::FaultBndErr => {
                    decoded.push("si_lower", pointer(u64_at(data, 32)?));
                    decoded.push("si_upper", pointer(u64_at(data, 40)?));
                }
                Branch::FaultPkuErr => decoded.push("si_pkey", u32_at(data, 32)?.to_string()),
                Branch::FaultPerf => {
                    decoded.push("si_perf_data", format!("{:#x}", u64_at(data, 24)?));
                    decoded.push("si_perf_type", u32_at(data, 32)?.to_string());
                    decoded.push("si_perf_flags", format!("{:#x}", u32_at(data, 36)?));
                }
                _ => {}
            }
        }
        Branch::Poll => {
            let band = u64::try_from(i64_at(data, 16)?).unwrap_or(u64::MAX);
            decoded.push("si_band", flags(band, POLL_BANDS));
            decoded.push("si_fd", i32_at(data, 24)?.to_string());
        }
        Branch::Sys => {
            decoded.push("si_call_addr", pointer(u64_at(data, 16)?));
            let syscall = i32_at(data, 24)?;
            decoded.push(
                "si_syscall",
                u64::try_from(syscall)
                    .ok()
                    .and_then(crate::syscalls::known_name)
                    .map_or_else(|| syscall.to_string(), str::to_owned),
            );
            decoded.push("si_arch", {
                let arch = u64::from(u32_at(data, 28)?);
                let name = named(arch, AUDIT_ARCHES);
                if name == arch.to_string() {
                    format!("{arch:#x}")
                } else {
                    name
                }
            });
        }
    }
    Some(())
}

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;

/// A `struct sigevent`: how to notify, then what the `sigev_notify` branch
/// uses. Through a system call SIGEV_THREAD is mq_notify's netlink form:
/// `sigev_signo` is then a socket descriptor, not a signal.
pub(super) fn sigevent(data: &[u8]) -> Option<Decoded> {
    let value = u64_at(data, 0)?;
    let signo = i32_at(data, 8)?;
    let notify = i32_at(data, 12)?;
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push(
        "sigev_notify",
        match notify {
            SIGEV_SIGNAL => "SIGEV_SIGNAL".to_owned(),
            SIGEV_NONE => "SIGEV_NONE".to_owned(),
            SIGEV_THREAD => "SIGEV_THREAD".to_owned(),
            SIGEV_THREAD_ID => "SIGEV_THREAD_ID".to_owned(),
            other => other.to_string(),
        },
    );
    match notify {
        SIGEV_NONE => {}
        SIGEV_THREAD => {
            decoded.push("sigev_signo", signo.to_string());
            decoded.push("sigev_value", pointer(value));
            if let (Some(function), Some(attributes)) = (u64_at(data, 16), u64_at(data, 24)) {
                decoded.push("sigev_notify_function", pointer(function));
                decoded.push("sigev_notify_attributes", pointer(attributes));
            }
        }
        _ => {
            decoded.push(
                "sigev_signo",
                signal_name(u64::try_from(signo).unwrap_or(u64::MAX)),
            );
            decoded.push("sigev_value", pointer(value));
            if notify == SIGEV_THREAD_ID
                && let Some(tid) = i32_at(data, 16)
            {
                decoded.push("sigev_notify_thread_id", tid.to_string());
            }
        }
    }
    Some(decoded)
}

const SS_FLAGS: &[(&str, u64)] = &[
    ("SS_ONSTACK", 1),
    ("SS_DISABLE", 2),
    ("SS_AUTODISARM", 1 << 31),
];

/// A `stack_t`: the alternate stack's base, flags and size.
pub(super) fn stack(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("ss_sp", pointer(u64_at(data, 0)?));
    decoded.push("ss_flags", flags(u64::from(u32_at(data, 8)?), SS_FLAGS));
    decoded.push("ss_size", u64_at(data, 16)?.to_string());
    Some(decoded)
}
