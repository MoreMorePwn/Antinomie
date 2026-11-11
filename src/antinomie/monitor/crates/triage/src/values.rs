// SPDX-License-Identifier: GPL-3.0-only
//! Syscall values shown by meaning: counts, sizes, descriptors, PIDs and
//! results in decimal; pointers, addresses and flags in hex; errors by name
//! (the number stays available on hover); captured strings without their
//! terminating NUL. File sizes read as the exact byte count with a rounded
//! 1024-based figure.
use crate::tone::ValueKind;
use antinomie_monitor_core::{syscalls, WaitStatus};

/// A value as the trace shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    pub text: String,
    pub kind: ValueKind,
    /// The plain number, when `text` names it instead (errors, AT_FDCWD,
    /// signals, decoded flags).
    pub raw: Option<String>,
}

impl Shown {
    pub fn new(text: impl Into<String>, kind: ValueKind) -> Self {
        Self {
            text: text.into(),
            kind,
            raw: None,
        }
    }

    pub fn named(text: impl Into<String>, kind: ValueKind, raw: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind,
            raw: Some(raw.into()),
        }
    }

    /// Hover text: the shown value and, when it is a name, its number.
    pub fn hover(&self) -> String {
        match &self.raw {
            Some(raw) => format!("{} = {raw}", self.text),
            None => self.text.clone(),
        }
    }
}

pub use antinomie_monitor_core::errno::errno_name;
use antinomie_monitor_core::errno::{ERRNO, KERNEL_ERRNO};

/// The errno number of a symbolic name (`EACCES` is 13).
pub fn errno_number(name: &str) -> Option<u64> {
    ERRNO
        .iter()
        .position(|candidate| !candidate.is_empty() && *candidate == name)
        .map(|index| index as u64)
        .or_else(|| {
            KERNEL_ERRNO
                .iter()
                .find(|(_, candidate, _)| *candidate == name)
                .map(|(number, ..)| *number)
        })
}

/// A failed call's result as an outcome reads: "failed (EACCES)", or the
/// number when it has no name.
pub fn failed_outcome(result: i64) -> String {
    match errno_name(result.unsigned_abs()) {
        Some(name) => format!("failed ({name})"),
        None => format!("failed ({result})"),
    }
}

/// The hover of an outcome cell "failed (EACCES)": the number and the words.
pub fn outcome_hover(text: &str) -> Option<String> {
    let name = text.strip_prefix("failed (")?.strip_suffix(')')?;
    let number = errno_number(name)?;
    let words = errno_description(number).unwrap_or_default();
    Some(
        format!("{name}: errno {number} (result -{number}) {words}")
            .trim_end()
            .to_owned(),
    )
}

/// What an errno means, in words ("No such file or directory").
pub fn errno_description(errno: u64) -> Option<String> {
    if let Some((.., text)) = KERNEL_ERRNO.iter().find(|(number, ..)| *number == errno) {
        return Some(format!("{text} (kernel internal)"));
    }
    errno_name(errno)?;
    // The guest is Linux, as is the host this app runs on: the C library
    // describes the same numbers.
    let text = std::io::Error::from_raw_os_error(i32::try_from(errno).ok()?).to_string();
    Some(match text.find(" (os error") {
        Some(end) => text[..end].to_owned(),
        None => text,
    })
}

/// A raw syscall return that encodes an error (`-4095..=-1`).
pub fn is_error(result: i64) -> bool {
    (-4095..0).contains(&result)
}

/// Syscalls whose successful return is an address.
pub fn returns_address(nr: u64) -> bool {
    matches!(
        syscalls::known_name(nr),
        Some("mmap" | "brk" | "mremap" | "shmat")
    )
}

/// A syscall return value by meaning: an error by name, an address in hex,
/// anything else (counts, descriptors, PIDs) in decimal.
pub fn result(nr: u64, result: i64) -> Shown {
    if is_error(result) {
        let errno = result.unsigned_abs();
        return match errno_name(errno) {
            Some(name) => Shown::named(name, ValueKind::Error, result.to_string()),
            None => Shown::new(result.to_string(), ValueKind::Error),
        };
    }
    if returns_address(nr) {
        return Shown::new(format!("{:#x}", result as u64), ValueKind::Pointer);
    }
    Shown::new(result.to_string(), ValueKind::Number)
}

/// Hover text of a return value: its number and, for an error, what it means.
pub fn result_hover(nr: u64, value: i64) -> String {
    let shown = result(nr, value);
    if is_error(value) {
        let errno = value.unsigned_abs();
        let mut text = format!("{} = {value}", shown.text);
        if let Some(description) = errno_description(errno) {
            text.push_str(&format!("\n{description}"));
        }
        return text;
    }
    shown.hover()
}

/// How a task ended: "exit 1", or "killed by SIGKILL" with "(core dumped)".
pub fn task_end(status: &WaitStatus) -> String {
    match *status {
        WaitStatus::Exited { code } => format!("exit {code}"),
        WaitStatus::Signaled {
            signal,
            core_dumped,
        } => format!(
            "killed by {}{}",
            SIGNALS
                .get(usize::from(signal))
                .filter(|_| signal != 0)
                .map_or_else(|| format!("signal {signal}"), |name| (*name).to_owned()),
            if core_dumped { " (core dumped)" } else { "" }
        ),
    }
}

pub const SIGNALS: [&str; 32] = [
    "0",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGBUS",
    "SIGFPE",
    "SIGKILL",
    "SIGUSR1",
    "SIGSEGV",
    "SIGUSR2",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGSTKFLT",
    "SIGCHLD",
    "SIGCONT",
    "SIGSTOP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "SIGIO",
    "SIGPWR",
    "SIGSYS",
];

/// How an argument's number reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Meaning {
    Pointer,
    Flags,
    Hex,
    Mode,
    Descriptor,
    Signal,
    Signed32,
    Signed64,
    Unsigned32,
    Unsigned,
}

pub fn meaning(nr: u64, index: usize) -> Meaning {
    let Some(info) = syscalls::syscall(nr) else {
        return Meaning::Unsigned;
    };
    let Some(argument) = info.arguments.get(index) else {
        return Meaning::Unsigned;
    };
    let name = argument.name.as_str();
    let c_type = argument.c_type.as_str();
    if argument.pointer {
        return Meaning::Pointer;
    }
    if argument.flags.is_some() {
        return Meaning::Flags;
    }
    if name == "fd" || name.ends_with("fd") || name.starts_with("fd_") {
        return Meaning::Descriptor;
    }
    if c_type == "umode_t" || name == "mode" {
        return Meaning::Mode;
    }
    if matches!(name, "sig" | "signal" | "signum") {
        return Meaning::Signal;
    }
    // ioctl requests encode direction, size and type in their bits.
    if info.name == "ioctl" && name == "cmd" {
        return Meaning::Hex;
    }
    // An address, not its length (addrlen, addr_len).
    if (name.contains("addr") && !name.ends_with("len"))
        || matches!(
            name,
            "brk" | "start" | "newsp" | "tls" | "stack" | "address" | "ptr" | "uaddr" | "uaddr2"
        )
    {
        return Meaning::Pointer;
    }
    match c_type {
        "int" | "pid_t" | "clockid_t" | "key_t" | "timer_t" | "mqd_t" | "key_serial_t" => {
            Meaning::Signed32
        }
        "loff_t" => Meaning::Signed64,
        // long and the kernel's off_t follow the data model (ILP32: 32 bits).
        "long" | "off_t" => match syscalls::table_of(nr)
            .unwrap_or(syscalls::native())
            .constants()
            .data_model
        {
            syscalls::DataModel::Lp64 => Meaning::Signed64,
            syscalls::DataModel::Ilp32 => Meaning::Signed32,
        },
        "unsigned int" | "u32" | "__u32" | "uint32_t" | "uid_t" | "gid_t" | "qid_t" => {
            Meaning::Unsigned32
        }
        _ => Meaning::Unsigned,
    }
}

/// Conventional role of a standard descriptor; its target can be redirected.
pub fn standard_fd_name(fd: u64) -> Option<&'static str> {
    match fd {
        0 => Some("stdin"),
        1 => Some("stdout"),
        2 => Some("stderr"),
        _ => None,
    }
}

/// Whether `prctl`'s `arg2` is a user pointer for this option. The table types
/// it `unsigned long` because most options pass a number there; these pass a
/// `char *` (`PR_SET_NAME`, `PR_GET_NAME`) or the address of an `int` or
/// `unsigned long` the kernel writes (`PR_GET_PDEATHSIG`, `PR_GET_UNALIGN`,
/// `PR_GET_FPEMU`, `PR_GET_FPEXC`, `PR_GET_ENDIAN`, `PR_GET_TSC`,
/// `PR_GET_CHILD_SUBREAPER`, `PR_GET_TID_ADDRESS`, `PR_GET_AUXV`).
fn prctl_pointer(nr: u64, index: usize, args: &[u64; 6]) -> bool {
    const POINTER_OPTIONS: [u32; 11] = [2, 5, 9, 11, 15, 16, 19, 25, 37, 40, 0x4155_5856];
    index == 1
        && syscalls::syscall(nr).is_some_and(|info| info.name == "prctl")
        && POINTER_OPTIONS.contains(&(args[0] as u32))
}

/// Argument `index` of syscall `nr` by meaning. `args` gives the other
/// arguments some values depend on (socket option names by level, the
/// pointer `prctl` takes for some options).
pub fn argument(nr: u64, index: usize, args: &[u64; 6]) -> Shown {
    let value = args[index];
    if let Some(name) = syscalls::selector_name(nr, index, args) {
        return Shown::named(name, ValueKind::Flags, format!("{value:#x}"));
    }
    let meaning = if prctl_pointer(nr, index, args) {
        Meaning::Pointer
    } else {
        meaning(nr, index)
    };
    match meaning {
        Meaning::Pointer if value == 0 => Shown::new("NULL", ValueKind::Pointer),
        Meaning::Pointer => Shown::new(format!("{value:#x}"), ValueKind::Pointer),
        Meaning::Flags => flags(nr, index, value),
        Meaning::Hex => Shown::new(format!("{value:#x}"), ValueKind::Flags),
        Meaning::Mode if value & 0o7777 == 0 => Shown::new("0", ValueKind::Number),
        Meaning::Mode => Shown::new(format!("0{:o}", value & 0o7777), ValueKind::Number),
        Meaning::Descriptor => {
            let fd = value as i32;
            if fd == -100 {
                Shown::named("AT_FDCWD", ValueKind::Name, "-100")
            } else if let Some(name) = standard_fd_name(value) {
                Shown::named(name, ValueKind::Name, fd.to_string())
            } else {
                Shown::new(fd.to_string(), ValueKind::Number)
            }
        }
        Meaning::Signal => match SIGNALS.get(value as usize).filter(|_| value != 0) {
            Some(name) => Shown::named(*name, ValueKind::Name, value.to_string()),
            None => Shown::new((value as i32).to_string(), ValueKind::Number),
        },
        Meaning::Signed32 => Shown::new((value as i32).to_string(), ValueKind::Number),
        Meaning::Signed64 => Shown::new((value as i64).to_string(), ValueKind::Number),
        Meaning::Unsigned32 => Shown::new((value as u32).to_string(), ValueKind::Number),
        Meaning::Unsigned => Shown::new(value.to_string(), ValueKind::Number),
    }
}

/// Decoded flag names joined with `|`; bits the schema cannot name follow
/// in hex.
pub fn flags(nr: u64, index: usize, value: u64) -> Shown {
    let raw = format!("{value:#x}");
    let Some(decoded) = syscalls::argument_flags(nr, index, value) else {
        return Shown::new(raw, ValueKind::Flags);
    };
    let mut names = decoded.names;
    if decoded.unknown_bits != 0 {
        names.push(format!("{:#x}", decoded.unknown_bits));
    }
    if names.is_empty() {
        return Shown::new(raw, ValueKind::Flags);
    }
    Shown::named(names.join("|"), ValueKind::Flags, raw)
}

/// Captured bytes as a quoted string: printable text escaped, the trailing
/// NUL terminators dropped (they end C strings, they are not content).
pub fn quoted(data: &[u8]) -> String {
    let end = data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    quoted_bytes(&data[..end])
}

/// Every byte of a data buffer as a quoted string, zeros included:
/// printable text as is, other bytes escaped.
pub fn quoted_bytes(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len() + 2);
    text.push('"');
    for byte in data {
        match byte {
            0 => text.push_str("\\0"),
            b'\n' => text.push_str("\\n"),
            b'\r' => text.push_str("\\r"),
            b'\t' => text.push_str("\\t"),
            b'"' => text.push_str("\\\""),
            b'\\' => text.push_str("\\\\"),
            byte if byte.is_ascii_graphic() || *byte == b' ' => text.push(char::from(*byte)),
            byte => text.push_str(&format!("\\x{byte:02x}")),
        }
    }
    text.push('"');
    text
}

/// A captured `struct sockaddr` as an address (`10.0.2.3:53`, `[::1]:443`, a
/// Unix socket path, a netlink, packet, vsock, ALG or CAN address, or
/// `AF_UNSPEC`). None for other families or short data.
pub fn sockaddr(data: &[u8]) -> Option<String> {
    antinomie_monitor_core::typed_fields::sockaddr(data, None)
}

/// A file's size as the exact byte count and, from 1024 bytes up, a rounded
/// figure in 1024-based units: `16080 bytes (15.7 KiB)`.
pub fn file_size(bytes: u64) -> String {
    antinomie_monitor_core::byte_size::file_size(bytes)
}

/// A size for a table cell, a button or a one-line summary: the rounded
/// figure only (`1.9 MiB`). Properties and records use [`file_size`], with the
/// exact byte count; a short size carries it in its hover text.
pub fn short_size(bytes: u64) -> String {
    antinomie_monitor_core::byte_size::short_size(bytes)
}

/// A count with thousands separators: `1,024`. Every count shown in a label
/// or a status line uses this.
pub fn thousands(value: u64) -> String {
    antinomie_monitor_core::analysis::detection::group_digits(value)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn prctl_names_are_pointers_in_arg2_and_other_options_stay_numbers() {
        for abi in [syscalls::Abi::X86_64, syscalls::Abi::Aarch64] {
            let nr = syscalls::id(abi, syscalls::table(abi).number("prctl").unwrap());
            for option in [15, 16] {
                let shown = argument(nr, 1, &[option, 0x4d_2020, 0, 0, 0, 0]);
                assert_eq!(shown.text, "0x4d2020", "{abi:?} {option}");
                assert_eq!(shown.kind, ValueKind::Pointer);
                assert_eq!(argument(nr, 1, &[option, 0, 0, 0, 0, 0]).text, "NULL");
            }
            // PR_SET_TIMERSLACK takes a number.
            let shown = argument(nr, 1, &[29, 50000, 0, 0, 0, 0]);
            assert_eq!(shown.text, "50000");
            assert_eq!(shown.kind, ValueKind::Number);
        }
        // Only prctl, and only arg2.
        let nr = syscalls::id(syscalls::Abi::X86_64, 157);
        assert_ne!(
            argument(nr, 2, &[15, 0, 0x4d_2020, 0, 0, 0]).kind,
            ValueKind::Pointer
        );
        let lseek = syscalls::table(syscalls::Abi::X86_64)
            .number("lseek")
            .unwrap();
        let shown = argument(
            syscalls::id(syscalls::Abi::X86_64, lseek),
            1,
            &[15, 0x4d_2020, 0, 0, 0, 0],
        );
        assert_eq!(shown.kind, ValueKind::Number);
    }

    #[test]
    fn counts_use_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1024), "1,024");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn file_sizes_use_the_shared_bytes_format() {
        assert_eq!(file_size(4096), "4096 bytes (4.0 KiB)");
        assert_eq!(file_size(1), "1 byte");
    }

    #[test]
    fn errors_show_by_name_with_the_number_kept() {
        let shown = result(257, -2);
        assert_eq!(shown.text, "ENOENT");
        assert_eq!(shown.kind, ValueKind::Error);
        assert_eq!(shown.raw.as_deref(), Some("-2"));
        assert!(result_hover(257, -2).contains("ENOENT = -2"));
        assert!(result_hover(257, -2).contains("No such file or directory"));
        assert_eq!(result(0, -11).text, "EAGAIN");
        assert_eq!(result(0, -512).text, "ERESTARTSYS");
        // An errno nobody named stays a number, still an error.
        assert_eq!(result(0, -4000).text, "-4000");
        assert_eq!(result(0, -4000).kind, ValueKind::Error);
        assert_eq!(errno_name(41), None);
        assert_eq!(errno_name(133), Some("EHWPOISON"));
    }

    #[test]
    fn results_are_decimal_counts_or_hex_addresses() {
        assert_eq!(result(0, 832), Shown::new("832", ValueKind::Number));
        assert_eq!(result(257, 3).text, "3");
        assert_eq!(
            result(9, 0x7f12_3456_7000),
            Shown::new("0x7f1234567000", ValueKind::Pointer)
        );
        assert_eq!(result(12, 0x55d0_0000_0000).text, "0x55d000000000");
        // Below the error range a large negative is not an errno.
        assert_eq!(result(0, -5000).text, "-5000");
    }

    #[test]
    fn arguments_read_by_meaning() {
        // read(fd, buf, count)
        let args = [3, 0x7ffe_0c24_fcf8, 832, 0, 0, 0];
        assert_eq!(argument(0, 0, &args), Shown::new("3", ValueKind::Number));
        assert_eq!(
            argument(0, 1, &args),
            Shown::new("0x7ffe0c24fcf8", ValueKind::Pointer)
        );
        assert_eq!(argument(0, 2, &args), Shown::new("832", ValueKind::Number));
        // openat(AT_FDCWD, path, O_RDONLY|O_CLOEXEC, 0)
        let args = [(-100i64) as u64, 0x5555_0000, 0o2000000, 0o644, 0, 0];
        let dfd = argument(257, 0, &args);
        assert_eq!(dfd.text, "AT_FDCWD");
        assert_eq!(dfd.raw.as_deref(), Some("-100"));
        let flags = argument(257, 2, &args);
        assert_eq!(flags.kind, ValueKind::Flags);
        assert!(flags.text.contains("O_CLOEXEC"), "{flags:?}");
        assert_eq!(flags.raw.as_deref(), Some("0x80000"));
        assert_eq!(argument(257, 3, &args).text, "0644");
        // mmap(NULL, 8192, ..., fd -1, 0)
        let args = [0, 8192, 3, 0x22, u64::MAX, 0];
        assert_eq!(argument(9, 0, &args).text, "NULL");
        assert_eq!(argument(9, 1, &args).text, "8192");
        assert_eq!(argument(9, 4, &args).text, "-1");
        // kill(pid, SIGTERM); a PID is signed decimal.
        let args = [(-1i64) as u64, 15, 0, 0, 0, 0];
        assert_eq!(argument(62, 0, &args).text, "-1");
        assert_eq!(argument(62, 1, &args).text, "SIGTERM");
        // ioctl requests read by name; the number stays available.
        let args = [1, 0x5401, 0x7ffd_0000, 0, 0, 0];
        assert_eq!(argument(16, 1, &args).text, "TCGETS");
        assert_eq!(argument(16, 1, &args).raw.as_deref(), Some("0x5401"));
        // An address length is a count, not an address.
        let args = [3, 0x7ffd_0000, 16, 0, 0, 0];
        assert_eq!(argument(49, 2, &args).text, "16");
        assert_eq!(argument(49, 1, &args).text, "0x7ffd0000");
        // Only descriptor arguments are named; equal byte counts stay numeric.
        for (fd, name) in [(0, "stdin"), (1, "stdout"), (2, "stderr")] {
            let args = [fd, 0x1000, fd, 0, 0, 0];
            let shown = argument(0, 0, &args);
            assert_eq!(shown.text, name);
            assert_eq!(shown.raw, Some(fd.to_string()));
            assert_eq!(argument(0, 2, &args).text, fd.to_string());
        }
    }

    #[test]
    fn socket_addresses_decode_by_family() {
        let mut inet = vec![2, 0, 0, 53, 10, 0, 2, 3];
        inet.extend([0; 8]);
        assert_eq!(sockaddr(&inet).as_deref(), Some("10.0.2.3:53"));
        let mut inet6 = vec![10, 0, 1, 187, 0, 0, 0, 0];
        inet6.extend(std::net::Ipv6Addr::LOCALHOST.octets());
        assert_eq!(sockaddr(&inet6).as_deref(), Some("[::1]:443"));
        assert_eq!(
            sockaddr(b"\x01\x00/run/x.sock\0").as_deref(),
            Some("unix:/run/x.sock")
        );
        assert_eq!(sockaddr(&[2, 0, 0]), None);
        assert_eq!(sockaddr(&[17, 0, 0, 0]), None);
        assert_eq!(sockaddr(&[0, 0]).as_deref(), Some("AF_UNSPEC"));
        // Families with their own members.
        let mut netlink = vec![16, 0, 0, 0];
        netlink.extend(0u32.to_le_bytes());
        netlink.extend(1u32.to_le_bytes());
        assert_eq!(
            sockaddr(&netlink).as_deref(),
            Some("netlink:pid=0,groups=0x1")
        );
        let mut packet = vec![17, 0, 0x08, 0x06];
        packet.extend(2i32.to_le_bytes());
        packet.extend([1, 0, 0, 6]);
        packet.extend([0x52, 0x54, 0, 0x12, 0x34, 0x56, 0, 0]);
        assert_eq!(
            sockaddr(&packet).as_deref(),
            Some("packet:proto=ETH_P_ARP,ifindex=2,hatype=ARPHRD_ETHER,mac=52:54:00:12:34:56")
        );
    }

    #[test]
    fn strings_drop_their_terminator_and_escape_the_rest() {
        assert_eq!(quoted(b"/etc/passwd\0"), "\"/etc/passwd\"");
        assert_eq!(quoted(b"/etc\0\0\0"), "\"/etc\"");
        assert_eq!(quoted(b"a\0b\n\x01"), "\"a\\0b\\n\\x01\"");
        assert_eq!(quoted(b"\0"), "\"\"");
    }
}
