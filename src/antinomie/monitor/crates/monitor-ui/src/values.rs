//! Syscall values shown by meaning: counts, sizes, descriptors, PIDs and
//! results in decimal; pointers, addresses and flags in hex; errors by name
//! (the number stays available on hover); captured strings without their
//! terminating NUL.
use crate::theme::ValueKind;
use antinomie_monitor_core::{syscalls, WaitStatus};

/// A value as the trace shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Shown {
    pub(crate) text: String,
    pub(crate) kind: ValueKind,
    /// The plain number, when `text` names it instead (errors, AT_FDCWD,
    /// signals, decoded flags).
    pub(crate) raw: Option<String>,
}

impl Shown {
    fn new(text: impl Into<String>, kind: ValueKind) -> Self {
        Self {
            text: text.into(),
            kind,
            raw: None,
        }
    }

    fn named(text: impl Into<String>, kind: ValueKind, raw: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind,
            raw: Some(raw.into()),
        }
    }

    /// Hover text: the shown value and, when it is a name, its number.
    pub(crate) fn hover(&self) -> String {
        match &self.raw {
            Some(raw) => format!("{} = {raw}", self.text),
            None => self.text.clone(),
        }
    }
}

/// Names of the Linux errno values (x86-64), index = errno.
const ERRNO: [&str; 134] = [
    "",
    "EPERM",
    "ENOENT",
    "ESRCH",
    "EINTR",
    "EIO",
    "ENXIO",
    "E2BIG",
    "ENOEXEC",
    "EBADF",
    "ECHILD",
    "EAGAIN",
    "ENOMEM",
    "EACCES",
    "EFAULT",
    "ENOTBLK",
    "EBUSY",
    "EEXIST",
    "EXDEV",
    "ENODEV",
    "ENOTDIR",
    "EISDIR",
    "EINVAL",
    "ENFILE",
    "EMFILE",
    "ENOTTY",
    "ETXTBSY",
    "EFBIG",
    "ENOSPC",
    "ESPIPE",
    "EROFS",
    "EMLINK",
    "EPIPE",
    "EDOM",
    "ERANGE",
    "EDEADLK",
    "ENAMETOOLONG",
    "ENOLCK",
    "ENOSYS",
    "ENOTEMPTY",
    "ELOOP",
    "",
    "ENOMSG",
    "EIDRM",
    "ECHRNG",
    "EL2NSYNC",
    "EL3HLT",
    "EL3RST",
    "ELNRNG",
    "EUNATCH",
    "ENOCSI",
    "EL2HLT",
    "EBADE",
    "EBADR",
    "EXFULL",
    "ENOANO",
    "EBADRQC",
    "EBADSLT",
    "",
    "EBFONT",
    "ENOSTR",
    "ENODATA",
    "ETIME",
    "ENOSR",
    "ENONET",
    "ENOPKG",
    "EREMOTE",
    "ENOLINK",
    "EADV",
    "ESRMNT",
    "ECOMM",
    "EPROTO",
    "EMULTIHOP",
    "EDOTDOT",
    "EBADMSG",
    "EOVERFLOW",
    "ENOTUNIQ",
    "EBADFD",
    "EREMCHG",
    "ELIBACC",
    "ELIBBAD",
    "ELIBSCN",
    "ELIBMAX",
    "ELIBEXEC",
    "EILSEQ",
    "ERESTART",
    "ESTRPIPE",
    "EUSERS",
    "ENOTSOCK",
    "EDESTADDRREQ",
    "EMSGSIZE",
    "EPROTOTYPE",
    "ENOPROTOOPT",
    "EPROTONOSUPPORT",
    "ESOCKTNOSUPPORT",
    "EOPNOTSUPP",
    "EPFNOSUPPORT",
    "EAFNOSUPPORT",
    "EADDRINUSE",
    "EADDRNOTAVAIL",
    "ENETDOWN",
    "ENETUNREACH",
    "ENETRESET",
    "ECONNABORTED",
    "ECONNRESET",
    "ENOBUFS",
    "EISCONN",
    "ENOTCONN",
    "ESHUTDOWN",
    "ETOOMANYREFS",
    "ETIMEDOUT",
    "ECONNREFUSED",
    "EHOSTDOWN",
    "EHOSTUNREACH",
    "EALREADY",
    "EINPROGRESS",
    "ESTALE",
    "EUCLEAN",
    "ENOTNAM",
    "ENAVAIL",
    "EISNAM",
    "EREMOTEIO",
    "EDQUOT",
    "ENOMEDIUM",
    "EMEDIUMTYPE",
    "ECANCELED",
    "ENOKEY",
    "EKEYEXPIRED",
    "EKEYREVOKED",
    "EKEYREJECTED",
    "EOWNERDEAD",
    "ENOTRECOVERABLE",
    "ERFKILL",
    "EHWPOISON",
];

/// Kernel-internal errors that can still reach a syscall exit (restarts).
const KERNEL_ERRNO: [(u64, &str, &str); 19] = [
    (512, "ERESTARTSYS", "restart the call (signal)"),
    (513, "ERESTARTNOINTR", "restart the call"),
    (514, "ERESTARTNOHAND", "restart the call if no handler"),
    (515, "ENOIOCTLCMD", "no such ioctl command"),
    (
        516,
        "ERESTART_RESTARTBLOCK",
        "restart through restart_syscall",
    ),
    (517, "EPROBE_DEFER", "driver probe deferred"),
    (518, "EOPENSTALE", "open found a stale dentry"),
    (519, "ENOPARAM", "parameter not supported"),
    (521, "EBADHANDLE", "illegal NFS file handle"),
    (522, "ENOTSYNC", "update synchronization mismatch"),
    (523, "EBADCOOKIE", "cookie is stale"),
    (524, "ENOTSUPP", "operation not supported"),
    (525, "ETOOSMALL", "buffer or request is too small"),
    (526, "ESERVERFAULT", "server fault"),
    (527, "EBADTYPE", "type not supported by server"),
    (528, "EJUKEBOX", "request initiated, wait"),
    (529, "EIOCBQUEUED", "I/O control block queued"),
    (530, "ERECALLCONFLICT", "conflict with recalled state"),
    (531, "ENOGRACE", "NFS file lock reclaim refused"),
];

/// The symbolic name of a Linux errno, such as `ENOENT` for 2.
pub(crate) fn errno_name(errno: u64) -> Option<&'static str> {
    if let Some(name) = usize::try_from(errno)
        .ok()
        .and_then(|index| ERRNO.get(index))
        .filter(|name| !name.is_empty())
    {
        return Some(name);
    }
    KERNEL_ERRNO
        .iter()
        .find(|(number, ..)| *number == errno)
        .map(|(_, name, _)| *name)
}

/// What an errno means, in words ("No such file or directory").
pub(crate) fn errno_description(errno: u64) -> Option<String> {
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
pub(crate) fn is_error(result: i64) -> bool {
    (-4095..0).contains(&result)
}

/// Syscalls whose successful return is an address.
fn returns_address(nr: u64) -> bool {
    // mmap, brk, mremap, shmat
    matches!(nr, 9 | 12 | 25 | 30)
}

/// A syscall return value by meaning: an error by name, an address in hex,
/// anything else (counts, descriptors, PIDs) in decimal.
pub(crate) fn result(nr: u64, result: i64) -> Shown {
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
pub(crate) fn result_hover(nr: u64, value: i64) -> String {
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
pub(crate) fn task_end(status: &WaitStatus) -> String {
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

const SIGNALS: [&str; 32] = [
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
enum Meaning {
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

fn meaning(nr: u64, index: usize) -> Meaning {
    let Some(argument) = syscalls::syscall(nr).and_then(|info| info.arguments.get(index)) else {
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
    if nr == 16 && index == 1 {
        return Meaning::Hex;
    }
    if name.contains("addr")
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
        "long" | "loff_t" | "off_t" => Meaning::Signed64,
        "unsigned int" | "u32" | "__u32" | "uint32_t" | "uid_t" | "gid_t" | "qid_t" => {
            Meaning::Unsigned32
        }
        _ => Meaning::Unsigned,
    }
}

/// Argument `index` of syscall `nr` by meaning. `args` gives the other
/// arguments some values depend on (socket option names by level).
pub(crate) fn argument(nr: u64, index: usize, args: &[u64; 6]) -> Shown {
    let value = args[index];
    if let Some(name) = syscalls::selector_name(nr, index, args) {
        return Shown::named(name, ValueKind::Flags, format!("{value:#x}"));
    }
    match meaning(nr, index) {
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
fn flags(nr: u64, index: usize, value: u64) -> Shown {
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
pub(crate) fn quoted(data: &[u8]) -> String {
    let end = data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    let mut text = String::with_capacity(end + 2);
    text.push('"');
    for byte in &data[..end] {
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

/// A captured `struct sockaddr` as an address: `10.0.2.3:53`,
/// `[::1]:443` or a Unix socket path. None for other families or short data.
pub(crate) fn sockaddr(data: &[u8]) -> Option<String> {
    let family = u16::from_le_bytes(data.get(..2)?.try_into().ok()?);
    let port =
        |data: &[u8]| -> Option<u16> { Some(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?)) };
    match family {
        // AF_UNIX; a leading NUL names an abstract socket.
        1 => {
            let path = data.get(2..)?;
            let (prefix, path) = match path.split_first() {
                Some((0, rest)) => ("@", rest),
                _ => ("", path),
            };
            let end = path
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(path.len());
            let text = String::from_utf8_lossy(&path[..end]);
            Some(format!("unix:{prefix}{text}"))
        }
        // AF_INET
        2 => {
            let address: [u8; 4] = data.get(4..8)?.try_into().ok()?;
            Some(format!(
                "{}:{}",
                std::net::Ipv4Addr::from(address),
                port(data)?
            ))
        }
        // AF_INET6
        10 => {
            let address: [u8; 16] = data.get(8..24)?.try_into().ok()?;
            Some(format!(
                "[{}]:{}",
                std::net::Ipv6Addr::from(address),
                port(data)?
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // ioctl requests are bit fields.
        let args = [1, 0x5401, 0x7ffd_0000, 0, 0, 0];
        assert_eq!(argument(16, 1, &args).text, "0x5401");
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
    }

    #[test]
    fn strings_drop_their_terminator_and_escape_the_rest() {
        assert_eq!(quoted(b"/etc/passwd\0"), "\"/etc/passwd\"");
        assert_eq!(quoted(b"/etc\0\0\0"), "\"/etc\"");
        assert_eq!(quoted(b"a\0b\n\x01"), "\"a\\0b\\n\\x01\"");
        assert_eq!(quoted(b"\0"), "\"\"");
    }
}
