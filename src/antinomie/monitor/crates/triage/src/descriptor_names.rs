// SPDX-License-Identifier: GPL-3.0-only
//! Names for the descriptors that lead to no file: sockets, pipes and the
//! kernel's anonymous inodes (ANT-T0593).
//!
//! The Files tables name the file of a read or write by the path its
//! descriptor was opened with. A socket, a pipe or an eventfd has no path, so
//! the call that made the descriptor names it instead, in the same table of
//! open descriptors the paths live in (it follows `dup`, `fork`, `close` and
//! `exec` with them):
//!
//! - `socket (tcp)` from `socket()`, then `socket → 1.2.3.4:80 (tcp)` once it
//!   connected, `socket ← 10.0.2.15:23 (tcp)` once it was bound or accepted;
//! - `pipe (read end)`, `pipe (write end)`, `eventfd`, `timerfd`, ... .
//!
//! A descriptor the recording never saw made stays unnamed. A `memfd` keeps
//! its own `memfd:name` form, which is a file-like name.
use super::*;

/// What a descriptor name stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A socket of any family, including a Unix one.
    Socket,
    /// One end of a pipe.
    Pipe,
    /// An anonymous inode: eventfd, timerfd, epoll, inotify, io_uring, ...
    Anonymous,
}

const ANONYMOUS: &[&str] = &[
    "eventfd",
    "signalfd",
    "timerfd",
    "inotify",
    "epoll",
    "fanotify",
    "perf_event",
    "userfaultfd",
    "pidfd",
    "io_uring",
];

/// The kind of descriptor a displayed name stands for; `None` for a path, a
/// `memfd:` name and an unknown descriptor.
pub fn kind(label: &str) -> Option<Kind> {
    let word_end = label.find([' ', ':']).unwrap_or(label.len());
    let (word, rest) = label.split_at(word_end);
    let shaped = rest.is_empty() || rest.starts_with(" → ") || rest.starts_with(" ← ") || {
        rest.starts_with(" (") && !rest.starts_with(" (relative,") && !rest.starts_with(" (lexical")
    };
    if !shaped {
        return None;
    }
    match word {
        "socket" | "socketpair" => Some(Kind::Socket),
        "pipe" => Some(Kind::Pipe),
        word if ANONYMOUS.contains(&word) => Some(Kind::Anonymous),
        _ => None,
    }
}

/// The tag a filter sees for a descriptor name: `socket`, `pipe` or
/// `anonymous`.
pub fn kind_tag(kind: Kind) -> &'static str {
    match kind {
        Kind::Socket => "socket",
        Kind::Pipe => "pipe",
        Kind::Anonymous => "anonymous",
    }
}

/// The note a descriptor no call of the recording made carries on hover.
pub const BEFORE_RECORDING: &str = "descriptor opened before the recording";

/// A call's descriptor argument leads to a socket, by the name the run gave it
/// or by the socket table the event journal keeps.
pub fn socket_fd(files: &FdState, call: &InvocationSummary, event: &EventSummary) -> bool {
    let Some(fd) = fd_argument(call, event) else {
        return false;
    };
    let owner = table_owner(files, call.task_cookie, event.tid);
    files
        .opened
        .get(&(owner.0, owner.1, fd))
        .is_some_and(|label| kind(label) == Some(Kind::Socket))
        || crate::sigma_events::socket_at(files, call.task_cookie, event.tid, fd).is_some()
}

const CLOEXEC: u64 = 0x80000;

/// The protocol word of a socket from its domain and type.
pub fn protocol(domain: u64, kind: u64) -> &'static str {
    match domain {
        1 => "unix",
        2 | 10 => match kind & 0xf {
            1 => "tcp",
            2 => "udp",
            3 => "raw",
            5 => "sctp",
            _ => "inet",
        },
        16 => "netlink",
        17 => "packet",
        31 => "bluetooth",
        40 => "vsock",
        38 => "alg",
        _ => "socket",
    }
}

/// `ip:port`, `[ip6]:port`, a Unix path or abstract name (`@name`), or a
/// netlink address, from the `struct sockaddr` bytes a call carried.
pub fn endpoint(data: &[u8], complete: bool) -> Option<String> {
    let family = u16::from_le_bytes(data.get(..2)?.try_into().ok()?);
    match family {
        1 => {
            let name = data.get(2..)?;
            if let Some((0, rest)) = name.split_first() {
                // An abstract name runs the captured length; trailing zero
                // padding of the structure is not part of it.
                let end = rest
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map_or(0, |at| at + 1);
                let text = String::from_utf8_lossy(&rest[..end]).into_owned();
                return Some(format!("@{}", text.escape_default()));
            }
            let end = name.iter().position(|byte| *byte == 0);
            if end.is_none() && !complete {
                return None;
            }
            let path = &name[..end.unwrap_or(name.len())];
            (!path.is_empty()).then(|| String::from_utf8_lossy(path).into_owned())
        }
        2 | 10 if complete => {
            let address = crate::sigma_events::address_from(data)?;
            Some(if address.ip.contains(':') {
                format!("[{}]:{}", address.ip, address.port)
            } else {
                format!("{}:{}", address.ip, address.port)
            })
        }
        16 if complete => {
            let pid = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?);
            let groups = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?);
            Some(format!("pid {pid} groups {groups:#x}"))
        }
        _ => None,
    }
}

fn socket_label(arrow: Option<(&str, &str)>, protocol: &str) -> String {
    match arrow {
        Some((arrow, name)) => format!("socket {arrow} {name} ({protocol})"),
        None => format!("socket ({protocol})"),
    }
}

/// The protocol word and any name of a descriptor label made by `socket_label`.
fn parts(label: &str) -> Option<(&str, Option<(&str, &str)>)> {
    let rest = label.strip_prefix("socket")?;
    let (head, protocol) = rest.strip_suffix(')')?.rsplit_once(" (")?;
    let named = head
        .strip_prefix(" → ")
        .map(|name| ("→", name))
        .or_else(|| head.strip_prefix(" ← ").map(|name| ("←", name)));
    Some((protocol, named))
}

/// Names the descriptors a call made or changed. Returns whether the call was
/// one of these, so the caller has nothing more to remember from it.
pub fn remember(files: &mut FdState, call: &InvocationSummary, event: &EventSummary) -> bool {
    let name = event.syscall_name.as_str();
    if !matches!(
        name,
        "socket"
            | "socketpair"
            | "connect"
            | "bind"
            | "accept"
            | "accept4"
            | "pipe"
            | "pipe2"
            | "eventfd"
            | "eventfd2"
            | "signalfd"
            | "signalfd4"
            | "timerfd_create"
            | "inotify_init"
            | "inotify_init1"
            | "epoll_create"
            | "epoll_create1"
            | "fanotify_init"
            | "perf_event_open"
            | "userfaultfd"
            | "pidfd_open"
            | "io_uring_setup"
    ) {
        return false;
    }
    let Some(args) = call_args(call) else {
        return true;
    };
    let result = call.exit.as_ref().and_then(|exit| exit.result);
    let owner = table_owner(files, call.task_cookie, event.tid);
    let key = |fd: u64| (owner.0, owner.1, fd);
    let made = |files: &mut FdState, fd: u64, label: String, cloexec: bool| {
        files.opened.insert(key(fd), label);
        if cloexec {
            files.cloexec.insert(key(fd));
        } else {
            files.cloexec.remove(&key(fd));
        }
    };
    // A connect still going has already named its peer.
    let connecting = name == "connect" && result == Some(crate::sigma_events::EINPROGRESS);
    if !connecting && !result.is_some_and(|result| result >= 0) {
        return true;
    }
    let fd = result.unwrap_or(0) as u64;
    match name {
        "socket" => made(
            files,
            fd,
            socket_label(None, protocol(args[0], args[1])),
            args[1] & CLOEXEC != 0,
        ),
        "socketpair" => {
            if let Some([first, second]) = descriptor_pair(call, event, 3) {
                let label = format!("socketpair ({})", protocol(args[0], args[1]));
                made(files, first, label.clone(), args[1] & CLOEXEC != 0);
                made(files, second, label, args[1] & CLOEXEC != 0);
            }
        }
        "pipe" | "pipe2" => {
            if let Some([read, write]) = descriptor_pair(call, event, 0) {
                let cloexec = name == "pipe2" && args[1] & CLOEXEC != 0;
                made(files, read, "pipe (read end)".into(), cloexec);
                made(files, write, "pipe (write end)".into(), cloexec);
            }
        }
        "connect" | "bind" => {
            let Some(current) = files.opened.get(&key(args[0])) else {
                return true;
            };
            let Some((protocol, named)) = parts(current) else {
                return true;
            };
            let argument = crate::sigma_events::address_argument(event.syscall_nr, name);
            let found = argument
                .and_then(|argument| {
                    crate::sigma_events::address_bytes(call, event.syscall_nr, name, argument)
                })
                .and_then(|(data, complete)| endpoint(&data, complete));
            // A connection's peer is what the descriptor goes to; a bind only
            // says where it listens, and does not replace a known peer.
            let label = match (name, found, named) {
                ("connect", Some(peer), _) => socket_label(Some(("→", &peer)), protocol),
                ("bind", Some(local), None) => socket_label(Some(("←", &local)), protocol),
                _ => return true,
            };
            files.opened.insert(key(args[0]), label);
        }
        "accept" | "accept4" => {
            let listener = files
                .opened
                .get(&key(args[0]))
                .and_then(|label| parts(label))
                .map(|(protocol, named)| {
                    (protocol.to_owned(), named.map(|(_, name)| name.to_owned()))
                });
            let (protocol, local) = listener.unwrap_or_else(|| ("tcp".into(), None));
            let argument = crate::sigma_events::address_argument(event.syscall_nr, name);
            let peer = argument
                .and_then(|argument| {
                    crate::sigma_events::address_bytes(call, event.syscall_nr, name, argument)
                })
                .and_then(|(data, complete)| endpoint(&data, complete))
                .or(local);
            let label = socket_label(peer.as_deref().map(|peer| ("←", peer)), &protocol);
            made(
                files,
                fd,
                label,
                name == "accept4" && args[3] & CLOEXEC != 0,
            );
        }
        "eventfd" | "eventfd2" => made(
            files,
            fd,
            "eventfd".into(),
            name == "eventfd2" && args[1] & CLOEXEC != 0,
        ),
        "signalfd" | "signalfd4" => {
            // A signalfd call on an existing descriptor changes its mask only.
            if args[0] as i32 == -1 {
                made(
                    files,
                    fd,
                    "signalfd".into(),
                    name == "signalfd4" && args[3] & CLOEXEC != 0,
                );
            }
        }
        "timerfd_create" => made(files, fd, "timerfd".into(), args[1] & CLOEXEC != 0),
        "inotify_init" => made(files, fd, "inotify".into(), false),
        "inotify_init1" => made(files, fd, "inotify".into(), args[0] & CLOEXEC != 0),
        "epoll_create" => made(files, fd, "epoll".into(), false),
        "epoll_create1" => made(files, fd, "epoll".into(), args[0] & CLOEXEC != 0),
        "fanotify_init" => made(files, fd, "fanotify".into(), args[0] & 1 != 0),
        "perf_event_open" => made(files, fd, "perf_event".into(), args[3] & 8 != 0),
        "userfaultfd" => made(files, fd, "userfaultfd".into(), args[0] & CLOEXEC != 0),
        "pidfd_open" => made(files, fd, format!("pidfd (pid {})", args[0]), true),
        "io_uring_setup" => made(files, fd, "io_uring".into(), true),
        _ => {}
    }
    true
}

/// The two descriptors a `pipe` or `socketpair` call stored in the array at
/// `argument`.
fn descriptor_pair(
    call: &InvocationSummary,
    event: &EventSummary,
    argument: usize,
) -> Option<[u64; 2]> {
    let field = call
        .entry
        .iter()
        .chain(call.exit.iter())
        .flat_map(|event| &event.fields)
        .find(|field| {
            field.complete
                && !field.key.contains("len")
                && trace::field_argument_on(event.syscall_nr, &event.syscall_name, field)
                    == Some(argument)
        })?;
    let data = trace::covered_preview(field);
    let read = i32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    let write = i32::from_le_bytes(data.get(4..8)?.try_into().ok()?);
    Some([u64::try_from(read).ok()?, u64::try_from(write).ok()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_told_from_paths() {
        assert_eq!(kind("socket → 1.2.3.4:80 (tcp)"), Some(Kind::Socket));
        assert_eq!(kind("socket (udp)"), Some(Kind::Socket));
        assert_eq!(kind("socketpair (unix)"), Some(Kind::Socket));
        assert_eq!(kind("pipe (read end)"), Some(Kind::Pipe));
        assert_eq!(kind("eventfd"), Some(Kind::Anonymous));
        assert_eq!(kind("pidfd (pid 7)"), Some(Kind::Anonymous));
        assert_eq!(kind("memfd:payload"), None);
        assert_eq!(kind("/tmp/socket"), None);
        assert_eq!(kind("socket (relative, cwd not recorded)"), None);
        assert_eq!(kind("pipe.txt (lexical cwd path; symlinks unknown)"), None);
        assert_eq!(kind("—"), None);
    }

    #[test]
    fn a_socket_name_is_taken_apart_and_put_back() {
        let label = socket_label(Some(("→", "[::1]:80")), "tcp");
        assert_eq!(parts(&label), Some(("tcp", Some(("→", "[::1]:80")))));
        assert_eq!(parts("socket (unix)"), Some(("unix", None)));
    }

    #[test]
    fn unix_addresses_have_a_path_or_an_abstract_name() {
        let mut path = 1u16.to_le_bytes().to_vec();
        path.extend(b"/tmp/s\0\0\0");
        assert_eq!(endpoint(&path, true).as_deref(), Some("/tmp/s"));
        let mut hidden = 1u16.to_le_bytes().to_vec();
        hidden.extend(b"\0name\0\0");
        assert_eq!(endpoint(&hidden, true).as_deref(), Some("@name"));
        assert_eq!(endpoint(&path[..4], false), None);
    }
}
