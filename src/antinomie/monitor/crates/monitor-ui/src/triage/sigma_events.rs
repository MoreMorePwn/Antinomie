// SPDX-License-Identifier: MIT
//! State the Sigma normalizer keeps across calls, and the fields built from it:
//! parent process, working directory, new files, sockets and DNS names.
//!
//! Everything here is derived from the recorded calls and packets. A value
//! that comes from tracking state or from correlating two sources is reported
//! as inferred by the caller; a value nothing supports stays missing.
use super::*;
use antinomie_monitor_core::kernel_notes;
use std::collections::{BTreeMap, BTreeSet};

/// Paths remembered as existing. Past this, "not seen before" no longer means
/// anything, so no file is inferred to be new.
const KNOWN_PATHS: usize = 262_144;
/// Bound on every other per-run table kept here.
const TABLE_LIMIT: usize = 262_144;

const SOCKET: u64 = 41;
const CONNECT: u64 = 42;
const ACCEPT: u64 = 43;
const SENDTO: u64 = 44;
const BIND: u64 = 49;
const ACCEPT4: u64 = 288;
pub(super) const O_CREAT: u64 = 0o100;
pub(super) const O_EXCL: u64 = 0o200;
pub(super) const O_TRUNC: u64 = 0o1000;
/// `__O_TMPFILE | O_DIRECTORY`; both bits must be set.
pub(super) const O_TMPFILE: u64 = 0o20200000;
const SOCK_CLOEXEC: u64 = 0o2000000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SocketKind {
    Stream,
    Datagram,
    Other,
}

#[derive(Clone, Copy)]
struct Socket {
    kind: SocketKind,
    cloexec: bool,
}

#[derive(Default)]
pub(super) struct State {
    known: BTreeSet<String>,
    known_overflow: bool,
    sockets: BTreeMap<(u64, u32, u64), Socket>,
    /// `(owner cookie, owner pid, address, port)` of datagram flows already reported.
    flows: BTreeSet<(u64, u32, String, u16)>,
    /// Answer address → `(capture time in µs, queried name)`.
    dns: BTreeMap<String, Vec<(Option<u64>, String)>>,
    /// Working directory the root process was launched in.
    pub launch_cwd: Option<String>,
    pub root_cookie: u64,
    seeded: bool,
    /// Credentials in effect for each task, by task cookie.
    credentials: BTreeMap<u64, kernel_notes::Credentials>,
}

impl State {
    /// The path was seen earlier in this run, so it existed then.
    pub(super) fn knows(&self, path: &str) -> bool {
        self.known.contains(path)
    }

    pub(super) fn set_credentials(&mut self, task: u64, creds: kernel_notes::Credentials) {
        if self.credentials.len() < TABLE_LIMIT || self.credentials.contains_key(&task) {
            self.credentials.insert(task, creds);
        }
    }

    pub(super) fn credentials(&self, task: u64) -> Option<kernel_notes::Credentials> {
        self.credentials.get(&task).copied()
    }

    pub(super) fn copy_sockets(&mut self, source: (u64, u32), target: (u64, u32)) {
        let copied: Vec<_> = self
            .sockets
            .iter()
            .filter(|((cookie, pid, _), _)| (*cookie, *pid) == source)
            .map(|((_, _, fd), socket)| (*fd, *socket))
            .collect();
        for (fd, socket) in copied {
            self.sockets.insert((target.0, target.1, fd), socket);
        }
    }

    /// Remember what a capture's DNS answers say, from one DNS row.
    pub(super) fn learn_dns(&mut self, row: &[Cell]) {
        let values = row
            .first()
            .map(|cell| cell.values.as_slice())
            .unwrap_or_default();
        let find = |key: &str| values.iter().find(|(name, _)| *name == key).map(|v| &v.1);
        let (Some(RowValue::Text(name)), Some(RowValue::List(answers))) =
            (find("dns.name"), find("dns.answers"))
        else {
            return;
        };
        let time = match find("frame.time_us") {
            Some(RowValue::Number(time)) => u64::try_from(*time).ok(),
            _ => None,
        };
        for answer in answers {
            let Ok(address) = answer.parse::<std::net::IpAddr>() else {
                continue;
            };
            if self.dns.len() >= TABLE_LIMIT && !self.dns.contains_key(&address.to_string()) {
                return;
            }
            self.dns
                .entry(address.to_string())
                .or_default()
                .push((time, name.trim_end_matches('.').to_owned()));
        }
    }

    /// The name a DNS answer in this run's capture gave for `address`. Several
    /// different names for one address are only told apart by capture time;
    /// without it none is chosen.
    pub(super) fn hostname(&self, address: &str, at_us: Option<u64>) -> Option<String> {
        let address = address.parse::<std::net::IpAddr>().ok()?.to_string();
        let answers = self.dns.get(&address)?;
        let first = &answers.first()?.1;
        if answers
            .iter()
            .all(|(_, name)| name.eq_ignore_ascii_case(first))
        {
            return Some(first.clone());
        }
        let at = at_us?;
        answers
            .iter()
            .filter_map(|(time, name)| Some((time.filter(|time| *time <= at)?, name)))
            .max_by_key(|(time, _)| *time)
            .map(|(_, name)| name.clone())
    }

    fn remember(&mut self, path: String) {
        if self.known.len() >= KNOWN_PATHS {
            self.known_overflow = true;
        } else {
            self.known.insert(path);
        }
    }
}

/// Seed the root process's working directory with the directory it was
/// launched in, the first time one of its tasks is seen. Later `chdir` and
/// `fchdir` calls are followed from there.
pub(super) fn seed_launch_cwd(files: &mut FdState, event: &EventSummary) {
    let state = &mut files.journal;
    if state.seeded
        || state.root_cookie == 0
        || event.task_cookie != state.root_cookie
        || event.pid != event.tid
    {
        return;
    }
    let Some(cwd) = state.launch_cwd.clone() else {
        return;
    };
    state.seeded = true;
    files
        .cwd
        .entry((event.task_cookie, event.tid))
        .or_insert(cwd);
}

pub(super) struct Parent {
    pub pid: u32,
    pub image: Option<String>,
    pub command_line: Option<String>,
}

/// The parent a fork or clone result linked to this task, with the image and
/// command line that parent had when last seen to exec.
pub(super) fn parent(files: &FdState, event: &EventSummary) -> Option<Parent> {
    let node = files.process_images.get(&TaskKey {
        pid: event.pid,
        cookie: event.task_cookie,
    })?;
    let key = node.parent?;
    let parent = files.process_images.get(&key)?;
    Some(Parent {
        pid: key.pid,
        image: Some(parent.comm.clone()).filter(|image| !image.is_empty() && image != "?"),
        command_line: parent.command_line.clone(),
    })
}

/// The task's working directory and whether it is only inferred: a directory
/// reached by `chdir` is joined lexically and symlinks are not followed, so
/// only the launch directory and a `getcwd` answer are exact.
pub(super) fn current_directory(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
) -> Option<(String, bool)> {
    let owner = fs_owner(files, call.task_cookie, event.tid);
    let path = files.cwd.get(&owner)?;
    Some((path.clone(), files.cwd_unverified.contains(&owner)))
}

const LEXICAL: [&str; 2] = [
    " (lexical cwd path; symlinks unknown)",
    " (lexical dirfd path; symlinks unknown)",
];

/// A displayed path without its annotation, and whether it was only joined
/// lexically. Relative paths that could not be resolved give nothing.
pub(super) fn clean(display: &str) -> Option<(String, bool)> {
    if display.is_empty()
        || display == "—"
        || display.contains("(relative,")
        || display.contains("path unavailable")
    {
        return None;
    }
    for suffix in LEXICAL {
        if let Some(path) = display.strip_suffix(suffix) {
            return Some((path.to_owned(), true));
        }
    }
    Some((display.to_owned(), false))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Subject,
    Old,
    New,
}

pub(super) struct PathUse {
    pub name: String,
    /// Joined lexically from the working directory or a directory descriptor.
    pub lexical: bool,
    pub role: Role,
}

fn resolved(
    raw: &str,
    call: &InvocationSummary,
    event: &EventSummary,
    files: &FdState,
    dirfd: Option<u64>,
) -> (String, bool) {
    let shown = resolve_path_dirfd(raw, call, event, files, dirfd);
    clean(&shown).unwrap_or_else(|| (raw.to_owned(), false))
}

/// The paths a call names, resolved as far as the trace allows. A path that
/// cannot be resolved keeps the text the call was given, as auditd records it.
pub(super) fn paths(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
) -> Vec<PathUse> {
    let name = event.syscall_name.as_str();
    let args = call_args(call);
    let arg = |index: usize| args.map(|args| args[index]);
    let two = |old: Option<u64>, new: Option<u64>, old_role: Option<Role>| {
        let mut found = Vec::new();
        let old_name = named_path(call, event, &["oldname", "old_path"]);
        let new_name = named_path(call, event, &["newname", "new_path"]);
        if let (Some(raw), Some(role)) = (old_name, old_role) {
            let (name, lexical) = resolved(&raw, call, event, files, old);
            found.push(PathUse {
                name,
                lexical,
                role,
            });
        }
        if let Some(raw) = new_name {
            let (name, lexical) = resolved(&raw, call, event, files, new);
            found.push(PathUse {
                name,
                lexical,
                role: Role::New,
            });
        }
        found
    };
    match name {
        "rename" | "link" => two(None, None, Some(Role::Old)),
        "renameat" | "renameat2" | "linkat" => two(arg(0), arg(2), Some(Role::Old)),
        "symlink" => two(None, None, None),
        "symlinkat" => two(None, arg(1), None),
        _ => path_list(call)
            .first()
            .map(|raw| {
                let (name, lexical) =
                    resolved(raw, call, event, files, dirfd_argument(call, event));
                vec![PathUse {
                    name,
                    lexical,
                    role: Role::Subject,
                }]
            })
            .unwrap_or_default(),
    }
}

pub(super) struct Creation {
    pub path: String,
    pub lexical: bool,
    /// The call proves a new file only by the path not having been seen
    /// before, or names a directory instead of the file (`O_TMPFILE`).
    pub inferred: Vec<&'static str>,
}

/// The file a successful call created, for `file_event`.
///
/// `mkdir`, `mknod`, `link`, `symlink` and `O_CREAT|O_EXCL` fail on an
/// existing name, so success proves a new file. `creat` and
/// `O_CREAT|O_TRUNC` succeed on an existing file too: the file is new only if
/// the path was not seen before, which the caller marks as inferred. With
/// `plain_creat` an `O_CREAT` open without either flag is judged the same way.
pub(super) fn creation(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    plain_creat: bool,
) -> Option<Creation> {
    if !succeeded(call) {
        return None;
    }
    let name = event.syscall_name.as_str();
    let used = paths(files, call, event);
    let found = |lexical: bool, path: String, inferred: Vec<&'static str>| Creation {
        path,
        lexical,
        inferred,
    };
    if matches!(
        name,
        "mkdir" | "mkdirat" | "mknod" | "mknodat" | "link" | "linkat" | "symlink" | "symlinkat"
    ) {
        let used = used
            .into_iter()
            .find(|used| matches!(used.role, Role::New | Role::Subject))?;
        return Some(found(used.lexical, used.name, Vec::new()));
    }
    if !matches!(name, "open" | "openat" | "openat2" | "creat") {
        return None;
    }
    let flags = open_flags(call, event)?;
    let used = used.into_iter().next()?;
    if flags & O_TMPFILE == O_TMPFILE {
        return Some(found(
            used.lexical,
            used.name,
            vec!["IsNewFile", "TargetFilename"],
        ));
    }
    if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
        return Some(found(used.lexical, used.name, Vec::new()));
    }
    let truncating = flags & (O_CREAT | O_TRUNC) == O_CREAT | O_TRUNC;
    if !(truncating || plain_creat && flags & O_CREAT != 0) {
        return None;
    }
    if files.journal.known_overflow || files.journal.known.contains(&used.name) {
        return None;
    }
    Some(found(used.lexical, used.name, vec!["IsNewFile"]))
}

/// Update what is known about paths and sockets after one call.
pub(super) fn track(files: &mut FdState, call: &InvocationSummary, event: &EventSummary) {
    track_sockets(files, call, event);
    if !succeeded(call) {
        return;
    }
    let name = event.syscall_name.as_str();
    let used = paths(files, call, event);
    let deletes = matches!(name, "unlink" | "unlinkat" | "rmdir");
    for used in used {
        if deletes || used.role == Role::Old {
            files.journal.known.remove(&used.name);
        } else {
            files.journal.remember(used.name);
        }
    }
}

fn track_sockets(files: &mut FdState, call: &InvocationSummary, event: &EventSummary) {
    let Some(args) = call_args(call) else { return };
    let Some(result) = call.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    let owner = table_owner(files, call.task_cookie, event.tid);
    let key = |fd: u64| (owner.0, owner.1, fd);
    let sockets = &mut files.journal.sockets;
    match event.syscall_nr {
        _ if result < 0 => {}
        SOCKET => {
            let kind = match (args[0], args[1] & 0xf) {
                (2 | 10, 1) => SocketKind::Stream,
                (2 | 10, 2) => SocketKind::Datagram,
                _ => SocketKind::Other,
            };
            if sockets.len() < TABLE_LIMIT {
                let cloexec = args[1] & SOCK_CLOEXEC != 0;
                sockets.insert(key(result as u64), Socket { kind, cloexec });
            }
        }
        ACCEPT | ACCEPT4 => {
            let cloexec = event.syscall_nr == ACCEPT4 && args[3] & SOCK_CLOEXEC != 0;
            if sockets.len() < TABLE_LIMIT {
                let kind = SocketKind::Stream;
                sockets.insert(key(result as u64), Socket { kind, cloexec });
            }
        }
        3 => {
            sockets.remove(&key(args[0]));
        }
        32 | 33 | 292 | 72 => {
            let new = match (event.syscall_nr, args[1]) {
                (32, _) | (72, 0 | 1030) => result as u64,
                (33 | 292, _) => args[1],
                (72, 2) => {
                    if let Some(socket) = sockets.get_mut(&key(args[0])) {
                        socket.cloexec = args[2] & 1 != 0;
                    }
                    return;
                }
                _ => return,
            };
            match sockets.get(&key(args[0])).copied() {
                Some(mut socket) => {
                    socket.cloexec = (event.syscall_nr == 292 && args[2] & 0x80000 != 0)
                        || (event.syscall_nr == 72 && args[1] == 1030);
                    sockets.insert(key(new), socket);
                }
                None => {
                    sockets.remove(&key(new));
                }
            }
        }
        436 => {
            // A cloexec range keeps the descriptors until the next exec.
            let cloexec = args[2] & 4 != 0;
            let range: Vec<_> = sockets
                .range(key(args[0])..=key(args[1]))
                .map(|(key, _)| *key)
                .collect();
            for key in range {
                if cloexec {
                    if let Some(socket) = sockets.get_mut(&key) {
                        socket.cloexec = true;
                    }
                } else {
                    sockets.remove(&key);
                }
            }
        }
        59 | 322 => {
            sockets.retain(|(cookie, pid, _), socket| (*cookie, *pid) != owner || !socket.cloexec)
        }
        _ => {}
    }
}

/// What the descriptor passed as the call's first argument is, when its
/// `socket()` or `accept()` was seen.
pub(super) fn socket_kind(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
) -> Option<SocketKind> {
    let fd = call_args(call)?[0];
    let owner = table_owner(files, call.task_cookie, event.tid);
    files
        .journal
        .sockets
        .get(&(owner.0, owner.1, fd))
        .map(|socket| socket.kind)
}

/// First time this process reaches this datagram peer. A datagram socket has
/// no connection to open or close, so each peer is reported once.
pub(super) fn first_flow(
    files: &mut FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    address: &str,
    port: u16,
) -> bool {
    let owner = table_owner(files, call.task_cookie, event.tid);
    let flows = &mut files.journal.flows;
    flows.len() < TABLE_LIMIT && flows.insert((owner.0, owner.1, address.to_owned(), port))
}

pub(super) struct Address {
    pub ip: String,
    pub port: u16,
    /// The `struct sockaddr` as captured.
    pub raw: Vec<u8>,
}

/// The IP address and port in the `struct sockaddr` a call was given or
/// filled in. Only a complete AF_INET or AF_INET6 address is decoded; Unix
/// sockets and short captures give nothing.
pub(super) fn address(call: &InvocationSummary, nr: u64, argument: usize) -> Option<Address> {
    // accept4 takes the same address argument as accept.
    let nr = if nr == ACCEPT4 { ACCEPT } else { nr };
    let field = call
        .entry
        .iter()
        .chain(call.exit.iter())
        .flat_map(|event| &event.fields)
        .find(|field| {
            field.key.contains("addr")
                && !field.key.contains("len")
                && !field.key.contains("capacity")
                && trace::field_argument(nr, &field.key) == Some(argument)
        })?;
    if !field.complete {
        return None;
    }
    let data = trace::covered_preview(field);
    let family = u16::from_le_bytes(data.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(data.get(2..4)?.try_into().ok()?);
    let (ip, size) = match family {
        2 => {
            let octets: [u8; 4] = data.get(4..8)?.try_into().ok()?;
            (std::net::Ipv4Addr::from(octets).to_string(), 16)
        }
        10 => {
            let octets: [u8; 16] = data.get(8..24)?.try_into().ok()?;
            (std::net::Ipv6Addr::from(octets).to_string(), 28)
        }
        _ => return None,
    };
    Some(Address {
        ip,
        port,
        raw: data[..data.len().min(size)].to_vec(),
    })
}

/// Index of the address argument of an address-taking syscall.
pub(super) fn address_argument(nr: u64) -> Option<usize> {
    match nr {
        CONNECT | ACCEPT | ACCEPT4 | BIND => Some(1),
        SENDTO => Some(4),
        _ => None,
    }
}
