// SPDX-License-Identifier: GPL-3.0-only
//! File descriptor, working directory and path tracking per task.
use super::*;

/// Successful `open`, `openat` and `openat2` return the new descriptor.
/// Every other file operation uses the argument whose schema name is `fd`.
pub(super) fn file_fd(invocation: &InvocationSummary, event: &EventSummary) -> String {
    if OPEN_NAMES.contains(&event.syscall_name.as_str()) {
        if async_files::direct_descriptor(invocation) {
            return "registered".into();
        }
        return invocation
            .exit
            .as_ref()
            .and_then(|exit| exit.result)
            .filter(|result| *result >= 0)
            .map(|result| result.to_string())
            .unwrap_or_else(|| "—".into());
    }
    fd_argument(invocation, event)
        .map(|fd| {
            if fd == u64::from(u32::MAX) || fd == u64::MAX {
                "—".to_string()
            } else {
                fd.to_string()
            }
        })
        .unwrap_or_else(|| "—".into())
}

/// The `fd` argument. `mmap2` is not in the x86-64 table; its descriptor is
/// still argument 4, the same slot `mmap` names `fd`.
pub(super) fn fd_argument(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    let args = call_args(invocation)?;
    if matches!(event.syscall_name.as_str(), "copy_file_range" | "splice") {
        return Some(args[2]);
    }
    if event.syscall_name == "sendfile" {
        return Some(args[0]);
    }
    let index = (0..args.len())
        .find(|index| trace::argument_name(event.syscall_nr, *index) == "fd")
        .or_else(|| matches!(event.syscall_name.as_str(), "mmap" | "mmap2").then_some(4))?;
    (index < args.len()).then_some(args[index])
}

pub(super) fn table_owner(files: &FdState, cookie: u64, pid: u32) -> (u64, u32) {
    follow_share(&files.share, cookie, pid)
}

pub(super) fn fs_owner(files: &FdState, cookie: u64, pid: u32) -> (u64, u32) {
    follow_share(&files.fs_share, cookie, pid)
}

fn follow_share(
    share: &std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    cookie: u64,
    pid: u32,
) -> (u64, u32) {
    let mut key = (cookie, pid);
    for _ in 0..8 {
        match share.get(&key) {
            Some(next) if *next != key => key = *next,
            _ => break,
        }
    }
    key
}

pub(super) fn file_outcome(invocation: &InvocationSummary) -> String {
    match invocation.exit.as_ref().and_then(|exit| exit.result) {
        Some(result) if result >= 0 => "successful".into(),
        Some(_) => "failed attempt".into(),
        None => "exit not recorded".into(),
    }
}

pub(super) fn succeeded(invocation: &InvocationSummary) -> bool {
    invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .is_some_and(|result| result >= 0)
}

pub(super) fn remember_open(
    files: &mut FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
) {
    if event.syscall_name == "memfd_create" && succeeded(invocation) {
        if let Some(fd) = invocation.exit.as_ref().and_then(|exit| exit.result) {
            let owner = table_owner(files, invocation.task_cookie, event.tid);
            let name = event
                .fields
                .iter()
                .find_map(path_text)
                .unwrap_or_else(|| "unnamed".into());
            let key = (owner.0, owner.1, fd as u64);
            files.opened.insert(key, format!("memfd:{name}"));
            if call_args(invocation).is_some_and(|args| args[1] & 1 != 0) {
                files.cloexec.insert(key);
            }
        }
        return;
    }
    remember_identity(files, invocation, event);
    if !OPEN_NAMES.contains(&event.syscall_name.as_str()) {
        return;
    }
    if !succeeded(invocation) || async_files::direct_descriptor(invocation) {
        return;
    }
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    let key = (cookie, pid, result as u64);
    let paths = path_list(invocation);
    if paths.is_empty() {
        files.opened.remove(&key);
    } else {
        files
            .opened
            .insert(key, displayed_path(invocation, event, files));
    }
    if open_flags(invocation, event).is_some_and(|flags| flags & 0x80000 != 0) {
        files.cloexec.insert(key);
    } else {
        files.cloexec.remove(&key);
    }
}

pub(super) fn remember_cwd(
    files: &mut FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
) {
    if !matches!(event.syscall_name.as_str(), "chdir" | "fchdir" | "getcwd") {
        return;
    }
    let owner = fs_owner(files, invocation.task_cookie, event.tid);
    if invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .is_some_and(|ret| ret < 0)
    {
        return;
    }
    if !succeeded(invocation) {
        files.cwd.remove(&owner);
        files.cwd_unverified.insert(owner);
        return;
    }
    let path = match event.syscall_name.as_str() {
        "getcwd" => path_list(invocation)
            .into_iter()
            .next()
            .filter(|path| path.starts_with('/')),
        "chdir" => path_list(invocation)
            .into_iter()
            .next()
            .and_then(|path| resolve_chdir(files, owner, path)),
        "fchdir" => call_args(invocation).and_then(|args| {
            let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
            files
                .opened
                .get(&(cookie, pid, args[0]))
                .cloned()
                .filter(|path| path.starts_with('/'))
        }),
        _ => None,
    };
    if let Some(path) = path {
        files.cwd.insert(owner, path);
        if event.syscall_name == "getcwd" {
            files.cwd_unverified.remove(&owner);
        } else {
            files.cwd_unverified.insert(owner);
        }
    } else {
        files.cwd.remove(&owner);
        files.cwd_unverified.insert(owner);
    }
}

/// An absolute chdir is stored as given. A relative chdir is applied to the
/// task's current directory. Without a recorded directory the relative change
/// is left unknown instead of being treated as an absolute path.
fn resolve_chdir(files: &FdState, owner: (u64, u32), path: String) -> Option<String> {
    if path.starts_with('/') {
        return Some(path);
    }
    let base = files.cwd.get(&owner)?;
    Some(join_cwd(base, &path))
}

fn join_cwd(base: &str, relative: &str) -> String {
    // chdir resolves '..' after symlinks. Lexical normalization would invent
    // a physical working directory, so retain the literal observed components.
    format!("{}/{relative}", base.trim_end_matches('/'))
}

/// `dup` returns the new descriptor. `dup2` and `dup3` name it in argument 1.
pub(super) fn apply_dup(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    if event.syscall_name == "fcntl" && succeeded(invocation) {
        if let Some(args) = call_args(invocation) {
            if args[1] == 2 {
                let owner = table_owner(files, invocation.task_cookie, event.tid);
                let key = (owner.0, owner.1, args[0]);
                if args[2] & 1 != 0 {
                    files.cloexec.insert(key);
                } else {
                    files.cloexec.remove(&key);
                }
                return;
            }
        }
    }
    let kind = match event.syscall_name.as_str() {
        "dup" => DupKind::Return,
        "dup2" | "dup3" => DupKind::Argument,
        "fcntl" if call_args(invocation).is_some_and(|args| matches!(args[1], 0 | 1030)) => {
            DupKind::Return
        }
        _ => return,
    };
    if !succeeded(invocation) {
        return;
    }
    let Some(args) = call_args(invocation) else {
        return;
    };
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    let new_fd = match kind {
        DupKind::Return => result as u64,
        DupKind::Argument => args[1],
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    let Some(path) = files.opened.get(&(cookie, pid, args[0])).cloned() else {
        files.opened.remove(&(cookie, pid, new_fd));
        return;
    };
    files.opened.insert((cookie, pid, new_fd), path);
    let key = (cookie, pid, new_fd);
    if new_fd != args[0] {
        files.cloexec.remove(&key);
    }
    if event.syscall_name == "dup3" && args[2] & 0x80000 != 0 {
        files.cloexec.insert(key);
    }
    if event.syscall_name == "fcntl" && args[1] == 1030 {
        files.cloexec.insert(key);
    }
}

/// One cookie per pid when every event for that pid shares it. Two cookies
/// for one pid are not a guess: the caller uses 0.
#[cfg(test)]
pub(super) fn task_cookies(
    invocations: &[InvocationSummary],
) -> std::collections::BTreeMap<u32, u64> {
    let mut sets: std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>> =
        std::collections::BTreeMap::new();
    for invocation in invocations {
        for event in invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
        {
            if event.tid == 0 {
                continue;
            }
            sets.entry(event.tid)
                .or_default()
                .insert(invocation.task_cookie);
        }
    }
    sets.into_iter()
        .filter_map(|(pid, cookies)| {
            (cookies.len() == 1).then(|| (pid, cookies.into_iter().next().unwrap()))
        })
        .collect()
}

/// A successful `close` drops that task's descriptor only.
pub(super) fn forget_closed(
    files: &mut FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
) {
    if matches!(event.syscall_name.as_str(), "execve" | "execveat") && succeeded(invocation) {
        detach_files(files, invocation.task_cookie, event.tid);
        let owner = table_owner(files, invocation.task_cookie, event.tid);
        let closed = files
            .cloexec
            .iter()
            .filter(|(cookie, tid, _)| (*cookie, *tid) == owner)
            .copied()
            .collect::<Vec<_>>();
        for key in closed {
            files.opened.remove(&key);
            files.cloexec.remove(&key);
        }
        return;
    }
    if event.syscall_name == "close_range" && succeeded(invocation) {
        if let Some(args) = call_args(invocation) {
            if args[2] & 2 != 0 {
                detach_files(files, invocation.task_cookie, event.tid);
            }
            let owner = table_owner(files, invocation.task_cookie, event.tid);
            let keys = files
                .opened
                .keys()
                .filter(|(cookie, tid, fd)| {
                    (*cookie, *tid) == owner && *fd >= args[0] && *fd <= args[1]
                })
                .copied()
                .collect::<Vec<_>>();
            for key in keys {
                if args[2] & 4 != 0 {
                    files.cloexec.insert(key);
                } else {
                    files.opened.remove(&key);
                    files.cloexec.remove(&key);
                }
            }
        }
        return;
    }
    if event.syscall_name != "close" {
        return;
    }
    if invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .is_some_and(|ret| ret < 0)
    {
        return;
    }
    let Some(fd) = fd_argument(invocation, event) else {
        return;
    };
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    files.opened.remove(&(cookie, pid, fd));
    files.cloexec.remove(&(cookie, pid, fd));
}

fn detach_files(files: &mut FdState, cookie: u64, tid: u32) {
    let owner = table_owner(files, cookie, tid);
    if owner == (cookie, tid) {
        let sharers = files
            .share
            .keys()
            .copied()
            .filter(|(c, t)| table_owner(files, *c, *t) == owner)
            .collect::<Vec<_>>();
        if let Some(new_owner) = sharers.first().copied() {
            copy_files(files, owner, new_owner);
            files.share.remove(&new_owner);
            for sharer in sharers.into_iter().skip(1) {
                files.share.insert(sharer, new_owner);
            }
        }
    } else {
        copy_files(files, owner, (cookie, tid));
        files.share.remove(&(cookie, tid));
    }
}

fn copy_files(files: &mut FdState, source: (u64, u32), target: (u64, u32)) {
    let entries = files
        .opened
        .iter()
        .filter(|((cookie, tid, _), _)| (*cookie, *tid) == source)
        .map(|((_, _, fd), path)| (*fd, path.clone()))
        .collect::<Vec<_>>();
    for (fd, path) in entries {
        files.opened.insert((target.0, target.1, fd), path);
        if files.cloexec.contains(&(source.0, source.1, fd)) {
            files.cloexec.insert((target.0, target.1, fd));
        }
    }
    files.journal.copy_sockets(source, target);
}

/// Snapshot the parent's open descriptors onto the new process. The child
/// keeps its own entries; a later close does not edit the parent.
pub(super) fn inherit_open_fds(
    files: &mut FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
    cookies: &std::collections::BTreeMap<u32, u64>,
) {
    let name = event.syscall_name.as_str();
    if !matches!(name, "fork" | "vfork" | "clone" | "clone3")
        || (name == "clone3" && clone3_flags(invocation).is_none())
    {
        return;
    }
    let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
        return;
    };
    if result <= 0 {
        return;
    }
    let Some(child_pid) = u32::try_from(result).ok() else {
        return;
    };
    let child_cookie = cookies.get(&child_pid).copied().unwrap_or(0);
    if child_pid == event.tid && child_cookie == invocation.task_cookie {
        return;
    }
    let parent = table_owner(files, invocation.task_cookie, event.tid);
    if shares_files(invocation, event) {
        files.share.insert((child_cookie, child_pid), parent);
    } else {
        copy_files(files, parent, (child_cookie, child_pid));
    }
    let directory = fs_owner(files, invocation.task_cookie, event.tid);
    if shares_fs(invocation, event) {
        files.fs_share.insert((child_cookie, child_pid), directory);
    } else if let Some(cwd) = files.cwd.get(&directory).cloned() {
        files.cwd.entry((child_cookie, child_pid)).or_insert(cwd);
        if files.cwd_unverified.contains(&directory) {
            files.cwd_unverified.insert((child_cookie, child_pid));
        }
    }
}

fn shares_files(invocation: &InvocationSummary, event: &EventSummary) -> bool {
    clone_flag(invocation, event, CLONE_FILES)
}

fn shares_fs(invocation: &InvocationSummary, event: &EventSummary) -> bool {
    clone_flag(invocation, event, CLONE_FS)
}

fn clone_flag(invocation: &InvocationSummary, event: &EventSummary, flag: u64) -> bool {
    match event.syscall_name.as_str() {
        "clone" => call_args(invocation).is_some_and(|args| clone_flags(&args) & flag != 0),
        "clone3" => clone3_flags(invocation).is_some_and(|flags| flags & flag != 0),
        _ => false,
    }
}

pub(super) fn clone3_flags(invocation: &InvocationSummary) -> Option<u64> {
    let field = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(invocation.async_events.iter())
        .flat_map(|event| event.fields.iter())
        .find(|field| field.key.contains("clone_args") && field.key.contains("flags"))?;
    let bytes = trace::covered_preview(field);
    match bytes.len() {
        4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

pub(super) fn displayed_path(
    invocation: &InvocationSummary,
    event: &EventSummary,
    files: &FdState,
) -> String {
    if matches!(event.syscall_name.as_str(), "renameat" | "renameat2") {
        let args = call_args(invocation);
        let old = named_path(invocation, event, &["oldname", "old_path"])
            .map(|path| {
                resolve_path_dirfd(&path, invocation, event, files, args.map(|args| args[0]))
            })
            .unwrap_or_else(|| "—".into());
        let new = named_path(invocation, event, &["newname", "new_path"])
            .map(|path| {
                resolve_path_dirfd(&path, invocation, event, files, args.map(|args| args[2]))
            })
            .unwrap_or_else(|| "—".into());
        return format!("{old} → {new}");
    }
    if event.syscall_name == "memfd_create" {
        return event
            .fields
            .iter()
            .find_map(path_text)
            .map(|name| format!("memfd:{name}"))
            .unwrap_or_else(|| "memfd:unnamed".into());
    }
    let own = path_list(invocation);
    if !own.is_empty() {
        return own
            .iter()
            .enumerate()
            .map(|(index, path)| {
                if index == 1 && matches!(event.syscall_name.as_str(), "renameat" | "renameat2") {
                    resolve_path_dirfd(
                        path,
                        invocation,
                        event,
                        files,
                        call_args(invocation).map(|args| args[2]),
                    )
                } else {
                    resolve_path(path, invocation, event, files)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
    }
    if matches!(event.syscall_name.as_str(), "mmap" | "mmap2") {
        let anonymous = call_args(invocation)
            .is_some_and(|args| args.get(3).is_some_and(|flags| flags & MAP_ANONYMOUS != 0));
        if anonymous {
            return "—".into();
        }
        if let Some(fd) = fd_argument(invocation, event) {
            if fd != u64::MAX {
                let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
                if let Some(path) = files.opened.get(&(cookie, pid, fd)) {
                    return path.clone();
                }
            }
        }
        return "—".into();
    }
    if let Some(fd) = fd_argument(invocation, event) {
        let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
        if let Some(path) = files.opened.get(&(cookie, pid, fd)) {
            return path.clone();
        }
    }
    if let Some(path) = identity_path(files, invocation) {
        return path.to_owned();
    }
    // Trace text is not a path. An uncaptured filename stays unknown.
    "—".into()
}

/// Remember the name of a file the guest identified, when a call opened it or
/// renamed it, so a later call that reaches the same file by no descriptor of
/// the run (a slot of an io_uring registered table) can still be named.
fn remember_identity(files: &mut FdState, invocation: &InvocationSummary, event: &EventSummary) {
    let Some(id) = kernel_records::file_id(invocation) else {
        return;
    };
    if !succeeded(invocation) {
        return;
    }
    let name = event.syscall_name.as_str();
    let path = if OPEN_NAMES.contains(&name) {
        Some(displayed_path(invocation, event, files))
    } else if name.starts_with("rename") {
        sigma_events::paths(files, invocation, event)
            .into_iter()
            .find(|used| used.role == sigma_events::Role::New)
            .map(|used| used.name)
    } else {
        None
    };
    if let Some(path) = path.filter(|path| path != "—") {
        if files.identity_paths.len() < 65536 || files.identity_paths.contains_key(&id.key) {
            files.identity_paths.insert(id.key, path);
        }
    }
}

/// The name of the file a call acted on, from the identity the guest recorded
/// for it, when an earlier open or rename of the run named that file.
pub(super) fn identity_path<'a>(
    files: &'a FdState,
    invocation: &InvocationSummary,
) -> Option<&'a str> {
    kernel_records::file_id(invocation)
        .and_then(|id| files.identity_paths.get(&id.key))
        .map(String::as_str)
}

fn resolve_path(
    path: &str,
    invocation: &InvocationSummary,
    event: &EventSummary,
    files: &FdState,
) -> String {
    resolve_path_dirfd(
        path,
        invocation,
        event,
        files,
        dirfd_argument(invocation, event),
    )
}

pub(super) fn resolve_path_dirfd(
    path: &str,
    invocation: &InvocationSummary,
    event: &EventSummary,
    files: &FdState,
    dirfd: Option<u64>,
) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    let (cookie, pid) = table_owner(files, invocation.task_cookie, event.tid);
    if event.syscall_name.ends_with("at") || event.syscall_name.ends_with("at2") {
        if let Some(dirfd) = dirfd {
            if dirfd != AT_FDCWD {
                return match files.opened.get(&(cookie, pid, dirfd)) {
                    Some(base) if base.starts_with('/') => format!(
                        "{}/{path} (lexical dirfd path; symlinks unknown)",
                        base.split(" (lexical").next().unwrap_or(base)
                    ),
                    _ => format!("{path} (relative, dirfd not recorded)"),
                };
            }
        }
    }
    let directory = fs_owner(files, invocation.task_cookie, event.tid);
    match files.cwd.get(&directory) {
        Some(cwd) => format!("{cwd}/{path} (lexical cwd path; symlinks unknown)"),
        None => format!("{path} (relative, cwd not recorded)"),
    }
}

pub(super) fn dirfd_argument(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    let args = call_args(invocation)?;
    let index = (0..args.len()).find(|index| {
        matches!(
            trace::argument_name(event.syscall_nr, *index),
            "dfd" | "dirfd" | "olddfd"
        )
    })?;
    (index < args.len()).then_some(args[index])
}

pub(super) fn path_key(key: &str) -> bool {
    key.split(['.', '[', ']']).any(|part| {
        matches!(
            part,
            "path" | "pathname" | "filename" | "oldname" | "newname" | "old_path" | "new_path"
        )
    })
}

pub(super) fn named_path(
    invocation: &InvocationSummary,
    event: &EventSummary,
    names: &[&str],
) -> Option<String> {
    let arguments = (0..6)
        .filter(|index| names.contains(&trace::argument_name(event.syscall_nr, *index)))
        .map(|index| format!("arg{index}."))
        .collect::<Vec<_>>();
    invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| &event.fields)
        .filter(|field| {
            path_key(&field.key)
                && (field.key.split('.').any(|part| names.contains(&part))
                    || arguments.iter().any(|prefix| field.key.starts_with(prefix)))
        })
        .find_map(path_text)
}

pub(super) fn path_text(field: &antinomie_monitor_core::FieldSummary) -> Option<String> {
    if field.capture_error != 0 {
        return None;
    }
    let bytes = trace::covered_preview(field);
    // A preview prefix is not a complete path. Preserve legitimate spaces and
    // '=' characters instead of rejecting names based on their appearance.
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return None;
    }
    Some(text.to_string())
}

pub(super) fn path_list(invocation: &InvocationSummary) -> Vec<String> {
    let mut paths = Vec::new();
    for event in invocation.entry.iter().chain(invocation.exit.iter()) {
        for field in &event.fields {
            if !path_key(&field.key)
                && !(event.syscall_name == "getcwd" && field.key.split('.').any(|key| key == "buf"))
            {
                continue;
            }
            if let Some(text) = path_text(field) {
                if !paths.contains(&text) {
                    paths.push(text);
                }
            }
        }
    }
    paths
}
