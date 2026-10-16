// SPDX-License-Identifier: MIT
//! File activity rows built from recorded calls.
use super::*;

#[cfg(test)]
pub(super) fn file_rows(invocations: &[InvocationSummary], names: &[&str]) -> LimitedRows {
    let mut limited = LimitedRows {
        rows: Vec::new(),
        stopped_early: false,
    };
    // Successful opens are remembered for this slice only. A fork, vfork, or
    // process clone copies the parent's descriptors unless CLONE_FILES shares
    // one table. CLONE_FS shares the working directory; CLONE_FILES does not.
    // Later closes change only the task that owns the descriptor table.
    let mut files = FdState::default();
    let cookies = task_cookies(invocations);
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        remember_cwd(&mut files, invocation, event);
        remember_open(&mut files, invocation, event);
        apply_dup(&mut files, invocation, event);
        forget_closed(&mut files, invocation, event);
        inherit_open_fds(&mut files, invocation, event, &cookies);
        if let Some(row) = file_event_row(&files, invocation, event, names) {
            if !push_limited(&mut limited, row) {
                break;
            }
        }
    }
    limited
}

pub(super) fn file_event_row(
    files: &FdState,
    invocation: &InvocationSummary,
    event: &EventSummary,
    names: &[&str],
) -> Option<Vec<Cell>> {
    let changed_view = names.contains(&"write");
    let flags = open_flags(invocation, event);
    let creates = OPEN_NAMES.contains(&event.syscall_name.as_str())
        && flags.is_some_and(|flags| flags & (0x40 | 0x200) != 0);
    if !names.iter().any(|name| event.syscall_name == *name) && !(changed_view && creates) {
        return None;
    }
    if matches!(event.syscall_name.as_str(), "mmap" | "mmap2") {
        let writable = call_args(invocation).is_some_and(|args| args[2] & 2 != 0);
        let private = call_args(invocation)
            .and_then(|args| args.get(3).copied())
            .is_some_and(|flags| flags & MAP_PRIVATE != 0);
        if !writable || private {
            return None;
        }
    }
    let path = displayed_path(invocation, event, files);
    let result = invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "—".into());
    let mut row = vec![
        cell(
            if path.is_empty() {
                "—".to_string()
            } else {
                path
            },
            theme::text(),
            true,
        ),
        cell(
            process_identity(event.pid, event.tid, process_image(files, event)),
            theme::text(),
            true,
        ),
        cell(
            {
                let fd = file_fd(invocation, event);
                fd.parse()
                    .ok()
                    .and_then(crate::values::standard_fd_name)
                    .map_or_else(|| fd.clone(), |name| format!("{fd} ({name})"))
            },
            theme::value(theme::ValueKind::Number),
            true,
        ),
        cell(
            event.syscall_name.clone(),
            theme::value(theme::ValueKind::Name),
            false,
        ),
        cell(result, theme::text(), true),
        cell(file_outcome(invocation), theme::text(), false),
    ];
    let paths = path_list(invocation);
    let ret = invocation.exit.as_ref().and_then(|exit| exit.result);
    let writing = matches!(
        event.syscall_name.as_str(),
        "write" | "writev" | "pwrite64" | "pwritev" | "pwritev2"
    );
    let written = writing.then_some(ret).flatten().filter(|ret| *ret >= 0);
    let requested = matches!(event.syscall_name.as_str(), "write" | "pwrite64")
        .then(|| call_args(invocation).map(|args| args[2]))
        .flatten();
    let access = flags
        .map(|flags| {
            format!(
                "{} flags {flags:#x}",
                match flags & 3 {
                    0 => "read",
                    1 => "write",
                    2 => "read/write",
                    _ => "unknown",
                }
            )
        })
        .unwrap_or_else(|| "—".into());
    row[0].values = vec![
        (
            "process.exe",
            process_image(files, event)
                .map_or(RowValue::Missing, |image| RowValue::Text(image.into())),
        ),
        (
            "file.path",
            paths
                .first()
                .cloned()
                .or_else(|| (row[0].text != "—").then(|| row[0].text.clone()))
                .map_or(RowValue::Missing, RowValue::Text),
        ),
        (
            "file.old_path",
            if matches!(
                event.syscall_name.as_str(),
                "rename" | "renameat" | "renameat2"
            ) {
                named_path(invocation, event, &["oldname", "old_path"])
                    .map_or(RowValue::Missing, RowValue::Text)
            } else {
                RowValue::Missing
            },
        ),
        (
            "file.new_path",
            if matches!(
                event.syscall_name.as_str(),
                "rename" | "renameat" | "renameat2"
            ) {
                named_path(invocation, event, &["newname", "new_path"])
                    .map_or(RowValue::Missing, RowValue::Text)
            } else {
                RowValue::Missing
            },
        ),
        (
            "file.fd",
            file_fd(invocation, event)
                .parse::<i128>()
                .map_or(RowValue::Missing, RowValue::Number),
        ),
        ("file.operation", RowValue::Text(event.syscall_name.clone())),
        (
            "file.access",
            if flags.is_some() {
                RowValue::Text(access.clone())
            } else {
                RowValue::Missing
            },
        ),
        (
            "file.success",
            ret.map_or(RowValue::Missing, |ret| RowValue::Bool(ret >= 0)),
        ),
        (
            "file.written_size",
            written.map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
        ),
        (
            "file.requested_size",
            requested.map_or(RowValue::Missing, |size| RowValue::Number(i128::from(size))),
        ),
        (
            "file.offset",
            if event.syscall_name == "pwrite64" {
                call_args(invocation).map_or(RowValue::Missing, |args| {
                    RowValue::Number(i128::from(args[3] as i64))
                })
            } else {
                RowValue::Missing
            },
        ),
        ("file.count", RowValue::Number(1)),
        ("process.pid", RowValue::Number(i128::from(event.pid))),
        ("process.tid", RowValue::Number(i128::from(event.tid))),
        (
            "process.cookie",
            RowValue::Number(i128::from(invocation.task_cookie)),
        ),
        ("event.id", RowValue::Number(i128::from(invocation.call_id))),
        (
            "stream.id",
            RowValue::Number(i128::from(invocation.stream_id)),
        ),
        (
            "event.time_ns",
            RowValue::Number(i128::from(event.timestamp_ns)),
        ),
        (
            "syscall.ret",
            ret.map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
        ),
    ];
    row.extend([
        cell(access, theme::text(), false),
        cell(event.timestamp_ns.to_string(), theme::text(), true),
        cell(
            written.map_or("—".into(), |size| size.to_string()),
            theme::text(),
            true,
        ),
        cell(
            requested.map_or("—".into(), |size| size.to_string()),
            theme::text(),
            true,
        ),
        cell(paths.join(" → "), theme::text(), true),
        cell(format!("call {}", invocation.call_id), theme::text(), true),
        cell(event.timestamp_ns.to_string(), theme::text(), true),
        cell("1", theme::text(), true),
    ]);
    Some(row)
}

pub(super) fn open_flags(invocation: &InvocationSummary, event: &EventSummary) -> Option<u64> {
    match event.syscall_name.as_str() {
        "creat" => Some(0x241),
        "open" => call_args(invocation).map(|args| args[1]),
        "openat" => call_args(invocation).map(|args| args[2]),
        "openat2" => invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .flat_map(|event| &event.fields)
            .find(|field| field.key.ends_with(".flags"))
            .and_then(|field| trace::covered_preview(field).get(..8))
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes),
        _ => None,
    }
}

pub(super) const OPEN_NAMES: &[&str] = &["open", "openat", "openat2", "creat", "memfd_create"];

pub(super) const CHANGE_NAMES: &[&str] = &[
    "write",
    "writev",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "truncate",
    "ftruncate",
    "mkdir",
    "mkdirat",
    "rmdir",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "fchmodat2",
    "msync",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "utime",
    "utimes",
    "futimesat",
    "utimensat",
    "mknod",
    "mknodat",
    "fallocate",
    "sendfile",
    "copy_file_range",
    "splice",
];
