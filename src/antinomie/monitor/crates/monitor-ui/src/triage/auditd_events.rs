// SPDX-License-Identifier: GPL-3.0-only
//! auditd-style records built from one traced call, so Sigma rules written for
//! `service: auditd` can be evaluated against a run.
//!
//! Field names are the ones those rules use (`type`, `a0`..`a3`, `exe`, `comm`,
//! `name`, `nametype`, `saddr`). The trace has no audit rules, so there is no
//! `key`; it has no file mode or inode; and a recording from a kernel that did
//! not write credential records has no `uid`, `euid`, `auid` or the rest of
//! that family. Those fields are left out, never filled in.
use super::kernel_records;
use super::sigma_events::{self, Role};
use super::*;
use std::collections::BTreeMap;

pub(super) struct Record {
    pub fields: BTreeMap<String, serde_json::Value>,
    pub inferred: Vec<String>,
}

/// Syscalls that get a SYSCALL record: the ones auditd rules for this kind of
/// telemetry watch. File calls are described by their PATH records instead.
const AUDITED: &[&str] = &[
    "execve",
    "execveat",
    "connect",
    "accept",
    "accept4",
    "bind",
    "sendto",
    "memfd_create",
    "mknod",
    "mknodat",
    "personality",
    "syslog",
    "ptrace",
    "init_module",
    "finit_module",
    "delete_module",
];

/// Calls that name a file; each name becomes a PATH record.
const PATH_CALLS: &[&str] = &[
    "open",
    "openat",
    "openat2",
    "creat",
    "mkdir",
    "mkdirat",
    "mknod",
    "mknodat",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "unlink",
    "unlinkat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "chmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "lchown",
    "fchownat",
    "truncate",
    "execve",
    "execveat",
];

/// Longest `comm` the kernel keeps.
const COMM_LEN: usize = 15;

/// Longest `PROCTITLE` the kernel logs, in bytes of the NUL-joined argv.
const PROCTITLE_LEN: usize = 128;

fn text(value: impl Into<String>) -> serde_json::Value {
    serde_json::Value::String(value.into())
}

fn record(kind: &str) -> Record {
    Record {
        fields: BTreeMap::from([("type".to_owned(), text(kind))]),
        inferred: Vec::new(),
    }
}

/// Records for one call. `image` is the executable the process last exec'd.
pub(super) fn records(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    image: Option<&str>,
) -> Vec<Record> {
    let name = event.syscall_name.as_str();
    let ret = call.exit.as_ref().and_then(|exit| exit.result);
    let mut found = Vec::new();
    if AUDITED.contains(&name) {
        found.push(syscall(files, call, event, image, ret));
    }
    if matches!(event.syscall_nr, 59 | 322) {
        found.extend(execve(call, event));
    }
    if let Some(address) = sigma_events::address_argument(event.syscall_nr)
        .and_then(|argument| sigma_events::address(call, event.syscall_nr, argument))
    {
        let mut sockaddr = record("SOCKADDR");
        let hex: String = address
            .raw
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();
        sockaddr.fields.insert("saddr".into(), text(hex));
        found.push(sockaddr);
    }
    if PATH_CALLS.contains(&name) {
        found.extend(path_records(files, call, event, ret));
    }
    // auditd writes the working directory and the command line with every
    // event that has a SYSCALL or PATH record.
    if !found.is_empty() {
        found.extend(cwd(files, call, event));
        found.extend(proctitle(files, call, event));
    }
    found
}

/// The `CWD` record: the working directory, exact while it is still the launch
/// directory and joined lexically after a `chdir`.
fn cwd(files: &FdState, call: &InvocationSummary, event: &EventSummary) -> Option<Record> {
    let (directory, lexical) = sigma_events::current_directory(files, call, event)?;
    let mut found = record("CWD");
    found.fields.insert("cwd".into(), text(directory));
    if lexical {
        found.inferred.push("cwd".into());
    }
    Some(found)
}

/// The `PROCTITLE` record: the arguments joined with NULs and hex-encoded,
/// cut at the length the kernel logs. An exec gives the new program's
/// arguments; any other call the ones its process was last seen to start with.
/// Without a complete argument vector there is no record: a partial one would
/// be a different title.
fn proctitle(files: &FdState, call: &InvocationSummary, event: &EventSummary) -> Option<Record> {
    let arguments = if matches!(event.syscall_nr, 59 | 322) {
        normalized::complete_argv(call, event)?
    } else {
        files
            .process_images
            .get(&TaskKey {
                pid: event.pid,
                cookie: event.task_cookie,
            })?
            .proctitle
            .clone()?
    };
    let mut joined = arguments.join("\0").into_bytes();
    joined.truncate(PROCTITLE_LEN);
    let hex: String = joined.iter().map(|byte| format!("{byte:02X}")).collect();
    let mut found = record("PROCTITLE");
    found.fields.insert("proctitle".into(), text(hex));
    Some(found)
}

fn syscall(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    image: Option<&str>,
    ret: Option<i64>,
) -> Record {
    let mut found = record("SYSCALL");
    let fields = &mut found.fields;
    fields.insert("Syscall".into(), text(&event.syscall_name));
    if let Some(args) = call_args(call) {
        for (index, value) in args.iter().take(4).enumerate() {
            fields.insert(format!("a{index}"), text(format!("{value:x}")));
        }
    }
    if let Some(ret) = ret {
        fields.insert("exit".into(), text(ret.to_string()));
        fields.insert("success".into(), text(if ret < 0 { "no" } else { "yes" }));
    }
    fields.insert("pid".into(), text(event.pid.to_string()));
    kernel_records::audit_ids(
        fields,
        kernel_records::credentials(files, call).as_ref(),
        files.journal.names.as_deref(),
    );
    if let Some(parent) = sigma_events::parent(files, event) {
        fields.insert("ppid".into(), text(parent.pid.to_string()));
    }
    // The recorded image is the path the program was started with: it may be
    // a link, so `exe` is not the resolved binary. `comm` is the name the
    // kernel gave the task at exec, which the program can later change.
    if let Some(image) = image.filter(|image| image.starts_with('/')) {
        fields.insert("exe".into(), text(image));
        found.inferred.push("exe".into());
    }
    if let Some(base) = image.and_then(|image| image.rsplit('/').find(|part| !part.is_empty())) {
        let comm: String = base.chars().take(COMM_LEN).collect();
        found.fields.insert("comm".into(), text(comm));
        found.inferred.push("comm".into());
    }
    found
}

fn execve(call: &InvocationSummary, event: &EventSummary) -> Option<Record> {
    let vector = normalized::argument_vector(call, event)?;
    let mut found = record("EXECVE");
    for (index, argument) in vector.arguments.iter().take(16).enumerate() {
        if let Some(argument) = argument {
            found.fields.insert(format!("a{index}"), text(argument));
        }
    }
    if vector.complete {
        found
            .fields
            .insert("argc".into(), text(vector.arguments.len().to_string()));
    }
    (found.fields.len() > 1).then_some(found)
}

fn path_records(
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
    ret: Option<i64>,
) -> Vec<Record> {
    let name = event.syscall_name.as_str();
    let succeeded = ret.is_some_and(|ret| ret >= 0);
    let created = sigma_events::creation(files, call, event, true);
    sigma_events::paths(files, call, event)
        .into_iter()
        .map(|used| {
            let mut found = record("PATH");
            found.fields.insert("name".into(), text(&used.name));
            if used.lexical {
                found.inferred.push("name".into());
            }
            // A failed call leaves the kind of name unknown; auditd would say
            // UNKNOWN or NORMAL depending on why it failed.
            if succeeded {
                let removed = matches!(name, "unlink" | "unlinkat" | "rmdir")
                    || used.role == Role::Old && name.starts_with("rename");
                let kind = if removed {
                    "DELETE"
                } else if used.role == Role::New
                    || created
                        .as_ref()
                        .is_some_and(|created| created.path == used.name)
                {
                    "CREATE"
                } else {
                    "NORMAL"
                };
                found.fields.insert("nametype".into(), text(kind));
                let by_inference = created.as_ref().is_some_and(|created| {
                    created.path == used.name && created.inferred.contains(&"IsNewFile")
                });
                if by_inference {
                    found.inferred.push("nametype".into());
                }
            }
            found
        })
        .collect()
}
