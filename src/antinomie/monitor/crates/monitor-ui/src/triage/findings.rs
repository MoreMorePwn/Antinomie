// SPDX-License-Identifier: GPL-3.0-only
//! Suspicious-behaviour findings and their confidence.
use super::*;

pub(super) fn hit(
    rule: &str,
    severity: &str,
    process: String,
    summary: String,
    source: &str,
    event: &EventSummary,
    invocation: &InvocationSummary,
) -> Finding {
    let color = if severity == "high" {
        theme::error()
    } else {
        theme::warn()
    };
    let time = if event.timestamp_ns == 0 {
        "—".to_string()
    } else {
        event.timestamp_ns.to_string()
    };
    Finding {
        key: trace::key(invocation),
        call_id: invocation.call_id,
        values: vec![
            ("finding.rule", RowValue::Text(rule.into())),
            ("finding.version", RowValue::Number(1)),
            ("finding.severity", RowValue::Text(severity.into())),
            (
                "finding.confidence",
                RowValue::Text(
                    if event.complete && invocation.exit.as_ref().is_some_and(|exit| exit.complete)
                    {
                        "high"
                    } else {
                        "limited"
                    }
                    .into(),
                ),
            ),
            ("finding.source", RowValue::Text(source.into())),
            ("finding.summary", RowValue::Text(summary.clone())),
            ("finding.attempted", RowValue::Bool(true)),
            (
                "finding.success",
                invocation
                    .exit
                    .as_ref()
                    .and_then(|exit| exit.result)
                    .map_or(RowValue::Missing, |ret| RowValue::Bool(ret >= 0)),
            ),
            (
                "syscall.ret",
                invocation
                    .exit
                    .as_ref()
                    .and_then(|exit| exit.result)
                    .map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
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
            ("process.pid", RowValue::Number(i128::from(event.pid))),
            ("process.tid", RowValue::Number(i128::from(event.tid))),
            (
                "process.cookie",
                RowValue::Number(i128::from(invocation.task_cookie)),
            ),
            ("entry.tag", RowValue::Missing),
        ],
        cells: vec![
            cell(rule, color, false),
            cell(severity, color, false),
            cell(process, theme::text(), true),
            cell(summary, theme::text(), false),
            cell(source, theme::muted(), false),
            cell(time, theme::text(), true),
            cell(confidence(invocation), theme::text(), false),
            cell(
                format!("syscall {} call {}", event.syscall_name, invocation.call_id),
                theme::text(),
                true,
            ),
            cell("1", theme::text(), true),
            cell(outcome(invocation), theme::text(), false),
        ],
    }
}

pub(super) fn confidence(invocation: &InvocationSummary) -> &'static str {
    if invocation
        .entry
        .as_ref()
        .is_some_and(|event| event.complete)
        && invocation.exit.as_ref().is_some_and(|event| event.complete)
    {
        "high"
    } else {
        "limited"
    }
}

pub(super) fn call_args(invocation: &InvocationSummary) -> Option<[u64; 6]> {
    invocation
        .entry
        .as_ref()
        .and_then(|event| event.args)
        .or_else(|| invocation.exit.as_ref().and_then(|event| event.args))
}

pub(super) fn outcome(invocation: &InvocationSummary) -> String {
    invocation
        .exit
        .as_ref()
        .and_then(|exit| exit.result)
        .map_or("exit not recorded".to_string(), |result| {
            if result < 0 {
                format!("failed ({result})")
            } else {
                format!("returned {result}")
            }
        })
}

/// `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER)`. Another level with optname 26 is not a match.
pub(super) fn classic_socket_filter(event: &EventSummary, args: [u64; 6]) -> bool {
    (event.syscall_name == "setsockopt" || event.syscall_nr == 54) && args[1] == 1 && args[2] == 26
}

pub(super) fn filter_findings(rows: Vec<Finding>, filter: &str) -> Vec<Finding> {
    let compiled = query::compile_table(filter, FINDING_FIELDS);
    rows.into_iter()
        .filter(|row| compiled.keep_table(&row.values))
        .collect()
}

pub(super) fn suspicious_rows(invocations: &[InvocationSummary]) -> Vec<Finding> {
    suspicious_rows_state(invocations, None)
}

pub(super) fn suspicious_rows_state(
    invocations: &[InvocationSummary],
    files: Option<&FdState>,
) -> Vec<Finding> {
    let mut rows = Vec::new();
    for invocation in invocations {
        let Some(event) = trace::representative(invocation) else {
            continue;
        };
        let args = event.args.or(call_args(invocation)).unwrap_or([0; 6]);
        let process = process_identity(
            event.pid,
            event.tid,
            files.and_then(|files| process_image(files, event)),
        );
        let outcome = outcome(invocation);
        if matches!(event.syscall_nr, 9 | 10) && args.get(2).is_some_and(|prot| prot & 7 == 7) {
            rows.push(hit(
                if succeeded(invocation) {
                    "memory.rwx"
                } else {
                    "memory.rwx_attempt"
                },
                "high",
                process.clone(),
                format!("{} prot {:#x}; {outcome}", event.syscall_name, args[2]),
                "MITRE ATT&CK T1055",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 59 | 322) {
            let paths = path_list(invocation);
            // T1059.004 is Unix Shell. A normal program execution is not that technique.
            let reference = paths
                .first()
                .filter(|path| unix_shell(path))
                .map_or("Observed process execution", |_| "MITRE ATT&CK T1059.004");
            rows.push(hit(
                "process.exec",
                "medium",
                process.clone(),
                format!("{} {outcome}", preview_line(event)),
                reference,
                event,
                invocation,
            ));
            if paths.first().is_some_and(|path| {
                matches!(
                    path.rsplit('/').next().unwrap_or(""),
                    "sh" | "bash"
                        | "dash"
                        | "zsh"
                        | "python"
                        | "python3"
                        | "perl"
                        | "ruby"
                        | "node"
                )
            }) {
                rows.push(hit(
                    "process.interpreter",
                    "medium",
                    process.clone(),
                    format!(
                        "captured interpreter/shell path {}; {outcome}",
                        paths.join(", ")
                    ),
                    "MITRE ATT&CK T1059",
                    event,
                    invocation,
                ));
            }
            let memfd = files.and_then(|files| {
                let owner = table_owner(files, invocation.task_cookie, event.tid);
                (event.syscall_nr == 322 && args[4] & 0x1000 != 0)
                    .then(|| files.opened.get(&(owner.0, owner.1, args[0])))
                    .flatten()
                    .filter(|path| path.starts_with("memfd:"))
                    .cloned()
            });
            if let Some(memfd) = memfd {
                rows.push(hit(
                    "process.memfd_exec",
                    "high",
                    process.clone(),
                    format!("execveat AT_EMPTY_PATH references observed {memfd}; {outcome}"),
                    "MITRE ATT&CK T1620",
                    event,
                    invocation,
                ));
            }
        }
        if event.syscall_nr == 101 {
            rows.push(hit(
                "process.ptrace",
                "high",
                process.clone(),
                outcome.clone(),
                "MITRE ATT&CK T1055.008",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 310 | 311) {
            rows.push(hit(
                "process.vm_rw",
                "high",
                process.clone(),
                format!("{} {outcome}", event.syscall_name),
                "MITRE ATT&CK T1055.009",
                event,
                invocation,
            ));
        }
        if event.syscall_nr == 319 {
            rows.push(hit(
                "process.memfd",
                "medium",
                process.clone(),
                outcome.clone(),
                "MITRE ATT&CK DET0508",
                event,
                invocation,
            ));
        }
        if matches!(event.syscall_nr, 175 | 313) {
            rows.push(hit(
                "persistence.module",
                "high",
                process.clone(),
                format!("{} {outcome}", event.syscall_name),
                "MITRE ATT&CK T1547.006",
                event,
                invocation,
            ));
        }
        // x86-64: setuid, setgid, setreuid, setregid, setresuid, setresgid,
        // setfsuid, setfsgid, capset. 130 is rt_sigsuspend, not a credential change.
        if matches!(
            event.syscall_nr,
            105 | 106 | 113 | 114 | 117 | 119 | 122 | 123 | 126
        ) {
            rows.push(hit(
                "privilege.change",
                "medium",
                process.clone(),
                format!("{} args {args:x?}; {outcome}", event.syscall_name),
                "Observed credential/capability change attempt",
                event,
                invocation,
            ));
        }
        if (event.syscall_nr == 317 && args[0] == 1)
            || (event.syscall_nr == 157 && args[0] == 22 && args[1] == 2)
        {
            rows.push(hit(
                "bpf.seccomp_filter",
                "medium",
                process.clone(),
                format!("classic seccomp filter installation; {outcome}"),
                "Linux seccomp filter interface",
                event,
                invocation,
            ));
        }
        let file_path = files
            .map(|files| displayed_path(invocation, event, files))
            .unwrap_or_else(|| path_list(invocation).join(", "));
        let notable = [
            "/etc/",
            "/root/.ssh/",
            "/var/spool/cron/",
            "/usr/lib/systemd/",
            "/lib/systemd/",
        ]
        .iter()
        .any(|prefix| file_path.starts_with(prefix))
            || (file_path.starts_with("/home/")
                && ["/.ssh/", "/.config/", "/.bashrc", "/.profile"]
                    .iter()
                    .any(|part| file_path.contains(part)));
        let write_like = matches!(
            event.syscall_name.as_str(),
            "write"
                | "writev"
                | "pwrite64"
                | "pwritev"
                | "pwritev2"
                | "truncate"
                | "ftruncate"
                | "rename"
                | "renameat"
                | "renameat2"
                | "unlink"
                | "unlinkat"
                | "chmod"
                | "fchmod"
                | "chown"
                | "fchown"
        ) || open_flags(invocation, event)
            .is_some_and(|flags| flags & (0x40 | 0x200) != 0);
        if notable && write_like {
            rows.push(hit(
                "persistence.config_write",
                "medium",
                process.clone(),
                format!(
                    "{} at notable configuration/persistence path {file_path}; {outcome}",
                    event.syscall_name
                ),
                "Observed configuration location; normal administrative use can be benign",
                event,
                invocation,
            ));
        }
        if let Some(command) = bpf::command_name(event) {
            if matches!(
                command,
                "BPF_PROG_LOAD" | "BPF_PROG_ATTACH" | "BPF_PROG_DETACH"
            ) {
                rows.push(hit(
                    "bpf.program",
                    "medium",
                    process.clone(),
                    format!("{command}; {outcome}"),
                    "Fournier, Afchain, Baubeau, Black Hat USA 2021",
                    event,
                    invocation,
                ));
            }
        }
        if classic_socket_filter(event, args) {
            rows.push(hit(
                "bpf.socket_filter",
                "medium",
                process.clone(),
                format!("classic socket filter; {outcome}"),
                "McCanne and Jacobson, USENIX 1993",
                event,
                invocation,
            ));
        }
    }
    rows
}
