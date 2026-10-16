// SPDX-License-Identifier: MIT
//! Normalize facts already reconstructed by triage; do not infer missing fields.
use super::*;
use antinomie_monitor_core::analysis::detection::{Event, EventJournal, Evidence};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Counts {
    pub calls: u64,
    pub findings: u64,
    pub opened: u64,
    pub reads: u64,
    pub changed: u64,
    pub http: u64,
    pub dns: u64,
}

fn text(fields: &mut BTreeMap<String, serde_json::Value>, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| {
        !value.is_empty()
            && *value != "—"
            && !value.contains("(relative,")
            && !value.contains("path unavailable")
    }) {
        fields.insert(name.into(), value.into());
    }
}

pub(super) fn call(
    journal: &mut EventJournal,
    files: &FdState,
    call: &InvocationSummary,
    event: &EventSummary,
) -> Result<(), String> {
    let mut fields = BTreeMap::from([
        ("ProcessId".into(), serde_json::json!(event.pid)),
        ("ThreadId".into(), serde_json::json!(event.tid)),
        ("Syscall".into(), serde_json::json!(event.syscall_name)),
        ("Operation".into(), serde_json::json!(event.syscall_name)),
    ]);
    text(&mut fields, "Image", process_image(files, event));
    let ret = call.exit.as_ref().and_then(|exit| exit.result);
    if let Some(ret) = ret {
        fields.insert("Result".into(), ret.into());
    }
    let evidence = Evidence::Call {
        stream: call.stream_id,
        cookie: call.task_cookie,
        call: call.call_id,
    };
    let mut emit = |category: &str, fields: BTreeMap<String, serde_json::Value>| {
        journal.push(Event {
            category: category.into(),
            fields,
            evidence: evidence.clone(),
        })
    };
    if committed_exec(call) {
        // argv previews do not prove the complete vector was captured. Exclude
        // CommandLine rather than letting negation match an omitted argument.
        emit("process_creation", fields.clone())?;
    }
    if ret.is_some_and(|ret| ret >= 0)
        && call_args(call).and_then(|args| bpf_command(event, args)) == Some("BPF_PROG_LOAD")
    {
        let mut fields = fields.clone();
        fields.insert("BpfCommand".into(), "BPF_PROG_LOAD".into());
        emit("antinomie_bpf", fields)?;
    }
    let operation = event.syscall_name.as_str();
    let file_operation = OPEN_NAMES.contains(&operation)
        || CHANGE_NAMES.contains(&operation)
        || matches!(
            operation,
            "read" | "pread64" | "readv" | "preadv" | "preadv2"
        );
    if file_operation {
        let path = displayed_path(call, event, files);
        text(&mut fields, "TargetFilename", Some(&path));
        if matches!(
            operation,
            "read"
                | "pread64"
                | "readv"
                | "preadv"
                | "preadv2"
                | "write"
                | "pwrite64"
                | "writev"
                | "pwritev"
                | "pwritev2"
        ) {
            if let Some(ret) = ret.filter(|ret| *ret >= 0) {
                fields.insert("TransferredSize".into(), ret.into());
            }
        }
        emit("file_access", fields.clone())?;
        if ret.is_some_and(|ret| ret >= 0) {
            let mode = call_args(call).and_then(|args| match operation {
                "chmod" | "fchmod" => Some(args[1]),
                "fchmodat" | "fchmodat2" => Some(args[2]),
                _ => None,
            });
            if let Some(mode) = mode {
                let mut metadata = fields.clone();
                metadata.insert("Mode".into(), mode.into());
                metadata.insert("Setuid".into(), (mode & 0o4000 != 0).into());
                emit("antinomie_file_metadata", metadata)?;
            }
            if OPEN_NAMES.contains(&operation)
                && open_flags(call, event).is_some_and(|flags| flags & 0xc0 == 0xc0)
            {
                emit("file_event", fields.clone())?;
            }
            if matches!(operation, "unlink" | "unlinkat" | "rmdir") {
                emit("file_delete", fields.clone())?;
            }
            if matches!(operation, "rename" | "renameat" | "renameat2") {
                text(
                    &mut fields,
                    "SourceFilename",
                    named_path(call, event, &["oldname", "old_path"]).as_deref(),
                );
                fields.remove("TargetFilename");
                text(
                    &mut fields,
                    "TargetFilename",
                    named_path(call, event, &["newname", "new_path"]).as_deref(),
                );
                emit("file_rename", fields)?;
            }
        }
    }
    Ok(())
}

pub(super) fn packet(
    journal: &mut EventJournal,
    path: &Path,
    row: &[Cell],
    http: bool,
    destination: &str,
    port: &str,
) -> Result<(), String> {
    let values = row
        .first()
        .map(|cell| cell.values.as_slice())
        .unwrap_or_default();
    let Some(frame) = files::number(values, "frame.number") else {
        return Ok(());
    };
    let mut fields = BTreeMap::new();
    let mapping: &[(&str, &str)] = if http {
        &[
            ("http.method", "HttpMethod"),
            ("http.host", "HttpHost"),
            ("http.uri", "HttpUri"),
            ("http.status", "ResponseCode"),
        ]
    } else {
        &[
            ("dns.name", "QueryName"),
            ("dns.type", "QueryType"),
            ("dns.rcode", "ResponseCode"),
        ]
    };
    for (source, target) in mapping {
        if let Some((_, value)) = values.iter().find(|(name, _)| name == source) {
            match value {
                RowValue::Text(value) => {
                    fields.insert((*target).into(), value.clone().into());
                }
                RowValue::Number(value) => {
                    if let Ok(value) = i64::try_from(*value) {
                        fields.insert((*target).into(), value.into());
                    }
                }
                _ => {}
            }
        }
    }
    text(&mut fields, "DestinationIp", Some(destination));
    if let Ok(port) = port.parse::<u16>() {
        fields.insert("DestinationPort".into(), port.into());
    }
    journal.push(Event {
        category: if http { "http_request" } else { "dns_query" }.into(),
        fields,
        evidence: Evidence::Packet {
            capture: path.to_path_buf(),
            frame,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::analysis::detection::Identity;
    #[test]
    fn normalized_exec_requires_commit_and_never_treats_partial_argv_as_a_command_line() {
        let temp = PacketSpool::new().unwrap();
        let identity = Identity {
            vm_id: "v".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            root_cookie: 1,
        };
        let mut journal = EventJournal::new(&temp.directory, &identity).unwrap();
        let mut files = FdState::default();
        let mut exec = super::super::tests::path_call(1, 59, "execve", 0, "/bin/sh");
        exec.call_id = u64::MAX;
        observe_processes(&mut files.process_images, std::slice::from_ref(&exec));
        call(
            &mut journal,
            &files,
            &exec,
            trace::representative(&exec).unwrap(),
        )
        .unwrap();
        let failed = super::super::tests::path_call(1, 59, "execve", -2, "/bin/other");
        call(
            &mut journal,
            &files,
            &failed,
            trace::representative(&failed).unwrap(),
        )
        .unwrap();
        let summary = journal.finish(true).unwrap();
        assert_eq!(summary.events, 1);
        let data = std::fs::read_to_string(temp.directory.join(engine_file())).unwrap();
        let event: serde_json::Value = serde_json::from_str(data.lines().nth(1).unwrap()).unwrap();
        assert_eq!(event["event"]["fields"]["Image"], "/bin/sh");
        assert!(event["event"]["fields"].get("CommandLine").is_none());
        assert_eq!(event["event"]["evidence"]["call"].as_u64(), Some(u64::MAX));
    }
    fn engine_file() -> &'static str {
        antinomie_monitor_core::analysis::detection::JOURNAL_FILE
    }
    #[test]
    fn path_evidence_preserves_valid_names_and_excludes_unterminated_previews() {
        let full = super::super::tests::captured("arg0.pathname", "", b" /tmp/a=b \0");
        assert_eq!(path_text(&full).as_deref(), Some(" /tmp/a=b "));
        let mut prefix = full;
        prefix.preview.pop();
        prefix.ranges = vec![(0, prefix.preview.len() as u64)];
        prefix.complete = false;
        assert!(path_text(&prefix).is_none());
    }
}
