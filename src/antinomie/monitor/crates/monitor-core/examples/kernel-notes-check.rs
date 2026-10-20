// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Print the credential and file-hash records the guest kernel wrote for each
//! call of a saved run, read back through the same archive pages the app uses.
//!
//! usage: kernel-notes-check RUN_DIR
//!
//! One line per record: the call (pid, syscall, result) and the decoded record.
//! Exits nonzero when a record does not decode or the pages report issues.
use antinomie_monitor_core::{kernel_notes, recording::Recording};
use std::{path::PathBuf, sync::atomic::AtomicBool};

fn main() {
    let Some(directory) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: kernel-notes-check RUN_DIR");
        std::process::exit(2);
    };
    let recording = Recording {
        directory,
        manifest: serde_json::Value::Null,
        events: Vec::new(),
    };
    let cancel = AtomicBool::new(false);
    let (mut offset, mut calls, mut undecoded, mut issues) = (0, 0u64, 0u64, 0usize);
    loop {
        let page = recording
            .invocation_page_cancellable(offset, 256, &cancel)
            .unwrap_or_else(|error| {
                eprintln!("{error}");
                std::process::exit(1);
            });
        issues += page.issues.len();
        for call in &page.invocations {
            calls += 1;
            let Some(event) = call.entry.as_ref().or(call.exit.as_ref()) else {
                continue;
            };
            let result = call.exit.as_ref().and_then(|exit| exit.result);
            for note in &call.kernel_notes {
                let head = format!(
                    "pid {} tid {} call {} {} -> {result:?} at {} ms",
                    event.pid,
                    event.tid,
                    call.call_id,
                    event.syscall_name,
                    note.timestamp_ns / 1_000_000
                );
                if let Some(creds) = kernel_notes::credentials(note) {
                    let login = creds.auid.map_or("unset".to_owned(), |id| id.to_string());
                    println!(
                        "{head}: CREDS {:?} uid {} euid {} suid {} fsuid {} gid {} egid {} sgid {} fsgid {} auid {login} audit {} caps eff {:x} perm {:x} inh {:x} bset {} amb {} securebits {}",
                        creds.change,
                        creds.uid,
                        creds.euid,
                        creds.suid,
                        creds.fsuid,
                        creds.gid,
                        creds.egid,
                        creds.sgid,
                        creds.fsgid,
                        creds.audit,
                        creds.cap_effective,
                        creds.cap_permitted,
                        creds.cap_inheritable,
                        creds
                            .cap_bounding
                            .map_or("-".into(), |set| format!("{set:x}")),
                        creds
                            .cap_ambient
                            .map_or("-".into(), |set| format!("{set:x}")),
                        creds
                            .securebits
                            .map_or("-".into(), |bits| format!("{bits:#x}"))
                    );
                } else if let Some(hash) = kernel_notes::file_hash(note) {
                    println!(
                        "{head}: HASH {:?} {:?} size {} sha256 {} skipped {:?} changed {} interpreter {} cached {} queue_us {} hash_us {} lost {} error {}",
                        hash.kind,
                        hash.status,
                        hash.size,
                        hash.sha256_hex().unwrap_or_else(|| "-".into()),
                        hash.skipped(),
                        hash.changed,
                        hash.interpreter,
                        hash.cached,
                        hash.queue_us,
                        hash.hash_us,
                        hash.lost,
                        hash.error
                    );
                } else {
                    undecoded += 1;
                    println!(
                        "{head}: UNDECODED note {:?}",
                        note.fields.first().map(|f| &f.key)
                    );
                }
            }
        }
        match page.next_offset {
            Some(next) => offset = next,
            None => break,
        }
    }
    println!("calls {calls} undecoded {undecoded} page issues {issues}");
    if undecoded > 0 {
        std::process::exit(1);
    }
}
