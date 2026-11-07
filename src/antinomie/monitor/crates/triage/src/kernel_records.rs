// SPDX-License-Identifier: GPL-3.0-only
//! Credentials and file hashes the guest kernel recorded, turned into the
//! Sysmon `User`, `LogonId` and `Hashes` fields and the auditd `uid`, `euid`,
//! `auid` family.
//!
//! The kernel writes a task's credentials at its first traced call and after
//! every change, and the SHA-256 of an executed image or of a file about to be
//! deleted. Triage follows the credentials task by task and attaches the ones
//! in effect after a call to everything built from it, the way auditd reports
//! them at syscall exit. Nothing is filled in without a record:
//!
//! * `User` is the effective user's name in the guest, from the `/etc/passwd`
//!   of the base the VM's disk came from, read on the host (see
//!   `antinomie_monitor_core::guest_names`), and the numeric effective uid when
//!   no name is known. Nothing is assumed (not even `root` for 0).
//! * `LogonId` is the audit login uid, which is what Sysmon for Linux reports.
//!   It is empty when the guest never set one, or its kernel does not track it.
//! * `Hashes` is `SHA256=…`, from a record the guest wrote, and only for the
//!   file the call named. When the guest skipped or dropped a hash, or it
//!   would describe another file, `HashSkipped` says why. A file the run
//!   created gets the hash the guest took when its last writer closed it.
//! * auditd keeps every id numeric, as auditd writes them; with names known,
//!   the interpreted `UID`, `AUID`, `GID` and the rest of that family follow,
//!   as auditd's enriched format adds them (`unset`, `unknown(N)`).
use super::*;
use antinomie_monitor_core::api::FieldSummary;
use antinomie_monitor_core::guest_names::GuestNames;
use antinomie_monitor_core::kernel_notes::{
    self, Credentials, ExecImage, FileCopy, FileHash, FileId, FileMapped, FilePosition, HashKind,
};
use std::collections::BTreeMap;

/// Follow the credential records of one call. They apply from this call on.
pub(super) fn observe(files: &mut FdState, call: &InvocationSummary) {
    for creds in call
        .kernel_notes
        .iter()
        .filter_map(kernel_notes::credentials)
    {
        files.journal.set_credentials(call.task_cookie, creds);
    }
}

/// The credentials in effect after the call, when the guest recorded any.
pub(super) fn credentials(files: &FdState, call: &InvocationSummary) -> Option<Credentials> {
    files.journal.credentials(call.task_cookie)
}

/// The hash record of this call for `kind`, when one was recorded.
pub(super) fn file_hash(call: &InvocationSummary, kind: HashKind) -> Option<FileHash> {
    call.kernel_notes
        .iter()
        .filter_map(kernel_notes::file_hash)
        .find(|hash| hash.kind == kind)
}

/// The hashes of files the run wrote that the guest took when their last
/// writer closed them, attached to the call the closing task made last.
pub(super) fn write_hashes(call: &InvocationSummary) -> impl Iterator<Item = FileHash> + '_ {
    call.kernel_notes
        .iter()
        .filter_map(kernel_notes::file_hash)
        .filter(|hash| hash.kind == HashKind::Write && hash.file.is_some())
}

/// The identity of the file this call acted on, when the guest recorded one:
/// from a note of the call, or from the operand of an io_uring request.
pub(super) fn file_id(call: &InvocationSummary) -> Option<FileId> {
    call.kernel_notes.iter().find_map(kernel_notes::file_id)
}

/// The image an exec of this call loaded and the interpreter it named.
pub(super) fn exec_image(call: &InvocationSummary) -> Option<ExecImage> {
    call.kernel_notes.iter().find_map(kernel_notes::exec_image)
}

/// Where this read or write began in its file and what it moved, when the
/// guest recorded it (revision 18): exact for a shared descriptor or an append.
pub(super) fn file_position(call: &InvocationSummary) -> Option<FilePosition> {
    call.exit.as_ref().and_then(kernel_notes::file_position)
}

/// What this sendfile, splice, copy_file_range, clone or fallocate moved or
/// changed, when the guest recorded it (revision 18).
pub(super) fn file_copy(call: &InvocationSummary) -> Option<FileCopy> {
    call.exit.as_ref().and_then(kernel_notes::file_copy)
}

/// The pages written through shared mappings this call's task wrote back or
/// dropped dirty (revision 18), each with the field holding its bytes: those
/// published before the call's exit (`before_exit`), or after it (the
/// address space dropped when the task exited).
pub(super) fn file_mapped(
    call: &InvocationSummary,
    before_exit: bool,
) -> Vec<(FileMapped, Option<&FieldSummary>)> {
    let exit_seq = call.exit.as_ref().map(|exit| exit.event_seq);
    call.kernel_notes
        .iter()
        .filter(|note| exit_seq.is_some_and(|exit| note.event_seq < exit) == before_exit)
        .flat_map(|note| {
            kernel_notes::file_mapped(note)
                .into_iter()
                .map(move |record| {
                    let data = record
                        .data
                        .and_then(|id| note.fields.iter().find(|field| field.object_id == id));
                    (record, data)
                })
        })
        .collect()
}

/// Sysmon `User` and `LogonId`.
pub(super) fn sysmon_user(
    fields: &mut BTreeMap<String, serde_json::Value>,
    creds: Option<&Credentials>,
    names: Option<&GuestNames>,
) {
    let Some(creds) = creds else { return };
    let user = names
        .and_then(|names| names.user(creds.euid))
        .map_or_else(|| creds.euid.to_string(), str::to_owned);
    fields.insert("User".into(), user.into());
    if let Some(auid) = creds.auid {
        fields.insert("LogonId".into(), auid.into());
    }
}

/// Sysmon `Hashes`, or `HashSkipped` when the guest recorded none.
pub(super) fn sysmon_hashes(
    fields: &mut BTreeMap<String, serde_json::Value>,
    hash: Option<&FileHash>,
) {
    let Some(hash) = hash else { return };
    match (hash.sysmon(), hash.skipped()) {
        (Some(hashes), _) => {
            fields.insert("Hashes".into(), hashes.into());
        }
        (None, Some(why)) => {
            fields.insert("HashSkipped".into(), why.into());
        }
        (None, None) => {}
    }
}

/// The auditd credential fields. The kernel prints an unset login uid and
/// session as 4294967295, so a kernel that tracks them reports that value and
/// one that does not leaves both out.
pub(super) fn audit_ids(
    fields: &mut BTreeMap<String, serde_json::Value>,
    creds: Option<&Credentials>,
    names: Option<&GuestNames>,
) {
    let Some(creds) = creds else { return };
    if let Some(names) = names {
        interpreted_ids(fields, creds, names);
    }
    for (name, value) in [
        ("uid", creds.uid),
        ("euid", creds.euid),
        ("suid", creds.suid),
        ("fsuid", creds.fsuid),
        ("gid", creds.gid),
        ("egid", creds.egid),
        ("sgid", creds.sgid),
        ("fsgid", creds.fsgid),
    ] {
        fields.insert(name.into(), value.to_string().into());
    }
    if creds.audit {
        let unset = kernel_notes::UNSET;
        fields.insert(
            "auid".into(),
            creds.auid.unwrap_or(unset).to_string().into(),
        );
        fields.insert(
            "ses".into(),
            creds.session.unwrap_or(unset).to_string().into(),
        );
    }
}

/// auditd's interpreted id fields (`log_format = ENRICHED`): a name for each
/// id, `unknown(N)` for an id with none and `unset` for the unset login uid.
fn interpreted_ids(
    fields: &mut BTreeMap<String, serde_json::Value>,
    creds: &Credentials,
    names: &GuestNames,
) {
    let user = |id: u32| {
        names
            .user(id)
            .map_or_else(|| format!("unknown({id})"), str::to_owned)
    };
    let group = |id: u32| {
        names
            .group(id)
            .map_or_else(|| format!("unknown({id})"), str::to_owned)
    };
    for (name, value) in [
        ("UID", user(creds.uid)),
        ("EUID", user(creds.euid)),
        ("SUID", user(creds.suid)),
        ("FSUID", user(creds.fsuid)),
        ("GID", group(creds.gid)),
        ("EGID", group(creds.egid)),
        ("SGID", group(creds.sgid)),
        ("FSGID", group(creds.fsgid)),
    ] {
        fields.insert(name.into(), value.into());
    }
    if creds.audit {
        let auid = match creds.auid {
            None | Some(kernel_notes::UNSET) => "unset".to_owned(),
            Some(auid) => user(auid),
        };
        fields.insert("AUID".into(), auid.into());
    }
}
