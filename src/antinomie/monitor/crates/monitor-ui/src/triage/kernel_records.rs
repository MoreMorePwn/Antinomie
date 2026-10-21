// SPDX-License-Identifier: MIT
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
//! * `User` is the numeric effective uid. A guest's `/etc/passwd` is not
//!   available on the host without a guest agent, so no name is looked up or
//!   assumed (not even `root` for 0).
//! * `LogonId` is the audit login uid, which is what Sysmon for Linux reports.
//!   It is empty when the guest never set one, or its kernel does not track it.
//! * `Hashes` is `SHA256=…`, from a record the guest wrote, and only for the
//!   file the call named. When the guest skipped or dropped a hash, or it
//!   would describe another file, `HashSkipped` says why.
use super::*;
use antinomie_monitor_core::kernel_notes::{
    self, Credentials, ExecImage, FileHash, FileId, HashKind,
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

/// The identity of the file this call acted on, when the guest recorded one:
/// from a note of the call, or from the operand of an io_uring request.
pub(super) fn file_id(call: &InvocationSummary) -> Option<FileId> {
    call.kernel_notes.iter().find_map(kernel_notes::file_id)
}

/// The image an exec of this call loaded and the interpreter it named.
pub(super) fn exec_image(call: &InvocationSummary) -> Option<ExecImage> {
    call.kernel_notes.iter().find_map(kernel_notes::exec_image)
}

/// Sysmon `User` and `LogonId`.
pub(super) fn sysmon_user(
    fields: &mut BTreeMap<String, serde_json::Value>,
    creds: Option<&Credentials>,
) {
    let Some(creds) = creds else { return };
    fields.insert("User".into(), creds.euid.to_string().into());
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
) {
    let Some(creds) = creds else { return };
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
