// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::api::FieldSummary;

fn note(key: &str, layout: &str, bytes: Vec<u8>) -> EventSummary {
    EventSummary {
        root_task_cookie: 1,
        stream_id: 1,
        task_cookie: 2,
        call_id: 3,
        event_seq: 4,
        phase: 3,
        syscall_nr: 105,
        syscall_name: "setuid".into(),
        pid: 5,
        tid: 5,
        cpu: 0,
        timestamp_ns: 0,
        args: None,
        result: None,
        complete: true,
        issues: Vec::new(),
        fields: vec![FieldSummary {
            arg: None,
            object_id: 1,
            key: key.into(),
            layout: layout.into(),
            logical_len: Some(bytes.len() as u64),
            captured_len: bytes.len() as u64,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: bytes,
            raw_path: None,
            ranges: Vec::new(),
            recapture: None,
            encoding: None,
        }],
    }
}

fn creds_bytes(values: [u32; 12], caps: [u64; 3]) -> Vec<u8> {
    let mut bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    bytes.extend(caps.iter().flat_map(|value| value.to_le_bytes()));
    // Bounding set, ambient set, securebits and the reserved word.
    bytes.extend([0; 24]);
    bytes
}

#[test]
fn bounding_ambient_and_securebits_are_read_and_earlier_records_lack_them() {
    let mut bytes = creds_bytes([0; 12], [1, 2, 3]);
    bytes[72..80].copy_from_slice(&0x1ff_ffff_ffffu64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x2000u64.to_le_bytes());
    bytes[88..92].copy_from_slice(&0x2fu32.to_le_bytes());
    bytes[40..44].copy_from_slice(&11u32.to_le_bytes());
    let creds = credentials(&note(CREDS_KEY, CREDS_LAYOUT, bytes.clone())).unwrap();
    assert_eq!(creds.change, CredentialChange::Prctl);
    assert_eq!(
        (creds.cap_bounding, creds.cap_ambient, creds.securebits),
        (Some(0x1ff_ffff_ffff), Some(0x2000), Some(0x2f))
    );
    // A /1 record is the first 72 bytes; the three newer fields stay unknown.
    let old = credentials(&note(CREDS_KEY, CREDS_LAYOUT_V1, bytes[..72].to_vec())).unwrap();
    assert_eq!(old.cap_permitted, 2);
    assert_eq!(
        (old.cap_bounding, old.cap_ambient, old.securebits),
        (None, None, None)
    );
    // The wrong length for a layout is never guessed at.
    assert!(credentials(&note(CREDS_KEY, CREDS_LAYOUT_V1, bytes.clone())).is_some());
    assert!(credentials(&note(CREDS_KEY, CREDS_LAYOUT, bytes[..72].to_vec())).is_none());
}

#[test]
fn credentials_decode_every_id_and_the_login_uid() {
    let bytes = creds_bytes([0, 1000, 0, 1000, 0, 100, 0, 100, 1000, 7, 2, 1], [1, 2, 3]);
    let event = note(CREDS_KEY, CREDS_LAYOUT, bytes);
    assert!(is_note(&event));
    let creds = credentials(&event).unwrap();
    assert_eq!(
        (creds.uid, creds.euid, creds.suid, creds.fsuid),
        (0, 1000, 0, 1000)
    );
    assert_eq!(
        (creds.gid, creds.egid, creds.sgid, creds.fsgid),
        (0, 100, 0, 100)
    );
    assert_eq!((creds.auid, creds.session), (Some(1000), Some(7)));
    assert_eq!(creds.change, CredentialChange::SetUid);
    assert_eq!(creds.cap_permitted, 2);
}

#[test]
fn an_unset_login_uid_is_unset_and_an_untracked_one_is_missing() {
    let unset = creds_bytes([5; 12], [0; 3]);
    let mut tracked = unset.clone();
    for at in [32, 36] {
        tracked[at..at + 4].copy_from_slice(&UNSET.to_le_bytes());
    }
    tracked[44..48].copy_from_slice(&1u32.to_le_bytes());
    let creds = credentials(&note(CREDS_KEY, CREDS_LAYOUT, tracked)).unwrap();
    assert!(creds.audit);
    assert_eq!((creds.auid, creds.session), (None, None));
    // Without audit the kernel recorded nothing, whatever the bytes say.
    let mut untracked = unset;
    untracked[44..48].copy_from_slice(&0u32.to_le_bytes());
    let creds = credentials(&note(CREDS_KEY, CREDS_LAYOUT, untracked)).unwrap();
    assert!(!creds.audit);
    assert_eq!(creds.auid, None);
}

#[test]
fn damaged_or_foreign_records_decode_to_nothing() {
    let good = creds_bytes([1; 12], [0; 3]);
    assert!(credentials(&note(CREDS_KEY, CREDS_LAYOUT, good[..95].to_vec())).is_none());
    assert!(credentials(&note(CREDS_KEY, "antinomie.creds/3", good.clone())).is_none());
    let mut incomplete = note(CREDS_KEY, CREDS_LAYOUT, good.clone());
    incomplete.fields[0].complete = false;
    assert!(credentials(&incomplete).is_none());
    let mut entry = note(CREDS_KEY, CREDS_LAYOUT, good);
    entry.phase = 1;
    assert!(credentials(&entry).is_none() && !is_note(&entry));
    assert!(file_hash(&note(HASH_KEY, HASH_LAYOUT, vec![0; 79])).is_none());
}

fn hash_bytes(kind: u8, status: u8, flags: u8) -> Vec<u8> {
    let mut bytes = vec![0; HASH_SIZE];
    bytes[0] = kind;
    bytes[1] = status;
    bytes[2] = 1;
    bytes[3] = flags;
    bytes[8..16].copy_from_slice(&1234u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&1234u64.to_le_bytes());
    bytes[24..32].copy_from_slice(&(16u64 << 20).to_le_bytes());
    for (index, byte) in bytes[32..64].iter_mut().enumerate() {
        *byte = index as u8;
    }
    bytes[72..76].copy_from_slice(&3u32.to_le_bytes());
    bytes
}

#[test]
fn a_hash_reads_back_as_sysmon_text() {
    let hash = file_hash(&note(HASH_KEY, HASH_LAYOUT, hash_bytes(1, 0, 0))).unwrap();
    assert_eq!(hash.kind, HashKind::Exec);
    assert_eq!(hash.size, 1234);
    assert_eq!(hash.lost, 3);
    assert!(!hash.cached);
    let cached = file_hash(&note(HASH_KEY, HASH_LAYOUT, hash_bytes(1, 0, 4))).unwrap();
    assert!(cached.cached && cached.sysmon().is_some());
    let hex: String = (0..32u8).map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hash.sysmon(), Some(format!("SHA256={hex}")));
    assert_eq!(hash.skipped(), None);
}

#[test]
fn a_written_file_hash_names_its_file_and_only_in_its_own_layout() {
    let mut bytes = hash_bytes(3, 0, 0);
    bytes.resize(112, 0);
    bytes[80..88].copy_from_slice(&0x803u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&77u64.to_le_bytes());
    bytes[96..100].copy_from_slice(&9u32.to_le_bytes());
    bytes[100..104].copy_from_slice(&0o100644u32.to_le_bytes());
    bytes[104..108].copy_from_slice(&0u32.to_le_bytes());
    let hash = file_hash(&note(HASH_KEY, HASH_WRITE_LAYOUT, bytes.clone())).unwrap();
    assert_eq!(hash.kind, HashKind::Write);
    assert!(hash.sysmon().is_some());
    let file = hash.file.unwrap();
    assert_eq!(
        file.key,
        FileKey {
            dev: 0x803,
            ino: 77,
            generation: 9
        }
    );
    assert_eq!((file.mode, file.nlink), (0o100644, 0));
    // The earlier records carry no file; a write kind needs one, and an exec
    // or delete kind never comes in the write layout.
    assert!(file_hash(&note(HASH_KEY, HASH_LAYOUT, bytes[..80].to_vec())).is_none());
    let mut exec = bytes.clone();
    exec[0] = 1;
    assert!(file_hash(&note(HASH_KEY, HASH_WRITE_LAYOUT, exec)).is_none());
    assert!(file_hash(&note(HASH_KEY, HASH_WRITE_LAYOUT, bytes[..104].to_vec())).is_none());
    let exec = file_hash(&note(HASH_KEY, HASH_LAYOUT, hash_bytes(1, 0, 0))).unwrap();
    assert_eq!(exec.file, None);
}

#[test]
fn a_script_interpreter_or_a_changed_file_gives_no_sysmon_hash_and_says_why() {
    for (flags, words) in [(1, "interpreter"), (2, "changed")] {
        let hash = file_hash(&note(HASH_KEY, HASH_LAYOUT, hash_bytes(2, 0, flags))).unwrap();
        assert_eq!(hash.kind, HashKind::Delete);
        assert!(hash.sha256_hex().is_some());
        assert_eq!(hash.sysmon(), None);
        assert!(hash.skipped().unwrap().contains(words));
    }
}

#[test]
fn every_skipped_status_has_a_reason_and_no_digest() {
    for (status, words) in [
        (1, "over the 16 MiB limit"),
        (2, "filesystem"),
        (3, "regular"),
        (4, "queue was full"),
        (5, "read error"),
        (6, "memory"),
        (7, "too many bytes"),
        (9, "unknown status 9"),
    ] {
        let mut bytes = hash_bytes(2, status, 0);
        bytes[2] = 0;
        let hash = file_hash(&note(HASH_KEY, HASH_LAYOUT, bytes)).unwrap();
        assert_eq!(hash.sha256, None, "{status}");
        assert_eq!(hash.sysmon(), None, "{status}");
        assert!(hash.skipped().unwrap().contains(words), "{status}");
    }
}

#[test]
fn the_layouts_match_the_shared_control_header() {
    let header = include_str!("../../../../protocol/control.h");
    let define = |name: &str| -> usize {
        header
            .lines()
            .find(|line| line.split_whitespace().nth(1) == Some(name))
            .and_then(|line| line.split_whitespace().nth(2))
            .unwrap_or_else(|| panic!("{name} missing"))
            .parse()
            .unwrap()
    };
    assert_eq!(define("ANTC_CREDS_SIZE"), CREDS_SIZE);
    assert_eq!(define("ANTC_HASH_SIZE"), HASH_SIZE);
    assert_eq!(define("ANTC_HASH_WRITE_SIZE"), HASH_WRITE_SIZE);
    assert_eq!(define("ANTC_HASH_FILE_MAX"), 16 << 20);
    for (name, value) in [
        ("ANTC_CRED_START", 1),
        ("ANTC_CRED_SETUID", 2),
        ("ANTC_CRED_SETGID", 3),
        ("ANTC_CRED_SETRES", 4),
        ("ANTC_CRED_SETFS", 5),
        ("ANTC_CRED_CAPSET", 6),
        ("ANTC_CRED_EXEC_SETID", 7),
        ("ANTC_CRED_EXEC_CAPS", 8),
        ("ANTC_CRED_LOGINUID", 9),
        ("ANTC_CRED_OTHER", 10),
        ("ANTC_HASH_EXEC", 1),
        ("ANTC_HASH_DELETE", 2),
        ("ANTC_HASH_WRITE", 3),
        ("ANTC_HASH_OK", 0),
        ("ANTC_HASH_TOO_LARGE", 1),
        ("ANTC_HASH_UNSUPPORTED_FS", 2),
        ("ANTC_HASH_NOT_REGULAR", 3),
        ("ANTC_HASH_QUEUE_FULL", 4),
        ("ANTC_HASH_READ_ERROR", 5),
        ("ANTC_HASH_NO_MEMORY", 6),
        ("ANTC_HASH_BUDGET", 7),
        ("ANTC_HASH_SHA256", 1),
        ("ANTC_HASH_INTERPRETER", 1),
        ("ANTC_HASH_CHANGED", 2),
        ("ANTC_HASH_CACHED", 4),
        ("ANTC_HASH_QUEUE", 16),
        ("ANTC_HASH_PENDING_MAX", 64 << 20),
        ("ANTC_FILEPOS_SIZE", FILE_POSITION_SIZE),
        ("ANTC_FILECOPY_SIZE", FILE_COPY_SIZE),
        ("ANTC_FILECOPY_SENDFILE", 1),
        ("ANTC_FILECOPY_SPLICE", 2),
        ("ANTC_FILECOPY_RANGE", 3),
        ("ANTC_FILECOPY_CLONE", 4),
        ("ANTC_FILECOPY_FALLOCATE", 5),
        ("ANTC_FILECOPY_SOURCE_OFFSET", 1),
        ("ANTC_FILECOPY_DEST_OFFSET", 2),
        ("ANTC_FILECOPY_DATA", 4),
        ("ANTC_FILECOPY_DATA_CUT", 8),
        ("ANTC_FILECOPY_DATA_MAX", 1 << 20),
        ("ANTC_FILEMAP_SIZE", FILE_MAPPED_SIZE),
        ("ANTC_FILEMAP_WRITEBACK", 1),
        ("ANTC_FILEMAP_UNMAP", 2),
        ("ANTC_FILEMAP_DATA", 1),
        ("ANTC_FILEMAP_CUT_BUDGET", 1),
        ("ANTC_FILEMAP_CUT_MEMORY", 2),
        ("ANTC_FILEMAP_DATA_MAX", 4 << 20),
        ("ANTC_FILEMAP_RANGES", 64),
    ] {
        assert_eq!(define(name), value, "{name}");
    }
}

#[test]
fn pairing_gives_each_call_its_notes_in_event_order() {
    let mut entry = note(CREDS_KEY, CREDS_LAYOUT, creds_bytes([1; 12], [0; 3]));
    entry.phase = 1;
    entry.fields.clear();
    let mut later = note(HASH_KEY, HASH_LAYOUT, hash_bytes(1, 0, 0));
    later.event_seq = 9;
    let mut earlier = note(CREDS_KEY, CREDS_LAYOUT, creds_bytes([1; 12], [0; 3]));
    earlier.event_seq = 5;
    let mut unattached = note(CREDS_KEY, CREDS_LAYOUT, creds_bytes([1; 12], [0; 3]));
    unattached.call_id = 0;
    let rows = crate::pair_events(&[entry, later, earlier, unattached]);
    assert_eq!(rows.len(), 1);
    let order: Vec<_> = rows[0].kernel_notes.iter().map(|e| e.event_seq).collect();
    assert_eq!(order, [5, 9]);
    assert!(rows[0].async_events.is_empty() && rows[0].task_exit.is_none());
}

#[test]
fn the_guest_lost_counter_reads_from_the_latest_hash_record_only() {
    let hash = note(HASH_KEY, HASH_LAYOUT, hash_bytes(1, 0, 0));
    assert_eq!(guest_lost(&hash), Some(3));
    let creds = note(CREDS_KEY, CREDS_LAYOUT, creds_bytes([1; 12], [0; 3]));
    assert_eq!(guest_lost(&creds), None);
}

pub(crate) fn lost_note(lost: u32) -> EventSummary {
    let mut bytes = hash_bytes(1, 0, 0);
    bytes[72..76].copy_from_slice(&lost.to_le_bytes());
    note(HASH_KEY, HASH_LAYOUT, bytes)
}

fn file_id_bytes(kind: u8, flags: u8, nlink: u32, dev: u64, ino: u64, generation: u32) -> Vec<u8> {
    let mut bytes = vec![0; FILE_ID_SIZE];
    bytes[0] = kind;
    bytes[1] = flags;
    bytes[4..8].copy_from_slice(&nlink.to_le_bytes());
    bytes[8..16].copy_from_slice(&dev.to_le_bytes());
    bytes[16..24].copy_from_slice(&ino.to_le_bytes());
    bytes[24..28].copy_from_slice(&generation.to_le_bytes());
    bytes[28..32].copy_from_slice(&0o100644u32.to_le_bytes());
    bytes
}

#[test]
fn a_file_identity_record_names_the_inode_and_what_the_call_did_to_it() {
    let event = note(
        FILE_ID_KEY,
        FILE_ID_LAYOUT,
        file_id_bytes(4, 2, 1, 0x801, 1234, 7),
    );
    assert!(is_note(&event));
    let id = file_id(&event).unwrap();
    assert_eq!(id.kind, FileIdKind::Unlink);
    assert_eq!(
        id.key,
        FileKey {
            dev: 0x801,
            ino: 1234,
            generation: 7
        }
    );
    assert_eq!((id.nlink, id.mode), (1, 0o100644));
    assert!(id.regular && !id.directory && !id.symlink);
    for (code, kind) in [
        (1, FileIdKind::Open),
        (2, FileIdKind::Rename),
        (3, FileIdKind::Link),
        (5, FileIdKind::Issue),
        (6, FileIdKind::Exec),
        (9, FileIdKind::Unknown(9)),
    ] {
        let event = note(
            FILE_ID_KEY,
            FILE_ID_LAYOUT,
            file_id_bytes(code, 0, 1, 1, 2, 3),
        );
        assert_eq!(file_id(&event).unwrap().kind, kind);
    }
}

#[test]
fn a_file_identity_record_that_is_short_incomplete_or_of_another_layout_is_not_read() {
    let good = file_id_bytes(1, 2, 1, 1, 2, 3);
    assert!(file_id(&note(FILE_ID_KEY, FILE_ID_LAYOUT, good[..31].to_vec())).is_none());
    assert!(file_id(&note(FILE_ID_KEY, "antinomie.fileid/2", good.clone())).is_none());
    assert!(file_id(&note("lifecycle.other", FILE_ID_LAYOUT, good.clone())).is_none());
    let mut incomplete = note(FILE_ID_KEY, FILE_ID_LAYOUT, good.clone());
    incomplete.fields[0].complete = false;
    assert!(file_id(&incomplete).is_none());
    // The operand form of an io_uring request.
    let mut operand = note(FILE_ID_OPERAND, FILE_ID_LAYOUT, good).fields.remove(0);
    assert_eq!(
        file_id_operand(&operand).unwrap().key,
        FileKey {
            dev: 1,
            ino: 2,
            generation: 3
        }
    );
    operand.complete = false;
    assert!(file_id_operand(&operand).is_none());
}

fn exec_image_bytes(flags: u32, interpreter: &str, path: &str) -> Vec<u8> {
    let interp_len = if interpreter.is_empty() {
        0
    } else {
        interpreter.len() + 1
    };
    let path_len = if path.is_empty() { 0 } else { path.len() + 1 };
    let mut bytes = vec![0; EXEC_IMAGE_HEADER];
    bytes[0..4].copy_from_slice(&flags.to_le_bytes());
    bytes[4..8].copy_from_slice(&(interp_len as u32).to_le_bytes());
    bytes[8..12].copy_from_slice(&(path_len as u32).to_le_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&0x801u64.to_le_bytes());
    bytes[24..32].copy_from_slice(&99u64.to_le_bytes());
    bytes[32..36].copy_from_slice(&5u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&0o100755u32.to_le_bytes());
    if interp_len != 0 {
        bytes.extend(interpreter.as_bytes());
        bytes.push(0);
    }
    if path_len != 0 {
        bytes.extend(path.as_bytes());
        bytes.push(0);
    }
    bytes
}

#[test]
fn an_exec_image_record_names_the_interpreter_of_a_script_and_the_file_loaded() {
    let event = note(
        EXEC_IMAGE_KEY,
        EXEC_IMAGE_LAYOUT,
        exec_image_bytes(1, "/bin/sh", "/usr/bin/busybox"),
    );
    assert!(is_note(&event));
    let image = exec_image(&event).unwrap();
    assert_eq!(image.interpreter.as_deref(), Some("/bin/sh"));
    assert_eq!(image.path.as_deref(), Some("/usr/bin/busybox"));
    assert_eq!(image.key.ino, 99);
    // A program that is not a script has no interpreter.
    let plain = exec_image(&note(
        EXEC_IMAGE_KEY,
        EXEC_IMAGE_LAYOUT,
        exec_image_bytes(0, "", "/tmp/sample"),
    ))
    .unwrap();
    assert_eq!(
        (plain.interpreter, plain.path.as_deref()),
        (None, Some("/tmp/sample"))
    );
}

#[test]
fn a_name_the_guest_cut_short_or_left_unterminated_is_never_shown_as_a_path() {
    let cut = exec_image(&note(
        EXEC_IMAGE_KEY,
        EXEC_IMAGE_LAYOUT,
        exec_image_bytes(1 | 2 | 4, "/very/long", "/also/long"),
    ))
    .unwrap();
    assert_eq!((cut.interpreter, cut.path), (None, None));
    assert!(cut.interpreter_truncated && cut.path_truncated);
    // Lengths that run past the record, or a name with no NUL, read as unknown.
    let mut bytes = exec_image_bytes(1, "/bin/sh", "/bin/busybox");
    bytes[8..12].copy_from_slice(&500u32.to_le_bytes());
    let image = exec_image(&note(EXEC_IMAGE_KEY, EXEC_IMAGE_LAYOUT, bytes)).unwrap();
    assert_eq!(image.interpreter.as_deref(), Some("/bin/sh"));
    assert_eq!(image.path, None);
    let mut bytes = exec_image_bytes(1, "/bin/sh", "/bin/busybox");
    let last = bytes.len() - 1;
    bytes[last] = b'x';
    assert_eq!(
        exec_image(&note(EXEC_IMAGE_KEY, EXEC_IMAGE_LAYOUT, bytes))
            .unwrap()
            .path,
        None
    );
    assert!(exec_image(&note(EXEC_IMAGE_KEY, EXEC_IMAGE_LAYOUT, vec![0; 39])).is_none());
}

/// An Exit event of `name` carrying `fields` (key, layout, bytes).
pub(crate) fn exit_with(name: &str, fields: Vec<(&str, &str, Vec<u8>)>) -> EventSummary {
    let mut event = note("", "", Vec::new());
    event.phase = 2;
    event.syscall_name = name.into();
    event.fields = fields
        .into_iter()
        .map(|(key, layout, bytes)| {
            let mut field = note(key, layout, bytes).fields.remove(0);
            field.key = key.into();
            field
        })
        .collect();
    event
}

pub(crate) fn position_bytes(offset: u64, len: u64, order: u64) -> Vec<u8> {
    [offset.to_le_bytes(), len.to_le_bytes(), order.to_le_bytes()].concat()
}

/// A file.copy record: kind, flags, mode, length, offsets, the two ends'
/// (dev, ino, generation, mode), the destination size and the carried length.
#[allow(clippy::too_many_arguments)]
pub(crate) fn copy_bytes(
    kind: u8,
    flags: u8,
    mode: u32,
    len: u64,
    offsets: (u64, u64),
    source: (u64, u64, u32, u32),
    destination: (u64, u64, u32, u32),
    size: u64,
    data_len: u32,
) -> Vec<u8> {
    let mut bytes = vec![kind, flags, 0, 0];
    bytes.extend(mode.to_le_bytes());
    bytes.extend(len.to_le_bytes());
    bytes.extend(offsets.0.to_le_bytes());
    bytes.extend(offsets.1.to_le_bytes());
    for end in [source, destination] {
        bytes.extend(end.0.to_le_bytes());
        bytes.extend(end.1.to_le_bytes());
        bytes.extend(end.2.to_le_bytes());
        bytes.extend(end.3.to_le_bytes());
    }
    bytes.extend(size.to_le_bytes());
    bytes.extend(data_len.to_le_bytes());
    bytes.extend([0; 4]);
    // The write order: none in these records.
    bytes.extend(0u64.to_le_bytes());
    bytes
}

#[test]
fn a_position_record_says_where_the_transfer_began_and_its_length() {
    let exit = exit_with(
        "write",
        vec![(
            FILE_POSITION_KEY,
            FILE_POSITION_LAYOUT,
            position_bytes(4096, 12, 41),
        )],
    );
    assert_eq!(
        file_position(&exit),
        Some(FilePosition {
            offset: 4096,
            len: 12,
            order: Some(41),
        })
    );
    // A read, or a write the file system did not number: no order.
    let read = exit_with(
        "read",
        vec![(
            FILE_POSITION_KEY,
            FILE_POSITION_LAYOUT,
            position_bytes(4096, 12, 0),
        )],
    );
    assert_eq!(file_position(&read).unwrap().order, None);
    // Only an Exit carries it, complete and in its own layout and length.
    let mut entry = exit.clone();
    entry.phase = 1;
    assert_eq!(file_position(&entry), None);
    let mut short = exit.clone();
    short.fields[0].preview.truncate(23);
    assert_eq!(file_position(&short), None);
    let mut foreign = exit.clone();
    foreign.fields[0].layout = "antinomie.filepos/2".into();
    assert_eq!(file_position(&foreign), None);
    let mut partial = exit;
    partial.fields[0].complete = false;
    assert_eq!(file_position(&partial), None);
}

#[test]
fn a_copy_record_names_both_ends_their_offsets_and_the_bytes_carried() {
    const REGULAR: u32 = 0o100644;
    const FIFO: u32 = 0o010600;
    // A file to file copy_file_range: both offsets, nothing carried.
    let range = copy_bytes(
        3,
        3,
        0,
        100,
        (10, 20),
        (0xfe00, 12, 7, REGULAR),
        (0xfe00, 13, 8, REGULAR),
        120,
        0,
    );
    let copy = file_copy(&exit_with(
        "copy_file_range",
        vec![(FILE_COPY_KEY, FILE_COPY_LAYOUT, range)],
    ))
    .unwrap();
    assert_eq!(copy.kind, CopyKind::CopyRange);
    assert_eq!(copy.len, 100);
    let source = copy.source.unwrap();
    assert_eq!(
        (source.key.ino, source.key.generation, source.offset),
        (12, 7, Some(10))
    );
    assert!(source.regular());
    assert_eq!(
        (copy.destination.key.ino, copy.destination.offset),
        (13, Some(20))
    );
    assert_eq!(copy.destination_size, Some(120));
    assert_eq!((copy.data_len, copy.data_cut), (0, false));
    assert_eq!(copy.order, None);
    // The write into the destination is numbered at 96.
    let mut ordered = range_record();
    ordered[96..104].copy_from_slice(&7u64.to_le_bytes());
    let copy = file_copy(&exit_with(
        "copy_file_range",
        vec![(FILE_COPY_KEY, FILE_COPY_LAYOUT, ordered)],
    ))
    .unwrap();
    assert_eq!(copy.order, Some(7));
    // A splice from a pipe: no source offset, the bytes carried, cut.
    let splice = copy_bytes(
        2,
        2 | 4 | 8,
        0,
        70000,
        (0, 5),
        (0xd, 99, 0, FIFO),
        (0xfe00, 13, 8, REGULAR),
        70005,
        65536,
    );
    let copy = file_copy(&exit_with(
        "splice",
        vec![(FILE_COPY_KEY, FILE_COPY_LAYOUT, splice)],
    ))
    .unwrap();
    assert_eq!(copy.kind, CopyKind::Splice);
    assert_eq!(copy.source.unwrap().offset, None);
    assert!(!copy.source.unwrap().regular());
    assert_eq!((copy.data_len, copy.data_cut), (65536, true));
    // An allocation has no source, and its mode says what it did.
    let punch = copy_bytes(
        5,
        2,
        FileCopy::PUNCH_HOLE | 1,
        4096,
        (0, 8192),
        (0, 0, 0, 0),
        (0xfe00, 13, 8, REGULAR),
        65536,
        0,
    );
    let copy = file_copy(&exit_with(
        "fallocate",
        vec![(FILE_COPY_KEY, FILE_COPY_LAYOUT, punch)],
    ))
    .unwrap();
    assert_eq!(
        (copy.kind, copy.source, copy.mode),
        (CopyKind::Fallocate, None, 3)
    );
    assert_eq!(copy.destination.offset, Some(8192));
    // A destination with no positions has no size.
    let to_pipe = copy_bytes(
        1,
        1,
        0,
        9,
        (3, 0),
        (0xfe00, 12, 7, REGULAR),
        (0xd, 98, 0, FIFO),
        0,
        0,
    );
    let copy = file_copy(&exit_with(
        "sendfile",
        vec![(FILE_COPY_KEY, FILE_COPY_LAYOUT, to_pipe)],
    ))
    .unwrap();
    assert_eq!(
        (copy.destination.offset, copy.destination_size),
        (None, None)
    );
    // The wrong length or layout is never guessed at.
    let mut short = range_record();
    short.truncate(103);
    assert!(
        file_copy(&exit_with(
            "splice",
            vec![(FILE_COPY_KEY, FILE_COPY_LAYOUT, short)]
        ))
        .is_none()
    );
    assert!(
        file_copy(&exit_with(
            "splice",
            vec![(FILE_COPY_KEY, "antinomie.filecopy/2", range_record())]
        ))
        .is_none()
    );
}

fn range_record() -> Vec<u8> {
    copy_bytes(
        3,
        3,
        0,
        1,
        (0, 0),
        (1, 2, 3, 0o100644),
        (1, 4, 5, 0o100644),
        1,
        0,
    )
}

/// A `lifecycle.file_mapped` record: cause, flags, cut, (offset, len,
/// carried), inode, size, time, write order, index, count, lost, unlisted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mapped_bytes(
    cause: u8,
    flags: u8,
    cut: u8,
    range: (u64, u64, u64),
    ino: u64,
    size: u64,
    order: u64,
    lost: u32,
    unlisted: u64,
) -> Vec<u8> {
    let mut bytes = vec![cause, flags, cut, 0];
    bytes.extend(4096u32.to_le_bytes());
    bytes.extend(range.0.to_le_bytes());
    bytes.extend(range.1.to_le_bytes());
    bytes.extend(range.2.to_le_bytes());
    bytes.extend(0xfe01u64.to_le_bytes());
    bytes.extend(ino.to_le_bytes());
    bytes.extend(3u32.to_le_bytes());
    bytes.extend(0o100644u32.to_le_bytes());
    bytes.extend(size.to_le_bytes());
    bytes.extend(777u64.to_le_bytes());
    bytes.extend(order.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(lost.to_le_bytes());
    bytes.extend(unlisted.to_le_bytes());
    bytes
}

fn data_field(object_id: u32, bytes: &[u8]) -> FieldSummary {
    FieldSummary {
        arg: None,
        object_id,
        key: FILE_MAPPED_DATA_KEY.into(),
        layout: String::new(),
        logical_len: Some(bytes.len() as u64),
        captured_len: bytes.len() as u64,
        status: Some(0),
        capture_error: 0,
        complete: true,
        preview: bytes.to_vec(),
        raw_path: None,
        ranges: vec![(0, bytes.len() as u64)],
        recapture: None,
        encoding: None,
    }
}

#[test]
fn mapped_pages_name_the_file_the_range_the_copy_and_the_order() {
    // Two pages written back by msync, both copied, then a range unmapped
    // with no copy (past the budget) and no order (a write held the lock).
    let first = mapped_bytes(1, 1, 0, (4096, 8192, 8192), 12, 10000, 41, 2, 0);
    let second = mapped_bytes(2, 0, 1, (0, 4096, 0), 13, 4096, 0, 0, 5);
    let mut event = note(FILE_MAPPED_KEY, FILE_MAPPED_LAYOUT, first);
    event.fields.push(data_field(2, &[7; 16]));
    let mut record = event.fields[0].clone();
    record.object_id = 3;
    record.preview = second;
    event.fields.push(record);
    assert!(is_note(&event));
    let records = file_mapped(&event);
    assert_eq!(records.len(), 2);
    let msync = records[0];
    assert_eq!(msync.cause, MappedCause::Writeback);
    assert_eq!(
        msync.file,
        FileKey {
            dev: 0xfe01,
            ino: 12,
            generation: 3
        }
    );
    assert_eq!(
        (msync.offset, msync.len, msync.carried, msync.cut),
        (4096, 8192, 8192, None)
    );
    assert_eq!(
        (msync.size, msync.time_ns, msync.order, msync.lost),
        (10000, 777, Some(41), 2)
    );
    assert_eq!((msync.page_size, msync.data), (4096, Some(2)));
    let unmap = records[1];
    assert_eq!(unmap.cause, MappedCause::Unmap);
    assert_eq!(
        (
            unmap.carried,
            unmap.cut,
            unmap.order,
            unmap.unlisted,
            unmap.data
        ),
        (0, Some(MappedCut::Budget), None, 5, None)
    );
}

#[test]
fn mapped_bytes_are_the_next_field_only_and_a_wrong_record_is_skipped() {
    // DATA set but the next field is not the record's bytes: nothing carried.
    let bytes = mapped_bytes(2, 1, 0, (0, 100, 100), 12, 100, 1, 0, 0);
    let mut event = note(FILE_MAPPED_KEY, FILE_MAPPED_LAYOUT, bytes.clone());
    event.fields.push(data_field(5, b"x"));
    let records = file_mapped(&event);
    assert_eq!((records[0].carried, records[0].data), (0, None));
    // Short, of another layout, incomplete, or not a lifecycle record.
    let mut short = note(FILE_MAPPED_KEY, FILE_MAPPED_LAYOUT, bytes[..95].to_vec());
    assert!(file_mapped(&short).is_empty());
    short.fields[0].preview = bytes.clone();
    short.fields[0].layout = "antinomie.filemap/2".into();
    assert!(file_mapped(&short).is_empty());
    let mut partial = note(FILE_MAPPED_KEY, FILE_MAPPED_LAYOUT, bytes.clone());
    partial.fields[0].complete = false;
    assert!(file_mapped(&partial).is_empty());
    let mut exit = note(FILE_MAPPED_KEY, FILE_MAPPED_LAYOUT, bytes);
    exit.phase = 2;
    assert!(file_mapped(&exit).is_empty());
}
