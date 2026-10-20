// SPDX-License-Identifier: MIT
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
