// SPDX-License-Identifier: MIT
//! io_uring and AIO requests read as the system calls they stand for, and what
//! Triage then shows for them.
use super::*;
use crate::triage::{async_files, file_category, files::FileIndex};
use antinomie_monitor_core::FieldSummary;

fn scalar(key: &str, value: u64) -> FieldSummary {
    captured(key, "", &value.to_le_bytes())
}

/// A submission queue entry as the program wrote it.
fn sqe(opcode: u8, flags: u8, fd: i32, off: u64, addr: u64, len: u32, rw_flags: u32) -> Vec<u8> {
    let mut sqe = vec![0u8; 64];
    sqe[0] = opcode;
    sqe[1] = flags;
    sqe[4..8].copy_from_slice(&fd.to_le_bytes());
    sqe[8..16].copy_from_slice(&off.to_le_bytes());
    sqe[16..24].copy_from_slice(&addr.to_le_bytes());
    sqe[24..28].copy_from_slice(&len.to_le_bytes());
    sqe[28..32].copy_from_slice(&rw_flags.to_le_bytes());
    sqe
}

fn observation(
    seq: u64,
    request: u64,
    stage: u64,
    opcode: u8,
    result: i64,
    fields: Vec<FieldSummary>,
) -> EventSummary {
    let mut event = call(1, 426, "io_uring_enter", 0).entry.unwrap();
    event.phase = 3;
    event.event_seq = seq;
    event.timestamp_ns = seq * 10;
    event.fields = vec![
        scalar("async.request_id", request),
        scalar("async.stage", stage),
        scalar("async.opcode", u64::from(opcode)),
        scalar("async.result", result as u64),
        captured("async.system", "", b"io_uring\0"),
    ];
    event.fields.extend(fields);
    event
}

fn path(key: &str, value: &str) -> FieldSummary {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    captured(key, "", &bytes)
}

fn identity(kind: u8, nlink: u32, inode: u64) -> FieldSummary {
    let mut bytes = vec![0u8; 32];
    bytes[0] = kind;
    bytes[1] = 2;
    bytes[4..8].copy_from_slice(&nlink.to_le_bytes());
    bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&inode.to_le_bytes());
    bytes[28..32].copy_from_slice(&0o100644u32.to_le_bytes());
    captured("async.operand.file_id", "antinomie.fileid/1", &bytes)
}

/// A request that was submitted and completed: its two observations.
fn request(
    first_seq: u64,
    id: u64,
    entry: Vec<u8>,
    operands: Vec<FieldSummary>,
    result: i64,
) -> Vec<EventSummary> {
    let opcode = entry[0];
    let mut submitted = vec![captured("async.submission", "", &entry)];
    submitted.extend(operands);
    vec![
        observation(first_seq, id, 1, opcode, 0, submitted),
        observation(first_seq + 1, id, 4, opcode, result, Vec::new()),
    ]
}

fn parent() -> InvocationSummary {
    let mut parent = call(1, 426, "io_uring_enter", 5);
    parent.call_id = 9;
    parent
}

fn args(call: &InvocationSummary) -> [u64; 6] {
    call.entry.as_ref().unwrap().args.unwrap()
}

#[test]
fn file_requests_become_the_calls_they_stand_for_with_the_submitters_identity() {
    const O_RDWR_CREAT: u32 = 0x42;
    let mut events = Vec::new();
    events.extend(request(
        10,
        1,
        sqe(18, 0, -100, 0, 0x1000, 0o600, O_RDWR_CREAT),
        vec![path("async.operand.path", "/tmp/a"), identity(1, 1, 100)],
        5,
    ));
    let mut write = request(20, 2, sqe(23, 0, 5, 0, 0x2000, 4, 0), Vec::new(), 4);
    write[0]
        .fields
        .push(captured("async.payload.input", "", b"data"));
    events.extend(write);
    let mut read = request(30, 3, sqe(22, 0, 5, u64::MAX, 0x2000, 4, 0), Vec::new(), 4);
    read[1]
        .fields
        .push(captured("async.payload.output", "", b"data"));
    events.extend(read);
    events.extend(request(40, 4, sqe(19, 0, 5, 0, 0, 0, 0), Vec::new(), 0));
    events.extend(request(
        50,
        5,
        sqe(36, 0, -100, 0, 0x3000, 0, 0),
        vec![path("async.operand.path", "/tmp/a"), identity(4, 0, 100)],
        0,
    ));
    let calls = async_files::calls(&parent(), &events);
    let names: Vec<_> = calls
        .iter()
        .map(|call| call.entry.as_ref().unwrap().syscall_name.as_str())
        .collect();
    assert_eq!(names, ["openat", "pwrite64", "read", "close", "unlinkat"]);
    // The submitting call's identity, so the evidence is the io_uring_enter.
    for call in &calls {
        assert_eq!((call.stream_id, call.task_cookie, call.call_id), (1, 1, 9));
        assert_eq!(async_files::via(call), Some("io_uring"));
    }
    let open = &calls[0];
    assert_eq!(args(open)[0] as i64, -100);
    assert_eq!(args(open)[2], u64::from(O_RDWR_CREAT));
    assert_eq!(open.exit.as_ref().unwrap().result, Some(5));
    assert_eq!(path_list(open), ["/tmp/a"]);
    assert_eq!(
        kernel_records::file_id(open).unwrap().key.ino,
        100,
        "the identity the guest attached to the request rides with the call"
    );
    // A positioned write carries its offset and its bytes; a read at the file
    // position is a plain read whose bytes are in the completion.
    let write = &calls[1];
    assert_eq!(&args(write)[..4], &[5, 0x2000, 4, 0]);
    assert!(write
        .entry
        .as_ref()
        .unwrap()
        .fields
        .iter()
        .any(|field| field.key == "arg1.buf" && field.preview == b"data"));
    let read = &calls[2];
    assert!(read
        .exit
        .as_ref()
        .unwrap()
        .fields
        .iter()
        .any(|field| field.key == "arg1.buf" && field.preview == b"data"));
    assert_eq!(path_list(&calls[4]), ["/tmp/a"]);
}

#[test]
fn renames_links_and_a_request_that_never_completed_keep_what_is_known() {
    let mut events = request(
        10,
        1,
        sqe(35, 0, -100, 0x4000, 0x3000, (-100i32) as u32, 0),
        vec![
            path("async.operand.oldpath", "/tmp/a"),
            path("async.operand.newpath", "/tmp/b"),
        ],
        0,
    );
    // Submitted and never completed.
    let mut hung = request(20, 2, sqe(23, 0, 5, 0, 0x2000, 4, 0), Vec::new(), 0);
    hung.pop();
    events.extend(hung);
    let calls = async_files::calls(&parent(), &events);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].entry.as_ref().unwrap().syscall_name, "renameat2");
    assert_eq!(path_list(&calls[0]), ["/tmp/a", "/tmp/b"]);
    assert!(calls[1].exit.is_none(), "no completion, no result");
    assert_eq!(
        file_category::outcome(&calls[1]),
        file_category::Outcome::NoExit
    );
}

#[test]
fn a_registered_descriptor_is_not_the_descriptor_of_the_same_number() {
    // IOSQE_FIXED_FILE: fd 3 is slot 3 of the ring's table.
    let events = request(10, 1, sqe(23, 1, 3, 0, 0x2000, 2, 0), Vec::new(), 2);
    let calls = async_files::calls(&parent(), &events);
    assert_eq!(args(&calls[0])[0], u64::MAX);
}

#[test]
fn an_open_into_the_registered_table_names_no_descriptor_of_the_process() {
    // IORING_OP_OPENAT with file_index 1: the file goes to slot 0 of the
    // ring's table and the result 0 is not descriptor 0 of the process.
    let mut entry = sqe(18, 0, -100, 0, 0x1000, 0o600, 0x42);
    entry[44..48].copy_from_slice(&1u32.to_le_bytes());
    let mut events = request(
        10,
        1,
        entry,
        vec![
            path("async.operand.path", "/tmp/direct"),
            identity(1, 1, 300),
        ],
        0,
    );
    // A write on that slot, tied to the file by its identity.
    let mut write = request(
        20,
        2,
        sqe(23, 1, 0, 0, 0x2000, 2, 0),
        vec![identity(5, 1, 300)],
        2,
    );
    write[0]
        .fields
        .push(captured("async.payload.input", "", b"zz"));
    events.extend(write);
    let calls = async_files::calls(&parent(), &events);
    assert!(async_files::direct_descriptor(&calls[0]));
    assert!(!async_files::direct_descriptor(&calls[1]));
    let event = trace::representative(&calls[0]).unwrap();
    assert_eq!(file_fd(&calls[0], event), "registered");
    let mut files = FdState::default();
    remember_open(&mut files, &calls[0], event);
    assert!(
        files.opened.is_empty(),
        "descriptor 0 of the process did not become the opened file"
    );
    // The write on the slot is named by the file's identity, by descriptor.
    let write = trace::representative(&calls[1]).unwrap();
    assert_eq!(displayed_path(&calls[1], write, &files), "/tmp/direct");
    assert!(matches!(
        file_category::access(&files, &calls[1], write),
        file_category::Access::ByDescriptor
    ));
    let (index, _) = track(&calls);
    let changes = index.finish();
    let direct: Vec<_> = changes
        .iter()
        .filter(|change| change.row(None)[1].text == "/tmp/direct")
        .collect();
    assert_eq!(direct.len(), 1, "the slot write reaches the opened file");
    assert!(direct[0].lifecycle_text().contains("written"));
}

#[test]
fn a_read_published_in_stages_is_read_back_in_order_up_to_a_missing_stage() {
    // IORING_OP_READV of 64 bytes that returned 22: the guest published the
    // first segment's bytes at offset 0, the second at 11 and an empty stage
    // for the rest of the vector at 22.
    let stage = |seq: u64, offset: u64, data: &[u8]| {
        observation(
            seq,
            1,
            4,
            1,
            22,
            vec![
                scalar("async.payload.result_offset", offset),
                captured("async.payload.output", "", data),
            ],
        )
    };
    let mut events = request(10, 1, sqe(1, 0, 5, 0, 0x2000, 1, 0), Vec::new(), 22);
    events.insert(1, stage(11, 11, b"vector two\n"));
    events.insert(1, stage(12, 0, b"vector one\n"));
    events.insert(1, stage(13, 22, b""));
    let calls = async_files::calls(&parent(), &events);
    let exit = calls[0].exit.as_ref().unwrap();
    let keys: Vec<_> = exit.fields.iter().map(|field| field.key.as_str()).collect();
    assert_eq!(keys, ["arg1.iov[0].data", "arg1.iov[1].data"]);
    let data = crate::triage::file_content::capture(&calls[0], true, None, 22);
    assert_eq!(data.preview(), "vector one\\nvector two\\n");
    // A stage that never arrived ends the data where it is missing.
    let mut gap = request(10, 1, sqe(1, 0, 5, 0, 0x2000, 1, 0), Vec::new(), 22);
    gap.insert(1, stage(11, 11, b"vector two\n"));
    let calls = async_files::calls(&parent(), &gap);
    assert!(calls[0].exit.as_ref().unwrap().fields.is_empty());
}

#[test]
fn requests_that_touch_no_file_and_calls_that_carry_none_produce_no_call() {
    let mut events = request(10, 1, sqe(0, 0, 0, 0, 0, 0, 0), Vec::new(), 0);
    events.extend(request(20, 2, sqe(6, 0, 4, 0, 0, 0, 1), Vec::new(), 1));
    events.extend(request(
        30,
        3,
        sqe(27, 0, 4, 0, 0x2000, 8, 0),
        Vec::new(),
        8,
    ));
    assert!(async_files::calls(&parent(), &events).is_empty());
    // A call that is not a submission never gets requests, whatever its events say.
    let events = request(10, 1, sqe(23, 0, 5, 0, 0x2000, 4, 0), Vec::new(), 4);
    assert!(async_files::calls(&call(1, 0, "read", 4), &events).is_empty());
}

#[test]
fn aio_requests_read_their_control_block() {
    let mut iocb = vec![0u8; 64];
    iocb[16..18].copy_from_slice(&1u16.to_le_bytes());
    iocb[20..24].copy_from_slice(&7u32.to_le_bytes());
    iocb[24..32].copy_from_slice(&0x5000u64.to_le_bytes());
    iocb[32..40].copy_from_slice(&512u64.to_le_bytes());
    iocb[40..48].copy_from_slice(&4096u64.to_le_bytes());
    let mut parent = call(1, 209, "io_submit", 1);
    parent.call_id = 4;
    let mut submitted = observation(
        10,
        1,
        1,
        1,
        0,
        vec![captured("async.submission", "", &iocb)],
    );
    submitted.fields[4] = captured("async.system", "", b"AIO\0");
    let mut done = observation(11, 1, 4, 1, 512, Vec::new());
    done.fields[4] = captured("async.system", "", b"AIO\0");
    let calls = async_files::calls(&parent, &[submitted, done]);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].entry.as_ref().unwrap().syscall_name, "pwrite64");
    assert_eq!(&args(&calls[0])[..4], &[7, 0x5000, 512, 4096]);
    assert_eq!(async_files::via(&calls[0]), Some("AIO"));
}

/// Run calls through the same tracking the scan applies.
fn track(calls: &[InvocationSummary]) -> (FileIndex, Vec<Vec<Cell>>) {
    let mut index = FileIndex::default();
    let mut files = FdState::default();
    let mut reads = Vec::new();
    let cookies = task_cookies(calls);
    for call in calls {
        let event = trace::representative(call).unwrap();
        remember_open(&mut files, call, event);
        apply_dup(&mut files, call, event);
        forget_closed(&mut files, call, event);
        inherit_open_fds(&mut files, call, event, &cookies);
        let hits = file_category::classify(&files, call, event);
        if let Some(row) = index.observe_with(&files, call, event, None, &hits) {
            reads.push(row);
        }
    }
    (index, reads)
}

#[test]
fn an_io_uring_session_is_followed_like_the_system_calls_it_stands_for() {
    let mut events = Vec::new();
    events.extend(request(
        10,
        1,
        sqe(18, 0, -100, 0, 0x1000, 0o600, 0x42),
        vec![path("async.operand.path", "/tmp/a"), identity(1, 1, 100)],
        5,
    ));
    let mut write = request(20, 2, sqe(23, 0, 5, 0, 0x2000, 4, 0), Vec::new(), 4);
    write[0]
        .fields
        .push(captured("async.payload.input", "", b"data"));
    events.extend(write);
    events.extend(request(
        30,
        3,
        sqe(35, 0, -100, 0x4000, 0x3000, (-100i32) as u32, 0),
        vec![
            path("async.operand.oldpath", "/tmp/a"),
            path("async.operand.newpath", "/tmp/b"),
            identity(2, 1, 100),
        ],
        0,
    ));
    // A write on a registered descriptor, found by its file's identity alone.
    let mut fixed = request(
        40,
        4,
        sqe(23, 1, 0, 4, 0x2000, 2, 0),
        vec![identity(5, 1, 100)],
        2,
    );
    fixed[0]
        .fields
        .push(captured("async.payload.input", "", b"zz"));
    events.extend(fixed);
    events.extend(request(
        50,
        5,
        sqe(36, 0, -100, 0, 0x3000, 0, 0),
        vec![path("async.operand.path", "/tmp/b"), identity(4, 0, 100)],
        0,
    ));
    let calls = async_files::calls(&parent(), &events);
    let (index, _) = track(&calls);
    let changes = index.finish();
    assert_eq!(
        changes.len(),
        1,
        "one file through open, write, rename, unlink"
    );
    let story = changes[0].lifecycle_text();
    for step in ["written", "renamed → /tmp/b", "deleted"] {
        assert!(story.contains(step), "{step:?} missing from {story}");
    }
    let row = changes[0].row(None);
    assert_eq!(row[1].text, "/tmp/a");
    assert!(row[0]
        .values
        .iter()
        .any(|(name, value)| *name == "file.inode" && matches!(value, RowValue::Text(_))));
}

#[test]
fn a_script_exec_names_its_interpreter_and_the_file_that_was_loaded() {
    fn image(flags: u32, interpreter: &str, path: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 40];
        bytes[0..4].copy_from_slice(&flags.to_le_bytes());
        let interp_len = if interpreter.is_empty() {
            0
        } else {
            interpreter.len() + 1
        };
        bytes[4..8].copy_from_slice(&(interp_len as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&((path.len() + 1) as u32).to_le_bytes());
        if interp_len != 0 {
            bytes.extend(interpreter.as_bytes());
            bytes.push(0);
        }
        bytes.extend(path.as_bytes());
        bytes.push(0);
        bytes
    }
    let detail = |bytes: Option<Vec<u8>>| {
        let mut exec = path_call(1, 59, "execve", 0, "/tmp/run.sh");
        if let Some(bytes) = bytes {
            let mut note = exec.exit.clone().unwrap();
            note.phase = 3;
            note.fields = vec![captured(
                "lifecycle.exec_image",
                "antinomie.execimg/1",
                &bytes,
            )];
            exec.kernel_notes.push(note);
        }
        let event = trace::representative(&exec).unwrap();
        file_category::detail(
            &FdState::default(),
            &exec,
            event,
            file_category::Hit {
                category: file_category::Category::Executed,
                inferred: false,
            },
        )
    };
    let shebang = detail(Some(image(1, "/bin/sh", "/bin/busybox")));
    assert!(
        shebang.contains("script run through /bin/sh (loaded /bin/busybox)"),
        "{shebang}"
    );
    let same = detail(Some(image(1, "/bin/sh", "/bin/sh")));
    assert!(
        same.ends_with("script run through /bin/sh)") || same == "script run through /bin/sh",
        "{same}"
    );
    // A binary is not a script, and a guest without the record says what it
    // could not: the path was not recorded.
    assert!(!detail(Some(image(0, "", "/tmp/run.sh"))).contains("script"));
    let long = detail(Some(image(1 | 2, "/bin/very-long", "/bin/busybox")));
    assert!(long.contains("too long to record"), "{long}");
    assert!(!detail(None).contains("script"));
}

#[test]
fn sync_splice_and_attribute_requests_are_the_calls_they_stand_for() {
    let mut events = Vec::new();
    events.extend(request(10, 1, sqe(3, 0, 5, 0, 0, 0, 0), Vec::new(), 0));
    events.extend(request(20, 2, sqe(3, 0, 5, 0, 0, 0, 1), Vec::new(), 0));
    events.extend(request(30, 3, sqe(8, 0, 5, 4096, 0, 512, 2), Vec::new(), 0));
    // SPLICE: the output is the request's descriptor, the input its
    // splice_fd_in; the offsets are values, not pointers.
    let mut splice = sqe(30, 0, 6, u64::MAX, u64::MAX, 100, 0);
    splice[44..48].copy_from_slice(&5i32.to_le_bytes());
    events.extend(request(40, 4, splice.clone(), Vec::new(), 100));
    splice[28..32].copy_from_slice(&(1u32 << 31).to_le_bytes());
    events.extend(request(50, 5, splice, Vec::new(), 100));
    events.extend(request(
        60,
        6,
        sqe(41, 0, 5, 0x6000, 0x5000, 3, 0),
        vec![
            path("async.operand.xattr_name", "user.tag"),
            captured("async.operand.xattr_value", "", b"red"),
        ],
        0,
    ));
    let mut set = sqe(42, 0, 0, 0x6000, 0x5000, 3, 1);
    set[48..56].copy_from_slice(&0x7000u64.to_le_bytes());
    events.extend(request(
        70,
        7,
        set,
        vec![
            path("async.operand.xattr_name", "user.tag"),
            captured("async.operand.xattr_value", "", b"red"),
            path("async.operand.path", "/tmp/x"),
        ],
        0,
    ));
    events.extend(request(
        80,
        8,
        sqe(44, 0, 0, 0x6000, 0x5000, 16, 0),
        vec![
            path("async.operand.xattr_name", "user.tag"),
            path("async.operand.path", "/tmp/x"),
        ],
        3,
    ));
    let calls = async_files::calls(&parent(), &events);
    let names: Vec<_> = calls
        .iter()
        .map(|call| call.entry.as_ref().unwrap().syscall_name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "fsync",
            "fdatasync",
            "sync_file_range",
            "splice",
            "splice",
            "fsetxattr",
            "setxattr",
            "getxattr"
        ]
    );
    assert_eq!(&args(&calls[2])[..4], &[5, 4096, 512, 2]);
    assert_eq!(args(&calls[3]), [5, 0, 6, 0, 100, 0]);
    assert_eq!(
        args(&calls[4])[0],
        u64::MAX,
        "a registered input names no descriptor of the process"
    );
    assert_eq!(&args(&calls[6])[..2], &[0x7000, 0x5000]);
    assert_eq!(path_list(&calls[6]), ["/tmp/x"]);
    let field = |call: &InvocationSummary, suffix: &str| {
        call.entry
            .as_ref()
            .unwrap()
            .fields
            .iter()
            .find(|field| field.key.starts_with(suffix))
            .map(|field| field.preview.clone())
    };
    assert_eq!(field(&calls[5], "arg1."), Some(b"user.tag\0".to_vec()));
    assert_eq!(field(&calls[5], "arg2."), Some(b"red".to_vec()));
    assert_eq!(field(&calls[7], "arg2."), None, "a get carries no value in");
    // Triage files them as it files the system calls.
    let files = FdState::default();
    let category = |call: &InvocationSummary| {
        file_category::classify(&files, call, call.entry.as_ref().unwrap())
            .into_iter()
            .map(|hit| hit.category)
            .collect::<Vec<_>>()
    };
    assert_eq!(category(&calls[3]), [file_category::Category::Copied]);
    assert_eq!(category(&calls[5]), [file_category::Category::Xattrs]);
    assert_eq!(category(&calls[6]), [file_category::Category::Xattrs]);
}

#[test]
fn requests_a_ring_thread_submitted_wait_for_their_time_among_the_calls() {
    // An SQPOLL ring's thread submitted these for the ring's creator: they
    // carry no call of their own and are held for the calls of that time.
    let mut setup = call(1, 425, "io_uring_setup", 3);
    setup.call_id = 2;
    let mut events = request(100, 1, sqe(23, 0, 3, 0, 0x2000, 4, 0), Vec::new(), 4);
    events.extend(request(300, 2, sqe(3, 0, 3, 0, 0, 0, 0), Vec::new(), 0));
    let mut held = async_files::Attributed::default();
    let mut reach = async_files::Reach::default();
    held.hold(0, &setup, &events, &mut reach);
    assert_eq!(reach.requests, 2);
    let at = |time: u64| {
        let mut call = call(1, 0, "read", 0);
        call.entry.as_mut().unwrap().timestamp_ns = time;
        call
    };
    assert!(held.due(0, &at(999)).is_empty(), "the write was at 1000 ns");
    let due = held.due(0, &at(1000));
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].entry.as_ref().unwrap().syscall_name, "pwrite64");
    // The creator's identity: its descriptors, its setup call as evidence.
    assert_eq!((due[0].task_cookie, due[0].call_id), (1, 2));
    // A later segment takes every call of an earlier one.
    let due = held.due(1, &at(0));
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].entry.as_ref().unwrap().syscall_name, "fsync");
    assert!(held.rest().is_empty());
}
