// SPDX-License-Identifier: MIT
//! The Sysmon-style fields and auditd-style records built from the trace.
use super::*;
use antinomie_monitor_core::analysis::detection::{EventJournal, Identity};

const POINTER: &str = "linux-6.12.94/x86_64/pointer";

fn identity() -> Identity {
    Identity {
        vm_id: "v".into(),
        boot_id: "b".into(),
        run_id: "r".into(),
        root_cookie: 1,
    }
}

/// An execve of `path` whose whole argument vector was captured.
fn exec(pid: u32, path: &str, arguments: &[&str]) -> InvocationSummary {
    let mut row = tests::path_call(pid, 59, "execve", 0, path);
    let entry = row.entry.as_mut().unwrap();
    for (index, argument) in arguments.iter().enumerate() {
        let mut text = argument.as_bytes().to_vec();
        text.push(0);
        entry.fields.push(tests::captured(
            &format!("arg1.ptr[{index}]"),
            POINTER,
            &(0x1000 + index as u64).to_le_bytes(),
        ));
        entry
            .fields
            .push(tests::captured(&format!("arg1.string[{index}]"), "", &text));
    }
    entry.fields.push(tests::captured(
        &format!("arg1.ptr[{}]", arguments.len()),
        POINTER,
        &0u64.to_le_bytes(),
    ));
    row
}

fn with_args(mut row: InvocationSummary, args: [u64; 6]) -> InvocationSummary {
    row.entry.as_mut().unwrap().args = Some(args);
    row
}

fn with_path(mut row: InvocationSummary, key: &str, path: &str) -> InvocationSummary {
    let mut bytes = path.as_bytes().to_vec();
    bytes.push(0);
    row.entry
        .as_mut()
        .unwrap()
        .fields
        .push(tests::captured(key, "", &bytes));
    row
}

fn with_address(
    mut row: InvocationSummary,
    key: &str,
    family: u16,
    ip: [u8; 4],
    port: u16,
) -> InvocationSummary {
    let mut data = family.to_le_bytes().to_vec();
    data.extend(port.to_be_bytes());
    data.extend(ip);
    data.extend([0; 8]);
    row.entry
        .as_mut()
        .unwrap()
        .fields
        .push(tests::captured(key, "", &data));
    row
}

type Fields = serde_json::Value;

/// Run calls the way the scan does and return the journal's events.
fn run(files: &mut FdState, calls: &[InvocationSummary]) -> Vec<Fields> {
    let temp = PacketSpool::new().unwrap();
    let mut journal = EventJournal::new(&temp.directory, &identity()).unwrap();
    let mut held = Vec::new();
    let cookies: std::collections::BTreeMap<u32, u64> = calls
        .iter()
        .filter_map(|call| Some((call.entry.as_ref()?.pid, call.task_cookie)))
        .collect();
    for invocation in calls {
        observe_processes(&mut files.process_images, std::slice::from_ref(invocation));
        let event = trace::representative(invocation).unwrap();
        sigma_events::seed_launch_cwd(files, event);
        remember_cwd(files, invocation, event);
        remember_open(files, invocation, event);
        inherit_open_fds(files, invocation, event, &cookies);
        normalized::call(&mut journal, &mut held, files, invocation, event).unwrap();
    }
    normalized::flush_connections(&mut journal, held, files, None).unwrap();
    journal.finish(true).unwrap();
    let data = std::fs::read_to_string(
        temp.directory
            .join(antinomie_monitor_core::analysis::detection::JOURNAL_FILE),
    )
    .unwrap();
    data.lines()
        .map(|line| serde_json::from_str::<Fields>(line).unwrap())
        .filter(|line| line["kind"] == "event")
        .map(|line| line["event"].clone())
        .collect()
}

fn of<'a>(events: &'a [Fields], category: &str) -> Vec<&'a Fields> {
    events
        .iter()
        .filter(|event| event["category"] == category)
        .collect()
}

fn auditd<'a>(events: &'a [Fields], kind: &str) -> Vec<&'a Fields> {
    events
        .iter()
        .filter(|event| event["category"] == "auditd" && event["fields"]["type"] == kind)
        .collect()
}

#[test]
fn a_child_exec_names_its_parent_and_the_launch_directory() {
    let mut files = FdState::default();
    files.journal.launch_cwd = Some("/work".into());
    files.journal.root_cookie = 1;
    let calls = [
        exec(1, "/bin/sh", &["sh", "-c", "ls"]),
        tests::call(1, 57, "fork", 42),
        exec(42, "/bin/ls", &["ls", "-l"]),
        with_path(tests::call(42, 80, "chdir", 0), "arg0.filename", "sub"),
    ];
    let events = run(&mut files, &calls);
    let creations = of(&events, "process_creation");
    assert_eq!(creations.len(), 2);
    let root = &creations[0]["fields"];
    assert!(
        root.get("ParentProcessId").is_none(),
        "the root has no recorded parent"
    );
    assert_eq!(root["CurrentDirectory"], "/work");
    assert!(
        creations[0].get("_inferred").is_none(),
        "the launch directory is exact"
    );
    let child = &creations[1]["fields"];
    assert_eq!(child["ParentImage"], "/bin/sh");
    assert_eq!(child["ParentProcessId"], 1);
    assert_eq!(child["ParentCommandLine"], "sh -c ls");
    assert_eq!(child["CommandLine"], "ls -l");
    assert_eq!(
        child["CurrentDirectory"], "/work",
        "fork copies the directory"
    );
}

#[test]
fn chdir_is_followed_from_the_launch_directory_and_marked_inferred() {
    let mut files = FdState::default();
    files.journal.launch_cwd = Some("/work".into());
    files.journal.root_cookie = 1;
    let calls = [
        with_path(tests::call(1, 80, "chdir", 0), "arg0.filename", "sub"),
        exec(1, "/bin/id", &["id"]),
    ];
    let events = run(&mut files, &calls);
    let creation = of(&events, "process_creation")[0];
    assert_eq!(creation["fields"]["CurrentDirectory"], "/work/sub");
    assert_eq!(
        creation["_inferred"],
        serde_json::json!(["CurrentDirectory"])
    );
    // Without a launch directory a working directory is never invented.
    let mut files = FdState::default();
    let events = run(&mut files, &[exec(1, "/bin/id", &["id"])]);
    assert!(of(&events, "process_creation")[0]["fields"]
        .get("CurrentDirectory")
        .is_none());
}

#[test]
fn file_event_covers_creating_calls_and_infers_newness_from_paths_already_seen() {
    let mut files = FdState::default();
    let open = |path: &str, flags: u64| {
        with_args(
            tests::path_call(1, 2, "open", 3, path),
            [0, flags, 0, 0, 0, 0],
        )
    };
    let calls = [
        open("/etc/existing", 0),
        open("/etc/existing", 0o100 | 0o1000),
        open("/tmp/new", 0o100 | 0o1000),
        open("/tmp/new", 0o100 | 0o1000),
        open("/tmp/excl", 0o100 | 0o200),
        open("/tmp", 0o20200000),
        tests::path_call(1, 83, "mkdir", 0, "/tmp/dir"),
        tests::path_call(1, 133, "mknod", 0, "/tmp/node"),
        with_path(
            with_path(tests::call(1, 86, "link", 0), "arg0.oldname", "/tmp/new"),
            "arg1.newname",
            "/tmp/hard",
        ),
        tests::path_call(1, 85, "creat", 3, "/tmp/created"),
        open("/tmp/plain", 0o100),
    ];
    let events = run(&mut files, &calls);
    let made: Vec<_> = of(&events, "file_event")
        .into_iter()
        .map(|event| {
            (
                event["fields"]["TargetFilename"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                event["_inferred"].to_string(),
            )
        })
        .collect();
    let inferred = r#"["IsNewFile"]"#;
    assert_eq!(
        made,
        [
            ("/tmp/new".to_owned(), inferred.to_owned()),
            ("/tmp/excl".to_owned(), "null".to_owned()),
            (
                "/tmp".to_owned(),
                r#"["IsNewFile","TargetFilename"]"#.to_owned()
            ),
            ("/tmp/dir".to_owned(), "null".to_owned()),
            ("/tmp/node".to_owned(), "null".to_owned()),
            ("/tmp/hard".to_owned(), "null".to_owned()),
            ("/tmp/created".to_owned(), inferred.to_owned()),
        ],
        "a path seen before is not new, and plain O_CREAT is not a file_event"
    );
    assert!(of(&events, "file_event")
        .iter()
        .all(|event| event["fields"]["IsNewFile"] == "true"));
}

#[test]
fn accepted_connections_and_udp_peers_are_network_connections() {
    let mut files = FdState::default();
    let tcp = with_args(tests::call(1, 41, "socket", 4), [2, 1, 0, 0, 0, 0]);
    let udp = with_args(tests::call(1, 41, "socket", 5), [2, 2, 0, 0, 0, 0]);
    let connect = with_address(
        with_args(tests::call(1, 42, "connect", 0), [4, 0, 16, 0, 0, 0]),
        "arg1.address",
        2,
        [203, 0, 113, 9],
        443,
    );
    let send = |peer: [u8; 4]| {
        with_address(
            with_args(tests::call(1, 44, "sendto", 12), [5, 0, 12, 0, 0, 16]),
            "arg4.address",
            2,
            peer,
            53,
        )
    };
    let listener = with_args(tests::call(1, 41, "socket", 3), [2, 1, 0, 0, 0, 0]);
    let accept = with_address(
        with_args(tests::call(1, 43, "accept", 6), [3, 0, 0, 0, 0, 0]),
        "arg1.sockaddr",
        2,
        [198, 51, 100, 7],
        40000,
    );
    let unknown = with_address(
        with_args(tests::call(1, 44, "sendto", 12), [9, 0, 12, 0, 0, 16]),
        "arg4.address",
        2,
        [192, 0, 2, 1],
        53,
    );
    let calls = [
        listener,
        tcp,
        udp,
        connect,
        send([192, 0, 2, 53]),
        send([192, 0, 2, 53]),
        send([192, 0, 2, 54]),
        accept,
        unknown,
    ];
    let events = run(&mut files, &calls);
    let seen: Vec<_> = of(&events, "network_connection")
        .into_iter()
        .map(|event| {
            let fields = &event["fields"];
            let text = |key: &str| fields.get(key).map(|value| value.to_string());
            (
                text("Protocol"),
                text("Initiated"),
                text("DestinationIp").or_else(|| text("SourceIp")),
            )
        })
        .collect();
    let some = |text: &str| Some(text.to_owned());
    assert_eq!(
        seen,
        [
            (some("\"tcp\""), some("\"false\""), some("\"198.51.100.7\"")),
            (some("\"tcp\""), some("\"true\""), some("\"203.0.113.9\"")),
            (some("\"udp\""), some("\"true\""), some("\"192.0.2.53\"")),
            (some("\"udp\""), some("\"true\""), some("\"192.0.2.54\"")),
        ],
        "accepts are written at once, connections after the DNS pass; each datagram peer once; a send on an unknown descriptor is not assumed UDP"
    );
    let accepted = of(&events, "network_connection")[0];
    assert!(
        accepted["fields"].get("DestinationIp").is_none(),
        "the local address is not captured"
    );
}

#[test]
fn a_destination_takes_its_name_from_the_dns_answer_and_says_so() {
    let mut files = FdState::default();
    let answer = |name: &str, address: &str, time: i128| {
        let mut row = cell("", theme::text(), true);
        row.values = vec![
            ("dns.name", RowValue::Text(name.into())),
            (
                "dns.answers",
                RowValue::List(vec!["alias.test".into(), address.into()]),
            ),
            ("frame.time_us", RowValue::Number(time)),
        ];
        vec![row]
    };
    files
        .journal
        .learn_dns(&answer("one.test.", "203.0.113.9", 100));
    files
        .journal
        .learn_dns(&answer("two.test", "192.0.2.5", 100));
    files
        .journal
        .learn_dns(&answer("three.test", "192.0.2.5", 200));
    assert_eq!(
        files.journal.hostname("203.0.113.9", None).as_deref(),
        Some("one.test")
    );
    assert_eq!(
        files.journal.hostname("192.0.2.5", None),
        None,
        "two names and no time"
    );
    assert_eq!(
        files.journal.hostname("192.0.2.5", Some(150)).as_deref(),
        Some("two.test")
    );
    assert_eq!(
        files.journal.hostname("192.0.2.5", Some(50)),
        None,
        "asked before any answer"
    );
    assert_eq!(files.journal.hostname("198.18.0.1", None), None);
    let connect = with_address(
        tests::call(1, 42, "connect", 0),
        "arg1.address",
        2,
        [203, 0, 113, 9],
        80,
    );
    let events = run(&mut files, &[connect]);
    let event = of(&events, "network_connection")[0];
    assert_eq!(event["fields"]["DestinationHostname"], "one.test");
    assert_eq!(
        event["_inferred"],
        serde_json::json!(["DestinationHostname"])
    );
}

#[test]
fn auditd_records_use_audit_field_names_and_never_invent_credentials_or_hashes() {
    let mut files = FdState::default();
    let calls = [
        exec(7, "/usr/bin/chmod", &["chmod", "u+s", "/tmp/x"]),
        with_address(
            with_args(tests::call(7, 42, "connect", 0), [4, 0, 16, 0, 0, 0]),
            "arg1.address",
            2,
            [203, 0, 113, 9],
            443,
        ),
        tests::path_call(7, 87, "unlink", 0, "/tmp/gone"),
        with_args(
            tests::call(7, 135, "personality", 0),
            [0x40000, 0, 0, 0, 0, 0],
        ),
    ];
    let events = run(&mut files, &calls);
    let syscall = auditd(&events, "SYSCALL");
    let first = &syscall[0]["fields"];
    assert_eq!(first["Syscall"], "execve");
    assert_eq!(first["exe"], "/usr/bin/chmod");
    assert_eq!(first["comm"], "chmod");
    assert_eq!(first["exit"], "0");
    assert_eq!(first["success"], "yes");
    assert_eq!(syscall[0]["_inferred"], serde_json::json!(["exe", "comm"]));
    assert_eq!(syscall.last().unwrap()["fields"]["a0"], "40000");
    let execve = &auditd(&events, "EXECVE")[0]["fields"];
    for (key, value) in [
        ("a0", "chmod"),
        ("a1", "u+s"),
        ("a2", "/tmp/x"),
        ("argc", "3"),
    ] {
        assert_eq!(execve[key], value);
    }
    assert_eq!(
        auditd(&events, "SOCKADDR")[0]["fields"]["saddr"],
        "0200 01BB CB007109".replace(' ', "") + "0000000000000000"
    );
    let paths: Vec<_> = auditd(&events, "PATH")
        .into_iter()
        .map(|event| {
            let text = |key: &str| event["fields"][key].as_str().unwrap().to_owned();
            (text("name"), text("nametype"))
        })
        .collect();
    let pair = |name: &str, kind: &str| (name.to_owned(), kind.to_owned());
    assert_eq!(
        paths,
        [
            pair("/usr/bin/chmod", "NORMAL"),
            pair("/tmp/gone", "DELETE")
        ]
    );
    for event in of(&events, "auditd") {
        for missing in [
            "auid", "uid", "euid", "suid", "fsuid", "gid", "egid", "sgid", "fsgid", "ses", "key",
            "mode", "inode", "User", "LogonId", "Hashes",
        ] {
            assert!(
                event["fields"].get(missing).is_none(),
                "{missing} needs a record the kernel did not write"
            );
        }
    }
}

#[test]
fn an_incomplete_argument_vector_gives_no_argc_and_only_the_arguments_that_were_whole() {
    let mut row = exec(7, "/bin/cp", &["cp", "a"]);
    let entry = row.entry.as_mut().unwrap();
    entry.fields.retain(|field| field.key != "arg1.ptr[2]");
    entry.fields[3].complete = false;
    let mut files = FdState::default();
    let events = run(&mut files, &[row]);
    let execve = &auditd(&events, "EXECVE")[0]["fields"];
    assert_eq!(execve["a0"], "cp");
    assert!(execve.get("a1").is_none());
    assert!(execve.get("argc").is_none());
}

use antinomie_monitor_core::kernel_notes::{CREDS_KEY, HASH_KEY};

/// A credentials record: `ids` are uid, euid, suid, fsuid then the gids.
fn creds_note(ids: [u32; 8], login: Option<u32>, audit: bool, reason: u32) -> EventSummary {
    let mut bytes: Vec<u8> = ids.iter().flat_map(|id| id.to_le_bytes()).collect();
    let (auid, session) = match login {
        Some(auid) => (auid, 3),
        None => (u32::MAX, u32::MAX),
    };
    for value in [auid, session, reason, u32::from(audit)] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend([0; 24]);
    note(CREDS_KEY, "antinomie.creds/1", &bytes)
}

fn hash_note(kind: u8, status: u8, flags: u8, size: u64) -> EventSummary {
    let mut bytes = vec![0u8; 80];
    bytes[0] = kind;
    bytes[1] = status;
    bytes[2] = u8::from(status == 0);
    bytes[3] = flags;
    bytes[8..16].copy_from_slice(&size.to_le_bytes());
    bytes[24..32].copy_from_slice(&(16u64 << 20).to_le_bytes());
    if status == 0 {
        bytes[32..64].fill(0xab);
    }
    note(HASH_KEY, "antinomie.hash/1", &bytes)
}

fn note(key: &str, layout: &str, bytes: &[u8]) -> EventSummary {
    let mut event = tests::call(1, 0, "", 0).entry.unwrap();
    event.phase = 3;
    event.args = None;
    event.fields = vec![tests::captured(key, layout, bytes)];
    event
}

fn with_notes(mut row: InvocationSummary, notes: Vec<EventSummary>) -> InvocationSummary {
    row.kernel_notes = notes;
    row
}

const ROOT: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const USER: [u32; 8] = [1000, 1000, 1000, 1000, 100, 100, 100, 100];

#[test]
fn credentials_follow_the_task_and_apply_after_the_call_that_changed_them() {
    let mut files = FdState::default();
    let calls = [
        with_notes(
            exec(1, "/bin/sh", &["sh"]),
            vec![creds_note(ROOT, None, true, 1)],
        ),
        with_notes(
            tests::call(1, 105, "setuid", 0),
            vec![creds_note(USER, None, true, 2)],
        ),
        exec(1, "/bin/id", &["id"]),
    ];
    let events = run(&mut files, &calls);
    let users: Vec<_> = of(&events, "process_creation")
        .iter()
        .map(|event| event["fields"]["User"].clone())
        .collect();
    assert_eq!(users, ["0", "1000"], "numeric uid, not a guessed name");
    for event in of(&events, "process_creation") {
        assert!(
            event["fields"].get("LogonId").is_none(),
            "the guest never set a login uid"
        );
    }
    let syscall = auditd(&events, "SYSCALL");
    let ids = |event: &Fields| {
        ["uid", "euid", "suid", "fsuid", "gid", "egid", "auid", "ses"]
            .map(|name| event["fields"][name].as_str().unwrap().to_owned())
    };
    assert_eq!(
        ids(syscall[0]),
        ["0", "0", "0", "0", "0", "0", "4294967295", "4294967295"],
        "an unset login uid is what auditd prints"
    );
    assert_eq!(
        ids(syscall[1]),
        [
            "1000",
            "1000",
            "1000",
            "1000",
            "100",
            "100",
            "4294967295",
            "4294967295"
        ]
    );
}

#[test]
fn a_login_uid_is_the_logon_id_and_an_untracked_one_is_left_out() {
    let mut files = FdState::default();
    let calls = [
        with_notes(
            exec(1, "/bin/a", &["a"]),
            vec![creds_note(USER, Some(1000), true, 1)],
        ),
        with_notes(
            exec(2, "/bin/b", &["b"]),
            vec![creds_note(USER, None, false, 1)],
        ),
    ];
    let events = run(&mut files, &calls);
    let creations = of(&events, "process_creation");
    assert_eq!(creations[0]["fields"]["LogonId"], 1000);
    assert!(creations[1]["fields"].get("LogonId").is_none());
    let syscall = auditd(&events, "SYSCALL");
    assert_eq!(syscall[0]["fields"]["auid"], "1000");
    assert_eq!(syscall[0]["fields"]["ses"], "3");
    assert!(syscall[1]["fields"].get("auid").is_none());
    assert_eq!(syscall[1]["fields"]["euid"], "1000");
}

#[test]
fn an_exec_and_a_delete_carry_the_hash_the_guest_recorded() {
    let mut files = FdState::default();
    let calls = [
        with_notes(exec(1, "/bin/sh", &["sh"]), vec![hash_note(1, 0, 0, 100)]),
        with_notes(
            tests::path_call(1, 87, "unlink", 0, "/tmp/gone"),
            vec![hash_note(2, 0, 0, 5)],
        ),
    ];
    let events = run(&mut files, &calls);
    let want = format!("SHA256={}", "ab".repeat(32));
    assert_eq!(of(&events, "process_creation")[0]["fields"]["Hashes"], want);
    assert_eq!(of(&events, "file_delete")[0]["fields"]["Hashes"], want);
}

#[test]
fn a_skipped_hash_says_why_and_a_missing_one_leaves_the_field_out() {
    let mut files = FdState::default();
    let calls = [
        with_notes(
            tests::path_call(1, 87, "unlink", 0, "/tmp/big"),
            vec![hash_note(2, 1, 0, 40 << 20)],
        ),
        with_notes(
            exec(1, "/usr/bin/env", &["env", "x"]),
            vec![hash_note(1, 0, 1, 100)],
        ),
        tests::path_call(1, 87, "unlink", 0, "/tmp/plain"),
    ];
    let events = run(&mut files, &calls);
    let deletes = of(&events, "file_delete");
    let big = &deletes[0]["fields"];
    assert!(big.get("Hashes").is_none());
    let why = big["HashSkipped"].as_str().unwrap();
    assert!(why.contains("over the 16 MiB limit"), "{why}");
    let script = &of(&events, "process_creation")[0]["fields"];
    assert!(script.get("Hashes").is_none());
    assert!(script["HashSkipped"]
        .as_str()
        .unwrap()
        .contains("interpreter"));
    for field in ["Hashes", "HashSkipped"] {
        assert!(
            deletes[1]["fields"].get(field).is_none(),
            "no record, no {field}"
        );
    }
}

#[test]
fn a_failed_delete_still_reports_nothing_the_guest_did_not_record() {
    let mut files = FdState::default();
    let events = run(
        &mut files,
        &[with_notes(
            tests::path_call(1, 87, "unlink", -2, "/tmp/missing"),
            vec![hash_note(2, 0, 0, 5)],
        )],
    );
    assert!(of(&events, "file_delete").is_empty());
}

#[test]
#[ignore = "requires a run recorded by a kernel with credential and hash records in ANTINOMIE_NOTES_RUN"]
fn a_recorded_run_reaches_the_journal_with_credentials_and_hashes() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("ANTINOMIE_NOTES_RUN").expect("set the recorded run directory"),
    );
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).unwrap()).unwrap();
    let text = |key: &str| run[key].as_str().unwrap().to_owned();
    let request = ScanRequest {
        root_cookie: run["root_task_cookie"].as_u64().unwrap(),
        identity: Some((text("vm_id"), text("boot_id"), text("id"))),
        run_finished: true,
        ..Default::default()
    };
    let scan = archive_scan::scan_archive_query(
        &directory,
        None,
        false,
        &Arc::new(AtomicBool::new(false)),
        &request,
    )
    .unwrap();
    assert!(scan.event_error.is_none(), "{:?}", scan.event_error);
    let journal = std::fs::read_to_string(
        directory.join(antinomie_monitor_core::analysis::detection::JOURNAL_FILE),
    )
    .unwrap();
    let events: Vec<Fields> = journal
        .lines()
        .map(|line| serde_json::from_str::<Fields>(line).unwrap())
        .filter(|line| line["kind"] == "event")
        .map(|line| line["event"].clone())
        .collect();
    let mut shown = 0;
    for event in &events {
        let fields = &event["fields"];
        let interesting = fields.get("Hashes").is_some()
            || fields.get("HashSkipped").is_some()
            || (event["category"] == "auditd"
                && fields["type"] == "SYSCALL"
                && fields["Syscall"] == "execve");
        if interesting {
            shown += 1;
            eprintln!("{} {}", event["category"], fields);
        }
    }
    assert!(shown > 0, "no event carries a hash or credentials");
    assert!(events
        .iter()
        .any(|event| event["category"] == "process_creation"
            && event["fields"]["Hashes"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("SHA256="))
            && event["fields"]["User"].is_string()));
    assert!(events
        .iter()
        .any(|event| event["category"] == "file_delete" && event["fields"]["Hashes"].is_string()));
    assert!(events.iter().any(|event| event["fields"]["HashSkipped"]
        .as_str()
        .is_some_and(|why| why.contains("16 MiB"))));
    assert!(events.iter().any(|event| event["category"] == "auditd"
        && event["fields"]["euid"] == "0"
        && event["fields"]["uid"] == "1000"));
}
