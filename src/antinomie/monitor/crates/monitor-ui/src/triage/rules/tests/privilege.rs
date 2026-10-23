// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;

const SYS_ADMIN: u64 = 1 << 21;
/// The task starts as a user.
fn start() -> InvocationSummary {
    with_notes(call(1, 39, "getpid", 1), vec![creds(USER, 0, 1)])
}

#[test]
fn rights_gained_through_a_normal_path_are_medium() {
    let by_setuid = with_notes(
        sys(1, 105, "setuid", [0; 6], 0),
        vec![creds(ROOT, SYS_ADMIN, 2)],
    );
    let out = run(vec![start(), by_setuid]);
    assert_eq!(tier(&out, "privilege.gain").as_deref(), Some("medium"));
    assert_eq!(
        list(rows(&out, "privilege.gain")[0], "finding.technique"),
        ["T1548.001", "DET0110"]
    );
    let by_capset = with_notes(
        sys(1, 126, "capset", [0; 6], 0),
        vec![creds(USER, SYS_ADMIN, 6)],
    );
    assert!(has(&run(vec![start(), by_capset]), "privilege.gain"));
    let by_prctl = with_notes(
        sys(1, 157, "prctl", [47, 0, 0, 0, 0, 0], 0),
        vec![creds(USER, 1 << 12, 11)],
    );
    assert!(has(&run(vec![start(), by_prctl]), "privilege.gain"));
    assert!(
        !has(&run(vec![start()]), "privilege.gain"),
        "the first record is the starting point"
    );
}

#[test]
fn giving_up_rights_is_info_and_does_not_count() {
    let drop = with_notes(
        sys(1, 105, "setuid", [1000, 0, 0, 0, 0, 0], 0),
        vec![creds(USER, 0, 2)],
    );
    let out = run(vec![
        with_notes(call(1, 39, "getpid", 1), vec![creds(ROOT, SYS_ADMIN, 1)]),
        drop,
    ]);
    assert_eq!(tier(&out, "privilege.drop").as_deref(), Some("info"));
    assert_eq!(out.badge, 0);
    assert!(!has(&out, "privilege.gain"));
}

#[test]
fn a_setuid_program_is_low_and_in_a_staging_directory_medium() {
    let run_su = |path: &str| {
        run(vec![
            start(),
            with_notes(exec(1, path, &["x"]), vec![creds(ROOT, SYS_ADMIN, 7)]),
        ])
    };
    let sudo = run_su("/usr/bin/sudo");
    assert_eq!(tier(&sudo, "privilege.setuid_exec").as_deref(), Some("low"));
    assert!(
        has(&sudo, "privilege.gain"),
        "root through an exec is also a gain"
    );
    assert!(
        !has(&sudo, "privilege.kernel_exploit"),
        "sudo is a legitimate path"
    );
    assert_eq!(
        tier(&run_su("/tmp/su"), "privilege.setuid_exec").as_deref(),
        Some("medium")
    );
    let caps = run(vec![
        start(),
        with_notes(
            exec(1, "/usr/bin/ping", &["ping"]),
            vec![creds(USER, 1 << 13, 8)],
        ),
    ]);
    assert_eq!(tier(&caps, "privilege.setuid_exec").as_deref(), Some("low"));
}

#[test]
fn root_during_a_call_that_does_not_change_credentials_is_a_kernel_exploit() {
    let exploit = with_notes(
        sys(1, 16, "ioctl", [3, 0xdead, 0, 0, 0, 0], 0),
        vec![creds(ROOT, SYS_ADMIN, 10)],
    );
    let out = run(vec![start(), exploit]);
    let row = rows(&out, "privilege.kernel_exploit");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "high");
    assert_eq!(list(row[0], "finding.technique"), ["T1068", "DET0514"]);
    assert!(text(row[0], "finding.summary").contains("ioctl"));
    // The kernel's own commit during setsockopt, write or bpf is the same finding.
    for (nr, name) in [
        (1, "write"),
        (54, "setsockopt"),
        (321, "bpf"),
        (250, "keyctl"),
    ] {
        let call = with_notes(
            sys(1, nr, name, [0; 6], 0),
            vec![creds(ROOT, SYS_ADMIN, 10)],
        );
        assert!(
            has(&run(vec![start(), call]), "privilege.kernel_exploit"),
            "{name}"
        );
    }
    // A failed call keeps its tier: there is no failed form of this rule.
    let failed = with_notes(
        sys(1, 16, "ioctl", [3, 0xdead, 0, 0, 0, 0], -1),
        vec![creds(ROOT, SYS_ADMIN, 10)],
    );
    assert_eq!(
        tier(&run(vec![start(), failed]), "privilege.kernel_exploit").as_deref(),
        Some("high")
    );
}

#[test]
fn a_new_user_namespace_is_not_a_kernel_exploit() {
    // unshare(CLONE_NEWUSER) gives capabilities in the new namespace, recorded as Other.
    let unshare = with_notes(
        sys(1, 272, "unshare", [0x1000_0000, 0, 0, 0, 0, 0], 0),
        vec![creds(USER, SYS_ADMIN, 10)],
    );
    let out = run(vec![start(), unshare]);
    assert_eq!(tier(&out, "privilege.userns").as_deref(), Some("medium"));
    assert!(!has(&out, "privilege.kernel_exploit"));
    // Later changes of the same task keep ignoring namespace-local capabilities.
    let later = with_notes(
        sys(1, 16, "ioctl", [3, 1, 0, 0, 0, 0], 0),
        vec![creds(USER, SYS_ADMIN | 1, 10)],
    );
    let out = run(vec![
        start(),
        with_notes(
            sys(1, 272, "unshare", [0x1000_0000, 0, 0, 0, 0, 0], 0),
            vec![creds(USER, SYS_ADMIN, 10)],
        ),
        later,
    ]);
    assert!(!has(&out, "privilege.kernel_exploit"));
    assert!(!has(
        &run(vec![sys(
            1,
            272,
            "unshare",
            [0x4000_0000, 0, 0, 0, 0, 0],
            0
        )]),
        "privilege.userns"
    ));
}

#[test]
fn pkexec_without_arguments_is_high() {
    let mut empty = exec(1, "/usr/bin/pkexec", &[]);
    empty
        .entry
        .as_mut()
        .unwrap()
        .fields
        .retain(|field| !field.key.starts_with("arg1.ptr"));
    empty
        .entry
        .as_mut()
        .unwrap()
        .fields
        .push(captured_pointer(0));
    assert_eq!(
        tier(&run(vec![empty]), "privilege.pwnkit").as_deref(),
        Some("high")
    );
    let with_env = exec_env(1, "/usr/bin/pkexec", &["pkexec", "ls"], &["GCONV_PATH=./x"]);
    assert!(has(&run(vec![with_env]), "privilege.pwnkit"));
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/pkexec", &["pkexec", "ls"])]),
        "privilege.pwnkit"
    ));
}

fn captured_pointer(value: u64) -> antinomie_monitor_core::FieldSummary {
    captured(
        "arg1.ptr[0]",
        "linux-6.12.94/x86_64/pointer",
        &value.to_le_bytes(),
    )
}

#[test]
fn setuid_bits_and_file_capabilities_are_high() {
    for mode in [0o4755, 0o2755, 0o6755] {
        let out = run(vec![chmod(1, "/tmp/sh", mode)]);
        assert_eq!(
            tier(&out, "privilege.setid_bit").as_deref(),
            Some("high"),
            "{mode:o}"
        );
    }
    assert!(!has(
        &run(vec![chmod(1, "/tmp/sh", 0o755)]),
        "privilege.setid_bit"
    ));
    let cap = with_path(
        with_path(call(1, 188, "setxattr", 0), "arg0.path", "/tmp/x"),
        "arg1.xattr_name",
        "security.capability",
    );
    assert!(has(&run(vec![cap]), "privilege.setid_bit"));
    let other = with_path(
        with_path(call(1, 188, "setxattr", 0), "arg0.path", "/tmp/x"),
        "arg1.xattr_name",
        "user.note",
    );
    assert!(!has(&run(vec![other]), "privilege.setid_bit"));
}

#[test]
fn kernel_helpers_that_run_as_root_are_high() {
    for path in [
        "/proc/sys/kernel/core_pattern",
        "/proc/sys/kernel/modprobe",
        "/proc/sys/kernel/hotplug",
        "/sys/kernel/uevent_helper",
        "/proc/sys/fs/binfmt_misc/register",
    ] {
        let out = run(vec![open_write(1, path, 3), write(1, 3, b"|/tmp/x %p")]);
        assert_eq!(
            tier(&out, "privilege.kernel_helper_hijack").as_deref(),
            Some("high"),
            "{path}"
        );
    }
    assert!(!has(
        &run(vec![open_read(1, "/proc/sys/kernel/core_pattern", 3)]),
        "privilege.kernel_helper_hijack"
    ));
}

#[test]
fn reaching_the_host_from_a_container_is_medium() {
    assert_eq!(
        tier(
            &run(vec![exec(
                1,
                "/usr/bin/nsenter",
                &["nsenter", "-t", "1", "-m", "sh"]
            )]),
            "privilege.container_escape"
        )
        .as_deref(),
        Some("medium")
    );
    let setns = run(vec![
        open_read(1, "/proc/1/ns/mnt", 5),
        sys(1, 308, "setns", [5, 0, 0, 0, 0, 0], 0),
    ]);
    assert!(has(&setns, "privilege.container_escape"));
    let socket = |path: &str| {
        let mut data = 1u16.to_le_bytes().to_vec();
        data.extend(path.as_bytes());
        data.push(0);
        with_entry(
            sys(1, 42, "connect", [3, 0, 110, 0, 0, 0], 0),
            "arg1.address",
            &data,
        )
    };
    for path in [
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/podman/podman.sock",
    ] {
        assert!(
            has(&run(vec![socket(path)]), "privilege.container_escape"),
            "{path}"
        );
    }
    assert!(!has(
        &run(vec![socket("/run/user/1000/bus")]),
        "privilege.container_escape"
    ));
    assert!(has(
        &run(vec![connect(1, 3, [10, 0, 0, 5], 2375)]),
        "privilege.container_escape"
    ));
}

#[test]
fn a_page_cache_overwrite_through_a_pipe_is_high() {
    let out = run(vec![
        open_read(1, "/etc/passwd", 3),
        sys(1, 275, "splice", [3, 0, 5, 0, 4096, 0], 4096),
        write(1, 5, b"root::0:0::/:/bin/sh\n"),
    ]);
    assert_eq!(tier(&out, "privilege.dirty_pipe").as_deref(), Some("high"));
    let plain = run(vec![
        open_read(1, "/tmp/data", 3),
        sys(1, 275, "splice", [3, 0, 5, 0, 4096, 0], 4096),
        write(1, 5, b"x"),
    ]);
    assert!(!has(&plain, "privilege.dirty_pipe"));
}

#[test]
fn physical_and_kernel_memory_devices_are_high_for_any_access() {
    for path in ["/dev/mem", "/dev/kmem", "/dev/port", "/proc/kcore"] {
        for out in [
            run(vec![open_read(1, path, 3)]),
            run(vec![open_write(1, path, 3)]),
        ] {
            let row = rows(&out, "rootkit.dev_mem");
            assert_eq!(row.len(), 1, "{path}");
            assert_eq!(text(row[0], "finding.tier"), "high");
            assert_eq!(text(row[0], "finding.category"), "rootkit");
            assert_eq!(list(row[0], "finding.technique"), ["T1014", "DET0377"]);
        }
    }
    assert!(!has(
        &run(vec![open_read(1, "/dev/null", 3)]),
        "rootkit.dev_mem"
    ));
}

#[test]
fn loading_or_attaching_an_ebpf_program_is_medium_and_creating_a_map_is_not() {
    for (command, expected) in [(5, true), (8, true), (9, true), (0, false), (1, false)] {
        let out = run(vec![sys(1, 321, "bpf", [command, 0, 0, 0, 0, 0], 3)]);
        assert_eq!(has(&out, "bpf.program"), expected, "command {command}");
    }
    let out = run(vec![sys(1, 321, "bpf", [5, 0, 0, 0, 0, 0], 3)]);
    assert_eq!(tier(&out, "bpf.program").as_deref(), Some("medium"));
    assert_eq!(
        text(rows(&out, "bpf.program")[0], "finding.category"),
        "rootkit"
    );
}
