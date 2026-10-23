// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;

#[test]
fn writable_and_executable_memory_is_high_with_or_without_read() {
    for prot in [7, 6] {
        let out = run(vec![mmap(1, prot, 0x22, 0x7000)]);
        let row = rows(&out, "memory.rwx");
        assert_eq!(row.len(), 1, "prot {prot}");
        assert_eq!(text(row[0], "finding.tier"), "high");
        assert_eq!(text(row[0], "finding.version"), "");
        assert_eq!(list(row[0], "finding.technique"), ["T1620", "DET0300"]);
    }
    assert!(
        !has(&run(vec![mmap(1, 5, 0x22, 0x7000)]), "memory.rwx"),
        "read and execute is a normal mapping"
    );
    let protect = run(vec![sys(1, 10, "mprotect", [0x7000, 4096, 7, 0, 0, 0], 0)]);
    assert!(has(&protect, "memory.rwx"));
    let keyed = run(vec![sys(
        1,
        329,
        "pkey_mprotect",
        [0x7000, 4096, 6, 0, 0, 0],
        0,
    )]);
    assert!(
        has(&keyed, "memory.rwx"),
        "a protection key is still a protection change"
    );
}

#[test]
fn a_refused_request_keeps_its_own_row_and_a_jit_runtime_is_one_tier_down() {
    let refused = run(vec![mmap(1, 7, 0x22, -1)]);
    assert!(!has(&refused, "memory.rwx"));
    assert_eq!(
        tier(&refused, "memory.rwx_attempt").as_deref(),
        Some("medium")
    );
    let mut jit = vec![exec(1, "/usr/lib/jvm/bin/java", &["java"])];
    jit.push(mmap(1, 7, 0x22, 0x7000));
    let out = run(jit);
    let row = rows(&out, "memory.rwx");
    assert_eq!(text(row[0], "finding.tier"), "medium");
    assert!(list(row[0], "finding.flags").contains(&"allow-listed".to_owned()));
}

#[test]
fn memory_written_and_then_made_executable_is_medium() {
    let out = run(vec![
        mmap(1, 3, 0x22, 0x7000_0000),
        sys(1, 10, "mprotect", [0x7000_0000, 4096, 5, 0, 0, 0], 0),
    ]);
    assert_eq!(
        tier(&out, "memory.wx_transition").as_deref(),
        Some("medium")
    );
    assert_eq!(
        list(rows(&out, "memory.wx_transition")[0], "finding.technique"),
        ["T1027.002", "DET0023", "T1620"]
    );
    // Memory never mapped writable by this task is a plain protection change.
    let plain = run(vec![sys(
        1,
        10,
        "mprotect",
        [0x9000_0000, 4096, 5, 0, 0, 0],
        0,
    )]);
    assert!(!has(&plain, "memory.wx_transition"));
}

#[test]
fn a_program_that_removes_its_own_file_while_running_is_self_deleting() {
    let out = run(vec![exec(1, "/tmp/.x", &["x"]), unlink(1, "/tmp/.x")]);
    let row = rows(&out, "evasion.self_delete");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "high");
    assert_eq!(list(row[0], "finding.technique"), ["T1070.004", "DET0140"]);
    // After it exited, removing the file is cleaning up.
    let later = run(vec![
        exec(1, "/tmp/.x", &["x"]),
        sys(1, 231, "exit_group", [0; 6], 0),
        unlink(2, "/tmp/.x"),
    ]);
    assert!(!has(&later, "evasion.self_delete"));
    // By identity: the unlinked inode is the one a live task runs.
    let by_key = run(vec![
        with_notes(exec(1, "/tmp/a", &["a"]), vec![file_id(6, 900, 1)]),
        with_notes(unlink(2, "/tmp/other-name"), vec![file_id(4, 900, 0)]),
    ]);
    assert!(has(&by_key, "evasion.self_delete"));
}

#[test]
fn clearing_logs_and_history_covers_files_the_ring_buffer_and_tools() {
    for out in [
        run(vec![unlink(1, "/var/log/auth.log")]),
        run(vec![open_truncate(1, "/var/log/wtmp", 3)]),
        run(vec![sys(1, 103, "syslog", [5, 0, 0, 0, 0, 0], 0)]),
        run(vec![exec(
            1,
            "/usr/bin/journalctl",
            &["journalctl", "--vacuum-time=1s"],
        )]),
    ] {
        assert_eq!(tier(&out, "evasion.log_clear").as_deref(), Some("high"));
    }
    assert!(
        !has(
            &run(vec![sys(1, 103, "syslog", [3, 0, 0, 0, 0, 0], 0)]),
            "evasion.log_clear"
        ),
        "reading the ring buffer is not clearing it"
    );
    let mut rotated = vec![exec(1, "/usr/sbin/logrotate", &["logrotate"])];
    rotated.push(unlink(1, "/var/log/syslog.1"));
    assert_eq!(
        tier(&run(rotated), "evasion.log_clear").as_deref(),
        Some("medium")
    );
    for out in [
        run(vec![unlink(1, "/root/.bash_history")]),
        run(vec![open_truncate(1, "/home/user/.zsh_history", 3)]),
        run(vec![exec_env(
            1,
            "/bin/ls",
            &["ls"],
            &["HISTFILE=/dev/null"],
        )]),
        run(vec![shell(1, "history -c; ls")]),
        run(vec![shell(1, "unset HISTFILE")]),
    ] {
        assert_eq!(
            tier(&out, "evasion.history_clear").as_deref(),
            Some("medium")
        );
    }
}

#[test]
fn turning_off_security_tools_the_firewall_and_audit() {
    for (script, rule) in [
        ("setenforce 0", "evasion.security_disable"),
        ("systemctl stop falcon-sensor", "evasion.security_disable"),
        ("systemctl disable apparmor", "evasion.security_disable"),
        ("service aegis stop", "evasion.security_disable"),
        ("aa-teardown", "evasion.security_disable"),
        ("iptables -F", "evasion.firewall_modify"),
        (
            "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080",
            "evasion.firewall_modify",
        ),
        ("nft flush ruleset", "evasion.firewall_modify"),
        ("ufw disable", "evasion.firewall_modify"),
        ("systemctl stop firewalld", "evasion.firewall_modify"),
        ("auditctl -D", "evasion.audit_disable"),
        ("auditctl -e 0", "evasion.audit_disable"),
        ("systemctl stop auditd", "evasion.audit_disable"),
    ] {
        let out = run(vec![shell(1, script)]);
        assert!(has(&out, rule), "{script}");
    }
    let out = run(vec![shell(1, "setenforce 0")]);
    assert_eq!(
        tier(&out, "evasion.security_disable").as_deref(),
        Some("high")
    );
    assert_eq!(
        list(
            rows(&out, "evasion.security_disable")[0],
            "finding.technique"
        ),
        ["T1685", "DET0497"]
    );
    assert_eq!(
        list(
            rows(
                &run(vec![shell(1, "iptables -F")]),
                "evasion.firewall_modify"
            )[0],
            "finding.technique"
        ),
        ["T1686", "DET0145"]
    );
    assert_eq!(
        list(
            rows(&run(vec![shell(1, "auditctl -D")]), "evasion.audit_disable")[0],
            "finding.technique"
        ),
        ["T1685.004", "DET0062"]
    );
    assert!(!has(
        &run(vec![shell(1, "iptables -L")]),
        "evasion.firewall_modify"
    ));
    assert!(!has(
        &run(vec![shell(1, "setenforce 1")]),
        "evasion.security_disable"
    ));
    for (path, rule) in [
        ("/sys/fs/selinux/enforce", "evasion.security_disable"),
        ("/etc/selinux/config", "evasion.security_disable"),
        ("/etc/audit/rules.d/audit.rules", "evasion.audit_disable"),
    ] {
        let out = run(vec![open_write(1, path, 3), write(1, 3, b"0")]);
        assert!(has(&out, rule), "{path}");
    }
}

#[test]
fn a_process_named_like_a_kernel_thread_or_a_daemon() {
    let renamed = |name: &str| {
        run(vec![
            exec(1, "/tmp/x", &["x"]),
            with_path(
                sys(1, 157, "prctl", [15, 0, 0, 0, 0, 0], 0),
                "arg1.name",
                name,
            ),
        ])
    };
    for name in [
        "[kworker/0:0]",
        "kworker/u8:1",
        "ksoftirqd/0",
        "migration/3",
    ] {
        assert_eq!(
            tier(&renamed(name), "evasion.masquerade_kthread").as_deref(),
            Some("high"),
            "{name}"
        );
    }
    assert_eq!(
        tier(&renamed("sshd"), "evasion.masquerade_daemon").as_deref(),
        Some("medium")
    );
    assert!(!has(&renamed("worker-1"), "evasion.masquerade_daemon"));
    assert!(!has(&renamed("worker-1"), "evasion.masquerade_kthread"));
    let argv = run(vec![exec(1, "/tmp/x", &["[kworker/0:1]"])]);
    assert!(has(&argv, "evasion.masquerade_kthread"));
    let daemon = run(vec![exec(1, "/tmp/x", &["/sbin/udevd", "-d"])]);
    assert!(has(&daemon, "evasion.masquerade_daemon"));
    assert!(!has(
        &run(vec![exec(1, "/usr/sbin/sshd", &["sshd"])]),
        "evasion.masquerade_daemon"
    ));
}

#[test]
fn file_times_set_on_purpose_are_medium_and_now_is_not() {
    let timespec = |sec: u64, nsec: u64| {
        let mut data = Vec::new();
        for (s, n) in [(sec, nsec), (sec, nsec)] {
            data.extend(s.to_le_bytes());
            data.extend(n.to_le_bytes());
        }
        data
    };
    let set = |nsec| {
        let row = with_args(
            path_call_for("utimensat", 280, "/tmp/x"),
            [0, 0, 0x1000, 0, 0, 0],
        );
        with_entry(row, "arg2.data", &timespec(1_200_000_000, nsec))
    };
    assert_eq!(
        tier(&run(vec![set(0)]), "evasion.timestomp").as_deref(),
        Some("medium")
    );
    assert!(
        !has(&run(vec![set(0x3fff_ffff)]), "evasion.timestomp"),
        "UTIME_NOW is not a chosen time"
    );
    let null = with_args(
        path_call_for("utimensat", 280, "/tmp/x"),
        [0, 0, 0, 0, 0, 0],
    );
    assert!(!has(&run(vec![null]), "evasion.timestomp"));
}

fn path_call_for(name: &str, nr: u64, path: &str) -> InvocationSummary {
    with_path(call(1, nr, name, 0), "arg1.filename", path)
}

#[test]
fn hidden_entries_immutable_files_hidden_processes_and_weakened_protections() {
    assert_eq!(
        tier(
            &run(vec![open_write(1, "/tmp/.hidden", 3)]),
            "evasion.hidden_artifact"
        )
        .as_deref(),
        Some("low")
    );
    assert_eq!(
        tier(
            &run(vec![open_write(1, "/usr/share/..hide", 3)]),
            "evasion.hidden_artifact"
        )
        .as_deref(),
        Some("low")
    );
    assert!(
        !has(
            &run(vec![open_write(1, "/home/user/.bashrc", 3)]),
            "evasion.hidden_artifact"
        ),
        "dotfiles in a home are normal"
    );
    assert!(!has(
        &run(vec![open_write(1, "/tmp/visible", 3)]),
        "evasion.hidden_artifact"
    ));
    let flags = |bits: u32| {
        vec![
            open_read(1, "/etc/cron.d/x", 4),
            with_entry(
                sys(1, 16, "ioctl", [4, 0x4008_6602, 0x1000, 0, 0, 0], 0),
                "arg2.data",
                &bits.to_le_bytes(),
            ),
        ]
    };
    assert_eq!(
        tier(&run(flags(0x10)), "evasion.immutable_attr").as_deref(),
        Some("high")
    );
    assert!(
        !has(&run(flags(0x80)), "evasion.immutable_attr"),
        "other attributes are ordinary"
    );
    let plain = run(vec![
        open_read(1, "/tmp/data", 4),
        with_entry(
            sys(1, 16, "ioctl", [4, 0x4008_6602, 0x1000, 0, 0, 0], 0),
            "arg2.data",
            &0x10u32.to_le_bytes(),
        ),
    ]);
    assert_eq!(
        tier(&plain, "evasion.immutable_attr").as_deref(),
        Some("medium")
    );
    assert!(has(
        &run(vec![shell(1, "chattr +i /etc/cron.d/x")]),
        "evasion.immutable_attr"
    ));
    assert!(!has(
        &run(vec![shell(1, "chattr -R +x /tmp")]),
        "evasion.immutable_attr"
    ));
    let mount = with_path(
        with_path(
            sys(1, 165, "mount", [0, 0, 0, 4096, 0, 0], 0),
            "arg1.dir_name",
            "/proc/1234",
        ),
        "arg0.dev_name",
        "/tmp/empty",
    );
    assert_eq!(
        tier(&run(vec![mount]), "evasion.proc_hide_mount").as_deref(),
        Some("high")
    );
    let other = with_path(
        sys(1, 165, "mount", [0, 0, 0, 4096, 0, 0], 0),
        "arg1.dir_name",
        "/mnt/x",
    );
    assert!(!has(&run(vec![other]), "evasion.proc_hide_mount"));
    for path in [
        "/proc/sys/kernel/randomize_va_space",
        "/proc/sys/kernel/yama/ptrace_scope",
        "/proc/sys/kernel/kptr_restrict",
    ] {
        let out = run(vec![open_write(1, path, 3), write(1, 3, b"0")]);
        assert_eq!(
            tier(&out, "evasion.sysctl_security").as_deref(),
            Some("medium"),
            "{path}"
        );
    }
    assert!(has(
        &run(vec![sys(
            1,
            135,
            "personality",
            [0x0004_0000, 0, 0, 0, 0, 0],
            0
        )]),
        "evasion.sysctl_security"
    ));
    assert_eq!(
        tier(
            &run(vec![sys(1, 157, "prctl", [4, 0, 0, 0, 0, 0], 0)]),
            "evasion.dumpable_off"
        )
        .as_deref(),
        Some("low")
    );
    assert!(!has(
        &run(vec![sys(1, 157, "prctl", [4, 1, 0, 0, 0, 0], 0)]),
        "evasion.dumpable_off"
    ));
}

#[test]
fn io_uring_and_seccomp_are_context() {
    let out = run(vec![sys(1, 425, "io_uring_setup", [8, 0, 0, 0, 0, 0], 3)]);
    assert_eq!(
        tier(&out, "evasion.io_uring_usage").as_deref(),
        Some("info")
    );
    let seccomp = run(vec![sys(1, 317, "seccomp", [1, 0, 0, 0, 0, 0], 0)]);
    assert_eq!(tier(&seccomp, "bpf.seccomp_filter").as_deref(), Some("low"));
    let prctl = run(vec![sys(1, 157, "prctl", [22, 2, 0, 0, 0, 0], 0)]);
    assert!(has(&prctl, "bpf.seccomp_filter"));
    assert!(!has(
        &run(vec![sys(1, 157, "prctl", [22, 1, 0, 0, 0, 0], 0)]),
        "bpf.seccomp_filter"
    ));
}

#[test]
fn killing_many_processes_it_did_not_start_is_a_kill_list() {
    let kills = |targets: &[u64]| {
        run(targets
            .iter()
            .map(|pid| sys(1, 62, "kill", [*pid, 9, 0, 0, 0, 0], 0))
            .collect())
    };
    assert_eq!(
        tier(&kills(&[900, 901, 902, 903, 904]), "evasion.kill_list").as_deref(),
        Some("medium")
    );
    assert!(!has(&kills(&[900, 901]), "evasion.kill_list"));
    assert!(has(
        &run(vec![exec(
            1,
            "/usr/bin/pkill",
            &["pkill", "xmrig", "kdevtmpfsi", "cpuminer"]
        )]),
        "evasion.kill_list"
    ));
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/pkill", &["pkill", "xmrig"])]),
        "evasion.kill_list"
    ));
}

#[test]
fn a_sleep_of_a_minute_before_any_work_is_medium_and_later_low() {
    let sleep = |seconds: u64| {
        let mut data = seconds.to_le_bytes().to_vec();
        data.extend(0u64.to_le_bytes());
        with_entry(
            sys(1, 35, "nanosleep", [0x1000, 0, 0, 0, 0, 0], 0),
            "arg0.data",
            &data,
        )
    };
    let early = run(vec![sleep(120)]);
    assert_eq!(
        tier(&early, "evasion.long_sleep").as_deref(),
        Some("medium")
    );
    assert_eq!(
        list(rows(&early, "evasion.long_sleep")[0], "finding.technique"),
        ["T1497.003", "DET0141"]
    );
    let late = run(vec![
        socket(1, 2, 1, 3),
        connect(1, 3, [203, 0, 113, 9], 80),
        sleep(120),
    ]);
    assert_eq!(tier(&late, "evasion.long_sleep").as_deref(), Some("low"));
    assert!(!has(&run(vec![sleep(5)]), "evasion.long_sleep"));
    let clock = with_entry(
        sys(1, 230, "clock_nanosleep", [1, 0, 0x1000, 0, 0, 0], 0),
        "arg2.data",
        &{
            let mut data = 300u64.to_le_bytes().to_vec();
            data.extend(0u64.to_le_bytes());
            data
        },
    );
    assert!(has(&run(vec![clock]), "evasion.long_sleep"));
    assert!(has(
        &run(vec![sys(1, 37, "alarm", [90, 0, 0, 0, 0, 0], 0)]),
        "evasion.long_sleep"
    ));
    assert!(has(
        &run(vec![sys(1, 7, "poll", [0, 0, 120_000, 0, 0, 0], 0)]),
        "evasion.long_sleep"
    ));
}
