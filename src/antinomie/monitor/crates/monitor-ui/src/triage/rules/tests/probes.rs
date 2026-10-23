// SPDX-License-Identifier: GPL-3.0-only
//! The Evasion category: every anti-analysis check, the answer the guest gave, and what the task did next.
use super::support::*;

/// A task that opens a file, reads it and gets `answer`.
fn probe(pid: u32, path: &str, fd: i64, answer: &[u8]) -> Calls {
    vec![
        open_read(pid, path, fd),
        read(pid, fd as u64, answer),
        close(pid, fd as u64),
    ]
}

fn detail(row: &Finding) -> Vec<String> {
    list(row, "finding.detail")
}

#[test]
fn one_check_is_info_and_two_kinds_of_vm_evidence_are_a_medium_sandbox_probe() {
    let one = run(probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n"));
    let row = rows(&one, "evasion.sandbox_probe");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "info");
    let mut calls = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n");
    calls.extend(probe(
        1,
        "/proc/cpuinfo",
        4,
        b"model name\t: Intel\nflags\t\t: fpu vme hypervisor\n",
    ));
    let two = run(calls);
    let row = rows(&two, "evasion.sandbox_probe");
    assert_eq!(row.len(), 1, "one row per task");
    assert_eq!(text(row[0], "finding.tier"), "medium");
    assert_eq!(list(row[0], "finding.technique"), ["T1497.001", "DET0168"]);
    assert_eq!(text(row[0], "finding.category"), "evasion");
    assert!(
        text(row[0], "finding.summary").contains("2 checks"),
        "{}",
        text(row[0], "finding.summary")
    );
}

#[test]
fn details_list_each_check_with_the_answer_and_what_decides_it() {
    let mut calls = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n");
    calls.extend(probe(
        1,
        "/sys/class/dmi/id/product_name",
        4,
        b"Latitude 7490\n",
    ));
    calls.extend(probe(
        1,
        "/proc/cpuinfo",
        5,
        b"model name\t: Intel(R) Core(TM) i7\nflags\t\t: fpu vme\n",
    ));
    calls.extend(probe(
        1,
        "/sys/class/net/eth0/address",
        6,
        b"52:54:00:12:34:56\n",
    ));
    calls.extend(probe(1, "/proc/uptime", 7, b"31.52 28.10\n"));
    let out = run(calls);
    let lines = detail(rows(&out, "evasion.sandbox_probe")[0]).join("\n");
    assert!(
        lines.contains("sys_vendor")
            && lines.contains("\"QEMU\"")
            && lines.contains("would show it"),
        "{lines}"
    );
    assert!(
        lines.contains("\"Latitude 7490\"") && lines.contains("does not show it"),
        "{lines}"
    );
    assert!(lines.contains("no hypervisor flag"), "{lines}");
    assert!(lines.contains("52:54:00:12:34:56"), "{lines}");
    assert!(lines.contains("up 32 s"), "a fresh boot is a tell: {lines}");
    assert!(
        lines.contains("Stealth profile › Machine identity"),
        "{lines}"
    );
    assert!(lines.contains("Stealth profile › Network card"), "{lines}");
    assert!(lines.contains("Still visible"), "{lines}");
    assert!(
        lines.contains("CPUID"),
        "instruction-level checks are said to be invisible: {lines}"
    );
    assert!(lines.contains("call 1"), "{lines}");
    assert!(lines.contains("Heuristic"), "{lines}");
}

#[test]
fn hypervisor_cpu_flag_pci_vendors_clocksource_and_modules_are_judged() {
    let cpu = |flags: &str| {
        let out = run(probe(
            1,
            "/proc/cpuinfo",
            3,
            format!("model name\t: X\nflags\t\t: {flags}\n").as_bytes(),
        ));
        detail(rows(&out, "evasion.sandbox_probe")[0]).join("\n")
    };
    assert!(cpu("fpu hypervisor lm").contains("flags include hypervisor"));
    assert!(cpu("fpu lm").contains("no hypervisor flag"));
    let pci = run(probe(
        1,
        "/sys/bus/pci/devices/0000:00:03.0/vendor",
        3,
        b"0x1af4\n",
    ));
    assert!(detail(rows(&pci, "evasion.sandbox_probe")[0])
        .join("\n")
        .contains("would show it"));
    let real = run(probe(
        1,
        "/sys/bus/pci/devices/0000:00:03.0/vendor",
        3,
        b"0x8086\n",
    ));
    assert!(detail(rows(&real, "evasion.sandbox_probe")[0])
        .join("\n")
        .contains("does not show it"));
    let clock = run(probe(
        1,
        "/sys/devices/system/clocksource/clocksource0/current_clocksource",
        3,
        b"kvm-clock\n",
    ));
    assert!(detail(rows(&clock, "evasion.sandbox_probe")[0])
        .join("\n")
        .contains("would show it"));
    let modules = run(probe(
        1,
        "/proc/modules",
        3,
        b"vboxguest 1234 0 - Live 0x0\n",
    ));
    assert!(detail(rows(&modules, "evasion.sandbox_probe")[0])
        .join("\n")
        .contains("would show it"));
    let files = run(vec![
        stat(1, "/dev/vboxguest", -2),
        stat(1, "/sys/hypervisor/type", -2),
    ]);
    let lines = detail(rows(&files, "evasion.sandbox_probe")[0]).join("\n");
    assert!(
        lines.contains("not available (ENOENT)") && lines.contains("does not show it"),
        "{lines}"
    );
}

#[test]
fn disk_models_and_vendor_strings_are_checks_too() {
    let out = run(probe(
        1,
        "/sys/block/sda/device/model",
        3,
        b"QEMU HARDDISK   \n",
    ));
    let lines = detail(rows(&out, "evasion.sandbox_probe")[0]).join("\n");
    assert!(
        lines.contains("would show it") && lines.contains("Stealth profile › Devices"),
        "{lines}"
    );
    let scsi = run(probe(
        1,
        "/proc/scsi/scsi",
        3,
        b"Vendor: ATA Model: VBOX HARDDISK\n",
    ));
    assert!(detail(rows(&scsi, "evasion.sandbox_probe")[0])
        .join("\n")
        .contains("would show it"));
}

#[test]
fn a_tool_that_inspects_the_machine_is_a_check_whose_output_is_not_captured() {
    let out = run(vec![exec(
        1,
        "/usr/sbin/dmidecode",
        &["dmidecode", "-s", "system-product-name"],
    )]);
    let row = rows(&out, "evasion.sandbox_probe");
    assert_eq!(row.len(), 1);
    assert!(detail(row[0])
        .join("\n")
        .contains("its output is not captured"));
    assert!(has(
        &run(vec![exec(
            1,
            "/usr/bin/systemd-detect-virt",
            &["systemd-detect-virt"]
        )]),
        "evasion.sandbox_probe"
    ));
}

#[test]
fn tracer_pid_in_proc_self_status_is_a_debugger_check_with_the_value_it_read() {
    let status = |tracer: u32| {
        let text = format!("Name:\tx\nUmask:\t0022\nState:\tR (running)\nTgid:\t1\nNgid:\t0\nPid:\t1\nPPid:\t0\nTracerPid:\t{tracer}\nUid:\t0\n");
        run(probe(1, "/proc/self/status", 3, text.as_bytes()))
    };
    let clean = status(0);
    let row = rows(&clean, "evasion.debugger_check");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "low");
    assert_eq!(list(row[0], "finding.technique"), ["T1622", "DET0371"]);
    let lines = detail(row[0]).join("\n");
    assert!(
        lines.contains("TracerPid 0") && lines.contains("does not show it"),
        "{lines}"
    );
    assert!(
        lines.contains("Antinomie's debugger uses no ptrace"),
        "{lines}"
    );
    let traced = status(4242);
    assert!(detail(rows(&traced, "evasion.debugger_check")[0])
        .join("\n")
        .contains("TracerPid 4242"));
    assert!(detail(rows(&traced, "evasion.debugger_check")[0])
        .join("\n")
        .contains("would show it"));
    let by_pid = run(probe(9, "/proc/9/status", 3, b"TracerPid:\t0\n"));
    assert!(
        has(&by_pid, "evasion.debugger_check"),
        "its own pid is itself"
    );
}

#[test]
fn ptrace_traceme_prctl_dumpable_and_a_sigtrap_handler_join_the_debugger_row() {
    let traceme = sys(1, 101, "ptrace", [0; 6], 0);
    let dumpable = sys(1, 157, "prctl", [3, 0, 0, 0, 0, 0], 1);
    let mut handler = 0x4000_1000u64.to_le_bytes().to_vec();
    handler.extend([0; 24]);
    let sigtrap = with_entry(
        sys(1, 13, "rt_sigaction", [5, 0x1000, 0, 8, 0, 0], 0),
        "arg1.sigaction",
        &handler,
    );
    let out = run(vec![traceme, dumpable, sigtrap]);
    let lines = detail(rows(&out, "evasion.debugger_check")[0]).join("\n");
    assert!(
        lines.contains("ptrace(PTRACE_TRACEME)") && lines.contains("accepted"),
        "{lines}"
    );
    assert!(lines.contains("PR_GET_DUMPABLE"), "{lines}");
    assert!(lines.contains("SIGTRAP handler installed"), "{lines}");
    let refused = run(vec![sys(1, 101, "ptrace", [0; 6], -1)]);
    let lines = detail(rows(&refused, "evasion.debugger_check")[0]).join("\n");
    assert!(
        lines.contains("refused") && lines.contains("would show it"),
        "{lines}"
    );
    let default = {
        let mut zero = vec![0u8; 32];
        zero[0] = 0;
        with_entry(
            sys(1, 13, "rt_sigaction", [5, 0x1000, 0, 8, 0, 0], 0),
            "arg1.sigaction",
            &zero,
        )
    };
    assert!(!has(&run(vec![default]), "evasion.debugger_check"));
}

#[test]
fn container_markers_are_a_low_row_and_absence_is_the_answer() {
    let out = run(vec![
        stat(1, "/.dockerenv", -2),
        stat(1, "/run/.containerenv", -2),
    ]);
    let row = rows(&out, "evasion.container_check");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "low");
    let lines = detail(row[0]).join("\n");
    assert!(
        lines.contains("not available (ENOENT)") && lines.contains("does not show it"),
        "{lines}"
    );
    assert!(lines.contains("not a container"), "{lines}");
    let present = run(vec![stat(1, "/.dockerenv", 0)]);
    assert!(detail(rows(&present, "evasion.container_check")[0])
        .join("\n")
        .contains("would show it"));
    let cgroup = run(probe(1, "/proc/1/cgroup", 3, b"0::/docker/abc\n"));
    assert!(has(&cgroup, "evasion.container_check"));
    assert!(
        !has(&cgroup, "evasion.sandbox_probe"),
        "container checks have their own row"
    );
}

#[test]
fn an_exit_right_after_a_revealing_answer_is_probe_then_exit() {
    let mut calls = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n");
    calls.extend(probe(1, "/proc/cpuinfo", 4, b"flags\t: hypervisor\n"));
    calls.push(at(sys(1, 231, "exit_group", [0; 6], 0), 2 * SECOND));
    let out = run(calls);
    let row = rows(&out, "evasion.probe_then_exit");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "medium");
    let lines = detail(row[0]).join("\n");
    assert!(lines.contains("QEMU"), "{lines}");
    assert!(
        lines.contains("Heuristic"),
        "the verdict says it is a heuristic: {lines}"
    );
    let probe_row = rows(&out, "evasion.sandbox_probe")[0];
    assert!(
        detail(probe_row).join("\n").contains("exited"),
        "{:?}",
        detail(probe_row)
    );
}

#[test]
fn work_after_the_checks_means_no_reaction() {
    let mut calls = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n");
    calls.extend(probe(1, "/proc/cpuinfo", 4, b"flags\t: hypervisor\n"));
    calls.push(at(socket(1, 2, 1, 5), 2 * SECOND));
    calls.push(at(connect(1, 5, [203, 0, 113, 9], 443), 3 * SECOND));
    calls.push(at(sys(1, 231, "exit_group", [0; 6], 0), 4 * SECOND));
    let out = run(calls);
    assert!(!has(&out, "evasion.probe_then_exit"));
    let lines = detail(rows(&out, "evasion.sandbox_probe")[0]).join("\n");
    assert!(
        lines.contains("went on") || lines.contains("network calls"),
        "{lines}"
    );
}

#[test]
fn a_late_exit_or_a_check_that_shows_nothing_is_not_probe_then_exit() {
    let mut late = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n");
    late.push(at(sys(1, 231, "exit_group", [0; 6], 0), 60 * SECOND));
    assert!(!has(&run(late), "evasion.probe_then_exit"));
    let mut clean = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"Dell Inc.\n");
    clean.push(at(sys(1, 231, "exit_group", [0; 6], 0), 2 * SECOND));
    assert!(!has(&run(clean), "evasion.probe_then_exit"));
}

#[test]
fn a_task_that_stops_using_the_network_after_its_checks_is_reported_so() {
    let mut calls = vec![socket(1, 2, 1, 5), connect(1, 5, [203, 0, 113, 9], 443)];
    calls.extend(probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n"));
    calls.push(at(
        sys(1, 35, "nanosleep", [0x1000, 0, 0, 0, 0, 0], 0),
        20 * SECOND,
    ));
    let out = run(calls);
    let lines = detail(rows(&out, "evasion.sandbox_probe")[0]).join("\n");
    assert!(lines.contains("stopped making network calls"), "{lines}");
}

#[test]
fn a_long_sleep_after_a_revealing_check_is_a_reaction() {
    let sleep = |seconds: u64| {
        let mut data = seconds.to_le_bytes().to_vec();
        data.extend(0u64.to_le_bytes());
        with_entry(
            sys(1, 35, "nanosleep", [0x1000, 0, 0, 0, 0, 0], 0),
            "arg0.data",
            &data,
        )
    };
    let mut calls = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n");
    calls.push(at(sleep(600), 2 * SECOND));
    let out = run(calls);
    assert_eq!(rows(&out, "evasion.probe_then_exit").len(), 1);
    assert!(text(rows(&out, "evasion.probe_then_exit")[0], "finding.summary").contains("sleep"));
    assert!(has(&out, "evasion.long_sleep"));
}

#[test]
fn a_loop_of_clock_reads_is_a_timing_check() {
    let mut calls = Vec::new();
    for at_ms in 0..40u64 {
        calls.push(at(
            sys(1, 228, "clock_gettime", [1, 0x1000, 0, 0, 0, 0], 0),
            at_ms * 10 * MS,
        ));
    }
    let out = run(calls);
    let lines = detail(rows(&out, "evasion.sandbox_probe")[0]).join("\n");
    assert!(
        lines.contains("clock reads in a loop") && lines.contains("within one second"),
        "{lines}"
    );
    let few = run((0..5u64)
        .map(|n| {
            at(
                sys(1, 228, "clock_gettime", [1, 0x1000, 0, 0, 0, 0], 0),
                n * MS,
            )
        })
        .collect());
    assert!(!has(&few, "evasion.sandbox_probe"));
}

#[test]
fn sysinfo_uptime_and_the_mac_ioctl_are_read_from_their_buffers() {
    let sysinfo = with_exit(
        sys(1, 99, "sysinfo", [0x1000, 0, 0, 0, 0, 0], 0),
        "arg0.data",
        &45u64.to_le_bytes().repeat(14),
    );
    let out = run(vec![sysinfo]);
    assert!(detail(rows(&out, "evasion.sandbox_probe")[0])
        .join("\n")
        .contains("up 45 s"));
    let mut ifreq = b"eth0".to_vec();
    ifreq.resize(16, 0);
    ifreq.extend(1u16.to_le_bytes());
    ifreq.extend([0x08, 0x00, 0x27, 0xaa, 0xbb, 0xcc]);
    let mac = with_exit(
        sys(1, 16, "ioctl", [3, 0x8927, 0x2000, 0, 0, 0], 0),
        "arg2.data",
        &ifreq,
    );
    let lines = detail(rows(&run(vec![mac]), "evasion.sandbox_probe")[0]).join("\n");
    assert!(
        lines.contains("08:00:27:aa:bb:cc") && lines.contains("would show it"),
        "{lines}"
    );
}

#[test]
fn the_probe_rows_belong_to_the_evasion_category_filter() {
    let mut calls = probe(1, "/sys/class/dmi/id/sys_vendor", 3, b"QEMU\n");
    calls.extend(probe(1, "/proc/cpuinfo", 4, b"flags\t: hypervisor\n"));
    let out = run(calls);
    let evasion = View {
        categories: 1 << 3,
        ..View::default()
    };
    let kept: Vec<_> = out
        .rows
        .iter()
        .filter(|row| view_keeps(&evasion, &row.values))
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(text(kept[0], "finding.rule"), "evasion.sandbox_probe");
    // Reading cpuinfo is also system discovery, which the Evasion chip leaves out.
    assert!(has(&out, "discovery.system_info"));
    let discovery = View {
        categories: 1 << 5,
        ..View::default()
    };
    assert!(out
        .rows
        .iter()
        .filter(|row| view_keeps(&discovery, &row.values))
        .all(|row| text(row, "finding.category") == "discovery"));
}

#[test]
fn a_debuggers_child_calling_traceme_before_its_exec_is_not_a_check() {
    let out = run(vec![
        sys(1, 101, "ptrace", [0; 6], 0),
        exec(1, "/bin/true", &["true"]),
    ]);
    assert!(!has(&out, "evasion.traceme"));
    assert!(!has(&out, "evasion.debugger_check"));
    let alone = run(vec![sys(1, 101, "ptrace", [0; 6], 0)]);
    assert!(has(&alone, "evasion.traceme") && has(&alone, "evasion.debugger_check"));
}
