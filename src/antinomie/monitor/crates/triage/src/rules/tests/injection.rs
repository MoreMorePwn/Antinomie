// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;

fn ptrace(pid: u32, request: u64, target: u64) -> super::support::Calls {
    vec![sys(pid, 101, "ptrace", [request, target, 0, 0, 0, 0], 0)]
}

#[test]
fn attaching_to_another_process_is_high_and_to_itself_is_not() {
    for request in [16, 0x4206] {
        let out = run(ptrace(1, request, 99));
        assert_eq!(
            tier(&out, "injection.ptrace_attach").as_deref(),
            Some("high"),
            "{request}"
        );
        assert_eq!(
            list(
                rows(&out, "injection.ptrace_attach")[0],
                "finding.technique"
            ),
            ["T1055.008", "DET0203"]
        );
    }
    assert!(!has(&run(ptrace(1, 16, 1)), "injection.ptrace_attach"));
}

#[test]
fn writing_a_tracee_is_high_and_peeking_is_low_and_folded() {
    for request in [4, 5, 6, 13, 15, 0x4205] {
        let out = run(ptrace(1, request, 99));
        assert_eq!(
            tier(&out, "injection.ptrace_poke").as_deref(),
            Some("high"),
            "{request}"
        );
    }
    let mut peeks = Vec::new();
    for _ in 0..1000 {
        peeks.extend(ptrace(1, 2, 99));
    }
    let out = run(peeks);
    let rows = rows(&out, "process.ptrace");
    assert_eq!(rows.len(), 1, "a PEEKDATA loop is one row");
    assert_eq!(text(rows[0], "finding.tier"), "low");
    assert_eq!(count(rows[0]), 1000);
}

#[test]
fn ptrace_traceme_is_an_anti_debug_check_unless_an_exec_follows() {
    let alone = run(ptrace(1, 0, 0));
    assert_eq!(tier(&alone, "evasion.traceme").as_deref(), Some("medium"));
    assert_eq!(
        list(rows(&alone, "evasion.traceme")[0], "finding.technique"),
        ["T1622", "DET0371"]
    );
    // A debugger's child calls it right before exec.
    let mut debugged = ptrace(1, 0, 0);
    debugged.push(exec(1, "/bin/true", &["true"]));
    assert!(!has(&run(debugged), "evasion.traceme"));
}

#[test]
fn process_vm_writev_is_injection_and_readv_is_credential_access() {
    let write = run(vec![sys(
        1,
        311,
        "process_vm_writev",
        [99, 0, 1, 0, 1, 0],
        8,
    )]);
    let row = rows(&write, "injection.vm_write");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "high");
    assert_eq!(
        list(row[0], "finding.technique"),
        ["T1055", "DET0508", "DET0203"]
    );
    let read = run(vec![sys(
        1,
        310,
        "process_vm_readv",
        [99, 0, 1, 0, 1, 0],
        8,
    )]);
    let row = rows(&read, "credential.proc_mem_read");
    assert_eq!(row.len(), 1);
    assert_eq!(list(row[0], "finding.technique"), ["T1003.007", "DET0593"]);
    assert!(
        !has(&read, "injection.vm_write"),
        "reading is not injection"
    );
    let own = run(vec![sys(
        7,
        311,
        "process_vm_writev",
        [7, 0, 1, 0, 1, 0],
        8,
    )]);
    assert!(!has(&own, "injection.vm_write"));
}

#[test]
fn proc_pid_mem_is_injection_for_writes_and_scraping_for_reads() {
    let write = run(vec![open(1, "/proc/99/mem", 2, 3)]);
    let row = rows(&write, "injection.proc_mem_write");
    assert_eq!(
        (row.len(), text(row[0], "finding.tier").as_str()),
        (1, "high")
    );
    assert_eq!(list(row[0], "finding.technique"), ["T1055.009", "DET0541"]);
    let own = run(vec![open(1, "/proc/self/mem", 2, 3)]);
    assert_eq!(
        tier(&own, "injection.proc_mem_write").as_deref(),
        Some("medium")
    );
    let by_pid = run(vec![open(5, "/proc/5/mem", 2, 3)]);
    assert_eq!(
        tier(&by_pid, "injection.proc_mem_write").as_deref(),
        Some("medium"),
        "its own pid is itself"
    );
    let read = run(vec![open(1, "/proc/99/mem", 0, 3)]);
    assert_eq!(
        tier(&read, "credential.proc_mem_read").as_deref(),
        Some("high")
    );
    assert!(!has(&read, "injection.proc_mem_write"));
    assert!(!has(
        &run(vec![open(1, "/proc/self/mem", 0, 3)]),
        "credential.proc_mem_read"
    ));
}

#[test]
fn a_preload_variable_in_the_environment_is_medium() {
    let out = run(vec![exec_env(
        1,
        "/bin/ls",
        &["ls"],
        &["PATH=/bin", "LD_PRELOAD=/tmp/evil.so"],
    )]);
    let row = rows(&out, "injection.ld_preload_env");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "medium");
    assert!(text(row[0], "finding.summary").contains("LD_PRELOAD=/tmp/evil.so"));
    let audit = run(vec![exec_env(1, "/bin/ls", &["ls"], &["LD_AUDIT=/x.so"])]);
    assert!(has(&audit, "injection.ld_preload_env"));
    let path = run(vec![exec_env(
        1,
        "/bin/ls",
        &["ls"],
        &["LD_LIBRARY_PATH=/tmp/lib:/usr/lib"],
    )]);
    assert!(has(&path, "injection.ld_preload_env"));
    let ordinary = run(vec![exec_env(
        1,
        "/bin/ls",
        &["ls"],
        &["LD_LIBRARY_PATH=/usr/lib", "PATH=/bin"],
    )]);
    assert!(!has(&ordinary, "injection.ld_preload_env"));
}

#[test]
fn ld_so_preload_is_high_and_the_linker_search_path_is_medium() {
    let preload = run(vec![
        open_write(1, "/etc/ld.so.preload", 3),
        write(1, 3, b"/lib/evil.so\n"),
    ]);
    let row = rows(&preload, "injection.ld_so_preload");
    assert_eq!(row.len(), 1);
    assert_eq!(
        (text(row[0], "finding.tier").as_str(), count(row[0])),
        ("high", 2)
    );
    assert_eq!(list(row[0], "finding.technique"), ["T1574.006", "DET0435"]);
    assert!(
        !has(&preload, "persistence.config_write"),
        "a specific rule took the path"
    );
    let renamed = run(vec![rename(1, "/tmp/x", "/etc/ld.so.preload")]);
    assert!(has(&renamed, "injection.ld_so_preload"));
    let conf = run(vec![open_write(1, "/etc/ld.so.conf.d/evil.conf", 3)]);
    assert_eq!(
        tier(&conf, "injection.ld_so_conf").as_deref(),
        Some("medium")
    );
    let read = run(vec![open_read(1, "/etc/ld.so.preload", 3)]);
    assert!(
        !has(&read, "injection.ld_so_preload"),
        "reading it is normal"
    );
}
