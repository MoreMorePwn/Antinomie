// SPDX-License-Identifier: GPL-3.0-only
//! The noise pipeline: tiers after context, folding, caps, scope and the badge.
use super::super::table::SPECS;
use super::super::*;
use super::support::*;

#[test]
fn a_failed_call_is_one_tier_down_and_says_so() {
    let out = run(vec![open(1, "/etc/ld.so.preload", 1, -13)]);
    let row = rows(&out, "injection.ld_so_preload");
    assert_eq!(text(row[0], "finding.tier"), "medium");
    assert_eq!(text(row[0], "finding.base_tier"), "high");
    assert!(list(row[0], "finding.flags").contains(&"failed".to_owned()));
    assert!(list(row[0], "finding.why")
        .iter()
        .any(|line| line.contains("failed")));
    assert_eq!(row[0].cells[11].text, "failed (-13)");
}

#[test]
fn failing_is_the_signal_for_scans_and_the_kernel_exploit_and_rwx_attempts() {
    for rule in SPECS.iter().filter(|spec| spec.signal).map(|spec| spec.id) {
        assert!(
            [
                "memory.rwx_attempt",
                "privilege.kernel_exploit",
                "discovery.network_scan",
                "lateral.bruteforce",
                "lateral.service_exploit",
                "impact.fork_bomb"
            ]
            .contains(&rule),
            "{rule}"
        );
    }
}

#[test]
fn five_failed_attempts_at_one_target_keep_a_high_rule_high() {
    let tries = |n: usize| {
        run((0..n)
            .map(|_| sys(1, 175, "init_module", [0, 100, 0, 0, 0, 0], -1))
            .collect())
    };
    assert_eq!(
        tier(&tries(4), "persistence.module").as_deref(),
        Some("medium")
    );
    let five = tries(5);
    let row = rows(&five, "persistence.module");
    assert_eq!(text(row[0], "finding.tier"), "high");
    assert_eq!(count(row[0]), 5);
    assert!(list(row[0], "finding.flags").contains(&"repeated".to_owned()));
    // One success among failures keeps the tier for its own reason.
    let mixed = run(vec![
        sys(1, 175, "init_module", [0, 100, 0, 0, 0, 0], -1),
        sys(1, 175, "init_module", [0, 100, 0, 0, 0, 0], 0),
    ]);
    assert_eq!(tier(&mixed, "persistence.module").as_deref(), Some("high"));
}

#[test]
fn repeats_fold_by_rule_task_and_object() {
    let same: Calls = (0..5).map(|_| open_write(1, "/etc/cron.d/x", 3)).collect();
    let out = run(same);
    assert_eq!(rows(&out, "persistence.cron").len(), 1);
    assert_eq!(count(rows(&out, "persistence.cron")[0]), 5);
    let two_files = run(vec![
        open_write(1, "/etc/cron.d/a", 3),
        open_write(1, "/etc/cron.d/b", 3),
    ]);
    assert_eq!(rows(&two_files, "persistence.cron").len(), 2);
    let two_tasks = run(vec![
        open_write(1, "/etc/cron.d/a", 3),
        open_write(2, "/etc/cron.d/a", 3),
    ]);
    assert_eq!(rows(&two_tasks, "persistence.cron").len(), 2);
    let row = &rows(&out, "persistence.cron")[0];
    assert!(
        files::number(&row.values, "finding.last_ns")
            > files::number(&row.values, "finding.first_ns")
    );
}

#[test]
fn a_pool_of_identical_children_is_one_row_with_a_count() {
    let mut calls = vec![exec(1, "/tmp/miner", &["miner", "--pool", "x"])];
    for child in 0..64i64 {
        calls.push(fork(1, 100 + child));
    }
    for child in 0..64u32 {
        calls.push(exec(100 + child, "/tmp/worker", &["worker", "-t", "1"]));
        calls.push(open_write(100 + child, "/etc/cron.d/persist", 3));
    }
    let out = run(calls);
    let row = rows(&out, "persistence.cron");
    assert_eq!(
        row.len(),
        1,
        "{:?}",
        row.iter()
            .map(|row| text(row, "finding.object"))
            .collect::<Vec<_>>()
    );
    assert_eq!(count(row[0]), 64);
    assert!(list(row[0], "finding.flags").contains(&"collapsed".to_owned()));
    assert!(row[0].cells[4].text.contains("the same in 64 processes"));
    // Children running other programs are not siblings.
    let mut mixed = vec![exec(1, "/tmp/a", &["a"]), fork(1, 100), fork(1, 101)];
    mixed.extend([
        exec(100, "/tmp/one", &["one"]),
        open_write(100, "/etc/cron.d/p", 3),
    ]);
    mixed.extend([
        exec(101, "/tmp/two", &["two"]),
        open_write(101, "/etc/cron.d/p", 3),
    ]);
    assert_eq!(rows(&run(mixed), "persistence.cron").len(), 2);
}

#[test]
fn a_steady_loop_is_shown_as_every_so_long() {
    let calls: Calls = (0..12u64)
        .map(|n| at(open_write(1, "/etc/cron.d/x", 3), n * 5 * SECOND))
        .collect();
    let out = run(calls);
    let row = rows(&out, "persistence.cron")[0];
    assert!(
        row.cells[4].text.contains("×12 every ~5.0 s"),
        "{}",
        row.cells[4].text
    );
    assert!(list(row, "finding.flags").contains(&"periodic".to_owned()));
    assert_eq!(
        text(row, "finding.tier"),
        "high",
        "collapsing never lowers a tier"
    );
    let irregular: Calls = [0u64, 1, 9, 10, 30, 31, 70, 71, 72, 200, 201, 400]
        .iter()
        .map(|n| at(open_write(1, "/etc/cron.d/x", 3), n * SECOND))
        .collect();
    let out = run(irregular);
    assert!(
        !list(rows(&out, "persistence.cron")[0], "finding.flags").contains(&"periodic".to_owned())
    );
}

#[test]
fn rows_past_the_per_rule_and_task_cap_are_counted_in_one_overflow_row() {
    let calls: Calls = (0..60)
        .map(|n| open_write(1, &format!("/etc/cron.d/job{n}"), 3))
        .collect();
    let out = run(calls);
    let all = rows(&out, "persistence.cron");
    assert_eq!(all.len(), 51);
    let overflow: Vec<_> = all
        .iter()
        .filter(|row| row.cells[4].text.starts_with("+"))
        .collect();
    assert_eq!(overflow.len(), 1);
    assert_eq!(overflow[0].cells[4].text, "+10 more not stored (cap)");
    assert_eq!(text(overflow[0], "finding.tier"), "high");
    assert!(list(overflow[0], "finding.flags").contains(&"capped".to_owned()));
    assert_eq!(out.capped, 10);
    assert_eq!(out.badge, 60, "the badge counts the capped rows");
}

#[test]
fn info_is_counted_and_its_rows_are_built_only_when_asked() {
    let calls = vec![
        exec(1, "/bin/ls", &["ls"]),
        exec(1, "/bin/cat", &["cat", "x"]),
    ];
    let counted = run_with(calls.clone(), Options::default());
    assert!(counted.rows.is_empty());
    assert_eq!(counted.tiers[3], 2);
    assert_eq!(counted.badge, 0);
    let shown = run(calls);
    assert_eq!(shown.rows.len(), 2);
    assert_eq!(shown.tiers[3], 2);
    assert_eq!(shown.badge, 0, "INFO never adds to the badge");
}

#[test]
fn the_badge_tiers_and_task_chip_count_visible_rows_of_low_and_above() {
    let out = run(vec![
        open_write(1, "/etc/cron.d/x", 3),
        open_write(1, "/etc/systemd/system/y.service", 3),
        open_write(1, "/etc/update-motd.d/z", 3),
        exec(1, "/bin/sh", &["sh"]),
        exec(2, "/bin/ls", &["ls"]),
    ]);
    assert_eq!(out.tiers[0], 2, "two high");
    assert_eq!(out.tiers[1], 1, "one medium");
    assert_eq!(out.tiers[2], 1, "the shell is low");
    assert_eq!(out.badge, 4);
    assert_eq!(out.tasks.get(&(1, 1)), Some(&4));
    assert_eq!(
        out.tasks.get(&(2, 2)),
        None,
        "an exec alone does not mark a task"
    );
}

#[test]
fn a_capture_of_the_whole_vm_keeps_only_what_started_during_it() {
    let capture = |calls: Calls| {
        run_with(
            calls,
            Options {
                show_info: true,
                capture_all: true,
            },
        )
    };
    // A process that was already running: no creation seen, first call is not an exec.
    let old = capture(vec![open_write(7, "/etc/cron.d/x", 3)]);
    let row = rows(&old, "persistence.cron")[0];
    assert_eq!(text(row, "finding.tier"), "medium");
    assert!(list(row, "finding.flags").contains(&"outside-scope".to_owned()));
    assert!(matches!(
        row.values
            .iter()
            .find(|(name, _)| *name == "finding.hidden"),
        Some((_, RowValue::Bool(true)))
    ));
    assert_eq!(old.badge, 0, "hidden rows do not count");
    assert_eq!(old.hidden, 1);
    assert!(!view_keeps(&View::default(), &row.values));
    assert!(view_keeps(
        &View {
            show_hidden: true,
            ..View::default()
        },
        &row.values
    ));
    // Started by an exec during the capture.
    let started = capture(vec![
        exec(7, "/tmp/x", &["x"]),
        open_write(7, "/etc/cron.d/x", 3),
    ]);
    assert_eq!(tier(&started, "persistence.cron").as_deref(), Some("high"));
    // Created by a fork the capture saw.
    let forked = capture(vec![
        exec(1, "/bin/sh", &["sh"]),
        fork(1, 8),
        open_write(8, "/etc/cron.d/x", 3),
    ]);
    assert_eq!(tier(&forked, "persistence.cron").as_deref(), Some("high"));
    // Caused by the sample: its image was written during the run.
    let caused = capture(vec![
        exec(1, "/bin/sh", &["sh"]),
        open_write(1, "/etc/cron.d/dropper", 3),
        with_path(call(9, 0, "read", 0), "arg0.path", "/x"),
        exec(9, "/etc/cron.d/dropper", &["dropper"]),
    ]);
    assert!(!rows(&caused, "persistence.cron").is_empty());
    assert_eq!(out_hidden(&caused), 0);
}

fn out_hidden(out: &Output) -> u64 {
    out.hidden
}

#[test]
fn a_run_scopes_by_its_root_so_nothing_is_outside() {
    let out = run(vec![open_write(7, "/etc/cron.d/x", 3)]);
    assert_eq!(out.hidden, 0);
    assert_eq!(tier(&out, "persistence.cron").as_deref(), Some("high"));
}

#[test]
fn the_chips_narrow_by_tier_and_category() {
    let out = run(vec![
        open_write(1, "/etc/cron.d/x", 3),
        open_read(1, "/root/.aws/credentials", 4),
        open_read(1, "/etc/hostname", 5),
    ]);
    let keep = |view: View| -> Vec<String> {
        let mut rules: Vec<_> = out
            .rows
            .iter()
            .filter(|row| view_keeps(&view, &row.values))
            .map(|row| text(row, "finding.rule"))
            .collect();
        rules.sort();
        rules
    };
    assert_eq!(keep(View::default()).len(), 3);
    let mut high = View::default();
    high.toggle_tier(Tier::High);
    assert_eq!(keep(high), ["credential.cloud_tokens", "persistence.cron"]);
    let mut persistence = View::default();
    persistence.toggle_category(Category::Persistence);
    assert_eq!(keep(persistence), ["persistence.cron"]);
    let mut both = persistence;
    both.toggle_category(Category::Credential);
    assert_eq!(keep(both), ["credential.cloud_tokens", "persistence.cron"]);
    let mut info = View::default();
    info.toggle_tier(Tier::Info);
    assert_eq!(keep(info), ["discovery.system_info"]);
}

#[test]
fn file_requests_through_io_uring_are_judged_by_the_file_rules_only() {
    let write = open_write(1, "/etc/cron.d/x", 3);
    let files = FdState::default();
    let mut engine = Engine::new(Options {
        show_info: true,
        capture_all: false,
    });
    engine.observe(&write, &files, None, true);
    // A process rule on the same kind of call is not evaluated for a file request.
    engine.observe(
        &sys(1, 175, "init_module", [0, 1, 0, 0, 0, 0], 0),
        &files,
        None,
        true,
    );
    let out = engine.finish(&files);
    let row = rows(&out, "persistence.cron");
    assert_eq!(row.len(), 1);
    assert!(list(row[0], "finding.flags").contains(&"async".to_owned()));
    assert!(!has(&out, "persistence.module"));
}

#[test]
fn the_table_has_unique_ids_valid_attack_ids_and_every_emitted_rule() {
    let mut seen = std::collections::BTreeSet::new();
    for spec in SPECS {
        assert!(seen.insert(spec.id), "{} twice", spec.id);
        assert!(spec.version >= 1);
        for id in spec.attack {
            let digits =
                |text: &str, n: usize| text.len() == n && text.bytes().all(|b| b.is_ascii_digit());
            let valid = id.strip_prefix("DET").is_some_and(|rest| digits(rest, 4))
                || id.strip_prefix("TA").is_some_and(|rest| digits(rest, 4))
                || id.strip_prefix('T').is_some_and(|rest| {
                    let (technique, sub) = rest
                        .split_once('.')
                        .map_or((rest, None), |(a, b)| (a, Some(b)));
                    digits(technique, 4) && sub.is_none_or(|sub| digits(sub, 3))
                });
            assert!(valid, "{}: {id}", spec.id);
        }
    }
    // Every rule id a source file emits is classified.
    let sources = [
        include_str!("../exec.rs"),
        include_str!("../paths.rs"),
        include_str!("../process.rs"),
        include_str!("../network.rs"),
        include_str!("../evasion.rs"),
        include_str!("../probes.rs"),
        include_str!("../state.rs"),
    ];
    let prefixes = [
        "process.",
        "execution.",
        "injection.",
        "persistence.",
        "privilege.",
        "memory.",
        "evasion.",
        "bpf.",
        "credential.",
        "discovery.",
        "c2.",
        "network.",
        "lateral.",
        "exfil.",
        "collection.",
        "impact.",
        "rootkit.",
    ];
    for source in sources {
        for piece in source.split('"').skip(1).step_by(2) {
            let is_id = piece.len() > 4
                && !piece.ends_with('.')
                && prefixes.iter().any(|prefix| piece.starts_with(prefix))
                && piece
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_');
            if is_id {
                assert!(
                    spec(piece).is_some(),
                    "{piece} is emitted but not classified"
                );
            }
        }
    }
}

#[test]
fn the_citations_the_old_rules_got_wrong_are_corrected() {
    let attack = |id: &str| spec(id).unwrap().attack.to_vec();
    // process.memfd cited DET0508, the process injection strategy; memfd is DET0300.
    assert_eq!(attack("process.memfd"), ["T1620", "DET0300"]);
    // A change to the process's own memory is reflective loading, not process injection.
    assert_eq!(attack("memory.rwx"), ["T1620", "DET0300"]);
    // process_vm_readv is not T1055.009, which is /proc/PID/mem.
    assert!(spec("process.vm_rw").is_none(), "retired by a split");
    assert!(!attack("injection.vm_write").contains(&"T1055.009"));
    assert_eq!(attack("credential.proc_mem_read"), ["T1003.007", "DET0593"]);
    assert_eq!(attack("injection.proc_mem_write"), ["T1055.009", "DET0541"]);
    assert!(
        spec("privilege.change").is_none(),
        "retired by the credential rules"
    );
    for spec in SPECS {
        assert!(
            !spec.attack.contains(&"DET0508") || spec.id == "injection.vm_write",
            "{}",
            spec.id
        );
    }
}

#[test]
fn the_tiers_match_the_classification_counts_of_the_rules_implemented() {
    let count = |tier: Tier| SPECS.iter().filter(|spec| spec.tier == tier).count();
    assert!(
        count(Tier::High) > 40
            && count(Tier::Medium) > 35
            && count(Tier::Low) > 10
            && count(Tier::Info) >= 5
    );
    assert_eq!(
        SPECS
            .iter()
            .map(|spec| spec.category)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        Category::ALL.len()
    );
}

/// Cost of the rules on a large run of ordinary calls, printed for a human to read.
#[test]
#[ignore = "measures time; run with --ignored --nocapture"]
fn the_rules_cost_little_on_a_large_ordinary_run() {
    let mut calls = Vec::new();
    for n in 0..60_000u64 {
        let pid = 1 + (n % 40) as u32;
        calls.push(open_read(
            pid,
            &format!("/usr/lib/x86_64-linux-gnu/lib{}.so", n % 300),
            3,
        ));
        calls.push(read(pid, 3, b"\x7fELF\x02\x01\x01"));
        calls.push(mmap(pid, 5, 0x802, 0x7000));
        calls.push(sys(pid, 202, "futex", [0; 6], 0));
        calls.push(close(pid, 3));
    }
    let count = calls.len();
    let start = std::time::Instant::now();
    let out = run_with(calls, Options::default());
    let rules = start.elapsed();
    eprintln!(
        "{count} calls in {rules:?}: {:?} per call; {} rows",
        rules / count as u32,
        out.rows.len()
    );
    assert!(out.rows.len() < 100);
}

#[test]
fn the_resource_collector_of_an_older_base_is_antinomie_s_not_the_sample_s() {
    let collector = "/tmp/.antinomie-resource-abc123def456";
    let out = run(vec![
        exec(9, collector, &["res"]),
        open_read(9, "/proc/meminfo", 3),
        unlink(9, collector),
        stat(9, "/sys/fs/selinux", 0),
    ]);
    assert!(out.rows.is_empty(), "{:?}", rules_of(&out));
    assert_eq!(out.tiers[3], 0);
    // The same behaviour from a program of the run is reported.
    let sample = run(vec![
        exec(9, "/tmp/.other", &["x"]),
        unlink(9, "/tmp/.other"),
    ]);
    assert!(has(&sample, "evasion.self_delete"));
    assert!(has(&sample, "execution.temp_exec"));
}
