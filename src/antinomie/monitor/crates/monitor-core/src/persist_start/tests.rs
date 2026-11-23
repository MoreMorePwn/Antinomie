// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn row(rule: &str, path: &str) -> Written {
    Written {
        rule: rule.into(),
        path: path.into(),
        failed: false,
        pid: 100,
    }
}

const ROOT: (u32, u32, &str) = (0, 0, "/root");
const USER: (u32, u32, &str) = (1000, 1000, "/home/user");

#[test]
fn startable_paths_are_classified_and_others_are_not() {
    let cases = [
        (
            "/etc/systemd/system/dbus-x.service",
            Some((EntryKind::Systemd, false)),
        ),
        (
            "/lib/systemd/system/x.service",
            Some((EntryKind::Systemd, false)),
        ),
        (
            "/home/u/.config/systemd/user/x.service",
            Some((EntryKind::Systemd, true)),
        ),
        ("/etc/systemd/system/x.timer", None),
        ("/etc/systemd/system/getty@.service", None),
        ("/etc/init.d/sshd2", Some((EntryKind::InitScript, false))),
        ("/etc/rc.d/init.d/x", Some((EntryKind::InitScript, false))),
        ("/etc/rc2.d/S01x", Some((EntryKind::InitScript, false))),
        ("/etc/rc.d/rc3.d/S99x", Some((EntryKind::InitScript, false))),
        ("/etc/rc2.d/K01x", None),
        ("/etc/rc.local", Some((EntryKind::RcLocal, false))),
        ("/etc/inittab", None),
        ("/etc/crontab", Some((EntryKind::Cron, false))),
        ("/etc/cron.d/job", Some((EntryKind::Cron, false))),
        (
            "/var/spool/cron/crontabs/root",
            Some((EntryKind::Cron, false)),
        ),
        (
            "/var/spool/cron/crontabs/user",
            Some((EntryKind::Cron, true)),
        ),
        ("/var/spool/cron/root", Some((EntryKind::Cron, false))),
        ("/var/spool/cron/crontabs/tmp.Xa81", None),
        ("/var/spool/cron/atjobs/a0001", None),
        ("/etc/cron.daily/x", Some((EntryKind::CronScript, false))),
        ("/root/.bashrc", Some((EntryKind::Login, true))),
        ("/etc/profile.d/x.sh", Some((EntryKind::Login, true))),
        ("/etc/profile", Some((EntryKind::Login, true))),
        (
            "/etc/xdg/autostart/x.desktop",
            Some((EntryKind::Autostart, true)),
        ),
        (
            "/home/u/.config/autostart/x.desktop",
            Some((EntryKind::Autostart, true)),
        ),
        ("/etc/passwd", None),
        ("relative/.bashrc", None),
        ("/etc/init.d/../passwd", None),
    ];
    for (path, want) in cases {
        assert_eq!(classify(path), want, "{path}");
    }
}

#[test]
fn entries_come_in_boot_order_once_each() {
    let written = [
        row("persistence.shell_profile", "/root/.bashrc"),
        row("persistence.cron", "/etc/cron.d/job"),
        row("persistence.rc_init", "/etc/rc2.d/S01upd"),
        row("persistence.rc_init", "/etc/init.d/upd"),
        row("persistence.rc_init", "/etc/init.d/upd"),
        row(
            "persistence.systemd",
            "/etc/systemd/system/multi-user.target.wants/x.service",
        ),
        row("persistence.systemd", "/etc/systemd/system/x.service"),
        row("persistence.shell_profile", "/root/.profile"),
        row("process.interpreter", "/etc/init.d/other"),
    ];
    let (entries, more) = select(&written, ROOT);
    assert_eq!(more, 0);
    let got: Vec<(EntryKind, &str)> = entries.iter().map(|e| (e.kind, e.path.as_str())).collect();
    assert_eq!(
        got,
        [
            (EntryKind::Systemd, "/etc/systemd/system/x.service"),
            (EntryKind::InitScript, "/etc/init.d/upd"),
            (EntryKind::Cron, "/etc/cron.d/job"),
            (EntryKind::Login, "/root/.bashrc"),
        ]
    );
    // One login reads both profiles of root.
    assert_eq!(entries[3].files, ["/root/.bashrc", "/root/.profile"]);
    assert_eq!((entries[3].uid, entries[3].home.as_str()), (0, "/root"));
    assert!(entries[2].system_crontab);
}

#[test]
fn failed_writes_are_not_entries() {
    let mut refused = row("persistence.rc_init", "/etc/init.d/x");
    refused.failed = true;
    assert!(select(&[refused.clone()], USER).0.is_empty());
    // A later row of the same path that did not fail counts.
    let (entries, _) = select(
        &[refused, row("persistence.rc_init", "/etc/init.d/x")],
        USER,
    );
    assert_eq!(entries.len(), 1);
}

#[test]
fn user_entries_run_as_their_user() {
    let written = [
        row("persistence.shell_profile", "/home/user/.bashrc"),
        row(
            "persistence.xdg_autostart",
            "/home/user/.config/autostart/a.desktop",
        ),
        row("persistence.cron", "/var/spool/cron/crontabs/user"),
        row("persistence.rc_init", "/etc/rc.local"),
    ];
    let (entries, _) = select(&written, USER);
    let by_kind = |kind| entries.iter().find(|e| e.kind == kind).unwrap();
    assert_eq!(by_kind(EntryKind::RcLocal).uid, 0);
    assert_eq!(by_kind(EntryKind::Cron).uid, 1000);
    assert!(!by_kind(EntryKind::Cron).system_crontab);
    let login = by_kind(EntryKind::Login);
    assert_eq!((login.uid, login.home.as_str()), (1000, "/home/user"));
    // A run as root that wrote a user's profile logs that user in.
    let (entries, _) = select(&written[..1], ROOT);
    assert_eq!(
        (entries[0].uid, entries[0].home.as_str()),
        (1000, "/home/user")
    );
}

#[test]
fn at_most_the_limit_is_started_and_the_rest_counted() {
    let written: Vec<Written> = (0..11)
        .map(|n| row("persistence.rc_init", &format!("/etc/init.d/s{n}")))
        .collect();
    let (entries, more) = select(&written, ROOT);
    assert_eq!(entries.len(), MAX_ENTRIES);
    assert_eq!(more, 3);
}

#[test]
fn the_option_the_stop_and_the_run_time_decide() {
    let on = StartPersistence {
        run_limit_s: Some(300),
    };
    let early = Duration::from_secs(2);
    assert_eq!(refusal(Some(&on), early, false, true), None);
    assert_eq!(
        refusal(
            Some(&StartPersistence::default()),
            Duration::from_secs(4000),
            false,
            true
        ),
        None
    );
    let off = refusal(None, early, false, true).unwrap();
    assert_eq!(
        off,
        "the tree ended after 2 s; persistence installed but not started (option off)"
    );
    assert!(
        refusal(Some(&on), Duration::from_secs(280), false, true)
            .unwrap()
            .contains("less than 30 s")
    );
    assert!(
        refusal(Some(&on), early, true, true)
            .unwrap()
            .contains("stopped")
    );
    assert!(
        refusal(Some(&on), early, false, false)
            .unwrap()
            .contains("no live Triage rules")
    );
    assert_eq!(
        not_started_note(&off),
        "The tree ended after 2 s; persistence installed but not started (option off)."
    );
}

#[test]
fn scripts_start_the_entry_and_never_the_launched_program() {
    let (entries, _) = select(
        &[
            row("persistence.rc_init", "/etc/init.d/it's"),
            row("persistence.cron", "/etc/crontab"),
            row("persistence.systemd", "/etc/systemd/system/x.service"),
        ],
        ROOT,
    );
    let init = script(&entries[1], "/tmp/sample");
    assert!(init.contains("f='/etc/init.d/it'\\''s'"), "{init}");
    assert!(init.contains("exec \"$f\" start"), "{init}");
    let cron = script(&entries[2], "/tmp/sample");
    assert!(cron.contains("shift 5"), "{cron}");
    assert!(
        cron.contains("[ $# -gt 1 ] || continue\n  shift\n"),
        "{cron}"
    );
    assert!(
        cron.contains("[ \"$1\" = '/tmp/sample' ] && continue"),
        "{cron}"
    );
    assert!(cron.contains("run-parts"), "{cron}");
    let unit = script(&entries[0], "/tmp/sample");
    assert!(unit.contains("ExecStart"), "{unit}");
    assert!(unit.contains(&format!("exit {EXIT_LAUNCHED}")), "{unit}");
    for text in [&init, &cron, &unit] {
        assert!(text.starts_with("exec </dev/null >/dev/null 2>&1\n"));
        assert!(!text.to_ascii_lowercase().contains("antinomie"));
    }
    let env = environment(&entries[1]);
    assert!(env.contains(&"_SYSTEMCTL_SKIP_REDIRECT=1".to_owned()));
    assert!(env.contains(&"HOME=/root".to_owned()));
}

#[test]
fn the_cron_script_runs_job_lines_in_a_shell() {
    // Run the generated script with the host's sh over a crontab, each job
    // command replaced by an echo into a file.
    let dir = std::env::temp_dir().join(format!("ant-persist-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("out");
    let tab = dir.join("crontab");
    std::fs::write(
        &tab,
        format!(
            "SHELL=/bin/sh\n# comment\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n\
             */5 * * * * root echo one >> {out}\n@reboot root echo two >> {out}\n\
             * * * * * root /tmp/sample\n",
            out = out.display()
        ),
    )
    .unwrap();
    let entry = Entry {
        kind: EntryKind::Cron,
        path: tab.display().to_string(),
        files: Vec::new(),
        uid: 0,
        gid: 0,
        home: "/".into(),
        system_crontab: true,
        zsh: false,
    };
    let text = script(&entry, "/tmp/sample").replace("exec </dev/null >/dev/null 2>&1\n", "");
    let status = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&text)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
    // The jobs ran in the background.
    for _ in 0..50 {
        if std::fs::read_to_string(&out).is_ok_and(|text| text.lines().count() == 2) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut lines: Vec<String> = std::fs::read_to_string(&out)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    lines.sort();
    assert_eq!(lines, ["one", "two"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_record_marks_each_entry_and_the_note_lists_them() {
    let (entries, _) = select(&[row("persistence.rc_init", "/etc/init.d/x")], ROOT);
    let record = PersistenceStart {
        tree_ended_after_ms: 1200,
        entries: entries.iter().map(StartedEntry::of).collect(),
        ..Default::default()
    };
    assert_eq!(
        record.entries[0].started_by,
        "started by Antinomie (persistence)"
    );
    let note = started_note(&record);
    assert!(note.contains("ended after 1 s"), "{note}");
    assert!(note.contains("/etc/init.d/x start as root"), "{note}");
    assert!(
        note.contains("started by Antinomie (persistence)"),
        "{note}"
    );
    let saved = serde_json::to_value(&record).unwrap();
    assert_eq!(saved["entries"][0]["kind"], "init_script");
    assert_eq!(
        serde_json::from_value::<PersistenceStart>(saved).unwrap(),
        record
    );
}
