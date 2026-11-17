// SPDX-License-Identifier: GPL-3.0-only
//! What a bot does to the device it lands on (the BusyBox camera base,
//! ANT-T0558): watchdog, a service's port, the firewall, the flash.
use super::support::*;

const WDIOC_SETOPTIONS: u64 = 0x8004_5704;
const WDIOC_SETTIMEOUT: u64 = 0xc004_5706;

#[test]
pub fn opening_and_turning_off_the_watchdog_is_high() {
    // Mirai: open("/dev/watchdog", O_RDWR), ioctl(WDIOC_SETOPTIONS, &WDIOS_DISABLECARD).
    let out = run(vec![
        exec(1, "/tmp/x", &["x"]),
        open(1, "/dev/watchdog", 2, 3),
        sys(1, 16, "ioctl", [3, WDIOC_SETOPTIONS, 0x1000, 0, 0, 0], 0),
    ]);
    assert_eq!(
        tier(&out, "evasion.watchdog_disable").as_deref(),
        Some("high")
    );
    let summaries: Vec<String> = rows(&out, "evasion.watchdog_disable")
        .iter()
        .map(|row| text(row, "finding.summary"))
        .collect();
    assert!(
        summaries
            .iter()
            .any(|text| text.contains("WDIOC_SETOPTIONS")),
        "{summaries:?}"
    );
    assert_eq!(
        list(
            rows(&out, "evasion.watchdog_disable")[0],
            "finding.technique"
        ),
        ["T1490", "DET0329"]
    );
    // The other device names, a new timeout and the magic close.
    for path in ["/dev/watchdog0", "/dev/misc/watchdog"] {
        let out = run(vec![
            open(1, path, 1, 3),
            sys(1, 16, "ioctl", [3, WDIOC_SETTIMEOUT, 0x1000, 0, 0, 0], 0),
        ]);
        assert!(has(&out, "evasion.watchdog_disable"), "{path}");
    }
    let magic = run(vec![open(1, "/dev/watchdog", 1, 3), write(1, 3, b"V")]);
    assert!(rows(&magic, "evasion.watchdog_disable")
        .iter()
        .any(|row| text(row, "finding.summary").contains("magic close")));
}

#[test]
pub fn reading_a_watchdog_or_a_failed_open_is_not_taking_it_over() {
    assert!(!has(
        &run(vec![open_read(1, "/dev/watchdog", 3)]),
        "evasion.watchdog_disable"
    ));
    assert!(!has(
        &run(vec![open(1, "/dev/watchdog", 2, -16)]),
        "evasion.watchdog_disable"
    ));
    assert!(!has(
        &run(vec![open(1, "/dev/watchdogs", 2, 3)]),
        "evasion.watchdog_disable"
    ));
    // An ioctl of another device with the same number is not the watchdog's.
    assert!(!has(
        &run(vec![
            open(1, "/dev/null", 2, 3),
            sys(1, 16, "ioctl", [3, WDIOC_SETOPTIONS, 0x1000, 0, 0, 0], 0),
        ]),
        "evasion.watchdog_disable"
    ));
}

#[test]
pub fn a_watchdog_daemon_feeding_the_watchdog_is_lowered() {
    let out = run(vec![
        exec(1, "/usr/sbin/watchdog", &["watchdog"]),
        open(1, "/dev/watchdog", 1, 3),
    ]);
    assert_eq!(
        tier(&out, "evasion.watchdog_disable").as_deref(),
        Some("medium")
    );
}

fn bind_tcp(pid: u32, fd: u64, ip: [u8; 4], port: u16, result: i64) -> Calls {
    vec![
        socket(pid, 2, 1, fd as i64),
        with_entry(
            sys(pid, 49, "bind", [fd, 0x1000, 16, 0, 0, 0], result),
            "arg1.address",
            &address(2, ip, port),
        ),
    ]
}

#[test]
pub fn killing_a_service_and_binding_its_port_is_a_takeover() {
    // Mirai's killer: read /proc/net/tcp, kill the telnet daemon, bind 23.
    let mut calls = vec![
        exec(1, "/tmp/x", &["x"]),
        open_read(1, "/proc/net/tcp", 3),
        sys(1, 62, "kill", [412, 9, 0, 0, 0, 0], 0),
    ];
    calls.extend(bind_tcp(1, 4, [0, 0, 0, 0], 23, 0));
    let out = run(calls);
    assert_eq!(
        tier(&out, "impact.service_takeover").as_deref(),
        Some("high")
    );
    let summary = text(rows(&out, "impact.service_takeover")[0], "finding.summary");
    assert!(
        summary.contains("23") && summary.contains("412"),
        "{summary}"
    );
    assert_eq!(
        list(
            rows(&out, "impact.service_takeover")[0],
            "finding.technique"
        ),
        ["T1489", "DET0021"]
    );
    // A camera maker's vendor port counts too, and so does another task of the run.
    let mut vendor = vec![
        exec(1, "/tmp/x", &["x"]),
        sys(1, 62, "kill", [500, 15, 0, 0, 0, 0], 0),
    ];
    vendor.extend(bind_tcp(2, 4, [0, 0, 0, 0], 37777, 0));
    assert!(has(&run(vendor), "impact.service_takeover"));
}

#[test]
pub fn a_bind_without_a_kill_a_failed_bind_or_a_high_port_is_no_takeover() {
    let alone = run(bind_tcp(1, 4, [0, 0, 0, 0], 23, 0));
    assert!(!has(&alone, "impact.service_takeover"));
    let mut failed = vec![sys(1, 62, "kill", [412, 9, 0, 0, 0, 0], 0)];
    failed.extend(bind_tcp(1, 4, [0, 0, 0, 0], 23, -98));
    assert!(!has(&run(failed), "impact.service_takeover"));
    let mut high = vec![sys(1, 62, "kill", [412, 9, 0, 0, 0, 0], 0)];
    high.extend(bind_tcp(1, 4, [0, 0, 0, 0], 40000, 0));
    assert!(!has(&run(high), "impact.service_takeover"));
    let mut loopback = vec![sys(1, 62, "kill", [412, 9, 0, 0, 0, 0], 0)];
    loopback.extend(bind_tcp(1, 4, [127, 0, 0, 1], 23, 0));
    assert!(!has(&run(loopback), "impact.service_takeover"));
    // A kill that failed (no such process), or one of the run's own children.
    let mut refused = vec![sys(1, 62, "kill", [412, 9, 0, 0, 0, 0], -3)];
    refused.extend(bind_tcp(1, 4, [0, 0, 0, 0], 23, 0));
    assert!(!has(&run(refused), "impact.service_takeover"));
    let mut own = vec![
        exec(1, "/bin/sh", &["sh"]),
        exec(2, "/bin/sleep", &["sleep"]),
        sys(1, 62, "kill", [2, 9, 0, 0, 0, 0], 0),
    ];
    own.extend(bind_tcp(1, 4, [0, 0, 0, 0], 23, 0));
    assert!(!has(&run(own), "impact.service_takeover"));
}

#[test]
pub fn a_bind_more_than_a_minute_after_the_kill_is_no_takeover() {
    let mut calls = vec![at(sys(1, 62, "kill", [412, 9, 0, 0, 0, 0], 0), SECOND)];
    calls.extend(
        bind_tcp(1, 4, [0, 0, 0, 0], 23, 0)
            .into_iter()
            .map(|call| at(call, 62 * SECOND)),
    );
    assert!(!has(&run(calls), "impact.service_takeover"));
}

#[test]
pub fn adding_a_firewall_rule_or_replacing_a_table_is_a_firewall_change() {
    for script in [
        "iptables -A INPUT -p tcp --dport 23 -j DROP",
        "iptables -I INPUT 1 -p tcp --dport 22 -j REJECT",
        "iptables -D INPUT -p tcp --dport 23 -j DROP",
        "iptables -P INPUT DROP",
        "ip6tables -A INPUT -j DROP",
        "nft add rule inet filter input tcp dport 23 drop",
        "ufw deny 23",
        "iptables-restore",
    ] {
        assert!(
            has(&run(vec![shell(1, script)]), "evasion.firewall_modify"),
            "{script}"
        );
    }
    for script in [
        "iptables -L -n",
        "iptables -S",
        "nft list ruleset",
        "ufw status",
    ] {
        assert!(
            !has(&run(vec![shell(1, script)]), "evasion.firewall_modify"),
            "{script}"
        );
    }
    // iptables-legacy's commit, as a program that skips the command does it.
    let replace = run(vec![
        exec(1, "/tmp/x", &["x"]),
        socket(1, 2, 3, 3),
        sys(1, 54, "setsockopt", [3, 0, 64, 0x1000, 4096, 0], 0),
    ]);
    assert!(has(&replace, "evasion.firewall_modify"));
    let read_only = run(vec![
        socket(1, 2, 3, 3),
        sys(1, 55, "getsockopt", [3, 0, 64, 0x1000, 0x2000, 0], 0),
    ]);
    assert!(!has(&read_only, "evasion.firewall_modify"));
}

#[test]
pub fn writing_or_erasing_flash_is_a_block_device_write() {
    for path in ["/dev/mtd3", "/dev/mtdblock2"] {
        let out = run(vec![open(1, path, 1, 3), write(1, 3, b"\xff\xff")]);
        assert!(has(&out, "impact.block_device_write"), "{path}");
    }
    // MEMERASE and MEMERASE64.
    for request in [0x4008_4d02u64, 0x4010_4d14] {
        let out = run(vec![
            open(1, "/dev/mtd0", 2, 3),
            sys(1, 16, "ioctl", [3, request, 0x1000, 0, 0, 0], 0),
        ]);
        assert!(
            rows(&out, "impact.block_device_write")
                .iter()
                .any(|row| text(row, "finding.summary").contains("erases")),
            "{request:#x}"
        );
    }
    assert!(!has(
        &run(vec![open_read(1, "/dev/mtd0", 3), read(1, 3, b"\xff")]),
        "impact.block_device_write"
    ));
}
