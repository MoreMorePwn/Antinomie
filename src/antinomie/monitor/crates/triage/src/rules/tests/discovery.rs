// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;
use crate::query::RowValue;

#[test]
fn walking_the_process_list_is_low_after_ten_processes_or_with_ps() {
    let mut calls = vec![open_read(1, "/proc", 3)];
    calls.push(sys(1, 217, "getdents64", [3, 0, 4096, 0, 0, 0], 512));
    for pid in 100..112 {
        calls.push(open_read(1, &format!("/proc/{pid}/cmdline"), 4));
    }
    let out = run(calls);
    assert_eq!(tier(&out, "discovery.process_enum").as_deref(), Some("low"));
    let few: Calls = (100..105)
        .map(|pid| open_read(1, &format!("/proc/{pid}/cmdline"), 4))
        .collect();
    assert!(!has(&run(few), "discovery.process_enum"));
    assert!(has(
        &run(vec![exec(1, "/bin/ps", &["ps", "aux"])]),
        "discovery.process_enum"
    ));
    assert!(has(
        &run(vec![exec(1, "/usr/bin/pgrep", &["pgrep", "-f", "agent"])]),
        "discovery.process_enum"
    ));
}

#[test]
fn system_details_users_and_network_configuration_are_context() {
    for path in [
        "/etc/os-release",
        "/proc/version",
        "/proc/meminfo",
        "/etc/hostname",
    ] {
        let out = run(vec![open_read(1, path, 3)]);
        assert_eq!(
            tier(&out, "discovery.system_info").as_deref(),
            Some("info"),
            "{path}"
        );
        assert_eq!(out.badge, 0, "{path}: INFO does not count");
    }
    for argv in [vec!["uname", "-a"], vec!["hostnamectl"], vec!["lscpu"]] {
        let path = format!("/usr/bin/{}", argv[0]);
        assert!(
            has(&run(vec![exec(1, &path, &argv)]), "discovery.system_info"),
            "{argv:?}"
        );
    }
    for argv in [
        vec!["id"],
        vec!["whoami"],
        vec!["who"],
        vec!["last"],
        vec!["getent", "passwd"],
    ] {
        let path = format!("/usr/bin/{}", argv[0]);
        assert_eq!(
            tier(&run(vec![exec(1, &path, &argv)]), "discovery.user_enum").as_deref(),
            Some("info"),
            "{argv:?}"
        );
    }
    let both = run(vec![
        open_read(1, "/etc/passwd", 3),
        open_read(1, "/etc/group", 4),
    ]);
    assert_eq!(tier(&both, "discovery.user_enum").as_deref(), Some("info"));
    assert!(
        !has(
            &run(vec![open_read(1, "/etc/passwd", 3)]),
            "discovery.user_enum"
        ),
        "one lookup is the C library"
    );
    for path in [
        "/proc/net/tcp",
        "/proc/net/route",
        "/etc/resolv.conf",
        "/sys/class/net/eth0/address",
        "/proc/net/arp",
    ] {
        let out = run(vec![open_read(1, path, 3)]);
        assert_eq!(
            tier(&out, "discovery.network_config").as_deref(),
            Some("low"),
            "{path}"
        );
    }
    for argv in [
        vec!["ip", "a"],
        vec!["ifconfig"],
        vec!["netstat", "-an"],
        vec!["ss", "-tlnp"],
        vec!["arp", "-a"],
    ] {
        let path = format!("/usr/bin/{}", argv[0]);
        assert!(
            has(
                &run(vec![exec(1, &path, &argv)]),
                "discovery.network_config"
            ),
            "{argv:?}"
        );
    }
}

#[test]
fn a_sweep_of_directories_and_a_search_for_keys_is_low() {
    let mut calls = Vec::new();
    for n in 0..250 {
        calls.push(open_read(1, &format!("/home/user/d{n}"), 3));
        calls.push(sys(1, 217, "getdents64", [3, 0, 4096, 0, 0, 0], 100));
        calls.push(close(1, 3));
    }
    assert_eq!(
        tier(&run(calls), "discovery.file_search").as_deref(),
        Some("low")
    );
    let few: Calls = (0..10)
        .flat_map(|n| {
            vec![
                open_read(1, &format!("/home/user/d{n}"), 3),
                sys(1, 217, "getdents64", [3, 0, 4096, 0, 0, 0], 100),
            ]
        })
        .collect();
    assert!(!has(&run(few), "discovery.file_search"));
    assert!(has(
        &run(vec![exec(
            1,
            "/usr/bin/find",
            &["find", "/", "-name", "id_rsa"]
        )]),
        "discovery.file_search"
    ));
    assert!(has(
        &run(vec![exec(
            1,
            "/usr/bin/find",
            &["find", "/", "-name", "*.pem"]
        )]),
        "discovery.file_search"
    ));
    assert!(!has(
        &run(vec![exec(
            1,
            "/usr/bin/find",
            &["find", ".", "-name", "*.c"]
        )]),
        "discovery.file_search"
    ));
}

#[test]
fn looking_for_security_software_is_medium_even_when_it_is_absent() {
    for path in [
        "/usr/local/aegis",
        "/etc/aliyun",
        "/opt/CrowdStrike/falconctl",
        "/usr/local/qcloud",
    ] {
        let found = run(vec![stat(1, path, -2)]);
        assert_eq!(
            tier(&found, "discovery.security_software").as_deref(),
            Some("low"),
            "{path}: a failed probe is one tier down"
        );
        let present = run(vec![stat(1, path, 0)]);
        assert_eq!(
            tier(&present, "discovery.security_software").as_deref(),
            Some("medium"),
            "{path}"
        );
    }
    // The operating system's own hardening paths are looked at by many tools.
    assert_eq!(
        tier(
            &run(vec![stat(1, "/sys/fs/selinux", 0)]),
            "discovery.security_software"
        )
        .as_deref(),
        Some("info")
    );
    assert!(!has(
        &run(vec![stat(1, "/usr/bin/ls", 0)]),
        "discovery.security_software"
    ));
}

#[test]
fn many_hosts_or_ports_within_seconds_is_a_scan_and_failure_does_not_lower_it() {
    let mut calls = vec![socket(1, 2, 1, 3)];
    for host in 1..=25u8 {
        let mut attempt = connect(1, 3, [198, 51, 100, host], 23);
        attempt.exit.as_mut().unwrap().result = Some(-111);
        calls.push(attempt);
    }
    let out = run(calls);
    assert_eq!(
        tier(&out, "discovery.network_scan").as_deref(),
        Some("medium")
    );
    let ports: Calls = std::iter::once(socket(1, 2, 1, 3))
        .chain((1000..1030u16).map(|port| connect(1, 3, [198, 51, 100, 7], port)))
        .collect();
    assert!(has(&run(ports), "discovery.network_scan"));
    let few: Calls = std::iter::once(socket(1, 2, 1, 3))
        .chain((1..4u8).map(|host| connect(1, 3, [198, 51, 100, host], 80)))
        .collect();
    assert!(!has(&run(few), "discovery.network_scan"));
    assert!(has(
        &run(vec![exec(
            1,
            "/usr/bin/nmap",
            &["nmap", "-sS", "10.0.0.0/24"]
        )]),
        "discovery.network_scan"
    ));
}

#[test]
fn a_dns_loop_reading_resolv_conf_again_and_again_is_flagged_once() {
    let mut calls = Vec::new();
    for _ in 0..300 {
        calls.push(open_read(1, "/etc/resolv.conf", 3));
        calls.push(close(1, 3));
    }
    let out = run(calls);
    let found = rows(&out, "discovery.network_config");
    assert_eq!(found.len(), 1, "one row");
    assert!(
        found[0]
            .values
            .iter()
            .any(|(name, value)| *name == "finding.count" && matches!(value, RowValue::Number(1))),
        "the reads after the first are name resolution, not counted"
    );
}

#[test]
fn hardware_files_are_one_row_with_the_files_listed_and_startup_reads_are_not_discovery() {
    let out = run(vec![
        open_read(1, "/proc/cpuinfo", 3),
        open_read(1, "/sys/devices/system/cpu/cpu0/topology/core_id", 4),
        open_read(1, "/sys/class/dmi/id/product_name", 5),
        open_read(1, "/sys/hypervisor/type", 6),
    ]);
    let hardware: Vec<_> = rows(&out, "discovery.system_info")
        .into_iter()
        .filter(|row| text(row, "finding.object") == "hardware")
        .collect();
    assert_eq!(hardware.len(), 1, "one finding for the category");
    let detail = list(hardware[0], "finding.detail").join("\n");
    for file in [
        "/proc/cpuinfo",
        "core_id",
        "product_name",
        "/sys/hypervisor/type",
    ] {
        assert!(detail.contains(file), "{file}: {detail}");
    }
    // What the C library and language runtimes read as they start.
    let startup = run(vec![
        open_read(1, "/sys/devices/system/cpu/online", 3),
        open_read(1, "/sys/devices/system/cpu/possible", 4),
        open_read(1, "/sys/devices/system/cpu/cpu0/cache/index0/size", 5),
        open_read(1, "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", 6),
        open_read(1, "/proc/self/auxv", 7),
        open_read(1, "/proc/self/maps", 8),
    ]);
    assert!(
        !has(&startup, "discovery.system_info"),
        "{:?}",
        rules_of(&startup)
    );
    let mounts = run(vec![open_read(1, "/proc/self/mountinfo", 3)]);
    assert!(has(&mounts, "discovery.system_info"));
}

#[test]
fn uname_the_system_call_is_kernel_discovery() {
    let out = run(vec![
        exec(1, "/tmp/x", &["x"]),
        sys(1, 63, "uname", [0x7000, 0, 0, 0, 0, 0], 0),
    ]);
    assert_eq!(rows(&out, "discovery.system_info").len(), 1);
    // The uname program has its own rule; the loader's call is not the program's.
    let program = run(vec![
        exec(1, "/usr/bin/uname", &["uname", "-a"]),
        sys(1, 63, "uname", [0x7000, 0, 0, 0, 0, 0], 0),
    ]);
    assert_eq!(rows(&program, "discovery.system_info").len(), 1);
}

#[test]
fn interface_ioctls_and_route_queries_are_network_configuration() {
    for request in [0x8912u64, 0x8915, 0x8927, 0x891b, 0x8933] {
        let out = run(vec![
            socket(1, 2, 2, 3),
            sys(1, 16, "ioctl", [3, request, 0x2000, 0, 0, 0], 0),
        ]);
        assert_eq!(
            tier(&out, "discovery.network_config").as_deref(),
            Some("low"),
            "{request:#x}"
        );
    }
    let other = run(vec![
        socket(1, 2, 2, 3),
        sys(1, 16, "ioctl", [3, 0x5401, 0x2000, 0, 0, 0], 0),
    ]);
    assert!(!has(&other, "discovery.network_config"));
    // getifaddrs: RTM_GETADDR over a route netlink socket.
    let mut request = vec![0u8; 20];
    request[4..6].copy_from_slice(&22u16.to_le_bytes());
    let netlink = run(vec![
        socket(1, 16, 3, 3),
        with_entry(
            sys(1, 44, "sendto", [3, 0x2000, 20, 0, 0, 0], 20),
            "arg1.data",
            &request,
        ),
    ]);
    assert!(has(&netlink, "discovery.network_config"));
    request[4..6].copy_from_slice(&16u16.to_le_bytes());
    let new_link = run(vec![
        socket(1, 16, 3, 3),
        with_entry(
            sys(1, 44, "sendto", [3, 0x2000, 20, 0, 0, 0], 20),
            "arg1.data",
            &request,
        ),
    ]);
    assert!(!has(&new_link, "discovery.network_config"));
}
