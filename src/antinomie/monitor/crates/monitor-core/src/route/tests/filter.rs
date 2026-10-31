// SPDX-License-Identifier: GPL-3.0-only
//! The egress abuse filter: every limit on its own (the state machine with
//! a fake clock), then through the gateway on a proxied route with a fake
//! SOCKS5 server. Everything stays on loopback; nothing is sent anywhere.
use super::{
    Rig, WAIT, config_for,
    guest::{Connect, Tcp},
    socks_server::FakeSocks,
};
use crate::route::{
    EgressFilter, RouteConfig, RouteKind, RouteStats,
    filter::{Block, FilterState},
};
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

const SHORT: Duration = Duration::from_millis(800);

fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
}

#[test]
fn the_defaults_block_mail_and_limit_the_rest() {
    let filter = EgressFilter::default();
    assert!(filter.enabled);
    assert_eq!(filter.blocked_ports, vec![25, 26, 465, 587, 2525]);
    assert_eq!(filter.max_new_per_second, 30);
    assert_eq!(filter.max_concurrent, 200);
    assert_eq!(filter.max_destinations_per_minute, 100);
    assert_eq!(filter.run_limit_minutes, 0, "no time limit unless set");
    assert_eq!(filter.run_limit(), None);
    assert!(RouteConfig::default().filter.enabled);
}

#[test]
fn mail_ports_are_refused_and_other_ports_are_not() {
    let filter = EgressFilter::default();
    let mut state = FilterState::default();
    let now = Instant::now();
    for port in [25, 26, 465, 587, 2525] {
        assert_eq!(
            state.admit(&filter, now, "1.2.3.4", port, 0, false),
            Err(Block::Port(port))
        );
    }
    for port in [80, 443, 53, 22, 110, 993] {
        assert_eq!(state.admit(&filter, now, "1.2.3.4", port, 0, false), Ok(()));
    }
    let custom = EgressFilter {
        blocked_ports: vec![6667],
        ..EgressFilter::default()
    };
    assert_eq!(
        state.admit(&custom, now, "1.2.3.4", 6667, 0, false),
        Err(Block::Port(6667))
    );
    assert_eq!(state.admit(&custom, now, "1.2.3.4", 25, 0, false), Ok(()));
}

#[test]
fn new_connections_per_second_are_capped_and_the_window_slides() {
    let filter = EgressFilter {
        max_new_per_second: 3,
        ..EgressFilter::default()
    };
    let mut state = FilterState::default();
    let t0 = Instant::now();
    for i in 0..3 {
        assert_eq!(
            state.admit(&filter, at(t0, i * 100), "a", 80, 0, false),
            Ok(())
        );
    }
    assert_eq!(
        state.admit(&filter, at(t0, 500), "a", 80, 0, false),
        Err(Block::Rate)
    );
    // A refused attempt does not extend the lockout.
    assert_eq!(
        state.admit(&filter, at(t0, 1000), "a", 80, 0, false),
        Ok(())
    );
}

#[test]
fn open_connections_are_capped() {
    let filter = EgressFilter {
        max_concurrent: 2,
        ..EgressFilter::default()
    };
    let mut state = FilterState::default();
    let now = Instant::now();
    assert_eq!(state.admit(&filter, now, "a", 80, 1, false), Ok(()));
    assert_eq!(
        state.admit(&filter, now, "a", 80, 2, false),
        Err(Block::Concurrent)
    );
}

#[test]
fn distinct_destinations_per_minute_are_capped_and_repeats_are_free() {
    let filter = EgressFilter {
        max_destinations_per_minute: 3,
        max_new_per_second: 0,
        ..EgressFilter::default()
    };
    let mut state = FilterState::default();
    let t0 = Instant::now();
    for (i, host) in ["a", "b", "c"].into_iter().enumerate() {
        assert_eq!(
            state.admit(&filter, at(t0, i as u64), host, 80, 0, false),
            Ok(())
        );
    }
    assert_eq!(state.admit(&filter, at(t0, 10), "a", 443, 0, false), Ok(()));
    assert_eq!(
        state.admit(&filter, at(t0, 20), "d", 80, 0, false),
        Err(Block::Destinations)
    );
    // A minute on, the old destinations have aged out.
    assert_eq!(
        state.admit(&filter, at(t0, 61_000), "d", 80, 0, false),
        Ok(())
    );
}

#[test]
fn the_time_limit_refuses_everything_and_zero_limits_mean_none() {
    let filter = EgressFilter::default();
    let mut state = FilterState::default();
    let now = Instant::now();
    assert_eq!(
        state.admit(&filter, now, "a", 80, 0, true),
        Err(Block::TimeLimit)
    );
    let unlimited = EgressFilter {
        max_new_per_second: 0,
        max_concurrent: 0,
        max_destinations_per_minute: 0,
        blocked_ports: Vec::new(),
        ..EgressFilter::default()
    };
    for i in 0..5000 {
        assert_eq!(
            state.admit(&unlimited, now, &format!("h{i}"), 25, 10_000, false),
            Ok(())
        );
    }
    let timed = EgressFilter {
        run_limit_minutes: 10,
        ..EgressFilter::default()
    };
    assert_eq!(timed.run_limit(), Some(Duration::from_secs(600)));
    assert_eq!(
        EgressFilter {
            enabled: false,
            ..timed
        }
        .run_limit(),
        None
    );
}

#[test]
fn echo_replies_are_capped_per_second() {
    let filter = EgressFilter {
        max_icmp_per_second: 2,
        ..EgressFilter::default()
    };
    let mut state = FilterState::default();
    let t0 = Instant::now();
    assert!(state.echo_allowed(&filter, t0));
    assert!(state.echo_allowed(&filter, at(t0, 10)));
    assert!(!state.echo_allowed(&filter, at(t0, 20)));
    assert!(state.echo_allowed(&filter, at(t0, 1100)));
    assert!(state.echo_allowed(&EgressFilter::off(), t0));
}

#[test]
fn the_settings_are_checked_and_old_settings_files_get_the_defaults() {
    let mut config = RouteConfig::default();
    config.filter.blocked_ports.push(0);
    assert!(config.validate().is_err());
    config.filter.blocked_ports = (1..=65).collect();
    assert!(config.validate().is_err());
    config.filter = EgressFilter::default();
    config.filter.run_limit_minutes = 8 * 24 * 60;
    assert!(config.validate().is_err());
    // A file written before the filter existed has no `filter` key.
    let old: RouteConfig = serde_json::from_str(r#"{"allow_lan": true}"#).unwrap();
    assert_eq!(old.filter, EgressFilter::default());
    // A partial filter keeps the defaults of what it leaves out.
    let partial: RouteConfig =
        serde_json::from_str(r#"{"filter": {"max_new_per_second": 5}}"#).unwrap();
    assert_eq!(partial.filter.max_new_per_second, 5);
    assert_eq!(partial.filter.blocked_ports, vec![25, 26, 465, 587, 2525]);
}

fn proxied(name: &str, tweak: impl FnOnce(&mut EgressFilter)) -> (Rig, FakeSocks) {
    let socks = FakeSocks::echo();
    let rig = Rig::new(name);
    let mut config = config_for(&socks);
    tweak(&mut config.filter);
    rig.claim("run1", &config, RouteKind::Tor).unwrap();
    (rig, socks)
}

const FAR: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

#[test]
fn a_sample_that_tries_smtp_is_refused_before_anything_reaches_the_proxy() {
    let (mut rig, socks) = proxied("filter-smtp", |_| {});
    for port in [25, 465, 587] {
        let (_tcp, state) = Tcp::open(&mut rig.guest, FAR, port, WAIT);
        assert_eq!(state, Connect::Refused, "port {port}");
    }
    let (mut web, state) = Tcp::open(&mut rig.guest, FAR, 443, WAIT);
    assert_eq!(state, Connect::Open);
    web.send_all(&mut rig.guest, b"x");
    assert_eq!(web.read(&mut rig.guest, 1, WAIT), b"x");
    assert_eq!(socks.requests().len(), 1, "only the web connection left");
    let stats = rig.gateway.stats();
    assert_eq!((stats.filter_port, stats.tcp_blocked), (3, 3));
    assert_eq!(stats.tcp_connections, 1);
    assert_eq!(
        rig.gateway.blocked_ports(),
        vec![(25, 1), (465, 1), (587, 1)]
    );
    let said = stats.filter_summary(&rig.gateway.blocked_ports()).unwrap();
    assert_eq!(
        said,
        "Egress filter blocked 1 connection to port 25 and 1 to port 465 and 1 to port 587"
    );
}

#[test]
fn the_filter_off_lets_mail_ports_through_and_the_other_routes_are_untouched() {
    let (mut rig, socks) = proxied("filter-off", |f| f.enabled = false);
    let (_tcp, state) = Tcp::open(&mut rig.guest, FAR, 25, WAIT);
    assert_eq!(state, Connect::Open);
    assert_eq!(socks.requests().len(), 1);
    assert_eq!(rig.gateway.stats().filter_total(), 0);
    // InetSim has no egress to limit: SMTP reaches the fake server.
    let mut rig = Rig::new("filter-inetsim");
    rig.claim("run1", &RouteConfig::default(), RouteKind::InetSim)
        .unwrap();
    let (mut smtp, state) = Tcp::open(&mut rig.guest, FAR, 25, WAIT);
    assert_eq!(state, Connect::Open);
    assert!(String::from_utf8_lossy(&smtp.read(&mut rig.guest, 4, WAIT)).starts_with("220 "));
    assert_eq!(rig.gateway.stats().filter_total(), 0);
}

#[test]
fn a_fast_connect_loop_is_cut_off_at_the_rate_limit() {
    let (mut rig, socks) = proxied("filter-rate", |f| {
        f.max_new_per_second = 5;
        f.max_destinations_per_minute = 0;
    });
    let mut open = 0;
    let mut refused = 0;
    let mut keep = Vec::new();
    for _ in 0..12 {
        let (tcp, state) = Tcp::open(&mut rig.guest, FAR, 8080, SHORT);
        match state {
            Connect::Open => open += 1,
            Connect::Refused => refused += 1,
            Connect::Silent => {}
        }
        keep.push(tcp);
    }
    // The loop is far faster than a second, so at most five got through.
    assert!(
        (1..=6).contains(&open) && refused >= 6,
        "{open} open, {refused} refused"
    );
    let stats = rig.gateway.stats();
    assert_eq!(stats.filter_rate, refused);
    assert_eq!(socks.requests().len() as u64, stats.tcp_connections);
    let said = stats.filter_summary(&[]).unwrap();
    assert!(said.contains("over the connection-rate limit"), "{said}");
}

#[test]
fn connections_open_at_once_are_capped() {
    let (mut rig, _socks) = proxied("filter-open", |f| {
        f.max_concurrent = 2;
        f.max_new_per_second = 0;
    });
    let mut held = Vec::new();
    for _ in 0..2 {
        let (tcp, state) = Tcp::open(&mut rig.guest, FAR, 8080, WAIT);
        assert_eq!(state, Connect::Open);
        held.push(tcp);
    }
    let (_third, state) = Tcp::open(&mut rig.guest, FAR, 8080, WAIT);
    assert_eq!(state, Connect::Refused);
    assert_eq!(rig.gateway.stats().filter_concurrent, 1);
}

#[test]
fn a_scan_of_many_destinations_is_stopped_at_the_destination_limit() {
    let (mut rig, socks) = proxied("filter-scan", |f| {
        f.max_destinations_per_minute = 3;
        f.max_new_per_second = 0;
    });
    let mut states = Vec::new();
    for last in 1..=5u8 {
        let (_tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(93, 184, 216, last), 80, WAIT);
        states.push(state);
    }
    assert_eq!(
        states,
        [
            Connect::Open,
            Connect::Open,
            Connect::Open,
            Connect::Refused,
            Connect::Refused
        ]
    );
    // A destination already used is still reachable.
    let (_tcp, state) = Tcp::open(&mut rig.guest, Ipv4Addr::new(93, 184, 216, 1), 81, WAIT);
    assert_eq!(state, Connect::Open);
    assert_eq!(rig.gateway.stats().filter_destinations, 2);
    assert_eq!(socks.requests().len(), 4);
}

#[test]
fn forwarding_stops_when_the_time_limit_ends() {
    let (mut rig, socks) = proxied("filter-time", |f| {
        f.run_limit_minutes = 30;
        f.max_new_per_second = 0;
    });
    let (mut tcp, state) = Tcp::open(&mut rig.guest, FAR, 8080, WAIT);
    assert_eq!(state, Connect::Open);
    tcp.send_all(&mut rig.guest, b"before");
    assert_eq!(tcp.read(&mut rig.guest, 6, WAIT), b"before");
    rig.gateway.end_time_limit_for_tests();
    // The open connection is reset, new ones are refused, names unanswered.
    assert!(tcp.wait_reset(&mut rig.guest, WAIT));
    let (_late, state) = Tcp::open(&mut rig.guest, FAR, 8080, WAIT);
    assert_eq!(state, Connect::Refused);
    assert!(
        rig.guest
            .dns("late.example", crate::route::dns::TYPE_A, SHORT)
            .is_none()
    );
    let stats = rig.gateway.stats();
    assert_eq!(stats.filter_time, 2, "one open, one new");
    assert_eq!(socks.requests().len(), 1);
}

#[test]
fn a_ping_flood_at_the_router_is_answered_only_up_to_the_limit() {
    let (mut rig, _socks) = proxied("filter-icmp", |f| f.max_icmp_per_second = 5);
    let request = [8, 0, 0, 0, 0, 1, 0, 1, b'p', b'i', b'n', b'g'];
    for _ in 0..30 {
        rig.guest.send_ip(super::GATEWAY, 1, &request);
    }
    std::thread::sleep(Duration::from_millis(400));
    let stats = rig.gateway.stats();
    assert!(stats.filter_icmp >= 20, "{stats:?}");
    assert_eq!(stats.icmp_dropped, stats.filter_icmp);
}

#[test]
fn the_text_names_each_reason_and_old_counts_say_nothing() {
    assert_eq!(RouteStats::default().filter_summary(&[]), None);
    let stats = RouteStats {
        filter_port: 5,
        filter_rate: 2,
        filter_concurrent: 1,
        filter_destinations: 3,
        filter_time: 4,
        filter_icmp: 6,
        ..RouteStats::default()
    };
    let said = stats.filter_summary(&[(25, 4), (587, 1)]).unwrap();
    assert!(said.starts_with("Egress filter blocked 4 connections to port 25 and 1 to port 587"));
    for part in [
        "2 over the connection-rate limit",
        "1 over the open-connections limit",
        "3 to new destinations",
        "4 after the run time limit",
        "6 ICMP echo replies withheld",
    ] {
        assert!(said.contains(part), "{said}");
    }
    // Counts saved without the filter fields read as zero.
    let old: RouteStats = serde_json::from_str(r#"{"tcp_blocked": 3}"#).unwrap();
    assert_eq!(old.filter_total(), 0);
}
