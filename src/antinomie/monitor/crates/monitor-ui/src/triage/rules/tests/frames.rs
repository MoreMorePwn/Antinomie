// SPDX-License-Identifier: GPL-3.0-only
//! Rules over the capture: DNS names, HTTP requests, sessions, and what they are tied to.
use super::super::*;
use super::support::*;

type Values = Vec<(&'static str, RowValue)>;

fn base(frame: u64, time_us: u64) -> Values {
    vec![
        (
            "capture.path",
            RowValue::Text("/runs/r/capture.pcap".into()),
        ),
        ("frame.number", RowValue::Number(i128::from(frame))),
        ("frame.time_us", RowValue::Number(i128::from(time_us))),
    ]
}

fn dns(frame: u64, time_us: u64, name: &str, rcode: i128, answers: &[&str], kind: &str) -> Values {
    let mut values = base(frame, time_us);
    values.extend([
        ("dns.name", RowValue::Text(name.into())),
        ("dns.type", RowValue::Text(kind.into())),
        ("dns.rcode", RowValue::Number(rcode)),
        (
            "dns.answers",
            RowValue::List(answers.iter().map(|text| (*text).to_owned()).collect()),
        ),
    ]);
    values
}

fn http(frame: u64, time_us: u64, host: &str, uri: &str) -> Values {
    let mut values = base(frame, time_us);
    values.extend([
        ("http.host", RowValue::Text(host.into())),
        ("http.uri", RowValue::Text(uri.into())),
    ]);
    values
}

fn session(
    frame: u64,
    time_us: u64,
    protocol: &str,
    kind: &str,
    name: &str,
    details: &str,
) -> Values {
    let mut values = base(frame, time_us);
    values.extend([
        ("session.protocol", RowValue::Text(protocol.into())),
        ("session.kind", RowValue::Text(kind.into())),
        ("session.server_name", RowValue::Text(name.into())),
        ("session.details", RowValue::Text(details.into())),
    ]);
    values
}

struct Capture {
    engine: Engine,
    files: FdState,
}

impl Capture {
    fn new() -> Self {
        Self {
            engine: Engine::new(Options {
                show_info: true,
                capture_all: false,
            }),
            files: FdState::default(),
        }
    }

    fn calls(mut self, calls: Calls) -> Self {
        for (at, mut call) in calls.into_iter().enumerate() {
            call.call_id = at as u64 + 1;
            self.engine.observe(&call, &self.files, None, false);
        }
        self
    }

    fn frame(&mut self, kind: FrameKind, values: &Values, destination: &str, port: &str) {
        self.engine.frame(kind, values, destination, port, None);
    }

    fn finish(self) -> Output {
        self.engine.finish(&self.files)
    }
}

const NAMES: [&str; 12] = [
    "xk3j9q2mzp8w.example",
    "q8w7e6r5t4y3.example",
    "zz91hd7fk20a.example",
    "p0o9i8u7y6t5.example",
    "m4n3b2v1c0x9.example",
    "a7s6d5f4g3h2.example",
    "l9k8j7h6g5f4.example",
    "r2t4y6u8i0o1.example",
    "b1v3c5x7z9a2.example",
    "w9e8r7t6y5u4.example",
    "n6m5b4v3c2x1.example",
    "h3j5k7l9q1w2.example",
];

#[test]
fn a_burst_of_failed_random_names_is_dga_only_when_a_resolver_answers_something() {
    let burst = |answered: bool| {
        let mut capture = Capture::new();
        for (at, name) in NAMES.iter().enumerate() {
            capture.frame(
                FrameKind::Dns,
                &dns(
                    at as u64 + 1,
                    1_000_000 + at as u64 * 1_000_000,
                    name,
                    3,
                    &[],
                    "A",
                ),
                "10.0.2.3",
                "53",
            );
        }
        if answered {
            capture.frame(
                FrameKind::Dns,
                &dns(99, 20_000_000, "example.org", 0, &["93.184.216.34"], "A"),
                "10.0.2.3",
                "53",
            );
        }
        capture.finish()
    };
    let out = burst(true);
    let row = rows(&out, "network.dga_nxdomain");
    assert_eq!(row.len(), 1);
    assert_eq!(
        text(row[0], "finding.tier"),
        "low",
        "a lookup seen only in the capture is VM-wide: one tier down"
    );
    assert!(list(row[0], "finding.flags").contains(&"vm-wide".to_owned()));
    assert_eq!(list(row[0], "finding.technique"), ["T1568.002", "DET0419"]);
    let isolated = burst(false);
    assert!(!has(&isolated, "network.dga_nxdomain"));
    assert!(
        isolated
            .notes
            .iter()
            .any(|note| note.contains("no resolver answered")),
        "{:?}",
        isolated.notes
    );
    // Ordinary typos are not a burst.
    let mut few = Capture::new();
    for (at, name) in NAMES.iter().take(4).enumerate() {
        few.frame(
            FrameKind::Dns,
            &dns(at as u64, 1_000_000 + at as u64, name, 3, &[], "A"),
            "10.0.2.3",
            "53",
        );
    }
    few.frame(
        FrameKind::Dns,
        &dns(50, 5_000_000, "example.org", 0, &["93.184.216.34"], "A"),
        "10.0.2.3",
        "53",
    );
    assert!(!has(&few.finish(), "network.dga_nxdomain"));
}

#[test]
fn a_task_that_talked_to_the_name_server_is_blamed_with_its_tier_kept() {
    let mut capture =
        Capture::new().calls(vec![socket(7, 2, 2, 3), connect(7, 3, [10, 0, 2, 3], 53)]);
    for (at, name) in NAMES.iter().enumerate() {
        capture.frame(
            FrameKind::Dns,
            &dns(
                at as u64 + 1,
                1_000_000 + at as u64 * 1_000_000,
                name,
                3,
                &[],
                "A",
            ),
            "10.0.2.3",
            "53",
        );
    }
    capture.frame(
        FrameKind::Dns,
        &dns(99, 20_000_000, "example.org", 0, &["93.184.216.34"], "A"),
        "10.0.2.3",
        "53",
    );
    let out = capture.finish();
    let row = rows(&out, "network.dga_nxdomain");
    assert_eq!(text(row[0], "finding.tier"), "medium");
    assert!(list(row[0], "finding.flags").contains(&"inferred".to_owned()));
    assert_eq!(files::number(&row[0].values, "process.cookie"), Some(7));
    assert_eq!(
        files::number(&row[0].values, "frame.number"),
        Some(10),
        "the frame that completed the burst"
    );
    assert_eq!(text(row[0], "capture.path"), "/runs/r/capture.pcap");
}

#[test]
fn long_labels_and_many_text_queries_are_a_tunnel() {
    let mut capture = Capture::new();
    let long = format!("{}.tunnel.example", "a".repeat(52));
    for at in 0..6 {
        capture.frame(
            FrameKind::Dns,
            &dns(at, 1_000_000 + at * 1000, &long, 0, &["1.2.3.4"], "A"),
            "10.0.2.3",
            "53",
        );
    }
    for at in 0..25u64 {
        capture.frame(
            FrameKind::Dns,
            &dns(
                100 + at,
                2_000_000 + at * 1000,
                &format!("c{at}.txt.example"),
                0,
                &["x"],
                "TXT",
            ),
            "10.0.2.3",
            "53",
        );
    }
    let out = capture.finish();
    assert_eq!(rows(&out, "network.dns_tunnel").len(), 2);
    let mut quiet = Capture::new();
    quiet.frame(
        FrameKind::Dns,
        &dns(1, 1, &long, 0, &["1.2.3.4"], "A"),
        "10.0.2.3",
        "53",
    );
    assert!(!has(&quiet.finish(), "network.dns_tunnel"));
}

#[test]
fn paste_chat_and_file_drop_services_hidden_services_and_the_metadata_service() {
    let mut capture = Capture::new();
    capture.frame(
        FrameKind::Dns,
        &dns(1, 1, "api.telegram.org", 0, &["149.154.167.220"], "A"),
        "10.0.2.3",
        "53",
    );
    capture.frame(
        FrameKind::Http,
        &http(2, 2, "raw.githubusercontent.com", "/x/y/z.sh"),
        "185.199.108.133",
        "80",
    );
    capture.frame(
        FrameKind::Http,
        &http(3, 3, "discord.com", "/api/webhooks/1/abc"),
        "162.159.135.232",
        "80",
    );
    capture.frame(
        FrameKind::Http,
        &http(4, 4, "discord.com", "/channels/1"),
        "162.159.135.232",
        "80",
    );
    capture.frame(
        FrameKind::Session,
        &session(5, 5, "TLS", "client hello", "pastebin.com", ""),
        "104.20.67.143",
        "443",
    );
    capture.frame(
        FrameKind::Dns,
        &dns(6, 6, "abcdefghij234567.onion", 0, &[], "A"),
        "10.0.2.3",
        "53",
    );
    capture.frame(
        FrameKind::Dns,
        &dns(
            7,
            7,
            "metadata.google.internal",
            0,
            &["169.254.169.254"],
            "A",
        ),
        "10.0.2.3",
        "53",
    );
    capture.frame(
        FrameKind::Http,
        &http(8, 8, "169.254.169.254", "/latest/meta-data/"),
        "169.254.169.254",
        "80",
    );
    let out = capture.finish();
    let services: Vec<_> = rows(&out, "network.web_service")
        .iter()
        .map(|row| text(row, "finding.object"))
        .collect();
    assert_eq!(services.len(), 4, "{services:?}");
    assert!(services
        .iter()
        .any(|object| object == "discord.com/api/webhooks/1/abc"));
    assert!(
        !services.iter().any(|object| object.contains("/channels")),
        "plain discord pages are not a webhook"
    );
    assert_eq!(rows(&out, "network.tor").len(), 1);
    assert_eq!(rows(&out, "credential.cloud_metadata").len(), 2);
    assert!(
        rows(&out, "network.ip_literal").is_empty(),
        "the metadata address has its own rule"
    );
}

#[test]
fn an_address_in_the_host_header_and_a_known_protocol_on_an_odd_port() {
    let mut capture = Capture::new();
    capture.frame(
        FrameKind::Http,
        &http(1, 1, "203.0.113.9", "/gate.php"),
        "203.0.113.9",
        "80",
    );
    capture.frame(
        FrameKind::Http,
        &http(2, 2, "files.example", "/a"),
        "198.51.100.4",
        "4444",
    );
    capture.frame(
        FrameKind::Session,
        &session(3, 3, "TLS", "client hello", "c2.example", ""),
        "198.51.100.5",
        "4443",
    );
    capture.frame(
        FrameKind::Session,
        &session(4, 4, "TLS", "client hello", "c2.example", ""),
        "198.51.100.5",
        "9001",
    );
    capture.frame(
        FrameKind::Session,
        &session(5, 5, "SSH", "banner", "", "SSH-2.0-OpenSSH_9"),
        "198.51.100.6",
        "2222",
    );
    capture.frame(
        FrameKind::Session,
        &session(6, 6, "SSH", "banner", "", "SSH-2.0-OpenSSH_9"),
        "198.51.100.6",
        "22",
    );
    let out = capture.finish();
    assert_eq!(rows(&out, "network.ip_literal").len(), 1);
    let ports: Vec<_> = rows(&out, "network.nonstandard_port")
        .iter()
        .map(|row| text(row, "finding.object"))
        .collect();
    assert_eq!(ports.len(), 3, "{ports:?}");
    assert!(ports.iter().any(|object| object == "files.example:4444"));
    assert!(ports.iter().any(|object| object == "c2.example:9001"));
    assert!(
        !ports.iter().any(|object| object.ends_with(":4443")),
        "4443 is a TLS port"
    );
}

#[test]
fn regular_requests_to_one_host_are_a_beacon_and_irregular_ones_are_not() {
    let mut steady = Capture::new();
    for at in 0..10u64 {
        steady.frame(
            FrameKind::Http,
            &http(at, at * 30_000_000, "update.example", "/check"),
            "198.51.100.9",
            "8080",
        );
    }
    let out = steady.finish();
    let row = rows(&out, "network.beacon");
    assert_eq!(row.len(), 1);
    assert!(text(row[0], "finding.summary").contains("about every 30.0 s"));
    let mut jitter = Capture::new();
    for (at, second) in [0u64, 1, 9, 40, 41, 100, 250, 251, 600, 1300]
        .iter()
        .enumerate()
    {
        jitter.frame(
            FrameKind::Http,
            &http(at as u64, second * 1_000_000, "update.example", "/check"),
            "198.51.100.9",
            "8080",
        );
    }
    assert!(!has(&jitter.finish(), "network.beacon"));
}

#[test]
fn frames_of_the_base_itself_are_skipped_and_counted() {
    let mut capture = Capture::new();
    capture.frame(
        FrameKind::Dns,
        &dns(1, 1, "2.debian.pool.ntp.org", 0, &["1.2.3.4"], "A"),
        "10.0.2.3",
        "53",
    );
    capture.frame(
        FrameKind::Dns,
        &dns(2, 2, "deb.debian.org", 0, &["1.2.3.5"], "A"),
        "10.0.2.3",
        "53",
    );
    capture.frame(
        FrameKind::Dns,
        &dns(3, 3, "printer.local", 0, &[], "A"),
        "224.0.0.251",
        "5353",
    );
    capture.frame(
        FrameKind::Dns,
        &dns(4, 4, "xk3j9q2mzp8w.lan", 3, &[], "A"),
        "10.0.2.3",
        "53",
    );
    capture.frame(
        FrameKind::Http,
        &http(5, 5, "connectivity-check.ubuntu.com", "/"),
        "91.189.91.49",
        "80",
    );
    capture.frame(
        FrameKind::Dns,
        &dns(6, 6, "pastebin.com", 0, &["1.2.3.4"], "A"),
        "10.0.2.3",
        "53",
    );
    let out = capture.finish();
    assert_eq!(out.suppressed, 5);
    assert_eq!(rules_of(&out), ["network.web_service"]);
}

#[test]
fn a_packet_row_opens_its_frame_and_never_a_call() {
    let mut capture = Capture::new();
    capture.frame(
        FrameKind::Dns,
        &dns(42, 1, "pastebin.com", 0, &["1.2.3.4"], "A"),
        "10.0.2.3",
        "53",
    );
    let out = capture.finish();
    let row = rows(&out, "network.web_service")[0];
    assert_eq!(row.cells[9].text, "packet #42");
    assert_eq!(row.key, (0, 0, 42));
    assert_eq!(row.cells[3].text, "VM-wide (capture)");
}
