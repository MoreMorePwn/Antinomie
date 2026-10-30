// SPDX-License-Identifier: GPL-3.0-only
use super::super::{Engine, Options};
use super::support::*;

fn read_file(path: &str) -> Calls {
    vec![open_read(1, path, 3), read(1, 3, b"data\n")]
}

#[test]
fn credential_stores_have_their_rules_and_tiers() {
    for (path, rule, expected) in [
        ("/etc/shadow", "credential.shadow_read", "high"),
        ("/etc/gshadow", "credential.shadow_read", "high"),
        ("/etc/security/opasswd", "credential.shadow_read", "high"),
        ("/etc/shadow-", "credential.shadow_read", "high"),
        ("/root/.ssh/id_rsa", "credential.ssh_keys", "medium"),
        (
            "/home/user/.ssh/id_ed25519",
            "credential.ssh_keys",
            "medium",
        ),
        ("/etc/ssh/ssh_host_rsa_key", "credential.ssh_keys", "medium"),
        ("/root/.aws/credentials", "credential.cloud_tokens", "high"),
        ("/home/user/.kube/config", "credential.cloud_tokens", "high"),
        (
            "/home/user/.docker/config.json",
            "credential.cloud_tokens",
            "high",
        ),
        (
            "/home/user/.config/gcloud/credentials.db",
            "credential.cloud_tokens",
            "high",
        ),
        (
            "/home/user/.git-credentials",
            "credential.cloud_tokens",
            "high",
        ),
        (
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "credential.cloud_tokens",
            "high",
        ),
        (
            "/home/user/.mozilla/firefox/abc.default/logins.json",
            "credential.browser_store",
            "medium",
        ),
        (
            "/home/user/.config/google-chrome/Default/Login Data",
            "credential.browser_store",
            "medium",
        ),
        (
            "/home/user/.bitcoin/wallet.dat",
            "credential.wallet",
            "medium",
        ),
        (
            "/home/user/.electrum/wallets/default_wallet",
            "credential.wallet",
            "medium",
        ),
        (
            "/home/user/.ethereum/keystore/UTC--2020",
            "credential.wallet",
            "medium",
        ),
        ("/root/.bash_history", "credential.history_read", "low"),
        ("/home/user/.zsh_history", "credential.history_read", "low"),
        ("/tmp/krb5cc_1000", "credential.kerberos_ccache", "medium"),
        ("/etc/krb5.keytab", "credential.kerberos_ccache", "medium"),
    ] {
        let out = run(read_file(path));
        assert_eq!(
            tier(&out, rule).as_deref(),
            Some(expected),
            "{path} should be {rule}"
        );
    }
}

#[test]
fn near_misses_are_not_credential_reads() {
    for path in [
        "/root/.ssh/id_rsa.pub",
        "/root/.ssh/known_hosts",
        "/etc/passwd",
        "/home/user/.aws/notes.txt",
        "/home/user/.mozilla/firefox/abc/places.sqlite",
        "/etc/ssh/ssh_host_rsa_key.pub",
        "/tmp/shadow",
    ] {
        let out = run(read_file(path));
        assert!(
            !rules_of(&out)
                .iter()
                .any(|rule| rule.starts_with("credential.") && rule != "credential.history_read"),
            "{path}: {:?}",
            rules_of(&out)
        );
    }
    // Writing a key is persistence, not credential access.
    assert!(!has(
        &run(vec![open_write(1, "/root/.ssh/id_rsa", 3)]),
        "credential.ssh_keys"
    ));
}

#[test]
fn the_tool_that_owns_a_store_is_one_tier_down() {
    let mut calls = vec![exec(1, "/usr/bin/ssh", &["ssh", "host"])];
    calls.extend(read_file("/root/.ssh/id_rsa"));
    let out = run(calls);
    let row = rows(&out, "credential.ssh_keys");
    assert_eq!(text(row[0], "finding.tier"), "low");
    let mut login = vec![exec(1, "/usr/sbin/unix_chkpwd", &["unix_chkpwd"])];
    login.extend(read_file("/etc/shadow"));
    assert_eq!(
        tier(&run(login), "credential.shadow_read").as_deref(),
        Some("medium")
    );
}

#[test]
fn a_private_key_found_by_its_first_bytes_is_a_credential_read() {
    let out = run(vec![
        open_read(1, "/tmp/somefile", 3),
        read(1, 3, b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc"),
    ]);
    assert_eq!(tier(&out, "credential.ssh_keys").as_deref(), Some("medium"));
    let text_file = run(vec![
        open_read(1, "/tmp/somefile", 3),
        read(1, 3, b"-----BEGIN CERTIFICATE-----\nabc"),
    ]);
    assert!(!has(&text_file, "credential.ssh_keys"));
}

#[test]
fn the_instance_metadata_service_is_high_even_when_nothing_answers() {
    for ip in [
        [169, 254, 169, 254],
        [169, 254, 170, 2],
        [169, 254, 0, 23],
        [100, 100, 100, 200],
    ] {
        let out = run(vec![socket(1, 2, 1, 3), connect(1, 3, ip, 80)]);
        assert_eq!(
            tier(&out, "credential.cloud_metadata").as_deref(),
            Some("high")
        );
        assert_eq!(
            list(
                rows(&out, "credential.cloud_metadata")[0],
                "finding.technique"
            ),
            ["T1552.005", "DET0001"]
        );
    }
    let mut refused = connect(1, 3, [169, 254, 169, 254], 80);
    refused.exit.as_mut().unwrap().result = Some(-111);
    let out = run(vec![socket(1, 2, 1, 3), refused]);
    assert_eq!(
        tier(&out, "credential.cloud_metadata").as_deref(),
        Some("medium"),
        "a failed attempt is one tier down"
    );
    assert!(!has(
        &run(vec![
            socket(1, 2, 1, 3),
            connect(1, 3, [169, 254, 1, 1], 80)
        ]),
        "credential.cloud_metadata"
    ));
}

fn cloud_report() -> antinomie_monitor_core::route::MetadataReport {
    use antinomie_monitor_core::route::MetadataReport;
    let event = |kind: &str, detail: &str, endpoint: &str, ms| {
        serde_json::from_value(serde_json::json!({
            "ms": ms, "kind": kind, "detail": detail, "endpoint": endpoint
        }))
        .unwrap()
    };
    MetadataReport {
        version: 1,
        provider: "cloud-tencent-cvm".into(),
        address: "169.254.0.23".into(),
        events: vec![
            event(
                "request",
                "GET /latest/meta-data/instance-id",
                "169.254.0.23:80",
                1_000,
            ),
            event(
                "request",
                "GET /latest/meta-data/cam/security-credentials/CVMRole",
                "169.254.0.23:80",
                2_000,
            ),
            event(
                "credentials",
                "GET /latest/meta-data/cam/security-credentials/CVMRole",
                "169.254.0.23:80",
                2_000,
            ),
            event(
                "canary-use",
                "Authorization: Bearer AKIDexamplefixture",
                "203.0.113.9:80",
                3_000,
            ),
        ],
        ..MetadataReport::default()
    }
}

#[test]
fn a_cloud_profiles_metadata_report_becomes_findings_and_an_endpoint() {
    let mut engine = Engine::new(Options::default());
    engine.cloud_report(&cloud_report(), None);
    let log = engine.take_ioc();
    let out = engine.finish(&Default::default());
    // One row for the requests, with the request lines as facts.
    let requests = rows(&out, "credential.cloud_metadata");
    assert_eq!(requests.len(), 1);
    assert_eq!(count(requests[0]), 2);
    assert!(list(requests[0], "finding.detail")
        .iter()
        .any(|line| line.contains("security-credentials/CVMRole")));
    assert_eq!(
        list(requests[0], "finding.technique"),
        ["T1552.005", "DET0001"]
    );
    for rule in ["credential.cloud_credentials", "credential.canary_used"] {
        assert_eq!(tier(&out, rule).as_deref(), Some("high"), "{rule}");
        assert_eq!(
            list(rows(&out, rule)[0], "finding.technique"),
            ["T1552.005", "DET0001"]
        );
    }
    assert_eq!(
        text(rows(&out, "credential.canary_used")[0], "finding.object"),
        "203.0.113.9:80"
    );
    // The place the canary went to is an endpoint indicator.
    assert_eq!(log.connections.len(), 1);
    assert_eq!(log.connections[0].port, 80);
    assert_eq!(log.connections[0].ip.to_string(), "203.0.113.9");
    // No report, no rows.
    let mut empty = Engine::new(Options::default());
    empty.cloud_report(&Default::default(), None);
    assert!(empty.finish(&Default::default()).rows.is_empty());
}

#[test]
fn many_documents_read_from_home_directories_is_a_local_sweep() {
    let mut calls = Vec::new();
    for n in 0..60 {
        calls.push(open_read(
            1,
            &format!("/home/user/Documents/report{n}.pdf"),
            3,
        ));
    }
    let out = run(calls);
    assert_eq!(tier(&out, "collection.local_sweep").as_deref(), Some("low"));
    let few: Calls = (0..10)
        .map(|n| open_read(1, &format!("/home/user/Documents/r{n}.pdf"), 3))
        .collect();
    assert!(!has(&run(few), "collection.local_sweep"));
    let system: Calls = (0..60)
        .map(|n| open_read(1, &format!("/usr/share/doc/p{n}.pdf"), 3))
        .collect();
    assert!(!has(&run(system), "collection.local_sweep"));
}

#[test]
fn the_machines_known_hosts_then_ssh_is_a_worm_pattern() {
    let out = run(vec![
        open_read(1, "/root/.ssh/known_hosts", 3),
        exec(
            1,
            "/usr/bin/ssh",
            &["ssh", "-o", "BatchMode=yes", "10.0.0.7", "id"],
        ),
    ]);
    assert_eq!(tier(&out, "lateral.ssh_spread").as_deref(), Some("high"));
    let alone = run(vec![exec(1, "/usr/bin/ssh", &["ssh", "10.0.0.7"])]);
    assert!(!has(&alone, "lateral.ssh_spread"));
    let by_socket = run(vec![
        open_read(1, "/root/.ssh/config", 3),
        socket(1, 2, 1, 4),
        connect(1, 4, [10, 0, 0, 7], 22),
    ]);
    assert!(has(&by_socket, "lateral.ssh_spread"));
}
