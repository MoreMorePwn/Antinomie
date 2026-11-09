// SPDX-License-Identifier: GPL-3.0-only
//! The cross-link model end to end: a report shaped like the BPFDoor run of
//! the 2026-11-07 evaluation (minimised, no sample bytes) is linked, and every
//! format must hold unique anchors and links that all resolve.
use super::*;
use std::collections::BTreeSet;

const SAMPLE: &str = "fd1b20ee5bd4b5de4fa7e1bdd4b0a0f1c2f0ff2a4bd1f8f1c3d5e6f7a8b9c0d1";
const START: u64 = 1_794_051_496_000;

fn data() -> RowData {
    RowData::default()
}

fn table(columns: &[&str], rows: Vec<(Vec<&str>, RowData)>) -> Table {
    let (rows, data): (Vec<Vec<String>>, Vec<RowData>) = rows
        .into_iter()
        .map(|(cells, d)| (cells.into_iter().map(String::from).collect(), d))
        .unzip();
    Table {
        columns: columns.iter().map(|c| (*c).to_owned()).collect(),
        rows,
        data,
        ..Table::default()
    }
}

fn process(pid: u32, parent: Option<u32>, depth: u32, at: u64) -> RowData {
    RowData {
        pid: Some(pid),
        cookie: Some(u64::from(pid) * 7),
        parent_pid: parent,
        parent_cookie: parent.map(|p| u64::from(p) * 7),
        depth: Some(depth),
        relative_ms: Some(at),
        time_ms: Some(START + at),
        ..data()
    }
}

fn finding(pid: u32, rule: &str, target: &str, attack: &[&str], at: u64) -> RowData {
    RowData {
        pid: Some(pid),
        cookie: Some(u64::from(pid) * 7),
        rule: rule.into(),
        target: target.into(),
        attack: attack.iter().map(|a| (*a).to_owned()).collect(),
        relative_ms: Some(at),
        time_ms: Some(START + at),
        count: Some(1),
        ..data()
    }
}

fn file_row(pid: u32, path: &str, at: u64) -> RowData {
    RowData {
        pid: Some(pid),
        cookie: Some(u64::from(pid) * 7),
        path: path.into(),
        relative_ms: Some(at),
        time_ms: Some(START + at),
        ..data()
    }
}

/// A run with processes, findings (one rule five times, to fold), files,
/// network, indicators, techniques and detections.
pub(super) fn bpfdoor() -> Report {
    let mut report = Report::new(
        RunInfo {
            vm_id: "vm-eval".into(),
            boot_id: "boot-1".into(),
            run_id: "f9c3d854aa0b4c5d9e8f7a6b5c4d3e2f".into(),
            started_ms: Some(START),
            finished: true,
            state: "Stopped by you at 5 min 9 s \u{b7} root exited 0".into(),
            exit: "exit 0".into(),
            stopped_by_user: true,
            duration_ms: Some(309_000),
            route: "Tor via the gateway".into(),
            environment: vec![
                Fact::new("Base image", "Debian 13 (Minimal)"),
                Fact::new("Kernel", "6.12.94-antinomie"),
                Fact::new(
                    "Rule packs",
                    "yara-forge-core 20261101; elastic-protections 20261020; abuse-ch-yarahub 20261106",
                ),
            ],
            ..RunInfo::default()
        },
        START + 900_000,
    );
    report.sample = Some(SampleInfo {
        name: "elf-fd1b20ee5bd4".into(),
        sha256: SAMPLE.into(),
        size: Some(31_744),
        role: String::new(),
    });
    let proc_cols = [
        "Process",
        "Argv",
        "Findings",
        "User ID",
        "Started",
        "Lifetime",
        "Outcome",
        "Calls",
        "Exec chain",
    ];
    report.processes = Some(table(
        &proc_cols,
        vec![
            (
                vec![
                    "fd1b20ee-elf-fd1b20ee5bd4 (1351 \u{b7} 1351)",
                    "/tmp/fd1b20ee-elf-fd1b20ee5bd4",
                    "1",
                    "0",
                    "+0.000 s",
                    "5 ms",
                    "exit 0",
                    "37",
                    "renamed to \"/sbin/auditd -n\"",
                ],
                process(1351, None, 0, 0),
            ),
            (
                vec![
                    "fd1b20ee-elf-fd1b20ee5bd4 (1352 \u{b7} 1352)  fork",
                    "/tmp/fd1b20ee-elf-fd1b20ee5bd4",
                    "8",
                    "0",
                    "+0.005 s",
                    "5 min 13 s",
                    "exit 0",
                    "24",
                    "",
                ],
                process(1352, Some(1351), 1, 5),
            ),
        ],
    ));
    let finding_cols = [
        "Time",
        "Tier",
        "Behaviour",
        "Rule",
        "Target",
        "Process",
        "ATT&CK",
        "Count",
        "Result",
        "Summary",
    ];
    let p1352 = "fd1b20ee-elf-fd1b20ee5bd4 (1352 \u{b7} 1352)";
    let mut findings = vec![
        (
            vec![
                "~17:38:16.049 (UTC+7)",
                "high",
                "Waiting for chosen packets: BPF on raw socket",
                "c2.bpf_backdoor",
                "SO_ATTACH_FILTER",
                p1352,
                "T1205.002 Socket Filters",
                "\u{d7}1",
                "succeeded",
                "a classic filter on a raw or packet socket",
            ],
            finding(
                1352,
                "c2.bpf_backdoor",
                "SO_ATTACH_FILTER",
                &["T1205.002"],
                32,
            ),
        ),
        (
            vec![
                "~17:38:16.046 (UTC+7)",
                "low",
                "Process renamed itself",
                "evasion.process_rename",
                "/sbin/auditd -n",
                "fd1b20ee-elf-fd1b20ee5bd4 (1351 \u{b7} 1351)",
                "T1036.005 Match Legitimate Resource Name or Location",
                "\u{d7}1",
                "succeeded",
                "prctl(PR_SET_NAME) renames it",
            ],
            finding(
                1351,
                "evasion.process_rename",
                "/sbin/auditd -n",
                &["T1036.005"],
                3,
            ),
        ),
    ];
    // One rule five times on the lock file: folded into one row.
    for n in 0..5 {
        findings.push((
            vec![
                "~17:38:16.049 (UTC+7)",
                "medium",
                "Lock file in /var/run",
                "persistence.lock_file",
                "/var/run/xinetd.lock",
                p1352,
                "",
                "\u{d7}1",
                "succeeded",
                "creates a lock file",
            ],
            finding(
                1352,
                "persistence.lock_file",
                "/var/run/xinetd.lock",
                &[],
                40 + n,
            ),
        ));
    }
    report.findings = Some(table(&finding_cols, findings));
    let event_cols = ["Time", "Operation", "Path", "Detail", "Process", "Result"];
    report.files = Some(FilesSection {
        tabs: vec![
            NamedTable {
                name: "Opened files".into(),
                table: table(
                    &["Time", "Path", "Process", "Result"],
                    vec![
                        (
                            vec![
                                "~17:38:16.043 (UTC+7)",
                                "/etc/ld.so.cache",
                                p1352,
                                "Succeeded",
                            ],
                            file_row(1352, "/etc/ld.so.cache", 1),
                        ),
                        (
                            vec![
                                "~17:38:16.048 (UTC+7)",
                                "/var/run/xinetd.lock",
                                p1352,
                                "Succeeded",
                            ],
                            file_row(1352, "/var/run/xinetd.lock", 31),
                        ),
                    ],
                ),
            },
            NamedTable {
                name: "Created files".into(),
                table: table(
                    &event_cols,
                    vec![(
                        vec![
                            "~17:38:16.049 (UTC+7)",
                            "openat",
                            "/var/run/xinetd.lock",
                            "path not seen earlier in this run",
                            p1352,
                            "Succeeded",
                        ],
                        file_row(1352, "/var/run/xinetd.lock", 32),
                    )],
                ),
            },
            NamedTable {
                name: "Read files".into(),
                table: table(
                    &["Time", "Path", "Process", "Transferred", "Result"],
                    vec![],
                ),
            },
            NamedTable {
                name: "Changed files".into(),
                table: table(
                    &[
                        "Time",
                        "Path",
                        "Process",
                        "Lifecycle",
                        "Changes",
                        "Location",
                        "Evidence",
                        "Type",
                        "SHA-256",
                    ],
                    vec![(
                        vec![
                            "~17:38:16.049 (UTC+7)",
                            "/var/run/xinetd.lock",
                            p1352,
                            "created (inferred) \u{2192} closed, nothing written \u{2192} deleted",
                            "no content change",
                            "\u{2014}",
                            "call 15",
                            "unknown",
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        ],
                        file_row(1352, "/var/run/xinetd.lock", 32),
                    )],
                ),
            },
        ],
    });
    report.file_activity = Some(vec![FileRecord {
        path: "/var/run/xinetd.lock".into(),
        created: true,
        deleted: true,
        changed: true,
        final_size: Some(0),
        guest_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        reconstruction: "complete".into(),
        ..FileRecord::default()
    }]);
    let endpoint = |e: &str| RowData {
        endpoint: e.into(),
        ..data()
    };
    report.network = Some(vec![
        NamedTable {
            name: "Endpoints".into(),
            table: table(
                &[
                    "Endpoint",
                    "IOC",
                    "Proto",
                    "Frames",
                    "Bytes",
                    "Country",
                    "Organization",
                    "First seen",
                    "Last seen",
                ],
                vec![
                    (
                        vec![
                            "198.18.0.5:443",
                            "No match",
                            "tcp",
                            "40",
                            "18 KiB",
                            "Unavailable",
                            "Unavailable",
                            "17:40:42.662 (UTC+7)",
                            "17:44:01.554 (UTC+7)",
                        ],
                        RowData {
                            time_ms: Some(START + 7_000),
                            relative_ms: Some(5_463),
                            last_ms: Some(START + 12_500),
                            last_relative_ms: Some(10_963),
                            ..endpoint("198.18.0.5:443")
                        },
                    ),
                    (
                        vec![
                            "203.0.113.9:8443",
                            "Matched",
                            "tcp",
                            "12",
                            "2 KiB",
                            "Exampleland",
                            "Example ISP",
                            "17:41:00.000 (UTC+7)",
                            "17:42:00.000 (UTC+7)",
                        ],
                        endpoint("203.0.113.9:8443"),
                    ),
                ],
            ),
        },
        NamedTable {
            name: "Domains".into(),
            table: table(
                &[
                    "Domain",
                    "IOC",
                    "Seen as",
                    "Resolved / connected IPs",
                    "Queries",
                    "First seen",
                    "Last seen",
                    "Rcode",
                ],
                vec![(
                    vec![
                        "metadata.ftp-master.debian.org",
                        "No match",
                        "DNS lookup, TLS server name",
                        "198.18.0.5",
                        "4",
                        "17:41:45.553 (UTC+7)",
                        "17:43:30.807 (UTC+7)",
                        "NOERROR",
                    ],
                    RowData {
                        domain: "metadata.ftp-master.debian.org".into(),
                        addresses: vec!["198.18.0.5".into()],
                        ..data()
                    },
                )],
            ),
        },
        NamedTable {
            name: "URLs".into(),
            table: table(&["Frame", "Time", "Endpoint", "Host"], vec![]),
        },
        NamedTable {
            name: "TLS".into(),
            table: table(
                &["Frame", "Server name", "IOC", "Endpoint", "Version"],
                vec![(
                    vec![
                        "#67",
                        "metadata.ftp-master.debian.org",
                        "No match",
                        "198.18.0.5:443",
                        "TLS 1.3",
                    ],
                    RowData {
                        endpoint: "198.18.0.5:443".into(),
                        domain: "metadata.ftp-master.debian.org".into(),
                        ..data()
                    },
                )],
            ),
        },
    ]);
    report.indicators = Some(vec![
        Indicator {
            kind: "endpoint".into(),
            value: "203.0.113.9:8443".into(),
            verdict: "Matched".into(),
            matched: true,
            dataset: "threatfox".into(),
            family: "BPFDoor".into(),
            process: p1352.into(),
            pids: vec![1352],
            first_seen: "2026-11-07T10:41:00.000Z".into(),
            count: "12 frames".into(),
            ..Indicator::default()
        },
        Indicator {
            kind: "endpoint".into(),
            value: "198.18.0.5:443".into(),
            verdict: "No match".into(),
            stand_in: "metadata.ftp-master.debian.org".into(),
            not_shared: "Tor gateway stand-in address; the name it stands for is the indicator"
                .into(),
            ..Indicator::default()
        },
        Indicator {
            kind: "file".into(),
            value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            path: "/var/run/xinetd.lock".into(),
            verdict: "No match".into(),
            process: p1352.into(),
            pids: vec![1352],
            count: "created, deleted".into(),
            ..Indicator::default()
        },
    ]);
    report.attack = Some(vec![
        Technique {
            id: "T1205.002".into(),
            name: "Traffic Signaling: Socket Filters".into(),
            rules: vec!["c2.bpf_backdoor".into()],
            count: 1,
            ..Technique::default()
        },
        Technique {
            id: "T1036.005".into(),
            name: "Masquerading: Match Legitimate Resource Name or Location".into(),
            rules: vec![
                "evasion.process_rename".into(),
                "Sigma: Potentially Suspicious Execution From Tmp Folder".into(),
            ],
            count: 2,
            ..Technique::default()
        },
    ]);
    report.detections = Some(vec![
        Detection {
            engine: "YARA".into(),
            rule_id: "s1919::Linux_Trojan_BPFDoor_f690fe3b".into(),
            title: "Linux_Trojan_BPFDoor_f690fe3b".into(),
            severity: "100".into(),
            strength: "strong".into(),
            family: "BPFDoor".into(),
            count: 1,
            author: "Elastic Security".into(),
            license: "Elastic License v2".into(),
            source: "selection/pack/elastic-protections-artifacts/Linux_Trojan_BPFDoor.yar".into(),
            reference: "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor".into(),
            ..Detection::default()
        },
        Detection {
            engine: "Sigma".into(),
            rule_id: "be8e5c8a".into(),
            title: "Potentially Suspicious Execution From Tmp Folder".into(),
            severity: "high".into(),
            mitre: vec!["T1036.005".into()],
            count: 1,
            license: "DRL 1.1".into(),
            source: "SigmaHQ".into(),
            ..Detection::default()
        },
    ]);
    report.summary = Some(Summary {
        assessment: "suspicious_behaviour".into(),
        statement: "Triage observed: 4 activity rule(s) fired, the worst at HIGH tier. Family: \
                    BPFDoor, named by 1 YARA rule."
            .into(),
        highest_tier: "high".into(),
        families: vec!["BPFDoor".into()],
        family_sources: vec![
            "BPFDoor: YARA \u{b7} Elastic rule Linux_Trojan_BPFDoor_f690fe3b".into(),
        ],
        tiers: TierCounts {
            high: 1,
            medium: 5,
            low: 1,
            info: 0,
            info_not_listed: 3,
        },
        key_findings: vec![
            KeyFinding {
                tier: "high".into(),
                rule: "c2.bpf_backdoor".into(),
                title: "Waiting for chosen packets: BPF on raw socket".into(),
                target: "SO_ATTACH_FILTER".into(),
                process: "fd1b20ee-elf-fd1b20ee5bd4".into(),
                pid: Some(1352),
                cookie: Some(1352 * 7),
                count: 1,
                first_ms: Some(START + 32),
                relative_ms: Some(32),
                attack: vec!["T1205.002".into()],
                finding: Some(1),
                ..KeyFinding::default()
            },
            KeyFinding {
                tier: "medium".into(),
                rule: "persistence.lock_file".into(),
                title: "Lock file in /var/run".into(),
                target: "/var/run/xinetd.lock".into(),
                process: "fd1b20ee-elf-fd1b20ee5bd4".into(),
                pid: Some(1352),
                cookie: Some(1352 * 7),
                count: 1,
                relative_ms: Some(42),
                finding: Some(5),
                ..KeyFinding::default()
            },
        ],
        key_findings_text: vec!["HIGH Waiting for chosen packets: BPF on raw socket".into()],
        key_findings_total: 7,
        key_behaviours: vec![Behaviour {
            rule: "c2.bpf_backdoor".into(),
            tier: "high".into(),
            category: "c2".into(),
            count: 1,
        }],
        counts: Counts {
            processes: 2,
            findings: 7,
            indicators: 3,
            indicators_matched: 1,
            techniques: 2,
            files_changed: 1,
            files_opened: 2,
            endpoints: 2,
            domains: 1,
        },
        ..Summary::default()
    });
    report.evidence = Some(vec![
        EvidenceRef {
            kind: "telemetry".into(),
            path: "telemetry.raw".into(),
            size: 2_400_000,
            sha256: "ef".repeat(32),
            files: None,
        },
        EvidenceRef {
            kind: "object store".into(),
            path: "objects/".into(),
            size: 7_000,
            sha256: String::new(),
            files: Some(3),
        },
    ]);
    report.notes.push(
        "Network: IP geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0.".into(),
    );
    refs::link(&mut report);
    report
}

/// The `id="…"` and `href="#…"` of an HTML document.
fn html_anchors(html: &str) -> (Vec<String>, Vec<String>) {
    let grab = |marker: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = html;
        while let Some(at) = rest.find(marker) {
            rest = &rest[at + marker.len()..];
            if let Some(end) = rest.find('"') {
                out.push(rest[..end].to_owned());
            }
        }
        out
    };
    (grab(" id=\""), grab("href=\"#"))
}

/// The names of a PDF's `/Dests` dictionary and of its link annotations.
fn pdf_anchors(pdf: &[u8]) -> (Vec<String>, Vec<String>) {
    let text = String::from_utf8_lossy(pdf);
    let dests_obj = text
        .split("/Dests ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap();
    let start = text.find(&format!("\n{dests_obj} 0 obj\n")).unwrap();
    let body = &text[start..text[start..].find("endobj").unwrap() + start];
    // `/name [page 0 R /XYZ x y 0]`: a name is followed by its array.
    let names: Vec<String> = body
        .split(" /")
        .skip(1)
        .filter_map(|item| {
            let (name, rest) = item.split_once(' ')?;
            rest.starts_with('[').then(|| name.to_owned())
        })
        .collect();
    let links: Vec<String> = text
        .split("/Subtype /Link ")
        .skip(1)
        .map(|item| {
            item.split("/Dest /")
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect();
    (names, links)
}

fn unique(ids: &[String]) -> bool {
    ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
}

#[test]
fn every_entry_gets_an_anchor_of_the_scheme_and_every_ref_resolves() {
    let report = bpfdoor();
    assert_eq!(refs::problems(&report), Vec::<String>::new());
    let processes = report.processes.as_ref().unwrap();
    assert_eq!(processes.data[0].id, "proc-1351");
    assert_eq!(processes.data[1].id, "proc-1352");
    assert_eq!(processes.data[1].parent_ref, "proc-1351");
    let findings = report.findings.as_ref().unwrap();
    assert_eq!(findings.data[0].id, "finding-1");
    assert_eq!(findings.data[0].anchors, ["rule-c2.bpf_backdoor"]);
    assert_eq!(findings.data[0].process_ref, "proc-1352");
    assert_eq!(findings.data[0].attack_refs, ["attack-T1205.002"]);
    let lock = anchor::file("/var/run/xinetd.lock");
    assert_eq!(
        findings.data[2].target_ref, lock,
        "a path object is the file's entry"
    );
    // The file's entry is its File activity record; the tab rows link to it.
    let record = &report.file_activity.as_ref().unwrap()[0];
    assert_eq!(record.id, lock);
    assert_eq!(record.process_ref, "proc-1352");
    let tabs = &report.files.as_ref().unwrap().tabs;
    assert!(
        tabs.iter()
            .flat_map(|t| &t.table.data)
            .all(|d| d.id != lock)
    );
    assert!(
        tabs[0].table.data[0].id == anchor::file("/etc/ld.so.cache"),
        "a file only opened has its Opened files row as entry"
    );
    let network = report.network.as_ref().unwrap();
    assert_eq!(network[0].table.data[0].id, "ep-198.18.0.5-443");
    assert_eq!(
        network[1].table.data[0].id,
        "dom-metadata.ftp-master.debian.org"
    );
    assert_eq!(
        network[1].table.data[0].endpoint_refs,
        ["ep-198.18.0.5-443"]
    );
    assert_eq!(
        network[3].table.data[0].domain_ref,
        "dom-metadata.ftp-master.debian.org"
    );
    let indicators = report.indicators.as_ref().unwrap();
    assert_eq!(indicators[0].id, "ioc-1");
    assert_eq!(indicators[0].target_ref, "ep-203.0.113.9-8443");
    assert_eq!(indicators[0].process_refs, ["proc-1352"]);
    assert_eq!(indicators[2].target_ref, lock);
    let attack = report.attack.as_ref().unwrap();
    assert_eq!(
        attack[1].rule_refs,
        ["rule-evasion.process_rename", "det-sigma-be8e5c8a"]
    );
    let detections = report.detections.as_ref().unwrap();
    assert_eq!(detections[0].id, "det-yara-Linux_Trojan_BPFDoor_f690fe3b");
    assert_eq!(detections[1].attack_refs, ["attack-T1036.005"]);
    let key = &report.summary.as_ref().unwrap().key_findings;
    assert_eq!(key[0].finding_ref, "finding-1");
    assert_eq!(key[0].process_ref, "proc-1352");
    assert_eq!(key[1].target_ref, lock);
}

#[test]
fn an_entry_lists_the_findings_about_it_and_a_process_its_files() {
    let report = bpfdoor();
    let processes = report.processes.as_ref().unwrap();
    assert_eq!(processes.data[0].finding_refs, ["finding-2"]);
    assert_eq!(
        processes.data[1].finding_refs,
        [
            "finding-1",
            "finding-3",
            "finding-4",
            "finding-5",
            "finding-6",
            "finding-7"
        ]
    );
    assert_eq!(
        processes.data[1].file_refs,
        [anchor::file("/var/run/xinetd.lock")]
    );
    let record = &report.file_activity.as_ref().unwrap()[0];
    assert_eq!(record.finding_refs.len(), 5);
    let lock = &report.indicators.as_ref().unwrap()[2];
    assert_eq!(lock.finding_refs.len(), 5, "the file indicator too");
}

#[test]
fn a_ref_to_a_section_that_was_not_chosen_is_dropped_and_link_is_repeatable() {
    let mut report = bpfdoor();
    report.processes = None;
    report.file_activity = None;
    refs::link(&mut report);
    refs::link(&mut report);
    assert_eq!(refs::problems(&report), Vec::<String>::new());
    let findings = report.findings.as_ref().unwrap();
    assert!(findings.data[0].process_ref.is_empty());
    // The Changed files row is the lock file's entry now.
    let tabs = &report.files.as_ref().unwrap().tabs;
    let changed = tabs.iter().find(|t| t.name == "Changed files").unwrap();
    assert_eq!(
        changed.table.data[0].id,
        anchor::file("/var/run/xinetd.lock")
    );
    assert_eq!(findings.data[2].target_ref, changed.table.data[0].id);
}

#[test]
fn the_json_has_key_findings_as_objects_with_refs_and_the_old_sentences() {
    let report = bpfdoor();
    let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(value["schema_version"], 2);
    let key = &value["summary"]["key_findings"][0];
    assert_eq!(key["rule"], "c2.bpf_backdoor");
    assert_eq!(key["pid"], 1352);
    assert_eq!(key["finding_ref"], "finding-1");
    assert_eq!(key["process_ref"], "proc-1352");
    assert!(value["summary"]["key_findings_text"][0].is_string());
    let row = &value["findings"]["data"][0];
    assert_eq!(row["id"], "finding-1");
    assert_eq!(row["relative_ms"], 32);
    assert_eq!(row["pid"], 1352);
    assert!(row.get("domain_ref").is_none(), "empty refs are left out");
    // Every ref of the JSON names an id of the JSON.
    let back: Report = serde_json::from_value(value).unwrap();
    assert_eq!(refs::problems(&back), Vec::<String>::new());
}

#[test]
fn html_anchors_are_unique_and_every_link_resolves() {
    let report = bpfdoor();
    let html = String::from_utf8(export::render(&report, Format::Html, true).unwrap()).unwrap();
    let (ids, links) = html_anchors(&html);
    assert!(unique(&ids), "ids are unique: {ids:?}");
    for link in &links {
        assert!(ids.contains(link), "#{link} resolves");
    }
    for wanted in [
        "proc-1352",
        "finding-1",
        "rule-c2.bpf_backdoor",
        "ep-198.18.0.5-443",
        "dom-metadata.ftp-master.debian.org",
        "attack-T1205.002",
        "det-yara-Linux_Trojan_BPFDoor_f690fe3b",
        "ioc-1",
        "overview-family-evidence",
    ] {
        assert!(ids.contains(&wanted.to_owned()), "{wanted} is an anchor");
        assert!(links.contains(&wanted.to_owned()), "{wanted} is linked to");
    }
    // The key findings are a table that links to the finding and the process.
    assert!(html.contains("<caption>Key findings</caption>"));
    assert!(html.contains("<a href=\"#finding-1\">c2.bpf_backdoor</a>"));
    // The fold: finding-5 is folded into finding-3; the key finding follows
    // it, and keeps its own number (2) instead of the fold row's (3).
    assert!(!ids.contains(&"finding-5".to_owned()));
    assert!(html.contains("<a href=\"#finding-3\">2</a>"), "{html}");
    assert!(html.contains("<a href=\"#finding-1\">1</a>"), "{html}");
    assert!(
        html.contains(">3 (+4)</td>"),
        "the folded row says how many"
    );
    // The opened file is a link to its entry.
    let lock = anchor::file("/var/run/xinetd.lock");
    assert!(html.contains(&format!("<a href=\"#{lock}\">/var/run/xinetd.lock</a>")));
    // The tier counts link to the findings; reserved ranges have no country.
    assert!(html.contains("<a href=\"#findings\">1 HIGH</a>"));
    assert!(html.contains("3 more INFO findings are counted but not listed"));
    assert!(html.contains("<td class=\"nw\">\u{2014}</td>"));
    // Still self-contained.
    assert!(!html.contains("<script") && !html.contains("href=\"http"));
}

#[test]
fn markdown_anchors_are_unique_and_every_link_resolves() {
    let report = bpfdoor();
    let md = String::from_utf8(export::render(&report, Format::Markdown, true).unwrap()).unwrap();
    let (ids, links) = markdown::anchors_and_links(&md);
    assert!(unique(&ids), "{ids:?}");
    assert!(!links.is_empty());
    for link in &links {
        assert!(ids.contains(link), "#{link} resolves in the Markdown");
    }
    assert!(md.contains("<a id=\"proc-1352\"></a>"));
    assert!(md.contains("[c2.bpf\\_backdoor](#finding-1)"), "{md}");
    assert!(md.contains(
        "| # | Tier | Rule | Behaviour | Object | Process | Count | First seen | ATT&CK |"
    ));
}

#[test]
fn pdf_links_go_to_named_destinations_and_it_has_a_contents_block() {
    let report = bpfdoor();
    let pdf = export::render(&report, Format::Pdf, true).unwrap();
    let (dests, links) = pdf_anchors(&pdf);
    assert!(unique(&dests), "{dests:?}");
    assert!(links.len() > 20, "{} links", links.len());
    for link in &links {
        assert!(dests.contains(link), "/{link} is a destination");
    }
    for wanted in [
        "proc-1352",
        "finding-1",
        "overview",
        "files",
        "network",
        "contents",
    ] {
        assert!(dests.contains(&wanted.to_owned()), "{wanted}");
    }
    let text = String::from_utf8_lossy(&pdf);
    assert!(text.contains("/Border [0 0 0]"));
    // The document's own anchors are all destinations of the PDF.
    let document = layout::document(&report, true);
    for id in page::ids(&document) {
        assert!(dests.contains(&id), "{id} drawn as a destination");
    }
}

#[test]
fn every_format_holds_the_linked_report_and_a_bare_one() {
    let linked = bpfdoor();
    let bare = Report::new(
        RunInfo {
            run_id: "c7211dbf".into(),
            finished: true,
            state: "Not started: the Tor route did not become ready in 120 s".into(),
            ..RunInfo::default()
        },
        START,
    );
    for report in [&linked, &bare] {
        for format in Format::ALL {
            let bytes = export::render(report, format, true).unwrap();
            assert!(!bytes.is_empty(), "{format:?}");
        }
        let document = layout::document(report, false);
        let ids = page::ids(&document);
        assert!(unique(&ids));
        for target in page::links(&document) {
            assert!(ids.contains(&target), "{target}");
        }
    }
}

/// With `ANTINOMIE_REPORT_OUT` set, the linked fixture is written in every
/// format there, for a person to look at.
#[test]
fn write_the_linked_fixture_when_asked() {
    let Ok(out) = std::env::var("ANTINOMIE_REPORT_OUT") else {
        return;
    };
    let folder = std::path::Path::new(&out).join("core-fixture-run");
    std::fs::create_dir_all(&folder).unwrap();
    let report = bpfdoor();
    for format in Format::ALL {
        let bytes = export::render(&report, format, true).unwrap();
        std::fs::write(
            folder.join(format!("bpfdoor-shaped{}", format.suffix())),
            bytes,
        )
        .unwrap();
    }
}

/// Every cell of every table of the section `id`, as text, row by row.
fn section_rows(report: &Report, id: &str) -> Vec<Vec<String>> {
    let document = layout::document(report, false);
    let section = document.sections.iter().find(|s| s.id == id).unwrap();
    section
        .blocks
        .iter()
        .filter_map(|block| match block {
            layout::Block::Table(table) => Some(table),
            _ => None,
        })
        .flat_map(|table| &table.rows)
        .map(|row| row.iter().map(|cell| cell.text()).collect())
        .collect()
}

#[test]
fn network_times_are_written_like_the_other_tables() {
    let report = bpfdoor();
    let rows = section_rows(&report, "network");
    let row = rows.iter().find(|r| r[0] == "198.18.0.5:443").unwrap();
    let [.., first, last] = row.as_slice() else {
        panic!("{row:?}")
    };
    assert_eq!(
        *first,
        format!("+5.463 s \u{b7} {}", clock(START + 7_000)),
        "{row:?}"
    );
    assert_eq!(*last, format!("+10.963 s \u{b7} {}", clock(START + 12_500)));
    // A row with no typed time keeps the text the table had.
    let other = rows.iter().find(|r| r[0] == "203.0.113.9:8443").unwrap();
    assert_eq!(other[other.len() - 2], "17:41:00.000 (UTC+7)");
}

#[test]
fn an_indicators_time_is_relative_then_the_time_of_day() {
    let at = START + 3_250;
    assert_eq!(layout::iso_ms(&iso(at)), Some(at));
    assert_eq!(layout::iso_ms("created, deleted"), None);
    assert_eq!(
        layout::indicator_stamp(&iso(at), Some(3_250)),
        format!("+3.250 s \u{b7} {}", clock(at))
    );
    assert_eq!(layout::indicator_stamp(&iso(at), None), clock(at));
    assert_eq!(layout::indicator_stamp("-", Some(1)), "-");
}

#[test]
fn a_child_process_is_indented_under_its_parent() {
    let report = bpfdoor();
    let rows = section_rows(&report, "processes");
    assert!(!rows[0][0].starts_with("+- "), "the root is not indented");
    assert!(
        rows[1][0].starts_with("+- fd1b20ee-elf"),
        "{:?}",
        rows[1][0]
    );
    // Two levels in: a step of no-break spaces first.
    let mut deeper = bpfdoor();
    deeper.processes.as_mut().unwrap().data[1].depth = Some(2);
    let rows = section_rows(&deeper, "processes");
    assert!(
        rows[1][0].starts_with("\u{a0}\u{a0}\u{a0}+- "),
        "{:?}",
        rows[1][0]
    );
}

#[test]
fn the_pdf_contents_lists_every_sub_heading_like_the_bookmarks() {
    use super::layout::{Block, DocTable, Document, Section};
    use super::pdf_layout::{Op, lay_out};
    let section = |id: &str, title: &str, subs: &[(&str, &str)]| Section {
        id: id.into(),
        title: title.into(),
        blocks: subs
            .iter()
            .flat_map(|(sub_id, sub_title)| {
                [
                    Block::Sub {
                        title: (*sub_title).into(),
                        id: (*sub_id).into(),
                    },
                    Block::Table(DocTable::plain(vec!["A".into()], vec![vec!["x".into()]])),
                ]
            })
            .collect(),
    };
    let document = Document {
        title: "t".into(),
        subtitle: "s".into(),
        defanged: false,
        sections: vec![
            section("processes", "Processes", &[("p-tree", "Process tree")]),
            section(
                "indicators",
                "Indicators",
                &[("i-url", "URLs"), ("i-ip", "Addresses")],
            ),
            section("files", "Files", &[("f-w", "Written files")]),
        ],
        meta: Default::default(),
        aliases: Default::default(),
    };
    let laid = lay_out(&document);
    let words: Vec<&str> = laid
        .pages
        .iter()
        .flat_map(|page| &page.ops)
        .filter_map(|op| match op {
            Op::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    for title in ["Process tree", "URLs", "Addresses", "Written files"] {
        // Once in the contents, once as the heading.
        assert_eq!(
            words.iter().filter(|w| **w == title).count(),
            2,
            "{title} in {words:?}"
        );
    }
    let first_page_links: Vec<&str> = laid.pages[0]
        .links
        .iter()
        .map(|l| l.dest.as_str())
        .collect();
    for id in ["p-tree", "i-url", "i-ip", "f-w"] {
        assert!(
            first_page_links.contains(&id),
            "{id} in {first_page_links:?}"
        );
    }
    // The bookmarks hold the same sub-headings.
    for title in ["Process tree", "URLs", "Addresses", "Written files"] {
        assert!(laid.bookmarks.iter().any(|b| b.title == title), "{title}");
    }
}
