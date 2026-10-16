// SPDX-License-Identifier: MIT
use super::{
    runner::{Capture, Staged},
    *,
};
use std::{
    io::{BufRead, BufReader, Read},
    time::{Duration, Instant},
};

fn select_ids_rules(
    text: &str,
    seen: &mut std::collections::BTreeSet<String>,
) -> (String, Vec<String>) {
    let mut kept = String::new();
    let mut skipped = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if current.is_empty() && !trimmed.starts_with("alert") && !trimmed.starts_with("drop") {
            continue;
        }
        current.push_str(line);
        current.push('\n');
        if !trimmed.ends_with(')') {
            continue;
        }
        let sid = current
            .split("sid:")
            .nth(1)
            .and_then(|rest| rest.split([';', ',']).next())
            .map(str::trim)
            .unwrap_or("");
        if current.contains("dataset:") {
            skipped.push(format!("sid {sid}: requires an external dataset"));
        } else if current.contains("ja3.") || current.contains("ja3s.") || current.contains("ja4.")
        {
            skipped.push(format!(
                "sid {sid}: requires a TLS fingerprint keyword that this configuration does not enable"
            ));
        } else if sid.is_empty() {
            skipped.push("a rule has no SID and was not loaded".into());
        } else if !seen.insert(sid.to_owned()) {
            skipped.push(format!(
                "sid {sid}: duplicate SID; the later copy was not loaded"
            ));
        } else {
            kept.push_str(&current);
        }
        current.clear();
    }
    (kept, skipped)
}

fn value(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .chars()
        .take(4096)
        .collect()
}

fn alert(event: &serde_json::Value, capture: &Capture, report: &mut Report) {
    if event.get("event_type").and_then(serde_json::Value::as_str) != Some("alert") {
        return;
    }
    let Some(data) = event.get("alert") else {
        return;
    };
    let Some(sid) = data.get("signature_id").and_then(serde_json::Value::as_u64) else {
        return;
    };
    let gid = data
        .get("gid")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let rev = data
        .get("rev")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let key = format!("{gid}:{sid}:{rev}");
    let index = match report
        .findings
        .iter()
        .position(|finding| finding.rule_id == key)
    {
        Some(index) => index,
        None if report.findings.len() < MATCH_LIMIT => {
            let metadata = data.get("metadata").cloned().unwrap_or_default();
            let metadata_text = metadata.to_string();
            let license = metadata
                .get("license")
                .map(|value| value.to_string())
                .unwrap_or_else(|| "Not declared in EVE; see selected rule source".into());
            report.findings.push(Finding {
                rule_id: key,
                title: value(data, "signature"),
                severity: data
                    .get("severity")
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "Unknown".into()),
                source: "Suricata / selected local corpus".into(),
                license: license.chars().take(1024).collect(),
                author: metadata
                    .get("signature_author")
                    .or_else(|| metadata.get("author"))
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                mitre: mitre_references(&metadata_text),
                count: 0,
                evidence: vec![],
                details: format!(
                    "{}; {}:{} → {}:{}; {}",
                    value(data, "category"),
                    value(event, "src_ip"),
                    event.get("src_port").cloned().unwrap_or_default(),
                    value(event, "dest_ip"),
                    event.get("dest_port").cloned().unwrap_or_default(),
                    metadata_text
                )
                .chars()
                .take(8192)
                .collect(),
            });
            report.findings.len() - 1
        }
        None => {
            report.omitted_evidence += 1;
            report.state = State::Partial;
            return;
        }
    };
    let finding = &mut report.findings[index];
    finding.count += 1;
    // Pseudo-packets have no pcap_cnt. Preserve the alert without inventing a frame.
    if let Some(frame) = event
        .get("pcap_cnt")
        .and_then(serde_json::Value::as_u64)
        .filter(|frame| *frame > 0 && *frame <= capture.packets)
    {
        if finding.evidence.len() < 16 {
            finding.evidence.push(Evidence::Packet {
                capture: capture.original.clone(),
                frame,
            });
        } else {
            report.omitted_evidence += 1;
        }
    } else {
        report.omitted_evidence += 1;
    }
}

fn read_eve(path: &Path, capture: &Capture, report: &mut Report) -> Result<(), String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    if file.metadata().map_err(|error| error.to_string())?.len() > 128 * 1024 * 1024 {
        return Err("EVE output exceeds 128 MiB".into());
    }
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    for _ in 0..1_000_000 {
        line.clear();
        let read = (&mut reader)
            .take(128 * 1024 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Ok(());
        }
        if line.len() > 128 * 1024 {
            return Err("EVE record exceeds 128 KiB".into());
        }
        let event: serde_json::Value = serde_json::from_slice(&line)
            .map_err(|error| format!("invalid EVE record: {error}"))?;
        alert(&event, capture, report);
    }
    Err("EVE output exceeds one million records".into())
}

/// Suricata's reference file is `config reference: <name> <url>` with whitespace.
fn fallback_reference() -> &'static [u8] {
    b"config reference: url https://doc.emergingthreats.net/\n"
}

fn suricata_tool() -> Option<String> {
    if let Ok(path) = std::env::var("ANTINOMIE_SURICATA")
        && std::path::Path::new(&path).is_file()
    {
        return Some(path);
    }
    super::super::tools::find(&[
        "/usr/bin/suricata",
        "/usr/sbin/suricata",
        "/usr/local/bin/suricata",
    ])
    .map(str::to_owned)
}

fn suricata_config(classification: &Path, reference: &Path, threshold: &Path) -> String {
    let class = serde_json::to_string(classification).unwrap_or_else(|_| "null".into());
    let reference = serde_json::to_string(reference).unwrap_or_else(|_| "null".into());
    let threshold = serde_json::to_string(threshold).unwrap_or_else(|_| "null".into());
    format!(
        "%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: \"[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n    HTTP_SERVERS: \"$HOME_NET\"\n    SMTP_SERVERS: \"$HOME_NET\"\n    SQL_SERVERS: \"$HOME_NET\"\n    DNS_SERVERS: \"$HOME_NET\"\n    TELNET_SERVERS: \"$HOME_NET\"\n    AIM_SERVERS: \"$HOME_NET\"\n  port-groups:\n    HTTP_PORTS: \"80\"\n    SHELLCODE_PORTS: \"!80\"\n    ORACLE_PORTS: 1521\n    SSH_PORTS: 22\n    DNP3_PORTS: 20000\n    MODBUS_PORTS: 502\n    FILE_DATA_PORTS: \"$HTTP_PORTS,110,143\"\n    FTP_PORTS: 21\n    SIP_PORTS: \"5060,5061\"\nthreshold-file: {threshold}\nclassification-file: {class}\nreference-config-file: {reference}\ndefault-rule-path: .\noutputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      types:\n        - alert:\n            metadata: yes\n  - stats:\n      enabled: no\nlogging:\n  default-log-level: warning\n  outputs:\n    - console:\n        enabled: yes\nflow:\n  memcap: 64mb\nstream:\n  memcap: 64mb\n  checksum-validation: no\n  reassembly:\n    memcap: 128mb\n    depth: 1mb\napp-layer:\n  protocols:\n    http:\n      enabled: yes\nunix-command:\n  enabled: no\n"
    )
}

pub(super) fn scan(staged: &Staged, work: &Path) -> Result<Report, String> {
    if staged.no_rules || staged.ids_sources.is_empty() && staged.warnings.is_empty() {
        let mut report = Report::empty(Engine::Ids, staged.request.identity.clone());
        report.state = State::NoRules;
        report.selection = staged.selection.clone();
        report.warnings.push("No rules enabled".into());
        return Ok(report);
    }
    let Some(tool) = suricata_tool() else {
        return Ok(Report::unavailable(
            Engine::Ids,
            staged.request.identity.clone(),
            "Local Suricata is not installed. No packets were evaluated.",
        ));
    };
    let libs = std::env::var("ANTINOMIE_SURICATA_LIBS").unwrap_or_default();
    let pair = [("LD_LIBRARY_PATH", libs.as_str())];
    let tool_env: &[(&str, &str)] = if libs.is_empty() { &[] } else { &pair };
    let mut report = Report::empty(Engine::Ids, staged.request.identity.clone());
    report.selection = staged.selection.clone();
    let version = super::super::tools::run_with(
        tool.as_str(),
        &["-V"],
        tool_env,
        Duration::from_secs(20),
        4096,
        true,
    )
    .map(|run| {
        run.stderr
            .lines()
            .chain(run.stdout.lines())
            .find(|line| !line.is_empty())
            .unwrap_or("suricata")
            .to_owned()
    })
    .unwrap_or_else(|_| "suricata".into());
    let mut rules = Vec::new();
    let mut seen_sids = std::collections::BTreeSet::new();
    let mut classification_bytes = None;
    let mut reference_bytes = None;
    for source in &staged.ids_sources {
        let data = fs::read(&source.path).map_err(|error| error.to_string())?;
        if data.len() > 32 * 1024 * 1024 {
            return Err("IDS source exceeds 32 MiB".into());
        }
        if source.name.ends_with("classification.config") {
            classification_bytes = Some(data);
            continue;
        }
        if source.name.ends_with("reference.config") {
            reference_bytes = Some(data);
            continue;
        }
        let text = String::from_utf8_lossy(&data);
        let (kept, skipped) = select_ids_rules(&text, &mut seen_sids);
        report.skipped.extend(skipped);
        rules.extend_from_slice(kept.as_bytes());
        report.sources.push(Source {
            name: source.name.clone(),
            version: version.clone(),
            license: "User-selected; per-rule and pack terms. Historical Antinomie IDS sources stay labeled as recorded.".into(),
            sha256: source.sha256.clone(),
            data: "VM-wide owned PCAP segments. Suricata decodes the capture; the HTTP/DNS table is not the input. Packet evidence is not process attribution.".into(),
        });
    }
    report.skipped_rules = report.skipped.len() as u64;
    if rules.is_empty() {
        report.state = State::Unavailable;
        report
            .warnings
            .push("No compatible IDS rules were evaluated.".into());
        return Ok(report);
    }
    report.source_digest = Some(crate::storage::sha256_hex(&rules));
    let rule_path = work.join("combined.rules");
    fs::write(&rule_path, rules).map_err(|error| error.to_string())?;
    let classification = work.join("classification.config");
    fs::write(
        &classification,
        classification_bytes
            .unwrap_or_else(|| b"config classification: misc-activity,Misc activity,3\n".to_vec()),
    )
    .map_err(|error| error.to_string())?;
    let reference = work.join("reference.config");
    fs::write(
        &reference,
        reference_bytes.unwrap_or_else(|| fallback_reference().to_vec()),
    )
    .map_err(|error| error.to_string())?;
    let threshold = work.join("threshold.config");
    fs::write(&threshold, b"# no local thresholds\n").map_err(|error| error.to_string())?;
    let config = work.join("suricata.yaml");
    let config_text = suricata_config(&classification, &reference, &threshold);
    report.warnings.push(
        "HOME_NET is the private address ranges because this scan has no recorded guest address set. Rules that negate those groups can load; matches are limited to that assumption. VM-wide PCAP is not process attribution.".into(),
    );
    fs::write(&config, config_text).map_err(|error| error.to_string())?;
    if staged.captures.is_empty() {
        report.state = State::Missing;
        report.warnings.push(
            "Evidence missing: no saved run-owned PCAP segment. This is not a clean result.".into(),
        );
        return Ok(report);
    }
    let deadline = Instant::now() + Duration::from_secs(100);
    let mut successful = 0;
    for (index, capture) in staged.captures.iter().enumerate() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            report.state = State::Partial;
            report
                .warnings
                .push("IDS scan reached its 100 second budget".into());
            break;
        };
        let output = work.join(format!("ids-{index}"));
        crate::storage::private_dir(&output).map_err(|error| error.to_string())?;
        let strings = [&config, &capture.path, &rule_path, &output]
            .map(|path| path.to_str().ok_or("IDS path is not UTF-8"))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let result = super::super::tools::run_with(
            tool.as_str(),
            &[
                "-v",
                "-c",
                strings[0],
                "-r",
                strings[1],
                "-S",
                strings[2],
                "-l",
                strings[3],
                "--runmode",
                "single",
                "-k",
                "none",
            ],
            tool_env,
            remaining,
            1024 * 1024,
            true,
        )?;
        if let Some(line) = result
            .stderr
            .lines()
            .chain(result.stdout.lines())
            .find(|line| line.contains("rules successfully loaded"))
        {
            report
                .warnings
                .push(format!("Suricata reported: {}", line.trim()));
        }
        for line in result
            .stderr
            .lines()
            .chain(result.stdout.lines())
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                (lower.contains("error") || lower.contains("unknown rule keyword"))
                    && !lower.contains("rules successfully loaded")
            })
        {
            if report.skipped.len() < 200 {
                report.skipped.push(line.chars().take(300).collect());
            }
        }
        if !result.success || result.timed_out {
            report.state = State::Partial;
            report.warnings.push(format!(
                "Segment {}: Suricata failed or timed out; alerts are partial. {}",
                index + 1,
                result.stdout.chars().take(1024).collect::<String>()
            ));
        } else {
            successful += 1;
            report.scanned_objects += capture.packets;
        }
        if !capture.complete {
            report.state = State::Partial;
        }
        if let Err(error) = read_eve(&output.join("eve.json"), capture, &mut report) {
            report.state = State::Partial;
            report
                .warnings
                .push(format!("Segment {}: {error}", index + 1));
        }
        // Bound peak scratch across segments; structured evidence and the
        // bounded worker log survive outside this directory.
        if let Err(error) = fs::remove_dir_all(&output) {
            report.state = State::Partial;
            report
                .warnings
                .push(format!("IDS segment cleanup failed: {error}"));
            break;
        }
        if report.warnings.len() >= 256 {
            report.state = State::Partial;
            break;
        }
    }
    if successful == 0 {
        report.state = State::Unavailable;
    }
    if staged.captures.len() > 1 {
        report.warnings.push("Each capture segment is evaluated independently; streams crossing snapshot boundaries cannot be reassembled across segments.".into());
        report.state = if report.state == State::Unavailable {
            State::Unavailable
        } else {
            State::Partial
        };
    }
    report.warnings.push("IDS sees captured plaintext and metadata; encrypted application contents are unavailable. Stream reassembly is capped at 1 MiB. VM-wide PCAP is not process attribution.".into());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_frame_in_different_segments_has_distinct_evidence_and_pseudo_packets_stay_unlocated() {
        let mut report = Report::empty(
            Engine::Ids,
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        );
        let mut capture = Capture {
            path: "/snapshot".into(),
            original: "/first.pcap".into(),
            complete: true,
            packets: 10,
        };
        let event = serde_json::json!({"event_type":"alert","pcap_cnt":2,"alert":{"signature_id":99,"signature":"test","metadata":{"mitre_technique_id":["T1105"]}}});
        alert(&event, &capture, &mut report);
        capture.original = "/second.pcap".into();
        alert(&event, &capture, &mut report);
        assert_eq!(report.findings[0].count, 2);
        assert_ne!(
            report.findings[0].evidence[0],
            report.findings[0].evidence[1]
        );
        assert_eq!(report.findings[0].mitre, vec!["T1105"]);
        let mut pseudo = event;
        pseudo.as_object_mut().unwrap().remove("pcap_cnt");
        alert(&pseudo, &capture, &mut report);
        assert_eq!(report.findings[0].count, 3);
        assert_eq!(report.findings[0].evidence.len(), 2);
        assert_eq!(report.omitted_evidence, 1);
    }

    #[test]
    fn home_net_is_a_private_range_not_any() {
        let text = suricata_config(
            Path::new("classification.config"),
            Path::new("reference.config"),
            Path::new("threshold.config"),
        );
        assert!(text.contains("threshold-file:"));
        assert!(!text.contains("/etc/suricata"));
        assert!(text.contains("HOME_NET: \"[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]\""));
        assert!(text.contains("EXTERNAL_NET: \"!$HOME_NET\""));
        assert!(!text.contains("HOME_NET: any"));
        assert!(!text.contains("EXTERNAL_NET: any"));
    }

    #[test]
    fn reference_fallback_separates_the_name_and_url() {
        let text = std::str::from_utf8(fallback_reference()).unwrap();
        assert!(text.starts_with("config reference: "));
        assert!(!text.contains(','));
        let mut parts = text.split_whitespace();
        assert_eq!(parts.next(), Some("config"));
        assert_eq!(parts.next(), Some("reference:"));
        let name = parts.next().unwrap();
        let url = parts.next().unwrap();
        assert!(!name.is_empty() && !url.is_empty());
        assert!(url.starts_with("https://"));
        assert_eq!(parts.next(), None);
    }

    /// Loads the selected Emerging Threats tree with the Suricata named by
    /// `ANTINOMIE_SURICATA`. A missing variable is not an engine result.
    #[test]
    fn emerging_threats_pack_loads_and_reads_a_pcap() {
        let Ok(tool) = std::env::var("ANTINOMIE_SURICATA") else {
            eprintln!("emerging_threats_pack_loads_and_reads_a_pcap: ANTINOMIE_SURICATA unset");
            return;
        };
        let Ok(rules_root) = std::env::var("ANTINOMIE_ET_RULES") else {
            eprintln!("emerging_threats_pack_loads_and_reads_a_pcap: ANTINOMIE_ET_RULES unset");
            return;
        };
        let libs = std::env::var("ANTINOMIE_SURICATA_LIBS").unwrap_or_default();
        let root = PathBuf::from(rules_root);
        let mut seen = std::collections::BTreeSet::new();
        let mut rules = Vec::new();
        let mut skipped = Vec::new();
        let mut classification = None;
        let mut reference = None;
        let mut files = Vec::new();
        collect_rule_files(&root, &mut files);
        for path in files {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let data = fs::read(&path).unwrap();
            if name == "classification.config" {
                classification = Some(data);
                continue;
            }
            if name == "reference.config" {
                reference = Some(data);
                continue;
            }
            if !name.ends_with(".rules") {
                continue;
            }
            let text = String::from_utf8_lossy(&data);
            let (kept, rejected) = select_ids_rules(&text, &mut seen);
            skipped.extend(rejected);
            rules.extend_from_slice(kept.as_bytes());
        }
        let dataset = skipped
            .iter()
            .filter(|line| line.contains("dataset"))
            .count();
        let fingerprints = skipped
            .iter()
            .filter(|line| line.contains("fingerprint"))
            .count();
        let duplicates = skipped
            .iter()
            .filter(|line| line.contains("duplicate"))
            .count();
        assert!(!rules.is_empty(), "the pack emitted no rules");
        let work = std::env::temp_dir().join(format!("ant-ids-{}", std::process::id()));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("combined.rules"), &rules).unwrap();
        fs::write(
            work.join("classification.config"),
            classification.unwrap_or_else(|| {
                b"config classification: misc-activity,Misc activity,3\n".to_vec()
            }),
        )
        .unwrap();
        let reference_path = work.join("reference.config");
        fs::write(
            &reference_path,
            reference.unwrap_or_else(|| fallback_reference().to_vec()),
        )
        .unwrap();
        let written = fs::read_to_string(&reference_path).unwrap();
        assert!(
            !written.contains("url,"),
            "reference file still uses a comma"
        );
        let threshold = work.join("threshold.config");
        fs::write(&threshold, b"# no local thresholds\n").unwrap();
        let config = work.join("suricata.yaml");
        fs::write(
            &config,
            suricata_config(
                &work.join("classification.config"),
                &reference_path,
                &threshold,
            ),
        )
        .unwrap();
        let log = work.join("test");
        fs::create_dir_all(&log).unwrap();
        let loaded = suricata_text(
            &tool,
            &libs,
            &[
                "-v",
                "-T",
                "-c",
                config.to_str().unwrap(),
                "-S",
                work.join("combined.rules").to_str().unwrap(),
                "-l",
                log.to_str().unwrap(),
                "-k",
                "none",
            ],
        );
        let summary = loaded
            .lines()
            .find(|line| line.contains("rules successfully loaded"))
            .unwrap_or("no load summary")
            .to_owned();
        eprintln!(
            "selected_sids={} emitted_bytes={} rejected={} dataset={} ja3_ja4={} duplicates={} engine={}",
            seen.len(),
            rules.len(),
            skipped.len(),
            dataset,
            fingerprints,
            duplicates,
            summary.trim()
        );
        assert!(
            loaded.contains("rules successfully loaded"),
            "Suricata did not load the pack:\n{loaded}"
        );
        assert!(
            !loaded.contains("Invalid Reference Config"),
            "reference file was rejected:\n{loaded}"
        );
        let pcap = work.join("one.pcap");
        fs::write(&pcap, minimal_pcap()).unwrap();
        let scan_log = work.join("scan");
        fs::create_dir_all(&scan_log).unwrap();
        let scanned = suricata_text(
            &tool,
            &libs,
            &[
                "-c",
                config.to_str().unwrap(),
                "-r",
                pcap.to_str().unwrap(),
                "-S",
                work.join("combined.rules").to_str().unwrap(),
                "-l",
                scan_log.to_str().unwrap(),
                "--runmode",
                "single",
                "-k",
                "none",
            ],
        );
        assert!(
            !scanned.contains("Invalid Reference Config"),
            "pcap scan rejected the reference file:\n{scanned}"
        );
        assert!(
            scan_log.join("eve.json").is_file(),
            "pcap scan produced no EVE output:\n{scanned}"
        );
        let _ = fs::remove_dir_all(&work);
    }

    /// The production `scan` path, not a direct Suricata command. A missing
    /// tool variable is not an engine result.
    #[test]
    fn production_scan_matches_et_sid_2010371_and_ignores_the_negative_pcap() {
        let Ok(rules_root) = std::env::var("ANTINOMIE_ET_RULES") else {
            eprintln!("production ET scan: ANTINOMIE_ET_RULES unset; not an engine result");
            return;
        };
        if std::env::var_os("ANTINOMIE_SURICATA").is_none() {
            eprintln!("production ET scan: ANTINOMIE_SURICATA unset; not an engine result");
            return;
        }
        let work = std::env::temp_dir().join(format!("ant-ids-scan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work).unwrap();
        let mut files = Vec::new();
        collect_rule_files(Path::new(&rules_root), &mut files);
        let sources = files
            .iter()
            .filter(|path| {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                name.ends_with(".rules")
                    || name == "classification.config"
                    || name == "reference.config"
            })
            .map(|path| super::super::runner::RuleFile {
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                path: path.clone(),
                sha256: "0".repeat(64),
            })
            .collect::<Vec<_>>();
        assert!(sources.len() > 10, "ET pack did not yield rule files");
        let positive = work.join("positive.pcap");
        let negative = work.join("negative.pcap");
        fs::write(&positive, service_scan_pcap()).unwrap();
        fs::write(&negative, minimal_pcap()).unwrap();
        let positive_report = scan_pcap(&work, &sources, &positive, 4);
        let finding = positive_report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "1:2010371:2")
            .unwrap_or_else(|| {
                panic!(
                    "SID 2010371 was not detected: state={:?} warnings={:?} findings={:?}",
                    positive_report.state,
                    positive_report.warnings,
                    positive_report
                        .findings
                        .iter()
                        .map(|finding| finding.rule_id.clone())
                        .take(12)
                        .collect::<Vec<_>>()
                )
            });
        assert!(
            matches!(finding.evidence.first(), Some(Evidence::Packet { frame, .. }) if *frame >= 1),
            "positive alert has no source packet: {:?}",
            finding.evidence
        );
        assert!(
            positive_report
                .warnings
                .iter()
                .any(|warning| warning.contains("rules successfully loaded")),
            "loaded count was not recorded: {:?}",
            positive_report.warnings
        );
        let negative_report = scan_pcap(&work, &sources, &negative, 1);
        assert!(
            negative_report
                .findings
                .iter()
                .all(|finding| finding.rule_id != "1:2010371:2"),
            "negative pcap matched the known SID"
        );
        eprintln!(
            "production ids selected_files={} positive_findings={} loaded={:?} state={:?}",
            sources.len(),
            positive_report.findings.len(),
            positive_report
                .warnings
                .iter()
                .find(|warning| warning.contains("rules successfully loaded")),
            positive_report.state
        );
        let _ = fs::remove_dir_all(&work);
    }

    fn scan_pcap(
        work: &Path,
        sources: &[super::super::runner::RuleFile],
        pcap: &Path,
        packets: u64,
    ) -> Report {
        let identity = Identity {
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            run_id: "run".into(),
            root_cookie: 1,
        };
        let staged = super::super::runner::Staged {
            request: Request {
                engine: Engine::Ids,
                identity: identity.clone(),
                directory: work.to_path_buf(),
                settings: Settings::default(),
                source_digest: None,
                frozen: None,
            },
            sigma_sources: vec![],
            yara_sources: vec![],
            ids_sources: sources.to_vec(),
            captures: vec![super::super::runner::Capture {
                path: pcap.to_path_buf(),
                original: pcap.to_path_buf(),
                complete: true,
                packets,
            }],
            journal: None,
            warnings: vec![],
            selection: "et-test".into(),
            no_rules: false,
            include_dir: None,
        };
        let output = work.join(format!("out-{}", packets));
        fs::create_dir_all(&output).unwrap();
        scan(&staged, &output).unwrap()
    }

    fn service_scan_pcap() -> Vec<u8> {
        let payload = b"service:thc://service:thc";
        let packets = [
            tcp_packet(Tcp {
                src: [1, 2, 3, 4],
                dst: [10, 0, 0, 8],
                sport: 12345,
                dport: 80,
                seq: 1000,
                ack: 0,
                flags: 0x02,
                payload: b"",
            }),
            tcp_packet(Tcp {
                src: [10, 0, 0, 8],
                dst: [1, 2, 3, 4],
                sport: 80,
                dport: 12345,
                seq: 2000,
                ack: 1001,
                flags: 0x12,
                payload: b"",
            }),
            tcp_packet(Tcp {
                src: [1, 2, 3, 4],
                dst: [10, 0, 0, 8],
                sport: 12345,
                dport: 80,
                seq: 1001,
                ack: 2001,
                flags: 0x10,
                payload: b"",
            }),
            tcp_packet(Tcp {
                src: [1, 2, 3, 4],
                dst: [10, 0, 0, 8],
                sport: 12345,
                dport: 80,
                seq: 1001,
                ack: 2001,
                flags: 0x18,
                payload,
            }),
        ];
        let mut bytes = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1,
            0, 0, 0,
        ];
        for packet in packets {
            let len = (packet.len() as u32).to_le_bytes();
            bytes.extend([0, 0, 0, 0, 0, 0, 0, 0]);
            bytes.extend(len);
            bytes.extend(len);
            bytes.extend(packet);
        }
        bytes
    }

    struct Tcp {
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &'static [u8],
    }

    fn tcp_packet(packet: Tcp) -> Vec<u8> {
        let Tcp {
            src,
            dst,
            sport,
            dport,
            seq,
            ack,
            flags,
            payload,
        } = packet;
        let mut packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        ];
        let total = (20 + 20 + payload.len()) as u16;
        let mut ip = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            1,
            0,
            0,
            64,
            6,
            0,
            0,
        ];
        ip.extend(src);
        ip.extend(dst);
        let sum = ip_checksum(&ip);
        ip[10] = (sum >> 8) as u8;
        ip[11] = sum as u8;
        packet.extend(ip);
        packet.extend(sport.to_be_bytes());
        packet.extend(dport.to_be_bytes());
        packet.extend(seq.to_be_bytes());
        packet.extend(ack.to_be_bytes());
        packet.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        packet.extend(payload);
        packet
    }

    fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rule_files(&path, out);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }

    fn suricata_text(tool: &str, libs: &str, args: &[&str]) -> String {
        let mut command = std::process::Command::new(tool);
        command.args(args).env("LC_ALL", "C");
        if !libs.is_empty() {
            command.env("LD_LIBRARY_PATH", libs);
        }
        let output = command.output().expect("suricata did not start");
        let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stdout));
        if !output.status.success() {
            text.push_str(&format!("\nexit: {}", output.status));
        }
        text
    }

    fn minimal_pcap() -> Vec<u8> {
        let mut packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        ];
        let mut ip = vec![
            0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let sum = ip_checksum(&ip);
        ip[10] = (sum >> 8) as u8;
        ip[11] = sum as u8;
        packet.extend(ip);
        packet.extend([
            0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        let mut bytes = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1,
            0, 0, 0,
        ];
        let len = (packet.len() as u32).to_le_bytes();
        bytes.extend([0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend(len);
        bytes.extend(len);
        bytes.extend(packet);
        bytes
    }

    fn ip_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in header.chunks(2) {
            let word = u16::from_be_bytes([pair[0], pair[1]]);
            sum += u32::from(word);
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
