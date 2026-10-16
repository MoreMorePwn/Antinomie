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

fn suricata_config(classification: &Path, reference: &Path) -> String {
    let class = serde_json::to_string(classification).unwrap_or_else(|_| "null".into());
    let reference = serde_json::to_string(reference).unwrap_or_else(|_| "null".into());
    format!(
        "%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: \"[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]\"\n    EXTERNAL_NET: \"!$HOME_NET\"\n    HTTP_SERVERS: \"$HOME_NET\"\n    SMTP_SERVERS: \"$HOME_NET\"\n    SQL_SERVERS: \"$HOME_NET\"\n    DNS_SERVERS: \"$HOME_NET\"\n    TELNET_SERVERS: \"$HOME_NET\"\n    AIM_SERVERS: \"$HOME_NET\"\n  port-groups:\n    HTTP_PORTS: \"80\"\n    SHELLCODE_PORTS: \"!80\"\n    ORACLE_PORTS: 1521\n    SSH_PORTS: 22\n    DNP3_PORTS: 20000\n    MODBUS_PORTS: 502\n    FILE_DATA_PORTS: \"$HTTP_PORTS,110,143\"\n    FTP_PORTS: 21\n    SIP_PORTS: \"5060,5061\"\nclassification-file: {class}\nreference-config-file: {reference}\ndefault-rule-path: .\noutputs:\n  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      types:\n        - alert:\n            metadata: yes\n  - stats:\n      enabled: no\nlogging:\n  default-log-level: warning\n  outputs:\n    - console:\n        enabled: yes\nflow:\n  memcap: 64mb\nstream:\n  memcap: 64mb\n  checksum-validation: no\n  reassembly:\n    memcap: 128mb\n    depth: 1mb\napp-layer:\n  protocols:\n    http:\n      enabled: yes\nunix-command:\n  enabled: no\n"
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
    let Some(tool) = super::super::tools::find(&[
        "/usr/bin/suricata",
        "/usr/sbin/suricata",
        "/usr/local/bin/suricata",
    ]) else {
        return Ok(Report::unavailable(
            Engine::Ids,
            staged.request.identity.clone(),
            "Local Suricata is not installed. No packets were evaluated.",
        ));
    };
    let mut report = Report::empty(Engine::Ids, staged.request.identity.clone());
    report.selection = staged.selection.clone();
    let version = super::super::tools::version(tool, &["-V"]);
    let mut rules = Vec::new();
    let mut seen_sids = std::collections::BTreeSet::new();
    let mut classification_bytes = None;
    for source in &staged.ids_sources {
        let data = fs::read(&source.path).map_err(|error| error.to_string())?;
        if data.len() > 32 * 1024 * 1024 {
            return Err("IDS source exceeds 32 MiB".into());
        }
        if source.name.ends_with("classification.config") {
            classification_bytes = Some(data);
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
    if !reference.is_file() {
        fs::write(
            &reference,
            b"config reference: url,https://doc.emergingthreats.net/\n",
        )
        .map_err(|error| error.to_string())?;
    }
    let config = work.join("suricata.yaml");
    let config_text = suricata_config(&classification, &reference);
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
            tool,
            &[
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
            &[],
            remaining,
            64 * 1024,
            true,
        )?;
        for line in result.stdout.lines().filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("error") || lower.contains("unknown rule keyword")
        }) {
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
    report.warnings.push("IDS sees captured plaintext and metadata; encrypted application contents are unavailable. Stream reassembly is capped at 1 MiB. Loaded rule count is not reported by this adapter.".into());
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
        );
        assert!(text.contains("HOME_NET: \"[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]\""));
        assert!(text.contains("EXTERNAL_NET: \"!$HOME_NET\""));
        assert!(!text.contains("HOME_NET: any"));
        assert!(!text.contains("EXTERNAL_NET: any"));
    }
}
