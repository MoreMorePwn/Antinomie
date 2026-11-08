// SPDX-License-Identifier: GPL-3.0-only
//! The indicators of a scan of a fixture capture, matched against fixture
//! datasets (moved from the GUI crate's IOC tests).
use super::fixtures::*;
use super::*;
use crate::ioc_scan::Capture;
use antinomie_monitor_core::ioc::{indicator::Source, verdict::OnlineResults};

#[test]
fn a_capture_gives_endpoints_domains_and_urls_with_no_datasets_unchecked() {
    if !tshark() {
        return;
    }
    let fixture = Fixture::new(false);
    let scan = fixture.scan(None);
    let ioc = scan.ioc.clone().unwrap();
    assert_eq!(ioc.capture, Capture::Read);
    let (at, endpoint) = find(&ioc, Type::Endpoint, "93.184.216.34:80");
    assert!(endpoint.sources.contains(&Source::Pcap));
    assert_eq!(endpoint.count, "1 frame");
    assert!(endpoint.process.is_none(), "the capture is VM-wide");
    let (_, domain) = find(&ioc, Type::Domain, "example.com");
    assert_eq!(domain.sub, "HTTP Host");
    let (_, url) = find(&ioc, Type::Url, "GET example.com/");
    assert_eq!(url.sub, "HTTP/1.1");
    // No datasets: nothing is checked, and that is said.
    let verdicts = ioc_scan::verdicts(&ioc, &[], &OnlineResults::default());
    assert!(verdicts.iter().all(|v| v.outcome == Outcome::NotChecked));
    assert_eq!(verdicts[at].why, "no datasets downloaded");
    // The rebuilt tabs hold the same rows, with an IOC column.
    let new = &scan.new_tabs;
    assert_eq!(new.endpoints.len(), 1);
    assert_eq!(new.endpoints[0][0].text, "93.184.216.34:80");
    // No call names the flow: the Source says so.
    assert_eq!(new.endpoints[0][2].text, "Unattributed");
    assert_eq!(new.endpoints[0][3].text, "tcp");
    assert_eq!(new.endpoints[0][1].text, "Not checked");
    assert_eq!(new.domains[0][0].text, "example.com");
    assert_eq!(new.urls.len(), 1);
    assert_eq!(new.urls[0][7].text, "HTTP/1.1");
    assert_eq!(new.urls[0][3].text, "Not checked");
    assert!(scan.findings.iter().all(|f| !f.values.iter().any(
        |(k, v)| *k == "finding.rule" && matches!(v, RowValue::Text(t) if t == "c2.ioc_match")
    )));
}

#[test]
fn a_dataset_match_is_listed_as_a_finding_and_a_known_false_positive_removes_it() {
    if !tshark() {
        return;
    }
    let fixture = Fixture::new(true);
    let scan = fixture.scan(None);
    let ioc = scan.ioc.clone().unwrap();
    assert_eq!(ioc.scan.loaded.len(), 6);
    let verdicts = ioc_scan::verdicts(&ioc, &[], &OnlineResults::default());
    let (at, _) = find(&ioc, Type::Endpoint, "93.184.216.34:80");
    assert_eq!(verdicts[at].outcome, Outcome::Matched);
    assert_eq!(verdicts[at].primary().unwrap().record.family, "Mirai");
    let (url, _) = find(&ioc, Type::Url, "GET example.com/");
    assert_eq!(verdicts[url].primary().unwrap().record.record_id, "3350918");
    let rule = |scan: &ArchiveScan| {
        scan.findings
            .iter()
            .filter(|finding| {
                finding.values.iter().any(|(key, value)| {
                    *key == "finding.rule"
                        && matches!(value, RowValue::Text(t) if t == "c2.ioc_match")
                })
            })
            .count()
    };
    assert_eq!(
        rule(&scan),
        3,
        "the endpoint, its domain and the URL are listed with the detections"
    );
    let listed = scan
        .findings
        .iter()
        .find(|finding| {
            finding.cells[rules::COL_SUMMARY]
                .text
                .contains("93.184.216.34:80")
        })
        .expect("a finding for the endpoint");
    assert!(listed.cells[rules::COL_SUMMARY]
        .text
        .contains("ThreatFox: Mirai"));
    assert!(
        listed.values.iter().any(|(key, _)| *key == "capture.path"),
        "packet evidence"
    );
    // The tabs say Matched.
    assert_eq!(scan.new_tabs.endpoints[0][1].text, "Matched");
    // The same scan again reuses the datasets' answer.
    let again = fixture.scan(Some(ioc.cache.clone()));
    assert!(Arc::ptr_eq(&again.ioc.as_ref().unwrap().scan, &ioc.scan));
    // A known false positive: the row is Known FP and the finding is gone.
    antinomie_monitor_core::known_fp::add(
        &fixture.data,
        antinomie_monitor_core::ioc::Kind::IpPort,
        "93.184.216.34:80",
        None,
        "A test server.",
        1,
    )
    .unwrap();
    let after = fixture.scan(Some(ioc.cache.clone()));
    let ioc = after.ioc.clone().unwrap();
    let known = antinomie_monitor_core::known_fp::load(&fixture.data);
    let verdicts = ioc_scan::verdicts(&ioc, &known, &OnlineResults::default());
    let (at, _) = find(&ioc, Type::Endpoint, "93.184.216.34:80");
    assert_eq!(verdicts[at].outcome, Outcome::KnownFp);
    assert_eq!(after.new_tabs.endpoints[0][1].text, "Known FP");
    assert!(
        !after
            .findings
            .iter()
            .any(|finding| finding.cells[rules::COL_SUMMARY]
                .text
                .contains("93.184.216.34:80")),
        "an excused match is not a finding"
    );
    assert_eq!(rule(&after), 2, "the domain and the URL are left");
}
