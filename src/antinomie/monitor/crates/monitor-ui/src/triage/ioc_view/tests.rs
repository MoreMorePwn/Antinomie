// SPDX-License-Identifier: GPL-3.0-only
//! The IOC section and the rebuilt Network tabs: a scan of a fixture capture,
//! matched against small fixture datasets served by a mock (no network).
use super::*;
use crate::app::tests::texts;
use crate::triage::tests::{http_pcap, write_rwx_calls};
use antinomie_monitor_core::{
    api_keys::Secret,
    ioc::{indicator::Type, update_all, verdict::Outcome},
    ruleset::Fetcher,
};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 1500.0);

// The fixture capture is a GET of http://example.com/ to 93.184.216.34:80.
const THREATFOX: &str = "# \"first_seen_utc\", \"ioc_id\", \"ioc_value\", \"ioc_type\", \"threat_type\", \"fk_malware\", \"malware_alias\", \"malware_printable\", \"last_seen_utc\", \"confidence_level\"\n\"2026-09-02 10:11:12\", \"1831204\", \"93.184.216.34:80\", \"ip:port\", \"botnet_cc\", \"elf.mirai\", \"\", \"Mirai\", \"\", \"75\"\n";
const URLHAUS: &str = "# id,dateadded,url,url_status,last_online,threat,tags\n\"3350918\",\"2026-10-11 08:00:00\",\"http://example.com/\",\"online\",\"\",\"malware_download\",\"mirai,elf\"\n";
const PAYLOADS: &str = "# firstseen,url,filetype,md5,sha256,signature\n\"2026-10-11 08:00:02\",\"http://x.example/a\",\"elf\",\"87221652a79fc3c9b04cde0b335fdd5b\",\"f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa\",\"Mirai\"\n";
const FEODO: &str = "[{\"ip_address\":\"203.0.113.45\",\"port\":443,\"status\":\"online\",\"first_seen\":\"2026-08-01 00:00:00\",\"malware\":\"Dridex\"}]";
const SSLBL_JA3: &str = "# ja3_md5,Firstseen,Lastseen,Listingreason\nf6d64cbcb6dead5e8e864400f056fa32,2026-08-19 10:00:00,2026-10-01 10:00:00,Gafgyt C&C\n";
const SSLBL_CERT: &str = "# Listingdate,SHA1,Listingreason\n2026-08-19 10:00:00,2f22765d04931a078909145ca628d2264c852d7d,Gafgyt C&C\n";

struct Served;

impl Fetcher for Served {
    fn fetch(
        &self,
        url: &str,
        dest: &Path,
        _max: u64,
        _cancel: &AtomicBool,
        _progress: &mut dyn FnMut(u64),
    ) -> Result<(), String> {
        let feed = feeds::FEEDS.iter().find(|feed| feed.owns(url)).unwrap();
        let text = match feed.id {
            "threatfox" => THREATFOX,
            "urlhaus" => URLHAUS,
            "urlhaus-payloads" => PAYLOADS,
            "feodo" => FEODO,
            "sslbl-ja3" => SSLBL_JA3,
            _ => SSLBL_CERT,
        };
        std::fs::write(dest, text).map_err(|error| error.to_string())
    }
}

fn tshark() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

struct Fixture {
    run: PacketSpool,
    data: std::path::PathBuf,
}

impl Fixture {
    fn new(datasets: bool) -> Self {
        let run = PacketSpool::new().unwrap();
        let mut raw = Vec::new();
        write_rwx_calls(&mut raw, 0..1);
        std::fs::write(run.directory.join("telemetry.raw"), raw).unwrap();
        std::fs::write(run.directory.join("fixture.pcap"), http_pcap()).unwrap();
        let data = std::env::temp_dir().join(format!(
            "ant-ioc-triage-{}-{}",
            std::process::id(),
            antinomie_monitor_core::storage::sha256_hex(run.directory.to_string_lossy().as_bytes())
                [..8]
                .to_owned()
        ));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).unwrap();
        if datasets {
            let outcomes = update_all(
                &data,
                &Secret::new("fixture-key"),
                &Served,
                &AtomicBool::new(false),
                &mut |_| {},
            );
            assert!(outcomes.iter().all(|outcome| outcome.result.is_ok()));
        }
        Self { run, data }
    }

    fn scan(&self, cache: Option<ioc_scan::Cache>) -> ArchiveScan {
        let request = ScanRequest {
            root_cookie: 55,
            data_dir: Some(self.data.clone()),
            ioc_cache: cache,
            ..ScanRequest::default()
        };
        scan_archive_query(
            &self.run.directory,
            Some(&self.run.directory.join("fixture.pcap")),
            false,
            &Arc::new(AtomicBool::new(false)),
            &request,
        )
        .unwrap()
    }

    fn view(&self, scan: ArchiveScan, section: Section) -> TriageView {
        let mut view = TriageView::default();
        view.scan = Some(scan);
        view.section = section;
        view.context_key = Some("vm\nboot\nrun\n".into());
        view.ioc.set_data_dir(&self.data);
        view.ioc.reset_run(Some(&self.run.directory));
        view
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

fn draw(
    ctx: &egui::Context,
    view: &mut TriageView,
    pcap: &Path,
    events: Vec<egui::Event>,
    time: f64,
) -> egui::FullOutput {
    let input = TriageInput {
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run"),
        pcap: Some(pcap),
        ..TriageInput::empty()
    };
    ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            events,
            time: Some(time),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(ui, input);
            });
        },
    )
}

fn settle(ctx: &egui::Context, view: &mut TriageView) -> egui::FullOutput {
    let pcap = std::path::PathBuf::from("/nonexistent/capture.pcap");
    let mut out = draw(ctx, view, &pcap, vec![], 0.0);
    for n in 1..4 {
        out = draw(ctx, view, &pcap, vec![], f64::from(n) * 0.02);
    }
    out
}

fn shown(out: &egui::FullOutput) -> String {
    texts(out)
        .into_iter()
        .map(|(text, _)| text)
        .collect::<Vec<_>>()
        .join("\n")
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

fn find<'a>(scan: &'a ioc_scan::IocScan, ty: Type, key: &str) -> (usize, &'a Indicator) {
    scan.indicators
        .iter()
        .enumerate()
        .find(|(_, i)| i.ty == ty && i.key.contains(key))
        .unwrap_or_else(|| {
            panic!(
                "no {ty:?} {key} in {:?}",
                scan.indicators.iter().map(|i| &i.key).collect::<Vec<_>>()
            )
        })
}

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
    assert_eq!(new.endpoints[0][2].text, "tcp");
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

#[test]
fn the_ioc_section_lists_the_tabs_the_verdicts_and_marks_a_false_positive() {
    if !tshark() {
        return;
    }
    let fixture = Fixture::new(true);
    let scan = fixture.scan(None);
    let mut view = fixture.view(scan, Section::Ioc);
    let ctx = context();
    let out = settle(&ctx, &mut view);
    let text = shown(&out);
    for wanted in [
        "Indicators of compromise",
        "Datasets",
        "Online lookups",
        "Summary",
        "Matched indicators",
        "Where the indicators came from",
        "Mirai ×",
    ] {
        assert!(text.contains(wanted), "{wanted:?} missing: {text}");
    }
    // Endpoints tab: the row, the chip and the details.
    view.ioc.tab = Tab::Of(Type::Endpoint);
    let text = shown(&settle(&ctx, &mut view));
    assert!(text.contains("93.184.216.34:80"), "{text}");
    assert!(text.contains("Matched"), "{text}");
    assert!(text.contains("Mirai"), "{text}");
    assert!(text.contains("Mark as false positive"), "{text}");
    assert!(text.contains("unattributed"), "{text}");
    // Marking writes the known false-positive list and asks for a rescan.
    let ioc = view.scan.as_ref().unwrap().ioc.clone().unwrap();
    let (at, indicator) = find(&ioc, Type::Endpoint, "93.184.216.34:80");
    let verdict = view.ioc.verdicts[at].clone();
    view.ioc.reason = "Public test server.".into();
    view.ioc.mark(indicator, &verdict);
    assert!(view.ioc.take_refresh());
    let entries = antinomie_monitor_core::known_fp::load(&fixture.data);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].value, "93.184.216.34:80");
    assert_eq!(entries[0].dataset.as_deref(), Some("threatfox"));
    assert_eq!(entries[0].reason, "Public test server.");
}

#[test]
fn export_writes_csv_and_json_beside_the_run_without_replacing() {
    if !tshark() {
        return;
    }
    let fixture = Fixture::new(true);
    let scan = fixture.scan(None);
    let mut view = fixture.view(scan, Section::Ioc);
    let ioc = view.scan.as_ref().unwrap().ioc.clone().unwrap();
    view.ioc.sync(Some(&ioc));
    let rows: Vec<usize> = (0..ioc.indicators.len())
        .filter(|&at| ioc.indicators[at].ty == Type::Endpoint)
        .collect();
    view.ioc.export(&ioc, Type::Endpoint, &rows, false);
    view.ioc.export(&ioc, Type::Endpoint, &rows, true);
    let folder = fixture.run.directory.join("ioc");
    let mut names: Vec<String> = std::fs::read_dir(&folder)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    let csv = names.iter().find(|name| name.ends_with(".csv")).unwrap();
    let text = std::fs::read_to_string(folder.join(csv)).unwrap();
    assert!(text.starts_with("type,indicator,"));
    assert!(
        text.contains("93.184.216.34:80") && text.contains("Matched") && text.contains("threatfox")
    );
    let json = names.iter().find(|name| name.ends_with(".json")).unwrap();
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(folder.join(json)).unwrap()).unwrap();
    assert_eq!(
        value["indicators"][0]["dataset_date"]
            .as_str()
            .map(str::len),
        Some(10)
    );
}

#[test]
fn the_online_check_is_off_by_default_and_needs_the_key() {
    let fixture = Fixture::new(false);
    let mut view = View::default();
    assert!(!view.online_on, "off in a new session");
    view.set_data_dir(&fixture.data);
    view.start_online(vec![antinomie_monitor_core::ioc::indicator::Lookup {
        kind: antinomie_monitor_core::ioc::Kind::Domain,
        value: "a.example".into(),
    }]);
    let (message, error) = view.status.clone().unwrap();
    assert!(error && message.contains("Auth-Key"), "{message}");
    assert!(view.job.is_none(), "nothing was started or sent");
}

#[test]
fn the_network_section_has_four_tabs_and_no_layout_switch() {
    if !tshark() {
        return;
    }
    let fixture = Fixture::new(true);
    let scan = fixture.scan(None);
    let mut view = fixture.view(scan, Section::Network);
    let ctx = context();
    let out = settle(&ctx, &mut view);
    let text = shown(&out);
    for wanted in [
        "Endpoints",
        "Domains",
        "URLs",
        "TLS",
        "93.184.216.34:80",
        "tcp",
        "Matched",
    ] {
        assert!(text.contains(wanted), "{wanted:?} missing: {text}");
    }
    assert!(!text.contains("Sessions"), "{text}");
    // A saved filter on a 0.7.0 field name still compiles for its table.
    for (fields, filter) in [
        (network::ENDPOINT_FIELDS, "network.country == US"),
        (network::DOMAIN_FIELDS, "dns.name contains example"),
        (HTTP_FIELDS, "http.method == GET"),
        (network::TLS_FIELDS, "session.alpn contains h2"),
    ] {
        let compiled = query::compile_table(filter, fields);
        assert!(compiled.error.is_none(), "{filter}: {:?}", compiled.error);
    }
    // The URL tab.
    view.new_tab = NewTab::Urls;
    let text = shown(&settle(&ctx, &mut view));
    assert!(
        text.contains("GET") && text.contains("example.com") && text.contains("Matched"),
        "{text}"
    );
    // The 0.7.0 layout and its switch are gone: the four tabs are all there is.
    let text = shown(&settle(&ctx, &mut view));
    for wanted in ["Endpoints", "Domains", "URLs", "TLS"] {
        assert!(text.contains(wanted), "{wanted:?} missing: {text}");
    }
    for gone in ["Current layout (0.7.0)", "New layout", "Sessions"] {
        assert!(!text.contains(gone), "{gone:?} present: {text}");
    }
}

#[test]
fn a_run_without_a_capture_says_the_network_tabs_were_skipped() {
    let fixture = Fixture::new(false);
    let mut scan = fixture.scan(None);
    scan.network_counts = None;
    let mut view = fixture.view(scan, Section::Network);
    let ctx = context();
    let out = settle(&ctx, &mut view);
    // The drawing helper passes a pcap; ask without one.
    let _ = out;
    let input = TriageInput {
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run"),
        ..TriageInput::empty()
    };
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            time: Some(1.0),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(ui, input);
            });
        },
    );
    assert!(
        shown(&output).contains("Network capture was off"),
        "{}",
        shown(&output)
    );
}

#[test]
fn the_summary_page_has_an_ioc_card_and_the_tab_counts_the_indicators() {
    if !tshark() {
        return;
    }
    let fixture = Fixture::new(true);
    let scan = fixture.scan(None);
    let mut view = fixture.view(scan, Section::Summary);
    let ctx = context();
    let text = shown(&settle(&ctx, &mut view));
    assert!(text.contains("Indicators (IOC)"), "{text}");
    assert!(
        text.contains("indicators matched") || text.contains("indicator matched"),
        "{text}"
    );
    assert!(text.contains("Open IOC"), "{text}");
    let (matched, total, date) = view.ioc_headline().unwrap();
    assert!(matched >= 2 && total >= 3, "{matched} of {total}");
    assert_eq!(date.len(), 10);
}
