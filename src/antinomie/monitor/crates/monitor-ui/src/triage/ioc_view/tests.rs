// SPDX-License-Identifier: GPL-3.0-only
//! The IOC section and the rebuilt Network tabs: a scan of a fixture capture,
//! matched against small fixture datasets served by a mock (no network).
use super::*;
use crate::app::tests::texts;
use antinomie_monitor_core::ioc::indicator::Type;
// The fixture run, datasets and scan are the triage crate's.
use antinomie_triage::ioc_view::fixtures::{find, tshark, Fixture};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 2800.0);

/// The fixture's scan in a Triage view showing `section`.
trait FixtureView {
    fn view(&self, scan: ArchiveScan, section: Section) -> TriageView;
}

impl FixtureView for Fixture {
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
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            events,
            time: Some(time),
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
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
    // Endpoints tab: the row and the chip. The details are in the shared Details pane.
    view.ioc.tab = Tab::Of(Type::Endpoint);
    let text = shown(&settle(&ctx, &mut view));
    assert!(text.contains("93.184.216.34:80"), "{text}");
    assert!(text.contains("Matched"), "{text}");
    assert!(text.contains("Mirai"), "{text}");
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
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            time: Some(1.0),
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
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
fn the_summary_indicators_header_names_the_matches_and_the_tab_counts_the_indicators() {
    if !tshark() {
        return;
    }
    let fixture = Fixture::new(true);
    let scan = fixture.scan(None);
    let mut view = fixture.view(scan, Section::Summary);
    let ctx = context();
    let text = shown(&settle(&ctx, &mut view));
    // The dataset line sits in the Indicators header and opens the IOC view.
    assert!(text.contains("Indicators"), "{text}");
    assert!(
        text.contains("indicators matched (datasets dated ")
            || text.contains("indicator matched (datasets dated "),
        "{text}"
    );
    let (matched, total, date) = view.ioc_headline().unwrap();
    assert!(matched >= 2 && total >= 3, "{matched} of {total}");
    assert_eq!(date.len(), 10);
}
