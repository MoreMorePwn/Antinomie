// SPDX-License-Identifier: GPL-3.0-only
//! The Network section: Endpoints, Domains, URLs and TLS, all read from
//! TShark. The capture is VM-wide, so no row names a process; the IOC column
//! says whether the row's indicator matches a dataset, and the IOC section
//! holds the process, the sources and the evidence.
use super::counts::{tab, Count};
use super::*;
use crate::widgets;

pub(super) const ENDPOINT_HEADERS: &[&str] = &[
    "Endpoint",
    "IOC",
    "Proto",
    "Frames",
    "Bytes",
    "Country",
    "Organization",
    "First seen",
    "Last seen",
];
pub(super) const DOMAIN_HEADERS: &[&str] = &[
    "Domain",
    "IOC",
    "Seen as",
    "Resolved / connected IPs",
    "Queries",
    "First seen",
    "Last seen",
    "Rcode",
];
/// The 0.7.0 HTTP columns, with the verdict after the endpoint and the protocol
/// version before the response (the response frame stays in Details).
pub(super) const URL_HEADERS: &[&str] = &[
    "Frame", "Time", "Endpoint", "IOC", "Method", "Host", "URI", "Version", "Response",
];
pub(super) const TLS_HEADERS: &[&str] = &[
    "Frame",
    "Server name",
    "IOC",
    "Endpoint",
    "Version",
    "ALPN",
    "JA3",
    "JA4",
    "JA3S",
    "Cert SHA-1",
    "Sessions",
];

/// The same columns as the scan stores them, before the IOC column is added
/// (a sort is made on the stored rows).
pub(super) const ENDPOINT_STORED: &[&str] = &[
    "Endpoint",
    "Proto",
    "Frames",
    "Bytes",
    "Country",
    "Organization",
    "First seen",
    "Last seen",
];
pub(super) const DOMAIN_STORED: &[&str] = &[
    "Domain",
    "Seen as",
    "Resolved / connected IPs",
    "Queries",
    "First seen",
    "Last seen",
    "Rcode",
];
pub(super) const TLS_STORED: &[&str] = &[
    "Frame",
    "Server name",
    "Endpoint",
    "Version",
    "ALPN",
    "JA3",
    "JA4",
    "JA3S",
    "Cert SHA-1",
    "Sessions",
];

/// The column of the stored HTTP row behind column `shown` of the URLs tab:
/// the verdict and the version are not stored, and sorting by them sorts by
/// the first column.
pub(super) fn stored_url_column(shown: usize) -> usize {
    match shown {
        0..=2 => shown,
        3 | 7 => 0,
        4..=6 => shown - 1,
        _ => 6,
    }
}

/// The column of the stored row behind column `shown` of a rebuilt tab: the
/// IOC column is not stored, and sorting by it sorts by the first column.
pub(super) fn stored_column(slot: usize, shown: usize) -> usize {
    let ioc = if slot == TLS_SLOT { 2 } else { 1 };
    match shown.cmp(&ioc) {
        std::cmp::Ordering::Less => shown,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => shown - 1,
    }
}

impl TriageView {
    fn new_count(&self, which: NewTab) -> Count {
        if self.scan_rx.is_some() {
            return Count::Pending;
        }
        let Some(scan) = &self.scan else {
            return Count::Unavailable;
        };
        if scan.network_counts.is_none() {
            return Count::Unavailable;
        }
        Count::Ready(match which {
            NewTab::Endpoints => {
                scan.new_tabs.endpoints.len() as u64 + scan.new_tabs.endpoints_omitted
            }
            NewTab::Domains => scan.new_tabs.domains.len() as u64 + scan.new_tabs.domains_omitted,
            NewTab::Urls => scan.http.len() as u64 + scan.http_omitted,
            NewTab::Tls => scan.new_tabs.tls.len() as u64 + scan.new_tabs.tls_omitted,
        })
    }

    pub(super) fn new_network(&mut self, ui: &mut egui::Ui, input: &TriageInput<'_>) {
        widgets::tab_row(ui, |ui| {
            for (value, title) in [
                (NewTab::Endpoints, "Endpoints"),
                (NewTab::Domains, "Domains"),
                (NewTab::Urls, "URLs"),
                (NewTab::Tls, "TLS"),
            ] {
                if tab(
                    ui,
                    self.new_tab == value,
                    title,
                    self.new_count(value),
                    false,
                ) {
                    self.new_tab = value;
                }
            }
        });
        let (index, fields, example, hint) = match self.new_tab {
            NewTab::Endpoints => (
                ENDPOINT_SLOT,
                network::ENDPOINT_FIELDS,
                "network.country == US",
                "",
            ),
            NewTab::Domains => (
                DOMAIN_SLOT,
                network::DOMAIN_FIELDS,
                "dns.name contains example",
                "DNS names, TLS server names and HTTP Host headers, merged by name.",
            ),
            NewTab::Urls => (3, HTTP_FIELDS, "http.method == GET", ""),
            NewTab::Tls => (
                TLS_SLOT,
                network::TLS_FIELDS,
                "tls.sni contains example",
                "",
            ),
        };
        let (count, omitted) = self
            .scan
            .as_ref()
            .map_or((0, 0), |scan| match self.new_tab {
                NewTab::Endpoints => (
                    scan.new_tabs.endpoints.len(),
                    scan.new_tabs.endpoints_omitted,
                ),
                NewTab::Domains => (scan.new_tabs.domains.len(), scan.new_tabs.domains_omitted),
                NewTab::Urls => (scan.http.len(), scan.http_omitted),
                NewTab::Tls => (scan.new_tabs.tls.len(), scan.new_tabs.tls_omitted),
            });
        let capture_missing = self
            .scan
            .as_ref()
            .is_some_and(|scan| scan.network_counts.is_none());
        if capture_missing && self.scan_rx.is_none() {
            let off = input.pcap.is_none();
            if off {
                ui.colored_label(theme::muted(), "Network capture was off for this run.");
            } else if let Some(warning) = self.scan.as_ref().and_then(|s| s.network_warning.clone())
            {
                crate::activity::warning(ui, warning);
            }
            return;
        }
        let packets = input.pcap.is_some();
        self.query_bar(
            ui,
            index,
            fields,
            example,
            (count, count as u64 + omitted),
            Bar::Network { packets },
        );
        let Some(scan) = &self.scan else {
            theme::loading_weak(ui, "Indexing this run’s capture…");
            return;
        };
        if let Some(warning) = &scan.network_warning {
            crate::activity::warning(ui, warning);
        }
        let mut open_ioc = false;
        ui.horizontal_wrapped(|ui| {
            if !hint.is_empty() {
                ui.label(RichText::new(egui_phosphor::regular::INFO).color(theme::muted()))
                    .on_hover_text(hint);
            }
            if ui
                .small_button("Open IOC")
                .on_hover_text("Indicators with dataset matches, their process and evidence")
                .clicked()
            {
                open_ioc = true;
            }
        });
        match self.new_tab {
            NewTab::Endpoints => table(
                ui,
                "triage-endpoints",
                ENDPOINT_HEADERS,
                &scan.new_tabs.endpoints,
            ),
            NewTab::Domains => table(ui, "triage-domains", DOMAIN_HEADERS, &scan.new_tabs.domains),
            NewTab::Urls => table(ui, "triage-http", URL_HEADERS, &scan.new_tabs.urls),
            NewTab::Tls => table(ui, "triage-tls", TLS_HEADERS, &scan.new_tabs.tls),
        }
        if open_ioc {
            self.section = Section::Ioc;
        }
    }
}
