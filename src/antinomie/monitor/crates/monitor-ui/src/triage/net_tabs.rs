// SPDX-License-Identifier: GPL-3.0-only
//! The Network section: Endpoints, Domains, URLs and TLS, all read from
//! TShark. The capture is VM-wide, so no row names a process; the IOC column
//! says whether the row's indicator matches a dataset, and the IOC section
//! holds the process, the sources and the evidence.
use super::counts::{tab, Count};
use super::*;
use crate::widgets;

pub(super) use antinomie_triage::net_tabs::*;

impl TriageView {
    pub(super) fn new_count(&self, which: NewTab) -> Count {
        if self.preparing() {
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

    /// The run's packets look stamped in the host zone (see
    /// [`capture_zone_shift`]).
    fn old_capture_shift(&self) -> bool {
        self.scan
            .as_ref()
            .is_some_and(|scan| capture_zone_shift(scan, self.scan_request.clock_anchor))
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
        if self.old_capture_shift() {
            crate::activity::info(
                ui,
                "Capture times of runs recorded before 0.8.2 on a host that is not on UTC may be \
                 shifted by the host's zone offset; this run's packets are about a whole zone \
                 offset away from its start.",
            );
        }
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
                ui.colored_label(theme::muted(), "Network capture was off for this run. Turn on Capture network in Run program to record one.");
            } else if let Some(warning) = self.scan.as_ref().and_then(|s| s.network_warning.clone())
            {
                network_note(ui, warning);
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
            network_note(ui, warning);
        }
        let mut open_ioc = false;
        ui.horizontal_wrapped(|ui| {
            if !hint.is_empty() {
                ui.label(RichText::new(egui_phosphor::regular::INFO).color(theme::muted()))
                    .on_hover_text(hint);
            }
            if self.new_tab == NewTab::Endpoints && antinomie_monitor_core::geoip::attribution_due()
            {
                crate::tools_page::geoip_attribution(ui);
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

/// A pcap index note: lookup and list limits are information; an index that
/// could not be built stays a warning.
fn network_note(ui: &mut egui::Ui, text: impl std::fmt::Display) {
    let text = text.to_string();
    if text.starts_with("Network index unavailable") {
        crate::activity::warning(ui, text);
    } else {
        crate::activity::info(ui, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_notes_are_warnings_only_when_the_index_is_unavailable() {
        let ctx = egui::Context::default();
        let mut journal = crate::activity::Journal::default();
        let _ = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| {
                network_note(
                    ui,
                    "Address lookup limited to 24 public destinations; 3 more were not queried.",
                );
                network_note(ui, "Network index unavailable: broken");
            });
        });
        journal.ingest(&ctx);
        assert_eq!(journal.counts(), (1, 0));
        assert_eq!(journal.messages().len(), 2);
    }
}
