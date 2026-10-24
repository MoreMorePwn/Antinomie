// SPDX-License-Identifier: GPL-3.0-only
//! Network routes in the interface: the choice in the Run form and the words
//! for the route a run used. Triage, Run History and the Run form read the
//! same text from here.
use crate::theme;
use antinomie_monitor_core::{
    route::{RouteConfig, RouteKind, RouteRecord, RouteStats, RouteVia},
    ExecRequest, VmNetwork,
};
use eframe::egui::{self, RichText};

/// What a run that has no recorded route reads as.
pub(crate) const NOT_RECORDED: &str = "Not recorded";

/// The words for one run's route. The default is a run with no recorded
/// route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouteText {
    /// One line: the route and where it went, or "Not recorded".
    pub headline: String,
    /// What that route does, and what the gateway counted once the run ended.
    pub detail: String,
    /// The route is one that can let traffic leave this computer.
    pub leaves: bool,
}

impl Default for RouteText {
    fn default() -> Self {
        describe(None, None)
    }
}

/// The text for `route`, with the gateway's counts when they were saved.
pub(crate) fn describe(route: Option<&RouteRecord>, stats: Option<RouteStats>) -> RouteText {
    let Some(route) = route else {
        return RouteText {
            headline: NOT_RECORDED.into(),
            detail: "This run was saved before network routes were recorded.".into(),
            leaves: false,
        };
    };
    let mut detail = match route.via {
        RouteVia::Gateway => route.kind.explain().to_owned(),
        RouteVia::VmNat => "The VM's NAT (QEMU user networking) was in use: the sample could \
                            reach the host's network and the Internet."
            .to_owned(),
        RouteVia::VmIsolated => {
            "The VM's isolated network was in use: nothing left the VM.".to_owned()
        }
        RouteVia::VmDisconnected => "The VM had no network card.".to_owned(),
    };
    let counted = stats.or(route.stats);
    match counted.map(|stats| stats.summary()) {
        Some(summary) if !summary.is_empty() => {
            detail.push_str(&format!(" The gateway counted: {summary}."));
        }
        Some(_) if route.via == RouteVia::Gateway => {
            detail.push_str(" The gateway saw no connections or lookups.");
        }
        None if route.via == RouteVia::Gateway => {
            detail.push_str(" Counts are saved when the run's process tree ends.");
        }
        _ => {}
    }
    RouteText {
        headline: route.label.clone(),
        detail,
        leaves: matches!(
            route.kind,
            RouteKind::Internet | RouteKind::Tor | RouteKind::Vpn | RouteKind::Socks5
        ) && route.via != RouteVia::VmIsolated
            && route.via != RouteVia::VmDisconnected,
    }
}

/// A line "Network route: ..." with the details on hover.
pub(crate) fn line(ui: &mut egui::Ui, text: &RouteText) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Network route").color(theme::muted()));
        let color = if text.headline == NOT_RECORDED {
            theme::muted()
        } else {
            theme::text()
        };
        ui.label(RichText::new(&text.headline).strong().color(color))
            .on_hover_text(&text.detail);
    });
}

/// What the Run form needs to offer a route.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RouteChoice {
    pub network: VmNetwork,
    /// The default route of Settings > Network routes.
    pub default: RouteKind,
    /// A missing setting, per route in [`RouteKind::ALL`] order.
    pub problems: [Option<&'static str>; 6],
}

impl RouteChoice {
    pub fn new(network: VmNetwork, config: &RouteConfig) -> Self {
        let mut problems = [None; 6];
        for (slot, kind) in problems.iter_mut().zip(RouteKind::ALL) {
            *slot = config.setup_problem(kind);
        }
        Self {
            network,
            default: config.default_route,
            problems,
        }
    }

    /// For a Run form that does not know the VM.
    #[cfg(test)]
    pub fn fixed(network: VmNetwork) -> Self {
        Self {
            network,
            default: RouteKind::Drop,
            problems: [None; 6],
        }
    }

    fn problem(&self, kind: RouteKind) -> Option<&'static str> {
        RouteKind::ALL
            .iter()
            .position(|candidate| *candidate == kind)
            .and_then(|index| self.problems[index])
    }
}

/// The route row of the Run form. A Routed VM chooses; any other VM has one
/// fixed network, which the row names.
pub(crate) fn selector(ui: &mut egui::Ui, request: &mut ExecRequest, choice: &RouteChoice) {
    if choice.network != VmNetwork::Routed {
        request.route = None;
        let fixed = RouteRecord::for_network(choice.network);
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Route").color(theme::muted()));
            ui.label(RichText::new(&fixed.label).color(theme::text()));
        })
        .response
        .on_hover_text(
            "This VM's network is fixed. Set its network to Routed to choose Tor, a VPN, \
             InetSim or none for each run.",
        );
        return;
    }
    let mut selected = request.route.unwrap_or(choice.default);
    ui.horizontal(|ui| {
        ui.label("Route");
        egui::ComboBox::from_id_salt("run-route")
            .selected_text(selected.label())
            .show_ui(ui, |ui| {
                for kind in RouteKind::ALL {
                    ui.selectable_value(&mut selected, kind, kind.label());
                }
            });
    });
    request.route = Some(selected);
    ui.add(
        egui::Label::new(
            RichText::new(selected.explain())
                .small()
                .color(theme::muted()),
        )
        .wrap(),
    );
    if let Some(problem) = choice.problem(selected) {
        crate::activity::warning(
            ui,
            format!("{} The run will not start until it is set.", problem),
        );
    }
    if selected == RouteKind::Internet {
        crate::activity::warning(
            ui,
            "Internet: the sample can reach the real Internet from this computer.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::route::RouteVia;

    fn record(kind: RouteKind, via: RouteVia, label: &str) -> RouteRecord {
        RouteRecord {
            kind,
            label: label.into(),
            via,
            checked_ms: None,
            stats: None,
        }
    }

    #[test]
    fn an_old_run_reads_as_not_recorded() {
        let text = describe(None, None);
        assert_eq!(text.headline, NOT_RECORDED);
        assert!(!text.leaves);
        assert!(text.detail.contains("before network routes were recorded"));
    }

    #[test]
    fn a_recorded_route_names_the_route_and_what_the_gateway_counted() {
        let route = record(RouteKind::Tor, RouteVia::Gateway, "Tor via 127.0.0.1:9050");
        let waiting = describe(Some(&route), None);
        assert_eq!(waiting.headline, "Tor via 127.0.0.1:9050");
        assert!(waiting.leaves);
        assert!(waiting
            .detail
            .contains("saved when the run's process tree ends"));
        let stats = RouteStats {
            tcp_connections: 3,
            dns_queries: 5,
            udp_dropped: 2,
            ..RouteStats::default()
        };
        let done = describe(Some(&route), Some(stats));
        assert!(done
            .detail
            .contains("3 TCP connections, 5 DNS queries, 2 UDP dropped"));
        let quiet = describe(Some(&route), Some(RouteStats::default()));
        assert!(quiet.detail.contains("no connections or lookups"));
    }

    #[test]
    fn fixed_networks_and_drop_do_not_claim_to_leave() {
        let nat = RouteRecord::for_network(VmNetwork::Nat);
        assert!(describe(Some(&nat), None).leaves);
        let isolated = RouteRecord::for_network(VmNetwork::Isolated);
        assert!(!describe(Some(&isolated), None).leaves);
        let dropped = record(RouteKind::Drop, RouteVia::Gateway, "None (drop)");
        assert!(!describe(Some(&dropped), None).leaves);
        let inetsim = record(RouteKind::InetSim, RouteVia::Gateway, "InetSim");
        assert!(!describe(Some(&inetsim), None).leaves);
    }

    fn draw(request: &mut ExecRequest, choice: RouteChoice) {
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| selector(ui, request, &choice));
        });
    }

    #[test]
    fn a_fixed_network_clears_any_route_and_a_routed_one_fills_the_default() {
        let mut request = ExecRequest {
            route: Some(RouteKind::Tor),
            ..ExecRequest::default()
        };
        draw(&mut request, RouteChoice::fixed(VmNetwork::Nat));
        assert_eq!(request.route, None);
        let mut routed = ExecRequest::default();
        let config = RouteConfig {
            default_route: RouteKind::InetSim,
            ..RouteConfig::default()
        };
        draw(&mut routed, RouteChoice::new(VmNetwork::Routed, &config));
        assert_eq!(routed.route, Some(RouteKind::InetSim));
        // A route picked earlier stays.
        routed.route = Some(RouteKind::Drop);
        draw(&mut routed, RouteChoice::new(VmNetwork::Routed, &config));
        assert_eq!(routed.route, Some(RouteKind::Drop));
    }

    #[test]
    fn missing_settings_are_known_before_a_run_is_tried() {
        let config = RouteConfig::default();
        let choice = RouteChoice::new(VmNetwork::Routed, &config);
        assert!(choice.problem(RouteKind::Vpn).is_some());
        assert!(choice.problem(RouteKind::Socks5).is_some());
        assert!(choice.problem(RouteKind::Tor).is_none());
        assert!(choice.problem(RouteKind::Drop).is_none());
    }
}
