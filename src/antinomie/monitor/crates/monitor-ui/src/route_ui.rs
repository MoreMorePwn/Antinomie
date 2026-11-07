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
    /// A fact about the run's network that is no warning, for the Notes of
    /// Triage: the run used the VM's own network and no route.
    pub note: Option<String>,
    /// What the egress filter refused ("Egress filter blocked 3 connections
    /// to port 25"), when it refused anything.
    pub filter: Option<String>,
    /// The run's overall state ("Running · 12:34 elapsed"), shown beside the
    /// route line where the run is known.
    pub run_state: Option<String>,
    /// The run's start and end times, for the tooltip of the state words.
    pub run_state_tip: Option<String>,
    /// The colour of the state words (the run-state palette).
    pub run_state_color: Option<egui::Color32>,
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
            note: None,
            filter: None,
            run_state: None,
            run_state_tip: None,
            run_state_color: None,
        };
    };
    let mut detail = match route.via {
        RouteVia::Gateway => route.kind.explain().to_owned(),
        RouteVia::VmNat => "The VM's NAT (QEMU user networking) was in use: the sample could \
                            reach the host's network and the Internet. A route is chosen per run \
                            only on a Routed VM."
            .to_owned(),
        RouteVia::VmIsolated => {
            "The VM's isolated network was in use: nothing left the VM.".to_owned()
        }
        RouteVia::VmDisconnected => "The VM had no network card.".to_owned(),
    };
    let counted = stats.or(route.stats);
    let filter = counted.and_then(|stats| stats.filter_summary(&route.blocked_ports));
    if let Some(filter) = &filter {
        detail.push_str(&format!(" {filter}."));
    }
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
        note: (route.via == RouteVia::VmNat).then(|| {
            "This run used the VM's NAT, so no route was chosen. To choose a route per run, \
             set the VM's network to Routed and restart the VM to apply the new network."
                .to_owned()
        }),
        detail,
        filter,
        run_state: None,
        run_state_tip: None,
        run_state_color: None,
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
        if let Some(filter) = &text.filter {
            ui.label(RichText::new(filter).color(theme::warn()));
        }
        if let Some(state) = &text.run_state {
            ui.label(RichText::new("·").color(theme::muted()));
            let label = ui.label(
                RichText::new(state)
                    .strong()
                    .color(text.run_state_color.unwrap_or_else(theme::text)),
            );
            if let Some(tip) = &text.run_state_tip {
                label.on_hover_text(tip);
            }
        }
    });
}

/// The Samples window's warning for a VM whose runs can leave the host, or
/// `None` when they cannot. NAT reaches the network and the Internet; a
/// Routed VM reaches the Internet when its default route (Settings > Network
/// routes) is a live one, and the text says which. A run can still choose
/// another route in its form, so it speaks of the default.
pub(crate) fn internet_warning(network: VmNetwork, default: RouteKind) -> Option<String> {
    match network {
        VmNetwork::Nat => Some(
            "NAT is on for this VM: a sample run there can reach your network and the Internet."
                .into(),
        ),
        VmNetwork::Routed => {
            let how = match default {
                RouteKind::Internet => "straight to the real Internet from this computer",
                RouteKind::Tor => "to the Internet through Tor",
                RouteKind::Vpn => "to the Internet through your WireGuard tunnel",
                RouteKind::Socks5 => "to the Internet through your SOCKS5 proxy",
                RouteKind::Drop | RouteKind::InetSim => return None,
            };
            Some(format!(
                "This VM is Routed and its default route is {}: a sample run there can reach \
                 {how}. Choose another route in the run form to keep it off the Internet.",
                default.label()
            ))
        }
        VmNetwork::Isolated | VmNetwork::Disconnected => None,
    }
}

/// What the Run form needs to offer a route.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RouteChoice {
    pub network: VmNetwork,
    /// The default route of Tools > Settings > Network routes.
    pub default: RouteKind,
    /// A missing setting, per route in [`RouteKind::ALL`] order.
    pub problems: [Option<&'static str>; 6],
    /// The cloud provider the VM's device profile imitates; its metadata
    /// service answers on a Routed network whatever the route.
    pub cloud: Option<&'static str>,
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
            cloud: None,
        }
    }

    /// For a Run form that does not know the VM.
    #[cfg(test)]
    pub fn fixed(network: VmNetwork) -> Self {
        Self {
            network,
            default: RouteKind::Drop,
            problems: [None; 6],
            cloud: None,
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
            "This VM's network is fixed while it runs. Stop it, set its network to Routed and \
             start it again to choose Tor, a VPN, InetSim or none for each run.",
        );
        return;
    }
    // The default fills the choice until the person picks a route. A fill
    // that Settings > Network routes has since changed follows the new
    // default, so a saved Tor shows as Tor in the next Run form.
    let filled_id = egui::Id::new("run-route-filled");
    let filled = ui.data(|data| data.get_temp::<RouteKind>(filled_id));
    if request.route.is_none() || (request.route == filled && filled != Some(choice.default)) {
        request.route = Some(choice.default);
        ui.data_mut(|data| data.insert_temp(filled_id, choice.default));
    }
    let mut selected = request.route.unwrap_or(choice.default);
    let before = selected;
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
    if selected != before {
        // Picked by hand: the default no longer replaces it.
        ui.data_mut(|data| data.remove::<RouteKind>(filled_id));
    }
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
        // The route's own settings are in Tools > Settings > Network routes.
        crate::settings_link::button(ui, "Network routes");
    }
    if let Some(provider) = choice.cloud {
        crate::widgets::fact_line(
            ui,
            "Cloud metadata",
            &format!(
                "answered by the simulated {provider} service at 169.254.169.254; it never uses the route"
            ),
        );
    }
    if selected == RouteKind::Internet {
        // A choice the user made, not a fault: a plain note, like "Downloads are off".
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Internet: the sample can reach the real Internet from this computer.",
                )
                .color(theme::muted()),
            )
            .wrap(),
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
            blocked_ports: Vec::new(),
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
        let _ = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| selector(ui, request, &choice));
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
    fn a_default_saved_in_settings_fills_the_next_run_form_unless_a_route_was_picked() {
        let ctx = egui::Context::default();
        let draw = |request: &mut ExecRequest, choice: RouteChoice| {
            let _ = ctx.run_ui(egui::RawInput::default(), |root| {
                egui::CentralPanel::default().show(root, |ui| selector(ui, request, &choice));
            });
        };
        let config = |default_route| RouteConfig {
            default_route,
            ..RouteConfig::default()
        };
        let mut request = ExecRequest::default();
        draw(
            &mut request,
            RouteChoice::new(VmNetwork::Routed, &config(RouteKind::Drop)),
        );
        assert_eq!(request.route, Some(RouteKind::Drop));
        // Settings now says Tor: the form, still holding the old fill, follows.
        draw(
            &mut request,
            RouteChoice::new(VmNetwork::Routed, &config(RouteKind::Tor)),
        );
        assert_eq!(request.route, Some(RouteKind::Tor));
        // A route the person picked is not replaced (marked as picked by hand).
        ctx.data_mut(|data| data.remove::<RouteKind>(egui::Id::new("run-route-filled")));
        request.route = Some(RouteKind::InetSim);
        draw(
            &mut request,
            RouteChoice::new(VmNetwork::Routed, &config(RouteKind::Drop)),
        );
        assert_eq!(request.route, Some(RouteKind::InetSim));
    }

    #[test]
    fn what_the_egress_filter_blocked_is_in_the_route_text_and_hover() {
        let mut tor = record(RouteKind::Tor, RouteVia::Gateway, "Tor");
        tor.stats = Some(RouteStats {
            filter_port: 3,
            tcp_blocked: 3,
            ..RouteStats::default()
        });
        tor.blocked_ports = vec![(25, 3)];
        let text = describe(Some(&tor), None);
        assert_eq!(
            text.filter.as_deref(),
            Some("Egress filter blocked 3 connections to port 25")
        );
        assert!(text
            .detail
            .contains("Egress filter blocked 3 connections to port 25."));
        let ctx = egui::Context::default();
        let output = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| line(ui, &text));
        });
        let shown = crate::app::tests::texts(&output);
        assert!(shown
            .iter()
            .any(|(t, _)| t == "Egress filter blocked 3 connections to port 25"));
        // A run the filter did not touch says nothing about it.
        let quiet = record(RouteKind::Tor, RouteVia::Gateway, "Tor");
        assert_eq!(describe(Some(&quiet), None).filter, None);
    }

    #[test]
    fn the_samples_warning_covers_nat_and_a_routed_vm_with_a_live_default_route() {
        let nat = internet_warning(VmNetwork::Nat, RouteKind::Drop).unwrap();
        assert!(nat.contains("NAT") && nat.contains("Internet"), "{nat}");
        let internet = internet_warning(VmNetwork::Routed, RouteKind::Internet).unwrap();
        assert!(internet.contains("default route is Internet"), "{internet}");
        for (kind, word) in [
            (RouteKind::Tor, "Tor"),
            (RouteKind::Vpn, "WireGuard"),
            (RouteKind::Socks5, "SOCKS5"),
        ] {
            let text = internet_warning(VmNetwork::Routed, kind).unwrap();
            assert!(text.contains(kind.label()) && text.contains(word), "{text}");
        }
        for kind in [RouteKind::Drop, RouteKind::InetSim] {
            assert_eq!(internet_warning(VmNetwork::Routed, kind), None);
        }
        for network in [VmNetwork::Isolated, VmNetwork::Disconnected] {
            assert_eq!(internet_warning(network, RouteKind::Internet), None);
        }
    }

    #[test]
    fn the_internet_route_is_a_plain_note_not_a_warning() {
        let ctx = egui::Context::default();
        let mut request = ExecRequest {
            route: Some(RouteKind::Internet),
            ..ExecRequest::default()
        };
        let choice = RouteChoice::new(VmNetwork::Routed, &RouteConfig::default());
        let output = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| selector(ui, &mut request, &choice));
        });
        let shown = crate::app::tests::texts(&output);
        assert!(shown
            .iter()
            .any(|(text, _)| text.starts_with("Internet: the sample can reach")));
        let mut log = crate::activity::Journal::default();
        log.ingest(&ctx);
        assert_eq!(log.counts(), (0, 0), "{:?}", log.messages());
    }

    #[test]
    fn a_run_on_the_vms_nat_notes_that_no_route_was_chosen_and_how_to_get_one() {
        let nat = RouteRecord::for_network(VmNetwork::Nat);
        let note = describe(Some(&nat), None).note.unwrap();
        assert!(note.contains("restart the VM"), "{note}");
        let tor = record(RouteKind::Tor, RouteVia::Gateway, "Tor");
        assert_eq!(describe(Some(&tor), None).note, None);
    }

    #[test]
    fn a_route_with_a_missing_setting_offers_its_settings_page_and_a_cloud_vm_says_who_answers_metadata(
    ) {
        let ctx = egui::Context::default();
        let mut request = ExecRequest {
            route: Some(RouteKind::Vpn),
            ..ExecRequest::default()
        };
        let mut choice = RouteChoice::new(VmNetwork::Routed, &RouteConfig::default());
        choice.cloud = Some("Hetzner Cloud");
        let output = ctx.run_ui(egui::RawInput::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| selector(ui, &mut request, &choice));
        });
        let shown = crate::app::tests::texts(&output);
        assert!(
            shown
                .iter()
                .any(|(text, _)| text == "Open Network routes settings"),
            "{shown:?}"
        );
        let all: String = shown.iter().map(|(text, _)| text.as_str()).collect();
        assert!(all.contains("Cloud metadata"), "{all}");
        assert!(all.contains("simulated Hetzner Cloud service"), "{all}");
        // The button asks the app to open that page.
        assert_eq!(
            crate::settings_link::take(&ctx),
            None,
            "nothing pressed yet"
        );
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
