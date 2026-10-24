//! How a run records its route, and how the choice of route is made.
use super::{Rig, config_for, no_data, record_for, socks_server::FakeSocks};
use crate::{
    api::{ExecRequest, RunArtifacts, VmNetwork},
    route::{RouteConfig, RouteKind, RouteStats, RouteVia, claim_for_run, release_for_run},
};

#[test]
fn a_vm_that_is_not_routed_has_one_fixed_network_and_refuses_another() {
    let config = RouteConfig::default();
    for (network, kind, via) in [
        (VmNetwork::Nat, RouteKind::Internet, RouteVia::VmNat),
        (VmNetwork::Isolated, RouteKind::Drop, RouteVia::VmIsolated),
        (
            VmNetwork::Disconnected,
            RouteKind::Drop,
            RouteVia::VmDisconnected,
        ),
    ] {
        let (record, claim) = claim_for_run(network, None, no_data(), &config, "r", None).unwrap();
        assert!(claim.is_none());
        assert_eq!((record.kind, record.via), (kind, via));
        assert!(record.stats.is_none() && record.checked_ms.is_none());
        // Asking for what the network already is is fine.
        claim_for_run(network, None, no_data(), &config, "r", Some(kind)).unwrap();
        // Anything else would be a route the VM cannot carry.
        let other = if kind == RouteKind::Tor {
            RouteKind::Vpn
        } else {
            RouteKind::Tor
        };
        let error = claim_for_run(network, None, no_data(), &config, "r", Some(other)).unwrap_err();
        assert!(
            error.contains("fixed") && error.contains("Routed"),
            "{error}"
        );
    }
}

#[test]
fn a_routed_vm_without_its_gateway_does_not_run_anything() {
    let error = claim_for_run(
        VmNetwork::Routed,
        None,
        no_data(),
        &RouteConfig::default(),
        "r",
        None,
    )
    .unwrap_err();
    assert!(error.contains("no network gateway"), "{error}");
}

#[test]
fn a_routed_run_records_the_route_and_what_the_gateway_counted() {
    let socks = FakeSocks::echo();
    let rig = Rig::new("record");
    let mut config = config_for(&socks);
    config.default_route = RouteKind::Tor;
    // No route asked for: the default of the settings.
    let (mut record, claim) = claim_for_run(
        VmNetwork::Routed,
        Some(&rig.gateway),
        no_data(),
        &config,
        "run1",
        None,
    )
    .unwrap();
    assert_eq!(record.kind, RouteKind::Tor);
    assert_eq!(record.via, RouteVia::Gateway);
    assert_eq!(record.label, format!("Tor via 127.0.0.1:{}", socks.port()));
    assert!(record.checked_ms.is_some_and(|ms| ms > 1_700_000_000_000));
    let claim = claim.unwrap();
    release_for_run(Some(&rig.gateway), "run1", Some(&mut record), claim);
    assert_eq!(record.stats, Some(RouteStats::default()));
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
    // A route asked for wins over the default.
    let (record, claim) = claim_for_run(
        VmNetwork::Routed,
        Some(&rig.gateway),
        no_data(),
        &config,
        "run2",
        Some(RouteKind::InetSim),
    )
    .unwrap();
    assert_eq!(record.kind, RouteKind::InetSim);
    release_for_run(Some(&rig.gateway), "run2", None, claim.unwrap());
}

#[test]
fn a_route_that_cannot_start_is_the_runs_error() {
    let rig = Rig::new("claim-fail");
    let config = RouteConfig::default();
    let error = claim_for_run(
        VmNetwork::Routed,
        Some(&rig.gateway),
        no_data(),
        &config,
        "run1",
        Some(RouteKind::Socks5),
    )
    .unwrap_err();
    assert!(error.contains("SOCKS5"), "{error}");
    assert_eq!(rig.gateway.kind(), RouteKind::Drop);
}

#[test]
fn run_records_round_trip_and_older_files_read_as_not_recorded() {
    let mut record = record_for(RouteKind::Vpn);
    record.label = "VPN (WireGuard via wireproxy, 127.0.0.1:25344)".into();
    record.stats = Some(RouteStats {
        tcp_connections: 4,
        ..RouteStats::default()
    });
    let artifacts = RunArtifacts {
        run_id: "r".into(),
        route: Some(record.clone()),
        ..RunArtifacts::default()
    };
    let json = serde_json::to_string(&artifacts).unwrap();
    assert!(json.contains("\"route\"") && json.contains("\"vpn\""));
    let back: RunArtifacts = serde_json::from_str(&json).unwrap();
    assert_eq!(back.route, Some(record));
    // A run saved by a release that had no routes.
    let old: RunArtifacts = serde_json::from_str(r#"{"run_id":"old","vm_id":"v"}"#).unwrap();
    assert!(old.route.is_none());
    let json = serde_json::to_string(&old).unwrap();
    assert!(!json.contains("route"));
    // The request's route is skipped when unset, so older releases read it.
    assert!(
        !serde_json::to_string(&ExecRequest::default())
            .unwrap()
            .contains("route")
    );
    let request = ExecRequest {
        route: Some(RouteKind::Tor),
        ..ExecRequest::default()
    };
    let back: ExecRequest =
        serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
    assert_eq!(back.route, Some(RouteKind::Tor));
}

#[test]
fn nothing_secret_is_in_a_record() {
    let socks = FakeSocks::echo();
    let rig = Rig::new("secret");
    let mut config = config_for(&socks);
    config.socks5.username = "someone".into();
    config.socks5.password = "hunter2".into();
    // The fake server takes no login; a client that offers one is served.
    let (mut record, claim) = claim_for_run(
        VmNetwork::Routed,
        Some(&rig.gateway),
        no_data(),
        &config,
        "run1",
        Some(RouteKind::Socks5),
    )
    .unwrap();
    release_for_run(
        Some(&rig.gateway),
        "run1",
        Some(&mut record),
        claim.unwrap(),
    );
    let artifacts = RunArtifacts {
        route: Some(record),
        ..RunArtifacts::default()
    };
    let json = serde_json::to_string(&artifacts).unwrap();
    assert!(
        !json.contains("hunter2") && !json.contains("someone"),
        "{json}"
    );
}
