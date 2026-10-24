// SPDX-License-Identifier: GPL-3.0-only
//! A run's route: choosing it from the request and the VM's network, bringing
//! it up before the sample starts, and saving what happened when it ends.
//!
//! This is where the route fails closed. A request that cannot be honoured
//! (a route the VM's network cannot carry, a route that is not set up, one
//! that does not answer) is an error and the run does not start. No path
//! here chooses another route than the one asked for.
use super::{Gateway, RouteConfig, RouteKind, RouteRecord, RouteStats, RouteVia};
use crate::api::VmNetwork;
use std::{path::Path, time::Duration};

/// What the route of a run needs to remember while the run lasts.
#[derive(Clone, Copy, Debug)]
pub struct RouteClaim {
    /// The gateway's counters when the run began.
    pub baseline: RouteStats,
}

/// Picks and brings up the route of run `run`.
///
/// * A Routed VM uses `requested`, or the default of the saved settings; the
///   route is claimed on the gateway, which starts what it needs and checks
///   that it is up.
/// * Any other VM has one fixed network. `requested` must be empty or say
///   the same thing as that network.
///
/// The claim is `None` when the VM's network is fixed (nothing to release).
pub fn claim_for_run(
    network: VmNetwork,
    gateway: Option<&Gateway>,
    data_dir: &Path,
    config: &RouteConfig,
    run: &str,
    requested: Option<RouteKind>,
) -> Result<(RouteRecord, Option<RouteClaim>), String> {
    if network != VmNetwork::Routed {
        let record = RouteRecord::for_network(network);
        if let Some(kind) = requested
            && kind != record.kind
        {
            return Err(format!(
                "This VM's network is fixed ({}), so the run cannot use the route \"{}\". \
                 Set the VM's network to Routed to choose a route for each run.",
                record.label,
                kind.label()
            ));
        }
        return Ok((record, None));
    }
    let gateway = gateway.ok_or("this Routed VM has no network gateway; restart the VM")?;
    let kind = requested.unwrap_or(config.default_route);
    let spec = config.spec(data_dir, kind)?;
    let label = spec.label.clone();
    let baseline = gateway.stats();
    let claimed = gateway.claim(run, spec)?;
    Ok((
        RouteRecord {
            kind,
            label,
            via: RouteVia::Gateway,
            checked_ms: Some(claimed.checked_ms),
            stats: None,
        },
        Some(RouteClaim { baseline }),
    ))
}

/// Ends run `run`'s hold on the route: the last run out puts the gateway
/// back on Drop and stops what the route started. The record gets what the
/// gateway counted during the run.
pub fn release_for_run(
    gateway: Option<&Gateway>,
    run: &str,
    record: Option<&mut RouteRecord>,
    claim: RouteClaim,
) {
    let Some(gateway) = gateway else { return };
    let counted = gateway.stats().since(claim.baseline);
    gateway.release(run);
    if let Some(record) = record {
        record.stats = Some(counted);
    }
}

/// The check behind Settings > Network routes > Test: brings `kind` up the
/// way a run would (starting wireproxy for the VPN route, or the own tor for
/// the Tor route) and says whether it answers. Nothing stays running
/// afterwards.
pub fn test_route(
    data_dir: &Path,
    config: &RouteConfig,
    kind: RouteKind,
) -> Result<String, String> {
    let mut spec = config.spec(data_dir, kind)?;
    // wireproxy's log needs a private folder; it is removed with the check.
    let scratch =
        std::env::temp_dir().join(format!("ant-route-test-{}", crate::storage::unique_id()));
    crate::storage::private_dir(&scratch).map_err(|e| e.to_string())?;
    let result = (|| {
        let managed = super::managed::start_for(
            &mut spec,
            &scratch,
            "settings-test",
            (Duration::from_secs(15), super::managed::TOR_WAIT),
        )?;
        super::probe::check(&spec)?;
        drop(managed);
        Ok(format!("{} is up", spec.label))
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    result
}
