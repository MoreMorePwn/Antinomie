// SPDX-License-Identifier: GPL-3.0-only
//! A run's network route on the session: claimed before the run exists,
//! released when its process tree ends or its launch fails.
use super::*;
use crate::{
    api::VmNetwork,
    route::{RouteClaim, RouteConfig, RouteStats, RouteVia},
};

/// The route of a run carried over a transport reconnect or a snapshot
/// restore. `held` is the claim's counter baseline when the run held its
/// route at the checkpoint, `None` when it did not.
///
/// * A reconnect keeps the VM process, so its gateway still holds the route
///   under the same run id: the claim is only taken over.
/// * A restored snapshot has a new gateway, on Drop: the route is claimed
///   again for the restored run (`summary.id`), which starts wireproxy or tor
///   and checks it, before the guest runs. On failure the gateway stays on
///   Drop and the error says so for the run's record.
pub(super) fn restored_route(
    options: &BackendOptions,
    vm: &VmConfig,
    gateway: Option<&crate::route::Gateway>,
    summary: &mut RunSummary,
    held: Option<RouteStats>,
    reconnect: bool,
) -> Result<Option<RouteClaim>, String> {
    let Some(route) = summary
        .route
        .clone()
        .filter(|route| route.via == RouteVia::Gateway)
    else {
        return Ok(None);
    };
    let Some(baseline) = held else {
        return Ok(None);
    };
    if reconnect {
        return Ok(Some(RouteClaim { baseline }));
    }
    let network = vm.network();
    let claimed = if network == VmNetwork::Routed {
        crate::route::load_config(&options.data_dir)
    } else {
        Ok(RouteConfig::default())
    }
    .and_then(|config| {
        crate::route::claim_for_run(
            network,
            gateway,
            &options.data_dir,
            &config,
            &summary.id,
            Some(route.kind),
        )
    });
    match claimed {
        Ok((record, claim)) => {
            summary.route = Some(record);
            Ok(claim)
        }
        Err(error) => Err(format!(
            "the run's route \"{}\" could not be brought back after the snapshot restore: \
             {error}; the restored VM's traffic is dropped",
            route.label
        )),
    }
}

impl Session {
    /// Brings up the route of run `run_id`; an error means the run must not
    /// start. A VM that is not Routed has a fixed network and needs no claim.
    pub(super) fn claim_run_route(
        &mut self,
        options: &BackendOptions,
        run_id: &str,
        requested: Option<crate::route::RouteKind>,
    ) -> Result<(crate::route::RouteRecord, Option<RouteClaim>), String> {
        let network = self.vm.network();
        // Only a Routed VM reads the settings, so a damaged settings file
        // cannot stop a run that does not use them.
        let config = if network == VmNetwork::Routed {
            crate::route::load_config(&options.data_dir)?
        } else {
            RouteConfig::default()
        };
        crate::route::claim_for_run(
            network,
            self.process.gateway.as_ref(),
            &options.data_dir,
            &config,
            run_id,
            requested,
        )
    }

    /// Asks the gateway whether the route's program (wireproxy, tor) still
    /// runs. When it stopped, every run holding the route records why, and
    /// the reason is returned for the user (with any save error).
    pub(super) fn check_route_helper(&mut self) -> Option<String> {
        let reason = self.process.gateway.as_ref()?.helper_stopped()?;
        let mut message = reason.clone();
        for owner in self.run_artifacts.values_mut() {
            if owner.route_claim.is_some() {
                owner.issue(reason.clone());
                if let Err(error) = owner.save() {
                    message = format!("{message}; {error}");
                }
            }
        }
        Some(message)
    }

    /// Lets go of a claim whose run never got an owner.
    pub(super) fn release_unowned_route(&mut self, run_id: &str, claim: Option<RouteClaim>) {
        if let Some(claim) = claim {
            crate::route::release_for_run(self.process.gateway.as_ref(), run_id, None, claim);
        }
    }

    /// The run's process tree ended (or its launch failed): the route is
    /// released and the record keeps what the gateway counted.
    pub(super) fn release_run_route(&mut self, owner: &mut RunArtifactOwner) -> bool {
        let Some(claim) = owner.route_claim.take() else {
            return false;
        };
        // A cloud profile's metadata log goes into the run's folder before
        // the next run's claim starts a new one.
        if let Some(gateway) = self.process.gateway.as_ref() {
            // Best effort: a run without the report only lacks the extra
            // findings; the capture and the calls still show the requests.
            let _ = gateway.write_metadata_report(&owner.directory);
        }
        crate::route::release_for_run(
            self.process.gateway.as_ref(),
            &owner.summary.run_id,
            owner.summary.route.as_mut(),
            claim,
        );
        true
    }
}
