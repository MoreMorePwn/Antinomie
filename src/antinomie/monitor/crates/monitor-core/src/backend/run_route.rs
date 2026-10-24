// SPDX-License-Identifier: GPL-3.0-only
//! A run's network route on the session: claimed before the run exists,
//! released when its process tree ends or its launch fails.
use super::*;
use crate::{
    api::VmNetwork,
    route::{RouteClaim, RouteConfig},
};

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
            &config,
            run_id,
            requested,
        )
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
        crate::route::release_for_run(
            self.process.gateway.as_ref(),
            &owner.summary.run_id,
            owner.summary.route.as_mut(),
            claim,
        );
        true
    }
}
