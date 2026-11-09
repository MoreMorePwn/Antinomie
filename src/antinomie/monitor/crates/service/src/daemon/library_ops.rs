// SPDX-License-Identifier: GPL-3.0-only
//! `sample.*`, `vm.list`, `base.list` and `custody.verify` on the socket
//! (design 5.3). The library and the custody chains are read and written
//! through [`crate::library`], the code direct mode runs too, so both return
//! the same objects. `vm.list` and `base.list` answer from the engine's
//! latest snapshot (the lane thread owns the engine, so nothing here waits
//! for it).
//!
//! No path of a client is opened: `sample.add` takes a finished upload
//! (`sample.upload_id`) and refuses `sample.path` on the socket, and
//! `sample.download` reads a range of the archive the library itself names
//! for a SHA-256.

use super::service::{Service, params, to_value};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ops::*,
        status::{BaseSummary, VmSummary},
    },
    library,
    server::{CallContext, Transport},
};
use serde_json::{Value, json};

impl Service {
    /// The library operations. `op` is one of `sample.*` or `custody.verify`.
    pub(super) fn library_op(
        &self,
        op: Op,
        value: Value,
        ctx: &CallContext,
    ) -> Result<Value, ApiError> {
        let actor = &ctx.caller.client_id;
        match op {
            Op::SampleList => {
                let request: SampleListParams = params(value)?;
                library::list(library::open_existing(&self.data_dir)?.as_ref(), &request)
            }
            Op::SampleGet => {
                let request: SampleGetParams = params(value)?;
                library::get(library::open_existing(&self.data_dir)?.as_ref(), &request)
            }
            Op::SampleAdd => self.sample_add(value, ctx),
            Op::SampleDownload => {
                let request: SampleDownloadParams = params(value)?;
                library::download(&self.data_dir, actor, &request)
            }
            Op::SampleTag => {
                let request: SampleTagParams = params(value)?;
                library::set_tags(&self.data_dir, actor, &request)
            }
            Op::CustodyVerify => {
                let request: CustodyVerifyParams = params(value)?;
                library::custody_verify(library::open_existing(&self.data_dir)?.as_ref(), &request)
            }
            _ => Err(ApiError::new(
                ErrorCode::Internal,
                "not a library operation",
            )),
        }
    }

    fn sample_add(&self, value: Value, ctx: &CallContext) -> Result<Value, ApiError> {
        let request: SampleAddParams = params(value)?;
        if request.sample.path.is_some() && ctx.transport == Transport::Socket {
            return Err(ApiError::invalid_argument(
                "sample.path",
                "the daemon does not open files a client names; send the file with upload.begin, upload.put and upload.finish, then pass sample.upload_id",
            ));
        }
        if request.sample.sha256.is_some() || request.sample.path.is_some() {
            return Err(ApiError::invalid_argument(
                "sample",
                "sample.add takes sample.upload_id",
            ));
        }
        let Some(upload) = &request.sample.upload_id else {
            return Err(ApiError::invalid_argument(
                "sample.upload_id",
                "sample.add needs a finished upload",
            ));
        };
        let tags = request
            .tags
            .iter()
            .flatten()
            .map(library::tag_of_api)
            .collect::<Result<Vec<_>, _>>()?;
        let client = &ctx.caller.client_id;
        let (sha256, new) =
            self.intake
                .add_upload(client, upload, request.name.as_deref(), tags, client)?;
        let sha = crate::api::ids::Sha256Hex::try_from(sha256)
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
        let mut sample = library::get(
            library::open_existing(&self.data_dir)?.as_ref(),
            &SampleGetParams {
                sha256: sha,
                origins: None,
                events: None,
                runs: None,
            },
        )?;
        sample["new"] = json!(new);
        Ok(sample)
    }

    /// `vm.list`: the VMs of the engine; a lane's VM carries its lane.
    pub(super) fn vm_list(&self) -> Result<Value, ApiError> {
        let lanes = self.lane_statuses();
        let view = crate::store::lock(&self.view).lanes.clone();
        let vms = view
            .vms
            .iter()
            .map(|vm| VmSummary {
                id: vm.id.clone(),
                name: vm.name.clone(),
                base_identity: vm.base_identity.clone(),
                lane: lanes
                    .iter()
                    .find(|lane| lane.vm_id.as_deref() == Some(vm.id.as_str()))
                    .map(|lane| lane.lane.clone()),
            })
            .collect();
        to_value(&VmList { vms })
    }

    /// `base.list`: the installed bases. While the engine still lists them
    /// the answer is `unavailable` and retryable.
    pub(super) fn base_list(&self) -> Result<Value, ApiError> {
        let view = crate::store::lock(&self.view).lanes.clone();
        if view.bases_checking && view.bases.is_empty() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the installed bases are being listed",
            )
            .retryable(true));
        }
        let bases = view
            .bases
            .iter()
            .map(|base| BaseSummary {
                identity: base.id.clone(),
                name: base.label.clone(),
                architecture: Some(base.arch.label().to_owned()),
            })
            .collect();
        to_value(&BaseList { bases })
    }
}
