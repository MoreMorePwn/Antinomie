// SPDX-License-Identifier: GPL-3.0-only
//! The checks of `run.submit` in the order of the access specification
//! ("How a submit is checked, in order"), on the run as it will run:
//!
//! 1. the caller may submit at all (`runs.submit`; [`super::submit`]);
//! 2. the request's shape (`RunRequest::validate_shape`);
//! 3. the preset exists, else `preset_denied` ([`super::submit`]; `offered_to`
//!    names roles, and 0.9.0 callers have none, so it locks nothing);
//! 4. the overrides resolve onto the preset (the Custom rule) and every value
//!    is valid, else `invalid_argument` naming the field; a key 0.9.0 reserves
//!    away from its default is `unsupported` ("arrives with 0.9.1");
//! 5. every risky option has its permission, else `permission_denied` naming
//!    them in `details.needs`;
//! 6. the node has what the run needs, else `unavailable_on_node`;
//! 7. the values are within the caller's limits, else `limit_exceeded`.
//!
//! Steps 3 and 4 store nothing; a refusal of steps 5 to 7 becomes a
//! `rejected` job carrying the code, the field and the details. Nothing here
//! touches the store. The sample checks (intake) come after these, because
//! intake archives the sample: a refused run adds nothing to the library.

use crate::{
    api::{
        error::{ApiError, ErrorCode, ErrorReason},
        failure::FailureCode,
        ops::{Caller, Permission},
        spec::{Overrides, Route, RunRequest},
    },
    config::{
        LoadedPreset, Preset,
        preset::changed_options,
        validate::{self, Severity},
    },
};
use serde_json::{Map, Value, json};

/// A spec the service refuses as a `rejected` job: the failure code, the
/// field to blame and the details the code names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    pub code: FailureCode,
    pub message: String,
    pub field: Option<String>,
    pub details: Map<String, Value>,
}

impl Reject {
    pub fn new(code: FailureCode, field: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            field: field.map(str::to_owned),
            details: Map::new(),
        }
    }

    fn detail(mut self, key: &str, value: Value) -> Self {
        self.details.insert(key.to_owned(), value);
        self
    }
}

/// Why `resolve` refused: a `rejected` job, or a request error (a value out
/// of range, a reserved key) that stores nothing.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    Rejected(Reject),
    Invalid(ApiError),
}

impl From<Reject> for Refusal {
    fn from(reject: Reject) -> Self {
        Self::Rejected(reject)
    }
}

pub const DEFAULT_PRIORITY: u8 = 5;

/// A permission a resolved run uses, and the preset key that asks for it
/// (`None` for `runs.submit`, which every run uses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Used {
    pub permission: Permission,
    pub field: Option<&'static str>,
}

/// The permissions the options of `preset` use, in the order of the access
/// specification: submit, route, user, core and memory dumps (also those the
/// dump trigger takes), Check online, keep the VM. Prechecks asks the same
/// list again when the run starts.
pub fn permissions_used(preset: &Preset) -> Vec<Used> {
    let mut used = vec![Used {
        permission: Permission::RunsSubmit,
        field: None,
    }];
    let mut add = |permission, field| {
        if !used.iter().any(|u: &Used| u.permission == permission) {
            used.push(Used {
                permission,
                field: Some(field),
            });
        }
    };
    let network = &preset.network;
    if let Some(permission) = route_permission(&network.route) {
        add(permission, "network.route");
    }
    if network.private_addresses {
        add(Permission::RouteLan, "network.private_addresses");
    }
    if !network.abuse_filter {
        add(Permission::RouteUnfiltered, "network.abuse_filter");
    }
    if preset.program.privileged() {
        add(Permission::RunAsRoot, "program.user");
    }
    let dumps = &preset.dumps;
    let trigger = dumps.trigger();
    if dumps.core_dump_on_exit {
        add(Permission::EvidenceCoreDump, "dumps.core_dump_on_exit");
    }
    if trigger.as_ref().is_some_and(|t| t.core) {
        add(Permission::EvidenceCoreDump, "dumps.trigger_core");
    }
    if dumps.memory_dump_on_exit {
        add(Permission::EvidenceMemoryDump, "dumps.memory_dump_on_exit");
    }
    if trigger.as_ref().is_some_and(|t| t.memory) {
        add(Permission::EvidenceMemoryDump, "dumps.trigger_memory_dump");
    }
    if dumps.disk_dump {
        add(Permission::EvidenceDiskDump, "dumps.disk_dump");
    }
    if preset.detection.check_online {
        add(Permission::LookupOnline, "detection.check_online");
    }
    if preset.vm.keep_on_failure {
        add(Permission::RunKeepVm, "vm.keep_on_failure");
    }
    used
}

/// The permission a route needs: none for `drop` and `inet_sim` (nothing
/// leaves the lab), its `route.*` permission for a live route.
pub fn route_permission(route: &Route) -> Option<Permission> {
    match route {
        Route::Drop | Route::InetSim => None,
        Route::Internet => Some(Permission::RouteInternet),
        Route::Nat => Some(Permission::RouteNat),
        Route::Tor => Some(Permission::RouteTor),
        Route::Vpn(_) => Some(Permission::RouteVpn),
        Route::Socks5(_) => Some(Permission::RouteSocks5),
    }
}

/// `permission_denied` for the `missing` permissions of a run: the message
/// names them, `details.needs` lists their keys, `field` is the first one's.
pub fn missing_permissions(missing: &[Used]) -> Reject {
    let names: Vec<String> = missing
        .iter()
        .map(|u| format!("{} ({})", u.permission.key(), u.permission.name()))
        .collect();
    let needs: Vec<Value> = missing.iter().map(|u| json!(u.permission.key())).collect();
    Reject::new(
        FailureCode::PermissionDenied,
        missing.first().and_then(|u| u.field),
        format!("this run needs the permission {}", names.join(", ")),
    )
    .detail("needs", Value::Array(needs))
}

/// Something the node does not have for a run: the preset key, what is
/// missing (`details.what`) and a sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRefusal {
    pub field: &'static str,
    pub what: String,
    pub message: String,
}

/// What this node lacks for the options of `preset`: no live route is set
/// up for the service before 0.9.1, a kept VM arrives with 0.9.1, and the
/// lane group must be the node's (`[lanes] group`).
pub fn node_refusals(preset: &Preset, lane_group: &str) -> Vec<NodeRefusal> {
    let mut out = Vec::new();
    let route = &preset.network.route;
    if route.is_live() {
        out.push(NodeRefusal {
            field: "network.route",
            what: format!("route.{}", route.kind()),
            message: format!(
                "route {route} is not set up on this node; live routes arrive with 0.9.1"
            ),
        });
    }
    if preset.vm.keep_on_failure {
        out.push(NodeRefusal {
            field: "vm.keep_on_failure",
            what: "keep_vm".into(),
            message: "keeping a VM arrives with 0.9.1".into(),
        });
    }
    if preset.vm.lane_group != lane_group {
        out.push(NodeRefusal {
            field: "vm.lane_group",
            what: format!("lane_group.{}", preset.vm.lane_group),
            message: format!(
                "lane group {} is not set up on this node",
                preset.vm.lane_group
            ),
        });
    }
    out
}

pub(super) fn limit(field: &str, limit: u64, message: String) -> Reject {
    Reject::new(FailureCode::LimitExceeded, Some(field), message)
        .detail("field", json!(field))
        .detail("limit", json!(limit))
        .detail("source", json!("caller"))
}

/// A run as admission settled it: the spec as stored (the preset's name, the
/// priority, the overrides reduced to the keys that changed a value) and the
/// preset it freezes (the named one, or Custom).
#[derive(Clone, Debug, PartialEq)]
pub struct Resolved {
    pub spec: RunRequest,
    pub preset: LoadedPreset,
}

/// Steps 3 to 7 at once: [`settle`], then [`check`].
pub fn resolve(
    spec: &RunRequest,
    caller: &Caller,
    base: &LoadedPreset,
    lane_group: &str,
) -> Result<Resolved, Refusal> {
    let resolved = settle(spec, caller, base).map_err(Refusal::Invalid)?;
    check(&resolved, caller, lane_group)?;
    Ok(resolved)
}

/// Step 4: resolve the overrides of `spec` onto `base` (the Custom rule: any
/// changed value makes the run Custom, based on the preset), check every
/// value and the reserved keys, and fill in the priority. An error stores
/// nothing.
pub fn settle(
    spec: &RunRequest,
    caller: &Caller,
    base: &LoadedPreset,
) -> Result<Resolved, ApiError> {
    let preset = base
        .apply(&spec.overrides.0)
        .map_err(|error| ApiError::invalid_argument(&error.field, error.message))?;
    // A preset was checked when it was loaded; Custom options are checked
    // here.
    let custom = preset.based_on.is_some();
    if let Some(problem) = validate::check_options(&preset.preset)
        .into_iter()
        .find(|p| custom && p.severity == Severity::Error)
    {
        let key = problem.key.unwrap_or_default();
        return Err(ApiError::invalid_argument(
            &format!("overrides.{key}"),
            problem.message,
        ));
    }
    if let Some((key, message)) = validate::reserved(&preset.preset)
        .into_iter()
        .find(|_| custom)
    {
        return Err(
            ApiError::new(ErrorCode::Unsupported, format!("{key}: {message}"))
                .with_field(key)
                .with_reason(ErrorReason::Reserved),
        );
    }
    let priority = spec.priority.unwrap_or_else(|| {
        DEFAULT_PRIORITY.min(caller.limits.priority_max.unwrap_or(DEFAULT_PRIORITY))
    });
    Ok(Resolved {
        spec: RunRequest {
            sample: spec.sample.clone(),
            name: spec.name.clone(),
            preset: Some(base.name.clone()),
            priority: Some(priority),
            labels: spec.labels.clone(),
            idempotency_key: spec.idempotency_key.clone(),
            overrides: Overrides(changed_options(&base.preset, &preset.preset)),
        },
        preset,
    })
}

/// Steps 5 to 7 on a settled run: permissions, the node (`lane_group` is
/// the node's), the caller's limits. A refusal is a `rejected` job.
pub fn check(resolved: &Resolved, caller: &Caller, lane_group: &str) -> Result<(), Reject> {
    let options = &resolved.preset.preset;
    // Does every risky option have its permission?
    let missing: Vec<Used> = permissions_used(options)
        .into_iter()
        .filter(|u| !caller.has(u.permission))
        .collect();
    if !missing.is_empty() {
        return Err(missing_permissions(&missing));
    }

    // Does the node have it?
    if let Some(refusal) = node_refusals(options, lane_group).into_iter().next() {
        return Err(Reject::new(
            FailureCode::UnavailableOnNode,
            Some(refusal.field),
            refusal.message,
        )
        .detail("what", json!(refusal.what)));
    }

    // Within the caller's limits? (Set per caller in service.toml.)
    let limits = &caller.limits;
    let priority = resolved.spec.priority.unwrap_or(DEFAULT_PRIORITY);
    if let Some(most) = limits.priority_max
        && priority > most
    {
        return Err(limit(
            "priority",
            u64::from(most),
            format!("priority {priority} is above the limit of {most}"),
        ));
    }
    if let Some(longest) = limits.max_run_s
        && options.program.run_time_s > longest
    {
        return Err(limit(
            "program.run_time_s",
            u64::from(longest),
            format!(
                "a run of {} s is above the limit of {longest} s",
                options.program.run_time_s
            ),
        ));
    }
    Ok(())
}
