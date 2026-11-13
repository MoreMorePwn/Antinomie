// SPDX-License-Identifier: GPL-3.0-only
//! The checks of `job.submit` in the order of the access specification
//! ("How a submit is checked, in order"), on the run as it will run:
//!
//! 1. the caller may submit at all (`runs.submit`; [`super::submit`]);
//! 2. the policy (the preset of 0.9.0) is offered to the caller, else
//!    `preset_denied`;
//! 3. every value is in its range (`JobSpec::validate_shape`, before this);
//! 4. every risky option has its permission, else `permission_denied` naming
//!    them in `details.needs`;
//! 5. the node has what the run needs, else `unavailable_on_node`;
//! 6. the values are within the limits, else `limit_exceeded`;
//! 7. last, the policy's own ceilings and switches, which presets replace
//!    (card P-A2): a value outside them is `invalid_argument` naming the
//!    field, and nothing is stored.
//!
//! A refusal of steps 2 to 6 becomes a `rejected` job carrying the code, the
//! field and the details; nothing here touches the store. The sample checks
//! (intake) come after these, because intake archives the sample: a refused
//! run adds nothing to the library.

use crate::{
    api::{
        error::ApiError,
        failure::FailureCode,
        ops::{Caller, Permission, Scope},
        spec::{CoreDump, DetectionSelection, JobSpec, Overrides, Route, RunAs, RunAsName, RunIn},
    },
    config::{LoadedPolicy, Policy},
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

/// Why `resolve` refused: a `rejected` job, or a request error (a value
/// outside the policy) that stores nothing.
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

/// A permission a resolved run uses, and the request field that asked for it
/// (`None` for `runs.submit`, which every run uses).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Used {
    pub permission: Permission,
    pub field: Option<&'static str>,
}

/// The permissions a resolved spec uses under `policy`, in the order of the
/// access specification: submit, route, user, core and memory dumps (also
/// those the policy's dump trigger would take), Check online, keep the VM.
/// Prechecks asks the same list again when the run starts.
pub fn permissions_used(spec: &JobSpec, policy: &Policy) -> Vec<Used> {
    let o = &spec.overrides;
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
    if let Some(permission) = route_permission(o.route.unwrap_or(policy.network.route)) {
        add(permission, "overrides.route");
    }
    if o.run_as.as_ref().is_some_and(privileged)
        || (o.run_as.is_none() && policy.run.run_as == RunAsName::Root)
    {
        add(Permission::RunAsRoot, "overrides.run_as");
    }
    let core = match o.core_dump {
        Some(CoreDump::Switch(on)) => on,
        Some(CoreDump::Limits(_)) => true,
        None => policy.evidence.core_dump,
    };
    let trigger = policy.evidence.trigger();
    if core {
        add(Permission::EvidenceCoreDump, "overrides.core_dump");
    }
    if trigger.as_ref().is_some_and(|t| t.core) {
        add(
            Permission::EvidenceCoreDump,
            "policy.evidence.dump_trigger_kind",
        );
    }
    if o.memory_dump.unwrap_or(policy.evidence.memory_dump) {
        add(Permission::EvidenceMemoryDump, "overrides.memory_dump");
    }
    if trigger.as_ref().is_some_and(|t| t.memory) {
        add(
            Permission::EvidenceMemoryDump,
            "policy.evidence.dump_trigger_kind",
        );
    }
    if policy.analysis.online_ioc {
        add(Permission::LookupOnline, "policy.analysis.online_ioc");
    }
    if o.keep_on_failure == Some(true) {
        add(Permission::RunKeepVm, "overrides.keep_on_failure");
    }
    used
}

/// The permission a route needs: none for `drop` and `inet_sim` (nothing
/// leaves the lab), its `route.*` permission for a live route.
pub fn route_permission(route: Route) -> Option<Permission> {
    match route {
        Route::Drop | Route::InetSim => None,
        Route::Internet => Some(Permission::RouteInternet),
        Route::Tor => Some(Permission::RouteTor),
        Route::Vpn => Some(Permission::RouteVpn),
        Route::Socks5 => Some(Permission::RouteSocks5),
    }
}

fn privileged(run_as: &RunAs) -> bool {
    match run_as {
        RunAs::Named(name) => *name == RunAsName::Root,
        RunAs::Ids(ids) => ids.uid < 1000 || ids.gid < 1000,
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

fn limit(field: &str, limit: u64, message: String) -> Refusal {
    Reject::new(FailureCode::LimitExceeded, Some(field), message)
        .detail("field", json!(field))
        .detail("limit", json!(limit))
        .detail("source", json!("policy"))
        .into()
}

fn invalid(field: &str, message: impl Into<String>) -> Refusal {
    Refusal::Invalid(ApiError::invalid_argument(field, message))
}

/// Check `spec` in the documented order and fill in the policy's defaults.
/// The result is the resolved spec a [`Job`](crate::api::job::Job) carries.
pub fn resolve(spec: &JobSpec, caller: &Caller, loaded: &LoadedPolicy) -> Result<JobSpec, Refusal> {
    let policy = &loaded.policy;
    // Is the policy offered to this caller?
    if !loaded.allows(&caller.client_id, Scope::Submit) {
        return Err(Reject::new(
            FailureCode::PresetDenied,
            Some("policy"),
            format!("policy {} is not available to this caller", loaded.name),
        )
        .detail("preset", json!(loaded.name))
        .into());
    }
    let o = &spec.overrides;
    let route = o.route.unwrap_or(policy.network.route);
    let run_as = o.run_as.clone().unwrap_or(RunAs::Named(policy.run.run_as));

    // Does every risky option have its permission?
    let missing: Vec<Used> = permissions_used(spec, policy)
        .into_iter()
        .filter(|u| !caller.has(u.permission))
        .collect();
    if !missing.is_empty() {
        return Err(missing_permissions(&missing).into());
    }

    // Does the node have it? No live route is set up for the service yet,
    // and a kept VM arrives with 0.9.1.
    if route_permission(route).is_some() {
        return Err(Reject::new(
            FailureCode::UnavailableOnNode,
            Some("overrides.route"),
            format!(
                "route {} is not set up on this node; live routes arrive with 0.9.1",
                route_name(route)
            ),
        )
        .detail("what", json!(format!("route.{}", route_name(route))))
        .into());
    }
    if o.keep_on_failure == Some(true) {
        return Err(Reject::new(
            FailureCode::UnavailableOnNode,
            Some("overrides.keep_on_failure"),
            "keeping a VM arrives with 0.9.1",
        )
        .detail("what", json!("keep_vm"))
        .into());
    }

    // Within the limits? Until limits per caller (P-A5) the policy holds them.
    let priority = spec
        .priority
        .unwrap_or_else(|| DEFAULT_PRIORITY.min(policy.limits.priority_max));
    if priority > policy.limits.priority_max {
        return Err(limit(
            "priority",
            u64::from(policy.limits.priority_max),
            format!(
                "priority {priority} is above the limit of {} (policy {})",
                policy.limits.priority_max, loaded.name
            ),
        ));
    }
    if let Some(timeout) = o.timeout_s
        && timeout > policy.run.max_run_s
    {
        return Err(limit(
            "overrides.timeout_s",
            u64::from(policy.run.max_run_s),
            format!(
                "a run of {timeout} s is above the limit of {} s (policy {})",
                policy.run.max_run_s, loaded.name
            ),
        ));
    }

    let (core_dump, detection) = policy_ceilings(o, loaded, route, &run_as)?;
    Ok(JobSpec {
        sample: spec.sample.clone(),
        name: spec.name.clone(),
        policy: Some(loaded.name.clone()),
        priority: Some(priority),
        labels: spec.labels.clone(),
        idempotency_key: spec.idempotency_key.clone(),
        overrides: Overrides {
            timeout_s: Some(o.timeout_s.unwrap_or(policy.run.timeout_s)),
            args: o.args.clone(),
            env: o.env.clone(),
            run_as: Some(run_as),
            run_in: Some(RunIn::AppTerminal),
            route: Some(route),
            network_capture: Some(o.network_capture.unwrap_or(policy.network.capture)),
            memory_dump: Some(o.memory_dump.unwrap_or(policy.evidence.memory_dump)),
            core_dump: Some(core_dump),
            static_checks: Some(
                o.static_checks
                    .clone()
                    .unwrap_or_else(|| policy.analysis.static_checks.clone()),
            ),
            static_time_limit_min: o
                .static_time_limit_min
                .or(policy.analysis.static_time_limit_min),
            detection: Some(detection),
            reports: Some(
                o.reports
                    .clone()
                    .unwrap_or_else(|| policy.report.formats.clone()),
            ),
            report_bundle: Some(o.report_bundle.unwrap_or(policy.report.bundle)),
            report_defang: Some(o.report_defang.unwrap_or(policy.report.defang)),
            keep_on_failure: Some(o.keep_on_failure.unwrap_or(false)),
        },
    })
}

/// The policy's own ceilings and switches, checked after the permissions
/// (presets replace them, card P-A2). A value outside them is
/// `invalid_argument` naming the field. Returns the resolved core dump and
/// detection selection.
fn policy_ceilings(
    o: &Overrides,
    loaded: &LoadedPolicy,
    route: Route,
    run_as: &RunAs,
) -> Result<(CoreDump, DetectionSelection), Refusal> {
    let policy = &loaded.policy;
    if o.args.is_some() && !policy.run.args_allowed {
        return Err(invalid(
            "overrides.args",
            "this policy does not allow program arguments",
        ));
    }
    if o.env.is_some() && !policy.run.env_allowed {
        return Err(invalid(
            "overrides.env",
            "this policy does not allow environment variables",
        ));
    }
    if o.run_as.is_some() && privileged(run_as) && !policy.run.allow_root {
        return Err(invalid(
            "overrides.run_as",
            "root or an id below 1000 needs run.allow_root in the policy",
        ));
    }
    if !policy.network.allowed_routes.contains(&route) {
        return Err(invalid(
            "overrides.route",
            format!(
                "route {} is not allowed by policy {}",
                route_name(route),
                loaded.name
            ),
        ));
    }
    // A switch the policy leaves off cannot be turned on by a job.
    if o.memory_dump == Some(true) && !policy.evidence.memory_dump {
        return Err(invalid(
            "overrides.memory_dump",
            "this policy does not allow memory dumps",
        ));
    }
    let core_dump = match o.core_dump {
        None => CoreDump::Switch(policy.evidence.core_dump),
        Some(CoreDump::Switch(true)) | Some(CoreDump::Limits(_)) if !policy.evidence.core_dump => {
            return Err(invalid(
                "overrides.core_dump",
                "this policy does not allow core dumps",
            ));
        }
        Some(CoreDump::Limits(limits)) if limits.max_mib > policy.evidence.core_max_mib => {
            return Err(invalid(
                "overrides.core_dump",
                format!(
                    "above the policy's core_max_mib of {}",
                    policy.evidence.core_max_mib
                ),
            ));
        }
        Some(asked) => asked,
    };
    let asked = o.detection.unwrap_or_default();
    for (name, want, have) in [
        ("yara", asked.yara, policy.analysis.detection.yara),
        ("sigma", asked.sigma, policy.analysis.detection.sigma),
        ("ids", asked.ids, policy.analysis.detection.ids),
    ] {
        if want == Some(true) && !have {
            return Err(invalid(
                "overrides.detection",
                format!("this policy does not run the {name} engine"),
            ));
        }
    }
    let detection = DetectionSelection {
        yara: asked.yara.or(Some(policy.analysis.detection.yara)),
        sigma: asked.sigma.or(Some(policy.analysis.detection.sigma)),
        ids: asked.ids.or(Some(policy.analysis.detection.ids)),
    };
    Ok((core_dump, detection))
}

fn route_name(route: Route) -> String {
    serde_json::to_value(route)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}
