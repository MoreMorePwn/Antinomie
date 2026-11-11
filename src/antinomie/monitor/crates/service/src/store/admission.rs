// SPDX-License-Identifier: GPL-3.0-only
//! The policy checks of `job.submit` (design 4.4, 5.4.1): a spec may override
//! a default only within the policy's ceiling. A failure becomes a `rejected`
//! job with code `policy_denied`; nothing here touches the store.

use crate::{
    api::{
        failure::FailureCode,
        ops::{Caller, Scope},
        spec::{CoreDump, DetectionSelection, JobSpec, Overrides, Route, RunAs, RunAsName, RunIn},
    },
    config::{LoadedPolicy, policy::glob},
};

/// A spec the service refuses: the failure code and the field to blame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    pub code: FailureCode,
    pub message: String,
    pub field: Option<String>,
}

fn denied(field: &str, message: impl Into<String>) -> Reject {
    Reject {
        code: FailureCode::PolicyDenied,
        message: message.into(),
        field: Some(field.to_owned()),
    }
}

pub const DEFAULT_PRIORITY: u8 = 5;

/// Check `spec` against the policy and fill in the policy's defaults. The
/// result is the resolved spec a [`Job`](crate::api::job::Job) carries.
pub fn resolve(spec: &JobSpec, caller: &Caller, loaded: &LoadedPolicy) -> Result<JobSpec, Reject> {
    let policy = &loaded.policy;
    if !loaded.allows(&caller.client_id, Scope::Submit)
        || (!caller.policies.is_empty()
            && !caller
                .policies
                .iter()
                .any(|pattern| glob(pattern, &loaded.name)))
    {
        return Err(denied(
            "policy",
            format!("policy {} is not available to this caller", loaded.name),
        ));
    }
    let o = &spec.overrides;
    let priority = spec
        .priority
        .unwrap_or_else(|| DEFAULT_PRIORITY.min(policy.limits.priority_max));
    if priority > policy.limits.priority_max {
        return Err(denied(
            "priority",
            format!(
                "policy {} allows priority up to {}",
                loaded.name, policy.limits.priority_max
            ),
        ));
    }
    if let Some(timeout) = o.timeout_s
        && timeout > policy.run.max_run_s
    {
        return Err(denied(
            "overrides.timeout_s",
            format!(
                "above the policy's max_run_s of {} seconds",
                policy.run.max_run_s
            ),
        ));
    }
    if o.args.is_some() && !policy.run.args_allowed {
        return Err(denied(
            "overrides.args",
            "this policy does not allow program arguments",
        ));
    }
    if o.env.is_some() && !policy.run.env_allowed {
        return Err(denied(
            "overrides.env",
            "this policy does not allow environment variables",
        ));
    }
    let run_as = match &o.run_as {
        None => RunAs::Named(policy.run.run_as),
        Some(RunAs::Named(RunAsName::User)) => RunAs::Named(RunAsName::User),
        Some(asked) => {
            let privileged = match asked {
                RunAs::Named(name) => *name == RunAsName::Root,
                RunAs::Ids(ids) => ids.uid < 1000 || ids.gid < 1000,
            };
            if privileged && !policy.run.allow_root {
                return Err(denied(
                    "overrides.run_as",
                    "root or an id below 1000 needs run.allow_root in the policy",
                ));
            }
            asked.clone()
        }
    };
    let route = o.route.unwrap_or(policy.network.route);
    if !route.allowed_in_v1() || !policy.network.allowed_routes.contains(&route) {
        return Err(denied(
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
        return Err(denied(
            "overrides.memory_dump",
            "this policy does not allow memory dumps",
        ));
    }
    let core_dump = match o.core_dump {
        None => CoreDump::Switch(policy.evidence.core_dump),
        Some(CoreDump::Switch(true)) | Some(CoreDump::Limits(_)) if !policy.evidence.core_dump => {
            return Err(denied(
                "overrides.core_dump",
                "this policy does not allow core dumps",
            ));
        }
        Some(CoreDump::Limits(limits)) if limits.max_mib > policy.evidence.core_max_mib => {
            return Err(denied(
                "overrides.core_dump",
                format!(
                    "above the policy's core_max_mib of {}",
                    policy.evidence.core_max_mib
                ),
            ));
        }
        Some(asked) => asked,
    };
    let detection = {
        let mine = DetectionSelection {
            yara: Some(policy.analysis.detection.yara),
            sigma: Some(policy.analysis.detection.sigma),
            ids: Some(policy.analysis.detection.ids),
        };
        let asked = o.detection.unwrap_or_default();
        for (name, want, have) in [
            ("yara", asked.yara, policy.analysis.detection.yara),
            ("sigma", asked.sigma, policy.analysis.detection.sigma),
            ("ids", asked.ids, policy.analysis.detection.ids),
        ] {
            if want == Some(true) && !have {
                return Err(denied(
                    "overrides.detection",
                    format!("this policy does not run the {name} engine"),
                ));
            }
        }
        DetectionSelection {
            yara: asked.yara.or(mine.yara),
            sigma: asked.sigma.or(mine.sigma),
            ids: asked.ids.or(mine.ids),
        }
    };
    if o.keep_on_failure == Some(true) && !policy.run.allow_keep_on_failure {
        return Err(denied(
            "overrides.keep_on_failure",
            "this policy does not allow keeping the VM after a failure",
        ));
    }
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

fn route_name(route: Route) -> String {
    serde_json::to_value(route)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}
