// SPDX-License-Identifier: GPL-3.0-only
//! Configuration: `service.toml` (design 2.4.2) and `policies/*.toml` (4.4),
//! their validation (`config validate`) and the set of policies a running
//! service holds. A job freezes the policy it is submitted under, so a reload
//! (SIGHUP) never changes a job already queued or running (5.6).

pub mod catalog;
pub mod locate;
pub mod policy;
pub mod service;
pub mod validate;

use crate::api::{
    ops::{Caller, Scope},
    status::PolicySummary,
};
pub use catalog::{DiskVms, NoVms, VmCatalog, VmFacts, VmNet};
pub use policy::{LoadedPolicy, Policy};
pub use service::ServiceConfig;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, RwLock},
};
pub use validate::{ConfigReport, Problem, Severity};

/// The shipped `default.toml`: conservative (design 4.4). `auto init` writes
/// it when the data directory has no policy.
pub const DEFAULT_POLICY: &str = r#"description = "Static checks, 5 minute run, nothing leaves the machine"

[sample]
accept_types   = ["elf"]
accept_arch    = ["x86_64"]
max_sample_mib = 64
on_duplicate   = "run"

[vm]
lane_vm      = "auto-1"
revert       = "snapshot_disk"
revert_to    = "auto-clean"
network      = "routed"
revert_after = false

[run]
timeout_s    = 300
max_run_s    = 1800
run_as       = "user"
allow_root   = false
run_in       = "app_terminal"
guest_dir    = "/tmp"
args_allowed = true
env_allowed  = false

[network]
route          = "drop"
allowed_routes = ["drop", "inet_sim"]
capture        = true

[evidence]
memory_dump  = false
core_dump    = false
core_max_mib = 64
dump_trigger      = "off"   # off, low, medium or high: dump when the live Triage rules match
dump_trigger_kind = "core"  # core, memory or both

[analysis]
static_checks         = "triage"
static_time_limit_min = 2
triage                = true
detection             = { yara = true, sigma = true, ids = true }
required_stages       = ["analyse"]
online_ioc            = false

[report]
formats = ["html", "json"]
bundle  = false
defang  = true

[verdict]
mapping = "default"

[retry]
max_attempts = 2
backoff_s    = [30, 120]
retry_on     = ["vm_start_failed", "guest_unreachable", "upload_failed", "guest_lost"]

[access]
scopes  = ["submit"]
clients = ["*"]

[limits]
max_queued_per_client = 50
max_jobs_per_day      = 500
max_concurrent        = 1
priority_max          = 5
wait_s                = 3600
"#;

/// Where the service finds a policy by name.
pub trait PolicyLookup: Send + Sync {
    fn get(&self, name: &str) -> Option<Arc<LoadedPolicy>>;
}

/// An immutable set of policies.
#[derive(Clone, Debug, Default)]
pub struct PolicySet {
    by_name: BTreeMap<String, Arc<LoadedPolicy>>,
}

impl PolicySet {
    pub fn new(by_name: BTreeMap<String, Arc<LoadedPolicy>>) -> Self {
        Self { by_name }
    }

    /// A set of one policy, for tests and for the direct-mode CLI.
    pub fn single(policy: LoadedPolicy) -> Self {
        let mut by_name = BTreeMap::new();
        by_name.insert(policy.name.clone(), Arc::new(policy));
        Self { by_name }
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// `policy.list`: the policies `caller` may use, with their ceilings
    /// (design 5.3). A caller sees only what it may use.
    pub fn list_for(&self, caller: &Caller) -> Vec<PolicySummary> {
        self.by_name
            .values()
            .filter(|policy| policy.allows(&caller.client_id, Scope::Submit))
            .filter(|policy| {
                caller.policies.is_empty()
                    || caller
                        .policies
                        .iter()
                        .any(|pattern| policy::glob(pattern, &policy.name))
            })
            .map(|policy| summary(policy))
            .collect()
    }
}

fn summary(loaded: &LoadedPolicy) -> PolicySummary {
    use serde_json::json;
    let p = &loaded.policy;
    let mut ceilings = BTreeMap::new();
    ceilings.insert("max_run_s".to_owned(), json!(p.run.max_run_s));
    ceilings.insert("max_sample_mib".to_owned(), json!(p.sample.max_sample_mib));
    ceilings.insert("priority_max".to_owned(), json!(p.limits.priority_max));
    ceilings.insert("allow_root".to_owned(), json!(p.run.allow_root));
    ceilings.insert("allowed_routes".to_owned(), json!(p.network.allowed_routes));
    ceilings.insert("accept_types".to_owned(), json!(p.sample.accept_types));
    ceilings.insert("accept_arch".to_owned(), json!(p.sample.accept_arch));
    ceilings.insert(
        "max_queued_per_client".to_owned(),
        json!(p.limits.max_queued_per_client),
    );
    PolicySummary {
        name: loaded.name.clone(),
        description: p.description.clone(),
        ceilings,
    }
}

impl PolicyLookup for PolicySet {
    fn get(&self, name: &str) -> Option<Arc<LoadedPolicy>> {
        self.by_name.get(name).cloned()
    }
}

/// The policies of a running service, replaced as a whole by a reload.
pub struct SharedPolicies {
    current: RwLock<Arc<PolicySet>>,
}

impl SharedPolicies {
    pub fn new(set: PolicySet) -> Self {
        Self {
            current: RwLock::new(Arc::new(set)),
        }
    }

    pub fn snapshot(&self) -> Arc<PolicySet> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Read `<data>/policies` again (SIGHUP). On any error the old set stays
    /// and the problems are returned; jobs already stored keep the policy they
    /// froze either way.
    pub fn reload(&self, data_dir: &Path, catalog: &dyn VmCatalog) -> Result<usize, Vec<Problem>> {
        let report = validate::load(data_dir, catalog, None);
        if report.has_errors() {
            return Err(report.problems);
        }
        let count = report.policies.len();
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Arc::new(PolicySet::new(report.policies));
        Ok(count)
    }
}

impl PolicyLookup for SharedPolicies {
    fn get(&self, name: &str) -> Option<Arc<LoadedPolicy>> {
        self.snapshot().get(name)
    }
}
