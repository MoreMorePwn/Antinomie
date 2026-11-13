// SPDX-License-Identifier: GPL-3.0-only
//! Where a caller's permissions come from in 0.9.0 (the access
//! specification, "Changes to 0.9.0": the callers stay as they are):
//!
//! * the owner on the local socket, `local:<uid>`, holds every permission
//!   (as it held every scope);
//! * a watch folder submits as `auto:policy-<preset>` with `runs.submit` and
//!   the folder's `permissions` from `service.toml`.
//!
//! Prechecks asks [`CallerLookup`] again when a run starts, so a permission
//! taken away while the run waited (a reloaded `service.toml`) refuses it.

use super::service::ServiceConfig;
use crate::api::ops::{Caller, Permission};
use std::collections::{BTreeMap, BTreeSet};

/// A job's labels (`watch` names the folder a watch client submitted from).
pub type Labels = BTreeMap<String, String>;

/// The client id prefix of the owner on the local socket.
pub const LOCAL_PREFIX: &str = "local:";
/// The client id prefix of a watch folder.
pub const WATCH_PREFIX: &str = "auto:policy-";

/// The caller a watch folder acts as: a client named for the preset, with
/// `runs.submit` and the folder's own `permissions`.
pub fn watch_caller(policy: &str, permissions: &[Permission]) -> Caller {
    let mut caller = Caller::new(format!("{WATCH_PREFIX}{policy}"), &[Permission::RunsSubmit]);
    caller.permissions.extend(permissions.iter().copied());
    caller
}

/// What a job's client holds now.
pub trait CallerLookup: Send + Sync {
    /// The permissions `client_id` (a job's client, with the job's `labels`)
    /// holds now; `None` when the service does not configure that client
    /// (its permissions came with the call only), and the run keeps what it
    /// was admitted with.
    fn permissions_now(&self, client_id: &str, labels: &Labels) -> Option<BTreeSet<Permission>>;
}

/// The owner only: `local:*` holds every permission, any other client is not
/// known. For the host pool (which runs no prechecks) and for tests.
pub struct LocalOnly;

impl CallerLookup for LocalOnly {
    fn permissions_now(&self, client_id: &str, _: &Labels) -> Option<BTreeSet<Permission>> {
        client_id
            .starts_with(LOCAL_PREFIX)
            .then(|| Permission::ALL.into_iter().collect())
    }
}

/// The permissions `client_id` holds under `config`: every one for the
/// local owner; for a watch client `runs.submit` and the `permissions` of the
/// folders that submit to its preset (or choose it by subfolder) and, when
/// the job carries the `watch` label, whose label is that one.
pub fn permissions_now(
    config: &ServiceConfig,
    client_id: &str,
    labels: &Labels,
) -> Option<BTreeSet<Permission>> {
    if client_id.starts_with(LOCAL_PREFIX) {
        return Some(Permission::ALL.into_iter().collect());
    }
    let policy = client_id.strip_prefix(WATCH_PREFIX)?;
    let label = labels.get("watch");
    let mut held: BTreeSet<Permission> = [Permission::RunsSubmit].into();
    for folder in &config.inbox.watch {
        if (folder.preset == policy || folder.preset_by_dir)
            && label.is_none_or(|label| *label == folder.label())
        {
            held.extend(folder.permissions.iter().copied());
        }
    }
    Some(held)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::service::Watch;

    fn folder(path: &str, policy: &str, permissions: &[Permission]) -> Watch {
        let mut watch: Watch = toml::from_str(&format!("path = {path:?}\npreset = {policy:?}"))
            .expect("a watch folder");
        watch.permissions = permissions.to_vec();
        watch
    }

    fn labels(label: Option<&str>) -> Labels {
        label
            .map(|label| [("watch".to_owned(), label.to_owned())].into())
            .unwrap_or_default()
    }

    #[test]
    fn a_watch_folder_names_its_permissions_by_key() {
        let watch: Watch =
            toml::from_str("path = \"/srv/drop/cores\"\npermissions = [\"evidence.core_dump\"]")
                .unwrap();
        assert_eq!(watch.permissions, [Permission::EvidenceCoreDump]);
        assert_eq!(watch.label(), "cores");
        let plain: Watch = toml::from_str("path = \"/srv/drop/x\"").unwrap();
        assert!(plain.permissions.is_empty());
        // An unknown key, and the web's own permissions, are refused.
        for key in ["evidence.everything", "users.manage", "submit"] {
            let text = format!("path = \"/x\"\npermissions = [{key:?}]");
            assert!(toml::from_str::<Watch>(&text).is_err(), "{key}");
        }
    }

    #[test]
    fn a_watch_caller_holds_submit_and_its_folder_permissions() {
        let caller = watch_caller("strict", &[Permission::EvidenceCoreDump]);
        assert_eq!(caller.client_id, "auto:policy-strict");
        assert!(caller.has(Permission::RunsSubmit));
        assert!(caller.has(Permission::EvidenceCoreDump));
        assert!(!caller.has(Permission::SamplesAdd));
        assert!(!caller.has(Permission::RunsSeeAll));
    }

    #[test]
    fn the_local_owner_holds_every_permission_and_others_are_unknown() {
        let none = labels(None);
        assert_eq!(
            LocalOnly
                .permissions_now("local:1000", &none)
                .map(|p| p.len()),
            Some(Permission::ALL.len())
        );
        assert_eq!(LocalOnly.permissions_now("web:alice", &none), None);
        let config = ServiceConfig::default();
        assert_eq!(permissions_now(&config, "web:alice", &none), None);
        assert_eq!(
            permissions_now(&config, "local:1000", &none).map(|p| p.len()),
            Some(Permission::ALL.len())
        );
    }

    #[test]
    fn a_watch_client_holds_what_its_folders_grant_now() {
        let mut config = ServiceConfig::default();
        config.inbox.watch = vec![
            folder(
                "/srv/drop/cores",
                "default",
                &[Permission::EvidenceCoreDump],
            ),
            folder("/srv/drop/plain", "default", &[]),
            folder(
                "/srv/drop/other",
                "strict",
                &[Permission::EvidenceMemoryDump],
            ),
        ];
        let cores =
            permissions_now(&config, "auto:policy-default", &labels(Some("cores"))).unwrap();
        assert!(cores.contains(&Permission::RunsSubmit));
        assert!(cores.contains(&Permission::EvidenceCoreDump));
        assert!(!cores.contains(&Permission::EvidenceMemoryDump));
        let plain =
            permissions_now(&config, "auto:policy-default", &labels(Some("plain"))).unwrap();
        assert_eq!(plain, [Permission::RunsSubmit].into());
        // Without the label, every folder of the policy counts.
        let any = permissions_now(&config, "auto:policy-default", &labels(None)).unwrap();
        assert!(any.contains(&Permission::EvidenceCoreDump));
        // The folder lost the permission (a reload): the run no longer holds it.
        config.inbox.watch[0].permissions.clear();
        let now = permissions_now(&config, "auto:policy-default", &labels(Some("cores"))).unwrap();
        assert!(!now.contains(&Permission::EvidenceCoreDump));
    }
}
