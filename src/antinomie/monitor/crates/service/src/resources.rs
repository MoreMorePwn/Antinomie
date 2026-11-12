// SPDX-License-Identifier: GPL-3.0-only
//! Resource floors and the queue pause (design 4.6.3, 4.11 "Kill switch";
//! card P3-5c).
//!
//! Three floors keep a job from starting on a machine that cannot take it:
//!
//! | Resource | Floor | Below it |
//! |---|---|---|
//! | RAM | `MemAvailable` at least the lane VM's RAM plus 2048 MiB (`[resources] min_free_ram_mib`) | the job stays `queued` (`waiting_for: resources`); `engine.alert` `low_memory`, once an hour |
//! | disk | free space on the data directory and on every recording root at least `min_free_disk_gib` (20) plus the job's estimate (the capture quota, plus the VM's RAM when a memory dump is asked for) | the job stays `queued`; during `run` the floor itself is checked every minute: the run is stopped (`end_reason: stopped`), the job ends `partial` with the warning `low_disk`, and the queue pauses (`low_disk`) |
//! | KVM | `/dev/kvm` readable and writable when `require_kvm` | the job stays `queued` (`waiting_for: dependency`); the queue pauses (`no_kvm`) |
//!
//! Every probe is injected ([`Probes`]), so the tests move the numbers. The
//! real ones read `/proc/meminfo`, `statvfs` and `access(2)`.
//!
//! [`Governor::tick`] is what the daemon calls every few seconds, on every
//! lane's loop between its jobs (so a lane that is free looks before it
//! starts one, whatever the other lanes are running): it turns the
//! conditions into the queue's pause (`pause_reason`: `file` for the operator's
//! `run/PAUSE` file, `low_disk`, `no_kvm`) with an `engine.alert`, and lifts a
//! pause it set when the condition is gone. A pause the operator set
//! (`operator`) or a quarantined lane (`lane_quarantined`) is never lifted
//! here, and never replaced.
use crate::{
    api::{
        event::EventBody,
        job::{Job, WaitingFor},
        status::PauseReason,
    },
    config::{Policy, service::Resources},
    stages::{HostChecks, HostProblem},
    store::Store,
};
use std::path::{Path, PathBuf};

/// What the machine says.
pub trait Probes: Send + Sync {
    /// `MemAvailable` in MiB.
    fn mem_available_mib(&self) -> Option<u64>;
    /// Free space in GiB of the file system holding `path`.
    fn free_gib(&self, path: &Path) -> Option<u64>;
    /// `/dev/kvm` can be opened for reading and writing.
    fn kvm_usable(&self) -> bool;
    /// The operator's `run/PAUSE` file exists.
    fn pause_file(&self) -> bool;
}

/// The machine itself.
pub struct SystemProbes {
    pub pause_file: PathBuf,
}

impl Probes for SystemProbes {
    fn mem_available_mib(&self) -> Option<u64> {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = text.lines().find(|l| l.starts_with("MemAvailable:"))?;
        let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kib / 1024)
    }

    fn free_gib(&self, path: &Path) -> Option<u64> {
        let stat = rustix::fs::statvfs(path).ok()?;
        Some(stat.f_bavail.saturating_mul(stat.f_frsize) >> 30)
    }

    fn kvm_usable(&self) -> bool {
        rustix::fs::access(
            "/dev/kvm",
            rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK,
        )
        .is_ok()
    }

    fn pause_file(&self) -> bool {
        std::fs::symlink_metadata(&self.pause_file).is_ok()
    }
}

/// The numbers a floor is made of.
#[derive(Clone, Debug)]
pub struct Floors {
    pub min_free_disk_gib: u64,
    pub min_free_ram_mib: u64,
    pub require_kvm: bool,
    /// The data directory and every recording root.
    pub disk_paths: Vec<PathBuf>,
    /// The lane VM's RAM (a memory dump is that big).
    pub vm_ram_mib: u64,
    /// `capture_quota_size` in GiB (the per-job estimate).
    pub quota_gib: u64,
}

impl Floors {
    /// The floors of `[resources]` for a lane VM with `vm_ram_mib`.
    pub fn of(
        config: &Resources,
        vm_ram_mib: u32,
        disk_paths: Vec<PathBuf>,
        quota_bytes: u64,
    ) -> Self {
        Self {
            min_free_disk_gib: u64::from(config.min_free_disk_gib),
            min_free_ram_mib: u64::from(
                config
                    .min_free_ram_mib
                    .unwrap_or(vm_ram_mib.saturating_add(2048)),
            ),
            require_kvm: config.require_kvm,
            disk_paths,
            vm_ram_mib: u64::from(vm_ram_mib),
            quota_gib: quota_bytes.div_ceil(1 << 30),
        }
    }
}

/// A floor that is not met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shortage {
    Memory {
        available_mib: u64,
        needed_mib: u64,
    },
    Disk {
        path: PathBuf,
        free_gib: u64,
        needed_gib: u64,
    },
    NoKvm,
}

impl Shortage {
    pub fn words(&self) -> String {
        match self {
            Self::Memory {
                available_mib,
                needed_mib,
            } => {
                format!("{available_mib} MiB of memory are available, {needed_mib} MiB are needed")
            }
            Self::Disk {
                path,
                free_gib,
                needed_gib,
            } => format!(
                "{} has {free_gib} GiB free, {needed_gib} GiB are needed",
                path.display()
            ),
            Self::NoKvm => "/dev/kvm cannot be opened for reading and writing".into(),
        }
    }
}

/// The floors with the probes: the checks themselves.
pub struct ResourceChecks<'a> {
    pub floors: Floors,
    pub probes: &'a dyn Probes,
}

impl ResourceChecks<'_> {
    pub fn memory(&self) -> Option<Shortage> {
        let available = self.probes.mem_available_mib()?;
        (available < self.floors.min_free_ram_mib).then_some(Shortage::Memory {
            available_mib: available,
            needed_mib: self.floors.min_free_ram_mib,
        })
    }

    /// Free space above the floor plus `extra_gib`, on every path.
    pub fn disk(&self, extra_gib: u64) -> Option<Shortage> {
        let needed = self.floors.min_free_disk_gib + extra_gib;
        self.floors.disk_paths.iter().find_map(|path| {
            let free = self.probes.free_gib(path)?;
            (free < needed).then(|| Shortage::Disk {
                path: path.clone(),
                free_gib: free,
                needed_gib: needed,
            })
        })
    }

    pub fn kvm(&self) -> Option<Shortage> {
        (self.floors.require_kvm && !self.probes.kvm_usable()).then_some(Shortage::NoKvm)
    }

    /// What one job needs on disk: the capture quota, and a memory dump.
    pub fn estimate_gib(&self, memory_dump: bool) -> u64 {
        self.floors.quota_gib
            + if memory_dump {
                self.floors.vm_ram_mib.div_ceil(1024)
            } else {
                0
            }
    }
}

impl HostChecks for ResourceChecks<'_> {
    fn check(&self, job: &Job, policy: &Policy) -> Result<(), HostProblem> {
        if let Some(shortage) = self.kvm() {
            return Err(HostProblem::Wait(WaitingFor::Dependency, shortage.words()));
        }
        let dump = job
            .spec
            .overrides
            .memory_dump
            .unwrap_or(policy.evidence.memory_dump);
        if let Some(shortage) = self.memory().or_else(|| self.disk(self.estimate_gib(dump))) {
            return Err(HostProblem::Wait(WaitingFor::Resources, shortage.words()));
        }
        Ok(())
    }

    fn low_disk(&self) -> Option<String> {
        self.disk(0).map(|shortage| shortage.words())
    }

    fn admission(&self) -> Option<(WaitingFor, String)> {
        if let Some(shortage) = self.kvm() {
            return Some((WaitingFor::Dependency, shortage.words()));
        }
        [self.memory(), self.disk(self.estimate_gib(false))]
            .into_iter()
            .flatten()
            .next()
            .map(|shortage| (WaitingFor::Resources, shortage.words()))
    }
}

/// A pause the governor sets and lifts itself.
fn automatic(reason: PauseReason) -> bool {
    matches!(
        reason,
        PauseReason::File | PauseReason::LowDisk | PauseReason::NoKvm
    )
}

/// Turns the conditions into the queue's pause (see the module text).
pub struct Governor<'a> {
    pub checks: ResourceChecks<'a>,
    pub store: &'a Store,
    low_memory_alert_ms: Option<u64>,
    /// With several lanes every lane has a governor: they tick one at a time
    /// through this, which keeps the time of the last `low_memory` alert.
    shared: Option<std::sync::Arc<std::sync::Mutex<Option<u64>>>>,
}

/// What the governors of several lanes share ([`Governor::shared`]).
pub type GovernorShare = std::sync::Arc<std::sync::Mutex<Option<u64>>>;

/// `low_memory` is raised at most once an hour.
pub const LOW_MEMORY_ALERT_EVERY_MS: u64 = 3_600_000;

impl<'a> Governor<'a> {
    pub fn new(checks: ResourceChecks<'a>, store: &'a Store) -> Self {
        Self {
            checks,
            store,
            low_memory_alert_ms: None,
            shared: None,
        }
    }

    /// One of several governors (one per lane): their ticks take turns and
    /// the hourly `low_memory` alert is raised once for all of them.
    pub fn shared(mut self, share: GovernorShare) -> Self {
        self.shared = Some(share);
        self
    }

    fn alert(&self, code: &str, text: &str) -> Result<(), crate::api::error::ApiError> {
        self.store.emit_engine(EventBody::EngineAlert {
            code: code.into(),
            text: text.into(),
        })
    }

    /// What the pause should be now, with the words for the alert.
    fn wanted(&self) -> Option<(PauseReason, String)> {
        if self.checks.probes.pause_file() {
            return Some((
                PauseReason::File,
                "the run/PAUSE file exists; remove it to resume".into(),
            ));
        }
        if let Some(shortage) = self.checks.disk(0) {
            return Some((PauseReason::LowDisk, shortage.words()));
        }
        self.checks
            .kvm()
            .map(|shortage| (PauseReason::NoKvm, shortage.words()))
    }

    /// Look at the machine once. `now_ms` is the clock of the caller.
    pub fn tick(&mut self, now_ms: u64) -> Result<(), crate::api::error::ApiError> {
        let Some(share) = self.shared.clone() else {
            return self.look(now_ms);
        };
        let mut last_alert = crate::store::lock(&share);
        self.low_memory_alert_ms = *last_alert;
        let result = self.look(now_ms);
        *last_alert = self.low_memory_alert_ms;
        result
    }

    fn look(&mut self, now_ms: u64) -> Result<(), crate::api::error::ApiError> {
        let current = self.store.pause_reason()?;
        match (current, self.wanted()) {
            // The operator's pause and a quarantined lane stand.
            (Some(reason), _) if !automatic(reason) => {}
            (current, Some((reason, words))) => {
                if current != Some(reason) {
                    self.store.set_pause(Some(reason))?;
                    self.alert(
                        match reason {
                            PauseReason::LowDisk => "low_disk",
                            PauseReason::NoKvm => "no_kvm",
                            _ => "queue_paused",
                        },
                        &format!("the queue is paused: {words}"),
                    )?;
                }
            }
            (Some(_), None) => {
                self.store.set_pause(None)?;
                self.alert("queue_resumed", "the queue is running again")?;
            }
            (None, None) => {}
        }
        if let Some(shortage) = self.checks.memory() {
            let due = self
                .low_memory_alert_ms
                .is_none_or(|last| now_ms.saturating_sub(last) >= LOW_MEMORY_ALERT_EVERY_MS);
            if due {
                self.low_memory_alert_ms = Some(now_ms);
                self.alert("low_memory", &shortage.words())?;
            }
        } else {
            self.low_memory_alert_ms = None;
        }
        Ok(())
    }
}

/// Whether an error's words say the disk is full: SQLite's `SQLITE_FULL`,
/// `ENOSPC` or `EDQUOT` from a file write.
pub fn disk_full(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    [
        "database or disk is full",
        "no space left on device",
        "os error 28)",
        "disk quota exceeded",
        "os error 122)",
    ]
    .iter()
    .any(|words| text.contains(words))
}

/// Pause the queue for a floor that failed while a job was running.
pub fn pause_for_low_disk(store: &Store, words: &str) {
    if store.pause_reason().ok().flatten().is_none() {
        let _ = store.set_pause(Some(PauseReason::LowDisk));
    }
    let _ = store.emit_engine(EventBody::EngineAlert {
        code: "low_disk".into(),
        text: format!("the queue is paused: {words}"),
    });
}
