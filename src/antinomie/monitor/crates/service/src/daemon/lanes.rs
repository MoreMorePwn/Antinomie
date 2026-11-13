// SPDX-License-Identifier: GPL-3.0-only
//! Several lanes in one daemon (multi-lane M1, addendum P5-1 card C;
//! ANT-T0455): which lanes start, where their data folders are, and what each
//! lane's engine is started with.
//!
//! | Lane | Data folder | Engine |
//! |---|---|---|
//! | `lane-1` | the data folder itself (it owns the shared folders) | started first, as before |
//! | `lane-N` (2 to [`MAX_LANES`]) | `<data>/lanes/N/` (core's lane N, [`core_lanes::MIN_LANE`] and up) | `BackendOptions { data_dir: lanes/N, shared_root: Some(<data>), owner.lane: Some(N) }` |
//!
//! The lane files of every lane are lane 1's (`<data>/service/lanes/lane-N.json`),
//! as are the job store, `service.toml`, the presets and the host work pool.
//! A lane engine reads lane 1's engine settings and route settings (core
//! resolves `settings.json` and `network/routes.json` of a lane folder into
//! lane 1's), so the lanes are configured once. Core numbers the lanes the
//! same way: lane 1 is the data folder, `<data>/lanes/1/` is never a lane.
//!
//! **Which lanes start** ([`plan_lanes`]): lane 1 always, as before. Lane N
//! (2 to `daemon.lanes`) when it has a lane file and a VM (`auto init --lane
//! N`), and when `MemAvailable` covers the RAM of the lane VMs that start
//! before it plus this lane's own floor (`[resources] min_free_ram_mib`,
//! default its VM's RAM plus 2048 MiB). The first lane refused for memory
//! stops the count: the lanes start in order. Every lane left out is named
//! with its reason in the log, in `lane list` and in the status.
use crate::{
    api::ids::LaneId,
    config::{
        ServiceConfig,
        catalog::{DiskVms, VmCatalog},
    },
    lane::LaneDir,
};
use antinomie_monitor_core::{
    BackendOptions, VmLocations, lanes as core_lanes,
    recording::{RecordingError, read_only_locations},
};
use std::path::{Path, PathBuf};

pub use crate::config::service::MAX_LANES;

/// The lane's number (`lane-3`: 3).
pub fn lane_number(lane: &LaneId) -> Option<u32> {
    lane.as_str()
        .strip_prefix("lane-")
        .and_then(|n| n.parse().ok())
}

/// The data folder of `lane` under lane 1's data folder `root`.
pub fn lane_data_dir(root: &Path, lane: &LaneId) -> PathBuf {
    match lane_number(lane) {
        Some(n) if n >= 2 => core_lanes::lane_dir(root, n),
        _ => root.to_path_buf(),
    }
}

/// The engine options of `lane`, from lane 1's (`first`, whose `data_dir`
/// should be canonical): the same settings, the lane's own folder, lane 1's
/// folder as the shared root and the lane named in the owner claim.
pub fn lane_options(first: &BackendOptions, lane: &LaneId) -> BackendOptions {
    match lane_number(lane) {
        Some(n) if n >= 2 => {
            let mut options = first.clone();
            options.data_dir = core_lanes::lane_dir(&first.data_dir, n);
            options.shared_root = Some(first.data_dir.clone());
            options.owner.lane = Some(n);
            options
        }
        _ => first.clone(),
    }
}

/// The data folders the reads look in (multi-lane card D): lane 1's
/// (`first`), then every lane folder under it that carries its lane record
/// (`auto init --lane N` made it), in lane order. A lane that `daemon.lanes`
/// no longer starts is still read: its runs stay where its jobs left them.
/// A folder whose record does not read, names another lane, or resolves
/// outside `first`'s `lanes/` (a link to another place) is not read.
/// `first` being a lane folder itself (a command pointed at `lanes/N`) reads
/// only that lane.
pub fn read_lanes(first: &BackendOptions) -> Vec<(LaneId, BackendOptions)> {
    match core_lanes::lane_of(&first.data_dir) {
        Ok(Some(lane)) => return vec![(LaneId::new(lane.lane), first.clone())],
        // A record that does not read: the folder alone, as before lanes.
        Err(_) => return vec![(LaneId::new(1), first.clone())],
        Ok(None) => {}
    }
    let mut found = vec![(LaneId::new(1), first.clone())];
    let Ok(root) = std::fs::canonicalize(&first.data_dir) else {
        return found;
    };
    for lane in core_lanes::lanes(&root) {
        let id = LaneId::new(lane.lane);
        if lane.shared_root == root && lane.data_dir == core_lanes::lane_dir(&root, lane.lane) {
            found.push((id.clone(), lane_options(first, &id)));
        }
    }
    found
}

/// Where every VM of every lane in [`read_lanes`] keeps its disk and
/// recordings, lane by lane, each read without writing. Lane 1's folder that
/// cannot be read is an error; another lane's is left out, so one lane
/// cannot hide the others.
pub fn read_locations(first: &BackendOptions) -> Result<Vec<VmLocations>, RecordingError> {
    let mut all = Vec::new();
    for (index, (_, options)) in read_lanes(first).iter().enumerate() {
        match read_only_locations(options) {
            Ok(found) => all.extend(found),
            Err(error) if index == 0 => return Err(error),
            Err(_) => {}
        }
    }
    Ok(all)
}

/// A lane the plan starts.
#[derive(Clone, Debug)]
pub struct PlannedLane {
    pub lane: LaneId,
    pub options: BackendOptions,
    /// The lane VM's RAM, when its VM is found.
    pub ram_mib: Option<u32>,
}

/// A lane `daemon.lanes` asks for that does not start, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeftOut {
    pub lane: LaneId,
    pub reason: String,
}

/// Which lanes start.
#[derive(Clone, Debug)]
pub struct LanePlan {
    /// Lane 1 first, then the others in order.
    pub start: Vec<PlannedLane>,
    pub left: Vec<LeftOut>,
}

impl LanePlan {
    /// One line for the log: how many lanes start, and why the others do not.
    pub fn summary(&self, asked: u32) -> String {
        let names: Vec<&str> = self.start.iter().map(|l| l.lane.as_str()).collect();
        let mut line = format!(
            "lanes: {} of {asked} started ({})",
            self.start.len(),
            names.join(", ")
        );
        for left in &self.left {
            line.push_str(&format!("; {} not started: {}", left.lane, left.reason));
        }
        line
    }
}

/// The RAM of `lane`'s VM, from its lane file and its data folder's VMs.
fn lane_ram(lanes: &LaneDir, root: &Path, lane: &LaneId) -> Result<Option<u32>, String> {
    let Some(file) = lanes.load(lane).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let dir = lane_data_dir(root, lane);
    Ok(DiskVms::open(&dir).find(&file.vm_id).map(|vm| vm.ram_mib))
}

/// Decide which lanes start (see the module text). `first` are lane 1's
/// engine options (canonical `data_dir`); `available_mib` is `MemAvailable`.
pub fn plan_lanes(
    config: &ServiceConfig,
    first: &BackendOptions,
    lanes: &LaneDir,
    available_mib: Option<u64>,
) -> LanePlan {
    let root = &first.data_dir;
    let one = LaneId::new(1);
    let first_ram = lane_ram(lanes, root, &one).ok().flatten();
    let mut plan = LanePlan {
        start: vec![PlannedLane {
            lane: one,
            options: first.clone(),
            ram_mib: first_ram,
        }],
        left: Vec::new(),
    };
    let mut running_mib = u64::from(first_ram.unwrap_or(0));
    let mut out_of_memory = false;
    for n in 2..=config.daemon.lanes.min(MAX_LANES) {
        let lane = LaneId::new(n);
        let leave = |plan: &mut LanePlan, reason: String| {
            plan.left.push(LeftOut {
                lane: lane.clone(),
                reason,
            })
        };
        if out_of_memory {
            leave(
                &mut plan,
                "a lane before it did not fit in memory (lanes start in order)".into(),
            );
            continue;
        }
        let file = match lanes.load(&lane) {
            Ok(Some(file)) => file,
            Ok(None) => {
                leave(
                    &mut plan,
                    format!("it has no lane VM; run `antinomie-cli auto init --lane {n}`"),
                );
                continue;
            }
            Err(error) => {
                leave(&mut plan, format!("its lane file cannot be used: {error}"));
                continue;
            }
        };
        let dir = lane_data_dir(root, &lane);
        let Some(vm) = DiskVms::open(&dir).find(&file.vm_id) else {
            leave(
                &mut plan,
                format!("its VM {} is not in {}", file.vm_id, dir.display()),
            );
            continue;
        };
        let floor = u64::from(config.min_free_ram_mib(vm.ram_mib));
        let needed = running_mib + floor;
        match available_mib {
            Some(available) if available >= needed => {
                running_mib += u64::from(vm.ram_mib);
                plan.start.push(PlannedLane {
                    lane: lane.clone(),
                    options: lane_options(first, &lane),
                    ram_mib: Some(vm.ram_mib),
                });
            }
            Some(available) => {
                out_of_memory = true;
                leave(
                    &mut plan,
                    format!(
                        "the RAM floor is not met: it needs {needed} MiB available ({running_mib} MiB for the lane VMs before it plus its own floor of {floor} MiB), the machine has {available} MiB"
                    ),
                );
            }
            None => {
                out_of_memory = true;
                leave(
                    &mut plan,
                    "MemAvailable cannot be read, so its RAM floor cannot be checked".into(),
                );
            }
        }
    }
    plan
}
