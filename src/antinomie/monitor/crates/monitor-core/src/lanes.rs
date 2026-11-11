// SPDX-License-Identifier: GPL-3.0-only
//! Lane data folders (multi-lane M1, addendum P5-1 card B).
//!
//! A node may run several lanes in one process, each with its own engine and
//! VM. Lane 0 is the data folder the operator chose. Lane N (1 and up) has its
//! own data folder, `<lane 0>/lanes/N/`, for its VMs, runs and settings, and
//! shares lane 0's bases, samples, ioc, rules, tools and volatility-plugins
//! folders.
//!
//! The engine of lane N starts with [`BackendOptions::shared_root`] set to lane
//! 0's folder and an owner claim naming lane N. It records the lane in
//! `<lane>/lane.json`. Every path helper that takes a data folder
//! ([`crate::samples::samples_dir`], [`crate::ruleset::rules_root`],
//! [`crate::analysis_tools::tools_dir`], [`crate::ioc::feeds::root`],
//! [`bases_dir`], [`crate::memory::plugins_dir`]) reads that record and
//! resolves into lane 0's folder, in any process, without symbolic links. The
//! shared root is the lane folder's grandparent, so moving the whole tree
//! keeps the lanes working.
//!
//! Only lane 0 changes the shared folders. A lane engine refuses base imports,
//! deletes, downloads and builds and tool installs and removals, and the rule,
//! feed, known false positive and GeoIP writers refuse a lane folder
//! ([`refuse_in_lane`]); the known false positives are lane 0's too. The
//! sample library is the exception: every lane writes it, serialised by its
//! writer lock (`samples::write_lock`) and SQLite.
//!
//! A folder without `lane.json` is a plain data folder, as before.
use crate::api::BackendOptions;
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// The folder of lane 0 that holds the other lanes' data folders.
pub const LANES_DIR: &str = "lanes";
/// The record that makes a data folder a lane's.
pub const MARKER_FILE: &str = "lane.json";
/// The highest lane number a data folder may have.
pub const MAX_LANE: u32 = 64;
/// Part of every refusal of a shared writer on a lane; front ends match on it.
pub const SHARED_WRITER: &str = "only lane 0 changes the folders the lanes share";

const MARKER_MAX: u64 = 4096;

/// The content of `lane.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneMarker {
    pub schema: u32,
    pub lane: u32,
}

/// A lane data folder: its number and the folder it shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lane {
    pub lane: u32,
    /// Lane 0's data folder, canonical.
    pub shared_root: PathBuf,
    /// This lane's data folder, canonical.
    pub data_dir: PathBuf,
}

/// The data folder of lane `lane` of `shared_root`.
pub fn lane_dir(shared_root: &Path, lane: u32) -> PathBuf {
    shared_root.join(LANES_DIR).join(lane.to_string())
}

/// Whether `data_dir` carries a lane record, readable or not.
pub fn is_lane_folder(data_dir: &Path) -> bool {
    fs::symlink_metadata(data_dir.join(MARKER_FILE)).is_ok()
}

/// The lane `data_dir` is, from its record. `Ok(None)` for a plain data folder;
/// an error for a record that does not read or does not match the folder's
/// place (`<root>/lanes/<lane>`).
pub fn lane_of(data_dir: &Path) -> Result<Option<Lane>, String> {
    let path = data_dir.join(MARKER_FILE);
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(MARKER_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() as u64 > MARKER_MAX {
        return Err(format!("{}: too large", path.display()));
    }
    let marker: LaneMarker =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    if marker.schema != 1 || marker.lane == 0 || marker.lane > MAX_LANE {
        return Err(format!("{}: not a lane record", path.display()));
    }
    let data_dir =
        fs::canonicalize(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let parent = data_dir
        .parent()
        .filter(|p| p.file_name() == Some(LANES_DIR.as_ref()));
    let shared_root = parent
        .and_then(Path::parent)
        .filter(|_| data_dir.file_name() == Some(marker.lane.to_string().as_ref()))
        .ok_or_else(|| {
            format!(
                "{} says lane {}, but the folder is not <data>/{LANES_DIR}/{}",
                path.display(),
                marker.lane,
                marker.lane
            )
        })?
        .to_path_buf();
    Ok(Some(Lane {
        lane: marker.lane,
        shared_root,
        data_dir,
    }))
}

/// The folder whose shared folders `data_dir` uses: lane 0's for a lane
/// folder, `data_dir` itself otherwise. A lane record that does not read
/// resolves nowhere new; the lane's engine refuses to start on it, and the
/// writers refuse it ([`refuse_in_lane`]).
pub fn shared_root(data_dir: &Path) -> PathBuf {
    match lane_of(data_dir) {
        Ok(Some(lane)) => lane.shared_root,
        _ => data_dir.to_path_buf(),
    }
}

/// The installed bases of the data folder `data_dir` uses.
pub fn bases_dir(data_dir: &Path) -> PathBuf {
    shared_root(data_dir).join("bases")
}

/// The lane folders under `shared_root` (lane 0), in lane order. Folders
/// under `lanes/` without a record are not lanes; a record that does not read
/// is an error, for a caller that must not miss a lane.
pub fn lanes_checked(shared_root: &Path) -> Result<Vec<Lane>, String> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(shared_root.join(LANES_DIR)) else {
        return Ok(found);
    };
    for entry in entries.flatten() {
        if let Some(lane) = lane_of(&entry.path())? {
            found.push(lane);
        }
    }
    found.sort_by_key(|lane| lane.lane);
    Ok(found)
}

/// [`lanes_checked`] without the lanes whose record does not read.
pub fn lanes(shared_root: &Path) -> Vec<Lane> {
    let Ok(entries) = fs::read_dir(shared_root.join(LANES_DIR)) else {
        return Vec::new();
    };
    let mut found: Vec<Lane> = entries
        .flatten()
        .filter_map(|entry| lane_of(&entry.path()).ok().flatten())
        .collect();
    found.sort_by_key(|lane| lane.lane);
    found
}

/// Whether `data_dir` is lane 0 of at least one lane folder, or is a lane.
pub fn has_lanes(data_dir: &Path) -> bool {
    is_lane_folder(data_dir)
        || fs::read_dir(data_dir.join(LANES_DIR))
            .is_ok_and(|entries| entries.flatten().any(|entry| is_lane_folder(&entry.path())))
}

/// A change of the shared folders that only lane 0 makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedWrite {
    ImportBase,
    DeleteBase,
    DownloadBase,
    BuildBase,
    InstallTool,
    RemoveTool,
    RuleUpdate,
    FeedUpdate,
    KnownFalsePositives,
    GeoipUpdate,
}

impl SharedWrite {
    pub fn label(self) -> &'static str {
        match self {
            Self::ImportBase => "importing a base",
            Self::DeleteBase => "deleting a base",
            Self::DownloadBase => "downloading a base",
            Self::BuildBase => "building a base",
            Self::InstallTool => "installing an analysis tool",
            Self::RemoveTool => "removing an analysis tool",
            Self::RuleUpdate => "changing the rule packs",
            Self::FeedUpdate => "changing the IOC datasets",
            Self::KnownFalsePositives => "changing the known false positives",
            Self::GeoipUpdate => "updating the GeoIP databases",
        }
    }
}

/// A shared write a lane refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneRefusal {
    /// The lane, when its record reads.
    pub lane: Option<u32>,
    pub action: SharedWrite,
}

impl fmt::Display for LaneRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.lane {
            Some(lane) => write!(f, "{} is refused on lane {lane}: ", self.action.label())?,
            None => write!(
                f,
                "{} is refused in a lane data folder: ",
                self.action.label()
            )?,
        }
        write!(f, "{SHARED_WRITER}")
    }
}

impl std::error::Error for LaneRefusal {}

/// Whether an error text is a [`LaneRefusal`].
pub fn is_refusal(error: &str) -> bool {
    error.contains(SHARED_WRITER)
}

/// `Err` with a [`LaneRefusal`] when `data_dir` is a lane folder: the writers
/// of the shared folders call this with the folder they were given.
pub fn refuse_in_lane(data_dir: &Path, action: SharedWrite) -> Result<(), String> {
    if !is_lane_folder(data_dir) {
        return Ok(());
    }
    let lane = lane_of(data_dir).ok().flatten().map(|lane| lane.lane);
    Err(LaneRefusal { lane, action }.to_string())
}

/// Check what an engine is about to take, before it takes the folder:
/// `options.data_dir` (canonical) against `shared_root` and the owner claim's
/// lane, and against the record already in the folder. Returns the record to
/// write once the folder is ours, for a lane engine.
pub(crate) fn check_start(options: &BackendOptions) -> Result<Option<LaneMarker>, String> {
    let data_dir = &options.data_dir;
    let found = lane_of(data_dir)?;
    match (options.owner.lane, &options.shared_root) {
        (None, None) => match found {
            None => Ok(None),
            Some(lane) => Err(format!(
                "{} is the data folder of lane {} of {}; open {} instead",
                data_dir.display(),
                lane.lane,
                lane.shared_root.display(),
                lane.shared_root.display()
            )),
        },
        (Some(lane), Some(root)) => {
            if lane == 0 || lane > MAX_LANE {
                return Err(format!("lane {lane} is not between 1 and {MAX_LANE}"));
            }
            let root = fs::canonicalize(root)
                .map_err(|e| format!("shared root {}: {e}", root.display()))?;
            if !root.is_dir() {
                return Err(format!("shared root {} is not a folder", root.display()));
            }
            if is_lane_folder(&root) {
                return Err(format!(
                    "shared root {} is itself a lane's data folder",
                    root.display()
                ));
            }
            let expected = lane_dir(&root, lane);
            if *data_dir != expected {
                return Err(format!(
                    "the data folder of lane {lane} must be {}, not {}",
                    expected.display(),
                    data_dir.display()
                ));
            }
            if let Some(other) = found.filter(|found| found.lane != lane) {
                return Err(format!(
                    "{} is the data folder of lane {}, not lane {lane}",
                    data_dir.display(),
                    other.lane
                ));
            }
            Ok(Some(LaneMarker { schema: 1, lane }))
        }
        (Some(lane), None) => Err(format!(
            "lane {lane} needs the shared root (lane 0's data folder)"
        )),
        (None, Some(root)) => Err(format!(
            "a shared root ({}) is only for a lane engine; the owner claim names no lane",
            root.display()
        )),
    }
}

/// Write the lane record into a folder this process now owns. The `lanes`
/// folder is made private like the data folders it holds.
pub(crate) fn write_marker(data_dir: &Path, marker: &LaneMarker) -> Result<(), String> {
    if let Some(lanes) = data_dir.parent() {
        crate::storage::private_dir(lanes).map_err(|e| format!("{}: {e}", lanes.display()))?;
    }
    if lane_of(data_dir)?.is_some_and(|lane| lane.lane == marker.lane) {
        return Ok(());
    }
    crate::storage::atomic_json(&data_dir.join(MARKER_FILE), marker)
}

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod tests;
