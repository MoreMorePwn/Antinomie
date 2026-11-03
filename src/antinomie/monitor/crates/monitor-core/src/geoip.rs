// SPDX-License-Identifier: GPL-3.0-only
//! Offline IP geolocation for TShark.
//!
//! TShark (4.x) reads country, city and AS data only from MaxMind-format
//! `.mmdb` files found in its MaxMind database paths (`/usr/share/GeoIP` and
//! `/var/lib/GeoIP` on Debian and Kali). The legacy `GeoIP.dat` files are
//! ignored, so a computer with only those gets empty country and organization
//! columns. This module finds out whether TShark has a usable database,
//! points it at Antinomie's managed DB-IP Lite copy or a folder the person
//! chose, and does so for Antinomie's own TShark runs only. Those run in a
//! bubblewrap sandbox with no access to the data folder, so the database
//! folders are mounted read-only into it and a `maxmind_db_paths` file naming
//! them is written to the run's private configuration folder (see
//! `packet_filter::process`). The person's own Wireshark configuration is
//! never read or written.
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

mod refresh;
pub use refresh::{Latest, check_latest, update_latest};

/// Id of the managed package in `analysis_tools::PACKAGES`.
pub const TOOL_ID: &str = "geoip";
/// The attribution CC BY 4.0 asks for wherever the data appears.
pub const ATTRIBUTION: &str = "IP geolocation by DB-IP";
/// Where the attribution links to.
pub const ATTRIBUTION_URL: &str = "https://db-ip.com";
/// The licence of the DB-IP Lite databases.
pub const LICENCE: &str = "CC BY 4.0";
pub const LICENCE_URL: &str = "https://creativecommons.org/licenses/by/4.0/";
/// The line for report notes and tooltips.
pub const ATTRIBUTION_NOTE: &str =
    "IP geolocation by DB-IP (https://db-ip.com), DB-IP Lite databases under CC BY 4.0.";
/// Where TShark looks when `tshark -G folders` cannot be read.
const SYSTEM_DIRS: &[&str] = &["/usr/share/GeoIP", "/var/lib/GeoIP"];
/// The largest `.mmdb` file read for its type (the metadata is at its end).
const TAIL: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Country,
    City,
    Asn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// In one of TShark's own MaxMind paths.
    System,
    /// Antinomie's DB-IP Lite copy under `<data>/tools/geoip`.
    Managed,
    /// The folder chosen in Settings > Network lookup.
    Folder,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Database {
    pub path: PathBuf,
    pub kind: Kind,
    /// The `database_type` the file states, e.g. "DBIP-Country-Lite".
    pub name: String,
    pub origin: Origin,
}

/// What Antinomie's managed copy is, from its `tool.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Managed {
    /// The month of the data, "2026-11".
    pub month: String,
    /// Pinned in the app (SHA-256 checked against it) or a newer month taken
    /// on first sight, its hash only recorded.
    pub pinned: bool,
}

/// Whether TShark can look up addresses, and with what.
#[derive(Clone, Debug, Default)]
pub struct Status {
    pub databases: Vec<Database>,
    pub managed: Option<Managed>,
    /// Every folder TShark will read, in order.
    pub folders: Vec<PathBuf>,
}

impl Status {
    pub fn has_location(&self) -> bool {
        self.databases
            .iter()
            .any(|database| matches!(database.kind, Kind::Country | Kind::City))
    }

    pub fn has_asn(&self) -> bool {
        self.databases
            .iter()
            .any(|database| database.kind == Kind::Asn)
    }

    /// Both a country (or city) and an AS database are there.
    pub fn complete(&self) -> bool {
        self.has_location() && self.has_asn()
    }

    /// A sentence for the Warning when something is missing; `None` when
    /// TShark can fill both country and organization.
    pub fn warning(&self) -> Option<String> {
        const FIX: &str = "Install the DB-IP Lite databases in Library > Analysis tools, \
            or choose a folder with GeoLite2 .mmdb files in Settings > Network lookup. \
            TShark 4.x ignores the old GeoIP.dat files.";
        match (self.has_location(), self.has_asn()) {
            (true, true) => None,
            (false, false) => Some(format!(
                "TShark has no MaxMind-format (.mmdb) database, so the Country and \
                 Organization columns stay empty. {FIX}"
            )),
            (false, true) => Some(format!(
                "TShark has an AS database but no country or city database, so the \
                 Country column stays empty. {FIX}"
            )),
            (true, false) => Some(format!(
                "TShark has a country database but no AS database, so the Organization \
                 column stays empty. {FIX}"
            )),
        }
    }
}

/// The `database_type` of an `.mmdb` file: its metadata map sits after the
/// marker `\xAB\xCD\xEFMaxMind.com` near the end of the file.
pub fn database_type(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(TAIL)))
        .ok()?;
    let mut tail = Vec::new();
    file.take(TAIL).read_to_end(&mut tail).ok()?;
    let marker = b"\xab\xcd\xefMaxMind.com";
    let start = tail
        .windows(marker.len())
        .rposition(|window| window == marker)?
        + marker.len();
    let metadata = &tail[start..];
    let key = b"database_type";
    let at = metadata
        .windows(key.len())
        .position(|window| window == key)?
        + key.len();
    // A string: control byte 0b010xxxxx; sizes of 29 and more continue in the
    // next bytes ("DBIP-ASN-Lite (compat=GeoLite2-ASN)" is one).
    let control = *metadata.get(at)?;
    (control & 0xe0 == 0x40).then_some(())?;
    let (length, skip) = match control & 0x1f {
        29 => (29 + usize::from(*metadata.get(at + 1)?), 2),
        30 => (
            285 + usize::from(*metadata.get(at + 1)?) * 256 + usize::from(*metadata.get(at + 2)?),
            3,
        ),
        short @ 0..=28 => (usize::from(short), 1),
        _ => return None,
    };
    let text = metadata.get(at + skip..at + skip + length)?;
    String::from_utf8(text.to_vec()).ok()
}

fn kind_of(name: &str) -> Option<Kind> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("asn") {
        Some(Kind::Asn)
    } else if lower.contains("city") {
        Some(Kind::City)
    } else if lower.contains("country") {
        Some(Kind::Country)
    } else {
        None
    }
}

/// The `.mmdb` files directly in `dir` that hold country, city or AS data.
pub fn scan_dir(dir: &Path, origin: Origin) -> Vec<Database> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<Database> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "mmdb")
        })
        .filter_map(|path| {
            let name = database_type(&path)?;
            Some(Database {
                kind: kind_of(&name)?,
                path,
                name,
                origin,
            })
        })
        .collect();
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

/// The folders TShark reads on its own, from `tshark -G folders`.
pub fn system_dirs() -> Vec<PathBuf> {
    let listed = Command::new("tshark")
        .args(["-G", "folders"])
        .env("LC_ALL", "C")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.strip_prefix("MaxMind database path:"))
                .map(|path| PathBuf::from(path.trim()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for dir in listed
        .into_iter()
        .chain(SYSTEM_DIRS.iter().map(PathBuf::from))
    {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// The folder of a complete system database (country or city, and AS) among
/// TShark's default paths, for the tool list; no process is started.
pub fn system_databases() -> Option<String> {
    SYSTEM_DIRS.iter().map(Path::new).find_map(|dir| {
        let databases = scan_dir(dir, Origin::System);
        let location = databases
            .iter()
            .any(|d| matches!(d.kind, Kind::Country | Kind::City));
        let asn = databases.iter().any(|d| d.kind == Kind::Asn);
        (location && asn).then(|| dir.display().to_string())
    })
}

/// `<data>/tools/geoip`, where the managed databases are unpacked.
pub fn managed_dir(data_dir: &Path) -> PathBuf {
    crate::analysis_tools::tools_dir(data_dir).join(TOOL_ID)
}

/// The managed copy's month and whether it is the pinned one.
pub fn managed_info(data_dir: &Path) -> Option<Managed> {
    let text = fs::read(managed_dir(data_dir).join("tool.json")).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&text).ok()?;
    (value.get("id")?.as_str()? == TOOL_ID).then_some(())?;
    Some(Managed {
        month: value.get("version")?.as_str()?.to_owned(),
        pinned: value
            .get("pinned")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
    })
}

/// Every database TShark can use with the current settings: its own paths,
/// Antinomie's managed copy and the chosen folder.
pub fn detect(data_dir: &Path, folder: Option<&Path>) -> Status {
    let mut status = Status::default();
    let add = |dir: PathBuf, origin: Origin, status: &mut Status| {
        if status.folders.contains(&dir) {
            return;
        }
        status.databases.extend(scan_dir(&dir, origin));
        status.folders.push(dir);
    };
    for dir in system_dirs() {
        add(dir, Origin::System, &mut status);
    }
    status.managed = managed_info(data_dir);
    if status.managed.is_some() {
        add(managed_dir(data_dir), Origin::Managed, &mut status);
    }
    if let Some(folder) = folder {
        add(folder.to_path_buf(), Origin::Folder, &mut status);
    }
    status
}

/// The database folders to hand to Antinomie's TShark runs, set by [`configure`].
static DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// The environment variable that carries the folders from [`apply`] to the
/// sandbox launcher, which strips it before the run starts.
pub(crate) const DIRS_ENV: &str = "ANTINOMIE_GEOIP_DIRS";

/// Choose the folders Antinomie's TShark runs read besides TShark's own: the
/// managed copy when it is installed and the chosen folder.
pub fn configure(data_dir: &Path, folder: Option<&Path>) {
    let managed = managed_info(data_dir).is_some();
    MANAGED_IN_USE.store(managed, std::sync::atomic::Ordering::Relaxed);
    let mut dirs: Vec<PathBuf> = Vec::new();
    if managed {
        dirs.push(managed_dir(data_dir));
    }
    if let Some(folder) = folder.filter(|folder| folder.is_dir()) {
        dirs.push(folder.to_path_buf());
    }
    if let Ok(mut current) = DIRS.lock() {
        *current = dirs;
    }
}

/// Whether Antinomie's DB-IP Lite copy is what TShark looks addresses up in,
/// so the places that show the result must carry the attribution.
pub fn attribution_due() -> bool {
    MANAGED_IN_USE.load(std::sync::atomic::Ordering::Relaxed)
}

static MANAGED_IN_USE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether Antinomie's TShark runs can find a database: a managed or chosen
/// folder, or a complete one in TShark's own folders.
pub fn configured() -> bool {
    DIRS.lock().is_ok_and(|dirs| !dirs.is_empty()) || system_databases().is_some()
}

/// Make a TShark run read the folders [`configure`] chose.
pub fn apply(command: &mut Command) {
    let dirs = DIRS.lock().map(|dirs| dirs.clone()).unwrap_or_default();
    if let Ok(joined) = std::env::join_paths(&dirs)
        && !dirs.is_empty()
    {
        command.env(DIRS_ENV, joined);
    }
}

/// The folders [`apply`] put on `command`, for the sandbox launcher.
pub(crate) fn dirs_of(command: &Command) -> Vec<PathBuf> {
    command
        .get_envs()
        .find(|(name, _)| *name == DIRS_ENV)
        .and_then(|(_, value)| value)
        .map(|value| std::env::split_paths(value).collect())
        .unwrap_or_default()
}

/// Decompress `source` (gzip) into `target`, stopping at `limit` octets.
pub(crate) fn gunzip_file(
    source: &Path,
    target: &Path,
    limit: u64,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<(), String> {
    use std::io::{Read, Write};
    let mut reader = flate2::read::GzDecoder::new(
        fs::File::open(source).map_err(|e| format!("{}: {e}", source.display()))?,
    );
    let mut out = fs::File::create(target).map_err(|e| format!("{}: {e}", target.display()))?;
    let mut buffer = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("tool installation cancelled".into());
        }
        let read = reader.read(&mut buffer).map_err(|e| format!("gzip: {e}"))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > limit {
            return Err("gzip: the file is larger than the database limit".into());
        }
        out.write_all(&buffer[..read]).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The largest database unpacked (the City database is about 130 MiB).
pub(crate) const UNPACK_LIMIT: u64 = 512 * 1024 * 1024;
