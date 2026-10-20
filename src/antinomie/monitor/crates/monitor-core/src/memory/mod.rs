//! Memory dumps and their analysis with Volatility 3.
//!
//! A dump of a running VM is QEMU's `dump-guest-memory` (an ELF core of the
//! guest's physical memory, written while QEMU keeps the guest paused) in
//! `<recording dir>/memory/<dump>/memory.elf`, beside a JSON summary and the
//! base's Volatility symbol table under `symbols/linux/`. An imported dump
//! keeps its file where it is and gets the same folder for its results.
//!
//! Each plugin run is saved in `runs/<run>/` of its dump: `run.json`, the
//! result as JSON lines (`output.jsonl`: a `columns` line, then one line per
//! row with its tree depth), Volatility's messages (`log.txt`) and the files
//! plugins write with `--dump` (`files/`). Runs are kept, like Run History, so
//! every earlier result can be opened again without running it again.
use serde::{Deserialize, Serialize};
mod results;
pub use results::{RESULT_PAGE_MAX_ROWS, ResultPage, read_result_page_with};
use std::{
    cmp::Ordering,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};

/// Folder of a recording directory that holds memory dumps.
pub const MEMORY_DIR: &str = "memory";
/// File name of a dump taken by Antinomie.
pub const DUMP_FILE: &str = "memory.elf";
const SUMMARY_FILE: &str = "dump.json";
const SYMBOLS_DIR: &str = "symbols";
const RUNS_DIR: &str = "runs";
const RUN_FILE: &str = "run.json";
/// A run's result, as JSON lines.
pub const OUTPUT_FILE: &str = "output.jsonl";
/// Volatility's messages of a run.
pub const LOG_FILE: &str = "log.txt";
/// Files a run's plugin wrote (`--dump` and similar options).
pub const FILES_DIR: &str = "files";
/// The Volatility launcher and result renderer (python3 -I -c).
const LAUNCHER: &str = include_str!("volatility.py");
/// Prebuilt Linux and macOS symbol tables of distribution kernels (about
/// 11,000), looked up by kernel banner when a dump has no table of its own:
/// <https://github.com/Abyss-W4tcher/volatility3-symbols>.
pub const ONLINE_SYMBOLS: &str =
    "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json";
/// Shown with runs that looked up their symbol table online.
pub const ONLINE_SYMBOLS_NAME: &str = "Abyss-W4tcher/volatility3-symbols";

pub mod community;

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

/// Operating system of a dump: which Volatility plugins apply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    #[default]
    Linux,
    Windows,
    Mac,
}

impl Os {
    pub const ALL: [Os; 3] = [Os::Linux, Os::Windows, Os::Mac];
    /// Prefix of its plugin names (`linux.pslist.PsList`).
    pub fn prefix(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Windows => "windows",
            Os::Mac => "mac",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Os::Linux => "Linux",
            Os::Windows => "Windows",
            Os::Mac => "macOS",
        }
    }
}

/// One memory dump: taken from a running VM, or imported.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemoryDump {
    pub id: String,
    /// The VM it was taken from, or whose recordings it was imported into.
    pub vm_id: String,
    pub vm_name: String,
    /// The boot it was taken in; `None` for an imported dump.
    pub boot_id: Option<String>,
    /// The dump file: its name in the dump folder, or (imported) its path.
    pub file: PathBuf,
    pub imported: bool,
    pub os: Os,
    /// Wall clock, milliseconds since the Unix epoch.
    pub started_ms: u64,
    /// `None` while QEMU is still writing it.
    pub finished_ms: Option<u64>,
    pub bytes: Option<u64>,
    pub ram_mib: u32,
    /// The guest kernel or system, as known when it was taken or imported.
    pub system: String,
    /// A symbol table was saved with the dump (`symbols/`).
    pub symbols: bool,
    /// Why the dump failed, if it did.
    pub error: Option<String>,
    /// The dump folder (not saved).
    #[serde(skip)]
    pub dir: PathBuf,
}

impl MemoryDump {
    /// The dump file on disk.
    pub fn path(&self) -> PathBuf {
        if self.imported {
            self.file.clone()
        } else {
            self.dir.join(&self.file)
        }
    }
    pub fn complete(&self) -> bool {
        self.finished_ms.is_some() && self.error.is_none()
    }
    /// The dump file is gone (an imported file moved or deleted).
    pub fn missing(&self) -> bool {
        self.complete() && !self.path().is_file()
    }
    fn summary_path(&self) -> PathBuf {
        self.dir.join(SUMMARY_FILE)
    }
    pub fn save(&self) -> Result<(), String> {
        crate::storage::atomic_json(&self.summary_path(), self)
    }
    fn symbols_dir(&self) -> PathBuf {
        self.dir.join(SYMBOLS_DIR)
    }
    /// Its plugin runs, newest first.
    pub fn runs(&self) -> Vec<PluginRun> {
        let mut runs: Vec<PluginRun> = fs::read_dir(self.dir.join(RUNS_DIR))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let dir = entry.path();
                let mut run: PluginRun =
                    serde_json::from_slice(&fs::read(dir.join(RUN_FILE)).ok()?).ok()?;
                run.dir = dir;
                Some(run)
            })
            .collect();
        runs.sort_by(|a, b| b.started_ms.cmp(&a.started_ms).then(b.id.cmp(&a.id)));
        runs
    }
}

/// A new dump folder in `recording_dir`, with the base's symbol table.
fn create(
    recording_dir: &Path,
    mut dump: MemoryDump,
    symbols: Option<&Path>,
) -> Result<MemoryDump, String> {
    dump.dir = recording_dir.join(MEMORY_DIR).join(&dump.id);
    let memory = recording_dir.join(MEMORY_DIR);
    crate::storage::private_dir(&memory).map_err(|e| format!("{}: {e}", memory.display()))?;
    crate::storage::private_dir(&dump.dir).map_err(|e| format!("memory dump folder: {e}"))?;
    if let Some(symbols) = symbols {
        // Volatility finds Linux tables by banner under <symbol dir>/linux.
        let linux = dump.symbols_dir().join("linux");
        fs::create_dir_all(&linux).map_err(|e| format!("symbol folder: {e}"))?;
        fs::copy(symbols, linux.join(crate::storage::SYMBOLS_FILE))
            .map_err(|e| format!("symbol table: {e}"))?;
        dump.symbols = true;
    }
    dump.save()?;
    Ok(dump)
}

/// A dump of a running VM, before QEMU writes it.
pub fn new_vm_dump(
    recording_dir: &Path,
    vm: &crate::api::VmConfig,
    boot_id: &str,
    system: String,
    symbols: Option<&Path>,
) -> Result<MemoryDump, String> {
    let dump = MemoryDump {
        id: crate::storage::unique_id(),
        vm_id: vm.id.clone(),
        vm_name: vm.name.clone(),
        boot_id: Some(boot_id.into()),
        file: DUMP_FILE.into(),
        os: Os::Linux,
        started_ms: unix_ms(),
        ram_mib: vm.ram_mib,
        system,
        ..MemoryDump::default()
    };
    let dump = create(recording_dir, dump, symbols)?;
    // QEMU truncates the file it is given and keeps its mode: private.
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dump.path())
        .map_err(|e| format!("memory dump file: {e}"))?;
    Ok(dump)
}

/// Import a dump file made elsewhere (raw, LiME, ELF core, crash dump,
/// hibernation file...). The file stays where it is.
pub fn import(
    recording_dir: &Path,
    vm: &crate::api::VmConfig,
    path: &Path,
    os: Os,
    symbols: Option<(&Path, String)>,
) -> Result<MemoryDump, String> {
    let path = fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let metadata = fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    let now = unix_ms();
    let dump = MemoryDump {
        id: crate::storage::unique_id(),
        vm_id: vm.id.clone(),
        vm_name: vm.name.clone(),
        file: path,
        imported: true,
        os,
        started_ms: now,
        finished_ms: Some(now),
        bytes: Some(metadata.len()),
        system: symbols
            .as_ref()
            .map_or_else(|| os.label().into(), |(_, label)| label.clone()),
        ..MemoryDump::default()
    };
    create(recording_dir, dump, symbols.as_ref().map(|(path, _)| *path))
}

/// Every dump in these recording directories, newest first.
pub fn list(recording_dirs: &[PathBuf]) -> Vec<MemoryDump> {
    let mut dumps: Vec<MemoryDump> = recording_dirs
        .iter()
        .flat_map(|root| {
            fs::read_dir(root.join(MEMORY_DIR))
                .into_iter()
                .flatten()
                .flatten()
        })
        .filter_map(|entry| {
            let dir = entry.path();
            let mut dump: MemoryDump =
                serde_json::from_slice(&fs::read(dir.join(SUMMARY_FILE)).ok()?).ok()?;
            dump.dir = dir;
            Some(dump)
        })
        .collect();
    dumps.sort_by(|a, b| b.started_ms.cmp(&a.started_ms).then(b.id.cmp(&a.id)));
    dumps.dedup_by(|a, b| a.dir == b.dir);
    dumps
}

/// Delete a dump with its results. An imported file is left alone.
pub fn delete(dump: &MemoryDump) -> Result<(), String> {
    if dump.dir.file_name().is_none() || !dump.dir.join(SUMMARY_FILE).is_file() {
        return Err("not a memory dump folder".into());
    }
    fs::remove_dir_all(&dump.dir).map_err(|e| format!("{}: {e}", dump.dir.display()))
}

/// QMP command that writes `dump` in the background; QEMU pauses the guest
/// until it is written.
pub fn dump_command(dump: &MemoryDump) -> Result<serde_json::Value, String> {
    let path = dump.path();
    let file = path.to_str().ok_or("memory dump path is not UTF-8")?;
    Ok(serde_json::json!({
        "execute": "dump-guest-memory",
        "arguments": {
            "paging": false,
            "protocol": format!("file:{file}"),
            "detach": true,
            "format": "elf",
        },
    }))
}

pub const QUERY_DUMP: &str = r#"{"execute":"query-dump"}"#;

/// What `query-dump` says about the background dump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpStatus {
    Active {
        completed: u64,
        total: u64,
    },
    Completed,
    Failed,
    /// No dump was started.
    None,
}

pub fn dump_status(reply: &serde_json::Value) -> DumpStatus {
    let count = |key| {
        reply
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    match reply.get("status").and_then(serde_json::Value::as_str) {
        Some("active") => DumpStatus::Active {
            completed: count("completed"),
            total: count("total"),
        },
        Some("completed") => DumpStatus::Completed,
        Some("failed") => DumpStatus::Failed,
        _ => DumpStatus::None,
    }
}

/// The dump being written, for the Memory tab.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DumpProgress {
    pub dump: MemoryDump,
    pub completed: u64,
    pub total: u64,
}

impl DumpProgress {
    /// "Writing RAM dump 41% - VM paused" (no figure before QEMU reports one).
    pub fn status_text(&self) -> String {
        if self.total == 0 || self.completed == 0 {
            "Writing RAM dump - VM paused".into()
        } else {
            let percent =
                (u128::from(self.completed.min(self.total)) * 100 / u128::from(self.total)) as u64;
            format!("Writing RAM dump {percent}% - VM paused")
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunState {
    #[default]
    Running,
    Finished,
    Failed,
    Cancelled,
}

/// One Volatility plugin run on a dump.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginRun {
    pub id: String,
    pub dump_id: String,
    /// Full plugin name, e.g. `linux.pslist.PsList`.
    pub plugin: String,
    /// The plugin's options as given on Volatility's command line.
    pub args: Vec<String>,
    pub started_ms: u64,
    pub finished_ms: Option<u64>,
    pub state: RunState,
    pub exit_code: Option<i32>,
    /// Result rows (top level and nested).
    pub rows: u64,
    /// The last error Volatility reported, for a failed run.
    pub error: Option<String>,
    /// The symbol table index searched online, when the dump had none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols_online: Option<String>,
    /// Its folder (not saved).
    #[serde(skip)]
    pub dir: PathBuf,
}

impl PluginRun {
    /// The plugin name without its module path (`PsList`).
    pub fn short_name(&self) -> &str {
        self.plugin.rsplit('.').next().unwrap_or(&self.plugin)
    }
    pub fn output(&self) -> PathBuf {
        self.dir.join(OUTPUT_FILE)
    }
    pub fn log(&self) -> PathBuf {
        self.dir.join(LOG_FILE)
    }
    pub fn files(&self) -> PathBuf {
        self.dir.join(FILES_DIR)
    }
    fn save(&self) -> Result<(), String> {
        crate::storage::atomic_json(&self.dir.join(RUN_FILE), self)
    }
}

/// Delete one saved run.
pub fn delete_run(run: &PluginRun) -> Result<(), String> {
    if !run.dir.join(RUN_FILE).is_file() {
        return Err("not a plugin run folder".into());
    }
    fs::remove_dir_all(&run.dir).map_err(|e| format!("{}: {e}", run.dir.display()))
}

/// Kind of a plugin option, as Volatility declares it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OptionKind {
    Bool,
    Int,
    #[default]
    String,
    Choice,
    List,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginOption {
    pub name: String,
    pub kind: OptionKind,
    pub help: String,
    pub optional: bool,
    /// Element type of a list option (`int` or `str`).
    pub element: Option<String>,
    pub choices: Vec<String>,
    pub default: Option<serde_json::Value>,
}

impl PluginOption {
    /// Its command-line flag (`decorate_comm` → `--decorate-comm`).
    pub fn flag(&self) -> String {
        format!("--{}", self.name.replace('_', "-"))
    }
}

/// One Volatility plugin with its options.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginInfo {
    pub name: String,
    pub help: String,
    pub options: Vec<PluginOption>,
    /// From the community plugins folder, not Volatility itself.
    pub community: bool,
}

/// The plugins Volatility can run, and the community plugin modules that
/// failed to load.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginCatalog {
    pub plugins: Vec<PluginInfo>,
    pub failures: Vec<String>,
}

/// Folder of community Volatility 3 plugins (`.py` files), passed to
/// Volatility with `-p`. They run as the user, outside any sandbox.
pub fn plugins_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("volatility-plugins")
}

/// Names, sizes and times of the Python files under `dir`: a changed folder
/// lists its plugins again. `None` when it holds none.
fn plugins_fingerprint(dir: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                walk(&path, base, out);
            } else if path.extension().is_some_and(|ext| ext == "py") {
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |time| time.as_nanos());
                out.push(format!(
                    "{} {} {modified}",
                    path.strip_prefix(base).unwrap_or(&path).display(),
                    metadata.len()
                ));
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, dir, &mut files);
    if files.is_empty() {
        return None;
    }
    files.sort();
    let digest = Sha256::digest(files.join("\n").as_bytes());
    Some(digest.iter().take(8).map(|b| format!("{b:02x}")).collect())
}

impl PluginInfo {
    /// Deprecated aliases Volatility keeps for older names.
    pub fn deprecated(&self) -> bool {
        self.help.contains("(deprecated)")
    }
    /// The OS it applies to; `None` for generic plugins (yarascan, timeliner...).
    pub fn os(&self) -> Option<Os> {
        let prefix = self.name.split('.').next()?;
        Os::ALL.into_iter().find(|os| os.prefix() == prefix)
    }
}

/// Command-line arguments for `plugin` from option values typed in the UI
/// (empty values are left out; list values are separated by commas or spaces).
pub fn plugin_args(
    plugin: &PluginInfo,
    values: &[(String, String)],
) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    for option in &plugin.options {
        let Some((_, value)) = values.iter().find(|(name, _)| *name == option.name) else {
            continue;
        };
        let value = value.trim();
        match option.kind {
            OptionKind::Bool => {
                if value == "true" {
                    args.push(option.flag());
                }
            }
            _ if value.is_empty() => {}
            OptionKind::Int => {
                parse_int(value)
                    .ok_or_else(|| format!("{}: not a number: {value}", option.name))?;
                args.extend([option.flag(), value.into()]);
            }
            OptionKind::List => {
                args.push(option.flag());
                for item in value.split([',', ' ']).filter(|item| !item.is_empty()) {
                    if option.element.as_deref() == Some("int") && parse_int(item).is_none() {
                        return Err(format!("{}: not a number: {item}", option.name));
                    }
                    args.push(item.into());
                }
            }
            OptionKind::Choice => {
                if !option.choices.iter().any(|choice| choice == value) {
                    return Err(format!(
                        "{}: choose one of {}",
                        option.name,
                        option.choices.join(", ")
                    ));
                }
                args.extend([option.flag(), value.into()]);
            }
            OptionKind::String => args.extend([option.flag(), value.into()]),
        }
    }
    Ok(args)
}

fn parse_int(text: &str) -> Option<i128> {
    let (negative, digits) = text
        .strip_prefix('-')
        .map_or((false, text), |rest| (true, rest));
    let value = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => i128::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<i128>().ok()?,
    };
    Some(if negative { -value } else { value })
}

/// Volatility 3 as Antinomie installed it, run by the system Python 3.
#[derive(Clone, Debug)]
pub struct Volatility {
    python: PathBuf,
    root: PathBuf,
    community: PathBuf,
    pub version: String,
}

/// Python interpreters tried, in order.
const PYTHONS: &[&str] = &["/usr/bin/python3", "/usr/local/bin/python3"];

impl Volatility {
    /// The installed Volatility, or why it cannot run.
    pub fn locate(data_dir: &Path) -> Result<Self, String> {
        let package =
            crate::analysis_tools::package("volatility3").ok_or("no Volatility package")?;
        let root = crate::analysis_tools::tools_dir(data_dir).join(package.id);
        let installed = crate::analysis_tools::statuses(data_dir)
            .into_iter()
            .find(|status| status.id == package.id)
            .and_then(|status| status.installed)
            .ok_or("Volatility 3 is not installed: install it in Tools → Analysis tools")?;
        let python = PYTHONS
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .ok_or("Volatility needs Python 3 (/usr/bin/python3): install the python3 package")?;
        Ok(Volatility {
            python,
            root,
            community: plugins_dir(data_dir),
            version: installed,
        })
    }

    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(&self.python);
        // -I: no user site packages, no PYTHON* variables, no script folder.
        command
            .arg("-I")
            .arg("-c")
            .arg(LAUNCHER)
            .arg(self.root.join("lib"))
            .arg(mode)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::null());
        command
    }

    /// Every plugin with its options, community ones included; cached per
    /// Volatility version and community folder contents.
    pub fn plugins(&self) -> Result<PluginCatalog, String> {
        let fingerprint = plugins_fingerprint(&self.community);
        let cache = self.root.join(format!(
            "catalog-{}-{}.json",
            self.version,
            fingerprint.as_deref().unwrap_or("official")
        ));
        if let Ok(bytes) = fs::read(&cache)
            && let Ok(catalog) = serde_json::from_slice(&bytes)
        {
            return Ok(catalog);
        }
        let mut command = self.command("describe");
        if fingerprint.is_some() {
            command.arg(&self.community);
        }
        let output = command
            .output()
            .map_err(|e| format!("{}: {e}", self.python.display()))?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "Volatility could not list its plugins: {}",
                message.lines().last().unwrap_or("no message")
            ));
        }
        let catalog: PluginCatalog =
            serde_json::from_slice(&output.stdout).map_err(|e| format!("plugin list: {e}"))?;
        // One cached catalog: drop those of other versions or folder contents.
        for entry in fs::read_dir(&self.root).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.starts_with("catalog-") || name.starts_with("plugins-"))
                && name.ends_with(".json")
            {
                let _ = fs::remove_file(entry.path());
            }
        }
        let _ = fs::write(&cache, &output.stdout);
        Ok(catalog)
    }

    /// Start `plugin` on `dump` in the background. A Linux or macOS dump
    /// without its own symbol table has it looked up online when
    /// `online_symbols` is set (after Volatility's local folders).
    pub fn start(
        &self,
        dump: &MemoryDump,
        plugin: &str,
        args: Vec<String>,
        online_symbols: bool,
    ) -> Result<RunHandle, String> {
        if !dump.complete() {
            return Err("this dump is not complete".into());
        }
        if dump.missing() {
            return Err(format!("the dump file is gone: {}", dump.path().display()));
        }
        if plugin.is_empty()
            || !plugin
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_')
        {
            return Err(format!("invalid plugin name {plugin:?}"));
        }
        // The dump's own table, and those community plugins bring;
        // Volatility separates its symbol folders with semicolons.
        let mut dirs = community::symbol_dirs(&self.community);
        if dump.symbols {
            dirs.insert(0, dump.symbols_dir());
        }
        let mut symbol_dirs: Option<std::ffi::OsString> = None;
        for dir in dirs {
            if dir.as_os_str().as_encoded_bytes().contains(&b';') {
                return Err(format!("{}: a ';' in the path", dir.display()));
            }
            let joined = symbol_dirs.get_or_insert_with(Default::default);
            if !joined.is_empty() {
                joined.push(";");
            }
            joined.push(dir);
        }
        let runs = dump.dir.join(RUNS_DIR);
        crate::storage::private_dir(&runs).map_err(|e| format!("{}: {e}", runs.display()))?;
        let run = PluginRun {
            id: crate::storage::unique_id(),
            dump_id: dump.id.clone(),
            plugin: plugin.into(),
            args,
            started_ms: unix_ms(),
            symbols_online: (online_symbols && !dump.symbols && dump.os != Os::Windows)
                .then(|| ONLINE_SYMBOLS.to_owned()),
            ..PluginRun::default()
        };
        let run = PluginRun {
            dir: runs.join(&run.id),
            ..run
        };
        crate::storage::private_dir(&run.dir).map_err(|e| format!("plugin run folder: {e}"))?;
        crate::storage::private_dir(&run.files()).map_err(|e| format!("plugin run files: {e}"))?;
        run.save()?;
        let cache = self.root.join("cache");
        let _ = fs::create_dir_all(&cache);
        let mut command = self.command("run");
        command
            .arg("-r")
            .arg("antinomie")
            .arg("--cache-path")
            .arg(&cache)
            .arg("-o")
            .arg(run.files())
            .arg("-f")
            .arg(dump.path());
        if plugins_fingerprint(&self.community).is_some() {
            command.arg("-p").arg(&self.community);
        }
        if let Some(dirs) = &symbol_dirs {
            command.arg("-s").arg(dirs);
        }
        if dump.symbols {
            // The base's own table: nothing to look up online.
            command.arg("--offline");
        } else if let Some(index) = &run.symbols_online {
            command.arg("--remote-isf-url").arg(index);
        }
        command.arg(plugin).args(&run.args);
        let output = File::create(run.output()).map_err(|e| format!("plugin output: {e}"))?;
        let child = command
            .current_dir(&run.dir)
            .stdout(output)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{}: {e}", self.python.display()));
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                let failed = PluginRun {
                    state: RunState::Failed,
                    finished_ms: Some(unix_ms()),
                    error: Some(error.clone()),
                    ..run
                };
                let _ = failed.save();
                return Err(error);
            }
        };
        let stderr = child.stderr.take().ok_or("plugin messages")?;
        let shared = Arc::new(Mutex::new(Progress::default()));
        let process = Arc::new(Mutex::new(Some(child)));
        let handle = RunHandle {
            run: run.clone(),
            progress: shared.clone(),
            process: process.clone(),
        };
        thread::Builder::new()
            .name("antinomie-volatility".into())
            .spawn(move || watch(run, stderr, shared, process))
            .map_err(|e| e.to_string())?;
        Ok(handle)
    }
}

/// Live progress of a plugin run.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Progress {
    /// Percent of Volatility's current step.
    pub percent: f32,
    pub step: String,
    /// The finished run, once Volatility exited.
    pub finished: Option<PluginRun>,
    cancelled: bool,
}

/// A plugin run in progress.
#[derive(Clone, Debug)]
pub struct RunHandle {
    /// The run as it started.
    pub run: PluginRun,
    progress: Arc<Mutex<Progress>>,
    process: Arc<Mutex<Option<Child>>>,
}

impl RunHandle {
    pub fn progress(&self) -> Progress {
        self.progress.lock().map(|p| p.clone()).unwrap_or_default()
    }
    pub fn cancel(&self) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.cancelled = true;
        }
        if let Ok(mut process) = self.process.lock()
            && let Some(child) = process.as_mut()
        {
            let _ = child.kill();
        }
    }
}

/// Follow Volatility's messages until it exits, then save the run.
fn watch(
    mut run: PluginRun,
    stderr: std::process::ChildStderr,
    progress: Arc<Mutex<Progress>>,
    process: Arc<Mutex<Option<Child>>>,
) {
    let mut log = File::create(run.log()).ok();
    if let (Some(log), Some(_)) = (log.as_mut(), &run.symbols_online) {
        let _ = writeln!(
            log,
            "Symbol table: Volatility's folders, then {ONLINE_SYMBOLS_NAME} (online)"
        );
    }
    let mut reader = BufReader::new(stderr);
    let mut last_error = None;
    let mut no_symbols = false;
    let mut line = Vec::new();
    // Progress lines end in a carriage return, messages in a newline.
    loop {
        line.clear();
        let mut byte = [0u8];
        let mut ended = false;
        loop {
            match reader.read(&mut byte) {
                Ok(1) if byte[0] == b'\r' || byte[0] == b'\n' => break,
                Ok(1) => line.push(byte[0]),
                _ => {
                    ended = true;
                    break;
                }
            }
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end();
        if let Some(rest) = text.trim_start().strip_prefix("Progress:") {
            let rest = rest.trim_start();
            let (number, step) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            if let (Ok(percent), Ok(mut progress)) = (number.parse::<f32>(), progress.lock()) {
                progress.percent = percent;
                progress.step = step.trim().into();
            }
        } else if !text.trim().is_empty() {
            if let Some(log) = log.as_mut() {
                let _ = writeln!(log, "{text}");
            }
            if text.contains("rror") || text.starts_with("Unsatisfied") {
                last_error = Some(text.trim().to_owned());
            }
            no_symbols |= text.contains("symbol_table_name");
        }
        if ended {
            break;
        }
    }
    let status = process
        .lock()
        .ok()
        .and_then(|mut process| process.take())
        .and_then(|mut child| child.wait().ok());
    let cancelled = progress.lock().map(|p| p.cancelled).unwrap_or(false);
    run.finished_ms = Some(unix_ms());
    run.exit_code = status.and_then(|status| status.code());
    run.rows = count_rows(&run.output());
    run.state = if cancelled {
        RunState::Cancelled
    } else if status.is_some_and(|status| status.success()) {
        RunState::Finished
    } else {
        run.error = Some(if no_symbols {
            no_symbols_message(&run)
        } else {
            last_error.unwrap_or_else(|| "Volatility failed; see its messages".into())
        });
        RunState::Failed
    };
    let _ = run.save();
    if let Ok(mut progress) = progress.lock() {
        progress.finished = Some(run);
    }
}

/// Why a run found no symbol table, and what helps.
fn no_symbols_message(run: &PluginRun) -> String {
    if run.symbols_online.is_some() {
        format!(
            "No symbol table matches this dump's kernel, in Volatility's folders or in \
             {ONLINE_SYMBOLS_NAME}. Run banners.Banners to see the kernel; its table can \
             be made with dwarf2json from the kernel's debug package."
        )
    } else {
        "No symbol table matches this dump's kernel. Turn on online symbol tables in the \
         Memory tab, or import the dump with the table of the base it was taken from."
            .into()
    }
}

fn count_rows(path: &Path) -> u64 {
    File::open(path)
        .map(|file| {
            BufReader::new(file)
                .lines()
                .map_while(Result::ok)
                .filter(|line| line.starts_with("{\"d\":"))
                .count() as u64
        })
        .unwrap_or(0)
}

/// Kind of a result column, for display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColumnKind {
    Int,
    Hex,
    Bin,
    Bool,
    Bytes,
    Time,
    Disasm,
    #[default]
    Str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ColumnKind,
}

/// One result row: its depth in the result tree and its values (JSON; an
/// absent value is `{"absent": "<reason>"}`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResultRow {
    pub depth: u16,
    pub values: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResultTable {
    pub columns: Vec<Column>,
    pub rows: Vec<ResultRow>,
    /// More rows than `limit` were saved.
    pub truncated: bool,
}

/// Read a saved result (at most `limit` rows).
pub fn read_result(path: &Path, limit: usize) -> Result<ResultTable, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = BufReader::new(file).lines();
    let mut table = ResultTable::default();
    #[derive(Deserialize)]
    struct Header {
        columns: Vec<Column>,
    }
    #[derive(Deserialize)]
    struct Row {
        d: u16,
        v: Vec<serde_json::Value>,
    }
    if let Some(first) = lines.next() {
        let first = first.map_err(|e| e.to_string())?;
        let header: Header =
            serde_json::from_str(&first).map_err(|e| format!("result columns: {e}"))?;
        table.columns = header.columns;
    }
    for line in lines {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        if table.rows.len() >= limit {
            table.truncated = true;
            break;
        }
        // A run cut short can leave a partial last line, and results saved
        // before plugin prints were kept out of them can hold such lines.
        let Ok(row) = serde_json::from_str::<Row>(&line) else {
            continue;
        };
        table.rows.push(ResultRow {
            depth: row.d,
            values: row.v,
        });
    }
    Ok(table)
}

/// A value as text, the way the result table shows and copies it.
pub fn value_text(kind: ColumnKind, value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => String::new(),
        Value::Object(map) => match map.get("absent").and_then(Value::as_str) {
            Some("NotApplicableValue") => "N/A".into(),
            Some("UnreadableValue") => "Unreadable".into(),
            Some("UnparsableValue") => "Unparsable".into(),
            Some(_) => "-".into(),
            None => value.to_string(),
        },
        Value::Number(number) => match (kind, number.as_u64(), number.as_i64()) {
            (ColumnKind::Hex, Some(n), _) => format!("{n:#x}"),
            (ColumnKind::Hex, None, Some(n)) => format!("-{:#x}", n.unsigned_abs()),
            (ColumnKind::Bin, Some(n), _) => format!("{n:#b}"),
            _ => number.to_string(),
        },
        Value::Bool(flag) => flag.to_string(),
        Value::String(text) => text.clone(),
        Value::Array(_) => value.to_string(),
    }
}

/// An absent value (`N/A`, unreadable...) or none at all.
fn is_absent(value: &serde_json::Value) -> bool {
    value.is_null() || value.get("absent").is_some()
}

/// Order of two values of one column: numbers by value, text ignoring case,
/// then the rest by their text.
pub fn compare_values(a: &serde_json::Value, b: &serde_json::Value) -> Ordering {
    use serde_json::Value;
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(x), Some(y)) => x.cmp(&y),
            _ => match (x.as_u64(), y.as_u64()) {
                (Some(x), Some(y)) => x.cmp(&y),
                _ => {
                    let (x, y) = (x.as_f64().unwrap_or(0.0), y.as_f64().unwrap_or(0.0));
                    x.partial_cmp(&y).unwrap_or(Ordering::Equal)
                }
            },
        },
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => x
            .to_lowercase()
            .cmp(&y.to_lowercase())
            .then_with(|| x.cmp(y)),
        (Value::Number(_), _) => Ordering::Less,
        (_, Value::Number(_)) => Ordering::Greater,
        _ => a.to_string().cmp(&b.to_string()),
    }
}

/// `rows` (indices into `table.rows`) ordered by `column`; rows of equal
/// value keep their order, and absent values stay last either way.
pub fn sort_rows(table: &ResultTable, rows: &mut [usize], column: usize, descending: bool) {
    let value = |row: usize| table.rows[row].values.get(column);
    rows.sort_by(|&a, &b| match (value(a), value(b)) {
        (Some(x), Some(y)) => match (is_absent(x), is_absent(y)) {
            (false, false) if descending => compare_values(y, x),
            (false, false) => compare_values(x, y),
            (x, y) => x.cmp(&y),
        },
        (x, y) => y.is_some().cmp(&x.is_some()),
    });
}

/// `rows` of the result as Volatility prints them by default (its quick text
/// renderer): a header line, then tab-separated values, nested rows marked
/// with a `*` per level.
pub fn result_text(table: &ResultTable, rows: &[usize]) -> String {
    use std::fmt::Write as _;
    let mut text = String::from("\n");
    let names: Vec<&str> = table.columns.iter().map(|c| c.name.as_str()).collect();
    text.push_str(&names.join("\t"));
    text.push('\n');
    for &index in rows {
        let row = &table.rows[index];
        text.push('\n');
        if row.depth > 0 {
            let _ = write!(text, "{} ", "*".repeat(row.depth as usize));
        }
        let values: Vec<String> = row
            .values
            .iter()
            .zip(&table.columns)
            .map(|(value, column)| match value {
                // As Python prints them.
                serde_json::Value::Bool(true) => "True".into(),
                serde_json::Value::Bool(false) => "False".into(),
                _ => value_text(column.kind, value),
            })
            .collect();
        text.push_str(&values.join("\t"));
    }
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm() -> crate::api::VmConfig {
        crate::api::VmConfig {
            id: "vm".into(),
            name: "Sample".into(),
            ram_mib: 1024,
            ..crate::api::VmConfig::default()
        }
    }

    fn temp(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ant-memory-{name}-{}", crate::storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn vm_dumps_are_listed_with_their_symbols_and_runs() {
        let root = temp("list");
        let symbols = root.join("isf.json.xz");
        fs::write(&symbols, b"isf").unwrap();
        let mut dump =
            new_vm_dump(&root, &vm(), "boot", "Linux 6.12.94".into(), Some(&symbols)).unwrap();
        assert!(
            dump.path()
                .ends_with("memory/".to_owned() + &dump.id + "/memory.elf")
        );
        assert_eq!(
            fs::read(dump.dir.join("symbols/linux/symbols.json.xz")).unwrap(),
            b"isf"
        );
        assert!(!dump.complete());
        dump.finished_ms = Some(dump.started_ms + 1);
        dump.bytes = Some(4096);
        dump.save().unwrap();
        let listed = list(std::slice::from_ref(&root));
        assert_eq!(listed, vec![dump.clone()]);
        assert!(listed[0].complete() && listed[0].symbols);

        let run = PluginRun {
            id: "r1".into(),
            plugin: "linux.pslist.PsList".into(),
            started_ms: 5,
            dir: dump.dir.join(RUNS_DIR).join("r1"),
            ..PluginRun::default()
        };
        fs::create_dir_all(&run.dir).unwrap();
        run.save().unwrap();
        assert_eq!(dump.runs(), vec![run.clone()]);
        assert_eq!(run.short_name(), "PsList");
        delete_run(&run).unwrap();
        assert!(dump.runs().is_empty());
        delete(&dump).unwrap();
        assert!(list(std::slice::from_ref(&root)).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn community_folder_changes_are_noticed() {
        let root = temp("community");
        let dir = plugins_dir(&root);
        assert_eq!(plugins_fingerprint(&dir), None, "no folder");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("notes.txt"), b"not a plugin").unwrap();
        assert_eq!(plugins_fingerprint(&dir), None, "no Python files");
        fs::write(dir.join("sub/one.py"), b"x = 1").unwrap();
        let first = plugins_fingerprint(&dir).unwrap();
        assert_eq!(plugins_fingerprint(&dir).as_ref(), Some(&first));
        fs::write(dir.join("sub/one.py"), b"x = 22").unwrap();
        assert_ne!(plugins_fingerprint(&dir).unwrap(), first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn imported_dumps_stay_in_place() {
        let root = temp("import");
        let file = root.join("guest.lime");
        fs::write(&file, vec![0u8; 100]).unwrap();
        let dump = import(&root, &vm(), &file, Os::Windows, None).unwrap();
        assert!(dump.imported && dump.complete() && !dump.symbols);
        assert_eq!(dump.path(), fs::canonicalize(&file).unwrap());
        assert_eq!(dump.bytes, Some(100));
        assert_eq!(dump.system, "Windows");
        delete(&dump).unwrap();
        assert!(file.is_file(), "the imported file is not deleted");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qmp_dump_command_and_status() {
        let dump = MemoryDump {
            dir: "/rec/memory/d1".into(),
            file: DUMP_FILE.into(),
            ..MemoryDump::default()
        };
        let command = dump_command(&dump).unwrap();
        assert_eq!(command["execute"], "dump-guest-memory");
        assert_eq!(
            command["arguments"]["protocol"],
            "file:/rec/memory/d1/memory.elf"
        );
        assert_eq!(command["arguments"]["detach"], true);
        assert_eq!(command["arguments"]["paging"], false);
        let reply = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap();
        assert_eq!(
            dump_status(&reply(r#"{"status":"active","completed":10,"total":40}"#)),
            DumpStatus::Active {
                completed: 10,
                total: 40
            }
        );
        assert_eq!(
            dump_status(&reply(
                r#"{"status":"completed","completed":40,"total":40}"#
            )),
            DumpStatus::Completed
        );
        assert_eq!(
            dump_status(&reply(r#"{"status":"failed"}"#)),
            DumpStatus::Failed
        );
        assert_eq!(
            dump_status(&reply(r#"{"status":"none"}"#)),
            DumpStatus::None
        );
    }

    #[test]
    fn option_values_become_volatility_arguments() {
        let plugin: PluginInfo = serde_json::from_str(
            r#"{"name":"linux.pslist.PsList","help":"Lists the processes","options":[
                {"name":"pid","kind":"list","element":"int","optional":true},
                {"name":"decorate_comm","kind":"bool","optional":true},
                {"name":"dump","kind":"bool","optional":true},
                {"name":"maxsize","kind":"int","optional":true},
                {"name":"format","kind":"choice","choices":["gz","none"],"optional":true},
                {"name":"find","kind":"string","optional":true}]}"#,
        )
        .unwrap();
        assert_eq!(plugin.os(), Some(Os::Linux));
        let values = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect()
        };
        assert_eq!(
            plugin_args(
                &plugin,
                &values(&[
                    ("pid", "1, 42 0x10"),
                    ("decorate_comm", "true"),
                    ("dump", "false"),
                    ("maxsize", "0x1000"),
                    ("format", "gz"),
                    ("find", "/etc/passwd"),
                ])
            )
            .unwrap(),
            [
                "--pid",
                "1",
                "42",
                "0x10",
                "--decorate-comm",
                "--maxsize",
                "0x1000",
                "--format",
                "gz",
                "--find",
                "/etc/passwd"
            ]
        );
        assert!(plugin_args(&plugin, &values(&[("pid", "init")])).is_err());
        assert!(plugin_args(&plugin, &values(&[("format", "zip")])).is_err());
        assert!(
            plugin_args(&plugin, &values(&[("pid", " ")]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn results_are_read_as_typed_columns_and_tree_rows() {
        let root = temp("result");
        let path = root.join(OUTPUT_FILE);
        fs::write(
            &path,
            concat!(
                r#"{"columns":[{"name":"OFFSET","type":"hex"},{"name":"PID","type":"int"},{"name":"COMM","type":"str"},{"name":"File output","type":"str"}]}"#,
                "\n",
                r#"{"d":0,"v":[18446612686364999680,1,"systemd",{"absent":"NotApplicableValue"}]}"#,
                "\n",
                r#"{"d":1,"v":[18446612682071001088,100,"sh",{"absent":"UnreadableValue"}]}"#,
                "\n",
                r#"{"d":0,"v":[1"#,
            ),
        )
        .unwrap();
        let table = read_result(&path, 10).unwrap();
        assert_eq!(table.columns.len(), 4);
        assert_eq!(table.columns[0].kind, ColumnKind::Hex);
        assert_eq!(table.rows.len(), 2, "the partial last line is dropped");
        assert_eq!(table.rows[1].depth, 1);
        assert_eq!(
            value_text(ColumnKind::Hex, &table.rows[0].values[0]),
            "0xffff888100000000"
        );
        assert_eq!(value_text(ColumnKind::Str, &table.rows[0].values[3]), "N/A");
        assert_eq!(
            value_text(ColumnKind::Str, &table.rows[1].values[3]),
            "Unreadable"
        );
        let one = read_result(&path, 1).unwrap();
        assert!(one.truncated && one.rows.len() == 1);
        assert_eq!(count_rows(&path), 3);
        fs::remove_dir_all(root).unwrap();
    }

    fn sample_table() -> ResultTable {
        use serde_json::json;
        let column = |name: &str, kind| Column {
            name: name.into(),
            kind,
        };
        let row = |depth, values: Vec<serde_json::Value>| ResultRow { depth, values };
        ResultTable {
            columns: vec![
                column("PID", ColumnKind::Int),
                column("COMM", ColumnKind::Str),
            ],
            rows: vec![
                row(0, vec![json!(10), json!("sshd")]),
                row(1, vec![json!(200), json!("Bash")]),
                row(
                    0,
                    vec![json!({"absent": "NotApplicableValue"}), json!("kthreadd")],
                ),
                row(0, vec![json!(9), json!("agetty")]),
            ],
            truncated: false,
        }
    }

    #[test]
    fn result_rows_sort_by_value_with_absent_values_last() {
        let table = sample_table();
        let mut rows = vec![0, 1, 2, 3];
        sort_rows(&table, &mut rows, 0, false);
        assert_eq!(rows, vec![3, 0, 1, 2]);
        sort_rows(&table, &mut rows, 0, true);
        assert_eq!(rows, vec![1, 0, 3, 2]);
        sort_rows(&table, &mut rows, 1, false);
        assert_eq!(rows, vec![3, 1, 2, 0], "text ignores case");
    }

    #[test]
    fn results_render_as_volatility_text() {
        let table = sample_table();
        assert_eq!(
            result_text(&table, &[0, 1, 2]),
            "\nPID\tCOMM\n\n10\tsshd\n* 200\tBash\nN/A\tkthreadd\n"
        );
    }

    #[test]
    fn lines_a_plugin_printed_among_the_rows_are_skipped() {
        let root = temp("stray");
        let path = root.join(OUTPUT_FILE);
        fs::write(
            &path,
            "{\"columns\":[{\"name\":\"A\",\"type\":\"str\"}]}\n\
             Searching from 11 Oct 2026\n{\"d\":0,\"v\":[\"x\"]}\n{\"d\":0,\"v\":[\"y\"]}\n",
        )
        .unwrap();
        assert_eq!(read_result(&path, 10).unwrap().rows.len(), 2);
        assert_eq!(count_rows(&path), 2);
        fs::remove_dir_all(root).unwrap();
    }
}
