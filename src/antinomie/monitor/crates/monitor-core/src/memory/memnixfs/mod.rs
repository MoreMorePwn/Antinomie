// SPDX-License-Identifier: GPL-3.0-only
//! MemNixFS (<https://github.com/MemNixFS/MemNixFS>) as the second analysis
//! backend of the Memory tab.
//!
//! MemNixFS reads a Linux physical-memory dump and presents the kernel state
//! it finds as a virtual filesystem (`/json/pslist.json`,
//! `/sys/findevil/triage.txt`, `/fs` with recovered file contents...). A run
//! here is one **report**: a path of that filesystem. The tool exports it with
//! `memnixfs export`, and the result is saved like a Volatility run (`run.json`,
//! `output.jsonl`, `log.txt`, `files/` with the raw export) so the Memory tab's
//! table, filters, messages and Files button work unchanged.
//!
//! The tool never sees more than it needs. It runs in the same bubblewrap
//! profile as the other analysis tools: no network (it is offline by design:
//! `--no-http-cache`, no symbol download), the dump and the dump's symbol
//! table read-only, a private working folder, no home directory. Only
//! whole-guest physical-memory dumps are passed to it (see [`format`]).
use super::{Analyzer, MemoryDump, Os, PluginRun, Progress, RunHandle, RunState, unix_ms};
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, atomic::AtomicBool, atomic::Ordering},
    thread,
    time::Duration,
};

mod convert;
pub mod format;
mod messages;
pub use format::DumpFormat;

/// How long one report may take, from start to the saved result.
const RUN_TIMEOUT: Duration = Duration::from_secs(45 * 60);
/// Address space of the tool beyond the dump it maps, in octets.
const ADDRESS_SPACE_EXTRA_SIZE: u64 = 6 * 1024 * 1024 * 1024;
/// Lower bound of its address space, in octets.
const ADDRESS_SPACE_MIN_SIZE: u64 = 8 * 1024 * 1024 * 1024;
/// File name of the package's tool inside its directory.
const PROGRAM: &str = "memnixfs";

/// How a report's file becomes a result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A JSON list of records, as a table.
    Table,
    /// A text report, one line per row.
    Text,
    /// A folder of recovered files: listed with sizes and hashes, kept in
    /// the run's `files/`.
    Files,
}

/// One thing MemNixFS can show of a dump: a path of its virtual filesystem.
#[derive(Debug)]
pub struct Report {
    /// The name after `memnixfs.` in the run (`processes`).
    pub name: &'static str,
    /// Group in the report picker.
    pub area: &'static str,
    pub help: &'static str,
    /// Path in MemNixFS's filesystem.
    pub path: &'static str,
    pub kind: Kind,
    /// Columns shown first (tables).
    pub columns: &'static [&'static str],
}

const PROCESS_COLUMNS: &[&str] = &["pid", "tgid", "ppid", "uid", "comm", "cmdline"];

pub const REPORTS: &[Report] = &[
    Report {
        name: "processes",
        area: "Processes",
        help: "Processes found by walking the kernel's task list",
        path: "/json/pslist.json",
        kind: Kind::Table,
        columns: PROCESS_COLUMNS,
    },
    Report {
        name: "process_tree",
        area: "Processes",
        help: "The same processes as a tree by parent",
        path: "/sys/processes/pstree.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "process_scan",
        area: "Processes",
        help: "Processes found by scanning memory, to compare with the task list (hidden processes)",
        path: "/sys/findevil/psscan.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "threads",
        area: "Processes",
        help: "Threads of every process",
        path: "/sys/processes/threads.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "tcp",
        area: "Network",
        help: "TCP sockets in the kernel's tables",
        path: "/json/net_tcp.json",
        kind: Kind::Table,
        columns: &[],
    },
    Report {
        name: "udp",
        area: "Network",
        help: "UDP sockets in the kernel's tables",
        path: "/json/net_udp.json",
        kind: Kind::Table,
        columns: &[],
    },
    Report {
        name: "triage",
        area: "Threat hunting",
        help: "Ranked summary of the threat-hunting findings",
        path: "/sys/findevil/triage.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "indicators",
        area: "Threat hunting",
        help: "Every indicator with severity, confidence and evidence",
        path: "/json/findevil_indicators.json",
        kind: Kind::Table,
        columns: &[
            "severity",
            "type",
            "pid",
            "comm",
            "summary",
            "evidence",
            "confidence",
        ],
    },
    Report {
        name: "findings",
        area: "Threat hunting",
        help: "Threat-hunting counters (kernel hooks, hidden objects)",
        path: "/json/findevil.json",
        kind: Kind::Table,
        columns: &[],
    },
    Report {
        name: "malfind",
        area: "Threat hunting",
        help: "Injected or anomalous memory regions of processes",
        path: "/json/malfind.json",
        kind: Kind::Table,
        columns: &["pid", "comm"],
    },
    Report {
        name: "yara",
        area: "Threat hunting",
        help: "Built-in YARA rules run over the recovered memory",
        path: "/json/yara.json",
        kind: Kind::Table,
        columns: &[],
    },
    Report {
        name: "iocs",
        area: "Threat hunting",
        help: "URLs, addresses, e-mail addresses and keys found in process memory",
        path: "/json/iocs.json",
        kind: Kind::Table,
        columns: &["type", "value", "pid", "comm"],
    },
    Report {
        name: "syscall_table",
        area: "Kernel",
        help: "System call table check for hooks",
        path: "/sys/findevil/check_syscall.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "modules",
        area: "Kernel",
        help: "Loaded kernel modules",
        path: "/sys/modules/modules.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "hidden_modules",
        area: "Kernel",
        help: "Kernel modules missing from the module list",
        path: "/sys/findevil/hidden_modules.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "banner",
        area: "Kernel",
        help: "The kernel's version banner",
        path: "/sys/banner.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "memory_ranges",
        area: "Kernel",
        help: "Which physical address ranges the dump actually holds",
        path: "/sys/mem_ranges.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "dmesg",
        area: "Logs and history",
        help: "The kernel log (printk ring buffer)",
        path: "/sys/dmesg",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "shell_history",
        area: "Logs and history",
        help: "Shell history recovered from process memory",
        path: "/sys/shell_history.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "timeline",
        area: "Logs and history",
        help: "Everything MemNixFS dated, on one UTC time line",
        path: "/forensic/timeline.txt",
        kind: Kind::Text,
        columns: &[],
    },
    Report {
        name: "recovered_files",
        area: "Recovered files",
        help: "Files rebuilt from the page cache; contents are kept under Files",
        path: "/fs",
        kind: Kind::Files,
        columns: &[],
    },
];

/// The report a run name (`memnixfs.processes` or `processes`) stands for.
pub fn report(name: &str) -> Option<&'static Report> {
    let name = name.strip_prefix("memnixfs.").unwrap_or(name);
    REPORTS.iter().find(|report| report.name == name)
}

impl Report {
    /// The name saved in a run's `plugin`.
    pub fn plugin(&self) -> String {
        format!("memnixfs.{}", self.name)
    }
}

/// MemNixFS as Antinomie installed it.
#[derive(Clone, Debug)]
pub struct MemNixFs {
    root: PathBuf,
    tools: PathBuf,
    pub version: String,
}

impl MemNixFs {
    /// The installed tool, or why it cannot run: not installed, no
    /// bubblewrap, or a system library it needs is missing.
    pub fn locate(data_dir: &Path) -> Result<Self, String> {
        let package = crate::analysis_tools::package("memnixfs").ok_or("no MemNixFS package")?;
        let tools = crate::analysis_tools::tools_dir(data_dir);
        let installed = crate::analysis_tools::statuses(data_dir)
            .into_iter()
            .find(|status| status.id == package.id)
            .and_then(|status| status.installed)
            .ok_or("MemNixFS is not installed: install it in Tools → Analysis tools")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "util-linux")?;
        let root = tools.join(package.id);
        let output = Command::new(root.join(PROGRAM))
            .arg("--help")
            .env_clear()
            .env("LD_LIBRARY_PATH", root.join("lib"))
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("{}: {e}", root.join(PROGRAM).display()))?;
        if !output.status.success() {
            return Err(messages::startup_problem(&String::from_utf8_lossy(
                &output.stderr,
            )));
        }
        Ok(MemNixFs {
            root,
            tools,
            version: installed,
        })
    }

    /// Run `report` on `dump` in the background and save the result with the
    /// dump. Refuses anything but a complete Linux dump of the guest's
    /// physical memory.
    pub fn start(&self, dump: &MemoryDump, report: &str) -> Result<RunHandle, String> {
        let report = self::report(report).ok_or_else(|| format!("unknown report {report:?}"))?;
        if !dump.complete() {
            return Err("this dump is not complete".into());
        }
        if dump.missing() {
            return Err(format!("the dump file is gone: {}", dump.path().display()));
        }
        if dump.os != Os::Linux {
            return Err(format!(
                "MemNixFS reads Linux memory; this dump is {}",
                dump.os.label()
            ));
        }
        let path = dump.path();
        let format = format::classify(&path)?;
        let size = fs::metadata(&path).map_or(0, |metadata| metadata.len());
        let symbols = dump
            .symbols
            .then(|| {
                dump.symbols_dir()
                    .join("linux")
                    .join(crate::storage::SYMBOLS_FILE)
            })
            .filter(|symbols| symbols.is_file());
        let runs = dump.dir.join(super::RUNS_DIR);
        crate::storage::private_dir(&runs).map_err(|e| format!("{}: {e}", runs.display()))?;
        let run = PluginRun {
            id: crate::storage::unique_id(),
            dump_id: dump.id.clone(),
            plugin: report.plugin(),
            started_ms: unix_ms(),
            analyzer: Analyzer::MemNixFs,
            tool_version: Some(self.version.clone()),
            dump_format: Some(format.label()),
            ..PluginRun::default()
        };
        let run = PluginRun {
            dir: runs.join(&run.id),
            ..run
        };
        crate::storage::private_dir(&run.dir).map_err(|e| format!("plugin run folder: {e}"))?;
        crate::storage::private_dir(&run.files()).map_err(|e| format!("plugin run files: {e}"))?;
        crate::storage::private_dir(&work_dir(&run))
            .map_err(|e| format!("plugin run work folder: {e}"))?;
        run.save()?;
        let job = Job {
            tools: self.tools.clone(),
            dump: path,
            symbols,
            report,
            address_space_size: (size + ADDRESS_SPACE_EXTRA_SIZE).max(ADDRESS_SPACE_MIN_SIZE),
            format,
        };
        let progress = Arc::new(Mutex::new(Progress {
            step: "Loading the dump and reading its kernel structures".into(),
            ..Progress::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = RunHandle {
            run: run.clone(),
            progress: progress.clone(),
            process: Arc::new(Mutex::new(None)),
            stop: stop.clone(),
        };
        thread::Builder::new()
            .name("antinomie-memnixfs".into())
            .spawn(move || work(run, &job, &progress, &stop))
            .map_err(|e| e.to_string())?;
        Ok(handle)
    }

    /// Where the package's files are.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn work_dir(run: &PluginRun) -> PathBuf {
    run.dir.join("work")
}

struct Job {
    tools: PathBuf,
    dump: PathBuf,
    symbols: Option<PathBuf>,
    report: &'static Report,
    address_space_size: u64,
    format: DumpFormat,
}

/// Run the report and save the run, however it ends.
fn work(mut run: PluginRun, job: &Job, progress: &Mutex<Progress>, stop: &AtomicBool) {
    let work = work_dir(&run);
    let started = run.started_ms;
    let outcome = execute(&run, job, &work, stop);
    let log = collect_log(&work);
    let cancelled = stop.load(Ordering::Relaxed);
    run.finished_ms = Some(unix_ms().max(started));
    match outcome {
        Ok(converted) => {
            run.state = RunState::Finished;
            run.rows = converted.rows;
            run.exit_code = Some(0);
            run.partial = messages::partial_notes(&log);
            run.partial.extend(converted.notes);
            if job.symbols.is_none() {
                run.partial.push(messages::NO_SYMBOLS_NOTE.into());
            }
            if job.format == DumpFormat::Raw {
                run.partial.push(messages::RAW_NOTE.into());
            }
        }
        Err(error) => {
            run.state = if cancelled {
                RunState::Cancelled
            } else {
                RunState::Failed
            };
            run.exit_code = None;
            if !cancelled {
                run.error = Some(messages::failure(&error, &log));
            }
            run.partial = Vec::new();
        }
    }
    let _ = write_log(&run, job, &log);
    // The work folder only holds the sandbox's own files and the export,
    // which a finished run has already moved into `files/`.
    let _ = fs::remove_dir_all(&work);
    let _ = run.save();
    if let Ok(mut progress) = progress.lock() {
        progress.finished = Some(run);
    }
}

fn execute(
    run: &PluginRun,
    job: &Job,
    work: &Path,
    stop: &AtomicBool,
) -> Result<convert::Converted, String> {
    let export = work.join("export");
    let program = Path::new(crate::analysis_tools::SANDBOX_DIR)
        .join("memnixfs")
        .join(PROGRAM);
    let text = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("{} is not UTF-8", path.display()))
    };
    let mut args = vec!["--dump".to_owned(), text(&job.dump)?];
    let mut read_only = vec![job.dump.clone()];
    if let Some(symbols) = &job.symbols {
        args.extend(["--symbols".into(), text(symbols)?]);
        read_only.push(symbols.clone());
    }
    // Offline: no symbol mirrors, and the sandbox has no network anyway.
    args.extend(["--no-http-cache".into(), "-v".into(), "export".into()]);
    args.extend([job.report.path.to_owned(), text(&export)?]);
    let library = format!("{}/memnixfs/lib", crate::analysis_tools::SANDBOX_DIR);
    let mounts = crate::analysis::jobs::Mounts {
        paths: &read_only,
        tools: Some(&job.tools),
    };
    crate::analysis::jobs::run_sandboxed_sized(
        &program,
        &args,
        work,
        &mounts,
        &[
            ("HOME", "/tmp"),
            ("LMPFS_SYMBOL_CACHE", "/tmp/symbols"),
            ("LD_LIBRARY_PATH", &library),
            ("NO_COLOR", "1"),
        ],
        RUN_TIMEOUT,
        stop,
        job.address_space_size,
    )?;
    let output = File::create(run.output()).map_err(|e| format!("plugin output: {e}"))?;
    let mut output = BufWriter::new(output);
    let converted = match job.report.kind {
        Kind::Files => {
            if !export.is_dir() {
                return Err(unavailable(job.report));
            }
            let converted = convert::files_table(&export, &mut output)?;
            output.flush().map_err(|e| e.to_string())?;
            let files = run.files();
            // The run's files folder was made empty for this.
            fs::remove_dir(&files).map_err(|e| format!("{}: {e}", files.display()))?;
            fs::rename(&export, &files).map_err(|e| format!("{}: {e}", files.display()))?;
            return Ok(converted);
        }
        Kind::Table | Kind::Text => {
            let name = Path::new(job.report.path)
                .file_name()
                .ok_or("report without a name")?;
            let exported = export.join(name);
            if !exported.is_file() {
                return Err(unavailable(job.report));
            }
            let converted = if job.report.kind == Kind::Table {
                convert::json_table(&exported, &mut output, job.report.columns)?
            } else {
                convert::text_table(&exported, &mut output)?
            };
            // The raw export stays with the run, for the Files button.
            fs::rename(&exported, run.files().join(name))
                .map_err(|e| format!("{}: {e}", exported.display()))?;
            converted
        }
    };
    output.flush().map_err(|e| e.to_string())?;
    Ok(converted)
}

fn unavailable(report: &Report) -> String {
    format!(
        "MemNixFS has no {} for this dump ({} was not produced): the kernel structures it \
         needs could not be read",
        report.name, report.path
    )
}

/// The sandbox's diagnostics (MemNixFS's messages), without colors.
fn collect_log(work: &Path) -> String {
    let mut logs: Vec<PathBuf> = fs::read_dir(work)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "log"))
        .collect();
    logs.sort();
    let mut text = String::new();
    for log in logs {
        if let Ok(bytes) = fs::read(&log) {
            text.push_str(&messages::strip_colors(&String::from_utf8_lossy(&bytes)));
        }
    }
    text
}

fn write_log(run: &PluginRun, job: &Job, log: &str) -> std::io::Result<()> {
    let mut file = File::create(run.log())?;
    writeln!(
        file,
        "MemNixFS {} · {} · offline in the analysis sandbox",
        run.tool_version.as_deref().unwrap_or("?"),
        job.report.path
    )?;
    writeln!(file, "Dump format: {}", job.format.label())?;
    writeln!(
        file,
        "Symbol table: {}",
        if job.symbols.is_some() {
            "the dump's own (saved with it)"
        } else {
            "none: MemNixFS uses the kernel's BTF and kallsyms if the dump has them"
        }
    )?;
    for note in &run.partial {
        writeln!(file, "Partial: {note}")?;
    }
    writeln!(file)?;
    file.write_all(log.as_bytes())
}

#[cfg(test)]
mod tests;
