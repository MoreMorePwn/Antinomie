// SPDX-License-Identifier: GPL-3.0-only
//! Run MemNixFS reports on a real guest memory dump, as the Memory tab's
//! MemNixFS backend does, and print what each run saved.
//!
//! usage: memnixfs-check DATA_DIR RECORDING_DIR DUMP [SYMBOLS] REPORT...
//!
//! DATA_DIR holds the installed tool (`install-tool DATA_DIR memnixfs`).
//! RECORDING_DIR is a scratch folder: the dump is imported there (the file
//! stays where it is) and the results are saved under it. SYMBOLS is the
//! dump's `symbols.json.xz`, given when the argument ends with `.xz`.
use antinomie_monitor_core::{
    VmConfig,
    memory::{self, Os, memnixfs::MemNixFs},
};
use std::{path::PathBuf, process::ExitCode, thread, time::Duration};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [data, recording, dump, rest @ ..] = args.as_slice() else {
        eprintln!("usage: memnixfs-check DATA_DIR RECORDING_DIR DUMP [SYMBOLS.xz] REPORT...");
        return ExitCode::FAILURE;
    };
    let (symbols, reports) = match rest.split_first() {
        Some((first, reports)) if first.ends_with(".xz") => (Some(PathBuf::from(first)), reports),
        _ => (None, rest),
    };
    let tool = match MemNixFs::locate(&PathBuf::from(data)) {
        Ok(tool) => tool,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let vm = VmConfig {
        id: "check".into(),
        name: "Check".into(),
        ..VmConfig::default()
    };
    let imported = memory::import(
        &PathBuf::from(recording),
        &vm,
        &PathBuf::from(dump),
        Os::Linux,
        symbols.as_deref().map(|path| (path, "Linux".to_owned())),
    );
    let dump = match imported {
        Ok(dump) => dump,
        Err(error) => {
            eprintln!("import: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("MemNixFS {} on dump {}", tool.version, dump.id);
    let mut failed = false;
    for report in reports {
        let handle = match tool.start(&dump, report) {
            Ok(handle) => handle,
            Err(error) => {
                println!("{report}: refused: {error}");
                failed = true;
                continue;
            }
        };
        let run = loop {
            if let Some(run) = handle.progress().finished {
                break run;
            }
            thread::sleep(Duration::from_millis(200));
        };
        println!(
            "{report}: {:?}, {} rows, {} ms",
            run.state,
            run.rows,
            run.finished_ms.unwrap_or(0).saturating_sub(run.started_ms)
        );
        for note in &run.partial {
            println!("  partial: {note}");
        }
        if let Some(error) = &run.error {
            println!("  error: {error}");
            failed = true;
        }
        println!("  result: {}", run.output().display());
    }
    println!("results kept under {}", dump.dir.display());
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
