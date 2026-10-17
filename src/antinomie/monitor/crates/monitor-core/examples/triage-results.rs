// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Run the normal offline Properties or Detection job on a recorded sample.
//! Usage: triage-results --properties ANALYSIS_DIR [TOOLS_DIR] | --detect REQUEST.json
//! TOOLS_DIR is a `<data>/tools` folder whose managed tools (Magika) are mounted.
//! Detection uses the public detection::Request format; Sigma needs the normalized
//! journal produced by Triage. This executable also hosts its isolated workers.
use antinomie_monitor_core::analysis::{self, detection, properties};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

fn run() -> Result<serde_json::Value, String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !(2..=3).contains(&args.len()) || (args.len() == 3 && args[0] != "--properties") {
        return Err(
            "usage: triage-results --properties ANALYSIS_DIR [TOOLS_DIR] | --detect REQUEST.json"
                .into(),
        );
    }
    let path = PathBuf::from(&args[1]);
    if args[0] == "--properties" {
        let report = analysis::open_report(&path)?;
        let tools = args.get(2).map(PathBuf::from);
        let result = properties::run(&path, &report.id, tools.as_deref(), &AtomicBool::new(false))?;
        serde_json::to_value(result).map_err(|error| error.to_string())
    } else if args[0] == "--detect" {
        let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
        let request = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        serde_json::to_value(detection::run(request, &Arc::new(AtomicBool::new(false)))?)
            .map_err(|error| error.to_string())
    } else {
        Err("expected --properties or --detect".into())
    }
}

fn main() {
    if let Some(code) =
        properties::worker_main_if_requested().or_else(detection::worker_main_if_requested)
    {
        std::process::exit(code);
    }
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
