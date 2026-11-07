// SPDX-License-Identifier: GPL-3.0-only
//! `antinomie-cli`: the headless front end. Command groups are in `commands`;
//! this file only hosts the sandboxed worker roles and exits.
// The skeleton declares the whole contract (all exit and error codes, list
// output, the mode flags) before every command uses it; later cards use them.
#![allow(dead_code)]

use std::io::Write;

mod app;
mod args;
mod commands;
mod context;
mod engine;
mod error;
mod exit;
mod logging;
mod output;

/// The analysis workers re-run the running program with a flag (design 1.3), so
/// every binary that starts them must serve the flags before anything else.
/// The earlier-bytes copier is the fifth role and arrives with card P2-0.
fn serve_worker_roles() -> Option<i32> {
    use antinomie_monitor_core::{analysis, disks};
    analysis::detection::worker_main_if_requested()
        .or_else(analysis::properties::worker_main_if_requested)
        .or_else(analysis::worker_main_if_requested)
        .or_else(disks::reader::worker_main_if_requested)
}

fn main() {
    if let Some(code) = serve_worker_roles() {
        std::process::exit(code);
    }
    let environment = app::Environment::from_process();
    let (exit, rendered) = app::execute(std::env::args_os().collect(), &environment);
    // A closed pipe (`| head`) is not a failure of the command.
    let _ = std::io::stdout().write_all(rendered.stdout.as_bytes());
    let _ = std::io::stderr().write_all(rendered.stderr.as_bytes());
    let _ = std::io::stdout().flush();
    std::process::exit(i32::from(exit.code()));
}
