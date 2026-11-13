// SPDX-License-Identifier: GPL-3.0-only
//! `antinomie-cli auto ...` (design 3.4.4): Auto mode. `auto daemon` runs the
//! service (card P3-6a); `auto init` and `auto lane` make and mend the lane
//! (P3-5b); the others submit runs and follow them (P3-6b). A command that
//! needs the run API goes to the daemon when one answers at the socket (see
//! `link`).
use crate::{context::Context, error::CliError, output::Reply};
use clap::Subcommand;

pub mod daemon;
mod housekeeping;
mod init;
mod lanes;
pub(crate) mod link;
mod render;
mod runs;
pub(crate) mod submit;

#[derive(Subcommand, Debug)]
pub enum Auto {
    /// Make a lane: create the lane VM (routed), boot it once, stop it, take
    /// its clean snapshot, write service/lanes/lane-N.json and, for lane 1
    /// with another VM name or snapshot, the [lanes] of a new service.toml.
    /// The presets need no file: five are built in. `--lane N` (2 to 4)
    /// makes another lane, in
    /// <data>/lanes/N/, for `daemon.lanes`. Runs in this process: stop the
    /// daemon first.
    Init(init::Init),
    /// Run the daemon in the foreground until SIGTERM or SIGINT: it owns the
    /// data folder, runs the queue on its lanes (one by default; `[daemon]
    /// lanes` in service.toml) and serves the local socket (owner only). Put it
    /// in the background with a service manager or `&`.
    Daemon(daemon::DaemonArgs),
    /// Submit a file (or a library sample) as a run. Without a daemon, the run
    /// runs in this process and the command exits with its code.
    Submit(Box<submit::Submit>),
    /// One run, or the queue and the lanes.
    Status(runs::Status),
    /// Runs, newest first.
    List(runs::List),
    /// Wait until the runs have ended; exit with the worst code.
    Wait(runs::Wait),
    /// A run's events (or every run's with --all), stored and, with --follow, live.
    Events(runs::Events),
    /// A run's outcome, label and report files.
    Result(runs::RunArg),
    /// A run's artifacts.
    Artifacts(runs::RunArg),
    /// Copy one report or artifact of a run.
    Fetch(runs::Fetch),
    /// Cancel a run that waits or runs.
    Cancel(runs::Cancel),
    /// A new run from a finished one: its resolved options (or another
    /// preset's, `--preset`), with `--override` on top.
    Rerun(runs::Rerun),
    /// The queue: status, pause, resume.
    #[command(subcommand)]
    Queue(runs::Queue),
    /// The lanes: list, reset, unquarantine (`--lane lane-N`).
    #[command(subcommand)]
    Lane(lanes::Lane),
    /// The presets: `list` (the five built-in ones and presets/*.toml, with
    /// the permissions their options need) and `show NAME` (every option).
    #[command(subcommand)]
    Preset(runs::Preset),
    /// The watch folders: their state, and a scan now.
    #[command(subcommand)]
    Watch(housekeeping::Watch),
    /// Apply retention now (recordings, run records, rejected files, staged
    /// uploads); `--dry-run` only prints the plan.
    Gc(housekeeping::Gc),
    /// Delete a finished run's record and artifacts (the sample stays).
    Delete(housekeeping::Delete),
}

impl Auto {
    /// The command prints events as they happen.
    pub fn streams_events(&self) -> bool {
        match self {
            Auto::Submit(submit) => submit.follow,
            Auto::Events(events) => events.follow,
            _ => false,
        }
    }
}

pub fn run(auto: &Auto, context: &Context) -> Result<Reply, CliError> {
    match auto {
        Auto::Init(arguments) => init::run(arguments, context),
        Auto::Daemon(arguments) => daemon::run(arguments, context),
        Auto::Submit(arguments) => submit::run(arguments, context),
        Auto::Status(arguments) => runs::status(arguments, context),
        Auto::List(arguments) => runs::list(arguments, context),
        Auto::Wait(arguments) => runs::wait(arguments, context),
        Auto::Events(arguments) => runs::events(arguments, context),
        Auto::Result(arguments) => runs::result(arguments, context),
        Auto::Artifacts(arguments) => runs::artifacts(arguments, context),
        Auto::Fetch(arguments) => runs::fetch(arguments, context),
        Auto::Cancel(arguments) => runs::cancel(arguments, context),
        Auto::Rerun(arguments) => runs::rerun(arguments, context),
        Auto::Queue(command) => runs::queue(command, context),
        Auto::Lane(command) => lanes::run(command, context),
        Auto::Preset(command) => runs::preset(command, context),
        Auto::Watch(command) => housekeeping::watch(command, context),
        Auto::Gc(arguments) => housekeeping::gc(arguments, context),
        Auto::Delete(arguments) => housekeeping::delete(arguments, context),
    }
}
