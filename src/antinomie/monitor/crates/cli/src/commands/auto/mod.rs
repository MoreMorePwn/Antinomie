// SPDX-License-Identifier: GPL-3.0-only
//! `antinomie-cli auto ...` (design 3.4.4): Auto mode. `auto daemon` runs the
//! service (card P3-6a); `auto init` and `auto lane` make and mend the lane
//! (P3-5b); the others submit jobs and follow them (P3-6b). A command that
//! needs the job API goes to the daemon when one answers at the socket (see
//! `link`).
use crate::{context::Context, error::CliError, output::Reply};
use clap::Subcommand;

mod daemon;
mod housekeeping;
mod init;
mod jobs;
mod lanes;
pub(crate) mod link;
mod render;
pub(crate) mod submit;

#[derive(Subcommand, Debug)]
pub enum Auto {
    /// Make the lane: create the lane VM (routed), boot it once, stop it, take
    /// its clean snapshot, write lanes/lane-1.json and, when there is none, a
    /// default policy. Runs in this process: stop the daemon first.
    Init(init::Init),
    /// Run the daemon in the foreground until SIGTERM or SIGINT: it owns the
    /// data folder, runs the queue on the lane and serves the local socket
    /// (owner only). Put it in the background with a service manager or `&`.
    Daemon(daemon::DaemonArgs),
    /// Submit a file (or a library sample) as a job. Without a daemon, the job
    /// runs in this process and the command exits with its code.
    Submit(Box<submit::Submit>),
    /// One job, or the queue and the lanes.
    Status(jobs::Status),
    /// Jobs, newest first.
    List(jobs::List),
    /// Wait until the jobs have ended; exit with the worst code.
    Wait(jobs::Wait),
    /// A job's events (or every job's with --all), stored and, with --follow, live.
    Events(jobs::Events),
    /// A job's outcome, label and report files.
    Result(jobs::JobArg),
    /// A job's artifacts.
    Artifacts(jobs::JobArg),
    /// Copy one report or artifact of a job.
    Fetch(jobs::Fetch),
    /// Cancel a queued or running job.
    Cancel(jobs::Cancel),
    /// A new job from a finished one's spec.
    Retry(jobs::Retry),
    /// The queue: status, pause, resume.
    #[command(subcommand)]
    Queue(jobs::Queue),
    /// The lanes: list, reset, unquarantine.
    #[command(subcommand)]
    Lane(lanes::Lane),
    /// The policies you may submit to.
    #[command(subcommand)]
    Policy(jobs::Policy),
    /// The watch folders: their state, and a scan now.
    #[command(subcommand)]
    Watch(housekeeping::Watch),
    /// Apply retention now (recordings, job records, rejected files, staged
    /// uploads); `--dry-run` only prints the plan.
    Gc(housekeeping::Gc),
    /// Delete a finished job's record and artifacts (the sample stays).
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
        Auto::Status(arguments) => jobs::status(arguments, context),
        Auto::List(arguments) => jobs::list(arguments, context),
        Auto::Wait(arguments) => jobs::wait(arguments, context),
        Auto::Events(arguments) => jobs::events(arguments, context),
        Auto::Result(arguments) => jobs::result(arguments, context),
        Auto::Artifacts(arguments) => jobs::artifacts(arguments, context),
        Auto::Fetch(arguments) => jobs::fetch(arguments, context),
        Auto::Cancel(arguments) => jobs::cancel(arguments, context),
        Auto::Retry(arguments) => jobs::retry(arguments, context),
        Auto::Queue(command) => jobs::queue(command, context),
        Auto::Lane(command) => lanes::run(command, context),
        Auto::Policy(command) => jobs::policy(command, context),
        Auto::Watch(command) => housekeeping::watch(command, context),
        Auto::Gc(arguments) => housekeeping::gc(arguments, context),
        Auto::Delete(arguments) => housekeeping::delete(arguments, context),
    }
}
