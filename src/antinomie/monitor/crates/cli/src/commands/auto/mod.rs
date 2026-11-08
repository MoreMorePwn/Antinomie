// SPDX-License-Identifier: GPL-3.0-only
//! `antinomie-cli auto ...` (design 3.4.4): Auto mode. `auto daemon` runs the
//! service (card P3-6a); `auto init` and `auto lane` make and mend the lane
//! (P3-5b).
use crate::{context::Context, error::CliError, output::Reply};
use clap::Subcommand;

mod daemon;
mod init;
mod lanes;
mod link;

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
    /// The lanes: list, reset, unquarantine.
    #[command(subcommand)]
    Lane(lanes::Lane),
}

impl Auto {
    /// The command prints events as they happen.
    pub fn streams_events(&self) -> bool {
        false
    }
}

pub fn run(auto: &Auto, context: &Context) -> Result<Reply, CliError> {
    match auto {
        Auto::Init(arguments) => init::run(arguments, context),
        Auto::Daemon(arguments) => daemon::run(arguments, context),
        Auto::Lane(command) => lanes::run(command, context),
    }
}
