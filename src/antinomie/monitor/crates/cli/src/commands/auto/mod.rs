// SPDX-License-Identifier: GPL-3.0-only
//! `antinomie-cli auto ...` (design 3.4.4): Auto mode. `auto daemon` runs the
//! service (card P3-6a).
use crate::{context::Context, error::CliError, output::Reply};
use clap::Subcommand;

mod daemon;

#[derive(Subcommand, Debug)]
pub enum Auto {
    /// Run the daemon in the foreground until SIGTERM or SIGINT: it owns the
    /// data folder, runs the queue on the lane and serves the local socket
    /// (owner only). Put it in the background with a service manager or `&`.
    Daemon(daemon::DaemonArgs),
}

pub fn run(auto: &Auto, context: &Context) -> Result<Reply, CliError> {
    match auto {
        Auto::Daemon(arguments) => daemon::run(arguments, context),
    }
}
