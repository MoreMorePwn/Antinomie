// SPDX-License-Identifier: GPL-3.0-only
//! The command groups (design 3.4). Each group lives in its own module and is
//! one variant of [`Command`], so a card that adds a group touches one line
//! here.
use crate::{context::Context, error::CliError, output::Reply};
use clap::Subcommand;

mod analyze;
mod capabilities;
mod config;
mod custody;
mod doctor;
mod library;
mod rules;
mod sample;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Check the machine for the tools the engine needs.
    Doctor(doctor::Doctor),
    /// Print what this build and machine can do.
    Capabilities,
    /// Paths and settings of the data directory.
    #[command(subcommand)]
    Config(config::Config),
    /// Static analysis of a host file, no VM; takes the engine lock.
    Analyze(analyze::Analyze),
    /// Rule packs and groups: list, enable, disable.
    #[command(subcommand)]
    Rules(rules::Rules),
    /// Samples in the library; no engine lock needed.
    #[command(subcommand)]
    Sample(sample::Sample),
    /// Custody chains of the samples; no engine lock needed.
    #[command(subcommand)]
    Custody(custody::Custody),
}

pub fn run(command: &Command, context: &Context) -> Result<Reply, CliError> {
    match command {
        Command::Doctor(arguments) => doctor::run(arguments, context),
        Command::Capabilities => capabilities::run(context),
        Command::Config(config) => config::run(config, context),
        Command::Analyze(arguments) => analyze::run(arguments, context),
        Command::Rules(rules) => rules::run(rules, context),
        Command::Sample(sample) => sample::run(sample, context),
        Command::Custody(custody) => custody::run(custody, context),
    }
}
