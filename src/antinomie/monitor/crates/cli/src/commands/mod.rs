// SPDX-License-Identifier: GPL-3.0-only
//! The command groups (design 3.4). Each group lives in its own module and is
//! one variant of [`Command`], so a card that adds a group touches one line
//! here.
use crate::{context::Context, error::CliError, output::Reply};
use clap::Subcommand;

mod analyze;
mod base;
mod capabilities;
mod config;
mod custody;
mod detect;
mod doctor;
mod library;
mod machine;
mod recording;
mod report;
mod rules;
mod run;
mod sample;
mod snapshot;
mod triage;
mod vm;

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
    /// Bases: list, install, download, build, delete; takes the engine lock.
    #[command(subcommand)]
    Base(base::Base),
    /// VMs: create, start, stop, status, reset, duplicate, delete; takes the engine lock.
    #[command(subcommand)]
    Vm(vm::Vm),
    /// VM snapshots: list, create, restore, delete; takes the engine lock.
    #[command(subcommand)]
    Snapshot(snapshot::Snapshot),
    /// Run a library sample in a VM: `run exec`; takes the engine lock.
    #[command(subcommand)]
    Run(run::Run),
    /// Samples in the library; no engine lock needed.
    #[command(subcommand)]
    Sample(sample::Sample),
    /// Custody chains of the samples; no engine lock needed.
    #[command(subcommand)]
    Custody(custody::Custody),
    /// Index a saved run as Triage does and print its summary: the assessment,
    /// the counts and the key behaviours. No engine lock needed.
    Triage(triage::Triage),
    /// Run YARA, Sigma and IDS over a saved run's evidence; no engine lock
    /// needed unless --save keeps the results in the recording.
    Detect(detect::Detect),
    /// Write a saved run's report (HTML, PDF, JSON, MISP, STIX, Markdown), the
    /// same files the window's Export report writes. No engine lock needed.
    Report(report::Report),
}

impl Command {
    /// The command prints events as they happen (`run exec --events`).
    pub fn streams_events(&self) -> bool {
        matches!(self, Command::Run(run) if run.streams_events())
    }
}

pub fn run(command: &Command, context: &Context) -> Result<Reply, CliError> {
    match command {
        Command::Doctor(arguments) => doctor::run(arguments, context),
        Command::Capabilities => capabilities::run(context),
        Command::Config(config) => config::run(config, context),
        Command::Analyze(arguments) => analyze::run(arguments, context),
        Command::Rules(rules) => rules::run(rules, context),
        Command::Base(base) => base::run(base, context),
        Command::Vm(vm) => vm::run(vm, context),
        Command::Snapshot(snapshot) => snapshot::run(snapshot, context),
        Command::Run(run) => run::run(run, context),
        Command::Sample(sample) => sample::run(sample, context),
        Command::Custody(custody) => custody::run(custody, context),
        Command::Triage(arguments) => triage::run(arguments, context),
        Command::Detect(arguments) => detect::run(arguments, context),
        Command::Report(arguments) => report::run(arguments, context),
    }
}
