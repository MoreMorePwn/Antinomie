// SPDX-License-Identifier: GPL-3.0-only
//! `capabilities` (design 5.4.9). This card fills the members that do not
//! depend on policies or a daemon; `max_sample_bytes`, `accept_*`, `routes`,
//! `static_checks`, `detection`, `ioc_datasets` and `queries` follow with the
//! policy and query cards. `lanes` is the running daemon's when one answers.
use crate::{context::Context, error::CliError, output::Reply};
use antinomie_monitor_core::{
    api::{APP_REVISION, APP_VERSION},
    dependencies::{self, Dependency},
};
use antinomie_service::API_VERSION;
use serde_json::json;

/// Formats `report export` can write (design 5.4.9).
pub const REPORT_FORMATS: [&str; 6] = ["html", "pdf", "json", "misp", "stix", "md"];

pub fn run(context: &Context) -> Result<Reply, CliError> {
    let report = dependencies::check(&context.options);
    let kvm_usable = !context.options.force_tcg
        && report
            .checks
            .iter()
            .any(|check| check.dependency == Dependency::Kvm && check.problem.is_none());
    // The lanes a running daemon has (`daemon.lanes`, ANT-T0455 card C);
    // without one, the one lane a command runs.
    let lanes = match crate::commands::auto::link::daemon(context) {
        Ok(Some(mut client)) => client
            .call("capabilities", json!({}))
            .ok()
            .and_then(|caps| caps["lanes"].as_u64())
            .unwrap_or(1),
        _ => 1,
    };
    Ok(Reply::value(json!({
        "api_version": API_VERSION,
        "app_version": APP_VERSION,
        "app_revision": APP_REVISION,
        "lanes": lanes,
        "report_formats": REPORT_FORMATS,
        "accelerator": if kvm_usable { "kvm" } else { "tcg" },
        "features": [],
    })))
}
