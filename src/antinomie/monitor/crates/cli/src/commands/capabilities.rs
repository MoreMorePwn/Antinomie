// SPDX-License-Identifier: GPL-3.0-only
//! `capabilities` (design 5.4.9). This card fills the members that do not
//! depend on policies or a daemon; `max_sample_bytes`, `accept_*`, `routes`,
//! `static_checks`, `detection`, `ioc_datasets` and `queries` follow with the
//! policy and query cards.
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
    Ok(Reply::value(json!({
        "api_version": API_VERSION,
        "app_version": APP_VERSION,
        "app_revision": APP_REVISION,
        "lanes": 1,
        "report_formats": REPORT_FORMATS,
        "accelerator": if kvm_usable { "kvm" } else { "tcg" },
        "features": [],
    })))
}
