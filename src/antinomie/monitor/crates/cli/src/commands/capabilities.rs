// SPDX-License-Identifier: GPL-3.0-only
//! `capabilities` (design 5.4.9). When a daemon answers, its whole answer is
//! printed: the lanes, the accepted types and architectures, the routes, the
//! static checks, the detection engines, the IOC datasets, the queries and the
//! run API features it serves. Without one, this command fills what does not
//! need a daemon, and `features` is empty because no run API is served.
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
    // A running daemon's own answer: every member, including the run API
    // features it serves.
    if let Ok(Some(mut client)) = crate::commands::auto::link::daemon(context)
        && let Ok(caps) = client.call("capabilities", json!({}))
        && caps.is_object()
    {
        return Ok(Reply::value(caps));
    }
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
