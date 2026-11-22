// SPDX-License-Identifier: GPL-3.0-only
//! The limits of 5.12.5 and 5.12.6 as one settings value: row and byte limits,
//! the two pools' sizes and the deadlines (`service.toml [query]`).

use super::catalogue::QueryLimits;
use std::time::Duration;

/// A page is cut before its encoded size would pass this (1 MiB); fewer rows,
/// never a truncated row.
pub const PAGE_BYTES: usize = 1 << 20;

/// Settings of the read side. The defaults are the contract's.
#[derive(Clone, Debug)]
pub struct QuerySettings {
    /// `capabilities.queries.limits`.
    pub limits: QueryLimits,
    /// Deadline of a light read.
    pub light_timeout: Duration,
    /// Deadline of a heavy read page.
    pub heavy_timeout: Duration,
    /// What `retry_after_s` says when the heavy pool is full.
    pub heavy_retry_after_s: u64,
    /// A Triage scan that runs longer is cancelled (`scan_s`, 900 s).
    pub scan_deadline: Duration,
    /// Public-address lookups of a Triage scan (`service.toml [privacy]`).
    pub address_lookup: antinomie_monitor_core::settings::AddressLookup,
}

impl QuerySettings {
    /// The settings `service.toml` asks for: the two pools' sizes, the two
    /// deadlines and the lookup mode (`[query]`, `[privacy]`).
    pub fn from_config(config: &crate::config::ServiceConfig) -> Self {
        let mut settings = Self::default();
        settings.limits.light_concurrency = config.query.light_concurrency;
        settings.limits.heavy_concurrency = config.query.heavy_concurrency;
        settings.limits.scan_cache_mib = config.query.scan_cache_mib;
        settings.light_timeout = Duration::from_secs(u64::from(config.query.light_timeout_s));
        settings.heavy_timeout = Duration::from_secs(u64::from(config.query.heavy_timeout_s));
        settings.address_lookup = config.privacy.address_lookup.triage_mode();
        settings
    }
}

impl Default for QuerySettings {
    fn default() -> Self {
        Self {
            limits: QueryLimits::default(),
            light_timeout: Duration::from_secs(10),
            heavy_timeout: Duration::from_secs(60),
            heavy_retry_after_s: 2,
            scan_deadline: Duration::from_secs(900),
            address_lookup: antinomie_monitor_core::settings::AddressLookup::Tshark,
        }
    }
}

impl QuerySettings {
    /// Rows per page: `(default, max)` for a row page.
    pub fn rows(&self) -> (u32, u32) {
        (self.limits.row.default, self.limits.row.max)
    }
}

/// Seconds a Triage scan may take for each MiB of `telemetry.raw`, once the
/// recording is bigger than the fixed `scan_s` covers (ANT-T0590). The zerobot
/// run (589 MiB) took 417 s on a loaded machine after the T0588 fixes, 0.7 s
/// a MiB; 3 s a MiB leaves four times that.
pub const SCAN_SECONDS_PER_MIB: u64 = 3;
/// The longest a scan's deadline scales to.
pub const SCAN_DEADLINE_CAP: Duration = Duration::from_secs(4 * 3600);

/// The deadline of a scan of a recording of `bytes`: `base` (`scan_s`), or
/// [`SCAN_SECONDS_PER_MIB`] a MiB up to [`SCAN_DEADLINE_CAP`] when that is longer.
pub fn scan_deadline_for(base: Duration, bytes: u64) -> Duration {
    let scaled = Duration::from_secs((bytes >> 20).saturating_mul(SCAN_SECONDS_PER_MIB));
    base.max(scaled.min(SCAN_DEADLINE_CAP))
}

/// How many leading items of `sizes` fit in [`PAGE_BYTES`]; at least one when
/// there is one, because a single row is bounded by the engine's previews.
pub fn fit_in_page(sizes: impl IntoIterator<Item = usize>) -> usize {
    let mut total = 0usize;
    let mut kept = 0usize;
    for size in sizes {
        if kept > 0 && total.saturating_add(size) > PAGE_BYTES {
            break;
        }
        total = total.saturating_add(size);
        kept += 1;
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_big_recording_gets_a_longer_scan_deadline_and_a_small_one_keeps_scan_s() {
        let base = Duration::from_secs(900);
        let mib = 1u64 << 20;
        assert_eq!(scan_deadline_for(base, 0), base);
        assert_eq!(scan_deadline_for(base, 100 * mib), base);
        // 589 MiB (the zerobot run): 1767 s instead of 900.
        assert_eq!(
            scan_deadline_for(base, 589 * mib),
            Duration::from_secs(1767)
        );
        assert_eq!(scan_deadline_for(base, 1_000_000 * mib), SCAN_DEADLINE_CAP);
        // A configured deadline longer than the cap stays.
        let long = Duration::from_secs(10 * 3600);
        assert_eq!(scan_deadline_for(long, 1_000_000 * mib), long);
    }

    #[test]
    fn service_toml_sets_the_pools_the_deadlines_and_the_lookup_mode() {
        use crate::config::validate::parse_service;
        use antinomie_monitor_core::settings::AddressLookup;
        let (config, problems) = parse_service(
            "service.toml",
            "[query]\nlight_concurrency = 3\nheavy_concurrency = 1\nlight_timeout_s = 7\nheavy_timeout_s = 9\n[privacy]\naddress_lookup = \"off\"\n",
        );
        assert!(problems.is_empty(), "{problems:?}");
        let settings = QuerySettings::from_config(&config.unwrap());
        assert_eq!(settings.limits.light_concurrency, 3);
        assert_eq!(settings.limits.heavy_concurrency, 1);
        assert_eq!(settings.light_timeout, Duration::from_secs(7));
        assert_eq!(settings.heavy_timeout, Duration::from_secs(9));
        assert_eq!(settings.address_lookup, AddressLookup::Off);
        // The pools take their sizes from it.
        let pool = crate::query::pool::ReadPool::new(&settings);
        assert_eq!(pool.in_flight(), (0, 0));
        // BH-31: `capabilities.queries.limits` is the service's, not the
        // defaults.
        let service = crate::query::QueryService::with_settings(
            antinomie_monitor_core::BackendOptions::default(),
            settings.clone(),
        );
        assert_eq!(service.limits(), settings.limits);
        assert_eq!(service.limits().light_concurrency, 3);
        // No file: the contract's defaults, and the lookup `off` of the design.
        let (config, _) = parse_service("service.toml", "");
        let settings = QuerySettings::from_config(&config.unwrap());
        assert_eq!(settings.limits.light_concurrency, 16);
        assert_eq!(settings.light_timeout, Duration::from_secs(10));
        assert_eq!(settings.address_lookup, AddressLookup::Off);
        let (config, _) = parse_service("service.toml", "[privacy]\naddress_lookup = \"tshark\"\n");
        assert_eq!(
            QuerySettings::from_config(&config.unwrap()).address_lookup,
            AddressLookup::Tshark
        );
    }

    #[test]
    fn a_page_keeps_whole_rows_under_one_mebibyte() {
        assert_eq!(fit_in_page([]), 0);
        assert_eq!(fit_in_page([10, 10, 10]), 3);
        assert_eq!(fit_in_page([600_000, 600_000, 1]), 1);
        assert_eq!(fit_in_page([PAGE_BYTES * 2, 1]), 1, "one row always goes");
        assert_eq!(fit_in_page([PAGE_BYTES - 1, 1, 1]), 2);
    }
}
