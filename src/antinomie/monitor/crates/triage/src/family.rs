// SPDX-License-Identifier: GPL-3.0-only
//! Which malware family a run's detections name: the logic lives in the core
//! (`antinomie_monitor_core::family`) so the exported reports name the same
//! families as Triage's Summary. This module gathers what the family
//! profiles read of a scan.
pub use antinomie_monitor_core::family::*;

use crate::{ArchiveScan, FileTab};
use antinomie_monitor_core::ioc::indicator::{Indicator, Type};

/// A URL indicator as a URL: `http://host/path`, or `ftp://` and `tftp://`
/// for the InetSim log's FTP and TFTP requests.
pub fn indicator_url(indicator: &Indicator) -> Option<String> {
    if indicator.ty != Type::Url || indicator.path.is_empty() {
        return None;
    }
    let scheme = match indicator.value.split(' ').next() {
        Some("TFTP") => "tftp",
        Some("FTP") => "ftp",
        _ => "http",
    };
    Some(format!("{scheme}://{}", indicator.path))
}

/// The file tabs whose paths the profiles read: what the run opened, read,
/// created, wrote, renamed, executed or looked up. Deletions and attribute
/// changes are left out: a bot that removes rival miners unlinks their files
/// (`/tmp/kinsing`, `/tmp/kdevtmpfsi` in a T0600 run), which says nothing
/// about its own family.
const PROFILE_TABS: [FileTab; 5] = [
    FileTab::Created,
    FileTab::Written,
    FileTab::Renamed,
    FileTab::Executed,
    FileTab::Probed,
];

/// What the family profiles read of a run (ANT-T0604): the rule ids of its
/// findings, the paths of [`PROFILE_TABS`], the opened and read files and
/// the files it changed, its indicators' values and URLs (not the base
/// image's own traffic), and its processes' command lines.
pub fn seen_of(scan: &ArchiveScan) -> Seen {
    let mut seen = Seen {
        findings: crate::digest::behaviour_of(scan)
            .rules
            .into_iter()
            .map(|hit| hit.rule)
            .collect(),
        ..Seen::default()
    };
    let position = |headers: &[&str]| headers.iter().position(|h| *h == "Path");
    let event = position(crate::file_category::EVENT_HEADERS);
    let read = position(crate::file_tabs::READ_HEADERS);
    let mut add = |rows: &[Vec<crate::Cell>], at: Option<usize>| {
        let Some(at) = at else { return };
        seen.paths.extend(
            rows.iter()
                .filter_map(|row| row.get(at))
                .map(|cell| cell.text.clone()),
        );
    };
    add(&scan.opened, event);
    add(&scan.read, read);
    for tab in PROFILE_TABS {
        add(&scan.file_tabs[tab.slot() - 8].rows, event);
    }
    seen.paths.extend(
        scan.file_activity
            .files
            .iter()
            .map(|file| file.path.clone()),
    );
    if let Some(ioc) = &scan.ioc {
        for indicator in ioc.indicators.iter().filter(|i| i.noise.is_none()) {
            if indicator.ty == Type::File {
                seen.paths.push(indicator.path.clone());
                continue;
            }
            seen.network.push(indicator.value.clone());
            seen.network.extend(indicator_url(indicator));
        }
    }
    seen.commands.extend(
        scan.process
            .iter()
            .filter(|process| !process.argv.is_empty())
            .map(|process| process.argv.join(" ")),
    );
    seen.tidy()
}
