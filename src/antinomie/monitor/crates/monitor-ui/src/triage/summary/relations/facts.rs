// SPDX-License-Identifier: GPL-3.0-only
//! Reads the plain facts the Relationships graph is built from out of the scan.
use super::model::{EndpointFact, Fact, Facts, FileFact, Proc};
use crate::triage::{process_cells, rules, ArchiveScan, RowValue};
use antinomie_monitor_core::ioc::indicator::Type;

fn text<'a>(values: &'a [(&'static str, RowValue)], key: &str) -> &'a str {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::Text(text) if *name == key => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("")
}

fn number(values: &[(&'static str, RowValue)], key: &str) -> u64 {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::Number(number) if *name == key => Some(*number),
            _ => None,
        })
        .map_or(0, |number| number.clamp(0, i128::from(u64::MAX)) as u64)
}

/// A capture time (host Unix microseconds) as guest nanoseconds, through the
/// run's clock anchor.
fn guest_ns(
    anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    host_us: Option<u64>,
) -> Option<u64> {
    let (anchor, us) = (anchor?, host_us?);
    let delta = (i128::from(us) - i128::from(anchor.host_us)) * 1000;
    u64::try_from(i128::from(anchor.guest_ns) + delta).ok()
}

pub(in crate::triage) fn facts_of(scan: &ArchiveScan) -> Facts {
    let mut facts = Facts::default();
    for node in scan.process.iter().filter(|node| !node.thread) {
        facts.procs.push(Proc {
            pid: node.pid,
            cookie: node.cookie,
            parent: node.parent.map(|parent| (parent.pid, parent.cookie)),
            name: process_cells::file_name(&node.comm).to_owned(),
            mismatch: !node.forked
                && process_cells::argv0_mismatch(&node.comm, &node.argv).is_some(),
            first_ns: node.first_ns,
            execs: node.record.execs.clone(),
            sent: node.record.sent.clone(),
            forked: node.forked,
        });
    }
    for finding in &scan.findings {
        let values = &finding.values;
        let hidden = values.iter().any(|(name, value)| {
            *name == "finding.hidden" && matches!(value, RowValue::Bool(true))
        });
        let Some(tier) = rules::Tier::from_tag(text(values, "finding.tier")) else {
            continue;
        };
        if hidden {
            continue;
        }
        facts.findings.push(Fact {
            tier,
            rule: text(values, "finding.rule").to_owned(),
            object: text(values, "finding.object").to_owned(),
            pid: number(values, "process.pid") as u32,
            cookie: number(values, "process.cookie"),
            first_ns: number(values, "finding.first_ns"),
        });
    }
    if let Some(ioc) = &scan.ioc {
        let anchor = scan.clock_anchor;
        for indicator in ioc
            .indicators
            .iter()
            .filter(|indicator| indicator.noise.is_none())
        {
            let process = indicator
                .process
                .as_ref()
                .map(|process| (process.pid, process.cookie));
            let ns = guest_ns(anchor, indicator.first_us);
            match indicator.ty {
                Type::File => facts.files.push(FileFact {
                    path: if indicator.path.is_empty() {
                        indicator.value.clone()
                    } else {
                        indicator.path.clone()
                    },
                    roles: indicator.roles.clone(),
                    process,
                    ns,
                }),
                Type::Endpoint => facts.endpoints.push(EndpointFact {
                    endpoint: indicator.value.clone(),
                    process,
                    ns,
                }),
                _ => {}
            }
        }
    }
    facts
}
