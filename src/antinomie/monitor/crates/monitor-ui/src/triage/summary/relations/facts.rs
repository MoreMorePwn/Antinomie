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

/// The process's name: the recorded one; when that is empty or "?", the file
/// name of the last image it ran, else of its argv[0].
fn recorded_name(node: &crate::triage::ProcessNode) -> String {
    let name = process_cells::file_name(&node.comm);
    if !name.is_empty() && name != "?" {
        return name.to_owned();
    }
    node.record
        .execs
        .last()
        .map(|(image, _)| process_cells::file_name(image))
        .or_else(|| {
            node.exec_history
                .last()
                .map(|image| process_cells::file_name(image))
        })
        .filter(|name| !name.is_empty() && *name != "?")
        .or_else(|| node.argv.first().map(|arg| process_cells::file_name(arg)))
        .filter(|name| !name.is_empty() && *name != "?")
        .unwrap_or("")
        .to_owned()
}

pub(in crate::triage) fn facts_of(scan: &ArchiveScan) -> Facts {
    let mut facts = Facts::default();
    for node in scan.process.iter().filter(|node| !node.thread) {
        facts.procs.push(Proc {
            pid: node.pid,
            cookie: node.cookie,
            parent: node.parent.map(|parent| (parent.pid, parent.cookie)),
            name: recorded_name(node),
            mismatch: !node.forked
                && process_cells::argv0_mismatch(&node.comm, &node.argv).is_some(),
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
        });
    }
    if let Some(ioc) = &scan.ioc {
        for indicator in ioc
            .indicators
            .iter()
            .filter(|indicator| indicator.noise.is_none())
        {
            let process = indicator
                .process
                .as_ref()
                .map(|process| (process.pid, process.cookie));
            match indicator.ty {
                Type::File => facts.files.push(FileFact {
                    path: if indicator.path.is_empty() {
                        indicator.value.clone()
                    } else {
                        indicator.path.clone()
                    },
                    roles: indicator.roles.clone(),
                    process,
                }),
                Type::Endpoint => facts.endpoints.push(EndpointFact {
                    endpoint: indicator.value.clone(),
                    process,
                }),
                _ => {}
            }
        }
    }
    facts
}
