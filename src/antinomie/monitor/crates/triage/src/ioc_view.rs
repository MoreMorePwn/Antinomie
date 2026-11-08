// SPDX-License-Identifier: GPL-3.0-only
//! The model of Triage > IOC: the filter fields and values of an indicator
//! row, the Details selection, the verdict line and where a jump to evidence
//! goes. The tabs, chips and tables that draw them are the GUI's.
use super::*;
use crate::query::{FieldSpec, RowValue};
use antinomie_monitor_core::ioc::{
    indicator::{Indicator, Jump as Evidence, Type},
    verdict::{Outcome, Verdict},
};

#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
#[cfg(test)]
mod tests;

/// The one full statement that no match proves nothing; the IOC headline
/// carries it as a tooltip.
pub const NO_MATCH_NOTE: &str = "No match is not a clean result: a dataset only lists what abuse.ch has seen, and Antinomie checks only the datasets loaded on this machine.";

/// Where a jump to evidence goes.
pub enum Jump {
    Packet { capture: String, frame: u64 },
    Call { stream: u64, cookie: u64, call: u64 },
    Properties,
}

pub const FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("ioc.type", "endpoint, domain, url, tls or file"),
    FieldSpec::text("ioc.value", "The indicator as the row shows it"),
    FieldSpec::text("ioc.match", "matched, known_fp, no_match or not_checked"),
    FieldSpec::tags("ioc.source", "pcap, syscall, disk or static"),
    FieldSpec::text("ioc.process", "The one process that made a matching call"),
    FieldSpec::text("ioc.dataset", "The dataset that lists it"),
    FieldSpec::text("ioc.family", "The family the record names"),
    FieldSpec::number("ioc.confidence", "The record's confidence, when it has one"),
    FieldSpec::number("ioc.first_us", "First seen in the run, Unix microseconds"),
    FieldSpec::number("ioc.last_us", "Last seen in the run, Unix microseconds"),
    FieldSpec::text("tls.sni", "TLS server name"),
    FieldSpec::text("tls.ja3", "JA3 client fingerprint"),
    FieldSpec::text("tls.ja4", "JA4 client fingerprint"),
    FieldSpec::text("tls.ja3s", "JA3S server fingerprint"),
    FieldSpec::text("tls.cert", "Certificate SHA-1"),
    FieldSpec::tags(
        "file.role",
        "sample, created, executed, deleted, written at close, changed",
    ),
    FieldSpec::text("file.path", "Path in the guest"),
    FieldSpec::text("file.sha256", "SHA-256 of the content"),
];

pub fn example(ty: Type) -> &'static str {
    match ty {
        Type::Endpoint => "ioc.match == matched",
        Type::Domain => "ioc.value contains example",
        Type::Url => "ioc.value contains .kd",
        Type::Tls => "tls.ja3 == \"f6d64cbcb6dead5e8e864400f056fa32\"",
        Type::File => "file.role contains executed",
    }
}

fn text(value: &str) -> RowValue {
    if value.is_empty() {
        RowValue::Missing
    } else {
        RowValue::Text(value.to_owned())
    }
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Matched => "matched",
        Outcome::KnownFp => "known_fp",
        Outcome::NoMatch => "no_match",
        Outcome::NotChecked => "not_checked",
    }
}

/// The values a filter can read from one row.
pub fn values(indicator: &Indicator, verdict: &Verdict) -> Vec<(&'static str, RowValue)> {
    let tls = indicator.tls.clone().unwrap_or_default();
    let primary = verdict
        .primary()
        .or_else(|| verdict.excused.as_ref().map(|(found, _)| found));
    let hash = indicator
        .hashes
        .as_ref()
        .map(|hashes| hashes.sha256.as_str())
        .unwrap_or("");
    vec![
        ("ioc.type", RowValue::Text(indicator.ty.id().into())),
        ("ioc.value", RowValue::Text(indicator.value.clone())),
        (
            "ioc.match",
            RowValue::Text(outcome_name(verdict.outcome).into()),
        ),
        (
            "ioc.source",
            RowValue::List(
                indicator
                    .sources
                    .iter()
                    .map(|s| s.label().to_owned())
                    .collect(),
            ),
        ),
        (
            "ioc.process",
            indicator
                .process
                .as_ref()
                .map_or(RowValue::Missing, |process| RowValue::Text(process.label())),
        ),
        (
            "ioc.dataset",
            primary.map_or(RowValue::Missing, |found| text(&found.record.feed)),
        ),
        (
            "ioc.family",
            primary.map_or(RowValue::Missing, |found| text(&found.record.family)),
        ),
        (
            "ioc.confidence",
            primary
                .and_then(|found| found.record.confidence)
                .map_or(RowValue::Missing, |c| RowValue::Number(i128::from(c))),
        ),
        (
            "ioc.first_us",
            indicator
                .first_us
                .map_or(RowValue::Missing, |us| RowValue::Number(i128::from(us))),
        ),
        (
            "ioc.last_us",
            indicator
                .last_us
                .map_or(RowValue::Missing, |us| RowValue::Number(i128::from(us))),
        ),
        ("tls.sni", text(&tls.sni)),
        ("tls.ja3", text(&tls.ja3)),
        ("tls.ja4", text(&tls.ja4)),
        ("tls.ja3s", text(&tls.ja3s)),
        ("tls.cert", text(&tls.cert_sha1)),
        (
            "file.role",
            RowValue::List(indicator.roles.iter().map(|r| (*r).to_owned()).collect()),
        ),
        ("file.path", text(&indicator.path)),
        ("file.sha256", text(hash)),
    ]
}

/// The shared Details table this tab selects into.
pub const DETAILS_TABLE: &str = "triage-ioc";
pub const DETAILS_HEADERS: &[&str] = &["Indicator", "Kind", "Id"];

/// The selection the shared Details pane keeps: the value, the kind and the
/// indicator's id, which finds it again in the scan.
pub fn details_cells(indicator: &Indicator) -> Vec<Cell> {
    vec![
        cell(&indicator.value, tone::text(), true),
        cell(kind_name(indicator.ty), tone::text(), false),
        cell(indicator.id(), tone::text(), true),
    ]
}

pub fn time_text(us: Option<u64>) -> String {
    us.map_or("—".into(), crate::time_format::short_time_us)
}

pub fn jump_of(jump: &Evidence) -> Option<Jump> {
    match jump {
        Evidence::Packet { capture, frame } => Some(Jump::Packet {
            capture: capture.clone(),
            frame: *frame,
        }),
        Evidence::Call {
            stream,
            cookie,
            call,
        } => Some(Jump::Call {
            stream: *stream,
            cookie: *cookie,
            call: *call,
        }),
        Evidence::Text => Some(Jump::Properties),
    }
}

/// What the Details heading calls an indicator of this type.
pub fn kind_name(ty: Type) -> &'static str {
    match ty {
        Type::Endpoint => "Endpoint",
        Type::Domain => "Domain",
        Type::Url => "URL",
        Type::Tls => "TLS session",
        Type::File => "File",
    }
}

/// The line under the verdict chip.
pub fn verdict_line(verdict: &Verdict) -> String {
    match verdict.outcome {
        Outcome::Matched => verdict.primary().map_or_else(String::new, |found| {
            format!(
                "{} · {} · {} · first seen {}",
                if found.record.family.is_empty() {
                    "no family"
                } else {
                    &found.record.family
                },
                ioc_scan::dataset_name(&found.record.feed),
                found
                    .record
                    .confidence
                    .map_or("no confidence".to_owned(), |c| format!("{c}%")),
                found.record.first_seen,
            )
        }),
        Outcome::KnownFp => verdict
            .excused
            .as_ref()
            .map_or_else(String::new, |(found, entry)| {
                format!(
                    "{} · dataset {}",
                    if entry.reason.is_empty() {
                        "known false positive"
                    } else {
                        &entry.reason
                    },
                    verdict
                        .date
                        .clone()
                        .unwrap_or_else(|| ioc_scan::dataset_name(&found.record.feed).to_owned())
                )
            }),
        Outcome::NoMatch => format!(
            "dataset {}{}",
            verdict.date.clone().unwrap_or_default(),
            if verdict.partial() {
                format!(
                    " · {} of {} feeds",
                    verdict.feeds_used, verdict.feeds_needed
                )
            } else {
                String::new()
            }
        ),
        Outcome::NotChecked => verdict.why.clone(),
    }
}
