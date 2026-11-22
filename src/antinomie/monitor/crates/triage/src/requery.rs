// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! A filter, sort or page change answered from the rows a scan kept
//! ([`row_index`]) instead of from the recording (ANT-T0590).
//!
//! The result is what a scan of the same recording with the same request would
//! have made: each table runs the scan's own [`query::compile_table`] and
//! [`sorting::Page`] over its rows in the order the scan saw them. What the
//! passes learned (processes, files, counts, the IOC list) does not depend on a
//! filter, sort or page, and is copied from the index the rows belong to.
use super::*;

/// The index `base` made, as `request` asks to see it; `None` when `base` kept
/// no rows or `request` has other toggles than the rows were made under.
pub fn answer(
    base: &ArchiveScan,
    request: &ScanRequest,
    cancel: &Arc<AtomicBool>,
) -> Option<Result<ArchiveScan, String>> {
    let index = base.rows.as_ref().filter(|index| index.fits(request))?;
    Some(derive(base, index, request, cancel))
}

fn derive(
    base: &ArchiveScan,
    index: &Arc<row_index::RowIndex>,
    request: &ScanRequest,
    cancel: &Arc<AtomicBool>,
) -> Result<ArchiveScan, String> {
    let mut data: ScanData = (*base.0).clone();
    data.whole_run = is_whole_run(request);

    // The findings table, the behaviour tally and the graph: the engine's rows
    // narrowed by the chips and the filter.
    let mut graph = graph::Collector::new(&data.process, request.finding_view);
    for mark in &index.info {
        graph.count_info(&request.finding_view, mark);
    }
    let mut finding_page = sorting::Page::new(request, 0, cancel);
    let finding_query = query::compile_table(&request.filters[0], FINDING_FIELDS);
    let mut tally = crate::digest::Tally::default();
    for finding in &index.findings {
        let in_table = rules::view_keeps(&request.finding_view, &finding.values)
            && finding_query.keep_table(&finding.values);
        graph.push(finding, in_table);
        if in_table {
            tally.push(finding);
            finding_page.push(finding.clone())?;
        }
    }
    data.graph = graph.finish();
    let (findings, findings_omitted, _) = finding_page.finish()?;
    data.findings = findings;
    data.findings_omitted = findings_omitted;
    data.behaviour = Some(tally.finish());

    // The file tables.
    let page_of = |slot: usize, fields: &[FieldSpec<'static>]| -> Result<_, String> {
        let query = query::compile_table(&request.filters[slot], fields);
        let mut page = sorting::Page::<Vec<Cell>>::new(request, slot, cancel);
        index.each(slot, cancel, |row| {
            if query.keep_table(&row[0].values) {
                page.push(row)?;
            }
            Ok(())
        })?;
        page.finish()
    };
    (data.read, data.read_omitted, _) = page_of(5, FILE_FIELDS)?;
    let (opened, opened_omitted, _) = page_of(1, FILE_FIELDS)?;
    data.opened = opened;
    data.opened_omitted = opened_omitted;
    for at in 0..FILE_TABS {
        let (rows, omitted, _) = page_of(8 + at, FILE_FIELDS)?;
        data.file_tabs[at] = FileRows { rows, omitted };
    }

    // The Changed files table, from the files themselves.
    let change_query = query::compile_table(&request.filters[2], FILE_FIELDS);
    let mut change_page = sorting::Page::<Vec<Cell>>::new(request, 2, cancel);
    let mut listed = Vec::new();
    for (at, change) in index.changes.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let row = change.row(data.clock_anchor);
        if change_query.keep_table(&row[0].values) {
            change_page.push(row)?;
            listed.push(at);
        }
    }
    data.file_changes = listed
        .iter()
        .skip(request.offsets[2])
        .take(request.rows())
        .map(|at| index.changes[*at].clone())
        .collect();
    let (mut changed, changed_omitted, _) = change_page.finish()?;
    crate::inetsim::label_stand_in_files(&mut changed);
    data.changed = changed;
    data.changed_omitted = changed_omitted;

    // The Network tables.
    (data.http, data.http_omitted, _) = page_of(3, HTTP_FIELDS)?;
    let mut tabs = NewTabs {
        inetsim: std::mem::take(&mut data.new_tabs.inetsim),
        ..NewTabs::default()
    };
    (tabs.endpoints, tabs.endpoints_omitted, _) = page_of(ENDPOINT_SLOT, network::ENDPOINT_FIELDS)?;
    (tabs.domains, tabs.domains_omitted, _) = page_of(DOMAIN_SLOT, network::DOMAIN_FIELDS)?;
    (tabs.tls, tabs.tls_omitted, _) = page_of(TLS_SLOT, network::TLS_FIELDS)?;
    let ioc = data.ioc.clone().ok_or("the kept index has no IOC list")?;
    ioc_scan::annotate(&mut tabs, &data.http, &ioc, &index.verdicts);
    data.new_tabs = tabs;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    Ok(ArchiveScan::new(data))
}

/// What differs between two indexes in the tables a filter, sort or page
/// shapes; empty when they are the same. For the tests and the timing harness.
#[cfg(any(test, feature = "test-support"))]
pub fn differences(a: &ScanData, b: &ScanData) -> Vec<String> {
    fn rows(rows: &[Vec<Cell>]) -> Vec<String> {
        rows.iter()
            .map(|row| {
                row.iter()
                    .map(|cell| {
                        format!(
                            "{}|{:?}|{}|{:?}",
                            cell.text, cell.tone, cell.mono, cell.values
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\u{1f}")
            })
            .collect()
    }
    fn findings(rows: &[Finding]) -> Vec<String> {
        rows.iter()
            .map(|finding| format!("{:?}|{}|{:?}", finding.key, finding.call_id, finding.values))
            .collect()
    }
    let mut out = Vec::new();
    let mut check = |name: &str, same: bool| {
        if !same {
            out.push(name.to_owned());
        }
    };
    check("findings", findings(&a.findings) == findings(&b.findings));
    check("findings_omitted", a.findings_omitted == b.findings_omitted);
    check("behaviour", a.behaviour == b.behaviour);
    check(
        "graph.index.tiers",
        a.graph.index.tiers == b.graph.index.tiers,
    );
    check(
        "graph.index.records",
        a.graph.index.records.len() == b.graph.index.records.len(),
    );
    check(
        "graph.index.unplaced",
        a.graph.index.unplaced == b.graph.index.unplaced,
    );
    check(
        "graph.overview.tiers",
        a.graph.overview.tiers == b.graph.overview.tiers,
    );
    check("graph.high", a.graph.high == b.graph.high);
    check(
        "read",
        rows(&a.read) == rows(&b.read) && a.read_omitted == b.read_omitted,
    );
    check(
        "changed",
        rows(&a.changed) == rows(&b.changed) && a.changed_omitted == b.changed_omitted,
    );
    check(
        "file_changes",
        a.file_changes
            .iter()
            .map(|c| c.evidence_key())
            .collect::<Vec<_>>()
            == b.file_changes
                .iter()
                .map(|c| c.evidence_key())
                .collect::<Vec<_>>(),
    );
    check(
        "opened",
        rows(&a.opened) == rows(&b.opened) && a.opened_omitted == b.opened_omitted,
    );
    for at in 0..FILE_TABS {
        check(
            &format!("file_tabs[{at}]"),
            rows(&a.file_tabs[at].rows) == rows(&b.file_tabs[at].rows)
                && a.file_tabs[at].omitted == b.file_tabs[at].omitted,
        );
    }
    check(
        "http",
        rows(&a.http) == rows(&b.http) && a.http_omitted == b.http_omitted,
    );
    let (x, y) = (&a.new_tabs, &b.new_tabs);
    check(
        "endpoints",
        rows(&x.endpoints) == rows(&y.endpoints) && x.endpoints_omitted == y.endpoints_omitted,
    );
    check(
        "domains",
        rows(&x.domains) == rows(&y.domains) && x.domains_omitted == y.domains_omitted,
    );
    check(
        "tls",
        rows(&x.tls) == rows(&y.tls) && x.tls_omitted == y.tls_omitted,
    );
    check("urls", rows(&x.urls) == rows(&y.urls));
    check("inetsim", rows(&x.inetsim) == rows(&y.inetsim));
    check("whole_run", a.whole_run == b.whole_run);
    out
}
