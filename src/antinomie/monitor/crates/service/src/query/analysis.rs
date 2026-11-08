// SPDX-License-Identifier: GPL-3.0-only
//! `recording.analysis.list`, `.section` and `.ghidra` (design 5.12.3): the
//! static analysis report of a run, or the host-side analysis of a job, read
//! from its archived report and listings. Exactly one of `run_key` and
//! `job_id` addresses it. Specimen bytes are not part of any reply.

use super::{
    cursor::{Cursor, CursorBinding, Generation, stable_hash},
    key::RunKey,
    limits::fit_in_page,
    page::{Page, PageExtra, PageRequest},
    request::{
        AnalysisGhidraParams, AnalysisListParams, AnalysisSectionParams, AnalysisSubject, Sort,
        SortDir, analysis_subject,
    },
    service::{Opened, QueryService},
    types::*,
};
use crate::api::{error::ApiError, ids::JobId, job::RecordingPhase};
use antinomie_monitor_core::analysis::{
    self, AnalysisKind, AnalysisListingPage, ListingSort, StructureField,
};
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

/// The analysis an operation reads and what its pages are bound to.
struct Source {
    /// The folder holding `report.json` and `listings/`.
    dir: PathBuf,
    generation: Generation,
    phase: RecordingPhase,
    partial: bool,
    growing: bool,
    /// What a cursor is bound to besides the generation.
    subject: String,
    /// Keeps the run's lease while the read lasts.
    _opened: Option<Opened>,
}

fn kind_of(kind: AnalysisKind) -> AnalysisKindName {
    use AnalysisKind as K;
    match kind {
        K::Metadata => AnalysisKindName::Metadata,
        K::Structures => AnalysisKindName::Structures,
        K::Strings => AnalysisKindName::Strings,
        K::Regex => AnalysisKindName::Regex,
        K::Entropy => AnalysisKindName::Entropy,
        K::Hardening => AnalysisKindName::Hardening,
        K::Rules => AnalysisKindName::Rules,
        K::Identification => AnalysisKindName::Identification,
        K::Capabilities => AnalysisKindName::Capabilities,
        K::Disassembly => AnalysisKindName::Disassembly,
        K::Decompilation => AnalysisKindName::Decompilation,
        K::Embedded => AnalysisKindName::Embedded,
        K::Floss => AnalysisKindName::Floss,
        K::Unpacking => AnalysisKindName::Unpacking,
    }
}

fn engine_kind(kind: AnalysisKindName) -> AnalysisKind {
    use AnalysisKind as K;
    match kind {
        AnalysisKindName::Metadata => K::Metadata,
        AnalysisKindName::Structures => K::Structures,
        AnalysisKindName::Strings => K::Strings,
        AnalysisKindName::Regex => K::Regex,
        AnalysisKindName::Entropy => K::Entropy,
        AnalysisKindName::Hardening => K::Hardening,
        AnalysisKindName::Rules => K::Rules,
        AnalysisKindName::Identification => K::Identification,
        AnalysisKindName::Capabilities => K::Capabilities,
        AnalysisKindName::Disassembly => K::Disassembly,
        AnalysisKindName::Decompilation => K::Decompilation,
        AnalysisKindName::Embedded => K::Embedded,
        AnalysisKindName::Floss => K::Floss,
        AnalysisKindName::Unpacking => K::Unpacking,
    }
}

fn state_of(state: analysis::AnalysisSectionState) -> AnalysisSectionState {
    use analysis::AnalysisSectionState as S;
    match state {
        S::Pending => AnalysisSectionState::Pending,
        S::Running => AnalysisSectionState::Running,
        S::Complete => AnalysisSectionState::Complete,
        S::Partial => AnalysisSectionState::Partial,
        S::Unavailable => AnalysisSectionState::Unavailable,
        S::Timeout => AnalysisSectionState::Timeout,
    }
}

/// The text of a serde unit variant (`rows`, `time`, ...).
fn variant_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn section_info(section: &analysis::AnalysisSection) -> AnalysisSection {
    let (rows, bytes, truncated) = match &section.listing {
        Some(listing) => (listing.rows, listing.bytes, listing.truncated),
        None => (
            section.entries.len() as u64,
            section
                .entries
                .iter()
                .map(|e| (e.label.len() + e.value.len()) as u64)
                .sum(),
            section.limits.iter().any(|limit| {
                matches!(
                    limit.kind,
                    analysis::AnalysisLimitKind::Rows | analysis::AnalysisLimitKind::Size
                )
            }),
        ),
    };
    AnalysisSection {
        kind: kind_of(section.kind),
        state: state_of(section.state),
        summary: section.summary.clone(),
        tools: section.tools.clone(),
        rows,
        bytes,
        truncated,
        limits: section
            .limits
            .iter()
            .map(|limit| AnalysisLimitInfo {
                kind: variant_name(&limit.kind),
                text: limit.text.clone(),
                seconds: limit.seconds,
                setting: limit.setting.as_ref().map(variant_name),
            })
            .collect(),
        ghidra: section.disassembly.as_ref().map(|d| GhidraInfo {
            tool: d.tool.clone(),
            language: d.language.clone(),
            endian: d.endian.clone(),
            pointer_bits: d.pointer_bits,
            functions: d.functions,
            instructions: d.instructions,
            note: d.note.clone(),
        }),
    }
}

fn entry_of(entry: &analysis::AnalysisEntry) -> AnalysisEntry {
    AnalysisEntry {
        label: entry.label.clone(),
        value: entry.value.clone(),
        offset: entry.offset.map(U64),
        record: entry.record.as_ref().map(|record| AnalysisRecord {
            revision: u32::from(record.revision),
            id: record.id.to_string(),
            location: record.location.as_ref().map(|location| AnalysisLocation {
                kind: variant_name(&location.kind),
                value: format!("{:#x}", location.value),
                file_range: location.file_range.map(|range| FileRange {
                    offset: U64(range.offset),
                    len: range.len,
                }),
            }),
            data: serde_json::to_value(&record.data).unwrap_or(serde_json::Value::Null),
        }),
    }
}

/// The engine's sort of a request: the Strings columns, or a `StructureField`.
fn listing_sort(kind: AnalysisKind, sort: &Sort) -> Result<ListingSort, ApiError> {
    let descending = sort.dir == SortDir::Desc;
    let bad = || ApiError::invalid_argument("sort", format!("cannot sort by {}", sort.field));
    if kind == AnalysisKind::Strings {
        let column = match sort.field.as_str() {
            "offset" => 0,
            "encoding" => 1,
            "length" => 2,
            "text" => 3,
            _ => return Err(bad()),
        };
        return Ok(ListingSort {
            column,
            descending,
            field: None,
        });
    }
    let field = match sort.field.as_str() {
        "name" => StructureField::Name,
        "value" => StructureField::Value,
        "address" => StructureField::Address,
        "offset" => StructureField::Offset,
        "virtual_size" => StructureField::VirtualSize,
        "file_size" => StructureField::FileSize,
        "flags" => StructureField::Flags,
        "library" => StructureField::Library,
        "ordinal" => StructureField::Ordinal,
        "kind" => StructureField::Kind,
        "scope" => StructureField::Scope,
        "defined" => StructureField::Defined,
        "size" => StructureField::Size,
        _ => return Err(bad()),
    };
    Ok(ListingSort {
        column: 0,
        descending,
        field: Some(field),
    })
}

/// A hash of the files an analysis folder is made of.
fn analysis_generation(dir: &std::path::Path) -> Generation {
    let mut parts: Vec<(String, u64, i64, i64)> = Vec::new();
    for name in ["report.json", "listings"] {
        if let Ok(meta) = fs::symlink_metadata(dir.join(name)) {
            parts.push((name.to_owned(), meta.len(), meta.mtime(), meta.mtime_nsec()));
        }
    }
    Generation(stable_hash(&parts))
}

impl QueryService {
    fn analysis_source(
        &self,
        run_key: &Option<RunKey>,
        job_id: &Option<JobId>,
    ) -> Result<Source, ApiError> {
        match analysis_subject(run_key, job_id)? {
            AnalysisSubject::Run(key) => {
                let opened = self.open_run(&key)?;
                let dir = opened.dir.join("analysis");
                if !dir.join("report.json").is_file() {
                    return Err(ApiError::not_recorded("static analysis"));
                }
                Ok(Source {
                    dir,
                    generation: opened.generation,
                    phase: opened.phase.phase,
                    partial: opened.phase.partial(),
                    growing: opened.phase.growing(),
                    subject: key.to_string(),
                    _opened: Some(opened),
                })
            }
            AnalysisSubject::Job(job) => {
                let dir = self
                    .jobs
                    .as_ref()
                    .and_then(|jobs| jobs.analysis_directory(&job))
                    .ok_or_else(|| ApiError::not_found("job analysis"))?;
                let dir = fs::canonicalize(dir).map_err(|_| ApiError::not_found("job analysis"))?;
                if !dir.join("report.json").is_file() {
                    return Err(ApiError::not_recorded("static analysis"));
                }
                Ok(Source {
                    generation: analysis_generation(&dir),
                    dir,
                    phase: RecordingPhase::Complete,
                    partial: false,
                    growing: false,
                    subject: job.to_string(),
                    _opened: None,
                })
            }
        }
    }

    fn report(&self, source: &Source) -> Result<analysis::AnalysisReport, ApiError> {
        analysis::open_report(&source.dir).map_err(|e| super::errors::text_error(&e, &self.scrub))
    }

    fn analysis_page<T>(&self, source: &Source, items: Vec<T>) -> Page<T> {
        let mut page = Page::new(items, source.generation, source.phase);
        page.partial = source.partial.then_some(true);
        page.untrusted = Some(true);
        page
    }

    /// `recording.analysis.list`.
    pub(super) fn analysis_list(
        &self,
        params: &AnalysisListParams,
    ) -> Result<Page<AnalysisSection>, ApiError> {
        let source = self.analysis_source(&params.run_key, &params.job_id)?;
        let report = self.report(&source)?;
        let items: Vec<AnalysisSection> = report.sections.iter().map(section_info).collect();
        let total = items.len() as u64;
        let mut page = self.analysis_page(&source, items);
        page.total = Some(total);
        page.total_exact = Some(!source.growing);
        Ok(page)
    }

    #[allow(clippy::too_many_arguments)]
    fn analysis_rows(
        &self,
        source: &Source,
        kind: AnalysisKindName,
        ghidra: bool,
        q: &Option<String>,
        sort: &Option<Sort>,
        request: PageRequest,
    ) -> Result<Page<AnalysisRow>, ApiError> {
        let row_limits = &self.settings.limits.row;
        let limit = request.effective_limit(row_limits.analysis, row_limits.analysis)? as usize;
        let query = q.clone().unwrap_or_default();
        let engine = engine_kind(kind);
        let sort_request = match sort {
            Some(sort) => Some(listing_sort(engine, sort)?),
            None => None,
        };
        let binding = CursorBinding {
            generation: source.generation,
            filter_hash: stable_hash(&(&source.subject, kind, ghidra, &query)),
            sort_hash: stable_hash(sort),
        };
        let start = match &request.cursor {
            Some(text) => Cursor::resume(text, binding)?,
            None => 0,
        };
        let report = self.report(source)?;
        let by_text = |needle: String| {
            move |entry: &analysis::AnalysisEntry| {
                needle.is_empty()
                    || entry.label.to_lowercase().contains(&needle)
                    || entry.value.to_lowercase().contains(&needle)
            }
        };
        let listed: AnalysisListingPage = if ghidra {
            analysis::read_ghidra_disassembly_page(
                &source.dir,
                &report.id,
                start,
                limit,
                &query,
                by_text(query.to_lowercase()),
            )
        } else {
            let section = report
                .sections
                .iter()
                .find(|section| section.kind == engine)
                .ok_or_else(|| ApiError::not_found("analysis section"))?;
            if section.listing.is_some() {
                analysis::read_listing_page_sorted(
                    &source.dir,
                    &report.id,
                    engine,
                    start,
                    limit,
                    &query,
                    sort_request,
                    by_text(query.to_lowercase()),
                )
            } else {
                Ok(embedded_page(&report.id, section, &query, start, limit))
            }
        }
        .map_err(|e| super::errors::text_error(&e, &self.scrub))?;
        let rows: Vec<AnalysisRow> = listed
            .rows
            .iter()
            .map(|(index, entry)| AnalysisRow {
                index: *index,
                entry: entry_of(entry),
            })
            .collect();
        let kept = fit_in_page(
            rows.iter()
                .map(|row| serde_json::to_vec(row).map_or(0, |b| b.len())),
        );
        let rows: Vec<AnalysisRow> = rows.into_iter().take(kept).collect();
        let next = start + rows.len() as u64;
        let mut page = self.analysis_page(source, rows);
        page.total = Some(listed.total);
        page.total_exact = Some(!source.growing);
        page.next_cursor = (next < listed.total && !page.items.is_empty()).then(|| {
            Cursor {
                offset: next,
                binding,
            }
            .encode()
        });
        let is_source = matches!(
            engine,
            AnalysisKind::Disassembly | AnalysisKind::Decompilation
        ) || ghidra;
        page.notes = Some(PageExtra::Analysis(AnalysisPageNotes {
            functions: (is_source && start == 0).then(|| {
                listed
                    .functions
                    .iter()
                    .map(|function| AnalysisFunctionLines {
                        name: function.name.clone(),
                        address: format!("{:#x}", function.address),
                        lines: function.lines,
                    })
                    .collect()
            }),
            sorted: listed.sort.is_some(),
        }));
        Ok(page)
    }

    /// `recording.analysis.section`.
    pub(super) fn analysis_section(
        &self,
        params: &AnalysisSectionParams,
    ) -> Result<Page<AnalysisRow>, ApiError> {
        let source = self.analysis_source(&params.run_key, &params.job_id)?;
        let request = PageRequest {
            limit: params.limit,
            cursor: params.cursor.clone(),
        };
        self.analysis_rows(
            &source,
            params.kind,
            false,
            &params.q,
            &params.sort,
            request,
        )
    }

    /// `recording.analysis.ghidra`.
    pub(super) fn analysis_ghidra(
        &self,
        params: &AnalysisGhidraParams,
    ) -> Result<Page<AnalysisRow>, ApiError> {
        let source = self.analysis_source(&params.run_key, &params.job_id)?;
        let request = PageRequest {
            limit: params.limit,
            cursor: params.cursor.clone(),
        };
        let report = self.report(&source)?;
        if report
            .ghidra_disassembly_section()
            .and_then(|s| s.disassembly.as_ref())
            .is_none()
        {
            return Err(ApiError::not_recorded("Ghidra disassembly"));
        }
        self.analysis_rows(
            &source,
            AnalysisKindName::Disassembly,
            true,
            &params.q,
            &None,
            request,
        )
    }
}

/// The page of a section whose rows live in the report itself.
fn embedded_page(
    report_id: &str,
    section: &analysis::AnalysisSection,
    query: &str,
    start: u64,
    count: usize,
) -> AnalysisListingPage {
    let needle = query.to_lowercase();
    let matching: Vec<(u64, &analysis::AnalysisEntry)> = section
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            needle.is_empty()
                || entry.label.to_lowercase().contains(&needle)
                || entry.value.to_lowercase().contains(&needle)
        })
        .map(|(index, entry)| (index as u64, entry))
        .collect();
    AnalysisListingPage {
        report_id: report_id.to_owned(),
        kind: section.kind,
        ghidra: false,
        query: query.to_owned(),
        sort: None,
        start,
        total: matching.len() as u64,
        rows: matching
            .into_iter()
            .skip(start as usize)
            .take(count)
            .map(|(index, entry)| (index, entry.clone()))
            .collect(),
        functions: Vec::new(),
    }
}
