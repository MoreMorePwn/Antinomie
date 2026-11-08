// SPDX-License-Identifier: GPL-3.0-only
//! `recording.summary`, `recording.findings.list/get` and
//! `recording.indicators.list` (design 5.12.3 class T, card Q-4). Every row is
//! the Triage crate's own: the findings of the scan the window shows, the
//! summary and the indicators of the report builder the export and
//! `antinomie-cli triage` use, so the counts are the same on every route.

use super::{
    page::{Page, PageRequest, Single},
    request::{FindingGetParams, FindingsListParams, IndicatorsListParams, RunParams},
    scan::{Scan, Scanned},
    service::{Opened, QueryService},
    tables::{self, Cut, V, Values},
    types::*,
};
use crate::{
    api::{
        assessment::Tier,
        error::{ApiError, ErrorCode},
        job::RecordingPhase,
    },
    verdict::Facts,
};
use antinomie_monitor_core::{
    ioc::{feeds, online},
    known_fp,
    report::{self, Choices, Part},
};
use antinomie_triage::{
    FINDING_FIELDS, ioc_scan, ioc_view, report_export, summary::rule_text, time_format,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

/// What the report builder gives that more than one read uses: the summary,
/// and the indicators with their filter values. Built once per scan.
pub struct Derived {
    pub summary: Summary,
    pub indicators: Vec<(
        report::Indicator,
        Vec<(&'static str, antinomie_triage::query::RowValue)>,
    )>,
    pub notes: Vec<String>,
}

/// The enum value a Triage text spells (`"high"`, `"c2"`, `"allow-listed"`).
fn parse<T: DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
}

pub(super) fn tier_of(text: &str) -> Tier {
    parse(text).unwrap_or(Tier::None)
}

impl QueryService {
    /// The scan of the run for a class T read: `Ok(Err(page))` while it is
    /// being built. A recording that is still being written is refused.
    pub(super) fn triage_scan(
        &self,
        opened: &Opened,
    ) -> Result<Result<Scanned, super::page::Building>, ApiError> {
        if opened.phase.phase == RecordingPhase::Live {
            return Err(ApiError::recording_open("live"));
        }
        if opened.run.root_task_cookie == 0 {
            return Err(ApiError::new(
                ErrorCode::PreconditionFailed,
                "the run has no recorded program (it never started): there is nothing to triage",
            ));
        }
        match self.scans.get(
            &opened.run,
            &opened.dir,
            opened.generation,
            &self.options,
            self.settings.heavy_retry_after_s,
            &self.scrub,
        )? {
            Scan::Ready(done) => Ok(Ok(done)),
            Scan::Building(building) => Ok(Err(building)),
        }
    }

    /// The summary and the indicators of a scan, built on first use.
    pub(super) fn derived<'a>(&self, scanned: &'a Scanned) -> Result<&'a Derived, ApiError> {
        scanned
            .derived
            .get_or_init(|| self.build_derived(scanned))
            .as_ref()
            .map_err(|error| ApiError::recording_unreadable(&self.scrub.text(error)))
    }

    fn build_derived(&self, scanned: &Scanned) -> Result<Derived, String> {
        let choices = Choices {
            parts: vec![
                Part::Summary,
                Part::Attack,
                Part::Detections,
                Part::Indicators,
            ],
            formats: Vec::new(),
            bundle: false,
            ..Choices::default()
        };
        let job = report_export::Job::for_saved(&scanned.saved, choices, time_format::now_ms());
        let (job, built) = report_export::build_report(&job, &scanned.scan)?;
        let report = built.report;
        let summary = report.summary.clone().unwrap_or_default();
        let datasets = feeds::status(&self.options.data_dir)
            .iter()
            .filter(|feed| feed.usable())
            .count() as u32;
        let facts = Facts::of_report(
            &summary,
            report.detections.as_deref().unwrap_or_default(),
            report.attack.as_deref().unwrap_or_default(),
            None,
            datasets,
        );
        // The rows' filter values, in the order of the report's indicators.
        let values: Vec<Vec<(&'static str, antinomie_triage::query::RowValue)>> =
            match &scanned.scan.ioc {
                Some(ioc) => {
                    let fp = job
                        .data_dir
                        .as_deref()
                        .map(known_fp::load)
                        .unwrap_or_default();
                    let online = online::load(&job.archive);
                    ioc.indicators
                        .iter()
                        .zip(ioc_scan::verdicts(ioc, &fp, &online))
                        .map(|(indicator, verdict)| ioc_view::values(indicator, &verdict))
                        .collect()
                }
                None => Vec::new(),
            };
        let indicators = report
            .indicators
            .unwrap_or_default()
            .into_iter()
            .zip(values)
            .collect();
        Ok(Derived {
            summary: Summary {
                assessment: facts.assessment,
                highest_tier: facts.highest_tier,
                families: facts.families,
                counts: facts.counts,
                key_behaviours: facts.key_behaviours,
                detections: facts.detections,
                techniques: facts.techniques,
                ioc_dataset_count: datasets,
                basis: facts.statement,
            },
            indicators,
            notes: report.notes,
        })
    }

    fn building_page<T>(&self, opened: &Opened, building: super::page::Building) -> Page<T> {
        Page::building(opened.generation, opened.phase.phase, building)
    }

    /// `recording.summary`.
    pub(super) fn summary(&self, params: &RunParams) -> Result<Single<Summary>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        match self.triage_scan(&opened)? {
            Err(building) => Ok(Single::building(
                opened.generation,
                opened.phase.phase,
                building,
            )),
            Ok(scanned) => {
                let derived = self.derived(&scanned)?;
                let mut single = opened.single(derived.summary.clone(), true);
                if scanned.scan.partial {
                    single.partial = Some(true);
                }
                Ok(single)
            }
        }
    }

    /// `recording.findings.list`.
    pub(super) fn findings_list(
        &self,
        params: &FindingsListParams,
    ) -> Result<Page<Finding>, ApiError> {
        tables::check_sort(params.sort.as_ref(), FINDING_FIELDS)?;
        let compiled = tables::compile_q(params.q.as_deref(), FINDING_FIELDS)?;
        let opened = self.open_run(&params.run_key)?;
        let binding = opened.binding(
            &(
                params.tier,
                params.category,
                &params.rule,
                params.pid,
                &params.q,
            ),
            &params.sort,
        );
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => return Ok(self.building_page(&opened, building)),
            Ok(scanned) => scanned,
        };
        let scan = &scanned.scan;
        let tier = params.tier.map(tier_name);
        let category = params.category.map(|category| enum_name(&category));
        let keep = |values: &Values| {
            let v = V(values);
            tier.as_deref().is_none_or(|t| v.text("finding.tier") == t)
                && category
                    .as_deref()
                    .is_none_or(|c| v.text("finding.category") == c)
                && params
                    .rule
                    .as_deref()
                    .is_none_or(|rule| v.text("finding.rule") == rule)
                && params
                    .pid
                    .is_none_or(|pid| v.number("process.pid") == Some(i128::from(pid)))
        };
        // The default order: first occurrence, then the scan's own order.
        let mut base: Vec<usize> = (0..scan.findings.len()).collect();
        base.sort_by_key(|at| V(&scan.findings[*at].values).u64("finding.first_ns"));
        let rows: Vec<&Values> = base
            .iter()
            .map(|at| scan.findings[*at].values.as_slice())
            .collect();
        let order: Vec<usize> =
            tables::select(rows.iter().copied(), &compiled, keep, params.sort.as_ref())
                .into_iter()
                .map(|at| base[at])
                .collect();
        let cut = Cut {
            request: &PageRequest {
                limit: params.limit,
                cursor: params.cursor.clone(),
            },
            max: self.settings.rows().1,
            binding,
            omitted: scan.findings_omitted,
            untrusted: true,
        };
        tables::page_of(&opened, &order, &cut, |at| {
            finding_row(&opened, &scan.findings[at])
        })
    }

    /// `recording.findings.get`.
    pub(super) fn findings_get(
        &self,
        params: &FindingGetParams,
    ) -> Result<Single<FindingDetail>, ApiError> {
        let opened = self.open_run(&params.run_key)?;
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => {
                return Ok(Single::building(
                    opened.generation,
                    opened.phase.phase,
                    building,
                ));
            }
            Ok(scanned) => scanned,
        };
        let found = scanned
            .scan
            .findings
            .iter()
            .find(|finding| finding_id(&opened, finding) == params.finding_id)
            .ok_or_else(|| ApiError::not_found("finding"))?;
        let row = finding_row(&opened, found);
        let rule = row.rule.clone();
        let call = row.call;
        let count = row.count;
        let mut text = rule_text::rule_description(&rule);
        if text.is_empty() {
            text = rule_text::rule_title(&rule);
        }
        let detail = FindingDetail {
            finding: row,
            // The scan folds repeats into one row and keeps its representative
            // call only (departure from the design, noted in ANT-T0367).
            evidence_refs: vec![call],
            evidence_omitted: count.saturating_sub(1),
            rule_text: text,
        };
        Ok(opened.single(detail, true))
    }

    /// `recording.indicators.list`.
    pub(super) fn indicators_list(
        &self,
        params: &IndicatorsListParams,
    ) -> Result<Page<Indicator>, ApiError> {
        let fields = ioc_view::FIELDS;
        tables::check_sort(params.sort.as_ref(), fields)?;
        let compiled = tables::compile_q(params.q.as_deref(), fields)?;
        let opened = self.open_run(&params.run_key)?;
        let binding = opened.binding(
            &(params.kind, params.matched, &params.q, params.defang),
            &params.sort,
        );
        let scanned = match self.triage_scan(&opened)? {
            Err(building) => return Ok(self.building_page(&opened, building)),
            Ok(scanned) => scanned,
        };
        let derived = self.derived(&scanned)?;
        let kind = params.kind.map(|kind| enum_name(&kind));
        let keep = |values: &Values| {
            let v = V(values);
            kind.as_deref().is_none_or(|k| v.text("ioc.type") == k)
                && params
                    .matched
                    .is_none_or(|m| (v.text("ioc.match") == "matched") == m)
        };
        // The default order: matched first, then kind, then value.
        let mut base: Vec<usize> = (0..derived.indicators.len()).collect();
        base.sort_by_key(|at| {
            let (item, _) = &derived.indicators[*at];
            (!item.matched, item.kind.clone(), item.value.clone())
        });
        let rows: Vec<&Values> = base
            .iter()
            .map(|at| derived.indicators[*at].1.as_slice())
            .collect();
        let order: Vec<usize> =
            tables::select(rows.iter().copied(), &compiled, keep, params.sort.as_ref())
                .into_iter()
                .map(|at| base[at])
                .collect();
        let cut = Cut {
            request: &PageRequest {
                limit: params.limit,
                cursor: params.cursor.clone(),
            },
            max: self.settings.rows().1,
            binding,
            omitted: scanned.scan.ioc.as_ref().map_or(0, |ioc| ioc.omitted),
            untrusted: true,
        };
        tables::page_of(&opened, &order, &cut, |at| {
            let (item, values) = &derived.indicators[at];
            indicator_row(item, values, params.defang.unwrap_or(false))
        })
    }
}

fn enum_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn tier_name(tier: Tier) -> String {
    enum_name(&tier)
}

/// The opaque id of a finding row inside one generation: the call that made it
/// and the rule and object it was folded by.
pub(super) fn finding_id(opened: &Opened, finding: &antinomie_triage::Finding) -> String {
    let v = V(&finding.values);
    let digest = Sha256::digest(
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            opened.key.as_str(),
            v.text("stream.id"),
            v.text("process.cookie"),
            v.text("event.id"),
            v.text("finding.rule"),
            v.text("finding.object"),
        )
        .as_bytes(),
    );
    let hex: String = digest[..10].iter().map(|b| format!("{b:02x}")).collect();
    format!("fnd_{hex}")
}

/// The API row of one Triage finding.
fn finding_row(opened: &Opened, finding: &antinomie_triage::Finding) -> Finding {
    let v = V(&finding.values);
    let first = v.u64("finding.first_ns");
    let call = CallRef {
        stream: U64(v.u64("stream.id")),
        task: U64(v.u64("process.cookie")),
        call: U64(v.u64("event.id")),
    };
    Finding {
        finding_id: finding_id(opened, finding),
        rule: v.text("finding.rule"),
        version: v.u32("finding.version"),
        tier: tier_of(&v.text("finding.tier")),
        base_tier: tier_of(&v.text("finding.base_tier")),
        category: parse(&v.text("finding.category")).unwrap_or(FindingCategory::Execution),
        techniques: v.list("finding.technique"),
        count: v.u64("finding.count").max(1),
        flags: v
            .list("finding.flags")
            .iter()
            .filter_map(|flag| parse(flag))
            .collect(),
        hidden: v.flag("finding.hidden").unwrap_or(false),
        confidence: parse(&v.text("finding.confidence")).unwrap_or(Confidence::Limited),
        source: v.text("finding.source"),
        summary: v.text("finding.summary"),
        object: v.text("finding.object"),
        attempted: v.flag("finding.attempted").unwrap_or(false),
        success: v.flag("finding.success"),
        first_guest_ns: first,
        last_guest_ns: v.u64("finding.last_ns"),
        ts_ms: opened.ts_ms(first),
        process: ProcessRef {
            pid: v.u32("process.pid"),
            tid: v.u32("process.tid"),
            cookie: U64(v.u64("process.cookie")),
            exe: v.opt_text("process.exe"),
        },
        call,
        ret: v.number("syscall.ret").map(|n| n.to_string()),
    }
}

/// The API row of one report indicator.
fn indicator_row(item: &report::Indicator, values: &Values, defang: bool) -> Indicator {
    let v = V(values);
    let defanged = antinomie_monitor_core::samples::defang(&item.kind, &item.value);
    let sources = item
        .sources
        .split([',', ' '])
        .filter_map(|s| parse::<IndicatorSource>(&s.trim().to_lowercase()))
        .collect();
    let matching = if item.matched {
        IndicatorMatch::Matched
    } else {
        let verdict = item.verdict.to_lowercase();
        if verdict.contains("known") {
            IndicatorMatch::KnownFp
        } else if verdict.contains("not checked") {
            IndicatorMatch::NotChecked
        } else {
            IndicatorMatch::NoMatch
        }
    };
    let kind = parse(&item.kind).unwrap_or(IndicatorKind::Endpoint);
    Indicator {
        kind,
        value: if defang {
            defanged.clone()
        } else {
            item.value.clone()
        },
        defanged,
        matching,
        dataset: item.dataset.clone(),
        record_id: item.record_id.clone(),
        family: item.family.clone(),
        reference: item.reference.clone(),
        confidence: item.confidence.map(u32::from),
        sources,
        process: item.process.clone(),
        first_us: v.u64("ioc.first_us"),
        last_us: v.u64("ioc.last_us"),
        count: item.count.trim().parse().unwrap_or(0),
        url: item.url.clone(),
        sni: item.sni.clone(),
        ja3: item.ja3.clone(),
        ja4: item.ja4.clone(),
        ja3s: v.text("tls.ja3s"),
        cert_sha1: item.cert_sha1.clone(),
        path: item.path.clone(),
        sha256: item.sha256.clone(),
        md5: item.md5.clone(),
        sha1: item.sha1.clone(),
        file_role: v.list("file.role"),
        raw_indicators: !defang,
    }
}
