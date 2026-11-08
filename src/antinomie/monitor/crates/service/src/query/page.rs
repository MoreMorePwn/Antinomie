// SPDX-License-Identifier: GPL-3.0-only
//! `PageRequest`, `Page<T>` and `Single<T>` (design 5.12.1, 5.12.5): the only
//! two result shapes of version 1.

use super::{
    cursor::Generation,
    types::{AnalysisPageNotes, ProcessTreeNotes},
};
use crate::api::{error::ApiError, job::RecordingPhase};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `{limit, cursor}`. `limit` defaults to 100 and is at most 500 for a row page
/// (packets 500, analysis and Ghidra pages 1024, terminal 256).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl PageRequest {
    /// The limit to use, or `invalid_argument` naming `limit`. `max` is the
    /// operation's (`ops[].max_limit`).
    pub fn effective_limit(&self, default: u32, max: u32) -> Result<u32, ApiError> {
        match self.limit {
            None => Ok(default.min(max)),
            Some(limit) if (1..=max).contains(&limit) => Ok(limit),
            Some(_) => Err(ApiError::invalid_argument("limit", format!("1 to {max}"))),
        }
    }
}

/// Progress of a running Triage scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanProgress {
    pub done: u64,
    pub total: u64,
}

/// The answer of a Triage-based read (class T) whose scan is not cached: a
/// success, mapped to HTTP `202` with `Retry-After`. The page has no items, no
/// `next_cursor`, no `total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Building {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<ScanProgress>,
    pub retry_after_ms: u64,
}

/// What a few operations add to their first page (design 5.12.3): the process
/// tree's issues and the analysis pages' function table. The members of the
/// two objects differ, so a page's `notes` tells them apart by shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PageExtra {
    Process(ProcessTreeNotes),
    Analysis(AnalysisPageNotes),
}

/// A page of rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    /// When cheap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// False while the recording or a TShark parse is still growing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_exact: Option<bool>,
    pub generation: Generation,
    pub phase: RecordingPhase,
    /// True when the recording is `interrupted` or an engine limit cut the
    /// page. Absent means false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub building: Option<Building>,
    /// True when rows carry strings that came from the sample or the guest
    /// (5.2): escape them on display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<bool>,
    /// The extras of `recording.process.tree` (first page) and of the analysis
    /// pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<PageExtra>,
}

impl<T> Page<T> {
    /// A page of a recording at `generation` in `phase`, nothing optional set.
    pub fn new(items: Vec<T>, generation: Generation, phase: RecordingPhase) -> Self {
        Self {
            items,
            next_cursor: None,
            total: None,
            total_exact: None,
            generation,
            phase,
            partial: None,
            building: None,
            untrusted: None,
            notes: None,
        }
    }

    /// The `building` reply: no items, no cursor, no total.
    pub fn building(generation: Generation, phase: RecordingPhase, building: Building) -> Self {
        Self {
            building: Some(building),
            ..Self::new(Vec::new(), generation, phase)
        }
    }
}

/// A single result (`recording.run.get`, `summary`, `findings.get`,
/// `network.summary`, `trace.get`, `files.versions`, `packet`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Single<T> {
    /// Absent while `building`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
    pub generation: Generation,
    pub phase: RecordingPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub building: Option<Building>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<bool>,
}

impl<T> Single<T> {
    pub fn new(value: T, generation: Generation, phase: RecordingPhase) -> Self {
        Self {
            value: Some(value),
            generation,
            phase,
            partial: None,
            building: None,
            untrusted: None,
        }
    }

    pub fn building(generation: Generation, phase: RecordingPhase, building: Building) -> Self {
        Self {
            value: None,
            generation,
            phase,
            partial: None,
            building: Some(building),
            untrusted: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn limits_default_and_bound() {
        let page = PageRequest::default();
        assert_eq!(page.effective_limit(100, 500).unwrap(), 100);
        assert_eq!(page.effective_limit(100, 50).unwrap(), 50);
        let zero = PageRequest {
            limit: Some(0),
            cursor: None,
        };
        assert_eq!(
            zero.effective_limit(100, 500).unwrap_err().field.as_deref(),
            Some("limit")
        );
        let big = PageRequest {
            limit: Some(501),
            cursor: None,
        };
        assert!(big.effective_limit(100, 500).is_err());
        assert_eq!(
            PageRequest {
                limit: Some(500),
                cursor: None
            }
            .effective_limit(100, 500)
            .unwrap(),
            500
        );
    }

    #[test]
    fn a_plain_page_has_only_the_always_present_members() {
        let page: Page<u32> = Page::new(vec![1, 2], Generation(9), RecordingPhase::Complete);
        assert_eq!(
            serde_json::to_value(&page).unwrap(),
            json!({"items": [1, 2], "next_cursor": null, "generation": "9", "phase": "complete"})
        );
    }

    #[test]
    fn a_building_page_has_no_items_cursor_or_total() {
        let page: Page<u32> = Page::building(
            Generation(1),
            RecordingPhase::Complete,
            Building {
                progress: Some(ScanProgress { done: 1, total: 4 }),
                retry_after_ms: 750,
            },
        );
        let value = serde_json::to_value(&page).unwrap();
        assert_eq!(value["items"], json!([]));
        assert!(value["next_cursor"].is_null());
        assert!(value.get("total").is_none());
        assert_eq!(
            value["building"],
            json!({"progress": {"done": 1, "total": 4}, "retry_after_ms": 750})
        );
        let single: Single<u32> = Single::building(
            Generation(1),
            RecordingPhase::Finalizing,
            Building {
                progress: None,
                retry_after_ms: 1,
            },
        );
        let value = serde_json::to_value(&single).unwrap();
        assert!(value.get("value").is_none());
        assert_eq!(
            serde_json::from_value::<Single<u32>>(value).unwrap(),
            single
        );
    }

    #[test]
    fn partial_and_inexact_totals_are_carried() {
        let mut page: Page<u32> = Page::new(vec![], Generation(2), RecordingPhase::Interrupted);
        page.partial = Some(true);
        page.total = Some(10);
        page.total_exact = Some(false);
        let back: Page<u32> = serde_json::from_value(serde_json::to_value(&page).unwrap()).unwrap();
        assert_eq!(back, page);
    }
}
