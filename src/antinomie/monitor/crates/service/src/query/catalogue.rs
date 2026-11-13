// SPDX-License-Identifier: GPL-3.0-only
//! `capabilities.queries` (design 5.12.4a): the catalogue of every query
//! operation this build implements, with its filters, sortable fields and
//! limits, so a client never hard-codes one.

use crate::api::ops::Permission;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `C` needs only the engine; `T` needs the Triage scan and can answer
/// `building`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum OpClass {
    C,
    T,
}

/// What addresses an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OpSubject {
    RecordingKey,
    /// The analysis operations: a run's analysis, or a run's host-side one.
    RunIdOrRecordingKey,
    /// Custody, instead of a run.
    Sha256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilterType {
    String,
    Integer,
    Boolean,
    Enum,
    TimeMs,
    /// The `q` language.
    Query,
    /// A Wireshark display filter.
    DisplayFilter,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FilterInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: FilterType,
    /// The allowed values of an `enum`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// The type of a table column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Text,
    Number,
    Boolean,
    Tags,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SortableInfo {
    pub field: String,
    #[serde(rename = "type")]
    pub kind: FieldType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
}

/// A column of a table, copied from the engine's `FieldSpec` lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FieldInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: FieldType,
    pub description: String,
    pub sortable: bool,
}

/// The columns of one `tab` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TableInfo {
    pub fields: Vec<FieldInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryOpInfo {
    /// For example `recording.findings.list`.
    pub op: String,
    pub class: OpClass,
    /// The permission the read needs: `runs.see_all`, or `evidence.view`
    /// for the bytes the sample or the guest made.
    pub permission: Permission,
    pub subject: OpSubject,
    pub filters: Vec<FilterInfo>,
    /// Empty: the list has a fixed order and a `sort` on it is
    /// `invalid_argument`.
    pub sortable: Vec<SortableInfo>,
    pub default_order: String,
    pub max_limit: u32,
    /// For operations with a `tab`: one table per tab value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tables: Option<BTreeMap<String, TableInfo>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RowLimits {
    pub default: u32,
    pub max: u32,
    pub analysis: u32,
    pub packets: u32,
    pub terminal: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ByteReadLimits {
    pub captured: u32,
    pub content: u32,
}

/// The row, byte and concurrency limits of 5.12.5 and 5.12.6.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryLimits {
    pub row: RowLimits,
    pub page_bytes: u32,
    pub byte_read: ByteReadLimits,
    pub light_concurrency: u32,
    pub heavy_concurrency: u32,
    pub scan_cache_mib: u32,
}

impl Default for QueryLimits {
    /// The defaults of the contract (`service.toml [query]` may change the
    /// concurrency and cache ones).
    fn default() -> Self {
        Self {
            row: RowLimits {
                default: 100,
                max: 500,
                analysis: 1024,
                packets: 500,
                terminal: 256,
            },
            page_bytes: 1 << 20,
            byte_read: ByteReadLimits {
                captured: 65_536,
                content: 1 << 20,
            },
            light_concurrency: 16,
            heavy_concurrency: 2,
            scan_cache_mib: 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryCatalogue {
    pub ops: Vec<QueryOpInfo>,
    pub limits: QueryLimits,
}
