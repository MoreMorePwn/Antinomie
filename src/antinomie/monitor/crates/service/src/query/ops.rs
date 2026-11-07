// SPDX-License-Identifier: GPL-3.0-only
//! The table every `recording.*` operation is defined by (design 5.12.3, 5.12.4,
//! 5.12.5). `capabilities.queries` is generated from this table, and a test
//! checks the request types against it: an operation cannot take a filter or a
//! sort that the catalogue does not list.

use super::catalogue::*;
use super::types::*;
use std::collections::BTreeMap;

/// One operation: the catalogue row plus the request members that address the
/// read rather than filter it.
pub struct OpDef {
    pub info: QueryOpInfo,
    /// Request members that are neither filters nor paging nor `sort`:
    /// references, offsets, ranges, the subject.
    pub addressing: &'static [&'static str],
}

fn filter(name: &str, kind: FilterType) -> FilterInfo {
    FilterInfo {
        name: name.into(),
        kind,
        values: None,
        required: None,
    }
}

fn enum_filter<T: serde::Serialize>(name: &str, values: &[T], required: bool) -> FilterInfo {
    FilterInfo {
        name: name.into(),
        kind: FilterType::Enum,
        values: Some(
            values
                .iter()
                .filter_map(|v| serde_json::to_value(v).ok()?.as_str().map(str::to_owned))
                .collect(),
        ),
        required: required.then_some(true),
    }
}

/// Table columns: every column of a published table is sortable.
fn columns(fields: &[(&str, FieldType, &str)]) -> Vec<FieldInfo> {
    fields
        .iter()
        .map(|(name, kind, description)| FieldInfo {
            name: (*name).into(),
            kind: *kind,
            description: (*description).into(),
            sortable: true,
        })
        .collect()
}

fn sortable_of(tables: &BTreeMap<String, TableInfo>, default: &str) -> Vec<SortableInfo> {
    let mut seen: BTreeMap<String, FieldType> = BTreeMap::new();
    for table in tables.values() {
        for field in table.fields.iter().filter(|f| f.sortable) {
            seen.entry(field.name.clone()).or_insert(field.kind);
        }
    }
    seen.into_iter()
        .map(|(field, kind)| SortableInfo {
            default: (field == default).then_some(true),
            field,
            kind,
        })
        .collect()
}

use FieldType::{Boolean, Number, Tags, Text};

fn finding_table() -> TableInfo {
    TableInfo {
        fields: columns(&[
            ("rule", Text, "Stable activity rule"),
            ("version", Number, "Rule version"),
            ("tier", Text, "Tier after context"),
            ("base_tier", Text, "The rule's own tier"),
            ("category", Text, "ATT&CK-style category"),
            ("techniques", Tags, "Technique and detection ids"),
            ("count", Number, "Occurrences folded into the row"),
            ("flags", Tags, "Row flags"),
            ("hidden", Boolean, "Hidden as housekeeping"),
            ("confidence", Text, "high or limited"),
            ("summary", Text, "Matching facts"),
            ("object", Text, "What repeats are folded by"),
            ("success", Boolean, "Observed non-negative exit"),
            ("first_guest_ns", Number, "First occurrence, guest time"),
            ("last_guest_ns", Number, "Last occurrence, guest time"),
            ("pid", Number, "Guest thread group"),
            ("exe", Text, "Process executable"),
        ]),
    }
}

fn indicator_table() -> TableInfo {
    TableInfo {
        fields: columns(&[
            ("kind", Text, "endpoint, domain, url, tls or file"),
            ("value", Text, "The raw indicator"),
            ("match", Text, "matched, known_fp, no_match or not_checked"),
            ("dataset", Text, "Dataset that answered"),
            ("family", Text, "Family of the record"),
            ("confidence", Number, "Record confidence"),
            ("sources", Tags, "pcap, syscall, disk or static"),
            ("process", Text, "The process that made a matching call"),
            ("first_us", Number, "First seen, capture clock"),
            ("count", Number, "Occurrences"),
        ]),
    }
}

fn operation_file_table() -> TableInfo {
    TableInfo {
        fields: columns(&[
            ("path", Text, "File path"),
            ("operation", Text, "The call as the tables name it"),
            ("via", Text, "syscall, io_uring or AIO"),
            ("success", Boolean, "The call succeeded"),
            ("access", Text, "Access mode"),
            ("read_size", Number, "Bytes read"),
            ("written_size", Number, "Bytes written"),
            ("count", Number, "Calls folded into the row"),
            ("interpreter", Text, "Interpreter of a script"),
            ("content", Text, "Captured first octets, as text"),
            ("pid", Number, "Guest thread group"),
            ("exe", Text, "Process executable"),
            ("guest_ns", Number, "Guest time"),
        ]),
    }
}

fn changed_file_table() -> TableInfo {
    TableInfo {
        fields: columns(&[
            ("path", Text, "File path"),
            ("names", Tags, "Every name seen"),
            ("created", Boolean, "Created during the run"),
            ("deleted", Boolean, "Deleted during the run"),
            ("original_size", Number, "Size before"),
            ("final_size", Number, "Size after"),
            ("diff_count", Number, "Changed ranges"),
            ("complete", Boolean, "Fully reconstructed"),
            (
                "reconstruction",
                Text,
                "complete, incomplete or not reconstructed",
            ),
            ("bytes_written", Number, "Bytes written"),
            (
                "bytes_not_captured",
                Number,
                "Written bytes the recording lacks",
            ),
            ("earlier", Text, "State of the earlier-bytes copy"),
            ("first_guest_ns", Number, "First change, guest time"),
            ("last_guest_ns", Number, "Last change, guest time"),
        ]),
    }
}

fn network_tables() -> BTreeMap<String, TableInfo> {
    let mut tables = BTreeMap::new();
    let mut add = |tab: &str, fields: &[(&str, FieldType, &str)]| {
        tables.insert(
            tab.to_owned(),
            TableInfo {
                fields: columns(fields),
            },
        );
    };
    add(
        "endpoints",
        &[
            ("endpoint", Text, "Address and port"),
            ("ip", Text, "IP address"),
            ("port", Number, "Port"),
            ("protocol", Text, "tcp or udp"),
            ("frames", Number, "Frames"),
            ("bytes", Number, "Bytes"),
            ("country", Text, "Country"),
            ("organization", Text, "Organization"),
            ("first_us", Number, "First seen"),
            ("last_us", Number, "Last seen"),
        ],
    );
    add(
        "domains",
        &[
            ("hostname", Text, "Name"),
            ("addresses", Tags, "Addresses"),
            ("count", Number, "Occurrences"),
            ("sources", Tags, "DNS, HTTP or TLS"),
            ("rcodes", Tags, "DNS response codes"),
            ("first_us", Number, "First seen"),
            ("last_us", Number, "Last seen"),
        ],
    );
    add(
        "dns",
        &[
            ("hostname", Text, "Name"),
            ("rcodes", Tags, "DNS response codes"),
            ("addresses", Tags, "Addresses"),
            ("count", Number, "Occurrences"),
            ("first_us", Number, "First seen"),
        ],
    );
    add(
        "urls",
        &[
            ("url", Text, "Request URL"),
            ("method", Text, "HTTP method"),
            ("host", Text, "Host"),
            ("uri", Text, "Request target"),
            ("status", Number, "Response status"),
            ("count", Number, "Requests"),
            ("first_us", Number, "First seen"),
        ],
    );
    add(
        "tls",
        &[
            ("time_us", Number, "Time"),
            ("endpoint", Text, "Server"),
            ("sni", Text, "Server name"),
            ("alpn", Tags, "Protocols offered"),
            ("version", Text, "TLS version"),
            ("ja3", Text, "JA3"),
            ("ja4", Text, "JA4"),
            ("ja3s", Text, "JA3S"),
            ("cert_sha1", Text, "Certificate SHA-1"),
            ("sessions", Number, "Sessions"),
        ],
    );
    add(
        "http",
        &[
            ("time_us", Number, "Time"),
            ("endpoints", Text, "Connection"),
            ("method", Text, "HTTP method"),
            ("host", Text, "Host"),
            ("uri", Text, "Request target"),
            ("version", Text, "HTTP version"),
            ("status", Number, "Response status"),
            ("complete", Boolean, "Request and response both seen"),
            (
                "attribution",
                Text,
                "Process, when the socket identity proves it",
            ),
        ],
    );
    tables
}

fn file_tables() -> BTreeMap<String, TableInfo> {
    let mut tables = BTreeMap::new();
    for tab in [
        "opened",
        "created",
        "read",
        "written",
        "deleted",
        "renamed",
        "executed",
        "attributes",
        "probed",
        "other",
    ] {
        tables.insert(tab.to_owned(), operation_file_table());
    }
    tables.insert("changed".to_owned(), changed_file_table());
    tables
}

#[allow(clippy::too_many_arguments)]
fn op(
    name: &str,
    class: OpClass,
    scope: OpScope,
    subject: OpSubject,
    filters: Vec<FilterInfo>,
    default_order: &str,
    max_limit: u32,
    addressing: &'static [&'static str],
) -> OpDef {
    OpDef {
        info: QueryOpInfo {
            op: name.into(),
            class,
            scope,
            subject,
            filters,
            sortable: Vec::new(),
            default_order: default_order.into(),
            max_limit,
            tables: None,
        },
        addressing,
    }
}

/// Every operation of 5.12.3 in the table's order.
pub fn definitions() -> Vec<OpDef> {
    use OpClass::{C, T};
    use OpScope::{ArtifactsSensitive as S, Read as N};
    use OpSubject::{JobIdOrRunKey, RunKey, Sha256};
    let limits = QueryLimits::default();
    let (row, analysis, packets, terminal) = (
        limits.row.max,
        limits.row.analysis,
        limits.row.packets,
        limits.row.terminal,
    );
    let mut defs = vec![
        op(
            "recording.run.list",
            C,
            N,
            RunKey,
            vec![
                filter("vm_id", FilterType::String),
                filter("sample_sha256", FilterType::String),
                filter("job_id", FilterType::String),
                enum_filter(
                    "state",
                    &[
                        RunStateName::Unknown,
                        RunStateName::Running,
                        RunStateName::StopRequested,
                        RunStateName::Finished,
                        RunStateName::Stopped,
                        RunStateName::TerminalClosed,
                        RunStateName::Finalized,
                        RunStateName::FailedToStart,
                        RunStateName::LaunchUnconfirmed,
                        RunStateName::Interrupted,
                    ],
                    false,
                ),
                filter("since_ms", FilterType::TimeMs),
            ],
            "started_ms descending, then run_key",
            row,
            &[],
        ),
        op(
            "recording.run.get",
            C,
            N,
            RunKey,
            vec![],
            "",
            0,
            &["run_key"],
        ),
        op(
            "recording.summary",
            T,
            N,
            RunKey,
            vec![],
            "",
            0,
            &["run_key"],
        ),
        op(
            "recording.trace.page",
            C,
            N,
            RunKey,
            vec![
                filter("pid", FilterType::Integer),
                filter("q", FilterType::Query),
                enum_filter("hide_groups", &SyscallGroupName::ALL, false),
            ],
            "raw-file byte offset (event order)",
            row,
            &[],
        ),
        op(
            "recording.trace.get",
            C,
            N,
            RunKey,
            vec![],
            "",
            0,
            &["run_key", "ref"],
        ),
        op(
            "recording.captured.read",
            C,
            S,
            RunKey,
            vec![],
            "",
            0,
            &["run_key", "field", "offset", "len"],
        ),
        op(
            "recording.process.tree",
            C,
            N,
            RunKey,
            vec![filter("root_pid", FilterType::Integer)],
            "pid ascending",
            row,
            &[],
        ),
        op(
            "recording.findings.list",
            T,
            N,
            RunKey,
            vec![
                enum_filter(
                    "tier",
                    &[
                        crate::api::assessment::Tier::High,
                        crate::api::assessment::Tier::Medium,
                        crate::api::assessment::Tier::Low,
                        crate::api::assessment::Tier::Info,
                    ],
                    false,
                ),
                enum_filter(
                    "category",
                    &[
                        FindingCategory::Execution,
                        FindingCategory::Persistence,
                        FindingCategory::Privilege,
                        FindingCategory::Evasion,
                        FindingCategory::Credential,
                        FindingCategory::Discovery,
                        FindingCategory::Injection,
                        FindingCategory::C2,
                        FindingCategory::Rootkit,
                        FindingCategory::Impact,
                        FindingCategory::Collection,
                        FindingCategory::Lateral,
                        FindingCategory::Exfiltration,
                    ],
                    false,
                ),
                filter("rule", FilterType::String),
                filter("pid", FilterType::Integer),
                filter("q", FilterType::Query),
            ],
            "first_guest_ns ascending",
            row,
            &[],
        ),
        op(
            "recording.findings.get",
            T,
            N,
            RunKey,
            vec![],
            "",
            0,
            &["run_key", "finding_id"],
        ),
        op(
            "recording.indicators.list",
            T,
            N,
            RunKey,
            vec![
                enum_filter(
                    "kind",
                    &[
                        IndicatorKind::Endpoint,
                        IndicatorKind::Domain,
                        IndicatorKind::Url,
                        IndicatorKind::Tls,
                        IndicatorKind::File,
                    ],
                    false,
                ),
                filter("matched", FilterType::Boolean),
                filter("q", FilterType::Query),
                filter("defang", FilterType::Boolean),
            ],
            "matched first, then kind, then value",
            row,
            &[],
        ),
        op(
            "recording.files.list",
            T,
            N,
            RunKey,
            vec![
                enum_filter(
                    "tab",
                    &[
                        FileTab::Opened,
                        FileTab::Created,
                        FileTab::Read,
                        FileTab::Written,
                        FileTab::Deleted,
                        FileTab::Renamed,
                        FileTab::Executed,
                        FileTab::Attributes,
                        FileTab::Probed,
                        FileTab::Other,
                        FileTab::Changed,
                    ],
                    true,
                ),
                filter("q", FilterType::Query),
            ],
            "guest_ns ascending (operation tabs), path (changed)",
            row,
            &[],
        ),
        op(
            "recording.files.versions",
            T,
            N,
            RunKey,
            vec![],
            "",
            0,
            &["run_key", "file_id"],
        ),
        op(
            "recording.files.content",
            T,
            S,
            RunKey,
            vec![],
            "",
            0,
            &["run_key", "version_id", "range"],
        ),
        op(
            "recording.network.summary",
            T,
            N,
            RunKey,
            vec![],
            "",
            0,
            &["run_key"],
        ),
        op(
            "recording.network.list",
            T,
            N,
            RunKey,
            vec![
                enum_filter(
                    "tab",
                    &[
                        NetworkTab::Endpoints,
                        NetworkTab::Domains,
                        NetworkTab::Urls,
                        NetworkTab::Tls,
                        NetworkTab::Dns,
                        NetworkTab::Http,
                    ],
                    true,
                ),
                filter("q", FilterType::Query),
            ],
            "first_us ascending (bytes descending for endpoints)",
            row,
            &[],
        ),
        op(
            "recording.network.captures",
            C,
            N,
            RunKey,
            vec![],
            "segment ascending",
            0,
            &["run_key"],
        ),
        op(
            "recording.network.packets",
            C,
            N,
            RunKey,
            vec![filter("filter", FilterType::DisplayFilter)],
            "frame number ascending",
            packets,
            &["capture_id"],
        ),
        op(
            "recording.network.packet",
            C,
            S,
            RunKey,
            vec![],
            "",
            0,
            &["run_key", "capture_id", "n"],
        ),
        op(
            "recording.timeline",
            T,
            N,
            RunKey,
            vec![
                filter("from_ms", FilterType::TimeMs),
                filter("to_ms", FilterType::TimeMs),
                enum_filter(
                    "kinds",
                    &[
                        TimelineKind::ProcessStart,
                        TimelineKind::ProcessExit,
                        TimelineKind::Finding,
                        TimelineKind::File,
                        TimelineKind::Network,
                        TimelineKind::Detection,
                    ],
                    false,
                ),
            ],
            "ts_ms ascending, then kind, then source id",
            row,
            &[],
        ),
        op(
            "recording.cores.list",
            C,
            N,
            RunKey,
            vec![],
            "core_id ascending",
            0,
            &["run_key"],
        ),
        op(
            "recording.analysis.list",
            C,
            N,
            JobIdOrRunKey,
            vec![],
            "",
            0,
            &["run_key", "job_id"],
        ),
        op(
            "recording.analysis.section",
            C,
            N,
            JobIdOrRunKey,
            vec![
                enum_filter(
                    "kind",
                    &[
                        AnalysisKindName::Metadata,
                        AnalysisKindName::Structures,
                        AnalysisKindName::Strings,
                        AnalysisKindName::Regex,
                        AnalysisKindName::Entropy,
                        AnalysisKindName::Hardening,
                        AnalysisKindName::Rules,
                        AnalysisKindName::Identification,
                        AnalysisKindName::Capabilities,
                        AnalysisKindName::Disassembly,
                        AnalysisKindName::Decompilation,
                        AnalysisKindName::Embedded,
                        AnalysisKindName::Floss,
                        AnalysisKindName::Unpacking,
                    ],
                    true,
                ),
                filter("q", FilterType::Query),
            ],
            "the listing's order",
            analysis,
            &["run_key", "job_id"],
        ),
        op(
            "recording.analysis.ghidra",
            C,
            N,
            JobIdOrRunKey,
            vec![filter("q", FilterType::Query)],
            "address order",
            analysis,
            &["run_key", "job_id"],
        ),
        op(
            "recording.custody.list",
            C,
            N,
            Sha256,
            vec![],
            "seq ascending",
            row,
            &["run_key", "sha256"],
        ),
        op(
            "recording.terminal.replay",
            C,
            N,
            RunKey,
            vec![],
            "journal order",
            terminal,
            &[],
        ),
        op(
            "recording.artifact.list",
            C,
            N,
            RunKey,
            vec![],
            "name ascending",
            0,
            &["run_key"],
        ),
        op(
            "recording.artifact.get",
            C,
            S,
            RunKey,
            vec![],
            "",
            0,
            &["run_key", "artifact_id", "range"],
        ),
    ];
    // Tables, and the sort each table allows. The Triage lists are sortable by
    // any published column; every other list has a fixed order.
    for def in &mut defs {
        match def.info.op.as_str() {
            "recording.findings.list" => {
                let tables = BTreeMap::from([("findings".to_owned(), finding_table())]);
                def.info.sortable = sortable_of(&tables, "first_guest_ns");
                def.info.tables = Some(tables);
            }
            "recording.indicators.list" => {
                let tables = BTreeMap::from([("indicators".to_owned(), indicator_table())]);
                def.info.sortable = sortable_of(&tables, "value");
                def.info.tables = Some(tables);
            }
            "recording.files.list" => {
                let tables = file_tables();
                def.info.sortable = sortable_of(&tables, "guest_ns");
                def.info.tables = Some(tables);
            }
            "recording.network.list" => {
                let tables = network_tables();
                def.info.sortable = sortable_of(&tables, "first_us");
                def.info.tables = Some(tables);
            }
            // The engine sorts a listing by Strings column or `StructureField`.
            "recording.analysis.section" => {
                def.info.sortable = [
                    "name",
                    "value",
                    "address",
                    "offset",
                    "virtual_size",
                    "file_size",
                    "flags",
                    "library",
                    "ordinal",
                    "kind",
                    "scope",
                    "defined",
                    "size",
                    "length",
                    "text",
                    "encoding",
                ]
                .iter()
                .map(|field| SortableInfo {
                    field: (*field).into(),
                    kind: if matches!(
                        *field,
                        "name" | "value" | "text" | "encoding" | "library" | "kind" | "scope"
                    ) {
                        Text
                    } else {
                        Number
                    },
                    default: None,
                })
                .collect();
            }
            _ => {}
        }
    }
    defs
}

/// `capabilities.queries` for this build: every operation, and the limits.
pub fn catalogue(limits: QueryLimits) -> QueryCatalogue {
    QueryCatalogue {
        ops: definitions().into_iter().map(|d| d.info).collect(),
        limits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::request::RecordingRead;
    use std::collections::BTreeSet;

    const PAGING: [&str; 2] = ["limit", "cursor"];

    fn properties(op: &str) -> BTreeSet<String> {
        let schema =
            RecordingRead::params_schema(op).unwrap_or_else(|| panic!("{op}: no request type"));
        schema["properties"]
            .as_object()
            .map(|p| p.keys().cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn the_table_and_the_request_types_name_the_same_operations() {
        let table: Vec<_> = definitions().into_iter().map(|d| d.info.op).collect();
        assert_eq!(table, RecordingRead::OPS);
        let unique: BTreeSet<_> = table.iter().collect();
        assert_eq!(unique.len(), table.len());
    }

    /// An operation must not take a filter or a sort the catalogue leaves out.
    #[test]
    fn every_request_member_is_a_listed_filter_or_an_addressing_member() {
        for def in definitions() {
            let op = def.info.op.as_str();
            let props = properties(op);
            let implied: &[&str] = if op == "recording.run.list" {
                &[]
            } else {
                match def.info.subject {
                    OpSubject::RunKey => &["run_key"],
                    OpSubject::JobIdOrRunKey => &["run_key", "job_id"],
                    OpSubject::Sha256 => &["run_key", "sha256"],
                }
            };
            let mut allowed: BTreeSet<String> =
                def.info.filters.iter().map(|f| f.name.clone()).collect();
            allowed.extend(def.addressing.iter().map(|s| (*s).to_owned()));
            allowed.extend(implied.iter().map(|s| (*s).to_owned()));
            allowed.extend(PAGING.iter().map(|s| (*s).to_owned()));
            allowed.insert("sort".into());
            for prop in &props {
                assert!(
                    allowed.contains(prop),
                    "{op}: request member {prop} is not in the catalogue"
                );
            }
            for filter in &def.info.filters {
                assert!(
                    props.contains(&filter.name),
                    "{op}: catalogue filter {} is not a request member",
                    filter.name
                );
            }
            for addressed in def.addressing {
                assert!(
                    props.contains(*addressed),
                    "{op}: addressing member {addressed} is not a request member"
                );
            }
        }
    }

    #[test]
    fn sort_and_paging_agree_with_the_catalogue() {
        for def in definitions() {
            let op = def.info.op.as_str();
            let props = properties(op);
            assert_eq!(
                props.contains("sort"),
                !def.info.sortable.is_empty(),
                "{op}: a sortable list takes `sort`, a fixed-order list does not"
            );
            let paged = PAGING.iter().all(|p| props.contains(*p));
            let some_paging = PAGING.iter().any(|p| props.contains(*p));
            assert_eq!(paged, some_paging, "{op}: limit and cursor go together");
            if paged {
                assert!(
                    def.info.max_limit > 0,
                    "{op}: a paged list names its maximum"
                );
            } else {
                assert_eq!(def.info.max_limit, 0, "{op}: not paged, no maximum");
            }
            assert!(
                def.info.default_order.is_empty() || def.info.max_limit > 0 || !paged,
                "{op}"
            );
            if let Some(tables) = &def.info.tables {
                for sortable in &def.info.sortable {
                    assert!(
                        tables.values().any(|t| t
                            .fields
                            .iter()
                            .any(|f| f.name == sortable.field && f.sortable)),
                        "{op}: sortable {} is in no table",
                        sortable.field
                    );
                }
            }
        }
    }

    #[test]
    fn row_limits_follow_the_design() {
        let by_op = |name: &str| {
            definitions()
                .into_iter()
                .find(|d| d.info.op == name)
                .unwrap()
                .info
        };
        assert_eq!(by_op("recording.run.list").max_limit, 500);
        assert_eq!(by_op("recording.network.packets").max_limit, 500);
        assert_eq!(by_op("recording.analysis.section").max_limit, 1024);
        assert_eq!(by_op("recording.analysis.ghidra").max_limit, 1024);
        assert_eq!(by_op("recording.terminal.replay").max_limit, 256);
        assert_eq!(
            by_op("recording.trace.page").sortable,
            vec![],
            "the trace is in event order"
        );
    }

    #[test]
    fn classes_scopes_and_subjects_follow_the_design() {
        let by_op = |name: &str| {
            definitions()
                .into_iter()
                .find(|d| d.info.op == name)
                .unwrap()
                .info
        };
        let triage = [
            "recording.summary",
            "recording.findings.list",
            "recording.findings.get",
            "recording.indicators.list",
            "recording.files.list",
            "recording.files.versions",
            "recording.files.content",
            "recording.network.summary",
            "recording.network.list",
            "recording.timeline",
        ];
        let sensitive = [
            "recording.captured.read",
            "recording.files.content",
            "recording.network.packet",
        ];
        for def in definitions() {
            let op = def.info.op.as_str();
            assert_eq!(def.info.class == OpClass::T, triage.contains(&op), "{op}");
            if sensitive.contains(&op) {
                assert_eq!(def.info.scope, OpScope::ArtifactsSensitive, "{op}");
            }
        }
        assert_eq!(
            by_op("recording.analysis.list").subject,
            OpSubject::JobIdOrRunKey
        );
        assert_eq!(by_op("recording.custody.list").subject, OpSubject::Sha256);
        assert_eq!(by_op("recording.run.get").subject, OpSubject::RunKey);
    }

    #[test]
    fn the_catalogue_serializes_with_the_documented_members() {
        let catalogue = catalogue(QueryLimits::default());
        let value = serde_json::to_value(&catalogue).unwrap();
        assert_eq!(value["limits"]["row"]["default"], 100);
        assert_eq!(value["limits"]["page_bytes"], 1_048_576);
        assert_eq!(value["limits"]["byte_read"]["captured"], 65_536);
        let ops = value["ops"].as_array().unwrap();
        assert_eq!(ops.len(), RecordingRead::OPS.len());
        let files = ops
            .iter()
            .find(|o| o["op"] == "recording.files.list")
            .unwrap();
        assert_eq!(files["class"], "T");
        assert_eq!(files["scope"], "read");
        assert_eq!(files["subject"], "run_key");
        assert!(
            files["tables"]["changed"]["fields"]
                .as_array()
                .unwrap()
                .len()
                > 5
        );
        assert_eq!(files["filters"][0]["name"], "tab");
        assert_eq!(files["filters"][0]["required"], true);
        let back: QueryCatalogue = serde_json::from_value(value).unwrap();
        assert_eq!(back, catalogue);
    }
}
