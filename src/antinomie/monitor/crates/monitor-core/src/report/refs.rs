// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The links between a report's entries: every process, file, endpoint,
//! domain, finding, indicator, technique and detection gets an anchor id
//! ([`super::anchor`]), every mention of one names it in a `*_ref` field, and
//! an entry lists the findings that are about it (`finding_refs`). [`link`]
//! derives all of it from the typed values the builder put in each row
//! ([`RowData`]), so the JSON and every document format link the same way;
//! [`problems`] checks that each id is unique and each ref resolves.
use super::anchor;
use super::{Report, Table};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn none(text: &str) -> bool {
    text.is_empty()
}

/// The typed values and links of one table row.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RowData {
    /// The row's anchor id, when it is the entry of something.
    #[serde(skip_serializing_if = "none")]
    pub id: String,
    /// More ids this row answers to: the first finding of a rule is also
    /// `rule-<rule id>`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The stable task identity that tells two processes with one pid apart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_cookie: Option<u64>,
    /// Depth in the process tree (0 for a root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    /// When, ms since the epoch (from the guest clock for guest events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_ms: Option<u64>,
    /// When, ms since the run's first call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// A file row's guest path.
    #[serde(skip_serializing_if = "none")]
    pub path: String,
    /// A network row's `address:port`.
    #[serde(skip_serializing_if = "none")]
    pub endpoint: String,
    /// A network row's domain name (a Domains row, a URL's host, a TLS name).
    #[serde(skip_serializing_if = "none")]
    pub domain: String,
    /// The addresses a domain resolved to.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// A finding's rule id and tier.
    #[serde(skip_serializing_if = "none")]
    pub rule: String,
    #[serde(skip_serializing_if = "none")]
    pub tier: String,
    /// A finding's object as the rule names it (a path, an address).
    #[serde(skip_serializing_if = "none")]
    pub target: String,
    /// ATT&CK technique ids.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<String>,
    #[serde(skip_serializing_if = "none")]
    pub process_ref: String,
    #[serde(skip_serializing_if = "none")]
    pub parent_ref: String,
    /// The entry of the row's object: the file, endpoint or domain row.
    #[serde(skip_serializing_if = "none")]
    pub target_ref: String,
    #[serde(skip_serializing_if = "none")]
    pub domain_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoint_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attack_refs: Vec<String>,
    /// The findings about this entry (a process's, a file's, an address's).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub finding_refs: Vec<String>,
    /// A process row: the files it created or changed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub file_refs: Vec<String>,
}

/// One row of the Summary's Key findings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyFinding {
    /// `high`, `medium` or `low`.
    pub tier: String,
    pub rule: String,
    /// The behaviour in words: "Waiting for chosen packets: BPF on raw socket".
    pub title: String,
    /// What the rule saw it on: a path, an address, a socket option.
    pub target: String,
    /// The process as the tables name it.
    pub process: String,
    pub pid: Option<u32>,
    pub cookie: Option<u64>,
    pub count: u64,
    /// First time, ms since the epoch, and ms since the run's first call.
    pub first_ms: Option<u64>,
    pub relative_ms: Option<u64>,
    pub attack: Vec<String>,
    /// Why it matters, as the rule describes it (cut at about 140 characters).
    pub why: String,
    /// Its row in Suspicious activity, numbered from 1.
    pub finding: Option<usize>,
    pub finding_ref: String,
    pub process_ref: String,
    pub target_ref: String,
    pub attack_refs: Vec<String>,
}

/// The Files tabs in the order the document shows them: what was written or
/// changed first, what was only looked at last. A file's entry is its first
/// row in this order.
pub const FILE_TAB_ORDER: [&str; 11] = [
    "Changed files",
    "Executed files",
    "Created files",
    "Deleted files",
    "Renamed / moved",
    "Written / resized",
    "Attributes",
    "Opened files",
    "Read files",
    "Metadata probed",
    "Other",
];

/// Where a Files tab goes in [`FILE_TAB_ORDER`]; unknown names go last.
pub fn file_tab_rank(name: &str) -> usize {
    FILE_TAB_ORDER
        .iter()
        .position(|tab| *tab == name)
        .unwrap_or(FILE_TAB_ORDER.len())
}

/// The tabs whose rows are a file the run made or changed.
const WRITING_TABS: [&str; 4] = [
    "Changed files",
    "Created files",
    "Written / resized",
    "Renamed / moved",
];

/// The entries of a report by what they are about.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    processes: BTreeMap<(u32, u64), String>,
    /// The first process seen with a pid, for a mention with no cookie.
    by_pid: BTreeMap<u32, String>,
    pub files: BTreeMap<String, String>,
    pub endpoints: BTreeMap<String, String>,
    pub domains: BTreeMap<String, String>,
    /// Rule id → the anchor of its first finding.
    pub rules: BTreeMap<String, String>,
    /// Engine and rule (and `Engine: title`) → the detection's anchor.
    pub detections: BTreeMap<String, String>,
    pub techniques: BTreeMap<String, String>,
    /// Every id of the report.
    pub ids: BTreeSet<String>,
    /// Display text of a process entry, for a cell that lists it.
    pub labels: BTreeMap<String, String>,
}

impl Registry {
    pub fn process(&self, pid: Option<u32>, cookie: Option<u64>) -> String {
        let Some(pid) = pid else {
            return String::new();
        };
        cookie
            .and_then(|cookie| self.processes.get(&(pid, cookie)))
            .or_else(|| self.by_pid.get(&pid))
            .cloned()
            .unwrap_or_default()
    }

    pub fn file(&self, path: &str) -> String {
        self.files.get(path).cloned().unwrap_or_default()
    }

    pub fn endpoint(&self, text: &str) -> String {
        self.endpoints.get(text).cloned().unwrap_or_default()
    }

    pub fn domain(&self, name: &str) -> String {
        self.domains
            .get(&name.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }

    /// The entry an object text names: a file by path, an endpoint, a domain.
    pub fn target(&self, text: &str) -> String {
        let text = text.trim();
        if text.is_empty() {
            return String::new();
        }
        if text.starts_with('/') {
            return self.file(text);
        }
        let endpoint = self.endpoint(text);
        if !endpoint.is_empty() {
            return endpoint;
        }
        self.domain(text)
    }

    /// The entry a rule of the ATT&CK table names: a behaviour rule's first
    /// finding, or a detection (`Sigma: <title>`, `YARA: <rule>`).
    pub fn rule(&self, text: &str) -> String {
        self.rules
            .get(text)
            .or_else(|| self.detections.get(text))
            .cloned()
            .unwrap_or_default()
    }

    /// Endpoint entries at `address` (any port).
    pub fn endpoints_at(&self, address: &str) -> Vec<String> {
        self.endpoints
            .iter()
            .filter(|(text, _)| {
                text.rsplit_once(':')
                    .map(|(host, _)| host.trim_matches(['[', ']']))
                    == Some(address)
            })
            .map(|(_, id)| id.clone())
            .collect()
    }

    pub fn technique(&self, id: &str) -> String {
        self.techniques.get(id).cloned().unwrap_or_default()
    }
}

/// Every table of the report with its section name.
fn tables_mut(report: &mut Report) -> Vec<(String, &mut Table)> {
    let mut out: Vec<(String, &mut Table)> = Vec::new();
    if let Some(table) = report.processes.as_mut() {
        out.push(("processes".into(), table));
    }
    if let Some(table) = report.findings.as_mut() {
        out.push(("findings".into(), table));
    }
    if let Some(files) = report.files.as_mut() {
        for tab in &mut files.tabs {
            out.push((format!("files/{}", tab.name), &mut tab.table));
        }
    }
    if let Some(tabs) = report.network.as_mut() {
        for tab in tabs {
            out.push((format!("network/{}", tab.name), &mut tab.table));
        }
    }
    out
}

/// Set every anchor and link of `report` from its rows' typed values. Safe to
/// run again: it starts from no links.
pub fn link(report: &mut Report) {
    let mut reg = Registry::default();
    // Start clean.
    for (_, table) in tables_mut(report) {
        for data in &mut table.data {
            let keep = RowData {
                id: String::new(),
                anchors: Vec::new(),
                process_ref: String::new(),
                parent_ref: String::new(),
                target_ref: String::new(),
                domain_ref: String::new(),
                endpoint_refs: Vec::new(),
                attack_refs: Vec::new(),
                finding_refs: Vec::new(),
                file_refs: Vec::new(),
                ..data.clone()
            };
            *data = keep;
        }
    }
    // Processes: proc-<pid>, then proc-<pid>-2 for a second process of a pid.
    if let Some(table) = report.processes.as_mut() {
        let mut nth: BTreeMap<u32, usize> = BTreeMap::new();
        for (at, data) in table.data.iter_mut().enumerate() {
            let Some(pid) = data.pid else { continue };
            let key = (pid, data.cookie.unwrap_or(0));
            if reg.processes.contains_key(&key) {
                continue;
            }
            let n = nth.entry(pid).or_insert(0);
            *n += 1;
            let id = anchor::process(pid, *n);
            reg.processes.insert(key, id.clone());
            reg.by_pid.entry(pid).or_insert_with(|| id.clone());
            if let Some(name) = table.rows.get(at).and_then(|row| row.first()) {
                reg.labels
                    .insert(id.clone(), name.trim_start_matches(['-', ' ']).to_owned());
            }
            data.id = id;
        }
    }
    // Files: the first row of a path, in the document's order, is its entry.
    if let Some(records) = report.file_activity.as_mut() {
        for record in records.iter_mut() {
            record.id.clear();
            record.process_ref.clear();
            record.finding_refs.clear();
            if !reg.files.contains_key(&record.path) {
                let id = anchor::file(&record.path);
                reg.files.insert(record.path.clone(), id.clone());
                record.id = id;
            }
        }
    }
    if let Some(files) = report.files.as_mut() {
        let mut order: Vec<usize> = (0..files.tabs.len()).collect();
        order.sort_by_key(|&at| file_tab_rank(&files.tabs[at].name));
        for at in order {
            for data in &mut files.tabs[at].table.data {
                if data.path.is_empty() || reg.files.contains_key(&data.path) {
                    continue;
                }
                let id = anchor::file(&data.path);
                reg.files.insert(data.path.clone(), id.clone());
                data.id = id;
            }
        }
    }
    // Network: endpoints and domains.
    if let Some(tabs) = report.network.as_mut() {
        for tab in tabs.iter_mut() {
            for data in &mut tab.table.data {
                match tab.name.as_str() {
                    "Endpoints" if !data.endpoint.is_empty() => {
                        if !reg.endpoints.contains_key(&data.endpoint) {
                            let id = anchor::endpoint(&data.endpoint);
                            reg.endpoints.insert(data.endpoint.clone(), id.clone());
                            data.id = id;
                        }
                    }
                    "Domains" if !data.domain.is_empty() => {
                        let key = data.domain.to_ascii_lowercase();
                        if let std::collections::btree_map::Entry::Vacant(slot) =
                            reg.domains.entry(key)
                        {
                            let id = anchor::domain(slot.key());
                            slot.insert(id.clone());
                            data.id = id;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // Detections.
    if let Some(detections) = report.detections.as_mut() {
        for hit in detections.iter_mut() {
            hit.attack_refs.clear();
            let id = anchor::detection(&hit.engine, &hit.rule_id);
            let title = super::layout::plain_rule(&hit.title).to_owned();
            let rule = super::layout::plain_rule(&hit.rule_id).to_owned();
            if reg.ids.insert(id.clone()) {
                for key in [
                    format!("{}: {title}", hit.engine),
                    format!("{}: {rule}", hit.engine),
                    rule,
                ] {
                    reg.detections.entry(key).or_insert_with(|| id.clone());
                }
                hit.id = id;
            } else {
                hit.id.clear();
            }
        }
    }
    // Techniques.
    if let Some(attack) = report.attack.as_mut() {
        for technique in attack.iter_mut() {
            let id = anchor::attack(&technique.id);
            if reg.techniques.contains_key(&technique.id) {
                continue;
            }
            reg.techniques.insert(technique.id.clone(), id);
        }
    }
    // Findings: finding-<n>; the first of a rule is also rule-<id>.
    if let Some(table) = report.findings.as_mut() {
        for (at, data) in table.data.iter_mut().enumerate() {
            data.id = anchor::finding(at + 1);
            if !data.rule.is_empty() && !reg.rules.contains_key(&data.rule) {
                let id = anchor::rule(&data.rule);
                reg.rules.insert(data.rule.clone(), id.clone());
                data.anchors.push(id);
            }
        }
    }
    // Every id, for the pruning below.
    reg.ids.extend(reg.processes.values().cloned());
    reg.ids.extend(reg.files.values().cloned());
    reg.ids.extend(reg.endpoints.values().cloned());
    reg.ids.extend(reg.domains.values().cloned());
    reg.ids.extend(reg.rules.values().cloned());
    reg.ids.extend(reg.techniques.values().cloned());
    if let Some(table) = &report.findings {
        reg.ids.extend(table.data.iter().map(|d| d.id.clone()));
    }

    // Forward links of every row.
    let reg_ref = &reg;
    for (name, table) in tables_mut(report) {
        for data in &mut table.data {
            data.process_ref = reg_ref.process(data.pid, data.cookie);
            if name == "processes" {
                data.parent_ref = reg_ref.process(data.parent_pid, data.parent_cookie);
                if data.parent_ref == data.id {
                    data.parent_ref.clear();
                }
                data.process_ref.clear();
            }
            if !data.path.is_empty() {
                data.target_ref = reg_ref.file(&data.path);
            } else if !data.target.is_empty() {
                data.target_ref = reg_ref.target(&data.target);
            }
            if !data.endpoint.is_empty() && !name.ends_with("/Endpoints") {
                data.endpoint_refs = vec![reg_ref.endpoint(&data.endpoint)];
            }
            if !data.domain.is_empty() && !name.ends_with("/Domains") {
                data.domain_ref = reg_ref.domain(&data.domain);
            }
            for address in &data.addresses {
                data.endpoint_refs.extend(reg_ref.endpoints_at(address));
            }
            data.attack_refs = data.attack.iter().map(|t| reg_ref.technique(t)).collect();
            data.endpoint_refs.retain(|id| !id.is_empty());
            data.endpoint_refs.dedup();
            data.attack_refs.retain(|id| !id.is_empty());
        }
    }
    if let Some(records) = report.file_activity.as_mut() {
        // The process that wrote it: the Changed files row of the same path.
        let writers: BTreeMap<String, String> = report
            .files
            .iter()
            .flat_map(|files| &files.tabs)
            .filter(|tab| WRITING_TABS.contains(&tab.name.as_str()))
            .flat_map(|tab| &tab.table.data)
            .filter(|data| !data.process_ref.is_empty())
            .map(|data| (data.path.clone(), data.process_ref.clone()))
            .rev()
            .collect();
        for record in records.iter_mut() {
            record.process_ref = writers.get(&record.path).cloned().unwrap_or_default();
        }
    }
    if let Some(indicators) = report.indicators.as_mut() {
        for (at, indicator) in indicators.iter_mut().enumerate() {
            indicator.id = anchor::indicator(at + 1);
            indicator.finding_refs.clear();
            indicator.target_ref = match indicator.kind.as_str() {
                "endpoint" => reg_ref.endpoint(&indicator.value),
                "domain" => reg_ref.domain(&indicator.value),
                "file" if !indicator.path.is_empty() => reg_ref.file(&indicator.path),
                "file" => reg_ref.file(&indicator.value),
                "tls" => reg_ref.domain(&indicator.value),
                "url" => reg_ref.domain(
                    indicator
                        .value
                        .split("://")
                        .last()
                        .unwrap_or_default()
                        .split(['/', ':'])
                        .next()
                        .unwrap_or_default(),
                ),
                _ => String::new(),
            };
            indicator.process_refs = indicator
                .pids
                .iter()
                .map(|pid| reg_ref.process(Some(*pid), None))
                .filter(|id| !id.is_empty())
                .collect();
            indicator.process_refs.dedup();
        }
    }
    if let Some(attack) = report.attack.as_mut() {
        for technique in attack.iter_mut() {
            technique.rule_refs = technique.rules.iter().map(|r| reg_ref.rule(r)).collect();
        }
    }
    if let Some(detections) = report.detections.as_mut() {
        for hit in detections.iter_mut() {
            hit.attack_refs = hit
                .mitre
                .iter()
                .flat_map(|text| anchor::techniques_in(text))
                .map(|t| reg_ref.technique(&t))
                .filter(|id| !id.is_empty())
                .collect();
        }
    }
    let findings_rows: Vec<RowData> = report
        .findings
        .as_ref()
        .map(|t| t.data.clone())
        .unwrap_or_default();
    if let Some(summary) = report.summary.as_mut() {
        for key in &mut summary.key_findings {
            key.finding_ref = key
                .finding
                .and_then(|n| findings_rows.get(n.wrapping_sub(1)))
                .map(|data| data.id.clone())
                .unwrap_or_default();
            key.process_ref = reg_ref.process(key.pid, key.cookie);
            key.target_ref = reg_ref.target(&key.target);
            key.attack_refs = key
                .attack
                .iter()
                .map(|t| reg_ref.technique(t))
                .filter(|id| !id.is_empty())
                .collect();
        }
    }

    // Back-links: an entry lists the findings about it.
    let mut about: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for data in &findings_rows {
        let data_ref = &data;
        let process = reg_ref.process(data_ref.pid, data_ref.cookie);
        let target = if data.path.is_empty() {
            reg_ref.target(&data.target)
        } else {
            reg_ref.file(&data.path)
        };
        for entry in [process, target] {
            if !entry.is_empty() {
                let list = about.entry(entry).or_default();
                if !list.contains(&data.id) {
                    list.push(data.id.clone());
                }
            }
        }
    }
    // A process lists the files it made or changed.
    let mut written: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(files) = &report.files {
        for tab in files
            .tabs
            .iter()
            .filter(|tab| WRITING_TABS.contains(&tab.name.as_str()))
        {
            for data in &tab.table.data {
                if data.process_ref.is_empty() || data.target_ref.is_empty() {
                    continue;
                }
                let list = written.entry(data.process_ref.clone()).or_default();
                if !list.contains(&data.target_ref) {
                    list.push(data.target_ref.clone());
                }
            }
        }
    }
    for (name, table) in tables_mut(report) {
        if name == "findings" {
            continue;
        }
        for data in &mut table.data {
            if data.id.is_empty() {
                continue;
            }
            if let Some(list) = about.get(&data.id) {
                data.finding_refs.clone_from(list);
            }
            if name == "processes"
                && let Some(list) = written.get(&data.id)
            {
                data.file_refs.clone_from(list);
            }
        }
    }
    if let Some(records) = report.file_activity.as_mut() {
        for record in records.iter_mut() {
            if let Some(list) = about.get(&anchor::file(&record.path)) {
                record.finding_refs.clone_from(list);
            }
        }
    }
    if let Some(indicators) = report.indicators.as_mut() {
        for indicator in indicators.iter_mut() {
            if let Some(list) = about.get(&indicator.target_ref) {
                indicator.finding_refs.clone_from(list);
            }
        }
    }
    prune(report);
}

/// Every anchor id of `report`, with how many times each is used.
pub fn report_ids(report: &Report) -> BTreeMap<String, usize> {
    let mut ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut add = |id: &str| {
        if !id.is_empty() {
            *ids.entry(id.to_owned()).or_default() += 1;
        }
    };
    let tables: Vec<&Table> = report
        .processes
        .iter()
        .chain(&report.findings)
        .chain(
            report
                .files
                .iter()
                .flat_map(|f| f.tabs.iter().map(|t| &t.table)),
        )
        .chain(report.network.iter().flatten().map(|t| &t.table))
        .collect();
    for table in tables {
        for data in &table.data {
            add(&data.id);
            data.anchors.iter().for_each(|a| add(a));
        }
    }
    for record in report.file_activity.iter().flatten() {
        add(&record.id);
    }
    for indicator in report.indicators.iter().flatten() {
        add(&indicator.id);
    }
    for hit in report.detections.iter().flatten() {
        add(&hit.id);
    }
    // A technique's id is made from its ATT&CK id when the table is chosen.
    for technique in report.attack.iter().flatten() {
        add(&anchor::attack(&technique.id));
    }
    ids
}

/// Every link of `report`: (where it is, the id it names).
pub fn report_refs(report: &Report) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut add = |at: &str, ids: &[&String]| {
        for id in ids {
            if !id.is_empty() {
                out.push((at.to_owned(), (*id).clone()));
            }
        }
    };
    let tables: Vec<(&str, &Table)> = report
        .processes
        .iter()
        .map(|t| ("processes", t))
        .chain(report.findings.iter().map(|t| ("findings", t)))
        .chain(
            report
                .files
                .iter()
                .flat_map(|f| f.tabs.iter().map(|t| ("files", &t.table))),
        )
        .chain(
            report
                .network
                .iter()
                .flatten()
                .map(|t| ("network", &t.table)),
        )
        .collect();
    for (name, table) in tables {
        for data in &table.data {
            let mut ids = vec![
                &data.process_ref,
                &data.parent_ref,
                &data.target_ref,
                &data.domain_ref,
            ];
            ids.extend(&data.endpoint_refs);
            ids.extend(&data.attack_refs);
            ids.extend(&data.finding_refs);
            ids.extend(&data.file_refs);
            add(name, &ids);
        }
    }
    for record in report.file_activity.iter().flatten() {
        let mut ids = vec![&record.process_ref];
        ids.extend(&record.finding_refs);
        add("file_activity", &ids);
    }
    for i in report.indicators.iter().flatten() {
        let mut ids = vec![&i.target_ref];
        ids.extend(&i.process_refs);
        ids.extend(&i.finding_refs);
        add("indicators", &ids);
    }
    for t in report.attack.iter().flatten() {
        add("attack", &t.rule_refs.iter().collect::<Vec<_>>());
    }
    for hit in report.detections.iter().flatten() {
        add("detections", &hit.attack_refs.iter().collect::<Vec<_>>());
    }
    for key in report.summary.iter().flat_map(|s| &s.key_findings) {
        let mut ids = vec![&key.finding_ref, &key.process_ref, &key.target_ref];
        ids.extend(&key.attack_refs);
        add("key_findings", &ids);
    }
    out
}

/// Drop every link whose id the report does not hold (a section that was
/// not chosen, a row the index did not keep).
fn prune(report: &mut Report) {
    let ids: BTreeSet<String> = report_ids(report).into_keys().collect();
    let keep = |id: &mut String| {
        if !ids.contains(id) {
            id.clear();
        }
    };
    let keep_all = |list: &mut Vec<String>| list.retain(|id| ids.contains(id));
    for (_, table) in tables_mut(report) {
        for data in &mut table.data {
            keep(&mut data.process_ref);
            keep(&mut data.parent_ref);
            keep(&mut data.target_ref);
            keep(&mut data.domain_ref);
            keep_all(&mut data.endpoint_refs);
            keep_all(&mut data.attack_refs);
            keep_all(&mut data.finding_refs);
            keep_all(&mut data.file_refs);
        }
    }
    for record in report.file_activity.iter_mut().flatten() {
        keep(&mut record.process_ref);
        keep_all(&mut record.finding_refs);
    }
    for i in report.indicators.iter_mut().flatten() {
        keep(&mut i.target_ref);
        keep_all(&mut i.process_refs);
        keep_all(&mut i.finding_refs);
    }
    for t in report.attack.iter_mut().flatten() {
        // Parallel to `rules`: an unknown one is an empty string.
        t.rule_refs.iter_mut().for_each(keep);
        if t.rule_refs.iter().all(String::is_empty) {
            t.rule_refs.clear();
        }
    }
    for hit in report.detections.iter_mut().flatten() {
        keep_all(&mut hit.attack_refs);
    }
    for key in report.summary.iter_mut().flat_map(|s| &mut s.key_findings) {
        keep(&mut key.finding_ref);
        keep(&mut key.process_ref);
        keep(&mut key.target_ref);
        keep_all(&mut key.attack_refs);
    }
}

/// What is wrong with the report's links: an id used twice, a ref to an id
/// the report does not hold. Empty for a linked report.
pub fn problems(report: &Report) -> Vec<String> {
    let ids = report_ids(report);
    let mut out: Vec<String> = ids
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(id, n)| format!("id {id} is used {n} times"))
        .collect();
    for (at, id) in report_refs(report) {
        if !ids.contains_key(&id) {
            out.push(format!("{at}: {id} does not resolve"));
        }
    }
    out
}

/// The registry of a linked report: what the document links by text.
pub fn registry(report: &Report) -> Registry {
    let mut reg = Registry::default();
    if let Some(table) = &report.processes {
        for (at, data) in table.data.iter().enumerate() {
            if let (Some(pid), false) = (data.pid, data.id.is_empty()) {
                reg.processes
                    .insert((pid, data.cookie.unwrap_or(0)), data.id.clone());
                reg.by_pid.entry(pid).or_insert_with(|| data.id.clone());
                if let Some(name) = table.rows.get(at).and_then(|row| row.first()) {
                    reg.labels.insert(
                        data.id.clone(),
                        name.trim_start_matches(['-', ' ']).to_owned(),
                    );
                }
            }
        }
    }
    for record in report.file_activity.iter().flatten() {
        if !record.id.is_empty() {
            reg.files.insert(record.path.clone(), record.id.clone());
        }
    }
    for tab in report.files.iter().flat_map(|f| &f.tabs) {
        for data in &tab.table.data {
            if !data.id.is_empty() && !data.path.is_empty() {
                reg.files
                    .entry(data.path.clone())
                    .or_insert_with(|| data.id.clone());
            }
        }
    }
    for tab in report.network.iter().flatten() {
        for data in &tab.table.data {
            if data.id.is_empty() {
                continue;
            }
            if tab.name == "Endpoints" {
                reg.endpoints.insert(data.endpoint.clone(), data.id.clone());
            } else if tab.name == "Domains" {
                reg.domains
                    .insert(data.domain.to_ascii_lowercase(), data.id.clone());
            }
        }
    }
    if let Some(table) = &report.findings {
        for data in &table.data {
            for anchor in &data.anchors {
                reg.rules.entry(data.rule.clone()).or_insert(anchor.clone());
            }
        }
    }
    for hit in report.detections.iter().flatten() {
        if hit.id.is_empty() {
            continue;
        }
        let title = super::layout::plain_rule(&hit.title).to_owned();
        let rule = super::layout::plain_rule(&hit.rule_id).to_owned();
        for key in [
            format!("{}: {title}", hit.engine),
            format!("{}: {rule}", hit.engine),
            rule,
        ] {
            reg.detections.entry(key).or_insert_with(|| hit.id.clone());
        }
    }
    for technique in report.attack.iter().flatten() {
        reg.techniques
            .entry(technique.id.clone())
            .or_insert_with(|| anchor::attack(&technique.id));
    }
    reg.ids = report_ids(report).into_keys().collect();
    reg
}
