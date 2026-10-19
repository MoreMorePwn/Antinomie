// SPDX-License-Identifier: MIT
//! One finding in full: how each engine's explanation is read, and the movable
//! Details window with the rule, its metadata and every evidence location.
use super::*;
use antinomie_monitor_core::analysis::detection::journal::Focus;

/// An engine's `details` text split into a readable summary and label/value
/// rows. The text is built by the engines in monitor-core and is never shown
/// as one block of `key=value` pairs.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Parsed {
    pub summary: String,
    pub rows: Vec<(String, String)>,
}

pub(super) fn parse_details(engine: Engine, details: &str) -> Parsed {
    let parsed = match engine {
        Engine::Yara => yara_details(details),
        Engine::Ids => ids_details(details),
        Engine::Sigma => Some(sigma_details(details)),
    };
    parsed.unwrap_or_else(|| generic_details(details))
}

/// `<description>; author: <authors>; tags: <tags>`. The author is shown from
/// the finding itself.
fn yara_details(details: &str) -> Option<Parsed> {
    let tags_at = details.rfind("; tags:")?;
    let author_at = details[..tags_at].rfind("; author:")?;
    let tags = details[tags_at + "; tags:".len()..].trim();
    let mut rows = Vec::new();
    if !tags.is_empty() {
        rows.push(("Tags".to_owned(), tags.to_owned()));
    }
    Some(Parsed {
        summary: details[..author_at].trim().to_owned(),
        rows,
    })
}

/// `<category>; <src>:<port> → <dst>:<port>; <EVE metadata as JSON>`.
fn ids_details(details: &str) -> Option<Parsed> {
    let (category, rest) = details.split_once("; ")?;
    let (flow, metadata) = rest.split_once("; ")?;
    let flow = if flow.chars().any(char::is_alphanumeric) {
        flow.trim()
    } else {
        ""
    };
    let category = category.trim();
    let mut rows = Vec::new();
    if !category.is_empty() {
        rows.push(("Category".to_owned(), category.to_owned()));
    }
    if !flow.is_empty() {
        rows.push(("Flow".to_owned(), flow.to_owned()));
    }
    match serde_json::from_str::<serde_json::Value>(metadata) {
        Ok(serde_json::Value::Object(map)) => {
            for (key, value) in map {
                rows.push((label_for(&key), json_text(&value)));
            }
        }
        Ok(serde_json::Value::Null) => {}
        _ if metadata.trim().is_empty() => {}
        _ => rows.push(("Metadata".to_owned(), metadata.trim().to_owned())),
    }
    let summary = [category, flow]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    Some(Parsed { summary, rows })
}

/// `<how it was evaluated>[ References: <a>; <b>]`.
fn sigma_details(details: &str) -> Parsed {
    let (note, references) = match details.split_once(" References: ") {
        Some((note, references)) => (note, references.trim()),
        None => (details, ""),
    };
    let mut rows = Vec::new();
    // The rule's own description comes first; results saved before it was
    // kept start with the evaluation note.
    let (summary, evaluation) = match note.find(SIGMA_EVALUATION) {
        Some(at) if at > 0 => (note[..at].trim(), note[at..].trim()),
        _ => (note.trim(), ""),
    };
    if !evaluation.is_empty() {
        rows.push(("Evaluation".to_owned(), evaluation.to_owned()));
    }
    if !references.is_empty() {
        rows.push(("References".to_owned(), references.replace("; ", "\n")));
    }
    Parsed {
        summary: summary.to_owned(),
        rows,
    }
}

const SIGMA_EVALUATION: &str = "Evaluated against normalized captured Linux events";

/// Unknown shapes: `key=value` and `key: value` segments become rows and the
/// remaining text is the summary.
fn generic_details(details: &str) -> Parsed {
    let mut summary = Vec::new();
    let mut rows = Vec::new();
    for part in details.split("; ") {
        match pair(part) {
            Some((key, value)) => rows.push((label_for(key), value.to_owned())),
            None if !part.trim().is_empty() => summary.push(part.trim()),
            None => {}
        }
    }
    Parsed {
        summary: summary.join("; "),
        rows,
    }
}

fn pair(part: &str) -> Option<(&str, &str)> {
    let at = part.find(['=', ':'])?;
    let (key, value) = (part[..at].trim(), part[at + 1..].trim());
    let word = !key.is_empty()
        && key.len() <= 32
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    (word && !value.is_empty()).then_some((key, value))
}

fn label_for(key: &str) -> String {
    let spaced = key.replace(['_', '-'], " ");
    let mut chars = spaced.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}

fn json_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(items) => {
            items.iter().map(json_text).collect::<Vec<_>>().join(", ")
        }
        other => other.to_string(),
    }
}

/// The rule pack a finding came from. YARA records a namespace `sN` that
/// indexes the report's sources, and Sigma appends the source digest.
pub(super) fn pack_name(report: &Report, finding: &Finding) -> String {
    let index = finding
        .source
        .strip_prefix('s')
        .and_then(|index| index.parse::<usize>().ok());
    if let Some(source) = index.and_then(|index| report.sources.get(index)) {
        return source.name.clone();
    }
    finding
        .source
        .split_once(" sha256:")
        .map_or(finding.source.as_str(), |(name, _)| name)
        .to_owned()
}

pub(super) fn evidence_label(evidence: &Evidence) -> String {
    match evidence {
        Evidence::Call {
            stream,
            cookie,
            call,
        } => format!("Open syscall {stream}/{cookie}/{call}"),
        Evidence::Packet { capture, frame } => format!(
            "Open packet #{} — {}",
            frame,
            capture.file_name().unwrap_or_default().to_string_lossy()
        ),
        Evidence::Bytes { path, offset, .. } => format!(
            "{} — {}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            offset.map_or("file-level match; no byte position".into(), |offset| {
                format!("open bytes at 0x{offset:x}")
            })
        ),
    }
}

pub(super) fn evidence_values(evidence: &Evidence) -> Vec<(&'static str, RowValue)> {
    let number = |value: u64| RowValue::Number(i128::from(value));
    match evidence {
        Evidence::Call {
            stream,
            cookie,
            call,
        } => vec![
            ("stream.id", number(*stream)),
            ("process.cookie", number(*cookie)),
            ("event.id", number(*call)),
        ],
        Evidence::Packet { capture, frame } => vec![
            (
                "capture.path",
                RowValue::Text(capture.display().to_string()),
            ),
            ("frame.number", number(*frame)),
        ],
        Evidence::Bytes {
            path,
            offset,
            address,
            report_id,
            block,
        } => vec![
            (
                "evidence.block",
                block
                    .as_ref()
                    .and_then(|block| serde_json::to_string(block).ok())
                    .map_or(RowValue::Missing, RowValue::Text),
            ),
            ("evidence.path", RowValue::Text(path.display().to_string())),
            ("evidence.offset", offset.map_or(RowValue::Missing, number)),
            (
                "evidence.address",
                address.map_or(RowValue::Missing, number),
            ),
            (
                "evidence.report",
                report_id
                    .as_ref()
                    .map_or(RowValue::Missing, |value| RowValue::Text(value.clone())),
            ),
        ],
    }
}

/// What a click on an evidence row asks for.
#[derive(Debug, PartialEq)]
pub(super) enum Pick {
    /// The recorded call, packet or bytes.
    Source(Evidence),
    /// The normalized event in the Sigma journal.
    Journal(Focus),
}

/// Where the event behind `finding.evidence[index]` sits in the journal. Only
/// Sigma evaluates the journal. A result saved before event numbers were kept
/// can only name the call or packet, which may have produced several events.
pub(super) fn journal_focus(engine: Engine, finding: &Finding, index: usize) -> Option<Focus> {
    if engine != Engine::Sigma {
        return None;
    }
    if let Some(event) = finding.events.get(index) {
        return Some(Focus::Event(*event));
    }
    match finding.evidence.get(index)? {
        source @ (Evidence::Call { .. } | Evidence::Packet { .. }) => {
            Some(Focus::Source(source.clone()))
        }
        Evidence::Bytes { .. } => None,
    }
}

/// Every retained location of a finding, each one a button. Returns the one
/// clicked this frame. A Sigma location also opens the journal event.
pub(super) fn evidence_list(
    ui: &mut egui::Ui,
    engine: Engine,
    finding: &Finding,
    salt: impl std::hash::Hash,
    max_height: f32,
) -> Option<Pick> {
    let mut selected = None;
    if finding.evidence.is_empty() {
        ui.weak("No evidence location was recorded for this rule.");
    }
    egui::ScrollArea::vertical()
        .id_salt(salt)
        .max_height(max_height)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for (index, evidence) in finding.evidence.iter().enumerate() {
                let focus = journal_focus(engine, finding, index);
                ui.horizontal_wrapped(|ui| {
                    if let Some(Focus::Event(event)) = &focus {
                        let label = format!("Journal event #{event}");
                        let button = ui
                            .add(egui::Button::new(label).wrap())
                            .on_hover_text("Open this event in the normalized event journal");
                        if button.clicked() {
                            selected = Some(Pick::Journal(Focus::Event(*event)));
                        }
                    }
                    if ui
                        .add(egui::Button::new(evidence_label(evidence)).wrap())
                        .clicked()
                    {
                        selected = Some(Pick::Source(evidence.clone()));
                    }
                    if let Some(Focus::Source(source)) = &focus {
                        let button = ui.small_button("In journal").on_hover_text(
                            "Saved before event numbers were kept: shows the first journal event recorded for this source",
                        );
                        if button.clicked() {
                            selected = Some(Pick::Journal(Focus::Source(source.clone())));
                        }
                    }
                });
            }
        });
    if (finding.count as usize) > finding.evidence.len() {
        ui.weak(format!(
            "{} hits are counted; {} locations are listed.",
            finding.count,
            finding.evidence.len()
        ));
    }
    selected
}

/// The bytes read for the last clicked location, if it belongs to this finding.
pub(super) fn byte_preview(
    ui: &mut egui::Ui,
    preview: Option<&BytePreview>,
    loading: bool,
    finding: &Finding,
) {
    if loading {
        ui.spinner();
    }
    match preview {
        Some(Ok((evidence, data))) if finding.evidence.contains(evidence) => {
            ui.add(egui::Label::new(format!("{evidence:?}")).wrap());
            for (index, chunk) in data.chunks(16).enumerate() {
                let offset = match evidence {
                    Evidence::Bytes {
                        offset: Some(offset),
                        ..
                    } => offset + (index * 16) as u64,
                    _ => (index * 16) as u64,
                };
                let hex = chunk
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                ui.add(
                    egui::Label::new(RichText::new(format!("{offset:016x}  {hex}")).monospace())
                        .wrap(),
                );
            }
        }
        Some(Err(error)) => {
            crate::activity::warning(ui, error);
        }
        _ => {}
    }
}

/// Which finding a Details window shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WindowKey {
    pub engine: usize,
    pub rule_id: String,
    pub title: String,
}

impl View {
    pub(super) fn open_window(&mut self, key: WindowKey) {
        if !self.windows.contains(&key) {
            self.windows.push(key);
        }
    }

    /// Act on a clicked location. `scanned` is the journal digest of the
    /// result it came from, so the viewer can tell if the file has changed.
    pub(super) fn open_pick(&mut self, ctx: &egui::Context, scanned: Option<String>, pick: Pick) {
        match pick {
            Pick::Source(evidence) => self.open_evidence(ctx, evidence),
            Pick::Journal(focus) => self.journal.open(ctx, scanned, Some(focus)),
        }
    }

    /// Open a retained location: bytes load a preview, the rest jump to their view.
    pub(super) fn open_evidence(&mut self, ctx: &egui::Context, evidence: Evidence) {
        match evidence {
            Evidence::Bytes { .. } => self.read_bytes(ctx, evidence),
            _ => request_evidence_jump(ctx, &evidence_values(&evidence)),
        }
    }

    /// One movable, resizable window per opened finding. Call once per frame.
    pub(crate) fn show_windows(&mut self, ctx: &egui::Context) {
        let mut keys = std::mem::take(&mut self.windows);
        let mut clicked = None;
        keys.retain(|key| {
            let Some(Ok(report)) = self.results.get(key.engine).and_then(Option::as_ref) else {
                return false;
            };
            let Some(finding) = report
                .findings
                .iter()
                .find(|finding| finding.rule_id == key.rule_id && finding.title == key.title)
            else {
                return false;
            };
            let mut open = true;
            egui::Window::new(format!("{} · {}", name(report.engine), finding.title))
                .id(egui::Id::new((
                    "detection-finding",
                    key.engine,
                    &key.rule_id,
                    &key.title,
                )))
                .open(&mut open)
                .default_size([680.0, 560.0])
                .resizable(true)
                .collapsible(true)
                .show(ctx, |ui| {
                    let preview = self.bytes.as_ref();
                    let loading = self.byte_rx.is_some();
                    if let Some(pick) = finding_body(ui, report, finding, preview, loading) {
                        clicked = Some((report.source_digest.clone(), pick));
                    }
                });
            open
        });
        self.windows = keys;
        if let Some((scanned, pick)) = clicked {
            self.open_pick(ctx, scanned, pick);
        }
        self.journal.show(ctx, self.identity.as_ref(), self.clock);
    }
}

fn finding_body(
    ui: &mut egui::Ui,
    report: &Report,
    finding: &Finding,
    preview: Option<&BytePreview>,
    loading: bool,
) -> Option<Pick> {
    let parsed = parse_details(report.engine, &finding.details);
    let mut clicked = None;
    egui::ScrollArea::vertical()
        .id_salt("detection-finding-body")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(&finding.title)
                            .strong()
                            .size(ui.text_style_height(&egui::TextStyle::Body) + 2.0)
                            .color(theme::heading()),
                    )
                    .wrap(),
                );
                if !finding.severity.is_empty() {
                    presentation::badge(ui, &finding.severity, severity_color(&finding.severity));
                }
            });
            ui.add_space(6.0);
            let count = finding.count.to_string();
            let source = pack_name(report, finding);
            let facts = [
                ("Rule id", finding.rule_id.as_str(), true),
                ("Engine", name(report.engine), false),
                ("Source", source.as_str(), false),
                ("License", finding.license.as_str(), false),
                ("Author", attribution(&finding.author), false),
                ("Hits", count.as_str(), false),
            ];
            rows_grid(ui, "detection-finding-facts", &facts);
            if !finding.mitre.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for reference in &finding.mitre {
                        presentation::badge(ui, reference, theme::blue());
                    }
                });
            }
            if !parsed.summary.is_empty() {
                section(ui, "Description");
                ui.add(egui::Label::new(RichText::new(&parsed.summary).color(theme::text())).wrap());
            }
            if !parsed.rows.is_empty() {
                section(ui, "Rule metadata");
                let rows: Vec<_> = parsed
                    .rows
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str(), false))
                    .collect();
                rows_grid(ui, "detection-finding-metadata", &rows);
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Rule").strong().color(theme::heading()));
                if !finding.rule_text.is_empty() && ui.button("Copy rule").clicked() {
                    ui.ctx().copy_text(finding.rule_text.clone());
                }
            });
            if finding.rule_text.is_empty() {
                ui.weak("The rule text was not retained for results saved before this version. Scan again to keep it.");
            } else {
                egui::ScrollArea::vertical()
                    .id_salt("detection-finding-rule")
                    .max_height(260.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        let mut text: &str = &finding.rule_text;
                        ui.add(
                            egui::TextEdit::multiline(&mut text)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY),
                        );
                    });
            }
            section(
                ui,
                &format!("Evidence locations ({})", finding.evidence.len()),
            );
            if let Some(pick) = evidence_list(ui, report.engine, finding, "detection-finding-hits", 240.0)
            {
                clicked = Some(pick);
            }
            byte_preview(ui, preview, loading, finding);
        });
    clicked
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(8.0);
    ui.label(RichText::new(title).strong().color(theme::heading()));
}

fn rows_grid(ui: &mut egui::Ui, id: &str, rows: &[(&str, &str, bool)]) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            for (label, value, mono) in rows {
                ui.label(RichText::new(*label).small().color(theme::muted()));
                let text = RichText::new(*value).color(theme::text());
                ui.add(egui::Label::new(if *mono { text.monospace() } else { text }).wrap());
                ui.end_row();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::super::tests::{frames, rendered_text};
    use super::*;

    fn bytes_at(offset: u64) -> Evidence {
        Evidence::Bytes {
            path: PathBuf::from("specimen"),
            offset: Some(offset),
            address: None,
            report_id: None,
            block: None,
        }
    }

    #[test]
    fn yara_metadata_becomes_a_summary_and_rows() {
        let parsed = parse_details(
            Engine::Yara,
            "Detects a loader; with a semicolon; author: A; B; tags: MALWARE loader",
        );
        assert_eq!(parsed.summary, "Detects a loader; with a semicolon");
        assert_eq!(
            parsed.rows,
            vec![("Tags".to_owned(), "MALWARE loader".to_owned())]
        );
        let empty = parse_details(Engine::Yara, "; author: ; tags: ");
        assert_eq!(empty, Parsed::default());
    }

    #[test]
    fn ids_metadata_json_becomes_rows() {
        let parsed = parse_details(
            Engine::Ids,
            "A Network Trojan; 10.0.0.2:5000 → 203.0.113.9:80; {\"mitre_technique_id\":[\"T1071\"],\"updated_at\":[\"2026_01_01\"]}",
        );
        assert_eq!(
            parsed.summary,
            "A Network Trojan · 10.0.0.2:5000 → 203.0.113.9:80"
        );
        assert!(parsed
            .rows
            .contains(&("Mitre technique id".to_owned(), "T1071".to_owned())));
        assert!(parsed.rows.iter().any(|(key, _)| key == "Flow"));
        let none = parse_details(Engine::Ids, "cat; :  → :; null");
        assert_eq!(none.summary, "cat");
        assert_eq!(none.rows, vec![("Category".to_owned(), "cat".to_owned())]);
    }

    #[test]
    fn sigma_references_and_unknown_text_are_split() {
        let parsed = parse_details(
            Engine::Sigma,
            "Evaluated events. References: https://a; https://b",
        );
        assert_eq!(parsed.summary, "Evaluated events.");
        assert_eq!(parsed.rows[0].1, "https://a\nhttps://b");
        let generic = parse_details(Engine::Yara, "plain note; owner=ops; score: 3");
        assert_eq!(generic.summary, "plain note");
        assert_eq!(generic.rows.len(), 2);
        assert_eq!(generic.rows[0], ("Owner".to_owned(), "ops".to_owned()));
        assert_eq!(parse_details(Engine::Ids, "marker").summary, "marker");
    }

    #[test]
    fn sigma_description_is_the_summary_and_the_evaluation_note_a_row() {
        let parsed = parse_details(
            Engine::Sigma,
            "Detects curl piped to a shell. Evaluated against normalized captured Linux events; joined argv is not original shell quoting. References: https://a",
        );
        assert_eq!(parsed.summary, "Detects curl piped to a shell.");
        assert_eq!(parsed.rows[0].0, "Evaluation");
        assert!(parsed.rows[0].1.starts_with("Evaluated against"));
        assert_eq!(
            parsed.rows[1],
            ("References".to_owned(), "https://a".to_owned())
        );
    }

    #[test]
    fn pack_name_resolves_the_namespace_and_drops_the_digest() {
        let mut report = Report::empty(
            Engine::Yara,
            Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        );
        report.sources.push(engine::Source {
            name: "Forge Core".into(),
            version: String::new(),
            license: String::new(),
            sha256: String::new(),
            data: String::new(),
        });
        let mut finding = super::super::tests::finding("rule", "T", vec![]);
        finding.source = "s0".into();
        assert_eq!(pack_name(&report, &finding), "Forge Core");
        finding.source = "Sigma Pack sha256:abcd".into();
        assert_eq!(pack_name(&report, &finding), "Sigma Pack");
        finding.source = "antinomie".into();
        assert_eq!(pack_name(&report, &finding), "antinomie");
    }

    #[test]
    fn details_window_lists_the_rule_text_and_every_evidence_location() {
        let mut view = View::default();
        let mut finding = super::super::tests::finding(
            "sample_rule",
            "Sample rule",
            vec![bytes_at(0x10), bytes_at(0x20), bytes_at(0x30)],
        );
        finding.count = 9;
        finding.details = "Finds the sample; author: Ann; tags: MALWARE".into();
        finding.rule_text = "rule sample_rule {\n  condition: true\n}".into();
        view.results[0] = Some(Ok(super::super::tests::report(vec![finding])));
        view.open_window(WindowKey {
            engine: 0,
            rule_id: "sample_rule".into(),
            title: "Sample rule".into(),
        });
        // A second open of the same finding does not stack another window.
        view.open_window(view.windows[0].clone());
        assert_eq!(view.windows.len(), 1);
        let ctx = egui::Context::default();
        let shapes = frames(&ctx, 4, |ctx| view.show_windows(ctx));
        let joined = rendered_text(&shapes);
        assert!(joined.contains("rule sample_rule {"), "{joined}");
        assert!(joined.contains("condition: true"), "{joined}");
        assert!(joined.contains("Copy rule"), "{joined}");
        for offset in ["0x10", "0x20", "0x30"] {
            assert!(
                joined.contains(&format!("specimen — open bytes at {offset}")),
                "{offset}\n{joined}"
            );
        }
        assert!(joined.contains("Evidence locations (3)"), "{joined}");
        assert!(
            joined.contains("9 hits are counted; 3 locations are listed."),
            "{joined}"
        );
        assert!(joined.contains("Finds the sample"), "{joined}");
        assert!(joined.contains("Sample rule"), "{joined}");
        assert!(!joined.contains("author: Ann"), "{joined}");
    }

    #[test]
    fn details_window_explains_a_missing_rule_text_and_closes_for_a_gone_result() {
        let mut view = View::default();
        let finding = super::super::tests::finding("old", "Old result", vec![bytes_at(1)]);
        view.results[0] = Some(Ok(super::super::tests::report(vec![finding])));
        view.open_window(WindowKey {
            engine: 0,
            rule_id: "old".into(),
            title: "Old result".into(),
        });
        let ctx = egui::Context::default();
        let joined = rendered_text(&frames(&ctx, 4, |ctx| view.show_windows(ctx)));
        assert!(
            joined.contains("not retained for results saved before this version"),
            "{joined}"
        );
        assert!(!joined.contains("Copy rule"), "{joined}");
        view.results[0] = None;
        let _ = frames(&ctx, 1, |ctx| view.show_windows(ctx));
        assert!(view.windows.is_empty());
    }
}
