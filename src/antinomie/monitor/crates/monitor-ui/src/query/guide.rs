// SPDX-License-Identifier: GPL-3.0-only
//! The filter guide window and its examples.
use super::*;

/// Short recommended filters. Opened from Help → Filter guide.
pub(crate) fn guide(ctx: &egui::Context) {
    let id = egui::Id::new("filter-guide-open");
    let mut open = ctx.data(|data| data.get_temp::<bool>(id).unwrap_or(false));
    if !open {
        return;
    }
    crate::widgets::window("Filter guide")
        .open(&mut open)
        .resizable(true)
        .default_size([760.0, 540.0])
        .show(ctx, |ui| {
            ui.label("Use typed fields to compare values. A bare word searches the row. Text comparisons are case-sensitive; lower(field) makes text matching case-insensitive.");
            ui.label("Unavailable values stay missing. Packet filters use the installed TShark engine and its own field registry.");
            let query_id = egui::Id::new("filter-guide-query");
            let mut query = ui.ctx().data(|data| data.get_temp::<String>(query_id).unwrap_or_default());
            ui.add(
                egui::TextEdit::singleline(&mut query)
                    .hint_text(crate::theme::hint_text("Search fields, operators, schema argument names, syscall names"))
                    .desired_width(f32::INFINITY),
            );
            let needle = query.to_lowercase();
            ui.ctx().data_mut(|data| data.insert_temp(query_id, query));
            ui.add_space(6.0);
            ui.strong("Examples");
            let packet = ctx.data(|data| data.get_temp::<bool>(egui::Id::new("filter-guide-packet"))).unwrap_or(false);
            let contextual = ui.ctx().data(|data| data.get_temp::<std::sync::Arc<Vec<(String, String, String)>>>(egui::Id::new("filter-guide-fields")));
            let fallback: Vec<_> = syscall_fields().iter().map(|field| (field.name.to_owned(), field.kind.to_owned(), field.detail.to_owned())).collect();
            let rows = contextual.as_deref().map(Vec::as_slice).unwrap_or(&fallback);
            let examples = guide_examples(rows, packet);
            for line in &examples {
                ui.monospace(line);
            }
            ui.add_space(4.0);
            ui.label("Fields available in this filter. Right-click a value to build a clause.");
            let rows: Vec<_> = rows.iter().filter(|(field, kind, meaning)| {
                needle.is_empty() || field.to_lowercase().contains(&needle)
                    || kind.to_lowercase().contains(&needle)
                    || meaning.to_lowercase().contains(&needle)
            }).collect();
            let rows: Vec<_> = crate::table_sort::order(ui.ctx(), "filter-keywords", rows.len(), |column, a, b| {
                let (a, b) = (rows[a], rows[b]);
                match column {
                    0 => a.0.to_lowercase().cmp(&b.0.to_lowercase()),
                    1 => a.1.to_lowercase().cmp(&b.1.to_lowercase()),
                    _ => a.2.to_lowercase().cmp(&b.2.to_lowercase()),
                }
            })
            .into_iter()
            .map(|index| rows[index])
            .collect();
            use egui_extras::{Column, TableBuilder};
            crate::widgets::table::begin(ui);
            TableBuilder::new(ui)
                .id_salt("filter-keywords")
                .striped(true)
                .column(Column::initial(160.0))
                .column(Column::initial(120.0))
                .column(Column::remainder())
                .header(22.0, |mut header| {
                    for (column, title) in ["Field", "Type", "Meaning"].into_iter().enumerate() {
                        header.col(|ui| crate::table_sort::header(ui, "filter-keywords", column, title));
                    }
                })
                .body(|body| {
                    body.rows(22.0, rows.len(), |mut row| {
                            let (field, kind, meaning) = rows[row.index()];
                            row.col(|ui| {
                                ui.monospace(field);
                            });
                            row.col(|ui| {
                                ui.label(kind);
                            });
                            row.col(|ui| {
                                ui.label(meaning);
                            });
                    });
                });

        });
    ctx.data_mut(|data| data.insert_temp(id, open));
}

fn guide_examples(fields: &[(String, String, String)], packet: bool) -> Vec<String> {
    if packet {
        return [
            "ip.src == 10.0.2.15 && tcp.dstport == 80",
            "http.request.method == \"GET\"",
            "dns.qry.name contains \"example\"",
            "tcp && !udp",
        ]
        .map(str::to_owned)
        .into();
    }
    let mut examples = vec!["==  !=  <  <=  >  >=  contains  in  &  &&  ||  !  ( )".into()];
    if let Some((field, _, _)) = fields.iter().find(|(_, kind, _)| kind == "integer") {
        examples.push(format!("{field} >= 0 && exists({field})"));
        examples.push(format!("{field} in {{0, 1}}"));
    }
    if let Some((field, _, _)) = fields.iter().find(|(_, kind, _)| kind == "text") {
        examples.push(format!("{field} contains \"sample\""));
        examples.push(format!("lower({field}) == \"sample\""));
    }
    if let Some((field, _, _)) = fields.iter().find(|(_, kind, _)| kind == "text list") {
        examples.push(format!("{field} == \"needs review\""));
    }
    examples
}

pub(crate) fn open_guide(ctx: &egui::Context) {
    ctx.data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-open"), true));
}

#[cfg(test)]
fn guide_rows() -> &'static [(String, String, String)] {
    use std::collections::BTreeSet;
    use std::sync::OnceLock;
    static ROWS: OnceLock<Vec<(String, String, String)>> = OnceLock::new();
    ROWS.get_or_init(|| {
        let mut rows = Vec::new();
        for (field, kind, meaning) in KEYWORDS {
            rows.push(((*field).into(), (*kind).into(), (*meaning).into()));
        }
        for (field, meaning) in [
            ("==", "Equal. Text compare is case-sensitive on syscall rows."),
            ("!=", "Not equal."),
            ("<", "Less than. Numbers only."),
            ("<=", "Less than or equal. Numbers only."),
            (">", "Greater than. Numbers only."),
            (">=", "Greater than or equal. Numbers only."),
            ("&&", "And. Binds looser than a comparison."),
            ("||", "Or. Binds looser than &&."),
            ("!", "Not."),
            ("contains", "Substring on a text field."),
            ("in", "Membership. Example: syscall.num in {9, 10}."),
            ("exists", "The field was recorded."),
            ("missing", "The field was not recorded."),
            ("&", "Bit test. Example: args.prot & 7 == 7."),
        ] {
            rows.push(((*field).into(), "operator".into(), (*meaning).into()));
        }
        for (field, meaning) in [
            ("ip.src", "Source IP. Equality only."),
            ("ip.dst", "Destination IP. Equality only."),
            ("ip.addr", "Either IP endpoint."),
            ("tcp.srcport", "TCP source port."),
            ("tcp.dstport", "TCP destination port."),
            ("udp.port", "Either UDP port."),
            ("frame.len", "Captured frame length."),
            ("http.request", "Bare field: decoded HTTP request line, not a status line."),
            (
                "http.request.method",
                "Method token of the decoded HTTP request line.",
            ),
            (
                "http.request.uri",
                "Request-target token of the decoded HTTP request line.",
            ),
            (
                "dns.qry.name",
                "Name from a decoded query TYPE name or response TYPE name summary. A bare field means the packet is DNS.",
            ),
            ("frame contains", "Substring of the packet summary. Not a field comparison."),
        ] {
            rows.push(((*field).into(), "packet".into(), (*meaning).into()));
        }
        let mut arguments = BTreeSet::new();
        let mut names = BTreeSet::new();
        for syscall in antinomie_monitor_core::syscalls::all() {
            names.insert(syscall.name.clone());
            for argument in &syscall.arguments {
                arguments.insert(argument.name.clone());
            }
        }
        for name in arguments {
            rows.push((
                format!("args.{name}"),
                "schema argument".into(),
                "Argument name from protocol/native-syscalls.json.".into(),
            ));
        }
        for name in names {
            rows.push((
                name,
                "syscall name".into(),
                "syscall.name value from the native schema.".into(),
            ));
        }
        rows
    })
    .as_slice()
}

#[cfg(test)]
pub(super) fn guide_has(needle: &str) -> bool {
    guide_rows().iter().any(|(field, _, _)| field == needle)
}
