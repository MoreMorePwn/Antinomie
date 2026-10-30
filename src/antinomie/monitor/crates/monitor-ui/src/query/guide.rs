// SPDX-License-Identifier: GPL-3.0-only
//! The filter guide window and its examples.
use super::*;

/// The widest the guide grows, so it stays a readable panel on a wide screen.
const GUIDE_MAX_WIDTH: f32 = 760.0;

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
        .default_size([640.0, 540.0])
        .max_width(GUIDE_MAX_WIDTH)
        .show(ctx, |ui| {
            ui.label("Bare words search the row; text compares are case-sensitive, lower(field) ignores case.");
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
                ui.add(egui::Label::new(egui::RichText::new(line).monospace()).wrap());
            }
            ui.add_space(4.0);
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
            // The field column fits the longest name shown; the type column
            // fits its longest kind. Anything longer is cut with a tooltip.
            let mono = egui::TextStyle::Monospace.resolve(ui.style());
            let body = egui::TextStyle::Body.resolve(ui.style());
            let widest = |font: &egui::FontId, texts: Vec<&str>| {
                ui.fonts(|fonts| {
                    texts
                        .into_iter()
                        .map(|text| {
                            text.chars()
                                .map(|c| fonts.glyph_width(font, c))
                                .sum::<f32>()
                        })
                        .fold(0.0_f32, f32::max)
                })
            };
            let field_width = (widest(&mono, rows.iter().map(|row| row.0.as_str()).collect())
                + 24.0)
                .clamp(120.0, 300.0);
            let kind_width = (widest(&body, rows.iter().map(|row| row.1.as_str()).collect())
                + 24.0)
                .clamp(70.0, 140.0);
            TableBuilder::new(ui)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .id_salt("filter-keywords")
                .striped(true)
                .column(Column::exact(field_width).clip(true))
                .column(Column::exact(kind_width).clip(true))
                .column(Column::remainder().at_least(160.0).clip(true))
                .header(22.0, |mut header| {
                    for (column, title) in ["Field", "Type", "Meaning"].into_iter().enumerate() {
                        header.col(|ui| crate::table_sort::header(ui, "filter-keywords", column, title));
                    }
                })
                .body(|body| {
                    body.rows(22.0, rows.len(), |mut row| {
                            let (field, kind, meaning) = rows[row.index()];
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(field).monospace())
                                        .truncate(),
                                )
                                .on_hover_text(field);
                            });
                            row.col(|ui| {
                                ui.add(egui::Label::new(kind).truncate());
                            });
                            row.col(|ui| {
                                ui.add(egui::Label::new(meaning).truncate())
                                    .on_hover_text(meaning);
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

#[cfg(test)]
mod layout_tests {
    use super::*;

    /// A guide opened on a very wide screen stays a panel of readable width.
    #[test]
    fn the_guide_keeps_a_maximum_width() {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        open_guide(&ctx);
        for _ in 0..3 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(2400.0, 1200.0),
                    )),
                    ..Default::default()
                },
                guide,
            );
        }
        let area = ctx
            .memory(|memory| memory.area_rect(egui::Id::new("Filter guide")))
            .expect("the guide window");
        assert!(area.width() <= GUIDE_MAX_WIDTH + 24.0, "{area:?}");
        assert!(area.width() > 300.0, "{area:?}");
    }
}
