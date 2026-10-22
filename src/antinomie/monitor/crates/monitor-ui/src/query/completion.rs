// SPDX-License-Identifier: GPL-3.0-only
//! Field, operator and value completions for the filter editor.
use super::*;

#[cfg(test)]
pub(crate) fn completions(text: &str, cursor: usize, scope: FilterScope) -> Vec<Completion> {
    completions_with(text, cursor, scope, &[])
}

#[cfg(test)]
pub(crate) fn completions_with(
    text: &str,
    cursor: usize,
    scope: FilterScope,
    known_values: &[String],
) -> Vec<Completion> {
    completions_fields(text, cursor, &fields_for(scope), known_values, None)
}

#[cfg(test)]
pub(super) fn completions_fields(
    text: &str,
    cursor: usize,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
    selection: Option<(usize, usize)>,
) -> Vec<Completion> {
    completions_field_iter(
        text,
        cursor,
        fields.iter().copied(),
        known_values,
        selection,
        false,
    )
}

pub(super) fn completions_field_iter<'a>(
    text: &str,
    cursor: usize,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
    selection: Option<(usize, usize)>,
    packet: bool,
) -> Vec<Completion> {
    let cursor = floor_boundary(text, cursor.min(text.len()));
    let (start, end, prefix_end) =
        if let Some((start, end)) = selection.filter(|(start, end)| start != end) {
            let start = floor_boundary(text, start.min(text.len()));
            let end = floor_boundary(text, end.min(text.len())).max(start);
            (start, end, end)
        } else {
            (token_start(text, cursor), token_end(text, cursor), cursor)
        };
    let prefix = &text[start..prefix_end];
    let previous = previous_word(text, start);
    let mut items = Vec::new();
    let function = editor_tokens(&text[..start])
        .windows(2)
        .last()
        .and_then(|tokens| {
            (text[tokens[1].0..tokens[1].1].trim() == "(")
                .then(|| text[tokens[0].0..tokens[0].1].trim())
        })
        .filter(|name| matches!(*name, "lower" | "exists" | "missing"));
    let clause_start = function.is_none()
        && previous.as_deref().is_none_or(|word| {
            matches!(word, "&&" | "||" | "(" | "!")
                || word.eq_ignore_ascii_case("and")
                || word.eq_ignore_ascii_case("or")
        });
    if clause_start && !packet {
        let needle = prefix.to_ascii_lowercase();
        for (insert, detail) in [
            ("exists", "Recorded field, written before the field name"),
            ("missing", "Absent field, written before the field name"),
        ] {
            if needle.is_empty() || insert.starts_with(&needle) {
                items.push(Completion {
                    start,
                    end,
                    insert: format!("{insert} "),
                    detail: detail.into(),
                });
            }
        }
    }
    if let Some(field) = previous.as_deref().and_then(|word| {
        fields
            .clone()
            .find(|field| field.name.eq_ignore_ascii_case(word))
    }) {
        if prefix.is_empty() || operator_prefix(prefix) {
            for (insert, detail) in if packet {
                packet_operators(field.kind)
            } else {
                operators(field.kind)
            } {
                if insert
                    .trim()
                    .to_ascii_lowercase()
                    .starts_with(&prefix.to_ascii_lowercase())
                    || prefix.is_empty()
                {
                    items.push(Completion {
                        start,
                        end,
                        insert: format!(" {insert} "),
                        detail: (*detail).into(),
                    });
                }
            }
        }
    }
    if let Some(field_name) = field_before_operator(text, start) {
        let quoted_prefix = prefix.starts_with(['"', '\'']);
        let value_prefix = if quoted_prefix { &prefix[1..] } else { prefix };
        for (insert, detail) in values_for(&field_name, value_prefix, known_values) {
            items.push(Completion {
                start,
                end,
                insert: if fields.clone().any(|field| {
                    field.name.eq_ignore_ascii_case(&field_name) && field.kind == "integer"
                }) {
                    insert
                } else {
                    quote_value(&insert, quoted_prefix)
                },
                detail,
            });
        }
        if let Some(field) = fields
            .clone()
            .find(|field| field.name.eq_ignore_ascii_case(&field_name))
        {
            if field.kind == "boolean" || field.kind == "FT_BOOLEAN" {
                for value in ["true", "false"] {
                    if value.starts_with(value_prefix) {
                        items.push(Completion {
                            start,
                            end,
                            insert: value.into(),
                            detail: "boolean value".into(),
                        });
                    }
                }
            }
        }
        return items;
    }
    if unclosed_quote(&text[..cursor]) {
        return Vec::new();
    }
    if let Ok(tokens) = tokenize(text[..start].trim_end()) {
        let mut parser = Parser { tokens, at: 0 };
        if parser
            .parse_or()
            .is_ok_and(|expr| !matches!(expr, Expr::Value(_)))
            && parser.at == parser.tokens.len()
        {
            for (insert, detail) in [("&&", "And"), ("||", "Or"), ("and", "And"), ("or", "Or")] {
                if insert.starts_with(&prefix.to_ascii_lowercase()) {
                    items.push(Completion {
                        start,
                        end,
                        insert: format!(" {insert} "),
                        detail: detail.into(),
                    });
                }
            }
            return items;
        }
    }
    let offering_operator = previous.as_deref().is_some_and(|word| {
        fields
            .clone()
            .any(|field| field.name.eq_ignore_ascii_case(word))
            && (prefix.is_empty() || operator_prefix(prefix))
    });
    if !offering_operator && !prefix.is_empty() {
        let needle = prefix.to_ascii_lowercase();
        for field in fields.clone() {
            if function == Some("lower") && !matches!(field.kind, "text" | "text list") {
                continue;
            }
            if field
                .name
                .get(..needle.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&needle))
            {
                items.push(Completion {
                    start,
                    end,
                    insert: field.name.into(),
                    detail: format!("{} · {}", field.kind, field.detail),
                });
                if items.len() >= 12 {
                    break;
                }
            }
        }
    } else if !offering_operator && prefix.is_empty() {
        for field in fields
            .clone()
            .filter(|field| function != Some("lower") || matches!(field.kind, "text" | "text list"))
            .take(8)
        {
            items.push(Completion {
                start,
                end,
                insert: field.name.into(),
                detail: format!("{} · {}", field.kind, field.detail),
            });
        }
    }
    items.truncate(12);
    items
}

pub(super) fn quote_value(value: &str, force: bool) -> String {
    let reserved = matches!(
        value.to_ascii_lowercase().as_str(),
        "and" | "or" | "not" | "exists" | "missing" | "contains" | "in"
    );
    if !force
        && !reserved
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return value.to_owned();
    }
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    )
}

pub(super) fn apply_completion(text: &mut String, item: &Completion) -> usize {
    let start = item.start.min(text.len());
    let end = item.end.min(text.len()).max(start);
    text.replace_range(start..end, &item.insert);
    start + item.insert.len()
}

pub(super) fn fields_for(scope: FilterScope) -> Vec<FieldSpec<'static>> {
    match scope {
        FilterScope::Syscall => syscall_fields(),
        FilterScope::Table(fields) => fields.to_vec(),
        FilterScope::Record => vec![
            FieldSpec {
                name: "entry.id",
                kind: "text",
                detail: "Run or result id",
            },
            FieldSpec {
                name: "entry.name",
                kind: "text",
                detail: "Annotation name",
            },
            FieldSpec {
                name: "entry.path",
                kind: "text",
                detail: "Run executable or result path",
            },
            FieldSpec {
                name: "entry.tag",
                kind: "text",
                detail: "Annotation tag",
            },
            FieldSpec {
                name: "tag",
                kind: "text",
                detail: "Annotation tag",
            },
            FieldSpec {
                name: "tags",
                kind: "text",
                detail: "Annotation tag",
            },
            FieldSpec {
                name: "name",
                kind: "text",
                detail: "Annotation name",
            },
        ],
        #[cfg(test)]
        FilterScope::Packet => vec![
            FieldSpec {
                name: "ip.src",
                kind: "ip",
                detail: "Source IP",
            },
            FieldSpec {
                name: "ip.dst",
                kind: "ip",
                detail: "Destination IP",
            },
            FieldSpec {
                name: "ip.addr",
                kind: "ip",
                detail: "Either IP endpoint",
            },
            FieldSpec {
                name: "ipv6.addr",
                kind: "ip",
                detail: "IPv6 endpoint",
            },
            FieldSpec {
                name: "tcp.srcport",
                kind: "integer",
                detail: "TCP source port",
            },
            FieldSpec {
                name: "tcp.dstport",
                kind: "integer",
                detail: "TCP destination port",
            },
            FieldSpec {
                name: "tcp.port",
                kind: "integer",
                detail: "Either TCP port",
            },
            FieldSpec {
                name: "udp.srcport",
                kind: "integer",
                detail: "UDP source port",
            },
            FieldSpec {
                name: "udp.dstport",
                kind: "integer",
                detail: "UDP destination port",
            },
            FieldSpec {
                name: "udp.port",
                kind: "integer",
                detail: "Either UDP port",
            },
            FieldSpec {
                name: "frame.number",
                kind: "integer",
                detail: "Frame number",
            },
            FieldSpec {
                name: "frame.len",
                kind: "integer",
                detail: "Captured frame length",
            },
            FieldSpec {
                name: "frame.protocol",
                kind: "text",
                detail: "Protocol column",
            },
            FieldSpec {
                name: "frame.info",
                kind: "text",
                detail: "Info column",
            },
            FieldSpec {
                name: "frame.contains",
                kind: "text",
                detail: "Substring of the packet summary",
            },
            FieldSpec {
                name: "http.request",
                kind: "text",
                detail: "Decoded HTTP request line",
            },
            FieldSpec {
                name: "http.request.method",
                kind: "text",
                detail: "HTTP method",
            },
            FieldSpec {
                name: "http.request.uri",
                kind: "text",
                detail: "HTTP request target",
            },
            FieldSpec {
                name: "http.host",
                kind: "text",
                detail: "HTTP Host header",
            },
            FieldSpec {
                name: "dns.qry.name",
                kind: "text",
                detail: "DNS query name",
            },
            FieldSpec {
                name: "tcp.flags.syn",
                kind: "integer",
                detail: "TCP SYN",
            },
            FieldSpec {
                name: "tcp.flags.ack",
                kind: "integer",
                detail: "TCP ACK",
            },
            FieldSpec {
                name: "tcp.flags.fin",
                kind: "integer",
                detail: "TCP FIN",
            },
            FieldSpec {
                name: "tcp.flags.reset",
                kind: "integer",
                detail: "TCP RST",
            },
            FieldSpec {
                name: "tcp.flags.push",
                kind: "integer",
                detail: "TCP PSH",
            },
        ],
    }
}

pub(super) fn syscall_fields() -> Vec<FieldSpec<'static>> {
    let mut fields: Vec<FieldSpec<'static>> = KEYWORDS
        .iter()
        .filter(|(name, _, _)| {
            *name != "args.<name>" && *name != "args.raw[0..5]" && !name.starts_with("entry.")
        })
        .map(|(name, kind, detail)| FieldSpec { name, kind, detail })
        .collect();
    fields.extend([
        FieldSpec::number("syscall.number", "Alias of syscall.num"),
        FieldSpec::text("syscall", "Alias of syscall.name"),
        FieldSpec::number("task.cookie", "Alias of task"),
        FieldSpec::number("call_id", "Alias of call.id"),
        FieldSpec::number("args.address", "Captured addr or address argument"),
        FieldSpec::number("args.addr", "Captured addr or address argument"),
        FieldSpec::number("args.length", "Captured len or length argument"),
        FieldSpec::number("args.len", "Captured len or length argument"),
        FieldSpec::number("args.protection", "Captured prot or protection argument"),
        FieldSpec::number("args.prot", "Captured prot or protection argument"),
        FieldSpec::number("args.buffer", "Captured buf or buffer pointer"),
        FieldSpec::number("args.buf", "Captured buf or buffer pointer"),
        FieldSpec::text("args.file", "Captured path text; pointer is in args.raw"),
        FieldSpec::text("args.filename", "Captured filename text"),
        FieldSpec::text("args.pathname", "Captured pathname text"),
        FieldSpec::text("args.oldname", "Captured old path text"),
        FieldSpec::text("args.newname", "Captured new path text"),
    ]);
    for index in 0..6 {
        fields.push(FieldSpec::number(
            match index {
                0 => "args.0",
                1 => "args.1",
                2 => "args.2",
                3 => "args.3",
                4 => "args.4",
                _ => "args.5",
            },
            "Captured argument word",
        ));
        fields.push(FieldSpec {
            name: match index {
                0 => "args.raw[0]",
                1 => "args.raw[1]",
                2 => "args.raw[2]",
                3 => "args.raw[3]",
                4 => "args.raw[4]",
                _ => "args.raw[5]",
            },
            kind: "integer",
            detail: "Captured argument word",
        });
    }
    let known: std::collections::BTreeSet<&str> = fields.iter().map(|field| field.name).collect();
    fields.extend(
        schema_argument_fields()
            .into_iter()
            .filter(|field| !known.contains(field.name)),
    );
    fields.extend(
        antinomie_monitor_core::filter_members::registry()
            .iter()
            .map(|member| {
                use antinomie_monitor_core::filter_members::MemberKind;
                FieldSpec {
                    name: &member.name,
                    kind: match member.kind {
                        MemberKind::Integer => "integer",
                        MemberKind::Text => "text",
                        MemberKind::Boolean => "boolean",
                    },
                    detail: &member.detail,
                }
            }),
    );
    fields
}

pub(super) fn schema_argument_fields() -> Vec<FieldSpec<'static>> {
    use std::sync::OnceLock;
    static FIELDS: OnceLock<Vec<(String, String)>> = OnceLock::new();
    let stored = FIELDS.get_or_init(|| {
        let mut names = std::collections::BTreeSet::new();
        for syscall in antinomie_monitor_core::syscalls::all() {
            for argument in &syscall.arguments {
                names.insert(argument.name.clone());
            }
        }
        names
            .into_iter()
            .map(|name| (format!("args.{name}"), "Schema argument".into()))
            .collect()
    });
    stored
        .iter()
        .map(|(name, detail)| FieldSpec {
            name: name.as_str(),
            kind: if matches!(
                name.as_str(),
                "args.path"
                    | "args.pathname"
                    | "args.filename"
                    | "args.old_path"
                    | "args.new_path"
                    | "args.oldname"
                    | "args.newname"
            ) {
                "text"
            } else {
                "integer"
            },
            detail: detail.as_str(),
        })
        .collect()
}

pub(super) fn operators(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "text" | "text list" => &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("contains", "Substring"),
            ("in", "Membership set"),
        ],
        "boolean" => &[("==", "Equal"), ("!=", "Not equal")],
        "ip" => &[("==", "Equal"), ("!=", "Not equal")],
        _ => &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("<", "Less than"),
            ("<=", "Less than or equal"),
            (">", "Greater than"),
            (">=", "Greater than or equal"),
            ("in", "Membership set"),
            ("&", "Bit mask"),
        ],
    }
}

fn packet_operators(kind: &str) -> &'static [(&'static str, &'static str)] {
    if kind == "FT_PROTOCOL" {
        return &[("&&", "And"), ("||", "Or")];
    }
    if matches!(kind, "FT_BOOLEAN" | "boolean") {
        return &[("==", "Equal"), ("!=", "Not equal")];
    }
    if kind.starts_with("FT_STRING") || kind == "text" {
        return &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("contains", "Substring"),
            ("matches", "Regular expression"),
            ("in", "Membership set"),
        ];
    }
    if matches!(kind, "FT_BYTES" | "FT_UINT_BYTES" | "bytes") {
        return &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("contains", "Byte sequence"),
            ("in", "Membership set"),
        ];
    }
    if matches!(
        kind,
        "FT_IPv4" | "FT_IPv6" | "FT_ETHER" | "FT_GUID" | "FT_OID" | "FT_REL_OID" | "ip"
    ) {
        return &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("in", "Membership set"),
        ];
    }
    &[
        ("==", "Equal"),
        ("!=", "Not equal"),
        ("<", "Less than"),
        ("<=", "Less than or equal"),
        (">", "Greater than"),
        (">=", "Greater than or equal"),
        ("in", "Membership set"),
    ]
}

fn values_for(field: &str, prefix: &str, known_values: &[String]) -> Vec<(String, String)> {
    let needle = prefix.to_ascii_lowercase();
    let mut values = Vec::new();
    if matches!(
        field.to_ascii_lowercase().as_str(),
        "tag" | "tags" | "entry.tag"
    ) {
        for value in known_values {
            if value.to_ascii_lowercase().starts_with(&needle) {
                values.push((value.clone(), "recorded tag".into()));
            }
            if values.len() == 12 {
                break;
            }
        }
    }
    if field.eq_ignore_ascii_case("syscall.name") {
        for syscall in antinomie_monitor_core::syscalls::all() {
            if syscall.name.to_ascii_lowercase().starts_with(&needle) {
                values.push((syscall.name.clone(), "syscall name".into()));
            }
            if values.len() == 12 {
                break;
            }
        }
    } else if field.eq_ignore_ascii_case("http.request.method") {
        for method in ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            if method.to_ascii_lowercase().starts_with(&needle) {
                values.push((method.into(), "HTTP method".into()));
            }
        }
    } else if field.eq_ignore_ascii_case("args.prot") {
        for (value, detail) in [
            ("0", "PROT_NONE"),
            ("1", "PROT_READ"),
            ("2", "PROT_WRITE"),
            ("4", "PROT_EXEC"),
            ("7", "read, write and execute"),
        ] {
            if value.starts_with(prefix) {
                values.push((value.into(), detail.into()));
            }
        }
    }
    values
}
