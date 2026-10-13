// SPDX-License-Identifier: MIT
//! Display filter for syscall rows. A bare word still matches the row text.
//! A comparison such as `syscall.num == 9 && args.fd < 3` uses the fields below.
use crate::trace::{self, argument_name};
use antinomie_monitor_core::{EventSummary, InvocationSummary};
use eframe::egui;

pub(crate) const HELP: &str = "\
syscall.num  syscall.name  syscall\n\
tid  pid  ret  result  cpu  task  cookie  call.id  call_id\n\
info  tag\n\
args.0 … args.5   args.<name>  (fd, path, buf, addr, len, prot, flags, dirfd, …)\n\
args.raw[0] … args.raw[5]\n\
==  !=  <  <=  >  >=  contains  in\n\
exists  missing  &  &&  ||  !  ( )\n\
exists ret\n\
syscall.num in {9, 10}\n\
args.prot & 7 == 7\n\
args.raw[4] == 2\n\
call.id == 1\n\
A word with none of these matches the syscall name, TID, task or info text.
tag and tags on a syscall row are missing unless that row has an annotation.
On a run or result they match annotation.json, not path text.";

/// Fields the syscall and record filters actually implement.
const KEYWORDS: &[(&str, &str, &str)] = &[
    ("syscall.num", "integer", "Native syscall number"),
    ("syscall.name", "text", "Syscall name, case-sensitive in =="),
    ("tid", "integer", "Thread id"),
    ("pid", "integer", "Process id"),
    ("cpu", "integer", "CPU recorded on the event"),
    ("task", "integer", "Task cookie"),
    ("cookie", "integer", "Task cookie"),
    ("ret", "integer", "Exit result; missing when the exit was not recorded"),
    ("result", "integer", "Same as ret"),
    ("syscall.ret", "integer", "Same as ret"),
    ("info", "text", "Rendered trace text"),
    (
        "tag",
        "text list",
        "Annotation tag. Missing on a syscall row. On a run or result, one stored tag.",
    ),
    ("tags", "text list", "Same as tag"),
    ("entry.tag", "text list", "Same as tag, for a run or result annotation"),
    ("call.id", "integer", "Invocation id"),
    ("args.raw[0..5]", "integer", "Captured argument word. Not decoded path text."),
    (
        "args.path",
        "text",
        "Captured path, filename, or pathname string. Not the pointer in args.raw.",
    ),
    ("args.old_path", "text", "Captured old path string"),
    ("args.new_path", "text", "Captured new path string"),
    (
        "args.<name>",
        "integer",
        "Named argument word for this syscall: fd, dirfd, flags, prot, addr, len, and the schema name.",
    ),
    ("entry.id", "text", "Run or result id"),
    ("entry.name", "text", "Annotation name. Missing when the annotation has no name."),
    ("name", "text", "Syscall name on a syscall row; annotation name on a run or result"),
    ("entry.path", "text", "Run executable or result path"),
];

/// Short recommended filters. Opened from Help → Filter guide.
pub(crate) fn guide(ctx: &egui::Context) {
    let id = egui::Id::new("filter-guide-open");
    let mut open = ctx.data(|data| data.get_temp::<bool>(id).unwrap_or(false));
    if !open {
        return;
    }
    egui::Window::new("Filter guide")
        .open(&mut open)
        .resizable(true)
        .show(ctx, |ui| {
            ui.label("Use a comparison when you know the field. A bare word searches the row.");
            ui.label(
                "This is a native subset with the fields below. It is not a Wireshark display filter.",
            );
            let query_id = egui::Id::new("filter-guide-query");
            let mut query = ui.ctx().data(|data| data.get_temp::<String>(query_id).unwrap_or_default());
            ui.add(
                egui::TextEdit::singleline(&mut query)
                    .hint_text("Search fields, operators, schema argument names, syscall names")
                    .desired_width(f32::INFINITY),
            );
            let needle = query.to_lowercase();
            ui.ctx().data_mut(|data| data.insert_temp(query_id, query));
            ui.add_space(6.0);
            ui.strong("Syscall rows");
            for line in [
                "syscall.num == 9 && args.prot == 7",
                "syscall.name == execve",
                "args.fd < 3",
                "info contains \"/tmp\"",
                "tag contains \"bpf\"",
            ] {
                ui.monospace(line);
            }
            ui.add_space(4.0);
            ui.label("Every field this filter implements. A name that is not in this list is an error.");
            use egui_extras::{Column, TableBuilder};
            TableBuilder::new(ui)
                .id_salt("filter-keywords")
                .striped(true)
                .column(Column::initial(160.0))
                .column(Column::initial(120.0))
                .column(Column::remainder())
                .header(22.0, |mut header| {
                    for title in ["Field", "Type", "Meaning"] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|mut body| {
                    for (field, kind, meaning) in guide_rows() {
                        if !needle.is_empty()
                            && !field.to_lowercase().contains(&needle)
                            && !kind.to_lowercase().contains(&needle)
                            && !meaning.to_lowercase().contains(&needle)
                        {
                            continue;
                        }
                        body.row(22.0, |mut row| {
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
                    }
                });
            ui.add_space(8.0);
            ui.strong("Examples");
            for line in [
                "syscall.num == 9 && args.prot == 7",
                "syscall.name == execve",
                "ip.src == 10.0.2.15 && tcp.dstport == 80",
                "http.request.method == \"GET\"",
                "dns.qry.name contains \"example\"",
            ] {
                if needle.is_empty() || line.to_lowercase().contains(&needle) {
                    ui.monospace(line);
                }
            }
        });
    ctx.data_mut(|data| data.insert_temp(id, open));
}

pub(crate) fn open_guide(ctx: &egui::Context) {
    ctx.data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-open"), true));
}

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
fn guide_has(needle: &str) -> bool {
    guide_rows().iter().any(|(field, _, _)| field == needle)
}

pub(crate) struct Compiled {
    pub error: Option<String>,
    mode: Mode,
}

enum Mode {
    All,
    Text(String),
    Expr(Expr),
}

impl Compiled {
    pub(crate) fn keep(&self, invocation: &InvocationSummary) -> bool {
        if self.error.is_some() {
            return false;
        }
        match &self.mode {
            Mode::All => true,
            Mode::Text(filter) => {
                let Some(event) = trace::representative(invocation) else {
                    return false;
                };
                let haystack = format!(
                    "{} {} {} {} {}",
                    event.syscall_name,
                    event.tid,
                    event.task_cookie,
                    event.pid,
                    trace::info(invocation)
                );
                haystack.to_lowercase().contains(&filter.to_lowercase())
            }
            Mode::Expr(expr) => expr.eval(invocation).unwrap_or(false),
        }
    }

    pub(crate) fn keep_record(&self, labels: &RecordLabels<'_>) -> bool {
        if self.error.is_some() {
            return false;
        }
        match &self.mode {
            Mode::All => true,
            Mode::Text(filter) => {
                let haystack = format!(
                    "{} {} {} {}",
                    labels.id,
                    labels.name,
                    labels.path,
                    labels.tags.join(" ")
                );
                haystack.to_lowercase().contains(&filter.to_lowercase())
            }
            Mode::Expr(expr) => expr.eval_record(labels).unwrap_or(false),
        }
    }
}

pub(crate) fn compile_note(filter: &str) -> Compiled {
    compile_with(filter, false)
}

/// Run and result rows. `tag` is the annotation on that directory.
/// An invalid expression is an error and is not a text search.
pub(crate) fn compile_record(filter: &str) -> Compiled {
    compile_with(filter, true)
}

pub(crate) fn structured(filter: &str) -> bool {
    is_expression(filter.trim())
}

fn compile_with(filter: &str, record: bool) -> Compiled {
    match compiled(filter, record) {
        Ok(mode) => Compiled { error: None, mode },
        Err(error) => Compiled {
            error: Some(error),
            mode: Mode::All,
        },
    }
}

/// Labels stored beside a run or result. Tags do not come from path text.
pub(crate) struct RecordLabels<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub path: &'a str,
    pub tags: &'a [String],
}

#[cfg(test)]
pub(crate) fn matches(filter: &str, invocation: &InvocationSummary) -> Result<bool, String> {
    let compiled = compile_note(filter);
    if let Some(error) = compiled.error.clone() {
        return Err(error);
    }
    Ok(compiled.keep(invocation))
}

fn compiled(filter: &str, record: bool) -> Result<Mode, String> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Ok(Mode::All);
    }
    if !is_expression(filter) {
        return Ok(Mode::Text(filter.to_owned()));
    }
    let tokens = tokenize(filter)?;
    let mut parser = Parser { tokens, at: 0 };
    let expr = parser.parse_or()?;
    if parser.at != parser.tokens.len() {
        return Err("Unexpected text after the filter".into());
    }
    check_fields(&expr, record)?;
    Ok(Mode::Expr(expr))
}

fn check_fields(expr: &Expr, record: bool) -> Result<(), String> {
    match expr {
        Expr::Value(value) => check_value(value, record),
        Expr::Not(inner) => check_fields(inner, record),
        Expr::And(left, right) | Expr::Or(left, right) => {
            check_fields(left, record)?;
            check_fields(right, record)
        }
        Expr::Cmp(left, _, right) => {
            if matches!(left, Value::Masked(_, _)) {
                require_field(left, record)?;
            } else {
                check_value(left, record)?;
            }
            check_value(right, record)
        }
        Expr::Exists(value) | Expr::Missing(value) => require_field(value, record),
        Expr::In(left, items) => {
            require_field(left, record)?;
            if items.is_empty() {
                return Err("Empty set".into());
            }
            for item in items {
                check_literal(item)?;
            }
            Ok(())
        }
    }
}

fn check_value(value: &Value, record: bool) -> Result<(), String> {
    match value {
        Value::Field(name) => {
            if record {
                if !known_record_field(name) {
                    return Err(unknown_field(name));
                }
                return Ok(());
            }
            if name.contains('.') && !known_field(name) {
                return Err(unknown_field(name));
            }
            Ok(())
        }
        Value::Masked(inner, _) => check_value(inner, record),
        Value::Raw(_) if record => Err("args.raw is a syscall field".into()),
        Value::Raw(_) | Value::Number(_) | Value::Text(_) => Ok(()),
    }
}

fn require_field(value: &Value, record: bool) -> Result<(), String> {
    match value {
        Value::Raw(_) if record => Err("args.raw is a syscall field".into()),
        Value::Raw(_) => Ok(()),
        Value::Field(name) if record && known_record_field(name) => Ok(()),
        Value::Field(name) if !record && known_field(name) => Ok(()),
        Value::Field(name) => Err(unknown_field(name)),
        Value::Masked(inner, _) => require_field(inner, record),
        Value::Number(_) | Value::Text(_) => Err("Expected a field".into()),
    }
}

fn known_record_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "tag" | "tags" | "entry.tag" | "entry.name" | "entry.id" | "entry.path" | "name"
    )
}

fn check_literal(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(_) | Value::Text(_) => Ok(()),
        _ => Err("Expected a number or quoted text in the set".into()),
    }
}

fn unknown_field(name: &str) -> String {
    format!(
        "Unknown filter field {name}. Fields: syscall.num, syscall.name, tid, pid, ret, info, tag, call.id, args.N, args.<name>"
    )
}

fn known_field(name: &str) -> bool {
    let key = name.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "syscall.num"
            | "syscall.number"
            | "syscall.name"
            | "syscall"
            | "name"
            | "tid"
            | "pid"
            | "cpu"
            | "task"
            | "cookie"
            | "task.cookie"
            | "ret"
            | "result"
            | "syscall.ret"
            | "info"
            | "tag"
            | "tags"
            | "call.id"
            | "call_id"
    ) || key
        .strip_prefix("args.")
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('.'))
}

fn is_expression(filter: &str) -> bool {
    filter.contains("==")
        || filter.contains("!=")
        || filter.contains("&&")
        || filter.contains("||")
        || filter.contains('<')
        || filter.contains('>')
        || filter.contains('(')
        || filter.contains('&')
        || filter.contains('{')
        || filter.contains('[')
        || filter.to_lowercase().contains(" contains ")
        || has_filter_word(filter, "exists")
        || has_filter_word(filter, "missing")
        || has_filter_word(filter, "in")
        || filter.split_whitespace().any(|word| word.contains('.'))
}

fn has_filter_word(filter: &str, word: &str) -> bool {
    filter
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|part| part.eq_ignore_ascii_case(word))
}

#[derive(Clone, Debug)]
enum Token {
    Ident(String),
    Number(i64),
    Text(String),
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    Exists,
    Missing,
    In,
    And,
    Or,
    Not,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Amp,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let rest = &input[index..];
        let lower = rest.to_ascii_lowercase();
        if lower.starts_with("&&") {
            tokens.push(Token::And);
            index += 2;
        } else if lower.starts_with("||") {
            tokens.push(Token::Or);
            index += 2;
        } else if lower.starts_with("==") {
            tokens.push(Token::Eq);
            index += 2;
        } else if lower.starts_with("!=") {
            tokens.push(Token::Ne);
            index += 2;
        } else if lower.starts_with("<=") {
            tokens.push(Token::Le);
            index += 2;
        } else if lower.starts_with(">=") {
            tokens.push(Token::Ge);
            index += 2;
        } else if lower.starts_with("contains")
            && rest[8..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_alphanumeric())
        {
            tokens.push(Token::Contains);
            index += 8;
        } else if byte == b'<' {
            tokens.push(Token::Lt);
            index += 1;
        } else if byte == b'>' {
            tokens.push(Token::Gt);
            index += 1;
        } else if byte == b'!' {
            tokens.push(Token::Not);
            index += 1;
        } else if byte == b'(' {
            tokens.push(Token::LParen);
            index += 1;
        } else if byte == b')' {
            tokens.push(Token::RParen);
            index += 1;
        } else if byte == b'{' {
            tokens.push(Token::LBrace);
            index += 1;
        } else if byte == b'}' {
            tokens.push(Token::RBrace);
            index += 1;
        } else if byte == b'[' {
            tokens.push(Token::LBracket);
            index += 1;
        } else if byte == b']' {
            tokens.push(Token::RBracket);
            index += 1;
        } else if byte == b',' {
            tokens.push(Token::Comma);
            index += 1;
        } else if byte == b'&' {
            tokens.push(Token::Amp);
            index += 1;
        } else if byte == b'"' || byte == b'\'' {
            let quote = byte as char;
            let body = &input[index + 1..];
            let end = body
                .find(quote)
                .ok_or_else(|| "Unclosed quote in the filter".to_owned())?;
            tokens.push(Token::Text(body[..end].to_owned()));
            index += end + 2;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            if rest.starts_with("0x") || rest.starts_with("0X") {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                    index += 1;
                }
                let text = &input[start..index];
                let value =
                    i64::from_str_radix(text.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .map_err(|_| format!("Invalid number {text}"))?;
                tokens.push(Token::Number(value));
            } else {
                while index < bytes.len() && (bytes[index].is_ascii_digit()) {
                    index += 1;
                }
                let text = &input[start..index];
                let value = text
                    .parse::<i64>()
                    .map_err(|_| format!("Invalid number {text}"))?;
                tokens.push(Token::Number(value));
            }
        } else if byte.is_ascii_alphabetic() || byte == b'_' || byte == b'.' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'.')
            {
                index += 1;
            }
            let word = input[start..index].to_owned();
            match word.to_ascii_lowercase().as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                "contains" => tokens.push(Token::Contains),
                "exists" => tokens.push(Token::Exists),
                "missing" => tokens.push(Token::Missing),
                "in" => tokens.push(Token::In),
                _ => tokens.push(Token::Ident(word)),
            }
        } else {
            return Err(format!(
                "Unexpected character in the filter: {}",
                byte as char
            ));
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn pop(&mut self) -> Result<Token, String> {
        let token = self
            .tokens
            .get(self.at)
            .cloned()
            .ok_or_else(|| "Filter ended early".to_owned())?;
        self.at += 1;
        Ok(token)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.at += 1;
            left = Expr::Or(Box::new(left), Box::new(self.parse_and()?));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.at += 1;
            left = Expr::And(Box::new(left), Box::new(self.parse_not()?));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.at += 1;
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Token::LParen)) {
            self.at += 1;
            let inner = self.parse_or()?;
            if !matches!(self.pop()?, Token::RParen) {
                return Err("Missing closing parenthesis".into());
            }
            return Ok(inner);
        }
        if matches!(self.peek(), Some(Token::Exists | Token::Missing)) {
            let missing = matches!(self.peek(), Some(Token::Missing));
            self.at += 1;
            let field = self.parse_value()?;
            return Ok(if missing {
                Expr::Missing(field)
            } else {
                Expr::Exists(field)
            });
        }
        let mut left = self.parse_value()?;
        if matches!(self.peek(), Some(Token::Amp)) {
            self.at += 1;
            let mask = match self.pop()? {
                Token::Number(number) if number >= 0 => {
                    u64::try_from(number).map_err(|_| "Negative mask".to_owned())?
                }
                Token::Number(_) => return Err("Negative mask".into()),
                _ => return Err("Expected a number after &".into()),
            };
            left = Value::Masked(Box::new(left), mask);
            let op = match self.pop()? {
                Token::Eq => Cmp::Eq,
                Token::Ne => Cmp::Ne,
                _ => return Err("Expected == or != after the mask".into()),
            };
            let right = self.parse_value()?;
            return Ok(Expr::Cmp(left, op, right));
        }
        if matches!(self.peek(), Some(Token::In)) {
            self.at += 1;
            return Ok(Expr::In(left, self.parse_set()?));
        }
        let op = match self.peek() {
            Some(Token::Eq) => Cmp::Eq,
            Some(Token::Ne) => Cmp::Ne,
            Some(Token::Lt) => Cmp::Lt,
            Some(Token::Le) => Cmp::Le,
            Some(Token::Gt) => Cmp::Gt,
            Some(Token::Ge) => Cmp::Ge,
            Some(Token::Contains) => Cmp::Contains,
            _ => return Ok(Expr::Value(left)),
        };
        self.at += 1;
        let right = self.parse_value()?;
        Ok(Expr::Cmp(left, op, right))
    }

    fn parse_set(&mut self) -> Result<Vec<Value>, String> {
        if !matches!(self.pop()?, Token::LBrace) {
            return Err("Expected { after in".into());
        }
        if matches!(self.peek(), Some(Token::RBrace)) {
            return Err("Empty set".into());
        }
        let mut items = Vec::new();
        loop {
            items.push(self.parse_set_item()?);
            match self.peek() {
                Some(Token::Comma) => {
                    self.at += 1;
                    if matches!(self.peek(), Some(Token::RBrace)) {
                        return Err("Expected a value in the set".into());
                    }
                }
                Some(Token::RBrace) => {
                    self.at += 1;
                    break;
                }
                _ => return Err("Expected } to close the set".into()),
            }
        }
        Ok(items)
    }

    fn parse_set_item(&mut self) -> Result<Value, String> {
        match self.pop()? {
            Token::Number(number) => Ok(Value::Number(number)),
            Token::Text(text) => Ok(Value::Text(text)),
            Token::Ident(name) => Ok(Value::Text(name)),
            _ => Err("Expected a number or quoted text in the set".into()),
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        match self.pop()? {
            Token::Ident(name) if name.eq_ignore_ascii_case("args.raw") => self.parse_raw_slot(),
            Token::Ident(name) => Ok(Value::Field(name)),
            Token::Number(number) => Ok(Value::Number(number)),
            Token::Text(text) => Ok(Value::Text(text)),
            _ => Err("Expected a field, number or quoted text".into()),
        }
    }

    fn parse_raw_slot(&mut self) -> Result<Value, String> {
        if !matches!(self.peek(), Some(Token::LBracket)) {
            return Err("args.raw needs an index from 0 through 5".into());
        }
        self.at += 1;
        let index = match self.pop()? {
            Token::Number(number) if (0..6).contains(&number) => number as usize,
            Token::Number(number) => {
                return Err(format!("args.raw index {number} is outside 0 through 5"));
            }
            Token::Ident(_) => return Err("args.raw takes a slot number, not a name".into()),
            _ => return Err("args.raw needs an index from 0 through 5".into()),
        };
        if !matches!(self.pop()?, Token::RBracket) {
            return Err("Expected ] after the args.raw index".into());
        }
        Ok(Value::Raw(index))
    }
}

#[derive(Clone, Copy)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

enum Expr {
    Value(Value),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(Value, Cmp, Value),
    Exists(Value),
    Missing(Value),
    In(Value, Vec<Value>),
}

enum Value {
    Field(String),
    Number(i64),
    Text(String),
    Raw(usize),
    Masked(Box<Value>, u64),
}

enum Resolved {
    Number(i64),
    Text(String),
    List(Vec<String>),
    Missing,
}

impl Expr {
    fn eval(&self, invocation: &InvocationSummary) -> Result<bool, String> {
        match self {
            Expr::Not(inner) => Ok(!inner.eval(invocation)?),
            Expr::And(left, right) => Ok(left.eval(invocation)? && right.eval(invocation)?),
            Expr::Or(left, right) => Ok(left.eval(invocation)? || right.eval(invocation)?),
            Expr::Value(value) => Ok(match value.resolve(invocation)? {
                Resolved::Number(number) => number != 0,
                Resolved::Text(text) => !text.is_empty(),
                Resolved::List(items) => !items.is_empty(),
                Resolved::Missing => false,
            }),
            Expr::Exists(value) => Ok(is_present(&value.resolve(invocation)?)),
            Expr::Missing(value) => Ok(!is_present(&value.resolve(invocation)?)),
            Expr::Cmp(left, op, right) => {
                let left = left.resolve(invocation)?;
                let right = right.resolve(invocation)?;
                Ok(compare(*op, &left, &right))
            }
            Expr::In(left, items) => in_list(left.resolve(invocation)?, items, |item| {
                item.resolve(invocation)
            }),
        }
    }

    fn eval_record(&self, labels: &RecordLabels<'_>) -> Result<bool, String> {
        match self {
            Expr::Not(inner) => Ok(!inner.eval_record(labels)?),
            Expr::And(left, right) => Ok(left.eval_record(labels)? && right.eval_record(labels)?),
            Expr::Or(left, right) => Ok(left.eval_record(labels)? || right.eval_record(labels)?),
            Expr::Value(value) => Ok(match value.resolve_record(labels)? {
                Resolved::Number(number) => number != 0,
                Resolved::Text(text) => !text.is_empty(),
                Resolved::List(items) => !items.is_empty(),
                Resolved::Missing => false,
            }),
            Expr::Exists(value) => Ok(is_present(&value.resolve_record(labels)?)),
            Expr::Missing(value) => Ok(!is_present(&value.resolve_record(labels)?)),
            Expr::Cmp(left, op, right) => Ok(compare(
                *op,
                &left.resolve_record(labels)?,
                &right.resolve_record(labels)?,
            )),
            Expr::In(left, items) => in_list(left.resolve_record(labels)?, items, |item| {
                item.resolve_record(labels)
            }),
        }
    }
}

fn in_list(
    left: Resolved,
    items: &[Value],
    mut resolve: impl FnMut(&Value) -> Result<Resolved, String>,
) -> Result<bool, String> {
    if matches!(left, Resolved::Missing) {
        return Ok(false);
    }
    for item in items {
        if compare(Cmp::Eq, &left, &resolve(item)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_present(value: &Resolved) -> bool {
    match value {
        Resolved::Number(_) => true,
        Resolved::Text(text) => !text.is_empty(),
        Resolved::List(items) => !items.is_empty(),
        Resolved::Missing => false,
    }
}

impl Value {
    fn resolve(&self, invocation: &InvocationSummary) -> Result<Resolved, String> {
        match self {
            Value::Number(number) => Ok(Resolved::Number(*number)),
            Value::Text(text) => Ok(Resolved::Text(text.clone())),
            Value::Raw(index) => {
                let Some(event) = trace::representative(invocation) else {
                    return Ok(Resolved::Missing);
                };
                Ok(event
                    .args
                    .and_then(|args| args.get(*index).copied())
                    .map(|value| Resolved::Number(value as i64))
                    .unwrap_or(Resolved::Missing))
            }
            Value::Masked(value, mask) => match value.resolve(invocation)? {
                Resolved::Number(number) => Ok(Resolved::Number(number & *mask as i64)),
                _ => Ok(Resolved::Missing),
            },
            Value::Field(name) => match field(invocation, name) {
                Ok(value) => Ok(value),
                Err(_) if !name.contains('.') => Ok(Resolved::Text(name.clone())),
                Err(error) => Err(error),
            },
        }
    }

    fn resolve_record(&self, labels: &RecordLabels<'_>) -> Result<Resolved, String> {
        match self {
            Value::Number(number) => Ok(Resolved::Number(*number)),
            Value::Text(text) => Ok(Resolved::Text(text.clone())),
            Value::Raw(_) => Err("args.raw is a syscall field".into()),
            Value::Masked(value, mask) => match value.resolve_record(labels)? {
                Resolved::Number(number) => Ok(Resolved::Number(number & *mask as i64)),
                _ => Ok(Resolved::Missing),
            },
            Value::Field(name) => record_field(labels, name),
        }
    }
}

fn record_field(labels: &RecordLabels<'_>, name: &str) -> Result<Resolved, String> {
    match name.to_ascii_lowercase().as_str() {
        "tag" | "tags" | "entry.tag" => Ok(if labels.tags.is_empty() {
            Resolved::Missing
        } else {
            Resolved::List(labels.tags.to_vec())
        }),
        "entry.name" | "name" => {
            if labels.name.is_empty() {
                Ok(Resolved::Missing)
            } else {
                Ok(Resolved::Text(labels.name.to_string()))
            }
        }
        "entry.id" => Ok(Resolved::Text(labels.id.to_string())),
        "entry.path" => Ok(Resolved::Text(labels.path.to_string())),
        _ => Err(unknown_field(name)),
    }
}

fn compare(op: Cmp, left: &Resolved, right: &Resolved) -> bool {
    match (left, right) {
        (Resolved::Missing, _) | (_, Resolved::Missing) => false,
        (Resolved::List(items), Resolved::Text(needle)) => match op {
            Cmp::Eq => items.iter().any(|item| item == needle),
            Cmp::Ne => !items.iter().any(|item| item == needle),
            Cmp::Contains => items.iter().any(|item| item.contains(needle.as_str())),
            Cmp::Lt | Cmp::Le | Cmp::Gt | Cmp::Ge => false,
        },
        (Resolved::List(items), Resolved::Number(number)) => match op {
            Cmp::Eq => items.iter().any(|item| item == &number.to_string()),
            Cmp::Ne => !items.iter().any(|item| item == &number.to_string()),
            _ => false,
        },
        (Resolved::List(_), _) | (_, Resolved::List(_)) => false,
        (Resolved::Number(left), Resolved::Number(right)) => match op {
            Cmp::Eq => left == right,
            Cmp::Ne => left != right,
            Cmp::Lt => left < right,
            Cmp::Le => left <= right,
            Cmp::Gt => left > right,
            Cmp::Ge => left >= right,
            Cmp::Contains => left.to_string().contains(&right.to_string()),
        },
        (left, right) => {
            let left = match left {
                Resolved::Text(text) => text.clone(),
                Resolved::Number(number) => number.to_string(),
                Resolved::List(items) => items.join(", "),
                Resolved::Missing => return false,
            };
            let right = match right {
                Resolved::Text(text) => text.clone(),
                Resolved::Number(number) => number.to_string(),
                Resolved::List(items) => items.join(", "),
                Resolved::Missing => return false,
            };
            match op {
                Cmp::Eq => left.eq_ignore_ascii_case(&right),
                Cmp::Ne => !left.eq_ignore_ascii_case(&right),
                Cmp::Contains => left.to_lowercase().contains(&right.to_lowercase()),
                Cmp::Lt | Cmp::Le | Cmp::Gt | Cmp::Ge => false,
            }
        }
    }
}

/// Captured path text for one argument name. A pointer in `args` is not a path.
fn captured_path(event: &EventSummary, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(text) = event.fields.iter().find_map(|field| {
            let key = field.key.rsplit('.').next().unwrap_or(field.key.as_str());
            if key != *name {
                return None;
            }
            let text = String::from_utf8_lossy(crate::trace::covered_preview(field))
                .trim_end_matches('\0')
                .trim()
                .to_owned();
            (!text.is_empty()).then_some(text)
        }) {
            return Some(text);
        }
    }
    None
}

fn path_names(alias: &str, argument: &str) -> Option<&'static [&'static str]> {
    match alias {
        "path" | "filename" | "pathname" => Some(&["path", "filename", "pathname"]),
        "old_path" | "oldname" => Some(&["old_path", "oldname"]),
        "new_path" | "newname" => Some(&["new_path", "newname"]),
        _ => match argument {
            "path" | "filename" | "pathname" => Some(&["path", "filename", "pathname"]),
            "old_path" | "oldname" => Some(&["old_path", "oldname"]),
            "new_path" | "newname" => Some(&["new_path", "newname"]),
            _ => None,
        },
    }
}

fn field(invocation: &InvocationSummary, name: &str) -> Result<Resolved, String> {
    let key = name.to_ascii_lowercase();
    // Every invocation row carries call_id. A row with no entry, exit, or async
    // event still has that id; there is no separate call record to look up.
    if matches!(key.as_str(), "call.id" | "call_id") {
        return Ok(Resolved::Number(invocation.call_id as i64));
    }
    let Some(event) = trace::representative(invocation) else {
        return Ok(Resolved::Missing);
    };
    let number = match key.as_str() {
        "syscall.num" | "syscall.number" => Some(event.syscall_nr as i64),
        "tid" => Some(i64::from(event.tid)),
        "pid" => Some(i64::from(event.pid)),
        "cpu" => Some(i64::from(event.cpu)),
        "task" | "cookie" | "task.cookie" => Some(event.task_cookie as i64),
        _ => None,
    };
    if let Some(number) = number {
        return Ok(Resolved::Number(number));
    }
    if matches!(key.as_str(), "ret" | "result" | "syscall.ret") {
        // The return is the exit record. `representative` prefers the entry,
        // whose result is often absent even when the exit has already returned.
        let outcome = match invocation.exit.as_ref() {
            Some(exit) => exit.result,
            None => event.result,
        };
        return Ok(outcome.map_or(Resolved::Missing, Resolved::Number));
    }
    if matches!(key.as_str(), "syscall.name" | "syscall" | "name") {
        return Ok(Resolved::Text(event.syscall_name.clone()));
    }
    if key == "info" {
        return Ok(Resolved::Text(trace::info(invocation)));
    }
    if matches!(key.as_str(), "tag" | "tags") {
        return Ok(Resolved::Missing);
    }
    if let Some(index) = key.strip_prefix("args.") {
        let alias = match index {
            "addr" | "address" => "address",
            "len" | "length" => "length",
            "prot" | "protection" => "protection",
            "buf" | "buffer" => "buf",
            "file" | "filename" | "pathname" => "path",
            other => other,
        };
        let slot = if let Ok(index) = alias.parse::<usize>() {
            Some(index)
        } else {
            (0..6).find(|index| {
                let name = argument_name(event.syscall_nr, *index);
                name.eq_ignore_ascii_case(alias)
                    || (alias == "protection" && name.eq_ignore_ascii_case("prot"))
                    || (alias == "buf" && name == "buf")
                    || (alias == "path"
                        && matches!(
                            name,
                            "path" | "old_path" | "new_path" | "filename" | "pathname"
                        ))
            })
        };
        let Some(index) = slot else {
            return Ok(Resolved::Missing);
        };
        let argument = argument_name(event.syscall_nr, index);
        if let Some(names) = path_names(alias, argument) {
            return Ok(captured_path(event, names).map_or(Resolved::Missing, Resolved::Text));
        }
        return Ok(event
            .args
            .and_then(|args| args.get(index).copied())
            .map(|value| Resolved::Number(value as i64))
            .unwrap_or(Resolved::Missing));
    }
    Err(unknown_field(name))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterScope {
    Syscall,
    Record,
    Packet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub start: usize,
    pub end: usize,
    pub insert: String,
    pub detail: String,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn completions(text: &str, cursor: usize, scope: FilterScope) -> Vec<Completion> {
    completions_with(text, cursor, scope, &[])
}

pub(crate) fn completions_with(
    text: &str,
    cursor: usize,
    scope: FilterScope,
    known_values: &[String],
) -> Vec<Completion> {
    let cursor = floor_boundary(text, cursor.min(text.len()));
    if unclosed_quote(&text[..cursor]) {
        return Vec::new();
    }
    let start = token_start(text, cursor);
    let end = token_end(text, cursor);
    let prefix = &text[start..cursor];
    let fields = fields_for(scope);
    let previous = previous_word(text, start);
    let mut items = Vec::new();
    let clause_start = previous.as_deref().is_none_or(|word| {
        matches!(word, "&&" | "||" | "&" | "|" | "(" | "!")
            || word.eq_ignore_ascii_case("and")
            || word.eq_ignore_ascii_case("or")
    });
    if clause_start {
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
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(word))
    }) {
        if prefix.is_empty() || operator_prefix(prefix) {
            for (insert, detail) in operators(field.kind) {
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
        for (insert, detail) in values_for(&field_name, prefix, known_values) {
            items.push(Completion {
                start,
                end,
                insert,
                detail,
            });
        }
    }
    let offering_operator = previous.as_deref().is_some_and(|word| {
        fields
            .iter()
            .any(|field| field.name.eq_ignore_ascii_case(word))
            && (prefix.is_empty() || operator_prefix(prefix))
    });
    if !offering_operator && !prefix.is_empty() {
        let needle = prefix.to_ascii_lowercase();
        for field in fields {
            if field.name.to_ascii_lowercase().starts_with(&needle) {
                items.push(Completion {
                    start,
                    end,
                    insert: field.name.into(),
                    detail: format!("{} · {}", field.kind, field.detail),
                });
            }
        }
    } else if !offering_operator && prefix.is_empty() {
        for field in fields.iter().take(8) {
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

pub(crate) fn filter_edit(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
) -> egui::Response {
    filter_edit_with(ui, text, hint, width, scope, &[])
}

pub(crate) fn filter_edit_with(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
    known_values: &[String],
) -> egui::Response {
    let id = ui.id().with(("filter-edit", hint));
    let mut dismiss = ui
        .data(|data| data.get_temp::<bool>(id.with("dismiss")))
        .unwrap_or(false);
    let mut selected = ui
        .data(|data| data.get_temp::<usize>(id.with("selected")))
        .unwrap_or(0);
    let was_focused = ui
        .data(|data| data.get_temp::<bool>(id.with("focus")))
        .unwrap_or(false);
    let pending = ui
        .data(|data| data.get_temp::<Vec<Completion>>(id.with("items")))
        .unwrap_or_default();
    let mut caret = None;
    if was_focused {
        let reopen = ui.input_mut(|input| {
            input.consume_key(egui::Modifiers::CTRL, egui::Key::Space)
                || input.consume_key(egui::Modifiers::COMMAND, egui::Key::Space)
        });
        if reopen {
            dismiss = false;
        }
        if !pending.is_empty() && !dismiss {
            let accept = ui.input_mut(|input| {
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                    selected = selected.saturating_add(1) % pending.len();
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                    selected = if selected == 0 {
                        pending.len() - 1
                    } else {
                        selected - 1
                    };
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                    dismiss = true;
                }
                input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                    || input.consume_key(egui::Modifiers::NONE, egui::Key::Tab)
            });
            if accept && !dismiss {
                if let Some(item) = pending.get(selected.min(pending.len() - 1)).cloned() {
                    let byte = apply_completion(text, &item);
                    caret = Some(char_index(text, byte));
                    dismiss = true;
                }
            }
        }
    }
    let output = egui::TextEdit::singleline(text)
        .hint_text(hint)
        .desired_width(width)
        .margin(crate::theme::TEXT_EDIT_MARGIN)
        .show(ui);
    if let Some(caret) = caret {
        let mut state = output.state.clone();
        state
            .cursor
            .set_char_range(Some(egui::text::CCursorRange::one(
                egui::text::CCursor::new(caret),
            )));
        state.store(ui.ctx(), output.response.id);
    }
    let cursor_chars = output
        .cursor_range
        .map(|range| range.primary.ccursor.index)
        .unwrap_or(text.chars().count());
    let cursor = byte_index(text, cursor_chars);
    let changed = output.response.changed();
    if changed {
        dismiss = false;
        selected = 0;
    }
    let items = if output.response.has_focus() && !dismiss {
        completions_with(text, cursor, scope, known_values)
    } else {
        Vec::new()
    };
    let popup_id = id.with("popup");
    if items.is_empty() {
        ui.memory_mut(|memory| {
            if memory.is_popup_open(popup_id) {
                memory.close_popup();
            }
        });
    } else {
        ui.memory_mut(|memory| memory.open_popup(popup_id));
        let shown = items.clone();
        let mut picked = None;
        egui::popup::popup_below_widget(
            ui,
            popup_id,
            &output.response,
            egui::PopupCloseBehavior::IgnoreClicks,
            |ui| {
                ui.set_min_width(width.clamp(180.0, 420.0));
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for (index, item) in shown.iter().enumerate() {
                            let label = format!("{}  {}", item.insert.trim(), item.detail);
                            if ui.selectable_label(index == selected, label).clicked() {
                                picked = Some(item.clone());
                            }
                        }
                    });
            },
        );
        if let Some(item) = picked {
            let byte = apply_completion(text, &item);
            let caret = char_index(text, byte);
            let mut state = output.state.clone();
            state
                .cursor
                .set_char_range(Some(egui::text::CCursorRange::one(
                    egui::text::CCursor::new(caret),
                )));
            state.store(ui.ctx(), output.response.id);
            output.response.request_focus();
            dismiss = true;
        }
    }
    let focused = output.response.has_focus();
    ui.data_mut(|data| {
        data.insert_temp(id.with("dismiss"), dismiss);
        data.insert_temp(id.with("selected"), selected);
        data.insert_temp(id.with("focus"), focused);
        data.insert_temp(id.with("items"), items);
    });
    output.response
}

fn apply_completion(text: &mut String, item: &Completion) -> usize {
    let start = item.start.min(text.len());
    let end = item.end.min(text.len()).max(start);
    text.replace_range(start..end, &item.insert);
    start + item.insert.len()
}

struct FieldSpec {
    name: &'static str,
    kind: &'static str,
    detail: &'static str,
}

fn fields_for(scope: FilterScope) -> Vec<FieldSpec> {
    match scope {
        FilterScope::Syscall => syscall_fields(),
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

fn syscall_fields() -> Vec<FieldSpec> {
    let mut fields: Vec<FieldSpec> = KEYWORDS
        .iter()
        .filter(|(name, _, _)| *name != "args.<name>" && *name != "args.raw[0..5]")
        .map(|(name, kind, detail)| FieldSpec { name, kind, detail })
        .collect();
    for index in 0..6 {
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
    fields
}

fn schema_argument_fields() -> Vec<FieldSpec> {
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
            kind: "integer",
            detail: detail.as_str(),
        })
        .collect()
}

fn operators(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "text" | "text list" => &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("contains", "Substring"),
        ],
        "ip" => &[("==", "Equal"), ("!=", "Not equal")],
        _ => &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("<", "Less than"),
            ("<=", "Less than or equal"),
            (">", "Greater than"),
            (">=", "Greater than or equal"),
        ],
    }
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

fn operator_prefix(prefix: &str) -> bool {
    prefix.starts_with(['=', '!', '<', '>', '&', '|', 'c', 'i', 'e', 'm'])
}

fn field_before_operator(text: &str, start: usize) -> Option<String> {
    let before = text[..start].trim_end();
    let operator = before
        .rsplit_once(|ch: char| ch.is_whitespace())
        .map(|(_, word)| word)
        .unwrap_or(before);
    if !matches!(
        operator,
        "==" | "!=" | "<" | "<=" | ">" | ">=" | "contains" | "&"
    ) {
        return None;
    }
    let head = before[..before.len() - operator.len()].trim_end();
    let field = head
        .rsplit_once(|ch: char| ch.is_whitespace())
        .map(|(_, word)| word)
        .unwrap_or(head);
    if field.is_empty() {
        None
    } else {
        Some(field.to_owned())
    }
}

fn previous_word(text: &str, start: usize) -> Option<String> {
    let before = text[..start].trim_end();
    if before.is_empty() {
        return None;
    }
    let word = before
        .rsplit_once(|ch: char| ch.is_whitespace())
        .map(|(_, word)| word)
        .unwrap_or(before);
    if word.is_empty() {
        None
    } else {
        Some(word.to_owned())
    }
}

fn byte_index(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map(|(index, _)| index)
        .unwrap_or(text.len())
}

fn char_index(text: &str, byte: usize) -> usize {
    text[..byte.min(text.len())].chars().count()
}

fn token_end(text: &str, cursor: usize) -> usize {
    let bytes = text.as_bytes();
    let mut end = cursor.min(bytes.len());
    while end < bytes.len() {
        let ch = bytes[end];
        if ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'_' | b'[' | b']' | b'=' | b'<' | b'>')
        {
            end += 1;
        } else {
            break;
        }
    }
    end
}

fn token_start(text: &str, cursor: usize) -> usize {
    let bytes = text.as_bytes();
    let mut start = cursor;
    while start > 0 {
        let ch = bytes[start - 1];
        if ch.is_ascii_alphanumeric()
            || matches!(ch, b'.' | b'_' | b'[' | b']' | b'=' | b'<' | b'>')
        {
            start -= 1;
        } else {
            break;
        }
    }
    start
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn unclosed_quote(text: &str) -> bool {
    let mut quoted = false;
    let mut escape = false;
    for ch in text.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
        }
    }
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{EventSummary, FieldSummary, InvocationSummary};

    #[test]
    fn help_lists_schema_argument_names() {
        assert!(guide_has("args.filename"));
        assert!(guide_has("execve"));
        assert!(guide_has("http.request.method"));
        assert!(guide_has("dns.qry.name"));
    }

    fn call(nr: u64, name: &str, args: [u64; 6]) -> InvocationSummary {
        InvocationSummary {
            stream_id: 1,
            task_cookie: 4,
            call_id: 1,
            entry: Some(EventSummary {
                root_task_cookie: 4,
                stream_id: 1,
                task_cookie: 4,
                call_id: 1,
                event_seq: 1,
                phase: 1,
                syscall_nr: nr,
                syscall_name: name.into(),
                pid: 9,
                tid: 9,
                cpu: 0,
                timestamp_ns: 0,
                args: Some(args),
                result: Some(3),
                complete: true,
                issues: Vec::new(),
                fields: Vec::new(),
            }),
            exit: None,
            async_events: Vec::new(),
            task_exit: None,
        }
    }

    #[test]
    fn call_id_matches_only_that_invocation() {
        let one = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        assert_eq!(one.call_id, 1);
        assert!(compile_note("call.id == 5").error.is_none());
        assert!(matches("call.id == 1", &one).unwrap());
        assert!(matches("call_id == 1", &one).unwrap());
        let mut other = one.clone();
        other.call_id = 2;
        assert!(!matches("call.id == 1", &other).unwrap());
        assert!(!matches("call_id == 1", &other).unwrap());
    }

    #[test]
    fn comparisons_combine_syscall_number_and_named_argument() {
        let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        assert!(matches("syscall.num == 9 && args.fd < 3", &mmap).unwrap());
        assert!(!matches("syscall.num == 9 && args.fd < 2", &mmap).unwrap());
        assert!(matches("syscall.name == mmap", &mmap).unwrap());
        assert!(matches("mmap", &mmap).unwrap());
        assert!(matches("args.prot == 7", &mmap).unwrap());
    }

    #[test]
    fn ret_uses_exit_outcome_when_entry_result_is_absent() {
        let mut paired = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        paired.entry.as_mut().unwrap().result = None;
        let mut exit = paired.entry.clone().unwrap();
        exit.phase = 2;
        exit.event_seq = 2;
        exit.result = Some(7);
        paired.exit = Some(exit);
        assert!(trace::representative(&paired).unwrap().result.is_none());
        for filter in ["ret == 7", "result == 7", "syscall.ret == 7"] {
            assert!(
                matches(filter, &paired).unwrap(),
                "{filter} should use the exit result"
            );
        }
    }

    #[test]
    fn tag_does_not_match_path_text_stored_only_in_info() {
        let mut row = call(2, "open", [0x1000, 0, 0, 0, 0, 0]);
        let path = b"/tmp/example\0";
        let captured = path.len() as u64;
        row.entry.as_mut().unwrap().fields.push(FieldSummary {
            object_id: 1,
            key: "path".into(),
            layout: String::new(),
            logical_len: Some(captured),
            captured_len: captured,
            status: None,
            capture_error: 0,
            complete: true,
            preview: path.to_vec(),
            raw_path: None,
            ranges: vec![(0, captured)],
        });
        let info = trace::info(&row);
        assert!(info.contains("/tmp"), "{info}");
        assert!(!matches(r#"tag contains "tmp""#, &row).unwrap());
        assert!(!matches(r#"tags contains "tmp""#, &row).unwrap());
        assert!(matches(r#"info contains "tmp""#, &row).unwrap());
        assert!(matches(r#"args.path == "/tmp/example""#, &row).unwrap());
        assert!(matches("args.raw[0] == 4096", &row).unwrap());
        assert!(!matches(r#"args.path == "4096""#, &row).unwrap());
    }

    #[test]
    fn typo_in_dotted_field_is_a_compile_error() {
        let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        let compiled = compile_note("syscall.typo == 9");
        assert!(compiled.error.is_some());
        assert!(matches("syscall.typo == 9", &mmap).is_err());
    }

    #[test]
    fn exists_set_mask_and_raw_slot() {
        let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        assert!(matches("exists ret", &mmap).unwrap());
        assert!(!matches("missing ret", &mmap).unwrap());
        assert!(matches("syscall.num in {9, 10}", &mmap).unwrap());
        assert!(!matches("syscall.num in {10, 11}", &mmap).unwrap());
        assert!(matches(r#"syscall.name in {"mmap", "open"}"#, &mmap).unwrap());
        assert!(matches("args.prot & 7 == 7", &mmap).unwrap());
        assert!(matches("args.prot & 7 != 1", &mmap).unwrap());
        assert!(!matches("args.prot & 7 == 1", &mmap).unwrap());
        assert!(matches("args.raw[4] == 2", &mmap).unwrap());
        assert!(matches("args.raw[0] == 0", &mmap).unwrap());
        assert!(matches("args.raw[5] == 0", &mmap).unwrap());
        assert!(matches("exists ret && syscall.num in {9, 10}", &mmap).unwrap());

        let mut zero = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        zero.entry.as_mut().unwrap().result = Some(0);
        assert!(matches("exists ret", &zero).unwrap());
        let mut absent = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        absent.entry.as_mut().unwrap().result = None;
        assert!(!matches("exists ret", &absent).unwrap());
        assert!(matches("missing ret", &absent).unwrap());

        let mut tagged = call(2, "open", [0x1000, 0, 0, 0, 0, 0]);
        let path = b"/tmp/example\0";
        let captured = path.len() as u64;
        tagged.entry.as_mut().unwrap().fields.push(FieldSummary {
            object_id: 1,
            key: "path".into(),
            layout: String::new(),
            logical_len: Some(captured),
            captured_len: captured,
            status: None,
            capture_error: 0,
            complete: true,
            preview: path.to_vec(),
            raw_path: None,
            ranges: vec![(0, captured)],
        });
        assert!(trace::info(&tagged).contains("/tmp"));
        assert!(!matches("exists tag", &tagged).unwrap());
        assert!(matches("missing tag", &tagged).unwrap());

        assert!(matches("syscall.num in {}", &mmap).is_err());
        assert!(matches("args.prot & -1 == 7", &mmap).is_err());
        assert!(matches("args.raw[6]", &mmap).is_err());
        assert!(matches("args.raw[6] == 0", &mmap).is_err());
        assert!(matches("args.raw[prot] == 7", &mmap).is_err());
    }

    #[test]
    fn record_tags_come_from_annotations_not_from_the_path() {
        let labels = RecordLabels {
            id: "run-1",
            name: "sample",
            path: "/tmp/example",
            tags: &["review".into()],
        };
        let tagged = compile_record(r#"tag == "review""#);
        assert!(tagged.error.is_none());
        assert!(tagged.keep_record(&labels));
        assert!(!compile_record(r#"tag == "tmp""#).keep_record(&labels));
        assert!(!compile_record(r#"tag contains "tmp""#).keep_record(&labels));
        assert!(compile_record(r#"entry.path contains "tmp""#).keep_record(&labels));
        let untagged = RecordLabels {
            tags: &[],
            ..labels
        };
        assert!(!compile_record("exists tag").keep_record(&untagged));
        assert!(compile_record("missing tag").keep_record(&untagged));
        let invalid = compile_record("syscall.typo == 9");
        assert!(invalid.error.is_some());
        assert!(!invalid.keep_record(&labels));
    }

    #[test]
    fn completions_keep_the_surrounding_clause_and_follow_the_registry() {
        let text = "syscall.num == 9 && args.pr";
        let items = completions(text, text.len(), FilterScope::Syscall);
        let prot = items
            .iter()
            .find(|item| item.insert == "args.prot")
            .expect("args.prot");
        let mut edited = text.to_owned();
        edited.replace_range(prot.start..prot.end, &prot.insert);
        assert_eq!(edited, "syscall.num == 9 && args.prot");
        let sysc = completions("sysc", 4, FilterScope::Syscall);
        let names: Vec<_> = sysc.iter().map(|item| item.insert.as_str()).collect();
        assert!(names.contains(&"syscall.name"), "{names:?}");
        assert!(names.contains(&"syscall.num"), "{names:?}");
        let method = completions("http.req", 8, FilterScope::Packet);
        assert!(method
            .iter()
            .any(|item| item.insert == "http.request.method"));
        assert!(method.iter().any(|item| item.insert == "http.request.uri"));
        let operators = completions("syscall.num ", 12, FilterScope::Syscall);
        assert!(operators.iter().any(|item| item.insert.contains("==")));
        assert!(operators.iter().any(|item| item.insert.contains("<=")));
        let inside = "info contains \"exa";
        assert!(completions(inside, inside.len(), FilterScope::Syscall).is_empty());
        let text = "syscall.num == 9 && args.prot";
        let caret = text.find("args.pr").unwrap() + "args.pr".len();
        let prot = completions(text, caret, FilterScope::Syscall)
            .into_iter()
            .find(|item| item.insert == "args.prot")
            .expect("whole token");
        let mut edited = text.to_owned();
        let next = apply_completion(&mut edited, &prot);
        assert_eq!(edited, "syscall.num == 9 && args.prot");
        assert_eq!(next, edited.len());
        let unicode = "info contains \"é\" && args.pr";
        let byte_caret = unicode.find("args.pr").unwrap() + "args.pr".len();
        let char_caret = char_index(unicode, byte_caret);
        assert_ne!(char_caret, byte_caret);
        assert_eq!(byte_index(unicode, char_caret), byte_caret);
        let prot = completions(unicode, byte_index(unicode, char_caret), FilterScope::Syscall)
            .into_iter()
            .find(|item| item.insert == "args.prot")
            .expect("unicode caret");
        let mut edited = unicode.to_owned();
        apply_completion(&mut edited, &prot);
        assert_eq!(edited, "info contains \"é\" && args.prot");
        let presence = completions("ex", 2, FilterScope::Syscall);
        assert!(presence.iter().any(|item| item.insert == "exists "));
        assert!(completions("syscall.num ex", 14, FilterScope::Syscall)
            .iter()
            .all(|item| !item.insert.contains("exists")));
        let tags = completions_with("tag == mal", 10, FilterScope::Record, &["malware".into()]);
        assert!(tags.iter().any(|item| item.insert == "malware"));
    }

    #[test]
    #[ignore = "native X11 filter popup; stays open long enough to cover a 30s refresh"]
    fn native_filter_autocomplete() {
        use std::time::{Duration, Instant};
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct App {
            syscall: String,
            history: String,
            packet: String,
            frames: u64,
            started: Instant,
            deadline: Instant,
            focused: bool,
        }
        impl eframe::App for App {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                self.frames += 1;
                let elapsed = self.started.elapsed().as_secs();
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label(format!("refresh {elapsed}s · frame {}", self.frames));
                    ui.label("Syscall filter");
                    let syscall = crate::query::filter_edit(
                        ui,
                        &mut self.syscall,
                        "Filter syscalls",
                        ui.available_width(),
                        FilterScope::Syscall,
                    );
                    ui.label("Run history filter");
                    let _ = crate::query::filter_edit(
                        ui,
                        &mut self.history,
                        "Filter runs",
                        ui.available_width(),
                        FilterScope::Record,
                    );
                    ui.label("Packet filter");
                    let _ = crate::query::filter_edit(
                        ui,
                        &mut self.packet,
                        "Filter packets",
                        ui.available_width(),
                        FilterScope::Packet,
                    );
                    if !self.focused {
                        syscall.request_focus();
                        self.focused = true;
                    }
                });
                let _ = std::fs::write(
                    "/tmp/antinomie-filter-refresh",
                    format!("{elapsed} {}\n", self.frames),
                );
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let wide = std::env::var_os("ANTINOMIE_FILTER_QA_WIDE").is_some();
        let font = std::env::var("ANTINOMIE_FILTER_QA_FONT")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(if wide { 16.0 } else { 24.0 });
        let seconds = std::env::var("ANTINOMIE_FILTER_QA_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(35)
            .clamp(1, 90);
        eframe::run_native(
            "Antinomie Filter QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(if wide {
                        [1100.0, 720.0]
                    } else {
                        [420.0, 760.0]
                    })
                    .with_position([80.0, 60.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                crate::theme::install(&cc.egui_ctx);
                crate::theme::text_size(&cc.egui_ctx, font);
                Ok(Box::new(App {
                    syscall: "syscall.num == 9 && args.pr".into(),
                    history: "entry.na".into(),
                    packet: "tcp.f".into(),
                    frames: 0,
                    started: Instant::now(),
                    deadline: Instant::now() + Duration::from_secs(seconds),
                    focused: false,
                }))
            }),
        )
        .unwrap();
    }
}
