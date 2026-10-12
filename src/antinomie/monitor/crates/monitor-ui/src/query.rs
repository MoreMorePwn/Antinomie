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
A word with none of these matches the syscall name, TID, task or info text.";

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
            ui.label("Fields: syscall.num, syscall.name, tid, pid, ret, args.fd, args.path, args.prot, args.addr, info, tag.");
            ui.add_space(8.0);
            ui.strong("Packets");
            for line in [
                "ip.src == 10.0.2.15 && tcp.dstport == 80",
                "port 53",
                "http",
                "dns",
                "frame contains \"GET\"",
            ] {
                ui.monospace(line);
            }
            ui.add_space(4.0);
            ui.label("Also: ip.dst, tcp.srcport, udp.port, frame.number, frame.len, proto, and a bare protocol name.");
        });
    ctx.data_mut(|data| data.insert_temp(id, open));
}

pub(crate) fn open_guide(ctx: &egui::Context) {
    ctx.data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-open"), true));
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
}

pub(crate) fn compile_note(filter: &str) -> Compiled {
    match compiled(filter) {
        Ok(mode) => Compiled { error: None, mode },
        Err(error) => Compiled {
            error: Some(error),
            mode: Mode::All,
        },
    }
}

#[cfg(test)]
pub(crate) fn matches(filter: &str, invocation: &InvocationSummary) -> Result<bool, String> {
    let compiled = compile_note(filter);
    if let Some(error) = compiled.error.clone() {
        return Err(error);
    }
    Ok(compiled.keep(invocation))
}

fn compiled(filter: &str) -> Result<Mode, String> {
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
    check_fields(&expr)?;
    Ok(Mode::Expr(expr))
}

fn check_fields(expr: &Expr) -> Result<(), String> {
    match expr {
        Expr::Value(value) => check_value(value),
        Expr::Not(inner) => check_fields(inner),
        Expr::And(left, right) | Expr::Or(left, right) => {
            check_fields(left)?;
            check_fields(right)
        }
        Expr::Cmp(left, _, right) => {
            if matches!(left, Value::Masked(_, _)) {
                require_field(left)?;
            } else {
                check_value(left)?;
            }
            check_value(right)
        }
        Expr::Exists(value) | Expr::Missing(value) => require_field(value),
        Expr::In(left, items) => {
            require_field(left)?;
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

fn check_value(value: &Value) -> Result<(), String> {
    match value {
        Value::Field(name) => {
            if name.contains('.') && !known_field(name) {
                return Err(unknown_field(name));
            }
            Ok(())
        }
        Value::Masked(inner, _) => check_value(inner),
        Value::Raw(_) | Value::Number(_) | Value::Text(_) => Ok(()),
    }
}

fn require_field(value: &Value) -> Result<(), String> {
    match value {
        Value::Raw(_) => Ok(()),
        Value::Field(name) if known_field(name) => Ok(()),
        Value::Field(name) => Err(unknown_field(name)),
        Value::Masked(inner, _) => require_field(inner),
        Value::Number(_) | Value::Text(_) => Err("Expected a field".into()),
    }
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
                Resolved::Missing => false,
            }),
            Expr::Exists(value) => Ok(is_present(&value.resolve(invocation)?)),
            Expr::Missing(value) => Ok(!is_present(&value.resolve(invocation)?)),
            Expr::Cmp(left, op, right) => {
                let left = left.resolve(invocation)?;
                let right = right.resolve(invocation)?;
                Ok(compare(*op, &left, &right))
            }
            Expr::In(left, items) => {
                let left = left.resolve(invocation)?;
                if matches!(left, Resolved::Missing) {
                    return Ok(false);
                }
                for item in items {
                    if compare(Cmp::Eq, &left, &item.resolve(invocation)?) {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

fn is_present(value: &Resolved) -> bool {
    match value {
        Resolved::Number(_) => true,
        Resolved::Text(text) => !text.is_empty(),
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
}

fn compare(op: Cmp, left: &Resolved, right: &Resolved) -> bool {
    match (left, right) {
        (Resolved::Missing, _) | (_, Resolved::Missing) => false,
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
                Resolved::Missing => return false,
            };
            let right = match right {
                Resolved::Text(text) => text.clone(),
                Resolved::Number(number) => number.to_string(),
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

/// Captured path text. A pointer in `args` is not a path.
fn captured_path(event: &EventSummary) -> Option<String> {
    event.fields.iter().find_map(|field| {
        let key = field.key.rsplit('.').next().unwrap_or(field.key.as_str());
        if !matches!(
            key,
            "path" | "old_path" | "new_path" | "filename" | "pathname" | "oldname" | "newname"
        ) {
            return None;
        }
        let text = String::from_utf8_lossy(crate::trace::covered_preview(field))
            .trim_end_matches('\0')
            .trim()
            .to_owned();
        (!text.is_empty()).then_some(text)
    })
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
        if alias == "path"
            || matches!(
                argument_name(event.syscall_nr, index),
                "path" | "old_path" | "new_path" | "filename" | "pathname"
            )
        {
            return Ok(captured_path(event).map_or(Resolved::Missing, Resolved::Text));
        }
        return Ok(event
            .args
            .and_then(|args| args.get(index).copied())
            .map(|value| Resolved::Number(value as i64))
            .unwrap_or(Resolved::Missing));
    }
    Err(unknown_field(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{EventSummary, FieldSummary, InvocationSummary};

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
}
