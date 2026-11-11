// SPDX-License-Identifier: GPL-3.0-only
//! The expression grammar of `[[verdict.rule]] when = "..."` (design 4.9.2): a
//! tiny language over a closed set of fields. It reuses nothing executable:
//! the text is tokenised and parsed here, and evaluation reads a [`Facts`].
//!
//! ```text
//! expr  := and ("or" and)*
//! and   := cmp ("and" cmp)*
//! cmp   := atom (("==" | "!=" | "<" | "<=" | ">" | ">=" | "in") atom)?
//! atom  := string | integer | field | "[" atom ("," atom)* "]" | "(" expr ")"
//! ```
//!
//! A string is `'...'` or `"..."`; equality of strings ignores case. A field
//! that holds a list (`families`, `techniques`, `detections.engine`,
//! `detections.severity`) compares true when **any** element does, and
//! `x in [...]` is true when any element of `x` is one of the list. A bare
//! atom is not an expression: it must be compared.

use super::Facts;

/// The fields a rule may read.
pub const FIELDS: &[&str] = &[
    "assessment",
    "highest_tier",
    "counts.processes",
    "counts.findings",
    "counts.indicators",
    "counts.indicators_matched",
    "counts.techniques",
    "counts.files_changed",
    "counts.files_opened",
    "counts.endpoints",
    "counts.domains",
    "detections.engine",
    "detections.severity",
    "families",
    "techniques",
    "run.end_reason",
];

/// A parse error with the byte offset it was found at.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message} (at character {at})")]
pub struct ExprError {
    pub message: String,
    pub at: usize,
}

fn err<T>(at: usize, message: impl Into<String>) -> Result<T, ExprError> {
    Err(ExprError {
        message: message.into(),
        at,
    })
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Str(String),
    Int(i64),
    Name(String),
    Op(Cmp),
    And,
    Or,
    In,
    Open,
    Close,
    ListOpen,
    ListClose,
    Comma,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

fn tokens(text: &str) -> Result<Vec<(usize, Token)>, ExprError> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let (at, c) = chars[i];
        let next = chars.get(i + 1).map(|(_, c)| *c);
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push((at, Token::Open));
                i += 1;
            }
            ')' => {
                out.push((at, Token::Close));
                i += 1;
            }
            '[' => {
                out.push((at, Token::ListOpen));
                i += 1;
            }
            ']' => {
                out.push((at, Token::ListClose));
                i += 1;
            }
            ',' => {
                out.push((at, Token::Comma));
                i += 1;
            }
            '=' if next == Some('=') => {
                out.push((at, Token::Op(Cmp::Eq)));
                i += 2;
            }
            '!' if next == Some('=') => {
                out.push((at, Token::Op(Cmp::Ne)));
                i += 2;
            }
            '<' if next == Some('=') => {
                out.push((at, Token::Op(Cmp::Le)));
                i += 2;
            }
            '>' if next == Some('=') => {
                out.push((at, Token::Op(Cmp::Ge)));
                i += 2;
            }
            '<' => {
                out.push((at, Token::Op(Cmp::Lt)));
                i += 1;
            }
            '>' => {
                out.push((at, Token::Op(Cmp::Gt)));
                i += 1;
            }
            '\'' | '"' => {
                let mut j = i + 1;
                let mut value = String::new();
                loop {
                    match chars.get(j) {
                        None => return err(at, "a string is not closed"),
                        Some((_, q)) if *q == c => break,
                        Some((_, other)) => value.push(*other),
                    }
                    j += 1;
                }
                out.push((at, Token::Str(value)));
                i = j + 1;
            }
            c if c.is_ascii_digit() => {
                let mut j = i;
                while chars.get(j).is_some_and(|(_, d)| d.is_ascii_digit()) {
                    j += 1;
                }
                let digits: String = chars[i..j].iter().map(|(_, d)| *d).collect();
                match digits.parse() {
                    Ok(n) => out.push((at, Token::Int(n))),
                    Err(_) => return err(at, "the number is too large"),
                }
                i = j;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut j = i;
                while chars
                    .get(j)
                    .is_some_and(|(_, d)| d.is_ascii_alphanumeric() || *d == '_' || *d == '.')
                {
                    j += 1;
                }
                let word: String = chars[i..j].iter().map(|(_, d)| *d).collect();
                out.push((
                    at,
                    match word.as_str() {
                        "and" => Token::And,
                        "or" => Token::Or,
                        "in" => Token::In,
                        _ => Token::Name(word),
                    },
                ));
                i = j;
            }
            other => return err(at, format!("unexpected character {other:?}")),
        }
    }
    Ok(out)
}

/// What a value is: a field is a string, an integer or a list of strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Str,
    Int,
}

#[derive(Clone, Debug, PartialEq)]
enum Atom {
    Str(String),
    Int(i64),
    Field(&'static str),
    List(Vec<Atom>),
}

impl Atom {
    fn kind(&self) -> Kind {
        match self {
            Self::Str(_) => Kind::Str,
            Self::Int(_) => Kind::Int,
            Self::Field(name) => {
                if name.starts_with("counts.") {
                    Kind::Int
                } else {
                    Kind::Str
                }
            }
            Self::List(items) => items.first().map_or(Kind::Str, Atom::kind),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Or(Box<Node>, Box<Node>),
    And(Box<Node>, Box<Node>),
    Compare(Atom, Cmp, Atom),
    In(Atom, Atom),
}

/// A parsed `when` expression.
#[derive(Clone, Debug, PartialEq)]
pub struct Expr {
    node: Node,
}

/// The longest expression and the deepest parenthesis nesting accepted. A
/// rule is a sentence; without these a hostile policy file (found by the
/// `label_expr` fuzz target) overflows the stack while parsing, evaluating
/// or dropping a chain or a nest of tens of thousands of terms.
pub const MAX_LEN: usize = 2048;
pub const MAX_DEPTH: usize = 32;

struct Parser {
    tokens: Vec<(usize, Token)>,
    at: usize,
    end: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at).map(|(_, t)| t)
    }

    fn here(&self) -> usize {
        self.tokens.get(self.at).map_or(self.end, |(p, _)| *p)
    }

    fn eat(&mut self, token: &Token) -> bool {
        if self.peek() == Some(token) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expr(&mut self) -> Result<Node, ExprError> {
        let mut left = self.and()?;
        while self.eat(&Token::Or) {
            let right = self.and()?;
            left = Node::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Node, ExprError> {
        let mut left = self.compare()?;
        while self.eat(&Token::And) {
            let right = self.compare()?;
            left = Node::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn compare(&mut self) -> Result<Node, ExprError> {
        if self.peek() == Some(&Token::Open) {
            if self.depth >= MAX_DEPTH {
                return err(
                    self.here(),
                    format!("parentheses nest deeper than {MAX_DEPTH} levels"),
                );
            }
            self.at += 1;
            self.depth += 1;
            let inner = self.expr();
            self.depth -= 1;
            let inner = inner?;
            if !self.eat(&Token::Close) {
                return err(self.here(), "a parenthesis is not closed");
            }
            return Ok(inner);
        }
        let at = self.here();
        let left = self.atom()?;
        match self.peek().cloned() {
            Some(Token::Op(op)) => {
                self.at += 1;
                let right_at = self.here();
                let right = self.atom()?;
                if matches!(right, Atom::List(_)) {
                    return err(right_at, "a list is compared with `in`");
                }
                if left.kind() != right.kind() {
                    return err(at, "the two sides are not the same kind of value");
                }
                if matches!(op, Cmp::Lt | Cmp::Le | Cmp::Gt | Cmp::Ge) && left.kind() != Kind::Int {
                    return err(at, "only numbers are ordered");
                }
                Ok(Node::Compare(left, op, right))
            }
            Some(Token::In) => {
                self.at += 1;
                let right = self.atom()?;
                if left.kind() != right.kind() {
                    return err(at, "the two sides are not the same kind of value");
                }
                Ok(Node::In(left, right))
            }
            _ => err(at, "a value must be compared (==, !=, <, <=, >, >=, in)"),
        }
    }

    fn atom(&mut self) -> Result<Atom, ExprError> {
        let at = self.here();
        match self.peek().cloned() {
            Some(Token::Str(s)) => {
                self.at += 1;
                Ok(Atom::Str(s))
            }
            Some(Token::Int(n)) => {
                self.at += 1;
                Ok(Atom::Int(n))
            }
            Some(Token::Name(name)) => {
                self.at += 1;
                match FIELDS.iter().find(|field| **field == name) {
                    Some(field) => Ok(Atom::Field(field)),
                    None => err(
                        at,
                        format!(
                            "unknown field `{name}`; the fields are {}",
                            FIELDS.join(", ")
                        ),
                    ),
                }
            }
            Some(Token::ListOpen) => {
                self.at += 1;
                let mut items = Vec::new();
                if !self.eat(&Token::ListClose) {
                    loop {
                        let item_at = self.here();
                        let item = self.atom()?;
                        if matches!(item, Atom::List(_)) {
                            return err(item_at, "lists do not nest");
                        }
                        if items
                            .first()
                            .is_some_and(|first: &Atom| first.kind() != item.kind())
                        {
                            return err(item_at, "a list holds one kind of value");
                        }
                        items.push(item);
                        if self.eat(&Token::Comma) {
                            continue;
                        }
                        if self.eat(&Token::ListClose) {
                            break;
                        }
                        return err(self.here(), "expected `,` or `]`");
                    }
                }
                Ok(Atom::List(items))
            }
            Some(_) => err(at, "expected a value"),
            None => err(at, "the expression ends where a value is expected"),
        }
    }
}

impl Expr {
    /// Parse `text`.
    pub fn parse(text: &str) -> Result<Self, ExprError> {
        if text.len() > MAX_LEN {
            return err(0, format!("the expression is longer than {MAX_LEN} bytes"));
        }
        let tokens = tokens(text)?;
        if tokens.is_empty() {
            return err(0, "the expression is empty");
        }
        let mut parser = Parser {
            tokens,
            at: 0,
            end: text.len(),
            depth: 0,
        };
        let node = parser.expr()?;
        if parser.at < parser.tokens.len() {
            return err(parser.here(), "unexpected text after the expression");
        }
        Ok(Self { node })
    }

    /// Whether the rule matches.
    pub fn eval(&self, facts: &Facts) -> bool {
        eval(&self.node, facts)
    }
}

use super::expr_value::Value;

fn value(atom: &Atom, facts: &Facts) -> Value {
    match atom {
        Atom::Str(s) => Value::Strs(vec![s.clone()]),
        Atom::Int(n) => Value::Ints(vec![*n]),
        Atom::List(items) => match items.first() {
            Some(Atom::Int(_)) => Value::Ints(
                items
                    .iter()
                    .filter_map(|a| if let Atom::Int(n) = a { Some(*n) } else { None })
                    .collect(),
            ),
            _ => Value::Strs(
                items
                    .iter()
                    .filter_map(|a| {
                        if let Atom::Str(s) = a {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
            ),
        },
        Atom::Field(name) => facts.read(name),
    }
}

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn eval(node: &Node, facts: &Facts) -> bool {
    match node {
        Node::Or(a, b) => eval(a, facts) || eval(b, facts),
        Node::And(a, b) => eval(a, facts) && eval(b, facts),
        Node::In(left, right) => match (value(left, facts), value(right, facts)) {
            (Value::Strs(l), Value::Strs(r)) => l.iter().any(|x| r.iter().any(|y| same(x, y))),
            (Value::Ints(l), Value::Ints(r)) => l.iter().any(|x| r.contains(x)),
            _ => false,
        },
        Node::Compare(left, op, right) => match (value(left, facts), value(right, facts)) {
            (Value::Strs(l), Value::Strs(r)) => {
                let hit = l.iter().any(|x| r.iter().any(|y| same(x, y)));
                match op {
                    Cmp::Eq => hit,
                    Cmp::Ne => !hit,
                    _ => false,
                }
            }
            (Value::Ints(l), Value::Ints(r)) => {
                let (Some(x), Some(y)) = (l.first(), r.first()) else {
                    return false;
                };
                match op {
                    Cmp::Eq => x == y,
                    Cmp::Ne => x != y,
                    Cmp::Lt => x < y,
                    Cmp::Le => x <= y,
                    Cmp::Gt => x > y,
                    Cmp::Ge => x >= y,
                }
            }
            _ => false,
        },
    }
}
