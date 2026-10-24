// SPDX-License-Identifier: GPL-3.0-only
//! The graph's share of the Suspicious activity filter: a brushed time range
//! and a clicked lane are written into the filter text, after whatever the
//! user typed, and read back from it, so the filter stays the one truth.
const FROM: &str = "event.time_ns >= ";
const TO: &str = " && event.time_ns <= ";
const COOKIE: &str = "process.cookie == ";

/// A filter taken apart: what the user wrote, then the lane, then the brush.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::triage) struct Parts {
    pub base: String,
    pub cookies: Vec<u64>,
    pub brush: Option<(u64, u64)>,
}

impl Parts {
    pub(in crate::triage) fn parse(filter: &str) -> Self {
        let mut rest = filter.trim().to_owned();
        let mut parts = Parts::default();
        if let Some((at, range)) = brush_suffix(&rest) {
            parts.brush = Some(range);
            rest = trim_and(&rest[..at]);
        }
        if let Some((at, cookies)) = lane_suffix(&rest) {
            parts.cookies = cookies;
            rest = trim_and(&rest[..at]);
        }
        parts.base = unwrap(&rest);
        parts
    }

    pub(in crate::triage) fn render(&self) -> String {
        let mut clauses = Vec::new();
        if !self.cookies.is_empty() {
            let list: Vec<String> = self
                .cookies
                .iter()
                .map(|c| format!("{COOKIE}{c}"))
                .collect();
            clauses.push(if list.len() == 1 {
                list[0].clone()
            } else {
                format!("({})", list.join(" || "))
            });
        }
        if let Some((from, to)) = self.brush {
            clauses.push(format!("{FROM}{from}{TO}{to}"));
        }
        let base = self.base.trim();
        if clauses.is_empty() {
            return base.to_owned();
        }
        let tail = clauses.join(" && ");
        if base.is_empty() {
            tail
        } else if base.contains("||") {
            format!("({base}) && {tail}")
        } else {
            format!("{base} && {tail}")
        }
    }
}

fn trim_and(text: &str) -> String {
    let text = text.trim_end();
    text.strip_suffix("&&")
        .unwrap_or(text)
        .trim_end()
        .to_owned()
}

/// Remove one pair of parentheses that encloses the whole text.
fn unwrap(text: &str) -> String {
    let text = text.trim();
    if text.starts_with('(') && text.ends_with(')') {
        let mut depth = 0;
        for (at, ch) in text.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && at + 1 != text.len() {
                        return text.to_owned();
                    }
                }
                _ => {}
            }
        }
        return text[1..text.len() - 1].trim().to_owned();
    }
    text.to_owned()
}

/// Where a trailing `event.time_ns >= A && event.time_ns <= B` starts.
fn brush_suffix(text: &str) -> Option<(usize, (u64, u64))> {
    let at = text.rfind(FROM)?;
    let tail = &text[at + FROM.len()..];
    let (from, to) = tail.split_once(TO)?;
    let (from, to) = (from.parse().ok()?, to.parse().ok()?);
    let leading = text[..at].trim_end();
    if !(leading.is_empty() || leading.ends_with("&&")) {
        return None;
    }
    Some((at, (from, to)))
}

/// Where a trailing `process.cookie == N` or `(process.cookie == N || …)` starts.
fn lane_suffix(text: &str) -> Option<(usize, Vec<u64>)> {
    let (at, body) = if text.ends_with(')') {
        let at = text.rfind(&format!("({COOKIE}"))?;
        (at, &text[at + 1..text.len() - 1])
    } else {
        let at = text.rfind(COOKIE)?;
        (at, &text[at..])
    };
    let cookies: Option<Vec<u64>> = body
        .split(" || ")
        .map(|part| part.strip_prefix(COOKIE)?.parse().ok())
        .collect();
    let leading = text[..at].trim_end();
    if !(leading.is_empty() || leading.ends_with("&&")) {
        return None;
    }
    cookies
        .filter(|cookies| !cookies.is_empty())
        .map(|cookies| (at, cookies))
}
