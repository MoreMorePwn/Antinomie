// SPDX-License-Identifier: GPL-3.0-only
//! Reading the text of a filter being edited: its tokens and the one at the cursor.
use super::*;

pub fn operator_prefix(prefix: &str) -> bool {
    prefix.starts_with(['=', '!', '<', '>', '&', '|', 'c', 'i', 'e', 'm'])
}

pub fn field_before_operator(text: &str, start: usize) -> Option<String> {
    let tokens = tokenize(text[..start].trim_end()).ok()?;
    if matches!(tokens.last(), Some(Token::LBrace | Token::Comma)) {
        for pair in tokens.windows(2).rev() {
            if let [Token::Ident(field), Token::In] = pair {
                return Some(field.clone());
            }
            if matches!(pair[1], Token::And | Token::Or) {
                break;
            }
        }
    }
    let mut tail = tokens.iter().rev();
    if !matches!(
        tail.next()?,
        Token::Eq
            | Token::Ne
            | Token::Lt
            | Token::Le
            | Token::Gt
            | Token::Ge
            | Token::Contains
            | Token::Amp
    ) {
        return None;
    }
    match tail.next()? {
        Token::Ident(field) => Some(field.clone()),
        _ => None,
    }
}

pub fn previous_word(text: &str, start: usize) -> Option<String> {
    let before = text[..start].trim_end();
    let (begin, end) = editor_tokens(before).last().copied()?;
    Some(before[begin..end].to_owned())
}

pub fn byte_index(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map(|(index, _)| index)
        .unwrap_or(text.len())
}

pub fn char_index(text: &str, byte: usize) -> usize {
    text[..byte.min(text.len())].chars().count()
}

pub fn token_end(text: &str, cursor: usize) -> usize {
    active_token(text, cursor).map_or(cursor, |(_, end)| end)
}

pub fn token_start(text: &str, cursor: usize) -> usize {
    active_token(text, cursor).map_or(cursor, |(start, _)| start)
}

pub fn active_token(text: &str, cursor: usize) -> Option<(usize, usize)> {
    let tokens = editor_tokens(text);
    tokens
        .iter()
        .copied()
        .find(|(start, end)| *start <= cursor && cursor < *end)
        .or_else(|| {
            tokens.into_iter().find(|(start, end)| {
                *start < cursor
                    && cursor == *end
                    && !matches!(
                        &text[*start..*end],
                        "(" | ")" | "{" | "}" | "," | "&&" | "||" | "!"
                    )
            })
        })
}

pub fn editor_tokens(text: &str) -> Vec<(usize, usize)> {
    let mut tokens = Vec::new();
    let mut iter = text.char_indices().peekable();
    while let Some((start, ch)) = iter.next() {
        if ch.is_whitespace() {
            continue;
        }
        let mut end = start + ch.len_utf8();
        if ch == '"' || ch == '\'' {
            let mut escape = false;
            for (at, next) in iter.by_ref() {
                end = at + next.len_utf8();
                if escape {
                    escape = false;
                    continue;
                }
                if next == '\\' {
                    escape = true;
                } else if next == ch {
                    break;
                }
            }
        } else if ch.is_alphanumeric() || matches!(ch, '_' | '.' | '-' | '/') {
            while let Some(&(at, next)) = iter.peek() {
                if !next.is_alphanumeric()
                    && !matches!(next, '_' | '.' | '[' | ']' | '-' | '/' | ':')
                {
                    break;
                }
                end = at + next.len_utf8();
                iter.next();
            }
        } else if matches!(ch, '=' | '!' | '<' | '>' | '&' | '|') {
            while let Some(&(at, next)) = iter.peek() {
                if !matches!(next, '=' | '&' | '|') {
                    break;
                }
                end = at + next.len_utf8();
                iter.next();
            }
        }
        tokens.push((start, end));
    }
    tokens
}

pub fn floor_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

pub fn unclosed_quote(text: &str) -> bool {
    let mut quote = None;
    let mut escape = false;
    for ch in text.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            escape = true;
            continue;
        }
        if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && matches!(ch, '"' | '\'') {
            quote = Some(ch);
        }
    }
    quote.is_some()
}
/// A placeholder example must be a filter its own box accepts.
#[cfg(any(test, feature = "test-support"))]
pub fn assert_example_compiles(example: &str, fields: &[FieldSpec<'_>]) {
    let compiled = compile_table(example, fields);
    assert!(
        compiled.error.is_none() && !compiled.keeps_everything(),
        "placeholder example {example:?} is not a valid filter: {:?}",
        compiled.error
    );
}
