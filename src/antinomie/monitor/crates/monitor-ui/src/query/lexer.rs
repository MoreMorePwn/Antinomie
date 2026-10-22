// SPDX-License-Identifier: GPL-3.0-only
//! Filter tokens and their positions.
use super::*;

#[derive(Clone, Debug)]
pub(super) enum Token {
    Ident(String),
    Number(i128),
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

pub(super) fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    tokenize_with_positions(input).map(|(tokens, _)| tokens)
}

pub(super) fn position_error(error: String, input: &str, offset: usize) -> String {
    format!(
        "{error} at column {}",
        input[..floor_boundary(input, offset.min(input.len()))]
            .chars()
            .count()
            + 1
    )
}

pub(super) fn tokenize_with_positions(input: &str) -> Result<(Vec<Token>, Vec<usize>), String> {
    if input.len() > 64 * 1024 {
        return Err("Filter exceeds 64 KiB at column 1".into());
    }
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut offsets = Vec::new();
    let mut index = 0;
    let mut nesting = 0usize;
    let mut boolean_count = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let rest = &input[index..];
        offsets.push(index);
        if rest.starts_with("&&") {
            tokens.push(Token::And);
            index += 2;
        } else if rest.starts_with("||") {
            tokens.push(Token::Or);
            index += 2;
        } else if rest.starts_with("==") {
            tokens.push(Token::Eq);
            index += 2;
        } else if rest.starts_with("!=") {
            tokens.push(Token::Ne);
            index += 2;
        } else if rest.starts_with("<=") {
            tokens.push(Token::Le);
            index += 2;
        } else if rest.starts_with(">=") {
            tokens.push(Token::Ge);
            index += 2;
        } else if rest
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("contains"))
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
            index += 1;
            let mut value = String::new();
            let mut closed = false;
            while index < input.len() {
                let ch = input[index..]
                    .chars()
                    .next()
                    .ok_or("Unclosed quote in the filter")?;
                index += ch.len_utf8();
                if ch == quote {
                    closed = true;
                    break;
                }
                if ch == '\\' {
                    let escaped = input[index..]
                        .chars()
                        .next()
                        .ok_or("Incomplete escape in the filter")?;
                    index += escaped.len_utf8();
                    match escaped {
                        '\\' | '"' | '\'' => value.push(escaped),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        't' => value.push('\t'),
                        _ => return Err(format!("Unknown escape \\{escaped}")),
                    }
                } else {
                    value.push(ch);
                }
            }
            if !closed {
                return Err("Unclosed quote in the filter".into());
            }
            tokens.push(Token::Text(value));
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            if rest.starts_with("0x") || rest.starts_with("0X") {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                    index += 1;
                }
                let text = &input[start..index];
                let value = i128::from_str_radix(
                    text.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .map_err(|_| format!("Invalid number {text}"))?;
                tokens.push(Token::Number(value));
            } else {
                while index < bytes.len() && (bytes[index].is_ascii_digit()) {
                    index += 1;
                }
                let text = &input[start..index];
                let value = text
                    .parse::<i128>()
                    .map_err(|_| format!("Invalid number {text}"))?;
                tokens.push(Token::Number(value));
            }
        } else if byte.is_ascii_alphabetic() || byte == b'_' || byte == b'.' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'.'
                    || bytes[index] == b'['
                    || bytes[index] == b']')
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
        match tokens.last() {
            Some(Token::LParen) => nesting += 1,
            Some(Token::RParen) => nesting = nesting.saturating_sub(1),
            Some(Token::And | Token::Or | Token::Not) => boolean_count += 1,
            _ => {}
        }
        if tokens.len() > 2048 || nesting > 64 || boolean_count > 256 {
            return Err(position_error("Filter is too complex (maximum 2048 tokens, 64 nested parentheses, 256 boolean operators)".into(), input, index));
        }
    }
    Ok((tokens, offsets))
}
